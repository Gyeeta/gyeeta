//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include 		<uapi/linux/ptrace.h>

#pragma 		clang diagnostic push
#pragma 		clang diagnostic ignored "-Wtautological-compare"

#include 		<net/sock.h>
#undef 			dynamic_pr_debug
#define 		dynamic_pr_debug(fmt, ...) 
#include 		<net/tcp.h>
#include 		<net/inet_connection_sock.h>

#pragma 		clang diagnostic pop

#include 		<bcc/proto.h>
#include 		<linux/sched.h>

#include		"tcpresponse_bpf.h"

BPF_PERF_OUTPUT(ipv4_xmit_perf);
BPF_PERF_OUTPUT(ipv6_xmit_perf);
BPF_ARRAY(config_resp, uint64_t, ARR_MAX_KEYS);

static int read_ipv4_tuple(struct ipv4_tuple_t *tuple, struct sock *skp)
{
	u32 			net_ns_inum = 0;
	u32 			saddr = skp->__sk_common.skc_rcv_saddr;
	u32 			daddr = skp->__sk_common.skc_daddr;
	struct inet_sock 	*sockp = (struct inet_sock *)skp;
	u16 			sport = sockp->inet_sport;
	u16 			dport = skp->__sk_common.skc_dport;

#ifdef CONFIG_NET_NS
	possible_net_t 		skc_net = skp->__sk_common.skc_net;
	bpf_probe_read(&net_ns_inum, sizeof(net_ns_inum), &skc_net.net->ns.inum);
#endif

	tuple->saddr = saddr;
	tuple->daddr = daddr;
	tuple->sport = sport;
	tuple->dport = dport;
	tuple->netns = net_ns_inum;
	
	// if addresses or ports are 0, ignore
	if (gy_unlikely(saddr == 0 || daddr == 0 || sport == 0 || dport == 0)) {
		return 0;
	}

	return 1;
}

static int read_ipv6_tuple(struct ipv6_tuple_t *tuple, struct sock *skp)
{
	u32 			net_ns_inum = 0;
	unsigned __int128 	saddr = 0, daddr = 0;
	struct inet_sock 	*sockp = (struct inet_sock *)skp;
	u16 			sport = sockp->inet_sport;
	u16 			dport = skp->__sk_common.skc_dport;

#ifdef CONFIG_NET_NS
	possible_net_t 		skc_net = skp->__sk_common.skc_net;
	bpf_probe_read(&net_ns_inum, sizeof(net_ns_inum), &skc_net.net->ns.inum);
#endif
	bpf_probe_read(&saddr, sizeof(saddr), skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
	bpf_probe_read(&daddr, sizeof(daddr), skp->__sk_common.skc_v6_daddr.in6_u.u6_addr8);

	tuple->saddr = saddr;
	tuple->daddr = daddr;
	tuple->sport = sport;
	tuple->dport = dport;
	tuple->netns = net_ns_inum;

	// if addresses or ports are 0, ignore
	if (gy_unlikely(saddr == 0 || daddr == 0 || sport == 0 || dport == 0)) {
		return 0;
	}

	return 1;
}

	
static inline bool check_family(struct sock *sk, u16 expected_family) 
{
	u16 			family = sk->__sk_common.skc_family;
	return (family == expected_family);
}

#if 0
static inline bool check_protocol(struct sock *sk, u8 proto)
{
	struct {
		unsigned int		sk_padding : 1,
					sk_kern_sock : 1,
					sk_no_check_tx : 1,
					sk_no_check_rx : 1,
					sk_userlocks : 4,
					sk_protocol  : 8,
					sk_type      : 16;
	} protocol = {};
		
	// workaround for reading the sk_protocol bitfield
	
	bpf_probe_read(&protocol, 4, (void *)(sk->__sk_flags_offset));

	if (protocol.sk_protocol != proto) {
		return 0;
	}	

	return 1;
}	
#endif

int trace_ip_xmit(struct pt_regs *ctx, struct sock *skp)
{
	struct tcp_sock		*ptcp = (struct tcp_sock *)skp;

	if (!check_family(skp, AF_INET)) {
		return 0;
	}	

	if (ptcp->bytes_received == 0) {
		return 0;
	}

	/*
	 * Only process xmits of listened sockets
	 */
	if (skp->sk_max_ack_backlog == 0) {
		return 0;
	}	

	u32			lrcvtime = ptcp->inet_conn.icsk_ack.lrcvtime;

	if (lrcvtime + 10 < ptcp->rcv_tstamp) {
		// Probably a continuation of response. The response time will have been accounted in an earlier packet
		return 0;
	}	

	if (ptcp->lsndtime < lrcvtime) {
		// Request not responded yet
		return 0;
	}	

	uint64_t 		*pto_enable;
	int 			key_config = ARR_CONFIG_ENABLE;
	
	pto_enable = config_resp.lookup(&key_config);
	if (pto_enable && (0 == *pto_enable)) {
		uint64_t 	*pvalskipped;
		int		key_skipped = ARR_SKIPPED_IPv4; 

		pvalskipped = config_resp.lookup(&key_skipped);
		if (pvalskipped) (*pvalskipped)++;
				
		return 0;
	}	

	struct tcp_ipv4_resp_event_t evt4 = {};

	if (!read_ipv4_tuple(&evt4.tup, skp)) {
		return 0;
	}

	evt4.bytes_received 	= ptcp->bytes_received;
	evt4.bytes_acked	= ptcp->bytes_acked;
	evt4.lsndtime		= ptcp->lsndtime;
	evt4.lrcvtime		= ptcp->inet_conn.icsk_ack.lrcvtime;

	ipv4_xmit_perf.perf_submit(ctx, &evt4, sizeof(evt4));
	
	return 0;
};

int trace_ipv6_xmit(struct pt_regs *ctx, struct sock *skp)
{
	struct tcp_sock		*ptcp = (struct tcp_sock *)skp;

	if (!check_family(skp, AF_INET6)) {
		return 0;
	}	

	if (ptcp->bytes_received == 0) {
		return 0;
	}

	/*
	 * Only process xmits of listened sockets
	 */
	if (skp->sk_max_ack_backlog == 0) {
		return 0;
	}	

	u32			lrcvtime = ptcp->inet_conn.icsk_ack.lrcvtime;

	if (lrcvtime + 10 < ptcp->rcv_tstamp) {
		// Probably a continuation of response. The response time will have been accounted in an earlier packet
		return 0;
	}	

	if (ptcp->lsndtime < lrcvtime) {
		// Request not responded yet
		return 0;
	}	

	uint64_t 		*pto_enable;
	int 			key_config = ARR_CONFIG_ENABLE;
	
	pto_enable = config_resp.lookup(&key_config);
	if (pto_enable && (0 == *pto_enable)) {
		uint64_t 	*pvalskipped;
		int		key_skipped = ARR_SKIPPED_IPv6; 

		pvalskipped = config_resp.lookup(&key_skipped);
		if (pvalskipped) (*pvalskipped)++;
				
		return 0;
	}	

	struct tcp_ipv6_resp_event_t evt6 = {};

	if (!read_ipv6_tuple(&evt6.tup, skp)) {
		return 0;
	}

	evt6.bytes_received 	= ptcp->bytes_received;
	evt6.bytes_acked	= ptcp->bytes_acked;
	evt6.lsndtime		= ptcp->lsndtime;
	evt6.lrcvtime		= ptcp->inet_conn.icsk_ack.lrcvtime;

	ipv6_xmit_perf.perf_submit(ctx, &evt6, sizeof(evt6));


	return 0;
};

