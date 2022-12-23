//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include 		<vmlinux.h>
#include 		<bpf/bpf_helpers.h>
#include 		<bpf/bpf_core_read.h>
#include 		<bpf/bpf_tracing.h>

#include		"tcpresponse_bpf.h"

#ifndef 		AF_INET
#define 		AF_INET		2	/* Internet IP Protocol 	*/
#define 		AF_INET6	10	/* IP version 6			*/
#endif

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} ipv4_xmit_perf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} ipv6_xmit_perf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, ARR_MAX_KEYS);
	__type(key, u32);
	__type(value, u64);
} config_resp SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

static int read_ipv4_tuple(struct ipv4_tuple_t *tuple, struct sock *skp)
{
	u32 			net_ns_inum = 0, saddr, daddr;
	struct inet_sock 	*sockp;
	u16 			sport, dport;

	saddr = BPF_CORE_READ(skp, __sk_common.skc_rcv_saddr);
	daddr = BPF_CORE_READ(skp, __sk_common.skc_daddr);

	sockp = (struct inet_sock *)skp;

	BPF_CORE_READ_INTO(&sport, sockp, inet_sport);
	BPF_CORE_READ_INTO(&dport, skp, __sk_common.skc_dport);

	if (bpf_core_field_exists(skp->__sk_common.skc_net)) {
		BPF_CORE_READ_INTO(&net_ns_inum, skp, __sk_common.skc_net.net, ns.inum);
	}

	tuple->saddr = saddr;
	tuple->daddr = daddr;
	tuple->sport = sport;
	tuple->dport = dport;
	tuple->netns = net_ns_inum;
	
	// if addresses or ports are 0, ignore
	if (saddr == 0 || daddr == 0 || sport == 0 || dport == 0) {
		return 0;
	}

	return 1;
}

static int read_ipv6_tuple(struct ipv6_tuple_t *tuple, struct sock *skp)
{
	u32 			net_ns_inum = 0;
	struct inet_sock 	*sockp = (struct inet_sock *)skp;
	u16 			sport;
	u16 			dport;

	BPF_CORE_READ_INTO(&sport, sockp, inet_sport);
	BPF_CORE_READ_INTO(&dport, skp, __sk_common.skc_dport);

	if (bpf_core_field_exists(skp->__sk_common.skc_net)) {
		BPF_CORE_READ_INTO(&net_ns_inum, skp, __sk_common.skc_net.net, ns.inum);
	}

	BPF_CORE_READ_INTO(&tuple->saddr, skp, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
	BPF_CORE_READ_INTO(&tuple->daddr, skp, __sk_common.skc_v6_daddr.in6_u.u6_addr32);

	tuple->sport = sport;
	tuple->dport = dport;
	tuple->netns = net_ns_inum;

	// if addresses or ports are 0, ignore
	if (tuple->saddr == 0 || tuple->daddr == 0 || sport == 0 || dport == 0) {
		return 0;
	}

	return 1;
}

static inline bool check_family(struct sock *sk, u16 expected_family) 
{
	u16 			family;
	
	BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);

	return (family == expected_family);
}

static int do_trace_ipv4_xmit(void *ctx, struct sock *skp)
{
	struct tcp_sock			*ptcp = (struct tcp_sock *)skp;
	u64				bytes_received = 0, bytes_acked = 0;
	u32				sk_max_ack_backlog = 0, lrcvtime = 0, lsndtime = 0, rcv_tstamp = 0;

	BPF_CORE_READ_INTO(&bytes_received, ptcp, bytes_received);
	if (bytes_received == 0) {
		return 0;
	}

	/*
	 * Only process xmits of listened sockets
	 */
	BPF_CORE_READ_INTO(&sk_max_ack_backlog, skp, sk_max_ack_backlog);
	if (sk_max_ack_backlog == 0) {
		return 0;
	}	

	if (!check_family(skp, AF_INET)) {
		return 0;
	}	

	BPF_CORE_READ_INTO(&lrcvtime, ptcp, inet_conn.icsk_ack.lrcvtime);
	BPF_CORE_READ_INTO(&rcv_tstamp, ptcp, rcv_tstamp);

	if (lrcvtime + 10 < rcv_tstamp) {
		// Probably a continuation of response. The response time will have been accounted in an earlier packet
		return 0;
	}	

	BPF_CORE_READ_INTO(&lsndtime, ptcp, lsndtime);

	if (lsndtime < lrcvtime) {
		// Request not responded yet
		return 0;
	}	

	uint64_t 		*pto_enable;
	u32 			key_config = (u32)ARR_CONFIG_ENABLE;
	
	pto_enable = bpf_map_lookup_elem(&config_resp, &key_config);

	if (pto_enable && (0 == *pto_enable)) {
		return 0;
	}	

	struct tcp_ipv4_resp_event_t evt4 = {};

	if (!read_ipv4_tuple(&evt4.tup, skp)) {
		return 0;
	}

	BPF_CORE_READ_INTO(&bytes_acked, ptcp, bytes_acked);

	evt4.bytes_received 	= bytes_received;
	evt4.bytes_acked	= bytes_acked;
	evt4.lsndtime		= lsndtime;
	evt4.lrcvtime		= lrcvtime;

	bpf_perf_event_output(ctx, &ipv4_xmit_perf, BPF_F_CURRENT_CPU, &evt4, sizeof(evt4));
	
	return 0;
}

SEC("kprobe/__ip_queue_xmit")
int BPF_KPROBE(trace_ipv4_xmit, struct sock *skp)
{
	return do_trace_ipv4_xmit(ctx, skp);
}	

SEC("fentry/__ip_queue_xmit")
int BPF_PROG(fentry_trace_ipv4_xmit, struct sock *skp)
{
	return do_trace_ipv4_xmit(ctx, skp);
}	


static int do_trace_ipv6_xmit(void *ctx, struct sock *skp)
{
	struct tcp_sock			*ptcp = (struct tcp_sock *)skp;
	u64				bytes_received = 0, bytes_acked = 0;
	u32				sk_max_ack_backlog = 0, lrcvtime = 0, lsndtime = 0, rcv_tstamp = 0;

	BPF_CORE_READ_INTO(&bytes_received, ptcp, bytes_received);
	if (bytes_received == 0) {
		return 0;
	}

	/*
	 * Only process xmits of listened sockets
	 */
	BPF_CORE_READ_INTO(&sk_max_ack_backlog, skp, sk_max_ack_backlog);
	if (sk_max_ack_backlog == 0) {
		return 0;
	}	

	if (!check_family(skp, AF_INET6)) {
		return 0;
	}	

	BPF_CORE_READ_INTO(&lrcvtime, ptcp, inet_conn.icsk_ack.lrcvtime);
	BPF_CORE_READ_INTO(&rcv_tstamp, ptcp, rcv_tstamp);

	if (lrcvtime + 10 < rcv_tstamp) {
		// Probably a continuation of response. The response time will have been accounted in an earlier packet
		return 0;
	}	

	BPF_CORE_READ_INTO(&lsndtime, ptcp, lsndtime);

	if (lsndtime < lrcvtime) {
		// Request not responded yet
		return 0;
	}	

	uint64_t 		*pto_enable;
	u32 			key_config = (u32)ARR_CONFIG_ENABLE;
	
	pto_enable = bpf_map_lookup_elem(&config_resp, &key_config);

	if (pto_enable && (0 == *pto_enable)) {
		return 0;
	}	

	struct tcp_ipv6_resp_event_t evt6 = {};

	if (!read_ipv6_tuple(&evt6.tup, skp)) {
		return 0;
	}

	BPF_CORE_READ_INTO(&bytes_acked, ptcp, bytes_acked);

	evt6.bytes_received 	= bytes_received;
	evt6.bytes_acked	= bytes_acked;
	evt6.lsndtime		= lsndtime;
	evt6.lrcvtime		= lrcvtime;

	bpf_perf_event_output(ctx, &ipv6_xmit_perf, BPF_F_CURRENT_CPU, &evt6, sizeof(evt6));

	return 0;
}

SEC("kprobe/inet6_csk_xmit")
int BPF_KPROBE(trace_ipv6_xmit, struct sock *skp)
{
	return do_trace_ipv6_xmit(ctx, skp);
}	

SEC("fentry/inet6_csk_xmit")
int BPF_PROG(fentry_trace_ipv6_xmit, struct sock *skp)
{
	return do_trace_ipv6_xmit(ctx, skp);
}	



