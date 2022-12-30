//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include 		<vmlinux.h>
#include 		<bpf/bpf_helpers.h>
#include 		<bpf/bpf_core_read.h>
#include 		<bpf/bpf_tracing.h>
#include 		<bpf/bpf_endian.h>

#ifndef 		AF_INET

#define 		AF_INET			2		/* IPv4	*/
#define 		AF_INET6		10		/* IPv6	*/

#endif

#include		"../common/gy_ebpf_kernel.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} ip_vs_new_conn_event SEC(".maps");


struct ip_vs_conn___gy {
	__be16                  cport;
	__be16                  dport;
	__be16                  vport;
	u16			af;		/* address family */
	union nf_inet_addr      caddr;          /* client address */
	union nf_inet_addr      vaddr;          /* virtual address */
	union nf_inet_addr      daddr;          /* destination address */
	volatile __u32          flags;          /* status flags */
	__u16                   protocol;       /* Which protocol (TCP/UDP) */
	__u16			daf;		/* Address family of the dest */
}  __attribute__((preserve_access_index));

static int send_ip_vs_conn_info(struct pt_regs *ctx, struct ip_vs_conn___gy *pconn)
{
	struct ip_vs_conn_event_t	evt = {};

	if (pconn == NULL) {
		return 0;
	}

	if (BPF_CORE_READ(pconn, protocol) != IPPROTO_TCP) {
		return 0;
	}	

	BPF_CORE_READ_INTO(&evt.af, pconn, af);
	BPF_CORE_READ_INTO(&evt.daf, pconn, daf);

	if (evt.af == AF_INET) {
		BPF_CORE_READ_INTO(&evt.cliaddr.v4addr, pconn, caddr.ip);
		BPF_CORE_READ_INTO(&evt.virtaddr.v4addr, pconn, vaddr.ip);
	}	
	else {
		BPF_CORE_READ_INTO(&evt.cliaddr.v6addr, pconn, caddr.ip6);
		BPF_CORE_READ_INTO(&evt.virtaddr.v6addr, pconn, vaddr.ip6);
	}	

	if (evt.daf == AF_INET) {
		BPF_CORE_READ_INTO(&evt.destaddr.v4addr, pconn, daddr.ip);
	}	
	else {
		BPF_CORE_READ_INTO(&evt.destaddr.v6addr, pconn, daddr.ip6);
	}	

	evt.cliport		= bpf_ntohs(BPF_CORE_READ(pconn, cport));
	evt.virtport		= bpf_ntohs(BPF_CORE_READ(pconn, vport));
	evt.destport		= bpf_ntohs(BPF_CORE_READ(pconn, dport));

	bpf_perf_event_output(ctx, &ip_vs_new_conn_event, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

	return 0;
}	

SEC("kretprobe/ip_vs_conn_new")
int BPF_KRETPROBE(trace_ip_vs_conn_return, void *pc1)
{
	struct ip_vs_conn___gy 		*pconn = (struct ip_vs_conn___gy *)pc1;

	return send_ip_vs_conn_info(ctx, pconn);
}	

SEC("kprobe/ip_vs_conn_seq_show")
int BPF_KPROBE(trace_ip_vs_conn_show, void *seq, void *pc1)
{
	struct ip_vs_conn___gy 		*pconn = (struct ip_vs_conn___gy *)pc1;

	(void)seq;

	if ((uint64_t)pconn > 7) {
		return send_ip_vs_conn_info(ctx, pconn);
	}
	return 0;
}	

