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

#ifndef 		CLONE_NEWNS

#define 		CLONE_NEWNS		0x00020000	/* New mount namespace group */
#define 		CLONE_NEWUTS		0x04000000	/* New utsname namespace */
#define 		CLONE_NEWIPC		0x08000000	/* New ipc namespace */
#define 		CLONE_NEWPID		0x20000000	/* New pid namespace */
#define 		CLONE_NEWNET		0x40000000	/* New network namespace */

#endif

#ifndef 		CLONE_NEWCGROUP

#define 		CLONE_NEWCGROUP		0x02000000	/* New cgroup namespace */

#endif

#include		"../common/gy_ebpf_kernel.h"


struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} tcp_ipv4_event SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} tcp_ipv6_event SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} tcp_listener_event SEC(".maps");


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
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} create_ns_event SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} cgroup_migrate_event SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct ipv4_tuple_t);
	__type(value, struct pid_comm_t);
} tuplepid_ipv4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct ipv6_tuple_t);
	__type(value, struct pid_comm_t);
} tuplepid_ipv6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u64);
	__type(value, struct sock *);
} connectsock SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u64);
	__type(value, struct sock *);
} connectsock_ipv6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} config_tcp_response SEC(".maps");


char LICENSE[] SEC("license") = "GPL";


SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(trace_connect_v4_entry, struct sock *sk)
{
	u64 			pid = bpf_get_current_pid_tgid();

	// stash the sock ptr for lookup on return
	bpf_map_update_elem(&connectsock, &pid, &sk, BPF_ANY);

	return 0;
}

static int do_trace_connect_v4_return(int ret, struct sock *sk, u64 pid)
{
	struct ipv4_tuple_t 	t = {};

	if (!read_ipv4_tuple(&t, sk)) {
		return 0;
	}

	struct pid_comm_t 	p = {};

	p.pid_tid 		= pid;

	bpf_get_current_comm(&p.comm, sizeof(p.comm));

	bpf_map_update_elem(&tuplepid_ipv4, &t, &p, BPF_ANY);

	return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(trace_connect_v4_return, int ret)
{
	u64 			pid = bpf_get_current_pid_tgid();

	struct sock 		**skpp;

	skpp = bpf_map_lookup_elem(&connectsock, &pid);
	if (skpp == NULL) {
		return 0;       // missed entry
	}

	bpf_map_delete_elem(&connectsock, &pid);

	if (ret != 0) {
		// failed to send SYNC packet, may not have populated
		// socket __sk_common.{skc_rcv_saddr, ...}
		return 0;
	}

	struct sock 		*sk = *skpp;

	return do_trace_connect_v4_return(ret, sk, pid);
}


SEC("fexit/tcp_v4_connect")
int BPF_PROG(fexit_trace_connect_v4_return, struct sock *sk, struct sockaddr *uaddr, int addr_len, int ret)
{
	u64 			pid = bpf_get_current_pid_tgid();

	if (!sk) {
		return 0;
	}

	return do_trace_connect_v4_return(ret, sk, pid);
}	

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(trace_connect_v6_entry, struct sock *sk)
{
	u64 			pid = bpf_get_current_pid_tgid();

	// stash the sock ptr for lookup on return
	bpf_map_update_elem(&connectsock_ipv6, &pid, &sk, BPF_ANY);

	return 0;
}


static int do_trace_connect_v6_return(int ret, struct sock *sk, u64 pid)
{
	struct ipv6_tuple_t 	t = {};

	if (!read_ipv6_tuple(&t, sk)) {
		return 0;
	}

	struct pid_comm_t 	p = {};

	p.pid_tid 		= pid;

	bpf_get_current_comm(&p.comm, sizeof(p.comm));

	bool 			is_src_ipv4_mapped = is_ipv4_mapped_ipv6(t.saddr);
	bool 			is_dest_ipv4_mapped = is_ipv4_mapped_ipv6(t.daddr);

	if (is_src_ipv4_mapped || is_dest_ipv4_mapped) {
		struct ipv4_tuple_t		t4 = {};
		u8				*pipbuf = (u8 *)&t.saddr, *pipbuf2 = (u8 *)&t.daddr;

		__builtin_memcpy(&t4.saddr, pipbuf + 12, 4);
		__builtin_memcpy(&t4.daddr, pipbuf2 + 12, 4);

		t4.sport 	= t.sport;
		t4.dport	= t.dport;
		t4.netns	= t.netns;

		bpf_map_update_elem(&tuplepid_ipv4, &t4, &p, BPF_ANY);

		return 0;
	}	

	bpf_map_update_elem(&tuplepid_ipv6, &t, &p, BPF_ANY);

	return 0;
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(trace_connect_v6_return, int ret)
{
	u64 			pid = bpf_get_current_pid_tgid();

	struct sock 		**skpp;

	skpp = bpf_map_lookup_elem(&connectsock_ipv6, &pid);
	if (skpp == NULL) {
		return 0;       // missed entry
	}

	bpf_map_delete_elem(&connectsock_ipv6, &pid);

	if (ret != 0) {
		return 0;
	}

	// pull in details
	struct sock 		*sk = *skpp;

	return do_trace_connect_v6_return(ret, sk, pid);
}


SEC("fexit/tcp_v6_connect")
int BPF_PROG(fexit_trace_connect_v6_return, struct sock *sk, struct sockaddr *uaddr, int addr_len, int ret)
{
	u64 			pid = bpf_get_current_pid_tgid();

	if (!sk) {
		return 0;
	}

	return do_trace_connect_v6_return(ret, sk, pid);
}

static int do_trace_tcp_set_state_entry(void *ctx, struct sock *sk, int state)
{
	if (state != TCP_ESTABLISHED && state != TCP_CLOSE) {
		return 0;
	}

	u8 			ipver = 0;
	u16			family = 0;

	u8 			oldstate;
	
	oldstate = BPF_CORE_READ(sk, __sk_common.skc_state);

	if (oldstate == TCP_SYN_RECV || oldstate == TCP_NEW_SYN_RECV) {
		return 0;
	}

	family = BPF_CORE_READ(sk, __sk_common.skc_family);

	if (family == AF_INET) {
		ipver = 4;
		
		struct ipv4_tuple_t 	t = {};

		if (!read_ipv4_tuple(&t, sk)) {
			return 0;
		}

		if (state == TCP_CLOSE) {
			bpf_map_delete_elem(&tuplepid_ipv4, &t);
			return 0;
		}

		struct pid_comm_t 	*p;

		p = bpf_map_lookup_elem(&tuplepid_ipv4, &t);

		if (p == NULL) {
			return 0;       // missed entry
		}

		struct tcp_ipv4_event_t evt4 = {};

		evt4.ts_ns 	= bpf_ktime_get_ns();
		evt4.type 	= TCP_EVENT_TYPE_CONNECT;
		evt4.pid 	= p->pid_tid >> 32;
		evt4.tid 	= p->pid_tid & ~0u;
		evt4.ipver 	= ipver;
		evt4.saddr 	= t.saddr;
		evt4.daddr 	= t.daddr;
		evt4.sport 	= bpf_ntohs(t.sport);
		evt4.dport 	= bpf_ntohs(t.dport);
		evt4.netns 	= t.netns;

		__builtin_memcpy(&evt4.comm, p->comm, TASK_COMM_LEN);
		evt4.comm[TASK_COMM_LEN - 1] = '\0';

		bpf_perf_event_output(ctx, &tcp_ipv4_event, BPF_F_CURRENT_CPU, &evt4, sizeof(evt4));
		
		bpf_map_delete_elem(&tuplepid_ipv4, &t);

	} 
	else if (family == AF_INET6) {
		ipver = 6;

		struct ipv6_tuple_t 	t = {};

		if (!read_ipv6_tuple(&t, sk)) {
			return 0;
		}

		if (state == TCP_CLOSE) {
			bpf_map_delete_elem(&tuplepid_ipv6, &t);
			return 0;
		}

		struct pid_comm_t 	*p;
		u64 			pid_tid = 0;
		struct tcp_ipv6_event_t evt6 = {};

		p = bpf_map_lookup_elem(&tuplepid_ipv6, &t);
		if (p == NULL) {
			bool 			is_src_ipv4_mapped = is_ipv4_mapped_ipv6(t.saddr);
			bool 			is_dest_ipv4_mapped = is_ipv4_mapped_ipv6(t.daddr);

			if (is_src_ipv4_mapped || is_dest_ipv4_mapped) {
				struct ipv4_tuple_t		t4 = {};
				u8				*pipbuf = (u8 *)&t.saddr, *pipbuf2 = (u8 *)&t.daddr;

				__builtin_memcpy(&t4.saddr, pipbuf + 12, 4);
				__builtin_memcpy(&t4.daddr, pipbuf2 + 12, 4);

				t4.sport 	= t.sport;
				t4.dport	= t.dport;
				t4.netns	= t.netns;
		
				p = bpf_map_lookup_elem(&tuplepid_ipv4, &t4);
				if (p) {
					pid_tid 	= p->pid_tid;

					__builtin_memcpy(&evt6.comm, p->comm, TASK_COMM_LEN);
					
					bpf_map_delete_elem(&tuplepid_ipv4, &t4);

					p = NULL;
					
					goto sendipv6;
				}	
			}

			return 0;       // missed entry
		}
		else {
			pid_tid = p->pid_tid;
		}	

sendipv6 :
		evt6.ts_ns 	= bpf_ktime_get_ns();
		evt6.type 	= TCP_EVENT_TYPE_CONNECT;
		evt6.pid 	= pid_tid >> 32;
		evt6.tid 	= pid_tid & ~0u;
		evt6.ipver 	= ipver;
		evt6.saddr 	= t.saddr;
		evt6.daddr 	= t.daddr;
		evt6.sport 	= bpf_ntohs(t.sport);
		evt6.dport 	= bpf_ntohs(t.dport);
		evt6.netns 	= t.netns;

		if (p) {
			__builtin_memcpy(&evt6.comm, p->comm, TASK_COMM_LEN);

			bpf_map_delete_elem(&tuplepid_ipv6, &t);
		}

		evt6.comm[TASK_COMM_LEN - 1] = '\0';

		bpf_perf_event_output(ctx, &tcp_ipv6_event, BPF_F_CURRENT_CPU, &evt6, sizeof(evt6));
	}
	// else drop

	return 0;
}

SEC("kprobe/tcp_set_state")
int BPF_KPROBE(trace_tcp_set_state_entry, struct sock *sk, int state)
{
	return do_trace_tcp_set_state_entry(ctx, sk, state);
}

SEC("fentry/tcp_set_state")
int BPF_PROG(fentry_trace_tcp_set_state_entry, struct sock *sk, int state)
{
	return do_trace_tcp_set_state_entry(ctx, sk, state);
}

static int do_trace_close_entry(void *ctx, struct sock *sk)
{
	u64 			pid = bpf_get_current_pid_tgid();
	u8 			oldstate = BPF_CORE_READ(sk, __sk_common.skc_state);

	// Don't generate close events for connections that were never
	// established in the first place.
	if (oldstate == TCP_SYN_SENT || oldstate == TCP_SYN_RECV || oldstate == TCP_NEW_SYN_RECV) {
		return 0;
	}	

	u8 			ipver = 0;
	u16			family = 0;

	family = BPF_CORE_READ(sk, __sk_common.skc_family); 

	if (family == AF_INET) {
		ipver = 4;

		struct ipv4_tuple_t 	t = {};

		if (!read_ipv4_tuple(&t, sk)) {
			bpf_map_delete_elem(&tuplepid_ipv4, &t);
			return 0;
		}

		struct tcp_sock		*ptcp = (struct tcp_sock *)sk;

		struct tcp_ipv4_event_t evt4 = {};

		evt4.ts_ns 		= bpf_ktime_get_ns();
		evt4.bytes_received 	= BPF_CORE_READ(ptcp, bytes_received);
		evt4.bytes_acked	= BPF_CORE_READ(ptcp, bytes_acked);

		if (BPF_CORE_READ(sk, sk_max_ack_backlog) > 0) {
			evt4.type 	= TCP_EVENT_TYPE_CLOSE_SER;
		}
		else {
			evt4.type 	= TCP_EVENT_TYPE_CLOSE_CLI;
		}		
		evt4.pid 		= pid >> 32;
		evt4.tid 		= pid & ~0u;
		evt4.ipver 		= ipver;
		evt4.saddr 		= t.saddr;
		evt4.daddr 		= t.daddr;
		evt4.sport 		= bpf_ntohs(t.sport);
		evt4.dport 		= bpf_ntohs(t.dport);
		evt4.netns 		= t.netns;

		bpf_get_current_comm(&evt4.comm, sizeof(evt4.comm));

		bpf_perf_event_output(ctx, &tcp_ipv4_event, BPF_F_CURRENT_CPU, &evt4, sizeof(evt4));

	} 
	else if (family == AF_INET6) {
		ipver = 6;

		struct ipv6_tuple_t 	t = {};

		if (!read_ipv6_tuple(&t, sk)) {
			bpf_map_delete_elem(&tuplepid_ipv6, &t);
			return 0;
		}

		bool 			is_src_ipv4_mapped = is_ipv4_mapped_ipv6(t.saddr);
		bool 			is_dest_ipv4_mapped = is_ipv4_mapped_ipv6(t.daddr);

		if (is_src_ipv4_mapped || is_dest_ipv4_mapped) {
			struct ipv4_tuple_t		t4;
			u8				*pipbuf = (u8 *)&t.saddr, *pipbuf2 = (u8 *)&t.daddr;

			__builtin_memcpy(&t4.saddr, pipbuf + 12, 4);
			__builtin_memcpy(&t4.daddr, pipbuf2 + 12, 4);

			t4.sport 	= t.sport;
			t4.dport	= t.dport;
			t4.netns	= t.netns;

			struct tcp_sock		*ptcp = (struct tcp_sock *)sk;

			struct tcp_ipv4_event_t evt4 = {};

			evt4.ts_ns 		= bpf_ktime_get_ns();
			evt4.bytes_received 	= BPF_CORE_READ(ptcp, bytes_received);
			evt4.bytes_acked	= BPF_CORE_READ(ptcp, bytes_acked);

			if (BPF_CORE_READ(sk, sk_max_ack_backlog) > 0) {
				evt4.type 	= TCP_EVENT_TYPE_CLOSE_SER;
			}
			else {
				evt4.type 	= TCP_EVENT_TYPE_CLOSE_CLI;
			}		
			evt4.pid 		= pid >> 32;
			evt4.tid 		= pid & ~0u;
			evt4.ipver 		= 4;
			evt4.saddr 		= t4.saddr;
			evt4.daddr 		= t4.daddr;
			evt4.sport 		= bpf_ntohs(t4.sport);
			evt4.dport 		= bpf_ntohs(t4.dport);
			evt4.netns 		= t4.netns;

			bpf_get_current_comm(&evt4.comm, sizeof(evt4.comm));

			if (evt4.saddr != 0 && evt4.daddr != 0 && evt4.sport != 0 && evt4.dport != 0) {
				bpf_perf_event_output(ctx, &tcp_ipv4_event, BPF_F_CURRENT_CPU, &evt4, sizeof(evt4));
			}	
			
			return 0;
		}	

		struct tcp_sock		*ptcp = (struct tcp_sock *)sk;

		struct tcp_ipv6_event_t evt6 = {};

		evt6.ts_ns 		= bpf_ktime_get_ns();
		evt6.bytes_received 	= BPF_CORE_READ(ptcp, bytes_received);
		evt6.bytes_acked	= BPF_CORE_READ(ptcp, bytes_acked);

		if (BPF_CORE_READ(sk, sk_max_ack_backlog) > 0) {
			evt6.type 	= TCP_EVENT_TYPE_CLOSE_SER;
		}
		else {
			evt6.type 	= TCP_EVENT_TYPE_CLOSE_CLI;
		}		
		evt6.pid 		= pid >> 32;
		evt6.tid 		= pid & ~0u;
		evt6.ipver 		= ipver;
		evt6.saddr 		= t.saddr;
		evt6.daddr 		= t.daddr;
		evt6.sport 		= bpf_ntohs(t.sport);
		evt6.dport 		= bpf_ntohs(t.dport);
		evt6.netns 		= t.netns;

		bpf_get_current_comm(&evt6.comm, sizeof(evt6.comm));

		bpf_perf_event_output(ctx, &tcp_ipv6_event, BPF_F_CURRENT_CPU, &evt6, sizeof(evt6));
	}
	// else drop

	return 0;
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(trace_close_entry, struct sock *sk)
{
	return do_trace_close_entry(ctx, sk);
}

SEC("fentry/tcp_close")
int BPF_PROG(fentry_trace_close_entry, struct sock *sk)
{
	return do_trace_close_entry(ctx, sk);
}

static int do_trace_accept_return(void *ctx, struct sock *newsk)
{
	u64 			pid = bpf_get_current_pid_tgid();

	if (newsk == NULL) {
		return 0;
	}

	u16 			lport = 0, dport = 0;
	u32 			net_ns_inum = 0;
	u8 			ipver = 0;

	BPF_CORE_READ_INTO(&dport, newsk, __sk_common.skc_dport);
	BPF_CORE_READ_INTO(&lport, newsk, __sk_common.skc_num);

	if (bpf_core_field_exists(newsk->__sk_common.skc_net)) {
		BPF_CORE_READ_INTO(&net_ns_inum, newsk, __sk_common.skc_net.net, ns.inum);
	}

	u16			family = 0;

	family = BPF_CORE_READ(newsk, __sk_common.skc_family); 

	if (family == AF_INET) {
		ipver = 4;

		struct tcp_ipv4_event_t 	evt4 = {};

		evt4.ts_ns 	= bpf_ktime_get_ns();
		evt4.type 	= TCP_EVENT_TYPE_ACCEPT;
		evt4.netns 	= net_ns_inum;
		evt4.pid 	= pid >> 32;
		evt4.tid 	= pid & ~0u;
		evt4.ipver 	= ipver;

		BPF_CORE_READ_INTO(&evt4.saddr, newsk, __sk_common.skc_rcv_saddr);
		BPF_CORE_READ_INTO(&evt4.daddr, newsk, __sk_common.skc_daddr);

		evt4.sport 	= lport;
		evt4.dport 	= bpf_ntohs(dport);

		bpf_get_current_comm(&evt4.comm, sizeof(evt4.comm));

		// do not send event if IP address is 0.0.0.0 or port is 0
		if (evt4.saddr != 0 && evt4.daddr != 0 && evt4.sport != 0 && evt4.dport != 0) {
			bpf_perf_event_output(ctx, &tcp_ipv4_event, BPF_F_CURRENT_CPU, &evt4, sizeof(evt4));
		}

	} 
	else if (family == AF_INET6) {
		ipver = 6;

		struct tcp_ipv6_event_t	evt6 = {};

		evt6.ts_ns 	= bpf_ktime_get_ns();
		evt6.type 	= TCP_EVENT_TYPE_ACCEPT;
		evt6.netns 	= net_ns_inum;
		evt6.pid 	= pid >> 32;
		evt6.tid 	= pid & ~0u;
		evt6.ipver 	= ipver;

		BPF_CORE_READ_INTO(&evt6.saddr, newsk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&evt6.daddr, newsk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);

		evt6.sport 	= lport;
		evt6.dport 	= bpf_ntohs(dport);

		bpf_get_current_comm(&evt6.comm, sizeof(evt6.comm));

		bool 			is_src_ipv4_mapped = is_ipv4_mapped_ipv6(evt6.saddr);
		bool 			is_dest_ipv4_mapped = is_ipv4_mapped_ipv6(evt6.daddr);

		if (is_src_ipv4_mapped || is_dest_ipv4_mapped) {
			struct ipv4_tuple_t		t4;
			u8				*pipbuf = (u8 *)&evt6.saddr, *pipbuf2 = (u8 *)&evt6.daddr;

			__builtin_memcpy(&t4.saddr, pipbuf + 12, 4);
			__builtin_memcpy(&t4.daddr, pipbuf2 + 12, 4);

			struct tcp_ipv4_event_t evt4 = {};

			evt4.ts_ns 	= evt6.ts_ns;
			evt4.type 	= evt6.type;
			evt4.pid 	= evt6.pid;
			evt4.tid 	= evt6.tid;
			evt4.ipver 	= 4;
			evt4.saddr 	= t4.saddr;
			evt4.daddr 	= t4.daddr;
			evt4.sport 	= evt6.sport;
			evt4.dport 	= evt6.dport;
			evt4.netns 	= evt6.netns;

			__builtin_memcpy(&evt4.comm, evt6.comm, sizeof(evt4.comm));

			if (evt4.saddr != 0 && evt4.daddr != 0 && evt4.sport != 0 && evt4.dport != 0) {
				bpf_perf_event_output(ctx, &tcp_ipv4_event, BPF_F_CURRENT_CPU, &evt4, sizeof(evt4));
			}	
			
			return 0;
		}	

		// do not send event if IP address is 0.0.0.0 or port is 0
		if (evt6.saddr != 0 && evt6.daddr != 0 && evt6.sport != 0 && evt6.dport != 0) {
			bpf_perf_event_output(ctx, &tcp_ipv6_event, BPF_F_CURRENT_CPU, &evt6, sizeof(evt6));
		}
	}
	// else drop

	return 0;
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(trace_accept_return, struct sock *newsk)
{
	return do_trace_accept_return(ctx, newsk);
}	


SEC("fexit/inet_csk_accept")
int BPF_PROG(fexit_trace_accept_return, struct sock *sk, int flags, int *err, bool kern, struct sock *newsk)
{
	return do_trace_accept_return(ctx, newsk);
}	


SEC("kprobe/create_new_namespaces")
int BPF_KPROBE(trace_create_ns, u64 flags)
{
	if (!(flags & (CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWCGROUP))) {
		return 0;
	}

	struct create_ns_data_t		nsdata = {};
	u64 				pid = bpf_get_current_pid_tgid();

	nsdata.ts_ns 			= bpf_ktime_get_ns();
	nsdata.pid 			= pid >> 32;
	nsdata.tid 			= pid & ~0u;
	nsdata.flags 			= flags;

	bpf_get_current_comm(&nsdata.comm, sizeof(nsdata.comm));

	bpf_perf_event_output(ctx, &create_ns_event, BPF_F_CURRENT_CPU, &nsdata, sizeof(nsdata));

	return 0;
}	


SEC("kprobe/inet_listen")
int BPF_KPROBE(trace_inet_listen, struct socket *sock, int backlog)
{
	struct sock 			*sk = BPF_CORE_READ(sock, sk);
	struct inet_sock 		*inet = (struct inet_sock *)sk;

	u16 				family 	= BPF_CORE_READ(sk, __sk_common.skc_family);
	u64 				pid = bpf_get_current_pid_tgid();
	
	struct tcp_listener_event_t 	evt = {};

	evt.ts_ns 	= bpf_ktime_get_ns();

	if (bpf_core_field_exists(sk->__sk_common.skc_net)) {
		BPF_CORE_READ_INTO(&evt.netns, sk, __sk_common.skc_net.net, ns.inum);
	}	

	evt.pid 	= pid >> 32;
	evt.tid 	= pid & ~0u;

	if (family == AF_INET) {
		evt.ipver 	= 4;
		BPF_CORE_READ_INTO(&evt.addr.v4addr, inet, sk.__sk_common.skc_rcv_saddr);
	} 
	else if (family == AF_INET6) {
		evt.ipver 	= 6;
		BPF_CORE_READ_INTO(&evt.addr.v6addr, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
	}
	else {
		return 0;
	}

	BPF_CORE_READ_INTO(&evt.lport, inet, inet_sport);
	evt.lport 	= bpf_ntohs(evt.lport);
	
	evt.backlog	= backlog;

	bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

	bpf_perf_event_output(ctx, &tcp_listener_event, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

	return 0;
}	

static int do_trace_ipv4_xmit(void *ctx, struct sock *sk)
{
	struct tcp_sock			*ptcp = (struct tcp_sock *)sk;
	u64				bytes_received = 0;
	u32				sk_max_ack_backlog = 0, lrcvtime = 0, lsndtime = 0, rcv_tstamp = 0;

	BPF_CORE_READ_INTO(&bytes_received, ptcp, bytes_received);
	if (bytes_received == 0) {
		return 0;
	}

	BPF_CORE_READ_INTO(&sk_max_ack_backlog, sk, sk_max_ack_backlog);
	if (sk_max_ack_backlog == 0) {
		return 0;
	}	

	if (!check_family(sk, AF_INET)) {
		return 0;
	}	

	BPF_CORE_READ_INTO(&lrcvtime, ptcp, inet_conn.icsk_ack.lrcvtime);
	BPF_CORE_READ_INTO(&rcv_tstamp, ptcp, rcv_tstamp);

	if (lrcvtime + 10 < rcv_tstamp) {
		return 0;
	}	

	BPF_CORE_READ_INTO(&lsndtime, ptcp, lsndtime);

	if (lsndtime < lrcvtime) {
		return 0;
	}	

	uint64_t 		*pto_enable;
	u32 			key_config = 0;
	
	pto_enable = bpf_map_lookup_elem(&config_tcp_response, &key_config);

	if (pto_enable && (ENABLE_PERF_PROBE != *pto_enable)) {
		return 0;
	}	

	struct tcp_ipv4_resp_event_t evt4 = {};

	if (!read_ipv4_tuple(&evt4.tup, sk)) {
		return 0;
	}

	evt4.lsndtime		= lsndtime;
	evt4.lrcvtime		= lrcvtime;

	bpf_perf_event_output(ctx, &ipv4_xmit_perf, BPF_F_CURRENT_CPU, &evt4, sizeof(evt4));
	
	return 0;
}

SEC("kprobe/__ip_queue_xmit")
int BPF_KPROBE(trace_ipv4_xmit, struct sock *sk)
{
	return do_trace_ipv4_xmit(ctx, sk);
}	

SEC("fentry/__ip_queue_xmit")
int BPF_PROG(fentry_trace_ipv4_xmit, struct sock *sk)
{
	return do_trace_ipv4_xmit(ctx, sk);
}	


static int do_trace_ipv6_xmit(void *ctx, struct sock *sk)
{
	struct tcp_sock			*ptcp = (struct tcp_sock *)sk;
	u64				bytes_received = 0;
	u32				sk_max_ack_backlog = 0, lrcvtime = 0, lsndtime = 0, rcv_tstamp = 0;

	BPF_CORE_READ_INTO(&bytes_received, ptcp, bytes_received);
	if (bytes_received == 0) {
		return 0;
	}

	BPF_CORE_READ_INTO(&sk_max_ack_backlog, sk, sk_max_ack_backlog);
	if (sk_max_ack_backlog == 0) {
		return 0;
	}	

	if (!check_family(sk, AF_INET6)) {
		return 0;
	}	

	BPF_CORE_READ_INTO(&lrcvtime, ptcp, inet_conn.icsk_ack.lrcvtime);
	BPF_CORE_READ_INTO(&rcv_tstamp, ptcp, rcv_tstamp);

	if (lrcvtime + 10 < rcv_tstamp) {
		return 0;
	}	

	BPF_CORE_READ_INTO(&lsndtime, ptcp, lsndtime);

	if (lsndtime < lrcvtime) {
		return 0;
	}	

	uint64_t 		*pto_enable;
	u32 			key_config = 0;
	
	pto_enable = bpf_map_lookup_elem(&config_tcp_response, &key_config);

	if (pto_enable && (ENABLE_PERF_PROBE != *pto_enable)) {
		return 0;
	}	

	struct tcp_ipv6_resp_event_t evt6 = {};

	if (!read_ipv6_tuple(&evt6.tup, sk)) {
		return 0;
	}

	bool 			is_src_ipv4_mapped = is_ipv4_mapped_ipv6(evt6.tup.saddr);
	bool 			is_dest_ipv4_mapped = is_ipv4_mapped_ipv6(evt6.tup.daddr);

	if (is_src_ipv4_mapped || is_dest_ipv4_mapped) {
		u8				*pipbuf = (u8 *)&evt6.tup.saddr, *pipbuf2 = (u8 *)&evt6.tup.daddr;
		struct tcp_ipv4_resp_event_t 	evt4 = {};

		read_ipv4_tuple(&evt4.tup, sk);

		__builtin_memcpy(&evt4.tup.saddr, pipbuf + 12, 4);
		__builtin_memcpy(&evt4.tup.daddr, pipbuf2 + 12, 4);

		evt4.lsndtime		= lsndtime;
		evt4.lrcvtime		= lrcvtime;
		
		bpf_perf_event_output(ctx, &ipv4_xmit_perf, BPF_F_CURRENT_CPU, &evt4, sizeof(evt4));
		
		return 0;
	}

	evt6.lsndtime		= lsndtime;
	evt6.lrcvtime		= lrcvtime;

	bpf_perf_event_output(ctx, &ipv6_xmit_perf, BPF_F_CURRENT_CPU, &evt6, sizeof(evt6));

	return 0;
}

SEC("kprobe/inet6_csk_xmit")
int BPF_KPROBE(trace_ipv6_xmit, struct sock *sk)
{
	return do_trace_ipv6_xmit(ctx, sk);
}	

SEC("fentry/inet6_csk_xmit")
int BPF_PROG(fentry_trace_ipv6_xmit, struct sock *sk)
{
	return do_trace_ipv6_xmit(ctx, sk);
}	


SEC("kprobe/cgroup_migrate")
int BPF_KPROBE(trace_cgroup_migrate, struct task_struct *task, bool threadgroup)
{
	struct cgroup_migrate_event_t 	evt = {};

	evt.pid 	= BPF_CORE_READ(task, tgid);
	evt.tid 	= BPF_CORE_READ(task, pid);
	evt.threadgroup	= threadgroup;

	bpf_perf_event_output(ctx, &cgroup_migrate_event, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

	return 0;
}


