
static const char gbpf_kernel_buf1[] = R"(

#ifdef 			USE_RANDOMIZE_MACRO
#undef 			randomized_struct_fields_start
#undef 			randomized_struct_fields_end

#define 		randomized_struct_fields_start  struct {
#define 		randomized_struct_fields_end    };
#endif

#ifdef 			asm_inline
#undef 			asm_inline
#define 		asm_inline asm
#endif

#ifdef 			asm_volatile_goto
#undef 			asm_volatile_goto
#endif

#define 		asm_volatile_goto(x...) asm volatile("invalid use of asm_volatile_goto")

#include 		<uapi/linux/ptrace.h>

#pragma 		clang diagnostic push

#pragma 		clang diagnostic ignored "-Wtautological-compare"
#pragma 		clang diagnostic ignored "-Wenum-conversion"


#ifndef 		BPF_F_RDONLY_PROG
#define 		BPF_F_RDONLY_PROG  	(1U << 7)
#endif

#ifndef 		BPF_F_WRONLY_PROG
#define 		BPF_F_WRONLY_PROG       (1U << 8)
#endif

#include 		<net/sock.h>

#undef 			dynamic_pr_debug
#define 		dynamic_pr_debug(fmt, ...) 
#include 		<net/tcp.h>
#include 		<net/inet_connection_sock.h>

#pragma 		clang diagnostic pop

#include 		<net/inet_sock.h>
#include 		<net/net_namespace.h>

#include 		<bcc/proto.h>

#include 		<linux/sched.h>

)";


static const char gbpf_kernel_buf3[] = R"(

BPF_PERF_OUTPUT(tcp_ipv4_event);	// PROBE_TCP_CONN_IPv4
BPF_PERF_OUTPUT(tcp_ipv6_event);	// PROBE_TCP_CONN_IPv6

BPF_PERF_OUTPUT(tcp_listener_event);	// PROBE_TCP_LISTENER

BPF_PERF_OUTPUT(ipv4_xmit_perf);	// PROBE_TCP_RESPONSE_IPv4
BPF_PERF_OUTPUT(ipv6_xmit_perf);	// PROBE_TCP_RESPONSE_IPv6

BPF_PERF_OUTPUT(create_ns_event);	// PROBE_CREATE_NS

BPF_PERF_OUTPUT(cgroup_migrate_event);	// PROBE_CGROUP_MIGRATE

BPF_PERF_OUTPUT(ip_vs_new_conn_event);	// PROBE_IP_VS_NEW_CONN

BPF_HASH(tuplepid_ipv4, struct ipv4_tuple_t, struct pid_comm_t);
BPF_HASH(tuplepid_ipv6, struct ipv6_tuple_t, struct pid_comm_t);

BPF_HASH(connectsock, u64, struct sock *);
BPF_HASH(connectsock_ipv6, u64, struct sock *);

#ifdef USE_PERCPU_TABLE
BPF_TABLE("percpu_array", int, u64, config_tcp_response, 1);
#else
BPF_TABLE("array", int, u64, config_tcp_response, 1);
#endif

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
	if (unlikely(saddr == 0 || daddr == 0 || sport == 0 || dport == 0)) {
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
	if (unlikely(saddr == 0 || daddr == 0 || sport == 0 || dport == 0)) {
		return 0;
	}

	return 1;
}

static inline bool is_ipv4_mapped_ipv6(unsigned __int128 ip128_be)
{
	u8 		*pipbuf = (u8 *)&ip128_be;

	if (
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__		
		(0 == (ip128_be >> 64ull))  
#else
		(0 == (ip128_be & ~0ull))  
#endif		
			
		&& (0 == memcmp(pipbuf + 8, "\x0\x0\xff\xff", 4))) {

		return true;
	}

	return false;	
}
	
int trace_connect_v4_entry(struct pt_regs *ctx, struct sock *sk)
{
	u64 			pid = bpf_get_current_pid_tgid();

	// stash the sock ptr for lookup on return
	connectsock.update(&pid, &sk);

	return 0;
}

int trace_connect_v4_return(struct pt_regs *ctx)
{
	int 			ret = PT_REGS_RC(ctx);
	u64 			pid = bpf_get_current_pid_tgid();

	struct sock 		**skpp;

	skpp = connectsock.lookup(&pid);
	if (skpp == NULL) {
		return 0;       // missed entry
	}

	connectsock.delete(&pid);

	if (ret != 0) {
		// failed to send SYNC packet, may not have populated
		// socket __sk_common.{skc_rcv_saddr, ...}
		return 0;
	}

	// pull in details
	struct sock 		*skp = *skpp;
	struct ipv4_tuple_t 	t = {};

	if (!read_ipv4_tuple(&t, skp)) {
		return 0;
	}

	struct pid_comm_t 	p = {};

	p.pid_tid 		= pid;

	bpf_get_current_comm(p.comm, sizeof(p.comm));

	tuplepid_ipv4.update(&t, &p);

	return 0;
}

int trace_connect_v6_entry(struct pt_regs *ctx, struct sock *sk)
{
	u64 			pid = bpf_get_current_pid_tgid();

	// stash the sock ptr for lookup on return
	connectsock_ipv6.update(&pid, &sk);

	return 0;
}

int trace_connect_v6_return(struct pt_regs *ctx)
{
	int 			ret = PT_REGS_RC(ctx);
	u64 			pid = bpf_get_current_pid_tgid();

	struct sock 		**skpp;

	skpp = connectsock_ipv6.lookup(&pid);
	if (skpp == NULL) {
		return 0;       // missed entry
	}

	connectsock_ipv6.delete(&pid);

	if (ret != 0) {
		return 0;
	}

	// pull in details
	struct sock 		*skp = *skpp;
	struct ipv6_tuple_t 	t = {};

	if (!read_ipv6_tuple(&t, skp)) {
		return 0;
	}

	struct pid_comm_t 	p = {};

	p.pid_tid 		= pid;

	bpf_get_current_comm(p.comm, sizeof(p.comm));

	bool 			is_src_ipv4_mapped = is_ipv4_mapped_ipv6(t.saddr);
	bool 			is_dest_ipv4_mapped = is_ipv4_mapped_ipv6(t.daddr);

	if (is_src_ipv4_mapped || is_dest_ipv4_mapped) {
		struct ipv4_tuple_t		t4 = {};
		u8				*pipbuf = (u8 *)&t.saddr, *pipbuf2 = (u8 *)&t.daddr;

		memcpy(&t4.saddr, pipbuf + 12, 4);
		memcpy(&t4.daddr, pipbuf2 + 12, 4);

		t4.sport 	= t.sport;
		t4.dport	= t.dport;
		t4.netns	= t.netns;

		tuplepid_ipv4.update(&t4, &p);

		return 0;
	}	

	tuplepid_ipv6.update(&t, &p);

	return 0;
}

int trace_tcp_set_state_entry(struct pt_regs *ctx, struct sock *skp, int state)
{
	if (state != TCP_ESTABLISHED && state != TCP_CLOSE) {
		return 0;
	}

	u8 			ipver = 0;
	u16			family = 0;

	u8 			oldstate = skp->sk_state;

	if (oldstate == TCP_SYN_RECV || oldstate == TCP_NEW_SYN_RECV) {
		return 0;
	}

	family = skp->__sk_common.skc_family; 

	if (family == AF_INET) {
		ipver = 4;
		
		struct ipv4_tuple_t 	t = {};

		if (!read_ipv4_tuple(&t, skp)) {
			return 0;
		}

		if (state == TCP_CLOSE) {
			tuplepid_ipv4.delete(&t);
			return 0;
		}

		struct pid_comm_t 	*p;

		p = tuplepid_ipv4.lookup(&t);
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
		evt4.sport 	= ntohs(t.sport);
		evt4.dport 	= ntohs(t.dport);
		evt4.netns 	= t.netns;

		for (int i = 0; i < TASK_COMM_LEN; i++) {
			evt4.comm[i] = p->comm[i];
		}
		evt4.comm[TASK_COMM_LEN - 1] = '\0';

		tcp_ipv4_event.perf_submit(ctx, &evt4, sizeof(evt4));
		
		tuplepid_ipv4.delete(&t);

	} else if (family == AF_INET6) {
		ipver = 6;

		struct ipv6_tuple_t 	t = {};

		if (!read_ipv6_tuple(&t, skp)) {
			return 0;
		}

		if (state == TCP_CLOSE) {
			tuplepid_ipv6.delete(&t);
			return 0;
		}

		struct pid_comm_t 	*p;
		u64 			pid_tid = 0;
		struct tcp_ipv6_event_t evt6 = {};

		p = tuplepid_ipv6.lookup(&t);
		if (p == NULL) {
			bool 			is_src_ipv4_mapped = is_ipv4_mapped_ipv6(t.saddr);
			bool 			is_dest_ipv4_mapped = is_ipv4_mapped_ipv6(t.daddr);

			if (is_src_ipv4_mapped || is_dest_ipv4_mapped) {
				struct ipv4_tuple_t		t4 = {};
				u8				*pipbuf = (u8 *)&t.saddr, *pipbuf2 = (u8 *)&t.daddr;

				memcpy(&t4.saddr, pipbuf + 12, 4);
				memcpy(&t4.daddr, pipbuf2 + 12, 4);

				t4.sport 	= t.sport;
				t4.dport	= t.dport;
				t4.netns	= t.netns;
		
				p = tuplepid_ipv4.lookup(&t4);
				if (p) {
					pid_tid = p->pid_tid;
					for (int i = 0; i < TASK_COMM_LEN; i++) {
						evt6.comm[i] = p->comm[i];
					}
					tuplepid_ipv4.delete(&t4);

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
		evt6.sport 	= ntohs(t.sport);
		evt6.dport 	= ntohs(t.dport);
		evt6.netns 	= t.netns;

		if (p) {
			for (int i = 0; i < TASK_COMM_LEN; i++) {
				evt6.comm[i] = p->comm[i];
			}
			tuplepid_ipv6.delete(&t);
		}

		evt6.comm[TASK_COMM_LEN - 1] = '\0';

		tcp_ipv6_event.perf_submit(ctx, &evt6, sizeof(evt6));
	}
	// else drop

	return 0;
}

int trace_close_entry(struct pt_regs *ctx, struct sock *skp)
{
	u64 			pid = bpf_get_current_pid_tgid();
	u8 			oldstate = skp->sk_state;

	// Don't generate close events for connections that were never
	// established in the first place.
	if (oldstate == TCP_SYN_SENT || oldstate == TCP_SYN_RECV || oldstate == TCP_NEW_SYN_RECV) {
		return 0;
	}	

	u8 			ipver = 0;
	u16			family = 0;

	family = skp->__sk_common.skc_family; 

	if (family == AF_INET) {
		ipver = 4;

		struct ipv4_tuple_t 	t = {};

		if (!read_ipv4_tuple(&t, skp)) {
			tuplepid_ipv4.delete(&t);
			return 0;
		}

		struct tcp_sock		*ptcp = (struct tcp_sock *)skp;

		struct tcp_ipv4_event_t evt4 = {};

		evt4.ts_ns 		= bpf_ktime_get_ns();
		evt4.bytes_received 	= ptcp->bytes_received;
		evt4.bytes_acked	= ptcp->bytes_acked;

		if (skp->sk_max_ack_backlog > 0) {
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
		evt4.sport 		= ntohs(t.sport);
		evt4.dport 		= ntohs(t.dport);
		evt4.netns 		= t.netns;

		bpf_get_current_comm(evt4.comm, sizeof(evt4.comm));

		tcp_ipv4_event.perf_submit(ctx, &evt4, sizeof(evt4));

	} else if (family == AF_INET6) {
		ipver = 6;

		struct ipv6_tuple_t 	t = {};

		if (!read_ipv6_tuple(&t, skp)) {
			tuplepid_ipv6.delete(&t);
			return 0;
		}

		bool is_src_ipv4_mapped = is_ipv4_mapped_ipv6(t.saddr);
		bool is_dest_ipv4_mapped = is_ipv4_mapped_ipv6(t.daddr);

		if (is_src_ipv4_mapped || is_dest_ipv4_mapped) {
			struct ipv4_tuple_t		t4;
			u8				*pipbuf = (u8 *)&t.saddr, *pipbuf2 = (u8 *)&t.daddr;

			memcpy(&t4.saddr, pipbuf + 12, 4);
			memcpy(&t4.daddr, pipbuf2 + 12, 4);

			t4.sport 	= t.sport;
			t4.dport	= t.dport;
			t4.netns	= t.netns;

			struct tcp_sock		*ptcp = (struct tcp_sock *)skp;

			struct tcp_ipv4_event_t evt4 = {};

			evt4.ts_ns 		= bpf_ktime_get_ns();
			evt4.bytes_received 	= ptcp->bytes_received;
			evt4.bytes_acked	= ptcp->bytes_acked;

			if (skp->sk_max_ack_backlog > 0) {
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
			evt4.sport 		= ntohs(t4.sport);
			evt4.dport 		= ntohs(t4.dport);
			evt4.netns 		= t4.netns;

			bpf_get_current_comm(evt4.comm, sizeof(evt4.comm));

			if (evt4.saddr != 0 && evt4.daddr != 0 && evt4.sport != 0 && evt4.dport != 0) {
				tcp_ipv4_event.perf_submit(ctx, &evt4, sizeof(evt4));
			}	
			
			return 0;
		}	

		struct tcp_sock		*ptcp = (struct tcp_sock *)skp;

		struct tcp_ipv6_event_t evt6 = {};

		evt6.ts_ns 		= bpf_ktime_get_ns();
		evt6.bytes_received 	= ptcp->bytes_received;
		evt6.bytes_acked	= ptcp->bytes_acked;

		if (skp->sk_max_ack_backlog > 0) {
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
		evt6.sport 		= ntohs(t.sport);
		evt6.dport 		= ntohs(t.dport);
		evt6.netns 		= t.netns;

		bpf_get_current_comm(evt6.comm, sizeof(evt6.comm));

		tcp_ipv6_event.perf_submit(ctx, &evt6, sizeof(evt6));
	}
	// else drop

	return 0;
};

int trace_accept_return(struct pt_regs *ctx)
{
	struct sock 		*newsk = (struct sock *)PT_REGS_RC(ctx);
	u64 			pid = bpf_get_current_pid_tgid();

	if (newsk == NULL) {
		return 0;
	}

	// pull in details
	u16 			lport = 0, dport = 0;
	u32 			net_ns_inum = 0;
	u8 			ipver = 0;

	bpf_probe_read(&dport, sizeof(dport), &newsk->__sk_common.skc_dport);
	bpf_probe_read(&lport, sizeof(lport), &newsk->__sk_common.skc_num);

	// Get network namespace id, if kernel supports it
#ifdef CONFIG_NET_NS
	possible_net_t 		skc_net = {};

	bpf_probe_read(&skc_net, sizeof(skc_net), &newsk->__sk_common.skc_net);
	bpf_probe_read(&net_ns_inum, sizeof(net_ns_inum), &skc_net.net->ns.inum);
#endif
	u16			family = 0;

	family = newsk->__sk_common.skc_family; 

	if (family == AF_INET) {
		ipver = 4;

		struct tcp_ipv4_event_t 	evt4 = {};

		evt4.ts_ns 	= bpf_ktime_get_ns();
		evt4.type 	= TCP_EVENT_TYPE_ACCEPT;
		evt4.netns 	= net_ns_inum;
		evt4.pid 	= pid >> 32;
		evt4.tid 	= pid & ~0u;
		evt4.ipver 	= ipver;

		bpf_probe_read(&evt4.saddr, sizeof(evt4.saddr), &newsk->__sk_common.skc_rcv_saddr);
		bpf_probe_read(&evt4.daddr, sizeof(evt4.daddr), &newsk->__sk_common.skc_daddr);

		evt4.sport 	= lport;
		evt4.dport 	= ntohs(dport);

		bpf_get_current_comm(evt4.comm, sizeof(evt4.comm));

		// do not send event if IP address is 0.0.0.0 or port is 0
		if (evt4.saddr != 0 && evt4.daddr != 0 && evt4.sport != 0 && evt4.dport != 0) {
			tcp_ipv4_event.perf_submit(ctx, &evt4, sizeof(evt4));
		}

	} else if (family == AF_INET6) {
		ipver = 6;

		struct tcp_ipv6_event_t	evt6 = {};

		evt6.ts_ns 	= bpf_ktime_get_ns();
		evt6.type 	= TCP_EVENT_TYPE_ACCEPT;
		evt6.netns 	= net_ns_inum;
		evt6.pid 	= pid >> 32;
		evt6.tid 	= pid & ~0u;
		evt6.ipver 	= ipver;

		bpf_probe_read(&evt6.saddr, sizeof(evt6.saddr), newsk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		bpf_probe_read(&evt6.daddr, sizeof(evt6.daddr), newsk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

		evt6.sport 	= lport;
		evt6.dport 	= ntohs(dport);

		bpf_get_current_comm(evt6.comm, sizeof(evt6.comm));

		bool is_src_ipv4_mapped = is_ipv4_mapped_ipv6(evt6.saddr);
		bool is_dest_ipv4_mapped = is_ipv4_mapped_ipv6(evt6.daddr);

		if (is_src_ipv4_mapped || is_dest_ipv4_mapped) {
			struct ipv4_tuple_t		t4;
			u8				*pipbuf = (u8 *)&evt6.saddr, *pipbuf2 = (u8 *)&evt6.daddr;

			memcpy(&t4.saddr, pipbuf + 12, 4);
			memcpy(&t4.daddr, pipbuf2 + 12, 4);

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

			memcpy(evt4.comm, evt6.comm, sizeof(evt4.comm));

			if (evt4.saddr != 0 && evt4.daddr != 0 && evt4.sport != 0 && evt4.dport != 0) {
				tcp_ipv4_event.perf_submit(ctx, &evt4, sizeof(evt4));
			}	
			
			return 0;
		}	

		// do not send event if IP address is 0.0.0.0 or port is 0
		if (evt6.saddr != 0 && evt6.daddr != 0 && evt6.sport != 0 && evt6.dport != 0) {
			tcp_ipv6_event.perf_submit(ctx, &evt6, sizeof(evt6));
		}
	}
	// else drop

	return 0;
}

#ifndef 	CLONE_NEWCGROUP
#define 	CLONE_NEWCGROUP		0
#endif

int trace_create_ns(struct pt_regs *ctx, u64 flags)
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

	bpf_get_current_comm(nsdata.comm, sizeof(nsdata.comm));

	create_ns_event.perf_submit(ctx, &nsdata, sizeof(nsdata));

	return 0;
}	

int trace_inet_listen(struct pt_regs *ctx, struct socket *sock, int backlog)
{
	struct sock 			*sk = sock->sk;
	struct inet_sock 		*inet = (struct inet_sock *)sk;

	u16 				family 	= sk->__sk_common.skc_family;
	u64 				pid = bpf_get_current_pid_tgid();
	
	struct tcp_listener_event_t 	evt = {};

	evt.ts_ns 	= bpf_ktime_get_ns();

#ifdef CONFIG_NET_NS
	evt.netns 	= sk->__sk_common.skc_net.net->ns.inum;
#else
	evt.netns 	= 0;
#endif
	evt.pid 	= pid >> 32;
	evt.tid 	= pid & ~0u;

	if (family == AF_INET) {
		evt.ipver 	= 4;
		evt.addr.v4addr = inet->inet_rcv_saddr;
	} 
	else if (family == AF_INET6) {
		evt.ipver 	= 6;
		bpf_probe_read(&evt.addr.v6addr, sizeof(evt.addr.v6addr), sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
	}
	else {
		return 0;
	}

	evt.lport 	= inet->inet_sport;
	evt.lport 	= ntohs(evt.lport);
	
	evt.backlog	= backlog;

	bpf_get_current_comm(evt.comm, sizeof(evt.comm));

	tcp_listener_event.perf_submit(ctx, &evt, sizeof(evt));

	return 0;
}	

int trace_ip_xmit(struct pt_regs *ctx, struct sock *skp)
{
	struct tcp_sock		*ptcp = (struct tcp_sock *)skp;

	if (ptcp->bytes_received == 0) {
		return 0;
	}

	if (skp->sk_max_ack_backlog == 0) {
		return 0;
	}	

	u16 			family = skp->__sk_common.skc_family;
	
	if (!((family == AF_INET) || (family == AF_INET6))) {
		return 0;
	}	

	u32			lrcvtime = ptcp->inet_conn.icsk_ack.lrcvtime;
	u32			lsndtime = ptcp->lsndtime;

	if (lrcvtime + 10 < ptcp->rcv_tstamp) {
		return 0;
	}	

	if (lsndtime < lrcvtime) {
		return 0;
	}	

	uint64_t 		*pto_enable;
	int 			key_config = 0;
	
	pto_enable = config_tcp_response.lookup(&key_config);
	if (pto_enable && (ENABLE_PERF_PROBE != *pto_enable)) {
		return 0;
	}	

	if (family == AF_INET) {
		struct tcp_ipv4_resp_event_t evt4 = {};

		if (!read_ipv4_tuple(&evt4.tup, skp)) {
			return 0;
		}

		evt4.lsndtime		= lsndtime;
		evt4.lrcvtime		= lrcvtime;
		
		ipv4_xmit_perf.perf_submit(ctx, &evt4, sizeof(evt4));

		return 0;
	}
	else {
		struct tcp_ipv6_resp_event_t evt6 = {};

		if (!read_ipv6_tuple(&evt6.tup, skp)) {
			return 0;
		}

		bool is_src_ipv4_mapped = is_ipv4_mapped_ipv6(evt6.tup.saddr);
		bool is_dest_ipv4_mapped = is_ipv4_mapped_ipv6(evt6.tup.daddr);

		if (is_src_ipv4_mapped || is_dest_ipv4_mapped) {
			u8				*pipbuf = (u8 *)&evt6.tup.saddr, *pipbuf2 = (u8 *)&evt6.tup.daddr;
			struct tcp_ipv4_resp_event_t 	evt4 = {};

			read_ipv4_tuple(&evt4.tup, skp);

			memcpy(&evt4.tup.saddr, pipbuf + 12, 4);
			memcpy(&evt4.tup.daddr, pipbuf2 + 12, 4);

			evt4.lsndtime		= lsndtime;
			evt4.lrcvtime		= lrcvtime;
			
			ipv4_xmit_perf.perf_submit(ctx, &evt4, sizeof(evt4));
			
			return 0;
		}

		evt6.lsndtime		= lsndtime;
		evt6.lrcvtime		= lrcvtime;

		ipv6_xmit_perf.perf_submit(ctx, &evt6, sizeof(evt6));
		
		return 0;
	}
};

int trace_cgroup_migrate(struct pt_regs *ctx, struct task_struct *task, bool threadgroup)
{
	struct cgroup_migrate_event_t 	evt = {};

	evt.pid 	= task->tgid;
	evt.tid 	= task->pid;
	evt.threadgroup	= threadgroup;

	cgroup_migrate_event.perf_submit(ctx, &evt, sizeof(evt));

	return 0;
}	

static int send_ip_vs_conn_info(struct pt_regs *ctx, struct gy_ip_vs_conn *porigconn)
{
	struct gy_ip_vs_conn 		conn, *pconn;
	struct ip_vs_conn_event_t	evt = {};

	if (porigconn == NULL) {
		return 0;
	}

	pconn = &conn;

	bpf_probe_read(pconn, sizeof(conn), porigconn);

	if (pconn->protocol != IPPROTO_TCP) {
		return 0;
	}	

	bpf_probe_read(&evt.af, sizeof(evt.af), &pconn->af);
	bpf_probe_read(&evt.daf, sizeof(evt.daf), &pconn->daf);

	if (evt.af == AF_INET) {
		memcpy(&evt.cliaddr.v4addr, pconn->caddr, sizeof(evt.cliaddr.v4addr));
		memcpy(&evt.virtaddr.v4addr, pconn->vaddr, sizeof(evt.virtaddr.v4addr));
	}	
	else {
		memcpy(&evt.cliaddr.v6addr, pconn->caddr, sizeof(evt.cliaddr.v6addr));
		memcpy(&evt.virtaddr.v6addr, pconn->vaddr, sizeof(evt.virtaddr.v6addr));
	}	

	if (evt.daf == AF_INET) {
		memcpy(&evt.destaddr.v4addr, pconn->daddr, sizeof(evt.destaddr.v4addr));
	}	
	else {
		memcpy(&evt.destaddr.v6addr, pconn->daddr, sizeof(evt.destaddr.v6addr));
	}	

	evt.cliport		= ntohs(pconn->cport);
	evt.virtport		= ntohs(pconn->vport);
	evt.destport		= ntohs(pconn->dport);

	ip_vs_new_conn_event.perf_submit(ctx, &evt, sizeof(evt));

	return 0;
}	

int trace_ip_vs_conn_return(struct pt_regs *ctx)
{
	struct gy_ip_vs_conn		*porigconn = (struct gy_ip_vs_conn *)PT_REGS_RC(ctx);

	return send_ip_vs_conn_info(ctx, porigconn);
}	

int trace_ip_vs_conn_show(struct pt_regs *ctx, void *seq, struct gy_ip_vs_conn *porigconn)
{
	if ((uint64_t)porigconn > 7) {
		return send_ip_vs_conn_info(ctx, porigconn);
	}
	return 0;
}	

)";


