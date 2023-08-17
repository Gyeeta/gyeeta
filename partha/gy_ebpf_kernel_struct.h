
/* Auto generated header file. XXX Do not edit this file directly... */


static const char gbpf_kernel_buf2[] = R"(

#ifndef				_GY_EBPF_BPF_COMMON_H
#define				_GY_EBPF_BPF_COMMON_H

#if				defined (BCC_SEC) && !defined (__BCC__)

#define 			__BCC__

#endif

#ifndef 			AF_INET

#define 			AF_INET			2		/* IPv4	*/
#define 			AF_INET6		10		/* IPv6	*/

#endif

typedef uint8_t 		u8;
typedef uint16_t 		u16;
typedef uint32_t 		u32;
typedef uint64_t 		u64;

struct ipv4_tuple_t 
{
	u32 			saddr;
	u32 			daddr;
	u32 			netns;
	u16 			sport;
	u16 			dport;
};

struct ipv6_tuple_t 
{
	unsigned __int128 	saddr;
	unsigned __int128 	daddr;
	u32 			netns;
	u16 			sport;
	u16 			dport;
};

#if				defined (__clang__) && defined (__BPF__)

// TCP Flags 

#define				GY_TH_FIN		0x01
#define				GY_TH_SYN		0x02
#define				GY_TH_RST		0x04
#define				GY_TH_PUSH		0x08
#define				GY_TH_ACK		0x10
#define				GY_TH_URG		0x20
#define				GY_TH_ECE		0x40
#define				GY_TH_CWR		0x80

#endif

#if				defined (__clang__) && defined (__BPF__) && !defined (__BCC__)

#ifdef GY_BPF_DEBUG

#define				gy_bpf_printk(fmt, args...) bpf_printk(fmt, ##args)

#else

#define 			gy_bpf_printk(fmt, args...)

#endif


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

static __always_inline bool check_family(struct sock *sk, u16 expected_family) 
{
	u16 			family;
	
	BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);

	return (family == expected_family);
}

static __always_inline bool is_ipv4_mapped_ipv6(unsigned __int128 ip128_be)
{
	u8 			*pipbuf = (u8 *)&ip128_be;

	if (
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__		
		(0 == (ip128_be >> 64ull))  
#else
		(0 == (ip128_be & ~0ull))  
#endif		
			
		&& (0 == __builtin_memcmp(pipbuf + 8, "\x0\x0\xff\xff", 4))) {

		return true;
	}

	return false;	
}

static uint64_t align_up_8(uint64_t nsize)
{
	return ((nsize - 1) & ~7) + 8;
}

#endif // defined (__clang__) && defined (__BPF__)

#endif


//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

/*
 * XXX This file is also included from the ebpf Kernel program. So all C++ and userspace stuff needs 
 * to be within a #if defined
 */ 
#if				defined (__cplusplus) && defined (__GLIBCXX__)

#pragma				once

#include			"gy_common_inc.h"

namespace gyeeta {

#endif				// __cplusplus && __GLIBCXX__

#ifndef				BCC_SEC 

#include			"gy_ebpf_bpf_common.h"

#endif

enum {
	TCP_EVENT_TYPE_CONNECT	= 1,
	TCP_EVENT_TYPE_ACCEPT,
	TCP_EVENT_TYPE_CLOSE_CLI,
	TCP_EVENT_TYPE_CLOSE_SER,
};	

#define				ENABLE_PERF_PROBE	100	
	
#ifndef 			TASK_COMM_LEN
#define 			TASK_COMM_LEN 		16
#endif

struct tcp_ipv4_event_t 
{
	u64 			ts_ns;
	u64			bytes_received;
	u64			bytes_acked;
	u32 			pid;
	u32 			tid;
	char 			comm[TASK_COMM_LEN];
	u32 			saddr;
	u32 			daddr;
	u32 			netns;
	u16 			sport;
	u16 			dport;
	u8 			ipver;
	u8 			type;
};

struct tcp_ipv6_event_t 
{
	u64 			ts_ns;
	u64			bytes_received;
	u64			bytes_acked;
	u32 			pid;
	u32			tid;
	char 			comm[TASK_COMM_LEN];
	unsigned __int128 	saddr;
	unsigned __int128 	daddr;
	u32 			netns;
	u16 			sport;
	u16 			dport;
	u8 			ipver;
	u8 			type;
};

struct pid_comm_t 
{
	u64 			pid_tid;
	char 			comm[TASK_COMM_LEN];
};

#ifndef 	CLONE_NEWCGROUP
#define 	CLONE_NEWCGROUP		0
#endif

struct create_ns_data_t
{
	u64 			ts_ns;
	u64			flags;
	u32 			pid;
	u32			tid;
	char 			comm[TASK_COMM_LEN];
};	

struct tcp_listener_event_t 
{
	u64 				ts_ns;
	u32 				pid;
	u32 				tid;
	char 				comm[TASK_COMM_LEN];
	union {
		unsigned __int128 	v6addr;
		u32 			v4addr;
	} addr;
	u32 				netns;
	u32				backlog;
	u16 				lport;
	u8 				ipver;
};

struct tcp_ipv4_resp_event_t 
{
	struct ipv4_tuple_t	tup;
	u32			lsndtime;
	u32			lrcvtime;
};

struct tcp_ipv6_resp_event_t 
{
	struct ipv6_tuple_t	tup;
	u32			lsndtime;
	u32			lrcvtime;
};

struct cgroup_migrate_event_t
{
	u32 				pid;
	u32 				tid;
	bool				threadgroup;
};	

/*
 * BCC has apparently an issue with unions. This is needed in the interim.
 * XXX If ip_vs_conn struct definition changes in net/ip_vs.h, we need to update here as well...
 */
struct gy_ip_vs_conn
{
	void			*pdummy1;
	void			*pdummy2;	/* struct hlist_node	c_list */

	u16                     cport;
	u16                     dport;
	u16                     vport;
	u16			af;		/* address family */
	u32		      	caddr[4];       /* client address */
	u32			vaddr[4];       /* virtual address */
	u32			daddr[4];       /* destination address */
	u32 		        flags;          /* status flags */
	u16                     protocol;       /* Which protocol (TCP/UDP) */
	u16      		daf;		/* Address family of the dest */
};	

union ipv4_ipv6_u {
	unsigned __int128 		v6addr;
	u32 				v4addr;
};

struct ip_vs_conn_event_t
{
	union ipv4_ipv6_u		cliaddr;
	union ipv4_ipv6_u		virtaddr;
	union ipv4_ipv6_u		destaddr;
	
	u16				cliport;
	u16				virtport;
	u16				destport;

	u16				af;
	u16				daf;
};	


#if				defined (__cplusplus) && defined (__GLIBCXX__)
} // namespace gyeeta
#endif

)";
