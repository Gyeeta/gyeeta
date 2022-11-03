//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

/*
 * XXX This file is also included from the ebpf Kernel program. So all C++ and userspace stuff needs 
 * to be within a #if defined
 */ 
#if				defined (__cplusplus) && defined (__GLIBCXX__)

#pragma				once

#include			"gy_common_inc.h"

namespace ebpf 
{
	class 			BPF;
}

namespace gyeeta {

#endif				// __cplusplus && __GLIBCXX__

typedef uint8_t 		u8;
typedef uint16_t 		u16;
typedef uint32_t 		u32;
typedef uint64_t 		u64;

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

