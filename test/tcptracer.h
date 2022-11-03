//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _TCPTRACER_H
#define _TCPTRACER_H

enum {
	TCP_EVENT_TYPE_CONNECT	= 1,
	TCP_EVENT_TYPE_ACCEPT,
	TCP_EVENT_TYPE_CLOSE_CLI,
	TCP_EVENT_TYPE_CLOSE_SER,
};		
	
#ifndef 		TASK_COMM_LEN
#define 		TASK_COMM_LEN 		16
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

struct tcptrace_debug_t 
{
	struct ipv4_tuple_t	ipv4;
	struct ipv6_tuple_t	ipv6;
	int			iptype;
};	

struct pid_comm_t 
{
	u64 			pid_tid;
	char 			comm[TASK_COMM_LEN];
};

struct nsproxy_data_t
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

#endif

