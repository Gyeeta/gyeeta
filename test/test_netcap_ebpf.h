//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#ifndef 		_TEST_NETCAP_EBPF_H
#define			_TEST_NETCAP_EBPF_H


#define			TCAP_PROTO_UNKNOWN		0
#define			TCAP_PROTO_HTTP			1
#define			TCAP_PROTO_HTTP2		2
#define			TCAP_PROTO_GRPC			3
#define			TCAP_PROTO_POSTGRES		4
#define			TCAP_PROTO_MYSQL		5
#define			TCAP_PROTO_REDIS		6

typedef uint8_t 		u8;
typedef uint16_t 		u16;
typedef uint32_t 		u32;
typedef uint64_t 		u64;


struct tlisteninfo
{
	union {
		unsigned __int128	ser6addr;
		u32			ser4addr;
	} seraddr;	

	u32 				netns;
	u16 				serport;
};	

struct tlistenstat
{
	u16				proto;
	u8 				ipver;
	u8				isssl;
	u8				isany;
};	

struct tlistener
{
	struct tlisteninfo		info;
	struct tlistenstat		stat;
	u32				last_cli_seq;
	u32				last_ser_seq;
};


struct taddr_tuple
{
	union {
		unsigned __int128	ser6addr;
		u32			ser4addr;
	} seraddr;	

	union {
		unsigned __int128	cli6addr;
		u32			cli4addr;
	} cliaddr;	

	u32 				netns;
	u16 				serport;
	u16 				cliport;

	u16				proto;
	u8 				ipver;
	u8				isssl;
};

struct tcaphdr_t 
{
	u64 				ts_ns;
	struct taddr_tuple		tuple;
	u32				len;		// Actual Payload len + Pad bytes (npadbytes) Follows this hdr
	u32 				pid;
	u32				cli_seq;
	u32				ser_seq;
	bool				is_inbound;
	u8				tcp_flags;
	u8				npadbytes;
};



#endif

