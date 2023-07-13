//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#ifndef 				_TEST_NETCAP_EBPF_H
#define					_TEST_NETCAP_EBPF_H


#define					TCAP_PROTO_UNKNOWN		0
#define					TCAP_PROTO_HTTP			1
#define					TCAP_PROTO_HTTP2		2
#define					TCAP_PROTO_GRPC			3
#define					TCAP_PROTO_POSTGRES		4
#define					TCAP_PROTO_MYSQL		5
#define					TCAP_PROTO_REDIS		6

#define					TDIR_INBOUND			0
#define					TDIR_OUTBOUND			1

typedef uint8_t 			u8;
typedef uint16_t 			u16;
typedef uint32_t 			u32;
typedef uint64_t 			u64;


struct tlistenkey
{
	union {
		unsigned __int128	ser6addr;
		u32			ser4addr;
	} seraddr;	

	u32 				netns;
	u16 				serport;
	u8 				ipver;
};	

struct tlistenstat
{
	u16				proto;
	u8				isssl;
	u8				isany;
	bool				pausecap;				
};	


struct tiov_iter_arg
{
	struct taddr_tuple		tuple;
	struct iovec			iov;
	size_t 				iov_offset;
	uint16_t			nr_segs;
	u8 				iter_type;
	bool 				user_backed;

	u16				proto;
	u8				isssl;
	u8				isany;
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

	u8 				ipver;
};

struct tcaphdr_t 
{
	u64 				ts_ns;
	struct taddr_tuple		tuple;
	u32				len;		// Actual Payload len + Pad bytes (npadbytes) Follows this hdr
	u32 				pid;
	u32				nxt_cli_seq;
	u32				nxt_ser_seq;
	bool				is_inbound;
	u8				tcp_flags;
	u8				npadbytes;
};

#define					TMAX_ONE_PAYLOAD_LEN		(16 * 1024 - sizeof(tcaphdr_t) - 64)
#define					TMAX_TOTAL_PAYLOAD_LEN		(TMAX_ONE_PAYLOAD_LEN * 5)


#endif

