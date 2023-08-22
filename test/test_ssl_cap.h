//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later


#ifndef _SSL_CAP_H
#define _SSL_CAP_H

#include			"../common/gy_ebpf_bpf_common.h"

struct tssl_rw_args
{
	void 				*pssl;
	void 				*buf;
	size_t 				*pexsize;
};

struct tssl_key
{
	void 				*ssl;
	u32				pid;
};

struct tssl_tcp_val
{
	struct tssl_key			tkey;
	bool				is_init;
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

struct tssl_conn_info
{
	struct taddr_tuple		tup;
	u32				nxt_cli_seq;
	u32				nxt_ser_seq;
	bool				is_client;
};	

struct tcaphdr_t 
{
	u64 				ts_ns;
	struct taddr_tuple		tuple;
	u32				len;		// Actual Payload len + Pad bytes (npadbytes) Follows this hdr
	u32 				pid;
	u32				nxt_cli_seq;
	u32				nxt_ser_seq;
	u16				npadbytes;
	bool				is_inbound;
	u8				tcp_flags;

#ifdef	__cplusplus
	
	uint32_t get_src_seq_start() const noexcept
	{
		if (is_inbound) {
			return nxt_cli_seq - get_act_payload_len();
		}	
		else {
			return nxt_ser_seq - get_act_payload_len();
		}	
	}	

	uint32_t get_act_payload_len() const noexcept
	{
		return len - npadbytes;
	}	
#endif

};

#define TSEQ_START			1024
#define	TMAX_ONE_RING_SZ		(1024 * 2)
#define	TMAX_ONE_PAYLOAD_LEN		(TMAX_ONE_RING_SZ - sizeof(struct tcaphdr_t))
#define	TMAX_TOTAL_PAYLOAD_LEN		(80 * 1024 / TMAX_ONE_PAYLOAD_LEN + 1024)


#endif
