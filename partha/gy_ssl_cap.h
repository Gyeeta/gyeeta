//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later


#ifndef _SSL_CAP_H
#define _SSL_CAP_H

#include			"../common/gy_ebpf_bpf_common.h"

struct ssl_rw_args
{
	void 				*pssl;
	void 				*buf;
	size_t 				*pexsize;
};

struct ssl_key
{
	void 				*ssl;
	u32				pid;
};

struct ssl_tcp_val
{
	struct ssl_key			tkey;
	bool				is_init;
};

struct addr_tuple
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

struct ssl_conn_info
{
	struct addr_tuple		tup;
	u32				nxt_cli_seq;
	u32				nxt_ser_seq;
	bool				is_client;
	bool				cli_started;
	bool				ser_started;
};	

struct caphdr_t 
{
	u64 				ts_ns;
	struct addr_tuple		tuple;
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

#define SSL_SEQ_START			1024
#define	SSL_MAX_ONE_RING_SZ		(4096)
#define	SSL_MAX_ONE_PAYLOAD_LEN		(SSL_MAX_ONE_RING_SZ - sizeof(struct caphdr_t))
#define	SSL_MAX_TOTAL_PAYLOAD_LEN	(32 * 1024)


#endif
