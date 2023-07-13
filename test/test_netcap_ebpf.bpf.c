//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include 		<vmlinux.h>
#include 		<bpf/bpf_helpers.h>
#include 		<bpf/bpf_core_read.h>
#include 		<bpf/bpf_tracing.h>
#include 		<bpf/bpf_endian.h>

#include		"../common/gy_ebpf_bpf_common.h"
#include		"test_netcap_ebpf.h"

#ifndef			MSG_OOB

#define 		MSG_OOB				1
#define 		MSG_PEEK			2
#define 		MSG_ERRQUEUE			0x2000
#define 		MSG_ZEROCOPY			0x4000000	/* Use user data in kernel path */

#endif

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct tlistenkey);
	__type(value, struct tlistenstat);
} listenmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, struct tiov_iter_arg);
} iovargmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 8 * 1024 * 1024);
} capring SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

static __always_inline uint64_t align_up_2(uint64_t nsize, uint64_t nalign)
{
	return ((nsize - 1) & ~(nalign - 1)) + nalign;
}

static bool read_addr_tuple(struct taddr_tuple *ptuple, struct sock *skp, bool is_inbound)
{
	struct inet_sock 		*sockp;
	u16 				family;
	
	sockp = (struct inet_sock *)skp;

	BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);

	if (family == AF_INET) {
		if (is_inbound) {
			ptuple->ser4addr 	= BPF_CORE_READ(skp, __sk_common.skc_daddr);
			ptuple->cli4addr 	= BPF_CORE_READ(skp, __sk_common.skc_rcv_saddr);

			ptuple->serport		= bpf_ntohs(BPF_CORE_READ(skp, __sk_common.skc_dport));
			ptuple->cliport 	= bpf_ntohs(BPF_CORE_READ(sockp, inet_sport));
		}
		else {
			ptuple->cli4addr 	= BPF_CORE_READ(skp, __sk_common.skc_daddr);
			ptuple->ser4addr 	= BPF_CORE_READ(skp, __sk_common.skc_rcv_saddr);

			ptuple->cliport		= bpf_ntohs(BPF_CORE_READ(skp, __sk_common.skc_dport));
			ptuple->serport 	= bpf_ntohs(BPF_CORE_READ(sockp, inet_sport));
		}

		ptuple->ipver = 4;
	}	
	else if (family == AF_INET6) {

		if (is_inbound) {
			ptuple->ser6addr 	= BPF_CORE_READ(skp, __sk_common.skc_daddr);
			ptuple->cli6addr 	= BPF_CORE_READ(skp, __sk_common.skc_rcv_saddr);

			ptuple->serport		= bpf_ntohs(BPF_CORE_READ(skp, __sk_common.skc_dport));
			ptuple->cliport 	= bpf_ntohs(BPF_CORE_READ(sockp, inet_sport));
		}
		else {
			ptuple->cli6addr 	= BPF_CORE_READ(skp, __sk_common.skc_daddr);
			ptuple->ser6addr 	= BPF_CORE_READ(skp, __sk_common.skc_rcv_saddr);

			ptuple->cliport		= bpf_ntohs(BPF_CORE_READ(skp, __sk_common.skc_dport));
			ptuple->serport 	= bpf_ntohs(BPF_CORE_READ(sockp, inet_sport));
		}

		ptuple->ipver = 6;

		bool 				is_src_ipv4_mapped = is_ipv4_mapped_ipv6(ptuple->ser6addr);
		bool 				is_dest_ipv4_mapped = is_ipv4_mapped_ipv6(ptuple->cli6addr);

		if (is_src_ipv4_mapped || is_dest_ipv4_mapped) {
			unsigned __int128		saddr = ptuple->ser6addr, caddr = ptuple->cli6addr;
			u8				*pipbuf = (u8 *)&saddr, *pipbuf2 = (u8 *)&caddr;

			__builtin_memcpy(&ptuple->ser4addr, pipbuf + 12, 4);
			__builtin_memcpy(&ptuple->cli4addr, pipbuf2 + 12, 4);

			ptuple->ipver = 4;
		}
	}
	else {
		return false;
	}	

	if (bpf_core_field_exists(skp->__sk_common.skc_net)) {
		BPF_CORE_READ_INTO(&ptuple->netns, skp, __sk_common.skc_net.net, ns.inum);
	}

	// if ports are 0, ignore
	if (sport == 0 || dport == 0) {
		return false;
	}

	return true;
}

static struct tlistenstat * lookup_listener(struct tlistenkey *pkey)
{
	struct tlistenstat		*pstat;

	pstat = bpf_map_lookup_elem(&listenmap, pkey);
	
	if (!pstat) {
		// Try any addr
		pkey->seraddr.ser6addr = 0;

		pstat = bpf_map_lookup_elem(&listenmap, pkey);
		
		if (!pstat) {
			return NULL;
		}
	}	

	return pstat;
}	

static uint32_t read_iov_data(uint8_t *pdeststart, uint32_t nbytes, struct tiov_iter_arg *parg, size_t init_iov_offset, bool user_backed)
{
	uint32_t			nrd = 0;
	int				err;

	for (uint16_t n = 0; n < parg->nr_segs && nrd < nbytes; ++n) {

		uint8_t				*pdest = pdeststart + nrd;
		const void			*psrc = (const uint8_t *)parg->iov[n].iov_base + init_iov_offset;
		int				ilen = parg->iov[n].iov_len - init_iov_offset;
		
		init_iov_offset = 0;

		if (ilen < 0) {
			break;
		}
		else if (ilen == 0) {
			continue;
		}	
		
		if ((uint32_t)ilen + nrd > nbytes) {
			ilen = nbytes - nrd;
		}

		if (user_backed) {
			err = bpf_core_read_user(pdest, ilen, psrc);
		}
		else {
			err = bpf_core_read(pdest, ilen, psrc);
		}	

		if (err) {
			break;
		}	
		
		nrd += ilen;
	}	

	return nrd;
}	

static int do_trace_close_entry(void *ctx, struct sock *sk)
{
	u8 				oldstate = BPF_CORE_READ(sk, __sk_common.skc_state);

	// Only track established conns
	if (oldstate == TCP_SYN_SENT || oldstate == TCP_SYN_RECV || oldstate == TCP_NEW_SYN_RECV) {
		return 0;
	}	

	u32				sk_max_ack_backlog = 0

	/*
	 * Ignore external listeners
	 */
	BPF_CORE_READ_INTO(&sk_max_ack_backlog, sk, sk_max_ack_backlog);
	if (sk_max_ack_backlog == 0) {
		return 0;
	}	

	struct tcp_sock			*ptcp = (struct tcp_sock *)sk;
	struct taddr_tuple		tuple = {};

	if (!read_addr_tuple(&tuple, sk, false /* is_inbound */)) {
		return 0;
	}	

	struct tlistenkey		lkey = {};
	
	__builtin_memcpy(&lkey.seraddr, &tuple.seraddr, sizeof(lkey.seraddr));
	
	lkey.netns			= tuple.netns;
	lkey.serport			= tuple.serport;
	lkey.ipver			= tuple.ipver;
		
	struct tlistenstat		*pstat;

	pstat = lookup_listener(&lkey);
	
	if (!pstat || pstat->pausecap) {
		return 0;
	}	

	struct tcaphdr_t 		*phdr;
	
	phdr = bpf_ringbuf_reserve(&capring, sizeof(*phdr), 0);
	if (!phdr) {
		return 0;
	}	
	
	phdr->ts_ns			= bpf_ktime_get_ns();

	__builtin_memcpy(&phdr->tuple, &tuple, sizeof(phdr->tuple));

	// Send the FIN indicator to userspace
	phdr->len			= 0;
	phdr->pid			= bpf_get_current_pid_tgid() >> 32;
	phdr->nxt_cli_seq		= BPF_CORE_READ(ptcp, rcv_nxt);
	phdr->nxt_ser_seq		= BPF_CORE_READ(ptcp, write_seq);
	phdr->is_inbound		= false;
	phdr->tcp_flags			= GY_TH_FIN | GY_TH_ACK;
	phdr->npadbytes			= 0;

	bpf_ringbuf_submit(phdr, 0);

	return 0;
}

SEC("fentry/tcp_close")
int BPF_PROG(fentry_tcp_close_entry, struct sock *sk)
{
	return do_trace_close_entry(ctx, sk);
}

static int do_stash_entry_args(struct sock *sk, struct msghdr *msg, bool is_inbound)
{
	u32				sk_max_ack_backlog = 0

	/*
	 * Ignore external listeners
	 */
	BPF_CORE_READ_INTO(&sk_max_ack_backlog, sk, sk_max_ack_backlog);
	if (sk_max_ack_backlog == 0) {
		return 0;
	}	

	struct taddr_tuple		tuple = {};

	if (!read_addr_tuple(&tuple, sk, is_inbound)) {
		return 0;
	}	

	struct tlistenkey		lkey = {};
	
	__builtin_memcpy(&lkey.seraddr, &tuple.seraddr, sizeof(lkey.seraddr));
	
	lkey.netns			= tuple.netns;
	lkey.serport			= tuple.serport;
	lkey.ipver			= tuple.ipver;
		
	struct tlistenstat		*pstat;

	pstat = lookup_listener(&lkey);
	
	if (!pstat || pstat->pausecap) {
		return 0;
	}	

	// stash the args as the args will be updated on exit
	struct tiov_iter_arg		iarg = {}; 

	u64 				pid = bpf_get_current_pid_tgid();
	u8 				iter_type;
	bool 				user_backed = true, copy_mc = false;

	if (bpf_core_field_exists(msg->msg_iter.iter_type)) {	
		// From Kernel 5.14

		iter_type 			= BPF_CORE_READ(msg, msg_iter.iter_type);
		
		if (bpf_core_field_exists(msg->msg_iter.copy_mc)) {
			copy_mc		 	= BPF_CORE_READ(msg, msg_iter.copy_mc);
		}

		if (bpf_core_field_exists(msg->msg_iter.user_backed)) {
			user_backed 		= BPF_CORE_READ(msg, msg_iter.user_backed);
		}
		else {
			user_backed 		= iter_type != ITER_KVEC;
		}

		if (bpf_core_enum_value_exists(enum iter_type, ITER_UBUF)) {
			if (iter_type != ITER_IOVEC && iter_type != ITER_KVEC && iter_type != ITER_UBUF) {
				// Not handled
				return 0;
			}	
		}
		else {
			if (iter_type != ITER_IOVEC && iter_type != ITER_KVEC) {
				// Not handled
				return 0;
			}	
		}	

		if (BPF_CORE_READ(msg, msg_flags) & MSG_ZEROCOPY) {
			// Not handled
			return 0;
		}	

		if (copy_mc) {
			// Not handled
			return 0;
		}	

		if (iter_type == ITER_UBUF && !user_backed) {
			// Not handled
			return 0;
		}
		else if (iter_type == ITER_KVEC && user_backed) {
			// This should not happen
			return 0;
		}	

	}
	else {
		iter_type 			= (u8)BPF_CORE_READ(msg, msg_iter.type);
		copy_mc			 	= false;
		user_backed 			= iter_type != ITER_KVEC;

		if (iter_type != ITER_IOVEC && iter_type != ITER_KVEC) {
			// Not handled
			return 0;
		}	
	}	

	__builtin_memcpy(&iarg.tuple, &tuple, sizeof(tuple));
	
	if (bpf_core_field_exists(msg->msg_iter.copy_mc)) {	
		// From Kernel 6.0

		if (iter_type == ITER_UBUF) {
			iarg.iov.iov_base 		= BPF_CORE_READ_USER(msg, msg_iter.__ubuf_iovec.iov_base);
			iarg.iov.iov_len 		= BPF_CORE_READ_USER(msg, msg_iter.__ubuf_iovec.iov_len);
			iarg.nr_segs 			= (uint16_t)(uint64_t)BPF_CORE_READ_USER(msg, msg_iter.nr_segs);
		}
		else if (iter_type == ITER_IOVEC) {
			if (user_backed) {
				iarg.iov.iov_base 	= BPF_CORE_READ_USER(msg, msg_iter.__iov, iov_base);
				iarg.iov.iov_len 	= BPF_CORE_READ_USER(msg, msg_iter.__iov, iov_len);
				iarg.nr_segs 		= (uint16_t)(uint64_t)BPF_CORE_READ_USER(msg, msg_iter.nr_segs);
			}
			else {
				// Is this case possible?
				iarg.iov.iov_base 	= BPF_CORE_READ(msg, msg_iter.__iov, iov_base);
				iarg.iov.iov_len 	= BPF_CORE_READ(msg, msg_iter.__iov, iov_len);
				iarg.nr_segs 		= (uint16_t)(uint64_t)BPF_CORE_READ(msg, msg_iter.nr_segs);
			}
		}	
	}
	else {
		if (bpf_core_enum_value_exists(enum iter_type, ITER_UBUF)) {
			if (iter_type == ITER_UBUF) {
				iarg.iov.iov_base 		= BPF_CORE_READ_USER(msg, msg_iter.ubuf);
				iarg.iov.iov_len 		= BPF_CORE_READ_USER(msg, msg_iter.count);
				iarg.nr_segs 			= (uint16_t)(uint64_t)BPF_CORE_READ_USER(msg, msg_iter.nr_segs);
			}
		}

		if (iter_type == ITER_IOVEC) {
			if (user_backed) {
				iarg.iov.iov_base 	= BPF_CORE_READ_USER(msg, msg_iter.iov, iov_base);
				iarg.iov.iov_len 	= BPF_CORE_READ_USER(msg, msg_iter.iov, iov_len);
				iarg.nr_segs 		= (uint16_t)(uint64_t)BPF_CORE_READ_USER(msg, msg_iter.nr_segs);
			}
			else {
				// Is this case possible?
				iarg.iov.iov_base 	= BPF_CORE_READ(msg, msg_iter.iov, iov_base);
				iarg.iov.iov_len 	= BPF_CORE_READ(msg, msg_iter.iov, iov_len);
				iarg.nr_segs 		= (uint16_t)(uint64_t)BPF_CORE_READ(msg, msg_iter.nr_segs);
			}
		}	
	}

	if (iter_type == ITER_KVEC) {
		iarg.iov.iov_base 		= BPF_CORE_READ(msg, msg_iter.kvec, iov_base);
		iarg.iov.iov_len 		= BPF_CORE_READ(msg, msg_iter.kvec, iov_len);
		iarg.nr_segs 			= (uint16_t)(uint64_t)BPF_CORE_READ(msg, msg_iter.nr_segs);
	}

	iarg.iov_offset			= is_inbound ? 0 : BPF_CORE_READ(msg, msg_iter.iov_offset);
	iarg.iter_type			= iter_type;
	iarg.user_backed		= user_backed;

	iarg.proto			= pstat->proto;
	iarg.isssl			= pstat->isssl;
	iarg.isany			= pstat->isany;
		
	bpf_map_update_elem(&iovargmap, &pid, &iarg, BPF_ANY);

	return 0;
}	

SEC("fentry/tcp_sendmsg")
int BPF_PROG(fentry_tcp_sendmsg_entry, struct sock *sk, struct msghdr *msg, size_t size)
{
	return do_stash_entry_args(sk, msg, false /* is_inbound */);
}

static int do_tcp_sendmsg_exit(struct sock *sk, struct msghdr *msg, int ret)
{
	u64 				pid = bpf_get_current_pid_tgid();
	struct tiov_iter_arg 		*parg;

	parg = bpf_map_lookup_elem(&iovargmap, &pid);
	if (parg == NULL) {
		return 0;       // missed entry
	}

	if (ret <= 0) {
		goto done;
	}	
	
	struct tcp_sock			*ptcp = (struct tcp_sock *)sk;
	struct tcaphdr_t		*phdr;
	u64				ts_ns = bpf_ktime_get_ns(), pid = bpf_get_current_pid_tgid() >> 32, bytes_received;

	size_t				tbytes = ret, maxbytes = tbytes > TMAX_TOTAL_PAYLOAD_LEN ? TMAX_TOTAL_PAYLOAD_LEN : tbytes;
	ssize_t				npend = maxbytes;

	uint32_t			actendseq = BPF_CORE_READ(ptcp, write_seq), startseq = actendseq - tbytes, endseq = startseq + maxbytes;
	uint32_t			nxt_cli_seq = BPF_CORE_READ(ptcp, rcv_nxt);
	
	const uint8_t			niter = maxbytes / TMAX_ONE_PAYLOAD_LEN + 1;

	BPF_CORE_READ_INTO(&bytes_received, ptcp, bytes_received);
	if (bytes_received == 0) {
		u64				bytes_sent;

		BPF_CORE_READ_INTO(&bytes_sent, ptcp, bytes_sent);
		
		if (bytes_sent == (unsigned)ret) {
			// Send dummy SYN/ACK needed for a server initiated start

			struct tcaphdr_t 		*phdr;
			
			phdr = bpf_ringbuf_reserve(&capring, sizeof(*phdr), 0);
			if (!phdr) {
				goto done;
			}	
			
			phdr->ts_ns			= ts_ns;

			__builtin_memcpy(&phdr->tuple, &parg->tuple, sizeof(phdr->tuple));

			// Send the SYN/ACK indicator to userspace
			phdr->len			= 0;
			phdr->pid			= pid;
			phdr->nxt_cli_seq		= nxt_cli_seq;
			phdr->nxt_ser_seq		= startseq;
			phdr->is_inbound		= false;
			phdr->tcp_flags			= GY_TH_SYN | GY_TH_ACK;
			phdr->npadbytes			= 0;

			bpf_ringbuf_submit(phdr, 0);
		}
	}

	for (uint8_t i = 0; i < niter && npend > 0; ++i) {
		const uint32_t			tbytes = sizeof(*phdr) + (uint32_t)(npend < TMAX_ONE_PAYLOAD_LEN ? npend : TMAX_ONE_PAYLOAD_LEN);
		const uint32_t			ringsz = align_up_2(tbytes, 8);
		const uint8_t			pad[7] = {}, npad = (uint8_t)(ringsz - tbytes);

		const uint32_t			actbytes = ringsz - sizeof(*phdr) - npad;
		uint8_t				*pring = bpf_ringbuf_reserve(&capring, ringsz, 0);

		if (!pring) {
			break;
		}	

		startseq			+= actbytes;
		npend				-= actbytes;
		
		phdr 				= (struct tcaphdr_t *)pring;

		phdr->ts_ns			= ts_ns;

		__builtin_memcpy(&phdr->tuple, &parg->tuple, sizeof(phdr->tuple));

		phdr->len			= ringsz - sizeof(*phdr);
		phdr->pid			= pid;
		phdr->nxt_cli_seq		= nxt_cli_seq;
		phdr->nxt_ser_seq		= startseq;
		phdr->is_inbound		= false;
		phdr->tcp_flags			= GY_TH_ACK;
		phdr->npadbytes			= npad;

		nret = read_iov_data(pring + sizeof(*phdr), actbytes, parg, parg->iov_offset, parg->user_backed); 
		
		if (nret != actbytes) {
			bpf_ringbuf_discard(pring, 0);
			break;
		}	

		if (npad > 0 && npad <= 7) {
			__builtin_memcpy(pring + sizeof(*phdr) + actbytes, pad, npad);
		}

		bpf_ringbuf_submit(pring, 0);
	}	

done :
	bpf_map_delete_elem(&iovargmap, &pid);
	
	return 0;
}	

SEC("fexit/tcp_sendmsg")
int BPF_PROG(fexit_tcp_sendmsg_exit, struct sock *sk, struct msghdr *msg, size_t size, int ret)
{
	return do_tcp_sendmsg_exit(sk, msg, ret);
}


SEC("fentry/tcp_recvmsg")
int BPF_PROG(fentry_tcp_recvmsg_entry, struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len)
{
	if (flags & (MSG_PEEK | MSG_ERRQUEUE | MSG_OOB))
		return 0;
	}

	return do_stash_entry_args(sk, msg, true /* is_inbound */);
}


static int do_tcp_recvmsg_exit(struct sock *sk, struct msghdr *msg, int ret)
{
	u64 				pid = bpf_get_current_pid_tgid();
	struct tiov_iter_arg 		*parg;

	parg = bpf_map_lookup_elem(&iovargmap, &pid);
	if (parg == NULL) {
		return 0;       // missed entry
	}

	if (ret <= 0) {
		goto done;
	}	
	
	struct tcp_sock			*ptcp = (struct tcp_sock *)sk;
	struct tcaphdr_t		*phdr;
	u64				ts_ns = bpf_ktime_get_ns(), pid = bpf_get_current_pid_tgid() >> 32, bytes_sent;

	size_t				tbytes = ret, maxbytes = tbytes > TMAX_TOTAL_PAYLOAD_LEN ? TMAX_TOTAL_PAYLOAD_LEN : tbytes; 
	ssize_t				npend = maxbytes;

	uint32_t			actendseq = BPF_CORE_READ(ptcp, copied_seq), startseq = actendseq - tbytes, endseq = startseq + maxbytes;
	uint32_t			nxt_ser_seq = BPF_CORE_READ(ptcp, write_seq);
	
	const uint8_t			niter = maxbytes / TMAX_ONE_PAYLOAD_LEN + 1;

	BPF_CORE_READ_INTO(&bytes_sent, ptcp, bytes_sent);
	if (bytes_sent == 0) {
		u64				bytes_received;

		BPF_CORE_READ_INTO(&bytes_received, ptcp, bytes_received);
		
		if (bytes_received == (unsigned)ret) {
			// Send dummy SYN needed for a server initiated start

			struct tcaphdr_t 		*phdr;
			
			phdr = bpf_ringbuf_reserve(&capring, sizeof(*phdr), 0);
			if (!phdr) {
				goto done;
			}	
			
			phdr->ts_ns			= ts_ns;

			__builtin_memcpy(&phdr->tuple, &parg->tuple, sizeof(phdr->tuple));

			// Send the SYN indicator to userspace
			phdr->len			= 0;
			phdr->pid			= pid;
			phdr->nxt_ser_seq		= nxt_ser_seq;
			phdr->nxt_cli_seq		= startseq;
			phdr->is_inbound		= false;
			phdr->tcp_flags			= GY_TH_SYN;
			phdr->npadbytes			= 0;

			bpf_ringbuf_submit(phdr, 0);
		}
	}

	for (uint8_t i = 0; i < niter && npend > 0; ++i) {
		const uint32_t			tbytes = sizeof(*phdr) + (uint32_t)(npend < TMAX_ONE_PAYLOAD_LEN ? npend : TMAX_ONE_PAYLOAD_LEN);
		const uint32_t			ringsz = align_up_2(tbytes, 8);
		const uint8_t			pad[7] = {}, npad = (uint8_t)(ringsz - tbytes);

		const uint32_t			actbytes = ringsz - sizeof(*phdr) - npad;
		uint8_t				*pring = bpf_ringbuf_reserve(&capring, ringsz, 0);

		if (!pring) {
			break;
		}	

		startseq			+= actbytes;
		npend				-= actbytes;
		
		phdr 				= (struct tcaphdr_t *)pring;

		phdr->ts_ns			= ts_ns;

		__builtin_memcpy(&phdr->tuple, &parg->tuple, sizeof(phdr->tuple));

		phdr->len			= ringsz - sizeof(*phdr);
		phdr->pid			= pid;
		phdr->nxt_cli_seq		= startseq;
		phdr->nxt_ser_seq		= nxt_ser_seq;
		phdr->is_inbound		= true;
		phdr->tcp_flags			= GY_TH_ACK;
		phdr->npadbytes			= npad;

		nret = read_iov_data(pring + sizeof(*phdr), actbytes, parg, parg->iov_offset, parg->user_backed); 
		
		if (nret != actbytes) {
			bpf_ringbuf_discard(pring, 0);
			break;
		}	

		if (npad > 0 && npad <= 7) {
			__builtin_memcpy(pring + sizeof(*phdr) + actbytes, pad, npad);
		}

		bpf_ringbuf_submit(pring, 0);
	}	

done :
	bpf_map_delete_elem(&iovargmap, &pid);
	
	return 0;
}	

SEC("fexit/tcp_recvmsg")
int BPF_PROG(fexit_tcp_recvmsg_exit, struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len, int ret)
{
	return do_tcp_recvmsg_exit(sk, msg, ret);
}


