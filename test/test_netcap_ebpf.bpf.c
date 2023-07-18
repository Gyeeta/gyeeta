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


struct iov_iter___v6_0 
{
	u8 iter_type;
	bool copy_mc;
	bool user_backed;

	union {
		size_t iov_offset;
		int last_offset;
	};

	union {
		struct iovec __ubuf_iovec;
		struct {
			union {
				const struct iovec *__iov;
				const struct kvec *kvec;
				void *ubuf;
			};
			size_t count;
		};
	};
	union {
		unsigned long nr_segs;
	};
}  __attribute__((preserve_access_index));

struct iov_iter___v5_14 
{
	u8 iter_type;
	bool data_source;
	size_t iov_offset;
	size_t count;
	union {
		const struct iovec *iov;
		const struct kvec *kvec;
	};
	union {
		unsigned long nr_segs;
	};
}  __attribute__((preserve_access_index));

struct iov_iter___v5_10 
{
	unsigned int type;
	size_t iov_offset;
	size_t count;
	union {
		const struct iovec *iov;
		const struct kvec *kvec;
	};
	union {
		unsigned long nr_segs;
	};

}  __attribute__((preserve_access_index));

static __always_inline uint64_t align_up_2(uint64_t nsize, uint64_t nalign)
{
	return ((nsize - 1) & ~(nalign - 1)) + nalign;
}


static bool read_addr_tuple(struct taddr_tuple *ptuple, struct sock *sk, bool is_inbound)
{
	struct inet_sock 		*sockp;
	u16 				family;
	
	sockp = (struct inet_sock *)sk;

	BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);

	if (family == AF_INET) {
		if (is_inbound) {
			ptuple->seraddr.ser4addr 	= BPF_CORE_READ(sk, __sk_common.skc_daddr);
			ptuple->cliaddr.cli4addr 	= BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);

			ptuple->serport			= bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
			ptuple->cliport 		= bpf_ntohs(BPF_CORE_READ(sockp, inet_sport));
		}
		else {
			ptuple->cliaddr.cli4addr 	= BPF_CORE_READ(sk, __sk_common.skc_daddr);
			ptuple->seraddr.ser4addr 	= BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);

			ptuple->cliport			= bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
			ptuple->serport 		= bpf_ntohs(BPF_CORE_READ(sockp, inet_sport));
		}

		ptuple->ipver = 4;
	}	
	else if (family == AF_INET6) {

		if (is_inbound) {
			ptuple->seraddr.ser6addr 	= BPF_CORE_READ(sk, __sk_common.skc_daddr);
			ptuple->cliaddr.cli6addr 	= BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);

			ptuple->serport			= bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
			ptuple->cliport 		= bpf_ntohs(BPF_CORE_READ(sockp, inet_sport));
		}
		else {
			ptuple->cliaddr.cli6addr 	= BPF_CORE_READ(sk, __sk_common.skc_daddr);
			ptuple->seraddr.ser6addr 	= BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);

			ptuple->cliport			= bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
			ptuple->serport 		= bpf_ntohs(BPF_CORE_READ(sockp, inet_sport));
		}

		ptuple->ipver = 6;

		bool 				is_src_ipv4_mapped = is_ipv4_mapped_ipv6(ptuple->seraddr.ser6addr);
		bool 				is_dest_ipv4_mapped = is_ipv4_mapped_ipv6(ptuple->cliaddr.cli6addr);

		if (is_src_ipv4_mapped || is_dest_ipv4_mapped) {
			unsigned __int128		saddr = ptuple->seraddr.ser6addr, caddr = ptuple->cliaddr.cli6addr;
			u8				*pipbuf = (u8 *)&saddr, *pipbuf2 = (u8 *)&caddr;

			__builtin_memcpy(&ptuple->seraddr.ser4addr, pipbuf + 12, 4);
			__builtin_memcpy(&ptuple->cliaddr.cli4addr, pipbuf2 + 12, 4);

			ptuple->ipver = 4;
		}
	}
	else {
		return false;
	}	

	if (bpf_core_field_exists(sk->__sk_common.skc_net)) {
		BPF_CORE_READ_INTO(&ptuple->netns, sk, __sk_common.skc_net.net, ns.inum);
	}

	// if ports are 0, ignore
	if (ptuple->serport == 0 || ptuple->cliport == 0) {
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

static bool read_iov_data(struct tiov_iter_arg *parg, uint32_t maxbytes, bool is_inbound, uint32_t startsrcseq, uint32_t nxt_dst_seq)
{
	uint64_t				ts_ns = bpf_ktime_get_ns(), pid = bpf_get_current_pid_tgid();
	uint32_t				npend = maxbytes, offset = parg->iov_offset;
	int					err = 0;
	uint16_t				niov = 0;
	const uint16_t				maxiov = parg->nr_segs;
	const bool				user_backed = parg->user_backed;

	if (!maxbytes || !parg) {
		return true;
	}	

	bpf_printk("read_iov_data input #maxbytes : %u, server port : %u, iter_type : %u\n", maxbytes, parg->tuple.serport, (uint32_t)parg->iter_type);

	for (int i = 0; i < 1 && (int)npend > 0 && niov < 128 && niov < maxiov; ++i) {

		struct iovec			iov;

		if (parg->iter_type == GY_ITER_UBUF) {
			iov.iov_base		= parg->iov1.iov_base;
			iov.iov_len		= parg->iov1.iov_len;

			err			= 0;
		}
		else {
			err = bpf_probe_read(&iov, sizeof(iov), parg->pvec.piov + niov);
		}

		// bpf_printk("read_iov_data IOV data is base %p len %d err %d\n", iov.iov_base, (int)iov.iov_len, err);

		if (err) {
			break;
		}	

		if (offset > iov.iov_len) {
			break;
		}	
		if ((iov.iov_len == 0) || (offset == iov.iov_len)) {
			niov++;
			offset = 0;

			continue;
		}	

		struct tcaphdr_t		*phdr;

		const uint8_t			*psrc = (const uint8_t *)iov.iov_base + offset;
		uint32_t			len = iov.iov_len - offset;

		if (len > npend) {
			len = npend;
		}	

		uint32_t			ringsz = 0, nbytes = len;

		
		if (nbytes > TMAX_ONE_RING_SZ - sizeof(*phdr)) {
			nbytes = TMAX_ONE_RING_SZ - sizeof(*phdr);
			offset += nbytes; 
		}	
		else {
			offset = 0;
			niov++;
		}	

		ringsz = nbytes + sizeof(*phdr);
		
		if (ringsz < 511) {
			ringsz = 512;
		}	
		else {
			ringsz = TMAX_ONE_RING_SZ;
		}	

		const uint16_t			npad = (uint16_t)(ringsz - sizeof(*phdr) - nbytes);

		uint8_t				*pring = bpf_ringbuf_reserve(&capring, ringsz, 0);

		if (!pring) {
			break;
		}	

		startsrcseq			+= nbytes;
		
		phdr 				= (struct tcaphdr_t *)pring;

		phdr->ts_ns			= ts_ns;

		__builtin_memcpy(&phdr->tuple, &parg->tuple, sizeof(phdr->tuple));

		phdr->len			= ringsz - sizeof(*phdr);
		phdr->pid			= pid >> 32;
		phdr->nxt_cli_seq		= is_inbound ? startsrcseq : nxt_dst_seq;
		phdr->nxt_ser_seq		= is_inbound ? nxt_dst_seq : startsrcseq;
		phdr->is_inbound		= is_inbound;
		phdr->tcp_flags			= GY_TH_ACK;
		phdr->npadbytes			= npad;

		if (user_backed) {
			err = bpf_core_read_user(pring + sizeof(*phdr), nbytes, psrc);
		}
		else {
			err = bpf_core_read(pring + sizeof(*phdr), nbytes, psrc);
		}	

		if (err) {
			bpf_printk("ERROR read_iov_data read failed err = %d : nbytes %u, user_backed %d\n", err, nbytes, (int)user_backed);
			bpf_ringbuf_discard(pring, 0);
			break;
		}	

		bpf_ringbuf_submit(pring, 0);

		bpf_printk("SUCCESS read_iov_data read nbytes %u, user_backed %d\n", nbytes, (int)user_backed);

		npend				-= nbytes;
	}	

	return npend == 0;
}

static int do_trace_close_entry(void *ctx, struct sock *sk)
{
	u8 				oldstate = BPF_CORE_READ(sk, __sk_common.skc_state);

	// Only track established conns
	if (oldstate == TCP_SYN_SENT || oldstate == TCP_SYN_RECV || oldstate == TCP_NEW_SYN_RECV) {
		return 0;
	}	

	u32				sk_max_ack_backlog = 0;

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
	u32				sk_max_ack_backlog = 0;

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

	struct iov_iter___v6_0		*pmsg_iter_ = NULL;

	bpf_core_read(&pmsg_iter_, sizeof(pmsg_iter_), &msg->msg_iter);

	if (!pmsg_iter_) {
		return 0;
	}

	if (BPF_CORE_READ(msg, msg_flags) & MSG_ZEROCOPY) {
		// Not handled
		return 0;
	}	

	if ((bpf_core_field_exists(pmsg_iter_->iter_type)) && (bpf_core_field_exists(pmsg_iter_->copy_mc))) {	
		// From Kernel 6.0
		struct iov_iter___v6_0		*pmsg_iter = pmsg_iter_;

		iter_type 			= BPF_CORE_READ(pmsg_iter, iter_type);
		copy_mc			 	= BPF_CORE_READ(pmsg_iter, copy_mc);
		user_backed	 		= BPF_CORE_READ(pmsg_iter, user_backed);

		if (copy_mc) {
			// Not handled
			return 0;
		}	

		if (iter_type == GY_ITER_UBUF && !user_backed) {
			// Not handled
			return 0;
		}
		else if (iter_type == GY_ITER_KVEC && user_backed) {
			// This should not happen
			return 0;
		}	

		iarg.nr_segs 			= (uint16_t)(uint64_t)BPF_CORE_READ(pmsg_iter, nr_segs);
		iarg.iov_offset			= is_inbound ? 0 : BPF_CORE_READ(pmsg_iter, iov_offset);
	
		if (iter_type == GY_ITER_UBUF) {
			iarg.iov1.iov_base 	= BPF_CORE_READ(pmsg_iter, ubuf);
			iarg.iov1.iov_len 	= BPF_CORE_READ(pmsg_iter, count);
			iarg.pvec.piov		= &iarg.iov1;
			iarg.nr_segs		= 1;
		}
		else if (iter_type == GY_ITER_IOVEC) {
			iarg.pvec.piov		= BPF_CORE_READ(pmsg_iter, __iov);
		}	
		else if (iter_type == GY_ITER_KVEC) {
			iarg.pvec.pkvec		= BPF_CORE_READ(pmsg_iter, kvec);
		}
		else {
			// Not handled
			return 0;
		}	
	}
	else if (bpf_core_field_exists(pmsg_iter_->iter_type)) {	
		// From Kernel 5.14

		struct iov_iter___v5_14		*pmsg_iter = (struct iov_iter___v5_14 *)pmsg_iter_;

		iter_type 			= BPF_CORE_READ(pmsg_iter, iter_type);
		
		copy_mc			 	= false;
		user_backed	 		= iter_type != ITER_KVEC;

		iarg.nr_segs 			= (uint16_t)(uint64_t)BPF_CORE_READ(pmsg_iter, nr_segs);
		iarg.iov_offset			= is_inbound ? 0 : BPF_CORE_READ(pmsg_iter, iov_offset);
	
		if (iter_type == GY_ITER_IOVEC) {
			iarg.pvec.piov		= BPF_CORE_READ(pmsg_iter, iov);
		}	
		else if (iter_type == GY_ITER_KVEC) {
			iarg.pvec.pkvec		= BPF_CORE_READ(pmsg_iter, kvec);
		}
		else {
			// Not handled
			return 0;
		}	
	}
	else {
		struct iov_iter___v5_10		*pmsg_iter = (struct iov_iter___v5_10 *)pmsg_iter_;

		uint8_t				gtype = (u8)BPF_CORE_READ(pmsg_iter, type) & 0xFC;

		if (gtype == 4) {
			iter_type		= GY_ITER_IOVEC;
		}	
		else if (gtype == 8) {
			iter_type		= GY_ITER_KVEC;
		}
		else {
			// Not handled
			return 0;
		}	

		copy_mc			 	= false;
		user_backed 			= iter_type != ITER_KVEC;

		iarg.nr_segs 			= (uint16_t)(uint64_t)BPF_CORE_READ(pmsg_iter, nr_segs);
		iarg.iov_offset			= is_inbound ? 0 : BPF_CORE_READ(pmsg_iter, iov_offset);
	
		if (iter_type == GY_ITER_IOVEC) {
			iarg.pvec.piov		= BPF_CORE_READ(pmsg_iter, iov);
		}	
		else if (iter_type == GY_ITER_KVEC) {
			iarg.pvec.pkvec		= BPF_CORE_READ(pmsg_iter, kvec);
		}
		else {
			// Not handled
			return 0;
		}	
	}	

	if (iarg.nr_segs == 0) {
		iarg.nr_segs 		= 1;
	}	

	__builtin_memcpy(&iarg.tuple, &tuple, sizeof(tuple));

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
	u64				bytes_received;

	size_t				tbytes = ret, maxbytes = tbytes > TMAX_TOTAL_PAYLOAD_LEN ? TMAX_TOTAL_PAYLOAD_LEN : tbytes;

	uint32_t			actendseq = BPF_CORE_READ(ptcp, write_seq), startseq = actendseq - tbytes;
	uint32_t			nxt_cli_seq = BPF_CORE_READ(ptcp, rcv_nxt);
	
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
			
			phdr->ts_ns			= bpf_ktime_get_ns();

			__builtin_memcpy(&phdr->tuple, &parg->tuple, sizeof(phdr->tuple));

			// Send the SYN/ACK indicator to userspace
			phdr->len			= 0;
			phdr->pid			= pid >> 32;
			phdr->nxt_cli_seq		= nxt_cli_seq;
			phdr->nxt_ser_seq		= startseq;
			phdr->is_inbound		= false;
			phdr->tcp_flags			= GY_TH_SYN | GY_TH_ACK;
			phdr->npadbytes			= 0;

			bpf_ringbuf_submit(phdr, 0);
		}
	}

	read_iov_data(parg, maxbytes, false /* is_inbound */, startseq, nxt_cli_seq);

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
	if (flags & (MSG_PEEK | MSG_ERRQUEUE | MSG_OOB)) {
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
	u64				bytes_sent;

	size_t				tbytes = ret;
	uint32_t			maxbytes = tbytes > TMAX_TOTAL_PAYLOAD_LEN ? TMAX_TOTAL_PAYLOAD_LEN : tbytes; 

	uint32_t			actendseq = BPF_CORE_READ(ptcp, copied_seq), startseq = actendseq - tbytes;
	uint32_t			nxt_ser_seq = BPF_CORE_READ(ptcp, write_seq);
	
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
			
			phdr->ts_ns			= bpf_ktime_get_ns();

			__builtin_memcpy(&phdr->tuple, &parg->tuple, sizeof(phdr->tuple));

			// Send the SYN indicator to userspace
			phdr->len			= 0;
			phdr->pid			= pid >> 32;
			phdr->nxt_ser_seq		= nxt_ser_seq;
			phdr->nxt_cli_seq		= startseq;
			phdr->is_inbound		= false;
			phdr->tcp_flags			= GY_TH_SYN;
			phdr->npadbytes			= 0;

			bpf_ringbuf_submit(phdr, 0);
		}
	}

	read_iov_data(parg, maxbytes, true /* is_inbound */, startseq, nxt_ser_seq);

done :
	bpf_map_delete_elem(&iovargmap, &pid);
	
	return 0;
}	

SEC("fexit/tcp_recvmsg")
int BPF_PROG(fexit_tcp_recvmsg_exit, struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len, int ret)
{
	return do_tcp_recvmsg_exit(sk, msg, ret);
}

SEC("fexit/tcp_recvmsg")
int BPF_PROG(fexit_tcp_recvmsg_old_exit, struct sock *sk, struct msghdr *msg, size_t len, int nonblock, int flags, int *addr_len, int ret)
{
	return do_tcp_recvmsg_exit(sk, msg, ret);
}
