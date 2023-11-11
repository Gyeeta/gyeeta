//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include 		<vmlinux.h>
#include 		<bpf/bpf_helpers.h>
#include 		<bpf/bpf_core_read.h>
#include 		<bpf/bpf_tracing.h>
#include 		<bpf/bpf_endian.h>

#include		"gy_ssl_cap.h"

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(key_size, sizeof(struct ssl_key));
	__uint(value_size, sizeof(struct ssl_conn_info));
	__uint(max_entries, 1);
} ssl_conn_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(key_size, sizeof(struct ssl_key));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 1);
} ssl_unmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(key_size, sizeof(struct ssl_key));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 1);
} ssl_initmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(struct ssl_tcp_val));
	__uint(max_entries, 1);
} ssl_tcp_unmap SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(struct ssl_rw_args));
	__uint(max_entries, 1);
} ssl_write_args_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(struct ssl_rw_args));
	__uint(max_entries, 1);
} ssl_read_args_map SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 1);
} pid_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1);
} sslcapring SEC(".maps");


struct ClearArgs
{
	struct ssl_conn_info 		*psslinfo;
	struct ssl_rw_args 		*pargs;
	int 				nbytes;
	u32 				pid;
	u8 				tcp_flags;
	bool				is_write;
};	

char LICENSE[] SEC("license") = "GPL";

static bool valid_cap_pid(u32 pid, bool checkppid)
{
	u32			*pvalid = bpf_map_lookup_elem(&pid_map, &pid);

	if (pvalid && *pvalid == 1) {
		return true;
	}	
	else if (checkppid == false) {
		return false;
	}	

	struct task_struct 	*task;
	u32			ppid;

	task = (struct task_struct *)bpf_get_current_task();

	if (task) {	
		ppid = BPF_CORE_READ(task, real_parent, tgid);
		
		if (ppid) {
			pvalid = bpf_map_lookup_elem(&pid_map, &ppid);

			if (pvalid && *pvalid == 1) {
				u32			val = 1;

				bpf_map_update_elem(&pid_map, &pid, &val, BPF_ANY);
				return true;
			}	
		}	
	}

	return false;
}	

static bool read_addr_tuple(struct addr_tuple *ptuple, struct sock *sk, bool * pis_client, bool is_write)
{
	struct inet_sock 		*sockp;
	u32				sk_max_ack_backlog = 0;
	u16 				family, port1, port2;
	bool				is_inbound;

	sockp = (struct inet_sock *)sk;

	BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);
	
	if (!(family == AF_INET || family == AF_INET6)) {
		return false;
	}	

	BPF_CORE_READ_INTO(&sk_max_ack_backlog, sk, sk_max_ack_backlog);

	port1					= bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	port2 					= bpf_ntohs(BPF_CORE_READ(sockp, inet_sport));

	if (port1 == 0 || port2 == 0) {
		return false;
	}	

	if (sk_max_ack_backlog > 0) {
		if (is_write) {
			is_inbound			= false;
			*pis_client			= false;
		}	
		else {
			is_inbound			= true;
			*pis_client			= true;
		}	
	}
	else {
		if (!is_write) {
			is_inbound			= false;
			*pis_client			= false;
		}	
		else {
			is_inbound			= true;
			*pis_client			= true;
		}
	}	

	if (family == AF_INET) {

		if (is_inbound) {
			ptuple->seraddr.ser4addr 	= BPF_CORE_READ(sk, __sk_common.skc_daddr);
			ptuple->cliaddr.cli4addr 	= BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);

			ptuple->serport			= port1;
			ptuple->cliport 		= port2;
		}
		else {
			ptuple->cliaddr.cli4addr 	= BPF_CORE_READ(sk, __sk_common.skc_daddr);
			ptuple->seraddr.ser4addr 	= BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);

			ptuple->cliport			= port1;
			ptuple->serport 		= port2;
		}

		ptuple->ipver = 4;
	}	
	else if (family == AF_INET6) {

		if (is_inbound) {
			BPF_CORE_READ_INTO(&ptuple->seraddr.ser6addr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
			BPF_CORE_READ_INTO(&ptuple->cliaddr.cli6addr, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);

			ptuple->serport			= port1;
			ptuple->cliport 		= port2;
		}
		else {
			BPF_CORE_READ_INTO(&ptuple->cliaddr.cli6addr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
			BPF_CORE_READ_INTO(&ptuple->seraddr.ser6addr, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);

			ptuple->cliport			= port1;
			ptuple->serport 		= port2;
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

	if (bpf_core_field_exists(sk->__sk_common.skc_net)) {
		BPF_CORE_READ_INTO(&ptuple->netns, sk, __sk_common.skc_net.net, ns.inum);
	}

	return true;
}

static bool get_cleartext(void *ctx, struct ClearArgs *pcleararg)
{
	struct ssl_conn_info 		*psslinfo 	= pcleararg->psslinfo;
	struct ssl_rw_args 		*pargs		= pcleararg->pargs;
	const int 			nbytes		= pcleararg->nbytes;
	u32 				pid		= pcleararg->pid;
	u8 				tcp_flags	= pcleararg->tcp_flags;
	bool				is_write	= pcleararg->is_write;

	if (nbytes < 0) {
		return false;
	}	
	
	bool 				is_resp;

	if (psslinfo->is_client) {
		is_resp			= !is_write;
	}
	else {
		is_resp			= is_write;
	}	

	if (tcp_flags & GY_TH_SYN) {
		psslinfo->nxt_cli_seq	= SSL_SEQ_START;
		psslinfo->nxt_ser_seq	= SSL_SEQ_START;

		if (is_resp) {
			psslinfo->nxt_cli_seq++;
			psslinfo->cli_started = true;
			psslinfo->ser_started = false;
		}
		else {
			psslinfo->nxt_ser_seq++;
			psslinfo->ser_started = true;
			psslinfo->cli_started = false;
		}	
	}	

	uint64_t			ts_ns = bpf_ktime_get_ns();
	uint32_t			startsrcseq, nxt_dst_seq;			

	if (is_resp) {
		if (nbytes > 0 && psslinfo->ser_started == false) {
			psslinfo->nxt_ser_seq++;
			psslinfo->ser_started = true;
		}	

		startsrcseq		= psslinfo->nxt_ser_seq;
		nxt_dst_seq		= psslinfo->nxt_cli_seq;

		psslinfo->nxt_ser_seq	+= nbytes;
	}
	else {
		if (nbytes > 0 && psslinfo->cli_started == false) {
			psslinfo->nxt_cli_seq++;
			psslinfo->cli_started = true;
		}	

		startsrcseq		= psslinfo->nxt_cli_seq;
		nxt_dst_seq		= psslinfo->nxt_ser_seq;

		psslinfo->nxt_cli_seq	+= nbytes;
	}	

	uint32_t			nleft = (nbytes < SSL_MAX_TOTAL_PAYLOAD_LEN ? nbytes : SSL_MAX_TOTAL_PAYLOAD_LEN), nloops = nleft/SSL_MAX_ONE_PAYLOAD_LEN + 1;
	uint32_t			nskipped = nbytes - nleft, startsrcseq_end = startsrcseq + nbytes;
	const uint8_t			*porigsrc = pargs->buf, *pend = porigsrc + nleft, *psrc = porigsrc;

	for (uint32_t i = 0; i < nloops && i < SSL_MAX_TOTAL_PAYLOAD_LEN/SSL_MAX_ONE_PAYLOAD_LEN + 1 && psrc <= pend; ++i) {
		uint32_t			rd, npad;
		const uint32_t			nring = SSL_MAX_ONE_RING_SZ;

		rd 				= nleft > SSL_MAX_ONE_PAYLOAD_LEN ? SSL_MAX_ONE_PAYLOAD_LEN : nleft;
		npad 				= nring - (sizeof(struct caphdr_t) + rd);

		uint8_t				*pring = bpf_ringbuf_reserve(&sslcapring, nring, 0);

		if (!pring) {
			goto done1;
		}	

		startsrcseq			+= rd;

		struct caphdr_t			*phdr;
		
		phdr 				= (struct caphdr_t *)pring;

		phdr->ts_ns			= ts_ns;

		__builtin_memcpy(&phdr->tuple, &psslinfo->tup, sizeof(phdr->tuple));

		phdr->len			= nring - sizeof(*phdr);
		phdr->pid			= pid;
		phdr->nxt_cli_seq		= !is_resp ? startsrcseq : nxt_dst_seq;
		phdr->nxt_ser_seq		= !is_resp ? nxt_dst_seq : startsrcseq;
		phdr->is_inbound		= !is_resp;
		phdr->tcp_flags			= tcp_flags;
		phdr->npadbytes			= npad;

		if (rd > 0 && rd <= SSL_MAX_ONE_PAYLOAD_LEN) {
			int			err = bpf_probe_read_user(pring + sizeof(*phdr), rd, psrc);

			if (err) {
				bpf_ringbuf_discard(pring, 0);
				goto done1;
			}	
		}

		bpf_ringbuf_submit(pring, 0);

		nleft				-= rd;
		psrc				+= rd;

		if ((nleft == 0) || (psrc >= pend)) {
			break;
		}	
	}	

	if (nskipped > 0) {
		uint32_t			rd, npad;
		const uint32_t			nring = 256 + sizeof(struct caphdr_t);

		rd				= (nskipped > 256 ? 256 : nskipped);
		npad 				= nring - (sizeof(struct caphdr_t) + rd);

		uint8_t				*pring = bpf_ringbuf_reserve(&sslcapring, nring, 0);

		if (!pring) {
			goto done1;
		}	

		struct caphdr_t			*phdr;
		
		phdr 				= (struct caphdr_t *)pring;

		phdr->ts_ns			= ts_ns;

		__builtin_memcpy(&phdr->tuple, &psslinfo->tup, sizeof(phdr->tuple));

		phdr->len			= nring - sizeof(*phdr);
		phdr->pid			= pid;
		phdr->nxt_cli_seq		= !is_resp ? startsrcseq_end : nxt_dst_seq;
		phdr->nxt_ser_seq		= !is_resp ? nxt_dst_seq : startsrcseq_end;
		phdr->is_inbound		= !is_resp;
		phdr->tcp_flags			= tcp_flags;
		phdr->npadbytes			= npad;

		psrc 				= porigsrc + nbytes - rd;

		int				err = bpf_probe_read_user(pring + sizeof(*phdr), rd, psrc);

		if (err) {
			bpf_ringbuf_discard(pring, 0);
			goto done1;
		}	

		bpf_ringbuf_submit(pring, 0);
	}	

done1 :

	return nleft == 0;
}

static void ssl_rw_probe(void *ssl, void *buffer, size_t *pwritten, bool is_write)
{
	u64				pidtid = bpf_get_current_pid_tgid(), pid = pidtid >> 32;
	
	if (!valid_cap_pid(pid, true /* checkppid */)) {
		return;
	}	

	struct ssl_conn_info		*psslinfo;
	struct ssl_key			tkey = {};

	tkey.ssl			= ssl;
	tkey.pid			= pid;

	if (0 == bpf_map_delete_elem(&ssl_unmap, &tkey)) {

		psslinfo = bpf_map_lookup_elem(&ssl_conn_map, &tkey);

		if (!psslinfo) {
			// Need to populate ssl_tcp_unmap
			struct ssl_tcp_val		*pval;
			bool				is_init;

			is_init = (0 == bpf_map_delete_elem(&ssl_initmap, &tkey));

			pval = bpf_map_lookup_elem(&ssl_tcp_unmap, &pidtid);

			if (!pval || pval->tkey.ssl != ssl) {
				struct ssl_tcp_val	val = {};

				val.tkey		= tkey;
				val.is_init		= is_init;

				bpf_map_update_elem(&ssl_tcp_unmap, &pidtid, &val, BPF_ANY);
			}	
		}
	}

	struct ssl_rw_args		args = {};

	args.pssl			= ssl;
	args.buf			= buffer;
	args.pexsize			= pwritten;

	bpf_map_update_elem(is_write ? (void *)&ssl_write_args_map : (void *)&ssl_read_args_map, &pidtid, &args, BPF_ANY);
}	

static void ssl_ret_rw_probe(void *ctx, int rc, bool is_write)
{
	u64				pidtid = bpf_get_current_pid_tgid();
	int 				nbytes = 0;	
	
	if (rc <= 0) {
		goto done;
	}

	struct ssl_rw_args		*pargs;

	pargs = bpf_map_lookup_elem(is_write ? (void *)&ssl_write_args_map : (void *)&ssl_read_args_map, &pidtid);
	if (!pargs) {
		return;
	}	

	if (pargs->pexsize == NULL) {
		nbytes = rc;
	}	
	else {
		if (rc != 1) {
			goto done;
		}	

		size_t			count;
		long 			err;

		err = bpf_probe_read_user(&count, sizeof(size_t), (void *)pargs->pexsize);

		if (err != 0 || (ssize_t)count <= 0) {
			goto done;
		}	

		nbytes = (int)count;
	}	

	struct ssl_conn_info		*psslinfo;
	struct ssl_key			key = {};

	key.ssl				= pargs->pssl;
	key.pid				= pidtid >> 32;

	psslinfo = bpf_map_lookup_elem(&ssl_conn_map, &key);

	if (!psslinfo) {
		u32				tval = 0;
		
		bpf_map_update_elem(&ssl_unmap, &key, &tval, BPF_ANY);
		goto done;
	}	

	struct ClearArgs		clearargs = 
	{
		.psslinfo		= psslinfo,
		.pargs			= pargs,
		.nbytes			= nbytes,
		.pid			= pidtid >> 32,
		.tcp_flags		= GY_TH_ACK,
		.is_write		= is_write,
	};

	get_cleartext(ctx, &clearargs);

done :
	bpf_map_delete_elem(is_write ? (void *)&ssl_write_args_map : (void *)&ssl_read_args_map, &pidtid);
}	

SEC("uprobe")
void BPF_UPROBE(ssl_do_handshake, void *ssl) 
{
	u64 				pidtid = bpf_get_current_pid_tgid(), pid = pidtid >> 32;

	if (!valid_cap_pid(pid, true /* checkppid */)) {
		return;
	}	

	struct ssl_conn_info		*pssl;
	struct ssl_key			tkey = {};

	tkey.ssl			= ssl;
	tkey.pid			= pid;

	// Handle renegotiation

	pssl = bpf_map_lookup_elem(&ssl_conn_map, &tkey);

	if (!pssl) {
		struct ssl_tcp_val	val = {};

		val.tkey		= tkey;
		val.is_init		= true;

		bpf_map_update_elem(&ssl_tcp_unmap, &pidtid, &val, BPF_ANY);
	}

}	

SEC("uretprobe")
int BPF_URETPROBE(ssl_ret_do_handshake) 
{
	u64 				pidtid = bpf_get_current_pid_tgid();

	bpf_map_delete_elem(&ssl_tcp_unmap, &pidtid);

	return 0;
}	

SEC("uprobe")
void BPF_UPROBE(ssl_write, void *ssl, void *buffer, int num) 
{
	ssl_rw_probe(ssl, buffer, NULL, true /* is_write */);
}

SEC("uretprobe")
void BPF_URETPROBE(ssl_ret_write, int rc) 
{
	ssl_ret_rw_probe(ctx, rc, true /* is_write */);
}

SEC("uprobe")
void BPF_UPROBE(ssl_write_ex, void *ssl, void *buffer, size_t num, size_t *written) 
{
	ssl_rw_probe(ssl, buffer, written, true /* is_write */);
}

SEC("uretprobe")
void BPF_URETPROBE(ssl_ret_write_ex, int rc) 
{
	ssl_ret_rw_probe(ctx, rc, true /* is_write */);
}


SEC("uprobe")
void BPF_UPROBE(ssl_read, void *ssl, void *buffer, int num) 
{
	ssl_rw_probe(ssl, buffer, NULL, false /* is_write */);
}

SEC("uretprobe")
void BPF_URETPROBE(ssl_ret_read, int rc) 
{
	ssl_ret_rw_probe(ctx, rc, false /* is_write */);
}

SEC("uprobe")
void BPF_UPROBE(ssl_read_ex, void *ssl, void *buffer, size_t num, size_t *readbytes) 
{
	ssl_rw_probe(ssl, buffer, readbytes, false /* is_write */);
}

SEC("uretprobe")
void BPF_URETPROBE(ssl_ret_read_ex, int rc) 
{
	ssl_ret_rw_probe(ctx, rc, false /* is_write */);
}

static int upd_tcp_sock(void *ctx, struct sock *sk, bool is_write)
{
	u64 				pidtid = bpf_get_current_pid_tgid();
	struct ssl_tcp_val		*pval;

	pval = bpf_map_lookup_elem(&ssl_tcp_unmap, &pidtid);
	if (!pval) {
		return 0;
	}	

	struct ssl_conn_info		sslinfo = {};
	bool				bret;

	bret = read_addr_tuple(&sslinfo.tup, sk, &sslinfo.is_client, is_write);
	if (!bret) {
		goto done;
	}	
	
	if (pval->is_init) {
		struct ssl_rw_args		args = {};

		args.pssl			= pval->tkey.ssl;

		struct ClearArgs		clearargs = 
		{
			.psslinfo		= &sslinfo,
			.pargs			= &args,
			.nbytes			= 0,
			.pid			= pidtid >> 32,
			.tcp_flags		= GY_TH_SYN,
			.is_write		= true,
		};

		get_cleartext(ctx, &clearargs);
	}

	bpf_map_update_elem(&ssl_conn_map, &pval->tkey, &sslinfo, BPF_ANY);

done :
	bpf_map_delete_elem(&ssl_tcp_unmap, &pidtid);

	return 0;
}	

SEC("uprobe")
int BPF_UPROBE(ssl_shutdown, void *ssl) 
{
	u64 				pidtid = bpf_get_current_pid_tgid();
	struct ssl_conn_info		*psslinfo;
	struct ssl_key			tkey = {};

	tkey.ssl			= ssl;
	tkey.pid			= pidtid >> 32;

	psslinfo = bpf_map_lookup_elem(&ssl_conn_map, &tkey);
	if (!psslinfo) {
		bpf_map_delete_elem(&ssl_unmap, &tkey);
		bpf_map_delete_elem(&ssl_initmap, &tkey);

		return 0;
	}

	struct ssl_rw_args		args = {};

	args.pssl			= ssl;

	struct ClearArgs		clearargs = 
	{
		.psslinfo		= psslinfo,
		.pargs			= &args,
		.nbytes			= 0,
		.pid			= pidtid >> 32,
		.tcp_flags		= GY_TH_FIN | GY_TH_ACK,
		.is_write		= true,
	};

	get_cleartext(ctx, &clearargs);

	bpf_map_delete_elem(&ssl_conn_map, &tkey);

	return 0;
}

SEC("uprobe")
void BPF_UPROBE(ssl_set_ex_data, void *ssl) 
{
	u64 				pidtid = bpf_get_current_pid_tgid(), pid = pidtid >> 32;

	if (!valid_cap_pid(pid, true /* checkppid */)) {
		return;
	}	

	struct ssl_conn_info		*pssl;
	struct ssl_key			tkey = {};

	tkey.ssl			= ssl;
	tkey.pid			= pid;

	pssl = bpf_map_lookup_elem(&ssl_conn_map, &tkey);

	if (!pssl) {
		u32				tval = 0;
		
		bpf_map_update_elem(&ssl_unmap, &tkey, &tval, BPF_ANY);
		bpf_map_update_elem(&ssl_initmap, &tkey, &tval, BPF_ANY);
	}	

}	

SEC("fentry/tcp_sendmsg")
int BPF_PROG(fentry_tcp_sendmsg_entry, struct sock *sk)
{
	return upd_tcp_sock(ctx, sk, true /* is_write */);
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_enter_execve(struct trace_event_raw_sys_enter * ctx)
{
	u32				pid = bpf_get_current_pid_tgid() >> 32;

	bpf_map_delete_elem(&pid_map, &pid);
	return 0;
}	


SEC("tracepoint/sched/sched_process_exit")
int sched_process_exit(void *ctx)
{
	u64 				pidtid = bpf_get_current_pid_tgid();
	u32				pid = pidtid >> 32, tid = (u32)pidtid;

	if (pid == tid) {
		bpf_map_delete_elem(&pid_map, &pid);
	}	

	return 0;
}


