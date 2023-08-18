//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include 		<vmlinux.h>
#include 		<bpf/bpf_helpers.h>
#include 		<bpf/bpf_core_read.h>
#include 		<bpf/bpf_tracing.h>
#include 		<bpf/bpf_endian.h>

#define			GY_BPF_DEBUG

#include		"test_ssl_cap.h"

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(key_size, sizeof(struct tssl_key));
	__uint(value_size, sizeof(struct tssl_conn_info));
	__uint(max_entries, 1);
} ssl_conn_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(key_size, sizeof(struct tssl_key));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 1);
} ssl_unmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(struct tssl_tcp_val));
	__uint(max_entries, 1);
} ssl_tcp_unmap SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(struct tssl_rw_args));
	__uint(max_entries, 1);
} ssl_write_args_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(struct tssl_rw_args));
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

				bpf_map_update_elem(pid_map, &pid, &val, BPF_ANY);
				return true;
			}	
		}	
	}

	return false;
}	

static bool read_addr_tuple(struct taddr_tuple *ptuple, struct sock *sk, bool * pis_client)
{
	struct inet_sock 		*sockp;
	u16 				family, port1, port2;
	bool				is_inbound;

	sockp = (struct inet_sock *)sk;

	BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);
	
	if (!(family == AF_INET || family == AF_INET6)) {
		return false;
	}	

	port1					= bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	port2 					= bpf_ntohs(BPF_CORE_READ(sockp, inet_sport));

	if (port1 > port2) {
		is_inbound			= false;
		*pis_client			= false;
	}	
	else {
		is_inbound			= true;
		*pis_client			= true;
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
			ptuple->seraddr.ser6addr 	= BPF_CORE_READ(sk, __sk_common.skc_daddr);
			ptuple->cliaddr.cli6addr 	= BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);

			ptuple->serport			= port1;
			ptuple->cliport 		= port2;
		}
		else {
			ptuple->cliaddr.cli6addr 	= BPF_CORE_READ(sk, __sk_common.skc_daddr);
			ptuple->seraddr.ser6addr 	= BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);

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

	// if ports are 0, ignore
	if (ptuple->serport == 0 || ptuple->cliport == 0) {
		return false;
	}

	return true;
}

static bool get_cleartext(void *ctx, struct tssl_conn_info *psslinfo, struct tssl_rw_args *pargs, int nbytes, u8 tcp_flags, u32 pid, bool is_write)
{
	if (nbytes < 0) {
		return false;
	}	
	
	bool 				is_resp;

	if (psslinfo->is_client) {
		is_resp			= !is_write
	}
	else {
		is_resp			= is_write;
	}	

	if (tcp_flags & GY_TH_SYN) {
		psslinfo->nxt_cli_seq	= TSEQ_START + !is_resp;
		psslinfo->nxt_ser_seq	= TSEQ_START + is_resp;
	}	

	uint64_t			ts_ns = bpf_ktime_get_ns();
	uint32_t			startsrcseq, nxt_dst_seq;			

	if (is_resp) {
		startsrcseq		= psslinfo->nxt_ser_seq;
		nxt_dst_seq		= psslinfo->nxt_cli_seq;

		psslinfo->nxt_ser_seq	+= nbytes;
	}
	else {
		startsrcseq		= psslinfo->nxt_cli_seq;
		nxt_dst_seq		= psslinfo->nxt_ser_seq;

		psslinfo->nxt_cli_seq	+= nbytes;
	}	

	uint32_t			nleft = nbytes < TMAX_TOTAL_PAYLOAD_LEN ? nbytes : TMAX_TOTAL_PAYLOAD_LEN, nloops = nleft/TMAX_ONE_PAYLOAD_LEN + 1;
	const uint8_t			*porigsrc = pargs->buf, *pend = porigsrc + nleft, *psrc = porigsrc;

	for (uint32_t i = 0; i < nloops && i < TMAX_TOTAL_PAYLOAD_LEN/TMAX_ONE_PAYLOAD_LEN + 1 && psrc <= pend; ++i) {
		uint32_t			rd, npad, nring;

		rd 				= nleft > TMAX_ONE_PAYLOAD_LEN ? TMAX_ONE_PAYLOAD_LEN : nleft;
		nring 				= align_up_8(sizeof(tcaphdr_t) + rd); 
		npad 				= nring - (sizeof(tcaphdr_t) + rd);

		uint8_t				*pring = bpf_ringbuf_reserve(&sslcapring, nring, 0);

		if (!pring) {
			break;
		}	

		startsrcseq			+= rd;
		
		phdr 				= (struct tcaphdr_t *)pring;

		phdr->ts_ns			= ts_ns;

		__builtin_memcpy(&phdr->tuple, &parg->tuple, sizeof(phdr->tuple));

		phdr->len			= nring - sizeof(*phdr);
		phdr->pid			= pid;
		phdr->nxt_cli_seq		= !is_resp ? startsrcseq : nxt_dst_seq;
		phdr->nxt_ser_seq		= !is_resp ? nxt_dst_seq : startsrcseq;
		phdr->is_inbound		= !is_resp;
		phdr->tcp_flags			= tcp_flags;
		phdr->npadbytes			= npad;

		if (rd > 0 && rd < TMAX_ONE_PAYLOAD_LEN) {
			err = bpf_probe_read_user(pring + sizeof(*phdr), rd, psrc);

			if (err) {
				gy_bpf_printk("ERROR : SSL user bytes read failed err = %d : rd %u bytes : nleft %u bytes\n", err, rd, nleft);
				bpf_ringbuf_discard(pring, 0);
				break;
			}	
		}

		bpf_ringbuf_submit(pring, 0);

		gy_bpf_printk("SUCCESS : SSL user bytes read success rd %u bytes : nleft %u bytes\n", rd, nleft);

		nleft				-= nrd;
		psrc				+= nrd;

		if ((nleft == 0) || (psrc >= pend)) {
			break;
		}	
	}	

	return nleft == 0;
}

static void ssl_rw_probe(void *ssl, void *buffer, size_t *pwritten, bool is_write)
{
	u64				pidtid = bpf_get_current_pid_tgid(), pid = pidtid >> 32;
	
	if (!valid_cap_pid(pid, true /* checkppid */)) {
		return;
	}	

	struct tssl_key			tkey = {};

	tkey.ssl			= ssl;
	tkey.pid			= pid;

	if (is_write) {
		if (0 == bpf_map_delete_elem(&ssl_unmap, &tkey)) {
			// Need to populate ssl_tcp_unmap
			struct tssl_tcp_val		*pval;

			pval = bpf_map_lookup_elem(&ssl_tcp_unmap, &pidtid);

			if (!pval || pval->tkey.ssl != ssl) {
				struct tssl_tcp_val	val = {};

				val.tkey		= tkey;
				val.is_init		= false;

				bpf_map_update_elem(&ssl_tcp_unmap, &pidtid, &val, BPF_ANY);
			}	
		}
	}

	struct tssl_rw_args		args = {};

	args.pssl			= ssl;
	args.buf			= buffer;
	args.pexsize			= pwritten;

	bpf_map_update_elem(is_write ? &ssl_write_args_map : &ssl_read_args_map, &pidtid, &args, BPF_ANY);
}	

static void ssl_ret_rw_probe(void *ctx, bool is_write)
{
	u64				pidtid = bpf_get_current_pid_tgid();
	int 				rc = (int)PT_REGS_RC(ctx), nbytes = 0;	
	
	if (rc <= 0) {
		goto done;
	}

	struct tssl_rw_args		*pargs;

	pargs = bpf_map_lookup_elem(is_write ? &ssl_write_args_map : &ssl_read_args_map, &pidtid);
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

	struct tssl_conn_info		*psslinfo;
	struct tssl_key			key = {};

	key.ssl				= pargs->pssl;
	key.pid				= pidtid >> 32;

	psslinfo = bpf_map_lookup_elem(&ssl_conn_map, &key);

	if (!psslinfo) {
		u32				tval = 0;
		
		bpf_map_update_elem(&ssl_unmap, &key, &tval, BPF_ANY);
		goto done;
	}	

	get_cleartext(ctx, psslinfo, pargs, nbytes, is_resp, GY_TH_ACK, pidtid >> 32, is_write);

done :
	bpf_map_delete_elem(is_write ? &ssl_write_args_map : &ssl_read_args_map, &pidtid);
}	

SEC("uprobe/SSL_do_handshake")
void BPF_UPROBE(ssl_do_handshake, void *ssl) 
{
	u64 				pidtid = bpf_get_current_pid_tgid();
	struct tssl_conn_info		*pssl;
	struct tssl_key			tkey = {};

	tkey.ssl			= ssl;
	tkey.pid			= pidtid >> 32;

	// Handle renegotiation

	pssl = bpf_map_lookup_elem(&ssl_conn_map, &tkey);

	if (!pssl) {
		struct tssl_tcp_val	val = {};

		val.tkey		= tkey;
		val.is_init		= true;

		bpf_map_update_elem(&ssl_tcp_unmap, &pidtid, &val, BPF_ANY);
	}
}	

SEC("uretprobe/SSL_do_handshake")
int BPF_URETPROBE(ssl_do_handshake) 
{
	u64 				pidtid = bpf_get_current_pid_tgid();

	bpf_map_delete_elem(&ssl_tcp_unmap, &pidtid);

	return 0;
}	

SEC("uprobe/ssl_write")
void BPF_UPROBE(ssl_write, void *ssl, void *buffer, int num) 
{
	ssl_rw_probe(ssl, buffer, NULL, true /* is_write */);
}

SEC("uretprobe/ssl_write")
void BPF_URETPROBE(ssl_ret_write) 
{
	ssl_ret_rw_probe(ctx, true /* is_write */);
}

SEC("uprobe/ssl_write_ex")
void BPF_UPROBE(ssl_write_ex, void *ssl, void *buffer, size_t num, size_t *written) 
{
	ssl_rw_probe(ssl, buffer, written, true /* is_write */);
}

SEC("uretprobe/ssl_write_ex")
void BPF_URETPROBE(ssl_ret_write_ex) 
{
	ssl_ret_rw_probe(ctx, true /* is_write */);
}


SEC("uprobe/ssl_read")
void BPF_UPROBE(ssl_read, void *ssl, void *buffer, int num) 
{
	ssl_rw_probe(ssl, buffer, NULL, false /* is_write */);
}

SEC("uretprobe/ssl_read")
void BPF_URETPROBE(ssl_ret_read) 
{
	ssl_ret_rw_probe(ctx, false /* is_write */);
}

SEC("uprobe/ssl_read_ex")
void BPF_UPROBE(ssl_read_ex, void *ssl, void *buffer, size_t num, size_t *readbytes) 
{
	ssl_rw_probe(ssl, buffer, readbytes, false /* is_write */);
}

SEC("uretprobe/ssl_read_ex")
void BPF_URETPROBE(ssl_ret_read_ex) 
{
	ssl_ret_rw_probe(ctx, false /* is_write */);
}

static int upd_tcp_sock(void *ctx, struct sock *sk)
{
	u64 				pidtid = bpf_get_current_pid_tgid();
	struct tssl_tcp_val		*pval;

	pval = bpf_map_lookup_elem(&ssl_tcp_unmap, &pidtid);
	if (!pval) {
		return 0;
	}	

	struct tssl_conn_info		sslinfo = {};
	bool				bret;

	bret = read_addr_tuple(&sslinfo.tup, sk, &sslinfo.is_client);
	if (!bret) {
		goto done;
	}	
	
	if (pval->is_init) {
		struct tssl_rw_args	args = {};

		args.pssl		= pval->tkey.ssl;

		get_cleartext(ctx, &sslinfo, &args, 0, GY_TH_SYN, pidtid >> 32, true /* is_write */);
	}

	bpf_map_update_elem(&ssl_conn_map, &pval->tkey, &sslinfo, BPF_ANY);

done :
	bpf_map_delete_elem(&ssl_tcp_unmap, &pidtid);

	return 0;
}	

SEC("uprobe/SSL_shutdown")
int BPF_UPROBE(ssl_shutdown, void *ssl) 
{
	u64 				pidtid = bpf_get_current_pid_tgid();
	struct tssl_conn_info		*psslinfo;
	struct tssl_key			tkey = {};

	tkey.ssl			= ssl;
	tkey.pid			= pidtid >> 32;

	psslinfo = bpf_map_lookup_elem(&ssl_conn_map, &tkey);
	if (!psslinfo) {
		return 0;
	}

	struct tssl_rw_args		args = {};

	args.pssl			= ssl;

	get_cleartext(ctx, psslinfo, &args, 0, GY_TH_FIN | GY_TH_ACK, pidtid >> 32, true /* is_write */);

	bpf_map_delete_elem(&ssl_conn_map, &tkey);

	return 0;
}

SEC("fentry/tcp_sendmsg")
int BPF_PROG(fentry_tcp_sendmsg_entry, struct sock *sk)
{
	return upd_tcp_sock(ctx, sk);
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


