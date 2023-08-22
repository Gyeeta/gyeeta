//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_common_inc.h"

#include 			<unistd.h>
#include 			<cstdlib>
#include 			<string>
#include			<cstdint>
#include			<arpa/inet.h>

#include			"gy_libbpf.h"
#include			"gy_pcap_write.h"
#include			"gy_folly_stack_map.h"
#include			"gy_ssl_cap_util.h"

#include			"test_ssl_cap.h"
#include			"test_ssl_cap.skel.h"

using namespace			gyeeta;
using 				folly::StringPiece;

GY_CLOCK_TO_TIME		clktime;
std::atomic<int>		gsig_rcvd(0);

void handle_data(void *pcb_cookie, void *pdata, int data_size)
{
	GY_PCAP_WRITER			*pwriter = (GY_PCAP_WRITER *)pcb_cookie;

	if (!pdata || data_size < (signed)(sizeof(tcaphdr_t))) {
		ERRORPRINT("Invalid ring buffer callback size seen %d : expected min %lu\n", data_size, sizeof(tcaphdr_t));
		return;
	}

	tcaphdr_t			event, *pevent = &event;

	std::memcpy(&event, pdata, sizeof(event));
	
	if ((uint32_t)data_size != pevent->len + sizeof(*pevent)) {
		ERRORPRINT("Invalid ring buffer callback size seen %d : expected size %lu\n", data_size, sizeof(tcaphdr_t) + pevent->len);
		return;
	}
	
	bool				bret;

	if (pevent->is_inbound) {
		bret = pwriter->write_tcp_pkt(clktime.get_timeval(pevent->ts_ns/1000), 
					GY_IP_ADDR(IPv4_v6(pevent->tuple.cliaddr.cli6addr, pevent->tuple.cliaddr.cli4addr, pevent->tuple.ipver == 6)), 
					GY_IP_ADDR(IPv4_v6(pevent->tuple.seraddr.ser6addr, pevent->tuple.seraddr.ser4addr, pevent->tuple.ipver == 6)), 
					pevent->tuple.cliport, pevent->tuple.serport,
					pevent->get_src_seq_start(), pevent->nxt_ser_seq, 
					pevent->tcp_flags, (const uint8_t *)pdata + sizeof(*pevent), pevent->get_act_payload_len());
	}
	else {
		// Outbound
		bret = pwriter->write_tcp_pkt(clktime.get_timeval(pevent->ts_ns/1000), 
					GY_IP_ADDR(IPv4_v6(pevent->tuple.seraddr.ser6addr, pevent->tuple.seraddr.ser4addr, pevent->tuple.ipver == 6)), 
					GY_IP_ADDR(IPv4_v6(pevent->tuple.cliaddr.cli6addr, pevent->tuple.cliaddr.cli4addr, pevent->tuple.ipver == 6)), 
					pevent->tuple.serport, pevent->tuple.cliport,
					pevent->get_src_seq_start(), pevent->nxt_cli_seq, 
					pevent->tcp_flags, (const uint8_t *)pdata + sizeof(*pevent), pevent->get_act_payload_len());
		
	}

	if (!bret) {
		ERRORPRINT("Failed to write packet to pcap file %s\n", pwriter->get_filename());
	}
}	




class TSSLCAP
{
public :
	using TSSLCAP_OBJ			= GY_LIBBPF_OBJ<test_ssl_cap_bpf>;
	using LINK_VEC				= std::vector<UNIQ_BPF_LINK_PTR>;
	using LINK_PATH_MAP			= folly::F14NodeMap<std::string, LINK_VEC, FollyTransparentStringHash, FollyTransparentStringEqual>;
	
	TSSLCAP()				= default;

	~TSSLCAP() noexcept			= default;

	void start_collection(void *pwriter)
	{
		SCOPE_GY_MUTEX			sc(statemutex_);

		if (true == is_init_.load(mo_relaxed)) {
			return;
		}

		int				ret;

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Starting init of SSL collection...\n");
	
		bpf_map__set_max_entries(obj_.get()->maps.ssl_conn_map, 8192);
		bpf_map__set_max_entries(obj_.get()->maps.ssl_unmap, 2048);
		bpf_map__set_max_entries(obj_.get()->maps.ssl_tcp_unmap, 2048);
		bpf_map__set_max_entries(obj_.get()->maps.ssl_write_args_map, 2048);
		bpf_map__set_max_entries(obj_.get()->maps.ssl_read_args_map, 2048);
		bpf_map__set_max_entries(obj_.get()->maps.pid_map, 4096);
		bpf_map__set_max_entries(obj_.get()->maps.sslcapring, 8 * 1024 * 1024);

		obj_.load_bpf();

		obj_.attach_bpf();

		pdatapool_.emplace("SSL Cap Pool", bpf_map__fd(obj_.get()->maps.sslcapring), handle_data, pwriter);

		is_init_.store(true, mo_release);
	}	

	int poll(int timeout_ms) noexcept
	{
		if (pdatapool_) {
			return pdatapool_->poll(timeout_ms);
		}

		return -1;
	}	

	int add_procs(void *pwriter, pid_t pid)
	{
		if (false == is_init_.load(mo_acquire)) {
			start_collection(pwriter);
		}

		int 				ret, fd;

		fd = bpf_map__fd(obj_.get()->maps.pid_map);

		if (fd < 0) {
			GY_THROW_SYS_EXCEPTION("Failed to find fd of libbpf pid_map");
		}	

		ret = attach_uprobes(pid);

		if (ret != 0) {
			return ret;
		}	

		u32				key = pid, value = 1;

		bpf_map_update_elem(fd, &key, &value, BPF_ANY);

		return 0;
	}
	
	int attach_uprobes(pid_t pid)
	{
		char				errbuf[256];
		int				ret;

		auto				pssllib = get_pid_ssl_lib(pid, ret, errbuf);

		if (!pssllib) {
			if (ret != 0) {
				ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to get SSL Lib for PID %d due to %s\n\n", pid, errbuf);
				return -1;
			}
			else {
				INFOPRINTCOLOR(GY_COLOR_CYAN, "PID %d binary does not link with an SSL Library\n\n", pid);
				return 1;
			}	
		}	

		auto				libtype = pssllib->get_lib_type();

		if (!((libtype == SSL_LIB_OPENSSL) || (libtype == SSL_LIB_GNUTLS))) {

			ERRORPRINTCOLOR(GY_COLOR_RED, "Internal Error : Invalid SSL Lib Type %d seen for PID %d\n\n", libtype, pid);
			return -1;
		}	

		auto				hashbuf = pssllib->get_hash_buf();
		StringPiece			hashview = StringPiece(hashbuf.get());

		const char 			*path = pssllib->get_mount_ns_safe_path();

		if (!path || 0 == *path) {
			ERRORPRINTCOLOR(GY_COLOR_RED, "Internal Error : Invalid SSL Lib Path seen for PID %d\n\n", pid);
			return -1;
		}
		else {
			SCOPE_GY_MUTEX		sc(statemutex_);

			auto			it = linkpathmap_.find(hashview);

			if (it != linkpathmap_.end()) {
				INFOPRINTCOLOR(GY_COLOR_GREEN, "SSL Capture already enabled for PID %d as path %s already attached (%s)\n", pid, path, hashbuf.get());
				return 0;
			}	
		}	

		LINK_VEC			vec;

		if (libtype == SSL_LIB_OPENSSL) {
			bpf_link			*plink;
			off_t				offset;
			
			offset = pssllib->get_func_offset("SSL_do_handshake");

			if (offset == 0) {
				ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to get SSL Lib Function SSL_do_handshake offset for PID %d\n\n", pid);
				return -1;
			}	

			plink = bpf_program__attach_uprobe(obj_.get()->progs.ssl_do_handshake, false /* retprobe */, -1, path, offset);
			
			if (!plink) {
				ERRORPRINTCOLOR(GY_COLOR_RED, "BPF : Failed to attach Function SSL_do_handshake for PID %d due to %s\n", pid, gy_get_perror());
				return -1;
			}	

			vec.emplace_back(plink);

			plink = bpf_program__attach_uprobe(obj_.get()->progs.ssl_ret_do_handshake, true /* retprobe */, -1, path, offset);
			
			if (!plink) {
				ERRORPRINTCOLOR(GY_COLOR_RED, "BPF : Failed to attach ret function SSL_do_handshake for PID %d due to %s\n", pid, gy_get_perror());
				return -1;
			}	

			vec.emplace_back(plink);
			
			offset = pssllib->get_func_offset("SSL_write");

			if (offset == 0) {
				ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to get SSL Lib Function SSL_write offset for PID %d\n\n", pid);
				return -1;
			}	

			plink = bpf_program__attach_uprobe(obj_.get()->progs.ssl_write, false /* retprobe */, -1, path, offset);
			
			if (!plink) {
				ERRORPRINTCOLOR(GY_COLOR_RED, "BPF : Failed to attach Function SSL_write for PID %d due to %s\n", pid, gy_get_perror());
				return -1;
			}	

			vec.emplace_back(plink);

			plink = bpf_program__attach_uprobe(obj_.get()->progs.ssl_ret_write, true /* retprobe */, -1, path, offset);
			
			if (!plink) {
				ERRORPRINTCOLOR(GY_COLOR_RED, "BPF : Failed to attach ret function SSL_write for PID %d due to %s\n", pid, gy_get_perror());
				return -1;
			}	
			
			vec.emplace_back(plink);

			offset = pssllib->get_func_offset("SSL_write_ex");

			if (offset == 0) {
				ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to get SSL Lib Function SSL_write_ex offset for PID %d\n\n", pid);
				return -1;
			}	

			plink = bpf_program__attach_uprobe(obj_.get()->progs.ssl_write_ex, false /* retprobe */, -1, path, offset);
			
			if (!plink) {
				ERRORPRINTCOLOR(GY_COLOR_RED, "BPF : Failed to attach Function SSL_write_ex for PID %d due to %s\n", pid, gy_get_perror());
				return -1;
			}	

			vec.emplace_back(plink);

			plink = bpf_program__attach_uprobe(obj_.get()->progs.ssl_ret_write_ex, true /* retprobe */, -1, path, offset);
			
			if (!plink) {
				ERRORPRINTCOLOR(GY_COLOR_RED, "BPF : Failed to attach ret function SSL_write_ex for PID %d due to %s\n", pid, gy_get_perror());
				return -1;
			}	

			vec.emplace_back(plink);

			offset = pssllib->get_func_offset("SSL_read");

			if (offset == 0) {
				ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to get SSL Lib Function SSL_read offset for PID %d\n\n", pid);
				return -1;
			}	

			plink = bpf_program__attach_uprobe(obj_.get()->progs.ssl_read, false /* retprobe */, -1, path, offset);
			
			if (!plink) {
				ERRORPRINTCOLOR(GY_COLOR_RED, "BPF : Failed to attach Function SSL_read for PID %d due to %s\n", pid, gy_get_perror());
				return -1;
			}	

			vec.emplace_back(plink);

			plink = bpf_program__attach_uprobe(obj_.get()->progs.ssl_ret_read, true /* retprobe */, -1, path, offset);
			
			if (!plink) {
				ERRORPRINTCOLOR(GY_COLOR_RED, "BPF : Failed to attach ret function SSL_read for PID %d due to %s\n", pid, gy_get_perror());
				return -1;
			}	
			
			vec.emplace_back(plink);

			offset = pssllib->get_func_offset("SSL_read_ex");

			if (offset == 0) {
				ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to get SSL Lib Function SSL_read_ex offset for PID %d\n\n", pid);
				return -1;
			}	

			plink = bpf_program__attach_uprobe(obj_.get()->progs.ssl_read_ex, false /* retprobe */, -1, path, offset);
			
			if (!plink) {
				ERRORPRINTCOLOR(GY_COLOR_RED, "BPF : Failed to attach Function SSL_read_ex for PID %d due to %s\n", pid, gy_get_perror());
				return -1;
			}	

			vec.emplace_back(plink);

			plink = bpf_program__attach_uprobe(obj_.get()->progs.ssl_ret_read_ex, true /* retprobe */, -1, path, offset);
			
			if (!plink) {
				ERRORPRINTCOLOR(GY_COLOR_RED, "BPF : Failed to attach ret function SSL_read_ex for PID %d due to %s\n", pid, gy_get_perror());
				return -1;
			}	

			vec.emplace_back(plink);

			offset = pssllib->get_func_offset("SSL_shutdown");

			if (offset == 0) {
				ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to get SSL Lib Function SSL_shutdown offset for PID %d\n\n", pid);
				return -1;
			}	

			plink = bpf_program__attach_uprobe(obj_.get()->progs.ssl_shutdown, false /* retprobe */, -1, path, offset);
			
			if (!plink) {
				ERRORPRINTCOLOR(GY_COLOR_RED, "BPF : Failed to attach Function SSL_shutdown for PID %d due to %s\n", pid, gy_get_perror());
				return -1;
			}	

			vec.emplace_back(plink);
			
		}	
		else if (libtype == SSL_LIB_GNUTLS) {
			// TODO
		}

		SCOPE_GY_MUTEX		sc(statemutex_);

		linkpathmap_.try_emplace(hashview, std::move(vec));

		INFOPRINTCOLOR(GY_COLOR_GREEN, "SSL Capture enabled for PID %d : Attached File path %s Hash Path (%s)\n", pid, path, hashbuf.get());

		return 0;
	}	

	GY_BTF_INIT				btf_;
	TSSLCAP_OBJ				obj_			{"SSL Cap bpf"};
	std::optional<GY_RING_BUFPOOL>		pdatapool_;
	GY_MUTEX				statemutex_;
	LINK_PATH_MAP				linkpathmap_;
	std::unordered_set<std::string>		pathset_;
	std::atomic<bool>			is_init_		{false};
};


int handle_signal(int signo)
{
	alarm(5);

	gsig_rcvd.store(signo);

	return signo;
}	



void * sslcap_thr(void *parg)
{
	auto				*psslcap = (TSSLCAP *)parg;

	gy_nanosleep(0, 1000 * 1000 * 100);

	while (gsig_rcvd.load() == 0) {
		psslcap->poll(2000);
	}	

	INFOPRINT("Thread %s returning as signal %s received...\n", __FUNCTION__, gy_signal_str(gsig_rcvd.load()));

	return (void *)0;
}	
MAKE_PTHREAD_FUNC_WRAPPER(sslcap_thr);


void *debug_thread(void *arg)
{
	PROC_CPU_IO_STATS		procstats(getpid(), getpid(), true);

	while (0 == gsig_rcvd.load()) {

		gy_nanosleep(10, 0);

		procstats.get_current_stats(true);
	}

	return nullptr;
}
MAKE_PTHREAD_FUNC_WRAPPER(debug_thread);



int main(int argc, char *argv[])
{
	try {	

		if (argc < 3) {
			IRPRINT("\nUsage : %s <Output pcap path> <PID1 (PID of process to capture)> <PID2> ...\n"
					"\tFor e.g. %s /tmp/test1.pcap 1840 1842\n\n", argv[0], argv[0]);
			return 1;
		}	
		
		int				ret;
		char				buf1[1024];
		size_t				idx;
		std::optional<TSSLCAP>		phdlr;

		gdebugexecn = 11;

		if (!access("/sys/kernel/btf/vmlinux", R_OK)) {
			if (probe_ringbuf()) {
				phdlr.emplace();
			}	
			else {
				ERRORPRINT("BPF Ring buffer not supported on this host. Requires a Linux kernel version 5.8 or higher...\n");
				_exit(1);
			}	
		}	
		else {
			ERRORPRINT("BPF BTF (CO-RE) not supported on this host. Requires a Linux kernel version 5.8 or higher...\n");
			_exit(1);
		}	

		GY_SIGNAL_HANDLER::init_singleton(argv[0], handle_signal, false);

		GY_SIGNAL_HANDLER::get_singleton()->ignore_signal(SIGHUP);

		GY_PCAP_WRITER		wrpcap(argv[1], true /* use_unlocked_io */, false /* throw_if_exists */);
		pthread_t		dbgtid, thrid;

		gy_create_thread(&dbgtid, GET_PTHREAD_WRAPPER(debug_thread), nullptr, 64 * 1024, false);

		ret = gy_create_thread(&thrid, GET_PTHREAD_WRAPPER(sslcap_thr), std::addressof(phdlr.value()), GY_UP_MB(1), true);
		if (ret) {
			PERRORPRINT("Could not create sslcap handling thread");
			return -1;
		}	

		/*
		 * We wait for 2 seconds and then enable capture
		 */
		INFOPRINT("Sleeping for 2 sec : Will start the ebpf load and each process will be captured after an init delay of 2 sec thereafter...\n\n");

		gy_nanosleep(2, 0);

		for (int i = 2; i < argc; ++i) {
			try {
				phdlr->add_procs(&wrpcap, atoi(argv[i]));
			}
			GY_CATCH_MSG("Exception seen while adding PID for ssl capture");

			gy_nanosleep(2, 0);
		}

		pthread_join(thrid, nullptr);

		auto			[ npkts, nbytes, tstart ] = wrpcap.get_stats();

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Output pcap %s : Written # %lu packets : Total %lu bytes : Running since %ld sec\n\n",  
				wrpcap.get_filename(), npkts, nbytes, time(nullptr) - tstart);

		return 0;
	}
	GY_CATCH_MSG("Exception occured for SSL Capture");

	return -1;
}	



