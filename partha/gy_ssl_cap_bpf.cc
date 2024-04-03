//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_ssl_cap_bpf.h"
#include			"gy_ssl_cap.h"
#include			"gy_svc_net_capture.h"

using 				folly::StringPiece;

namespace gyeeta {

std::optional<GY_SSLCAP>	SSL_CAP_SVC::gsslcap_;
GY_CLOCK_TO_TIME		SSL_CAP_SVC::gclktime_;

GY_SSLCAP::GY_SSLCAP(GY_EBPF_CB cb, void *pcb_cookie)
{
	bool				bret;
	char 				errorbuf[256];

	bret = init_collection(cb, pcb_cookie, false, errorbuf);

	if (!bret) {
		GY_THROW_EXPRESSION("Failed to initialize SSL uprobe collection : %s", errorbuf);
	}	
}	

// Will update pidarr and set skipped pids to 0
size_t GY_SSLCAP::add_procs_with_init(pid_t *pidarr, size_t npids, GY_EBPF_CB cb, void *pcb_cookie, char (&errorbuf)[256])
{
	bool				bret;

	if (!probes_attached()) {

		bret = init_collection(cb, pcb_cookie, true, errorbuf);
		
		if (!bret) {
			return 0;
		}	

	}

	return add_procs(pidarr, npids, errorbuf);
}

// Will update pidarr and set skipped pids to 0
size_t GY_SSLCAP::add_procs(pid_t *pidarr, size_t npids, char (&errorbuf)[256])
{
	int 			ret, fd;
	size_t			nok = 0;

	if (!probes_attached(true /* try_attach */)) {
		return 0;
	}	

	fd = bpf_map__fd(obj_.get()->maps.pid_map);

	if (fd < 0) {
		GY_THROW_SYS_EXCEPTION("Failed to find SSL uprobe fd of libbpf pid_map");
	}	

	for (size_t i = 0; i < npids; ++i) {
		pid_t			pid = pidarr[i];

		ret = attach_uprobes(pid, errorbuf);

		if (ret != 0) {
			pidarr[i] = 0;
			continue;
		}	

		uint32_t			key = pid, value = 1;

		bpf_map_update_elem(fd, &key, &value, BPF_ANY);
		
		nok++;
	}

	return nok;
}

void GY_SSLCAP::del_procs(pid_t *pidarr, size_t npids)
{
	if (!probes_attached()) {
		return;
	}	

	int 				ret, fd;

	fd = bpf_map__fd(obj_.get()->maps.pid_map);

	if (fd < 0) {
		GY_THROW_SYS_EXCEPTION("Failed to find fd of libbpf pid_map");
	}	

	for (ssize_t i = 0; i < (ssize_t)npids; ++i) {
		uint32_t			key = pidarr[i];

		bpf_map_delete_elem(fd, &key);
	}

	SCOPE_GY_MUTEX		sc(statemutex_);

	for (ssize_t i = 0; i < (ssize_t)npids; ++i) {
		pid_t			pid = pidarr[i];
		auto			itp = pidpathmap_.find(pid);

		if (itp != pidpathmap_.end()) {

			auto			it = linkpathmap_.find(itp->second);

			if (it != linkpathmap_.end()) {
				auto			iret = it->second.del_shr_cnt_locked();

				if (iret <= 0) {
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Stopped SSL Capture for PID %d and removing probes as attached count is %ld : Path (%s)\n", 
						pid, iret, it->first.data());

					linkpathmap_.erase(it);
				}
				else {
					DEBUGEXECN(1, 
						INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Stopped SSL Capture for PID %d but keeping probes as attached count is %ld : Path (%s)\n", 
							pid, iret, it->first.data());
					);	
				}	
			}	

			pidpathmap_.erase(itp);
		}
	}

	if (linkpathmap_.empty()) {
		detach_all_probes_locked();
	}	
}

bool GY_SSLCAP::init_collection(GY_EBPF_CB cb, void *pcb_cookie, bool attach_probes, char (&errorbuf)[256])
{
	SCOPE_GY_MUTEX			sc(statemutex_);

	if (state_ == SSL_PROBE_ATTACHED) {
		return true;
	}

	if (state_ == SSL_PROBE_DISABLED) {
		return false;
	}

	int				ret;

	if (state_ == SSL_PROBE_UNUINIT) {
		if (!access("/sys/kernel/btf/vmlinux", R_OK)) {
			if (!probe_ringbuf()) {
				GY_STRNCPY(errorbuf, "SSL Uprobe disabled as BPF Ring buffer not supported on this host. Requires a Linux kernel version 5.8 or higher", sizeof(errorbuf));
				state_ = SSL_PROBE_DISABLED;

				return false;
			}	
		}	
		else {
			GY_STRNCPY(errorbuf, "SSL Uprobe disabled as BPF BTF (CO-RE) not supported on this host. Requires a Linux kernel version 5.8 or higher", sizeof(errorbuf));
			state_ = SSL_PROBE_DISABLED;

			return false;
		}	
		
		INFOPRINTCOLOR(GY_COLOR_GREEN, "Starting SSL Capture eBPF initialization...\n");
	
		bpf_map__set_max_entries(obj_.get()->maps.ssl_conn_map, 8192);
		bpf_map__set_max_entries(obj_.get()->maps.ssl_unmap, 2048);
		bpf_map__set_max_entries(obj_.get()->maps.ssl_initmap, 2048);
		bpf_map__set_max_entries(obj_.get()->maps.ssl_tcp_unmap, 2048);
		bpf_map__set_max_entries(obj_.get()->maps.ssl_write_args_map, 2048);
		bpf_map__set_max_entries(obj_.get()->maps.ssl_read_args_map, 2048);
		bpf_map__set_max_entries(obj_.get()->maps.pid_map, 4096);
		bpf_map__set_max_entries(obj_.get()->maps.sslcapring, 8 * 1024 * 1024);

		try {
			obj_.load_bpf();
		}
		GY_CATCH_EXPRESSION(
			ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to load SSL uprobes : %s\n", GY_GET_EXCEPT_STRING);
			throw;
		);

		pdatapool_.emplace("SSL Cap Pool", bpf_map__fd(obj_.get()->maps.sslcapring), cb, pcb_cookie);

		pthrpool_ = std::make_unique<GY_THREAD>("SSL Pool Thread", GY_SSLCAP::GET_PTHREAD_WRAPPER(ring_pool_thread), this, nullptr, nullptr, false /* start_immed */, 1024 * 1024, 2500, 
				true, true, true, 10000, false);

		pthrpool_->start_thread();
	}

	if (state_ == SSL_PROBE_DETACHED) {
		if (!attach_probes) {
			return true;
		}

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Attaching probes for SSL collection now...\n");
	}

	state_ = SSL_PROBE_DETACHED;

	if (!attach_probes) {
		return true;
	}

	obj_.attach_bpf();

	state_ = SSL_PROBE_ATTACHED;

	return true;
}	

bool GY_SSLCAP::try_attach_probes_locked()
{
	if (state_ != SSL_PROBE_DETACHED) {
		return state_ == SSL_PROBE_ATTACHED;
	}

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Attaching probes for SSL collection now...\n");

	obj_.attach_bpf();

	state_ = SSL_PROBE_ATTACHED;

	return true;
}	


int GY_SSLCAP::attach_uprobes(pid_t pid, char (&errorbuf)[256])
{
	int				ret;

	auto				pssllib = get_pid_ssl_lib(pid, ret, errorbuf);

	if (!pssllib) {
		if (ret != 0) {
			return -1;
		}
		else {
			snprintf(errorbuf, sizeof(errorbuf), "PID %d binary does not link with a supported SSL Library", pid);
			return 1;
		}	
	}	

	auto				libtype = pssllib->get_lib_type();

	if (!((libtype == SSL_LIB_OPENSSL) || (libtype == SSL_LIB_GNUTLS) || (libtype == SSL_LIB_BORINGSSL))) {

		snprintf(errorbuf, sizeof(errorbuf), "Internal Error : Invalid SSL Lib Type %d seen for PID %d", libtype, pid);
		return -1;
	}	

	/*
	 * TODO Add support for these libs...
	 */
	if (libtype == SSL_LIB_GNUTLS || libtype == SSL_LIB_BORINGSSL) {
		snprintf(errorbuf, sizeof(errorbuf), "BPF : SSL Probes for %s library not supported yet : Disabling TLS Probe for PID %d", 
				libtype == SSL_LIB_GNUTLS ? "gnutls lib" : "BoringSSL lib", pid);
		return -1;
	}

	auto				hashbuf = pssllib->get_hash_buf();
	StringPiece			hashview = StringPiece(hashbuf.get());

	const char 			*path = pssllib->get_mount_ns_safe_path();

	if (!path || 0 == *path) {
		snprintf(errorbuf, sizeof(errorbuf), "Internal Error : Invalid SSL Lib Path seen for PID %d", pid);
		return -1;
	}
	else {
		SCOPE_GY_MUTEX		sc(statemutex_);

		auto			it = linkpathmap_.find(hashview);

		if (it != linkpathmap_.end()) {
			it->second.add_shr_cnt_locked();

			pidpathmap_.try_emplace(pid, hashview.data(), hashview.size());

			DEBUGEXECN(1,
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "SSL Capture already enabled for PID %d as path %s already attached %ld times (%s)\n", 
					pid, path, it->second.get_shr_cnt(), hashbuf.get());
			);
			return 0;
		}	
	}	

	LINK_VEC			vec;

	if (libtype == SSL_LIB_OPENSSL) {
		bpf_link			*plink;
		off_t				offset;
		
		vec.reserve(GY_ARRAY_SIZE(SSL_LIB_INFO::opensslfuncs));

		offset = pssllib->get_func_offset("SSL_do_handshake");

		if (offset == 0) {
			snprintf(errorbuf, sizeof(errorbuf), "Failed to get SSL Lib Function SSL_do_handshake offset for PID %d", pid);
			return -1;
		}	

		plink = bpf_program__attach_uprobe(obj_.get()->progs.ssl_do_handshake, false /* retprobe */, -1, path, offset);
		
		if (!plink) {
			snprintf(errorbuf, sizeof(errorbuf), "BPF : Failed to attach Function SSL_do_handshake for PID %d due to %s", pid, gy_get_perror().get());
			return -1;
		}	

		vec.emplace_back(plink);

		plink = bpf_program__attach_uprobe(obj_.get()->progs.ssl_ret_do_handshake, true /* retprobe */, -1, path, offset);
		
		if (!plink) {
			snprintf(errorbuf, sizeof(errorbuf), "BPF : Failed to attach ret function SSL_do_handshake for PID %d due to %s", pid, gy_get_perror().get());
			return -1;
		}	

		vec.emplace_back(plink);
		
		offset = pssllib->get_func_offset("SSL_write");

		if (offset == 0) {
			snprintf(errorbuf, sizeof(errorbuf), "Failed to get SSL Lib Function SSL_write offset for PID %d", pid);
			return -1;
		}	

		plink = bpf_program__attach_uprobe(obj_.get()->progs.ssl_write, false /* retprobe */, -1, path, offset);
		
		if (!plink) {
			snprintf(errorbuf, sizeof(errorbuf), "BPF : Failed to attach Function SSL_write for PID %d due to %s", pid, gy_get_perror().get());
			return -1;
		}	

		vec.emplace_back(plink);

		plink = bpf_program__attach_uprobe(obj_.get()->progs.ssl_ret_write, true /* retprobe */, -1, path, offset);
		
		if (!plink) {
			snprintf(errorbuf, sizeof(errorbuf), "BPF : Failed to attach ret function SSL_write for PID %d due to %s", pid, gy_get_perror().get());
			return -1;
		}	
		
		vec.emplace_back(plink);

		offset = pssllib->get_func_offset("SSL_write_ex");

		if (offset == 0) {
			snprintf(errorbuf, sizeof(errorbuf), "Failed to get SSL Lib Function SSL_write_ex offset for PID %d", pid);
			return -1;
		}	

		plink = bpf_program__attach_uprobe(obj_.get()->progs.ssl_write_ex, false /* retprobe */, -1, path, offset);
		
		if (!plink) {
			snprintf(errorbuf, sizeof(errorbuf), "BPF : Failed to attach Function SSL_write_ex for PID %d due to %s", pid, gy_get_perror().get());
			return -1;
		}	

		vec.emplace_back(plink);

		plink = bpf_program__attach_uprobe(obj_.get()->progs.ssl_ret_write_ex, true /* retprobe */, -1, path, offset);
		
		if (!plink) {
			snprintf(errorbuf, sizeof(errorbuf), "BPF : Failed to attach ret function SSL_write_ex for PID %d due to %s", pid, gy_get_perror().get());
			return -1;
		}	

		vec.emplace_back(plink);

		offset = pssllib->get_func_offset("SSL_read");

		if (offset == 0) {
			snprintf(errorbuf, sizeof(errorbuf), "Failed to get SSL Lib Function SSL_read offset for PID %d", pid);
			return -1;
		}	

		plink = bpf_program__attach_uprobe(obj_.get()->progs.ssl_read, false /* retprobe */, -1, path, offset);
		
		if (!plink) {
			snprintf(errorbuf, sizeof(errorbuf), "BPF : Failed to attach Function SSL_read for PID %d due to %s", pid, gy_get_perror().get());
			return -1;
		}	

		vec.emplace_back(plink);

		plink = bpf_program__attach_uprobe(obj_.get()->progs.ssl_ret_read, true /* retprobe */, -1, path, offset);
		
		if (!plink) {
			snprintf(errorbuf, sizeof(errorbuf), "BPF : Failed to attach ret function SSL_read for PID %d due to %s", pid, gy_get_perror().get());
			return -1;
		}	
		
		vec.emplace_back(plink);

		offset = pssllib->get_func_offset("SSL_read_ex");

		if (offset == 0) {
			snprintf(errorbuf, sizeof(errorbuf), "Failed to get SSL Lib Function SSL_read_ex offset for PID %d", pid);
			return -1;
		}	

		plink = bpf_program__attach_uprobe(obj_.get()->progs.ssl_read_ex, false /* retprobe */, -1, path, offset);
		
		if (!plink) {
			snprintf(errorbuf, sizeof(errorbuf), "BPF : Failed to attach Function SSL_read_ex for PID %d due to %s", pid, gy_get_perror().get());
			return -1;
		}	

		vec.emplace_back(plink);

		plink = bpf_program__attach_uprobe(obj_.get()->progs.ssl_ret_read_ex, true /* retprobe */, -1, path, offset);
		
		if (!plink) {
			snprintf(errorbuf, sizeof(errorbuf), "BPF : Failed to attach ret function SSL_read_ex for PID %d due to %s", pid, gy_get_perror().get());
			return -1;
		}	

		vec.emplace_back(plink);

		offset = pssllib->get_func_offset("SSL_shutdown");

		if (offset == 0) {
			snprintf(errorbuf, sizeof(errorbuf), "Failed to get SSL Lib Function SSL_shutdown offset for PID %d", pid);
			return -1;
		}	

		plink = bpf_program__attach_uprobe(obj_.get()->progs.ssl_shutdown, false /* retprobe */, -1, path, offset);
		
		if (!plink) {
			snprintf(errorbuf, sizeof(errorbuf), "BPF : Failed to attach Function SSL_shutdown for PID %d due to %s", pid, gy_get_perror().get());
			return -1;
		}	

		vec.emplace_back(plink);

		offset = pssllib->get_func_offset("SSL_set_ex_data");

		if (offset == 0) {
			snprintf(errorbuf, sizeof(errorbuf), "Failed to get SSL Lib Function SSL_set_ex_data offset for PID %d", pid);
			return -1;
		}	

		plink = bpf_program__attach_uprobe(obj_.get()->progs.ssl_set_ex_data, false /* retprobe */, -1, path, offset);
		
		if (!plink) {
			snprintf(errorbuf, sizeof(errorbuf), "BPF : Failed to attach Function SSL_set_ex_data for PID %d due to %s", pid, gy_get_perror().get());
			return -1;
		}	

		vec.emplace_back(plink);

		offset = pssllib->get_func_offset("SSL_set_accept_state");

		if (offset == 0) {
			snprintf(errorbuf, sizeof(errorbuf), "Failed to get SSL Lib Function SSL_set_accept_state offset for PID %d", pid);
			return -1;
		}	

		plink = bpf_program__attach_uprobe(obj_.get()->progs.ssl_set_accept_state, false /* retprobe */, -1, path, offset);
		
		if (!plink) {
			snprintf(errorbuf, sizeof(errorbuf), "BPF : Failed to attach Function ssl_set_accept_state for PID %d due to %s", pid, gy_get_perror().get());
			return -1;
		}	

		vec.emplace_back(plink);

	}	

	SCOPE_GY_MUTEX		sc(statemutex_);

	pidpathmap_.try_emplace(pid, hashview.data(), hashview.size());

	auto [it, added] 	= linkpathmap_.try_emplace(hashview, std::move(vec));

	if (it != linkpathmap_.end()) {
		if (!added) {
			it->second.add_shr_cnt_locked();

			DEBUGEXECN(1, 
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "SSL Capture already enabled for PID %d as path %s already attached %ld times (%s)\n", 
					pid, path, it->second.get_shr_cnt(), hashbuf.get());
			);
			return 0;
		}	
	}	

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "SSL Capture enabled for PID %d : Attached File path %s Hash Path (%s)\n", pid, path, hashbuf.get());

	return 0;
}	

void GY_SSLCAP::detach_all_probes_locked()
{
	if (state_ < SSL_PROBE_ATTACHED) {
		return;
	}

	INFOPRINTCOLOR(GY_COLOR_CYAN, "Detaching all SSL Capture probes now...\n");

	obj_.detach_bpf();

	state_ = SSL_PROBE_DETACHED;
}	


bool GY_SSLCAP::is_pid_ssl_probable(pid_t pid, char (&errorbuf)[256]) noexcept
{
	*errorbuf = 0;

	try {
		int				ret;

		auto				pssllib = get_pid_ssl_lib(pid, ret, errorbuf);

		return bool(pssllib);
	}
	catch (...) {
		return false;
	}	
}

int GY_SSLCAP::ring_pool_thread() noexcept
{
	uint64_t			nrecs = 0, currrecs = 0;
	int				ret;

	pthrpool_->set_thread_init_done();

try1 :
	try {
		do {
			ret = pdatapool_->poll(2000);

			if (ret < 0 || ((nrecs += ret, currrecs += ret) > 1000)) {
				currrecs = 0;

				if (pthrpool_->is_thread_stop_signalled(mo_relaxed)) {
					break;
				}	
			}
			
		} while (true);
	}
	catch(...) {
		goto try1;
	}	

	return 1;
}	


SSL_CAP_SVC::SSL_CAP_SVC(SVC_NET_CAPTURE & svcnet)
{
	if (!gsslcap_) {
		gsslcap_.emplace(SVC_NET_CAPTURE::svc_ssl_probe_cb, &svcnet);
	}	

}	

SSL_CAP_SVC::SSL_CAP_SVC() noexcept		= default;

SSL_CAP_SVC::~SSL_CAP_SVC() noexcept
{
	SCOPE_GY_MUTEX				slock(mapmutex_);

	for (const auto & [ svcid, _ ] : svcmap_) {
		stop_svc_cap(svcid);
	}
}	


size_t SSL_CAP_SVC::start_svc_cap(const char * comm, uint64_t glob_id, uint16_t port, pid_t *pidarr, size_t npids) noexcept
{
	try {
		char				errorbuf[256];
		auto				*psvcnet = SVC_NET_CAPTURE::get_singleton();
		size_t				nok;

		if (!psvcnet || !psvcnet->apihdlr_ || !psvcnet->apihdlr_->allow_ssl_probe_.load(mo_relaxed)) return 0;

		if (!gsslcap_) {
			// Check if the PID binaries are compatible with our SSL Probes

			bool				isok = false, bret;

			for (int i = 0; (unsigned)i < npids; ++i) {
				pid_t				pid = pidarr[i];

				bret = GY_SSLCAP::is_pid_ssl_probable(pid, errorbuf);

				if (bret) {
					isok = true;
					break;
				}	
			}	
		
			if (!isok) {
				errorbuf[sizeof(errorbuf) - 1] = 0;

				psvcnet->apihdlr_->msgpool_.write(PARSE_MSG_BUF(std::in_place_type<MSG_SVC_SSL_CAP>, glob_id, SSL_REQ_E::SSL_REJECTED, errorbuf));

				return 0;
			}

			try {
				gsslcap_.emplace(SVC_NET_CAPTURE::svc_ssl_probe_cb, psvcnet);
			}
			GY_CATCH_EXPRESSION(
				ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to initialize SSL BPF Probes : %s : Disabling SSL Probes...\n", GY_GET_EXCEPT_STRING);
				psvcnet->apihdlr_->allow_ssl_probe_.store(false, mo_relaxed);

				psvcnet->apihdlr_->msgpool_.write(PARSE_MSG_BUF(std::in_place_type<MSG_SVC_SSL_CAP>, glob_id, SSL_REQ_E::SSL_REJECTED, GY_GET_EXCEPT_STRING));

				return 0;
			);
		}

		std::vector<pid_t>			pidvec;

		pidvec.reserve(npids);

		nok = gsslcap_->add_procs(pidarr, npids, errorbuf);

		if (nok > 0) {
			psvcnet->apihdlr_->msgpool_.write(PARSE_MSG_BUF(std::in_place_type<MSG_SVC_SSL_CAP>, glob_id, SSL_REQ_E::SSL_ACTIVE));

			for (int i = 0; i < (int)npids; ++i) {
				if (pidarr[i] != 0) {
					pidvec.emplace_back(pidarr[i]);
				}	
			}	

			try {
				SCOPE_GY_MUTEX			slock(mapmutex_);

				auto				[it, succ] = svcmap_.try_emplace(glob_id, std::move(pidvec));

				if (!succ && it != svcmap_.end()) {
					it->second = std::move(pidvec);
				}	
			}
			catch(...) {

			}	
		}
		else {
			psvcnet->apihdlr_->msgpool_.write(PARSE_MSG_BUF(std::in_place_type<MSG_SVC_SSL_CAP>, glob_id, SSL_REQ_E::SSL_REJECTED, errorbuf));
		}	
			
		return nok;

	}
	catch(...) {
		return 0;
	}
}	

void SSL_CAP_SVC::stop_svc_cap(uint64_t glob_id) noexcept
{
	if (!gsslcap_) {
		return;
	}

	try {
		SCOPE_GY_MUTEX			slock(mapmutex_);

		auto				it = svcmap_.find(glob_id);

		if (it == svcmap_.end()) {
			return;
		}	

		std::vector<pid_t>		vec = std::move(it->second);

		svcmap_.erase(it);

		slock.unlock();

		gsslcap_->del_procs(vec.data(), vec.size());	
	}
	catch(...) {
	}
}

bool SSL_CAP_SVC::ssl_uprobes_allowed() noexcept
{
	static int			sallowed = 0;

	if (sallowed != 0) {
		return sallowed == 1;
	}	

	if ((0 != access("/sys/kernel/btf/vmlinux", R_OK)) || !probe_ringbuf()) {
		sallowed = -1;

		WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "SSL Uprobe disabled as BPF Ring buffer not supported on this host. Requires a Linux kernel version 5.8 or higher\n");

		return false;
	}	

	sallowed = 1;
	return true;
}

void SVC_NET_CAPTURE::handle_uprobe_cb(void *pdata, int data_size)
{
	if (!pdata || data_size < (signed)sizeof(caphdr_t)) {
		return;
	}

	caphdr_t			event;

	std::memcpy(&event, pdata, sizeof(event));
	
	if ((uint32_t)data_size != event.len + sizeof(event)) {
		return;
	}
	
	PARSE_PKT_HDR			hdr;

	hdr.tv_				= SSL_CAP_SVC::gclktime_.get_timeval(event.ts_ns/1000);
	
	if (event.tuple.ipver != 6) {
		hdr.cliip_.set_ip(event.tuple.cliaddr.cli4addr);
		hdr.serip_.set_ip(event.tuple.seraddr.ser4addr);
	}	
	else {
		hdr.cliip_.set_ip(event.tuple.cliaddr.cli6addr);
		hdr.serip_.set_ip(event.tuple.seraddr.ser6addr);
	}	

	hdr.datalen_			= event.get_act_payload_len();
	hdr.wirelen_			= hdr.datalen_;
	hdr.nxt_cli_seq_		= event.nxt_cli_seq;
	hdr.nxt_ser_seq_		= event.nxt_ser_seq;

	if (event.is_inbound) {
		hdr.start_cli_seq_	= event.get_src_seq_start(); 
		hdr.start_ser_seq_	= event.nxt_ser_seq;
		hdr.dir_		= DirPacket::DirInbound;
	}	
	else {
		hdr.start_cli_seq_	= event.nxt_cli_seq;
		hdr.start_ser_seq_	= event.get_src_seq_start(); 
		hdr.dir_		= DirPacket::DirOutbound;
	}	

	hdr.pid_			= event.pid;
	hdr.netns_			= event.tuple.netns;
	hdr.cliport_			= event.tuple.cliport;
	hdr.serport_			= event.tuple.serport;
	hdr.tcpflags_			= event.tcp_flags;
	hdr.src_			= SRC_UPROBE_SSL;

	if (apihdlr_) {
		apihdlr_->send_pkt_to_parser(hdr, (const uint8_t *)pdata + sizeof(event), hdr.datalen_);
	}
}


	
} // namespace gyeeta

