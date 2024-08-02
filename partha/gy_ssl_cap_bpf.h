//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_ssl_cap_common.h"
#include			"gy_libbpf.h"
#include			"gy_folly_stack_map.h"
#include			"gy_ssl_cap_util.h"
#include			"gy_ssl_cap.skel.h"

namespace gyeeta {

class GY_SSLCAP
{
public :
	using GY_SSLCAP_OBJ			= GY_LIBBPF_OBJ<gy_ssl_cap_bpf>;
	using LINK_VEC				= std::vector<UNIQ_BPF_LINK_PTR>;

	struct LinkSharedVec
	{
		LINK_VEC			vec_;
		std::atomic<int64_t>		shrcnt_		{1};

		LinkSharedVec(LINK_VEC && vec) noexcept
			: vec_(std::move(vec))
		{}	

		int64_t get_shr_cnt() const noexcept
		{
			return shrcnt_.load(mo_acquire);
		}	

		void add_shr_cnt_locked() noexcept
		{
			shrcnt_.fetch_add(1, mo_relaxed);
		}	

		int64_t del_shr_cnt_locked() noexcept
		{
			return shrcnt_.fetch_sub(1, mo_relaxed) - 1;
		}	

	};	

	enum SSL_PROBESTATE : uint8_t
	{
		SSL_PROBE_UNUINIT		= 0,
		SSL_PROBE_DISABLED,
		SSL_PROBE_DETACHED,
		SSL_PROBE_ATTACHED,
	};	

	using LINK_PATH_MAP			= folly::F14NodeMap<std::string, LinkSharedVec, FollyTransparentStringHash, FollyTransparentStringEqual>;
	using PID_PATH_MAP			= std::unordered_map<pid_t, std::string, GY_JHASHER<pid_t>>;
	
	GY_SSLCAP()				= default;

	GY_SSLCAP(GY_EBPF_CB cb, void *pcb_cookie);

	// Will update pidarr and set skipped pids to 0
	size_t add_procs_with_init(pid_t *pidarr, size_t npids, GY_EBPF_CB cb, void *pcb_cookie, char (&errorbuf)[256]);

	// Will update pidarr and set skipped pids to 0
	size_t add_procs(pid_t *pidarr, size_t npids, char (&errorbuf)[256]);
	
	void del_procs(pid_t *pidarr, size_t npids);
	
	int poll(int timeout_ms) noexcept
	{
		if (pdatapool_) {
			return pdatapool_->poll(timeout_ms);
		}

		return -1;
	}	

	bool probes_attached(bool try_attach = false) noexcept
	{
		SCOPE_GY_MUTEX			sc(statemutex_);

		if (state_ != SSL_PROBE_ATTACHED) {
			if (try_attach && state_ == SSL_PROBE_DETACHED) {

				try {
					try_attach_probes_locked();
					
					return true;
				}
				catch(...) {
					return false;
				}
			}	
			
			return false;
		}	

		return true;
	}

	bool probes_disabled() const noexcept
	{
		SCOPE_GY_MUTEX			sc(statemutex_);

		return (state_ == SSL_PROBE_DISABLED);
	}

	bool init_collection(GY_EBPF_CB cb, void *pcb_cookie, bool attach_probes, char (&errorbuf)[256]);

	static bool is_pid_ssl_probable(pid_t pid, char (&errorbuf)[256]) noexcept;

protected :

	int attach_uprobes(pid_t pid, char (&errorbuf)[256]);

	void detach_all_probes_locked();
		
	bool try_attach_probes_locked();

	MAKE_CLASS_FUNC_WRAPPER_NO_ARG(GY_SSLCAP, ring_pool_thread);

	int ring_pool_thread() noexcept;


	mutable GY_MUTEX			statemutex_;

	GY_BTF_INIT				btf_;
	GY_SSLCAP_OBJ				obj_			{"SSL Cap bpf"};
	std::unique_ptr<GY_THREAD>		pthrpool_;

	std::optional<GY_RING_BUFPOOL>		pdatapool_;

	LINK_PATH_MAP				linkpathmap_;
	PID_PATH_MAP				pidpathmap_;
	SSL_PROBESTATE				state_			{ SSL_PROBE_UNUINIT };
};

} // namespace gyeeta

