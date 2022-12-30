//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma 			once

#include			"gy_common_inc.h"
#include			"gy_rcu_inc.h"
#include			"gy_print_offload.h"
#include			"gy_file_api.h"
#include			"gy_misc.h"
#include			"gy_ebpf_kernel.h"

namespace gyeeta {

enum BPF_PROBE_TYPES_E
{
	PROBE_TCP_CONN_IPv4		= 0,
	PROBE_TCP_CONN_IPv6,
	PROBE_TCP_LISTENER,
	PROBE_TCP_RESPONSE_IPv4,
	PROBE_TCP_RESPONSE_IPv6,
	PROBE_CGROUP_MIGRATE,
	PROBE_CREATE_NS, 
	PROBE_IP_VS_NEW_CONN,

	PROBE_MAX_TYPE,			
};	

static constexpr uint64_t			RESPONSE_BPF_TIME_MSEC		= 5000;	// 5 sec
static constexpr int				MAX_RESP_SAMPLING_SLOTS 	= 10;		
static constexpr uint64_t			RESPONSE_SLOT_MSEC		= RESPONSE_BPF_TIME_MSEC/MAX_RESP_SAMPLING_SLOTS; // 5000/10 = 500 msec/slot

class RESP_SAMPLING
{
public :	
	bool					sample_state_arr_[MAX_RESP_SAMPLING_SLOTS]	{};
	mutable uint8_t				curr_slot_idx_					{0};					
	uint8_t					curr_sampling_pct_				{0};

	RESP_SAMPLING(uint8_t resp_sampling_pct) noexcept
	{
		set_resp_sampling_pct(resp_sampling_pct);
	}	

	void set_resp_sampling_pct(uint8_t resp_sampling_pct) noexcept;
	
	bool get_next_sampling_slot() const noexcept
	{
		curr_slot_idx_++;
		if (curr_slot_idx_ >= MAX_RESP_SAMPLING_SLOTS) {
			curr_slot_idx_ = 0;
		}
		return sample_state_arr_[curr_slot_idx_];
	}	

	uint8_t get_curr_sampling_pct() const noexcept
	{
		return curr_sampling_pct_;
	}	
};	


class TCP_SOCK_HANDLER;
class TASK_HANDLER;
class GY_EBPF_BASE;

class GY_EBPF
{
	std::unique_ptr <GY_EBPF_BASE> 			pbpf_;					
	pthread_t					perf_reader_thr_[PROBE_MAX_TYPE]	{};
	
	TCP_SOCK_HANDLER				*psock_handler_				{nullptr};
	TASK_HANDLER					*ptask_handler_				{nullptr};
	
	COND_VAR<SCOPE_GY_MUTEX>			thr_cond_;	
	std::atomic<int>				nthrs_init_				{0};
	std::atomic<bool>				to_stop_				{false};
	char						buf_error_[256]				{};

	uint32_t					kern_version_num_			{0};
	
	RESP_SAMPLING					resp_sampling_;
	GY_MUTEX					resp_mutex_;
	bool						resp_probe_enabled_			{true};
	bool						resp_sample_enabled_			{false};

	bool						sched_started_				{false};
	bool						ipvs_probe_started_			{false};

public :	
	GY_EBPF(TCP_SOCK_HANDLER *psock = nullptr, TASK_HANDLER *ptask = nullptr, uint8_t resp_sampling_percent = 50);
	
	GY_EBPF(const GY_EBPF &)			= delete;
	GY_EBPF(GY_EBPF &&)				= delete;
	GY_EBPF & operator= (const GY_EBPF &)		= delete;
	GY_EBPF & operator= (GY_EBPF &&)		= delete;

	~GY_EBPF();

	void 				get_ipvs_existing_conns() noexcept;

	// Use this to enable/disable Response time kprobes
	int				set_resp_probe(bool to_enable) noexcept;
	
	int				set_resp_sampling(bool to_enable) noexcept;

	void				set_sampling_pct(uint8_t resp_sampling_percent) noexcept
	{
		resp_sampling_.set_resp_sampling_pct(resp_sampling_percent);
		
	}	

	uint8_t 			get_curr_sampling_pct() const noexcept
	{
		return resp_sampling_.get_curr_sampling_pct();
	}	

	/*
	 * Perf Reader Threads
	 */ 
	int				tcp_conn_ipv4_thread();
	MAKE_CLASS_FUNC_WRAPPER_NO_ARG(GY_EBPF, tcp_conn_ipv4_thread);
	
	int				tcp_conn_ipv6_thread();
	MAKE_CLASS_FUNC_WRAPPER_NO_ARG(GY_EBPF, tcp_conn_ipv6_thread);
	
	int				tcp_listener_thread();
	MAKE_CLASS_FUNC_WRAPPER_NO_ARG(GY_EBPF, tcp_listener_thread);
	
	int				tcp_response_ipv4_thread();
	MAKE_CLASS_FUNC_WRAPPER_NO_ARG(GY_EBPF, tcp_response_ipv4_thread);
	
	int				tcp_response_ipv6_thread();
	MAKE_CLASS_FUNC_WRAPPER_NO_ARG(GY_EBPF, tcp_response_ipv6_thread);
	
	int				cgroup_migrate_thread();
	MAKE_CLASS_FUNC_WRAPPER_NO_ARG(GY_EBPF, cgroup_migrate_thread);
	
	int				create_ns_thread();
	MAKE_CLASS_FUNC_WRAPPER_NO_ARG(GY_EBPF, create_ns_thread);
	
	void				handle_create_ns_event(create_ns_data_t *pevent, bool more_data) noexcept;

	int ip_vs_new_conn_thread_checker() noexcept
	{
		if (ipvs_probe_started_ == true) {
			return ip_vs_new_conn_thread();
		}	
		
		auto lam1 = [this]() -> bool {					
			int nthr = nthrs_init_.fetch_add(1);		
			if (nthr + 1 == gyeeta::PROBE_MAX_TYPE) {
				return true;			
			}				
			else return false;	
		};			
		thr_cond_.cond_signal(lam1);					

		while (to_stop_.load(std::memory_order_relaxed) == false) {					
			if (pbpf_.get() && (0 == access("/proc/net/ip_vs_conn", R_OK))) {
				try {
					INFOPRINT_OFFLOAD("Detected IPVS Activation. Attaching probe now ...\n");

					start_ip_vs_kprobe(pbpf_.get());

					INFOPRINT_OFFLOAD("IPVS Kprobe is now active...\n");
					
					return ip_vs_new_conn_thread();
				}
				GY_CATCH_EXCEPTION(
					ERRORPRINT("Could not start kprobe on ip_vs_conn_new due to %s. Will ignore IPVS conntrack now...\n", GY_GET_EXCEPT_STRING);
					return -1;
				);
			}
			
			gy_msecsleep(1000);
		}

		return 0;
	}	
		

	int				ip_vs_new_conn_thread();
	MAKE_CLASS_FUNC_WRAPPER_NO_ARG(GY_EBPF, ip_vs_new_conn_thread_checker);

	pthread_t			get_perf_tid(BPF_PROBE_TYPES_E type) const noexcept
	{
		if (type < PROBE_MAX_TYPE) {
			return perf_reader_thr_[type];
		}	

		return 0;
	}	

	static GY_EBPF *		get_singleton() noexcept;

private :

	void				next_resp_sampling_update() noexcept
	{
		bool			to_enable = resp_sampling_.get_next_sampling_slot();

		if (to_enable == resp_sample_enabled_) {
			return;
		}

		set_resp_sampling(to_enable);
	}

	void 				start_ip_vs_kprobe(GY_EBPF_BASE *gpbpf); 

	void 				start_ebpf_probes(GY_EBPF_BASE *gpbpf);

	void 				start_probe_threads();
};	

int clear_bpf_kprobes(pid_t pid, int sysfs_dir_fd = -1);

} // namespace gyeeta	

