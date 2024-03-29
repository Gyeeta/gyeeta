//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include		"gy_ebpf.h"
#include		"gy_rcu_inc.h"
#include		"gy_sys_hardware.h"
#include		"gy_socket_stat.h"
#include		"gy_task_handler.h"
#include		"gy_scheduler.h"

#include		"gy_ebpf_common.h"

/*
 * We include the following 2 files and the #define to skip includes from the system dirs
 */
#include 		"compat/linux/bpf.h"
#include 		"compat/linux/bpf_common.h"

#ifndef 		__LINUX_BPF_H__
#define 		__LINUX_BPF_H__
#endif

#include		"BPF.h"

namespace ebpf 
{
	class 			BPF;
}

namespace gyeeta {
	
#include		"gy_ebpf_kernel.cc"
#include		"gy_ebpf_kernel_struct.h"

		
class GY_EBPF_BASE : public ebpf::BPF
{
public :
	uint32_t			max_possible_cpus_		{(uint32_t)ebpf::BPFTable::get_possible_cpu_count()};
	std::vector<uint64_t> 		bpf_resp_vec_;
	const char			*pgip_queue_xmit_		{nullptr};	
	bool				use_per_cpu_config_		{false};

	GY_EBPF_BASE() : ebpf::BPF(0, nullptr, false)
	{
		if (max_possible_cpus_ > 32767) {
			GY_THROW_EXCEPTION("eBPF : Failed to get max possible CPU count");
		}

		bpf_resp_vec_.reserve(max_possible_cpus_);

		for (uint32_t i = 0; i < max_possible_cpus_; ++i) {
			bpf_resp_vec_.push_back(ENABLE_PERF_PROBE);
		}	
	}
};	
		
thread_local		bool extra_cb_info;
static GY_EBPF		*pgebf_;	

#define EBPF_GET_PERF_BUFFER(_perfbuffer)	pbpf_->get_perf_buffer(#_perfbuffer)

GY_EBPF *		GY_EBPF::get_singleton() noexcept
{
	return pgebf_;
}	

GY_EBPF::GY_EBPF(TCP_SOCK_HANDLER *psock, TASK_HANDLER *ptask, uint8_t resp_sampling_percent)
	: psock_handler_(psock), ptask_handler_(ptask), resp_sampling_(resp_sampling_percent)
{
	if (!psock_handler_) {
		psock_handler_ = TCP_SOCK_HANDLER::get_singleton();
		if (!psock_handler_) {
			GY_THROW_EXCEPTION("TCP Socket Handler singleton not yet initialized");
		}	
	}

	if (!ptask_handler_) {
		ptask_handler_ = TASK_HANDLER::get_singleton();
		if (!ptask_handler_) {
			GY_THROW_EXCEPTION("Task Handler singleton not yet initialized");
		}	
	}

	auto schedshrnocatch = GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_NO_CATCHUP);
	if (!schedshrnocatch) {
		GY_THROW_EXCEPTION("Scheduler singletons not yet initialized");
	}

	std::string			bpf_program(gbpf_kernel_buf1);

	bpf_program.append(gbpf_kernel_buf2);
	bpf_program.append(gbpf_kernel_buf3);

	std::vector<std::string> 	cflags {};


	auto pbpf = std::make_unique <GY_EBPF_BASE>();

	auto pos = OS_INFO::get_singleton();
	if (pos) {
		/*
		 * We check if kernel version is >= 4.7.0 and if so, use the percpu array for TCP Response
		 */
		kern_version_num_ = pos->get_kernel_version(); 

		if (kern_version_num_ >= 0x040700) {
			pbpf->use_per_cpu_config_ = true;
			cflags.emplace_back("-DUSE_PERCPU_TABLE=1");
		}	

		/*
		 * 4.13 Kernel needs the randomized_struct_fields_start redefinition for task_struct
		 */
		if (kern_version_num_ >= 0x040D00 && kern_version_num_ < 0x040E00) {
			cflags.emplace_back("-DUSE_RANDOMIZE_MACRO=1");
		}	

		cflags.emplace_back("-Wno-macro-redefined");
	}

	auto st1 = pbpf->init(bpf_program, cflags);
	if (st1.code() != 0) {
		GY_THROW_EXCEPTION("Could not initialize BPF tracing : %s", st1.msg().c_str());
	}

	start_ebpf_probes(pbpf.get());
	
	pbpf_ = std::move(pbpf);

	start_probe_threads();

	/*
	 * Now start the RESPONSE_SLOT_MSEC Toggle check.
	 */
	try { 
		schedshrnocatch->add_schedule(5000 + RESPONSE_SLOT_MSEC, RESPONSE_SLOT_MSEC, 0, gstr_resp_sampling, 
		[this] { 
			next_resp_sampling_update();
		});
		sched_started_ = true;
	}
	GY_CATCH_EXCEPTION(ERRORPRINT("Failed to add schedule for response collection toggle : %s\n", GY_GET_EXCEPT_STRING););

	pgebf_ = this;
}
		
GY_EBPF::~GY_EBPF()
{
	if (sched_started_) {
		auto schedshrnocatch = GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_NO_CATCHUP);

		if (schedshrnocatch) {
			schedshrnocatch->cancel_schedule(gstr_resp_sampling, true); 
		}	
	}	
	
	INFOPRINT("Stopping all ebpf perf reader threads...\n");

	to_stop_.store(true);

	for (int i = 0; i < PROBE_MAX_TYPE; i++) {
		if (perf_reader_thr_[i]) {
			gy_pthread_join(perf_reader_thr_[i], nullptr, 1200, true); 
			perf_reader_thr_[i] = 0;
		}	
	}	
}	
		

int GY_EBPF::set_resp_sampling(bool to_enable) noexcept
{
	const uint64_t		updval = (to_enable ? ENABLE_PERF_PROBE : 0);
	const char 		*ptype = (to_enable ? "enable" : "disable");

	try {
		if (pbpf_->use_per_cpu_config_) {
			auto 			config_resp_tbl = pbpf_->get_percpu_array_table<uint64_t>("config_tcp_response");
			const uint32_t		nmax = pbpf_->max_possible_cpus_;

			for (uint32_t i = 0; i < nmax; i++) {
				pbpf_->bpf_resp_vec_[i] = updval;
			}	

			auto col_status = config_resp_tbl.update_value(0, pbpf_->bpf_resp_vec_);
			if (col_status.code() != 0) {
				ONCE_EVERY_MSEC(5000,
					ERRORPRINT_OFFLOAD("Could not set ebpf per cpu TCP response sampling to %s : %s\n", ptype, col_status.msg().c_str());
				);	
				return -1;
			}
		}
		else {
			auto 		config_resp_tbl = pbpf_->get_array_table<uint64_t>("config_tcp_response");

			auto col_status = config_resp_tbl.update_value(0, updval);
			if (col_status.code() != 0) {
				ONCE_EVERY_MSEC(5000,
					ERRORPRINT_OFFLOAD("Could not set ebpf per cpu TCP response sampling to %s : %s\n", ptype, col_status.msg().c_str());
				);
				return -1;
			}
		}	

		resp_sample_enabled_ = to_enable;
		
		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT("Failed to change ebpf Response sampling to %s : %s\n", ptype, GY_GET_EXCEPT_STRING); 
		return -1;
	);
}	

int GY_EBPF::set_resp_probe(bool to_enable) noexcept
{
	try {
		SCOPE_GY_MUTEX		scopelock(&resp_mutex_);

		if (resp_probe_enabled_ == to_enable) {
			return 1;
		}	

		if (to_enable == true) {
			INFOPRINT_OFFLOAD("Now starting Response time kprobes...\n");

			GY_NOMT_COLLECT_PROFILE(10, "Starting trace_ip_xmit kprobes");

			auto tres1 = pbpf_->attach_kprobe(pbpf_->pgip_queue_xmit_, "trace_ip_xmit", 0, BPF_PROBE_ENTRY);
			if (tres1.code() != 0) {
				ERRORPRINT_OFFLOAD("Could not attach to kprobe ip_queue_xmit entry : %s\n", tres1.msg().c_str());
				return -1;
			}

			auto tres2 = pbpf_->attach_kprobe("inet6_csk_xmit", "trace_ip_xmit", 0, BPF_PROBE_ENTRY);
			if (tres2.code() != 0) {
				ERRORPRINT_OFFLOAD("Could not attach to kprobe inet6_csk_xmit entry : %s\n", tres2.msg().c_str());
			}
		}	
		else {
			INFOPRINT_OFFLOAD("Now stopping Response time kprobes...\n");

			GY_NOMT_COLLECT_PROFILE(10, "Stopping trace_ip_xmit kprobes");

			pbpf_->detach_kprobe(pbpf_->pgip_queue_xmit_, BPF_PROBE_ENTRY);
			pbpf_->detach_kprobe("inet6_csk_xmit", BPF_PROBE_ENTRY);
		}	

		resp_probe_enabled_ = to_enable;
		
		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT("Failed to start/stop Response kprobes : %s\n", GY_GET_EXCEPT_STRING); 
		return -1;
	);
}	

void GY_EBPF::start_ebpf_probes(GY_EBPF_BASE *gpbpf)
{
	INFOPRINT("Starting eBPF BCC probes...\n");

	std::optional<GY_EBPF_ISRA>		isra;

	auto res1 = gpbpf->attach_kprobe("tcp_v4_connect", "trace_connect_v4_entry", 0ul, BPF_PROBE_ENTRY);
	if (res1.code() != 0) {
		GY_THROW_EXCEPTION("Could not attach to kprobe tcp_v4_connect entry : %s", res1.msg().c_str());
	}

	auto res2 = gpbpf->attach_kprobe("tcp_v4_connect", "trace_connect_v4_return", 0ul, BPF_PROBE_RETURN);
	if (res2.code() != 0) {
		GY_THROW_EXCEPTION("Could not attach to kprobe tcp_v4_connect return : %s", res2.msg().c_str());
	}

	auto res3 = gpbpf->attach_kprobe("tcp_v6_connect", "trace_connect_v6_entry", 0ul, BPF_PROBE_ENTRY);
	if (res3.code() != 0) {
		GY_THROW_EXCEPTION("Could not attach to kprobe tcp_v6_connect entry : %s", res3.msg().c_str());
	}

	auto res4 = gpbpf->attach_kprobe("tcp_v6_connect", "trace_connect_v6_return", 0ul, BPF_PROBE_RETURN);
	if (res4.code() != 0) {
		GY_THROW_EXCEPTION("Could not attach to kprobe tcp_v6_connect return : %s", res4.msg().c_str());
	}

	auto res5 = gpbpf->attach_kprobe("tcp_set_state", "trace_tcp_set_state_entry", 0ul, BPF_PROBE_ENTRY);
	if (res5.code() != 0) {
		GY_THROW_EXCEPTION("Could not attach to kprobe tcp_set_state entry : %s", res5.msg().c_str());
	}

	auto res6 = gpbpf->attach_kprobe("tcp_close", "trace_close_entry", 0ul, BPF_PROBE_ENTRY);
	if (res6.code() != 0) {
		GY_THROW_EXCEPTION("Could not attach to kprobe tcp_close entry : %s", res6.msg().c_str());
	}

	auto res7 = gpbpf->attach_kprobe("inet_csk_accept", "trace_accept_return", 0ul, BPF_PROBE_RETURN);
	if (res7.code() != 0) {
		GY_THROW_EXCEPTION("Could not attach to kprobe inet_csk_accept return : %s", res7.msg().c_str());
	}

	EBPF_PERF_CALLBACK(tcp_ipv4_event_t, TCP_SOCK_HANDLER, handle_ipv4_conn_event);

	auto open_res4 = gpbpf->open_perf_buffer("tcp_ipv4_event", EBPF_PERF_GET_CB_NAME(tcp_ipv4_event_t), nullptr, psock_handler_, 32);
	if (open_res4.code() != 0) {
		GY_THROW_EXCEPTION("Could not open perf buffer for tcp_ipv4_event : %s", open_res4.msg().c_str());
	}

	EBPF_PERF_CALLBACK(tcp_ipv6_event_t, TCP_SOCK_HANDLER, handle_ipv6_conn_event);

	auto open_res6 = gpbpf->open_perf_buffer("tcp_ipv6_event", EBPF_PERF_GET_CB_NAME(tcp_ipv6_event_t), nullptr, psock_handler_, 32);
	if (open_res6.code() != 0) {
		GY_THROW_EXCEPTION("Could not open perf buffer for tcp_ipv6_event : %s", open_res4.msg().c_str());
	}

	
	auto ns_res = gpbpf->attach_kprobe("create_new_namespaces", "trace_create_ns", 0ul, BPF_PROBE_ENTRY);
	if (ns_res.code() != 0) {
		const char			*pname;

		if (!isra) {
			isra.emplace();
		}	

		pname = isra->get_isra_name("create_new_namespaces");
		if (pname) {
			WARNPRINT("Could not attach to kprobe create_new_namespaces entry (Trying with the isra version %s)\n", pname);
			
			ns_res = gpbpf->attach_kprobe(pname, "trace_create_ns", 0ul, BPF_PROBE_ENTRY);
		}	

		if (ns_res.code() != 0) {
			ERRORPRINT("Could not attach to kprobe create_new_namespaces entry (Skipping) : %s\n", ns_res.msg().c_str());
		}	
	}
	
	EBPF_PERF_CALLBACK(create_ns_data_t, TCP_SOCK_HANDLER, handle_create_ns_event);

	auto open_nsproc = gpbpf->open_perf_buffer("create_ns_event", EBPF_PERF_GET_CB_NAME(create_ns_data_t), nullptr, psock_handler_, 8);
	if (open_nsproc.code() != 0) {
		GY_THROW_EXCEPTION("Could not open perf buffer for create ns event : %s", open_nsproc.msg().c_str());
	}

	auto list_res = gpbpf->attach_kprobe("inet_listen", "trace_inet_listen", 0ul, BPF_PROBE_ENTRY);
	if (list_res.code() != 0) {
		GY_THROW_EXCEPTION("Could not attach to kprobe inet_listen entry : %s", list_res.msg().c_str());
	}
	
	EBPF_PERF_CALLBACK(tcp_listener_event_t, TCP_SOCK_HANDLER, handle_listener_event);

	auto open_list = gpbpf->open_perf_buffer("tcp_listener_event", EBPF_PERF_GET_CB_NAME(tcp_listener_event_t), nullptr, psock_handler_, 8);
	if (open_list.code() != 0) {
		GY_THROW_EXCEPTION("Could not open perf buffer for tcp_listener_event : %s", open_list.msg().c_str());
	}

	// ip_queue_xmit renamed to __ip_queue_xmit in 4.19
	const char *		pip_queue_xmit 		= (kern_version_num_ >= 0x041300 /* 4.19 */ ? "__ip_queue_xmit" : "ip_queue_xmit");
	const char *		pip_queue_xmit_try2 	= (kern_version_num_ >= 0x041300 /* 4.19 */ ? "ip_queue_xmit" : "__ip_queue_xmit");

	gpbpf->pgip_queue_xmit_		= pip_queue_xmit;

	auto tres1 = gpbpf->attach_kprobe(pip_queue_xmit, "trace_ip_xmit", 0, BPF_PROBE_ENTRY);
	if (tres1.code() != 0) {
		tres1 = gpbpf->attach_kprobe(pip_queue_xmit_try2, "trace_ip_xmit", 0, BPF_PROBE_ENTRY);
		if (tres1.code() != 0) {
			GY_THROW_EXCEPTION("Could not attach to kprobe ip_queue_xmit entry : %s", tres1.msg().c_str());
		}	

		gpbpf->pgip_queue_xmit_	= pip_queue_xmit_try2;
	}

	auto tres2 = gpbpf->attach_kprobe("inet6_csk_xmit", "trace_ip_xmit", 0, BPF_PROBE_ENTRY);
	if (tres2.code() != 0) {
		GY_THROW_EXCEPTION("Could not attach to kprobe inet6_csk_xmit entry : %s", tres2.msg().c_str());
	}

	EBPF_PERF_CALLBACK(tcp_ipv4_resp_event_t, TCP_SOCK_HANDLER, handle_ipv4_resp_event);

	auto topen_res4 = gpbpf->open_perf_buffer("ipv4_xmit_perf", EBPF_PERF_GET_CB_NAME(tcp_ipv4_resp_event_t), nullptr, psock_handler_, 32);
	if (topen_res4.code() != 0) {
		GY_THROW_EXCEPTION("Could not open perf buffer for ipv4_xmit_perf : %s", topen_res4.msg().c_str());
	}

	EBPF_PERF_CALLBACK(tcp_ipv6_resp_event_t, TCP_SOCK_HANDLER, handle_ipv6_resp_event);

	auto topen_res6 = gpbpf->open_perf_buffer("ipv6_xmit_perf", EBPF_PERF_GET_CB_NAME(tcp_ipv6_resp_event_t), nullptr, psock_handler_, 32);
	if (topen_res6.code() != 0) {
		GY_THROW_EXCEPTION("Could not open perf buffer for ipv6_xmit_perf : %s", topen_res4.msg().c_str());
	}

	auto list_cg = gpbpf->attach_kprobe("cgroup_migrate", "trace_cgroup_migrate", 0ul, BPF_PROBE_ENTRY);
	if (list_cg.code() != 0) {
		GY_THROW_EXCEPTION("Could not attach to kprobe cgroup_migrate entry : %s", list_cg.msg().c_str());
	}
	
	EBPF_PERF_CALLBACK(cgroup_migrate_event_t, TASK_HANDLER, handle_cgroup_change_event);

	auto open_cg = gpbpf->open_perf_buffer("cgroup_migrate_event", EBPF_PERF_GET_CB_NAME(cgroup_migrate_event_t), nullptr, ptask_handler_, 8);
	if (open_cg.code() != 0) {
		GY_THROW_EXCEPTION("Could not open perf buffer for cgroup_migrate_event : %s", open_cg.msg().c_str());
	}

	if (0 == access("/proc/net/ip_vs_conn", R_OK)) {
		start_ip_vs_kprobe(gpbpf);
		ipvs_probe_started_ = true;
	}
	else {
		INFOPRINT_OFFLOAD("No IPVS Active currently. Will periodically recheck...\n");
		ipvs_probe_started_ = false;
	}	
}	
		
void GY_EBPF::start_ip_vs_kprobe(GY_EBPF_BASE *gpbpf) 
{
	if (ipvs_probe_started_) {
		return;
	}

	auto ipvs_cg = gpbpf->attach_kprobe("ip_vs_conn_new", "trace_ip_vs_conn_return", 0ul, BPF_PROBE_RETURN);
	if (ipvs_cg.code() != 0) {
		GY_THROW_EXCEPTION("Could not attach to kprobe ip_vs_conn_new entry : %s", ipvs_cg.msg().c_str());
	}
	
	EBPF_PERF_CALLBACK(ip_vs_conn_event_t, TCP_SOCK_HANDLER, handle_ip_vs_conn_event);

	auto perf_ipvs_cg = gpbpf->open_perf_buffer("ip_vs_new_conn_event", EBPF_PERF_GET_CB_NAME(ip_vs_conn_event_t), nullptr, psock_handler_, 16);
	if (perf_ipvs_cg.code() != 0) {
		gpbpf->detach_kprobe("ip_vs_conn_new", BPF_PROBE_RETURN);
		GY_THROW_EXCEPTION("Could not open perf buffer for ip_vs_conn event : %s", perf_ipvs_cg.msg().c_str());
	}

	ipvs_probe_started_ = true;
}	
		
EBPF_PERF_THREAD(tcp_conn_ipv4_thread, tcp_ipv4_event, tcpv4_idle_cb, true);
EBPF_PERF_THREAD(tcp_conn_ipv6_thread, tcp_ipv6_event, tcpv6_idle_cb, true);
EBPF_PERF_THREAD(tcp_listener_thread, tcp_listener_event, listener_idle_cb, true);
EBPF_PERF_THREAD(tcp_response_ipv4_thread, ipv4_xmit_perf, gyeeta::gy_rcu_offline, false);
EBPF_PERF_THREAD(tcp_response_ipv6_thread, ipv6_xmit_perf, gyeeta::gy_rcu_offline, false);
EBPF_PERF_THREAD(cgroup_migrate_thread, cgroup_migrate_event, gyeeta::gy_rcu_offline, false);
EBPF_PERF_THREAD(create_ns_thread, create_ns_event, gyeeta::gy_rcu_offline, false);
EBPF_PERF_THREAD(ip_vs_new_conn_thread, ip_vs_new_conn_event, gyeeta::gy_rcu_offline, false);

void GY_EBPF::start_probe_threads()
{
	int			ret;
	
	PTHREAD_FUNC_PTR	cbarr[] = { 
					GY_EBPF::GET_PTHREAD_WRAPPER(tcp_conn_ipv4_thread), 
					GY_EBPF::GET_PTHREAD_WRAPPER(tcp_conn_ipv6_thread), 
					GY_EBPF::GET_PTHREAD_WRAPPER(tcp_listener_thread), 
					GY_EBPF::GET_PTHREAD_WRAPPER(tcp_response_ipv4_thread), 
					GY_EBPF::GET_PTHREAD_WRAPPER(tcp_response_ipv6_thread), 
					GY_EBPF::GET_PTHREAD_WRAPPER(cgroup_migrate_thread), 
					GY_EBPF::GET_PTHREAD_WRAPPER(create_ns_thread), 
					GY_EBPF::GET_PTHREAD_WRAPPER(ip_vs_new_conn_thread_checker) 
				};	


	INFOPRINT("Starting ebpf BCC perf thread spawns ...\n");

	auto lamc = [&]() 
	{ 
		if ((PROBE_MAX_TYPE == nthrs_init_.load()) || (true == to_stop_.load())) {
			return false;
		}
			
		return true; 
	};

	auto lamerr = []() 
	{
		PERRORPRINT("ebpf thread spawn check timed wait. Assuming threads running fine...");
	};	

	auto lamsuccess = []() {};

	for (uint32_t i = 0; i < PROBE_MAX_TYPE && i < GY_ARRAY_SIZE(cbarr); i++) {
		ret = gy_create_thread(&perf_reader_thr_[i], cbarr[i], this, GY_UP_MB(1)); 

		if (ret) {
			PERRORPRINT("Could not create ebpf probe thread %d", i);
			
			snprintf(buf_error_, sizeof(buf_error_), "Thread creation failed");

			goto doneerr;
		}	
	}	
	
	gyeeta::gy_rcu_offline();

	DEBUGEXECN(1, INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "ebpf %d threads spawned. Waiting for confirmation of perf collection activation...\n", PROBE_MAX_TYPE););


	thr_cond_.template cond_timed_wait<decltype(lamc), decltype(lamerr), decltype(lamsuccess)>(lamc, lamerr, lamsuccess, 30 * GY_MSEC_PER_SEC);

	if (true == to_stop_.load()) {
		goto doneerr;
	}	

	if (PROBE_MAX_TYPE != nthrs_init_.load()) {
		snprintf(buf_error_, sizeof(buf_error_), "Perf thread status update failed");

		goto doneerr;
	}	
	
	INFOPRINT_OFFLOAD("All ebpf perf threads active. ebpf object has been initialized...\n");
	
	return;

doneerr :
	
	this->~GY_EBPF();
	GY_THROW_EXCEPTION("Failed to start perf threads for ebpf readers : %s", buf_error_);
}

void GY_EBPF::get_ipvs_existing_conns() noexcept
{
	// Get the current list of IPVS connections
	try {
		if ((pbpf_.get() == nullptr) || (ipvs_probe_started_ == false)) {
			return;
		}

		auto ipvs_cg = pbpf_->attach_kprobe("ip_vs_conn_seq_show", "trace_ip_vs_conn_show", 0ul, BPF_PROBE_ENTRY);
		if (ipvs_cg.code() != 0) {
			GY_THROW_EXCEPTION("Could not attach to kprobe ip_vs_conn_seq_show entry : %s", ipvs_cg.msg().c_str());
		}

		SCOPE_FD		scopefd("/proc/net/ip_vs_conn", O_RDONLY);
		int			connfd = scopefd.get(), sret;
		char			buf[8192];

		if (connfd > 0) {
			do {
				sret = read(connfd, buf, sizeof(buf));

				// Give some time to perf reader to drain the buffer
				gy_msecsleep(50);
			} while (sret > 0);	
		}	

		pbpf_->detach_kprobe("ip_vs_conn_seq_show", BPF_PROBE_ENTRY);
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Failed to get the list of existing IPVS connections : %s\n", GY_GET_EXCEPT_STRING);
	);
}	


bool GY_EBPF::is_bpf_core() noexcept
{
	return false;
}

int clear_bpf_kprobes(pid_t pid, int sysfs_dir_fd)
{
	/*
	 * We need to delete all entries in /sys/kernel/debug/tracing/kprobe_events for PID pid
	 *
	 * For example : 
	 *	p:kprobes/p_tcp_v6_connect_bcc_5072 tcp_v6_connect
	 *
	 */ 
	char			*pkprobe, substr[32], probename[256];
	const char		*path, *ptmp; 
	size_t			kprobesize = 0, nbytes, ncopy;
	int			fd, nclr = 0, ret;

	if (sysfs_dir_fd > 0) {
		path = "./kernel/debug/tracing/kprobe_events"; 
	}
	else {
		path = "/sys/kernel/debug/tracing/kprobe_events";
	}
	{
		SCOPE_FD		fdscope(sysfs_dir_fd, path, O_RDONLY);
		 
		fd = fdscope.get();
		if (fd == -1) {
			PERRORPRINT("Failed to open kprobe_events file in sysfs %s for reading of current bpf probes", path);	
			return -1;
		}	 
		
		pkprobe = read_fd_to_alloc_buffer(fd, &kprobesize, 1024 * 1024 * 10);
	}
	
	GY_SCOPE_EXIT {
		if (pkprobe) {
			free(pkprobe);
		}	
	};	

	if (!(pkprobe && kprobesize)) {
		// No probes active or using perf mechanism
		return 0;
	}	

	snprintf(substr, sizeof(substr), "_bcc_%d", pid);

	STR_RD_BUF		strbuf(pkprobe, kprobesize);

	do {
		ptmp = strbuf.get_next_word(nbytes);
		if (!ptmp) {
			break;	
		}	 
		
		GY_SAFE_MEMCPY(probename, sizeof(probename) - 1, ptmp, nbytes, ncopy);
		probename[ncopy] = '\0';

		if (strstr(probename, substr)) {
			DEBUGEXECN(5, INFOPRINTCOLOR(GY_COLOR_CYAN_ITALIC, "Clearing kprobe %s for bpf\n", probename););
			 
			*probename = '-';

			SCOPE_FD		fdscope(sysfs_dir_fd, path, O_WRONLY | O_APPEND);
			 
			fd = fdscope.get();
			if (fd == -1) {
				PERRORPRINT("Failed to open kprobe_events file in sysfs %s for clearing bpf probes", path);	
				return -1;
			}	 

			ret = write(fd, probename, ncopy);
			if (ret < 0) {
				PERRORPRINT("Failed to clear kprobe %s while clearing bpf probes", probename + 2);
			}	

			nclr++;
		}	

		ptmp = strbuf.get_next_word(nbytes, true, "\n");
		if (!ptmp) {
			break;	
		}	 
		
	} while (true);	

	INFOPRINT("Cleared %d kprobe events during bpf cleanup...\n", nclr);

	return 0;
}	

} // namespace gyeeta		
