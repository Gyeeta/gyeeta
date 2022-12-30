//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_common_inc.h"
#include			"gy_rcu_inc.h"
#include			"gy_sys_hardware.h"
#include			"gy_socket_stat.h"
#include			"gy_task_handler.h"

#include			"gy_ebpf_bpf.h"


namespace gyeeta {
	
	
thread_local		bool extra_cb_info;
static GY_EBPF		*pgebf_;	

#define EBPF_GET_PERF_BUFFER(_perfbuffer)					\
({										\
	GY_PERF_BUFPOOL			*_pbuf = nullptr;			\
										\
	if (pbpf_->_perfbuffer) {						\
		_pbuf = &(*pbpf_->_perfbuffer);					\
	}									\
	_pbuf;									\
})

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

	auto 			schedshrnocatch = GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_NO_CATCHUP);

	if (!schedshrnocatch) {
		GY_THROW_EXCEPTION("Scheduler singletons not yet initialized");
	}

	auto 			pbpf = std::make_unique <GY_EBPF_BASE> ();

	if (pbpf->max_possible_cpus_ > 32767) {
		GY_THROW_EXCEPTION("eBPF : Failed to get max possible CPU count");
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
		
GY_EBPF_BASE::GY_EBPF_BASE()
{
	int			ret;

	if (fentry_can_attach("inet6_csk_xmit", nullptr)) {

		is_fentry_ = true;

		ret = bpf_program__set_attach_target(obj_.get()->progs.fentry_trace_ipv4_xmit, 0, "__ip_queue_xmit");

		if (ret) {
			ret = bpf_program__set_attach_target(obj_.get()->progs.fentry_trace_ipv4_xmit, 0, "ip_queue_xmit");
			
			if (ret) {
				GY_THROW_SYS_EXCEPTION("Failed to attach fentry bpf probe for ip_queue_xmit");
			}	
		}

		ret = bpf_program__set_attach_target(obj_.get()->progs.fentry_trace_ipv6_xmit, 0, "inet6_csk_xmit");
		if (ret) {
			GY_THROW_SYS_EXCEPTION("Failed to attach fentry bpf probe for inet6_csk_xmit");
		}	

		bpf_program__set_autoload(obj_.get()->progs.trace_ipv4_xmit, false);
		bpf_program__set_autoload(obj_.get()->progs.trace_ipv6_xmit, false);
	} 
	else {
		bpf_program__set_autoload(obj_.get()->progs.fentry_trace_ipv4_xmit, false);
		bpf_program__set_autoload(obj_.get()->progs.fentry_trace_ipv6_xmit, false);
	}

	// Disable autoattach for optional probes
	bpf_program__set_autoattach(obj_.get()->progs.trace_create_ns, false);
	bpf_program__set_autoattach(mobj_.get()->progs.trace_ip_vs_conn_show, false);
}	

void GY_EBPF::start_ebpf_probes(GY_EBPF_BASE *gpbpf)
{
	auto			*psched = GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_NO_CATCHUP);

	INFOPRINT("Starting eBPF BPF CO-RE probes...\n");

	gpbpf->obj_.load_bpf();
	gpbpf->obj_.attach_bpf();

	EBPF_PERF_CALLBACK(tcp_ipv4_event_t, TCP_SOCK_HANDLER, handle_ipv4_conn_event);
	gpbpf->tcp_ipv4_event_pool_.emplace("tcp_ipv4_event perf buffer", bpf_map__fd(gpbpf->obj_.get()->maps.tcp_ipv4_event), 32, 
						EBPF_PERF_GET_CB_NAME(tcp_ipv4_event_t), psock_handler_, nullptr, psched);

	EBPF_PERF_CALLBACK(tcp_ipv6_event_t, TCP_SOCK_HANDLER, handle_ipv6_conn_event);
	gpbpf->tcp_ipv6_event_pool_.emplace("tcp_ipv6_event perf buffer", bpf_map__fd(gpbpf->obj_.get()->maps.tcp_ipv6_event), 32, 
						EBPF_PERF_GET_CB_NAME(tcp_ipv6_event_t), psock_handler_, nullptr, psched);

	EBPF_PERF_CALLBACK(tcp_listener_event_t, TCP_SOCK_HANDLER, handle_listener_event);
	gpbpf->tcp_listener_event_pool_.emplace("tcp_listener_event perf buffer", bpf_map__fd(gpbpf->obj_.get()->maps.tcp_listener_event), 8, 
						EBPF_PERF_GET_CB_NAME(tcp_listener_event_t), psock_handler_, nullptr, psched);

	EBPF_PERF_CALLBACK(tcp_ipv4_resp_event_t, TCP_SOCK_HANDLER, handle_ipv4_resp_event);
	gpbpf->ipv4_xmit_perf_pool_.emplace("ipv4_xmit_perf perf buffer", bpf_map__fd(gpbpf->obj_.get()->maps.ipv4_xmit_perf), 32, 
						EBPF_PERF_GET_CB_NAME(tcp_ipv4_resp_event_t), psock_handler_, nullptr, psched);

	EBPF_PERF_CALLBACK(tcp_ipv6_resp_event_t, TCP_SOCK_HANDLER, handle_ipv6_resp_event);
	gpbpf->ipv6_xmit_perf_pool_.emplace("ipv6_xmit_perf perf buffer", bpf_map__fd(gpbpf->obj_.get()->maps.ipv6_xmit_perf), 32, 
						EBPF_PERF_GET_CB_NAME(tcp_ipv6_resp_event_t), psock_handler_, nullptr, psched);

	EBPF_PERF_CALLBACK(cgroup_migrate_event_t, TASK_HANDLER, handle_cgroup_change_event);
	gpbpf->cgroup_migrate_event_pool_.emplace("cgroup_migrate_event perf buffer", bpf_map__fd(gpbpf->obj_.get()->maps.cgroup_migrate_event), 8, 
						EBPF_PERF_GET_CB_NAME(cgroup_migrate_event_t), ptask_handler_, nullptr, psched);

	
	gpbpf->obj_.get()->links.trace_create_ns = bpf_program__attach_kprobe(gpbpf->obj_.get()->progs.trace_create_ns, false, "create_new_namespaces");
	if (!gpbpf->obj_.get()->links.trace_create_ns) {
		PERRORPRINT("Could not attach to kprobe create_new_namespaces entry (Skipping)");
	}

	EBPF_PERF_CALLBACK(create_ns_data_t, TCP_SOCK_HANDLER, handle_create_ns_event);
	gpbpf->create_ns_event_pool_.emplace("create_ns_event perf buffer", bpf_map__fd(gpbpf->obj_.get()->maps.create_ns_event), 8, 
						EBPF_PERF_GET_CB_NAME(create_ns_data_t), psock_handler_);

	if (0 == access("/proc/net/ip_vs_conn", R_OK)) {
		start_ip_vs_kprobe(gpbpf);
		ipvs_probe_started_ = true;
	}
	else {
		INFOPRINT_OFFLOAD("No IPVS Active currently. Will periodically recheck...\n");
		ipvs_probe_started_ = false;
	}	
}

int GY_EBPF::set_resp_sampling(bool to_enable) noexcept
{
	const uint64_t		updval = (to_enable ? ENABLE_PERF_PROBE : 0);
	const char 		*ptype = (to_enable ? "enable" : "disable");

	try {
		uint32_t			key = 0;
		int				ret;

		const uint32_t			nmax = pbpf_->max_possible_cpus_;
		uint64_t			values[nmax];

		for (uint32_t i = 0; i < nmax; i++) {
			values[i] = updval;
		}	

		ret = bpf_map__update_elem(pbpf_->obj_.get()->maps.config_tcp_response, &key, sizeof(key), values, nmax * sizeof(uint64_t), BPF_ANY);
		if (ret != 0) {
			/*ERRORPRINT("Could not set per cpu TCP response sampling to %s\n", ptype);*/
			return -1;
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
	// Not implemented
	return 0;
}	

bool GY_EBPF::is_bpf_core() noexcept
{
	return true;
}


void GY_EBPF::start_ip_vs_kprobe(GY_EBPF_BASE *gpbpf) 
{
	auto			*psched = GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_NO_CATCHUP);

	if (ipvs_probe_started_) {
		return;
	}

	gpbpf->mobj_.load_bpf();
	gpbpf->mobj_.attach_bpf();

	gpbpf->mobj_.get()->links.trace_ip_vs_conn_return = bpf_program__attach_kprobe(gpbpf->mobj_.get()->progs.trace_ip_vs_conn_return, true /* retprobe */, "ip_vs_conn_new");
	if (!gpbpf->mobj_.get()->links.trace_ip_vs_conn_return) {
		GY_THROW_SYS_EXCEPTION("Could not attach to kprobe ip_vs_conn_new entry");
	}
	
	EBPF_PERF_CALLBACK(ip_vs_conn_event_t, TCP_SOCK_HANDLER, handle_ip_vs_conn_event);
	gpbpf->ip_vs_new_conn_event_pool_.emplace("ip_vs_new_conn_event perf buffer", bpf_map__fd(gpbpf->mobj_.get()->maps.ip_vs_new_conn_event), 16, 
						EBPF_PERF_GET_CB_NAME(ip_vs_conn_event_t), psock_handler_, nullptr, psched);

	ipvs_probe_started_ = true;
}	
		

EBPF_PERF_THREAD(tcp_conn_ipv4_thread, tcp_ipv4_event_pool_, tcpv4_idle_cb, true);
EBPF_PERF_THREAD(tcp_conn_ipv6_thread, tcp_ipv6_event_pool_, tcpv6_idle_cb, true);
EBPF_PERF_THREAD(tcp_listener_thread, tcp_listener_event_pool_, listener_idle_cb, true);
EBPF_PERF_THREAD(tcp_response_ipv4_thread, ipv4_xmit_perf_pool_, gyeeta::gy_rcu_offline, false);
EBPF_PERF_THREAD(tcp_response_ipv6_thread, ipv6_xmit_perf_pool_, gyeeta::gy_rcu_offline, false);
EBPF_PERF_THREAD(cgroup_migrate_thread, cgroup_migrate_event_pool_, gyeeta::gy_rcu_offline, false);
EBPF_PERF_THREAD(create_ns_thread, create_ns_event_pool_, gyeeta::gy_rcu_offline, false);
EBPF_PERF_THREAD(ip_vs_new_conn_thread, ip_vs_new_conn_event_pool_, gyeeta::gy_rcu_offline, false);

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


	INFOPRINT("Starting ebpf BPF CO-RE perf thread spawns ...\n");

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

		pbpf_->mobj_.get()->links.trace_ip_vs_conn_show = bpf_program__attach_kprobe(pbpf_->mobj_.get()->progs.trace_ip_vs_conn_show, false, "ip_vs_conn_seq_show");
		if (!pbpf_->mobj_.get()->links.trace_ip_vs_conn_show) {
			GY_THROW_SYS_EXCEPTION("Could not attach to kprobe ip_vs_conn_seq_show entry");
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

		bpf_link__destroy(pbpf_->mobj_.get()->links.trace_ip_vs_conn_show);
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Failed to get the list of existing IPVS connections : %s\n", GY_GET_EXCEPT_STRING);
	);
}	


int clear_bpf_kprobes(pid_t pid, int sysfs_dir_fd)
{
	/*
	 * Not needed for libbpf...
	 */
	return 0;
}


} // namespace gyeeta
