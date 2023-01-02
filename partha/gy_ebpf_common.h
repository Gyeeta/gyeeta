//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_sys_hardware.h"
#include			"gy_socket_stat.h"
#include			"gy_task_handler.h"
#include			"gy_scheduler.h"

namespace gyeeta {

#define EBPF_PERF_CALLBACK(_type, _class_cb, _cb)								\
	auto _type##_cb_ = [](void *pcb_cookie, void *pdata, int data_size) noexcept				\
	{													\
		if (gy_unlikely(data_size < (signed)sizeof(_type))) {						\
			return;											\
		}												\
														\
		_type				evt;								\
														\
		std::memcpy(&evt, pdata, sizeof(evt));								\
														\
		_class_cb		*_pthis = static_cast<_class_cb *>(pcb_cookie);				\
		_pthis->_cb(&evt, extra_cb_info);								\
	};

#define EBPF_PERF_GET_CB_NAME(_type)		_type##_cb_

/*
 * Specify _cbafter1sec as true only for callbacks which are likely to be sporadic as it will result in
 * a get_usec_clock() call for every callback event.
 */
#define EBPF_PERF_THREAD(_name, _perfbuffer, _idle_cb, _cbafter1sec)						\
int GY_EBPF::_name()												\
{														\
	DEBUGEXECN(1, INFOPRINT_OFFLOAD("Starting eBPF perf thread %s\n", __FUNCTION__););			\
														\
	auto perf_buffer = EBPF_GET_PERF_BUFFER(_perfbuffer);							\
														\
	if (perf_buffer) {											\
														\
		auto lam1 = [this]() -> bool									\
		{												\
			int nthr = nthrs_init_.fetch_add(1);							\
			if (nthr + 1 == gyeeta::PROBE_MAX_TYPE) {						\
				return true;									\
			}											\
			else return false;									\
		};												\
		thr_cond_.cond_signal(lam1);									\
														\
		constexpr bool		cbafter1sec = (_cbafter1sec);						\
		const pid_t 		threadid = syscall(__NR_gettid);					\
		uint64_t		startcusec = get_usec_clock();						\
														\
again1 :													\
		try {												\
			while (to_stop_.load(std::memory_order_relaxed) == false) {				\
				int evcnt = perf_buffer->poll(1000 /* msec */, &extra_cb_info, threadid);	\
				if (evcnt == 0) {								\
					_idle_cb();								\
														\
					if (cbafter1sec) {							\
						startcusec = get_usec_clock();					\
					}									\
				}										\
				else if (cbafter1sec) {								\
					uint64_t		cusec = get_usec_clock();			\
														\
					if (cusec - startcusec > GY_USEC_PER_SEC) {				\
						startcusec	= cusec;					\
														\
						_idle_cb();							\
					}									\
				}										\
			}											\
		}												\
		catch(...) {											\
		}												\
														\
		if (to_stop_.load(std::memory_order_relaxed) == false) {					\
			goto again1;										\
		}												\
		INFOPRINT("ebpf perf thread %s returning as quit received...\n",  __FUNCTION__);		\
	}													\
	else {													\
		ERRORPRINT(#_perfbuffer " perf buffer not found. Signalling object quit\n");			\
														\
		snprintf(buf_error_, sizeof(buf_error_), "perf buffer " #_perfbuffer " not found");		\
														\
		auto lam2 = [this]() -> bool									\
		{ 												\
			to_stop_.store(true);									\
			return true; 										\
		};												\
		thr_cond_.cond_signal(lam2);									\
														\
		return -1;											\
	}													\
														\
	return 0;												\
}


static const char	*gstr_resp_sampling = "Check for ebpf response collection toggle";


static void listener_idle_cb() noexcept
{
	try {
		TCP_SOCK_HANDLER::get_singleton()->notify_new_listener(nullptr, false /* more_data */);
	}
	catch(...) {
	}

	gyeeta::gy_rcu_offline();
}	
		
static void tcpv4_idle_cb() noexcept
{
	TCP_SOCK_HANDLER::get_singleton()->flush_tcp_v4_cache();
	gyeeta::gy_rcu_offline();
}	
		
static void tcpv6_idle_cb() noexcept
{
	TCP_SOCK_HANDLER::get_singleton()->flush_tcp_v6_cache();
	gyeeta::gy_rcu_offline();
}			

bool host_btf_enabled(bool check_module) noexcept;


} // namespace gyeeta

