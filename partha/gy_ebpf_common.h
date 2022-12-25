
#pragma				once

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


} // namespace gyeeta

