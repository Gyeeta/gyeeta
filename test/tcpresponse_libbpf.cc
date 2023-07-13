//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_common_inc.h"
#include			"gy_file_api.h"
#include			"gy_pkt_pool.h"

#include 			<unistd.h>
#include 			<cstdlib>
#include 			<string>
#include			<cstdint>
#include			<arpa/inet.h>

#include			"gy_statistics.h"
#include			"gy_libbpf.h"
#include			"tcpresponse_libbpf.h"
#include			"tcpresponse_libbpf.skel.h"

#include			"tcpresponse_bpf.h"

#include	 		<unordered_map>
#include 			"gy_inet_inc.h"

using namespace			gyeeta;

uint64_t 			gstarttimens;

void				*glbpf = nullptr;

std::atomic<int>		gsig_rcvd(0);

struct GY_RESP_DIST
{
	GY_INET_SOCK				sock;
	RESP_TIME_HISTOGRAM<NULL_MUTEX>		dist;
	uint64_t				last_bytes_received;
};	

typedef std::unordered_map<uint16_t, GY_RESP_DIST> 	GY_DIST_MAP;

template <typename T>
void process_ip_resp(T __restrict__ *pevent)
{
	thread_local 	uint32_t		glast_sndtime = 0;
	thread_local	time_t			glast_time_t = 0, gtlastprint = 0;
	thread_local 	GY_DIST_MAP		gymap;

	pevent->tup.sport = ntohs(pevent->tup.sport);
	pevent->tup.dport = ntohs(pevent->tup.dport);

	int			resp = pevent->lsndtime - pevent->lrcvtime;
	uint32_t		tcur = pevent->lsndtime;
	bool			print_msg = false;
	size_t			bucket_id;

	// Ignore responses > 1000 sec or negative 
	if ((unsigned)resp > 1000'000) {
		return;
	}	

	if (glast_sndtime != tcur/100) { 
		/*
		 * Update glast_sndtime every 100 msec
		 */
		glast_sndtime = tcur/100;
		glast_time_t = time(nullptr);

		if (glast_time_t - gtlastprint >= 100) {
			print_msg = true;
			gtlastprint = glast_time_t;
		}	
	}

	try {
		auto && data = gymap[pevent->tup.sport];

		if (data.sock.port == 0) {
			GY_INET_SOCK		sock(pevent->tup.saddr, pevent->tup.sport, pevent->tup.netns);
			data.sock = sock;
			data.last_bytes_received = 0;
		}	

		if (data.last_bytes_received != pevent->bytes_received) {
			data.last_bytes_received = pevent->bytes_received;
			data.dist.add_data(resp, glast_time_t, bucket_id);
		}
		else {
			if (print_msg) {
				if (!(gdebugexecn >= 2)) {
					goto print1;
				}
				else {
					goto print2;
				}	
			}	
			return;
		}	
		
		if (gdebugexecn >= 2) {
print2:			
			char			clibufevent[512], bufevent[512];

			GY_INET_SOCK		clisock(pevent->tup.daddr, pevent->tup.dport, pevent->tup.netns);
			clisock.get_sock_info_str(clibufevent, sizeof(clibufevent), "Client");

			GY_INET_SOCK		sock(pevent->tup.saddr, pevent->tup.sport, pevent->tup.netns);

			sock.get_sock_info_str(bufevent, sizeof(bufevent), "Server");

			DEBUGEXECN(2, INFOPRINT("Response time of " GY_COLOR_GREEN "%d msec " GY_COLOR_RESET "for %s to " GY_COLOR_YELLOW "%s" 
					GY_COLOR_RESET" : Event bytes_received %lu bytes_acked %lu lsndtime %u lrcvtime %u\n", 
					resp, clibufevent, bufevent, pevent->bytes_received, pevent->bytes_acked, pevent->lsndtime, pevent->lrcvtime)); 
		}

		if (print_msg) {
print1: 			
			char 			bufevent[512], buf[4096];

			GY_INET_SOCK		sock(pevent->tup.saddr, pevent->tup.sport, pevent->tup.netns);

			sock.get_sock_info_str(bufevent, sizeof(bufevent), "Server");

			INFOPRINT(GY_COLOR_YELLOW "Complete Response Time distribution data : Total number of server entries %lu\n" GY_COLOR_RESET, gymap.size());

			for (auto && it : gymap) {
				it.second.dist.flush(glast_time_t);

				it.second.sock.get_sock_info_str(bufevent, sizeof(bufevent), "Server");

				INFOPRINT("Response Time distribution stats for " GY_COLOR_YELLOW "%s" GY_COLOR_RESET" : \n%s\n", 
					bufevent, it.second.dist.get_print_str(buf, sizeof(buf) - 1, 99));
			}	

			IRPRINT(GY_COLOR_YELLOW "\n------------------------------------------------------------------------------------\n" GY_COLOR_RESET);

			auto memutil = gy_get_proc_vmsize(0);

			INFOPRINT(GY_COLOR_GREEN "Current PID %d Memory Util is %lu (%lu MB)\n" GY_COLOR_RESET, getpid(), memutil, memutil >> 20);
		}	

	}
	GY_CATCH_EXCEPTION(ERRORPRINT("Exception occured while populating response map %s\n", GY_GET_EXCEPT_STRING); return;);
}	

template <typename T>
static void print_ip_resp(void *pcb_cookie, void *pdata, int data_size)
{
	if (data_size < (signed)(sizeof(T) + sizeof(uint32_t))) {
		DEBUGEXECN(1, ERRORPRINT("Invalid perf buffer callback size seen %d : expected %lu\n", data_size, sizeof(T) + sizeof(uint32_t)););
		return;
	}

	T				evt, *pevent = &evt;

	std::memcpy(pevent, pdata, sizeof(*pevent));

	process_ip_resp<T>(pevent);
}

class RESP_THR_C
{

public :
	void *ipv4_resp_thr(void *parg);
	void *ipv6_resp_thr(void *parg);

	MAKE_CLASS_FUNC_WRAPPER_WITH_ARG(RESP_THR_C, ipv4_resp_thr);
	MAKE_CLASS_FUNC_WRAPPER_WITH_ARG(RESP_THR_C, ipv6_resp_thr);
};	

void * RESP_THR_C::ipv4_resp_thr(void *parg)
{
	const char *pipv4_perf_namein	= (const char *)parg;

	auto memutil = gy_get_proc_vmsize(0);

	INFOPRINT(GY_COLOR_BLUE "Current PID Starting %d %s libbpf perf poll : Memory Util is %lu (%lu MB)\n" GY_COLOR_RESET, getpid(), pipv4_perf_namein, memutil, memutil >> 20);
		
	while (gsig_rcvd.load() == 0) {
		tcpresponse_libbpf_poll(glbpf, 2000 /* msec */, true /* is_v4 */);
	}	

	INFOPRINT("Thread %s returning as signal %s received...\n", __FUNCTION__, gy_signal_str(gsig_rcvd.load()));

	return (void *)0;
}	

void * RESP_THR_C::ipv6_resp_thr(void *parg)
{
	const char *pipv6_perf_namein	= (const char *)parg;

	gy_nanosleep(0, 1000 * 1000 * 100);

	while (gsig_rcvd.load() == 0) {
		tcpresponse_libbpf_poll(glbpf, 2000 /* msec */, false /* is_v4 */);
	}	

	INFOPRINT("Thread %s returning as signal %s received...\n", __FUNCTION__, gy_signal_str(gsig_rcvd.load()));

	return (void *)0;
}	


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


int handle_signal(int signo)
{
	alarm(5);

	gsig_rcvd.store(signo);

	return signo;
}	



class TCPRESPONSE_LIBBPF
{
public :
	using TCPRESPONSE_OBJ		= GY_LIBBPF_OBJ<tcpresponse_libbpf_bpf>;
	
	TCPRESPONSE_LIBBPF(TCPRESPONSE_LIBBPF_CB cbv4, TCPRESPONSE_LIBBPF_CB cbv6, void *pcb_cookie)
		: cbv4_((GY_EBPF_CB)cbv4), cbv6_((GY_EBPF_CB)cbv6), pcb_cookie_(pcb_cookie)
	{
		int			ret;

		if (false && fentry_can_attach("inet6_csk_xmit", nullptr)) {

			ret = bpf_program__set_attach_target(obj_.get()->progs.fentry_trace_ipv4_xmit, 0, "__ip_queue_xmit");

			if (ret) {
				ret = bpf_program__set_attach_target(obj_.get()->progs.fentry_trace_ipv4_xmit, 0, "ip_queue_xmit");
				
				if (ret) {
					GY_THROW_SYS_EXCEPTION("Failed to attach fentry bpf probe for __ip_queue_xmit");
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

			ret = bpf_program__set_attach_target(obj_.get()->progs.trace_ipv4_xmit, 0, "__ip_queue_xmit");

			if (ret) {
				ret = bpf_program__set_attach_target(obj_.get()->progs.trace_ipv4_xmit, 0, "ip_queue_xmit");
				
				if (ret) {
					GY_THROW_SYS_EXCEPTION("Failed to attach kprobe bpf probe for __ip_queue_xmit");
				}	
			}

			ret = bpf_program__set_attach_target(obj_.get()->progs.trace_ipv6_xmit, 0, "inet6_csk_xmit");
			if (ret) {
				GY_THROW_SYS_EXCEPTION("Failed to attach kprobe bpf probe for inet6_csk_xmit");
			}	

			bpf_program__set_autoload(obj_.get()->progs.fentry_trace_ipv4_xmit, false);
			bpf_program__set_autoload(obj_.get()->progs.fentry_trace_ipv6_xmit, false);
		}

	}	

	~TCPRESPONSE_LIBBPF() noexcept		= default;

	void poll(int msec, bool is_v4)
	{
		if (is_v4 && pv4pool_.has_value()) {
			pv4pool_->poll(msec);
		}	
		else if (!is_v4 && pv6pool_.has_value()) {
			pv6pool_->poll(msec);
		}	
	}	

	void start_collection()
	{
		obj_.load_bpf();
		obj_.attach_bpf();

		pv4pool_.emplace("ipv4_xmit_perf perf buffer", bpf_map__fd(obj_.get()->maps.ipv4_xmit_perf), 32, cbv4_, pcb_cookie_);
		pv6pool_.emplace("ipv6_xmit_perf perf buffer", bpf_map__fd(obj_.get()->maps.ipv6_xmit_perf), 32, cbv6_, pcb_cookie_);

		int 				fd = bpf_map__fd(obj_.get()->maps.config_resp);

		if (fd < 0) {
			GY_THROW_SYS_EXCEPTION("Failed to find fd of libbpf config map");
		}	

		uint32_t			key = (uint32_t)ARR_CONFIG_ENABLE, value = 1;
		int				ret;

		ret = bpf_map_update_elem(fd, &key, &value, BPF_ANY);

		if (ret) {
			GY_THROW_SYS_EXCEPTION("Failed to set libbpf config map");
		}	

	}	

	GY_BTF_INIT				btf_;
	TCPRESPONSE_OBJ				obj_		{"TCP Response bpf"};
	std::optional<GY_PERF_BUFPOOL>		pv4pool_;
	std::optional<GY_PERF_BUFPOOL>		pv6pool_;
	GY_EBPF_CB				cbv4_		{nullptr};
	GY_EBPF_CB				cbv6_		{nullptr};
	void					*pcb_cookie_	{nullptr};
};


void * tcpresponse_libbpf_init(TCPRESPONSE_LIBBPF_CB cbv4, TCPRESPONSE_LIBBPF_CB cbv6, void *pcb_cookie)
{
	return new TCPRESPONSE_LIBBPF(cbv4, cbv6, pcb_cookie);
}	


void tcpresponse_libbpf_poll(void *parg, int msec, bool is_v4)
{
	if (!parg) return;

	auto			*pbpf = (TCPRESPONSE_LIBBPF *)parg;

	pbpf->poll(msec, is_v4);
}

void tcpresponse_libbpf_start_collection(void *parg)
{
	if (!parg) return;

	auto			*pbpf = (TCPRESPONSE_LIBBPF *)parg;

	pbpf->start_collection();
}

void tcpresponse_libbpf_destroy(void *parg)
{
	if (parg) {
		auto			*pbpf = (TCPRESPONSE_LIBBPF *)parg;
		
		delete pbpf;
	}	
}

int main(int argc, char **argv)
{
	if (argc > 1) {
		gdebugexecn = atoi(argv[1]);
	}	

	try {	

		int				ret;
		char				buf1[1024];
		size_t				idx;
		
		GY_SCOPE_EXIT {
			if (glbpf) {
				tcpresponse_libbpf_destroy(glbpf);
			}	
		};

		if (!access("/sys/kernel/btf/vmlinux", R_OK)) {
			glbpf = tcpresponse_libbpf_init(print_ip_resp<tcp_ipv4_resp_event_t>, print_ip_resp<tcp_ipv6_resp_event_t>);
		}	
		else {
			ERRORPRINT("BPF BTF (CO-RE) not supported on this host. Please try BCC version...\n");
			_exit(1);
		}	

		GY_SIGNAL_HANDLER::init_singleton(argv[0], handle_signal, false);

		GY_SIGNAL_HANDLER::get_singleton()->ignore_signal(SIGHUP);

		gstarttimens = get_nsec_clock();

		RESP_THR_C		respthr;
		pthread_t		dbgtid, thrid4, thrid6;

		gy_create_thread(&dbgtid, GET_PTHREAD_WRAPPER(debug_thread), nullptr, 64 * 1024, false);

		ret = gy_create_thread(&thrid4, RESP_THR_C::GET_PTHREAD_WRAPPER(ipv4_resp_thr), alloc_thread_args(&respthr, (void *)"ipv4_xmit_perf")); 
		if (ret) {
			PERRORPRINT("Could not create IPv4 handling thread");
			return -1;
		}	

		ret = gy_create_thread(&thrid6, RESP_THR_C::GET_PTHREAD_WRAPPER(ipv6_resp_thr), alloc_thread_args(&respthr, (void *)"ipv6_xmit_perf")); 
		if (ret) {
			PERRORPRINT("Could not create IPv6 handling thread");
			return -1;
		}	

		/*
		 * We wait for 2 seconds and then enable TCP Response stats
		 */
		gy_nanosleep(2, 0);

		tcpresponse_libbpf_start_collection(glbpf);

		pthread_join(thrid4, nullptr);
		pthread_join(thrid6, nullptr);

		INFOPRINT("Now exiting from process after deleting bpf ...\n\n");

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT("Exception occured due to %s : Exiting...\n", GY_GET_EXCEPT_STRING);
		return -1;
	);	
}

