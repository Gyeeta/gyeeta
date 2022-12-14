//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later


#include		"gy_common_inc.h"
#include		"gy_file_api.h"
#include		"gy_pkt_pool.h"

#include 		<unistd.h>
#include 		<cstdlib>
#include 		<string>
#include		<cstdint>
#include		<arpa/inet.h>

#include		"gy_statistics.h"

/*
 * We include the following 2 files and the #define to skip includes from the system dirs
 */
#include 		"compat/linux/bpf.h"
#include 		"compat/linux/bpf_common.h"

#ifndef 		__LINUX_BPF_H__
#define 		__LINUX_BPF_H__
#endif


#include 		"BPF.h"

typedef uint8_t 	u8;
typedef uint16_t 	u16;
typedef uint32_t 	u32;
typedef uint64_t 	u64;

#include 		"tcpresponse_bpf.h"

#include 		<unordered_map>
#include 		"gy_inet_inc.h"

using namespace		gyeeta;

uint64_t 		gstarttimens;

ebpf::BPF 		*gpbpf;
std::atomic<int>	gsig_rcvd(0);

struct GY_RESP_DIST
{
	GY_INET_SOCK				sock;
	RESP_TIME_HISTOGRAM<SCOPE_GY_MUTEX>	dist;
	uint64_t				last_bytes_received;
};	

typedef std::unordered_map<uint16_t, GY_RESP_DIST> 		GY_DIST_MAP;

GY_DIST_MAP			gymap;


template <typename T>
void process_ip_resp(T __restrict__ *pevent)
{
	thread_local 	uint32_t		glast_sndtime = 0;
	thread_local	time_t			glast_time_t = 0, gtlastprint = 0;

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
		DEBUGEXECN(5, ERRORPRINT("Invalid perf buffer callback size seen %d : expected %lu\n", data_size, sizeof(T) + sizeof(uint32_t)););
		return;
	}

	T				evt, *pevent = &evt;

	std::memcpy(pevent, pdata, sizeof(*pevent));

	process_ip_resp<T>(pevent);
}

class RESP_THR_C
{
	ebpf::BPFPerfBuffer		*pipv4_perf_buffer;
	ebpf::BPFPerfBuffer		*pipv6_perf_buffer;

public :
	RESP_THR_C() : pipv4_perf_buffer(nullptr), pipv6_perf_buffer(nullptr) {}
	
	void *ipv4_resp_thr(void *parg);
	void *ipv6_resp_thr(void *parg);

	MAKE_CLASS_FUNC_WRAPPER_WITH_ARG(RESP_THR_C, ipv4_resp_thr);
	MAKE_CLASS_FUNC_WRAPPER_WITH_ARG(RESP_THR_C, ipv6_resp_thr);
};	

void * RESP_THR_C::ipv4_resp_thr(void *parg)
{
	const char *pipv4_perf_namein	= (const char *)parg;
	auto perf_buffer 		= gpbpf->get_perf_buffer(pipv4_perf_namein);

	auto memutil = gy_get_proc_vmsize(0);

	INFOPRINT(GY_COLOR_BLUE "Current PID Starting %d %s perf poll : Memory Util is %lu (%lu MB)\n" GY_COLOR_RESET, getpid(), pipv4_perf_namein, memutil, memutil >> 20);
	
	if (perf_buffer) {
		while (gsig_rcvd.load() == 0) {
			perf_buffer->poll(2000 /* msec */);
		}	

		INFOPRINT("Thread %s returning as signal %s received...\n", __FUNCTION__, gy_signal_str(gsig_rcvd.load()));
	}
	else {
		ERRORPRINT("%s perf buffer not found\n", pipv4_perf_namein);
	}	

	return (void *)0;
}	

void * RESP_THR_C::ipv6_resp_thr(void *parg)
{
	const char *pipv6_perf_namein	= (const char *)parg;

	gy_nanosleep(0, 1000 * 1000 * 100);

	auto perf_buffer = gpbpf->get_perf_buffer(pipv6_perf_namein);

	if (perf_buffer) {
		while (gsig_rcvd.load() == 0) {
			perf_buffer->poll(2000 /* msec */);
		}	

		INFOPRINT("Thread %s returning as signal %s received...\n", __FUNCTION__, gy_signal_str(gsig_rcvd.load()));
	}
	else {
		ERRORPRINT("%s perf buffer not found\n", pipv6_perf_namein);
	}	

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



int main(int argc, char **argv)
{
	using namespace ebpf;
	
	if (argc > 1) {
		gdebugexecn = atoi(argv[1]);
	}	

	try {	

		int			ret;
		char			buf1[1024];
		size_t			idx;
		ebpf::BPF 		bpf(0, nullptr, false);
		
		gpbpf = &bpf;

		GY_SIGNAL_HANDLER::init_singleton(argv[0], handle_signal, false);

		GY_SIGNAL_HANDLER::get_singleton()->ignore_signal(SIGHUP);

		std::string		bpf_program;
		
		bpf_program = read_file_to_string("tcpresponse_bpf.c");

		auto st1 = gpbpf->init(bpf_program);

		if (st1.code() != 0) {
			ERRORPRINT("Could not initialize BPF tracing : %s\n\n", st1.msg().c_str());
			return -1;
		}

		auto res1 = gpbpf->attach_kprobe("ip_queue_xmit", "trace_ip_xmit", 0, BPF_PROBE_ENTRY);
		if (res1.code() != 0) {
			ERRORPRINT("Could not attach to kprobe ip_queue_xmit entry : %s\n", res1.msg().c_str());
			return -1;
		}

		auto res2 = gpbpf->attach_kprobe("inet6_csk_xmit", "trace_ipv6_xmit", 0, BPF_PROBE_ENTRY);
		if (res2.code() != 0) {
			ERRORPRINT("Could not attach to kprobe inet6_csk_xmit entry : %s\n", res2.msg().c_str());
			return -1;
		}

		auto open_res4 = gpbpf->open_perf_buffer("ipv4_xmit_perf", print_ip_resp<tcp_ipv4_resp_event_t>, nullptr, nullptr, 32);
		if (open_res4.code() != 0) {
			ERRORPRINT("Could not open perf buffer for ipv4_xmit_perf : %s\n", open_res4.msg().c_str());
			return -1;
		}

		auto open_res6 = gpbpf->open_perf_buffer("ipv6_xmit_perf", print_ip_resp<tcp_ipv6_resp_event_t>, nullptr, nullptr, 32);
		if (open_res6.code() != 0) {
			ERRORPRINT("Could not open perf buffer for ipv6_xmit_perf : %s\n", open_res4.msg().c_str());
			return -1;
		}

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
		 * We wait for 5 seconds and then enable TCP Response stats
		 */
		gy_nanosleep(5, 0);

		auto 		config_resp_tbl = gpbpf->get_array_table<uint64_t>("config_resp"); 

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Enabling TCP Response collection. "
			"Number of IPv4 Response packets skipped so far %lu : Number of IPv6 %lu\n\n",
			config_resp_tbl[ARR_SKIPPED_IPv4], config_resp_tbl[ARR_SKIPPED_IPv6]);
		
		auto start_coll_status = config_resp_tbl.update_value(ARR_CONFIG_ENABLE, 1);
		if (start_coll_status.code() != 0) {
			ERRORPRINT("Could not set start TCP stats collection : %s\n", start_coll_status.msg().c_str());
			return -1;
		}

		config_resp_tbl.update_value(ARR_SKIPPED_IPv4, 0);
		config_resp_tbl.update_value(ARR_SKIPPED_IPv6, 0);

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

