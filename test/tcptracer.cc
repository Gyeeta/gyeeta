//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include 		"tcptracer_user.h"

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

#include 		"tcptracer.h"

using namespace		gyeeta;

uint64_t 		gstarttimens;
const char *		geventtypename[] = {"Invalid", "TCP Connect", "TCP Accept", "TCP Close Client", "TCP Close Server"};
ebpf::BPF 		*gpbpf;

std::atomic<int>	gsig_rcvd(0);

static void print_ipv4_event(void *pcb_cookie, void *pdata, int data_size)
{
	tcp_ipv4_event_t	*peventorig = static_cast<tcp_ipv4_event_t *>(pdata), evt, *pevent = &evt;

	if (data_size < (int)sizeof(tcp_ipv4_event_t)) {
		DEBUGEXECN(1, ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "BPF Callback invalid number of bytes received %d for callback %s\n",
			data_size, __FUNCTION__););
	}	

	evt = *peventorig;

	GY_IP_ADDR		saddr(pevent->saddr), daddr(pevent->daddr);
	char			sipdesc[256], dipdesc[256], sipbuf[64], dipbuf[64];

	pevent->comm[sizeof(pevent->comm) - 1] = '\0';
	if (pevent->type >  TCP_EVENT_TYPE_CLOSE_SER) pevent->type = 0;

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Event : IPv4 %s, Time diff : %.09lf, Process PID : %u, Process TID : %u, Process name : %s, Source IPv4 : %s, Dest IPv4 : %s, Source TCP Port : %hu, Dest TCP Port : %hu, NetNS : %u, Bytes Received %lu, Bytes Sent %lu, Source Addr Desc : %s, Dest Addr Desc : %s\n\n", geventtypename[pevent->type],  (pevent->ts_ns - gstarttimens)/1000000000.0, pevent->pid, pevent->tid, pevent->comm, saddr.printaddr(sipbuf, sizeof(sipbuf) - 1), daddr.printaddr(dipbuf, sizeof(dipbuf) - 1), pevent->sport, pevent->dport, pevent->netns, pevent->bytes_received, pevent->bytes_acked, saddr.get_ipdescription(sipdesc, sizeof(sipdesc) - 1), daddr.get_ipdescription(dipdesc, sizeof(dipdesc) - 1));
}

static void print_ipv6_event(void *pcb_cookie, void *pdata, int data_size)
{
	tcp_ipv6_event_t	*peventorig = static_cast<tcp_ipv6_event_t *>(pdata), evt, *pevent = &evt;

	if (data_size < (int)sizeof(tcp_ipv6_event_t)) {
		DEBUGEXECN(1, ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "BPF Callback invalid number of bytes received %d for callback %s\n",
			data_size, __FUNCTION__););
	}	

	evt = *peventorig;

	GY_IP_ADDR		saddr(pevent->saddr), daddr(pevent->daddr);
	char			sipdesc[256], dipdesc[256], sipbuf[64], dipbuf[64];

	pevent->comm[sizeof(pevent->comm) - 1] = '\0';
	if (pevent->type >  TCP_EVENT_TYPE_CLOSE_SER) pevent->type = 0;

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Event : IPv6 %s, Time diff : %.09lf, Process PID : %u, Process TID : %u, Process name : %s, Source IPv6 : %s, Dest IPv6 : %s, Source TCP Port : %hu, Dest TCP Port : %hu, NetNS : %u, Bytes Received %lu, Bytes Sent %lu, Source Addr Desc : %s, Dest Addr Desc : %s\n\n", geventtypename[pevent->type], (pevent->ts_ns - gstarttimens)/1000000000.0, pevent->pid, pevent->tid, pevent->comm, saddr.printaddr(sipbuf, sizeof(sipbuf) - 1), daddr.printaddr(dipbuf, sizeof(dipbuf) - 1), pevent->sport, pevent->dport, pevent->netns, pevent->bytes_received, pevent->bytes_acked, saddr.get_ipdescription(sipdesc, sizeof(sipdesc) - 1), daddr.get_ipdescription(dipdesc, sizeof(dipdesc) - 1));
}

static void print_nsproxy_event(void *pcb_cookie, void *pdata, int data_size)
{
	nsproxy_data_t			*pevent = static_cast<nsproxy_data_t *>(pdata), evt;

	if (data_size < (int)sizeof(nsproxy_data_t)) {
		DEBUGEXECN(1, ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "BPF Callback invalid number of bytes received %d for callback %s\n",
			data_size, __FUNCTION__););
	}	

	evt = *pevent;
	
	STRING_BUFFER<512>	ss;

	if (evt.flags & CLONE_NEWNS) {
		ss.append(" New Mount Namespace,");
	}	
	if (evt.flags & CLONE_NEWUTS) {
		ss.append(" New utsname Namespace,");
	}	
	if (evt.flags & CLONE_NEWIPC) {
		ss.append(" New IPC Namespace,");
	}	
	if (evt.flags & CLONE_NEWPID) {
		ss.append(" New PID Namespace,");
	}	
	if (evt.flags & CLONE_NEWNET) {
		ss.append(" New network Namespace,");
	}	
	if (evt.flags & CLONE_NEWCGROUP) {
		ss.append(" New cgroup Namespace,");
	}	

	INFOPRINTCOLOR(GY_COLOR_BOLD_YELLOW, "Namespace Event : Time diff : %.09lf, Process PID : %u, Process TID : %u, Process name : %s, %s\n\n", (pevent->ts_ns - gstarttimens)/1000000000.0, pevent->pid, pevent->tid, pevent->comm, ss.buffer());
}

static void print_tcp_listener(void *pcb_cookie, void *pdata, int data_size)
{
	tcp_listener_event_t			*pevent = static_cast<tcp_listener_event_t *>(pdata), evt;

	if (data_size < (int)sizeof(tcp_listener_event_t)) {
		DEBUGEXECN(1, ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "BPF Callback invalid number of bytes received %d for callback %s\n",
			data_size, __FUNCTION__););
	}	

	evt = *pevent;
	
	GY_IP_ADDR		saddr;
	char			sipdesc[256], sipbuf[64];

	if (pevent->ipver == 6) {
		saddr.set_ip(evt.addr.v6addr);
	}	
	else {
		saddr.set_ip(evt.addr.v4addr);
	}	

	evt.comm[sizeof(evt.comm) - 1] = '\0';

	INFOPRINTCOLOR(GY_COLOR_BOLD_YELLOW, "TCP Listener Event : New Listener : Time diff : %.09lf, Process PID : %u, Process TID : %u, Process name : %s, IP : %s, Listener TCP Port : %hu, NetNS : %u, Listener Backlog %u, Listener Addr Desc : %s\n\n", 
		(evt.ts_ns - gstarttimens)/1000000000.0, evt.pid, evt.tid, evt.comm, saddr.printaddr(sipbuf, sizeof(sipbuf) - 1), evt.lport, evt.netns, evt.backlog, saddr.get_ipdescription(sipdesc, sizeof(sipdesc) - 1));
}


void * ipv4_thr(void *arg)
{
	auto perf_buffer = gpbpf->get_perf_buffer("tcp_ipv4_event");
	
	if (perf_buffer) {
		while (gsig_rcvd.load() == 0) {
			perf_buffer->poll(1000 /* msec */);
		}	

		INFOPRINT("Thread %s returning as signal %s received...\n", __FUNCTION__, gy_signal_str(gsig_rcvd.load()));
	}
	else {
		ERRORPRINT("tcp_ipv4_event perf buffer not found\n");
	}	

	return (void *)0;
}	

void * ipv6_thr(void *arg)
{
	gy_nanosleep(0, 1000 * 1000 * 100);

	auto perf_buffer = gpbpf->get_perf_buffer("tcp_ipv6_event");

	if (perf_buffer) {
		while (gsig_rcvd.load() == 0) {
			perf_buffer->poll(1000 /* msec */);
		}	

		INFOPRINT("Thread %s returning as signal %s received...\n", __FUNCTION__, gy_signal_str(gsig_rcvd.load()));
	}
	else {
		ERRORPRINT("tcp_ipv6_event perf buffer not found\n");
	}	

	return (void *)0;
}	

void * nsproxy_thr(void *arg)
{
	auto perf_buffer = gpbpf->get_perf_buffer("nsproxy_event");
	
	if (perf_buffer) {
		while (gsig_rcvd.load() == 0) {
			perf_buffer->poll(1000 /* msec */);
		}	

		INFOPRINT("Thread %s returning as signal %s received...\n", __FUNCTION__, gy_signal_str(gsig_rcvd.load()));
	}
	else {
		ERRORPRINT("nsproxy_event perf buffer not found\n");
	}	

	return (void *)0;
}	

void * listener_thr(void *arg)
{
	auto perf_buffer = gpbpf->get_perf_buffer("tcp_listener_event");
	
	if (perf_buffer) {
		while (gsig_rcvd.load() == 0) {
			perf_buffer->poll(1000 /* msec */);
		}	

		INFOPRINT("Thread %s returning as signal %s received...\n", __FUNCTION__, gy_signal_str(gsig_rcvd.load()));
	}
	else {
		ERRORPRINT("tcp_listener_event perf buffer not found\n");
	}	

	return (void *)0;
}	

MAKE_PTHREAD_FUNC_WRAPPER(ipv4_thr);
MAKE_PTHREAD_FUNC_WRAPPER(ipv6_thr);
MAKE_PTHREAD_FUNC_WRAPPER(nsproxy_thr);
MAKE_PTHREAD_FUNC_WRAPPER(listener_thr);
MAKE_PTHREAD_FUNC_WRAPPER(nlct_thread);
MAKE_PTHREAD_FUNC_WRAPPER(inet_diag_thr);

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
		PROC_CPU_IO_STATS::init_singleton();

		int			ret;
		char			buf1[1024];
		size_t			idx;
		ebpf::BPF 		bpf(0, nullptr, false);

		gpbpf = &bpf;

		std::string	bpf_program = read_file_to_string("tcptracer_bpf.c");

		GY_SIGNAL_HANDLER::init_singleton(argv[0], handle_signal, false);

		auto st1 = gpbpf->init(bpf_program);

		if (st1.code() != 0) {
			ERRORPRINT("Could not initialize BPF tracing : %s\n\n", st1.msg().c_str());
			return -1;
		}

		auto res1 = gpbpf->attach_kprobe("tcp_v4_connect", "trace_connect_v4_entry", 0ul, BPF_PROBE_ENTRY);
		if (res1.code() != 0) {
			ERRORPRINT("Could not attach to kprobe tcp_v4_connect entry : %s\n", res1.msg().c_str());
			return -1;
		}
		auto res2 = gpbpf->attach_kprobe("tcp_v4_connect", "trace_connect_v4_return", 0ul, BPF_PROBE_RETURN);
		if (res2.code() != 0) {
			ERRORPRINT("Could not attach to kprobe tcp_v4_connect return : %s\n", res2.msg().c_str());
			return -1;
		}

		auto res3 = gpbpf->attach_kprobe("tcp_v6_connect", "trace_connect_v6_entry", 0ul, BPF_PROBE_ENTRY);
		if (res3.code() != 0) {
			ERRORPRINT("Could not attach to kprobe tcp_v6_connect entry : %s\n", res3.msg().c_str());
			return -1;
		}
		auto res4 = gpbpf->attach_kprobe("tcp_v6_connect", "trace_connect_v6_return", 0ul, BPF_PROBE_RETURN);
		if (res4.code() != 0) {
			ERRORPRINT("Could not attach to kprobe tcp_v6_connect return : %s\n", res4.msg().c_str());
			return -1;
		}


		auto res5 = gpbpf->attach_kprobe("tcp_set_state", "trace_tcp_set_state_entry", 0ul, BPF_PROBE_ENTRY);
		if (res5.code() != 0) {
			ERRORPRINT("Could not attach to kprobe tcp_set_state entry : %s\n", res5.msg().c_str());
			return -1;
		}

		auto res6 = gpbpf->attach_kprobe("tcp_close", "trace_close_entry", 0ul, BPF_PROBE_ENTRY);
		if (res6.code() != 0) {
			ERRORPRINT("Could not attach to kprobe tcp_close entry : %s\n", res6.msg().c_str());
			return -1;
		}

		auto res7 = gpbpf->attach_kprobe("inet_csk_accept", "trace_accept_return", 0ul, BPF_PROBE_RETURN);
		if (res7.code() != 0) {
			ERRORPRINT("Could not attach to kprobe inet_csk_accept return : %s\n", res7.msg().c_str());
			return -1;
		}

		auto open_res4 = gpbpf->open_perf_buffer("tcp_ipv4_event", print_ipv4_event, nullptr, nullptr, 32);
		if (open_res4.code() != 0) {
			ERRORPRINT("Could not open perf buffer for tcp_ipv4_event : %s\n", open_res4.msg().c_str());
			return -1;
		}

		auto open_res6 = gpbpf->open_perf_buffer("tcp_ipv6_event", print_ipv6_event, nullptr, nullptr, 32);
		if (open_res6.code() != 0) {
			ERRORPRINT("Could not open perf buffer for tcp_ipv4_event : %s\n", open_res4.msg().c_str());
			return -1;
		}

		auto nsproxy_res = gpbpf->attach_kprobe("create_new_namespaces", "trace_create_ns", 0ul, BPF_PROBE_ENTRY);
		if (nsproxy_res.code() != 0) {
			ERRORPRINT("Could not attach to kprobe create_new_namespaces entry : %s\n", nsproxy_res.msg().c_str());
			return -1;
		}
		
		auto open_nsproc = gpbpf->open_perf_buffer("nsproxy_event", print_nsproxy_event, nullptr, nullptr, 8);
		if (open_nsproc.code() != 0) {
			ERRORPRINT("Could not open perf buffer for nsproxy event : %s\n", open_nsproc.msg().c_str());
			return -1;
		}

		auto list_res = gpbpf->attach_kprobe("inet_listen", "trace_inet_listen", 0ul, BPF_PROBE_ENTRY);
		if (list_res.code() != 0) {
			ERRORPRINT("Could not attach to kprobe inet_listen entry : %s\n", list_res.msg().c_str());
			return -1;
		}
		
		auto open_list = gpbpf->open_perf_buffer("tcp_listener_event", print_tcp_listener, nullptr, nullptr, 8);
		if (open_list.code() != 0) {
			ERRORPRINT("Could not open perf buffer for tcp_listener_event : %s\n", open_list.msg().c_str());
			return -1;
		}

		gstarttimens = get_nsec_clock();

		pthread_t		thrid4, thrid6, thr_nlct, thr_inet_diag, thrnsproxy, thrlistener;

		ret = gy_create_thread(&thrid4, GET_PTHREAD_WRAPPER(ipv4_thr), nullptr);
		if (ret) {
			PERRORPRINT("Could not create IPv4 handling thread");
			return -1;
		}	

		ret = gy_create_thread(&thrid6, GET_PTHREAD_WRAPPER(ipv6_thr), nullptr);
		if (ret) {
			PERRORPRINT("Could not create IPv6 handling thread");
			return -1;
		}	

		ret = gy_create_thread(&thrnsproxy, GET_PTHREAD_WRAPPER(nsproxy_thr), nullptr);
		if (ret) {
			PERRORPRINT("Could not create nsproxy handling thread");
			return -1;
		}	

		ret = gy_create_thread(&thrlistener, GET_PTHREAD_WRAPPER(listener_thr), nullptr);
		if (ret) {
			PERRORPRINT("Could not create listener_thr handling thread");
			return -1;
		}	

#if 1		
		ret = gy_create_thread(&thr_nlct, GET_PTHREAD_WRAPPER(nlct_thread), nullptr);
		if (ret) {
			PERRORPRINT("Could not create Netlink Conntrack handling thread");
			return -1;
		}	
		
		ret = gy_create_thread(&thr_inet_diag, GET_PTHREAD_WRAPPER(inet_diag_thr), nullptr);
		if (ret) {
			PERRORPRINT("Could not create inet Diag handling thread");
			return -1;
		}	
#endif

		pthread_join(thrid4, nullptr);
		pthread_join(thrid6, nullptr);
#if 1		
		pthread_join(thr_nlct, nullptr);
		pthread_join(thr_inet_diag, nullptr);
#endif
		pthread_join(thrnsproxy, nullptr);
		pthread_join(thrlistener, nullptr);

		INFOPRINT("Now exiting from process after deleting bpf ...\n\n");

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT("Exception occured due to %s : Exiting...\n", GY_GET_EXCEPT_STRING);
		return -1;
	);	
}

