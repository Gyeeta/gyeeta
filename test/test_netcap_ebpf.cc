//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_common_inc.h"

#include 			<unistd.h>
#include 			<cstdlib>
#include 			<string>
#include			<cstdint>
#include			<arpa/inet.h>

#include			"gy_libbpf.h"
#include			"gy_pcap_write.h"

#include			"test_netcap_ebpf.h"
#include			"test_netcap_ebpf.skel.h"

using namespace			gyeeta;

int64_t				gpkts = 0;
GY_CLOCK_TO_TIME		clktime;

void handle_data(void *pcb_cookie, void *pdata, int data_size)
{
	GY_PCAP_WRITER			*pwriter = (GY_PCAP_WRITER *)pcb_cookie;
	const tcaphdr_t			*pevent = static_cast<const tcaphdr_t *>(pdata);

	if (data_size < (signed)(sizeof(tcaphdr_t))) {
		ERRORPRINT("Invalid ring buffer callback size seen %d : expected min %lu\n", data_size, sizeof(tcaphdr_t));
		return;
	}
	
	if (data_size != pevent->len + sizeof(*pevent)) {
		ERRORPRINT("Invalid ring buffer callback size seen %d : expected size %lu\n", data_size, sizeof(tcaphdr_t) + pevent->len);
		return;
	}
	
	struct timeval			tv = clktime.get_timeval(pevent->ts_ns/1000);
	GY_IP_ADDR			seraddr(IPv4_v6(pevent->tuple.seraddr, pevent->tuple.ipver == 6));	
	bool				bret;

	if (pevent->is_inbound) {
		bret = pwriter->write_tcp_pkt(clktime.get_timeval(pevent->ts_ns/1000), 
					GY_IP_ADDR(IPv4_v6(pevent->tuple.cliaddr, pevent->tuple.ipver == 6)), 
					GY_IP_ADDR(IPv4_v6(pevent->tuple.seraddr, pevent->tuple.ipver == 6)), 
					pevent->tuple.cliport, pevent->tuple.serport,
					pevent->nxt_cli_seq - pevent->len - pevent->npadbytes, pevent->nxt_ser_seq, 
					pevent->tcp_flags, pevent + 1, pevent->len - pevent->npadbytes);
	}
	else {
		bret = pwriter->write_tcp_pkt(clktime.get_timeval(pevent->ts_ns/1000), 
					GY_IP_ADDR(IPv4_v6(pevent->tuple.seraddr, pevent->tuple.ipver == 6)), 
					GY_IP_ADDR(IPv4_v6(pevent->tuple.cliaddr, pevent->tuple.ipver == 6)), 
					pevent->tuple.serport, pevent->tuple.cliport,
					pevent->nxt_ser_seq - pevent->len - pevent->npadbytes, pevent->nxt_cli_seq, 
					pevent->tcp_flags, pevent + 1, pevent->len - pevent->npadbytes);
		
	}

	if (!bret) {
		ERRORPRINT("Failed to write packet to pcap file %s\n", pwriter->get_filename());
	}
}	


class TNETCAP
{
public :
	using TNETCAP_OBJ			= GY_LIBBPF_OBJ<test_netcap_ebpf>;
	
	TNETCAP_OBJ()				= default;

	~TNETCAP_OBJ() noexcept			= default;

	void start_collection(void *pwriter)
	{
		obj_.load_bpf();
		obj_.attach_bpf();

		pdatapool_.emplace("Net cap Pool", bpf_map__fd(obj_.get()->maps.capring), handle_data, pwriter);
	}	

	int poll(int timeout_ms) noexcept
	{
		return obj_.poll(timeout_ms);
	}	

	void update_listener(const GY_IP_ADDR & ipaddr, uint16_t port, uint32_t netns, uint16_t proto, bool to_pause)
	{
		int 				fd = bpf_map__fd(obj_.get()->maps.listenmap);

		if (fd < 0) {
			GY_THROW_SYS_EXCEPTION("Failed to find fd of libbpf listenmap");
		}	

		tlistenkey			key {};
		tlistenstat			value {};

		if (false == ipaddr.is_ipv6_addr()) {
			ipaddr.get_as_inaddr(&key.seraddr.ser4addr);
			key.ipver		= 4;
		}
		else {
			ipaddr.get_as_inaddr(&key.seraddr.ser6addr);
			key.ipver		= 6;
		}	

		key.netns 			= netns;
		key.serport			= port;

		value.proto			= proto;
		value.isany			= ipaddr.is_any_address();
		value.pausecap			= to_pause;

		bpf_map_update_elem(fd, &key, &value, to_pause == false ? BPF_ANY : BPF_EXIST);
	}	
	
	void delete_listener(const GY_IP_ADDR & ipaddr, uint16_t port, uint32_t netns, uint16_t proto)
	{
		int 				fd = bpf_map__fd(obj_.get()->maps.listenmap);

		if (fd < 0) {
			GY_THROW_SYS_EXCEPTION("Failed to find fd of libbpf listenmap");
		}	

		tlistenkey			key {};

		if (false == ipaddr.is_ipv6_addr()) {
			ipaddr.get_as_inaddr(&key.seraddr.ser4addr);
			key.ipver		= 4;
		}
		else {
			ipaddr.get_as_inaddr(&key.seraddr.ser6addr);
			key.ipver		= 6;
		}	

		key.netns 			= netns;
		key.serport			= port;

		bpf_map_delete_elem(fd, &key);
	}	
	

	GY_BTF_INIT				btf_;
	TNETCAP_OBJ				obj_		{"TCP Cap bpf"};
	std::optional<GY_RING_BUFPOOL>		pdatapool_;
};

class TNETCAP_HDLR
{
public:
	TNETCAP_HDLR()				= default;
	
	~TNETCAP_HDLR()				= default;
	
	void start_collection(void *pwriter)
	{
		cap_.start_collection(pwriter);
	}	

	void add_listener(const GY_IP_ADDR & ipaddr, uint16_t port, uint32_t netns, uint16_t proto)
	{
		cap_.set_listener(ipaddr, port, netns, proto, false);
	}	

	void pause_listener(const GY_IP_ADDR & ipaddr, uint16_t port, uint32_t netns, uint16_t proto)
	{
		cap_.set_listener(ipaddr, port, netns, proto, true);
	}

	void resume_listener(const GY_IP_ADDR & ipaddr, uint16_t port, uint32_t netns, uint16_t proto)
	{
		cap_.set_listener(ipaddr, port, netns, proto, false);
	}

	void delete_listener(const GY_IP_ADDR & ipaddr, uint16_t port, uint32_t netns, uint16_t proto)
	{
		cap_.delete_listener(ipaddr, port, netns, proto);
	}


	TNETCAP					cap_;
};	



void * netcap_thr(void *parg)
{
	auto				*pnetcap = (TNETCAP *)parg;

	gy_nanosleep(0, 1000 * 1000 * 100);

	while (gsig_rcvd.load() == 0) {
		pnetcap->poll(2000);
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



int main(int argc, char *argv[])
{
	try {	

		if (argc < 5) {
			IRPRINT("\nUsage : %s <Output pcap path> <Listener IP to capture> <Listener Port> <Listener NetNS inode> <Listener 2 IP> ...\n"
					"\tFor e.g. %s /tmp/test1.pcap 0.0.0.0 10040 4026531840 192.168.0.1 10037 4026531840\n\n", argv[0]);
			return 1;
		}	
		
		int				ret;
		char				buf1[1024];
		size_t				idx;
		std::optional<TNETCAP_HDLR>	phdlr;

		gdebugexecn = 11;

		if (!access("/sys/kernel/btf/vmlinux", R_OK)) {
			if (probe_ringbuf()) {
				phdlr.emplace();
			}	
			else {
				ERRORPRINT("BPF Ring buffer not supported on this host. Requires a Linux kernel version 5.8 or higher...\n");
				_exit(1);
			}	
		}	
		else {
			ERRORPRINT("BPF BTF (CO-RE) not supported on this host. Requires a Linux kernel version 5.8 or higher...\n");
			_exit(1);
		}	

		GY_SIGNAL_HANDLER::init_singleton(argv[0], handle_signal, false);

		GY_SIGNAL_HANDLER::get_singleton()->ignore_signal(SIGHUP);

		gstarttimens = get_nsec_clock();

		GY_PCAP_WRITER		wrpcap(argv[1]);
		pthread_t		dbgtid, thrid;

		gy_create_thread(&dbgtid, GET_PTHREAD_WRAPPER(debug_thread), nullptr, 64 * 1024, false);

		ret = gy_create_thread(&thrid, GET_PTHREAD_WRAPPER(netcap_thr), &phdlr->cap_, GY_UP_MB(1), false);
		if (ret) {
			PERRORPRINT("Could not create netcap handling thread");
			return -1;
		}	

		/*
		 * We wait for 2 seconds and then enable TCP Capture
		 */
		gy_nanosleep(2, 0);

		phdlr->start_collection(&wrpcap);

		/*
		 * Wait for 1 second and then set the listeners to capture
		 */
		gy_nanosleep(1, 0);

		for (int i = 1; i + 2 < argc; i += 3) {
			phdlr->add_listener(GY_IP_ADDR(argv[i]), string_to_number(argv[i + 1]), string_to_number(argv[i + 2]));
		}	

		pthread_join(thrid, nullptr);

		auto			[ npkts, nbytes, tstart ] = wrpcap.get_stats();

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Output pcap %s : Written # %lu packets : Total %lu bytes : Running since %ld sec\n\n",  
				wrpcap.get_filename(), npkts, nbytes, time(nullptr) - tstart);

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT("Exception occured due to %s : Exiting...\n", GY_GET_EXCEPT_STRING);
		return -1;
	);	
}	



