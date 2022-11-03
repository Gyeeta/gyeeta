//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include		"gy_common_inc.h"
#include		"gy_pcap_read.h"
#include		"gy_network_capture.h"

using namespace gyeeta;

static std::atomic<int64_t>	gntcp {0}, gnudp {0}, gnip {0}, gnip6 {0}, gnskipped {0}, gnframe {0};
static std::atomic<int>		gsig_rcvd {false};	
static bool			gprintpacket = false;

static int process_packet(const uint8_t *pframe, uint32_t caplen, uint32_t origlen, int linktype, struct timeval tv_pkt, const char *ifname)
{
	const struct ip 	*pip;
	const struct ip6_hdr	*pip6;
	const uint8_t		*porigframe, *ptcp, *pudp; 
	GY_TCP_HDR		tcp;
	GY_UDP_HDR		udp;
	uint8_t			transport_proto;
	uint32_t 		ip_offset, transport_offset, data_offset, data_len;
	int			ret;
	bool			is_ipv4;
	GY_IP_ADDR		srcip, dstip;
	char			printbuf[512];
	
	gnframe.fetch_add(1, std::memory_order_relaxed);

	ret = get_ip_offset(pframe, caplen, linktype, ip_offset, is_ipv4);
	if (ret != 0 || (ip_offset > caplen)) {
		gnskipped.fetch_add(1, std::memory_order_relaxed);
		return 1;
	}	

	porigframe = pframe;

	caplen -= ip_offset;
	pframe += ip_offset;

	if (is_ipv4) {
		gnip.fetch_add(1, std::memory_order_relaxed);

		pip = decltype(pip)(pframe);
		
		srcip.set_ip(pip->ip_src.s_addr);
		dstip.set_ip(pip->ip_dst.s_addr);

		ret = get_ipv4_transport_offset(pip, caplen, transport_proto, transport_offset, data_offset, data_len);
	}	
	else {
		gnip6.fetch_add(1, std::memory_order_relaxed);

		pip6 = decltype(pip6)(pframe);
		
		unsigned __int128	sip128_be, dip128_be;
		
		memcpy(&sip128_be, pip6->ip6_src.s6_addr, sizeof(sip128_be));
		memcpy(&dip128_be, pip6->ip6_dst.s6_addr, sizeof(dip128_be));

		srcip.set_ip(sip128_be); 
		dstip.set_ip(dip128_be);

		ret = get_ipv6_transport_offset(pip6, caplen, transport_proto, transport_offset, data_offset, data_len);
	}	

	if (ret != 0 || ((transport_offset > caplen) || ((data_len > 0) && ((data_offset + data_len > caplen) || (data_offset < transport_offset))))) {
		gnskipped.fetch_add(1, std::memory_order_relaxed);
		return 1;
	}	

	caplen -= transport_offset;
	pframe += transport_offset;

	STR_WR_BUF		strbuf(printbuf, sizeof(printbuf));
	char			ipbuf1[128], ipbuf2[128];
	uint16_t		urgent_len = 0;
	uint8_t			*purg = nullptr;

	strbuf.appendfmt("Frame %ld : Interface %s : Source IP %s : Dest IP %s : ", 
			gnframe.load(std::memory_order_relaxed), ifname, srcip.printaddr(ipbuf1, sizeof(ipbuf1)), dstip.printaddr(ipbuf2, sizeof(ipbuf2)));

	if (transport_proto == IP_PROTO_TCP) {
		gntcp.fetch_add(1, std::memory_order_relaxed);

		ptcp = pframe;
		
		tcp.~GY_TCP_HDR();
		new (&tcp) GY_TCP_HDR(ptcp);

		strbuf.appendfmt("TCP Source Port %hu : Dest Port %hu : Seq 0x%08x : Ack 0x%08x : Flags %s : TCP Payload Length %u", 
			tcp.source, tcp.dest, tcp.seq, tcp.ack_seq, tcp.print_tcp_flags(ipbuf1, sizeof(ipbuf1)), data_len);

		if (urgent_len) {
			strbuf.appendfmt(" Urgent Data Length %hu", urgent_len);
		}	
	}
	else if (transport_proto == IP_PROTO_UDP) {
		gnudp.fetch_add(1, std::memory_order_relaxed);

		pudp = pframe;
		
		udp.~GY_UDP_HDR();
		new (&udp) GY_UDP_HDR(pudp);

		strbuf.appendfmt("UDP Source Port %hu : Dest Port %hu : UDP Payload Length %u", udp.source, udp.dest, data_len);
	}	
	else {
		strbuf.appendfmt("Transport Proto %hhu", transport_proto);
		data_len = 0;
	}	
	
	INFOPRINTCOLOR(GY_COLOR_GREEN, "%s\n", printbuf);

	if (data_len || urgent_len) {
		pframe += (data_offset - transport_offset);

		// L7 Data starts from pframe now of length data_len
		// purg points to any urgent data if present of length urgent_len

		if (gprintpacket) {
			gy_print_buf(STDOUT_FILENO, pframe, data_len, 1, "Packet Data");
		}	
	}

	return 0;
}	

static int read_pcap(const char *pfilename)
{
	try {
		PCAP_READER		pcap(pfilename);

		struct timeval 		tv_pkt;
		uint32_t 		caplen, origlen;
		int			ret;
		uint8_t			*pframe;
		
		const int		linktype = pcap.get_linktype();

		do {
			pframe = pcap.read_next_pcap_pkt(tv_pkt, caplen, origlen);
			if (!pframe) {
				INFOPRINTCOLOR(GY_COLOR_GREEN, "Completed reading the pcap. Total TCP Packets %ld UDP %ld IPv4 %ld IPv6 %ld Skipped %ld\n",
					gntcp.load(std::memory_order_relaxed), gnudp.load(std::memory_order_relaxed), gnip.load(std::memory_order_relaxed), 
					gnip6.load(std::memory_order_relaxed), gnskipped.load(std::memory_order_relaxed)); 
				return 0;
			}	
		
			ret = process_packet(pframe, caplen, origlen, linktype, tv_pkt, "[File]");
			if (ret != 0) {
				continue;
			}	

		} while (true);	
	}
	GY_CATCH_EXCEPTION(ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Exception caught while reading pcap : %s\n", GY_GET_EXCEPT_STRING); return -1;);
}	

void handle_signal(int signo, siginfo_t *, void *)
{
	alarm(5);

	gsig_rcvd.store(signo);
}	

static int read_network(const char *pfilter, char **pifname, int nifs)
{
	try {
		PCAP_NET_CAP		*pcaparr[nifs] {};
		
		GY_SIGNAL_HANDLER::get_singleton()->set_signal_handler(SIGINT, handle_signal);

		GY_SCOPE_EXIT {
			for (int i = 0; i < nifs; i++) {
				delete pcaparr[i];
			}	
		};

		for (int i = 0; i < nifs; i++) {
			auto pcapcb = [ifname = std::string(pifname[i])](const uint8_t * pframe, uint32_t caplen, uint32_t origlen, int linktype, struct timeval tv_cap)
			{
				return process_packet(pframe, caplen, origlen, linktype, tv_cap, ifname.c_str());
			};

			pcaparr[i] = new PCAP_NET_CAP(pifname[i], pfilter, strlen(pfilter), std::move(pcapcb));
		}	
	
		while (0 == gsig_rcvd.load()) {
			gy_nanosleep(1, 0);
		}	

		INFOPRINTCOLOR(GY_COLOR_RED, "Network Capture signalled to exit... Returning now...\n");

		return 0;

	}
	GY_CATCH_EXCEPTION(ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Exception caught while capturing from network : %s\n", GY_GET_EXCEPT_STRING); return -1;);
}	

int main(int argc, char **argv)
{
	try {
		int				ret, i;

		gdebugexecn = 25;	
		
		if (argc < 3) {
err1 :			
			IRPRINT("\nUsage : \n\n"
				"\tTo capture from Network interfaces : \n\t%s --netcapture <--printpacket Optional> <Filter String> <Interface 1> <interface 2> ...\n\n"
				"\tTo read from a captured pcap : \n\t%s -r <pcap file>\n\n", 
				argv[0], argv[0]);
			return -1;
		}	
	
		GY_SIGNAL_HANDLER::init_singleton(argv[0]);

		if (0 == strcmp(argv[1], "--netcapture")) {
			int			filnum = 2;

			if (argc < 4) {
				goto err1;
			}	

			if (0 == strcmp(argv[2], "--printpacket")) {
				gprintpacket = true;
				argc--;
				filnum++;

				if (argc < 4) {
					goto err1;
				}	
			}	

			ret = read_network(argv[filnum], &argv[filnum + 1], argc - 3 < 64 ? argc - 3 : 64);
		}
		else {
			ret = read_pcap(argv[2]);
		}	

		return ret;
	}
	GY_CATCH_EXCEPTION(ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Exception caught while reading/capturing pcap : %s\n", GY_GET_EXCEPT_STRING););
}	
