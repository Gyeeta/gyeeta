
#include		"gy_common_inc.h"
#include		"gy_pcap_read.h"
#include		"gy_network_capture.h"
#include		"gy_dns_mapping.h"

using namespace gyeeta;

static std::atomic<int>		gsig_rcvd;	
static int64_t			gnframe;

int parse_dns_resp(const uint8_t *pdata, uint32_t len, struct timeval tv_pkt) noexcept	
{
	try {
		const uint8_t 		*pstart = pdata, *pend = pdata + len;
		const uint8_t		*ptmp = pdata;
		uint32_t		nqueries, nanswers;

		char			ipbuf[128];
		
		if (len < 32) {
			return 1;
		}
		
		ptmp += 2;

		if ((0 == (ptmp[0] & 0x80)) || (0 != (ptmp[1] & 0x0F))) {
			return 1;
		}	
			
		ptmp += 2;
			
		nqueries = unaligned_read_be16(ptmp);

		if ((nqueries == 0) || (nqueries > 8)) {
			return 1;
		}	

		ptmp += 2;

		nanswers = unaligned_read_be16(ptmp);

		if (nanswers == 0) {
			return 1;
		}
		else if (nanswers > 16) {
			nanswers = 16;
		}	

		char			domainarray[nqueries + 1][MAX_DOMAINNAME_SIZE];
		uint16_t		offsetarray[nqueries + 1] {};

		uint16_t		tdata;
		uint8_t			n;

		ptmp += 6;

		for (uint32_t i = 0; i < nqueries; i++) {
			STR_WR_BUF		strbuf(domainarray[i], MAX_DOMAINNAME_SIZE);

			if (ptmp + 5 >= pend) {
				return 1;
			}	
			
			offsetarray[i] = ptmp - pstart;

			do {
				n = *ptmp++;

				if (ptmp + n >= pend) {
					return 1;
				}	
				
				if (n == 0) {
					strbuf.set_last_char('\0');
					break;
				}
					
				strbuf.append((const char *)ptmp, n);
				strbuf.append('.');

				ptmp += n;

			} while (ptmp + 4 < pend);

			if (0 == strbuf.length()) {
				return 1;
			}	
			
			if (ptmp + 4 >= pend) {
				return 1;
			}	

			ptmp += 4;
		}	
		
		/*
		 * Now parse the Answers
		 */
		for (uint32_t i = 0; i < nanswers; i++) {
			char			inlinename[MAX_DOMAINNAME_SIZE];
			const char 		*pdomain = nullptr;

			if (ptmp + 15 > pend) {
				return 1;
			}	 
		
			if ((*ptmp & 0xC0) == 0xC0) {

				tdata = unaligned_read_be16(ptmp);
				tdata &= 0x0FFF;

				uint32_t 	j = 0;

				if (nqueries > 1) {
					for (; j < nqueries; j++) {
						if (offsetarray[j] == tdata) {
							break;
						}	
					}	

					if (j == nqueries) {
						return 1;
					}
				}

				ptmp += 2;

				pdomain = domainarray[j];
			}
			else {
				STR_WR_BUF		strbuf(inlinename, MAX_DOMAINNAME_SIZE);

				if (ptmp + 5 >= pend) {
					return 1;
				}	
				
				do {
					n = *ptmp++;

					if (ptmp + n >= pend) {
						return 1;
					}	
					
					if (n == 0) {
						strbuf.set_last_char('\0');
						break;
					}
						
					strbuf.append((const char *)ptmp, n);
					strbuf.append('.');

					ptmp += n;

				} while (ptmp + 4 < pend);

				if (0 == strbuf.length()) {
					return 1;
				}	

				pdomain = inlinename;
			}	

			if (gy_unlikely(nullptr == pdomain)) {
				return 1;
			}	

			tdata = unaligned_read_be16(ptmp);
			
			if (tdata == 0x1) {
				// IPv4
				ptmp += 8;

				if (ptmp + 2 + 4 > pend) {
					return 1;
				}	

				tdata = unaligned_read_be16(ptmp);

				if (tdata != 4) {
					return 1;
				}	

				ptmp += 2;
				
				uint32_t		ip4;
				std::memcpy(&ip4, ptmp, sizeof(ip4));

				ptmp += 4;

				GY_IP_ADDR		addr(ip4);

				INFOPRINTCOLOR(GY_COLOR_GREEN, "DNS Response for domain %s : IPv4 is %s\n", pdomain, addr.printaddr(ipbuf, sizeof(ipbuf)));
			}	
			else if (tdata == 0x1c) {
				// IPv6
				ptmp += 8;

				if (ptmp + 2 + 16 > pend) {
					return 1;
				}	
				tdata = unaligned_read_be16(ptmp);

				if (tdata != 16) {
					return 1;
				}	

				ptmp += 2;

				unsigned __int128	ip6;

				std::memcpy(&ip6, ptmp, sizeof(ip6));

				ptmp += 16;

				GY_IP_ADDR		addr(ip6);

				INFOPRINTCOLOR(GY_COLOR_GREEN, "DNS Response for domain %s : IPv6 is %s\n", pdomain, addr.printaddr(ipbuf, sizeof(ipbuf)));
			}	
			else if (tdata == 0x5 && (nqueries == 1)) { // CNAME Record : Proceed only if nqueries == 1  
				
				ptmp += 8;

				if (ptmp + 2 > pend) {
					return 1;
				}	

				tdata = unaligned_read_be16(ptmp);

				ptmp += 2 + tdata;
				
				continue;
			}	
			else {
				return 1;
			}	
		}
			
		return 0;	
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Exception caught while parsing DNS response : %s\n", GY_GET_EXCEPT_STRING););
		return -1;
	);	
}	
	
int process_packet(const uint8_t *pframe, uint32_t caplen, uint32_t origlen, int linktype, struct timeval tv_pkt) noexcept
{
	const struct ip 	*pip;
	const struct ip6_hdr	*pip6;
	const uint8_t		*porigframe, *pudp; 
	GY_UDP_HDR		udp;
	uint8_t			transport_proto;
	uint32_t 		ip_offset, transport_offset, data_offset, data_len;
	int			ret;
	bool			is_ipv4;
	
	ret = get_ip_offset(pframe, caplen, linktype, ip_offset, is_ipv4);
	if (ret != 0 || (ip_offset > caplen)) {
		return 1;
	}	

	porigframe = pframe;

	caplen -= ip_offset;
	pframe += ip_offset;

	if (is_ipv4) {
		pip = decltype(pip)(pframe);
		
		ret = get_ipv4_transport_offset(pip, caplen, transport_proto, transport_offset, data_offset, data_len);
	}	
	else {
		pip6 = decltype(pip6)(pframe);
		
		ret = get_ipv6_transport_offset(pip6, caplen, transport_proto, transport_offset, data_offset, data_len);
	}	

	if (ret != 0 || ((transport_offset > caplen) || ((data_len > 0) && ((data_offset + data_len > caplen) || (data_offset < transport_offset))))) {
		return 1;
	}	

	if ((data_len == 0) || (transport_proto != IP_PROTO_UDP)) {
		return 1;
	}	

	caplen -= transport_offset;
	pframe += transport_offset;

	pudp = decltype(pudp)(pframe);
		
	udp.~GY_UDP_HDR();
	new (&udp) GY_UDP_HDR(pudp);

	if (gy_unlikely(udp.source != 53)) {
		return 1;
	}	
	
	pframe += (data_offset - transport_offset);

	return parse_dns_resp(pframe, data_len, tv_pkt);
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
				INFOPRINTCOLOR(GY_COLOR_GREEN, "Completed reading the pcap. Exiting ...\n");
				return 0;
			}	

			gnframe++;
		
			ret = process_packet(pframe, caplen, origlen, linktype, tv_pkt);
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

static int read_network(char **pifname, int nifs)
{
	try {
		PCAP_NET_CAP		*pcaparr[nifs] {};

		const char 		*pfilter = "udp && src port 53";
		
		GY_SIGNAL_HANDLER::get_singleton()->set_signal_handler(SIGINT, handle_signal);

		auto pcapcb = [](const uint8_t * pframe, uint32_t caplen, uint32_t origlen, int linktype, struct timeval tv_cap)
		{
			return process_packet(pframe, caplen, origlen, linktype, tv_cap);
		};

		GY_SCOPE_EXIT {
			for (int i = 0; i < nifs; i++) {
				delete pcaparr[i];
			}	
		};

		for (int i = 0; i < nifs; i++) {
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
				"\tTo capture DNS responses from Network interfaces : \n\t%s --netcapture <Interface 1> <interface 2> ...\n\n"
				"\tTo read DNS Responses from a captured pcap : \n\t%s -r <pcap file>\n\n", 
				argv[0], argv[0]);
			return -1;
		}	
	
		GY_SIGNAL_HANDLER::init_singleton(argv[0]);


		if (0 == strcmp(argv[1], "--netcapture")) {
			DNS_MAPPING::init_singleton();

			ret = read_network(&argv[2], argc - 2 < 64 ? argc - 2 : 64);
		}
		else {
			ret = read_pcap(argv[2]);
		}	

		return ret;
	}
	GY_CATCH_EXCEPTION(ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Exception caught while reading/capturing pcap : %s\n", GY_GET_EXCEPT_STRING););
}	
