
#include			"gy_common_inc.h"
#include			"gy_pcap_write.h"

using namespace gyeeta;


void write_pcap(const char *pfile)
{
	GY_PCAP_WRITER			writer(pfile);
	uint32_t			cseq = 1024, dseq = 32768;
	bool				bret;
	
	bret = writer.write_tcp_pkt(get_timeval(), GY_IP_ADDR("127.0.0.1"), GY_IP_ADDR("127.0.0.1"), 40010, 2022, cseq, 0, GY_TH_SYN, nullptr, 0);
	assert(bret);

	cseq++;

	bret = writer.write_tcp_pkt(get_timeval(), GY_IP_ADDR("127.0.0.1"), GY_IP_ADDR("127.0.0.1"), 2022, 40010, dseq, cseq, GY_TH_SYN | GY_TH_ACK, nullptr, 0);
	assert(bret);

	dseq++;

	bret = writer.write_tcp_pkt(get_timeval(), GY_IP_ADDR("127.0.0.1"), GY_IP_ADDR("127.0.0.1"), 40010, 2022, cseq, dseq, 0, "Testing data", GY_CONST_STRLEN("Testing data"));
	assert(bret);

	cseq += GY_CONST_STRLEN("Testing data");

	bret = writer.write_tcp_pkt(get_timeval(), GY_IP_ADDR("127.0.0.1"), GY_IP_ADDR("127.0.0.1"), 2022, 40010, dseq, cseq, 0, "Reply Testing data", GY_CONST_STRLEN("Reply Testing data"));
	assert(bret);

	dseq += GY_CONST_STRLEN("Reply Testing data");

	char				buf1[5000];

	std::memset(buf1, 'd', sizeof(buf1));

	bret = writer.write_tcp_pkt(get_timeval(), GY_IP_ADDR("127.0.0.1"), GY_IP_ADDR("127.0.0.1"), 2022, 40010, dseq, cseq, 0, buf1, sizeof(buf1));
	assert(bret);

	dseq += sizeof(buf1);

	bret = writer.write_tcp_pkt(get_timeval(), GY_IP_ADDR("127.0.0.1"), GY_IP_ADDR("127.0.0.1"), 40010, 2022, cseq, dseq, GY_TH_FIN | GY_TH_ACK, nullptr, 0);
	assert(bret);

	// Next 

	gy_msecsleep(1000);

	cseq = 8192;
	dseq = 16 * 1024;

	bret = writer.write_tcp_pkt(get_timeval(), GY_IP_ADDR("::1"), GY_IP_ADDR("::1"), 40011, 2022, cseq, 0, GY_TH_SYN, nullptr, 0);
	assert(bret);

	cseq++;

	bret = writer.write_tcp_pkt(get_timeval(), GY_IP_ADDR("::1"), GY_IP_ADDR("::1"), 2022, 40011, dseq, cseq, GY_TH_SYN | GY_TH_ACK, nullptr, 0);
	assert(bret);

	dseq++;

	bret = writer.write_tcp_pkt(get_timeval(), GY_IP_ADDR("::1"), GY_IP_ADDR("::1"), 40011, 2022, cseq, dseq, 0, "Testing data", GY_CONST_STRLEN("Testing data"));
	assert(bret);

	cseq += GY_CONST_STRLEN("Testing data");

	bret = writer.write_tcp_pkt(get_timeval(), GY_IP_ADDR("::1"), GY_IP_ADDR("::1"), 2022, 40011, dseq, cseq, 0, "Reply Testing data", GY_CONST_STRLEN("Reply Testing data"));
	assert(bret);

	dseq += GY_CONST_STRLEN("Reply Testing data");

	bret = writer.write_tcp_pkt(get_timeval(), GY_IP_ADDR("::1"), GY_IP_ADDR("::1"), 40011, 2022, cseq, dseq, GY_TH_FIN | GY_TH_ACK, nullptr, 0);
	assert(bret);

	// Next 

	gy_msecsleep(1000);

	bret = writer.write_udp_pkt(get_timeval(), GY_IP_ADDR("fe80::23d:f900:123a:edbc"), GY_IP_ADDR("fe80::23d:f900:123a:edbd"), 40012, 2053, "DNS Query", GY_CONST_STRLEN("DNS Query"));
	assert(bret);

	bret = writer.write_udp_pkt(get_timeval(), GY_IP_ADDR("fe80::23d:f900:123a:edbd"), GY_IP_ADDR("fe80::23d:f900:123a:edbc"), 2053, 40012, "DNS Response", GY_CONST_STRLEN("DNS Response"));
	assert(bret);

	auto			[ npkts, nbytes, tstart ] = writer.get_stats();

	IRPRINT("\n");

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Output pcap %s : Written # %lu packets : Total %lu bytes : Running since %ld sec\n\n",  writer.get_filename(), npkts, nbytes, time(nullptr) - tstart);
}	


int main(int argc, char **argv)
{
	if (argc != 2) {
		IRPRINT("\n\nUsage : %s <Output pcap file path>\n\ne.g. %s /tmp/test1.pcap\n\n", argv[0], argv[0]);
		return -1;
	}	
	
	try {
		write_pcap(argv[1]);
	}
	GY_CATCH_EXPRESSION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "pcap writer failed : %s\n", GY_GET_EXCEPT_STRING);
	);

	return 0;
}


