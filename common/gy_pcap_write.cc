//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later


#include			"gy_pcap_write.h"
#include			"gy_pcap_read.h"

namespace gyeeta {

GY_PCAP_WRITER::GY_PCAP_WRITER(const char *outputfile, bool use_unlocked_io, bool throw_if_exists, size_t maxsize)
	: sfile_(GY_TAG_EXCEPTION(), outputfile, throw_if_exists ? "w+x" : "w+", use_unlocked_io), maxsize_(maxsize), filename_(outputfile)
{
	size_t				n;
	PCAP_FILE_HEADER		hdr {};

	hdr.magic			= GY_TCPDUMP_MAGIC;
	hdr.version_major		= GY_PCAP_VERSION_MAJOR;
	hdr.version_minor		= GY_PCAP_VERSION_MINOR;
	hdr.snaplen			= 0xFFFF;
	hdr.linktype			= DLT_RAW;

	
	n = fwrite(&hdr, 1, sizeof(hdr), sfile_.get());

	if (n != sizeof(hdr)) {
		GY_THROW_SYS_EXCEPTION("Failed to write to output pcap file %s", outputfile);
	}	

	nwritten_			= sizeof(hdr);
}	

bool GY_PCAP_WRITER::write_tcp_pkt(struct timeval tv, const GY_IP_ADDR & cip, const GY_IP_ADDR &dip, uint16_t cport, uint16_t dport, 
				uint32_t seq, uint32_t ack, uint8_t tcpflags, const void *pdata, uint16_t datalen) noexcept
{
	if (nwritten_ >= maxsize_) {
		return false;
	}

	struct iovec			iov[4];
	PCAP_REC_HEADER			hdr = {};
	GY_TCP_HDR			tcp = {};
	struct ip			ipv4;
	struct ip6_hdr			ipv6;
	size_t				nwr, npend;

	hdr.ts.tv_sec			= tv.tv_sec;
	hdr.ts.tv_usec			= tv.tv_usec;

	iov[0].iov_base			= &hdr;
	iov[0].iov_len			= sizeof(hdr);

	if (false == cip.is_ipv6_addr()) {
		std::memset(&ipv4, 0, sizeof(ipv4));

		// Set the IPv4 header
		ipv4.ip_hl		= 5;		// 20 bytes
		ipv4.ip_v		= 4;
		ipv4.ip_len		= htons(sizeof(ipv4) + sizeof(GY_TCP_HDR) + datalen);
		ipv4.ip_id		= htons(1234);
		ipv4.ip_ttl		= 64;
		ipv4.ip_p		= IP_PROTO_TCP;

		cip.get_as_inaddr(&ipv4.ip_src);
		dip.get_as_inaddr(&ipv4.ip_dst);

		iov[1].iov_base		= &ipv4;
		iov[1].iov_len		= sizeof(ipv4);

		hdr.caplen		= sizeof(ipv4);
		hdr.len			= sizeof(ipv4);
	}
	else {
		std::memset(&ipv6, 0, sizeof(ipv6));

		// Set the IPv6 header
		unaligned_write_32(&ipv6.ip6_ctlun.ip6_un1.ip6_un1_flow, 0x60, BO_LITTLE_ENDIAN);

		ipv6.ip6_ctlun.ip6_un1.ip6_un1_plen 	= htons(sizeof(GY_TCP_HDR) + datalen);
		ipv6.ip6_ctlun.ip6_un1.ip6_un1_nxt	= IP_PROTO_TCP;
		ipv6.ip6_ctlun.ip6_un1.ip6_un1_hlim	= 60;

		cip.get_as_inaddr(&ipv6.ip6_src);
		dip.get_as_inaddr(&ipv6.ip6_dst);

		iov[1].iov_base		= &ipv6;
		iov[1].iov_len		= sizeof(ipv6);

		hdr.caplen		= sizeof(ipv6);
		hdr.len			= sizeof(ipv6);
	}	

	if (datalen > 0) {
		tcpflags 		|= GY_TH_PUSH; 
	}	

	if (ack) {
		tcpflags		|= GY_TH_ACK;
	}	

	tcp.source			= htons(cport);
	tcp.dest			= htons(dport);
	tcp.seq				= htonl(seq);
	tcp.ack_seq			= htonl(ack);
	tcp.doff			= 5;

	tcp.set_flags(tcpflags);

	tcp.window			= 0xFFFF;
	
	iov[2].iov_base			= &tcp;
	iov[2].iov_len			= sizeof(tcp);

	iov[3].iov_base			= (void *)pdata;
	iov[3].iov_len			= datalen;

	hdr.caplen			+= sizeof(tcp) + datalen;
	hdr.len				+= sizeof(tcp) + datalen;

	nwr = gy_fwrite_iov(sfile_.get(), iov, 4, &npend);

	nwritten_ += nwr;

	if (npend > 0) {
		npkts_ += !!nwr;
		return false;
	}	

	npkts_++;

	return true;
}	

bool GY_PCAP_WRITER::write_udp_pkt(struct timeval tv, const GY_IP_ADDR & cip, const GY_IP_ADDR &dip, uint16_t cport, uint16_t dport, const void *pdata, uint16_t datalen) noexcept
{
	if (nwritten_ >= maxsize_) {
		return false;
	}

	struct iovec			iov[4];
	PCAP_REC_HEADER			hdr = {};
	GY_UDP_HDR			udp = {};
	struct ip			ipv4;
	struct ip6_hdr			ipv6;
	size_t				nwr, npend;

	hdr.ts.tv_sec			= tv.tv_sec;
	hdr.ts.tv_usec			= tv.tv_usec;

	iov[0].iov_base			= &hdr;
	iov[0].iov_len			= sizeof(hdr);

	if (false == cip.is_ipv6_addr()) {
		std::memset(&ipv4, 0, sizeof(ipv4));

		// Set the IPv4 header
		ipv4.ip_hl		= 5;		// 20 bytes
		ipv4.ip_v		= 4;
		ipv4.ip_len		= htons(sizeof(ipv4) + sizeof(GY_UDP_HDR) + datalen);
		ipv4.ip_id		= htons(1234);
		ipv4.ip_ttl		= 64;
		ipv4.ip_p		= IP_PROTO_UDP;

		cip.get_as_inaddr(&ipv4.ip_src);
		dip.get_as_inaddr(&ipv4.ip_dst);

		iov[1].iov_base		= &ipv4;
		iov[1].iov_len		= sizeof(ipv4);

		hdr.caplen		= sizeof(ipv4);
		hdr.len			= sizeof(ipv4);
	}
	else {
		std::memset(&ipv6, 0, sizeof(ipv6));

		// Set the IPv6 header
		unaligned_write_32(&ipv6.ip6_ctlun.ip6_un1.ip6_un1_flow, 0x60, BO_LITTLE_ENDIAN);
		
		ipv6.ip6_ctlun.ip6_un1.ip6_un1_plen 	= htons(sizeof(GY_UDP_HDR) + datalen);
		ipv6.ip6_ctlun.ip6_un1.ip6_un1_nxt	= IP_PROTO_UDP;
		ipv6.ip6_ctlun.ip6_un1.ip6_un1_hlim	= 60;

		cip.get_as_inaddr(&ipv6.ip6_src);
		dip.get_as_inaddr(&ipv6.ip6_dst);

		iov[1].iov_base		= &ipv6;
		iov[1].iov_len		= sizeof(ipv6);

		hdr.caplen		= sizeof(ipv6);
		hdr.len			= sizeof(ipv6);
	}	

	udp.source			= htons(cport);
	udp.dest			= htons(dport);
	udp.len				= htons(sizeof(udp) + datalen);
	udp.check			= htons(0xABCD);		// Dummy chksum
	
	iov[2].iov_base			= &udp;
	iov[2].iov_len			= sizeof(udp);

	iov[3].iov_base			= (void *)pdata;
	iov[3].iov_len			= datalen;

	hdr.caplen			+= sizeof(udp) + datalen;
	hdr.len				+= sizeof(udp) + datalen;

	nwr = gy_fwrite_iov(sfile_.get(), iov, 4, &npend);

	nwritten_ += nwr;

	if (npend > 0) {
		npkts_ += !!nwr;
		return false;
	}	

	npkts_++;

	return true;
}	

} // namespace gyeeta

