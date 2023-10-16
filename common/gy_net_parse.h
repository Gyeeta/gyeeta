//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma 			once

#include			"gy_common_inc.h"
#include			"gy_inet_inc.h"
#include			"gy_print_offload.h"

#include			<netinet/ip.h>
#include			<netinet/ip6.h>

#include 			"pcap/dlt.h"

namespace gyeeta {

enum ETHER_TYPES_E 
{
	ETHER_TYPE_IPv4		= 0x0800,
	ETHER_TYPE_ARP 		= 0x0806,
	ETHER_TYPE_IPv6		= 0x86DD,
	ETHER_TYPE_VLAN_8021Q	= 0x8100,
	ETHER_TYPE_VLAN_8021AD	= 0x88A8,
};	

struct GY_ETHERNET_HDR 
{
	static constexpr int 	GY_ETHER_ADDR_LEN 		= 6;

	uint8_t 		ether_dhost[GY_ETHER_ADDR_LEN]; 
	uint8_t 		ether_shost[GY_ETHER_ADDR_LEN];
	uint16_t 		ether_type; 		
};

/*
 * TCP Flags
 */
const uint8_t			GY_TH_FIN	= 0x01;
const uint8_t			GY_TH_SYN	= 0x02;
const uint8_t			GY_TH_RST	= 0x04;
const uint8_t			GY_TH_PUSH	= 0x08;
const uint8_t			GY_TH_ACK	= 0x10;
const uint8_t			GY_TH_URG	= 0x20;
const uint8_t			GY_TH_ECE	= 0x40;
const uint8_t			GY_TH_CWR	= 0x80;

struct GY_TCP_HDR 
{
	uint16_t		source;
	uint16_t		dest;
	uint32_t		seq;
	uint32_t		ack_seq;

	union {
		uint16_t		tcpflags;

		struct {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__		
		uint16_t		res1:4,
					doff:4,
					fin:1,
					syn:1,
					rst:1,
					psh:1,
					ack:1,
					urg:1,
					ece:1,
					cwr:1;
#else
		uint16_t		doff:4,
					res1:4,
					cwr:1,
					ece:1,
					urg:1,
					ack:1,
					psh:1,
					rst:1,
					syn:1,
					fin:1;
#endif	
		};
	};

	uint16_t		window;
	uint16_t		check;
	uint16_t		urg_ptr;

	GY_TCP_HDR() noexcept	= default;

	GY_TCP_HDR(const uint8_t *ptcp) noexcept
	{
		std::memcpy((void *)this, ptcp, sizeof(*this));

		source 		= ntohs(source);
		dest		= ntohs(dest);	
		seq		= ntohl(seq);	
		ack_seq		= ntohl(ack_seq);	
		window		= ntohs(window);
		check		= ntohs(check);

		if (urg == 1) {
			urg_ptr	= ntohs(urg_ptr);
		}
		else {
			urg_ptr = 0;
		}	
	}	

	void set_flags(uint8_t flags) noexcept
	{
		if (flags & GY_TH_ACK) {
			ack = 1;
		}	

		if (flags & GY_TH_SYN) {
			syn = 1;
		}	

		if (flags & GY_TH_FIN) {
			fin = 1;
		}	

		if (flags & GY_TH_RST) {
			rst = 1;
		}	

		if (flags & GY_TH_PUSH) {
			psh = 1;
		}	

		if (flags & GY_TH_URG) {
			urg = 1;
		}	

		if (flags & GY_TH_ECE) {
			ece = 1;
		}	

		if (flags & GY_TH_CWR) {
			cwr = 1;
		}	

	}	

	uint32_t next_expected_src_seq(uint32_t data_len) const noexcept
	{
		return seq + data_len + urg_ptr + syn;
	}	

	char * print_tcp_flags(char *pbuf, size_t sz) const noexcept
	{
		if (!pbuf) {
			return nullptr;
		}

		STR_WR_BUF		strbuf(pbuf, sz);

		strbuf.appendconst("TCP Flags : ");

		if (fin) strbuf.appendconst(" FIN |");
		if (syn) strbuf.appendconst(" SYN |");
		if (rst) strbuf.appendconst(" RST |");
		if (psh) strbuf.appendconst(" PSH |");
		if (urg) strbuf.appendconst(" URG |");

		strbuf.set_last_char(' ');

		return pbuf;
	}	
};

struct GY_UDP_HDR 
{
	uint16_t		source;
	uint16_t		dest;
	uint16_t		len;
	uint16_t		check;

	GY_UDP_HDR() noexcept	= default;

	GY_UDP_HDR(const uint8_t *pudp) noexcept
	{
		std::memcpy((void *)this, pudp, sizeof(*this));
		
		source		= ntohs(source);
		dest		= ntohs(dest);
		len		= ntohs(len);
		check		= ntohs(check);
	}	
};

struct GY_IPNET_HDR 
{
	/* Solaris IPNET */
	uint8_t			iph_version;
	uint8_t			iph_family;
	uint16_t		iph_htype;
	uint32_t		iph_pktlen;
	uint32_t		iph_ifindex;
	uint32_t		iph_grifindex;
	uint32_t		iph_zsrc;
	uint32_t		iph_zdst;
};

struct GY_SLL_HDR 
{
	static constexpr int	SLL_ADDR_LEN		= 8;

	uint16_t 		sll_pkttype;		/* packet type */
	uint16_t 		sll_hatype;		/* link-layer address type */
	uint16_t 		sll_halen;		/* link-layer address length */
	uint8_t 		sll_addr[SLL_ADDR_LEN];	/* link-layer address */
	uint16_t 		sll_protocol;		/* protocol */
};

static constexpr int 		SIZE_ETHERNET 		= (int)sizeof(GY_ETHERNET_HDR);
static constexpr int 		SIZE_ETHERNET_VLAN 	= SIZE_ETHERNET + 2;
static constexpr int		SIZE_NULLHDR		= 4;
static constexpr int		SIZE_SLL_HDR		= (int)sizeof(GY_SLL_HDR);
static constexpr int		SIZE_IPNET_HDR		= (int)sizeof(struct GY_IPNET_HDR);

/*
 * Updates ip_offset with offset of IPv4/IPv6 packet within the frame
 *
 * Returns 0 on success
 *
 * For callbacks from libpcap specify the appropriate linktype.
 *
 * For cases where pframe directly points to the IP header, specify linktype as DLT_RAW
 * 
 * XXX Does not currently handle IP Encapsulations such as VxLAN or IP-IP
 */ 
static int get_ip_offset(const uint8_t *pframe, uint32_t len, int linktype, uint32_t & ip_offset, bool & is_ipv4) noexcept
{
	struct GY_ETHERNET_HDR 		*pethernet;
	struct ip 			*pip;
	struct ip6_hdr 			*pip6;
	struct GY_SLL_HDR		*psll;
	struct GY_IPNET_HDR		*pipnet;

	const uint8_t 			* const ppkt_end = pframe + len;
	const uint8_t			*ptmp;
	uint32_t			family;
	uint16_t			ether_type;

	if (!pframe || len < sizeof(struct ip)) return -1;

	switch (linktype) {
		case DLT_EN10MB :
		case DLT_IEEE802 :
			
			if (gy_unlikely(len < sizeof(struct GY_ETHERNET_HDR) + sizeof(struct ip) + 4)) {
				return -1;
			}

			ptmp = pframe;

			pethernet = (struct GY_ETHERNET_HDR *)pframe;
			ether_type = ntohs(pethernet->ether_type);
		
			if (ether_type == ETHER_TYPE_VLAN_8021Q) {
				ether_type = unaligned_read_be16(pframe + SIZE_ETHERNET + 2);
				ptmp += 2;
			}	
			else if (ether_type == ETHER_TYPE_VLAN_8021AD) {
				ether_type = unaligned_read_be16(pframe + SIZE_ETHERNET + 4);
				ptmp += 4;
			}	

			switch (ether_type) {
			
			case ETHER_TYPE_IPv4 :	
				is_ipv4 = true;
				ip_offset = SIZE_ETHERNET + (ptmp - pframe);
				return 0;
				
			case ETHER_TYPE_IPv6 :	
				if (gy_unlikely(ptmp + sizeof(GY_ETHERNET_HDR) + sizeof(struct ip6_hdr) >= ppkt_end)) {
					return -1;
				}	

				is_ipv4 = false;
				ip_offset = SIZE_ETHERNET + (ptmp - pframe);
				return 0;

			default :
				return -1;	
			}	

		case DLT_LINUX_SLL :

			if (gy_unlikely(len < SIZE_SLL_HDR + sizeof(struct ip))) {
				return -1;
			}

			psll = (struct GY_SLL_HDR *)pframe;
			
			ether_type = ntohs(psll->sll_protocol);

			switch (ether_type) {
			
			case ETHER_TYPE_IPv4 :	
				is_ipv4 = true;
				ip_offset = SIZE_SLL_HDR;
				return 0;
				
			case ETHER_TYPE_IPv6 :	
				if (gy_unlikely(len < SIZE_SLL_HDR + sizeof(struct ip6_hdr))) {
					return -1;
				}

				is_ipv4 = false;
				ip_offset = SIZE_SLL_HDR;
				return 0;

			default :
				return -1;	
			}	


		case DLT_NULL :
		case DLT_LOOP :

			if (gy_unlikely(len < SIZE_NULLHDR + sizeof(struct ip))) {
				return -1;
			}	

			memcpy((char *)&family, (char *)pframe, sizeof(family));

			/*
			 * This isn't necessarily in our host byte order; if this is
			 * a DLT_LOOP capture, it's in network byte order, and if
			 * this is a DLT_NULL capture from a machine with the opposite
			 * byte-order, it's in the opposite byte order from ours.
			 *
			 * If the upper 16 bits aren't all zero, assume it's byte-swapped.
			 */
			if ((family & 0xFFFF0000) != 0) {
				family = GY_SWAP_32(family);
			}

			if (family == 0) {
				return -1; 
			}

			pip = (struct ip *)(pframe + SIZE_NULLHDR);

			switch (pip->ip_v) {
			case 4:
				is_ipv4 = true;
				ip_offset = SIZE_NULLHDR;
				return 0;

			case 6:
				if (gy_unlikely(len < SIZE_NULLHDR + sizeof(struct ip6_hdr))) {
					return -1;
				}	

				is_ipv4 = false;
				ip_offset = SIZE_NULLHDR;
				return 0;

			default:
				return -1;
			}

		case DLT_RAW :

			if (gy_unlikely(len < sizeof(struct ip))) {
				return -1;
			}	

			pip = (struct ip *)(pframe);

			switch (pip->ip_v) {
			case 4:
				is_ipv4 = true;
				ip_offset = 0;
				return 0;

			case 6:
				if (len < sizeof(struct ip6_hdr)) {
					return -1;
				}

				is_ipv4 = false;
				ip_offset = 0;
				return 0;

			default:
				return -1;
			}

		case DLT_IPNET :

#ifndef IPH_AF_INET
#define	IPH_AF_INET	2		/* Matches Solaris's AF_INET */
#define	IPH_AF_INET6	26		/* Matches Solaris's AF_INET6 */
#endif
			if (len < SIZE_IPNET_HDR + sizeof(struct ip)) {
				return -1;
			}

			pipnet = (struct GY_IPNET_HDR *)pframe;
			
			switch (pipnet->iph_family) {

			case IPH_AF_INET :
				is_ipv4 = true;
				ip_offset = SIZE_IPNET_HDR;
				return 0;

			case IPH_AF_INET6 :
				if (len < SIZE_IPNET_HDR + sizeof(struct ip6_hdr)) {
					return -1;
				}

				is_ipv4 = false;
				ip_offset = SIZE_IPNET_HDR;
				return 0;

			default:
				return -1;
			}


		default :
			return -1;
	}

	return -1;
}

static void get_src_dest_ipv4(const struct ip *pip, GY_IP_ADDR & srcip, GY_IP_ADDR & destip) noexcept
{
	srcip.set_ip(pip->ip_src);
	destip.set_ip(pip->ip_dst);
}

static void get_src_dest_ipv6(const struct ip6_hdr *pip, GY_IP_ADDR & srcip, GY_IP_ADDR & destip) noexcept
{
	srcip.set_ip(pip->ip6_src);
	destip.set_ip(pip->ip6_dst);
}


/*
 * Get the TCP/UDP header from an IPv4 fragment. pktlen is buffer length starting from IPv4 header
 * Returns 0 on success, > 1 for ignore packet, < 1 on errors
 *
 * SCTP and other Transport protocols not supported.
 *
 * XXX data_offset and data_len will be populated only for TCP or UDP transport
 * data_offset is the (uint8_t *)pip + transport header i.e. pointing to the first Payload byte beyond the Transport header e.g. TCP/UDP Payload
 * data_len is the length of the transport data payload len (e.g. TCP Payload len)
 *
 * XXX Does not currently handle IP Encapsulated TCP/UDP such as VxLAN or IP-IP
 */ 
static int get_ipv4_transport_offset(const struct ip *pip, uint32_t pktlen, uint8_t & transport_proto, uint32_t & transport_offset, uint32_t & data_offset, uint32_t & data_len) noexcept
{
	const uint8_t 		* const phdr = reinterpret_cast<const uint8_t *>(pip);
	const uint8_t 		* const ppkt_end = phdr + pktlen;
	uint16_t		off;
	uint32_t		size_ip, size_tcp, size_udp, ip_len, urg_len, tlen;
	const GY_TCP_HDR	*ptcp;
	const GY_UDP_HDR	*pudp;

	if (((uintptr_t)pip) & 3) {
		uint16_t	ip_off, ip_16_len;

		memcpy(&ip_off, (char *)&pip->ip_off, sizeof(ip_off));
		off = ntohs(ip_off);

		memcpy(&ip_16_len, (char *)&pip->ip_len, sizeof(ip_16_len));
		ip_len = ntohs(ip_16_len);
	}
	else {
		off = ntohs(pip->ip_off);
		ip_len = ntohs(pip->ip_len);
	}

	if ((off & 0x1fff) != 0) {
		DEBUGEXECN(1, 
			static uint32_t		nipprints = 0;

			if (0 == nipprints % 1000) {
				WARNPRINT_OFFLOAD("IP Fragment encountered. IP Fragmentation currently Not Supported. Total IP Fragments seen so far = %u\n", nipprints + 1);
			}
			nipprints++;
		);

		return 1;
	}

	size_ip = pip->ip_hl << 2;

	if (size_ip < sizeof(*pip) || size_ip >= pktlen) {
		return 1;
	}	

	transport_proto 	= pip->ip_p;
	transport_offset 	= size_ip;
	
	/*
	 * Now validate the transport proto. We currently only validate TCP and UDP
	 */ 
	switch (transport_proto) {
	
	case IP_PROTO_TCP :
		if (phdr + size_ip + sizeof(*ptcp) > ppkt_end) {
			return 1;
		}	

		ptcp = (decltype(ptcp))(phdr + size_ip);
		size_tcp = ptcp->doff << 2;

		if ((size_tcp < sizeof(*ptcp)) || (phdr + size_ip + size_tcp > ppkt_end)) {
			return 1;
		}	

		urg_len = 0;

		if (ptcp->urg) {
			if (ptcp->urg_ptr > 0) {
				urg_len = ntohs(ptcp->urg_ptr);

				if (phdr + size_ip + size_tcp + urg_len > ppkt_end) {
					return 1;
				}	
			}
		}

		if (ip_len > 0) {
			tlen = ip_len;
		}
		else {
			tlen = 	pktlen;
		}		

		data_offset	= size_ip + size_tcp + urg_len;
		data_len	= tlen - size_ip - size_tcp - urg_len;
		
		return 0;

	case IP_PROTO_UDP :
		if (phdr + size_ip + sizeof(*pudp) > ppkt_end) {
			return 1;
		}	

		pudp = (decltype(pudp))(phdr + size_ip);
		size_udp = ntohs(pudp->len);

		if ((size_udp < sizeof(*pudp)) || (phdr + size_ip + size_udp > ppkt_end)) {
			return 1;
		}	

		if (ip_len > 0) {
			tlen = ip_len;
		}
		else {
			tlen = 	pktlen;
		}		

		data_offset	= size_ip + sizeof(*pudp);
		data_len	= size_udp - sizeof(*pudp);
		
		return 0;

	default :
		data_offset	= 0;
		data_len	= 0;

		return 1;
	}	
}

/*
 * Get the TCP/UDP header from an IPv6 fragment. pktlen is buffer length starting from IPv6 header
 * Returns 0 on success, > 1 for ignore packet, < 1 on errors
 *
 * SCTP and other Transport protocols not supported.
 *
 * XXX data_offset and data_len will be populated only for TCP or UDP transport
 * data_offset is the (uint8_t *)pip + transport header i.e. pointing to the first Payload byte beyond the Transport header e.g. TCP/UDP Payload
 * data_len is the length of the transport data payload len (e.g. TCP Payload len)
 *
 * XXX Does not currently handle IP Encapsulated TCP/UDP such as VxLAN or IP-IP
 */ 
static int get_ipv6_transport_offset(const struct ip6_hdr *pip, uint32_t pktlen, uint8_t & transport_proto, uint32_t & transport_offset, uint32_t & data_offset, uint32_t & data_len) noexcept
{
	const uint8_t 		* const phdr = reinterpret_cast<const uint8_t *>(pip);
	const uint8_t 		* const ppkt_end = phdr + pktlen;
	const uint8_t		*ptmp;
	uint8_t			nxthdr;
	uint32_t		size_tcp, size_udp, ip_len, urg_len, tlen;
	const GY_TCP_HDR	*ptcp;
	const GY_UDP_HDR	*pudp;

	if (((uintptr_t)pip) & 1) {
		uint16_t	ip_16_len;

		memcpy(&ip_16_len, (char *)&pip->ip6_plen, sizeof(ip_16_len));
		ip_len = ntohs(ip_16_len);
	}
	else {
		ip_len = ntohs(pip->ip6_plen);
	}

	if (sizeof(*pip) + sizeof(*pudp) > pktlen) {
		return 1;
	}	
	
	ptmp = phdr + sizeof(*pip);
	nxthdr = pip->ip6_nxt;

	while (ptmp < ppkt_end) {

		switch (nxthdr) {
	
		case IP_PROTO_TCP :
				
			if (ptmp + sizeof(*ptcp) > ppkt_end) {
				return 1;
			}

			transport_proto 	= IP_PROTO_TCP;
			transport_offset	= ptmp - phdr;

			ptcp = (decltype(ptcp))ptmp;
			size_tcp = ptcp->doff << 2;

			if ((size_tcp < sizeof(*ptcp)) || (ptmp + size_tcp > ppkt_end)) {
				return 1;
			}	

			urg_len = 0;

			if (ptcp->urg) {
				if (ptcp->urg_ptr > 0) {
					urg_len = ntohs(ptcp->urg_ptr);

					if (ptmp + size_tcp + urg_len > ppkt_end) {
						return 1;
					}	
				}
			}

			if (ip_len > 0) {
				tlen = ip_len;
			}
			else {
				tlen = 	ppkt_end - ptmp;
			}		

			data_offset	= transport_offset + size_tcp + urg_len;
			data_len	= tlen - size_tcp - urg_len;
		
			return 0;

		case IP_PROTO_UDP :
				
			if (ptmp + sizeof(*pudp) > ppkt_end) {
				return 1;
			}

			transport_proto 	= IP_PROTO_UDP;
			transport_offset	= ptmp - phdr;

			pudp = (decltype(pudp))ptmp;
			size_udp = ntohs(pudp->len);

			if ((size_udp < sizeof(*pudp)) || (ptmp + size_udp > ppkt_end)) {
				return 1;
			}	

			if (ip_len > 0) {
				tlen = ip_len;
			}
			else {
				tlen = 	pktlen;
			}		

			data_offset	= transport_offset + sizeof(*pudp);
			data_len	= size_udp - sizeof(*pudp);
			
			return 0;

		case IP_PROTO_IPv6_HOPOPT :
		case IP_PROTO_IPv6_ROUTE :
		case IP_PROTO_IPv6_DST_OPTIONS :
			{
				struct ip6_ext		*pext;
					
				if (ptmp + sizeof(*pext) > ppkt_end) {
					return 1;
				}
				
				pext = (decltype(pext))ptmp;

				nxthdr = pext->ip6e_nxt;
				ptmp += (pext->ip6e_len + 1u) << 3;

				break;
			}

		case IP_PROTO_IPv6_NO_NXT_HDR :
			// NO Transport Header. Ignore pkt
			return 1;	
		
		case IP_PROTO_IPv6_FRAGMENT :
			DEBUGEXECN(1, 
				static uint32_t		nipprints = 0;

				if (0 == nipprints % 1000) {
					WARNPRINT_OFFLOAD("IPv6 Fragment encountered. IP Fragmentation currently Not Supported. Total IPv6 Fragments seen so far = %u\n", nipprints + 1);
				}
				nipprints++;
			);
			return 1;
					
		default :
			return 1;	
		}	
	};	

	return 1;
}


} // namespace gyeeta
