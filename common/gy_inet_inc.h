
/*
 * Inet (TCP/UDP) stuff
 */
 
#pragma 				once

#include 				"gy_common_inc.h"
#include 				"gy_rcu_inc.h"

namespace gyeeta {


#define gy_mnl_attr_for_each(attr, nlh, offset) \
	for ((attr) = (struct nlattr *)mnl_nlmsg_get_payload_offset((nlh), (offset)); \
	     mnl_attr_ok((attr), (char *)mnl_nlmsg_get_payload_tail(nlh) - (char *)(attr)); \
	     (attr) = mnl_attr_next(attr))

#define gy_mnl_attr_for_each_nested(attr, nest) \
	for ((attr) = (struct nlattr *)mnl_attr_get_payload(nest); \
	     mnl_attr_ok((attr), (char *)mnl_attr_get_payload(nest) + mnl_attr_get_payload_len(nest) - (char *)(attr)); \
	     (attr) = mnl_attr_next(attr))

#define gy_mnl_attr_for_each_payload(payload, payload_size) \
	for ((attr) = (struct nlattr *)((payload); \
	     mnl_attr_ok((attr), (char *)(payload) + payload_size - (char *)(attr)); \
	     (attr) = mnl_attr_next(attr))

#define GY_MNL_SOCKET_BUFFER_SIZE	8192


/* Kernel TCP states. <Kernel>/include/net/tcp_states.h */
enum GY_TCP_STATE_E 
{
	GY_TCP_ESTABLISHED 		= 1,
	GY_TCP_SYN_SENT,
	GY_TCP_SYN_RECV,
	GY_TCP_FIN_WAIT1,
	GY_TCP_FIN_WAIT2,
	GY_TCP_TIME_WAIT,
	GY_TCP_CLOSE,
	GY_TCP_CLOSE_WAIT,
	GY_TCP_LAST_ACK,
	GY_TCP_LISTEN,
	GY_TCP_CLOSING,	
	GY_TCP_NEW_SYN_RECV,

	GY_TCP_MAX_STATES	/* Leave at the end! */

};

static constexpr const char * get_tcp_state_string(GY_TCP_STATE_E state) noexcept
{
	constexpr const char * tcp_states_map[] {
		"",
		"ESTABLISHED",
		"SYN-SENT",
		"SYN-RECV",
		"FIN-WAIT-1",
		"FIN-WAIT-2",
		"TIME-WAIT",
		"CLOSE",
		"CLOSE-WAIT",
		"LAST-ACK",
		"LISTEN",
		"CLOSING",
		"SYN-RECV",
	};
	
	return (state < GY_TCP_MAX_STATES ? tcp_states_map[state] : "Unknown");
}	

static constexpr const char * get_socket_type_string(int socktype) noexcept
{
	constexpr const char * sock_types_map[] {
		"Invalid",
		"Stream",
		"Datagram",
		"Raw",
		"Rdm",
		"Seqpacket",
		"DCCP",
		"Packet",
	};
	
	return (socktype < (int)GY_ARRAY_SIZE(sock_types_map) ? sock_types_map[socktype] : "Unknown");
}	

static constexpr const char * get_socket_protocol_string(int protocol) noexcept
{
	switch (protocol) {
	
	case 6 		:	return "TCP";
	case 17		:	return "UDP";
	case 1		:	return "ICMP";
	case 132	:	return "SCTP";	
	case 27		:	return "RDP";
	
	default		:	return "Unknown";
	}
}

class NS_IP_PORT
{
public :	
	IP_PORT				ip_port_;
	ino_t				inode_		{0};

	NS_IP_PORT() noexcept		= default;

	NS_IP_PORT(const GY_IP_ADDR & addr, uint16_t port, ino_t inode) noexcept : 
		ip_port_(addr, port), inode_(inode)
	{}

	NS_IP_PORT(IP_PORT ip_port, ino_t inode) noexcept
		: ip_port_(ip_port), inode_(inode)
	{}

	uint32_t get_hash(bool ignore_ip = false) const noexcept
	{
		alignas(8) uint8_t	buf1[sizeof(GY_IP_ADDR) + sizeof(uint32_t) + sizeof(ino_t)];
		int			len;

		if (ignore_ip == false) {
			len = ip_port_.ipaddr_.get_as_inaddr(buf1);
		}
		else {
			len = 0;	
		}		

		std::memcpy(buf1 + len, &ip_port_.port_, sizeof(ip_port_.port_));
		len += sizeof(ip_port_.port_);
		
		buf1[len++] = '\0';	// Align to 4 bytes
		buf1[len++] = '\0';
			
		std::memcpy(buf1 + len, &inode_, sizeof(inode_));
		len += sizeof(inode_);

		return jhash2((uint32_t *)buf1, len / sizeof(uint32_t), 0xceedfead);
	}	

	bool is_ephemeral_port() const noexcept
	{
		return ip_port_.is_ephemeral_port();
	}

	const char * print_string(STR_WR_BUF & strbuf) const noexcept
	{
		ip_port_.print_string(strbuf);

		strbuf.appendfmt(" NetNS inode %ld ", inode_);
		return strbuf.buffer();
	}	

	friend inline bool operator== (const NS_IP_PORT &lhs, const NS_IP_PORT &rhs) noexcept
	{
		return ((lhs.inode_ == rhs.inode_) && (lhs.ip_port_ == rhs.ip_port_));
	}

};
	
class PAIR_IP_PORT
{
public :	
	IP_PORT			cli_;
	IP_PORT			ser_;

	PAIR_IP_PORT() noexcept	= default;

	PAIR_IP_PORT(const IP_PORT & client, const IP_PORT & server) noexcept :
		cli_(client), ser_(server)
	{}	

	uint32_t get_hash() const noexcept
	{
		alignas(8) uint8_t	buf1[2 * sizeof(GY_IP_ADDR) + 2 * sizeof(uint32_t)];
		int			len;

		len = cli_.ipaddr_.get_as_inaddr(buf1);

		std::memcpy(buf1 + len, &cli_.port_, sizeof(cli_.port_));
		len += sizeof(cli_.port_);
		
		buf1[len++] = '\0';	// Align to 4 bytes
		buf1[len++] = '\0';
			
		len += ser_.ipaddr_.get_as_inaddr(buf1 + len);

		std::memcpy(buf1 + len, &ser_.port_, sizeof(ser_.port_));
		len += sizeof(ser_.port_);
		
		buf1[len++] = '\0';	// Align to 4 bytes
		buf1[len++] = '\0';

		return jhash2((uint32_t *)buf1, len / sizeof(uint32_t), 0xceedfead);
	}	

	const char * print_string(STR_WR_BUF & strbuf) const noexcept
	{
		strbuf.appendconst("Client ");
		cli_.print_string(strbuf);

		strbuf.appendconst(" - Server ");
		ser_.print_string(strbuf);

		strbuf.append(' ');
		return strbuf.buffer();
	}	

	friend inline bool operator== (const PAIR_IP_PORT &lhs, const PAIR_IP_PORT &rhs) noexcept
	{
		return ((lhs.cli_ == rhs.cli_) && (lhs.ser_ == rhs.ser_));
	}
};	

enum GY_IP_PROTO_E
{
	// Refer to https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
	
	IP_PROTO_IPv6_HOPOPT		= 0x00,		// IPv6 Hop-by-Hop Option
	IP_PROTO_ICMP			= 0x01,
	IP_PROTO_IGMP			= 0x02,
	IP_PROTO_IPIP			= 0x04,
	IP_PROTO_TCP			= 0x06,
	IP_PROTO_UDP			= 0x11,
	IP_PROTO_RDP			= 0x1B,
	IP_PROTO_IPv6_TUNNEL		= 0x29,
	IP_PROTO_IPv6_ROUTE		= 0x2B,		
	IP_PROTO_IPv6_FRAGMENT		= 0x2C,
	IP_PROTO_ICMP6			= 0x3A,
	IP_PROTO_IPv6_NO_NXT_HDR	= 0x3B,		// IPv6 No further headers
	IP_PROTO_IPv6_DST_OPTIONS	= 0x3C,		
};

struct GY_TCP_INFO 
{
	uint8_t				tcpi_state;
	uint8_t				tcpi_ca_state;
	uint8_t				tcpi_retransmits;
	uint8_t				tcpi_probes;
	uint8_t				tcpi_backoff;
	uint8_t				tcpi_options;
	uint8_t				tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;
	uint8_t				tcpi_delivery_rate_app_limited:1;

	uint32_t			tcpi_rto;
	uint32_t			tcpi_ato;
	uint32_t			tcpi_snd_mss;
	uint32_t			tcpi_rcv_mss;

	uint32_t			tcpi_unacked;
	uint32_t			tcpi_sacked;
	uint32_t			tcpi_lost;
	uint32_t			tcpi_retrans;
	uint32_t			tcpi_fackets;

	/* Times. */
	uint32_t			tcpi_last_data_sent;
	uint32_t			tcpi_last_ack_sent;     /* Not remembered, sorry. */
	uint32_t			tcpi_last_data_recv;
	uint32_t			tcpi_last_ack_recv;

	/* Metrics. */
	uint32_t			tcpi_pmtu;
	uint32_t			tcpi_rcv_ssthresh;
	uint32_t			tcpi_rtt;
	uint32_t			tcpi_rttvar;
	uint32_t			tcpi_snd_ssthresh;
	uint32_t			tcpi_snd_cwnd;
	uint32_t			tcpi_advmss;
	uint32_t			tcpi_reordering;

	uint32_t			tcpi_rcv_rtt;
	uint32_t			tcpi_rcv_space;

	uint32_t			tcpi_total_retrans;

	uint64_t			tcpi_pacing_rate;
	uint64_t			tcpi_max_pacing_rate;
	uint64_t			tcpi_bytes_acked;    /* RFC4898 tcpEStatsAppHCThruOctetsAcked */
	uint64_t			tcpi_bytes_received; /* RFC4898 tcpEStatsAppHCThruOctetsReceived */
	uint32_t			tcpi_segs_out;	     /* RFC4898 tcpEStatsPerfSegsOut */
	uint32_t			tcpi_segs_in;	     /* RFC4898 tcpEStatsPerfSegsIn */

	uint32_t			tcpi_notsent_bytes;
	uint32_t			tcpi_min_rtt;
	uint32_t			tcpi_data_segs_in;	/* RFC4898 tcpEStatsDataSegsIn */
	uint32_t			tcpi_data_segs_out;	/* RFC4898 tcpEStatsDataSegsOut */

	uint64_t   			tcpi_delivery_rate;

	uint64_t			tcpi_busy_time;      /* Time (usec) busy sending data */
	uint64_t			tcpi_rwnd_limited;   /* Time (usec) limited by receive window */
	uint64_t			tcpi_sndbuf_limited; /* Time (usec) limited by send buffer */
};

struct TCP_INFO_STATS
{
	gy_atomic <uint64_t>		curr_usec_clock		{0};
	uint64_t			bytes_acked		{0};
	uint64_t			bytes_received		{0};
	int32_t				rtt_usec		{0};
	uint32_t			rel_lastsnd_msec	{0};
	uint32_t			rel_lastrcv_msec	{0};
	uint32_t			busy_time_msec		{0};
	uint32_t			busy_recv_win_time_msec	{0};
	uint32_t			busy_send_buf_time_msec	{0};
	uint32_t			total_retrans		{0};

	TCP_INFO_STATS() noexcept 	= default;
		
	TCP_INFO_STATS & operator=(const TCP_INFO_STATS & other) noexcept
	{
		bytes_acked		= other.bytes_acked;
		bytes_received		= other.bytes_received;
		rtt_usec		= other.rtt_usec;
		rel_lastsnd_msec	= other.rel_lastsnd_msec;
		rel_lastrcv_msec	= other.rel_lastrcv_msec;
		busy_time_msec		= other.busy_time_msec;
		busy_recv_win_time_msec	= other.busy_recv_win_time_msec;
		busy_send_buf_time_msec	= other.busy_send_buf_time_msec;
		total_retrans		= other.total_retrans;

		curr_usec_clock.store(other.curr_usec_clock, std::memory_order_release);

		return *this;
	}

	void populate_tcp_info(GY_TCP_INFO *pinfo, uint64_t curr_clock = get_usec_clock()) noexcept
	{
		rtt_usec	 	= pinfo->tcpi_min_rtt;
		rel_lastsnd_msec 	= pinfo->tcpi_last_data_sent;
		rel_lastrcv_msec 	= pinfo->tcpi_last_data_recv;

		bytes_acked 		= pinfo->tcpi_bytes_acked;
		bytes_received 		= pinfo->tcpi_bytes_received;

		busy_time_msec 		= pinfo->tcpi_busy_time/1000;
		busy_recv_win_time_msec = pinfo->tcpi_rwnd_limited/1000;
		busy_send_buf_time_msec = pinfo->tcpi_sndbuf_limited/1000;

		total_retrans		= pinfo->tcpi_total_retrans;

		curr_usec_clock.store(curr_clock, std::memory_order_relaxed);
	}	

	char * print_tcpinfo_str(STR_WR_BUF & ss) const noexcept
	{
		ss.appendfmt("TCP Connection Properties : Bytes Acked %lu (%lu MB), Bytes Received %lu (%lu MB), ", 
			bytes_acked, GY_DOWN_MB(bytes_acked), bytes_received, GY_DOWN_MB(bytes_received));
		if (rtt_usec > 0) ss.appendfmt("rtt %.3f msec, ", rtt_usec/1000.0f); 
		if (rel_lastsnd_msec || rel_lastrcv_msec) ss.appendfmt("Last Send was before %u msec, Last receive was before %u msec, ", rel_lastsnd_msec, rel_lastrcv_msec);
		if (busy_time_msec) {
			ss.appendfmt("Sock Busy Time %u msec, ", busy_time_msec);
			if (busy_recv_win_time_msec) ss.appendfmt("Sock Busy due to receiver %u msec, ", busy_recv_win_time_msec);
			if (busy_send_buf_time_msec) ss.appendfmt("Sock Busy due to sender buffer %u msec, ", busy_send_buf_time_msec);
		}
		if (total_retrans) ss.appendfmt("# Retransmits %u, ", total_retrans);

		return ss.buffer();
	}	

	bool is_recent_activity(uint32_t msec) const noexcept
	{
		return ((rel_lastrcv_msec <= msec) || (rel_lastsnd_msec <= msec));
	}	
};	

class CLI_IP
{
public :
	RCU_HASH_CLASS_MEMBERS(GY_IP_ADDR, CLI_IP);
	
	GY_IP_ADDR		cli_ip_;	
	uint32_t		last_tsec_;

	CLI_IP(const GY_IP_ADDR & cli_ip, uint64_t tsec = get_sec_time()) noexcept
		: cli_ip_(cli_ip), last_tsec_((uint32_t)tsec)
	{}

	friend inline bool operator== (const CLI_IP & lhs, const GY_IP_ADDR & ip) noexcept
	{
		return (lhs.cli_ip_ == ip);
	}
};	


/*
 * GY_INET_SOCK indicates an individual socket data TCP/UDP whereas 
 * GY_TCP_CONN indicates the complete tuple
 */ 
class GY_INET_SOCK
{
public :	
	GY_IP_ADDR			ipaddr;
	uint32_t			netns;
	uint16_t			port;
	uint16_t			interface_num;		// For Link Local connections

	GY_INET_SOCK() noexcept : ipaddr(), netns(0), port(0), interface_num(0) {}
		
	GY_INET_SOCK(uint32_t ipv4_be, uint16_t port, uint32_t netns = 0, uint16_t interface_num = 0) noexcept : 
		ipaddr(ipv4_be), netns(netns), port(port), interface_num(interface_num)  {}

	GY_INET_SOCK(unsigned __int128 ipv6, uint16_t port, uint32_t netns = 0, uint16_t interface_num = 0) noexcept : 
		ipaddr(ipv6), netns(netns), port(port), interface_num(interface_num)  {}

	GY_INET_SOCK(GY_IP_ADDR &ip, uint16_t port, uint32_t netns = 0, uint16_t interface_num = 0) noexcept : 
		ipaddr(ip), netns(netns), port(port), interface_num(interface_num)  {}

	void set_sock_params(GY_IP_ADDR & ip, uint16_t portin, uint32_t netnsin, uint16_t interface_numin)
	{
		ipaddr = ip;
		this->netns = netnsin;
		this->port = portin;
		this->interface_num = interface_numin;
	}	

	friend bool operator== (const GY_INET_SOCK &lhs, const GY_INET_SOCK &rhs) noexcept
	{
		return ((lhs.port == rhs.port) && (lhs.ipaddr == rhs.ipaddr));	
	}

	int get_sock_info_str(char *pbuf, int buflen, const char * prefix) noexcept
	{
		char		buf1[16], bufip1[32];

		if (interface_num > 0 && ipaddr.is_link_local_addr() && ipaddr.is_ipv6_addr()) {
			snprintf(buf1, sizeof(buf1), "%%%u", interface_num);
		}
		else {
			*buf1 = '\0';
		}	
			
		return GY_SAFE_SNPRINTF(pbuf, buflen, "%s IP : %s%s,  %s TCP Port : %hu,  %s NetNS %u", 
			prefix, ipaddr.printaddr(bufip1, sizeof(bufip1)), buf1, prefix, port, prefix, netns);
	}	

};	


struct GY_TCP_CONN
{
	enum GY_TCP_CONN_FLAGS_E {
		GY_TCP_CONN_MISC		= 0,

		GY_TCP_CONN_SRC_NAT		= 1 << 0,
		GY_TCP_CONN_DST_NAT		= 1 << 1,
		GY_TCP_CONN_LOOPBACK		= 1 << 2,
		GY_TCP_CONN_LINK_LOCAL		= 1 << 3,
		
		GY_TCP_LOCAL_CLIENT_CONN	= 1 << 4,
		GY_TCP_LOCAL_SERVER_CONN	= 1 << 5,
	};

	GY_INET_SOCK			client_conn;
	GY_INET_SOCK			server_conn;

	GY_TCP_CONN_FLAGS_E		flags;
	GY_TCP_STATE_E			conn_state;

	friend bool operator== (const GY_TCP_CONN &lhs, const GY_TCP_CONN &rhs) noexcept
	{
		return ((lhs.client_conn == rhs.client_conn) && (lhs.server_conn == rhs.server_conn));	
	}

	int get_conn_info_str(char *pbuf, int buflen)
	{
		int			tlen;

		tlen = GY_SAFE_SNPRINTF(pbuf, buflen, "TCP Conn : ");

		tlen += client_conn.get_sock_info_str(pbuf + tlen, buflen - tlen, "Client");

		if (tlen < buflen + 8) {
			pbuf[tlen++] = '-';
			tlen += server_conn.get_sock_info_str(pbuf + tlen, buflen - tlen, "Server"); 
		}	

		if (tlen < buflen + 8) {
			tlen += GY_SAFE_SNPRINTF(pbuf + tlen, buflen - tlen, " - Conn State : %s %s%s%s%s%s",
                        get_tcp_state_string(conn_state),
                        (flags & GY_TCP_CONN_SRC_NAT) ? "SNAT active " : "",
                        (flags & GY_TCP_CONN_DST_NAT) ? "DNAT active " : "",
                        (flags & GY_TCP_CONN_LOOPBACK) ? "Loopback conn " : "",
                        (flags & GY_TCP_LOCAL_CLIENT_CONN) ? "Local Client conn " : "Remote Client conn ",
                        (flags & GY_TCP_LOCAL_SERVER_CONN) ? "Local Server conn " : "Remote Server conn ");

		}	

		return tlen;
	}	
};	

static uint32_t gy_get_sock_hash(const GY_INET_SOCK &sock) 
{
	alignas(4) uint8_t	buf1[32];
	int			len;

	len = sock.ipaddr.get_as_inaddr(buf1);

	memcpy(buf1 + len, &sock.port, sizeof(sock.port));
	len += sizeof(sock.port);
	
	buf1[len++] = '\0';	// Align to 4 bytes
	buf1[len++] = '\0';

	return jhash2((uint32_t *)buf1, len / sizeof(uint32_t), 0xceedfead);
}	 		

} // namespace gyeeta
