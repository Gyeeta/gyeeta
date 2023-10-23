//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"
#include			"gy_inet_inc.h"
#include			"gy_misc.h"
#include			"gy_http_proto.h"
#include			"gy_http2_proto.h"
#include			"gy_postgres_proto.h"
#include			"gy_stack_container.h"

#include 			"folly/container/F14Map.h"
#include			"folly/MPMCQueue.h"
#include			"folly/IndexedMemPool.h"

#include 			<variant>

namespace gyeeta {

static constexpr uint32_t			MAX_PARSE_API_LEN	{16 * 1024};	
static constexpr uint32_t			MAX_PARSE_CONC_SESS	{10 * 1024};	
static constexpr uint32_t			MAX_PARSE_POOL_PKT	{100'000};

enum PROTO_TYPES : uint16_t 
{
	PROTO_UNINIT				= 0,

	PROTO_HTTP1,
	PROTO_HTTP2,
	PROTO_POSTGRES,
	PROTO_MYSQL,
	PROTO_MONGO,
	PROTO_REDIS,

	PROTO_UNKNOWN
};	

static constexpr const char * proto_to_string(PROTO_TYPES proto) noexcept
{
	constexpr const char		*protostr[PROTO_UNKNOWN + 1] = {
		[PROTO_UNINIT] = "Uninitialized", [PROTO_HTTP1] = "HTTP1.x", [PROTO_HTTP2] = "HTTP2", 
		[PROTO_POSTGRES] = "Postgres", [PROTO_MYSQL] = "MySQL", [PROTO_MONGO] = "Mongo", 
		[PROTO_REDIS] = "Redis", 

		[PROTO_UNKNOWN] = "Unknown",
	};	

	if ((unsigned)proto < PROTO_UNKNOWN) {
		return protostr[proto] ? protostr[proto] : "";
	}	

	return "Invalid";
}	

enum API_CAP_SRC : uint8_t
{
	SRC_UNKNOWN				= 0,
	SRC_PCAP,
	SRC_UPROBE,
	SRC_KPROBE,
	SRC_UPROBE_SSL,

	SRC_MAX,
};	

static constexpr const char * capsrc_to_string(API_CAP_SRC src) noexcept
{
	constexpr const char		*capstr[SRC_MAX + 1] = {
		[SRC_UNKNOWN] = "Unknown", [SRC_PCAP] = "Network Capture", [SRC_UPROBE] = "User eBPF Probe",
		[SRC_KPROBE] = "Kernel eBPF Probe", [SRC_UPROBE_SSL] = "User SSL eBPF Probe",


		[SRC_MAX] = "Invalid",
	};	

	if ((unsigned)src < SRC_MAX) {
		return capstr[src] ? capstr[src] : "";
	}	

	return "Invalid";
}	


class TCP_LISTENER;

struct proto_base
{
	uint64_t				reqlen_			{0};
	uint64_t				reslen_			{0};
	uint64_t				reqnum_			{0};
	uint64_t				response_usec_		{0};

	struct timeval				tv_upd_			{};		// last data timestamp for processing
	struct timeval				tv_in_			{};		// last data inbound
	struct timeval				tv_connect_		{};
	struct timeval				tv_close_		{};
	struct timeval				tv_req_			{};		// time of first request packet
	struct timeval				tv_res_			{};		// time of first response packet

	IP_PORT					cli_ipport_;
	IP_PORT					ser_ipport_;

	uint64_t				reaction_usec_		{0};
	int					errorcode_		{0};

	bool					is_ssl_			{false};
};	

struct unknown_sess
{

};	

struct http1_sess : public proto_base
{
	std::unique_ptr<http1_sessinfo>		sessuniq_;
};	

struct http2_sess : public proto_base
{
	std::unique_ptr<http2_sessinfo>		sessuniq_;
};

struct postgres_sess : public proto_base
{
	std::unique_ptr<postgres_sessinfo>	sessuniq_;
};


struct svc_session
{
	using proto_sess = std::variant<unknown_sess, http1_sess, http2_sess, postgres_sess>;

	proto_sess				sess_;
	PROTO_TYPES				proto_			{PROTO_UNINIT};
};	

struct PARSE_PKT_HDR;

class SVC_PARSE_STATS
{
public :
	time_t					tlastpkt_		{0};

	uint64_t				npkts_			{0};
	uint64_t				nbytes_			{0};
	uint64_t				nreqpkts_		{0};
	uint64_t				nreqbytes_		{0};
	uint64_t				nresppkts_		{0};
	uint64_t				nrespbytes_		{0};

	uint64_t				srcpkts_[API_CAP_SRC::SRC_MAX]	{};

	void update_pkt_stats(const PARSE_PKT_HDR & hdr) noexcept;
};	

class SSL_SVC_CAP
{
public :
	// TODO
};	

class PROTO_DETECT
{
public :
	static constexpr size_t			MaxSessEntries		{64};
	static constexpr uint32_t		MAX_API_PROTO		{4};

	struct ApiStats
	{
		uint32_t			npkts_			{0};
		uint16_t			nreq_likely_		{0};
		uint16_t			nresp_likely_		{0};
		uint16_t			nconfirm_		{0};
		uint16_t			nmaybe_not_		{0};		
		API_CAP_SRC			src_			{SRC_UNKNOWN};
		PROTO_TYPES			proto_			{PROTO_UNINIT};
	};

	struct SessInfo
	{
		time_t				tstart_			{0};
		time_t				tfirstreq_		{0};
		uint32_t			nxt_cli_seq_		{0};
		uint32_t			nxt_ser_seq_		{0};
		uint32_t			npkts_data_		{0};
		ApiStats			apistats_[MAX_API_PROTO];
		uint16_t			ndrops_			{0};
		uint16_t			nssl_			{0};
		bool				syn_seen_		{false}; 
		
		SessInfo(time_t tstart, uint32_t nxt_cli_seq, uint32_t nxt_ser_seq, bool syn_seen) noexcept
			: tstart_(tstart), nxt_cli_seq_(nxt_cli_seq), nxt_ser_seq_(nxt_ser_seq), syn_seen_(syn_seen)
		{}	
	};	

	using SessMap				= INLINE_STACK_HASH_MAP<IP_PORT, SessInfo, MaxSessEntries * sizeof(SessInfo) * 3 + 128, IP_PORT::IP_PORT_HASH>;

	SessMap					smap_;
	time_t					tfirstreq_		{0};
	time_t					tfirstresp_		{0};
	uint32_t				nreqpkts_		{0};
	uint32_t				nresppkts_		{0};
	uint16_t				nconfirm_		{0};
	uint16_t				nconfirm_with_syn_	{0};
	uint16_t				nssl_confirm_		{0};
	uint8_t					nsynsess_		{0};
	uint8_t					nmidsess_		{0};
};	

class SVC_INFO_CAP
{
public :
	using SvcSessMap 			= folly::F14NodeMap<IP_PORT, svc_session, IP_PORT::IP_PORT_HASH>;
	
	SVC_PARSE_STATS				stats_;
	std::weak_ptr<TCP_LISTENER>		svcweak_;
	SvcSessMap				sessmap_;

	/*
	 * Lazy init fields as the constructor is called under RCU lock
	 */
	std::unique_ptr<PROTO_DETECT>		protodetect_;
	std::unique_ptr<SSL_SVC_CAP>		sslcap_;

	uint64_t 				glob_id_		{0};
	NS_IP_PORT				ns_ip_port_;
	char					comm_[TASK_COMM_LEN]	{};
	gy_atomic<uint64_t>			stop_parser_nsec_	{0};			// Set by Capture Schedule Thread only if Pool is blocked

	PROTO_TYPES				proto_			{PROTO_UNINIT};
	gy_atomic<bool>				is_reorder_		{false};
	
	bool					is_any_ip_		{false};
	bool					is_root_netns_		{false};

	// Previously set listener info
	PROTO_TYPES				orig_proto_		{PROTO_UNINIT};
	bool					orig_ssl_		{false};		

	SVC_INFO_CAP(const std::shared_ptr<TCP_LISTENER> & listenshr);

	void lazy_init() noexcept;

	bool detect_svc_req(PARSE_PKT_HDR & hdr, uint8_t *pdata);
	bool detect_svc_resp(PARSE_PKT_HDR & hdr, uint8_t *pdata);
};

struct PARSE_PKT_HDR
{
	struct timeval				tv_			{};
	GY_IP_ADDR				cliip_;
	GY_IP_ADDR				serip_;
	
	uint32_t				datalen_		{0};
	uint32_t				wirelen_		{0};
	uint32_t				nxt_cli_seq_		{0};
	uint32_t				start_cli_seq_		{0};
	uint32_t				nxt_ser_seq_		{0};
	uint32_t				start_ser_seq_		{0};
	uint32_t 				pid_			{0};

	uint16_t				cliport_		{0};
	uint16_t				serport_		{0};
	DirPacket				dir_			{DirPacket::DIR_UNKNOWN};
	uint8_t					tcpflags_		{0};
	API_CAP_SRC				src_			{SRC_UNKNOWN};

	// Data bytes follow

	uint32_t get_trunc_bytes() const noexcept
	{
		return wirelen_ - datalen_;
	}	
};	

static constexpr uint32_t			MAX_PARSE_TOTAL_LEN	{1800};
static constexpr uint32_t			MAX_PARSE_DATA_LEN	{MAX_PARSE_TOTAL_LEN - sizeof(PARSE_PKT_HDR)};

using ParserMemPool = folly::IndexedMemPool<UCHAR_BUF<MAX_PARSE_TOTAL_LEN>, 8, 200, std::atomic, folly::IndexedMemPoolTraitsLazyRecycle<UCHAR_BUF<MAX_PARSE_TOTAL_LEN>>>;

struct MSG_PKT_SVCCAP
{
	SVC_INFO_CAP				*psvc_			{nullptr};
	uint64_t 				glob_id_		{0};
	ParserMemPool::UniquePtr		pooluniq_;

	MSG_PKT_SVCCAP(SVC_INFO_CAP *psvc, uint64_t glob_id, ParserMemPool::UniquePtr && pooluniq) noexcept
		: psvc_(psvc), glob_id_(glob_id), pooluniq_(std::move(pooluniq))
	{}	
};	


struct MSG_ADD_SVCCAP
{
	std::shared_ptr<SVC_INFO_CAP>		svcinfocap_;
	uint64_t 				glob_id_		{0};

	MSG_ADD_SVCCAP() noexcept		= default;

	MSG_ADD_SVCCAP(std::shared_ptr<SVC_INFO_CAP> svcinfocap, uint64_t glob_id) noexcept
		: svcinfocap_(std::move(svcinfocap)), glob_id_(glob_id)
	{}	
};	

struct MSG_DEL_SVCCAP
{
	uint64_t 				glob_id_		{0};

	MSG_DEL_SVCCAP(uint64_t glob_id = 0) noexcept
		: glob_id_(glob_id)
	{}	
};	

struct MSG_TIMER_SVCCAP
{
	uint64_t				cusec_			{get_usec_clock()};
};	


class SVC_NET_CAPTURE;

using PARSE_MSG_BUF	 			= std::variant<MSG_ADD_SVCCAP, MSG_PKT_SVCCAP, MSG_DEL_SVCCAP, MSG_TIMER_SVCCAP>;

class API_PARSE_HDLR
{
public :
	static constexpr uint32_t		MAX_REORDER_PKTS	{20000};

	using SvcInfoMap 			= folly::F14NodeMap<uint64_t, std::shared_ptr<SVC_INFO_CAP>, HASH_SAME_AS_KEY<uint64_t>>;
	using ParMsgPool			= folly::MPMCQueue<PARSE_MSG_BUF>;
	using StatsStrMap			= std::unordered_map<const char *, int64_t, GY_JHASHER<const char *>>;

	ParserMemPool				parsepool_		{MAX_PARSE_POOL_PKT};
	ParMsgPool				msgpool_		{MAX_PARSE_POOL_PKT + 1000};
	
	// The following section is only updated by parser thread
	SvcInfoMap				reordermap_;		
	uint32_t				nreorderpkts_		{0};
	StatsStrMap				statsmap_;		

	SVC_NET_CAPTURE				&svcnet_;

	GY_MUTEX				svcmutex_;
	SvcInfoMap				svcinfomap_;		// Updated by Capture threads

	API_PARSE_HDLR(SVC_NET_CAPTURE & svcnet)
		: svcnet_(svcnet)
	{}	

	bool send_pkt_to_parser(SVC_INFO_CAP *psvccap, uint64_t glob_id, const PARSE_PKT_HDR & msghdr, const uint8_t *pdata, const uint32_t len);

	void api_parse_rd_thr() noexcept;

	static bool is_valid_pool_idx(uint32_t idx, bool is_reorder) noexcept
	{
		return idx > 0 && idx <= ParserMemPool::maxIndexForCapacity(MAX_PARSE_POOL_PKT);
	}	

	static bool reorder_possible(API_CAP_SRC src) noexcept
	{
		return src == SRC_PCAP;
	}	

private :
	bool handle_proto_pkt(MSG_PKT_SVCCAP & msg) noexcept;
	bool handle_svc_add(MSG_ADD_SVCCAP & msg) noexcept;
	bool handle_svc_del(MSG_DEL_SVCCAP & msg) noexcept;
	bool handle_parse_timer(MSG_TIMER_SVCCAP & msg) noexcept;
	bool handle_parse_no_msg() noexcept;

};	


} // namespace gyeeta

