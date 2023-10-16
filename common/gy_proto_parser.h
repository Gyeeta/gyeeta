//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"
#include			"gy_inet_inc.h"
#include			"gy_misc.h"
#include			"gy_http_proto.h"
#include			"gy_http2_proto.h"
#include			"gy_postgres_proto.h"

#include 			"folly/container/F14Map.h"
#include			"folly/MPMCQueue.h"
#include			"folly/IndexedMemPool.h"

#include 			<variant>

namespace gyeeta {

static constexpr uint32_t			MAX_PARSE_API_LEN	{16 * 1024};	
static constexpr uint32_t			MAX_PARSE_CONC_SESS	{10 * 1024};	

enum PROTO_TYPES : uint16_t 
{
	PROTO_UNKNOWN				= 0,

	PROTO_HTTP1				= 1,
	PROTO_HTTP2				= 2,
	PROTO_POSTGRES				= 3,
	PROTO_MYSQL				= 4,
	PROTO_MONGO				= 5,
	PROTO_REDIS				= 6,

	PROTO_MAX
};	

enum API_CAP_SRC : uint8_t
{
	SRC_UNKNOWN				= 0,
	SRC_PCAP,
	SRC_UPROBE,
	SRC_KPROBE,
	SRC_UPROBE_SSL,
};	

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
	PROTO_TYPES				proto_			{PROTO_UNKNOWN};
};	

class SVC_INFO_CAP
{
public :
	using SvcSessMap 			= folly::F14NodeMap<IP_PORT, svc_session, IP_PORT::IP_PORT_HASH>;
	
	std::weak_ptr<TCP_LISTENER>		svcweak_;
	SvcSessMap				sessmap_;
	uint64_t 				glob_id_		{0};
	NS_IP_PORT				ns_ip_port_;
	char					comm_[TASK_COMM_LEN]	{};
	gy_atomic<bool>				is_reorder_		{false};
	bool					is_any_ip_		{false};
	bool					is_root_netns_		{false};

	SVC_INFO_CAP(const std::shared_ptr<TCP_LISTENER> & listenshr);

};

struct PARSE_PKT_HDR
{
	struct timeval				tv_			{};
	GY_IP_ADDR				cliip_;
	GY_IP_ADDR				serip_;
	
	uint32_t				poolidx_		{0};		
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
	bool					istcp_			{true};
	bool					isreorder_		{false};
	API_CAP_SRC				src_			{SRC_UNKNOWN};
};	

struct MSG_PKT_SVCCAP
{
	SVC_INFO_CAP				*psvc_			{nullptr};
	uint64_t 				glob_id_		{0};
	PARSE_PKT_HDR				hdr_;
};	

struct MSG_DEL_SVCCAP
{
	uint64_t 				glob_id_		{0};
};	

struct MSG_TIMER_SVCCAP
{
};	

using PARSE_MSG_BUF = std::variant<MSG_TIMER_SVCCAP, MSG_PKT_SVCCAP, MSG_DEL_SVCCAP>;

class SVC_NET_CAPTURE;

class API_PARSE_HDLR
{
public :
	static constexpr uint32_t		MAX_PARSE_POOL_PKT	{100'000};
	static constexpr uint32_t		MAX_REORDER_POOL_PKT	{16000};
	static constexpr uint32_t		MAX_PKT_DATA_LEN	{1600};

	using SvcInfoMap 			= folly::F14NodeMap<uint64_t, std::shared_ptr<SVC_INFO_CAP>, HASH_SAME_AS_KEY<uint64_t>>;
	using ParMsgPool			= folly::MPMCQueue<PARSE_MSG_BUF>;
	using ParserMemPool 			= folly::IndexedMemPool<UCHAR_BUF<MAX_PKT_DATA_LEN>, 8, 200, std::atomic, 
										folly::IndexedMemPoolTraitsLazyRecycle<UCHAR_BUF<MAX_PKT_DATA_LEN>>>;
	
	ParserMemPool				parsepool_		{MAX_PARSE_POOL_PKT};
	ParserMemPool				reorderpool_		{MAX_REORDER_POOL_PKT};
	ParMsgPool				msgpool_		{MAX_PARSE_POOL_PKT + 1000};
	SvcInfoMap				reordermap_;		// Only updated by parser thread

	SVC_NET_CAPTURE				&svcnet_;

	GY_MUTEX				svcmutex_;
	SvcInfoMap				svcinfomap_;		// Updated by Capture threads

	API_PARSE_HDLR(SVC_NET_CAPTURE & svcnet)
		: svcnet_(svcnet)
	{}	

	bool send_pkt_to_parser(MSG_PKT_SVCCAP & msghdr, const uint8_t *pdata, uint32_t len);

	void api_parse_rd_thr() noexcept;

	static bool is_valid_pool_idx(uint32_t idx, bool is_reorder) noexcept
	{
		return idx > 0 && idx <= ParserMemPool::maxIndexForCapacity(!is_reorder ? MAX_PARSE_POOL_PKT : MAX_REORDER_POOL_PKT);
	}	

};	


} // namespace gyeeta

