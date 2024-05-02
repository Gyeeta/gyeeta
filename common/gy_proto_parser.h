//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"
#include			"gy_inet_inc.h"
#include			"gy_misc.h"
#include			"gy_ssl_cap_common.h"
#include			"gy_stack_container.h"
#include			"gy_pool_alloc.h"
#include			"gy_proto_common.h"

#include 			"folly/container/F14Map.h"
#include			"folly/MPMCQueue.h"
#include			"folly/IndexedMemPool.h"
#include 			"folly/IntrusiveList.h"

#include 			<variant>

namespace gyeeta {

static constexpr uint32_t			MAX_PARSE_CONC_SESS	{16 * 1024};	
static constexpr uint32_t			MAX_PARSE_POOL_PKT	{100'000};
static constexpr uint32_t			MAX_REORDER_PKTS	{20000};

/*
 * Currently single threaded parser (Requires changes in gy_svc_net_capture.h if > 1)
 */
static constexpr size_t				MAX_API_PARSERS		{1};			


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

static bool ssl_multiplexed_proto(PROTO_TYPES proto) noexcept
{
	switch (proto) {
	
	case PROTO_POSTGRES :
	case PROTO_MYSQL :
	case PROTO_MONGO :
	case PROTO_REDIS :
		return true;

	default :
		return false;
	}	
}

enum DROP_TYPES : uint8_t 
{
	DT_NO_DROP 		= 0,
	DT_RETRANSMIT		= 1 << 0,
	DT_DROP_SEEN		= 1 << 1,
	DT_DROP_NEW_SESS	= 1 << 2,		// Very Large drop, maybe a new sess
};


// Returns drop status for both dirs (current and other)
static std::pair<DROP_TYPES, DROP_TYPES> is_tcp_drop(uint32_t exp_seq, uint32_t act_seq, uint32_t exp_ack, uint32_t act_ack, bool is_syn = false, bool is_finack = false) noexcept
{
	int			diff = exp_seq - act_seq, diffack = exp_ack - act_ack;

	if (diff == 0) {
		if (diffack >= 0) {
			return {DT_NO_DROP, diffack == 0 ? DT_NO_DROP : DT_RETRANSMIT};
		}

		if (is_finack && diffack == -1) {
			return {DT_NO_DROP, DT_NO_DROP};
		}	

		return {DT_NO_DROP, DT_DROP_SEEN};
	}

	if (diff > 0) {	
		if (diff < 1024 * 1024) {
			return {DT_RETRANSMIT, DT_RETRANSMIT};
		}
		else {
			if (is_syn || abs(diffack) > 1024 * 1024) {
				return {DT_DROP_NEW_SESS, DT_DROP_NEW_SESS};
			}
			else {
				return {DT_RETRANSMIT, DT_RETRANSMIT};
			}
		}
	}

	if ((diff < -100 * 1024 * 1024) || ((diff < -1024 * 1024) && (is_syn || abs(diffack) > 1024 * 1024))) {
		return {DT_DROP_NEW_SESS, DT_DROP_NEW_SESS};
	}

	if (diffack >= 0) {
		return {DT_DROP_SEEN, diffack == 0 ? DT_NO_DROP : DT_RETRANSMIT};
	}

	return {DT_DROP_SEEN, DT_DROP_SEEN};
}	

// Returns {drop_cli_bytes, drop_ser_bytes}
static std::pair<uint32_t, uint32_t> tcp_drop_bytes(uint32_t cli_exp_seq, uint32_t cli_act_seq, uint32_t ser_exp_seq, uint32_t ser_act_seq, DROP_TYPES clitype, DROP_TYPES sertype) noexcept
{
	uint32_t			dbytescli = 0, dbytesser = 0;

	if ((clitype == DT_NO_DROP || clitype == DT_RETRANSMIT) && (sertype == DT_NO_DROP || sertype == DT_RETRANSMIT)) {
		return {0, 0};
	}	
	else if ((clitype == DT_DROP_NEW_SESS) && (sertype == DT_DROP_NEW_SESS)) {
		return {1024, 1024};	// We do not know the extent of the drop. Set a small drop byte count
	}	

	if (clitype == DT_DROP_SEEN) {
		dbytescli = abs(int(cli_act_seq - cli_exp_seq));
	}	

	if (sertype == DT_DROP_SEEN) {
		dbytesser = abs(int(ser_act_seq - ser_exp_seq));
	}	

	return {dbytescli, dbytesser};
}	



class TCP_LISTENER;

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
	uint32_t 				netns_			{0};
	
	uint16_t				cliport_		{0};
	uint16_t				serport_		{0};
	uint8_t					tcpflags_		{0};
	DirPacket				dir_			{DirPacket::DirUnknown};
	API_CAP_SRC				src_			{SRC_UNKNOWN};

	// Data bytes follow

	uint32_t get_trunc_bytes() const noexcept
	{
		return wirelen_ - datalen_;
	}	
};	

static constexpr uint32_t			MAX_PARSE_TOTAL_LEN	{1800};
static constexpr uint32_t			MAX_PARSE_FRAG_LEN	{MAX_PARSE_TOTAL_LEN - sizeof(PARSE_PKT_HDR)};

using ParserMemPool = folly::IndexedMemPool<UCHAR_BUF<MAX_PARSE_TOTAL_LEN>, 8, 200, std::atomic, folly::IndexedMemPoolTraitsLazyRecycle<UCHAR_BUF<MAX_PARSE_TOTAL_LEN>>>;


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
		uint8_t				nis_not_		{0};
		API_CAP_SRC			src_			{SRC_UNKNOWN};
		PROTO_TYPES			proto_			{PROTO_UNINIT};
	};

	struct SessInfo
	{
		time_t				tstart_			{0};
		time_t				tfirstreq_		{0};
		time_t				tfirstresp_		{0};
		time_t				tlastpkt_		{0};
		PROTO_DETECT			& detect_;
		uint32_t			nxt_cli_seq_		{0};
		uint32_t			nxt_ser_seq_		{0};
		uint32_t			npkts_data_		{0};
		ApiStats			apistat_;
		uint16_t			ndrops_			{0};

		bool				syn_seen_		{false}; 
		bool				init_skipped_		{false}; 
		uint8_t				skip_to_req_after_resp_	{0};
		bool				resp_seen_		{false};
		bool				is_ssl_			{false};
		bool				ssl_init_req_		{false};
		bool				ssl_init_resp_		{false};
		uint8_t				ssl_nreq_		{0};
		uint8_t				ssl_nresp_		{0};
		DirPacket			lastdir_		{DirPacket::DirUnknown};
		
		SessInfo(time_t tstart, PROTO_DETECT & detect, uint32_t nxt_cli_seq, uint32_t nxt_ser_seq, bool syn_seen) noexcept
			: tstart_(tstart), tlastpkt_(tstart), detect_(detect), nxt_cli_seq_(nxt_cli_seq), nxt_ser_seq_(nxt_ser_seq), syn_seen_(syn_seen)
		{
			if (syn_seen_) {
				detect_.nsynsess_++;
			}	
			else {
				detect_.nmidsess_++;
			}	
		}	

		~SessInfo() noexcept
		{
			if (syn_seen_) {
				detect_.nsynsess_--;
			}	
			else {
				detect_.nmidsess_--;
			}	

		}	
	};	

	using SessMap				= INLINE_STACK_HASH_MAP<IP_PORT, SessInfo, MaxSessEntries * sizeof(SessInfo) * 3 + 128, IP_PORT::IP_PORT_HASH>;

	SessMap					smap_;
	time_t					tfirstreq_		{0};
	time_t					tfirstresp_		{0};
	time_t					tlastchk_		{0};
	time_t					tlast_inactive_sec_	{0};
	ApiStats				apistats_[MAX_API_PROTO];
	uint16_t				nconfirm_		{0};
	uint16_t				nconfirm_with_syn_	{0};
	uint16_t				nssl_confirm_		{0};
	uint16_t				nssl_confirm_syn_	{0};
	uint8_t					nsynsess_		{0};
	uint8_t					nmidsess_		{0};

	void cleanup_inactive_sess(time_t tcur) noexcept;
};	

struct REORDER_PKT_HDR
{
	ParserMemPool::UniquePtr		pooluniq_;
	uint64_t				tpktusec_		{0};
	uint32_t				datalen_		{0};
	uint32_t				start_pkt_seq_		{0};
	uint32_t				ack_seq_		{0};
	DirPacket				dir_			{DirPacket::DirUnknown};
	uint8_t					parseridx_		{0};
	folly::SafeIntrusiveListHook		listhook_;

	static POOL_ALLOC			*greorderpools_[MAX_API_PARSERS];		

	REORDER_PKT_HDR(ParserMemPool::UniquePtr && pooluniq, const PARSE_PKT_HDR & hdr, uint8_t parseridx);

	~REORDER_PKT_HDR() noexcept;

	static void destroy(REORDER_PKT_HDR *pdata) noexcept
	{
		delete pdata;
	}	

	static void operator delete(void *ptr, size_t sz);
};	

struct SVC_SESSION;

struct REORDER_INFO
{
	using ReorderList = folly::CountedIntrusiveList<REORDER_PKT_HDR, &REORDER_PKT_HDR::listhook_>;

	ReorderList				reorder_list_;

	uint64_t				tfirstusec_		{0};

	uint64_t				nreorders_		{0};
	uint64_t				nreorder_fail_		{0};

	uint32_t				exp_cli_seq_start_	{0};		// Set to 0 for no drops
	uint32_t				seen_cli_seq_		{0};

	uint32_t				exp_ser_seq_start_	{0};		// Set to 0 for no drops
	uint32_t				seen_ser_seq_		{0};

	uint32_t				ninbound_		{0};
	uint32_t				noutbound_		{0};

	static constexpr size_t			MAX_SESS_REORDER_PKTS	{2048};

	REORDER_INFO() 				= default;

	~REORDER_INFO() noexcept;

	static_assert(ReorderList::constant_time_size == true, "Require constant time size() operation");

	bool is_active() const noexcept
	{
		return !reorder_list_.empty();
	}	

	bool head_timed_out(uint64_t tcurrusec) const noexcept
	{
		return tcurrusec >= tfirstusec_ + GY_USEC_PER_SEC && tfirstusec_ > 0;
	}	

	void set_head_info(SVC_SESSION & sess, PARSE_PKT_HDR & hdr);
};	

struct COMMON_PROTO
{
	uint64_t				tot_reqlen_		{0};		// Total Req Inbound Bytes
	uint64_t				tot_reslen_		{0};		// Total Req Outbound Bytes

	uint64_t				tlastpkt_usec_		{0};		// last seen pkt time
	uint64_t				tconnect_usec_		{0};
	uint64_t				tclose_usec_		{0};

	IP_PORT					cli_ipport_;
	IP_PORT					ser_ipport_;
	uint64_t				glob_id_		{0};

	uint32_t				nxt_cli_seq_		{0};
	uint32_t				nxt_ser_seq_		{0};

	uint32_t 				pid_			{0};
	uint32_t 				netns_			{0};
	uint32_t				curr_req_drop_bytes_	{0};
	uint32_t				curr_resp_drop_bytes_	{0};

	DirPacket				currdir_		{DirPacket::DirUnknown};
	DirPacket				lastdir_		{DirPacket::DirUnknown};
	DROP_TYPES				clidroptype_		{DT_NO_DROP};
	DROP_TYPES				serdroptype_		{DT_NO_DROP};

	bool					is_ssl_			{false};
	bool					syn_seen_		{false}; 

	COMMON_PROTO() noexcept			= default;

	COMMON_PROTO(uint64_t glob_id, PARSE_PKT_HDR & hdr) noexcept;

	void set_src_chg(PARSE_PKT_HDR & hdr) noexcept;

	void upd_stats(PARSE_PKT_HDR & hdr) noexcept;
};	

class API_PARSE_HDLR;
class SVC_NET_CAPTURE;
class SVC_INFO_CAP;

class HTTP1_PROTO;
class HTTP1_SESSINFO;

class HTTP2_PROTO;
class HTTP2_SESSINFO;

class POSTGRES_PROTO;
class POSTGRES_SESSINFO;

struct SVC_SESSION
{
	using proto_sess = std::variant<std::monostate, HTTP1_SESSINFO *, HTTP2_SESSINFO *, POSTGRES_SESSINFO *>;

	proto_sess				pvarproto_;
	void					*pdataproto_		{nullptr};
	COMMON_PROTO				common_;				
	SVC_INFO_CAP				*psvc_			{nullptr};
	PROTO_TYPES				proto_			{PROTO_UNINIT};
	REORDER_INFO				reorder_;
	uint32_t				to_del_			{0};
	bool					isrdrmap_		{false};

	SVC_SESSION() 				= default;

	SVC_SESSION(SVC_INFO_CAP & svc, PARSE_PKT_HDR & hdr);

	~SVC_SESSION() noexcept;

	void set_reorder_end();

	void set_to_delete(bool to_del = true) noexcept
	{
		to_del_ = (to_del ? 0xABCDABCD : 0);
	}	

	bool to_delete() const noexcept
	{
		return to_del_ == 0xABCDABCD;
	}	

	bool reorder_active() const noexcept
	{
		return reorder_.is_active();
	}	

	bool is_req_pkt_drop() const noexcept
	{
		return common_.clidroptype_ == DT_DROP_SEEN;
	}

	bool is_resp_pkt_drop() const noexcept
	{
		return common_.serdroptype_ == DT_DROP_SEEN;
	}

	size_t get_req_drop_bytes() const noexcept
	{
		return common_.curr_req_drop_bytes_;
	}	

	size_t get_resp_drop_bytes() const noexcept
	{
		return common_.curr_resp_drop_bytes_;
	}	

	bool is_pkt_drop() const noexcept
	{
		return (is_req_pkt_drop() || is_resp_pkt_drop());
	}

	void set_new_proto(PROTO_TYPES newproto) noexcept
	{
		proto_ = newproto;
	}	
};	

struct SVC_PARSE_STATS
{
	time_t					tlastpkt_		{0};

	uint64_t				npkts_			{0};
	uint64_t				nbytes_			{0};
	uint64_t				nreqpkts_		{0};
	uint64_t				nreqbytes_		{0};
	uint64_t				nresppkts_		{0};
	uint64_t				nrespbytes_		{0};
	
	uint64_t				nrequests_		{0};
	uint64_t				ncli_errors_		{0};
	uint64_t				nser_errors_		{0};

	uint64_t				ndroppkts_		{0};
	uint64_t				ndropbytes_		{0};
	uint64_t				ndropbytesin_		{0};
	uint64_t				ndropbytesout_		{0};
	uint64_t				nrdrpkts_		{0};
	uint64_t				nrdrbytes_		{0};
	uint64_t				nrdr_sess_max_		{0};
	uint64_t				nrdr_timeout_		{0};
	uint64_t				nrdr_alloc_fails_	{0};

	uint64_t				nsessions_new_		{0};
	uint64_t				nsessions_del_		{0};
	uint64_t				nsess_drop_new_		{0};
	uint64_t				nskip_conc_sess_	{0};

	uint64_t				nsrc_chg_		{0};
	uint64_t				srcpkts_[API_CAP_SRC::SRC_MAX]	{};

	bool update_pkt_stats(const PARSE_PKT_HDR & hdr) noexcept;
	void print_stats(STR_WR_BUF & strbuf, uint64_t tcurrusec, uint64_t tlastusec) const noexcept;

	void operator -= (const SVC_PARSE_STATS & other) noexcept;
};	

class SVC_INFO_CAP : public std::enable_shared_from_this<SVC_INFO_CAP>
{
public :
	using SvcSessMap 			= folly::F14NodeMap<IP_PORT, SVC_SESSION, IP_PORT::IP_PORT_HASH>;
	using SessReorderMap 			= folly::F14ValueMap<SVC_SESSION *, uint64_t>;
	using SessMapIt				= typename SvcSessMap::iterator;
	
	API_PARSE_HDLR				& apihdlr_;

	SVC_PARSE_STATS				stats_;
	std::weak_ptr<TCP_LISTENER>		svcweak_;
	SvcSessMap				sessmap_;
	SessReorderMap				sessrdrmap_;
	SVC_PARSE_STATS				laststats_;
	std::unique_ptr<PROTO_DETECT>		protodetect_;

	uint64_t 				glob_id_		{0};
	NS_IP_PORT				ns_ip_port_;
	char					comm_[TASK_COMM_LEN]	{};
	uint64_t				tstartusec_		{get_usec_time()};
	gy_atomic<uint64_t>			stopped_parser_tusec_	{0};

	std::unique_ptr<char []>		api_cap_err_;
	PROTO_TYPES				proto_			{PROTO_UNINIT};
	gy_atomic<SSL_REQ_E>			ssl_req_		{SSL_REQ_E::SSL_NO_REQ};
	
	bool					is_any_ip_		{false};
	bool					is_root_netns_		{false};
	SSL_SVC_E				svc_ssl_		{SSL_SVC_E::SSL_UNINIT};

	// Previously set listener info
	PROTO_TYPES				orig_proto_		{PROTO_UNINIT};
	bool					orig_ssl_		{false};		

	SVC_INFO_CAP(const std::shared_ptr<TCP_LISTENER> & listenshr, API_PARSE_HDLR & apihdlr);

	~SVC_INFO_CAP() noexcept;

	void destroy(uint64_t tusec) noexcept;

	void svc_init_blocking(SVC_NET_CAPTURE & svcnet) noexcept;

	void schedule_ssl_probe();

	void schedule_ssl_stop() noexcept;

	void schedule_stop_capture() noexcept;

	bool detect_svc_req_resp(PARSE_PKT_HDR & hdr, uint8_t *pdata);

	void analyze_detect_status();

	bool parse_pkt(ParserMemPool::UniquePtr & puniq, PARSE_PKT_HDR & hdr, uint8_t *pdata);

	bool do_proto_parse(SVC_SESSION & sess, PARSE_PKT_HDR & hdr, uint8_t *pdata) noexcept;

	bool proto_handle_ssl_chg(SVC_SESSION & sess, PARSE_PKT_HDR & hdr, uint8_t *pdata);

	bool handle_reorder(SVC_SESSION & sess, ParserMemPool::UniquePtr & puniq, PARSE_PKT_HDR & hdr, uint8_t *pdata);

	bool set_pkt_drops(SVC_SESSION & sess, PARSE_PKT_HDR & hdr);

	bool chk_drops_and_parse(SVC_SESSION & sess, ParserMemPool::UniquePtr & puniq, PARSE_PKT_HDR & hdr, uint8_t *pdata, bool ign_reorder);
	
	REORDER_PKT_HDR * alloc_reorder(SVC_SESSION & sess, ParserMemPool::UniquePtr & puniq, PARSE_PKT_HDR & hdr, uint8_t *pdata);
	
	bool start_reorder(SVC_SESSION & sess, ParserMemPool::UniquePtr & puniq, PARSE_PKT_HDR & hdr, uint8_t *pdata);

	bool send_reorder_to_parser(SVC_SESSION & sess, uint64_t tcurrusec, bool clear_all);
	
	bool add_to_reorder_list(SVC_SESSION & sess, REORDER_PKT_HDR *pnewpkt, ParserMemPool::UniquePtr & puniq, PARSE_PKT_HDR & hdr, uint8_t *pdata);

	void print_stats(STR_WR_BUF & strbuf, uint64_t tcurrusec, uint64_t tlastusec) noexcept;
};

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
	uint64_t				tusec_			{get_usec_time()};

	MSG_DEL_SVCCAP(uint64_t glob_id = 0) noexcept
		: glob_id_(glob_id)
	{}	
};	

struct MSG_TIMER_SVCCAP
{
	uint64_t				tusec_			{get_usec_time()};
};	


struct MSG_SVC_SSL_CAP
{
	uint64_t 				glob_id_		{0};
	std::unique_ptr<char []>		msguniq_;
	SSL_REQ_E				req_			{SSL_REQ_E::SSL_NO_REQ};

	MSG_SVC_SSL_CAP(uint64_t glob_id, SSL_REQ_E req, const char *msg = nullptr)
		: glob_id_(glob_id), req_(req)
	{
		if (msg && *msg) {
			size_t			nbytes = strlen(msg) + 1;

			msguniq_.reset(new char [nbytes]);
			
			std::memcpy(msguniq_.get(), msg, nbytes);
		}
	}
};

// Do not change the order here 
using PARSE_MSG_BUF = std::variant<MSG_ADD_SVCCAP, MSG_PKT_SVCCAP, MSG_DEL_SVCCAP, MSG_TIMER_SVCCAP, MSG_SVC_SSL_CAP>;

struct API_PARSER_STATS
{
	uint64_t				nsvcadd_		{0};
	uint64_t				nsvcdel_		{0};
	uint64_t				nsvcssl_on_		{0};
	uint64_t				nsvcssl_fail_		{0};
	uint64_t				ninvalid_pkt_		{0};
	uint64_t				ninvalid_msg_		{0};
	uint64_t				nrdr_alloc_fails_	{0};
	uint64_t				nxfer_pool_fail_	{0};
	uint64_t				nsend_req_fail_		{0};
	uint64_t				nsend_bytes_		{0};

	alignas(64) gy_atomic<uint64_t>		nskip_pool_		{0};

	void operator -= (const API_PARSER_STATS & other) noexcept;
	void print_stats(STR_WR_BUF & strbuf, uint64_t tcurrusec, uint64_t tlastusec) const noexcept;
};	

class API_PARSE_HDLR
{
public :
	using ParMsgPool			= folly::MPMCQueue<PARSE_MSG_BUF>;
	using TranMsgPool			= folly::MPMCQueue<DATA_BUFFER_ELEM>;
	using SvcInfoIdMap 			= folly::F14NodeMap<uint64_t, std::shared_ptr<SVC_INFO_CAP>, HASH_SAME_AS_KEY<uint64_t>>;
	using SvcInfoIdPtrMap 			= folly::F14NodeMap<uint64_t, SVC_INFO_CAP *, HASH_SAME_AS_KEY<uint64_t>>;
	using SvcInfoPortMap 			= folly::F14NodeMap<NS_IP_PORT, std::shared_ptr<SVC_INFO_CAP>, NS_IP_PORT::ANY_IP, NS_IP_PORT::ANY_IP>;

	ParserMemPool				parsepool_		{MAX_PARSE_POOL_PKT};
	ParMsgPool				msgpool_		{MAX_PARSE_POOL_PKT + 1000};
	POOL_ALLOC				reorderpool_		{sizeof(REORDER_PKT_HDR), MAX_REORDER_PKTS};	// Only from parser thread
	DATA_BUFFER				reqbuffer_;
	API_PARSER_STATS			stats_;
	API_PARSER_STATS			laststats_;

	uint64_t				tstartusec_		{get_usec_time()};
	uint64_t				tlast_rdrchk_usec_	{tstartusec_};
	uint64_t				tlast_svc_chk_usec_	{tstartusec_};
	uint64_t				tlast_print_usec_	{tstartusec_};

	std::unique_ptr<HTTP1_PROTO>		phttp1_;
	std::unique_ptr<HTTP2_PROTO>		phttp2_;
	std::unique_ptr<POSTGRES_PROTO>		ppostgres_;

	SVC_NET_CAPTURE				& svcnet_;
	SSL_CAP_SVC				sslcap_;
	uint32_t				api_max_len_		{0};
	std::atomic<bool>			allow_ssl_probe_	{SSL_CAP_SVC::ssl_uprobes_allowed()};
	uint8_t					parseridx_		{0};
	
protected :

	// The following section is only accessed by parser thread
	SvcInfoIdMap				svcinfomap_;
	SvcInfoIdPtrMap				reordermap_;		
	SvcInfoPortMap				nsportmap_;
	uint32_t				nreorderpkts_		{0};

	friend class				SVC_SESSION;
	friend class				SVC_INFO_CAP;

public :

	static std::optional<TranMsgPool>	gtranpool_;
	static std::optional<GY_THREAD>		gtran_thr_;
	
	static constexpr uint64_t		REORDER_CHK_SEC		{2};
	static constexpr uint64_t		SVC_CHK_SEC		{30};
	static constexpr uint64_t		PRINT_STATS_SEC		{60};

	API_PARSE_HDLR(SVC_NET_CAPTURE & svcnet, uint8_t parseridx, uint32_t api_max_len);

	~API_PARSE_HDLR() noexcept;

	bool send_pkt_to_parser(const PARSE_PKT_HDR & msghdr, const uint8_t *pdata, const uint32_t len, SVC_INFO_CAP *psvccap = nullptr, uint64_t glob_id = 0ul);

	void api_parse_rd_thr() noexcept;

	static int api_xfer_thread(void *) noexcept;

	MAKE_PTHREAD_FUNC_WRAPPER(api_xfer_thread);

	uint8_t * get_xfer_pool_buf();

	bool set_xfer_buf_sz(size_t elemsz, bool force_flush = false);

	static bool is_valid_pool_idx(uint32_t idx, bool is_reorder) noexcept
	{
		return idx > 0 && idx <= ParserMemPool::maxIndexForCapacity(MAX_PARSE_POOL_PKT);
	}	

	static bool reorder_possible(API_CAP_SRC src) noexcept
	{
		return src == SRC_PCAP;
	}	

	static bool xfer_pool_allowed() noexcept
	{
		return gtranpool_->sizeGuess() < MAX_TRAN_STR_ELEM * 0.8;
	};	

private :
	bool handle_proto_pkt(MSG_PKT_SVCCAP & msg) noexcept;
	bool handle_svc_add(MSG_ADD_SVCCAP & msg) noexcept;
	bool handle_svc_del(MSG_DEL_SVCCAP & msg, SvcInfoIdMap::iterator *pit = nullptr) noexcept;
	bool handle_parse_timer(MSG_TIMER_SVCCAP & msg) noexcept;
	bool handle_ssl_active(MSG_SVC_SSL_CAP & msg) noexcept;
	bool handle_ssl_rejected(MSG_SVC_SSL_CAP & msg) noexcept;
	bool handle_parse_no_msg() noexcept;

	void chk_svc_reorders();
	void chk_svc_info();
	void print_stats() noexcept;
};	


} // namespace gyeeta

