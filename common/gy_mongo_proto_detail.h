//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_mongo_proto.h"
#include			"gy_proto_common.h"

namespace gyeeta {

static constexpr uint32_t		MG_MAX_CURSOR_LEN		{127};
static constexpr uint32_t		MG_MAX_SESS_CURSORS		{128};
static constexpr uint32_t		MG_RESP_TAIL_BYTES		{200};

struct MG_CURSOR
{
	char				dyn_sql_[MG_MAX_CURSOR_LEN];
	uint8_t				lensql_				{0};
	uint64_t			dyn_prep_reqnum_		{0};
	time_t				dyn_prep_time_t_		{0};
	time_t				tlastsec_			{0};

	MG_CURSOR() noexcept
	{
		*dyn_sql_ = 0;
	}	

	MG_CURSOR(const char *sql, uint32_t len, uint64_t reqnum, time_t preptime) noexcept
		: dyn_prep_reqnum_(reqnum), dyn_prep_time_t_(preptime), tlastsec_(preptime)
	{
		uint32_t		clen = std::min<uint32_t>(len, sizeof(dyn_sql_) - 1);

		std::memcpy(dyn_sql_, sql, clen);
		dyn_sql_[clen] = 0;

		lensql_ = clen;
	}

	uint32_t get_len() const noexcept
	{
		return lensql_;
	}

	void reset() noexcept
	{
		memset(dyn_sql_, 0, sizeof(dyn_sql_));
		lensql_ = 0;
		dyn_prep_reqnum_ = 0;
		dyn_prep_time_t_ = 0;
		tlastsec_ = 0;
	}	
};

using MG_CURSOR_MAP			= std::unordered_map<uint64_t, MG_CURSOR, GY_JHASHER<uint64_t>>;

struct MG_TRAN_EXTSTAT
{
	STRING_BUFFER<MAX_USER_DB_LEN>	userbuf_;
	STRING_BUFFER<MAX_USER_DB_LEN>	appbuf_;
	STRING_BUFFER<256>		errorbuf_;

	uint64_t			reqnum_				{0};
	uint64_t			last_upd_tusec_			{0};
	uint64_t			dyn_prep_reqnum_		{0};
	time_t				dyn_prep_time_t_		{0};
	bool				is_serv_err_			{false};

	void reset_on_req() noexcept
	{
		errorbuf_.reset();
		dyn_prep_reqnum_ = 0;
		dyn_prep_time_t_ = 0;
		is_serv_err_ = false;
	}
};	

struct MG_REQSTAT
{
	alignas(4) uint8_t		reqhdr_[sizeof(MONGO_PROTO::MG_MSG_HDR)]	{};
	uint8_t				resphdr_[sizeof(MONGO_PROTO::MG_MSG_HDR)]	{};
	uint8_t				resptailbuf_[MG_RESP_TAIL_BYTES];

	int64_t				curr_req_cursorid_		{0};	
	uint8_t				req_tkn_frag_			{0};	
	uint8_t				resp_tkn_frag_			{0};	
	uint8_t				req_hdr_fraglen_		{0};
	uint8_t				resp_hdr_fraglen_		{0};
	uint32_t			nbytes_req_frag_		{0};
	uint32_t			nbytes_resp_frag_		{0};
	uint32_t			skip_req_bytes_			{0};
	uint32_t			skip_resp_bytes_		{0};
	uint16_t			nready_resp_pending_		{0};

	uint8_t				nresp_tail_			{0};
	uint8_t				skip_till_auth_resp_		{0};
	uint8_t				skip_to_req_after_resp_		{0};
	uint8_t				skip_req_till_sync_		{0};
	uint8_t				skip_req_resp_till_ready_	{0};
	uint8_t				drop_seen_			{0};

	void reset_req_frag_stat() noexcept
	{
		req_tkn_frag_ = 0;
		memset(reqhdr_, 0, sizeof(reqhdr_));
		req_hdr_fraglen_ = 0;
		nbytes_req_frag_ = 0;
		skip_req_bytes_ = 0;
	}	

	void reset_resp_frag_stat() noexcept
	{
		curr_req_cursorid_ = 0;
		resp_tkn_frag_ = 0;
		memset(resphdr_, 0, sizeof(resphdr_));
		resp_hdr_fraglen_ = 0;
		nbytes_resp_frag_ = 0;
		nresp_tail_ = 0;
		skip_resp_bytes_ = 0;
	}	

	void reset_stats_on_resp(bool clear_req = false) noexcept
	{
		if (clear_req) {	
			reset();	
			return;
		}

		reset_resp_frag_stat();
		
		skip_till_auth_resp_ = 0;
		skip_to_req_after_resp_ = 0;
		skip_req_till_sync_ = 0;
		skip_req_resp_till_ready_ = 0;
		nready_resp_pending_ = 0;
	}	

	void reset()
	{
		this->~MG_REQSTAT();
		new (this) MG_REQSTAT();
	}	
};	


class SVC_INFO_CAP;

class MONGO_SESSINFO : public MONGO_PROTO
{
public :

	enum MG_STATS_E : uint8_t
	{
		STATMG_NEW_SESS		= 0,
		STATMG_SESS_COMPLETE,
		STATMG_MIDWAY_SESS,
		STATMG_SSL_SESS,
		STATMG_SKIP_SESS,
		STATMG_SKIP_SESS_COMP,

		STATMG_SESS_SKIP_PKT,
		STATMG_REQ_PKT_SKIP,
		STATMG_RESP_PKT_SKIP,
		STATMG_SSL_INVALID,
		STATMG_REQ_SYNC_OVF,
		STATMG_REQ_SYNC_TIMEOUT,
		STATMG_REQ_RESET_ERR,
		STATMG_RESP_RESET_ERR,

		STATMG_CURSOR_FIND_OK,
		STATMG_CURSOR_FIND_FAIL,
		STATMG_CURSOR_ADD,
		STATMG_CURSOR_DEL,
		STATMG_CURSOR_ADD_SKIP,

		STATMG_MAX,
	};	

	static inline constexpr const char *	gstatstr[STATMG_MAX] =
	{
		"New Session", "Session Completed", "Midway Session", "SSL Session", "Session Skipped", "Compression Session Skip",
		"Session Skipped Pkt", "Request Packets Skipped", "Response Packets Skipped", "SSL Incorrectly Detected", 
		"Req Sync Overflow", "Req Sync Timeout", "Req Reset on Error", "Resp Reset on Error",
		"Cursor Find Success", "Cursor Find Fail", "Cursor Added", "Cursor Deleted", "Cursor Add Skipped",
	};	

	static inline uint64_t		gstats[STATMG_MAX]		{};
	static inline uint64_t		gstats_old[STATMG_MAX]		{};
	static inline uint64_t		gtotal_queries = 0, glast_queries = 0, gtotal_resp = 0, glast_resp = 0;


	MG_REQSTAT			statmg_;
	API_TRAN			tran_;
	STRING_HEAP			tdstrbuf_;
	MG_TRAN_EXTSTAT			tdstat_;

	uint8_t				*preqfragbuf_			{nullptr};
	uint8_t				*prespfragbuf_			{nullptr};

	MG_CURSOR_MAP			dsql_map_;

	SVC_SESSION 			& svcsess_;
	SVC_INFO_CAP			*psvc_				{nullptr};

	uint8_t				is_midway_session_		{0};
	int8_t				is_ssl_sess_			{(int8_t)-1};
	uint8_t				nssl_resp_chk_			{0};
	uint8_t				skip_session_			{0};
	uint8_t				drop_seen_			{0};
	uint8_t				ncomp_req_			{0};
	uint8_t				ncomp_resp_			{0};
	uint8_t				part_query_started_		{0};

	MONGO_SESSINFO(MONGO_PROTO & prot, SVC_SESSION & svcsess);

	~MONGO_SESSINFO() noexcept;

	int handle_request_pkt(PARSE_PKT_HDR & hdr, uint8_t *pdata);
	int handle_response_pkt(PARSE_PKT_HDR & hdr, uint8_t *pdata);
	void handle_session_end(PARSE_PKT_HDR & hdr);
	void handle_ssl_change(PARSE_PKT_HDR & hdr, uint8_t *pdata);

	void set_new_req() noexcept;
	int parse_req_pkt(PARSE_PKT_HDR & hdr, uint8_t *pdata);
	int parse_resp_pkt(PARSE_PKT_HDR & hdr, uint8_t *pdata);
	int handle_req_token(const MG_MSG_HDR & hdr, uint8_t * sptr, int maxlen);
	int handle_resp_token(const MG_MSG_HDR & hdr, uint8_t * sptr, int maxlen, uint8_t *tailbuf, int ntail);

	void req_parse_doc(MG_OPCODE_E opcode, uint8_t *ptmp, int tlen, bool is_doc, std::string_view parent_key);
	bool resp_parse_doc(MG_OPCODE_E opcode, uint8_t *ptmp, int tlen, bool is_doc, std::string_view parent_key);
	std::string_view get_cursor_text(int64_t curid);
	void add_cursor(int64_t curid);
	bool close_cursor(int64_t curid);
	bool check_for_cursor(uint8_t *tailbuf, uint32_t ntail);
	void request_done(bool flushreq = true, bool clear_req = false);
	void reset_on_error();
	
	bool print_req() noexcept;
	
	void print_partial_req()
	{
		// TODO
	}

	void set_partial_req()
	{
		// TODO
	}	

	void drop_partial_req()
	{
		// TODO
	}	

	static void print_stats(STR_WR_BUF & strbuf, time_t tcur, time_t tlast) noexcept;
};

} // namespace gyeeta

