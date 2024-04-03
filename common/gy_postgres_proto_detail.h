//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_postgres_proto.h"
#include			"gy_proto_common.h"

#include 			<bitset>

namespace gyeeta {

static constexpr uint32_t		PG_MAX_DYN_SQL_LEN		{127};
static constexpr uint32_t		PG_MAX_DYN_SQL_BIND_LEN		{511};
static constexpr uint32_t		PG_ROW_MAX_COLUMNS 		{64};
static constexpr uint32_t		PG_MAX_SESS_PREP_SQLS		{500};
static constexpr uint32_t		PG_MAX_SESS_PORTALS		{16};

struct PG_DYN_PREP
{
	char				dyn_sql_[PG_MAX_DYN_SQL_LEN];
	uint8_t				lensql_				{0};
	uint64_t			dyn_prep_reqnum_		{0};
	time_t				dyn_prep_time_t_		{0};
	std::bitset<PG_ROW_MAX_COLUMNS>	oidparams_;
	std::bitset<PG_ROW_MAX_COLUMNS>	intparams_;
	std::bitset<PG_ROW_MAX_COLUMNS>	floatparams_;

	PG_DYN_PREP() noexcept
	{
		*dyn_sql_ = 0;
	}	

	PG_DYN_PREP(const char *sql, uint32_t len, uint64_t reqnum, time_t preptime) noexcept
		: dyn_prep_reqnum_(reqnum), dyn_prep_time_t_(preptime)
	{
		uint32_t		clen = std::min<uint32_t>(len, sizeof(dyn_sql_) - 1);

		std::memcpy(dyn_sql_, sql, clen);
		dyn_sql_[clen] = 0;

		lensql_ = clen;
	}

	~PG_DYN_PREP() noexcept		= default;

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
		oidparams_.reset();
		intparams_.reset();
		floatparams_.reset();
	}	
};

typedef std::unordered_map<uint32_t, PG_DYN_PREP>  		PG_DYN_PREP_MAP;
typedef std::unordered_map<uint32_t, PG_DYN_PREP>::iterator	PG_DYN_PREP_MAP_ITER;

struct PG_DYN_PORTAL
{
	std::string			bind_sql_;
	uint64_t			dyn_prep_reqnum_	{0};
	uint64_t			dyn_prep_time_t_	{0};

	PG_DYN_PORTAL() 		= default;
	~PG_DYN_PORTAL() noexcept	= default;

	PG_DYN_PORTAL(const char *sql, uint32_t len, uint64_t reqnum, time_t bindtime)
		: bind_sql_(sql, std::min<uint32_t>(len, PG_MAX_DYN_SQL_BIND_LEN)), dyn_prep_reqnum_(reqnum), dyn_prep_time_t_(bindtime)
	{}

	uint32_t get_len() const noexcept
	{
		return bind_sql_.size();
	}

	void reset() noexcept
	{
		bind_sql_.clear();
		dyn_prep_reqnum_ = 0;
		dyn_prep_time_t_ = 0;
	}	
};

typedef std::unordered_map<uint32_t, PG_DYN_PORTAL>  			PG_DYN_PORTAL_MAP;
typedef std::unordered_map<uint32_t, PG_DYN_PORTAL>::iterator		PG_DYN_PORTAL_MAP_ITER;

struct TRAN_EXTSTAT
{
	STRING_BUFFER<MAX_USER_DB_LEN>	userbuf_;
	STRING_BUFFER<MAX_USER_DB_LEN>	appbuf_;
	STRING_BUFFER<MAX_USER_DB_LEN>	dbbuf_;
	STRING_BUFFER<256>		errorbuf_;

	uint64_t			reqnum_				{0};
	uint64_t			last_upd_tusec_			{0};
	uint64_t			dyn_prep_reqnum_		{0};
	time_t				dyn_prep_time_t_		{0};
	uint32_t			nrows_				{0};
	int				spid_				{0};
	bool				is_serv_err_			{false};

	void reset_on_req() noexcept
	{
		errorbuf_.reset();
		dyn_prep_reqnum_ = 0;
		dyn_prep_time_t_ = 0;
		nrows_ = 0;
		is_serv_err_ = false;
	}
};	

struct PG_REQSTAT
{
	uint8_t				req_tkn_frag_			{0};	
	uint8_t				resp_tkn_frag_			{0};	
	uint8_t				reqhdr_[8]			{};
	uint8_t				resphdr_[8]			{};
	uint8_t				req_hdr_fraglen_		{0};
	uint8_t				resp_hdr_fraglen_		{0};
	uint32_t			nbytes_req_frag_		{0};
	uint32_t			nbytes_resp_frag_		{0};
	uint32_t			skip_req_bytes_			{0};
	uint32_t			skip_resp_bytes_		{0};
	uint16_t			nready_resp_pending_		{0};

	uint8_t				skip_till_auth_resp_		{0};
	uint8_t				skip_to_req_after_resp_		{0};
	uint8_t				skip_req_till_sync_		{0};
	uint8_t				skip_req_resp_till_ready_	{0};
	uint8_t				drop_seen_			{0};
	uint8_t				copy_mode_			{0};

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
		resp_tkn_frag_ = 0;
		memset(resphdr_, 0, sizeof(resphdr_));
		resp_hdr_fraglen_ = 0;
		nbytes_resp_frag_ = 0;
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
		copy_mode_ = 0;
		nready_resp_pending_ = 0;
	}	

	void reset() noexcept
	{
		std::memset((void *)this, 0, sizeof(*this));
	}	
};	

class SVC_INFO_CAP;

class POSTGRES_SESSINFO : public POSTGRES_PROTO
{
public :
	enum PG_STATS_E : uint8_t
	{
		STATPG_NEW_SESS		= 0,
		STATPG_SESS_COMPLETE,
		STATPG_MIDWAY_SESS,
		STATPG_SSL_SESS,
		STATPG_SKIP_SESS,
		STATPG_REQ_RESET_ERR,
		STATPG_RESP_RESET_ERR,
		STATPG_REQ_SYNC_OVF,
		STATPG_REQ_SYNC_TIMEOUT,
		STATPG_PREPARE_DEL,
		STATPG_PREPARE_ADD_SKIP,
		STATPG_PREPARE_ADD,
		STATPG_PREPARE_FIND_OK,
		STATPG_PREPARE_FIND_FAIL,
		STATPG_PORTAL_DEL,
		STATPG_PORTAL_CLEAR_ALL,
		STATPG_PORTAL_ADD,
		STATPG_SESS_SKIP_PKT,
		STATPG_REQ_PKT_SKIP,
		STATPG_RESP_PKT_SKIP,

		STATPG_MAX,
	};	

	static inline constexpr const char *	gstatstr[STATPG_MAX] =
	{
		"New Session", "Session Completed", "Midway Session", "SSL Session", "Session Skipped", 
		"Req Reset on Error", "Resp Reset on Error", "Req Sync Overflow", "Req Sync Timeout", "DSQL Prepare Deleted",
		"DSQL Prepare Add Skipped", "DSQL Prepare Added", "DSQL Prep Find Success", "DSQL Prep Find Failed",
		"DSQL Portal Deleted", "DSQL Portal Clear All", "DSQL Portal Added", "Session Skipped Pkt", 
		"Request Packets Skipped", "Response Packets Skipped",
	};	

	static inline uint64_t		gstats[STATPG_MAX]		{};
	static inline uint64_t		gstats_old[STATPG_MAX]		{};
	static inline uint64_t		gtotal_queries = 0, glast_queries = 0, gtotal_resp = 0, glast_resp = 0;


	PG_REQSTAT			statpg_;
	API_TRAN			tran_;
	STRING_HEAP			tdstrbuf_;
	TRAN_EXTSTAT			tdstat_;

	uint8_t				*preqfragbuf_			{nullptr};
	uint8_t				*presfragbuf_			{nullptr};

	PG_DYN_PREP_MAP			pg_dsql_map_;
	PG_DYN_PORTAL_MAP		pg_portal_map_;
	
	PG_DYN_PREP			noname_dsql_;
	PG_DYN_PORTAL			noname_portal_;

	SVC_SESSION 			& svcsess_;
	SVC_INFO_CAP			*psvc_				{nullptr};

	uint8_t				login_complete_			{0};
	uint8_t				is_midway_session_		{0};
	uint8_t				is_ssl_sess_			{0};
	uint8_t				nssl_resp_chk_			{0};
	uint8_t				skip_session_			{0};
	uint8_t				drop_seen_			{0};
	uint8_t				part_query_started_		{0};

	POSTGRES_SESSINFO(POSTGRES_PROTO & prot, SVC_SESSION & svcsess);

	~POSTGRES_SESSINFO() noexcept;

	int handle_request_pkt(PARSE_PKT_HDR & hdr, uint8_t *pdata);

	int handle_response_pkt(PARSE_PKT_HDR & hdr, uint8_t *pdata);

	void handle_session_end(PARSE_PKT_HDR & hdr);

	void handle_ssl_change(PARSE_PKT_HDR & hdr, uint8_t *pdata);

	void set_new_req() noexcept;

	int parse_req_pkt(PARSE_PKT_HDR & hdr, uint8_t *pdata);
	
	int parse_resp_pkt(PARSE_PKT_HDR & hdr, uint8_t *pdata);

	int handle_req_token(PG_MSG_TYPES_E tkntype, uint32_t tknlen, uint8_t * sptr, int maxlen);

	int handle_resp_token(PG_MSG_TYPES_E tkntype, uint32_t tknlen, uint8_t * sptr, int maxlen);
	
	void request_done(bool flushreq = true, bool clear_req = false);
	
	void reset_on_error();
	
	std::pair<int, bool> get_error_code(char *ebuf) noexcept;

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

