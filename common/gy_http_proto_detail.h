//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_http_proto.h"
#include			"gy_proto_parser.h"

namespace gyeeta {

enum HCONN_STATE_E : uint8_t
{
	HCONN_IDLE			= 0,
	HCONN_HDR,
	HCONN_CONTENT_DATA,
	HCONN_CHUNK_START,
	HCONN_CHUNK_DATA,
	HCONN_CHUNK_END,
};	

struct HCONN_STAT
{
	size_t				data_chunk_len_			{0};
	size_t				data_chunk_left_		{0};
	uint16_t			fraglen_			{0};
	HCONN_STATE_E			state_				{HCONN_IDLE};
	HTTP1_PROTO::METHODS_E		req_method_			{HTTP1_PROTO::METHOD_UNKNOWN};
	int8_t				save_req_payload_		{0};
	bool				skip_till_eol_			{false};
	bool				skip_till_resp_chunk_end_	{false};
	bool				is_content_len_			{false};
	bool				is_chunk_data_			{false};

	void reset() noexcept
	{
		std::memset(this, 0, sizeof(*this));
		req_method_ = HTTP1_PROTO::METHOD_UNKNOWN;
	}	

	void reset_skip_method() noexcept
	{
		auto			method = req_method_;

		reset();
		req_method_ = method;
	}	
};	

class HTTP1_SESSINFO : public HTTP1_PROTO
{
public :
	static constexpr size_t		MAX_PIPELINE_ELEMS		{128};
	static constexpr size_t		MAX_FRAG_LEN			{128};
	static constexpr size_t		MAX_PAYLOAD_SAVE_LEN		{512};

	enum REQ_HDR_HTTP : uint8_t
	{
		REQ_HDR_CONTENT_TYPE	= 0,
		REQ_HDR_CONTENT_LEN,
		REQ_HDR_CONTENT_ENCODE,
		REQ_HDR_TRANSFER_ENCODE,
		REQ_HDR_USER_AGENT,

		REQ_HDR_MAX,
	};

	static constexpr std::string_view req_hdr_http[REQ_HDR_MAX] = {
		"Content-Type:", "Content-Length:", "Content-Encoding", "Transfer-Encoding:", "User-Agent:",
	};	

	static constexpr std::string_view req_content_types[] = {
		"/json", "text/", "/x-www-form-urlencoded", "/xml", "form-data",
	};	

	static constexpr std::string_view comp_content_types[] = {
		"gzip", "compress", "deflate", "br",
	};	

	enum RESP_HDR_HTTP : uint8_t
	{
		RESP_HDR_CONTENT_LEN	= 0,
		RESP_HDR_TRANSFER_ENCODE,

		RESP_HDR_MAX,
	};

	static constexpr std::string_view resp_hdr_http[RESP_HDR_MAX] = {
		"Content-Length:", "Transfer-Encoding:",
	};	

	enum STATS_H1_E : uint8_t
	{
		STATH1_NEW_SESS		= 0,
		STATH1_SESS_COMPLETE,
		STATH1_MIDWAY_SESS,
		STATH1_SKIP_SESS,
		STATH1_HTTPS_SESS,
		STATH1_HTTP2_CONN,

		STATH1_REQ_RESET_ERR,
		STATH1_RESP_RESET_ERR,
		STATH1_SESS_SKIP_PKT,
		STATH1_REQ_PKT_SKIP,
		STATH1_RESP_PKT_SKIP,
		STATH1_REQ_PIPELINED,
		STATH1_REQ_PIPELINE_OVF,
		STATH1_REQ_PIPELINE_TIMEOUT,
		STATH1_REQ_SYNC_MISS,
		STATH1_CHUNK_FRAG_OVF,
		STATH1_INVALID_STATE,
		STATH1_DROP_RECOVER,

		STATH1_CONNECT_VPN,

		STATH1_MAX,
	};	

	static inline constexpr const char *	gstatstr[STATH1_MAX] =
	{
		"New Session", "Session Completed", "Midway Session", "Session Skipped", "HTTPS Connection", "HTTP2 Connection",
		"Req Reset on Error", "Resp Reset on Error", 
		"Session Skipped Pkt", "Request Packets Skipped", "Response Packets Skipped",
		"Request Pipelined", "Req Pipeline Overflow", "Req Pipeline Timeout", "Req Sync Miss", "Chunk Overflow",
		"Connection State Invalid", "Drop Quick Recovery", "Connect VPN Session",
	};	

	static inline uint64_t			gstats[STATH1_MAX]		{};
	static inline uint64_t			gstats_old[STATH1_MAX]		{};
	static inline uint64_t			gtotal_queries = 0, glast_queries = 0, gtotal_resp = 0, glast_resp = 0;


	API_TRAN				tran_;
	STRING_HEAP				tdstrbuf_;
	STRING_BUFFER<MAX_PAYLOAD_SAVE_LEN>	parambuf_;
	STRING_BUFFER<MAX_USER_DB_LEN>		useragentbuf_;
	STRING_BUFFER<256>			errorbuf_;
	uint64_t				reqnum_					{0};
	uint64_t				last_upd_tusec_				{0};
	
	METHODS_E				resp_pipline_[MAX_PIPELINE_ELEMS]	{};
	uint8_t					nresp_pending_				{0};
	uint8_t					nresp_completed_			{0};
	uint16_t				last_resp_status_			{0};
	bool					resp_error_added_			{false};	

	alignas(8) uint8_t			reqfragbuf_[MAX_FRAG_LEN];
	uint8_t					respfragbuf_[MAX_FRAG_LEN];

	HCONN_STAT				reqstate_;
	HCONN_STAT				respstate_;

	SVC_SESSION 				& svcsess_;

	bool					is_https_			{false};
	bool					is_keep_alive_			{false};
	bool					is_http10_			{false};
	uint8_t					skip_session_			{0};
	uint8_t					part_query_started_		{0};
	uint8_t					is_midway_session_		{0};

	uint8_t					drop_seen_			{0};
	bool					skip_till_req_			{false};
	bool					skip_till_resp_			{false};
	uint8_t					skip_to_req_after_resp_		{0};

	HTTP1_SESSINFO(HTTP1_PROTO & prot, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr);

	~HTTP1_SESSINFO() noexcept;

	int handle_request_pkt(PARSE_PKT_HDR & hdr, uint8_t *pdata);

	int handle_response_pkt(PARSE_PKT_HDR & hdr, uint8_t *pdata);

	void handle_session_end(PARSE_PKT_HDR & hdr);

	void handle_ssl_change(PARSE_PKT_HDR & hdr, uint8_t *pdata);

	int handle_drop_on_req(PARSE_PKT_HDR & hdr, uint8_t *pdata, const uint32_t pktlen);
	
	int handle_drop_on_resp(PARSE_PKT_HDR & hdr, uint8_t *pdata, const uint32_t pktlen);

	void set_new_req() noexcept;

	int parse_req_pkt(PARSE_PKT_HDR & hdr, uint8_t *pdata, const uint32_t pktlen);
	
	int parse_resp_pkt(PARSE_PKT_HDR & hdr, uint8_t *pdata, const uint32_t pktlen);

	void request_done(bool flushreq = true, bool clear_req = false);
	
	void reset_all_state() noexcept
	{
		reset_for_new_req();
		reqstate_.reset();
		respstate_.reset();

		nresp_pending_ = 0;
		nresp_completed_ = 0;

		drop_seen_ = 0;
		skip_till_req_ = false;
		skip_till_resp_ = false;
		skip_to_req_after_resp_ = false;
	}

	void reset_for_new_req() noexcept;

	void reset_stats_on_resp(bool clear_req = false) noexcept;

	void reset_on_resp_error();
	
	void reset_till_resp(bool resp_expected) noexcept
	{
		reqstate_.reset_skip_method();

		skip_till_resp_ = true;

		if (resp_expected) {
			set_resp_expected();
		}	
	}

	bool set_resp_expected() noexcept;

	METHODS_E get_curr_req_method() noexcept;

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

	DirPacket get_last_dir() const noexcept
	{
		return svcsess_.common_.lastdir_;
	}	

	static inline bool is_eol(char c) noexcept
	{
		return c == '\r' || c == '\n';
	}	

	static void print_stats(STR_WR_BUF & strbuf, time_t tcur, time_t tlast) noexcept;
	
};

} // namespace gyeeta

