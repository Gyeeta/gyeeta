//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_http_proto.h"
#include			"gy_proto_parser.h"

namespace gyeeta {

enum REQ_HDR_HTTP : uint8_t
{
	REQ_HDR_CONTENT_TYPE,
	REQ_HDR_CONTENT_LEN,
	REQ_HDR_TRANSFER_ENCODE,
};

enum RESP_HDR_HTTP : uint8_t
{
	RESP_HDR_CONTENT_TYPE,
	RESP_HDR_CONTENT_LEN,
	RESP_HDR_CONTENT_ENCODING,
	RESP_HDR_TRANSFER_ENCODE,
	RESP_HDR_UPGRADE,
	RESP_HDR_CONNECTION,
};

enum HCONN_STATE_E : uint8_t
{
	HCONN_IDLE			= 0,
	HCONN_START_LINE,
	HCONN_HDR_ACTIVE,
	HCONN_DATA_ACTIVE,
	HCONN_CHUNK_HDR,
	HCONN_CHUNK_DATA,
};	

enum CONN_STATE_E : uint8_t
{
	CONN_IDLE			= 0,
	CONN_REQ_ACTIVE,
	CONN_RESP_NEXT,
	CONN_RESP_ACTIVE,
};	

struct HCONN_STAT
{
	size_t				data_chunk_len_		{0};
	size_t				data_chunk_left_	{0};
	uint16_t			fraglen_		{0};
	uint16_t			resp_status_		{0};
	HCONN_STATE_E			state_			{HCONN_IDLE};
	HTTP1_PROTO::METHODS_E		req_method_		{HTTP1_PROTO::METHOD_GET};
	bool				data_compressed_	{false};	// Content-Encoding compressed or Transfer Encoding compressed
};	

class HTTP1_SESSINFO : public HTTP1_PROTO
{
public :
	static constexpr size_t		MAX_PIPELINE_ELEMS	{128};
	static constexpr size_t		MAX_FRAG_LEN		{512};

	enum STATS_H1_E : uint8_t
	{
		STATH1_NEW_SESS		= 0,
		STATH1_SESS_COMPLETE,
		STATH1_MIDWAY_SESS,
		STATH1_SKIP_SESS,

		STATH1_REQ_RESET_ERR,
		STATH1_RESP_RESET_ERR,
		STATH1_SESS_SKIP_PKT,
		STATH1_REQ_PKT_SKIP,
		STATH1_RESP_PKT_SKIP,
		STATH1_REQ_PIPELINED,
		STATH1_REQ_PIPELINE_OVF,

		STATH1_MAX,
	};	

	static inline constexpr const char *	gstatstr[STATH1_MAX] =
	{
		"New Session", "Session Completed", "Midway Session", "Session Skipped", 
		"Req Reset on Error", "Resp Reset on Error", 
		"Session Skipped Pkt", "Request Packets Skipped", "Response Packets Skipped",
		"Request Pipelined", "Req Pipeline Overflow", 
	};	

	static inline uint64_t		gstats[STATH1_MAX]		{};
	static inline uint64_t		gstats_old[STATH1_MAX]		{};
	static inline uint64_t		gtotal_queries = 0, glast_queries = 0, gtotal_resp = 0, glast_resp = 0;


	API_TRAN			tran_;
	STRING_HEAP			tdstrbuf_;
	STRING_BUFFER<1024>		reqbody_buf_;
	STRING_BUFFER<256>		errorbuf_;
	
	METHODS_E			req_methods_[MAX_PIPELINE_ELEMS]	{};
	uint16_t			npending_				{0};

	uint8_t				reqfragbuf_[MAX_FRAG_LEN];
	uint8_t				respfragbuf_[MAX_FRAG_LEN];

	HCONN_STAT			reqstate_;
	HCONN_STAT			respstate_;

	SVC_SESSION 			& svcsess_;

	bool				is_https_		{false};
	bool				is_keep_alive_		{false};
	bool				is_http10_		{false};
	uint8_t				skip_session_		{false};
	uint8_t				drop_seen_		{0};
	uint8_t				part_query_started_	{0};
	uint8_t				is_midway_session_	{0};

	HTTP1_SESSINFO(HTTP1_PROTO & prot, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr);

	~HTTP1_SESSINFO() noexcept;

	int handle_request_pkt(PARSE_PKT_HDR & hdr, uint8_t *pdata);

	int handle_response_pkt(PARSE_PKT_HDR & hdr, uint8_t *pdata);

	void handle_session_end(PARSE_PKT_HDR & hdr);

	void handle_ssl_change(PARSE_PKT_HDR & hdr, uint8_t *pdata);

	void set_new_req() noexcept;

	int parse_req_pkt(PARSE_PKT_HDR & hdr, uint8_t *pdata);
	
	int parse_resp_pkt(PARSE_PKT_HDR & hdr, uint8_t *pdata);

	void request_done(bool flushreq = true, bool clear_req = false);
	
	void reset_on_new_req() noexcept;

	void reset_req_frag_stat() noexcept;

	void reset_resp_frag_stat() noexcept;

	void reset_stats_on_resp(bool clear_req = false) noexcept;

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

