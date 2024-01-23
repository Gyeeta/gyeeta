//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_http_proto.h"

namespace gyeeta {

struct HTTP_REQSTAT
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


class HTTP1_SESSINFO : public HTTP1_PROTO
{
public :
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

