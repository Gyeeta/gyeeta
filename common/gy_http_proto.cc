//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_http_proto.h"
#include			"gy_http_proto_detail.h"
#include			"gy_proto_parser.h"

namespace gyeeta {

HTTP1_PROTO::HTTP1_PROTO(API_PARSE_HDLR & apihdlr, uint32_t api_max_len)
	: apihdlr_(apihdlr), api_max_len_(api_max_len)
{}	

HTTP1_PROTO::~HTTP1_PROTO() noexcept		= default;

std::pair<HTTP1_SESSINFO *, void *> HTTP1_PROTO::alloc_sess(SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr)
{
	return { new HTTP1_SESSINFO(*this, svcsess, hdr), nullptr };
}	

void HTTP1_PROTO::destroy(HTTP1_SESSINFO *pobj, void *pdata) noexcept
{
	delete pobj;
}	


void HTTP1_PROTO::handle_request_pkt(HTTP1_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	sess.handle_request_pkt(hdr, pdata);
}

void HTTP1_PROTO::handle_response_pkt(HTTP1_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	sess.handle_response_pkt(hdr, pdata);
}

void HTTP1_PROTO::handle_session_end(HTTP1_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr)
{
	sess.handle_session_end(hdr);
}	

void HTTP1_PROTO::handle_ssl_change(HTTP1_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	sess.handle_ssl_change(hdr, pdata);
}

void HTTP1_PROTO::print_stats(STR_WR_BUF & strbuf, time_t tcur, time_t tlast) noexcept
{
	HTTP1_SESSINFO::print_stats(strbuf, tcur, tlast);
}

HTTP1_SESSINFO::HTTP1_SESSINFO(HTTP1_PROTO & prot, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr)
	: HTTP1_PROTO(prot), 
	tran_(svcsess.common_.tlastpkt_usec_, svcsess.common_.tconnect_usec_, svcsess.common_.cli_ipport_, svcsess.common_.ser_ipport_, svcsess.common_.glob_id_, svcsess.proto_), 
	tdstrbuf_(prot.api_max_len_ - 1), 
	svcsess_(svcsess), is_https_(hdr.src_ == SRC_UPROBE_SSL)
{
	std::memset(tdstrbuf_.get(), 0, 128);
	
	gstats[STATH1_NEW_SESS]++;
	
	if (svcsess.common_.syn_seen_ == false) {
		is_midway_session_ = 1;
		
		// TODO

		gstats[STATH1_MIDWAY_SESS]++;
	}
}

HTTP1_SESSINFO::~HTTP1_SESSINFO() noexcept
{
	gstats[STATH1_SESS_COMPLETE]++;

	if (part_query_started_ == 1) {
		drop_partial_req();
	}
}

int HTTP1_SESSINFO::handle_request_pkt(PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	if (skip_session_ == 1) {
		gstats[STATH1_SESS_SKIP_PKT]++;
		return 0;
	}

	if (drop_seen_ || common.clidroptype_ == DT_DROP_SEEN || common.serdroptype_ == DT_DROP_SEEN) {

		if (part_query_started_ == 1) {
			drop_partial_req();
			part_query_started_ = 0;
		}
			
		// TODO
		drop_seen_ = 0;

		return 0;
	}

	ret = parse_req_pkt(hdr, pdata);
	if (ret < 0) {
		gstats[STATH1_REQ_PKT_SKIP]++;
		return 0;
	}	

	tran_.update_req_stats(common.tlastpkt_usec_, hdr.datalen_);

	if (tdstrbuf_.size() && part_query_started_ == 0) {
		tran_.request_len_ = tdstrbuf_.size() + 1;
		part_query_started_ = 1;
		set_partial_req();
	}

	return 0;
}

int HTTP1_SESSINFO::handle_response_pkt(PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	uint8_t 		*sptr = pdata;
	uint32_t 		bytes_left, pktlen = hdr.datalen_;
	auto			& common = svcsess_.common_;
	int 			ret;

	if (skip_session_ == 1) {
		gstats[STATH1_SESS_SKIP_PKT]++;
		return 0;
	}

	if (drop_seen_ || common.clidroptype_ == DT_DROP_SEEN || common.serdroptype_ == DT_DROP_SEEN) {

drop_chk :
		if (part_query_started_ == 1) {
			drop_partial_req();
			part_query_started_ = 0;
		}
			
		drop_seen_ = 0;

		// TODO

		return 0;
	}

	tran_.update_resp_stats(common.tlastpkt_usec_, hdr.datalen_);

	ret = parse_resp_pkt(hdr, pdata);
	if (ret < 0) {
		gstats[STATH1_RESP_PKT_SKIP]++;
	}	

	return 0;
}

void HTTP1_SESSINFO::handle_session_end(PARSE_PKT_HDR & hdr)
{
	auto				& common = svcsess_.common_;

	if (part_query_started_ == 1) {
		drop_partial_req();
		part_query_started_ = 0;
	}
	
	if (tdstat_.reqnum_ == 0) {
		return;
	}	

	/*
	 * Flush existing request
	 */
	if (tran_.reqlen_ && tdstrbuf_.size() > 0 && (!(drop_seen_ || common.clidroptype_ == DT_DROP_SEEN || common.serdroptype_ == DT_DROP_SEEN))) {
		if (tran_.reslen_ == 0) {
			tran_.tupd_usec_ = common.tlastpkt_usec_;
			tran_.tres_usec_ = common.tlastpkt_usec_;

			tran_.reslen_ = 1;
		}	

		request_done();
	}	
	else {
		request_done(false /* flushreq */, true /* clear_req */);
	}	

}

void HTTP1_SESSINFO::handle_ssl_change(PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	is_https_ = true;
}	

void HTTP1_SESSINFO::set_new_req() noexcept
{
	COMMON_PROTO 				& common = svcsess_.common_;

	tran_.reset();

	tran_.treq_usec_			= common.tlastpkt_usec_;
	tran_.tupd_usec_			= common.tlastpkt_usec_;
	tran_.tin_usec_				= common.tlastpkt_usec_;
	
	reset_on_new_req();
}

void HTTP1_SESSINFO::reset_on_new_req() noexcept
{
	tdstrbuf_.reset();
	reqbody_buf_.reset();
	errorbuf_.reset();
}

void HTTP1_SESSINFO::reset_req_frag_stat() noexcept
{
	req_tkn_frag_ = 0;
	memset(reqhdr_, 0, sizeof(reqhdr_));
	req_hdr_fraglen_ = 0;
	nbytes_req_frag_ = 0;
	skip_req_bytes_ = 0;
}	

void HTTP1_SESSINFO::reset_resp_frag_stat() noexcept
{
	resp_tkn_frag_ = 0;
	memset(resphdr_, 0, sizeof(resphdr_));
	resp_hdr_fraglen_ = 0;
	nbytes_resp_frag_ = 0;
	skip_resp_bytes_ = 0;
}	

void HTTP1_SESSINFO::reset_stats_on_resp(bool clear_req) noexcept
{
	if (clear_req) {	
		reset_req_frag_stat();	
	}

	reset_resp_frag_stat();
	
	// TODO
}	

int HTTP1_SESSINFO::parse_req_pkt(PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	return 0;
}

int HTTP1_SESSINFO::parse_resp_pkt(PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	return 0;
}

void HTTP1_SESSINFO::request_done(bool flushreq, bool clear_req)
{

}

void HTTP1_SESSINFO::reset_on_error()
{

}

bool HTTP1_SESSINFO::print_req() noexcept
{
	return true;
}

void HTTP1_SESSINFO::print_stats(STR_WR_BUF & strbuf, time_t tcur, time_t tlast) noexcept
{

}

} // namespace gyeeta

