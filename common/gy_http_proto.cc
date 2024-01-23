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
	svcsess_(svcsess), is_https_(hdr.src_ == SRC_UPROBE_SSL)
{

}

HTTP1_SESSINFO::~HTTP1_SESSINFO() noexcept
{

}

int HTTP1_SESSINFO::handle_request_pkt(PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	return 0;
}

int HTTP1_SESSINFO::handle_response_pkt(PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	return 0;
}

void HTTP1_SESSINFO::handle_session_end(PARSE_PKT_HDR & hdr)
{

}

void HTTP1_SESSINFO::handle_ssl_change(PARSE_PKT_HDR & hdr, uint8_t *pdata)
{

}	

void HTTP1_SESSINFO::set_new_req() noexcept
{

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

} // namespace gyeeta

