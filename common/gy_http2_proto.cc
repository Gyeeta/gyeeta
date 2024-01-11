//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_http2_proto.h"
#include			"gy_http2_proto_detail.h"
#include			"gy_proto_parser.h"

namespace gyeeta {

HTTP2_PROTO::HTTP2_PROTO(API_PARSE_HDLR & apihdlr, uint32_t api_max_len)
	: apihdlr_(apihdlr), api_max_len_(api_max_len)
{}	

HTTP2_PROTO::~HTTP2_PROTO() noexcept		= default;

std::pair<HTTP2_SESSINFO *, void *> HTTP2_PROTO::alloc_sess(SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr)
{
	return { new HTTP2_SESSINFO(), nullptr };
}	

void HTTP2_PROTO::destroy(HTTP2_SESSINFO *pobj, void *pdata) noexcept
{
	delete pobj;
}	


void HTTP2_PROTO::handle_request_pkt(HTTP2_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr, uint8_t *pdata)
{

}

void HTTP2_PROTO::handle_response_pkt(HTTP2_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr, uint8_t *pdata)
{

}

void HTTP2_PROTO::handle_session_end(HTTP2_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr)
{

}	

void HTTP2_PROTO::handle_ssl_change(HTTP2_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr, uint8_t *pdata)
{

}

void HTTP2_PROTO::print_stats(STR_WR_BUF & strbuf, time_t tcur, time_t tlast) noexcept
{

}


} // namespace gyeeta

