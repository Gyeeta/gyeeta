//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_http2_proto_detail.h"
#include			"gy_proto_parser.h"

namespace gyeeta {

void http2_sessinfo::handle_request_pkt(SVC_SESSION & sess, PARSE_PKT_HDR & hdr, uint8_t *pdata)
{

}

void http2_sessinfo::handle_response_pkt(SVC_SESSION & sess, PARSE_PKT_HDR & hdr, uint8_t *pdata)
{

}

void http2_sessinfo::handle_session_end(SVC_SESSION & sess, PARSE_PKT_HDR & hdr)
{

}	

void http2_sessinfo::handle_ssl_change(SVC_SESSION & sess, PARSE_PKT_HDR & hdr, uint8_t *pdata)
{

}

std::pair<http2_sessinfo *, void *> http2_sessinfo::alloc_sess(SVC_SESSION & sess, PARSE_PKT_HDR & hdr)
{
	return { new http2_sessinfo(), nullptr };
}	

void http2_sessinfo::destroy(http2_sessinfo *pobj, void *pdata) noexcept
{
	delete pobj;
}	

} // namespace gyeeta

