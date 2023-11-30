//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_http_proto_detail.h"
#include			"gy_proto_parser.h"

namespace gyeeta {

void http1_sessinfo::handle_request_pkt(SVC_SESSION & sess, PARSE_PKT_HDR & hdr, uint8_t *pdata)
{

}

void http1_sessinfo::handle_response_pkt(SVC_SESSION & sess, PARSE_PKT_HDR & hdr, uint8_t *pdata)
{

}

void http1_sessinfo::handle_session_end(SVC_SESSION & sess, PARSE_PKT_HDR & hdr)
{

}	

void http1_sessinfo::handle_ssl_change(SVC_SESSION & sess, PARSE_PKT_HDR & hdr, uint8_t *pdata)
{

}

std::pair<http1_sessinfo *, void *> http1_sessinfo::alloc_sess(SVC_SESSION & sess, PARSE_PKT_HDR & hdr)
{
	return { new http1_sessinfo(), nullptr };
}	

void http1_sessinfo::destroy(http1_sessinfo *pobj, void * pdata) noexcept
{
	delete pobj;
}	

} // namespace gyeeta

