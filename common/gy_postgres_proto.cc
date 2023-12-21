//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_postgres_proto.h"
#include			"gy_postgres_proto_detail.h"
#include			"gy_proto_parser.h"

namespace gyeeta {

POSTGRES_PROTO::POSTGRES_PROTO(API_PARSE_HDLR & apihdlr)
	: apihdlr_(apihdlr)
{}	

POSTGRES_PROTO::~POSTGRES_PROTO() noexcept		= default;

std::pair<POSTGRES_SESSINFO *, void *> POSTGRES_PROTO::alloc_sess(SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr)
{
	return { new POSTGRES_SESSINFO(), nullptr };
}	

void POSTGRES_PROTO::destroy(POSTGRES_SESSINFO *pobj, void *pdata) noexcept
{
	delete pobj;
}	


void POSTGRES_PROTO::handle_request_pkt(POSTGRES_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr, uint8_t *pdata)
{

}

void POSTGRES_PROTO::handle_response_pkt(POSTGRES_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr, uint8_t *pdata)
{

}

void POSTGRES_PROTO::handle_session_end(POSTGRES_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr)
{

}	

void POSTGRES_PROTO::handle_ssl_change(POSTGRES_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr, uint8_t *pdata)
{

}

} // namespace gyeeta

