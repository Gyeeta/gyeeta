//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_http2_proto.h"

namespace gyeeta {

struct PARSE_PKT_HDR;
class SVC_SESSION;

class http2_sessinfo : public http2_proto
{
public :
	http2_sessinfo()			= default;
	
	~http2_sessinfo() noexcept		= default;

	void handle_request_pkt(SVC_SESSION & sess, PARSE_PKT_HDR & hdr, uint8_t *pdata);

	void handle_response_pkt(SVC_SESSION & sess, PARSE_PKT_HDR & hdr, uint8_t *pdata);

	void handle_session_end(SVC_SESSION & sess, PARSE_PKT_HDR & hdr);

	void handle_ssl_change(SVC_SESSION & sess, PARSE_PKT_HDR & hdr, uint8_t *pdata);

	static std::pair<http2_sessinfo *, void *> alloc_sess(SVC_SESSION & sess, PARSE_PKT_HDR & hdr);

	static void destroy(http2_sessinfo *pobj, void *pdata) noexcept;
};


} // namespace gyeeta

