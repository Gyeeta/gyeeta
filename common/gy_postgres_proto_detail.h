//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_postgres_proto.h"

namespace gyeeta {

struct PARSE_PKT_HDR;
class SVC_SESSION;

class postgres_sessinfo : public postgres_proto
{
public :
	postgres_sessinfo()			= default;

	~postgres_sessinfo() noexcept		= default;

	void handle_request_pkt(SVC_SESSION & sess, PARSE_PKT_HDR & hdr, uint8_t *pdata);

	void handle_response_pkt(SVC_SESSION & sess, PARSE_PKT_HDR & hdr, uint8_t *pdata);

	void handle_session_end(SVC_SESSION & sess, PARSE_PKT_HDR & hdr);

	void handle_ssl_change(SVC_SESSION & sess, PARSE_PKT_HDR & hdr, uint8_t *pdata);

	static std::pair<postgres_sessinfo *, void *> alloc_sess(SVC_SESSION & sess, PARSE_PKT_HDR & hdr);

	static void destroy(postgres_sessinfo *pobj, void *pdata) noexcept;
};

} // namespace gyeeta

