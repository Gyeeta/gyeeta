//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_common_inc.h"
#include			"gy_http_proto.h"

using namespace gyeeta;

int main()
{
	static constexpr std::string_view	reqarr[] = {
		"GET /home HTTP/1.1\r\nHost: example.com\r\nCookie: \r\n\r\n",
		"GET /hoge HTTP/1.1\r\nHost: example.com\r\nUser-Agent: \343\201\262\343/1.0\r\n\r\n",
		"GET https://datatracker.ietf.org/doc/html/rfc7230?paramdummy1=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa HTTP/1.1\r\nHost: datatracker.ietf.org\r\nUser-Agent: \343\201\262\343/1.0\r\n\r\n",
	};	

	for (auto sv : reqarr) {
		assert(true == HTTP1_PROTO::is_valid_req((const uint8_t *)sv.data(), sv.size(), sv.size()));
	}	

}	

