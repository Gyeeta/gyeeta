//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_proto_parser.h"
#include			"gy_socket_stat.h"

namespace gyeeta {

SVC_INFO_CAP::SVC_INFO_CAP(const std::shared_ptr<TCP_LISTENER> & listenshr)
	: svcweak_(
	({
		if (!listenshr) {
			GY_THROW_EXCEPTION("Invalid Listen Shared Pointer for API Capture");
		}	
		listenshr;

	})), glob_id_(listenshr->glob_id_), ns_ip_port_(listenshr->ns_ip_port_),
	is_any_ip_(listenshr->is_any_ip_), is_root_netns_(listenshr->is_root_netns_)
{
	GY_STRNCPY(comm_, listenshr->comm_, sizeof(comm_));
}	

bool API_PARSE_HDLR::send_pkt_to_parser(MSG_PKT_SVCCAP & msghdr, const uint8_t *pdata, uint32_t len)
{
	const uint32_t			nfrag = gy_div_round_up(len, MAX_PKT_DATA_LEN);
	uint32_t			i;	
	uint8_t				*pdest, *ptmp;
	
	for (uint32_t i = 0; i < nfrag; ++i) {


	}	

	return true;
}	


void API_PARSE_HDLR::api_parse_rd_thr() noexcept
{

try1 :
	try {
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "API Capture initialized : API Parser thread init completed as well\n");
	

	}
	GY_CATCH_MSG("API Parser Reader Thread exception");

	goto try1;
}	
	
} // namespace gyeeta

