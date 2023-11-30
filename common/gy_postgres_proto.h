//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"
#include			"gy_misc.h"

namespace gyeeta {

class postgres_proto 
{
public :

	static tribool is_valid_req(const uint8_t *pdata, uint32_t caplen, uint32_t wirelen) noexcept
	{
		return false;
	}	

	static bool is_valid_resp(const uint8_t *pdata, uint32_t len) noexcept
	{
		return false;
	}	

	static tribool is_valid_req_resp(const uint8_t *pdata, uint32_t caplen, uint32_t wirelen, DirPacket dir) noexcept
	{
		if (dir == DirPacket::DirInbound) {
			return is_valid_req(pdata, caplen, wirelen);
		}	

		return is_valid_resp(pdata, caplen);
	}	

};

} // namespace gyeeta

