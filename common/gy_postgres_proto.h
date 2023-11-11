//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"
#include			"gy_misc.h"

namespace gyeeta {

class postgres_sessinfo
{
public :

};

class postgres_proto 
{
public :

	static tribool is_valid_req(const uint8_t *pdata, uint32_t caplen, uint32_t actlen) noexcept
	{
		return false;
	}	

	static bool is_valid_resp(const uint8_t *pdata, uint32_t len) noexcept
	{
		return false;
	}	
};

} // namespace gyeeta

