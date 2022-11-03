//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma			once

#include		"gy_common_inc.h"

namespace gyeeta {
namespace partha {

extern const char *	gversion;

extern uint32_t		gversion_num, gmin_madhava_version, gmin_shyama_version, gmin_node_version;

static const char * get_version_str() noexcept
{
	return gversion;
}	

static uint32_t get_version_num() noexcept
{
	return gversion_num;
}	

} // namespace partha
} // namespace gyeeta

