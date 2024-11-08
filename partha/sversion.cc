//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include		"gy_common_inc.h"

namespace gyeeta {
namespace partha {

const char *		gversion = "0.5.1";

const char		gcopyright[] = "Copyright 2024 - present by Exact Solutions, Inc.";

uint32_t		gversion_num 		= get_version_from_string(gversion, 3);

uint32_t		gmin_madhava_version 	= get_version_from_string("0.5.0", 3); 
uint32_t		gmin_shyama_version 	= get_version_from_string("0.5.0", 3); 
uint32_t		gmin_node_version 	= get_version_from_string("0.2.0", 3); 

/*
 * 
 *	Version		Date		Description
 *
 *	0.5.1		Nov 07, 2024	Support for 6.10+ kernels and Optional Host ID from config
 *	0.5.0		Aug 31, 2024	Added support for Request Tracing
 *	0.4.1		May 18, 2023	Support partha-bcc for newer kernels and Aggregation bug fix
 *	0.4.0		Apr 27, 2023	Handling short lived connections and Delay settings
 *	0.3.1		Mar 24, 2023	Service Capture redundancy changes
 *	0.3.0		Mar 15, 2023	Svc Cluster Group enhancements
 *	0.2.0		Jan 10, 2023	BPF CO-RE support and more Host metrics
 *	0.1.1		Nov 17, 2022	Fix for Cloud Metadata
 *	0.1.0		Nov 10, 2022	First Release
 */

} // namespace partha 
} // namespace gyeeta 

