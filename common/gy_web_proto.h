//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"

namespace gyeeta {

/*
 * Node Web Protocol formats for use between Node and Shyama/Madhava servers. Some of the content here may not be used by REST API Specs...
 *
 *
 	All Query/Response pairs will have the JSON Query/Response preceded by COMM_HDR and QUERY_CMD/QUERY_RESPONSE headers.
	This is done to enable multiplexing of multiple messages if it is enabled for better performance.

	This implies that if any Error Response occurs, then the QUERY_RESPONSE header will have non 0 respcode_ and then the
	subsequent JSON payload will have the format :

	Generic Error JSON Response format :
	{
		"error"			: 123,
		"errmsg"		: "Invalid Query Parameter specified",
		"madid"			: "6f5d86e5dbff410a"
	}	
 */

enum NODE_MSG_TYPE_E
{
	NODE_MSG_QUERY			= 1,
	NODE_MSG_ADD			= 2,
	NODE_MSG_UPDATE			= 3,
	NODE_MSG_DELETE			= 4,
	NODE_MSG_PING			= 5,
};	

/*
 * All Query Types will be from 1001 to 5000
 * Note that these also include CRUD commands besides normal queries...
 * XXX Ensure this is in sync with Node gyeeta_comm.js NodeQueryTypes
 */
enum NODE_QUERY_TYPE_E
{
	NQUERY_MIN_TYPE				= 1000,

	NQUERY_NS_MADHAVA_LIST			= 1001,
	NQUERY_NM_HOST_STATE			= 1002,
	NQUERY_NM_CPU_MEM			= 1003,
	NQUERY_NM_LISTENER_STATE		= 1004,
	NQUERY_NM_TOP_HOST_PROCS		= 1005,
	NQUERY_NM_TOP_LISTENERS			= 1006,
	NQUERY_NM_LISTENER_INFO			= 1007,
	NQUERY_NM_ACTIVE_CONN			= 1008,
	NQUERY_NM_LISTENER_SUMM			= 1009,
	NQUERY_NM_LISTENPROC_MAP		= 1010,
	NQUERY_NM_CLIENT_CONN			= 1011,
	NQUERY_NM_NOTIFY_MSG			= 1012,
	NQUERY_NM_HOST_INFO			= 1013,
	NQUERY_NM_PROC_INFO			= 1014,
	NQUERY_NM_PROC_STATE			= 1015,
	NQUERY_NM_TOP_AGGR_PROCS		= 1016,
	NQUERY_NM_CLUSTER_STATE			= 1017,
	NQUERY_NS_SVC_MESH_CLUST		= 1018,
	NQUERY_NS_SVC_IP_CLUST			= 1019,
	NQUERY_NS_ALERTS			= 1020,
	NQUERY_NS_ALERTDEF			= 1021,
	NQUERY_NS_INHIBITS			= 1022,
	NQUERY_NS_SILENCES			= 1023,
	NQUERY_NS_ACTIONS			= 1024,
	NQUERY_NM_EXTSVCSTATE			= 1025,
	NQUERY_NM_EXTACTIVECONN			= 1026,
	NQUERY_NM_EXTCLIENTCONN			= 1027,
	NQUERY_NM_EXTPROCSTATE			= 1028,
	NQUERY_NS_SHYAMASTATUS			= 1029,
	NQUERY_NM_MADHAVASTATUS			= 1030,
	NQUERY_NM_PARTHALIST			= 1031,
	NQUERY_NM_TRACEREQ			= 1032,
	NQUERY_NM_TRACECONN			= 1033,
	NQUERY_NM_TRACEUNIQ			= 1034,
	NQUERY_NM_EXTTRACEREQ			= 1035,
	NQUERY_NS_TRACEDEF			= 1036,
	NQUERY_NM_TRACESTATUS			= 1037,
	NQUERY_NM_TRACEHISTORY			= 1038,

	NQUERY_MAX_TYPE,

	NQUERY_NM_MULTI_QUERY			= 5000,

};	


static constexpr size_t				MAX_MULTI_QUERIES	= 8;


} // namespace gyeeta
