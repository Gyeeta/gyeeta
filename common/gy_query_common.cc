//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_query_common.h"
#include			"gy_comm_proto.h"
#include			"gy_stack_container.h"

using namespace		 	gyeeta::comm;

namespace gyeeta {

static constexpr const char 	*gaggr_oper[] { "sum(", "avg(", "max(", "min(", "percentile(", "count(", "first_elem(", "last_elem(", "bool_or(", "bool_and(" };

SUBSYS_CLASS subsys_class_list[SUBSYS_MAX] =
{
	// jsonstr		subsysval		jsoncrc				pjsonmap		szjsonmap					machidfilstr
	{ "host",		SUBSYS_HOST, 		fnv1_consthash("host"),		json_db_host_arr, 	GY_ARRAY_SIZE(json_db_host_arr),		" %smachid = \'%s\' " },
	{ "hoststate",		SUBSYS_HOSTSTATE, 	fnv1_consthash("hoststate"),	json_db_hoststate_arr,	GY_ARRAY_SIZE(json_db_hoststate_arr),		nullptr },
	{ "cpumem",		SUBSYS_CPUMEM,		fnv1_consthash("cpumem"),	json_db_cpumem_arr,	GY_ARRAY_SIZE(json_db_cpumem_arr),		nullptr },
	{ "svcstate",		SUBSYS_SVCSTATE,	fnv1_consthash("svcstate"),	json_db_svcstate_arr,	GY_ARRAY_SIZE(json_db_svcstate_arr),		nullptr },	
	{ "svcinfo",		SUBSYS_SVCINFO,		fnv1_consthash("svcinfo"),	json_db_svcinfo_arr,	GY_ARRAY_SIZE(json_db_svcinfo_arr),		nullptr },	
	{ "extsvcstate",	SUBSYS_EXTSVCSTATE,	fnv1_consthash("extsvcstate"),	nullptr,		0,						nullptr },
	{ "svcsumm",		SUBSYS_SVCSUMM,		fnv1_consthash("svcsumm"),	json_db_svcsumm_arr,	GY_ARRAY_SIZE(json_db_svcsumm_arr),		nullptr },	
	{ "activeconn",		SUBSYS_ACTIVECONN,	fnv1_consthash("activeconn"),	json_db_activeconn_arr,	GY_ARRAY_SIZE(json_db_activeconn_arr),		nullptr },
	{ "extactiveconn",	SUBSYS_EXTACTIVECONN,	fnv1_consthash("extactiveconn"),nullptr,		0,						nullptr },
	{ "clientconn",		SUBSYS_CLIENTCONN,	fnv1_consthash("clientconn"),	json_db_clientconn_arr,	GY_ARRAY_SIZE(json_db_clientconn_arr),		nullptr },
	{ "extclientconn",	SUBSYS_EXTCLIENTCONN,	fnv1_consthash("extclientconn"),nullptr,		0,						nullptr },
	{ "svcprocmap",		SUBSYS_SVCPROCMAP,	fnv1_consthash("svcprocmap"),	json_db_svcprocmap_arr,	GY_ARRAY_SIZE(json_db_svcprocmap_arr),		nullptr },
	{ "notifymsg",		SUBSYS_NOTIFYMSG,	fnv1_consthash("notifymsg"),	json_db_notifymsg_arr,	GY_ARRAY_SIZE(json_db_notifymsg_arr),		" %smachid = \'%s\' " },
	{ "procstate",		SUBSYS_PROCSTATE,	fnv1_consthash("procstate"),	json_db_procstate_arr,	GY_ARRAY_SIZE(json_db_procstate_arr),		nullptr },
	{ "procinfo",		SUBSYS_PROCINFO,	fnv1_consthash("procinfo"),	json_db_procinfo_arr,	GY_ARRAY_SIZE(json_db_procinfo_arr),		nullptr },
	{ "extprocstate",	SUBSYS_EXTPROCSTATE,	fnv1_consthash("extprocstate"),	nullptr,		0,						nullptr },
	{ "topcpu",		SUBSYS_TOPCPU,		fnv1_consthash("topcpu"),	json_db_topcpu_arr,	GY_ARRAY_SIZE(json_db_topcpu_arr),		nullptr },	
	{ "toppgcpu",		SUBSYS_TOPPGCPU,	fnv1_consthash("toppgcpu"),	json_db_toppgcpu_arr,	GY_ARRAY_SIZE(json_db_toppgcpu_arr),		nullptr },	
	{ "toprss",		SUBSYS_TOPRSS,		fnv1_consthash("toprss"),	json_db_toprss_arr,	GY_ARRAY_SIZE(json_db_toprss_arr),		nullptr },	
	{ "topfork",		SUBSYS_TOPFORK,		fnv1_consthash("topfork"),	json_db_topfork_arr,	GY_ARRAY_SIZE(json_db_topfork_arr),		nullptr },	
	{ "hostinfo",		SUBSYS_HOSTINFO,	fnv1_consthash("hostinfo"),	json_db_hostinfo_arr,	GY_ARRAY_SIZE(json_db_hostinfo_arr),		" %smachid = \'%s\' " },	
	{ "clusterstate",	SUBSYS_CLUSTERSTATE, 	fnv1_consthash("clusterstate"),	json_db_clusterstate_arr, GY_ARRAY_SIZE(json_db_clusterstate_arr), 	nullptr },
	{ "svcmeshclust",	SUBSYS_SVCMESHCLUST, 	fnv1_consthash("svcmeshclust"),	json_db_svcmeshclust_arr, GY_ARRAY_SIZE(json_db_svcmeshclust_arr), 	nullptr },
	{ "svcipclust",		SUBSYS_SVCIPCLUST, 	fnv1_consthash("svcipclust"),	json_db_svcipclust_arr,	GY_ARRAY_SIZE(json_db_svcipclust_arr),		nullptr },
	{ "alerts",		SUBSYS_ALERTS, 		fnv1_consthash("alerts"),	json_db_alerts_arr,	GY_ARRAY_SIZE(json_db_alerts_arr),		nullptr },
	{ "alertdef",		SUBSYS_ALERTDEF,	fnv1_consthash("alertdef"),	json_db_alertdef_arr,	GY_ARRAY_SIZE(json_db_alertdef_arr),		nullptr },
	{ "inhibits",		SUBSYS_INHIBITS, 	fnv1_consthash("inhibits"),	json_db_inhibits_arr,	GY_ARRAY_SIZE(json_db_inhibits_arr),		nullptr },
	{ "silences",		SUBSYS_SILENCES,	fnv1_consthash("silences"),	json_db_silences_arr,	GY_ARRAY_SIZE(json_db_silences_arr),		nullptr },
	{ "actions",		SUBSYS_ACTIONS,		fnv1_consthash("actions"),	json_db_actions_arr,	GY_ARRAY_SIZE(json_db_actions_arr),		nullptr },
	{ "madhavalist",	SUBSYS_MADHAVALIST, 	fnv1_consthash("madhavalist"),	json_db_madhavalist_arr,GY_ARRAY_SIZE(json_db_madhavalist_arr),		nullptr },
	{ "tags",		SUBSYS_TAGS,		fnv1_consthash("tags"),		nullptr,		0,						" %smachid = \'%s\' " },
	{ "shyamastatus",	SUBSYS_SHYAMASTATUS,	fnv1_consthash("shyamastatus"),	nullptr,		0,						nullptr },
	{ "madhavastatus",	SUBSYS_MADHAVASTATUS,	fnv1_consthash("madhavastatus"),nullptr,		0,						nullptr },
	{ "parthalist",		SUBSYS_PARTHALIST,	fnv1_consthash("parthalist"),	json_db_parthalist_arr,	GY_ARRAY_SIZE(json_db_parthalist_arr),		nullptr },
	{ "cgroupstate",	SUBSYS_CGROUPSTATE,	fnv1_consthash("cgroupstate"),	nullptr,		0,						" %smachid = \'%s\' " },
	{ "tracereq",		SUBSYS_TRACEREQ,	fnv1_consthash("tracereq"),	json_db_tracereq_arr,	GY_ARRAY_SIZE(json_db_tracereq_arr),		nullptr },
	{ "exttracereq",	SUBSYS_EXTTRACEREQ,	fnv1_consthash("exttracereq"),	nullptr,		0,						nullptr },
	{ "traceconn",		SUBSYS_TRACECONN,	fnv1_consthash("traceconn"),	json_db_traceconn_arr,	GY_ARRAY_SIZE(json_db_traceconn_arr),		nullptr },
	{ "traceuniq",		SUBSYS_TRACEUNIQ,	fnv1_consthash("traceuniq"),	json_db_traceuniq_arr,	GY_ARRAY_SIZE(json_db_traceuniq_arr),		nullptr },
	{ "tracedef",		SUBSYS_TRACEDEF,	fnv1_consthash("tracedef"),	json_db_tracedef_arr,	GY_ARRAY_SIZE(json_db_tracedef_arr),		nullptr },
	{ "tracestatus",	SUBSYS_TRACESTATUS,	fnv1_consthash("tracestatus"),	json_db_tracestatus_arr,GY_ARRAY_SIZE(json_db_tracestatus_arr),		" %smachid = \'%s\' " },
	{ "tracehistory",	SUBSYS_TRACEHISTORY,	fnv1_consthash("tracehistory"),	json_db_tracehistory_arr,GY_ARRAY_SIZE(json_db_tracehistory_arr),	nullptr },
};	


DB_AGGR_CLASS subsys_aggr_list[SUBSYS_MAX] =
{
	// subsysval		pajsonmap			szajsonmap					paggrinfo			szaggrinfo				minqrysec
	{ SUBSYS_HOST, 		json_db_host_arr, 		GY_ARRAY_SIZE(json_db_host_arr),		host_aggr_info,			GY_ARRAY_SIZE(host_aggr_info),		10 },
	{ SUBSYS_HOSTSTATE, 	json_db_aggr_hoststate_arr, 	GY_ARRAY_SIZE(json_db_aggr_hoststate_arr),	hoststate_aggr_info,		GY_ARRAY_SIZE(hoststate_aggr_info),	10 },
	{ SUBSYS_CPUMEM,	json_db_aggr_cpumem_arr, 	GY_ARRAY_SIZE(json_db_aggr_cpumem_arr),		cpumem_aggr_info,		GY_ARRAY_SIZE(cpumem_aggr_info),	10 },
	{ SUBSYS_SVCSTATE,	json_db_aggr_svcstate_arr, 	GY_ARRAY_SIZE(json_db_aggr_svcstate_arr),	svcstate_aggr_info,		GY_ARRAY_SIZE(svcstate_aggr_info),	10 },
	{ SUBSYS_SVCINFO,	json_db_aggr_svcinfo_arr, 	GY_ARRAY_SIZE(json_db_aggr_svcinfo_arr),	svcinfo_aggr_info,		GY_ARRAY_SIZE(svcinfo_aggr_info),	300 },
	{ SUBSYS_EXTSVCSTATE,	nullptr, /* Update at startup */0,						nullptr,			0,					10 },
	{ SUBSYS_SVCSUMM,	json_db_aggr_svcsumm_arr, 	GY_ARRAY_SIZE(json_db_aggr_svcsumm_arr),	svcsumm_aggr_info,		GY_ARRAY_SIZE(svcsumm_aggr_info),	10 },
	{ SUBSYS_ACTIVECONN,	json_db_aggr_activeconn_arr, 	GY_ARRAY_SIZE(json_db_aggr_activeconn_arr),	activeconn_aggr_info,		GY_ARRAY_SIZE(activeconn_aggr_info),	25 },
	{ SUBSYS_EXTACTIVECONN,	nullptr /* Update at startup */,0,						nullptr,			0,					25 },
	{ SUBSYS_CLIENTCONN,	json_db_aggr_clientconn_arr, 	GY_ARRAY_SIZE(json_db_aggr_clientconn_arr),	clientconn_aggr_info,		GY_ARRAY_SIZE(clientconn_aggr_info),	25 },
	{ SUBSYS_EXTCLIENTCONN,	nullptr, /* Update at startup */0,						nullptr,			0,					25 },
	{ SUBSYS_SVCPROCMAP,	nullptr, 			0,						nullptr,			0,					0 },
	{ SUBSYS_NOTIFYMSG,	nullptr, 			0,						nullptr,			0,					0 },
	{ SUBSYS_PROCSTATE,	json_db_aggr_procstate_arr, 	GY_ARRAY_SIZE(json_db_aggr_procstate_arr),	procstate_aggr_info,		GY_ARRAY_SIZE(procstate_aggr_info),	10 },
	{ SUBSYS_PROCINFO,	json_db_aggr_procinfo_arr, 	GY_ARRAY_SIZE(json_db_aggr_procinfo_arr),	procinfo_aggr_info,		GY_ARRAY_SIZE(procinfo_aggr_info),	300 },
	{ SUBSYS_EXTPROCSTATE,	nullptr, /* Update at startup */0,						nullptr,			0,					10 },
	{ SUBSYS_TOPCPU,	nullptr, 			0,						nullptr,			0,					0 },
	{ SUBSYS_TOPPGCPU,	nullptr, 			0,						nullptr,			0,					0 },
	{ SUBSYS_TOPRSS,	nullptr, 			0,						nullptr,			0,					0 },
	{ SUBSYS_TOPFORK,	nullptr, 			0,						nullptr,			0,					0 },
	{ SUBSYS_HOSTINFO,	json_db_aggr_hostinfo_arr,	GY_ARRAY_SIZE(json_db_aggr_hostinfo_arr),	hostinfo_aggr_info,		GY_ARRAY_SIZE(hostinfo_aggr_info),	60 },
	{ SUBSYS_CLUSTERSTATE, 	json_db_aggr_clusterstate_arr, 	GY_ARRAY_SIZE(json_db_aggr_clusterstate_arr),	clusterstate_aggr_info,		GY_ARRAY_SIZE(clusterstate_aggr_info),	10 },
	{ SUBSYS_SVCMESHCLUST, 	nullptr, 			0,						nullptr,			0,					0 },
	{ SUBSYS_SVCIPCLUST, 	nullptr, 			0,						nullptr,			0,					0 },
	{ SUBSYS_ALERTS, 	json_db_aggr_alerts_arr,	GY_ARRAY_SIZE(json_db_aggr_alerts_arr),		alerts_aggr_info,		GY_ARRAY_SIZE(alerts_aggr_info),	60 },
	{ SUBSYS_ALERTDEF, 	nullptr, 			0,						nullptr,			0,					0 },
	{ SUBSYS_INHIBITS, 	nullptr, 			0,						nullptr,			0,					0 },
	{ SUBSYS_SILENCES, 	nullptr, 			0,						nullptr,			0,					0 },
	{ SUBSYS_ACTIONS, 	nullptr, 			0,						nullptr,			0,					0 },

	{ SUBSYS_MADHAVALIST,	nullptr, 			0,						nullptr,			0,					0 },
	{ SUBSYS_TAGS,		nullptr, 			0,						nullptr,			0,					0 },

	{ SUBSYS_SHYAMASTATUS,	nullptr, 			0,						nullptr,			0,					0 },
	{ SUBSYS_MADHAVASTATUS,	nullptr, 			0,						nullptr,			0,					0 },
	{ SUBSYS_PARTHALIST,	nullptr, 			0,						nullptr,			0,					0 },

	{ SUBSYS_CGROUPSTATE,	nullptr, 			0,						nullptr,			0,					0 },

	{ SUBSYS_TRACEREQ,	nullptr, 			0,						nullptr,			0,					0 },
	{ SUBSYS_EXTTRACEREQ,	nullptr,/* Update at startup */	0,						nullptr,			0,					0 },
	{ SUBSYS_TRACECONN,	nullptr, 			0,						nullptr,			0,					0 },
	{ SUBSYS_TRACEUNIQ,	json_db_aggr_traceuniq_arr, 	GY_ARRAY_SIZE(json_db_aggr_traceuniq_arr),	traceuniq_aggr_info,		GY_ARRAY_SIZE(traceuniq_aggr_info),	3600 },
	{ SUBSYS_TRACEDEF,	nullptr, 			0,						nullptr,			0,					0 },
	{ SUBSYS_TRACESTATUS,	json_db_aggr_tracestatus_arr, 	GY_ARRAY_SIZE(json_db_aggr_tracestatus_arr),	tracestatus_aggr_info,		GY_ARRAY_SIZE(tracestatus_aggr_info),	60 },
	{ SUBSYS_TRACEHISTORY,	nullptr, 			0,						nullptr,			0,					0 },
};	


SUBSYS_STATS subsys_stats_list[SUBSYS_MAX] =
{
	// subsysval		upd_inter_sec			akeytype		ahandler	systype		
	{ SUBSYS_HOST, 		300, 				AKEY_INVALID,		AHDLR_MADHAVA, 	ASYS_HOST,	},
	{ SUBSYS_HOSTSTATE, 	2, 				AKEY_MACHID,		AHDLR_MADHAVA,	ASYS_HOST,	},
	{ SUBSYS_CPUMEM,	2,				AKEY_MACHID,		AHDLR_MADHAVA,	ASYS_HOST,	},
	{ SUBSYS_SVCSTATE,	5,				AKEY_ID,		AHDLR_MADHAVA,	ASYS_PROC_SVC,	},
	{ SUBSYS_SVCINFO,	300,				AKEY_ID,		AHDLR_MADHAVA,	ASYS_PROC_SVC,	},
	{ SUBSYS_EXTSVCSTATE,	5,				AKEY_ID,		AHDLR_MADHAVA,	ASYS_PROC_SVC,	},
	{ SUBSYS_SVCSUMM,	5,				AKEY_MACHID,		AHDLR_MADHAVA,	ASYS_HOST,	},
	{ SUBSYS_ACTIVECONN,	15,				AKEY_ID,		AHDLR_MADHAVA,	ASYS_PROC_SVC,	},
	{ SUBSYS_EXTACTIVECONN,	15,				AKEY_ID,		AHDLR_MADHAVA,	ASYS_PROC_SVC,	},
	{ SUBSYS_CLIENTCONN,	15,				AKEY_ID,		AHDLR_MADHAVA,	ASYS_PROC_SVC,	},
	{ SUBSYS_EXTCLIENTCONN,	15,				AKEY_ID,		AHDLR_MADHAVA,	ASYS_PROC_SVC,	},
	{ SUBSYS_SVCPROCMAP,	300,				AKEY_INVALID,		AHDLR_MADHAVA,	ASYS_PROC_SVC,	},
	{ SUBSYS_NOTIFYMSG,	60,				AKEY_INVALID,		AHDLR_MADHAVA,	ASYS_HOST,	},
	{ SUBSYS_PROCSTATE,	5,				AKEY_ID,		AHDLR_MADHAVA,	ASYS_PROC_SVC,	},
	{ SUBSYS_PROCINFO,	300,				AKEY_ID,		AHDLR_MADHAVA,	ASYS_PROC_SVC,	},
	{ SUBSYS_EXTPROCSTATE,	5,				AKEY_ID,		AHDLR_MADHAVA,	ASYS_PROC_SVC,	},
	{ SUBSYS_TOPCPU,	10,				AKEY_ID,		AHDLR_MADHAVA,	ASYS_PROC_SVC,	},
	{ SUBSYS_TOPPGCPU,	10,				AKEY_ID,		AHDLR_MADHAVA,	ASYS_PROC_SVC,	},
	{ SUBSYS_TOPRSS,	10,				AKEY_ID,		AHDLR_MADHAVA,	ASYS_PROC_SVC,	},
	{ SUBSYS_TOPFORK,	10,				AKEY_ID,		AHDLR_MADHAVA,	ASYS_PROC_SVC,	},
	{ SUBSYS_HOSTINFO,	60,				AKEY_INVALID,		AHDLR_MADHAVA,	ASYS_HOST,	},

	{ SUBSYS_CLUSTERSTATE, 	5,				AKEY_ID,		AHDLR_SHYAMA,	ASYS_CLUSTER,	},
	{ SUBSYS_SVCMESHCLUST, 	300,				AKEY_INVALID,		AHDLR_SHYAMA,	ASYS_CLUSTER,	},
	{ SUBSYS_SVCIPCLUST, 	360,				AKEY_INVALID,		AHDLR_SHYAMA,	ASYS_CLUSTER,	},

	// Alerts on Alerts not yet supported
	{ SUBSYS_ALERTS, 	60,				AKEY_INVALID,		AHDLR_SHYAMA,	ASYS_NONE,	},	
	{ SUBSYS_ALERTDEF, 	60, 				AKEY_INVALID,		AHDLR_SHYAMA,	ASYS_NONE,	},
	{ SUBSYS_INHIBITS, 	60, 				AKEY_INVALID,		AHDLR_SHYAMA,	ASYS_NONE,	},
	{ SUBSYS_SILENCES, 	60, 				AKEY_INVALID,		AHDLR_SHYAMA,	ASYS_NONE,	},
	{ SUBSYS_ACTIONS, 	60, 				AKEY_INVALID,		AHDLR_SHYAMA,	ASYS_NONE,	},

	{ SUBSYS_MADHAVALIST,	60,				AKEY_INVALID,		AHDLR_SHYAMA,	ASYS_NONE,	},
	{ SUBSYS_TAGS,		60,				AKEY_INVALID,		AHDLR_SHYAMA,	ASYS_NONE,	},

	{ SUBSYS_SHYAMASTATUS,	60,				AKEY_INVALID,		AHDLR_SHYAMA,	ASYS_NONE,	},
	{ SUBSYS_MADHAVASTATUS,	60,				AKEY_INVALID,		AHDLR_MADHAVA,	ASYS_NONE,	},
	{ SUBSYS_PARTHALIST,	60,				AKEY_INVALID,		AHDLR_MADHAVA,	ASYS_NONE,	},

	{ SUBSYS_CGROUPSTATE,	15,				AKEY_INVALID,		AHDLR_PARTHA,	ASYS_PROC_SVC,	},	// Invalid till its implemented

	{ SUBSYS_TRACEREQ,	5,				AKEY_INVALID,		AHDLR_MADHAVA,	ASYS_PROC_SVC,	},
	{ SUBSYS_EXTTRACEREQ,	5,				AKEY_INVALID,		AHDLR_MADHAVA,	ASYS_PROC_SVC,	},
	{ SUBSYS_TRACECONN,	5,				AKEY_INVALID,		AHDLR_MADHAVA,	ASYS_PROC_SVC,	},
	{ SUBSYS_TRACEUNIQ,	3600,				AKEY_INVALID,		AHDLR_MADHAVA,	ASYS_PROC_SVC,	},
	{ SUBSYS_TRACEDEF,	60,				AKEY_INVALID,		AHDLR_SHYAMA,	ASYS_NONE,	},
	{ SUBSYS_TRACESTATUS,	60,				AKEY_INVALID,		AHDLR_MADHAVA,	ASYS_NONE,	},
	{ SUBSYS_TRACEHISTORY,	60,				AKEY_INVALID,		AHDLR_MADHAVA,	ASYS_NONE,	},
};	


QUERY_OPTIONS::QUERY_OPTIONS(const GEN_JSON_VALUE & jdoc, EXT_POOL_ALLOC & extpool, bool is_multiquery, uint32_t multiquery_index, bool allocregex, const SUBSYS_CLASS_E *pfixedsubsys)
	: pjsonobj_(std::addressof(jdoc)), is_multiquery_(is_multiquery)
{
	if (false == jdoc.IsObject()) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Query Params : Not of a JSON Object type");
	}	

	time_t				tcurr = time(nullptr);
	decltype(jdoc.FindMember(""))	siter, oiter, jiter, titer;
	const GEN_JSON_VALUE		*pfilteropt = &jdoc;

	*starttime_	= 0;
	*endtime_	= 0;
	maxrecs_	= MAX_JSON_RECORDS;

	try {
		if (is_multiquery_) {
			siter = jdoc.FindMember("multiqueryarr");
			
			if ((siter == jdoc.MemberEnd()) || (false == siter->value.IsArray())) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Multiquery type specified but not present in params");
			}	
			
			if (multiquery_index >= siter->value.Size()) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Multiquery type index specified %u out of bounds", multiquery_index);
			}	

			if (false == siter->value[multiquery_index].IsObject()) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Options : Multiquery type : Element not of object type");
			}	

			nmulti_queries_ 	= siter->value.Size();
			multiquery_index_	= multiquery_index;

			pfilteropt 		= &siter->value[multiquery_index];

			const auto &		mobj = siter->value[multiquery_index].GetObject();
				
			jiter = mobj.FindMember("qid");

			if ((jiter == mobj.MemberEnd()) || (false == jiter->value.IsString())) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Options : Multiquery type : Element object missing qid field");
			}	
			
			GY_STRNCPY(multiqueryid_, jiter->value.GetString(), sizeof(multiqueryid_));
		}	

		siter = jdoc.FindMember("starttime");
		titer = jdoc.FindMember("timeoffsetsec"); 

		if ((siter != jdoc.MemberEnd()) && (siter->value.IsString())) {
			const char		*pstarttime, *pendtime;

			pstarttime = siter->value.GetString();

			tvstart_ = gy_iso8601_to_timeval(pstarttime);
			
			if (tvstart_.tv_sec == 0) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Invalid starttime \'%s\' specified", pstarttime);
			}

			siter = jdoc.FindMember("endtime");

			if ((siter != jdoc.MemberEnd()) && (siter->value.IsString())) {

				pendtime = siter->value.GetString();

				tvend_ = gy_iso8601_to_timeval(pendtime);

				if (tvend_.tv_sec < tvstart_.tv_sec) {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Invalid endtime specified : endtime is less than starttime");
				}	
			}	
			else {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Missing parameter : endtime is not specified");
			}

			if (tvstart_.tv_sec > tcurr + 10) {
				if (tvstart_.tv_sec >= tcurr + 60) {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Invalid starttime specified : starttime \'%s\' is %ld seconds in future", 
								pstarttime, tvstart_.tv_sec - tcurr);
				}

				tvstart_ = {};
				goto setcurr1;
			}	

			if (tvstart_.tv_sec > tcurr - 3) {
				is_historical_ = false;
			}	
			else {
				is_historical_ = true;

				siter = jdoc.FindMember("pointintime");
				if ((siter != jdoc.MemberEnd()) && (siter->value.IsBool())) {
					point_in_time_ = siter->value.GetBool();
				}	
			}	

			GY_STRNCPY(starttime_, pstarttime, sizeof(starttime_));
			GY_STRNCPY(endtime_, pendtime, sizeof(endtime_));
		}	
		else if (titer != jdoc.MemberEnd() && titer->value.IsInt()) {
			int		timeoffsetsec = titer->value.GetInt();
			
			if (timeoffsetsec < 0) {
				timeoffsetsec = -timeoffsetsec;
			}

			if (timeoffsetsec >= 10 && timeoffsetsec < 2 * 365 * 24 * 3600) {
				is_historical_ = true;
				
				tvstart_ = {tcurr - timeoffsetsec, 0};
				tvend_ = {tcurr, 0};
				
				snprintf(starttime_, sizeof(starttime_), "to_timestamp(%ld)", tvstart_.tv_sec);
				snprintf(endtime_, sizeof(endtime_), "to_timestamp(%ld)", tvend_.tv_sec);
			}
			else {
				goto setcurr1;
			}	
		}	
		else {
setcurr1 :		
			is_historical_ = false;
		}	

		jiter = jdoc.FindMember("parid");

		if ((jiter != jdoc.MemberEnd()) && (jiter->value.IsString())) {
			const char		*pmachstr = jiter->value.GetString();			

			if (false == parid_.set_from_string(pmachstr, jiter->value.GetStringLength(), false /* throw_on_error */)) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Invalid Partha ID Specified in \'parid\' parameter");
			}	
			
			is_multihost_ = false;
		}	
		else {
			is_multihost_ = true;
		}	

		qtype_ = gy_get_json_qtype(*pfilteropt, "Invalid Query Params", !!pfixedsubsys /* is_noexcept */);

		if (!pfixedsubsys || int(*pfixedsubsys) >= SUBSYS_MAX) {
			nsubsys_ = upd_subsys_from_qtype(qtype_, pallowed_subsys_arr_, GY_ARRAY_SIZE(pallowed_subsys_arr_) - 1);

			if (nsubsys_ == 0) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params :  Query Type %u not valid for a DB Query", qtype_);
			}	
		}
		else {
			pallowed_subsys_arr_[0]		= *pfixedsubsys;
			nsubsys_ 			= 1;
		}	

		pdefsubsys_ = get_subsys_info(pallowed_subsys_arr_[0]);
		if (!pdefsubsys_) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query options : Invalid subsystem specified for allowed subsys list");
		}

		if (pdefsubsys_->machidfilstr == nullptr) {
			pallowed_subsys_arr_[nsubsys_++]	= SUBSYS_HOST;
		}
		else {
			is_multihost_ = false;
		}	

		const auto				*phostsubsys = get_subsys_info(SUBSYS_HOST);
		const auto				*phostjsonmap = json_db_host_arr;
		size_t					szhostjsonmap = is_multihost_ ? GY_ARRAY_SIZE(json_db_host_arr) : 0;

		// Get "filter", "options" and "aggrfilter" either from jdoc or pfilteropt in case of multiquery
		oiter = pfilteropt->FindMember("options");

		if ((oiter != pfilteropt->MemberEnd()) && (!oiter->value.IsObject())) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : \'options\' field not of Object type within json");
		}
		else if ((oiter != pfilteropt->MemberEnd())) {
			const auto	& optobj = oiter->value.GetObject();

			poptjson_ 	= std::addressof(oiter->value);

			/*
			 * For use with multiquery where a group of madfilterarr was specified
			 */
			siter = optobj.FindMember("madid");
			if ((siter != optobj.MemberEnd()) && (siter->value.IsString())) {

				if (siter->value.GetStringLength() != 16) {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Invalid Madhava ID Specified in \'madid\' options parameter");
				}

				std::memcpy(madid_opt_, siter->value.GetString(), 16);
				madid_opt_[16] = 0;

				is_madid_opt_ = true;
			}	

			siter = optobj.FindMember("maxrecs");
			if ((siter != optobj.MemberEnd()) && (siter->value.IsUint())) {
				maxrecs_ = siter->value.GetUint();

				if (maxrecs_ > MAX_JSON_RECORDS || maxrecs_ == 0) {
					maxrecs_ = MAX_JSON_RECORDS;
				}	
			}	

			siter = optobj.FindMember("recoffset");
			if ((siter != optobj.MemberEnd()) && (siter->value.IsUint())) {
				recoffset_ = siter->value.GetUint();
			}	

			siter = optobj.FindMember("aggregate");

			if ((siter != optobj.MemberEnd()) && (siter->value.IsBool())) {
				is_aggregated_ = siter->value.GetBool();

				if (is_aggregated_ && (true == is_historical()) && (true == is_pointintime())) {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Aggregation requested but Point in Time \'pointintime\' option set. "
							"Aggregation cannot be done on a single time record");
				}

				if (is_aggregated_ && tvend_.tv_sec < tvstart_.tv_sec + 15) {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Aggregation requested but time duration less than minimum which is 15 sec. "
							"Please increase the time duration of the query");
				}
			}	

			if (is_aggregated_) {
				auto			*pdbarg = get_subsys_aggr_info(pallowed_subsys_arr_[0]);

				if (!pdbarg || pdbarg->pajsonmap == nullptr) {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Aggregation not supported for the query subsystem \'%s\' specified", 
						get_subsys_info(pallowed_subsys_arr_[0]) ? get_subsys_info(pallowed_subsys_arr_[0])->jsonstr : "");
				}

				siter = optobj.FindMember("aggrsec");
				if ((siter != optobj.MemberEnd()) && (siter->value.IsNumber())) {
					aggr_dur_sec_ = (int)siter->value.GetDouble();
				}

				siter = optobj.FindMember("aggroper");
				if ((siter != optobj.MemberEnd()) && (siter->value.IsString())) {
					const char		*poper = siter->value.GetString();

					if (0 == strcasecmp(poper, "sum")) {
						aggr_oper_	= AOPER_SUM;
					}	
					else if (0 == strcasecmp(poper, "avg")) {
						aggr_oper_ 	= AOPER_AVG;
					}	
					else if (0 == strcasecmp(poper, "max")) {
						aggr_oper_	= AOPER_MAX;
					}	
					else if (0 == strcasecmp(poper, "min")) {
						aggr_oper_	= AOPER_MIN;
					}	
				}

				siter = optobj.FindMember("columns");
				if ((siter != optobj.MemberEnd()) && (siter->value.IsArray())) {

					if (siter->value.Size() > MAX_CUST_COLUMNS) {
						GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Custom Aggregated Column List specified but Max number of custom columns %lu exceeded : %u", 
								MAX_CUST_COLUMNS, siter->value.Size());
					}

					naggr_column_spec_ 	= siter->value.Size();

					if (naggr_column_spec_) {
						paggrstrbuf_	= (char *)extpool.safe_malloc(MAX_AGGR_COL_BUFSZ, paggrbuf_free_fp_, maxstrbufsz_);
					}
				}	
				else if (siter != optobj.MemberEnd()) {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Aggregation Custom Columns field \'columns\' not in JSON Array format");
				}	
				else {
					naggr_column_spec_ 	= 0;
				}	
			}	
			else {
				const char		*colname;
				const auto		*pjsonmap = pdefsubsys_->pjsonmap;
				size_t			szjsonmap = pdefsubsys_->szjsonmap;
				bool			ishost;

				siter = optobj.FindMember("columns");
				if ((siter != optobj.MemberEnd()) && (siter->value.IsArray())) {

					if (siter->value.Size() > MAX_CUST_COLUMNS) {
						GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Custom Column List specified but max number of custom columns %lu exceeded : %u", 
								MAX_CUST_COLUMNS, siter->value.Size());
					}

					// Allocate more than specified columns to add szhostjsonmap entries if needed externally
					columnarr_ 	= (const JSON_DB_MAPPING **)extpool.safe_malloc((siter->value.Size() + szhostjsonmap) * sizeof(const JSON_DB_MAPPING *), col_free_fp_);
					ncols_ 		= 0;

					for (uint32_t i = 0; i < siter->value.Size(); i++) {
						if (false == siter->value[i].IsString()) {
							GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Invalid Column Name : Not of a string type specified");
						}	
						
						ishost 	= false;
						colname = siter->value[i].GetString();

						const auto		*pcol = get_jsoncrc_mapping(colname, siter->value[i].GetStringLength(), pjsonmap, szjsonmap);
						
						if (!pcol) {
							if (szhostjsonmap) {
								pcol = get_jsoncrc_mapping(colname, siter->value[i].GetStringLength(), phostjsonmap, szhostjsonmap);
							}

							if (!pcol) {
								if (has_aggr_oper(colname)) {
									GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Aggregation Operator specified for \'%s\' : "
													"Please set aggregation options within the query", colname);
								}	
								GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Invalid Column Name \'%s\' specified", colname);
							}
							else {
								ishost = true;
							}	
						}	

						if (is_historical() && pcol->dbcolname[0] == 0) {
							GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Column Name \'%s\' specified not present in DB schema. "
													"Cannot be used for historical queries", colname);
						}	
							
						/*
						 * NOTE : We currently ignore host columns addition as they are added mandatorily anyways
						 */
						if (!ishost) { 
							columnarr_[ncols_++] = pcol;
						}
					}
				}	
				else if (siter != optobj.MemberEnd()) {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Options : Invalid \'columns\' field type : Needs to be an Array");
				}	

				set_sort_options(pjsonmap, szjsonmap, phostjsonmap, szhostjsonmap, pdefsubsys_, phostsubsys);

				if (recoffset_ > 0 && nsort_ == 0) {
					DEBUGEXECN(15, 
						WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "DB Offset option specified without any sort order. Resultset may overlap...\n");
					);	
				}	
			}

			auto			fiter = optobj.FindMember("filter");

			if (fiter != optobj.MemberEnd()) {
				if (!fiter->value.IsString()) {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : \'filter\' field not of String type");
				}	

				pfilterjson_ = std::addressof(fiter->value);

				criteria_ = CRITERIA_SET(fiter->value.GetString(), fiter->value.GetStringLength(), pallowed_subsys_arr_[0], 
									&extpool, is_multihost_ /* check_multihost */, allocregex);
			}

		}

		auto			fiter = pfilteropt->FindMember("filter");

		if (fiter != pfilteropt->MemberEnd()) {
			if (pfilterjson_) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : \'filter\' field seen both within \'options\' object and by itself as well : Please use one of the two");
			}

			if (!fiter->value.IsString()) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : \'filter\' field not of String type");
			}	

			pfilterjson_ = std::addressof(fiter->value);

			criteria_ = CRITERIA_SET(fiter->value.GetString(), fiter->value.GetStringLength(), pallowed_subsys_arr_[0], 
								&extpool, is_multihost_ /* check_multihost */, allocregex);
		}

		is_valid_ = true;
	}
	catch(...) {
		destroy();
		throw;
	}
}	

void QUERY_OPTIONS::set_max_records(size_t newmax) noexcept
{
	if (newmax <= MAX_JSON_RECORDS && newmax > 0) {
		maxrecs_ = newmax;
	}	
}	

bool QUERY_OPTIONS::has_aggr_oper(const char *colname) noexcept
{

	if (nullptr == strchr(colname, '(')) {
		return false;
	}	

	for (size_t i = 0; i < GY_ARRAY_SIZE(gaggr_oper); ++i) {
		if (strstr(colname, gaggr_oper[i])) {
			return true;
		}	
	}	

	return false;
}	

char * QUERY_OPTIONS::get_db_select_query(STR_WR_BUF & strbuf, SUBSYS_CLASS_E subsys, const char *tablename, const char *table_alias_prefix, bool ign_col_list) const
{
	if (!is_valid_) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid DB Query Options object");
	}	

	if (subsys >= SUBSYS_MAX) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid subsystem %d specified for select query creation", (int)subsys);
	}	

	if (*table_alias_prefix) {
		assert(table_alias_prefix[strlen(table_alias_prefix) - 1] == '.');
	}	

	char			tabalias[128];

	if (*table_alias_prefix) {
		size_t		slen = strlen(table_alias_prefix);

		if (slen >= sizeof(tabalias)) {
			slen = sizeof(tabalias) - 1;
		}	

		if (table_alias_prefix[slen - 1] == '.') {
			slen--;
		}	

		std::memcpy(tabalias, table_alias_prefix, slen);
		tabalias[slen] = 0;
	}	
	else {
		*tabalias = 0;
	}	

	strbuf.appendconst(" select ");
	
	get_db_table_columns(strbuf, subsys, table_alias_prefix, ign_col_list);
	
	strbuf.appendfmt(" from %s %s ", tablename, tabalias);

	get_db_where_clause(strbuf, subsys, tablename, "", table_alias_prefix, false /* add_multihost_subsys */);
	get_db_sort_limit(strbuf, subsys, table_alias_prefix);

	if (strbuf.is_overflow()) {
		GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "[Internal Error]: DB query buffer overflow encountered while creating DB query : Please reduce the criteria parameters");
	}

	CONDEXEC(
		DEBUGEXECN(11,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Postgres Single Host Select Query is : \"%s\"\n", strbuf.buffer());
		);
	);

	return strbuf.buffer();
}	

char * QUERY_OPTIONS::get_db_select_multihost_query(STR_WR_BUF & strbuf, SUBSYS_CLASS_E subsys, const char *tablename, const char *datetbl, bool ign_col_list) const
{
	if (!is_valid_) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid DB Query Options object");
	}	

	if (subsys >= SUBSYS_MAX || subsys == SUBSYS_HOST) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid subsystem %d specified for multihost query creation", (int)subsys);
	}	

	if (AHDLR_MADHAVA != get_subsys_handler(subsys)) {
		GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "[Internal Error] : Multihost Query called for Subsystem \'%s\' not handled by Madhava", 
					get_subsys_info(subsys) ? get_subsys_info(subsys)->jsonstr : "");
	}	

	strbuf.appendconst(" select * from (select * from gy_multihostselect( $a$ ");

	get_db_where_clause(strbuf, SUBSYS_HOST, tablename, datetbl, "");

	strbuf.appendfmt(" $a$, \'%s\', \'%s\', \'tbl\', \'", tablename, datetbl);
	
	get_db_table_columns(strbuf, subsys, "tbl.", ign_col_list);

	strbuf << " \', $b$ "sv;

	get_db_where_clause(strbuf, subsys, tablename, datetbl, "tbl.", true /* add_multihost_subsys */);

	get_db_sort_limit(strbuf, subsys, "tbl.", true /* ignorelimit */, false /* ignoresort */, true /* ignoffset */);

	if (maxrecs_) {
		strbuf.appendfmt(" limit %lu ", maxrecs_ + recoffset_);
	}

	if (maxrecs_ > 0) {
		strbuf.appendfmt(" $b$, %lu) as (machid char(32), hostname text, madhavaid char(16), clustername text,", maxrecs_ + recoffset_);
	}
	else {
		strbuf.appendconst(" $b$ ) as (machid char(32), hostname text, madhavaid char(16), clustername text,");
	}

	size_t			ncol;
	
	ncol = get_db_column_definition(strbuf, subsys, ign_col_list);

	if (ncol == 0) {
		strbuf.set_last_char(' ');
	}

	const char		*pqtbl = pdefsubsys_ ? pdefsubsys_->jsonstr : "qtbl";

	strbuf << " ) ) "sv << pqtbl << ' ';

	get_db_sort_limit(strbuf, subsys);

	if (strbuf.is_overflow()) {
		GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "[Internal Error]: DB Multi Host Query buffer overflow seen : Please reduce the criteria parameters");
	}	

	CONDEXEC(
		DEBUGEXECN(11,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Postgres Multi Host Select Query is : \"%s\"\n", strbuf.buffer());
		);
	);

	return strbuf.buffer();
}


char * QUERY_OPTIONS::get_date_trunc_str(STR_WR_BUF & strbuf) noexcept
{
	if (aggr_dur_sec_ > tvend_.tv_sec - tvstart_.tv_sec + 1) {
		// Clamp time to starttime_
		return strbuf.appendfmt(" \'%s\'::timestamptz ", gy_localtime_iso8601_sec(tvstart_.tv_sec, "%F %H:%M:%S").get());
	}	

	return get_db_date_trunc(strbuf, aggr_dur_sec_);
}	

uint32_t QUERY_OPTIONS::get_select_aggr_query(STR_WR_BUF & strbuf, SUBSYS_CLASS_E subsys, JSON_DB_MAPPING (& pcolarr)[MAX_AGGR_COLUMNS], const char *tablename, const char * extra_inner_where, EXT_POOL_ALLOC *pstrpool)
{
	const auto			*poption = get_options_json();
	
	if (!poption || !pdefsubsys_) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Aggregation not supported as no option specified");
	}	

	auto				*pdbarg = get_subsys_aggr_info(subsys);

	if (!pdbarg || pdbarg->pajsonmap == nullptr || pdbarg->paggrinfo == nullptr) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Aggregation not supported for the subsystem \'%s\' specified", get_subsys_info(subsys) ? get_subsys_info(subsys)->jsonstr : "");
	}

	const auto			*phostsubsys = get_subsys_info(SUBSYS_HOST);
	const auto			*pajsonmap = pdbarg->pajsonmap;
	const auto			*paggrinfo = pdbarg->paggrinfo;
	const auto			*phostjsonmap = json_db_host_arr;
	const uint32_t			szhostjsonmap = 0;
	uint32_t			szajsonmap = pdbarg->szajsonmap, szaggrinfo = pdbarg->szaggrinfo, noutcol = 0, nincol = 0, npostcol = 0, ngrpby = 0;

	if (!naggr_column_spec_) {
		// Default aggregation oper
		
		strbuf.appendconst(" select * from (select ");

		uint32_t 		istart = 0;

		if (aggr_dur_sec_ && (pajsonmap[0].jsoncrc == FIELD_TIME || pajsonmap[0].jsoncrc == FIELD_ALERTTIME)) {

			get_date_trunc_str(strbuf);
			strbuf << " as atime, "sv;

			pcolarr[noutcol++] = pajsonmap[0];
			istart++;
		}	
		else if (pajsonmap[0].jsoncrc == FIELD_TIME || pajsonmap[0].jsoncrc == FIELD_ALERTTIME) {
			istart++;
		}	
		
		for (uint32_t i = istart; i < szaggrinfo; ++i) {
			auto		paggr = paggrinfo + i;

			if (paggr->dbexpr[0] == '%') {
				strbuf.appendfmt(paggr->dbexpr, get_aggr_oper_str(paggr->dflt_aggr, paggr->ignore_sum));
			}
			else {
				strbuf.append(paggr->dbexpr);
			}	
			
			pcolarr[noutcol++] = pajsonmap[i];

			if (i + 1 < szaggrinfo) {
				strbuf << ", "sv;
			}	
		}

		strbuf.appendfmt(" from %s ", tablename);

		get_db_where_clause(strbuf, subsys, tablename, "", "", false /* add_multihost_subsys */);
		
		strbuf << extra_inner_where << ' ';

		if (aggr_dur_sec_ && (pajsonmap[0].jsoncrc == FIELD_TIME || pajsonmap[0].jsoncrc == FIELD_ALERTTIME)) {

			strbuf << " group by atime "sv;
			ngrpby = 1;
		}

		for (uint32_t i = istart; i < szaggrinfo; ++i) {
			auto			paggr = paggrinfo + i;

			if (paggr->dflt_aggr != AOPER_GROUPBY) {
				continue;
			}

			if (ngrpby > 0) {
				strbuf << ", "sv;
			}	
			else {
				strbuf << " group by "sv;
			}

			ngrpby++;

			strbuf.append(paggr->dbfieldname);
		}

		strbuf << " ) "sv << pdefsubsys_->jsonstr << ' ';
		
		set_aggr_where_clause(strbuf, pcolarr, noutcol);

		set_sort_options(pajsonmap, szajsonmap, phostjsonmap, szhostjsonmap, pdefsubsys_, phostsubsys);

		if (aggr_dur_sec_) {
			set_sort_column("atime", SORT_DIR_ASC, pajsonmap, szajsonmap, phostjsonmap, szhostjsonmap, pdefsubsys_, phostsubsys);
		}	

		get_db_sort_limit(strbuf, subsys);

		if (strbuf.is_overflow()) {
			GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "[Internal Error]: DB Single Host Aggregated Query buffer overflow seen : Please reduce the criteria parameters");
		}	

		CONDEXEC(
			DEBUGEXECN(11,
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Postgres Single Host Default Aggregated Query is : \"%s\"\n", strbuf.buffer());
			);
		);

		return noutcol;
	}

	assert(gy_get_thread_local().get_thread_stack_freespace() >= 150 * 1024);

	DB_AGGR_INFO			dbinnerarr[MAX_AGGR_COLUMNS], dbouterarr[MAX_AGGR_COLUMNS], dbpostaggrarr[MAX_AGGR_COLUMNS];
	std::optional<EXT_POOL_ALLOC>	strpool;
	
	if (pstrpool == nullptr) {
		strpool.emplace(paggrstrbuf_, maxstrbufsz_, nullptr, true /* noheap_alloc */);
		pstrpool = std::addressof(strpool.value());
	}

	auto t = get_custom_aggr_columns(subsys, pajsonmap, szajsonmap, phostjsonmap, szhostjsonmap, paggrinfo, pcolarr, dbinnerarr, dbouterarr, dbpostaggrarr, *pstrpool);

	noutcol		= std::get<0>(t);
	nincol		= std::get<1>(t);
	npostcol	= std::get<2>(t);

	if (npostcol == 0) {
		return 0;
	}

	strbuf << " select * from (select "sv;

	aggr_column_query(strbuf, dbpostaggrarr, npostcol);
	
	strbuf << " from ( select "sv;
	
	aggr_column_query(strbuf, dbouterarr, noutcol);

	strbuf << " from ( select "sv;

	aggr_column_query(strbuf, dbinnerarr, nincol);

	strbuf.appendfmt(" from %s ", tablename);

	get_db_where_clause(strbuf, subsys, tablename, "", "", false /* add_multihost_subsys */);
		
	strbuf << extra_inner_where << ' ';

	aggr_groupby_query(strbuf, dbinnerarr, nincol);

	strbuf << " ) s "sv;

	aggr_groupby_query(strbuf, dbouterarr, noutcol);

	strbuf << " ) ss ) "sv << pdefsubsys_->jsonstr << ' ';

	set_aggr_where_clause(strbuf, pcolarr, npostcol);

	set_sort_options(pcolarr, npostcol, phostjsonmap, 0, pdefsubsys_, nullptr);

	get_db_sort_limit(strbuf, subsys);

	if (strbuf.is_overflow()) {
		GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "[Internal Error]: DB Single Host Custom Column Aggregated Query buffer overflow seen : Please reduce the criteria parameters");
	}	

	CONDEXEC(
		DEBUGEXECN(11,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Postgres Single Host Custom Column Aggregated Query is : \"%s\"\n", strbuf.buffer());
		);
	);

	return npostcol;
}

uint32_t QUERY_OPTIONS::get_select_aggr_multihost_query(STR_WR_BUF & strbuf, SUBSYS_CLASS_E subsys, JSON_DB_MAPPING (& pcolarr)[MAX_AGGR_COLUMNS], const char *tablename, const char *datetbl, const char * extra_inner_where, EXT_POOL_ALLOC *pstrpool)
{
	const auto			*poption = get_options_json();
	
	if (!poption || !pdefsubsys_) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Aggregation not supported as no option specified");
	}	

	auto				*pdbarg = get_subsys_aggr_info(subsys);

	if (!pdbarg || pdbarg->pajsonmap == nullptr || pdbarg->paggrinfo == nullptr) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Aggregation not supported for the subsystem \'%s\' specified", get_subsys_info(subsys) ? get_subsys_info(subsys)->jsonstr : "");
	}

	if (AHDLR_MADHAVA != get_subsys_handler(subsys)) {
		GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "[Internal Error] : Multihost Aggregation called for Subsystem \'%s\' not handled by Madhava", 
					get_subsys_info(subsys) ? get_subsys_info(subsys)->jsonstr : "");
	}	

	const auto			*pajsonmap = pdbarg->pajsonmap;
	const auto			*paggrinfo = pdbarg->paggrinfo, *phostaggrinfo = host_aggr_info;
	const auto			*phostjsonmap = json_db_host_arr;
	const uint32_t			szhostjsonmap = GY_ARRAY_SIZE(json_db_host_arr);
	const auto			*phostsubsys = get_subsys_info(SUBSYS_HOST);
	uint32_t			szajsonmap = pdbarg->szajsonmap, szaggrinfo = pdbarg->szaggrinfo, noutcol = 0, nincol = 0, npostcol = 0, ngrpby = 0;

	if (!naggr_column_spec_) {
		// Default aggregation oper
		
		for (uint32_t i = 0; i < szhostjsonmap; ++i) {
			pcolarr[i] 	= json_db_host_arr[i];
		}
		noutcol			= szhostjsonmap;

		strbuf.appendconst(" select * from (select * from gy_multihostselect( $a$ ");

		get_db_where_clause(strbuf, SUBSYS_HOST, tablename, datetbl, "");

		strbuf.appendfmt(" $a$, \'%s\', \'%s\', \'tbl\',  $a$ ", tablename, datetbl);

		uint32_t 		istart = 0;

		if (aggr_dur_sec_ && (pajsonmap[0].jsoncrc == FIELD_TIME || pajsonmap[0].jsoncrc == FIELD_ALERTTIME)) {

			get_date_trunc_str(strbuf);
			strbuf << " as atime, "sv;

			pcolarr[noutcol++] = pajsonmap[0];

			istart++;
		}	
		else if (pajsonmap[0].jsoncrc == FIELD_TIME || pajsonmap[0].jsoncrc == FIELD_ALERTTIME) {
			istart++;
		}	
		
		for (uint32_t i = istart; i < szaggrinfo; ++i) {
			auto		paggr = paggrinfo + i;

			if (paggr->dbexpr[0] == '%') {
				strbuf.appendfmt(paggr->dbexpr, get_aggr_oper_str(paggr->dflt_aggr, paggr->ignore_sum));
			}
			else {
				strbuf.append(paggr->dbexpr);
			}	
			
			pcolarr[noutcol++] = pajsonmap[i];

			if (i + 1 < szaggrinfo) {
				strbuf << ", "sv;
			}	
		}

		strbuf << " $a$ , $b$ "sv;

		get_db_where_clause(strbuf, subsys, tablename, datetbl, "tbl.", true /* add_multihost_subsys */);

		strbuf << extra_inner_where << ' ';

		if (aggr_dur_sec_ && (pajsonmap[0].jsoncrc == FIELD_TIME || pajsonmap[0].jsoncrc == FIELD_ALERTTIME)) {

			strbuf << " group by atime "sv;
			ngrpby = 1;
		}

		for (uint32_t i = istart; i < szaggrinfo; ++i) {
			auto			paggr = paggrinfo + i;

			if (paggr->dflt_aggr != AOPER_GROUPBY) {
				continue;
			}

			if (ngrpby > 0) {
				strbuf << ", "sv;
			}	
			else {
				strbuf << " group by "sv;
			}

			ngrpby++;

			strbuf.append(paggr->dbfieldname);
		}

		for (uint32_t i = 0; i < szhostjsonmap; ++i) {
			auto			paggr = phostaggrinfo + i;

			if (paggr->dflt_aggr != AOPER_GROUPBY) {
				continue;
			}

			if (ngrpby > 0) {
				strbuf << ", "sv;
			}	
			else {
				strbuf << " group by "sv;
			}

			ngrpby++;

			strbuf.append(paggr->dbfieldname);
		}

		strbuf << " $b$, 50000) as ("sv;

		for (uint32_t i = 0; i < szhostjsonmap; ++i) {
			strbuf << phostaggrinfo[i].dbfieldname << ' ' << phostaggrinfo[i].dbfieldtype << ',';
		}	

		if (aggr_dur_sec_ && (pajsonmap[0].jsoncrc == FIELD_TIME || pajsonmap[0].jsoncrc == FIELD_ALERTTIME)) {
			strbuf << "atime timestamptz,"sv;
		}

		for (uint32_t i = istart; i < szaggrinfo; ++i) {
			strbuf << paggrinfo[i].dbfieldname << ' ' << paggrinfo[i].dbfieldtype << ',';
		}

		strbuf.set_last_char(')');

		strbuf << " limit 100000 "sv;

		strbuf << " ) "sv << pdefsubsys_->jsonstr << ' ';

		set_aggr_where_clause(strbuf, pcolarr, noutcol);

		set_sort_options(pajsonmap, szajsonmap, phostjsonmap, szhostjsonmap, pdefsubsys_, phostsubsys);

		if (aggr_dur_sec_) {
			set_sort_column("atime", SORT_DIR_ASC, pajsonmap, szajsonmap, phostjsonmap, szhostjsonmap, pdefsubsys_, phostsubsys);
		}	

		get_db_sort_limit(strbuf, subsys);

		if (strbuf.is_overflow()) {
			GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "[Internal Error]: DB Multi Host Aggregated Query buffer overflow seen : Please reduce the criteria parameters");
		}	

		CONDEXEC(
			DEBUGEXECN(11,
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Postgres Multi Host Default Aggregated Query is : \"%s\"\n", strbuf.buffer());
			);
		);

		return noutcol;
	}

	assert(gy_get_thread_local().get_thread_stack_freespace() >= 150 * 1024);

	DB_AGGR_INFO			dbinnerarr[MAX_AGGR_COLUMNS], dbouterarr[MAX_AGGR_COLUMNS], dbpostaggrarr[MAX_AGGR_COLUMNS];

	/*
	 * TODO : Currently Multi Madhava Aggregation is not enabled.
	 */
	/*bool				multi_madhava_aggr = to_enable_multi_madhava_aggr();*/

	std::optional<EXT_POOL_ALLOC>	strpool;
	
	if (pstrpool == nullptr) {
		strpool.emplace(paggrstrbuf_, maxstrbufsz_, nullptr, true /* noheap_alloc */);
		pstrpool = std::addressof(strpool.value());
	}

	auto t = get_custom_aggr_columns(subsys, pajsonmap, szajsonmap, phostjsonmap, szhostjsonmap, paggrinfo, pcolarr, dbinnerarr, dbouterarr, dbpostaggrarr, *pstrpool);

	noutcol		= std::get<0>(t);
	nincol		= std::get<1>(t);
	npostcol	= std::get<2>(t);

	if (npostcol == 0) {
		return 0;
	}

	strbuf << " select * from (select "sv;

	aggr_column_query(strbuf, dbpostaggrarr, npostcol);
	
	strbuf << " from ( select "sv;
	
	aggr_column_query(strbuf, dbouterarr, noutcol);

	strbuf << " from ( select * from gy_multihostselect( $a$ "sv;

	get_db_where_clause(strbuf, SUBSYS_HOST, tablename, datetbl, "");

	strbuf.appendfmt(" $a$, \'%s\', \'%s\', \'tbl\',  $a$ ", tablename, datetbl);

	aggr_column_query(strbuf, dbinnerarr, nincol);

	strbuf << " $a$ , $b$ "sv;

	get_db_where_clause(strbuf, subsys, tablename, datetbl, "tbl.", true /* add_multihost_subsys */);
	
	strbuf << extra_inner_where << ' ';

	aggr_groupby_query(strbuf, dbinnerarr, nincol);

	strbuf << " $b$, 50000) as ("sv;

	for (uint32_t i = 0; i < nincol; ++i) {
		strbuf << dbinnerarr[i].dbfieldname << ' ' << dbinnerarr[i].dbfieldtype << ',';
	}

	strbuf.set_last_char(')');

	strbuf << " limit 100000 "sv;

	strbuf << " ) ss "sv;
	
	aggr_groupby_query(strbuf, dbouterarr, noutcol);

	strbuf << " ) sss ) "sv << pdefsubsys_->jsonstr << ' ';

	set_aggr_where_clause(strbuf, pcolarr, npostcol);

	set_sort_options(pcolarr, npostcol, phostjsonmap, 0 /* as host fields within pcolarr */, pdefsubsys_, nullptr);

	get_db_sort_limit(strbuf, subsys);

	if (strbuf.is_overflow()) {
		GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "[Internal Error]: DB Multi Host Custom Column Aggregated Query buffer overflow seen : Please reduce the criteria parameters");
	}	

	CONDEXEC(
		DEBUGEXECN(11,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Postgres Multi Host Custom Column Aggregated Query is : \"%s\"\n", strbuf.buffer());
		);
	);

	return npostcol;
}

std::tuple<uint32_t, uint32_t, uint32_t> 
QUERY_OPTIONS::get_custom_aggr_columns(SUBSYS_CLASS_E subsys, const JSON_DB_MAPPING *pajsonmap, size_t szajsonmap, const JSON_DB_MAPPING *phostjsonmap, size_t szhostjsonmap, \
						const DB_AGGR_INFO *paggrinfo, JSON_DB_MAPPING *pcolarr, DB_AGGR_INFO *dbinnerarr, DB_AGGR_INFO *dbouterarr, DB_AGGR_INFO *dbpostaggrarr, 
						EXT_POOL_ALLOC & strpool)
{
	assert(pajsonmap && phostjsonmap && paggrinfo && pcolarr && dbinnerarr && dbouterarr && dbpostaggrarr);

	assert(gy_get_thread_local().get_thread_stack_freespace() >= 120 * 1024);

	const auto			*poption = get_options_json();
	
	if (!poption) {
		return {};
	}	

	uint32_t			idindex, noutcol = 0, nincol = 0, npostcol = 0;
	bool				is_time = false, is_inrecs = false, innerhostupd = false;
	STRING_BUFFER<80>		timebuf;

	const char			*colname;
	auto				siter = poption->FindMember("columns");
	
	if ((siter == poption->MemberEnd()) || (false == siter->value.IsArray())) {
		return {};
	}	

	if (is_multihost_ && szhostjsonmap) {
		for (uint32_t i = 0; i < szhostjsonmap; ++i) {
			dbinnerarr[nincol]		= host_aggr_info[i];
			dbinnerarr[nincol].dbexpr	= "";			// as gy_multihostselect does not require the dbexpr

			nincol++;
		}	

		innerhostupd = true;
	}

	for (uint32_t i = 0; i < siter->value.Size() && noutcol + 3 < MAX_AGGR_COLUMNS && nincol + 3 < MAX_AGGR_COLUMNS && npostcol + 3 < MAX_AGGR_COLUMNS; i++) {
		if (false == siter->value[i].IsString()) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Invalid Column Name : Not of a string type specified");
		}	
		
		colname = siter->value[i].GetString();

		const auto		*pcol = get_jsoncrc_mapping(colname, siter->value[i].GetStringLength(), pajsonmap, szajsonmap, idindex);
		bool			ishost = false;
		
		if (!pcol) {
			if (AHDLR_MADHAVA == get_subsys_handler(subsys)) {
				pcol = get_jsoncrc_mapping(colname, siter->value[i].GetStringLength(), phostjsonmap, szhostjsonmap, idindex);
			}

			if (pcol) {
				ishost = true;
			}	
			else {
				if (!has_aggr_oper(colname)) {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Invalid Column Name \'%s\' specified : "
						"Custom columns can contain either existing fields as is or Aggregated Operators like sum(), max(), percentile(), count() on these fields", colname);
				}
				else {
					parse_aggr_col_expr(subsys, colname, siter->value[i].GetStringLength(), i, noutcol, nincol, npostcol, pcolarr, dbinnerarr, dbouterarr, dbpostaggrarr, strpool, 
								pajsonmap, szajsonmap);
					continue;
				}
			}
		}	

		if (pcol) {

			if (ishost && innerhostupd) {
				// Already updated
			}
			else {
				dbinnerarr[nincol]	= !ishost ? paggrinfo[idindex] : host_aggr_info[idindex];

				auto			paggr = dbinnerarr + nincol;

				if (paggr->dbexpr[0] == '%') {
					char			tbuf[128];
					size_t			tsz;
					
					tsz = GY_SAFE_SNPRINTF(tbuf, sizeof(tbuf), "%s(%s) as %s", 
								get_aggr_oper_str(paggr->dflt_aggr, paggr->ignore_sum), pcol->jsonfield, pcol->jsonfield);

					char			*pstrfield = (char *)std::memcpy(strpool.safe_malloc(tsz + 1), tbuf, tsz + 1);

					parse_aggr_col_expr(subsys, pstrfield, tsz, i, noutcol, nincol, npostcol, pcolarr, dbinnerarr, dbouterarr, dbpostaggrarr, strpool, 
								pajsonmap, szajsonmap);
					continue;
				}	
			}	

			dbouterarr[noutcol]		= !ishost ? paggrinfo[idindex] : host_aggr_info[idindex];
			pcolarr[npostcol] 		= *pcol;
			dbpostaggrarr[npostcol]		= dbouterarr[noutcol];
			dbpostaggrarr[npostcol].dbexpr	= pcol->dbcolname;
			
			if (pcol->jsoncrc == FIELD_TIME || pcol->jsoncrc == FIELD_ALERTTIME) {
				if (aggr_dur_sec_ == 0) {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Aggregation by \'time\' requested but Aggregation Interval \'aggrsec\' not specified");
				}
				else if (aggr_dur_sec_ < 15) {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Aggregation by \'time\' requested but Aggregation Interval \'aggrsec\' too small (%u sec) : "
								"Minimum 15 sec needed", aggr_dur_sec_);
				}	

				get_date_trunc_str(timebuf);
				timebuf << " as atime";

				dbinnerarr[nincol].dbexpr 	= (const char *)std::memcpy(strpool.safe_malloc(timebuf.length() + 1), timebuf.buffer(), timebuf.length() + 1);
				dbouterarr[noutcol].dbexpr 	= "atime";

				is_time				= true;
			}	
			else if (pcol->jsoncrc == FIELD_INRECS) {
				pcolarr[npostcol].dbtype	= "bigint";
				pcolarr[npostcol].numtype	= NUM_INT64;

				dbinnerarr[nincol].dbexpr 	= "count(*)::bigint as inrecs";
				dbinnerarr[nincol].dbfieldtype 	= "bigint";
				dbouterarr[noutcol].dbexpr 	= "sum(inrecs)::bigint as inrecs";

				is_inrecs 			= true;
			}	
			else if (dbinnerarr[nincol].dflt_aggr == AOPER_COUNT) {

				char			tbuf[128];
				size_t			tsz;
					
				tsz = GY_SAFE_SNPRINTF(tbuf, sizeof(tbuf), "sum(%s)::bigint as %s", pcol->dbcolname, pcol->dbcolname);

				char			*pstrfield = (char *)std::memcpy(strpool.safe_malloc(tsz + 1), tbuf, tsz + 1);

				dbouterarr[noutcol].dbexpr 	= pstrfield;

				pcolarr[npostcol].dbtype	= "bigint";
				pcolarr[npostcol].numtype	= NUM_INT64;
			}	

			noutcol++;
			npostcol++;

			if (!ishost || !innerhostupd) {
				nincol++;
			}
		}	
	}

	if (!is_time && aggr_dur_sec_ >= 15 && noutcol < MAX_AGGR_COLUMNS && nincol < MAX_AGGR_COLUMNS && npostcol < MAX_AGGR_COLUMNS) {

		const JSON_DB_MAPPING			*pcol = nullptr;
		
		if (subsys != SUBSYS_ALERTS) {
			pcol = get_jsoncrc_mapping("time", GY_CONST_STRLEN("time"), pajsonmap, szajsonmap, idindex);
		}
		else {
			static_assert(json_db_aggr_alerts_arr[0].jsoncrc == FIELD_ALERTTIME);

			pcol 				= &json_db_aggr_alerts_arr[0];
			idindex				= 0;
		}	
		
		if (pcol) {
			pcolarr[npostcol] 		= *pcol;
			dbinnerarr[nincol]		= paggrinfo[idindex];
			dbouterarr[noutcol]		= paggrinfo[idindex];
			
			get_date_trunc_str(timebuf);
			timebuf << " as atime";

			dbinnerarr[nincol].dbexpr 	= (const char *)std::memcpy(strpool.safe_malloc(timebuf.length() + 1), timebuf.buffer(), timebuf.length() + 1);
			dbouterarr[noutcol].dbexpr 	= "atime";
			dbpostaggrarr[npostcol]		= dbouterarr[noutcol];

			noutcol++;
			npostcol++;
			nincol++;
		}	
	}

	if (!is_inrecs && noutcol < MAX_AGGR_COLUMNS && nincol < MAX_AGGR_COLUMNS && npostcol < MAX_AGGR_COLUMNS) {
		uint32_t		jsoncrc = fnv1_hash("inrecs", GY_CONST_STRLEN("inrecs"));

		pcolarr[npostcol] = {
					.jsonfield 	= "inrecs",
					.dbcolname 	= "inrecs",
					.szjson		= GY_CONST_STRLEN("inrecs"),
					.jsoncrc	= jsoncrc,
					.subsys		= subsys,
					.jsontype	= JSON_NUMBER,
					.numtype	= NUM_INT64,
					.dbtype		= "bigint",
					.dbstrtype	= DB_STR_NONE,
					.oper 		= nullptr,
					.dboper		= nullptr,
					.coldesc	= "",
				};

		dbinnerarr[nincol] = {
					.dbexpr		= "count(*)::bigint as inrecs",
					.jsoncrc	= jsoncrc,
					.dbfieldname	= "inrecs",
					.dbfieldtype	= "bigint",
					.dflt_aggr	= AOPER_SUM,
					.ignore_sum	= false,
					.extarg		= 0,
				};

		dbouterarr[noutcol] = {
					.dbexpr		= "sum(inrecs)::bigint as inrecs",
					.jsoncrc	= jsoncrc,
					.dbfieldname	= "inrecs",
					.dbfieldtype	= "bigint",
					.dflt_aggr	= AOPER_SUM,
					.ignore_sum	= false,
					.extarg		= 0,
				};

		dbpostaggrarr[npostcol]			= dbouterarr[noutcol];
		dbpostaggrarr[npostcol].dbexpr		= "inrecs";
		
		noutcol++;
		npostcol++;
		nincol++;
	}

	return {noutcol, nincol, npostcol};
}	

static bool starts_with_aggr_operator(const char *colname) noexcept
{
	for (size_t i = 0; i < GY_ARRAY_SIZE(gaggr_oper); ++i) {
		if (0 == strncmp(colname, gaggr_oper[i], strlen(gaggr_oper[i]))) {
			return true;
		}	
	}	

	return false;
}								

void QUERY_OPTIONS::parse_aggr_col_expr(SUBSYS_CLASS_E subsys, const char *colname, size_t szcol, uint32_t colnum, uint32_t & noutcol, uint32_t & nincol, uint32_t & npostcol, JSON_DB_MAPPING *pcolarr, DB_AGGR_INFO *dbinnerarr, DB_AGGR_INFO *dbouterarr, DB_AGGR_INFO *dbpostaggrarr, EXT_POOL_ALLOC & strpool, const JSON_DB_MAPPING *pajsonmap, size_t szajsonmap) const
{
	static constexpr const char	separators[] = " \t\n\r()+-*/%&|,", invalidchars[] = "\\\";$";

	// Reserved fields used as keys while generating alerts
	static constexpr const char	*reservednames[] {"time", "inrecs", "rowid", "cluster", "parid", "madid", "svcid", "procid", "host", "region", "zone", "cprocid", "cparid", "sparid", 
								"name", "svcname", "cname", "sname", "shyamaid" };

	STR_RD_BUF			rdbuf(colname, szcol);
	STRING_BUFFER<1024>		strbuf;
	char				field[24], tfieldname[24];
	const char			*pas, *ptmp, *ptmp2, *poper, *pfield, *pwrstart, *pend = colname + szcol;
	size_t				nbytes, nfieldbytes;
	int				nexpr = 0, lastoutcol = -1;
	uint32_t			fieldcrc, i;
	char				c;
	bool				operactive = false, isreal = false, bret, isdiv, asclause;

	if (!pdefsubsys_) return;

	size_t				szjsonmap	= pdefsubsys_->szjsonmap;
	const JSON_DB_MAPPING		*pjsonmap 	= pdefsubsys_->pjsonmap;

	/*
	 * First validate the column
	 */
	if ((ptmp = strpbrk(colname, invalidchars))) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Custom Column \'%s\' contains char \'%c\' which is not valid", colname, *ptmp);
	}	

	pas = rdbuf.skip_till_whole_word_const("as");
	if (!pas) {
		asclause = false;
		pas = pend;
		
		nfieldbytes = snprintf(tfieldname, sizeof(tfieldname), "column%hu", (uint16_t)colnum + 1);
		pfield = tfieldname;
	}	
	else {
		asclause = true;

		pas -= GY_CONST_STRLEN("as");

		pfield = rdbuf.get_next_word(nfieldbytes, true, separators, true /* skip_leading_space */, true /* ignore_escape */, true /* skip_multi_separators */);
		if (!pfield) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Custom Column \'%s\' does not contain the as <JSON Field> expression field e.g. \'max(p95resp5s) as maxp95resp\'", 
						colname);
		}	
		else if (nfieldbytes > 24) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Custom Column \'%s\' has field name as \'%s\' length too long. Please use a different name upto 24 bytes'", 
						colname, pfield);
		}	
	
		else if ((ptmp = strpbrk(pfield, "<>=!&"))) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Custom Column \'%s\' has field name as \'%s\' which contains character \'%c\' which is not allowed. "
					"Please use a different name", colname, pfield, *ptmp);
		}	

		for (const char *resname : reservednames) {
			if (0 == strcmp(pfield, resname)) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Custom Column \'%s\' has field name as \'%s\' which is a reserved name. Please use a different field", 
						colname, pfield);
			}
		}

		auto 			escname = gy_escape_json<300>(pfield, nfieldbytes, true /* throw_on_error */); 

		if (escname.size() != nfieldbytes + 2) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Custom Column \'%s\' contains invalid characters : Must be ASCII characters or numbers (escaped name is \'%s\')", 
				pfield, escname.data());
		}	

		ptmp = rdbuf.get_next_word(nbytes, true, separators);
		if (ptmp) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Custom Column \'%s\' has field name \'%s\' as multi word which is not allowed'", colname, pfield);
		}
	}	

	rdbuf.reset();
	pwrstart = rdbuf.get_curr_pos();
	strbuf << '(';

	do {
		ptmp = rdbuf.get_next_word(nbytes, true, separators);

		if (!ptmp || ptmp >= pas) {
			break;
		}	
		
		if (nbytes) {
			char			c = *ptmp;

			if (operactive == false) {
				if (c >= 'a' && c <= 'z' && starts_with_aggr_operator(ptmp)) {
					int		nlp = 1, nrp = 0;

					operactive 	= true;
					poper 		= ptmp;
					

					do {
						ptmp = rdbuf.skip_till_next_delim("()", 2);

						if (!ptmp || ptmp >= pas) {
							GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Parenthesis mismatch for aggregation column : \'%s\'", colname);
						}	

						if (ptmp[-1] == '(') {
							nlp++;
						}	
						else if (ptmp[-1] == ')') {
							nrp++;
						}	

						if (*ptmp == '(') {
							nlp++;
							++rdbuf;
						}	
						else if ((*ptmp == ')') && (nlp > nrp)) {
							nrp++;
							++rdbuf;
							ptmp++;
						}	

						if (nlp == nrp) {
							fieldcrc = fnv1_hash(poper, ptmp - poper);

							snprintf(field, sizeof(field), "c%u", fieldcrc);

							for (i = 0; i < noutcol; ++i) {
								if (dbouterarr[i].jsoncrc == fieldcrc) {
									isreal |= (dbouterarr[i].dbfieldtype[0] == 'r');
									break;
								}	
							}	
							
							if (i == noutcol) {
								bret = parse_one_aggr_colname(poper, ptmp - poper, field, fieldcrc,
										noutcol, nincol, dbinnerarr, dbouterarr, strpool, pjsonmap, szjsonmap, pajsonmap, szajsonmap);

								if (noutcol > 0) {
									lastoutcol = noutcol - 1;
								}
								isreal |= bret;
							}	

							operactive = false;

							strbuf.append(pwrstart, poper - pwrstart);

							isdiv = false;

							if (poper > colname) {
								ptmp2 = poper - 1;

								while (ptmp2 >= colname && is_space_tab(*ptmp2)) {
									ptmp2--;
								}	

								if ((*ptmp2 == '/') || (*ptmp2 == '%')) {
									strbuf << "nullif("sv << field << ", 0)"sv;
									isdiv = true;
								}	
							}

							if (!isdiv) {
								strbuf << field;
							}	
							pwrstart = ptmp;
							nexpr++;

							break;
						}	
					} while (true);	
				}	
			}
		}
		
	} while (true);

	if (!nexpr) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : No valid aggregation expression found in column : \'%s\'", colname);
	}	

	strbuf.append(pwrstart, pas - pwrstart);

	if (!isreal) {
		// Check if a decimal number is part of the colname
		rdbuf.reset();

		do {	
			ptmp = rdbuf.skip_till_next_delim('.');
			if (ptmp && ptmp - 2 >= colname && ptmp < pend) {
				c = ptmp[0];

				if (c >= '0' && c <= '9') {
					c = ptmp[-2];
					if (c >= '0' && c <= '9') {
						isreal = true;
						break;
					}
				}	
			}	
		} while (ptmp);	
	}

	strbuf.appendfmt(") as %s", pfield);

	if (strbuf.is_overflow()) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Param : Custom Column Aggregated Query buffer overflow seen for column %s : Please reduce the criteria parameters", pfield);
	}	

	if (npostcol < MAX_AGGR_COLUMNS) {
		char			*pstrfield	= (char *)std::memcpy(strpool.safe_malloc(nfieldbytes + 1), pfield, nfieldbytes);
		
		pstrfield[nfieldbytes] 	= 0;
		fieldcrc		= fnv1_hash(pstrfield, nfieldbytes);

		if (lastoutcol >= 0 && ((0 == memcmp(dbouterarr[lastoutcol].dbfieldtype, "text", 4)) || (0 == memcmp(dbouterarr[lastoutcol].dbfieldtype, "char(", 5)) || 
				(0 == strcmp(dbouterarr[lastoutcol].dbfieldtype, "interval")) || (0 == strcmp(dbouterarr[lastoutcol].dbfieldtype, "timestamptz")) ||
				(0 == strcmp(dbouterarr[lastoutcol].dbfieldtype, "boolean")))) {
			pcolarr[npostcol] = {
						.jsonfield 	= pstrfield,
						.dbcolname 	= pstrfield,
						.szjson		= int(nfieldbytes),
						.jsoncrc	= fieldcrc,
						.subsys		= subsys,
						.jsontype	= (dbouterarr[lastoutcol].dbfieldtype[0] == 'b' ? JSON_BOOL : JSON_STRING),
						.numtype	= NUM_NAN,
						.dbtype		= "text",
						.dbstrtype	= (dbouterarr[lastoutcol].dbfieldtype[0] != 'c' ? DB_STR_TEXT : DB_STR_OCHAR),
						.oper		= nullptr,
						.dboper 	= (dbouterarr[lastoutcol].dbfieldtype[0] == 'b' ? booltojson : nullptr),
						.coldesc	= "",
					};
			
			dbpostaggrarr[npostcol] = {
						.dbexpr		= (const char *)std::memcpy(strpool.safe_malloc(strbuf.length() + 1), strbuf.buffer(), strbuf.length() + 1),
						.jsoncrc	= fieldcrc,
						.dbfieldname	= pstrfield,
						.dbfieldtype	= pcolarr[npostcol].dbtype,
						.dflt_aggr	= dbouterarr[lastoutcol].dflt_aggr,
						.ignore_sum	= false,
						.extarg		= 0,
					};

		}
		else {
			pcolarr[npostcol] = {
						.jsonfield 	= pstrfield,
						.dbcolname 	= pstrfield,
						.szjson		= int(nfieldbytes),
						.jsoncrc	= fieldcrc,
						.subsys		= subsys,
						.jsontype	= JSON_NUMBER,
						.numtype	= isreal ? NUM_DOUBLE : NUM_INT64,
						.dbtype		= isreal ? "real" : "bigint",
						.dbstrtype	= DB_STR_NONE,
						.oper 		= nullptr,
						.dboper		= nullptr,
						.coldesc	= "",
					};
			
			dbpostaggrarr[npostcol] = {
						.dbexpr		= (const char *)std::memcpy(strpool.safe_malloc(strbuf.length() + 1), strbuf.buffer(), strbuf.length() + 1),
						.jsoncrc	= fieldcrc,
						.dbfieldname	= pstrfield,
						.dbfieldtype	= pcolarr[npostcol].dbtype,
						.dflt_aggr	= AOPER_SUM,
						.ignore_sum	= false,
						.extarg		= 0,
					};
		}

		npostcol++;
	}
	else {
		GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "[Internal Error] : Post Aggregation Max Column Count exceeded %lu", MAX_AGGR_COLUMNS);
	}	

}


bool QUERY_OPTIONS::parse_one_aggr_colname(const char *colname, size_t szcol, const char *pfield, uint32_t fieldcrc, uint32_t & noutcol, uint32_t & nincol, DB_AGGR_INFO *dbinnerarr, DB_AGGR_INFO *dbouterarr, EXT_POOL_ALLOC & strpool, const JSON_DB_MAPPING *pjsonmap, size_t szjsonmap, const JSON_DB_MAPPING *pajsonmap, size_t szajsonmap) const
{
	
	static constexpr const char	*aoperstr[] { "sum", 		"avg", 		"max", 		"min", 		"percentile", 				"count", 	
								"first_elem",		"last_elem", 		"bool_or",	"bool_and",	};
	static constexpr const char	*qryoper[]  { "sum", 		"avg", 		"max", 		"min", 		"public.tdigest_percentile", 		"count", 	
								"public.first_elem",	"public.last_elem",	"bool_or",	"bool_and",	 };
	static constexpr AGGR_OPER_E	aoperarr[]  { AOPER_SUM,	AOPER_AVG,	AOPER_MAX,	AOPER_MIN,	AOPER_PERCENTILE,			AOPER_COUNT, 	
								AOPER_FIRST_ELEM,	AOPER_LAST_ELEM, 	AOPER_BOOL_OR,	AOPER_BOOL_AND, };

	static_assert(GY_ARRAY_SIZE(aoperstr) == GY_ARRAY_SIZE(qryoper) && GY_ARRAY_SIZE(aoperstr) == GY_ARRAY_SIZE(aoperarr));

	static constexpr const char	separators[] = " \t\n\r()+-*/%&|,";

	STR_RD_BUF			rdbuf(colname, szcol);

	size_t				nbytes, nfieldbytes = strlen(pfield);
	STRING_BUFFER<512>		outera, innera;
	const char			*ptmp, *ptmp2, *pdbtype = "bigint", *pinnertype = "bigint";
	char				*pstrfield, *pstrtmp1, *pstrtmp2;
	AGGR_OPER_E			aoper = AOPER_UNSPEC;
	int				aoperid = 0;
	double				pct = 0;
	int				ret;
	bool				bret;
	
	assert(noutcol + 2 < MAX_AGGR_COLUMNS && nincol + 2 < MAX_AGGR_COLUMNS);
	
	if (noutcol + 2 >= MAX_AGGR_COLUMNS || nincol + 2 >= MAX_AGGR_COLUMNS) {
		GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "Internal Error : Number of columns allocated for query expression too small");
	}	

	ptmp = rdbuf.get_next_word(nbytes, true, separators);

	if (!ptmp) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Custom Column \'%s\' does not contain the aggregation operator", colname);
	}

	if (nbytes == 0) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Custom Column \'%s\' does not contain the aggregation operator at the start of the expression", colname);
	}

	for (size_t i = 0; i < GY_ARRAY_SIZE(aoperstr); ++i) {
		if (true == gy_same_string(ptmp, nbytes, aoperstr[i], strlen(aoperstr[i]))) {
			aoper = aoperarr[i];
			aoperid = (int)i;
			break;
		}	
	}	

	if (aoper == AOPER_UNSPEC) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Custom Column \'%s\' does not contain a valid aggregation operator at the start of the expression", colname);
	}

	pstrfield = (char *)strpool.safe_malloc(nfieldbytes + 1);

	std::memcpy(pstrfield, pfield, nfieldbytes);
	pstrfield[nfieldbytes] = 0;

	switch(aoper) {
	
	case AOPER_PERCENTILE : 
		if (true) {
			ptmp = rdbuf.get_next_word(nbytes, true, ",");
			if (!ptmp) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Custom Column \'%s\' not a valid percentile format e.g. usage \'percentile(0.99, cpudelus) as p99cpudel\'", 
							colname);
			}	

			bret = string_to_number(ptmp, pct);
			if (!bret) {
				GY_THROW_SYS_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Custom Column \'%s\' not a valid percentile e.g. usage \'percentile(0.99, cpudelus) as p99cpudel\'", 
							colname);
			}	

			if (pct >= 1 && pct < 100) {
				pct /= 100;
			}	

			if (pct <= 0 || pct >= 1) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Custom Column \'%s\' percentile must be between 0 and 1 e.g. usage \'percentile(0.99, cpudelus) as p99cpudel\'", 
							colname);
			}	

			innera << "public.tdigest(("sv;
			outera << "public.tdigest_percentile("sv << pstrfield << ',' << pct << ")::real as "sv << pfield;

			bool			validfield = false;

			do {
				ptmp = rdbuf.get_next_word(nbytes, true, separators);

				if (!ptmp) {
					if (!validfield) {
						GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Custom Column \'%s\' not a valid percentile format "
								"e.g. usage \'percentile(0.99, cpudelus) as p99cpudel\'", colname);
					}
					break;
				}	

				if (nbytes) {
					ptmp2 = dbcol_from_jsoncol(ptmp, nbytes, pjsonmap, szjsonmap);
					
					if (!ptmp2) {
						ptmp2 = dbcol_from_jsoncol(ptmp, nbytes, pajsonmap, szajsonmap);
					}	

					if (ptmp2) {
						validfield = true;

						innera << ptmp2;
					}
					else {
						innera.append(ptmp, nbytes);
					}
				}

				innera << ptmp[nbytes] << ' ';
				
			} while (true);

			innera << ", 100)::public.tdigest as "sv << pfield;
			
			pdbtype 	= "real";
			pinnertype	= "public.tdigest";
		}	

		break;

	case AOPER_MIN :
	case AOPER_MAX :
	case AOPER_SUM :
	case AOPER_FIRST_ELEM :
	case AOPER_LAST_ELEM :
	case AOPER_BOOL_OR :
	case AOPER_BOOL_AND :
		if (true) {
			innera << qryoper[aoperid] << "(("sv;
			outera << qryoper[aoperid] << "("sv << pstrfield;

			const JSON_DB_MAPPING		*pdbcol = nullptr;
			bool				validfield = false;

			do {
				ptmp = rdbuf.get_next_word(nbytes, true, separators);

				if (!ptmp) {
					if (!validfield) {
						GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Custom Column \'%s\' not in a valid aggregate format e.g. usage \'%s(cpudelus) as opercpudel\'", 
								colname, aoperstr[aoperid]);
					}
					break;
				}	
				
				if (nbytes) {
					const auto		*ptmpcol = get_jsoncrc_mapping(ptmp, nbytes, pjsonmap, szjsonmap);

					if (!ptmpcol) {
						ptmpcol = get_jsoncrc_mapping(ptmp, nbytes, pajsonmap, szajsonmap);
					}	

					if (ptmpcol) {
						validfield = true;
						
						pdbcol = ptmpcol;

						if (aoper == AOPER_SUM) {
							if (strcmp(ptmpcol->dbtype, "real")) {
								pdbtype = "bigint";
							}	
							else {
								pdbtype = ptmpcol->dbtype;
							}	
						}
						else {
							pdbtype = ptmpcol->dbtype;
						}
						
						pinnertype	= pdbtype;

						innera << ptmpcol->dbcolname;
					}
					else {
						innera.append(ptmp, nbytes);
					}
				}

				innera << ptmp[nbytes] << ' ';
				
			} while (true);

			if (pdbcol && (0 == strcmp(pdbcol->dbtype, "timestamptz"))) {
				innera << ")" << ' ' << " as " << pfield;
				outera << ")" << ' ' << " as " << pfield;

				pinnertype = "interval";
				pdbtype = "interval";
			}
			else if (aoper == AOPER_BOOL_OR || aoper == AOPER_BOOL_AND) {
				innera << ")" << ' ' << " as " << pfield;
				outera << ")" << ' ' << " as " << pfield;

				pinnertype = "boolean";
				pdbtype = "boolean";
			}
			else {
				innera << ")::" << pinnertype << ' ' << " as " << pfield;
				outera << ")::" << pdbtype << ' ' << " as " << pfield;
			}
		}	

		break;

	case AOPER_AVG :
		if (true) {
			innera << "sum(("sv;

			bool			validfield = false;

			do {
				ptmp = rdbuf.get_next_word(nbytes, true, separators);

				if (!ptmp) {
					if (!validfield) {
						GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Custom Column \'%s\' not a valid avg format e.g. usage \'avg(cpudelus) as avgcpudel\'", colname);
					}
					break;
				}	
				
				if (nbytes) {
					const auto		*ptmpcol = get_jsoncrc_mapping(ptmp, nbytes, pjsonmap, szjsonmap);

					if (!ptmpcol) {
						ptmpcol = get_jsoncrc_mapping(ptmp, nbytes, pajsonmap, szajsonmap);
					}	

					if (ptmpcol) {
						validfield = true;

						if (strcmp(ptmpcol->dbtype, "real")) {
							pinnertype = "bigint";
						}	
						else {
							pinnertype = "real";
						}	
						
						if (0 == strcmp(ptmpcol->dbtype, "timestamptz")) {
							pinnertype = "interval";
							pdbtype = "interval";
						}	
						else {
							pdbtype	= "real";
						}	

						innera << ptmpcol->dbcolname;
					}
					else {
						innera.append(ptmp, nbytes);
					}
				}
				
				innera << ptmp[nbytes] << ' ';


			} while (true);

			innera << ")::"sv << pinnertype << " as "sv << pfield;
			outera << "(sum("sv << pstrfield << ")/greatest(sum(inrecs), 1))::"sv << pdbtype << " as "sv << pfield;
		}	

		break;

	case AOPER_COUNT :
		if (true) {
			innera << "count(*) filter (where ("sv;
			outera << "sum("sv << pstrfield;

			const char		*pcurr = rdbuf.get_curr_pos();
			bool			validfield = false, compseen = false;

			if (0 == memcmp(pcurr, "*)", 2)) {
				innera << "true)"sv;
			}
			else {
				do {
					ptmp = rdbuf.get_next_word(nbytes, true, separators);

					if (!ptmp) {
						if (!validfield) {
							GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Custom Column \'%s\' not a valid Count format e.g. usage \'count(cpudelus > 0) as cntcpudel\'", 
									colname);
						}

						if (!compseen) {
							if (nullptr == strcasestr(colname, " is ") || nullptr == strcasestr(colname, "null")) {
								GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Custom Column \'%s\' not a valid Count format : No Comparator like <, > or = seen "
										"e.g. usage \'count(cpudelus > 0) as cntcpudel\'", colname);
							}

							compseen = true;
						}	

						break;
					}	
					
					if (nbytes) {
						const auto		*ptmpcol = get_jsoncrc_mapping(ptmp, nbytes, pjsonmap, szjsonmap);

						if (!ptmpcol) {
							ptmpcol = get_jsoncrc_mapping(ptmp, nbytes, pajsonmap, szajsonmap);
						}	

						if (ptmpcol) {
							validfield = true;
							innera << ptmpcol->dbcolname;
						}
						else {
							if (!compseen) {
								if ((memchr(ptmp, '<', nbytes)) || (memchr(ptmp, '>', nbytes)) || (memchr(ptmp, '=', nbytes)) || (memchr(ptmp, '~', nbytes))) {
									compseen = true;
								}	
							}	

							innera.append(ptmp, nbytes);
						}
					}

					innera << ptmp[nbytes] << ' ';
					
				} while (true);
			}	

			innera << ")::bigint as "sv << pfield;
			outera << ")::bigint as "sv << pfield;
		}	

		break;

	default :
		break;
	}

	if (innera.is_overflow() || outera.is_overflow()) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Custom Column \'%s\' too big an expression. Please specify a smaller expression upto 300 characters\'", colname);
	}	

	pstrtmp1 	= (char *)strpool.safe_malloc(innera.length() + 1);

	std::memcpy(pstrtmp1, innera.buffer(), innera.length() + 1);

	dbinnerarr[nincol] = {
				.dbexpr		= pstrtmp1,
				.jsoncrc	= fieldcrc,
				.dbfieldname	= pstrfield,
				.dbfieldtype	= pinnertype,
				.dflt_aggr	= aoper,
				.ignore_sum	= false,
				.extarg		= pct,
			};
	nincol++;

	pstrtmp2	= (char *)strpool.safe_malloc(outera.length() + 1);

	std::memcpy(pstrtmp2, outera.buffer(), outera.length() + 1);

	dbouterarr[noutcol] = {
				.dbexpr		= pstrtmp2,
				.jsoncrc	= fieldcrc,
				.dbfieldname	= pstrfield,
				.dbfieldtype	= pdbtype,
				.dflt_aggr	= aoper,
				.ignore_sum	= false,
				.extarg		= pct,
			};
	noutcol++;	

	return pdbtype[0] == 'r';
}	

void QUERY_OPTIONS::set_aggr_where_clause(STR_WR_BUF & strbuf, const JSON_DB_MAPPING *pjsonmap, size_t szjsonmap) 
{
	const auto			*poption = get_options_json();

	if (!poption) {
		return;
	}	
	
	const auto			& optobj = *poption;

	auto				siter = optobj.FindMember("aggrfilter");

	if (siter == optobj.MemberEnd()) {
		return;
	}

	if (!siter->value.IsString()) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Invalid Aggregated Filter \'aggrfilter\' type : Not a string type");
	}	

	static constexpr const char	separators[] = " \t\n\r(){}><+-*/=%&|!.,", invalidchars[] = "\\\";$";

	size_t				szfilter = siter->value.GetStringLength(), nbytes;
	const char			*pfilter = siter->value.GetString(), *pend = pfilter + szfilter, *ptmp, *ptmp2;
	STR_RD_BUF			rdbuf(pfilter, szfilter);
	int				ncolseen = 0;
	char				c;
	bool				updated = false, prevdiv = false;

	if ((ptmp = strpbrk(pfilter, invalidchars))) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Aggregated Filter field \'aggrfilter\' contains char \'%c\' which is not allowed. "
						"If needed add that filter within \'filter\' field as Aggregated filters can only be for limited types", *ptmp);
	}	

	strbuf << " where "sv;
	
	do {
		ptmp = rdbuf.get_next_word(nbytes, true, separators);
		if (!ptmp) {
			break;
		}	
		
		if (nbytes) {
			auto			pcol2 = get_jsoncrc_mapping(ptmp, nbytes, pjsonmap, szjsonmap);

			if (pcol2) {
				if (prevdiv && pcol2->numtype != NUM_NAN && pcol2->numtype != NUM_DOUBLE) {
					strbuf << "nullif("sv << pcol2->dbcolname << ", 0)::real"sv;
				}
				else {
					strbuf << pcol2->dbcolname;
				}
				ncolseen++;
			}
			else {
				if ((nbytes == 2 && 0 == memcmp(ptmp, "in", 2)) || (nbytes == 5 && 0 == memcmp(ptmp, "notin", 5))) {
					const char		*pbrace = "";

					if (nbytes == 2) {
						strbuf << "in ("sv;
					}
					else {
						strbuf << "not in ("sv;
					}	
					
					ptmp += nbytes;

					ptmp2 = rdbuf.skip_till_next_delim("})", GY_CONST_STRLEN("})"));	// Skip till } or )

					if (!ptmp2) {
						ptmp2 = pend;
					}	
					else {
						--ptmp2;
						if (*ptmp2 == '}') {
							++rdbuf;
							pbrace = ") ";
						}	
						else {
							--rdbuf;
						}
					}	

					strbuf.append(ptmp, ptmp2 - ptmp);
					strbuf << ") " << pbrace;

					continue;
				}
				else {
					strbuf.append(ptmp, nbytes);
				}	
			}

			updated = true;
		}

		c = ptmp[nbytes];

		if (c == '{') {
			c = '(';	
		}	
		else if (c == '}') {
			c = ')';
		}	

		if (nbytes == 0) {
			if (c == '=') {
				if (ptmp > pfilter && ptmp[-1] == '=') {
					// Ignore ==
					continue;
				}	
			}	
		}

		strbuf << c;
		
		prevdiv = false;

		if (c == '/') {
			prevdiv = true;
		}	
		else if (c == '-') {
			if (ptmp + nbytes + 1 < pend) {
				char		c2 = ptmp[nbytes + 1];

				if (c2 >= '0' && c2 <= '9') {
					continue;
				}	
			}	
		}
		else if (c == '>' || c == '<' || c == '!') {
			if (ptmp + nbytes + 1 < pend && (ptmp[nbytes + 1] == '=' || ptmp[nbytes + 1] == '~')) {
				continue;
			}	
		}	
		else if (c == '.') {
			continue;
		}	

		strbuf << ' ';
	
	} while (true);

	if (!updated) {
		strbuf << " (true) "sv;
	}
	
	has_aggr_filters_ = !!ncolseen;
}	

void QUERY_OPTIONS::set_sort_options(const JSON_DB_MAPPING *pjsonmap, size_t szjsonmap, const JSON_DB_MAPPING *phostjsonmap, size_t szhostjsonmap, const SUBSYS_CLASS *pmainsubsys, const SUBSYS_CLASS *phostsubsys)
{
	const auto			*poption = get_options_json();
	
	if (!poption) {
		return;
	}	
	
	const auto			& optobj = *poption;

	const char			*colname;
	auto				siter = optobj.FindMember("sortcolumns");

	if ((siter != optobj.MemberEnd()) && (siter->value.IsArray())) {
		if (siter->value.Size() > MAX_SORT_COLUMNS) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Options : Too many Sort Columns %u specified : Max allowed = %lu", siter->value.Size(), MAX_SORT_COLUMNS);
		}	

		for (uint32_t i = 0; i < siter->value.Size(); i++) {
			if (false == siter->value[i].IsString()) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Invalid Sort Column Name : Not of a string type specified");
			}	
			
			colname = siter->value[i].GetString();

			const auto		*pcol = get_jsoncrc_mapping(colname, siter->value[i].GetStringLength(), pjsonmap, szjsonmap);
			bool			ishost = false;
			
			if (!pcol) {
				if (szhostjsonmap && phostsubsys) {
					pcol = get_jsoncrc_mapping(colname, siter->value[i].GetStringLength(), phostjsonmap, szhostjsonmap);
				}

				if (!pcol) {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Invalid Sort Column Name \'%s\' specified", colname);
				}

				ishost = true;
			}	
			else if (is_historical() && pcol->dbcolname[0] == 0) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Params : Sort Column Name \'%s\' specified not present in DB schema. Cannot be used for historical queries", colname);
			}	
				
			sortcolarr_[i] 		= pcol;

			if (!ishost) {
				sortsubsys_[i]	= pmainsubsys;
			}	
			else {
				sortsubsys_[i]	= phostsubsys;
			}	
		}

		nsort_ = siter->value.Size();
	}	
	else if (siter != optobj.MemberEnd()) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Options : Invalid sortcolumns field type : Needs to be an Array");
	}	

	if (nsort_ > 0) {

		// Default Asc for string columns and Desc for rest
		for (uint32_t i = 0; i < nsort_; i++) {
			if (sortcolarr_[i]->jsontype != JSON_STRING) {
				sortdir_[i] = SORT_DIR_DESC;
			}	
			else {
				sortdir_[i] = SORT_DIR_ASC;
			}	
		}	

		siter = optobj.FindMember("sortdir");

		if ((siter != optobj.MemberEnd()) && (siter->value.IsArray())) {

			for (uint32_t i = 0; i < siter->value.Size() && i < nsort_; i++) {
				if (false == siter->value[i].IsString()) {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Options : Invalid sortdir option : Not of a string array type specified");
				}	
				
				const char *pdir = siter->value[i].GetString();
				
				if (0 == strncasecmp(pdir, "asc", 3)) {
					sortdir_[i] = SORT_DIR_ASC;
				}	
				else if (0 == strncasecmp(pdir, "desc", 4)) {
					sortdir_[i] = SORT_DIR_DESC;
				}	
				else {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Options : Invalid sortdir option specified \'%s\'", pdir);
				}	
			}
		}
		else if ((siter != optobj.MemberEnd()) && (siter->value.IsString())) {
			const char *pdir = siter->value.GetString();

			if (0 == strncasecmp(pdir, "asc", 3)) {
				sortdir_[0] = SORT_DIR_ASC;
			}	
			else if (0 == strncasecmp(pdir, "desc", 4)) {
				sortdir_[0] = SORT_DIR_DESC;
			}	
			else {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Options : Invalid sortdir option specified \'%s\'", pdir);
			}	
		}	
	}	
}	

void QUERY_OPTIONS::aggr_column_query(STR_WR_BUF & strbuf, const DB_AGGR_INFO *dbarr, uint32_t ncol, uint32_t ninitcol) const
{
	int			nupd = ninitcol;

	for (size_t i = 0; i < ncol; ++i) {
		auto			paggr = dbarr + i;

		if (!paggr->dbexpr || paggr->dbexpr[0] == 0) {
			continue;
		}

		if (nupd++ > 0) {
			strbuf << ", "sv;
		}	

		strbuf << paggr->dbexpr;
	}
}	

uint32_t QUERY_OPTIONS::aggr_groupby_query(STR_WR_BUF & strbuf, const DB_AGGR_INFO *dbarr, uint32_t ncol, uint32_t ninitgroupby) const
{
	int			ngrpby = ninitgroupby;

	/*
	 * group by time first...
	 */
	for (size_t i = 0; i < ncol; ++i) {
		auto			paggr = dbarr + i;

		if (paggr->jsoncrc != FIELD_TIME && paggr->jsoncrc != FIELD_ALERTTIME) {
			continue;
		}

		if (ngrpby > 0) {
			strbuf << ", "sv;
		}	
		else {
			strbuf << " group by "sv;
		}

		ngrpby++;

		strbuf.append(paggr->dbfieldname);
		break;
	}

	for (size_t i = 0; i < ncol; ++i) {
		auto			paggr = dbarr + i;

		if (paggr->dflt_aggr != AOPER_GROUPBY || paggr->jsoncrc == FIELD_TIME || paggr->jsoncrc == FIELD_ALERTTIME) {
			continue;
		}

		if (ngrpby > 0) {
			strbuf << ", "sv;
		}	
		else {
			strbuf << " group by "sv;
		}

		ngrpby++;

		strbuf.append(paggr->dbfieldname);
	}

	return ngrpby;
}	

/*
 * We check if any of the columns are Partha Host or Madhava local and if so, multi Madhava aggregation not needed.
 */
bool QUERY_OPTIONS::to_enable_multi_madhava_aggr() const
{
	if ((is_multihost_ == false) || (is_madid_opt_ == true)) {
		return false;
	}

	const auto			*poption = get_options_json();
	
	if (!poption) {
		return false;
	}	

	auto				siter = poption->FindMember("columns");
	
	if ((siter == poption->MemberEnd()) || (false == siter->value.IsArray())) {
		return false;
	}	

	constexpr uint32_t		uniqidcols[] { 	
							FIELD_PARID, FIELD_HOST, FIELD_MADID, FIELD_SVCID, FIELD_PROCID, FIELD_CPROCID, FIELD_CPARID, FIELD_CMADID, 
							FIELD_SPARID, FIELD_SMADID, FIELD_CLUSTID, FIELD_MADHAVANAME, FIELD_CONNID,
							};		
	const char			*colname;
	uint32_t			jsoncrc;

	for (uint32_t i = 0; i < siter->value.Size(); i++) {
		if (false == siter->value[i].IsString()) {
			return false;
		}	
		
		colname = siter->value[i].GetString();
		jsoncrc = fnv1_hash(colname, strlen(colname));

		for (uint32_t j = 0; j < GY_ARRAY_SIZE(uniqidcols); ++j) {
			if (jsoncrc == uniqidcols[j]) {
				return false;
			}	
		}	
	}

	return true;
}	

std::optional<size_t> get_time_modifier_secs(const char *ptimemod, size_t szmod, size_t neversec) noexcept
{
	if (!ptimemod || !szmod || *ptimemod == 0) return {};
	
	char				tbuf[128];
	size_t				multiplier = 1, num;
	const char			*ptmp = ptimemod, *pend = ptimemod + szmod;
	char				c;
	bool				bret;

	while (ptmp < pend && is_space_tab(*ptmp)) ptmp++;

	if (ptmp == pend) return {};

	if (size_t(pend - ptmp) >= sizeof(tbuf)) {
		return {};
	}	

	if (pend - ptmp >= 5 && (0 == strncasecmp(ptmp, "never", 5))) {
		return neversec;
	}	

	*tbuf = 0;
	ptimemod = ptmp;

	while (ptmp < pend) {
		c = *ptmp;

		if (!(c >= '0' && c <= '9')) {
		
			if (ptmp == ptimemod) {
				return {};
			}	

			switch (gy_tolower_ascii(c)) {
			
			case 's' 	:	multiplier = 1; 	break;		// secs

			case 'm' 	: 	multiplier = 60;	break;		// mins

			case 'h' 	:	multiplier = 3600;	break;		// hours

			case 'd' 	:	multiplier = 3600 * 24;	break;		// days
			
			case ' '	:	
			case '\t'	:
						goto next1;

			default  	:	return {};
	
			}	

			pend = ptmp;
			break;
		}

next1 :
		ptmp++;
	}	

	std::memcpy(tbuf, ptimemod, pend - ptimemod);
	tbuf[pend - ptimemod] = 0;

	bret = string_to_number(tbuf, num, nullptr, 10); 
	if (!bret) {
		return {};
	}	

	return num * multiplier;
}	


uint32_t get_hoststate_aggr_query(STR_WR_BUF & strbuf, QUERY_OPTIONS & qryopt, const char *datetbl, JSON_DB_MAPPING (& pcolarr)[QUERY_OPTIONS::MAX_AGGR_COLUMNS], EXT_POOL_ALLOC *pstrpool)
{
	uint32_t			ncol;

	if (qryopt.is_multi_host()) {
		ncol = qryopt.get_select_aggr_multihost_query(strbuf, SUBSYS_HOSTSTATE, pcolarr, "hoststatetbl", datetbl, "", pstrpool);

		strbuf.appendconst(";\n reset search_path; ");
	}
	else {
		char				tablename[128];

		snprintf(tablename, sizeof(tablename), "sch%s.hoststatetbl%s", qryopt.get_parid_str().get(), datetbl);

		ncol = qryopt.get_select_aggr_query(strbuf, SUBSYS_HOSTSTATE, pcolarr, tablename, "", pstrpool);
	}

	return ncol;
}	

uint32_t get_cpumem_aggr_query(STR_WR_BUF & strbuf, QUERY_OPTIONS & qryopt, const char *datetbl, JSON_DB_MAPPING (& pcolarr)[QUERY_OPTIONS::MAX_AGGR_COLUMNS], EXT_POOL_ALLOC *pstrpool)
{
	uint32_t			ncol;

	if (qryopt.is_multi_host()) {
		ncol = qryopt.get_select_aggr_multihost_query(strbuf, SUBSYS_CPUMEM, pcolarr, "cpumemstatetbl", datetbl, "", pstrpool);

		strbuf.appendconst(";\n reset search_path; ");
	}
	else {
		char				tablename[128];

		snprintf(tablename, sizeof(tablename), "sch%s.cpumemstatetbl%s", qryopt.get_parid_str().get(), datetbl);

		ncol = qryopt.get_select_aggr_query(strbuf, SUBSYS_CPUMEM, pcolarr, tablename, "", pstrpool);
	}

	return ncol;
}	

uint32_t get_svcsumm_aggr_query(STR_WR_BUF & strbuf, QUERY_OPTIONS & qryopt, const char *datetbl, JSON_DB_MAPPING (& pcolarr)[QUERY_OPTIONS::MAX_AGGR_COLUMNS], EXT_POOL_ALLOC *pstrpool)
{
	uint32_t			ncol;

	if (qryopt.is_multi_host()) {
		ncol = qryopt.get_select_aggr_multihost_query(strbuf, SUBSYS_SVCSUMM, pcolarr, "listensummtbl", datetbl, "", pstrpool);

		strbuf.appendconst(";\n reset search_path; ");
	}
	else {
		char				tablename[128];

		snprintf(tablename, sizeof(tablename), "sch%s.listensummtbl%s", qryopt.get_parid_str().get(), datetbl);

		ncol = qryopt.get_select_aggr_query(strbuf, SUBSYS_SVCSUMM, pcolarr, tablename, "", pstrpool);
	}

	return ncol;
}	

uint32_t get_activeconn_aggr_query(STR_WR_BUF & strbuf, QUERY_OPTIONS & qryopt, const char *datetbl, JSON_DB_MAPPING (& pcolarr)[QUERY_OPTIONS::MAX_AGGR_COLUMNS], EXT_POOL_ALLOC *pstrpool, bool is_extended)
{
	uint32_t			ncol;
	SUBSYS_CLASS_E			subsys = (false == is_extended ? SUBSYS_ACTIVECONN : SUBSYS_EXTACTIVECONN);
	const char			*acttbl = (false == is_extended ? "activeconntbl" : "extactiveconntbl");

	if (qryopt.is_multi_host()) {
		ncol = qryopt.get_select_aggr_multihost_query(strbuf, subsys, pcolarr, acttbl, datetbl, "", pstrpool);

		strbuf.appendconst(";\n reset search_path; ");
	}
	else {
		char				tablename[128];

		snprintf(tablename, sizeof(tablename), "sch%s.%s%s", qryopt.get_parid_str().get(), acttbl, datetbl);

		ncol = qryopt.get_select_aggr_query(strbuf, subsys, pcolarr, tablename, "", pstrpool);
	}

	return ncol;
}	

uint32_t get_clientconn_aggr_query(STR_WR_BUF & strbuf, QUERY_OPTIONS & qryopt, const char *datetbl, JSON_DB_MAPPING (& pcolarr)[QUERY_OPTIONS::MAX_AGGR_COLUMNS], const char *madhava_id_str, EXT_POOL_ALLOC *pstrpool, bool is_extended)
{
	char				tablename[128], acttablename[256], extrawhere[128];
	uint32_t			ncol;
	bool				onlyremote = false;
	const auto			*poptions = qryopt.get_options_json();

	if (poptions) {
		const auto	& optobj = poptions->GetObject();
		auto		miter = optobj.FindMember("onlyremote");

		if ((miter != optobj.MemberEnd()) && (miter->value.IsBool())) {
			onlyremote = miter->value.GetBool();

			if (is_extended && onlyremote) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Query Params : Aggregated Extended Client Conn query : Only Remote Connections requested. "
						"Currently Extended Query support for only remote conns not available...");
			}	
		}	
	}	

	SUBSYS_CLASS_E			subsys = (is_extended ? SUBSYS_EXTCLIENTCONN : SUBSYS_CLIENTCONN);
	const char			*clitbl = (is_extended ? "extclientconntbl" : onlyremote ? "remoteconntbl" : "clientconntbl");

	if (qryopt.is_multi_host()) {
		ncol = qryopt.get_select_aggr_multihost_query(strbuf, subsys, pcolarr, clitbl, datetbl, "", pstrpool);

		strbuf.appendconst(";\n reset search_path; ");
		return ncol;
	}
	else {
		char				tablename[128];

		snprintf(tablename, sizeof(tablename), "sch%s.%s%s", qryopt.get_parid_str().get(), clitbl, datetbl);

		ncol = qryopt.get_select_aggr_query(strbuf, subsys, pcolarr, tablename, "", pstrpool);
	}

	return ncol;
}	

uint32_t get_svcstate_aggr_query(STR_WR_BUF & strbuf, QUERY_OPTIONS & qryopt, const char *datetbl, JSON_DB_MAPPING (& pcolarr)[QUERY_OPTIONS::MAX_AGGR_COLUMNS], EXT_POOL_ALLOC *pstrpool, bool is_extended)
{
	uint32_t			ncol;
	SUBSYS_CLASS_E			subsys = (false == is_extended ? SUBSYS_SVCSTATE : SUBSYS_EXTSVCSTATE);
	const char			*listentbl = (false == is_extended ? "listenstatetbl" : "extlistenstatetbl");

	if (qryopt.is_multi_host()) {
		ncol = qryopt.get_select_aggr_multihost_query(strbuf, subsys, pcolarr, listentbl, datetbl, "", pstrpool);

		strbuf.appendconst(";\n reset search_path; ");
	}
	else {
		char				tablename[128];

		snprintf(tablename, sizeof(tablename), "sch%s.%s%s", qryopt.get_parid_str().get(), listentbl, datetbl);

		ncol = qryopt.get_select_aggr_query(strbuf, subsys, pcolarr, tablename, "", pstrpool);
	}

	return ncol;
}	

uint32_t get_svcinfo_aggr_query(STR_WR_BUF & strbuf, QUERY_OPTIONS & qryopt, const char *datetbl, JSON_DB_MAPPING (& pcolarr)[QUERY_OPTIONS::MAX_AGGR_COLUMNS], EXT_POOL_ALLOC *pstrpool)
{
	uint32_t			ncol;

	if (qryopt.is_multi_host()) {
		ncol = qryopt.get_select_aggr_multihost_query(strbuf, SUBSYS_SVCINFO, pcolarr, "listeninfotbl", datetbl, "", pstrpool);

		strbuf.appendconst(";\n reset search_path; ");
	}
	else {
		char				tablename[128];

		snprintf(tablename, sizeof(tablename), "sch%s.listeninfotbl%s", qryopt.get_parid_str().get(), datetbl);

		ncol = qryopt.get_select_aggr_query(strbuf, SUBSYS_SVCINFO, pcolarr, tablename, "", pstrpool);
	}

	return ncol;
}	


uint32_t get_procstate_aggr_query(STR_WR_BUF & strbuf, QUERY_OPTIONS & qryopt, const char *datetbl, JSON_DB_MAPPING (& pcolarr)[QUERY_OPTIONS::MAX_AGGR_COLUMNS], EXT_POOL_ALLOC *pstrpool, bool is_extended)
{
	uint32_t			ncol;
	SUBSYS_CLASS_E			subsys = (false == is_extended ? SUBSYS_PROCSTATE : SUBSYS_EXTPROCSTATE);
	const char			*proctbl = (false == is_extended ? "aggrtaskstatetbl" : "extaggrtaskstatetbl");

	if (qryopt.is_multi_host()) {
		ncol = qryopt.get_select_aggr_multihost_query(strbuf, subsys, pcolarr, proctbl, datetbl, "", pstrpool);

		strbuf.appendconst(";\n reset search_path; ");
	}
	else {
		char				tablename[128];

		snprintf(tablename, sizeof(tablename), "sch%s.%s%s", qryopt.get_parid_str().get(), proctbl, datetbl);

		ncol = qryopt.get_select_aggr_query(strbuf, subsys, pcolarr, tablename, "", pstrpool);
	}

	return ncol;
}	

uint32_t get_procinfo_aggr_query(STR_WR_BUF & strbuf, QUERY_OPTIONS & qryopt, const char *datetbl, JSON_DB_MAPPING (& pcolarr)[QUERY_OPTIONS::MAX_AGGR_COLUMNS], EXT_POOL_ALLOC *pstrpool)
{
	uint32_t			ncol;

	if (qryopt.is_multi_host()) {
		ncol = qryopt.get_select_aggr_multihost_query(strbuf, SUBSYS_PROCINFO, pcolarr, "aggrtaskinfotbl", datetbl, "", pstrpool);

		strbuf.appendconst(";\n reset search_path; ");
	}
	else {
		char				tablename[128];

		snprintf(tablename, sizeof(tablename), "sch%s.aggrtaskinfotbl%s", qryopt.get_parid_str().get(), datetbl);

		ncol = qryopt.get_select_aggr_query(strbuf, SUBSYS_PROCINFO, pcolarr, tablename, "", pstrpool);
	}

	return ncol;
}	

uint32_t get_hostinfo_aggr_query(STR_WR_BUF & strbuf, QUERY_OPTIONS & qryopt, JSON_DB_MAPPING (& pcolarr)[QUERY_OPTIONS::MAX_AGGR_COLUMNS], EXT_POOL_ALLOC *pstrpool)
{
	uint32_t			ncol;

	ncol = qryopt.get_select_aggr_query(strbuf, SUBSYS_HOSTINFO, pcolarr, "public.hostinfoview", "", pstrpool);

	return ncol;
}


uint32_t get_clusterstate_aggr_query(STR_WR_BUF & strbuf, QUERY_OPTIONS & qryopt, const char *datetbl, JSON_DB_MAPPING (& pcolarr)[QUERY_OPTIONS::MAX_AGGR_COLUMNS], EXT_POOL_ALLOC *pstrpool)
{
	uint32_t			ncol;
	char				tablename[128];

	snprintf(tablename, sizeof(tablename), "public.clusterstatetbl%s", datetbl);

	ncol = qryopt.get_select_aggr_query(strbuf, SUBSYS_CLUSTERSTATE, pcolarr, tablename, "", pstrpool);

	return ncol;
}

uint32_t get_alerts_aggr_query(STR_WR_BUF & strbuf, QUERY_OPTIONS & qryopt, const char *datetbl, JSON_DB_MAPPING (& pcolarr)[QUERY_OPTIONS::MAX_AGGR_COLUMNS], EXT_POOL_ALLOC *pstrpool)
{
	uint32_t			ncol;
	char				tablename[128];

	snprintf(tablename, sizeof(tablename), "public.alertstbl%s", datetbl);

	ncol = qryopt.get_select_aggr_query(strbuf, SUBSYS_ALERTS, pcolarr, tablename, "", pstrpool);

	return ncol;
}

uint32_t get_tracestatus_aggr_query(STR_WR_BUF & strbuf, QUERY_OPTIONS & qryopt, const char *datetbl, JSON_DB_MAPPING (& pcolarr)[QUERY_OPTIONS::MAX_AGGR_COLUMNS], EXT_POOL_ALLOC *pstrpool)
{
	uint32_t			ncol;
	char				tablename[128];

	snprintf(tablename, sizeof(tablename), "public.tracestatus_vtbl%s", datetbl);

	ncol = qryopt.get_select_aggr_query(strbuf, SUBSYS_TRACESTATUS, pcolarr, tablename, "", pstrpool);

	return ncol;
}



void validate_json_name(const char *pname, size_t namelen, size_t maxlen, const char *ptype, bool firstalphaonly, bool emptyok, const char * extrainvchars)
{
	static constexpr const char	invalid_chars[]		{"\'\\\";$"};
	const char			*ptmp;

	assert(maxlen < 1024 - 2);

	if (namelen >= maxlen) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid %s as name too long (upto max %lu bytes allowed) : \'%s\'", ptype, maxlen - 1, pname);
	}

	if (namelen == 0) {
		if (!emptyok) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid %s as empty string specified", ptype);
		}

		return;
	}

	if (firstalphaonly && (!gy_isalpha_ascii(*pname))) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid %s as first character \'%c\' is not an ASCII alphabet", ptype, *pname);
	}	
	
	if ((ptmp = strpbrk(pname, invalid_chars))) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid %s as name \'%s\' contains char \'%c\' which is not valid", ptype, pname, *ptmp);
	}	

	if (extrainvchars && *extrainvchars) {
		if ((ptmp = strpbrk(pname, extrainvchars))) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid %s as name \'%s\' contains char \'%c\' which is not valid", ptype, pname, *ptmp);
		}	
	}	
		
	auto 				escname = gy_escape_json<6 * 1024>(pname, namelen, false /* throw_on_error */); 

	if (escname.size() != namelen + 2) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid %s as name \'%s\' contains characters not allowed : Must be Alphabets, Numbers, underscore or hyphen only (escaped name is \'%s\')", 
			ptype, pname, escname.data());
	}	
}	

void validate_db_name(const char *pname, size_t namelen, size_t maxlen, const char *ptype)
{
	const char			*ptmp;

	if (namelen >= maxlen) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid %s as name too long (upto max %lu bytes allowed) : \'%s\'", ptype, maxlen, pname);
	}

	if (namelen == 0) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid %s as empty string specified", ptype);
	}

	if (!gy_isalpha_ascii(*pname)) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid %s as first character \'%c\' is not an Ascii Alphabet", ptype, *pname);
	}	
	
	for (size_t i = 0; i < namelen; ++i) {
		if (!gy_isalnum_underscore_ascii(pname[i])) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid %s as character \'%c\' is not an Ascii Alphabet or Number or Underscore", ptype, *pname);
		}	
	}	
}	



void init_subsys_maps() 
{
	using AlertSet			= INLINE_STACK_HASH_SET<uint32_t, 1024, GY_JHASHER<uint32_t>>;

	AlertSet			alertset(GY_ARRAY_SIZE(json_db_alerts_arr));

	ASSERT_OR_THROW(GY_ARRAY_SIZE(subsys_class_list) == GY_ARRAY_SIZE(subsys_aggr_list), "Internal Error : subsystem maps not updated or incorrect size");
	ASSERT_OR_THROW(GY_ARRAY_SIZE(subsys_class_list) == GY_ARRAY_SIZE(subsys_stats_list), "Internal Error : subsystem stats maps are incorrect");

	// Allocate the SUBSYS_EXT* column maps
	set_ext_svcstate_fields();
	set_ext_activeconn_fields();
	set_ext_clientconn_fields();
	set_ext_procstate_fields();
	set_ext_tracereq_fields();

	for (size_t n = 0; n < GY_ARRAY_SIZE(json_db_alerts_arr); ++n) {
		alertset.emplace(json_db_alerts_arr[n].jsoncrc);
	}	

	for (size_t i = 0; i < SUBSYS_MAX; ++i) {
		ASSERT_OR_THROW(subsys_class_list[i].szjsonmap < MAX_COLUMN_LIST, "Internal Error : subsystem map for %s has columns %lu greater than max %lu", 
					subsys_class_list[i].jsonstr, subsys_class_list[i].szjsonmap, MAX_COLUMN_LIST);
		ASSERT_OR_THROW(subsys_aggr_list[i].szajsonmap == subsys_aggr_list[i].szaggrinfo, "Internal Error : subsystem map for %s has aggregate columns size mismatch",
					subsys_class_list[i].jsonstr);
		
		size_t			ncol 	= subsys_class_list[i].szjsonmap;
		const auto		*pmap 	= subsys_class_list[i].pjsonmap;

		for (size_t n = 0; n < ncol; ++n) {
			ASSERT_OR_THROW((size_t)pmap[n].subsys == i, "Internal Error : subsystem map for %s has subsystem name mismatch", subsys_class_list[i].jsonstr);
		}	
		
		if (i != SUBSYS_ALERTS && i != SUBSYS_ALERTDEF) {
			for (size_t n = 0; n < ncol; ++n) {
				ASSERT_OR_THROW(alertset.find(pmap[n].jsoncrc) == alertset.end(), "Internal Error : subsystem map for %s has field name \'%s\' matching Alert subsystem field. "
					"Please ensure other subsystems do not have any fields in common with Alerts fields...", subsys_class_list[i].jsonstr, pmap[n].jsonfield);
			}	
		}	

		size_t			ncola 		= subsys_aggr_list[i].szajsonmap;
		const auto		*pmapa 		= subsys_aggr_list[i].pajsonmap;
		const auto		*pmapainfo 	= subsys_aggr_list[i].paggrinfo;

		for (size_t n = 0; n < ncola; ++n) {
			ASSERT_OR_THROW((size_t)pmapa[n].subsys == i, "Internal Error : subsystem map for %s has aggregated subsystem name mismatch", subsys_class_list[i].jsonstr);

			ASSERT_OR_THROW(pmapa[n].jsoncrc == pmapainfo[n].jsoncrc, "Internal Error : Aggregation Subsystem Map for %s has column name mismatch for column %s",
						subsys_class_list[i].jsonstr, pmapa[n].jsonfield);
		}	

	}
}	

static constexpr const char	init_instancemastertbl[] = R"(
create table if not exists public.instancemastertbl(
	id 			int PRIMARY KEY NOT NULL,
	hostip 			text NOT NULL, 
	port 			int NOT NULL, 
	tupd 			timestamptz NOT NULL
);

create table if not exists public.instanceversiontbl(
	id 			int PRIMARY KEY NOT NULL,
	dbversion 		int CHECK (dbversion > 0),
	procvernum		int CHECK (procvernum > 0),
	procverstr		text NOT NULL,
	tupd 			timestamptz NOT NULL
);

)";

static constexpr const char	init_instancemastertbl_proc[] = R"(

create or replace function gy_try_instance_master(newhostip text, newport int, isholder int, OUT ismaster int, OUT currhostip text, OUT currport int) as $$
declare
	rhostip			text;
	rport			int;
	cnt			int;
begin
	lock table public.instancemastertbl in EXCLUSIVE mode;
	
	select hostip, port into rhostip, rport from public.instancemastertbl where id = 1 and tupd > now() - '3 min'::interval and tupd < now() + '30 min'::interval;
	if not found then
		raise notice '[%]:[NOTE]: Instance has taken over as master : new master hostip = % port = %', now()::text, newhostip, newport;

		execute format($fmt$ insert into public.instancemastertbl values (1, '%s', %s, now()) on conflict (id) do update set (hostip, port, tupd) = (excluded.hostip, excluded.port, excluded.tupd) $fmt$, 
				newhostip, newport);

		ismaster 	:= 1;
		currhostip 	:= newhostip;
		currport	:= newport;

	elsif isholder > 0 or (rhostip = newhostip and rport = newport) then
		if rhostip != newhostip or rport != newport then
			raise notice '[%]:[ERROR]: A new Instance has taken over as master : new master hostip = % port = %', now()::text, rhostip, rport;
			ismaster := 0;
		else
			update public.instancemastertbl set tupd = now() where id = 1;
			ismaster := 1;
		end if;	

		currhostip 	:= rhostip;
		currport	:= rport;

	else
		ismaster 	:= 0;
		currhostip 	:= rhostip;
		currport	:= rport;
	end if;

end;
$$ language plpgsql;

)";

static constexpr const char 	common_pg_procs[] = R"(

create or replace function gy_cleanup_partition(schname text, parttbl text, mindate date) returns void as $$
declare
	c 	refcursor;
	r 	record;
	spart	text := schname || '.' || parttbl;
begin
	open c for select relid FROM pg_partition_tree(spart)  where level > 0 and right(relid::text, 8)::date < mindate;
	loop
		fetch c into r;
		exit when not found;
		execute format('drop table if exists %s cascade', r.relid);
	end loop;
end;
$$ language plpgsql;

create or replace function gy_add_partition(days_to_keep int, arr anyarray, ns_regex text, isunlogged boolean) returns void as $$
declare
	c 		refcursor;
	r 		record;
	part		text;
	logmode		text;
	daystr 		text := days_to_keep::text || ' days';
	tbltoday	text := to_char(now()::date, 'yyyymmdd');
	tbltom		text := to_char(now()::date + '1 day'::interval, 'yyyymmdd');
	tblyest		text := to_char(now()::date - '1 day'::interval, 'yyyymmdd');
	tbldel		text := to_char(now()::date - daystr::interval, 'yyyymmdd');
	timetoday	text := date_trunc('day', now())::text;
	timetomor	text := date_trunc('day', now() + '1 day'::interval)::text;
	timedayafter	text := date_trunc('day', now() + '2 days'::interval)::text;
begin
	if not isunlogged then
		logmode := '';
	else
		logmode := 'unlogged';
	end if;	

	open c for select nspname from pg_catalog.pg_namespace where nspname ~ ns_regex;
	loop
		fetch c into r;
		exit when not found;
		foreach part in array arr
		loop
			execute format('create %s table if not exists %s.%s_%s partition of %s.%s FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)', 
				logmode, r.nspname, part, tbltoday, r.nspname, part, timetoday, timetomor);
			execute format('create %s table if not exists %s.%s_%s partition of %s.%s FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)',
				logmode, r.nspname, part, tbltom, r.nspname, part, timetomor, timedayafter);
			execute format('drop table if exists %s.%s_%s cascade', r.nspname, part, tbldel);
		end loop;
	end loop;
end;
$$ language plpgsql;

create or replace function gy_set_tbl_logged(arr anyarray, ns_regex text) returns void as $$
declare
	c 		refcursor;
	r 		record;
	part		text;
	tblyest		text := to_char(now()::date - '1 day'::interval, 'yyyymmdd');
begin
	open c for select nspname from pg_catalog.pg_namespace where nspname ~ ns_regex;
	loop
		fetch c into r;
		exit when not found;
		foreach part in array arr
		loop
			execute format('alter table if exists %s.%s_%s set logged', r.nspname, part, tblyest);
		end loop;
	end loop;
end;
$$ language plpgsql;

create or replace function gy_set_tbl_unlogged(arr anyarray, ns_regex text) returns void as $$
declare
	c 		refcursor;
	r 		record;
	part		text;
	tblyest		text := to_char(now()::date - '1 day'::interval, 'yyyymmdd');
begin
	open c for select nspname from pg_catalog.pg_namespace where nspname ~ ns_regex;
	loop
		fetch c into r;
		exit when not found;
		foreach part in array arr
		loop
			execute format('alter table if exists %s.%s_%s set unlogged', r.nspname, part, tblyest);
		end loop;
	end loop;
end;
$$ language plpgsql;



create or replace function gy_del_entries(arr anyarray, ns_regex text) returns void as $$
declare
	c 		refcursor;
	r 		record;
	tbl		text;
begin
	open c for select nspname from pg_catalog.pg_namespace where nspname ~ ns_regex;
	loop
		fetch c into r;
		exit when not found;
		foreach tbl in array arr
		loop
			execute format('delete from %s.%s where del_after < now()::timestamptz', r.nspname, tbl);
		end loop;
	end loop;
end;
$$ language plpgsql;

create or replace function gy_del_if_many(arr anyarray, ns_regex text) returns void as $$
declare
	c 		refcursor;
	r 		record;
	ndel		bigint;
	tbl		text;
begin
	open c for select nspname from pg_catalog.pg_namespace where nspname ~ ns_regex;
	loop
		fetch c into r;
		exit when not found;
		foreach tbl in array arr
		loop
			execute format('select count(*) from %s.%s where del_after is not null', r.nspname, tbl) into ndel;

			if ndel > 10000 then
				execute format('delete from %s.%s where del_after is not null', r.nspname, tbl);
			end if;	
		end loop;
	end loop;
end;
$$ language plpgsql;

create or replace function gy_del_init_entries(arr anyarray, mintime timestamptz, ns_regex text) returns void as $$
declare
	c 		refcursor;
	r 		record;
	tbl		text;
begin
	open c for select nspname from pg_catalog.pg_namespace where nspname ~ ns_regex;
	loop
		fetch c into r;
		exit when not found;
		foreach tbl in array arr
		loop
			execute format('delete from %s.%s where lastupdtime < ''%s''::timestamptz', r.nspname, tbl, mintime);
		end loop;
	end loop;
end;
$$ language plpgsql;

create or replace function gy_trunc_init_entries(arr anyarray, ns_regex text) returns void as $$
declare
	c 		refcursor;
	r 		record;
	tbl		text;
begin
	open c for select nspname from pg_catalog.pg_namespace where nspname ~ ns_regex;
	loop
		fetch c into r;
		exit when not found;
		foreach tbl in array arr
		loop
			execute format('truncate %s.%s', r.nspname, tbl);
		end loop;
	end loop;
end;
$$ language plpgsql;

-- Schema Disk Usage in bytes
create or replace function gy_schema_size(text) returns bigint as $$
	select sum(pg_total_relation_size(quote_ident(schemaname) || '.' || quote_ident(tablename)))::bigint from pg_tables where schemaname = $1
$$ language sql;

-- To get Disk Usage of case-sensitive regular expression for a subset of table names within the schema
create or replace function gy_schema_size_filter(text, text) returns bigint as $$
	select sum(pg_total_relation_size(quote_ident(schemaname) || '.' || quote_ident(tablename)))::bigint from pg_tables where schemaname = $1 and tablename ~ $2
$$ language sql;


-- To get a very quick estimate of the number of rows in a table as per last analyze operation :
-- e.g. select gy_row_estimate('select * from schb994cfde213046e8a148cca2df722743.activeconntbl where time > now() - ''1 day''::interval');
-- Do not use this for aggregate queries

create or replace function gy_row_estimate(query text) returns bigint as 
$func$
declare
	rec   record;
	rows  bigint;
begin
	for rec in execute 'explain ' || query loop
		rows := substring(rec."query plan" from ' rows=([[:digit:]]+)');
		exit when rows is not null;
	end loop;

	return rows;
end
$func$ language plpgsql;

create or replace function gy_table_exists(schemaname text, tblname text, partname text) returns boolean as $$
declare
	chkint		integer;
begin
	execute format($f$ select 1 from information_schema.tables where table_schema = '%s' and table_name = '%s%s' $f$, schemaname, tblname, partname) into chkint;
	if chkint = 1 then
		return true;
	else
		return false;
	end if;	
end;
$$ language plpgsql;

/*
 * Truncate timestamptz to arbitrary intervals < 1 hour. For intervals >= hour, the timezone offset from UTC will be added
 * e.g. SELECT date_trunc_by_interval('5 min'::interval, '2020-02-16 20:38:40+05:30'::timestamptz);
 * will return '2020-02-16 20:35:00+05:30'
 */
drop cast if exists (bigint as timestamptz);
drop cast if exists (timestamptz as bigint);
create cast (bigint as timestamptz) without function;
create cast (timestamptz as bigint) without function;

create or replace function date_trunc_by_interval(interval, timestamptz) RETURNS timestamptz 
language sql immutable
returns null on null input
as $$ 
	select
		case when $2::bigint >= 0::bigint then
			$2::bigint - $2::bigint % (extract (epoch from $1)*1000000 ) ::bigint 
		else
			$2::bigint - $2::bigint % (extract (epoch from $1)*1000000 ) ::bigint - (extract (epoch from $1)*1000000 ) ::bigint
	end ::timestamptz
$$;

/*
 * Add timestamptz + seconds operator
 */
create or replace function ts_plus_num(tzmod timestamptz, nsec integer)
returns timestamptz as
$$
	select tzmod + (nsec || ' sec')::interval;
$$ language sql stable;


drop operator if exists + (timestamptz, integer);

CREATE OPERATOR + (
	PROCEDURE = ts_plus_num,
	LEFTARG = TIMESTAMPTZ,
	RIGHTARG = INTEGER
);
	
/*
 * Add timestamptz - seconds operator
 */
create or replace function ts_minus_num(tzmod timestamptz, nsec integer)
returns timestamptz as
$$
	select tzmod - (nsec || ' sec')::interval;
$$ language sql stable;


drop operator if exists - (timestamptz, integer);

CREATE OPERATOR - (
	PROCEDURE = ts_minus_num,
	LEFTARG = TIMESTAMPTZ,
	RIGHTARG = INTEGER
);
	
	
CREATE OR REPLACE FUNCTION public.first_agg (anyelement, anyelement) RETURNS anyelement
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS
	'SELECT $1;';

CREATE OR REPLACE AGGREGATE public.first_elem(anyelement) (
  SFUNC = public.first_agg
, STYPE = anyelement
, PARALLEL = safe
);

CREATE OR REPLACE FUNCTION public.last_agg (anyelement, anyelement) RETURNS anyelement
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS
	'SELECT $2';

CREATE OR REPLACE AGGREGATE public.last_elem(anyelement) (
  SFUNC = public.last_agg
, STYPE = anyelement
, PARALLEL = safe
);

/*
 * Load the tdigest extension
 */
create extension if not exists tdigest;

)";

const char * get_common_instancemaster_tbl() noexcept
{
	return init_instancemastertbl;
}	

const char * get_common_instancemaster_proc() noexcept
{
	return init_instancemastertbl_proc;
}	



const char * get_common_pg_procs() noexcept
{
	return common_pg_procs;
}	


} // namespace gyeeta	

