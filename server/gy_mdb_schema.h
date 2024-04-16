//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma			once

#include		"gy_common_inc.h"

namespace gyeeta {
namespace madhava {	

extern const int 		CURR_DB_VERSION;

static constexpr const char	*db_glob_partition_tbls[] = {
	"notificationtbl", 
};	

// Must end with "tbl" as its used in alerts db queries
static constexpr const char	*db_partha_partition_tbls[] = {
	"hoststatetbl", "listenstatetbl", "cpumemstatetbl", "aggrtaskstatetbl", "topcputbl", "toppgcputbl", 
	"toprsstbl", "topforktbl", "activeconntbl", "deplistenissuetbl", "tasktbl", "listensummtbl", "listentaskmaptbl", "remoteconntbl",
	"aggrtaskinfotbl", "listeninfotbl", "tracereqtbl", "traceconntbl", "traceuniqtbl",
};	


/*
 * Tables which are permanently unlogged for much faster inserts...
 */
static constexpr const char	*db_partha_unlogged_partition_tbls[] = {
	"tracereqtbl", "traceconntbl", 
};	

class DBFailStats
{
public :
	gy_atomic<int64_t>		nconns_failed_		{0};
	gy_atomic<int64_t>		ndbquery_failed_	{0};
	gy_atomic<int64_t>		ndbquery_timeout_	{0};
	gy_atomic<int64_t>		nadd_partha_failed_	{0};
	gy_atomic<int64_t>		nadd_partition_failed_	{0};
	gy_atomic<int64_t>		ndel_partition_failed_	{0};
	gy_atomic<int64_t>		nhost_state_failed_	{0};
	gy_atomic<int64_t>		nlisten_state_failed_	{0};
	gy_atomic<int64_t>		ncpumem_state_failed_	{0};
	gy_atomic<int64_t>		naggrtask_state_failed_	{0};
	gy_atomic<int64_t>		ntop_tasks_failed_	{0};
	gy_atomic<int64_t>		nactive_conns_failed_	{0};
	gy_atomic<int64_t>		ndeplisten_failed_	{0};
	gy_atomic<int64_t>		nnewlisten_failed_	{0};
	gy_atomic<int64_t>		nlisten_del_failed_	{0};
	gy_atomic<int64_t>		ntaskadd_failed_	{0};
	gy_atomic<int64_t>		nlistentask_failed_	{0};
	gy_atomic<int64_t>		ncloseconn_failed_	{0};
	gy_atomic<int64_t>		nhostinfo_failed_	{0};
	gy_atomic<int64_t>		ncpumemchange_failed_	{0};
	gy_atomic<int64_t>		nnotify_failed_		{0};
	gy_atomic<int64_t>		nsvccluster_failed_	{0};
	gy_atomic<int64_t>		naggrtaskinfo_failed_	{0};
	gy_atomic<int64_t>		nsvcinfo_failed_	{0};
	gy_atomic<int64_t>		ntracereq_failed_	{0};
	gy_atomic<int64_t>		ntraceconn_failed_	{0};
	gy_atomic<int64_t>		ntraceuniqreq_failed_	{0};

	void print_stats() const noexcept
	{
		INFOPRINT_OFFLOAD("Postgres DB Error Statistics : #DB Connection Fails %ld, #DB Query Fails %ld, #DB Query Timeouts %ld, #Add Partha Fails %ld, "
			"#Add Partition Fails %ld, #Delete Partition Fails %ld, #Host State Fails %ld, #Listen State Fails %ld, "
			"#CPU Mem Fails %ld, #Aggr Task State Fails %ld, #Top Task Fails %ld, #Active Conn Fails %ld, "
			"#Dependent Listener Fails %ld, #New Listener Fails %ld, #Del Listener Fails %ld, #Task Add Fails %ld, "
			"#Listen Task Map Fails %ld, #Close Conn Fails %ld, #Partha Host Info Fails %ld, "
			"#CPU Mem Change Fails %ld, #Notification Fails %ld, #Svc Cluster Fails %ld, "
			"#Aggr Task Info Fails %ld, #Svc Info Fails %ld, #Trace API Fails %ld, #Trace Conn Fails %ld, $Trace Normalized Req Fails %ld\n",
			nconns_failed_.load(mo_relaxed), ndbquery_failed_.load(mo_relaxed), ndbquery_timeout_.load(mo_relaxed),
			nadd_partha_failed_.load(mo_relaxed), nadd_partition_failed_.load(mo_relaxed), ndel_partition_failed_.load(mo_relaxed),
			nhost_state_failed_.load(mo_relaxed), nlisten_state_failed_.load(mo_relaxed),
			ncpumem_state_failed_.load(mo_relaxed), naggrtask_state_failed_.load(mo_relaxed),
			ntop_tasks_failed_.load(mo_relaxed), nactive_conns_failed_.load(mo_relaxed),
			ndeplisten_failed_.load(mo_relaxed), nnewlisten_failed_.load(mo_relaxed),
			nlisten_del_failed_.load(mo_relaxed), ntaskadd_failed_.load(mo_relaxed), 
			nlistentask_failed_.load(mo_relaxed), ncloseconn_failed_.load(mo_relaxed), nhostinfo_failed_.load(mo_relaxed),
			ncpumemchange_failed_.load(mo_relaxed), nnotify_failed_.load(mo_relaxed), 
			nsvccluster_failed_.load(mo_relaxed), naggrtaskinfo_failed_.load(mo_relaxed), nsvccluster_failed_.load(mo_relaxed),
			ntracereq_failed_.load(mo_relaxed), ntraceconn_failed_.load(mo_relaxed), ntraceuniqreq_failed_.load(mo_relaxed)
			);
	}	
};	

} // namespace madhava
} // namespace gyeeta

