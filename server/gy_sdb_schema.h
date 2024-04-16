//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later


#pragma			once

#include		"gy_common_inc.h"

namespace gyeeta {
namespace shyama {

extern const int		CURR_DB_VERSION;

// Must end with "tbl" as its used in alerts db queries
static constexpr const char	*db_glob_partition_tbls[] = {
	"clusterstatetbl", "svcmeshtbl", "svcnatiptbl", "alertstbl",
};	

class DBFailStats
{
public :
	gy_atomic<int64_t>		nconns_failed_			{0};
	gy_atomic<int64_t>		ndbquery_failed_		{0};
	gy_atomic<int64_t>		ndbquery_timeout_		{0};
	
	gy_atomic<int64_t>		nadd_partition_failed_		{0};
	gy_atomic<int64_t>		ndel_partition_failed_		{0};
	gy_atomic<int64_t>		ncluster_state_failed_		{0};
	gy_atomic<int64_t>		ncluster_mesh_failed_		{0};
	gy_atomic<int64_t>		ncluster_natip_failed_		{0};
	gy_atomic<int64_t>		nalertdef_failed_		{0};
	gy_atomic<int64_t>		ninhibits_failed_		{0};
	gy_atomic<int64_t>		nsilences_failed_		{0};
	gy_atomic<int64_t>		nactions_failed_		{0};
	gy_atomic<int64_t>		nalerts_failed_			{0};
	gy_atomic<int64_t>		npartha_failed_			{0};
	gy_atomic<int64_t>		ntracedef_failed_			{0};

	void print_stats() const noexcept
	{
		INFOPRINT_OFFLOAD("Postgres DB Error Statistics : #DB Connection Fails %ld, #DB Query Fails %ld, #DB Query Timeouts %ld, "
			"#Add Partition Fails %ld, #Delete Partition Fails %ld, #Cluster State Fails %ld, #Cluster Mesh Failed %ld, #Cluster NAT IP Failed %ld, "
			"#Alert Defs Fails %ld, #Inhibit Fails %ld, #Silence Fails %ld, #Alert Action Fails %ld, #Alert Stat Fails %ld, #Partha Table Fails %ld, "
			"#Req Trace Defs Fails %ld\n",
			nconns_failed_.load(mo_relaxed), ndbquery_failed_.load(mo_relaxed), ndbquery_timeout_.load(mo_relaxed),
			nadd_partition_failed_.load(mo_relaxed), ndel_partition_failed_.load(mo_relaxed), ncluster_state_failed_.load(mo_relaxed), 
			ncluster_mesh_failed_.load(mo_relaxed), ncluster_natip_failed_.load(mo_relaxed),
			nalertdef_failed_.load(mo_relaxed), ninhibits_failed_.load(mo_relaxed), nsilences_failed_.load(mo_relaxed),
			nactions_failed_.load(mo_relaxed), nalertdef_failed_.load(mo_relaxed), npartha_failed_.load(mo_relaxed),
			ntracedef_failed_.load(mo_relaxed)
			);
	}	
};	



} // namespace shyama
} // namespace gyeeta

