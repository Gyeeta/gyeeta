//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later


#pragma				once

#include			"gy_common_inc.h"
#include			"gy_query_criteria.h"

namespace gyeeta {
namespace shyama {

class ClusterStateFields
{
public :
	using STATE_ONE			= comm::MS_CLUSTER_STATE::STATE_ONE;

	const STATE_ONE			& cstate_;
	const char			*pclustername_;
	uint32_t			lencluster_;
	time_t				tcurr_;
	mutable uint32_t		last_unknown_jsoncrc_		{0};

	ClusterStateFields(const comm::MS_CLUSTER_STATE::STATE_ONE & cstate, const char *pclustername, uint32_t lencluster, time_t tcurr = 0) noexcept
		: cstate_(cstate), pclustername_(pclustername), lencluster_(lencluster), tcurr_(tcurr)
	{};

	NUMBER_CRITERION get_num_field(const JSON_DB_MAPPING *pfield) const noexcept
	{
		const auto			& cstate = cstate_;

		switch (pfield->jsoncrc) {

		case FIELD_NHOSTS 		: 	return NUMBER_CRITERION((int)cstate.nhosts_);
		case FIELD_NPROCISSUE 		: 	return NUMBER_CRITERION((int)cstate.ntasks_issue_);
		case FIELD_NPROCHOSTS 		: 	return NUMBER_CRITERION((int)cstate.ntaskissue_hosts_);
		case FIELD_NPROC 		: 	return NUMBER_CRITERION((int)cstate.ntasks_);
		case FIELD_NLISTISSUE 		: 	return NUMBER_CRITERION((int)cstate.nsvc_issue_);
		case FIELD_NLISTHOSTS 		: 	return NUMBER_CRITERION((int)cstate.nsvcissue_hosts_);
		case FIELD_NLISTEN 		: 	return NUMBER_CRITERION((int)cstate.nsvc_);
		case FIELD_TOTQPS 		: 	return NUMBER_CRITERION((int)cstate.total_qps_);
		case FIELD_SVCNETMB 		: 	return NUMBER_CRITERION((int)cstate.svc_net_mb_);
		case FIELD_NCPUISSUE 		: 	return NUMBER_CRITERION((int)cstate.ncpu_issue_);
		case FIELD_NMEMISSUE 		: 	return NUMBER_CRITERION((int)cstate.nmem_issue_);
		
		default				:	last_unknown_jsoncrc_ = pfield->jsoncrc; return {};
		}
	}	

	std::pair<const char *, uint32_t> get_str_field(const JSON_DB_MAPPING *pfield, char * tbuf, size_t szbuf) const noexcept
	{
		switch (pfield->jsoncrc) {

		case FIELD_CLUSTER 		: 	return { pclustername_, lencluster_ };
		
		default				:	last_unknown_jsoncrc_ = pfield->jsoncrc; return {};
		}	
	}	

	BOOL_CRITERION get_bool_field(const JSON_DB_MAPPING *pfield) const noexcept
	{
		switch (pfield->jsoncrc) {

		default				:	last_unknown_jsoncrc_ = pfield->jsoncrc; return {};
		}	
	}	

	CRIT_RET_E filter_match(const CRITERIA_SET & criteria) const
	{
		const SUBSYS_CLASS_E		subsysarr[] {SUBSYS_CLUSTERSTATE};

		auto num_field = [&](const JSON_DB_MAPPING *pfield, SUBSYS_CLASS_E subsys) -> NUMBER_CRITERION
		{
			return get_num_field(pfield);
		};

		auto str_field = [&](const JSON_DB_MAPPING *pfield, char * tbuf, size_t szbuf, SUBSYS_CLASS_E subsys) -> std::pair<const char *, uint32_t>
		{
			return get_str_field(pfield, tbuf, szbuf);
		};	

		auto bool_field = [&](const JSON_DB_MAPPING *pfield, SUBSYS_CLASS_E subsys) -> BOOL_CRITERION
		{
			return get_bool_field(pfield);
		};

		return criteria.match_criteria(num_field, str_field, bool_field, tcurr_, subsysarr, GY_ARRAY_SIZE(subsysarr));
	}	

	template <typename Jsonwriter>
	bool print_field(uint32_t jsoncrc, Jsonwriter & writer, const char *timebuf) const
	{
		const auto			& cstate = cstate_;

		switch (jsoncrc) {

		case FIELD_TIME :
			writer.KeyConst("time");
			writer.String(timebuf ? timebuf : "");
			return true;

		case FIELD_CLUSTER :
			writer.KeyConst("cluster");
			writer.String(pclustername_, lencluster_);
			return true;

		case FIELD_NHOSTS :
			writer.KeyConst("nhosts");
			writer.Uint(cstate.nhosts_);
			return true;

		case FIELD_NPROCISSUE :
			writer.KeyConst("nprocissue");
			writer.Uint(cstate.ntasks_issue_);
			return true;

		case FIELD_NPROCHOSTS :
			writer.KeyConst("nprochosts");
			writer.Uint(cstate.ntaskissue_hosts_);
			return true;

		case FIELD_NPROC :
			writer.KeyConst("nproc");
			writer.Uint(cstate.ntasks_);
			return true;

		case FIELD_NLISTISSUE :
			writer.KeyConst("nlistissue");
			writer.Uint(cstate.nsvc_issue_);
			return true;

		case FIELD_NLISTHOSTS :
			writer.KeyConst("nlisthosts");
			writer.Uint(cstate.nsvcissue_hosts_);
			return true;

		case FIELD_NLISTEN :
			writer.KeyConst("nlisten");
			writer.Uint(cstate.nsvc_);
			return true;

		case FIELD_TOTQPS :
			writer.KeyConst("totqps");
			writer.Uint(cstate.total_qps_);
			return true;

		case FIELD_SVCNETMB :
			writer.KeyConst("svcnetmb");
			writer.Uint(cstate.svc_net_mb_);
			return true;

		case FIELD_NCPUISSUE :
			writer.KeyConst("ncpuissue");
			writer.Uint(cstate.ncpu_issue_);
			return true;

		case FIELD_NMEMISSUE :
			writer.KeyConst("nmemissue");
			writer.Uint(cstate.nmem_issue_);
			return true;

		default :
			return false;
		}

		return false;
	}	

	template <typename Jsonwriter>
	void print_json(const JSON_DB_MAPPING * const *colarr, size_t ncol, Jsonwriter & writer, const char *timebuf, bool startobj = true) const
	{
		if (startobj) {
			writer.StartObject();
		}
		
		for (size_t i = 0; i < ncol; ++i) {
			print_field(colarr[i]->jsoncrc, writer, timebuf);
		}

		if (startobj) {
			writer.EndObject();
		}
	}

};	


} // namespace shyama
} // namespace gyeeta
