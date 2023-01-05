//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"
#include			"gy_query_criteria.h"

namespace gyeeta {
namespace madhava {

template <class ParthaInfo, class MadhavaInfo, class ShyamaInfo, class TCP_Listener, class AggrTask>
class MFIELDS_T
{
public :
	class HostFields
	{
	public :
		const ParthaInfo		& partha_;
		const char 			*madhava_id_str_;
		mutable uint32_t		last_unknown_jsoncrc_		{0};

		HostFields(const ParthaInfo & partha, const char *madhava_id_str) noexcept
			: partha_(partha), madhava_id_str_(madhava_id_str)
		{};

		NUMBER_CRITERION get_num_field(const JSON_DB_MAPPING *pfield) const noexcept
		{
			switch (pfield->jsoncrc) {
			
			default				:	last_unknown_jsoncrc_ = pfield->jsoncrc; return {};
			}	
		}	

		std::pair<const char *, uint32_t> get_str_field(const JSON_DB_MAPPING *pfield, char * tbuf, size_t szbuf) const noexcept
		{
			const auto			*prawpartha = &partha_;

			switch (pfield->jsoncrc) {

			case FIELD_PARID 		: 	return { prawpartha->machine_id_str_, 		32 };
			case FIELD_HOST 		: 	return { prawpartha->hostname_, 		GY_READ_ONCE(prawpartha->hostname_len_) };
			case FIELD_MADID		:	return { madhava_id_str_,			16 };
			case FIELD_CLUSTER 		: 	return { prawpartha->cluster_name_,		GY_READ_ONCE(prawpartha->cluster_len_) };

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
			const SUBSYS_CLASS_E		subsysarr[] {SUBSYS_HOST};

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

			return criteria.match_criteria(num_field, str_field, bool_field, 0, subsysarr, GY_ARRAY_SIZE(subsysarr));
		}	


		template <typename Jsonwriter>
		bool print_field(uint32_t jsoncrc, Jsonwriter & writer) const
		{
			const auto			*prawpartha = &partha_;

			switch (jsoncrc) {

			case FIELD_PARID :
				writer.KeyConst("parid");
				writer.String(prawpartha->machine_id_str_, sizeof(prawpartha->machine_id_str_) - 1);
				return true;
			
			case FIELD_HOST :
				writer.KeyConst("host");
				writer.String(prawpartha->hostname_, GY_READ_ONCE(prawpartha->hostname_len_));
				return true;

			case FIELD_MADID :
				writer.KeyConst("madid");
				writer.String(madhava_id_str_, 16);
				return true;

			case FIELD_CLUSTER :
				writer.KeyConst("cluster");
				writer.String(prawpartha->cluster_name_, GY_READ_ONCE(prawpartha->cluster_len_));
				return true;

			default :
				return false;
			}

			return false;
		}	

		template <typename Jsonwriter>
		void print_json(const JSON_DB_MAPPING * const *colarr, size_t ncol, Jsonwriter & writer, bool startobj = true) const
		{
			if (startobj) {
				writer.StartObject();
			}
			
			for (size_t i = 0; i < ncol; ++i) {
				print_field(colarr[i]->jsoncrc, writer);
			}

			if (startobj) {
				writer.EndObject();
			}
		}

	};	

	class HostStateFields
	{
	public :
		const ParthaInfo		& partha_;
		const comm::HOST_STATE_NOTIFY 	& hstate_;
		const char 			*madhava_id_str_;
		time_t				tcurr_;
		mutable uint32_t		last_unknown_jsoncrc_		{0};

		HostStateFields(const ParthaInfo & partha, const comm::HOST_STATE_NOTIFY & hstate, const char *madhava_id_str, time_t tcurr = 0) noexcept
			: partha_(partha), hstate_(hstate), madhava_id_str_(madhava_id_str), tcurr_(tcurr)
		{}

		NUMBER_CRITERION get_num_field(const JSON_DB_MAPPING *pfield) const noexcept
		{
			const auto			& hstate = hstate_;

			switch (pfield->jsoncrc) {

			case FIELD_NPROCISSUE 		: 	return NUMBER_CRITERION((int)hstate.ntasks_issue_);
			case FIELD_NPROCSEVERE 		: 	return NUMBER_CRITERION((int)hstate.ntasks_severe_);
			case FIELD_NPROC 		: 	return NUMBER_CRITERION((int)hstate.ntasks_);
			case FIELD_NLISTISSUE 		: 	return NUMBER_CRITERION((int)hstate.nlisten_issue_);
			case FIELD_NLISTSEVERE 		: 	return NUMBER_CRITERION((int)hstate.nlisten_severe_);
			case FIELD_NLISTEN 		: 	return NUMBER_CRITERION((int)hstate.nlisten_);
			case FIELD_CPUDELMS 		: 	return NUMBER_CRITERION((int)hstate.total_cpu_delayms_);
			case FIELD_VMDELMS 		: 	return NUMBER_CRITERION((int)hstate.total_vm_delayms_);
			case FIELD_IODELMS 		: 	return NUMBER_CRITERION((int)hstate.total_io_delayms_);
			
			default				:	last_unknown_jsoncrc_ = pfield->jsoncrc; return {};
			}	
		}	

		std::pair<const char *, uint32_t> get_str_field(const JSON_DB_MAPPING *pfield, char * tbuf, size_t szbuf) const noexcept
		{
			const auto			*prawpartha = &partha_;
			const auto			& hstate = hstate_;

			switch (pfield->jsoncrc) {

			case FIELD_PARID 		: 	return { prawpartha->machine_id_str_, 		32 };
			case FIELD_HOST 		: 	return { prawpartha->hostname_, 		GY_READ_ONCE(prawpartha->hostname_len_) };
			case FIELD_MADID		:	return { madhava_id_str_,			16 };
			case FIELD_CLUSTER 		: 	return { prawpartha->cluster_name_,		GY_READ_ONCE(prawpartha->cluster_len_) };
			case FIELD_STATE  		:	return state_to_stringlen((OBJ_STATE_E)hstate.curr_state_);
			
			default				:	last_unknown_jsoncrc_ = pfield->jsoncrc; return {};
			}	

		}	

		BOOL_CRITERION get_bool_field(const JSON_DB_MAPPING *pfield) const noexcept
		{
			const auto			& hstate = hstate_;

			switch (pfield->jsoncrc) {

			case FIELD_CPUISSUE		:	return BOOL_CRITERION(hstate.cpu_issue_);
			case FIELD_MEMISSUE		:	return BOOL_CRITERION(hstate.mem_issue_);
			case FIELD_SEVERECPU		:	return BOOL_CRITERION(hstate.severe_cpu_issue_);
			case FIELD_SEVEREMEM		:	return BOOL_CRITERION(hstate.severe_mem_issue_);

			default				:	last_unknown_jsoncrc_ = pfield->jsoncrc; return {};
			}	
		}	

		CRIT_RET_E filter_match(const CRITERIA_SET & criteria) const
		{
			const SUBSYS_CLASS_E		subsysarr[] {SUBSYS_HOSTSTATE, SUBSYS_HOST};

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
		bool print_field(uint32_t jsoncrc, Jsonwriter & writer, const char *timebuf = nullptr) const
		{
			const auto			*prawpartha = &partha_;
			const auto			& hstate = hstate_;

			switch (jsoncrc) {

			case FIELD_PARID :
				writer.KeyConst("parid");
				writer.String(prawpartha->machine_id_str_, sizeof(prawpartha->machine_id_str_) - 1);
				return true;
			
			case FIELD_HOST :
				writer.KeyConst("host");
				writer.String(prawpartha->hostname_, GY_READ_ONCE(prawpartha->hostname_len_));
				return true;

			case FIELD_MADID :
				writer.KeyConst("madid");
				writer.String(madhava_id_str_, 16);
				return true;

			case FIELD_CLUSTER :
				writer.KeyConst("cluster");
				writer.String(prawpartha->cluster_name_, GY_READ_ONCE(prawpartha->cluster_len_));
				return true;

			case FIELD_TIME :
				writer.KeyConst("time");

				if (timebuf) {
					writer.String(timebuf);
				}
				else {
					struct timeval 			tv = GY_USEC_TO_TIMEVAL(hstate.curr_time_usec_);
					
					writer.String(gy_localtime_iso8601(tv, CHAR_BUF<64>().get(), 64));
				}
				return true;

			case FIELD_STATE :
				writer.KeyConst("state");
				writer.String(state_to_stringlen((OBJ_STATE_E)hstate.curr_state_));
				return true;

			case FIELD_NPROCISSUE :
				writer.KeyConst("nprocissue");
				writer.Uint(hstate.ntasks_issue_);
				return true;

			case FIELD_NPROCSEVERE :
				writer.KeyConst("nprocsevere");
				writer.Uint(hstate.ntasks_severe_);
				return true;

			case FIELD_NPROC :
				writer.KeyConst("nproc");
				writer.Uint(hstate.ntasks_);
				return true;

			case FIELD_NLISTISSUE :
				writer.KeyConst("nlistissue");
				writer.Uint(hstate.nlisten_issue_);
				return true;

			case FIELD_NLISTSEVERE :
				writer.KeyConst("nlistsevere");
				writer.Uint(hstate.nlisten_severe_);
				return true;

			case FIELD_NLISTEN :
				writer.KeyConst("nlisten");
				writer.Uint(hstate.nlisten_);
				return true;

			case FIELD_CPUISSUE :
				writer.KeyConst("cpuissue");
				writer.Bool(hstate.cpu_issue_);
				return true;

			case FIELD_SEVERECPU :
				writer.KeyConst("severecpu");
				writer.Bool(hstate.severe_cpu_issue_);
				return true;

			case FIELD_MEMISSUE :
				writer.KeyConst("memissue");
				writer.Bool(hstate.mem_issue_);
				return true;

			case FIELD_SEVEREMEM :
				writer.KeyConst("severemem");
				writer.Bool(hstate.severe_mem_issue_);
				return true;

			case FIELD_CPUDELMS :
				writer.KeyConst("cpudelms");
				writer.Uint(hstate.total_cpu_delayms_);
				return true;

			case FIELD_VMDELMS :
				writer.KeyConst("vmdelms");
				writer.Uint(hstate.total_vm_delayms_);
				return true;

			case FIELD_IODELMS :
				writer.KeyConst("iodelms");
				writer.Uint(hstate.total_io_delayms_);
				return true;

			default :
				return false;
			}	

			return false;
		}	

		template <typename Jsonwriter>
		void print_json(const JSON_DB_MAPPING * const *colarr, size_t ncol, Jsonwriter & writer, const char *timebuf = nullptr, bool startobj = true) const
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

	class CpuMemFields
	{
	public :
		const ParthaInfo		& partha_;
		const CPU_MEM_STATE 		& cpu_mem_state_;
		const char 			*madhava_id_str_;
		time_t				tcurr_;
		mutable uint32_t		last_unknown_jsoncrc_		{0};

		CpuMemFields(const ParthaInfo & partha, const CPU_MEM_STATE & cpu_mem_state, const char *madhava_id_str, time_t tcurr = 0) noexcept
			: partha_(partha), cpu_mem_state_(cpu_mem_state), madhava_id_str_(madhava_id_str), tcurr_(tcurr)
		{};

		NUMBER_CRITERION get_num_field(const JSON_DB_MAPPING *pfield) const noexcept
		{
			const auto 			& cpu_mem = cpu_mem_state_.cpu_mem_;

			switch (pfield->jsoncrc) {

			case FIELD_CPU_PCT 		: 	return NUMBER_CRITERION((double)cpu_mem.cpu_pct_);
			case FIELD_USERCPU_PCT 		: 	return NUMBER_CRITERION((double)cpu_mem.usercpu_pct_);
			case FIELD_SYSCPU_PCT		:	return NUMBER_CRITERION((double)cpu_mem.syscpu_pct_);
			case FIELD_IOWAIT_PCT		:	return NUMBER_CRITERION((double)cpu_mem.iowait_pct_);
			case FIELD_CUMUL_CPU_PCT	:	return NUMBER_CRITERION((double)cpu_mem.cumul_core_cpu_pct_);
			case FIELD_FORKS_SEC		:	return NUMBER_CRITERION((int)cpu_mem.forks_sec_);
			case FIELD_PROCS		:	return NUMBER_CRITERION((int)cpu_mem.procs_running_);
			case FIELD_CS_SEC		:	return NUMBER_CRITERION((int64_t)cpu_mem.cs_sec_);
			case FIELD_CS_P95_SEC		:	return NUMBER_CRITERION((int64_t)cpu_mem.cs_p95_sec_);
			case FIELD_CPU_P95		: 	return NUMBER_CRITERION((int)cpu_mem.cpu_p95_);
			case FIELD_CPU_5MIN_P95		: 	return NUMBER_CRITERION((int)cpu_mem.cpu_5min_p95_);
			case FIELD_FORK_P95_SEC		: 	return NUMBER_CRITERION((int)cpu_mem.fork_p95_sec_);
			case FIELD_FORK_5MIN_P95_SEC	: 	return NUMBER_CRITERION((int)cpu_mem.fork_5min_p95_sec_);
			case FIELD_PROCS_P95		: 	return NUMBER_CRITERION((int)cpu_mem.procs_p95_);
			case FIELD_PROCS_5MIN_P95	: 	return NUMBER_CRITERION((int)cpu_mem.procs_5min_p95_);
			case FIELD_CPUISSUE		: 	return NUMBER_CRITERION((int16_t)cpu_mem.cpu_issue_);
		
			case FIELD_RSS_PCT		: 	return NUMBER_CRITERION((double)cpu_mem.rss_pct_);
			case FIELD_RSS_MB		: 	return NUMBER_CRITERION((int64_t)cpu_mem.rss_memory_mb_);
			case FIELD_TOTAL_MB		: 	return NUMBER_CRITERION((int64_t)cpu_mem.total_memory_mb_);
			case FIELD_LOCKED_MB		: 	return NUMBER_CRITERION((int64_t)cpu_mem.locked_memory_mb_);
			case FIELD_COMMIT_MB		: 	return NUMBER_CRITERION((int64_t)cpu_mem.committed_memory_mb_);
			case FIELD_COMMIT_PCT		: 	return NUMBER_CRITERION((double)cpu_mem.committed_pct_);
			case FIELD_SWAP_FREE_MB		: 	return NUMBER_CRITERION((int64_t)cpu_mem.swap_free_mb_);
			case FIELD_PG_INOUT_SEC		: 	return NUMBER_CRITERION((int)cpu_mem.pg_inout_sec_);
			case FIELD_SWAP_INOUT_SEC	: 	return NUMBER_CRITERION((int)cpu_mem.swap_inout_sec_);
			case FIELD_RECLAIM_STALLS	: 	return NUMBER_CRITERION((int)cpu_mem.reclaim_stalls_);
			case FIELD_PGMAJFAULT		: 	return NUMBER_CRITERION((int)cpu_mem.pgmajfault_);
			case FIELD_OOM_KILL		: 	return NUMBER_CRITERION((int)cpu_mem.oom_kill_);
			case FIELD_RSS_PCT_P95		: 	return NUMBER_CRITERION((int)cpu_mem.rss_pct_p95_);
			case FIELD_PGINOUT_P95		: 	return NUMBER_CRITERION((int)cpu_mem.pginout_p95_);
			case FIELD_SWPINOUT_P95		: 	return NUMBER_CRITERION((int)cpu_mem.swpinout_p95_);
			case FIELD_MEMISSUE		: 	return NUMBER_CRITERION((int16_t)cpu_mem.mem_issue_);
			
			default				:	last_unknown_jsoncrc_ = pfield->jsoncrc; return {};
			}	
		}	

		std::pair<const char *, uint32_t> get_str_field(const JSON_DB_MAPPING *pfield, char * tbuf, size_t szbuf) const noexcept
		{
			const auto			*prawpartha = &partha_;
			const auto 			& cpu_mem = cpu_mem_state_.cpu_mem_;

			switch (pfield->jsoncrc) {

			case FIELD_PARID 		: 	return { prawpartha->machine_id_str_, 		32 };
			case FIELD_HOST 		: 	return { prawpartha->hostname_, 		GY_READ_ONCE(prawpartha->hostname_len_) };
			case FIELD_MADID		:	return { madhava_id_str_,			16 };
			case FIELD_CLUSTER 		: 	return { prawpartha->cluster_name_,		GY_READ_ONCE(prawpartha->cluster_len_) };

			case FIELD_CPU_STATE 		: 	return state_to_stringlen((OBJ_STATE_E)cpu_mem.cpu_state_);
			case FIELD_MEM_STATE 		:	return state_to_stringlen((OBJ_STATE_E)cpu_mem.mem_state_); 	
			
			case FIELD_CPU_STATE_STR 	: 
				do {
					uint32_t		slen = GY_READ_ONCE(cpu_mem.cpu_state_string_len_);		

					if (slen > 1 && slen < sizeof(cpu_mem_state_.cpu_state_str_)) {
						return { cpu_mem_state_.cpu_state_str_, slen - 1};
					}

					return {};
				} while (0);	

			case FIELD_MEM_STATE_STR 	: 
				do {
					uint32_t		slen = GY_READ_ONCE(cpu_mem.mem_state_string_len_);		

					if (slen > 1 && slen < sizeof(cpu_mem_state_.mem_state_str_)) {
						return { cpu_mem_state_.mem_state_str_, slen - 1};
					}

					return {};
				} while (0);	

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
			const SUBSYS_CLASS_E		subsysarr[] {SUBSYS_CPUMEM, SUBSYS_HOST};

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
		bool print_field(uint32_t jsoncrc, Jsonwriter & writer, const char *timebuf = nullptr) const
		{
			const auto			*prawpartha = &partha_;
			const auto 			& cpu_mem = cpu_mem_state_.cpu_mem_;

			switch (jsoncrc) {
			
			case FIELD_PARID :
				writer.KeyConst("parid");
				writer.String(prawpartha->machine_id_str_, sizeof(prawpartha->machine_id_str_) - 1);
				return true;
			
			case FIELD_HOST :
				writer.KeyConst("host");
				writer.String(prawpartha->hostname_, GY_READ_ONCE(prawpartha->hostname_len_));
				return true;

			case FIELD_MADID :
				writer.KeyConst("madid");
				writer.String(madhava_id_str_, 16);
				return true;

			case FIELD_CLUSTER :
				writer.KeyConst("cluster");
				writer.String(prawpartha->cluster_name_, GY_READ_ONCE(prawpartha->cluster_len_));
				return true;

			case FIELD_TIME :
				writer.KeyConst("time");

				if (timebuf) {
					writer.String(timebuf);
				}
				else {
					struct timeval 			tv = GY_USEC_TO_TIMEVAL(cpu_mem_state_.tusec_);
					
					writer.String(gy_localtime_iso8601(tv, CHAR_BUF<64>().get(), 64));	
				}	
				return true;

			case FIELD_CPU_PCT :
				writer.KeyConst("cpu_pct");
				writer.Double(cpu_mem.cpu_pct_);
				return true;

			case FIELD_USERCPU_PCT :
				writer.KeyConst("usercpu_pct");
				writer.Double(cpu_mem.usercpu_pct_);
				return true;

			case FIELD_SYSCPU_PCT :
				writer.KeyConst("syscpu_pct");
				writer.Double(cpu_mem.syscpu_pct_);
				return true;

			case FIELD_IOWAIT_PCT :
				writer.KeyConst("iowait_pct");
				writer.Double(cpu_mem.iowait_pct_);
				return true;

			case FIELD_CUMUL_CPU_PCT :
				writer.KeyConst("cumul_cpu_pct");
				writer.Double(cpu_mem.cumul_core_cpu_pct_);
				return true;

			case FIELD_FORKS_SEC :
				writer.KeyConst("forks_sec");
				writer.Uint(cpu_mem.forks_sec_);
				return true;

			case FIELD_PROCS :
				writer.KeyConst("procs");
				writer.Uint(cpu_mem.procs_running_);
				return true;

			case FIELD_CS_SEC :
				writer.KeyConst("cs_sec");
				writer.Uint64(cpu_mem.cs_sec_);
				return true;

			case FIELD_CS_P95_SEC :
				writer.KeyConst("cs_p95_sec");
				writer.Uint(cpu_mem.cs_p95_sec_);
				return true;

			case FIELD_CS_5MIN_P95_SEC :
				writer.KeyConst("cs_5min_p95_sec");
				writer.Uint(cpu_mem.cs_5min_p95_sec_);
				return true;

			case FIELD_CPU_P95 :
				writer.KeyConst("cpu_p95");
				writer.Uint(cpu_mem.cpu_p95_);
				return true;

			case FIELD_CPU_5MIN_P95 :
				writer.KeyConst("cpu_5min_p95");
				writer.Uint(cpu_mem.cpu_5min_p95_);
				return true;

			case FIELD_FORK_P95_SEC :
				writer.KeyConst("fork_p95_sec");
				writer.Uint(cpu_mem.fork_p95_sec_);
				return true;

			case FIELD_FORK_5MIN_P95_SEC :
				writer.KeyConst("fork_5min_p95_sec");
				writer.Uint(cpu_mem.fork_5min_p95_sec_);
				return true;

			case FIELD_PROCS_P95 :
				writer.KeyConst("procs_p95");
				writer.Uint(cpu_mem.procs_p95_);
				return true;

			case FIELD_PROCS_5MIN_P95 :
				writer.KeyConst("procs_5min_p95");
				writer.Uint(cpu_mem.procs_5min_p95_);
				return true;

			case FIELD_CPU_STATE :
				writer.KeyConst("cpu_state");
				writer.String(state_to_stringlen((OBJ_STATE_E)cpu_mem.cpu_state_));
				return true;

			case FIELD_CPUISSUE :
				writer.KeyConst("cpuissue");
				writer.Uint(cpu_mem.cpu_issue_);
				return true;

			case FIELD_RSS_PCT :
				writer.KeyConst("rss_pct");
				writer.Double(cpu_mem.rss_pct_);
				return true;

			case FIELD_RSS_MB :
				writer.KeyConst("rss_mb");
				writer.Uint64(cpu_mem.rss_memory_mb_);
				return true;

			case FIELD_TOTAL_MB :
				writer.KeyConst("total_mb");
				writer.Uint64(cpu_mem.total_memory_mb_);
				return true;

			case FIELD_LOCKED_MB :
				writer.KeyConst("locked_mb");
				writer.Uint64(cpu_mem.locked_memory_mb_);
				return true;

			case FIELD_COMMIT_MB :
				writer.KeyConst("commit_mb");
				writer.Uint64(cpu_mem.committed_memory_mb_);
				return true;

			case FIELD_COMMIT_PCT :
				writer.KeyConst("commit_pct");
				writer.Double(cpu_mem.committed_pct_);
				return true;

			case FIELD_SWAP_FREE_MB :
				writer.KeyConst("swap_free_mb");
				writer.Uint64(cpu_mem.swap_free_mb_);
				return true;

			case FIELD_PG_INOUT_SEC :
				writer.KeyConst("pg_inout_sec");
				writer.Uint(cpu_mem.pg_inout_sec_);
				return true;

			case FIELD_SWAP_INOUT_SEC :
				writer.KeyConst("swap_inout_sec");
				writer.Uint(cpu_mem.swap_inout_sec_);
				return true;

			case FIELD_RECLAIM_STALLS :
				writer.KeyConst("reclaim_stalls");
				writer.Uint(cpu_mem.reclaim_stalls_);
				return true;

			case FIELD_PGMAJFAULT :
				writer.KeyConst("pgmajfault");
				writer.Uint(cpu_mem.pgmajfault_);
				return true;

			case FIELD_OOM_KILL :
				writer.KeyConst("oom_kill");
				writer.Uint(cpu_mem.oom_kill_);
				return true;

			case FIELD_RSS_PCT_P95 :
				writer.KeyConst("rss_pct_p95");
				writer.Uint(cpu_mem.rss_pct_p95_);
				return true;

			case FIELD_PGINOUT_P95 :
				writer.KeyConst("pginout_p95");
				writer.Uint64(cpu_mem.pginout_p95_);
				return true;

			case FIELD_SWPINOUT_P95 :
				writer.KeyConst("swpinout_p95");
				writer.Uint64(cpu_mem.swpinout_p95_);
				return true;

			case FIELD_MEM_STATE :
				writer.KeyConst("mem_state");
				writer.String(state_to_stringlen((OBJ_STATE_E)cpu_mem.mem_state_));
				return true;

			case FIELD_MEMISSUE :
				writer.KeyConst("memissue");
				writer.Uint(cpu_mem.mem_issue_);
				return true;

			case FIELD_CPU_STATE_STR :
				if (true) {
					writer.KeyConst("cpu_state_str");

					uint32_t		slen = GY_READ_ONCE(cpu_mem.cpu_state_string_len_);		

					if (slen > 1 && slen < sizeof(cpu_mem_state_.cpu_state_str_)) {
						writer.String(cpu_mem_state_.cpu_state_str_, slen - 1);
					}
					else {
						writer.String("", 0);
					}	
				}
				return true;

			case FIELD_MEM_STATE_STR :
				if (true) {
					writer.KeyConst("mem_state_str");

					uint32_t		slen = GY_READ_ONCE(cpu_mem.mem_state_string_len_);		

					if (slen > 1 && slen < sizeof(cpu_mem_state_.mem_state_str_)) {
						writer.String(cpu_mem_state_.mem_state_str_, slen - 1);
					}
					else {
						writer.String("", 0);
					}	
				}
				return true;

			default :
				return false;
			}	

			return false;
		}

		template <typename Jsonwriter>
		void print_json(const JSON_DB_MAPPING * const *colarr, size_t ncol, Jsonwriter & writer, const char *timebuf = nullptr, bool startobj = true) const
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

	class SvcSummFields
	{
	public :
		const ParthaInfo		& partha_;
		const LISTEN_SUMM_STATS<int> 	& stats_;
		const char 			*madhava_id_str_;
		time_t				tcurr_;
		mutable uint32_t		last_unknown_jsoncrc_		{0};

		SvcSummFields(const ParthaInfo & partha, const LISTEN_SUMM_STATS<int> & stats, const char *madhava_id_str, time_t tcurr = 0) noexcept
			: partha_(partha), stats_(stats), madhava_id_str_(madhava_id_str), tcurr_(tcurr)
		{};

		NUMBER_CRITERION get_num_field(const JSON_DB_MAPPING *pfield) const noexcept
		{
			const auto			& stats = stats_;

			switch (pfield->jsoncrc) {
			
			case FIELD_NIDLE		:	return NUMBER_CRITERION(stats.nstates_[STATE_IDLE]);
			case FIELD_NGOOD		:	return NUMBER_CRITERION(stats.nstates_[STATE_GOOD]);
			case FIELD_NOK			:	return NUMBER_CRITERION(stats.nstates_[STATE_OK]);
			case FIELD_NBAD			:	return NUMBER_CRITERION(stats.nstates_[STATE_BAD]);
			case FIELD_NSEVERE		:	return NUMBER_CRITERION(stats.nstates_[STATE_SEVERE]);
			case FIELD_NDOWN		:	return NUMBER_CRITERION(stats.nstates_[STATE_DOWN]);

			case FIELD_TOTQPS		:	return NUMBER_CRITERION(stats.tot_qps_);
			case FIELD_TOTACONN		:	return NUMBER_CRITERION(stats.tot_act_conn_);
			case FIELD_TOTKBIN		:	return NUMBER_CRITERION(stats.tot_kb_inbound_);
			case FIELD_TOTKBOUT		:	return NUMBER_CRITERION(stats.tot_kb_outbound_);
			case FIELD_TOTSERERR		:	return NUMBER_CRITERION(stats.tot_ser_errors_);
			case FIELD_NSVC			:	return NUMBER_CRITERION(stats.nlisteners_);
			case FIELD_NACTIVE		:	return NUMBER_CRITERION(stats.nactive_);

			default				:	last_unknown_jsoncrc_ = pfield->jsoncrc; return {};
			}	
		}	

		std::pair<const char *, uint32_t> get_str_field(const JSON_DB_MAPPING *pfield, char * tbuf, size_t szbuf) const noexcept
		{
			const auto			*prawpartha = &partha_;

			switch (pfield->jsoncrc) {

			case FIELD_PARID 		: 	return { prawpartha->machine_id_str_, 		32 };
			case FIELD_HOST 		: 	return { prawpartha->hostname_, 		GY_READ_ONCE(prawpartha->hostname_len_) };
			case FIELD_MADID		:	return { madhava_id_str_,			16 };
			case FIELD_CLUSTER 		: 	return { prawpartha->cluster_name_,		GY_READ_ONCE(prawpartha->cluster_len_) };

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
			const SUBSYS_CLASS_E		subsysarr[] {SUBSYS_SVCSUMM, SUBSYS_HOST};

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
		bool print_field(uint32_t jsoncrc, Jsonwriter & writer, const char *timebuf = nullptr) const
		{
			const auto			*prawpartha = &partha_;
			const auto			& stats = stats_;

			switch (jsoncrc) {
			
			case FIELD_PARID :
				writer.KeyConst("parid");
				writer.String(prawpartha->machine_id_str_, sizeof(prawpartha->machine_id_str_) - 1);
				return true;
			
			case FIELD_HOST :
				writer.KeyConst("host");
				writer.String(prawpartha->hostname_, GY_READ_ONCE(prawpartha->hostname_len_));
				return true;

			case FIELD_MADID :
				writer.KeyConst("madid");
				writer.String(madhava_id_str_, 16);
				return true;

			case FIELD_CLUSTER :
				writer.KeyConst("cluster");
				writer.String(prawpartha->cluster_name_, GY_READ_ONCE(prawpartha->cluster_len_));
				return true;

			case FIELD_TIME :
				writer.KeyConst("time");

				if (timebuf) {
					writer.String(timebuf);
				}
				else {
					struct timeval 			tv = GY_USEC_TO_TIMEVAL(prawpartha->last_listen_state_tusec_);
					
					writer.String(gy_localtime_iso8601_sec(tv.tv_sec).get());	
				}
				return true;

			case FIELD_NIDLE :
				writer.KeyConst("nidle");
				writer.Int64(stats.nstates_[STATE_IDLE]);
				return true;

			case FIELD_NGOOD :
				writer.KeyConst("ngood");
				writer.Int64(stats.nstates_[STATE_GOOD]);
				return true;

			case FIELD_NOK :
				writer.KeyConst("nok");
				writer.Int64(stats.nstates_[STATE_OK]);
				return true;

			case FIELD_NBAD :
				writer.KeyConst("nbad");
				writer.Int64(stats.nstates_[STATE_BAD]);
				return true;

			case FIELD_NSEVERE :
				writer.KeyConst("nsevere");
				writer.Int64(stats.nstates_[STATE_SEVERE]);
				return true;

			case FIELD_NDOWN :
				writer.KeyConst("ndown");
				writer.Int64(stats.nstates_[STATE_DOWN]);
				return true;

			case FIELD_TOTQPS :
				writer.KeyConst("totqps");
				writer.Int64(stats.tot_qps_);
				return true;

			case FIELD_TOTACONN :
				writer.KeyConst("totaconn");
				writer.Int64(stats.tot_act_conn_);
				return true;

			case FIELD_TOTKBIN :
				writer.KeyConst("totkbin");
				writer.Int64(stats.tot_kb_inbound_);
				return true;

			case FIELD_TOTKBOUT :
				writer.KeyConst("totkbout");
				writer.Int64(stats.tot_kb_outbound_);
				return true;
			
			case FIELD_TOTSERERR :
				writer.KeyConst("totsererr");
				writer.Int64(stats.tot_ser_errors_);
				return true;

			case FIELD_NSVC :
				writer.KeyConst("nsvc");
				writer.Int64(stats.nlisteners_);
				return true;

			case FIELD_NACTIVE :
				writer.KeyConst("nactive");
				writer.Int64(stats.nactive_);
				return true;

			default :
				return false;
			}	

			return false;
		}

		template <typename Jsonwriter>
		void print_json(const JSON_DB_MAPPING * const *colarr, size_t ncol, Jsonwriter & writer, const char *timebuf = nullptr, bool startobj = true) const
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

	class SvcInfoFields
	{
	public :
		const TCP_Listener 		& listener_;
		const char 			*madhava_id_str_;
		const ParthaInfo		*prawpartha_;
		time_t				tcurr_;
		mutable uint32_t		last_unknown_jsoncrc_		{0};

		SvcInfoFields(const TCP_Listener & listener, const char *madhava_id_str, time_t tcurr = 0) 
			: listener_(listener), madhava_id_str_(madhava_id_str), prawpartha_(listener_.parthashr_.get()), tcurr_(tcurr)
		{
			if (!prawpartha_) GY_THROW_EXPRESSION("Invalid Listener object for Svc Info Fields as Null Partha seen"); 
		}

		SvcInfoFields(const ParthaInfo & partha, const TCP_Listener & listener, const char *madhava_id_str, time_t tcurr = 0) noexcept
			: listener_(listener), madhava_id_str_(madhava_id_str), prawpartha_(&partha), tcurr_(tcurr)
		{}

		NUMBER_CRITERION get_num_field(const JSON_DB_MAPPING *pfield) const noexcept
		{
			const auto			& listener = listener_;

			switch (pfield->jsoncrc) {
			
			case FIELD_PORT			:	return NUMBER_CRITERION((int)listener.ns_ip_port_.ip_port_.port_);
			case FIELD_TSTART		:	return NUMBER_CRITERION((int64_t)(listener.tusec_start_/GY_USEC_PER_SEC));

			case FIELD_P95RESP5D		:	return NUMBER_CRITERION((int)listener.day_stats_.p95_5d_respms_);
			case FIELD_AVGRESP5D		:	return NUMBER_CRITERION((int64_t)(listener.day_stats_.tsum_5d_/NUM_OR_1(listener.day_stats_.tcount_5d_)));
			case FIELD_P95QPS		:	return NUMBER_CRITERION((int)listener.day_stats_.p95_qps_);
			case FIELD_P95ACONN		:	return NUMBER_CRITERION((int)listener.day_stats_.p95_nactive_);

			case FIELD_SVCPORT1		:	return NUMBER_CRITERION((int)listener.nat_ip_port_arr_[0].port_);
			case FIELD_SVCPORT2		:	return NUMBER_CRITERION((int)listener.nat_ip_port_arr_[1].port_);

			case FIELD_NSVCMESH		:	return NUMBER_CRITERION((int)listener.ntotal_mesh_svc_);
			case FIELD_NIP1SVC		:	return NUMBER_CRITERION((int)listener.ntotal_nat_ip_svc_[0]);
			case FIELD_NIP2SVC		:	return NUMBER_CRITERION((int)listener.ntotal_nat_ip_svc_[1]);

			default				:	last_unknown_jsoncrc_ = pfield->jsoncrc; return {};
			}	
		}	

		std::pair<const char *, uint32_t> get_str_field(const JSON_DB_MAPPING *pfield, char * tbuf, size_t szbuf) const noexcept
		{
			const auto			& listener = listener_;
			const auto			*prawpartha = prawpartha_;

			switch (pfield->jsoncrc) {

			case FIELD_PARID 		: 	return { prawpartha->machine_id_str_, 		32 };
			case FIELD_HOST 		: 	return { prawpartha->hostname_, 		GY_READ_ONCE(prawpartha->hostname_len_) };
			case FIELD_MADID		:	return { madhava_id_str_,			16 };
			case FIELD_CLUSTER 		: 	return { prawpartha->cluster_name_,		GY_READ_ONCE(prawpartha->cluster_len_) };
			case FIELD_REGION		:	return { prawpartha->region_name_,		GY_READ_ONCE(prawpartha->region_len_) };
			case FIELD_ZONE			:	return { prawpartha->zone_name_,		GY_READ_ONCE(prawpartha->zone_len_) };

			case FIELD_SVCID		:	
				if (tbuf && szbuf > 16) {
					std::pair<const char *, uint32_t>	p;

					p.first		= tbuf;
					p.second 	= snprintf(tbuf, szbuf, "%016lx", listener.glob_id_);

					return p;
				}
				return {};

			case FIELD_NAME			:	return { listener.comm_, GY_READ_ONCE(listener.comm_len_) };

			case FIELD_IP			:	
				do {
					listener.ns_ip_port_.ip_port_.ipaddr_.printaddr(tbuf, szbuf);

					return { tbuf, strlen(tbuf) };
				} while (false);	

			case FIELD_RELSVCID		:	
				if (tbuf && szbuf > 16) {
					std::pair<const char *, uint32_t>	p;

					p.first		= tbuf;
					p.second 	= snprintf(tbuf, szbuf, "%016lx", listener.related_listen_id_);

					return p;
				}
				return {};

			case FIELD_CMDLINE		:	return { listener.cmdline_, GY_READ_ONCE(listener.cmdline_len_) };

			case FIELD_SVCIP1		:	
				do {
					if (listener.nat_ip_port_arr_[0].port_ > 0) {
						listener.nat_ip_port_arr_[0].ipaddr_.printaddr(tbuf, szbuf);

						return { tbuf, strlen(tbuf) };
					}
					return {};
				} while (false);

			case FIELD_SVCIP2		:	
				do {
					if (listener.nat_ip_port_arr_[1].port_ > 0) {
						listener.nat_ip_port_arr_[1].ipaddr_.printaddr(tbuf, szbuf);

						return { tbuf, strlen(tbuf) };
					}
					return {};
				} while (false);

			case FIELD_SVCDNS		:	return { listener.server_domain_, GY_READ_ONCE(listener.domain_string_len_) };

			case FIELD_SVCTAG		:
				do {

					auto relshr = listener.related_listen_shr_.load(mo_relaxed);

					if (relshr) {
						return { relshr->tagbuf_, GY_READ_ONCE(relshr->tag_len_) };
					}	

					return {};
				} while (false);	

			case FIELD_SVCMESHID		:	
				if (listener.is_cluster_mesh_ && tbuf && szbuf > 16) {
					std::pair<const char *, uint32_t>	p;

					p.first		= tbuf;
					p.second 	= snprintf(tbuf, szbuf, "%016lx", listener.eff_mesh_cluster_id_.load(mo_relaxed));

					return p;
				}
				return {};

			case FIELD_IP1CLUID		:	
				if (listener.is_cluster_nat_ip_[0] && tbuf && szbuf > 16) {
					std::pair<const char *, uint32_t>	p;

					p.first		= tbuf;
					p.second 	= snprintf(tbuf, szbuf, "%016lx", listener.nat_ip_cluster_id_[0].load(mo_relaxed));

					return p;
				}
				return {};

			case FIELD_IP2CLUID		:	
				if (listener.is_cluster_nat_ip_[0] && tbuf && szbuf > 16) {
					std::pair<const char *, uint32_t>	p;

					p.first		= tbuf;
					p.second 	= snprintf(tbuf, szbuf, "%016lx", listener.nat_ip_cluster_id_[1].load(mo_relaxed));

					return p;
				}
				return {};


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
			const SUBSYS_CLASS_E		subsysarr[] {SUBSYS_SVCINFO, SUBSYS_HOST};

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
			const auto			*prawpartha = prawpartha_;
			const auto			& listener = listener_;

			switch (jsoncrc) {

			case FIELD_TIME :
				writer.KeyConst("time");
				writer.String(timebuf ? timebuf : "");
				return true;

			case FIELD_SVCID :
				writer.KeyConst("svcid");
				writer.String(number_to_string(listener.glob_id_, "%016lx").get(), 16);
				return true;

			case FIELD_PARID :
				writer.KeyConst("parid");
				writer.String(prawpartha->machine_id_str_, 32);
				return true;
			
			case FIELD_HOST :
				writer.KeyConst("host");
				writer.String(prawpartha->hostname_, GY_READ_ONCE(prawpartha->hostname_len_));
				return true;

			case FIELD_MADID :
				writer.KeyConst("madid");
				writer.String(madhava_id_str_, 16);
				return true;

			case FIELD_CLUSTER :
				writer.KeyConst("cluster");
				writer.String(prawpartha->cluster_name_, GY_READ_ONCE(prawpartha->cluster_len_));
				return true;

			case FIELD_NAME :
				writer.KeyConst("name");
				writer.String(listener.comm_, GY_READ_ONCE(listener.comm_len_));
				return true;

			case FIELD_IP :
				writer.KeyConst("ip");
				writer.String(listener.ns_ip_port_.ip_port_.ipaddr_.printaddr().get());
				return true;

			case FIELD_PORT :
				writer.KeyConst("port");
				writer.Int(listener.ns_ip_port_.ip_port_.port_);
				return true;

			case FIELD_RELSVCID :
				writer.KeyConst("relsvcid");
				writer.String(number_to_string(listener.related_listen_id_, "%016lx").get(), 16);
				return true;

			case FIELD_TSTART :
				writer.KeyConst("tstart");
				writer.String(gy_localtime_iso8601_sec(listener.tusec_start_/GY_USEC_PER_SEC).get());
				return true;

			case FIELD_CMDLINE :
				writer.KeyConst("cmdline");
				writer.String(listener.cmdline_, GY_READ_ONCE(listener.cmdline_len_));
				return true;

			case FIELD_P95RESP5D :
				writer.KeyConst("p95resp5d");
				writer.Int(listener.day_stats_.p95_5d_respms_);
				return true;

			case FIELD_AVGRESP5D :
				writer.KeyConst("avgresp5d");
				writer.Int64(listener.day_stats_.tsum_5d_/NUM_OR_1(listener.day_stats_.tcount_5d_));
				return true;

			case FIELD_P95QPS :
				writer.KeyConst("p95qps");
				writer.Int(listener.day_stats_.p95_qps_);
				return true;

			case FIELD_P95ACONN :
				writer.KeyConst("p95aconn");
				writer.Int(listener.day_stats_.p95_nactive_);
				return true;

			case FIELD_SVCIP1 :
				writer.KeyConst("svcip1");

				if (listener.nat_ip_port_arr_[0].port_ > 0) {
					writer.String(listener.nat_ip_port_arr_[0].ipaddr_.printaddr().get());
				}
				else {
					writer.String("", 0);
				}
				return true;

			case FIELD_SVCPORT1 :
				writer.KeyConst("svcport1");
				writer.Int(listener.nat_ip_port_arr_[0].port_);
				return true;

			case FIELD_SVCIP2 :
				writer.KeyConst("svcip2");

				if (listener.nat_ip_port_arr_[1].port_ > 0) {
					writer.String(listener.nat_ip_port_arr_[1].ipaddr_.printaddr().get());
				}
				else {
					writer.String("", 0);
				}
				return true;

			case FIELD_SVCPORT2 :
				writer.KeyConst("svcport2");
				writer.Int(listener.nat_ip_port_arr_[1].port_);
				return true;

			case FIELD_SVCDNS :
				writer.KeyConst("svcdns");
				writer.String(listener.server_domain_, GY_READ_ONCE(listener.domain_string_len_));
				return true;

			case FIELD_SVCTAG :
				if (true) {
					writer.KeyConst("svctag");

					auto relshr = listener.related_listen_shr_.load(mo_relaxed);

					if (relshr) {
						writer.String(relshr->tagbuf_, GY_READ_ONCE(relshr->tag_len_));
					}	
					else {
						writer.String("", 0);
					}	
				}
				return true;

			case FIELD_SVCMESHID :
				writer.KeyConst("svcmeshid");

				if (listener.is_cluster_mesh_) {
					writer.String(number_to_string(listener.eff_mesh_cluster_id_.load(mo_relaxed), "%016lx").get(), 16);
				}
				else {
					writer.String("", 0);
				}	
				return true;

			case FIELD_NSVCMESH :
				writer.KeyConst("nsvcmesh");
				writer.Int(listener.ntotal_mesh_svc_);
				return true;

			case FIELD_IP1CLUID :
				writer.KeyConst("ip1cluid");

				if (listener.is_cluster_nat_ip_[0]) {
					writer.String(number_to_string(listener.nat_ip_cluster_id_[0].load(mo_relaxed), "%016lx").get(), 16);
				}
				else {
					writer.String("", 0);
				}	
				return true;

			case FIELD_NIP1SVC :
				writer.KeyConst("nip1svc");
				writer.Int(listener.ntotal_nat_ip_svc_[0]);
				return true;

			case FIELD_IP2CLUID :
				writer.KeyConst("ip2cluid");

				if (listener.is_cluster_nat_ip_[1]) {
					writer.String(number_to_string(listener.nat_ip_cluster_id_[1].load(mo_relaxed), "%016lx").get(), 16);
				}
				else {
					writer.String("", 0);
				}	
				return true;

			case FIELD_NIP2SVC :
				writer.KeyConst("nip2svc");
				writer.Int(listener.ntotal_nat_ip_svc_[1]);
				return true;

			case FIELD_REGION :
				writer.KeyConst("region");
				writer.String(prawpartha->region_name_, GY_READ_ONCE(prawpartha->region_len_));
				return true;

			case FIELD_ZONE :
				writer.KeyConst("zone");
				writer.String(prawpartha->zone_name_, GY_READ_ONCE(prawpartha->zone_len_));
				return true;


			default :
				return false;
			}	
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

	class SvcStateFields
	{
	public :
		const TCP_Listener 		& listener_;
		const char 			*madhava_id_str_;
		const ParthaInfo		*prawpartha_;
		time_t				tcurr_;
		mutable uint32_t		last_unknown_jsoncrc_		{0};

		SvcStateFields(const TCP_Listener & listener, const char *madhava_id_str, time_t tcurr = 0)
			: listener_(listener), madhava_id_str_(madhava_id_str), prawpartha_(listener_.parthashr_.get()), tcurr_(tcurr)
		{
			if (!prawpartha_) GY_THROW_EXPRESSION("Invalid Listener object for Svc State Fields as Null Partha seen"); 
		}

		SvcStateFields(const ParthaInfo & partha, const TCP_Listener & listener, const char *madhava_id_str, time_t tcurr = 0) noexcept
			: listener_(listener), madhava_id_str_(madhava_id_str), prawpartha_(&partha), tcurr_(tcurr)
		{}

		NUMBER_CRITERION get_num_field(const JSON_DB_MAPPING *pfield) const noexcept
		{
			const auto				& listener = listener_;
			const comm::LISTENER_STATE_NOTIFY	& state = listener.state_;

			switch (pfield->jsoncrc) {
			
			case FIELD_QPS5S		:	return NUMBER_CRITERION(int(state.nqrys_5s_/5));
			case FIELD_NQRY5S		:	return NUMBER_CRITERION(int(state.nqrys_5s_));
			case FIELD_RESP5S		:	return NUMBER_CRITERION(int(state.total_resp_5sec_/(state.nqrys_5s_ ? state.nqrys_5s_ : 1)));
			case FIELD_P95RESP5S		:	return NUMBER_CRITERION(int(state.p95_5s_resp_ms_));
			case FIELD_P95RESP5M		:	return NUMBER_CRITERION(int(state.p95_5min_resp_ms_));
			case FIELD_NCONNS		:	return NUMBER_CRITERION(int(state.nconns_));
			case FIELD_NACTIVE		:	return NUMBER_CRITERION(int(state.nconns_active_));
			case FIELD_NPROCS		:	return NUMBER_CRITERION(int(state.ntasks_));

			case FIELD_KBIN15S		:	return NUMBER_CRITERION(int(state.curr_kbytes_inbound_));
			case FIELD_KBOUT15S		:	return NUMBER_CRITERION(int(state.curr_kbytes_outbound_));
			case FIELD_SERERR		:	return NUMBER_CRITERION(int(state.ser_http_errors_));
			case FIELD_CLIERR		:	return NUMBER_CRITERION(int(state.cli_http_errors_));

			case FIELD_DELAYUS		:	return NUMBER_CRITERION(int(state.tasks_delay_usec_));
			case FIELD_CPUDELUS		:	return NUMBER_CRITERION(int(state.tasks_cpudelay_usec_));
			case FIELD_IODELUS		:	return NUMBER_CRITERION(int(state.tasks_blkiodelay_usec_));
			case FIELD_VMDELUS		:	return NUMBER_CRITERION(int(state.tasks_delay_usec_ - state.tasks_cpudelay_usec_ - state.tasks_blkiodelay_usec_));

			case FIELD_USERCPU		:	return NUMBER_CRITERION(int(state.tasks_user_cpu_));
			case FIELD_SYSCPU		:	return NUMBER_CRITERION(int(state.tasks_sys_cpu_));
			case FIELD_RSSMB		:	return NUMBER_CRITERION(int(state.tasks_rss_mb_));

			case FIELD_NISSUE		:	return NUMBER_CRITERION(int(state.ntasks_issue_));
			case FIELD_ISSUE		:	return NUMBER_CRITERION(int16_t(state.curr_issue_));

			default				:	last_unknown_jsoncrc_ = pfield->jsoncrc; return {};
			}				
		}	

		std::pair<const char *, uint32_t> get_str_field(const JSON_DB_MAPPING *pfield, char * tbuf, size_t szbuf) const noexcept
		{
			const auto				& listener = listener_;
			const comm::LISTENER_STATE_NOTIFY	& state = listener.state_;
			const auto				*prawpartha = prawpartha_;

			switch (pfield->jsoncrc) {

			case FIELD_PARID 		: 	return { prawpartha->machine_id_str_, 		32 };
			case FIELD_HOST 		: 	return { prawpartha->hostname_, 		GY_READ_ONCE(prawpartha->hostname_len_) };
			case FIELD_MADID		:	return { madhava_id_str_,			16 };
			case FIELD_CLUSTER 		: 	return { prawpartha->cluster_name_,		GY_READ_ONCE(prawpartha->cluster_len_) };

			case FIELD_SVCID		:	
				if (tbuf && szbuf > 16) {
					std::pair<const char *, uint32_t>	p;

					p.first		= tbuf;
					p.second 	= snprintf(tbuf, szbuf, "%016lx", listener.glob_id_);

					return p;
				}
				return {};

			case FIELD_NAME			:	return { listener.comm_, GY_READ_ONCE(listener.comm_len_) };
			
			case FIELD_STATE		:	return state_to_stringlen((OBJ_STATE_E)state.curr_state_);

			case FIELD_DESC			:	
				do {
					uint32_t		len = GY_READ_ONCE(state.issue_string_len_);
					
					if (len > 1) {
						return { listener.issue_string_, len - 1 };
					}

					return {};
				} while (false);	
			
			default				:	last_unknown_jsoncrc_ = pfield->jsoncrc; return {};
			}
		}	

		BOOL_CRITERION get_bool_field(const JSON_DB_MAPPING *pfield) const noexcept
		{
			const auto				& listener = listener_;
			const comm::LISTENER_STATE_NOTIFY	& state = listener.state_;

			switch (pfield->jsoncrc) {

			case FIELD_ISHTTP		:	return BOOL_CRITERION(state.is_http_svc_);

			default				:	last_unknown_jsoncrc_ = pfield->jsoncrc; return {};
			}	
		}	

		CRIT_RET_E filter_match(const CRITERIA_SET & criteria) const
		{
			const SUBSYS_CLASS_E		subsysarr[] {SUBSYS_SVCSTATE, SUBSYS_HOST};

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
		bool print_field(uint32_t jsoncrc, Jsonwriter & writer, const char *timebuf = nullptr) const
		{
			const auto			*prawpartha = prawpartha_;
			const auto			& listener = listener_;
			const auto			& state = listener.state_;

			switch (jsoncrc) {

			case FIELD_PARID :
				writer.KeyConst("parid");
				writer.String(prawpartha_->machine_id_str_, 32);
				return true;
			
			case FIELD_HOST :
				writer.KeyConst("host");
				writer.String(prawpartha_->hostname_, GY_READ_ONCE(prawpartha_->hostname_len_));
				return true;

			case FIELD_MADID :
				writer.KeyConst("madid");
				writer.String(madhava_id_str_, 16);
				return true;

			case FIELD_CLUSTER :
				writer.KeyConst("cluster");
				writer.String(prawpartha_->cluster_name_, GY_READ_ONCE(prawpartha_->cluster_len_));
				return true;

			case FIELD_TIME :
				writer.KeyConst("time");

				if (timebuf) {
					writer.String(timebuf);
				}
				else {
					auto 			tusec = listener.last_state_tusec_.load(mo_relaxed);
					
					writer.String(gy_localtime_iso8601(tusec/GY_USEC_PER_SEC, CHAR_BUF<64>().get(), 64));	
				}
				return true;

			case FIELD_SVCID :
				writer.KeyConst("svcid");
				writer.String(number_to_string(listener.glob_id_, "%016lx").get(), 16);
				return true;

			case FIELD_NAME :
				writer.KeyConst("name");
				writer.String(listener.comm_, GY_READ_ONCE(listener.comm_len_));
				return true;

			case FIELD_QPS5S :
				writer.KeyConst("qps5s");
				writer.Uint(state.nqrys_5s_/5);
				return true;

			case FIELD_NQRY5S :
				writer.KeyConst("nqry5s");
				writer.Uint(state.nqrys_5s_);
				return true;

			case FIELD_RESP5S :
				if (true) {
					auto 			nqrys_5s = state.nqrys_5s_;

					writer.KeyConst("resp5s");
					writer.Uint(state.total_resp_5sec_/(nqrys_5s > 0 ? nqrys_5s : 1));
				}
				return true;

			case FIELD_P95RESP5S :
				writer.KeyConst("p95resp5s");
				writer.Uint(state.p95_5s_resp_ms_);
				return true;

			case FIELD_P95RESP5M :
				writer.KeyConst("p95resp5m");
				writer.Uint(state.p95_5min_resp_ms_);
				return true;

			case FIELD_NCONNS :
				writer.KeyConst("nconns");
				writer.Uint(state.nconns_);
				return true;

			case FIELD_NACTIVE :
				writer.KeyConst("nactive");
				writer.Uint(state.nconns_active_);
				return true;

			case FIELD_NPROCS :
				writer.KeyConst("nprocs");
				writer.Uint(state.ntasks_);
				return true;

			case FIELD_KBIN15S :
				writer.KeyConst("kbin15s");
				writer.Uint(state.curr_kbytes_inbound_);
				return true;

			case FIELD_KBOUT15S :
				writer.KeyConst("kbout15s");
				writer.Uint(state.curr_kbytes_outbound_);
				return true;

			case FIELD_SERERR :
				writer.KeyConst("sererr");
				writer.Uint(state.ser_http_errors_);
				return true;

			case FIELD_CLIERR :
				writer.KeyConst("clierr");
				writer.Uint(state.cli_http_errors_);
				break;

			case FIELD_DELAYUS :
				writer.KeyConst("delayus");
				writer.Uint(state.tasks_delay_usec_);
				return true;

			case FIELD_CPUDELUS :
				writer.KeyConst("cpudelus");
				writer.Uint(state.tasks_cpudelay_usec_);
				return true;

			case FIELD_IODELUS :
				writer.KeyConst("iodelus");
				writer.Uint(state.tasks_blkiodelay_usec_);
				return true;

			case FIELD_VMDELUS :
				if (true) {
					int64_t			vmdelus = state.tasks_delay_usec_ - state.tasks_cpudelay_usec_ - state.tasks_blkiodelay_usec_;

					writer.KeyConst("vmdelus");
					writer.Uint(vmdelus > 0 ? (uint32_t)vmdelus : 0);
				}	
				return true;

			case FIELD_USERCPU :
				writer.KeyConst("usercpu");
				writer.Uint(state.tasks_user_cpu_);
				return true;

			case FIELD_SYSCPU :
				writer.KeyConst("syscpu");
				writer.Uint(state.tasks_sys_cpu_);
				return true;
			
			case FIELD_RSSMB :
				writer.KeyConst("rssmb");
				writer.Uint(state.tasks_rss_mb_);
				break;

			case FIELD_NISSUE :
				writer.KeyConst("nissue");
				writer.Uint(state.ntasks_issue_);
				return true;

			case FIELD_STATE :
				writer.KeyConst("state");
				writer.String(state_to_stringlen((OBJ_STATE_E)state.curr_state_));
				return true;
			
			case FIELD_ISSUE :
				writer.KeyConst("issue");
				writer.Uint(state.curr_issue_);
				return true;

			case FIELD_ISHTTP :
				writer.KeyConst("ishttp");
				writer.Bool(state.is_http_svc_);
				return true;

			case FIELD_DESC :
				if (true) {
					uint32_t		len = GY_READ_ONCE(state.issue_string_len_);

					writer.KeyConst("desc");
					writer.String(listener.issue_string_, len > 1 ? len - 1 : 0);
				}	
				return true;
			
			default :
				return false;
			}	

			return false;
		}	

		template <typename Jsonwriter>
		void print_json(const JSON_DB_MAPPING * const *colarr, size_t ncol, Jsonwriter & writer, const char *timebuf = nullptr, bool startobj = true) const
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

	class ExtSvcStateFields
	{
	public :
		SvcStateFields			svcstatefields_;
		SvcInfoFields			svcinfofields_;

		ExtSvcStateFields(const TCP_Listener & listener, const char *madhava_id_str, time_t tcurr = 0) 
			: svcstatefields_(listener, madhava_id_str, tcurr), svcinfofields_(listener, madhava_id_str, tcurr)
		{}

		ExtSvcStateFields(const ParthaInfo & partha, const TCP_Listener & listener, const char *madhava_id_str, time_t tcurr = 0) noexcept
			: svcstatefields_(partha, listener, madhava_id_str, tcurr), svcinfofields_(partha, listener, madhava_id_str, tcurr)
		{}

		NUMBER_CRITERION get_num_field(const JSON_DB_MAPPING *pfield) const noexcept
		{
			auto				numc = svcstatefields_.get_num_field(pfield);

			if (!numc.is_valid() && svcstatefields_.last_unknown_jsoncrc_ == pfield->jsoncrc) {
				return svcinfofields_.get_num_field(pfield);
			}	

			return numc;
		}	

		std::pair<const char *, uint32_t> get_str_field(const JSON_DB_MAPPING *pfield, char * tbuf, size_t szbuf) const noexcept
		{
			auto				p = svcstatefields_.get_str_field(pfield, tbuf, szbuf);

			if (!p.second && svcstatefields_.last_unknown_jsoncrc_ == pfield->jsoncrc) {
				return svcinfofields_.get_str_field(pfield, tbuf, szbuf);
			}	

			return p;
		}	

		BOOL_CRITERION get_bool_field(const JSON_DB_MAPPING *pfield) const noexcept
		{
			auto				b = svcstatefields_.get_bool_field(pfield);

			if (!b.is_valid() && svcstatefields_.last_unknown_jsoncrc_ == pfield->jsoncrc) {
				return svcinfofields_.get_bool_field(pfield);
			}	

			return b;
		}	

		CRIT_RET_E filter_match(const CRITERIA_SET & criteria) const
		{
			const SUBSYS_CLASS_E		subsysarr[] {SUBSYS_EXTSVCSTATE, SUBSYS_HOST};

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

			return criteria.match_criteria(num_field, str_field, bool_field, svcstatefields_.tcurr_, subsysarr, GY_ARRAY_SIZE(subsysarr));
		}	

		template <typename Jsonwriter>
		void print_json(const JSON_DB_MAPPING * const *colarr, size_t ncol, Jsonwriter & writer, const char *timebuf = nullptr, bool startobj = true) const
		{
			if (startobj) {
				writer.StartObject();
			}
			
			for (size_t i = 0; i < ncol; ++i) {
				bool			bret;
				
				bret = svcstatefields_.print_field(colarr[i]->jsoncrc, writer, timebuf);

				if (!bret) {
					svcinfofields_.print_field(colarr[i]->jsoncrc, writer, timebuf);
				}	
			}

			if (startobj) {
				writer.EndObject();
			}
		}
	};	

	class ProcInfoFields
	{
	public :
		const ParthaInfo		& partha_;
		const AggrTask	 		& task_;
		const char 			*madhava_id_str_;
		time_t				tcurr_;
		mutable uint32_t		last_unknown_jsoncrc_		{0};

		ProcInfoFields(const ParthaInfo & partha, const AggrTask & task, const char *madhava_id_str, time_t tcurr = 0) noexcept
			: partha_(partha), task_(task), madhava_id_str_(madhava_id_str), tcurr_(tcurr)
		{};

		NUMBER_CRITERION get_num_field(const JSON_DB_MAPPING *pfield) const noexcept
		{
			const auto			& task = task_;

			switch (pfield->jsoncrc) {

			case FIELD_UID			:	return NUMBER_CRITERION(int(task.uid_));
			case FIELD_GID			:	return NUMBER_CRITERION(int(task.gid_));
			case FIELD_TSTART		:	return NUMBER_CRITERION((int64_t)(task.histstats_.starttimeusec_/GY_USEC_PER_SEC));
			case FIELD_P95CPUPCT		:	return NUMBER_CRITERION((int)task.histstats_.p95_cpu_pct_);
			case FIELD_P95CPUDEL		:	return NUMBER_CRITERION((int)task.histstats_.p95_cpu_delay_ms_);
			case FIELD_P95IODEL		:	return NUMBER_CRITERION((int)task.histstats_.p95_blkio_delay_ms_);
			case FIELD_NPROC		:	return NUMBER_CRITERION((int)task.histstats_.nprocs_);
			case FIELD_NTHR			:	return NUMBER_CRITERION((int)task.histstats_.nthreads_);
			case FIELD_MAXCORE		:	return NUMBER_CRITERION((int16_t)task.histstats_.max_cores_allowed_);
			case FIELD_CGCPULIMPCT		:	return NUMBER_CRITERION((int16_t)task.histstats_.cpu_cg_pct_limit_);
			case FIELD_CGRSSPCT		:	return NUMBER_CRITERION((int16_t)task.histstats_.max_mem_cg_pct_rss_);

			default				:	last_unknown_jsoncrc_ = pfield->jsoncrc; return {};
			}	
		}	

		std::pair<const char *, uint32_t> get_str_field(const JSON_DB_MAPPING *pfield, char * tbuf, size_t szbuf) const noexcept
		{
			const auto			*prawpartha = &partha_;
			const auto			& task = task_;

			switch (pfield->jsoncrc) {

			case FIELD_PARID 		: 	return { prawpartha->machine_id_str_, 		32 };
			case FIELD_HOST 		: 	return { prawpartha->hostname_, 		GY_READ_ONCE(prawpartha->hostname_len_) };
			case FIELD_MADID		:	return { madhava_id_str_,			16 };
			case FIELD_CLUSTER 		: 	return { prawpartha->cluster_name_,		GY_READ_ONCE(prawpartha->cluster_len_) };
			case FIELD_REGION		:	return { prawpartha->region_name_,		GY_READ_ONCE(prawpartha->region_len_) };
			case FIELD_ZONE			:	return { prawpartha->zone_name_,		GY_READ_ONCE(prawpartha->zone_len_) };

			case FIELD_PROCID		:	
				if (tbuf && szbuf > 16) {
					std::pair<const char *, uint32_t>	p;

					p.first		= tbuf;
					p.second 	= snprintf(tbuf, szbuf, "%016lx", task.aggr_task_id_);

					return p;
				}
				return {};

			case FIELD_NAME			:	return { task.comm_, GY_READ_ONCE(task.comm_len_) };
			
			case FIELD_RELSVCID		:	
				if (tbuf && szbuf > 16) {
					std::pair<const char *, uint32_t>	p;

					p.first		= tbuf;
					p.second 	= snprintf(tbuf, szbuf, "%016lx", task.related_listen_id_);

					return p;
				}
				return {};

			case FIELD_TAG			:	return { task.tagbuf_, GY_READ_ONCE(task.tag_len_) };

			case FIELD_CMDLINE		:	return { task.cmdline_.data(), task.cmdline_len_.load(mo_relaxed) };

			default				:	last_unknown_jsoncrc_ = pfield->jsoncrc; return {};
			}	
		}	

		BOOL_CRITERION get_bool_field(const JSON_DB_MAPPING *pfield) const noexcept
		{
			const auto			& task = task_;

			switch (pfield->jsoncrc) {

			case FIELD_HICAP		:	return bool(task.is_high_cap_);
			case FIELD_CPUTHR		:	return bool(task.is_cpu_cgroup_throttled_);	 
			case FIELD_MEMLIM		:	return bool(task.is_mem_cgroup_limited_);
			case FIELD_RTPROC		:	return bool(task.is_rt_proc_);
			case FIELD_CONPROC		:	return bool(task.is_container_proc_);

			default				:	last_unknown_jsoncrc_ = pfield->jsoncrc; return {};
			}	
		}	

		CRIT_RET_E filter_match(const CRITERIA_SET & criteria) const
		{
			const SUBSYS_CLASS_E		subsysarr[] {SUBSYS_PROCINFO, SUBSYS_HOST};

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
			const auto			*prawpartha = &partha_;
			const auto			& task = task_;
			const auto			& hist = task.histstats_;

			switch (jsoncrc) {

			case FIELD_TIME :
				writer.KeyConst("time");
				writer.String(timebuf ? timebuf : "");
				return true;

			case FIELD_PARID :
				writer.KeyConst("parid");
				writer.String(prawpartha->machine_id_str_, 32);
				return true;

			case FIELD_HOST :
				writer.KeyConst("host");
				writer.String(prawpartha->hostname_, GY_READ_ONCE(prawpartha->hostname_len_));
				return true;
				
			case FIELD_MADID :
				writer.KeyConst("madid");
				writer.String(madhava_id_str_, 16);
				return true;

			case FIELD_CLUSTER :
				writer.KeyConst("cluster");
				writer.String(prawpartha->cluster_name_, GY_READ_ONCE(prawpartha->cluster_len_));
				return true;

			case FIELD_PROCID :
				writer.KeyConst("procid");
				writer.String(number_to_string(task.aggr_task_id_, "%016lx").get(), 16);
				return true;

			case FIELD_NAME :
				writer.KeyConst("name");
				writer.String(task.comm_);
				return true;

			case FIELD_RELSVCID :
				writer.KeyConst("relsvcid");
				writer.String(number_to_string(task.related_listen_id_, "%016lx").get(), 16);
				return true;

			case FIELD_CMDLINE :
				writer.KeyConst("cmdline");
				writer.String(task.cmdline_.data(), task.cmdline_len_.load(mo_relaxed));
				return true;

			case FIELD_TAG :	
				writer.KeyConst("tag");
				writer.String(task.tagbuf_, GY_READ_ONCE(task.tag_len_));
				return true;

			case FIELD_UID :	
				writer.KeyConst("uid");
				writer.Int(task.uid_);
				return true;

			case FIELD_GID :	
				writer.KeyConst("gid");
				writer.Int(task.gid_);
				return true;

			case FIELD_HICAP :	
				writer.KeyConst("hicap");
				writer.Bool(bool(task.is_high_cap_));
				return true;

			case FIELD_CPUTHR :	
				writer.KeyConst("cputhr");
				writer.Bool(bool(task.is_cpu_cgroup_throttled_));
				return true;

			case FIELD_MEMLIM :	
				writer.KeyConst("memlim");
				writer.Bool(bool(task.is_mem_cgroup_limited_));
				return true;

			case FIELD_RTPROC :	
				writer.KeyConst("rtproc");
				writer.Bool(bool(task.is_rt_proc_));
				return true;

			case FIELD_CONPROC :	
				writer.KeyConst("conproc");
				writer.Bool(bool(task.is_container_proc_));
				return true;

			case FIELD_TSTART :	
				writer.KeyConst("tstart");
				writer.String(gy_localtime_iso8601_sec(hist.starttimeusec_/GY_USEC_PER_SEC).get());
				return true;

			case FIELD_P95CPUPCT :	
				writer.KeyConst("p95cpupct");
				writer.Int(hist.p95_cpu_pct_);
				return true;

			case FIELD_P95CPUDEL :	
				writer.KeyConst("p95cpudel");
				writer.Int(hist.p95_cpu_delay_ms_);
				return true;

			case FIELD_P95IODEL :
				writer.KeyConst("p95iodel");
				writer.Int(hist.p95_blkio_delay_ms_);
				return true;

			case FIELD_NPROC :
				writer.KeyConst("nproc");
				writer.Int(hist.nprocs_);
				return true;

			case FIELD_NTHR :	
				writer.KeyConst("nthr");
				writer.Int(hist.nthreads_);
				return true;

			case FIELD_MAXCORE :	
				writer.KeyConst("maxcore");
				writer.Int(hist.max_cores_allowed_);
				return true;

			case FIELD_CGCPULIMPCT :
				writer.KeyConst("cgcpulimpct");
				writer.Int(hist.cpu_cg_pct_limit_);
				return true;

			case FIELD_CGRSSPCT : 
				writer.KeyConst("cgrsspct");
				writer.Int(hist.max_mem_cg_pct_rss_);
				return true;

			case FIELD_REGION :
				writer.KeyConst("region");
				writer.String(prawpartha->region_name_, GY_READ_ONCE(prawpartha->region_len_));
				return true;

			case FIELD_ZONE :
				writer.KeyConst("zone");
				writer.String(prawpartha->zone_name_, GY_READ_ONCE(prawpartha->zone_len_));
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


	class ProcStateFields
	{
	public :
		const ParthaInfo		& partha_;
		const AggrTask	 		& task_;
		const char 			*madhava_id_str_;
		time_t				tcurr_;
		mutable uint32_t		last_unknown_jsoncrc_		{0};

		ProcStateFields(const ParthaInfo & partha, const AggrTask & task, const char *madhava_id_str, time_t tcurr = 0) noexcept
			: partha_(partha), task_(task), madhava_id_str_(madhava_id_str), tcurr_(tcurr)
		{};

		NUMBER_CRITERION get_num_field(const JSON_DB_MAPPING *pfield) const noexcept
		{
			const auto				& task = task_;
			const comm::AGGR_TASK_STATE_NOTIFY	& state = task.task_issue_.task_state_;

			switch (pfield->jsoncrc) {

			case FIELD_PID1			:	return NUMBER_CRITERION(int(state.pid_arr_[0]));
			case FIELD_PID2			:	return NUMBER_CRITERION(int(state.pid_arr_[1]));
			case FIELD_NETKB		:	return NUMBER_CRITERION(int(state.tcp_kbytes_));
			case FIELD_NCONN		:	return NUMBER_CRITERION(int(state.tcp_conns_));
			case FIELD_CPU			:	return NUMBER_CRITERION(double(state.total_cpu_pct_));
			case FIELD_RSS			:	return NUMBER_CRITERION(int(state.rss_mb_));
			case FIELD_CPUDEL		:	return NUMBER_CRITERION(int(state.cpu_delay_msec_));
			case FIELD_VMDEL		:	return NUMBER_CRITERION(int(state.vm_delay_msec_));
			case FIELD_IODEL		:	return NUMBER_CRITERION(int(state.blkio_delay_msec_));
			case FIELD_PROCS		:	return NUMBER_CRITERION(int(state.ntasks_total_));
			case FIELD_NISSUE		:	return NUMBER_CRITERION(int(state.ntasks_issue_));
			case FIELD_ISSUE		:	return NUMBER_CRITERION(int(state.curr_issue_));
			
			default				:	last_unknown_jsoncrc_ = pfield->jsoncrc; return {};
			}
		}	

		std::pair<const char *, uint32_t> get_str_field(const JSON_DB_MAPPING *pfield, char * tbuf, size_t szbuf) const noexcept
		{
			const auto				*prawpartha = &partha_;
			const auto				& task = task_;
			const comm::AGGR_TASK_STATE_NOTIFY	& state = task.task_issue_.task_state_;

			switch (pfield->jsoncrc) {

			case FIELD_PARID 		: 	return { prawpartha->machine_id_str_, 		32 };
			case FIELD_HOST 		: 	return { prawpartha->hostname_, 		GY_READ_ONCE(prawpartha->hostname_len_) };
			case FIELD_MADID		:	return { madhava_id_str_,			16 };
			case FIELD_CLUSTER 		: 	return { prawpartha->cluster_name_,		GY_READ_ONCE(prawpartha->cluster_len_) };

			case FIELD_PROCID		:	
				if (tbuf && szbuf > 16) {
					std::pair<const char *, uint32_t>	p;

					p.first		= tbuf;
					p.second 	= snprintf(tbuf, szbuf, "%016lx", task.aggr_task_id_);

					return p;
				}
				return {};

			case FIELD_NAME			:	return { task.comm_, GY_READ_ONCE(task.comm_len_) };
			case FIELD_STATE		:	return state_to_stringlen((OBJ_STATE_E)state.curr_state_);

			case FIELD_DESC			:	
				if (true) {
					uint32_t		len = GY_READ_ONCE(state.issue_string_len_);
					
					if (len > 1) {
						return { task.task_issue_.issue_string_, len - 1 };
					}
				}	

				return {};
			
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
			const SUBSYS_CLASS_E		subsysarr[] {SUBSYS_PROCSTATE, SUBSYS_HOST};

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
		bool print_field(uint32_t jsoncrc, Jsonwriter & writer, const char *timebuf = nullptr) const
		{
			const auto				*prawpartha = &partha_;
			const auto				& mtask = task_;
			const comm::AGGR_TASK_STATE_NOTIFY	& state = mtask.task_issue_.task_state_;

			switch (jsoncrc) {

			case FIELD_PARID :
				writer.KeyConst("parid");
				writer.String(prawpartha->machine_id_str_, 32);
				return true;
			
			case FIELD_HOST :
				writer.KeyConst("host");
				writer.String(prawpartha->hostname_, GY_READ_ONCE(prawpartha->hostname_len_));
				return true;

			case FIELD_MADID :
				writer.KeyConst("madid");
				writer.String(madhava_id_str_, 16);
				return true;

			case FIELD_CLUSTER :
				writer.KeyConst("cluster");
				writer.String(prawpartha->cluster_name_, GY_READ_ONCE(prawpartha->cluster_len_));
				return true;

			case FIELD_TIME :
				writer.KeyConst("time");

				if (timebuf) {
					writer.String(timebuf);
				}
				else {
					uint64_t			tusec = GY_READ_ONCE(mtask.task_issue_.last_usec_time_);
					
					writer.String(gy_localtime_iso8601(tusec/GY_USEC_PER_SEC, CHAR_BUF<64>().get(), 64));	
				}	
				return true;

			case FIELD_PROCID :
				writer.KeyConst("procid");
				writer.String(number_to_string(state.aggr_task_id_, "%016lx").get(), 16);
				return true;

			case FIELD_NAME :
				writer.KeyConst("name");
				writer.String(state.onecomm_);
				return true;

			case FIELD_PID1 :
				writer.KeyConst("pid1");
				writer.Int(state.pid_arr_[0]);
				return true;

			case FIELD_PID2 :
				writer.KeyConst("pid2");
				writer.Int(state.pid_arr_[1]);
				return true;

			case FIELD_NETKB :
				writer.KeyConst("netkb");
				writer.Int(state.tcp_kbytes_);
				return true;

			case FIELD_NCONN :
				writer.KeyConst("nconn");
				writer.Int(state.tcp_conns_);
				return true;
			
			case FIELD_CPU :
				writer.KeyConst("cpu");
				writer.Double(state.total_cpu_pct_);
				return true;
			
			case FIELD_RSS :
				writer.KeyConst("rss");
				writer.Int(state.rss_mb_);
				return true;
			
			case FIELD_CPUDEL :
				writer.KeyConst("cpudel");
				writer.Int(state.cpu_delay_msec_);
				return true;
			
			case FIELD_VMDEL :
				writer.KeyConst("vmdel");
				writer.Int(state.vm_delay_msec_);
				return true;
			
			case FIELD_IODEL :
				writer.KeyConst("iodel");
				writer.Int(state.blkio_delay_msec_);
				return true;
			
			case FIELD_NPROCS :
				writer.KeyConst("nprocs");
				writer.Int(state.ntasks_total_);
				return true;
			
			case FIELD_NISSUE :
				writer.KeyConst("nissue");
				writer.Int(state.ntasks_issue_);
				return true;
			
			case FIELD_STATE :
				writer.KeyConst("state");
				writer.String(state_to_stringlen((OBJ_STATE_E)state.curr_state_));
				return true;

			case FIELD_ISSUE :
				writer.KeyConst("issue");
				writer.Int(state.curr_issue_);
				return true;

			case FIELD_DESC :
				if (true) {
					uint32_t		len = GY_READ_ONCE(state.issue_string_len_);

					writer.KeyConst("desc");
					writer.String(mtask.task_issue_.issue_string_, len > 1 ? len - 1 : 0);
				}
				return true;

			default :
				return false;
			}	

			return false;
		}

		template <typename Jsonwriter>
		void print_json(const JSON_DB_MAPPING * const *colarr, size_t ncol, Jsonwriter & writer, const char *timebuf = nullptr, bool startobj = true) const
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
	
	class ExtProcStateFields
	{
	public :
		ProcStateFields			procstatefields_;
		ProcInfoFields			procinfofields_;

		ExtProcStateFields(const ParthaInfo & partha, const AggrTask & task, const char *madhava_id_str, time_t tcurr = 0) noexcept
			: procstatefields_(partha, task, madhava_id_str, tcurr), procinfofields_(partha, task, madhava_id_str, tcurr)
		{}

		NUMBER_CRITERION get_num_field(const JSON_DB_MAPPING *pfield) const noexcept
		{
			auto				numc = procstatefields_.get_num_field(pfield);

			if (!numc.is_valid() && procstatefields_.last_unknown_jsoncrc_ == pfield->jsoncrc) {
				return procinfofields_.get_num_field(pfield);
			}	

			return numc;
		}	

		std::pair<const char *, uint32_t> get_str_field(const JSON_DB_MAPPING *pfield, char * tbuf, size_t szbuf) const noexcept
		{
			auto				p = procstatefields_.get_str_field(pfield, tbuf, szbuf);

			if (!p.second && procstatefields_.last_unknown_jsoncrc_ == pfield->jsoncrc) {
				return procinfofields_.get_str_field(pfield, tbuf, szbuf);
			}	

			return p;
		}	

		BOOL_CRITERION get_bool_field(const JSON_DB_MAPPING *pfield) const noexcept
		{
			auto				b = procstatefields_.get_bool_field(pfield);

			if (!b.is_valid() && procstatefields_.last_unknown_jsoncrc_ == pfield->jsoncrc) {
				return procinfofields_.get_bool_field(pfield);
			}	

			return b;
		}	

		CRIT_RET_E filter_match(const CRITERIA_SET & criteria) const
		{
			const SUBSYS_CLASS_E		subsysarr[] {SUBSYS_EXTPROCSTATE, SUBSYS_HOST};

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

			return criteria.match_criteria(num_field, str_field, bool_field, procstatefields_.tcurr_, subsysarr, GY_ARRAY_SIZE(subsysarr));
		}	

		template <typename Jsonwriter>
		void print_json(const JSON_DB_MAPPING * const *colarr, size_t ncol, Jsonwriter & writer, const char *timebuf = nullptr, bool startobj = true) const
		{
			if (startobj) {
				writer.StartObject();
			}
			
			for (size_t i = 0; i < ncol; ++i) {
				bool			bret;
				
				bret = procstatefields_.print_field(colarr[i]->jsoncrc, writer, timebuf);

				if (!bret) {
					procinfofields_.print_field(colarr[i]->jsoncrc, writer, timebuf);
				}	
			}

			if (startobj) {
				writer.EndObject();
			}
		}
	};	

	
	// Used both for SUBSYS_ACTIVECONN and SUBSYS_CLIENTCONN
	class ActiveClientConnFields
	{
	public :
		const ParthaInfo		& partha_;
		const comm::ACTIVE_CONN_STATS	& aconn_;
		const char 			*madhava_id_str_;
		SUBSYS_CLASS_E 			csubsys_;
		time_t				tcurr_;
		mutable uint32_t		last_unknown_jsoncrc_		{0};

		ActiveClientConnFields(const ParthaInfo & partha, const comm::ACTIVE_CONN_STATS & aconn, const char *madhava_id_str, SUBSYS_CLASS_E csubsys, time_t tcurr = 0) noexcept
			: partha_(partha), aconn_(aconn), madhava_id_str_(madhava_id_str), csubsys_(csubsys), tcurr_(tcurr)
		{};

		void set_subsys(SUBSYS_CLASS_E csubsys) noexcept
		{
			csubsys_ = csubsys;
		}	

		const comm::ACTIVE_CONN_STATS & get_conn() const noexcept
		{
			return aconn_;
		}

		NUMBER_CRITERION get_num_field(const JSON_DB_MAPPING *pfield) const noexcept
		{
			switch (pfield->jsoncrc) {
			
			case FIELD_CNETOUT		:	return NUMBER_CRITERION((int64_t)aconn_.bytes_sent_);
			case FIELD_CNETIN		:	return NUMBER_CRITERION((int64_t)aconn_.bytes_received_);
			case FIELD_CDELMS		:	return NUMBER_CRITERION((int)aconn_.cli_delay_msec_);
			case FIELD_SDELMS		:	return NUMBER_CRITERION((int)aconn_.ser_delay_msec_);
			case FIELD_RTTMS		:	return NUMBER_CRITERION((double)aconn_.max_rtt_msec_);
			case FIELD_NCONNS		:	return NUMBER_CRITERION((int)aconn_.active_conns_);

			default				:	last_unknown_jsoncrc_ = pfield->jsoncrc; return {};
			}	
		}	

		std::pair<const char *, uint32_t> get_str_field(const JSON_DB_MAPPING *pfield, char * tbuf, size_t szbuf) const noexcept
		{
			const auto			*prawpartha = &partha_;

			switch (pfield->jsoncrc) {

			case FIELD_PARID 		: 	return { prawpartha->machine_id_str_, 		32 };
			case FIELD_HOST 		: 	return { prawpartha->hostname_, 		GY_READ_ONCE(prawpartha->hostname_len_) };
			case FIELD_MADID		:	return { madhava_id_str_,			16 };
			case FIELD_CLUSTER 		: 	return { prawpartha->cluster_name_,		GY_READ_ONCE(prawpartha->cluster_len_) };

			case FIELD_SVCID		:
				if (tbuf && szbuf > 16) {
					std::pair<const char *, uint32_t>	p;

					p.first		= tbuf;
					p.second 	= snprintf(tbuf, szbuf, "%016lx", aconn_.listener_glob_id_);

					return p;
				}
				return {};

			case FIELD_SVCNAME		:	return { aconn_.ser_comm_, strlen(aconn_.ser_comm_) };

			case FIELD_CPROCID		:
				if (tbuf && szbuf > 16) {
					std::pair<const char *, uint32_t>	p;

					p.first		= tbuf;
					p.second 	= snprintf(tbuf, szbuf, "%016lx", aconn_.cli_aggr_task_id_);

					return p;
				}
				return {};

			case FIELD_CNAME		:	return { aconn_.cli_comm_, strlen(aconn_.cli_comm_) };

			case FIELD_CPARID		:
			case FIELD_SPARID		:
				if (tbuf && szbuf > 32) {
					std::pair<const char *, uint32_t>	p;

					p.first		= tbuf;
					p.second 	= snprintf(tbuf, szbuf, "%016lx%016lx", aconn_.remote_machine_id_.get_first(), aconn_.remote_machine_id_.get_second());

					return p;
				}
				return {};

			case FIELD_CMADID		:
			case FIELD_SMADID		:
				if (tbuf && szbuf > 16) {
					std::pair<const char *, uint32_t>	p;

					p.first		= tbuf;
					p.second 	= snprintf(tbuf, szbuf, "%016lx", aconn_.remote_madhava_id_);

					return p;
				}
				return {};

			default				:	last_unknown_jsoncrc_ = pfield->jsoncrc; return {};
			}	
		}	

		BOOL_CRITERION get_bool_field(const JSON_DB_MAPPING *pfield) const noexcept
		{
			switch (pfield->jsoncrc) {
			
			case FIELD_CSVC			:	return BOOL_CRITERION(aconn_.cli_listener_proc_);

			default				:	last_unknown_jsoncrc_ = pfield->jsoncrc; return {};
			}	
		}	

		CRIT_RET_E filter_match(const CRITERIA_SET & criteria) const
		{
			const SUBSYS_CLASS_E		subsysarr[] {csubsys_, SUBSYS_HOST};

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
			const auto			*prawpartha = &partha_;

			switch (jsoncrc) {

			case FIELD_PARID :
				writer.KeyConst("parid");
				writer.String(prawpartha->machine_id_str_, 32);
				return true;
			
			case FIELD_HOST :
				writer.KeyConst("host");
				writer.String(prawpartha->hostname_, GY_READ_ONCE(prawpartha->hostname_len_));
				return true;

			case FIELD_MADID :
				writer.KeyConst("madid");
				writer.String(madhava_id_str_, 16);
				return true;

			case FIELD_CLUSTER :
				writer.KeyConst("cluster");
				writer.String(prawpartha->cluster_name_, GY_READ_ONCE(prawpartha->cluster_len_));
				return true;

			case FIELD_TIME :
				writer.KeyConst("time");
				writer.String(timebuf);
				return true;

			case FIELD_SVCID :
				writer.KeyConst("svcid");
				writer.String(number_to_string(aconn_.listener_glob_id_, "%016lx").get(), 16);
				return true;

			case FIELD_SVCNAME :
				writer.KeyConst("svcname");
				writer.String(aconn_.ser_comm_);
				return true;

			case FIELD_CPROCID :
				writer.KeyConst("cprocid");
				writer.String(number_to_string(aconn_.cli_aggr_task_id_, "%016lx").get(), 16);
				return true;

			case FIELD_CNAME :
				writer.KeyConst("cname");
				writer.String(aconn_.cli_comm_);
				return true;

			case FIELD_CNETOUT :
				writer.KeyConst("cnetout");
				writer.Int64(aconn_.bytes_sent_);
				return true;

			case FIELD_CNETIN :
				writer.KeyConst("cnetin");
				writer.Int64(aconn_.bytes_received_);
				return true;

			case FIELD_NCONNS :
				writer.KeyConst("nconns");
				writer.Int(aconn_.active_conns_);
				return true;

			case FIELD_CSVC :
				writer.KeyConst("csvc");
				writer.Bool(bool(aconn_.cli_listener_proc_));
				return true;

			case FIELD_CPARID :
				writer.KeyConst("cparid");
				writer.String(aconn_.remote_machine_id_.get_string().get(), 32);
				return true;

			case FIELD_CMADID :
				writer.KeyConst("cmadid");
				writer.String(number_to_string(aconn_.remote_madhava_id_, "%016lx").get(), 16);
				return true;

			case FIELD_CDELMS :
				writer.KeyConst("cdelms");
				writer.Int(aconn_.cli_delay_msec_);
				return true;

			case FIELD_SDELMS :
				writer.KeyConst("sdelms");
				writer.Int(aconn_.ser_delay_msec_);
				return true;

			case FIELD_RTTMS :
				writer.KeyConst("rttms");
				writer.Double(aconn_.max_rtt_msec_);
				return true;

			case FIELD_SPARID :
				writer.KeyConst("sparid");
				writer.String(aconn_.remote_machine_id_.get_string().get(), 32);
				return true;
		
			case FIELD_SMADID :
				writer.KeyConst("smadid");
				writer.String(number_to_string(aconn_.remote_madhava_id_, "%016lx").get(), 16);
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

	class ExtActiveConnFields
	{
	public :
		ActiveClientConnFields		actconnfields_;
		SvcInfoFields			svcinfofields_;

		ExtActiveConnFields(const ParthaInfo & partha, const comm::ACTIVE_CONN_STATS & aconn, const TCP_Listener & listener, const char *madhava_id_str, time_t tcurr = 0) noexcept
			: actconnfields_(partha, aconn, madhava_id_str, SUBSYS_ACTIVECONN, tcurr), svcinfofields_(partha, listener, madhava_id_str, tcurr)
		{}

		NUMBER_CRITERION get_num_field(const JSON_DB_MAPPING *pfield) const noexcept
		{
			auto				numc = actconnfields_.get_num_field(pfield);

			if (!numc.is_valid() && actconnfields_.last_unknown_jsoncrc_ == pfield->jsoncrc) {
				return svcinfofields_.get_num_field(pfield);
			}	

			return numc;
		}	

		std::pair<const char *, uint32_t> get_str_field(const JSON_DB_MAPPING *pfield, char * tbuf, size_t szbuf) const noexcept
		{
			auto				p = actconnfields_.get_str_field(pfield, tbuf, szbuf);

			if (!p.second && actconnfields_.last_unknown_jsoncrc_ == pfield->jsoncrc) {
				return svcinfofields_.get_str_field(pfield, tbuf, szbuf);
			}	

			return p;
		}	

		BOOL_CRITERION get_bool_field(const JSON_DB_MAPPING *pfield) const noexcept
		{
			auto				b = actconnfields_.get_bool_field(pfield);

			if (!b.is_valid() && actconnfields_.last_unknown_jsoncrc_ == pfield->jsoncrc) {
				return svcinfofields_.get_bool_field(pfield);
			}	

			return b;
		}	

		CRIT_RET_E filter_match(const CRITERIA_SET & criteria) const
		{
			const SUBSYS_CLASS_E		subsysarr[] {SUBSYS_EXTACTIVECONN, SUBSYS_HOST};

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

			return criteria.match_criteria(num_field, str_field, bool_field, actconnfields_.tcurr_, subsysarr, GY_ARRAY_SIZE(subsysarr));
		}	

		template <typename Jsonwriter>
		void print_json(const JSON_DB_MAPPING * const *colarr, size_t ncol, Jsonwriter & writer, const char *timebuf = nullptr, bool startobj = true) const
		{
			if (startobj) {
				writer.StartObject();
			}
			
			for (size_t i = 0; i < ncol; ++i) {
				bool			bret;
				
				bret = actconnfields_.print_field(colarr[i]->jsoncrc, writer, timebuf);

				if (!bret) {
					svcinfofields_.print_field(colarr[i]->jsoncrc, writer, timebuf);
				}	
			}

			if (startobj) {
				writer.EndObject();
			}
		}
	};	

	class ExtClientConnFields
	{
	public :
		ActiveClientConnFields		cliconnfields_;
		ProcInfoFields			procinfofields_;

		ExtClientConnFields(const ParthaInfo & partha, const comm::ACTIVE_CONN_STATS & aconn, const AggrTask & task, const char *madhava_id_str, time_t tcurr = 0) noexcept
			: cliconnfields_(partha, aconn, madhava_id_str, SUBSYS_CLIENTCONN, tcurr), procinfofields_(partha, task, madhava_id_str, tcurr)
		{}

		NUMBER_CRITERION get_num_field(const JSON_DB_MAPPING *pfield) const noexcept
		{
			auto				numc = cliconnfields_.get_num_field(pfield);

			if (!numc.is_valid() && cliconnfields_.last_unknown_jsoncrc_ == pfield->jsoncrc) {
				return procinfofields_.get_num_field(pfield);
			}	

			return numc;
		}	

		std::pair<const char *, uint32_t> get_str_field(const JSON_DB_MAPPING *pfield, char * tbuf, size_t szbuf) const noexcept
		{
			auto				p = cliconnfields_.get_str_field(pfield, tbuf, szbuf);

			if (!p.second && cliconnfields_.last_unknown_jsoncrc_ == pfield->jsoncrc) {
				return procinfofields_.get_str_field(pfield, tbuf, szbuf);
			}	

			return p;
		}	

		BOOL_CRITERION get_bool_field(const JSON_DB_MAPPING *pfield) const noexcept
		{
			auto				b = cliconnfields_.get_bool_field(pfield);

			if (!b.is_valid() && cliconnfields_.last_unknown_jsoncrc_ == pfield->jsoncrc) {
				return procinfofields_.get_bool_field(pfield);
			}	

			return b;
		}	

		CRIT_RET_E filter_match(const CRITERIA_SET & criteria) const
		{
			const SUBSYS_CLASS_E		subsysarr[] {SUBSYS_EXTCLIENTCONN, SUBSYS_HOST};

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

			return criteria.match_criteria(num_field, str_field, bool_field, cliconnfields_.tcurr_, subsysarr, GY_ARRAY_SIZE(subsysarr));
		}	

		template <typename Jsonwriter>
		void print_json(const JSON_DB_MAPPING * const *colarr, size_t ncol, Jsonwriter & writer, const char *timebuf = nullptr, bool startobj = true) const
		{
			if (startobj) {
				writer.StartObject();
			}
			
			for (size_t i = 0; i < ncol; ++i) {
				bool			bret;
				
				bret = cliconnfields_.print_field(colarr[i]->jsoncrc, writer, timebuf);

				if (!bret) {
					procinfofields_.print_field(colarr[i]->jsoncrc, writer, timebuf);
				}	
			}

			if (startobj) {
				writer.EndObject();
			}
		}
	};	



	// Valid for both SUBSYS_TOPCPU and SUBSYS_TOPRSS
	class TopCpuRssFields
	{
	public :
		const ParthaInfo			& partha_;
		const comm::TASK_TOP_PROCS::TOP_TASK 	& task_;
		const char 				*madhava_id_str_;
		int					rank_;
		const SUBSYS_CLASS_E 			csubsys_;
		time_t					tcurr_;
		mutable uint32_t			last_unknown_jsoncrc_		{0};

		TopCpuRssFields(const ParthaInfo & partha, const comm::TASK_TOP_PROCS::TOP_TASK & task, const char *madhava_id_str, int rank, SUBSYS_CLASS_E csubsys, time_t tcurr = 0) noexcept
			: partha_(partha), task_(task), madhava_id_str_(madhava_id_str), rank_(rank), csubsys_(csubsys), tcurr_(tcurr)
		{};

		NUMBER_CRITERION get_num_field(const JSON_DB_MAPPING *pfield) const noexcept
		{
			const auto			& task = task_;

			switch (pfield->jsoncrc) {

			case FIELD_PID	 		: 	return NUMBER_CRITERION((int)task.pid_);
			case FIELD_PPID	 		: 	return NUMBER_CRITERION((int)task.ppid_);
			case FIELD_RSS	 		: 	return NUMBER_CRITERION((int)task.rss_mb_);
			case FIELD_CPU	 		: 	return NUMBER_CRITERION((double)task.cpupct_);
			case FIELD_RANK	 		: 	return rank_;
			
			default				:	last_unknown_jsoncrc_ = pfield->jsoncrc; return {};
			}	
		}	

		std::pair<const char *, uint32_t> get_str_field(const JSON_DB_MAPPING *pfield, char * tbuf, size_t szbuf) const noexcept
		{
			const auto			*prawpartha = &partha_;
			const auto			& task = task_;

			switch (pfield->jsoncrc) {

			case FIELD_PARID 		: 	return { prawpartha->machine_id_str_, 		32 };
			case FIELD_HOST 		: 	return { prawpartha->hostname_, 		GY_READ_ONCE(prawpartha->hostname_len_) };
			case FIELD_MADID		:	return { madhava_id_str_,			16 };
			case FIELD_CLUSTER 		: 	return { prawpartha->cluster_name_,		GY_READ_ONCE(prawpartha->cluster_len_) };
			
			case FIELD_PROCID		:	
				if (tbuf && szbuf > 16) {
					std::pair<const char *, uint32_t>	p;

					p.first		= tbuf;
					p.second 	= snprintf(tbuf, szbuf, "%016lx", task.aggr_task_id_);

					return p;
				}
				return {};

			case FIELD_NAME			:	return { task.comm_, strlen(task.comm_) };

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
			const SUBSYS_CLASS_E		subsysarr[] {csubsys_, SUBSYS_HOST};

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
			const auto			*prawpartha = &partha_;
			const auto			*ptoptask = &task_;

			switch (jsoncrc) {

			case FIELD_PARID :	
				writer.KeyConst("parid");
				writer.String(prawpartha->machine_id_str_, sizeof(prawpartha->machine_id_str_) - 1);
				return true;
				
			case FIELD_HOST :	
				writer.KeyConst("host");
				writer.String(prawpartha->hostname_, GY_READ_ONCE(prawpartha->hostname_len_));
				return true;

			case FIELD_MADID :
				writer.KeyConst("madid");
				writer.String(madhava_id_str_, 16);
				return true;

			case FIELD_CLUSTER :	
				writer.KeyConst("cluster");
				writer.String(prawpartha->cluster_name_, GY_READ_ONCE(prawpartha->cluster_len_));
				return true;

			case FIELD_TIME :
				writer.KeyConst("time");
				writer.String(timebuf ? timebuf : "");
				return true;

			case FIELD_PROCID :
				writer.KeyConst("procid");
				writer.String(number_to_string(ptoptask->aggr_task_id_, "%016lx").get(), 16);
				return true;

			case FIELD_PID :	
				writer.KeyConst("pid");
				writer.Int(ptoptask->pid_);
				return true;

			case FIELD_PPID :	
				writer.KeyConst("ppid");
				writer.Int(ptoptask->ppid_);
				return true;

			case FIELD_RSS :	
				writer.KeyConst("rss");
				writer.Uint(ptoptask->rss_mb_);
				return true;

			case FIELD_CPU :	
				writer.KeyConst("cpu");
				writer.Double(ptoptask->cpupct_);
				return true;

			case FIELD_NAME :	
				writer.KeyConst("name");
				writer.String(ptoptask->comm_);
				return true;

			case FIELD_RANK :	
				writer.KeyConst("rank");
				writer.Int(rank_);
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

	class TopPgCpuFields
	{
	public :
		const ParthaInfo			& partha_;
		const comm::TASK_TOP_PROCS::TOP_PG_TASK & task_;
		const char 				*madhava_id_str_;
		int					rank_;
		time_t					tcurr_;
		mutable uint32_t			last_unknown_jsoncrc_		{0};

		TopPgCpuFields(const ParthaInfo & partha, const comm::TASK_TOP_PROCS::TOP_PG_TASK & task, const char *madhava_id_str, int rank, time_t tcurr = 0) noexcept
			: partha_(partha), task_(task), madhava_id_str_(madhava_id_str), rank_(rank), tcurr_(tcurr)
		{};

		NUMBER_CRITERION get_num_field(const JSON_DB_MAPPING *pfield) const noexcept
		{
			const auto			& task = task_;

			switch (pfield->jsoncrc) {

			case FIELD_PGPID 		: 	return NUMBER_CRITERION((int)task.pg_pid_);
			case FIELD_CPID	 		: 	return NUMBER_CRITERION((int)task.cpid_);
			case FIELD_NPROCS	 	: 	return NUMBER_CRITERION((int)task.ntasks_);
			case FIELD_TRSS	 		: 	return NUMBER_CRITERION((int)task.tot_rss_mb_);
			case FIELD_TCPU	 		: 	return NUMBER_CRITERION((double)task.tot_cpupct_);
			case FIELD_RANK	 		: 	return rank_;
			
			default				:	last_unknown_jsoncrc_ = pfield->jsoncrc; return {};
			}	
		}	

		std::pair<const char *, uint32_t> get_str_field(const JSON_DB_MAPPING *pfield, char * tbuf, size_t szbuf) const noexcept
		{
			const auto			*prawpartha = &partha_;
			const auto			& task = task_;

			switch (pfield->jsoncrc) {

			case FIELD_PARID 		: 	return { prawpartha->machine_id_str_, 		32 };
			case FIELD_HOST 		: 	return { prawpartha->hostname_, 		GY_READ_ONCE(prawpartha->hostname_len_) };
			case FIELD_MADID		:	return { madhava_id_str_,			16 };
			case FIELD_CLUSTER 		: 	return { prawpartha->cluster_name_,		GY_READ_ONCE(prawpartha->cluster_len_) };
			
			case FIELD_PROCID		:	
				if (tbuf && szbuf > 16) {
					std::pair<const char *, uint32_t>	p;

					p.first		= tbuf;
					p.second 	= snprintf(tbuf, szbuf, "%016lx", task.aggr_task_id_);

					return p;
				}
				return {};

			case FIELD_PGNAME			:	return { task.pg_comm_, strlen(task.pg_comm_) };
			case FIELD_CNAME			:	return { task.child_comm_, strlen(task.child_comm_) };

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
			const SUBSYS_CLASS_E		subsysarr[] {SUBSYS_TOPPGCPU, SUBSYS_HOST};

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
			const auto			*prawpartha = &partha_;
			const auto			*ptoppgtask = &task_;

			switch (jsoncrc) {

			case FIELD_PARID :
				writer.KeyConst("parid");
				writer.String(prawpartha->machine_id_str_, sizeof(prawpartha->machine_id_str_) - 1);
				return true;
				
			case FIELD_HOST :
				writer.KeyConst("host");
				writer.String(prawpartha->hostname_, GY_READ_ONCE(prawpartha->hostname_len_));
				return true;

			case FIELD_MADID :
				writer.KeyConst("madid");
				writer.String(madhava_id_str_, 16);
				return true;

			case FIELD_CLUSTER :
				writer.KeyConst("cluster");
				writer.String(prawpartha->cluster_name_, GY_READ_ONCE(prawpartha->cluster_len_));
				return true;

			case FIELD_TIME :
				writer.KeyConst("time");
				writer.String(timebuf ? timebuf : "");
				return true;

			case FIELD_PROCID :
				writer.KeyConst("procid");
				writer.String(number_to_string(ptoppgtask->aggr_task_id_, "%016lx").get(), 16);
				return true;

			case FIELD_PGPID :
				writer.KeyConst("pgpid");
				writer.Int(ptoppgtask->pg_pid_);
				return true;
			
			case FIELD_CPID :
				writer.KeyConst("cpid");
				writer.Int(ptoppgtask->cpid_);
				return true;

			case FIELD_NPROCS :
				writer.KeyConst("nprocs");
				writer.Int(ptoppgtask->ntasks_);
				return true;

			case FIELD_TRSS :
				writer.KeyConst("trss");
				writer.Uint(ptoppgtask->tot_rss_mb_);
				return true;

			case FIELD_TCPU :
				writer.KeyConst("tcpu");
				writer.Double(ptoppgtask->tot_cpupct_);
				return true;

			case FIELD_PGNAME :
				writer.KeyConst("pgname");
				writer.String(ptoppgtask->pg_comm_);
				return true;

			case FIELD_CNAME :
				writer.KeyConst("cname");
				writer.String(ptoppgtask->child_comm_);
				return true;

			case FIELD_RANK :
				writer.KeyConst("rank");
				writer.Int(rank_);
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


	class TopForkFields
	{
	public :
		const ParthaInfo				& partha_;
		const comm::TASK_TOP_PROCS::TOP_FORK_TASK 	& task_;
		const char 					*madhava_id_str_;
		int						rank_;
		time_t						tcurr_;
		mutable uint32_t				last_unknown_jsoncrc_		{0};

		TopForkFields(const ParthaInfo & partha, const comm::TASK_TOP_PROCS::TOP_FORK_TASK & task, const char *madhava_id_str, int rank, time_t tcurr = 0) noexcept
			: partha_(partha), task_(task), madhava_id_str_(madhava_id_str), rank_(rank), tcurr_(tcurr)
		{};

		NUMBER_CRITERION get_num_field(const JSON_DB_MAPPING *pfield) const noexcept
		{
			const auto			& task = task_;

			switch (pfield->jsoncrc) {

			case FIELD_PID	 		: 	return NUMBER_CRITERION((int)task.pid_);
			case FIELD_PPID	 		: 	return NUMBER_CRITERION((int)task.ppid_);
			case FIELD_FORKSEC	 	: 	return NUMBER_CRITERION((int)task.nfork_per_sec_);
			case FIELD_RANK	 		: 	return rank_;
			
			default				:	last_unknown_jsoncrc_ = pfield->jsoncrc; return {};
			}	
		}	

		std::pair<const char *, uint32_t> get_str_field(const JSON_DB_MAPPING *pfield, char * tbuf, size_t szbuf) const noexcept
		{
			const auto			*prawpartha = &partha_;
			const auto			& task = task_;

			switch (pfield->jsoncrc) {

			case FIELD_PARID 		: 	return { prawpartha->machine_id_str_, 		32 };
			case FIELD_HOST 		: 	return { prawpartha->hostname_, 		GY_READ_ONCE(prawpartha->hostname_len_) };
			case FIELD_MADID		:	return { madhava_id_str_,			16 };
			case FIELD_CLUSTER 		: 	return { prawpartha->cluster_name_,		GY_READ_ONCE(prawpartha->cluster_len_) };
			
			case FIELD_PROCID		:	
				if (tbuf && szbuf > 16) {
					std::pair<const char *, uint32_t>	p;

					p.first		= tbuf;
					p.second 	= snprintf(tbuf, szbuf, "%016lx", task.aggr_task_id_);

					return p;
				}
				return {};

			case FIELD_NAME			:	return { task.comm_, strlen(task.comm_) };

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
			const SUBSYS_CLASS_E		subsysarr[] {SUBSYS_TOPFORK, SUBSYS_HOST};

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
			const auto			*prawpartha = &partha_;
			const auto			*ptoptask = &task_;

			switch (jsoncrc) {

			case FIELD_PARID :	
				writer.KeyConst("parid");
				writer.String(prawpartha->machine_id_str_, sizeof(prawpartha->machine_id_str_) - 1);
				return true;
				
			case FIELD_HOST :	
				writer.KeyConst("host");
				writer.String(prawpartha->hostname_, GY_READ_ONCE(prawpartha->hostname_len_));
				return true;

			case FIELD_MADID :	
				writer.KeyConst("madid");
				writer.String(madhava_id_str_, 16);
				return true;

			case FIELD_CLUSTER :	
				writer.KeyConst("cluster");
				writer.String(prawpartha->cluster_name_, GY_READ_ONCE(prawpartha->cluster_len_));
				return true;

			case FIELD_TIME :	
				writer.KeyConst("time");
				writer.String(timebuf ? timebuf : "");
				return true;

			case FIELD_PROCID :	
				writer.KeyConst("procid");
				writer.String(number_to_string(ptoptask->aggr_task_id_, "%016lx").get(), 16);
				return true;

			case FIELD_PID :	
				writer.KeyConst("pid");
				writer.Int(ptoptask->pid_);
				return true;

			case FIELD_PPID :	
				writer.KeyConst("ppid");
				writer.Int(ptoptask->ppid_);
				return true;

			case FIELD_FORKSEC :	
				writer.KeyConst("forksec");
				writer.Int(ptoptask->nfork_per_sec_);
				return true;

			case FIELD_NAME :	
				writer.KeyConst("name");
				writer.String(ptoptask->comm_);
				return true;

			case FIELD_RANK :	
				writer.KeyConst("rank");
				writer.Int(rank_);
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

};

} // namespace madhava
} // namespace gyeeta

