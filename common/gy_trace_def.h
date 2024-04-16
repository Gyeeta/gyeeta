//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"
#include			"gy_query_criteria.h"
#include			"gy_json_field_maps.h"

namespace gyeeta {

static constexpr uint32_t			MAX_REQ_TRACE_DEFS	{1000};	

class REQ_TRACE_DEF
{
public :
	static constexpr size_t			MAX_NAMELEN		{64};

	time_t					tstart_			{0};
	time_t					tend_			{0};
	uint64_t				cstartus_		{get_usec_clock()};
	char					name_[MAX_NAMELEN];
	uint32_t				reqdefid_		{0};
	std::vector<uint64_t>			cap_glob_id_vec_;
	std::optional<CRITERIA_SET>		filcrit_;
	std::string				filterstr_;

	REQ_TRACE_DEF(uint32_t reqdefid, const char *name, std::string_view filterstr, time_t tend, time_t tstart = time(nullptr))
		: tend_(tend), reqdefid_(reqdefid), 
		filcrit_(std::in_place, filterstr.data(), filterstr.size(), SUBSYS_SVCINFO), filterstr_(filterstr)
	{
		if (tend_ == 0) {
			tend_ = tstart + 20 * GY_SEC_PER_YEAR;
		}

		GY_STRNCPY(name_, name, sizeof(name_));
	}	

	REQ_TRACE_DEF(uint32_t reqdefid, uint64_t *cap_glob_id_arr, uint16_t ncap_glob_id_arr, const char *name, time_t tend, time_t tstart = time(nullptr))
		: tend_(tend), reqdefid_(reqdefid)
	{
		if (tend_ == 0) {
			tend_ = tstart + 20 * GY_SEC_PER_YEAR;
		}

		cap_glob_id_vec_.reserve(ncap_glob_id_arr);

		for (uint16_t i = 0; i < ncap_glob_id_arr; ++i) {
			cap_glob_id_vec_.emplace_back(cap_glob_id_arr[i]);
		}	

		GY_STRNCPY(name_, name, sizeof(name_));
	}	

	REQ_TRACE_DEF(uint32_t reqdefid, const char *name, std::string_view filterstr, CRITERIA_SET && crit, time_t tend, time_t tstart = time(nullptr))
		: tend_(tend), reqdefid_(reqdefid), 
		filcrit_(std::in_place, std::move(crit)), filterstr_(filterstr)
	{
		if (tend_ == 0) {
			tend_ = tstart + 20 * GY_SEC_PER_YEAR;
		}

		GY_STRNCPY(name_, name, sizeof(name_));
	}	

	REQ_TRACE_DEF(REQ_TRACE_DEF && other) noexcept			= default;

	REQ_TRACE_DEF & operator= (REQ_TRACE_DEF && other) noexcept	= default;

	bool is_fixed_svcs() const noexcept
	{
		return cap_glob_id_vec_.size() > 0;
	}	

	const CRITERIA_SET * get_filter() const noexcept
	{
		if (filcrit_) {
			return std::addressof(*filcrit_);
		}	

		return nullptr;
	}	

	uint32_t get_ext_sz() const noexcept
	{
		if (is_fixed_svcs()) {
			return cap_glob_id_vec_.size() * sizeof(uint64_t);
		}	

		return filterstr_.size();
	}

	void reset_criteria() noexcept
	{
		filcrit_.reset();
	}	

	static uint32_t get_def_id(const char *name, size_t namelen) noexcept
	{
		return gy_cityhash32(name, namelen);
	}	

};	


} // namespace gyeeta
