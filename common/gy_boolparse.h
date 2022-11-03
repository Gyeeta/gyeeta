//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"

namespace gyeeta {

/*
 * Disjunctive Normalization of a Logical (Boolean) expression
 * Check test_boolparse.cc for an example on how to use 
 */
class GY_BOOLPARSE
{
public :
	GY_BOOLPARSE(const char *pexpr, size_t szexpr);
	
	/*
	 * Returns number of critarr updated
	 */
	uint32_t get_group_criteria(size_t grpnum, std::string_view critarr[], size_t maxelem) const;						
	
	void get_stats(uint32_t & ntotalgroups, uint32_t & nl2groups, uint32_t & nl1_crit, bool & is_l1_and, uint32_t & max1crit, uint32_t & total_crit) const noexcept
	{
		ntotalgroups		= ncritgroups_;
		nl2groups		= nl2groups_;
		nl1_crit		= nl1_crit_;
		is_l1_and		= is_l1_and_;
		max1crit		= max1crit_;
		total_crit		= total_crit_;
	}	

	uint32_t get_total_criteria() const noexcept
	{
		return total_crit_;
	}	

private :
	using				CritIdVec = std::vector<std::vector<uint32_t>>;

	std::vector<std::string_view>	mapvec_;
	std::string_view		firstcrit_;
	CritIdVec			idvec_;
	uint32_t			ncritgroups_		{0};
	uint32_t			nl2groups_		{0};
	uint32_t 			nl1_crit_		{0};
	uint32_t 			max1crit_		{0};
	uint32_t 			total_crit_		{0};
	bool				is_l1_and_		{false};

	void 				replace_expr_criteria(STR_WR_BUF & strbuf, const char *pstart, size_t sz);
};	

} // namespace gyeeta

