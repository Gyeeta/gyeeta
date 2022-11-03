//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_common_inc.h"
#include			"gy_malloc_hook.h"

#pragma 			GCC diagnostic push
#pragma 			GCC diagnostic ignored "-Wparentheses"

#include 			"boost/accumulators/accumulators.hpp"
#include 			"boost/accumulators/statistics/stats.hpp"
#include 			"boost/accumulators/statistics/rolling_sum.hpp"
#pragma 			GCC diagnostic pop

using namespace gyeeta;
using namespace boost::accumulators;

int main()
{
	GY_MALLOC_HOOK::gy_malloc_init("Starting rolling_sum tests", true /* print_individual */);

	GY_MALLOC_HOOK::gy_print_memuse("Before construct : 0 mallocs expected...", true);

	accumulator_set<int, stats<tag::rolling_sum>> 	acc	{tag::rolling_window::window_size = 12};

	GY_MALLOC_HOOK::gy_print_memuse("After construct : 0 mallocs expected...", false);

	acc(2);

	GY_MALLOC_HOOK::gy_print_memuse("After 1st add : 0 mallocs expected...", false);
	
	acc(10);
	acc(1);
	
	GY_MALLOC_HOOK::gy_print_memuse("Before rolling_sum()...", false);

	INFOPRINT("Boost Rolling sum(5) = %d\n", rolling_sum(acc));

	GY_MALLOC_HOOK::gy_print_memuse("After rolling_sum()...", false);

	acc(0);
	acc(1);
	acc(3);

	INFOPRINT("Boost Rolling sum(5) = %d\n", rolling_sum(acc));

	acc(0);
	INFOPRINT("Boost Rolling sum(5) = %d\n", rolling_sum(acc));

	for (int i = 0; i < 1440; ++i) {
		acc(i);
	}	

	INFOPRINT("Boost Rolling sum(5) = %d\n", rolling_sum(acc));

	GY_MALLOC_HOOK::gy_print_memuse("At end...", false);
}
