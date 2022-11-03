//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include		"gy_acct_taskstat.h"

namespace gyeeta {

static TASKSTATS_HDLR	*pgtaskstat_hdlr_ = nullptr;

TASKSTATS_HDLR * TASKSTATS_HDLR::get_singleton() noexcept
{
	return pgtaskstat_hdlr_;
}	
	
int TASKSTATS_HDLR::init_singleton()
{
	int				texp = 0, tdes = 1;
	static std::atomic<int>		is_init_done(0);

	if (false == is_init_done.compare_exchange_strong(texp, tdes)) {
		return 0;
	}
	
	try {
		pgtaskstat_hdlr_ = new TASKSTATS_HDLR();

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT("Exception caught while creating global Taskstat handler object : %s\n", GY_GET_EXCEPT_STRING);
		throw;
	);
}
		
} // namespace gyeeta			

