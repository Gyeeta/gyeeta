//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include 			"gy_rcu_inc.h"
#include			"gy_async_func.h"			


namespace gyeeta {

thread_local 	RCU_THREAD_LOCAL	grcu_thrdata_local_;

int rcu_send_async_destroy(struct cds_lfht *pht) noexcept
{
	int			ret = -1;
	auto 			pasync = ASYNC_FUNC_HDLR::get_singleton();

	assert(pht);

	if (pasync) {
		COMM_MSG_C		elem;

		elem.func_ = [](uint64_t arg1, uint64_t arg2, uint64_t arg3, const uint8_t *poptbuf, size_t opt_bufsize) noexcept -> int
		{
			struct cds_lfht 	*phtable = reinterpret_cast<cds_lfht *>(arg1);	
			int			ret = 0;

			if (phtable) {
				ret = cds_lfht_destroy(phtable, nullptr);
			}	

			return ret;
		};

		elem.arg1_	= reinterpret_cast<uintptr_t>(pht);

		ret = pasync->send_async_func(elem, nullptr, true /* exec_if_async_failed */);
	}	
	
	return ret;
}
	
/*
 * Use with caution as this function will offline the thread even though multiple 
 * call frames may be in a RCU Read Lock. Inly if a RCU walk is active will the thread 
 * remain in RCU Lock state. 
 */
void __attribute__((noinline)) gy_rcu_offline() noexcept
{
	GY_CC_BARRIER();
	gy_thread_rcu().gy_rcu_thread_offline();
}	
		
} // namespace gyeeta	
