//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_scheduler.h"

namespace gyeeta {


static GY_SCHEDULER 		*pgsched_long_ = nullptr, *pgsched_long2_ = nullptr, *pgsched_high_prio_ = nullptr, 
				*pgsched_no_catchup_ = nullptr, *pgsched_maintenance_ = nullptr;

GY_SCHEDULER *  GY_SCHEDULER::get_singleton(SCHEDULER_TYPE_E type) noexcept
{
	switch (type) {
	
	case SCHEDULER_LONG_DURATION 	: return pgsched_long_;
	
	case SCHEDULER_LONG2_DURATION 	: return pgsched_long2_;
		
	case SCHEDULER_HIGH_PRIO 	: return pgsched_high_prio_;		

	case SCHEDULER_NO_CATCHUP 	: return pgsched_no_catchup_;	

	case SCHEDULER_MAINTENANCE 	: return pgsched_maintenance_;	
	
	default				: return pgsched_no_catchup_;	
	}	
}	

int GY_SCHEDULER::init_singleton_maintenance(bool use_rcu)
{
	int				texp = 0, tdes = 1;
	static std::atomic<int>		is_init_sched(0);

	if (false == is_init_sched.compare_exchange_strong(texp, tdes)) {
		return 0;
	}

	try {
		pgsched_maintenance_	= new GY_SCHEDULER(false /* allow_catchup is false */);

		if (use_rcu) {
			start_rcu_schedules();
		}

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT("Exception caught while creating global scheduler objects ... : %s\n", GY_GET_EXCEPT_STRING);
		throw;
	);
}
	
int GY_SCHEDULER::init_singletons(bool use_rcu)
{
	int				texp = 0, tdes = 1;
	static std::atomic<int>		is_init_sched(0);

	if (false == is_init_sched.compare_exchange_strong(texp, tdes)) {
		return 0;
	}

	try {
		pgsched_long_ 		= new GY_SCHEDULER(true);
		pgsched_long2_		= new GY_SCHEDULER(true);
		pgsched_high_prio_	= new GY_SCHEDULER(true);
		pgsched_no_catchup_	= new GY_SCHEDULER(false /* allow_catchup is false */);
		
		init_singleton_maintenance();
	
		if (use_rcu) {
			start_rcu_schedules();
		}

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT("Exception caught while creating global scheduler objects ... : %s\n", GY_GET_EXCEPT_STRING);
		throw;
	);
}	

void GY_SCHEDULER::start_rcu_schedules()
{
	auto lam = [](GY_SCHEDULER *psch) 
	{
		if (psch) {
			psch->add_schedule(1000, 1000, 0, "rcu offline scheduler thread", 
				[] {
					gy_rcu_offline();
				}, false);	
		}	
	};

	lam(pgsched_long_);
	lam(pgsched_long2_);
	lam(pgsched_high_prio_);
	lam(pgsched_no_catchup_);
	lam(pgsched_maintenance_);
}

void GY_SCHEDULER::cancel_rcu_schedules()
{
	auto canlam = [](GY_SCHEDULER *psch) 
	{
		if (psch) {
			psch->cancel_schedule("rcu offline scheduler thread");
		}	
	};

	canlam(pgsched_long_);
	canlam(pgsched_long2_);
	canlam(pgsched_high_prio_);
	canlam(pgsched_no_catchup_);
	canlam(pgsched_maintenance_);
}
			
}	

