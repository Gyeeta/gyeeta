//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

/*
 * Wrapper for folly::FunctionScheduler()
 */

#pragma 			once

#include			"gy_common_inc.h"
#include 			"gy_rcu_inc.h"
#include 			"gy_print_offload.h"

#include 			"folly/experimental/FunctionScheduler.h"
#include 			"folly/Function.h"

namespace folly {
class FunctionScheduler;
}

namespace gyeeta {

class GY_SCHEDULER : public folly::FunctionScheduler 
{
public :
	GY_SCHEDULER(bool allow_catchup = false)
	{
		folly::FunctionScheduler::setSteady(allow_catchup);

		folly::FunctionScheduler::start();

		// Init the Thread Local objects
		add_oneshot_schedule(0, "Init Function Scheduler thread name", 
			[] { 
				DEBUGEXECN(1, INFOPRINT("Starting new Function Scheduler... : thrid = %d\n", gy_gettid()););

				gy_get_thread_local().set_name("Function Scheduler", false); 
			});
	}	
		
	~GY_SCHEDULER()						= 	default;

	GY_SCHEDULER(const GY_SCHEDULER &)			=	delete;
	GY_SCHEDULER(GY_SCHEDULER &&)				=	delete;
	GY_SCHEDULER & operator= (const GY_SCHEDULER &)		=	delete;
	GY_SCHEDULER & operator= (GY_SCHEDULER &&)		=	delete;

	bool add_schedule(uint64_t start_after_msec, uint64_t repeat_interval_msec, uint64_t nmaxiter /* 0 for unlimited */, const char *name, folly::Function<void()> && fcb, bool print_on_error = true) noexcept
	{
		DEBUGEXECN(1, 
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Adding a new Function Schedule \'%s\' : Repeat Interval %lu msec : Max Iterations %lu...\n", 
				name, repeat_interval_msec, nmaxiter);
		);

		try {
			if (nmaxiter > 0) {
				if (nmaxiter == 1) {
					return add_oneshot_schedule(start_after_msec, name, std::move(fcb), print_on_error);
				}

				folly::FunctionScheduler::addFunction(
					[niter = 0ul, nmaxiter = nmaxiter, namestr = std::string(name), fcb = std::move(fcb), this]() mutable
					{
						niter++;

						fcb();

						if (niter >= nmaxiter) {
							cancel_schedule(namestr.c_str());		
						}	
					},	
					std::chrono::milliseconds(repeat_interval_msec), name, std::chrono::milliseconds(start_after_msec));
			}
			else {
				folly::FunctionScheduler::addFunction(std::move(fcb), std::chrono::milliseconds(repeat_interval_msec), name, std::chrono::milliseconds(start_after_msec));
			}
			
			return true;
		}
		GY_CATCH_EXCEPTION(
			if (print_on_error) {
				ERRORPRINT_OFFLOAD("Failed to add Function schedule \'%s\' : %s\n", name, GY_GET_EXCEPT_STRING);
			}	
			return false;
		);
	}	

	bool add_schedule_uniform_dist(uint64_t start_after_msec, uint64_t min_dist_msec, uint64_t max_dist_msec, const char *name, folly::Function<void()> && fcb, bool print_on_error = true) noexcept
	{
		DEBUGEXECN(1, 
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Adding a new Function Schedule \'%s\' repeats randomly within interval of %lu msec to %lu msec...\n", 
				name, min_dist_msec, max_dist_msec);
		);

		try {
			folly::FunctionScheduler::addFunctionUniformDistribution(std::move(fcb), std::chrono::milliseconds(min_dist_msec), 
				std::chrono::milliseconds(max_dist_msec), name, std::chrono::milliseconds(start_after_msec));

			return true;
		}
		GY_CATCH_EXCEPTION(
			if (print_on_error) {
				ERRORPRINT_OFFLOAD("Failed to add uniform dist Function schedule \'%s\' : %s\n", name, GY_GET_EXCEPT_STRING);
			}	
			return false;
		);
	}	
	
	bool add_schedule_poisson_dist(uint64_t start_after_msec, double poisson_mean_msec, const char *name, folly::Function<void()> && fcb, bool print_on_error = true) noexcept
	{
		DEBUGEXECN(1, 
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Adding a new Function Schedule name \'%s\' repeats with a Poisson distribution around %lu msec...\n", 
				name, (uint64_t)poisson_mean_msec);
		);

		try {
			folly::FunctionScheduler::LatencyDistribution	latdist(true, poisson_mean_msec);

			folly::FunctionScheduler::addFunction(std::move(fcb), std::chrono::milliseconds(1000) /* unused */, latdist,
				name, std::chrono::milliseconds(start_after_msec));

			return true;
		}
		GY_CATCH_EXCEPTION(
			if (print_on_error) {
				ERRORPRINT_OFFLOAD("Failed to add Poisson dist Function schedule \'%s\' : %s\n", name, GY_GET_EXCEPT_STRING);
			}
			return false;
		);
	}	

	bool add_oneshot_schedule(uint64_t start_after_msec, const char *name, folly::Function<void()> && fcb, bool print_on_error = true) noexcept
	{
		DEBUGEXECN(1, INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Adding a new one shot Function Schedule \'%s\' ...\n", name););

		try {
			folly::FunctionScheduler::addFunctionOnce(std::move(fcb), name, std::chrono::milliseconds(start_after_msec));

			return true;
		}
		GY_CATCH_EXCEPTION(
			if (print_on_error) {
				ERRORPRINT_OFFLOAD("Failed to add one shot Function schedule \'%s\' : %s\n", name, GY_GET_EXCEPT_STRING);
			}
			return false;
		);
	}	

	bool cancel_schedule(const char *name, bool wait_if_currently_running = false) noexcept
	{
		DEBUGEXECN(1, INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Cancelling Function Schedule \'%s\' ...\n", name););

		try {
			bool			bret;

			if (wait_if_currently_running == false) {
				bret = folly::FunctionScheduler::cancelFunction(name);
			}
			else {
				bret = folly::FunctionScheduler::cancelFunctionAndWait(name);
			}

			return bret;
		}
		catch(...) {
			return false;
		};
	}	

	void cancel_all_schedules(bool wait_if_currently_running = false) noexcept
	{
		DEBUGEXECN(1, INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Cancelling all Function Schedules...\n"););

		try {
			if (wait_if_currently_running == false) {
				folly::FunctionScheduler::cancelAllFunctions();
			}
			else {
				folly::FunctionScheduler::cancelAllFunctionsAndWait();
			}
		}
		GY_CATCH_EXCEPTION(
			ERRORPRINT_OFFLOAD("Failed to cancel all Function schedules : %s\n", GY_GET_EXCEPT_STRING);
		);
	}	

	bool reset_schedule_timer(const char *name) noexcept
	{
		try {
			return folly::FunctionScheduler::resetFunctionTimer(name);
		}
		GY_CATCH_EXCEPTION(
			DEBUGEXECN(1, ERRORPRINT_OFFLOAD("Failed to reset time of Function schedule \'%s\' : %s\n", name, GY_GET_EXCEPT_STRING););
			return false;
		);
	}	

	bool start_scheduler() noexcept
	{
		try {
			return folly::FunctionScheduler::start();
		}	
		GY_CATCH_EXCEPTION(
			ERRORPRINT("Failed to start Function scheduler : %s\n", GY_GET_EXCEPT_STRING);
			return false;
		);
	}	

	bool stop_scheduler() noexcept
	{
		try {
			return folly::FunctionScheduler::shutdown();
		}	
		GY_CATCH_EXCEPTION(
			ERRORPRINT("Failed to stop Function scheduler : %s\n", GY_GET_EXCEPT_STRING);
			return false;
		);
	}	

	enum SCHEDULER_TYPE_E {
		SCHEDULER_LONG_DURATION		= 1,	/* Catchup enabled */
		SCHEDULER_LONG2_DURATION	= 2,	/* Catchup enabled */
		SCHEDULER_HIGH_PRIO		= 3,	/* Catchup enabled */
		SCHEDULER_NO_CATCHUP		= 4,	/* No catchup for jobs required a fixed time slot say run at every 5th second only, can result in job misses */
		SCHEDULER_MAINTENANCE		= 5,	/* No catchup : Use for long running maintenance tasks to be periodically triggered */
	};
		
	static GY_SCHEDULER * 			get_singleton(SCHEDULER_TYPE_E type) noexcept;

	// Just initialize only the maintenance handler scheduler object
	static int				init_singleton_maintenance(bool use_rcu = false);
	
	// Initialize all scheduler objects
	static int				init_singletons(bool use_rcu = false);

	static void				start_rcu_schedules();

	static void				cancel_rcu_schedules();
};	

} // namespace gyeeta

