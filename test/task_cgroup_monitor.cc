//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include 		"gy_common_inc.h"
#include 		"gy_cgroup_stat.h"
#include 		"gy_task_stat.h"
#include 		"gy_task_handler.h"
#include 		"gy_rcu_inc.h"

#include		<dirent.h>

using namespace gyeeta;

std::atomic<int>	gsig_rcvd;	

int test_task_handler()
{
	TASK_HANDLER::init_singleton(false);

	while (0 == gsig_rcvd.load()) {
		gy_nanosleep(1, 0);
	}	

	delete TASK_HANDLER::get_singleton();

	return 0;
}	

void *debug_thread(void *arg)
{
	PROC_CPU_IO_STATS		procstats(getpid(), getpid(), true);

	while (0 == gsig_rcvd.load(std::memory_order_relaxed)) {

		for (int i = 0; i < 60 && (0 == gsig_rcvd.load(std::memory_order_relaxed)); i++) {
			gy_nanosleep(1, 0);
		}	

		procstats.get_current_stats(true);
	}

	return nullptr;
}
MAKE_PTHREAD_FUNC_WRAPPER(debug_thread);

int handle_signal(int signo)
{
	alarm(5);

	gsig_rcvd.store(signo);

	return signo;
}	


int main(int argc, char **argv)
{
	try {
		gdebugexecn = 25;	
	
		GY_SIGNAL_HANDLER::init_singleton(argv[0], handle_signal, false);
	
		CGROUP_HANDLE::init_singleton();
		
		pthread_t 			dbgtid;
		
		gy_create_thread(&dbgtid, GET_PTHREAD_WRAPPER(debug_thread), nullptr, 65535, false);

		test_task_handler();

		INFOPRINTCOLOR(GY_COLOR_BOLD_GREEN, "All threads exited. Waiting for RCU free calls to complete...\n");

		wait_for_all_call_rcu_free();

		return 0;
	}
	GY_CATCH_EXCEPTION(ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Exception caught while monitoring task : %s\n", GY_GET_EXCEPT_STRING););
}	
