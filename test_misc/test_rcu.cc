
#include		"gy_common_inc.h"
#include		"gy_file_api.h"
#include		"gy_rcu_inc.h"
#include		"gy_async_func.h"			

#include 		<sys/wait.h>

using 			namespace gyeeta;

namespace TEST_SPACE {

/*
 * XXX Note the assert(*plocal_ptr == 8) is likely to fail randomly. It is not an error...
 */

static int *test_rcu_pointer;

void * start_reader_thr(void *arg)
{
	INFOPRINT("Starting Reader thread %lu : TID %ld\n", (size_t)(arg), syscall(SYS_gettid));

	for (int j = 0; j < 10; j++) {
		for (int i = 0; i < 100'000; i++) {
			{
				RCU_LOCK_NO_CHKS		fastestlock;
				auto plocal_ptr = rcu_dereference(test_rcu_pointer);
				if (plocal_ptr) {
/* 					assert(*plocal_ptr == 8); */
				}	
			}

			{
				RCU_LOCK_SLOW		slowlock;
				auto plocal_ptr = rcu_dereference(test_rcu_pointer);
				if (plocal_ptr) {
					assert(*plocal_ptr == 8);
				}	
			}

			// gy_thread_rcu().gy_synchronize_rcu_delete<int, false>(nullptr);
		}

		gy_nanosleep(1, 0);
	}

	return nullptr;
}	
MAKE_PTHREAD_FUNC_WRAPPER(start_reader_thr);

void * start_writer_thr(void *arg)
{
	INFOPRINT("Starting Writer thread %lu : TID %ld\n", (size_t)(arg), syscall(SYS_gettid));

	gy_nanosleep(0, 1000);

	for (int i = 0; i < 100'000; i++) {
		int *pnew = (int *)malloc(sizeof(int));

		*pnew = 8;

		int *pold = rcu_xchg_pointer(&test_rcu_pointer, pnew);

		gy_thread_rcu().gy_synchronize_rcu_delete<int, FUNCTOR_FREE<int>>(pold);
	}

	for (int i = 0; i < 100'000; i++) {
		int *pnew = (int *)malloc(sizeof(int));

		*pnew = 8;

		int *pold = rcu_xchg_pointer(&test_rcu_pointer, pnew);

		if (pold) gy_thread_rcu().gy_call_rcu_using_wrapper<int, FUNCTOR_FREE<int>>(pold);
	}

	return nullptr;
}	
MAKE_PTHREAD_FUNC_WRAPPER(start_writer_thr);

void * reader_block_thr(void *arg)
{
	INFOPRINT("Starting Reader Blocking thread %lu : TID %ld\n", (size_t)(arg), syscall(SYS_gettid));

	for (int i = 0; i < 30; i++) {
		{
			RCU_LOCK_TIMED		fastlock;
			auto plocal_ptr = rcu_dereference(test_rcu_pointer);
			if (plocal_ptr) {
				assert(*plocal_ptr == 8);
			}	

			gy_nanosleep(1, 0);

			{
				RCU_LOCK_FAST	fastlock;
				auto plocal_ptr = rcu_dereference(test_rcu_pointer);
				if (plocal_ptr) {
					assert(*plocal_ptr == 8);
				}	
			}
		}


		{
			RCU_LOCK_SLOW		slowlock;
			auto plocal_ptr = rcu_dereference(test_rcu_pointer);
			if (plocal_ptr) {
				assert(*plocal_ptr == 8);
			}	
			
			gy_nanosleep(1, 0);

			{
				RCU_LOCK_SLOW		slowlock;
				auto plocal_ptr = rcu_dereference(test_rcu_pointer);
				if (plocal_ptr) {
					assert(*plocal_ptr == 8);
				}	
			}
			
		}
	}


	return nullptr;
}	
MAKE_PTHREAD_FUNC_WRAPPER(reader_block_thr);

void * writer_block_thr(void *arg)
{
	INFOPRINT("Starting blocking Writer thread %lu : TID %ld\n", (size_t)(arg), syscall(SYS_gettid));

	gy_nanosleep(0, 1000);

	for (int i = 0; i < 100'000; i++) {
		int *pnew = (int *)malloc(sizeof(int));

		*pnew = 8;

		int *pold = rcu_xchg_pointer(&test_rcu_pointer, pnew);

		gy_thread_rcu().gy_synchronize_rcu_delete<int, FUNCTOR_FREE<int>>(pold);
	}

	return nullptr;
}	
MAKE_PTHREAD_FUNC_WRAPPER(writer_block_thr);

static int to_exit = 0;

void *debug_thread(void *arg)
{
	PROC_CPU_IO_STATS		procstats(getpid(), getpid(), true);

	while (to_exit == 0) {
		gy_nanosleep(5, 0);

		procstats.get_current_stats(true);
	}

	return nullptr;
}	
MAKE_PTHREAD_FUNC_WRAPPER(debug_thread);

struct TEST_LARGE_STRUCT
{
	char		buf[8192];
};	

void * call_writer_thr(void *arg)
{
	INFOPRINT("Starting call_rcu Writer thread %lu : TID %ld\n", (size_t)(arg), syscall(SYS_gettid));

	
	gy_nanosleep(0, 1000);

	for (int i = 0; i < 500000; i++) {
		auto pnew = new TEST_LARGE_STRUCT;

		gy_thread_rcu().gy_call_rcu_using_wrapper<TEST_LARGE_STRUCT>(pnew);
	}

	return nullptr;
}	
MAKE_PTHREAD_FUNC_WRAPPER(call_writer_thr);

static void test_rcu_fork(void)
{
	pid_t		pid1, pid2, pid3;

	auto pnew1 = new TEST_LARGE_STRUCT;
	auto pnew2 = new TEST_LARGE_STRUCT;
	auto pnew3 = new TEST_LARGE_STRUCT;
	auto pnew4 = new TEST_LARGE_STRUCT;

	INFOPRINT("Testing RCU fork semantics...\n");

	gy_thread_rcu().gy_call_rcu_using_wrapper<TEST_LARGE_STRUCT>(pnew1);

	urcu_qsbr_call_rcu_before_fork();

	pid1 = fork();
	if (pid1 == 0) {
		urcu_qsbr_call_rcu_after_fork_child();
		// Test for fork failure
		exit(1);
	}

	urcu_qsbr_call_rcu_after_fork_parent();
	
	urcu_qsbr_synchronize_rcu();

	INFOPRINT("fork 1 test successful...\n");

	waitpid(pid1, nullptr, 0);

	gy_thread_rcu().gy_call_rcu_using_wrapper<TEST_LARGE_STRUCT>(pnew2);
	
	urcu_qsbr_call_rcu_before_fork();

	pid2 = fork();
	if (pid2 == 0) {

		urcu_qsbr_call_rcu_after_fork_child();

		gy_nanosleep(5, 0); 
		exit(0);
	}
	
	urcu_qsbr_call_rcu_after_fork_parent();

	waitpid(pid2, nullptr, 0);
	
	gy_thread_rcu().gy_call_rcu_using_wrapper<TEST_LARGE_STRUCT>(pnew3);
	gy_thread_rcu().gy_call_rcu_using_wrapper<TEST_LARGE_STRUCT>(pnew4);
	
	urcu_qsbr_synchronize_rcu();

	INFOPRINT("fork 2 test successful...\n");
}


}

int main()
{
	using namespace 	TEST_SPACE;

	gdebugexecn = 10;

	CPU_IO_STATS		procstats(GY_COLOR_BOLD_YELLOW "Process summary stats" GY_COLOR_RESET, getpid(), true);
	pthread_t		rdtid[5], wrtid[5], dbgtid;
	int			ret;
	uint64_t		memutil;

	ASYNC_FUNC_HDLR::init_singleton();

	memutil = gy_get_proc_vmsize(0);

	INFOPRINT(GY_COLOR_GREEN "Initial Memory : Current PID %d Memory Util is %lu (%lu MB)\n" GY_COLOR_RESET, getpid(), memutil, memutil >> 20);

	// test_rcu_fork();

	// return 0;

	gy_create_thread(&dbgtid, GET_PTHREAD_WRAPPER(debug_thread), nullptr);

	for (size_t i = 0; i < sizeof(rdtid)/sizeof(*rdtid); i++) {
		ret = gy_create_thread(rdtid + i, GET_PTHREAD_WRAPPER(start_reader_thr), (void *)(i));
	}	

	for (size_t i = 0; i < sizeof(wrtid)/sizeof(*wrtid); i++) {
		ret = gy_create_thread(wrtid + i, GET_PTHREAD_WRAPPER(start_writer_thr), (void *)(i));
	}	

	memutil = gy_get_proc_vmsize(0);

	INFOPRINT(GY_COLOR_GREEN "After Thread spawn : Current PID %d Memory Util is %lu (%lu MB)\n" GY_COLOR_RESET, getpid(), memutil, memutil >> 20);

	for (size_t i = 0; i < sizeof(rdtid)/sizeof(*rdtid); i++) {
		pthread_join(rdtid[i], nullptr);
	}	

	for (size_t i = 0; i < sizeof(wrtid)/sizeof(*wrtid); i++) {
		pthread_join(wrtid[i], nullptr);
	}

	memutil = gy_get_proc_vmsize(0);

	INFOPRINT(GY_COLOR_GREEN "After Thread join : Current PID %d Memory Util is %lu (%lu MB)\n" GY_COLOR_RESET, getpid(), memutil, memutil >> 20);

	for (size_t i = 0; i < sizeof(rdtid)/sizeof(*rdtid); i++) {
		ret = gy_create_thread(rdtid + i, GET_PTHREAD_WRAPPER(reader_block_thr), (void *)(i));
	}	

	for (size_t i = 0; i < sizeof(wrtid)/sizeof(*wrtid); i++) {
		ret = gy_create_thread(wrtid + i, i < 3 ? GET_PTHREAD_WRAPPER(writer_block_thr) : GET_PTHREAD_WRAPPER(call_writer_thr), (void *)(i));
	}	

	for (size_t i = 0; i < sizeof(rdtid)/sizeof(*rdtid); i++) {
		pthread_join(rdtid[i], nullptr);
	}	

	for (size_t i = 0; i < sizeof(wrtid)/sizeof(*wrtid); i++) {
		pthread_join(wrtid[i], nullptr);
	}

	gy_nanosleep(10, 0);

	to_exit = 1;
/* 	pthread_cancel(dbgtid); */
	pthread_join(dbgtid, nullptr);

	memutil = gy_get_proc_vmsize(0);

	INFOPRINT(GY_COLOR_GREEN "Before exiting : Current PID %d Memory Util is %lu (%lu MB)\n" GY_COLOR_RESET, getpid(), memutil, memutil >> 20);

	INFOPRINT("\n\nExiting Now....\n\n");

	return 0;
}

