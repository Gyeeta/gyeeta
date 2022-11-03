//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#undef		DO_PROFILE

#include 	"gy_common_inc.h"
#include	"folly/memory/EnableSharedFromThis.h"

#include 	<malloc.h>

using namespace gyeeta;

namespace gyeeta {

int						gdebugexecn = 10;	
bool						guse_utc_time = false, gunbuffered_stdout = false;

thread_local 	GY_THR_LOCAL			gthrdata_local_;
thread_local 	pid_t				gtid_local_ = -1, gtid_startpid_;

size_t 						gpgsz_local_;
uint32_t 					gclktck_local_;

uint64_t					gproc_start_usec, gproc_start_clock, gproc_start_boot;
pid_t						gproc_start_pid, gproc_curr_pid;

GY_TIMEZONE* GY_TIMEZONE::get_singleton() noexcept	
{
	return nullptr;
}	

}

void * my_malloc(size_t count)
{
	auto ptr = std::malloc(count);

	INFOPRINTCOLOR(GY_COLOR_GREEN, "my_malloc : Allocated %lu bytes Addr %p\n", count, ptr);

	return ptr;
}

void my_free(void *ptr) noexcept
{
	INFOPRINTCOLOR(GY_COLOR_YELLOW, "my_free called for pointer %p\n", ptr);

	std::free(ptr);
}

void * operator new(size_t count)
{
	auto ptr = std::malloc(count);

	INFOPRINTCOLOR(GY_COLOR_GREEN, "malloc : Allocated %lu bytes Addr %p\n", count, ptr);

	return ptr;
}

void operator delete(void *ptr) noexcept
{
	INFOPRINTCOLOR(GY_COLOR_YELLOW, "free called for pointer %p\n", ptr);

	std::free(ptr);
}

struct MyLargeType  : public folly::enable_shared_from_this<MyLargeType>
{
	MyLargeType()
	{
		INFOPRINT("Constructor of MyLargeType called : this = %p\n", this);

		arr[0] = 1;
		arr[1] = 2;
	}

	~MyLargeType() 
	{ 
		INFOPRINT("Destructor of MyLargeType called : this = %p\n", this);

		arr[0] = 3;
		arr[1] = 4;
	}

	int 	arr[100];
};

struct MyDel { 
	void operator()(MyLargeType * p) const 
	{
		INFOPRINTCOLOR(GY_COLOR_BLUE, "Deleter Functor called...\n");
		p->~MyLargeType();
		my_free(p);
	}
};


int __attribute__((noinline)) test_tuple_shr(std::tuple<std::shared_ptr<MyLargeType> &, int, bool> &tup)
{
	INFOPRINTCOLOR(GY_COLOR_BLACK, "Tuple contents : is shared_ptr valid %d, %lu\n", std::get<0>(tup) ? 1 : 0, std::get<0>(tup).use_count());
	return 0;
}	

void * dummy_thread(void *)
{
	while (true) {
		gy_nanosleep(100, 0);
	}	
}

int main() 
{
	pthread_t		thrid;

	// Create a dummy thread so that g++ will actually use Atomic stuff
	gy_create_thread(&thrid, dummy_thread, nullptr, 32 * 1024, false);

	{
		MyLargeType			*praw;
		std::weak_ptr<MyLargeType> 	pw2, pweak_from2, pweak_from3;
		{
			std::weak_ptr<MyLargeType> pw, pweak_from1;
			{
				INFOPRINT("Calling shared_ptr default constructor ...\n");
			
				std::shared_ptr<MyLargeType> dft;

				INFOPRINT("Calling make_shared<> ...\n");
				auto p = std::make_shared<MyLargeType>();
				pw = p;        
				dft = p;

				INFOPRINTCOLOR(GY_COLOR_BLACK, "Calling weak_from_this for make_shared pointer...\n");
				pweak_from1 = p.get()->weak_from_this();

				praw = p.get();

				INFOPRINTCOLOR(GY_COLOR_CYAN, "Large object data[0] = %d data[1] = %d use_count = %lu\n", praw->arr[0], praw->arr[1], pweak_from1.use_count());
			}
			INFOPRINT("make_shared scope ended.. use_count = %lu : Referencing praw even after destructor : data[0] = %d data[1] = %d\n", 
					pw.use_count(), praw->arr[0], praw->arr[1]);
		}
		{
			INFOPRINT("Calling new for shared_ptr ...\n");
			auto rawptr = new MyLargeType();

			std::shared_ptr<MyLargeType> p(rawptr);
			pw2 = p; 

			INFOPRINTCOLOR(GY_COLOR_BLACK, "Calling weak_from_this for new based shared pointer...\n");

			pweak_from2 = rawptr->weak_from_this();

			std::shared_ptr<MyLargeType> q = rawptr->shared_from_this();

			auto	valptr = pweak_from2.lock();

			pweak_from3 = pweak_from2;

			if (valptr) {
				INFOPRINTCOLOR(GY_COLOR_CYAN, "Lock of weak_ptr success... use_count = %lu weak_ptr use_count = %lu\n", valptr.use_count(), pweak_from3.use_count());
			}	
			else {
				ERRORPRINTCOLOR(GY_COLOR_RED, "weak_ptr lock failed...\n");
			}	

		}
		{
			INFOPRINTCOLOR(GY_COLOR_BLUE, "Calling my_malloc for shared_ptr with custom deleter ...\n");
			auto pm = my_malloc(sizeof(MyLargeType));

			auto rawptr = new (pm) MyLargeType();

			std::shared_ptr<MyLargeType> p(rawptr, MyDel());
			pw2 = p; 

			INFOPRINTCOLOR(GY_COLOR_BLACK, "Calling weak_from_this for new based shared pointer...\n");

			pweak_from2 = rawptr->weak_from_this();

			auto q = rawptr->shared_from_this();

			auto	valptr = pweak_from2.lock();

			pweak_from3 = pweak_from2;

			if (valptr) {
				INFOPRINTCOLOR(GY_COLOR_CYAN, "Lock of weak_ptr success... use_count = %lu weak_ptr use_count = %lu\n", valptr.use_count(), pweak_from3.use_count());
			}	
			else {
				ERRORPRINTCOLOR(GY_COLOR_RED, "weak_ptr lock failed...\n");
			}	

		}
		auto	expptr = pweak_from2.lock();

		if (expptr) {
			INFOPRINTCOLOR(GY_COLOR_RED, "Can lock an expired shared_ptr based weak_ptr...\n");
		}	
		else {
			INFOPRINTCOLOR(GY_COLOR_CYAN, "weak_ptr lock failed use_count = %lu...\n", pweak_from2.use_count());
		}	
		INFOPRINT("new based shared_ptr scope ended...\n");
	}

	IRPRINT("\n\n");

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Now testing time for weak_ptr lock...\n\n");
	int		var = 0;
	uint64_t	tresp;
	auto 		rawptr = new MyLargeType();

	std::shared_ptr<MyLargeType> pshr(rawptr);

	auto weakptr = rawptr->weak_from_this();

	std::shared_ptr<MyLargeType> qshr = rawptr->shared_from_this();

	{
		EXEC_TIME		exec("weak_ptr.lock", __LINE__, &tresp);
		for (int i = 0; i < 10000000; ++i) {
			auto	expptr = weakptr.lock();
			if (expptr) {
				(*expptr).arr[0]++;
			}	
			GY_CC_BARRIER();
		}
	}

	INFOPRINT("Avg Exec time for each call of a single weak_ptr lock() %lu nsec (%.09f sec) : arr[0] = %d\n", tresp/10000000, tresp/1000000000.0f/10000000, rawptr->arr[0]); 

	{
		uint64_t		totalns = 0, tmp1, tmp2;

		for (int i = 0; i < 10000000; ++i) {
			GY_CC_BARRIER();

			tmp1 = get_nsec_clock();\

			auto	expptr = weakptr.lock();

			totalns += get_nsec_clock() - tmp1;

			GY_CC_BARRIER();

			auto shrp = qshr;

			GY_CC_BARRIER();
			
			weakptr = shrp;
		}
	}

	INFOPRINT("Avg Exec time for each call of 2nd weak_ptr lock() %lu nsec (%.09f sec)\n", tresp/10000000, tresp/1000000000.0f/10000000); 


	{
		tresp = 0;

		EXEC_TIME		exec("shared_ptr access", __LINE__, &tresp);
		for (int i = 0; i < 10000000; ++i) {
			qshr->arr[0]++;
			GY_CC_BARRIER();
		}
	}
	INFOPRINT("Avg Exec time for each call of shared_ptr access %lu nsec (%.09f sec) : arr[0] = %d\n", tresp/1000000000, tresp/1000000000.0f/10000000, rawptr->arr[0]); 

	{
		INFOPRINTCOLOR(GY_COLOR_BLACK, "Creating a new shared_ptr based tuple struct : Current qshr.use_count is %lu...\n", qshr.use_count());

		std::tuple<std::shared_ptr<MyLargeType> &, int, bool>	tup {qshr, 0, true};

		test_tuple_shr(tup);
	}

	INFOPRINTCOLOR(GY_COLOR_CYAN, "Exiting...\n\n");
	return 0;
}
