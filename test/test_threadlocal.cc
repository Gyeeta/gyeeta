//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#undef 			DO_PROFILE
#define			DO_PROFILE

#include		"gy_common_inc.h"
#include		"gy_file_api.h"
#include		"gy_file_api.h"
#include		"gy_pkt_pool.h"
#include		"gy_stack_container.h"

#include 		<unistd.h>
#include 		<cstdlib>
#include 		<string>
#include		<cstdint>

#include 		"folly/ThreadLocal.h"

#include 		<iostream>

#undef 			NDEBUG
#include 		<assert.h> 

using 			namespace gyeeta;
using 			std::chrono::seconds;

namespace TEST_SPACE {

struct FOLLY_LIST {
	pid_t		tid;
	int		counter;
};

class THR_LOCAL_S_TAG;							// For accessAllThreads() recommended to use separate tags for mutex contention less
folly::ThreadLocal<FOLLY_LIST, THR_LOCAL_S_TAG> 			pgcounter;

struct THR_LOCAL
{
	pid_t							tid;
	std::string						name;
	MULTI_IO_STATS<false>				iw_io_stats;
	THR_IO_PROFILE<false>				iw_io_class;
	// char							stacksmash[1024 * 1024];

	THR_LOCAL() : tid(syscall(SYS_gettid)), iw_io_stats(__FUNCTION__, tid, "thread stats", 1), iw_io_class(&iw_io_stats)
	{
		char		buf1[256], tbuf[128];
		struct timeval	tv;

		gettimeofday(&tv, nullptr);

		auto len = GY_SAFE_SNPRINTF(buf1, sizeof(buf1), "Thread %d Started at %s : this = %p", tid, gy_time_print(tbuf, sizeof(tbuf) - 1, tv).first, this);
		name.assign(buf1, len);
		INFOFDUNLOCKPRINT(STDOUT_FILENO, "Thread Local storage constructor for thread %s\n", buf1);

		pgcounter->tid = tid;
		pgcounter->counter = 1;
	}	

	~THR_LOCAL()
	{
		INFOFDUNLOCKPRINT(STDOUT_FILENO, "Thread Local storage destructor called for thread %s\n", name.c_str());
	}	
};

[[gnu::noinline]] static void create_stack_map()
{
	using Stackmap 		= INLINE_STACK_HASH_MAP<std::string, std::string, (sizeof(std::string) * 2 + 8) * 128>;

	Stackmap		u(4096 /* initial bucket count */);

	u["RED"] 	= "#FF0000";

	GY_CC_BARRIER();

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Within Inline Stack Map of size %lu : Current stack remaining bytes %lu\n", 
			sizeof(u), gy_get_thread_local().get_thread_stack_freespace());
}	

static void display_thread_attributes(char *prefix)
{
	int 				ret;
	pthread_attr_t 			attr;

	ret = pthread_getattr_np(pthread_self(), &attr);
	if (ret != 0) {
		PERRORPRINT("pthread_getattr_np failed");
		return;
	}	

	GY_SCOPE_EXIT { pthread_attr_destroy(&attr); INFOPRINT("Exiting display_thread_attributes() for %s\n", prefix);};
	GY_SCOPE_EXIT { INFOPRINT("Exiting second scope display_thread_attributes() for %s\n", prefix);};

	size_t 				stack_size, guard_size = 0;
	void 				*stack_addr;

	ret = pthread_attr_getguardsize(&attr, &guard_size);
	if (ret != 0) {
		PERRORPRINT("pthread_attr_getguardsize failed");
	}
	else {
		INFOPRINT("%s : Guard size          = %lu bytes\n", prefix, guard_size);
	}	

	ret = pthread_attr_getstack(&attr, &stack_addr, &stack_size);
	if (ret != 0) {
		PERRORPRINT("pthread_attr_getstack failed : Cannot get Stack start pointer");
		return;
	}
	INFOPRINT("%s : Stack Start address       = %p", prefix, (char *)stack_addr + guard_size);
		
	if (stack_size > 0) IRPRINT(" (End of Stack = %p)\n", (char *) stack_addr + guard_size + stack_size);
	INFOPRINT("%s : Stack size          = 0x%lx (%lu bytes)\n\n", prefix, stack_size - guard_size, stack_size - guard_size);

	INFOPRINT("%s : Parameters from thread_local calculations : Stack size %lu : Stack Starts at %p : Current Thread stack remaining bytes %lu\n",
		prefix, gy_get_thread_local().get_max_stack_size(), gy_get_thread_local().get_stack_start(), gy_get_thread_local().get_thread_stack_freespace());
}

size_t 	vla_sz = sizeof(FOLLY_LIST) + 4096, vla_sz2 = sizeof(FOLLY_LIST) + 8192;	
	
void test_func()
{
	char				testbuf[2048];
	int				test1 = 0;
		
	snprintf(testbuf, sizeof(testbuf), "%s", __FUNCTION__);
		
	INFOPRINTCOLOR(GY_COLOR_GREEN, "Within %s for thread %s gy_get_thread_local is %p : Current stack remaining bytes %lu\n", 
			testbuf, gy_get_thread_local().get_name(), &gy_get_thread_local(), gy_get_thread_local().get_thread_stack_freespace());

	static thread_local char	gtest1[2048];	

	strcpy(gtest1, "XXXXXXXXXXXXXXXXX");

	display_thread_attributes(gy_get_thread_local().get_name());

	create_stack_map();

	INFOPRINTCOLOR(GY_COLOR_GREEN, "After Inline Stack Map Function call : Current stack remaining bytes %lu\n\n", 
			gy_get_thread_local().get_thread_stack_freespace());

	
	if (time(nullptr) > 1000) {
		const auto testfn = [&]() 
		{
			using Stackmap 		= INLINE_STACK_HASH_MAP<std::string, std::string, (sizeof(std::string) * 2 + 8) * 1024>;

			Stackmap		u(4096 /* initial bucket count */);

			u["RED"] 	= "#FF0000";

			GY_CC_BARRIER();

			INFOPRINTCOLOR(GY_COLOR_GREEN, "Within Inline Stack Map conditional block of size %lu : Current stack remaining bytes %lu\n", 
					sizeof(u), gy_get_thread_local().get_thread_stack_freespace());
		};

		if (time(nullptr) > 10001) {
			INFOPRINTCOLOR(GY_COLOR_GREEN, "Before Inline Stack Map lambda call : Current stack remaining bytes %lu\n\n", 
				gy_get_thread_local().get_thread_stack_freespace());
		
			testfn();
		}	
	}	

	char				*pdata = nullptr, *pdata2;
	bool				is_malloc, is_malloc2;
	uint32_t			mallcnt = 0;
	
	SAFE_STACK_ALLOC(pdata, 256 * 1024, is_malloc);
	assert(is_malloc == true);

	strcpy(pdata, "malloc allocated pdata");
	INFOPRINTCOLOR(GY_COLOR_GREEN, "pdata is %p for %s : Current stack remaining bytes %lu : %s\n", 
			pdata, gy_get_thread_local().get_name(), gy_get_thread_local().get_thread_stack_freespace(), pdata);

	SAFE_STACK_ALLOC(pdata2, 1 * 1024, is_malloc);
	
	auto str1 = read_file_to_string("/proc/self/maps", 32767, 8192);
	GY_STRNCPY(pdata, str1.c_str(), 32);		
	GY_STRNCPY(pdata2, str1.c_str(), 32);		

	INFOPRINTCOLOR(GY_COLOR_GREEN_UNDERLINE, "%s : Current stack remaining bytes %lu : Now starting direct stack allocation loops...\n\n\n", 
		gy_get_thread_local().get_name(), gy_get_thread_local().get_thread_stack_freespace());

	size_t			currstacksz = gy_get_thread_local().get_thread_stack_freespace();

	for (int i = 0; i < 400; i++) {
		GY_MT_COLLECT_PROFILE(100, "Direct Stack Alloc test");					

		FOLLY_LIST			*pfol, *pfol2;
		alignas(8) uint8_t		pbuf[sizeof(*pfol) + 4096];
		
		pfol = reinterpret_cast<FOLLY_LIST *>(pbuf);

		uint8_t				test1[512 + i % 400];

		GY_CC_BARRIER();

		*(test1 + 111 + i) = '\0';

		alignas(8) uint8_t		pbuf2[sizeof(*pfol2) + 8192];

		pfol2 = reinterpret_cast<FOLLY_LIST *>(pbuf2);

		GY_CC_BARRIER();

		pfol->tid = 1;
		pfol->counter = 1;

		GY_CC_BARRIER();

		pfol2->tid = 1;
		pfol2->counter = 1;

		if (i == 0) {
			INFOPRINTCOLOR(GY_COLOR_GREEN, "Within Direct Stack Alloc test : Current stack remaining bytes %lu : Bytes used = %ld\n", 
					gy_get_thread_local().get_thread_stack_freespace(), currstacksz - gy_get_thread_local().get_thread_stack_freespace());
		}	
	}

	INFOPRINTCOLOR(GY_COLOR_GREEN_UNDERLINE, "%s : Current stack remaining bytes %lu : Now starting Variable Length Array loops...\n\n\n", 
		gy_get_thread_local().get_name(), gy_get_thread_local().get_thread_stack_freespace());
	

	for (int i = 0; i < 400; i++) {
		GY_MT_COLLECT_PROFILE(100, "Variable Length Array test");					

		FOLLY_LIST			*pfol, *pfol2;

		GY_CC_BARRIER();

		alignas(8) uint8_t		pbuf[vla_sz];

		uint8_t				test1[512 + i % 400];

		GY_CC_BARRIER();

		*(test1 + 111 + i) = '\0';

		alignas(8) uint8_t		pbuf2[vla_sz2];
		
		pfol = reinterpret_cast<FOLLY_LIST *>(pbuf);
		pfol2 = reinterpret_cast<FOLLY_LIST *>(pbuf2);

		GY_CC_BARRIER();

		pfol->tid = 1;
		pfol->counter = 1;

		pfol2->tid = 1;
		pfol2->counter = 1;

		vla_sz++;
		vla_sz2++;

		if (vla_sz > 9000) vla_sz = 9000;
		if (vla_sz2 > 9000) vla_sz2 = 9000;
	}


	INFOPRINTCOLOR(GY_COLOR_GREEN_UNDERLINE, "%s : Current stack remaining bytes %lu : Now starting SAFE_STACK_ALLOC loops...\n\n\n", 
		gy_get_thread_local().get_name(), gy_get_thread_local().get_thread_stack_freespace());

	for (int i = 0; i < 400; i++) {
		GY_MT_COLLECT_PROFILE(100, "SAFE_STACK_ALLOC test");					

		FOLLY_LIST			*pfol, *pfol2;
		
		SAFE_STACK_ALLOC(pfol, vla_sz, is_malloc);	

		if (!pfol) {
			PERRORPRINT("Failed to allocate space");
			return;
		}	

		uint8_t				test1[512 + i % 400];

		GY_CC_BARRIER();

		*(test1 + 111 + i) = '\0';

		SAFE_STACK_ALLOC(pfol2,  vla_sz2, is_malloc2);	

		pfol->tid = 1;
		pfol->counter = 1;

		pfol2->tid = 1;
		pfol2->counter = 1;

		if (is_malloc) {
			mallcnt++;
		}

		if (is_malloc2) {
			mallcnt++;
		}
	}

	INFOPRINTCOLOR(GY_COLOR_GREEN, "%s : Current stack remaining bytes %lu : Malloc count %u : Now starting malloc loop ...\n\n\n", 
			gy_get_thread_local().get_name(), gy_get_thread_local().get_thread_stack_freespace(), mallcnt);

	for (int i = 0; i < 400; i++) {
		GY_MT_COLLECT_PROFILE(100, "malloc test");					

		FOLLY_LIST			*pfol, *pfol2;
		
		pfol = (decltype(pfol))malloc(vla_sz);	
		if (!pfol) {
			PERRORPRINT("Failed to allocate space");
			return;
		}	

		pfol->tid = 1;
		pfol->counter = 1;

		uint8_t				*ptest1 = new uint8_t[512 + i % 400];

		GY_CC_BARRIER();

		*(ptest1 + 111 + i) = '\0';

		GY_CC_BARRIER();

		delete [] ptest1;

		pfol2 = (decltype(pfol))malloc(vla_sz2);	
		if (!pfol2) {
			PERRORPRINT("Failed to allocate space");
			free(pfol);
			return;
		}	

		pfol2->tid = 1;
		pfol2->counter = 1;

		free(pfol2);
		free(pfol);
	}

	INFOPRINTCOLOR(GY_COLOR_GREEN, "pdata2 is %p for %s : Current stack remaining bytes %lu : %s\n\n\n", 
			pdata2, gy_get_thread_local().get_name(), gy_get_thread_local().get_thread_stack_freespace(), pdata2);
}	

void * start_thread(void *arg)
{
	auto				&thrdata = gy_get_thread_local();
		
	thread_local THR_LOCAL	gthr;
	time_t				tnow;
	long				extrasyscall = (long)(arg);
	
	for (int i = 0; i < 1000; i++) {
		tnow = time(nullptr);
		if (extrasyscall) {
			pgcounter->counter = 100;
			for (int j = 0; j < 100; j++) {
				int fd = open("/proc/self/exe", O_RDONLY);
				GY_SCOPE_EXIT {
					uint8_t		tbuf[1024];

					read(fd, tbuf, sizeof(tbuf));
					if (fd > 0) close(fd);
				};	
			}	

		}	
	}	

	if (extrasyscall) {
		GY_MMAP		mmap1(16 * 1024, false);

		for (const auto& i : TEST_SPACE::pgcounter.accessAllThreads()) {
			INFOPRINT("From Thread %d : ----- Thread %d : Counter %d\n", gthr.tid, i.tid, i.counter);
		}
		gy_nanosleep_safe(0, 1000);

		memset(mmap1.get_map_addr(), 0, mmap1.get_mapped_size());

		int fd = open("/proc/self/exe", O_RDONLY);
		GY_SCOPE_EXIT {
			read(fd, mmap1.get_map_addr(), 16 * 1024);
			if (fd > 0) close(fd);
		};	

		test_func();
	}	

	INFOFDUNLOCKPRINT(STDOUT_FILENO, "Thread %s exiting now...\n\n", gthr.name.c_str());
	return nullptr;
}	

}

int main()
{
	pthread_t		tids[8];
	int			ret;

	gdebugexecn = 5;

	INFOPRINTCOLOR(GY_COLOR_GREEN, "main thread  : Current stack remaining bytes %lu\n", gy_get_thread_local().get_thread_stack_freespace());

	for (size_t i = 0; i < sizeof(tids)/sizeof(*tids); i++) {
		ret = gy_create_thread(tids + i, TEST_SPACE::start_thread, (void *)(i > 4 ? 1L : 0L));
/* 		ret = gy_create_thread(tids + i, TEST_SPACE::start_thread, (void *)(i == 3 ? 1L : 0L)); */
	}	

	for (size_t i = 0; i < sizeof(tids)/sizeof(*tids); i++) {
		ret = pthread_join(tids[i], nullptr);
	}	
	
	INFOFDUNLOCKPRINT(STDOUT_FILENO, "\n\nExiting Now....\n\n");
	return 0;
}

