//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include		"gy_common_inc.h"
#include		"gy_misc.h"
#include		"gy_malloc_hook.h"

using namespace gyeeta;

using BUFCACHE = IOVEC_BUFFER_CACHE<5, 4>;

static void test_bufcache_realloc_pool()
{
	try {
		IRPRINT("\n\n");
		INFOPRINTCOLOR(GY_COLOR_GREEN, "Now testing IOVEC_BUFFER_CACHE realloc pool ...\n");

		size_t			szarr[] {128, 512, 1024, 2048};
		size_t			maxarr[] {256, 256, 256, 256};
		POOL_ALLOC_ARRAY	poolarr(szarr, maxarr, GY_ARRAY_SIZE(szarr), true);
		BUFCACHE		bufcache(GY_UP_MB(16), &poolarr);

		uint32_t 		min_sz, recomm_sz, szmax, total_sz, nmsg_set;
		char			*pbuf;

		for (uint32_t j = 0; j < GY_ARRAY_SIZE(szarr); ++j) {
			uint32_t	asz = szarr[j];

			for (int i = 0; i < 256; ++i) {
				min_sz 		= 190 + i;
				recomm_sz	= min_sz * 2;

				pbuf = (char *)bufcache.get_buf(min_sz, recomm_sz, szmax);
				strcpy(pbuf, "Testing...");
		
				bufcache.set_buf_sz(std::min(recomm_sz - 16u, szmax));
			}	

			auto iovarr = bufcache.get_iovec_array(total_sz, nmsg_set);
		}

		GY_MALLOC_HOOK::gy_print_memuse("During test_bufcache_realloc_pool()");
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception while handling Buffer Cache Reallocs %s\n", GY_GET_EXCEPT_STRING);
	);
}	

static void test_bufcache_realloc_malloc()
{
	try {
		IRPRINT("\n\n");
		INFOPRINTCOLOR(GY_COLOR_LIGHT_BLUE, "Now testing IOVEC_BUFFER_CACHE realloc malloc ...\n");

		size_t			szarr[] {128, 512, 1024, 2048};
		size_t			maxarr[] {256, 256, 256, 256};
		BUFCACHE		bufcache(GY_UP_MB(16));

		uint32_t 		min_sz, recomm_sz, szmax, total_sz, nmsg_set;
		char			*pbuf;

		for (uint32_t j = 0; j < GY_ARRAY_SIZE(szarr); ++j) {
			uint32_t	asz = szarr[j];

			for (int i = 0; i < 256; ++i) {
				min_sz 		= 190 + i;
				recomm_sz	= min_sz * 2;

				pbuf = (char *)bufcache.get_buf(min_sz, recomm_sz, szmax);
				strcpy(pbuf, "Testing...");
		
				bufcache.set_buf_sz(std::min(recomm_sz - 16u, szmax));
			}	

			auto iovarr = bufcache.get_iovec_array(total_sz, nmsg_set);
		}

		GY_MALLOC_HOOK::gy_print_memuse("During test_bufcache_realloc_malloc()");
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception while handling Buffer Cache Reallocs %s\n", GY_GET_EXCEPT_STRING);
	);
}	



static void test_bufcache_cb_pool()
{
	try {
		IRPRINT("\n\n");
		INFOPRINTCOLOR(GY_COLOR_CYAN, "Now testing IOVEC_BUFFER_CACHE callbacks pool...\n");
 
		size_t			szarr[] {128, 512, 1024, 2048};
		size_t			maxarr[] {256, 256, 256, 256};
		POOL_ALLOC_ARRAY	poolarr(szarr, maxarr, GY_ARRAY_SIZE(szarr), true);
		BUFCACHE		bufcache(GY_UP_MB(16), &poolarr);

		uint32_t 		min_sz, recomm_sz, szmax, total_sz, nmsg_set, ncbs = 0;
		char			*pbuf;

		auto fcb = [&](IOVEC_ARRAY<5> && iovarr, uint32_t total_sz, uint32_t nmsg_set)
		{
			ncbs++;
		};	

		for (uint32_t j = 0; j < GY_ARRAY_SIZE(szarr); ++j) {
			uint32_t	asz = szarr[j];

			for (int i = 0; i < 256; ++i) {
				min_sz 		= 190 + i;
				recomm_sz	= min_sz * 2;

				pbuf = (char *)bufcache.get_buf(fcb, min_sz, recomm_sz, szmax);

				if (!pbuf) {
					pbuf = (char *)bufcache.get_buf(fcb, min_sz, recomm_sz, szmax);

					assert(pbuf);
				}

				strcpy(pbuf, "Testing...");
		
				bufcache.set_buf_sz(std::min(recomm_sz - 16u, szmax));
			}	
		}

		INFOPRINTCOLOR(GY_COLOR_CYAN, "IOVEC_BUFFER_CACHE received %u callbacks with pool\n\n", ncbs);

		GY_MALLOC_HOOK::gy_print_memuse("During test_bufcache_cb_pool()");
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception while handling Buffer Cache Callbacks %s\n", GY_GET_EXCEPT_STRING);
	);
}	


static void test_bufcache_cb_malloc()
{
	try {
		IRPRINT("\n\n");
		INFOPRINTCOLOR(GY_COLOR_BLUE, "Now testing IOVEC_BUFFER_CACHE callbacks with mallocs...\n");

		size_t			szarr[] {128, 512, 1024, 2048};
		size_t			maxarr[] {256, 256, 256, 256};
		BUFCACHE		bufcache(GY_UP_MB(16));

		uint32_t 		min_sz, recomm_sz, szmax, total_sz, nmsg_set, ncbs = 0;
		char			*pbuf;

		auto fcb = [&](IOVEC_ARRAY<5> && iovarr, uint32_t total_sz, uint32_t nmsg_set)
		{
			ncbs++;
		};	

		for (uint32_t j = 0; j < GY_ARRAY_SIZE(szarr); ++j) {
			uint32_t	asz = szarr[j];

			for (int i = 0; i < 256; ++i) {
				min_sz 		= 190 + i;
				recomm_sz	= min_sz * 2;

				pbuf = (char *)bufcache.get_buf(fcb, min_sz, recomm_sz, szmax);

				if (!pbuf) {
					pbuf = (char *)bufcache.get_buf(fcb, min_sz, recomm_sz, szmax);

					assert(pbuf);
				}

				strcpy(pbuf, "Testing...");
		
				bufcache.set_buf_sz(std::min(recomm_sz - 16u, szmax));
			}	
		}

		INFOPRINTCOLOR(GY_COLOR_BLUE, "IOVEC_BUFFER_CACHE received %u callbacks with mallocs\n\n", ncbs);

		GY_MALLOC_HOOK::gy_print_memuse("During test_bufcache_cb()");
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception while handling Buffer Cache Callbacks %s\n", GY_GET_EXCEPT_STRING);
	);
}	


int main()
{
	GY_MALLOC_HOOK::gy_malloc_init("Starting Buffer Cache tests");

	malloc_trim(0);
	GY_MALLOC_HOOK::gy_print_memuse("Starting Tests now...", true);

	test_bufcache_realloc_pool();
	GY_MALLOC_HOOK::gy_print_memuse("After test_bufcache_realloc_pool()", true);

	test_bufcache_realloc_malloc();
	GY_MALLOC_HOOK::gy_print_memuse("After test_bufcache_realloc_malloc()", true);

	test_bufcache_cb_pool();
	GY_MALLOC_HOOK::gy_print_memuse("After test_bufcache_cb_pool()", true);

	test_bufcache_cb_malloc();
	GY_MALLOC_HOOK::gy_print_memuse("After test_bufcache_cb_malloc()", true);

}	
