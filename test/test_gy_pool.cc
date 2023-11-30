//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

/*
 * On multi socket systems run as : sudo numactl -i 1 ./test_gy_pool
 */
#include			"gy_common_inc.h"
#include			"gy_pool_alloc.h"
#include			"gy_stack_pool.h"
#include			"gy_misc.h"
#include	 		"gy_msg_comm.h"

using namespace gyeeta;

using MPMCQ_COMM		= folly::MPMCQueue<COMM_MSG_C>;


void * mpmc_thread(void * arg)
{
	GY_THREAD			*pthread = (GY_THREAD *)arg;
	MPMCQ_COMM			*pfuncpool = (MPMCQ_COMM *)pthread->get_opt_arg1();
	FREE_FPTR			pfree = (FREE_FPTR)pthread->get_opt_arg2();
	COMM_MSG_C			comm;
	int				ret;
	min_max_counter<false>		tcounter;
	uint64_t			totalres, minres, maxres, iterval, tcurrnsec;
	double				avgres;

	EXEC_TIME			prof1("free Benchmark", 1);
	uint64_t			ttime1 = prof1.get_profile_time(), ttime2, tsubtime1, tsubtime2 = 0;

	do {
		pfuncpool->blockingRead(comm);

		tcurrnsec = get_nsec_clock();
		
		assert(comm.arg2_);

		assert(tcurrnsec >= comm.arg1_);

		tcounter.add(tcurrnsec - comm.arg1_);

		if (gy_unlikely(comm.arg2_ == 1)) {
			tcounter.get_current(totalres, minres, maxres, iterval, avgres);
			break;
		}

		tsubtime1 = prof1.get_profile_time();

		pfree((void *)comm.arg2_);

		tsubtime2 += prof1.get_profile_time() - tsubtime1;

	} while (1);

	ttime2 = prof1.get_profile_time();

	INFOPRINTCOLOR(GY_COLOR_CYAN, "Thread %s Total frees = %lu : Avg free() execution time = %lu nsec\n\n", 
		pthread->get_description(), iterval, tsubtime2/iterval);

	INFOPRINTCOLOR(GY_COLOR_CYAN, "Thread %s Total frees = %lu : Avg free() and thread pool read execution time = %lu nsec\n\n", 
		pthread->get_description(), iterval, (ttime2 - ttime1)/iterval);

	return nullptr;
}	

template <typename TAG>
class FIXED_ATOMIC_COUNTER 
{
public:
	static std::atomic<int64_t>		total_bytes_;
};


template <typename TAG>
std::atomic<int64_t>				FIXED_ATOMIC_COUNTER<TAG>::total_bytes_	= 0;

template <typename TAG>
class FIXED_NONATOMIC_COUNTER 
{
public:
	static gyeeta::gy_noatomic<int64_t>	total_bytes_;
};

template <typename TAG>
gyeeta::gy_noatomic<int64_t>			FIXED_NONATOMIC_COUNTER<TAG>::total_bytes_	= 0;


template <size_t maxsz_, typename TAG, typename TATOMIC = FIXED_ATOMIC_COUNTER<TAG>>
struct TFIXED_ALLOC : public TATOMIC
{
	typedef std::size_t 		size_type;
	typedef std::ptrdiff_t 		difference_type;

	static char * malloc(const size_type bytes) noexcept
	{ 
		int64_t			tcur = TATOMIC::total_bytes_.load(std::memory_order_relaxed);

		if (tcur + bytes < maxsz_) {
			TATOMIC::total_bytes_.fetch_add(bytes, std::memory_order_relaxed);
			return static_cast<char *>(std::malloc(bytes)); 
		}
		return nullptr;
	}
	
	static void free(char * block) noexcept
	{ 
		std::free(block); 
	}
};	


int main()
{
	using TPOOL1		= boost::pool<TFIXED_ALLOC<8192, void>>;
		
	int			eret;

	{
		POOL_ALLOC	pool1(512, 16);
	
		void *		parg[17];

		parg[0] = pool1.malloc();
		assert(parg[0]);

		for (size_t i = 1; i < 16; ++i) {
			parg[i] = pool1.malloc();
			assert(parg[i]);
		}	

		parg[16] = pool1.malloc();
		assert(parg[16] == nullptr);

		// Test invalid free
		pool1.free((void *)&eret);

		(void)pool1.malloc();
	}	


	{
		THR_POOL_ALLOC		pool1(505, 15, true);
	
		void *		parg[16];

		parg[0] = pool1.malloc();
		assert(parg[0]);

		for (size_t i = 1; i < 15; ++i) {
			parg[i] = pool1.malloc();
			assert(parg[i]);
		}	

		parg[15] = pool1.malloc();
		assert(parg[15] == nullptr);

		THR_POOL_ALLOC::dealloc(parg[0]);

		parg[15] = pool1.malloc();
		assert(parg[15] != nullptr);

		INFOPRINTCOLOR(GY_COLOR_CYAN, "THR_POOL_ALLOC test completed. sizeof elem = %lu\n", pool1.get_elem_fixed_size());
		INFOPRINTCOLOR(GY_COLOR_CYAN, "There should be an error message printed after this after 10 sec as the pool mallocs have not been freed. It can be ignored...\n");
	}

	{
		INFOPRINTCOLOR(GY_COLOR_GREEN, "Testing STACK_POOL_ALLOC  with pool allocs with header...\n");

		size_t			szarr[] {128, 512 };
		size_t			maxarr[] {128, 128 };

		POOL_ALLOC_ARRAY	poolarr(szarr, maxarr, GY_ARRAY_SIZE(szarr), true);
		STACK_POOL_ALLOC_32K	stackpool(&poolarr);
		
		const int		nallocs = 1024;
		char			**pallocarr = (char **)stackpool.safe_malloc(nallocs * sizeof(char *));

		for (int i = 0; i < nallocs; ++i) {
			pallocarr[i] = (char *)stackpool.safe_malloc(256);
		}	

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Stats after alloc : %s\n", stackpool.print_stats().get());

		for (int i = 0; i < nallocs; ++i) {
			STACK_POOL_ALLOC_32K::dealloc(pallocarr[i]);
		}	

		STACK_POOL_ALLOC_32K::dealloc(pallocarr);

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Stats after cleanup : %s\n\n", stackpool.print_stats().get());
	}

	{
		INFOPRINTCOLOR(GY_COLOR_GREEN, "Testing STACK_POOL_ALLOC without pool (heap allocs with header) ...\n");

		STACK_POOL_ALLOC_32K	stackpool;
		
		const int		nallocs = 1024;
		char			**pallocarr = (char **)stackpool.safe_malloc(nallocs * sizeof(char *));

		for (int i = 0; i < nallocs; ++i) {
			pallocarr[i] = (char *)stackpool.safe_malloc(256);
		}	

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Stats after alloc : %s\n", stackpool.print_stats().get());

		for (int i = 0; i < nallocs; ++i) {
			STACK_POOL_ALLOC_32K::dealloc(pallocarr[i]);
		}	

		STACK_POOL_ALLOC_32K::dealloc(pallocarr);

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Stats after cleanup : %s\n\n", stackpool.print_stats().get());
	}

	{
		INFOPRINTCOLOR(GY_COLOR_GREEN, "Testing STACK_POOL_ALLOC without pool (heap allocs without header) ...\n");

		/*HEAP_POOL_ALLOC		stackpool(32 * 1024);*/
		STACK_POOL_ALLOC_32K	stackpool;
		
		const int		nallocs = 1024;
		FREE_FPTR		allocarr_free, freearr_free;
		char			**pallocarr = (char **)stackpool.safe_malloc(nallocs * sizeof(char *), allocarr_free);
		FREE_FPTR		*pfreearr = (FREE_FPTR *)stackpool.safe_malloc(nallocs * sizeof(FREE_FPTR), freearr_free);

		for (int i = 0; i < nallocs; ++i) {
			pallocarr[i] = (char *)stackpool.safe_malloc(256, pfreearr[i]);
		}	

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Stats after alloc : %s\n", stackpool.print_stats().get());

		for (int i = 0; i < nallocs; ++i) {
			if (pfreearr[i]) {
				(*pfreearr[i])(pallocarr[i]);
			}	
		}	

		if (freearr_free) {
			(*freearr_free)(pfreearr);
		}	

		if (allocarr_free) {
			(*allocarr_free)(pallocarr);
		}	

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Stats after cleanup : %s\n\n", stackpool.print_stats().get());
	}

	static constexpr size_t		TMAX_ELEM = 4096, TMULTIPLIER = 1000;
	/*static constexpr size_t		TMAX_ELEM = 4096, TMULTIPLIER = 10;*/

	{
		IRPRINT("\n\n");
		INFOPRINTCOLOR(GY_COLOR_GREEN, "Now benchmarking single threaded gyeeta::POOL_ALLOC...\n");

		void			*parray[TMAX_ELEM];
		POOL_ALLOC		pool1(512, TMAX_ELEM);
		uint64_t		tmalloc = 0, tfree = 0;

		for (size_t j = 0; j < TMULTIPLIER; ++j) {
			uint64_t		ttime1 = get_nsec_clock(), ttime2 = 0, ttime3 = 0;

			for (size_t i = 0; i < TMAX_ELEM; ++i) {
				COMM_MSG_C	*pmsg;

				pmsg = (COMM_MSG_C *)pool1.malloc();

				pmsg->arg2_	= (uint64_t)pmsg;
				parray[i]	= pmsg;
			}

			ttime2 = get_nsec_clock();
			tmalloc += ttime2 - ttime1;

			for (size_t i = 0; i < TMAX_ELEM; ++i) {
				pool1.free(parray[i]);
			}

			ttime3 = get_nsec_clock();
			tfree += ttime3 - ttime2;
		}

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Total Single Threaded Pool Mallocs = %lu : Avg pool.malloc() execution time = %lu nsec : Avg pool.free() = %lu nsec\n\n", 
			TMAX_ELEM * TMULTIPLIER, tmalloc/(TMAX_ELEM * TMULTIPLIER), tfree/(TMAX_ELEM * TMULTIPLIER));
	}

	{
		IRPRINT("\n\n");
		INFOPRINTCOLOR(GY_COLOR_GREEN, "Now benchmarking single threaded gyeeta::THR_POOL_ALLOC...\n");

		void			*parray[TMAX_ELEM];
		THR_POOL_ALLOC		pool1(512, TMAX_ELEM, true);
		uint64_t		tmalloc = 0, tfree = 0;

		for (size_t j = 0; j < TMULTIPLIER; ++j) {
			uint64_t		ttime1 = get_nsec_clock(), ttime2 = 0, ttime3 = 0;

			for (size_t i = 0; i < TMAX_ELEM; ++i) {
				COMM_MSG_C	*pmsg;

				pmsg = (COMM_MSG_C *)pool1.malloc();

				pmsg->arg2_	= (uint64_t)pmsg;
				parray[i]	= pmsg;
			}

			ttime2 = get_nsec_clock();
			tmalloc += ttime2 - ttime1;

			for (size_t i = 0; i < TMAX_ELEM; ++i) {
				THR_POOL_ALLOC::dealloc(parray[i]);
			}

			ttime3 = get_nsec_clock();
			tfree += ttime3 - ttime2;
		}

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Total Single Threaded Pool Mallocs = %lu : Avg pool.malloc() execution time = %lu nsec : Avg pool.free() = %lu nsec\n\n", 
			TMAX_ELEM * TMULTIPLIER, tmalloc/(TMAX_ELEM * TMULTIPLIER), tfree/(TMAX_ELEM * TMULTIPLIER));
	}
	{
		IRPRINT("\n\n");
		INFOPRINTCOLOR(GY_COLOR_YELLOW, "Now benchmarking multi threaded gyeeta::POOL_ALLOC_ARRAY::malloc()...\n");

		size_t			szarr[] {128, 512, 1024, 2048};
		size_t			maxarr[] {TMAX_ELEM, TMAX_ELEM, TMAX_ELEM, TMAX_ELEM};

		POOL_ALLOC_ARRAY	poolarr(szarr, maxarr, GY_ARRAY_SIZE(szarr), true);

		MPMCQ_COMM		spsc(TMAX_ELEM);

		EXEC_TIME		prof1("THR_POOL_ALLOC malloc Benchmark", 1);

		GY_THREAD		pooltid("MPMCQ_COMM folly::MPMCQueue reader thread", mpmc_thread, &pooltid, &spsc, (void *)THR_POOL_ALLOC::dealloc);
		GY_THREAD		pooltid2("MPMCQ_COMM folly::MPMCQueue 2 reader thread", mpmc_thread, &pooltid, &spsc, (void *)THR_POOL_ALLOC::dealloc);
		GY_THREAD		pooltid3("MPMCQ_COMM folly::MPMCQueue 3 reader thread", mpmc_thread, &pooltid, &spsc, (void *)THR_POOL_ALLOC::dealloc);
		
		uint32_t		act_size;
		uint64_t		ttime1 = prof1.get_profile_time(), ttime2, tsubtime1, tsubtime2 = 0, tsubyield1, tsubyield2 = 0;

		for (size_t i = 0; i < TMAX_ELEM * TMULTIPLIER; ++i) {
			COMM_MSG_C	*pmsg;
			FREE_FPTR	free_fp;

			do {
				pmsg = (COMM_MSG_C *)poolarr.malloc(szarr[i % GY_ARRAY_SIZE(szarr)], act_size);
				if (!pmsg) {
					tsubyield1 = prof1.get_profile_time();

					pthread_yield();
					
					tsubyield2 += prof1.get_profile_time() - tsubyield1;
				}
			} while (!pmsg);

			pmsg->arg1_ 	= get_nsec_clock();
			pmsg->arg2_	= (uint64_t)pmsg;

			tsubtime1 = prof1.get_profile_time();

			spsc.blockingWrite(*pmsg);

			tsubtime2 += prof1.get_profile_time() - tsubtime1;

		}	

		ttime2 = prof1.get_profile_time();

		INFOPRINTCOLOR(GY_COLOR_YELLOW, "Total Pool Mallocs = %lu : Avg pool.malloc() execution time with yields = %lu nsec, without yields = %lu nsec\n\n", 
			TMAX_ELEM * TMULTIPLIER, (ttime2 - ttime1 - tsubtime2)/(TMAX_ELEM * TMULTIPLIER), (ttime2 - ttime1 - tsubtime2 - tsubyield2)/(TMAX_ELEM * TMULTIPLIER));

		INFOPRINTCOLOR(GY_COLOR_YELLOW, "Total Pool Mallocs = %lu : Avg pool.malloc() and thread signal execution time = %lu nsec\n\n", 
			TMAX_ELEM * TMULTIPLIER, (ttime2 - ttime1)/(TMAX_ELEM * TMULTIPLIER));

		COMM_MSG_C		tmsg;

		tmsg.arg1_ = get_nsec_clock();
		tmsg.arg2_ = 1;

		spsc.blockingWrite(tmsg);
		spsc.blockingWrite(tmsg);
		spsc.blockingWrite(tmsg);

	}

	{
		IRPRINT("\n\n");
		INFOPRINTCOLOR(GY_COLOR_BLUE, "Now benchmarking multi threaded gyeeta::THR_POOL_ALLOC::ordered_malloc(3) ...\n");

		std::vector<std::unique_ptr<THR_POOL_ALLOC>>	tpool;
		
		tpool.reserve(4);

		tpool.emplace_back(new THR_POOL_ALLOC(128, TMAX_ELEM, true));
		tpool.emplace_back(new THR_POOL_ALLOC(512, TMAX_ELEM, true));
		tpool.emplace_back(new THR_POOL_ALLOC(1024, TMAX_ELEM, true));
		tpool.emplace_back(new THR_POOL_ALLOC(2048, TMAX_ELEM, true));
		
		MPMCQ_COMM		spsc(TMAX_ELEM);

		EXEC_TIME		prof1("THR_POOL_ALLOC ordered_malloc Benchmark", 1);

		GY_THREAD		pooltid("MPMCQ_COMM folly::MPMCQueue reader thread", mpmc_thread, &pooltid, &spsc, (void *)THR_POOL_ALLOC::dealloc);
		GY_THREAD		pooltid2("MPMCQ_COMM folly::MPMCQueue 2 reader thread", mpmc_thread, &pooltid, &spsc, (void *)THR_POOL_ALLOC::dealloc);
		GY_THREAD		pooltid3("MPMCQ_COMM folly::MPMCQueue 3 reader thread", mpmc_thread, &pooltid, &spsc, (void *)THR_POOL_ALLOC::dealloc);

		uint64_t		ttime1 = prof1.get_profile_time(), ttime2, tsubtime1, tsubtime2 = 0;

		for (size_t i = 0; i < TMAX_ELEM * TMULTIPLIER; ++i) {
			COMM_MSG_C	*pmsg;

			do {
				pmsg = (COMM_MSG_C *)tpool[i % tpool.size()]->ordered_malloc(3 + i % 4);
				if (!pmsg) {
					pthread_yield();
				}
			} while (!pmsg);

			pmsg->arg1_ 	= get_nsec_clock();
			pmsg->arg2_	= (uint64_t)pmsg;

			tsubtime1 = prof1.get_profile_time();

			spsc.blockingWrite(*pmsg);

			tsubtime2 += prof1.get_profile_time() - tsubtime1;
		}	

		ttime2 = prof1.get_profile_time();

		INFOPRINTCOLOR(GY_COLOR_BLUE, "Total Pool Mallocs = %lu : Avg pool.ordered_malloc() execution time = %lu nsec\n\n", 
			TMAX_ELEM * TMULTIPLIER, (ttime2 - ttime1 - tsubtime2)/(TMAX_ELEM * TMULTIPLIER));

		INFOPRINTCOLOR(GY_COLOR_BLUE, "Total Pool Mallocs = %lu : Avg pool.ordered_malloc() and thread signal execution time = %lu nsec\n\n", 
			TMAX_ELEM * TMULTIPLIER, (ttime2 - ttime1)/(TMAX_ELEM * TMULTIPLIER));

		COMM_MSG_C		tmsg;

		tmsg.arg1_ = get_nsec_clock();
		tmsg.arg2_ = 1;

		spsc.blockingWrite(tmsg);
		spsc.blockingWrite(tmsg);
		spsc.blockingWrite(tmsg);

	}
{
		IRPRINT("\n\n");
		INFOPRINTCOLOR(GY_COLOR_YELLOW, "Now benchmarking multi threaded gyeeta::POOL_ALLOC_ARRAY::malloc()...\n");

		size_t			szarr[] {128, 512, 1024, 2048};
		size_t			maxarr[] {TMAX_ELEM, TMAX_ELEM, TMAX_ELEM, TMAX_ELEM};

		POOL_ALLOC_ARRAY	poolarr(szarr, maxarr, GY_ARRAY_SIZE(szarr), true);

		MPMCQ_COMM		spsc(TMAX_ELEM);

		EXEC_TIME		prof1("THR_POOL_ALLOC malloc Benchmark", 1);

		GY_THREAD		pooltid("MPMCQ_COMM folly::MPMCQueue reader thread", mpmc_thread, &pooltid, &spsc, (void *)THR_POOL_ALLOC::dealloc);
		GY_THREAD		pooltid2("MPMCQ_COMM folly::MPMCQueue 2 reader thread", mpmc_thread, &pooltid, &spsc, (void *)THR_POOL_ALLOC::dealloc);
		GY_THREAD		pooltid3("MPMCQ_COMM folly::MPMCQueue 3 reader thread", mpmc_thread, &pooltid, &spsc, (void *)THR_POOL_ALLOC::dealloc);
		
		uint32_t		act_size;
		uint64_t		ttime1 = prof1.get_profile_time(), ttime2, tsubtime1, tsubtime2 = 0, tsubyield1, tsubyield2 = 0;

		for (size_t i = 0; i < TMAX_ELEM * TMULTIPLIER; ++i) {
			COMM_MSG_C	*pmsg;
			FREE_FPTR	free_fp;

			do {
				pmsg = (COMM_MSG_C *)poolarr.malloc(szarr[i % GY_ARRAY_SIZE(szarr)], act_size);
				if (!pmsg) {
					tsubyield1 = prof1.get_profile_time();

					pthread_yield();
					
					tsubyield2 += prof1.get_profile_time() - tsubyield1;
				}
			} while (!pmsg);

			pmsg->arg1_ 	= get_nsec_clock();
			pmsg->arg2_	= (uint64_t)pmsg;

			tsubtime1 = prof1.get_profile_time();

			spsc.blockingWrite(*pmsg);

			tsubtime2 += prof1.get_profile_time() - tsubtime1;

		}	

		ttime2 = prof1.get_profile_time();

		INFOPRINTCOLOR(GY_COLOR_YELLOW, "Total Pool Mallocs = %lu : Avg pool.malloc() execution time with yields = %lu nsec, without yields = %lu nsec\n\n", 
			TMAX_ELEM * TMULTIPLIER, (ttime2 - ttime1 - tsubtime2)/(TMAX_ELEM * TMULTIPLIER), (ttime2 - ttime1 - tsubtime2 - tsubyield2)/(TMAX_ELEM * TMULTIPLIER));

		INFOPRINTCOLOR(GY_COLOR_YELLOW, "Total Pool Mallocs = %lu : Avg pool.malloc() and thread signal execution time = %lu nsec\n\n", 
			TMAX_ELEM * TMULTIPLIER, (ttime2 - ttime1)/(TMAX_ELEM * TMULTIPLIER));

		COMM_MSG_C		tmsg;

		tmsg.arg1_ = get_nsec_clock();
		tmsg.arg2_ = 1;

		spsc.blockingWrite(tmsg);
		spsc.blockingWrite(tmsg);
		spsc.blockingWrite(tmsg);

	}
	{
		IRPRINT("\n\n");
		INFOPRINTCOLOR(GY_COLOR_YELLOW, "Now testing multi threaded gyeeta::POOL_ALLOC_ARRAY::safe_malloc() with larger allocations...\n");

		size_t			szarr[] {128, 512, 1024, 2048};
		size_t			maxarr[] {TMAX_ELEM, TMAX_ELEM, TMAX_ELEM, TMAX_ELEM};

		POOL_ALLOC_ARRAY	poolarr(szarr, maxarr, GY_ARRAY_SIZE(szarr), true);

		MPMCQ_COMM		spsc(TMAX_ELEM);

		EXEC_TIME		prof1("THR_POOL_ALLOC malloc Benchmark", 1);

		GY_THREAD		pooltid("MPMCQ_COMM folly::MPMCQueue reader thread", mpmc_thread, &pooltid, &spsc, (void *)THR_POOL_ALLOC::dealloc);
		GY_THREAD		pooltid2("MPMCQ_COMM folly::MPMCQueue 2 reader thread", mpmc_thread, &pooltid, &spsc, (void *)THR_POOL_ALLOC::dealloc);
		GY_THREAD		pooltid3("MPMCQ_COMM folly::MPMCQueue 3 reader thread", mpmc_thread, &pooltid, &spsc, (void *)THR_POOL_ALLOC::dealloc);
		
		uint32_t		act_size;
		uint64_t		ttime1 = prof1.get_profile_time(), ttime2, tsubtime1, tsubtime2 = 0, tsubyield1, tsubyield2 = 0;

		for (size_t i = 0; i < TMAX_ELEM * 10; ++i) {
			COMM_MSG_C	*pmsg;
			FREE_FPTR	free_fp;

			do {
				/*pmsg = (COMM_MSG_C *)poolarr.safe_malloc(szarr[i % GY_ARRAY_SIZE(szarr)] + i % 1024, free_fp, act_size);*/
				pmsg = (COMM_MSG_C *)poolarr.safe_malloc(1024 + i % TMAX_ELEM, free_fp, act_size);
				if (!pmsg || free_fp == ::free) {
					tsubyield1 = prof1.get_profile_time();

					if (pmsg) {
						(*free_fp)(pmsg);
						pmsg = nullptr;
					}

					pthread_yield();
					
					tsubyield2 += prof1.get_profile_time() - tsubyield1;
				}
			} while (!pmsg);

			pmsg->arg1_ 	= get_nsec_clock();
			pmsg->arg2_	= (uint64_t)pmsg;
			pmsg->arg3_	= act_size;

			tsubtime1 = prof1.get_profile_time();

			spsc.blockingWrite(*pmsg);

			tsubtime2 += prof1.get_profile_time() - tsubtime1;

		}	

		ttime2 = prof1.get_profile_time();

		INFOPRINTCOLOR(GY_COLOR_YELLOW, "Total Pool Mallocs = %lu : Avg pool.malloc() execution time with yields = %lu nsec, without yields = %lu nsec\n\n", 
			TMAX_ELEM * TMULTIPLIER, (ttime2 - ttime1 - tsubtime2)/(TMAX_ELEM * TMULTIPLIER), (ttime2 - ttime1 - tsubtime2 - tsubyield2)/(TMAX_ELEM * TMULTIPLIER));

		INFOPRINTCOLOR(GY_COLOR_YELLOW, "Total Pool Mallocs = %lu : Avg pool.malloc() and thread signal execution time = %lu nsec\n\n", 
			TMAX_ELEM * TMULTIPLIER, (ttime2 - ttime1)/(TMAX_ELEM * TMULTIPLIER));

		COMM_MSG_C		tmsg;

		tmsg.arg1_ = get_nsec_clock();
		tmsg.arg2_ = 1;

		spsc.blockingWrite(tmsg);
		spsc.blockingWrite(tmsg);
		spsc.blockingWrite(tmsg);

	}
	{
		IRPRINT("\n\n");
		INFOPRINTCOLOR(GY_COLOR_YELLOW, "Now testing multi threaded gyeeta::POOL_ALLOC_ARRAY::safe_malloc() with ::malloc used as well ...\n");

		size_t			szarr[] {128, 512, 1024, 2048};
		size_t			maxarr[] {128, 128, 128, 128};

		POOL_ALLOC_ARRAY	poolarr(szarr, maxarr, GY_ARRAY_SIZE(szarr), true);

		MPMCQ_COMM		spsc(TMAX_ELEM);

		EXEC_TIME		prof1("THR_POOL_ALLOC malloc Benchmark", 1);

		GY_THREAD		pooltid("MPMCQ_COMM folly::MPMCQueue reader thread", mpmc_thread, &pooltid, &spsc, (void *)THR_POOL_ALLOC::dealloc);
		GY_THREAD		pooltid2("MPMCQ_COMM folly::MPMCQueue 2 reader thread", mpmc_thread, &pooltid, &spsc, (void *)THR_POOL_ALLOC::dealloc);
		GY_THREAD		pooltid3("MPMCQ_COMM folly::MPMCQueue 3 reader thread", mpmc_thread, &pooltid, &spsc, (void *)THR_POOL_ALLOC::dealloc);
		
		uint32_t		act_size;
		uint64_t		ttime1 = prof1.get_profile_time(), ttime2, tsubtime1, tsubtime2 = 0, tsubyield1, tsubyield2 = 0;

		for (size_t i = 0; i < TMAX_ELEM * TMULTIPLIER; ++i) {
			COMM_MSG_C	*pmsg;
			FREE_FPTR	free_fp;

			do {
				pmsg = (COMM_MSG_C *)poolarr.safe_malloc(1024 + i % TMAX_ELEM, free_fp, act_size, true /* try_other_pools */, true /* use_malloc_hdr */);
				if (!pmsg || free_fp == ::free) {
					tsubyield1 = prof1.get_profile_time();

					if (pmsg) {
						(*free_fp)(pmsg);
						pmsg = nullptr;
					}

					pthread_yield();
					
					tsubyield2 += prof1.get_profile_time() - tsubyield1;
				}
			} while (!pmsg);

			pmsg->arg1_ 	= get_nsec_clock();
			pmsg->arg2_	= (uint64_t)pmsg;
			pmsg->arg3_	= act_size;

			tsubtime1 = prof1.get_profile_time();

			spsc.blockingWrite(*pmsg);

			tsubtime2 += prof1.get_profile_time() - tsubtime1;

		}	

		ttime2 = prof1.get_profile_time();

		INFOPRINTCOLOR(GY_COLOR_YELLOW, "Total Pool Mallocs = %lu : Avg pool.malloc() execution time with yields = %lu nsec, without yields = %lu nsec\n\n", 
			TMAX_ELEM * TMULTIPLIER, (ttime2 - ttime1 - tsubtime2)/(TMAX_ELEM * TMULTIPLIER), (ttime2 - ttime1 - tsubtime2 - tsubyield2)/(TMAX_ELEM * TMULTIPLIER));

		INFOPRINTCOLOR(GY_COLOR_YELLOW, "Total Pool Mallocs = %lu : Avg pool.malloc() and thread signal execution time = %lu nsec\n\n", 
			TMAX_ELEM * TMULTIPLIER, (ttime2 - ttime1)/(TMAX_ELEM * TMULTIPLIER));

		COMM_MSG_C		tmsg;

		tmsg.arg1_ = get_nsec_clock();
		tmsg.arg2_ = 1;

		spsc.blockingWrite(tmsg);
		spsc.blockingWrite(tmsg);
		spsc.blockingWrite(tmsg);

	}
	{
		IRPRINT("\n\n");
		INFOPRINTCOLOR(GY_COLOR_GREEN, "Now benchmarking multi threaded malloc/free...\n");

		const size_t		sizearr[] {128, 512, 1024, 2048};

		MPMCQ_COMM		spsc(TMAX_ELEM);

		EXEC_TIME		prof1("malloc/free Benchmark", 2);

		GY_THREAD		pooltid("MPMCQ_COMM folly::MPMCQueue reader thread", mpmc_thread, &pooltid, &spsc, (void *)::free);
		GY_THREAD		pooltid2("MPMCQ_COMM folly::MPMCQueue 2 reader thread", mpmc_thread, &pooltid, &spsc, (void *)::free);
		GY_THREAD		pooltid3("MPMCQ_COMM folly::MPMCQueue 3 reader thread", mpmc_thread, &pooltid, &spsc, (void *)::free);

		uint64_t		ttime1 = prof1.get_profile_time(), ttime2, tsubtime1, tsubtime2 = 0;

		for (size_t i = 0; i < TMAX_ELEM * TMULTIPLIER; ++i) {
			COMM_MSG_C	*pmsg;

			do {
				pmsg = (COMM_MSG_C *)::malloc(sizearr[i % GY_ARRAY_SIZE(sizearr)]);
				if (!pmsg) {
					pthread_yield();
				}
			} while (!pmsg);

			pmsg->arg1_ 	= get_nsec_clock();
			pmsg->arg2_	= (uint64_t)pmsg;

			tsubtime1 = prof1.get_profile_time();

			spsc.blockingWrite(*pmsg);

			tsubtime2 += prof1.get_profile_time() - tsubtime1;
		}	

		ttime2 = prof1.get_profile_time();

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Total ::mallocs = %lu : Avg ::malloc() execution time = %lu nsec\n\n", 
			TMAX_ELEM * TMULTIPLIER, (ttime2 - ttime1 - tsubtime2)/(TMAX_ELEM * TMULTIPLIER));

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Total ::mallocs = %lu : Avg ::malloc() and thread signal execution time = %lu nsec\n\n", 
			TMAX_ELEM * TMULTIPLIER, (ttime2 - ttime1)/(TMAX_ELEM * TMULTIPLIER));


		COMM_MSG_C		tmsg;

		tmsg.arg1_ = get_nsec_clock();
		tmsg.arg2_ = 1;

		spsc.blockingWrite(tmsg);
		spsc.blockingWrite(tmsg);
		spsc.blockingWrite(tmsg);

	}
	return 0;
}	

