
#pragma				once

#include			"gy_common_inc.h"
#include			"gy_atomic.h"
#include			"gy_memory.h"

#pragma 			GCC diagnostic push
#pragma 			GCC diagnostic ignored "-Wsign-compare"

#include			"folly/MPMCQueue.h"

#pragma 			GCC diagnostic pop

#include			"boost/pool/pool.hpp"

#include 			<algorithm>

namespace gyeeta {

using GY_BOOST_POOL		= boost::pool<boost::default_user_allocator_malloc_free>;

/*
 * Fixed Element size and Fixed Max # Elements Memory Pool using boost::pool. 
 *
 * Not Thread safe...
 *
 * Returned memory is aligned to 8 bytes.
 */
class POOL_ALLOC : public GY_BOOST_POOL
{
public :	
	ssize_t				currsz_		{0};
	const ssize_t			max_elem_;
	const size_t			fixsz_;
	
	explicit POOL_ALLOC(size_t fix_reqsz, size_t max_elem = INT_MAX)
		: GY_BOOST_POOL(fix_reqsz), max_elem_(max_elem > 8 ? max_elem : 8), fixsz_(GY_BOOST_POOL::alloc_size())
	{}	

	void * malloc()
	{ 
		void		*pret;

		if (currsz_ < max_elem_) {
			pret = GY_BOOST_POOL::malloc();
			if (pret) {
				currsz_++;
				return pret;
			}	
		}	

		return nullptr;
	}

	void * ordered_malloc()
	{ 
		void		*pret;

		if (currsz_ < max_elem_) {
			pret = GY_BOOST_POOL::ordered_malloc();
			if (pret) {
				currsz_++;
				return pret;
			}	
		}	

		return nullptr;
	}

	// Allocate a contiguous section of n chunks for arrays
	void * ordered_malloc(size_t nchunks)
	{
		void		*pret;

		if (size_t(currsz_) + nchunks < size_t(max_elem_)) {
			pret = GY_BOOST_POOL::ordered_malloc(nchunks);
			if (pret) {
				currsz_ += nchunks;
				return pret;
			}	
		}	
		
		return nullptr;
	}	

	void free(void * const pdata)
	{
		if (pdata) {
			currsz_--;
			GY_BOOST_POOL::free(pdata);
		}	
	}	

	void ordered_free(void * const pdata)
	{
		if (pdata) {
			currsz_--;
			GY_BOOST_POOL::ordered_free(pdata);
		}	
	}

	// chunks must have been previously returned by ordered_malloc(n)
	void free(void * const pdata, const size_t nchunks)
	{ 
		if (pdata && nchunks) {
			if (currsz_ >= (ssize_t)nchunks) {
				currsz_ -= nchunks;
			}
			else {
				currsz_ = 0;
			}
			GY_BOOST_POOL::free(pdata, nchunks);
		}	
	}

	// chunks must have been previously returned by ordered_malloc(n)
	void ordered_free(void * const pdata, const size_t nchunks)
	{ 
		if (pdata && nchunks && nchunks < size_t(max_elem_)) {
			if (currsz_ >= (ssize_t)nchunks) {
				currsz_ -= nchunks;
			}
			else {
				currsz_ = 0;
			}
			GY_BOOST_POOL::ordered_free(pdata, nchunks);
		}	
	}

	// Releases all memory blocks, even if chunks are still allocated
	// Returns true if memory was actually deallocated
	bool purge_memory()
	{
		bool		bret;

		bret = GY_BOOST_POOL::purge_memory();
		if (bret == true) {
			currsz_ = 0;
		}	

		return bret;
	}	

	size_t get_bytes_used() const noexcept
	{
		return currsz_ * fixsz_;
	}

	size_t get_elems_used() const noexcept
	{
		return currsz_;
	}

	size_t get_total_elems() const noexcept
	{
		return max_elem_;
	}	

	ssize_t get_free_count() const noexcept
	{
		return max_elem_ - currsz_;
	}

	size_t get_elem_fixed_size() const noexcept
	{
		return fixsz_;
	}	

	static void dealloc_free(void *pdata, void *pthis) noexcept
	{
		if (pdata && pthis) {
			try {
				POOL_ALLOC		*pobj = static_cast<POOL_ALLOC *>(pthis);

				pobj->free(pdata);
			}
			catch(...) {

			}	
		}	
	}	

	static void dealloc_ordered_free(void *pdata, void *pthis) noexcept
	{
		if (pdata && pthis) {
			try {
				POOL_ALLOC		*pobj = static_cast<POOL_ALLOC *>(pthis);

				pobj->ordered_free(pdata);
			}
			catch(...) {

			}	
		}	
	}	
};	

/*
 * Allocations from a fixed thread with deallocations possible from multiple threads.
 * 
 * Recommended use as a per thread allocator object to allocate objects over 100 bytes as each allocation has a memory overhead
 * of approx 32 bytes per allocation (24 bytes malloc header and ~8 bytes pool element)
 *
 * Returned memory is aligned to 8 bytes.
 *
 * Memory frees from the dealloc threads must call the THR_POOL_ALLOC::dealloc(ptr) instead of calling this->free(ptr)
 * Memory frees from the allocator thread can use the this->free(ptr) directly for slightly better efficiency or call the
 * THR_POOL_ALLOC::dealloc(ptr). 
 *
 * NOTE : The allocator thread MUST call the set_alloc_thrid(tid) if the constructor arg is_caller_allocator_thread is specified false.
 * This needs to be called before any allocations start. Having multiple threads call this->malloc() will cause memory corruption.
 * 
 * If allocations are needed from multiple threads but max allocs may be from 1 thread, then the safe_malloc() method can be called
 * which will allocate memory from the pool for allocations called from the fixed thread and call ::malloc() for other thread allocs.
 *
 * Benchmarked to be at least 4 times faster than libc ::malloc() with 1 alloc and 2/3 other dealloc threads 
 * with avg pool allocs timed around 150 nsec compared to ~ 600 nsec for ::malloc() along with concurrent pool frees on other 
 * threads and avg pool frees from dealloc threads timed 7+ times faster around 130 nsec compared to ::free() around 1 usec
 * along with concurrent mallocs on another thread
 *
 */
class THR_POOL_ALLOC : public POOL_ALLOC
{
public :
	static constexpr uint32_t	TPOOL_MALLOC_SIGN	{0xFEED};

	class TPOOL_ELEM
	{
	public :
		void			*pdata_			{nullptr};
		THR_POOL_ALLOC		*pthis_			{nullptr};
		uint32_t		nchunks_		{0};
		bool			is_ordered_		{false};
		bool			is_alloced_		{false};

		TPOOL_ELEM() noexcept	= default;

		TPOOL_ELEM(void *pdata, THR_POOL_ALLOC *pthis, bool is_ordered = false, uint32_t nchunks = 1) noexcept
			: pdata_(pdata), pthis_(pthis), nchunks_(nchunks), is_ordered_(is_ordered), is_alloced_(true)
		{}	

		~TPOOL_ELEM() noexcept
		{
			pdata_		= nullptr;
			nchunks_	= 0;
			is_alloced_	= false;
		}	
	};	
	
	using MPSC_FREEQ		= folly::MPMCQueue<TPOOL_ELEM>;

	static constexpr int		MAX_WR_NO_CHK		{8};

	MPSC_FREEQ			freeq_;
	int				nwr_no_check_		{0};
	pthread_t			alloc_pthrid_		{0};

	uint64_t			alloc_cnt_		{0};
	uint64_t			dealloc_cnt_		{0};
	uint64_t			same_thr_deallocs_	{0};
	uint64_t			malloc_cnt_		{0};
	uint64_t			malloc_hdr_cnt_		{0};
	uint64_t			combined_allocs_	{0};
	uint64_t			thr_mismatch_cnt_	{0};

	static inline gy_atomic<uint64_t>	invalid_buf_cnt_	{0};
	static inline gy_atomic<uint64_t>	ext_malloc_free_cnt_	{0};

	/*
	 * fix_reqsz 			=> The fixed pool element size. Preferred to not have small sizes due to extra overhead of freeq_
	 *					The fix_reqsz is aligned to 8 bytes	
	 * max_elem			=> Max number of elements within the pool
	 * is_caller_allocator_thread	=> Is the caller of this constructor the thread which will be allocating the buffers
	 */
	THR_POOL_ALLOC(size_t fix_reqsz, size_t max_elem, bool is_caller_allocator_thread)
		: POOL_ALLOC(fix_reqsz + sizeof(TPOOL_ELEM), max_elem > 8 ? max_elem : 8), 
		freeq_(max_elem > 8 ? max_elem + 16 : 8 + 16), alloc_pthrid_(is_caller_allocator_thread ? pthread_self() : 0)
	{
		if (fix_reqsz > GY_UP_GB(1)) {
			GY_THROW_EXCEPTION("Max size of Pool Buffer elements limited to 1 GB");
		}	
	}	

	~THR_POOL_ALLOC()
	{
		purge_memory();

		CONDEXEC(
			INFOPRINTCOLOR(GY_COLOR_CYAN_ITALIC, "%s\n", print_stats(STRING_BUFFER<256>().get_str_buf()));
		);
	}	

	/*
	 * The allocator thread must call this function before allocations start if the allocator thread is
	 * separate from the constructor calling thread for faster deallocations if called using THR_POOL_ALLOC::dealloc()
	 * This should only be called before any allocations have started or else corruption will occur.
	 */
	void set_alloc_thrid(pthread_t tid = pthread_self()) noexcept
	{
		alloc_pthrid_	= tid;
	}

	/*
	 * Not thread safe : Must be called only from a single thread (alloc thread)
	 */
	void * malloc(bool ignore_frees = false)
	{ 
		char		*pret;
		
		check_freeq(ignore_frees);

		pret = static_cast<char *>(POOL_ALLOC::malloc());
		if (pret) {
			alloc_cnt_++;

			new (pret) TPOOL_ELEM(pret + sizeof(TPOOL_ELEM), this, false);

			return pret + sizeof(TPOOL_ELEM);
		}

		return nullptr;
	}

	/*
	 * Not thread safe : Must be called only from a single thread (alloc thread)
	 */
	void * ordered_malloc()
	{ 
		char		*pret;

		check_freeq();

		pret = static_cast<char *>(POOL_ALLOC::ordered_malloc());
		if (pret) {
			
			alloc_cnt_++;
		
			new (pret) TPOOL_ELEM(pret + sizeof(TPOOL_ELEM), this, true);

			return pret + sizeof(TPOOL_ELEM);
		}	

		return nullptr;
	}

	// Allocate a contiguous section of n chunks for arrays
	void * ordered_malloc(size_t nchunks)
	{
		char		*pret;

		check_freeq();

		pret = static_cast<char *>(POOL_ALLOC::ordered_malloc(nchunks));
		if (pret) {
		
			alloc_cnt_++;
	
			new (pret) TPOOL_ELEM(pret + sizeof(TPOOL_ELEM), this, true, nchunks);

			return pret + sizeof(TPOOL_ELEM);
		}	

		return nullptr;
	}	

	/*
	 * Not thread safe : Must be called only from a single thread (alloc thread)
	 */
	void free(const void * pdata)
	{
		if (pdata) {
			TPOOL_ELEM		*pelem = reinterpret_cast<TPOOL_ELEM *>((char *)pdata - sizeof(TPOOL_ELEM));

			assert(0 == ((uint64_t)pelem & 7));
		
			dealloc_cnt_++;
	
			pelem->~TPOOL_ELEM();

			POOL_ALLOC::free(pelem);
		}	
	}	

	/*
	 * Not thread safe : Must be called only from a single thread (alloc thread)
	 */
	void ordered_free(const void * pdata)
	{
		if (pdata) {
			TPOOL_ELEM		*pelem = reinterpret_cast<TPOOL_ELEM *>((char *)pdata - sizeof(TPOOL_ELEM));

			assert(0 == ((uint64_t)pelem & 7));

			dealloc_cnt_++;
	
			pelem->~TPOOL_ELEM();

			POOL_ALLOC::ordered_free(pelem);
		}	
	}

	// chunks must have been previously returned by ordered_malloc(n)
	void free(void * const chunks, const size_t nchunks)
	{ 
		if (chunks && nchunks) {
			TPOOL_ELEM		*pelem = reinterpret_cast<TPOOL_ELEM *>((char *)chunks - sizeof(TPOOL_ELEM));

			assert(0 == ((uint64_t)pelem & 7));
		
			dealloc_cnt_++;
	
			pelem->~TPOOL_ELEM();

			POOL_ALLOC::free(pelem, nchunks);
		}	
	}

	// chunks must have been previously returned by ordered_malloc(n)
	void ordered_free(void * const chunks, const size_t nchunks)
	{ 
		if (chunks && nchunks) {
			TPOOL_ELEM		*pelem = reinterpret_cast<TPOOL_ELEM *>((char *)chunks - sizeof(TPOOL_ELEM));

			assert(0 == ((uint64_t)pelem & 7));
	
			dealloc_cnt_++;

			pelem->~TPOOL_ELEM();

			POOL_ALLOC::ordered_free(pelem, nchunks);
		}	
	}

	/* 
	 * Thread safe allocation : Allocations from other threads than the alloc thread will use ::malloc()
	 * Will always return non-null ptr or throw an exception. 
	 * Specify use_malloc_hdr for generic deallocs (i.e. free_fp will not be considered but THR_POOL_ALLOC::dealloc() will be called instead).
	 */
	void * safe_malloc(FREE_FPTR & free_fp, bool use_malloc_hdr = false) 
	{
		void			*pmem;

		if (gy_unlikely(false == pthread_equal(alloc_pthrid_, pthread_self()))) {
		
			// Not atomic
			thr_mismatch_cnt_++;
			goto use_mal;
		}

		pmem = this->malloc();

		if (pmem) {
			free_fp = THR_POOL_ALLOC::dealloc;
			return pmem;
		}	

use_mal :
		pmem = malloc_or_throw(get_elem_fixed_size() + (use_malloc_hdr ? sizeof(TPOOL_ELEM) : 0));
		
		malloc_cnt_++;
		if (use_malloc_hdr) {
			malloc_hdr_cnt_++;
		}	

		if (use_malloc_hdr) {
			new (pmem) TPOOL_ELEM((uint8_t *)pmem + sizeof(TPOOL_ELEM), nullptr, false, TPOOL_MALLOC_SIGN);

			pmem = (uint8_t *)pmem + sizeof(TPOOL_ELEM);
			free_fp = THR_POOL_ALLOC::dealloc;
		}
		else {
			free_fp = ::free;
		}	
		return pmem;
	}

	/*
	 * Thread safe allocation : Allocations from other threads than the alloc thread will use ::malloc()
	 * Will always allocate the TPOOL_ELEM malloc header resulting in extra 24 bytes overhead per allocation even if ::malloc to be used.
	 * The dealloc function will always be THR_POOL_ALLOC::dealloc
	 */
	void * safe_malloc()
	{
		FREE_FPTR		free_fp;

		return safe_malloc(free_fp, true /* use_malloc_hdr */);
	}	

	/* 
	 * Thread safe allocation : Allocations from other threads than the alloc thread will use ::malloc()
	 * Will always return non-null ptr or throw an exception
	 * Specify use_malloc_hdr for generic deallocs (i.e. free_fp will not be considered but THR_POOL_ALLOC::dealloc() will be called instead).
	 * act_size can be used as the allocated size will be incremented to nchunks * fixed size - header size 
	 */
	void * safe_ordered_malloc(size_t nchunks, FREE_FPTR & free_fp, uint32_t & act_size, bool use_malloc_hdr = false) 
	{
		void			*pmem;

		if (gy_unlikely(nchunks == 0)) {
			GY_THROW_EXCEPTION("0 chunks ordered malloc requested");
		}
		else if (nchunks * get_elem_fixed_size() > GY_UP_GB(2)) {
			GY_THROW_EXCEPTION("Max Ordered Malloc total size limited to 2 GB");
		}	

		if (gy_unlikely(false == pthread_equal(alloc_pthrid_, pthread_self()))) {
		
			// Not atomic
			thr_mismatch_cnt_++;
			goto use_mal;
		}

		pmem = this->ordered_malloc(nchunks);

		if (pmem) {
			free_fp = THR_POOL_ALLOC::dealloc;
			act_size = this->get_elem_combined_size() * nchunks - sizeof(TPOOL_ELEM);

			return pmem;
		}	

use_mal :
		act_size	= nchunks * get_elem_fixed_size();

		pmem = malloc_or_throw(act_size + (use_malloc_hdr ? sizeof(TPOOL_ELEM) : 0));
		
		malloc_cnt_++;
		if (use_malloc_hdr) {
			malloc_hdr_cnt_++;
		}	

		if (use_malloc_hdr) {
			new (pmem) TPOOL_ELEM((uint8_t *)pmem + sizeof(TPOOL_ELEM), nullptr, false, TPOOL_MALLOC_SIGN);

			pmem = (uint8_t *)pmem + sizeof(TPOOL_ELEM);
			free_fp = THR_POOL_ALLOC::dealloc;
		}
		else {		
			free_fp = ::free;
		}

		return pmem;
	}

	/*
	 * Thread safe allocation : Allocations from other threads than the alloc thread will use ::malloc()
	 * Will always allocate the TPOOL_ELEM malloc header resulting in extra 24 bytes overhead per allocation even if ::malloc to be used.
	 * The dealloc function will always be THR_POOL_ALLOC::dealloc
	 */
	void * safe_ordered_malloc(size_t nchunks)
	{
		FREE_FPTR		free_fp;
		uint32_t		act_size;

		return safe_ordered_malloc(nchunks, free_fp, act_size, true /* use_malloc_hdr */);
	}	

	size_t get_elem_fixed_size() const noexcept
	{
		return POOL_ALLOC::get_elem_fixed_size() - sizeof(TPOOL_ELEM);
	}	

	/*
	 * Size including inline per elem book-keeping struct
	 * this->get_elem_fixed_size() + sizeof(TPOOL_ELEM)
	 */
	size_t get_elem_combined_size() const noexcept
	{
		return POOL_ALLOC::get_elem_fixed_size();
	}	

	// Destroy all memory except the freeq_ MPMC queue
	bool purge_memory()
	{
		int			niter = 0, nfrees;
		ssize_t			nused;

		nwr_no_check_ = 65535 + get_elems_used();
		
		/*
		 * We wait max 10 sec for any pending pool frees
		 */
		 
		do {
			nfrees = check_freeq();
			nused = get_elems_used();
			if (nused > 0) {
				if (nfrees < MAX_WR_NO_CHK) {
					niter++;
					gy_msecsleep(10);
				}
				continue;
			}
			break;
		} while (niter < 1000); 	

		nwr_no_check_ = 0;

		if (niter == 1000 && get_elems_used() > 0) {
			ERRORPRINTCOLOR(GY_COLOR_RED, "Waited for over 10 seconds for pool malloced element frees. Ignoring pending frees %lu now...\n", get_elems_used());
		}		

		return POOL_ALLOC::purge_memory();
	}	

	char * print_stats(STR_WR_BUF & strbuf) const noexcept
	{
		strbuf.appendfmt("Threaded Memory Pool of size %lu stats : ", get_elem_fixed_size());
		
		if (alloc_cnt_ + malloc_cnt_) {
			strbuf.appendfmt("Total Pool Allocs %lu, Pool Deallocs %lu, Writer Thread Deallocs %lu, "
					"External Mallocs %lu, External Mallocs with Headers %lu, Combined Buffer Counts %lu, Writer Thread Mismatches %lu ", 
					alloc_cnt_, dealloc_cnt_, same_thr_deallocs_, malloc_cnt_, malloc_hdr_cnt_, combined_allocs_, thr_mismatch_cnt_);	
		}

		auto		extmal = ext_malloc_free_cnt_.load(std::memory_order_relaxed);
		if (extmal) {
			strbuf.appendfmt("External Malloc based Deallocs across all Threaded Memory Pools = %lu ", extmal);
		}	

		auto		inv = invalid_buf_cnt_.load(std::memory_order_relaxed);
		if (inv) {
			strbuf.appendfmt("Invalid Buffer Deallocs across all Threaded Memory Pools = %lu ", inv);
		}	

		return strbuf.buffer();
	}	

	/*
	 * External threads other than the allocator thread must call this method to free up
	 *
	 * Must be passed only Pool allocated buffer and not external malloc'ed buffer except if use_malloc_hdr was set while allocating global heap mem. 
	 * No validation done on passed buffer and so if passed an external malloc allocated buffer may result in segfault
	 */
	static void dealloc(void *pdata) noexcept
	{
		if (gy_unlikely(nullptr == pdata)) {
			return;
		}	

		TPOOL_ELEM		*pelem = reinterpret_cast<TPOOL_ELEM *>((char *)pdata - sizeof(TPOOL_ELEM));

		assert(0 == ((uint64_t)pelem & 7));

		THR_POOL_ALLOC		*ppool = pelem->pthis_;
		
		// Check for double frees and corruption issues
		assert(pelem->pdata_ == pdata && pelem->is_alloced_ == true);
		
		if (gy_likely(pelem->pdata_ == pdata && ppool && pelem->is_alloced_ == true)) {

			try {
				if (false == pthread_equal(ppool->alloc_pthrid_, pthread_self())) {
					// Called from a separate thread
					ppool->freeq_.blockingWrite(*pelem);

					return;
				}	
				
				ppool->same_thr_deallocs_++;

				auto 		nchunks = pelem->nchunks_;
				auto		is_ordered = pelem->is_ordered_;

				if (gy_likely(nchunks < 2 && is_ordered == false)) {
					ppool->free(pelem->pdata_);
				}	
				else if (nchunks < 2 && is_ordered) {
					ppool->ordered_free(pelem->pdata_);
				}	
				else {
					ppool->ordered_free(pelem->pdata_, nchunks);
				}
			} 
			catch(...) {
			}	

			return;
		}	
		else if (pelem->pdata_ == pdata && ppool == nullptr && pelem->nchunks_ == TPOOL_MALLOC_SIGN) {
			pelem->~TPOOL_ELEM();
			
			ext_malloc_free_cnt_.fetch_add_relaxed(1, std::memory_order_relaxed);

			::free(pelem);
			return;
		}	

		invalid_buf_cnt_.fetch_add_relaxed(1, std::memory_order_relaxed);
	}	

	/*
	 * Must be passed only Pool allocated buffer and not external malloc'ed buffer unless use_malloc_hdr was set. 
	 * No validation done on passed buffer and so if passed an external malloc allocated buffer may result in segfault
	 */
	static void dealloc_arg(void *pdata, void * ignored) noexcept
	{
		dealloc(pdata);
	}	

	/*
	 * Must be passed only Pool allocated buffer and not malloc'ed buffer unless use_malloc_hdr was set
	 * No validation done on passed buffer and so if passed a malloc allocated buffer may result in segfault
	 */
	static bool validate_buf(void *pdata) noexcept
	{
		if (gy_unlikely(nullptr == pdata)) {
			return false;
		}	

		TPOOL_ELEM		*pelem = reinterpret_cast<TPOOL_ELEM *>((char *)pdata - sizeof(TPOOL_ELEM));

		assert(0 == ((uint64_t)pelem & 7));
		
		// Check for double frees and corruption issues
		return ((pelem->pdata_ == pdata && pelem->pthis_ && pelem->is_alloced_ == true) || 
			(pelem->pdata_ == pdata && pelem->pthis_ == nullptr && pelem->nchunks_ == TPOOL_MALLOC_SIGN));
	}

	/*
	 * Get stats such as Buffer size, Thread Pool and ordered chunks
	 * Returns true if valid pool buffer. 
	 *
	 * Must be passed only Pool allocated buffer and not malloc'ed buffer
	 * No validation done on passed buffer and so if passed a malloc allocated buffer may result in segfault
	 */
	static bool get_buffer_stats(void *pdata, uint32_t & size, THR_POOL_ALLOC ** ppthrpool, bool & is_ordered, uint32_t & nchunks) noexcept
	{
		if (gy_unlikely(nullptr == pdata)) {
			return false;
		}	

		TPOOL_ELEM		*pelem = reinterpret_cast<TPOOL_ELEM *>((char *)pdata - sizeof(TPOOL_ELEM));

		assert(0 == ((uint64_t)pelem & 7));
		
		// Check for double frees and corruption issues
		if (pelem->pdata_ == pdata && pelem->pthis_ && pelem->is_alloced_ == true) {
			size		= pelem->pthis_->get_elem_fixed_size();
			*ppthrpool	= pelem->pthis_;
			is_ordered	= pelem->is_ordered_;
			nchunks		= pelem->nchunks_;

			return true;
		}	

		return false;
	}

	/*
	 * Returns true if poldbuf and pnewbuf are contiguous with pnewbuf after poldbuf.
	 *
	 * combine_if_contiguous : Specify as true if you need to combine the 2 buffers book-keeping data which will only
	 * be done if they are contiguous.
	 * 
	 * combined_size : Returns the size after combining the 2 buffers. Will be set only if combine_if_contiguous is true.
	 *
	 * Must be passed only Pool allocated buffers and not malloc'ed buffer
	 * No validation done on passed buffer and so if passed a malloc allocated buffer may result in segfault
	 */
	static bool bufs_contiguous(void *poldbuf, void *pnewbuf, bool combine_if_contiguous, size_t & combined_size) noexcept
	{
		uint32_t 		size1, size2;
		THR_POOL_ALLOC 		*pthrpool1, *pthrpool2;
		bool 			is_ordered1, is_ordered2, bret;
		uint32_t 		nchunks1, nchunks2;
		
		bret = get_buffer_stats(poldbuf, size1, &pthrpool1, is_ordered1, nchunks1);
		if (bret == true) {
			bret = get_buffer_stats(pnewbuf, size2, &pthrpool2, is_ordered2, nchunks2);
			
			if (bret && (pthrpool1 == pthrpool2) && 
				((uint8_t *)poldbuf - sizeof(TPOOL_ELEM) + nchunks1 * pthrpool1->get_elem_combined_size() == (uint8_t *)pnewbuf - sizeof(TPOOL_ELEM))) {

				if (combine_if_contiguous) {
					TPOOL_ELEM		*pelem1 = reinterpret_cast<TPOOL_ELEM *>((char *)poldbuf - sizeof(TPOOL_ELEM));
					TPOOL_ELEM		*pelem2 = reinterpret_cast<TPOOL_ELEM *>((char *)pnewbuf - sizeof(TPOOL_ELEM));

					pelem1->nchunks_ 	+= nchunks2;	
					pelem1->is_ordered_	= true;

					combined_size 		= pelem1->nchunks_ * pthrpool1->get_elem_combined_size() - sizeof(TPOOL_ELEM);

					// Reset pnewbuf header so that it cannot be deallocated
					pelem2->pdata_ 		= nullptr;

					
					pthrpool1->combined_allocs_++;
				}

				return true;
			}	
		}	

		return false;
	}	

private :
	int check_freeq(bool ignore_frees = false)
	{
		int		nwr = ++nwr_no_check_, nfrees = 0;

		if ((unsigned)nwr >= (unsigned)MAX_WR_NO_CHK) {
			if (ignore_frees && ((unsigned)nwr < POOL_ALLOC::get_total_elems() >> 1)) {
				return nfrees;
			}
			
			bool		bret;
			TPOOL_ELEM	elem;
			
			do {
				bret = freeq_.read(elem);
				if (bret) {
					assert(elem.pthis_ == this);
					assert(elem.pdata_);

					nfrees++;

					if (gy_likely(elem.nchunks_ < 2 && elem.is_ordered_ == false)) {
						this->free(elem.pdata_);
					}	
					else if (elem.nchunks_ < 2 && elem.is_ordered_) {
						ordered_free(elem.pdata_);
					}	
					else {
						assert(elem.nchunks_ < POOL_ALLOC::get_total_elems());

						ordered_free(elem.pdata_, elem.nchunks_);
					}	
				}	
			} while (bret && nfrees < MAX_WR_NO_CHK);

			nwr_no_check_ -= nfrees;
		}

		return nfrees;
	}	
};	

template <typename T>
class TPOOL_DEALLOC
{
public :
	void operator()(T * pdata) const noexcept(std::is_nothrow_destructible<T>::value)
	{
		deleter(pdata);
	}	

	void operator()(T * pdata, void *arg) const noexcept(std::is_nothrow_destructible<T>::value)
	{
		if (gy_unlikely(pdata == nullptr)) {
			return;
		}

		pdata->~T();
		THR_POOL_ALLOC::dealloc_arg(pdata, arg);
	}	

	static void deleter(T *pdata) noexcept(std::is_nothrow_destructible<T>::value)
	{
		if (gy_unlikely(pdata == nullptr)) {
			return;
		}

		pdata->~T();
		THR_POOL_ALLOC::dealloc(pdata);
	}	
};	

/*
 * User specified Bucketed Array of Threaded Allocator pools.
 * Single Threaded Allocator, Multi Threaded Deallocator array of memory pools. See comments for THR_POOL_ALLOC above.
 */
class POOL_ALLOC_ARRAY
{
	std::vector<std::unique_ptr<THR_POOL_ALLOC>>	vpool_;
	std::vector<size_t>				size_vec_;
	pthread_t					alloc_pthrid_		{0};	
	uint32_t					max_elem_size_		{0};
	THR_POOL_ALLOC					*pmaxsz_pool_		{nullptr};
	int						last_free_cnt_		{0};
	int						last_malloc_cnt_	{0};
	
	uint64_t					malloc_cnt_		{0};
	uint64_t					higher_pool_allocs_	{0};
	uint64_t					chunked_allocs_		{0};
	uint64_t					thr_mismatch_cnt_	{0};

public :
	POOL_ALLOC_ARRAY() 				= default;

	/*
	 * size_array			=> Array of max size of each bucket
	 * max_elem_array		=> Max Elements to allocate for each bucket. 
	 * narray_elem			=> Number of elements in size_array and max_elem_array : Both arrays must be of same size
	 * is_caller_allocator_thread	=> Is the constructor caller pthread the same thread which will allocate memory 
	 */
	POOL_ALLOC_ARRAY(const size_t *size_array, const size_t *max_elem_array, const uint32_t narray_elem, bool is_caller_allocator_thread)
	{
		pool_alloc(size_array, max_elem_array, narray_elem, is_caller_allocator_thread);
	}	

	~POOL_ALLOC_ARRAY() 
	{
		CONDEXEC(
			INFOPRINTCOLOR(GY_COLOR_CYAN_ITALIC, "%s\n", print_stats(STRING_BUFFER<1024>().get_str_buf(), false));
		);
	}

	void pool_alloc(const size_t *size_array, const size_t *max_elem_array, const uint32_t narray_elem, bool is_caller_allocator_thread)
	{
		assert(size_array && max_elem_array && narray_elem);

		if (size_vec_.size()) {
			GY_THROW_EXCEPTION("Pool array allocation for already allocated pool");
		}	
		
		std::vector<std::pair<size_t, size_t>>	tszmax;

		size_vec_.reserve(narray_elem);
		tszmax.reserve(narray_elem);

		for (uint32_t i = 0; i < narray_elem; ++i) {
			if (size_array[i] > GY_UP_GB(1)) {
				GY_THROW_EXCEPTION("Max Pool Memory size of buffers is limited to 1 GB");
			}	

			tszmax.emplace_back(std::pair(size_array[i], max_elem_array[i]));
		}	

		std::sort(tszmax.begin(), tszmax.end(), 
			[](std::pair<size_t, size_t> a, std::pair<size_t, size_t> b)
			{
				return a.first < b.first;
			}
		);	
	
		for (uint32_t i = 0; i < narray_elem; ++i) {
			vpool_.emplace_back(std::make_unique<THR_POOL_ALLOC>(tszmax[i].first, tszmax[i].second, is_caller_allocator_thread));

			size_vec_.emplace_back(tszmax[i].first);
		}

		max_elem_size_ 	= tszmax[narray_elem - 1].first;
		pmaxsz_pool_	= vpool_[narray_elem - 1].get();

		if (is_caller_allocator_thread) {
			alloc_pthrid_ = pthread_self();
		}	
	}	
	
	void set_alloc_thrid(pthread_t tid = pthread_self()) noexcept
	{
		for (const auto & it : vpool_) {
			it->set_alloc_thrid(tid);
		}	

		alloc_pthrid_ = tid;
	}

	/*
	 * Allocate a single buffer from the set of pools configured. If no free buffers available, use the libc malloc
	 * If libc malloc fails will throw an exception. 
	 * Also checks if the safe_malloc() is called from the same thread as the set_alloc_thrid() or if is_caller_allocator_thread. 
	 * Else uses malloc() directly...
	 *
	 * Will always return non-null ptr or throw an exception
	 * Specify use_malloc_hdr for generic deallocs (i.e. free_fp will not be considered but THR_POOL_ALLOC::dealloc() will be called instead).
	 */
	void * safe_malloc(const uint32_t sz, FREE_FPTR & free_fp, uint32_t & act_size, bool try_other_pools = true, bool use_malloc_hdr = false) 
	{
		void		*pmem;

		if (gy_unlikely(sz == 0)) {
			GY_THROW_EXCEPTION("0 size malloc requested");
		}
		else if (gy_unlikely(sz > GY_UP_GB(2))) {
			GY_THROW_EXCEPTION("Over 2 GB size malloc requested : Max limited to 2 GB");
		}	

		if (0 == size_vec_.size()) {
			goto use_mal;
		}	

		if (false == pthread_equal(alloc_pthrid_, pthread_self())) {
			// Not atomic
			thr_mismatch_cnt_++;		
			goto use_mal;
		}

		if (true) {
			uint32_t	indexid;
			auto		ptpool = get_pool_from_sz(sz, indexid);

			if (ptpool) {
again1 :			
				pmem = ptpool->malloc();
				if (pmem) {
					act_size = ptpool->get_elem_fixed_size();
					free_fp = THR_POOL_ALLOC::dealloc;

					if (ptpool == pmaxsz_pool_) {
						last_free_cnt_ 		= ptpool->get_free_count();
						last_malloc_cnt_	= 0;
					}	
					return pmem;
				}	
				else if (try_other_pools && indexid + 1 < size_vec_.size() && size_vec_[indexid + 1] <= size_vec_[indexid] * 16) {

					// Check the next higher pool for at least 64 free elems
					ptpool = vpool_[indexid + 1].get();

					if (ptpool->get_free_count() > 64) {
				
						higher_pool_allocs_++;

						try_other_pools = false;
						goto again1;				
					}	
				}	
			}	
			else if (try_other_pools) {
				/*
				 * Try using an array of largest elem blocks
				 */

				int		nchunks = gy_div_round_up(sz, max_elem_size_);

				if (nchunks < 512 && last_free_cnt_ > nchunks + 16) {
					ptpool			= pmaxsz_pool_;
					last_free_cnt_ 		= ptpool->get_free_count();
					last_malloc_cnt_	= 0;

					if (last_free_cnt_ > nchunks + 16) {
						pmem 	= ptpool->ordered_malloc(nchunks);
						if (pmem) {
							
							chunked_allocs_++;

							last_free_cnt_ -= nchunks;

							act_size = ptpool->get_elem_combined_size() * nchunks - sizeof(THR_POOL_ALLOC::TPOOL_ELEM);
							free_fp = THR_POOL_ALLOC::dealloc;
							return pmem;
						}
					}
				}	
				else {
					if (++last_malloc_cnt_ > 32) {
						last_malloc_cnt_	= 0;
						last_free_cnt_ 		= pmaxsz_pool_->get_free_count();
					}	
				}	
			}	
		}
		
use_mal :
	
		malloc_cnt_++;

		pmem = malloc_or_throw(sz + (use_malloc_hdr ? sizeof(THR_POOL_ALLOC::TPOOL_ELEM) : 0));
	
		if (!use_malloc_hdr) {
			act_size	= gy_malloc_usable_size(pmem, sz);
		}
		else {
			act_size	= gy_malloc_usable_size(pmem, sz + sizeof(THR_POOL_ALLOC::TPOOL_ELEM)) - sizeof(THR_POOL_ALLOC::TPOOL_ELEM);
		}	

		if (use_malloc_hdr) {
			new (pmem) THR_POOL_ALLOC::TPOOL_ELEM((uint8_t *)pmem + sizeof(THR_POOL_ALLOC::TPOOL_ELEM), nullptr, false, THR_POOL_ALLOC::TPOOL_MALLOC_SIGN);

			pmem = (uint8_t *)pmem + sizeof(THR_POOL_ALLOC::TPOOL_ELEM);
			free_fp = THR_POOL_ALLOC::dealloc;

			return pmem;
		}
		
		free_fp 	= ::free;
		return pmem;
	}

	void * safe_malloc(const uint32_t sz, FREE_FPTR & free_fp) 
	{
		uint32_t		act_size;

		return safe_malloc(sz, free_fp, act_size);
	}
	
	// Allocate from pool if valid pool or else from heap
	static void * opt_safe_malloc(POOL_ALLOC_ARRAY *ppool, const uint32_t sz, FREE_FPTR & free_fp, uint32_t & act_size, bool try_other_pools = true) 
	{
		if (ppool) {
			return ppool->safe_malloc(sz, free_fp, act_size, try_other_pools);
		}

		void			*palloc;

		palloc = malloc_or_throw(sz);
		free_fp = ::free;
		act_size = gy_malloc_usable_size(palloc, sz);

		return palloc;
	}	

	/*
	 * Allocate 1 or more ordered buffers from the set of pools configured. If no free buffers available, use the libc malloc
	 * If libc malloc fails will throw an exception.
	 * Also checks if called from the same thread as the set_alloc_thrid() or if is_caller_allocator_thread. 
	 *
	 * pporderedpool can be used if further contiguous allocations may be needed
	 *
	 * Will always return non-null ptr or throw an exception
	 * Specify use_malloc_hdr for generic deallocs (i.e. free_fp will not be considered but THR_POOL_ALLOC::dealloc() will be called instead).
	 */
	void * safe_ordered_malloc(uint32_t sz, uint32_t nchunks, FREE_FPTR & free_fp, uint32_t & act_size, THR_POOL_ALLOC **pporderedpool = nullptr, bool use_malloc_hdr = false) 
	{
		const size_t		reqsz = sz * nchunks;
		void			*pmem;
		THR_POOL_ALLOC		*ptpool = nullptr;
		bool			is_chunked = false;

		if (gy_unlikely(reqsz == 0)) {
			GY_THROW_EXCEPTION("0 size ordered malloc requested");
		}
		else if (gy_unlikely(sz > GY_UP_GB(2))) {
			GY_THROW_EXCEPTION("Over 2 GB size ordered malloc requested : Max limited to 2 GB");
		}	

		if (0 == size_vec_.size()) {
			goto use_mal;
		}	

		if (false == pthread_equal(alloc_pthrid_, pthread_self())) {
			// Not atomic
			thr_mismatch_cnt_++;		
			goto use_mal;
		}

		if (sz > max_elem_size_) {
			nchunks 	+= gy_div_round_up(sz, max_elem_size_);	
			sz 		= max_elem_size_;
			ptpool 		= pmaxsz_pool_;
			is_chunked	= true;
		}
		else {
			ptpool = get_pool_from_sz(sz);
		}	

		pmem = ptpool->ordered_malloc(nchunks);

		if (pmem) {

		
			if (is_chunked) chunked_allocs_++;	

			if (pporderedpool) {
				*pporderedpool = ptpool;
			}

			act_size = ptpool->get_elem_combined_size() * nchunks - sizeof(THR_POOL_ALLOC::TPOOL_ELEM);
			free_fp = THR_POOL_ALLOC::dealloc;

			return pmem;
		}

use_mal :
	
		malloc_cnt_++;

		act_size = reqsz;

		pmem = malloc_or_throw(reqsz + (use_malloc_hdr ? sizeof(THR_POOL_ALLOC::TPOOL_ELEM) : 0));
	
		if (pporderedpool) {
			*pporderedpool = nullptr;
		}

		if (use_malloc_hdr) {
			new (pmem) THR_POOL_ALLOC::TPOOL_ELEM((uint8_t *)pmem + sizeof(THR_POOL_ALLOC::TPOOL_ELEM), nullptr, false, THR_POOL_ALLOC::TPOOL_MALLOC_SIGN);

			pmem = (uint8_t *)pmem + sizeof(THR_POOL_ALLOC::TPOOL_ELEM);
			free_fp = THR_POOL_ALLOC::dealloc;

			return pmem;
		}

		free_fp 	= ::free;
		return pmem;
	}

	void * malloc(const uint32_t sz, uint32_t & act_size) const
	{ 
		auto		ptpool = get_pool_from_sz(sz);

		if (ptpool) {
			act_size = ptpool->get_elem_fixed_size();
			return ptpool->malloc();
		}	

		return nullptr;
	}

	void * ordered_malloc(const uint32_t sz, uint32_t & act_size) const
	{ 
		auto		ptpool = get_pool_from_sz(sz);

		if (ptpool) {
			act_size = ptpool->get_elem_fixed_size();
			return ptpool->ordered_malloc();
		}	

		return nullptr;
	}

	/*
	 * Allocate a contiguous section of n chunks for arrays. Returns the pool pointer in pporderedpool so that
	 * if further allocations needed, users can directly use that pool for further ordered malloc to maintain
	 * contiguousness...
	 */
	void * ordered_malloc(const uint32_t sz, const uint32_t nchunks, uint32_t & act_size, THR_POOL_ALLOC ** pporderedpool = nullptr) const
	{
		auto		ptpool = get_pool_from_sz(sz);

		if (ptpool) {
			if (pporderedpool) {
				*pporderedpool = ptpool;
			}

			act_size = ptpool->get_elem_combined_size() * nchunks - sizeof(THR_POOL_ALLOC::TPOOL_ELEM);

			return ptpool->ordered_malloc(nchunks);
		}	

		return nullptr;
	}	
	
	THR_POOL_ALLOC * get_pool_from_sz(uint32_t sz_malloc) const noexcept
	{
		const size_t		n = size_vec_.size();

		for (uint32_t i = 0; i < n; ++i) {
			if (size_vec_[i] >= sz_malloc) {
				return vpool_[i].get();
			}	
		}	
		
		return nullptr;
	}	

	THR_POOL_ALLOC * get_pool_from_sz(uint32_t sz_malloc, uint32_t & indexid) const noexcept
	{
		const size_t		n = size_vec_.size();

		for (uint32_t i = 0; i < n; ++i) {
			if (size_vec_[i] >= sz_malloc) {
				indexid = i;
				return vpool_[i].get();
			}	
		}	
		
		return nullptr;
	}	


	THR_POOL_ALLOC * get_pool(uint32_t poolid) const noexcept
	{
		if (poolid < size_vec_.size()) {
			return vpool_[poolid].get();
		}	
		
		return nullptr;
	}	

	static void dealloc(void *pdata) noexcept
	{
		return THR_POOL_ALLOC::dealloc(pdata);
	}	

	static bool validate_buf(void *pdata) noexcept
	{
		return THR_POOL_ALLOC::validate_buf(pdata);
	}

	size_t get_max_size() const noexcept
	{
		return max_elem_size_;
	}	

	size_t get_min_size() const noexcept
	{
		return size_vec_[0];
	}

	size_t get_bytes_used() const noexcept
	{
		size_t		nused = 0;

		for (const auto & it : vpool_) {
			nused += it->get_bytes_used();
		}	

		return nused;
	}

	size_t get_elems_used() const noexcept
	{
		size_t		nused = 0;

		for (const auto & it : vpool_) {
			nused += it->get_elems_used();
		}	

		return nused;
	}

	char * print_stats(STR_WR_BUF & strbuf, bool print_individual = true, const char * pool_ident_str = "Threaded Memory Pool Array") const noexcept
	{
		strbuf.appendfmt("%s Stats : ", pool_ident_str);

		if (print_individual) {
			strbuf.appendconst("Individual Pool Stats Follow :");

			for (const auto & it : vpool_) {
				strbuf.appendconst("\n\t\t");
				it->print_stats(strbuf);
			}
		}

	
		strbuf.appendfmt("\n\t\tCumulative Stats : Total External Mallocs %lu, Higher Pool Allocs %lu, Combined Chunked Counts %lu, Writer Thread Mismatches %lu ", 
			malloc_cnt_, higher_pool_allocs_, chunked_allocs_, thr_mismatch_cnt_);	

		return strbuf.buffer();
	}	

};	

} // namespace gyeeta	

