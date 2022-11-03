//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"
#include			"gy_pool_alloc.h"

namespace gyeeta {

/*
 * Fixed Single Slab Allocator with Pool Allocator/Heap as fallback. If pool is nullptr will use heap. Not Thread Safe.
 * Will use Pool/Heap memory once allocated size exhausted. If noheap_alloc is specified true, then will throw an exception
 * if allocation buffer exhausted and no Pool specified as allocating from heap is to be skipped.
 *
 * The extbuf constructor argument is usually a stack allocated single buffer but may be a heap alocated buffer as well.
 * 
 * For extbuf allocated objects, 0 overhead bytes per allocation if use_malloc_hdr == false, else 16 bytes overhead per alloc.
 * While for Pool allocated objects 32 bytes per alloc. For heap allocated objects if use_malloc_hdr == true, will use 16 bytes per alloc else 0.
 *
 * Allocated memory is aligned to 8 bytes. 
 *
 * For extbuf allocated objects, on destruction, extbuf memory is not released. IOW, the extbuf memory usage will keep
 * going up as new objects are allocated and no space is reclaimed on deleting those objects.
 *
 * This is not the case for heap or pool allocated objects.
 * 
 * Once the allocated extbuf space is used up, all further allocations will be either from pool or heap.
 * 
 * Usage : call <obj>.safe_malloc(...) for allocations and passed FREE_FPTR for deallocs. For the safe_malloc(size_t) 
 * method use the static method EXT_POOL_ALLOC::dealloc for deallocations unless noheap_alloc specified in which case
 * no dealloc ptr.
 */

class EXT_POOL_ALLOC
{
	char				* const extbuf_;
	const size_t				maxbytes_;	
	char					*ptr_			{nullptr};
	POOL_ALLOC_ARRAY			*pthrpoolarr_		{nullptr};
	uint32_t				nextallocs_		{0};
	bool					noheap_alloc_		{false};
	
	static inline uint32_t			ninvalid_frees_;

	static constexpr uintptr_t		EXT_ALLOC_MAGIC		{(uintptr_t)0xAC0ul};	// < 4 KB as magic for heap alloc

public:
	EXT_POOL_ALLOC(void *extbuf, size_t szbuf, POOL_ALLOC_ARRAY *pthrpoolarr = nullptr, bool noheap_alloc = false)
		: 
		extbuf_(static_cast<char *>(extbuf)), maxbytes_(szbuf > 128 ? szbuf - 8 : szbuf), ptr_(extbuf_), 
		pthrpoolarr_(pthrpoolarr), noheap_alloc_(noheap_alloc) 
	{
		if (!extbuf) {
			GY_THROW_EXPRESSION("Ext Pool : Null Pointer specified as buffer");
		}	
	}

	~EXT_POOL_ALLOC() noexcept
	{
		ptr_ 		= nullptr;
		pthrpoolarr_	= nullptr;
	}

	EXT_POOL_ALLOC(const EXT_POOL_ALLOC &) 			= delete;
	EXT_POOL_ALLOC & operator=(const EXT_POOL_ALLOC &) 	= delete;

	EXT_POOL_ALLOC(EXT_POOL_ALLOC &&) 			= delete;
	EXT_POOL_ALLOC & operator=(EXT_POOL_ALLOC &&) 		= delete;

	struct EXT_ELEM
	{
		EXT_POOL_ALLOC		*pthis_			{nullptr};
		uint32_t		pdata_lo_		{0};
		uint32_t		nbytes_ 		{0};

		EXT_ELEM() noexcept	= default;

		EXT_ELEM(void *pdata, EXT_POOL_ALLOC *pthis, uint32_t nbytes) noexcept
			: pthis_(pthis), pdata_lo_((uint32_t)(uintptr_t)pdata & ~0u), nbytes_(nbytes)
		{}	

		~EXT_ELEM() noexcept
		{
			pdata_lo_	= 0;
			nbytes_		= 0;
		}	
	};	

	void * safe_malloc(size_t n, FREE_FPTR & free_fp, uint32_t & act_size, bool use_malloc_hdr = false)
	{
		if (gy_unlikely(n == 0)) {
			return nullptr;
		}

		assert(pointer_in_buffer(ptr_) && "EXT_POOL_ALLOC : Use after destroy");

		const size_t 		naligned = align_up(n);

		if (use_malloc_hdr == false) {
			if (size_t(extbuf_ + maxbytes_ - ptr_) >= naligned) {

				char		*sptr = ptr_;

				ptr_ 		+= naligned;

				free_fp 	= nullptr;
				act_size 	= naligned;
		
				return sptr;
			}
		}
		else {
			if (size_t(extbuf_ + maxbytes_ - ptr_) >= naligned + sizeof(EXT_ELEM)) {

				char		* sptr = ptr_;
				ptr_ 		+= naligned + sizeof(EXT_ELEM);

				new (sptr) EXT_ELEM(sptr + sizeof(EXT_ELEM), this, naligned + sizeof(EXT_ELEM));

				free_fp 	= EXT_POOL_ALLOC::dealloc;
				act_size 	= naligned;
		
				return sptr + sizeof(EXT_ELEM);
			}
		}	

		nextallocs_++;

		if (pthrpoolarr_) {
			// Allocate from pool
			return pthrpoolarr_->safe_malloc(n, free_fp, act_size, true /* try_other_pools */, true /* use_malloc_hdr */);
		}
		else if (use_malloc_hdr && !noheap_alloc_) {
			// Allocate from heap with header

			char		* sptr = (char *)malloc_or_throw(n + sizeof(EXT_ELEM));

			new (sptr) EXT_ELEM(sptr + sizeof(EXT_ELEM), (EXT_POOL_ALLOC *)EXT_ALLOC_MAGIC, n + sizeof(EXT_ELEM));

			free_fp 	= EXT_POOL_ALLOC::dealloc;
			act_size 	= gy_malloc_usable_size(sptr, n + sizeof(EXT_ELEM)) - sizeof(EXT_ELEM);
	
			return sptr + sizeof(EXT_ELEM);
		}
		else if (!noheap_alloc_) {
			// Allocate from heap without header

			char		* sptr = (char *)malloc_or_throw(n);

			free_fp 	= ::free;
			act_size 	= gy_malloc_usable_size(sptr, n);
	
			return sptr;
		}	
		else {
			GY_THROW_EXPRESSION("Heap allocation needed for Ext Pool element as buffer full and no heap allowed");
		}	
	}	

	void * safe_malloc(size_t n, FREE_FPTR & free_fp, bool use_malloc_hdr = false)
	{
		uint32_t		act_size;

		return safe_malloc(n, free_fp, act_size, use_malloc_hdr);
	}	

	/*
	 * If noheap_alloc_ == false, use EXT_POOL_ALLOC<N>::dealloc for deallocations (along with extra malloc header per call), 
	 * else if noheap_alloc_ == true, then no extra malloc header overhead and nullptr as dealloc ptr 
	 */
	void * safe_malloc(size_t n)
	{
		FREE_FPTR		free_fp;
		uint32_t		act_size;

		return safe_malloc(n, free_fp, act_size, !noheap_alloc_ /* use_malloc_hdr */);
	}	

	static void * opt_safe_malloc(EXT_POOL_ALLOC *pextpool, size_t n, FREE_FPTR & free_fp, uint32_t & act_size)
	{
		if (pextpool) {
			return pextpool->safe_malloc(n, free_fp, act_size);
		}

		void			*palloc;

		palloc = malloc_or_throw(n);
		free_fp = ::free;
		act_size = gy_malloc_usable_size(palloc, n);

		return palloc;
	}	

	static void * opt_safe_malloc(EXT_POOL_ALLOC *pextpool, size_t n, FREE_FPTR & free_fp)
	{
		uint32_t		act_size;

		return opt_safe_malloc(pextpool, n, free_fp, act_size);
	}	

	static void dealloc(void * pbuf) noexcept
	{
		char 			*p = static_cast<char *>(pbuf);
		EXT_ELEM		*pelem = reinterpret_cast<EXT_ELEM *>(p - sizeof(EXT_ELEM));

		assert(0 == ((uint64_t)pelem & 7));

		EXT_POOL_ALLOC	*pthis = pelem->pthis_;

		// Check for double frees and corruption issues
		if (gy_likely(pelem->pdata_lo_ == ((uint32_t)(uintptr_t)pbuf & ~0u) && pthis && pelem->nbytes_ > 0)) {
			pelem->~EXT_ELEM();

			if (pthis != (void *)EXT_ALLOC_MAGIC) {
				pthis->dealloc_internal(pelem, pelem->nbytes_);
			}
			else {
				::free(pelem);
			}	
		}
		else if (true == THR_POOL_ALLOC::validate_buf(pbuf)) {
			THR_POOL_ALLOC::dealloc(pbuf);
		}	
		else {
			ninvalid_frees_++;
			assert(false);
		}	
	}	

	size_t ext_size() const noexcept 
	{
		return maxbytes_;
	}

	size_t ext_bytes_used() const noexcept 
	{
		return static_cast<size_t>(ptr_ - extbuf_);
	}
	
	size_t ext_bytes_left() const noexcept 
	{
		return extbuf_ + maxbytes_ - ptr_;
	}

	void reset_ext() noexcept 
	{
		ptr_ 		= extbuf_;
		nextallocs_	= 0;
	}

	void set_heap_allowed(bool alloc_from_heap) noexcept
	{
		noheap_alloc_	= alloc_from_heap;
	}	

	void dealloc_internal(void * pbuf, size_t n) noexcept
	{
		char 			*p = static_cast<char *>(pbuf);

		assert(pointer_in_buffer(ptr_) && "EXT_POOL_ALLOC : Use after destroy");

		if (pointer_in_buffer(p)) {
			n = align_up(n);

			if (p + n == ptr_) {
				ptr_ = p;
			}	
		}
	}	

	CHAR_BUF<256> print_stats() const noexcept
	{
		CHAR_BUF<256>		sbuf;

		snprintf(sbuf.get(), sizeof(sbuf), "Ext Pool of size %lu : # Bytes Used %lu # Bytes Left %lu # Pool/Heap Allocs %u # Invalid Frees %u ",
			ext_size(), ext_bytes_used(), ext_bytes_left(), nextallocs_, ninvalid_frees_);

		return sbuf;
	}	

private:
	// We always align to 8 bytes
	static size_t align_up(size_t n) noexcept
	{
		return (n + (8 - 1)) & ~(8 - 1);
	}

	bool pointer_in_buffer(const char * p) const noexcept
	{
		return extbuf_ <= p && p <= extbuf_ + maxbytes_;
	}

};	

template <size_t stacksz>
class STACK_POOL_ALLOC : public CHAR_BUF<stacksz>, public EXT_POOL_ALLOC
{
public:
	STACK_POOL_ALLOC(POOL_ALLOC_ARRAY *pthrpoolarr = nullptr) noexcept 
		: EXT_POOL_ALLOC(this->buf_, stacksz, pthrpoolarr) 
	{}

	EXT_POOL_ALLOC & get_ext_pool() noexcept
	{
		return *this;
	}	
};

class HEAP_POOL_ALLOC : public std::unique_ptr<char []>, public EXT_POOL_ALLOC
{
public :
	using UniqChar			= std::unique_ptr<char []>;

	HEAP_POOL_ALLOC(size_t heapsz, POOL_ALLOC_ARRAY *pthrpoolarr = nullptr)
		: UniqChar(new char[heapsz]), EXT_POOL_ALLOC(UniqChar::get(), heapsz, pthrpoolarr)
	{}	

	EXT_POOL_ALLOC & get_ext_pool() noexcept
	{
		return *this;
	}	

	const std::unique_ptr<char []> & get_uniq_ptr() const noexcept
	{
		return *this;
	}	
};

using STACK_POOL_ALLOC_64K 	= STACK_POOL_ALLOC<64 * 1024>;
using STACK_POOL_ALLOC_32K 	= STACK_POOL_ALLOC<32 * 1024>;
using STACK_POOL_ALLOC_8K 	= STACK_POOL_ALLOC<8 * 1024>;


} // namespace gyeeta

