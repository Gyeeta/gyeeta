//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"
#include			"gy_atomic.h"

namespace gyeeta {

/*
 * A simple Reference Counted Class used to reference count an inline / external block and free on 0 reference 
 * Use GY_REFCNT for multi thread safe reference counted objects and GY_LOCAL_REFCNT for single thread safe reference counted objects.
 *
 * Use allocate_refbuf to allocate an inline block along with the object as in make_shared
 * Use init_allocated_refblock to initialize already allocated block
 */
template <template <typename> class Atomic = std::atomic>
class REFCNT_INT
{
public :
	Atomic<size_t>		refcnt_			{1};
	void			*pguardptr_		{(uint8_t *)this + sizeof(*this)};
	FREE_FPTR		free_fp_		{nullptr};

	REFCNT_INT(FREE_FPTR free_fp) noexcept 
		: free_fp_(free_fp)
	{}	

	~REFCNT_INT() noexcept
	{
		pguardptr_	= nullptr;
	}	

	/*
	 * Allocate an inline Ref counted block (24 bytes overhead per allocation)
	 */
	static void * allocate_refbuf(size_t sz, size_t alignment = 0) 
	{
		size_t		newzsz = sz + sizeof(REFCNT_INT);
		uint8_t		*pdata;

		if (!alignment) {
			pdata = (uint8_t *)::malloc(newzsz);
		}
		else {
			pdata = (uint8_t *)::aligned_alloc(alignment, newzsz);

			if (!pdata && errno == EINVAL) {
				GY_THROW_SYS_EXCEPTION("Failed to allocate reference counted block");
			}	
		}
		if (!pdata) {
		        throw std::bad_alloc();
		}	
		
		new (pdata) REFCNT_INT(::free);

		return pdata + sizeof(REFCNT_INT);
	}	

	/*
	 * Initialze an externally allocated block as a Ref counted block and return the new Data pointer with reduced_sz set
	 */
	static void * init_allocated_refblock(void *palloc, size_t totalsz, FREE_FPTR free_fp, size_t & reduced_sz)
	{
		assert(palloc);

		if (gy_unlikely(totalsz <= sizeof(REFCNT_INT))) {
			GY_THROW_EXCEPTION("Allocated Block too small (size %lu) for a Reference Counted Block", totalsz);
		}	

		new (palloc) REFCNT_INT(free_fp);

		reduced_sz = totalsz - sizeof(REFCNT_INT);

		return (uint8_t *)palloc + sizeof(REFCNT_INT);
	}	

	// Return size specified + inline Control Block size 
	static constexpr size_t	get_ref_size(size_t initsz) noexcept
	{
		return initsz + sizeof(REFCNT_INT);
	}	

	// Returns new refcnt after adding inc for valid Refcounted pointers and -1 for others
	static ssize_t add_refcount(void *pdata, size_t inc = 1) noexcept
	{
		auto		pref = get_refblock(pdata);

		if (pref) {
			return inc + pref->refcnt_.fetch_add(inc, mo_acq_rel);
		}

		return -1;
	}	

	// Will decrment the refcount by 1 and if the count falls to 0 will free the pointer
	static void sub_refcount_free(void *pdata) noexcept
	{
		auto		pref = get_refblock(pdata);
		
		if (pref) {
			ssize_t		oldcnt;
		
			oldcnt = pref->refcnt_.fetch_sub(1, mo_acq_rel);	// acq_rel decrement

			assert(oldcnt > 0);

			if (oldcnt == 1) {
				pref->~REFCNT_INT();

				if  (pref->free_fp_) {
					(*pref->free_fp_)(pref);
				}
			}	
		}
	}	

	// Returns >= 0 for valid Refcounted pointers and -1 for others
	static ssize_t get_curr_refcnt(void *pdata) noexcept
	{
		auto		pref = get_refblock(pdata);

		if (pref) {
			return pref->refcnt_.load(mo_acquire);
		}

		return -1;
	}	

	static REFCNT_INT * get_refblock(void *pdata) noexcept
	{
		if (gy_likely(pdata)) {
			REFCNT_INT		*pref = reinterpret_cast<REFCNT_INT *>((char *)pdata - sizeof(REFCNT_INT));

			assert(pref->pguardptr_ == pdata);

			assert(0 == ((uint64_t)pref & 7));

			if (pref->pguardptr_ == pdata) {
				return pref;
			}	
		}	

		return nullptr;
	}	
};	

using GY_REFCNT 		= REFCNT_INT<std::atomic>;
using GY_LOCAL_REFCNT		= REFCNT_INT<gy_noatomic>;		// Single thread safe refcnt

template <typename RefType>
class REFCNT_FREE
{
public :
	void operator()(void * pdata) const noexcept
	{
		RefType::sub_refcount_free(pdata);
	}	
};


using UNIQ_REFCNT		= std::unique_ptr<void, REFCNT_FREE<GY_REFCNT>>;
using UNIQ_LOCAL_REFCNT		= std::unique_ptr<void, REFCNT_FREE<GY_LOCAL_REFCNT>>;	// Single thread safe

static UNIQ_REFCNT make_refcnt_uniq(size_t sz)
{
	return UNIQ_REFCNT(GY_REFCNT::allocate_refbuf(sz));
}	

static UNIQ_LOCAL_REFCNT make_local_refcnt_uniq(size_t sz)
{
	return UNIQ_LOCAL_REFCNT(GY_LOCAL_REFCNT::allocate_refbuf(sz));
}

/*
 * Base Class for use with boost::intrusive_ptr
 * Usage : 
 * class MyClass : public INT_REF_CNT<gy_noatomic> for non-atomic Intrusive Pointers (Single thread safe)
 * 	OR
 * class MyClass : public INT_REF_CNT<gy_atomic or std::atomic> for atomic Intrusive Pointers (Multi thread safe)
 *
 * Then use boost::intrusive_ptr<MyClass> directly
 */
template <template <typename> class Atomic = std::atomic>
class INT_REF_CNT
{
	mutable Atomic<uint64_t>	intr_cnt_	{0};

public :
	uint64_t intr_add_ref() const noexcept
	{
		return intr_cnt_.fetch_add(1, mo_relaxed) + 1;
	}	

	uint64_t intr_dec_ref() const noexcept
	{
		return intr_cnt_.fetch_sub(1, mo_relaxed) - 1;
	}	

	uint64_t intr_use_cnt() const noexcept
	{
		return intr_cnt_.load(mo_relaxed);
	}	

	static void intr_thread_fence(std::memory_order order) noexcept
	{
		if constexpr (!std::is_same_v<Atomic<int>, gy_noatomic<int>>) {
			std::atomic_thread_fence(order);
		}	
	}	
};	

template <typename T>
static void intrusive_ptr_add_ref(const T *p) noexcept
{
	if (p) {
		p->intr_add_ref();
	}	
}

template <typename T>
static void intrusive_ptr_release(const T *p) noexcept
{
	if (p && (0 == p->intr_dec_ref())) {

		T::intr_thread_fence(mo_acquire);

		try {
			delete p;
		}
		catch(...) {
		}	
	}
}

} // namespace gyeeta
