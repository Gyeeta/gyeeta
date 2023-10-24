//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma			once

#include 		"gy_common_inc.h"
#include 		"gy_file_api.h"
#include		"gy_pool_alloc.h"
#include		"gy_json_field_maps.h"
#include 		"jhash.h"
#include 		"gy_memory.h"

#include		<bitset>

#include 		<sys/mount.h>
#include 		<sys/capability.h>

#include		<boost/logic/tribool.hpp>


using boost::logic::tribool;
using boost::logic::indeterminate;

namespace gyeeta {

#ifndef 			TASK_COMM_LEN
#define 			TASK_COMM_LEN 				16
#endif

static constexpr int		MAX_CONTAINER_NAME_LEN 			{256};

static constexpr int		CPU_SATURATION_PERCENT			{80};
static constexpr int		CPU_LOW_USE_PERCENT			{30};
static constexpr int		CPU_IOWAIT_LOW_PERCENT			{10};
static constexpr int		CPU_IDLE_PERCENT			{10};

static constexpr int		MEM_RSS_SATURATION_PCT			{80};
static constexpr int		MEM_RSS_LOW_USE_PCT			{30};
static constexpr int		MEM_COMMIT_SATURATION_PCT		{95};

static constexpr int		MAX_PROCESSOR_CORES 			{512};			// Max CPU Threads : Revisit once we have a successor to 2x Epyc 7742 
static constexpr int		MAX_PROCESSOR_SOCKETS 			{64};			// Max NUMA nodes we currently support

using CPU_CORES_BITSET		= std::bitset<MAX_PROCESSOR_CORES>;
using MEM_NODE_BITSET		= std::bitset<MAX_PROCESSOR_SOCKETS>;

enum CB_STATE_E : uint8_t
{
	STATE_CB_UNINIT		= 0,
	STATE_CB_SENT		= 1,
	STATE_CB_RCVD		= 2,
};

enum class DirPacket : uint8_t
{
	DirUnknown		= 0,

	DirInbound		= 1,	/* Inbound to a Service i.e. From Client to Server */
	DirOutbound		= 2,	/* Outbound : From Server to Client */
};	


template <typename T>
int set_bitset_from_buffer(T &bset, const char *buf, size_t buflen) noexcept
{
	try {
		/*
		 * Input string is in following format : <Range1>,<Range2>... where Range is in format <Num> or <Num1-Num2> with nospace allowed 
		 * e.g. "0,2-4,6-8,10,31,60"
		 */
		const char		*pstart = buf, *pend = buf + buflen, *ptmp = pstart;
		char			*pnxt;
		uint64_t		ulval = 0, ulstart = 0;
		int			ret;
		bool			isrange = false, bret;
		constexpr size_t	maxbits = bset.size();
			
		bset.reset();

		do {
			pnxt = nullptr;

			bret = string_to_number(ptmp, ulval, &pnxt, 10);
			if (!bret) {
				return 1;
			}	
			else if (ulval > maxbits) {
				return 1;
			}
			else if (ulval == 0 && (pnxt == ptmp)) {

			}	
			else {

				if (isrange == false) {
					bset[ulval] = true;
				}
				else {
					isrange = false;

					for (uint64_t i = ulstart; i <= ulval; i++) {
						bset[i] = true;
					}	
				}
			}

			if (pnxt && *pnxt) {
				if (*pnxt == ',') {
					ptmp = pnxt + 1;
					continue;
				}	
				else if (*pnxt == '-') {
					ptmp = pnxt + 1;

					isrange = true;
					ulstart = ulval;
					continue;
				}	
				else if (isspace(*pnxt)) {
					ptmp = pnxt;
					do {
						ptmp++;
					} while ((ptmp < pend) && (isspace(*ptmp)));	
				}
				else return 1;
			}	
			else {
				break;
			}	
		} while (ptmp < pend);	

		return 0;
	}
	GY_CATCH_MSG("Exception caught while setting bitset from buffer");
	
	return -1;
}	


/*
 * An iovec array with a corresponding free pointer array
 * Not thread-safe
 */
template <int max_arr_size_ = 8>
struct IOVEC_ARRAY 
{
	int			niov_				{0};
	struct iovec		iovarr_[max_arr_size_]		{};
	FREE_FPTR		free_fp_arr_[max_arr_size_]	{}; // Function to free individual iovec iov_base's : nullptr for no frees e.g. for stack memory

	static_assert(max_arr_size_ > 0 && max_arr_size_ <= 64, "Max array size is limited to 64");

	IOVEC_ARRAY() noexcept	= default;

	IOVEC_ARRAY(void *pbuf, size_t nbytes, FREE_FPTR free_fp) noexcept
		: niov_(1)
	{
		iovarr_[0].iov_base	= pbuf;
		iovarr_[0].iov_len	= (int)nbytes;
		free_fp_arr_[0]		= free_fp;
	}

	// Pass tuples of {void *pbuf, size_t nbytes, FREE_FPTR free_fp} as individual members not using std::tuple...
	IOVEC_ARRAY(size_t ntuples, bool throw_on_error, ...)
	{
		const bool		is_err = (ntuples > max_arr_size_);
		va_list 		ap;

		va_start(ap, throw_on_error);
		
		if (gy_likely(is_err == false)) {
			for (size_t i = 0; i < ntuples; ++i) {
				void		*pbuf 	= va_arg(ap, void *);
				size_t		nbytes	= va_arg(ap, size_t);
				FREE_FPTR	free_fp = va_arg(ap, FREE_FPTR);

				iovarr_[i].iov_base	= pbuf;
				iovarr_[i].iov_len	= nbytes;
				free_fp_arr_[i]		= free_fp;
			}

			if ((ntuples == 2) && (iovarr_[1].iov_len == 0) && (free_fp_arr_[1] == nullptr)) {
				ntuples = 1;
			}

			niov_	= ntuples;
		}	
		else {
			for (size_t i = 0; i < ntuples; ++i) {
				void		*pbuf 	= va_arg(ap, void *);
				size_t		nbytes	= va_arg(ap, size_t);
				FREE_FPTR	free_fp = va_arg(ap, FREE_FPTR);

				if (free_fp && pbuf) {
					(*free_fp)(pbuf);
				}	
			}
		}

		va_end(ap);
	
		if (gy_unlikely(is_err && throw_on_error)) {
			GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "Tuple count exceeds max allowed for IOVEC_ARR : %lu", ntuples);
		}	
	}

	/*
	 * Will throw exception if niov > max_arr_size_ after free'ing the passed piovarr
	 */
	IOVEC_ARRAY(struct iovec *piovarr, int niov, FREE_FPTR * pfree_fparr, bool throw_on_error = true)
	{
		assert(piovarr && pfree_fparr);

		if (niov > 0 && niov <= max_arr_size_) {
			niov_ = niov;
			std::memcpy(iovarr_, piovarr, niov_ * sizeof(*iovarr_));
			std::memcpy(free_fp_arr_, pfree_fparr, niov_ * sizeof(*free_fp_arr_));
		}
		else {
			for (int i = 0; i < niov; ++i) {
				if (piovarr[i].iov_base) {
					if (pfree_fparr[i]) {
						pfree_fparr[i](piovarr[i].iov_base);
						piovarr[i].iov_base = nullptr;
					}	
				}
				else {
					break;
				}	
			}

			if (throw_on_error) {
				GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "Max iovec count exceeded for IOVEC_ARR %d", max_arr_size_);
			}
		}	
	}

	IOVEC_ARRAY(const IOVEC_ARRAY &)		= delete;
	IOVEC_ARRAY & operator=(const IOVEC_ARRAY &)	= delete;

	IOVEC_ARRAY(IOVEC_ARRAY && other) noexcept
	{
		std::memcpy(this, &other, sizeof(*this));
		other.reset();
	}	

	IOVEC_ARRAY & operator= (IOVEC_ARRAY && other) noexcept
	{
		if (this != &other) {
			dealloc();
			std::memcpy((void *)this, &other, sizeof(*this));

			other.reset();
		}

		return *this;
	}	

	~IOVEC_ARRAY() noexcept
	{
		dealloc();
	}	

	/*
	 * If max elems already reached will free the passed buffer and throw an exception
	 * Returns the number of iovec used so far
	 */
	int push_iovec(void *pbuf, size_t nbytes, FREE_FPTR free_fp) 
	{
		if (gy_unlikely(niov_ >= max_arr_size_)) {
			if (pbuf && free_fp) {
				(*free_fp)(pbuf);
			}	

			GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "Max buffer count exceeded for IOVEC_ARR %d", max_arr_size_);
		}	

		int			n = niov_++;

		iovarr_[n].iov_base	= pbuf;
		iovarr_[n].iov_len	= (int)nbytes;
		free_fp_arr_[n]		= free_fp;

		return n + 1;
	}

	void reset() noexcept
	{
		iovarr_[0].iov_base	= nullptr;
		niov_ 			= 0;
	}	

	void dealloc() noexcept
	{	
		for (int i = 0; i < niov_ && i < max_arr_size_; ++i) {
			if (iovarr_[i].iov_base) {
				if (free_fp_arr_[i]) {
					free_fp_arr_[i](iovarr_[i].iov_base);
				}	

				iovarr_[i].iov_base = nullptr;
			}
		}
		
		reset();
	}

	size_t get_byte_count() const noexcept
	{
		return iovec_bytes(iovarr_, niov_);
	}

	int get_num_iovec() const noexcept
	{
		return niov_;
	}	

	int get_avail_iovecs() const noexcept
	{
		return max_arr_size_ - niov_;
	}

	static constexpr int get_max_iovecs() noexcept
	{
		return max_arr_size_;
	}	
};

/*
 * A Cache of multiple allocations upto a max max_arr_size_ allocs. If number of iovec allocs reaches max,
 * the last buffer will be optionally reallocated with the new size required or a new IOVEC_ARRAY will be returned via a callback. 
 * Can be used as a scrathpad till all data is written to it and at the end the get_iovec_array() method can be called to 
 * get the IOVEC_ARRAY which can then be sent to a remote TCP conn using gy_writev()
 * 
 * Users should call get_buf() followed by set_buf_sz() specifying bytes used.
 *
 * Default max_arr_size_ is 1 buffer less for final trailer / padding buffer
 */
template <int orig_max_arr_size_ = 8, int max_arr_size_ = orig_max_arr_size_ - 1>
class IOVEC_BUFFER_CACHE
{
public :
	struct iovec		iovarr_[max_arr_size_]		{};
	FREE_FPTR		free_fp_arr_[max_arr_size_]	{};
	int			niov_				{0};

	uint8_t			*pcurralloc_			{nullptr};
	uint32_t		max_szcurr_			{0};
	uint32_t		used_szcurr_			{0};
	FREE_FPTR		free_fp_curr_			{nullptr};

	POOL_ALLOC_ARRAY	*parrpool_			{nullptr};
	THR_POOL_ALLOC		*plast_pool_ptr_		{nullptr};	// Updated for last array elem

	uint32_t		total_sz_			{0};
	int			nmsg_set_			{0};
	const uint32_t		max_total_sz_;

	static constexpr bool	is_padding_enabled_		= (max_arr_size_ < orig_max_arr_size_);

	static_assert(max_arr_size_ > 0 && max_arr_size_ <= 64, "Max array size is limited to 64");

	static_assert(max_arr_size_ <= orig_max_arr_size_);


	IOVEC_BUFFER_CACHE() 	= delete;

	/*
	 * max_total_sz is max total size that can be used (across multiple allocations)
	 * Specify parrpool if a Buffer Pool is available
	 */
	IOVEC_BUFFER_CACHE(uint32_t max_total_sz, POOL_ALLOC_ARRAY *parrpool = nullptr) noexcept 
		: parrpool_(parrpool), max_total_sz_(max_total_sz)
	{
		assert(max_total_sz_ > 64);
	}

	~IOVEC_BUFFER_CACHE() noexcept
	{
		dealloc();
	}

	IOVEC_BUFFER_CACHE(const IOVEC_BUFFER_CACHE &)			= delete;
	IOVEC_BUFFER_CACHE & operator=(const IOVEC_BUFFER_CACHE &)	= delete;

	IOVEC_BUFFER_CACHE(IOVEC_BUFFER_CACHE && other) noexcept
	{
		std::memcpy((void *)this, &other, sizeof(*this));
		other.reset(false);
	}	

	IOVEC_BUFFER_CACHE & operator= (IOVEC_BUFFER_CACHE && other) noexcept
	{
		if (this != &other) {
			this->dealloc();
			std::memcpy((void *)this, &other, sizeof(*this));

			other.reset(false);
		}

		return *this;
	}	

	/*
	 * Returns a buffer with size at least min_sz bytes (the new max sz is updated in szmax). 
	 * recomm_sz can be used to request a higher allocation size so that if a new buffer is
	 * required to be malloc'ed the recomm_sz will be used and min_sz is the absolute min required.
	 * IOW, recomm_sz will be considered only for new buffer allocations...
	 * 
	 * If the number of discrete allocs have exceeded max_arr_size_, will reallocate the last buffer
	 * to fit the new size (realloc will occur).
	 *
	 * Will never return nullptr
	 */
	void * get_buf(uint32_t min_sz, uint32_t recomm_sz, uint32_t & szmax)
	{
		uint32_t		asz;

		if (gy_unlikely(recomm_sz < min_sz)) {
			recomm_sz = min_sz;
		}
		else if (recomm_sz == 0) {
			recomm_sz = 64;
		}	

		if (pcurralloc_) { 

			if (used_szcurr_ + min_sz <= max_szcurr_) {
				szmax = max_szcurr_ - used_szcurr_;
				return pcurralloc_ + used_szcurr_;
			}	
			
			if (used_szcurr_ > 0) {
				if (niov_ + 1 < max_arr_size_) {
					iovarr_[niov_].iov_base	= pcurralloc_;
					iovarr_[niov_].iov_len	= used_szcurr_;
					free_fp_arr_[niov_]	= free_fp_curr_;
					niov_++;
				}	
				else {
					uint8_t			*ptmp = nullptr;
					uint32_t		newrecom = get_next_alloc_size(min_sz, recomm_sz);

					/*
					 * We need to allocate a new buffer and prepend the existing data to it.
					 * We try to optimize this by using ordered_malloc for the last buffer and then
					 * then combine the new buffer saving on memcpy's
					 */
					asz = used_szcurr_ + newrecom; 

					if (free_fp_curr_ == ::free) {

						ptmp = (uint8_t *)realloc_or_throw(pcurralloc_, asz);

						pcurralloc_ 	= ptmp;
						max_szcurr_	= gy_malloc_usable_size(ptmp, asz);
					}	
					else {
						bool			is_contig = false;
						FREE_FPTR		fp;

						if (parrpool_) {
							if (plast_pool_ptr_) {
								uint32_t		nchunks;
								size_t			newsz;

								nchunks = gy_div_round_up(used_szcurr_ + std::min(newrecom, recomm_sz), (uint32_t)plast_pool_ptr_->get_elem_fixed_size());

								ptmp = (uint8_t *)plast_pool_ptr_->ordered_malloc(nchunks);
								if (ptmp) {
									fp = THR_POOL_ALLOC::dealloc;
									
									if (true == THR_POOL_ALLOC::bufs_contiguous(pcurralloc_, ptmp, true, newsz)) {
										is_contig = true;
										max_szcurr_ = (uint32_t)newsz;
									}	
								}	
							}

							if (nullptr == ptmp) {
								ptmp = (uint8_t *)parrpool_->safe_malloc(asz, fp, max_szcurr_);
							}	
						}
						else {
							ptmp = (uint8_t *)malloc_or_throw(asz);
							
							fp 		= ::free;
							max_szcurr_	= gy_malloc_usable_size(ptmp, asz);
						}	

						if (is_contig == false) {
							std::memcpy(ptmp, pcurralloc_, used_szcurr_);

							if (free_fp_curr_) {
								(*free_fp_curr_)(pcurralloc_);
							}	

							pcurralloc_ 	= ptmp;
							free_fp_curr_	= fp;

							plast_pool_ptr_	= nullptr;
						}
					}	

					szmax = max_szcurr_ - used_szcurr_;
					return pcurralloc_ + used_szcurr_;
				}	
			}	
			else {
				if (free_fp_curr_) {
					(*free_fp_curr_)(pcurralloc_);
				}	
			}	

			pcurralloc_ 	= nullptr;
			used_szcurr_	= 0;
			free_fp_curr_	= nullptr;
		}

		asz = get_next_alloc_size(min_sz, recomm_sz);

		if (parrpool_) {
			if (niov_ + 1 < max_arr_size_) {
				pcurralloc_ = (uint8_t *)parrpool_->safe_malloc(asz, free_fp_curr_, max_szcurr_);
			}
			else {
				// Last Array Element Try ordered_malloc to maintain contiguousness
				pcurralloc_ = (uint8_t *)parrpool_->safe_ordered_malloc(asz, 1, free_fp_curr_, max_szcurr_, &plast_pool_ptr_);
			}	
		}
		else {
			pcurralloc_ 	= (uint8_t *)malloc_or_throw(asz);

			free_fp_curr_	= ::free;
			max_szcurr_	= gy_malloc_usable_size(pcurralloc_, asz);
		}	
		
		used_szcurr_	= 0;
		szmax 		= max_szcurr_;

		return pcurralloc_;
	}

	/*
	 * Returns a buffer with size at least min_sz bytes (the new max sz is updated in szmax). 
	 * recomm_sz can be used to request a higher allocation size so that if a new buffer is
	 * required to be malloc'ed the recomm_sz will be used and min_sz is the absolute min required.
	 * IOW, recomm_sz will be considered only for new buffer allocations...
	 * 
	 * If the number of discrete allocs have exceeded max_arr_size_, will call the 
	 * flushcb(IOVEC_ARRAY<orig_max_arr_size_> && iovec, uint32_t total_sz, uint32_t nmsg_set) 
	 * and after the callback will return nullptr. 
	 *
	 * Return value is nullptr only if flushcb called. Else always returns non null
	 */
	template <typename FCB>
	void * get_buf(FCB & flushcb, uint32_t min_sz, uint32_t recomm_sz, uint32_t & szmax)
	{
		uint32_t		asz;

		if (gy_unlikely(recomm_sz < min_sz)) {
			recomm_sz = min_sz;
		}
		else if (recomm_sz == 0) {
			recomm_sz = 64;
		}	

		if (pcurralloc_) { 

			if (used_szcurr_ + min_sz <= max_szcurr_) {
				szmax = max_szcurr_ - used_szcurr_;
				return pcurralloc_ + used_szcurr_;
			}	
			
			if (used_szcurr_ > 0) {
				if (niov_ + 1 < max_arr_size_) {
					iovarr_[niov_].iov_base	= pcurralloc_;
					iovarr_[niov_].iov_len	= used_szcurr_;
					free_fp_arr_[niov_]	= free_fp_curr_;
					niov_++;
				}	
				else {
					uint32_t		total_sz, nmsg_set;
					
					auto			iovarr = get_iovec_array(total_sz, nmsg_set);
					
					flushcb(std::move(iovarr), total_sz, nmsg_set);

					szmax = 0;
					return nullptr;
				}	
			}	
			else {
				if (free_fp_curr_) {
					(*free_fp_curr_)(pcurralloc_);
				}	
			}	

			pcurralloc_ 	= nullptr;
			used_szcurr_	= 0;
			free_fp_curr_	= nullptr;
		}

		asz = get_next_alloc_size(min_sz, recomm_sz, !niov_ /* throw_on_error */);

		if (gy_unlikely(asz == 0)) {
			uint32_t		total_sz, nmsg_set;
			auto			iovarr = get_iovec_array(total_sz, nmsg_set);
					
			flushcb(std::move(iovarr), total_sz, nmsg_set);

			szmax = 0;
			return nullptr;
		}	

		if (parrpool_) {
			pcurralloc_ = (uint8_t *)parrpool_->safe_malloc(asz, free_fp_curr_, max_szcurr_);
		}
		else {
			pcurralloc_ 	= (uint8_t *)malloc_or_throw(asz);

			free_fp_curr_	= ::free;
			max_szcurr_	= gy_malloc_usable_size(pcurralloc_, asz);
		}	
		
		used_szcurr_	= 0;
		szmax 		= max_szcurr_;

		return pcurralloc_;
	}

	// Will return non nullptr only if required sz already available, else returns nullptr
	void * get_buf_if_avail(uint32_t sz, uint32_t & szmax) const noexcept
	{
		if (pcurralloc_ && (used_szcurr_ + sz <= max_szcurr_)) {
			szmax = max_szcurr_ - used_szcurr_;
			return pcurralloc_ + used_szcurr_;
		}	

		return nullptr;
	}

	void set_buf_sz(uint32_t sz) 
	{
		if (sz == 0) {
			return;
		}

		if (pcurralloc_ && used_szcurr_ + sz <= max_szcurr_) {
			nmsg_set_++;

			used_szcurr_ 	+= sz;
			total_sz_ 	+= sz;

			if ((used_szcurr_ == max_szcurr_) && (niov_ + 1 < max_arr_size_)) {
				iovarr_[niov_].iov_base	= pcurralloc_;
				iovarr_[niov_].iov_len	= used_szcurr_;
				free_fp_arr_[niov_]	= free_fp_curr_;
				niov_++;
				
				pcurralloc_ 	= nullptr;
				used_szcurr_	= 0;
				free_fp_curr_	= nullptr;
			}	
		}	
		else {
			GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "Invalid Buffer set size specified for Iovec Data Cache %u", sz);
		}	
	}	

	std::tuple<uint32_t, int, int> get_stats() const noexcept
	{
		return {total_sz_, nmsg_set_, niov_};
	}
	
	size_t get_curr_bytes() const noexcept
	{
		return total_sz_;
	}	

	IOVEC_ARRAY <orig_max_arr_size_>  get_iovec_array(uint32_t & total_sz, uint32_t & nmsg_set)
	{
		if (gy_unlikely(total_sz_ == 0)) {
			total_sz 	= 0;
			nmsg_set	= 0;

			return {};
		}

		total_sz		= total_sz_;
		nmsg_set		= nmsg_set_;

		struct iovec		iovarr[max_arr_size_];
		FREE_FPTR		free_fp_arr[max_arr_size_];

		int			niov = niov_;

		if (niov > 0) {
			std::memcpy(iovarr, iovarr_, niov * sizeof(*iovarr));
			std::memcpy(free_fp_arr, free_fp_arr_, niov * sizeof(*free_fp_arr));
		}

		if (pcurralloc_) {
			if (used_szcurr_ && (unsigned)niov < (unsigned)max_arr_size_) {
				iovarr[niov].iov_base	= pcurralloc_;
				iovarr[niov].iov_len	= used_szcurr_;
				free_fp_arr[niov]	= free_fp_curr_;
				niov++;
			}
			else if (free_fp_curr_) {
				(*free_fp_curr_)(pcurralloc_);
			}	
		}

		reset(false);

		return IOVEC_ARRAY <orig_max_arr_size_> (iovarr, niov, free_fp_arr, true /* throw_on_error */);
	}	

	void reset(bool to_dealloc = false) noexcept
	{
		if (to_dealloc) {
			dealloc();
		}

		iovarr_[0].iov_base	= nullptr;
		niov_ 			= 0;
		pcurralloc_		= nullptr;
		max_szcurr_		= 0;
		used_szcurr_		= 0;
		total_sz_		= 0;
		nmsg_set_		= 0;
		plast_pool_ptr_		= nullptr;
	}	

	void dealloc() noexcept
	{
		for (int i = 0; i < niov_ && i < max_arr_size_; ++i) {
			if (iovarr_[i].iov_base) {
				if (free_fp_arr_[i]) {
					free_fp_arr_[i](iovarr_[i].iov_base);
				}	

				iovarr_[i].iov_base = nullptr;
			}
		}
		
		if (pcurralloc_ && free_fp_curr_) {
			(*free_fp_curr_)(pcurralloc_);
		}	

		pcurralloc_ 	= nullptr;
		niov_		= 0;
		total_sz_	= 0;
	}	

	POOL_ALLOC_ARRAY * get_inter_pool() const noexcept
	{
		return parrpool_;
	}	

	constexpr size_t get_max_iovecs() const noexcept
	{
		return max_arr_size_;
	}	

private :
	uint32_t get_next_alloc_size(uint32_t min_sz, uint32_t recomm_sz, bool throw_on_error = true) const 
	{
		if (gy_unlikely(total_sz_ + recomm_sz >= max_total_sz_)) {
			if (total_sz_ + min_sz >= max_total_sz_) {
				if (throw_on_error) {
					GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "Max Total Message size limit breached %u", max_total_sz_);
				}
				else {
					return 0;
				}	
			}
			recomm_sz = min_sz;

			return recomm_sz;
		}

		if ((recomm_sz < 1024 * 1024) && (niov_ + 1 >= max_arr_size_) && (total_sz_ + (recomm_sz << 1) < max_total_sz_)) {
			// We are reaching the array limit. Double the allocation
			recomm_sz <<= 1;
		}	
		else if (recomm_sz > GY_UP_MB(16) && min_sz < GY_UP_MB(16)) {
			recomm_sz = GY_UP_MB(16);
		}	
		
		return recomm_sz;
	}	
};

/*
 * A single buffer based cache to keep a number of a variable len size items to be sent in batches
 * Not thread safe. The writer thread must call flush_cache() periodically
 * to flush the semi-filled cache. Includes an optional inline Memory Allocator pool.
 *
 * IOVEC_BUFFER_CACHE can be used to cache multiple discontiguous buffers whereas DATA_BUFFER is used
 * as a single buffer cache... IOVEC_BUFFER_CACHE is more useful for variable length messages whereas
 * DATA_BUFFER is more useful for finite fixed size messages. 
 *
 * Usage : Call get_next_buffer() followed by set_buffer_sz() for each element. After flush_cache()
 * a new buffer will be allocated on the next get_next_buffer() call.
 *
 * NOTE : No memory is allocated until the get_next_buffer() method is called except in the case of inline memory pool.
 */
class DATA_BUFFER
{
public :
	THR_POOL_ALLOC				*pmem_pool_		{nullptr};	
	uint8_t					*palloc_		{nullptr};
	uint8_t					*pcur_			{nullptr};
	uint8_t					*pendptr_		{nullptr};
	FREE_FPTR 				free_fp_		{nullptr};
	uint32_t				ncurr_			{0};			
	uint32_t				init_reserve_sz_	{0};
	const uint32_t				max_elem_sz_;
	const uint32_t				min_cache_elem_;
	const uint32_t				max_cache_elem_;
	const bool				is_ext_pool_;

	/*
	 * Use this constructor if a new inline Memory Pool needs to be allocated for this Data cache
	 */
	DATA_BUFFER(uint32_t max_elem_sz, uint32_t max_pool_elem, uint32_t min_cache_elem, uint32_t max_cache_elem, uint32_t init_reserve_sz, bool is_caller_allocator_thread) :
		pmem_pool_(new THR_POOL_ALLOC(max_elem_sz, max_pool_elem, is_caller_allocator_thread)), 
		init_reserve_sz_(init_reserve_sz), max_elem_sz_(pmem_pool_->get_elem_fixed_size()), min_cache_elem_(min_cache_elem), max_cache_elem_(max_cache_elem), 
		is_ext_pool_(false)
	{
		assert(max_pool_elem >= min_cache_elem_ && min_cache_elem_ > 1 && max_cache_elem_ >= min_cache_elem_);
	}	

	/*
	 * Use this constructor if an existing Memory Pool needs to be used for this Data cache
	 */
	DATA_BUFFER(THR_POOL_ALLOC & mem_pool, uint32_t max_elem_sz, uint32_t min_cache_elem, uint32_t max_cache_elem, uint32_t init_reserve_sz) noexcept :
		pmem_pool_(&mem_pool), init_reserve_sz_(init_reserve_sz), max_elem_sz_(mem_pool.get_elem_fixed_size()), 
		min_cache_elem_(min_cache_elem), max_cache_elem_(max_cache_elem), is_ext_pool_(true)
	{

		assert(min_cache_elem_ > 1 && max_cache_elem_ >= min_cache_elem_);
	}	

	/*
	 * Use this constructor if global Heap malloc is the source of the memory for this Data cache
	 */
	DATA_BUFFER(uint32_t max_elem_sz, uint32_t min_cache_elem, uint32_t max_cache_elem, uint32_t init_reserve_sz) noexcept :
		pmem_pool_(nullptr), init_reserve_sz_(init_reserve_sz), max_elem_sz_(max_elem_sz), min_cache_elem_(min_cache_elem), max_cache_elem_(max_cache_elem), 
		is_ext_pool_(true)
	{
		assert(min_cache_elem_ > 1 && max_cache_elem_ >= min_cache_elem_);
	}

	~DATA_BUFFER()
	{
		if (palloc_ && free_fp_) {
			(*free_fp_)(palloc_);
			reset_elems();
		}	

		if (pmem_pool_ && false == is_ext_pool_) {
			delete pmem_pool_;
			pmem_pool_ = nullptr;
		}	
	}	

	void set_alloc_thrid(pthread_t tid) noexcept
	{
		if (pmem_pool_) {
			pmem_pool_->set_alloc_thrid(tid);
		}
	}	
	
	void * get_alloc_buf(FREE_FPTR & free_fp, size_t & sz) const noexcept
	{
		free_fp 	= free_fp_;
		sz 		= pcur_ - palloc_;

		return palloc_;
	}

	/*
	 * Will throw an exception if no memory can be allocated
	 */
	void * get_next_buffer() 
	{
		if (palloc_ && pcur_ >= palloc_) {
			return pcur_;
		}	

		assert(palloc_ == nullptr && ncurr_ == 0);

		uint32_t 	ncachelem, act_size;

		ncachelem 	= min_cache_elem_ + gy_div_round_up(init_reserve_sz_, max_elem_sz_);

		uint8_t  	*ptmp;
		
		if (pmem_pool_) {
			ptmp 	= (uint8_t *)pmem_pool_->safe_ordered_malloc(ncachelem, free_fp_, act_size);
		}
		else {
			ptmp	= (uint8_t *)malloc_or_throw(ncachelem * max_elem_sz_);

			free_fp_	= ::free;
			act_size	= gy_malloc_usable_size(ptmp, ncachelem * max_elem_sz_);
		}	
		
		palloc_ 	= ptmp;
		pcur_ 		= ptmp + init_reserve_sz_;
		pendptr_	= ptmp + act_size;
		ncurr_		= 0;

		return pcur_;
	}

	/*
	 * This call will update the internal cache size and if no more elements possible in cache will
	 * invoke the passed sendfcb callback. After sendfcb(), the internal cache is reset.
	 * 
	 * The sendfcb() callback is responsible for freeing the allocated cache memory specified by palloc
	 * 
	 * Sample sendfcb() :
	 	auto sendcb = [this, pconn](void *palloc, size_t sz, FREE_FPTR free_fp, size_t nelems) -> bool
		{
			bool bret = send_blocking(pconn, palloc, sz);
			if (free_fp) {
				(*free_fp)(palloc);
			}
			return bret;
		};	

	 * Returns output of sendfcb() or true if no sendfcb invoked as buffer space still pending.
	 */
	template <typename FCB>
	bool set_buffer_sz(FCB & sendfcb, uint32_t sz, bool force_flush = false)
	{
		bool			bret = true;
		size_t			szpend;

		if (sz > 0) {
			assert(pcur_ && sz <= max_elem_sz_);

			pcur_ 	+= sz;
			ncurr_++;
		
			szpend	= pendptr_ - pcur_;
		}
		else {
			szpend = max_elem_sz_;
		}	

		if ((force_flush && ncurr_ > 0) || ((szpend < max_elem_sz_) || (ncurr_ >= max_cache_elem_))) {
			try {
				bret = sendfcb((void *)palloc_, (size_t)(pcur_ - palloc_), free_fp_, (size_t)ncurr_);
				reset_elems();
			}
			catch(...) {
				reset_elems();
				throw;
			}	
		}	

		return bret;
	}	
	
	/*
	 * This will call the sendfcb() and reset internal cache. See comment for set_buffer_sz() above as well.
	 */
	template <typename FCB>
	bool flush_cache(FCB & sendfcb)
	{
		bool		bret = false;

		if (ncurr_ > 0) {
			try {
				bret = sendfcb((void *)palloc_, (size_t)(pcur_ - palloc_), free_fp_, (size_t)ncurr_);
				reset_elems();
			}
			catch(...) {
				reset_elems();
				throw;
			}	
		}	

		return bret;
	}	

	void set_init_reserve_size(uint32_t new_init_sz) noexcept
	{
		init_reserve_sz_ = new_init_sz;
	}	

	size_t get_buf_num_elems() const noexcept
	{
		return ncurr_;
	}

	/*
	 * Purge existing cache elems without freeing the memory
	 */
	void purge_all() noexcept
	{
		pcur_		= palloc_ ? palloc_ + init_reserve_sz_ : nullptr;
		ncurr_		= 0;
	}

	void reset_elems() noexcept
	{
		palloc_ 	= nullptr;
		pcur_		= nullptr;
		pendptr_	= nullptr;
		free_fp_	= nullptr;
		ncurr_		= 0;
	}	

	THR_POOL_ALLOC * get_pool() const noexcept
	{
		return pmem_pool_;
	}	
};	

enum {
	PROC_EVENT_NONE 	= 0x00000000,
	PROC_EVENT_FORK 	= 0x00000001,
	PROC_EVENT_EXEC 	= 0x00000002,
	PROC_EVENT_UID  	= 0x00000004,
	PROC_EVENT_GID  	= 0x00000040,
	PROC_EVENT_SID  	= 0x00000080,
	PROC_EVENT_PTRACE 	= 0x00000100,
	PROC_EVENT_COMM 	= 0x00000200,
	PROC_EVENT_COREDUMP 	= 0x40000000,
	PROC_EVENT_EXIT 	= 0x80000000
};

/*
 * Copied from linux/cn_proc.h struct proc_event
 */
struct GY_PROC_EVENT {
	enum what {
		PROC_EVENT_NONE 	= 0x00000000,
		PROC_EVENT_FORK 	= 0x00000001,
		PROC_EVENT_EXEC 	= 0x00000002,
		PROC_EVENT_UID  	= 0x00000004,
		PROC_EVENT_GID  	= 0x00000040,
		PROC_EVENT_SID  	= 0x00000080,
		PROC_EVENT_PTRACE 	= 0x00000100,
		PROC_EVENT_COMM 	= 0x00000200,
		PROC_EVENT_COREDUMP 	= 0x40000000,
		PROC_EVENT_EXIT 	= 0x80000000
	} what;
	__u32 cpu;
	__u64 __attribute__((aligned(8))) timestamp_ns;
		/* Number of nano seconds since system boot */
	union { /* must be last field of proc_event struct */
		struct {
			__u32 err;
		} ack;

		struct fork_proc_event {
			__kernel_pid_t parent_pid;
			__kernel_pid_t parent_tgid;
			__kernel_pid_t child_pid;
			__kernel_pid_t child_tgid;
		} fork;

		struct exec_proc_event {
			__kernel_pid_t process_pid;
			__kernel_pid_t process_tgid;
		} exec;

		struct id_proc_event {
			__kernel_pid_t process_pid;
			__kernel_pid_t process_tgid;
			union {
				__u32 ruid; /* task uid */
				__u32 rgid; /* task gid */
			} r;
			union {
				__u32 euid;
				__u32 egid;
			} e;
		} id;

		struct sid_proc_event {
			__kernel_pid_t process_pid;
			__kernel_pid_t process_tgid;
		} sid;

		struct ptrace_proc_event {
			__kernel_pid_t process_pid;
			__kernel_pid_t process_tgid;
			__kernel_pid_t tracer_pid;
			__kernel_pid_t tracer_tgid;
		} ptrace;

		struct comm_proc_event {
			__kernel_pid_t process_pid;
			__kernel_pid_t process_tgid;
			char           comm[16];
		} comm;

		struct coredump_proc_event {
			__kernel_pid_t process_pid;
			__kernel_pid_t process_tgid;
			__kernel_pid_t parent_pid;
			__kernel_pid_t parent_tgid;
		} coredump;

		struct exit_proc_event {
			__kernel_pid_t process_pid;
			__kernel_pid_t process_tgid;
			__u32 exit_code, exit_signal;
			__kernel_pid_t parent_pid;
			__kernel_pid_t parent_tgid;
		} exit;

	} event_data;
};


static inline bool path_is_absolute(const char *p) noexcept
{
        return p[0] == '/';
}

static inline bool is_path_type_string(const char *p) noexcept
{
        return !!strchr(p, '/');
}

union CAP_BITFLAGS 
{
	uint32_t			is_elevated_cap		{0};
	struct {
		bool			is_cap_ipc_lock : 1;
		bool			is_cap_kill : 1;
		bool			is_cap_net_admin : 1;
		bool			is_cap_net_raw : 1;
		bool			is_cap_sys_admin : 1;
		bool			is_cap_sys_nice : 1;		
		bool			is_cap_sys_module : 1;		
		bool			is_cap_sys_rawio : 1;		
		bool			is_cap_sys_resource : 1;		
	};
};

class GY_CAPABILITIES	
{
public :	
	GY_CAPABILITIES	() noexcept : cap(nullptr) {}		

	explicit GY_CAPABILITIES(pid_t pid) noexcept : cap(cap_get_pid(pid))
	{}

	explicit GY_CAPABILITIES(cap_t capo) noexcept : cap(capo ? cap_dup(capo) : nullptr)
	{}

	~GY_CAPABILITIES() noexcept
	{
		reset();
	}	

	GY_CAPABILITIES(GY_CAPABILITIES && other) noexcept 
	{
		this->cap  	= other.cap;
		other.cap 	= nullptr;
	}	

	GY_CAPABILITIES & operator= (GY_CAPABILITIES && other) noexcept
	{
		if (this != &other) {
			reset();

			this->cap  	= other.cap;
			other.cap 	= nullptr;
		}
		return *this;
	}

	GY_CAPABILITIES(const GY_CAPABILITIES & other) noexcept
	{
		if (other.cap) {
			this->cap = cap_dup(other.cap);
		}	
		else {
			this->cap = nullptr;
		}	
	}	

	GY_CAPABILITIES & operator= (const GY_CAPABILITIES & other) noexcept
	{
		if (this != &other) {
			reset();

			if (other.cap) {
				this->cap = cap_dup(other.cap);
			}	
		}
			
		return *this;
	}	 

	void reset() noexcept
	{
		if (cap) {
			cap_free(cap);
			cap = nullptr;
		}	
	}
		
	const cap_t get() const noexcept
	{
		return cap;
	}

	cap_t get() noexcept
	{
		return cap;
	}

	void setpid(pid_t pid) noexcept
	{
		reset();
		cap = cap_get_pid(pid);
	}

	bool is_cap_set(cap_value_t cap_flag) const noexcept			
	{
		int			ret;
		cap_flag_value_t	res;

		if (!cap) {
			return false;
		}
			
		ret = cap_get_flag(cap, cap_flag, CAP_EFFECTIVE, &res);
		if (ret == 0 && res == CAP_SET) {
			return true;
		}	
		return false;
	}

	void set_cap_bitflags(CAP_BITFLAGS & cap_flags) const noexcept
	{
		/*
		 * We currently only set the main Capability bitflags (Not all)
		 */ 
		cap_flags.is_cap_ipc_lock 	= is_cap_set(CAP_IPC_LOCK);
		cap_flags.is_cap_kill 		= is_cap_set(CAP_KILL);
		cap_flags.is_cap_net_admin 	= is_cap_set(CAP_NET_ADMIN);
		cap_flags.is_cap_net_raw 	= is_cap_set(CAP_NET_RAW);
		cap_flags.is_cap_sys_admin 	= is_cap_set(CAP_SYS_ADMIN);
		cap_flags.is_cap_sys_nice 	= is_cap_set(CAP_SYS_NICE);
		cap_flags.is_cap_sys_module 	= is_cap_set(CAP_SYS_MODULE);
		cap_flags.is_cap_sys_rawio 	= is_cap_set(CAP_SYS_RAWIO);
		cap_flags.is_cap_sys_resource 	= is_cap_set(CAP_SYS_RESOURCE);
	}	
		
	static int proc_clear_all_cap(bool clear_only_inheritable = false) noexcept
	{
		cap_t 		cap;
		cap_flag_t	cap_flag = (clear_only_inheritable ? CAP_INHERITABLE : CAP_EFFECTIVE);
		int		ret, olderrno;

		cap = cap_get_proc();
		if (!cap) {
			return -1;
		}	

		GY_SCOPE_EXIT {
			olderrno = errno;
			cap_free(cap);
			errno = olderrno;
		};	

		ret = cap_clear_flag(cap, cap_flag);
		if (ret != 0) {
			return ret;
		}	

		ret = cap_set_proc(cap);
		return ret;
	}	
		
	cap_t			cap;
};	


enum NS_TYPES_E
{
	NS_TYPE_IPC	= 0,
	NS_TYPE_MNT,
	NS_TYPE_NET,
	NS_TYPE_PID,
	NS_TYPE_USER,
	NS_TYPE_UTS,
	NS_TYPE_PID_FOR_CHILDREN,
	NS_TYPE_CGROUP,
};	

class TASK_NS_INODES
{
public :	
	ino_t			ipc_inode		{0};			
	ino_t			mnt_inode		{0};
	ino_t			net_inode		{0};
	ino_t			pid_inode		{0};
	ino_t			user_inode		{0};
	ino_t			uts_inode		{0};
	ino_t			pid_for_children_inode	{0};	
	ino_t			cgroup_inode		{0};

	pid_t			pid			{0};

	union {
		uint16_t		flags_		{0};

		struct {
			bool			ipc_in_root_ns : 1;
			bool			mnt_in_root_ns : 1;
			bool			net_in_root_ns : 1;
			bool			pid_in_root_ns : 1;
			bool			pid_child_in_root_ns : 1;
			bool			user_in_root_ns : 1;
			bool			uts_in_root_ns : 1;
			bool			cgroup_in_root_ns : 1;
		};
	};	

	bool			is_init;

	TASK_NS_INODES() noexcept 		= default;
		
	TASK_NS_INODES(pid_t pid, const TASK_NS_INODES *prootns_inodes) 
	{
		int				ret;

		ret = populate_ns_inodes(-1, pid, prootns_inodes);
		if (ret != 0) {
			errno = -ret;
			GY_THROW_SYS_EXCEPTION("Failed to populate Namespace inodes for PID %d", pid);
		}		
	}

	TASK_NS_INODES(int proc_dir_fd, pid_t pid, const TASK_NS_INODES *prootns_inodes) 
	{
		int				ret;

		ret = populate_ns_inodes(proc_dir_fd, pid, prootns_inodes);
		if (ret != 0) {
			errno = -ret;
			GY_THROW_SYS_EXCEPTION("Failed to populate Namespace inodes for PID %d", pid);
		}		
	}
			
	int populate_ns_inodes(int proc_dir_fd, pid_t pidin, const TASK_NS_INODES *prootns_inodes) noexcept
	{
		const char *	 		nsstr[] = {"ipc", "mnt", "net", "pid", "user", "uts", "pid_for_children", "cgroup"};
		ino_t				nsinode[GY_ARRAY_SIZE(nsstr)] {};

		int				ret;

		assert(prootns_inodes);

		ret = get_proc_ns_inodes(pidin, nsstr, nsinode, GY_ARRAY_SIZE(nsstr), proc_dir_fd);
		if (ret < 0) {
			errno = -ret;
			return -1;
		}	
		
		static_assert(GY_ARRAY_SIZE(nsstr) >= 8);

		ipc_inode = nsinode[0];
		mnt_inode = nsinode[1];
		net_inode = nsinode[2];
		pid_inode = nsinode[3];
		user_inode = nsinode[4];
		uts_inode = nsinode[5];
		pid_for_children_inode = nsinode[6];
		cgroup_inode = nsinode[7];

		if (this != prootns_inodes) {
			ipc_in_root_ns = (prootns_inodes->ipc_inode == this->ipc_inode);
			mnt_in_root_ns = (prootns_inodes->mnt_inode == this->mnt_inode);
			net_in_root_ns = (prootns_inodes->net_inode == this->net_inode);
			pid_in_root_ns = (prootns_inodes->pid_inode == this->pid_inode);
			user_in_root_ns = (prootns_inodes->user_inode == this->user_inode);
			uts_in_root_ns = (prootns_inodes->uts_inode == this->uts_inode);
			pid_child_in_root_ns = (prootns_inodes->pid_child_in_root_ns == this->pid_child_in_root_ns);
			cgroup_in_root_ns = (prootns_inodes->cgroup_inode == this->cgroup_inode);
		}
		else {
			ipc_in_root_ns = true;
			mnt_in_root_ns = true;
			net_in_root_ns = true;
			pid_in_root_ns = true;
			pid_child_in_root_ns = true;
			user_in_root_ns = true;
			uts_in_root_ns = true;
			cgroup_in_root_ns = true;
		}	
		
		pid = pidin;

		is_init = true;

		return 0;
	}		

	bool is_same_ns(NS_TYPES_E type, ino_t nsinode) const noexcept
	{
		switch (type) {
		
		case NS_TYPE_IPC : return nsinode == ipc_inode;

		case NS_TYPE_MNT : return nsinode == mnt_inode;

		case NS_TYPE_NET : return nsinode == net_inode;

		case NS_TYPE_PID : return nsinode == pid_inode;

		case NS_TYPE_USER : return nsinode == user_inode;

		case NS_TYPE_UTS : return nsinode == uts_inode;

		case NS_TYPE_PID_FOR_CHILDREN : return nsinode == pid_for_children_inode;
	
		case NS_TYPE_CGROUP : return nsinode == cgroup_inode;

		default : return false;
		}	
	}	

	ino_t get_ns_inode(NS_TYPES_E type) const noexcept 
	{
		switch (type) {
		
		case NS_TYPE_IPC : return ipc_inode;

		case NS_TYPE_MNT : return mnt_inode;

		case NS_TYPE_NET : return net_inode;

		case NS_TYPE_PID : return pid_inode;

		case NS_TYPE_USER : return user_inode;

		case NS_TYPE_UTS : return uts_inode;

		case NS_TYPE_PID_FOR_CHILDREN : return pid_for_children_inode;
	
		case NS_TYPE_CGROUP : return cgroup_inode;

		default : return 0;
		}	
	}
	
	bool is_in_root_ns(NS_TYPES_E type) const noexcept
	{
		switch (type) {
		
		case NS_TYPE_IPC : return ipc_in_root_ns;

		case NS_TYPE_MNT : return mnt_in_root_ns;

		case NS_TYPE_NET : return net_in_root_ns;

		case NS_TYPE_PID : return pid_in_root_ns;

		case NS_TYPE_USER : return user_in_root_ns;

		case NS_TYPE_UTS : return uts_in_root_ns;

		case NS_TYPE_PID_FOR_CHILDREN : return pid_child_in_root_ns;
	
		case NS_TYPE_CGROUP : return cgroup_in_root_ns;

		default : return false;
		}	
	}

	bool in_container() const noexcept
	{
		return (!ipc_in_root_ns || !mnt_in_root_ns || !net_in_root_ns || !pid_in_root_ns || !user_in_root_ns || !uts_in_root_ns || !cgroup_in_root_ns); 
	}	
		
	bool is_initialized() const noexcept
	{
		return is_init;
	}	
};	

/*
 * Returns a path valid from the current mount namespace. Use in case a path is returned from a process possibly in 
 * another mount namespace.
 * pid is the process ID for whom the path is valid
 */
static CHAR_BUF<GY_PATH_MAX> get_ns_safe_file_path(pid_t pid, const char *path, char (&errbuf)[256], bool *pnewmount = nullptr) noexcept
{
	CHAR_BUF<GY_PATH_MAX>		obuf;
	char				spath[GY_PATH_MAX], dpath[GY_PATH_MAX];
	const char 			*psrc, *pdest;
	ssize_t				sret;
	ino_t				tns = get_proc_ns_inode(pid, "mnt");
	
	if (tns == 0) {
		snprintf(errbuf, sizeof(errbuf), "Failed to get pid %d Mount namespace : %s", pid, gy_get_perror().get());
		return obuf;
	}
	else if (!path || (0 == *path)) {
		snprintf(errbuf, sizeof(errbuf), "No path specified");
		return obuf;
	}	

	if (*path != '/') {
		char			npath[GY_PATH_MAX], tpath[GY_PATH_MAX];

		snprintf(npath, sizeof(npath), "/proc/%d/cwd", pid);

		sret = readlink(npath, tpath, sizeof(tpath) - 1);
		if (sret < 0) {
			snprintf(errbuf, sizeof(errbuf), "Failed to get pid %d current working dir : %s", pid, gy_get_perror().get());
			return obuf;
		}
		else if (sret == sizeof(tpath) - 1) {
			snprintf(errbuf, sizeof(errbuf), "Failed as pid %d Current Working Dir too long : currently not handled", pid);
			return obuf;
		}	
		
		tpath[sret] = 0;

		snprintf(spath, sizeof(spath), "%s/%s", tpath, path);

		psrc = spath;
	}
	else {
		psrc = path;
	}	

	if (tns == get_curr_mountns_inode()) {
		pdest = psrc;
	}	
	else {
		pdest = dpath;

		sret = snprintf(dpath, sizeof(dpath), "/proc/%d/root%s", pid, psrc);

		if ((unsigned)sret >= sizeof(dpath)) {
			snprintf(errbuf, sizeof(errbuf), "Failed as path specified is too long : currently not handled");
			return obuf;
		}	

		if (pnewmount) {
			*pnewmount = true;
		}	
	}	

	*errbuf = 0;

	obuf.setbuf(pdest);

	return obuf;
}	

/*
 * Walk the /proc/pid/maps entry for a PID for each lib path
 * Pass a lambda with params (const char *plibname, const char *plibpath, const char *pline, bool is_lib_deleted) -> CB_RET_E
 * The lambda if returns a CB_BREAK_LOOP will terminate the walk.
 */
template <typename FCB> 
int walk_proc_pid_map_libs(pid_t pid, FCB & walk) noexcept(noexcept(walk(nullptr, nullptr, nullptr, false)))
{
	SCOPE_FILE			sfile(gy_to_charbuf<128>("/proc/%d/maps", pid).get(), "r");
	FILE 				*pfp = sfile.get();

	if (nullptr == pfp) {
		return -1;
	}	

	char 				*pline = nullptr, *lib, *plibpath, *pdel;
	size_t 				len = 0;
	ssize_t				nread;
	int				nlibs = 0;
	CB_RET_E			cret;

	GY_SCOPE_EXIT {
		if (pline) free(pline);
	};

	while ((nread = getline(&pline, &len, pfp)) != -1) {
		if (nread <= 5) {
			continue;
		}
		if (pline[nread - 1] == '\n') {
			nread--;
			pline[nread] = 0;
		}	

		lib = (char *)memrchr(pline, '/', nread - 4);
		if (!lib) {
			continue;
		}	

		lib++;

		if ((0 == memcmp(lib, "lib", 3)) && strstr(lib, ".so")) {

			plibpath = (char *)memrchr(pline, ' ', lib - pline);
			if (!plibpath) {
				continue;
			}	
			plibpath++;

			nlibs++;

			pdel = strstr(lib, " (deleted)");
			if (pdel) {
				*pdel = 0;
			}	

			cret = walk(lib, plibpath, pline, !!pdel);

			if (cret == CB_BREAK_LOOP || cret == CB_DELETE_BREAK) {
				break;
			}	
		}	
	}

	return nlibs;
}

} // namespace gyeeta


