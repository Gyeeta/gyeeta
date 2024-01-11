//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma 			once

#include 			"gy_common_inc.h"

#include 			<sys/uio.h>

/*
 * Non-blocking single/multi writer and a single blocking reader variable length contiguous pool.
 * If multiple writers, the writers need to be synchronized externally using a mutex for e.g.
 *
 * Allows the reader to sweep multiple data sets in a single go due to the contiguous nature of the
 * pool storage. Also option to peek without consuming.
 */

namespace gyeeta {

static constexpr uint32_t	SHM_POOL_MAGIC 		= 0xAABBCCDDu;
static constexpr uint32_t	SHM_DEBUG_CNT		= 1000000u;
static constexpr uint32_t 	SHM_DEBUG_BLK_CNT	= 50000u;

/*
 * Default shmpool read callback 
 */ 
class SHM_POOL_MEMCPY_CB
{
public :	
	uint64_t		skipped_bytes;
	uint8_t			is_peek;

	SHM_POOL_MEMCPY_CB()  noexcept : skipped_bytes(0), is_peek(0) {}

	int operator()(char *pin, uint32_t lenin, void *poutarrin, uint32_t maxelem, uint32_t max_elem_size, void *parg, uint32_t *pcopied_elem) noexcept
	{
		uint32_t	origlen = lenin, nouts = 0, clen;
		int		len = (int)lenin;
		char		*porigin = pin, *ptmp, *pend;
		struct iovec 	*poutarr = static_cast<struct iovec *>(poutarrin);

		ptmp = pin;
		pend = pin + lenin;

		if ((len == 0) || (maxelem == 0) || (max_elem_size == 0)) {
			goto done;
		}

		while ((nouts < maxelem) && (len > 0) && (ptmp < pend)) {
			clen = std::min((uint32_t)len, max_elem_size);

			memcpy(poutarr[nouts].iov_base, ptmp, clen);
			poutarr[nouts].iov_len = clen;

			nouts++;
			len -= clen;
			ptmp += clen;
		}

	done :	
		*pcopied_elem = nouts;
		
		if (ptmp > pend) {
			ptmp = pend;
		}

		if (ptmp < pin) {
			ptmp = pin;
		}

		return ptmp - porigin;
	}

};

template <typename RFCB = SHM_POOL_MEMCPY_CB>
class SHM_POOL 
{
public :
	std::atomic <uint32_t>	logical_head			__attribute__((aligned(128)));
	uint64_t		shm_write_cnt;
	uint64_t		shm_block_cnt;
	uint64_t		shm_write_bytes;
	uint64_t		shm_block_bytes;
	uint64_t		nunlocks;

	std::atomic <uint32_t>	logical_tail			__attribute__((aligned(128)));
	uint64_t		shm_read_cnt;
	uint64_t		shm_read_bytes;
	std::atomic <int>	reader_active;

	pthread_mutex_t		shmmutex			__attribute__((aligned(128)));
	const bool		is_proc_shared;
	pthread_cond_t		shmcond;

	std::atomic <uint32_t>	use_lock_;

	/* totalpoollen = poollen + 1 extra data item size */		

	uint32_t		totalpoollen;			__attribute__((aligned(128)))
	uint32_t		poollen;
	uint32_t		max_elem_size;
	const bool		use_atomic;
	const bool		is_fixlen;
	char			namestr[64];
	uint32_t		poolmagic;
	std::atomic <int>	nattached;

	RFCB			fcb;				/* Used only the reader */

	/*
	 * Default template specialization is SHM_POOL_MEMCPY_CB.
	 * Please create a function object of the callback type to be passed to the constructor.
	 *
	 * The constructor needs to be invoked as a placement new call only XXX
	 *
	 * This implies that the typical single process usage scenario would be :
	 *
	  	uint8_t			*ptmpalloc = nullptr;
	  	int			ret;
	
		// Using placement new as new will not allocate 128 byte aligned memory before C++17
		
		const size_t		poolsz = sizeof(SHM_POOL<SHM_POOL_MEMCPY_CB>) + (maxelems + 1) * sz_elem;

		ret = posix_memalign((void **)&ptmpalloc, 128, poolsz + 16);

		if (ret || !ptmpalloc) {
			errno = ret;
			GY_THROW_SYS_EXCEPTION("Failed to allocate memory for Shm Pool");
		}

	  	SHM_POOL_MEMCPY_CB	fcb();		// Or your defined Callback class
	 
	 	try {
	  		new (ptmpalloc) SHM_POOL<SHM_POOL_MEMCPY_CB>(poolsz, sz_elem, 0/1, 0/1, 0/1, "test pool", fcb);		// placement new
		}
		catch(...) {
			free(ptmpalloc);
		}	

	 */
	SHM_POOL(uint32_t poollenin, uint32_t max_elem_sizein, bool is_proc_sharedin, bool use_atomicin, bool is_fixlenin, const char *pnamein, RFCB fcbin) :
		logical_head(0), shm_write_cnt(0), shm_block_cnt(0), shm_write_bytes(0), shm_block_bytes(0), nunlocks(0),
		logical_tail(0), shm_read_cnt(0), shm_read_bytes(0), is_proc_shared(is_proc_sharedin), use_lock_(use_atomicin ? 0 : 1), 
		totalpoollen(0), poollen(0), max_elem_size(max_elem_sizein),  
		use_atomic(use_atomicin), is_fixlen(is_fixlenin), namestr(), poolmagic(0), nattached(1), fcb(fcbin)
	{
		
		if ((poollenin < sizeof(*this) + max_elem_sizein * 5) || (max_elem_sizein > poollenin/2) || 
			(max_elem_sizein == 0) || (!pnamein)) {
			
			GY_THROW_EXCEPTION("Shm Pool Initialization : Invalid input parameters seen.");
		}

		totalpoollen 	= poollenin - sizeof(*this);
		poollen 	= totalpoollen - max_elem_size - sizeof(*this);
		poollen		-= poollen % max_elem_size;

		std::memset((char *)this + sizeof(*this) + poollen, 0, max_elem_size);

		strncpy(namestr, pnamein, sizeof(namestr) - 1);

		pthread_mutexattr_t		sh_mattr;
		pthread_condattr_t		sh_cattr;

		pthread_mutexattr_init(&sh_mattr);
		pthread_condattr_init(&sh_cattr);

		if (is_proc_shared) {
			pthread_mutexattr_setpshared(&sh_mattr, PTHREAD_PROCESS_SHARED);
			pthread_condattr_setpshared(&sh_cattr, PTHREAD_PROCESS_SHARED);
		}

		int ret = pthread_mutex_init(&shmmutex, &sh_mattr);
		if (ret != 0) {
			if (ret != EBUSY) {
				GY_THROW_SYS_EXCEPTION("Shmpool pthread mutex initialization failed");
			}
		}

		ret = pthread_cond_init(&shmcond, &sh_cattr);
		if (ret != 0) {
			if (ret != EBUSY) {
				GY_THROW_SYS_EXCEPTION("Shm pool pthread cond initialization failed");
			}
		}

		pthread_mutexattr_destroy(&sh_mattr);
		pthread_condattr_destroy(&sh_cattr);

		GY_CC_BARRIER();

		poolmagic = SHM_POOL_MAGIC;
	}


	/*
	 * Constructor to be used in case the pool has already been initialized (e.g. For use in multi-process environments)
	 */ 
	SHM_POOL(RFCB fcbin) : fcb(fcbin)
	{
		if (!is_init()) {
			GY_THROW_EXCEPTION("Shm Pool default constructor called without initialization...");
		}

		pthread_mutexattr_t		sh_mattr;
		pthread_condattr_t		sh_cattr;

		pthread_mutexattr_init(&sh_mattr);
		pthread_condattr_init(&sh_cattr);

		if (is_proc_shared) {
			pthread_mutexattr_setpshared(&sh_mattr, PTHREAD_PROCESS_SHARED);
			pthread_condattr_setpshared(&sh_cattr, PTHREAD_PROCESS_SHARED);
		}

		int ret = pthread_mutex_init(&shmmutex, &sh_mattr);
		if (ret != 0) {
			if (ret != EBUSY) {
				GY_THROW_SYS_EXCEPTION("Shmpool pthread mutex initialization failed");
			}
		}

		ret = pthread_cond_init(&shmcond, &sh_cattr);
		if (ret != 0) {
			if (ret != EBUSY) {
				GY_THROW_SYS_EXCEPTION("Shm pool pthread cond initialization failed");
			}
		}

		pthread_mutexattr_destroy(&sh_mattr);
		pthread_condattr_destroy(&sh_cattr);

		nattached.fetch_add(1, std::memory_order_release);

		shm_write_cnt 	= 0;
		shm_block_cnt 	= 0;
		shm_read_cnt  	= 0;
		nunlocks	= 0;

		shm_write_bytes = 0;
		shm_block_bytes = 0;
		shm_read_bytes  = 0;
	}


	~SHM_POOL()
	{
		if (shm_write_cnt || shm_read_cnt) {
			INFOPRINT("Shm Pool %s Destroying... : Total Writes = %lu Reads = %lu Wr Dropped = %lu : "
				"Write bytes %lu Read Bytes %lu Wr Blocked Bytes %lu Unlocks %lu\n", 
				namestr, shm_write_cnt, shm_read_cnt, shm_block_cnt, shm_write_bytes, 
				shm_read_bytes, shm_block_bytes, nunlocks);
		}

		int		noldattach  = nattached.fetch_sub(1, std::memory_order_acq_rel);

		if (noldattach == 1) {
			// shmmutex && shmcond need to be destroyed only if both reader and writer objects destroyed
			pthread_cond_destroy(&shmcond);
			pthread_mutex_destroy(&shmmutex);

			poolmagic = 0;
		}	
	}

	/*
	 * write_pool :
	 *
	 * Returns 0 in case of success.
	 * Returns 1 to indicate Blocking as no space available
	 * Returns -1 for other failures.
	 *
	 * ppwraddr will specify the first location of written data. XXX Do not use this for multi process shmpools
	 */
	int write_pool(const struct iovec *piov, int iovcnt, char **ppwraddr = nullptr) noexcept
	{
		uint32_t 		sz = 0, lhead, ltail, head, tail;
		uint32_t		use_lock, nspins = 0;
		int			t, j;
		char * const		pdatablock = (char *)this + sizeof(*this), *pdataend;

		pdataend = pdatablock + poollen;

		for (t = 0; t < iovcnt; t++) {
			sz += piov[t].iov_len;
		}
		
		if (sz > 0) { 
			if (sz > max_elem_size) {
				ERRORPRINT("Shm Pool %s : Invalid write pool buffer size %u > max %u\n", namestr, sz, max_elem_size);
				return -1;
			}
		}		
		else {
			return -1;
		}	

start:
		use_lock = use_lock_.load(std::memory_order_acquire);

		if (use_lock) {
			proc_mutex_lock(&shmmutex, is_proc_shared);
		}	

		lhead = logical_head.load(std::memory_order_relaxed);
		ltail = logical_tail.load(std::memory_order_acquire);	

		head = lhead % poollen;
		tail = ltail % poollen;

		if ((lhead - ltail + sz) >= poollen) {
			if (use_lock == 0) {
				if (nspins++ < 100) {
					goto start;
				}
			}
			else {
				pthread_cond_signal(&shmcond);
				if (++nspins < 5) {
					pthread_mutex_unlock(&shmmutex);
					goto start;
				}
			}	
			
			++shm_block_cnt;
			shm_block_bytes += sz;

			if (use_lock) {
				pthread_mutex_unlock(&shmmutex);
			}	

			return 1;
		}

		if (lhead > 0xFD000000) { /*do not let logical values grow too big*/
			if (use_lock == 0) {
				use_lock_.store(1, std::memory_order_release);
				use_lock = 1;
					
				sched_yield();

				DEBUGEXECN(1, INFOPRINTCOLOR(GY_COLOR_GREEN, "Shm Pool %s Trying to reduce head tail...\n", namestr);); 

				while (1 == reader_active.load(std::memory_order_acquire)) {
					sched_yield();
				}

				goto start;
			}
			uint32_t diff = lhead - head;

			lhead = head + poollen;
			ltail -= (diff - poollen);

			logical_head.store(lhead, std::memory_order_relaxed);
			logical_tail.store(ltail, std::memory_order_relaxed);

			DEBUGEXECN(1, INFOPRINTCOLOR(GY_COLOR_GREEN, "Shm Pool %s reducing head, tail by %u : Total Writes %lu Reads %lu Wr Blocks %lu\n", 
					namestr, diff, shm_write_cnt, shm_read_cnt, shm_block_cnt););
		}

		if (ppwraddr && sz) {
			*ppwraddr = pdatablock + head;
		}

		for (t = 0, j = 0; t < iovcnt; t++) {
			if (piov[t].iov_len > 0) {
				memcpy(pdatablock + head + j, piov[t].iov_base, piov[t].iov_len);
				j += piov[t].iov_len;
			}
		}

		lhead += sz;

		logical_head.store(lhead, std::memory_order_relaxed);

		++shm_write_cnt;
		shm_write_bytes += sz;

		if (use_lock == 0) {
			use_lock = use_lock_.load(std::memory_order_acquire);
			
			if (use_lock) {
				proc_mutex_lock(&shmmutex, is_proc_shared);
			}
		}

		if (use_lock) {
			if (use_atomic) {
				use_lock_.store(0, std::memory_order_release);
				nunlocks++;
				use_lock = 0;
			}

			pthread_cond_signal(&shmcond);
			pthread_mutex_unlock(&shmmutex);
		}

		return 0;

	}

	/*
	 * Required Output arr poutarr of at least max_elem_size each, can be an array of iovecs or 
	 * array of structures whatever is specified by way of the callback object.
	 *
	 * minlen can be used to specify the minimum length needed to be copied to each output elem.
	 * pcopied_elem & pcopied_bytes contain the number of array elements updated and the total size
	 *
	 * parg is a void * argument to be sent to the callback.
	 *
	 * Returns 0 in case of success.
	 * Returns 1 in case non-blocking specified (write_pool() is always non-blocking) and opertaion may block.
	 * Returns -1 for other failures.
	 *
	 * Specify is_peek = 1 in case you want to just lookup the data without consuming...
	 * Use is_non_block in case you do not want to wait for data to be written.
	 */

	int read_pool(void *poutarr, uint32_t maxelem, uint32_t minlen, void *parg, uint32_t *pcopied_elem, uint32_t *pcopied_bytes, \
						int is_non_block = 0, int is_peek = 0) noexcept
	{
		uint32_t		use_lock, nspins = 0, ntimes = 0, maxavail;
		uint32_t 		head, tail, lhead, ltail, clen = 0, is_wrap = 0;
		int			ret, alType;
		char 			*top;
		struct timeval		tnow;
		struct timespec		timeout;
		char * const		pdatablock = (char *)this + sizeof(*this), *pdataend;

		pdataend = pdatablock + poollen + max_elem_size;	/* 1 data element beyond the poollen */

	start :
		use_lock = use_lock_.load(std::memory_order_acquire);

		reader_active.store(1, std::memory_order_release);

		if (use_lock) {
			proc_mutex_lock(&shmmutex, is_proc_shared);
		}	

		lhead = logical_head.load(std::memory_order_acquire);
		ltail = logical_tail.load(std::memory_order_relaxed);	

		head = lhead % poollen;
		tail = ltail % poollen;

		if (lhead < ltail + minlen) {
			if (is_peek) {
				// No spins
				nspins = 100;
			}

			if (use_lock == 0) {
				if (nspins++ < 50) {
					reader_active.store(0, std::memory_order_release);
					goto start;
				}

				if (is_non_block) {
					reader_active.store(0, std::memory_order_release);
					*pcopied_elem = 0;
					*pcopied_bytes = 0;
					return 1;
				}
			
				use_lock_.store(1, std::memory_order_release);
				use_lock = 1;
				reader_active.store(0, std::memory_order_release);
						
				sched_yield();

				goto start;
			}
			else {
				if (is_non_block) {
					if (nspins++ < 5) {
						reader_active.store(0, std::memory_order_release);
						pthread_mutex_unlock(&shmmutex);
						goto start;
					}

					reader_active.store(0, std::memory_order_release);
					pthread_mutex_unlock(&shmmutex);

					*pcopied_elem = 0;
					*pcopied_bytes = 0;

					return 1;
				}

				if (ntimes++ >= 100 /* 5 sec */) {
					reader_active.store(0, std::memory_order_release);
					pthread_mutex_unlock(&shmmutex);

					*pcopied_elem = 0;
					*pcopied_bytes = 0;

					return 1;
				}

				reader_active.store(0, std::memory_order_release);

				gettimeofday(&tnow, nullptr);
				
				tnow.tv_usec += 1000 * 50;	// 50 msec
				if (tnow.tv_usec >= 1000 * 1000) {
					tnow.tv_sec++;
					tnow.tv_usec -= 1000 * 1000;
				}
				timeout.tv_sec = tnow.tv_sec;
				timeout.tv_nsec = tnow.tv_usec * 1000;

				ret = pthread_cond_timedwait(&shmcond, &shmmutex, &timeout); 
				if (ret != 0) {
					if (ret != ETIMEDOUT) {
						pthread_mutex_unlock(&shmmutex);

						*pcopied_elem = 0;
						*pcopied_bytes = 0;

						return 1;
					}
				}

				pthread_mutex_unlock(&shmmutex);

				goto start;
			}
		}	
		else {
			maxavail = lhead - ltail;

			uint32_t	tlen1 = (is_fixlen ? 0 : max_elem_size);
	
			if ((uint64_t)tail + maxavail > (uint64_t)poollen + tlen1) {
				maxavail = poollen + tlen1 - tail;
				is_wrap = 1;
			}

			if (maxavail >= minlen) {
				
				if (is_peek && use_lock && use_atomic) {
					/*
					 * Unlock the queue as the peek call could potentially block.
					 * This is assuming a single reader scenario. 
					 */ 
					pthread_mutex_unlock(&shmmutex);
					fcb.is_peek = 1;
				}
				else {
					fcb.is_peek = 0;
				}

				clen = fcb(pdatablock + tail, maxavail, poutarr, maxelem, max_elem_size, parg, pcopied_elem);	
				
				if (clen > 0) {

					if (is_peek == 0) {
						ltail = logical_tail.load(std::memory_order_acquire) + clen;

						logical_tail.store(ltail, std::memory_order_release);

						shm_read_cnt += *pcopied_elem;
						shm_read_bytes += clen;

#if 0
						if ((shm_read_cnt % SHM_DEBUG_CNT) == 0) {
							INFOPRINT("Shm Pool %s : Total Writes = %lu Reads = %lu Wr Blocks = %lu : "
								"Write bytes %lu Read Bytes %lu Wr Blocked Bytes %lu Unlocks %lu : "
								"Callback Skipped Bytes %lu\n", 
								namestr, shm_write_cnt, shm_read_cnt, shm_block_cnt, shm_write_bytes, 
								shm_read_bytes, shm_block_bytes, nunlocks, fcb.skipped_bytes);
						}
#endif						
					}
				}
				else if (is_wrap && !is_peek) {
					ERRORPRINT("Shm pool %s : Invalid Records seen in shm pool wrap around. Skipping %u bytes\n",
						namestr, maxavail);

					ltail = logical_tail.load(std::memory_order_acquire) + maxavail;

					logical_tail.store(ltail, std::memory_order_release);

					fcb.skipped_bytes += maxavail;
				}
			}
			else if (is_wrap && !is_peek) {
				ERRORPRINT("Shm pool %s : Invalid Records seen in shm pool wrap around 2. Skipping %u bytes\n",
					namestr, maxavail);

				ltail = logical_tail.load(std::memory_order_acquire) + maxavail;

				logical_tail.store(ltail, std::memory_order_release);

				fcb.skipped_bytes += maxavail;
			}

			reader_active.store(0, std::memory_order_release);

			if (use_lock && !is_peek) {
				pthread_mutex_unlock(&shmmutex);
			}	

			*pcopied_bytes = clen;

			return ((clen > 0) ? 0 : 1);
		}

		if (use_lock) {
			pthread_mutex_unlock(&shmmutex);
		}	

		*pcopied_elem = 0;
		*pcopied_bytes = 0;

		return 1;
	}	
		
	int data_available() const noexcept
	{
		return ((logical_head.load(std::memory_order_acquire)) > (logical_tail.load(std::memory_order_acquire)));
	}
	
	char * reader_position() const noexcept
	{
		char * const		pdatablock = (char *)this + sizeof(*this);

		return pdatablock + ((logical_tail.load(std::memory_order_relaxed)) % poollen);
	}

	char * writer_position() const noexcept
	{
		char * const		pdatablock = (char *)this + sizeof(*this);

		return pdatablock + ((logical_head.load(std::memory_order_relaxed)) % poollen);
	}

	int is_valid_addr(char *paddrin) const noexcept
	{
		char * const		pdatablock = (char *)this + sizeof(*this), *pdataend;

		pdataend = pdatablock + poollen + max_elem_size;

		return ((paddrin >= pdatablock) && (paddrin < pdataend));
	}

	char * get_end_addr() const noexcept
	{
		char * const		pdatablock = (char *)this + sizeof(*this);

		return pdatablock + poollen + max_elem_size;
	}

	int is_init() const  noexcept
	{
		return poolmagic == SHM_POOL_MAGIC;
	}

	RFCB & get_fcb() noexcept
	{
		return fcb;
	}	

	uint64_t get_wr_count() const noexcept
	{
		return shm_write_bytes;
	}	
	
	uint64_t get_rd_count() const noexcept
	{
		return shm_read_bytes;
	}	

};

} // namespace gyeeta

