//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include 		"gy_pkt_pool.h"
#include 		"gy_rcu_inc.h"
#include 		"gy_file_api.h"
#include		"gy_misc.h"
#include		"gy_print_offload.h"

#include 		<poll.h>
#include 		<sys/mman.h>

namespace gyeeta {

GY_PKT_POOL::GY_PKT_POOL(uint32_t bufcntin, uint32_t lenin, uint32_t max_dyn_buf_sizein, uint32_t drop_dyn_secin, int multi_processin, int is_single_writer,
		const char *pstrin, bool is_reader_rcu_thread, bool is_writer_rcu_thread, int do_realloc_in, 
		PKTPOOL_CHK_FP pfpin, void *paramin, PKTPOOL_BUF_ALLOC_FP pext_bufalloc_fpin, PKTPOOL_BUF_FREE_FP pext_buf_free_fpin)
			:
			is_reader_rcu_thread(is_reader_rcu_thread), is_writer_rcu_thread(is_writer_rcu_thread)
{
	uint32_t		i;
	char			*pmbuf = nullptr;
	pthread_mutexattr_t 	sh_mattr;
	pthread_condattr_t 	sh_cattr;

	assert(bufcntin >= 10);

	lenin = (uint32_t)gy_align_up_2(lenin, 8);

	if (lenin < 8) {
		lenin = 8;
	}

	if (multi_processin) {
		pktpool = (PKT_ELEM *)gy_mmap_alloc((bufcntin + 1) * sizeof(PKT_ELEM), &size_pktpool, 1 /* use_proc_shared */);
		if (!pktpool) {
			GY_THROW_SYS_EXCEPTION("Memory allocation mmap of pool \'%s\' failed for length %lu", pstrin, (bufcntin + 1) * sizeof(PKT_ELEM));
		}

		memset((void *)pktpool, 0, (bufcntin + 1) * sizeof(PKT_ELEM));
	}
	else {
		pktpool = (PKT_ELEM *)calloc_or_throw((bufcntin + 1),  sizeof(PKT_ELEM));
	}	

	bufcnt = bufcntin;
	maxbuflen = lenin;

	chkfp = pfpin;
	param = paramin;

	multi_process = multi_processin;

	pthread_mutexattr_init(&sh_mattr);
	pthread_condattr_init(&sh_cattr);	

	if (multi_process) {
		pthread_mutexattr_setpshared(&sh_mattr, PTHREAD_PROCESS_SHARED);
		pthread_mutexattr_setrobust(&sh_mattr, PTHREAD_MUTEX_ROBUST);

		pthread_condattr_setpshared(&sh_cattr, PTHREAD_PROCESS_SHARED);
	}

	pthread_mutex_init(&mutex, &sh_mattr); 
	pthread_cond_init(&cond, &sh_cattr); 

	pthread_mutexattr_destroy(&sh_mattr);
	pthread_condattr_destroy(&sh_cattr);

	if (multi_process) {
		pmbuf = (char *)gy_mmap_alloc(lenin * bufcntin + 8, &size_pbuf, 1 /* use_proc_shared */);
		if (!pmbuf) {
			int		olderrno = errno;

			gy_mmap_free(pktpool, size_pktpool);
			
			pthread_mutex_destroy(&mutex);
			pthread_cond_destroy(&cond);

			errno = olderrno;

			GY_THROW_SYS_EXCEPTION("Memory allocation mmap of pool \'%s\' buffer of size %u failed", pstrin, lenin * bufcntin + 8);
		}

		max_dyn_buf_size = 0;	/* No dynamic mmap */
		drop_dyn_sec = 0;
		do_realloc = 0;
	}
	else {
		do_realloc = do_realloc_in;

		max_dyn_buf_size = max_dyn_buf_sizein;
		drop_dyn_sec = drop_dyn_secin;
	}

	for (i = 0; i < bufcntin; i++) {
		if (pmbuf == nullptr) {
			pktpool[i].pbuf = (char *)malloc(lenin);
			if (!pktpool[i].pbuf) {
				int		olderrno = errno;

				for (uint32_t j = 0; j < i; j++) {
					free(pktpool[j].pbuf);
				}	

				pthread_mutex_destroy(&mutex);
				pthread_cond_destroy(&cond);

				errno = olderrno;

				GY_THROW_SYS_EXCEPTION("Memory allocation failed for pool \'%s\' elements alloc", pstrin);
			}	
		}
		else {
			pktpool[i].pbuf = pmbuf + i * lenin;
		}
		pktpool[i].dlen = lenin;
		pktpool[i].isvalid.store(0, std::memory_order_relaxed);
	}

	if (pstrin) {
		strncpy(poolstr, pstrin, sizeof(poolstr) - 1);
	}
	else {
		*poolstr = '\0';
	}

	pext_bufalloc_fp = pext_bufalloc_fpin;
	pext_buf_free_fp = pext_buf_free_fpin;

	if (max_dyn_buf_size && !pext_bufalloc_fpin) {
		pext_bufalloc_fpin = malloc;
		pext_buf_free_fp = free;
	}

	use_atomic = is_single_writer;
	
	wr_.store(0, std::memory_order_relaxed);
	rd_.store(0, std::memory_order_relaxed);
	use_lock_.store(use_atomic == 0);

	cmagic = PKT_POOL_MAGIC;

	DEBUGEXECN(1, INFOPRINT("Initialized pool \'%s\' buf %u max dynamic %u drop sec %u multi_process %d use_atomic %d\n",
		poolstr, bufcnt, max_dyn_buf_size, drop_dyn_sec, multi_process, use_atomic));
}

PKT_RET_E GY_PKT_POOL::pool_write_buffer(const uint8_t *pbuf, uint32_t szbuf, uint32_t *count, int is_non_block) noexcept
{
	const struct iovec	iov[1] = {(void *)pbuf, szbuf};

	return pool_write_buffer(iov, 1, count, is_non_block);
}	

PKT_RET_E GY_PKT_POOL::pool_write_buffer(const struct iovec *piov, int iovcnt, uint32_t *count, int is_non_block) noexcept
{
	int 			toblock = 0, ret, stimes = 0, ptimes = 0, drop_cond_hit = 0, isvalid = 0, use_lock;
	int			reset_lock = 0, nspins = 0, t;
	size_t			i, j, inlen = 0;
	struct timeval 		tnow;
	struct timespec 	timeout;
	size_t 			rd, wr, rd_last = 0;
	uint8_t			*pdynbuf, *pbuf;
	PKT_DYN_ELEM		*pdynelem;

	assert(cmagic == PKT_POOL_MAGIC);

	if (gy_unlikely(cmagic != PKT_POOL_MAGIC)) {
		return PKT_RET_ERROR;	
	}

	for (t = 0; t < iovcnt; t++) {
		inlen += piov[t].iov_len;
	}
	
	if (is_writer_rcu_thread) {
		gy_rcu_offline();
	}
		
	use_lock = use_lock_.load(std::memory_order_acquire);
	
	if (use_lock) {
		proc_mutex_lock(&mutex, multi_process);
	}

	/*
	 * We check the pktpool for an empty buf. If not block.
	 * Start from wr & then loop around.
	 */ 
	while (1) {
		toblock = 0;

		/*
		 * Calculate the diff between reader & writer. Max MAX_PKT_TCP_READER_LAG
		 */

		wr = wr_.load(std::memory_order_relaxed);
		i = wr;	

		isvalid = pktpool[i].isvalid.load(std::memory_order_relaxed);

		rd = rd_.load(std::memory_order_acquire);

		if (wr > rd) {
			if ((bufcnt - wr + rd - 1) < MAX_PKT_TCP_READER_LAG) {
				toblock = 1;
				rd_last = rd;
			}
		}
		else if ((rd > wr) && (rd - wr < MAX_PKT_TCP_READER_LAG)) {
			toblock = 1;
			rd_last = rd;
		}

		if (isvalid == 1) { 
			toblock = 1;
		}

		if (use_lock && toblock == 0) {
			if (use_atomic && (pkts_dyn_written == pkts_dyn_read)) {
				reset_lock = 1;
			}
		}

		if (to_reset || wr_exited) {
			if ((wr_exited) && (is_wr_blocking == 1)) {
				wr_exited = 0;
			}
			is_wr_blocking = 0;

			if (use_lock) {
				pthread_mutex_unlock(&mutex);
			}		

			*count = 0;
			return PKT_RET_SIGNAL;
		}

		if (toblock == 1) {

			if (use_lock == 0) {
				if (nspins++ < 30) {
					continue;
				}

				use_lock_.store(1, std::memory_order_release);
				use_lock = 1;
				
				proc_mutex_lock(&mutex, multi_process);

				continue;
			}

			/*
			 * Check if session in a potential deadlock mode. If so add an element to the dyn list
			 * We check the cur_dyn_buf_size. If its < max_dyn_buf_size, then add an elem.
			 * Else, we wait for drop_dyn_sec and then drop this pkt if still not read.
			 */
			if (max_dyn_buf_size > 0) {

				if (gy_unlikely(drop_cond_hit == 1)) {
					pkts_dyn_dropped++;
					tot_pkts_dyn_dropped++;

					is_wr_blocking = 0;

					pthread_cond_signal(&cond);

					pthread_mutex_unlock(&mutex);

					if (pkts_dyn_dropped < 10) {
						INFOPRINT_OFFLOAD("Pool Writer Dropping record for pool \'%s\' because of stalemate. Dyn size = %u\n", 
							poolstr, cur_dyn_buf_size);
					}

					*count = 0;
					return PKT_RET_ERROR;
				}

				pbuf = nullptr;

				if (cur_dyn_buf_size + inlen > max_dyn_buf_size) {
					if (pext_bufalloc_fp) {
						try {
							pbuf = (uint8_t *)(*pext_bufalloc_fp)(sizeof(PKT_DYN_ELEM) + inlen + 16);
						}
						catch(...) {
						}	
					}
					if (pbuf) {
						pdynbuf = pbuf;
						goto buf_avail;
					}

					if (pkts_written - last_cond_wr_cnt > 1000) {
						last_cond_wr_cnt = pkts_written;
						pthread_cond_signal(&cond);
					}

					if ((drop_dyn_sec) && ((uint32_t)stimes >= drop_dyn_sec * 10)) {
						drop_cond_hit = 1;
					}
				}
				else {
					pdynbuf = (uint8_t *)malloc(sizeof(PKT_DYN_ELEM) + inlen + 16);
					if (!pdynbuf) {
						goto delay_wr;
					}
buf_avail :
					pdynelem = (PKT_DYN_ELEM *)pdynbuf;

					pdynelem->pbuf = pdynbuf + sizeof(PKT_DYN_ELEM);
					pdynelem->next = nullptr;

					pdynelem->len = inlen;
					if (pbuf == nullptr) {
						pdynelem->is_external_buf = 0;
					}
					else {
						pdynelem->is_external_buf = 1;
					}

					for (t = 0, j = 0; t < iovcnt; t++) {
						if (piov[t].iov_len > 0) {
							memcpy(pdynelem->pbuf + j, piov[t].iov_base, piov[t].iov_len);
							j += piov[t].iov_len;
						}
					}
					*count = inlen;
					
					if (!pktpool[i].pdyntail) {
						pktpool[i].pdynhead = pdynelem;
						pktpool[i].pdyntail = pdynelem;
					}
					else {
						pktpool[i].pdyntail->next = pdynelem;
						pktpool[i].pdyntail = pdynelem;
					}

					pktpool[i].cur_dyn_pkts++;
					pktpool[i].cur_dyn_buf_size += inlen;

					pkts_dyn_written++;
					tot_pkts_dyn_written++;
					cur_dyn_buf_size += inlen;

					goto done_wr;
				}
			}

delay_wr :
			if (is_non_block) {
				*count = 0;
				is_wr_blocking = 0;

				if ((is_rd_blocking == 1) || (pkts_written - last_cond_wr_cnt > 1000)) {
					last_cond_wr_cnt = pkts_written;
					pthread_cond_signal(&cond);
				}

				pthread_mutex_unlock(&mutex);
				return PKT_BLOCKING;
			}

			if (to_reset || wr_exited) {
				*count = 0;
				if (wr_exited) {
					wr_exited = 0;
				}
				is_wr_blocking = 0;

				pthread_mutex_unlock(&mutex);

				return PKT_RET_SIGNAL;
			}

			if ((is_rd_blocking == 1) || (pkts_written - last_cond_wr_cnt > 1000)) {
				last_cond_wr_cnt = pkts_written;
				pthread_cond_signal(&cond);
			}

			is_wr_blocking = 1;	

			if (ptimes > 30) {
				INFOPRINT_OFFLOAD("Pool Writer thread %d blocking for pool \'%s\' Dyn Size = %u Dyn Buffers = %u "
					"Records Written %lu Read %lu\n", 
					gy_gettid(), poolstr, cur_dyn_buf_size, pktpool[i].cur_dyn_pkts, pkts_written, pkts_read);
				ptimes = 0;
			}
			else if (ptimes > 10) {
				DEBUGEXECN(1, INFOPRINT_OFFLOAD("Pool Writer thread %d blocking for pool \'%s\' Dyn Size = %u Dyn Buffers = %u "
					"Records Written %lu Read %lu\n", 
					gy_gettid(), poolstr, cur_dyn_buf_size, pktpool[i].cur_dyn_pkts, pkts_written, pkts_read));
			}

			++ptimes;

			ret = 0;

			gettimeofday(&tnow, nullptr);
			
			tnow.tv_usec += 1000 * 100;	// msec
			if (tnow.tv_usec >= 1000 * 1000) {
				tnow.tv_sec++;
				tnow.tv_usec -= 1000 * 1000;
			}
			timeout.tv_sec = tnow.tv_sec;
			timeout.tv_nsec = tnow.tv_usec * 1000;

			if (rd_last == rd) {
				// Check if reader no longer reading this pool
				if (chkfp && pkts_dyn_dropped) {

					pthread_mutex_unlock(&mutex);

					try {
						ret = (*chkfp)(param);
					}
					catch(...) {
						ret = -1;
					}		

					if (ret < 0) {
						proc_mutex_lock(&mutex, multi_process);

						is_wr_blocking = 0;
						pkts_dyn_dropped++;
						tot_pkts_dyn_dropped++;

						if ((is_rd_blocking == 1) || ((pkts_written - last_cond_wr_cnt > 1000))) { 
							last_cond_wr_cnt = pkts_written;
							pthread_cond_signal(&cond);
						} 

						pthread_mutex_unlock(&mutex);

						WARNPRINT_OFFLOAD("Pool Writer dropping record for pool \'%s\' because of "
							"reader stop. Dyn size = %u Dropped Records %lu\n", 
							poolstr, cur_dyn_buf_size, pkts_dyn_dropped);

						*count = 0;
						return PKT_RET_ERROR;
					}
					else {
						proc_mutex_lock(&mutex, multi_process);
					}
				}


				pkts_wr_waits++;
				tot_pkts_wr_waits++;

				ret = pthread_cond_timedwait(&cond, &mutex, &timeout);

				rd = rd_.load(std::memory_order_acquire);

				if (to_reset || wr_exited || (ret == EINTR)) {
					*count = 0;

					if (wr_exited) {
						wr_exited = 0;
					}
					is_wr_blocking = 0;

					pthread_mutex_unlock(&mutex);

					return PKT_RET_SIGNAL;
				}
				else if (rd_last == rd) {
					// Check if reader no longer reading this pool
					if (chkfp) {
						pthread_mutex_unlock(&mutex);

						try {
							ret = (*chkfp)(param);
						}
						catch(...) {
							ret = -1;	
						}
								
						if (ret < 0) {
							proc_mutex_lock(&mutex, multi_process);

							is_wr_blocking = 0;
							pkts_dyn_dropped++;
							tot_pkts_dyn_dropped++;

							if ((is_rd_blocking == 1) || ((pkts_written - last_cond_wr_cnt > 1000))) { 
								last_cond_wr_cnt = pkts_written;
								pthread_cond_signal(&cond);
							} 

							pthread_mutex_unlock(&mutex);

							WARNPRINT_OFFLOAD("Pool Writer dropping record for pool \'%s\' because of "
								"Reader stop. Dyn size = %u Dropped Records %lu\n", 
								poolstr, cur_dyn_buf_size, pkts_dyn_dropped);

							*count = 0;
							return PKT_RET_ERROR;
						}
						else {
							proc_mutex_lock(&mutex, multi_process);
						}
					}
				}
				stimes++;
				ptimes++;
			}

/* 			i = wr; */
			continue;
		}

		// Ok we have the buf

		if (inlen > pktpool[i].dlen) {

			if ((multi_process == 0) && (do_realloc)) {
				char		*ptbuf = pktpool[i].pbuf;	

				pktpool[i].pbuf = (char *)malloc(inlen + 128);
				if (!pktpool[i].pbuf) {
					PERRORPRINT_OFFLOAD("Could not allocate pktpool buffer of larger size");

					pktpool[i].pbuf = ptbuf;
	
					if (use_lock) {
						pthread_mutex_unlock(&mutex);
					}		
					*count = 0;
					return PKT_RET_ERROR;
				}	
				pktpool[i].dlen = inlen + 128;
				free(ptbuf);
			}
			else {
				is_wr_blocking = 0;
				if (use_lock) {
					pthread_mutex_unlock(&mutex);
				}		
				*count = 0;

				CONDEXEC(
					WARNPRINT_OFFLOAD("Pool \'%s\' buffer size overflow... Dropping record of len : %u\n", poolstr, (uint32_t)inlen);
				);

				return PKT_RET_ERROR;
			}
		}

		for (t = 0, j = 0; t < iovcnt; t++) {
			if (piov[t].iov_len > 0) {
				memcpy(pktpool[i].pbuf + j, piov[t].iov_base, piov[t].iov_len);
				j += piov[t].iov_len;
			}
		}

		*count = (uint32_t)inlen;

		pktpool[i].len = (uint32_t)inlen;
		pktpool[i].isvalid.store(1, std::memory_order_relaxed);

		break;
	}

	wr++;
	if (wr == bufcnt) {
		wr = 0;
	}

	wr_.store(wr, std::memory_order_relaxed);

done_wr :
	is_pktpool_used = 1;


	pkts_written++;
	tot_pkts_written++;

	// Now signal the reader that data is available
	is_wr_blocking = 0;

	if (use_lock == 0) {
		use_lock = use_lock_.load(std::memory_order_acquire);
		
		if (use_lock) {
			proc_mutex_lock(&mutex, multi_process);
		}
	}

	if (is_rd_blocking == 1) { 
		if (use_lock == 0) {
			use_lock = 1;

			proc_mutex_lock(&mutex, multi_process);
		}

		if (is_rd_blocking == 1) { 
			pthread_cond_signal(&cond);
		}	
	} 

	if (use_lock) {
		pkts_wr_under_lock++;
		tot_pkts_wr_under_lock++;

		pthread_mutex_unlock(&mutex);

		if (reset_lock) {
			use_lock_.store(0, std::memory_order_release);

			lock_resets++;
			tot_lock_resets++;
		}
	}

	return PKT_RET_SUCCESS;
}


PKT_RET_E GY_PKT_POOL::pool_read_buffer(uint8_t *buf, uint32_t size, uint32_t *count, int is_non_block, uint32_t max_wait_msec) noexcept
{
	int 			ret, stimes, isvalid, use_lock, nspins = 0, ntimeouts = 0;
	size_t			i;
	PKT_DYN_ELEM		*pelem = nullptr;
	struct timeval 		tnow;
	struct timespec 	timeout;

	assert(cmagic == PKT_POOL_MAGIC);

	if (gy_unlikely(cmagic != PKT_POOL_MAGIC)) {
		return PKT_RET_ERROR;
	}

	if (is_reader_rcu_thread) {
		gy_rcu_offline();
	}

	use_lock = use_lock_.load(std::memory_order_acquire);
	
	if (use_lock) {
		proc_mutex_lock(&mutex, multi_process);
	}

	/*
	 * We check the pktpool for an empty buf. If not block.
	 * Start from rd & then loop around.
	 */ 

	i = rd_.load(std::memory_order_acquire);

	while (1) {
	
		if ((use_lock == 0) && (nspins > 0)) {
			use_lock = use_lock_.load(std::memory_order_acquire);
			
			if (use_lock) {
				proc_mutex_lock(&mutex, multi_process);
			}
		}

		if (use_lock && to_reset) {

			pthread_mutex_unlock(&mutex);

			INFOPRINT("Pool Reader for \'%s\' : Returning because of exit/reset signal\n", poolstr); 
			*count = 0;
			return PKT_RET_SIGNAL;
		}

		if (pktpool[i].pdynhead) {

			if (use_lock == 0) {
				use_lock = 1;
				proc_mutex_lock(&mutex, multi_process);

				if ((pktpool[i].pdynhead) && (0 == use_lock_.load(std::memory_order_acquire))) {
					use_lock_.store(1, std::memory_order_release);
				}
				continue;
			}

			pelem = pktpool[i].pdynhead;

			if (pelem->next) {
				pktpool[i].pdynhead = pelem->next;
			}
			else {
				pktpool[i].pdynhead = nullptr;
				pktpool[i].pdyntail = nullptr;
			}
					
			pktpool[i].cur_dyn_pkts--;
			pktpool[i].cur_dyn_buf_size -= pelem->len;
			
			cur_dyn_buf_size -= pelem->len;
			pkts_dyn_read++;
			tot_pkts_dyn_read++;

			if (size > pelem->len) {
				size = pelem->len;
			}
			goto read_done;
		}

		isvalid = pktpool[i].isvalid.load(use_lock == 0 ? std::memory_order_seq_cst : std::memory_order_acquire);

		if (isvalid == 0) {

			if (use_lock == 0) {
				if (nspins++ < 30) {
					continue;
				}

				if (is_non_block) {
					if (is_wr_blocking == 1) { 
						pthread_cond_signal(&cond);
					} 
					return PKT_BLOCKING;
				}

				use_lock_.store(1, std::memory_order_release);
				use_lock = 1;
				
				proc_mutex_lock(&mutex, multi_process);

				continue;
			}

			if (wr_exited && (isvalid == 0)) {
				pthread_mutex_unlock(&mutex);

				*count = 0;
				return PKT_RET_SIGNAL;
			}	

			if (is_non_block) {
				if (is_wr_blocking == 1) { 
					pthread_cond_signal(&cond);
				} 

				pthread_mutex_unlock(&mutex);
				return PKT_BLOCKING;
			}

			if (to_reset) {
				*count = 0;
				pthread_mutex_unlock(&mutex);
				return PKT_RET_SIGNAL;
			}

			is_rd_blocking = 1;	

			ret = 0;
			stimes = 0;

			if (max_wait_msec > 0) {
				if (max_wait_msec > 20) {
					ntimeouts = 2;
				}
			}	
			
			while (1) {

				i = rd_.load(std::memory_order_acquire);
				isvalid = pktpool[i].isvalid.load(std::memory_order_seq_cst);

				if (isvalid == 0) {
					if (pktpool[i].pdynhead) {
						break;
					}

					if (ntimeouts++ < 2) {
						gettimeofday(&tnow, nullptr);
						
						tnow.tv_usec += 1000 * ntimeouts * 10;	// msec
						if (tnow.tv_usec >= 1000 * 1000) {
							tnow.tv_sec++;
							tnow.tv_usec -= 1000 * 1000;
						}
						timeout.tv_sec = tnow.tv_sec;
						timeout.tv_nsec = tnow.tv_usec * 1000;

						ret = pthread_cond_timedwait(&cond, &mutex, &timeout);
					}
					else if (max_wait_msec > 0) {
						auto dsec 	= max_wait_msec/1000;
						auto dmsec 	= max_wait_msec % 1000;

						gettimeofday(&tnow, nullptr);
						
						tnow.tv_usec += 1000 * dmsec;
						tnow.tv_sec += dsec;

						if (tnow.tv_usec >= 1000'000) {
							tnow.tv_usec = 0;
							tnow.tv_sec++;
						}

						timeout.tv_sec = tnow.tv_sec;
						timeout.tv_nsec = tnow.tv_usec * 1000;

						ret = pthread_cond_timedwait(&cond, &mutex, &timeout);
					}
					else {
						ret = pthread_cond_wait(&cond, &mutex);
					}

					isvalid = pktpool[i].isvalid.load(std::memory_order_relaxed);

					if (to_reset || (ret == EINTR)) {
						pthread_mutex_unlock(&mutex);

						*count = 0;
						return PKT_RET_SIGNAL;
					}
				
					if ((isvalid == 0) && (wr_exited)) {
						pthread_mutex_unlock(&mutex);

						*count = 0;
						return PKT_RET_SIGNAL;
					}

					if (isvalid == 0 && max_wait_msec) {
						pthread_mutex_unlock(&mutex);

						*count = 0;
						return PKT_BLOCKING;
					}

					stimes++;
					if (stimes > 10) {
						break;
					}
				}
				else {
					break;
				}
			}

			i = rd_.load(std::memory_order_acquire);

			continue;
		}

		// Ok we have the buf
		if (size > pktpool[i].len) {
			size = pktpool[i].len;
		}
		memcpy(buf, pktpool[i].pbuf, size);
		*count = size;
    
		pktpool[i].isvalid.store(0, std::memory_order_relaxed);

		break;
	}

	i++;
	if (i == bufcnt) {
		i = 0;
	}

	rd_.store(i, std::memory_order_release);

read_done :
	pkts_read++;
	tot_pkts_read++;
	
	// Now signal the writer that data has been read
	is_rd_blocking = 0;

	if (use_lock == 0) {
		use_lock = use_lock_.load(std::memory_order_acquire);
		
		if (use_lock) {
			proc_mutex_lock(&mutex, multi_process);
		}
	}

	if (is_wr_blocking == 1) { 
		if (use_lock == 0) {
			use_lock = 1;

			proc_mutex_lock(&mutex, multi_process);
		}

		if (is_wr_blocking == 1) { 
			pthread_cond_signal(&cond);
		}
	} 

	if (pelem) {
		memcpy(buf, pelem->pbuf, size);
		*count = size;

		if (pelem->is_external_buf == 0) {
			free(pelem);
		}
		else if (pext_buf_free_fp == nullptr) {
			free(pelem);
		}
		else {
			try {
				(*pext_buf_free_fp)(pelem);
			}
			catch(...) {
				
			}		
		}
	}

	if (use_lock) {
		pkts_rd_under_lock++;
		tot_pkts_rd_under_lock++;

		pthread_mutex_unlock(&mutex);
	}

	return PKT_RET_SUCCESS;
}

static thread_local size_t		gsaved_wr = ~0lu;

/*
 * Zero copy, non-blocking write method. Please refer to gy_pkt_pool.h for details on using this method.
 */
 
PKT_RET_E GY_PKT_POOL::pool_get_write_buf(uint8_t **ppdatabuf, size_t *pbufsize, bool is_non_block) noexcept 
{
	int		ret, toblock = 0, isvalid;
	size_t 		rd, wr, i;

	assert(cmagic == PKT_POOL_MAGIC);

	if (gy_unlikely(cmagic != PKT_POOL_MAGIC)) {
		return PKT_RET_ERROR;	
	}

	if (!is_non_block && is_writer_rcu_thread) {
		gy_rcu_offline();
	}

	use_lock_.store(1, std::memory_order_release);

	if (is_non_block) {
		int			ntries = 0;

		do {
			ret = proc_mutex_trylock(&mutex, multi_process);
		} while (ret != 0 && ++ntries < 10);

		if (ret != 0) {
			return PKT_BLOCKING;
		}	
	}
	else {	
		proc_mutex_lock(&mutex, multi_process);
	}	

	wr = wr_.load(std::memory_order_relaxed);
	i = wr;	

	isvalid = pktpool[i].isvalid.load(std::memory_order_relaxed);

	rd = rd_.load(std::memory_order_acquire);

	if (wr > rd) {
		if ((bufcnt - wr + rd - 1) < MAX_PKT_TCP_READER_LAG) {
			toblock = 1;
		}
	}
	else if ((rd > wr) && (rd - wr < MAX_PKT_TCP_READER_LAG)) {
		toblock = 1;
	}

	if (isvalid == 1) { 
		toblock = 1;
	}

	if (to_reset || wr_exited) {
		if ((wr_exited) && (is_wr_blocking == 1)) {
			wr_exited = 0;
		}
		is_wr_blocking = 0;

		pthread_mutex_unlock(&mutex);

		*ppdatabuf = nullptr;
		*pbufsize = 0;
		return PKT_RET_SIGNAL;
	}

	if (toblock == 1) {
		pthread_mutex_unlock(&mutex);

		*ppdatabuf = nullptr;
		*pbufsize = 0;
		return PKT_BLOCKING;
	}

	// Ok we have the buf
	*ppdatabuf = (uint8_t *)pktpool[wr].pbuf;
	*pbufsize = pktpool[wr].dlen;
	
	gsaved_wr = wr;

	return PKT_RET_SUCCESS;
}

PKT_RET_E GY_PKT_POOL::pool_save_write_buf(uint8_t *pdatabuf, size_t nbytes) noexcept
{
	PKT_RET_E	retp = PKT_RET_ERROR;
	size_t		wr;

	/*
	 * We already hold the pool lock
	 */
	if (nbytes > 0) {
		wr = gsaved_wr;

		assert(wr < bufcnt);

		if (wr >= bufcnt) {
			ERRORPRINT_OFFLOAD("Invalid writer position %lu in pool save buffer : Please check if same thread invoked the get method()...\n", wr);
			return retp;
		}

		if (nbytes > pktpool[wr].dlen) {
			ERRORPRINT_OFFLOAD("Invalid number of bytes written %lu to pool save buffer...\n", nbytes);
			goto done;
		}

		if ((char *)pdatabuf != pktpool[wr].pbuf) {
			ERRORPRINT_OFFLOAD("Invalid buffer address for pool save buffer...\n");
			goto done;
		}

		pktpool[wr].len = nbytes;
		pktpool[wr].isvalid.store(1, std::memory_order_relaxed);

		wr++;
		if (wr == bufcnt) {
			wr = 0;
		}

		wr_.store(wr, std::memory_order_relaxed);

		is_pktpool_used = 1;

		pkts_written++;
		tot_pkts_written++;

		// Now signal the reader that data is available
		is_wr_blocking = 0;

		if (is_rd_blocking == 1) { 
			pthread_cond_signal(&cond);
		} 

		retp = PKT_RET_SUCCESS;
	}
	
done :
	pthread_mutex_unlock(&mutex);

	gsaved_wr = ~0lu;

	return retp;
}


void GY_PKT_POOL::pool_set_wr_exited(void) noexcept
{
	if (cmagic != PKT_POOL_MAGIC) {
		return;
	}

	if (is_writer_rcu_thread) {
		gy_rcu_offline();
	}

	use_lock_.store(1, std::memory_order_release);

	proc_mutex_lock(&mutex, multi_process);

	wr_exited = 1;

	if (is_rd_blocking == 1) { 
		pthread_cond_signal(&cond);
	} 
	pthread_mutex_unlock(&mutex);

}

void GY_PKT_POOL::pool_set_reset_signal(void) noexcept
{
	if (cmagic != PKT_POOL_MAGIC) {
		return;
	}

	if (is_writer_rcu_thread || is_reader_rcu_thread) {
		gy_rcu_offline();
	}

	use_lock_.store(1, std::memory_order_release);

	proc_mutex_lock(&mutex, multi_process);

	to_reset = 1;

	if (is_rd_blocking == 1) { 
		pthread_cond_signal(&cond);
	} 

	pthread_mutex_unlock(&mutex);
}

int GY_PKT_POOL::pool_release_mmap_buffers(void) noexcept
{
	if (cmagic != PKT_POOL_MAGIC) {
		return 1;
	}

	if ((multi_process == 0) || (size_pbuf == 0) || (!pktpool[0].pbuf)) {
		return 1;
	}

	INFOPRINT("Pool %s : Releasing mmap buffers...\n", poolstr);

	gy_mmap_free(pktpool[0].pbuf, size_pbuf);

	return 0;
}

void GY_PKT_POOL::print_cumul_stats(int is_unlocked) noexcept
{
	if (cmagic != PKT_POOL_MAGIC) {
		return;
	}

	if (is_unlocked) {
		INFOFDUNLOCKPRINT(STDOUT_FILENO, "Pool \'%s\' : Total Records Written %lu Read %lu Dyn Written %lu Dyn Read %lu Dyn Dropped %lu "
			"Wrwaits %lu Lockwrites %lu Lockreads %lu Lock Resets %lu\n", 
			poolstr, tot_pkts_written, tot_pkts_read, tot_pkts_dyn_written, 
			tot_pkts_dyn_read, tot_pkts_dyn_dropped, tot_pkts_wr_waits, tot_pkts_wr_under_lock, 
			tot_pkts_rd_under_lock, tot_lock_resets);

	}
	else {
		INFOPRINT("Pool \'%s\' : Total Records Written %lu Read %lu Dyn Written %lu Dyn Read %lu Dyn Dropped %lu "
			"Wrwaits %lu Lockwrites %lu Lockreads %lu Lock Resets %lu\n", 
			poolstr, tot_pkts_written, tot_pkts_read, tot_pkts_dyn_written, 
			tot_pkts_dyn_read, tot_pkts_dyn_dropped, tot_pkts_wr_waits, tot_pkts_wr_under_lock, 
			tot_pkts_rd_under_lock, tot_lock_resets);
	}
}

int GY_PKT_POOL::pool_reset(int realloc_buf, uint32_t newsz) noexcept
{
	PKT_DYN_ELEM		*pelem, *phead;
	char			*pmbuf = nullptr;
	uint32_t		i;

	if (cmagic != PKT_POOL_MAGIC) {
		return 1;
	}

	if (is_writer_rcu_thread || is_reader_rcu_thread) {
		gy_rcu_offline();
	}

	use_lock_.store(1, std::memory_order_release);

	proc_mutex_lock(&mutex, multi_process);

	INFOPRINT("Pool %s resetting : Records Written %lu Read %lu Dyn Written %lu Dyn Read %lu Dyn Dropped %lu"
		" Wr Waits %lu Lockwrites %lu Lockreads %lu Lock Resets %lu\n\n",
		poolstr, pkts_written, pkts_read, pkts_dyn_written, 
		pkts_dyn_read, pkts_dyn_dropped, pkts_wr_waits, pkts_wr_under_lock, pkts_rd_under_lock,
		lock_resets);

	wr_.store(0, std::memory_order_relaxed);
	rd_.store(0, std::memory_order_relaxed);
	
	pkts_written = pkts_read = 0ull;
	pkts_dyn_dropped = 0ull;
	pkts_dyn_written = 0ull;
	pkts_dyn_read = 0ull;
	pkts_wr_waits = 0ull;
	pkts_wr_under_lock = 0ull;
	pkts_rd_under_lock = 0ull;
	lock_resets = 0ull;

	to_reset = 0;

	wr_exited = 0;

	for (i = 0; i < bufcnt; i++) {
		pktpool[i].isvalid.store(0, std::memory_order_relaxed);
		
		phead = pktpool[i].pdynhead;
		while (phead) {
			pelem = phead;
			phead = phead->next;

			if (pelem->is_external_buf == 0) {
				free(pelem);
			}
			else if (pext_buf_free_fp == nullptr) {
				free(pelem);
			}
			else {
				try {
					(*pext_buf_free_fp)(pelem);
				}
				catch(...) {
				
				}
			}
		}

		pktpool[i].cur_dyn_buf_size = 0;
		pktpool[i].cur_dyn_pkts = 0;
		pktpool[i].pdynhead = nullptr;
		pktpool[i].pdyntail = nullptr;
	}

	cur_dyn_buf_size = 0;

	if (realloc_buf && newsz) {
		maxbuflen = (uint32_t)gy_align_up_2(newsz, 8);

		if (maxbuflen < 8) {
			maxbuflen = 8;
		}

		DEBUGEXECN(1, INFOPRINT("Reallocating pool %s buffer size to %u\n", poolstr, maxbuflen););
	
		if (multi_process == 0) {
			for (i = 0; i < bufcnt; i++) {
				free(pktpool[i].pbuf);
				pktpool[i].pbuf = nullptr;
			}
		}
		else {
			gy_mmap_free(pktpool[0].pbuf, size_pbuf);
			pktpool[0].pbuf = nullptr;

			pmbuf = (char *)gy_mmap_alloc(maxbuflen * bufcnt + 8, &size_pbuf, 1 /* use_proc_shared */);
			if (!pmbuf) {
				PERRORPRINT("mmap of pktpool buffer failed for pool realloc failed for length %u", maxbuflen * bufcnt + 8);
				
				cmagic = 0;
				pthread_mutex_unlock(&mutex);

				return -1;
			}

			max_dyn_buf_size = 0;	/* No dynamic mmap */
		}


		for (i = 0; i < bufcnt; i++) {
			if (pmbuf == nullptr) {
				pktpool[i].pbuf = (char *)malloc(maxbuflen);
				if (!pktpool[i].pbuf) {
					PERRORPRINT("malloc failed for pool realloc");
					cmagic = 0;
					
					pthread_mutex_unlock(&mutex);
					return -1;	
				}	
			}
			else {
				pktpool[i].pbuf = pmbuf + i * maxbuflen;
			}
			pktpool[i].dlen = maxbuflen;
			pktpool[i].isvalid.store(0, std::memory_order_relaxed);
		}
	}

	if (is_wr_blocking == 1) { 
		pthread_cond_signal(&cond);
	} 

	if (is_rd_blocking == 1) { 
		pthread_cond_signal(&cond);
	} 

	pthread_mutex_unlock(&mutex);

	use_lock_.store(0, std::memory_order_release);

	return 0;
}


GY_PKT_POOL::~GY_PKT_POOL()
{
	uint32_t		i;
	PKT_DYN_ELEM		*pelem, *phead;
	
	if (cmagic != PKT_POOL_MAGIC) {
		return;
	}

	proc_mutex_lock(&mutex, multi_process);

	print_cumul_stats(1);

	for (i = 0; i < bufcnt; i++) {
		if (multi_process == 0) {
			if (pktpool[i].pbuf) {
				free(pktpool[i].pbuf);
			}	
		}

		pktpool[i].isvalid.store(0, std::memory_order_relaxed);

		phead = pktpool[i].pdynhead;
		while (phead) {
			pelem = phead;
			phead = phead->next;

			if (pelem->is_external_buf == 0) {
				free(pelem);
			}
			else if (pext_buf_free_fp == nullptr) {
				free(pelem);
			}
			else {
				try {
					(*pext_buf_free_fp)(pelem);
				}
				catch(...) {
					
				}		
			}
		}

		pktpool[i].cur_dyn_buf_size = 0;
		pktpool[i].cur_dyn_pkts = 0;
		pktpool[i].pdynhead = nullptr;
		pktpool[i].pdyntail = nullptr;
	}

	if (multi_process == 1) {
		gy_mmap_free(pktpool[0].pbuf, size_pbuf);
	}

	pthread_mutex_unlock(&mutex);

	pthread_mutex_destroy(&mutex);
	
	// XXX We leave the process-shared cond undestroyed as attached processes may have exited
	if (!multi_process) {
		pthread_cond_destroy(&cond);
	}	

	if (pktpool) {

		if (multi_process == 1) {
			gy_mmap_free(pktpool, size_pktpool);
		}
		else {
			free(pktpool);
		}
	}

	cmagic = 0;
}

GY_PKT_POOL * GY_PKT_POOL::alloc_shared_proc_pool(uint32_t bufcnt, uint32_t maxbuflen, bool is_single_writer, const char *pnamepool)
{
	GY_PKT_POOL			*pshmpool;
	size_t				sz;
	
	pshmpool = static_cast<GY_PKT_POOL *>(gy_mmap_alloc(sizeof(GY_PKT_POOL), &sz, 1));
	if (!pshmpool) {
		GY_THROW_SYS_EXCEPTION("Failed to allocate memory for shared proc Pool object");
	}

	try {
		new (pshmpool) GY_PKT_POOL(bufcnt, maxbuflen, 0, 0, 1 /* multi_process */, is_single_writer, pnamepool);

		pshmpool->size_obj = sz;

		return pshmpool;
	}
	GY_CATCH_EXCEPTION(
		gy_mmap_free(pshmpool, sz);

		throw;
	);
}	
	
void GY_PKT_POOL::dealloc_shared_proc_pool(GY_PKT_POOL * pshmpool, bool call_destructor, bool clear_internal_mem)
{
	size_t			sz = pshmpool->size_obj;

	if (call_destructor) {
		pshmpool->~GY_PKT_POOL();
	}	
	else if (clear_internal_mem) {
		pshmpool->pool_release_mmap_buffers();
	}	

	gy_mmap_free(pshmpool, sz);
}	

} // namespace gyeeta
