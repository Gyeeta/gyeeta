
#include		"gy_print_offload.h"

namespace gyeeta {

PRINT_OFFLOAD::PRINT_OFFLOAD(const char *name, uint32_t nmaxelem, int rate_limit_per_sec, CUST_PRINT_FUNCP default_cust_hdlr, void *cust_arg1, void *cust_arg2)
	: 
	printpool_(nmaxelem, MAX_PRINT_LEN, 0, 2, 0 /* multi_process */, 0 /* is_single_writer */, name),
	readtid_("Print Offload Reader Thread", PRINT_OFFLOAD::GET_PTHREAD_WRAPPER(print_reader), this, nullptr, nullptr, true /* start_immed */, 128 * 1024 /* max_stack_sz */, \
		2000 /* max_msecs_to_wait_for_quit_signal */, true /* use_signal_after_timeout_quit */, true /* wait_indefinitely_if_timeout_quit */, \
		false /* thr_func_calls_init_done_ */, 0 /* max_msecs_for_thr_init_ */, false /* throw_on_init_timeout */,
		[](void * arg) { 
			PRINT_OFFLOAD *	pthis = (PRINT_OFFLOAD *)arg; 
			
			INFOPRINT("Print Offload \'%s\' destructor called. Waiting for reader thread...\n", pthis->printpool_.poolstr);
			pthis->printpool_.pool_set_wr_exited();
		}, this),
	max_prints_per_sec_(rate_limit_per_sec),
	default_cust_hdlr_(default_cust_hdlr), cust_arg1_(cust_arg1), cust_arg2_(cust_arg2)	
{
	INFOPRINT("Initialized Print Offload Object \'%s\' : Max Rate is %d/sec and total %u Buffers allocated...\n",
		name, rate_limit_per_sec, nmaxelem);
}


thread_local time_t		gcurr_tsec = 0;			
thread_local int		gcurr_prints_per_sec = 0, gcurr_errors_per_sec = 0;

[[gnu::format (printf, 10, 11)]] 
int PRINT_OFFLOAD::send_print_msg(MSG_TYPE_E msgtype, int cust_type, CUST_PRINT_FUNCP cust_funcp, void *cust_arg1, void * cust_arg2, bool is_non_block, bool use_fflush, bool print_on_offload_fail, const char *pfmt, ...) noexcept
{
	uint8_t			*pbuf = nullptr;
	size_t			sz = 0;
	int			nwr = 0, olderrno = errno;
	PKT_RET_E		retp;
	va_list 		va;
	struct timeval		tv;
	PRINT_ELEM_C		*pelem;

	gettimeofday(&tv, nullptr);

	if (max_prints_per_sec_) {
		if (gcurr_tsec != tv.tv_sec) {
			gcurr_tsec 		= tv.tv_sec;
			gcurr_prints_per_sec 	= 0;
			gcurr_errors_per_sec 	= 0;
		}
		else {
			++gcurr_prints_per_sec;
			
			if (msgtype >= MSG_TYPE_ERROR) {
				gcurr_errors_per_sec++;	
			}
				 
			if (gcurr_prints_per_sec > max_prints_per_sec_) {
				if ((msgtype < MSG_TYPE_ERROR) || (gcurr_errors_per_sec > max_prints_per_sec_)) {
					nskipped_.fetch_add_relaxed(1, std::memory_order_relaxed);
					return -1;
				}
			}		
		}	
	}
		
	retp = printpool_.pool_get_write_buf(&pbuf, &sz, is_non_block);

	if (retp != PKT_RET_SUCCESS) {
		if (print_on_offload_fail && !is_non_block && msgtype != MSG_TYPE_NO_LOG) {
			FILE		*fp;
			char		stimebuf[64], ebuf[128];

			if (msgtype == MSG_TYPE_ERROR || msgtype == MSG_TYPE_PERROR) {
				fp = stderr;
			}
			else {
				fp = stdout;	
			}		

			if (msgtype != MSG_TYPE_NO_PREFIX) {
				nwr += fprintf(fp, "[%s]:[%s]: ", gy_time_print(stimebuf, sizeof(stimebuf) - 1, tv).first, get_prefix_str(msgtype));
			}

			va_start(va, pfmt);
			nwr += vfprintf(fp, pfmt, va);
			va_end(va);

			if (msgtype == MSG_TYPE_PERROR) {
				nwr += fprintf(fp, ": %s\n", strerror_r(olderrno, ebuf, sizeof(ebuf) - 1));
			}
				
			if (use_fflush && !gunbuffered_stdout) {
				fflush(fp);
			}	

			ninline_.fetch_add_relaxed(1, std::memory_order_relaxed);
			return nwr;
		}	
		else {
			nskipped_.fetch_add_relaxed(1, std::memory_order_relaxed);
			return -1;
		}	
	}

	pelem = new (pbuf) PRINT_ELEM_C(msgtype, tv, olderrno, cust_type, cust_funcp, cust_arg1, cust_arg2, use_fflush);

	va_start(va, pfmt);
	nwr = vsnprintf(reinterpret_cast<char *>(pbuf) + sizeof(PRINT_ELEM_C), sz - sizeof(PRINT_ELEM_C) - 1 - 32, pfmt, va);
	va_end(va);

	if (nwr > 0) {
		nwr += sizeof(PRINT_ELEM_C);

		if (nwr >= (int)sz - 1 - 32) {
			nwr = sz - 1 - 32 - 1; 	// Truncate
			pbuf[nwr++] 	= ' ';
			pbuf[nwr++] 	= '.';
			pbuf[nwr++] 	= '.';
			pbuf[nwr++] 	= '.';
			pbuf[nwr] 	= '\0';
		}	

		if (msgtype == MSG_TYPE_PERROR) {
			int			n;
			char			ebuf[128];

			n = snprintf(reinterpret_cast<char *>(pbuf) + nwr, sz - nwr - 1, ": %s\n", strerror_r(olderrno, ebuf, sizeof(ebuf) - 1));
			
			if (n > 0) {
				nwr += n;
				if (nwr > (int)sz) {
					nwr = sz;
				}	
			}
		}

		pelem->msglen_ = nwr - sizeof(PRINT_ELEM_C);

		printpool_.pool_save_write_buf(pbuf, nwr);

		return nwr;
	}
	else {
		printpool_.pool_save_write_buf(pbuf, 0);

		nskipped_.fetch_add_relaxed(1, std::memory_order_relaxed);
		return -1;
	}
}	

int PRINT_OFFLOAD::print_reader() noexcept
{
	alignas(8) uint8_t		celem[sizeof(PRINT_ELEM_C)], elem[MAX_PRINT_LEN + 64];
	PKT_RET_E 			retp;
	uint32_t			count;
	int				ret, nerror = 0;
	PRINT_ELEM_C			*pelem;

	do {
		retp = printpool_.pool_read_buffer(elem, sizeof(elem) - 1, &count, 0 /* is_non_block */);

		if (retp != PKT_RET_SUCCESS) {
			INFOPRINT("Print Offload Pool \'%s\' reader exiting as writer seems to have exited.\n", printpool_.poolstr);
			break;
		}

		if (count < sizeof(PRINT_ELEM_C)) {
			if (nerror++ < 10) {
				ERRORPRINT("Internal Error (%u) : Print Offload pool \'%s\' Invalid Data size seen\n", __LINE__, printpool_.poolstr); 
			}	
			continue;
		}

		pelem = reinterpret_cast<PRINT_ELEM_C *>(elem);

		if (pelem->magic_ != PRINT_ELEM_C::ELEM_MAGIC_) {
			if (nerror++ < 10) {
				ERRORPRINT("Internal Error (%u) : Print Offload pool \'%s\' Invalid Data Magic seen\n", __LINE__, printpool_.poolstr); 
			}	
			continue;
		}	

		if (count != sizeof(PRINT_ELEM_C) + pelem->msglen_) {
			if (nerror++ < 10) {
				ERRORPRINT("Internal Error (%u) : Print Offload pool \'%s\' Invalid Data Length seen\n", __LINE__, printpool_.poolstr); 
			}	
			continue;
		}	

		if (pelem->msgtype_ >= MSG_TYPE_MAX) {
			if (nerror++ < 10) {
				ERRORPRINT("Internal Error (%u) : Print Offload pool \'%s\' Invalid Msg Type seen\n", __LINE__, printpool_.poolstr); 
			}	
			continue;
		}	

		elem[count] = '\0';
		
		print_elem(pelem, reinterpret_cast<char *>(elem) + sizeof(PRINT_ELEM_C));
			
	} while (1);

	return 0;
}	


int PRINT_OFFLOAD::print_elem(PRINT_ELEM_C * pelem, char *pdatabuf) noexcept
{
	FILE			*fp;
	char			stimebuf[64];
	
	if (max_prints_per_sec_) {
		if (gcurr_tsec != pelem->tv_.tv_sec) {
			gcurr_tsec 		= pelem->tv_.tv_sec;
			gcurr_prints_per_sec 	= 0;
			gcurr_errors_per_sec 	= 0;
		}
		else {
			++gcurr_prints_per_sec;

			if (pelem->msgtype_ >= MSG_TYPE_ERROR) {
				gcurr_errors_per_sec++;	
			}

			if (gcurr_prints_per_sec > max_prints_per_sec_) {
				if ((pelem->msgtype_ < MSG_TYPE_ERROR) || (gcurr_errors_per_sec > max_prints_per_sec_)) {
					nskipped_.fetch_add_relaxed(1, std::memory_order_relaxed);
					return -1;
				}	
			}		
		}	
	}

	nprints_[pelem->msgtype_]++;
	totalprints_++;

	if (pelem->msgtype_ == MSG_TYPE_ERROR || pelem->msgtype_ == MSG_TYPE_PERROR) {
		fp = stderr;
	}
	else {
		fp = stdout;	
	}		

	gy_time_print(stimebuf, sizeof(stimebuf) - 1, pelem->tv_);
	
	if (pelem->msgtype_ != MSG_TYPE_NO_LOG) {

		/*fprintf(fp, "[%s]:[%s]: %s", stimebuf, get_prefix_str(pelem->msgtype_), pdatabuf);*/

		flockfile(fp);

		if (pelem->msgtype_ != MSG_TYPE_NO_PREFIX) { 
			fputc_unlocked('[', fp);
			fputs_unlocked(stimebuf, fp);
			fputs_unlocked("]:[", fp);
			fputs_unlocked(get_prefix_str(pelem->msgtype_), fp);
			fputs_unlocked("]: ", fp);
		}

		fwrite_unlocked(pdatabuf, 1, pelem->msglen_, fp);

		if (pelem->use_fflush_ && !gunbuffered_stdout) {
			fflush_unlocked(fp);
		}	

		funlockfile(fp);
	}

	if (pelem->cust_type_ != 0) {
		try {
			if (pelem->cust_funcp_) {

				(*pelem->cust_funcp_)(pelem, pdatabuf, stimebuf, pelem->cust_arg1_, pelem->cust_arg2_);
				custprints_++;
			}
			else {
				volatile CUST_PRINT_FUNCP		pdefault = GY_READ_ONCE(default_cust_hdlr_);

				GY_CC_BARRIER();

				if (pdefault) {
					(*pdefault)(pelem, pdatabuf, stimebuf, cust_arg1_, cust_arg2_);
					custprints_++;
				}
			}	
		}
		catch(...) {
			return -1;
		}
	}	

	return 0;
}	

static PRINT_OFFLOAD		*pgoffload_ = nullptr;

PRINT_OFFLOAD * PRINT_OFFLOAD::get_singleton() noexcept
{
	return pgoffload_;
}	

int PRINT_OFFLOAD::init_singleton(int rate_limit_per_sec, uint32_t max_concurrent_elems, CUST_PRINT_FUNCP default_cust_hdlr, void *cust_arg1, void *cust_arg2)
{
	int				texp = 0, tdes = 1;
	static std::atomic<int>		is_init_done(0);

	if (false == is_init_done.compare_exchange_strong(texp, tdes)) {
		return 0;
	}

	char				*ptmpalloc = nullptr;
	int				ret;
	
	// Using placement new as new will not allocate 128 byte aligned memory before C++17
	ret = posix_memalign((void **)&ptmpalloc, 128, sizeof(PRINT_OFFLOAD) + 16);

	if (ret || !ptmpalloc) {
		errno = ret;
		GY_THROW_SYS_EXCEPTION("Failed to allocate memory for Print Offload singleton object");
	}

	pgoffload_ = new (ptmpalloc) PRINT_OFFLOAD("Print Offload singleton", max_concurrent_elems, rate_limit_per_sec, default_cust_hdlr, cust_arg1, cust_arg2);

	return 0;
}	

} // namespace gyeeta

