//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include		"gy_async_func.h"
#include		"gy_rcu_inc.h"
#include		"gy_print_offload.h"

namespace gyeeta {

ASYNC_FUNC_HDLR::ASYNC_FUNC_HDLR(const char *name, uint32_t nmaxfunc, bool use_rcu)
	: 
	funcpool(nmaxfunc, (uint32_t)sizeof(COMM_MSG_C) + MAX_ASYNC_OPT_BUFSZ, 0, 0, 0 /* multi_process */, 0 /* is_single_writer */, name), 
	use_rcu(use_rcu),
	readertid("Async Pool Reader Thread", ASYNC_FUNC_HDLR::GET_PTHREAD_WRAPPER(pool_reader), this, nullptr, nullptr, true /* start_immed */, 256 * 1024 /* max_stack_sz */, \
		2000 /* max_msecs_to_wait_for_quit_signal */, true /* use_signal_after_timeout_quit */, true /* wait_indefinitely_if_timeout_quit */, \
		false /* thr_func_calls_init_done_ */, 0 /* max_msecs_for_thr_init_ */, false,
		[](void * arg) { 
			ASYNC_FUNC_HDLR *	pthis = (ASYNC_FUNC_HDLR *)arg; 
			
			INFOPRINT("Async Function \'%s\' destructor called. Waiting for reader thread...\n", pthis->funcpool.poolstr);
			pthis->funcpool.pool_set_wr_exited();
		}, this)
{}

int ASYNC_FUNC_HDLR::pool_reader() noexcept
{
	alignas(8) uint8_t		elembuf[sizeof(COMM_MSG_C) + MAX_ASYNC_OPT_BUFSZ + 64];
	COMM_MSG_C			*pelem;
	PKT_RET_E 			retp;
	uint32_t			count;
	int				ret;

	do {
		if (use_rcu) {
			gy_rcu_offline();
		}
			
		retp = funcpool.pool_read_buffer(elembuf, sizeof(COMM_MSG_C) + MAX_ASYNC_OPT_BUFSZ, &count, 0 /* is_non_block */);

		if (retp != PKT_RET_SUCCESS) {
			INFOPRINT("Async Function \'%s\' reader exiting as writer seems to have exited.\n", funcpool.poolstr);
			break;
		}

		pelem = reinterpret_cast<COMM_MSG_C *>(elembuf);

		if (!pelem->func_ || (count != sizeof(COMM_MSG_C) + pelem->opt_bufsize_)) {
			DEBUGEXECN(1,
				ERRORPRINT_OFFLOAD("Internal Error (%u) : async function pool \'%s\' read parameters invalid\n", __LINE__, funcpool.poolstr); 
			);	
			continue;
		}
		
		pelem->exec_func(elembuf + sizeof(COMM_MSG_C));
			
	} while (1);

	return 0;
}	

int ASYNC_FUNC_HDLR::send_async_func(COMM_MSG_C & param, const uint8_t *poptbuf, bool exec_inline_if_async_failed, uint32_t maxretries, bool async_safe_write, bool is_writer_rcu) noexcept
{
	PKT_RET_E			retp;
	uint32_t			ntries = 0, niov = 1, count;
	int				ret;
	struct iovec			iov[2];
	
	iov[0] = {&param, sizeof(param)};

	if (param.opt_bufsize_) {
		if ((param.opt_bufsize_ <= MAX_ASYNC_OPT_BUFSZ) && poptbuf) {
			iov[1] = {(uint8_t *)poptbuf, param.opt_bufsize_};
			niov++;
		}
		else {
			DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Invalid async send paramaters sent : poptbuf = %p opt_bufsize_ = %lu\n", poptbuf, param.opt_bufsize_););
			return -1;
		}	
	}		

	if (async_safe_write == false) {
		do {
			retp = funcpool.pool_write_buffer(iov, niov, &count, 1 /* is_non_block but with mutex lock */);

			if (retp == PKT_RET_SUCCESS) {
				return 0;
			}	

			if (ntries == 0 && is_writer_rcu) {
				gy_rcu_offline();
			}	
		} while (++ntries < maxretries);
	}
	else {
		uint8_t                 *pbuf = nullptr;
		size_t                  sz = 0;

		do {
			retp = funcpool.pool_get_write_buf(&pbuf, &sz, true /* is_non_block */);
			if (retp == PKT_RET_SUCCESS) {

				std::memcpy(pbuf, &param, sizeof(param));
				if (param.opt_bufsize_) {
					std::memcpy(pbuf + sizeof(param), poptbuf, param.opt_bufsize_);
				}	

				funcpool.pool_save_write_buf(pbuf, sizeof(param) + param.opt_bufsize_);

				return 0;
			}       
		} while (++ntries < maxretries);
	}	

	if (exec_inline_if_async_failed) {
		ninline.fetch_add_relaxed(1);

		if (!async_safe_write) {
			DEBUGEXECN(1, 
				INFOPRINTCOLOR(GY_COLOR_BOLD_RED, "Async Exec pool \'%s\' blocked. Executing function within caller context. Total inline execs so far %ld\n", 
					funcpool.poolstr, ninline.load());
			);
		}	

		if (is_writer_rcu) {
			gy_rcu_offline();
		}	

		param.exec_func(poptbuf);

		return 1;
	}		
	else {
		nskipped.fetch_add_relaxed(1);

		if (!async_safe_write) {
			
			DEBUGEXECN(1, 
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Async Exec pool \'%s\' blocked. Failed to execute async func : Total Skipped Count so far %ld\n", 
					funcpool.poolstr, nskipped.load()););
		}	
		return -3;
	}	
}	

static ASYNC_FUNC_HDLR		*pgasync_ = nullptr;

ASYNC_FUNC_HDLR * ASYNC_FUNC_HDLR::get_singleton() noexcept
{
	return pgasync_;
}	

int ASYNC_FUNC_HDLR::init_singleton()
{
	int				texp = 0, tdes = 1;
	static std::atomic<int>		is_init_done(0);

	if (false == is_init_done.compare_exchange_strong(texp, tdes)) {
		return 0;
	}

	char				*ptmpalloc = nullptr;
	int				ret;
	
	// Using placement new as new will not allocate 128 byte aligned memory before C++17
	ret = posix_memalign((void **)&ptmpalloc, 128, sizeof(ASYNC_FUNC_HDLR) + 16);

	if (ret || !ptmpalloc) {
		errno = ret;
		GY_THROW_SYS_EXCEPTION("Failed to allocate memory for Async Function object");
	}

	pgasync_ = new (ptmpalloc) ASYNC_FUNC_HDLR("async global function", 2048);

	return 0;
}	



} // namespace gyeeta
	
