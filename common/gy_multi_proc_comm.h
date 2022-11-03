//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma 		once

#include		"gy_common_inc.h"
#include		"gy_file_api.h"
#include		"gy_print_offload.h"


namespace gyeeta {

template <bool is_multi_proc_, size_t nelems_, size_t datalen_>
class MULTI_PROC_COMM_HDLR
{
public :
	static constexpr size_t		ndata_elems_ = nelems_;

	enum SENDER_STATE_E : uint8_t
	{
		SENDER_NOT_WAITING		= 0,
		SENDER_ASYNC_POLLING,
		SENDER_WAITING,
		SENDER_WAIT_TERMINATED,
	};	

	class MULTI_PROC_ELEM
	{
	public :		
		COND_VAR <SCOPE_GY_MUTEX>		cond_				{is_multi_proc_};
		MULTI_PROC_COMM_HDLR 			*pthisparent_			{nullptr};		
		std::atomic <size_t>			curr_len_			{0};
		std::atomic <int>			resp_code_			{0};
		std::atomic <SENDER_STATE_E>		sender_waiting_			{SENDER_NOT_WAITING};
		std::atomic <bool>			resp_completed_			{false};
		alignas(8) uint8_t			data_[datalen_]			{};

		MULTI_PROC_ELEM()			= default;

		MULTI_PROC_ELEM(MULTI_PROC_MUTEX_INFO *pshm_info) : cond_(pshm_info)
		{}

		~MULTI_PROC_ELEM() noexcept		= default;
		
		bool is_response_completed() const noexcept
		{
			return resp_completed_.load(std::memory_order_acquire);
		}	
		
		static constexpr size_t get_max_data_len() noexcept
		{
			return datalen_;
		}	

		uint8_t * get_data_buf() noexcept
		{
			return data_;
		}	

		/*
		 * Poll for response completion. Will return true if completed and will update
		 * the response to copybuf with copylen set to the response length and respcode also updated.
		 *
		 * Returns false if response not yet completed.
		 */ 
		bool dispatch_poll(uint8_t copybuf[datalen_], size_t & copylen, int & respcode) noexcept
		{
			if (false == is_response_completed()) {
				return false;
			}

			size_t		clen = std::min<size_t>(curr_len_.load(std::memory_order_acquire), datalen_);

			std::memcpy(copybuf, data_, clen);
			copylen 	= clen;
			respcode 	= resp_code_.load(std::memory_order_relaxed);

			release_buf();
			
			return true;
		}	

		/*
		 * Will wait indefinitely for the response and thereafter copy the shared buffer to 
		 * copybuf. copylen is the shared buf len and respcode is the response completion code.
		 */ 
		void dispatch_wait(uint8_t copybuf[datalen_], size_t & copylen, int & respcode) noexcept
		{
			if (false == is_response_completed()) {
				sender_waiting_.store(SENDER_WAITING, std::memory_order_release);

				auto waitcb = [this]() noexcept
				{
					return !is_response_completed();
				};

				auto waitsuc = []() noexcept {};

				cond_.cond_wait(waitcb, waitsuc);
			}
			
			std::atomic_thread_fence(std::memory_order_acquire);

			size_t		clen = std::min<size_t>(curr_len_.load(std::memory_order_acquire), datalen_);

			std::memcpy(copybuf, data_, clen);
			copylen 	= clen;
			respcode 	= resp_code_.load(std::memory_order_relaxed);

			release_buf();
		}

		/*
		 * Will wait indefinitely for the response...
		 * Use this to directly operate on the shared buffer within the callback and save on copying while reading
		 */ 
		template <typename FCB>
		void dispatch_wait(FCB &cb) noexcept(noexcept(cb()))
		{
			if (false == is_response_completed()) {
				sender_waiting_.store(SENDER_WAITING, std::memory_order_release);

				auto waitcb = [this]() noexcept
				{
					return !is_response_completed();
				};

				cond_.cond_wait(waitcb, []() {});
			}
			
			std::atomic_thread_fence(std::memory_order_acquire);

			size_t		clen = curr_len_.load(std::memory_order_acquire);
			int		respcode = resp_code_.load(std::memory_order_relaxed);

			assert(clen <= datalen_);
			
			GY_SCOPE_EXIT {
				release_buf();
			};
				
			cb(data_, clen, respcode);	
		}

		/*
		 * On timeout will return false. The buffer will be assumed no longer valid and multiple calls
		 * to dispatch_timed_wait() must not be used as the receiver process might release the buffer
		 * once timeout occurs
		 */ 
		bool dispatch_timed_wait(uint64_t msec_to_wait, uint8_t copybuf[datalen_], size_t & copylen, int & respcode) noexcept
		{
			int			ret;

			if (false == is_response_completed()) {
				sender_waiting_.store(SENDER_WAITING, std::memory_order_release);

				auto waitcb = [this]() noexcept
				{
					return !is_response_completed();
				};
					
				auto timeout_cb = [this]() noexcept
				{
					sender_waiting_.store(SENDER_WAIT_TERMINATED, std::memory_order_release);
				};

				auto successcb = []() noexcept {};

				ret = cond_.template cond_timed_wait<decltype(waitcb), decltype(timeout_cb), decltype(successcb)>(waitcb, timeout_cb, successcb, msec_to_wait);	

				if (ret != 0) {
					copylen = 0;
					return false;
				}
			}

			std::atomic_thread_fence(std::memory_order_acquire);

			size_t		clen = std::min<size_t>(curr_len_.load(std::memory_order_acquire), datalen_);

			std::memcpy(copybuf, data_, clen);
			copylen 	= clen;
			respcode 	= resp_code_.load(std::memory_order_relaxed);

			release_buf();
			
			return true;
		}	

		/*
		 * To be called by the receiver on completion of response. szdata is the size of the shared buffer updated
		 * by the response and respcode indicates the return code from the exec function.
		 */ 
		void signal_completion(int respcode, size_t szdata) noexcept
		{
			bool		to_rel = false;

			assert(szdata <= datalen_);

			if (szdata > datalen_) szdata = datalen_;

			resp_code_.store(respcode, std::memory_order_relaxed);
			curr_len_.store(szdata, std::memory_order_relaxed);

			auto chkl = [&to_rel, this]() -> bool
			{
				auto state = sender_waiting_.load(std::memory_order_acquire);

				if (gy_unlikely(SENDER_WAIT_TERMINATED == state)) {
					to_rel = true;
				}	
				else {
					resp_completed_.store(true, std::memory_order_release);

					if (state < SENDER_WAITING) {
						return false;
					}	
				}

				return true;
			};	

			cond_.cond_signal(chkl);

			if (gy_unlikely(to_rel)) {
				release_buf();
			}	
		}	

		MULTI_PROC_ELEM(const MULTI_PROC_ELEM &) 		= delete;
		MULTI_PROC_ELEM(MULTI_PROC_ELEM &&) 			= delete;

		MULTI_PROC_ELEM & operator=(const MULTI_PROC_ELEM &)	= delete;
		MULTI_PROC_ELEM & operator=(MULTI_PROC_ELEM &&)		= delete;
	
		friend class MULTI_PROC_COMM_HDLR;
				
	private :
		void release_buf() noexcept
		{
			sender_waiting_.store(SENDER_NOT_WAITING, std::memory_order_relaxed);
			resp_completed_.store(false, std::memory_order_relaxed);
			resp_code_.store(0, std::memory_order_relaxed);
			curr_len_.store(0, std::memory_order_relaxed);

			pthisparent_->release_proc_buf(this);
		}	
	};

	struct PROC_TEST_SET
	{
		MULTI_PROC_ELEM 	*pelem_		= nullptr;
		std::atomic_flag	is_used_	= ATOMIC_FLAG_INIT;	
	};

	MULTI_PROC_COMM_HDLR()
	{
		for (size_t i = 0; i < ndata_elems_; ++i) {
			auto		ptest = ptest_arr_ + i;
			auto		pdata = pdata_arr_ + i;

			ptest_arr_[i].pelem_ = pdata;
		}	

		for (size_t i = 0; i < ndata_elems_; ++i) {
			auto		pdata = pdata_arr_ + i;

			pdata->pthisparent_ = this;
		}
	}	

	~MULTI_PROC_COMM_HDLR() 					= default;
	
	MULTI_PROC_COMM_HDLR(const MULTI_PROC_COMM_HDLR &) 		= delete; 
	MULTI_PROC_COMM_HDLR(MULTI_PROC_COMM_HDLR &&)	 		= delete; 

	MULTI_PROC_COMM_HDLR & operator=(const MULTI_PROC_COMM_HDLR &)	= delete;
	MULTI_PROC_COMM_HDLR & operator=(MULTI_PROC_COMM_HDLR &&)	= delete;

	/*
	 * Returns a MULTI_PROC_ELEM buffer if available or nullptr otherwise
	 * By default, the get_proc_buf() is non-blocking. If is_non_block == false, then after each retry_sleep_msec, 
	 * a retry will be attempted upto max_retries times
	 */ 
	MULTI_PROC_ELEM * get_proc_buf(bool is_non_block = true, size_t max_retries = 10, uint64_t retry_sleep_msec = 10) noexcept
	{
		size_t			nloops = (is_non_block ? 1 : max_retries);
		bool			chk_done = false;

		for (size_t n = 0; n < nloops; ++n) {
			for (size_t i = 0; i < ndata_elems_; ++i) {
				auto		ptest = ptest_arr_ + i;

				if (false == ptest->is_used_.test_and_set(std::memory_order_acquire)) {
					ptest_arr_[i].pelem_->sender_waiting_.store(SENDER_ASYNC_POLLING, std::memory_order_relaxed);

					return ptest_arr_[i].pelem_;
				}	
			}	

			if (n + 1 < nloops) {
				if (!chk_done && n * retry_sleep_msec > 50) {
					chk_done = true;
					verify_bufs();
				}
				gy_nanosleep(retry_sleep_msec * GY_NSEC_PER_MSEC); 
			}	
		}

		return nullptr;
	}
		
	void release_proc_buf(MULTI_PROC_ELEM *pbuf) noexcept
	{
		assert(pbuf >= pdata_arr_ && pbuf < pdata_arr_ + ndata_elems_);

		if (pbuf >= pdata_arr_ && pbuf < pdata_arr_ + ndata_elems_) {
			auto 		pt = ptest_arr_ + (pbuf - pdata_arr_);

			std::atomic_thread_fence(std::memory_order_release);

			pt->is_used_.clear(std::memory_order_release);
		}
	}	

	static constexpr size_t get_max_data_len() noexcept
	{
		return datalen_;
	}	

	static constexpr size_t get_elem_size() noexcept
	{
		return sizeof(MULTI_PROC_ELEM);
	}	

	static constexpr size_t get_num_buffers() noexcept
	{
		return ndata_elems_;
	}
		
	void verify_bufs() noexcept
	{
		int		nraces = 0;

		for (size_t i = 0; i < ndata_elems_; ++i) {
			auto		ptest = ptest_arr_ + i;
			auto		pdata = pdata_arr_ + i;

			if ((true == pdata->resp_completed_.load(std::memory_order_acquire)) &&
				((SENDER_WAIT_TERMINATED == pdata->sender_waiting_.load(std::memory_order_acquire))
				|| (SENDER_NOT_WAITING == pdata->sender_waiting_.load(std::memory_order_acquire)))) {
				
				std::atomic_thread_fence(std::memory_order_acquire);
			
				if (true == ptest->is_used_.test_and_set(std::memory_order_acquire)) {
					++nraces;
					pdata->release_buf();
				}
				else {
					ptest->is_used_.clear(std::memory_order_release);
				}	
			}	
		}	

		if (nraces > 0) {
			WARNPRINT_OFFLOAD("Multi Process Comm Buffers (%d buffers) affected by Timeout races. Please increase the sender timeouts...\n", nraces);
		}	
	}

	// Use this to allocate a multi process handler
	static MULTI_PROC_COMM_HDLR * allocate_handler()
	{
		MULTI_PROC_COMM_HDLR	*phdlr;
		size_t			sz;

		if (is_multi_proc_) {
			phdlr = static_cast<MULTI_PROC_COMM_HDLR *>(gy_mmap_alloc(sizeof(MULTI_PROC_COMM_HDLR), &sz, 1 /* use_proc_shared */));

			if (!phdlr) {
				GY_THROW_SYS_EXCEPTION("Failed to allocate multi process mmap space for muli proc communication");
			}	

			new (phdlr) MULTI_PROC_COMM_HDLR();

			phdlr->mmap_sz_ = sz;
		}	
		else {
			phdlr = new MULTI_PROC_COMM_HDLR();
		}	

		return phdlr;
	}	

	// Use for multi process. Specify call_destructor as false if more than 1 process is currently referencing this handler
	static void deallocate_handler(MULTI_PROC_COMM_HDLR *phdlr, bool call_destructor = true)
	{
		if (!phdlr) {
			return;
		}
			
		if (is_multi_proc_) {
			size_t			sz = phdlr->mmap_sz_;

			if (call_destructor) {
				phdlr->~MULTI_PROC_COMM_HDLR();
			}

			gy_mmap_free(phdlr, sz);
		}	
		else {
			delete phdlr;
		}	
	}	

private :
	PROC_TEST_SET		ptest_arr_[ndata_elems_];
	MULTI_PROC_ELEM		pdata_arr_[ndata_elems_];		
	size_t			mmap_sz_ = 0;
};	

class MULTI_COMM_SINGLETON final
{
public :	
	using MULTI_PROC_SZ_4096	= MULTI_PROC_COMM_HDLR<true, 128, 4096>;	
	using SINGLE_PROC_SZ_64		= MULTI_PROC_COMM_HDLR<false, 1024, 64>;	
	using SINGLE_PROC_SZ_512	= MULTI_PROC_COMM_HDLR<false, 512, 512>;	

	static int 			init_singleton();
	
	static MULTI_PROC_SZ_4096 	*get_multi_4096() noexcept;
	static SINGLE_PROC_SZ_64 	*get_single_64() noexcept;
	static SINGLE_PROC_SZ_512 	*get_single_512() noexcept;

	~MULTI_COMM_SINGLETON()		= delete;

private :
	MULTI_COMM_SINGLETON();
		
	MULTI_PROC_SZ_4096		*pmulti4096_		{nullptr};
	SINGLE_PROC_SZ_64		*psingle64_		{nullptr};
	SINGLE_PROC_SZ_512		*psingle512_		{nullptr};
};	
	
} // namespace gyeeta

