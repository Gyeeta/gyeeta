
#pragma				once

#include			"gy_common_inc.h"
#include			"gy_pkt_pool.h"
#include			"gy_msg_comm.h"

namespace gyeeta {

/*
 * Async function calling mechanism. Use to offload execution of a function pointer to the async thread (one per object).
 * Note that only captureless lambdas or function pointers will work.
 */
class ASYNC_FUNC_HDLR
{
public :	
	static constexpr size_t		MAX_ASYNC_OPT_BUFSZ	{512};

	alignas(128) GY_PKT_POOL	funcpool;
	const bool			use_rcu;
	GY_THREAD			readertid;
	gy_atomic<int64_t>		nskipped	{0};
	gy_atomic<int64_t>		ninline		{0};

	ASYNC_FUNC_HDLR(const char *name, uint32_t nmaxfunc, bool use_rcu = true);

	ASYNC_FUNC_HDLR(const ASYNC_FUNC_HDLR &)		= delete;
	ASYNC_FUNC_HDLR(ASYNC_FUNC_HDLR &&)			= delete;

	ASYNC_FUNC_HDLR & operator= (const ASYNC_FUNC_HDLR &)	= delete;
	ASYNC_FUNC_HDLR & operator= (ASYNC_FUNC_HDLR &&)	= delete;

	~ASYNC_FUNC_HDLR() noexcept
	{	
		print_stats();
	}

	/*
	 * Send a function to be executed by another thread under deterministic times (no indefinite delays).
	 *
	 * Returns 0 on successful send, 1 if send failed but exec_inline_if_async_failed is set and so was executed inline, else < 0
	 *
	 * Specify exec_inline_if_async_failed as true, if the send failed due to too many pending writes and so execute inline within the calling thread context.
	 * maxretries is the number of times the retry should be done if no buffers available for sending.
	 * async_safe_write should be set as true only if no mutex locking needed. For e.g. within a signal handler
	 * is_writer_rcu should be set as true, in case the writer needs to be set rcu offline in case of delays.
	 */ 
	int send_async_func(COMM_MSG_C & param, const uint8_t *poptbuf = nullptr, bool exec_inline_if_async_failed = false, uint32_t maxretries = 50, bool async_safe_write = false, \
				bool is_writer_rcu = false) noexcept;
	
	// See comments above
	int send_async_func(PROC_FUNCP func, uint64_t arg1 = 0, uint64_t arg2 = 0, uint64_t arg3 = 0, size_t opt_bufsize = 0, const uint8_t *poptbuf = nullptr, \
				bool exec_inline_if_async_failed = false, uint32_t maxretries = 50, bool async_safe_write = false, bool is_writer_rcu = false) noexcept
	{
		COMM_MSG_C		param(func, arg1, arg2, arg3, opt_bufsize);

		return send_async_func(param, poptbuf, exec_inline_if_async_failed, maxretries, async_safe_write, is_writer_rcu);
	}

	int pool_reader() noexcept;

	MAKE_CLASS_FUNC_WRAPPER_NO_ARG(ASYNC_FUNC_HDLR, pool_reader);

	void print_stats(bool is_unlocked = false) noexcept
	{
		funcpool.print_cumul_stats(is_unlocked);

		if (nskipped.load(std::memory_order_relaxed) || ninline.load(std::memory_order_relaxed)) {
			if (is_unlocked) {
				INFOFDUNLOCKPRINT(STDOUT_FILENO, "Async Pool \'%s\' : Total Function Executions Skipped %ld : Total Function Execs inline %ld\n",
					funcpool.poolstr, nskipped.load(std::memory_order_relaxed), ninline.load(std::memory_order_relaxed));
			}	
			else {
				INFOPRINT("Async Pool \'%s\' : Total Function Executions Skipped %ld : Total Function Execs inline %ld\n",
					funcpool.poolstr, nskipped.load(std::memory_order_relaxed), ninline.load(std::memory_order_relaxed));
			}	
		}
	}	

	static ASYNC_FUNC_HDLR * 		get_singleton() noexcept;

	static int				init_singleton();

};	

} // namespace gyeeta

