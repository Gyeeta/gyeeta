//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later
 
#pragma				once

#include 			"gy_common_inc.h"
#include 			"gy_print.h"
#include 			"gy_file_api.h"
#include			"gy_pkt_pool.h"

namespace gyeeta {

/*
 * Offload printing of log messages to a separate thread with optional rate limiting and further custom processing
 * of log messages. 
 * 
 * Default rate limit is set to 1000 normal logs/sec and 1000 error logs/sec. Max size of an individual Log
 * message is around 8KB (over which truncation occurs). No Heap allocations occur after init.
 *
 * Usage :
 * 
 * At init, call the PRINT_OFFLOAD::init_singleton() to start the offload thread. The *_OFFLOAD macros will
 * all work even if the singleton is not yet initialized in which case the log will be printed by the calling thread itself.
 *
 * Also in case extra processing of messages is needed, say we want to log the messages and send them as well to a remote 
 * logging server, we need to set the extra processing callback using either the PRINT_OFFLOAD constructor or
 * using the set_default_custom_handler() passing any parameters which will be passed to the callback as well.
 *
 * Then, for just offloading the logging without no extra processing, use the INFOPRINT_OFFLOAD/PERRORPRINT_OFFLOAD, etc
 * calls.
 * 
 * For logging as well as extra processing, use the CUSTOM_* macros passing a non-zero _cust_type to enable the
 * custom handler calls.
 * 
 * Users can specify different custom handler per call by directly using the send_print_msg() specifying the 
 * callback handler with optional args and non-zero cust_type_
 *
 * XXX The format specifier for all macro calls needs to be a string literal or else will not compile
 *
 * Max print message size for offload prints is limited to ~ 8KB. Larger messages will be truncated.
 *
 * Examples :
 *
	INFOPRINT_OFFLOAD("This message will be printed by a separate thread i = %d\n", i);

	PERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Write to file %s failed", pfilename);
	
	To send the data to a remote server, first register the extra handler using :

	PRINT_OFFLOAD::get_singleton()->set_default_custom_handler(
		[](PRINT_ELEM_C *pelem, char *printbuf, const char *time_buf, void *arg1, void *arg2)
		{
			MY_CLASS_C	*pthis = static_cast<MY_CLASS_C *>(arg1);

			if (pelem->cust_type_ > 1) {
				pthis->send_remote("Received Log Msg [%s.%06lu] : %s\n", time_buf, pelem->tv_.tv_usec, printbuf);
			}	
		}, this, nullptr);
	
	Then, subsequent calls using CUSTOM_*PRINT with non-zero _cust_type will result in the callback being invoked.
	XXX The extra handler must not use more than 100 KB stack space as the offload thread has only 128 KB stack.
 * 
 * To invoke the offload prints in a Async signal safe way, use the *UNLOCKPRINT_OFFLOADs
 * 
 */

#define OFFLOADPRINT(_type, _cust_type, _is_non_block, format, args...) 								\
({																	\
	auto 			poffload = gyeeta::PRINT_OFFLOAD::get_singleton();							\
	int			_cust_type1 = (_cust_type), _ret = 0;									\
	gyeeta::MSG_TYPE_E	_type1 = (_type);											\
	bool			_is_non_block1 = !!static_cast<int>(_is_non_block), _use_fflush1;					\
																	\
	_use_fflush1 = (_type1 < gyeeta::MSG_TYPE_ERROR) && (!gyeeta::is_str_last_char(format, '\n')); 					\
																	\
	if (gy_likely(poffload != nullptr)) {												\
		_ret = poffload->send_print_msg(_type1, _cust_type1, nullptr, nullptr, nullptr, _is_non_block1, _use_fflush1, 		\
					true /* print_on_offload_fail */, format, ## args);						\
	}																\
	else if (_type1 != gyeeta::MSG_TYPE_NO_LOG && !_is_non_block1) {								\
		FILE			*_pfp = (_type1 >= gyeeta::MSG_TYPE_ERROR ? stderr : stdout);					\
																	\
		if (_type1 == gyeeta::MSG_TYPE_NO_PREFIX) IRPRINT(format, ## args);							\
		else if (_type1 != gyeeta::MSG_TYPE_PERROR) {										\
			TIMEPRINT(_pfp, "[%s]: " format, gyeeta::PRINT_OFFLOAD::get_prefix_str(_type1),  ## args);			\
		}															\
		else {															\
			char 			_bufp[128];										\
			int			_olderrno = errno;									\
																	\
			_ret = TIMEPRINT(stderr, "[SYSTEM ERROR]: " format ": %s\n", 							\
					## args, GY_GETPERROR(_olderrno, _bufp, sizeof(_bufp)));					\
		}															\
																	\
		if (_use_fflush1 && !gyeeta::gunbuffered_stdout) {									\
			::fflush(_pfp);													\
		}															\
	}																\
	else if (_type1 != gyeeta::MSG_TYPE_NO_LOG && _is_non_block1) {									\
		int			_fd = (_type1 >= gyeeta::MSG_TYPE_ERROR ? STDERR_FILENO : STDOUT_FILENO);			\
																	\
		if (_type1 == gyeeta::MSG_TYPE_NO_PREFIX) IRFDUNLOCKPRINT(_fd, format, ## args);					\
		else if (_type1 != gyeeta::MSG_TYPE_PERROR) {										\
			TIMEFDPRINT(_fd, true, "[%s]: " format, gyeeta::PRINT_OFFLOAD::get_prefix_str(_type1),  ## args);		\
		}															\
		else {															\
			char 			_bufp[128];										\
			int			_olderrno = errno;									\
																	\
			_ret = TIMEFDPRINT(_fd, true, "[SYSTEM ERROR]: " format ": %s\n", 						\
					## args, GY_GETPERROR(_olderrno, _bufp, sizeof(_bufp)));					\
		}															\
	}																\
	_ret;																\
})

#define IRPRINT_OFFLOAD(format, args...) 			OFFLOADPRINT(gyeeta::MSG_TYPE_NO_PREFIX, 0, false, format, ## args)

#define DEBUGPRINT_OFFLOAD(format, args...) 			OFFLOADPRINT(gyeeta::MSG_TYPE_DEBUG, 0, false, "[%s:%d] : " format, 	\
											__PRETTY_FUNCTION__, __LINE__, ## args) 

#define INFOPRINT_OFFLOAD(format, args...) 			OFFLOADPRINT(gyeeta::MSG_TYPE_INFO, 0, false, format, ## args)

#define NOTEPRINT_OFFLOAD(format, args...) 			OFFLOADPRINT(gyeeta::MSG_TYPE_NOTE, 0, false, format, ## args)

#define WARNPRINT_OFFLOAD(format, args...) 			OFFLOADPRINT(gyeeta::MSG_TYPE_WARN, 0, false, format, ## args)

#define ERRORPRINT_OFFLOAD(format, args...) 			OFFLOADPRINT(gyeeta::MSG_TYPE_ERROR, 0, false, format, ## args)

#define PERRORPRINT_OFFLOAD(format, args...) 												\
({																	\
	static_assert(false == gyeeta::is_str_last_char(format, '\n'), "PERRORPRINT_OFFLOAD format must not end with a newline");	\
																	\
	int		_ret;														\
	_ret = OFFLOADPRINT(gyeeta::MSG_TYPE_PERROR, 0, false, format ": (%s:#%u:%d) ", ## args, __FILE__, __LINE__, errno);		\
	_ret;																\
})



#define IRPRINTCOLOR_OFFLOAD(_color, format, args...) 		OFFLOADPRINT(gyeeta::MSG_TYPE_NO_PREFIX, 0, false, _color format  GY_COLOR_RESET, ## args)

#define DEBUGPRINTCOLOR_OFFLOAD(_color, format, args...) 	OFFLOADPRINT(gyeeta::MSG_TYPE_DEBUG, 0, false, _color "[%s:%d] : " format GY_COLOR_RESET, \
														__PRETTY_FUNCTION__, __LINE__, ## args) 
#define INFOPRINTCOLOR_OFFLOAD(_color, format, args...) 	OFFLOADPRINT(gyeeta::MSG_TYPE_INFO, 0, false, _color format  GY_COLOR_RESET, ## args)

#define NOTEPRINTCOLOR_OFFLOAD(_color, format, args...) 	OFFLOADPRINT(gyeeta::MSG_TYPE_NOTE, 0, false, _color format  GY_COLOR_RESET, ## args)

#define WARNPRINTCOLOR_OFFLOAD(_color, format, args...) 	OFFLOADPRINT(gyeeta::MSG_TYPE_WARN, 0, false, _color format  GY_COLOR_RESET, ## args)

#define ERRORPRINTCOLOR_OFFLOAD(_color, format, args...) 	OFFLOADPRINT(gyeeta::MSG_TYPE_ERROR, 0, false, _color format  GY_COLOR_RESET, ## args)

#define PERRORPRINTCOLOR_OFFLOAD(_color, format, args...) 										\
({																	\
	static_assert(false == gyeeta::is_str_last_char(format, '\n'), "PERRORPRINTCOLOR_OFFLOAD format must not end with a newline");	\
																	\
	int		_ret;														\
	_ret = OFFLOADPRINT(gyeeta::MSG_TYPE_PERROR, 0, false, _color format GY_COLOR_RESET ": (%s:#%u:%d) ", 				\
						## args, __FILE__, __LINE__, errno);							\
	_ret;																\
})


#define CUSTOM_IRPRINT(_cust_type, format, args...)		OFFLOADPRINT(gyeeta::MSG_TYPE_NO_PREFIX, _cust_type, false, format, ## args)

#define CUSTOM_DEBUGPRINT(_cust_type, format, args...)	 	OFFLOADPRINT(gyeeta::MSG_TYPE_DEBUG, _cust_type, false, "[%s:%d] : " format, \
													__PRETTY_FUNCTION__, __LINE__, ## args) 
#define CUSTOM_INFOPRINT(_cust_type, format, args...)		OFFLOADPRINT(gyeeta::MSG_TYPE_INFO, _cust_type, false, format, ## args)

#define CUSTOM_NOTEPRINT(_cust_type, format, args...)		OFFLOADPRINT(gyeeta::MSG_TYPE_NOTE, _cust_type, false, format, ## args)

#define CUSTOM_WARNPRINT(_cust_type, format, args...)		OFFLOADPRINT(gyeeta::MSG_TYPE_WARN, _cust_type, false, format, ## args)

#define CUSTOM_ERRORPRINT(_cust_type, format, args...)		OFFLOADPRINT(gyeeta::MSG_TYPE_ERROR, _cust_type, false, format, ## args)

#define CUSTOM_PERRORPRINT(_cust_type, format, args...) 										\
({																	\
	static_assert(false == gyeeta::is_str_last_char(format, '\n'), "CUSTOM_PERRORPRINT format must not end with a newline");	\
																	\
	int		_ret;														\
	_ret = OFFLOADPRINT(gyeeta::MSG_TYPE_PERROR, _cust_type, false, format ": (%s:#%u:%d) ", ## args,  __FILE__, __LINE__, errno);	\
	_ret;																\
})


#define IRUNLOCKPRINT_OFFLOAD(format, args...)			CUSTOM_IRUNLOCKPRINT(0, format, ## args)

#define INFOUNLOCKPRINT_OFFLOAD(format, args...)		CUSTOM_INFOUNLOCKPRINT(0, format, ## args)

#define NOTEUNLOCKPRINT_OFFLOAD(format, args...)		CUSTOM_NOTEUNLOCKPRINT(0, format, ## args)

#define WARNUNLOCKPRINT_OFFLOAD(format, args...)		CUSTOM_WARNUNLOCKPRINT(0, format, ## args)

#define ERRORUNLOCKPRINT_OFFLOAD(format, args...)		CUSTOM_ERRORUNLOCKPRINT(0, format, ## args)

#define PERRORUNLOCKPRINT_OFFLOAD(format, args...) 		CUSTOM_PERRORUNLOCKPRINT(0, format, ## args)



#define CUSTOM_IRUNLOCKPRINT(_cust_type, format, args...)	OFFLOADPRINT(gyeeta::MSG_TYPE_NO_PREFIX, _cust_type, true, format, ## args)

#define CUSTOM_INFOUNLOCKPRINT(_cust_type, format, args...)	OFFLOADPRINT(gyeeta::MSG_TYPE_INFO, _cust_type, true, format, ## args)

#define CUSTOM_NOTEUNLOCKPRINT(_cust_type, format, args...)	OFFLOADPRINT(gyeeta::MSG_TYPE_NOTE, _cust_type, true, format, ## args)

#define CUSTOM_WARNUNLOCKPRINT(_cust_type, format, args...)	OFFLOADPRINT(gyeeta::MSG_TYPE_WARN, _cust_type, true, format, ## args)

#define CUSTOM_ERRORUNLOCKPRINT(_cust_type, format, args...)	OFFLOADPRINT(gyeeta::MSG_TYPE_ERROR, _cust_type, true, format, ## args)

#define CUSTOM_PERRORUNLOCKPRINT(_cust_type, format, args...) 										\
({																	\
	static_assert(false == gyeeta::is_str_last_char(format, '\n'), "CUSTOM_PERRORPRINT format must not end with a newline");	\
																	\
	int		_ret;														\
	_ret = OFFLOADPRINT(gyeeta::MSG_TYPE_PERROR, _cust_type, true, format ": (%s:#%u:%d) ", ## args, __FILE__, __LINE__, errno);	\
	_ret;																\
})


enum MSG_TYPE_E : int
{
	MSG_TYPE_NO_PREFIX 	= 0,

	MSG_TYPE_DEBUG,
	MSG_TYPE_INFO,
	MSG_TYPE_NOTE,
	MSG_TYPE_WARN,
			
	/*
	 * Rate limiting is separated for above categories and below ones
	 */ 		

	MSG_TYPE_ERROR,		
	MSG_TYPE_PERROR,

	MSG_TYPE_NO_LOG,	// Use this along with cust_type_ if no direct logging but just custom handler needs to be invoked

	MSG_TYPE_MAX,		// Keep this last
};	

class PRINT_ELEM_C;

typedef void (*CUST_PRINT_FUNCP)(PRINT_ELEM_C *pelem, char *printbuf, const char *time_buf, void *arg1, void *arg2);

class PRINT_ELEM_C
{
public :	
	static const int16_t	ELEM_MAGIC_ = 0xAABB;

	struct timeval		tv_;
	CUST_PRINT_FUNCP	cust_funcp_;
	void			*cust_arg1_;
	void			*cust_arg2_;
	MSG_TYPE_E		msgtype_;
	int			cust_type_;
	int			curr_errno_;
	int16_t			magic_		{ELEM_MAGIC_};
	bool			use_fflush_;
	uint32_t		msglen_;

	PRINT_ELEM_C(MSG_TYPE_E msgtype, const struct timeval tv, int curr_errno, int cust_type, CUST_PRINT_FUNCP cust_funcp, \
		void *cust_arg1, void *cust_arg2, bool use_fflush, uint32_t msglen = 0) noexcept 
			: 
			tv_(tv), cust_funcp_(cust_funcp), cust_arg1_(cust_arg1), cust_arg2_(cust_arg2), 
			msgtype_(msgtype), cust_type_(cust_type), curr_errno_(curr_errno),  use_fflush_(use_fflush), msglen_(msglen)
	{}	
};	


class PRINT_OFFLOAD
{
public :
	static constexpr size_t		MAX_PRINT_LEN 		= 8192;		// Maximum Length of a single print message

	alignas(128) GY_PKT_POOL	printpool_;
	GY_THREAD			readtid_;

	int				max_prints_per_sec_	{0};

	gy_atomic<int64_t>		nskipped_		{0};
	gy_atomic<int64_t>		ninline_		{0};

	int64_t				nprints_[MSG_TYPE_MAX]	{};
	int64_t				totalprints_		{0};
	int64_t				custprints_		{0};
	
	CUST_PRINT_FUNCP		default_cust_hdlr_	{nullptr};
	void 				*cust_arg1_		{nullptr};
	void 				*cust_arg2_		{nullptr};

	PRINT_OFFLOAD(const char *name, uint32_t nmaxelem, int rate_limit_per_sec = 1000, CUST_PRINT_FUNCP default_cust_hdlr = nullptr, void *cust_arg1 = nullptr, void *cust_arg2 = nullptr);

	PRINT_OFFLOAD(const PRINT_OFFLOAD &)			= delete;
	PRINT_OFFLOAD(PRINT_OFFLOAD &&)				= delete;

	PRINT_OFFLOAD & operator= (const PRINT_OFFLOAD &)	= delete;
	PRINT_OFFLOAD & operator= (PRINT_OFFLOAD &&)		= delete;

	~PRINT_OFFLOAD() noexcept
	{
		print_stats();
	}

	[[gnu::format (printf, 10, 11)]] 
	int send_print_msg(MSG_TYPE_E msgtype, int cust_type, CUST_PRINT_FUNCP cust_funcp, void *cust_arg1, void * cust_arg2, bool is_non_block, bool use_fflush, \
				bool print_on_offload_fail, const char *pfmt, ...) noexcept;

	int print_reader() noexcept;

	MAKE_CLASS_FUNC_WRAPPER_NO_ARG(PRINT_OFFLOAD, print_reader);

	static constexpr const char * get_prefix_str(MSG_TYPE_E type) noexcept
	{
		constexpr const char * 	prefix_arr[MSG_TYPE_E::MSG_TYPE_MAX] = {"", "DEBUG", "INFO", "NOTE", "WARN", "ERROR", "SYSTEM ERROR", ""};
		
		if (type >= MSG_TYPE_MAX) return "";

		return prefix_arr[type];
	}
		
	void print_stats(bool print_pool_stats = false) noexcept
	{
		if (print_pool_stats) {
			printpool_.print_cumul_stats(false);
		}	

		INFOPRINT("Offload Print Pool \'%s\' : Total Prints %ld : Total Rate Limit Skips %ld : Total Prints inline %ld : "
			"Total No Prefix prints %ld : Debug %ld : Info %ld : Note %ld : Warn %ld : Error %ld : Perror %ld : Custom %ld\n", 
			printpool_.poolstr, totalprints_, nskipped_.load(std::memory_order_relaxed), ninline_.load(std::memory_order_relaxed),
			nprints_[MSG_TYPE_NO_PREFIX], nprints_[MSG_TYPE_DEBUG], nprints_[MSG_TYPE_INFO], nprints_[MSG_TYPE_NOTE], nprints_[MSG_TYPE_WARN], 
			nprints_[MSG_TYPE_ERROR], nprints_[MSG_TYPE_PERROR], custprints_);
	}	

	void clear_stats() noexcept
	{
		nskipped_ = 0;
		ninline_ = 0;
		std::memset(nprints_, 0, sizeof(nprints_));
		totalprints_ = 0;
		custprints_ = 0;
	}	

	void set_rate_limit(int max_prints_per_sec) noexcept
	{
		GY_WRITE_ONCE(max_prints_per_sec_, max_prints_per_sec);
	}
	
	int get_rate_limit() const noexcept
	{
		return max_prints_per_sec_;
	}	

	void set_default_custom_handler(CUST_PRINT_FUNCP custhdlr, void *arg1 = nullptr, void *arg2 = nullptr) noexcept
	{
		GY_WRITE_ONCE(default_cust_hdlr_, custhdlr);
		GY_CC_BARRIER();

		cust_arg1_		= arg1;
		cust_arg2_		= arg2;
	}	

	static PRINT_OFFLOAD * 			get_singleton() noexcept;

	static int				init_singleton(int rate_limit_per_sec = 1000, uint32_t max_concurrent_elems = 1024,
							CUST_PRINT_FUNCP default_cust_hdlr = nullptr, void *cust_arg1 = nullptr, void *cust_arg2 = nullptr);

private :

	int execute_print(PRINT_ELEM_C *pelem, char *printbuf) noexcept;
	
	int print_elem(PRINT_ELEM_C *pelem, char *pdatabuf) noexcept;
};	

} // namespace gyeeta

