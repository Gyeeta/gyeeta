
#pragma 			once

#include			"gy_common_inc.h"

namespace gyeeta {

typedef int (*PROC_FUNCP)(uint64_t arg1, uint64_t arg2, uint64_t arg3, const uint8_t *poptbuf, size_t opt_bufsize);

class COMM_MSG_C
{
public :	
	static constexpr uint64_t	COMM_MSG_MAGIC 	{0xAABBCCDD11223344UL};

	uint64_t			magic_		{COMM_MSG_MAGIC};
	PROC_FUNCP			func_		{nullptr};
	uint64_t			arg1_		{0};
	uint64_t			arg2_		{0};
	uint64_t			arg3_		{0};
	size_t				opt_bufsize_	{0}; 	// uint8_t poptbuf_[opt_bufsize_] follows if opt_bufsize_ > 0

	COMM_MSG_C() noexcept		= default;
	
	COMM_MSG_C(PROC_FUNCP func, uint64_t arg1 = 0, uint64_t arg2 = 0, uint64_t arg3 = 0, size_t opt_bufsize = 0) noexcept
		: func_(func), arg1_(arg1), arg2_(arg2), arg3_(arg3), opt_bufsize_(opt_bufsize)
	{}	

	bool is_exec_func() const noexcept
	{
		return !!func_;
	}	

	int exec_func(const uint8_t *poptbuf = nullptr) noexcept
	{
		if (func_) {
			try {
				(*func_)(arg1_, arg2_, arg3_, poptbuf, opt_bufsize_);
				return 0;
			}
			GY_CATCH_EXCEPTION(
				ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Exception caught while executing function from comm proc msg : %s\n", GY_GET_EXCEPT_STRING);
				return -1;
			);	
		}	

		return 1;
	}

	bool is_valid_magic() const noexcept
	{
		return magic_ == COMM_MSG_MAGIC;
	}
		
	static int 		send_msg(int fd, COMM_MSG_C & msg, const uint8_t *poptbuf = nullptr, bool is_nonblock = false) noexcept;

	// If is_nonblock and mutex could not be locked, will return > 0 which contains the errno
	static int 		send_msg_locked(int fd, pthread_mutex_t *pmutex, COMM_MSG_C & msg, const uint8_t *poptbuf = nullptr, bool is_nonblock = false) noexcept;

	static int		recv_msg(int fd, COMM_MSG_C & msg, uint8_t *poptbuf, size_t max_sz_popt, bool exec_func = true, bool is_nonblock = false) noexcept;
};	

} // namespace gyeeta

