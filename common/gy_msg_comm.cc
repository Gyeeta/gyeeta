
#include			"gy_child_proc.h"
#include			"gy_print_offload.h"

namespace gyeeta {

int COMM_MSG_C::send_msg_locked(int fd, pthread_mutex_t *pmutex, COMM_MSG_C & msg, const uint8_t *poptbuf, bool is_nonblock) noexcept
{
	SCOPE_PTHR_MUTEX	scopelock(nullptr);
	int			ret, ntries;

	assert(pmutex);

	if (is_nonblock) {
		ntries = 0;

		do {
			ret = scopelock.trylock(pmutex);
		}
		while(ret != 0 && ntries++ < 10);

		if (ret != 0) {
			return ret;
		}	
	}
	else {
		scopelock.setlock(pmutex);
	}	

	return send_msg(fd, msg, poptbuf, is_nonblock);
}	

int COMM_MSG_C::send_msg(int fd, COMM_MSG_C & msg, const uint8_t *poptbuf, bool is_nonblock) noexcept
{
	ssize_t			sret;
	const bool		is_opt = (msg.opt_bufsize_ > 0); 

	if (is_opt && !poptbuf) {
		assert(poptbuf);
		return -1;
	}	
	
	msg.magic_ = COMM_MSG_MAGIC;

	sret = gy_sendbuffer(fd, &msg, sizeof(msg), (is_nonblock ? MSG_DONTWAIT : 0) | (is_opt ? MSG_MORE : 0));
	if (sret == -1) {
		return -1;
	}	

	if (is_opt) {
		sret = gy_sendbuffer(fd, poptbuf, msg.opt_bufsize_, (is_nonblock ? MSG_DONTWAIT : 0));
		if (sret == -1) {
			return -1;
		}	
	}
	
	return 0;	
}			


int COMM_MSG_C::recv_msg(int fd, COMM_MSG_C & msg, uint8_t *poptbuf, size_t max_sz_popt, bool exec_func, bool is_nonblock) noexcept
{
	ssize_t			sret;

	assert(poptbuf);

	sret = gy_recvbuffer(fd, &msg, sizeof(msg), is_nonblock ? MSG_DONTWAIT : 0, false /* no_block_after_first_recv */, sizeof(msg));
	if (sret == -1) {
		return -1;
	}	
	
	if (gy_unlikely(msg.magic_ != COMM_MSG_MAGIC)) {

		ERRORPRINT_OFFLOAD("Invalid Msg received in %s : Magic invalid : Ignoring all immediate messages...\n", __FUNCTION__);

		// Drain all pending messages 
		do {
			sret = gy_recvbuffer(fd, poptbuf, max_sz_popt, MSG_DONTWAIT, false, 0);
			if (sret == -1) {
				return -2;
			}	
		} while (true);
	}	

	if (msg.opt_bufsize_) {
		if (gy_unlikely(msg.opt_bufsize_ > max_sz_popt)) {

			// Drain the msg and ignore
			DEBUGEXECN(1,
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Invalid Msg Optional Buffersize received in %s : %lu : Max allowed %lu...\n", 
						__FUNCTION__, msg.opt_bufsize_, max_sz_popt);
			);	

			do {
				size_t 		tsz = (msg.opt_bufsize_ > max_sz_popt ? max_sz_popt : msg.opt_bufsize_);

				sret = gy_recvbuffer(fd, poptbuf, tsz, is_nonblock ? MSG_DONTWAIT : 0, false, 0);
				if (sret == -1) {
					return -1;
				}	

				msg.opt_bufsize_ -= sret;
			} while (msg.opt_bufsize_ > 0);	
			
			return -3;
		}
		
		sret = gy_recvbuffer(fd, poptbuf, msg.opt_bufsize_, is_nonblock ? MSG_DONTWAIT : 0, false, msg.opt_bufsize_);
		if (sret == -1) {
			return -1;
		}	
	}
	
	if (exec_func) {
		return msg.exec_func(poptbuf);
	}	

	return 0;
}	
	
} // namespace gyeeta

