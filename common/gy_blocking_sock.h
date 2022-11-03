//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later
 
#pragma				once

#include 			"gy_common_inc.h"

#include 			<sys/socket.h>
#include 			<netdb.h>
#include 			<netinet/tcp.h>
#include 			<sys/un.h>

#include 			<functional>

namespace gyeeta {

/*
 * Blocking Socket Send/Receive : Not thread safe
 */ 
class BLOCKING_SOCK 
{
public :	
	using CloseSockCB 		= std::function<void(BLOCKING_SOCK &, void * /* cb_arg1 */, void * /* cb_arg2 */)>;
	
	int				sock_			{-1};

	CloseSockCB			close_cb_;
	void				*cb_arg1_		{nullptr};
	void				*cb_arg2_		{nullptr};

	char				desc_[256]		{};

	BLOCKING_SOCK(int sock = -1, const char * desc = "", CloseSockCB && closecb = {}, void * cb_arg1 = nullptr, void * cb_arg2 = nullptr) 
		: sock_(sock), close_cb_(closecb), cb_arg1_(std::move(cb_arg1)), cb_arg2_(cb_arg2)
	{
		GY_STRNCPY(desc_, desc, sizeof(desc_));
	}	
	
	BLOCKING_SOCK(int sock = -1, const char * desc = "", const CloseSockCB & closecb = {}, void * cb_arg1 = nullptr, void * cb_arg2 = nullptr) 
		: sock_(sock), close_cb_(closecb), cb_arg1_(cb_arg1), cb_arg2_(cb_arg2)
	{
		GY_STRNCPY(desc_, desc, sizeof(desc_));
	}	

	BLOCKING_SOCK(const BLOCKING_SOCK &)			= delete;
	BLOCKING_SOCK & operator=(const BLOCKING_SOCK &)	= delete;

	BLOCKING_SOCK(BLOCKING_SOCK && other) noexcept
		: sock_(std::exchange(other.sock_, -1)), close_cb_(std::move(other.close_cb_)), cb_arg1_(other.cb_arg1_), cb_arg2_(other.cb_arg2_)
	{
		std::memcpy(desc_, other.desc_, sizeof(desc_));
		desc_[sizeof(desc_) - 1] = 0;
	}

	BLOCKING_SOCK & operator=(BLOCKING_SOCK && other) noexcept
	{
		if (this != &other) {
			destroy();

			sock_		= std::exchange(other.sock_, -1);
			close_cb_	= std::move(other.close_cb_);
			cb_arg1_	= other.cb_arg1_;
			cb_arg2_	= other.cb_arg2_;

			std::memcpy(desc_, other.desc_, sizeof(desc_));
			desc_[sizeof(desc_) - 1] = 0;
		}	

		return *this;
	}	

	~BLOCKING_SOCK() noexcept
	{
		destroy();
	}	

	void destroy() noexcept
	{
		// Do not call close_cb_ on destruction
		close_cb_ = {};
		close_socket(true);
	}	

	void set_callback(CloseSockCB && close_cb, std::optional<void *> cb_arg1 = {}, std::optional<void *> cb_arg2 = {}) noexcept
	{
		close_cb_ = std::move(close_cb);

		if (cb_arg1) {
			cb_arg1_ = *cb_arg1;
		}	

		if (cb_arg2) {
			cb_arg2_ = *cb_arg2;
		}	
	}	

	void set_callback(const CloseSockCB & close_cb, std::optional<void *> cb_arg1 = {}, std::optional<void *> cb_arg2 = {})
	{
		close_cb_ = close_cb;

		if (cb_arg1) {
			cb_arg1_ = *cb_arg1;
		}	

		if (cb_arg2) {
			cb_arg2_ = *cb_arg2;
		}	
	}	

	void close_socket(bool graceful_close = true) noexcept
	{
		if (sock_ >= 0) {
			if (graceful_close) {
				gy_close_socket(sock_);
			}
			else {
				(void)close(sock_);
			}	
		}
		else {
			return;
		}	

		sock_ 		= -1;

		if (close_cb_) {
			try {
				close_cb_(*this, cb_arg1_, cb_arg2_);
			}
			catch(...) {
				
			}		
		}
	}
		
	bool is_valid() const noexcept
	{
		return sock_ >= 0;
	}

	int get_sock() const noexcept
	{
		return sock_;	
	}

	bool has_close_cb() const noexcept
	{
		return bool(close_cb_);
	}	

	ssize_t send_data(const struct iovec *piovin, int iovcnt, int timeout_msec = -1, bool close_on_timeout = false)
	{
		int			ret;
		ssize_t			sret;

		if (sock_ < 0) {
			return -1;
		}
			
		if (timeout_msec != -1) {
			ret = poll_sock(timeout_msec, close_on_timeout, POLLOUT);
			if (ret <= 0) {
				return ret;	
			}	 
		}	

		sret = gy_writev(fd, piovin, iovcnt);
		if (sret > 0) {
			return sret;
		}	

		close_socket(false);
		return -1;
	}	
			
	/* Will return error if buflen bytes could not be sent or bytes sent if non-blocking and partial bytes sent */
	ssize_t send_data(const uint8_t *buf, size_t buflen, int flags = 0, int timeout_msec = -1, bool close_on_timeout = false)
	{
		int			ret;
		ssize_t			sret;

		if (sock_ < 0) {
			return -1;
		}

		assert(buf);

		if (timeout_msec != -1) {
			ret = poll_sock(timeout_msec, close_on_timeout, POLLOUT);
			if (ret <= 0) {
				return ret;	
			}	 
		}	

		sret = gy_sendbuffer(sock_, buf, buflen, flags);
		if (sret > 0) {
			return sret;
		}	
		else if (errno == EAGAIN) {
			return 0;
		}	

		close_socket(false);
		return -1;
	}	

	/*
	 * Specify no_block_after_first_recv as false if you know how many bytes are expected to be received. 
	 * Default is true, which means recv all data blocking till the first payload arrives but don't block thereafter.
	 *
	 * min_bytes_to_recv can be specified as non-zero if any recv less than that should error out
	 */ 
	ssize_t recv_data(uint8_t *buf, size_t max_buflen, bool no_block_after_first_recv = true, size_t min_bytes_to_recv = 0, int flags = 0, int timeout_msec = -1, bool close_on_timeout = false)
	{
		int			ret;
		ssize_t			sret;

		if (sock_ < 0) {
			return -1;
		}

		assert(buf);

		if (timeout_msec != -1) {
			ret = poll_sock(timeout_msec, close_on_timeout, POLLIN);
			if (ret <= 0) {
				return ret;	
			}	 
		}	

		sret = gy_recvbuffer(fd, buf, max_buflen, flags, no_block_after_first_recv, min_bytes_to_recv);
		if (sret < 0) {
			if (false == is_socket_still_connected(sock_, true)) {
				close_socket(false);
				return -1;
			}	
		}	

		return sret;
	}
		
	int is_send_allowed(int poll_msec = 0, bool close_on_timeout = false)
	{
		return poll_sock(POLLOUT, timeout_msec, close_on_timeout);
	}

	int poll_recv_allowed(int timeout_msec, bool close_on_timeout = false)
	{
		return poll_sock(POLLIN, timeout_msec, close_on_timeout);
	}
		
	/*
	 * Specify timeout_msec as -1 for no timeout
	 *
	 * Returns > 0 if socket is available for the event needed
	 * Returns 0 if timeout occured for the event neeeded
	 * Returns < 0 for other errors
	 */ 			
	int poll_sock(int timeout_msec, bool close_on_timeout = false, int16_t poll_events = POLLIN | POLLOUT)
	{
		int			ret;
		struct pollfd 		pfds[1];

		if (sock_ < 0) {
			return -1;
		}
			
try_again :
		pfds[0].fd 	= sock_;
		pfds[0].events 	= poll_events;
		pfds[0].revents = 0;

		ret = ::poll(pfds, 1, timeout_msec);
		if (ret > 0) {
			if (pfds[0].revents & (POLLHUP | POLLERR | POLLNVAL)) {
				close_socket(false);
				return -1;
			}

			return ret;
		} 
		else if (ret == 0) {
			if (close_on_timeout) {
				close_socket(false);
			}
			return 0;
		}		
		else if (errno == EINTR) {
			goto try_again;
		}
		else {	
			close_socket(false);
			return -1;
		}
	}	
	
};	

} // namespace gyeeta
