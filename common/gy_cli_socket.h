
 
#pragma				once

#include 			"gy_common_inc.h"

#include 			<sys/socket.h>
#include 			<netdb.h>
#include 			<netinet/tcp.h>
#include 			<sys/un.h>

#include 			<functional>

namespace gyeeta {

/*
 * Blocking TCP / Unix Domain Client : Not thread safe
 */ 
class CLI_SOCKET final
{
public :	
	using CLI_SOCK_CB 		= std::function<void(CLI_SOCKET &, int /* sock */, bool /* is_connected */, void * /* cb_arg1 */, void * /* cb_arg2 */)>;

	char				serverhost_[MAX_DOMAINNAME_SIZE];
	char				server_desc_str_[64]	{};
	uint16_t			serverport_		{0};

	uint64_t			tlast_conn_usec_	{0};
	time_t				tlast_trial_		{0};

	CLI_SOCK_CB			up_down_cb_;
	void				*cb_arg1_		{nullptr};
	void				*cb_arg2_		{nullptr};

	struct sockaddr_storage		sockaddr_		{};
	socklen_t			socklen_		{0};
	int				sockfamily_		{AF_INET};
	
	int				sock_			{-1};

	bool				is_connected_		{false};
	bool				set_nodelay_		{true};
	bool				auto_reconnect_		{true};
	bool 				use_ipv4_only_		{false};
	bool 				is_unix_domain_		{false};

	char				last_connect_error_[128];	

	/*
	 * Default will throw an exception if connect failed. Specify is_nothrow as true otherwise
	 * 
	 * serverport		=>	TCP port number of server
	 * pserverhost 		=>	IP/Hostname of the TCP server. For Link Local IPv6 connections also specify the Link scope using %<Interface>	
	 * always_resolve_dns	=>	If pserverhost is in IP/DNS format. Even if specified false, on IP format error will try resolving using getaddrinfo()
	 * auto_reconnect	=>	Auto reconnect on connection failure (Retry will done once per sec on every call to send_data()/recv_data() (No separate thread)
	 * use_ipv4_only	=>	Prefer only IPv4 Addresses
	 * is_nothrow		=>	On Connect / send /recv errors do not throw an exception
	 * set_nodelay		=>	Disable Nagle Algorithm
	 * pserver_descr	=>	Debug string describing the server for printing errors
	 * up_down_cb		=>	Callback to be invoked on every new connection / disconnect of the TCP session (except during destructor)
	 * cb_arg1/cb_arg2	=> 	Aguments to be passed to above callback
	 */ 
	CLI_SOCKET(uint16_t serverport, const char *pserverhost, bool always_resolve_dns = false, bool auto_reconnect = false, bool use_ipv4_only = false, bool is_nothrow = false, bool set_nodelay = true, const char *pserver_descr = "", CLI_SOCK_CB up_down_cb = {}, void *cb_arg1 = nullptr, void *cb_arg2 = nullptr)
		: serverport_(
			({
				assert(pserverhost && serverport > 0);

				GY_STRNCPY(serverhost_, pserverhost, sizeof(serverhost_));
				if (pserver_descr) {
					GY_STRNCPY(server_desc_str_, pserver_descr, sizeof(server_desc_str_));
				}	
				else {
					*server_desc_str_ = '\0';
				}	
				*last_connect_error_ = '\0';

				serverport;
			})
		),		
		up_down_cb_(std::move(up_down_cb)), cb_arg1_(cb_arg1), cb_arg2_(cb_arg2),
		set_nodelay_(set_nodelay), auto_reconnect_(auto_reconnect), use_ipv4_only_(use_ipv4_only)
	{
		connect_server(is_nothrow, always_resolve_dns);
	}		

	/*
	 * path is the Unix Domain Socket path
	 * Default will throw an exception if connect failed. Specify is_nothrow as true otherwise
	 * See comment above as well.
	 */ 
	CLI_SOCKET(const char *path, bool auto_reconnect = false, bool is_nothrow = false, const char *pserver_descr = "", CLI_SOCK_CB up_down_cb = {}, void *cb_arg1 = nullptr, void *cb_arg2 = nullptr)
		: serverport_(
			({
				assert(path);

				GY_STRNCPY(serverhost_, path, sizeof(serverhost_));
				if (pserver_descr) {
					GY_STRNCPY(server_desc_str_, pserver_descr, sizeof(server_desc_str_));
				}	
				else {
					*server_desc_str_ = '\0';
				}	
				*last_connect_error_ = '\0';

				0;
			})
		),		
		up_down_cb_(std::move(up_down_cb)), cb_arg1_(cb_arg1), cb_arg2_(cb_arg2), auto_reconnect_(auto_reconnect), is_unix_domain_(true)
	{
		connect_server(is_nothrow);
	}		

	// Default constructor to be used only for subsequent move/copy assignment
	CLI_SOCKET() noexcept
		: serverport_(
			({
				*serverhost_ 		= '\0';
				*server_desc_str_	= '\0';
				*last_connect_error_ 	= '\0';

				0;
			})
		)		
	{}	

	/*
	 * Create a new socket connection based on other
	 */ 
	CLI_SOCKET(const CLI_SOCKET &other)
	{
		std::memcpy(serverhost_, other.serverhost_, sizeof(serverhost_));
		std::memcpy(server_desc_str_, other.server_desc_str_, sizeof(server_desc_str_));

		serverport_ 		= other.serverport_;
		tlast_conn_usec_	= 0;
		up_down_cb_		= other.up_down_cb_;
		cb_arg1_		= other.cb_arg1_;
		cb_arg2_		= other.cb_arg2_;

		sockaddr_		= other.sockaddr_;
		socklen_		= other.socklen_;
		sockfamily_		= other.sockfamily_;

		sock_ 			= -1;
		is_connected_		= false;
		set_nodelay_		= other.set_nodelay_;
		auto_reconnect_		= other.auto_reconnect_;
		use_ipv4_only_		= other.use_ipv4_only_;
		is_unix_domain_		= other.is_unix_domain_;

		*last_connect_error_	= 0;

		if (other.sock_ >= 0) {	
			connect_server(false /* is_nothrow */);
		}	
	}	

	CLI_SOCKET(CLI_SOCKET && other) noexcept
	{
		std::memcpy(serverhost_, other.serverhost_, sizeof(serverhost_));
		std::memcpy(server_desc_str_, other.server_desc_str_, sizeof(server_desc_str_));

		serverport_ 		= other.serverport_;
		tlast_conn_usec_	= other.tlast_conn_usec_;
		up_down_cb_		= std::move(other.up_down_cb_);
		cb_arg1_		= other.cb_arg1_;
		cb_arg2_		= other.cb_arg2_;

		sockaddr_		= other.sockaddr_;
		socklen_		= other.socklen_;
		sockfamily_		= other.sockfamily_;

		sock_ 			= std::exchange(other.sock_, -1);
		is_connected_		= std::exchange(other.is_connected_, false);
		set_nodelay_		= other.set_nodelay_;
		auto_reconnect_		= other.auto_reconnect_;
		use_ipv4_only_		= other.use_ipv4_only_;
		is_unix_domain_		= other.is_unix_domain_;

		std::memcpy(last_connect_error_, other.last_connect_error_, sizeof(last_connect_error_));
	}			

	/*
	 * Create a new socket connection based on other
	 */ 
	CLI_SOCKET & operator= (const CLI_SOCKET &other)
	{
		if (this != &other) {
			destroy();

			new (this) CLI_SOCKET(other);
		}	

		return *this;
	}		
	
	CLI_SOCKET & operator= (CLI_SOCKET && other) noexcept
	{
		if (this != &other) {
			destroy();

			new (this) CLI_SOCKET(std::move(other));
		}	

		return *this;
	}	

	~CLI_SOCKET() noexcept
	{
		destroy();
	}	

	void destroy() noexcept
	{
		up_down_cb_ = {};
		close_socket(true);
	}	

	void set_callback(CLI_SOCK_CB && up_down_cb, std::optional<void *> cb_arg1 = {}, std::optional<void *> cb_arg2 = {}) noexcept
	{
		up_down_cb_ = std::move(up_down_cb);

		if (cb_arg1) {
			cb_arg1_ = *cb_arg1;
		}	

		if (cb_arg2) {
			cb_arg2_ = *cb_arg2;
		}	
	}	

	void set_callback(const CLI_SOCK_CB & up_down_cb, std::optional<void *> cb_arg1 = {}, std::optional<void *> cb_arg2 = {})
	{
		up_down_cb_ = up_down_cb;

		if (cb_arg1) {
			cb_arg1_ = *cb_arg1;
		}	

		if (cb_arg2) {
			cb_arg2_ = *cb_arg2;
		}	
	}	

	/*
	 * Results in a getsockname() syscall on every invocation as we do not cache the local sockname
	 * Prints TCP Client IP <IP> Port <Port> : Server IP <IP> Port <Port>
	 */
	char * print_tuple(STR_WR_BUF & strbuf) const noexcept
	{
		if (sock_ >= 0) {
			if (is_unix_domain_ == false) {
				
				struct sockaddr_storage		csockaddr;
				socklen_t			clen = sizeof(csockaddr);
				int 				ret;

				ret = ::getsockname(sock_, (struct sockaddr *)&csockaddr, &clen);

				if (ret == 0) {
					try {
						IP_PORT			cipport((struct sockaddr *)&csockaddr, clen);
						IP_PORT			sipport((struct sockaddr *)&sockaddr_, socklen_);
						
						strbuf.appendconst("TCP Client ");
						cipport.print_string(strbuf);
						strbuf.appendconst(" : Server ");
						sipport.print_string(strbuf);
					}
					catch(...) {
					}	
				}
			}
			else {
				struct sockaddr_un 	*paddr = (sockaddr_un *)&sockaddr_;

				strbuf.appendfmt("Server Path : %s", paddr->sun_path);
			}	
		}
		
		return strbuf.buffer();
	}	
	
	// See comment above
	char * print_tuple(char *printbuf, size_t szbuf) const noexcept
	{
		if (!printbuf) {
			return nullptr;
		}

		STR_WR_BUF		strbuf(printbuf, szbuf);

		return print_tuple(strbuf);
	}	

	char * print_server_string(STR_WR_BUF & strbuf) const noexcept
	{
		if (sock_ >= 0) {
			if (is_unix_domain_ == false) {
				
				try {
					IP_PORT			sipport((struct sockaddr *)&sockaddr_, socklen_);
					
					strbuf.appendconst("TCP Server ");
					sipport.print_string(strbuf);
				}
				catch(...) {
				}	
			}
			else {
				struct sockaddr_un 	*paddr = (sockaddr_un *)&sockaddr_;

				strbuf.appendfmt("Server Path : %s", paddr->sun_path);
			}	
		}
		
		return strbuf.buffer();
	}	
	
	char * print_server_string(char *printbuf, size_t szbuf) const noexcept
	{
		if (!printbuf) {
			return nullptr;
		}

		STR_WR_BUF		strbuf(printbuf, szbuf);

		return print_server_string(strbuf);
	}	

	/*
	 * Returns socket fd if connected.
	 * If currently not connected, will retry connection if not done in current second earlier.
	 * If retry failed, returns -1. If retry not attempted as retry was already done this sec, will return -2. 
	 * Specify force_reconnect in case you need to connect irrespective of whether a connect was attempted this sec earlier
	 */ 
	int get_sock_or_reconnect(bool is_nothrow = true, bool force_reconnect = false)
	{
		if (sock_ >= 0) {
			return sock_;
		}
		
		time_t		tnow = time(nullptr);
		
		if (!force_reconnect && (tnow == tlast_trial_)) {
			return -2;	
		}

		if (auto_reconnect_ == false && tlast_conn_usec_ > 0) {
			return -1;
		}	
		
		return connect_server(is_nothrow);		
	}	

	void close_socket(bool graceful_close = true) noexcept
	{
		is_connected_ 	= false;

		if (sock_ >= 0) {
			if (graceful_close) {
				gy_close_socket(sock_);
			}
			else {
				(void)::close(sock_);
			}	
		}
		else {
			return;
		}	

		sock_ = -1;

		if (up_down_cb_) {
			try {
				up_down_cb_(*this, -1, false /* is_connected */, GY_READ_ONCE(cb_arg1_), GY_READ_ONCE(cb_arg2_));
			}
			catch(...) {
				
			}		
		}
	}
		
	bool is_connected() const noexcept
	{
		return is_connected_;
	}

	const char * get_connect_error_string() const noexcept
	{
		return last_connect_error_;
	}

	int get_sock() const noexcept
	{
		return sock_;	
	}

	// Release socket from object
	int release_sock() noexcept
	{
		int		sock;

		sock = sock_;
		close_socket();

		return sock;
	}

	uint64_t get_connect_time_usec() const noexcept
	{
		return tlast_conn_usec_;	
	}
							
	void get_sock_params(struct sockaddr_storage & sockaddr, socklen_t & socklen, int & sockfamily) const noexcept
	{
		sockaddr	= sockaddr_;
		socklen		= socklen_;
		sockfamily	= sockfamily_;
	}	

	bool is_auto_reconnect() const noexcept
	{
		return auto_reconnect_;
	}	

	ssize_t send_data(const struct iovec *piovin, int iovcnt, int timeout_msec = -1, bool close_on_timeout = false) noexcept
	{
		int			ret;
		ssize_t			sret;
		int			fd = get_sock_or_reconnect(true /* is_nothrow */, false /* force_reconnect */);

		if (fd < 0) {
			return fd;
		}
			
		if (timeout_msec != -1) {
			ret = poll_data(POLLOUT, timeout_msec, close_on_timeout);
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
	ssize_t send_data(const void *sbuf, size_t buflen, int flags = 0, int timeout_msec = -1, bool close_on_timeout = false) noexcept
	{
		const char		*buf = static_cast<const char *>(sbuf);
		int			ret;
		ssize_t			sret;
		int			fd = get_sock_or_reconnect(true /* is_nothrow */, false /* force_reconnect */);

		if (fd < 0) {
			return fd;
		}

		assert(buf);

		if (timeout_msec != -1) {
			ret = poll_data(POLLOUT, timeout_msec, close_on_timeout);
			if (ret <= 0) {
				return ret;	
			}	 
		}	

		sret = gy_sendbuffer(fd, buf, buflen, flags);
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
	ssize_t recv_data(void *rbuf, size_t max_buflen, bool no_block_after_first_recv = true, size_t min_bytes_to_recv = 0, int flags = 0, int timeout_msec = -1, bool close_on_timeout = false) noexcept
	{
		uint8_t			*buf = static_cast<uint8_t *>(rbuf);
		int			ret;
		ssize_t			sret;
		int			fd = get_sock_or_reconnect(true /* is_nothrow */, false /* force_reconnect */);

		if (fd < 0) {
			return fd;
		}

		assert(buf);

		if (timeout_msec != -1) {
			ret = poll_data(POLLIN, timeout_msec, close_on_timeout);
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
		
	int poll_send_allowed(int timeout_msec, bool close_on_timeout = false) noexcept
	{
		return poll_data(POLLOUT, timeout_msec, close_on_timeout);
	}

	int poll_recv_allowed(int timeout_msec, bool close_on_timeout = false) noexcept
	{
		return poll_data(POLLIN, timeout_msec, close_on_timeout);
	}
		
	/*
	 * Specify timeout_msec as -1 for no timeout
	 *
	 * Returns > 0 if socket is available for the event needed
	 * Returns 0 if timeout occured for the event neeeded
	 * Returns < 0 for other errors
	 */ 			
	int poll_data(int16_t poll_events, int timeout_msec, bool close_on_timeout = false) noexcept
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
	
	int connect_server(bool is_nothrow, bool always_resolve_dns = false)
	{
		int			ret = 0, cfd = -1, tfd = -1;

		if (sock_ >= 0 && is_connected_) {
			return 0;
		}
			
		if (gy_unlikely(socklen_ > 0 && sockfamily_ > 0)) {
			/*
			 * First try older resolved address
			 */ 
			cfd = ::socket(sockfamily_, SOCK_STREAM | SOCK_CLOEXEC, 0);
			if (cfd < 0) {
				char		ebuf[64];
				snprintf(last_connect_error_, sizeof(last_connect_error_), "Socket creation failed due to %s for \'%s\' connection", 
					strerror_r(errno, ebuf, sizeof(ebuf) - 1), server_desc_str_);
				
				if (is_nothrow) {
					return -1;
				}	
				GY_THROW_EXCEPTION("%s", last_connect_error_);
			}

			ret = ::connect(cfd, (const struct sockaddr *)&sockaddr_, socklen_); 		
			if (ret == 0) {
				tfd = cfd;
			}
			else {
				char		ebuf[64];
				snprintf(last_connect_error_, sizeof(last_connect_error_), "Could not connect due to %s for \'%s\' connection", 
					strerror_r(errno, ebuf, sizeof(ebuf) - 1), server_desc_str_);

				(void)::close(cfd);	

				/*
				 * Reset socklen_ if auto_reconnect_
				 */ 
				if (auto_reconnect_ == true) {
					socklen_ 	= 0;
					sockfamily_	= 0;
				}
				else if (is_unix_domain_ == false) {
					goto retry1;
				}	
			}		
		}			
		else {
			if (is_unix_domain_ == false) {
retry1 :				
				auto out = gy_tcp_connect(serverhost_, serverport_, last_connect_error_, server_desc_str_, false /* set_nodelay */, always_resolve_dns, 
						&sockaddr_, &socklen_, use_ipv4_only_, false /* set_nonblock */);

				tfd = out.first;
				if (tfd >= 0) {
					sockfamily_ = ((struct sockaddr *)&sockaddr_)->sa_family;
				}	
			}
			else {
				struct sockaddr_un 	*paddr = (sockaddr_un *)&sockaddr_;

				cfd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
				if (cfd < 0) {
					char		ebuf[64];
					snprintf(last_connect_error_, sizeof(last_connect_error_), "Socket creation failed due to %s for \'%s\' connection", 
						strerror_r(errno, ebuf, sizeof(ebuf) - 1), server_desc_str_);
					
					if (is_nothrow) {
						return -1;
					}	
					GY_THROW_EXCEPTION("%s", last_connect_error_);
				}

				std::memset(paddr, 0, sizeof(*paddr));

				socklen_		= sizeof(*paddr);	
				paddr->sun_family 	= AF_UNIX;

				GY_STRNCPY(paddr->sun_path, serverhost_, sizeof(paddr->sun_path) - 1);

				ret = ::connect(cfd, (const struct sockaddr *)&sockaddr_, socklen_); 		
				if (ret == 0) {
					tfd = cfd;
				}
				else {
					char		ebuf[64];
					snprintf(last_connect_error_, sizeof(last_connect_error_), "Could not connect to %s due to %s for \'%s\' connection", 
						paddr->sun_path, strerror_r(errno, ebuf, sizeof(ebuf) - 1), server_desc_str_);
					(void)::close(cfd);	
				}		
			}		
		}
			
		tlast_trial_ 	= time(nullptr);

		if (tfd < 0) {
			if (is_nothrow) {
				return -1;
			}	
			GY_THROW_EXCEPTION("%s", last_connect_error_);
		}	
				
		tlast_conn_usec_ 	= get_usec_time();
		sock_			= tfd;
		is_connected_		= true;
	
		if (set_nodelay_ && !is_unix_domain_) {
			int		to_set = 1;

			::setsockopt(sock_, IPPROTO_TCP, TCP_NODELAY, &to_set, sizeof(to_set));
		}	

		if (up_down_cb_) {
			try {
				up_down_cb_(*this, sock_, true /* is_connected */, GY_READ_ONCE(cb_arg1_), GY_READ_ONCE(cb_arg2_));
			}
			catch(...) {

				::close(sock_);

				sock_ 		= -1;
				is_connected_ 	= false;

				if (!is_nothrow) {
					throw;
				}	

				return -1;
			}		
		}
			
		return 0;
	}	
};	

} // namespace gyeeta
