//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma			once

#include		"gy_common_inc.h"
#include		"gy_misc.h"
#include		"gy_print_offload.h"

#include 		<sys/epoll.h>
#include 		<sys/socket.h>
#include 		<sys/un.h>
#include 		<optional>
#include 		<unordered_map>

#pragma 		GCC diagnostic push
#pragma 		GCC diagnostic ignored "-Wsign-compare"

#include		"folly/concurrency/DynamicBoundedQueue.h"
#include 		"folly/Function.h"

#pragma 		GCC diagnostic pop
		

#ifndef 		UNIX_PATH_MAX
#define 		UNIX_PATH_MAX   108
#endif

namespace gyeeta {

using EPOLL_IOVEC_ARR		= IOVEC_ARRAY <8>;

static constexpr int		MAX_IOVEC_ARR 	{EPOLL_IOVEC_ARR::get_max_iovecs()};	// 8

using MPSC_EPOLL_QUEUE		= folly::DMPSCQueue<EPOLL_IOVEC_ARR, false /* Producer/Consumer does not block : polls */, 4 /* 16 elems per segment */>;

/*
 * epoll based socket Connection tracking.  Supports send/recv operations only by a single epoll handler thread.
 *
 * If use_pipeline constructor arg is set, scheduling of sends can be done concurently by multiple threads, although
 * the actual send will still need to be done by the epoll handler thread.
 *
 * recv's are always handled only by the epoll thread.
 *
 * Requires non-blocking sockets and epoll Edge Triggered enabled on the socket.
 * Can be used both by server as well as client epoll threads
 */
class EPOLL_CONNTRACK
{
public :	
	class EDIR_STATS
	{
	public :
		bool				use_iovec_			{false};	// Set by this class on every call to set_buf()

		union {
			struct {
				struct iovec	iovarr_[MAX_IOVEC_ARR];
				FREE_FPTR	free_fp_arr_[MAX_IOVEC_ARR];
				int		niov_;
			};

			struct {
				uint8_t		*pdirbuf_			{nullptr};
				FREE_FPTR	dirbuf_free_fp_			{nullptr};
			};
		};

		uint32_t			max_buf_sz_			{0};		// Set by this class
		uint32_t			data_sz_			{0};		// Set by this class for reads : For writes if set_buf() is called, else needs
		uint32_t			curr_processed_sz_		{0};		// Used by wrstat_ : Available for rdstat_ callbacks to use

		int64_t				nrequests_			{0};		// Set by this class 
		int64_t				nbytes_seen_			{0};		// Set by this class 

		uint64_t			last_oper_cusec_		{0};		// Set by this class unless send/recv is handled externally
		uint64_t			pending_clock_usec_		{0};		// Needs to be set externally if timeout handling needed can be done in again_cb()
		uint32_t			pending_sz_			{0};		// Needs to be set externally if timeout handling needed can be done in again_cb()

		EDIR_STATS() noexcept		= default;

		EDIR_STATS(size_t max_req_sz, uint64_t start_clock_usec = get_usec_clock()) 
			: max_buf_sz_(max_req_sz), last_oper_cusec_(start_clock_usec)
		{
			if (max_buf_sz_) {
				pdirbuf_ = (uint8_t *)malloc(max_buf_sz_ * sizeof(uint8_t));
				if (!pdirbuf_) {
					GY_THROW_SYS_EXCEPTION("Failed to allocate memory for connection data");
				}	
				use_iovec_ 		= false;
				dirbuf_free_fp_		= ::free;
			}	
		}	

		EDIR_STATS(const EDIR_STATS &)	= delete;
		EDIR_STATS(EDIR_STATS &&)	= delete;

		~EDIR_STATS() noexcept
		{
			dealloc();
		}	

		void dealloc() noexcept
		{
			if (use_iovec_ == false) {
				if (pdirbuf_) {
					if (dirbuf_free_fp_) {
						(*dirbuf_free_fp_)(pdirbuf_);
					}

					pdirbuf_ 	= nullptr;
				}
			}
			else {
				for (int i = 0; i < niov_ && i < MAX_IOVEC_ARR; ++i) {
					if (iovarr_[i].iov_base) {
						if (free_fp_arr_[i]) {
							free_fp_arr_[i](iovarr_[i].iov_base);
						}

						iovarr_[i].iov_base = nullptr;
						iovarr_[i].iov_len = 0;
					}
				}

				niov_ 		= 0;
				use_iovec_ 	= false;
			}

			max_buf_sz_ = 0;
		}

		void reset_stats() noexcept
		{
			data_sz_		= 0;
			curr_processed_sz_	= 0;
			pending_clock_usec_	= 0;
			pending_sz_		= 0;
		}	

		/*
		 * On error, the passed pnewbuf is freed first before throwing
		 */
		bool set_buf(uint8_t * pnewbuf, FREE_FPTR free_fp, size_t new_maxbufsz, size_t new_datasz, bool throw_on_error = true)
		{
			assert(data_sz_ == 0);

			if ((data_sz_ > 0) || (new_datasz > new_maxbufsz)) {
				if (free_fp) {
					(*free_fp)(pnewbuf);
				}	
				if (throw_on_error) {	
					GY_THROW_EXCEPTION("Conntrack : New buffer set while existing data pending or invalid buffer parameters");
				}
				else {
					return false;
				}	
			}
		
			dealloc();
			
			pdirbuf_ 	= pnewbuf;
			max_buf_sz_	= new_maxbufsz;
			data_sz_	= new_datasz;
			dirbuf_free_fp_	= free_fp;
			use_iovec_	= false;

			return true;
		}	

		/*
		 * If exception is thrown, the passed piov is freed first before throwing
		 */
		bool set_buf(struct iovec *piov, int niov, FREE_FPTR * pfree_fp_arr, size_t new_datasz, bool throw_on_error = true)
		{
			assert(data_sz_ == 0);
			assert(piov && pfree_fp_arr);

			size_t		new_maxbufsz = iovec_bytes(piov, niov);

			if ((data_sz_ > 0) || ((niov > MAX_IOVEC_ARR) || (new_datasz > new_maxbufsz))) {
				for (int i = 0; i < niov; ++i) {
					if (piov[i].iov_base) {
						if (pfree_fp_arr[i]) {
							pfree_fp_arr[i](piov[i].iov_base);
							piov[i].iov_base = nullptr;
						}	
					}
				}

				if (throw_on_error == false) {
					return false;
				}

				if (data_sz_ > 0) {
					GY_THROW_EXCEPTION("Conntrack : New buffer set while existing data pending");
				}
				else {
					GY_THROW_EXCEPTION("Conntrack : New buffer set invalid buffer parameters");
				}	
			}

			dealloc();
			
			std::memcpy(iovarr_, piov, niov * sizeof(*piov));
			std::memcpy(free_fp_arr_, pfree_fp_arr, niov * sizeof(*free_fp_arr_));
			niov_		= niov;

			use_iovec_	= true;

			max_buf_sz_	= new_maxbufsz;
			data_sz_	= new_datasz;

			return true;
		}	

		void reset_buf(bool to_dealloc = false) noexcept
		{
			if (to_dealloc) {
				dealloc();
			}	

			pdirbuf_ 	= nullptr;
			max_buf_sz_	= 0;
			data_sz_	= 0;
			dirbuf_free_fp_	= nullptr;
			use_iovec_	= false;
		}

		bool is_buf_set() const noexcept
		{
			if (use_iovec_ == false) {
				return pdirbuf_ != nullptr;
			}
			
			return niov_ > 0;
		}

		bool is_buf_iovec() const noexcept
		{
			return use_iovec_;
		}

		bool is_ongoing_data() const noexcept
		{
			return data_sz_ > 0;
		}	

		FREE_FPTR get_dirbuf_freeptr() const noexcept
		{
			if (use_iovec_ == false) {
				return dirbuf_free_fp_;
			}
			return nullptr;
		}	

		FREE_FPTR get_iovec_freeptr(int iov_id) const noexcept
		{
			if (use_iovec_ && iov_id < niov_) {
				return free_fp_arr_[iov_id];
			}
			return nullptr;
		}	

	}; // class EDIR_STATS	

	union SADDR 
	{
		IP_PORT			peer_ipport_;
		char			sun_path_[UNIX_PATH_MAX];

		SADDR() noexcept
		{
			*sun_path_ 	= '\0';
		}

		~SADDR() noexcept
		{}
	};	

	uint64_t			start_clock_usec_		{0};
	SADDR				saddr_;
	uint64_t			max_idle_usec_			{0};			
	uint64_t			pending_timeout_usec_		{0};			

	void				*epoll_data_			{nullptr};
	int				epollfd_			{-1};
	const int			const_sock_;

	bool				close_conn_on_wr_complete_	{false};
	bool				is_inet_			{false};
	bool				is_unix_domain_			{false};
	bool				is_outgoing_conn_		{false};

	int				sockfd_				{-1};
	EDIR_STATS			rdstat_;
	EDIR_STATS			wrstat_;
	std::optional<MPSC_EPOLL_QUEUE>	wr_pipeline_;				// Bounded MPSC Queue of data to be sent. Scheduling allowed by multiple threads. send() only 1 thread
	uint32_t			max_sched_elems_		{4096};	// Max Distinct Messages allowed to be scheduled at one go (not bytes)
	std::atomic<bool>		is_conn_closed_			{false};
	bool				no_grace_close_			{false};

	static constexpr uint32_t	MAX_PIPELINE_SCHED		{32 * 1024};

	/*
	 * Requirements :
	 *
	 * 1. The peer socket is active (i.e. the peer has already been accepted or connected).
	 * 2. The socket has already been set as non-blocking
	 * 3. The epollfd has already been updated with this socket fd. (EPOLL_CTL_ADD already done)
	 * 4. epoll interface used is Edge triggered (EPOLLET)
	 */

	/*
	 * psockaddr		=>	Peer (Remote) IP/Port sockaddr_storage
	 * sockfd		=>	Accept/Connect'ed socket FD
	 * epollfd		=>	epoll handler FD
	 * epoll_data		=>	Identifer for this sockfd to be set in epoll data struct.
	 * init_rdbuf_sz	=>	Initial recv buffer alloc len (can be 0)
	 * init_wrbuf_sz	=>	Initial send buffer alloc len (can be 0)
	 * use_pipeline		=>	Set to true if multiple writer threads or multiple send buffers need to be scheduled before send() call
	 * max_idle_usec	=>	Set to > 0 in case the connection needs to be closed on idle condition. This check needs to be done externally
	 * pending_timeout_usec	=>	Set to > 0 if partial send/recvs's condition is hit. Checking for this needs to be done externally
	 * close_conn_on_wr_complete	=> Set to true for adhoc connections where the connection needs to be closed on first send completion itself
	 * is_outgoing		=>	Set to false for incoming connections
	 */
	EPOLL_CONNTRACK(struct sockaddr_storage *psockaddr, int sockfd, int epollfd, void *epoll_data, size_t init_rdbuf_sz, size_t init_wrbuf_sz, bool use_pipeline, uint64_t max_idle_usec = 0, uint64_t pending_timeout_usec = 0, bool close_conn_on_wr_complete = false, bool is_outgoing = false, uint64_t start_clock_usec = get_usec_clock()) 
		: 
		start_clock_usec_(start_clock_usec), max_idle_usec_(max_idle_usec), pending_timeout_usec_(pending_timeout_usec), epoll_data_(epoll_data),
		epollfd_(epollfd), const_sock_(sockfd), close_conn_on_wr_complete_(close_conn_on_wr_complete), is_outgoing_conn_(is_outgoing), sockfd_(sockfd),
		rdstat_(init_rdbuf_sz, start_clock_usec_), wrstat_(init_wrbuf_sz, start_clock_usec_)
	{
		if (use_pipeline) {
			wr_pipeline_.emplace(max_sched_elems_);
		}

		auto 		sockfamily = psockaddr->ss_family;

		if ((sockfamily == AF_INET) || (sockfamily == AF_INET6)) {
			try {
				IP_PORT		ipport(psockaddr);

				new (&saddr_.peer_ipport_) IP_PORT(ipport);

				is_inet_	= true;

				CONDEXEC(
					DEBUGEXECN(10,
						INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "New Connection : %s by thread TID %d\n", 
							print_peer(STRING_BUFFER<512>().get_str_buf()), gy_gettid());
					);
				);
			}
			catch(...) {
				is_inet_	= false;
			}	
		}
		else {
			is_inet_ = false;

			if (sockfamily == AF_UNIX) {
				struct sockaddr_un 	*paddr = (sockaddr_un *)psockaddr;

				is_unix_domain_	= true;
				snprintf(saddr_.sun_path_, sizeof(saddr_.sun_path_), "%s", paddr->sun_path);
			}	
		}	
	}	

	/*
	 * peer_ipport		=>	Peer (Remote) IP/Port
	 * sockfd		=>	Accept/Connect'ed socket FD
	 * epollfd		=>	epoll handler FD
	 * epoll_data		=>	Identifier for this sockfd to be set in epoll data struct.
	 * init_rdbuf_sz	=>	Initial recv buffer alloc len (can be 0)
	 * init_wrbuf_sz	=>	Initial send buffer alloc len (can be 0)
	 * use_pipeline		=>	Set to true if multiple writer threads or multiple send buffers need to be scheduled before send() call
	 * max_idle_usec	=>	Set to > 0 in case the connection needs to be closed on idle condition. This check needs to be done externally
	 * pending_timeout_usec	=>	Set to > 0 if partial send/recvs's condition is hit. Checking for this needs to be done externally
	 * close_conn_on_wr_complete	=> Set to true for adhoc connections where the connection needs to be closed on first send completion itself
	 * is_outgoing		=>	Set to false for incoming connections
	 */
	EPOLL_CONNTRACK(const IP_PORT & peer_ipport, int sockfd, int epollfd, void *epoll_data, size_t init_rdbuf_sz, size_t init_wrbuf_sz, bool use_pipeline, uint64_t max_idle_usec = 0, uint64_t pending_timeout_usec = 0, bool close_conn_on_wr_complete = false, bool is_outgoing = false, uint64_t start_clock_usec = get_usec_clock()) 
		: 
		start_clock_usec_(start_clock_usec), max_idle_usec_(max_idle_usec), pending_timeout_usec_(pending_timeout_usec), epoll_data_(epoll_data),
		epollfd_(epollfd), const_sock_(sockfd), close_conn_on_wr_complete_(close_conn_on_wr_complete), is_inet_(true), is_unix_domain_(false), is_outgoing_conn_(is_outgoing), 
		sockfd_(sockfd), rdstat_(init_rdbuf_sz, start_clock_usec_), wrstat_(init_wrbuf_sz, start_clock_usec_)
	{
		if (use_pipeline) {
			wr_pipeline_.emplace(max_sched_elems_);
		}

		new (&saddr_.peer_ipport_) IP_PORT(peer_ipport);

		CONDEXEC(
			DEBUGEXECN(10,
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "New Connection : %s by thread TID %d\n", 
							print_peer(STRING_BUFFER<512>().get_str_buf()), gy_gettid());
			);
		);
	}	

	EPOLL_CONNTRACK(const EPOLL_CONNTRACK &)		= delete;
	EPOLL_CONNTRACK(EPOLL_CONNTRACK &&)			= delete;
	EPOLL_CONNTRACK & operator=(const EPOLL_CONNTRACK &)	= delete;
	EPOLL_CONNTRACK & operator=(EPOLL_CONNTRACK &&)		= delete;

	~EPOLL_CONNTRACK() noexcept
	{
		close_conn();

		if (is_inet_) {
			saddr_.peer_ipport_.~IP_PORT();
		}	

		CONDEXEC(
			DEBUGEXECN(10,
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Connection Close : %s\n", print_stats(STRING_BUFFER<512>().get_str_buf()));
			);
		);
	}	

	/*
	 * Will remove the sock from the epoll monitored set and then close the socket
	 */
	void close_conn() noexcept
	{
		if (epollfd_ > 0 && sockfd_ > 0) {
			int			ret;

			ret = epoll_ctl(epollfd_, EPOLL_CTL_DEL, sockfd_, nullptr);
			
			if (no_grace_close_ == false) {
				gy_close_socket(sockfd_);
			}
			else {
				::close(sockfd_);
			}	

			sockfd_ = -1;
		}

		signal_conn_close();
	}

	void set_epollfd(int epollfd) noexcept
	{
		epollfd_ = epollfd;
	}

	void set_epoll_data(void *data) noexcept
	{
		epoll_data_ = data;
	}

	void * get_epoll_data() const noexcept
	{
		return epoll_data_;
	}	

	void set_no_grace_close() noexcept
	{
		no_grace_close_ = true; 
	}	

	void set_wr_pipeline() 
	{
		if (!wr_pipeline_) {
			wr_pipeline_.emplace(max_sched_elems_);
		}	
	}

	// Set Max Pipeline elements allowed. Min 100	
	void set_max_pipeline_sz(uint32_t max_elems) noexcept
	{
		if (bool(wr_pipeline_) && max_elems != max_sched_elems_ && max_elems >= 100 && max_elems < MAX_PIPELINE_SCHED) {
			max_sched_elems_ = max_elems;
			wr_pipeline_->reset_capacity(max_elems);
		}	
	}	

	size_t get_max_pipeline_sz() const noexcept
	{
		if (bool(wr_pipeline_)) {
			return max_sched_elems_;
		}	

		return 0;	
	}	

	void set_max_idle_usec(uint64_t max_idle_usec) noexcept
	{
		max_idle_usec_ 		= max_idle_usec;
	}

	void set_pending_timeout_usec(uint64_t pending_timeout_usec) noexcept
	{
		pending_timeout_usec_ 	= pending_timeout_usec;
	}

	void set_close_conn_on_wr_complete(bool to_close) noexcept
	{
		close_conn_on_wr_complete_ = to_close;
	}

	void set_outgoing_conn(bool is_outgoing) noexcept
	{
		is_outgoing_conn_ = is_outgoing;
	}	

	bool is_outgoing_conn() const noexcept
	{
		return is_outgoing_conn_;
	}	

	// Use this to set is_conn_closed_ as destructor may be delayed due to shared_ptrs
	void signal_conn_close() noexcept
	{
		is_conn_closed_.store(std::memory_order_release);
	}	

	bool is_conn_close_signalled() const noexcept
	{
		return is_conn_closed_.load(std::memory_order_acquire);
	}	


	/*
	 * The req_cb() will be called on reading 1 or more bytes. On error/close connection cases will not be called.
	 * The req_cb() must drain the rdstat_ by calling set_rd_complete() if the request has been completely read. 
	 *
	 * The again_cb() will be called when the reading blocks. The again_cb() must set the rdstat_.pending_sz_
	 * and rdstat_.pending_clock_usec_ if pending timeout handling needed.
	 *
	 * The sys_cb() will be called once the number of recv() syscalls exceeds max_sys_calls. Once that occurs,
	 * the function will return with the number of bytes read. The sys_cb() can be used to setup the socket
	 * recv_data() to be called again before the next epoll_wait().
	 *
	 * The close_cb() will be called if the socket was closed during the operation of the recv(). It can be used
	 * to cleanup the conntrack map based on the socket id.
	 *
	 * If the recv buffer is set as rdstat_.iovarr_ then bytes received per readv syscall will be overwritten 
	 * after every readv syscall and the req_cb() is completed.
	 */
	template <typename FCB_req, typename FCB_again, typename FCB_syscall, typename FCB_close>
	ssize_t recv_data(FCB_req & req_cb, FCB_again & again_cb, FCB_syscall & sys_cb, FCB_close & close_cb, int max_sys_calls = INT_MAX - 1) 
	{
		if (gy_unlikely(sockfd_ < 0)) {
			return -1;
		}

		ssize_t			sret = 0;

		GY_SCOPE_EXIT {
			if (sret > 0) {
				rdstat_.last_oper_cusec_ = get_usec_clock();
			}
		};


		if (rdstat_.use_iovec_ == false) {
			sret = recv_data_buf(req_cb, again_cb, sys_cb, max_sys_calls);
		}
		else {
			sret = recv_data_iovec(req_cb, again_cb, sys_cb, max_sys_calls);
		}

		if (sockfd_ < 0) {
			close_cb(this, const_sock_);
		}

		return sret;
	}	

	/*
	 * The wr_cb() callback will be called one or more times depending on the number of sends scheduled. It will be called 
	 * on completing each set of sends as per wrstat_.data_sz_. For close connection cases will not be called.

	 * Returns the total bytes sent across 1 or more set of messages. -1 on errors. On success will also free up the buffers.
	 * 
	 * The again_cb() will be called when the writing blocks. The again_cb() must set the wrstat_.pending_sz_
	 * and wrstat_.pending_clock_usec_ if pending timeout handling needed.
	 *
	 * The close_cb() will be called if the socket was closed during the operation of the send(). It can be used
	 * to cleanup the conntrack map based on the socket id.
	 *
	 * e.g. callbacks shown below :
	 *
	 		bool			is_closed = false;

			auto wr_cb = [](gyeeta::EPOLL_CONNTRACK * ptconn, ssize_t total_bytes) noexcept
			{
				// Do something if needed after sending 1 message
			};	
			
			auto again_cb = [&](gyeeta::EPOLL_CONNTRACK * ptconn, ssize_t total_bytes) noexcept
			{
				// Set these if timeout handling needed
				ptconn->wrstat_.pending_clock_usec_ 	= gyeeta::get_usec_clock();
				ptconn->wrstat_.pending_sz_		= total_bytes;
			};	

			auto close_cb = [&](gyeeta::EPOLL_CONNTRACK *ptconn, int tsock) noexcept
			{
				is_closed = true;
			};

	 *
	 */
	template <typename FCB_req, typename FCB_again, typename FCB_close>
	ssize_t send_data(FCB_req & wr_cb, FCB_again & again_cb, FCB_close & close_cb, bool & is_blocked) 
	{
		static_assert(noexcept(wr_cb(nullptr, 0)) && noexcept(again_cb(nullptr, 0)) && noexcept(close_cb(nullptr, 0)), "Require noexcept callbacks");

		ssize_t			nsent, total_sent = 0, nmsg_sent = 0;
		bool			bret;

		if (gy_unlikely(sockfd_ < 0)) {
			return -1;
		}

		GY_SCOPE_EXIT {
			if (sockfd_ < 0) {
				close_cb(this, const_sock_);
			}	
		};	

		do {
			if (wrstat_.data_sz_ > 0) {
				if (wrstat_.use_iovec_ == false) {
					nsent = send_data_buf(wr_cb, again_cb, is_blocked);
				}
				else {
					nsent = send_data_iovec(wr_cb, again_cb, is_blocked);
				}	

				if (nsent < 0) {
					return nsent;
				}	

				total_sent += nsent;

				if (is_blocked) {
					if (total_sent > 0) {
						wrstat_.last_oper_cusec_ = get_usec_clock();
					}	
					return total_sent;
				}	

				assert(0 == wrstat_.data_sz_);

				nmsg_sent++;
			}

			/*
			 * Now check the wr_pipeline_ for next set of data to be sent
			 */

			if (wr_pipeline_) {
				EPOLL_IOVEC_ARR 	arr1;
				bool 			avail =  wr_pipeline_->try_dequeue(arr1);

				if (avail) {
					if (arr1.niov_ == 1) {
						wrstat_.set_buf((uint8_t *)arr1.iovarr_[0].iov_base, arr1.free_fp_arr_[0], arr1.iovarr_[0].iov_len, arr1.iovarr_[0].iov_len);
					}	
					else {
						wrstat_.set_buf(arr1.iovarr_, arr1.niov_, arr1.free_fp_arr_, iovec_bytes(arr1.iovarr_, arr1.niov_));
					}

					arr1.reset();
				}	
			}
			
			if (wrstat_.data_sz_ == 0) {
				if (total_sent > 0) {
					if (close_conn_on_wr_complete_) {
						close_conn();
					}
					else {
						wrstat_.last_oper_cusec_ = get_usec_clock();
					}	
				}	
				break;
			}

		} while (true);	

		return total_sent;
	}	

	/*
	 * This populates the next set of buffers to be sent, but does not call the actual send.
	 * 
	 * If wr_pipeline_ is active, can be called by multiple writer threads although the send_data() needs
	 * to be called by the epoll handling thread only.
	 * 
	 * Throws an exception if no empty slots available (after deallocating the passed iovarr unless an unrecoverable exception occurs) 
	 * and throw_on_error is true, else returns false on error. Even if throw_on_error is false, may still throw an exception on other unrecoverable
	 * errors
	 */
	bool schedule_ext_send(EPOLL_IOVEC_ARR && iovarr, bool throw_on_error = true)
	{
		if (gy_unlikely(iovarr.get_num_iovec() <= 0)) {
			return false;
		}	

		if (wr_pipeline_) {
			bool 		success;

			/*
			 * try_enqueue() will fail if more than max_sched_elems_ elems already enqueued
			 */
			success = wr_pipeline_->try_enqueue(std::move(iovarr));

			if (false == success) {
				iovarr.dealloc();

				if (throw_on_error) {
					GY_THROW_EXCEPTION("Max possible messages already scheduled for sends");
				}
				return false;
			}	
		}	
		else if (wrstat_.data_sz_ == 0) {
			// Single threaded scheduling
			wrstat_.set_buf(iovarr.iovarr_, iovarr.get_num_iovec(), iovarr.free_fp_arr_, iovarr.get_byte_count(), throw_on_error);
			iovarr.reset();
		}	
		else {
			iovarr.dealloc();

			if (throw_on_error) {
				GY_THROW_EXCEPTION("Too many messages already scheduled for sends");
			}
			else {
				return false;
			}	
		}	

		return true;
	}
		
	size_t num_sends_scheduled() const noexcept
	{
		size_t			nsch = size_t(!!wrstat_.data_sz_) + (wr_pipeline_ ? wr_pipeline_->size() : 0);
		
		return nsch;
	}	

	size_t num_sends_possible() const noexcept
	{
		if (wr_pipeline_) {
			return (max_sched_elems_ - wr_pipeline_->size());
		}	

		return !wrstat_.is_ongoing_data();
	}

	bool sends_possible() const noexcept
	{
		return !!num_sends_possible();
	}

	bool send_data_pending() const noexcept
	{
		return (wrstat_.is_ongoing_data() || (wr_pipeline_ && false == wr_pipeline_->empty()));
	}

	void set_wr_complete() noexcept
	{
		wrstat_.nrequests_++;
		wrstat_.nbytes_seen_ += wrstat_.data_sz_;

		wrstat_.reset_stats();
	}	

	void set_rd_complete() noexcept
	{
		rdstat_.nrequests_++;
		rdstat_.reset_stats();
	}	

	bool get_peer_ip_port(IP_PORT & ip_port) const noexcept
	{
		if (is_inet_ == true) {
			ip_port = saddr_.peer_ipport_;
			return true;
		}

		return false;
	}

	bool get_peer_ip(GY_IP_ADDR & ipaddr) const noexcept
	{
		if (is_inet_ == true) {
			ipaddr = saddr_.peer_ipport_.ipaddr_;
			return true;
		}

		return false;
	}

	char * print_peer(STR_WR_BUF & strbuf) const noexcept
	{
		strbuf.appendconst("Remote Peer ");

		if (is_inet_ == true) {
			return saddr_.peer_ipport_.print_string(strbuf);
		}	

		return strbuf.buffer();
	}	

	char * print_peer(char *pbuf, size_t szbuf) const noexcept
	{
		if (!pbuf) {
			return nullptr;
		}

		STR_WR_BUF	strbuf(pbuf, szbuf);

		return print_peer(strbuf);
	}

	char * print_conn(STR_WR_BUF & strbuf) const noexcept
	{
		print_peer(strbuf);

		return strbuf.buffer();
	}	

	/*
	 * Results in a getsockname() syscall on every invocation as we do not cache the server sockname
	 * Prints (for Inet sockets) Remote Peer IP <IP> Port <Port> : Local IP <IP> Port <Port>
	 */
	char * print_tuple(STR_WR_BUF & strbuf) const noexcept
	{
		if (sockfd_ > 0) {
			if (is_inet_) {	
				struct sockaddr_storage		ssockaddr;
				socklen_t			slen = sizeof(ssockaddr);
				int 				ret;

				ret = ::getsockname(sockfd_, (struct sockaddr *)&ssockaddr, &slen);

				if (ret == 0) {
					try {
						IP_PORT			sipport((struct sockaddr *)&ssockaddr, slen);
						
						strbuf.appendconst("Remote Peer ");
						saddr_.peer_ipport_.print_string(strbuf);

						strbuf.appendconst(" : Local ");
						sipport.print_string(strbuf);
					}
					catch(...) {
					}	
				}
			}
			else if (is_unix_domain_) {
				strbuf.appendfmt("Server Path : %s", saddr_.sun_path_);
			}	
		}
		
		return strbuf.buffer();
	}	

	char * print_stats(STR_WR_BUF & strbuf, bool show_tuple = false, uint64_t curr_clock_usec = get_usec_clock()) const noexcept
	{
		if (show_tuple == false) {
			print_peer(strbuf);
		}
		else {
			print_tuple(strbuf);
		}	

		strbuf.appendfmt(" : Read #Requests %ld #Bytes %ld : Write #Requests %ld #Bytes %ld : Peer connected from %lu usec (%lu sec) ago", 
			rdstat_.nrequests_, rdstat_.nbytes_seen_, wrstat_.nrequests_, wrstat_.nbytes_seen_, 
			curr_clock_usec - start_clock_usec_, (curr_clock_usec - start_clock_usec_)/GY_USEC_PER_SEC);

		return strbuf.buffer();
	}	

	char * print_stats(char *pbuf, size_t szbuf, uint64_t curr_clock_usec = get_usec_clock()) const noexcept
	{
		if (!pbuf) {
			return nullptr;
		}

		STR_WR_BUF		strbuf(pbuf, szbuf);

		return print_stats(strbuf, false, curr_clock_usec);
	}

	/*
	 * Release socket for external handling by deleting epoll ctl 
	 * The socket if active is in Non-blocking mode. This call should
	 * be followed by destruction of this object to release resources allocated.
	 *
	 * Returns active socket fd or -1 if not active.
	 */
	int release_sock() noexcept
	{
		int			sock = -1;

		if (epollfd_ > 0 && sockfd_ > 0) {
			sock = sockfd_;

			(void)epoll_ctl(epollfd_, EPOLL_CTL_DEL, sockfd_, nullptr);
			sockfd_ = -1;
		}

		return sock;
	}

	int get_sockfd() const noexcept
	{
		return sockfd_;
	}	

	uint64_t get_last_oper_clock() const noexcept
	{
		return std::max(wrstat_.last_oper_cusec_, rdstat_.last_oper_cusec_);
	}

	uint64_t get_last_recv_clock() const noexcept
	{
		return rdstat_.last_oper_cusec_;
	}	

	uint64_t get_last_send_clock() const noexcept
	{
		return wrstat_.last_oper_cusec_;
	}	

	bool is_idle_timedout(uint64_t curr_clock_usec = get_usec_clock()) const noexcept
	{
		return (((int64_t)max_idle_usec_ > 0) && 
			(curr_clock_usec - rdstat_.last_oper_cusec_ > max_idle_usec_) && (curr_clock_usec - wrstat_.last_oper_cusec_ > max_idle_usec_)); 
	}	

	bool is_pending_timeout(uint64_t curr_clock_usec = get_usec_clock()) const noexcept
	{
		return ((rdstat_.pending_sz_ > 0 && curr_clock_usec - rdstat_.pending_clock_usec_ > pending_timeout_usec_) ||
			(wrstat_.pending_sz_ > 0 && curr_clock_usec - wrstat_.pending_clock_usec_ > pending_timeout_usec_));
	}	

	bool pending_recv_seen(size_t nbytes) noexcept
	{
		if (rdstat_.pending_sz_) {
			if (rdstat_.pending_sz_ >= nbytes) {
				rdstat_.pending_sz_ = 0;
				rdstat_.pending_clock_usec_ = 0;

				return true;
			}	
			else {
				rdstat_.pending_sz_ -= nbytes;
				return false;
			}	
		}	
		return true;
	}

	uint64_t get_bytes_sent() const noexcept
	{
		return wrstat_.nbytes_seen_;
	}

	uint64_t get_reqs_sent() const noexcept
	{
		return wrstat_.nrequests_;
	}

	uint64_t get_bytes_rcvd() const noexcept
	{
		return rdstat_.nbytes_seen_;
	}

	uint64_t get_reqs_rcvd() const noexcept
	{
		return rdstat_.nrequests_;
	}

protected :

	template <typename FCB_req, typename FCB_again, typename FCB_syscall>
	ssize_t recv_data_buf(FCB_req & req_cb, FCB_again & again_cb, FCB_syscall & sys_cb, int max_sys_calls) 
	{
		ssize_t			sret, max_bytes, totbytes = 0;
		int			nsyscall = 0;
		uint8_t			*prdbuf = rdstat_.pdirbuf_;

		if (!prdbuf) {
			close_conn();
			return -1;
		}	

		do {
			max_bytes = rdstat_.max_buf_sz_ > rdstat_.data_sz_ ? rdstat_.max_buf_sz_ - rdstat_.data_sz_ : 0;

			assert(max_bytes > 0);

			if (gy_unlikely(max_bytes == 0)) {
				// The previous req_cb() did not drain the buffer and now no space available
				GY_THROW_EXCEPTION("Connection recv callback error stats not drained...");
			}	

			if (gy_unlikely(nsyscall++ > max_sys_calls)) {
				sys_cb(this);

				return totbytes;
			}	

			sret = ::recv(sockfd_, prdbuf + rdstat_.data_sz_, max_bytes, 0);
			if (sret > 0) {
				rdstat_.data_sz_ 	+= sret;
				rdstat_.nbytes_seen_ 	+= sret;

				totbytes 		+= sret;

				req_cb(rdstat_.data_sz_, (uint32_t)sret, rdstat_, this, &prdbuf /* If prdbuf needs to be modified */, nullptr); 

				assert(prdbuf);
			}
			else if (sret == 0) {
				close_conn();
				return -1;
			}
			else {
				if (errno == EINTR) {
					continue;
				}
				else if (errno == EAGAIN) {
					again_cb(this);

					return totbytes;
				}	
				else {
					close_conn();
					return -1;
				}
			}	

			/*
			 * XXX The below while condition assumes we will not get an EINTR whilst the recv is active resulting in a lesser 
			 * number of bytes but not -1. If that condition occurs we will miss the Edge trigger and only when the next 
			 * trigger occurs will the pending bytes be read... This was done to avoid an extra recv() syscall
			 */
		} while (sret == max_bytes);

		return totbytes;
	}	

	/*
	 * The FCB_req req_cb() must copy/drain the rdstat_.iovarr_ on every call as on every recv_data() the iovarr_ will be overwritten
	 * The again_cb() must also drain the rdstat_.iovarr_ as iovarr_ will be overwritten or change the piov && niov variables
	 * to point to a new iovec array and withn the callback maintain state
	 */
	template <typename FCB_req, typename FCB_again, typename FCB_syscall>
	ssize_t recv_data_iovec(FCB_req & req_cb, FCB_again & again_cb, FCB_syscall & sys_cb, int max_sys_calls) 
	{
		ssize_t			sret, max_bytes = rdstat_.max_buf_sz_, totbytes = 0;
		int			nsyscall = 0;
		struct iovec		*piov = rdstat_.iovarr_;
		int			niov = rdstat_.niov_;

		if (!rdstat_.max_buf_sz_) {
			close_conn();
			return -1;
		}

		do {
			if (gy_unlikely(nsyscall++ > max_sys_calls)) {
				sys_cb(this);

				return totbytes;
			}	

			sret = ::readv(sockfd_, piov, niov);
			if (sret > 0) {
				rdstat_.data_sz_ 	= sret;
				rdstat_.nbytes_seen_ 	+= sret;
				totbytes		+= sret;

				req_cb(rdstat_.data_sz_, (uint32_t)sret, rdstat_, this, &piov /* If piov needs to be updated */, &niov); 

				assert(piov && niov > 0);
			}
			else if (sret == 0) {
				close_conn();
				return -1;
			}
			else {
				if (errno == EINTR) {
					continue;
				}
				else if (errno == EAGAIN) {
					again_cb(this);

					return totbytes;
				}	
				else {
					close_conn();
					return -1;
				}
			}	

			/*
			 * XXX The below while condition assumes we will not get an EINTR whilst the readv is active resulting in a lesser 
			 * number of bytes but not -1. If that condition occurs we will miss the Edge trigger and only when the next 
			 * trigger occurs will the pending bytes be read... This was done to avoid an extra readv() syscall
			 */
		} while (sret == max_bytes);

		return totbytes;
	}	

	template <typename FCB_req, typename FCB_again>
	ssize_t send_data_buf(FCB_req & wr_cb, FCB_again & again_cb, bool & is_blocked) 
	{
		ssize_t			sret, max_bytes, totbytes = 0;
		uint8_t			*pwrbuf = wrstat_.pdirbuf_;
		int			flags = MSG_NOSIGNAL;

		if (!pwrbuf) {
			close_conn();
			return -1;
		}	
		
		assert(wrstat_.data_sz_ <= wrstat_.max_buf_sz_ && wrstat_.curr_processed_sz_ <= wrstat_.data_sz_);
		
		max_bytes = wrstat_.data_sz_ > wrstat_.curr_processed_sz_ ? wrstat_.data_sz_ - wrstat_.curr_processed_sz_ : 0;

		if (gy_unlikely(max_bytes <= 0)) {
			is_blocked	= false;

			wrstat_.reset_stats();
			return 0;
		}	

try_again :
		sret = ::send(sockfd_, pwrbuf + wrstat_.curr_processed_sz_, max_bytes, flags);
		if (sret > 0) {
			wrstat_.curr_processed_sz_ 	+= sret;	
			totbytes 			= sret;

			if (max_bytes == sret) {
				is_blocked	= false;

				wr_cb(this, totbytes);

				set_wr_complete();

				return totbytes;
			}
			else {
				/*
				 * XXX The above condition assumes we will not get an EINTR whilst the send is active resulting in a lesser 
				 * number of bytes but not -1. If that condition occurs we will miss the Edge trigger and only when the next 
				 * schedule_ext_send occurs will the pending bytes be sent... This was done to avoid an extra send() syscall
				 */

				goto handle_eagain;
			}	

		}
		else {
			if (errno == EINTR) {
				goto try_again;
			}
			else if (errno == EAGAIN) {
handle_eagain :				
				is_blocked = true;

				again_cb(this, max_bytes /* pending bytes */);

				return totbytes;
			}
			else {
				close_conn();
				return -1;
			}	
		}	
	}	

	template <typename FCB_req, typename FCB_again>
	ssize_t send_data_iovec(FCB_req & wr_cb, FCB_again & again_cb, bool & is_blocked) 
	{
		ssize_t			sret, totbytes = 0;
		struct iovec		iov_pending[MAX_IOVEC_ARR];
		size_t			pending_bytes = 0;
		bool			base_const_arr[MAX_IOVEC_ARR];
		
		if (gy_unlikely((wrstat_.niov_ <= 0) || (wrstat_.niov_ > MAX_IOVEC_ARR))) {
			close_conn();
			return -1;
		}	
		
		assert(wrstat_.data_sz_ <= wrstat_.max_buf_sz_ && wrstat_.data_sz_ >= wrstat_.iovarr_[0].iov_len);
		
		for (int i = 0; i < wrstat_.niov_; ++i) {
			base_const_arr[i] = !!wrstat_.free_fp_arr_[i];
		}	

		sret = gy_writev(sockfd_, wrstat_.iovarr_, wrstat_.niov_, iov_pending, &pending_bytes, true /* is_stream_socket */, base_const_arr);
		if (sret < 0) {
			close_conn();
			return -1;
		}	

		if (pending_bytes > 0) {
			is_blocked = true;
			
			again_cb(this, pending_bytes);

			std::memcpy(wrstat_.iovarr_, iov_pending, wrstat_.niov_ * sizeof(*iov_pending));

			wrstat_.data_sz_ 	= pending_bytes;
			wrstat_.max_buf_sz_ 	= pending_bytes;
		}	
		else {
			is_blocked = false;

			if (gy_likely(sret > 0)) {
				wr_cb(this, sret);
				set_wr_complete();
			}	
			else {
				// No bytes were scheduled. Cleanup stuff
				wrstat_.reset_stats();
			}	
		}	

		return sret;
	}	
};	

/*
 * Classes for storing Async Recv Callbacks...
 */
template <typename ConnTrack>
class T_ASYNC_SOCK_CB
{
public :
	// 			pact_resp is the actual response payload after stripping off any prior headers. presphdr is the start of the response itself
	using READ_CB 		= folly::Function<bool(ConnTrack * pconn, void * pact_resp, size_t nact_resp, void * presphdr, bool is_expiry, bool is_error)>;

	READ_CB			fcb_;
	uint64_t		seqid_			{0};	
	time_t			texpiry_sec_		{0};	

	T_ASYNC_SOCK_CB() noexcept			= default;

	/*
	 * Set seqid using ASYNC_CB_HANDLER::next_callback_seqid() and 
	 * texpiry_sec as time(nullptr) + expiry secs or 0 for no expiry
	 */
	T_ASYNC_SOCK_CB(READ_CB && fcb, uint64_t seqid, time_t texpiry_sec) noexcept
		: fcb_(std::move(fcb)), seqid_(seqid), texpiry_sec_(texpiry_sec)
	{}	

	/*
	 * Use this constructor only for connect async callbacks as the seqid_ will be 
	 * populated on add_connect_cb() call
	 */
	T_ASYNC_SOCK_CB(READ_CB && fcb, time_t texpiry_sec) noexcept
		: fcb_(std::move(fcb)), seqid_(1), texpiry_sec_(texpiry_sec)
	{}	

	T_ASYNC_SOCK_CB(T_ASYNC_SOCK_CB &&) noexcept	= default;

	bool is_expired(time_t tcurr = time(nullptr)) const noexcept
	{
		return texpiry_sec_ > 0 && texpiry_sec_ < tcurr && seqid_ > 0;
	}

	uint64_t get_seqid() const noexcept
	{
		return seqid_;
	}

	time_t get_expiry_sec() const noexcept
	{
		return texpiry_sec_;
	}	

	READ_CB & get_fcb() noexcept
	{
		return fcb_;
	}

	bool is_valid() const noexcept
	{
		return (seqid_ > 0 && fcb_);
	}

	void reset() noexcept
	{
		fcb_ 		= nullptr;
		seqid_		= 0;
		texpiry_sec_	= 0;
	}	

};	

/*
 * Not thread safe. Assumes async cb adds / cancels / extracts done by the same thread
 * Max allowed callbacks pending per connection is currently 2048
 */
template <typename ConnTrack>
class ASYNC_CB_HANDLER
{
protected :
	using ASYNC_TBL	= 		std::unordered_map <int64_t, T_ASYNC_SOCK_CB<ConnTrack>, GY_JHASHER<int64_t>>;

	static constexpr size_t		LOW_MARK_NASYNC_CB		{128};
	static constexpr size_t		HIGH_MARK_NASYNC_CB		{1024};
	static constexpr size_t		MAX_NASYNC_CB			{2048};

	ASYNC_TBL			cb_tbl_;
	int64_t				ncallbacks_added_		{0};
	int64_t				ncallbacks_expired_		{0};
	time_t				tmin_next_expiry_sec_		{LONG_MAX - 1};

	ConnTrack			*pconn_;

public :

	ASYNC_CB_HANDLER() 		= delete;

	ASYNC_CB_HANDLER(ConnTrack *pconn) noexcept : pconn_(pconn)
	{}	

	/*
	 * Not thread-safe : Must only be called from the Map writer thread
	 * Will throw exception in case max callback limit reached...
	 */
	bool add_async_callback(T_ASYNC_SOCK_CB<ConnTrack> && cb, size_t *pncbs_deleted = nullptr) 
	{
		if (false == cb.is_valid()) {
			return false;
		}	

		try {
			const time_t		texpiry = cb.get_expiry_sec();

			if (cb_tbl_.size() > LOW_MARK_NASYNC_CB) {

				size_t 			ncbs_deleted;

				ncbs_deleted = cleanup_async_cbs();

				if (cb_tbl_.size() > HIGH_MARK_NASYNC_CB) {
					// Check if the conn has been idle for at least 5 min. If so, close the conn
					if (get_usec_clock() - pconn_->get_last_recv_clock() > 2 * GY_USEC_PER_MINUTE) {
						ERRORPRINT_OFFLOAD("%s connection has not received responses for a long time and a lot of callbacks %lu have been lined up. "
							"Throwing exception to avoid callback flooding...\n", 
							pconn_->print_conn(STRING_BUFFER<512>().get_str_buf()), cb_tbl_.size());

						GY_THROW_EXCEPTION("Too many callbacks for a long idle connection");
					}	

					if (cb_tbl_.size() >= MAX_NASYNC_CB) {
						ERRORPRINT_OFFLOAD("%s connection has max number of callbacks %lu lined up. Cannot add any new callback. "
							"Throwing exception to avoid callback flooding...\n", 
							pconn_->print_conn(STRING_BUFFER<512>().get_str_buf()), cb_tbl_.size());

						GY_THROW_EXCEPTION("Max callbacks scheduled for connection");
					}	
				}	

				if (ncbs_deleted) {
					DEBUGEXECN(1, 
						INFOPRINT_OFFLOAD("%s missed handling %lu async callbacks...\n", pconn_->print_conn(STRING_BUFFER<512>().get_str_buf()), ncbs_deleted);
					);	
				}

				if (pncbs_deleted) {
					*pncbs_deleted = ncbs_deleted;	
				}
			}
			else if (pncbs_deleted) {
				*pncbs_deleted = 0;
			}

			auto [it, success] = cb_tbl_.try_emplace(cb.get_seqid(), std::move(cb));
			
			if (success) {
				if (texpiry < tmin_next_expiry_sec_ && texpiry > 0) {
					tmin_next_expiry_sec_ = texpiry;
				}	

				ncallbacks_added_++;
			}

			return success;

		}
		catch(...) {
			try {
				cb.fcb_(pconn_, nullptr, 0, nullptr, false /* is_expiry */, true /* is_error */);
			}
			catch(...) {
			}	

			throw;
		}	
	}	

	/*
	 * Not thread-safe : Must only be called from the Map writer thread
	 * We reuse the recv cb_tbl_ for async connect callbacks with success cb having seqid 1 and failure 2
	 */
	bool add_connect_cb(T_ASYNC_SOCK_CB<ConnTrack> && cb, bool is_success_cb = true)
	{
		cb.seqid_ = (is_success_cb ? 1 : 2);

		if (false == cb.is_valid()) {
			return false;
		}	

		try {
			const time_t		texpiry = cb.get_expiry_sec();
			auto 			[it, success] = cb_tbl_.try_emplace(cb.seqid_, std::move(cb));

			if (success) {
				if (texpiry < tmin_next_expiry_sec_ && texpiry > 0) {
					tmin_next_expiry_sec_ = texpiry;
				}	

				ncallbacks_added_++;
			}
				
			return success;
		}
		catch(...) {
			try {
				cb.fcb_(pconn_, nullptr, -1, nullptr, false /* is_expiry */, true /* is_error */);
			}
			catch(...) {
			}	

			throw;
		}	
	}	

	/* 
	 * Not thread-safe : Must only be called from the Map writer thread
	 */
	void cancel_recv_cb(uint64_t seqid) noexcept
	{
		auto		ecb = extract_recv_cb(seqid);

		if (ecb.has_value()) {
			try {
				ecb->fcb_(pconn_, nullptr, 0, nullptr, false /* is_expiry */, true /* is_error */);
			}
			catch(...) {
			}	
		}
	}

	/*
	 * Finds and extracts the cb from the map
	 * Not thread-safe : Must only be called from the Map writer thread
	 */	 
	std::optional <T_ASYNC_SOCK_CB<ConnTrack>> extract_recv_cb(uint64_t seqid) noexcept
	{
		std::optional <T_ASYNC_SOCK_CB<ConnTrack>> 	cb;

		auto it = cb_tbl_.find(seqid);

		if (it != cb_tbl_.end()) {
			cb.emplace(std::move(it->second));

			cb_tbl_.erase(it);

			if ((true == bool(cb)) && (false == cb->is_valid())) {
				cb.reset();
			}	
		}

		return cb;
	}

	/*
	 * Finds and returns the cb iter from the map. Use this ONLY if the CB needs to be kept for e.g. in case
	 * of an incomplete response. Returns iterator to element or end if not found.
	 * Not thread-safe : Must only be called from the Map writer thread. Will not delete the Callback.
	 */	 
	std::pair<decltype(cb_tbl_.find(0)), bool> find_recv_cb(uint64_t seqid) noexcept
	{
		auto it = cb_tbl_.find(seqid);

		return {it, it != cb_tbl_.end()};
	}

	/*
	 * To be called once an async TCP connect is signalled EPOLLOUT indicating the connect has completed.
	 * Returns 0 in case of Async Connect sucess and Callback success
	 */
	ssize_t handle_async_connect() 
	{
		assert(pconn_->is_outgoing_conn() == true);

		int			ret, sock = pconn_->get_sockfd();
		bool			bret;
		socklen_t		rlen = sizeof(ret);

		if ((0 == getsockopt(sock, SOL_SOCKET, SO_ERROR, &ret, &rlen)) && (ret == 0)) {
			// Check if success callback registered
			auto 		scb = extract_recv_cb(1);

			if (scb.has_value()) {
				bret = scb->fcb_(pconn_, nullptr, 0, nullptr, false /* is_expiry */, false /* is_error */);

				if (bret == false) {
					CONDEXEC(
						DEBUGEXECN(1, 
							WARNPRINTCOLOR_OFFLOAD(GY_COLOR_LIGHT_RED, "Connection %s connect callback errored out. Closing connection...\n",
								pconn_->print_peer(STRING_BUFFER<128>().get_str_buf()));
						);
					);

					return -1;
				}	
			}

			return 0;	
		}

		// Check if failure callback registered
		auto 		ecb = extract_recv_cb(2);

		if (ecb.has_value()) {
			ecb->fcb_(pconn_, nullptr, ret, nullptr, false /* is_expiry */, true /* is_error */);
		}

		return -1;
	}

	size_t get_nrecv_cbs() const noexcept
	{
		return cb_tbl_.size();
	}	

	time_t get_next_async_timeout_sec() const noexcept
	{
		return tmin_next_expiry_sec_;
	}	

	char * print_cb_stats(STR_WR_BUF & strbuf) const noexcept
	{
		if (ncallbacks_added_ > 0) {
			strbuf.appendfmt(" Callbacks Added %ld Expired %ld ", ncallbacks_added_, ncallbacks_expired_);
		}

		return strbuf.buffer();
	}	

	/* 
	 * Not thread-safe : Must only be called from the Map writer thread
	 */
	size_t cleanup_async_cbs(time_t tcurr = time(nullptr)) noexcept
	{
		size_t			ndel = 0;
		time_t			tmin = LONG_MAX - 1;

		if (tcurr < tmin_next_expiry_sec_) {
			return 0;
		}	

		for (auto it = cb_tbl_.begin(); it != cb_tbl_.end(); ) {

			auto & cb = it->second;

			if (cb.is_expired(tcurr)) {
				
				if (cb.fcb_) {
					try {
						cb.fcb_(pconn_, nullptr, 0, nullptr, true /* is_expiry */, false /* is_error */);
					}
					catch(...) {
					}	
				}

				it = cb_tbl_.erase(it);
				ndel++;
			}
			else {
				const time_t		texpiry = cb.get_expiry_sec();
				
				if (texpiry > 0 && texpiry < tmin) {
					tmin = texpiry;
				}

				++it;
			}
		}	

		tmin_next_expiry_sec_ = tmin;

		ncallbacks_expired_ += ndel;
		
		return ndel;
	}	

	/* 
	 * Not thread-safe : Must only be called from the Map writer thread
	 */
	void clear_all_callbacks() noexcept
	{
		for (auto it = cb_tbl_.begin(); it != cb_tbl_.end(); ) {

			auto & cb = it->second;

			if (cb.fcb_) {
				try {
					cb.fcb_(pconn_, nullptr, 0, nullptr, false /* is_expiry */, true /* is_error */);
				}
				catch(...) {
				}	
			}

			it = cb_tbl_.erase(it);
		}	

		tmin_next_expiry_sec_ = LONG_MAX - 1;
	}	
	
	static uint64_t next_callback_seqid() noexcept
	{
		return get_nsec_clock() ^ ((uint64_t)(gy_gettid() & 0x7FF) << 32);
	}	
};	

} // namespace gyeeta	

