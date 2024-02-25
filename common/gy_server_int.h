//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include 			"gy_common_inc.h"
#include 			"gy_misc.h"
#include 			"gy_epoll_conntrack.h"
#include 			"gy_comm_proto.h"

namespace gyeeta {


using ASYNC_SOCK_CB		= T_ASYNC_SOCK_CB<EPOLL_CONNTRACK>;

class SERVER_CONNTRACK : public EPOLL_CONNTRACK, public ASYNC_CB_HANDLER <EPOLL_CONNTRACK>
{
public :	
	// See EPOLL_CONNTRACK constructor for comments regarding arguments
	SERVER_CONNTRACK(struct sockaddr_storage *psockaddr, int sockfd, int epollfd, void *epoll_data, size_t init_rdbuf_sz, size_t init_wrbuf_sz, bool use_pipeline, uint64_t max_idle_usec = 0, uint64_t pending_timeout_usec = 0, bool close_conn_on_wr_complete = false, bool is_outgoing = false, uint64_t start_clock_usec = get_usec_clock())
		: EPOLL_CONNTRACK(psockaddr, sockfd, epollfd, epoll_data, init_rdbuf_sz, init_wrbuf_sz, use_pipeline, max_idle_usec, pending_timeout_usec, 
				close_conn_on_wr_complete, is_outgoing, start_clock_usec),
		ASYNC_CB_HANDLER<EPOLL_CONNTRACK>(this)
	{}	

	// See EPOLL_CONNTRACK constructor for comments regarding arguments
	SERVER_CONNTRACK(const IP_PORT & peer_ipport, int sockfd, int epollfd, void *epoll_data, size_t init_rdbuf_sz, size_t init_wrbuf_sz, bool use_pipeline, uint64_t max_idle_usec = 0, uint64_t pending_timeout_usec = 0, bool close_conn_on_wr_complete = false, bool is_outgoing = false, uint64_t start_clock_usec = get_usec_clock()) 
		: EPOLL_CONNTRACK(peer_ipport, sockfd, epollfd, epoll_data, init_rdbuf_sz, init_wrbuf_sz, use_pipeline, max_idle_usec, pending_timeout_usec, 
				close_conn_on_wr_complete, is_outgoing, start_clock_usec),
		ASYNC_CB_HANDLER<EPOLL_CONNTRACK>(this)
	{}	
};

class SERVER_COMM
{
public :
	using HDR_MAGIC_E			= comm::COMM_HEADER::HDR_MAGIC_E;

	const HDR_MAGIC_E			comm_magic_;

	static constexpr uint8_t		gpadbuf[8] = "\x0\x0\x0\x0\x0\x0\x0";

	SERVER_COMM(HDR_MAGIC_E comm_magic) noexcept;

	uint64_t get_madhava_id() const noexcept;

	bool is_server_connected() const noexcept;

	std::shared_ptr<SERVER_CONNTRACK> get_server_conn(comm::CLI_TYPE_E cli_type) noexcept;

	int get_trace_sock(bool connect_if_none) const noexcept;

	void reconnect_trace_sock() noexcept;

	bool send_trace_data_blocking(const DATA_BUFFER_ELEM & elem) noexcept;

	bool send_server_data(EPOLL_IOVEC_ARR && iovarr, comm::CLI_TYPE_E cli_type, comm::COMM_TYPE_E comm_type, const std::shared_ptr<SERVER_CONNTRACK> & shrconn) noexcept;
	
	bool send_server_data(ASYNC_SOCK_CB && async_cb, EPOLL_IOVEC_ARR && iovarr, const std::shared_ptr<SERVER_CONNTRACK> & shrconn) noexcept;

	bool send_event_msg(void *palloc, size_t sz, FREE_FPTR free_fp, size_t nelems, comm::NOTIFY_TYPE_E ntype, const std::shared_ptr<SERVER_CONNTRACK> & shrp);

	bool send_event_cache(DATA_BUFFER & cache, void *palloc, size_t sz, FREE_FPTR free_fp, size_t nelems, comm::NOTIFY_TYPE_E ntype, \
				const std::shared_ptr<SERVER_CONNTRACK> & servconn = {});

	HDR_MAGIC_E get_conn_magic() const noexcept
	{
		return comm_magic_;
	}

	static SERVER_COMM * get_singleton() noexcept;
};	

} // namespace gyeeta

