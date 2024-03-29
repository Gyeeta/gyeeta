//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include 		"gy_server_int.h"

namespace gyeeta {

SERVER_COMM		serv(comm::COMM_HEADER::PS_ADHOC_MAGIC);

SERVER_COMM::SERVER_COMM(comm::COMM_HEADER::HDR_MAGIC_E comm_magic) noexcept
	: comm_magic_(comm_magic)
{
}	

SERVER_COMM * SERVER_COMM::get_singleton() noexcept
{
	return &serv;
}	

uint64_t SERVER_COMM::get_madhava_id() const noexcept
{
	return 0;
}	

bool SERVER_COMM::is_server_connected() const noexcept
{
	return false;
}	

std::shared_ptr<SERVER_CONNTRACK> SERVER_COMM::get_server_conn(comm::CLI_TYPE_E cli_type) noexcept
{
	return {};
}	

bool SERVER_COMM::send_server_data(EPOLL_IOVEC_ARR && iovarr, comm::CLI_TYPE_E cli_type, comm::COMM_TYPE_E comm_type, const std::shared_ptr<SERVER_CONNTRACK> & shrconn) noexcept
{
	return false;
}	

bool SERVER_COMM::send_server_data(ASYNC_SOCK_CB && async_cb, EPOLL_IOVEC_ARR && iovarr, const std::shared_ptr<SERVER_CONNTRACK> & shrconn) noexcept
{
	return false;
}

bool SERVER_COMM::send_event_msg(void *palloc, size_t sz, FREE_FPTR free_fp, size_t nelems, comm::NOTIFY_TYPE_E ntype, const std::shared_ptr<SERVER_CONNTRACK> & shrp)
{
	if (palloc && free_fp) {
		(*free_fp)(palloc);
	}	

	return false;
}

bool SERVER_COMM::send_event_cache(DATA_BUFFER & cache, void *palloc, size_t sz, FREE_FPTR free_fp, size_t nelems, comm::NOTIFY_TYPE_E ntype, const std::shared_ptr<SERVER_CONNTRACK> & shrp)
{
	cache.purge_all();
	return false;
}	

}
