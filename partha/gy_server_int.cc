//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_server_int.h"
#include			"gy_paconnhdlr.h"

namespace gyeeta {

static SERVER_COMM *		pgservercomm_ = nullptr;

SERVER_COMM::SERVER_COMM(comm::COMM_HEADER::HDR_MAGIC_E comm_magic) noexcept
	: comm_magic_(comm_magic)
{
	pgservercomm_		= this;
}	

SERVER_COMM * SERVER_COMM::get_singleton() noexcept
{
	return pgservercomm_;
}	

uint64_t SERVER_COMM::get_madhava_id() const noexcept
{
	const partha::PACONN_HANDLER	*paconn = static_cast<const partha::PACONN_HANDLER *>(this);

	return paconn->get_madhava_id();
}

bool SERVER_COMM::is_server_connected() const noexcept
{
	const partha::PACONN_HANDLER	*paconn = static_cast<const partha::PACONN_HANDLER *>(this);

	return paconn->is_server_connected();
}	

std::shared_ptr<SERVER_CONNTRACK> SERVER_COMM::get_server_conn(comm::CLI_TYPE_E cli_type) noexcept
{
	partha::PACONN_HANDLER		*paconn = static_cast<partha::PACONN_HANDLER *>(this);

	return paconn->get_server_conn(cli_type);
}	

bool SERVER_COMM::send_server_data(EPOLL_IOVEC_ARR && iovarr, comm::CLI_TYPE_E cli_type, comm::COMM_TYPE_E comm_type, const std::shared_ptr<SERVER_CONNTRACK> & shrconn) noexcept
{
	partha::PACONN_HANDLER		*paconn = static_cast<partha::PACONN_HANDLER *>(this);

	return paconn->send_server_data(std::move(iovarr), cli_type, comm_type, shrconn);
}	

bool SERVER_COMM::send_server_data(ASYNC_SOCK_CB && async_cb, EPOLL_IOVEC_ARR && iovarr, const std::shared_ptr<SERVER_CONNTRACK> & shrconn) noexcept
{
	partha::PACONN_HANDLER		*paconn = static_cast<partha::PACONN_HANDLER *>(this);

	return paconn->send_server_data(std::move(async_cb), std::move(iovarr), shrconn);
}	

bool SERVER_COMM::send_event_msg(void *palloc, size_t sz, FREE_FPTR free_fp, size_t nelems, comm::NOTIFY_TYPE_E ntype, const std::shared_ptr<SERVER_CONNTRACK> & shrp)
{
	using namespace		comm;

	if (!shrp) {
		if (palloc && free_fp) {
			(*free_fp)(palloc);
		}	
		return false;
	}

	assert(palloc && sz >= sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY));

	COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
	EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1); 
	bool				bret;

	new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, sz, get_conn_magic());

	new (pnot) EVENT_NOTIFY(ntype, nelems);

	return this->send_server_data(EPOLL_IOVEC_ARR(2, false, phdr, phdr->get_act_len(), free_fp, gpadbuf, phdr->get_pad_len(), nullptr), 
					comm::CLI_TYPE_REQ_ONLY, COMM_EVENT_NOTIFY, shrp);

}	

bool SERVER_COMM::send_event_cache(DATA_BUFFER & cache, void *palloc, size_t sz, FREE_FPTR free_fp, size_t nelems, comm::NOTIFY_TYPE_E ntype, const std::shared_ptr<SERVER_CONNTRACK> & shrp)
{
	using namespace		comm;

	if (!shrp) {
		cache.purge_all();
		return false;
	}

	assert(palloc);

	COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
	EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1); 
	bool				bret;

	new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, sz, get_conn_magic());

	new (pnot) EVENT_NOTIFY(ntype, nelems);

	return this->send_server_data(EPOLL_IOVEC_ARR(2, false, phdr, phdr->get_act_len(), free_fp, gpadbuf, phdr->get_pad_len(), nullptr), 
					comm::CLI_TYPE_REQ_ONLY, COMM_EVENT_NOTIFY, shrp);

}	

} // namespace gyeeta	

