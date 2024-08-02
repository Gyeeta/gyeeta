//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"
#include			"gy_comm_proto.h"

#include 			<forward_list>

namespace gyeeta {

template <typename ConnTrack, typename L1param, size_t max_conn_per_host, typename ScopeLock = SCOPE_GY_MUTEX>
class HOST_CONN_FLIST
{
public :	
	class HOST_CONN_L1
	{
	public :	
		const L1param			*pl1_			{nullptr};
		std::weak_ptr <ConnTrack>	weakconn_;
		ConnTrack			*pconn_			{nullptr};
		comm::HOST_TYPES_E		host_type_		{comm::HOST_INVALID};
		comm::CLI_TYPE_E		cli_type_		{comm::CLI_TYPE_REQ_RESP};

		HOST_CONN_L1(const L1param *pl1, std::weak_ptr<ConnTrack> && weakconn, ConnTrack *pconn, comm::HOST_TYPES_E host_type, comm::CLI_TYPE_E cli_type) noexcept
			: pl1_(pl1), weakconn_(std::move(weakconn)), pconn_(pconn), host_type_(host_type), 
			cli_type_((comm::CLI_TYPE_E)((uint32_t)cli_type % comm::CLI_TYPE_MAX))
		{}
	
		HOST_CONN_L1() noexcept						= default;

		HOST_CONN_L1(const HOST_CONN_L1 &) noexcept			= default;
		HOST_CONN_L1 & operator= (const HOST_CONN_L1 &) noexcept	= default;

		HOST_CONN_L1(HOST_CONN_L1 && other) noexcept
			: pl1_(std::exchange(other.pl1_, nullptr)), weakconn_(std::move(other.weakconn_)), pconn_(std::exchange(other.pconn_, nullptr)),
			host_type_(other.host_type_), cli_type_(other.cli_type_)
		{}

		HOST_CONN_L1 & operator= (HOST_CONN_L1 && other) noexcept
		{
			if (this != &other) {
				this->~HOST_CONN_L1();

				pl1_		= std::exchange(other.pl1_, nullptr);
				weakconn_	= std::move(other.weakconn_);
				pconn_		= std::exchange(other.pconn_, nullptr);
				host_type_	= other.host_type_;
				cli_type_	= other.cli_type_;
			}	

			return *this;
		}	

		~HOST_CONN_L1() noexcept
		{
			pl1_	= nullptr;
			pconn_	= nullptr;
		}	

		bool is_cli_active() const noexcept
		{
			return (pconn_ && !weakconn_.expired());
		}	
	};	


	GY_MUTEX			mutex_;
	std::forward_list<HOST_CONN_L1>	listconn_;
	size_t				nconns_					{0};
	uint64_t			last_connect_tusec_			{0};
	uint64_t			last_disconnect_tusec_			{0};
	time_t				last_check_time_			{0};
	uint64_t			last_db_upd_tusec_			{0};
	HOST_CONN_L1			*plast_cli_type_[comm::CLI_TYPE_MAX]	{};
	
	HOST_CONN_FLIST() noexcept	= default;

	size_t add_conn(const L1param *pl1, std::weak_ptr<ConnTrack> weakconn, ConnTrack *pconn, comm::HOST_TYPES_E host_type, comm::CLI_TYPE_E cli_type) 
	{
		ScopeLock		scopelock(mutex_);

		if (gy_unlikely(nconns_ > max_conn_per_host)) {
			size_t		nfree;

			nfree = clear_closed_conns_locked();
			if (nfree == 0) {
				GY_THROW_EXCEPTION("Too many persistent connections already seen %lu", nconns_);
			}	
		}	

		auto & lref = listconn_.emplace_front(pl1, std::move(weakconn), pconn, host_type, cli_type);
		nconns_++;
		last_connect_tusec_ = get_usec_time();

		plast_cli_type_[lref.cli_type_] = &lref;

		return nconns_;
	}

	// Returns remaining conns
	size_t del_conn(ConnTrack *pconn, comm::HOST_TYPES_E host_type) noexcept
	{
		ScopeLock		scopelock(mutex_);
		auto			previt = listconn_.before_begin();
		
		for (auto it = listconn_.begin(); it != listconn_.end(); ) {
			auto & lref = *it;

			if (lref.pconn_ == pconn) {
				nconns_--;
				
				if (plast_cli_type_[lref.cli_type_] == &lref) {
					plast_cli_type_[lref.cli_type_] = nullptr;
				}

				listconn_.erase_after(previt);
				
				last_disconnect_tusec_ = get_usec_time();

				if (nconns_ == 0) {
					// We keep the struct till the periodic cleanup
				}

				break;
			}	
			else {
				++previt;
				++it;
			}	
		}	

		return nconns_;
	}	
	
	bool is_cli_type_avail(comm::CLI_TYPE_E ctype) noexcept
	{
		ScopeLock		scopelock(mutex_);

		auto 			plast = plast_cli_type_[ctype];

		if (plast && (false == plast->weakconn_.expired())) {
			return true;
		}	

		// We need to walk the list to check
		for (auto it = listconn_.begin(); it != listconn_.end(); ++it) {
			auto 		& lref = *it;
			
			if ((lref.cli_type_ == ctype) && lref.pconn_ && (!lref.weakconn_.expired())) {
				plast_cli_type_[lref.cli_type_] = &lref;

				return true;
			}	
		}

		return false;
	}

	std::shared_ptr<ConnTrack> get_last_conn(comm::CLI_TYPE_E ctype) noexcept
	{
		ScopeLock		scopelock(mutex_);
		bool			close_chked = false;
		const time_t		tcurr = time(nullptr);
		
		if (tcurr - last_check_time_ > 300) {
			close_chked = true;
			clear_closed_conns_locked(tcurr);
		}	
			
		auto plast = plast_cli_type_[ctype];

		if (plast) {
			if (close_chked == false) {
				auto shrp = plast->weakconn_.lock();

				if (shrp) {
					return std::move(shrp);
				}

				clear_closed_conns_locked(tcurr);
			
				plast = plast_cli_type_[ctype];
				if (plast) {
					return plast->weakconn_.lock();
				}	
			}
			else {
				return plast->weakconn_.lock();
			}	
		}	

		return {};
	}	

	/*
	 * Scan through the list of conns, one at a time. Return CB_BREAK_LOOP from the walk FCB in case you want to break out of the scan.
	 * and CB_DELETE_ELEM in case you want to delete that elem. Else return CB_OK
	 */
	template <typename FCB>
	size_t walk_conn_list(FCB & walk) noexcept(noexcept(walk(rvalue_to_lvalue(std::declval<HOST_CONN_L1>()))))
	{
		CB_RET_E			cbret;
		size_t				nwalk = 0;

		ScopeLock			scopelock(mutex_);
		auto				previt = listconn_.before_begin();

		for (auto it = listconn_.begin(); it != listconn_.end(); ) {
			auto 			& lref = *it;

			cbret = walk(lref);

			nwalk++;

			if (cbret == CB_BREAK_LOOP) {
				break;
			}	
			else if (cbret == CB_DELETE_ELEM || cbret == CB_DELETE_BREAK) {
				nconns_--;
				
				if (plast_cli_type_[lref.cli_type_] == &lref) {
					plast_cli_type_[lref.cli_type_] = nullptr;
				}

				++it;
				listconn_.erase_after(previt);
				
				last_disconnect_tusec_ = get_usec_time();

				if (cbret == CB_BREAK_LOOP) {
					break;
				}
			}	
			else {
				++previt;
				++it;
			}	
		}	
		
		return nwalk;
	}	

	size_t get_num_conns() const noexcept
	{
		return GY_READ_ONCE(nconns_);
	}	

	bool is_conn_available() const noexcept
	{
		return !!(GY_READ_ONCE(nconns_));
	}

	uint64_t get_last_oper_time() const noexcept
	{
		uint64_t	tconn = GY_READ_ONCE(last_connect_tusec_), tdis = GY_READ_ONCE(last_disconnect_tusec_);

		return std::max(tconn, tdis);
	}	

	uint64_t get_last_connect_time() const noexcept
	{
		return GY_READ_ONCE(last_connect_tusec_);
	}

	uint64_t get_last_disconnect_time() const noexcept
	{
		return GY_READ_ONCE(last_disconnect_tusec_);
	}

	// Returns number of closed conns
	size_t clear_closed_conns() noexcept
	{
		ScopeLock		scopelock(mutex_);

		return clear_closed_conns_locked();
	}	

private :
	size_t clear_closed_conns_locked(time_t tcurr = time(nullptr)) noexcept
	{
		auto			previt = listconn_.before_begin();
		size_t			nrem = 0, nlastdel = 0;

		last_check_time_ = tcurr;

		for (auto it = listconn_.begin(); it != listconn_.end(); ) {
			auto 		& lref = *it;

			if (lref.pconn_ == nullptr || (lref.weakconn_.expired())) {
				nconns_--;
				
				if (plast_cli_type_[lref.cli_type_] == &lref) {
					plast_cli_type_[lref.cli_type_] = nullptr;
					nlastdel++;
				}

				listconn_.erase_after(previt);
				
				nrem++;
				break;
			}	
			else {
				++previt;
				++it;
			}	
		}	

		if (nrem > 0) {
			last_disconnect_tusec_ = get_usec_time();

			if (nlastdel) {
				// We need to walk the list to update the plast_cli_type_
				for (auto it = listconn_.begin(); it != listconn_.end(); ++it) {
					auto 		& lref = *it;
					
					for (size_t i = 0; i < comm::CLI_TYPE_MAX; ++i) {
						if (size_t(lref.cli_type_) == i) {
							if (nullptr == plast_cli_type_[lref.cli_type_]) {
								plast_cli_type_[lref.cli_type_] = &lref;
							}

							break;
						}	
					}
				}
			}
		}

		return nrem;
	}	
	
};	

} // namespace gyeeta
