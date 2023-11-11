//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_svc_net_capture.h"
#include			"gy_stack_container.h"
#include			"gy_socket_stat.h"
#include			"gy_http_proto.h"
#include			"gy_http2_proto.h"
#include			"gy_task_types.h"

#include			"folly/concurrency/UnboundedQueue.h"

namespace gyeeta {

using PortStackSet 		= INLINE_STACK_HASH_SET<uint32_t, 1024, GY_JHASHER<uint32_t>>;

static SVC_NET_CAPTURE		*pgsvccap = nullptr;

SVC_NET_CAPTURE * SVC_NET_CAPTURE::get_singleton() noexcept
{
	return pgsvccap;
}	

/*
 * NOTE : The errschedthr_ and apischedthr_ are the main handlers for all the captures. Also note that these threads will
 * keep alternating between the monitored Network Namespaces.
 *
 * Please do not assume the errschedthr_ or apischedthr_ will always run in root Network Namespace
 */
SVC_NET_CAPTURE::SVC_NET_CAPTURE(ino_t rootnsid)
	: rootnsid_(rootnsid),
	api_thr_("API Parser Thread", SVC_NET_CAPTURE::GET_PTHREAD_WRAPPER(api_parse_thread), this, nullptr, nullptr, true, 2 * 1024 * 1024, 2000, true, true, true, 10000, false)
{
	const auto		*pcpumem = CPU_MEM_INFO::get_singleton();

	if (pcpumem) {
		if (auto tcpu = pcpumem->get_number_of_cores(); tcpu == 1) {
			WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Host CPU Count allowed is too low (%u). API Captures Disabled..\n", tcpu);
			allow_api_cap_.store(false, mo_relaxed);
		}	
		else if (auto tmem = GY_DOWN_GB(pcpumem->get_total_memory()); tmem < 2) {
			WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Host System Memory is too low (%lu GB). API Captures Disabled..\n", tmem);
			allow_api_cap_.store(false, mo_relaxed);
		}	
	}

	if (nullptr == GY_READ_ONCE(pgsvccap)) {
		pgsvccap = this;
	}

	errschedthr_.add_schedule(100'100, 30'000, 0, "Check for netns Listener Deletes and Netns capture errors", 
	[this] { 
		check_netns_err_listeners();
	});

	errschedthr_.add_schedule(5500, 1000, 0, "rcu offline thread", 
	[] {
		gy_rcu_offline();
	});	

	apischedthr_.add_schedule(100'100, 30'000, 0, "Check for netns Listener Deletes and Netns capture errors", 
	[this] { 
		check_netns_api_listeners();
	});

	apischedthr_.add_schedule(5500, 1000, 0, "rcu offline thread", 
	[] {
		gy_rcu_offline();
	});	
}	

template <typename SvcType, typename NetNsType>
SvcType * find_by_globid_locked(const NetNsType & netns, uint64_t globid, uint16_t port, bool & portused) noexcept
{
	assert(false == gy_thread_rcu().is_rcu_thread_offline());

	if (true == gy_thread_rcu().is_rcu_thread_offline()) {
		return nullptr;
	}	
	
	SvcType			*pret = nullptr;

	const auto chkid = [&, globid](SvcType *pcap, void *, void *) noexcept -> CB_RET_E
	{
		portused = true;

		if (pcap && pcap->listenshr_ && pcap->glob_id_ == globid) {
			pret = pcap;
			return CB_BREAK_LOOP;
		}	

		return CB_OK;
	};

	netns.port_listen_tbl_.lookup_duplicate_elems(port, get_uint32_hash(port), chkid);

	return pret;
}	


SVC_ERR_HTTP * NETNS_HTTP_CAP1::find_svc_by_globid_locked(uint64_t globid, uint16_t port, bool & portused) const noexcept
{
	return find_by_globid_locked<SVC_ERR_HTTP, NETNS_HTTP_CAP1>(*this, globid, port, portused);
}
	
SVC_API_PARSER * NETNS_API_CAP1::find_svc_by_globid_locked(uint64_t globid, uint16_t port, bool & portused) const noexcept
{
	return find_by_globid_locked<SVC_API_PARSER, NETNS_API_CAP1>(*this, globid, port, portused);
}


template <typename SvcType, typename NetNsType>
std::pair<SvcType *, DirPacket> get_from_tuple_locked(const NetNsType & netns, const GY_IP_ADDR & srcip, uint16_t srcport, const GY_IP_ADDR & dstip, uint16_t dstport) noexcept
{
	assert(false == gy_thread_rcu().is_rcu_thread_offline());

	SvcType				*psvc = nullptr;
	uint16_t			maxsvcport = netns.max_listen_port_.load(mo_relaxed), minsvcport = netns.min_listen_port_.load(mo_relaxed);
	uint16_t			minport = std::min(srcport, dstport), maxport = std::max(srcport, dstport);

	if (minport > maxsvcport || maxport < minsvcport) {
		return {};
	}	

	const auto svcfind = [&](const GY_IP_ADDR & sip, uint16_t sport) noexcept 
	{
		uint32_t			shash = get_uint32_hash(sport);

		auto [nelem, pfirst1] 		= netns.port_listen_tbl_.count_duplicates_lookup_first_locked(sport, shash, 2);

		if (nelem == 0) {
			return;
		}

		if (nelem == 1) {
			// Should we still check the listener ip?
			psvc = pfirst1;
			return;
		}	

		SvcType			 	*prootanylisten = nullptr;

		const auto pchk = [&](SvcType *psvcone, void *, void *) -> CB_RET_E
		{
			auto 			plistener = psvcone->listenshr_.get();

			if (!plistener) {
				return CB_OK;
			}	

			const auto 		& ip = plistener->ns_ip_port_.ip_port_.ipaddr_;

			if (ip == sip) {
				psvc = psvcone;
				return CB_BREAK_LOOP;
			}	

			if (plistener->is_root_netns_ == false) {
				if (plistener->is_any_ip_) {
					psvc = psvcone;
					return CB_BREAK_LOOP;
				}	
			}	
			else if (plistener->is_any_ip_) {
				prootanylisten = psvcone;
			}	

			return CB_OK;
		};	

		netns.port_listen_tbl_.lookup_duplicate_elems(sport, shash, pchk);
		
		if (!psvc && prootanylisten) {
			psvc = prootanylisten;
		}	
	};

	if (minport == srcport) {
		svcfind(srcip, srcport);
		
		if (!psvc && dstport <= maxsvcport) {
			svcfind(dstip, dstport);

			return {psvc, psvc ? DirPacket::DirInbound : DirPacket::DirUnknown};
		}	
		else {
			return {psvc, psvc ? DirPacket::DirOutbound : DirPacket::DirUnknown};
		}	
	}
	else {
		svcfind(dstip, dstport);

		if (!psvc && srcport <= maxsvcport) {
			svcfind(srcip, srcport);

			return {psvc, psvc ? DirPacket::DirOutbound : DirPacket::DirUnknown};
		}	
		else {
			return {psvc, psvc ? DirPacket::DirInbound : DirPacket::DirUnknown};
		}	
	}	
}	

std::pair<SVC_ERR_HTTP *, DirPacket> NETNS_HTTP_CAP1::get_svc_from_tuple_locked(const GY_IP_ADDR & srcip, uint16_t srcport, const GY_IP_ADDR & dstip, uint16_t dstport) const noexcept
{
	return get_from_tuple_locked<SVC_ERR_HTTP, NETNS_HTTP_CAP1>(*this, srcip, srcport, dstip, dstport);
}	

std::pair<SVC_API_PARSER *, DirPacket> NETNS_API_CAP1::get_svc_from_tuple_locked(const GY_IP_ADDR & srcip, uint16_t srcport, const GY_IP_ADDR & dstip, uint16_t dstport) const noexcept
{
	return get_from_tuple_locked<SVC_API_PARSER, NETNS_API_CAP1>(*this, srcip, srcport, dstip, dstport);
}	


void SVC_NET_CAPTURE::add_err_listeners(SvcInodeMap & nslistmap) noexcept
{
	try {
		STRING_BUFFER<512>		strbuf;
		STRING_BUFFER<512>		skipbuf;

		for (auto & [inode, vecone] : nslistmap) {

			if (errcodemap_.size() >= MAX_NETNS_CAP_ERR) {
				ONCE_EVERY_MSEC(60000,
					WARNPRINT_OFFLOAD("Cannot add more HTTP Error listeners Network Capture as max Network Namespace limit breached : %lu\n", errcodemap_.size());
				);	
				return;
			}

			strbuf.reset();
			skipbuf.reset();

			try {
				auto 				[it, success] = errcodemap_.try_emplace(inode, inode, *this, inode == rootnsid_);
				auto				& nsone = it->second;
				bool				torestart = false;
				time_t				tcurr = time(nullptr);

				RCU_LOCK_SLOW			slowlock;
				uint32_t			nports = nsone.port_listen_tbl_.count_slow(), nskipped = 0;
				
				for (std::shared_ptr<TCP_LISTENER> & listenshr : vecone) {
					if (!listenshr) {
						continue;
					}

					auto			*plistener = listenshr.get();
					SVC_ERR_HTTP		*psvc;
					uint16_t		port = plistener->ns_ip_port_.ip_port_.port_;
					bool			portused = false;

					psvc = nsone.find_svc_by_globid_locked(plistener->glob_id_, port, portused);
					
					if (psvc && psvc->listenshr_ != listenshr) {
						nsone.port_listen_tbl_.delete_elem_locked(psvc);
					}	
					else if (psvc) {
						if (psvc->listenshr_) {
							psvc->listenshr_->httperr_cap_started_.store(true, std::memory_order_relaxed);
							psvc->listenshr_->is_http_svc_ = psvc->web_confirm_;
						}
						continue;
					}	

					if (!portused && nports >= MAX_NETNS_PORTS_ERR) {
						skipbuf << '\'' << plistener->comm_ << "\' Port "sv << port << ',';

						nskipped++;
						continue;
					}

					strbuf << '\'' << plistener->comm_ << "\' Port "sv << port << ',';

					psvc = new SVC_ERR_HTTP(std::move(listenshr), inode == rootnsid_, tcurr);
						
					nsone.port_listen_tbl_.insert_duplicate_elem(psvc, get_uint32_hash(port));

					if (!portused) {
						nports++;
					}
					torestart = true;
				}	

				slowlock.unlock();

				if (strbuf.size()) {
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Starting Error Network Capture for %s Network Namespace %lu for new listeners : %s\n", 
						success ? "new" : "existing", nsone.netinode_, strbuf.data());
				}

				if (nskipped) {
					WARNPRINT_OFFLOAD("Service Error Network Capture : "
						"Ignored %u Listeners as max Listener Ports per Namespace limit breached %u : List of ignored Listeners include %s\n", 
						nskipped, nports, skipbuf.data());
				}	

				if (torestart) {
					if (nsone.tstart_ > tcurr - 10) {
						// Recently restarted. Delay restart to next check
						nsone.forcerestart_ = true;
					}	
					else {
						nsone.restart_capture();
					}
				}	

			}
			GY_CATCH_EXCEPTION(
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while adding listener to Error Network Capture list due to %s\n", GY_GET_EXCEPT_STRING);
			);
		}
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while handling adding listener to Error Network Capture list due to %s\n", GY_GET_EXCEPT_STRING);
		);
	);
}	


void SVC_NET_CAPTURE::add_api_listeners(SvcInodeMap & nslistmap) noexcept
{
	try {
		static_assert(MAX_SVC_API_CAP < 256);

		STRING_BUFFER<1024>		strbuf;
		SVC_INFO_CAP			*capcachearr[MAX_SVC_API_CAP * 2];
		uint32_t			naddsvc = 0, ndelsvc = 0, ncapsvc = ncap_api_svc_.load(mo_relaxed), ncapcache = 0;

		if (allow_api_cap_.load(mo_relaxed) == false) {
			WARNPRINT_OFFLOAD("Cannot start Network API Capture as Capture disabled which may be because of inadequate hardware resources...\n");
			return;
		}

		if (!apihdlr_) {
			init_api_cap_handler();
		}	

		GY_SCOPE_EXIT {
			ncap_api_svc_.store(ncapsvc, mo_release);
		};

		for (auto & [inode, vecone] : nslistmap) {

			if (apicallmap_.size() >= MAX_NETNS_CAP_API) {
				WARNPRINT_OFFLOAD("Cannot add more listeners Network API Capture as max Network Namespace limit breached : %lu\n", apicallmap_.size());
				return;
			}

			strbuf.reset();
			ncapcache = 0;

			try {
				auto 				[it, success] = apicallmap_.try_emplace(inode, inode, *this, inode == rootnsid_);
				auto				& nsone = it->second;
				bool				torestart = false, bret;
				time_t				tcurr = time(nullptr);

				RCU_LOCK_SLOW			slowlock;
				uint32_t			nports = nsone.port_listen_tbl_.count_slow(), nskipped = 0;
				
				for (std::shared_ptr<TCP_LISTENER> & listenshr : vecone) {
					if (!listenshr) {
						continue;
					}

					auto			*plistener = listenshr.get();
					SVC_API_PARSER		*psvc;
					uint16_t		port = listenshr->ns_ip_port_.ip_port_.port_;
					bool			portused = false;

					psvc = nsone.find_svc_by_globid_locked(plistener->glob_id_, port, portused);
					
					if (psvc && psvc->listenshr_ != listenshr) {

						nsone.port_listen_tbl_.delete_elem_locked(psvc);
						ndelsvc++;
						ncapsvc--;

						bret = apihdlr_->msgpool_.write(PARSE_MSG_BUF(std::in_place_type<MSG_DEL_SVCCAP>, psvc->glob_id_));
						if (!bret) {
							if (psvc->svcinfocap_) {
								psvc->svcinfocap_->stop_parser_tusec_.store(get_usec_time(), mo_release);
							}

							WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Skipping Network API Capture for Listener %s Port %hu as Msg Pool is full and deletion msg failed...\n", 
									psvc->listenshr_ ? psvc->listenshr_->comm_ : "", port);

							nskipped++;
							continue;
						}	

					}	
					else if (psvc) {
						plistener->api_cap_started_.store(true, std::memory_order_relaxed);
						continue;
					}	

					if (!portused && nports >= MAX_NETNS_PORTS_API) {
						WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Skipping Network API Capture for Listener %s Port %hu as Max Ports Monitored breached %u\n",
							plistener->comm_, port, nports);

						nskipped++;
						continue;
					}

					if (ncapsvc + 1 >= MAX_SVC_API_CAP) {
						WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Skipping Network API Capture for Listener %s Port %hu as Max API Service Limit %u breached\n",
							plistener->comm_, port, MAX_SVC_API_CAP);

						nskipped++;
						continue;

					}	

					psvc = new SVC_API_PARSER(std::move(listenshr), inode == rootnsid_, tcurr);

					auto			psvcinfo = psvc->svcinfocap_.get();

					bret = apihdlr_->msgpool_.write(PARSE_MSG_BUF(std::in_place_type<MSG_ADD_SVCCAP>, psvc->svcinfocap_, psvc->glob_id_));
					if (!bret) {

						WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Skipping Network API Capture for Listener %s Port %hu as Msg Pool is full...\n", 
								plistener->comm_, port);

						delete psvc;

						nskipped++;
						continue;
					}	

					strbuf << '\'' << plistener->comm_ << "\' Port "sv << port << ',';

					naddsvc++;
					ncapsvc++;

					if (ncapcache + 1 < GY_ARRAY_SIZE(capcachearr)) {
						capcachearr[ncapcache++] = psvcinfo;
					}

					nsone.port_listen_tbl_.insert_duplicate_elem(psvc, get_uint32_hash(port));

					if (!portused) {
						nports++;
					}
					torestart = true;
				}	

				slowlock.unlock();

				if (strbuf.size()) {
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Starting API Network Capture for %s Network Namespace %lu for new listeners : %s\n", 
						success ? "new" : "existing", nsone.netinode_, strbuf.data());
				}

				// Lazy init of Svc Captures after RCU read lock unlocked
				for (uint32_t i = 0; i < ncapcache; ++i) {
					if (capcachearr[i]) {
						capcachearr[i]->lazy_init_blocking(*this);
					}	
				}	

				if (torestart) {
					if (nsone.tstart_ > tcurr - 10) {
						// Recently restarted. Delay restart to next check
						nsone.forcerestart_ = true;
					}	
					else {
						nsone.restart_capture();
					}
				}	
			}
			GY_CATCH_EXCEPTION(
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while adding listener to API Network Capture list due to %s\n", GY_GET_EXCEPT_STRING);
			);
		}

	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while handling adding listener to API Network Capture list due to %s\n", GY_GET_EXCEPT_STRING);
	);
}

void SVC_NET_CAPTURE::del_err_listeners(const GlobIDInodeMap & nslistmap) noexcept
{
	try {
		if (errcodemap_.size() == 0) {
			return;
		}	

		for (const auto & [inode, vecone] : nslistmap) {

			try {
				auto 			it = errcodemap_.find(inode);

				if (it == errcodemap_.end()) {
					continue;
				}

				auto				& nsone = it->second;
				bool				torestart = false;
				time_t				tcurr = time(nullptr);
				RCU_LOCK_SLOW			slowlock;
				uint32_t			nports = nsone.port_listen_tbl_.count_slow(), nskipped = 0;
					
				for (auto [globid, port] : vecone) {

					SVC_ERR_HTTP		*psvc;
					bool			portused = false;

					psvc = nsone.find_svc_by_globid_locked(globid, port, portused);
					
					if (!psvc) {
						continue;
					}

					DEBUGEXECN(1,
						INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Deleting Error Network Capture for Listener %s Port %hu as delete request seen\n",
							psvc->listenshr_ ? psvc->listenshr_->comm_ : "", psvc->serport_);
					);

					if (!torestart && (1 >= nsone.port_listen_tbl_.count_duplicate_elems(port, get_uint32_hash(port), 2))) {
						torestart = true;
					}

					if (psvc->listenshr_) {
						psvc->listenshr_->httperr_cap_started_.store(false, std::memory_order_relaxed);
					}
					nsone.port_listen_tbl_.delete_elem_locked(psvc);
				}	

				if (torestart && nsone.port_listen_tbl_.is_empty()) {
					slowlock.unlock();

					errcodemap_.erase(it);
					continue;
				}	

				slowlock.unlock();

				if (torestart) {
					if (nsone.tstart_ > tcurr - 10) {
						// Recently restarted. Delay restart to next check
						nsone.forcerestart_ = true;
					}	
					else {
						nsone.restart_capture();
					}
				}	

			}
			GY_CATCH_EXCEPTION(
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while deleting listener from Network Error Capture list due to %s\n", GY_GET_EXCEPT_STRING);
			);
		}

	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while handling deleting listener from Network Error Capture list due to %s\n", GY_GET_EXCEPT_STRING);
		);
	);
}

void SVC_NET_CAPTURE::del_api_listeners(const GlobIDInodeMap & nslistmap) noexcept
{
	try {
		if (apicallmap_.size() == 0) {
			return;
		}	

		uint64_t			sslidarr[MAX_SVC_API_CAP * 2];
		uint32_t			ndelsvc = 0, nssl = 0;

		for (const auto & [inode, vecone] : nslistmap) {

			try {
				auto 			it = apicallmap_.find(inode);

				if (it == apicallmap_.end()) {
					continue;
				}

				nssl = 0;

				auto				& nsone = it->second;
				bool				torestart = false;
				time_t				tcurr = time(nullptr);
				RCU_LOCK_SLOW			slowlock;
				uint32_t			nports = nsone.port_listen_tbl_.count_slow(), nskipped = 0;
					
				for (auto [globid, port] : vecone) {

					SVC_API_PARSER		*psvc;
					bool			portused = false, bret;

					psvc = nsone.find_svc_by_globid_locked(globid, port, portused);
					
					if (!psvc) {
						continue;
					}

					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Deleting API Network Capture for Listener %s Port %hu as delete request seen\n",
						psvc->listenshr_ ? psvc->listenshr_->comm_ : "", psvc->serport_);

					if (psvc->svcinfocap_) {
						auto			sslreq = psvc->svcinfocap_->ssl_req_.load(mo_acquire);

						if (sslreq != SSL_REQ_E::SSL_NO_REQ && sslreq != SSL_REQ_E::SSL_REJECTED) {
							if (nssl + 1 < GY_ARRAY_SIZE(sslidarr)) {
								sslidarr[nssl++] = psvc->glob_id_;
							}	
						}
					}

					bret = apihdlr_->msgpool_.write(PARSE_MSG_BUF(std::in_place_type<MSG_DEL_SVCCAP>, psvc->glob_id_));
					if (!bret) {
						if (psvc->svcinfocap_) {
							psvc->svcinfocap_->stop_parser_tusec_.store(get_usec_time(), mo_release);
						}

						DEBUGEXECN(1, 
							WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, 
								"Skipping sending Network API Capture Parser stop for Listener %s as Msg Pool is full and deletion msg failed...\n", 
									psvc->listenshr_ ? psvc->listenshr_->comm_ : "");
						);	
					}	

					if (!torestart && (1 >= nsone.port_listen_tbl_.count_duplicate_elems(port, get_uint32_hash(port), 2))) {
						torestart = true;
					}

					if (psvc->listenshr_) {
						psvc->listenshr_->api_cap_started_.store(false, std::memory_order_relaxed);
					}

					ndelsvc += nsone.port_listen_tbl_.delete_elem_locked(psvc);
				}	

				if (torestart && nsone.port_listen_tbl_.is_empty()) {
					slowlock.unlock();

					apicallmap_.erase(it);
					torestart = false;
				}	
				else {
					slowlock.unlock();
				}

				if (torestart) {
					if (nsone.tstart_ > tcurr - 10) {
						// Recently restarted. Delay restart to next check
						nsone.forcerestart_ = true;
					}	
					else {
						nsone.restart_capture();
					}
				}	

				for (int i = 0; i < (int)nssl; ++i) {
					apihdlr_->sslcap_.stop_svc_cap(sslidarr[i]);
				}	
			}
			GY_CATCH_EXCEPTION(
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while deleting listener from Network API Capture list due to %s\n", GY_GET_EXCEPT_STRING);
			);
		}

		if (ndelsvc > 0) {
			ncap_api_svc_.fetch_sub_relaxed_0(ndelsvc);
		}
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while handling deleting listener from Network API Capture list due to %s\n", GY_GET_EXCEPT_STRING);
		);
	);
}

void SVC_NET_CAPTURE::check_netns_err_listeners() noexcept
{
	try {
		size_t				nnetns = 0, nlisten = 0, nweb = 0, nhttp2 = 0;

		CONDDECLARE(
		STRING_BUFFER<8000>		strbuf;
		);

		NOTCONDDECLARE(
		STRING_BUFFER<2000>		strbuf;
		);

		const auto			psockhdlr = TCP_SOCK_HANDLER::get_singleton();
		const time_t			tcurr = time(nullptr);
		bool				forcerestart = false;

		nnetns = errcodemap_.size();

		if (nnetns == 0) {
			return;
		}	

		const auto pchk = [&](SVC_ERR_HTTP *psvcone, void *arg1) -> CB_RET_E
		{
			const auto 		& lshr = psvcone->listenshr_;
			NETNS_HTTP_CAP1		*pnetone = (NETNS_HTTP_CAP1 *)arg1;

			if (!lshr) {
				return CB_DELETE_ELEM;
			}

			assert(pnetone);

			if (psockhdlr->is_listener_deleted(lshr)) {

				if (!forcerestart && (1 >= pnetone->port_listen_tbl_.count_duplicate_elems(psvcone->serport_, get_uint32_hash(psvcone->serport_), 2))) {
					forcerestart = true;
				}
				return CB_DELETE_ELEM;
			}	

			if (psvcone->web_confirm_ == false && psvcone->nconfirm_web_ > 0) {
				psvcone->web_confirm_ = true;
				lshr->is_http_svc_ = true;

				strbuf.appendfmt("Listener %s ID %016lx Port %hu NetNS %lu  confirmed to be a HTTP%s Service...\n", 
							lshr->comm_, lshr->glob_id_, psvcone->serport_, pnetone->netinode_, psvcone->is_http2_ ? "2" : "1.x");

				forcerestart = true;
			}

			if (psvcone->web_confirm_ == false && 
				((psvcone->tfirstresp_ &&
				((tcurr >= psvcone->tfirstresp_ + 10 && psvcone->nconfirm_noweb_ >= 3) ||
				(tcurr >= psvcone->tfirstresp_ + 60 && psvcone->nconfirm_noweb_ >= 1 && psvcone->nmaybe_noweb_ > 100 && psvcone->nsess_chks_ > 6) ||
				(tcurr >= psvcone->tfirstresp_ + 100 && psvcone->nmaybe_noweb_ > 1000 && psvcone->nsess_chks_ > 6))) ||
				(psvcone->npkts_data_ > 1000'000 && psvcone->nsess_chks_ > 2 && tcurr > psvcone->tfirstreq_ + 600 && tcurr > psvcone->tfirstresp_ + 600))) {

				strbuf.appendfmt("Listener %s ID %016lx Port %hu NetNS %lu  does not seem to be a HTTP Service. Stopping Network Capture for it...\n", 
							lshr->comm_, lshr->glob_id_, psvcone->serport_, pnetone->netinode_);

				lshr->is_http_svc_ = false;
				lshr->httperr_cap_started_.store(false, std::memory_order_relaxed);

				if (!forcerestart && (1 >= pnetone->port_listen_tbl_.count_duplicate_elems(psvcone->serport_, get_uint32_hash(psvcone->serport_), 2))) {
					forcerestart = true;
				}

				return CB_DELETE_ELEM;
			}
			else if (psvcone->web_confirm_) {
				nweb++;

				if (psvcone->is_http2_) {
					nhttp2++;
				}	
			}	

			nlisten++;

			return CB_OK;
		};	

		for (auto it = errcodemap_.begin(); it != errcodemap_.end(); ) {
			auto				& netone = it->second;
			RCU_LOCK_SLOW			slowlock;

			forcerestart = false;

			netone.port_listen_tbl_.walk_hash_table(pchk, (void *)&netone);
			
			if (netone.port_listen_tbl_.is_empty() == true) {
				slowlock.unlock();
				
				strbuf.appendfmt("Deleting NeNS %lu as no active listeners\n", netone.netinode_);

				it = errcodemap_.erase(it);
				continue;
			}
			
			slowlock.unlock();

			if (forcerestart || netone.forcerestart_) {
				if (netone.tstart_ < tcurr - 5) {
					netone.restart_capture();
				}
				else {
					// Skip till next check
					netone.forcerestart_ = true;
				}	
			}	
			else if (netone.netcap_ && (false == netone.netcap_->is_capture_active())) {
				if (netone.tstart_ && netone.tstart_ < tcurr - 30) {
					if (++netone.nerror_retries_ < 3) {
						INFOPRINT_OFFLOAD("Service Error Network Capture for netns %lu has stopped. Restarting...\n", netone.netinode_);

						netone.netcap_.reset(nullptr);
						netone.restart_capture();
					}	
					else {
						WARNPRINT_OFFLOAD("Service Error Network Capture for netns %lu has stopped too many times. Stopping further captures for this Network Namespace...\n", 
							netone.netinode_);

						it = errcodemap_.erase(it);
						continue;
					}	
				}
			}	
			else if (netone.netcap_) {
				netone.nerror_retries_ = 0;
			}	

			++it;
		}
		
		nnetns = errcodemap_.size();

		last_errmapsize_.store(nnetns, mo_release);

		if (nnetns > 0 || nlisten > 0) {
			INFOPRINT_OFFLOAD("Service Error Network Capture : HTTP Error Code Network Namespaces %lu, Listeners %lu, Confirmed Web Services %lu, HTTP2/GRPC Services %lu\n%s\n",
					nnetns, nlisten, nweb, nhttp2, strbuf.buffer());
		}	
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Caught Exception while checking Error Port Listener Map : %s\n", GY_GET_EXCEPT_STRING););
	);
}	

void SVC_NET_CAPTURE::check_netns_api_listeners() noexcept
{
	try {
		size_t				nnetns = 0, nlisten = 0, nweb = 0, nhttp2 = 0;

		CONDDECLARE(
		STRING_BUFFER<8000>		strbuf;
		);

		NOTCONDDECLARE(
		STRING_BUFFER<2000>		strbuf;
		);

		const auto			psockhdlr = TCP_SOCK_HANDLER::get_singleton();
		const time_t			tcurr = time(nullptr);
		bool				forcerestart = false;

		nnetns = apicallmap_.size();

		if (nnetns == 0) {
			return;
		}	

		const auto pchk = [&](SVC_API_PARSER *psvcone, void *arg1) -> CB_RET_E
		{
			const auto 		& lshr = psvcone->listenshr_;
			NETNS_API_CAP1		*pnetone = (NETNS_API_CAP1 *)arg1;

			if (!lshr || !psvcone) {
				return CB_DELETE_ELEM;
			}

			assert(pnetone);

			if (psockhdlr->is_listener_deleted(lshr)) {

				if (!forcerestart && (1 >= pnetone->port_listen_tbl_.count_duplicate_elems(psvcone->serport_, get_uint32_hash(psvcone->serport_), 2))) {
					forcerestart = true;
				}
				return CB_DELETE_ELEM;
			}	

			pnetone->printbuf_ << "[Svc \'"sv << lshr->comm_ << "\' Port " << psvcone->serport_ << "], "sv;

#if 0
			if (psvcone->web_confirm_ == false && psvcone->nconfirm_web_ > 0) {
				psvcone->web_confirm_ = true;
				lshr->is_http_svc_ = true;

				strbuf.appendfmt("Listener %s ID %016lx Port %hu NetNS %lu  confirmed to be a HTTP%s Service...\n", 
							lshr->comm_, lshr->glob_id_, psvcone->serport_, pnetone->netinode_, psvcone->is_http2_ ? "2" : "1.x");

				forcerestart = true;
			}

			if (psvcone->web_confirm_ == false && 
				((psvcone->tfirstresp_ &&
				((tcurr >= psvcone->tfirstresp_ + 10 && psvcone->nconfirm_noweb_ >= 3) ||
				(tcurr >= psvcone->tfirstresp_ + 60 && psvcone->nconfirm_noweb_ >= 1 && psvcone->nmaybe_noweb_ > 100 && psvcone->nsess_chks_ > 6) ||
				(tcurr >= psvcone->tfirstresp_ + 100 && psvcone->nmaybe_noweb_ > 1000 && psvcone->nsess_chks_ > 6))) ||
				(psvcone->npkts_data_ > 1000'000 && psvcone->nsess_chks_ > 2 && tcurr > psvcone->tfirstreq_ + 600 && tcurr > psvcone->tfirstresp_ + 600))) {

				strbuf.appendfmt("Listener %s ID %016lx Port %hu NetNS %lu  does not seem to be a HTTP Service. Stopping Network Capture for it...\n", 
							lshr->comm_, lshr->glob_id_, psvcone->serport_, pnetone->netinode_);

				lshr->is_http_svc_ = false;
				lshr->httperr_cap_started_.store(false, std::memory_order_relaxed);

				if (!forcerestart && (1 >= pnetone->port_listen_tbl_.count_duplicate_elems(psvcone->serport_, get_uint32_hash(psvcone->serport_), 2))) {
					forcerestart = true;
				}

				return CB_DELETE_ELEM;
			}
			else if (psvcone->web_confirm_) {
				nweb++;

				if (psvcone->is_http2_) {
					nhttp2++;
				}	
			}	
#endif			

			nlisten++;

			return CB_OK;
		};	

		for (auto it = apicallmap_.begin(); it != apicallmap_.end(); ) {
			auto				& netone = it->second;
			size_t				tnsvc;
			RCU_LOCK_SLOW			slowlock;

			forcerestart = false;

			netone.printbuf_.reset();

			netone.port_listen_tbl_.walk_hash_table(pchk, (void *)&netone);
			
			if (netone.port_listen_tbl_.is_empty() == true) {
				slowlock.unlock();
				
				strbuf.appendfmt("Deleting NeNS %lu as no active listeners\n", netone.netinode_);

				it = apicallmap_.erase(it);
				continue;
			}
			
			slowlock.unlock();

			if (forcerestart || netone.forcerestart_) {
				if (netone.tstart_ < tcurr - 5) {
					netone.restart_capture();
				}
				else {
					// Skip till next check
					netone.forcerestart_ = true;
				}	
			}	
			else if (netone.netcap_ && (false == netone.netcap_->is_capture_active())) {
				if (netone.tstart_ && netone.tstart_ < tcurr - 30) {
					if (++netone.nerror_retries_ < 3) {
						INFOPRINT_OFFLOAD("Service API Network Capture for netns %lu has stopped. Restarting...\n", netone.netinode_);

						netone.netcap_.reset(nullptr);
						netone.restart_capture();
					}	
					else {
						ERRORPRINT_OFFLOAD("Service API Network Capture for netns %lu has stopped too many times. Stopping further captures for this Network Namespace...\n", 
							netone.netinode_);

						nlisten -= netone.port_listen_tbl_.approx_count_fast();

						it = apicallmap_.erase(it);

						continue;
					}	
				}
			}	
			else if (netone.netcap_) {
				netone.nerror_retries_ = 0;
			}	

			++it;
		}
		
		ncap_api_svc_.store(nlisten, mo_release);

		nnetns = apicallmap_.size();

		last_apimapsize_.store(nnetns, mo_release);

		if (nnetns > 0 || nlisten > 0) {
			INFOPRINT_OFFLOAD("Service API Network Capture : Network Namespaces %lu, Listeners %lu, Confirmed Web Services %lu, HTTP2/GRPC Services %lu\n%s\n",
					nnetns, nlisten, nweb, nhttp2, strbuf.buffer());
		}	
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Caught Exception while checking Error Port Listener Map : %s\n", GY_GET_EXCEPT_STRING););
	);
}

bool SVC_NET_CAPTURE::sched_add_listeners(uint64_t start_after_msec, const char *name, SvcInodeMap && nslistmap, bool isapicallmap)
{
	if (!isapicallmap) {
		return errschedthr_.add_oneshot_schedule(start_after_msec, name,
			[this, svcinodemap = std::move(nslistmap)]() mutable 
			{
				add_err_listeners(svcinodemap);

				last_errmapsize_.store(errcodemap_.size(), mo_release);
			});	
	}
	else {
		return apischedthr_.add_oneshot_schedule(start_after_msec, name,
			[this, svcinodemap = std::move(nslistmap)]() mutable 
			{
				add_api_listeners(svcinodemap);

				last_apimapsize_.store(apicallmap_.size(), mo_release);
			});	
	}	
}	

bool SVC_NET_CAPTURE::sched_del_listeners(uint64_t start_after_msec, const char *name, GlobIDInodeMap && nslistmap)
{
	auto				copymap = nslistmap; // Copy
	bool				b1ret, b2ret;

	b1ret = apischedthr_.add_oneshot_schedule(start_after_msec, name,
		[this, delidmap = std::move(copymap)]() {
			del_api_listeners(delidmap);

			last_apimapsize_.store(apicallmap_.size(), mo_release);
		});	

	b2ret = errschedthr_.add_oneshot_schedule(start_after_msec, name,
		[this, delidmap = std::move(nslistmap)]() {

			del_err_listeners(delidmap);

			last_errmapsize_.store(errcodemap_.size(), mo_release);
		});	

	return b1ret && b2ret;
}	

bool SVC_NET_CAPTURE::sched_svc_ssl_probe(const char *name, std::weak_ptr<TCP_LISTENER> svcweak)
{
	if (!apihdlr_ || apihdlr_->allow_ssl_probe_.load(mo_relaxed) == false) {
		return false;
	}

	return apischedthr_.add_oneshot_schedule(1, name, 
		[this, svcweak = std::move(svcweak)]() {
			try {
				auto				svcshr = svcweak.lock();

				if (!svcshr) {
					return;
				}	
		
				pid_t				pidarr[MAX_SVC_SSL_PROCS];
				size_t				npids;

				npids = svcshr->get_pids_for_uprobe(pidarr, GY_ARRAY_SIZE(pidarr));

				if (npids == 0) {
					return;
				}	
			
				apihdlr_->sslcap_.start_svc_cap(svcshr->comm_, svcshr->glob_id_, svcshr->ns_ip_port_.ip_port_.port_, pidarr, npids);
			}
			catch(...) {
			}
		});
}

SVC_ERR_HTTP::SVC_ERR_HTTP(std::shared_ptr<TCP_LISTENER> && listenshr, bool is_rootns, time_t tstart)
		: listenshr_(
		({
			if (!listenshr) GY_THROW_EXPRESSION("Service Error Network Capture : Invalid Listen shared pointer");
			std::move(listenshr);
		})), glob_id_(listenshr_->glob_id_),
		tstart_(tstart), serport_(listenshr_->ns_ip_port_.ip_port_.port_), is_rootns_(is_rootns)
{
	listenshr_->httperr_cap_started_.store(true, std::memory_order_relaxed);
}

SVC_API_PARSER::SVC_API_PARSER(std::shared_ptr<TCP_LISTENER> && listenshr, bool is_rootns, time_t tstart)
		: listenshr_(
		({
			if (!listenshr) GY_THROW_EXPRESSION("Service API Network Capture : Invalid Listen shared pointer");
			std::move(listenshr);
		})), glob_id_(listenshr_->glob_id_),
		tstart_(tstart), svcinfocap_(std::make_shared<SVC_INFO_CAP>(listenshr_)), serport_(listenshr_->ns_ip_port_.ip_port_.port_), is_rootns_(is_rootns)
{
	listenshr_->api_cap_started_.store(true, std::memory_order_relaxed);
}


SVC_ERR_HTTP::SessInfo * SVC_ERR_HTTP::get_session_inbound(const GY_IP_ADDR & cliip, uint16_t cliport, const GY_TCP_HDR & tcp, time_t tpkt) noexcept
{
	SessInfo		*psess;
	uint16_t		porthash = get_port_hash(cliport), iphash = get_ip_hash(cliip);

	psess = sesscache_ + porthash;
	
	if (psess->cli_port_ == 0) {
		psess->cli_port_ 	= cliport;
		psess->cli_ip_hash2_ 	= iphash;

		if (nsess_chks_ < 64) {
			nsess_chks_++;
		}
		return psess;
	}	

	if (psess->cli_port_ == cliport && psess->cli_ip_hash2_ == iphash) {
try_again :		
		if (psess->exp_cli_seq_ == tcp.seq || psess->exp_cli_seq_ == 0) {
			return psess;
		}	
		else if (psess->exp_cli_seq_ < tcp.seq + 16 * 1024) {
			// Dropped pkt
			std::memset(psess, 0, sizeof(*psess));
			return nullptr;
		}
		else if (tcp.syn && (tpkt & 0xFFFF) > psess->last_pkt_sec_ + 100) {
			std::memset(psess, 0, sizeof(*psess));

			psess->cli_port_ 	= cliport;
			psess->cli_ip_hash2_ 	= iphash;

			return psess;
		}	

		return nullptr;
	}	
	else {
		// Check if preceding port is used 
		psess = sesscache_ + (porthash > 0 ? porthash - 1 : MaxCliHash);

		if (psess->cli_port_ == cliport && psess->cli_ip_hash2_ == iphash) {
			goto try_again;
		}	
	}

	return nullptr;
}

SVC_ERR_HTTP::SessInfo * SVC_ERR_HTTP::get_session_outbound(const GY_IP_ADDR & cliip, uint16_t cliport, const GY_TCP_HDR & tcp, time_t tpkt) noexcept
{
	SessInfo		*psess;
	uint16_t		porthash = get_port_hash(cliport), iphash = get_ip_hash(cliip);

	psess = sesscache_ + porthash;
	
	if (psess->cli_port_ == 0) {
		psess->cli_port_ 	= cliport;
		psess->cli_ip_hash2_ 	= iphash;

		if (nsess_chks_ < 64) {
			nsess_chks_++;
		}
		return psess;
	}	
	else if (psess->cli_port_ == cliport && psess->cli_ip_hash2_ == iphash) {
try_again :		
		if (psess->exp_ser_seq_ == tcp.seq || psess->exp_ser_seq_ == 0) {
			return psess;
		}	
		else if (!tcp.syn && psess->exp_ser_seq_ < tcp.seq + 16 * 1024) {
			// Dropped packet
			std::memset(psess, 0, sizeof(*psess));
			return nullptr;
		}
		else if (tcp.syn && !psess->is_syn_sess_) {
			std::memset(psess, 0, sizeof(*psess));

			psess->cli_port_ 	= cliport;
			psess->cli_ip_hash2_ 	= iphash;

			if (nsess_chks_ < 64) {
				nsess_chks_++;
			}
			return psess;
		}	
	}	
	else if (!tcp.syn) {
		// Check if preceding port is used 
		psess = sesscache_ + (porthash > 0 ? porthash - 1 : MaxCliHash);

		if (psess->cli_port_ == cliport && psess->cli_ip_hash2_ == iphash) {
			goto try_again;
		}	
	}
	else {
		// Try the preceding entry
		psess = sesscache_ + (porthash > 0 ? porthash - 1 : MaxCliHash);

		if ((psess->cli_port_ == 0) || (!psess->is_syn_sess_) || ((tpkt & 0xFFFF) > psess->last_pkt_sec_ + 100)) {
			std::memset(psess, 0, sizeof(*psess));

			psess->cli_port_ 	= cliport;
			psess->cli_ip_hash2_ 	= iphash;

			if (nsess_chks_ < 64) {
				nsess_chks_++;
			}
			return psess;
		}	
	}	

	return nullptr;
}


void SVC_ERR_HTTP::reset_stats(time_t tcurr) noexcept
{
	std::memset(sesscache_, 0, sizeof(sesscache_));

	tstart_ 		= tcurr;
	tfirstreq_		= 0;
	tfirstresp_		= 0;
	nconfirm_web_		= 0;
	nconfirm_noweb_ 	= 0;
	nmaybe_noweb_		= 0;
	npkts_data_		= 0;
	nsess_chks_		= 0;
	is_http2_		= indeterminate;
	web_confirm_		= false;

	if (listenshr_) {
		listenshr_->httperr_cap_started_.store(true, std::memory_order_relaxed);
		listenshr_->is_http_svc_ = indeterminate;
	}	
}	

bool SVC_ERR_HTTP::operator== (uint16_t sport) const noexcept
{
	auto 			plist = listenshr_.get();
	
	return plist && (plist->ns_ip_port_.ip_port_.port_ == sport);
}

bool SVC_API_PARSER::operator== (uint16_t sport) const noexcept
{
	auto 			plist = listenshr_.get();
	
	return plist && (plist->ns_ip_port_.ip_port_.port_ == sport);
}


bool SEQ_ERR_RETRAN::is_retranmit(uint32_t ser_seq, uint32_t cli_seq, uint16_t cli_port) noexcept
{
	try {
		SeqErrOne		eone(ser_seq, cli_seq, cli_port);
		SeqErrHashSet		*pcurrset, *potherset;

		if (curr0_) {
			pcurrset 	= &set0_; 
			potherset 	= &set1_;
		}	
		else {
			pcurrset 	= &set1_;
			potherset 	= &set0_;
		}	

		auto			it = pcurrset->find(eone);

		if (it == pcurrset->end()) {
			it = potherset->find(eone);
			if (it == potherset->end()) {

				if (pcurrset->size() + 1 >= MaxSetEntries) {
					// Switch
					potherset->clear();
					potherset->reserve(MaxSetEntries);

					curr0_ 		= !curr0_;
					pcurrset 	= potherset;
				}

				pcurrset->emplace(eone);

				return false;
			}
		}

		nretrans_++;
		return true;
	}
	catch(...) {
		return false;
	}	
}	


NETNS_HTTP_CAP1::NETNS_HTTP_CAP1(ino_t netinode, SVC_NET_CAPTURE & svccap, bool is_rootns)
		: netinode_(netinode), svccap_(svccap), is_rootns_(is_rootns)
{
	if (is_rootns_) {
		retranchk_		= std::make_unique<SEQ_ERR_RETRAN>();
	}	
}

NETNS_API_CAP1::NETNS_API_CAP1(ino_t netinode, SVC_NET_CAPTURE & svccap, bool is_rootns)
		: netinode_(netinode), svccap_(svccap), is_rootns_(is_rootns)
{}

// Returns false on non HTTP payloads
bool NETNS_HTTP_CAP1::handle_req_err_locked(SVC_ERR_HTTP & svc, const GY_IP_ADDR & cliip, uint16_t cliport, const GY_TCP_HDR & tcp, const uint8_t *pdata, uint32_t datalen, uint32_t caplen, struct timeval tv_pkt) const 
{
	if (svc.nconfirm_web_ > 0 || svc.nconfirm_noweb_ >= 3) {
		// Ignore
		return true;
	}
	
	auto			psess = svc.get_session_inbound(cliip, cliport, tcp, tv_pkt.tv_sec);

	if (!psess) {
		return true;
	}	

	if (tcp.fin || tcp.rst) {
		std::memset(psess, 0, sizeof(*psess));
		return true;
	}	

	psess->exp_cli_seq_ 	= tcp.next_expected_src_seq(datalen);
	psess->last_pkt_sec_ 	= tv_pkt.tv_sec & 0xFFFF;

	if (tcp.syn) {
		psess->is_syn_sess_	= tcp.syn;
		psess->init_resp_pend_	= true;
		return true;
	}

	GY_SCOPE_EXIT {
		psess->last_pkt_resp_	= false;
		psess->req_seen_ 	= true;
	};	

	svc.npkts_data_++;

	if (svc.tfirstreq_ == 0) {
		svc.tfirstreq_ = tv_pkt.tv_sec;
	}

	if (psess->last_tcp_syn_ || psess->last_pkt_resp_) { 
		tribool			tret;

		tret = http_proto::is_valid_req(pdata, caplen, datalen);

		if (tret == false) {
			if (psess->last_tcp_syn_) {
				if (http2_proto::is_init_magic(pdata, caplen)) {
					if ((datalen == 24) || (caplen >= 33 && pdata[27] == 0x04)) {
						psess->init_http2_req_ = true;
						psess->http2_seen_ = true;
					}	
					return true;		
				}	

				psess->init_other_req_ = true;
				return false;
			}
			else {
				psess->last_http1_req_ = false;

				if (psess->http2_seen_) {
					bool		bret = http2_proto::is_valid_req_resp(pdata, caplen, datalen, DirPacket::DirInbound);
					
					if (bret) {
						psess->last_http2_req_ = true;
						return true;
					}	
				}	
				return false;
			}	
		}	
		else if (tret == true) {
			if (psess->last_tcp_syn_) {
				psess->init_http1_req_ = true;
			}
			else {
				psess->last_http1_req_ = true;
			}	
			return true;
		}	
		else {
			// Truncated req : Cannot figure
			psess->last_http1_req_maybe_ = true;
			return true;
		}	
	}
	else if (psess->init_http2_req_ && psess->last_pkt_resp_ == false) {
		// Check if settings 
		if (!(datalen >= 9 && caplen >= 9 && pdata[3] == 0x04)) {
			psess->init_http2_req_ = false;
			psess->last_other_req_ = true;

			return false;
		}	
	}	

	return true;
}	

// Returns false on non HTTP payloads
bool NETNS_HTTP_CAP1::handle_resp_err_locked(SVC_ERR_HTTP & svc, const GY_IP_ADDR & cliip, uint16_t cliport, const GY_TCP_HDR & tcp, const uint8_t *pdata, uint32_t datalen, uint32_t caplen, struct timeval tv_pkt) const 
{
	if (svc.nconfirm_noweb_ >= 3) {
		return true;
	}

	SVC_ERR_HTTP::SessInfo 		*psess = nullptr;
	
	if (svc.nconfirm_web_ == 0) {
		psess = svc.get_session_outbound(cliip, cliport, tcp, tv_pkt.tv_sec);

		if (psess) {
			if (tcp.fin || tcp.rst) {
				std::memset(psess, 0, sizeof(*psess));
				return true;
			}	

			psess->exp_ser_seq_ 	= tcp.next_expected_src_seq(datalen);

			if (tcp.syn) {
				psess->last_tcp_syn_ 	= true;
				psess->is_syn_sess_	= tcp.syn;
				psess->init_resp_pend_	= true;
				psess->last_pkt_sec_ 	= tv_pkt.tv_sec & 0xFFFF;
				return true;
			}
			else if (psess->req_seen_) {
				psess->last_tcp_syn_ 	= false;
			}	
		}
		else if (tcp.syn || tcp.fin || tcp.rst) {
			return true;
		}	
	}
	else if (tcp.syn || tcp.fin || tcp.rst) {
		return true;
	}	

	bool			is_cli_err = false, is_ser_err = false, bret;

	if (svc.nconfirm_web_ == 0) {
		GY_SCOPE_EXIT {
			if (psess) {
				psess->last_pkt_resp_	= true;
				psess->last_pkt_sec_ 	= tv_pkt.tv_sec & 0xFFFF;
			}
		};	

		if (svc.tfirstresp_ == 0) {
			svc.tfirstresp_ = tv_pkt.tv_sec;
		}

		svc.npkts_data_++;
		
		if (psess) {
			if (psess->init_resp_pend_) {
				if (psess->req_seen_ == false) {
					// Possible only for HTTP2 and some other protocols such as MySQL : Check for HTTP2 Settings
					
					bret = http2_proto::is_settings_response(pdata, caplen, datalen);

					// Lets wait for Client request before confirming
					return bret;
				}

				psess->init_resp_pend_ = false;

				if (psess->init_http1_req_ || psess->last_http1_req_maybe_) {
					psess->init_http1_req_ = false;
					psess->last_http1_req_maybe_ = false;

					bret = http_proto::get_status_response(pdata, caplen, is_cli_err, is_ser_err);

					if (!bret) {
						if (true == http2_proto::init_invalid_http2_resp(pdata, caplen)) {
							return true;
						}	
						else {
							svc.nconfirm_noweb_++;
							return false;
						}
					}
					else {
						svc.nconfirm_web_++;

						if (indeterminate(svc.is_http2_)) {
							svc.is_http2_ = false;
						}

						if (is_cli_err && svc.listenshr_) {
							svc.listenshr_->cumul_cli_errors_++;
						}	
						else if (is_ser_err && svc.listenshr_) {
							svc.listenshr_->cumul_ser_errors_++;
						}	

						return true;
					}	
				}	
				else if (psess->init_http2_req_) {
					psess->init_http2_req_ = false;

					bret = http2_proto::is_settings_response(pdata, caplen, datalen);

					if (!bret) {
						bret = http_proto::get_status_response(pdata, caplen, is_cli_err, is_ser_err);

						if (bret) {
							return true;
						}	
						else {
							svc.nconfirm_noweb_++;
							return false;
						}	
					}
					else {
						svc.nconfirm_web_++;
						svc.is_http2_ = true;

						return true;
					}	
				}	
				else {
					bret = http_proto::get_status_response(pdata, caplen, is_cli_err, is_ser_err);

					if (!bret) {
						if (true == http2_proto::init_invalid_http2_resp(pdata, caplen)) {
							return true;
						}	
						else {
							svc.nconfirm_noweb_++;
							return false;
						}	
					}	
					else {
						return true;
					}	
				}	
			}	
			else {
				// Currently we require fresh connections to confirm...
				bret = http_proto::get_status_response(pdata, caplen, is_cli_err, is_ser_err);

				if (!bret) {
					bret = http2_proto::is_valid_req_resp(pdata, caplen, datalen, DirPacket::DirOutbound);
				}	

				return bret;
			}	
		}
		else {
			bret = http_proto::get_status_response(pdata, caplen, is_cli_err, is_ser_err);

			if (!bret) {
				bret = http2_proto::is_valid_req_resp(pdata, caplen, datalen, DirPacket::DirOutbound);
			}	

			return bret;
		}	
	}	

	if (svc.is_http2_) {
		// First check if HTTP2 response
		bret = http2_proto::get_status_response(pdata, caplen, is_cli_err, is_ser_err);

		if (!bret) {
			bret = http_proto::get_status_response(pdata, caplen, is_cli_err, is_ser_err);
		}	
	}
	else {
		bret = http_proto::get_status_response(pdata, caplen, is_cli_err, is_ser_err);
	}

	if (is_cli_err && svc.listenshr_) {
		if (!retranchk_ || (false == retranchk_->is_retranmit(tcp.seq, tcp.ack_seq, tcp.dest))) {
			CONDEXEC(
				DEBUGEXECN(15,
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Listener %s Port %hu : A Client HTTP Error 4xx seen from network capture\n",
						svc.listenshr_->comm_, svc.serport_);
				);
			);
			svc.listenshr_->cumul_cli_errors_++;
		}	
	}	
	else if (is_ser_err && svc.listenshr_) {
		if (!retranchk_ || (false == retranchk_->is_retranmit(tcp.seq, tcp.ack_seq, tcp.dest))) {
			CONDEXEC(
				DEBUGEXECN(15,
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Listener %s Port %hu : A Server HTTP Error 5xx seen from network capture\n",
						svc.listenshr_->comm_, svc.serport_);
				);
			);
			svc.listenshr_->cumul_ser_errors_++;
		}
	}	

	return true;
}	

template <typename NetNsType>
int process_pkt(NetNsType & netns, const uint8_t *pframe, uint32_t caplen, uint32_t origlen, int linktype, struct timeval tv_pkt) noexcept
{
	try {
		const struct ip 		*pip = nullptr;
		const struct ip6_hdr		*pip6 = nullptr;
		const uint8_t			*porigframe, *pdata, *ptcp; 
		GY_IP_ADDR			srcip, dstip;
		uint16_t			msglen;
		uint8_t				transport_proto;
		uint32_t 			ip_offset, transport_offset, data_offset, data_len;
		int				ret;
		bool				is_ipv4;
		
		ret = get_ip_offset(pframe, caplen, linktype, ip_offset, is_ipv4);
		if (ret != 0 || (ip_offset > caplen)) {
			return 1;
		}	

		porigframe = pframe;

		pframe += ip_offset;
		caplen -= ip_offset;

		if (is_ipv4) {
			pip = decltype(pip)(pframe);
			
			ret = get_ipv4_transport_offset(pip, caplen, transport_proto, transport_offset, data_offset, data_len);
		}	
		else {
			pip6 = decltype(pip6)(pframe);
			
			ret = get_ipv6_transport_offset(pip6, caplen, transport_proto, transport_offset, data_offset, data_len);
		}	

		if (ret != 0 || (transport_proto != IP_PROTO_TCP) || (data_offset > caplen)) {
			return 1;
		}	

		ptcp = pframe + transport_offset;
				
		GY_TCP_HDR			tcp(ptcp);

		pframe += data_offset;
		caplen -= data_offset ;

		pdata = pframe;

		if ((caplen > origlen) || (caplen == 0 && (0 == (tcp.tcpflags & (GY_TH_SYN | GY_TH_FIN | GY_TH_RST))))) {
			return 0;
		}	

		if (is_ipv4) {
			get_src_dest_ipv4(pip, srcip, dstip);
		}
		else {
			get_src_dest_ipv6(pip6, srcip, dstip);
		}

		/*
		 * We use RCU Fast lock as on every 1000 pkts Ring Buffer Read or timeout offlne will be done
		 */

		RCU_LOCK_FAST			fastlock;

		auto				[psvc, dir] = netns.get_svc_from_tuple_locked(srcip, tcp.source, dstip, tcp.dest);

		if (!psvc) {
			return 1;
		}	

		std::optional<PARSE_PKT_HDR>	msghdr;
		SVC_INFO_CAP			*pcapsvc = nullptr;
		uint64_t			glob_id = 0;
		bool				bret;
		
		if (dir == DirPacket::DirInbound) {
			if constexpr (netns.parse_api_calls_ == false) {
				bret = netns.handle_req_err_locked(*psvc, srcip, tcp.source, tcp, pdata, data_len, caplen, tv_pkt);
				if (bret == false) {
					psvc->nmaybe_noweb_++;
				}	
			}
			else {
				if (psvc->svcinfocap_) {
					netns.set_api_msghdr(msghdr, srcip, dstip, tcp.source, tcp.dest, tcp, pdata, data_len, caplen, tv_pkt, dir);

					pcapsvc = psvc->svcinfocap_.get();
					glob_id = psvc->glob_id_;
				}	
			}	
		}
		else {
			if constexpr (netns.parse_api_calls_ == false) {
				bret = netns.handle_resp_err_locked(*psvc, dstip, tcp.dest, tcp, pdata, data_len, caplen, tv_pkt);
				if (bret == false) {
					psvc->nmaybe_noweb_++;
				}	
			}	
			else {
				if (psvc->svcinfocap_) {
					netns.set_api_msghdr(msghdr, dstip, srcip, tcp.dest, tcp.source, tcp, pdata, data_len, caplen, tv_pkt, dir);

					pcapsvc = psvc->svcinfocap_.get();
					glob_id = psvc->glob_id_;
				}	
			}	
		}	

		fastlock.unlock();

		if constexpr (netns.parse_api_calls_) {
			if (pcapsvc) {
				netns.nmissed_total_ += !netns.svccap_.apihdlr_->send_pkt_to_parser(pcapsvc, glob_id, *msghdr, pdata, caplen);
			}
		}	

		return 0;
	}
	catch(...) {
		return 0;
	}	
}	

// Returns the snaplen needed
uint32_t NETNS_HTTP_CAP1::get_filter_string(STR_WR_BUF & strbuf) 
{
	PortStackSet			portset;
	PortStackSet			dualportset;
	uint16_t			minport = 65535, maxport = 0, nports = 0, tports;
		
	const auto pchk = [&](SVC_ERR_HTTP *psvcone, void *arg1) -> CB_RET_E
	{
		const auto 		*plisten = psvcone->listenshr_.get();

		if (plisten) {
			uint16_t		port = plisten->ns_ip_port_.ip_port_.port_;
			
			if (psvcone->web_confirm_ == false && psvcone->nconfirm_noweb_ < 3) {
				dualportset.emplace(port);
			}
			
			portset.emplace(port);

			if (maxport < port) maxport = port;
			if (minport > port) minport = port;
		}	

		return CB_OK;
	};	

	tports = (uint16_t)port_listen_tbl_.walk_hash_table_const(pchk);

	for (uint16_t port : portset) {
		if (nports++ > 0) strbuf.appendconst(" or ");

		if (auto it = dualportset.find(port); it == dualportset.end()) {
			strbuf.appendfmt("tcp src port %hu", port);
		}
		else {
			strbuf.appendfmt("tcp port %hu", port);
		}
	}	

	if (strbuf.is_overflow() || tports == 0) {
		GY_THROW_EXCEPTION("Service Error Network Capture filter error : Internal buffer overflow or 0 ports seen : filter buffer length %lu : #ports %hu",
			strbuf.size(), tports);
	}	

	max_listen_port_.store(maxport, std::memory_order_relaxed);
	min_listen_port_.store(minport, std::memory_order_relaxed);

	DEBUGEXECN(1,
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Service Error Network Capture for Namespace inode %lu : Filter has %u ports with %lu bidirectional ports : Port Range is %hu-%hu\n", 
				netinode_, tports, dualportset.size(), minport, maxport);
	);

	return (dualportset.size() > 0 ? 196 : 128);
}	

// Returns the snaplen needed
uint32_t NETNS_API_CAP1::get_filter_string(STR_WR_BUF & strbuf) 
{
	PortStackSet			portset;
	uint16_t			minport = 65535, maxport = 0, nports = 0, tports;
		
	const auto pchk = [&](SVC_API_PARSER *psvcone, void *arg1) -> CB_RET_E
	{
		const auto 		*plisten = psvcone->listenshr_.get();

		if (plisten) {
			uint16_t		port = plisten->ns_ip_port_.ip_port_.port_;
			
			portset.emplace(port);

			if (maxport < port) maxport = port;
			if (minport > port) minport = port;
		}	

		return CB_OK;
	};	

	tports = (uint16_t)port_listen_tbl_.walk_hash_table_const(pchk);

	if ((portset.size() < 6) || (maxport - minport > 16 && maxport - minport > 1.5 * tports)) {
		for (uint16_t port : portset) {
			if (nports++ > 0) strbuf.appendconst(" or ");

			strbuf.appendfmt("tcp port %hu", port);
		}	
	}
	else {
		strbuf << "tcp portrange "sv << minport << '-' << maxport;
	}	

	if (strbuf.is_overflow() || tports == 0) {
		GY_THROW_EXCEPTION("Service API Network Capture filter error : Internal buffer overflow or 0 ports seen : filter buffer length %lu : #ports %hu",
			strbuf.size(), tports);
	}	

	max_listen_port_.store(maxport, std::memory_order_relaxed);
	min_listen_port_.store(minport, std::memory_order_relaxed);

	DEBUGEXECN(1,
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Service API Network Capture for Namespace inode %lu : Filter has %u ports : Port Range is %hu-%hu\n", 
				netinode_, tports, minport, maxport);
	);

	return 65535;
}


template <typename NetNsType>
void netns_restart_capture(NetNsType & netns)
{
	STRING_BUFFER<3000>		filstr;
	uint32_t			bufsz, snaplen;
	const char			*pnetstr = !netns.parse_api_calls_ ? "Error" : "API";

	netns.forcerestart_ 		= false;
	netns.tstart_ 			= time(nullptr);
	
	snaplen 			= netns.get_filter_string(filstr);
	
	if (netns.netcap_) {
		// Just signal. The capture thread will eventually restart the capture
		netns.netcap_->restart_capture_signal(filstr.buffer(), filstr.length());
		return;
	}

	RCU_LOCK_SLOW			slowlock;

	auto				pnetns = TCP_SOCK_HANDLER::get_singleton()->get_netns_locked(netns.netinode_);
	if (!pnetns) {
		DEBUGEXECN(1, WARNPRINT_OFFLOAD("Failed to get Net Namespace object for Service %s Net Capture of inode %lu\n", pnetstr, netns.netinode_));
		return;
	}	

	int				netfd = pnetns->get_ns_fd(), ret;

	if (netfd < 0) {
		return;
	}	

	ret = setns(netfd, CLONE_NEWNET);
	if ((ret == -1) && (errno != ENOSYS)) {
		return;
	}	
	
	slowlock.unlock();

	auto pcapcb = [&](const uint8_t * pframe, uint32_t caplen, uint32_t origlen, int linktype, struct timeval tv_cap) noexcept
	{
		return process_pkt(netns, pframe, caplen, origlen, linktype, tv_cap);
	};

	auto timeoutcb = [&, setns_called = false, next_stats_time = netns.tstart_ + 300](const PCAP_NET_CAP *pnetcap) mutable noexcept
	{
		if (!pnetcap) return;

		if (setns_called == false) {
			setns_called = true;

			RCU_LOCK_SLOW			slowlock;

			auto				pnetns = TCP_SOCK_HANDLER::get_singleton()->get_netns_locked(netns.netinode_);
			if (!pnetns) {
				return;
			}	

			int				netfd = pnetns->get_ns_fd(), ret;

			if (netfd < 0) {
				return;
			}	

			ret = setns(netfd, CLONE_NEWNET);
			if ((ret == -1) && (errno != ENOSYS)) {
				return;
			}	
		}	

		RCU_LOCK_SLOW			slowlock;
		time_t				tcurr = time(nullptr);		

		if (tcurr < next_stats_time) {
			return;
		}	
		
		next_stats_time = tcurr + 300;

		slowlock.unlock();

		auto			[npkts_received, npkts_kernel_drops] = pnetcap->update_pcap_stats();

		if (npkts_received) {
			netns.print_stats(npkts_received, npkts_kernel_drops);
		}
	};	

	if (!netns.is_rootns_) {
		if constexpr (netns.parse_api_calls_) {
			bufsz = 10 * 1024 * 1024;
		}	
		else {
			bufsz = 2 * 1024 * 1024;
		}	
	}	
	else {
		if constexpr (netns.parse_api_calls_) {
			bufsz = 32 * 1024 * 1024;
		}	
		else {
			bufsz = 8 * 1024 * 1024;
		}	
	}	

	netns.netcap_ = std::make_unique<PCAP_NET_CAP>("any", filstr.buffer(), filstr.length(), std::move(pcapcb), bufsz, snaplen, false /* use_promiscuous */, 1024 * 1024 /* thr_stacksz */,
							1 /* timeout_sec */, std::move(timeoutcb), 1000 /* ring_max_pkts */, true /* rcu_offline_after_read */);
}	

void NETNS_HTTP_CAP1::restart_capture()
{
	netns_restart_capture(*this);
}	

void NETNS_API_CAP1::restart_capture()
{
	netns_restart_capture(*this);
}	

inline void NETNS_API_CAP1::set_api_msghdr(std::optional<PARSE_PKT_HDR> & msghdr, const GY_IP_ADDR & cliip, const GY_IP_ADDR & serip, 
						uint16_t cliport, uint16_t serport, const GY_TCP_HDR & tcp, 
						const uint8_t *pdata, uint32_t datalen, uint32_t caplen, struct timeval tv_pkt, DirPacket dir) const noexcept
{
	msghdr.emplace();

	auto			& hdr = *msghdr;

	hdr.tv_			= tv_pkt;
	hdr.cliip_		= cliip;
	hdr.serip_		= serip;
	hdr.datalen_		= caplen;
	hdr.wirelen_		= datalen;

	if (dir == DirPacket::DirInbound) { 
		hdr.nxt_cli_seq_	= tcp.next_expected_src_seq(datalen);
		hdr.start_cli_seq_	= tcp.seq;

		hdr.nxt_ser_seq_	= tcp.ack_seq;
		hdr.start_ser_seq_	= tcp.ack_seq;
	}
	else {
		hdr.nxt_cli_seq_	= tcp.ack_seq;
		hdr.start_cli_seq_	= tcp.ack_seq;

		hdr.nxt_ser_seq_	= tcp.next_expected_src_seq(datalen);
		hdr.start_ser_seq_	= tcp.seq;
	}	

	hdr.cliport_		= cliport;
	hdr.serport_		= serport;
	hdr.dir_		= dir;
	hdr.tcpflags_		= tcp.tcpflags;
	hdr.src_		= SRC_PCAP;
}	

void SVC_NET_CAPTURE::init_api_cap_handler()
{
	if (apihdlr_) {
		return;
	}	

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Initializing API Capture Data structures : API Captures can be initiated thereafter...\n");

	apihdlr_.reset(new API_PARSE_HDLR(*this));
	
	auto lam1 = []() { return true; };

	api_cond_.cond_signal(lam1);

	apischedthr_.add_schedule(5400, 5000, 0, "Periodic ping to api parser thread for book-keeping", 
	[this] { 
		apihdlr_->msgpool_.write(PARSE_MSG_BUF(std::in_place_type<MSG_TIMER_SVCCAP>));	
	});
}	

void SVC_NET_CAPTURE::svc_ssl_probe_cb(void *pcb_cookie, void *pdata, int data_size) noexcept
{
	try {
		SVC_NET_CAPTURE				*psvcnet = (SVC_NET_CAPTURE *)pcb_cookie;

		psvcnet->handle_probe_cb(pdata, data_size);
	}	
	catch(...) {
	}	
}

void SVC_NET_CAPTURE::handle_probe_cb(void *pdata, int data_size)
{
	
}

	
int SVC_NET_CAPTURE::api_parse_thread() noexcept
{
	api_thr_.set_thread_init_done();

	auto waitcb = [this]() noexcept
	{
		return !bool(apihdlr_);
	};

	auto waitsuc = []() noexcept 
	{
	};

	/*
	 * Wait for apihdlr_ to be initialized. This will be done on first API capture msg
	 */
	api_cond_.cond_wait(waitcb, waitsuc);

	apihdlr_->api_parse_rd_thr(); 		// Will not return
	
	return 1;
}	

} // namespace gyeeta

