
#include			"gy_svc_net_capture.h"
#include			"gy_stack_container.h"
#include			"gy_socket_stat.h"
#include			"gy_http2_proto.h"
#include			"gy_task_types.h"

namespace gyeeta {

using PortStackSet 		= INLINE_STACK_HASH_SET<uint32_t, 1024, GY_JHASHER<uint32_t>>;

/*
 * NOTE : The schedthr_ is the main handler for all the captures. Also note that the schedthr_ will
 * keep alternating between the monitored Network Namespaces.
 *
 * Please do not assume the schedthr_ will always run in root Network Namespace
 */
SVC_NET_CAPTURE::SVC_NET_CAPTURE(ino_t rootnsid)
	: rootnsid_(rootnsid)
{
	schedthr_.add_schedule(100'100, 30'000, 0, "Check for netns Listener Deletes and Netns capture errors", 
	[this] { 
		check_netns_listeners();
	});

	schedthr_.add_schedule(5500, 1000, 0, "rcu offline thread", 
	[] {
		gy_rcu_offline();
	});	
}	

SVC_CAP_ONE * NETNS_CAP_ONE::find_svc_by_globid_locked(uint64_t globid, uint16_t port, bool & portused) const noexcept
{
	assert(false == gy_thread_rcu().is_rcu_thread_offline());

	if (true == gy_thread_rcu().is_rcu_thread_offline()) {
		return nullptr;
	}	
	
	SVC_CAP_ONE			*pret = nullptr;

	const auto chkid = [&, globid](SVC_CAP_ONE *pcap, void *, void *) noexcept -> CB_RET_E
	{
		portused = true;

		if (pcap && pcap->listenshr_ && pcap->listenshr_->glob_id_ == globid) {
			pret = pcap;
			return CB_BREAK_LOOP;
		}	

		return CB_OK;
	};

	port_listen_tbl_.lookup_duplicate_elems(port, get_uint32_hash(port), chkid);

	return pret;
}	

std::pair<SVC_CAP_ONE *, DirPacket> NETNS_CAP_ONE::get_svc_from_tuple_locked(const GY_IP_ADDR & srcip, uint16_t srcport, const GY_IP_ADDR & dstip, uint16_t dstport) const noexcept
{
	assert(false == gy_thread_rcu().is_rcu_thread_offline());

	if (true == gy_thread_rcu().is_rcu_thread_offline()) {
		return {};
	}	

	SVC_CAP_ONE			*psvc = nullptr;
	uint16_t			maxport = max_listen_port_.load(std::memory_order_relaxed);
	uint16_t			minport = std::min(srcport, dstport);

	if (minport > maxport) {
		return {};
	}	

	const auto svcfind = [&](const GY_IP_ADDR & sip, uint16_t sport) noexcept 
	{
		size_t				nelem;
		uint32_t			shash = get_uint32_hash(sport);

		nelem = port_listen_tbl_.count_duplicate_elems(sport, shash, 2);

		if (nelem == 0) {
			return;
		}	

		if (nelem == 1) {
			// Should we still check the listener ip?
			psvc = port_listen_tbl_.lookup_single_elem_locked(sport, shash);
			return;
		}	

		SVC_CAP_ONE	 	*prootanylisten = nullptr;

		const auto pchk = [&](SVC_CAP_ONE *psvcone, void *, void *) -> CB_RET_E
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

		port_listen_tbl_.lookup_duplicate_elems(sport, shash, pchk);
		
		if (!psvc && prootanylisten) {
			psvc = prootanylisten;
		}	
	};

	if (minport == srcport) {
		svcfind(srcip, srcport);
		
		if (!psvc && dstport <= maxport) {
			svcfind(dstip, dstport);
			return {psvc, DirPacket::DIR_INBOUND};
		}	
		else {
			return {psvc, DirPacket::DIR_OUTBOUND};
		}	
	}
	else {
		svcfind(dstip, dstport);

		if (!psvc && srcport <= maxport) {
			svcfind(srcip, srcport);
			return {psvc, DirPacket::DIR_OUTBOUND};
		}	
		else {
			return {psvc, DirPacket::DIR_INBOUND};
		}	
	}	
}	


void SVC_NET_CAPTURE::add_listeners(SvcInodeMap & nslistmap, bool isapicallmap) noexcept
{
	try {
		NetNSMap		& nmap = (!isapicallmap ? errcodemap_ : apicallmap_);

		for (auto & [inode, vecone] : nslistmap) {

			if (nmap.size() >= MAX_NETNS_CAP) {
				WARNPRINT_OFFLOAD("Cannot add more listeners Network Capture as max Network Namespace limit breached : %lu\n", nmap.size());
				return;
			}

			try {
				auto 			[it, success] = nmap.try_emplace(inode, inode, vecone, isapicallmap, inode == rootnsid_);
				auto			& nsone = it->second;
				bool			torestart = false;

				if (!success) {
					time_t				tcurr = time(nullptr);
					RCU_LOCK_SLOW			slowlock;
					uint32_t			nports = nsone.port_listen_tbl_.count_slow(), nskipped = 0;
					
					for (std::shared_ptr<TCP_LISTENER> & listenshr : vecone) {
						if (!listenshr) {
							continue;
						}

						SVC_CAP_ONE		*psvc;
						uint16_t		port = listenshr->ns_ip_port_.ip_port_.port_;
						bool			portused = false;

						psvc = nsone.find_svc_by_globid_locked(listenshr->glob_id_, port, portused);
						
						if (psvc && psvc->listenshr_ != listenshr) {
							nsone.port_listen_tbl_.delete_elem_locked(psvc);
						}	
						else if (psvc) {
							if (psvc->listenshr_) {
								psvc->listenshr_->net_cap_started_.store(true, std::memory_order_relaxed);
								psvc->listenshr_->is_http_svc_ = psvc->web_confirm_;
							}
							continue;
						}	

						if (!portused && nports >= MAX_NETNS_PORTS) {
							DEBUGEXECN(1,
								INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Skipping Network Capture for Listener %s as Max Ports Monitored breached %u\n",
									listenshr->comm_, nports);
							);

							nskipped++;
							continue;
						}

						psvc = new SVC_CAP_ONE(std::move(listenshr), isapicallmap, inode == rootnsid_, tcurr);
							
						nsone.port_listen_tbl_.insert_duplicate_elem(psvc, get_uint32_hash(port));

						if (!portused) {
							nports++;
						}
						torestart = true;
					}	

					slowlock.unlock();

					if (nskipped) {
						WARNPRINT_OFFLOAD("Service Network Capture : Ignored %u Listeners as max Listener Ports per Namespace limit breached %u\n", 
							nskipped, nports);
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

			}
			GY_CATCH_EXCEPTION(
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while adding listener to Network Capture list due to %s\n", GY_GET_EXCEPT_STRING);
			);
		}
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while handling adding listener to Network Capture list due to %s\n", GY_GET_EXCEPT_STRING);
		);
	);
}	

void SVC_NET_CAPTURE::del_listeners(const GlobIDInodeMap & nslistmap) noexcept
{
	try {
		const auto checkmap = [&](NetNSMap & nmap) 
		{
			if (nmap.size() == 0) {
				return;
			}	

			for (const auto & [inode, vecone] : nslistmap) {

				try {
					auto 			it = nmap.find(inode);

					if (it == nmap.end()) {
						continue;
					}

					auto				& nsone = it->second;
					bool				torestart = false;
					time_t				tcurr = time(nullptr);
					RCU_LOCK_SLOW			slowlock;
					uint32_t			nports = nsone.port_listen_tbl_.count_slow(), nskipped = 0;
						
					for (auto [globid, port] : vecone) {

						SVC_CAP_ONE		*psvc;
						bool			portused = false;

						psvc = nsone.find_svc_by_globid_locked(globid, port, portused);
						
						if (!psvc) {
							continue;
						}

						DEBUGEXECN(1,
							INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Deleting Network Capture for Listener %s Port %hu as delete request seen\n",
								psvc->listenshr_ ? psvc->listenshr_->comm_ : "", psvc->serport_);
						);

						if (!torestart && (1 >= nsone.port_listen_tbl_.count_duplicate_elems(port, get_uint32_hash(port), 2))) {
							torestart = true;
						}

						if (psvc->listenshr_) {
							psvc->listenshr_->net_cap_started_.store(false, std::memory_order_relaxed);
						}
						nsone.port_listen_tbl_.delete_elem_locked(psvc);
					}	

					if (torestart && nsone.port_listen_tbl_.is_empty()) {
						slowlock.unlock();

						nmap.erase(it);
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
					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while deleting listener from Network Capture list due to %s\n", GY_GET_EXCEPT_STRING);
				);
			}
		};

		checkmap(errcodemap_);
		checkmap(apicallmap_);
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while handling deleting listener from Network Capture list due to %s\n", GY_GET_EXCEPT_STRING);
		);
	);
}

void SVC_NET_CAPTURE::check_netns_listeners() noexcept
{
	try {
		size_t				nnetnserr = 0, nlistenerr = 0, nweberr = 0, nhttp2err = 0;
		size_t				nnetnsapi = 0, nlistenapi = 0, nwebapi = 0, nhttp2api = 0;

		CONDDECLARE(
		STRING_BUFFER<8000>		strbuf;
		);

		NOTCONDDECLARE(
		STRING_BUFFER<2000>		strbuf;
		);

		const auto checkmap = [&, tcurr = time(nullptr)](NetNSMap & cmap, size_t & nnetns, size_t & nlisten, size_t & nweb, size_t & nhttp2) 
		{
			bool			forcerestart = false;

			nnetns = cmap.size();

			if (nnetns == 0) {
				return;
			}	

			const auto pchk = [&](SVC_CAP_ONE *psvcone, void *arg1) -> CB_RET_E
			{
				const auto 		& lshr = psvcone->listenshr_;
				NETNS_CAP_ONE		*pnetone = (NETNS_CAP_ONE *)arg1;

				assert(pnetone);

				if (!lshr || lshr.use_count() == 1) {

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
					lshr->net_cap_started_.store(false, std::memory_order_relaxed);

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

			for (auto it = cmap.begin(); it != cmap.end(); ) {
				auto				& netone = it->second;
				RCU_LOCK_SLOW			slowlock;

				forcerestart = false;

				netone.port_listen_tbl_.walk_hash_table(pchk, (void *)&netone);
				
				if (netone.port_listen_tbl_.is_empty() == true) {
					slowlock.unlock();
					
					strbuf.appendfmt("Deleting NeNS %lu as no active listeners\n", netone.netinode_);

					it = cmap.erase(it);
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
							INFOPRINT_OFFLOAD("Service Network Capture for netns %lu has stopped. Restarting...\n", netone.netinode_);

							netone.netcap_.reset(nullptr);
							netone.restart_capture();
						}	
						else {
							WARNPRINT_OFFLOAD("Service Network Capture for netns %lu has stopped too many times. Stopping further captures for this Network Namespace...\n", 
								netone.netinode_);

							it = cmap.erase(it);
							continue;
						}	
					}
				}	
				else if (netone.netcap_) {
					netone.nerror_retries_ = 0;
				}	

				++it;
			}
		};

		checkmap(errcodemap_, nnetnserr, nlistenerr, nweberr, nhttp2err);
		checkmap(apicallmap_, nnetnsapi, nlistenapi, nwebapi, nhttp2api);
		
		if (nnetnserr + nnetnsapi > 0 || nlistenerr + nlistenapi > 0) {
			if (nlistenapi > 0) {
				INFOPRINT_OFFLOAD("Service Network Capture : HTTP Error Code Network Namespaces %lu, Listeners %lu, Confirmed Web Services %lu, HTTP2/GRPC Services %lu : "
					"API call Namespaces %lu Listeners %lu, Confirmed Web Services %lu, HTTP2/GRPC Services %lu : \n%s\n",
					nnetnserr, nlistenerr, nweberr, nhttp2err, nnetnsapi, nlistenapi, nwebapi, nhttp2api, strbuf.buffer());
			}
			else {
				INFOPRINT_OFFLOAD("Service Network Capture : HTTP Error Code Network Namespaces %lu, Listeners %lu, Confirmed Web Services %lu, HTTP2/GRPC Services %lu\n%s\n",
					nnetnserr, nlistenerr, nweberr, nhttp2err, strbuf.buffer());
			}	
		}	
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Caught Exception while checking Port Listener Map : %s\n", GY_GET_EXCEPT_STRING););
	);
}	

bool SVC_NET_CAPTURE::sched_add_listeners(uint64_t start_after_msec, const char *name, SvcInodeMap && nslistmap, bool isapicallmap)
{
	return schedthr_.add_oneshot_schedule(start_after_msec, name,
		[this, svcinodemap = std::move(nslistmap), isapicallmap]() mutable 
		{
			add_listeners(svcinodemap, isapicallmap);
		});	
}	

bool SVC_NET_CAPTURE::sched_del_listeners(uint64_t start_after_msec, const char *name, GlobIDInodeMap && nslistmap)
{
	return schedthr_.add_oneshot_schedule(start_after_msec, name,
		[this, delidmap = std::move(nslistmap)]() {
			del_listeners(delidmap);
		});	
}	

SVC_CAP_ONE::SVC_CAP_ONE(std::shared_ptr<TCP_LISTENER> && listenshr, bool parse_api_calls, bool is_rootns, time_t tstart) noexcept
		: listenshr_(std::move(listenshr)), tstart_(tstart), serport_(bool(listenshr_) ? listenshr_->ns_ip_port_.ip_port_.port_ : 0),
		parse_api_calls_(parse_api_calls), is_rootns_(is_rootns)
{
	if (listenshr_) {
		listenshr_->net_cap_started_.store(true, std::memory_order_relaxed);
	}
}


SVC_CAP_ONE::SessInfo * SVC_CAP_ONE::get_session_inbound(const GY_IP_ADDR & cliip, uint16_t cliport, const GY_TCP_HDR & tcp, time_t tpkt) noexcept
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

SVC_CAP_ONE::SessInfo * SVC_CAP_ONE::get_session_outbound(const GY_IP_ADDR & cliip, uint16_t cliport, const GY_TCP_HDR & tcp, time_t tpkt) noexcept
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


void SVC_CAP_ONE::reset_stats(time_t tcurr) noexcept
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
		listenshr_->net_cap_started_.store(true, std::memory_order_relaxed);
		listenshr_->is_http_svc_ = indeterminate;
	}	
}	

bool SVC_CAP_ONE::operator== (uint16_t sport) const noexcept
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

NETNS_CAP_ONE::NETNS_CAP_ONE(ino_t netinode, std::vector<std::shared_ptr<TCP_LISTENER>> & veclist, bool parse_api_calls, bool is_rootns)
		: netinode_(netinode), parse_api_calls_(parse_api_calls), is_rootns_(is_rootns)
{
	PortStackSet			portset;
	time_t				tcurr = time(nullptr);

	CONDDECLARE(
		STRING_BUFFER<8000>	strbuf;
	);

	if (is_rootns_) {
		retranchk_		= std::make_unique<SEQ_ERR_RETRAN>();
	}	

	RCU_LOCK_SLOW			slowlock;
	uint32_t			nadded = 0, nskipped = 0;

	for (std::shared_ptr<TCP_LISTENER> & listenshr : veclist) {
		if (!listenshr) {
			continue;
		}

		try {
			uint16_t		port = listenshr->ns_ip_port_.ip_port_.port_;
			
			if (portset.size() >= SVC_NET_CAPTURE::MAX_NETNS_PORTS) {
				auto			it = portset.find(port);

				if (it == portset.end()) {
					nskipped++;
					continue;
				}	
			}
			else { 
				portset.emplace(port);
			}

			CONDEXEC(
				DEBUGEXECN(1,
					strbuf.appendfmt(" : Listener %s Port %hu", listenshr->comm_, port);
				);
			);

			auto			psvc = new SVC_CAP_ONE(std::move(listenshr), parse_api_calls, is_rootns, tcurr);

			port_listen_tbl_.insert_duplicate_elem(psvc, get_uint32_hash(port));

			nadded++;
		}
		catch(...) {
			port_listen_tbl_.clear_table();
			throw;
		}	
	}	

	slowlock.unlock();

	if (nskipped) {
		WARNPRINT_OFFLOAD("Service Network Capture for new Namespace : Ignored %u Listeners as max Listener Ports per Namespace limit breached %u\n", 
			nskipped, SVC_NET_CAPTURE::MAX_NETNS_PORTS);
	}	

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Starting Network Capture for new Network Namespace %lu for %lu ports and %u listeners\n", 
		netinode_, portset.size(), nadded);

	CONDEXEC(
		DEBUGEXECN(1,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "List of Listeners %s\n\n", strbuf.buffer());
		);
	);

	// Now start capture
	restart_capture();
}

tribool NETNS_CAP_ONE::check_http1_req(const uint8_t *pdata, uint32_t caplen, uint32_t datalen) noexcept
{
	if (caplen < 18) {
		return false;
	}	
	
	switch (*pdata) {
	case 'G' :
	case 'P' :
	case 'O' :
	case 'H' :
	case 'C' :
	case 'D' :
		break;

	default :
		return false;
	}

	if (!((0 == memcmp(pdata, "GET ", 4)) || (0 == memcmp(pdata, "POST ", 5)) || (0 == memcmp(pdata, "PUT ", 4)) || (0 == memcmp(pdata, "OPTIONS ", 8)) ||
		(0 == memcmp(pdata, "HEAD ", 5)) || (0 == memcmp(pdata, "DELETE ", 7)) || (0 == memcmp(pdata, "CONNECT ", 8)))) {
		return false;
	}	

	auto			pend = pdata + caplen;
	const uint8_t		*phttp = (const uint8_t *)memmem(pdata + 4, caplen - 4, "HTTP/1.", 7);

	if (!phttp) {
		if (caplen < datalen) {
			// Truncated req
			return indeterminate;
		}	
		return false;
	}	
	
	if ((phttp + 9 < pend) && (phttp[7] == '1' || phttp[7] == '0') && phttp[8] == '\r' && phttp[9] == '\n') {
		return true;
	}	

	return false;
}

bool NETNS_CAP_ONE::get_http1_status_resp(const uint8_t *pdata, uint32_t caplen, bool & is_cli_err, bool & is_ser_err) noexcept
{
	if (caplen < 19) {
		return false;
	}	

	if (memcmp(pdata, "HTTP/1.", 7)) {
		return false;
	}	
	
	if (!(pdata[7] == '1' || pdata[7] == '0')) {
		return false;
	}	

	if (pdata[8] != ' ') {
		return false;
	}	

	const uint8_t		sbyte = pdata[9];

	if (!((sbyte >= '1' && sbyte <= '5') && (pdata[10] >= '0' && pdata[10] <= '9') && (pdata[11] >= '0' && pdata[11] <= '9') && pdata[12] == ' ')) {
		return false;
	}	

	if (sbyte == '4') {
		is_cli_err = true;
	}	
	else if (sbyte == '5') {
		is_ser_err = true;
	}	

	return true;
}


// Returns false on non HTTP payloads
bool NETNS_CAP_ONE::handle_req_err_locked(SVC_CAP_ONE & svc, const GY_IP_ADDR & cliip, uint16_t cliport, const GY_TCP_HDR & tcp, const uint8_t *pdata, uint32_t datalen, uint32_t caplen, struct timeval tv_pkt) const 
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

		tret = check_http1_req(pdata, caplen, datalen);

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
					bool		bret = http2_proto::is_valid_req_resp(pdata, datalen, caplen);
					
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
bool NETNS_CAP_ONE::handle_resp_err_locked(SVC_CAP_ONE & svc, const GY_IP_ADDR & cliip, uint16_t cliport, const GY_TCP_HDR & tcp, const uint8_t *pdata, uint32_t datalen, uint32_t caplen, struct timeval tv_pkt) const 
{
	if (svc.nconfirm_noweb_ >= 3) {
		return true;
	}

	SVC_CAP_ONE::SessInfo 		*psess = nullptr;
	
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
					
					bret = http2_proto::is_settings_response(pdata, datalen, caplen);

					// Lets wait for Client request before confirming
					return bret;
				}

				psess->init_resp_pend_ = false;

				if (psess->init_http1_req_ || psess->last_http1_req_maybe_) {
					psess->init_http1_req_ = false;
					psess->last_http1_req_maybe_ = false;

					bret = get_http1_status_resp(pdata, caplen, is_cli_err, is_ser_err);

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

					bret = http2_proto::is_settings_response(pdata, datalen, caplen);

					if (!bret) {
						bret = get_http1_status_resp(pdata, caplen, is_cli_err, is_ser_err);

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
					bret = get_http1_status_resp(pdata, caplen, is_cli_err, is_ser_err);

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
				bret = get_http1_status_resp(pdata, caplen, is_cli_err, is_ser_err);

				if (!bret) {
					bret = http2_proto::is_valid_req_resp(pdata, datalen, caplen);
				}	

				return bret;
			}	
		}
		else {
			bret = get_http1_status_resp(pdata, caplen, is_cli_err, is_ser_err);

			if (!bret) {
				bret = http2_proto::is_valid_req_resp(pdata, datalen, caplen);
			}	

			return bret;
		}	
	}	

	if (svc.is_http2_) {
		// First check if HTTP2 response
		bret = http2_proto::get_status_response(pdata, caplen, is_cli_err, is_ser_err);

		if (!bret) {
			bret = get_http1_status_resp(pdata, caplen, is_cli_err, is_ser_err);
		}	
	}
	else {
		bret = get_http1_status_resp(pdata, caplen, is_cli_err, is_ser_err);
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

int NETNS_CAP_ONE::process_pkt(const uint8_t *pframe, uint32_t caplen, uint32_t origlen, int linktype, struct timeval tv_pkt) const noexcept
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

		if ((caplen > origlen) || (caplen == 0 && !tcp.syn && !tcp.fin && !tcp.rst)) {
			return 0;
		}	

		if (is_ipv4) {
			get_src_dest_ipv4(pip, srcip, dstip);
		}
		else {
			get_src_dest_ipv6(pip6, srcip, dstip);
		}

		// We use RCU Fast lock as on everty Ring Buffer Read or timeout offlne will be done
		RCU_LOCK_FAST			fastlock;

		auto				[psvc, dir] = get_svc_from_tuple_locked(srcip, tcp.source, dstip, tcp.dest);
		bool				bret = true;
		
		if (!psvc) {
			return 1;
		}	

		if (dir == DirPacket::DIR_INBOUND) {
			if (parse_api_calls_ == false) {
				bret = handle_req_err_locked(*psvc, srcip, tcp.source, tcp, pdata, data_len, caplen, tv_pkt);
			}
		}
		else {
			if (parse_api_calls_ == false) {
				bret = handle_resp_err_locked(*psvc, dstip, tcp.dest, tcp, pdata, data_len, caplen, tv_pkt);
			}	
		}	

		if (bret == false) {
			psvc->nmaybe_noweb_++;
		}	

		return 0;
	}
	catch(...) {
		return 0;
	}	
}	

// Returns the snaplen needed
uint32_t NETNS_CAP_ONE::get_filter_string(STR_WR_BUF & strbuf) 
{
	PortStackSet			portset;
	PortStackSet			dualportset;
	uint16_t			maxport = 0, nports = 0;
		
	const auto pchk = [&, parse_api_calls = this->parse_api_calls_](SVC_CAP_ONE *psvcone, void *arg1) -> CB_RET_E
	{
		const auto 		*plisten = psvcone->listenshr_.get();

		if (plisten) {
			uint16_t		port = plisten->ns_ip_port_.ip_port_.port_;
			
			if (parse_api_calls || (psvcone->web_confirm_ == false && psvcone->nconfirm_noweb_ < 3)) {
				dualportset.emplace(port);
			}
			
			portset.emplace(port);

			if (maxport < port) maxport = port;
		}	

		return CB_OK;
	};	

	port_listen_tbl_.walk_hash_table_const(pchk);

	for (uint16_t port : portset) {
		if (nports++ > 0) strbuf.appendconst(" or ");

		if (auto it = dualportset.find(port); it == dualportset.end()) {
			strbuf.appendfmt("tcp src port %hu", port);
		}
		else {
			strbuf.appendfmt("tcp port %hu", port);
		}
	}	

	if (strbuf.is_overflow() || nports == 0) {
		GY_THROW_EXCEPTION("Service Network Capture filter error : Internal buffer overflow or 0 ports seen : filter buffer length %lu : #ports %hu",
			strbuf.size(), nports);
	}	

	max_listen_port_.store(maxport, std::memory_order_relaxed);

	DEBUGEXECN(1,
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Service Network Capture for Namespace inode %lu : Filter has %u ports with %lu bidirectional ports\n", 
				netinode_, nports, dualportset.size());
	);

	return (dualportset.size() > 0 ? 196 : 128);
}	


void NETNS_CAP_ONE::restart_capture()
{
	STRING_BUFFER<3000>		filstr;
	uint32_t			bufsz, snaplen;

	forcerestart_ = false;
	tstart_ = time(nullptr);
	
	snaplen = get_filter_string(filstr);
	
	if (netcap_) {
		// Just signal. The capture thread will eventually restart the capture
		netcap_->restart_capture_signal(filstr.buffer(), filstr.length());
		return;
	}

	RCU_LOCK_SLOW			slowlock;

	auto				pnetns = TCP_SOCK_HANDLER::get_singleton()->get_netns_locked(netinode_);
	if (!pnetns) {
		DEBUGEXECN(1, WARNPRINT_OFFLOAD("Failed to get Net Namespace object for Service Net Capture of inode %lu\n", netinode_));
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

	const auto pcapcb = [this](const uint8_t * pframe, uint32_t caplen, uint32_t origlen, int linktype, struct timeval tv_cap) noexcept
	{
		return process_pkt(pframe, caplen, origlen, linktype, tv_cap);
	};

	const auto timeoutcb = [this, setns_called = false, next_stats_time = tstart_ + 300](const PCAP_NET_CAP *pnetcap) mutable noexcept
	{
		if (!pnetcap) return;

		if (setns_called == false) {
			setns_called = true;

			RCU_LOCK_SLOW			slowlock;

			auto				pnetns = TCP_SOCK_HANDLER::get_singleton()->get_netns_locked(netinode_);
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
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Service Network Stats for Network Namespace %lu in last few minutes : "
				"%u packets %u drops #Listeners %lu Retransitted Errors %lu\n", 
				netinode_, npkts_received, npkts_kernel_drops, port_listen_tbl_.approx_count_fast(), 
				retranchk_ ? gy_diff_counter(retranchk_->nretrans_, retranchk_->last_nretrans_) : 0);
		}
	};	

	if (!is_rootns_) {
		if (parse_api_calls_) {
			bufsz = 4 * 1024 * 1024;
		}	
		else {
			bufsz = 2 * 1024 * 1024;
		}	
	}	
	else {
		if (parse_api_calls_) {
			bufsz = 16 * 1024 * 1024;
		}	
		else {
			bufsz = 8 * 1024 * 1024;
		}	
	}	

	netcap_ = std::make_unique<PCAP_NET_CAP>("any", filstr.buffer(), filstr.length(), std::move(pcapcb), bufsz, snaplen, false /* use_promiscuous */, 1024 * 1024 /* thr_stacksz */,
							1 /* timeout_sec */, std::move(timeoutcb), 1000, true /* rcu_offline_after_read */);
}	

} // namespace gyeeta

