//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include		"gy_dns_mapping.h"
#include		"gy_net_parse.h"
#include		"gy_sys_hardware.h"
#include		"gy_scheduler.h"
#include		"gy_stack_container.h"
#include		"gy_network_capture.h"
#include		"gy_print_offload.h"

namespace gyeeta {


DNS_MAPPING::DNS_MAPPING(const char * save_entry_pathin) 
	: dnstable(1)
{
	auto pnetif = NET_IF_HDLR::get_singleton();
	if (!pnetif) {
		GY_THROW_EXCEPTION("Network Interface singleton not initialized yet...");
	}	

	if (save_entry_pathin && *save_entry_pathin) {
		fd_save_file.~SCOPE_FD();

		new (&fd_save_file) SCOPE_FD(save_entry_pathin, O_RDWR | O_CREAT | O_CLOEXEC, 0640);	// noexcept

		// Load last saved DNS entries
		char 			*psavebuf;
		size_t			size, nentries;
		DNS_ENTRY		*pentry, *pelem;

		GY_STRNCPY(save_entry_path, save_entry_pathin, sizeof(save_entry_path) - 1);
		psavebuf = read_file_to_alloc_buffer(save_entry_path, &size, MAX_SAVED_DNS_ENTRIES * sizeof(DNS_ENTRY));

		GY_SCOPE_EXIT {
			if (psavebuf) {
				free(psavebuf);
			}	
		};
			
		if (psavebuf) {
			RCU_DEFER_OFFLINE	slowlock;

			nentries 		= size / sizeof(DNS_ENTRY);
			pentry 			= reinterpret_cast<DNS_ENTRY *>(psavebuf);

			for (size_t i = 0; i < nentries; ++i, ++pentry) {
				pentry->domain[MAX_DOMAINNAME_SIZE - 1] = '\0';

				pelem = new DNS_ENTRY(pentry->domain, pentry->dstaddr, pentry->tusec_added);

				DEBUGEXECN(1, 
					char		ipbuf[128];

					INFOPRINTCOLOR(GY_COLOR_CYAN, "Adding saved DNS entry for Domain \'%s\' with IP %s\n", 
							pelem->domain, pelem->dstaddr.printaddr(ipbuf, sizeof(ipbuf)));
				);

				dnstable.insert_or_replace(pelem, pelem->dstaddr, pelem->hash_field_);
			}	
		}	
	}
		
	/*
	 * We capture DNS responses on pseudo interface any and all bridge master interfaces
	 */
	INLINE_STACK_VECTOR<std::pair<std::string, std::weak_ptr <IF_LINK>>, 16 * 1024>		vecnew;
	std::weak_ptr <IF_LINK> 		weakp;

	vecnew.emplace_back("any", weakp);

	auto lambda1 = [&](NET_IF_ELEM_TYPE *pdatanode, void *arg1) noexcept -> CB_RET_E
	{
		try {
			auto			pif = pdatanode->get_data()->get();

			if (pif && pif->is_bridge && pif->if_kind == IF_KIND_BRIDGE_MASTER && pif->is_if_up) {

				if (vecnew.size() < DNS_MAPPING::MAX_CAPTURE_INTERFACES - 1) {
					vecnew.emplace_back(pif->ifname, pif->weak_from_this());
				}
				else {
					return CB_BREAK_LOOP;
				}	
			}
				 
			return CB_OK;
		}
		GY_CATCH_EXCEPTION(return CB_BREAK_LOOP;);
	};	

	pnetif->iftable.walk_hash_table(lambda1, nullptr); 	
	
	tlast_added = get_usec_time();

	for (auto & it : vecnew) {
		try {
			const auto pcapcb = [this](const uint8_t * pframe, uint32_t caplen, uint32_t origlen, int linktype, struct timeval tv_cap) noexcept
			{
				return process_dns_response(pframe, caplen, origlen, linktype, tv_cap);
			};

			pcapture_list.push_back(std::make_unique<PCAP_NET_CAP>(it.first.c_str(), CAP_FILTER_STRING, strlen(CAP_FILTER_STRING), std::move(pcapcb), 2 * 1024 * 1024, 4096));

			if (pcapture_list.size() >= MAX_CAPTURE_INTERFACES - 1) {
				break;
			}	
		}
		GY_CATCH_EXCEPTION(
			ERRORPRINT("Exception caught while starting pcap capture from network ... : %s\n", GY_GET_EXCEPT_STRING);

			pcapture_list.clear();
					
			throw;
		);	
	}	
}

int DNS_MAPPING::process_dns_response(const uint8_t *pframe, uint32_t caplen, uint32_t origlen, int linktype, struct timeval tv_pkt) noexcept
{
	const struct ip 	*pip;
	const struct ip6_hdr	*pip6;
	const uint8_t		*porigframe, *pudp, *ptcp; 
	uint8_t			transport_proto;
	uint32_t 		ip_offset, transport_offset, data_offset, data_len;
	int			ret;
	bool			is_ipv4;
	
	ret = get_ip_offset(pframe, caplen, linktype, ip_offset, is_ipv4);
	if (ret != 0 || (ip_offset > caplen)) {
		return 1;
	}	

	porigframe = pframe;

	caplen -= ip_offset;
	pframe += ip_offset;

	if (is_ipv4) {
		pip = decltype(pip)(pframe);
		
		ret = get_ipv4_transport_offset(pip, caplen, transport_proto, transport_offset, data_offset, data_len);
	}	
	else {
		pip6 = decltype(pip6)(pframe);
		
		ret = get_ipv6_transport_offset(pip6, caplen, transport_proto, transport_offset, data_offset, data_len);
	}	

	if (ret != 0 || ((transport_offset > caplen) || ((data_len > 0) && ((data_offset + data_len > caplen) || (data_offset < transport_offset))))) {
		return 1;
	}	

	if ((data_len < 32) || ((transport_proto != IP_PROTO_UDP) && (transport_proto != IP_PROTO_TCP))) {
		return 1;
	}	

	caplen -= transport_offset;
	pframe += transport_offset;

	if (transport_proto == IP_PROTO_UDP) {
		pudp = pframe;
			
		GY_UDP_HDR		udp(pudp);

		if (gy_unlikely(udp.source != 53)) {
			return 1;
		}	
		
		pframe += (data_offset - transport_offset);

		return parse_dns_response(pframe, data_len, tv_pkt);
	}
	else {
		ptcp = pframe;
			
		GY_TCP_HDR		tcp(ptcp);
		uint16_t		msglen;
		
		if (gy_unlikely(tcp.source != 53)) {
			return 1;
		}	
		
		pframe += (data_offset - transport_offset);

		do {
			msglen = unaligned_read_be16(pframe);

			if ((int)msglen > (int)data_len - 2) {
				return 1;
			}
			
			pframe 		+= 2;
			data_len 	-= 2;

			ret = parse_dns_response(pframe, msglen, tv_pkt);

			pframe 		+= msglen;
			data_len 	-= msglen;

		} while ((int)data_len > 2);

		return ret;
	}	
}	
	
int DNS_MAPPING::parse_dns_response(const uint8_t *pdata, uint32_t len, struct timeval tv_pkt) noexcept	
{
	try {
		const uint8_t 		* const pstart = pdata;
		const uint8_t 	 	* const pend = pdata + len;
		const uint8_t		*ptmp = pdata;
		uint32_t		nqueries, nanswers;
		
		if (len < 32) {
			return 1;
		}
		
		ptmp += 2;

		if ((0 == (ptmp[0] & 0x80)) || (0 != (ptmp[1] & 0x0F))) {
			return 1;
		}	
			
		ptmp += 2;
			
		nqueries = unaligned_read_be16(ptmp);

		if ((nqueries == 0) || (nqueries > 8)) {
			return 1;
		}	

		ptmp += 2;

		nanswers = unaligned_read_be16(ptmp);

		if (nanswers == 0) {
			return 1;
		}
		else if (nanswers > 16) {
			nanswers = 16;
		}	

		char			domainarray[nqueries + 1][MAX_DOMAINNAME_SIZE];
		uint16_t		offsetarray[nqueries + 1] {};

		uint16_t		tdata;
		uint8_t			n;

		ptmp += 6;

		for (uint32_t i = 0; i < nqueries; i++) {
			STR_WR_BUF		strbuf(domainarray[i], MAX_DOMAINNAME_SIZE);

			if (ptmp + 5 >= pend) {
				return 1;
			}	
			
			offsetarray[i] = ptmp - pstart;

			do {
				n = *ptmp++;

				if (ptmp + n >= pend) {
					return 1;
				}	
				
				if (n == 0) {
					strbuf.set_last_char('\0');
					break;
				}
					
				strbuf.append((const char *)ptmp, n);
				strbuf.append('.');

				ptmp += n;

			} while (ptmp + 4 < pend);

			if (0 == strbuf.length()) {
				return 1;
			}	
			
			if (ptmp + 4 >= pend) {
				return 1;
			}	

			ptmp += 4;
		}	
		
		/*
		 * Now parse the Answers
		 */
		for (uint32_t i = 0; i < nanswers; i++) {
			char			inlinename[MAX_DOMAINNAME_SIZE];
			const char 		*pdomain = nullptr;
			GY_IP_ADDR		addr;

			if (ptmp + 15 > pend) {
				return 1;
			}	 
		
			if ((*ptmp & 0xC0) == 0xC0) {
				// Pointer to domain. Check if the domain was previously saved...

				tdata = unaligned_read_be16(ptmp);
				tdata &= 0x0FFF;

				uint32_t 	j = 0;

				if (nqueries > 1) {
					for (; j < nqueries; j++) {
						if (offsetarray[j] == tdata) {
							break;
						}	
					}	

					if (j == nqueries) {
						return 1;
					}
				}

				pdomain = domainarray[j];
				ptmp += 2;
			}
			else {
				STR_WR_BUF		strbuf(inlinename, MAX_DOMAINNAME_SIZE);

				if (ptmp + 5 >= pend) {
					return 1;
				}	
				
				do {
					n = *ptmp++;

					if (ptmp + n >= pend) {
						return 1;
					}	
					
					if (n == 0) {
						strbuf.set_last_char('\0');
						break;
					}
						
					strbuf.append((const char *)ptmp, n);
					strbuf.append('.');

					ptmp += n;

				} while (ptmp + 4 < pend);

				if (0 == strbuf.length()) {
					return 1;
				}	

				pdomain = inlinename;
			}	

			if (gy_unlikely(nullptr == pdomain)) {
				return 1;
			}	

			tdata = unaligned_read_be16(ptmp);
			
			if (tdata == 0x1) {
				// IPv4
				ptmp += 8;

				if (ptmp + 2 + 4 > pend) {
					return 1;
				}	

				tdata = unaligned_read_be16(ptmp);

				if (tdata != 4) {
					return 1;
				}	

				ptmp += 2;
				
				uint32_t		ip4;

				std::memcpy(&ip4, ptmp, sizeof(ip4));

				ptmp += 4;

				addr.set_ip(ip4);
			}	
			else if (tdata == 0x1c) {
				// IPv6
				ptmp += 8;

				if (ptmp + 2 + 16 > pend) {
					return 1;
				}	
				tdata = unaligned_read_be16(ptmp);

				if (tdata != 16) {
					return 1;
				}	

				ptmp += 2;

				unsigned __int128	ip6;

				std::memcpy(&ip6, ptmp, sizeof(ip6));

				ptmp += 16;

				addr.set_ip(ip6);
			}	
			else if (tdata == 0x5 && (nqueries == 1)) { // CNAME Record : Proceed only if nqueries == 1  
				
				ptmp += 8;

				if (ptmp + 2 > pend) {
					return 1;
				}	

				tdata = unaligned_read_be16(ptmp);

				ptmp += 2 + tdata;
				
				continue;
			}	
			else {
				return 1;
			}	

			add_dns_entry(pdomain, addr);
		}
			
		return 0;	
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Exception caught while parsing DNS response : %s\n", GY_GET_EXCEPT_STRING););
		return -1;
	);	
}	
	
int DNS_MAPPING::add_dns_entry(const char *pdomain, const GY_IP_ADDR & addr) noexcept
{
	RCU_DEFER_OFFLINE		slowlock;

	try {
		const uint32_t		hash = addr.get_hash();
		bool			bret;

		auto lambda_look = [&](DNS_ENTRY *pdatanode, void *arg1, void *arg2) noexcept -> CB_RET_E
		{
			if (strcmp(pdatanode->domain, pdomain)) {
				CONDEXEC(
					DEBUGEXECN(1, 
						char		ipbuf[128];

						INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Replacing DNS entry for older Domain \'%s\' to new Domain \'%s\' with IP %s\n", 
							pdatanode->domain, pdomain, addr.printaddr(ipbuf, sizeof(ipbuf)));
					);
				);
			
				GY_STRNCPY(pdatanode->domain, pdomain, sizeof(pdatanode->domain));
			}	
			GY_WRITE_ONCE(pdatanode->tusec_access, get_usec_time());

			return CB_OK;
		};	
	
		bret = dnstable.lookup_single_elem(addr, hash, lambda_look);
		
		if (bret == true) {
			return 1;
		}	

		// Now add the new element

		DNS_ENTRY		*pelem;

		pelem = new DNS_ENTRY(pdomain, addr);

		CONDEXEC(
			DEBUGEXECN(1, 
				char		ipbuf[128];

				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Adding new DNS entry for Domain \'%s\' with IP %s\n", pdomain, addr.printaddr(ipbuf, sizeof(ipbuf)));
			);
		);

		dnstable.insert_or_replace(pelem, addr, hash);

		return 0;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Exception caught while adding DNS entry : %s\n", GY_GET_EXCEPT_STRING););
		return -1;
	);	
}	
	
int DNS_MAPPING::check_for_deletion() noexcept
{
	try {
		size_t		approxcount = dnstable.approx_count_fast();
		time_t 		tcur = time(nullptr);

		if (tcur - tlast_check > 30) {
			approxcount = dnstable.count_slow();
			tlast_check = tcur;

			INFOPRINT_OFFLOAD("Current DNS Entries is %lu\n", approxcount);
		}	

		if (approxcount < 1000) {
			return 0;
		}	

		uint64_t		tusec = get_usec_time(), tmin_access, tmin_added;
		size_t			ndels = 0;

		if (approxcount < 3000) {
			// We delete all DNS records older than 12 hours and not accessed in the last 1 hour
			tmin_access = tusec - 1 * GY_USEC_PER_HOUR; 
			tmin_added = tusec - 12 * GY_USEC_PER_HOUR;
		}
		else {
			// Remove all entries added over 1 hour earlier	
			tmin_access = tusec - 30 * GY_USEC_PER_MINUTE; 
			tmin_added = tusec - 60 * GY_USEC_PER_MINUTE;
		}		

		auto lam_walk = [&](DNS_ENTRY *pdatanode, void *arg1) -> CB_RET_E
		{
			if ((GY_READ_ONCE(pdatanode->tusec_access) < tmin_access) && (GY_READ_ONCE(pdatanode->tusec_added) < tmin_added)) {
				ndels++;	
				return CB_DELETE_ELEM;
			}		

			return CB_OK;
		};	

		dnstable.walk_hash_table(lam_walk, nullptr);

		if (ndels) {
			INFOPRINT_OFFLOAD("Large number of DNS Mapping entries %lu : Deleted %lu entries after cleanup\n", approxcount, ndels);
		}
		return 0;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Exception caught while checking for too many DNS entries : %s\n", GY_GET_EXCEPT_STRING););
		return -1;
	);	
}	

int DNS_MAPPING::check_new_bridge_masters() noexcept
{
	try {
		/*
		 * First check whether all captures running
		 */
		pcapture_list.remove_if(
			[](std::unique_ptr<PCAP_NET_CAP> & pelem)
			{
				if (pelem && (false == pelem->is_capture_active())) {
					INFOPRINT_OFFLOAD("DNS Capture on interface %s has stopped. Deleting...\n", pelem->ifname_);
					return true;
				}
				return false;
			}
		);		
		
		if (pcapture_list.size() >= MAX_CAPTURE_INTERFACES) {
			return 0;
		}
			
		auto pnetif = NET_IF_HDLR::get_singleton();
		if (!pnetif) {
			return -1;
		}	

		INLINE_STACK_VECTOR<std::pair<std::string, std::weak_ptr <IF_LINK>>, 16 * 1024>		vecnew;
		const uint64_t				last_usec = tlast_added;					
		const size_t				max_new_adds = MAX_CAPTURE_INTERFACES - pcapture_list.size();

		auto lambda1 = [&, last_usec](NET_IF_ELEM_TYPE *pdatanode, void *arg1) -> CB_RET_E
		{
			try {
				auto			pif = pdatanode->get_data()->get();

				if (pif && pif->is_bridge && pif->if_kind == IF_KIND_BRIDGE_MASTER && pif->is_if_up && pif->if_add_usec_time > last_usec) {

					if (vecnew.size() < max_new_adds) {
						vecnew.emplace_back(pif->ifname, pif->weak_from_this());
					}
					else {
						return CB_BREAK_LOOP;
					}	
				}
				
				return CB_OK;
			}
			GY_CATCH_EXCEPTION(return CB_BREAK_LOOP;);
		};	

		pnetif->iftable.walk_hash_table(lambda1, nullptr); 	
		
		for (auto & it : vecnew) {

			auto findit = std::find_if (std::begin(pcapture_list), std::end(pcapture_list),
					[&](const std::unique_ptr<PCAP_NET_CAP> & pelem)
					{ 
						return pelem && (0 == strcmp(pelem->ifname_, it.first.c_str()));
					} 
				);
			
			if (findit == pcapture_list.end()) {			

				INFOPRINT_OFFLOAD("New Bridge Master %s seen. Starting Network capture on this device...\n", it.first.c_str());

				const auto pcapcb = [this](const uint8_t * pframe, uint32_t caplen, uint32_t origlen, int linktype, struct timeval tv_cap) noexcept
				{
					return process_dns_response(pframe, caplen, origlen, linktype, tv_cap);
				};

				pcapture_list.push_back(std::make_unique<PCAP_NET_CAP>(it.first.c_str(), CAP_FILTER_STRING, strlen(CAP_FILTER_STRING), std::move(pcapcb), 2 * 1024 * 1024, 4096));
			}
		}	
		
		tlast_added = get_usec_time();

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT("Exception caught while checking for new Bridge Masters : %s\n", GY_GET_EXCEPT_STRING);
		return -1;
	);	
}	

int DNS_MAPPING::save_dns_to_file() noexcept
{
	try {
		int			fd = fd_save_file.get();

		if (fd == -1) {
			return -1;
		}	

		size_t			approxcount = dnstable.approx_count_fast();
		uint64_t		tusec = get_usec_time(), tmin_access;
		size_t			nsaved = 0;

		if (approxcount < 256) {
			// We save all entries upto 7 days
			tmin_access = tusec - 7 * GY_USEC_PER_DAY;
		}
		else {
			// We save all entries accessed in the last day
			tmin_access = tusec - GY_USEC_PER_DAY;
		}		
		
		ftruncate(fd, 0);
		lseek(fd, 0, SEEK_SET);

		auto lam_walk = [&](DNS_ENTRY *pdatanode, void *arg1) -> CB_RET_E
		{
			if (GY_READ_ONCE(pdatanode->tusec_access) > tmin_access) {
				int		ret;
			
				ret = write(fd, pdatanode, sizeof(*pdatanode));
				if (ret == sizeof(*pdatanode)) {
					nsaved++;	

					if (nsaved >= MAX_SAVED_DNS_ENTRIES) {
						return CB_BREAK_LOOP;
					}

					return CB_OK;
				}

				return CB_BREAK_LOOP;
			}		

			return CB_OK;
		};	

		dnstable.walk_hash_table(lam_walk, nullptr);

		if (nsaved) {
			INFOPRINT_OFFLOAD("Saved %lu DNS entries to file %s out of a total of %lu entries\n", nsaved, save_entry_path, approxcount);
		}
		return 0;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Exception caught while saving DNS entries to file : %s\n", GY_GET_EXCEPT_STRING););
		return -1;
	);	
}	


static DNS_MAPPING		*pgdns_mapping;

DNS_MAPPING * DNS_MAPPING::get_singleton() noexcept
{
	return pgdns_mapping;
}
	
int DNS_MAPPING::init_singleton(const char * save_entry_pathin)
{
	int				texp = 0, tdes = 1;
	static std::atomic<int>		is_init_done(0);

	if (false == is_init_done.compare_exchange_strong(texp, tdes)) {
		return 0;
	}

	/*
	 * Initialize all singletons we need, if not already done
	 */
	GY_SCHEDULER::init_singletons();

	SYS_HARDWARE::init_singleton();

	auto schedshr = GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_MAINTENANCE);

	if (!schedshr) {
		GY_THROW_EXCEPTION("Global Scheduler Shared object not yet initialized");
	}	
	 
	try {
		pgdns_mapping = new DNS_MAPPING(save_entry_pathin);

		/*
		 * Schedule a periodic 10 sec check for Too many DNS entries
		 */
		schedshr->add_schedule(43700, 10000, 0, "check for too many DNS entries", 
		[] { 
			auto pdns = DNS_MAPPING::get_singleton();
			if (pdns) {
				pdns->check_for_deletion();
			}	
		});
		
		/*
		 * Schedule a periodic 30 sec check for new Bridge Master devices
		 */
		schedshr->add_schedule(54700, 30000, 0, "check for new Bridge Master devices", 
		[] { 
			auto pdns = DNS_MAPPING::get_singleton();
			if (pdns) {
				pdns->check_new_bridge_masters();
			}	
		});

		/*
		 * Schedule a periodic 300 sec save of DNS entries to file
		 */
		if (save_entry_pathin && (pgdns_mapping->fd_save_file.get() != -1)) { 
			schedshr->add_schedule(90300, 300'000, 0, "save DNS entries to file", 
			[] { 
				auto pdns = DNS_MAPPING::get_singleton();
				if (pdns) {
					pdns->save_dns_to_file();
				}	
			});
		}

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT("Exception caught while creating global DNS Mapping object ... : %s\n", GY_GET_EXCEPT_STRING);
		throw;
	);	
}	

} // namespace gyeeta	
