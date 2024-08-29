//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later


#include			"gy_pseudo_pcap_cap.h"
#include			"gy_network_capture.h"
#include			"gy_svc_net_capture.h"


namespace gyeeta {

PSEUDO_PCAP_CAP::PSEUDO_PCAP_CAP(const char *filepath, const IP_PORT *pcap_ip_port_arr, const uint16_t *pact_port_arr, uint32_t narrelem, uint64_t netns, API_PARSE_HDLR & apihdlr, 
					int nrepeats, float comp_rate, bool delete_object_on_end)
	: netns_(netns), nrepeats_(nrepeats), comp_rate_(comp_rate), del_on_end_(delete_object_on_end), apihdlr_(apihdlr),
	delay_multiplier_(comp_rate >= 1.0f ? 1.0f / comp_rate : (comp_rate < 0 ? -comp_rate : 0)),
	rdpcap_(filepath)
{
	GY_STRNCPY(filepath_, filepath, sizeof(filepath_));

	if (!pcap_ip_port_arr || !pact_port_arr || !narrelem) {
		GY_THROW_EXCEPTION("No input pcap IP/Port or Actual Port specified for pseudo pcap");
	}

	for (int i = 0; i < (int)narrelem; ++i) {
		ipportmap_.try_emplace(pcap_ip_port_arr[i], pact_port_arr[i]);
	}

	pthr_ = std::make_unique<GY_THREAD>("pseudo pcap Thread", PSEUDO_PCAP_CAP::GET_PTHREAD_WRAPPER(pcap_rd_thread), this, nullptr, nullptr, false /* start_immed */, 1024 * 1024,
							0, false, true, true /* thr_func_calls_init_done */, 10000, true /* throw_on_init_timeout */);
	pthr_->start_thread();
}	
	

int PSEUDO_PCAP_CAP::pcap_rd_thread() noexcept
{
	pthr_->set_thread_init_done();

	gy_msecsleep(100);

	try {
		struct timeval 			tv_pkt;
		uint32_t 			caplen, origlen;
		int				ntimes = 0, ret;
		uint8_t				*pframe;
		const int			linktype = rdpcap_.get_linktype();
		uint64_t			currusec;

		pframe = rdpcap_.read_next_pcap_pkt(tv_pkt, caplen, origlen);
		if (!pframe) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Pseudo pcap handler : pcap file %s does not contain any valid packet\n", filepath_);
			return 0;
		}	

		tpcapstartus_ = timeval_to_usec(tv_pkt);

		do {	
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Pseudo pcap handler : Starting %d iteration of %d total for pcap %s with compression rate %f\n",
						ntimes + 1, nrepeats_ + 1, filepath_, comp_rate_);
			
			tactstartus_ = get_usec_time();
			
			rdpcap_.restart_pcap_read();
			
			do {
				pframe = rdpcap_.read_next_pcap_pkt(tv_pkt, caplen, origlen);
				if (!pframe) {
					break;
				}	
				
				ret = send_pkt(pframe, caplen, origlen, linktype, tv_pkt);
				if (ret != 0) {
					continue;
				}	

			} while (true);	
			
			
			currusec = get_usec_time();

			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Pseudo pcap handler : Completed %d iteration of %d total for pcap %s in %ld sec (%ld min) : "
						"Pkts seen %lu : skipped %lu Other servers %lu Pool skips %lu\n",
						ntimes + 1, nrepeats_ + 1, filepath_, (currusec - tactstartus_)/GY_USEC_PER_SEC, (currusec - tactstartus_)/GY_USEC_PER_MINUTE,
						stats_.npkts_, stats_.nskipped_, stats_.nother_server_, stats_.npool_skip_);

			if (ntimes++ < nrepeats_) {
				stats_.reset();

				gy_msecsleep(5000);
			}
			else {
				break;
			}	

		} while (true);

	}
	GY_CATCH_EXPRESSION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception seen in pseudo pcap reader : %s\n", GY_GET_EXCEPT_STRING);
	);

	if (del_on_end_) {
		// Deferred cleanup 
		apihdlr_.svcnet_.get_api_scheduler().add_oneshot_schedule(50, gy_to_charbuf<256>("Deferred Pseudo pcap cleanup %lu", get_usec_time()).get(),
			[this]() 
			{
				try {
					delete this;
				}
				catch(...) {

				}	
			});
	}	

	return 0;
}


int PSEUDO_PCAP_CAP::send_pkt(const uint8_t *pframe, uint32_t caplen, uint32_t origlen, int linktype, struct timeval tv_pkt) noexcept
{
	try {
		const struct ip 		*pip = nullptr;
		const struct ip6_hdr		*pip6 = nullptr;
		const uint8_t			*porigframe, *pdata, *ptcp; 

		GY_IP_ADDR			srcip, dstip;
		uint16_t			msglen;
		uint8_t				transport_proto;
		uint32_t 			ip_offset, transport_offset, data_offset, data_len, orig_caplen = caplen;
		int				ret;
		bool				is_ipv4;
		
		stats_.npkts_++;

		ret = get_ip_offset(pframe, caplen, linktype, ip_offset, is_ipv4);
		if (ret != 0 || (ip_offset > caplen)) {
			stats_.nskipped_++;
			return -1;
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
			stats_.nskipped_++;
			return 1;
		}	

		ptcp = pframe + transport_offset;
				
		GY_TCP_HDR			tcp(ptcp);

		pframe += data_offset;
		caplen -= data_offset ;

		pdata = pframe;

		if ((caplen > origlen) || (caplen == 0 && (0 == (tcp.tcpflags & (GY_TH_SYN | GY_TH_FIN | GY_TH_RST))))) {
			return 1;
		}	

		if (is_ipv4) {
			get_src_dest_ipv4(pip, srcip, dstip);
		}
		else {
			get_src_dest_ipv6(pip6, srcip, dstip);
		}

		IP_PORT			srcipport(srcip, tcp.source), dstipport(dstip, tcp.dest);
		DirPacket		dir;

		auto			it = ipportmap_.find(srcipport);	
	
		if (it == ipportmap_.end()) {
			it = ipportmap_.find(dstipport);

			if (it == ipportmap_.end()) {
				stats_.nother_server_++;
				return 1;
			}

			dir = DirPacket::DirInbound;
		}	
		else {
			dir = DirPacket::DirOutbound;
		}	

		sleep_per_pkt(tv_pkt);

		PARSE_PKT_HDR		hdr;
		bool			bret;
		
		hdr.tv_			= get_timeval();
		hdr.datalen_		= caplen;
		hdr.wirelen_		= origlen - (orig_caplen - caplen);

		if (dir == DirPacket::DirInbound) { 
			hdr.cliip_		= srcip;
			hdr.serip_		= dstip;
			hdr.cliport_		= tcp.source;

			hdr.nxt_cli_seq_	= tcp.next_expected_src_seq(caplen);	// For wirelen > caplen will cause a drop indication
			hdr.start_cli_seq_	= tcp.seq;

			hdr.nxt_ser_seq_	= tcp.ack_seq;
			hdr.start_ser_seq_	= tcp.ack_seq;
		}
		else {
			hdr.cliip_		= dstip;
			hdr.serip_		= srcip;
			hdr.cliport_		= tcp.dest;
		
			hdr.nxt_cli_seq_	= tcp.ack_seq;
			hdr.start_cli_seq_	= tcp.ack_seq;

			hdr.nxt_ser_seq_	= tcp.next_expected_src_seq(caplen);
			hdr.start_ser_seq_	= tcp.seq;
		}	

		hdr.serport_		= it->second;		// Substitute the Server Port

		hdr.netns_		= (uint32_t)netns_;
		hdr.tcpflags_		= tcp.tcpflags;
		hdr.dir_		= dir;
		hdr.src_		= SRC_PCAP;
		
		return !apihdlr_.send_pkt_to_parser(hdr, pdata, hdr.datalen_);
	}
	catch(...) {
		return 0;
	}	
}	

void PSEUDO_PCAP_CAP::sleep_per_pkt(const struct timeval & tv_pkt) noexcept
{
	if (delay_multiplier_ == 0) return;

	uint64_t			tpcap = timeval_to_usec(tv_pkt), tcurr = get_usec_time();
	int64_t				pcapdiffus = (int64_t)(tpcap - tpcapstartus_);
	int64_t				actdiffus = (int64_t)(tcurr - tactstartus_);
	int64_t				reqdiffus = pcapdiffus * delay_multiplier_;

	if (reqdiffus < actdiffus + 1000) {
		return;
	}	

	gy_usecsleep(reqdiffus - actdiffus);
}	

	
} // namespace gyeeta

