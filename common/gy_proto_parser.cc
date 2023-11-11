//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_proto_parser.h"
#include			"gy_socket_stat.h"
#include			"gy_net_parse.h"
#include			"gy_pkt_reorder.h"
#include			"gy_task_types.h"

namespace gyeeta {

SVC_INFO_CAP::SVC_INFO_CAP(const std::shared_ptr<TCP_LISTENER> & listenshr)
	: svcweak_(
	({
		if (!listenshr) {
			GY_THROW_EXCEPTION("Invalid Listen Shared Pointer for API Capture");
		}	
		listenshr;

	})), glob_id_(listenshr->glob_id_), ns_ip_port_(listenshr->ns_ip_port_),
	is_any_ip_(listenshr->is_any_ip_), is_root_netns_(listenshr->is_root_netns_)
{
	GY_STRNCPY(comm_, listenshr->comm_, sizeof(comm_));

	orig_proto_ = listenshr->api_proto_.load(mo_relaxed);

	if (orig_proto_ != PROTO_UNINIT && orig_proto_ < PROTO_UNKNOWN) {
		orig_ssl_ = listenshr->api_is_ssl_.load(mo_relaxed);
	}
}	

/*
 * Called by the SVC_NET_CAPTURE::schedthr_ only
 */
void SVC_INFO_CAP::lazy_init_blocking(SVC_NET_CAPTURE & svcnet) noexcept
{
	try {
		tribool				isssl = indeterminate;

		if (!svcnet.apihdlr_) {
			return;
		}

		auto				& apihdlr = *svcnet.apihdlr_.get();
		auto				listenshr = svcweak_.lock();

		if (!listenshr) {
			return;
		}	

		if (proto_ == PROTO_UNINIT) {
			if (orig_proto_ != PROTO_UNINIT && orig_proto_ < PROTO_UNKNOWN) {

				isssl = orig_ssl_;
				proto_ = orig_proto_;

				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Service API Network Capture for svc '%s\' port %hu set as %s with SSL Capture %s as per prior stats\n",
					comm_, ns_ip_port_.ip_port_.port_, proto_to_string(proto_), isssl == true ? "enabled" : "disabled");	
			}
			else {
				protodetect_ = std::make_unique<PROTO_DETECT>();
			}	
		}

		if (is_ssl_ == SSL_SVC_E::SSL_UNINIT && indeterminate(isssl)) {
			isssl =  typeinfo::ssl_enabled_listener(ns_ip_port_.ip_port_.port_, listenshr->comm_, listenshr->cmdline_);
		}

		if (isssl != false) {
			schedule_ssl_probe();
		}	
	}
	GY_CATCH_EXPRESSION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception seen : Failed to lazy init API Capture for svc %s port %hu : %s\n",
				comm_, ns_ip_port_.ip_port_.port_, GY_GET_EXCEPT_STRING);
	);
}	

/*
 * Called from capture threads...
 */
bool API_PARSE_HDLR::send_pkt_to_parser(SVC_INFO_CAP *psvccap, uint64_t glob_id, const PARSE_PKT_HDR & msghdr, const uint8_t *pdata, const uint32_t len)
{
	if (0 == len && (0 == (msghdr.tcpflags_ & (GY_TH_SYN | GY_TH_FIN | GY_TH_RST)))) {	// Ignore ACKs
		return true;
	}	

	uint32_t			nbytesdone = 0, nbytes;	
	uint8_t				*pdest, *pdestend, *ptmp, *pfragstart, *pfragend;
	const uint8_t			*psrcstart, *psrc_act_end = pdata + len;
	bool				bret = false;

	uint32_t			nfrag = gy_div_round_up(len, MAX_PARSE_DATA_LEN);

	if (nfrag == 0) {
		nfrag = 1;
	}	
	
	for (uint32_t i = 0; i < nfrag && nbytesdone < len; ++i) {
		auto				puniq = parsepool_.allocElem();

		if (!puniq) {
			return false;
		}	

		pfragstart 			= puniq.get()->get();
		PARSE_PKT_HDR			*phdr = (PARSE_PKT_HDR *)pfragstart;	

		nbytes				= std::min(len - nbytesdone, MAX_PARSE_DATA_LEN);

		std::memcpy(phdr, &msghdr, sizeof(*phdr));
		
		if (nfrag > 1) {
			if (i > 0) {
				phdr->tcpflags_ &= ~(GY_TH_SYN | GY_TH_URG);
			}	

			if (i < nfrag - 1) {
				phdr->tcpflags_ &= ~(GY_TH_FIN | GY_TH_RST);
			}	

			phdr->datalen_ 		= nbytes;	
			phdr->wirelen_ 		= nbytes + (i == nfrag - 1 ? msghdr.get_trunc_bytes() : 0);	

			if (phdr->dir_ == DirPacket::DirInbound) {
				phdr->start_cli_seq_	= msghdr.start_cli_seq_ + nbytesdone;
				phdr->nxt_cli_seq_	= phdr->start_cli_seq_ + nbytes + (phdr->tcpflags_ & GY_TH_SYN);
			}	
			else {
				phdr->start_ser_seq_	= msghdr.start_ser_seq_ + nbytesdone;
				phdr->nxt_ser_seq_	= phdr->start_ser_seq_ + nbytes + (phdr->tcpflags_ & GY_TH_SYN);
			}	
		}	

		if (nbytes > 0) {
			psrcstart			= pdata + nbytesdone;
			pdest				= pfragstart + sizeof(PARSE_PKT_HDR);
		
			std::memcpy(pdest, psrcstart, nbytes);
		}	

		nbytesdone += nbytes; 

		// Now send the msg
		for (int ntries = 0; ntries < 5; ++ntries) {
			bret = msgpool_.write(PARSE_MSG_BUF(std::in_place_type<MSG_PKT_SVCCAP>, psvccap, glob_id, std::move(puniq)));

			if (bret == true) {
				break;
			}

			sched_yield();
		}	

		if (bret == false) {
			return false;
		}	
	}	

	return true;
}	


void API_PARSE_HDLR::api_parse_rd_thr() noexcept
{
	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "API Capture initialized : API Parser thread init completed as well\n");

try1 :
	try {
		do {
			MSG_PKT_SVCCAP			*pmsgpkt;
			MSG_ADD_SVCCAP			*paddsvc;
			MSG_DEL_SVCCAP			*pdelsvc;
			MSG_TIMER_SVCCAP		*ptimer;
			MSG_SVC_SSL_CAP			*pssl;
			bool				bret;

			PARSE_MSG_BUF			msg;

			bret = msgpool_.tryReadUntil(std::chrono::steady_clock::now() + std::chrono::microseconds(3 * GY_USEC_PER_SEC), msg);
			if (bret) {

				switch (msg.index()) {

				case 1 :
					pmsgpkt	= std::get_if<MSG_PKT_SVCCAP>(&msg);

					if (!pmsgpkt) {
						ASSERT_OR_THROW(false, "Please fix the MSG_PKT_SVCCAP index");
					}

					handle_proto_pkt(*pmsgpkt);

					break;

				case 0 :
					paddsvc	= std::get_if<MSG_ADD_SVCCAP>(&msg);

					if (!paddsvc) {
						ASSERT_OR_THROW(false, "Please fix the MSG_ADD_SVCCAP index");
					}

					handle_svc_add(*paddsvc);
			
					break;

				case 2 :
					pdelsvc	= std::get_if<MSG_DEL_SVCCAP>(&msg);

					if (!pdelsvc) {
						ASSERT_OR_THROW(false, "Please fix the MSG_DEL_SVCCAP index");
					}
			
					handle_svc_del(*pdelsvc);

					break;

				case 3 :
					ptimer	= std::get_if<MSG_TIMER_SVCCAP>(&msg);

					if (!ptimer) {
						ASSERT_OR_THROW(false, "Please fix the MSG_TIMER_SVCCAP index");
					}

					handle_parse_timer(*ptimer);
			
				case 4 :
					pssl	= std::get_if<MSG_SVC_SSL_CAP>(&msg);

					if (!pssl) {
						ASSERT_OR_THROW(false, "Please fix the MSG_SVC_SSL_CAP index");
					}

					if (pssl->req_ == SSL_REQ_E::SSL_ACTIVE) {
						handle_ssl_active(*pssl);
					}
					else if (pssl->req_ == SSL_REQ_E::SSL_REJECTED) {
						handle_ssl_rejected(*pssl);
					}	
			
			
					break;

				default :
					assert(false);		// Unhandled index
					break;
				}	
			}	
			else {
				handle_parse_no_msg();
			}	

		} while (true);	

	}
	GY_CATCH_MSG("Exception Caught in Parser Thread");

	goto try1;
}	
	
void SVC_PARSE_STATS::update_pkt_stats(const PARSE_PKT_HDR & hdr) noexcept
{
	tlastpkt_	= hdr.tv_.tv_sec;
	
	npkts_++;
	nbytes_		+= hdr.datalen_;
	
	if (hdr.dir_ == DirPacket::DirInbound) {
		nreqpkts_++;
		nreqbytes_ += hdr.datalen_;
	}	
	else {
		nresppkts_++;
		nrespbytes_ += hdr.datalen_;
	}	

	if (hdr.src_ < API_CAP_SRC::SRC_MAX) {
		srcpkts_[hdr.src_]++;
	}	
}

bool SVC_INFO_CAP::detect_svc_req_resp(PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	IP_PORT				ipport(hdr.cliip_, hdr.cliport_);
	auto				& detect = *protodetect_.get();
	PROTO_DETECT::SessInfo		*psess = nullptr;
	bool				is_syn = hdr.tcpflags_ & GY_TH_SYN, is_finrst = hdr.tcpflags_ & (GY_TH_FIN | GY_TH_RST), skip_parse = false, skipdone = false;
	DROP_TYPES			droptype;

	auto				it = detect.smap_.find(ipport);
	
	if (it == detect.smap_.end()) {
		if (is_finrst) {
			return false;
		}	
		if (hdr.datalen_ == 0) {
			if (!is_syn) {
				return false;
			}	
		}	

		if (detect.smap_.size() < detect.MaxSessEntries) {
			if (!is_syn) {
				if (detect.nmidsess_ >= detect.MaxSessEntries/2) {
					return false;
				}	
			}	

			it = detect.smap_.try_emplace(ipport, hdr.tv_.tv_sec, 
						hdr.datalen_ == 0 ? hdr.nxt_cli_seq_ : hdr.start_cli_seq_, hdr.datalen_ == 0 ? hdr.nxt_ser_seq_ : hdr.start_ser_seq_, is_syn).first;
			
			if (is_syn) {
				detect.nsynsess_++;
			}	
			else {
				detect.nmidsess_++;
			}	
		}	
		else {
			return false;
		}	
	}	
	
	auto			& sess = it->second;
	psess			= &sess;

	const auto delsess = [&]()
	{
		if (!psess) return;

		if (psess->syn_seen_) {
			detect.nsynsess_--;
		}
		else {
			detect.nmidsess_--;
		}	

		detect.smap_.erase(it);

		psess = nullptr;
	};	

	if (is_finrst) {
		delsess();
		return true;
	}	

	if (sess.is_ssl_ && hdr.src_ != SRC_UPROBE_SSL) {
		return false;
	}	
	
	if (hdr.datalen_ == 0) {
		return true;
	}
	
	if (hdr.dir_ == DirPacket::DirInbound) {
		droptype = is_tcp_drop(sess.nxt_cli_seq_, hdr.start_cli_seq_, is_syn, sess.nxt_ser_seq_, hdr.start_ser_seq_);
	}
	else {
		droptype = is_tcp_drop(sess.nxt_ser_seq_, hdr.start_ser_seq_, is_syn, sess.nxt_cli_seq_, hdr.start_cli_seq_);
	}	

	if (droptype == DROP_TYPES::DROP_NEW_SESS) {
		delsess();
		return false;
	}	

	if (droptype == DROP_TYPES::RETRANSMIT) {
		return false;
	}

	sess.nxt_cli_seq_	= hdr.nxt_cli_seq_;
	sess.nxt_ser_seq_	= hdr.nxt_ser_seq_;
	sess.npkts_data_++;

	GY_SCOPE_EXIT {
		if (psess) {
			psess->lastdir_ = hdr.dir_;
		}	
	};

	if (droptype == DROP_TYPES::DROP_SEEN) {
		// No reorder handling here...
		if ((sess.tfirstreq_ == 0) || (sess.tfirstresp_ == 0)) {
			sess.syn_seen_ = false;
		}

		sess.ndrops_++;

		sess.skip_to_req_after_resp_ = 1;
		sess.lastdir_ = hdr.dir_;

		return true;
	}	

	if (hdr.dir_ == DirPacket::DirInbound) {
			
		if (sess.skip_to_req_after_resp_) {
			if (sess.skip_to_req_after_resp_ == 2) {
				sess.skip_to_req_after_resp_ = 0;
				skipdone = true;
			}	
			else {
				return true;
			}	
		}

		if (sess.tfirstreq_ == 0) {

			if (sess.syn_seen_) {
				// Check if TLS encrypted
				if (hdr.src_ == SRC_UPROBE_SSL) {
					sess.ssl_init_req_ = true;
				}

				else if (true == tls_proto::is_tls_req_resp(pdata, hdr.datalen_, hdr.dir_, true /* is_init_msg */)) {
					sess.ssl_init_req_ = true;
					skip_parse = true;
				}	
			}	
			else if (skipdone == false) {
				sess.skip_to_req_after_resp_ = 1;
				return true;
			}	
			else if (true == tls_proto::is_tls_req_resp(pdata, hdr.datalen_, hdr.dir_, false /* is_init_msg */)) {
				sess.ssl_nreq_++;
				skip_parse = true;
			}	

			sess.tfirstreq_ = hdr.tv_.tv_sec;
		}
		else if (!sess.is_ssl_ && sess.ssl_nreq_ > 0) {
			if ((hdr.src_ == SRC_UPROBE_SSL) || (true == tls_proto::is_tls_req_resp(pdata, hdr.datalen_, hdr.dir_, false /* is_init_msg */))) {
				sess.ssl_nreq_++;

				if (sess.ssl_nresp_ > 1) {
					sess.is_ssl_ = true;
					detect.nssl_confirm_++;

					if (sess.syn_seen_) {
						detect.nssl_confirm_syn_++;
					}	

					if (detect.nssl_confirm_ > 3 || (detect.nssl_confirm_syn_ > 0 && detect.nssl_confirm_ > 1)) {
						schedule_ssl_probe();
					}	
				}

				if (hdr.src_ != SRC_UPROBE_SSL) {
					return true;
				}
			}	
		}	

		if (hdr.src_ == SRC_UPROBE_SSL) {
			sess.ssl_nreq_++;
		}
	}
	else {
		if (sess.skip_to_req_after_resp_) {
			sess.skip_to_req_after_resp_ = 2;
			return true;
		}

		if (sess.tfirstresp_ == 0) {

			if (sess.syn_seen_) {
				// Check if TLS encrypted
				if (hdr.src_ == SRC_UPROBE_SSL) {
					sess.ssl_init_resp_ = true;
					sess.is_ssl_ = true;
					detect.nssl_confirm_++;

					if (sess.syn_seen_) {
						detect.nssl_confirm_syn_++;
					}	

					if (detect.nssl_confirm_ > 3 || (detect.nssl_confirm_syn_ > 0 && detect.nssl_confirm_ > 1)) {
						schedule_ssl_probe();
					}	
				}
				else if (true == tls_proto::is_tls_req_resp(pdata, hdr.datalen_, hdr.dir_, true /* is_init_msg */)) {
					sess.ssl_init_resp_ = true;
					skip_parse = true;

					if (sess.ssl_init_req_) {
						sess.is_ssl_ = true;
						detect.nssl_confirm_++;
						
						if (sess.syn_seen_) {
							detect.nssl_confirm_syn_++;
						}	

						if (detect.nssl_confirm_ > 3 || (detect.nssl_confirm_syn_ > 0 && detect.nssl_confirm_ > 1)) {
							schedule_ssl_probe();
						}	
					}	
				}	
			}	
			else if (skipdone == false) {
				sess.skip_to_req_after_resp_ = 1;
				return true;
			}	
			else if (true == tls_proto::is_tls_req_resp(pdata, hdr.datalen_, hdr.dir_, false /* is_init_msg */)) {
				sess.ssl_nresp_++;
				skip_parse = true;
			}	

			sess.tfirstresp_ = hdr.tv_.tv_sec;
		}
		else if (!sess.is_ssl_ && (sess.ssl_nreq_ > 0 || sess.ssl_nresp_ > 0)) {
			if (hdr.src_ == SRC_UPROBE_SSL) {
				if (sess.ssl_nreq_ > 1) {
					sess.is_ssl_ = true;
					detect.nssl_confirm_++;

					if (sess.syn_seen_) {
						detect.nssl_confirm_syn_++;
					}	

					if (detect.nssl_confirm_ > 3 || (detect.nssl_confirm_syn_ > 0 && detect.nssl_confirm_ > 1)) {
						schedule_ssl_probe();
					}	
				}
			}
			else if (true == tls_proto::is_tls_req_resp(pdata, hdr.datalen_, hdr.dir_, false /* is_init_msg */)) {
				sess.ssl_nresp_++;

				if (sess.ssl_nreq_ > 1) {
					sess.is_ssl_ = true;
					detect.nssl_confirm_++;

					if (sess.syn_seen_) {
						detect.nssl_confirm_syn_++;
					}	

					if (detect.nssl_confirm_ > 3 || (detect.nssl_confirm_syn_ > 0 && detect.nssl_confirm_ > 1)) {
						schedule_ssl_probe();
					}	
					return true;
				}

				skip_parse = true;
			}	
			else {
				sess.ssl_nreq_ = 0;
				sess.ssl_nresp_ = 0;

				sess.skip_to_req_after_resp_ = 1;
				skip_parse = true;
			}	
		}	

		if (hdr.src_ == SRC_UPROBE_SSL) {
			sess.ssl_nresp_++;
		}
	}

	if (skip_parse) {
		return true;
	}	

	auto				& apistat = sess.apistat_;
	tribool				isvalid;

	if (apistat.proto_ != PROTO_UNINIT && apistat.proto_ < PROTO_UNKNOWN) {
		switch (apistat.proto_) {

		case PROTO_HTTP1 :
			if (hdr.dir_ == DirPacket::DirInbound) {
				isvalid	= http_proto::is_valid_req(pdata, hdr.datalen_, hdr.wirelen_);
			}
			else {
				isvalid = http_proto::is_valid_resp(pdata, hdr.datalen_);
			}
			break;

		case PROTO_HTTP2 :
			isvalid	= http2_proto::is_valid_req_resp(pdata, hdr.datalen_, hdr.wirelen_, hdr.dir_);

			break;
		
		case PROTO_POSTGRES :
			if (hdr.dir_ == DirPacket::DirInbound) {
				isvalid	= postgres_proto::is_valid_req(pdata, hdr.datalen_, hdr.wirelen_);
			}
			else {
				isvalid = postgres_proto::is_valid_resp(pdata, hdr.datalen_);
			}
			break;
			
		default :
			isvalid = false;
			break;
		}	

		if (isvalid != true) {
			if (indeterminate(isvalid)) {
				apistat.nmaybe_not_++;

				if (apistat.nmaybe_not_ > 5) {
					apistat.nis_not_++;
					apistat.nmaybe_not_ = 0;
				}
			}	
			else {
				apistat.nis_not_++;
			}	

			if (apistat.nis_not_ > 2) {
				if (apistat.nconfirm_ > 0) {
					for (int i = 0; i < (int)PROTO_DETECT::MAX_API_PROTO; ++i) {
						if (detect.apistats_[i].proto_ == apistat.proto_) {
							if (detect.apistats_[i].nconfirm_ > 0) {
								detect.apistats_[i].nconfirm_--;
							}

							break;
						}		
					}	
				}

				std::memset((void *)&apistat, 0, sizeof(apistat));
			}	
		}	
		else {
			if (apistat.nconfirm_ > 0) {
				if (apistat.nconfirm_ < 10) {
					apistat.nconfirm_++;
				}	
			}
			else {
				if (hdr.dir_ == DirPacket::DirInbound) {
					apistat.nreq_likely_++;

					if (apistat.nresp_likely_ > 0) {
						apistat.nconfirm_ = 1;
					}	
				}	
				else {
					apistat.nresp_likely_++;

					if (apistat.nreq_likely_ > 0) {
						apistat.nconfirm_ = 1;
					}
				}	

				if (apistat.nconfirm_ == 1) {
					int			i;

					for (i = 0; i < (int)PROTO_DETECT::MAX_API_PROTO; ++i) {
						if (detect.apistats_[i].proto_ == apistat.proto_) {
							if (detect.apistats_[i].nconfirm_ < 250) {
								detect.apistats_[i].nconfirm_++;
							}

							break;
						}		
					}	

					if (i == (int)PROTO_DETECT::MAX_API_PROTO) {
						for (i = 0; i < (int)PROTO_DETECT::MAX_API_PROTO; ++i) {
							if (detect.apistats_[i].proto_ == PROTO_UNINIT) {

								detect.apistats_[i].src_ = apistat.src_;
								detect.apistats_[i].proto_ = apistat.proto_;
								detect.apistats_[i].nconfirm_ = 1;
								break;
							}		
						}
					}	

					detect.nconfirm_++;

					if (sess.syn_seen_) {
						detect.nconfirm_with_syn_++;
					}	

					if (detect.nconfirm_ > 3 || (detect.nconfirm_ > 1 && detect.nconfirm_with_syn_)) {

						// Also schedule ssl probe for multiplexed proto
					}	
				}	
			}	

		}	
	}	
	else {
		if (true == tls_proto::is_tls_req_resp(pdata, hdr.datalen_, hdr.dir_, false /* is_init_msg */)) {
			if (hdr.dir_ == DirPacket::DirInbound) {
				sess.ssl_nreq_++;
			}
			else {
				sess.ssl_nresp_++;
			}

			return true;
		}	

		// TODO Check various proto

	}	
	


	return true;
}	

void SVC_INFO_CAP::analyze_detect_status()
{
	// TODO

}

void SVC_INFO_CAP::schedule_ssl_probe()
{
	if (ssl_req_.load(mo_relaxed) != SSL_REQ_E::SSL_NO_REQ) {
		return;
	}	

	auto				psvcnet = SVC_NET_CAPTURE::get_singleton();

	if (!psvcnet) {
		return;
	}	

	ssl_req_.store(SSL_REQ_E::SSL_REQUEST_SCHED, mo_relaxed);

	psvcnet->sched_svc_ssl_probe(gy_to_charbuf<256>("SSL Probe for Svc %s %lx", comm_, glob_id_).get(), svcweak_);
}	

bool API_PARSE_HDLR::handle_proto_pkt(MSG_PKT_SVCCAP & msg) noexcept
{
	try {
		auto				& puniq = msg.pooluniq_;

		if (!puniq) {
			return false;
		}	

		PARSE_PKT_HDR			*phdr = (PARSE_PKT_HDR *)puniq.get()->get();
		uint8_t				*pdata = (uint8_t *)(phdr + 1);
		
		if (phdr->datalen_ > MAX_PARSE_DATA_LEN) {
			return false;
		}

		uint64_t			glob_id = msg.glob_id_;
		SVC_INFO_CAP			*psvc = msg.psvc_;

		if (!psvc) {
			if (phdr->src_ == SRC_PCAP || glob_id != 0) {
				return false;
			}	

			auto			it = nsportmap_.find(NS_IP_PORT(phdr->serip_, phdr->serport_, phdr->netns_));

			if (it == nsportmap_.end() || !bool(it->second)) {
				return false;
			}	

			psvc = it->second.get();
			glob_id = psvc->glob_id_;
		}	

		if (gy_unlikely(psvc->stop_parser_tusec_.load(mo_relaxed) > 0)) {
			return false;
		}	

		psvc->stats_.update_pkt_stats(*phdr);

		if (gy_unlikely(bool(psvc->protodetect_))) {
			psvc->detect_svc_req_resp(*phdr, pdata);

			psvc->analyze_detect_status();
			return true;
		}	

		// Parse the packets...
		
		return true;
	}
	GY_CATCH_EXPRESSION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception Caught while handling API Parser packet : %s\n", GY_GET_EXCEPT_STRING););
		return false;
	);
}	

bool API_PARSE_HDLR::handle_svc_add(MSG_ADD_SVCCAP & msg) noexcept
{
	try {
		if (!msg.svcinfocap_) {
			return false;
		}	

		auto 				[it, success] = svcinfomap_.try_emplace(msg.glob_id_, std::move(msg.svcinfocap_));
		bool				isreorder = false;

		if (!success) {
			if (it->second) {
				isreorder = it->second->is_reorder_.load(mo_relaxed);
			}	
			it->second = std::move(msg.svcinfocap_);
		}	

		auto 				[it2, success2] = nsportmap_.try_emplace(it->second->ns_ip_port_, it->second);

		if (!success2) {
			it2->second = it->second;
		}	

		if (!success && isreorder) {
			reordermap_.erase(msg.glob_id_);
		}

		return true;
	}
	GY_CATCH_MSG("Exception Caught while handling API Parser Add Svc");

	return false;
}	

bool API_PARSE_HDLR::handle_svc_del(MSG_DEL_SVCCAP & msg) noexcept
{
	try {
		std::shared_ptr<SVC_INFO_CAP>	svcshr;

		auto 				it = svcinfomap_.find(msg.glob_id_);

		if (it != svcinfomap_.end()) {
			if (it->second) {
				svcshr = std::move(it->second);
				svcshr->stop_parser_tusec_.store(msg.tusec_, mo_relaxed);
			}	

			svcinfomap_.erase(it);
		}	

		reordermap_.erase(msg.glob_id_);

		if (svcshr) {
			nsportmap_.erase(svcshr->ns_ip_port_);
			
			// Deferred cleanup of SVC_INFO_CAP after a 2 sec interval to allow in-flight packets to be handled
			svcnet_.get_api_scheduler().add_oneshot_schedule(2000, gy_to_charbuf<256>("Deferred Svc Net Capture cleanup for Glob ID %lx", msg.glob_id_).get(),
				[svcshr = std::move(svcshr)]() mutable 
				{
					DEBUGEXECN(1, 
						INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Starting Deferred Clean up of Service API Capture object for %s Glob ID %lx\n", 
								svcshr->comm_, svcshr->glob_id_);
					);	
					svcshr.reset();
				});
		}

		return true;
	}
	GY_CATCH_MSG("Exception Caught while handling API Parser Del Svc");

	return false;
}	

bool API_PARSE_HDLR::handle_parse_timer(MSG_TIMER_SVCCAP & msg) noexcept
{
	try {

		return true;
	}
	GY_CATCH_MSG("Exception Caught while handling API Parser Timer");

	return false;
}	

bool API_PARSE_HDLR::handle_ssl_active(MSG_SVC_SSL_CAP & msg) noexcept
{
	try {
		auto				it = svcinfomap_.find(msg.glob_id_);

		if (it == svcinfomap_.end() || !it->second) {
			return false;
		}	
	
		it->second->ssl_req_.store(SSL_REQ_E::SSL_ACTIVE, mo_relaxed);

		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_LIGHT_GREEN, "SSL Probes active for Service %s ID %lx\n", it->second->comm_, it->second->glob_id_);

		return true;
	}
	catch(...) {
		return false;
	}	
}	

bool API_PARSE_HDLR::handle_ssl_rejected(MSG_SVC_SSL_CAP & msg) noexcept
{
	try {
		auto				it = svcinfomap_.find(msg.glob_id_);

		if (it == svcinfomap_.end() || !it->second) {
			return false;
		}	
	
		it->second->ssl_req_.store(SSL_REQ_E::SSL_REJECTED, mo_relaxed);

		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "SSL Probes disabled for Service %s ID %lx\n", it->second->comm_, it->second->glob_id_);
		
		// TODO send notification to madhava

		return true;
	}
	catch(...) {
		return false;
	}	
}	


bool API_PARSE_HDLR::handle_parse_no_msg() noexcept
{
	try {

		return true;
	}
	GY_CATCH_MSG("Exception Caught while handling API Parser No Msg");

	return false;
}	


} // namespace gyeeta

