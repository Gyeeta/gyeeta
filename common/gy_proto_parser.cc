//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_proto_parser.h"
#include			"gy_socket_stat.h"
#include			"gy_net_parse.h"
#include			"gy_pkt_reorder.h"

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

void SVC_INFO_CAP::lazy_init() noexcept
{
	try {
		bool				nossl = false;

		if (orig_proto_ != PROTO_UNINIT && orig_proto_ < PROTO_UNKNOWN) {

			nossl = !orig_ssl_;
			proto_ = orig_proto_;

			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Service API Network Capture for svc '%s\' port %hu set as %s with SSL Capture %s as per prior stats\n",
				comm_, ns_ip_port_.ip_port_.port_, proto_to_string(proto_), nossl ? "disabled" : "enabled");	
		}
		else {
			protodetect_ = std::make_unique<PROTO_DETECT>();
		}	

		if (nossl == false) {
			// TODO 
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

			if (phdr->dir_ == DirPacket::DIR_INBOUND) {
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
	
	if (hdr.dir_ == DirPacket::DIR_INBOUND) {
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

bool SVC_INFO_CAP::detect_svc_req(PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	IP_PORT				ipport(hdr.cliip_, hdr.cliport_);
	auto				& detect = *protodetect_.get();
	bool				is_syn = hdr.tcpflags_ & GY_TH_SYN, is_finrst = hdr.tcpflags_ & (GY_TH_FIN | GY_TH_RST);
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

	if (is_finrst) {
delsess :		
		if (sess.syn_seen_) {
			detect.nsynsess_--;
		}
		else {
			detect.nmidsess_--;
		}	

		detect.smap_.erase(it);
		return true;
	}	

	if (hdr.datalen_ == 0) {
		return true;
	}
	

	if (hdr.dir_ == DirPacket::DIR_INBOUND) {
		droptype = is_tcp_drop(sess.nxt_cli_seq_, hdr.start_cli_seq_, is_syn, sess.nxt_ser_seq_, hdr.start_ser_seq_);
	}
	else {
		droptype = is_tcp_drop(sess.nxt_ser_seq_, hdr.start_ser_seq_, is_syn, sess.nxt_cli_seq_, hdr.start_cli_seq_);
	}	

	if (droptype == DROP_TYPES::DROP_NEW_SESS) {
		goto delsess;
	}	

	if (droptype == DROP_TYPES::RETRANSMIT) {
		return false;
	}

	if (droptype == DROP_TYPES::DROP_SEEN) {
		sess.ndrops_++;
	}	

	sess.nxt_cli_seq_	= hdr.nxt_cli_seq_;
	sess.nxt_ser_seq_	= hdr.nxt_ser_seq_;
	sess.npkts_data_++;


	if (hdr.dir_ == DirPacket::DIR_INBOUND) {
		if (sess.tfirstreq_ == 0) {
			sess.tfirstreq_ = hdr.tv_.tv_sec;
		}
	
		for (int i = 0; i < PROTO_DETECT::MAX_API_PROTO; ++i) {
			auto			& apislot = detect.apistats_[i];

			if (apislot.proto_ != PROTO_UNINIT && apislot.proto_ < PROTO_UNKNOWN) {
				switch (apislot.proto_) {


				}	
			}	
		}	
	}
	else {

	}

	return true;
}	

bool SVC_INFO_CAP::detect_svc_resp(PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	IP_PORT				ipport(hdr.cliip_, hdr.cliport_);
	auto				& detect = *protodetect_.get();

	return true;
}

bool API_PARSE_HDLR::handle_proto_pkt(MSG_PKT_SVCCAP & msg) noexcept
{
	try {
		SVC_INFO_CAP			*psvc = msg.psvc_;
		uint64_t			glob_id = msg.glob_id_;
		auto				& puniq = msg.pooluniq_;

		if (!psvc || !puniq) {
			return false;
		}	

		PARSE_PKT_HDR			*phdr = (PARSE_PKT_HDR *)puniq.get()->get();
		uint8_t				*pdata = (uint8_t *)(phdr + 1);
		
		if (phdr->datalen_ > MAX_PARSE_DATA_LEN) {
			return false;
		}

		psvc->stats_.update_pkt_stats(*phdr);

		if (gy_unlikely(bool(psvc->protodetect_))) {

			if (phdr->dir_ == DirPacket::DIR_INBOUND) {
				return psvc->detect_svc_req(*phdr, pdata);
			}
			else {
				return psvc->detect_svc_resp(*phdr, pdata);
			}	
		}	

		
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

		SCOPE_GY_MUTEX			slock(svcmutex_);

		auto 				[it, success] = svcinfomap_.try_emplace(msg.glob_id_, std::move(msg.svcinfocap_));
		bool				isreorder = false;

		if (!success) {
			if (it->second) {
				isreorder = it->second->is_reorder_.load(mo_relaxed);
			}	
			it->second = std::move(msg.svcinfocap_);
		}	

		slock.unlock();

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
		SCOPE_GY_MUTEX			slock(svcmutex_);

		auto 				it = svcinfomap_.find(msg.glob_id_);
		bool				isreorder = false;

		if (it != svcinfomap_.end()) {
			if (it->second) {
				isreorder = it->second->is_reorder_.load(mo_relaxed);
			}	

			svcinfomap_.erase(it);
		}	

		slock.unlock();

		if (isreorder && it != svcinfomap_.end()) {
			reordermap_.erase(msg.glob_id_);
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

bool API_PARSE_HDLR::handle_parse_no_msg() noexcept
{
	try {

		return true;
	}
	GY_CATCH_MSG("Exception Caught while handling API Parser No Msg");

	return false;
}	


	
} // namespace gyeeta

