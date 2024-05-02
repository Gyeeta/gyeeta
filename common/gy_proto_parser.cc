//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_proto_parser.h"
#include			"gy_socket_stat.h"
#include			"gy_net_parse.h"
#include			"gy_task_types.h"
#include			"gy_tls_proto.h"
#include			"gy_proto_common.h"
#include			"gy_http_proto_detail.h"
#include			"gy_http2_proto_detail.h"
#include			"gy_postgres_proto_detail.h"
#include			"gy_pcap_write.h"
#include			"gy_server_int.h"

namespace gyeeta {

POOL_ALLOC					*REORDER_PKT_HDR::greorderpools_[MAX_API_PARSERS] = {};		
std::optional<API_PARSE_HDLR::TranMsgPool>	API_PARSE_HDLR::gtranpool_;
std::optional<GY_THREAD>			API_PARSE_HDLR::gtran_thr_;

// Uncomment this to enable API Records print to file
/*#define				GY_API_PRINT	"/tmp/gy_api_records___.txt"*/

// Uncomment this to enable pcap packet writes
/*#define					GY_TEST_PCAPWRITE*/

// Uncomment this to test the reorder handling (will also enable GY_TEST_PCAPWRITE)
/*#define				GY_TEST_REORDER_PKTS	10*/

#ifdef GY_TEST_REORDER_PKTS

// Enable GY_TEST_PCAPWRITE if GY_TEST_PCAPWRITE set
#ifndef 				GY_TEST_PCAPWRITE
#define 				GY_TEST_PCAPWRITE
#endif

class TestRdr
{
public :	
	struct TestRdrData
	{
		SVC_INFO_CAP			*psvc_		{nullptr};
		ParserMemPool::UniquePtr	puniq_;
		PARSE_PKT_HDR			hdr_;
		uint8_t				*pdata_		{nullptr};

		TestRdrData(SVC_INFO_CAP *psvc, ParserMemPool::UniquePtr & puniq, PARSE_PKT_HDR & hdr, uint8_t *pdata)
			: psvc_(psvc), puniq_(std::move(puniq)), hdr_(hdr), pdata_(pdata)
		{}

		TestRdrData() noexcept		= default;
	};	

	enum RdrType : uint8_t
	{
		RdrNone				= 0,
		RdrRandom,
		RdrReverse,
		RdrBlock,
		RdrDirBlock,

		RdrMax,
	};	

	static constexpr uint32_t		MAX_RDR_BLOCK		{static_cast<uint32_t>(GY_TEST_REORDER_PKTS)};

	std::list<TestRdrData>			list_;
	RdrType					currtype_		{RdrNone};

	bool do_rdr_test(SVC_INFO_CAP *psvc, ParserMemPool::UniquePtr & puniq, PARSE_PKT_HDR & hdr, uint8_t *pdata)
	{
		switch (currtype_) {
			
		case RdrNone :
			list_.emplace_back(psvc, puniq, hdr, pdata);

			if (list_.size() >= MAX_RDR_BLOCK) {
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Reorder Test : Flushing no Reorder packets %lu : Next Reorder Test is Random Reorders...\n", list_.size());

				flush();
			}	

			return true;

		case RdrRandom :

			if (list_.size() > 1) {
				TestRdrData			data(psvc, puniq, hdr, pdata);
				uint32_t			n = 0, nrand = std::rand() % list_.size();
				bool				ok = false;

				for (auto it = list_.begin(); it != list_.end(); ++it) {
					if (n++ == nrand) {
						list_.insert(it, std::move(data));
						ok = true;
						break;
					}	
				}	

				if (!ok) {
					list_.push_back(std::move(data));
				}	

				if (list_.size() >= MAX_RDR_BLOCK) {
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Reorder Test : Flushing Random Reorder packets %lu : Next Reorder Test is Reverse Reorders...\n", list_.size());
					
					flush();
				}	
			}
			else {
				list_.emplace_back(psvc, puniq, hdr, pdata);
			}	

			return true;

		case RdrReverse :

			list_.emplace_back(psvc, puniq, hdr, pdata);

			if (list_.size() >= MAX_RDR_BLOCK) {
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Reorder Test : Flushing Random Reorder packets %lu : Next Reorder Test is Block Reorders...\n", list_.size());

				list_.reverse();
				flush();
			}	

			return true;


		case RdrBlock :

			if (list_.size() < MAX_RDR_BLOCK * 2) {
				list_.emplace_back(psvc, puniq, hdr, pdata);

				if (list_.size() == MAX_RDR_BLOCK * 2) {
					std::list<TestRdrData>		list2;
					auto 				it = list_.begin();

					std::advance(it, MAX_RDR_BLOCK);

					list2.splice(list2.begin(), list_, it, list_.end());

					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Reorder Test : Flushing Block Reorder packets : Next Reorder Test is Dir specific Block Reorders...\n");
					
					for (; !list2.empty(); list2.pop_front()) {
						auto			& elem = list2.front();

						elem.psvc_->parse_pkt(elem.puniq_, elem.hdr_, elem.pdata_);
					}	
					
					flush();
				}	
			}	

			return true;

		case RdrDirBlock :

			if (list_.size() < MAX_RDR_BLOCK * 2) {
				list_.emplace_back(psvc, puniq, hdr, pdata);

				if (list_.size() == MAX_RDR_BLOCK * 2) {
					std::list<TestRdrData>		list2;
					auto 				it = list_.begin();

					for (auto it = list_.begin(); it != list_.end(); ) {
						auto			& data = *it;

						if (data.hdr_.dir_ == DirPacket::DirOutbound) {
							list2.push_back(std::move(data));
							
							it = list_.erase(it);
						}	
						else {
							++it;
						}	
					}	

					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Reorder Test : Flushing Dir specific Block Reorder packets : Next Reorder Test is No Reorders...\n");

					// Send Outbound first
					for (; !list2.empty(); list2.pop_front()) {
						auto			& elem = list2.front();

						elem.psvc_->parse_pkt(elem.puniq_, elem.hdr_, elem.pdata_);
					}	
					
					flush();
				}	
			}	

			return true;

		default :
			return false;
			
		}	
	}	

	void flush()
	{
		for (; !list_.empty(); list_.pop_front()) {
			auto			& elem = list_.front();

			elem.psvc_->parse_pkt(elem.puniq_, elem.hdr_, elem.pdata_);
		}	

		currtype_ = RdrType(int(currtype_) + 1);

		if (currtype_ == RdrMax) {
			currtype_ = RdrNone;
		}	
	}	
};

static TestRdr				gtestrdr[MAX_API_PARSERS];		

static bool test_reorders(uint8_t parseridx, SVC_INFO_CAP *psvc, ParserMemPool::UniquePtr & puniq, PARSE_PKT_HDR & hdr, uint8_t *pdata)
{

	if (parseridx < MAX_API_PARSERS) {
		return gtestrdr[parseridx].do_rdr_test(psvc, puniq, hdr, pdata);
	}

	return false;
}	

#endif /* GY_TEST_REORDER_PKTS */

#ifdef GY_TEST_PCAPWRITE

static GY_PCAP_WRITER			gpcapwr("/tmp/test_rdr_gyeeta.pcap", true /* use_unlocked_io */, false /* throw_if_exists */, GY_UP_GB(1));

#endif



API_PARSE_HDLR::API_PARSE_HDLR(SVC_NET_CAPTURE & svcnet, uint8_t parseridx, uint32_t api_max_len)
		: reqbuffer_(API_TRAN::get_max_elem_size(api_max_len), API_TRAN::MAX_NUM_REQS, 32, API_TRAN::MAX_NUM_REQS/2, 
				sizeof(comm::COMM_HEADER) + sizeof(comm::EVENT_NOTIFY), false, API_TRAN::MAX_SEND_SZ), 
		svcnet_(svcnet), api_max_len_(api_max_len), parseridx_(parseridx)
{
	if (api_max_len_ > MAX_PARSE_API_LEN) {
		GY_THROW_EXPRESSION("API Parser Initialiation : Invalid Max API Capture Length specified %u : Max allowed is %u", api_max_len_, MAX_PARSE_API_LEN);
	}	

	static_assert(MAX_API_PARSERS <= 4, "Please limit to max 4");

	if (parseridx < MAX_API_PARSERS) {
		REORDER_PKT_HDR::greorderpools_[parseridx] = &reorderpool_;

		phttp1_.reset(new HTTP1_PROTO(*this, api_max_len_));
		phttp2_.reset(new HTTP2_PROTO(*this, api_max_len_));
		ppostgres_.reset(new POSTGRES_PROTO(*this, api_max_len_));
	}	
	else {	
		GY_THROW_EXPRESSION("API Parser Initialiation : Invalid Parser Index id specified %hhu : Max allowed is %lu", parseridx, MAX_API_PARSERS);
	}	

	if (parseridx == 0) {
		gtranpool_.emplace(MAX_TRAN_STR_ELEM);
		gtran_thr_.emplace("API Tranfer Thread", API_PARSE_HDLR::GET_PTHREAD_WRAPPER(api_xfer_thread), nullptr, nullptr, nullptr, true /* start_immed */, GY_UP_MB(1));
	}
}	

API_PARSE_HDLR::~API_PARSE_HDLR() noexcept		= default;

/*
 * Called by the SVC_NET_CAPTURE::schedthr_ only
 */
SVC_INFO_CAP::SVC_INFO_CAP(const std::shared_ptr<TCP_LISTENER> & listenshr, API_PARSE_HDLR & apihdlr)
	: apihdlr_(apihdlr), 
	svcweak_(
	({
		if (!listenshr) {
			GY_THROW_EXCEPTION("Invalid Listen Shared Pointer for API Capture");
		}	
		listenshr;

	})), glob_id_(listenshr->glob_id_), ns_ip_port_(listenshr->ns_ip_port_),
	is_any_ip_(listenshr->is_any_ip_), is_root_netns_(listenshr->is_root_netns_)
{
	GY_STRNCPY(comm_, listenshr->comm_, sizeof(comm_));

	orig_proto_ = listenshr->api_proto_.load(mo_acquire);

	if (orig_proto_ != PROTO_UNINIT && orig_proto_ < PROTO_INVALID) {
		if (true == listenshr->api_is_ssl_.load(mo_relaxed)) {
			orig_ssl_ = true;
		}
		else {
			orig_ssl_ = false;
		}	
		listenshr->api_cap_started_.store(CAPSTAT_ACTIVE, std::memory_order_release);
	}

	auto				psvcnet = SVC_NET_CAPTURE::get_singleton();

	if (!psvcnet) {
		return;
	}	

	svc_init_blocking(*psvcnet);
}	

SVC_INFO_CAP::~SVC_INFO_CAP() noexcept
{
	schedule_ssl_stop();

	proto_ = PROTO_INVALID;
}

void SVC_INFO_CAP::destroy(uint64_t tusec) noexcept
{
	try {
		stopped_parser_tusec_.store(tusec, mo_relaxed);

		svcweak_.reset();
		sessmap_.clear();
		sessrdrmap_.clear();
		protodetect_.reset();

		schedule_ssl_stop();

		proto_ = PROTO_INVALID;
	}
	catch(...) {
	
	}
}

// Called from constructor
void SVC_INFO_CAP::svc_init_blocking(SVC_NET_CAPTURE & svcnet) noexcept
{
	try {
		tribool				isssl = indeterminate;

		auto				listenshr = svcweak_.lock();

		if (!listenshr) {
			return;
		}	

		SCOPE_GY_MUTEX			slock(listenshr->svcweak_lock_);

		listenshr->api_svcweak_ = weak_from_this();

		slock.unlock();

		if (proto_ == PROTO_UNINIT) {
			if (orig_proto_ != PROTO_UNINIT && orig_proto_ < PROTO_INVALID) {

				isssl = orig_ssl_;
				proto_ = orig_proto_;

				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Service API Network Capture for svc '%s\' port %hu set as %s with SSL Capture %s as per prior stats\n",
					comm_, ns_ip_port_.ip_port_.port_, proto_to_string(proto_), isssl == true ? "enabled" : "disabled");	

				listenshr->api_cap_started_.store(CAPSTAT_ACTIVE, std::memory_order_release);
			}
			else {
				protodetect_ = std::make_unique<PROTO_DETECT>();
			}	
		}

		if (svc_ssl_ == SSL_SVC_E::SSL_UNINIT && indeterminate(isssl)) {
			isssl =  typeinfo::ssl_enabled_listener(ns_ip_port_.ip_port_.port_, listenshr->comm_, listenshr->cmdline_);
		}

		if (isssl == true) {
			schedule_ssl_probe();
		}	
	}
	GY_CATCH_EXPRESSION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception seen : Failed to lazy init API Capture for svc %s port %hu : %s\n",
				comm_, ns_ip_port_.ip_port_.port_, GY_GET_EXCEPT_STRING);
	);
}	

/*
 * Called from capture and probe threads...
 */
bool API_PARSE_HDLR::send_pkt_to_parser(const PARSE_PKT_HDR & msghdr, const uint8_t *pdata, const uint32_t len, SVC_INFO_CAP *psvccap, uint64_t glob_id)
{
	if (0 == len && (0 == (msghdr.tcpflags_ & (GY_TH_SYN | GY_TH_FIN | GY_TH_RST)))) {	// Ignore ACKs
		return true;
	}	

	uint32_t			nbytesdone = 0, nbytes;	
	uint8_t				*pdest, *pdestend, *ptmp, *pfragstart, *pfragend;
	const uint8_t			*psrcstart, *psrc_act_end = pdata + len;
	bool				bret = false;

	uint32_t			nfrag = gy_div_round_up(len, MAX_PARSE_FRAG_LEN);

	if (nfrag == 0) {
		nfrag = 1;
	}	
	
	for (uint32_t i = 0; i < nfrag && nbytesdone <= len; ++i) {
		auto				puniq = parsepool_.allocElem();

		if (!puniq) {
			stats_.nskip_pool_.fetch_add_relaxed(1);

			return false;
		}	

		pfragstart 			= puniq.get()->get();
		PARSE_PKT_HDR			*phdr = (PARSE_PKT_HDR *)pfragstart;	

		nbytes				= std::min(len - nbytesdone, MAX_PARSE_FRAG_LEN);

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
		for (int ntries = 0; ;) {
			bret = msgpool_.write(PARSE_MSG_BUF(std::in_place_type<MSG_PKT_SVCCAP>, psvccap, glob_id, std::move(puniq)));

			if (bret == true) {
				break;
			}
			else {
				if (++ntries >= 3) {
					stats_.nskip_pool_.fetch_add_relaxed(1);
					return false;
				}

				sched_yield();
			}	
		}	
	}	

	return true;
}	

void PROTO_DETECT::cleanup_inactive_sess(time_t tcur) noexcept
{
	time_t				tmin = tcur - 300;
	int				ntime = 0, ndel = 0;

	tlast_inactive_sec_		= tcur;

	for (auto oit = smap_.begin(); oit != smap_.end();) {
		auto				it = oit++;
		auto				& sess = it->second;

		if (sess.tlastpkt_ < tmin && sess.apistat_.nconfirm_ == 0) {
			if (sess.apistat_.proto_ == PROTO_UNINIT) {
				smap_.erase(it);
				ndel++;
				continue;
			}

			ntime++;
		}
	}

	if (ndel < 3 && ntime > 10) {
		for (auto oit = smap_.begin(); oit != smap_.end();) {
			auto				it = oit++;
			auto				& sess = it->second;

			if (sess.tlastpkt_ < tmin && sess.apistat_.nconfirm_ == 0) {
				smap_.erase(it);
				ndel++;
				continue;
			}
		}
	}	
}

bool SVC_INFO_CAP::detect_svc_req_resp(PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	auto				& detect = *protodetect_.get();

	IP_PORT				ipport(hdr.cliip_, hdr.cliport_);
	PROTO_DETECT::SessInfo		*psess = nullptr;
	bool				is_syn = hdr.tcpflags_ & GY_TH_SYN, is_finrst = hdr.tcpflags_ & (GY_TH_FIN | GY_TH_RST), skip_parse = false, skipdone = false;
	bool				new_sess = false, is_init = false;
	DROP_TYPES			droptype, droptypeack;

	auto				it = detect.smap_.find(ipport);
	
	if (it == detect.smap_.end()) {
		if (is_finrst) {
			return false;
		}	
		if (hdr.datalen_ == 0) {
			if (!is_syn) {
				return false;
			}	
			if (hdr.start_cli_seq_ > 0 && hdr.nxt_ser_seq_ == 0) {
				return false;
			}	
		}	

		if (detect.smap_.size() >= detect.MaxSessEntries/2 && detect.tlast_inactive_sec_ < hdr.tv_.tv_sec - 100) {
			detect.cleanup_inactive_sess(hdr.tv_.tv_sec);
		}	

		if (detect.smap_.size() < detect.MaxSessEntries) {
			if (!is_syn) {
				if (detect.nmidsess_ >= detect.MaxSessEntries/2) {
					return false;
				}	
			}	

			it = detect.smap_.try_emplace(ipport, hdr.tv_.tv_sec, detect,
						hdr.datalen_ == 0 ? hdr.nxt_cli_seq_ : hdr.start_cli_seq_, hdr.datalen_ == 0 ? hdr.nxt_ser_seq_ : hdr.start_ser_seq_, is_syn).first;
			
			new_sess = true;
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

	if (hdr.src_ == SRC_UPROBE_SSL && !sess.is_ssl_) {
		sess.is_ssl_ = true;
		sess.lastdir_ = DirPacket::DirUnknown;
		detect.nssl_confirm_++;

		if (sess.syn_seen_) {
			detect.nssl_confirm_syn_++;
		}	

		if (!is_syn) {
			sess.PROTO_DETECT::SessInfo::~SessInfo();

			new (&sess) PROTO_DETECT::SessInfo(hdr.tv_.tv_sec, detect,
						hdr.datalen_ == 0 ? hdr.nxt_cli_seq_ : hdr.start_cli_seq_, hdr.datalen_ == 0 ? hdr.nxt_ser_seq_ : hdr.start_ser_seq_, is_syn);

			sess.is_ssl_ = true;
			sess.lastdir_ = DirPacket::DirUnknown;
		}	
	}	
	
	if (hdr.datalen_ == 0) {
		if (is_syn && !new_sess) {
			sess.PROTO_DETECT::SessInfo::~SessInfo();

			new (&sess) PROTO_DETECT::SessInfo(hdr.tv_.tv_sec, detect,
						hdr.datalen_ == 0 ? hdr.nxt_cli_seq_ : hdr.start_cli_seq_, hdr.datalen_ == 0 ? hdr.nxt_ser_seq_ : hdr.start_ser_seq_, is_syn);
		}

		return true;
	}
	
	if (hdr.dir_ == DirPacket::DirInbound) {
		auto p = is_tcp_drop(sess.nxt_cli_seq_, hdr.start_cli_seq_, sess.nxt_ser_seq_, hdr.start_ser_seq_, is_syn, hdr.tcpflags_ & GY_TH_FIN);

		droptype 	= p.first;
		droptypeack 	= p.second;

		if (detect.tfirstreq_ == 0) {
			detect.tfirstreq_ = hdr.tv_.tv_sec;
		}	
	}
	else {
		auto p = is_tcp_drop(sess.nxt_ser_seq_, hdr.start_ser_seq_, sess.nxt_cli_seq_, hdr.start_cli_seq_, is_syn, hdr.tcpflags_ & GY_TH_FIN);

		droptype 	= p.first;
		droptypeack 	= p.second;

		if (detect.tfirstresp_ == 0) {
			detect.tfirstresp_ = hdr.tv_.tv_sec;
		}	
	}	

	if (droptype == DT_DROP_NEW_SESS) {
		delsess();
		return false;
	}	

	if (droptype == DT_RETRANSMIT) {
		return false;
	}

	sess.tlastpkt_		= hdr.tv_.tv_sec;
	sess.nxt_cli_seq_	= hdr.nxt_cli_seq_;
	sess.nxt_ser_seq_	= hdr.nxt_ser_seq_;
	sess.npkts_data_++;

	GY_SCOPE_EXIT {
		if (psess) {
			psess->lastdir_ = hdr.dir_;
		}	
	};

	if (droptype == DT_DROP_SEEN) {
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
				sess.init_skipped_ = true;
				skipdone = true;
			}	
			else {
				return true;
			}	
		}

		if (sess.lastdir_ == DirPacket::DirInbound) {
			return false;
		}

		if (sess.tfirstreq_ == 0) {

			if (sess.syn_seen_) {
				is_init = true;

				// Check if TLS encrypted
				if (hdr.src_ == SRC_UPROBE_SSL) {
					sess.ssl_init_req_ = true;
				}
				else if (true == TLS_PROTO::is_tls_req_resp(pdata, hdr.datalen_, hdr.dir_, true /* is_init */)) {
					sess.ssl_init_req_ = true;
					skip_parse = true;
				}	
			}	
			else if (skipdone == false && !sess.init_skipped_) {
				if (hdr.src_ == SRC_PCAP) {
					sess.skip_to_req_after_resp_ = 1;
					return true;
				}
			}	
			else if (true == TLS_PROTO::is_tls_req_resp(pdata, hdr.datalen_, hdr.dir_, false /* is_init */)) {
				sess.ssl_nreq_++;
				skip_parse = true;
			}	

			sess.tfirstreq_ = hdr.tv_.tv_sec;
		}
		else if (!sess.is_ssl_ && sess.ssl_nreq_ > 0) {
			if ((hdr.src_ == SRC_UPROBE_SSL) || (true == TLS_PROTO::is_tls_req_resp(pdata, hdr.datalen_, hdr.dir_, false /* is_init */))) {
				sess.ssl_nreq_++;

				if (sess.ssl_nresp_ > 1) {
					sess.is_ssl_ = true;
					sess.lastdir_ = DirPacket::DirUnknown;
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
		if (sess.lastdir_ == DirPacket::DirOutbound) {
			return false;
		}

		if (sess.skip_to_req_after_resp_) {
			sess.skip_to_req_after_resp_ = 2;
			return true;
		}

		if (sess.tfirstresp_ == 0) {

			if (sess.syn_seen_) {
				is_init = true;

				// Check if TLS encrypted
				if (hdr.src_ == SRC_UPROBE_SSL) {
					sess.ssl_init_resp_ = true;
					sess.is_ssl_ = true;
					sess.lastdir_ = DirPacket::DirUnknown;
					detect.nssl_confirm_++;

					if (sess.syn_seen_) {
						detect.nssl_confirm_syn_++;
					}	

					if (detect.nssl_confirm_ > 3 || (detect.nssl_confirm_syn_ > 0 && detect.nssl_confirm_ > 1)) {
						schedule_ssl_probe();
					}	
				}
				else if (true == TLS_PROTO::is_tls_req_resp(pdata, hdr.datalen_, hdr.dir_, true /* is_init */)) {
					sess.ssl_init_resp_ = true;
					skip_parse = true;

					if (sess.ssl_init_req_) {
						sess.is_ssl_ = true;
						sess.lastdir_ = DirPacket::DirUnknown;
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
			else if (skipdone == false && !sess.init_skipped_) {
				sess.skip_to_req_after_resp_ = 1;
				return true;
			}	
			else if (true == TLS_PROTO::is_tls_req_resp(pdata, hdr.datalen_, hdr.dir_, false /* is_init */)) {
				sess.ssl_nresp_++;
				skip_parse = true;
			}	

			sess.tfirstresp_ = hdr.tv_.tv_sec;
		}
		else if (!sess.is_ssl_ && (sess.ssl_nreq_ > 0 || sess.ssl_nresp_ > 0)) {
			if (hdr.src_ == SRC_UPROBE_SSL) {
				if (sess.ssl_nreq_ > 1) {
					sess.is_ssl_ = true;
					sess.lastdir_ = DirPacket::DirUnknown;
					detect.nssl_confirm_++;

					if (sess.syn_seen_) {
						detect.nssl_confirm_syn_++;
					}	

					if (detect.nssl_confirm_ > 3 || (detect.nssl_confirm_syn_ > 0 && detect.nssl_confirm_ > 1)) {
						schedule_ssl_probe();
					}	
				}
			}
			else if (true == TLS_PROTO::is_tls_req_resp(pdata, hdr.datalen_, hdr.dir_, false /* is_init */)) {
				sess.ssl_nresp_++;

				if (sess.ssl_nreq_ > 1) {
					sess.is_ssl_ = true;
					sess.lastdir_ = DirPacket::DirUnknown;
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

	if (apistat.proto_ != PROTO_UNINIT && apistat.proto_ < PROTO_INVALID) {
		switch (apistat.proto_) {

		case PROTO_HTTP1 :
			isvalid	= HTTP1_PROTO::is_valid_req_resp(pdata, hdr.datalen_, hdr.wirelen_, hdr.dir_, is_init);

			break;

		case PROTO_HTTP2 :
			isvalid	= HTTP2_PROTO::is_valid_req_resp(pdata, hdr.datalen_, hdr.wirelen_, hdr.dir_, is_init);

			break;
		
		case PROTO_POSTGRES :
			isvalid	= POSTGRES_PROTO::is_valid_req_resp(pdata, hdr.datalen_, hdr.wirelen_, hdr.dir_, is_init);

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

			if (apistat.nis_not_ > 2 && apistat.nconfirm_ < 5) {
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

				apistat = {};
			}	
			else {
				return true;
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
				}	
			}	

			return true;
		}	
	}	

	if (true == TLS_PROTO::is_tls_req_resp(pdata, hdr.datalen_, hdr.dir_, is_init)) {
		if (hdr.dir_ == DirPacket::DirInbound) {
			sess.ssl_nreq_++;
		}
		else {
			sess.ssl_nresp_++;
		}

		return true;
	}	

	const auto init_apistat = [&](PROTO_TYPES proto)
	{
		apistat = {};

		apistat.npkts_++;

		if (hdr.dir_ == DirPacket::DirInbound) {
			apistat.nreq_likely_++;
		}	
		else {
			apistat.nresp_likely_++;
		}	

		apistat.src_ = hdr.src_;
		apistat.proto_ = proto;
	};	

	isvalid	= HTTP1_PROTO::is_valid_req_resp(pdata, hdr.datalen_, hdr.wirelen_, hdr.dir_, is_init);

	if (true == isvalid) {
		init_apistat(PROTO_HTTP1);

		return true;
	}	

	isvalid	= HTTP2_PROTO::is_valid_req_resp(pdata, hdr.datalen_, hdr.wirelen_, hdr.dir_, is_init);
		
	if (true == isvalid) {
		init_apistat(PROTO_HTTP2);

		return true;
	}

	if (!is_init || hdr.dir_ == DirPacket::DirInbound) {
		// Postgres Init Outbound ignored for detection
		isvalid	= POSTGRES_PROTO::is_valid_req_resp(pdata, hdr.datalen_, hdr.wirelen_, hdr.dir_, is_init);
			
		if (true == isvalid) {
			init_apistat(PROTO_POSTGRES);

			return true;
		}
	}

	return true;
}	

void SVC_INFO_CAP::analyze_detect_status()
{
	if (!protodetect_) return;

	auto				& detect = *protodetect_.get();
	auto				& tstats = stats_;

	if (detect.nconfirm_ > 3 || (detect.nconfirm_ > 1 && detect.nconfirm_with_syn_)) {
		auto				sslreq = ssl_req_.load(mo_relaxed);
		auto				svcshr = svcweak_.lock();

		if (!svcshr) {
			protodetect_.reset();
			return;
		}	

		// Also schedule ssl probe for multiplexed proto
		for (int i = 0; i < (int)PROTO_DETECT::MAX_API_PROTO; ++i) {
			auto			& apistat = detect.apistats_[i];

			if (apistat.nconfirm_ > 1 && apistat.proto_ > PROTO_UNINIT && apistat.proto_ < PROTO_INVALID) {
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Service API Capture : Service Protocol Detected as \'%s\' for Listener %s Port %hu ID %lx : "
							"SSL Capture is currently %sactive\n", proto_to_string(apistat.proto_), comm_, ns_ip_port_.ip_port_.port_,
							glob_id_, sslreq == SSL_REQ_E::SSL_ACTIVE ? "" : "not ");

				if (sslreq == SSL_REQ_E::SSL_ACTIVE) {
					svcshr->api_is_ssl_.store(true, mo_relaxed);

					if (true == ssl_multiplexed_proto(apistat.proto_)) {
						svc_ssl_ = SSL_SVC_E::SSL_MULTIPLEXED;
					}
					else if (detect.nssl_confirm_ > 0) {
						svc_ssl_ = SSL_SVC_E::SSL_ONLY;
					}
				}
				else if (sslreq == SSL_REQ_E::SSL_REJECTED) {
					svcshr->api_is_ssl_.store(false, mo_relaxed);
					svc_ssl_ = SSL_SVC_E::SSL_NO;
				}	
				else {
					svcshr->api_is_ssl_.store(indeterminate, mo_relaxed);

					if (true == ssl_multiplexed_proto(apistat.proto_)) {
						svc_ssl_ = SSL_SVC_E::SSL_MULTIPLEXED;
						
						if  (sslreq == SSL_REQ_E::SSL_NO_REQ) {
							schedule_ssl_probe();
						}
					}
					else if (detect.nssl_confirm_syn_ > 0 && detect.nssl_confirm_ > 0) {
						svc_ssl_ = SSL_SVC_E::SSL_ONLY;
					}	
					else {
						svc_ssl_ = SSL_SVC_E::SSL_NO;
					}	
				}	

				svcshr->api_proto_.store(apistat.proto_, mo_relaxed);
				svcshr->api_cap_started_.store(CAPSTAT_ACTIVE, mo_relaxed);

				proto_ = apistat.proto_;

				std::atomic_thread_fence(std::memory_order_release);

				// detect/apistat no longer valid after this...
				protodetect_.reset();

				return;
			}	
		}	
	}

	if (detect.nssl_confirm_ > 3 || (detect.nssl_confirm_syn_ > 0 && detect.nssl_confirm_ > 1)) {
		auto				sslreq = ssl_req_.load(mo_relaxed);
		auto				svcshr = svcweak_.lock();

		if (!svcshr) {
			protodetect_.reset();
			return;
		}	

		if (sslreq == SSL_REQ_E::SSL_REJECTED) {
			if (stopped_parser_tusec_.load(mo_relaxed) == 0) {

				WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Service API Capture being stopped as Protocol Detected as TLS Encrypted for Listener %s Port %hu ID %lx : "
					"But SSL Capture cannot be enabled which may be because of [%s] or unsupported binary (Golang, Java based) or an unsupported SSL Library\n", 
					comm_, ns_ip_port_.ip_port_.port_, glob_id_, bool(api_cap_err_) ? api_cap_err_.get() : "unspecified");

				schedule_stop_capture();
			}
			
			protodetect_.reset();
			return;
		}	
	}	

	time_t				tcurr = tstats.tlastpkt_;

	if (detect.tlastchk_ > tcurr - 5) {
		return;
	}	

	detect.tlastchk_ = tcurr;

	if (detect.tfirstreq_ && detect.tfirstresp_ && tcurr > detect.tfirstreq_ + 600 && tcurr > detect.tfirstresp_ + 600 && tstats.npkts_ > 1000 && 
		tstats.nbytes_ > GY_UP_MB(1) && (detect.nsynsess_ > 4 || (detect.nmidsess_ > 10 && detect.nsynsess_ > 1))) {

		auto				sslreq = ssl_req_.load(mo_relaxed);

		// No confirms or only upto two confirms
		if (stopped_parser_tusec_.load(mo_relaxed) == 0) {
			if (detect.nconfirm_ > 0) {
				WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Service API Capture : Service Protocol Detection failed due to inadequate protocol detects : "
					"Could only detect %u connections out of %u as \'%s\' for Listener %s Port %hu ID %lx : "
						"SSL Capture is currently %sactive\n", detect.nconfirm_, detect.nsynsess_ + detect.nmidsess_,
						proto_to_string(detect.apistats_[0].proto_), comm_, ns_ip_port_.ip_port_.port_,
						glob_id_, sslreq == SSL_REQ_E::SSL_ACTIVE ? "" : "not ");
			}
			else {
				WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Service API Capture : Service Protocol Detection failed due to protocol not detected : "
					"Could not detect protocol from %u connections for Listener %s Port %hu ID %lx : "
						"SSL Capture is currently %sactive\n", detect.nsynsess_ + detect.nmidsess_,
						comm_, ns_ip_port_.ip_port_.port_, glob_id_, sslreq == SSL_REQ_E::SSL_ACTIVE ? "" : "not ");

			}

			const char			ebuf[] = "Service Protocol Detection failed or Protocol not currently supported";
			char				*pebuf = new char[sizeof(ebuf)];

			std::memcpy(pebuf, ebuf, sizeof(ebuf));

			GY_CC_BARRIER();

			api_cap_err_.reset(pebuf);

			schedule_stop_capture();
		}
		
		protodetect_.reset();
		return;
	}

	uint64_t			tstopusec = stopped_parser_tusec_.load(mo_relaxed);

	if (tstopusec > 0 && tstopusec + 30 * GY_USEC_PER_SEC > tcurr * GY_USEC_PER_SEC) {
		protodetect_.reset();
		return;
	}	
}

void API_PARSE_HDLR::api_parse_rd_thr() noexcept
{
	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "API Capture initialized : API Parser thread init completed as well\n");

	reqbuffer_.set_alloc_thrid(pthread_self());

try1 :
	try {
		MSG_PKT_SVCCAP			*pmsgpkt;
		MSG_ADD_SVCCAP			*paddsvc;
		MSG_DEL_SVCCAP			*pdelsvc;
		MSG_TIMER_SVCCAP		*ptimer;
		MSG_SVC_SSL_CAP			*pssl;
		bool				bret;

		do {
			PARSE_MSG_BUF			msg;

			bret = msgpool_.tryReadUntil(std::chrono::steady_clock::now() + std::chrono::milliseconds(500), msg);
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
					else {
						stats_.ninvalid_msg_++;
					}	
			
					break;

				default :
					assert(false);		// Unhandled index

					stats_.ninvalid_msg_++;
					break;
				}	
			}	
			else {
				handle_parse_no_msg();
			}	

		} while (true);	

	}
	GY_CATCH_MSG("Exception Caught in API Parser Thread");

	goto try1;
}	
	

uint8_t * API_PARSE_HDLR::get_xfer_pool_buf()
{
	uint8_t			*pbuf = (uint8_t *)reqbuffer_.get_buffer_chked(xfer_pool_allowed, true /* use_malloc_hdr */);

	if (!pbuf) {
		stats_.nxfer_pool_fail_++;
	}	

	return pbuf;
}	


bool API_PARSE_HDLR::set_xfer_buf_sz(size_t elemsz, bool force_flush)
{
	auto sendcb = [this](void *palloc, size_t sz, FREE_FPTR free_fp, size_t nelems) -> bool
	{
		DATA_BUFFER_ELEM		elem(palloc, sz, free_fp, nelems);
		bool				bret;

		// Now send the msg
		for (int ntries = 0; ntries < 3; ++ntries) {
			bret = gtranpool_->write(std::move(elem));

			if (bret == true) {
				return true;
			}
		}
		
		stats_.nxfer_pool_fail_ += nelems;

		return false;
	};	

	return reqbuffer_.set_buffer_sz(sendcb, elemsz, force_flush);
}	

#ifdef GY_API_PRINT

CONDDECLARE(
static int			gapi_print_fd = open(GY_API_PRINT, O_RDWR | O_TRUNC | O_CREAT, 0644);	
);

#endif

int API_PARSE_HDLR::api_xfer_thread(void * _) noexcept
{
	using namespace			comm;

	gy_msecsleep(100);

	if (!API_PARSE_HDLR::gtranpool_) {
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "API Transfer Pool not yet initialized. Returning from Transfer Thread...\n");
		return -1;
	}

try1 :
	try {
		/*
		 * 1 MB stack...
		 */

		API_PARSER_STATS		stats, *pstats = nullptr;

		auto				& tranpool = *API_PARSE_HDLR::gtranpool_;

		auto				pser = SERVER_COMM::get_singleton();
		assert(pser);

		const auto			conn_magic = pser->get_conn_magic();

		do {
			DATA_BUFFER_ELEM 		elem;
			bool				bret;

			bret = tranpool.tryReadUntil(std::chrono::steady_clock::now() + std::chrono::seconds(5), elem);
			if (bret) {
				static constexpr size_t 	fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY);

				if (!elem.palloc_ || elem.sz_ < fixed_sz) {
					continue;
				}

				COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(elem.palloc_);
				EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1); 

				new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, elem.sz_, conn_magic);

				new (pnot) EVENT_NOTIFY(NOTIFY_REQ_TRACE_TRAN, elem.nelems_);

				ssize_t				totallen = phdr->get_act_len();

#ifdef GY_API_PRINT
				CONDEXEC(
					static uint64_t			gnrecs = 0;

					if (gapi_print_fd > 0 && gnrecs < 1'000'000) {

						char				trec[32767];
						ssize_t				ttotlen = totallen;
						uint32_t			nelems = pnot->nevents_;
						API_TRAN			*pone = (API_TRAN *)(pnot + 1);

						ttotlen -= fixed_sz;

						for (int i = 0; (unsigned)i < nelems && ttotlen >= (ssize_t)sizeof(API_TRAN); ++i) {
							ssize_t elem_sz = pone->get_elem_size();

							if (ttotlen < elem_sz) {
								break;
							}

							char				stimebuf[128];
							PARSE_EXT_FIELDS		fields;
							auto				sv = get_api_tran(pone, fields);

							if (sv.size()) {
								gy_time_print(stimebuf, sizeof(stimebuf), GY_USEC_TO_TIMEVAL(pone->treq_usec_));

								gy_fdprintf(gapi_print_fd, trec, sizeof(trec) - 1, false, 
									"[#%lu : Time %s, Req [%s], Response %lu usec, Username %s, Appname [%s], DBName %s, "
									"Error Code %d, Error Text [%s], Status Code %d, Bytes In %lu, Bytes Out %lu]\n",
									++gnrecs, stimebuf, sv.data(), pone->response_usec_, fields.username_.data(), fields.appname_.data(),
									fields.dbname_.data(), pone->errorcode_, fields.errtxt_.data(), fields.statuscode_, 
									pone->reqlen_, pone->reslen_);
							}

							ttotlen -= elem_sz;

							pone = (API_TRAN *)((uint8_t *)pone + elem_sz);
						}
					}
				);

#endif

				if (!pstats) {
				
					auto				*papihdlr0 = SVC_NET_CAPTURE::get_singleton() ? SVC_NET_CAPTURE::get_singleton()->get_api_handler(0) : nullptr;
					if (papihdlr0) {
						pstats = &papihdlr0->stats_;
					}	
					else {
						pstats = &stats;
					}	

					(void)pser->get_trace_sock(true /* connect_if_none */);					
				}

				// Send data blocking
				bret = pser->send_trace_data_blocking(elem);
	

				if (bret) {
					pstats->nsend_bytes_ += elem.size();
				}	
				else {
					pstats->nsend_req_fail_ += elem.nelems();
				}	
			}	
			else {
				
			}	

		} while (true);	

	}
	GY_CATCH_MSG("Exception Caught in API Transfer Thread");

	goto try1;
}	
	
bool SVC_PARSE_STATS::update_pkt_stats(const PARSE_PKT_HDR & hdr) noexcept
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

	if ((uint8_t)hdr.src_ < (uint8_t)API_CAP_SRC::SRC_MAX) {
		srcpkts_[hdr.src_]++;
	}	
	else {
		return false;
	}	

	return true;
}


COMMON_PROTO::COMMON_PROTO(uint64_t glob_id, PARSE_PKT_HDR & hdr) noexcept
	: cli_ipport_(hdr.cliip_, hdr.cliport_), ser_ipport_(hdr.serip_, hdr.serport_), glob_id_(glob_id)
{
	uint64_t			tusec = timeval_to_usec(hdr.tv_);

	tlastpkt_usec_			= tusec;
	tconnect_usec_			= tusec;

	nxt_cli_seq_			= hdr.nxt_cli_seq_;
	nxt_ser_seq_			= hdr.nxt_ser_seq_;

	pid_				= hdr.pid_;
	netns_				= hdr.netns_;
	currdir_			= hdr.dir_;
	is_ssl_				= hdr.src_ == SRC_UPROBE_SSL;
	syn_seen_			= hdr.tcpflags_ & GY_TH_SYN;
}	

void COMMON_PROTO::set_src_chg(PARSE_PKT_HDR & hdr) noexcept
{
	nxt_cli_seq_			= hdr.nxt_cli_seq_;
	nxt_ser_seq_			= hdr.nxt_ser_seq_;

	pid_				= hdr.pid_;
	netns_				= hdr.netns_;
	is_ssl_				= hdr.src_ == SRC_UPROBE_SSL;
	syn_seen_			= hdr.tcpflags_ & GY_TH_SYN;
}	

void COMMON_PROTO::upd_stats(PARSE_PKT_HDR & hdr) noexcept
{
	if (hdr.dir_ == DirPacket::DirInbound) {
		if (clidroptype_ == DT_DROP_SEEN || serdroptype_ == DT_DROP_SEEN) {	
			auto			[dropcli, dropser] = tcp_drop_bytes(nxt_cli_seq_, hdr.start_cli_seq_, nxt_ser_seq_, hdr.start_ser_seq_, 
											clidroptype_, serdroptype_); 

			curr_req_drop_bytes_ 	= dropcli;
			curr_resp_drop_bytes_	= dropser;
		}
		else {
			curr_req_drop_bytes_ 	= 0;
			curr_resp_drop_bytes_	= 0;
		}	

		tot_reqlen_		+= hdr.datalen_;
		nxt_cli_seq_		= hdr.nxt_cli_seq_;

		if (serdroptype_ != DT_RETRANSMIT) {
			nxt_ser_seq_	= hdr.nxt_ser_seq_;
		}	
	}
	else {
		if (clidroptype_ == DT_DROP_SEEN || serdroptype_ == DT_DROP_SEEN) {	
			auto			[dropser, dropcli] = tcp_drop_bytes(nxt_ser_seq_, hdr.start_ser_seq_, nxt_cli_seq_, hdr.start_cli_seq_, 
											serdroptype_, clidroptype_); 

			curr_req_drop_bytes_ 	= dropcli;
			curr_resp_drop_bytes_	= dropser;
		}
		else {
			curr_req_drop_bytes_ 	= 0;
			curr_resp_drop_bytes_	= 0;
		}	

		tot_reslen_		+= hdr.datalen_;
		nxt_ser_seq_		= hdr.nxt_ser_seq_;

		if (clidroptype_ != DT_RETRANSMIT) {
			nxt_cli_seq_	= hdr.nxt_cli_seq_;
		}
	}	

	tlastpkt_usec_			= timeval_to_usec(hdr.tv_);

	lastdir_			= currdir_;
	currdir_			= hdr.dir_;
}	

/*
 * TODO : Cleanup missed Session FINs using diag info
 */
 
SVC_SESSION::SVC_SESSION(SVC_INFO_CAP & svc, PARSE_PKT_HDR & hdr)
	: common_(svc.glob_id_, hdr), psvc_(&svc), proto_(svc.proto_)
{
	svc.stats_.nsessions_new_++;
}	

SVC_SESSION::~SVC_SESSION() noexcept
{
	if (psvc_) {
		psvc_->stats_.nsessions_del_++;
	}

	set_to_delete(false);

	if (reorder_active() || isrdrmap_) {
		try {
			set_reorder_end();
		}
		catch(...) {
		}	
	}	

	if (pvarproto_.index() != 0 && psvc_) {
		bool				del = false;

		switch (proto_) {

		case PROTO_HTTP1 :
			if (auto phttp1 = std::get_if<HTTP1_SESSINFO *>(&pvarproto_); phttp1) {
				if (*phttp1) psvc_->apihdlr_.phttp1_->destroy(*phttp1, pdataproto_);
				del = true;
			}	
			break;

		case PROTO_HTTP2 :
			if (auto phttp2 = std::get_if<HTTP2_SESSINFO *>(&pvarproto_); phttp2) {
				if (*phttp2) psvc_->apihdlr_.phttp2_->destroy(*phttp2, pdataproto_);
				del = true;
			}	
			break;

		case PROTO_POSTGRES :
			if (auto ppostgres = std::get_if<POSTGRES_SESSINFO *>(&pvarproto_); ppostgres) {
				if (*ppostgres) psvc_->apihdlr_.ppostgres_->destroy(*ppostgres, pdataproto_);
				del = true;
			}	
			break;

		default :
			break;
		}	

		if (!del) {
			if (auto phttp1 = std::get_if<HTTP1_SESSINFO *>(&pvarproto_); phttp1) {
				if (*phttp1) psvc_->apihdlr_.phttp1_->destroy(*phttp1, pdataproto_);
			}	
			else if (auto phttp2 = std::get_if<HTTP2_SESSINFO *>(&pvarproto_); phttp2) {
				if (*phttp2) psvc_->apihdlr_.phttp2_->destroy(*phttp2, pdataproto_);
			}	
			else if (auto ppostgres = std::get_if<POSTGRES_SESSINFO *>(&pvarproto_); ppostgres) {
				if (*ppostgres) psvc_->apihdlr_.ppostgres_->destroy(*ppostgres, pdataproto_);
			}	
		}	
	}
}	

void SVC_SESSION::set_reorder_end()
{
	reorder_.exp_cli_seq_start_ = 0;
	reorder_.exp_ser_seq_start_ = 0;

	if (psvc_ && psvc_->sessrdrmap_.erase(this) && psvc_->sessrdrmap_.empty()) {
		psvc_->apihdlr_.reordermap_.erase(psvc_->glob_id_);
	}	

	isrdrmap_ = false;
}

bool SVC_INFO_CAP::parse_pkt(ParserMemPool::UniquePtr & puniq, PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	IP_PORT				ipport(hdr.cliip_, hdr.cliport_);
	bool				is_syn = hdr.tcpflags_ & GY_TH_SYN, is_finrst = hdr.tcpflags_ & (GY_TH_FIN | GY_TH_RST);

	auto				it = sessmap_.find(ipport);
	
	if (it == sessmap_.end()) {

		if (svc_ssl_ == SSL_SVC_E::SSL_ONLY && hdr.src_ != SRC_UPROBE_SSL) {
			return false;
		}	

		if (is_finrst) {
			return false;
		}	
		else if (hdr.datalen_ == 0) {
			if (!is_syn) {
				return false;
			}	

			if (hdr.start_cli_seq_ > 0 && hdr.nxt_ser_seq_ == 0) {
				return false;
			}	
		}	
		else if (hdr.dir_ == DirPacket::DirOutbound && !is_syn) {
			// Wait for inbound first
			return false;
		}

		if (sessmap_.size() >= MAX_PARSE_CONC_SESS) {
			stats_.nskip_conc_sess_++;
			return false;
		}	

		it = sessmap_.try_emplace(ipport, *this, hdr).first;
	}	

	auto				& sess = it->second;

	if (sess.to_delete()) {
		sessmap_.erase(it);

		return false;
	}	

	if (is_finrst) {
		sess.common_.tclose_usec_ = timeval_to_usec(hdr.tv_);
	}

	if (sess.common_.is_ssl_ && hdr.src_ != SRC_UPROBE_SSL) {
		return false;
	}	

	if (hdr.datalen_ == 0 && (0 == (hdr.tcpflags_ & (GY_TH_SYN | GY_TH_FIN | GY_TH_RST)))) {
		// GY_TH_URG not handled currently
		return false;
	}	

	GY_SCOPE_EXIT {
		if (sess.to_delete()) {
			sessmap_.erase(it);
		}	
	};

	if (hdr.src_ == SRC_UPROBE_SSL && !sess.common_.is_ssl_) {
		if (sess.reorder_active()) {
			sess.set_reorder_end();
		}

		sess.reorder_.~REORDER_INFO();

		new (&sess.reorder_) REORDER_INFO();

		sess.common_.set_src_chg(hdr);

		proto_handle_ssl_chg(sess, hdr, pdata);
	}

	if (sess.reorder_active()) {
		return handle_reorder(sess, puniq, hdr, pdata);
	}	

	return chk_drops_and_parse(sess, puniq, hdr, pdata, false);
}	

bool SVC_INFO_CAP::add_to_reorder_list(SVC_SESSION & sess, REORDER_PKT_HDR *pnewpkt, ParserMemPool::UniquePtr & puniq, PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	auto				& rdr = sess.reorder_;
	auto				& rlist = rdr.reorder_list_;
	
	auto				dir = pnewpkt->dir_;
	uint32_t			seq, ack;
	int				seqdiff;
	DROP_TYPES			dtype;

	seq 				= pnewpkt->start_pkt_seq_;
	ack				= pnewpkt->ack_seq_;

	for (auto rit = rlist.rbegin(); rit != rlist.rend(); ++rit) {
		REORDER_PKT_HDR			& pkt = *rit;

		seqdiff = (pkt.dir_ == dir ? pkt.start_pkt_seq_ + pkt.datalen_ - seq : pkt.ack_seq_ - seq);
		
		if (seqdiff <= 0) {
			auto			it = rlist.iterator_to(pkt);

			rlist.insert(++it, *pnewpkt);

			if (rit != rlist.rbegin()) {
				stats_.nrdrpkts_++;
				stats_.nrdrbytes_ += pnewpkt->datalen_;
			}	
			return true;
		}	
	}

	if (dir == DirPacket::DirInbound) {
		dtype = is_tcp_drop(sess.common_.nxt_cli_seq_, seq, sess.common_.nxt_ser_seq_, ack, hdr.tcpflags_ & GY_TH_SYN, hdr.tcpflags_ & GY_TH_FIN).first;
	}
	else {
		dtype = is_tcp_drop(sess.common_.nxt_ser_seq_, seq, sess.common_.nxt_cli_seq_, ack, hdr.tcpflags_ & GY_TH_SYN, hdr.tcpflags_ & GY_TH_FIN).first;
	}	

	if (dtype == DT_RETRANSMIT) {
		delete pnewpkt;
		return false;
	}	
	else if (dtype == DT_DROP_NEW_SESS) {
		delete pnewpkt;

		stats_.nsess_drop_new_++;

		// Send all pkts to parser
		send_reorder_to_parser(sess, timeval_to_usec(hdr.tv_), true /* clear_all */);

		return chk_drops_and_parse(sess, puniq, hdr, pdata, true /* ign_reorder */);
	}	

	// Add to start of list
	rdr.reorder_list_.push_front(*pnewpkt);
	rdr.set_head_info(sess, hdr);

	stats_.nrdrpkts_++;
	stats_.nrdrbytes_ += pnewpkt->datalen_;

	return true;
}

bool SVC_INFO_CAP::handle_reorder(SVC_SESSION & sess, ParserMemPool::UniquePtr & puniq, PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	auto				& rdr = sess.reorder_;
	int				clidiff = 0, serdiff = 0;

	const auto addelem = [&]() -> bool
	{
		if (rdr.reorder_list_.size() >= rdr.MAX_SESS_REORDER_PKTS || (timeval_to_usec(hdr.tv_) > rdr.tfirstusec_ + GY_USEC_PER_SEC)) {
			if (rdr.reorder_list_.size() >= rdr.MAX_SESS_REORDER_PKTS) {
				stats_.nrdr_sess_max_++;
			}
			else {
				stats_.nrdr_timeout_++;
			}	

			// Skip reordering
			send_reorder_to_parser(sess, timeval_to_usec(hdr.tv_), false /* clear_all */);

			if (rdr.reorder_list_.empty()) {
				return chk_drops_and_parse(sess, puniq, hdr, pdata, false /* ign_reorder */);
			}
		}	
			
		auto				prdr = alloc_reorder(sess, puniq, hdr, pdata);

		if (!prdr) {
			// Send all pkts to parser
			send_reorder_to_parser(sess, timeval_to_usec(hdr.tv_), true /* clear_all */);

			return chk_drops_and_parse(sess, puniq, hdr, pdata, true /* ign_reorder */);
		}	

		return add_to_reorder_list(sess, prdr, puniq, hdr, pdata);
	};
	
	const auto addfirst = [&]() -> bool
	{
		auto				prdr = alloc_reorder(sess, puniq, hdr, pdata);

		if (!prdr) {
			// Send all pkts to parser
			bool			bret = chk_drops_and_parse(sess, puniq, hdr, pdata, true /* ign_reorder */);

			if (bret) {
				return send_reorder_to_parser(sess, timeval_to_usec(hdr.tv_), true /* clear_all */);
			}
			else {
				return false;
			}	
		}	

		rdr.reorder_list_.push_front(*prdr);
		rdr.set_head_info(sess, hdr);
		
		return true;

	};

	bool				bret;

	if (hdr.dir_ == DirPacket::DirInbound) {
		if (rdr.exp_cli_seq_start_ > 0) {
			clidiff = rdr.exp_cli_seq_start_ - hdr.start_cli_seq_;

			if (clidiff == 0) {
				stats_.nrdrpkts_++;
				stats_.nrdrbytes_ += hdr.datalen_;

				if (rdr.exp_ser_seq_start_ > 0) {
					serdiff = rdr.exp_ser_seq_start_ - hdr.start_ser_seq_;

					if (serdiff >= 0) {
						// Send pkt to parser
						bret = chk_drops_and_parse(sess, puniq, hdr, pdata, true /* ign_reorder */);
						
						if (bret) {
							return send_reorder_to_parser(sess, timeval_to_usec(hdr.tv_), false /* clear_all */);
						}
						else {
							return false;
						}	
					}	
					else {
						// Still missing preceding resp
						return addfirst();
					}	
				}	
				else {
					// Send pkt to parser
					bret = chk_drops_and_parse(sess, puniq, hdr, pdata, true /* ign_reorder */);

					if (bret) {
						return send_reorder_to_parser(sess, timeval_to_usec(hdr.tv_), false /* clear_all */);
					}
					else {
						return false;
					}	
				}	
			}	
			else {
				int			seenclidiff = rdr.seen_cli_seq_ - hdr.start_cli_seq_;

				if (seenclidiff > 0 && clidiff < 0) {
					stats_.nrdrpkts_++;
					stats_.nrdrbytes_ += hdr.datalen_;

					return addfirst();
				}	

				return addelem();
			}	
		}
		else {
			if (rdr.exp_ser_seq_start_ > 0) {
				return addelem();
			}

			// Error...
			send_reorder_to_parser(sess, timeval_to_usec(hdr.tv_), true /* clear_all */);

			return chk_drops_and_parse(sess, puniq, hdr, pdata, true /* ign_reorder */);
		}	
	}
	else {
		if (rdr.exp_ser_seq_start_ > 0) {
			serdiff = rdr.exp_ser_seq_start_ - hdr.start_ser_seq_;

			if (serdiff == 0) {
				stats_.nrdrpkts_++;
				stats_.nrdrbytes_ += hdr.datalen_;

				if (rdr.exp_cli_seq_start_ > 0) {
					clidiff = rdr.exp_cli_seq_start_ - hdr.start_cli_seq_;

					if (clidiff >= 0) {
						// Send pkt to parser
						bret = chk_drops_and_parse(sess, puniq, hdr, pdata, true /* ign_reorder */);

						if (bret) {
							return send_reorder_to_parser(sess, timeval_to_usec(hdr.tv_), false /* clear_all */);
						}
						else {
							return false;
						}	
					}	
					else {
						// Still missing preceding req
						return addfirst();
					}	
				}	
				else {
					// Send pkt to parser
					bret = chk_drops_and_parse(sess, puniq, hdr, pdata, true /* ign_reorder */);

					if (bret) {
						return send_reorder_to_parser(sess, timeval_to_usec(hdr.tv_), false /* clear_all */);
					}
					else {
						return false;
					}	
				}	
			}	
			else {
				int			seenserdiff = rdr.seen_ser_seq_ - hdr.start_ser_seq_;

				if (seenserdiff > 0 && serdiff < 0) {
					stats_.nrdrpkts_++;
					stats_.nrdrbytes_ += hdr.datalen_;

					return addfirst();
				}	

				return addelem();
			}	
		}
		else {
			if (rdr.exp_cli_seq_start_ > 0) {
				return addelem();
			}

			// Error...
			send_reorder_to_parser(sess, timeval_to_usec(hdr.tv_), true /* clear_all */);

			return chk_drops_and_parse(sess, puniq, hdr, pdata, true /* ign_reorder */);
		}	
	}	
		
	return true;
}

// Returns false for retransmits
bool SVC_INFO_CAP::set_pkt_drops(SVC_SESSION & sess, PARSE_PKT_HDR & hdr)
{
	auto				& common = sess.common_;
	bool				is_syn = hdr.tcpflags_ & GY_TH_SYN;

	if (hdr.dir_ == DirPacket::DirInbound) {
		auto 			p = is_tcp_drop(sess.common_.nxt_cli_seq_, hdr.start_cli_seq_, sess.common_.nxt_ser_seq_, hdr.start_ser_seq_, is_syn, hdr.tcpflags_ & GY_TH_FIN);

		if (p.first == DT_RETRANSMIT) {
			return false;
		}

		common.clidroptype_ 	= p.first;
		common.serdroptype_ 	= p.second;
	}
	else {
		auto 			p = is_tcp_drop(sess.common_.nxt_ser_seq_, hdr.start_ser_seq_, sess.common_.nxt_cli_seq_, hdr.start_cli_seq_, is_syn, hdr.tcpflags_ & GY_TH_FIN);

		if (p.first == DT_RETRANSMIT) {
			return false;
		}

		common.serdroptype_ 	= p.first;
		common.clidroptype_ 	= p.second;
	}	
	
	return true;
}

// Returns false if new session init
bool SVC_INFO_CAP::chk_drops_and_parse(SVC_SESSION & sess, ParserMemPool::UniquePtr & puniq, PARSE_PKT_HDR & hdr, uint8_t *pdata, bool ign_reorder)
{
	auto				& common = sess.common_;
	bool				bret;

	bret = set_pkt_drops(sess, hdr);
	if (!bret) {
		// Retransmit

		if (hdr.tcpflags_ & GY_TH_SYN) {
			// Need to set here as session could be initialized with a succeeding req due to reorder misses
			common.tconnect_usec_ = timeval_to_usec(hdr.tv_);

#ifdef	GY_TEST_PCAPWRITE
			if (hdr.dir_ == DirPacket::DirInbound) {
				gpcapwr.write_tcp_pkt(hdr.tv_, hdr.cliip_, hdr.serip_, hdr.cliport_, hdr.serport_, hdr.start_cli_seq_, hdr.nxt_ser_seq_, hdr.tcpflags_, pdata, hdr.datalen_);
			}
			else {
				gpcapwr.write_tcp_pkt(hdr.tv_, hdr.serip_, hdr.cliip_, hdr.serport_, hdr.cliport_, hdr.start_ser_seq_, hdr.nxt_cli_seq_, hdr.tcpflags_, pdata, hdr.datalen_);
			}	

			gpcapwr.flush_file();
#endif
		}

		return true;
	}	

	if (common.clidroptype_ == DT_DROP_NEW_SESS || common.serdroptype_ == DT_DROP_NEW_SESS) {
		stats_.nsess_drop_new_++;

		sess.~SVC_SESSION();

		new (&sess) SVC_SESSION(*this, hdr);

		do_proto_parse(sess, hdr, pdata);

		return false;
	}	
	else if (common.clidroptype_ != DT_DROP_SEEN && common.serdroptype_ != DT_DROP_SEEN) {
		return do_proto_parse(sess, hdr, pdata);
	}

	if (ign_reorder || hdr.src_ != SRC_PCAP || (sess.reorder_active())) {
		return do_proto_parse(sess, hdr, pdata);
	}	

	start_reorder(sess, puniq, hdr, pdata);

	return true;
}	

bool SVC_INFO_CAP::send_reorder_to_parser(SVC_SESSION & sess, uint64_t tcurrusec, bool clear_all)
{
	auto				& rdr = sess.reorder_;
	auto				& rlist = rdr.reorder_list_;
	auto				& common = sess.common_;

	size_t				rlen = rlist.size(), minpkts = 1, npkts = 0;
	bool				bret;

	if (rlist.empty()) {
		goto done;
	}
	
	if (rlen >= rdr.MAX_SESS_REORDER_PKTS) {
		minpkts = rlen >> 2;
	}	

	for (; !rlist.empty() && !sess.to_delete(); rlist.pop_front_and_dispose(REORDER_PKT_HDR::destroy)) {
		auto				& pkt = rlist.front();
		auto				& puniq = pkt.pooluniq_;	

		if (!puniq) {
			npkts++;
			continue;
		}	

		PARSE_PKT_HDR			*phdr = (PARSE_PKT_HDR *)puniq.get()->get(), & hdr = *phdr;
		uint8_t				*pdata = (uint8_t *)(phdr + 1);

		bret = set_pkt_drops(sess, hdr);
		if (!bret) {
			npkts++;
			continue;
		}	
		
		if (common.clidroptype_ == DT_DROP_NEW_SESS || common.serdroptype_ == DT_DROP_NEW_SESS) {
			auto			hdrcpy = hdr;

			stats_.nsess_drop_new_++;

			sess.~SVC_SESSION();

			new (&sess) SVC_SESSION(*this, hdrcpy);

			return true;
		}	
		else if (common.clidroptype_ != DT_DROP_SEEN && common.serdroptype_ != DT_DROP_SEEN) {
			do_proto_parse(sess, hdr, pdata);
			npkts++;
			continue;
		}

		// Drops exist

		npkts++;

		if (!clear_all) {
			if (npkts > minpkts || tcurrusec < timeval_to_usec(hdr.tv_) + GY_USEC_PER_SEC) {
				break;
			}	
		}	

		do_proto_parse(sess, hdr, pdata);
	}

done :
	if (rlist.empty()) {
		sess.set_reorder_end();
	}
	
	return true;
}

REORDER_PKT_HDR * SVC_INFO_CAP::alloc_reorder(SVC_SESSION & sess, ParserMemPool::UniquePtr & puniq, PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	REORDER_PKT_HDR			*prdr = (REORDER_PKT_HDR *)apihdlr_.reorderpool_.malloc();

	if (!prdr) {
		stats_.nrdr_alloc_fails_++;
		apihdlr_.stats_.nrdr_alloc_fails_++;

		return nullptr;
	}	

	new (prdr) REORDER_PKT_HDR(std::move(puniq), hdr, apihdlr_.parseridx_);

	return prdr;
}

bool SVC_INFO_CAP::start_reorder(SVC_SESSION & sess, ParserMemPool::UniquePtr & puniq, PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	if (sess.common_.clidroptype_ != DT_DROP_SEEN && sess.common_.serdroptype_ != DT_DROP_SEEN) {
		return do_proto_parse(sess, hdr, pdata);
	}

	auto				prdr = alloc_reorder(sess, puniq, hdr, pdata);

	if (!prdr) {
		return do_proto_parse(sess, hdr, pdata);
	}	

	auto				& reorder = sess.reorder_;

	reorder.reorder_list_.push_front(*prdr);
	reorder.set_head_info(sess, hdr);

	sessrdrmap_.insert_or_assign(&sess, prdr->tpktusec_);
	apihdlr_.reordermap_.try_emplace(glob_id_, this);

	sess.isrdrmap_ = true;

	return true;
}

REORDER_PKT_HDR::REORDER_PKT_HDR(ParserMemPool::UniquePtr && pooluniq, const PARSE_PKT_HDR & hdr, uint8_t parseridx)
	: pooluniq_(std::move(pooluniq)), tpktusec_(timeval_to_usec(hdr.tv_)), datalen_(hdr.datalen_),
	start_pkt_seq_(hdr.dir_ == DirPacket::DirInbound ? hdr.start_cli_seq_ : hdr.start_ser_seq_), 
	ack_seq_(hdr.dir_ == DirPacket::DirInbound ? hdr.nxt_ser_seq_ : hdr.nxt_cli_seq_), dir_(hdr.dir_), parseridx_(parseridx)
{
	if (parseridx_ >= MAX_API_PARSERS) {
		GY_THROW_EXPRESSION("Invalid Parser Index specified while constructing Reorder object");
	}	
}	

REORDER_PKT_HDR::~REORDER_PKT_HDR() noexcept
{
}

REORDER_INFO::~REORDER_INFO() noexcept
{
	while (!reorder_list_.empty()) {
		reorder_list_.pop_front_and_dispose(REORDER_PKT_HDR::destroy);
	}	
}

void REORDER_INFO::set_head_info(SVC_SESSION & sess, PARSE_PKT_HDR & hdr)
{
	auto				clidroptype = sess.common_.clidroptype_, serdroptype = sess.common_.serdroptype_;

	tfirstusec_			= timeval_to_usec(hdr.tv_);

	if (clidroptype == DT_DROP_SEEN) {
		exp_cli_seq_start_	= sess.common_.nxt_cli_seq_;
		seen_cli_seq_		= hdr.start_cli_seq_;
	}	
	else {
		exp_cli_seq_start_	= 0;
		seen_cli_seq_		= 0;
	}	

	if (serdroptype == DT_DROP_SEEN) {
		exp_ser_seq_start_	= sess.common_.nxt_ser_seq_;
		seen_ser_seq_		= hdr.start_ser_seq_;
	}	
	else {
		exp_ser_seq_start_	= 0;
		seen_ser_seq_		= 0;
	}	
	
	if (hdr.dir_ == DirPacket::DirInbound) {
		ninbound_++;
	}	
	else {
		noutbound_++;
	}	
}

void REORDER_PKT_HDR::operator delete(void *ptr, size_t sz)
{
	if (ptr && sz >= sizeof(REORDER_PKT_HDR)) {
		auto			*prdr = (REORDER_PKT_HDR *)ptr;
		POOL_ALLOC		*ppool = nullptr;	

		// UB done intentionally...
		if (prdr->parseridx_ >= MAX_API_PARSERS) {
			prdr->parseridx_ = 0;
		}	

		ppool = REORDER_PKT_HDR::greorderpools_[prdr->parseridx_];

		if (ppool) {
			try {
				ppool->free(ptr);
			}
			catch(...) {
			}	
		}	
	}	
}	
	

bool SVC_INFO_CAP::do_proto_parse(SVC_SESSION & sess, PARSE_PKT_HDR & hdr, uint8_t *pdata) noexcept
{
	try {
		auto				& common = sess.common_;

		common.upd_stats(hdr);

		if (sess.to_delete()) {
			return true;
		}
		
		if (sess.reorder_active()) {
			sess.reorder_.set_head_info(sess, hdr);
		}	

#ifdef	GY_TEST_PCAPWRITE
		if (hdr.dir_ == DirPacket::DirInbound) {
			gpcapwr.write_tcp_pkt(hdr.tv_, hdr.cliip_, hdr.serip_, hdr.cliport_, hdr.serport_, hdr.start_cli_seq_, hdr.nxt_ser_seq_, hdr.tcpflags_, pdata, hdr.datalen_);
		}
		else {
			gpcapwr.write_tcp_pkt(hdr.tv_, hdr.serip_, hdr.cliip_, hdr.serport_, hdr.cliport_, hdr.start_ser_seq_, hdr.nxt_cli_seq_, hdr.tcpflags_, pdata, hdr.datalen_);
		}	

		gpcapwr.flush_file();
#endif

		bool				is_finrst = hdr.tcpflags_ & (GY_TH_FIN | GY_TH_RST);

		if (sess.pvarproto_.index() == 0) {
			if (hdr.datalen_ == 0) {
				if (is_finrst) {
					sess.set_to_delete(true);
				}

				return true;
			}	
			
			switch (sess.proto_) {
			
			case PROTO_HTTP1 :
				if (true) {
					auto [psess, pdata]	 	= apihdlr_.phttp1_->alloc_sess(sess, hdr);

					sess.pvarproto_ 		= psess;
					sess.pdataproto_		= pdata;
				}
				break;

			case PROTO_HTTP2 :
				if (true) {
					auto [psess, pdata]		= apihdlr_.phttp2_->alloc_sess(sess, hdr);

					sess.pvarproto_ 		= psess;
					sess.pdataproto_		= pdata;
				}
				break;

			case PROTO_POSTGRES :
				if (true) {
					auto [psess, pdata]		= apihdlr_.ppostgres_->alloc_sess(sess, hdr);

					sess.pvarproto_ 		= psess;
					sess.pdataproto_		= pdata;
				}
				break;

			default :
				break;	
			}	
		}
			
		if (sess.is_pkt_drop()) {
			stats_.ndroppkts_++;

			stats_.ndropbytes_	+= (uint64_t)common.curr_req_drop_bytes_ + common.curr_resp_drop_bytes_;
			stats_.ndropbytesin_	+= common.curr_req_drop_bytes_;
			stats_.ndropbytesout_	+= common.curr_resp_drop_bytes_;
		}
			
		if (hdr.datalen_ > 0) {	
			switch (sess.proto_) {

			case PROTO_HTTP1 :
				if (auto phttp1 = std::get_if<HTTP1_SESSINFO *>(&sess.pvarproto_); phttp1 && *phttp1) {

					if (hdr.dir_ == DirPacket::DirInbound) {
						apihdlr_.phttp1_->handle_request_pkt(**phttp1, sess, hdr, pdata);

						// HTTP1 & HTTP2 on same port
						if (gy_unlikely(sess.proto_ == PROTO_HTTP2) && !is_finrst) {

							apihdlr_.phttp1_->destroy(*phttp1, sess.pdataproto_);
							
							auto [psess, pdata]		= apihdlr_.phttp2_->alloc_sess(sess, hdr);
					
							sess.pvarproto_ 		= psess;
							sess.pdataproto_		= pdata;
						}	
					}	
					else {
						apihdlr_.phttp1_->handle_response_pkt(**phttp1, sess, hdr, pdata);
					}	
				}
				break;

			case PROTO_HTTP2 :
				if (auto phttp2 = std::get_if<HTTP2_SESSINFO *>(&sess.pvarproto_); phttp2 && *phttp2) {

					if (hdr.dir_ == DirPacket::DirInbound) {
						apihdlr_.phttp2_->handle_request_pkt(**phttp2, sess, hdr, pdata);

						// HTTP1 & HTTP2 on same port
						if (gy_unlikely(sess.proto_ == PROTO_HTTP1) && !is_finrst) {

							apihdlr_.phttp2_->destroy(*phttp2, sess.pdataproto_);
							
							auto [psess, pdata]		= apihdlr_.phttp1_->alloc_sess(sess, hdr);
					
							sess.pvarproto_ 		= psess;
							sess.pdataproto_		= pdata;
						}	
					}	
					else {
						apihdlr_.phttp2_->handle_response_pkt(**phttp2, sess, hdr, pdata);
					}	
				}
				break;

			case PROTO_POSTGRES :
				if (auto ppostgres = std::get_if<POSTGRES_SESSINFO *>(&sess.pvarproto_); ppostgres && *ppostgres) {

					if (hdr.dir_ == DirPacket::DirInbound) {
						apihdlr_.ppostgres_->handle_request_pkt(**ppostgres, sess, hdr, pdata);
					}	
					else {
						apihdlr_.ppostgres_->handle_response_pkt(**ppostgres, sess, hdr, pdata);
					}	
				}
				break;

			default :
				break;	

			}	
		}

		if (is_finrst) {
			sess.set_to_delete(true);
		
			switch (sess.proto_) {

			case PROTO_HTTP1 :
				if (auto phttp1 = std::get_if<HTTP1_SESSINFO *>(&sess.pvarproto_); phttp1 && *phttp1) {
					apihdlr_.phttp1_->handle_session_end(**phttp1, sess, hdr);
				}
				break;

			case PROTO_HTTP2 :
				if (auto phttp2 = std::get_if<HTTP2_SESSINFO *>(&sess.pvarproto_); phttp2 && *phttp2) {
					apihdlr_.phttp2_->handle_session_end(**phttp2, sess, hdr);
				}
				break;

			case PROTO_POSTGRES :
				if (auto ppostgres = std::get_if<POSTGRES_SESSINFO *>(&sess.pvarproto_); ppostgres && *ppostgres) {
					apihdlr_.ppostgres_->handle_session_end(**ppostgres, sess, hdr);
				}
				break;

			default :
				break;	

			}	
		}
		
		return false;
	}
	GY_CATCH_EXPRESSION(
		DEBUGEXECN(1, WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while parsing API protocol : %s", GY_GET_EXCEPT_STRING););
		return false;
	);	
}	

bool SVC_INFO_CAP::proto_handle_ssl_chg(SVC_SESSION & sess, PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	stats_.nsrc_chg_++;

	switch (sess.proto_) {

	case PROTO_HTTP1 :
		if (auto phttp1 = std::get_if<HTTP1_SESSINFO *>(&sess.pvarproto_); phttp1 && *phttp1) {
			apihdlr_.phttp1_->handle_ssl_change(**phttp1, sess, hdr, pdata);
		}
		break;

	case PROTO_HTTP2 :
		if (auto phttp2 = std::get_if<HTTP2_SESSINFO *>(&sess.pvarproto_); phttp2 && *phttp2) {
			apihdlr_.phttp2_->handle_ssl_change(**phttp2, sess, hdr, pdata);
		}
		break;

	case PROTO_POSTGRES :
		if (auto ppostgres = std::get_if<POSTGRES_SESSINFO *>(&sess.pvarproto_); ppostgres && *ppostgres) {
			apihdlr_.ppostgres_->handle_ssl_change(**ppostgres, sess, hdr, pdata);
		}
		break;

	default :
		return false;
	}

	return true;
}	

void SVC_INFO_CAP::schedule_stop_capture() noexcept
{
	auto				psvcnet = SVC_NET_CAPTURE::get_singleton();
	
	if (!psvcnet) {
		return;
	}	

	psvcnet->sched_del_one_listener(0, glob_id_, ns_ip_port_.get_ns_inode(), ns_ip_port_.get_port(), true /* onlyapi */);
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

	auto				*papihdlr0 = psvcnet->get_api_handler(0);
	
	if (!papihdlr0 || papihdlr0->allow_ssl_probe_.load(mo_relaxed) == false) {
		ssl_req_.store(SSL_REQ_E::SSL_REJECTED, mo_relaxed);

		api_cap_err_ = std::make_unique<char []>(sizeof("SSL User Probes disalowed") + 1);

		std::memcpy(api_cap_err_.get(), "SSL User Probes disalowed", sizeof("SSL User Probes disalowed"));
		return;	
	}	

	ssl_req_.store(SSL_REQ_E::SSL_REQUEST_SCHED, mo_relaxed);

	psvcnet->sched_svc_ssl_probe(gy_to_charbuf<256>("SSL Probe for Svc %s %lx", comm_, glob_id_).get(), svcweak_);
}	

void SVC_INFO_CAP::schedule_ssl_stop() noexcept
{
	auto				sslreq = ssl_req_.load(mo_relaxed);

	if (sslreq == SSL_REQ_E::SSL_NO_REQ || sslreq == SSL_REQ_E::SSL_REJECTED) {
		return;
	}
	
	auto				psvcnet = SVC_NET_CAPTURE::get_singleton();

	if (!psvcnet) {
		return;
	}	

	psvcnet->sched_svc_ssl_stop(gy_to_charbuf<256>("Stop SSL Probe for Svc %s %lx", comm_, glob_id_).get(), glob_id_);

	ssl_req_.store(SSL_REQ_E::SSL_NO_REQ, mo_relaxed);
}	

void SVC_PARSE_STATS::operator -= (const SVC_PARSE_STATS & other) noexcept
{
	npkts_			-= other.npkts_;
	nbytes_			-= other.nbytes_;
	nreqpkts_		-= other.nreqpkts_;
	nreqbytes_		-= other.nreqbytes_;
	nresppkts_		-= other.nresppkts_;
	nrespbytes_		-= other.nrespbytes_;

	nrequests_		-= other.nrequests_;
	ncli_errors_		-= other.ncli_errors_;
	nser_errors_		-= other.nser_errors_;

	ndroppkts_		-= other.ndroppkts_;
	ndropbytes_		-= other.ndropbytes_;
	ndropbytesin_		-= other.ndropbytesin_;
	ndropbytesout_		-= other.ndropbytesout_;
	nrdrpkts_		-= other.nrdrpkts_;
	nrdrbytes_		-= other.nrdrbytes_;
	nrdr_sess_max_		-= other.nrdr_sess_max_;
	nrdr_timeout_		-= other.nrdr_timeout_;
	nrdr_alloc_fails_	-= other.nrdr_alloc_fails_;
	nsessions_new_		-= other.nsessions_new_;
	nsessions_del_		-= other.nsessions_del_;
	nsess_drop_new_		-= other.nsess_drop_new_;
	nskip_conc_sess_	-= other.nskip_conc_sess_;
	nsrc_chg_		-= other.nsrc_chg_;

	for (uint8_t i = 0; i < API_CAP_SRC::SRC_MAX; ++i) {
		srcpkts_[i]	-= other.srcpkts_[i];
	}
}


void SVC_PARSE_STATS::print_stats(STR_WR_BUF & strbuf, uint64_t tcurrusec, uint64_t tlastusec) const noexcept
{
	strbuf << "Stats for "sv << (tcurrusec - tlastusec)/GY_USEC_PER_SEC << " sec : Requests "sv << nrequests_ 
		<< ", Client Errors "sv << ncli_errors_ << ", Server Errors "sv << nser_errors_ << ", Packets "sv << npkts_ << ", Bytes "sv << nbytes_ << "("sv << (nbytes_ >> 20) 
		<< " MB), Request Pkts "sv << nreqpkts_ << ", Request Bytes "sv << nreqbytes_ << " ("sv << (nreqbytes_ >> 20) << " MB), Response Pkts "sv << nresppkts_ 
		<< ", Response Bytes "sv << nrespbytes_ << " ("sv << (nrespbytes_ >> 20) << " MB), Drop Pkts "sv << ndroppkts_ << ", Drop Bytes "sv << ndropbytes_ 
		<< " ("sv << (ndropbytes_ >> 20) << " MB), Drop Req Bytes "sv << ndropbytesin_ << ", Drop Resp Bytes "sv << ndropbytesout_ << ", Reordered Pkts "sv << nrdrpkts_ 
		<< ", Reorder Bytes "sv << nrdrbytes_ << " ("sv << (nrdrbytes_ >> 20) << " MB), "sv << "Reorder miss by max session pkts "sv << nrdr_sess_max_ 
		<< ", Reorder miss by timeout "sv << nrdr_timeout_ << ", Reorder miss by too many reorders "sv << nrdr_alloc_fails_ << ", Sessions Allocated "sv << nsessions_new_ 
		<< ", Sessions Completed "sv << nsessions_del_ << ", Sessions with drop Logouts "sv << nsess_drop_new_ << ", Sessions with Change of Src e.g. SSL "sv 
		<< nsrc_chg_ << ", Packets skipped by Max Concurrency hits " << nskip_conc_sess_ << "\n\n"sv;
}	

void SVC_INFO_CAP::print_stats(STR_WR_BUF & strbuf, uint64_t tcurrusec, uint64_t tlastusec) noexcept
{
	auto				diffstats = stats_, & lstats = laststats_;

	strbuf << "API Capture Statsistics for Svc '"sv << comm_ << "' Port "sv << ns_ip_port_.ip_port_.port_ << " Protocol "sv << proto_to_string(proto_);
	strbuf << " SSL Capture Status : "sv << ssl_req_to_string(ssl_req_.load(mo_relaxed)) << '\n';

	diffstats -= lstats;

	strbuf << "Interval "sv;
	diffstats.print_stats(strbuf, tcurrusec, tlastusec);
	
	strbuf << "Cumulative "sv;
	stats_.print_stats(strbuf, tcurrusec, tstartusec_);
	
	lstats = stats_;
}	

bool API_PARSE_HDLR::handle_proto_pkt(MSG_PKT_SVCCAP & msg) noexcept
{
	try {
		auto				& puniq = msg.pooluniq_;

		if (!puniq) {
			stats_.ninvalid_pkt_++;
			return false;
		}	

		PARSE_PKT_HDR			*phdr = (PARSE_PKT_HDR *)puniq.get()->get();
		uint8_t				*pdata = (uint8_t *)(phdr + 1);
		bool				bret;
		
		if (phdr->datalen_ > MAX_PARSE_FRAG_LEN) {
			stats_.ninvalid_pkt_++;
			return false;
		}

		uint64_t			glob_id = msg.glob_id_;
		SVC_INFO_CAP			*psvc = msg.psvc_;

		if (!psvc) {
			if (phdr->netns_ == 0 && phdr->src_ == SRC_PCAP) {
				stats_.ninvalid_pkt_++;
				return false;
			}	

			auto			it = nsportmap_.find(NS_IP_PORT(phdr->serip_, phdr->serport_, phdr->netns_));

			if (it == nsportmap_.end() || !bool(it->second)) {
				return false;
			}	

			psvc = it->second.get();
			glob_id = psvc->glob_id_;
		}	

		if (gy_unlikely(psvc->stopped_parser_tusec_.load(mo_relaxed) > 0)) {
			return false;
		}	

		bret = psvc->stats_.update_pkt_stats(*phdr);
		
		if (!bret) {
			stats_.ninvalid_pkt_++;
			return false;
		}	

		if (gy_unlikely(bool(psvc->protodetect_))) {
			if (true == psvc->detect_svc_req_resp(*phdr, pdata)) {
				psvc->analyze_detect_status();
			}	

			return true;
		}	

		if (psvc->proto_ != PROTO_UNINIT) {
#ifndef GY_TEST_REORDER_PKTS
			return psvc->parse_pkt(puniq, *phdr, pdata);
#else
			if (phdr->src_ == SRC_PCAP) {
				return test_reorders(parseridx_, psvc, puniq, *phdr, pdata);
			}

			return psvc->parse_pkt(puniq, *phdr, pdata);
#endif			
		}

		return false;
	}
	GY_CATCH_EXPRESSION(
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

		if (!success) {
			it->second = std::move(msg.svcinfocap_);
		}	

		auto 				[it2, success2] = nsportmap_.try_emplace(it->second->ns_ip_port_, it->second);

		if (!success2) {
			it2->second = it->second;
		}	

		if (!success) {
			reordermap_.erase(msg.glob_id_);
		}

		stats_.nsvcadd_++;

		return true;
	}
	GY_CATCH_MSG("Exception Caught while handling API Parser Add Svc");

	return false;
}	

bool API_PARSE_HDLR::handle_svc_del(MSG_DEL_SVCCAP & msg, SvcInfoIdMap::iterator *pit) noexcept
{
	try {
		std::shared_ptr<SVC_INFO_CAP>	svcshr;
		SvcInfoIdMap::iterator 		it;

		if (!pit) {
			it = svcinfomap_.find(msg.glob_id_);
		}
		else {
			it = *pit;
		}	

		if (it != svcinfomap_.end()) {
			if (it->second) {
				svcshr = std::move(it->second);
		
				// Call destroy to ensure the map clear() are called from this thread itself...
				svcshr->destroy(msg.tusec_);
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

		stats_.nsvcdel_++;

		return true;
	}
	GY_CATCH_MSG("Exception Caught while handling API Parser Del Svc");

	return false;
}	

bool API_PARSE_HDLR::handle_parse_timer(MSG_TIMER_SVCCAP & msg) noexcept
{
	try {
		if (tlast_rdrchk_usec_ <= msg.tusec_ - REORDER_CHK_SEC * GY_USEC_PER_SEC - 100 * GY_USEC_PER_MSEC /* 100 msec leeway */) {
			chk_svc_reorders();
		}	

		if (tlast_svc_chk_usec_ <= msg.tusec_ - SVC_CHK_SEC * GY_USEC_PER_SEC - 100 * GY_USEC_PER_MSEC /* 100 msec leeway */) {
			chk_svc_info();
		}	

		if (tlast_print_usec_ <= msg.tusec_ - PRINT_STATS_SEC * GY_USEC_PER_SEC - 100 * GY_USEC_PER_MSEC /* 100 msec leeway */) {
			print_stats();
		}	

		set_xfer_buf_sz(0, true /* force_flush */);

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

		stats_.nsvcssl_on_++;

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

		auto				& svcshr = it->second;
	
		svcshr->ssl_req_.store(SSL_REQ_E::SSL_REJECTED, mo_relaxed);

		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "SSL Probes disabled for Service %s ID %lx due to %s\n", 
			svcshr->comm_, svcshr->glob_id_, bool(msg.msguniq_) ? msg.msguniq_.get() : "unspecified reason");
		
		GY_CC_BARRIER();

		svcshr->api_cap_err_ = std::move(msg.msguniq_);

		stats_.nsvcssl_fail_++;

		return true;
	}
	catch(...) {
		return false;
	}	
}	

bool API_PARSE_HDLR::handle_parse_no_msg() noexcept
{
	try {
		set_xfer_buf_sz(0, true /* force_flush */);

		return true;
	}
	GY_CATCH_MSG("Exception Caught while handling API Parser No Msg");

	return false;
}	

void API_PARSE_HDLR::chk_svc_reorders()
{
	uint64_t			tcurrusec = get_usec_time();

	for (auto osit = reordermap_.begin(); osit != reordermap_.end();) {
		auto				oit = osit++;
		SVC_INFO_CAP			*psvc = oit->second;

		if (!psvc) {
			reordermap_.erase(oit);
			continue;
		}	

		for (auto sit = psvc->sessrdrmap_.begin(); sit != psvc->sessrdrmap_.end();) {
			auto				it = sit++;
			SVC_SESSION			*psess = it->first;

			if (!psess) {
				psvc->sessrdrmap_.erase(it);
				continue;
			}	

			if (psess->reorder_active() && psess->reorder_.tfirstusec_ < tcurrusec - GY_USEC_PER_SEC) {
				// Timed Out
				psvc->send_reorder_to_parser(*psess, tcurrusec, false /* clear_all */);

				if (psess->to_delete()) {
					psvc->sessmap_.erase(psess->common_.cli_ipport_);
					continue;
				}	
			}	
		}
		
	}	

	tlast_rdrchk_usec_ = tcurrusec;
}	

void API_PARSE_HDLR::chk_svc_info()
{
	uint64_t			tcurrusec = get_usec_time();

	for (auto osit = svcinfomap_.begin(); osit != svcinfomap_.end();) {
		auto				oit = osit++;
		SVC_INFO_CAP			*psvc = oit->second.get();

		if (!psvc) {
			svcinfomap_.erase(oit);
			continue;
		}	

		if (gy_unlikely(psvc->stopped_parser_tusec_.load(mo_relaxed) > 0)) {
			MSG_DEL_SVCCAP		msg(psvc->glob_id_);

			handle_svc_del(msg, &oit);
			continue;
		}

		if (gy_unlikely(psvc->protodetect_)) {
			psvc->analyze_detect_status();
		}
	}	

	tlast_svc_chk_usec_ = tcurrusec;
}	


void API_PARSER_STATS::operator -= (const API_PARSER_STATS & other) noexcept
{
	nsvcadd_		-=	other.nsvcadd_;
	nsvcdel_		-=	other.nsvcdel_;
	nsvcssl_on_		-=	other.nsvcssl_on_;
	nsvcssl_fail_		-=	other.nsvcssl_fail_;
	ninvalid_pkt_		-=	other.ninvalid_pkt_;
	ninvalid_msg_		-=	other.ninvalid_msg_;
	nrdr_alloc_fails_	-=	other.nrdr_alloc_fails_;
	nxfer_pool_fail_	-=	other.nxfer_pool_fail_;
	nsend_req_fail_		-=	other.nsend_req_fail_;
	nsend_bytes_		-=	other.nsend_bytes_;

	nskip_pool_.fetch_sub_relaxed_0(other.nskip_pool_.load(mo_relaxed));
}

void API_PARSER_STATS::print_stats(STR_WR_BUF & strbuf, uint64_t tcurrusec, uint64_t tlastusec) const noexcept
{
	strbuf << "Stats for "sv << (tcurrusec - tlastusec)/GY_USEC_PER_SEC << " sec : Service API Captures Started "sv << nsvcadd_ 
	<< ", Captures Stopped "sv << nsvcdel_ << ", SSL Captures Started "sv << nsvcssl_on_ << ", SSL Captures Failed "sv << nsvcssl_fail_ 
	<< ", Invalid Capture Packets "sv << ninvalid_pkt_ << ", Invalid Messages "sv << ninvalid_msg_ << ", Reorder Alloc Fails "sv 
	<< nrdr_alloc_fails_ 
	<< ", Requests Skipped by Transfer Pool Fails "sv << nxfer_pool_fail_
	<< ", Requests Skipped by Server send Fails "sv << nsend_req_fail_
	<< ", Requests Bytes sent to server "sv << nsend_bytes_ << " ("sv << GY_DOWN_MB(nsend_bytes_) << " MB)"sv

	<< ", Pkts skipped by Pool Blocks "sv << nskip_pool_.load(mo_relaxed) 
	<< "\n"sv;
}	


void API_PARSE_HDLR::print_stats() noexcept
{
	STRING_BUFFER<4096>		strbuf;
	uint64_t			tcurrusec = get_usec_time();

	strbuf << "API Parser Stats for captured services : "sv;

	for (auto osit = svcinfomap_.begin(); osit != svcinfomap_.end();) {
		auto				oit = osit++;
		SVC_INFO_CAP			*psvc = oit->second.get();

		if (!psvc) {
			svcinfomap_.erase(oit);
			continue;
		}	

		strbuf << '\n';

		psvc->print_stats(strbuf, tcurrusec, tlast_print_usec_);	

		if (strbuf.bytes_left() < 1500) {
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "%s\n", strbuf.buffer());
			strbuf.reset();
		}	
	}	

	if (strbuf.bytes_left() < 1500) {
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "%s\n", strbuf.buffer());
		strbuf.reset();
	}	

	HTTP1_PROTO::print_stats(strbuf, tcurrusec/GY_USEC_PER_SEC, tlast_print_usec_/GY_USEC_PER_SEC);

	if (strbuf.bytes_left() < 1500) {
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "%s\n", strbuf.buffer());
		strbuf.reset();
	}	

	HTTP2_PROTO::print_stats(strbuf, tcurrusec/GY_USEC_PER_SEC, tlast_print_usec_/GY_USEC_PER_SEC);

	if (strbuf.bytes_left() < 1500) {
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "%s\n", strbuf.buffer());
		strbuf.reset();
	}	

	POSTGRES_PROTO::print_stats(strbuf, tcurrusec/GY_USEC_PER_SEC, tlast_print_usec_/GY_USEC_PER_SEC);
	
	if (strbuf.bytes_left() < 1500) {
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "%s\n", strbuf.buffer());
		strbuf.reset();
	}	

	auto				diffstats = stats_, & lstats = laststats_;

	strbuf << "API Parser #"sv << parseridx_ << " Stats : \n"sv; 

	diffstats -= lstats;

	strbuf << "Interval "sv;
	diffstats.print_stats(strbuf, tcurrusec, tlast_print_usec_);
	
	strbuf << "Cumulative "sv;
	stats_.print_stats(strbuf, tcurrusec, tstartusec_);
	
	lstats = stats_;

	tlast_print_usec_ = tcurrusec;

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "%s\n", strbuf.buffer());
}	


} // namespace gyeeta

