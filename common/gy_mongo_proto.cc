//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_mongo_proto.h"
#include			"gy_mongo_proto_detail.h"
#include			"gy_proto_parser.h"
#include			"gy_tls_proto.h"

namespace gyeeta {

using MG_SER_ERR_SET		= std::unordered_set<int, GY_JHASHER<int>>;

static MG_SER_ERR_SET		gerrset_;

static void init_errcode_set()
{
	// Refer to https://www.mongodb.com/docs/manual/reference/error-codes/

	gerrset_ = {
		1, 5, 6, 7, 8, 15, 24, 25, 36, 37, 38, 39, 42, 46, 51, 55, 61, 63, 64, 65, 70, 71, 74, 83, 
		87, 89, 90, 91, 92, 93, 94, 95, 103, 104, 105, 106, 107, 108, 109, 110, 113, 114, 124, 127,
		138, 140, 142, 146, 147, 150, 152, 158, 159, 160, 188, 189, 190, 202, 203, 204, 205, 209,
		210, 215, 216, 230, 231, 235, 247, 248, 249, 250, 272, 273, 274, 288, 290, 301, 304, 333,
		10107, 11600, 11602, 13388, 13435, 13436, 14031
	};
};	

MONGO_PROTO::MONGO_PROTO(API_PARSE_HDLR & apihdlr, uint32_t api_max_len)
	: apihdlr_(apihdlr), api_max_len_(api_max_len), max_mongo_req_token_(api_max_len_ + 512), max_mongo_resp_token_(2048)
{
	init_errcode_set();
}	

MONGO_PROTO::~MONGO_PROTO() noexcept		= default;

std::pair<MONGO_SESSINFO *, void *> MONGO_PROTO::alloc_sess(SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr)
{
	return { new MONGO_SESSINFO(*this, svcsess), nullptr };
}	

void MONGO_PROTO::destroy(MONGO_SESSINFO *pobj, void *pdata) noexcept
{
	delete pobj;
}	

void MONGO_PROTO::handle_request_pkt(MONGO_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	sess.handle_request_pkt(hdr, pdata);
}

void MONGO_PROTO::handle_response_pkt(MONGO_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	sess.handle_response_pkt(hdr, pdata);
}

void MONGO_PROTO::handle_session_end(MONGO_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr)
{
	sess.handle_session_end(hdr);
}	

void MONGO_PROTO::handle_ssl_change(MONGO_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	sess.handle_ssl_change(hdr, pdata);
}


void MONGO_PROTO::print_stats(STR_WR_BUF & strbuf, time_t tcur, time_t tlast) noexcept
{
	MONGO_SESSINFO::print_stats(strbuf, tcur, tlast);
}	
	
MONGO_SESSINFO::MONGO_SESSINFO(MONGO_PROTO & prot, SVC_SESSION & svcsess)
	: MONGO_PROTO(prot), 
	tran_(svcsess.common_.tlastpkt_usec_, svcsess.common_.tconnect_usec_, svcsess.common_.cli_ipport_, svcsess.common_.ser_ipport_, 
		svcsess.common_.glob_id_, svcsess.proto_, svcsess.psvc_ ? svcsess.psvc_->comm_ : nullptr), 
	tdstrbuf_(prot.api_max_len_ - 1), 
	preqfragbuf_(new uint8_t[prot.max_mongo_req_token_ + 16 + prot.max_mongo_resp_token_ + 16]), prespfragbuf_(preqfragbuf_ + prot.max_mongo_req_token_ + 16), 
	svcsess_(svcsess), psvc_(svcsess.psvc_)
{
	std::memset(tdstrbuf_.get(), 0, 128);
	std::memset(preqfragbuf_, 0, 128);
	std::memset(prespfragbuf_, 0, 128);
	
	gstats[STATMG_NEW_SESS]++;
	
	if (svcsess.common_.syn_seen_ == false) {
		is_midway_session_ = 1;

		statmg_.skip_to_req_after_resp_ = 1;
		statmg_.skip_req_resp_till_ready_ = 1;

		gstats[STATMG_MIDWAY_SESS]++;
	}
}	
	
MONGO_SESSINFO::~MONGO_SESSINFO() noexcept
{
	gstats[STATMG_SESS_COMPLETE]++;

	if (part_query_started_ == 1) {
		drop_partial_req();
	}
	
	delete [] preqfragbuf_;
}	
	
int MONGO_SESSINFO::handle_request_pkt(PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	uint8_t			*ptmp, *pend = pdata + hdr.datalen_;
	uint8_t			*sptr = pdata;
	auto			& common = svcsess_.common_;
	int			ret;

	if (skip_session_ == 1) {
		gstats[STATMG_SESS_SKIP_PKT]++;
		return 0;
	}

	if (is_ssl_sess_ == 2 && hdr.src_ != SRC_UPROBE_SSL) {
		return 0;
	}	

	if (drop_seen_ || common.clidroptype_ == DT_DROP_SEEN || common.serdroptype_ == DT_DROP_SEEN) {

		if (part_query_started_ == 1) {
			drop_partial_req();
			part_query_started_ = 0;
		}
			
		statmg_.reset_stats_on_resp(true);

		is_midway_session_ = 1;

		drop_seen_ = 0;
		statmg_.skip_to_req_after_resp_ = 1;
		statmg_.skip_req_resp_till_ready_ = 1;

		return 0;
	}

	ret = parse_req_pkt(hdr, pdata);
	if (ret < 0) {
		gstats[STATMG_REQ_PKT_SKIP]++;
		return 0;
	}	

	tran_.update_req_stats(common.tlastpkt_usec_, hdr.datalen_);

	if (tdstrbuf_.size() && part_query_started_ == 0) {
		tran_.request_len_ = tdstrbuf_.size() + 1;
		part_query_started_ = 1;
		set_partial_req();
	}

	return 0;
}

int MONGO_SESSINFO::handle_response_pkt(PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	uint8_t 		*sptr = pdata;
	uint32_t 		bytes_left, pktlen = hdr.datalen_;
	auto			& common = svcsess_.common_;
	int 			ret;

	if (skip_session_ == 1) {
		gstats[STATMG_SESS_SKIP_PKT]++;
		return 0;
	}

	if (is_ssl_sess_ > 0) {
		if (is_ssl_sess_ == 2 && hdr.src_ != SRC_UPROBE_SSL) {
			return 0;
		}	
		else if (is_ssl_sess_ == 1) {
			if (true == TLS_PROTO::is_tls_req_resp(pdata, hdr.datalen_, hdr.dir_, !is_midway_session_ && common.serdroptype_ != DT_DROP_SEEN /* is_init */)) {
					
				is_ssl_sess_ = 2;
				gstats[STATMG_SSL_SESS]++;

				return 0;
			}	

			if (hdr.src_ == SRC_UPROBE_SSL) {
				is_ssl_sess_ = 2;
				gstats[STATMG_SSL_SESS]++;

				goto drop_chk;
			}	
			else if (++nssl_resp_chk_ > 8) {
				is_ssl_sess_ = (int8_t)-1;
				statmg_.skip_to_req_after_resp_ = 1;

				gstats[STATMG_SSL_INVALID]++;

				return 0;
			}	
			else if (++nssl_resp_chk_ > 32 && common.tlastpkt_usec_ > common.tconnect_usec_ + 30 * GY_USEC_PER_SEC) {
				skip_session_ = 1;
				gstats[STATMG_SKIP_SESS]++;

				return 0;
			}	
		}
	}
	
	if (drop_seen_ || common.clidroptype_ == DT_DROP_SEEN || common.serdroptype_ == DT_DROP_SEEN) {

drop_chk :
		if (part_query_started_ == 1) {
			drop_partial_req();
			part_query_started_ = 0;
		}
			
		statmg_.reset_stats_on_resp(true);

		is_midway_session_ = 1;

		drop_seen_ = 0;
		statmg_.skip_to_req_after_resp_ = 1;
		statmg_.skip_req_resp_till_ready_ = 1;

		return 0;
	}

	tran_.update_resp_stats(common.tlastpkt_usec_, hdr.datalen_);

	ret = parse_resp_pkt(hdr, pdata);
	if (ret < 0) {
		gstats[STATMG_RESP_PKT_SKIP]++;
	}	

	return 0;
}


void MONGO_SESSINFO::handle_session_end(PARSE_PKT_HDR & hdr)
{
	auto				& common = svcsess_.common_;

	if (part_query_started_ == 1) {
		drop_partial_req();
		part_query_started_ = 0;
	}
	
	if (tdstat_.reqnum_ == 0) {
		return;
	}	

	/*
	 * Flush existing request
	 */
	if (tran_.reqlen_ && tdstrbuf_.size() > 0 && (!(drop_seen_ || common.clidroptype_ == DT_DROP_SEEN || common.serdroptype_ == DT_DROP_SEEN))) {
		if (tran_.errorcode_ == 0) {
			tran_.errorcode_ = 30000;
			tdstat_.errorbuf_ << "Request followed by Logout\n"sv;
		}	

		if (tran_.reslen_ == 0) {
			tran_.tupd_usec_ = common.tlastpkt_usec_;
			tran_.tres_usec_ = common.tlastpkt_usec_;

			tran_.reslen_ = 1;
		}	

		request_done();
	}	
	else {
		request_done(false /* flushreq */, true /* clear_req */);
	}	

	/*
	 * Send logout request
	 */
	set_new_req();

	tdstrbuf_ << "logout"sv;
	tran_.tupd_usec_ = common.tlastpkt_usec_;
	tran_.reqlen_ = 1;
	tran_.reslen_ = 1;
	tran_.tres_usec_ = common.tlastpkt_usec_;

	request_done();
}

void MONGO_SESSINFO::handle_ssl_change(PARSE_PKT_HDR & hdr, uint8_t *pdata)
{

}	

void MONGO_SESSINFO::set_new_req() noexcept
{
	COMMON_PROTO 				& common = svcsess_.common_;

	tran_.reset();

	tran_.treq_usec_			= common.tlastpkt_usec_;
	tran_.tupd_usec_			= common.tlastpkt_usec_;
	
	tdstrbuf_.reset();
	tdstat_.reset_on_req();
}	

int MONGO_SESSINFO::parse_req_pkt(PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	uint8_t				*ppkt_end, *sptr = pdata, *startsptr;
	int64_t 			lenpkt = hdr.datalen_;
	uint32_t			pktlen = hdr.datalen_, ncopy;
	int 				ret, tknlen;
	MG_OPCODE_E			opcode;
	auto				& common = svcsess_.common_;
	MG_MSG_HDR			thdr = {};
	int8_t				tlen;

	if (statmg_.skip_req_resp_till_ready_) {
		return 0;
	}

	if (statmg_.skip_to_req_after_resp_) {
		if (statmg_.skip_to_req_after_resp_ == 2) {
			
			if (pktlen > 8) {
				if (true == is_valid_req(pdata, pktlen, hdr.wirelen_, false /* is_init */)) {	

					tdstrbuf_.reset();
					statmg_.skip_to_req_after_resp_ = 0;
					goto start1;
				}	
				else if (is_ssl_sess_ == (int8_t)-1) {
					if (true == TLS_PROTO::is_tls_req_resp(pdata, hdr.datalen_, hdr.dir_, false /* is_init */)) {
						is_ssl_sess_ = 1;
						return 0;
					}	

					is_ssl_sess_ = 0;
				}	
			}	

			statmg_.skip_req_resp_till_ready_ = 1;
		}	

		statmg_.skip_to_req_after_resp_ = 1;
		return 0;
	}	

start1 :
	ppkt_end = sptr + lenpkt;

	if (statmg_.skip_till_auth_resp_) {
		return 0;
	}	

	if (is_ssl_sess_ == (int8_t)-1) {
		if (true == TLS_PROTO::is_tls_req_resp(pdata, hdr.datalen_, hdr.dir_, !is_midway_session_ /* is_init */)) {
			is_ssl_sess_ = 1;
			return 0;
		}	

		is_ssl_sess_ = 0;
	}	

	do {
		startsptr	= sptr;
		tlen 		= 0;

		std::memset(&thdr, 0, sizeof(thdr));

		if (statmg_.req_tkn_frag_ == 2 && statmg_.req_hdr_fraglen_ > 0 && statmg_.req_hdr_fraglen_ < sizeof(MG_MSG_HDR)) {

			if (lenpkt + statmg_.req_hdr_fraglen_ >= (int64_t)sizeof(MG_MSG_HDR)) {
				std::memcpy(&thdr, statmg_.reqhdr_, statmg_.req_hdr_fraglen_);
				std::memcpy((uint8_t *)&thdr + statmg_.req_hdr_fraglen_, sptr, sizeof(MG_MSG_HDR) - statmg_.req_hdr_fraglen_);

				tlen = sizeof(MG_MSG_HDR);

				sptr += sizeof(MG_MSG_HDR) - statmg_.req_hdr_fraglen_;
				lenpkt -= sizeof(MG_MSG_HDR) - statmg_.req_hdr_fraglen_;

				statmg_.req_tkn_frag_ = 0;
				statmg_.req_hdr_fraglen_ = 0;
			}	
			else {
				std::memcpy(statmg_.reqhdr_ + statmg_.req_hdr_fraglen_, sptr, lenpkt);
				statmg_.req_hdr_fraglen_ += lenpkt;
				return 0;
			}	
		}	

		if (statmg_.req_tkn_frag_ == 0) {
			if ((unsigned)lenpkt + (unsigned)tlen < sizeof(MG_MSG_HDR)) {
				statmg_.req_tkn_frag_ = 2;
				statmg_.req_hdr_fraglen_ = tlen + lenpkt;

				std::memcpy(statmg_.reqhdr_, &thdr, tlen);
				std::memcpy(statmg_.reqhdr_ + tlen, sptr, lenpkt);
				
				return 0;
			}	

			if ((unsigned)tlen < sizeof(MG_MSG_HDR)) {
				std::memcpy((uint8_t *)&thdr + tlen, sptr, sizeof(MG_MSG_HDR) - tlen);
				sptr += sizeof(MG_MSG_HDR) - tlen;
				lenpkt -= sizeof(MG_MSG_HDR) - tlen;
			}

			if (thdr.msglen_ <= sizeof(MG_MSG_HDR)) {
				reset_on_error();
				return -1;	
			}	

			tknlen = thdr.msglen_ - sizeof(MG_MSG_HDR);
			opcode = thdr.opcode_;

			if ((tdstrbuf_.size() == 0) && 
				((opcode != OP_UPDATE) && (opcode != OP_INSERT) && (opcode != OP_DELETE) && (opcode != OP_KILL_CURSORS))) {

				set_new_req();
			}

			if (lenpkt < tknlen) {
				statmg_.req_tkn_frag_ = 1;
				statmg_.req_hdr_fraglen_ = sizeof(MG_MSG_HDR);
				statmg_.nbytes_req_frag_ = 0;
				statmg_.skip_req_bytes_ = 0;

				std::memcpy(statmg_.reqhdr_, &thdr, sizeof(MG_MSG_HDR));
			}	
			else {
				ret = handle_req_token(thdr, sptr, tknlen);

				if (ret < 0) {
					reset_on_error();
					return -1;
				}	

				statmg_.reset_req_frag_stat();

				sptr += tknlen;
				lenpkt -= tknlen;
			}	
		}		

		if (statmg_.req_tkn_frag_ == 1) {
			if (statmg_.req_hdr_fraglen_ < sizeof(MG_MSG_HDR) || lenpkt < 0) {
				reset_on_error();
				return -1;
			}	

			std::memcpy(&thdr, statmg_.reqhdr_, sizeof(MG_MSG_HDR));

			tknlen = thdr.msglen_;
			opcode = thdr.opcode_;

			if (tknlen <= (int)sizeof(MG_MSG_HDR)) {
				reset_on_error();
				return -1;	
			}		
			tknlen -= sizeof(MG_MSG_HDR);

			if (statmg_.nbytes_req_frag_ > (uint32_t)tknlen || statmg_.nbytes_req_frag_ > max_mongo_req_token_) {
				reset_on_error();
				return -1;
			}	

			if (statmg_.nbytes_req_frag_ < max_mongo_req_token_) {

				ncopy = std::min<uint32_t>(max_mongo_req_token_ - statmg_.nbytes_req_frag_, tknlen - statmg_.nbytes_req_frag_);
				ncopy = std::min<uint32_t>(ncopy, lenpkt);

				if (opcode != OP_UPDATE && opcode != OP_INSERT && opcode != OP_DELETE) {
					std::memcpy(preqfragbuf_ + statmg_.nbytes_req_frag_, sptr, ncopy);
				}
				else {
					std::memcpy(preqfragbuf_ + statmg_.nbytes_req_frag_, sptr, std::min<uint32_t>(ncopy, 64));
				}	

				statmg_.nbytes_req_frag_ += ncopy;
				sptr += ncopy;
				lenpkt -= ncopy;
			}	

			auto			totlen = statmg_.nbytes_req_frag_ + statmg_.skip_req_bytes_;

			if (tknlen <= totlen + lenpkt) {

				if (statmg_.nbytes_req_frag_ == max_mongo_req_token_) {
					sptr += tknlen - totlen;
					lenpkt -= tknlen - totlen;
				}

				ret = handle_req_token(thdr, preqfragbuf_, statmg_.nbytes_req_frag_);

				if (ret < 0) {
					reset_on_error();
					return -1;
				}	

				statmg_.reset_req_frag_stat();
			}	
			else {
				if (lenpkt > 0) {
					statmg_.skip_req_bytes_ += lenpkt;
				}

				return 0;
			}	
		}		

	} while (sptr >= pdata && sptr < ppkt_end && lenpkt > 0 && sptr != startsptr);	

	return 0;
}

int MONGO_SESSINFO::parse_resp_pkt(PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	uint8_t				*ppkt_end, *sptr = pdata, *startsptr;
	uint32_t			pktlen = hdr.datalen_, ncopy;
	int64_t 			lenpkt = pktlen;
	int 				ret, tknlen;
	MG_OPCODE_E			opcode;
	auto				& common = svcsess_.common_;
	MG_MSG_HDR			thdr = {};
	int8_t				tlen;

	ppkt_end = sptr + lenpkt;

	if (statmg_.skip_req_resp_till_ready_) {
		if (pktlen > 8) {
			if (true == is_valid_resp(pdata, pktlen, hdr.wirelen_, false /* is_init */)) {	
				statmg_.reset_stats_on_resp(true);

				goto start1;
			}	
		}	

		return 0;
	}

start1 :
	if (statmg_.skip_to_req_after_resp_) {
		statmg_.skip_to_req_after_resp_ = 2;
		return 0;
	}	

	if (statmg_.skip_till_auth_resp_) {
		if (statmg_.skip_till_auth_resp_ == 1) {
			statmg_.skip_till_auth_resp_ = 2;
			return 0;
		}
		
		statmg_.skip_till_auth_resp_ = 0;
	}	

	do {
		startsptr	= sptr;
		tlen 		= 0;

		std::memset(&thdr, 0, sizeof(thdr));

		if (statmg_.resp_tkn_frag_ == 2 && statmg_.resp_hdr_fraglen_ > 0 && statmg_.resp_hdr_fraglen_ < sizeof(MG_MSG_HDR)) {

			if (lenpkt + statmg_.resp_hdr_fraglen_ >= (int64_t)sizeof(MG_MSG_HDR)) {
				std::memcpy(&thdr, statmg_.resphdr_, statmg_.resp_hdr_fraglen_);
				std::memcpy((uint8_t *)&thdr + statmg_.resp_hdr_fraglen_, sptr, sizeof(MG_MSG_HDR) - statmg_.resp_hdr_fraglen_);

				tlen = sizeof(MG_MSG_HDR);

				sptr += sizeof(MG_MSG_HDR) - statmg_.resp_hdr_fraglen_;
				lenpkt -= sizeof(MG_MSG_HDR) - statmg_.resp_hdr_fraglen_;

				statmg_.resp_tkn_frag_ = 0;
				statmg_.resp_hdr_fraglen_ = 0;
			}	
			else {
				std::memcpy(statmg_.resphdr_ + statmg_.resp_hdr_fraglen_, sptr, lenpkt);
				statmg_.resp_hdr_fraglen_ += lenpkt;
				return 0;
			}	
		}	

		if (statmg_.resp_tkn_frag_ == 0) {
			if ((unsigned)lenpkt + (unsigned)tlen < sizeof(MG_MSG_HDR)) {
				statmg_.resp_tkn_frag_ = 2;
				statmg_.resp_hdr_fraglen_ = tlen + lenpkt;

				std::memcpy(statmg_.resphdr_, &thdr, tlen);
				std::memcpy(statmg_.resphdr_ + tlen, sptr, lenpkt);
				
				return 0;
			}	

			if ((unsigned)tlen < sizeof(MG_MSG_HDR)) {
				std::memcpy((uint8_t *)&thdr + tlen, sptr, sizeof(MG_MSG_HDR) - tlen);
				sptr += sizeof(MG_MSG_HDR) - tlen;
				lenpkt -= sizeof(MG_MSG_HDR) - tlen;
			}

			if (thdr.msglen_ <= sizeof(MG_MSG_HDR)) {
				reset_on_error();
				return -1;	
			}	

			tknlen = thdr.msglen_ - sizeof(MG_MSG_HDR);
			opcode = thdr.opcode_;

			if (lenpkt < tknlen) {
				statmg_.resp_tkn_frag_ = 1;
				statmg_.resp_hdr_fraglen_ = sizeof(MG_MSG_HDR);
				statmg_.nbytes_resp_frag_ = 0;
				statmg_.skip_resp_bytes_ = 0;

				std::memcpy(statmg_.resphdr_, &thdr, sizeof(MG_MSG_HDR));
			}	
			else {
				uint8_t				*ptail = (tknlen > (int64_t)MG_RESP_TAIL_BYTES ? sptr + tknlen - MG_RESP_TAIL_BYTES : nullptr);
				int				ntail = (ptail ? MG_RESP_TAIL_BYTES : 0);

				ret = handle_resp_token(thdr, sptr, tknlen, ptail, ntail);

				if (ret < 0) {
					reset_on_error();
					return -1;
				}	

				statmg_.reset_resp_frag_stat();

				sptr += tknlen;
				lenpkt -= tknlen;
			}	
		}		

		if (statmg_.resp_tkn_frag_ == 1) {
			if (statmg_.resp_hdr_fraglen_ < sizeof(MG_MSG_HDR) || lenpkt < 0) {
				reset_on_error();
				return -1;
			}	

			std::memcpy(&thdr, statmg_.resphdr_, sizeof(MG_MSG_HDR));

			tknlen = thdr.msglen_;
			opcode = thdr.opcode_;

			if (tknlen <= (int64_t)sizeof(MG_MSG_HDR)) {
				reset_on_error();
				return -1;	
			}		
			tknlen -= sizeof(MG_MSG_HDR);

			if (statmg_.nbytes_resp_frag_ > (uint32_t)tknlen || statmg_.nbytes_resp_frag_ > max_mongo_resp_token_) {
				reset_on_error();
				return -1;
			}	

			if (statmg_.nbytes_resp_frag_ < max_mongo_resp_token_) {

				ncopy = std::min<uint32_t>(max_mongo_resp_token_ - statmg_.nbytes_resp_frag_, tknlen - statmg_.nbytes_resp_frag_);
				ncopy = std::min<uint32_t>(ncopy, lenpkt);

				std::memcpy(prespfragbuf_ + statmg_.nbytes_resp_frag_, sptr, ncopy);

				statmg_.nbytes_resp_frag_ += ncopy;
				sptr += ncopy;
				lenpkt -= ncopy;

				statmg_.nresp_tail_ = 0;
			}	

			auto			totlen = statmg_.nbytes_resp_frag_ + statmg_.skip_resp_bytes_;

			if (tknlen <= totlen + lenpkt) {

				if (statmg_.nbytes_resp_frag_ == max_mongo_resp_token_) {
					sptr += tknlen - totlen;
					lenpkt -= tknlen - totlen;
				}

				constexpr int			maxtail = MG_RESP_TAIL_BYTES + (MG_RESP_TAIL_BYTES >> 1);
				uint8_t				tailbuf[maxtail + MG_RESP_TAIL_BYTES + 8], *ptail = tailbuf;
				int				ntail = 0;

				if (opcode == OP_MSG) {
					if (pktlen < maxtail) {
						if (statmg_.nresp_tail_ > 0 && statmg_.nresp_tail_ <= MG_RESP_TAIL_BYTES) {
							ntail = statmg_.nresp_tail_;
							std::memcpy(tailbuf, statmg_.resptailbuf_, ntail);
						}	
						
						std::memcpy(tailbuf + ntail, pdata, pktlen);
						ntail += pktlen;
					}	
					else {
						ptail = pdata + pktlen - maxtail;
						ntail = maxtail;
					}	
				}

				ret = handle_resp_token(thdr, prespfragbuf_, statmg_.nbytes_resp_frag_, ptail, ntail);

				if (ret < 0) {
					reset_on_error();
					return -1;
				}	

				statmg_.reset_resp_frag_stat();
			}	
			else {
				if (opcode == OP_MSG && tknlen - totlen - lenpkt < MG_RESP_TAIL_BYTES) { 
					int			ntail = (pktlen > MG_RESP_TAIL_BYTES ? MG_RESP_TAIL_BYTES : pktlen);
					uint8_t			*ptail = pdata + pktlen - ntail;

					std::memcpy(statmg_.resptailbuf_, ptail, ntail);
					statmg_.nresp_tail_ = (uint8_t)ntail;
				}	
				else {
					statmg_.nresp_tail_ = 0;
				}	
				
				if (lenpkt > 0) {
					statmg_.skip_resp_bytes_ += lenpkt;
				}

				return 0;
			}	
		}		

	} while (sptr >= pdata && sptr < ppkt_end && lenpkt > 0 && sptr != startsptr);	

	return 0;
}

static inline std::string_view get_cstring_view(uint8_t * & sptr, int & maxlen) noexcept
{
	const char			*pstr = (const char *)sptr;
	std::string_view		sv {pstr, strnlen(pstr, maxlen)};

	sptr += sv.size() + ((int)sv.size() < maxlen);
	maxlen -= (sv.size() + ((int)sv.size() < maxlen));

	return sv;
}


int MONGO_SESSINFO::handle_req_token(const MG_MSG_HDR & hdr, uint8_t * sptr, int maxlen)
{
	const MG_OPCODE_E		opcode = hdr.opcode_;
	const uint32_t			tknlen = hdr.msglen_;
	const bool			istrunc = (maxlen < (int)tknlen);
	uint8_t				*pstart = sptr, *pend = sptr + maxlen, *ptmp;

	switch (opcode) {
	
	case OP_MSG :
		if (maxlen < 10) {
			return -1;
		}
		else {
			uint32_t			flags, tlen1;
			int				seclen, nsec = 0;
			uint8_t				cksum, moretocome, kind;
			auto				oldmax = maxlen;

			flags = unaligned_read_le32(sptr);
		
			cksum 		= flags & 1;
			moretocome 	= flags & 2;

			if (cksum && !istrunc) {
				pend -= 4;
				maxlen -= 4;
			}

			sptr += 4;
			maxlen -= 4;

			tdstrbuf_ << '{';

			while (maxlen > 5 && sptr < pend - 5) {
				kind = *sptr++;
				maxlen--;

				if (kind > MG_KIND_SEQ) {
					return -1;
				}	

				seclen = unaligned_read_le32(sptr);

				sptr += 4;
				maxlen -= 4;
				seclen -= 4;

				if (maxlen < 4) {
					break;
				}

				if (seclen > (int)tknlen || seclen < 1) {
					break;
				}	
				else if (seclen > maxlen) {
					seclen = maxlen;
				}	

				ptmp = sptr;
				oldmax = maxlen;

				sptr += seclen;
				maxlen -= seclen;

				nsec++;

				if (kind == MG_KIND_BODY) {
					if (nsec > 1) {
						tdstrbuf_ << ',';
					}

					req_parse_doc(opcode, ptmp, seclen, true, "BodyDocument"sv);
				}
				else {
					auto				sv = get_cstring_view(ptmp, seclen);
					int				ndocs = 0;

					if (sv.size() == 0) {
						break;
					}	

					if (seclen < 5) {
						break;
					}	
			
					if (nsec > 1) {
						tdstrbuf_ << ',';
					}

					tdstrbuf_.appendfmt("{ \"%s\": [ ", sv.data());

					while (seclen > 4 && ptmp < pend) {

						tlen1 = unaligned_read_le32(ptmp);
						if ((int)tlen1 > seclen) {
							tlen1 = seclen;
						}	

						if (tlen1 < 5) {
							break;
						}	

						seclen -= tlen1;
						ptmp += 4;
						tlen1 -= 4;
						
						if (ndocs++ > 0) {
							tdstrbuf_ << ',';
						}	
				
						req_parse_doc(opcode, ptmp, tlen1, true, "DocumentSequence"sv);
						
						ptmp += tlen1;
					}	

					tdstrbuf_ << " ] }"sv; 
				}	
			}

			tdstrbuf_ << '}';
			
			if (!moretocome) {
				statmg_.nready_resp_pending_++;

				if (statmg_.nready_resp_pending_ > 128) {
					gstats[STATMG_REQ_SYNC_OVF]++;
					
					// Simulate a drop to try to get in sync
					drop_seen_ = 1;
				}	
			}
		}
		break;

	case OP_QUERY :
		if (maxlen < 15) {
			return -1;
		}
		else {
			uint32_t			tlen1;
			int				nskip, nlimit;
		
			sptr += 4;
			maxlen -= 4;

			auto				sv = get_cstring_view(sptr, maxlen);

			if (sv.size() == 0) {
				return -1;
			}	

			if (maxlen < 13) {
				return -1;
			}	

			nskip = unaligned_read_le32(sptr);
			nlimit = unaligned_read_le32(sptr + 4);
			tlen1 = unaligned_read_le32(sptr + 8);

			sptr += 12;
			maxlen -= 12;
			tlen1 -= 4;

			if (tlen1 < 1 || tlen1 > tknlen) {
				return -1;
			}	

			if ((int)tlen1 > maxlen) {
				tlen1 = maxlen;
			}
			
			tdstrbuf_ << "{ \"query\": "sv;

			req_parse_doc(opcode, sptr, tlen1, true, "query"sv);

			sptr += tlen1;
			maxlen -= tlen1;

			if (maxlen > 4) {
				tlen1 = unaligned_read_le32(sptr);
				
				sptr += 4;
				maxlen -= 4;

				if (tlen1 > 5) {
					tlen1 -= 4;

					if ((int)tlen1 > maxlen) {
						tlen1 = maxlen;
					}
					
					tdstrbuf_ << ",\"returnFieldsSelector\" : "sv;

					req_parse_doc(opcode, sptr, tlen1, true, "returnFieldsSelector"sv);
				}	
			}	

			tdstrbuf_ << ", \"collection\": \""sv << sv << "\",\"skip\":"sv << nskip << ",\"limit\":"sv << nlimit << '}';

			statmg_.nready_resp_pending_++;

			if (statmg_.nready_resp_pending_ > 128) {
				gstats[STATMG_REQ_SYNC_OVF]++;
				
				// Simulate a drop to try to get in sync
				drop_seen_ = 1;
			}	
		}
		break;

	case OP_COMPRESSED :
		if (maxlen < (int)sizeof(MG_COMP_HDR)) {
			return -1;
		}
		else {
			MG_COMP_HDR			chdr;

			std::memcpy(&chdr, sptr, sizeof(chdr));

			sptr 	+= sizeof(MG_COMP_HDR);
			maxlen	-= sizeof(MG_COMP_HDR);

			if (chdr.compid_ == 0) {
				MG_MSG_HDR		mhdr(hdr);

				mhdr.opcode_		= chdr.actop_;
				mhdr.msglen_		= chdr.uncomp_sz_;

				return handle_req_token(mhdr, sptr, maxlen);
			}	
			else {
				ncomp_req_++;

				if (ncomp_resp_ > 0 || ncomp_req_ > 8) {
					skip_session_ = 1;
					gstats[STATMG_SKIP_SESS_COMP]++;
					return -1;
				}

				tdstrbuf_ << "{ \"Compressed Request\" : \"Session will be skipped as Compression not supported currently.\" }"sv;
				
				statmg_.nready_resp_pending_++;

				if (statmg_.nready_resp_pending_ > 128) {
					gstats[STATMG_REQ_SYNC_OVF]++;
					
					// Simulate a drop to try to get in sync
					drop_seen_ = 1;
				}	
			}	
		}
		break;
	
	case OP_GET_MORE :
		if (maxlen < 18) {
			return -1;
		}
		else {
			int64_t				cursorid;
			uint32_t			tlen1;
			int				nrows;
		
			sptr += 4;
			maxlen -= 4;

			auto				sv = get_cstring_view(sptr, maxlen);

			if (sv.size() == 0) {
				return -1;
			}	

			if (maxlen < 12) {
				return -1;
			}	

			nrows = unaligned_read_le32(sptr);
			cursorid = unaligned_read_le64(sptr + 4);

			tdstrbuf_ << "{ \"Cursor getMore\" : { \"collection\": \""sv << sv << "\",\"nrows\":"sv << nrows << ",\"Cursor Text\": \""sv
						<< get_cursor_text(cursorid) << "\" } }"sv;

			statmg_.nready_resp_pending_++;

			if (statmg_.nready_resp_pending_ > 128) {
				gstats[STATMG_REQ_SYNC_OVF]++;
				
				// Simulate a drop to try to get in sync
				drop_seen_ = 1;
			}	
		}
		break;

	case OP_KILL_CURSORS :
		if (maxlen < 8) {
			return -1;
		}
		else {
			int64_t				cursorid;
			int				ncur;
		
			sptr += 4;
			maxlen -= 4;

			ncur = unaligned_read_le32(sptr);
			
			sptr += 4;
			maxlen -= 4;
			
			while (ncur-- > 0 && maxlen >= 8 && sptr + 8 < pend) {
				cursorid = unaligned_read_le64(sptr);
				
				sptr += 8;
				maxlen -= 8;

				close_cursor(cursorid);
			}
		}
		break;

	/*
	 * We do not support these older opcodes as no response expected...
	 * The pdata may only be updated upto 64 bytes as well...
	 */
	case OP_UPDATE :
	case OP_INSERT :
	case OP_DELETE :
	default :
		break;
	}

	return 0;
}

int MONGO_SESSINFO::handle_resp_token(const MG_MSG_HDR & hdr, uint8_t * sptr, int maxlen, uint8_t *tailbuf, int ntail)
{
	const MG_OPCODE_E		opcode = hdr.opcode_;
	const uint32_t			tknlen = hdr.msglen_;
	const bool			istrunc = (maxlen < (int)tknlen);
	uint8_t				*pstart = sptr, *pend = sptr + maxlen, *ptmp;

	switch (opcode) {
	
	case OP_MSG :
		if (statmg_.skip_req_resp_till_ready_) {
			statmg_.skip_req_resp_till_ready_ = 0;
		}

		if (maxlen < 10) {
			return -1;
		}
		else {
			uint32_t			flags, tlen1;
			int				seclen, nsec = 0;
			uint8_t				cksum, moretocome, kind;
			auto				oldmax = maxlen;
			bool				chk_cursor = false;

			flags = unaligned_read_le32(sptr);
		
			cksum 		= flags & 1;
			moretocome 	= flags & 2;

			if (moretocome) {
				// Only parse last msg
				return 0;
			}

			if (cksum && !istrunc) {
				pend -= 4;
				maxlen -= 4;
			}

			sptr += 4;
			maxlen -= 4;

			// Only parse 1 section
			if (maxlen > 5 && sptr < pend - 5) {
				kind = *sptr++;
				maxlen--;

				if (kind > MG_KIND_SEQ) {
					goto done;
				}	

				seclen = unaligned_read_le32(sptr);

				sptr += 4;
				maxlen -= 4;
				seclen -= 4;

				if (maxlen < 4) {
					goto done;
				}

				if (seclen > (int)tknlen || seclen < 1) {
					goto done;
				}	
				else if (seclen > maxlen) {
					seclen = maxlen;
				}	

				ptmp = sptr;
				oldmax = maxlen;

				sptr += seclen;
				maxlen -= seclen;

				nsec++;

				if (kind == MG_KIND_BODY) {
					chk_cursor = resp_parse_doc(opcode, ptmp, seclen, true, "TopResp"sv);
				}
				else {
					auto				sv = get_cstring_view(ptmp, seclen);

					if (sv.size() == 0) {
						break;
					}	

					if (seclen < 5) {
						break;
					}	
			
					while (seclen > 4 && ptmp < pend) {

						tlen1 = unaligned_read_le32(ptmp);
						if ((int)tlen1 > seclen) {
							tlen1 = seclen;
						}	

						if (tlen1 < 5) {
							break;
						}	

						seclen -= tlen1;
						ptmp += 4;
						tlen1 -= 4;
						
						chk_cursor = resp_parse_doc(opcode, ptmp, tlen1, true, "TopResp"sv);
						
						// Only first doc
						break;
					}	
				}	
			}

done :			
			if (chk_cursor && ntail > 32 && tailbuf) {
				check_for_cursor(tailbuf, ntail);
			}	
			
			if (statmg_.nready_resp_pending_ > 0) {
				statmg_.nready_resp_pending_--;

				if (tdstrbuf_.size() && statmg_.nready_resp_pending_ > 0 && (svcsess_.common_.tlastpkt_usec_ > (tran_.treq_usec_ + 10 * GY_USEC_PER_MINUTE))) {

					gstats[STATMG_REQ_SYNC_TIMEOUT]++;
					statmg_.nready_resp_pending_ = 0;
				}	

				if (statmg_.nready_resp_pending_ == 0) {
					request_done();
				}
			}
			else if (tdstrbuf_.size()) {
				request_done();
			}	
		}
		break;
	

	case OP_REPLY :
		if (maxlen < 20) {
			return -1;
		}	
		else {
			int64_t				curid;
			uint32_t			flags, tlen1, ndocs;
			uint8_t				curnotfound;

			flags = unaligned_read_le32(sptr);
		
			curnotfound 	= flags & 1;

			curid = unaligned_read_le64(sptr + 4);
			ndocs = unaligned_read_le32(sptr + 16);

			sptr += 20;
			maxlen -= 20;

			if (0 == curid && statmg_.curr_req_cursorid_) {
				close_cursor(statmg_.curr_req_cursorid_);
			}
			else if (curid && statmg_.curr_req_cursorid_ == 0 && tdstrbuf_.size()) {
				add_cursor(curid);
			}	

			if (ndocs > 0 && maxlen > 5) {
				// Just parse 1st doc
				tlen1 = unaligned_read_le32(sptr);
				
				if (tlen1 > tknlen || tlen1 < 5) {
					break;
				}	
				else if ((int)tlen1 > maxlen) {
					tlen1 = maxlen;
				}	

				sptr += 4;
				maxlen -= 4;
				tlen1 -= 4;

				resp_parse_doc(opcode, sptr, tlen1, true, "TopResp"sv);
			}	

			if (statmg_.nready_resp_pending_ > 0) {
				statmg_.nready_resp_pending_--;

				if (tdstrbuf_.size() && statmg_.nready_resp_pending_ > 0 && (svcsess_.common_.tlastpkt_usec_ > (tran_.treq_usec_ + 10 * GY_USEC_PER_MINUTE))) {

					gstats[STATMG_REQ_SYNC_TIMEOUT]++;
					statmg_.nready_resp_pending_ = 0;
				}	

				if (statmg_.nready_resp_pending_ == 0) {
					request_done();
				}
			}
			else if (tdstrbuf_.size()) {
				request_done();
			}	
		}
		break;

	case OP_COMPRESSED :
		if (maxlen < (int)sizeof(MG_COMP_HDR)) {
			return -1;
		}
		else {
			MG_COMP_HDR			chdr;

			std::memcpy(&chdr, sptr, sizeof(chdr));

			sptr 	+= sizeof(MG_COMP_HDR);
			maxlen	-= sizeof(MG_COMP_HDR);

			if (chdr.compid_ == 0) {
				MG_MSG_HDR		mhdr(hdr);

				mhdr.opcode_		= chdr.actop_;
				mhdr.msglen_		= chdr.uncomp_sz_;

				return handle_resp_token(mhdr, sptr, maxlen, tailbuf, ntail);
			}	
			else {
				ncomp_resp_++;

				if (ncomp_req_ > 0 || ncomp_resp_ > 10) {
					skip_session_ = 1;
					gstats[STATMG_SKIP_SESS_COMP]++;
					return -1;
				}

				if (statmg_.nready_resp_pending_ > 0) {
					statmg_.nready_resp_pending_--;

					if (tdstrbuf_.size() && statmg_.nready_resp_pending_ > 0 && (svcsess_.common_.tlastpkt_usec_ > (tran_.treq_usec_ + 10 * GY_USEC_PER_MINUTE))) {

						gstats[STATMG_REQ_SYNC_TIMEOUT]++;
						statmg_.nready_resp_pending_ = 0;
					}	

					if (statmg_.nready_resp_pending_ == 0) {
						request_done();
					}
				}
				else if (tdstrbuf_.size()) {
					request_done();
				}	
			}	
		}
		break;
	
	default :
		break;
	}

	return 0;
}	

void MONGO_SESSINFO::req_parse_doc(MG_OPCODE_E opcode, uint8_t *ptmp, int tlen, bool is_doc, std::string_view parent_key)
{
	if (tlen < 3) return;

	uint8_t				*pend = ptmp + tlen;
	int64_t				n64;
	int				nelems = 0, elen;
	bool				saslstart = false, is_auth = false, authenticate = false, clusterAuthenticate = false, is_speculative = false;
	MG_AUTH_MECH_E			amech = AMECH_NONE;

	if (is_doc) {
		tdstrbuf_ << '{';
	}	
	else {
		tdstrbuf_ << '[';
	}	

	while (tlen > 3 && ptmp + 3 < pend) {
		uint8_t				type, btype; 
		
		type 				= *ptmp++;
		tlen--;

		auto				sv = get_cstring_view(ptmp, tlen);

		if (sv.size() == 0) {
			break;
		}	
		
		if (type < BSON_DOUBLE || type > BSON_LONG_DOUBLE) {
			break;
		}	

		if (nelems++ > 0) {
			tdstrbuf_ << ',';
		}	

		if (tlen < 1) {
			if (type == BSON_UNDEFINED) {
				if (is_doc) {
					tdstrbuf_ << '"' << sv << "\": "sv;
				}	
				tdstrbuf_ << "undefined"sv;
			}	
			else if (type == BSON_NULL) {
				if (is_doc) {
					tdstrbuf_ << '"' << sv << "\": "sv;
				}	
				tdstrbuf_ << "null"sv;
			}	

			break;
		}

		if (sv == "saslStart"sv) {
			saslstart = true;
			is_auth = true;
			is_speculative = (parent_key == "speculativeAuthenticate"sv);
		}
		else if (sv == "authenticate"sv) {
			authenticate = true;
			is_auth = true;
		}	
		else if (sv == "clusterAuthenticate"sv) {
			clusterAuthenticate = true;
			is_auth = true;
		}	

		if (is_doc) {
			tdstrbuf_ << '"' << sv << "\": "sv;
		}	

		switch (type) {

		case BSON_DOUBLE :
			if (tlen < 8) {
				goto done;
			}	
			else {
				double				dbl;

				std::memcpy(&dbl, ptmp, sizeof(dbl));
				tdstrbuf_ << dbl;

				ptmp += 8;
				tlen -= 8;
			}	
			break;

		case BSON_STRING :
		case BSON_JAVASCRIPT :
		case BSON_SYMBOL :

			if (tlen < 4) {
				goto done;
			}	
			else {
				elen = unaligned_read_le32(ptmp);

				ptmp += 4;
				tlen -= 4;

				if (elen > tlen) {
					elen = tlen;
				}	

				auto			tsv = std::string_view((const char *)ptmp, elen > 1 ? elen - 1 : 0);

				tdstrbuf_ << '"' << tsv << '"';
				
				if (type == BSON_STRING) {
					if (is_auth) {
						if (saslstart && sv == "mechanism"sv) {
							/*
							 * XXX Currently we support only SCRAM and PLAIN mech
							 */
							if (tsv == AUTH_SASL_PLAIN_SV) {
								amech = AMECH_SASL_PLAIN;
							}	
							else if (tsv == AUTH_SCRAM_SHA1_SV) {
								amech = AMECH_SCRAM_SHA1;
							}	
							else if (tsv == AUTH_SCRAM_SHA256_SV) {
								amech = AMECH_SCRAM_SHA256;
							}	
						}	
						else if (authenticate || clusterAuthenticate) {
							if (sv == "user"sv) {
								tdstat_.userbuf_.reset().append(tsv);
							}
						}	
					}	

					if (sv == "name"sv && parent_key == "application"sv) {
						tdstat_.appbuf_.reset().append(tsv);
					}	
				}

				ptmp += elen;
				tlen -= elen;
			}	
			break;
		
		case BSON_DOCUMENT :
		case BSON_ARRAY :
			if (tlen < 4) {
				goto done;
			}	
			else {
				elen = unaligned_read_le32(ptmp);

				ptmp += 4;
				tlen -= 4;
				elen -= 4;

				if (elen > tlen) {
					elen = tlen;
				}	

				if (elen < 1) {
					goto done;
				}
				else {
					/*
					 * Stack Overflow not expected as the tlen will less than max_mongo_req_token_
					 */
					req_parse_doc(opcode, ptmp, elen, type == BSON_DOCUMENT, sv);

					ptmp += elen;
					tlen -= elen;
				}
			}	
			break;

		case BSON_BINARY :
			if (tlen < 5) {
				goto done;
			}	
			else {
				elen = unaligned_read_le32(ptmp);

				ptmp += 4;
				tlen -= 4;

				btype = *ptmp++;
				tlen--;

				if (elen > tlen) {
					elen = tlen;
				}	
				
				if (amech != AMECH_NONE && saslstart) {
					tdstat_.userbuf_.reset();

					if (amech == AMECH_SCRAM_SHA256 || amech == AMECH_SCRAM_SHA1) {
						const char		*puser = (const char *)ptmp, *puend = puser + elen, *pt1 = puser;

						while (puser < puend) {
							if (*puser == '=' && puser > pt1 && puser[-1] == 'n' && puser < puend - 2) {
								puser++;
								pt1 = puser;
								while (pt1 + 1 < puend && *pt1 != ',') pt1++;

								std::string_view	user(puser, pt1 - puser);

								tdstrbuf_ << "\"*login* "sv << user << '"';

								tdstat_.userbuf_ << user;
								break;
							}	

							puser++;
						}	
					}
					else if (amech == AMECH_SASL_PLAIN) {
						const char		*puser = (const char *)ptmp, *puend = puser + elen, *pt1 = puser;

						while (puser < puend && *puser) puser++;

						puser++;
						pt1 = puser;

						while (pt1 + 1 < puend && *pt1 != 0) pt1++;

						std::string_view	user(puser, pt1 - puser);

						tdstrbuf_ << "\"*login* "sv << user << '"';
						tdstat_.userbuf_ << user;
					}	

					if (is_speculative && tdstat_.userbuf_.size()) {
						statmg_.skip_till_auth_resp_ = 1;
					}	
				}
				else {
					tdstrbuf_ << "\"<Binary Data>\""sv;
				}

				ptmp += elen;
				tlen -= elen;
			}
			break;

		case BSON_UNDEFINED :
			tdstrbuf_ << "undefined"sv;
			break;

		case BSON_OBJECTID :
			if (tlen < 12) {
				goto done;
			}	
			else {
				tdstrbuf_ << "\"<ObjectID>\""sv;

				ptmp += 12;
				tlen -= 12;
			}	
			break;
		
		case BSON_BOOLEAN :
			if (tlen < 1) {
				goto done;
			}	
			else {
				if (*ptmp == 0) {
					tdstrbuf_ << "false"sv;
				}
				else {
					tdstrbuf_ << "true"sv;
				}

				ptmp++;
				tlen--;
			}	
			break;

		case BSON_UTC_DATETIME :
			if (tlen < 8) {
				goto done;
			}	
			else {
				uint64_t			tmsec;
				struct timeval			tv;

				tmsec = unaligned_read_le64(ptmp);

				tv.tv_sec 	= tmsec/1000;
				tv.tv_usec	= (tmsec % 1000) * 1000;

				tdstrbuf_.appendfmt("\"%s\"", gy_utc_time_iso8601_usec(tv).get());

				ptmp += 8;
				tlen -= 8;
			}	
			break;

		case BSON_NULL :
			tdstrbuf_ << "null"sv;
			break;

		case BSON_REGEX :
			if (tlen < 4) {
				goto done;
			}	
			else {
				auto				sv1 = get_cstring_view(ptmp, tlen);

				if (tlen < 1) {
					goto done;
				}	

				auto				sv2 = get_cstring_view(ptmp, tlen);

				tdstrbuf_ << "regex(\""sv << sv1 << ", \""sv << sv2 <<  "\")"sv;
			}
			break;
	
		case BSON_DBPOINTER :
			if (tlen < 16) {
				goto done;
			}	
			else {
				elen = unaligned_read_le32(ptmp);

				ptmp += 4;
				tlen -= 4;

				ptmp += elen + 12;
				tlen -= (elen + 12);

				tdstrbuf_ << "DBPointer()"sv;
			}	
			break;
	
		case BSON_JAVASCRIPT_SCOPE :
			if (tlen < 5) {
				goto done;
			}	
			else {
				elen = unaligned_read_le32(ptmp);

				ptmp += 4 + elen;
				tlen -= (4 + elen);

				tdstrbuf_ << "JavascriptWithScope()"sv;
			}	
			break;
	
		case BSON_INT32 :
			if (tlen < 4) {
				goto done;
			}	
			else {
				elen = unaligned_read_le32(ptmp);

				ptmp += 4;
				tlen -= 4;

				tdstrbuf_ << elen;
			}	
			break;

		case BSON_INT64 :
			if (tlen < 8) {
				goto done;
			}	
			else {
				n64 = unaligned_read_le64(ptmp);

				ptmp += 8;
				tlen -= 8;

				if (sv == "getMore"sv) {
					tdstrbuf_ << "\"/* Cursor getMore : "sv << get_cursor_text(n64) << " */\""sv;
				}	
				else {
					tdstrbuf_ << n64;
				}	
			}	
			break;

		case BSON_TIMESTAMP :
			if (tlen < 8) {
				goto done;
			}	
			else {
				ptmp += 8;
				tlen -= 8;

				tdstrbuf_ << "BinaryTimestamp"sv;
			}	
			break;
			
		case BSON_LONG_DOUBLE :
			if (tlen < 16) {
				goto done;
			}	
			else {
				ptmp += 16;
				tlen -= 16;

				tdstrbuf_ << "<Decimal128>"sv;
			}	
			break;

		default :
			goto done;
			
		}	
	} // while loop
	
done :	
	if (is_doc) {
		tdstrbuf_ << '}';
	}	
	else {
		tdstrbuf_ << ']';
	}	
}

bool MONGO_SESSINFO::resp_parse_doc(MG_OPCODE_E opcode, uint8_t *ptmp, int tlen, bool is_doc, std::string_view parent_key)
{
	if (tlen < 3) return false;

	uint8_t				*pend = ptmp + tlen;
	int64_t				n64;
	uint64_t			curid = ~0ul;
	int				nelems = 0, elen, errcode = 0;
	std::string_view		errmsg;
	bool				chk_cursor = false;
	tribool				is_cursor = indeterminate, is_ok = indeterminate;

	while (tlen > 3 && ptmp + 3 < pend) {
		uint8_t				type, btype;
		
		type 				= *ptmp++;
		tlen--;

		auto				sv = get_cstring_view(ptmp, tlen);

		if (sv.size() == 0) {
			break;
		}	
		
		if (type < BSON_DOUBLE || type > BSON_LONG_DOUBLE) {
			break;
		}	

		nelems++;

		if (tlen < 1) {
			break;
		}

		if (opcode == OP_MSG && (parent_key == "cursor"sv) && (sv == "firstBatch"sv || sv == "nextBatch"sv)) {
			is_cursor = true;
		}

		switch (type) {

		case BSON_DOUBLE :
			if (tlen < 8) {
				goto done;
			}	
			else {
				double				dbl;
			
				if (sv == "ok"sv && parent_key == "TopResp"sv) {
					std::memcpy(&dbl, ptmp, sizeof(dbl));

					is_ok = (dbl == 1.0);
				}

				ptmp += 8;
				tlen -= 8;
			}	
			break;

		case BSON_STRING :
		case BSON_JAVASCRIPT :
		case BSON_SYMBOL :

			if (tlen < 4) {
				goto done;
			}	
			else {
				elen = unaligned_read_le32(ptmp);

				ptmp += 4;
				tlen -= 4;

				if (elen > tlen) {
					elen = tlen;
				}	

				if (type == BSON_STRING) {
					auto			tsv = std::string_view((const char *)ptmp, elen > 1 ? elen - 1 : 0);

					if (sv == "errmsg"sv && ((parent_key == "TopResp"sv) || (gy_isdigit_ascii(*parent_key.data())))) {
						errmsg = tsv;
					}	
				}

				ptmp += elen;
				tlen -= elen;
			}	
			break;
		
		case BSON_DOCUMENT :
		case BSON_ARRAY :
			if (tlen < 4) {
				goto done;
			}	
			else {
				elen = unaligned_read_le32(ptmp);

				ptmp += 4;
				tlen -= 4;
				elen -= 4;

				if (elen > tlen) {
					elen = tlen;
				}	

				if (elen < 1) {
					goto done;
				}
				else {
					if ((parent_key == "TopResp"sv) || (type == BSON_ARRAY && parent_key == "writeErrors"sv)) {
						chk_cursor = resp_parse_doc(opcode, ptmp, elen, type == BSON_DOCUMENT, sv);
					}

					ptmp += elen;
					tlen -= elen;
				}
			}	
			break;

		case BSON_BINARY :
			if (tlen < 5) {
				goto done;
			}	
			else {
				elen = unaligned_read_le32(ptmp);

				ptmp += 4;
				tlen -= 4;

				btype = *ptmp++;
				tlen--;

				if (elen > tlen) {
					elen = tlen;
				}	
				
				ptmp += elen;
				tlen -= elen;
			}
			break;

		case BSON_UNDEFINED :
			break;

		case BSON_OBJECTID :
			if (tlen < 12) {
				goto done;
			}	
			else {
				ptmp += 12;
				tlen -= 12;
			}	
			break;
		
		case BSON_BOOLEAN :
			if (tlen < 1) {
				goto done;
			}	
			else {
				ptmp++;
				tlen--;
			}	
			break;

		case BSON_UTC_DATETIME :
			if (tlen < 8) {
				goto done;
			}	
			else {
				ptmp += 8;
				tlen -= 8;
			}	
			break;

		case BSON_NULL :
			break;

		case BSON_REGEX :
			if (tlen < 4) {
				goto done;
			}	
			else {
				auto				sv1 = get_cstring_view(ptmp, tlen);

				if (tlen < 1) {
					goto done;
				}	

				auto				sv2 = get_cstring_view(ptmp, tlen);
			}
			break;
	
		case BSON_DBPOINTER :
			if (tlen < 16) {
				goto done;
			}	
			else {
				elen = unaligned_read_le32(ptmp);

				ptmp += 4;
				tlen -= 4;

				ptmp += elen + 12;
				tlen -= (elen + 12);
			}	
			break;
	
		case BSON_JAVASCRIPT_SCOPE :
			if (tlen < 5) {
				goto done;
			}	
			else {
				elen = unaligned_read_le32(ptmp);

				ptmp += 4 + elen;
				tlen -= (4 + elen);
			}	
			break;
	
		case BSON_INT32 :
			if (tlen < 4) {
				goto done;
			}	
			else {
				if (sv == "code"sv && ((parent_key == "TopResp"sv) || (gy_isdigit_ascii(*parent_key.data())))) {
					errcode = unaligned_read_le32(ptmp);
				}

				ptmp += 4;
				tlen -= 4;
			}	
			break;

		case BSON_INT64 :
			if (tlen < 8) {
				goto done;
			}	
			else {
				if (is_cursor && (sv == "id"sv) && (parent_key == "cursor"sv)) {
					curid = unaligned_read_le64(ptmp);
				}	

				ptmp += 8;
				tlen -= 8;
			}	
			break;

		case BSON_TIMESTAMP :
			if (tlen < 8) {
				goto done;
			}	
			else {
				ptmp += 8;
				tlen -= 8;
			}	
			break;
			
		case BSON_LONG_DOUBLE :
			if (tlen < 16) {
				goto done;
			}	
			else {
				ptmp += 16;
				tlen -= 16;
			}	
			break;

		default :
			goto done;
			
		}	
	} // while loop
	
done :	

	if (errcode != 0 && errmsg.size()) {
		auto 			it = gerrset_.find(errcode); 
		
		tran_.errorcode_ = errcode;
		tdstat_.is_serv_err_ = (it != gerrset_.end());
		
		tdstat_.errorbuf_ << "{ \"ErrorMsg\" : \""sv << errmsg << "\" }"sv;
	}

	if (curid != ~0lu) {
		if (0 == curid && statmg_.curr_req_cursorid_) {
			close_cursor(statmg_.curr_req_cursorid_);
		}
		else if (curid && statmg_.curr_req_cursorid_ == 0 && tdstrbuf_.size()) {
			add_cursor(curid);
		}	
	}	
	
	return (chk_cursor || (is_cursor && (curid == ~0lu) && (is_ok || indeterminate(is_ok))));
}


std::string_view MONGO_SESSINFO::get_cursor_text(int64_t curid)
{
	auto			it = dsql_map_.find(curid);
	std::string_view	sv;
	
	if (it != dsql_map_.end()) {
		auto			& cinfo = it->second;
		
		cinfo.tlastsec_ = svcsess_.common_.tlastpkt_usec_/GY_USEC_PER_SEC;

		sv = {cinfo.dyn_sql_, cinfo.get_len()};

		statmg_.curr_req_cursorid_ = curid;

		tdstat_.dyn_prep_reqnum_ = cinfo.dyn_prep_reqnum_;
		tdstat_.dyn_prep_time_t_ = cinfo.dyn_prep_time_t_;

		gstats[STATMG_CURSOR_FIND_OK]++;
	}	
	else {
		sv = {"", 0};

		statmg_.curr_req_cursorid_ = 0;

		tdstat_.dyn_prep_reqnum_ = 0;
		tdstat_.dyn_prep_time_t_ = 0;

		gstats[STATMG_CURSOR_FIND_FAIL]++;
	}	
	
	return sv;
}

void MONGO_SESSINFO::add_cursor(int64_t curid)
{
	auto				it = dsql_map_.find(curid);
	time_t				preptime = tran_.treq_usec_/GY_USEC_PER_SEC, tmin;
	int				ndel;

	if (it != dsql_map_.end()) {
		auto			& curinfo = it->second;

		it->second.~MG_CURSOR();

		new (&it->second) MG_CURSOR(tdstrbuf_.data(), tdstrbuf_.size(), tdstat_.reqnum_, preptime);

		return;
	}
	
	if (dsql_map_.size() < MG_MAX_SESS_CURSORS) {
add :		
		dsql_map_.try_emplace(curid, tdstrbuf_.data(), tdstrbuf_.size(), tdstat_.reqnum_, preptime);

		gstats[STATMG_CURSOR_ADD]++;
		return;
	}	

	tmin = preptime - 300;
	ndel = 0;

	for (auto cit = dsql_map_.begin(); cit != dsql_map_.end();) {
		if (cit->second.tlastsec_ < tmin) {
			cit = dsql_map_.erase(cit);
			++ndel;

			gstats[STATMG_CURSOR_DEL]++;
			continue;
		}	
		++it;	
	}
	
	if (ndel > 0) {
		goto add;
	}	

	gstats[STATMG_CURSOR_ADD_SKIP]++;
}

bool MONGO_SESSINFO::close_cursor(int64_t curid)
{
	bool				bret;

	if (curid == 0) return false;

	bret = dsql_map_.erase(curid);
	if (bret) {
		gstats[STATMG_CURSOR_DEL]++;
	}	
	
	if (curid == statmg_.curr_req_cursorid_) {
		statmg_.curr_req_cursorid_ = 0;
	}	

	return bret;
}

bool MONGO_SESSINFO::check_for_cursor(uint8_t *tailbuf, uint32_t ntail)
{
	static constexpr uint8_t	idbuf[] = "\x12\x69\x64\x00", nsbuf[] = "\x02\x6e\x73\x00", 
					okbuf[] = "\x01\x6f\x6b\x00\x00\x00\x00\x00\x00\x00\xf0\x3f";

	uint8_t				*ptmp = tailbuf, *pend = tailbuf + ntail, *pcursor = nullptr;
	int64_t				curid = 0;
	uint32_t			tlen;
	bool				found = false;
					
	while (ptmp + 32 < pend && ptmp >= tailbuf) {				

		ptmp = (uint8_t *)memmem(ptmp, ntail, idbuf, sizeof(idbuf) - 1);
		if (!ptmp) {
			return false;
		}	

		if (ptmp + 32 > pend) {
			return false;
		}	

		ptmp += (sizeof(idbuf) - 1);
		pcursor = ptmp;
		
		ptmp += 8;
		if (memcmp(ptmp, nsbuf, sizeof(nsbuf) - 1)) {
			continue;
		}	
		
		ptmp += (sizeof(nsbuf) - 1);

		tlen = unaligned_read_le32(ptmp);

		if (!tlen || (ptmp + 4 + tlen + sizeof(okbuf) - 1 >= pend)) {
			return false;
		}	
		
		ptmp += 4 + tlen;
		
		if (*ptmp == 0) {
			ptmp++;
			if (ptmp + sizeof(okbuf) - 1 >= pend) {
				return false;
			}	
		}	

		if (memcmp(ptmp, okbuf, sizeof(okbuf) - 1)) {
			continue;
		}	

		found = true;
		break;
	}

	if (!found || !pcursor) {
		return false;
	}

	curid = unaligned_read_le64(pcursor);

	if (0 == curid && statmg_.curr_req_cursorid_) {
		close_cursor(statmg_.curr_req_cursorid_);
	}
	else if (curid && statmg_.curr_req_cursorid_ == 0 && tdstrbuf_.size()) {
		add_cursor(curid);
	}	

	return true;
}	

void MONGO_SESSINFO::request_done(bool flushreq, bool clear_req)
{
	if (tdstrbuf_.size() > 0) {
		tran_.request_len_ = tdstrbuf_.size() + 1;
	}

	if (part_query_started_ == 1) {
		drop_partial_req();
		part_query_started_ = 0;
	}

	if (tran_.reqlen_ > 0) {
		if ((tran_.reslen_ != 0) || (svcsess_.common_.tlastpkt_usec_ > (tran_.treq_usec_ + 2 * GY_USEC_PER_SEC))) {
			if (flushreq) {
				print_req();
			}
		}

		tran_.reset();
		tdstrbuf_.reset();
		tdstat_.reset_on_req();
	}

	statmg_.reset_stats_on_resp(clear_req);
}


void MONGO_SESSINFO::reset_on_error()
{
	request_done(false /* flushreq */, true /* clear_req */);

	if (svcsess_.common_.currdir_ == DirPacket::DirInbound) {
		statmg_.skip_to_req_after_resp_ = 1;
		gstats[STATMG_REQ_RESET_ERR]++;
	}
	else {
		gstats[STATMG_RESP_RESET_ERR]++;
	}	
}

bool MONGO_SESSINFO::print_req() noexcept
{
	auto				& apihdlr = get_api_hdlr();

	try {
		if (tdstrbuf_.size() == 0 || tran_.reslen_ == 0) {
			return false;
		}	

		if (tdstrbuf_.size() > get_api_max_len()) {
			tdstrbuf_.set_len_external(get_api_max_len());
		}	

		uint8_t				*pone = apihdlr.get_xfer_pool_buf();
		if (!pone) {
			return false;
		}	

		STR_WR_BIN			ustrbuf(pone + sizeof(API_TRAN) + tdstrbuf_.size() + 1, MAX_PARSE_EXT_LEN);
		API_TRAN			*ptran = (API_TRAN *)pone;
		uint8_t				next = 0;
		
		std::memcpy(ptran, &tran_, sizeof(tran_));
		std::memcpy(ptran + 1, tdstrbuf_.data(), tdstrbuf_.size() + 1);

		ustrbuf << next;

		if (tdstat_.userbuf_.size() && ustrbuf.bytes_left() >= sizeof(PARSE_FIELD_LEN) + tdstat_.userbuf_.size() + 1) {
			next++;
			ustrbuf << PARSE_FIELD_LEN(EFIELD_USERNAME, tdstat_.userbuf_.size() + 1) << std::string_view(tdstat_.userbuf_.data(), tdstat_.userbuf_.size() + 1);
		}	

		if (tdstat_.appbuf_.size() && ustrbuf.bytes_left() >= sizeof(PARSE_FIELD_LEN) + tdstat_.appbuf_.size() + 1) {
			next++;
			ustrbuf << PARSE_FIELD_LEN(EFIELD_APPNAME, tdstat_.appbuf_.size() + 1) << std::string_view(tdstat_.appbuf_.data(), tdstat_.appbuf_.size() + 1);
		}	

		bool			iserr = !!ptran->errorcode_;

		if (iserr) {
			if (tdstat_.errorbuf_.size() && ustrbuf.bytes_left() >= sizeof(PARSE_FIELD_LEN) + tdstat_.errorbuf_.size() + 1) {
				next++;
				ustrbuf << PARSE_FIELD_LEN(EFIELD_ERRTXT, tdstat_.errorbuf_.size() + 1) << std::string_view(tdstat_.errorbuf_.data(), tdstat_.errorbuf_.size() + 1);
			}
		}	

		if (tdstat_.dyn_prep_reqnum_ && tdstat_.dyn_prep_time_t_ && ustrbuf.bytes_left() >= 2 * sizeof(PARSE_FIELD_LEN) + 2 * sizeof(uint64_t)) {
			next++;
			ustrbuf << PARSE_FIELD_LEN(EFIELD_PREP_REQNUM, sizeof(uint64_t)) << tdstat_.dyn_prep_reqnum_;

			next++;
			ustrbuf << PARSE_FIELD_LEN(EFIELD_PREP_REQTIME, sizeof(time_t)) << tdstat_.dyn_prep_time_t_;
		}

		*(ustrbuf.data()) = next;

		ptran->reqnum_ = tdstat_.reqnum_++;

		if (ptran->reqnum_ > 0) {
			ptran->app_sleep_ms_ = (ptran->tupd_usec_ - tdstat_.last_upd_tusec_)/1000;
		}

		tdstat_.last_upd_tusec_ = ptran->tupd_usec_;

		ptran->request_len_ = tdstrbuf_.size() + 1;

		if (ustrbuf.size() > 1) {
			ptran->lenext_ = ustrbuf.size();
		}	
		else {
			ptran->lenext_ = 0;
		}	
		
		ptran->set_resp_times();
		ptran->set_padding_len();
		
		gtotal_queries++;
		gtotal_resp += ptran->response_usec_;

		if (psvc_) {
			psvc_->upd_stats_on_req(*ptran, iserr, tdstat_.is_serv_err_);
		}	

		return apihdlr.set_xfer_buf_sz(ptran->get_elem_size());
	}
	catch(...) {
		apihdlr.stats_.nxfer_pool_fail_++;
		return false;
	}	
}	

void MONGO_SESSINFO::print_stats(STR_WR_BUF & strbuf, time_t tcur, time_t tlast) noexcept
{
	uint64_t			diffstats[STATMG_MAX];

	std::memcpy(diffstats, gstats, sizeof(gstats));

	strbuf << "\nMongo Interval Stats for "sv << tcur - tlast << " sec : "sv;
	
	for (int i = 0; i < (int)STATMG_MAX; ++i) {
		diffstats[i] -= gstats_old[i];

		if (diffstats[i] > 0) {
			strbuf << ' ' << gstatstr[i] << ' ' << diffstats[i] << ',';
		}	
	}	
	
	strbuf << " Queries "sv << gtotal_queries - glast_queries << ", Avg Response usec "sv << (gtotal_resp - glast_resp)/(NUM_OR_1(gtotal_queries - glast_queries));
	
	std::memcpy(gstats_old, gstats, sizeof(gstats));

	glast_queries = gtotal_queries;
	glast_resp = gtotal_resp;

	strbuf << '\n';

	strbuf << "Mongo Cumulative Stats : "sv;
	
	for (int i = 0; i < (int)STATMG_MAX; ++i) {
		if (gstats[i] > 0) {
			strbuf << ' ' << gstatstr[i] << ' ' << gstats[i] << ',';
		}	
	}	

	strbuf << " Total Requests "sv << gtotal_queries << ", Overall Avg Response usec "sv << gtotal_resp/NUM_OR_1(gtotal_queries);

	strbuf << "\n\n"sv;
}	

} // namespace gyeeta

