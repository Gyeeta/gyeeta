//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#if 1

#include			"gy_postgres_proto.h"
#include			"gy_postgres_proto_detail.h"
#include			"gy_proto_parser.h"
#include			"gy_tls_proto.h"

namespace gyeeta {

POSTGRES_PROTO::POSTGRES_PROTO(API_PARSE_HDLR & apihdlr, uint32_t api_max_len)
	: apihdlr_(apihdlr), api_max_len_(api_max_len), max_pg_req_token_(api_max_len_ + 512), max_pg_resp_token_(2048)
{}	

POSTGRES_PROTO::~POSTGRES_PROTO() noexcept		= default;

std::pair<POSTGRES_SESSINFO *, void *> POSTGRES_PROTO::alloc_sess(SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr)
{
	return { new POSTGRES_SESSINFO(*this, svcsess), nullptr };
}	

void POSTGRES_PROTO::destroy(POSTGRES_SESSINFO *pobj, void *pdata) noexcept
{
	delete pobj;
}	


void POSTGRES_PROTO::handle_request_pkt(POSTGRES_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	sess.handle_request_pkt(hdr, pdata);
}

void POSTGRES_PROTO::handle_response_pkt(POSTGRES_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	sess.handle_response_pkt(hdr, pdata);
}

void POSTGRES_PROTO::handle_session_end(POSTGRES_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr)
{
	sess.handle_session_end(hdr);
}	

void POSTGRES_PROTO::handle_ssl_change(POSTGRES_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	sess.handle_ssl_change(hdr, pdata);
}


void POSTGRES_PROTO::print_stats(STR_WR_BUF & strbuf, time_t tcur, time_t tlast) noexcept
{
	POSTGRES_SESSINFO::print_stats(strbuf, tcur, tlast);
}	
	
POSTGRES_SESSINFO::POSTGRES_SESSINFO(POSTGRES_PROTO & prot, SVC_SESSION & svcsess)
	: tran_(svcsess.common_.tlastpkt_usec_, svcsess.common_.tconnect_usec_, svcsess.common_.cli_ipport_, svcsess.common_.ser_ipport_, svcsess.common_.glob_id_, svcsess.proto_), 
	tdstrbuf_(prot.api_max_len_ - 1), 
	preqfragbuf_(new uint8_t[prot.max_pg_req_token_ + 16 + prot.max_pg_resp_token_ + 16]), presfragbuf_(preqfragbuf_ + prot.max_pg_req_token_ + 16), 
	svcsess_(svcsess), prot_(prot)
{
	std::memset(tdstrbuf_.get(), 0, 128);
	std::memset(preqfragbuf_, 0, 128);
	std::memset(presfragbuf_, 0, 128);
	
	gstats[STATPG_NEW_SESS]++;
	
	if (svcsess.common_.syn_seen_ == false) {
		is_midway_session_ = 1;
		login_complete_ = 1;

		statpg_.skip_to_req_after_resp_ = 1;
		statpg_.skip_req_resp_till_ready_ = 1;

		gstats[STATPG_MIDWAY_SESS]++;
	}
}	
	
POSTGRES_SESSINFO::~POSTGRES_SESSINFO() noexcept
{
	gstats[STATPG_SESS_COMPLETE]++;

	delete [] preqfragbuf_;
}	
	
int POSTGRES_SESSINFO::handle_request_pkt(PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	uint8_t			*ptmp, *pend = pdata + hdr.datalen_;
	uint8_t			*sptr = pdata;
	auto			& common = svcsess_.common_;
	int			ret;

	if (skip_session_ == 1) {
		gstats[STATPG_SESS_SKIP_PKT]++;
		return 0;
	}

	if (is_ssl_sess_ == 2 && hdr.src_ != SRC_UPROBE_SSL) {
		return 0;
	}	

	if (drop_seen_ || common.clidroptype_ == DT_DROP_SEEN || common.serdroptype_ == DT_DROP_SEEN) {

		if (statpg_.part_query_started_ == 1) {
			drop_partial_req();
			statpg_.part_query_started_ = 0;
		}
			
		statpg_.reset_stats_on_resp(true);

		if (login_complete_ == 0) {
			login_complete_ = 1;
			is_midway_session_ = 1;
		}	

		drop_seen_ = 0;
		statpg_.skip_to_req_after_resp_ = 1;
		statpg_.skip_req_resp_till_ready_ = 1;

		return 0;
	}

	ret = parse_req_pkt(hdr, pdata);
	if (ret < 0) {
		gstats[STATPG_REQ_PKT_SKIP]++;
		return 0;
	}	

	tran_.update_req_stats(common.tlastpkt_usec_, hdr.datalen_);

	if (tdstrbuf_.size() && statpg_.part_query_started_ == 0) {
		tran_.request_len_ = tdstrbuf_.size() + 1;
		statpg_.part_query_started_ = 1;
		print_partial_req();
	}

	return 0;
}	

int POSTGRES_SESSINFO::handle_response_pkt(PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	uint8_t 		*sptr = pdata;
	uint32_t 		bytes_left, pktlen = hdr.datalen_;
	auto			& common = svcsess_.common_;
	int 			ret;

	if (skip_session_ == 1) {
		gstats[STATPG_SESS_SKIP_PKT]++;
		return 0;
	}

	if (is_ssl_sess_) {
		if (is_ssl_sess_ == 2 && hdr.src_ != SRC_UPROBE_SSL) {
			return 0;
		}	
		else if (is_ssl_sess_ == 1) {
			if (pktlen == 1) {
				if (*sptr == 'N') {
					is_ssl_sess_ = 0;
				}	
				else if (*sptr == 'S') {
					is_ssl_sess_ = 2;
					
					gstats[STATPG_SSL_SESS]++;
				}	
				
				return 0;
			}
			else if (common.serdroptype_ == DT_DROP_SEEN &&
					(true == TLS_PROTO::is_tls_req_resp(pdata, hdr.datalen_, hdr.dir_, false /* is_init */))) {
					
				is_ssl_sess_ = 2;
				gstats[STATPG_SSL_SESS]++;

				return 0;
			}	
			if (hdr.src_ == SRC_UPROBE_SSL) {
				is_ssl_sess_ = 2;
				gstats[STATPG_SSL_SESS]++;

				goto drop_chk;
			}	
			else if (++nssl_resp_chk_ > 32 && common.tlastpkt_usec_ > common.tconnect_usec_ + 30 * GY_USEC_PER_SEC) {
				skip_session_ = 1;
				gstats[STATPG_SKIP_SESS]++;

				return 0;
			}	
		}
	}
	
	if (drop_seen_ || common.clidroptype_ == DT_DROP_SEEN || common.serdroptype_ == DT_DROP_SEEN) {

drop_chk :
		if (statpg_.part_query_started_ == 1) {
			drop_partial_req();
			statpg_.part_query_started_ = 0;
		}
			
		statpg_.reset_stats_on_resp(true);

		if (login_complete_ == 0) {
			login_complete_ = 1;
			is_midway_session_ = 1;
		}	

		drop_seen_ = 0;
		statpg_.skip_to_req_after_resp_ = 1;
		statpg_.skip_req_resp_till_ready_ = 1;

		return 0;
	}

	tran_.update_resp_stats(common.tlastpkt_usec_, hdr.datalen_);

	ret = parse_resp_pkt(hdr, pdata);
	if (ret < 0) {
		gstats[STATPG_RESP_PKT_SKIP]++;
	}	

	return 0;
}	

void POSTGRES_SESSINFO::handle_session_end(PARSE_PKT_HDR & hdr)
{
	auto				& common = svcsess_.common_;

	if (statpg_.part_query_started_ == 1) {
		drop_partial_req();
		statpg_.part_query_started_ = 0;
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
	tran_.tin_usec_ = common.tlastpkt_usec_;
	tran_.reqlen_ = 1;
	tran_.reslen_ = 1;
	tran_.tres_usec_ = common.tlastpkt_usec_;

	request_done();
}	

void POSTGRES_SESSINFO::handle_ssl_change(PARSE_PKT_HDR & hdr, uint8_t *pdata)
{

}	

void POSTGRES_SESSINFO::set_new_req() noexcept
{
	COMMON_PROTO 				& common = svcsess_.common_;

	tran_.reset();

	tran_.treq_usec_			= common.tlastpkt_usec_;
	tran_.tupd_usec_			= common.tlastpkt_usec_;
	tran_.tin_usec_				= common.tlastpkt_usec_;
	
	tdstrbuf_.reset();
	tdstat_.reset_on_req();
}	

int POSTGRES_SESSINFO::parse_req_pkt(PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	uint8_t				*ppkt_end, *sptr = pdata, *startsptr;
	int64_t 			lenpkt = hdr.datalen_;
	uint32_t			pktlen = hdr.datalen_, ncopy;
	POSTGRES_PROTO::PG_MSG_TYPES_E	tkntype;
	int 				ret, tknlen;
	uint8_t				thdr[8] = {};
	int8_t				tlen;
	auto				& common = svcsess_.common_;

	if (statpg_.skip_req_resp_till_ready_) {
		return 0;
	}

	if (statpg_.skip_to_req_after_resp_) {
		if (statpg_.skip_to_req_after_resp_ == 2) {
			
			if (pktlen > 5) {
				uint32_t			len;

				tkntype = (decltype(tkntype))*sptr;
				len = unaligned_read_be32(sptr + 1);

				if (len + 1 <= pktlen && (int)len > 4) {
					switch (tkntype) {
					
					case POSTGRES_PROTO::MSG_F_QUERY :
					case POSTGRES_PROTO::MSG_F_CLOSE :
					case POSTGRES_PROTO::MSG_F_PARSE :
					case POSTGRES_PROTO::MSG_F_BIND :
					case POSTGRES_PROTO::MSG_F_DESCRIBE :
					case POSTGRES_PROTO::MSG_F_EXECUTE :
					case POSTGRES_PROTO::MSG_F_SYNC :
					case POSTGRES_PROTO::MSG_F_FUNCTION_CALL :

						statpg_.skip_to_req_after_resp_ = 0;
						goto start1;

					default :
						break;
					}
				}	
			}	

			statpg_.skip_req_resp_till_ready_ = 1;
		}	

		statpg_.skip_to_req_after_resp_ = 1;
		return 0;
	}	

start1 :
	ppkt_end = sptr + lenpkt;

	do {
		startsptr	= sptr;
		tkntype 	= POSTGRES_PROTO::MSG_FB_UNKNOWN;
		tknlen 		= 0;
		tlen 		= 0;

		memset(thdr, 0, sizeof(thdr));

		if (!login_complete_) {
			if (statpg_.skip_till_auth_resp_) {
				return 0;
			}	

			thdr[0] = POSTGRES_PROTO::MSG_F_STARTUP;
			tlen = 1;
		}	

		if (statpg_.req_tkn_frag_ == 2 && statpg_.req_hdr_fraglen_ > 0 && statpg_.req_hdr_fraglen_ <= 4) {
			if (lenpkt + statpg_.req_hdr_fraglen_ > 4) {
				memcpy(thdr, statpg_.reqhdr_, statpg_.req_hdr_fraglen_);
				memcpy(thdr + statpg_.req_hdr_fraglen_, sptr, 5 - statpg_.req_hdr_fraglen_);
				tlen = 5;

				sptr += 5 - statpg_.req_hdr_fraglen_;
				lenpkt -= 5 - statpg_.req_hdr_fraglen_;

				statpg_.req_tkn_frag_ = 0;
				statpg_.req_hdr_fraglen_ = 0;
			}	
			else {
				memcpy(statpg_.reqhdr_ + statpg_.req_hdr_fraglen_, sptr, lenpkt);
				statpg_.req_hdr_fraglen_ += lenpkt;
				return 0;
			}	
		}	

		if (statpg_.req_tkn_frag_ == 0) {
			if ((unsigned)lenpkt + (unsigned)tlen < 5) {
				statpg_.req_tkn_frag_ = 2;
				statpg_.req_hdr_fraglen_ = tlen + lenpkt;

				memcpy(statpg_.reqhdr_, thdr, tlen);
				memcpy(statpg_.reqhdr_ + tlen, sptr, lenpkt);
				
				return 0;
			}	

			if ((unsigned)tlen < 5) {
				memcpy(thdr + tlen, sptr, 5 - tlen);
				sptr += 5 - tlen;
				lenpkt -= 5 - tlen;
			}

			tkntype = POSTGRES_PROTO::PG_MSG_TYPES_E(*thdr);
			tknlen = unaligned_read_be32(thdr + 1);

			if (tknlen < 4) {
				reset_on_error();
				return -1;	
			}		
			tknlen -= 4;

			if (lenpkt < tknlen) {
				statpg_.req_tkn_frag_ = 1;
				statpg_.req_hdr_fraglen_ = 5;
				statpg_.nbytes_req_frag_ = 0;
				statpg_.skip_req_bytes_ = 0;

				memcpy(statpg_.reqhdr_, thdr, 5);
			}	
			else {
				ret = handle_req_token(tkntype, tknlen, sptr, tknlen);

				if (ret < 0) {
					reset_on_error();
					return -1;
				}	

				statpg_.reset_req_frag_stat();

				sptr += tknlen;
				lenpkt -= tknlen;
			}	
		}	
		
		if (statpg_.req_tkn_frag_ == 1) {
			if (statpg_.req_hdr_fraglen_ < 5 || lenpkt < 0) {
				reset_on_error();
				return -1;
			}	

			tkntype = POSTGRES_PROTO::PG_MSG_TYPES_E(*statpg_.reqhdr_);
			tknlen = unaligned_read_be32(&statpg_.reqhdr_[1]);

			if (tknlen < 4) {
				reset_on_error();
				return -1;	
			}		
			tknlen -= 4;

			if (statpg_.nbytes_req_frag_ > (uint32_t)tknlen || statpg_.nbytes_req_frag_ > prot_.max_pg_req_token_) {
				reset_on_error();
				return -1;
			}	

			if (statpg_.nbytes_req_frag_ < prot_.max_pg_req_token_) {
				ncopy = std::min<uint32_t>(prot_.max_pg_req_token_ - statpg_.nbytes_req_frag_, tknlen - statpg_.nbytes_req_frag_);

				ncopy = std::min<uint32_t>(ncopy, lenpkt);

				memcpy(preqfragbuf_ + statpg_.nbytes_req_frag_, sptr, ncopy);

				statpg_.nbytes_req_frag_ += ncopy;
				sptr += ncopy;
				lenpkt -= ncopy;
			}	

			if (tknlen <= statpg_.nbytes_req_frag_ + statpg_.skip_req_bytes_ + lenpkt) {
				ret = handle_req_token(tkntype, tknlen, preqfragbuf_, statpg_.nbytes_req_frag_);

				if (ret < 0) {
					reset_on_error();
					return -1;
				}	

				statpg_.reset_req_frag_stat();
			}	
			else {
				if (lenpkt > 0) {
					statpg_.skip_req_bytes_ += lenpkt;
				}

				return 0;
			}	
		}	

	} while (sptr >= pdata && sptr < ppkt_end && lenpkt > 0 && sptr != startsptr);	

	return 0;
}

int POSTGRES_SESSINFO::parse_resp_pkt(PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	uint8_t				*ppkt_end, *sptr = pdata, *startsptr;
	uint32_t			pktlen = hdr.datalen_, ncopy;
	int64_t 			lenpkt = pktlen;
	POSTGRES_PROTO::PG_MSG_TYPES_E			tkntype;
	int 				ret, tknlen;
	uint8_t				thdr[8];
	int8_t				tlen;
	auto				& common = svcsess_.common_;

	ppkt_end = sptr + lenpkt;

	if (statpg_.skip_req_resp_till_ready_) {
		if (lenpkt >= 5) {
			auto				*ptmp = ppkt_end - 6;
			uint32_t			len;

			if (0 == memcmp(ptmp, "\x5a\x00\x00\x00\x05", 5)) {
				// POSTGRES_PROTO::MSG_B_READY_FOR_QUERY hit
				sptr = ptmp;
				pktlen = lenpkt = 6;

				statpg_.reset_stats_on_resp(true);

				goto start1;
			}	
		}	

		return 0;
	}

start1 :
	if (statpg_.skip_to_req_after_resp_) {
		statpg_.skip_to_req_after_resp_ = 2;
		return 0;
	}	

	do {
		startsptr	= sptr;
		tkntype 	= POSTGRES_PROTO::MSG_FB_UNKNOWN;
		tknlen 		= 0;
		tlen 		= 0;

		memset(thdr, 0, sizeof(thdr));

		if (statpg_.resp_tkn_frag_ == 2 && statpg_.resp_hdr_fraglen_ > 0 && statpg_.resp_hdr_fraglen_ <= 4) {
			if (lenpkt + statpg_.resp_hdr_fraglen_ > 4) {
				memcpy(thdr, statpg_.resphdr_, statpg_.resp_hdr_fraglen_);
				memcpy(thdr + statpg_.resp_hdr_fraglen_, sptr, 5 - statpg_.resp_hdr_fraglen_);
				tlen = 5;

				sptr += 5 - statpg_.resp_hdr_fraglen_;
				lenpkt -= 5 - statpg_.resp_hdr_fraglen_;

				statpg_.resp_tkn_frag_ = 0;
				statpg_.resp_hdr_fraglen_ = 0;
			}	
			else {
				memcpy(statpg_.resphdr_ + statpg_.resp_hdr_fraglen_, sptr, lenpkt);
				statpg_.resp_hdr_fraglen_ += lenpkt;
				return 0;
			}	
		}	

		if (statpg_.resp_tkn_frag_ == 0) {
			if ((unsigned)lenpkt + (unsigned)tlen < 5) {
				statpg_.resp_tkn_frag_ = 2;
				statpg_.resp_hdr_fraglen_ = tlen + lenpkt;

				memcpy(statpg_.resphdr_, thdr, tlen);
				memcpy(statpg_.resphdr_ + tlen, sptr, lenpkt);
				
				return 0;
			}	

			if ((unsigned)tlen < 5) {
				memcpy(thdr + tlen, sptr, 5 - tlen);
				sptr += 5 - tlen;
				lenpkt -= 5 - tlen;
			}

			tkntype = POSTGRES_PROTO::PG_MSG_TYPES_E(*thdr);
			tknlen = unaligned_read_be32(thdr + 1);

			if (tknlen < 4) {
				reset_on_error();
				return -1;	
			}		
			tknlen -= 4;

			if (lenpkt < tknlen) {
				statpg_.resp_tkn_frag_ = 1;
				statpg_.resp_hdr_fraglen_ = 5;
				statpg_.nbytes_resp_frag_ = 0;
				statpg_.skip_resp_bytes_ = 0;

				memcpy(statpg_.resphdr_, thdr, 5);
			}	
			else {
				ret = handle_resp_token(tkntype, tknlen, sptr, tknlen);

				if (ret < 0) {
					reset_on_error();
					return -1;
				}	

				statpg_.reset_resp_frag_stat();

				sptr += tknlen;
				lenpkt -= tknlen;
			}	
		}	
		
		if (statpg_.resp_tkn_frag_ == 1) {
			if (statpg_.resp_hdr_fraglen_ < 5 || lenpkt < 0) {
				reset_on_error();
				return -1;
			}	

			tkntype = POSTGRES_PROTO::PG_MSG_TYPES_E(*statpg_.resphdr_);
			tknlen = unaligned_read_be32(&statpg_.resphdr_[1]);

			if (tknlen < 4) {
				reset_on_error();
				return -1;	
			}		
			tknlen -= 4;

			if (statpg_.nbytes_resp_frag_ > (uint32_t)tknlen || statpg_.nbytes_req_frag_ > prot_.max_pg_resp_token_) {
				reset_on_error();
				return -1;
			}	

			if (statpg_.nbytes_resp_frag_ < prot_.max_pg_resp_token_) {
				ncopy = std::min<uint32_t>(prot_.max_pg_resp_token_ - statpg_.nbytes_resp_frag_, tknlen - statpg_.nbytes_resp_frag_);

				ncopy = std::min<uint32_t>(ncopy, lenpkt);

				memcpy(presfragbuf_ + statpg_.nbytes_resp_frag_, sptr, ncopy);

				statpg_.nbytes_resp_frag_ += ncopy;
				sptr += ncopy;
				lenpkt -= ncopy;
			}	

			if (tknlen <= statpg_.nbytes_resp_frag_ + statpg_.skip_resp_bytes_ + lenpkt) {
				ret = handle_resp_token(tkntype, tknlen, presfragbuf_, statpg_.nbytes_resp_frag_);

				if (ret < 0) {
					reset_on_error();
					return -1;
				}	

				statpg_.reset_resp_frag_stat();
			}	
			else {
				if (lenpkt > 0) {
					statpg_.skip_resp_bytes_ += lenpkt;
				}

				return 0;
			}	
		}	

	} while (sptr >= pdata && sptr < ppkt_end && lenpkt > 0 && sptr != startsptr);	

	return 0;
}

int POSTGRES_SESSINFO::handle_req_token(POSTGRES_PROTO::PG_MSG_TYPES_E tkntype, uint32_t tknlen, uint8_t * sptr, int maxlen)
{
	const bool			istrunc = (maxlen < (int)tknlen);
	uint8_t				*pstart = sptr, *pend = sptr + maxlen;
	
	if (login_complete_ && (tdstrbuf_.size() == 0) && 
		(tkntype != POSTGRES_PROTO::MSG_F_COPYFAIL) && (tkntype != POSTGRES_PROTO::MSG_FB_COPYDATA) && (tkntype != POSTGRES_PROTO::MSG_FB_COPYDONE)) {

		set_new_req();
	}

	switch (tkntype) {
	
	case POSTGRES_PROTO::MSG_F_QUERY :
		if (maxlen > 0) {
			if (tdstrbuf_.size()) {
				tdstrbuf_ << ' ';
			}	
			tdstrbuf_.append((const char *)sptr, maxlen - 1);

			tran_.tran_type_ |= POSTGRES_PROTO::TYPE_PG_NORMAL_REQ; /* Normal Transaction */

			statpg_.nready_resp_pending_++;

			if (statpg_.nready_resp_pending_ > 128) {
				gstats[STATPG_REQ_SYNC_OVF]++;
				
				// Simulate a drop to try to get in sync
				drop_seen_ = 1;
			}	
		}

		break;

	case POSTGRES_PROTO::MSG_F_PARSE :	
		if (true) {
			const char			*ptmp = (const char *)sptr, *pname, *psql;
			int				nlen = 0, slen = 0;
			uint32_t			nhash = 0;
			PG_DYN_PREP			*pdyn = nullptr;

			if (maxlen < 5) {
				return -1;
			}	

			nlen = strnlen(ptmp, maxlen);

			if (nlen > 0) {
				nhash = fnv1_hash(ptmp, nlen);
			}	

			pname = ptmp;

			sptr += nlen + 1;
			maxlen -= nlen + 1;

			if (maxlen < 2) {
				return -1;
			}	
			
			ptmp = (const char *)sptr;

			slen = strnlen(ptmp, maxlen);

			if (slen == 0) {
				return -1;
			}

			psql = ptmp;

			if (tdstrbuf_.size()) {
				tdstrbuf_ << ' ';
			}	
			tdstrbuf_ << "/* DSQL Prepare */ "sv;
			tdstrbuf_.append(psql, slen);

			sptr += slen + 1;
			maxlen -= slen + 1;

			tran_.tran_type_ |= POSTGRES_PROTO::TYPE_PG_DSQL_PREPARE; /* DSQL Transaction */

			if (nlen == 0) {
				if (noname_dsql_.dyn_prep_time_t_ > 0) {
					gstats[STATPG_PREPARE_DEL]++;
				}

				noname_dsql_.~PG_DYN_PREP();

				new (&noname_dsql_) PG_DYN_PREP(psql, slen, tdstat_.reqnum_, tran_.treq_usec_/GY_USEC_PER_SEC);

				pdyn = &noname_dsql_;
			}	
			else {
				auto			it = pg_dsql_map_.find(nhash);
				
				if (it != pg_dsql_map_.end()) {
					it->second = PG_DYN_PREP(psql, slen, tdstat_.reqnum_, tran_.treq_usec_/GY_USEC_PER_SEC);
					pdyn = &(it->second);

					gstats[STATPG_PREPARE_DEL]++;
				}	
				else {
					if (pg_dsql_map_.size() >= PG_MAX_SESS_PREP_SQLS) {
						gstats[STATPG_PREPARE_ADD_SKIP]++;
					}	
					else {
						auto		[it, _] = pg_dsql_map_.try_emplace(nhash, psql, slen, tdstat_.reqnum_, tran_.treq_usec_/GY_USEC_PER_SEC);

						pdyn = &(it->second);
					}	
				}	
			}	

			if (pdyn) {
				gstats[STATPG_PREPARE_ADD]++;

				if (maxlen >= 6) {
					uint32_t			oid;
					uint16_t			nparam;

					nparam = unaligned_read_be16(sptr);

					sptr += 2;
					maxlen -= 2;

					if (nparam > 0 && maxlen >= nparam * 4) {
						auto			& oidparams = pdyn->oidparams_;
						auto			& intparams = pdyn->intparams_;
						auto			& floatparams = pdyn->floatparams_;
					
						oidparams.reset();
						intparams.reset();

						for (int i = 0; i < (int)nparam && i < (int)PG_ROW_MAX_COLUMNS; ++i) {
							oid = unaligned_read_be32(sptr);

							sptr += 4;
							maxlen -= 4;

							if (POSTGRES_PROTO::binary_param_ok(POSTGRES_PROTO::PG_OID_E(oid))) {
								oidparams.set(i);

								if (POSTGRES_PROTO::is_int_param(POSTGRES_PROTO::PG_OID_E(oid))) {
									intparams.set(i);
								}	
								else if (POSTGRES_PROTO::is_float_param(POSTGRES_PROTO::PG_OID_E(oid))) {
									floatparams.set(i);
								}	
							}
						}	
					}	
				}	
			}	
		}

		break;

	case POSTGRES_PROTO::MSG_F_BIND :	
		if (true) {
			const char			*ptmp = (char *)sptr, *pname, *psql = nullptr, *pbind = nullptr;
			int				nlen = 0, slen = 0, sqllen = 0, lenp;
			uint32_t			nhash = 0, dhash = 0;
			uint16_t			nfmt, nparam, fmt;
			uint8_t				allfmt = 0, fmtarr[PG_ROW_MAX_COLUMNS];
			PG_DYN_PREP			*pdyn = nullptr;
			PG_DYN_PORTAL			*pportal = nullptr;

			if (maxlen < 6) {
				return -1;
			}	

			nlen = strnlen(ptmp, maxlen);

			if (nlen > 0) {
				nhash = fnv1_hash(ptmp, nlen);
			}	

			pname = ptmp;

			sptr += nlen + 1;
			maxlen -= nlen + 1;

			if (maxlen < 5) {
				return -1;
			}	
			
			ptmp = (const char *)sptr;

			if (tdstrbuf_.size()) {
				tdstrbuf_ << ' ';
			}	
			tdstrbuf_ << "/* DSQL Bind */ ";

			pbind = tdstrbuf_.get_current();

			slen = strnlen(ptmp, maxlen);

			if (slen == 0) {
				if ((noname_dsql_.get_len()) > 0) {
					psql = noname_dsql_.dyn_sql_;
					sqllen = noname_dsql_.get_len();

					pdyn = &noname_dsql_;

					gstats[STATPG_PREPARE_FIND_OK]++;
				}	
				else {
					psql = " ";
					sqllen = 1;

					gstats[STATPG_PREPARE_FIND_FAIL]++;
				}	
			}
			else {
				dhash = fnv1_hash(ptmp, slen);
				
				auto			it = pg_dsql_map_.find(dhash);
				
				if (it != pg_dsql_map_.end()) {
					psql = it->second.dyn_sql_;
					sqllen = it->second.get_len();

					pdyn = &(it->second);

					gstats[STATPG_PREPARE_FIND_OK]++;
				}	
				else {
					psql = " ";
					sqllen = 1;

					gstats[STATPG_PREPARE_FIND_FAIL]++;
				}	
			}	

			if (pdyn && psql) {
				tdstrbuf_.append(psql, sqllen);
				
				tdstat_.dyn_prep_reqnum_ = pdyn->dyn_prep_reqnum_;
				tdstat_.dyn_prep_time_t_ = pdyn->dyn_prep_time_t_;
			}	
			else {
				tdstat_.dyn_prep_reqnum_ = 0;
				tdstat_.dyn_prep_time_t_ = 0;
			}	

			tran_.tran_type_ |= POSTGRES_PROTO::TYPE_PG_DSQL_BIND; /* DSQL Transaction */

			sptr += slen + 1;
			maxlen -= slen + 1;

			if (maxlen < 4) {
				return -1;
			}	
			
			nfmt = unaligned_read_be16(sptr);
			
			sptr += 2;
			maxlen -= 2;
			
			if (maxlen < 2 + nfmt * 2 || (int)nfmt < 0) {
				return -1;
			}	

			memset(fmtarr, 0, sizeof(fmtarr));

			if (nfmt == 1) {
				fmt = unaligned_read_be16(sptr);

				sptr += 2;
				maxlen -= 2;
				
				if (fmt == 1) {
					// All params are binary
					memset(fmtarr, 1, sizeof(fmtarr));
				}	
			}
			else {
				for (int i = 0; i < nfmt; ++i) {

					if (i < (int)PG_ROW_MAX_COLUMNS) {
						fmtarr[i] = unaligned_read_be16(sptr);
					}

					sptr += 2;
					maxlen -= 2;
				}
			}
			
			nparam = unaligned_read_be16(sptr);
			
			sptr += 2;
			maxlen -= 2;
			
			if (maxlen < 4 * nparam || (int)nparam < 0) {
				return -1;
			}	

			tdstrbuf_ << " $*P*$ "sv;

			for (int i = 0; i < nparam && i < (int)PG_ROW_MAX_COLUMNS; ++i) {
				if (maxlen < 4) {
					break;
				}	

				lenp = unaligned_read_be32(sptr);
				
				sptr += 4;
				maxlen -= 4;

				if (lenp == -1) {
					tdstrbuf_ << "NULL,"sv;
					continue;
				}
				else if (lenp < -1) {
					break;
				}	

				if (maxlen < lenp || tdstrbuf_.bytes_left() < (size_t)lenp) {
					break;
				}	

				if (fmtarr[i] == 0) {
					tdstrbuf_.append((const char *)sptr, lenp);
					tdstrbuf_ << ',';
				}	
				else if (pdyn && pdyn->oidparams_.test(i)) {
					if (pdyn->intparams_.test(i)) {
						int64_t				i64;
						int32_t				i32;
						int16_t				i16;

						switch (lenp) {
						
						case 8 :
							i64 = unaligned_read_be64(sptr);
							tdstrbuf_ << i64 << ',';
							break;

						case 4 :
							i32 = unaligned_read_be32(sptr);	
							tdstrbuf_ << i32 << ',';
							break;

						case 2 :
							i16 = unaligned_read_be16(sptr);	
							tdstrbuf_ << i16 << ',';
							break;

						default :
							break;
						}	
					}
					else if (pdyn->floatparams_.test(i)) {
						double				d;
						float				f;
						int64_t				i64;
						int32_t				i32;

						switch (lenp) {
						
						case 8 :
							i64 = unaligned_read_be64(sptr);
							memcpy(&d, &i64, sizeof(d));
							tdstrbuf_ << d << ',';
							break;

						case 4 :
							i32 = unaligned_read_be32(sptr);	
							memcpy(&f, &i32, sizeof(f));
							tdstrbuf_ << f << ',';
							break;

						default :
							break;
						}	

					}
					else {
						// String type
						tdstrbuf_.append((const char *)sptr, lenp);
						tdstrbuf_ << ',';
					}	
				}
				else {
					tdstrbuf_ << "<Binary Param>,"sv;
				}	

				sptr += lenp;
				maxlen -= lenp;
			}	
			
			if (nparam > PG_ROW_MAX_COLUMNS) {
				tdstrbuf_ << "...";
			}	

			if (nlen == 0) {
				if (noname_portal_.dyn_prep_time_t_ > 0) {
					gstats[STATPG_PORTAL_DEL]++;
				}

				noname_portal_.~PG_DYN_PORTAL();

				new (&noname_portal_) PG_DYN_PORTAL(pbind, tdstrbuf_.get_current() - pbind, tdstat_.reqnum_, tran_.treq_usec_/GY_USEC_PER_SEC);

				pportal = &noname_portal_;
			}	
			else if (nlen > 0) {
				nhash = fnv1_hash(pname, nlen);

				auto			it = pg_portal_map_.find(nhash);
				
				if (it != pg_portal_map_.end()) {
					it->second.~PG_DYN_PORTAL();

					new (&it->second) PG_DYN_PORTAL(pbind, tdstrbuf_.get_current() - pbind, tdstat_.reqnum_, tran_.treq_usec_/GY_USEC_PER_SEC);

					gstats[STATPG_PORTAL_DEL]++;
				}	
				else {
					// We clear all existing portals as unless its a hold cursor, all portals will be closed on tran commit/rollback
					if (pg_portal_map_.size() >= PG_MAX_SESS_PORTALS) {
						gstats[STATPG_PORTAL_CLEAR_ALL]++;

						pg_portal_map_.clear();
					}	

					auto		[it, _] = pg_portal_map_.try_emplace(nhash, pbind, tdstrbuf_.get_current() - pbind, tdstat_.reqnum_, tran_.treq_usec_/GY_USEC_PER_SEC);

					pportal = &(it->second);
				}	
			}	

			if (pportal) {
				gstats[STATPG_PORTAL_ADD]++;
			}
		}

		break;

	case POSTGRES_PROTO::MSG_F_DESCRIBE :
		
		if (true) {
			const char			*ptmp = (const char *)sptr, *pname, *psql = nullptr;
			int				nlen = 0, lensql = 0;
			uint32_t			nhash = 0;
			bool				is_portal;

			if (maxlen < 2) {
				return -1;
			}	

			if (*ptmp == 'P') {
				is_portal = true;
			}	
			else if (*ptmp == 'S') {
				is_portal = false;
			}	
			else {
				return -1;
			}	

			ptmp++;
			maxlen--;

			nlen = strnlen(ptmp, maxlen);

			if (nlen > 0) {
				nhash = fnv1_hash(ptmp, nlen);
			}	

			pname = ptmp;

			if (tdstrbuf_.size()) {
				tdstrbuf_ << ' ';
			}	
			tdstrbuf_ << "/* DSQL Describe */ "sv;
			
			tran_.tran_type_ |= POSTGRES_PROTO::TYPE_PG_DSQL_DESCRIBE; /* DSQL Transaction */

			if (tran_.tran_type_ & (POSTGRES_PROTO::TYPE_PG_DSQL_PREPARE | POSTGRES_PROTO::TYPE_PG_DSQL_BIND)) {
				// No need to add the sql
				break;
			}	

			if (nlen == 0) {
				if (is_portal) {
					if (noname_portal_.dyn_prep_time_t_ > 0) {
						psql = noname_portal_.bind_sql_.data();
						lensql = noname_portal_.get_len();
					}
				}
				else {
					if (noname_dsql_.dyn_prep_time_t_ > 0) {
						psql = noname_dsql_.dyn_sql_;
						lensql = noname_dsql_.get_len();
					}
				}
			}	
			else {
				if (is_portal) {
					auto			it = pg_portal_map_.find(nhash);
					
					if (it != pg_portal_map_.end()) {
						psql = it->second.bind_sql_.data();
						lensql = it->second.bind_sql_.size();
					}	
				}
				else {
					auto			it = pg_dsql_map_.find(nhash);
					
					if (it != pg_dsql_map_.end()) {
						psql = it->second.dyn_sql_;
						lensql = it->second.get_len();
					}	
				}
			}	

			if (psql && lensql) {
				tdstrbuf_.append(psql, lensql);
			}	
		}

		break;

	case POSTGRES_PROTO::MSG_F_EXECUTE :

		if (true) {
			const char			*ptmp = (const char *)sptr, *pname, *psql = nullptr;
			int				nlen = 0, lensql = 0;
			uint32_t			nhash = 0;

			if (maxlen < 1) {
				return -1;
			}	

			nlen = strnlen(ptmp, maxlen);

			if (nlen > 0) {
				nhash = fnv1_hash(ptmp, nlen);
			}	

			pname = ptmp;

			if (tdstrbuf_.size()) {
				tdstrbuf_ << ' ';
			}	
			tdstrbuf_ << "/* DSQL Exec */ "sv;
			
			tran_.tran_type_ |= POSTGRES_PROTO::TYPE_PG_DSQL_EXEC; /* DSQL Transaction */

			if (tran_.tran_type_ & POSTGRES_PROTO::TYPE_PG_DSQL_BIND) {
				// No need to add the sql
				break;
			}

			if (nlen == 0) {
				if (noname_portal_.dyn_prep_time_t_ > 0) {
					psql = noname_portal_.bind_sql_.data();
					lensql = noname_portal_.get_len();
				}
			}	
			else {
				auto			it = pg_portal_map_.find(nhash);
					
				if (it != pg_portal_map_.end()) {
					psql = it->second.bind_sql_.data();
					lensql = it->second.bind_sql_.size();
				}	
			}	

			if (psql && lensql) {
				tdstrbuf_.append(psql, lensql);
			}	
		}

		break;

	case POSTGRES_PROTO::MSG_F_SYNC :
		
		if (statpg_.copy_mode_ == 0) {
			statpg_.nready_resp_pending_++;

			if (statpg_.nready_resp_pending_ > 128) {
				gstats[STATPG_REQ_SYNC_OVF]++;
				
				// Simulate a drop to try to get in sync
				drop_seen_ = 1;
			}	
		}
		else {
			statpg_.nready_resp_pending_ = 1;
		}	

		break;

	case POSTGRES_PROTO::MSG_F_CLOSE :
		
		if (true) {
			const char			*ptmp = (const char *)sptr, *pname, *psql = nullptr;
			int				nlen = 0, lensql = 0;
			uint32_t			nhash = 0;
			bool				is_portal, found = false;

			if (maxlen < 2) {
				return -1;
			}	

			if (*ptmp == 'P') {
				is_portal = true;
			}	
			else if (*ptmp == 'S') {
				is_portal = false;
			}	
			else {
				return -1;
			}	

			ptmp++;
			maxlen--;

			nlen = strnlen(ptmp, maxlen);

			if (nlen > 0) {
				nhash = fnv1_hash(ptmp, nlen);
			}	

			pname = ptmp;

			if (tdstrbuf_.size()) {
				tdstrbuf_ << ' ';
			}	
			tdstrbuf_ << "/* DSQL Dealloc */ "sv;
			
			tran_.tran_type_ |= POSTGRES_PROTO::TYPE_PG_DSQL_DEALLOC; /* DSQL Transaction */

			if (nlen == 0) {
				if (is_portal) {
					if (noname_portal_.dyn_prep_time_t_ > 0) {
						psql = noname_portal_.bind_sql_.data();
						lensql = noname_portal_.get_len();

						tdstrbuf_.append(psql, lensql);
						gstats[STATPG_PORTAL_DEL]++;
					}

					noname_portal_.reset();
				}
				else {
					if (noname_dsql_.dyn_prep_time_t_ > 0) {
						psql = noname_dsql_.dyn_sql_;
						lensql = noname_dsql_.get_len();

						tdstrbuf_.append(psql, lensql);
						gstats[STATPG_PREPARE_DEL]++;
					}

					noname_dsql_.reset();
				}
			}	
			else {
				if (is_portal) {
					auto			it = pg_portal_map_.find(nhash);
					
					if (it != pg_portal_map_.end()) {
						psql = it->second.bind_sql_.data();
						lensql = it->second.bind_sql_.size();

						tdstrbuf_.append(psql, lensql);
						gstats[STATPG_PORTAL_DEL]++;

						pg_portal_map_.erase(it);
					}	
				}
				else {
					auto			it = pg_dsql_map_.find(nhash);
					
					if (it != pg_dsql_map_.end()) {
						psql = it->second.dyn_sql_;
						lensql = it->second.get_len();

						tdstrbuf_.append(psql, lensql);
						gstats[STATPG_PREPARE_DEL]++;

						pg_dsql_map_.erase(it);
					}	
				}
			}	
		}

		break;

	case POSTGRES_PROTO::MSG_F_FUNCTION_CALL :

		if (true) {
			const char			*ptmp = (char *)sptr;
			uint32_t			oid, lenp;
			uint16_t			nfmt, nparam, fmt;
			uint8_t				allfmt = 0, fmtarr[PG_ROW_MAX_COLUMNS];

			if (maxlen < 8) {
				return -1;
			}	

			oid = unaligned_read_be32(ptmp);

			if (tdstrbuf_.size()) {
				tdstrbuf_ << ' ';
			}
			tdstrbuf_ << "Function Call OID "sv << oid;

			sptr += 4;
			maxlen -= 4;

			nfmt = unaligned_read_be16(sptr);
			
			sptr += 2;
			maxlen -= 2;
			
			if (maxlen < 2 + nfmt * 2 || (int)nfmt < 0) {
				return -1;
			}	

			memset(fmtarr, 0, sizeof(fmtarr));

			if (nfmt == 1) {
				fmt = unaligned_read_be16(sptr);

				sptr += 2;
				maxlen -= 2;
				
				if (fmt == 1) {
					// All params are binary
					memset(fmtarr, 1, sizeof(fmtarr));
				}	
			}
			else {
				for (int i = 0; i < nfmt; ++i) {

					if (i < (int)PG_ROW_MAX_COLUMNS) {
						fmtarr[i] = unaligned_read_be16(sptr);
					}

					sptr += 2;
					maxlen -= 2;
				}
			}
			
			nparam = unaligned_read_be16(sptr);
			
			sptr += 2;
			maxlen -= 2;
			
			if (maxlen < 4 * nparam || (int)nparam < 0) {
				return -1;
			}	

			tdstrbuf_ << " $*P*$ "sv;

			for (int i = 0; i < nparam && i < (int)PG_ROW_MAX_COLUMNS; ++i) {
				if (maxlen < 4) {
					break;
				}	

				lenp = unaligned_read_be32(sptr);
				
				sptr += 4;
				maxlen -= 4;

				if ((int)lenp == -1) {
					tdstrbuf_ << "NULL,"sv;
					continue;
				}
				else if ((int)lenp < -1) {
					break;
				}	

				if (maxlen < (int)lenp || tdstrbuf_.bytes_left() < lenp) {
					break;
				}	

				if (fmtarr[i] == 0) {
					tdstrbuf_.append((const char *)sptr, lenp);
					tdstrbuf_ << ',';
				}	
				else {
					tdstrbuf_ << "<Binary Param>,"sv;
				}	

				sptr += lenp;
				maxlen -= lenp;
			}	
			
			if (nparam > PG_ROW_MAX_COLUMNS) {
				tdstrbuf_ << "..."sv;
			}	

			tran_.tran_type_ |= POSTGRES_PROTO::TYPE_PG_FUNCTION_CALL;
		}

		break;

	case POSTGRES_PROTO::MSG_F_TERMINATE :
		/* Set the response length to 1 so that error is shown for logout request */
		tran_.reslen_ = 1;

		break;

	case POSTGRES_PROTO::MSG_FB_COPYDATA :
	case POSTGRES_PROTO::MSG_F_COPYFAIL :
	case POSTGRES_PROTO::MSG_FB_COPYDONE :
		
		tran_.tran_type_ |= POSTGRES_PROTO::TYPE_PG_BULK_TRAN; /* Bulk Transaction */

		statpg_.copy_mode_ = 1;
		statpg_.nready_resp_pending_ = 1;

		break;


	case POSTGRES_PROTO::MSG_F_STARTUP :
		
		if (login_complete_) {
			return -1;
		}	
		else if (statpg_.skip_till_auth_resp_ || statpg_.skip_req_resp_till_ready_) {
				return 0;
		}	
		else {
			uint32_t			version;
			const char			*ptmp = (const char *)sptr;

			if (maxlen < 4) {
				login_complete_ = 1;
				is_midway_session_ = 1;
				statpg_.skip_req_resp_till_ready_ = 1;
				return -1;
			}	

			version = unaligned_read_be32(ptmp);

			ptmp += 4;
			maxlen -= 4;

			if (version == POSTGRES_PROTO::MSG_F_CANCEL) {
				if (maxlen < 8) {
					login_complete_ = 1;
					is_midway_session_ = 1;
					statpg_.skip_req_resp_till_ready_ = 1;
					return -1;
				}	

				uint32_t			pid;

				pid = unaligned_read_be32(ptmp);

				tdstrbuf_ << "Cancel Request $*P*$ PID "sv << pid;

				tran_.tran_type_ = POSTGRES_PROTO::TYPE_PG_CANCEL_QUERY;
				
				return 0;
			}	
			else if (version == POSTGRES_PROTO::MSG_F_SSL_REQ) {
				is_ssl_sess_ = 1;
				return 0;
			}
			else if (version == POSTGRES_PROTO::MSG_F_GSSENC_REQ) {
				skip_session_ = 1;
				gstats[STATPG_SKIP_SESS]++;
				return 0;
			}	
			else if ((version & 0xFFFFFF00) == POSTGRES_PROTO::MSG_F_AUTH_START) {
				/*
				 * Login Request
				 */

				const char			*puser = nullptr, *papp = nullptr, *pdb = nullptr;
				uint32_t			len, lenuser = 0, lenapp = 0, lendb = 0;

				if (maxlen < 5) {
					goto login_err;
				}

				do {
					if (0 == strcmp(ptmp, "user")) {
						ptmp += sizeof("user");
						maxlen -= sizeof("user");

						if (maxlen < 1) {
							goto login_err;
						}

						puser = ptmp;
						lenuser = len = strnlen(ptmp, maxlen);
						
						ptmp += len + 1;
						maxlen -= len + 1;

						continue;
					}	
					else if (0 == strcmp(ptmp, "database")) {
						ptmp += sizeof("database");
						maxlen -= sizeof("database");

						if (maxlen < 1) {
							goto login_err;
						}

						pdb = ptmp;
						lendb = len = strnlen(ptmp, maxlen);
						
						ptmp += len + 1;
						maxlen -= len + 1;

						continue;

					}
					else if (0 == strcmp(ptmp, "application_name")) {
						ptmp += sizeof("application_name");
						maxlen -= sizeof("application_name");

						if (maxlen < 1) {
							break;
						}

						papp = ptmp;
						lenapp = len = strnlen(ptmp, maxlen);
						
						ptmp += len + 1;
						maxlen -= len + 1;

						continue;
					}
					else {
						len = strnlen(ptmp, maxlen);

						ptmp += len + 1;
						maxlen -= len + 1;

						if (maxlen < 1) {
							break;
						}	

						len = strnlen(ptmp, maxlen);

						ptmp += len + 1;
						maxlen -= len + 1;
					}	

				} while (maxlen > 0);

				tdstrbuf_ << "*login* "sv;

				tran_.tran_type_ = POSTGRES_PROTO::TYPE_PG_LOGIN; /* Login Transaction */

				if (puser || pdb || papp) {
					struct in_addr 			in = {};

					tdstrbuf_.append(puser, lenuser);

					tdstat_.userbuf_.reset().append(puser, lenuser);

					tdstat_.appbuf_.reset();
					if (lenapp && papp) {
						tdstat_.appbuf_.append(papp, lenapp);
					}	

					tdstat_.dbbuf_.reset();
					if (lendb && pdb) {
						tdstat_.dbbuf_.append(pdb, lendb);
					}	
				}

				statpg_.skip_till_auth_resp_ = 1;
				statpg_.nready_resp_pending_ = 1;

			}	
			else {
login_err :				
				login_complete_ = 1;
				is_midway_session_ = 1;
				statpg_.skip_req_resp_till_ready_ = 1;
				return -1;
			}	
		}

		break;

	default :
		break;

	}

	return 0;
}

int POSTGRES_SESSINFO::handle_resp_token(POSTGRES_PROTO::PG_MSG_TYPES_E tkntype, uint32_t tknlen, uint8_t * sptr, int maxlen)
{
	const bool			istrunc = (maxlen < (int)tknlen);
	uint8_t				*pstart = sptr, *pend = sptr + maxlen;
	
	switch (tkntype) {
	
	case POSTGRES_PROTO::MSG_B_READY_FOR_QUERY :
		
		if (statpg_.nready_resp_pending_ > 0) {
			statpg_.nready_resp_pending_--;

			if (statpg_.nready_resp_pending_ == 0) {
				request_done();
			}
		}
		else if (tdstrbuf_.size()) {
			request_done();
		}	
		
		if (statpg_.skip_req_resp_till_ready_) {
			statpg_.skip_req_resp_till_ready_ = 0;
		}

		break;

	case POSTGRES_PROTO::MSG_B_ERROR_RESP :
		
		if (true) {
			char				c;
			const char			*ptmp = (const char *)sptr;			
			uint32_t			len;
			
			while (maxlen > 1) {
				c = *ptmp;

				ptmp++;
				maxlen--;
				
				len = strnlen(ptmp, maxlen);

				if (len > 0) {
					switch (c) {
					
					case 'S' :
						tdstat_.errorbuf_ << "Severity : "sv;
						tdstat_.errorbuf_.append(ptmp, len);
						tdstat_.errorbuf_ << ',';
			
						break;
					
					case 'C' :
						tdstat_.errorbuf_ << "Code : "sv;
						tdstat_.errorbuf_.append(ptmp, len);
						tdstat_.errorbuf_ << ',';
						
						tran_.errorcode_ = atoi(ptmp);
						break;
							
					case 'M' :
						tdstat_.errorbuf_ << "Message : "sv;
						tdstat_.errorbuf_.append(ptmp, len);
						tdstat_.errorbuf_ << ',';
			
						break;

					case 'R' :
						tdstat_.errorbuf_ << "Routine : "sv;
						tdstat_.errorbuf_.append(ptmp, len);
						tdstat_.errorbuf_ << ' ';
			
						break;

					default :
						break;
					}	
				}

				ptmp += len + 1;
				maxlen -= len + 1;
			}
			
			if (login_complete_ == 0) {
				request_done();
			}	
		}

		break;

	case POSTGRES_PROTO::MSG_B_CMD_COMPLETE :		
		if (!istrunc) {
			auto				*ptmp = (const char *)sptr;
			uint32_t			nrow = 0;

			if (maxlen > 5) {
				if (0 == memcmp(ptmp, "SELECT", sizeof("SELECT") - 1)) {
					ptmp += sizeof("SELECT") + 1;
					maxlen -= sizeof("SELECT") + 1;

					if (maxlen > 0) {
						nrow = atoi(ptmp);
					}
				}	
				else if (0 == memcmp(ptmp, "FETCH", sizeof("FETCH") - 1)) {
					ptmp += sizeof("FETCH") + 1;
					maxlen -= sizeof("FETCH") + 1;

					if (maxlen > 0) {
						nrow = atoi(ptmp);
					}	
				}

				if (nrow > 0) {
					tdstat_.nrows_ += nrow;
				}	
			}	
		}	

		break;

	case POSTGRES_PROTO::MSG_B_COPYOUT_RESP :
	case POSTGRES_PROTO::MSG_B_COPYIN_RESP :
	case POSTGRES_PROTO::MSG_B_COPYBOTH_RESP :
		
		tran_.tran_type_ |= POSTGRES_PROTO::TYPE_PG_BULK_TRAN; /* Bulk Transaction */

		statpg_.copy_mode_ = 1;
		statpg_.nready_resp_pending_ = 1;
		
		break;

	case POSTGRES_PROTO::MSG_B_KEYDATA :
		
		if (maxlen == 8) {
			tdstat_.spid_ = unaligned_read_be32(sptr);
		}

		break;


	case POSTGRES_PROTO::MSG_B_PARAM_STATUS :

		if (maxlen > 8) {
			auto				*ptmp = (const char *)sptr;
			uint32_t			len;

			// Update appname which may have changed
			if (0 == strcmp(ptmp, "application_name")) {
				ptmp += sizeof("application_name");
				maxlen -= sizeof("application_name");

				if (maxlen > 0) {
					len = strnlen(ptmp, maxlen);

					tdstat_.appbuf_.reset().append(ptmp, len);
				}	
			}	
		}

		break;

	case POSTGRES_PROTO::MSG_B_AUTH_RESP :
		if (login_complete_) {
			return -1;
		}	
		else if (maxlen >= 4) {
			const char			*ptmp = (const char *)sptr;			
			uint32_t			type;

			type = unaligned_read_be32(ptmp);

			if (type == 0) {
				login_complete_ = 1;
			}
		}

		break;


	default :
		break;

	}

	return 0;
}

void POSTGRES_SESSINFO::request_done(bool flushreq, bool clear_req)
{
	if (tdstrbuf_.size() > 0) {
		tran_.request_len_ = tdstrbuf_.size() + 1;
	}

	if (statpg_.part_query_started_ == 1) {
		drop_partial_req();
		statpg_.part_query_started_ = 0;
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

	statpg_.reset_stats_on_resp(clear_req);
}


void POSTGRES_SESSINFO::reset_on_error()
{
	request_done(false /* flushreq */, true /* clear_req */);

	if (svcsess_.common_.currdir_ == DirPacket::DirInbound) {
		statpg_.skip_to_req_after_resp_ = 1;
		gstats[STATPG_REQ_RESET_ERR]++;
	}
	else {
		gstats[STATPG_RESP_RESET_ERR]++;
	}	
}

bool POSTGRES_SESSINFO::print_req() noexcept
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
			ustrbuf << PARSE_FIELD_LEN(FIELD_USERNAME, tdstat_.userbuf_.size() + 1) << std::string_view(tdstat_.userbuf_.data(), tdstat_.userbuf_.size() + 1);
		}	

		if (tdstat_.appbuf_.size() && ustrbuf.bytes_left() >= sizeof(PARSE_FIELD_LEN) + tdstat_.appbuf_.size() + 1) {
			next++;
			ustrbuf << PARSE_FIELD_LEN(FIELD_APPNAME, tdstat_.appbuf_.size() + 1) << std::string_view(tdstat_.appbuf_.data(), tdstat_.appbuf_.size() + 1);
		}	

		if (tdstat_.dbbuf_.size() && ustrbuf.bytes_left() >= sizeof(PARSE_FIELD_LEN) + tdstat_.dbbuf_.size() + 1) {
			next++;
			ustrbuf << PARSE_FIELD_LEN(FIELD_DBNAME, tdstat_.dbbuf_.size() + 1) << std::string_view(tdstat_.dbbuf_.data(), tdstat_.dbbuf_.size() + 1);
		}	

		if (ptran->errorcode_ != 0 && (tdstat_.errorbuf_.size() && ustrbuf.bytes_left() >= sizeof(PARSE_FIELD_LEN) + tdstat_.errorbuf_.size() + 1)) {
			next++;
			ustrbuf << PARSE_FIELD_LEN(FIELD_ERRTXT, tdstat_.errorbuf_.size() + 1) << std::string_view(tdstat_.errorbuf_.data(), tdstat_.errorbuf_.size() + 1);
		}	

		if (tdstat_.dyn_prep_reqnum_ && tdstat_.dyn_prep_time_t_ && ustrbuf.bytes_left() >= 2 * sizeof(PARSE_FIELD_LEN) + 2 * sizeof(uint64_t)) {
			next++;
			ustrbuf << PARSE_FIELD_LEN(FIELD_PREP_REQNUM, sizeof(uint64_t)) << tdstat_.dyn_prep_reqnum_;

			next++;
			ustrbuf << PARSE_FIELD_LEN(FIELD_PREP_REQTIME, sizeof(time_t)) << tdstat_.dyn_prep_time_t_;
		}

		if (tdstat_.nrows_ && ustrbuf.bytes_left() >= sizeof(PARSE_FIELD_LEN) + sizeof(tdstat_.nrows_)) {
			next++;
			ustrbuf << PARSE_FIELD_LEN(FIELD_NROWS, sizeof(tdstat_.nrows_)) << tdstat_.nrows_;
		}

		if (tdstat_.spid_ && ustrbuf.bytes_left() >= sizeof(PARSE_FIELD_LEN) + sizeof(tdstat_.spid_)) {
			next++;
			ustrbuf << PARSE_FIELD_LEN(FIELD_SESSID, sizeof(tdstat_.spid_)) << tdstat_.spid_;
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

		return apihdlr.set_xfer_buf_sz(ptran->get_elem_size());
	}
	catch(...) {
		apihdlr.stats_.nxfer_pool_fail_++;
		return false;
	}	
}	

void POSTGRES_SESSINFO::print_stats(STR_WR_BUF & strbuf, time_t tcur, time_t tlast) noexcept
{
	uint64_t			diffstats[STATPG_MAX];

	std::memcpy(diffstats, gstats, sizeof(gstats));

	strbuf << "\nPostgres Interval Stats for "sv << tcur - tlast << " sec : "sv;
	
	for (int i = 0; i < (int)STATPG_MAX; ++i) {
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

	strbuf << "Postgres Cumulative Stats : "sv;
	
	for (int i = 0; i < (int)STATPG_MAX; ++i) {
		if (gstats[i] > 0) {
			strbuf << ' ' << gstatstr[i] << ' ' << gstats[i] << ',';
		}	
	}	

	strbuf << " Total Queries "sv << gtotal_queries;

	strbuf << "\n\n"sv;
}	

} // namespace gyeeta

#endif
