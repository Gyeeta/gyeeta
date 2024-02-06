//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_http_proto.h"
#include			"gy_http_proto_detail.h"
#include			"gy_proto_parser.h"
#include			"gy_http2_proto.h"

namespace gyeeta {

HTTP1_PROTO::HTTP1_PROTO(API_PARSE_HDLR & apihdlr, uint32_t api_max_len)
	: apihdlr_(apihdlr), api_max_len_(api_max_len)
{}	

HTTP1_PROTO::~HTTP1_PROTO() noexcept		= default;

std::pair<HTTP1_SESSINFO *, void *> HTTP1_PROTO::alloc_sess(SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr)
{
	return { new HTTP1_SESSINFO(*this, svcsess, hdr), nullptr };
}	

void HTTP1_PROTO::destroy(HTTP1_SESSINFO *pobj, void *pdata) noexcept
{
	delete pobj;
}	


void HTTP1_PROTO::handle_request_pkt(HTTP1_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	sess.handle_request_pkt(hdr, pdata);
}

void HTTP1_PROTO::handle_response_pkt(HTTP1_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	sess.handle_response_pkt(hdr, pdata);
}

void HTTP1_PROTO::handle_session_end(HTTP1_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr)
{
	sess.handle_session_end(hdr);
}	

void HTTP1_PROTO::handle_ssl_change(HTTP1_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	sess.handle_ssl_change(hdr, pdata);
}

void HTTP1_PROTO::print_stats(STR_WR_BUF & strbuf, time_t tcur, time_t tlast) noexcept
{
	HTTP1_SESSINFO::print_stats(strbuf, tcur, tlast);
}

HTTP1_SESSINFO::HTTP1_SESSINFO(HTTP1_PROTO & prot, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr)
	: HTTP1_PROTO(prot), 
	tran_(svcsess.common_.tlastpkt_usec_, svcsess.common_.tconnect_usec_, svcsess.common_.cli_ipport_, svcsess.common_.ser_ipport_, svcsess.common_.glob_id_, svcsess.proto_), 
	tdstrbuf_(prot.api_max_len_ - 1), 
	svcsess_(svcsess), is_https_(hdr.src_ == SRC_UPROBE_SSL)
{
	std::memset(tdstrbuf_.get(), 0, 128);
	
	gstats[STATH1_NEW_SESS]++;
	
	if (svcsess.common_.syn_seen_ == false) {
		is_midway_session_ = 1;
		
		// TODO

		gstats[STATH1_MIDWAY_SESS]++;
	}
}

HTTP1_SESSINFO::~HTTP1_SESSINFO() noexcept
{
	gstats[STATH1_SESS_COMPLETE]++;

	if (part_query_started_ == 1) {
		drop_partial_req();
	}
}

int HTTP1_SESSINFO::handle_request_pkt(PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	int				ret;
	auto				& common = svcsess_.common_;

	if (skip_session_ == 111) {
		gstats[STATH1_SESS_SKIP_PKT]++;
		return 0;
	}

	if (drop_seen_ || common.clidroptype_ == DT_DROP_SEEN || common.serdroptype_ == DT_DROP_SEEN) {

		if (part_query_started_ == 1) {
			drop_partial_req();
			part_query_started_ = 0;
		}
			
		// TODO
		drop_seen_ = 0;

		return 0;
	}

	ret = parse_req_pkt(hdr, pdata, hdr.datalen_);
	if (ret < 0) {
		gstats[STATH1_REQ_PKT_SKIP]++;
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

int HTTP1_SESSINFO::handle_response_pkt(PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	uint8_t 		*sptr = pdata;
	uint32_t 		bytes_left, pktlen = hdr.datalen_;
	auto			& common = svcsess_.common_;
	int 			ret;

	if (skip_session_ == 111) {
		gstats[STATH1_SESS_SKIP_PKT]++;
		return 0;
	}

	if (drop_seen_ || common.clidroptype_ == DT_DROP_SEEN || common.serdroptype_ == DT_DROP_SEEN) {

drop_chk :
		if (part_query_started_ == 1) {
			drop_partial_req();
			part_query_started_ = 0;
		}
			
		drop_seen_ = 0;

		// TODO

		return 0;
	}

	tran_.update_resp_stats(common.tlastpkt_usec_, hdr.datalen_);

	ret = parse_resp_pkt(hdr, pdata, hdr.datalen_);
	if (ret < 0) {
		gstats[STATH1_RESP_PKT_SKIP]++;
	}	

	return 0;
}

void HTTP1_SESSINFO::handle_session_end(PARSE_PKT_HDR & hdr)
{
	auto				& common = svcsess_.common_;

	if (part_query_started_ == 1) {
		drop_partial_req();
		part_query_started_ = 0;
	}
	
	if (reqnum_ == 0) {
		return;
	}	

	/*
	 * Flush existing request
	 */
	if (tran_.reqlen_ && tdstrbuf_.size() > 0 && (!(drop_seen_ || common.clidroptype_ == DT_DROP_SEEN || common.serdroptype_ == DT_DROP_SEEN))) {
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

}

void HTTP1_SESSINFO::handle_ssl_change(PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	is_https_ = true;
}	

void HTTP1_SESSINFO::set_new_req() noexcept
{
	COMMON_PROTO 				& common = svcsess_.common_;

	tran_.reset();

	tran_.treq_usec_			= common.tlastpkt_usec_;
	tran_.tupd_usec_			= common.tlastpkt_usec_;
	tran_.tin_usec_				= common.tlastpkt_usec_;
	
	reset_on_new_req();
}

void HTTP1_SESSINFO::reset_on_new_req() noexcept
{
	tdstrbuf_.reset();
	parambuf_.reset();
	errorbuf_.reset();
}

void HTTP1_SESSINFO::reset_req_frag_stat() noexcept
{
}	

void HTTP1_SESSINFO::reset_resp_frag_stat() noexcept
{
	resp_tkn_frag_ = 0;
	memset(resphdr_, 0, sizeof(resphdr_));
	resp_hdr_fraglen_ = 0;
	nbytes_resp_frag_ = 0;
	skip_resp_bytes_ = 0;
}	

void HTTP1_SESSINFO::reset_stats_on_resp(bool clear_req) noexcept
{
	if (clear_req) {	
		reset_req_frag_stat();	
	}

	reset_resp_frag_stat();
	
	// TODO
}	

bool HTTP1_SESSINFO::set_resp_expected() noexcept
{
	if ((uint8_t)connstate.req_method_ >= (uint8_t)METHOD_UNKNOWN) {
		connstate.reset();
		
		return false;
	}	

	if (nresp_pending_ + 1 < MAX_PIPELINE_ELEMS) {
		resp_pipline_[nresp_pending_++] = connstate.req_method_;
		connstate.reset();
		
		return true;
	}	

	gstats[STATH1_REQ_PIPELINE_OVF]++;

	resp_pipline_[0] = connstate.req_method_;
	nresp_pending_ = 1;
	nresp_completed_ = 0;

	connstate.reset();

	return false;
}

int HTTP1_SESSINFO::parse_req_pkt(PARSE_PKT_HDR & hdr, uint8_t *porigstart, const uint32_t len)
{
	uint8_t				*pdata = porigstart, * const pend = pdata + len, *ptmp, *ptmp2, *ptend, *pstart;
	int				pktlen = len, startlen, tlen;
	auto				& connstate = connstate;
	char				tbuf[64], c;
	bool				bret;

	
	if (skip_till_resp_ || skip_to_req_after_resp_ == 1) {
		return 0;
	}	
	else if (skip_to_req_after_resp_ == 2) {
		if (HTTP1_PROTO::get_req_method(pdata, pktlen) == METHOD_UNKNOWN) {
			skip_to_req_after_resp_ = 1;
			return 0;
		}	

		skip_to_req_after_resp_ = 0;
	}	
	
	do {
		pstart = pdata;
		startlen = pktlen;

		switch (connstate.state_) {
		
		case HCONN_IDLE		:	goto lbl_idle;
		case HCONN_HDR		:	goto lbl_hdr;
		case HCONN_CONTENT_DATA	:	goto lbl_cont_data;
		case HCONN_CHUNK_START	:	goto lbl_chunk_hdr;
		case HCONN_CHUNK_DATA	:	goto lbl_chunk_data;
		case HCONN_CHUNK_END	:	goto lbl_chunk_end;

		default			:	
						gstats[STATH1_INVALID_STATE]++;
						reset_till_resp();

						return 0;
		}

		if (connstate.state_ == HCONN_CHUNK_END) {
lbl_chunk_end :			
			if (pktlen <= 0) return 0;
			
			if (connstate.skip_till_eol_) {
				ptmp = get_delim_string(pdata, pktlen, "\r\n"sv);
				if (!ptmp) {
					return 0;
				}	
				if (*ptmp == '\r') {
					if (ptmp + 1 < pend) {
						if (ptmp[1] != '\n') {
							pdata = ptmp + 1;
							pktlen = pend - pdata;

							goto lbl_chunk_end;
						}	

						pdata = ptmp + 2;
						pktlen = pend - pdata;
					}
					else {
						return 0;
					}	
				}	
				else {
					pdata = ptmp + 1;
					pktlen = pend - pdata;
				}	
				
				connstate.skip_till_eol_ = false;
			}	

			if (pktlen <= 0) return 0;

			if (connstate.fraglen_ > 0) {
				if (connstate.fraglen_ > 3) {
					connstate.reset_till_resp(true);
					return 0;
				}	

				std::memcpy(tbuf, reqfragbuf_, connstate.fraglen_);
				std::memcpy(tbuf + connstate.fraglen_, pdata, std::min<uint32_t>(pktlen, 3));

				tlen = connstate.fraglen_;

				if (0 == memcmp(tbuf, "\r\n\r\n", 4)) {
					pktlen -= 4 - tlen;
					pdata += 4 - tlen;
					
					set_resp_expected();

					continue;
				}
				else {
					connstate.fraglen_ = 0;
				}	
			}

			ptmp = (uint8_t *)memmem(pdata, pktlen, "\r\n\r\n", 4);

			if (ptmp) {
				pdata = ptmp + 4;
				pktlen = pend - pdata;

				set_resp_expected();

				continue;
			}

			for (int i = 0; i < pktlen; ++i) {
				if (pdata[i] == '\r') {
					if (i + 3 == pktlen && pdata[i + 1] == '\n' && pdata[i + 2] == '\r') {
						memcpy(reqfragbuf_, "\r\n\r", 3);
						connstate.fraglen_ = 3;

						return 0;
					}	
					else if (i + 2 == pktlen && pdata[i + 1] == '\n') {
						memcpy(reqfragbuf_, "\r\n", 2);
						connstate.fraglen_ = 2;

						return 0;
					}	
					else if (i + 1 == pktlen) {
						*reqfragbuf_ = '\r';
						connstate.fraglen_ = 1;

						return 0;
					}	
				}	
			}	
			
			return 0;
		}

		if (connstate.state_ == HCONN_CHUNK_DATA) {
lbl_chunk_data :			
			if (pktlen <= 0) return 0;

			if (connstate.skip_till_eol_) {

				ptmp = get_delim_string(pdata, pktlen, "\r\n"sv);
				if (!ptmp) {
					return 0;
				}	
				if (*ptmp == '\r') {
					if (ptmp + 1 < pend) {
						if (ptmp[1] != '\n') {
							pdata = ptmp + 1;
							pktlen = pend - pdata;

							goto lbl_chunk_data;
						}	

						pdata = ptmp + 2;
						pktlen = pend - pdata;
					}
					else {
						return 0;
					}	
				}	
				else {
					pdata = ptmp + 1;
					pktlen = pend - pdata;
				}	
				
				connstate.skip_till_eol_ = false;
			}	

			uint64_t		slen = std::min<uint64_t>(pktlen, connstate.data_chunk_left_);
			auto			savepayload = connstate.save_req_payload_;
			
			if (slen > 0 && tdstrbuf_.size() > 0 && connstate.save_req_payload_ && parambuf_.bytes_left() > 0 && gy_isprint_ascii(*pdata)) {
				if (slen == 1 || gy_isprint_ascii(pdata[1])) {
					if (0 == parambuf_.size()) {
						parambuf_ << " $*PARAM*$ "sv;
					}
					parambuf_.append(pdata, slen);
				}	
			}

			if (pktlen < connstate.data_chunk_left_) {
				connstate.data_chunk_left_ -= pktlen;

				return 0;
			}	
			else if (pktlen == connstate.data_chunk_left_) {

				connstate.reset_skip_method();
				connstate.state_ = HCONN_CHUNK_START;

				return 0;
			}	
			else {
				pdata += connstate.data_chunk_left_;
				pktlen -= connstate.data_chunk_left_;

				if (pktlen >= 2 && pdata[0] == '\r' && pdata[1] == '\n') {
					pktlen -= 2;
					pdata += 2;
				}	

				connstate.reset_skip_method();

				connstate.state_ = HCONN_CHUNK_START;
				connstate.save_req_payload_ = savepayload;
			}	
		}	


		if (connstate.state_ == HCONN_CHUNK_START) {
lbl_chunk_hdr :			
			if (pktlen <= 0) return 0;

			*tbuf = 0;

			if (connstate.fraglen_ == 0) {
				if (pktlen > 0 && is_eol(*pdata)) {
					pktlen--;
					pdata++;
				}
				if (pktlen > 0 && is_eol(*pdata)) {
					pktlen--;
					pdata++;
				}

				if (pktlen == 0) {
					return 0;
				}

				ptmp = tbuf;

				while (pktlen > 0 && ptmp < tbuf + sizeof(tbuf) - 1) {
					c = (char)*pdata;

					if (gy_isxdigit_ascii(c)) {
						*ptmp++ = c;

						pdata++;
						pktlen--;
					}	
					else {
						if (ptmp == tbuf) {
							connstate.reset_till_resp(true);
							return 0;
						}	
						break;
					}	
				}	
				
				if (ptmp == tbuf || ptmp == tbuf + sizeof(tbuf) - 1) {
					connstate.reset_till_resp(true);
					return 0;
				}	

				if (pktlen == 0) {
					static_assert(sizeof(tbuf) < MAX_FRAG_LEN);

					connstate.fraglen_ = ptmp - tbuf;
					std::memcpy(reqfragbuf_, tbuf, connstate.fraglen_);
					
					return 0;
				}	

				*ptmp = 0;
			}
			else {
				if (connstate.fraglen_ >= MAX_FRAG_LEN) {
					gstats[STATH1_CHUNK_FRAG_OVF]++;

					connstate.reset_till_resp(true);
					return 0;
				}	

				std::memcpy(tbuf, reqfragbuf_, connstate.fraglen_);
				ptmp = tbuf + connstate.fraglen_;

				connstate.fraglen_ = 0;

				while (pktlen > 0 && ptmp < tbuf + sizeof(tbuf) - 1) {
					c = (char)*pdata;

					if (gy_isxdigit_ascii(c)) {
						*ptmp++ = c;

						pdata++;
						pktlen--;
					}	
					else {
						break;
					}	
				}	
				
				if (ptmp == tbuf + sizeof(tbuf) - 1) {
					connstate.reset_till_resp(true);
					return 0;
				}	

				*ptmp = 0;
			}	
			
			bret = string_to_number(tbuf, connstate.data_chunk_len_, nullptr, 16);
			if (!bret) {
				connstate.reset_till_resp(true);
				return 0;
			}	

			connstate.data_chunk_left_ = connstate.data_chunk_len_;

			if (pktlen >= 2 && pdata[0] == '\r' && pdata[1] == '\n') {
				pktlen -= 2;
				pdata += 2;
			}	
			else {
				connstate.skip_till_eol_ = true;
			}	

			if (connstate.data_chunk_len_ == 0) {
				connstate.state_ = HCONN_CHUNK_END;
				continue;
			}	
			else {
				connstate.state_ = HCONN_CHUNK_DATA;
			}	

			continue;
		}	

		if (connstate.state_ == HCONN_CONTENT_DATA) {
lbl_cont_data :			
			if (pktlen <= 0) return 0;

			uint64_t		slen = std::min<uint64_t>(pktlen, connstate.data_chunk_left_);
			
			if (slen > 0 && tdstrbuf_.size() > 0 && connstate.save_req_payload_ && parambuf_.bytes_left() > 0 && gy_isprint_ascii(*pdata)) {
				if (slen == 1 || gy_isprint_ascii(pdata[1])) {
					if (connstate.data_chunk_left_ == connstate.data_chunk_len_) {
						parambuf_ << " $*PARAM*$ "sv;
					}
					parambuf_.append(pdata, slen);
				}	
			}

			if (pktlen < connstate.data_chunk_left_) {
				connstate.data_chunk_left_ -= pktlen;

				return 0;
			}	
			else {
				pktlen -= connstate.data_chunk_left_;
				pdata += connstate.data_chunk_left_;

				set_resp_expected();

				continue;
			}	
		}	

		if (connstate.state_ == HCONN_IDLE) {
lbl_idle :			
			if (pktlen <= 0) return 0;

			startlen = pktlen;

			if (skip_till_req_) {
				skip_till_req_ = false;
			}
			
			if (connstate.fraglen_ > 0) {
				if (connstate.fraglen_ > MAX_METHOD_LEN) {
					connstate.reset_till_resp(true);
					return 0;
				}	

				static_assert(MAX_METHOD_LEN + 8 < sizeof(tbuf));
				
				std::memset(tbuf, 0, sizeof(tbuf));

				std::memcpy(tbuf, reqfragbuf_, connstate.fraglen_);
				std::memcpy(tbuf + connstate.fraglen_, pdata, std::min<int>(pktlen, 8));

				connstate.fraglen_ = 0;

				connstate.req_method_ = HTTP1_PROTO::get_req_method(tbuf, 10);
				
				if (connstate.req_method_ == METHOD_UNKNOWN) {
					connstate.reset_till_resp(true);
					return 0;
				}	

				while (pktlen > 0 && *pdata != ' ') {
					pktlen--;	
					pdata++;
				}	
			}	
			else {
				if (pktlen >= 2 && pdata[0] == '\r' && pdata[1] == '\n') {
					pktlen -= 2;
					pdata += 2;
				}	
				else if (*pdata == '\n') {
					pktlen--;
					pdata++;
				}	

				if (pktlen <= 0) return 0;
				
				connstate.req_method_ = HTTP1_PROTO::get_req_method(pdata, pktlen);

				if (connstate.req_method_ == METHOD_UNKNOWN) {

					if (pktlen < MAX_METHOD_LEN) {
						std::memcpy(reqfragbuf_, pdata, pktlen);
						connstate.fraglen_ = pktlen;

						return 0;
					}	
					
					if (pdata == porigstart && reqnum_ == 0 && true == HTTP2_PROTO::is_valid_req_resp(pdata, pktlen, pktlen, 
						DirPacket::DirInbound, svcsess_. !is_midway_session_ /* is_init */)) {
						
						gstats[STATH1_HTTP2_CONN]++;

						svcsess_.set_new_proto(PROTO_HTTP2);
						return -1;
					}	

					gstats[STATH1_REQ_SYNC_MISS]++;

					skip_till_resp_ = true;
					return 0;
				}	

				tlen = http_methods[connstate.req_method_].size();
				pktlen -= tlen;
				pdata += tlen;
			}

			while (pktlen > 0 && *pdata == ' ') {
				pktlen--;	
				pdata++;
			}	

			if (pktlen <= 0) return 0;

			if ((uint8_t)connstate.req_method_ < (uint8_t)METHOD_UNKNOWN) {
				if (0 == tdstrbuf_.size()) {
					set_new_req();
				}
				else {	
					tdstrbuf_ << "; "sv;
				}	
				tdstrbuf_ << http_methods[connstate.req_method_];
			}
			else {
				reset_till_resp(false);
				return 0;
			}	

			if (connstate.req_method_ == METHOD_GET || connstate.req_method_ == METHOD_HEAD) {
				ptmp = (uint8_t *)get_delim_string((const char *)pdata, pktlen, "? "sv);
			}
			else {
				ptmp = (uint8_t *)memchr(pdata, ' ', pktlen);
			}	

			if (!ptmp) {
				tdstrbuf_.append(pdata, pktlen);
				
				connstate.reset_skip_method();
				connstate.state_ = HCONN_HDR;
				connstate.skip_till_eol_ = true;

				return 0;
			}	

			tdstrbuf_.append(pdata, ptmp - pdata);

			pdata = ptmp + 1;
			pktlen = pend - pdata;

			if (*ptmp == '?') {
				parambuf_ << " $*PARAM*$ "sv;

				ptmp = (uint8_t *)memchr(pdata, ' ', pktlen);

				if (!ptmp) {
					parambuf_.append(pdata, pktlen);
					
					connstate.state_ = HCONN_HDR;
					connstate.skip_till_eol_ = true;

					return 0;
				}	
				
				parambuf_.append(pdata, ptmp - pdata);

				pdata = ptmp + 1;
				pktlen = pend - pdata;
			}	
			
			connstate.reset_skip_method();
			connstate.state_ = HCONN_HDR;

			while (pktlen > 0 && *pdata == ' ') {
				pktlen--;	
				pdata++;
			}	

			if (pktlen > sizeof("HTTP/1.1")) {
				if (0 == memcmp(pdata, "HTTP/1.", GY_CONST_STRLEN("HTTP/1."))) {
					if ('0' == pdata[GY_CONST_STRLEN("HTTP/1.")]) {
						is_http10_ = true;
					}	
				}	

				pdata += GY_CONST_STRLEN("HTTP/1.1");
				pktlen -= GY_CONST_STRLEN("HTTP/1.1");
			}	

			if (pktlen < 2) {
				connstate.skip_till_eol_ = true;
				return 0;
			}	

			if (pdata[0] != '\r' || pdata[1] != '\n') {
				ptmp = (uint8_t *)memchr(pdata + 1, '\r', pktlen - 1);
				if (!ptmp) {
					connstate.skip_till_eol_ = true;
					return 0;
				}	

				pdata = ptmp + 2;
				pktlen = pend - pdata;
			}
			else {
				pktlen -= 2;
				pdata += 2;
			}	

			if (pktlen == 0) {
				return 0;
			}	
		}	

		if (connstate.state_ == HCONN_HDR) {
lbl_hdr :			
			if (pktlen <= 0) return 0;

			if (connstate.skip_till_eol_) {
				ptmp = (uint8_t *)get_delim_string((const char *)pdata, pktlen, "\r\n"sv);
			
				if (!ptmp) {
					return 0;
				}

				pdata = ptmp + 1;
				pktlen = pend - pdata;

				if (*ptmp == '\r') {
					if (pktlen <= 0) {
						return 0;
					}	

					if (*pdata == '\n') {
						pktlen--;
						pdata++;
					}

					connstate.skip_till_eol_ = false;
				}	
				else {
					connstate.skip_till_eol_ = false;
				}	
				
				if (pktlen <= 0) return 0;
			}	

			std::string_view			sv1;

			ptmp = (uint8_t *)memchr(pdata, '\r', pktlen);

			if (connstate.fraglen_ > 0 && connstate.fraglen_ + 1 < MAX_FRAG_LEN) {
				
				if (!ptmp) {
					connstate.fraglen_ = 0;
					connstate.skip_till_eol_ = true;

					return 0;
				}	

				if (ptmp - pdata + 1 + connstate.fraglen_ < MAX_FRAG_LEN) {
					std::memcpy(reqfragbuf_ + connstate.fraglen_, pdata, ptmp - pdata + 1);
				}	
				else {
					pdata = ptmp + 2;
					pktlen = pend - pdata;

					connstate.fraglen_ = 0;
					connstate.skip_till_eol_ = true;
					
					continue;
				}	

				sv1 = {(const char *)reqfragbuf_, connstate.fraglen_ + ptmp - pdata};

				connstate.fraglen_ = 0;
			}	
			else {
				if (!ptmp) {
					if (pktlen + 4 < MAX_FRAG_LEN) {
						std::memcpy(reqfragbuf_, pdata, pktlen);
						connstate.fraglen_ = pktlen;

						return 0;
					}
					else {
						connstate.fraglen_ = 0;
						connstate.skip_till_eol_ = true;

						return 0;
					}	
				}

				sv1 = {(const char *)pdata, ptmp - pdata};
			}

			pdata = ptmp + 2;
			pktlen = pend - pdata;

			for (int i = 0; i < GY_ARRAY_SIZE(req_hdr_http); ++i) {
				const auto		& rv = req_hdr_http[i];

				if (sv1.size() > rv.size() && (0 == memcmp(sv1.data(), rv.data(), rv.size()))) {
					if (i == (int)REQ_HDR_CONTENT_TYPE) {
						if (connstate.save_req_payload_ != 0) {
							continue;
						}

						for (int j = 0; j < GY_ARRAY_SIZE(req_content_types); ++j) {
							const auto			& t = req_content_types[i];

							if (memmem(sv1.data() + rv.size(), sv1.size() - rv.size(), t.data(), t.size())) {
								connstate.save_req_payload_ = 1;
								break;
							}	
						}	
					}	
					else if (i == (int)REQ_HDR_CONTENT_LEN) {
						size_t				colen = 0;

						ptmp = sv1.data() + rv.size();
						
						bret = string_to_number(ptmp, colen, nullptr, 10);

						if (!bret || colen > GY_UP_GB(50)) {
							reset_till_resp(true);
							return 0;
						}	

						if (connstate.is_chunk_data_ == false && colen > 0) {
							connstate.is_content_len_ = true;
							connstate.data_chunk_len_ = colen;
							connstate.data_chunk_left_ = colen;
						}	
					}	
					else if (i == (int)REQ_HDR_CONTENT_ENCODE) {
						STR_RD_BUF		strbuf(sv1.data() + rv.size(), sv1.size() - rv.size());
						int8_t			is_chunk = 0;

						while (auto wv = strbuf.get_next_word(true /* ignore_separator_in_nbytes */, " ;,", true /* skip_leading_space */,
								true /* ignore_escape */, true /* skip_multi_separators */); wv.size() > 0) {
							
							for (int j = 0; j < GY_ARRAY_SIZE(comp_content_types); ++j) {
								const auto			& t = comp_content_types[i];

								if (t.size() == wv.size() && (0 == memcmp(wv.data(), t.data(), wv.size()))) {
									connstate.save_req_payload_ = (int8_t)-1;

									break;
								}	
							}	
						}	
					}
					else if (i == (int)REQ_HDR_TRANSFER_ENCODE) {
						STR_RD_BUF		strbuf(sv1.data() + rv.size(), sv1.size() - rv.size());
						bool			is_chunk = false;

						while (auto wv = strbuf.get_next_word(true /* ignore_separator_in_nbytes */, " ;,", true /* skip_leading_space */,
								true /* ignore_escape */, true /* skip_multi_separators */); wv.size() > 0) {
							
							if (0 == memcmp(wv.data(), "chunked", sizeof("chunked") - 1)) {
								is_chunk = true;
							}	
							else {
								for (int j = 0; j < GY_ARRAY_SIZE(comp_content_types); ++j) {
									const auto			& t = comp_content_types[i];

									if (t.size() == wv.size() && (0 == memcmp(wv.data(), t.data(), wv.size()))) {
										connstate.save_req_payload_ = (int8_t)-1;

										is_chunk = false;
										break;
									}	
								}	
							}	
						}	

						if (is_chunk) {
							connstate.data_chunk_len_ = 0;
							connstate.data_chunk_left_ = 0;
							connstate.is_content_len_ = false;
							connstate.is_chunk_data_ = true;
						}	
					}	
					else if (i == (int)REQ_HDR_USER_AGENT) {
						useragentbuf_.reset().append(sv1.data() + rv.size(), sv1.size() - rv.size());
					}						
				}	
			}	

			if (pktlen < 0) {
				connstate.skip_till_eol_ = true;
				return 0;
			}	

			if (pktlen >= 2 && pdata[0] == '\r' && pdata[1] == '\n') {
				pktlen -= 2;
				pdata += 2;

				if (!connstate.is_content_len_ && !connstate.is_chunk_data_) {
					set_resp_expected();

					continue;
				}

				if (connstate.is_chunk_data_) {
					connstate.state_ = HCONN_CHUNK_START;
					connstate.data_chunk_len_ = 0;
					connstate.data_chunk_left_ = 0;
					continue;
				}	
				else if (connstate.is_content_len_ && connstate.data_chunk_len_) {
					connstate.state_ = HCONN_CONTENT_DATA;
					continue;
				}	
				else {
					set_resp_expected();

					skip_till_resp_ = true;
					return 0;
				}	
			}
		}

	} while (pdata < pend && pdata > pstart && pktlen > 0);

	return 0;
}

int HTTP1_SESSINFO::parse_resp_pkt(PARSE_PKT_HDR & hdr, uint8_t *porigstart, const uint32_t len)
{
	uint8_t				*pdata = porigstart, * const pend = pdata + len, *ptmp, *ptmp2, *ptend, *pstart;
	int				pktlen = len, startlen, tlen;
	auto				& connstate = respstate_;
	char				tbuf[128], c;
	bool				bret;

	if (skip_till_req_) {
		return 0;
	}
	else if (skip_to_req_after_resp_) {
		if (skip_to_req_after_resp_ == 1) {
			if (HTTP1_PROTO::is_valid_resp(pdata, pktlen)) {
				skip_to_req_after_resp_ = 2;
			}
		}	

		return 0;
	}

	do {
		pstart = pdata;
		startlen = pktlen;

		switch (connstate.state_) {
		
		case HCONN_IDLE		:	goto lbl_idle;
		case HCONN_HDR		:	goto lbl_hdr;
		case HCONN_CONTENT_DATA	:	goto lbl_cont_data;
		case HCONN_CHUNK_START	:	goto lbl_chunk_hdr;
		case HCONN_CHUNK_DATA	:	goto lbl_chunk_data;
		case HCONN_CHUNK_END	:	goto lbl_chunk_end;

		default			:	
						gstats[STATH1_INVALID_STATE]++;
						reset_on_resp_error();

						return 0;
		}

		if (connstate.state_ == HCONN_CHUNK_END) {
lbl_chunk_end :			
			if (pktlen <= 0) return 0;
			
			if (connstate.skip_till_eol_) {
				ptmp = get_delim_string(pdata, pktlen, "\r\n"sv);
				if (!ptmp) {
					return 0;
				}	
				if (*ptmp == '\r') {
					if (ptmp + 1 < pend) {
						if (ptmp[1] != '\n') {
							pdata = ptmp + 1;
							pktlen = pend - pdata;

							goto lbl_chunk_end;
						}	

						pdata = ptmp + 2;
						pktlen = pend - pdata;
					}
					else {
						return 0;
					}	
				}	
				else {
					pdata = ptmp + 1;
					pktlen = pend - pdata;
				}	
				
				connstate.skip_till_eol_ = false;
			}	

			if (pktlen <= 0) return 0;

			if (connstate.fraglen_ > 0) {
				if (connstate.fraglen_ > 3) {
					connstate.reset_on_resp_error();
					return 0;
				}	

				std::memcpy(tbuf, respfragbuf_, connstate.fraglen_);
				std::memcpy(tbuf + connstate.fraglen_, pdata, std::min<uint32_t>(pktlen, 3));

				tlen = connstate.fraglen_;

				if (0 == memcmp(tbuf, "\r\n\r\n", 4)) {
					pktlen -= 4 - tlen;
					pdata += 4 - tlen;
					
					request_done();

					continue;
				}
				else {
					connstate.fraglen_ = 0;
				}	
			}

			ptmp = (uint8_t *)memmem(pdata, pktlen, "\r\n\r\n", 4);

			if (ptmp) {
				pdata = ptmp + 4;
				pktlen = pend - pdata;

				request_done();

				continue;
			}

			for (int i = 0; i < pktlen; ++i) {
				if (pdata[i] == '\r') {
					if (i + 3 == pktlen && pdata[i + 1] == '\n' && pdata[i + 2] == '\r') {
						memcpy(respfragbuf_, "\r\n\r", 3);
						connstate.fraglen_ = 3;

						return 0;
					}	
					else if (i + 2 == pktlen && pdata[i + 1] == '\n') {
						memcpy(respfragbuf_, "\r\n", 2);
						connstate.fraglen_ = 2;

						return 0;
					}	
					else if (i + 1 == pktlen) {
						*respfragbuf_ = '\r';
						connstate.fraglen_ = 1;

						return 0;
					}	
				}	
			}	
			
			return 0;
		}

		if (connstate.state_ == HCONN_CHUNK_DATA) {
lbl_chunk_data :			
			if (pktlen <= 0) return 0;

			if (connstate.skip_till_eol_) {

				ptmp = get_delim_string(pdata, pktlen, "\r\n"sv);
				if (!ptmp) {
					return 0;
				}	
				if (*ptmp == '\r') {
					if (ptmp + 1 < pend) {
						if (ptmp[1] != '\n') {
							pdata = ptmp + 1;
							pktlen = pend - pdata;

							goto lbl_chunk_data;
						}	

						pdata = ptmp + 2;
						pktlen = pend - pdata;
					}
					else {
						return 0;
					}	
				}	
				else {
					pdata = ptmp + 1;
					pktlen = pend - pdata;
				}	
				
				connstate.skip_till_eol_ = false;
			}	

			if (pktlen < connstate.data_chunk_left_) {
				connstate.data_chunk_left_ -= pktlen;

				return 0;
			}	
			else if (pktlen == connstate.data_chunk_left_) {

				connstate.reset_skip_method();
				connstate.state_ = HCONN_CHUNK_START;

				return 0;
			}	
			else {
				pdata += connstate.data_chunk_left_;
				pktlen -= connstate.data_chunk_left_;

				if (pktlen >= 2 && pdata[0] == '\r' && pdata[1] == '\n') {
					pktlen -= 2;
					pdata += 2;
				}	

				connstate.reset_skip_method();

				connstate.state_ = HCONN_CHUNK_START;
				connstate.save_req_payload_ = savepayload;
			}	
		}	


		if (connstate.state_ == HCONN_CHUNK_START) {
lbl_chunk_hdr :			
			if (pktlen <= 0) return 0;

			*tbuf = 0;

			if (connstate.fraglen_ == 0) {
				if (pktlen > 0 && is_eol(*pdata)) {
					pktlen--;
					pdata++;
				}
				if (pktlen > 0 && is_eol(*pdata)) {
					pktlen--;
					pdata++;
				}

				if (pktlen == 0) {
					return 0;
				}

				ptmp = tbuf;

				while (pktlen > 0 && ptmp < tbuf + sizeof(tbuf) - 1) {
					c = (char)*pdata;

					if (gy_isxdigit_ascii(c)) {
						*ptmp++ = c;

						pdata++;
						pktlen--;
					}	
					else {
						if (ptmp == tbuf) {
							connstate.reset_on_resp_error();
							return 0;
						}	
						break;
					}	
				}	
				
				if (ptmp == tbuf || ptmp == tbuf + sizeof(tbuf) - 1) {
					connstate.reset_on_resp_error();
					return 0;
				}	

				if (pktlen == 0) {
					static_assert(sizeof(tbuf) < MAX_FRAG_LEN);

					connstate.fraglen_ = ptmp - tbuf;
					std::memcpy(respfragbuf_, tbuf, connstate.fraglen_);
					
					return 0;
				}	

				*ptmp = 0;
			}
			else {
				if (connstate.fraglen_ >= MAX_FRAG_LEN) {
					gstats[STATH1_CHUNK_FRAG_OVF]++;

					connstate.reset_on_resp_error();
					return 0;
				}	

				std::memcpy(tbuf, respfragbuf_, connstate.fraglen_);
				ptmp = tbuf + connstate.fraglen_;

				connstate.fraglen_ = 0;

				while (pktlen > 0 && ptmp < tbuf + sizeof(tbuf) - 1) {
					c = (char)*pdata;

					if (gy_isxdigit_ascii(c)) {
						*ptmp++ = c;

						pdata++;
						pktlen--;
					}	
					else {
						break;
					}	
				}	
				
				if (ptmp == tbuf + sizeof(tbuf) - 1) {
					connstate.reset_on_resp_error();
					return 0;
				}	

				*ptmp = 0;
			}	
			
			bret = string_to_number(tbuf, connstate.data_chunk_len_, nullptr, 16);
			if (!bret) {
				connstate.reset_on_resp_error();
				return 0;
			}	

			connstate.data_chunk_left_ = connstate.data_chunk_len_;

			if (pktlen >= 2 && pdata[0] == '\r' && pdata[1] == '\n') {
				pktlen -= 2;
				pdata += 2;
			}	
			else {
				connstate.skip_till_eol_ = true;
			}	

			if (connstate.data_chunk_len_ == 0) {
				connstate.state_ = HCONN_CHUNK_END;
				continue;
			}	
			else {
				connstate.state_ = HCONN_CHUNK_DATA;
			}	

			continue;
		}	

		if (connstate.state_ == HCONN_CONTENT_DATA) {
lbl_cont_data :			
			if (pktlen <= 0) return 0;

			if (pktlen < connstate.data_chunk_left_) {
				connstate.data_chunk_left_ -= pktlen;

				return 0;
			}	
			else {
				pktlen -= connstate.data_chunk_left_;
				pdata += connstate.data_chunk_left_;

				request_done();

				continue;
			}	
		}	

		if (connstate.state_ == HCONN_IDLE) {
lbl_idle :			
			if (pktlen <= 0) return 0;

			startlen = pktlen;

			if (skip_till_resp_) {
				skip_till_resp_ = false;
			}	

			connstate.req_method_ = get_curr_req_method();
			
			if (connstate.req_method_ == METHOD_UNKNOWN) {
				connstate.reset_on_resp_error();
				return 0;
			}	

			if (connstate.fraglen_ > 0) {
				if (connstate.fraglen_ > sizeof(tbuf) - 8) {
					connstate.reset_on_resp_error();
					return 0;
				}	

				std::memset(tbuf, 0, sizeof(tbuf));

				std::memcpy(tbuf, respfragbuf_, connstate.fraglen_);
				std::memcpy(tbuf + connstate.fraglen_, pdata, tlen = std::min<int>(pktlen, 8));

				tlen += connstate.fraglen_;
				connstate.fraglen_ = 0;

				auto			[status, pnext] = get_status_response(tbuf, tlen);

				if (!pnext) {
					connstate.reset_on_resp_error();
					return 0;
				}

				connstate.resp_status_ = (uint16_t)status;

				pdata = pnext;
				pktlen = pend - pdata;
			}	
			else {
				if (pktlen >= 2 && pdata[0] == '\r' && pdata[1] == '\n') {
					pktlen -= 2;
					pdata += 2;
				}	
				else if (*pdata == '\n') {
					pktlen--;
					pdata++;
				}	

				if (pktlen <= 0) return 0;
				
				auto			[status, pnext] = get_status_response(tbuf, tlen);

				if (!pnext) {
					connstate.reset_on_resp_error();
					return 0;
				}

				connstate.resp_status_ = (uint16_t)status;

				pdata = pnext;
				pktlen = pend - pdata;
			}

			if (pktlen <= 0) return 0;

			connstate.reset_skip_method();
			connstate.state_ = HCONN_HDR;

			ptmp = (uint8_t *)memchr(pdata, '\r', pktlen);

			if (!ptmp || (ptmp + 1 == pend) || (ptmp[1] != '\n')) {
				connstate.skip_till_eol_ = true;
				return 0;
			}	

			pdata = ptmp + 2;
			pktlen = pend - pdata;

			if (pktlen <= 0) {
				return 0;
			}	
		}	

		if (connstate.state_ == HCONN_HDR) {
lbl_hdr :			
			if (pktlen <= 0) return 0;

			if (connstate.skip_till_eol_) {
				ptmp = (uint8_t *)get_delim_string((const char *)pdata, pktlen, "\r\n"sv);
			
				if (!ptmp) {
					return 0;
				}

				pdata = ptmp + 1;
				pktlen = pend - pdata;

				if (*ptmp == '\r') {
					if (pktlen <= 0) {
						return 0;
					}	

					if (*pdata == '\n') {
						pktlen--;
						pdata++;
					}

					connstate.skip_till_eol_ = false;
				}	
				else {
					connstate.skip_till_eol_ = false;
				}	
				
				if (pktlen <= 0) return 0;
			}	

			std::string_view			sv1;

			ptmp = (uint8_t *)memchr(pdata, '\r', pktlen);

			if (connstate.fraglen_ > 0 && connstate.fraglen_ + 1 < MAX_FRAG_LEN) {
				
				if (!ptmp) {
					connstate.fraglen_ = 0;
					connstate.skip_till_eol_ = true;

					return 0;
				}	

				if (ptmp - pdata + 1 + connstate.fraglen_ < MAX_FRAG_LEN) {
					std::memcpy(respfragbuf_ + connstate.fraglen_, pdata, ptmp - pdata + 1);
				}	
				else {
					pdata = ptmp + 2;
					pktlen = pend - pdata;

					connstate.fraglen_ = 0;
					connstate.skip_till_eol_ = true;
					
					continue;
				}	

				sv1 = {(const char *)respfragbuf_, connstate.fraglen_ + ptmp - pdata};

				connstate.fraglen_ = 0;
			}	
			else {
				if (!ptmp) {
					if (pktlen + 4 < MAX_FRAG_LEN) {
						std::memcpy(respfragbuf_, pdata, pktlen);
						connstate.fraglen_ = pktlen;

						return 0;
					}
					else {
						connstate.fraglen_ = 0;
						connstate.skip_till_eol_ = true;

						return 0;
					}	
				}

				sv1 = {(const char *)pdata, ptmp - pdata};
			}

			pdata = ptmp + 2;
			pktlen = pend - pdata;

			if (is_resp_body_valid(connstate.resp_status_, connstate.req_method_)) {
				for (int i = 0; i < GY_ARRAY_SIZE(resp_hdr_http); ++i) {
					const auto		& rv = resp_hdr_http[i];

					if (sv1.size() > rv.size() && (0 == memcmp(sv1.data(), rv.data(), rv.size()))) {
						if (i == (int)RESP_HDR_CONTENT_LEN) {
							size_t				colen = 0;

							ptmp = sv1.data() + rv.size();
							
							bret = string_to_number(ptmp, colen, nullptr, 10);

							if (!bret || colen > GY_UP_GB(50)) {
								reset_on_resp_error();
								return 0;
							}	

							if (connstate.is_chunk_data_ == false && colen > 0) {
								connstate.is_content_len_ = true;
								connstate.data_chunk_len_ = colen;
								connstate.data_chunk_left_ = colen;
							}	
						}	
						else if (i == (int)RESP_HDR_TRANSFER_ENCODE) {
							STR_RD_BUF		strbuf(sv1.data() + rv.size(), sv1.size() - rv.size());
							bool			is_chunk = false;

							while (auto wv = strbuf.get_next_word(true /* ignore_separator_in_nbytes */, " ;,", true /* skip_leading_space */,
									true /* ignore_escape */, true /* skip_multi_separators */); wv.size() > 0) {
								
								if (0 == memcmp(wv.data(), "chunked", sizeof("chunked") - 1)) {
									is_chunk = true;
								}	
								else {
									for (int j = 0; j < GY_ARRAY_SIZE(comp_content_types); ++j) {
										const auto			& t = comp_content_types[i];

										if (t.size() == wv.size() && (0 == memcmp(wv.data(), t.data(), wv.size()))) {
											connstate.save_req_payload_ = (int8_t)-1;

											is_chunk = false;
											break;
										}	
									}	
								}	
							}	

							if (is_chunk) {
								connstate.data_chunk_len_ = 0;
								connstate.data_chunk_left_ = 0;
								connstate.is_content_len_ = false;
								connstate.is_chunk_data_ = true;
							}	
						}	
					}	
				}	
			}

			if (pktlen < 0) {
				connstate.skip_till_eol_ = true;
				return 0;
			}	

			if (pktlen >= 2 && pdata[0] == '\r' && pdata[1] == '\n') {
				pktlen -= 2;
				pdata += 2;
				
				if (!connstate.is_content_len_ && !connstate.is_chunk_data_) {
					if (connstate.resp_status_ >= 100 && connstate.resp_status_ < 200) {
						connstate.reset_skip_method();
						connstate.state_ = HCONN_HDR;
					}	
					else if (connstate.req_method_ == METHOD_CONNECT && 
						(connstate.resp_status_ >= 200 && connstate.resp_status_ < 300)) {
						
						gstats[STATH1_CONNECT_VPN]++;
						skip_session_ = 111;

						return 0;
					}	
					else {
						request_done();
					}	

					continue;
				}

				if (connstate.is_chunk_data_) {
					connstate.state_ = HCONN_CHUNK_START;
					connstate.data_chunk_len_ = 0;
					connstate.data_chunk_left_ = 0;
					continue;
				}	
				else if (connstate.is_content_len_ && connstate.data_chunk_len_) {
					connstate.state_ = HCONN_CONTENT_DATA;
					continue;
				}	
				else {
					request_done();

					skip_till_req_ = true;
					return 0;
				}	
			}
		}

	} while (pdata < pend && pdata > pstart && pktlen > 0);

	return 0;
}

void HTTP1_SESSINFO::request_done(bool flushreq, bool clear_req)
{
	if (tdstrbuf_.size() > 0) {
		if (parambuf_.size() > 0) {
			size_t			maxsz - get_api_max_len();

			if (tdstrbuf_.size() + parambuf_.size() > maxsz) {
				parambuf_.set_len_external(maxsz > tdstrbuf_.size() ? maxsz - tdstrbuf_.size() : 0);
			}	
		}	
		tran_.request_len_ = tdstrbuf_.size() + parambuf_.size();
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
		reset_on_new_req();
	}

	reset_stats_on_resp(clear_req);
}


void HTTP1_SESSINFO::reset_on_resp_error()
{
	request_done(false /* flushreq */, true /* clear_req */);

	skip_till_req_ = 1;

	gstats[STATH1_RESP_RESET_ERR]++;
}

// Called from response contexts
METHODS_E HTTP1_SESSINFO::get_curr_req_method() noexcept
{
	if (nresp_completed_ < nresp_pending_) {
		if (nresp_completed_ < MAX_PIPELINE_ELEMS) {
			return resp_pipline_[nresp_completed_];
		}

		nresp_completed_ = nresp_pending_ = 0;

		return METHOD_UNKNOWN;
	}	

	if (reqstate_.state_ != HCONN_IDLE) {
		return reqstate_.req_method_;
	}	

	return METHOD_UNKNOWN;
}


bool HTTP1_SESSINFO::print_req() noexcept
{
	return true;
}

void HTTP1_SESSINFO::print_stats(STR_WR_BUF & strbuf, time_t tcur, time_t tlast) noexcept
{

}

} // namespace gyeeta

