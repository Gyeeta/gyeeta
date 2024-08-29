//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_sybase_proto.h"
#include			"gy_sybase_proto_detail.h"
#include			"gy_proto_parser.h"
#include			"gy_tls_proto.h"

namespace gyeeta {

#define SYB_TDS_SKIP			1
#define SYB_TDS_PARSE			2

#define SYB_RET_CHECK_PKT_END		7
#define SYB_MAX_TOKEN_SAVELEN		4096

#define SYB_GET_TDS_LEN(_sptr, _tdslen)									\
do {													\
	(_tdslen) = unaligned_read_be16((_sptr));							\
	if (gy_unlikely(((_tdslen) < 8) || ((_tdslen) > 65534))) {					\
		return -1;										\
	}												\
} while (0)

#define SYB_GET_TDS_TYPE(_sptr, _tdstype)								\
do {													\
	(_tdstype) = *(uint8_t *)(_sptr);								\
	if (gy_unlikely((_tdstype) > SYB_TYPE_MIGRATE)) {						\
		return -1;										\
	}												\
} while (0)


#define SYB_TDS_DONELEN			9
#define SYB_MAX_NUM_COLS		128

static SYB_DATATYPE_INFO_T sybdatalist[0xFF + 1];
static const int MONTHDAYS[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
static const int LMONTHDAYS[] = {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

static void init_sybgdatalist() noexcept
{
	for (int i = 0; i <= 0xFF; ++i) {
	
		switch (i) {

		case SYB_TDS_BINARY 	: sybdatalist[i] = {"SYB_TDS_BINARY", 255, SYB_DATA_TYPE_SIMPLE_LEN1, 0, 1, nullptr}; break;
		case SYB_TDS_BIT	: sybdatalist[i] = {"SYB_TDS_BIT", 1, SYB_DATA_TYPE_NORMAL, 0, 0, nullptr}; break;	
		case SYB_TDS_BLOB	: sybdatalist[i] = {"SYB_TDS_BLOB", ~0u, SYB_DATA_TYPE_BLOB, 1, 4, "Blob Data"}; break;
		case SYB_TDS_BOUNDARY	: sybdatalist[i] = {"SYB_TDS_BOUNDARY", 255, SYB_DATA_TYPE_SIMPLE_LEN1, 1, 1, ""}; break;
		case SYB_TDS_CHAR	: sybdatalist[i] = {"SYB_TDS_CHAR", 255, SYB_DATA_TYPE_SIMPLE_LEN1, 0, 1, nullptr}; break;
		case SYB_TDS_DATE	: sybdatalist[i] = {"SYB_TDS_DATE", 4, SYB_DATA_TYPE_NORMAL, 0, 0, nullptr}; break;
		case SYB_TDS_DATEN	: sybdatalist[i] = {"SYB_TDS_DATEN", 4, SYB_DATA_TYPE_SIMPLE_LEN1, 1, 1, nullptr}; break;
		case SYB_TDS_DATETIME	: sybdatalist[i] = {"SYB_TDS_DATETIME", 8, SYB_DATA_TYPE_NORMAL, 0, 0, nullptr}; break;
		case SYB_TDS_DATETIMEN	: sybdatalist[i] = {"SYB_TDS_DATETIMEN", 8, SYB_DATA_TYPE_SIMPLE_LEN1, 1, 1, nullptr}; break;
		case SYB_TDS_DECN	: sybdatalist[i] = {"SYB_TDS_DECN", 33, SYB_DATA_TYPE_DECIMAL, 1, 1, nullptr}; break;
		case SYB_TDS_FLT4	: sybdatalist[i] = {"SYB_TDS_FLT4", 4, SYB_DATA_TYPE_NORMAL, 0, 0, nullptr}; break;
		case SYB_TDS_FLT8	: sybdatalist[i] = {"SYB_TDS_FLT8", 8, SYB_DATA_TYPE_NORMAL, 0, 0, nullptr}; break;
		case SYB_TDS_FLTN	: sybdatalist[i] = {"SYB_TDS_FLTN", 8, SYB_DATA_TYPE_SIMPLE_LEN1, 1, 1, nullptr}; break;
		case SYB_TDS_IMAGE	: sybdatalist[i] = {"SYB_TDS_IMAGE", ~0u, SYB_DATA_TYPE_TEXT, 1, 4, "Image Data"}; break;
		case SYB_TDS_INT1	: sybdatalist[i] = {"SYB_TDS_INT1", 1, SYB_DATA_TYPE_NORMAL, 0, 0, nullptr}; break;
		case SYB_TDS_INT2	: sybdatalist[i] = {"SYB_TDS_INT2", 2, SYB_DATA_TYPE_NORMAL, 0, 0, nullptr}; break;
		case SYB_TDS_INT4	: sybdatalist[i] = {"SYB_TDS_INT4", 4, SYB_DATA_TYPE_NORMAL, 0, 0, nullptr}; break;
		case SYB_TDS_INT8	: sybdatalist[i] = {"SYB_TDS_INT8", 8, SYB_DATA_TYPE_NORMAL, 0, 0, nullptr}; break;
		case SYB_TDS_INTERVAL	: sybdatalist[i] = {"SYB_TDS_INTERVAL", 8, SYB_DATA_TYPE_NORMAL, 0, 0, ""}; break;
		case SYB_TDS_INTN	: sybdatalist[i] = {"SYB_TDS_INTN", 8, SYB_DATA_TYPE_SIMPLE_LEN1, 1, 1, nullptr}; break;
		case SYB_TDS_LONGBINARY	: sybdatalist[i] = {"SYB_TDS_LONGBINARY", ~0u, SYB_DATA_TYPE_SIMPLE_LEN4, 1, 4, nullptr}; break;
		case SYB_TDS_LONGCHAR	: sybdatalist[i] = {"SYB_TDS_LONGCHAR", ~0u, SYB_DATA_TYPE_SIMPLE_LEN4, 1, 4, nullptr}; break;
		case SYB_TDS_MONEY	: sybdatalist[i] = {"SYB_TDS_MONEY", 8, SYB_DATA_TYPE_NORMAL, 0, 0, nullptr}; break;
		case SYB_TDS_MONEYN	: sybdatalist[i] = {"SYB_TDS_MONEYN", 8, SYB_DATA_TYPE_SIMPLE_LEN1, 1, 1, nullptr}; break;
		case SYB_TDS_NUMN	: sybdatalist[i] = {"SYB_TDS_NUMN", 33, SYB_DATA_TYPE_DECIMAL, 1, 1, nullptr}; break;
		case SYB_TDS_SENSITIVITY: sybdatalist[i] = {"SYB_TDS_SENSITIVITY", 255, SYB_DATA_TYPE_SIMPLE_LEN1, 1, 1, ""}; break;
		case SYB_TDS_SHORTDATE	: sybdatalist[i] = {"SYB_TDS_SHORTDATE", 4, SYB_DATA_TYPE_NORMAL, 0, 0, nullptr}; break;
		case SYB_TDS_SHORTMONEY	: sybdatalist[i] = {"SYB_TDS_SHORTMONEY", 4, SYB_DATA_TYPE_NORMAL, 0, 0, nullptr}; break;
		case SYB_TDS_SINT1	: sybdatalist[i] = {"SYB_TDS_SINT1", 1, SYB_DATA_TYPE_NORMAL, 0, 0, nullptr}; break;
		case SYB_TDS_TEXT	: sybdatalist[i] = {"SYB_TDS_TEXT", ~0u, SYB_DATA_TYPE_TEXT, 1, 4, "Text Data"}; break;
		case SYB_TDS_TIME	: sybdatalist[i] = {"SYB_TDS_TIME", 4, SYB_DATA_TYPE_NORMAL, 0, 0, nullptr}; break;
		case SYB_TDS_TIMEN	: sybdatalist[i] = {"SYB_TDS_TIMEN", 4, SYB_DATA_TYPE_SIMPLE_LEN1, 1, 1, nullptr}; break;
		case SYB_TDS_UINT2	: sybdatalist[i] = {"SYB_TDS_UINT2", 2, SYB_DATA_TYPE_NORMAL, 0, 0, nullptr}; break;
		case SYB_TDS_UINT4	: sybdatalist[i] = {"SYB_TDS_UINT4", 4, SYB_DATA_TYPE_NORMAL, 0, 0, nullptr}; break;
		case SYB_TDS_UINT8	: sybdatalist[i] = {"SYB_TDS_UINT8", 8, SYB_DATA_TYPE_NORMAL, 0, 0, nullptr}; break;
		case SYB_TDS_UINTN	: sybdatalist[i] = {"SYB_TDS_UINTN", 8, SYB_DATA_TYPE_SIMPLE_LEN1, 1, 1, nullptr}; break;
		case SYB_TDS_UNITEXT	: sybdatalist[i] = {"SYB_TDS_UNITEXT", ~0u, SYB_DATA_TYPE_TEXT, 1, 4, "Unicode Text Data"}; break;
		case SYB_TDS_VARBINARY	: sybdatalist[i] = {"SYB_TDS_VARBINARY", 255, SYB_DATA_TYPE_SIMPLE_LEN1, 1, 1, "Binary Data"}; break;
		case SYB_TDS_VARCHAR	: sybdatalist[i] = {"SYB_TDS_VARCHAR", 255, SYB_DATA_TYPE_SIMPLE_LEN1, 1, 1, nullptr}; break;
		case SYB_TDS_XML	: sybdatalist[i] = {"SYB_TDS_XML", ~0u, SYB_DATA_TYPE_TEXT, 1, 4, "XML Data"}; break;
		case SYB_TDS_BIGDATETIMEN:sybdatalist[i] = {"SYB_TDS_BIGDATETIMEN", 8, SYB_DATA_TYPE_BIGDATE, 1, 1, nullptr}; break;
		case SYB_TDS_BIGTIMEN	: sybdatalist[i] = {"SYB_TDS_BIGTIMEN", 8, SYB_DATA_TYPE_BIGDATE, 1, 1, nullptr}; break;

		default 		: sybdatalist[i] = {}; break;

		}
	}	
}	

SYBASE_ASE_PROTO::SYBASE_ASE_PROTO(API_PARSE_HDLR & apihdlr, uint32_t api_max_len)
	: apihdlr_(apihdlr), api_max_len_(api_max_len), max_syb_req_token_(api_max_len_ + 512), max_syb_resp_token_(2048)
{
	init_sybgdatalist();
}	

SYBASE_ASE_PROTO::~SYBASE_ASE_PROTO() noexcept		= default;

std::pair<SYBASE_ASE_SESSINFO *, void *> SYBASE_ASE_PROTO::alloc_sess(SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr)
{
	return { new SYBASE_ASE_SESSINFO(*this, svcsess), nullptr };
}	

void SYBASE_ASE_PROTO::destroy(SYBASE_ASE_SESSINFO *pobj, void *pdata) noexcept
{
	delete pobj;
}	

void SYBASE_ASE_PROTO::handle_request_pkt(SYBASE_ASE_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	sess.handle_request_pkt(hdr, pdata);
}

void SYBASE_ASE_PROTO::handle_response_pkt(SYBASE_ASE_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	sess.handle_response_pkt(hdr, pdata);
}

void SYBASE_ASE_PROTO::handle_session_end(SYBASE_ASE_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr)
{
	sess.handle_session_end(hdr);
}	

void SYBASE_ASE_PROTO::handle_ssl_change(SYBASE_ASE_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	sess.handle_ssl_change(hdr, pdata);
}


void SYBASE_ASE_PROTO::print_stats(STR_WR_BUF & strbuf, time_t tcur, time_t tlast) noexcept
{
	SYBASE_ASE_SESSINFO::print_stats(strbuf, tcur, tlast);
}	
	
SYBASE_ASE_SESSINFO::SYBASE_ASE_SESSINFO(SYBASE_ASE_PROTO & prot, SVC_SESSION & svcsess)
	: SYBASE_ASE_PROTO(prot),
	tran_(svcsess.common_.tlastpkt_usec_, svcsess.common_.tconnect_usec_, svcsess.common_.cli_ipport_, svcsess.common_.ser_ipport_, 
		svcsess.common_.glob_id_, svcsess.proto_, svcsess.psvc_ ? svcsess.psvc_->comm_ : nullptr), 
	tdstrbuf_(prot.api_max_len_ - 1), 
	svcsess_(svcsess), psvc_(svcsess.psvc_)
{

	pReqFragBuf = (uint8_t *)malloc_or_throw(SYB_FRAGBUFLEN);

	pResFragBuf = (uint8_t *)malloc_or_throw(SYB_FRAGBUFLEN);

	pCurList = new DataList(SYB_MAX_CURSORS, 512);
	pCurIDLookupMap = new Hashtbl();

	if (pCurList->Init(SYBTDS_SQLLISTSIZE, sizeof(SYB_IW_CURSOR_LOOKUP_T)) == -1) {
		GY_THROW_SYS_EXCEPTION("Failed to init sybase cursor list");
	}	

	if (pCurIDLookupMap->set(sizeof(uint32_t), SYBTDS_HASHTBLSIZE) == 0) {
		GY_THROW_EXCEPTION("Failed to set sybase cursor list");
	}	

	std::memset(tdstrbuf_.get(), 0, 128);
	std::memset(pReqFragBuf, 0, 256);
	std::memset(pResFragBuf, 0, 256);

	std::memset(&sybstat_, 0, sizeof(sybstat_));
	
	gstats[STATSYB_NEW_SESS]++;

	if (svcsess.common_.syn_seen_ == false) {
		sybstat_.chk_for_tds_byteorder = 1;
		sybstat_.is_login_complete = 1;

		gstats[STATSYB_MIDWAY_SESS]++;
	}

	*curname = '\0';
}	
	
SYBASE_ASE_SESSINFO::~SYBASE_ASE_SESSINFO() noexcept
{
	gstats[STATSYB_SESS_COMPLETE]++;

	if (part_query_started_ == 1) {
		drop_partial_req();
	}

	if (pReqFragBuf) free(pReqFragBuf);
	if (pResFragBuf) free(pResFragBuf);
	if (pMultiTDSBuf) free(pMultiTDSBuf);
	if (pTokenBuf) free(pTokenBuf);

	const auto deallocate_lookup = [](char *id, int val, void *param) -> int
	{
		((SYBASE_ASE_SESSINFO *)param)->deallocate_cursor((SYB_IW_CURSOR_LOOKUP_T *)((SYBASE_ASE_SESSINFO *)param)->pCurList->GetElementPtr(val));

		return 0;
	};

	if (pCurList && pCurIDLookupMap) {
		pCurIDLookupMap->iterate(deallocate_lookup, (void *)this, 0);
	}

	delete pCurList;
	delete pCurIDLookupMap;

	if (pCurrParamFmt) {
		if (pCurrParamFmt->pcol) free(pCurrParamFmt->pcol);
		free(pCurrParamFmt);
	}

	delete pDynStmt;
	delete pDynStmtMap;
}	


void SYBASE_ASE_SESSINFO::request_text_set(const char *request, int reqlen, int chk_append)
{
	if (request == nullptr) return;

	if (chk_append && tdstrbuf_.size()) {
		tdstrbuf_ << ' ';
	}	

	if (reqlen > 0) {
		tdstrbuf_.append(request, reqlen);
	}	
	else {
		tdstrbuf_.append(request);	
	}	
}


void SYBASE_ASE_SESSINFO::new_request() noexcept
{
	new_request(svcsess_.common_.tlastpkt_usec_);
}	

void SYBASE_ASE_SESSINFO::new_request(uint64_t tupd_usec) noexcept
{
	tran_.reset();

	tran_.treq_usec_		= tupd_usec;
	tran_.tupd_usec_		= tupd_usec;
	
	tdstrbuf_.reset();
	tdstat_.reset_on_req();
}	

void SYBASE_ASE_SESSINFO::request_done()
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
			print_req();
		}

		tran_.reset();
		tdstrbuf_.reset();
		tdstat_.reset_on_req();
	}
}

void SYBASE_ASE_SESSINFO::handle_error(const char *errortext, size_t error_text_len, int error_code, uint8_t errclass)
{
	tran_.errorcode_ = error_code;

	if (error_code != 0) {
		tdstat_.errclass_ = errclass;
		tdstat_.is_serv_err_ = (errclass >= 17);	
		tdstat_.errorbuf_.append(errortext, error_text_len);
	}
}

void SYBASE_ASE_SESSINFO::set_session_pid(int pid)
{
	tdstat_.hostpid_ = pid;
}


/*
 * Returns 0 for a Complete TDS Fragment, 1 for incomplete, -1 for error.
 * *pbytes_left contains the pending bytes
 */ 
int SYBASE_ASE_SESSINFO::handle_prev_req_frag(uint8_t *sptr, uint32_t ppkt_len, uint32_t *pbytes_left) 
{
	uint8_t			*ptmp, tdstype;
	uint16_t 		frag_req_nparsed, frag_req_nleft;
	uint32_t 		ncopy;
	uint16_t 		tdslen;

	frag_req_nparsed = sybstat_.frag_req_nparsed;
	frag_req_nleft = sybstat_.frag_req_nleft;

	if (gy_unlikely(frag_req_nparsed < 8)) {
		/*
		 * TDS Header Fragmented.
		 */ 
		if (frag_req_nparsed + ppkt_len < 8 && ppkt_len <= 8) ncopy = ppkt_len;
		else ncopy = 8 - frag_req_nparsed;

		memcpy(pReqFragBuf + frag_req_nparsed, sptr, ncopy);
		sybstat_.frag_req_nparsed += ncopy;

		if (gy_unlikely(sybstat_.frag_req_nparsed < 8)) {
			*pbytes_left = 0;
			sybstat_.pcap_req_frag = 1;
			sybstat_.frag_req_nleft = 0;
			return 1;
		}

		sptr += ncopy;
		ppkt_len -= ncopy;

		ptmp = pReqFragBuf;

		SYB_GET_TDS_LEN(ptmp + 2, tdslen);
		SYB_GET_TDS_TYPE(ptmp, tdstype);

		frag_req_nparsed = sybstat_.frag_req_nparsed = 8;
		frag_req_nleft = sybstat_.frag_req_nleft = tdslen - 8;

		sybstat_.ign_req_frag = is_tds_of_interest(tdstype, DirPacket::DirInbound);
	}

	if (frag_req_nleft <= ppkt_len) {
		*pbytes_left = ppkt_len - frag_req_nleft;

		if (frag_req_nleft + frag_req_nparsed > 65535) return -1;

		if (sybstat_.ign_req_frag == SYB_TDS_PARSE) memcpy(pReqFragBuf + frag_req_nparsed, sptr, frag_req_nleft);

		sybstat_.frag_req_nleft = 0;
		sybstat_.frag_req_nparsed = 0;

		sybstat_.pcap_req_frag = 0;

		return 0;
	}

	/*
	 * Still Fragmented.
	 */
	frag_req_nleft -= ppkt_len;	

	*pbytes_left = 0;

	if (frag_req_nparsed + ppkt_len > 65535) return -1;

	if (sybstat_.ign_req_frag == SYB_TDS_PARSE && ppkt_len < SYB_FRAGBUFLEN) memcpy(pReqFragBuf + frag_req_nparsed, sptr, ppkt_len);

	sybstat_.frag_req_nparsed += ppkt_len;
	sybstat_.frag_req_nleft = frag_req_nleft;
	sybstat_.pcap_req_frag = 1;

	return 1;
}


/*
 * Returns 0 for a Complete TDS Resp Fragment, 1 for incomplete, -1 for error.
 * *pbytes_left contains the pending bytes
 */ 
int SYBASE_ASE_SESSINFO::handle_prev_resp_frag(uint8_t *sptr, uint32_t ppkt_len, uint32_t *pbytes_left)
{
	uint8_t			*ptmp, tdstype;
	uint16_t 		frag_resp_nparsed, frag_resp_nleft;
	uint32_t 		ncopy;
	uint16_t 		tdslen;

	frag_resp_nparsed = sybstat_.frag_resp_nparsed;
	frag_resp_nleft = sybstat_.frag_resp_nleft;

	if (gy_unlikely(frag_resp_nparsed < 8)) {
		/*
		 * TDS Header Fragmented.
		 */ 
		if (frag_resp_nparsed + ppkt_len < 8 && ppkt_len <= 8) ncopy = ppkt_len;
		else ncopy = 8 - frag_resp_nparsed;

		memcpy(pResFragBuf + frag_resp_nparsed, sptr, ncopy);
		sybstat_.frag_resp_nparsed += ncopy;

		if (gy_unlikely(sybstat_.frag_resp_nparsed < 8)) {
			*pbytes_left = 0;
			sybstat_.pcap_resp_frag = 1;
			sybstat_.frag_resp_nleft = 0;
			return 1;
		}

		sptr += ncopy;
		ppkt_len -= ncopy;

		ptmp = pResFragBuf;

		SYB_GET_TDS_LEN(ptmp + 2, tdslen);
		SYB_GET_TDS_TYPE(ptmp, tdstype);

		frag_resp_nparsed = sybstat_.frag_resp_nparsed = 8;
		frag_resp_nleft = sybstat_.frag_resp_nleft = tdslen - 8;

		sybstat_.ign_resp_frag = is_tds_of_interest(tdstype, DirPacket::DirOutbound);
	}

	if (frag_resp_nleft <= ppkt_len) {
		*pbytes_left = ppkt_len - frag_resp_nleft;

		if (frag_resp_nleft + frag_resp_nparsed > 65535) return -1;

		if (sybstat_.ign_resp_frag == SYB_TDS_PARSE) memcpy(pResFragBuf + frag_resp_nparsed, sptr, frag_resp_nleft);

		sybstat_.frag_resp_nleft = 0;
		sybstat_.frag_resp_nparsed = 0;

		sybstat_.pcap_resp_frag = 0;
		return 0;
	}

	/*
	 * Still Fragmented.
	 */
	frag_resp_nleft -= ppkt_len;	

	*pbytes_left = 0;

	if (frag_resp_nparsed + ppkt_len > 65535) return -1;

	if (sybstat_.ign_resp_frag == SYB_TDS_PARSE && ppkt_len < SYB_FRAGBUFLEN) memcpy(pResFragBuf + frag_resp_nparsed, sptr, ppkt_len);

	sybstat_.frag_resp_nparsed += ppkt_len;
	sybstat_.frag_resp_nleft = frag_resp_nleft;
	sybstat_.pcap_resp_frag = 1;

	return 1;
}


void SYBASE_ASE_SESSINFO::reset_req_flags()
{
	sybstat_.skip_pcap_req_till_eom = 0;
	sybstat_.skip_token_req = 0;
	sybstat_.skip_request_text = 0;
	sybstat_.param_req_pending = 0;
	sybstat_.cursor_query_active = 0;
}


void SYBASE_ASE_SESSINFO::set_resp_type_expected(SYB_RESP_TYPE_E resptype)
{
	reset_req_flags();

	sybstat_.to_flush_req = 1;

	sybstat_.npcap_response_pending++;

	if (gy_unlikely(sybstat_.npcap_response_pending > SYB_MAX_MULTIPLEX)) sybstat_.npcap_response_pending = 1;

	sybstat_.pcap_resp_type_expected[sybstat_.npcap_response_pending - 1] = resptype;
}


void SYBASE_ASE_SESSINFO::reset_resp_type_expected()
{
	if (gy_unlikely((sybstat_.npcap_response_pending == 0) || (sybstat_.npcap_response_pending > SYB_MAX_MULTIPLEX))) {
		sybstat_.npcap_response_pending = 1;
	}	

	sybstat_.npcap_response_pending--;
	for (uint8_t i = 1; i <= sybstat_.npcap_response_pending; i++) {
		sybstat_.pcap_resp_type_expected[i - 1] = sybstat_.pcap_resp_type_expected[i];
	}	

	sybstat_.curr_pcap_cursors_pending = 0;

	sybstat_.skip_to_req_after_resp = 0;

	sybstat_.pcap_attn_ack_expected = 0;
	sybstat_.skip_pcap_resp_till_eom = 0;
	sybstat_.cursor_query_active = 0;
	sybstat_.skip_pcap_req_till_eom = 0;
	sybstat_.is_data_col_ptr_valid = 0;
	sybstat_.pcap_buf_saved_len = 0;
	memset(&sybstat_.data_col_ptr, '\0', sizeof(sybstat_.data_col_ptr));

	sybstat_.fragresp_len = 0;

	sybstat_.skip_token_resp = 0;
	sybstat_.to_flush_req = 0;

	reset_req_flags();

	*sybstat_.cursortext = '\0';

	if (gy_unlikely(pMultiTDSBuf != nullptr)) {
		free(pMultiTDSBuf);
		pMultiTDSBuf = nullptr;
		sybstat_.max_multi_tds_len = sybstat_.curr_multi_tds_len = 0;
	}

	if (gy_unlikely(pTokenBuf != nullptr)) {
		free(pTokenBuf);
		pTokenBuf = nullptr;
		sybstat_.max_token_buf_len = 0;
		sybstat_.token_pending_len = 0;
		sybstat_.token_curr_len = 0;
	}
}


void SYBASE_ASE_SESSINFO::attention_reset_resp_type_expected()
{
	sybstat_.pcap_attn_ack_expected = 0;

	/* Set to 1 since reset_resp_type_expected() will be called later */

	sybstat_.npcap_response_pending = 1; 
}


int SYBASE_ASE_SESSINFO::find_pcap_cursor(uint32_t cursor)
{
	if (gy_unlikely((cursor == 0) || (sybstat_.ncurrcursor == 0))) return 1;

	pCurrCursor = nullptr;
	int index = -1;

	if (pCurIDLookupMap->search((char *)&cursor, &index)) {
		gstats[STATSYB_CURSOR_FIND_SUCCESS]++;

		if ((pCurrCursor = (SYB_IW_CURSOR_LOOKUP_T *)pCurList->GetElementPtr(index))) {
			if (*pCurrCursor->cursortext) {
				request_text_set(pCurrCursor->cursortext, pCurrCursor->len <= SYBTDS_SQLSTMTLEN ? pCurrCursor->len : SYBTDS_SQLSTMTLEN);

				if (pCurrCursor->dyn_prep_reqnum <= tdstat_.reqnum_) {
					tdstat_.dyn_prep_reqnum_ = pCurrCursor->dyn_prep_reqnum;
					tdstat_.dyn_prep_time_t_ = pCurrCursor->dyn_prep_time_t;
				}
				else {
					tdstat_.dyn_prep_reqnum_ = 0;
					tdstat_.dyn_prep_time_t_ = 0;
				}
			}

			return 0;
		}
	}
	else {
		gstats[STATSYB_CURSOR_FIND_FAIL]++;

		tdstat_.dyn_prep_reqnum_ = 0;
		tdstat_.dyn_prep_time_t_ = 0;
	}

	return 1;
}


int SYBASE_ASE_SESSINFO::add_cursor(uint32_t cursor, uint32_t status)
{
	if (gy_unlikely(cursor == 0)) return 1;

	pCurrCursor = nullptr;
	SYB_IW_CURSOR_LOOKUP_T curElem = {0};
	curElem.pcapcurstate = (uint16_t)status;
	curElem.pcurrparamfmt = nullptr;

	if (*curname) {
		GY_STRNCPY(curElem.cursorname, curname, SYBTDS_CURNAMELEN - 1);
		*curname = '\0';
	}

	if (*sybstat_.cursortext) {
		GY_STRNCPY(curElem.cursortext, sybstat_.cursortext, sizeof(curElem.cursortext));
		*sybstat_.cursortext = '\0';
		curElem.dyn_prep_reqnum = tdstat_.reqnum_;
		curElem.dyn_prep_time_t = tran_.treq_usec_/GY_USEC_PER_SEC;
		curElem.len = strlen(curElem.cursortext);
	}


	int index = pCurList->AddElement((void *)&curElem, sizeof(SYB_IW_CURSOR_LOOKUP_T));
	if (index >= 0) {
		gstats[STATSYB_CURSOR_ADDED]++;

		pCurIDLookupMap->add((char *)&cursor, index);
		sybstat_.ncurrcursor++;
		pCurrCursor = (SYB_IW_CURSOR_LOOKUP_T *)pCurList->GetElementPtr(index);
	}
	else {
		gstats[STATSYB_CURSOR_ADD_FAIL]++;

		return -1;
	}	

	return 0;
}


int SYBASE_ASE_SESSINFO::close_cursor(uint32_t cursor)
{
	if (gy_unlikely((cursor == 0) || (sybstat_.ncurrcursor == 0))) return 1;

	int index = -1;

	if (pCurIDLookupMap->search((char *)&cursor, &index)) {
		if ((pCurrCursor = (SYB_IW_CURSOR_LOOKUP_T *)pCurList->GetElementPtr(index))) {
			deallocate_cursor(pCurrCursor);
			pCurList->DeleteElement(index, 1);
			pCurIDLookupMap->remove((char *)&cursor);
			sybstat_.ncurrcursor--;
			pCurrCursor = nullptr;
			return 0;
		}
	}

	return 1;
}


void SYBASE_ASE_SESSINFO::deallocate_cursor(SYB_IW_CURSOR_LOOKUP_T *pcursor)
{
	if (gy_unlikely(pcursor == nullptr)) return;

	if ((pcursor->pcurrparamfmt) && (pcursor->pcurrparamfmt->magic == SYB_ROWFMT_MAGIC)) {
		if (pcursor->pcurrparamfmt->pcol) free(pcursor->pcurrparamfmt->pcol);

		free(pcursor->pcurrparamfmt);
	}
	pcursor->pcurrparamfmt = nullptr;

	pcursor->pcapcurstate = 0;

	gstats[STATSYB_CURSOR_DEALLOC]++;
}


int SYBASE_ASE_SESSINFO::handle_done_token_resp(uint8_t *sptr, uint16_t len, uint16_t *ptokenlen, int handle_frag)
{
	uint8_t	*ptmp = sptr;
	uint16_t fdstatus;

	if (len < SYB_TDS_DONELEN) {
		if (handle_frag) sybstat_.skip_token_resp = SYB_TDS_DONELEN - len;
		else sybstat_.skip_pcap_resp_till_eom = 1;

		return SYB_RET_CHECK_PKT_END;
	}

	fdstatus = unaligned_read_16(ptmp + 1, sybstat_.orig_client_bo);
	if (fdstatus & SYB_DONE_ATTN) {
		/*
		 * Now reset all pending responses 
		 */ 
		attention_reset_resp_type_expected();
	}

	*ptokenlen = SYB_TDS_DONELEN;

	return 0;
}


int SYBASE_ASE_SESSINFO::handle_doneinproc_token_resp(uint8_t *sptr, uint16_t len, uint16_t *ptokenlen, int handle_frag)
{
	if (len < SYB_TDS_DONELEN) {
		if (handle_frag) sybstat_.skip_token_resp = SYB_TDS_DONELEN - len;
		else sybstat_.skip_pcap_resp_till_eom = 1;

		return SYB_RET_CHECK_PKT_END;
	}

	*ptokenlen = SYB_TDS_DONELEN;

	return 0;
}


int SYBASE_ASE_SESSINFO::handle_doneproc_token_resp(uint8_t *sptr, uint16_t len, uint16_t *ptokenlen, int handle_frag)
{
	uint8_t	*ptmp = sptr;
	uint16_t fdstatus;

	if (len < SYB_TDS_DONELEN) {
		if (handle_frag) sybstat_.skip_token_resp = SYB_TDS_DONELEN - len;
		else sybstat_.skip_pcap_resp_till_eom = 1;

		return SYB_RET_CHECK_PKT_END;
	}

	fdstatus = unaligned_read_16(ptmp + 1, sybstat_.orig_client_bo);
	if (fdstatus & SYB_DONE_ATTN) {
		/*
		 * Now reset all pending responses 
		 */ 
		attention_reset_resp_type_expected();
	}

	*ptokenlen = SYB_TDS_DONELEN;

	return 0;
}


int SYBASE_ASE_SESSINFO::handle_loginack_token_resp(uint8_t *sptr, uint16_t len, uint16_t *ptokenlen, int handle_frag)
{
	static uint32_t		pcap_server_version = 0, p_minor_version = 0;
	uint8_t			*ptmp = sptr, *ppkt_end = sptr + len, lstatus;
	uint16_t 		pktlen = len;
	uint16_t 		tokenlen = 0;

	if ((sybstat_.pcap_sess_state != SYB_STATE_TDS_LOGIN_SPLIT_RESP) && 
			(sybstat_.pcap_sess_state != SYB_STATE_TDS_LOGIN_RESP) && sybstat_.is_login_complete) {
		sybstat_.skip_pcap_resp_till_eom = 1;

		return SYB_RET_CHECK_PKT_END;
	}

	if (pktlen <= 3) {
		if (handle_frag) {
			if (sybstat_.fragresp_len > 0) {
				if (pktlen + sybstat_.fragresp_len > SYB_FRAGBUFLEN) return -1;
			}
			memcpy(pResFragBuf + sybstat_.fragresp_len, ptmp, pktlen);
			sybstat_.fragresp_len += pktlen;

			*ptokenlen = len;	 /* Signal End of Packet */
		}
		else
		{
			sybstat_.skip_pcap_resp_till_eom = 1;
			return SYB_RET_CHECK_PKT_END;
		}
		return 0;
	}

	tokenlen = unaligned_read_16(ptmp + 1, sybstat_.orig_client_bo);

	if (gy_unlikely(tokenlen + 3 > pktlen)) {
		if (handle_frag == 0) {
			sybstat_.skip_pcap_resp_till_eom = 1;
			return SYB_RET_CHECK_PKT_END;
		}
	}
	else
	{
		pktlen = tokenlen;
		ppkt_end = ptmp + tokenlen + 3;
	}

	*ptokenlen = pktlen + 3; /* Login ack Token len is handled differently */	

	lstatus = *(ptmp + 3);
	if ((lstatus == 5) || ((lstatus != 6) && (sybstat_.cli_tds_version < 5))) {
		sybstat_.is_login_complete = 1;
		sybstat_.pcap_sess_state = SYB_STATE_LOGIN_COMPLETE;
	}
	else if (lstatus == 7) {
		/*
		 * We need to skip the next tds_msg
		 */
		sybstat_.skip_till_login_rsp = 1;
	}

	ptmp += 4;
	pktlen -= 4;

	if (ptmp + 4 > ppkt_end) return -1;

	if ((gy_unlikely(pcap_server_version == 0)) && sybstat_.cli_tds_version >= 5) {
		/*
		 * Now get the server version
		 */  
		ptmp = sptr + 3 + tokenlen - 4;
		pcap_server_version = *(ptmp + 0);	
		p_minor_version = *(ptmp + 1);	

		sybstat_.pcap_server_version = pcap_server_version;		

		INFOPRINT("ASE Database Server version is %u.%u\n", pcap_server_version, p_minor_version);
	}

	return 0;
}


int SYBASE_ASE_SESSINFO::handle_capability_token_resp(uint8_t *sptr, uint16_t len, uint16_t *ptokenlen, int handle_frag)
{
	uint8_t	*ptmp = sptr;
	uint16_t pktlen = len;
	uint16_t tokenlen = 0;

	if (pktlen <= 3) {
		if (handle_frag) {
			if (sybstat_.fragresp_len > 0) {
				if (pktlen + sybstat_.fragresp_len > SYB_FRAGBUFLEN) return -1;
			}
			memcpy(pResFragBuf + sybstat_.fragresp_len, ptmp, pktlen);
			sybstat_.fragresp_len += pktlen;

			*ptokenlen = len;	 /* Signal End of Packet */
		}
		else {
			sybstat_.skip_pcap_resp_till_eom = 1;
			return SYB_RET_CHECK_PKT_END;
		}
		return 0;
	}

	tokenlen = unaligned_read_16(ptmp + 1, sybstat_.orig_client_bo);

	if (gy_unlikely(tokenlen + 3 > pktlen)) {
		if (handle_frag == 0) {
			sybstat_.skip_pcap_resp_till_eom = 1;
			return SYB_RET_CHECK_PKT_END;
		}
	}
	else pktlen = tokenlen;

	*ptokenlen = pktlen + 3;

	return 0;
}


int SYBASE_ASE_SESSINFO::handle_info_token_resp(uint8_t *sptr, uint16_t len, uint16_t *ptokenlen, int handle_frag)
{
	uint8_t	*ptmp = sptr;
	uint16_t pktlen = len;
	uint16_t tokenlen = 0;

	if (pktlen <= 3) {
		if (handle_frag) {
			if (sybstat_.fragresp_len > 0) {
				if (pktlen + sybstat_.fragresp_len > SYB_FRAGBUFLEN) return -1;
			}
			memcpy(pResFragBuf + sybstat_.fragresp_len, ptmp, pktlen);
			sybstat_.fragresp_len += pktlen;

			*ptokenlen = len;	 /* Signal End of Packet */
		}
		else {
			sybstat_.skip_pcap_resp_till_eom = 1;
			return SYB_RET_CHECK_PKT_END;
		}
		return 0;
	}

	tokenlen = unaligned_read_16(ptmp + 1, sybstat_.orig_client_bo);

	if (gy_unlikely(tokenlen + 3 > pktlen)) {
		if (handle_frag == 0) {
			sybstat_.skip_pcap_resp_till_eom = 1;
			return SYB_RET_CHECK_PKT_END;
		}
	}
	else pktlen = tokenlen;

	*ptokenlen = pktlen + 3;

	return 0;
}


int SYBASE_ASE_SESSINFO::handle_error_token_resp(uint8_t *sptr, uint16_t len, uint16_t *ptokenlen, int handle_frag)
{
	int 			is_login = 0;
	uint8_t			*ptmp = sptr, *ppkt_end = sptr + len;
	uint16_t 		pktlen = len, token16len;
	uint8_t			c, errclass;
	uint16_t 		tokenlen = 0;
	uint32_t 		msgnum;

	if (pktlen <= 3) {
		if (handle_frag) {
			if (sybstat_.fragresp_len > 0) {
				if (pktlen + sybstat_.fragresp_len > SYB_FRAGBUFLEN) return -1;
			}
			memcpy(pResFragBuf + sybstat_.fragresp_len, ptmp, pktlen);
			sybstat_.fragresp_len += pktlen;

			*ptokenlen = len;	 /* Signal End of Packet */
		}
		else {
			sybstat_.skip_pcap_resp_till_eom = 1;
			return SYB_RET_CHECK_PKT_END;
		}
		return 0;
	}

	if ((sybstat_.pcap_sess_state == SYB_STATE_TDS_LOGIN_SPLIT_RESP) || 
			(sybstat_.pcap_sess_state == SYB_STATE_TDS_LOGIN_RESP)) {
		is_login = 1;
	}

	tokenlen = unaligned_read_16(ptmp + 1, sybstat_.orig_client_bo);

	if (gy_unlikely(tokenlen + 3 > pktlen)) {
		if (handle_frag == 0) {
			sybstat_.skip_pcap_resp_till_eom = 1;
			return SYB_RET_CHECK_PKT_END;
		}
	}
	else {
		pktlen = tokenlen;
		ppkt_end = ptmp + tokenlen + 3;
	}

	*ptokenlen = pktlen + 3;

	if (ptmp + 8 >= ppkt_end - 3) return 0;

	msgnum = unaligned_read_32(ptmp + 3, sybstat_.orig_client_bo);

	ptmp += 8;
	pktlen -= 8;
	errclass = *ptmp++;	/* Severity Class */

	token16len = unaligned_read_16(ptmp, sybstat_.orig_client_bo);
	if (ptmp + token16len + 2 >= ppkt_end) return 0;

	if (errclass > 10) {
		c = *(ptmp + 2 + token16len);
		*(ptmp + 2 + token16len) = '\0';

		handle_error((const char *)ptmp + 2, strlen((const char *)ptmp + 2), msgnum, errclass);

		*(ptmp + 2 + token16len) = c;
	}

	return 0;
}

int SYBASE_ASE_SESSINFO::test_extended_error_token_resp(uint8_t *sptr, uint16_t len)
{
	uint8_t			*ptmp = sptr, *ppkt_end = sptr + len, token8len, errstate, errclass;
	uint16_t		pktlen = len, errlen;
	uint8_t			c;
	uint16_t		tokenlen = 0, token16len;
	uint32_t		msgnum, i;
	int			is_split = 0;

	tokenlen = unaligned_read_16(ptmp + 1, sybstat_.orig_client_bo);

	if (tokenlen + 3 > pktlen) {
		return 0;
	}
	else {
		pktlen = tokenlen;
		ppkt_end = ptmp + tokenlen + 3;
	}

	if (ptmp + 8 >= ppkt_end - 3) {
		return 0;
	}

	msgnum = unaligned_read_32(ptmp + 3, sybstat_.orig_client_bo);

	if (msgnum == 0) {
		return 0;
	}

	errstate = *(ptmp + 7);
	errclass = *(ptmp + 8);

	ptmp += 8;
	pktlen -= 8;

	c = *ptmp;	/* Severity Class */

	if ((c <= 10) || (c > 26) || ((msgnum > 20000) && (c != 16))) {
		return 0;
	}

	tokenlen = *(ptmp + 1);
	ptmp += tokenlen + 2 + 3;

	if (gy_unlikely(ptmp + 4 >= ppkt_end)) {
		return 0;
	}

	token16len = unaligned_read_16(ptmp, sybstat_.orig_client_bo);
	if (ptmp + token16len + 2 >= ppkt_end) {
		return 0;
	}

	if ((c > 10) && (token16len > 16 + 2)) {
		for (i = 0; i < 16; i++) {
			if (!(isprint(*(ptmp + 2 + i)))) {
				break;
			}
		}

		if (i == 16) {

			c = *(ptmp + 2 + token16len);
			*(ptmp + 2 + token16len) = '\0';

			errlen = strlen((const char *)ptmp + 2);
			if (errlen > token16len/2) {

				if (msgnum > 20000) {
					for (i = 16; i < errlen; i++) {
						if (!(isprint(*(ptmp + 2 + i)))) {
							goto done;
						}
					}
				}

				handle_error((const char *)ptmp + 2, errlen, msgnum, errclass);

				*(ptmp + 2 + token16len) = c;

				return 1;
			}	

			*(ptmp + 2 + token16len) = c;
		}
	}

done :
	return 0;
}

int SYBASE_ASE_SESSINFO::handle_extended_error_token_resp(uint8_t *sptr, uint16_t len, uint16_t *ptokenlen, int handle_frag)
{
	int 			is_login = 0;
	uint8_t			*ptmp = sptr, *ppkt_end = sptr + len, token8len;
	uint16_t 		pktlen = len;
	uint8_t			c, errclass;
	uint16_t 		tokenlen = 0, token16len;
	uint32_t 		msgnum;

	if (pktlen <= 3)
	{
		if (handle_frag)
		{
			if (sybstat_.fragresp_len > 0)
			{
				if (pktlen + sybstat_.fragresp_len > SYB_FRAGBUFLEN)
					return -1;
			}
			memcpy(pResFragBuf + sybstat_.fragresp_len, ptmp, pktlen);
			sybstat_.fragresp_len += pktlen;

			*ptokenlen = len;	 /* Signal End of Packet */
		}
		else
		{
			sybstat_.skip_pcap_resp_till_eom = 1;
			return SYB_RET_CHECK_PKT_END;
		}
		return 0;
	}

	if ((sybstat_.pcap_sess_state == SYB_STATE_TDS_LOGIN_SPLIT_RESP) || 
			(sybstat_.pcap_sess_state == SYB_STATE_TDS_LOGIN_RESP))
		is_login = 1;

	tokenlen = unaligned_read_16(ptmp + 1, sybstat_.orig_client_bo);

	if (gy_unlikely(tokenlen + 3 > pktlen))
	{
		if (handle_frag == 0)
		{
			sybstat_.skip_pcap_resp_till_eom = 1;
			return SYB_RET_CHECK_PKT_END;
		}
	}
	else
	{
		pktlen = tokenlen;
		ppkt_end = ptmp + tokenlen + 3;
	}

	*ptokenlen = pktlen + 3;

	if (ptmp + 8 >= ppkt_end - 3)
		return 0;

	msgnum = unaligned_read_32(ptmp + 3, sybstat_.orig_client_bo);

	ptmp += 8;
	pktlen -= 8;

	errclass = *ptmp;	/* Severity Class */

	tokenlen = *(ptmp + 1);
	ptmp += tokenlen + 2 + 3;

	if (gy_unlikely(ptmp + 4 >= ppkt_end))
		return 0;

	token16len = unaligned_read_16(ptmp, sybstat_.orig_client_bo);
	if (ptmp + token16len + 2 >= ppkt_end)
		return 0;

	if (errclass > 10)
	{
		c = *(ptmp + 2 + token16len);
		*(ptmp + 2 + token16len) = '\0';

		handle_error((const char *)ptmp + 2, strlen((const char *)ptmp + 2), msgnum, errclass);

		*(ptmp + 2 + token16len) = c;
	}

	return 0;
}


int SYBASE_ASE_SESSINFO::handle_envchange_token_resp(uint8_t *sptr, uint16_t len, uint16_t *ptokenlen, int handle_frag)
{
	int 			is_login = 0;
	uint8_t			*ptmp = sptr, *ppkt_end = sptr + len;
	uint16_t 		pktlen = len;
	uint8_t			c, valuelen, tbuf[32];
	uint16_t 		tokenlen = 0, pktsize;

	if ((sybstat_.pcap_sess_state == SYB_STATE_TDS_LOGIN_SPLIT_RESP) || 
			(sybstat_.pcap_sess_state == SYB_STATE_TDS_LOGIN_RESP)) {
		is_login = 1;
	}	

	if (pktlen <= 3) {
		if (handle_frag) {
			if (sybstat_.fragresp_len > 0)
			{
				if (pktlen + sybstat_.fragresp_len > SYB_FRAGBUFLEN)
					return -1;
			}

			memcpy(pResFragBuf + sybstat_.fragresp_len, ptmp, pktlen);
			sybstat_.fragresp_len += pktlen;

			*ptokenlen = len;	 /* Signal End of Packet */
		}
		else {
			sybstat_.skip_pcap_resp_till_eom = 1;
			return SYB_RET_CHECK_PKT_END;
		}
		return 0;
	}

	tokenlen = unaligned_read_16(ptmp + 1, sybstat_.orig_client_bo);

	if (gy_unlikely(tokenlen + 3 > pktlen)) {
		if (handle_frag == 0) {
			sybstat_.skip_pcap_resp_till_eom = 1;
			return SYB_RET_CHECK_PKT_END;
		}
	}
	else {
		pktlen = tokenlen;
		ppkt_end = ptmp + tokenlen + 3;
	}

	*ptokenlen = pktlen + 3;

	ptmp += 3;
	pktlen -= 3;

	while ((ptmp < ppkt_end) && (ptmp > sptr)) {
		c = *ptmp;

		switch (c) {
			case SYB_ENVCHANGE_DB:
				valuelen = *(ptmp + 1);
				if ((valuelen < 128) && (valuelen <= pktlen)) {
					size_t			clen = unicode_to_ascii(tdstat_.dbbuf_.data(), ptmp + 2, valuelen, MAX_USER_DB_LEN, ppkt_end, 1 /* _tonullterm */);

					tdstat_.dbbuf_.set_len_external(clen);
				}	

				ptmp += 2 + valuelen;
				pktlen -= 2 + valuelen;

				if (ptmp >= ppkt_end - 1)
					break;

				/* oldvalue */
				valuelen = *ptmp;
				ptmp += 1 + valuelen;
				pktlen -= 1 + valuelen;
				break;

			case SYB_ENVCHANGE_LANG:
			case SYB_ENVCHANGE_CHARSET:
				valuelen = *(ptmp + 1);

				ptmp += 2 + valuelen;
				pktlen -= 2 + valuelen;

				if (ptmp >= ppkt_end - 1)
					break;

				/* oldvalue */
				valuelen = *ptmp;
				ptmp += 1 + valuelen;
				pktlen -= 1 + valuelen;
				break;

			case SYB_ENVCHANGE_PKTSIZE:
				valuelen = *(ptmp + 1);
				if ((valuelen < sizeof(tbuf)) && (valuelen <= pktlen)) {
					unicode_to_ascii(tbuf, ptmp + 2, valuelen, sizeof(tbuf), ppkt_end, 1 /* _tonullterm */);
					pktsize = atoi((char *)tbuf);
				}

				ptmp += 2 + valuelen;
				pktlen -= 2 + valuelen;

				if (ptmp >= ppkt_end - 1)
					break;

				/* oldvalue */
				valuelen = *ptmp;
				ptmp += 1 + valuelen;
				pktlen -= 1 + valuelen;
				break;

			default:
				return 0;
		}
	}

	return 0;
}


int SYBASE_ASE_SESSINFO::handle_curinfo_resp_tokens(uint8_t *sptr, uint16_t len, uint16_t *ptokenlen, int handle_frag)
{
	uint8_t			*ptmp = sptr, *ppkt_end = sptr + len;
	uint16_t 		pktlen = len;
	uint8_t			token = *ptmp, cmd;
	uint16_t 		tokenlen = 0;
	uint32_t 		cursorid, status;

	if (pktlen <= 3) {
		sybstat_.skip_pcap_resp_till_eom = 1;
		return SYB_RET_CHECK_PKT_END;
	}

	tokenlen = unaligned_read_16(ptmp + 1, sybstat_.orig_client_bo);

	if (gy_unlikely(tokenlen + 3 > pktlen)) {
		if (handle_frag == 0) {
			sybstat_.skip_pcap_resp_till_eom = 1;
			return SYB_RET_CHECK_PKT_END;
		}
		else {
			sybstat_.skip_token_resp = tokenlen + 3 - (ppkt_end - ptmp);
			return SYB_RET_CHECK_PKT_END;
		}
	}
	else {
		pktlen = tokenlen;
		ppkt_end = ptmp + tokenlen + 3;
	}

	*ptokenlen = pktlen + 3;

	if ((sybstat_.curr_pcap_cursors_pending == 0) && (sybstat_.ncurrcursor == 0))
		return 0;

	ptmp += 3;

	if (ptmp + 6 >= ppkt_end)
		return 0;

	cursorid = unaligned_read_32(ptmp, sybstat_.orig_client_bo);
	if (cursorid == 0)
		return 0;

	cmd = *(ptmp + 4);
	if (token == SYB_TOKEN_CURINFO) {
		status = unaligned_read_16(ptmp + 5, sybstat_.orig_client_bo);
	}
	else if (ptmp + 8 < ppkt_end) {
		status = unaligned_read_32(ptmp + 5, sybstat_.orig_client_bo);
	}
	else
		return 0;

	if (sybstat_.curr_pcap_cursors_pending == 1) {
		if (status & (SYB_CUR_DECLARED | SYB_CUR_OPEN)) {
			add_cursor(cursorid, status);
			sybstat_.curr_pcap_cursors_pending = 0;
		}
	}
	else if (status & SYB_CUR_DEALLOC)
		close_cursor(cursorid);

	return 0;
}



int SYBASE_ASE_SESSINFO::handle_language_req_token(uint8_t *sptr, uint16_t len, uint32_t *ptokenlen, int handle_frag)
{
	uint8_t			*ptmp = sptr, *ppkt_end = sptr + len;
	uint16_t 		pktlen = len;
	uint32_t 		tokenlen;
	int 			ret;

	if (pktlen < 6) {
		sybstat_.skip_pcap_req_till_eom = 1;
		return SYB_RET_CHECK_PKT_END; 
	}

	tokenlen = unaligned_read_32(ptmp + 1, sybstat_.orig_client_bo) + 5;
	*ptokenlen = tokenlen;

	tran_.tran_type_ |= TYPE_SYB_LANG_REQ;

	if (gy_unlikely(tokenlen > pktlen)) {
		if (handle_frag == 0) {
			sybstat_.skip_pcap_req_till_eom = 1;
			return SYB_RET_CHECK_PKT_END;
		}
		else {
			request_text_set((char *)ptmp + 6, pktlen - 6, 1);

			sybstat_.skip_token_req = tokenlen - (ppkt_end - ptmp);
			sybstat_.skip_request_text = tokenlen - (ppkt_end - ptmp);
			return SYB_RET_CHECK_PKT_END;
		}
	}
	else {
		pktlen = tokenlen;
		request_text_set((char *)ptmp + 6, pktlen - 6, 1);
	}

	return 0;
}


int SYBASE_ASE_SESSINFO::handle_dbrpc_token(uint8_t *sptr, uint16_t len, uint8_t token, uint32_t *ptokenlen, int handle_frag)
{
	uint8_t			*ptmp = sptr, *ppkt_end = sptr + len;
	uint16_t 		pktlen = len, namelen;
	uint32_t 		tokenlen;
	int 			ret;

	if (pktlen < 5) {
		sybstat_.skip_pcap_req_till_eom = 1;
		return SYB_RET_CHECK_PKT_END; 
	}

	tokenlen = unaligned_read_16(ptmp + 1, sybstat_.orig_client_bo) + 3;
	*ptokenlen = tokenlen;

	if (token == SYB_TOKEN_DBRPC) {
		namelen = *(ptmp + 3);
		ptmp += 4;
	}
	else {
		namelen = unaligned_read_16(ptmp + 3, sybstat_.orig_client_bo);
		ptmp += 5;
	}

	if (token != SYB_TOKEN_RPC) {
		request_text_set("/* DBRPC */");

		tran_.tran_type_ |= TYPE_SYB_DBRPC_RPC;
	}	
	else {
		request_text_set("/* RPC */");

		tran_.tran_type_ |= TYPE_SYB_DBRPC_RPC;
	}	

	if (gy_unlikely(tokenlen > pktlen)) {
		if (handle_frag == 0) {
			sybstat_.skip_pcap_req_till_eom = 1;
			return SYB_RET_CHECK_PKT_END;
		}
		else {
			if (ptmp + namelen < ppkt_end) {
				request_text_set((char *)ptmp, namelen, 1);
				sybstat_.skip_request_text = 0;
			}
			else {
				request_text_set((char *)ptmp, ppkt_end - ptmp, 1);
				sybstat_.skip_request_text = namelen - (ppkt_end - ptmp);
			}
			sybstat_.skip_token_req = tokenlen - (ppkt_end - sptr);
			return SYB_RET_CHECK_PKT_END;
		}
	}
	else {
		pktlen = tokenlen;
		request_text_set((char *)ptmp, namelen, 1);
	}

	return 0;
}


int SYBASE_ASE_SESSINFO::store_dyn_txt(uint8_t *pid, uint8_t idlen, uint8_t *pstmt, uint32_t slen)
{
	if ((idlen == 0) || (slen == 0)) return 0;

	uint8_t	is_trunc = 0;

	if (gy_unlikely(pDynStmt == nullptr)) {
		if ((pDynStmt = new (std::nothrow) DataList) == nullptr) return -1;

		if (pDynStmt->Init(SYBTDS_SQLLISTSIZE, sizeof(SYB_DYN_SQL_STATS_S)) == -1) return -1;
	}

	if (gy_unlikely(pDynStmtMap == nullptr)) {
		if ((pDynStmtMap = new (std::nothrow) Hashtbl) == nullptr) return -1;

		if (pDynStmtMap->set(SYBTDS_DYNIDLEN, SYBTDS_HASHTBLSIZE) == 0) return -1;
	}

	if (slen >= SYBTDS_SQLSTMTLEN) {
		slen = SYBTDS_SQLSTMTLEN - 3;
		is_trunc = 1;
	}

	SYB_DYN_SQL_STATS_S		dynstat1;

	memcpy(dynstat1.dyn_sql, (char *)pstmt, slen);	
	if (is_trunc) {
		memcpy(dynstat1.dyn_sql + slen, "..", 3);
		slen += 2;
	}
	else {
		dynstat1.dyn_sql[slen] = '\0';
	}

	dynstat1.len = slen;
	dynstat1.dyn_prep_reqnum = tdstat_.reqnum_;
	dynstat1.dyn_prep_time_t = tran_.treq_usec_/GY_USEC_PER_SEC;

	gstats[STATSYB_DYN_ADDED]++;

	int index = pDynStmt->AddElement((void *)&dynstat1, sizeof(dynstat1));
	if (index >= 0) {
		char id[SYBTDS_DYNIDLEN] = {0};
		memcpy(id, pid, (idlen >= SYBTDS_DYNIDLEN)? (SYBTDS_DYNIDLEN - 1) : idlen);
		pDynStmtMap->add((char *)id, index);
	}
	else return -1;

	return 0;
}


void SYBASE_ASE_SESSINFO::get_dyn_text(uint8_t *pid, uint8_t idlen, uint8_t dealloc, char *pdyntext, uint32_t max_dyn_len)
{
	if ((pDynStmt == nullptr) || (pDynStmtMap == nullptr) || (idlen == 0))
		return;

	char id[SYBTDS_DYNIDLEN] = {0};
	memcpy(id, pid, (idlen >= SYBTDS_DYNIDLEN)? (SYBTDS_DYNIDLEN - 1) : idlen);
	int index = -1;
	if (pDynStmtMap->search((char *)id, &index)) {

		gstats[STATSYB_DYN_FIND_SUCCESS]++;

		SYB_DYN_SQL_STATS_S		*pdynstat1 = static_cast<SYB_DYN_SQL_STATS_S *>(pDynStmt->GetElementPtr(index));

		if (pdyntext) {
			int tlen = pdynstat1->len < (max_dyn_len - 1) ? pdynstat1->len : max_dyn_len - 1;
			memcpy(pdyntext, pdynstat1->dyn_sql, tlen);
			pdyntext[tlen] = '\0';
			return;
		}

		request_text_set(pdynstat1->dyn_sql, pdynstat1->len <= SYBTDS_SQLSTMTLEN ? pdynstat1->len : SYBTDS_SQLSTMTLEN);

		if (pdynstat1->dyn_prep_reqnum <= tdstat_.reqnum_) {
			tdstat_.dyn_prep_reqnum_ = pdynstat1->dyn_prep_reqnum;
			tdstat_.dyn_prep_time_t_ = pdynstat1->dyn_prep_time_t;
		}
		else {
			tdstat_.dyn_prep_reqnum_ = 0;
			tdstat_.dyn_prep_time_t_ = 0;
		}

		if (dealloc)
		{
			pDynStmtMap->remove((char *)id);
			pDynStmt->DeleteElement(index, 1);
		}
	}
	else {
		gstats[STATSYB_DYN_FIND_FAIL]++;

		tdstat_.dyn_prep_reqnum_ = 0;
		tdstat_.dyn_prep_time_t_ = 0;

		if (pdyntext) {
			*pdyntext = '\0';
			return;
		}
	}
}	


int SYBASE_ASE_SESSINFO::handle_dyn_token(uint8_t *sptr, uint16_t len, uint8_t token, uint32_t *ptokenlen, int handle_frag)
{
	uint8_t			*ptmp = sptr, *ppkt_end = sptr + len, idlen, type, *pid, *pstmt, isdealloc = 0;
	uint16_t 		pktlen = len;
	uint32_t 		tokenlen, slen = 0;
	int 			ret, is_frag = 0;
	const uint8_t 		sbytes = ((token == SYB_TOKEN_DYNAMIC)? 2 : 4);

	if (pktlen < 4 + sbytes) {
		sybstat_.skip_pcap_req_till_eom = 1;
		return SYB_RET_CHECK_PKT_END; 
	}

	if (token == SYB_TOKEN_DYNAMIC) {
		tokenlen = unaligned_read_16(ptmp + 1, sybstat_.orig_client_bo) + 3;
		ptmp += 3;
	}
	else {
		tokenlen = unaligned_read_32(ptmp + 1, sybstat_.orig_client_bo) + 5;
		ptmp += 5;
	}

	*ptokenlen = tokenlen;

	type = *ptmp;
	switch (type) {
		case 0x01:
			request_text_set("/* DSQL Prepare */");
			tran_.tran_type_ |= TYPE_SYB_DSQL_PREPARE;
			break;

		case 0x02:
			request_text_set("/* DSQL Exec */");
			tran_.tran_type_ |= TYPE_SYB_DSQL_EXEC;
			break;

		case 0x04:
			request_text_set("/* DSQL Dealloc */");
			tran_.tran_type_ |= TYPE_SYB_DSQL_DEALLOC;
			isdealloc = 1;
			break;

		case 0x08:
			request_text_set("/* DSQL Exec Immed */");
			tran_.tran_type_ |= TYPE_SYB_DSQL_EXEC_IMMED;
			break;

		default:
			break;	

	}

	idlen = *(ptmp + 2);
	ptmp += 3;

	if (idlen > tokenlen) {
		sybstat_.skip_pcap_req_till_eom = 1;
		return SYB_RET_CHECK_PKT_END;
	}

	if (gy_unlikely(tokenlen > pktlen)) {
		is_frag = 1;
		if (handle_frag == 0) {
			sybstat_.skip_pcap_req_till_eom = 1;
			return SYB_RET_CHECK_PKT_END;
		}
		else {
			if (type > 0x08) {
				sybstat_.skip_pcap_req_till_eom = 1;
				return SYB_RET_CHECK_PKT_END;
			}

			if (ptmp + idlen + sbytes < ppkt_end)
				goto nxt_handle;
			else
				request_text_set((char *)ptmp, ppkt_end - ptmp, 1);

			sybstat_.skip_token_req = tokenlen - pktlen;
			return SYB_RET_CHECK_PKT_END;
		}
	}

	if (tokenlen <= pktlen) {
		pktlen = tokenlen;
		ppkt_end = sptr + tokenlen;
	}

nxt_handle:
	pid = ptmp;

	request_text_set((char *)ptmp, idlen, 0);
	request_text_set(" : ");	

	ptmp += idlen;

	if (token == SYB_TOKEN_DYNAMIC) {
		if (ptmp + 2 > ppkt_end)
			return 0;

		slen = unaligned_read_16(ptmp, sybstat_.orig_client_bo);
		ptmp += 2;
	}
	else {
		if (ptmp + 4 > ppkt_end)
			return 0;

		slen = unaligned_read_32(ptmp, sybstat_.orig_client_bo);
		ptmp += 4;
	}

	pstmt = ptmp;
	if (slen == 0) {
		/*
		 * Search for dyn stmt from cache
		 */
		get_dyn_text(pid, idlen, isdealloc);
	}
	else {
		if (ptmp + slen > ppkt_end) {
			request_text_set((char *)ptmp, ppkt_end - ptmp, 1);
			sybstat_.skip_request_text = slen - (ppkt_end - ptmp);
		}
		else {
			request_text_set((char *)ptmp, slen, 0);
		}	

		if (idlen > 0) {
			if (is_frag) {
				if (slen > SYBTDS_SQLSTMTLEN) slen = SYBTDS_SQLSTMTLEN;

				if (ptmp + slen < ppkt_end) store_dyn_txt(pid, idlen, pstmt, slen); 
			}
			else {
				store_dyn_txt(pid, idlen, pstmt, slen); 
			}	
		}
	}

	if (tokenlen > pktlen) {
		sybstat_.skip_token_req = tokenlen - pktlen;
		return SYB_RET_CHECK_PKT_END;
	}

	return 0;
}


int SYBASE_ASE_SESSINFO::handle_curdeclare_token(uint8_t *sptr, uint16_t len, uint8_t token, uint32_t *ptokenlen, int handle_frag)
{
	uint8_t			*ptmp = sptr, *ppkt_end = sptr + len, idlen, *pstmt, namelen, is_trunc = 0;
	uint16_t 		pktlen = len;
	uint32_t 		tokenlen, slen = 0, opt = 0;
	int 			ret, is_dyn_proc = 0;
	const uint8_t 		optlen = (token == SYB_TOKEN_CURDECLARE3) ? 4 : 1;	
	const uint8_t 		stbytes = (token == SYB_TOKEN_CURDECLARE) ? 2 : 4;	

	if ((token == SYB_TOKEN_CURDECLARE && pktlen < 4) || (token == SYB_TOKEN_DYNAMIC2 && pktlen < 6)) {
		sybstat_.skip_pcap_req_till_eom = 1;
		return SYB_RET_CHECK_PKT_END; 
	}

	if (token == SYB_TOKEN_CURDECLARE) {
		tokenlen = unaligned_read_16(ptmp + 1, sybstat_.orig_client_bo) + 3;
		ptmp += 3;
	}
	else {
		tokenlen = unaligned_read_32(ptmp + 1, sybstat_.orig_client_bo) + 5;
		ptmp += 5;
	}

	*ptokenlen = tokenlen;

	if (tokenlen <= pktlen) {
		pktlen = tokenlen;
		ppkt_end = sptr + tokenlen;
	}	

	sybstat_.cursor_query_active = token;
	sybstat_.curr_pcap_cursors_pending = 1;

	tran_.tran_type_ |= TYPE_SYB_CURSOR_DECLARE;

	request_text_set("/* Cursor Declare */");

	namelen = *ptmp;
	if (ptmp + namelen + optlen + 1 + stbytes + 1 >= ppkt_end) {
		sybstat_.skip_token_req = tokenlen - (ppkt_end - sptr);
		return SYB_RET_CHECK_PKT_END;
	}

	if (namelen > 0) {
		memset(curname, 0, SYBTDS_CURNAMELEN);
		memcpy(curname, (char *)(ptmp + 1), ((SYBTDS_CURNAMELEN <= namelen)? (SYBTDS_CURNAMELEN - 1) : namelen));
	}

	ptmp += namelen + 1;

	if (token == SYB_TOKEN_CURDECLARE3) {
		opt = unaligned_read_32(ptmp, sybstat_.orig_client_bo);
		ptmp += 5;

		if (opt & 0x04) request_text_set("/* Sensitive */");

		if (opt & 0x100) request_text_set("/* Scrollable */");
	}
	else {
		opt = *ptmp;
		ptmp += 2;
	}

	if (opt & 0x08) {	
		is_dyn_proc = 1;
	}

	if (token == SYB_TOKEN_CURDECLARE) {
		slen = unaligned_read_16(ptmp, sybstat_.orig_client_bo);
		ptmp += 2;
	}
	else {
		slen = unaligned_read_32(ptmp, sybstat_.orig_client_bo);
		ptmp += 4;
	}

	if ((ptmp + slen < ppkt_end) || (ppkt_end - ptmp >= slen)) {
		request_text_set((char *)ptmp, slen, 0);
		if (slen >= SYBTDS_SQLSTMTLEN)
		{
			slen = SYBTDS_SQLSTMTLEN - 3;
			is_trunc = 1;
		}
		memset(sybstat_.cursortext, 0, SYBTDS_SQLSTMTLEN);
		memcpy(sybstat_.cursortext, ptmp, slen);

		if (is_trunc) {
			memcpy(sybstat_.cursortext + slen, "..", 3);
		}
		else if ((is_dyn_proc == 1) && (slen + 24 < SYBTDS_SQLSTMTLEN)) {

			memcpy(sybstat_.cursortext + slen, " /* Dynamic Proc */", strlen(" /* Dynamic Proc */"));

			uint32_t newslen = slen + strlen(" /* Dynamic Proc */");

			if (newslen + 16 < SYBTDS_SQLSTMTLEN) {
				get_dyn_text((uint8_t *)sybstat_.cursortext, slen, 0, 
						sybstat_.cursortext + newslen, SYBTDS_SQLSTMTLEN - newslen - 1);
			}	
			request_text_set(sybstat_.cursortext + slen);
		}
	}
	else {
		request_text_set((char *)ptmp, ppkt_end - ptmp, 0);
		sybstat_.skip_request_text = slen - (ppkt_end - ptmp);

		if (ppkt_end - ptmp >= SYBTDS_SQLSTMTLEN) {
			slen = SYBTDS_SQLSTMTLEN - 4;
			memset(sybstat_.cursortext, 0, SYBTDS_SQLSTMTLEN);
			memcpy(sybstat_.cursortext, ptmp, slen);
			memcpy(sybstat_.cursortext + slen, "...", 4);
		}
	}

	if (tokenlen > pktlen) {
		sybstat_.skip_token_req = tokenlen - pktlen;
		return SYB_RET_CHECK_PKT_END;
	}

	return 0;
}


static void convert_four_byte_time(int timenum, int *ttimestamp, uint64_t *nanosecll) noexcept
{
	timenum &= 0x1ffffff;
	ttimestamp[3] = (timenum / 1080000);
	ttimestamp[4] = (timenum / 18000 % 60);
	ttimestamp[5] = (timenum / 300 % 60);
	*nanosecll = (timenum % 300LL * 10000000LL / 3LL);
}


static void convert_two_byte_time(int timenum, int *ttimestamp) noexcept
{
	ttimestamp[3] = (timenum / 60);
	ttimestamp[4] = (timenum % 60);
}


static int leapcnt(int year) noexcept
{
	int century = year / 100;
	int leaps = year / 4 - century + century / 4;

	return leaps;
}


static int leapyear(int year) noexcept
{
	year++;
	int retval = ((year % 4 == 0) && (year % 100 != 0)) || (year % 400 == 0);

	return retval;
}


static void num_to_ymd(int daynum, int *ttimestamp) noexcept 
{
	daynum += 693595;

	int year = daynum / 365;
	int dayinyear, month;

	while (1) {
		int leapyears = leapcnt(year);
		dayinyear = daynum - (year * 365 + leapyears);
		if (dayinyear >= 0) break;
		year--;
	}

	int *lp = (int *)MONTHDAYS;
	if (leapyear(year)) {
		lp = (int *)LMONTHDAYS;
	}

	int day = dayinyear;
	for (month = 0; day >= lp[month]; month++) {
		day -= lp[month];
	}
	ttimestamp[0] = year + 1;
	ttimestamp[1] = month + 1;
	ttimestamp[2] = day + 1;
}


static void calc_bigtime(uint64_t daynum, uint64_t daysincebasedate, int *ttimestamp, uint64_t *nanosecll) noexcept
{
	uint64_t usec_since_midnight = 86400000000LL * daysincebasedate;
	usec_since_midnight = daynum - usec_since_midnight;

	uint64_t hour = usec_since_midnight / 3600000000LL;
	ttimestamp[3] = (int)hour;

	uint64_t remaining_usec = usec_since_midnight % 3600000000LL;
	uint64_t min = remaining_usec / 60000000L;
	ttimestamp[4] = (int)min;

	remaining_usec %= 60000000L;
	uint64_t secs = remaining_usec / 1000000L;
	ttimestamp[5] = (int)secs;

	remaining_usec %= 1000000L;
	*nanosecll = (remaining_usec * 1000L);
}


static void calc_bigdatetime(uint64_t micros, int *ttimestamp, uint64_t *nanosecll) noexcept
{
	uint64_t daysincebasedate = micros / 86400000000LL;
	int datepart = (int)daysincebasedate;
	datepart -= 693595;
	datepart -= 366;

	num_to_ymd(datepart, ttimestamp);
	calc_bigtime(micros, daysincebasedate, ttimestamp, nanosecll);
}


void SYBASE_ASE_SESSINFO::parse_date_time(uint32_t dateint, uint32_t timeint, uint64_t usecll, int type)
{
	uint64_t 		numday_since_basedate, nanosecll = 0ull;
	int32_t 		ttimestamp[] = {0, 0, 0, 0, 0, 0};
	char 			parambuf[128];

	switch (type) {
		case 1: 
			num_to_ymd(dateint, ttimestamp);
			convert_four_byte_time(timeint, ttimestamp, &nanosecll);

			snprintf(parambuf, sizeof(parambuf), "\'%04d/%02d/%02d %02u:%02u:%02u.%lu nsec\'", 
					ttimestamp[0], ttimestamp[1], ttimestamp[2], ttimestamp[3], ttimestamp[4], ttimestamp[5], nanosecll);
			break;

		case 2:
			num_to_ymd(dateint, ttimestamp);
			convert_two_byte_time(timeint, ttimestamp);

			snprintf(parambuf, sizeof(parambuf), "\'%04d/%02d/%02d %02u:%02u:%02u\'", 
					ttimestamp[0], ttimestamp[1], ttimestamp[2], ttimestamp[3], ttimestamp[4], ttimestamp[5]);
			break;

		case 3:
			num_to_ymd(dateint, ttimestamp);

			snprintf(parambuf, sizeof(parambuf), "\'%04d/%02d/%02d\'", 
					ttimestamp[0], ttimestamp[1], ttimestamp[2]);
			break;

		case 4:
			convert_four_byte_time(timeint, ttimestamp, &nanosecll);

			snprintf(parambuf, sizeof(parambuf), "\'%02u:%02u:%02u.%lu\'", 
					ttimestamp[3], ttimestamp[4], ttimestamp[5], nanosecll);
			break;

		case 5:
			calc_bigdatetime(usecll, ttimestamp, &nanosecll);
			snprintf(parambuf, sizeof(parambuf), "\'%04d/%02d/%02d %02u:%02u:%02u.%lu nsec\'", 
					ttimestamp[0], ttimestamp[2], ttimestamp[1], ttimestamp[3], ttimestamp[4], ttimestamp[5], nanosecll);
			break;

		case 6:
			numday_since_basedate = usecll / 86400000000LL;
			calc_bigtime(usecll, numday_since_basedate, ttimestamp, &nanosecll);

			snprintf(parambuf, sizeof(parambuf), "\'%02u:%02u:%02u.%lu nsec\'", 
					ttimestamp[3], ttimestamp[4], ttimestamp[5], nanosecll);
			break;

		default:
			return;
	}

	request_text_set(parambuf);
}


void SYBASE_ASE_SESSINFO::parse_intn(uint8_t *ptmp, uint8_t len, int is_signed)
{
	uint64_t 		llint;
	uint32_t 		ui32;
	char 			parambuf[128];

	if (len == 8) {
		llint = unaligned_read_64(ptmp, sybstat_.orig_client_bo);
		if (is_signed)
			snprintf(parambuf, sizeof(parambuf), "%ld", (int64_t)llint);
		else
			snprintf(parambuf, sizeof(parambuf), "%lu", llint);
	}
	else if (len == 4) {
		ui32 = unaligned_read_32(ptmp, sybstat_.orig_client_bo);
		if (is_signed)
			snprintf(parambuf, sizeof(parambuf), "%d", (int32_t)ui32);
		else
			snprintf(parambuf, sizeof(parambuf), "%u", ui32);
	}
	else if (len == 2) {
		ui32 = unaligned_read_16(ptmp, sybstat_.orig_client_bo);
		if (is_signed)
			snprintf(parambuf, sizeof(parambuf), "%hd", (int16_t)ui32);
		else
			snprintf(parambuf, sizeof(parambuf), "%hu", (uint16_t)ui32);
	}
	else if (len == 1) {
		ui32 = *ptmp;
		if (is_signed)
			snprintf(parambuf, sizeof(parambuf), "%hhd", (int8_t)ui32);
		else
			snprintf(parambuf, sizeof(parambuf), "%hhu", (uint8_t)ui32);
	}
	else
		sprintf(parambuf, "NULL");

	request_text_set(parambuf);
}


void SYBASE_ASE_SESSINFO::parse_moneyn(uint8_t *ptmp, uint8_t len)
{
	int64_t			lmoney;
	alignas(8) char 	parambuf[128], tempdata[8];
	double 			dbl;

	if (len == 4) {
		lmoney = unaligned_read_32(ptmp, sybstat_.orig_client_bo);
		snprintf(parambuf, sizeof(parambuf), "%.2f", (double)lmoney/10000.0);
	}
	else if (len == 8) {
		tempdata[0] = *(ptmp+4);
		tempdata[1] = *(ptmp+5);
		tempdata[2] = *(ptmp+6);
		tempdata[3] = *(ptmp+7);
		tempdata[4] = *(ptmp);
		tempdata[5] = *(ptmp+1);
		tempdata[6] = *(ptmp+2);
		tempdata[7] = *(ptmp+3);				

		lmoney = *(int64_t *)tempdata;
		dbl = ((double)(lmoney))/10000;

		snprintf(parambuf, sizeof(parambuf), "%.2lf", dbl);
	}
	else
		sprintf(parambuf, "NULL");

	request_text_set(parambuf);
}


int SYBASE_ASE_SESSINFO::parse_fltn(uint8_t *ptmp, uint8_t len)
{
	int64_t			itemp1 = 0ull, ma = 0ull, sa = 0ull, ea = 0ull;
	char 			parambuf[128];
	double 			ta = 0.0, fa = 0.0;

	if (len == 4) {
		itemp1 = unaligned_read_32(ptmp, sybstat_.orig_client_bo);
		sa = ((itemp1 >> 31) == 0) ? 1 : -1;
		ea = (int)((itemp1 >> 23) & 0xff);
		ma = (ea == 0) ? ((itemp1 & 0x7fffff) << 1) : ((itemp1 & 0x7fffff) | 0x800000);
		ta = pow((double)2, (double)(ea-150));
		fa = sa*ma*ta;
		snprintf(parambuf, sizeof(parambuf), "%g", fa);

		request_text_set(parambuf);
	}
	else if (len == 8) {
		itemp1 = unaligned_read_64(ptmp, sybstat_.orig_client_bo);

		sa = ((itemp1 >> 63) == 0) ? 1 : -1;
		ea = (int)((itemp1 >> 52) & 0x7ff);
		ma = (ea == 0ULL) ? ((itemp1 & 0xfffffffffffffLL) << 1) : 
			((itemp1 & 0xfffffffffffffLL) | 0x10000000000000LL);
		ta = pow((double)2, (double)(ea-1075));
		fa = sa*ma*ta;
		snprintf(parambuf, sizeof(parambuf), "%e", fa);

		request_text_set(parambuf);
	}
	else
		request_text_set("NULL");

	return 0;
}


int SYBASE_ASE_SESSINFO::handle_param_token(uint8_t *sptr, uint16_t len, uint8_t token, uint32_t *ptokenlen, DirPacket dir, SYB_DATA_COL_PTR_T *psybdataptr, int handle_frag)
{
	uint8_t			*ptmp = sptr, *ppkt_end = sptr + len, *pcoldatastart, *pdatastart, tlen, status, parsept, labelpt;
	uint8_t			*poldtmp = nullptr, *poldpkt_end = nullptr, *pdata;
	uint16_t 		ncols, tlen2 = 0, toldlen = 0, daysh, timesh;
	uint32_t 		i, ntxt = 0, nblobs = 0, tlen4 = 0, chk1 = 0, is_val_frag = 0, no_req_parse = 0, dayint, timeint;
	uint64_t 		tlen8, ullval;
	SYB_ROWFMT_T 		*pcurrrowfmt = nullptr;
	SYB_COLFMT_T 		*pcol;
	const char 		*pstrtoken = "param";
	const char 		*pstrdir = "Request Packet";
	static void 		*plblarray[] = {&&lbl0, &&lbl1, &&lbl2, &&lbl3, &&lbl4};
	uint8_t			*pskip = &sybstat_.skip_pcap_req_till_eom;
	uint32_t 		*pskipbytes = &sybstat_.skip_token_req;

	if (gy_unlikely(psybdataptr != nullptr)) {
		if (gy_unlikely(len < psybdataptr->blob_bytes_to_skip)) {
			psybdataptr->blob_bytes_to_skip -= len;
			return SYB_RET_CHECK_PKT_END;
		}

		pdatastart = ptmp;
		pcoldatastart = ptmp;
		pcol = psybdataptr->pcol;
		pcurrrowfmt = psybdataptr->pcurrrowfmt;

		if (gy_unlikely(!pcurrrowfmt || !pcol)) {
			*pskip = 1;									
			return SYB_RET_CHECK_PKT_END;				
		}

		ncols = pcurrrowfmt->ncols;
		i = psybdataptr->currcol;
		labelpt	= psybdataptr->labelpt;
		parsept	= psybdataptr->parsept;
		is_val_frag = 1;	

		if (tdstrbuf_.is_overflow())
			no_req_parse = 1;

		if (psybdataptr->blob_bytes_to_skip > 0) {
			if (len == psybdataptr->blob_bytes_to_skip) {
				psybdataptr->blob_bytes_to_skip = 0;
				psybdataptr->parsept = 5;
				psybdataptr->lenbytes = 0;
				psybdataptr->lenbytes_pending = 4;	
				psybdataptr->labelpt = 4;	
				return SYB_RET_CHECK_PKT_END;
			}

			ptmp += psybdataptr->blob_bytes_to_skip;
			memset(psybdataptr, '\0', sizeof(*psybdataptr));
			sybstat_.is_data_col_ptr_valid = 0;

			goto lbls;
		}

		if (parsept == 0)
			goto lbl0;
		else if (parsept == 5) {
			if (psybdataptr->lenbytes_pending <= len) {
				if ((size_t)psybdataptr->lenbytes + psybdataptr->lenbytes_pending <= sizeof(psybdataptr->bytebuf)) {
					memcpy(psybdataptr->bytebuf + psybdataptr->lenbytes, ptmp, psybdataptr->lenbytes_pending);
				}
				pdata = psybdataptr->bytebuf;

				switch (psybdataptr->lenbytes + psybdataptr->lenbytes_pending) {
					case 1:
						tlen4 = *pdata;
						break;

					case 2:
						tlen4 = unaligned_read_16(pdata, sybstat_.orig_client_bo);
						break;

					case 4:
						tlen4 = unaligned_read_32(pdata, sybstat_.orig_client_bo);
						break;

					default:
						*pskip = 1;									
						return SYB_RET_CHECK_PKT_END;				
				}	

				ptmp += psybdataptr->lenbytes_pending;

				memset(psybdataptr, '\0', sizeof(*psybdataptr));
				sybstat_.is_data_col_ptr_valid = 0;

				goto *plblarray[labelpt];
			}
			else {
				if ((size_t)psybdataptr->lenbytes + len <= sizeof(psybdataptr->bytebuf)) {
					memcpy(psybdataptr->bytebuf + psybdataptr->lenbytes, ptmp, len);
				}
				psybdataptr->lenbytes += len;
				psybdataptr->lenbytes_pending -= len;

				return SYB_RET_CHECK_PKT_END;				
			}
		}
		else {
			if (sybstat_.pcap_buf_saved_len < SYB_MAX_BUF_SAVED_LEN) {
				chk1 = 1;

				if (pcol->datatype == SYB_DATA_TYPE_TEXT)
					tlen2 = 29 - sybstat_.pcap_buf_saved_len; /* Buffer upto 29 bytes */
				else if (pcol->blob_classid > 5)
					tlen2 = 41 - sybstat_.pcap_buf_saved_len;
				else {
					*pskip = 1;									
					return SYB_RET_CHECK_PKT_END;				
				}

				if (tlen2 > len) {
					*pskip = 1;									
					return SYB_RET_CHECK_PKT_END;				
				}

				if ((size_t)sybstat_.pcap_buf_saved_len + tlen2 <= sizeof(sybstat_.pcap_buf_saved)) {
					memcpy(sybstat_.pcap_buf_saved + sybstat_.pcap_buf_saved_len, ptmp, tlen2);
				}

				poldtmp = ptmp;
				poldpkt_end = ppkt_end;
				toldlen = tlen2;

				sybstat_.pcap_buf_saved_len += tlen2;

				ptmp = sybstat_.pcap_buf_saved;
				pdatastart = ptmp;	
				ppkt_end = sybstat_.pcap_buf_saved + sybstat_.pcap_buf_saved_len;

				goto lbl0;			
			}
			else {
				*pskip = 1;									
				return SYB_RET_CHECK_PKT_END;				
			}
		}
	}

	if ((sybstat_.cursor_query_active == 0) || (pCurrCursor == nullptr))
		pcurrrowfmt = pCurrParamFmt;
	else if (pCurrCursor)
		pcurrrowfmt = pCurrCursor->pcurrparamfmt;

	if (!pcurrrowfmt || !pcurrrowfmt->pcol) {
		sybstat_.skip_pcap_req_till_eom = 1;
		return SYB_RET_CHECK_PKT_END;
	}


#undef IR_HANDLE_DATA_FRAG
#define IR_HANDLE_DATA_FRAG(_len) 											\
	if (gy_unlikely(ptmp < pdatastart)) {										\
		*pskip = 1;												\
		return SYB_RET_CHECK_PKT_END;										\
	}														\
	if (gy_unlikely(ptmp + (_len) > ppkt_end))	{									\
															\
		if (gy_unlikely(chk1 == 1)) {										\
															\
			*pskip = 1;											\
			return SYB_RET_CHECK_PKT_END;									\
		}													\
		memset(&sybstat_.data_col_ptr, '\0', sizeof(sybstat_.data_col_ptr));					\
		if (parsept == 6) {											\
															\
			sybstat_.data_col_ptr.lenbytes_pending = 0;							\
			\
			if (sybdatalist[pcol->datatype].type_flags != SYB_DATA_TYPE_BLOB) {				\
															\
				*pskipbytes = tlen4 - (ppkt_end - ptmp);						\
				sybstat_.is_data_col_ptr_valid = 0;							\
															\
				if ((int)i == ncols - 1)								\
				return SYB_RET_CHECK_PKT_END;								\
															\
				request_text_set(", ");									\
				i++; pcol++; parsept = 0;								\
			}												\
			else sybstat_.data_col_ptr.blob_bytes_to_skip = tlen4 - (ppkt_end - ptmp);			\
		}													\
		else {													\
															\
			sybstat_.data_col_ptr.blob_bytes_to_skip = 0;							\
			\
			if (parsept == 5) {										\
															\
				sybstat_.data_col_ptr.lenbytes = ppkt_end - ptmp;					\
				if (ppkt_end - ptmp > 0 && size_t(ppkt_end - ptmp) <= 					\
					sizeof(sybstat_.data_col_ptr.bytebuf))						\
					memcpy(sybstat_.data_col_ptr.bytebuf, ptmp, ppkt_end - ptmp);			\
				\
				sybstat_.data_col_ptr.lenbytes_pending = tlen4 - (ppkt_end - ptmp);			\
			}												\
			else {												\
															\
				if (gy_unlikely(ptmp - pcoldatastart > SYB_MAX_BUF_SAVED_LEN)) {				\
															\
					*pskip = 1;									\
					return SYB_RET_CHECK_PKT_END;							\
				}											\
				\
				memcpy(sybstat_.pcap_buf_saved, pcoldatastart, ptmp - pcoldatastart);			\
				sybstat_.pcap_buf_saved_len = ptmp - pcoldatastart;					\
			}												\
		}													\
		sybstat_.data_col_ptr.pcurrrowfmt 	= pcurrrowfmt;							\
		sybstat_.data_col_ptr.pcol 	= pcol;									\
		sybstat_.data_col_ptr.ncols 	= ncols;								\
		sybstat_.data_col_ptr.currcol 	= i;									\
		sybstat_.data_col_ptr.parsept 	= parsept;								\
		sybstat_.data_col_ptr.labelpt 	= labelpt;								\
		sybstat_.data_col_ptr.ntimes++;									\
		sybstat_.is_data_col_ptr_valid	= token;								\
		\
		return SYB_RET_CHECK_PKT_END;										\
	}

	ptmp++;

	pdatastart = ptmp;

	request_text_set("  $*P*$ ");
	request_text_set(" -- ");

	ncols = pcurrrowfmt->ncols;
	pcol = pcurrrowfmt->pcol;

	for (i = 0; i < ncols; i++, pcol++) {
lbl0 :
		pcoldatastart = ptmp;
		parsept = 0;
		labelpt = 0;
		is_val_frag = 0;

		if (tdstrbuf_.is_overflow()) {
			*pskip = 1;
			return SYB_RET_CHECK_PKT_END;
		}

		if (pcol->status & 0x08) {
			IR_HANDLE_DATA_FRAG(1);
			status = *ptmp++;
			if (status & 0x1) {
				/*
				 * No data follows
				 */
				continue; 
			}
		}

		parsept = 1;

		switch (sybdatalist[pcol->datatype].type_flags) {
			case SYB_DATA_TYPE_NORMAL:
				parsept = 6;
				tlen4 = pcol->len;

				IR_HANDLE_DATA_FRAG(tlen4);

				if ((is_val_frag == 0) && (no_req_parse == 0)) {
					switch (pcol->datatype) {
						case SYB_TDS_BIT:
							if (*ptmp)
								request_text_set("True");
							else
								request_text_set("False");
							break;

						case SYB_TDS_DATE:
							dayint = unaligned_read_32(ptmp, sybstat_.orig_client_bo);
							parse_date_time(dayint, 0, 0ull, 3);
							break;

						case SYB_TDS_DATETIME:	
							dayint = unaligned_read_32(ptmp, sybstat_.orig_client_bo);
							timeint = unaligned_read_32(ptmp + 4, sybstat_.orig_client_bo);
							parse_date_time(dayint, timeint, 0ull, 1);
							break;

						case SYB_TDS_FLT4:
						case SYB_TDS_FLT8:
							parse_fltn(ptmp, tlen4);
							break;

						case SYB_TDS_SINT1:						
						case SYB_TDS_INT2:						
						case SYB_TDS_INT4:						
						case SYB_TDS_INT8:						
							parse_intn(ptmp, tlen4, 1 /* is_signed */);
							break;

						case SYB_TDS_INT1:
						case SYB_TDS_UINT2:						
						case SYB_TDS_UINT4:						
						case SYB_TDS_UINT8:						
							parse_intn(ptmp, tlen4, 0 /* is_signed */);
							break;

						case SYB_TDS_MONEY:
						case SYB_TDS_SHORTMONEY:
							parse_moneyn(ptmp, tlen4);					
							break;

						case SYB_TDS_SHORTDATE:
							daysh = unaligned_read_16(ptmp, sybstat_.orig_client_bo);
							timesh = unaligned_read_16(ptmp + 2, sybstat_.orig_client_bo);
							parse_date_time(daysh, timesh, 0ull, 2);
							break;

						case SYB_TDS_TIME:
							timeint = unaligned_read_32(ptmp, sybstat_.orig_client_bo);
							parse_date_time(0, timeint, 0ull, 4);
							break;

						default:
							break;
					}
				}

				ptmp += tlen4;		
				break;

			case SYB_DATA_TYPE_SIMPLE_LEN1:
			case SYB_DATA_TYPE_DECIMAL:
			case SYB_DATA_TYPE_BIGDATE:
				parsept = 5;
				labelpt = 1;

				tlen4 = 1;
				IR_HANDLE_DATA_FRAG(1);
				tlen4 = *ptmp++;

lbl1 :
				parsept = 6;

				IR_HANDLE_DATA_FRAG(tlen4);

				if ((is_val_frag == 0) && (no_req_parse == 0)) {
					switch (pcol->datatype) {
						case SYB_TDS_BINARY :
							if (tlen4)
								request_text_set("<Binary Data>");
							else
								request_text_set("NULL");
							break;

						case SYB_TDS_CHAR:
						case SYB_TDS_VARCHAR:
							if (tlen4)
							{
								request_text_set("\'");
								request_text_set((char *)ptmp, tlen4, 0);
								request_text_set("\'");
							}
							else
								request_text_set("NULL");
							break;

						case SYB_TDS_DATEN:
							if (tlen4 == 4)
							{
								dayint = unaligned_read_32(ptmp, sybstat_.orig_client_bo);
								parse_date_time(dayint, 0, 0ull, 3);
							}
							else
								request_text_set("NULL");
							break;

						case SYB_TDS_DATETIMEN:
							if (tlen4 == 8)
							{
								dayint = unaligned_read_32(ptmp, sybstat_.orig_client_bo);
								timeint = unaligned_read_32(ptmp + 4, sybstat_.orig_client_bo);
								parse_date_time(dayint, timeint, 0ull, 1);
							}
							else if (tlen4 == 4)
							{
								daysh = unaligned_read_16(ptmp, sybstat_.orig_client_bo);
								timesh = unaligned_read_16(ptmp + 2, sybstat_.orig_client_bo);
								parse_date_time(daysh, timesh, 0ull, 2);
							}
							else
								request_text_set("NULL");
							break;

						case SYB_TDS_FLTN:
							if ((tlen4 == 8) || (tlen4 == 4))
								parse_fltn(ptmp, tlen4);
							else
								request_text_set("NULL");
							break;

						case SYB_TDS_INTN:
							parse_intn(ptmp, tlen4, 1 /* is_signed */);
							break;

						case SYB_TDS_UINTN:
							parse_intn(ptmp, tlen4, 0 /* is_signed */);
							break;

						case SYB_TDS_MONEYN:
							parse_moneyn(ptmp, tlen4);					
							break;

						case SYB_TDS_TIMEN:
							if (tlen4 == 4)
							{
								timeint = unaligned_read_32(ptmp, sybstat_.orig_client_bo);
								parse_date_time(0, timeint, 0ull, 4);
							}
							else
								request_text_set("NULL");
							break;

						case SYB_TDS_VARBINARY:
							if (tlen4)
								request_text_set("<Binary Data>");
							else
								request_text_set("NULL");
							break;

						case SYB_TDS_DECN:
						case SYB_TDS_NUMN:
							if (tlen4 > 0)
							{
								/*
								 * XXX TODO
								 */
								request_text_set("<Decimal/Numeric Data>");
							}
							else
								request_text_set("NULL");
							break;

						case SYB_DATA_TYPE_BIGDATE:
							if (tlen4 == 8)
							{
								ullval = unaligned_read_64(ptmp, sybstat_.orig_client_bo);
								parse_date_time(0, 0, ullval, 5);
							}
							else
								request_text_set("NULL");
							break;

						case SYB_TDS_BIGTIMEN:
							if (tlen4 == 8)
							{
								ullval = unaligned_read_64(ptmp, sybstat_.orig_client_bo);
								parse_date_time(0, 0, ullval, 6);
							}
							else
								request_text_set("NULL");
							break;

						default:
							break;
					}
				}	

				ptmp += tlen4;
				break;

			case SYB_DATA_TYPE_SIMPLE_LEN4:
				parsept = 5;
				labelpt = 2;

				tlen4 = 4;
				IR_HANDLE_DATA_FRAG(4);
				tlen4 = unaligned_read_32(ptmp, sybstat_.orig_client_bo);

				ptmp += 4;

lbl2 :
				parsept = 6;

				IR_HANDLE_DATA_FRAG(tlen4);

				if ((is_val_frag == 0) && (no_req_parse == 0))
				{
					switch (pcol->datatype)
					{
						case SYB_TDS_LONGBINARY:
							if (tlen4)
								request_text_set("<Binary Data>");
							else
								request_text_set("NULL");
							break;

						case SYB_TDS_LONGCHAR:
							if (tlen4 > 0)
							{
								request_text_set("\'");
								request_text_set((char *)ptmp, tlen4, 0);
								request_text_set("\'");
							}
							else if (tlen4 == 0)
								request_text_set("NULL");
							break;
					}
				}	

				ptmp += tlen4;
				break;

			case SYB_DATA_TYPE_TEXT:
				ntxt++;

				IR_HANDLE_DATA_FRAG(1);
				tlen = *ptmp;

				parsept = 2;

				IR_HANDLE_DATA_FRAG(tlen + 1 + ((tlen > 0) ? 8 : 0));
				ptmp++;

				if (gy_unlikely(tlen == 0))
					break;

				ptmp += tlen + 8;

				parsept = 5;
				labelpt = 3;
				tlen4 = 4;

				IR_HANDLE_DATA_FRAG(4);
				tlen4 = unaligned_read_32(ptmp, sybstat_.orig_client_bo);

				ptmp += 4;

				if (gy_unlikely(chk1 == 1))
				{
					chk1 = 0;

					ptmp = poldtmp + toldlen;
					pdatastart = ptmp;
					ppkt_end = poldpkt_end;
				}

lbl3 :
				parsept = 6;

				IR_HANDLE_DATA_FRAG(tlen4);

				if ((is_val_frag == 0) && (no_req_parse == 0))
				{
					switch (pcol->datatype)
					{
						case SYB_TDS_IMAGE:
							if (tlen4) {
								request_text_set("<Image Data>");
							}	
							else
								request_text_set("NULL");
							break;

						case SYB_TDS_TEXT:
							if (tlen4) {
								request_text_set("<Text Data>");
							}	
							else
								request_text_set("NULL");
							break;

						case SYB_TDS_UNITEXT:
							if (tlen4) {
								request_text_set("<Unicode Text Data>");
							}	
							else
								request_text_set("NULL");
							break;

						case SYB_TDS_XML:
							if (tlen4) {
								request_text_set("<XML Data>");
							}	
							else
								request_text_set("NULL");
							break;
					}
				}	

				ptmp += tlen4;
				break;

			case SYB_DATA_TYPE_BLOB:
				if ((is_val_frag == 0) && (no_req_parse == 0)) {
					request_text_set("<Blob Data>");
					gstats[STATSYB_BLOB_DATA]++;
				}	

				IR_HANDLE_DATA_FRAG(3);
				status = *ptmp;	
				tlen4 = unaligned_read_16(ptmp + 1, sybstat_.orig_client_bo);

				parsept = 2;

				IR_HANDLE_DATA_FRAG(3 + tlen4);
				ptmp += 3 + tlen4;

				parsept = 3;

				if (pcol->blob_classid > 5) {
					gstats[STATSYB_LOB_LOCATOR_DATA]++;

					nblobs++;

					IR_HANDLE_DATA_FRAG(10);
					tlen8 = unaligned_read_64(ptmp, sybstat_.orig_client_bo);
					tlen2 = unaligned_read_16(ptmp + 8, sybstat_.orig_client_bo);

					ptmp += 10;

					parsept = 4;

					IR_HANDLE_DATA_FRAG(tlen2);

					ptmp += tlen2;
				}

				do {
lbls:
					parsept = 5;
					labelpt = 4;
					tlen4 = 4;

					IR_HANDLE_DATA_FRAG(4);
					tlen4 = unaligned_read_32(ptmp, sybstat_.orig_client_bo);

					ptmp += 4;

					if (gy_unlikely(chk1 == 1)) {
						chk1 = 0;

						ptmp = poldtmp + toldlen;
						pdatastart = ptmp;
						ppkt_end = poldpkt_end;
					}

lbl4:
					parsept = 6;

					if (tlen4 == 0)
						break;
					else if ((tlen4 & 0x80000000) == 0) {
						IR_HANDLE_DATA_FRAG(tlen4);
						ptmp += tlen4;

						if (ptmp + 4 < ppkt_end)
						{ 
							tlen4 = unaligned_read_32(ptmp, sybstat_.orig_client_bo);
							if (tlen4 != 0)
								break;
						}
					}
					else {
						tlen4 &= 0x7FFFFFFF;

						IR_HANDLE_DATA_FRAG(tlen4);
						ptmp += tlen4;
					}

				} while (1);
				break;

			default:
				*pskip = 1;									
				return SYB_RET_CHECK_PKT_END;				
		}

		if ((int)i != ncols - 1)
			request_text_set(", ");
	}

	if (sybstat_.is_data_col_ptr_valid) {
		sybstat_.is_data_col_ptr_valid = 0;
		sybstat_.pcap_buf_saved_len = 0;
		memset(&sybstat_.data_col_ptr, '\0', sizeof(sybstat_.data_col_ptr));
	}

	*ptokenlen = ptmp - sptr;

	return 0;
}


/*
 * Handles SYB_TOKEN_PARAMFMT, SYB_TOKEN_PARAMFMT2
 * It can be in either a request pkt or a resp pkt 
 * For e.g. for return params SYB_TOKEN_PARAMFMT could be used.
 */ 
int SYBASE_ASE_SESSINFO::handle_paramfmt_token(uint8_t *sptr, uint16_t len, uint8_t token, uint32_t *ptokenlen, DirPacket dir, int handle_frag)
{
	uint8_t			*ptmp = sptr, *ppkt_end = sptr + len, *pdatastart = sptr, tlen, datatype, is_blob = 0, ctype;
	uint16_t 		pktlen = len, tlen2;
	uint8_t			*pcolstart;
	uint16_t 		ncols, ntxt = 0, nblobs = 0;
	uint32_t 		tokenlen = 0, i, usertype;
	SYB_ROWFMT_T 		*pcurrrowfmt;
	SYB_COLFMT_T 		*pcol;
	const char 		*pstrtoken = "paramfmt";
	const char 		*pstrdir = "Request Packet";
	uint8_t			*pskip = &sybstat_.skip_pcap_req_till_eom;
	const uint8_t 		lenbytes = ((token == SYB_TOKEN_PARAMFMT2) ? 4 : 2);

	if (pktlen < lenbytes + 1) {
		*pskip = 1;
		return SYB_RET_CHECK_PKT_END;
	}

	if (token != SYB_TOKEN_PARAMFMT2)
		tokenlen = unaligned_read_16(ptmp + 1, sybstat_.orig_client_bo);
	else
		tokenlen = unaligned_read_32(ptmp + 1, sybstat_.orig_client_bo);

	*ptokenlen = tokenlen + lenbytes + 1;

	if (gy_unlikely(tokenlen + lenbytes + 1 > pktlen)) {
		if (handle_frag == 0) {
			*pskip = 1;
			return SYB_RET_CHECK_PKT_END;
		}
		else {
			if (tokenlen > SYB_MAX_TOKEN_SAVELEN) {
				*pskip = 1;
				return SYB_RET_CHECK_PKT_END;
			}
			if (!pTokenBuf || (sybstat_.max_token_buf_len < tokenlen + 8)) {
				if (pTokenBuf)
					free(pTokenBuf);

				if ((pTokenBuf = (uint8_t *)malloc(tokenlen + 8)) == nullptr) {
					*pskip = 1;
					return SYB_RET_CHECK_PKT_END;
				}
				sybstat_.max_token_buf_len = tokenlen + 8;
			}

			if (ppkt_end - ptmp <= sybstat_.max_token_buf_len) {
				memcpy(pTokenBuf, ptmp, ppkt_end - ptmp);
			}
			sybstat_.token_curr_len = ppkt_end - ptmp;
			sybstat_.token_pending_len = tokenlen + 3 - sybstat_.token_curr_len;
			sybstat_.param_req_pending = 1;

			return 0;
		}
	}
	else {
		pktlen = tokenlen + lenbytes + 1;
		ppkt_end = ptmp + pktlen;
	}

	if (gy_unlikely(pktlen < 10))
		return 0;

	if (gy_unlikely(sybstat_.cli_tds_version < 5))
		return 0;

	/*
	 * Now check the columns for SYB_DATA_TYPE_BLOB or SYB_DATA_TYPE_TEXT
	 */ 
	ncols = unaligned_read_16(ptmp + lenbytes + 1, sybstat_.orig_client_bo);

	if (gy_unlikely(ncols == 0))
		return 0;

	if (gy_unlikely(ncols > SYB_MAX_NUM_COLS))
		return 0;

	ptmp += lenbytes + 3;

	pcolstart = ptmp;

#undef IR_CHK_END_PTR
#define IR_CHK_END_PTR(_len) 									\
	if (gy_unlikely(ptmp < pdatastart)) {							\
		*pskip = 1;									\
		return SYB_RET_CHECK_PKT_END;							\
	}											\
	if (gy_unlikely(ptmp + (_len) > ppkt_end))	{						\
												\
		return 0;									\
	}

	for (i = 0; i < ncols; i++) {
		IR_CHK_END_PTR(1);

		tlen = *ptmp;

		IR_CHK_END_PTR(tlen + 1); 

		ptmp += tlen + 1;


		if (token != SYB_TOKEN_PARAMFMT2) {
			IR_CHK_END_PTR(6);
		}
		else {
			IR_CHK_END_PTR(9);
			ptmp += 3;
		}

		usertype = unaligned_read_32(ptmp + 1, sybstat_.orig_client_bo);		
		datatype = *(ptmp + 5);

		if (gy_unlikely(sybdatalist[datatype].pdatatype == nullptr))
			return 0;

		is_blob = 0;

		switch (sybdatalist[datatype].type_flags) {
			case SYB_DATA_TYPE_NORMAL:
				ptmp += 6;		
				break;

			case SYB_DATA_TYPE_SIMPLE_LEN1:
				ptmp += 7;
				break;

			case SYB_DATA_TYPE_SIMPLE_LEN4:
				ptmp += 10;
				break;

			case SYB_DATA_TYPE_DECIMAL:
				ptmp += 9;
				break;

			case SYB_DATA_TYPE_BIGDATE:
				ptmp += 8;
				break;

			case SYB_DATA_TYPE_TEXT:
				ntxt++;
				ptmp += 10;
				IR_CHK_END_PTR(3);
				tlen2 = unaligned_read_16(ptmp, sybstat_.orig_client_bo);
				ptmp += tlen2 + 2;
				break;

			case SYB_DATA_TYPE_BLOB:
				is_blob = 1;

				ctype = *(ptmp + 6);

				if (ctype > 5)
					nblobs++;

				ptmp += 7;
				break;
		}

		IR_CHK_END_PTR(1);
		tlen = *ptmp;

		IR_CHK_END_PTR(tlen + 1);

		ptmp += tlen + 1;	

		if (gy_unlikely(is_blob == 1)) {
			IR_CHK_END_PTR(2);
			tlen2 = unaligned_read_16(ptmp, sybstat_.orig_client_bo);
			IR_CHK_END_PTR(2 + tlen2);
			ptmp += 2 + tlen2;
		}
	}

	if (dir == DirPacket::DirInbound) {
		/*
		 * Create a SYB_ROWFMT_T
		 */
		if ((sybstat_.cursor_query_active == 0) || (pCurrCursor == nullptr)) {
			if (pCurrParamFmt) {
				if ((pCurrParamFmt->tokenlen == tokenlen) && pCurrParamFmt->pcol && 
						pCurrParamFmt->ncols == ncols && pCurrParamFmt->magic == SYB_ROWFMT_MAGIC) {
					/*
					 * Use prev def
					 */ 
				}
				else {
					if (pCurrParamFmt->magic == SYB_ROWFMT_MAGIC) {
						if (pCurrParamFmt->pcol)
							free(pCurrParamFmt->pcol);

						free(pCurrParamFmt);
					}
					pCurrParamFmt = nullptr;
				}
			}

			if (pCurrParamFmt == nullptr) {
				if ((pCurrParamFmt = (SYB_ROWFMT_T *)calloc(1, sizeof(SYB_ROWFMT_T))) == nullptr)
					return 1;

				if ((pCurrParamFmt->pcol = (SYB_COLFMT_T *)calloc(ncols, sizeof(SYB_COLFMT_T))) == nullptr)
					return 1;
			}

			pcurrrowfmt = pCurrParamFmt;
		}
		else {
			if ((pCurrCursor != nullptr)) {
				if (pCurrCursor->pcurrparamfmt) {
					if ((pCurrCursor->pcurrparamfmt->tokenlen == tokenlen) && 
							pCurrCursor->pcurrparamfmt->pcol && 
							pCurrCursor->pcurrparamfmt->ncols == ncols && 
							pCurrCursor->pcurrparamfmt->magic == SYB_ROWFMT_MAGIC) {
						/*
						 * Use prev def
						 */ 
					}
					else {
						if (pCurrCursor->pcurrparamfmt->magic == SYB_ROWFMT_MAGIC) {
							if (pCurrCursor->pcurrparamfmt->pcol)
								free(pCurrCursor->pcurrparamfmt->pcol);

							free(pCurrCursor->pcurrparamfmt);
						}
						pCurrCursor->pcurrparamfmt = nullptr;
					}
				}

				if (pCurrCursor->pcurrparamfmt == nullptr) {
					if ((pCurrCursor->pcurrparamfmt = (SYB_ROWFMT_T *)calloc(1, sizeof(SYB_ROWFMT_T))) == nullptr)
						return 1;

					if ((pCurrCursor->pcurrparamfmt->pcol = (SYB_COLFMT_T *)calloc(ncols, sizeof(SYB_COLFMT_T))) == nullptr)
						return 1;
				}

				pcurrrowfmt = pCurrCursor->pcurrparamfmt;

			}
			else
				return 0;
		}


		pcurrrowfmt->magic = SYB_ROWFMT_MAGIC;
		pcurrrowfmt->ncols = ncols;
		pcurrrowfmt->tokenlen = tokenlen;
		pcurrrowfmt->token = token;
		pcurrrowfmt->nblobs = nblobs;
		pcurrrowfmt->ntxt = ntxt;

		pcol = pcurrrowfmt->pcol;
		ptmp = pcolstart;

		for (i = 0; i < ncols; i++, pcol++) {
			tlen = *ptmp;

			ptmp += tlen + 1;

			if (token != SYB_TOKEN_PARAMFMT2)
				pcol->status = *ptmp;
			else {
				pcol->status = unaligned_read_32(ptmp, sybstat_.orig_client_bo);		
				ptmp += 3;
			}

			pcol->usertype = unaligned_read_32(ptmp + 1, sybstat_.orig_client_bo);		
			pcol->datatype = *(ptmp + 5);

			is_blob = 0;

			switch (sybdatalist[pcol->datatype].type_flags) {
				case SYB_DATA_TYPE_NORMAL :
					pcol->len = sybdatalist[pcol->datatype].maxlen;
					ptmp += 6;		
					break;

				case SYB_DATA_TYPE_SIMPLE_LEN1 :
					pcol->len = *(ptmp + 6);
					ptmp += 7;
					break;

				case SYB_DATA_TYPE_SIMPLE_LEN4 :
					pcol->len = unaligned_read_32(ptmp + 6, sybstat_.orig_client_bo);
					ptmp += 10;
					break;

				case SYB_DATA_TYPE_DECIMAL :
					pcol->len = *(ptmp + 6);
					pcol->precision = *(ptmp + 7);
					pcol->scale = *(ptmp + 8);

					ptmp += 9;
					break;

				case SYB_DATA_TYPE_BIGDATE :
					pcol->len = *(ptmp + 6);
					ptmp += 8;
					break;

				case SYB_DATA_TYPE_TEXT :
					pcol->len = unaligned_read_32(ptmp + 6, sybstat_.orig_client_bo);

					ptmp += 10;
					tlen2 = unaligned_read_16(ptmp, sybstat_.orig_client_bo);
					ptmp += tlen2 + 2;
					break;

				case SYB_DATA_TYPE_BLOB :
					pcol->blob_classid = *(ptmp + 6);
					is_blob = 1;

					ptmp += 7;
					break;
			}

			tlen = *ptmp;
			ptmp += tlen + 1;	

			if (gy_unlikely(is_blob == 1)) {
				tlen2 = unaligned_read_16(ptmp, sybstat_.orig_client_bo);
				ptmp += 2 + tlen2;
			}
		}
	} 	

	return 0;
}


int SYBASE_ASE_SESSINFO::chk_for_resp_errors(uint8_t *sptrin, uint16_t len)
{
	uint8_t			*sptr = sptrin, *ptmp, *ppkt_end = sptr + len;
	int			ret;

	if (len < 10) {
		return 0;
	}

	do {
		ptmp = (uint8_t *)memchr(sptr, SYB_TOKEN_EED, ppkt_end - sptr - 10);
		if (ptmp) {
			ret = test_extended_error_token_resp(ptmp, ppkt_end - ptmp);
			if (ret) {
				return ret;
			}

			sptr = ptmp + 1;
		}
		else {
			break;
		}
	} while (ppkt_end > sptr + 10);	

	return 0;
}


int SYBASE_ASE_SESSINFO::handle_server_response(uint8_t *sptr, uint16_t len, int fresh_resp, int is_eom)
{
	uint8_t			*ptmp = sptr, *ptmp_old, *ppkt_end = sptr + len;
	uint8_t			status, c;
	uint16_t 		pktlen = len, token16len = 0;
	uint32_t 		token32len = 0;	
	int 			ret = 0, chked = 0;

	status = *(ptmp + 1);

	ptmp += 8;
	pktlen -= 8;

	if (gy_unlikely(status & SYB_STATUS_ATTNACK)) {
		sybstat_.skip_pcap_resp_till_eom = 1;
		attention_reset_resp_type_expected();
	}

	if (gy_unlikely(sybstat_.pcap_attn_ack_expected && is_eom)) {
		/*
		 * Check if ATTN Ack is set
		 */
		if ((ppkt_end - sptr >= SYB_TDS_DONELEN) && 
				((*(ppkt_end - SYB_TDS_DONELEN) == SYB_TOKEN_DONE) || 
				 (*(ppkt_end - SYB_TDS_DONELEN) == SYB_TOKEN_DONEPROC))) {

			uint16_t		fdstatus;

			fdstatus = unaligned_read_16(ppkt_end - SYB_TDS_DONELEN + 1, sybstat_.orig_client_bo);

			if (fdstatus & SYB_DONE_ATTN) {
				attention_reset_resp_type_expected();

				sybstat_.skip_till_nextreq = 1;

				return 0;
			}
		}
	}

	if (gy_unlikely(sybstat_.skip_pcap_resp_till_eom)) {
		if (is_eom) {
			chk_for_resp_errors(ptmp, pktlen);
			return 0;
		}
		return 0;
	}

	if (fresh_resp == 0) {
		if ((sybstat_.curr_pcap_cursors_pending == 0) && (sybstat_.pcap_attn_ack_expected == 0) 
				&& (sybstat_.skip_token_resp == 0)) {
			if (is_eom) {
				chk_for_resp_errors(ptmp, pktlen);
				return 0;
			}
			return 0;
		}

		if (is_eom && sybstat_.pcap_attn_ack_expected) {
			if ((ppkt_end - sptr >= SYB_TDS_DONELEN) && 
					((*(ppkt_end - SYB_TDS_DONELEN) == SYB_TOKEN_DONE) || 
					 (*(ppkt_end - SYB_TDS_DONELEN) == SYB_TOKEN_DONEPROC))) {
				chked = 1;

				ptmp = ppkt_end - SYB_TDS_DONELEN;
				pktlen = SYB_TDS_DONELEN;

				goto chk_again;
			}
		}

		if (sybstat_.skip_token_resp > 0) {
			if (pktlen >= sybstat_.skip_token_resp) {
				ptmp += sybstat_.skip_token_resp;
				pktlen -= sybstat_.skip_token_resp;
				sybstat_.skip_token_resp = 0;

				if (sybstat_.is_data_col_ptr_valid == 0)
					goto chk_again;
			}
			else if (is_eom == 0) {
				sybstat_.skip_token_resp -= pktlen;
				return 0;
			}
			else {
				sybstat_.skip_token_resp = 0;
				return 0;
			}
		}
	}

	/*
	 * Now scan different tokens
	 */ 
chk_again:
	pktlen = ppkt_end - ptmp;

	while ((ptmp < ppkt_end) && (ptmp > sptr)) {
		c = *ptmp;
		ptmp_old = ptmp;

		switch (c) {
			case SYB_TOKEN_DONE:
				ret = handle_done_token_resp(ptmp, pktlen, &token16len,
						1 /* handle_frag */);
				if (ret == 0) {
					if (token16len <= pktlen) {
						ptmp += token16len;
						pktlen -= token16len;
					}
					else
						return 0;
				}
				else if (ret == SYB_RET_CHECK_PKT_END)
					return 0;
				else
					return ret;
				break;

			case SYB_TOKEN_DONEINPROC:
				ret = handle_doneinproc_token_resp(ptmp, pktlen, &token16len,
						1 /* handle_frag */);
				if (ret == 0) {
					if (token16len <= pktlen) {
						ptmp += token16len;
						pktlen -= token16len;
					}
					else
						return 0;
				}
				else if (ret == SYB_RET_CHECK_PKT_END)
					return 0;
				else
					return ret;
				break;

			case SYB_TOKEN_DONEPROC:
				ret = handle_doneproc_token_resp(ptmp, pktlen, &token16len,
						1 /* handle_frag */);
				if (ret == 0) {
					if (token16len <= pktlen) {
						ptmp += token16len;
						pktlen -= token16len;
					}
					else
						return 0;
				}
				else if (ret == SYB_RET_CHECK_PKT_END)
					return 0;
				else
					return ret;
				break;

			case SYB_TOKEN_ENVCHANGE:
				ret = handle_envchange_token_resp(ptmp, pktlen, &token16len, 
						0 /* handle_frag */);
				if (ret == 0) {
					if (token16len <= pktlen) {
						ptmp += token16len;
						pktlen -= token16len;
					}
					else
						return 0;
				}
				else if (ret == SYB_RET_CHECK_PKT_END) {
					sybstat_.skip_pcap_resp_till_eom = 1;
					return 0;
				}
				else
					return ret;
				break;

			case SYB_TOKEN_EED:
				ret = handle_extended_error_token_resp(ptmp, pktlen, &token16len, 1 /* handle_frag */);
				if (ret == 0) {
					if (token16len <= pktlen) {
						ptmp += token16len;
						pktlen -= token16len;
					}
					else
						return 0;
				}
				else if (ret == SYB_RET_CHECK_PKT_END)
					return 0;
				else
					return ret;
				break;


			case SYB_TOKEN_ERROR:
				ret = handle_error_token_resp(ptmp, pktlen, &token16len, 1 /* handle_frag */);
				if (ret == 0) {
					if (token16len <= pktlen) {
						ptmp += token16len;
						pktlen -= token16len;
					}
					else
						return 0;
				}
				else if (ret == SYB_RET_CHECK_PKT_END)
					return 0;
				else
					return ret;
				break;

			case SYB_TOKEN_INFO:
				ret = handle_info_token_resp(ptmp, pktlen, &token16len, 
						0 /* handle_frag */);
				if (ret == 0) {
					if (token16len <= pktlen) {
						ptmp += token16len;
						pktlen -= token16len;
					}
					else
						return 0;
				}
				else if (ret == SYB_RET_CHECK_PKT_END) {
					sybstat_.skip_pcap_resp_till_eom = 1;
					return 0;
				}
				else
					return ret;
				break;


			case SYB_TOKEN_CURINFO:
			case SYB_TOKEN_CURINFO2:
			case SYB_TOKEN_CURINFO3:
				ret = handle_curinfo_resp_tokens(ptmp, pktlen, &token16len, 
						1 /* handle_frag */);
				if (ret == 0) {
					if (token16len <= pktlen) {
						ptmp += token16len;
						pktlen -= token16len;
					}
					else
						return 0;
				}
				else if (ret == SYB_RET_CHECK_PKT_END)
					return 0;
				else
					return ret;
				break;


			case SYB_TOKEN_ROW:
			case SYB_TOKEN_PARAMS:
				sybstat_.skip_pcap_resp_till_eom = 1;
				return 0;

			case SYB_TOKEN_DYNAMIC:
				if (ptmp + 3 < ppkt_end) {
					token16len = unaligned_read_16(ptmp + 1, sybstat_.orig_client_bo) + 3;
					if (ptmp + token16len < ppkt_end) {
						ptmp += token16len;
						pktlen -= token16len;
						break;
					}
					else {
						sybstat_.skip_token_resp = token16len - (ppkt_end - ptmp);
						return 0;
					}
				}
				else {
					sybstat_.skip_pcap_resp_till_eom = 1;
					return 0;
				}
				break;

			case SYB_TOKEN_DYNAMIC2:
			case SYB_TOKEN_PARAMFMT2:
				if (ptmp + 5 < ppkt_end) {
					token32len = unaligned_read_32(ptmp + 1, sybstat_.orig_client_bo) + 5;
					if (ptmp + token32len < ppkt_end) {
						ptmp += token32len;
						pktlen -= token32len;
						break;
					}
					else {
						sybstat_.skip_token_resp = token32len - (ppkt_end - ptmp);
						return 0;
					}
				}
				else {
					sybstat_.skip_pcap_resp_till_eom = 1;
					return 0;
				}
				break;

			case SYB_TOKEN_ALTNAME:
			case SYB_TOKEN_ALTFMT:
			case SYB_TOKEN_CONTROL:
			case SYB_TOKEN_COLINFO:
			case SYB_TOKEN_EVENTNOTICE:
			case SYB_TOKEN_OPTIONCMD:
			case SYB_TOKEN_ORDERBY:
			case SYB_TOKEN_RETURNVALUE:
			case SYB_TOKEN_TABNAME:
			case SYB_TOKEN_ROWFMT:
			case SYB_TOKEN_PARAMFMT:
				if (ptmp + 3 < ppkt_end) {
					token16len = unaligned_read_16(ptmp + 1, sybstat_.orig_client_bo) + 3;
					if (ptmp + token16len < ppkt_end) {
						ptmp += token16len;
						pktlen -= token16len;
						break;
					}
					else {
						sybstat_.skip_token_resp = token16len - (ppkt_end - ptmp);
						return 0;
					}
				}
				else {
					sybstat_.skip_pcap_resp_till_eom = 1;
					return 0;
				}
				break;

			case SYB_TOKEN_ORDERBY2:
			case SYB_TOKEN_ROWFMT2:
				if (ptmp + 5 < ppkt_end) {
					token32len = unaligned_read_32(ptmp + 1, sybstat_.orig_client_bo) + 5;
					if (ptmp + token32len < ppkt_end) {
						ptmp += token32len;
						pktlen -= token32len;
						break;
					}
					else {
						sybstat_.skip_token_resp = token32len - (ppkt_end - ptmp);
						return 0;
					}
				}
				else {
					sybstat_.skip_pcap_resp_till_eom = 1;
					return 0;
				}
				break;

			case SYB_TOKEN_RETURNSTATUS:
			case SYB_TOKEN_OFFSET:
				if (ptmp + 5 < ppkt_end)
					ptmp += 5;
				else {
					sybstat_.skip_token_resp = 5 - (ppkt_end - ptmp);
					return 0;
				}
				break;

			case SYB_TOKEN_CAPABILITY:
				ret = handle_capability_token_resp(ptmp, pktlen, &token16len, 1 /* handle_frag */);
				if (ret == 0) {
					if (token16len <= pktlen) {
						ptmp += token16len;
						pktlen -= token16len;
					}
					else
						return 0;
				}
				else if (ret == SYB_RET_CHECK_PKT_END) {
					sybstat_.skip_pcap_resp_till_eom = 1;
					return 0;
				}
				else
					return ret;
				break;

			case SYB_TOKEN_LOGINACK:
				ret = handle_loginack_token_resp(ptmp, pktlen, &token16len, 1 /* handle_frag */);
				if (ret == 0) {
					if (token16len <= pktlen) {
						ptmp += token16len;
						pktlen -= token16len;
					}
					else
						return 0;
				}
				else if (ret == SYB_RET_CHECK_PKT_END) {
					sybstat_.skip_pcap_resp_till_eom = 1;
					return 0;
				}
				else
					return ret;
				break;

			default:
				/*
				 * We don't handle other Tokens.
				 */ 
				sybstat_.skip_pcap_resp_till_eom = 1;
				return 0;
		}

		if (gy_unlikely(ptmp == ptmp_old)) {
			sybstat_.skip_pcap_resp_till_eom = 1;
			return 0;
		}	
	}

	if (chked == 1)
		return 0;

	chked = 1;

	if (is_eom && sybstat_.pcap_attn_ack_expected) {
		if ((ppkt_end - sptr >= SYB_TDS_DONELEN) && 
				((*(ppkt_end - SYB_TDS_DONELEN) == SYB_TOKEN_DONE) || 
				 (*(ppkt_end - SYB_TDS_DONELEN) == SYB_TOKEN_DONEPROC))) {
			ptmp = ppkt_end - SYB_TDS_DONELEN;
			pktlen = SYB_TDS_DONELEN;

			goto chk_again;
		}
	}

	return 0;
}


int SYBASE_ASE_SESSINFO::handle_unparsed_req(uint8_t *sptr, uint16_t tdstype, uint16_t len, int fresh_req, int is_eom)
{
	if (is_eom == 1) {
		set_resp_type_expected(SYB_QUERY_RESP);
		gstats[STATSYB_UNPARSED_REQ]++;
	}	

	return 0;
}


int SYBASE_ASE_SESSINFO::handle_tds_normal_req(uint8_t *sptr, uint16_t len, int fresh_req, int is_eom)
{
	int 			ret = 0, chktext;
	uint8_t			*ptmp = sptr, c, *ppkt_end = sptr + len, lenbytes, curcloseopt = 0;
	uint16_t 		pktlen = len, token16len;
	uint32_t 		token32len, pcap_cursorid;

	if (gy_unlikely(sybstat_.skip_pcap_req_till_eom == 1)) {
		if (is_eom)
			sybstat_.skip_pcap_req_till_eom = 0;

		goto send_req;
	}

	/*
	 * We need to parse tokens for Cursor references, param fmts, parameters, etc.
	 */ 

	ptmp += 8;
	pktlen -= 8;

	if (!fresh_req) {
		if ((sybstat_.param_req_pending == 0) && (sybstat_.skip_token_req == 0) && (sybstat_.skip_request_text == 0) &&
				(sybstat_.cursor_query_active == 0) && (sybstat_.is_data_col_ptr_valid == 0)) {
			goto send_req;
		}

		if (sybstat_.skip_request_text > 0) {
			if (pktlen >= sybstat_.skip_request_text) {
				request_text_set((char *)ptmp, sybstat_.skip_request_text, 0);
				sybstat_.skip_request_text = 0;
			}
			else {
				sybstat_.skip_request_text -= pktlen;
				request_text_set((char *)ptmp, pktlen, 0);
			}
		}

		if (sybstat_.skip_token_req > 0) {
			if (pktlen >= sybstat_.skip_token_req) {
				ptmp += sybstat_.skip_token_req;
				pktlen -= sybstat_.skip_token_req;

				sybstat_.skip_token_req = 0;

				if (sybstat_.is_data_col_ptr_valid == 0)
					goto chk_again;
			}
			else if (is_eom == 0) {
				sybstat_.skip_token_req -= pktlen;
				goto send_req;
			}
			else {
				sybstat_.skip_token_req = 0;
				goto send_req;
			}
		}

		if (sybstat_.is_data_col_ptr_valid) {
			ret = handle_param_token(ptmp, pktlen, sybstat_.is_data_col_ptr_valid, 
					&token32len, DirPacket::DirInbound, &sybstat_.data_col_ptr, 1 /* handle_frag */);
			if (ret == 0) {
				if (token32len <= pktlen) {
					ptmp += token32len;
					pktlen -= token32len;

					goto chk_again;
				}
				else
					goto send_req;
			}
			else if (ret == SYB_RET_CHECK_PKT_END)
				goto send_req;
			else
				return ret;
		}
		else if (gy_unlikely(sybstat_.param_req_pending == 1)) {
			if (pktlen >= sybstat_.token_pending_len) {
				if ((size_t)sybstat_.token_curr_len + sybstat_.token_pending_len <= sybstat_.max_token_buf_len) {
					memcpy(pTokenBuf + sybstat_.token_curr_len, ptmp, sybstat_.token_pending_len);
				}
				sybstat_.token_curr_len += sybstat_.token_pending_len;
				ptmp += sybstat_.token_pending_len;
				sybstat_.token_pending_len = 0;
				sybstat_.param_req_pending = 0;

				c = *pTokenBuf;

				switch (c) {
					case SYB_TOKEN_PARAMFMT:
						ret = handle_paramfmt_token(pTokenBuf, 
								sybstat_.token_curr_len, c, &token32len, DirPacket::DirInbound, 0 /* handle_frag */);
						if (ret == 0)
							goto chk_again;
						else if (ret == SYB_RET_CHECK_PKT_END)
							goto send_req;
						else
							return ret;
						break;

					case SYB_TOKEN_PARAMFMT2:
						ret = handle_paramfmt_token(pTokenBuf, 
								sybstat_.token_curr_len, c, &token32len, DirPacket::DirInbound, 0 /* handle_frag */);
						if (ret == 0)
							goto chk_again;
						else if (ret == SYB_RET_CHECK_PKT_END)
							goto send_req;
						else
							return ret;
						break;
				}

			}
			else if (is_eom == 0) {

				if ((size_t)sybstat_.token_curr_len + pktlen <= sybstat_.max_token_buf_len) {
					memcpy(pTokenBuf + sybstat_.token_curr_len, ptmp, pktlen);
				}
				sybstat_.token_curr_len += pktlen;
				sybstat_.token_pending_len -= pktlen;

				goto send_req;
			}
			else {
				sybstat_.token_pending_len = 0;
				sybstat_.token_curr_len = 0;
				sybstat_.param_req_pending = 0;

				goto send_req;
			}
		}
	}


chk_again :
	pktlen = ppkt_end - ptmp;

	while (ptmp < ppkt_end) {
		c = *ptmp;

		switch (c) {
			case SYB_TOKEN_DBRPC:
			case SYB_TOKEN_DBRPC2:
			case SYB_TOKEN_RPC:
				ret = handle_dbrpc_token(ptmp, pktlen, c, &token32len, 1 /* handle_frag */);
				if (ret == 0) {
					token16len = (uint16_t)token32len;
					if (token16len <= pktlen) {
						ptmp += token16len;
						pktlen -= token16len;
					}
					else
						goto send_req;
				}
				else if (ret == SYB_RET_CHECK_PKT_END)
					goto send_req;
				else
					return ret;
				break;

			case SYB_TOKEN_DYNAMIC:
			case SYB_TOKEN_DYNAMIC2:
				ret = handle_dyn_token(ptmp, pktlen, c, &token32len, 1 /* handle_frag */);
				if (ret == 0) {
					if (token32len <= pktlen) {
						ptmp += token32len;
						pktlen -= token32len;
					}
					else
						goto send_req;
				}
				else if (ret == SYB_RET_CHECK_PKT_END)
					goto send_req;
				else
					return ret;
				break;


			case SYB_TOKEN_ALTFMT:
			case SYB_TOKEN_ALTNAME:
			case SYB_TOKEN_COLINFO:
			case SYB_TOKEN_CONTROL:
			case SYB_TOKEN_OPTIONCMD:
			case SYB_TOKEN_ORDERBY:
			case SYB_TOKEN_TABNAME:
				if (ptmp + 3 < ppkt_end) {
					token16len = unaligned_read_16(ptmp + 1, sybstat_.orig_client_bo) + 3;
					if (ptmp + token16len < ppkt_end) {
						ptmp += token16len;
						pktlen -= token16len;
						break;
					}
					else {
						sybstat_.skip_token_req = token16len - (ppkt_end - ptmp);
						goto send_req;
					}
				}
				else {
					sybstat_.skip_pcap_req_till_eom = 1;
					goto send_req;
				}
				break;

			case SYB_TOKEN_LANGUAGE:
				ret = handle_language_req_token(ptmp, pktlen, &token32len, 1 /* handle_frag */);
				if (ret == 0) {
					if (token32len <= pktlen) {
						ptmp += token32len;
						pktlen -= token32len;
					}
					else
						goto send_req;
				}
				else if (ret == SYB_RET_CHECK_PKT_END)
					goto send_req;
				else
					return ret;
				break;

			case SYB_TOKEN_ORDERBY2:
				if (ptmp + 5 < ppkt_end) {
					token32len = unaligned_read_32(ptmp + 1, sybstat_.orig_client_bo) + 5;
					if (ptmp + token32len < ppkt_end) {
						ptmp += token32len;
						pktlen -= token32len;
						break;
					}
					else {
						sybstat_.skip_token_req = token32len - (ppkt_end - ptmp);
						goto send_req;
					}
				}
				else {
					sybstat_.skip_pcap_req_till_eom = 1;
					goto send_req;
				}
				break;

			case SYB_TOKEN_PARAMFMT:
				ret = handle_paramfmt_token(ptmp, pktlen, c, &token32len, 
						DirPacket::DirInbound, 1 /* handle_frag */);
				if (ret == 0) {
					token16len = (uint16_t)token32len;
					if (token16len <= pktlen) {
						ptmp += token16len;
						pktlen -= token16len;
					}
					else
						goto send_req;
				}
				else if (ret == SYB_RET_CHECK_PKT_END)
					goto send_req;
				else
					return ret;
				break;

			case SYB_TOKEN_PARAMFMT2:
				ret = handle_paramfmt_token(ptmp, pktlen, c, &token32len, 
						DirPacket::DirInbound, 1 /* handle_frag */);
				if (ret == 0) {
					if (token32len <= pktlen) {
						ptmp += token32len;
						pktlen -= token32len;
					}
					else
						goto send_req;
				}
				else if (ret == SYB_RET_CHECK_PKT_END)
					goto send_req;
				else
					return ret;
				break;


			case SYB_TOKEN_PARAMS:
				if ((/*(sybstat_.cursor_query_active == 0) && */(pCurrParamFmt)) ||
						((sybstat_.cursor_query_active && pCurrCursor && 
						  (pCurrCursor->pcurrparamfmt)))) {
					ret = handle_param_token(ptmp, pktlen, c, 
							&token32len, DirPacket::DirInbound, nullptr, 1 /* handle_frag */);
					if (ret == 0) {
						if (token32len <= pktlen) {
							ptmp += token32len;
							pktlen -= token32len;
						}
						else
							goto send_req;
					}
					else if (ret == SYB_RET_CHECK_PKT_END)
						goto send_req;
					else
						return ret;
				}
				else {
					sybstat_.skip_pcap_req_till_eom = 1;
					goto send_req;
				}
				break;

			case SYB_TOKEN_CURDECLARE:
			case SYB_TOKEN_CURDECLARE2:
			case SYB_TOKEN_CURDECLARE3:
				ret = handle_curdeclare_token(ptmp, pktlen, c, &token32len, 1 /* handle_frag */);
				if (ret == 0) {
					if (token32len <= pktlen) {
						ptmp += token32len;
						pktlen -= token32len;
					}
					else
						goto send_req;
				}
				else if (ret == SYB_RET_CHECK_PKT_END)
					goto send_req;
				else
					return ret;
				break;

			case SYB_TOKEN_CURCLOSE:
			case SYB_TOKEN_CURFETCH:
			case SYB_TOKEN_CURDELETE:
			case SYB_TOKEN_CURINFO:
			case SYB_TOKEN_CURINFO2:
			case SYB_TOKEN_CURINFO3:
			case SYB_TOKEN_CUROPEN:
			case SYB_TOKEN_CURUPDATE:
				if (ptmp + 2 + 1 > ppkt_end) {
					sybstat_.skip_pcap_req_till_eom = 1;
					goto send_req;
				}

				sybstat_.cursor_query_active = c;

				token16len = unaligned_read_16(ptmp + 1, sybstat_.orig_client_bo) + 3;

				if ((c == SYB_TOKEN_CURINFO) && (sybstat_.curinfo_tokenlen_bug))
					token16len--;

				if (ptmp + token16len > ppkt_end) {
					sybstat_.skip_token_req =  token16len - (ppkt_end - ptmp);
					goto send_req;
				}

				chktext = 1;

				switch (c) {
					case SYB_TOKEN_CURCLOSE:
						tran_.tran_type_ |= TYPE_SYB_CURSOR_CLOSE;
						request_text_set("/* Cursor Close */", 0, 1);
						break;

					case SYB_TOKEN_CURFETCH:
						tran_.tran_type_ |= TYPE_SYB_CURSOR_FETCH;
						request_text_set("/* Cursor Fetch */", 0, 1);
						break;

					case SYB_TOKEN_CURDELETE:
						tran_.tran_type_ |= TYPE_SYB_CURSOR_DELETE;
						request_text_set("/* Cursor Delete */", 0, 1);
						break;

					case SYB_TOKEN_CUROPEN:
						tran_.tran_type_ |= TYPE_SYB_CURSOR_OPEN;
						request_text_set("/* Cursor Open */", 0, 1);
						break;

					case SYB_TOKEN_CURUPDATE:
						tran_.tran_type_ |= TYPE_SYB_CURSOR_UPDATE;
						request_text_set("/* Cursor Update */", 0, 1);
						break;

					default:
						chktext = 0;
						break;
				}

				pcap_cursorid = unaligned_read_32(ptmp + 3, sybstat_.orig_client_bo);

				if (pcap_cursorid > 0) {

					if (c == SYB_TOKEN_CURCLOSE) 
						curcloseopt = *(ptmp + 7);

					if (chktext)
						ret = find_pcap_cursor(pcap_cursorid);

					if (curcloseopt & 0x1)
						close_cursor(pcap_cursorid);
				}

				ptmp += token16len;

				if ((ptmp < ppkt_end) && (c == SYB_TOKEN_CURINFO)) {
					/*
					 * Handle TDS bug for SYB_TOKEN_CURINFO based tokens where len is not correct
					 */ 
					if (!syb_is_cursor_token(*ptmp)) {
						if (syb_is_cursor_token(*(ptmp - 1))) {
							sybstat_.curinfo_tokenlen_bug = 1;
							ptmp--;
						}
					}
				}
				break;

			case SYB_TOKEN_MSG:
				if (gy_unlikely(sybstat_.skip_till_login_rsp == 1)) {
					sybstat_.skip_till_login_rsp = 0;
					ret = 1;
				}
				goto send_req;

			case SYB_TOKEN_LOGOUT:
				goto send_req;

			default:
				sybstat_.skip_pcap_req_till_eom = 1;

				gstats[STATSYB_UNHANDLED_REQ_TOKEN]++;
				goto send_req;
		}
	}

send_req:

	if (is_eom == 1)
		set_resp_type_expected(SYB_QUERY_RESP);

	return 0;
}


int SYBASE_ASE_SESSINFO::handle_attention_req(uint8_t *sptr, uint16_t len, int fresh_req, int is_eom)
{
	if (tdstrbuf_.size() == 0) {
		tran_.tran_type_ |= TYPE_SYB_CANCEL_QUERY;

		request_text_set("Cancel Query ");
		gstats[STATSYB_CANCEL_QUERY]++;
	}	

	sybstat_.cursor_query_active = 0;

	if (is_eom == 1) {
		sybstat_.pcap_attn_ack_expected = 1;
		set_resp_type_expected(SYB_QUERY_RESP);
	}

	return 0;
}


int SYBASE_ASE_SESSINFO::handle_bulk_req(uint8_t *sptr, uint16_t len, int fresh_req, int is_eom)
{
	tran_.tran_type_ |= TYPE_SYB_BULK_INSERT;

	if (fresh_req) {
		request_text_set("/* Bulk Insert */"); 
	}	

	if (is_eom == 1)
		set_resp_type_expected(SYB_QUERY_RESP);

	return 0;
}


int SYBASE_ASE_SESSINFO::handle_rpc_req(uint8_t *sptr, uint16_t len, int fresh_req, int is_eom)
{
	uint8_t	*ptmp = sptr, c, *ppkt_end = sptr + len, lenbytes;
	uint16_t pktlen = len;

	ptmp += 8;
	pktlen -= 8;

	if (pktlen > 1) {
		c = *ptmp++;

		if ((c > 1) && (isascii(*ptmp))) {
			if (ptmp + c < ppkt_end) {
				if (*(ptmp + c - 1) == '\0')
					c--;

				request_text_set("/* RPC Request */");
				request_text_set((char *)ptmp, c, 1);

				tran_.tran_type_ |= TYPE_SYB_DBRPC_RPC;
			}	
		}
	}

	if (is_eom == 1)
		set_resp_type_expected(SYB_QUERY_RESP);

	return 0;
}


int SYBASE_ASE_SESSINFO::handle_lang_req(uint8_t *sptr, uint16_t len, int fresh_req, int is_eom)
{
	uint8_t	*ptmp = sptr, c, lenbytes;
	uint16_t pktlen = len;

	ptmp += 8;
	pktlen -= 8;

	if (pktlen > 0) {
		request_text_set((char *)ptmp, pktlen, (fresh_req && is_eom) /* chk_append */);
		tran_.tran_type_ |= TYPE_SYB_LANG_REQ;
	}

	if (is_eom == 1) set_resp_type_expected(SYB_QUERY_RESP);

	return 0;
}


int SYBASE_ASE_SESSINFO::handle_login_req(uint8_t *sptr, uint16_t len, int fresh_req)
{
	uint8_t			*ptmp = sptr, *ppkt_end = sptr + len, *pall;
	uint8_t			appname[32], username[32]; 
	uint16_t 		pktlen = len;
	uint8_t			lenusername, lenappname, ntdshdrs = 1;
	uint8_t			int2_byteorder, *pltype; 
	int 			ret;	
	uint8_t			tds_maj, tds_min;
	uint8_t			cl_v1, cl_v2, cl_v3, cl_v4;
	uint8_t			conn_len;
	int 			ver_len = 0;
	char 			conn_type[12] = {};
	int 			lenpid = 0;

	*username = 0;
	*appname = 0;

	if (sybstat_.pcap_sess_state == SYB_STATE_LOGIN_COMPLETE)
		goto sendreq;

	if (sybstat_.pcap_sess_state == SYB_STATE_UNINIT)
		sybstat_.pcap_sess_state = SYB_STATE_TDS_LOGIN_REQ;
	else if (sybstat_.pcap_sess_state == SYB_STATE_TDS_LOGIN_SPLIT_REQ)
		ntdshdrs++;
	else
		goto sendreq;

	/*
	 * First check for Multi-TDS.
	 */ 
	if (((*(sptr + 1)) & 0x1) == 0) {
		if (sybstat_.curr_multi_tds_len + len > 2048)
			return -1;

		ptmp = sptr;
		pktlen = len;

		if (sybstat_.curr_multi_tds_len + pktlen > sybstat_.max_multi_tds_len) {
			pall = (uint8_t *)realloc(pMultiTDSBuf, sybstat_.max_multi_tds_len + pktlen + 1024);
			if (pall == nullptr) {
				return -1;
			}	

			sybstat_.max_multi_tds_len += pktlen + 1024;
			pMultiTDSBuf = pall;
		}

		memcpy(pMultiTDSBuf + sybstat_.curr_multi_tds_len, ptmp, pktlen);
		sybstat_.curr_multi_tds_len += pktlen;
		sybstat_.pcap_sess_state = SYB_STATE_TDS_LOGIN_SPLIT_REQ;

		if (fresh_req == 1)
			set_resp_type_expected(SYB_LOGIN_RESP);

		return 1;
	}
	else if (sybstat_.pcap_sess_state == SYB_STATE_TDS_LOGIN_SPLIT_REQ) {
		if (sybstat_.curr_multi_tds_len + len > 2048)
			return -1;

		ptmp = sptr;
		pktlen = len;

		if (sybstat_.curr_multi_tds_len + pktlen > sybstat_.max_multi_tds_len) {
			pall = (uint8_t *)realloc(pMultiTDSBuf, sybstat_.max_multi_tds_len + pktlen + 4 * 1024);
			if (pall == nullptr) {
				return -1;
			}	

			sybstat_.max_multi_tds_len += pktlen + 4 * 1024;
			pMultiTDSBuf = pall;
		}

		memcpy(pMultiTDSBuf + sybstat_.curr_multi_tds_len, ptmp, pktlen);
		sybstat_.pcap_sess_state = SYB_STATE_TDS_LOGIN_REQ;

		sptr = ptmp = pMultiTDSBuf;
		len = pktlen = sybstat_.curr_multi_tds_len + pktlen;
		sybstat_.curr_multi_tds_len = 0;
	}

	ppkt_end = ptmp + pktlen;

	ptmp += 8;
	pktlen -= 8;

	if (pktlen < 563)
		return -1;

	ptmp += 31;
	pktlen -= 31;

	lenusername = *(ptmp + 30);
	if (lenusername <= 30)
		unicode_to_ascii(username, ptmp, lenusername, sizeof(username), ppkt_end, 1);
	else
		return -1;

	ptmp += 31;
	pktlen -= 31;

	ptmp += 31;
	pktlen -= 31;
	lenpid = *(ptmp + 30);
	if((lenpid > 1) && (lenpid < 30)) {
		char lpid[32];
		memcpy(lpid, ptmp, lenpid);
		lpid[lenpid] = 0;
		int ipid = atoi(lpid);
		set_session_pid(ipid);
	}
	else {
		set_session_pid(0);
	}

	ptmp = sptr + 8 + 124;
	pktlen = len - 8 - 124;

	int2_byteorder = *ptmp;

	if (int2_byteorder == 2)
		sybstat_.orig_client_bo = BO_BIG_ENDIAN;
	else
		sybstat_.orig_client_bo = BO_LITTLE_ENDIAN;

	ptmp = sptr + 8 + 140;
	pktlen = len - 8 - 140;

	lenappname = *(ptmp + 30);
	if (lenappname <= 30)
		unicode_to_ascii(appname, ptmp, lenappname, sizeof(appname), ppkt_end, 1);

	ptmp += 31;
	pktlen -= 31;

	ptmp += 31;
	pktlen -= 31;

	pltype = (sptr + 8 + 132);

	if ((*pltype != 0) && (*pltype != 0x04))
		*pltype = 0;

	ptmp = sptr + 8 + 458;
	if (*ptmp == 5)
		sybstat_.cli_tds_version = 5;
	else if (*(ptmp + 1) == 4)
		sybstat_.cli_tds_version = 4;

	ptmp = sptr + ntdshdrs * 8 + 568;

	tran_.tran_type_ = TYPE_SYB_LOGIN;

	request_text_set("*login* ");
	request_text_set((char*)username);

	tdstat_.userbuf_.reset().append(username);
	tdstat_.appbuf_.reset().append(appname);

	tds_maj	= *(sptr + 8 + 458);
	tds_min	= *(sptr + 8 + 459);
	conn_len = *(sptr + 8 + 472);
	if(conn_len <= 10) {
		memcpy(conn_type, sptr + 8 + 462, conn_len);
	}	

	cl_v1 = *(sptr + 8 + 473);
	cl_v2 = *(sptr + 8 + 474);
	cl_v3 = *(sptr + 8 + 475);
	cl_v4 = *(sptr + 8 + 476);

	tdstat_.appbuf_.appendfmt("(TDS%d.%d %s %2d.%2d.%2d.%2d)", tds_maj, tds_min, conn_type, cl_v1, cl_v2, cl_v3, cl_v4);

sendreq:

	if (fresh_req == 1)
		set_resp_type_expected(SYB_LOGIN_RESP);

	return 0;
}


int SYBASE_ASE_SESSINFO::handle_login_response(uint8_t *sptr, uint16_t len)
{
	int 			ret;
	uint8_t			*ptmp = sptr, *ptmp_old, *ppkt_end = sptr + len;
	uint16_t 		pktlen = len, status;
	uint8_t			c;
	uint16_t 		tokenlen = 0;
	int 			is_login_ack = 0, is_eom = 0;

	if (sybstat_.pcap_sess_state != SYB_STATE_TDS_LOGIN_SPLIT_RESP)
		sybstat_.pcap_sess_state = SYB_STATE_TDS_LOGIN_RESP;

	if (((*(sptr + 1)) & 0x1) == 0)
		sybstat_.pcap_sess_state = SYB_STATE_TDS_LOGIN_SPLIT_RESP;
	else
		is_eom = 1;

	if (sybstat_.pcap_sess_state == SYB_STATE_TDS_LOGIN_SPLIT_RESP) {
		/*
		 * Ckeck pResFragBuf if any prev token exists
		 */
		if (pktlen + sybstat_.fragresp_len > SYB_FRAGBUFLEN)
			return -1;

		if (sybstat_.fragresp_len > 0 && pktlen >= 8) {
			memcpy(pResFragBuf + sybstat_.fragresp_len, ptmp + 8, pktlen - 8);
			sybstat_.fragresp_len += pktlen - 8;
		}
		else {
			memcpy(pResFragBuf, ptmp, pktlen);
			sybstat_.fragresp_len = pktlen;
		}

		if (is_eom) {
			ptmp = pResFragBuf;
			pktlen = sybstat_.fragresp_len;
			ppkt_end = ptmp + pktlen;
			sptr = ptmp;
		}
		else
			return 0;
	}

	ptmp += 8;
	pktlen -= 8;

	/*
	 * Now scan the differet tokens.
	 * Login Response can contain Env Change, Error, Info, Done Tokens.
	 */
	while ((ptmp < ppkt_end) && (ptmp > sptr)) {
		c = *ptmp;
		ptmp_old = ptmp;

		switch (c) {
			case SYB_TOKEN_DONE:
				status = unaligned_read_16(ptmp + 1, sybstat_.orig_client_bo);
				if ((status & SYB_DONE_COUNT) == 0) {
					tdstat_.spid_ = unaligned_read_32(ptmp + 5, sybstat_.orig_client_bo);
				}
				return 0;

			case SYB_TOKEN_ENVCHANGE:
				ret = handle_envchange_token_resp(ptmp, pktlen, &tokenlen, 0 /* handle_frag */);
				if (ret == 0) {
					if (tokenlen <= pktlen) {
						ptmp += tokenlen;
						pktlen -= tokenlen;
					}
					else
						return -1;
				}
				else if (ret == SYB_RET_CHECK_PKT_END)
					return 0;
				else
					return ret;
				break;

			case SYB_TOKEN_EED:
				ret = handle_extended_error_token_resp(ptmp, pktlen, &tokenlen, 1 /* handle_frag */);
				if (ret == 0) {
					if (tokenlen <= pktlen) {
						ptmp += tokenlen;
						pktlen -= tokenlen;
					}
					else
						return -1;
				}
				else if (ret == SYB_RET_CHECK_PKT_END)
					return 0;
				else
					return ret;
				break;

			case SYB_TOKEN_ERROR:
				ret = handle_error_token_resp(ptmp, pktlen, &tokenlen, 1 /* handle_frag */);
				if (ret == 0) {
					if (tokenlen <= pktlen) {
						ptmp += tokenlen;
						pktlen -= tokenlen;
					}
					else
						return -1;
				}
				else if (ret == SYB_RET_CHECK_PKT_END)
					return 0;
				else
					return ret;
				break;

			case SYB_TOKEN_INFO:
				ret = handle_info_token_resp(ptmp, pktlen, &tokenlen, 1 /* handle_frag */);
				if (ret == 0) {
					if (tokenlen <= pktlen) {
						ptmp += tokenlen;
						pktlen -= tokenlen;
					}
					else
						return -1;
				}
				else if (ret == SYB_RET_CHECK_PKT_END)
					return 1;
				else
					return ret;
				break;

			case SYB_TOKEN_LOGINACK:
				ret = handle_loginack_token_resp(ptmp, pktlen, &tokenlen, 1 /* handle_frag */);
				if (ret == 0) {
					if (tokenlen <= pktlen) {
						ptmp += tokenlen;
						pktlen -= tokenlen;
						is_login_ack = 1;
					}
					else
						return -1;
				}
				else if (ret == SYB_RET_CHECK_PKT_END)
					return 0;
				else
					return ret;
				break;

			case SYB_TOKEN_CAPABILITY:
				ret = handle_capability_token_resp(ptmp, pktlen, &tokenlen, 1 /* handle_frag */);
				if (ret == 0) {
					if (tokenlen <= pktlen) {
						ptmp += tokenlen;
						pktlen -= tokenlen;
					}
					else
						return -1;
				}
				else if (ret == SYB_RET_CHECK_PKT_END)
					return 1;
				else
					return ret;
				break;

			case SYB_TOKEN_MSG:

				sybstat_.to_flush_req = 0;
				sybstat_.pcap_sess_state = SYB_STATE_TDS_LOGIN_SPLIT_RESP;
				if (is_eom) {
					if (*(ppkt_end - SYB_TDS_DONELEN) == SYB_TOKEN_DONE) {
						ptmp = ppkt_end - SYB_TDS_DONELEN;
						break;
					}
				}
				return 0;

			default :

				sybstat_.pcap_sess_state = SYB_STATE_LOGIN_COMPLETE;
				if (is_eom) {
					if (*(ppkt_end - SYB_TDS_DONELEN) == SYB_TOKEN_DONE) {
						ptmp = ppkt_end - SYB_TDS_DONELEN;
						break;
					}
				}
				return 0;


		}

		if (gy_unlikely(ptmp == ptmp_old))
			return 0;
	}	

	return 0;
}


int SYBASE_ASE_SESSINFO::handle_pcap_tds_req(uint8_t *sptr, int is_frag_buf, uint16_t ntds, PARSE_PKT_HDR & hdr)
{
	uint8_t			*ppkt_end, tdstype, *ptmp, status, c;
	uint16_t 		tdslen;
	uint32_t 		token32len, oldreqlen = 0;
	int 			ret = 0, is_req_eom = 0, fresh_req = 0;
	auto			& common = svcsess_.common_;

	ptmp = sptr;

	SYB_GET_TDS_LEN(ptmp + 2, tdslen);
	SYB_GET_TDS_TYPE(ptmp, tdstype);

	status = *(ptmp + 1);

	if (sybstat_.nbytes_cur_req == 0L) {
		/*
		 * Fresh Request
		 */
		sybstat_.nbytes_cur_req += tdslen; 
		fresh_req = 1;

		if ((tdstype != SYB_TYPE_ATTN) || (tdstrbuf_.size() == 0)) {
			if (sybstat_.to_flush_req) {
				sybstat_.to_flush_req = 0;
				request_done();
			}

			if (sybstat_.pcap_sess_state != SYB_STATE_TDS_LOGIN_SPLIT_RESP) {
				if (is_frag_buf) {
					oldreqlen = (uint32_t)tran_.reqlen_;
				}	
				new_request();
	
				if (oldreqlen) {
					tran_.reqlen_ += oldreqlen;
				}
			}	
		}
	}

	if (ntds < 2) {
		tran_.update_req_stats(common.tlastpkt_usec_, hdr.datalen_);
	}

	if (status & SYB_STATUS_EOM)
		is_req_eom = 1;

	ppkt_end = sptr + tdslen;

	if (gy_unlikely(sybstat_.chk_for_tds_byteorder == 2)) {
		if (!(fresh_req && is_req_eom))
			return 0;

		if (tdstype != SYB_TYPE_NORMAL)
			goto req_done;

		if (tdslen > 255)
			goto req_done;

		c = *(sptr + 8);

		switch (c) {
			case SYB_TOKEN_DYNAMIC:
			case SYB_TOKEN_CURDECLARE:
			case SYB_TOKEN_CURCLOSE:
			case SYB_TOKEN_CURFETCH:
			case SYB_TOKEN_CURDELETE:
			case SYB_TOKEN_CURINFO:
			case SYB_TOKEN_CURINFO2:
			case SYB_TOKEN_CURINFO3:
			case SYB_TOKEN_CUROPEN:
			case SYB_TOKEN_CURUPDATE:

				token32len = unaligned_read_16(sptr + 8 + 1, BO_LITTLE_ENDIAN) + 3;
				if ((token32len > 0) && (sptr + 8 + token32len < ppkt_end))
					sybstat_.orig_client_bo = BO_LITTLE_ENDIAN;
				else
					sybstat_.orig_client_bo = BO_BIG_ENDIAN;
				break;

			case SYB_TOKEN_LANGUAGE:
			case SYB_TOKEN_DYNAMIC2:
			case SYB_TOKEN_CURDECLARE2:
			case SYB_TOKEN_CURDECLARE3:
				token32len = unaligned_read_32(sptr + 8 + 1, BO_LITTLE_ENDIAN) + 5;
				if ((token32len > 0) && (sptr + 8 + token32len < ppkt_end))
					sybstat_.orig_client_bo = BO_LITTLE_ENDIAN;
				else
					sybstat_.orig_client_bo = BO_BIG_ENDIAN;
				break;

			default:
				goto req_done;

		}

		sybstat_.chk_for_tds_byteorder = 0;
	}

	switch (tdstype) {
		case SYB_TYPE_LC_SETUP:
			/* Fallthrough */

		case SYB_TYPE_LANG:
			ret = handle_lang_req(sptr, tdslen, fresh_req, is_req_eom);
			break;

		case SYB_TYPE_RPC:
			ret = handle_rpc_req(sptr, tdslen, fresh_req, is_req_eom);
			break;

		case SYB_TYPE_NORMAL:
			if (gy_unlikely(sybstat_.pcap_sess_state == SYB_STATE_TDS_LOGIN_SPLIT_REQ))
				ret = handle_login_req(sptr, tdslen, fresh_req);
			else
				ret = handle_tds_normal_req(sptr, tdslen, fresh_req, is_req_eom);
			break;

		case SYB_TYPE_ATTN:
			ret = handle_attention_req(sptr, tdslen, fresh_req, is_req_eom);
			break;

		case SYB_TYPE_BULK:
			ret = handle_bulk_req(sptr, tdslen, fresh_req, is_req_eom);
			break;

		case SYB_TYPE_LOGIN:
			ret = handle_login_req(sptr, tdslen, fresh_req);
			break;

		default:
			ret = handle_unparsed_req(sptr, tdstype, tdslen, fresh_req, is_req_eom);
			break;
	}

req_done:

	if (is_req_eom == 1) {
		sybstat_.nbytes_cur_req = 0;

		/* Flush Partial Req */
		if (tdstrbuf_.size() && part_query_started_ == 0) {
			tran_.request_len_ = tdstrbuf_.size() + 1;
			part_query_started_ = 1;
			set_partial_req();
		}
	}	

	if (ret > 0)
		ret = 0;

	return ret;
}


int SYBASE_ASE_SESSINFO::handle_pcap_tds_resp(uint8_t *sptr, int is_frag_buf, uint16_t ntds, PARSE_PKT_HDR & hdr)
{
	uint8_t 		tdstype, *ptmp, status, is_pcap_eom = 0;
	uint16_t 		tdslen;
	int 			ret = 0, fresh_resp = 0;
	auto			& common = svcsess_.common_;

	if (is_frag_buf == 1) {
		if (sybstat_.ign_resp_frag == SYB_TDS_SKIP) {
			sybstat_.ign_resp_frag = 0;
			return 0;
		}
	}

	if (gy_unlikely(sybstat_.npcap_response_pending == 0))
		return 0;

	ptmp = sptr;

	SYB_GET_TDS_LEN(ptmp + 2, tdslen);
	SYB_GET_TDS_TYPE(ptmp, tdstype);

	if (sybstat_.nbytes_pcap_resp == 0L) {
		/*
		 * Fresh response
		 */
		sybstat_.nbytes_pcap_resp += tdslen; 
		fresh_resp = 1;
	}

	status = *(ptmp + 1);
	if (status & SYB_STATUS_EOM)
		is_pcap_eom = 1;

	if (ntds < 2) {
		tran_.update_resp_stats(common.tlastpkt_usec_, hdr.datalen_);
	}

	if (gy_unlikely(sybstat_.pcap_sess_state != SYB_STATE_LOGIN_COMPLETE))
		ret = handle_login_response(sptr, tdslen);	
	else
		ret = handle_server_response(sptr, tdslen, fresh_resp, is_pcap_eom);	 

	if (ret > 0)
		ret = 0; /* Skip this response packet */

	if (is_pcap_eom == 1) {
		sybstat_.nbytes_pcap_resp = 0L;

		if (sybstat_.to_flush_req) {
			sybstat_.to_flush_req = 0;
			request_done();
		}

		reset_resp_type_expected();

		if (part_query_started_ == 1) {
			drop_partial_req();
			part_query_started_ = 0;
		}
	}

	return ret;
}


int SYBASE_ASE_SESSINFO::is_tds_of_interest(uint8_t tdstype, DirPacket dir)
{
	if ((sybstat_.pcap_sess_state != SYB_STATE_LOGIN_COMPLETE) || (dir == DirPacket::DirInbound))
		return SYB_TDS_PARSE;

	/* TODO Skip Responses where parsing not required for better optimization */

	return SYB_TDS_PARSE;
}


int SYBASE_ASE_SESSINFO::handle_drop_req_pkt(uint8_t *sptr, uint16_t ppkt_len)
{
	int is_pre_pcap = 0, ret;

	if (gy_unlikely(sybstat_.is_login_complete == 0)) {
		sybstat_.is_login_complete = 1;
		sybstat_.chk_for_tds_byteorder = 1;

		goto done1;
	}	

	if (sybstat_.drop_handled == 1) {
		if (sybstat_.last_dir == DirPacket::DirInbound)
			return 1;
	}

	if (part_query_started_ == 1) {
		drop_partial_req();
		part_query_started_ = 0;
	}

	sybstat_.drop_handled = 1;

	if ((sybstat_.drop_req_seen == 1) && (sybstat_.drop_resp_seen == 0)) {
		/* Drop from start of Request */
		sybstat_.skip_to_req_after_resp = 1;
		return 1;
	}
	else if ((sybstat_.drop_req_seen == 0) && (sybstat_.drop_resp_seen == 1)) {
done1 :		
		if (sybstat_.npcap_response_pending > 0)
			reset_resp_type_expected();

		sybstat_.drop_seen = 0;
		sybstat_.drop_resp_seen = 0;

		sybstat_.frag_resp_nleft = 0;
		sybstat_.frag_resp_nparsed = 0;
		sybstat_.pcap_resp_frag = 0;

		sybstat_.drop_handled = 0;

		return 0;
	}
	else if ((sybstat_.drop_req_seen == 1) && (sybstat_.drop_resp_seen == 1)) {
		if (sybstat_.nbytes_cur_req == 0L) {
			if (sybstat_.npcap_response_pending > 0)
				reset_resp_type_expected();
		}
		sybstat_.skip_to_req_after_resp = 1;
		return 1;
	}

	/* 
	 * We keep drop_seen till end of pcap response packet.
	 */ 

	return 0;
}


int SYBASE_ASE_SESSINFO::handle_drop_pcap_resp_eom(uint8_t *sptr, uint16_t ppkt_len)
{
	uint8_t			*ptmp, *ppkt_end, c;
	const uint8_t 		donelen = SYB_TDS_DONELEN;
	uint16_t 		len;
	uint16_t 		fdstat;

	/*
	 * Check if the current response packet is tentatively a EOM
	 * using SYB_TOKEN_DONE or SYB_TOKEN_DONEPROC.
	 */ 

	ptmp = sptr;
	len = ppkt_len;

	ppkt_end = sptr + len;

	if (len <= donelen)
		return 1;

	ptmp = ppkt_end - donelen;

	c = *ptmp;
	if (!((c == SYB_TOKEN_DONEPROC) || (c == SYB_TOKEN_DONE)))
		return 1;

	fdstat = unaligned_read_16(ptmp + 1, sybstat_.orig_client_bo);

	if (fdstat & 0x1)
		return 1;

	/*
	 * OK EOM of pcap reached
	 */ 

	if (sybstat_.npcap_response_pending == 0)
		sybstat_.npcap_response_pending = 1;

	reset_resp_type_expected();

	sybstat_.drop_seen = 0;
	sybstat_.drop_req_seen = 0;
	sybstat_.drop_resp_seen = 0;
	sybstat_.drop_handled = 0;

	sybstat_.frag_req_nleft = 0;
	sybstat_.frag_req_nparsed = 0;
	sybstat_.pcap_req_frag = 0;

	sybstat_.frag_resp_nleft = 0;
	sybstat_.frag_resp_nparsed = 0;
	sybstat_.pcap_resp_frag = 0;

	sybstat_.skip_till_nextreq = 1;

	return 1;
}


int SYBASE_ASE_SESSINFO::handle_drop_resp_pkt(uint8_t *sptr, uint16_t ppkt_len)
{
	int ret, is_pre_pcap = 0;

	if (gy_unlikely(sybstat_.is_login_complete == 0))
		return -1;

	if (part_query_started_ == 1) {
		drop_partial_req();
		part_query_started_ = 0;
	}

	if (sybstat_.drop_handled == 1) {
		/*
		 * We check if this pcap packet is an End of Response packet.
		 */ 
		ret = handle_drop_pcap_resp_eom(sptr, ppkt_len);
		return ret;
	}

	sybstat_.drop_handled = 1;

	if ((sybstat_.drop_req_seen == 1) || (sybstat_.drop_resp_seen == 1)) {
		if (sybstat_.drop_req_seen == 1)
			sybstat_.skip_to_req_after_resp = 1;

		ret = handle_drop_pcap_resp_eom(sptr, ppkt_len);
		return ret;
	}

	return 0;
}


int SYBASE_ASE_SESSINFO::handle_request_pkt(PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	uint8_t			*ppkt = pdata, *ppkt_end, *sptr = ppkt, tdstype;
	uint32_t 		pktlen = hdr.datalen_, ppkt_len = pktlen, bytes_left;
	uint16_t 		tdslen, ntds = 0;
	int 			ret;
	auto			& common = svcsess_.common_;

	ppkt_end = sptr + ppkt_len;

	if (gy_unlikely(sybstat_.skip_till_nextreq == 1)) sybstat_.skip_till_nextreq = 0;

	if (gy_unlikely(sybstat_.skip_to_req_after_resp == 1)) {
		gstats[STATSYB_REQ_PKT_SKIP]++;
		return 0;
	}	

	if (gy_unlikely(sybstat_.chk_for_tds_byteorder == 1)) {
		sybstat_.chk_for_tds_byteorder = 2;
		sybstat_.skip_to_req_after_resp = 1;	
		
		gstats[STATSYB_REQ_PKT_SKIP]++;
		return 0;
	}

	if ((sybstat_.drop_seen == 1) || common.clidroptype_ == DT_DROP_SEEN || common.serdroptype_ == DT_DROP_SEEN) {
		sybstat_.drop_seen = 1;
		sybstat_.drop_req_seen |= (common.clidroptype_ == DT_DROP_SEEN);
		sybstat_.drop_resp_seen |= (common.serdroptype_ == DT_DROP_SEEN);

		if (gy_unlikely(sybstat_.chk_for_tds_byteorder == 2)) {
			sybstat_.skip_to_req_after_resp = 1;	
		
			gstats[STATSYB_REQ_PKT_SKIP]++;
			return 0;
		}

		ret = handle_drop_req_pkt(sptr, ppkt_len);
		if (ret < 0) {
			gstats[STATSYB_REQ_PKT_SKIP]++;
			return ret;
		}	
		else if (ret > 0) { /* Skip this packet */
			gstats[STATSYB_REQ_PKT_SKIP]++;
			return 0;
		}	
	}

	sybstat_.last_dir = DirPacket::DirInbound;

	do {
		if (sybstat_.pcap_req_frag) {
			tdslen = 0;
			bytes_left = 0;

			ret = handle_prev_req_frag(ppkt, pktlen, &bytes_left);
			if (gy_unlikely(ret < 0)) {
				return ret;
			}	
			else if (ret > 0) {
				if (ntds == 0) {
					tran_.update_req_stats(common.tlastpkt_usec_, hdr.datalen_);
				}

				return 0; /* Still Fragmented */
			}	

			ret = handle_pcap_tds_req(pReqFragBuf, 1 /* is_frag_buf */, 1, hdr);
			if (ret < 0)
				return ret;

			/*
			 * Now check if other TDS frags present
			 */
			if (bytes_left > 0) {
				if (gy_unlikely((int)bytes_left > (int)pktlen))
					return -1;

				sptr = ppkt + pktlen - bytes_left;
				ppkt_len = bytes_left;
				ntds++;
			} 
			else
				return 0;
		}

		if (gy_unlikely(ppkt_len < 8)) {
			/* TDS Header Fragmentation */
			memcpy(pReqFragBuf, sptr, ppkt_len);

			sybstat_.frag_req_nleft = 0;
			sybstat_.frag_req_nparsed = ppkt_len;

			sybstat_.pcap_req_frag = 1;

			return 0;
		}

		SYB_GET_TDS_LEN(sptr + 2, tdslen);
		SYB_GET_TDS_TYPE(sptr, tdstype);

		if (tdslen > ppkt_len) {
			/* Fragmented */

			memcpy(pReqFragBuf, sptr, 8);

			sybstat_.frag_req_nleft = tdslen - ppkt_len;
			sybstat_.frag_req_nparsed = ppkt_len;

			sybstat_.pcap_req_frag = 1;

			sybstat_.ign_req_frag = is_tds_of_interest(tdstype, DirPacket::DirInbound);

			if ((sybstat_.ign_req_frag == SYB_TDS_PARSE) && ppkt_len >= 8)
				memcpy(pReqFragBuf + 8, sptr + 8, ppkt_len - 8);

			if (ntds == 0) {
				tran_.update_req_stats(common.tlastpkt_usec_, hdr.datalen_);

				if (sybstat_.nbytes_cur_req == 0L) {
					tran_.reqlen_ = hdr.datalen_; 
				}
			}

			return 0;
		}

		sybstat_.frag_req_nleft = 0;
		sybstat_.frag_req_nparsed = 0;
		sybstat_.pcap_req_frag = 0;

		ret = handle_pcap_tds_req(sptr, 0 /* is_frag_buf */, ++ntds, hdr);
		if (ret < 0)
			return ret;

		sptr += tdslen;
		ppkt_len -= tdslen;

	} while (sptr < ppkt_end);	

	return 0;
}	

int SYBASE_ASE_SESSINFO::handle_response_pkt(PARSE_PKT_HDR & hdr, uint8_t *pdata)
{
	uint8_t 		*ppkt = pdata, *sptr = ppkt, *ppkt_end, tdstype;
	uint32_t 		pktlen = hdr.datalen_, bytes_left, ppkt_len = pktlen;
	uint16_t 		tdslen, ntds = 0;
	int 			ret;
	auto			& common = svcsess_.common_;

	ppkt_end = sptr + ppkt_len;

	sybstat_.last_dir = DirPacket::DirOutbound;

	if (gy_unlikely(sybstat_.skip_till_nextreq == 1)) {
		new_request(tran_.treq_usec_);	
		gstats[STATSYB_RESP_PKT_SKIP]++;
		return 0;
	}

	if (gy_unlikely(sybstat_.chk_for_tds_byteorder == 1)) {	
		new_request(tran_.treq_usec_);	
		gstats[STATSYB_RESP_PKT_SKIP]++;
		return 0;
	}

	if ((sybstat_.drop_seen) || common.clidroptype_ == DT_DROP_SEEN || common.serdroptype_ == DT_DROP_SEEN) {
		sybstat_.drop_seen = 1;
		sybstat_.drop_req_seen |= (common.clidroptype_ == DT_DROP_SEEN);
		sybstat_.drop_resp_seen |= (common.serdroptype_ == DT_DROP_SEEN);

		ret = handle_drop_resp_pkt(sptr, ppkt_len);
		new_request(tran_.treq_usec_);	
		if (ret < 0) {
			gstats[STATSYB_RESP_PKT_SKIP]++;
			return ret;
		}	
		else if (ret > 0) {
			gstats[STATSYB_RESP_PKT_SKIP]++;
			return 0;
		}	
	}

	if (gy_unlikely(sybstat_.skip_to_req_after_resp == 1)) {
		/*
		 * We check if this pcap packet is an End of Response packet.
		 */ 
		ret = handle_drop_pcap_resp_eom(sptr, ppkt_len);
		new_request(tran_.treq_usec_);	

		gstats[STATSYB_RESP_PKT_SKIP]++;

		if (ret < 0)
			return ret;

		return 0;
	}

	do {
		if (sybstat_.pcap_resp_frag) {
			tdslen = 0;
			bytes_left = 0;

			ret = handle_prev_resp_frag(ppkt, pktlen, &bytes_left);
			if (gy_unlikely(ret < 0))
				return ret;
			else if (ret > 0)
				return 0; /* Still Fragmented */

			ret = handle_pcap_tds_resp(pResFragBuf, 1 /* is_frag_buf */, 1, hdr);
			if (ret < 0)
				return ret;
			/*
			 * Now check if other TDS frags present
			 */
			if (bytes_left > 0) {
				if (gy_unlikely((int)bytes_left > (int)pktlen))
					return -1;

				sptr = ppkt + pktlen - bytes_left;
				ppkt_len = bytes_left;
				ntds++;
			} 
			else
				return 0;
		}

		if (gy_unlikely(ppkt_len < 8)) {
			/* TDS Header Fragmentation */
			memcpy(pResFragBuf, sptr, ppkt_len);

			sybstat_.frag_resp_nleft = 0;
			sybstat_.frag_resp_nparsed = ppkt_len;

			sybstat_.pcap_resp_frag = 1;

			return 0;
		}

		SYB_GET_TDS_LEN(sptr + 2, tdslen);
		SYB_GET_TDS_TYPE(sptr, tdstype);

		if (tdslen > ppkt_len) {
			/* Fragmented */

			memcpy(pResFragBuf, sptr, 8);

			sybstat_.frag_resp_nleft = tdslen - ppkt_len;
			sybstat_.frag_resp_nparsed = ppkt_len;

			sybstat_.pcap_resp_frag = 1;

			sybstat_.ign_resp_frag = is_tds_of_interest(tdstype, DirPacket::DirOutbound);

			if ((sybstat_.ign_resp_frag == SYB_TDS_PARSE) && ppkt_len >= 8)
				memcpy(pResFragBuf + 8, sptr + 8, ppkt_len - 8);

			if (ntds == 0) {
				tran_.update_resp_stats(common.tlastpkt_usec_, hdr.datalen_);
			}

			return 0;
		}

		sybstat_.frag_resp_nleft = 0;
		sybstat_.frag_resp_nparsed = 0;
		sybstat_.pcap_resp_frag = 0;

		ret = handle_pcap_tds_resp(sptr, 0 /* is_frag_buf */, ++ntds, hdr);
		if (ret < 0)
			return ret;

		sptr += tdslen;
		ppkt_len -= tdslen;

	} while (sptr < ppkt_end);

	return 0;
}	

void SYBASE_ASE_SESSINFO::handle_session_end(PARSE_PKT_HDR & hdr)
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
	if (tran_.reqlen_ && tdstrbuf_.size() > 0 && (!(sybstat_.drop_seen || common.clidroptype_ == DT_DROP_SEEN || common.serdroptype_ == DT_DROP_SEEN))) {
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
		tran_.reslen_ = 0;
		request_done();
	}	

	/*
	 * Send logout request
	 */
	new_request();

	tdstrbuf_ << "logout"sv;
	tran_.tupd_usec_ = common.tlastpkt_usec_;
	tran_.reqlen_ = 1;
	tran_.reslen_ = 1;
	tran_.tres_usec_ = common.tlastpkt_usec_;

	request_done();
}	

void SYBASE_ASE_SESSINFO::handle_ssl_change(PARSE_PKT_HDR & hdr, uint8_t *pdata)
{

}	


bool SYBASE_ASE_SESSINFO::print_req() noexcept
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

		if (tdstat_.dbbuf_.size() && ustrbuf.bytes_left() >= sizeof(PARSE_FIELD_LEN) + tdstat_.dbbuf_.size() + 1) {
			next++;
			ustrbuf << PARSE_FIELD_LEN(EFIELD_DBNAME, tdstat_.dbbuf_.size() + 1) << std::string_view(tdstat_.dbbuf_.data(), tdstat_.dbbuf_.size() + 1);
		}	

		bool			iserr = !!ptran->errorcode_;

		if (iserr) {
			if (tdstat_.errorbuf_.size() && ustrbuf.bytes_left() >= sizeof(PARSE_FIELD_LEN) + tdstat_.errorbuf_.size() + 1) {
				next++;
				ustrbuf << PARSE_FIELD_LEN(EFIELD_ERRTXT, tdstat_.errorbuf_.size() + 1) << std::string_view(tdstat_.errorbuf_.data(), tdstat_.errorbuf_.size() + 1);
			}

			if (tdstat_.errclass_ && ustrbuf.bytes_left() >= sizeof(PARSE_FIELD_LEN) + sizeof(tdstat_.errclass_)) {
				next++;
				ustrbuf << PARSE_FIELD_LEN(EFIELD_ERRCLASS, sizeof(tdstat_.errclass_)) << (decltype(tdstat_.errclass_))tdstat_.errclass_;
			}
		}	

		if (tdstat_.dyn_prep_reqnum_ && tdstat_.dyn_prep_time_t_ && ustrbuf.bytes_left() >= 2 * sizeof(PARSE_FIELD_LEN) + 2 * sizeof(uint64_t)) {
			next++;
			ustrbuf << PARSE_FIELD_LEN(EFIELD_PREP_REQNUM, sizeof(uint64_t)) << tdstat_.dyn_prep_reqnum_;

			next++;
			ustrbuf << PARSE_FIELD_LEN(EFIELD_PREP_REQTIME, sizeof(time_t)) << tdstat_.dyn_prep_time_t_;
		}

		if (tdstat_.spid_ && ustrbuf.bytes_left() >= sizeof(PARSE_FIELD_LEN) + sizeof(tdstat_.spid_)) {
			next++;
			ustrbuf << PARSE_FIELD_LEN(EFIELD_SESSID, sizeof(tdstat_.spid_)) << tdstat_.spid_;
		}

		if (tdstat_.hostpid_ && ustrbuf.bytes_left() >= sizeof(PARSE_FIELD_LEN) + sizeof(tdstat_.hostpid_)) {
			next++;
			ustrbuf << PARSE_FIELD_LEN(EFIELD_HOSTPID, sizeof(tdstat_.hostpid_)) << tdstat_.hostpid_;
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

void SYBASE_ASE_SESSINFO::print_stats(STR_WR_BUF & strbuf, time_t tcur, time_t tlast) noexcept
{
	uint64_t			diffstats[STATSYB_MAX];

	std::memcpy(diffstats, gstats, sizeof(gstats));

	strbuf << "\nSybase ASE Interval Stats for "sv << tcur - tlast << " sec : "sv;
	
	for (int i = 0; i < (int)STATSYB_MAX; ++i) {
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

	strbuf << "Sybase ASE Cumulative Stats : "sv;
	
	for (int i = 0; i < (int)STATSYB_MAX; ++i) {
		if (gstats[i] > 0) {
			strbuf << ' ' << gstatstr[i] << ' ' << gstats[i] << ',';
		}	
	}	

	strbuf << " Total Requests "sv << gtotal_queries << ", Overall Avg Response usec "sv << gtotal_resp/NUM_OR_1(gtotal_queries);

	strbuf << "\n\n"sv;
}	


} // namespace gyeeta

