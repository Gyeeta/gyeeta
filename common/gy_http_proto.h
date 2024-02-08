//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"
#include			"gy_misc.h"

namespace gyeeta {

class API_PARSE_HDLR;
struct PARSE_PKT_HDR;
class SVC_SESSION;
class HTTP1_SESSINFO;

class HTTP1_PROTO 
{
public :
	enum METHODS_E : uint8_t 
	{
		METHOD_GET,
		METHOD_POST,
		METHOD_PUT,
		METHOD_OPTIONS,
		METHOD_HEAD,
		METHOD_DELETE,
		METHOD_CONNECT,
		METHOD_TRACE,

		METHOD_UNKNOWN,
	};

	static constexpr std::string_view http_methods[METHOD_UNKNOWN] = {
		"GET ", "POST ", "PUT ", "OPTIONS ", "HEAD ", "DELETE ", "CONNECT ", "TRACE ",
	};	

	static_assert(GY_ARRAY_SIZE(http_methods) == METHOD_UNKNOWN);

	static constexpr uint32_t		MIN_HTTP_FRAME = 18, MAX_METHOD_LEN = 8, MIN_STATUS_LEN = 19;

	static constexpr std::string_view 	chunked_end_bytes = "\x0d\x0a\x30\x0d\x0a\x0d\x0a";	// If no trailer

	static METHODS_E get_req_method(const uint8_t *pdata, uint32_t len) noexcept
	{
		if (len < MAX_METHOD_LEN) {
			return METHOD_UNKNOWN;
		}	
		
		switch (*pdata) {

		case 'G' :
			if (0 == memcmp(pdata, "GET ", 4)) {
				return METHOD_GET;
			}	
			return METHOD_UNKNOWN;

		case 'P' :
			if (0 == memcmp(pdata, "POST ", 5)) {
				return METHOD_POST;
			}	
			else if (0 == memcmp(pdata, "PUT ", 4)) {
				return METHOD_PUT;
			}	
			return METHOD_UNKNOWN;

		case 'D' :
			if (0 == memcmp(pdata, "DELETE ", 7)) {
				return METHOD_DELETE;
			}	
			return METHOD_UNKNOWN;

		case 'O' :
			if (0 == memcmp(pdata, "OPTIONS ", 8)) {
				return METHOD_OPTIONS;
			}	
			return METHOD_UNKNOWN;

		case 'H' :
			if (0 == memcmp(pdata, "HEAD ", 5)) {
				return METHOD_HEAD;
			}	
			return METHOD_UNKNOWN;

		case 'C' :
			if (0 == memcmp(pdata, "CONNECT ", 8)) {
				return METHOD_CONNECT;
			}	
			return METHOD_UNKNOWN;

		case 'T' :
			if (0 == memcmp(pdata, "TRACE ", 6)) {
				return METHOD_TRACE;
			}	
			return METHOD_UNKNOWN;

		default :
			return METHOD_UNKNOWN;
		}
	}

	static tribool is_valid_req(const uint8_t *pdata, uint32_t caplen, uint32_t wirelen, bool is_init = false) noexcept
	{
		auto			method = get_req_method(pdata, caplen);
		
		if (method == METHOD_UNKNOWN || caplen < MIN_HTTP_FRAME) {
			return false;
		}	

		auto			pend = pdata + caplen;	
		
		const uint8_t		*ptmp = (const uint8_t *)memchr(pdata + 4, '\r', caplen - 4);
		if (!ptmp) {
			if (caplen < wirelen && caplen < 1024) {
				// Truncated req
				return indeterminate;
			}				
			return false;
		}	

		if (ptmp[1] != '\n') {
			return false;
		}	

		ptmp -= GY_CONST_STRLEN(" HTTP/1.1");

		if (ptmp <= pdata) {
			return false;
		}	

		if (memcmp(ptmp, " HTTP/1.", GY_CONST_STRLEN(" HTTP/1."))) {
			return false;
		}	

		const uint8_t		*phttp = ptmp + 1;

		if (phttp > pdata + 2048) {
			return false;
		}

		if ((phttp + 9 < pend) && (phttp[7] == '1' || phttp[7] == '0') && phttp[8] == '\r' && phttp[9] == '\n') {
			return true;
		}	

		return false;
	}

	static bool is_valid_resp(const uint8_t *pdata, uint32_t len, bool is_init = false) noexcept
	{
		bool			is_cli_err, is_ser_err;

		return is_status_response(pdata, len, is_cli_err, is_ser_err);
	}	

	static tribool is_valid_req_resp(const uint8_t *pdata, uint32_t caplen, uint32_t wirelen, DirPacket dir, bool is_init = false) noexcept
	{
		if (dir == DirPacket::DirInbound) {
			return is_valid_req(pdata, caplen, wirelen, is_init);
		}	

		return is_valid_resp(pdata, caplen, is_init);
	}	
	
	static bool is_status_response(const uint8_t *pdata, uint32_t len, bool & is_cli_err, bool & is_ser_err) noexcept
	{
		if (len < MIN_STATUS_LEN) {
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

		const uint8_t			* const pend = pdata + len, *ptmp = pdata + 9;

		while (ptmp < pend && *ptmp == ' ') ptmp++;

		if (ptmp + 5 > pend) {
			return false;
		}

		const uint8_t			sbyte = *ptmp;

		if (!((sbyte >= '1' && sbyte <= '9') && (ptmp[1] >= '0' && ptmp[1] <= '9') && (ptmp[2] >= '0' && ptmp[2] <= '9') && (ptmp[3] == ' ' || ptmp[3] == '\r'))) {
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

	// Returns {status, pointer to first byte after status} : Returns {0, nullptr} on error
	static std::pair<int, const uint8_t *> get_status_response(const uint8_t *pdata, uint32_t len) noexcept
	{
		if (len < MIN_STATUS_LEN) {
			return {};
		}	

		if (memcmp(pdata, "HTTP/1.", 7)) {
			return {};
		}	
		
		if (!(pdata[7] == '1' || pdata[7] == '0')) {
			return {};
		}	

		if (pdata[8] != ' ') {
			return {};
		}	

		const uint8_t			* const pend = pdata + len, *ptmp = pdata + 9;

		while (ptmp < pend && *ptmp == ' ') ptmp++;

		if (ptmp + 5 > pend) {
			return {};
		}

		const uint8_t			sbyte1 = *ptmp, sbyte2 = ptmp[1], sbyte3 = ptmp[2];
		int				ret;

		if (!((sbyte1 >= '1' && sbyte1 <= '9') && (sbyte2 >= '0' && sbyte2 <= '9') && (sbyte3 >= '0' && sbyte3 <= '9') && (ptmp[3] == ' ' || ptmp[3] == '\r'))) {
			return {};
		}	

		ret = (sbyte1 - '0') * 100 + (sbyte2 - '0') * 10 + (sbyte3 - '0');
		
		return {ret, ptmp + 3};
	}

	static bool is_resp_body_valid(int status, METHODS_E req_method) noexcept
	{
		if (req_method == METHOD_HEAD) return false;

		if (status >= 100 && status < 200) return false;

		if (status == 204 /* No Content */ || status == 304 /* Not Modified */) return false;

		if (req_method == METHOD_CONNECT && status >= 200 && status < 300) return false;

		return true;
	}	

	static bool is_error_response(int status) noexcept
	{
		return status >= 400;
	}	

	// Returns { true if end detected, pend the first byte after the end} or {false, nullptr} if no end detected
	static std::pair<bool, const uint8_t *> is_req_resp_end_heuristic(const uint8_t *pdata, int pktlen, DirPacket dir) noexcept
	{
		const uint8_t			*pend = pdata + pktlen, *ptmp;
		auto				isvalid = is_valid_req_resp(pdata, pktlen, pktlen, dir);
		
		if (isvalid == false) {
			/*
			 * Missed the start of the msg...
			 */
			if (pktlen < 8 || pktlen > 1400) {
				return {};
			}

			ptmp = pend - chunked_end_bytes.size();
			
			// Chunked 
			if (0 == memcmp(ptmp, chunked_end_bytes.data(), chunked_end_bytes.size())) {
				return {true, ptmp + chunked_end_bytes.size()};
			}	
			
			return {};
		}	
		else if (isvalid == true) {
			if (ptmp = (const uint8_t *)memmem(pdata, std::min<size_t>(pktlen, 1024), "Transfer-Encoding:", sizeof("Transfer-Encoding:") - 1); ptmp) {
				if (pend - ptmp > 20 && memmem(ptmp, std::min<size_t>(pend - ptmp, 100), "chunked", sizeof("chunked") - 1)) {
					ptmp = pend - chunked_end_bytes.size();
					
					// Chunked 
					if (0 == memcmp(ptmp, chunked_end_bytes.data(), chunked_end_bytes.size())) {
						return {true, ptmp + chunked_end_bytes.size()};
					}
				}	

				return {};
			}
			if (ptmp = (const uint8_t *)memmem(pdata, std::min<size_t>(pktlen, 1024), "Content-Length:", sizeof("Content-Length:") - 1); ptmp) {
				ptmp += sizeof("Content-Length:") - 1;

				if (ptmp + 3 < pend) {
					char				tbuf[32] = {};
					ssize_t				colen = 0;
					bool				bret;

					std::memcpy(tbuf, ptmp, std::min<size_t>(pend - ptmp, 20));

					bret = string_to_number(tbuf, colen, nullptr, 10);

					if (!bret || colen > pend - ptmp || colen < 0) {
						return {};
					}	
					
					if (0 == memcmp(pend - colen - 4, "\r\n\r\n", 4)) {
						return {true, pend};
					}	
				}	

				return {};
			}
			
			if (0 == memcmp(pend - 4, "\r\n\r\n", 4) && gy_isprint_ascii(pend[-5])) {
				return {true, pend};
			}	
		}

		return {};
	}	

	


	API_PARSE_HDLR				& apihdlr_;
	uint32_t				api_max_len_;

	HTTP1_PROTO(API_PARSE_HDLR & apihdlr, uint32_t api_max_len);

	~HTTP1_PROTO() noexcept;
	
	void handle_request_pkt(HTTP1_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr, uint8_t *pdata);

	void handle_response_pkt(HTTP1_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr, uint8_t *pdata);

	void handle_session_end(HTTP1_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr);

	void handle_ssl_change(HTTP1_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr, uint8_t *pdata);

	std::pair<HTTP1_SESSINFO *, void *> alloc_sess(SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr);

	void destroy(HTTP1_SESSINFO *pobj, void *pdata) noexcept;

	static void print_stats(STR_WR_BUF & strbuf, time_t tcur, time_t tlast) noexcept;

	API_PARSE_HDLR & get_api_hdlr() noexcept
	{
		return apihdlr_;
	}

	uint32_t get_api_max_len() const noexcept
	{
		return api_max_len_;
	}	

};

} // namespace gyeeta

