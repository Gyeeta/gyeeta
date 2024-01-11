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

		METHOD_UNKNOWN,
	};

	static constexpr std::string_view http_methods_sv[] = {
		"GET ", "POST ", "PUT ", "OPTIONS ", "HEAD ", "DELETE ", "CONNECT ",
	};	

	static_assert(GY_ARRAY_SIZE(http_methods_sv) == METHOD_UNKNOWN);

	static METHODS_E get_req_method(const uint8_t *pdata, uint32_t len) noexcept
	{
		if (len < 18) {
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

		default :
			return METHOD_UNKNOWN;
		}
	}

	static tribool is_valid_req(const uint8_t *pdata, uint32_t caplen, uint32_t wirelen, bool is_init = false) noexcept
	{
		auto			method = get_req_method(pdata, caplen);
		
		if (method == METHOD_UNKNOWN) {
			return false;
		}	

		auto			pend = pdata + caplen;
		const uint8_t		*phttp = (const uint8_t *)memmem(pdata + 4, caplen - 4, "HTTP/1.", 7);

		if (!phttp) {
			if (caplen < wirelen) {
				// Truncated req
				return indeterminate;
			}				
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

		return get_status_response(pdata, len, is_cli_err, is_ser_err);
	}	

	static tribool is_valid_req_resp(const uint8_t *pdata, uint32_t caplen, uint32_t wirelen, DirPacket dir, bool is_init = false) noexcept
	{
		if (dir == DirPacket::DirInbound) {
			return is_valid_req(pdata, caplen, wirelen, is_init);
		}	

		return is_valid_resp(pdata, caplen, is_init);
	}	
	
	static bool get_status_response(const uint8_t *pdata, uint32_t len, bool & is_cli_err, bool & is_ser_err) noexcept
	{
		if (len < 19) {
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

		const uint8_t		sbyte = pdata[9];

		if (!((sbyte >= '1' && sbyte <= '5') && (pdata[10] >= '0' && pdata[10] <= '9') && (pdata[11] >= '0' && pdata[11] <= '9') && pdata[12] == ' ')) {
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

};

} // namespace gyeeta

