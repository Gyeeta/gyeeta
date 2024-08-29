//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"
#include			"gy_misc.h"

namespace gyeeta {

class API_PARSE_HDLR;
struct PARSE_PKT_HDR;
class SVC_SESSION;
class SYBASE_ASE_SESSINFO;

class SYBASE_ASE_PROTO 
{
public :

	enum SYB_TDS_TYPE_E : uint8_t 
	{
		SYB_TYPE_LANG			= 1,
		SYB_TYPE_LOGIN			= 2,
		SYB_TYPE_RPC			= 3,
		SYB_TYPE_RESPONSE		= 4,
		SYB_TYPE_UNFMT			= 5,
		SYB_TYPE_ATTN			= 6,
		SYB_TYPE_BULK			= 7,
		SYB_TYPE_LC_SETUP		= 8,
		SYB_TYPE_LC_CLOSE		= 9,
		SYB_TYPE_LC_ERROR		= 10,
		SYB_TYPE_LC_PROTACK		= 11,
		SYB_TYPE_ECHO			= 12,
		SYB_TYPE_LOGOUT			= 13,
		SYB_TYPE_ENDPARAM		= 14,
		SYB_TYPE_NORMAL			= 15,
		SYB_TYPE_URGENT			= 16,
		SYB_TYPE_MIGRATE		= 17,
	};


	enum SYB_TOKENS_E : uint8_t
	{
		SYB_TOKEN_ALTCONTROL		= 0xAF,
		SYB_TOKEN_ALTFMT		= 0xA8,
		SYB_TOKEN_ALTNAME		= 0xA7,
		SYB_TOKEN_ALTROW		= 0xD3,
		SYB_TOKEN_CAPABILITY		= 0xE2,
		SYB_TOKEN_COLFMT		= 0xA1,
		SYB_TOKEN_COLFMTOLD		= 0x2A,
		SYB_TOKEN_COLINFO		= 0xA5,
		SYB_TOKEN_COLNAME		= 0xA0,
		SYB_TOKEN_CONTROL		= 0xAE,
		SYB_TOKEN_CURCLOSE		= 0x80,
		SYB_TOKEN_CURDECLARE		= 0x86,
		SYB_TOKEN_CURDECLARE2		= 0x23,
		SYB_TOKEN_CURDECLARE3		= 0x10,
		SYB_TOKEN_CURDELETE		= 0x81,
		SYB_TOKEN_CURFETCH		= 0x82,
		SYB_TOKEN_CURINFO		= 0x83,
		SYB_TOKEN_CURINFO2		= 0x87,
		SYB_TOKEN_CURINFO3		= 0x88,
		SYB_TOKEN_CUROPEN		= 0x84,
		SYB_TOKEN_CURUPDATE		= 0x85,
		SYB_TOKEN_DBRPC			= 0xE6,
		SYB_TOKEN_DBRPC2		= 0xE8,
		SYB_TOKEN_DEBUGCMD		= 0x60,
		SYB_TOKEN_DONE			= 0xFD,
		SYB_TOKEN_DONEINPROC		= 0xFF,
		SYB_TOKEN_DONEPROC		= 0xFE,
		SYB_TOKEN_DYNAMIC		= 0xE7,
		SYB_TOKEN_DYNAMIC2		= 0x62,
		SYB_TOKEN_EED			= 0xE5,
		SYB_TOKEN_ENVCHANGE		= 0xE3,
		SYB_TOKEN_ERROR			= 0xAA,
		SYB_TOKEN_EVENTNOTICE		= 0xA2,
		SYB_TOKEN_INFO			= 0xAB,
		SYB_TOKEN_KEY			= 0xCA,
		SYB_TOKEN_LANGUAGE		= 0x21,
		SYB_TOKEN_LOGINACK		= 0xAD,
		SYB_TOKEN_LOGOUT		= 0x71,
		SYB_TOKEN_MSG			= 0x65,
		SYB_TOKEN_OFFSET		= 0x78,
		SYB_TOKEN_OPTIONCMD		= 0xA6,
		SYB_TOKEN_OPTIONCMD2		= 0x63,
		SYB_TOKEN_ORDERBY		= 0xA9,
		SYB_TOKEN_ORDERBY2		= 0x22,
		SYB_TOKEN_PARAMFMT		= 0xEC,
		SYB_TOKEN_PARAMFMT2		= 0x20,
		SYB_TOKEN_PARAMS		= 0xD7,
		SYB_TOKEN_PROCID		= 0x7C,
		SYB_TOKEN_RETURNSTATUS		= 0x79,
		SYB_TOKEN_RETURNVALUE		= 0xAC,
		SYB_TOKEN_ROW			= 0xD1,
		SYB_TOKEN_ROWFMT		= 0xEE,
		SYB_TOKEN_ROWFMT2		= 0x61,
		SYB_TOKEN_RPC			= 0xE0,
		SYB_TOKEN_TABNAME		= 0xA4,
	};



	static tribool is_valid_req(const uint8_t *pdata, uint32_t caplen, uint32_t wirelen, bool is_init = false, LAST_PKT_SNIPPET *plastsnippet = nullptr) noexcept
	{
		const uint8_t			*ptmp = pdata;
		uint16_t			tlen;
		uint8_t				c, tdstype, status;
		bool				is_eom;

		if (is_init) {
			if (caplen < 512 || caplen > 2048) {
				return false;
			}	

			if ((*pdata != SYB_TYPE_LOGIN) || (0 != (pdata[1] & 0xfe)) || pdata[4] || pdata[5] || pdata[6] || pdata[7]) {
				return false;
			}	
			
			tlen = unaligned_read_be16(pdata + 2);

			if (tlen > caplen || tlen < 512) {
				return false;
			}	
			
			if (pdata[1] == 1 && tlen != caplen) {
				return false;
			}

			if (pdata[1] == 0) {
				if (caplen > tlen + 8u) {
					ptmp = pdata + tlen;

					if ((*ptmp != 2) || (1 != ptmp[1]) || ptmp[4] || ptmp[5] || ptmp[6] || ptmp[7]) {
						return false;
					}	

					uint16_t			tlen2 = unaligned_read_be16(ptmp + 2);

					if (tlen2 > 2048) {
						return false;
					}	

				}	
			}	

			if ((!gy_isalpha_ascii(ptmp[8])) || (!gy_isalnum_ascii(ptmp[9])) || (!gy_isalnum_ascii(ptmp[10]))) {
				return false;
			}

			if (ptmp[32] || ptmp[33] || ptmp[34]) {
				return false;
			}	
			
			c = ptmp[38];

			if (c > 30 || c < 2) {
				return false;
			}	
			
			if (ptmp[8 + c]) {
				return false;
			}	

			ptmp = pdata + 8 + 458;
			
			c = *ptmp;

			if (c != 5 && c != 4) {
				return false;
			}

			return true;
		}

		if (caplen < 10) {
			return false;
		}	

		tdstype = *pdata;
		status = pdata[1];
		is_eom = status & 1;

		if ((tdstype > SYB_TYPE_MIGRATE) || (status & 0xF0) || pdata[4] || pdata[5] || pdata[6] || pdata[7]) {
			return false;
		}	
		
		tlen = unaligned_read_be16(pdata + 2);

		if (tlen < 8) {
			return false;
		}	

		if (is_eom && caplen > tlen) {
			return false;
		}	
		else if (!is_eom && tlen < 512) {
			return false;
		}	

		switch (tdstype) {
			case SYB_TYPE_LANG:
			case SYB_TYPE_RPC:
			case SYB_TYPE_NORMAL:
			case SYB_TYPE_ATTN:
				break;

			case SYB_TYPE_BULK:		// Keep indeterminate
			default:
				return indeterminate;
		}

		c = pdata[8];

		if (c < SYB_TOKEN_CURDECLARE3) {
			return false;
		}	

		switch (c) {
			case SYB_TOKEN_CURCLOSE :
			case SYB_TOKEN_CURDECLARE :
			case SYB_TOKEN_CURDECLARE2 :
			case SYB_TOKEN_CURDECLARE3 :
			case SYB_TOKEN_CURDELETE :
			case SYB_TOKEN_CURFETCH :
			case SYB_TOKEN_CURINFO :
			case SYB_TOKEN_CURINFO2 :
			case SYB_TOKEN_CURINFO3 :
			case SYB_TOKEN_CUROPEN :
			case SYB_TOKEN_CURUPDATE :
			case SYB_TOKEN_DBRPC :
			case SYB_TOKEN_DBRPC2 :
			case SYB_TOKEN_DEBUGCMD :
			case SYB_TOKEN_DYNAMIC :
			case SYB_TOKEN_DYNAMIC2 :
			case SYB_TOKEN_ENVCHANGE :
			case SYB_TOKEN_LANGUAGE :
			case SYB_TOKEN_MSG :
			case SYB_TOKEN_PARAMFMT :
			case SYB_TOKEN_PARAMFMT2 :
			case SYB_TOKEN_PARAMS :
			case SYB_TOKEN_RPC :
				
				if (caplen < tlen) {
					return indeterminate;
				}	
				return true;

			case SYB_TOKEN_CAPABILITY :
			case SYB_TOKEN_DONE :
			case SYB_TOKEN_DONEPROC :
			case SYB_TOKEN_DONEINPROC :
			case SYB_TOKEN_EED :
			case SYB_TOKEN_INFO :
			case SYB_TOKEN_ERROR :
			case SYB_TOKEN_LOGINACK :
			case SYB_TOKEN_RETURNSTATUS :
			case SYB_TOKEN_RETURNVALUE :
			case SYB_TOKEN_ROW :
			case SYB_TOKEN_ROWFMT :
			case SYB_TOKEN_ROWFMT2 :
			case SYB_TOKEN_OFFSET :
				
				return false;

			default :
				return indeterminate;
		}	
	}	

	static tribool is_valid_resp(const uint8_t *pdata, uint32_t caplen, uint32_t wirelen, bool is_init = false, LAST_PKT_SNIPPET *plastsnippet = nullptr) noexcept
	{
		const uint8_t			*ptmp = pdata, *ppkt_end = pdata + caplen, *ptmp_old;
		uint16_t			tlen, pktlen = (uint16_t)caplen, tokenlen;
		uint8_t				c, tdstype, status;
		bool				is_eom;

		if (is_init) {
			if (caplen < 200 || caplen > 2048) {
				return false;
			}	

			if ((*pdata != SYB_TYPE_NORMAL && *pdata != SYB_TYPE_RESPONSE) || (0 != (pdata[1] & 0xfe)) || pdata[4] || pdata[5] || pdata[6] || pdata[7]) {
				return false;
			}	
			
			tlen = unaligned_read_be16(pdata + 2);

			if (tlen != caplen) {
				return false;
			}	
			
			ptmp = ppkt_end - 9;

			if (*ptmp != SYB_TOKEN_DONE || (ptmp[1] & 0xFD) || (ptmp[2] & 0xFD) || (ptmp[3] & 0xFD) || (ptmp[4] & 0xFD)) {
				return false;
			}	

			ptmp = pdata + 8;
			pktlen -= 8;

			/*
			 * Now scan the differet tokens.
			 * Login Response can contain Env Change, Error, Info, Done Tokens.
			 */
			while ((ptmp < ppkt_end) && (ptmp > pdata)) {
				c = *ptmp;
				ptmp_old = ptmp;

				switch (c) {
					case SYB_TOKEN_ENVCHANGE :
					case SYB_TOKEN_EED :
					case SYB_TOKEN_ERROR :
					case SYB_TOKEN_INFO :
					case SYB_TOKEN_LOGINACK :
					case SYB_TOKEN_CAPABILITY :

						if (ptmp + 3 >= ppkt_end) {
							return false;
						}	
						
						// Assume both client and server have same Byteorder as Gyeeta
						tokenlen = unaligned_read_16(ptmp + 1);
						
						if (ptmp + tokenlen + 3 > ppkt_end) {
							return false;
						}	
						
						if (c == SYB_TOKEN_LOGINACK) {
							return (ptmp[4] == 5);
						}	

						ptmp += tokenlen + 3;
						pktlen -= (tokenlen + 3);

						break;

					case SYB_TOKEN_MSG :

						if (ptmp + 3 >= ppkt_end) {
							return false;
						}	
						
						tokenlen = *(ptmp + 1);
						
						if (ptmp + tokenlen + 2 > ppkt_end) {
							return false;
						}	
						
						ptmp += tokenlen + 2;
						pktlen -= (tokenlen + 2);

						break;

					default :
						return false;
				}

				if (ptmp == ptmp_old) {
					return false;
				}	
			}	
			
			return false;
		}

		if (caplen < 10) {
			return false;
		}	

		tdstype = *pdata;
		status = pdata[1];
		is_eom = status & 1;

		if ((status & 0xF0) || pdata[4] || pdata[5] || pdata[6] || pdata[7]) {
			return false;
		}	
		
		switch (tdstype) {
			case SYB_TYPE_RESPONSE:
			case SYB_TYPE_ATTN:
				break;

			case SYB_TYPE_BULK:		// Keep indeterminate
				return indeterminate;

			default :
				return false;
		}

		tlen = unaligned_read_be16(pdata + 2);

		if (tlen < 8) {
			return false;
		}	

		if (is_eom && caplen > tlen) {
			return false;
		}	
		else if (!is_eom && tlen < 512) {
			return false;
		}	

		c = pdata[8];

		if (c < SYB_TOKEN_CURDECLARE3) {
			return false;
		}	

		if (is_eom && caplen == tlen) {
			ptmp = ppkt_end - 9;

			if ((*ptmp != SYB_TOKEN_DONE && *ptmp != SYB_TOKEN_DONEPROC) || (ptmp[1] & 0xFD) || (ptmp[2] & 0xFD) || (ptmp[3] & 0xFD) || (ptmp[4] & 0xFD)) {
				return false;
			}	
		}	

		switch (c) {
			case SYB_TOKEN_CURCLOSE :
			case SYB_TOKEN_CURDECLARE :
			case SYB_TOKEN_CURDECLARE2 :
			case SYB_TOKEN_CURDECLARE3 :
			case SYB_TOKEN_CURDELETE :
			case SYB_TOKEN_CURFETCH :
			case SYB_TOKEN_CUROPEN :
			case SYB_TOKEN_CURUPDATE :
			case SYB_TOKEN_DBRPC :
			case SYB_TOKEN_DBRPC2 :
			case SYB_TOKEN_RPC :
				
				return false;

			case SYB_TOKEN_DONE :
			case SYB_TOKEN_DONEPROC :
			case SYB_TOKEN_DONEINPROC :
			case SYB_TOKEN_EED :
			case SYB_TOKEN_INFO :
			case SYB_TOKEN_ERROR :
			case SYB_TOKEN_RETURNSTATUS :
			case SYB_TOKEN_RETURNVALUE :
			case SYB_TOKEN_ROW :
			case SYB_TOKEN_ROWFMT :
			case SYB_TOKEN_ROWFMT2 :
			case SYB_TOKEN_OFFSET :
			case SYB_TOKEN_CURINFO :
			case SYB_TOKEN_CURINFO2 :
			case SYB_TOKEN_CURINFO3 :
			case SYB_TOKEN_DYNAMIC :
			case SYB_TOKEN_DYNAMIC2 :
			case SYB_TOKEN_ENVCHANGE :
			case SYB_TOKEN_MSG :
			case SYB_TOKEN_PARAMFMT :
			case SYB_TOKEN_PARAMFMT2 :
			case SYB_TOKEN_PARAMS :
				
				if (caplen < tlen || !is_eom) {
					return indeterminate;
				}	
				return true;

			default :
				return indeterminate;
		}	
	}	

	static tribool is_valid_req_resp(const uint8_t *pdata, uint32_t caplen, uint32_t wirelen, DirPacket dir, bool is_init = false, LAST_PKT_SNIPPET *plastsnippet = nullptr) noexcept
	{
		if (dir == DirPacket::DirInbound) {
			return is_valid_req(pdata, caplen, wirelen, is_init, plastsnippet);
		}	

		return is_valid_resp(pdata, caplen, wirelen, is_init, plastsnippet);
	}	


	API_PARSE_HDLR				& apihdlr_;
	uint32_t				api_max_len_;
	uint32_t				max_syb_req_token_;
	uint32_t				max_syb_resp_token_;

	SYBASE_ASE_PROTO(API_PARSE_HDLR & apihdlr, uint32_t api_max_len);

	~SYBASE_ASE_PROTO() noexcept;
	
	SYBASE_ASE_PROTO(const SYBASE_ASE_PROTO & other) noexcept		= default;

	SYBASE_ASE_PROTO & operator=(const SYBASE_ASE_PROTO & other) noexcept	= default;

	void handle_request_pkt(SYBASE_ASE_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr, uint8_t *pdata);

	void handle_response_pkt(SYBASE_ASE_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr, uint8_t *pdata);

	void handle_session_end(SYBASE_ASE_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr);

	void handle_ssl_change(SYBASE_ASE_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr, uint8_t *pdata);

	std::pair<SYBASE_ASE_SESSINFO *, void *> alloc_sess(SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr);

	void destroy(SYBASE_ASE_SESSINFO *pobj, void *pdata) noexcept;

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

