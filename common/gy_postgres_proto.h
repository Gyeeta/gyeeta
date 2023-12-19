//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"
#include			"gy_misc.h"

namespace gyeeta {

class postgres_proto 
{
public :
	/*
	 * Refer to https://www.postgresql.org/docs/current/protocol-message-formats.html
	 */
	enum PG_MSG_TYPES_E : char 
	{
		MSG_FB_UNKNOWN 			= 0,

		// Frontend (Request)
		MSG_F_QUERY 			= 'Q',
		MSG_F_CLOSE 			= 'C',
		MSG_F_COPYFAIL 			= 'f',
		MSG_F_PARSE 			= 'P',
		MSG_F_BIND 			= 'B',
		MSG_F_DESCRIBE 			= 'D',
		MSG_F_EXECUTE 			= 'E',
		MSG_F_SYNC 			= 'S',
		MSG_F_FLUSH 			= 'H',
		MSG_F_PASSWD 			= 'p',
		MSG_F_FUNCTION_CALL		= 'F',
		MSG_F_TERMINATE 		= 'X',

		// Dummy Msg Type for Startup
		MSG_F_STARTUP			= '\x07',

		// Backend (Response)
		MSG_B_DATAROW 			= 'D',
		MSG_B_READY_FOR_QUERY 		= 'Z',
		MSG_B_COPYOUT_RESP 		= 'H',
		MSG_B_COPYIN_RESP 		= 'G',
		MSG_B_COPYBOTH_RESP 		= 'W',
		MSG_B_ERROR_RESP 		= 'E',
		MSG_B_CMD_COMPLETE 		= 'C',
		MSG_B_CLOSE_COMPLETE 		= '3',
		MSG_B_PARSE_COMPLETE 		= '1',
		MSG_B_BIND_COMPLETE 		= '2',
		MSG_B_KEYDATA 			= 'K',
		MSG_B_PARAM_DESC 		= 't',
		MSG_B_PARAM_STATUS 		= 'S',
		MSG_B_ROW_DESC 			= 'T',
		MSG_B_PORTAL_SUSPENDED 		= 's',
		MSG_B_EMPTY_RESPONSE 		= 'I',
		MSG_B_AUTH_RESP			= 'R',
		MSG_B_NODATA 			= 'n',
		MSG_B_NOTICE_RESP		= 'N',
		MSG_B_NOTIFY_RESP		= 'A',
		MSG_B_FUNCTION_CALL_RESP	= 'V',
		MSG_B_NEGOTIATE_PROTO		= 'v',

		// Frontend & Backend
		MSG_FB_COPYDATA 		= 'd',
		MSG_FB_COPYDONE 		= 'c',

	};	

	enum : int
	{
		MSG_F_AUTH_START		= 196608,		// 0x00030000
		MSG_F_CANCEL			= 80877102,		// 0x04d2162e
		MSG_F_SSL_REQ			= 80877103,		// 0x04d2162f
		MSG_F_GSSENC_REQ		= 80877104,		// 0x04d21630
	};

	enum PG_AUTH_RESP_E : int
	{
		B_AUTH_SUCCESS			= 0,
		B_AUTH_KERBEROS			= 2,
		B_AUTH_CLEARTEXT_PWD		= 3,
		B_AUTH_MD5_PWD			= 5,
		B_AUTH_GSSAPI			= 7,
		B_AUTH_SSPI			= 9,
		B_AUTH_SASL			= 10,
	};	

	static tribool is_valid_req(const uint8_t *pdata, uint32_t caplen, uint32_t wirelen, bool is_init = false) noexcept
	{
		if (is_init) {
			uint32_t			version, msglen;

			if (caplen < 8) {
				return false;
			}	

			msglen = unaligned_read_be32(pdata);
			if (msglen != caplen) {
				return false;
			}

			version = unaligned_read_be32(pdata + 4);

			if ((version & 0xFFFFFF00) == MSG_F_AUTH_START) {
				if (caplen < 12) {
					return false;
				}	

				int				maxlen = caplen - 8, len;
				const char			*ptmp = (const char *)(pdata + 8);
	
				do {
					if ((0 == strcmp(ptmp, "user")) || (0 == strcmp(ptmp, "database")) || (0 == strcmp(ptmp, "options")) || 
						(0 == strcmp(ptmp, "application_name")) || (0 == strcmp(ptmp, "replication"))) {
						return true;
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
				
				return false;
			}
			else if (version == MSG_F_CANCEL) {
				if (caplen != 16) {
					return false;
				}	

				return true;
			}	
			else if (version == MSG_F_SSL_REQ || version == MSG_F_GSSENC_REQ) {
				if (caplen == 8) {
					return true;
				}

				return false;
			}	
			
			return false;
		}

		if (caplen < 5) {
			return false;
		}	
		
		int				maxlen = caplen, ntkns = 0;
		const char			*pstart = (const char *)pdata;

		do {

			uint32_t			tknlen;
			char				tkn = *pstart;

			tknlen = unaligned_read_be32(pstart + 1);

			if (tknlen < 4) {
				return false;
			}	

			// Not a protocol limit...
			if (tknlen > GY_UP_MB(128)) {
				return false;
			}	

			ntkns++;

			switch (tkn) {

			case MSG_F_QUERY :
			case MSG_F_CLOSE :
			case MSG_F_COPYFAIL :
			case MSG_F_PARSE :
			case MSG_F_BIND :
			case MSG_F_DESCRIBE :
			case MSG_F_EXECUTE :
			case MSG_F_PASSWD :
			case MSG_F_FUNCTION_CALL :
			case MSG_FB_COPYDATA :
			
				if (tknlen < 5) return false;
				break;
				
			case MSG_F_SYNC :
			case MSG_F_FLUSH :
			case MSG_F_TERMINATE :
			case MSG_FB_COPYDONE :
				if (tknlen != 4) return false;
				break;

			default :
				return false;
			}	

			pstart += tknlen + 1;
			maxlen -= (tknlen + 1);


		} while (maxlen >= 5);

		if (maxlen == 0) {
			return true;
		}

		if (ntkns > 2) {
			return true;
		}

		return indeterminate;
	}	

	static bool is_valid_resp(const uint8_t *pdata, uint32_t len, bool is_init = false) noexcept
	{
		if (is_init) {
			if (len >= 9) {
				uint32_t			msglen, type;
				char				c = (char)*pdata;

				if (c != MSG_B_AUTH_RESP) {
					return false;
				}	

				msglen = unaligned_read_be32(pdata + 1);

				if (len != msglen + 1) {
					return false;
				}

				type = unaligned_read_be32(pdata + 5);

				if (type == B_AUTH_SUCCESS || type == B_AUTH_KERBEROS || type == B_AUTH_CLEARTEXT_PWD 
					|| type == B_AUTH_MD5_PWD || type == B_AUTH_GSSAPI || type == B_AUTH_SSPI || type == B_AUTH_SASL) {
					
					return true;
				}	

				return false;
			}
			else if (len == 1) {
				char				c = (char)*pdata;

				if (c == 'S' || c == 'N') {
					// Maybe SSL Resp
					return indeterminate;
				}	
			}	

			return false;
		}

		if (len < 5) {
			return false;
		}	
		
		int				maxlen = len, ntkns = 0;
		const char			*pstart = (const char *)pdata;

		do {
			uint32_t			tknlen;
			char				tkn = *pstart, c;

			tknlen = unaligned_read_be32(pstart + 1);

			if (tknlen < 4) {
				return false;
			}	

			// Not a protocol limit...
			if (tknlen > GY_UP_MB(128)) {
				return false;
			}	

			ntkns++;

			switch (tkn) {

			case MSG_B_READY_FOR_QUERY :

				if (tknlen != 5) return false;

				if (maxlen >= (int)tknlen + 1) {
					c = pstart[5];
					if (c != 'I' && c != 'T' && c != 'E') return false;
				}

				break;

			case MSG_B_ERROR_RESP :
			case MSG_B_CMD_COMPLETE :

				if (tknlen <= 5) return false;

				if (maxlen > 5) {
					c = pstart[5];
					if (!(c >= 'A' && c <= 'Z')) return false;
				}

				break;
			
			case MSG_B_KEYDATA :

				if (tknlen != 12) return false;
				break;

			case MSG_B_DATAROW :
			case MSG_B_PARAM_DESC :
			case MSG_B_ROW_DESC :

				if (tknlen < 6) return false;
				break;

			case MSG_B_FUNCTION_CALL_RESP :

				if (tknlen < 8) return false;
				break;

			case MSG_B_AUTH_RESP :
			case MSG_B_COPYOUT_RESP :
			case MSG_B_COPYIN_RESP :
			case MSG_B_COPYBOTH_RESP :
			case MSG_B_NEGOTIATE_PROTO :	
			case MSG_B_NOTICE_RESP :
			case MSG_B_NOTIFY_RESP :
			case MSG_B_PARAM_STATUS :
			case MSG_FB_COPYDATA :

				if (tknlen < 5) return false;
				break;

			case MSG_B_CLOSE_COMPLETE :
			case MSG_B_PARSE_COMPLETE :
			case MSG_B_BIND_COMPLETE :
			case MSG_B_PORTAL_SUSPENDED :
			case MSG_B_EMPTY_RESPONSE :
			case MSG_B_NODATA :
			case MSG_FB_COPYDONE :

				if (tknlen != 4) return false;
				break;

			default :
				return false;
			}	

			pstart += tknlen + 1;
			maxlen -= (tknlen + 1);

		} while (maxlen >= 5);

		if (maxlen == 0) {
			return true;
		}

		if (ntkns > 2) {
			return true;
		}

		return indeterminate;
		
	}	

	static tribool is_valid_req_resp(const uint8_t *pdata, uint32_t caplen, uint32_t wirelen, DirPacket dir, bool is_init = false) noexcept
	{
		if (dir == DirPacket::DirInbound) {
			return is_valid_req(pdata, caplen, wirelen, is_init);
		}	

		return is_valid_resp(pdata, caplen, is_init);
	}	

};

} // namespace gyeeta

