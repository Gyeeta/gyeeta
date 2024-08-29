//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"
#include			"gy_misc.h"

namespace gyeeta {

class API_PARSE_HDLR;
struct PARSE_PKT_HDR;
class SVC_SESSION;
class MONGO_SESSINFO;

class MONGO_PROTO 
{
public :
	// Refer to https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol

	enum MG_OPCODE_E : uint32_t
	{
		OP_REPLY			= 	1,
		OP_QUERY			=	2004,
		OP_COMPRESSED			=	2012,
		OP_MSG				=	2013,
		OP_UPDATE			=	2001,
		OP_INSERT			=	2002,
		OP_RESERVED1			=	2003,
		OP_GET_MORE			=	2005,
		OP_DELETE			=	2006,
		OP_KILL_CURSORS			=	2007,
	};	

	struct MG_MSG_HDR
	{
		uint32_t			msglen_;
		uint32_t			reqid_;
		uint32_t			respid_;
		MG_OPCODE_E			opcode_;
	};

	static constexpr bool is_valid_opcode_req(MG_OPCODE_E opcode) noexcept
	{
		switch (opcode) {
		
		case OP_MSG :
		case OP_COMPRESSED :

		case OP_UPDATE ... OP_KILL_CURSORS :
			return true;

		default :
			return false;
		}	
	}	

	static constexpr bool is_valid_opcode_resp(MG_OPCODE_E opcode) noexcept
	{
		return (opcode == OP_MSG || opcode == OP_COMPRESSED || opcode == OP_REPLY);
	}	

	enum MG_COMPRESS_E : uint8_t
	{
		MG_COMP_NONE			=	0,
		MG_COMP_SNAPPY			=	1,
		MG_COMP_ZLIB			=	2,
		MG_COMP_ZSTD			=	3,

		MG_COMP_MAX,
	};

	struct MG_COMP_HDR
	{
		MG_OPCODE_E			actop_;
		uint32_t			uncomp_sz_;
		MG_COMPRESS_E			compid_;
	};	

	enum MG_OP_MSG_FLAGS_E : uint32_t
	{
		MG_FLAG_CKSUM			=	0x1,
		MG_FLAG_MORE			=	0x2,
		MG_EXHAUST_ALLOWED		=	0x10,		// More allowed
	};

	enum MG_OP_MSG_KIND_E : uint8_t
	{
		MG_KIND_BODY			= 	0,
		MG_KIND_SEQ			=	1,
	};	

	struct MG_MSG_SECTION
	{
		MG_OP_MSG_KIND_E		kind_;
		uint32_t			sec_len_;
		// uint8_t			sec_buf_[sec_len_] follows;
	};	

	enum BSON_ELEM_E : uint8_t
	{
		BSON_DOUBLE			= 1,
		BSON_STRING			= 2,
		BSON_DOCUMENT			= 3,
		BSON_ARRAY			= 4,
		BSON_BINARY			= 5,
		BSON_UNDEFINED			= 6,
		BSON_OBJECTID			= 7,
		BSON_BOOLEAN			= 8,
		BSON_UTC_DATETIME		= 9,
		BSON_NULL			= 10,
		BSON_REGEX		 	= 11,
		BSON_DBPOINTER			= 12,
		BSON_JAVASCRIPT			= 13,
		BSON_SYMBOL			= 14,
		BSON_JAVASCRIPT_SCOPE		= 15,
		BSON_INT32			= 16,
		BSON_TIMESTAMP			= 17,
		BSON_INT64			= 18,
		BSON_LONG_DOUBLE		= 19,
		
		BSON_MIN_KEY			= 0xFF,
		BSON_MAX_KEY			= 0x7F,
	};	

	enum BSON_BINARY_E : uint8_t
	{
		BIN_GENERIC			= 0,
		BIN_FUNCTION			= 1,
		BIN_OLD_BINARY			= 2,
		BIN_UUID_OLD			= 3,
		BIN_UUID			= 4,
		BIN_MD5				= 5,
		BIN_ENCRYPTED			= 6,
		BIN_COMPRESSED			= 7,
		BIN_SENSITIVE			= 8,
	};	

	enum MG_AUTH_MECH_E : uint8_t
	{
		AMECH_NONE			= 0,
		AMECH_CR,
		AMECH_X509,
		AMECH_SASL_PLAIN,
		AMECH_GSSAPI,
		AMECH_SCRAM_SHA1,
		AMECH_SCRAM_SHA256,
		AMECH_AWS,
		AMECH_OIDC,
	};

	static constexpr std::string_view 	AUTH_CR_SV 		= "MONGODB-CR";
	static constexpr std::string_view  	AUTH_X509_SV 		= "MONGODB-X509";
	static constexpr std::string_view 	AUTH_SASL_PLAIN_SV 	= "PLAIN";
	static constexpr std::string_view 	AUTH_GSSAPI_SV 		= "GSSAPI";
	static constexpr std::string_view 	AUTH_SCRAM_SHA1_SV 	= "SCRAM-SHA-1";
	static constexpr std::string_view 	AUTH_SCRAM_SHA256_SV 	= "SCRAM-SHA-256";
	static constexpr std::string_view 	AUTH_AWS_SV 		= "MONGODB-AWS";
	static constexpr std::string_view 	AUTH_OIDC_SV 		= "MONGODB-OIDC";

	static constexpr std::string_view 	SPECAUTH_SV 		= "speculativeAuthenticate";
	// Older auths
	static constexpr std::string_view 	CLUSTERAUTH_SV 		= "clusterAuthenticate";
	static constexpr std::string_view 	BASICAUTH_SV 		= "authenticate";

	static constexpr uint32_t		MAX_BSON_SIZE		{16777216};
	


	static tribool is_valid_req(const uint8_t *pdata, uint32_t caplen, uint32_t wirelen, bool is_init = false, LAST_PKT_SNIPPET *plastsnippet = nullptr) noexcept
	{
		if (caplen < sizeof(MG_MSG_HDR) + 8) {
			return false;
		}

		static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "Only Little Endian currently suported");
		
		MG_MSG_HDR			hdr;

		std::memcpy(&hdr, pdata, sizeof(hdr));

		if (hdr.respid_ != 0) {
			return false;
		}	

		if (hdr.msglen_ < caplen) {
			return false;
		}	

		if (hdr.msglen_ != caplen) {
			if (caplen < 1500) {
				return false;
			}	

			return indeterminate;
		}	

		if (is_init) {
			if (!(hdr.opcode_ == OP_MSG || hdr.opcode_ == OP_COMPRESSED || hdr.opcode_ == OP_QUERY)) {
				return false;
			}	
		}	
		else if (false == is_valid_opcode_req(hdr.opcode_)) {
			return false;
		}

		uint32_t			tdata;
		int				maxlen = hdr.msglen_ - sizeof(MG_MSG_HDR);
		const uint8_t			*ptmp = pdata + sizeof(MG_MSG_HDR), *pend = pdata + caplen;

		switch (hdr.opcode_) {
		
		case OP_MSG :
			if (maxlen < 9) {
				return false;
			}
			else {
				std::memcpy(&tdata, ptmp, 4);
				
				ptmp += 4;
				maxlen -= 4;

				bool			iscksum = tdata & MG_FLAG_CKSUM;

				if (iscksum) {
					maxlen -= 4;
					pend -= 4;
				}	

				while (ptmp + 5 < pend && ptmp > pdata) {
					uint8_t			kind = *ptmp++;

					if (kind > MG_KIND_SEQ) {
						return false;
					}	

					std::memcpy(&tdata, ptmp, 4);

					if (tdata > (uint32_t)maxlen || tdata < 5) {
						return false;
					}	

					if (tdata > 7) {
						if (kind == MG_KIND_BODY) {
							if (!gy_isprint_ascii(ptmp[5]) || !gy_isprint_ascii(ptmp[6])) {
								return false;
							}	
						}	
						else {
							if (!gy_isprint_ascii(ptmp[4]) || !gy_isprint_ascii(ptmp[5])) {
								return false;
							}	
						}	
					}

					ptmp += tdata; 
				}	

				return true;

			}

		case OP_COMPRESSED :	
			if (maxlen < (int)sizeof(MG_COMP_HDR)) {
				return false;
			}	
			else {
				MG_COMP_HDR			chdr;

				std::memcpy(&chdr, ptmp, sizeof(chdr));

				if (false == is_valid_opcode_req(chdr.actop_)) {
					return false;
				}

				if (chdr.compid_ >= MG_COMP_MAX) {
					return false;
				}	

				if (chdr.uncomp_sz_ < 9 || chdr.uncomp_sz_ > MAX_BSON_SIZE) {
					return false;
				}	

				return true;
			}	


		case OP_QUERY :
			if (maxlen < 23) {
				return false;
			}	
			else {
				bool			col = false;

				std::memcpy(&tdata, ptmp, 4);

				ptmp += 4;
				maxlen -= 4;

				if (tdata & 0xFFFFFFF0) {
					return false;
				}

				while (ptmp < pend) {
					if (0 == *ptmp) {
						col = true;
						ptmp++;
						break;
					}	
					else if (!gy_isprint_ascii(*ptmp)) {
						return false;
					}	

					++ptmp;
				}	

				if (!col) {
					return false;
				}	

				if (ptmp + 12 >= pend) {
					return false;
				}	

				std::memcpy(&tdata, ptmp, 4);

				if (is_init && tdata != 0) {
					return false;
				}	
				
				ptmp += 8;

				std:memcpy(&tdata, ptmp, 4);

				if (tdata > pend - ptmp) {
					return false;
				}
				else if (tdata == pend - ptmp) {
					return true;
				}	
				
				// field sel
				return indeterminate;
			}	
			
		case OP_DELETE :
			if (maxlen < 14) {
				return false;
			}	
			else {
				bool			col = false;

				std::memcpy(&tdata, ptmp, 4);

				ptmp += 4;
				maxlen -= 4;

				if (tdata & 0xFFFFFF00) {
					return false;
				}

				while (ptmp < pend) {
					if (0 == *ptmp) {
						col = true;
						ptmp++;
						break;
					}	
					else if (!gy_isprint_ascii(*ptmp)) {
						return false;
					}	

					++ptmp;
				}	

				if (!col) {
					return false;
				}	

				if (ptmp + 8 >= pend) {
					return false;
				}	

				ptmp += 4;

				std::memcpy(&tdata, ptmp, 4);

				return (tdata == pend - ptmp);
			}	

		case OP_GET_MORE :
			if (maxlen < 18) {
				return false;
			}	
			else {
				bool			col = false;

				std::memcpy(&tdata, ptmp, 4);

				ptmp += 4;
				maxlen -= 4;

				if (tdata & 0xFFFFFF00) {
					return false;
				}

				while (ptmp < pend) {
					if (0 == *ptmp) {
						col = true;
						ptmp++;
						break;
					}	
					else if (!gy_isprint_ascii(*ptmp)) {
						return false;
					}	

					++ptmp;
				}	

				if (!col) {
					return false;
				}	

				return (ptmp + 12 == pend);
			}	


		case OP_INSERT :
			if (maxlen < 8) {
				return false;
			}	
			else {
				bool			col = false;

				std::memcpy(&tdata, ptmp, 4);

				ptmp += 4;
				maxlen -= 4;

				if (tdata & 0xFFFFFFF0) {
					return false;
				}

				while (ptmp < pend) {
					if (0 == *ptmp) {
						col = true;
						ptmp++;
						break;
					}	
					else if (!gy_isprint_ascii(*ptmp)) {
						return false;
					}	

					++ptmp;
				}	

				if (!col) {
					return false;
				}	

				return true;
			}	

		case OP_KILL_CURSORS :
			if (maxlen < 16) {
				return false;
			}	
			else {
				bool			col = false;

				std::memcpy(&tdata, ptmp, 4);

				ptmp += 4;
				maxlen -= 4;

				if (tdata & 0xFFFFFF00) {
					return false;
				}

				std::memcpy(&tdata, ptmp, 4);

				ptmp += 4;
				maxlen -= 4;

				return ptmp + tdata * 8 == pend;
			}	

		default :
			return false;
			
		}	

		return false;
	}

	static tribool is_valid_resp(const uint8_t *pdata, uint32_t caplen, uint32_t wirelen, bool is_init = false, LAST_PKT_SNIPPET *plastsnippet = nullptr) noexcept
	{
		if (caplen < sizeof(MG_MSG_HDR) + 8) {
			return false;
		}

		static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "Only Little Endian currently suported");
		
		MG_MSG_HDR			hdr;

		std::memcpy(&hdr, pdata, sizeof(hdr));

		if (hdr.respid_ == 0 && !is_init) {
			return false;
		}	

		if (hdr.msglen_ < caplen) {
			return false;
		}	

		if (hdr.msglen_ != caplen) {
			if (caplen < 1500) {
				return false;
			}	

			return indeterminate;
		}	

		if (false == is_valid_opcode_resp(hdr.opcode_)) {
			return false;
		}

		uint32_t			tdata;
		int				maxlen = hdr.msglen_ - sizeof(MG_MSG_HDR);
		const uint8_t			*ptmp = pdata + sizeof(MG_MSG_HDR), *pend = pdata + caplen;

		switch (hdr.opcode_) {
		
		case OP_MSG :
			if (maxlen < 9) {
				return false;
			}
			else {
				std::memcpy(&tdata, ptmp, 4);
				
				ptmp += 4;
				maxlen -= 4;

				bool			iscksum = tdata & MG_FLAG_CKSUM;

				if (iscksum) {
					maxlen -= 4;
					pend -= 4;
				}	

				while (ptmp + 5 < pend && ptmp > pdata) {
					uint8_t			kind = *ptmp++;

					if (kind > MG_KIND_SEQ) {
						return false;
					}	

					std::memcpy(&tdata, ptmp, 4);

					if (tdata > (uint32_t)maxlen || tdata < 5) {
						return false;
					}	

					if (tdata > 7) {
						if (kind == MG_KIND_BODY) {
							if (!gy_isprint_ascii(ptmp[5]) || !gy_isprint_ascii(ptmp[6])) {
								return false;
							}	
						}	
						else {
							if (!gy_isprint_ascii(ptmp[4]) || !gy_isprint_ascii(ptmp[5])) {
								return false;
							}	
						}	
					}

					ptmp += tdata; 
				}	

				return true;

			}

		case OP_COMPRESSED :	
			if (maxlen < (int)sizeof(MG_COMP_HDR)) {
				return false;
			}	
			else {
				MG_COMP_HDR			chdr;

				std::memcpy(&chdr, ptmp, sizeof(chdr));

				if (false == is_valid_opcode_resp(chdr.actop_)) {
					return false;
				}

				if (chdr.compid_ >= MG_COMP_MAX) {
					return false;
				}	

				if (chdr.uncomp_sz_ < 9 || chdr.uncomp_sz_ > MAX_BSON_SIZE) {
					return false;
				}	

				return true;
			}	


		case OP_REPLY :
			if (maxlen < 24) {
				return false;
			}	
			else {
				std::memcpy(&tdata, ptmp, 4);

				ptmp += 4;
				maxlen -= 4;

				if (tdata & 0xFFFFFFF0) {
					return false;
				}
				
				if (is_init) {
					if (memcmp(ptmp, "\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x1\x0\x0\x0", 16)) {
						return false;
					}	
				}	

				ptmp += 12; 

				std::memcpy(&tdata, ptmp, 4);

				ptmp += 4;
				maxlen -= 4;

				if (tdata == 1) {
					std::memcpy(&tdata, ptmp, 4);
					
					if (tdata != pend - ptmp) {
						return false;
					}	
				}	
				else if (tdata > 1'000'000) {
					return false;
				}	

				return true;
			}	
			
		default :
			return false;
			
		}	

		return false;
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
	uint32_t				max_mongo_req_token_;
	uint32_t				max_mongo_resp_token_;

	MONGO_PROTO(API_PARSE_HDLR & apihdlr, uint32_t api_max_len);

	~MONGO_PROTO() noexcept;
	
	MONGO_PROTO(const MONGO_PROTO & other) noexcept			= default;

	MONGO_PROTO & operator=(const MONGO_PROTO & other) noexcept	= default;

	void handle_request_pkt(MONGO_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr, uint8_t *pdata);

	void handle_response_pkt(MONGO_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr, uint8_t *pdata);

	void handle_session_end(MONGO_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr);

	void handle_ssl_change(MONGO_SESSINFO & sess, SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr, uint8_t *pdata);

	std::pair<MONGO_SESSINFO *, void *> alloc_sess(SVC_SESSION & svcsess, PARSE_PKT_HDR & hdr);

	void destroy(MONGO_SESSINFO *pobj, void *pdata) noexcept;

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

