//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"

namespace gyeeta {

class tls_proto
{
public :
	static constexpr size_t			TLS_HDR_SZ			{5};

	enum TYPE_E : uint8_t 
	{
		TYPE_ChangeCipherSpec		= 0x14,
		TYPE_Alert			= 0x15,
		TYPE_Handshake			= 0x16,
		TYPE_Application		= 0x17,
		TYPE_Heartbeat			= 0x18,
	};

	enum HANDSHAKE_TYPE_E : uint8_t
	{
		HS_HelloRequest			= 0,
		HS_ClientHello			= 1,
		HS_ServerHello			= 2,
		HS_NewSessionTicket		= 3,
		HS_NewSessionTicket		= 4,
		HS_EncryptedExtensions		= 8,
		HS_Certificate			= 11,
		HS_ServerKeyExchange		= 12,
		HS_CertificateRequest		= 13,
		HS_ServerHelloDone		= 14,
		HS_CertificateVerify		= 15,
		HS_ClientKeyExchange		= 16,
		HS_Finished			= 20,

		HS_Max,
	};	

	static bool is_tls_request_resp(const uint8_t *porigdata, uint32_t origlen, DirPacket dir, bool is_init_msg = false) noexcept
	{
		uint8_t				*pdata = porigdata, type = pdata[0], majorv, minorv;
		int				len = origlen;
		uint16_t			hdrlen;
		bool				bret;

		if (len < TLS_HDR_SZ) {
			return false;
		}	
	
		if (!(type >= TYPE_ChangeCipherSpec && type <= TYPE_Heartbeat)) {
			return false;
		}	

		if (is_init_msg && (type != TYPE_Handshake)) {
			return false;
		}	
		
		majorv = pdata[1];
		minorv = pdata[2];

		if ((majorv != 0x3) || (minorv > 0x4)) {
			return false;
		}	

		hdrlen = unaligned_read_be16(pdata + 3);

		pdata += TLS_HDR_SZ;
		len -= TLS_HDR_SZ;

		switch (type) {
		
		case TYPE_ChangeCipherSpec :
			if (hdrlen != 1) {
				return false;
			}
			break;

		case TYPE_Alert :	
			if (hdrlen != 2) {
				return false;
			}
			break;

		case TYPE_Handshake :
			if (hdrlen < 4) {
				return false;
			}

			if (len >= 4) {
				uint8_t			htype = pdata[0], tbuf[4] = { 0, pdata[1], pdata[2], pdata[3] };
				uint32_t		hlen;
				
				if (htype >= HS_Max) {
					return false;
				}	

				hlen = unaligned_read_be32(tbuf);

				if (hlen > hdrlen - 4) {
					return false;
				}	
			}

			break;

		case TYPE_Application :
		case TYPE_Heartbeat :	
			break;

		default :
			return false;
		}	

		if (len <= (int)hdrlen) {
			return true;
		}	

		pdata += hdrlen;
		len -= hdrlen;

		if (len > TLS_HDR_SZ) {
			// Check one more msg
			bret = is_tls_request_resp(pdata, std::min<uint32_t>(len, TLS_HDR_SZ + 4), dir, false);

			if (!bret) {
				return false;
			}	
		}

		return true;
	}	
};

} // namespace gyeeta

