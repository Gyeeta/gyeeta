//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"
#include			"gy_misc.h"

namespace gyeeta {

class http2_sessinfo
{
public :

};


class http2_proto 
{
public :
	static constexpr uint32_t	MAX_FRAME_SIZE 	= 16'777'215;

	enum HTYPE_E : uint8_t 
	{
		HTYPE_DATA		= 0,
		HTYPE_HEADERS		= 1,
		HTYPE_PRIORITY		= 2,
		HTYPE_RST_STREAM	= 3,
		HTYPE_SETTINGS		= 4,
		HTYPE_PUSH_PROMISE	= 5,
		HTYPE_PING 		= 6,
		HTYPE_GOAWAY		= 7,
		HTYPE_WINDOW_UPDATE	= 8,
		HTYPE_CONTINUATION	= 9,
		HTYPE_ALTSVC		= 0xA,
		HTYPE_BLOCKED		= 0xB,

		HTYPE_INVALID		= 0xFF,
	};

	enum : uint8_t
	{
		HFLAG_ACK_END_STREAM	= 0x1,
		HFLAG_END_HEADERS	= 0x4,
		HFLAG_PADDED		= 0x8,
		HFLAG_PRIORITY		= 0x20,

		HFLAG_INVALID		= 0xFF,
	};

	enum : uint8_t
	{
		HDR_STATUS_200		= 0x88,
		HDR_STATUS_204		= 0x89,
		HDR_STATUS_206		= 0x8A,
		HDR_STATUS_304		= 0x8B,	
		HDR_STATUS_400		= 0x8C,
		HDR_STATUS_404		= 0x8D,
		HDR_STATUS_500		= 0x8E,

		HDR_STATUS_INDEX	= 0x48,
	};	

	struct FrameInfo
	{
		uint32_t		framelen_;
		uint32_t		streamid_;
		HTYPE_E			type_;
		uint8_t			flags_;
	};	

	static inline bool is_init_magic(const uint8_t *pdata, uint32_t caplen) noexcept
	{
		return (caplen >= 24 && (0 == memcmp(pdata, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24)));
	}	

	static inline bool init_invalid_http2_resp(const uint8_t *pdata, uint32_t caplen) noexcept
	{
		// GoAway or Settings Response
		return ((caplen == 17 && (0 == memcmp(pdata, "\x00\x00\x08\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16)))
			|| (caplen == 9 && (0 == memcmp(pdata, "\x00\x00\x00\x04\x00\x00\x00\x00\x00", 9)))
			|| (caplen == 26 && (0 == memcmp(pdata, "\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x08\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 25))));
	}	

	// Returns {is_valid, is_pending}
	static std::pair<bool, bool> is_valid_frame(const uint8_t *pdata, uint32_t caplen, uint32_t datalen, FrameInfo *pframe = nullptr) noexcept
	{
		if ((int)caplen < 9) {
			return {false, false};
		}	

		alignas(4) uint8_t		buf[4] {0, pdata[0], pdata[1], pdata[2]};
		uint32_t			framelen = ntohl(*(uint32_t *)buf);
		HTYPE_E				type;
		uint8_t				flags;

		if (framelen > MAX_FRAME_SIZE) {
			return {false, false};
		}	
		
		type = (HTYPE_E)pdata[3];
		
		if (type >= HTYPE_BLOCKED) {
			return {false, false};
		}	

		flags = pdata[4];

		switch (type) {

		case HTYPE_DATA :
			if (flags & ~(HFLAG_ACK_END_STREAM | HFLAG_PADDED)) {
				return {false, false};
			}	
			break;

		case HTYPE_HEADERS :
			if (flags & ~(HFLAG_ACK_END_STREAM | HFLAG_END_HEADERS | HFLAG_PRIORITY | HFLAG_PADDED)) {
				return {false, false};
			}	
			break;

		case HTYPE_PRIORITY :
		case HTYPE_RST_STREAM :
			if (flags) {
				return {false, false};
			}	
			break;

		case HTYPE_SETTINGS :
			if (flags & ~(HFLAG_ACK_END_STREAM)) {
				return {false, false};
			}	
			else if (flags && framelen > 0) {
				return {false, false};
			}
			else {
				if ((pdata[5] & 0x7F) | pdata[6] | pdata[7] | pdata[8]) {
					// StreamID must be 0
					return {false, false};
				}	

				if (framelen > 0 && (framelen % 6) > 0) {
					return {false, false};
				}	
			}	
			break;

		case HTYPE_PUSH_PROMISE :
			if (flags & ~(HFLAG_END_HEADERS | HFLAG_PADDED)) {
				return {false, false};
			}
			break;

		case HTYPE_PING :
			if (flags & ~(HFLAG_ACK_END_STREAM)) {
				return {false, false};
			}	
			else if (framelen != 8) {
				return {false, false};
			}
			else {
				if ((pdata[5] & 0x7F) | pdata[6] | pdata[7] | pdata[8]) {
					// StreamID must be 0
					return {false, false};
				}	
			}	
			break;

		case HTYPE_WINDOW_UPDATE :
			if (flags) {
				return {false, false};
			}	
			else if (framelen != 4) {
				return {false, false};
			}
			break;
		
		default :
			break;
		}	

		if (pframe) {
			alignas(4) uint8_t	sbuf[] { uint8_t(pdata[5] & 0x7F), pdata[6], pdata[7], pdata[8] };

			pframe->framelen_	= framelen;
			pframe->streamid_	= ntohl(*(uint32_t *)sbuf);
			pframe->type_		= type;
			pframe->flags_		= flags;
		}	

		return {true, datalen < framelen + 9};
	}	

	static bool is_settings_response(const uint8_t *pdata, uint32_t caplen, uint32_t datalen) noexcept
	{
		FrameInfo			finfo;
		auto [is_valid, is_pend]	= is_valid_frame(pdata, caplen, datalen, &finfo);

		if (!is_valid) {
			return false;
		}	

		return (finfo.type_ == HTYPE_SETTINGS);
	}	

	static bool is_valid_req_resp(const uint8_t *pdata, uint32_t caplen, uint32_t datalen, DirPacket dir) noexcept
	{
		auto [is_valid, is_pend]	= is_valid_frame(pdata, caplen, datalen);

		return is_valid;
	}	
	
	// Returns false if no valid status
	static bool get_status_response(const uint8_t *pdata, uint32_t caplen, bool & is_cli_err, bool & is_ser_err) noexcept
	{
		const uint8_t			*pend = pdata + caplen, *porig = pdata - 1, *pnext;
		FrameInfo			finfo;
		
		while (pdata < pend && pdata > porig) {
			auto [is_valid, is_pend] = is_valid_frame(pdata, pend - pdata, pend - pdata, &finfo);

			if (!is_valid) {
				return false;
			}	

			porig = pdata;

			if (finfo.type_ != HTYPE_HEADERS) {
				pdata += finfo.framelen_ + 9;
				continue;
			}	

			pnext = pdata + finfo.framelen_ + 9;

			if (pnext + 9 < pend) {
				// An extra check
				auto 		is_valid2 = is_valid_frame(pnext, pend - pnext, pend - pnext).first;

				if (!is_valid2) {
					return false;
				}	
			}	

			pdata += 9;
			
			if (finfo.flags_ & HFLAG_PADDED) {
				pdata++;
			}	

			if (finfo.flags_ & HFLAG_PRIORITY) {
				pdata += 5;
			}	
		
			if (pdata + 1 >= pend) {
				return false;
			}	

			/*
			 * Assumption is ":status" is the first Header Type 
			 */

			uint8_t			htype = *pdata;

			switch (htype) {
			
			case HDR_STATUS_200 :
			case HDR_STATUS_204 :
			case HDR_STATUS_206 :
			case HDR_STATUS_304 :
				is_cli_err = false;
				is_ser_err = false;

				return true;
			
			case HDR_STATUS_400 :
			case HDR_STATUS_404 :
				is_cli_err = true;
				is_ser_err = false;

				return true;
				
			case HDR_STATUS_500 :
				is_cli_err = false;
				is_ser_err = true;

				return true;
			
			case HDR_STATUS_INDEX :
				if (pdata + 3 >= pend) {
					return false;
				}	
				else {
					uint8_t			len = pdata[1] & 0x7F, status1 = pdata[2];

					if (pdata[1] & 0x80) {
						if (len != 2 && len != 3) {
							return false;
						}	

						switch (status1) {
						
						case 0x68 :
						case 0x69 :
							// 4xx Huffman Coded
							is_cli_err = true;
							is_ser_err = false;

							break;

						case 0x6C :
						case 0x6D :
							// 5xx Huffman Coded
							is_cli_err = false;
							is_ser_err = true;

							break;

						default :
							is_cli_err = false;
							is_ser_err = false;

							break;
						}	
					}
					else {
						// No Huffman

						if (len != 3) {
							return false;
						}	

						if (status1 == '4') {
							is_cli_err = true;
							is_ser_err = false;
						}	
						else if (status1 == '5') {
							is_cli_err = false;
							is_ser_err = true;
						}	
						else {
							is_cli_err = false;
							is_ser_err = false;
						}	
					}	
				}

				return true;

			default :
				pdata = pnext;
				break;
			}	
		}

		return false;
	}	
};	

} // namespace gyeeta

