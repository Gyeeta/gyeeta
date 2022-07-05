
#pragma			once

#include		"gy_common_inc.h"

namespace gyeeta {

static constexpr const uint8_t base64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static constexpr size_t get_base64_encode_len(size_t inputlen, bool wraplines = true) noexcept
{
	size_t			olen = 0;

	olen = inputlen * 4 / 3 + 4; /* 3 byte blocks to 4 bytes */

	if (wraplines) {
		olen += olen / 76; /* wrap lines at 76 bytes */
	}

	olen++; /* null termination */
	
	return olen;
}

static size_t gy_base64_encode(const uint8_t *src, size_t len, uint8_t *dest, size_t maxlen, bool wraplines = false)
{
	uint8_t 		*out = dest, *pos;
	const uint8_t 		*end, *in;
	size_t 			olen;
	int 			line_len;

	olen = get_base64_encode_len(len);

	if (maxlen < olen) {
		GY_THROW_EXCEPTION("Base64 encode failed as destination buffer too small : Require %lu Got %lu", olen, maxlen);
	}	

	end = src + len;
	in = src;
	pos = out;
	line_len = 0;

	while (end - in >= 3) {
		*pos++ = base64_table[in[0] >> 2];
		*pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
		*pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
		*pos++ = base64_table[in[2] & 0x3f];
		in += 3;
		line_len += 4;

		if (line_len >= 76 && wraplines) {
			*pos++ = '\n';
			line_len = 0;
		}
	}

	if (end > in) {
		*pos++ = base64_table[in[0] >> 2];
		if (end - in == 1) {
			*pos++ = base64_table[(in[0] & 0x03) << 4];
			*pos++ = '=';
		} 
		else {
			*pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
			*pos++ = base64_table[(in[1] & 0x0f) << 2];
		}
		*pos++ = '=';
		line_len += 4;
	}

	if (line_len) {
		*pos++ = '\n';
	}

	*pos = '\0';

	return	pos - out;
}

static std::optional<size_t> gy_base64_decode(const uint8_t *src, size_t len, uint8_t *dest, size_t maxlen)
{
	uint8_t 		dtable[256], *out = dest, *pos = out, in[4], block[4], tmp;
	size_t 			i, count, olen;

	std::memset(dtable, 0x80, sizeof(dtable));

	for (i = 0; i < sizeof(base64_table) - 1; i++) {
		dtable[base64_table[i]] = (uint8_t) i;
	}

	dtable['='] = 0;

	count = 0;
	for (i = 0; i < len; i++) {
		if (dtable[src[i]] != 0x80) {
			count++;
		}	
	}

	if (count == 0) {
		if (maxlen) {
			*out = 0;
		}	
		return 0;
	}

	if (count % 4) {
		if (maxlen) {
			*out = 0;
		}	
		return {};
	}

	olen = count / 4 * 3;
	
	if (maxlen < olen) {
		GY_THROW_EXCEPTION("Base64 decode failed as destination buffer too small : Require %lu Got %lu", olen, maxlen);
	}	

	*out = 0;

	count = 0;
	for (i = 0; i < len; i++) {
		tmp = dtable[src[i]];
		if (tmp == 0x80) {
			continue;
		}

		in[count] = src[i];
		block[count] = tmp;
		count++;

		if (count == 4) {
			*pos++ = (block[0] << 2) | (block[1] >> 4);
			*pos++ = (block[1] << 4) | (block[2] >> 2);
			*pos++ = (block[2] << 6) | block[3];
			count = 0;
		}
	}
	if (pos > out) {
		if (in[2] == '=') {
			pos -= 2;
		}	
		else if (in[3] == '=') {
			pos--;
		}	
	}

	return (pos - out);
}

} // namespace gyeeta

