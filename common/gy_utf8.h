
// Shamelessly inspired from https://github.com/sheredom/utf8.h

#pragma			once

#include 		<cstdio>
#include 		<cstdlib>
#include 		<cstring>
#include 		<cstdarg>
#include 		<cerrno>
#include 		<cassert>
#include 		<unistd.h>
#include 		<cinttypes>
#include 		<sys/types.h>

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored 	"-Wold-style-cast"
#pragma clang diagnostic ignored 	"-Wcast-qual"
#endif

namespace gyeeta {

[[gnu::pure]] 
static void *gy_utf8_str(const void *haystack, const void *needle) noexcept;
static void * gy_utf8_codepoint(const void *__restrict__ str, int *__restrict__ out_codepoint) noexcept;
static size_t gy_utf8_codepointsize(int chr) noexcept;
static int gy_utf8_lwrcodepoint(int cp) noexcept;
static int gy_utf8_uprcodepoint(int cp) noexcept;

// Return less than 0, 0, greater than 0 if src1 < src2, src1 == src2, src1 > src2 respectively, case insensitive.
[[gnu::pure]]
static int gy_utf8_casecmp(const void *src1, const void *src2) noexcept
{
	int src1_cp, src2_cp, src1_orig_cp, src2_orig_cp;

	for (;;) {
		src1 = gy_utf8_codepoint(src1, &src1_cp);
		src2 = gy_utf8_codepoint(src2, &src2_cp);

		// Take a copy of src1 & src2
		src1_orig_cp = src1_cp;
		src2_orig_cp = src2_cp;

		// Lower the srcs if required
		src1_cp = gy_utf8_lwrcodepoint(src1_cp);
		src2_cp = gy_utf8_lwrcodepoint(src2_cp);

		// Check if the lowered codepoints match
		if ((0 == src1_orig_cp) && (0 == src2_orig_cp)) {
			return 0;
		} else if (src1_cp == src2_cp) {
			continue;
		}

		// If they don't match, then we return which of the original's are less
		if (src1_orig_cp < src2_orig_cp) {
			return -1;
		} else if (src1_orig_cp > src2_orig_cp) {
			return 1;
		}
	}
}

// Find the first match of the utf8 codepoint chr in the utf8 string src.
[[gnu::pure]]
static void *gy_utf8_chr(const void *src, int chr) noexcept
{
	char c[5] = {'\0', '\0', '\0', '\0', '\0'};

	if (0 == chr) {
		// being asked to return position of null terminating byte, so
		// just run s to the end, and return!
		const char *s = (const char *)src;
		while ('\0' != *s) {
			s++;
		}
		return (void *)s;
	} else if (0 == ((int)0xffffff80 & chr)) {
		// 1-byte/7-bit ascii
		// (0b0xxxxxxx)
		c[0] = (char)chr;
	} else if (0 == ((int)0xfffff800 & chr)) {
		// 2-byte/11-bit utf8 code point
		// (0b110xxxxx 0b10xxxxxx)
		c[0] = 0xc0 | (char)(chr >> 6);
		c[1] = 0x80 | (char)(chr & 0x3f);
	} else if (0 == ((int)0xffff0000 & chr)) {
		// 3-byte/16-bit utf8 code point
		// (0b1110xxxx 0b10xxxxxx 0b10xxxxxx)
		c[0] = 0xe0 | (char)(chr >> 12);
		c[1] = 0x80 | (char)((chr >> 6) & 0x3f);
		c[2] = 0x80 | (char)(chr & 0x3f);
	} else { // if (0 == ((int)0xffe00000 & chr)) 
		// 4-byte/21-bit utf8 code point
		// (0b11110xxx 0b10xxxxxx 0b10xxxxxx 0b10xxxxxx)
		c[0] = 0xf0 | (char)(chr >> 18);
		c[1] = 0x80 | (char)((chr >> 12) & 0x3f);
		c[2] = 0x80 | (char)((chr >> 6) & 0x3f);
		c[3] = 0x80 | (char)(chr & 0x3f);
	}

	// we've made c into a 2 utf8 codepoint string, one for the chr we are
	// seeking, another for the null terminating byte. Now use gy_utf8_str to
	// search
	return gy_utf8_str(src, c);
}

// Number of utf8 codepoints in the utf8 string src that consists entirely of utf8 codepoints not from the utf8 string reject.
[[gnu::pure]]
static size_t gy_utf8_cspn(const void *src, const void *reject) noexcept
{
	const char *s = (const char *)src;
	size_t chars = 0;

	while ('\0' != *s) {
		const char *r = (const char *)reject;
		size_t offset = 0;

		while ('\0' != *r) {
			// checking that if *r is the start of a utf8 codepoint
			// (it is not 0b10xxxxxx) and we have successfully matched
			// a previous character (0 < offset) - we found a match
			if ((0x80 != (0xc0 & *r)) && (0 < offset)) {
				return chars;
			} else {
				if (*r == s[offset]) {
					// part of a utf8 codepoint matched, so move our checking
					// onwards to the next byte
					offset++;
					r++;
				} else {
					// r could be in the middle of an unmatching utf8 code point,
					// so we need to march it on to the next character beginning,

					do {
						r++;
					} while (0x80 == (0xc0 & *r));

					// reset offset too as we found a mismatch
					offset = 0;
				}
			}
		}

		// the current utf8 codepoint in src did not match reject, but src
		// could have been partway through a utf8 codepoint, so we need to
		// march it onto the next utf8 codepoint starting byte
		do {
			s++;
		} while ((0x80 == (0xc0 & *s)));
		chars++;
	}

	return chars;
}

// Number of utf8 codepoints (NOT bytes) in the utf8 string str, excluding the null terminating byte.
// If pnbytes is non-null, will save the strlen in bytes in pnbytes
static size_t gy_utf8_len(const void *str, size_t * pnbytes = nullptr) noexcept
{
	const uint8_t *s = (const uint8_t *)str;
	size_t length = 0;

	assert(str);

	while ('\0' != *s) {
		if (0x00 == (0x80 & *s)) {
			// 1-byte ascii (began with 0b0xxxxxxx)
			s += 1;
		}	
		else if (0xf0 == (0xf8 & *s)) {
			// 4-byte utf8 code point (began with 0b11110xxx)
			s += 4;
		} else if (0xe0 == (0xf0 & *s)) {
			// 3-byte utf8 code point (began with 0b1110xxxx)
			s += 3;
		} else if (0xc0 == (0xe0 & *s)) {
			// 2-byte utf8 code point (began with 0b110xxxxx)
			s += 2;
		} else { 
			// Assume ASCII
			s += 1;
		}

		// no matter the bytes we marched s forward by, it was
		// only 1 utf8 codepoint
		length++;
	}

	if (pnbytes) {
		*pnbytes = s - (const uint8_t *)str;
	}
		
	return length;
}

// Number of utf8 codepoints (NOT bytes) in the utf8 string str upto maxbytes, excluding the null terminating byte.
// If pnbytes is non-null, will save the strlen in bytes in pnbytes
static size_t gy_utf8_nlen(const void *utf8str, size_t maxbytes, size_t *pnbytes = nullptr) noexcept
{
	const uint8_t 	*s = (const uint8_t *)utf8str, *end = (const uint8_t *)utf8str + maxbytes, *olds = (const uint8_t *)utf8str;
	size_t length = 0;

	assert(utf8str);

	while ('\0' != *s) {
		if (0x0 == (0x80 & *s)) {
			// 1-byte ascii (began with 0b0xxxxxxx)
			s++;
		}
		else if (0xf0 == (0xf8 & *s)) {
			// 4-byte utf8 code point (began with 0b11110xxx)
			s += 4;
		} 
		else if (0xe0 == (0xf0 & *s)) {
			// 3-byte utf8 code point (began with 0b1110xxxx)
			s += 3;
		} 
		else if (0xc0 == (0xe0 & *s)) {
			// 2-byte utf8 code point (began with 0b110xxxxx)
			s += 2;
		} 
		else { 
			// Assume 1-byte ascii 
			s++;
		}

		if (s > end) {
			break;
		}	    

		// no matter the bytes we marched s forward by, it was
		// only 1 utf8 codepoint
		length++;

		olds = s;
	}

	if (pnbytes) {
		*pnbytes = olds - (const uint8_t *)utf8str;	
	}

	return length;
}

// Return less than 0, 0, greater than 0 if src1 < src2, src1 == src2, src1 >
// src2 respectively, case insensitive. Checking at most n bytes of each utf8 string.
[[gnu::pure]]
static int gy_utf8_ncasecmp(const void *src1, const void *src2, size_t n) noexcept
{
	int src1_cp, src2_cp, src1_orig_cp, src2_orig_cp;

	do {
		const uint8_t *const s1 = (const uint8_t *)src1;
		const uint8_t *const s2 = (const uint8_t *)src2;

		// first check that we have enough bytes left in n to contain an entire
		// codepoint
		if (0 == n) {
			return 0;
		}

		if ((1 == n) && ((0xc0 == (0xe0 & *s1)) || (0xc0 == (0xe0 & *s2)))) {
			const int c1 = (0xe0 & *s1);
			const int c2 = (0xe0 & *s2);

			if (c1 < c2) {
				return -1;
			} else if (c1 > c2) {
				return 1;
			} else {
				return 0;
			}
		}

		if ((2 >= n) && ((0xe0 == (0xf0 & *s1)) || (0xe0 == (0xf0 & *s2)))) {
			const int c1 = (0xf0 & *s1);
			const int c2 = (0xf0 & *s2);

			if (c1 < c2) {
				return -1;
			} else if (c1 > c2) {
				return 1;
			} else {
				return 0;
			}
		}

		if ((3 >= n) && ((0xf0 == (0xf8 & *s1)) || (0xf0 == (0xf8 & *s2)))) {
			const int c1 = (0xf8 & *s1);
			const int c2 = (0xf8 & *s2);

			if (c1 < c2) {
				return -1;
			} else if (c1 > c2) {
				return 1;
			} else {
				return 0;
			}
		}

		src1 = gy_utf8_codepoint(src1, &src1_cp);
		src2 = gy_utf8_codepoint(src2, &src2_cp);
		n -= gy_utf8_codepointsize(src1_cp);

		// Take a copy of src1 & src2
		src1_orig_cp = src1_cp;
		src2_orig_cp = src2_cp;

		// Lower srcs if required
		src1_cp = gy_utf8_lwrcodepoint(src1_cp);
		src2_cp = gy_utf8_lwrcodepoint(src2_cp);

		// Check if the lowered codepoints match
		if ((0 == src1_orig_cp) && (0 == src2_orig_cp)) {
			return 0;
		} else if (src1_cp == src2_cp) {
			continue;
		}

		// If they don't match, then we return which of the original's are less
		if (src1_orig_cp < src2_orig_cp) {
			return -1;
		} else if (src1_orig_cp > src2_orig_cp) {
			return 1;
		}
	} while (0 < n);

	// both utf8 strings matched
	return 0;
}


// Find the last match of the utf8 codepoint chr in the utf8 string src.
[[gnu::pure]] 
static void *gy_utf8_rchr(const void *src, int chr) noexcept
{
	const char *s = (const char *)src;
	const char *match = nullptr;
	char c[5] = {'\0', '\0', '\0', '\0', '\0'};

	if (0 == chr) {
		// being asked to return position of null terminating byte, so
		// just run s to the end, and return!
		while ('\0' != *s) {
			s++;
		}
		return (void *)s;
	} else if (0 == ((int)0xffffff80 & chr)) {
		// 1-byte/7-bit ascii
		// (0b0xxxxxxx)
		c[0] = (char)chr;
	} else if (0 == ((int)0xfffff800 & chr)) {
		// 2-byte/11-bit utf8 code point
		// (0b110xxxxx 0b10xxxxxx)
		c[0] = 0xc0 | (char)(chr >> 6);
		c[1] = 0x80 | (char)(chr & 0x3f);
	} else if (0 == ((int)0xffff0000 & chr)) {
		// 3-byte/16-bit utf8 code point
		// (0b1110xxxx 0b10xxxxxx 0b10xxxxxx)
		c[0] = 0xe0 | (char)(chr >> 12);
		c[1] = 0x80 | (char)((chr >> 6) & 0x3f);
		c[2] = 0x80 | (char)(chr & 0x3f);
	} else { // if (0 == ((int)0xffe00000 & chr)) 
		// 4-byte/21-bit utf8 code point
		// (0b11110xxx 0b10xxxxxx 0b10xxxxxx 0b10xxxxxx)
		c[0] = 0xf0 | (char)(chr >> 18);
		c[1] = 0x80 | (char)((chr >> 12) & 0x3f);
		c[2] = 0x80 | (char)((chr >> 6) & 0x3f);
		c[3] = 0x80 | (char)(chr & 0x3f);
	}

	// we've created a 2 utf8 codepoint string in c that is
	// the utf8 character asked for by chr, and a null
	// terminating byte

	while ('\0' != *s) {
		size_t offset = 0;

		while (s[offset] == c[offset]) {
			offset++;
		}

		if ('\0' == c[offset]) {
			// we found a matching utf8 code point
			match = s;
			s += offset;
		} else {
			s += offset;

			// need to march s along to next utf8 codepoint start
			// (the next byte that doesn't match 0b10xxxxxx)
			if ('\0' != *s) {
				do {
					s++;
				} while (0x80 == (0xc0 & *s));
			}
		}
	}

	// return the last match we found (or 0 if no match was found)
	return (void *)match;
}

// Locates the first occurence in the utf8 string str of any byte in the utf8 string accept, or 0 if no match was found.
[[gnu::pure]]
static void *gy_utf8_pbrk(const void *str, const void *accept) noexcept
{
	const char *s = (const char *)str;

	while ('\0' != *s) {
		const char *a = (const char *)accept;
		size_t offset = 0;

		while ('\0' != *a) {
			// checking that if *a is the start of a utf8 codepoint
			// (it is not 0b10xxxxxx) and we have successfully matched
			// a previous character (0 < offset) - we found a match
			if ((0x80 != (0xc0 & *a)) && (0 < offset)) {
				return (void *)s;
			} else {
				if (*a == s[offset]) {
					// part of a utf8 codepoint matched, so move our checking
					// onwards to the next byte
					offset++;
					a++;
				} else {
					// r could be in the middle of an unmatching utf8 code point,
					// so we need to march it on to the next character beginning,

					do {
						a++;
					} while (0x80 == (0xc0 & *a));

					// reset offset too as we found a mismatch
					offset = 0;
				}
			}
		}

		// we found a match on the last utf8 codepoint
		if (0 < offset) {
			return (void *)s;
		}

		// the current utf8 codepoint in src did not match accept, but src
		// could have been partway through a utf8 codepoint, so we need to
		// march it onto the next utf8 codepoint starting byte
		do {
			s++;
		} while ((0x80 == (0xc0 & *s)));
	}

	return nullptr;
}

// Number of utf8 codepoints in the utf8 string src that consists entirely of utf8 codepoints from the utf8 string accept.
[[gnu::pure]]
static size_t gy_utf8_spn(const void *src, const void *accept) noexcept
{
	const char *s = (const char *)src;
	size_t chars = 0;

	while ('\0' != *s) {
		const char *a = (const char *)accept;
		size_t offset = 0;

		while ('\0' != *a) {
			// checking that if *r is the start of a utf8 codepoint
			// (it is not 0b10xxxxxx) and we have successfully matched
			// a previous character (0 < offset) - we found a match
			if ((0x80 != (0xc0 & *a)) && (0 < offset)) {
				// found a match, so increment the number of utf8 codepoints
				// that have matched and stop checking whether any other utf8
				// codepoints in a match
				chars++;
				s += offset;
				break;
			} else {
				if (*a == s[offset]) {
					offset++;
					a++;
				} else {
					// a could be in the middle of an unmatching utf8 codepoint,
					// so we need to march it on to the next character beginning,
					do {
						a++;
					} while (0x80 == (0xc0 & *a));

					// reset offset too as we found a mismatch
					offset = 0;
				}
			}
		}

		// if a got to its terminating null byte, then we didn't find a match.
		// Return the current number of matched utf8 codepoints
		if ('\0' == *a) {
			return chars;
		}
	}

	return chars;
}

// The position of the utf8 string needle in the utf8 string haystack.
static void *gy_utf8_str(const void *haystack, const void *needle) noexcept
{
	const char *h = (const char *)haystack;
	int throwaway_codepoint;

	// if needle has no utf8 codepoints before the null terminating
	// byte then return haystack
	if ('\0' == *((const char *)needle)) {
		return (void *)haystack;
	}

	while ('\0' != *h) {
		const char *maybeMatch = h;
		const char *n = (const char *)needle;

		while (*h == *n && (*h != '\0' && *n != '\0')) {
			n++;
			h++;
		}

		if ('\0' == *n) {
			// we found the whole utf8 string for needle in haystack at
			// maybeMatch, so return it
			return (void *)maybeMatch;
		} else {
			// h could be in the middle of an unmatching utf8 codepoint,
			// so we need to march it on to the next character beginning
			// starting from the current character
			h = (const char*)gy_utf8_codepoint(maybeMatch, &throwaway_codepoint);
		}
	}

	// no match
	return nullptr;
}

// The position of the utf8 string needle in the utf8 string haystack, case insensitive.
[[gnu::pure]]
static void *gy_utf8_casestr(const void *haystack, const void *needle) noexcept
{
	const void *h = haystack;

	// if needle has no utf8 codepoints before the null terminating
	// byte then return haystack
	if ('\0' == *((const char *)needle)) {
		return (void *)haystack;
	}

	for (;;) {
		const void *maybeMatch = h;
		const void *n = needle;
		int h_cp, n_cp;

		// Get the next code point and track it
		const void *nextH = h = gy_utf8_codepoint(h, &h_cp);
		n = gy_utf8_codepoint(n, &n_cp);

		while ((0 != h_cp) && (0 != n_cp)) {
			h_cp = gy_utf8_lwrcodepoint(h_cp);
			n_cp = gy_utf8_lwrcodepoint(n_cp);

			// if we find a mismatch, bail out!
			if (h_cp != n_cp) {
				break;
			}

			h = gy_utf8_codepoint(h, &h_cp);
			n = gy_utf8_codepoint(n, &n_cp);
		}

		if (0 == n_cp) {
			// we found the whole utf8 string for needle in haystack at
			// maybeMatch, so return it
			return (void *)maybeMatch;
		}

		if (0 == h_cp) {
			// no match
			return nullptr;
		}

		// Roll back to the next code point in the haystack to test
		h = nextH;
	}
}

// Return 0 on success, or the position of the invalid utf8 codepoint on failure.
[[gnu::pure]]
static void *gy_utf8_valid(const void *str) noexcept
{
	const char *s = (const char *)str;

	while ('\0' != *s) {
		if (0xf0 == (0xf8 & *s)) {
			// ensure each of the 3 following bytes in this 4-byte
			// utf8 codepoint began with 0b10xxxxxx
			if ((0x80 != (0xc0 & s[1])) || (0x80 != (0xc0 & s[2])) ||
					(0x80 != (0xc0 & s[3]))) {
				return (void *)s;
			}

			// ensure that our utf8 codepoint ended after 4 bytes
			if (0x80 == (0xc0 & s[4])) {
				return (void *)s;
			}

			// ensure that the top 5 bits of this 4-byte utf8
			// codepoint were not 0, as then we could have used
			// one of the smaller encodings
			if ((0 == (0x07 & s[0])) && (0 == (0x30 & s[1]))) {
				return (void *)s;
			}

			// 4-byte utf8 code point (began with 0b11110xxx)
			s += 4;
		} else if (0xe0 == (0xf0 & *s)) {
			// ensure each of the 2 following bytes in this 3-byte
			// utf8 codepoint began with 0b10xxxxxx
			if ((0x80 != (0xc0 & s[1])) || (0x80 != (0xc0 & s[2]))) {
				return (void *)s;
			}

			// ensure that our utf8 codepoint ended after 3 bytes
			if (0x80 == (0xc0 & s[3])) {
				return (void *)s;
			}

			// ensure that the top 5 bits of this 3-byte utf8
			// codepoint were not 0, as then we could have used
			// one of the smaller encodings
			if ((0 == (0x0f & s[0])) && (0 == (0x20 & s[1]))) {
				return (void *)s;
			}

			// 3-byte utf8 code point (began with 0b1110xxxx)
			s += 3;
		} else if (0xc0 == (0xe0 & *s)) {
			// ensure the 1 following byte in this 2-byte
			// utf8 codepoint began with 0b10xxxxxx
			if (0x80 != (0xc0 & s[1])) {
				return (void *)s;
			}

			// ensure that our utf8 codepoint ended after 2 bytes
			if (0x80 == (0xc0 & s[2])) {
				return (void *)s;
			}

			// ensure that the top 4 bits of this 2-byte utf8
			// codepoint were not 0, as then we could have used
			// one of the smaller encodings
			if (0 == (0x1e & s[0])) {
				return (void *)s;
			}

			// 2-byte utf8 code point (began with 0b110xxxxx)
			s += 2;
		} else if (0x00 == (0x80 & *s)) {
			// 1-byte ascii (began with 0b0xxxxxxx)
			s += 1;
		} else {
			// we have an invalid 0b1xxxxxxx utf8 code point entry
			return (void *)s;
		}
	}

	return nullptr;
}

// Sets out_codepoint to the next utf8 codepoint in str, and returns the address of the utf8 codepoint after the current one in str.
static void *gy_utf8_codepoint(const void *__restrict__ str, int *__restrict__ out_codepoint) noexcept
{
	const char *s = (const char *)str;

	if (0xf0 == (0xf8 & s[0])) {
		// 4 byte utf8 codepoint
		*out_codepoint = ((0x07 & s[0]) << 18) | ((0x3f & s[1]) << 12) |
			((0x3f & s[2]) << 6) | (0x3f & s[3]);
		s += 4;
	} else if (0xe0 == (0xf0 & s[0])) {
		// 3 byte utf8 codepoint
		*out_codepoint =
			((0x0f & s[0]) << 12) | ((0x3f & s[1]) << 6) | (0x3f & s[2]);
		s += 3;
	} else if (0xc0 == (0xe0 & s[0])) {
		// 2 byte utf8 codepoint
		*out_codepoint = ((0x1f & s[0]) << 6) | (0x3f & s[1]);
		s += 2;
	} else {
		// 1 byte utf8 codepoint otherwise
		*out_codepoint = s[0];
		s += 1;
	}

	return (void *)s;
}

// Returns the size of the given codepoint in bytes.
static size_t gy_utf8_codepointsize(int chr) noexcept
{
	if (0 == ((int)0xffffff80 & chr)) {
		return 1;
	} else if (0 == ((int)0xfffff800 & chr)) {
		return 2;
	} else if (0 == ((int)0xffff0000 & chr)) {
		return 3;
	} else { // if (0 == ((int)0xffe00000 & chr)) 
		return 4;
	}
}

// Write a codepoint to the given string, and return the address to the next
// place after the written codepoint. Pass how many bytes left in the buffer to
// n. If there is not enough space for the codepoint, this function returns
// null.
static void *gy_utf8_catcodepoint(void *__restrict__ str, int chr, size_t n) noexcept
{
	char *s = (char *)str;

	if (0 == ((int)0xffffff80 & chr)) {
		// 1-byte/7-bit ascii
		// (0b0xxxxxxx)
		if (n < 1) {
			return nullptr;
		}
		s[0] = (char)chr;
		s += 1;
	} else if (0 == ((int)0xfffff800 & chr)) {
		// 2-byte/11-bit utf8 code point
		// (0b110xxxxx 0b10xxxxxx)
		if (n < 2) {
			return nullptr;
		}
		s[0] = 0xc0 | (char)(chr >> 6);
		s[1] = 0x80 | (char)(chr & 0x3f);
		s += 2;
	} else if (0 == ((int)0xffff0000 & chr)) {
		// 3-byte/16-bit utf8 code point
		// (0b1110xxxx 0b10xxxxxx 0b10xxxxxx)
		if (n < 3) {
			return nullptr;
		}
		s[0] = 0xe0 | (char)(chr >> 12);
		s[1] = 0x80 | (char)((chr >> 6) & 0x3f);
		s[2] = 0x80 | (char)(chr & 0x3f);
		s += 3;
	} else { // if (0 == ((int)0xffe00000 & chr)) 
		// 4-byte/21-bit utf8 code point
		// (0b11110xxx 0b10xxxxxx 0b10xxxxxx 0b10xxxxxx)
		if (n < 4) {
			return nullptr;
		}
		s[0] = 0xf0 | (char)(chr >> 18);
		s[1] = 0x80 | (char)((chr >> 12) & 0x3f);
		s[2] = 0x80 | (char)((chr >> 6) & 0x3f);
		s[3] = 0x80 | (char)(chr & 0x3f);
		s += 4;
	}

	return s;
}

// Returns true if the given character is lowercase, or false if it is not.
static bool gy_utf8_islower(int chr) noexcept
{ 
	return chr != gy_utf8_uprcodepoint(chr); 
}

// Returns true if the given character is lowercase, or false if it is not.
static bool gy_utf8_isupper(int chr) noexcept
{ 
	return chr != gy_utf8_lwrcodepoint(chr); 
}

// Transform the given string into all lowercase codepoints.
static void gy_utf8_to_lower(void *__restrict__ str) noexcept
{
	void *p, *pn;
	int cp;

	p = (char *)str;
	pn = gy_utf8_codepoint(p, &cp);

	while (cp != 0) {
		const int lwr_cp = gy_utf8_lwrcodepoint(cp);
		const size_t size = gy_utf8_codepointsize(lwr_cp);

		if (lwr_cp != cp) {
			gy_utf8_catcodepoint(p, lwr_cp, size);
		}

		p = pn;
		pn = gy_utf8_codepoint(p, &cp);
	}
}

// Transform the given string into all uppercase codepoints.
static void gy_utf8_to_upper(void *__restrict__ str) noexcept
{
	void *p, *pn;
	int cp;

	p = (char *)str;
	pn = gy_utf8_codepoint(p, &cp);

	while (cp != 0) {
		const int lwr_cp = gy_utf8_uprcodepoint(cp);
		const size_t size = gy_utf8_codepointsize(lwr_cp);

		if (lwr_cp != cp) {
			gy_utf8_catcodepoint(p, lwr_cp, size);
		}

		p = pn;
		pn = gy_utf8_codepoint(p, &cp);
	}
}

// Make a codepoint lower case if possible.
static int gy_utf8_lwrcodepoint(int cp) noexcept
{
	if (((0x0041 <= cp) && (0x005a >= cp)) ||
			((0x00c0 <= cp) && (0x00d6 >= cp)) ||
			((0x00d8 <= cp) && (0x00de >= cp)) ||
			((0x0391 <= cp) && (0x03a1 >= cp)) ||
			((0x03a3 <= cp) && (0x03ab >= cp))) {
		cp += 32;
	} else if (((0x0100 <= cp) && (0x012f >= cp)) ||
			((0x0132 <= cp) && (0x0137 >= cp)) ||
			((0x014a <= cp) && (0x0177 >= cp)) ||
			((0x0182 <= cp) && (0x0185 >= cp)) ||
			((0x01a0 <= cp) && (0x01a5 >= cp)) ||
			((0x01de <= cp) && (0x01ef >= cp)) ||
			((0x01f8 <= cp) && (0x021f >= cp)) ||
			((0x0222 <= cp) && (0x0233 >= cp)) ||
			((0x0246 <= cp) && (0x024f >= cp)) ||
			((0x03d8 <= cp) && (0x03ef >= cp))) {
		cp |= 0x1;
	} else if (((0x0139 <= cp) && (0x0148 >= cp)) ||
			((0x0179 <= cp) && (0x017e >= cp)) ||
			((0x01af <= cp) && (0x01b0 >= cp)) ||
			((0x01b3 <= cp) && (0x01b6 >= cp)) ||
			((0x01cd <= cp) && (0x01dc >= cp))) {
		cp += 1;
		cp &= ~0x1;
	} else {
		switch (cp) {
			default: break;
			case 0x0178: cp = 0x00ff; break;
			case 0x0243: cp = 0x0180; break;
			case 0x018e: cp = 0x01dd; break;
			case 0x023d: cp = 0x019a; break;
			case 0x0220: cp = 0x019e; break;
			case 0x01b7: cp = 0x0292; break;
			case 0x01c4: cp = 0x01c6; break;
			case 0x01c7: cp = 0x01c9; break;
			case 0x01ca: cp = 0x01cc; break;
			case 0x01f1: cp = 0x01f3; break;
			case 0x01f7: cp = 0x01bf; break;
			case 0x0187: cp = 0x0188; break;
			case 0x018b: cp = 0x018c; break;
			case 0x0191: cp = 0x0192; break;
			case 0x0198: cp = 0x0199; break;
			case 0x01a7: cp = 0x01a8; break;
			case 0x01ac: cp = 0x01ad; break;
			case 0x01af: cp = 0x01b0; break;
			case 0x01b8: cp = 0x01b9; break;
			case 0x01bc: cp = 0x01bd; break;
			case 0x01f4: cp = 0x01f5; break;
			case 0x023b: cp = 0x023c; break;
			case 0x0241: cp = 0x0242; break;
			case 0x03fd: cp = 0x037b; break;
			case 0x03fe: cp = 0x037c; break;
			case 0x03ff: cp = 0x037d; break;
			case 0x037f: cp = 0x03f3; break;
			case 0x0386: cp = 0x03ac; break;
			case 0x0388: cp = 0x03ad; break;
			case 0x0389: cp = 0x03ae; break;
			case 0x038a: cp = 0x03af; break;
			case 0x038c: cp = 0x03cc; break;
			case 0x038e: cp = 0x03cd; break;
			case 0x038f: cp = 0x03ce; break;
			case 0x0370: cp = 0x0371; break;
			case 0x0372: cp = 0x0373; break;
			case 0x0376: cp = 0x0377; break;
			case 0x03f4: cp = 0x03d1; break;
			case 0x03cf: cp = 0x03d7; break;
			case 0x03f9: cp = 0x03f2; break;
			case 0x03f7: cp = 0x03f8; break;
			case 0x03fa: cp = 0x03fb; break;
		};
	}

	return cp;
}

// Make a codepoint upper case if possible.
static int gy_utf8_uprcodepoint(int cp) noexcept
{
	if (((0x0061 <= cp) && (0x007a >= cp)) ||
			((0x00e0 <= cp) && (0x00f6 >= cp)) ||
			((0x00f8 <= cp) && (0x00fe >= cp)) ||
			((0x03b1 <= cp) && (0x03c1 >= cp)) ||
			((0x03c3 <= cp) && (0x03cb >= cp))) {
		cp -= 32;
	} else if (((0x0100 <= cp) && (0x012f >= cp)) ||
			((0x0132 <= cp) && (0x0137 >= cp)) ||
			((0x014a <= cp) && (0x0177 >= cp)) ||
			((0x0182 <= cp) && (0x0185 >= cp)) ||
			((0x01a0 <= cp) && (0x01a5 >= cp)) ||
			((0x01de <= cp) && (0x01ef >= cp)) ||
			((0x01f8 <= cp) && (0x021f >= cp)) ||
			((0x0222 <= cp) && (0x0233 >= cp)) ||
			((0x0246 <= cp) && (0x024f >= cp)) ||
			((0x03d8 <= cp) && (0x03ef >= cp))) {
		cp &= ~0x1;
	} else if (((0x0139 <= cp) && (0x0148 >= cp)) ||
			((0x0179 <= cp) && (0x017e >= cp)) ||
			((0x01af <= cp) && (0x01b0 >= cp)) ||
			((0x01b3 <= cp) && (0x01b6 >= cp)) ||
			((0x01cd <= cp) && (0x01dc >= cp))) {
		cp -= 1;
		cp |= 0x1;
	} else {
		switch (cp) {
			default: break;
			case 0x00ff: cp = 0x0178; break;
			case 0x0180: cp = 0x0243; break;
			case 0x01dd: cp = 0x018e; break;
			case 0x019a: cp = 0x023d; break;
			case 0x019e: cp = 0x0220; break;
			case 0x0292: cp = 0x01b7; break;
			case 0x01c6: cp = 0x01c4; break;
			case 0x01c9: cp = 0x01c7; break;
			case 0x01cc: cp = 0x01ca; break;
			case 0x01f3: cp = 0x01f1; break;
			case 0x01bf: cp = 0x01f7; break;
			case 0x0188: cp = 0x0187; break;
			case 0x018c: cp = 0x018b; break;
			case 0x0192: cp = 0x0191; break;
			case 0x0199: cp = 0x0198; break;
			case 0x01a8: cp = 0x01a7; break;
			case 0x01ad: cp = 0x01ac; break;
			case 0x01b0: cp = 0x01af; break;
			case 0x01b9: cp = 0x01b8; break;
			case 0x01bd: cp = 0x01bc; break;
			case 0x01f5: cp = 0x01f4; break;
			case 0x023c: cp = 0x023b; break;
			case 0x0242: cp = 0x0241; break;
			case 0x037b: cp = 0x03fd; break;
			case 0x037c: cp = 0x03fe; break;
			case 0x037d: cp = 0x03ff; break;
			case 0x03f3: cp = 0x037f; break;
			case 0x03ac: cp = 0x0386; break;
			case 0x03ad: cp = 0x0388; break;
			case 0x03ae: cp = 0x0389; break;
			case 0x03af: cp = 0x038a; break;
			case 0x03cc: cp = 0x038c; break;
			case 0x03cd: cp = 0x038e; break;
			case 0x03ce: cp = 0x038f; break;
			case 0x0371: cp = 0x0370; break;
			case 0x0373: cp = 0x0372; break;
			case 0x0377: cp = 0x0376; break;
			case 0x03d1: cp = 0x03f4; break;
			case 0x03d7: cp = 0x03cf; break;
			case 0x03f2: cp = 0x03f9; break;
			case 0x03f8: cp = 0x03f7; break;
			case 0x03fb: cp = 0x03fa; break;
		};
	}

	return cp;
}

/*
 * Search for whole word in a UTF8 string. Word delimiters are as per the separators characters
 */ 
static bool is_whole_word_in_utf8_str(const char *pinput, const char *pword, const char **ppwordlocation = nullptr, bool ignore_case = false, size_t leninput = 0, size_t lenword = 0) noexcept
{
	const char		*pstart = pinput, * const porigstart = pstart, *ptmp, *pend;
	char			c1, c2;
	size_t			wordlen, inputlen;
	const char 	* const	separators = " \t\n\r@.,<>=^-+/*:;?%&(){}[]~$!\"'";
	
	assert(pinput);
	assert(pword);

	if (lenword == 0) {
		wordlen = strlen(pword);	
	}
	else {
		wordlen = lenword;
	}

	if (leninput == 0) {
		inputlen = strlen(pinput);
	}
	else {
		inputlen = leninput;	
	}		
	
	pend = pstart + inputlen;

	do {
		if (ignore_case == false) {
			ptmp = (const char *)gy_utf8_str(pstart, pword);
		}
		else {
			ptmp = (const char *)gy_utf8_casestr(pstart, pword);
		}		

		if (!ptmp) {
			return false;
		}	

		if (ptmp > pstart) {
			c1 = *(ptmp - 1);
			if (!strchr(separators, c1)) {
				pstart = ptmp + wordlen;
				continue;
			}
		}		

		c2 = *(ptmp + wordlen);

		if ((!strchr(separators, c2)) && (c2 != '\0')) {
			pstart = ptmp + wordlen;
			continue;
		}

		if (ppwordlocation) {
			*ppwordlocation = (ptmp);
		}	

		return true;

	} while (pstart + wordlen <= pend && pstart > porigstart);	

	return false;
}	


} // namespace gyeeta

#if defined(__clang__)
#pragma clang diagnostic 		pop
#endif

