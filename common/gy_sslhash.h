//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma			once

#include 		"gy_common_inc.h"

#include 		<openssl/evp.h>

namespace gyeeta {

enum GY_HASH_ALGO_E : uint8_t
{
	GY_HASH_MD5		= 0,
	GY_HASH_SHA1,
	GY_HASH_SHA224,
	GY_HASH_SHA256,
	GY_HASH_SHA512,
};

/*
 * Returns size of the outbuf updated or -1 on error with errbuf updated with error string.
 * maxoutlen should be EVP_MAX_MD_SIZE (64 bytes)
 */
static int gy_get_ssl_hash(std::string_view input, uint8_t *outbuf, uint32_t maxoutlen, char (&errbuf)[256], GY_HASH_ALGO_E hash_algo = GY_HASH_SHA256) noexcept
{
	EVP_MD_CTX 			*pctx = EVP_MD_CTX_new();

	if (pctx == nullptr) {
		GY_STRNCPY(errbuf, "Failed to create SSL Hash context", sizeof(errbuf));
		return -1;
	}

	GY_SCOPE_EXIT {
		EVP_MD_CTX_free(pctx);
	};	

	const EVP_MD			*pmd;
	uint32_t			output_len = 0;

	switch (hash_algo) {

	case GY_HASH_MD5	: 	pmd = EVP_md5(); break;
	case GY_HASH_SHA1	:	pmd = EVP_sha1(); break;
	case GY_HASH_SHA224	:	pmd = EVP_sha224(); break;
	case GY_HASH_SHA256	:	pmd = EVP_sha256(); break;
	case GY_HASH_SHA512	:	pmd = EVP_sha512(); break;

	default			:	GY_STRNCPY(errbuf, "Invalid SSL Hash Algo specified", sizeof(errbuf)); return -1;	
	}

	if (maxoutlen < (size_t)EVP_MD_size(pmd)) {
		snprintf(errbuf, sizeof(errbuf), "SSL Digest Output Buffer length %u too small", maxoutlen);
		return -1;
	}

	if (1 != EVP_DigestInit_ex(pctx, pmd, nullptr)) {
		GY_STRNCPY(errbuf, "SSL Digest initialization failed", sizeof(errbuf));
		return -1;
	}

	if (1 != EVP_DigestUpdate(pctx, input.data(), input.size())) {
		GY_STRNCPY(errbuf, "SSL Digest update failed", sizeof(errbuf));
		return -1;
	}

	if (1 != EVP_DigestFinal_ex(pctx, outbuf, &output_len)) {
		GY_STRNCPY(errbuf, "SSL Digest finalization failed", sizeof(errbuf));
		return -1;
	}

	if (output_len != (size_t)EVP_MD_size(pmd)) {
		snprintf(errbuf, sizeof(errbuf), "SSL Digest Output length %u invalid", output_len);
		return -1;
	}

	return (int)output_len;
}	

static BIN_BUFFER<EVP_MAX_MD_SIZE> gy_get_ssl_hash(std::string_view input, GY_HASH_ALGO_E hash_algo = GY_HASH_SHA256)
{
	BIN_BUFFER<EVP_MAX_MD_SIZE>	obuf;
	char 				errbuf[256];
	int				olen;

	olen = gy_get_ssl_hash(input, obuf.get(), obuf.maxsz(), errbuf, hash_algo);

	if (olen <= 0) {
		GY_THROW_EXPRESSION("%s", errbuf);
	}

	obuf.set_len_external(olen);

	return obuf;
}	


} // namespace gyeeta

