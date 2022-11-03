//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"
#include			"gy_openssl_pthr.h"

#include	 		"curl/curl.h"

namespace gyeeta {

/*
 * Wrapper to libcurl easy interface.
 * Refer to https://curl.se/libcurl/c/
 *
 * Not Thread safe...
 */

static void gy_curl_free_ptr(void *ptr) noexcept
{
	if (ptr) {
		curl_free(ptr);
	}
}	

class GY_CURL_EASY
{
public :
	GY_CURL_EASY(bool default_options = true) 
	{
		phandle_ = curl_easy_init();

		if (!phandle_) {
			GY_THROW_EXCEPTION("Failed to initialze curl easy handle");
		}	

		if (default_options) {
			set_default_options();
		}

	}	

	GY_CURL_EASY(const GY_CURL_EASY &) 			= delete;
	GY_CURL_EASY & operator= (const GY_CURL_EASY &)		= delete;

	GY_CURL_EASY(GY_CURL_EASY && other) noexcept
		: phandle_(std::exchange(other.phandle_, nullptr)), phdrchunk_(std::exchange(other.phdrchunk_, nullptr)), last_errcode_(other.last_errcode_)
	{
		std::memcpy(errbuf_, other.errbuf_, sizeof(errbuf_));
	}	

	GY_CURL_EASY & operator= (GY_CURL_EASY && other) noexcept
	{
		if (this != &other) {
			this->~GY_CURL_EASY();

			new (this) GY_CURL_EASY(std::move(other));
		}

		return *this;
	}

	~GY_CURL_EASY() noexcept
	{
		if (phandle_) {
			curl_easy_cleanup(phandle_);
			phandle_ = nullptr;
		}	

		if (phdrchunk_) {
			curl_slist_free_all(phdrchunk_);
			phdrchunk_ = nullptr;
		}	

		*errbuf_ = 0;
	}	

	GY_CURL_EASY & set_default_options() noexcept
	{
		if (!phandle_) return *this;

		curl_easy_setopt(phandle_, CURLOPT_NOSIGNAL, 1L);		// Do not modify SIGPIPE signal handler
		curl_easy_setopt(phandle_, CURLOPT_ACCEPT_ENCODING, "");	// Accept all supported built-in compressions

		curl_easy_setopt(phandle_, CURLOPT_TCP_KEEPALIVE, 1L);

		curl_easy_setopt(phandle_, CURLOPT_TIMEOUT, 60L);
		curl_easy_setopt(phandle_, CURLOPT_FAILONERROR, 1L);		// Fail on all 4xx/5xx HTTP status codes

		curl_easy_setopt(phandle_, CURLOPT_MAXLIFETIME_CONN, 300L);	// Limit each connection to max 5 min

		return *this;
	}	

	GY_CURL_EASY & set_url(const char *url) noexcept
	{
		curl_easy_setopt(phandle_, CURLOPT_URL, url);

		return *this;
	}

	GY_CURL_EASY & set_http_post_data(const char *data, size_t datalen, bool make_copy) noexcept
	{
		curl_easy_setopt(phandle_, CURLOPT_POSTFIELDSIZE, ssize_t(datalen));

		if (!make_copy) {
			curl_easy_setopt(phandle_, CURLOPT_POSTFIELDS, data);
		}	
		else {
			curl_easy_setopt(phandle_, CURLOPT_COPYPOSTFIELDS, data);
		}	

		return *this;
	}	

	template <size_t N>
	GY_CURL_EASY & set_http_post_data(const char (&str)[N]) noexcept
	{
		return set_http_post_data(str, N - 1, false /* make_copy */);
	}

	template <size_t N>
	GY_CURL_EASY & set_http_post_data(char (&str)[N]) noexcept		= delete;

	GY_CURL_EASY & set_content_json() noexcept
	{
		set_http_header("Content-Type: application/json");

		return *this;
	}	

	/*
	 * The default timeout if default_options == true during construction is 60 sec
	 */
	GY_CURL_EASY & set_timeout_sec(int64_t sec) noexcept
	{
		curl_easy_setopt(phandle_, CURLOPT_TIMEOUT, sec);

		return *this;
	}	

	/*
	 * Fail on all 4xx/5xx HTTP status codes
	 * At construction if default_options == true, we set fail on error. Pass false if you want to handle errors yourself
	 */
	GY_CURL_EASY & set_fail_on_http_error(bool tofail = true) noexcept
	{
		curl_easy_setopt(phandle_, CURLOPT_FAILONERROR, long(tofail));

		return *this;
	}	

	GY_CURL_EASY & set_redirects(bool allow_redirect = true, size_t maxredirects = 32) noexcept
	{
		curl_easy_setopt(phandle_, CURLOPT_FOLLOWLOCATION, long(allow_redirect));
		curl_easy_setopt(phandle_, CURLOPT_MAXREDIRS, maxredirects);

		return *this;
	}	

	// To delete a previously added header pass an empty header e.g. "Accept:"
	GY_CURL_EASY & set_http_header(const char *phdr) noexcept 
	{
		if (!phdr) {
			return *this;
		}

		auto			*plist = curl_slist_append(phdrchunk_, phdr);

		if (plist) {
			phdrchunk_ = plist;
			return *this;
		}	
		
		reset_headers();

		return *this;
	}

	GY_CURL_EASY & set_response_callback(size_t (* prespcb)(void *contents, size_t size, size_t nmemb, void *userp), void *cb_priv_data = nullptr) noexcept
	{
		curl_easy_setopt(phandle_, CURLOPT_WRITEFUNCTION, prespcb);

		if (cb_priv_data) {
			curl_easy_setopt(phandle_, CURLOPT_WRITEDATA, cb_priv_data);
		}

		return *this;
	}	

	GY_CURL_EASY & set_hdr_response_callback(size_t (* phdrcb)(void *contents, size_t size, size_t nmemb, void *userp), void *cb_priv_data = nullptr) noexcept
	{
		curl_easy_setopt(phandle_, CURLOPT_HEADERFUNCTION, phdrcb);

		if (cb_priv_data) {
			curl_easy_setopt(phandle_, CURLOPT_HEADERDATA, cb_priv_data);
		}

		return *this;
	}	

	GY_CURL_EASY & set_user_agent(const char *useragent) noexcept 
	{
		curl_easy_setopt(phandle_, CURLOPT_USERAGENT, useragent);

		return *this;
	}	

	GY_CURL_EASY & set_http_get() noexcept
	{
		curl_easy_setopt(phandle_, CURLOPT_HTTPGET, 1L);
		curl_easy_setopt(phandle_, CURLOPT_CUSTOMREQUEST, "GET");

		return *this;
	}

	GY_CURL_EASY & set_http_post() noexcept
	{
		curl_easy_setopt(phandle_, CURLOPT_POST, 1L);
		curl_easy_setopt(phandle_, CURLOPT_CUSTOMREQUEST, "POST");

		return *this;
	}

	GY_CURL_EASY & set_http_put() noexcept
	{
		curl_easy_setopt(phandle_, CURLOPT_CUSTOMREQUEST, "PUT");

		return *this;
	}

	GY_CURL_EASY & set_http_delete() noexcept
	{
		curl_easy_setopt(phandle_, CURLOPT_CUSTOMREQUEST, "DELETE");

		return *this;
	}

	// Use to send HTTP PUT/DELETE etc e.g. pass "DELETE" fo a HTTP DELETE
	GY_CURL_EASY & set_custom_http_request(const char *ptype) noexcept 
	{
		curl_easy_setopt(phandle_, CURLOPT_CUSTOMREQUEST, ptype);

		return *this;
	}	

	GY_CURL_EASY & set_ssl_verify(bool verify) noexcept
	{
		if (!verify) {
			curl_easy_setopt(phandle_, CURLOPT_SSL_VERIFYPEER, 0L); 
			curl_easy_setopt(phandle_, CURLOPT_SSL_VERIFYHOST, 0L);
		}
		else {
			curl_easy_setopt(phandle_, CURLOPT_SSL_VERIFYPEER, 1L); 
			curl_easy_setopt(phandle_, CURLOPT_SSL_VERIFYHOST, 2L);
		}	

		return *this;
	}	

	// Returns {isok, status_code, errorstr} 
	std::tuple<bool, int64_t, const char *> send_request_blocking() noexcept 
	{
		CURLcode 		res;

		if (phdrchunk_) {
			curl_easy_setopt(phandle_, CURLOPT_HTTPHEADER, phdrchunk_);
		}	
		
		last_errcode_ 	= 0;
		*errbuf_ 	= 0;
		
		curl_easy_setopt(phandle_, CURLOPT_ERRORBUFFER, errbuf_);	 	

		res = curl_easy_perform(phandle_);

		if (res != CURLE_OK) {
			size_t 			len = strlen(errbuf_);

			if (!len) {
				GY_STRNCPY(errbuf_, curl_easy_strerror(res), sizeof(errbuf_));
			}	

			if (len > 0 && errbuf_[len - 1] == '\n') {
				errbuf_[len - 1] = 0;
			}	
		}

		curl_easy_getinfo(phandle_, CURLINFO_RESPONSE_CODE, &last_errcode_);

		return {res == CURLE_OK, last_errcode_, errbuf_};
	}

	bool is_last_status_error() const noexcept
	{
		return last_errcode_ >= 400;
	}

	int64_t get_last_status_code() const noexcept
	{
		return last_errcode_;
	}	

	const char * get_last_error() const noexcept
	{
		return errbuf_;
	}	

	void reset_headers() noexcept 
	{
		curl_easy_setopt(phandle_, CURLOPT_HTTPHEADER, nullptr);

		if (phdrchunk_) {
			curl_slist_free_all(phdrchunk_);
			phdrchunk_ = nullptr;
		}	
	}

	// Does not close connection, the Session ID cache and cookies remain same
	void reset_handle(bool to_reset_headers) noexcept 
	{
		if (to_reset_headers) {
			reset_headers();
		}	
		
		curl_easy_reset(phandle_);
	}

	CURL * get_handle() const noexcept
	{
		return phandle_;
	}	

	using unique_char_t = std::unique_ptr<char, decltype(&gy_curl_free_ptr)>;

	unique_char_t url_encode(const char *string, int length) noexcept
	{
		return unique_char_t(curl_easy_escape(phandle_, string, length), &gy_curl_free_ptr);
	}	

	unique_char_t url_decode(const char *encstring, int inlength, int * poutlen = nullptr) noexcept
	{
		return unique_char_t(curl_easy_unescape(phandle_, encstring, inlength, poutlen), &gy_curl_free_ptr);
	}	

	static void global_init() noexcept
	{
		curl_global_init(CURL_GLOBAL_ALL);
		gy_ssl_pthread_init();
	}	

	static void global_cleanup() noexcept
	{
		curl_global_cleanup();
	}	


protected :

	CURL			*phandle_			{nullptr};
	struct curl_slist 	*phdrchunk_ 			{nullptr};
	int64_t			last_errcode_			{0};
	char 			errbuf_[CURL_ERROR_SIZE]	{};
};	

} // namespace gyeeta

