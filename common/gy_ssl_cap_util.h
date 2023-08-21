//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"


namespace gyeeta {

static constexpr size_t			MAX_LIB_UPROBE_FUNCS			{24};

enum SSL_LIB_TYPE : uint8_t
{
	SSL_LIB_UNKNOWN			= 0,
	SSL_LIB_OPENSSL,
	SSL_LIB_GNUTLS,
};

class SSL_LIB_INFO
{
public :

	uint64_t			tstartns_				{get_nsec_time()};
	const char			*libname_				{nullptr};
	char				path_[GY_PATH_MAX];

	const char 			*funcarr_[MAX_LIB_UPROBE_FUNCS]		{};
	off_t				offsetarr_[MAX_LIB_UPROBE_FUNCS]	{};
	uint32_t			nfuncs_					{0};

	ino_t				inode_					{0};
	pid_t				init_pid_				{0};
	SSL_LIB_TYPE			libtype_				{SSL_LIB_UNKNOWN};

	bool				is_deleted_				{false};
	bool				is_static_binary_			{false};
	bool				is_go_binary_				{false};
	bool				newmount_				{false};

	static constexpr const char	openssl_libname[]			{"libssl.so"};
	static constexpr const char	gnutls_libname[]			{"libgnutls.so"};
	
	static const char *		ssl_libtype_to_string(SSL_LIB_TYPE libtype) noexcept
	{
		if (libtype == SSL_LIB_OPENSSL) return openssl_libname;
		else if (libtype == SSL_LIB_GNUTLS) return gnutls_libname;

		return "unknown";
	}	

	SSL_LIB_INFO(pid_t pid, SSL_LIB_TYPE libtype, const char *path, const char *funcarr[], off_t offsetarr[], size_t nfuncs, 
			ino_t inode, bool is_deleted, bool is_static_binary, bool is_go_binary, bool newmount) noexcept
		: libname_(ssl_libtype_to_string(libtype)), nfuncs_(nfuncs), inode_(inode), init_pid_(pid), libtype_(libtype), 
		is_deleted_(is_deleted), is_static_binary_(is_static_binary), is_go_binary_(is_go_binary), newmount_(newmount)
	{
		GY_STRNCPY(path_, path, sizeof(path_));

		if (nfuncs_ > MAX_LIB_UPROBE_FUNCS) nfuncs_ = MAX_LIB_UPROBE_FUNCS; 

		std::memcpy(funcarr_, funcarr, nfuncs_ * sizeof(*funcarr_));
		std::memcpy(offsetarr_, offsetarr, nfuncs_ * sizeof(*offsetarr_));
	}	

	CHAR_BUF<GY_PATH_MAX> get_hash_buf() const noexcept
	{
		return gy_to_charbuf<GY_PATH_MAX>("%s_%lu", path_, inode_);
	}

	const char * print(STR_WR_BUF & strbuf) const noexcept;

};	

std::unique_ptr<SSL_LIB_INFO> 		get_pid_ssl_lib(pid_t pid, int & retcode, char (&errorbuf)[256]);

} // namespace gyeeta

