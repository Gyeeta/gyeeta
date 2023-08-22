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
	char				filepath_[GY_PATH_MAX];

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

	static constexpr const char	*opensslfuncs[] = {
		"SSL_do_handshake", "SSL_read", "SSL_read_ex", "SSL_write", "SSL_write_ex", "SSL_shutdown",
	};

	static_assert(GY_ARRAY_SIZE(opensslfuncs) < MAX_LIB_UPROBE_FUNCS, "Please update MAX_LIB_UPROBE_FUNCS");

	static constexpr const char	*gnutlsfuncs[] = {
		"gnutls_handshake", "gnutls_transport_set_int2", "gnutls_transport_set_ptr", "gnutls_transport_set_ptr2",
		"gnutls_record_recv", "gnutls_record_send", "gnutls_bye", "gnutls_deinit",
	};

	static_assert(GY_ARRAY_SIZE(gnutlsfuncs) < MAX_LIB_UPROBE_FUNCS, "Please update MAX_LIB_UPROBE_FUNCS");
	
	static const char *		ssl_libtype_to_string(SSL_LIB_TYPE libtype) noexcept
	{
		if (libtype == SSL_LIB_OPENSSL) return openssl_libname;
		else if (libtype == SSL_LIB_GNUTLS) return gnutls_libname;

		return "unknown";
	}	

	/*
	 * path => Current Mount NS valid path to file
	 * filepath => Path as per /proc/pid/maps (which may not be current mount ns valid
	 */
	SSL_LIB_INFO(pid_t pid, SSL_LIB_TYPE libtype, const char *path, const char *filepath, const char *funcarr[], off_t offsetarr[], size_t nfuncs, 
			ino_t inode, bool is_deleted, bool is_static_binary, bool is_go_binary, bool newmount) noexcept
		: libname_(ssl_libtype_to_string(libtype)), nfuncs_(nfuncs), inode_(inode), init_pid_(pid), libtype_(libtype), 
		is_deleted_(is_deleted), is_static_binary_(is_static_binary), is_go_binary_(is_go_binary), newmount_(newmount)
	{
		GY_STRNCPY(path_, path, sizeof(path_));
		GY_STRNCPY(filepath_, filepath, sizeof(filepath_));

		if (nfuncs_ > MAX_LIB_UPROBE_FUNCS) nfuncs_ = MAX_LIB_UPROBE_FUNCS; 

		std::memcpy(funcarr_, funcarr, nfuncs_ * sizeof(*funcarr_));
		std::memcpy(offsetarr_, offsetarr, nfuncs_ * sizeof(*offsetarr_));
	}	

	CHAR_BUF<GY_PATH_MAX> get_hash_buf() const noexcept
	{
		CHAR_BUF<GY_PATH_MAX>		hbuf;
		int				ret;

		ret = snprintf(hbuf.get(), sizeof(hbuf), "%s@%lu", filepath_, inode_);

		if ((unsigned)ret < sizeof(hbuf)) {
			std::memset(hbuf.get() + ret, 0, sizeof(hbuf) - ret);
		}	

		return hbuf;
	}

	const char * print(STR_WR_BUF & strbuf) const noexcept;

	bool is_static_lib() const noexcept
	{
		return is_static_binary_;
	}	

	bool is_file_deleted() const noexcept
	{
		return is_deleted_;
	}	

	bool is_diff_mount_ns() const noexcept
	{
		return newmount_;
	}	

	bool is_go_binary() const noexcept
	{
		return is_go_binary_;
	}	

	// Returns 0 if not present
	off_t get_func_offset(const char *func) const noexcept
	{
		for (int i = 0; i < (int)nfuncs_; ++i) {
			if (func == funcarr_[i]) {
				return offsetarr_[i];
			}	
		}	

		// Try strcmp 
		for (int i = 0; i < (int)nfuncs_; ++i) {
			if (0 == strcmp(func, funcarr_[i])) {
				return offsetarr_[i];
			}	
		}	

		return 0;
	}	

	const char * get_mount_ns_safe_path() const noexcept
	{
		return path_;
	}	

	// May not be Mount NS safe
	const char * get_file_path() const noexcept
	{
		return filepath_;
	}	

	ino_t get_file_inode() const noexcept
	{
		return inode_;
	}	

	SSL_LIB_TYPE get_lib_type() const noexcept
	{
		return libtype_;
	}	
};	

std::unique_ptr<SSL_LIB_INFO> 		get_pid_ssl_lib(pid_t pid, int & retcode, char (&errorbuf)[256]);

} // namespace gyeeta

