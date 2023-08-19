//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_ssl_cap_util.h"
#include			"gy_misc.h"
#include			"gy_elf.h"

namespace gyeeta {

static constexpr const char	*opensslfuncs[] = {
	"SSL_do_handshake", "SSL_read", "SSL_read_ex", "SSL_write", "SSL_write_ex", "SSL_shutdown",
};

static constexpr const char	*gnutlsfuncs[] = {
	"gnutls_handshake", "gnutls_transport_set_int2", "gnutls_transport_set_ptr", "gnutls_transport_set_ptr2",
	"gnutls_record_recv", "gnutls_record_send", "gnutls_bye", "gnutls_deinit",
};

static_assert(GY_ARRAY_SIZE(opensslfuncs) < MAX_LIB_UPROBE_FUNCS, "Please update MAX_LIB_UPROBE_FUNCS");

static_assert(GY_ARRAY_SIZE(gnutlsfuncs) < MAX_LIB_UPROBE_FUNCS, "Please update MAX_LIB_UPROBE_FUNCS");


static bool verifyfuncs(const char *funcarr[], size_t nfuncs, off_t offsetarr[]) noexcept
{
	for (int i = 0; i < (int)nfuncs; ++i) {
		if (funcarr[i] && !offsetarr[i]) {
			return false;
		}	
	}	

	return true;
};	

std::unique_ptr<SSL_LIB_INFO> get_pid_ssl_lib(pid_t pid, int & retcode, char (&errorbuf)[256])
{
	constexpr uint32_t		maxfunc 		{GY_ARRAY_SIZE(opensslfuncs) + GY_ARRAY_SIZE(gnutlsfuncs)};
	const char 			*funcarr[maxfunc]	{};
	off_t				offsetarr[maxfunc]	{};
	uint32_t			nfuncs			{0};
	SSL_LIB_TYPE			libtype			{SSL_LIB_UNKNOWN};

	ssize_t				sret;
	char				pathbuf[GY_PATH_MAX], errbuf[256];
	int				ret;
	bool				is_deleted = false, bret, is_static_binary = false, newmount = false, is_error = false;
	
	std::unique_ptr<SSL_LIB_INFO>	ssluniq;

	const auto liblam = [&](const char *plibname, const char *plibpath, const char *pline, bool is_lib_deleted) -> CB_RET_E
	{
		int			id = -1;

		if (string_starts_with(plibname, SSL_LIB_INFO::openssl_libname, false, sizeof(SSL_LIB_INFO::openssl_libname) - 1)) {
			libtype		= SSL_LIB_OPENSSL;
			
			nfuncs		= GY_ARRAY_SIZE(opensslfuncs); 
			std::memcpy(funcarr, opensslfuncs, sizeof(opensslfuncs));
		}	
		else if (string_starts_with(plibname, SSL_LIB_INFO::gnutls_libname, false, sizeof(SSL_LIB_INFO::gnutls_libname) - 1)) {
			libtype		= SSL_LIB_GNUTLS;

			nfuncs		= GY_ARRAY_SIZE(gnutlsfuncs); 
			std::memcpy(funcarr, gnutlsfuncs, sizeof(gnutlsfuncs));
		}	
		else {
			return CB_OK;
		}	

		if (!is_lib_deleted) {
			GY_STRNCPY(pathbuf, get_ns_safe_file_path(pid, plibpath, errbuf, &newmount).get(), sizeof(pathbuf));

			if (0 == *pathbuf) {
				is_error = true;
			}	
		}	
		else {
			if (plibpath <= pline) {
				return CB_BREAK_LOOP;
			}	

			const char		*pspace = (const char *)memchr(pline, ' ', plibpath - pline);
			char			buf[sizeof("ffffffffffffffff-ffffffffffffffff") + 2];
			
			if (!pspace || (size_t(pspace - pline) >= sizeof(buf)) || (pspace == pline)) {
				return CB_BREAK_LOOP;
			}

			std::memcpy(buf, pline, pspace - pline);
			buf[pspace - pline] = 0;

			snprintf(pathbuf, sizeof(pathbuf), "/proc/%d/map_files/%s", pid, buf);
			is_deleted = true;
		}	

		return CB_BREAK_LOOP;
	};	

	*pathbuf = 0;
	*errbuf = 0;

	ret = walk_proc_pid_map_libs(pid, liblam);
	
	if ((ret < 0) || is_error) {
		retcode = -1;
		snprintf(errorbuf, sizeof(errorbuf), "Failed to get PID %d info : %s", pid, *errbuf ? errbuf : gy_get_perror().get());
		return ssluniq;
	}	

	if (libtype == SSL_LIB_UNKNOWN) {
		// Check if its a statically linked lib
		char			buf[GY_PATH_MAX];

		sret = get_task_exe_path(pid, buf, sizeof(buf) - 1, -1, &is_deleted);

		if (sret < 0) {
			retcode = -1;
			snprintf(errorbuf, sizeof(errorbuf), "Failed to get PID %d exe info : %s", pid, gy_get_perror().get());
			return ssluniq;
		}

		if (!is_deleted) {
			GY_STRNCPY(pathbuf, get_ns_safe_file_path(pid, buf, errbuf, &newmount).get(), sizeof(pathbuf));

			if (0 == *pathbuf) {
				retcode = -1;
				snprintf(errorbuf, sizeof(errorbuf), "Failed to get PID %d mount safe exe path : %s", 
						pid, *errbuf ? errbuf : gy_get_perror().get());
				return ssluniq;
			}	
		}
		else {
			snprintf(pathbuf, sizeof(pathbuf), "/proc/%d/exe", pid);
		}	

		std::memcpy(funcarr, opensslfuncs, sizeof(opensslfuncs));
		std::memcpy(funcarr + GY_ARRAY_SIZE(opensslfuncs), gnutlsfuncs, sizeof(gnutlsfuncs));

		nfuncs = GY_ARRAY_SIZE(opensslfuncs) + GY_ARRAY_SIZE(gnutlsfuncs);
	}	

	GY_ELF_UTIL			elf(pathbuf, ret, errbuf);
	struct stat			stat1;

	if (ret != 0) {
		retcode = -1;
		snprintf(errorbuf, sizeof(errorbuf), "Failed to get PID %d ELF info : %s", pid, errbuf);
		return ssluniq;
	}	
	
	if (nfuncs == 0 || nfuncs > maxfunc) {
		retcode = -1;
		snprintf(errorbuf, sizeof(errorbuf), "Internal Error : Failed to set probe function list for PID %d", pid);
		return ssluniq;
	}	

	sret = elf.find_func_offsets(funcarr, nfuncs, offsetarr);

	if (sret <= 0) {
		retcode = 0;
		*errorbuf = 0;

		return ssluniq;
	}	

	if (libtype == SSL_LIB_UNKNOWN) {

		bret = verifyfuncs(funcarr, GY_ARRAY_SIZE(opensslfuncs), offsetarr);
		if (!bret) {
			bret = verifyfuncs(&funcarr[GY_ARRAY_SIZE(opensslfuncs)], GY_ARRAY_SIZE(gnutlsfuncs), offsetarr + GY_ARRAY_SIZE(opensslfuncs));
			if (!bret) {
				retcode = 0;
				*errorbuf = 0;

				return ssluniq;
			}	
			libtype = SSL_LIB_GNUTLS;
		}	
		else {
			libtype = SSL_LIB_OPENSSL;
		}	

		is_static_binary = true;

	}
	else {
		bret = verifyfuncs(funcarr, nfuncs, offsetarr);
		if (!bret) {
			retcode = 0;
			*errorbuf = 0;

			return ssluniq;
		}
	}	

	ret = stat(pathbuf, &stat1);
	if (ret != 0) {
		retcode = -1;
		snprintf(errorbuf, sizeof(errorbuf), "Failed to stat PID %d ELF file %s : %s", pid, pathbuf, gy_get_perror().get());
		return ssluniq;
	}	

	ssluniq = std::make_unique<SSL_LIB_INFO>(pid, libtype, pathbuf, funcarr, offsetarr, nfuncs, stat1.st_ino, is_deleted, is_static_binary, 
							elf.is_go_binary(), newmount);

	return ssluniq;
}	

const char * SSL_LIB_INFO::print(STR_WR_BUF & strbuf) const noexcept
{
	strbuf.appendconst("SSL Library Probe Info : ");

	if (libtype_ == SSL_LIB_UNKNOWN) {
		strbuf << "SSL Library unknown...";
		return strbuf.data();
	}	

	strbuf << "SSL Library " << libname_ << " : Path " << path_ << " : Init PID " << init_pid_;
	
	if (is_deleted_) strbuf << " : File is deleted";
	if (is_static_binary_) strbuf << " : SSL Library is statically linked";
	if (is_go_binary_) strbuf << " : File is a Go Language binary";
	if (newmount_) strbuf << " : File is from a separate Mount Namespace";

	strbuf << "\n\n";

	return strbuf.data();
}

} // namespace gyeeta

