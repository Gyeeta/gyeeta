//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_ssl_cap_util.h"
#include			"gy_misc.h"
#include			"gy_elf.h"

namespace gyeeta {

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
	constexpr uint32_t		maxfunc 		{GY_ARRAY_SIZE(SSL_LIB_INFO::opensslfuncs)};
	const char 			*funcarr[maxfunc]	{};
	off_t				offsetarr[maxfunc]	{};
	uint32_t			nfuncs			{0};
	SSL_LIB_TYPE			libtype			{SSL_LIB_UNKNOWN};

	ssize_t				sret;
	char				pathbuf[GY_PATH_MAX], filepath[GY_PATH_MAX], errbuf[256];
	int				ret;
	bool				is_deleted = false, bret, is_static_binary = false, newmount = false, is_error = false;
	
	std::unique_ptr<SSL_LIB_INFO>	ssluniq;

	const auto liblam = [&](const char *plibname, const char *plibpath, const char *pline, bool is_lib_deleted) -> CB_RET_E
	{
		int			id = -1;

		if (string_starts_with(plibname, SSL_LIB_INFO::openssl_libname, false, sizeof(SSL_LIB_INFO::openssl_libname) - 1)) {
			libtype		= SSL_LIB_OPENSSL;
			
			nfuncs		= GY_ARRAY_SIZE(SSL_LIB_INFO::opensslfuncs); 
			std::memcpy(funcarr, SSL_LIB_INFO::opensslfuncs, sizeof(SSL_LIB_INFO::opensslfuncs));
		}	
		else {
			return CB_OK;
		}	

		GY_STRNCPY(filepath, plibpath, sizeof(filepath));

		if (!is_lib_deleted) {
			GY_STRNCPY(pathbuf, get_ns_safe_file_path(pid, plibpath, errbuf, &newmount).get(), sizeof(pathbuf));

			if (0 == *pathbuf) {
				is_error = true;
			}	
		}	
		else {
			if (plibpath <= pline) {
				is_error = true;
				return CB_BREAK_LOOP;
			}	

			const char		*pspace = (const char *)memchr(pline, ' ', plibpath - pline);
			char			buf[sizeof("ffffffffffffffff-ffffffffffffffff") + 2];
			
			if (!pspace || (size_t(pspace - pline) >= sizeof(buf)) || (pspace == pline)) {
				is_error = true;
				return CB_BREAK_LOOP;
			}

			std::memcpy(buf, pline, pspace - pline);
			buf[pspace - pline] = 0;

			snprintf(pathbuf, sizeof(pathbuf), "/proc/%d/map_files/%s", pid, buf);
			is_deleted = true;
		}	

		if (libtype != SSL_LIB_OPENSSL) {
			// We scan further libs to see if openssl is used
			return CB_OK;
		}

		return CB_BREAK_LOOP;
	};	

	*pathbuf = 0;
	*filepath = 0;
	*errbuf = 0;

	ret = walk_proc_pid_map_libs(pid, liblam);
	
	if ((ret < 0) || is_error) {
		retcode = -1;
		snprintf(errorbuf, sizeof(errorbuf), "Failed to get PID %d info : %s", pid, *errbuf ? errbuf : gy_get_perror().get());
		return ssluniq;
	}	

	if (libtype == SSL_LIB_UNKNOWN) {
		// Check if its a statically linked lib
		char			buf[GY_PATH_MAX], *ptmp;

		sret = get_task_exe_path(pid, buf, sizeof(buf) - 1, -1, &is_deleted);

		if (sret < 0) {
			retcode = -1;
			snprintf(errorbuf, sizeof(errorbuf), "Failed to get PID %d exe info : %s", pid, gy_get_perror().get());
			return ssluniq;
		}

		ptmp = strrchr(buf, '/');
		if (ptmp) {
			ptmp++;
		}	
		else {
			ptmp = buf;
		}	

		GY_STRNCPY(filepath, ptmp, sizeof(filepath));

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

		std::memcpy(funcarr, SSL_LIB_INFO::opensslfuncs, sizeof(SSL_LIB_INFO::opensslfuncs));

		nfuncs = GY_ARRAY_SIZE(SSL_LIB_INFO::opensslfuncs);
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

		bret = verifyfuncs(funcarr, GY_ARRAY_SIZE(SSL_LIB_INFO::opensslfuncs), offsetarr);
		if (!bret) {
			retcode = 0;
			*errorbuf = 0;

			return ssluniq;
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

	ssluniq = std::make_unique<SSL_LIB_INFO>(pid, libtype, pathbuf, filepath, funcarr, offsetarr, nfuncs, stat1.st_ino, is_deleted, is_static_binary, 
							elf.is_go_binary(), newmount);

	return ssluniq;
}	

const char * SSL_LIB_INFO::print(STR_WR_BUF & strbuf) const noexcept
{
	strbuf << "SSL Library Probe Info : "sv;

	if (libtype_ == SSL_LIB_UNKNOWN) {
		strbuf << "SSL Library unknown..."sv;
		return strbuf.data();
	}	

	strbuf << "SSL Library "sv << libname_ << " : Path "sv << path_ << " : Init PID "sv << init_pid_ << " : Inode "sv << inode_;
	
	if (is_deleted_) 	strbuf << " : File is deleted"sv;
	if (is_static_binary_) 	strbuf << " : SSL Library is statically linked"sv;
	if (is_go_binary_) 	strbuf << " : File is a Go Language binary"sv;
	if (newmount_) 		strbuf << " : File is from a separate Mount Namespace"sv;

	strbuf << "\n\n"sv;

	return strbuf.data();
}

} // namespace gyeeta

