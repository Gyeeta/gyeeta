//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma	once

#include 	"gy_common_inc.h"

namespace gyeeta {

/*
 * Updates MD5sum in poutput
 * Returns poutput len or -1 on error
 */   
extern int gy_get_md5sum(const void *pname, size_t sz, uint8_t *poutput, size_t szout) noexcept;

extern int gy_encrypt_buffer(const char *bufferin, size_t szbuf, const char *password, size_t szpass, const char *salt, size_t szsalt, std::string & encrypt_string, const char *algo = "aes256") noexcept;
extern int gy_decrypt_buffer(const char *encbufferin, size_t szbuf, const char *password, size_t szpass, const char *salt, size_t szsalt, std::string & decrypt_string, const char *algo = "aes256") noexcept;

extern int gy_send_email(const char *mailserver, bool use_ssl, bool use_auth, const char *username, const char *password, const char *psubject, const char *pemailbuffer, const char *sender, const char *receipients, char *perrbuf, size_t szerr, const char *file_attach_path = nullptr, bool use_unlock_stdio = false) noexcept;

}

