//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later


#include 	"Poco/MD5Engine.h"
#include 	"gy_crypto.h"

#include 	<sys/wait.h>
#include 	<sys/prctl.h>

#include	"gy_file_api.h"
#include	"gy_misc.h"
#include 	<zlib.h>

#include 	"Poco/Net/MailMessage.h"
#include 	"Poco/Net/MailRecipient.h"
#include 	"Poco/Net/SecureSMTPClientSession.h"
#include 	"Poco/Net/StringPartSource.h"
#include 	"Poco/Net/SSLManager.h"
#include 	"Poco/Net/KeyConsoleHandler.h"
#include 	"Poco/Net/AcceptCertificateHandler.h"
#include 	"Poco/SharedPtr.h"
#include 	"Poco/Path.h"
#include 	"Poco/Exception.h"
#include 	"Poco/Crypto/CipherFactory.h"
#include 	"Poco/Crypto/Cipher.h"
#include 	"Poco/Crypto/CipherKey.h"

namespace gyeeta {

int gy_get_md5sum(const void *pname, size_t sz, uint8_t *poutput, size_t szout) noexcept
{
	using 		Poco::DigestEngine;
	using 		Poco::MD5Engine;

	uint32_t 	i = 0;

	try {
		Poco::MD5Engine 			engine;
		
		engine.update(pname, sz);

		Poco::DigestEngine::Digest		digest = engine.digest();
		
		for (; i < szout && i < engine.digestLength(); i++) {
			poutput[i] = digest[i];
		}	

	}
	GY_CATCH_EXCEPTION(ERRORPRINT("Exception Caught while creating md5sum : %s\n", GY_GET_EXCEPT_STRING);return -1;);
	
	return (int)i;
}	 

int gy_encrypt_buffer(const char *bufferin, size_t szbuf, const char *password, size_t szpass, const char *salt, size_t szsalt, std::string & encrypt_string, const char *algo) noexcept
{
	using 			namespace Poco::Crypto;

	try {
		Cipher::Ptr pCipher = CipherFactory::defaultFactory().createCipher(CipherKey(std::string(algo), std::string(password, szpass),  std::string(salt, szsalt)));

		encrypt_string = std::move(pCipher->encryptString(std::string(bufferin, szbuf), Cipher::ENC_BASE64_NO_LF));
		
		return 0;
	}
	GY_CATCH_EXCEPTION(ERRORPRINT("Exception caught while encrypting buffer : %s\n", GY_GET_EXCEPT_STRING);return -1;);	
}	

int gy_decrypt_buffer(const char *encbufferin, size_t szbuf, const char *password, size_t szpass, const char *salt, size_t szsalt, std::string & decrypt_string, const char *algo) noexcept
{
	using 			namespace Poco::Crypto;

	try {
		Cipher::Ptr pCipher = CipherFactory::defaultFactory().createCipher(CipherKey(std::string(algo), std::string(password, szpass),  std::string(salt, szsalt)));
		
		decrypt_string = std::move(pCipher->decryptString(std::string(encbufferin, szbuf), Cipher::ENC_BASE64_NO_LF));
		
		return 0;
	}
	GY_CATCH_EXCEPTION(ERRORPRINT("Exception caught while decrypting buffer : %s\n", GY_GET_EXCEPT_STRING);return -1;);	
}	


int gy_send_email(const char *mailserver, bool is_ssl, bool is_auth, const char *username, const char *password, const char *psubject, const char *pemailbuffer, const char *sender, const char *receipients, char *perrbuf, size_t szerr, const char *pfileattach, bool use_unlock_stdio) noexcept
{
	using 		Poco::Net::MailMessage;
	using 		Poco::Net::MailRecipient;
	using 		Poco::Net::SMTPClientSession;
	using 		Poco::Net::SecureSMTPClientSession;
	using 		Poco::Net::StringPartSource;
	using 		Poco::Net::SSLManager;
	using 		Poco::Net::Context;
	using 		Poco::Net::PrivateKeyPassphraseHandler;
	using 		Poco::Net::InvalidCertificateHandler;
	using 		Poco::Net::AcceptCertificateHandler;
	using 		Poco::SharedPtr;
	using 		Poco::Path;
	using 		Poco::Exception;

	try {

		int						ret, nrcpt = 0, sret = 0;
		char						*prcpt, filename[256], *pattachment = nullptr, *ptmp;
		const char					*pmime = "text/plain";
		MailMessage 					message;
		std::unique_ptr<SecureSMTPClientSession> 	psslsession;
		std::unique_ptr<SMTPClientSession>		psession;
		std::unique_ptr<char[]> 			patuniq;
		struct stat					stat1;

		*filename = '\0';

		if (pfileattach) {
			int		fd1;

			fd1 = open(pfileattach, O_RDONLY);
			if (fd1 == -1) {
				snprintf(perrbuf, szerr, "Invalid Attachment file %s", pfileattach);
				return -1;
			}	

			ret = fstat(fd1, &stat1);
			if (ret) {
				snprintf(perrbuf, szerr, "Invalid Attachment file %s", pfileattach);
				(void)close(fd1);
				return -1;
			}	

			if (stat1.st_size > 100 * 1024 * 1024) {
				snprintf(perrbuf, szerr, "Attachment file %s size too large %lu MB. Max allowed size is 100 MB", pfileattach, stat1.st_size >> 20);
				(void)close(fd1);
				return -1;
			}	

			ptmp = (char *)strrchr(pfileattach, '/');
			if (ptmp) {
				ptmp++;
			}
			else {
				ptmp = (char *)pfileattach;		
			}		

			GY_STRNCPY(filename, ptmp, sizeof(filename) - 1);

			try {
				patuniq = std::make_unique<char[]>(stat1.st_size <= 5 * 1024 * 1024 ? stat1.st_size + 128 : stat1.st_size + 32 * 1024);
			}
			catch (const std::exception &e) {								
				snprintf(perrbuf, szerr, "Exception caught %s in %s() %u", e.what(), __FUNCTION__, __LINE__);
				(void)close(fd1);
				return -1;								
			}										
			
			pattachment = patuniq.get();
			
			ret = gy_readbuffer(fd1, pattachment, stat1.st_size);
			if (ret < 0) {
				snprintf(perrbuf, szerr, "Failed to read attachment");
				(void)close(fd1);
				return -1;								
			}	

			close(fd1);

			pattachment[ret] = '\0';

			if (stat1.st_size > 5 * 1024 * 1024) {
				
				gzFile			pfp;
				char			filebuf[512];

				snprintf(filebuf, sizeof(filebuf), "/tmp/.__test_email_%ld.gz", get_usec_time());

				pfp = gzopen(filebuf, "wb");
				if (pfp == nullptr) {
					snprintf(perrbuf, szerr, "Could not open temp file %s for compressing attachment", filebuf);
					return -1;
				}	

				sret = gzwrite(pfp, pattachment, ret);
				if (sret != ret) {
					snprintf(perrbuf, szerr, "Could not write to compressed attachment file %s", filebuf);
					gzclose(pfp);
					unlink(filebuf);
					return -1;
				}

				gzclose(pfp);

				fd1 = open(filebuf, O_RDONLY);
				if (fd1 == -1) {
					snprintf(perrbuf, szerr, "Invalid Compressed Attachment file %s", filebuf);
					unlink(filebuf);
					return -1;
				}	

				ret = fstat(fd1, &stat1);

				ret = gy_readbuffer(fd1, pattachment, stat1.st_size);
				if (ret < 0) {
					snprintf(perrbuf, szerr, "Failed to read attachment");
					(void)close(fd1);
					unlink(filebuf);
					return -1;								
				}	

				(void)close(fd1);

				unlink(filebuf);

				pmime = "application/x-gzip";
				if (sizeof(filename) > strlen(filename) + 4) {
					strcat(filename, ".gz");
				}

				if (gdebugexecn) {
					TIMEFDPRINT(STDOUT_FILENO, use_unlock_stdio, "[INFO]: Sending attachment as a gzipped compressed file since size is over 5 MB...\n\n");
				}	
			}	
		}	
		else {
			stat1.st_size = 0;
		}	

		static void			*poldcontext = nullptr;
		static GY_MUTEX			emailmutex;

		if (is_ssl) {
			
			if (gdebugexecn) {
				TIMEFDPRINT(STDOUT_FILENO, use_unlock_stdio, "[INFO]: Sending Email for SSL Mailserver %s Authentication %s for User %s with %s attachment\n\n", 
					mailserver, is_auth ? "Enabled" : "Disabled", username, pfileattach ? pfileattach : "no");
			}	

			try {

				SCOPE_GY_MUTEX			sclock(&emailmutex);

				if (poldcontext == nullptr) {
					Poco::Net::initializeSSL();
			
					InvalidCertificateHandler *pcert = new AcceptCertificateHandler(false);
					Context *pcon = new Context(Context::CLIENT_USE, "", "", "", Context::VERIFY_RELAXED, 
									9, true, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
					SSLManager::instance().initializeClient(0, pcert, pcon);
					poldcontext = (void *)pcon;
				}
			}
			catch (Exception &exc) {
				TIMEFDPRINT(STDERR_FILENO, use_unlock_stdio, "[ERROR]: Failed to initialize SSL environment for email : %s\n", exc.displayText().c_str());
				return -1;
			}
			catch (...) {
				TIMEFDPRINT(STDERR_FILENO, use_unlock_stdio, "[ERROR]: Exception caught while initialization of SSL env\n");
				return -1;
			}

			if (poldcontext == nullptr) {
				TIMEFDPRINT(STDERR_FILENO, use_unlock_stdio, "[ERROR]: SSL Context Not yet initialized due to earlier SSL Exception. Cannot send secure email...\n");
				return -1;
			}	

			try {
				psslsession = std::make_unique<SecureSMTPClientSession>(std::string(mailserver));
				psslsession->login();
				psslsession->startTLS();
				if (is_auth && *username & *password) {
					psslsession->login(SMTPClientSession::AUTH_LOGIN, username, password);
				}

				if (gdebugexecn) {
					TIMEFDPRINT(STDOUT_FILENO, use_unlock_stdio, "[INFO]: Connected to SSL email server. Sending email...\n\n");
				}	
			}
			catch (Exception &exc) {
				TIMEFDPRINT(STDERR_FILENO, use_unlock_stdio, "[ERROR]: Failed to login to mail server for SSL email : %s\n\n", exc.displayText().c_str());
				return -1;
			}
			catch (...) {
				TIMEFDPRINT(STDERR_FILENO, use_unlock_stdio, "[ERROR]: Exception caught while connecting to SSL mail server.\n\n");
				return -1;
			}
		}
		else {
			if (gdebugexecn) {
				TIMEFDPRINT(STDOUT_FILENO, use_unlock_stdio, "[INFO]: Sending Email for non-SSL Mailserver %s Authentication support disabled with %s attachment\n\n", 
					mailserver, pfileattach ? pfileattach : "no");
			}

			try {
				psession = std::make_unique<SMTPClientSession>(std::string(mailserver));
				psession->login();

				if (gdebugexecn) {
					TIMEFDPRINT(STDOUT_FILENO, use_unlock_stdio, "[INFO]: Connected to Email server. Sending email...\n\n");
				}	
			}
			catch (Exception &exc) {
				TIMEFDPRINT(STDERR_FILENO, use_unlock_stdio, "[ERROR]: Failed to login to mail server for email : %s\n\n", exc.displayText().c_str());
				return -1;
			}
			catch (...) {
				TIMEFDPRINT(STDERR_FILENO, use_unlock_stdio, "[ERROR]: Exception caught while connecting to mail server.\n\n");
				return -1;
			}
		}

		prcpt = strdup(receipients);
		if (!prcpt) {
			PERRORUNLOCKPRINT("Could not allocate mem for email receipients");
			return -1;
		}

		try {
			message.setSender(std::string(sender));
			message.setSubject(std::string(psubject));

			char *ptrcpt = prcpt, *ponercpt;
			
			do {
				ponercpt = strsep(&ptrcpt, ",");
				if (!ponercpt) {
					break;
				}
				message.addRecipient(MailRecipient(nrcpt++ ? MailRecipient::CC_RECIPIENT : MailRecipient::PRIMARY_RECIPIENT, 
					std::string(ponercpt)));
			} while (ptrcpt);
		}
		catch (Exception &exc) {
			TIMEFDPRINT(STDERR_FILENO, use_unlock_stdio, "[ERROR]: Failed to set message for email : %s\n\n", exc.displayText().c_str());
			free(prcpt);
			return -1;
		}

		free(prcpt);

		size_t 					sz1 = strlen(pemailbuffer);
		std::unique_ptr<char []>		pemail = std::make_unique<char []>(sz1 * 2 + 1);

		{
			char *ptmp = (char *)strchr(pemailbuffer, '\n');
			if (ptmp) {
				if (ptmp == pemailbuffer || (ptmp[-1] != '\r')) {
					gy_create_mail_buffer((char *)pemailbuffer, sz1, pemail.get(), sz1 * 2); 
				}
				else {
					std::memcpy(pemail.get(), pemailbuffer, sz1 + 1);	
				}
			}
			else {
				std::memcpy(pemail.get(), pemailbuffer, sz1 + 1);	
			}
		}

		try {
			message.addContent(new StringPartSource(pemail.get()));

			if (pattachment) {
				message.addAttachment(filename, new StringPartSource(std::string(pattachment, stat1.st_size)));
			}	

			if (psslsession) {
				psslsession->sendMessage(message);

			}
			else if (psession) {
				psession->sendMessage(message);
			}
		}
		catch (Exception &exc) {
			TIMEFDPRINT(STDERR_FILENO, use_unlock_stdio, "[ERROR]: Failed to send email : %s\n\n", exc.displayText().c_str());

			return 1;
		}

		return 0;

	}
	GY_CATCH_EXCEPTION(snprintf(perrbuf, szerr, "Exception Caught while sending email : %s", GY_GET_EXCEPT_STRING);return -1;);
}	


}

