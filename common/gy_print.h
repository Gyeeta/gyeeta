//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma			once

#include 		"gy_common_inc.h"

#include 		<cstdio>
#include 		<cstdlib>
#include 		<cstring>
#include 		<memory>
#include 		<cstdarg>
#include 		<cerrno>
#include 		<cassert>
#include 		<cmath>
#include 		<alloca.h>
#include 		<unistd.h>
#include 		<cinttypes>
#include 		<sys/types.h>
#include 		<sys/stat.h>
#include 		<sys/time.h>
#include 		<fcntl.h>
#include 		<climits>

namespace gyeeta {

/*
 * Generic Logging & Print Routines :
 *
 * The log APIs use fprintf style formats and no cout / cerr style streams are supported.
 *
 * The macros given in this file will directly invoke either fprintf or write syscall within the calling thread.
 * 
 * XXX For offloading the print writes to a separate thread or rate limited prints, please see the gy_print_offload.h.
 *
 * For the *UNLOCKPRINT routines, write() syscall is used. This implies that the *UNLOCKPRINT routines are not 
 * atomic (concurrent writes may be interleaved). Also, if the FD is a socket, the caller should have SIGPIPE ignored.
 *
 * By default, all timestamps are printed in Local Time Zone in YYYY-MM-DD HH:MM:SS.usec format. To print the timestamp in UTC TZ,
 * set the gyeeta::guse_utc_time global to true.
 *
 * ------------- File Buffered IO based Print Routines (fprintf based) --------------------------
 * 
 * XXX The format specifiers for all macro calls needs to be a string literal or else this file will not compile.
 *
 * Use INFOPRINT to print time prefixed mesages with [INFO] prefix to stdout 
 * Use NOTEPRINT to print time prefixed mesages with [NOTE] prefix to stdout 
 * Use WARNPRINT to print time prefixed mesages with [WARN] prefix to stdout 
 * Use ERRORPRINT to print time prefixed mesages with [ERROR] prefix to stderr 
 * Use INFOFDUNLOCKPRINT and other <Prefix>UNLOCKPRINTs to print time prefixed mesages for use in async safe functions
 * Use PERRORPRINT to print time prefixed system error mesages with [SYSTEM ERROR] prefix and strerror to stderr 
 * Use PERRORUNLOCKPRINT to print [SYSTEM ERROR] prefix and strerror : to be used in async safe functions to STDERR_FILENO 
 * Use IRPRINT for normal messages without any prefix to stdout
 *
 * Use DEBUGEXECN for conditional printing if gyeeta::gdebugexecn is >= N specified : Default is 0. See example below
 * Use CONDEXEC to print only if -DCONDCOMPILE compile time option is defined
 * CONDEXEC is a compile time check whereas DEBUGEXECN is a run time conditional check
 *
 * Use DEBUGPRINT to print time:[DEBUG]:[pretty function name:line number] as prefix to stdout
 * Use INFOPRINTCOLOR to print the message in a specific color e.g. INFOPRINTCOLOR(GY_COLOR_GREEN, "Msg in Green\n");
 * 
 * --------------- File Descriptor write() based Print Routines --------------------------------------
 *
 * These routines can write arbitratily sized buffers to fds if _is_unlock is not set.
 *
 * Use *FDPRINTs or *UNLOCKPRINTs for writing any messages (without any prefix) to any FD (could be a socket as well)
 * The *FDPRINTs can block if the message size is large enough to allocate memory. The *UNLOCKPRINTs will not block and
 * if the message size is large will truncate to around 1024 bytes.
 *
 * Use INFOFDPRINT to write time prefixed msg to any FD (could be a socket as well) (blocking writes)
 * Use NOTEFDPRINT to write time prefixed msg to any FD (could be a socket as well) (blocking writes)
 * Use WARNFDPRINT to write time prefixed msg to any FD (could be a socket as well) (blocking writes)
 * Use ERRORFDPRINT to write time prefixed msg to any FD (could be a socket as well) (blocking writes)
 * 
 * For Signal Handler safe print functions, use the *UNLOCKPRINT macros, e.g.
 *
 * NOTEFDUNLOCKPRINT, INFOFDUNLOCKPRINT, etc. These will not print the Human Readable Time String but will
 * just print the time_t value for use in Signal handlers or directly after fork(). 
 *
 * XXX TODO : snprintf is *NOT* async safe. Try using Chromium safe_sprintf...
 *
 * Example of INFOPRINT Use and Output : INFOPRINT("This is a sample INFOPRINT\n");
 *
 * [2018-03-12 16:20:21.764797]:[INFO]: This is a sample INFOPRINT
 *
 * In the above output, the timestamp is in [YYYY-MM-DD HH:MM:SS.usec] format
 *
 * NOTE : with PERRORPRINT / PERRORPRINTCOLOR do not append trailing '\n'
 *
 * Example of PERRORPRINTCOLOR Use and Output : if (ret == -1) PERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Open of file %s failed", argv[1]);
 * 
 * [2018-03-23 17:03:00.377022]:[SYSTEM ERROR]: Open of file /opt/dummy1 failed: No such file or directory (test_cp.cc:#47)
 * 
 * In the above output, the text from [SYSTEM ERROR] onwards will be printed in Bold Red color.
 */ 


extern bool				guse_utc_time, gunbuffered_stdout;

static std::pair<char *, int> 		gy_time_print(char *stimebuf, size_t sizebuf, struct timeval tv) noexcept;
static ssize_t 				gy_writebuffer(int, const void *, size_t) noexcept;

#ifdef __linux__
#	define GY_GETPERROR(_terrno, _pbuf, _sizebuf)		::strerror_r((_terrno), (_pbuf), (_sizebuf))
#else
#	define GY_GETPERROR(_terrno, _pbuf, _sizebuf) 		::strerror((_terrno))
#endif


#define PERRORPRINT(format, _arg...) 													\
({																	\
	char 			_bufp[128];												\
	int			_olderrno = errno;											\
																	\
	static_assert(false == gyeeta::is_str_last_char(format,'\n'), "PERRORPRINT format must not end with a newline");		\
																	\
	int			_ret;													\
	_ret = TIMEPRINT(stderr, "[SYSTEM ERROR]: " format ": %s (%s:#%u:%d)\n",							\
		## _arg, GY_GETPERROR(_olderrno, _bufp, sizeof(_bufp)), 								\
		__FILE__, __LINE__, _olderrno);												\
	_ret;																\
})

#define PERRORUNLOCKPRINT(format, _arg...) 												\
({																	\
	char 			_bufp[128];												\
	int			_olderrno = errno;											\
																	\
	static_assert(false == gyeeta::is_str_last_char(format, '\n'), "PERRORUNLOCKPRINT format must not end with a newline");		\
																	\
	int			_ret;													\
	_ret = TIMEFDPRINT(STDERR_FILENO, true, "[SYSTEM ERROR]: " 									\
		format ": %s (%s:#%u:%d)\n", ## _arg, GY_GETPERROR(_olderrno, _bufp, sizeof(_bufp)), 					\
		__FILE__, __LINE__, _olderrno);												\
	_ret;																\
})


#define TIMEPRINT(_file, format, args...)												\
({																	\
	char 			_stimebuf[50];												\
	struct timeval		_tv;													\
																	\
	::gettimeofday(&_tv, nullptr);													\
																	\
	auto _p = gyeeta::gy_time_print(_stimebuf, sizeof(_stimebuf), _tv);								\
																	\
	int			_ret;													\
	_ret = ::fprintf((_file), "[%.*s]:" format, _p.second, _p.first, ## args);							\
	_ret;																\
})


#define TIMEFDPRINT(_ofd, _is_unlock, format, args...)											\
({																	\
	char 			_stimebuf[50];												\
	struct timeval		_tv;													\
	bool			_is_non_block = !!static_cast<int>(_is_unlock);								\
																	\
	::gettimeofday(&_tv, nullptr);													\
																	\
	if ((_is_non_block == false)) {													\
		gyeeta::gy_time_print(_stimebuf, sizeof(_stimebuf), _tv);								\
	}																\
	else {																\
		::snprintf(_stimebuf, sizeof(_stimebuf), "%19ld.%06u", 									\
			(long)_tv.tv_sec, (uint32_t)_tv.tv_usec);									\
	}																\
																	\
	int		_ret;														\
	_ret = gyeeta::gy_fdprintf((_ofd), _is_non_block, "[%s]:" format, 								\
					_stimebuf, ## args);										\
	_ret;																\
})

#define DEBUGPRINT(format, args...) 			TIMEPRINT(stdout, "[DEBUG]:[%s:%d] : " format, __PRETTY_FUNCTION__, __LINE__, ## args) 

#define IRPRINT(format, args...) 			::fprintf(stdout, format, ## args)

#define INFOPRINT(format, args...) 			TIMEPRINT(stdout, "[INFO]: " format, ## args) 

#define NOTEPRINT(format, args...) 			TIMEPRINT(stdout, "[NOTE]: " format, ## args) 

#define WARNPRINT(format, args...) 			TIMEPRINT(stdout, "[WARN]: " format, ## args) 

#define ERRORPRINT(format, args...) 			TIMEPRINT(stderr, "[ERROR]: " format, ## args) 


#define IRFDPRINT(_fd, format, args...) 		gyeeta::gy_fdprintf((_fd), false, format, ## args)

#define INFOFDPRINT(_fd, format, args...) 		TIMEFDPRINT((_fd), false, "[INFO]: " format, ## args) 

#define NOTEFDPRINT(_fd, format, args...) 		TIMEFDPRINT((_fd), false, "[NOTE]: " format, ## args) 

#define WARNFDPRINT(_fd, format, args...) 		TIMEFDPRINT((_fd), false, "[WARN]: " format, ## args) 

#define ERRORFDPRINT(_fd, format, args...) 		TIMEFDPRINT((_fd), false, "[ERROR]: " format, ## args) 


#define IRFDUNLOCKPRINT(_fd, format, args...) 		gyeeta::gy_fdprintf((_fd), true, format, ## args)

#define INFOFDUNLOCKPRINT(_fd, format, args...) 	TIMEFDPRINT((_fd), true, "[INFO]: " format, ## args) 

#define NOTEFDUNLOCKPRINT(_fd, format, args...) 	TIMEFDPRINT((_fd), true, "[NOTE]: " format, ## args) 

#define WARNFDUNLOCKPRINT(_fd, format, args...) 	TIMEFDPRINT((_fd), true, "[WARN]: " format, ## args) 

#define ERRORFDUNLOCKPRINT(_fd, format, args...) 	TIMEFDPRINT((_fd), true, "[ERROR]: " format, ## args) 

#define COLOR_SHIFT_NEWLINE(_str, _N, _strnew)							\
do {												\
	constexpr bool		_is_nl = gyeeta::is_str_last_char(_str, '\n');			\
	constexpr size_t	_resetlen = gyeeta::GY_CONST_STRLEN(GY_COLOR_RESET);		\
												\
	IF_CONSTEXPR (_is_nl) {									\
		std::memcpy(_strnew, _str, _N - 2);						\
		std::memcpy(_strnew + _N - 2, GY_COLOR_RESET, _resetlen);			\
		_strnew[_N - 2 + _resetlen] = '\n';						\
		_strnew[_N - 2 + _resetlen + 1] = 0;						\
	}											\
	else {											\
		std::memcpy(_strnew, _str, _N - 1);						\
		std::memcpy(_strnew + _N - 1, GY_COLOR_RESET, _resetlen);			\
		_strnew[_N - 1 + _resetlen] = 0;						\
	}											\
} while (0)	


#define TIMECOLORPRINT(_file, format, args...)							\
({												\
	int			_ret;								\
	constexpr size_t	szbuf = gyeeta::GY_CONST_STRLEN("[%s]:" format);		\
												\
	static_assert(szbuf < 1024, "format specifier length too large : Limit to 1024 bytes");	\
												\
	char			_fmtbuf[szbuf + 8];						\
	char 			_stimebuf[50];							\
												\
	COLOR_SHIFT_NEWLINE("[%s]:" format, szbuf + 1, _fmtbuf);				\
												\
	gyeeta::gy_time_print(_stimebuf, sizeof(_stimebuf));					\
												\
	_ret = ::fprintf((_file), _fmtbuf, _stimebuf, ## args);					\
})

/*
 * Various COLOR Calls...
 */ 
#define IRPRINTCOLOR(_color, format, args...) 							\
({												\
	int			_ret;								\
	constexpr size_t	szbuf = gyeeta::GY_CONST_STRLEN(_color format);			\
												\
	static_assert(szbuf < 1024, "format specifier length too large : Limit to 1024 bytes");	\
												\
	char			_fmtbuf[szbuf + 8];						\
												\
	COLOR_SHIFT_NEWLINE(_color format, szbuf + 1, _fmtbuf);					\
												\
	_ret = IRPRINT(_fmtbuf, ## args);							\
})


#define INFOPRINTCOLOR(_color, format, args...) 			TIMECOLORPRINT(stdout, "[INFO]: " _color format, ## args);

#define INFOFDUNLOCKPRINTCOLOR(_ofd, _color, format, args...) 		INFOFDUNLOCKPRINT((_ofd), _color format  GY_COLOR_RESET, ## args);

#define NOTEPRINTCOLOR(_color, format, args...) 			TIMECOLORPRINT(stdout, "[NOTE]: " _color format, ## args);

#define NOTEFDUNLOCKPRINTCOLOR(_ofd, _color, format, args...) 		NOTEFDUNLOCKPRINT((_ofd), _color format  GY_COLOR_RESET, ## args);

#define WARNPRINTCOLOR(_color, format, args...) 			TIMECOLORPRINT(stdout, "[WARN]: " _color format, ## args);

#define WARNFDUNLOCKPRINTCOLOR(_ofd, _color, format, args...) 		WARNFDUNLOCKPRINT((_ofd), _color format  GY_COLOR_RESET, ## args);

#define ERRORPRINTCOLOR(_color, format, args...) 			TIMECOLORPRINT(stderr, "[ERROR]: " _color format, ## args);

#define ERRORFDUNLOCKPRINTCOLOR(_ofd, _color, format, args...) 		ERRORFDUNLOCKPRINT((_ofd), _color format  GY_COLOR_RESET, ## args);

#define PERRORPRINTCOLOR(_color, format, args...) 											\
({																	\
	static_assert(false == gyeeta::is_str_last_char(format, '\n'), "PERRORPRINTCOLOR format must not end with a newline");		\
																	\
	PERRORPRINT(_color format GY_COLOR_RESET, ## args);										\
})

#define PERRORUNLOCKPRINTCOLOR(_color, format, args...) 										\
({																	\
	static_assert(false == gyeeta::is_str_last_char(format, '\n'), "PERRORUNLOCKPRINTCOLOR format must not end with a newline");	\
																	\
	PERRORUNLOCKPRINT(_color format GY_COLOR_RESET, ## args);									\
})


#ifndef GY_NO_ANSI_COLORS

/*
 * ANSI Color Stuff follows.
 * To view the color formatted output in vim, use the :AnsiEsc plugin or use less -R command
 */ 
#define GY_COLOR_BLACK    		"\x1b[30m"
#define GY_COLOR_BLACK_ITALIC    	"\x1b[3;30m"
#define GY_COLOR_BLACK_UNDERLINE    	"\x1b[4;30m"

#define GY_COLOR_RED    		"\x1b[31m"
#define GY_COLOR_LIGHT_RED		"\x1b[31;22m"
#define GY_COLOR_BOLD_RED    		"\x1b[31;1m"
#define GY_COLOR_RED_ITALIC 	 	"\x1b[3;31m"
#define GY_COLOR_RED_UNDERLINE  	"\x1b[4;31m"
#define GY_COLOR_BOLD_RED_ITALIC  	"\x1b[3;31;1m"
#define GY_COLOR_BOLD_RED_UNDERLINE  	"\x1b[4;31;1m"

#define GY_COLOR_GREEN  		"\x1b[32m"
#define GY_COLOR_LIGHT_GREEN  		"\x1b[32;22m"
#define GY_COLOR_BOLD_GREEN  		"\x1b[32;1m"
#define GY_COLOR_GREEN_ITALIC	 	"\x1b[3;32m"
#define GY_COLOR_GREEN_UNDERLINE 	"\x1b[4;32m"

#define GY_COLOR_YELLOW 		"\x1b[33m"
#define GY_COLOR_LIGHT_YELLOW 		"\x1b[33;22m"
#define GY_COLOR_BOLD_YELLOW 		"\x1b[33;1m"
#define GY_COLOR_YELLOW_ITALIC 		"\x1b[3;33m"
#define GY_COLOR_YELLOW_UNDERLINE 	"\x1b[4;33m"

#define GY_COLOR_BLUE   		"\x1b[34m"
#define GY_COLOR_LIGHT_BLUE  		"\x1b[34;22m"
#define GY_COLOR_BOLD_BLUE  		"\x1b[34;1m"
#define GY_COLOR_BLUE_ITALIC 		"\x1b[3;34m"
#define GY_COLOR_BLUE_UNDERLINE 	"\x1b[4;34m"

#define GY_COLOR_MAGENTA		"\x1b[35m"		
#define GY_COLOR_MAGENTA_ITALIC		"\x1b[3;35m"	
#define GY_COLOR_MAGENTA_UNDERLINE	"\x1b[4;35m"

#define GY_COLOR_CYAN   		"\x1b[36m"
#define GY_COLOR_LIGHT_CYAN   		"\x1b[36;22m"
#define GY_COLOR_BOLD_CYAN   		"\x1b[36;1m"
#define GY_COLOR_CYAN_ITALIC 		"\x1b[3;36m"
#define GY_COLOR_CYAN_UNDERLINE 	"\x1b[4;36m"

#define GY_COLOR_WHITE   		"\x1b[37;m"

#define GY_COLOR_RESET  		"\x1b[0m"

#define GY_COLOR_CLEAR_SCREEN		"\x1b[2J\x1b[u"		/* clear the screen and reset the position */

#else

/*
 * NO ANSI Color stuff...
 */
#define GY_COLOR_BLACK    		""
#define GY_COLOR_BLACK_ITALIC    	""
#define GY_COLOR_BLACK_UNDERLINE    	""
#define GY_COLOR_RED    		""
#define GY_COLOR_LIGHT_RED		""
#define GY_COLOR_BOLD_RED    		""
#define GY_COLOR_RED_ITALIC 	 	""
#define GY_COLOR_RED_UNDERLINE  	""
#define GY_COLOR_GREEN  		""
#define GY_COLOR_LIGHT_GREEN  		""
#define GY_COLOR_BOLD_GREEN  		""
#define GY_COLOR_GREEN_ITALIC	 	""
#define GY_COLOR_GREEN_UNDERLINE 	""
#define GY_COLOR_YELLOW 		""
#define GY_COLOR_LIGHT_YELLOW 		""
#define GY_COLOR_BOLD_YELLOW 		""
#define GY_COLOR_YELLOW_ITALIC 		""
#define GY_COLOR_YELLOW_UNDERLINE 	""
#define GY_COLOR_BLUE   		""
#define GY_COLOR_LIGHT_BLUE  		""
#define GY_COLOR_BOLD_BLUE  		""
#define GY_COLOR_BLUE_ITALIC 		""
#define GY_COLOR_BLUE_UNDERLINE 	""
#define GY_COLOR_MAGENTA		""
#define GY_COLOR_MAGENTA_ITALIC		""	
#define GY_COLOR_MAGENTA_UNDERLINE	""
#define GY_COLOR_CYAN   		""
#define GY_COLOR_LIGHT_CYAN   		""
#define GY_COLOR_BOLD_CYAN   		""
#define GY_COLOR_CYAN_ITALIC 		""
#define GY_COLOR_CYAN_UNDERLINE 	""
#define GY_COLOR_WHITE   		""
#define GY_COLOR_RESET  		""
#define GY_COLOR_CLEAR_SCREEN		""	

#endif


} // namespace gyeeta

