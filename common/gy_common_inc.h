//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma 		once

#ifndef 		_GNU_SOURCE
#define 		_GNU_SOURCE
#endif

#if (__cplusplus < 201700L)
#	error 		"This header requires C++17. Please compile with -std=c++17"
#endif

#if (!defined(__GNUC__) || (__GNUC__ < 7))
#	error 		"This header requires gcc (g++) compiler version 7 or higher"
#endif

#pragma 		GCC diagnostic push
#pragma 		GCC diagnostic ignored "-Wunused"

#include 		<cstdio>
#include 		<cstdlib>
#include 		<cstring>
#include 		<memory>
#include 		<atomic>
#include 		<climits>
#include 		<limits>
#include 		<cstdarg>
#include 		<type_traits>
#include 		<typeinfo>

#include 		<cerrno>
#include 		<cassert>
#include 		<cmath>
#include 		<pthread.h>
#include 		<alloca.h>
#include 		<unistd.h>
#include 		<cinttypes>
#include 		<sys/types.h>
#include 		<sys/stat.h>
#include 		<fcntl.h>
#include 		<sys/types.h>
#include 		<arpa/inet.h>
#include 		<sys/socket.h>
#include 		<sys/prctl.h>
#include 		<sys/syscall.h>
#include 		<sys/uio.h>
#include 		<poll.h>
#include 		<csignal>
#include 		<climits>
#include 		<endian.h>
#include 		<stdio_ext.h>
#include 		<cxxabi.h>

#include 		"gy_print.h"
#include 		"gy_atomic.h"
#include 		"gy_file_api.h" 
#include 		"gy_scope.h"
#include 		"gy_utf8.h"
#include		"jhash.h"

using 			std::string_view_literals::operator""sv;

namespace gyeeta {

#define GY_READ_ONCE(x) 			(*(volatile decltype(x) *)&(x))
#define GY_WRITE_ONCE(x, val)			(*(volatile decltype(x) *)&(x)) = (val)
#define GY_CC_BARRIER() 			asm volatile ("": : :"memory")

#define GY_READ_CC_BARRIER(x)								\
({											\
	decltype(x)				_x = GY_READ_ONCE(x);			\
	GY_CC_BARRIER();								\
	_x;										\
})

#define GY_STRINGIFY(_str) 			GY_STRINGIFY_IMPL(_str)
#define GY_STRINGIFY_IMPL(_str)			#_str

#define GY_CONCATENATE(s1, s2) 			GY_CONCATENATE_IMPL(s1, s2)
#define GY_CONCATENATE_IMPL(s1, s2) 		s1##s2

#define GY_ANONYMOUS_VARIABLE(str) 		GY_CONCATENATE(str, __COUNTER__)

#define GY_PREFETCH(_X, _RW, _LO)		__builtin_prefetch((_X), (_RW), (_LO))

#define GY_CONTAINER_OF(ptr, type, member)								\
({													\
	const decltype(((type *) nullptr)->member) * __ptr = (ptr); 					\
	(type *)((char *)__ptr - offsetof(type, member));						\
})

#define gy_likely(x)				__builtin_expect(!!(x), 1)
#define gy_unlikely(x)				__builtin_expect(!!(x), 0)

#define GY_ARRAY_SIZE(arr) 			(sizeof((arr)) / sizeof((arr)[0]))

// GY_DOWN_* to down convert from a larger number to KB/MB/GB
#define GY_DOWN_KB(x) 				(((x)) >> 10)
#define GY_DOWN_MB(x) 				(((x)) >> 20)
#define GY_DOWN_GB(x) 				(((x)) >> 30)

// GY_UP_* to up convert from a smaller number to its KB/MB/GB expanded value (output is in uint64_t)
#define GY_UP_KB(x)				((static_cast<uint64_t>((x))) << 10)
#define GY_UP_MB(x)				((static_cast<uint64_t>((x))) << 20)
#define GY_UP_GB(x)				((static_cast<uint64_t>((x))) << 30)


/*
 * Compile time Code enabling using CONDCOMPILE compile time preprocessor option : See comments below 
 * Use CONDDECLARE to declare variables which will then be subsequently used within 2 or more subsequent CONDEXEC blocks
 * within the same scope block as CONDDECLARE or to declare class variables to beused only when CONDCOMPILE active.
 * Use NOTCONDDECLARE to declare variables which will be available only when CONDCOMPILE preprocessor option is not defined
 * See examples below...
 */
#ifdef CONDCOMPILE
#	define CONDEXEC(...) 		do { __VA_ARGS__; } while (0)
#	define NOTCONDEXEC(...) 	do { } while (0)
#	define CONDDECLARE(...) 	__VA_ARGS__; 
#	define NOTCONDDECLARE(...) 	
#else
#	define CONDEXEC(...)		do { } while (0)
#	define NOTCONDEXEC(...) 	do { __VA_ARGS__; } while (0)
#	define CONDDECLARE(...) 	
#	define NOTCONDDECLARE(...)	__VA_ARGS__;
#endif

/*
 * Conditional run time execution based on Debug Level gyeeta::gdebugexecn which can be changed on the fly : See example below
 */
#define DEBUGEXECN(debuglevel, ...)							\
do {											\
	int		_chkn = static_cast<int>(debuglevel);				\
											\
	if (gy_unlikely(gyeeta::gdebugexecn >= _chkn)) {				\
		__VA_ARGS__;								\
	}										\
} while (0)	


/*
 * Example use of DEBUGEXECN and CONDEXEC : 
 *
 CONDEXEC(
  	INFOPRINT("This will be printed if CONDCOMPILE preprocessor option is defined (-DCONDCOMPILE)\n");
 );

 DEBUGEXECN(5, 
 	char 		testbuf[64];

	snprintf(testbuf, sizeof(testbuf), "Current gyeeta::gdebugexecn = %d", gyeeta::gdebugexecn);

  	INFOPRINT("This will be printed if gyeeta::gdebugexecn >= 5 : %s\n", testbuf)
 );

 CONDEXEC and DEBUGEXECN can be cascaded for e.g. :

 CONDEXEC(
 	char		testbuf[128];
	
 	DEBUGEXECN(1,
		// Do something
		INFOPRINT("This message will only be printed if CONDCOMPILE is defined (-DCONDCOMPILE is defined) and if gyeeta::gdebugexecn >= 1\n");
	);
 );			
 *
 */

extern int 			gdebugexecn;

// Safe snprintf : Returns max _szbuf - 1 (i.e. strlen excluding '\0')
#define GY_SAFE_SNPRINTF(_pbuf, _szbuf, _fmt, args...)						\
({												\
	int 			_sz, _maxsz = (_szbuf);						\
	_sz = ::snprintf((_pbuf), _maxsz, _fmt, ## args);					\
												\
	if (_sz >= _maxsz && _maxsz > 0) 							\
		_sz = _maxsz - 1;								\
	else if (_sz < 0) 									\
		_sz = 0;									\
	_sz;											\
})

// snprintf returning the resultant string instead of ssize_t
#define GY_SNPRINTF_RET_STR(_pbuf, _szbuf, _fmt, args...)					\
({												\
	int 			_maxsz = (_szbuf);						\
	::snprintf((_pbuf), _maxsz, _fmt, ## args);						\
	(_pbuf);										\
})

/*
 * std::strncpy without the overhead of trailing buffer memset to '\0'. 
 * Is faster than std::strncpy/GY_STRNCPY_0 for small/medium dest strings copies upto 512 bytes.
 * Use GY_STRNCPY_0 for larger dest strings where src string is likely to be over 512 bytes but 
 * dest buffer size is not too large (over 4096)
 */
#define GY_STRNCPY(dest, src, len)								\
({												\
	char		*_dest = (dest);							\
	const char	*_src = (src);								\
	size_t		_len = (len);								\
	size_t 		_dlen = ::strnlen(_src, _len > 1 ? _len - 1 : 0);			\
												\
	if (!(_src >= _dest && _src < _dest + _dlen)) {						\
		std::memcpy(_dest, _src, _dlen);						\
	}											\
	else {											\
		std::memmove(_dest, _src, _dlen);						\
	}											\
	_dest[_dlen] = '\0';									\
	_dest;											\
})	

/* 
 * A safer std::strncpy (Will 0 out the trailing bytes unlike GY_STRNCPY)
 * See comment above.
 */
#define GY_STRNCPY_0(dest, src, len)								\
({												\
	char		*_dest = (dest);							\
	const char	*_src = (src);								\
	size_t		_len = (len);								\
	size_t 		_dlen = (_len > 1 ? _len - 1 : 0);					\
												\
	if (!(_src >= _dest && _src < _dest + _dlen)) {						\
		if (_dlen) std::strncpy(_dest, _src, _dlen);					\
	}											\
	else {											\
		std::memmove(_dest, _src, _dlen);						\
	}											\
	_dest[_dlen] = 0;									\
	_dest;											\
})	

/*
 * Like GY_STRNCPY but returns dest strlen
 */
#define GY_STRNCPY_LEN(dest, src, len)								\
({												\
	char		*_dest = (dest);							\
	const char	*_src = (src);								\
	size_t		_len = (len);								\
	size_t 		_dlen = ::strnlen(_src, _len > 1 ? _len - 1 : 0);			\
												\
	if (!(_src >= _dest && _src < _dest + _dlen)) {						\
		std::memcpy(_dest, _src, _dlen);						\
	}											\
	else {											\
		std::memmove(_dest, _src, _dlen);						\
	}											\
	_dest[_dlen] = '\0';									\
	_dlen;											\
})	


#define GY_STRNCAT(_dest, _maxlendest, _src, _nsrccopy)						\
({												\
	char		*_pdest = (_dest);							\
	const char	*_psrc = (_src);							\
	size_t		_maxdest = (_maxlendest), _n = (_nsrccopy);				\
	size_t 		dest_len = ::strlen(_pdest), i;						\
												\
	for (i = 0 ; i < _n && (i + dest_len < _maxdest) && _psrc[i] != '\0' ; i++) {		\
		_pdest[dest_len + i] = _psrc[i];						\
	}											\
												\
	_pdest[dest_len + i] = '\0';								\
												\
	_pdest;											\
})		

/*
 * Safe memcpy which will invoke memmove for overlapping buffers
 */
static void *memcpy_or_move(void *dest, const void *src, size_t n) noexcept
{
	char		*pdest = static_cast<char *>(dest);
	const char	*psrc = static_cast<const char *>(src);	
							
	if (!((psrc >= pdest && psrc < pdest + n) || (psrc < pdest && psrc + n > pdest))) {	
		std::memcpy(pdest, psrc, n);	
	}					
	else {					
		std::memmove(pdest, psrc, n);	
	}					

	return pdest;
}	


#define GY_SAFE_MEMCPY(_dest, _maxlendest, _src, _nsrccopy, _copied_len)			\
({												\
	char		*_pdest = (char *)(_dest);						\
	const char	*_psrc = (const char *)(_src);						\
	size_t		_maxdest = (_maxlendest), _n = (_nsrccopy);				\
	size_t 		_copy_len = std::min(_maxdest, _n);					\
												\
	memcpy_or_move(_pdest, _psrc, _copy_len);						\
												\
	(_copied_len) = (_copy_len);								\
	_pdest;											\
})

#define GY_SAFE_STR_MEMCPY(_dest, _maxlendest, _src, _nsrccopy)					\
({												\
	char		*_pdst = (char *)(_dest);						\
	size_t 		_clen;									\
												\
	if ((_maxlendest) > 0) {								\
		GY_SAFE_MEMCPY(_pdst, (_maxlendest) - 1, (_src), (_nsrccopy), _clen);		\
		_pdst[_clen] = 0;								\
	}											\
												\
	_pdst;											\
})


/*
 * Execute the passed block of code only once every nmsec millisec (at least). Will exec the first time it is called.
 * Can be used for rate limiting passed code based on time intervals. Returns bool indicating whether exec or not.
 * Uses a static variable and cannot debug the block statements in a debugger as it will be a single expression...
 */
#define ONCE_EVERY_MSEC(nmsec, ...)											\
({ 															\
	static uint64_t			_lastmsec = 0;									\
	uint64_t			_nmsec = static_cast<uint64_t>((nmsec));					\
	uint64_t			_cmsec = get_msec_clock();							\
	bool				_bret = false;									\
															\
	if (_cmsec >= _lastmsec + _nmsec) {										\
		_bret = true;												\
		_lastmsec = _cmsec;											\
		__VA_ARGS__;												\
	}														\
	_bret;														\
})

/*
 * Execute the passed block of code only once every ntime. Will exec the first time it is called.
 * Can be used for rate limiting passed code based on exec counts. Returns bool indicating whether exec or not.
 * Uses a static variable and cannot debug the block statements in a debugger as it will be a single expression...
 */
#define ONCE_EVERY_NTIMES(ntimes, ...)											\
({ 															\
	uint64_t			_ntimes = static_cast<uint64_t>((ntimes));					\
	static uint64_t			_lasttimes = _ntimes;								\
	bool				_bret = false;									\
															\
	if (++_lasttimes >= _ntimes) {											\
		_bret = true;												\
		_lasttimes = 0;												\
		__VA_ARGS__;												\
	}														\
	_bret;														\
})


/*
 * Execute the passed block of code only first ntimes. Returns bool indicating whether exec or not.
 * Uses a static variable and cannot debug the block statements in a debugger as it will be a single expression...
 */
#define EXEC_FIRST_NTIMES(ntimes, ...)											\
({ 															\
	uint64_t			_ntimes = static_cast<uint64_t>((ntimes));					\
	static uint64_t			_lasttimes = 0;									\
	bool				_bret = false;									\
															\
	if (_lasttimes < _ntimes) {											\
		_bret = true;												\
		_lasttimes++;												\
		__VA_ARGS__;												\
	}														\
	_bret;														\
})



// Will use strnlen for upto 512 bytes maxlen
static size_t gy_strnlen(const char *str, size_t maxlen) noexcept
{
	if (maxlen <= 512) {
		return ::strnlen(str, maxlen);
	}	

	size_t			slen;

	slen = ::strlen(str);

	if (slen > maxlen) {
		slen = maxlen;
	}	
	
	return slen;
}	

static inline bool gy_isalpha_ascii(int c) noexcept
{
	return ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'));
}

static inline bool gy_isdigit_ascii(int c) noexcept
{
	return (c >= '0' && c <= '9');
}	

static inline bool gy_isalnum_ascii(int c) noexcept
{
	return (gy_isalpha_ascii(c) || gy_isdigit_ascii(c));
}

static inline bool gy_isxdigit_ascii(int c) noexcept
{
	return ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'));
}	

static inline bool gy_isalnum_underscore_ascii(int c) noexcept
{
	return (c == '_' || gy_isalpha_ascii(c) || gy_isdigit_ascii(c));
}

static inline bool gy_islower_ascii(int c) noexcept
{
	return (c >= 'a' && c <= 'z');
}	

static inline bool gy_isupper_ascii(int c) noexcept
{
	return (c >= 'A' && c <= 'Z');
}	

// tolower only for ASCII else return same char
static inline int gy_tolower_ascii(int c) noexcept
{
	if ('A' <= c && c <= 'Z') return c + 'a' - 'A';
	return c;
}	

// toupper only for ASCII else return same char
static inline int gy_toupper_ascii(int c) noexcept
{
	if ('a' <= c && c <= 'z') return c - ('a' - 'A');
	return c;
}	

static inline bool gy_isblank_ascii(int c) noexcept
{
	return (c == ' ' || c == '\t');
}	

static inline bool is_space_tab(int c) noexcept
{
	return (c == ' ' || c == '\t');
}	


// string comparison for strings which need not be '\0' terminated
static bool gy_same_string(const char *str1, size_t slen1, const char *str2, size_t slen2, bool ignorecaseascii = false) noexcept
{
	if (slen1 != slen2) {
		return false;
	}	

	if (!ignorecaseascii) {
		return (0 == std::memcmp(str1, str2, slen1));
	}

	for (size_t i = 0; i < slen1; ++i) {
		if (gy_tolower_ascii(*str1++) != gy_tolower_ascii(*str2++)) {
			return false;
		}	
	}	

	return true;
}	


// Use to avoid Divide by zero 
#define NUM_OR_1(_num)										\
({												\
	decltype(_num)		_tnum = (_num), _onum = (_tnum != 0 ? _tnum : 1);		\
	_onum;											\
})

// Use to avoid nullptr string
#define STR_OR_EMPTY(_str)									\
({												\
	const char 		*_tstr = (_str), _ostr = (_tstr != nullptr ? _tstr : "");	\
	_ostr;											\
})


#define	mo_relaxed		std::memory_order_relaxed
#define	mo_acquire		std::memory_order_acquire
#define	mo_release		std::memory_order_release
#define	mo_acq_rel		std::memory_order_acq_rel
#define	mo_seq_cst		std::memory_order_seq_cst

static constexpr int	 	GY_PATH_MAX		= 512;		// Reduced PATH_MAX to save on mem
static constexpr int		MAX_DOMAINNAME_SIZE 	= 256;

[[gnu::const]] 
static constexpr bool gy_is_power_of_2(uint32_t v) noexcept
{
	return v && ((v & (v - 1)) == 0);
}	

[[gnu::const]] 
static constexpr uint32_t gy_round_up_to_power_of_2(uint32_t v) noexcept
{
	// Lifted from http://graphics.stanford.edu/~seander/bithacks.html
	v--;
	v |= v >> 1;
	v |= v >> 2;
	v |= v >> 4;
	v |= v >> 8;
	v |= v >> 16;
	v++;	

	return v;
}		

[[gnu::const]] 
static constexpr uint32_t gy_round_down_to_power_of_2(uint32_t x) noexcept
{
	x = x | (x >> 1);
	x = x | (x >> 2);
	x = x | (x >> 4);
	x = x | (x >> 8);
	x = x | (x >> 16);

	return x - (x >> 1);
}  


template <typename T, typename U = T>
static constexpr T gy_align_down(T nelem, U nalign) noexcept
{
	static_assert(std::is_integral<U>::value, "Integral data type required.");

	return ((nelem / NUM_OR_1(nalign)) * nalign);
}

template <typename T, typename U = T>
static constexpr T gy_align_up(T nelem, U nalign) noexcept
{
	T			ndown = 0;
	
	ndown = gy_align_down(nelem, nalign);

	return ndown + (!!(nelem - ndown)) * nalign;
}


// Faster version of gy_align_up but nalign needs to be a power of 2
[[gnu::const]] 
static constexpr uint64_t gy_align_up_2(uint64_t nsize, uint64_t nalign) noexcept
{
	assert(true == gy_is_power_of_2(nalign));

	return ((nsize - 1) & ~(nalign - 1)) + nalign;
}

// Faster version of gy_align_down but nalign needs to be a power of 2
[[gnu::const]] 
static constexpr uint64_t gy_align_down_2(uint64_t nsize, uint64_t nalign) noexcept
{
	assert(true == gy_is_power_of_2(nalign));

	return nsize & ~(nalign - 1);
}

// Returns whether val is aligned to nalign (nalign must be a power of 2)
template <typename T>
static constexpr bool gy_is_aligned(T val, T nalign) noexcept
{
	static_assert(std::is_integral<T>::value, "Integral data type required.");
	
	assert(true == gy_is_power_of_2(nalign));
	
	return (val & (nalign - 1));
}	

static bool gy_is_dbl_equal(double a, double b, double epsilon = 1e-7, double abstol = 1e-12) noexcept
{
	if (a == b) {
		return true;
	}

	double 			diff = std::fabs(a - b);
	double 			reltol = std::max(std::fabs(a), std::fabs(b)) * epsilon;

	return (diff < reltol || diff < abstol);
}

/*
 * Use if definite double comparison needed. 
 * In other cases a simple way is : a > b && (a - b > std::numeric_limits<double>::epsilon())
 */
static bool gy_is_dbl_greaterthan(double a, double b, double epsilon = 1e-7) noexcept
{
	double			fa = std::fabs(a), fb = std::fabs(b);

	return (a - b) > ((fa < fb ? fb : fa) * epsilon);
}

/*
 * Use if definite double comparison needed. 
 * In other cases a simple way is : a < b && (b - a > std::numeric_limits<double>::epsilon())
 */
static bool gy_is_dbl_lessthan(double a, double b, double epsilon = 1e-7) noexcept
{
	double			fa = std::fabs(a), fb = std::fabs(b);

	return (b - a) > ((fa < fb ? fb : fa) * epsilon);
}

typedef				void (*FREE_FPTR)(void *);
typedef				void (*FREE_FPTR_ARG)(void *, void *);

static void *malloc_or_throw(size_t size)
{
	void		*pbuf = ::malloc(size);

	if (pbuf) return pbuf;

	throw std::bad_alloc();
}	

static void *aligned_alloc_or_throw(size_t align, size_t size)
{
	void		*pbuf = ::aligned_alloc(align, size);

	if (pbuf) return pbuf;

	throw std::bad_alloc();
}	

static void *calloc_or_throw(size_t nmemb, size_t size)
{
	void		*pbuf = ::calloc(nmemb, size);

	if (pbuf) return pbuf;

	throw std::bad_alloc();
}	

static void *realloc_or_throw(void *ptr, size_t size)
{
	void		*pbuf = ::realloc(ptr, size);

	if (pbuf) return pbuf;

	throw std::bad_alloc();
}	

// Custom new with default params and aligned alloc as per alignment of T
template <typename T, std::enable_if_t<std::is_default_constructible<T>::value, int> = 0>
T * malloc_default_construct()
{
	T		*pdata;

	pdata = (T *)aligned_alloc_or_throw(alignof(T), sizeof(T));

	new (pdata) T();
}	

// Custom new [] with default params and aligned alloc as per alignment of T
template <typename T, std::enable_if_t<std::is_default_constructible<T>::value, int> = 0>
T * malloc_array_default_construct(size_t nelems)
{
	T		*pdata;

	pdata = (T *)aligned_alloc_or_throw(alignof(T), sizeof(T) * nelems);

	for (size_t i = 0; i < nelems; ++i) {
		new (pdata + i) T();
	}
}	

// Custom delete 
template <typename T>
void destruct_dealloc(T *pdata, FREE_FPTR free_fp) noexcept(std::is_nothrow_destructible<T>::value)
{
	if (pdata) {
		pdata->~T();

		if (free_fp) {
			(*free_fp)((void *)pdata);
		}	
	}	
}	

// Custom delete [] 
template <typename T>
void destruct_dealloc_array(T *pdata_arr, size_t nelems, FREE_FPTR free_fp) noexcept(std::is_nothrow_destructible<T>::value)
{
	if (pdata_arr) {
		
		for (size_t i = 0; i < nelems; ++i) {
			auto		pdata = pdata_arr + i;

			pdata->~T();
		}

		if (free_fp) {
			(*free_fp)((void *)pdata_arr);
		}	
	}	
}	

template <typename T>
class FUNCTOR_FREE
{
public :
	void operator()(T * pdata) const noexcept(std::is_nothrow_destructible<T>::value)
	{
		destruct_dealloc(pdata, ::free);
	}	
};

template <typename T = void>
using UNIQUE_PTR_FREE = std::unique_ptr<T, FUNCTOR_FREE<T>>;

template <typename T, void(*FreeFunc)(T *) noexcept>
struct GY_FUNC_DELETER 
{
	void operator()(T * pdata) const noexcept
	{ 
		FreeFunc(pdata); 
	}
};

template <typename T>
void gy_call_free(T *pdata) noexcept
{
	::free((void *)pdata);
}	

template <typename T, void (*function)(T *) noexcept>
using FUNC_DELETE_PTR = std::unique_ptr<T, GY_FUNC_DELETER<T, function>>;

using UNIQUE_C_PTR = FUNC_DELETE_PTR<char, gy_call_free<char>>;

/*
 * Returns the dirname ptr. Users need to pass a local uninitialized UNIQUE_C_PTR which
 * will be updated by this func
 */
const char * gy_dirname(const char *pathorig, UNIQUE_C_PTR & retuniq) noexcept;

/*
 * Returns the basename ptr. Users need to pass a local uninitialized UNIQUE_C_PTR which
 * will be updated by this func
 */
const char * gy_basename(const char *path, UNIQUE_C_PTR & retuniq) noexcept;

void gy_argv_free(char **argv) noexcept;
/*
 * Use the <return value>.get() to get the char **argv
 */
FUNC_DELETE_PTR<char *, gy_argv_free> gy_argv_split(const char *poriginput, int & argc, size_t max_strlen = 32767) noexcept; 


/*
 * Valid only for a single expression. 
 * After the expression is over the rvalue may expire resulting in a dangling reference.
 */
template <typename T> 
T & rvalue_to_lvalue(T && t)
{ 
	return t; 
}

template <typename T1, typename T2 = T1>
struct GY_PAIR
{
	T1			first;
	T2			second;
};	


static constexpr int gy_count_bits_set(uint32_t num) noexcept
{
	return __builtin_popcount(num); 
}	

static constexpr int gy_count_bits_set(uint64_t num) noexcept
{
	return __builtin_popcountll(num); 
}	

// Returns one plus the index of the least significant 1-bit of x, or if x is zero, returns zero
static constexpr int gy_least_bit_set(int x) noexcept
{
	return __builtin_ffs(x);
}
	
static constexpr int gy_least_bit_set(int64_t x) noexcept
{
	return __builtin_ffsll(x);
}

// Returns the number of leading 0-bits in x, starting at the most significant bit position. If x is 0, the result is undefined.
static constexpr int gy_leading_0_bits(int x) noexcept
{
	return __builtin_clz(x);
}
	
static constexpr int gy_leading_0_bits(int64_t x) noexcept
{
	return __builtin_clzll(x);
}

// Returns the number of trailing 0-bits in x, starting at the least significant bit position. If x is 0, the result is undefined.
static constexpr int gy_trailing_0_bits(int x) noexcept
{
	return __builtin_ctz(x);
}
	
static constexpr int gy_trailing_0_bits(int64_t x) noexcept
{
	return __builtin_ctzll(x);
}


/*
 * Empty struct to be used as a tag for class constructor which can throw exceptions
 */
struct GY_TAG_EXCEPTION
{};	

/*
 * Empty struct to be used as a tag for class constructor which should not throw exceptions
 */
struct GY_TAG_NOEXCEPT
{};

/*
 * Compile time strlen compute for string literals
 */ 
template <size_t N>
static constexpr size_t GY_CONST_STRLEN(const char (&str)[N]) noexcept
{
	return N - 1;
}

// constexpr strlen without template : Use only for compile time strlen
static constexpr size_t gy_strlen_constexpr(const char * str) noexcept 
{
	return *str ? 1 + gy_strlen_constexpr(str + 1) : 0;
}

static constexpr bool is_str_last_char(const char * str, const char c) noexcept
{
	size_t		slen = gy_strlen_constexpr(str);

	return (slen > 0 && str[slen - 1] == c);
}

template <typename T>
static constexpr T gy_div_round_up(T val, T div) noexcept
{
	static_assert(std::is_integral<T>::value, "Integral data type required.");

	return val / div + !!(val % div);
}	

static int64_t gy_div_round_near(int64_t val, int64_t div) noexcept
{
	return lround(double(val)/div);
}

template <typename T>
static constexpr inline uint64_t array_summ(const T *parr, size_t narray_size) noexcept
{
	uint64_t	tot = 0;

	for (size_t i = 0; i < narray_size; ++i) {
		tot += parr[i];
	}
	return tot;	
};

template <typename T>
static constexpr inline void array_shift_right(T *parr, size_t narray_size, size_t nshift = 1) noexcept(std::is_nothrow_move_assignable<T>::value)
{
	ssize_t		nshiftmin = std::min<ssize_t>(narray_size, nshift);

	if (nshiftmin <= 0) {
		return;
	}

	if constexpr (false == std::is_trivially_copy_assignable<T>::value) {

		for (ssize_t i = narray_size - 1; i >= nshiftmin; --i) {
			parr[i]	= std::move(parr[i - nshiftmin]);
		}        
	}
	else {
		if (narray_size <= 8) {
			for (ssize_t i = narray_size - 1; i >= nshiftmin; --i) {
				parr[i]	= std::move(parr[i - nshiftmin]);
			}
		}
		else {
			std::memmove(&parr[nshiftmin], &parr[0], sizeof(*parr) * (narray_size - nshiftmin));
		}
	}
}	

template <typename T>
static constexpr inline void array_shift_left(T *parr, size_t narray_size, size_t nshift = 1) noexcept(std::is_nothrow_move_assignable<T>::value)
{
	ssize_t		nshiftmin = std::min<ssize_t>(narray_size, nshift);

	if (nshiftmin <= 0) {
		return;
	}

	if constexpr (false == std::is_trivially_copy_assignable<T>::value) {

		for (ssize_t i = nshiftmin; i < (ssize_t)narray_size; ++i) {
			parr[i - nshiftmin] = std::move(parr[i]);
		}
	}
	else {
		if (narray_size <= 8) {
			for (ssize_t i = nshiftmin; i < (ssize_t)narray_size; ++i) {
				parr[i - nshiftmin] = std::move(parr[i]);
			}
		}
		else {
			std::memmove(&parr[0], &parr[nshiftmin], sizeof(*parr) * (narray_size - nshiftmin));
		}	
	}
}

template <typename T>
static constexpr inline void array_shift_copy_left(T *parr, size_t narray_size, const T *pnew, size_t nnew) noexcept(std::is_nothrow_copy_assignable<T>::value)
{
	ssize_t		ncopy = std::min<ssize_t>(nnew, narray_size);

	if constexpr (false == std::is_trivially_copy_assignable<T>::value) {

		for (ssize_t i = ncopy; i < (ssize_t)narray_size; ++i) {
			parr[i - ncopy] = std::move(parr[i]);
		}

		for (ssize_t i = narray_size - ncopy, j = 0; i < narray_size; ++i, ++j) {
			parr[i] = pnew[j];
		}	
	}
	else {
		std::memmove(&parr[0], &parr[ncopy], sizeof(*parr) * (narray_size - ncopy));

		std::memcpy(&parr[narray_size - ncopy], pnew, ncopy);
	}
}


template <typename T>
static constexpr inline void array_shift_move_left(T *parr, size_t narray_size, T *pnew, size_t nnew) noexcept(std::is_nothrow_move_assignable<T>::value)
{
	ssize_t		ncopy = std::min<ssize_t>(nnew, narray_size);

	if constexpr (false == std::is_trivially_copy_assignable<T>::value) {

		for (ssize_t i = ncopy; i < (ssize_t)narray_size; ++i) {
			parr[i - ncopy] = std::move(parr[i]);
		}

		for (ssize_t i = narray_size - ncopy, j = 0; i < narray_size; ++i, ++j) {
			parr[i] = std::move(pnew[j]);
		}	
	}
	else {
		std::memmove(&parr[0], &parr[ncopy], sizeof(*parr) * (narray_size - ncopy));

		std::memcpy(&parr[narray_size - ncopy], pnew, ncopy);
	}
}

template <typename T>
static constexpr inline void array_shift_copy_right(T *parr, size_t narray_size, const T *pnew, size_t nnew) noexcept(std::is_nothrow_copy_assignable<T>::value)
{
	ssize_t		ncopy = std::min<ssize_t>(nnew, narray_size);

	if constexpr (false == std::is_trivially_copy_assignable<T>::value) {

		for (ssize_t i = narray_size - 1; i >= ncopy; --i) {
			parr[i]	= std::move(parr[i - ncopy]);
		}        

		for (ssize_t i = 0; i < ncopy; ++i) {
			parr[i] = pnew[i];
		}	
		return;
	}
	else {
		std::memmove(&parr[ncopy], &parr[0], sizeof(*parr) * (narray_size - ncopy));

		std::memcpy(&parr[0], pnew, ncopy);
	}
}


template <typename T>
static constexpr inline void array_shift_move_right(T *parr, size_t narray_size, T *pnew, size_t nnew) noexcept(std::is_nothrow_move_assignable<T>::value)
{
	ssize_t		ncopy = std::min<ssize_t>(nnew, narray_size);

	if constexpr (false == std::is_trivially_copy_assignable<T>::value) {

		for (ssize_t i = narray_size - 1; i >= ncopy; --i) {
			parr[i]	= std::move(parr[i - ncopy]);
		}        

		for (ssize_t i = 0; i < ncopy; ++i) {
			parr[i] = std::move(pnew[i]);
		}	
		return;
	}
	else {
		std::memmove(&parr[ncopy], &parr[0], sizeof(*parr) * (narray_size - ncopy));

		std::memcpy(&parr[0], pnew, ncopy);
	}
}

/*
 * Wrap around safe statistic difference of continuous increment counters.
 * If newstat < oldstat, assumes wraparound (overflow)
 */ 
template <typename T>
static constexpr std::make_unsigned_t<T> gy_diff_counter(const T newstat, const T oldstat) noexcept
{
	static_assert(std::is_integral<T>::value, "Integral data type required.");

	std::make_unsigned_t<T>		uold = static_cast<decltype(uold)>(oldstat), unew = static_cast<decltype(unew)>(newstat);
	 
	if (unew >= uold) return unew - uold;
					
	std::make_unsigned_t<T>		maxdiff = decltype(maxdiff)(~0) - uold;

	return unew + maxdiff;
}

/*
 * Wrap around safe statistic difference of continuous increment counters but with a check to handle transient spurious values.
 * If the difference is over half the max range of the data type T, the new value is ignored and the diff is considered as 0.
 */ 
template <typename T>
static constexpr std::make_unsigned_t<T> gy_diff_counter_safe(const T newstat, const T oldstat, size_t max_diff_allowed = (std::numeric_limits<T>::max() >> 1)) noexcept
{
	std::make_unsigned_t<T>		ret = gy_diff_counter(newstat, oldstat);

	if (ret > max_diff_allowed) {
		// Too large a value. Ignore
		return 0;	
	}	 
	return ret;
}

/*
 * Using cmpxchg execute any atomic operation e.g. add/multiply. Returns the older value like fetch_add
 * e.g. 
 * auto mulcb = [mfactor](int64_t oldval) -> int64_t { return oldval * mfactor; };
 * int64_t newval = atomic_oper_locked(atomicvar, mulcb);
 */
template <typename FCB, typename T, typename AtomicT = std::atomic<T>>
T atomic_oper_locked(AtomicT & acnt, FCB & fcb) noexcept(noexcept(fcb((T)1)))
{
	T			expectedval, newval;

	do {
		expectedval = acnt.load(std::memory_order_relaxed);
		newval = fcb(expectedval);
	} while (false == acnt.compare_exchange_weak(expectedval, newval, std::memory_order_release, std::memory_order_relaxed));	

	return expectedval;
}	

// Atomic decrement to min 0 using cmpxchg
template <typename T, typename AtomicT = std::atomic<T>>
T atomic_sub_locked_chked(AtomicT & acnt, T subval) noexcept
{
	auto lam1 = [subval](T oldval) noexcept ->T
	{
		std::make_signed_t<T>		o = decltype(o)(oldval), s = decltype(s)(subval);

		if (o - s > 0) {
			return oldval - subval;
		}
		return (T)0;
	};

	return atomic_oper_locked<decltype(lam1), T, AtomicT>(acnt, lam1);
}	

[[gnu::const]] static uint32_t get_uint32_hash(uint32_t val) noexcept
{
	return jhash_1word(val, 0xceedfead);
}	

[[gnu::const]] static uint32_t get_int_hash(int val) noexcept
{
	return jhash_1word((uint32_t)val, 0xceedfead);
}	

[[gnu::const]] static uint32_t get_uint64_hash(uint64_t ukey) noexcept
{
	return jhash_2words(ukey & 0xFFFFFFFF, ukey >> 32, 0xceedfead);
}	

[[gnu::const]] static uint32_t get_pointer_hash(void * pval) noexcept
{
	uint64_t	val = reinterpret_cast<uint64_t>(pval);

	return get_uint64_hash(val);
}	
	
/*
 * Will return jhash'ed result. The hash is limited to 32 bits and upcast to 64 bits.
 * For std::pair and std::tuple of same sized integral types, ignore_uniq_obj_trait can be set to true
 */
template <typename T, bool ignore_uniq_obj_trait = false>
class GY_JHASHER 
{
public :
	static_assert(sizeof(T) < 512, "Please use a different Hashing algorithm for larger structs");

	static_assert(std::has_unique_object_representations_v<T> || ignore_uniq_obj_trait, "Padded structs cannot be hashed using this class");

	template <typename F = T, std::enable_if_t<sizeof(F) <= 32 && sizeof(F) == gy_align_up_2(sizeof(F), 4) && alignof(F) >= 4, int> = 0>
	uint64_t operator()(const T key) const noexcept
	{
		if constexpr(sizeof(key) == 4) {
			return jhash_1word(static_cast<uint32_t>(key), 0xceedfead);
		}
		else if constexpr(sizeof(key) == 8) {
			uint64_t		ukey = (uint64_t)(uintptr_t)(key);

			return jhash_2words(ukey & 0xFFFFFFFF, ukey >> 32, 0xceedfead);
		}

		return jhash2(reinterpret_cast<const uint32_t *>(&key), sizeof(key)/sizeof(uint32_t), 0xceedfead);
	}

	/*
	 * Structs with size < 4 or with alignment < 4
	 */
	template <typename F = T, std::enable_if_t<sizeof(F) <= 32 && (!(sizeof(F) == gy_align_up_2(sizeof(F), 4) && alignof(F) >= 4)), int> = 0>
	uint64_t operator()(const T key) const noexcept
	{
		static constexpr size_t		TALIGNSZ = gy_align_up_2(sizeof(T), 4);	
		alignas(8) char			tbuf[TALIGNSZ]	{};	

		std::memcpy(tbuf, &key, sizeof(T));

		if constexpr(sizeof(tbuf) == 4) {
			return jhash_1word(reinterpret_cast<const uint32_t *>(tbuf), 0xceedfead);
		}

		return jhash2(reinterpret_cast<const uint32_t *>(tbuf), sizeof(tbuf)/sizeof(uint32_t), 0xceedfead);
	}

	template <typename F = T, std::enable_if_t<(sizeof(F) > 32), int> = 0>
	uint64_t operator()(const T & key) const noexcept
	{
		static constexpr size_t		TALIGNSZ = gy_align_up_2(sizeof(T), 4);	
		alignas(8) char			tbuf[TALIGNSZ];	

		std::memcpy(tbuf, &key, sizeof(T));
		std::memset(tbuf + sizeof(T), 0, sizeof(tbuf) - sizeof(T));

		return jhash2(reinterpret_cast<const uint32_t *>(tbuf), sizeof(tbuf)/sizeof(uint32_t), 0xceedfead);
	}
};


template <size_t szbuf_, size_t align_bytes = 8>
class CHAR_BUF
{
protected :	
	alignas(align_bytes) char	buf_[szbuf_];

public :
	static_assert(szbuf_ > 0 && align_bytes > 0);

	CHAR_BUF() noexcept
	{
		*buf_ = 0;
	}	

	CHAR_BUF(const char * pmsg) noexcept
	{
		setbuf(pmsg);
	}

	CHAR_BUF(const char * pmsg, size_t szstr) noexcept
	{
		setbuf(pmsg, szstr);
	}

	CHAR_BUF(std::string_view v) noexcept
	{
		setbuf(v.data(), v.size());
	}

	// Adds ... mark for truncated strings over 16 bytes long
	CHAR_BUF(const char * pmsg, size_t szstr, bool add_truncation_mark) noexcept
	{
		size_t			sz;

		GY_SAFE_MEMCPY(buf_, szbuf_ - 1, pmsg, szstr, sz);
		
		if (add_truncation_mark && sz + 3 < szstr && sz > 16) {
			buf_[sz - 3] = '.';
			buf_[sz - 2] = '.';
			buf_[sz - 1] = '.';
		}	

		buf_[sz] = 0;
	}

	template <size_t l2, size_t alignb>
	CHAR_BUF(const CHAR_BUF <l2, alignb> & other) noexcept
	{
		if constexpr (l2 <= 512) {
			setbuf(other.get(), l2 - 1);
		}
		else {
			setbuf(other.get());
		}	
	}

	template <size_t l2, size_t alignb>
	CHAR_BUF & operator= (const CHAR_BUF <l2, alignb> & other) noexcept
	{
		if (this != &other) {
			if constexpr (l2 <= 512) {
				setbuf(other.get(), l2 - 1);
			}
			else {
				setbuf(other.get());
			}	
		}

		return *this;
	}

	template <size_t l2, size_t alignb>
	CHAR_BUF(CHAR_BUF <l2, alignb> && other) noexcept
	{
		if constexpr (l2 <= 512) {
			setbuf(other.get(), l2 - 1);
		}
		else {
			setbuf(other.get());
		}	

		*other.get() = 0;
	}

	template <size_t l2, size_t alignb>
	CHAR_BUF & operator= (CHAR_BUF <l2, alignb> && other) noexcept
	{
		if (this != &other) {
			if constexpr (l2 <= 512) {
				setbuf(other.get(), l2 - 1);
			}
			else {
				setbuf(other.get());
			}	

			*other.get() = 0;
		}

		return *this;
	}

	void setbuf(const char *pmsg) noexcept
	{
		GY_STRNCPY(buf_, pmsg, szbuf_);
	}	
	
	void setbuf(const char *pmsg, size_t szstr) noexcept
	{
		size_t			sz;

		GY_SAFE_MEMCPY(buf_, szbuf_ - 1, pmsg, szstr, sz);
		buf_[sz] = 0;
	}

	char * get() noexcept
	{
		return buf_;
	}	

	const char * get() const noexcept
	{
		return buf_;
	}	

	constexpr size_t maxsz() const noexcept
	{
		return szbuf_;
	}	

	size_t get_hash() const noexcept
	{
		return gy_cityhash64(get(), gy_strnlen(get(), szbuf_));
	}

	template <size_t l2, size_t alignb>
	bool operator== (const CHAR_BUF <l2, alignb> & rhs) const noexcept
	{
		return (0 == std::strcmp(get(), rhs.get()));
	}

	bool operator== (const char * prhs) const noexcept
	{
		return prhs && (0 == std::strcmp(get(), prhs));
	}

	friend std::ostream & operator<< (std::ostream & stream, const CHAR_BUF & str) 
	{
		return stream << str.get();
	}

	class CHAR_BUF_HASH 
	{
	public :
		size_t operator()(const CHAR_BUF & str) const noexcept
		{
			return str.get_hash();
		}
	};
};


template <size_t szbuf_, size_t align_bytes = 8, bool memset_trail_bytes = false>
class UCHAR_BUF
{
protected :	
	alignas(align_bytes) uint8_t	buf_[szbuf_];

public :
	static_assert(szbuf_ > 0 && align_bytes > 0);

	UCHAR_BUF() noexcept		= default;

	UCHAR_BUF(const void *pmsg, size_t szstr) noexcept
	{
		setbuf(pmsg, szstr);
	}
	
	void setbuf(const void *pmsg, size_t szstr) noexcept
	{
		size_t			sz;

		GY_SAFE_MEMCPY(buf_, szbuf_ - 1, pmsg, szstr, sz);

		if (memset_trail_bytes && sz < szbuf_) {
			std::memset(buf_ + sz, 0, szbuf_ - sz);
		}
	}

	uint8_t * get() noexcept
	{
		return buf_;
	}	

	const uint8_t * get() const noexcept
	{
		return buf_;
	}

	template <bool memset_trail = memset_trail_bytes, std::enable_if_t<memset_trail == true, int> = 0>
	bool operator== (const UCHAR_BUF & rhs) const noexcept
	{
		return (0 == std::memcmp(get(), rhs.get(), szbuf_));
	}

	constexpr size_t maxsz() const noexcept
	{
		return szbuf_;
	}	
};

static CHAR_BUF<128> gy_get_perror(int terrno = errno) noexcept
{
	char			pbuf[128];
	const char		*ptmp;

	if (terrno != 0) {
		ptmp = strerror_r(terrno, pbuf, sizeof(pbuf) - 1);
	}
	else {
		ptmp = "";
	}	

	return CHAR_BUF<128>(ptmp);
}	

class GY_EXCEPTION : public std::exception
{
public:
	GY_EXCEPTION(const char *msg1, int ecode = 0) noexcept
		: ecode_(ecode)
	{
		GY_STRNCPY(msg_, msg1, sizeof(msg_) - 1);
	}
	
	GY_EXCEPTION() noexcept 
	{
		*msg_ = '\0';
	}

	GY_EXCEPTION(int ecode) noexcept 
		: ecode_(ecode)
	{
		*msg_ = '\0';
	}

	GY_EXCEPTION(bool issyserr) noexcept 
		: errno_(errno)
	{
		*msg_ = '\0';
	}

	GY_EXCEPTION(int ecode, bool issyserr) noexcept 
		: ecode_(ecode), errno_(errno)
	{
		*msg_ = '\0';
	}

	virtual const char *what() const noexcept
	{
		return msg_;
	}

	static int get_except_code(const std::exception & e)
	{
		if (auto e2 = dynamic_cast<const GY_EXCEPTION *>(&e)) {
			return e2->ecode_;
		}	

		return 0;
	}

	static std::pair<int, int> get_except_code_errno(const std::exception & e)
	{
		if (auto e2 = dynamic_cast<const GY_EXCEPTION *>(&e)) {
			return {e2->ecode_, e2->errno_};
		}	

		return {0, 0};
	}	

	static int get_except_code(const GY_EXCEPTION & e)
	{
		return e.ecode_;
	}

	static std::pair<int, int> get_except_code_errno(const GY_EXCEPTION & e)
	{
		return {e.ecode_, e.errno_};
	}	

	char			msg_[700];
	int			ecode_		{0};
	int			errno_		{0};
};

/*
 * Throw exceptions with extra info for debugging and skipping multiple mallocs. Will allocate a single malloc of around 800 bytes per exception.
 *
 * Throws an exception of class GY_EXCEPTION defined above. For Syscall Error exceptions please use GY_THROW_SYS_EXCEPTION instead
 *
 * e.g. : GY_THROW_EXCEPTION("Could not parse file %s : ", pfilename);
 *
 * This will throw an exception message of a format "Could not parse file ./test1.dat (Line #201)"
 * 
 * The (Line #201) is the line where the exception occured and not where it was caught 
 */ 
#define GY_THROW_EXCEPTION(format, _arg...) 												\
do {																	\
	static_assert(false == gyeeta::is_str_last_char(format, '\n'), "GY_THROW_EXCEPTION format must not end with a newline");	\
																	\
	gyeeta::GY_EXCEPTION	_exc;													\
																	\
	::snprintf(_exc.msg_, sizeof(_exc.msg_), format " (Line #%d)", ##_arg, __LINE__);						\
	throw _exc;															\
} while (0)

#define GY_THROW_EXCEPT_CODE(ecode, format, _arg...) 											\
do {																	\
	static_assert(false == gyeeta::is_str_last_char(format, '\n'), "GY_THROW_EXCEPTION format must not end with a newline");	\
																	\
	int			ec = static_cast<int>(ecode);										\
	gyeeta::GY_EXCEPTION	_exc(ec);												\
																	\
	::snprintf(_exc.msg_, sizeof(_exc.msg_), format " (Line #%d)", ##_arg, __LINE__);						\
	throw _exc;															\
} while (0)


/*
 * Throw exceptions with extra info for debugging and skipping multiple mallocs. Will allocate a single malloc of around 800 bytes per exception.
 *
 * Throws an exception of class GY_EXCEPTION defined above for use with syscall errors
 *
 * e.g. : GY_THROW_SYS_EXCEPTION("Could not open %s : ", pfilename);
 *
 * This will throw an exception message of a format "[SYSTEM ERROR]: No such file or directory (2) : Could not open ./test1.dat (Line #201)"
 * 
 * The (Line #201) is the line where the exception occured and not where it was caught. The (2) indicates the errno 
 */ 
#define GY_THROW_SYS_EXCEPTION(format, _arg...) 											\
do {																	\
	char 			_bufp[128], *_pmsg;											\
																	\
	static_assert(false == gyeeta::is_str_last_char(format, '\n'), "GY_THROW_SYS_EXCEPTION format must not end with a newline");	\
																	\
	_pmsg = ::strerror_r(errno, _bufp, sizeof(_bufp) - 1);										\
																	\
	gyeeta::GY_EXCEPTION	_exc(true);												\
																	\
	::snprintf(_exc.msg_, sizeof(_exc.msg_), "[SYSTEM ERROR]: %s (%d) : " format " (Line #%d)", _pmsg, errno,  ##_arg, __LINE__);	\
	throw _exc;															\
} while (0)


#define GY_THROW_EXPR_CODE(ecode, format, _arg...) 											\
do {																	\
	int			ec = static_cast<int>(ecode);										\
	gyeeta::GY_EXCEPTION	_exc(ec);												\
																	\
	::snprintf(_exc.msg_, sizeof(_exc.msg_), format, ##_arg);									\
	throw _exc;															\
} while (0)

#define GY_THROW_SYS_EXPR_CODE(ecode, format, _arg...) 											\
do {																	\
	char 			_bufp[128], *_pmsg;											\
	int			ec = static_cast<int>(ecode);										\
	int			errnum = errno;												\
																	\
	static_assert(false == gyeeta::is_str_last_char(format, '\n'), "GY_THROW_SYS_EXPRESSION format must not end with a newline");	\
																	\
	_pmsg = ::strerror_r(errnum, _bufp, sizeof(_bufp) - 1);										\
																	\
	gyeeta::GY_EXCEPTION	_exc(ec, true);												\
																	\
	::snprintf(_exc.msg_, sizeof(_exc.msg_), format " (Error %s (%d))", ##_arg, _pmsg, errnum);					\
	throw _exc;															\
} while (0)


/*
 * Simple snprintf throw. No extra info added to thrown string...
 */
#define GY_THROW_EXPRESSION(format, _arg...) 												\
do {																	\
	gyeeta::GY_EXCEPTION	_exc;													\
																	\
	::snprintf(_exc.msg_, sizeof(_exc.msg_), format, ##_arg);									\
	throw _exc;															\
} while (0)

/*
 * Simple snprintf and strerror_r + errno throw. No other extra info added to thrown string...
 */
#define GY_THROW_SYS_EXPRESSION(format, _arg...) 											\
do {																	\
	char 			_bufp[128], *_pmsg;											\
	int			errnum = errno;												\
																	\
	static_assert(false == gyeeta::is_str_last_char(format, '\n'), "GY_THROW_SYS_EXPRESSION format must not end with a newline");	\
																	\
	_pmsg = ::strerror_r(errnum, _bufp, sizeof(_bufp) - 1);										\
																	\
	gyeeta::GY_EXCEPTION	_exc(true);												\
																	\
	::snprintf(_exc.msg_, sizeof(_exc.msg_), format " (Error %s (%d))", ##_arg, _pmsg, errnum);					\
	throw _exc;															\
} while (0)



/* 
 * Generic Exception Handler boilerplate code. 
 *
 * e.g. output :
 * Exception 'Another instance of the process ./partha with the same lock file seems to be running...' : caught at [int start_partha(int, char**):717]
 * 
 * GY_GET_EXCEPT_STRING contains the exception reason as a const char * buffer.
 *
 * Will catch exceptions of class std::exception and ... catch all
 *
 * Users can add custom exception classes above the GY_CATCH_EXCEPTION code as in :
 *
 * try { ... 
 * }
 * catch (int exceptcode) {
 * 	...
 * }
 * GY_CATCH_EXCEPTION(
 *	// Your code e.g.
 * 	ERRORPRINT("Exception caught due to : %s\n", GY_GET_EXCEPT_STRING);
 *	if (fd > 0) close(fd);
 * );
 */ 
#define GY_CATCH_EXCEPTION(...)												\
	catch (const std::exception &e) {										\
		char  __attribute__((unused)) except_string__[800];							\
															\
		::snprintf(except_string__, sizeof(except_string__), 							\
			" Exception \'%s\' : caught at [%s:%u]", e.what(), __PRETTY_FUNCTION__, __LINE__);		\
		__VA_ARGS__;												\
	}														\
	catch (...) {													\
		char  __attribute__((unused)) except_string__[800];							\
															\
		::snprintf(except_string__, sizeof(except_string__),	 						\
			" Unknown type Exception caught at [%s:%u]", __PRETTY_FUNCTION__, __LINE__);			\
		__VA_ARGS__;												\
	}


/*
 * Simple exception catching. No extra info added to thrown string for std::exception objects...
 */
#define GY_CATCH_EXPRESSION(...)											\
	catch (const std::exception &e) {										\
		const auto except_string__ = e.what();									\
		__VA_ARGS__;												\
	}														\
	catch (...) {													\
		GY_EXCEPTION			e;									\
		const char			*except_string__ = e.msg_;						\
															\
		::snprintf(e.msg_, sizeof(e.msg_),			 						\
			" Unknown type Exception caught at [%s:%u]", __PRETTY_FUNCTION__, __LINE__);			\
		__VA_ARGS__;												\
	}


#define GY_GET_EXCEPT_STRING		except_string__
#define GY_GET_EXCEPT_CODE()		GY_EXCEPTION::get_except_code(e)		
#define GY_GET_EXCEPT_CODE_ERRNO()	GY_EXCEPTION::get_except_code_errno(e)		

/*
 * On exceptions, the passed errmsg along with the exception cause will be ERRORPRINT'ed
 * Pass a 0 length errmsg to not print anything on an exception
 * e.g.

	std::unordered_map<int, uint64_t>	tmap;

	try {
		for (int j = 0; j < 100'000; ++j) {
			tmap.emplace(j, get_nsec_clock());
		}
	}	
	GY_CATCH_MSG("Adding to map failed");
 *
 */
#define GY_CATCH_MSG(errmsg)												\
	GY_CATCH_EXPRESSION(												\
		const char			*errmsg_ = static_cast<const char *>(errmsg);				\
		if (errmsg_ && *errmsg_) {										\
			ERRORPRINT("%s : %s\n", errmsg_, GY_GET_EXCEPT_STRING);						\
		}													\
	);														\

/*
 * Execute the passed block of code within a try catch and on exception return -1 or else 0
 * On exceptions, the passed errmsg along with the exception cause will be ERRORPRINT'ed
 * Pass a 0 length errmsg to not print anything on an exception
 * e.g.

	std::unordered_map<int, uint64_t>	tmap;

	if (0 != TRY_CATCH_BLOCK("Error while inserting into map",
		for (int j = 0; j < 100'000; ++j) {
			tmap.emplace(j, get_nsec_clock());
		}
	)) return -1;
 *
 * Disadvantage is we cannot debug the block statements in a debugger as it will be a single expression...
 */
#define TRY_CATCH_BLOCK(errmsg, ...)											\
({ 															\
	int			ret__ = -1;										\
															\
	try {														\
		__VA_ARGS__;												\
		ret__ = 0;												\
	}														\
	GY_CATCH_EXPRESSION(												\
		const char			*errmsg_ = static_cast<const char *>(errmsg);				\
		if (errmsg_ && *errmsg_) {										\
			ERRORPRINT("%s : %s\n", errmsg_, GY_GET_EXCEPT_STRING);						\
		}													\
	);														\
	ret__;														\
})

#define ASSERT_OR_THROW(cond, format, _arg...)												\
do {																	\
	static_assert(false == gyeeta::is_str_last_char(format, '\n'), "ASSERT_OR_THROW errmsg must not end with a newline");		\
																	\
	assert((cond));															\
																	\
	if (false == (cond)) {														\
		gyeeta::GY_EXCEPTION	_exc;												\
																	\
		::snprintf(_exc.msg_, sizeof(_exc.msg_), format " (Line #%d)", ##_arg, __LINE__);					\
		throw _exc;														\
	}																\
} while (0)


/*
 * noexcept cast for non noexcept func calls. Lifted from https://twitter.com/hankadusikova/status/1276828584179642368
 *
 * e.g. ret = gy_noexcept_cast(foo)();
 */
template <typename Fnc> 
struct gy_noexcept_cast_helper;

template <typename Ret, typename... Args> 
struct gy_noexcept_cast_helper<Ret(*)(Args...)> 
{
	using type = Ret(*)(Args...) noexcept;
};

template <typename T> 
static auto gy_noexcept_cast(const T obj) noexcept 
{
	return reinterpret_cast<typename gy_noexcept_cast_helper<T>::type>(obj);
};


// Enum for use in Callback invoked while in a loop
enum CB_RET_E : int
{
	CB_OK		= 0,
	CB_DELETE_ELEM	= 1,
	CB_BREAK_LOOP	= 2,
	CB_DELETE_BREAK	= 3,	// Delete while in a loop and then break
};

typedef uint64_t			gy_msec_t;
typedef uint64_t			gy_usec_t;
typedef	uint64_t			gy_nsec_t;

static constexpr uint64_t		GY_MSEC_PER_SEC  	= 1000;

static constexpr uint64_t		GY_USEC_PER_SEC  	= 1'000'000;
static constexpr uint64_t		GY_USEC_PER_MSEC	= 1000;

static constexpr uint64_t		GY_NSEC_PER_SEC 	= 1'000'000'000;
static constexpr uint64_t		GY_NSEC_PER_MSEC	= 1'000'000;
static constexpr uint64_t		GY_NSEC_PER_USEC	= 1000;

static constexpr uint64_t		GY_SEC_PER_MINUTE	= (60);
static constexpr uint64_t		GY_MSEC_PER_MINUTE	= (60 * GY_MSEC_PER_SEC);
static constexpr uint64_t		GY_USEC_PER_MINUTE	= (60 * GY_USEC_PER_SEC);
static constexpr uint64_t		GY_NSEC_PER_MINUTE	= (60 * GY_NSEC_PER_SEC);

static constexpr uint64_t		GY_SEC_PER_HOUR		= (60 * GY_SEC_PER_MINUTE);
static constexpr uint64_t		GY_MSEC_PER_HOUR	= (60 * GY_MSEC_PER_MINUTE);
static constexpr uint64_t		GY_USEC_PER_HOUR	= (60 * GY_USEC_PER_MINUTE);
static constexpr uint64_t		GY_NSEC_PER_HOUR	= (60 * GY_NSEC_PER_MINUTE);

static constexpr uint64_t		GY_SEC_PER_DAY		= (24 * GY_SEC_PER_HOUR);
static constexpr uint64_t		GY_MSEC_PER_DAY		= (24 * GY_MSEC_PER_HOUR);
static constexpr uint64_t		GY_USEC_PER_DAY		= (24 * GY_USEC_PER_HOUR);
static constexpr uint64_t		GY_NSEC_PER_DAY		= (24 * GY_NSEC_PER_HOUR);

static constexpr uint64_t		GY_SEC_PER_WEEK		= (7 * GY_SEC_PER_DAY);
static constexpr uint64_t		GY_MSEC_PER_WEEK	= (7 * GY_MSEC_PER_DAY);
static constexpr uint64_t		GY_USEC_PER_WEEK	= (7 * GY_USEC_PER_DAY);
static constexpr uint64_t		GY_NSEC_PER_WEEK	= (7 * GY_NSEC_PER_DAY);

static constexpr uint64_t		GY_SEC_PER_MONTH	= (2629800ul);					// 365.25 / 12 : 30.43 days
static constexpr uint64_t		GY_MSEC_PER_MONTH	= (2629800ul * GY_MSEC_PER_SEC);		// 365.25 / 12 : 30.43 days
static constexpr uint64_t		GY_USEC_PER_MONTH	= (2629800ul * GY_USEC_PER_SEC);		// 365.25 / 12 : 30.43 days
static constexpr uint64_t		GY_NSEC_PER_MONTH	= (2629800ul * GY_NSEC_PER_SEC);

static constexpr uint64_t		GY_SEC_PER_YEAR		= (31557600ul);
static constexpr uint64_t		GY_MSEC_PER_YEAR	= (31557600ul * GY_MSEC_PER_SEC);
static constexpr uint64_t		GY_USEC_PER_YEAR	= (31557600ul * GY_USEC_PER_SEC);
static constexpr uint64_t		GY_NSEC_PER_YEAR	= (31557600ul * GY_NSEC_PER_SEC);		// 365.25 days in a year

static inline struct timeval get_timeval() noexcept
{	
	struct timeval		tv;

	::gettimeofday(&tv, nullptr);

	return tv;
}	

static inline struct timespec get_timespec() noexcept
{	
	struct timespec		ts;

	clock_gettime(CLOCK_REALTIME, &ts);				

	return ts;
}	

static inline int64_t get_sec_time() noexcept
{	
	struct timespec			ts_; 
	
	clock_gettime(CLOCK_REALTIME, &ts_);				

	return ts_.tv_sec; 
}		

static inline int64_t get_sec_clock() noexcept
{	
	struct timespec			ts_; 
	
	clock_gettime(CLOCK_MONOTONIC, &ts_);				

	return ts_.tv_sec;
}	

static inline uint64_t get_msec_time() noexcept
{	
	struct timespec			ts_; 
	
	clock_gettime(CLOCK_REALTIME, &ts_);				

	return ts_.tv_sec * GY_MSEC_PER_SEC + ts_.tv_nsec/GY_NSEC_PER_MSEC;
}		

static inline uint64_t get_msec_clock() noexcept
{	
	struct timespec			ts_; 
	
	clock_gettime(CLOCK_MONOTONIC, &ts_);				

	return ts_.tv_sec * GY_MSEC_PER_SEC + ts_.tv_nsec/GY_NSEC_PER_MSEC;
}	

static inline uint64_t get_usec_time() noexcept
{	
	struct timespec			ts_; 
	
	clock_gettime(CLOCK_REALTIME, &ts_);				

	return ts_.tv_sec * GY_USEC_PER_SEC + ts_.tv_nsec/1000;
}		

static inline uint64_t get_usec_clock() noexcept
{	
	struct timespec			ts_; 
	
	clock_gettime(CLOCK_MONOTONIC, &ts_);				

	return ts_.tv_sec * GY_USEC_PER_SEC + ts_.tv_nsec/1000;
}	

static inline uint64_t get_nsec_time() noexcept
{	
	struct timespec			ts_; 
	
	clock_gettime(CLOCK_REALTIME, &ts_);				

	return ts_.tv_sec * GY_NSEC_PER_SEC + ts_.tv_nsec;
}		

static inline uint64_t get_nsec_clock() noexcept
{	
	struct timespec			ts_; 
	
	clock_gettime(CLOCK_MONOTONIC, &ts_);				

	return ts_.tv_sec * GY_NSEC_PER_SEC + ts_.tv_nsec;
}	

static inline uint64_t get_nsec_bootclock() noexcept
{	
	struct timespec			ts_; 
	
	clock_gettime(CLOCK_BOOTTIME, &ts_);				

	return ts_.tv_sec * GY_NSEC_PER_SEC + ts_.tv_nsec;
}	

static inline uint64_t get_usec_bootclock() noexcept
{
	return get_nsec_bootclock()/1000;
}	

static inline uint64_t get_msec_bootclock() noexcept
{
	return get_nsec_bootclock()/GY_NSEC_PER_MSEC;
}	

static inline uint64_t get_sec_bootclock() noexcept
{
	return get_nsec_bootclock()/GY_NSEC_PER_SEC;
}	

#define GY_USEC_CONVERT(_sec, _usec)								\
({												\
	uint64_t	_totusec = (_sec) * gyeeta::GY_USEC_PER_SEC + (_usec);			\
	_totusec;										\
})

#define GY_NSEC_CONVERT(_sec, _nsec)								\
({												\
	uint64_t	_totnsec = (_sec) * gyeeta::GY_NSEC_PER_SEC + (_nsec);			\
	_totnsec;										\
})

#define GY_USEC_TO_TIMEVAL(_usecin)								\
({												\
	uint64_t	_usec = (_usecin);							\
	struct timeval	_tv = { (time_t)((_usec) / gyeeta::GY_USEC_PER_SEC), 			\
				int64_t((uint64_t)((_usec) % gyeeta::GY_USEC_PER_SEC)) };	\
	_tv;											\
})	

#define GY_USEC_TO_TIMESPEC(_usecin)								\
({												\
	uint64_t	_usec = (_usecin);							\
	struct timespec	_ts = { (time_t)((_usec) / gyeeta::GY_USEC_PER_SEC), 			\
					int64_t((_usec) % gyeeta::GY_USEC_PER_SEC) * 1000ul };	\
	_ts;											\
})	

#define GY_NSEC_TO_TIMESPEC(_nsecin)								\
({												\
	uint64_t	_nsec = (_nsecin);							\
	struct timespec	_ts = { (time_t)((_nsec) / gyeeta::GY_NSEC_PER_SEC), 			\
					int64_t((_nsec) % gyeeta::GY_NSEC_PER_SEC) };		\
	_ts;											\
})	

static inline struct timespec timeval_to_timespec(const struct timeval tv) noexcept
{
	return {tv.tv_sec, tv.tv_usec * 1000};
}	

static inline struct timeval timespec_to_timeval(const struct timespec ts) noexcept
{
	return {ts.tv_sec, ts.tv_nsec / 1000};
}	


/*
 * Compare 2 struct timevals. Returns -1 if second < first, 1 if second > first and 0 if same
 */ 
#define GY_TIMEVAL_CMP(_first, _sec)									\
({													\
	int	_res = 1; 										\
													\
	if ((_sec)->tv_sec < ((_first)->tv_sec)) {							\
		_res = -1;										\
	}												\
	else if (((_sec)->tv_sec == ((_first)->tv_sec)) && ((_sec)->tv_usec < ((_first)->tv_usec))) {	\
		_res = -1;										\
	}												\
	else if (((_sec)->tv_sec == ((_first)->tv_sec)) && ((_sec)->tv_usec == ((_first)->tv_usec))) {	\
		_res = 0;										\
	}												\
	_res;												\
})

/*
 * Compare 2 struct timespecs. Returns -1 if second < first, 1 if second > first and 0 if same
 */ 
#define GY_TIMESPEC_CMP(_first, _sec)									\
({													\
	int	_res = 1; 										\
													\
	if ((_sec)->tv_sec < ((_first)->tv_sec)) {							\
		_res = -1;										\
	}												\
	else if (((_sec)->tv_sec == ((_first)->tv_sec)) && ((_sec)->tv_nsec < ((_first)->tv_nsec))) {	\
		_res = -1;										\
	}												\
	else if (((_sec)->tv_sec == ((_first)->tv_sec)) && ((_sec)->tv_nsec == ((_first)->tv_nsec))) {	\
		_res = 0;										\
	}												\
	_res;												\
})

// Returns diff of 2 timeval in usecs iff _currpkt > _prevpkt, else returns 0
#define GY_TV_DIFF(_currpkt, _prevpkt)								\
({												\
	uint64_t		_currus, _prevus, _resultus;					\
												\
	_currus = GY_USEC_CONVERT((_currpkt)->tv_sec, (_currpkt)->tv_usec);			\
	_prevus = GY_USEC_CONVERT((_prevpkt)->tv_sec, (_prevpkt)->tv_usec);			\
												\
	(_resultus) = _currus > _prevus ? _currus - _prevus : 0ul;				\
	_resultus;										\
})


// msec_to_add is truncated to 30 years
static inline void add_to_timespec(struct timespec & ts, uint64_t msec_to_add) noexcept
{
	uint64_t		nsec_to_add = msec_to_add < 30 * GY_MSEC_PER_YEAR ? msec_to_add * GY_NSEC_PER_MSEC : 30 * GY_NSEC_PER_YEAR;

	ts.tv_sec 		+= nsec_to_add / GY_NSEC_PER_SEC;
	ts.tv_nsec 		+= nsec_to_add % GY_NSEC_PER_SEC;

	if (ts.tv_nsec >= (signed)GY_NSEC_PER_SEC) {
		ts.tv_nsec -= GY_NSEC_PER_SEC;
		ts.tv_sec++;
	}	
}	

// msec_to_add is truncated to 30 years
static inline void add_to_timeval(struct timeval & tv, uint64_t msec_to_add) noexcept
{
	uint64_t		usec_to_add = msec_to_add < 30 * GY_MSEC_PER_YEAR ? msec_to_add * GY_USEC_PER_MSEC : 30 * GY_USEC_PER_YEAR;

	tv.tv_sec 		+= usec_to_add / GY_USEC_PER_SEC;
	tv.tv_usec 		+= usec_to_add % GY_USEC_PER_SEC;

	if (tv.tv_usec >= (signed)GY_USEC_PER_SEC) {
		tv.tv_usec -= GY_USEC_PER_SEC;
		tv.tv_sec++;
	}	
}	


/*
 * Get CLOCK_REALTIME usec from CLOCK_MONOTONIC or CLOCK_BOOTTIME (set boot_clock to true for this)
 * This is prone to scheduling side effects. If accurate correlation is needed, specify chk_accuracy
 */
static inline uint64_t get_usec_time_from_clock(uint64_t clock_usec, bool chk_accuracy = false, bool boot_clock = false) noexcept
{
	int64_t			currclock = !boot_clock ? get_usec_clock() : get_usec_bootclock();
	int64_t			currtime = get_usec_time();

	if (chk_accuracy) {
		int64_t			currclock2 = !boot_clock ? get_usec_clock() : get_usec_bootclock();
		
		if (gy_unlikely(currclock2 - currclock > 100 /* 100 usec */)) {
			currclock 	= currclock2;
			currtime  	= get_usec_time();
		}	
	}	
	
	return currtime + (clock_usec - currclock);
}	

/*
 * Get CLOCK_REALTIME nsec from CLOCK_MONOTONIC or CLOCK_BOOTTIME (set boot_clock to true for this)
 * This is prone to scheduling side effects. If accurate correlation is needed, specify chk_accuracy
 */
static inline uint64_t get_nsec_time_from_clock(uint64_t clock_nsec, bool chk_accuracy = false, bool boot_clock = false) noexcept
{
	int64_t			currclock = !boot_clock ? get_nsec_clock() : get_nsec_bootclock();
	int64_t			currtime = get_nsec_time();

	if (gy_unlikely(chk_accuracy)) {
		int64_t			currclock2 = !boot_clock ? get_nsec_clock() : get_nsec_bootclock();
		
		if (gy_unlikely(currclock2 - currclock > 100'000 /* 100 usec */)) {
			currclock 	= currclock2;
			currtime  	= get_nsec_time();
		}	
	}	

	return currtime + (clock_nsec - currclock);
}	

/*
 * Get CLOCK_REALTIME time_t from CLOCK_MONOTONIC or CLOCK_BOOTTIME (set boot_clock to true for this)
 * This is prone to scheduling side effects. If accurate correlation is needed, specify chk_accuracy
 */
static inline int64_t get_sec_time_from_clock(int64_t clock_sec, bool chk_accuracy = false, bool boot_clock = false) noexcept
{
	int64_t			currclock = !boot_clock ? get_sec_clock() : get_sec_bootclock();
	int64_t			currtime = get_sec_time();

	if (chk_accuracy) {
		int64_t			currclock2 = !boot_clock ? get_sec_clock() : get_sec_bootclock();
		
		if (gy_unlikely(currclock2 - currclock > 1)) {
			currclock 	= currclock2;
			currtime  	= get_sec_time();
		}	
	}	
	
	return currtime + (clock_sec - currclock);
}	

/*
 * Does not handle Host Suspend time
 */
static inline uint64_t get_usec_clock_from_time(int64_t atime) noexcept
{
	int64_t			currtime = get_usec_time();
	int64_t			currclock = get_usec_clock();

	return currclock + (atime - currtime);
}	

/*
 * Does not handle Host Suspend time
 */
static inline uint64_t get_nsec_clock_from_time(int64_t atime) noexcept
{
	int64_t			currtime = get_nsec_time();
	int64_t			currclock = get_nsec_clock();

	return currclock + (atime - currtime);
}	

static inline int64_t get_usec_clock_from_usec_diff(int64_t clockusec, int64_t usec_diff) noexcept
{
	if (clockusec > usec_diff) {
		return clockusec - usec_diff;
	}

	return 1000L;	// 1 msec from host uptime
}	

// Includes system suspend time as well
static inline uint64_t get_process_uptime_usec() noexcept
{
	return get_usec_bootclock() - get_proc_start_bootusec();
}	

static inline int64_t get_process_uptime_sec() noexcept
{
	return (get_usec_bootclock() - get_proc_start_bootusec()) / GY_USEC_PER_SEC;
}	


/*
 * Returns the usecs the system (host) has been running since boot.
 * Does not include any system suspend time
 *
 * CLOCK_MONOTONIC gives the system uptime for Linux
 */ 
static inline uint64_t get_host_uptime_usec() noexcept
{
	return get_usec_clock();
}	

static inline uint64_t get_host_uptime_usec_with_suspend() noexcept
{
	return get_usec_bootclock();
}

// See comments for get_host_uptime_usec() above
static inline uint64_t get_host_uptime_nsec() noexcept
{
	return get_nsec_clock();
}	


/*
 * Class to get the Real Time from a Clock time without the need to repeatedly call get_nsec_time() 
 * Use for fast retrieval of time when repeated calls are expected in a short duration
 */
class GY_CLOCK_TO_TIME
{
public :
	static constexpr int64_t		RECHECK_NSEC		{ 60 * GY_NSEC_PER_SEC };

	GY_CLOCK_TO_TIME() noexcept	= default;

	uint64_t get_time_ns(int64_t clockns, bool forcecheck = false) noexcept
	{
		do_recheck(clockns, forcecheck);

		return start_timens_ + clockns - start_clockns_;
	}	

	uint64_t get_time_us(int64_t clockus, bool forcecheck = false) noexcept
	{
		do_recheck(clockus * 1000, forcecheck);

		return start_timens_/1000 + clockus - start_clockns_/1000;
	}	

	uint64_t get_time_ms(int64_t clockms, bool forcecheck = false) noexcept
	{
		do_recheck(clockms * GY_NSEC_PER_MSEC, forcecheck);

		return start_timens_/GY_NSEC_PER_MSEC + clockms - start_clockns_/GY_NSEC_PER_MSEC;
	}	

	time_t get_time_t(int64_t clocksec, bool forcecheck = false) noexcept
	{
		do_recheck(clocksec * GY_NSEC_PER_SEC, forcecheck);

		return start_timens_/GY_NSEC_PER_SEC + clocksec - start_clockns_/GY_NSEC_PER_SEC;
	}	

	struct timespec get_timespec(int64_t clockns, bool forcecheck = false) noexcept
	{
		do_recheck(clockns, forcecheck);

		return GY_NSEC_TO_TIMESPEC(get_time_ns(clockns));
	}	

	struct timeval get_timeval(int64_t clockus, bool forcecheck = false) noexcept
	{
		do_recheck(clockus * 1000, forcecheck);

		return GY_USEC_TO_TIMEVAL(get_time_us(clockus));
	}	


protected :

	void do_recheck(int64_t clockns, bool forcecheck) noexcept
	{
		if (forcecheck || (clockns > next_check_clockns_)) {
			next_check_clockns_ += RECHECK_NSEC;

			start_clockns_ 	= get_nsec_clock();
			start_timens_	= get_nsec_time();
		}	
	}	

	int64_t				start_clockns_		{ (int64_t)get_nsec_clock() };
	int64_t				start_timens_		{ (int64_t)get_nsec_time() };
	int64_t				next_check_clockns_	{ start_clockns_ + RECHECK_NSEC };
};	

/*
 * Class to get the Clock Time from a Real Time without the need to repeatedly call get_nsec_clock() 
 * Use for fast retrieval of clock when repeated calls are expected in a short duration
 * XXX Does not account for system suspend times
 */
class GY_TIME_TO_CLOCK
{
public :
	GY_TIME_TO_CLOCK() noexcept	= default;

	uint64_t get_clock_ns(int64_t timens) const noexcept
	{
		return start_clockns_ + timens - start_timens_;
	}	

	uint64_t get_clock_ns(struct timespec ts) const noexcept
	{
		return get_clock_ns(ts.tv_sec * GY_NSEC_PER_SEC + ts.tv_nsec);
	}	

	uint64_t get_clock_us(int64_t timeus) const noexcept
	{
		return start_clockns_/1000 + timeus - start_timens_/1000;
	}	

	uint64_t get_clock_us(struct timeval tv) const noexcept
	{
		return get_clock_us(tv.tv_sec * GY_USEC_PER_SEC + tv.tv_usec);
	}	

	uint64_t get_clock_ms(int64_t timems) const noexcept
	{
		return start_clockns_/GY_NSEC_PER_MSEC + timems - start_timens_/GY_NSEC_PER_MSEC;
	}	

	uint64_t get_clock_sec(time_t tsec) const noexcept
	{
		return start_clockns_/GY_NSEC_PER_SEC + (uint64_t)tsec - start_timens_/GY_NSEC_PER_SEC;
	}	

	const int64_t			start_timens_		{ (int64_t)get_nsec_time() };
	const int64_t			start_clockns_		{ (int64_t)get_nsec_clock() };
};	


static int gy_nanosleep(int64_t sec, int64_t nsec) noexcept
{
	struct timespec		ts { sec, nsec };

	return clock_nanosleep(CLOCK_MONOTONIC, 0, &ts, nullptr);
}

static int gy_nanosleep(int64_t nsec) noexcept
{
	return gy_nanosleep(nsec / GY_NSEC_PER_SEC, nsec % GY_NSEC_PER_SEC);
}
	
static int gy_msecsleep(int64_t msec) noexcept
{
	uint64_t	nsec = msec * GY_NSEC_PER_MSEC;

	return gy_nanosleep(nsec / GY_NSEC_PER_SEC, nsec % GY_NSEC_PER_SEC);
}
	
// nanosleep with extra checks for input params and EINTR
static int gy_nanosleep_safe(int64_t sec, int64_t nsec) noexcept
{
	struct timespec 	tsleep;
	int			ret;

	assert((unsigned)nsec < GY_NSEC_PER_SEC);

	clock_gettime(CLOCK_MONOTONIC, &tsleep);

	tsleep.tv_sec += sec;
	tsleep.tv_nsec += nsec;

	if ((uint64_t)tsleep.tv_nsec >= GY_NSEC_PER_SEC) {
		tsleep.tv_sec++;
		tsleep.tv_nsec -= GY_NSEC_PER_SEC;

		if ((uint64_t)tsleep.tv_nsec >= GY_NSEC_PER_SEC) {
			tsleep.tv_nsec = 0;
		}	
	}	

	do {
		ret = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &tsleep, nullptr);
	} while (ret == EINTR);	

	return ret;
}

/*
 * Call clock_nanosleep at scope destruction. Use in loops where the loop next iteration 
 * must start every x nsecs.
 * NOTE : In case the scope is exited say due to an error, still the sleep will go through.
 * In such cases, call reset_sleep() and then return;
 */ 
struct SCOPE_NANOSLEEP
{
	struct timespec 	tsleep_;
	bool			is_reset_		{false};
	bool			restart_on_eintr_;

	SCOPE_NANOSLEEP(time_t sleep_sec, int64_t sleep_nsec = 0, bool restart_on_eintr = false) noexcept 
		: restart_on_eintr_(restart_on_eintr)
	{
		assert((uint64_t)sleep_nsec < GY_NSEC_PER_SEC);

		clock_gettime(CLOCK_MONOTONIC, &tsleep_);

		tsleep_.tv_sec += sleep_sec;
		tsleep_.tv_nsec += sleep_nsec;

		if ((uint64_t)tsleep_.tv_nsec >= GY_NSEC_PER_SEC) {
			tsleep_.tv_sec++;
			tsleep_.tv_nsec -= GY_NSEC_PER_SEC;
		}	
	}	

	~SCOPE_NANOSLEEP() noexcept
	{
		if (false == is_reset_) {
			int		ret;

			do {
				ret = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &tsleep_, nullptr);
			} while (ret == EINTR && restart_on_eintr_);	
		}
	}	

	void reset_sleep() noexcept
	{
		is_reset_ = true;
	}	
};	


static inline constexpr void get_time_diff_breakup(int64_t tdiff_usec, int64_t & days, int64_t & hours, int64_t & mins, int64_t & secs, int64_t & usecs) noexcept
{
	int64_t		tdiff_sec = tdiff_usec / GY_USEC_PER_SEC;
			
	days 		= tdiff_sec/(24 * 3600);
	hours		= (tdiff_sec % (24 * 3600)) / 3600;
	mins 		= (tdiff_sec % 3600) / 60;
	secs		= tdiff_sec % 60;

	usecs		= tdiff_usec % GY_USEC_PER_SEC;
}
	
static inline char * get_time_diff_string(int64_t tdiff_sec, char *pbuf, size_t szbuf) noexcept
{
 	snprintf(pbuf, szbuf, "%ld days : %02ld hrs : %02ld min : %02ld sec", 
		tdiff_sec/(24 * 3600), (tdiff_sec % (24 * 3600)) / 3600, (tdiff_sec % 3600) / 60, tdiff_sec % 60);

	return pbuf;
}	

static CHAR_BUF<512> get_time_diff_string(int64_t tdiff_sec) noexcept
{
	CHAR_BUF<512>			cbuf;

	get_time_diff_string(tdiff_sec, cbuf.get(), sizeof(cbuf));

	return cbuf;
}	

class GY_TIMEZONE
{
public :	
	time_t				tnxtcheck_		{0};
	int				curr_gmtoff_		{0};
	bool				is_period_check_on_	{false};
	char				curr_tz_string_[64]	{};

	GY_TIMEZONE() noexcept
	{
		get_utc_tzoffset();	
		upd_tz_string();
	}		

	int get_utc_tzoffset(bool force_check = false) noexcept
	{
		if (!is_period_check_on_ || force_check) {
			
			time_t			tcur = time(nullptr);

			if (force_check || tcur >= tnxtcheck_) {
				/*
				 * We recalculate on every 15 minutes boundary
				 */
				struct tm		tms = {};
				
				localtime_r(&tcur, &tms);

				tnxtcheck_ = tcur + (15 - ((tms.tm_min + 1) % 15)) * 60 + 60 - tms.tm_sec;

				curr_gmtoff_ = tms.tm_gmtoff;
			}
		}	

		return curr_gmtoff_;
	}

	void set_new_proc_timezone(const char *tz_string) noexcept
	{
		assert(tz_string);

		setenv("TZ", tz_string, 1);
		tzset();

		set_tz_env_updated();
	}	

	void set_tz_env_updated() noexcept
	{
		get_utc_tzoffset(true);
		upd_tz_string();
	}

	void set_periodic_check_on(bool is_check_on = true) noexcept
	{
		is_period_check_on_ = is_check_on;
	}

	const char * get_tz_string() const noexcept
	{
		return curr_tz_string_;
	}
		
	static int		init_singleton();

	static GY_TIMEZONE *	get_singleton() noexcept;

private :

	int upd_tz_string() noexcept
	{
		char		buf1[128], *ptmp;
		int		ret;

		ptmp = getenv("TZ");
		if (ptmp) {
			if (*ptmp == ':') {
				ptmp++;
			}	
			GY_STRNCPY(curr_tz_string_, ptmp, sizeof(curr_tz_string_) - 1);
			return 0;
		}	

		ret = readlink("/etc/localtime", buf1, sizeof(buf1) - 1);
		if (ret <= 0) {
			goto on_error;
		}	
		
		buf1[ret] = '\0';

		ptmp = strstr(buf1, "/usr/share/zoneinfo/");
		if (!ptmp) {
			goto on_error;
		}	

		ptmp += GY_CONST_STRLEN("/usr/share/zoneinfo/");
		
		if (0 == memcmp(ptmp, "Etc/", GY_CONST_STRLEN("Etc/"))) {
			ptmp += GY_CONST_STRLEN("Etc/");
		}	
		else if (0 == memcmp(ptmp, "posix/", GY_CONST_STRLEN("posix/"))) {
			ptmp += GY_CONST_STRLEN("posix/");
		}
		else if (0 == memcmp(ptmp, "right/", GY_CONST_STRLEN("right/"))) {
			ptmp += GY_CONST_STRLEN("right/");
		}
		else if (0 == memcmp(ptmp, "SystemV/", GY_CONST_STRLEN("SystemV/"))) {
			ptmp += GY_CONST_STRLEN("SystemV/");
		}
				
		GY_STRNCPY(curr_tz_string_, ptmp, sizeof(curr_tz_string_) - 1);
		return 0;

on_error :
		int		tm_gmtoff = curr_gmtoff_;
		char		c;

		/*
		 * UTC Offset as TZ string : Zones with times ahead of UTC will be represented as UTC-<offset> (man tzset). 
		 * For e.g. India with TZ Offset of +05:30 will be represented as UTC-05:30
		 */
		if (tm_gmtoff != 0) {
			if (tm_gmtoff > 0) {
				c = '-';
			}
			else {
				c = '+';
				tm_gmtoff = -tm_gmtoff;
			}
			snprintf(curr_tz_string_, sizeof(curr_tz_string_), "UTC%c%02d:%02d", c, tm_gmtoff / 3600, (tm_gmtoff / 60) % 60);
		}
		else {
			strcpy(curr_tz_string_, "UTC");
		}

		return 1;
	}	 	
};	

static inline int get_tz_offset_from_utc() noexcept
{
	return GY_TIMEZONE::get_singleton()->get_utc_tzoffset();
}		
	
// Outputs an ISO 8601 formatted time string from a time_t e.g. 2018-06-01T13:00:01+05:30
static char * gy_localtime_iso8601(const time_t tnow, char *timebuf, size_t szbuf, const char *iso_fmt = "%FT%H:%M:%S") noexcept
{
	struct tm			tms = {};
	size_t				buflen;

	assert(szbuf > GY_CONST_STRLEN("2018-06-01T13:00:00+05:30"));

	localtime_r(&tnow, &tms);
	buflen = strftime(timebuf, szbuf - 8, iso_fmt, &tms);

	if (gy_unlikely(buflen == 0)) {
		*timebuf = '\0';
		return timebuf;
	}	

	if (tms.tm_gmtoff != 0) {
		if (tms.tm_gmtoff > 0) {
			timebuf[buflen++] = '+';
		}
		else {
			timebuf[buflen++] = '-';
			tms.tm_gmtoff = -tms.tm_gmtoff;
		}
		buflen += GY_SAFE_SNPRINTF(timebuf + buflen, szbuf - buflen - 1, "%02ld:%02ld", tms.tm_gmtoff / 3600, (tms.tm_gmtoff / 60) % 60);
	}
	else {
		timebuf[buflen++] = 'Z';
	}
	timebuf[buflen] = '\0';

	return timebuf;	
}

static CHAR_BUF<64> gy_localtime_iso8601_sec(time_t tnow = time(nullptr), const char * iso_fmt = "%FT%H:%M:%S") noexcept
{
	CHAR_BUF<64>			buf;

	gy_localtime_iso8601(tnow, buf.get(), sizeof(buf), iso_fmt);

	return buf;
}	

// Outputs an ISO 8601 formatted time string from a timeval e.g. 2018-06-01T13:00:01.023030+05:30
static char * gy_localtime_iso8601(struct timeval tv, char *timebuf, size_t szbuf, const char *iso_fmt = "%FT%H:%M:%S") noexcept
{
	struct tm			tms = {};
	size_t				buflen;

	assert(szbuf > GY_CONST_STRLEN("2018-06-01T13:00:01.023030+05:30"));

	localtime_r(&tv.tv_sec, &tms);

	buflen = strftime(timebuf, szbuf - 14, iso_fmt, &tms);

	if (gy_unlikely(buflen == 0)) {
		*timebuf = '\0';
		return timebuf;
	}	

	buflen += GY_SAFE_SNPRINTF(timebuf + buflen, szbuf - buflen - 2, ".%06ld", tv.tv_usec);

	if (tms.tm_gmtoff != 0) {
		if (tms.tm_gmtoff > 0) {
			timebuf[buflen++] = '+';
		}
		else {
			timebuf[buflen++] = '-';
			tms.tm_gmtoff = -tms.tm_gmtoff;
		}
		buflen += GY_SAFE_SNPRINTF(timebuf + buflen, szbuf - buflen, "%02ld:%02ld", tms.tm_gmtoff / 3600, (tms.tm_gmtoff / 60) % 60);
	}
	else {
		timebuf[buflen++] = 'Z';
		timebuf[buflen] = '\0';
	}

	return timebuf;
}

static CHAR_BUF<64> gy_localtime_iso8601_usec(struct timeval tv = get_timeval(), const char *iso_fmt = "%FT%H:%M:%S") noexcept
{
	CHAR_BUF<64>			buf;

	gy_localtime_iso8601(tv, buf.get(), sizeof(buf), iso_fmt);

	return buf;
}	


// Outputs an ISO 8601 formatted time string from a timespec e.g. 2018-06-01T13:00:01.123456789+05:30
static char * gy_localtime_iso8601(struct timespec ts, char *timebuf, size_t szbuf, const char *iso_fmt = "%FT%H:%M:%S") noexcept
{
	struct tm			tms = {};
	size_t				buflen;

	assert(szbuf > GY_CONST_STRLEN("2018-06-01T13:00:01.123456789+05:30"));

	localtime_r(&ts.tv_sec, &tms);

	buflen = strftime(timebuf, szbuf - 17, iso_fmt, &tms);

	if (gy_unlikely(buflen == 0)) {
		*timebuf = '\0';
		return timebuf;
	}	

	buflen += GY_SAFE_SNPRINTF(timebuf + buflen, szbuf - buflen - 2, ".%09ld", ts.tv_nsec);

	if (tms.tm_gmtoff != 0) {
		if (tms.tm_gmtoff > 0) {
			timebuf[buflen++] = '+';
		}
		else {
			timebuf[buflen++] = '-';
			tms.tm_gmtoff = -tms.tm_gmtoff;
		}
		buflen += GY_SAFE_SNPRINTF(timebuf + buflen, szbuf - buflen, "%02ld:%02ld", tms.tm_gmtoff / 3600, (tms.tm_gmtoff / 60) % 60);
	}
	else {
		timebuf[buflen++] = 'Z';
		timebuf[buflen] = '\0';
	}

	return timebuf;
}

static CHAR_BUF<64> gy_localtime_iso8601_nsec(struct timespec ts = get_timespec(), const char *iso_fmt = "%FT%H:%M:%S") noexcept
{
	CHAR_BUF<64>			buf;

	gy_localtime_iso8601(ts, buf.get(), sizeof(buf), iso_fmt);

	return buf;
}	


// Outputs an ISO 8601 formatted UTC Time zone time string from a time_t e.g. 2018-06-01T13:00:01Z
static char * gy_utc_time_iso8601(const time_t tnow, char *timebuf, size_t szbuf, const char *iso_fmt = "%FT%H:%M:%S") noexcept
{
	struct tm			tms = {};
	size_t				buflen;

	assert(szbuf > GY_CONST_STRLEN("2018-06-01T13:00:01Z"));

	gmtime_r(&tnow, &tms);

	buflen = strftime(timebuf, szbuf - 2, iso_fmt, &tms);

	if (gy_unlikely(buflen == 0)) {
		*timebuf = '\0';
		return timebuf;
	}	

	timebuf[buflen++] = 'Z';
	timebuf[buflen] = '\0';

	return timebuf;
}

static CHAR_BUF<64> gy_utc_time_iso8601_sec(time_t tnow = time(nullptr), const char * iso_fmt = "%FT%H:%M:%S") noexcept
{
	CHAR_BUF<64>			buf;

	gy_utc_time_iso8601(tnow, buf.get(), sizeof(buf), iso_fmt);

	return buf;
}	

static CHAR_BUF<64> gy_time_iso8601_sec(time_t tnow = time(nullptr), bool use_utc = false, const char * iso_fmt = "%FT%H:%M:%S") noexcept
{
	CHAR_BUF<64>			buf;

	if (use_utc) {
		gy_utc_time_iso8601(tnow, buf.get(), sizeof(buf), iso_fmt);
	}
	else {
		gy_localtime_iso8601(tnow, buf.get(), sizeof(buf), iso_fmt);
	}	

	return buf;
}	


// Outputs an ISO 8601 formatted UTC Time Zone time string from a timeval e.g. 2018-06-01T13:00:01.023030Z
static char * gy_utc_time_iso8601(struct timeval tv, char *timebuf, size_t szbuf, const char *iso_fmt = "%FT%H:%M:%S") noexcept
{
	struct tm			tms = {};
	size_t				buflen;

	assert(szbuf > GY_CONST_STRLEN("2018-06-01T13:00:01.023030Z"));

	gmtime_r(&tv.tv_sec, &tms);

	buflen = strftime(timebuf, szbuf - 8, iso_fmt, &tms);

	if (gy_unlikely(buflen == 0)) {
		*timebuf = '\0';
		return timebuf;
	}	

	buflen += GY_SAFE_SNPRINTF(timebuf + buflen, szbuf - buflen - 1, ".%06ld", tv.tv_usec);

	timebuf[buflen++] = 'Z';
	timebuf[buflen] = '\0';

	return timebuf;
}

static CHAR_BUF<64> gy_utc_time_iso8601_usec(struct timeval tv = get_timeval(), const char *iso_fmt = "%FT%H:%M:%S") noexcept
{
	CHAR_BUF<64>			buf;

	gy_utc_time_iso8601(tv, buf.get(), sizeof(buf), iso_fmt);

	return buf;
}	

static CHAR_BUF<64> gy_time_iso8601_usec(struct timeval tv = get_timeval(), bool use_utc = false, const char *iso_fmt = "%FT%H:%M:%S") noexcept
{
	CHAR_BUF<64>			buf;

	if (use_utc) {
		gy_utc_time_iso8601(tv, buf.get(), sizeof(buf), iso_fmt);
	}
	else {
		gy_localtime_iso8601(tv, buf.get(), sizeof(buf), iso_fmt);
	}	

	return buf;
}	


// Outputs an ISO 8601 formatted UTC Time Zone time string from a timespec e.g. 2018-06-01T13:00:01.123456789Z
static char * gy_utc_time_iso8601(struct timespec ts, char *timebuf, size_t szbuf, const char *iso_fmt = "%FT%H:%M:%S") noexcept
{
	struct tm			tms = {};
	size_t				buflen;

	assert(szbuf > GY_CONST_STRLEN("2018-06-01T13:00:01.123456789Z"));

	gmtime_r(&ts.tv_sec, &tms);

	buflen = strftime(timebuf, szbuf - 11, iso_fmt, &tms);

	if (gy_unlikely(buflen == 0)) {
		*timebuf = '\0';
		return timebuf;
	}	

	buflen += GY_SAFE_SNPRINTF(timebuf + buflen, szbuf - buflen - 1, ".%09ld", ts.tv_nsec);

	timebuf[buflen++] = 'Z';
	timebuf[buflen] = '\0';

	return timebuf;
}

static CHAR_BUF<64> gy_utc_time_iso8601_nsec(struct timespec ts = get_timespec(), const char *iso_fmt = "%FT%H:%M:%S") noexcept
{
	CHAR_BUF<64>			buf;

	gy_utc_time_iso8601(ts, buf.get(), sizeof(buf), iso_fmt);

	return buf;
}	

static CHAR_BUF<64> gy_time_iso8601_nsec(struct timespec ts = get_timespec(), bool use_utc = false, const char *iso_fmt = "%FT%H:%M:%S") noexcept
{
	CHAR_BUF<64>			buf;

	if (use_utc) {
		gy_utc_time_iso8601(ts, buf.get(), sizeof(buf), iso_fmt);
	}
	else {
		gy_localtime_iso8601(ts, buf.get(), sizeof(buf), iso_fmt);
	}	

	return buf;
}	

static char * gy_tm_iso8601(const struct tm & tm, char *timebuf, size_t szbuf, const char *iso_fmt = "%FT%H:%M:%S") noexcept
{
	size_t				buflen;
	auto				tm_gmtoff = tm.tm_gmtoff;

	assert(szbuf > GY_CONST_STRLEN("2018-06-01T13:00:00+05:30"));

	buflen = strftime(timebuf, szbuf - 8, iso_fmt, &tm);

	if (gy_unlikely(buflen == 0)) {
		*timebuf = '\0';
		return timebuf;
	}	

	if (tm_gmtoff != 0) {
		if (tm_gmtoff > 0) {
			timebuf[buflen++] = '+';
		}
		else {
			timebuf[buflen++] = '-';
			tm_gmtoff = -tm.tm_gmtoff;
		}
		buflen += GY_SAFE_SNPRINTF(timebuf + buflen, szbuf - buflen - 1, "%02ld:%02ld", tm_gmtoff / 3600, (tm_gmtoff / 60) % 60);
	}
	else {
		timebuf[buflen++] = 'Z';
	}
	timebuf[buflen] = '\0';

	return timebuf;	
}

static CHAR_BUF<64> gy_tm_iso8601(const struct tm & tm, const char *iso_fmt = "%FT%H:%M:%S") noexcept
{
	CHAR_BUF<64>			buf;

	gy_tm_iso8601(tm, buf.get(), sizeof(buf), iso_fmt);

	return buf;
}	

/*
 * ISO8601 string to time_t + tv_nsec. Returns false on error. Else updates tsec and nsec. 
 *
 * Accepts formats :
 *
 * "2018-06-01T12:34:56Z", "2018-06-01T12:34:56.123456+05:30", "2018-06-01 12:34:11.123-0500"
 * "2018-06-01T12:34:56z", "2018-06-01 12:34:56.123456789 +05:30", "2018-06-01 12:34:56 +05:30"
 *
 * If TZ environment variable was updated followed by a tzset() since the last call to this function, then
 * please call the gyeeta::GY_TIMEZONE::get_singleton()->set_tz_env_updated() first or else the timestamp will be printed
 * in the older timezone.
 *
 * For other ISO formats, please specify the format pattern in iso_fmt argument.
 */ 
static bool gy_iso8601_to_timespec(const char *pisobuf, time_t & tsec, int64_t & nsec, const char *iso_fmt = nullptr) noexcept
{
	static constexpr char		fmtbuf[] = "%FT%H:%M:%S", fmtalt[] = "%F %H:%M:%S";
	struct tm			tms = {};
	size_t				buflen, isobuflen;
	char				tbuf[64], *pext, c;
	const char			*pend, *ptmp, *piso_fmt;
	int 				tzlocalsec, tzgivensec, next;

	assert(pisobuf);

	isobuflen = strnlen(pisobuf, sizeof(tbuf) - 1);

	if (gy_unlikely(isobuflen < 16)) {
		tsec = 0;
		nsec = 0;
		return false;
	}
		
	std::memcpy(tbuf, pisobuf, isobuflen);
	tbuf[isobuflen] = '\0';
	
	pend = tbuf + isobuflen;

	if (gy_likely(iso_fmt == nullptr)) {	
		if (tbuf[10] != ' ') {
			piso_fmt = fmtbuf;
		}
		else {
			piso_fmt = fmtalt;
		}
	}
	else {
		piso_fmt = iso_fmt;
	}	

	pext = strptime(tbuf, piso_fmt, &tms);

	if (gy_unlikely(pext == nullptr)) {
		tsec = 0;
		nsec = 0;
		return false;
	}	
	
	tms.tm_isdst = -1;

	c = *pext;

	if (gy_unlikely('\0' == c)) {
		// No TZ Assume local
		tsec = mktime(&tms);
		nsec = 0;

		return true;
	}
	
	// Check if additional msec/usec/nsec specified
	if (c == '.') {
		ptmp = ++pext;

		char			digbuf[10];
		
		std::memset(digbuf, '0', sizeof(digbuf) - 1);

		while (ptmp < pend && gy_isdigit_ascii(*ptmp)) ptmp++;
		
		if (unsigned(ptmp - pext) >= sizeof(digbuf)) {
			std::memcpy(digbuf, pext, sizeof(digbuf) - 1);
		}	
		else {
			std::memcpy(digbuf, pext, ptmp - pext);
		}	
		
		digbuf[sizeof(digbuf) - 1] = 0;

		nsec = atoi(digbuf);	
	}	
	else {
		ptmp = pext;
		nsec = 0;
	}	

	c = *ptmp;

	if (gy_unlikely(c == ' ' && ptmp + 1 < pend)) {
		ptmp++;
		c = *ptmp;
	}
		
	if (gy_toupper_ascii(c) == 'Z') {
		// UTC
		tsec = timegm(&tms);
		return true;
	}	
	else if (((c == '+') || (c == '-')) && (ptmp + 2 <= pend)) {
		int		ret;
		uint8_t		hr, mn = 0;

		if (ptmp + 5 <= pend && ((*(ptmp + 2) == ':') || (*(ptmp + 3) == ':'))) {
			ret = sscanf(ptmp + 1, "%hhu:%hhu", &hr, &mn);
		}
		else {
			ret = sscanf(ptmp + 1, "%02hhu%02hhu", &hr, &mn);
		}	
		if (ret > 0) {
			tzgivensec = (int)hr * 3600 + (int)mn * 60;
			if (c == '-') {
				tzgivensec *= -1;
			}
				
			tsec = timegm(&tms);

			if (c == '-') {
				tsec += -tzgivensec;
			}
			else {
				tsec -= tzgivensec;	
			}		
			return true;
		}	
	}	

	tsec = mktime(&tms);

	return true;
}	

// See comments for gy_iso8601_to_timespec above for details : Returns 0 sec on error
static struct timespec gy_iso8601_to_timespec(const char *pisobuf, const char *iso_fmt = nullptr) noexcept
{
	struct timespec		ts {};
	bool			bret;

	bret = gy_iso8601_to_timespec(pisobuf, ts.tv_sec, ts.tv_nsec, iso_fmt);
	if (bret == false) {
		ts.tv_sec 	= 0;
		ts.tv_nsec	= 0;
	}	
	
	return ts;
}	

// See comments for gy_iso8601_to_timespec above for details : Returns 0 sec on error
static struct timeval gy_iso8601_to_timeval(const char *pisobuf, const char *iso_fmt = nullptr) noexcept
{
	struct timespec		ts {};
	struct timeval		tv {};
	bool			bret;

	bret = gy_iso8601_to_timespec(pisobuf, ts.tv_sec, ts.tv_nsec, iso_fmt);
	if (bret == true) {
		tv.tv_sec 	= ts.tv_sec;
		tv.tv_usec	= ts.tv_nsec/1000;
	}	
	else {
		tv.tv_sec	= 0;
		tv.tv_usec	= 0;
	}	
	
	return tv;
}	

// See comments for gy_iso8601_to_timespec above for details : Returns 0 sec on error
static time_t gy_iso8601_to_time_t(const char *pisobuf, const char *iso_fmt = nullptr) noexcept
{
	struct timespec		ts {};
	bool			bret;

	bret = gy_iso8601_to_timespec(pisobuf, ts.tv_sec, ts.tv_nsec, iso_fmt);
	if (bret == false) {
		return 0;
	}	
	
	return ts.tv_sec;
}	

// Returns pisobuf1 - pisobuf2 diff in usec
static int64_t gy_iso8601_diff_usec(const char *pisobuf1, const char *pisobuf2, const char *iso_fmt = nullptr) noexcept
{
	struct timespec		ts1 {}, ts2 {};
	bool			bret;

	bret = gy_iso8601_to_timespec(pisobuf1, ts1.tv_sec, ts1.tv_nsec, iso_fmt);
	if (bret == false) {
		return 0;
	}	
	
	bret = gy_iso8601_to_timespec(pisobuf2, ts2.tv_sec, ts2.tv_nsec, iso_fmt);
	if (bret == false) {
		return 0;
	}	
	
	return (ts1.tv_sec * GY_USEC_PER_SEC + ts1.tv_nsec/1000) - (ts2.tv_sec * GY_USEC_PER_SEC + ts2.tv_nsec/1000);
}	

// Prints the time in format 2018-06-01 13:12:34.023030 without timezone or if guse_utc_time then a Z
static std::pair<char *, int> gy_time_print(char *stimebuf, size_t sizebuf, struct timeval tv = get_timeval()) noexcept
{
	struct tm 		tm_r = {};			
	size_t			sret, sbytes;							
	const bool		use_utc = guse_utc_time;								
									
	assert(sizebuf > GY_CONST_STRLEN("2018-06-01 13:12:34.023030Z"));

	if (use_utc == false) {								
		localtime_r(&tv.tv_sec, &tm_r);
	}
	else {
		gmtime_r(&tv.tv_sec, &tm_r);
	}	

	sret = strftime(stimebuf, sizebuf - 8, "%F %H:%M:%S", &tm_r);	

	if (sret > 0) {
		sbytes = GY_SAFE_SNPRINTF(stimebuf + sret, sizebuf - sret, ".%06u%c", (uint32_t)tv.tv_usec, use_utc ? 'Z' : '\0');
		sbytes += sret;
	}	
	else {
		sbytes = GY_SAFE_SNPRINTF(stimebuf, sizebuf - 1, "%19lu.%06u", tv.tv_sec, (uint32_t)tv.tv_usec);
	}		

	return {stimebuf, (int)sbytes};
}

static inline struct tm get_local_time(time_t tcur = time(nullptr)) noexcept
{
	struct tm 		tm {};			

	localtime_r(&tcur, &tm);
	
	return tm;
}

static inline struct tm get_utc_time(time_t tcur = time(nullptr)) noexcept
{
	struct tm 		tm {};			

	gmtime_r(&tcur, &tm);
	
	return tm;
}

static inline bool is_same_tz_offset(const struct tm & tm1, const struct tm & tm2) noexcept
{
	return ((tm1.tm_gmtoff == tm2.tm_gmtoff) && (tm1.tm_isdst == tm2.tm_isdst)); 
}	

/*
 * Get tzoffset seconds from tz string of formats : "Z", "+0530", "-0500", "+08:00", "-05:00", "UTC"
 */
static int str_get_tzoffset(const char *tz, uint32_t lenstr = 0)
{
	char			tzstr[16] {}; 
	const char		*pend;

	assert(tz);

	if (lenstr == 0) lenstr = strlen(tz);
	
	pend = tz + lenstr;

	while (pend > tz + 1 && is_space_tab(pend[-1])) pend--; 

	while (tz < pend && is_space_tab(*tz)) tz++;

	lenstr = pend - tz;

	if (lenstr == 5) {
		std::memcpy(tzstr, tz, 5);
		tzstr[5] = 0;
	}	
	else {
		if (lenstr == 1 && gy_toupper_ascii(*tz) == 'Z') {
			return 0;
		}	
		else if (lenstr == 3 && 0 == strncasecmp(tz, "UTC", 3)) {
			return 0;
		}	
		else if (lenstr == 6 && tz[3] == ':') {
			tzstr[0] = tz[0];
			tzstr[1] = tz[1];
			tzstr[2] = tz[2];
			tzstr[3] = tz[4];
			tzstr[4] = tz[5];
			tzstr[5] = 0;
		}	
		else {
			GY_THROW_EXPR_CODE(400, "Timezone offset string \'%s\' not correct format : Need in numeric format e.g. +0530 or -05:00 or Z for UTC", tz);
		}	
	}	

	int				mul = 1, hours, mins;

	if (*tzstr == '-') {
		mul = -1;
	}	
	else if (*tzstr != '+') {
		GY_THROW_EXPR_CODE(400, "Timezone offset string \'%s\' not correct format : Need in format e.g. +05:30 or -0500", tz);
	}	

	for (int i = 1; i <= 4; ++i) {
		if (!(tzstr[i] >= '0' && tzstr[i] <= '9')) {
			GY_THROW_EXPR_CODE(400, "Timezone offset string \'%s\' not correct format : Need in format e.g. +0530 or -0500", tz);
		}	
	}

	hours 	= (tzstr[1] - '0') * 10 + (tzstr[2] - '0');
	mins 	= (tzstr[3] - '0') * 10 + (tzstr[4] - '0');

	if (hours >= 24) {
		GY_THROW_EXPR_CODE(400, "Timezone offset string \'%s\' not correct format : Need in format e.g. +0530 or -0500", tz);
	}	

	if (mins >= 60) {
		GY_THROW_EXPR_CODE(400, "Timezone offset string \'%s\' not correct format : Need in format e.g. +0530 or -0500", tz);
	}	

	return mul * (hours * 3600 + mins * 60);
}	

static time_t get_tm_day_offset(struct tm & tm, int days_offset) noexcept
{
	tm.tm_mday += days_offset;
	tm.tm_isdst = -1;
	
	if (tm.tm_gmtoff == 0) {
		return timegm(&tm);	
	}
	else {
		return mktime(&tm);
	}	
}

/*
 * Specify tnow as the time_t equivalent to tm if it is known for faster calculation 
 */
static time_t get_tm_hour_offset(struct tm & tm, int hours_offset, time_t tnow = 0) noexcept
{
	if (tnow > 0) {
		if (hours_offset) {

			if (hours_offset < 24 && (tm.tm_hour + hours_offset >= 0 && tm.tm_hour + hours_offset < 24)) {
				tm.tm_hour += hours_offset;
				return tnow + hours_offset * 3600;
			}
		}
		else {
			return tnow;
		}	
	}

	tm.tm_hour += hours_offset;

	if (tm.tm_gmtoff == 0) {
		return timegm(&tm);	
	}
	else {
		if (tm.tm_hour <= 0 || tm.tm_hour >= 23) {
			tm.tm_isdst = -1;
		}

		return mktime(&tm);
	}	
}

/*
 * Specify tnow as the time_t equivalent to tm if it is known for faster calculation 
 */
static time_t get_tm_minute_offset(struct tm & tm, int min_offset, time_t tnow = 0) noexcept
{
	if (tnow > 0) {
		if (min_offset) {

			if (tm.tm_min + min_offset >= 0 && tm.tm_min + min_offset < 60) {
				tm.tm_min += min_offset;
				return tnow + min_offset * 60;
			}
			else {
				int			hours = min_offset/60;

				if (hours < 24 && (tm.tm_hour + hours > 0 || tm.tm_hour + hours < 23)) {
					int			newmin = min_offset % 60;

					tm.tm_hour += hours;
					tm.tm_min += newmin;

					if (tm.tm_min < 0) {
						tm.tm_hour--;
						tm.tm_min += 60;
					}	
					else if (tm.tm_min > 59) {
						tm.tm_hour++;
						tm.tm_min -= 60;
					}	

					return tnow + min_offset * 60;
				}	
			}	
		}
		else {
			return tnow;
		}	
	}

	tm.tm_min += min_offset;

	if (tm.tm_gmtoff == 0) {
		return timegm(&tm);	
	}
	else {
		int			hours = min_offset/60;

		if (tm.tm_hour + hours <= 0 || tm.tm_hour + hours >= 23) {
			tm.tm_isdst = -1;
		}

		return mktime(&tm);
	}	
}

/*
 * Specify tnow as the time_t equivalent to tm if it is known for faster calculation 
 */
static time_t get_tm_sec_offset(struct tm & tm, int sec_offset, time_t tnow = 0) noexcept
{
	if (tnow > 0) {
		if (sec_offset) {
			if (tm.tm_sec + sec_offset >= 0 && tm.tm_sec + sec_offset < 60) {
				tm.tm_sec += sec_offset;
				return tnow + sec_offset;
			}
			else {
				int			hours = sec_offset/3600;

				if (hours < 24 && (tm.tm_hour + hours > 0 || tm.tm_hour + hours < 23)) {
					int			min_offset = (sec_offset % 3600) / 60, newsec = sec_offset % 60;

					tm.tm_hour += hours;
					tm.tm_min += min_offset;
					tm.tm_sec += newsec;

					if (tm.tm_sec < 0) {
						tm.tm_min--;
						tm.tm_sec += 60;
					}	
					else if (tm.tm_sec > 59) {
						tm.tm_min++;
						tm.tm_sec -= 60;
					}

					if (tm.tm_min < 0) {
						tm.tm_hour--;
						tm.tm_min += 60;
					}	
					else if (tm.tm_min > 59) {
						tm.tm_hour++;
						tm.tm_min -= 60;
					}	

					return tnow + sec_offset;
				}	
			}	
		}
		else {
			return tnow;
		}	
	}
	

	tm.tm_sec += sec_offset;

	if (tm.tm_gmtoff == 0) {
		return timegm(&tm);	
	}
	else {
		int			hours = sec_offset/3600;

		if (tm.tm_hour + hours <= 0 || tm.tm_hour + hours >= 23) {
			tm.tm_isdst = -1;
		}
	
		return mktime(&tm);
	}	
}

/*
 * Will update tm as well as return new time_t
 */ 
static time_t get_tm_offset(struct tm & tm, int days_offset, int hours_offset, int min_offset, int sec_offset, time_t tnow = 0) noexcept
{
	if (tnow && ((uint32_t)days_offset + (uint32_t)hours_offset + (uint32_t)min_offset + (uint32_t)sec_offset < 1000u)) {
		return get_tm_sec_offset(tm, days_offset * 3600 * 24 + hours_offset * 3600 + min_offset * 60 + sec_offset, tnow);
	}	

	tm.tm_mday += days_offset;
	tm.tm_hour += hours_offset;
	tm.tm_min += min_offset;
	tm.tm_sec += sec_offset;
	tm.tm_isdst = -1;
	
	if (tm.tm_gmtoff == 0) {
		return timegm(&tm);	
	}
	else {
		return mktime(&tm);
	}	
}

static inline bool is_leap_year(int year) noexcept
{
	return ((year % 4) == 0 && ((year % 100) != 0 || (year % 400) == 0));
}	

/*
 * month is months starting from 1 for January to 12 for December
 * year is Gregorian year such as 2021
 */
static inline int get_month_days(int month, int year) noexcept
{
	static constexpr uint8_t days_by_month[2][16] {
		{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31, },
		{31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31, }
	};

	return days_by_month[is_leap_year(year)][((uint8_t)(month - 1)) & 0xF];
}	

static struct tm get_tm_at_tzoffset(const struct tm & inputtm, int tzoffset) noexcept
{
	struct tm		tm {inputtm};

	if (tzoffset == inputtm.tm_gmtoff) {
		return tm;
	}	

	assert(abs(tzoffset) < 15 * 3600);

	tm.tm_gmtoff = tzoffset;
	tm.tm_zone = "";	// empty
	
	int			sec_offset = -(inputtm.tm_gmtoff - tzoffset);
	int			hours = sec_offset/3600, min_offset = (sec_offset % 3600) / 60;
	
	tm.tm_hour += hours;
	tm.tm_min += min_offset;

	if (tm.tm_min < 0) {
		tm.tm_hour--;
		tm.tm_min += 60;
	}	
	else if (tm.tm_min > 59) {
		tm.tm_hour++;
		tm.tm_min -= 60;
	}	

	if (tm.tm_hour < 0) {
		tm.tm_mday--;
		tm.tm_hour += 24;
		tm.tm_wday--;
		if (tm.tm_wday < 0) tm.tm_wday = 6;
		tm.tm_yday--;
	}	
	else if (tm.tm_hour > 23) {
		tm.tm_mday++;
		tm.tm_hour -= 24;
		tm.tm_wday++;
		if (tm.tm_wday > 6) tm.tm_wday = 0;
		tm.tm_yday++;
	}	
	else {
		return tm;
	}	

	if (tm.tm_mon < 0 || tm.tm_mon >= 12) { 
		// Return with errors
		return tm;
	}

	if (tm.tm_mday < 1) {
		tm.tm_mon--;	

		if (tm.tm_mon < 0) {
			tm.tm_year--;
			tm.tm_mon = 11;
			tm.tm_yday = 364 + is_leap_year(1900 + tm.tm_year);
		}	
		
		tm.tm_mday = get_month_days(tm.tm_mon + 1, 1900 + tm.tm_year);
	}	
	else if (tm.tm_mday > get_month_days(tm.tm_mon + 1, 1900 + tm.tm_year)) {

		tm.tm_mday = 1;
		tm.tm_mon++;

		if (tm.tm_mon > 11) {
			tm.tm_year++;
			tm.tm_mon = 0;
			tm.tm_yday = 0;
		}	
	}	
	
	return tm;
}	

/*
 * Returns start of day for specified days_offset
 */ 
static time_t get_ndays_start(time_t tnow = time(nullptr), int days_offset = 1, bool use_utc = false) noexcept
{
	struct tm 		ltm = {};

	if (use_utc == false) {
		localtime_r(&tnow, &ltm);
	}
	else {
		gmtime_r(&tnow, &ltm);
	}	
	
	ltm.tm_mday += days_offset;
	ltm.tm_hour = 0;
	ltm.tm_min = 0;
	ltm.tm_sec = 0;
	ltm.tm_isdst = -1;
	
	if (use_utc) {
		return timegm(&ltm);	
	}
	else {
		return mktime(&ltm);
	}	
}

static time_t get_day_start(time_t tnow = time(nullptr), bool use_utc = false) noexcept
{
	struct tm 		ltm = {};
	time_t			td, tcalc;

	if (use_utc == false) {
		localtime_r(&tnow, &ltm);
	}
	else {
		gmtime_r(&tnow, &ltm);
	}	
	
	td = ltm.tm_hour * 3600 + ltm.tm_min * 60 + ltm.tm_sec;

	if ((uint64_t)td > 24 * 3600) {
		td = 24 * 3600;
	}
	
	tcalc = tnow - td;

	return tcalc;
}

// If on min boundary will return same time
static inline time_t to_next_min(time_t tcur) noexcept
{
	return gy_align_up(tcur, 60);
}	

// If on hour boundary will return same time
static inline time_t to_next_hour(time_t tcur) noexcept
{
	return gy_align_up(tcur, 3600);
}	

static inline time_t to_curr_min(time_t tcur) noexcept
{
	return gy_align_down(tcur, 60);
}	

static inline time_t to_curr_hour(time_t tcur) noexcept
{
	return gy_align_down(tcur, 3600);
}	


static std::tuple<int, int, int> get_time_ymd(time_t tnow = time(nullptr), bool use_utc = false) noexcept
{
	struct tm 		tm = {};
	time_t			td, tcalc;

	if (use_utc == false) {
		localtime_r(&tnow, &tm);
	}
	else {
		gmtime_r(&tnow, &tm);
	}	

	return {1900 + tm.tm_year, tm.tm_mon + 1, tm.tm_mday};
}	

[[gnu::const]] static uint32_t get_time_slot_of_day(time_t tcurr, uint32_t slotsec, time_t tdaystart) noexcept
{
	assert(slotsec);

	const uint32_t 		maxslots = 24 * 3600 / slotsec;
		
	tcurr = (tcurr / slotsec) * slotsec;

	return ((tcurr - tdaystart) / slotsec) % maxslots;
}	 	

static uint32_t get_time_slot_of_day(time_t tcurr, uint32_t slotsec) noexcept
{
	time_t			tdaystart = get_day_start(tcurr);	
			
	return get_time_slot_of_day(tcurr, slotsec, tdaystart);
}	 	


#define GY_SWAP_16(_x)		__bswap_16((_x))		
#define GY_SWAP_32(_x)		__bswap_32((_x))		
#define GY_SWAP_64(_x)		__bswap_64((_x))		

static inline uint16_t unaligned_read_be16(const void *_u) noexcept 
{
	const uint8_t 		*u = reinterpret_cast<const uint8_t *>(_u);

	return (((uint16_t) u[0]) << 8) | ((uint16_t) u[1]);
}

static inline uint32_t unaligned_read_be32(const void *_u) noexcept 
{
	const uint8_t 		*u = reinterpret_cast<const uint8_t *>(_u);

	return (((uint32_t) unaligned_read_be16(u)) << 16) | ((uint32_t) unaligned_read_be16(u + 2));
}

static inline uint64_t unaligned_read_be64(const void *_u) noexcept 
{
	const uint8_t 		*u = reinterpret_cast<const uint8_t *>(_u);

	return (((uint64_t) unaligned_read_be32(u)) << 32) | ((uint64_t) unaligned_read_be32(u + 4));
}

static inline void unaligned_write_be16(void *_u, uint16_t a) noexcept 
{
	uint8_t 		*u = reinterpret_cast<uint8_t *>(_u);

	u[0] = (uint8_t) (a >> 8); 
	u[1] = (uint8_t) a;
}

static inline void unaligned_write_be32(void *_u, uint32_t a) noexcept 
{
	uint8_t 		*u = reinterpret_cast<uint8_t *>(_u);

	unaligned_write_be16(u, (uint16_t) (a >> 16));
	unaligned_write_be16(u + 2, (uint16_t) a);
}

static inline void unaligned_write_be64(void *_u, uint64_t a) noexcept 
{
	uint8_t 		*u = reinterpret_cast<uint8_t *>(_u);

	unaligned_write_be32(u, (uint32_t) (a >> 32));
	unaligned_write_be32(u + 4, (uint32_t) a);
}

static inline uint16_t unaligned_read_le16(const void *_u) noexcept 
{
	const uint8_t 		*u = reinterpret_cast<const uint8_t *>(_u);

	return (((uint16_t) u[1]) << 8) | ((uint16_t) u[0]);
}

static inline uint32_t unaligned_read_le32(const void *_u) noexcept 
{
	const uint8_t 		*u = reinterpret_cast<const uint8_t *>(_u);

	return (((uint32_t) unaligned_read_le16(u + 2)) << 16) | ((uint32_t) unaligned_read_le16(u));
}

static inline uint64_t unaligned_read_le64(const void *_u) noexcept 
{
	const uint8_t 		*u = reinterpret_cast<const uint8_t *>(_u);

	return (((uint64_t) unaligned_read_le32(u + 4)) << 32) | ((uint64_t) unaligned_read_le32(u));
}

static inline void unaligned_write_le16(void *_u, uint16_t a) noexcept 
{
	uint8_t 		*u = reinterpret_cast<uint8_t *>(_u);

	u[0] = (uint8_t) a;
	u[1] = (uint8_t) (a >> 8);
}

static inline void unaligned_write_le32(void *_u, uint32_t a) noexcept 
{
	uint8_t 		*u = reinterpret_cast<uint8_t *>(_u);

	unaligned_write_le16(u, (uint16_t) a);
	unaligned_write_le16(u + 2, (uint16_t) (a >> 16));
}

static inline void unaligned_write_le64(void *_u, uint64_t a) noexcept 
{
	uint8_t 		*u = reinterpret_cast<uint8_t *>(_u);

	unaligned_write_le32(u, (uint32_t) a);
	unaligned_write_le32(u + 4, (uint32_t) (a >> 32));
}

static inline uint16_t unaligned_read16_swapped(const void *_u) noexcept 
{
        const struct __attribute__((packed, may_alias)) { uint16_t x; } *u = decltype(u)(_u);

	return GY_SWAP_16(u->x);
}	

static inline uint16_t unaligned_read32_swapped(const void *_u) noexcept 
{
        const struct __attribute__((packed, may_alias)) { uint32_t x; } *u = decltype(u)(_u);

	return GY_SWAP_32(u->x);
}	

static inline uint16_t unaligned_read64_swapped(const void *_u) noexcept 
{
        const struct __attribute__((packed, may_alias)) { uint64_t x; } *u = decltype(u)(_u);

	return GY_SWAP_64(u->x);
}	


static inline uint16_t unaligned_read_16(const void *_u) noexcept 
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return unaligned_read_le16(_u);	
#else
	return unaligned_read_be16(_u);
#endif
}

static inline uint32_t unaligned_read_32(const void *_u) noexcept 
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return unaligned_read_le32(_u);	
#else
	return unaligned_read_be32(_u);
#endif
}

static inline uint64_t unaligned_read_64(const void *_u) noexcept 
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return unaligned_read_le64(_u);	
#else
	return unaligned_read_be64(_u);
#endif
}

static inline void unaligned_write_16(void *_u, uint16_t a) noexcept 
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	unaligned_write_le16(_u, a);
#else
	unaligned_write_be16(_u, a);
#endif
}

static inline void unaligned_write_32(void *_u, uint32_t a) noexcept 
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	unaligned_write_le32(_u, a);
#else
	unaligned_write_be32(_u, a);
#endif
}

static inline void unaligned_write_64(void *_u, uint64_t a) noexcept 
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	unaligned_write_le64(_u, a);
#else
	unaligned_write_be64(_u, a);
#endif
}

enum BYTE_ORDER_E : int
{
	BO_BIG_ENDIAN		= 0,
	BO_LITTLE_ENDIAN	= 1,
};	


static inline uint16_t unaligned_read_16(const void *_u, BYTE_ORDER_E bo) noexcept 
{
	if (bo == BO_BIG_ENDIAN) {
		return unaligned_read_be16(_u);
	}
	else {
		return unaligned_read_le16(_u);	
	}		
}

static inline uint32_t unaligned_read_32(const void *_u, BYTE_ORDER_E bo) noexcept 
{
	if (bo == BO_BIG_ENDIAN) {
		return unaligned_read_be32(_u);
	}
	else {
		return unaligned_read_le32(_u);	
	}		
}

static inline uint64_t unaligned_read_64(const void *_u, BYTE_ORDER_E bo) noexcept 
{
	if (bo == BO_BIG_ENDIAN) {
		return unaligned_read_be64(_u);
	}
	else {
		return unaligned_read_le64(_u);	
	}		
}

static inline void unaligned_write_16(void *_u, uint16_t a, BYTE_ORDER_E bo) noexcept 
{
	if (bo == BO_BIG_ENDIAN) {
		unaligned_write_be16(_u, a);
	}
	else {
		unaligned_write_le16(_u, a);
	}		
}

static inline void unaligned_write_32(void *_u, uint32_t a, BYTE_ORDER_E bo) noexcept 
{
	if (bo == BO_BIG_ENDIAN) {
		unaligned_write_be32(_u, a);
	}
	else {
		unaligned_write_le32(_u, a);
	}		
}

static inline void unaligned_write_64(void *_u, uint64_t a, BYTE_ORDER_E bo) noexcept 
{
	if (bo == BO_BIG_ENDIAN) {
		unaligned_write_be64(_u, a);
	}
	else {
		unaligned_write_le64(_u, a);
	}		
}

extern size_t 			gpgsz_local_;

static inline size_t gy_page_size() noexcept 
{
        int64_t 		ret;
	size_t			pgsz = gpgsz_local_;

        if (gy_likely(pgsz > 0)) {
                return pgsz;
	}	

        ret = sysconf(_SC_PAGESIZE);

	if (ret <= 0) ret = 4096;

        GY_WRITE_ONCE(gpgsz_local_, (size_t)ret);

        return ret;
}

extern uint32_t 		gclktck_local_;

static inline uint32_t gy_clk_tck() noexcept 
{
        int64_t 		ret;
	uint32_t		clktck = gclktck_local_;

        if (gy_likely(clktck > 0)) {
                return clktck;
	}	

        ret = sysconf(_SC_CLK_TCK);

	if (ret <= 0) ret = 100;

        GY_WRITE_ONCE(gclktck_local_, (uint32_t)ret);

        return (uint32_t)ret;
}

/*
 * Specify in function attribute to remove inlining and any optimization
 */
#if defined(__clang__)
#	define GY_NO_OPTIMIZE __attribute__((noinline, optnone))
#elif defined(__GNUC__)
#	define GY_NO_OPTIMIZE __attribute__((noinline, optimize("O0")))
#endif


/*
 * sscanf() calls strlen() for each call which is expensive if the inputstr is large and we need to check only a few bytes ahead
 * This function modifies the input string by changing the inputstr, checking if strnlen() > max_len_to_check and if true, changing the 
 * max_len_to_check + 1 char to '\0' and calling sscanf() and again changing back thereafter
 */
static int sscanf_large_str(char *inputstr, size_t max_len_to_check, const char *format, ...) noexcept
{
	size_t			slen = strnlen(inputstr, max_len_to_check + 1);
	char			c = (slen == max_len_to_check + 1 ? inputstr[max_len_to_check] : 0);
	int			ret;
	va_list 		va;

	if (c) {
		inputstr[max_len_to_check] = 0;
	}	

	va_start(va, format);
	ret = vsscanf(inputstr, format, va);
	va_end(va);

	if (c) {
		inputstr[max_len_to_check] = c;
	}	

	return ret;
}	


/*
 * sscanf() calls strlen() for each call which is expensive if the inputstr is large and we need to check only a few bytes ahead
 * Use this function for const input strings which could potentially be much larger than max_len_to_check
 */
template <size_t max_len_to_check>
int sscanf_large_str(const char *inputstr, const char *format, ...) noexcept
{
	static_assert(max_len_to_check <= 512, "Use sscanf() directly");

	char			tstr[max_len_to_check + 1];
	const char		*pinputstr;
	size_t			slen = strnlen(inputstr, max_len_to_check + 1);
	int			ret;
	va_list 		va;

	if (slen == max_len_to_check + 1) {
		pinputstr = tstr;

		std::memcpy(tstr, inputstr, max_len_to_check);
		tstr[max_len_to_check] = 0;
	}	
	else {
		pinputstr = inputstr;
	}	

	va_start(va, format);
	ret = vsscanf(pinputstr, format, va);
	va_end(va);

	return ret;
}	



static CHAR_BUF<32> number_to_string(uint64_t num, const char * fmt = "%lu") noexcept
{
	CHAR_BUF<32>		cbuf;

	snprintf(cbuf.get(), sizeof(cbuf), fmt, num);

	return cbuf;
}	

static CHAR_BUF<32> number_to_string(uint32_t num, const char * fmt = "%u") noexcept
{
	CHAR_BUF<32>		cbuf;

	snprintf(cbuf.get(), sizeof(cbuf), fmt, num);

	return cbuf;
}	

static CHAR_BUF<32> number_to_string(uint16_t num, const char * fmt = "%hu") noexcept
{
	CHAR_BUF<32>		cbuf;

	snprintf(cbuf.get(), sizeof(cbuf), fmt, num);

	return cbuf;
}	

template <size_t sz_ = 128>
[[gnu::format (printf, 1, 2)]] 
CHAR_BUF<sz_> gy_to_charbuf(const char *fmt, ...) noexcept
{
	CHAR_BUF<sz_>		cbuf;
	va_list 		va;
	int			nwr;

	va_start(va, fmt);

	nwr = vsnprintf(cbuf.get(), sz_, fmt, va);

	if (nwr < 0) {
		*(cbuf.get()) = 0;
	}	

	va_end(va);

	return cbuf;
}	

/*
 * Returns true on success and updates result
 */ 
static inline bool string_to_number(const char *pstr, uint64_t &result, char **pendptr = nullptr, int base = 0) noexcept
{
	char			*endptr;
	
	errno = 0;
		
	result = std::strtoul(pstr, &endptr, base);

	if (pendptr) {
		*pendptr = endptr;
	}	

	if (gy_unlikely(((errno == ERANGE) && (result == ULONG_MAX)) || (errno != 0 && result == 0))) {
		return false;
	}	

	if (endptr == pstr) {
		errno = EINVAL;
		return false;
	}	

	return true;
}	


// Returns true on success and updates result
static inline bool string_to_number(const char *pstr, int64_t &result, char **pendptr = nullptr, int base = 0) noexcept
{
	char			*endptr;

	errno = 0;
	
	result = std::strtol(pstr, &endptr, base);

	if (pendptr) {
		*pendptr = endptr;
	}	

	if (gy_unlikely(((errno == ERANGE && (result == LONG_MAX || result == LONG_MIN)) || (errno != 0 && result == 0)))) {
		return false;
	}	

	if (endptr == pstr) {
		errno = EINVAL;
		return false;
	}	

	return true;
}	

// Returns true on success and updates result
static inline bool string_to_number(const char *pstr, int &result, char **pendptr = nullptr, int base = 0) noexcept
{
	int64_t			tret;
	char			*endptr;

	errno = 0;
	
	tret = std::strtol(pstr, &endptr, base);

	if (pendptr) {
		*pendptr = endptr;
	}	

	if (gy_unlikely((errno == ERANGE && (tret == LONG_MAX || tret == LONG_MIN)) || (errno != 0 && tret == 0))) {
		return false;
	}	
	
	if (gy_unlikely((tret >= INT_MAX) || (tret <= INT_MIN))) {
		errno = ERANGE;
		return false;
	}	

	if (endptr == pstr) {
		errno = EINVAL;
		return false;
	}	

	result = (int)tret;
	return true;
}	

// Returns true on success and updates result
static inline bool string_to_number(const char *pstr, uint32_t &result, char **pendptr = nullptr, int base = 0) noexcept
{
	uint64_t		tret;
	char			*endptr;

	errno = 0;
	
	tret = std::strtoul(pstr, &endptr, base);

	if (pendptr) {
		*pendptr = endptr;
	}	

	if (gy_unlikely((errno == ERANGE && (tret == ULONG_MAX)) || (errno != 0 && tret == 0)))  {
		return false;
	}	

	if (gy_unlikely(tret >= UINT_MAX)) {
		errno = ERANGE;
		return false;
	}	

	if (endptr == pstr) {
		errno = EINVAL;
		return false;
	}	

	result = (uint32_t)tret;
	return true;
}	

// Returns true on success and updates result
static inline bool string_to_number(const char *pstr, int16_t &result, char **pendptr = nullptr, int base = 0) noexcept
{
	int64_t			tret;
	char			*endptr;

	errno = 0;
	
	tret = std::strtol(pstr, &endptr, base);

	if (pendptr) {
		*pendptr = endptr;
	}	

	if (gy_unlikely((errno == ERANGE && (tret == LONG_MAX || tret == LONG_MIN)) || (errno != 0 && tret == 0)))  {
		return false;
	}	

	if (gy_unlikely((tret >= SHRT_MAX) || (tret <= SHRT_MIN))) {
		errno = ERANGE;
		return false;
	}

	if (endptr == pstr) {
		errno = EINVAL;
		return false;
	}	
	
	result = (int16_t)tret;
	return true;
}	

// Returns true on success and updates result
static inline bool string_to_number(const char *pstr, uint16_t &result, char **pendptr = nullptr, int base = 0) noexcept
{
	uint64_t		tret;
	char			*endptr;

	errno = 0;
	
	tret = std::strtoul(pstr, &endptr, base);

	if (pendptr) {
		*pendptr = endptr;
	}	

	if (gy_unlikely((errno == ERANGE && (tret == ULONG_MAX)) || (errno != 0 && tret == 0)))  {
		return false;
	}	

	if (gy_unlikely(tret >= USHRT_MAX)) {
		errno = ERANGE;
		return false;
	}	

	if (endptr == pstr) {
		errno = EINVAL;
		return false;
	}	

	result = (uint16_t)tret;
	return true;
}	


// Convert number to bool : Returns true on success and updates result
static inline bool string_to_number(const char *pstr, bool &result) noexcept
{
	int			iret;
	bool			bret;

	bret = string_to_number(pstr, iret);
	if (bret) {
		if (iret) {
			result = true;
		}
		else {
			result = false;	
		}		
		return true;
	}	
	else {
		return false;
	}	
}	

// Returns true on success and updates result
static inline bool string_to_number(const char *pstr, int8_t &result, char **pendptr = nullptr, int base = 0) noexcept
{
	int64_t			tret;
	char			*endptr;

	errno = 0;
	
	tret = std::strtol(pstr, &endptr, base);

	if (pendptr) {
		*pendptr = endptr;
	}	

	if (gy_unlikely((errno == ERANGE && (tret == LONG_MAX || tret == LONG_MIN)) || (errno != 0 && tret == 0)))  {
		return false;
	}	

	if (gy_unlikely((tret >= SCHAR_MAX) || (tret <= SCHAR_MIN))) {
		errno = ERANGE;
		return false;
	}

	if (endptr == pstr) {
		errno = EINVAL;
		return false;
	}	
		
	result = (int8_t)tret;
	return true;
}	

// Returns true on success and updates result
static inline bool string_to_number(const char *pstr, uint8_t &result, char **pendptr = nullptr, int base = 0) noexcept
{
	uint64_t		tret;
	char			*endptr;

	errno = 0;
	
	tret = std::strtoul(pstr, &endptr, base);

	if (pendptr) {
		*pendptr = endptr;
	}	

	if (gy_unlikely((errno == ERANGE && (tret == ULONG_MAX)) || (errno != 0 && tret == 0)))  {
		return false;
	}	

	if (gy_unlikely(tret >= UCHAR_MAX)) {
		errno = ERANGE;
		return false;
	}

	if (endptr == pstr) {
		errno = EINVAL;
		return false;
	}	
	
	result = (uint8_t)tret;
	return true;
}	


// Returns true on success and updates result
static inline bool string_to_number(const char *pstr, double &result, char **pendptr = nullptr) noexcept
{
	char			*endptr;

	errno = 0;
	
	result = std::strtod(pstr, &endptr);

	if (pendptr) {
		*pendptr = endptr;
	}	

	if ((errno == ERANGE && (result == HUGE_VAL)) || (errno != 0 && result == 0)) {
		return false;
	}	

	if (endptr == pstr) {
		errno = EINVAL;
		return false;
	}	

	return true;
}	

// Returns true on success and updates result
static inline bool string_to_number(const char *pstr, float &result, char **pendptr = nullptr) noexcept
{
	char			*endptr;

	errno = 0;
	
	result = std::strtof(pstr, &endptr);

	if (pendptr) {
		*pendptr = endptr;
	}	

	if ((errno == ERANGE && (result == HUGE_VALF)) || (errno != 0 && result == 0)) {
		return false;
	}	

	if (endptr == pstr) {
		errno = EINVAL;
		return false;
	}	

	return true;
}	

// Returns true on success and updates result
static inline bool string_to_number(const char *pstr, long double &result, char **pendptr = nullptr) noexcept
{
	char			*endptr;

	errno = 0;
	
	result = std::strtold(pstr, &endptr);

	if (pendptr) {
		*pendptr = endptr;
	}	

	if ((errno == ERANGE && (result == HUGE_VALL)) || (errno != 0 && result == 0)) {
		return false;
	}	

	if (endptr == pstr) {
		errno = EINVAL;
		return false;
	}	

	return true;
}	

// Will return T(0) in case of error and set *piserror = true
template <typename T>
T string_to_number(const char *pstr, int base = 0, bool *piserror = nullptr) noexcept
{
	T			res;
	bool			bret;

	if constexpr(std::is_integral<T>::value) {
		bret = string_to_number(pstr, res, nullptr, base);
	}
	else {
		bret = string_to_number(pstr, res);
	}	

	if (!bret) {
		if (piserror) {
			*piserror = true;
		}	

		return T(0);
	}	

	if (piserror) {
		*piserror = false;
	}

	return res;
}	

static inline std::optional<int> char_to_number(char c) noexcept
{
	if (!(c >= '0' && c <= '9')) {
		return {};
	}

	return c - '0';
}	

// Get length of string after rtrim (only space/tab chars)
static size_t get_rtrim_len(const char *str, size_t origlen) noexcept
{
	const char		*pend = str + origlen - 1;

	while (pend >= str && ((*pend == ' ') || (*pend == '\t'))) {
		pend--;
	}	

	if (pend >= str) {
		return pend - str + 1;
	}

	return 0;
}	

// Get string and length of string after ltrim (only space/tab chars)
static 
std::pair<const char *, size_t> get_ltrim(const char *str, size_t origlen) noexcept
{
	const char		*pend = str + origlen - 1;
	const char		*ptmp = str;

	while (ptmp <= pend && ((*ptmp == ' ') || (*ptmp == '\t'))) {
		ptmp++;
	}

	return {ptmp, pend - ptmp + 1};
}	

/*
 * Get string and length of string after left and right trim. (only space/tab chars)
 * Original string is not modified for right trim...
 */
static 
std::pair<const char *, size_t> get_trim_str(const char *str, size_t origlen) noexcept
{
	const char		*pend = str + origlen - 1;
	const char		*ptmp = str;

	while (ptmp <= pend && ((*ptmp == ' ') || (*ptmp == '\t'))) {
		ptmp++;
	}

	size_t			newlen = get_rtrim_len(ptmp, ssize_t(pend - ptmp + 1));

	return {ptmp, newlen};
}	

/*
 * Will return copied string in a CHAR_BUF<> without the trailing newline if nonewline (only last \n removed)
 */
template <size_t szbuf = 512>
CHAR_BUF<szbuf> copy_str_buf(const char *pmsg, bool nonewline = false) noexcept
{
	CHAR_BUF<szbuf>		ebuf;
	size_t			slen;	
	
	if (pmsg && *pmsg) {
		if constexpr(szbuf <= 512) {
			slen = strnlen(pmsg, sizeof(ebuf) - 1);
		}
		else {
			slen = strlen(pmsg);

			if (slen > sizeof(ebuf) - 1) {
				slen = sizeof(ebuf) - 1;
			}	
		}	

		if (slen && nonewline && pmsg[slen - 1] == '\n') {
			slen--;
		}	
		ebuf.setbuf(pmsg, slen);
	}	

	return ebuf;
}	


#define GY_ADD_NTOHS(_var, _inc)			\
({							\
	uint16_t _ts = htons(ntohs((_var)) + (_inc));	\
	_ts;						\
})	 

#define GY_ADD_NTOHL(_var, _inc)			\
({							\
	uint32_t _ts = htonl(ntohl((_var)) + (_inc));	\
	_ts;						\
})	

#define CTIME_NO_NEWLINE(_ptime, _pbuf)			\
({							\
	char		*__pb;				\
	__pb = ::ctime_r((_ptime), (_pbuf));		\
	if (__pb) {					\
		(_pbuf)[strlen(_pbuf) - 1] = '\0';	\
	}						\
	__pb;						\
})	
	
template <class T>
void error_if_polymorphic(const char *perrormsg)
{
	static_assert(!std::is_polymorphic<T>::value, "This cannot be used on a polymorphic class");
}	

/*
 * Max number of chars for a decimal type + space for - and \0
 * Usage : char		buf[DECIMAL_MAX_STRLEN(uint64_t)];
 */ 
#define DECIMAL_MAX_STRLEN(_type) 	(2 + (sizeof(_type) <= 1 ? 3 : sizeof(_type) <= 2 ? 5 : sizeof(_type) <= 4 ? 10 : sizeof(_type) <= 8 ? 20 : sizeof(_type) * 3))

static pid_t gy_gettid() noexcept;

static int get_task_cpu_mem_stats(pid_t pid, pid_t tid, uint64_t *pminflt, uint64_t *pmajflt, uint64_t *pusertime, uint64_t *psystime, uint64_t *pnum_threads, uint64_t *pvmsize, uint64_t *prss, uint64_t *pblkio_ticks, bool get_whole_proc, char *ptask_state = nullptr) noexcept
{
	int		fd, terr, ret;
	ssize_t		sz;
	char		c, buf[52 * DECIMAL_MAX_STRLEN(uint64_t)], *ptmp, *pend;
	
	if (get_whole_proc == false) {	
		snprintf(buf, sizeof(buf), "/proc/%d/task/%d/stat", pid, tid);
	}
	else {
		snprintf(buf, sizeof(buf), "/proc/%d/stat", pid);
	}		

	fd = open(buf, O_RDONLY);
	if (fd == -1) {
		return -1;
	}

	sz = read(fd, buf, sizeof(buf) - 1);
	if (sz <= 0) {
		terr = errno;
		close(fd);
		errno = terr;
		return -1;
	}
	
	close(fd);
	
	buf[sz] = '\0';
	
	pend = buf + sz;

	c = 0;

	if (sz > 50) {
		c = buf[50];
		buf[50] = 0;
	}

	ptmp = strrchr(buf, ')');

	if (!ptmp) {
		return -1;
	}
	
	if (c) {
		buf[50] = c;
	}

	while ((c = *ptmp) && (c != ' ')) {
		ptmp++;
	}

	while ((c = *ptmp) && (c == ' ')) {
		ptmp++;
	}	
	
	uint64_t	ul1, ul2, ul3, ul4, ul5, ul6;
	int64_t		l1, l2;

	ret = sscanf(ptmp, "%c %*d %*d %*d %*d %*d %*u %lu %*u %lu %*u %lu %lu %*d %*d %*d %*d %ld %*d %*u %lu %ld %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*d %*d %*u %*u %lu", 
			&c, &ul1, &ul2, &ul3, &ul4, &l1, &ul5, &l2, &ul6); 
	if (ret == 9) {
		if (ptask_state) {
			*ptask_state = c;
		}
			
		*pminflt 	= ul1;
		*pmajflt 	= ul2;
		*pusertime 	= ul3;
		*psystime	= ul4;
		*pnum_threads 	= l1;
		*pvmsize 	= ul5;
		*prss 		= (uint64_t)l2 * gy_page_size();
		*pblkio_ticks	= ul6;

		return 0;
	}
	
	return -1;
}

static int gy_task_io_stats(pid_t pid, pid_t tid, uint64_t *prdbytes, uint64_t *pwrbytes, uint64_t *prdsyscall, uint64_t *pwrsyscall, uint64_t *pactiord, uint64_t *pactiowr, bool get_whole_proc) noexcept
{
	int		fd, terr, ret;
	ssize_t		sz;
	char		buf[400], *ptmp, *pend;
	
	if (get_whole_proc == false) {
		snprintf(buf, sizeof(buf), "/proc/%d/task/%d/io", pid, tid);
	}
	else {
		snprintf(buf, sizeof(buf), "/proc/%d/io", pid);
	}		

	fd = open(buf, O_RDONLY);
	if (fd == -1) {
		return -1;
	}

	sz = read(fd, buf, sizeof(buf) - 1);
	if (sz <= 0) {
		terr = errno;
		close(fd);
		errno = terr;
		return -1;
	}
	
	close(fd);
	
	buf[sz] = '\0';

	pend = buf + sz;
	
	ptmp = strstr(buf, "rchar:");
	if (!ptmp) {
		return -1;
	}
	ptmp += strlen("rchar: ");
	
	if (ptmp + 1 >= pend) {
		return -1;
	}
	
	*prdbytes = std::strtoul(ptmp, nullptr, 10);
	
	ptmp = strstr(buf, "wchar:");
	if (!ptmp) {
		return -1;
	}
	ptmp += strlen("wchar: ");
	
	if (ptmp + 1 >= pend) {
		return -1;
	}
	
	*pwrbytes = std::strtoul(ptmp, nullptr, 10);
	
	ptmp = strstr(buf, "syscr:");
	if (!ptmp) {
		return -1;
	}
	ptmp += strlen("syscr: ");
	
	if (ptmp + 1 >= pend) {
		return -1;
	}
	
	*prdsyscall = std::strtoul(ptmp, nullptr, 10);
	
	ptmp = strstr(buf, "syscw:");
	if (!ptmp) {
		return -1;
	}
	ptmp += strlen("syscw: ");
	
	if (ptmp + 1 >= pend) {
		return -1;
	}
	
	*pwrsyscall = std::strtoul(ptmp, nullptr, 10);
	
	ptmp = strstr(buf, "read_bytes:");
	if (!ptmp) {
		return -1;
	}
	ptmp += strlen("read_bytes: ");
	
	if (ptmp + 1 >= pend) {
		return -1;
	}
	
	*pactiord = std::strtoul(ptmp, nullptr, 10);
	
	ptmp = strstr(buf, "write_bytes:");
	if (!ptmp) {
		return -1;
	}
	ptmp += strlen("write_bytes: ");
	
	if (ptmp + 1 >= pend) {
		return -1;
	}
	
	*pactiowr = std::strtoul(ptmp, nullptr, 10);
		
	return 0;
}

/*
 * Safe memset which detects a trivial class/struct to avoid clobbering the vtable
 * For classes with vtables or where memset on 'this' is unfeasable use GY_MEMBER_MEMSET as shown below :
 *
 * 
class my_test
{
public :	
	uint64_t		maxiter;
	classA			dist;
	classB			distend;

	virtual void		test1() {}
	
	// NOTE : cannot use std::memset(this, 0, sizeof (*this)); 

	my_test(uint64_t max_times) : 
		maxiter(GY_MEMBER_MEMSET(maxiter, distend, max_times)) 
	{ }
};	
 *
 * Example usage of gy_safe_memset : in constructor : gy_safe_memset(this);
 *
 */ 
template <typename T>
void * gy_safe_memset(T * pt) noexcept
{
	static_assert(std::is_trivially_copyable<T>::value, "ERROR : Cannot memset this class/struct : Use GY_MEMBER_MEMSET() instead");
	return std::memset((void *)pt, 0, sizeof(T)); 
}

#define GY_MEMBER_MEMSET(_first_member, _last_member, _first_member_data)										\
({																			\
	static_assert(std::is_trivial<decltype(_first_member)>::value, "For GY_MEMBER_MEMSET first element needs to be of trivial data type.");		\
																			\
	char 	*_pfirst = reinterpret_cast<char *>(&this->_first_member);										\
	char 	*_plast = reinterpret_cast<char *>(&this->_last_member);										\
	size_t	_sz = _plast - _pfirst + sizeof(this->_last_member);											\
																			\
	std::memset(_pfirst, 0, _sz);															\
	_first_member_data;																\
})

class SCOPE_LOCK_FILE
{
public :
	SCOPE_LOCK_FILE(FILE *pfile) noexcept
		: pfile_(pfile), tounlock_(pfile && (FSETLOCKING_INTERNAL == __fsetlocking(pfile, FSETLOCKING_QUERY)))
	{
		if (tounlock_) {
			flockfile(pfile);
		}	
	}

	~SCOPE_LOCK_FILE() noexcept
	{
		if (tounlock_) {
			funlockfile(pfile_);
		}	
	}	

	SCOPE_LOCK_FILE(SCOPE_LOCK_FILE && other) noexcept
		: pfile_(std::exchange(other.pfile_, nullptr)), tounlock_(std::exchange(other.tounlock_, false))
	{}	

	SCOPE_LOCK_FILE & operator= (SCOPE_LOCK_FILE && other) noexcept
	{
		if (this != &other) {
			this->~SCOPE_LOCK_FILE();

			new (this) SCOPE_LOCK_FILE(std::move(other));
		}

		return *this;
	}	

	SCOPE_LOCK_FILE(const SCOPE_LOCK_FILE &) 		= delete;

	SCOPE_LOCK_FILE & operator= (const SCOPE_LOCK_FILE &)	= delete;

	FILE				* pfile_;
	bool				tounlock_;
};	


/*
 * Single Execution Time profiler. 
 * At the end of the scope the execution time for the scope will be printed 
 */ 
class EXEC_TIME
{
public :
	const uint64_t			tprofstart_		{get_nsec_clock()};
	uint64_t			last_print_prof_	{0};
	const char 		* const name_			{""};
	uint64_t		* const	pexectime_		{nullptr};
	const uint32_t			linenum_		{0};
	const bool			dont_print_		{true};
		
	// Will not print on scope end
	EXEC_TIME() noexcept		= default;

	EXEC_TIME(const char *name, uint32_t linenum = 0, uint64_t *pexectime = nullptr, bool dont_print = false) noexcept
		: name_(name), pexectime_(pexectime), linenum_(linenum), dont_print_(dont_print) 
	{}

	~EXEC_TIME() noexcept
	{
		uint64_t		tresp;

		if (dont_print_ == false) {
			tresp = print_current_exec_time("At Scope End");
		}
		else if (pexectime_) {
			tresp = get_profile_time();	
		}		

		if (pexectime_) {
			*pexectime_ = tresp;
		}	
	}

	uint64_t print_current_exec_time(const char *prefix = "") noexcept
	{
		uint64_t		currcnsec = get_nsec_clock();
		uint64_t 		tresp 	= currcnsec - tprofstart_;
		char			buf1[512], buf2[512];

		snprintf(buf1, sizeof(buf1), "[%s] Execution time for \'%s\' : %u was %lu nsec (%lu usec) (%lu msec) (%.09f sec)", 
			prefix, name_, linenum_, tresp, tresp/1000, tresp/1000'000, tresp/1000000000.0f);

		if (last_print_prof_ > tprofstart_) {
			tresp 	= currcnsec - last_print_prof_;

			snprintf(buf2, sizeof(buf2), "\n\t\t\t\t\t\tExecution time since last print call : was %lu nsec (%lu usec) (%lu msec) (%.09f sec)", 
				tresp, tresp/1000, tresp/1000'000, tresp/1000000000.0f);
		}	
		else {
			*buf2 = 0;
		}	
		
		last_print_prof_ = currcnsec;

#		ifdef INFOPRINT_OFFLOAD
		INFOPRINT_OFFLOAD("%s%s\n", buf1, buf2);	
#		else
		INFOPRINT("%s%s\n", buf1, buf2);	
#		endif

		return tresp;
	}	

	/*
	 * Returns nanoseconds clock difference from start
	 */ 	
	uint64_t get_profile_time() const noexcept
	{
		return get_nsec_clock() - tprofstart_;
	}

	/*
	 * Returns {nanoseconds, msec, sec} from start
	 */ 	
	std::tuple<uint64_t, uint64_t, double> get_profile_times() const noexcept
	{
		uint64_t tresp = get_profile_time();

		return {tresp, tresp/1000'000, tresp/1000000000.0};
	}	
};

template <bool is_atomic = false>
struct min_max_uint64 
{
	typedef typename std::conditional<is_atomic == true, gy_atomic<uint64_t>, gy_noatomic<uint64_t>>::type 	Tuint64;

	Tuint64				tot_val_		{0ul};
	Tuint64				min_val_		{~0ul};
	Tuint64				max_val_		{0ul};

	min_max_uint64() noexcept	= default;

	void add(uint64_t val) noexcept
	{
		tot_val_.fetch_add(val, std::memory_order_relaxed);
		
		uint64_t curmint = min_val_.load(std::memory_order_relaxed);
		if (curmint > val) {
			// Not completely atomic as compare exchange not used...
			min_val_.store(val, std::memory_order_relaxed);
		} 

		uint64_t curmaxt = max_val_.load(std::memory_order_relaxed);

		if (curmaxt < val) {
			max_val_.compare_exchange_strong(curmaxt, val, std::memory_order_release, std::memory_order_relaxed);
		}
	}
		
	void add(uint64_t val, uint64_t * __restrict__ ptot_val, uint64_t * __restrict__ pmin_val, uint64_t * __restrict__ pmax_val) noexcept
	{
		uint64_t curtot = tot_val_.fetch_add(val, std::memory_order_relaxed);
		
		uint64_t curmint = min_val_.load(std::memory_order_relaxed);
		if (curmint > val) {
			// Not completely atomic...
			min_val_.store(val, std::memory_order_relaxed);
			curmint = val;
		} 

		uint64_t curmaxt = max_val_.load(std::memory_order_relaxed);

		if (curmaxt < val) {
			bool bret = max_val_.compare_exchange_strong(curmaxt, val, std::memory_order_release, std::memory_order_relaxed);
			if (bret == true) {
				curmaxt = val;
			}
		}

		*ptot_val = curtot + val;
		*pmin_val = (int64_t)curmint >= 0l ? curmint : 0ul;
		*pmax_val = curmaxt;
	}

	void get_current(uint64_t * __restrict__ ptot_val, uint64_t * __restrict__ pmin_val, uint64_t * __restrict__ pmax_val) const noexcept
	{
		*ptot_val = tot_val_.load(std::memory_order_relaxed);
		*pmin_val = min_val_.load(std::memory_order_relaxed);
		if (int64_t(*pmin_val) <= 0l) *pmin_val = 0ul;
		*pmax_val = max_val_.load(std::memory_order_relaxed);
	}

	void get_current(uint64_t & tot_val, uint64_t & min_val, uint64_t & max_val) const noexcept
	{
		tot_val = tot_val_.load(std::memory_order_relaxed);
		min_val = min_val_.load(std::memory_order_relaxed);
		if (int64_t(min_val) <= 0l) min_val = 0ul;
		max_val = max_val_.load(std::memory_order_relaxed);
	}
	
	void reset() noexcept
	{
		tot_val_.store(0ul, std::memory_order_relaxed);
		min_val_.store(~0ul, std::memory_order_relaxed);
		max_val_.store(0ul, std::memory_order_release);
	}
};

template <bool is_atomic = false>
struct min_max_counter
{
	typedef typename std::conditional<is_atomic == true, gy_atomic<uint64_t>, gy_noatomic<uint64_t>>::type 	T;
	
	min_max_uint64<is_atomic>	mstat_;
	T				niter_ 		{0};

	min_max_counter() noexcept 	= default;

	void add(uint64_t val) noexcept
	{
		mstat_.add(val);
		niter_.fetch_add(1, std::memory_order_relaxed);
	}
		
	void add(uint64_t val, uint64_t * __restrict__ ptot_val, uint64_t * __restrict__ pmin_val, uint64_t * __restrict__ pmax_val) noexcept
	{
		mstat_.add(val, ptot_val, pmin_val, pmax_val);
		niter_.fetch_add(1, std::memory_order_relaxed);
	}		

	void get_current(uint64_t * __restrict__ ptot_val, uint64_t * __restrict__ pmin_val, uint64_t * __restrict__ pmax_val, uint64_t * __restrict__ piter_val, double * pavg_val) const noexcept
	{
		mstat_.get_current(ptot_val, pmin_val, pmax_val);
		*piter_val = niter_.load(std::memory_order_relaxed);

		*pavg_val = *ptot_val/(1.0 * (*piter_val ? *piter_val : 1));
	}	

	void get_current(uint64_t & tot_val, uint64_t & min_val, uint64_t & max_val, uint64_t & iter_val, double & avg_val) const noexcept
	{
		mstat_.get_current(tot_val, min_val, max_val);
		iter_val = niter_.load(std::memory_order_relaxed);

		avg_val = tot_val/(1.0 * (iter_val ? iter_val : 1));
	}	

	void reset() noexcept
	{
		mstat_.reset();
		niter_.store(0, std::memory_order_relaxed);
	}	
};	

template <bool is_atomic>
class MULTI_EXEC_STATS
{
public :	
	typedef typename std::conditional<is_atomic == true, gy_atomic<uint64_t>, gy_noatomic<uint64_t>>::type 	T;

	T					nexecs;
	min_max_uint64 <is_atomic>		acc_resp;
	uint64_t				tstartstats;
	const uint64_t				nresetexecs;
	const char 				*pfuncname;
	const uint32_t				linenum;
	const char				*pcomment;
	
	MULTI_EXEC_STATS()	= delete;

	MULTI_EXEC_STATS(const char *pfuncname, uint32_t linenum, const char *pcomment, uint64_t nresetexecs) noexcept : 
		nexecs(0), tstartstats(get_nsec_clock()), nresetexecs(nresetexecs),
		pfuncname(pfuncname), linenum(linenum), pcomment(pcomment) 
	{
	}

	~MULTI_EXEC_STATS() noexcept
	{
		print_current();
	}
		
	void add(uint64_t tresp) noexcept
	{
		uint64_t curntimes = nexecs.fetch_add(1, std::memory_order_relaxed);
		uint64_t curtresp, curmint, curmaxt;
		
		acc_resp.add(tresp, &curtresp, &curmint, &curmaxt);

		if (curntimes + 1 >= nresetexecs) {
			curntimes++;

			bool bret = nexecs.compare_exchange_strong(curntimes, 0);
			if (bret == true) {

				acc_resp.reset();

				uint64_t		tnew = get_nsec_clock();

				if (curntimes > 1) {
					INFOPRINTCOLOR(GY_COLOR_CYAN_ITALIC, "Profile Stats (%s thread safe) for [%s : %u : %s] after %lu executions and %.09f sec : "
						"Avg Exec Time %lu nsec (%lu usec) (%.09f sec), Min %lu nsec (%lu usec), Max %lu nsec (%lu usec)\n",
						is_atomic ? "multi" : "single", pfuncname, linenum, pcomment, curntimes, (tnew - tstartstats)/1000000000.0f, 
						curtresp/curntimes, curtresp/(curntimes * 1000), curtresp/(curntimes * 1000000000.0f),
						curmint, curmint/1000, curmaxt, curmaxt/1000);
				}
				else {
					INFOPRINTCOLOR(GY_COLOR_CYAN_ITALIC, "Profile Stats (single execution) for [%s : %u : %s] after %lu executions and %.09f sec : "
						"Exec Time %lu nsec (%lu usec) (%.09f sec)\n",
						pfuncname, linenum, pcomment, curntimes, (tnew - tstartstats)/1000000000.0f, 
						curtresp/curntimes, curtresp/(curntimes * 1000), curtresp/(curntimes * 1000000000.0f));
				}
				tstartstats = tnew;
			}
		}
	}

	void get_stats(uint64_t & texec_nsec, uint64_t & total_cnt, uint64_t & avg_nsec, uint64_t & min_nsec, uint64_t & max_nsec) const noexcept
	{
		uint64_t curtresp, curmint, curmaxt;
		uint64_t curntimes = nexecs.load(std::memory_order_relaxed);

		acc_resp.get_current(&curtresp, &curmint, &curmaxt);

		texec_nsec 	= curtresp;
		total_cnt	= curntimes;
		avg_nsec	= curtresp/(curntimes ? curntimes : 1);
		min_nsec	= curmint;
		max_nsec	= curmaxt;
	}

	void print_current() const noexcept
	{
		uint64_t curtresp, curmint, curmaxt;
		uint64_t curntimes 	= nexecs.load(std::memory_order_relaxed);

		if (curntimes == 0) return;

		acc_resp.get_current(&curtresp, &curmint, &curmaxt);

		INFOPRINTCOLOR(GY_COLOR_CYAN_ITALIC, "Profile Stats (%s thread safe) for [%s : %u : %s] after %lu executions : "
			"Avg Exec Time %lu nsec (%lu usec) (%.09f sec), Min %lu nsec (%lu usec), Max %lu nsec (%lu usec)\n",
					is_atomic ? "multi" : "single",	pfuncname, linenum, pcomment, curntimes, 
					curtresp/curntimes, curtresp/(curntimes * 1000), curtresp/(curntimes * 1000000000.0f),
					curmint, curmint/1000, curmaxt, curmaxt/1000);

	}
};

/*
 * Multiple Execution Time profiler. (Optional Multi thread safe & Scope based)
 * Usage : 
 * Create a static object of type MULTI_EXEC_STATS<bool is_atomic> as in : 
 *
 * static MULTI_EXEC_STATS<true> stats1(__FUNCTION__, __LINE__, "My comment", 100000); for multi thread aggregated stats
 * 		OR 
 * static MULTI_EXEC_STATS<false> stats1(__FUNCTION__, __LINE__, "My comment", 100000); for single thread safe stats
 * 
 * Here 100000 is the execution count after which stats are printed and reset.
 *
 * Then, create a local object of type MULTI_EXEC_TIME <bool is_atomic> as in : 
 *
 * MULTI_EXEC_TIME <true>		prof1(&stats1); 	// for MT safety
 * 	OR
 * MULTI_EXEC_TIME <false>		prof1(&stats1); 	// for single thread safety
 *
 * 2 helper macros named GY_MT_COLLECT_PROFILE and GY_NOMT_COLLECT_PROFILE are defined below but 
 * are only compiled if DO_PROFILE is defined.
 *
 * GY_MT_COLLECT_PROFILE is multi thread safe while GY_NOMT_COLLECT_PROFILE is single thread safe.
 *
 * Example usage : GY_MT_COLLECT_PROFILE(1000000, "Execution time for mt safe test function");
 */ 
template <bool is_atomic>
class MULTI_EXEC_TIME
{
	const uint64_t			tprofstart;
	MULTI_EXEC_STATS<is_atomic>	*pstats;
		
public :
	MULTI_EXEC_TIME() = delete;

	MULTI_EXEC_TIME(MULTI_EXEC_STATS<is_atomic> *pstats) noexcept : tprofstart(get_nsec_clock()), pstats(pstats) 
	{ }

	~MULTI_EXEC_TIME() noexcept
	{
		uint64_t tresp = get_profile_time();
		pstats->add(tresp);
	}

	uint64_t get_profile_time(void) const noexcept
	{
		uint64_t tresp = get_nsec_clock() - tprofstart;

		return tresp;
	}

	void print_current() const noexcept
	{
		pstats->print_current();
	}
};

#ifdef DO_PROFILE

/*
 * Not Multi process safe XXX
 * For those cases, define a custom mmaped object of type MULTI_EXEC_STATS
 */ 
#define GY_MT_COLLECT_PROFILE(_nexec, _comment)											\
																\
static	gyeeta::MULTI_EXEC_STATS<true>		GY_CONCATENATE(stats__, __LINE__)(__FUNCTION__, __LINE__, _comment, (_nexec));	\
gyeeta::MULTI_EXEC_TIME<true>			GY_CONCATENATE(obj__, __LINE__)(&GY_CONCATENATE(stats__, __LINE__));
						
/*
 * Single thread safe multi execution profiler
 */ 
#define GY_NOMT_COLLECT_PROFILE(_nexec, _comment)										\
																\
static	gyeeta::MULTI_EXEC_STATS<false>		GY_CONCATENATE(stats__, __LINE__)(__FUNCTION__, __LINE__, _comment, (_nexec));	\
gyeeta::MULTI_EXEC_TIME<false>			GY_CONCATENATE(obj__, __LINE__)(&GY_CONCATENATE(stats__, __LINE__));

/*
 * Single execution time profiler. (No multi exec/threaded)
 */

#define GY_COLLECT_PROFILE(_comment)	 											\
																\
gyeeta::MULTI_EXEC_STATS<false>			GY_CONCATENATE(stats__, __LINE__)(__FUNCTION__, __LINE__, _comment, 1);		\
gyeeta::MULTI_EXEC_TIME<false>			GY_CONCATENATE(obj__, __LINE__)(&GY_CONCATENATE(stats__, __LINE__));

#else

#define GY_MT_COLLECT_PROFILE(_nexec, _comment) 						

#define GY_NOMT_COLLECT_PROFILE(_nexec, _comment) 						

#define GY_COLLECT_PROFILE(_comment)		 										

#endif

/*
 * See comment for THR_IO_PROFILE below...
 */ 
template <bool is_atomic>
class MULTI_IO_STATS
{
public :	
	typedef typename std::conditional<is_atomic == true, gy_atomic<uint64_t>, gy_noatomic<uint64_t>>::type 	T;

	T					nexecs;
	min_max_uint64 <is_atomic>		acc_minflt, acc_majflt, acc_usertime, acc_systime, acc_blkio_ticks;
	min_max_uint64 <is_atomic>		acc_rchar, acc_wchar, acc_syscr, acc_syscw, acc_read_bytes, acc_write_bytes;
	uint64_t				tstartstats;
	const uint64_t				nresetexecs;
	const char 				*pfuncname;
	const uint32_t				linenum;
	const char				*pcomment;
	const uint32_t				sc_tck;
	
	MULTI_IO_STATS()			= delete;

	MULTI_IO_STATS(const char *pfuncname, uint32_t linenum, const char *pcomment, uint64_t nresetexecs) noexcept : 
		nexecs(0), tstartstats(get_nsec_clock()), nresetexecs(nresetexecs),
		pfuncname(pfuncname), linenum(linenum), pcomment(pcomment), sc_tck(gy_clk_tck()) 
	{
	}

	~MULTI_IO_STATS() noexcept		= default;
		
	uint64_t get_nexec_print() const noexcept
	{
		return nresetexecs;	
	}
			
	void set_thread_start_clock(uint64_t startclock)
	{
		tstartstats = startclock;
	}
			
	void add(uint64_t minflt, uint64_t majflt, uint64_t usertime, uint64_t systime, uint64_t rchar, uint64_t wchar, uint64_t syscr, uint64_t syscw, uint64_t read_bytes, uint64_t write_bytes, uint64_t blkio_ticks, uint64_t vmsize, uint64_t rss, uint64_t num_threads) noexcept
	{
		uint64_t curntimes = nexecs.fetch_add(1, std::memory_order_relaxed);

		uint64_t cur_tot_minflt, cur_tot_majflt, cur_tot_usertime, cur_tot_systime, cur_tot_blkio_ticks;
		uint64_t cur_min_minflt, cur_min_majflt, cur_min_usertime, cur_min_systime, cur_min_blkio_ticks;
		uint64_t cur_max_minflt, cur_max_majflt, cur_max_usertime, cur_max_systime, cur_max_blkio_ticks;

		uint64_t cur_tot_rchar, cur_tot_wchar, cur_tot_syscr, cur_tot_syscw, cur_tot_read_bytes, cur_tot_write_bytes;
		uint64_t cur_min_rchar, cur_min_wchar, cur_min_syscr, cur_min_syscw, cur_min_read_bytes, cur_min_write_bytes;
		uint64_t cur_max_rchar, cur_max_wchar, cur_max_syscr, cur_max_syscw, cur_max_read_bytes, cur_max_write_bytes;

		char	 non_atomic_cpu_pct_str[128];	
		
		acc_minflt.add(minflt, &cur_tot_minflt, &cur_min_minflt, &cur_max_minflt);
		acc_majflt.add(majflt, &cur_tot_majflt, &cur_min_majflt, &cur_max_majflt);
		acc_usertime.add(usertime, &cur_tot_usertime, &cur_min_usertime, &cur_max_usertime);
		acc_systime.add(systime, &cur_tot_systime, &cur_min_systime, &cur_max_systime);
		acc_blkio_ticks.add(blkio_ticks, &cur_tot_blkio_ticks, &cur_min_blkio_ticks, &cur_max_blkio_ticks);

		acc_rchar.add(rchar, &cur_tot_rchar, &cur_min_rchar, &cur_max_rchar);
		acc_wchar.add(wchar, &cur_tot_wchar, &cur_min_wchar, &cur_max_wchar);
		acc_syscr.add(syscr, &cur_tot_syscr, &cur_min_syscr, &cur_max_syscr);
		acc_syscw.add(syscw, &cur_tot_syscw, &cur_min_syscw, &cur_max_syscw);
		acc_read_bytes.add(read_bytes, &cur_tot_read_bytes, &cur_min_read_bytes, &cur_max_read_bytes);
		acc_write_bytes.add(write_bytes, &cur_tot_write_bytes, &cur_min_write_bytes, &cur_max_write_bytes);

		if (curntimes + 1 >= nresetexecs) {
			curntimes++;

			bool bret = nexecs.compare_exchange_strong(curntimes, 0);
			if (bret == true) {

				acc_minflt.reset();
				acc_majflt.reset();
				acc_usertime.reset();
				acc_systime.reset();
				acc_blkio_ticks.reset();

				acc_rchar.reset();
				acc_wchar.reset();
				acc_syscr.reset();
				acc_syscw.reset();
				acc_read_bytes.reset();
				acc_write_bytes.reset();

				const uint64_t		tnew = get_nsec_clock();

				if (curntimes > 1) {

					if (is_atomic == false) {
						double		usercpupct, syscpupct, blkiodelaypct;
						uint64_t	diffticks = (tnew - tstartstats)/(GY_NSEC_PER_SEC/sc_tck);

						if (diffticks == 0) diffticks = 1;

						usercpupct = (double)cur_tot_usertime /  diffticks * 100;
						syscpupct = (double)cur_tot_systime /  diffticks * 100;
						blkiodelaypct = (double)cur_tot_blkio_ticks /  diffticks * 100;

						snprintf(non_atomic_cpu_pct_str, sizeof(non_atomic_cpu_pct_str),
							"User CPU Usage %.03f %%, Sys CPU Usage %.03f %%, Blkio Delay %.03f %%", usercpupct, syscpupct, blkiodelaypct);
					}
					else {
						*non_atomic_cpu_pct_str = '\0';
					}
						
					INFOPRINT("Thread/Proc CPU/Mem Stats (%s thread safe) for [%s : %u : %s] after %lu iterations : Duration %.09f sec : Avg Duration/call %.09f sec : %s "
						"Virtual Mem %lu MB RSS %lu MB Num Threads %ld : "
						"Avg Minor Page Faults %lu, Avg Major Page Fault %lu, Avg User Time %lu ticks, Avg Sys Time %lu ticks, Avg Blkio delay %lu ticks : "
						"Min Minor Page Faults %lu, Min Major Page Fault %lu, Min User Time %lu ticks, Min Sys Time %lu ticks, Min Blkio delay %lu ticks : "
						"Max Minor Page Faults %lu, Max Major Page Fault %lu, Max User Time %lu ticks, Max Sys Time %lu ticks, Max Blkio delay %lu ticks\n",
					
						is_atomic ? "multi" : "single", pfuncname, linenum, pcomment, curntimes, (tnew - tstartstats)/1000000000.0f, 
						(tnew - tstartstats)/1000000000.0f/curntimes, non_atomic_cpu_pct_str, GY_DOWN_MB(vmsize), GY_DOWN_MB(rss), num_threads,
						cur_tot_minflt/curntimes, cur_tot_majflt/curntimes, cur_tot_usertime/curntimes, cur_tot_systime/curntimes, cur_tot_blkio_ticks/curntimes,
						cur_min_minflt, cur_min_minflt, cur_min_usertime, cur_min_systime, cur_min_blkio_ticks,
						cur_max_minflt, cur_max_majflt, cur_max_usertime, cur_max_systime, cur_max_blkio_ticks);					

					INFOPRINT("Thread/Proc IO Stats (%s thread safe) for [%s : %u : %s] after %lu iterations : Duration %.09f sec : "
						"Avg Bytes Read %lu, Avg Bytes Written %lu, Avg Read Syscalls %lu, Avg Write Syscalls %lu, Avg Act Bytes Read %lu, Avg Act Bytes Written %lu : "
						"Min Bytes Read %lu, Min Bytes Written %lu, Min Read Syscalls %lu, Min Write Syscalls %lu, Min Act Bytes Read %lu, Min Act Bytes Written %lu : "
						"Max Bytes Read %lu, Max Bytes Written %lu, Max Read Syscalls %lu, Max Write Syscalls %lu, Max Act Bytes Read %lu, Max Act Bytes Written %lu\n",
						
						is_atomic ? "multi" : "single", pfuncname, linenum, pcomment, curntimes, (tnew - tstartstats)/1000000000.0f, 
						cur_tot_rchar/curntimes, cur_tot_wchar/curntimes, cur_tot_syscr/curntimes, cur_tot_syscw/curntimes, cur_tot_read_bytes/curntimes, 
						cur_tot_write_bytes/curntimes, 
						cur_min_rchar, cur_min_wchar, cur_min_syscr, cur_min_syscw, cur_min_read_bytes, cur_min_write_bytes, 
						cur_max_rchar, cur_max_wchar, cur_min_syscr, cur_max_syscw, cur_max_read_bytes, cur_max_write_bytes); 
				}
				else {
					double		usercpupct, syscpupct, blkiodelaypct;
					uint64_t	diffticks = (tnew - tstartstats)/(GY_NSEC_PER_SEC/sc_tck);

					if (diffticks == 0) diffticks = 1;

					usercpupct = (double)cur_max_usertime /  diffticks * 100;
					syscpupct = (double)cur_max_systime /  diffticks * 100;
					blkiodelaypct = (double)cur_max_blkio_ticks /  diffticks * 100;

					INFOPRINT("Thread/Proc CPU/Mem/IO Stats for [%s : %u : %s] after %.09f sec : "
						"User CPU Usage %.03f %%, Sys CPU Usage %.03f %%, Blkio Delay %.03f %%, User Time %lu ticks, Sys Time %lu ticks, Blkio Delay %lu ticks, "
						"Virtual Memory %lu MB, RSS %lu MB, Minor Page Faults %lu, Major Page Fault %lu, Num Threads %lu, "
						"Bytes Read %lu, Bytes Written %lu, Read Syscalls %lu, Write Syscalls %lu, Act Bytes Read %lu, Act Bytes Written %lu\n\n",
						pfuncname, linenum, pcomment, (tnew - tstartstats)/1000000000.0f, 
						usercpupct, syscpupct, blkiodelaypct, cur_max_usertime, cur_max_systime, cur_max_blkio_ticks, 
						GY_DOWN_MB(vmsize), GY_DOWN_MB(rss), cur_max_minflt, cur_max_majflt, num_threads,
						cur_max_rchar, cur_max_wchar, cur_min_syscr, cur_max_syscw, cur_max_read_bytes, cur_max_write_bytes); 
				}

				tstartstats = tnew;
			}
		}
	}

	void print_current() const noexcept
	{
		uint64_t curntimes = nexecs.load(std::memory_order_relaxed);

		if (curntimes == 0) return;

		uint64_t cur_tot_minflt, cur_tot_majflt, cur_tot_usertime, cur_tot_systime, cur_tot_blkio_ticks;
		uint64_t cur_min_minflt, cur_min_majflt, cur_min_usertime, cur_min_systime, cur_min_blkio_ticks;
		uint64_t cur_max_minflt, cur_max_majflt, cur_max_usertime, cur_max_systime, cur_max_blkio_ticks;

		uint64_t cur_tot_rchar, cur_tot_wchar, cur_tot_syscr, cur_tot_syscw, cur_tot_read_bytes, cur_tot_write_bytes;
		uint64_t cur_min_rchar, cur_min_wchar, cur_min_syscr, cur_min_syscw, cur_min_read_bytes, cur_min_write_bytes;
		uint64_t cur_max_rchar, cur_max_wchar, cur_max_syscr, cur_max_syscw, cur_max_read_bytes, cur_max_write_bytes;

		acc_minflt.get_current(&cur_tot_minflt, &cur_min_minflt, &cur_max_minflt);
		acc_majflt.get_current(&cur_tot_majflt, &cur_min_majflt, &cur_max_majflt);
		acc_usertime.get_current(&cur_tot_usertime, &cur_min_usertime, &cur_max_usertime);
		acc_systime.get_current(&cur_tot_systime, &cur_min_systime, &cur_max_systime);
		acc_systime.get_current(&cur_tot_blkio_ticks, &cur_min_blkio_ticks, &cur_max_blkio_ticks);

		acc_rchar.get_current(&cur_tot_rchar, &cur_min_rchar, &cur_max_rchar);
		acc_wchar.get_current(&cur_tot_wchar, &cur_min_wchar, &cur_max_wchar);
		acc_syscr.get_current(&cur_tot_syscr, &cur_min_syscr, &cur_max_syscr);
		acc_syscw.get_current(&cur_tot_syscw, &cur_min_syscw, &cur_max_syscw);
		acc_read_bytes.get_current(&cur_tot_read_bytes, &cur_min_read_bytes, &cur_max_read_bytes);
		acc_write_bytes.get_current(&cur_tot_write_bytes, &cur_min_write_bytes, &cur_max_write_bytes);

		INFOPRINT("Thread/Proc CPU/Mem Stats (%s thread safe) for [%s : %u : %s] after %lu executions : "
			"Avg Minor Page Faults %lu, Avg Major Page Fault %lu, Avg User Time %lu ticks, Avg Sys Time %lu ticks, Avg Blkio delay %lu ticks : "
			"Min Minor Page Faults %lu, Min Major Page Fault %lu, Min User Time %lu ticks, Min Sys Time %lu ticks, Min Blkio delay %lu ticks : "
			"Max Minor Page Faults %lu, Max Major Page Fault %lu, Max User Time %lu ticks, Max Sys Time %lu ticks, Max Blkio delay %lu ticks\n",
				
					is_atomic ? "multi" : "single", pfuncname, linenum, pcomment, curntimes, 
					cur_tot_minflt/curntimes, cur_tot_majflt/curntimes, cur_tot_usertime/curntimes, cur_tot_systime/curntimes, cur_tot_blkio_ticks/curntimes,
					cur_min_minflt, cur_min_minflt, cur_min_usertime, cur_min_systime, cur_min_blkio_ticks,
					cur_max_minflt, cur_max_majflt, cur_max_usertime, cur_max_systime, cur_max_blkio_ticks);					

		INFOPRINT("Thread/Proc IO Stats (%s thread safe) for [%s : %u : %s] after %lu executions : "
					"Avg Bytes Read %lu, Avg Bytes Written %lu, Avg Read Syscalls %lu, Avg Write Syscalls %lu, Avg Act Bytes Read %lu, Avg Act Bytes Written %lu : "
					"Min Bytes Read %lu, Min Bytes Written %lu, Min Read Syscalls %lu, Min Write Syscalls %lu, Min Act Bytes Read %lu, Min Act Bytes Written %lu : "
					"Max Bytes Read %lu, Max Bytes Written %lu, Max Read Syscalls %lu, Max Write Syscalls %lu, Max Act Bytes Read %lu, Max Act Bytes Written %lu\n\n",
					
					is_atomic ? "multi" : "single", pfuncname, linenum, pcomment, curntimes, 
					cur_tot_rchar/curntimes, cur_tot_wchar/curntimes, cur_tot_syscr/curntimes, cur_tot_syscw/curntimes, cur_tot_read_bytes/curntimes, 
					cur_tot_write_bytes/curntimes, 
					cur_min_rchar, cur_min_wchar, cur_min_syscr, cur_min_syscw, cur_min_read_bytes, cur_min_write_bytes, 
					cur_max_rchar, cur_max_wchar, cur_min_syscr, cur_max_syscw, cur_max_read_bytes, cur_max_write_bytes); 
	}
};


/*
 * Multiple Thread specific Page Fault/CPU Time Time profiler. (Optional Multi thread safe & Scope based or whole process monitor options as well...)
 *
 * CAUTION : Use only for profiling as the Counter readers will take a bit of CPU
 *
 * Usage : 
 * For multiple execution (aggregated over multiple threads) profiling, create a static object of type MULTI_IO_STATS<bool is_atomic> as in : 
 *
 * static MULTI_IO_STATS<true> 	stats1(__FUNCTION__, __LINE__, 100000); for multi thread safety multi iteration monitor
 * 
 * 		OR for a single thread, multi exec aggregation :
 * 		
 * static MULTI_IO_STATS<false> 	stats1(__FUNCTION__, __LINE__, 100000); for single thread safety multi iteration monitor
 * 
 * Here 100000 is the iteration count after which stats are printed and reset for next set. For a single execution non-atomic case, skip the static keyword.
 *
 * Then, create a local object of type THR_IO_PROFILE <bool is_atomic> as in : 
 *
 * THR_IO_PROFILE <true>		prof1(&stats1); 					// for MT safety
 * 	OR
 * THR_IO_PROFILE <false>		prof1(&stats1, <Optional bool monitor_whole_proc>); 	// for single thread safety
 *
 * 2 helper macros named GY_MT_COLLECT_THREAD_IO and GY_NOMT_COLLECT_THREAD_IO are defined below but 
 * are only compiled if profile=yes is passed to * buildall.sh script.
 *
 * GY_MT_COLLECT_THREAD_IO is multi thread safe while GY_NOMT_COLLECT_THREAD_IO is single thread safe.
 *
 * Example usage : GY_MT_COLLECT_THREAD_IO(1000000, "CPU/IO stats for mt safe test function");
 *
 * XXX The MULTI_IO_STATS constructor pfuncname && pcomment pointer is cached. Please ensure the
 * pointer remains valid whilst the object is alive... Better still pass these as string literals
 *
 */ 

template <bool is_atomic>
class THR_IO_PROFILE
{
	MULTI_IO_STATS<is_atomic>	*pstats;
	uint64_t			minflt, majflt, usertime, systime, vmsize, rss, blkio_ticks, num_threads;
	uint64_t			rchar, wchar, syscr, syscw, read_bytes, write_bytes;
	const bool			monitor_whole_proc;
	const pid_t			pid, tid;	


public :
	THR_IO_PROFILE() = delete;

	explicit THR_IO_PROFILE(MULTI_IO_STATS<is_atomic> *pstatsin, bool monitor_whole_proc = false, pid_t pid = getpid(), pid_t tid = gy_gettid()) noexcept : 
		pstats(pstatsin), monitor_whole_proc(monitor_whole_proc), pid(pid), tid(tid) 
	{ 
		if ((is_atomic == false) && (1 < pstats->get_nexec_print())) {
			pstats->set_thread_start_clock(get_nsec_clock());
		}
			
		int ret = get_task_cpu_mem_stats(pid, tid, &minflt, &majflt, &usertime, &systime, &num_threads, &vmsize, &rss, &blkio_ticks, monitor_whole_proc);
		if (ret != 0) {
			DEBUGEXECN(1, PERRORPRINT("Could not get Thread/Proc CPU/Memory statistics for PID %d Thread %d", pid, tid));
			return;
		}

		ret = gy_task_io_stats(pid, tid, &rchar, &wchar, &syscr, &syscw, &read_bytes, &write_bytes, monitor_whole_proc);
		if (ret != 0) {
			DEBUGEXECN(1, PERRORPRINT("Could not get Thread/Proc IO statistics for PID %d Thread %d", pid, tid));
		}
	}

	~THR_IO_PROFILE() noexcept
	{
		uint64_t			aminflt, amajflt, ausertime, asystime, ablkio_ticks;
		uint64_t			archar, awchar, asyscr, asyscw, aread_bytes, awrite_bytes;

		int ret = get_task_cpu_mem_stats(pid, tid, &aminflt, &amajflt, &ausertime, &asystime, &num_threads, &vmsize, &rss, &ablkio_ticks, monitor_whole_proc);
		if (ret != 0) {
			DEBUGEXECN(1, PERRORPRINT("Could not get Thread/Proc CPU/Memory statistics for PID %d Thread %d", pid, tid));
			return;
		}
		else {
			ret = gy_task_io_stats(pid, tid, &archar, &awchar, &asyscr, &asyscw, &aread_bytes, &awrite_bytes, monitor_whole_proc);
			if (ret != 0) {
				DEBUGEXECN(1, PERRORPRINT("Could not get Thread/Proc IO statistics for PID %d Thread %d", pid, tid));
			}
			else {
				pstats->add(gy_diff_counter_safe(aminflt,  minflt), gy_diff_counter_safe(amajflt, majflt), gy_diff_counter_safe(ausertime, usertime), 
						gy_diff_counter_safe(asystime, systime), gy_diff_counter_safe(archar, rchar), gy_diff_counter_safe(awchar, wchar), 
						gy_diff_counter_safe(asyscr, syscr), gy_diff_counter_safe(asyscw, syscw), gy_diff_counter_safe(aread_bytes, read_bytes), 
						gy_diff_counter_safe(awrite_bytes, write_bytes), gy_diff_counter_safe(ablkio_ticks, blkio_ticks),
						vmsize, rss, num_threads);
			}
		}
	}

	void print_current() const noexcept
	{
		pstats->print_current();
	}
};


/*
 * Scope based CPU/IO/Memory printing monitor.
 * At scope exit the process or thread Execution stats and IO stats will be printed.
 *
 * Please ensure pcomment pointer do not go out of scope as it is cached and not copied...
 * Better pass as string literal
 */ 
class CPU_IO_STATS
{
public :	
	MULTI_IO_STATS<false>			iw_io_stats;
	THR_IO_PROFILE<false>			iw_io_class;

	CPU_IO_STATS(const char *pcomment, uint32_t unique_id, bool monitor_whole_proc, pid_t pid = getpid(), pid_t tid = gy_gettid()) noexcept
		: iw_io_stats(pcomment, unique_id, "", 1), iw_io_class(&iw_io_stats, monitor_whole_proc, pid, tid)
	{ }	
};

#ifdef DO_PROFILE

/*
 * Not Multi process safe XXX
 * For those cases, define a custom mmaped object of type MULTI_IO_STATS
 */ 
#define GY_MT_COLLECT_THREAD_IO(_nexec, _comment) 										\
																\
static	gyeeta::MULTI_IO_STATS<true>		GY_CONCATENATE(stats__, __LINE__)(__FUNCTION__, __LINE__, _comment, (_nexec));	\
gyeeta::THR_IO_PROFILE<true>			GY_CONCATENATE(obj__, __LINE__)(&GY_CONCATENATE(stats__, __LINE__));
						
/*
 * Single thread safe multi execution profiler
 */ 
#define GY_NOMT_COLLECT_THREAD_IO(_nexec, _comment)										\
																\
static	gyeeta::MULTI_IO_STATS<false>		GY_CONCATENATE(stats__, __LINE__)(__FUNCTION__, __LINE__, _comment, (_nexec));	\
gyeeta::THR_IO_PROFILE<false>			GY_CONCATENATE(obj__, __LINE__)(&GY_CONCATENATE(stats__, __LINE__));

/*
 * Single execution IO profiler. (No multi exec/threaded)
 */
#define GY_COLLECT_THREAD_IO(_comment)												\
																\
gyeeta::MULTI_IO_STATS<false>			GY_CONCATENATE(stats__, __LINE__)(__FUNCTION__, __LINE__, _comment, 1);		\
gyeeta::THR_IO_PROFILE<false>			GY_CONCATENATE(obj__, __LINE__)(&GY_CONCATENATE(stats__, __LINE__));

#else

#define GY_MT_COLLECT_THREAD_IO(_nexec, _comment) 						
#define GY_NOMT_COLLECT_THREAD_IO(_nexec, _comment) 						
#define GY_COLLECT_THREAD_IO(_comment)		 										

#endif


/*
 * gy_reciprocal_scale - "scale" a value into range [0, ep_ro)
 *
 * This is useful, e.g. for accessing a index of an array containing
 * @ep_ro elements, for example. Think of it as sort of modulus, only that
 * the result isn't that of modulo. ;) Note that if initial input is a
 * small value, then result will return 0.
 *
 * Return: a result based on @val in interval [0, @ep_ro).
 *
 * KV : Lifted from Linux kernel shamelessly : Use for fast Modulo of hashed values
 */
static inline uint32_t gy_reciprocal_scale(uint32_t val, uint32_t ep_ro) noexcept
{
	return (uint32_t)(((uint64_t) val * ep_ro) >> 32);
}

/*
 * thread_local bookkeeping class. Do not use directly as gy_get_thread_local() will invoke this object constructor.
 * No phread_atfork() handlers will be registered for this object and forked child processes must explicitly
 * set the members.
 */ 
class GY_THR_LOCAL
{
public :	
	const uint64_t			thrstartns;
	void				*pstackstart		{nullptr};
	uint32_t			max_stack_sz		{0};
	const pid_t			thrid;
	char				thrname[63];
	bool				is_rcu_thread		{false};
#ifdef DO_PROFILE
	CPU_IO_STATS			thrprofile;
#endif	

	GY_THR_LOCAL() noexcept 
		: thrstartns(get_nsec_clock()), thrid(syscall(SYS_gettid)), is_rcu_thread(false) 
#ifdef DO_PROFILE
		/* Monitor CPU/IO of this thread */
		, thrprofile(GY_SNPRINTF_RET_STR(thrname, sizeof(thrname), "Thread %d", thrid), thrid, false)	
#endif				
	{
#ifndef DO_PROFILE
		snprintf(thrname, sizeof(thrname), "Thread %d", thrid); 
#endif
		int 			ret;
		pthread_attr_t 		attr;

		ret = pthread_getattr_np(pthread_self(), &attr);
		if (ret != 0) {
			DEBUGEXECN(1, PERRORPRINT("Failed to get pthread getattr for thread %d", thrid));

			char			*ptest = (char *)alloca(128);

			max_stack_sz = 32767;
			pstackstart = ptest - max_stack_sz;
			return;
		}	

		size_t 			stack_size, guard_size = 0;
		void 			*pstack_addr;

		pthread_attr_getguardsize(&attr, &guard_size);

		ret = pthread_attr_getstack(&attr, &pstack_addr, &stack_size);
		if (ret != 0) {
			DEBUGEXECN(1, PERRORPRINT("Failed to get pthread stack size for thread %d", thrid));

			char			*ptest = (char *)alloca(128);
			max_stack_sz = 32767;
			pstackstart = ptest - max_stack_sz;
			pthread_attr_destroy(&attr);
			return;
		}
		pstackstart =  (char *)pstack_addr + guard_size;
		max_stack_sz = stack_size - guard_size;	

		DEBUGEXECN(5, INFOPRINT("Initializing new thread_local object for thread TID %d Max Stack Size = %u KB this = %p\n", 
					thrid, GY_DOWN_KB(max_stack_sz), this));
		 
		pthread_attr_destroy(&attr);
	}

	~GY_THR_LOCAL() noexcept	
	{
		DEBUGEXECN(1, 
			uint64_t	tnowns = get_nsec_clock();	

			INFOPRINT("Thread %s : TID %d (%p) exiting now after %lu nsec (%lu sec)\n", 
				thrname, thrid, this, tnowns - thrstartns, (tnowns - thrstartns)/GY_NSEC_PER_SEC); 
		);
	}	

	void set_stack_start(void *paddr) noexcept
	{
		pstackstart = paddr;
	}

	void set_max_stack_size(size_t sz) noexcept
	{
		max_stack_sz = (uint32_t)sz;
	}	

	void set_rcu(bool is_rcu) noexcept
	{
		is_rcu_thread = is_rcu;
	}	

	void set_name(const char *pname, bool set_comm = false) noexcept
	{
		GY_STRNCPY(thrname, pname, sizeof(thrname) - 1);

		if (set_comm) {
			prctl(PR_SET_NAME, (unsigned long)pname);
			DEBUGEXECN(10, INFOPRINTCOLOR(GY_COLOR_GREEN, "Setting thread %d name to %s\n", thrid, pname););
		}	
	}	

	pid_t get_tid() const noexcept
	{
		return thrid;
	}
			
	char * get_name() noexcept
	{
		return thrname;
	}
	
	bool is_rcu() const noexcept	
	{
		return is_rcu_thread;
	}	

	void * get_stack_start() const noexcept
	{
		return pstackstart;
	}	

	size_t get_max_stack_size() const noexcept
	{
		return max_stack_sz;
	}	

	/*
	 * Returns current pthread stack remaining stack usage bytes. 
	 * XXX Will not work if compiled with segmented stacks (-fsplit-stack)
	 */ 
	[[gnu::noinline]] size_t get_thread_stack_freespace() const noexcept
	{
		char			*ptestbuf = (char *)::alloca(128);
		size_t 			sz;
			
		asm ("");

		sz = ptestbuf - (char *)get_stack_start(); // Stack grows downwards

		if (gy_unlikely(sz > max_stack_sz)) {
			if (max_stack_sz > 32767) {
				// Somethings wrong. Just return 20 KB
				
				CONDEXEC(
					DEBUGEXECN(1, 
						ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Thread Stack Freespace calculated %lu is > Max Stack Size %u\n",
							sz, max_stack_sz);
					);
				);	
				return 20 * 1024; 
			}	
		}	

		return sz;
	}	
};	

extern thread_local GY_THR_LOCAL	gthrdata_local_;

#define gy_get_thread_local()		gyeeta::gthrdata_local_


// fork safe gettid()
static inline pid_t gy_gettid() noexcept
{
	extern thread_local pid_t	gtid_local_, gtid_startpid_;

	if (gy_unlikely((gtid_local_ == -1) || (gtid_startpid_ != getpid()))) {
		gtid_local_ 	= syscall(SYS_gettid);
		gtid_startpid_	= getpid();
	}	

	return gtid_local_;
}	

extern void __attribute__((noinline)) 	gy_rcu_offline() noexcept;

/*
 * Safe stack allocs for allocations of upto 512 KB. Such allocations will happen on the stack and valid till scope end.
 * If adequate stack space not available, will return malloc'ed data struct with automatic scope based free 
 * If malloc also fails will throw an exception...
 *
 * A typical usage would be :
 *
 * MY_STRUCT		*pvar; 
 * bool 		is_malloc;
 *
 * SAFE_STACK_ALLOC(pvar, sizeof(MY_STRUCT), is_malloc);
 * new (pvar) MY_STRUCT();
 *
 * On scope exit, no destructor will be called. Users need to manually call placement destructors if needed. 
 *
 * Stack allocations will be used till 16KB free stack space is available to account for further stack allocations.
 *
 * XXX Variable Length Arrays are used for the allocation. Please ensure alloca() is not called within the same scope
 * or the VLA will not be freed on scope exit but on function exit...
 * XXX Will not work if compiled with segmented stacks (-fsplit-stack)
 */ 
#define SAFE_STACK_ALLOC(_poutput_var, _to_alloc_size, _is_malloc)									\
	void			* GY_CONCATENATE(_pmalloc, __LINE__) = nullptr;								\
	size_t			GY_CONCATENATE(vlasz, __LINE__) = 8;									\
	{																\
		size_t			_currstacksz =  gy_get_thread_local().get_thread_stack_freespace();				\
		size_t			_sz = (_to_alloc_size);										\
																	\
		if (gy_unlikely((_currstacksz < _sz + 16 * 1024) || (_sz > 512 * 1024))) {						\
			/* Use malloc instead of VLA */											\
			(_poutput_var) = (decltype(_poutput_var)) malloc_or_throw(_sz);							\
																	\
			GY_CONCATENATE(_pmalloc, __LINE__) = (void *)(_poutput_var);							\
			(_is_malloc) = true;												\
		}															\
		else {															\
			GY_CONCATENATE(vlasz, __LINE__) = _sz; 										\
			(_is_malloc) = false;												\
			(_poutput_var) = nullptr;											\
		}															\
	}																\
	GY_SCOPE_EXIT { 														\
		if (GY_CONCATENATE(_pmalloc, __LINE__)) ::free(GY_CONCATENATE(_pmalloc, __LINE__)); 					\
	};																\
																	\
	alignas(8) uint8_t		GY_CONCATENATE(vlabuf, __LINE__)[GY_CONCATENATE(vlasz, __LINE__)];				\
																	\
	if (!(_is_malloc)) (_poutput_var) = (decltype(_poutput_var))GY_CONCATENATE(vlabuf, __LINE__);					


// Returns bytes written or -1 on error. May return partial writes if non-blocking
static inline ssize_t gy_writebuffer(int fd, const void *buf, size_t buflen) noexcept
{
	const char 		*pbuf = static_cast<const char *>(buf);
	ssize_t			bytes_to_write = buflen, bytes;

	do {
		bytes = ::write(fd, pbuf, bytes_to_write);

		if (bytes > 0) {
			bytes_to_write -= bytes;
			pbuf += bytes;
		}
		else if (bytes == 0) {
			if (bytes_to_write) {
				continue;
			}	
		}	
		else if (errno == EINTR) {
			continue;
		}
		else if (errno == EAGAIN) {
			return buflen - bytes_to_write;
		}	
		else {
			return -1;
		}

	} while (bytes_to_write > 0);

	return buflen;
}

/*
 * Returns bytes read or -1 on error : 
 * Specify is_stream_fd as true as an optimization to avoid an extra read syscall ONLY if fd refers to a 
 * stream socket (TCP/Unix Domain), pipe, or a non-virtual fs, block device supported fd.
 * is_stream_fd must not be set as true for /proc, /sys and other virtual FS backed files, datagram sockets,
 * terminal fd.
 */
static inline ssize_t gy_readbuffer(int fd, void *buf, size_t readlen, bool is_stream_fd = false) noexcept
{
	char 			*pbuf = static_cast<char *>(buf);
	ssize_t			bytes_to_read = readlen, bytes;

	do {
		bytes = ::read(fd, pbuf, bytes_to_read);

		if (bytes > 0) {
			bytes_to_read -= bytes;
			pbuf += bytes;
		}
		else if (bytes == 0) {
			break;
		}	
		else if (errno == EINTR) {
			continue;
		}
		else if (errno == EAGAIN) {
			break;
		}
		else {
			return -1;
		}

	} while (bytes_to_read > 0 && ((false == is_stream_fd) || (bytes > 0)));

	return readlen - bytes_to_read;
}

// Returns bytes read or -1 on error. May return partial reads if non-blocking and offset from which to next try again will be 
// updated in poff_pending if specified
static inline ssize_t gy_preadbuffer(int fd, void *buf, size_t readlen, off_t offset, off_t *poff_pending = nullptr) noexcept
{
	char 			*pbuf = static_cast<char *>(buf);
	ssize_t			bytes_to_read = readlen, bytes;

	do {
		bytes = ::pread(fd, pbuf, bytes_to_read, offset);

		if (bytes > 0) {
			bytes_to_read -= bytes;
			pbuf += bytes;
			offset += bytes;
		}
		else if (bytes == 0) {
			break;
		}	
		else if (errno == EINTR) {
			continue;
		}
		else if (errno == EAGAIN) {
			if (poff_pending) {
				*poff_pending = offset;
			}	

			break;
		}
		else {
			return -1;
		}

	} while (bytes_to_read > 0);

	return readlen - bytes_to_read;
}

// Returns bytes written or -1 on error. May return partial writes if non-blocking and offset from which to next try again will be 
// updated in poff_pending if specified
static inline ssize_t gy_pwritebuffer(int fd, const void *buf, size_t buflen, off_t offset, off_t *poff_pending = nullptr) noexcept
{
	const char 		*pbuf = static_cast<const char *>(buf);
	ssize_t			bytes_to_write = buflen, bytes;

	do {
		bytes = ::pwrite(fd, pbuf, bytes_to_write, offset);

		if (bytes > 0) {
			bytes_to_write -= bytes;
			pbuf += bytes;
			offset += bytes;
		}
		else if (bytes == 0) {
			if (bytes_to_write) {
				continue;
			}	
		}	
		else if (errno == EINTR) {
			continue;
		}
		else if (errno == EAGAIN) {
			if (poff_pending) {
				*poff_pending = offset;
			}	
			return buflen - bytes_to_write;
		}	
		else {
			return -1;
		}

	} while (bytes_to_write > 0);

	return buflen;
}

/*
 * Returns bytes written on success and -1 on error. Pass the piov_pending ONLY if the fd is non-blocking.
 * Only upto 64 iovec supported. If iovcnt > 64 will return -1
 * 
 * For non-blocking fds, if EAGAIN encountered, will return the pending iovec in piov_pending and pbytes_pending if they are specified and -1 otherwise. 
 * The piov_pending must be the same size of piovin.
 * The piov_pending and piovin may refer to the same pointer if piovin can be modified. 
 * The piov_pending will contain the same number of buffers as piovin buf the iov_len for the completed buffers will be set to 0.
 * is_stream_socket is used only if piov_pending i.e. fdw is nonblocking and a socket
 *
 * If pbase_const_arr is specified and pbase_const_arr[i] == true, in case of EAGAIN (partial writes) within a single iovec [i], 
 * the pending bytes for that buffer will be memmove'd to preserve the iov_base in piov_pending
 */
static ssize_t gy_writev(int fdw, const struct iovec *piovin, int iovcnt, struct iovec *piov_pending = nullptr, size_t *pbytes_pending = nullptr, bool is_stream_socket = false, bool *pbase_const_arr = nullptr) noexcept
{
	ssize_t			written = 0, totallen = 0, twritten = 0;
	int			cur = 0, nrecs = iovcnt;
	struct iovec		*piov, iovarr[64 + 1];
	
	if (gy_likely((unsigned)nrecs < GY_ARRAY_SIZE(iovarr))) {
		piov = iovarr;
	}	
	else {
		// Maximum upto 64 iovec allowed
		assert(false);

		errno = EINVAL;
		return -1;
	}	
	
	std::memcpy(piov, piovin, nrecs * sizeof(*piovin));

	for (int i = 0; i < iovcnt; i++) {
		totallen += piov[i].iov_len;
	}	
	
	if (gy_unlikely(totallen == 0)) {
		if (pbytes_pending) {
			*pbytes_pending = 0;
		}
		return 0;
	}	

	while (1) {
		written = ::writev(fdw, piov + cur, nrecs - cur);

		if (written > 0) {
			twritten += written;

			if (twritten >= totallen) {
				break;
			}

			while ((uint64_t)written >= (uint64_t)piov[cur].iov_len) {
				written -= piov[cur++].iov_len;
			}

			if (gy_unlikely(cur >= nrecs)) {
				twritten = totallen;
				break;
			}

			piov[cur].iov_len -= written;

			if (piov_pending && pbytes_pending) {
				if (written > 0) { 

					// Current buffer partially written. Check if iov_base can be modified
					if (pbase_const_arr && pbase_const_arr[cur] == true) {
						std::memmove(piov[cur].iov_base, (char *)piov[cur].iov_base + written, piov[cur].iov_len);
					}
					else {
						piov[cur].iov_base = (char *)piov[cur].iov_base + written;
					}
				}

				if (is_stream_socket) { 
					/*
					 * Assumes we did get an EINTR whilst the writev syscall was ongoing resulting in a lesser 
					 * number of bytes but not -1. 
					 * Set is_stream_socket to false if you need to confirm using EAGAIN that the data transfer
					 * was not interrupted at the cost of an additional writev syscall.
					 */
					goto handle_eagain;
				}	
			}
			else {
				piov[cur].iov_base = (char *)piov[cur].iov_base + written;
			}	

			continue;
		}
		else if (written < 0) {
			if (errno == EINTR) {
				continue;
			}
			else if (errno == EAGAIN) {
				if (piov_pending && pbytes_pending) {

handle_eagain :				
					*pbytes_pending = totallen - twritten;

					std::memcpy(piov_pending, piov, nrecs * sizeof(*piov));
					for (int i = 0; i < cur; ++i) {
						piov_pending[i].iov_len = 0;
					}	
	
					return twritten;
				}	
			}	

			return -1;
		}
	}

	return twritten > 0 ? twritten : -1;	
}

/*
 * Returns bytes written on success and -1 on error. Pass the piov_pending ONLY if the fd is non-blocking.
 * Only upto 64 iovec supported. If iovcnt > 64 will return -1
 *
 * For non-blocking fds, if EAGAIN encountered, will return the pending iovec in piov_pending and pbytes_pending and poff_pending if they are specified and -1 otherwise. 
 * The piov_pending array must be the same size of piovin
 * The piov_pending and piovin may refer to the same pointer if piovin can be modified. 
 */
static ssize_t gy_pwritev(int fdw, const struct iovec *piovin, int iovcnt, off_t offset, struct iovec *piov_pending = nullptr, size_t *pbytes_pending = nullptr, off_t * poff_pending = nullptr) noexcept
{
	ssize_t			written = 0, totallen = 0, twritten = 0;
	int			cur = 0, nrecs = iovcnt;
	struct iovec		*piov, iovarr[64 + 1];
	
	if (gy_likely((unsigned)nrecs < GY_ARRAY_SIZE(iovarr))) {
		piov = iovarr;
	}	
	else {
		// Maximum upto 64 iovec allowed
		assert(false);

		errno = EINVAL;
		return -1;
	}	

	std::memcpy(piov, piovin, nrecs * sizeof(*piovin));

	for (int i = 0; i < iovcnt; i++) {
		totallen += piov[i].iov_len;
	}	
	
	if (gy_unlikely(totallen == 0)) {
		if (pbytes_pending) {
			*pbytes_pending = 0;
		}
		return 0;
	}	

	while (1) {
		written = ::pwritev(fdw, piov + cur, nrecs - cur, offset);

		if (written > 0) {
			twritten += written;
			offset += written;

			if (twritten >= totallen) {
				break;
			}

			while ((uint64_t)written >= (uint64_t)piov[cur].iov_len) {
				written -= piov[cur++].iov_len;
			}

			if (gy_unlikely(cur >= nrecs)) {
				twritten = totallen;
				break;
			}

			piov[cur].iov_base = (char *)piov[cur].iov_base + written;
			piov[cur].iov_len -= written;

			continue;
		}
		else if (written < 0) {
			if (errno == EINTR) {
				continue;
			}
			else if (errno == EAGAIN) {
				if (piov_pending && pbytes_pending && poff_pending) {

					std::memcpy(piov_pending, piov, nrecs * sizeof(*piov));
					for (int i = 0; i < cur; ++i) {
						piov_pending[i].iov_len = 0;
					}	

					*poff_pending 	= offset;
					*pbytes_pending = totallen - twritten;

					return twritten;
				}	
			}	

			return -1;
		}
	}

	return twritten > 0 ? twritten : -1;	
}

static inline size_t iovec_bytes(const struct iovec *piov, int iovcnt) noexcept
{
	ssize_t			totallen = 0;

	for (int i = 0; i < iovcnt; i++) {
		totallen += piov[i].iov_len;
	}	
	
	return totallen;
}	

/*
 * The input iovec array piov must be initialized with iov_base and max allowed iov_len before calling this function. 
 * The iov_len will be updated as per the copy on returning from this function.
 */
static void copy_buf_to_iovec(const uint8_t * const pbuf, size_t bufsz, struct iovec *piov, const int niovin, int & niovout, size_t & bytes_copied, size_t & pending_bytes) noexcept
{
	const uint8_t		*ptmp = pbuf;
	ssize_t			npending = bufsz, ncopy;
	int			niov = 0;

	assert(pbuf && piov);

	while (npending > 0 && niov < niovin) {
		if (gy_unlikely(nullptr == piov[niov].iov_base)) {
			break;
		}

		ncopy = std::min(npending, (ssize_t)piov[niov].iov_len);

		std::memcpy(piov[niov].iov_base, ptmp, ncopy);
		piov[niov].iov_len = (int)ncopy;
		
		niov++;
		npending -= ncopy;
		ptmp += ncopy;
	}

	niovout 	= niov;
	bytes_copied 	= bufsz - npending;
	pending_bytes	= npending;
}	

static void copy_iovec_to_buf(const struct iovec * const piov, const int niovin, uint8_t * const pbuf, size_t bufsz, size_t & bytes_copied, size_t & pending_bytes) noexcept
{
	uint8_t			*ptmp = pbuf;
	ssize_t			navail = bufsz, ncopy, ncopied = 0;
	int			niov = 0, bytes_left = 0;

	assert(pbuf && piov);

	while (navail > 0 && niov < niovin) {
		if (gy_unlikely(nullptr == piov[niov].iov_base)) {
			break;
		}

		ncopy = std::min(navail, (ssize_t)piov[niov].iov_len);

		bytes_left = piov[niov].iov_len - (int)ncopy;

		std::memcpy(ptmp, piov[niov].iov_base, ncopy);

		niov++;
		navail -= ncopy;
		ptmp += ncopy;
	}

	for (int i = niov; i < niovin; ++i) {

		if (gy_unlikely(nullptr == piov[i].iov_base)) {
			break;
		}
		bytes_left += piov[i].iov_len;
	}	

	bytes_copied 	= bufsz - navail;
	pending_bytes	= bytes_left;
}	

static size_t gy_fwrite_iov(FILE *pfile, const struct iovec *piov, int niov, size_t *pbytes_pending = nullptr) noexcept
{
	SCOPE_LOCK_FILE			slock(pfile);

	size_t				twr = 0, nwr;	

	if (pbytes_pending) {
		*pbytes_pending = 0;
	}

	for (int i = 0; i < niov; ++i) {
		if (piov[i].iov_len > 0) {
			nwr = fwrite_unlocked(piov[i].iov_base, 1, piov[i].iov_len, pfile);

			if (nwr != piov[i].iov_len) {
				if (nwr > 0) {
					twr += nwr;
				}	

				if (pbytes_pending) {
					*pbytes_pending = iovec_bytes(piov, niov) - twr;
				}	

				break;
			}	
			else {
				twr += nwr;
			}	
		}
	}	

	return twr;
}	

/*
 * fprintf style prints to a file descriptor/socket
 * If the size of the message is > 2 KB, then if is_non_block is specified, the message is truncated to 2 KB, else
 * if is_non_block is false, then we first try using alloca and then heap allocation to store the message.
 */ 
[[gnu::format (printf, 3, 4)]] 
static int gy_fdprintf(int ofd, bool is_non_block, const char *format, ...) noexcept
{
	char 			wrbuf[2048], *pwrbuf = wrbuf;				
	int			retc, retw, ret, ismal = 0;				
	va_list 		va, vacopy;
										
	va_start(va, format);
	va_copy(vacopy, va);
	retc = vsnprintf(wrbuf, sizeof(wrbuf) - 1, format, va);
	va_end(va);
								
	if (retc > 0 && (uint32_t)retc >= sizeof(wrbuf) - 1) {
		if (!is_non_block) {
			GY_CC_BARRIER();

			size_t		currstacksz =  gy_get_thread_local().get_thread_stack_freespace();

			if (retc < 48 * 1024 && (uint32_t)retc + 16 * 1024 < currstacksz) {
				pwrbuf = (char *)alloca(retc + 8);			
			}							
			else {			
				pwrbuf = new (std::nothrow) char[retc + 8];
				ismal = 1;				
			}				

			if (!pwrbuf) {	
				ismal = 0;					
				pwrbuf = wrbuf; 
				retc = sizeof(wrbuf) - 1;
			}						
			else {							
				(void)vsnprintf(pwrbuf, retc + 1, format, vacopy);
			}						
		}
		else {
			// Truncate
			retc = sizeof(wrbuf) - 1;
		}	
	}						
	else if (retc < 0) {
		va_end(vacopy);
		return retc;
	}	
											
	va_end(vacopy);

	ret = gy_writebuffer(ofd, pwrbuf, retc);				
											
	if (gy_unlikely(ismal == 1)) { 							
		int olderrno = errno; 
		delete [] pwrbuf; 
		errno = olderrno;		
	}											
	return ret;									
}	


/*
 * Set up predefined signal handlers : SIGSEGV, SIGBUS, SIGILL, SIGQUIT, SIGFPE and SIGINT, SIGTERM, SIGUSR2 and some others. 
 * NOTE, SIGHUP is not ignored by default. Users can call the ignore_signal(SIGHUP) method if needed.
 * SIGUSR2 empty signal hanlder is automatically installed so that threads can be interrupted using SIGUSR2.
 * By default SIGUSR1 will be ignored.
 *
 * 2 sets of default handlers will be installed :
 *
 * The set of SIGINT, SIGTERM, SIGXFSZ, SIGXCPU signals will use the GY_SIGNAL_HANDLER::gsighdlr() as handler as default.
 * These signals are non-fatal signals which can be safely caught.
 *
 * The set of SIGSEGV, SIGBUS, SIGILL, SIGQUIT, SIGFPE will use the GY_SIGNAL_HANDLER::gsigseg_hdlr() handler as default
 * These are fatal signals which will abort the process if encountered.
 *
 * By default, both these sets of handlers will only execute for the first signal received. Call enable_further_signals()
 * to enable the signal handler to execute for later signals (only applicable for the SIGINT category signals.) 
 */
class GY_SIGNAL_HANDLER 
{
public :	
	char			nameproc[128]		{};
	bool			use_altstack		{false};
	bool			exit_on_signals		{false};

	SA_SIGACTION_HDLR	psigint			{nullptr};
	SA_SIGACTION_HDLR	psigsegv		{nullptr};

	SIGNAL_CALLBACK_HDLR	psignal_callback	{nullptr};

	stack_t			stack1			{};
	pid_t			init_pid		{0}; 
	bool			enable_more_sigints	{false};

	static constexpr int	MAX_STACK_FRAMES 	{32};
	
	static void 		gsighdlr(int, siginfo_t *, void *);
	static void 		gsigseg_hdlr(int, siginfo_t *, void *);

	static void		gempty_sighdlr(int, siginfo_t *, void *) noexcept
	{}	
	
	GY_SIGNAL_HANDLER() 	= delete;
	
	/* 
	 * pnameproc 		=> Name of process string for printing 
	 * signal_callback	=> Specify a non-null callback in case you need a callback on the handled signals
	 * to_exit_on_signals	=> Specify if signal_callback non-null. In case false, the signal handler will return without exiting only for SIGINT. Its the
	 * 			   responsibility of user to subsequently cleanup and then exit. In case of SIGSEGV type signals, the signal handler
	 * 			   will itself abort() after calling signal_callback().
	 * sigint_hdlr		=> Specify non-null in case custom signal handler for SIGINT, SIGTERM, SIGXFSZ and SIGXCPU needed.
	 * sigsegv_hdlr		=> Specify non-null in case custom signal handler for SIGSEGV, SIGBUS, SIGILL, SIGFPE and SIGQUIT needed.				
	 *
	 * NOTE : The SIGINT default handler will exit the process by calling _exit() while the SIGSEGV default handler will abort().
	 */ 					
	GY_SIGNAL_HANDLER(const char *pnameproc, SIGNAL_CALLBACK_HDLR signal_callback = nullptr, bool to_exit_on_signals = true, bool use_altstack = true, SA_SIGACTION_HDLR sigint_hdlr = gsighdlr, SA_SIGACTION_HDLR sigsegv_hdlr = gsigseg_hdlr) noexcept : 
		use_altstack(use_altstack), exit_on_signals(to_exit_on_signals), psigint(sigint_hdlr ? sigint_hdlr : gsighdlr), psigsegv(sigsegv_hdlr ? sigsegv_hdlr : gsigseg_hdlr), 
		psignal_callback(signal_callback), init_pid(getpid())
	{
		if (pnameproc) {
			GY_STRNCPY(nameproc, pnameproc, sizeof(nameproc) - 1);
		}
		else {
			GY_STRNCPY(nameproc, "Program", sizeof(nameproc) - 1);	
		}		

		if (use_altstack) {
			stack1.ss_sp = malloc(SIGSTKSZ);
			stack1.ss_size = SIGSTKSZ;
			stack1.ss_flags = 0;

			if (::sigaltstack(&stack1, nullptr)) {
				use_altstack = false;
			}
		}	
		else {
			memset(&stack1, 0, sizeof(stack1));
		}	

		set_predefined_signal_handlers();
	}		

	~GY_SIGNAL_HANDLER() noexcept
	{
		if ((stack1.ss_size == (size_t)SIGSTKSZ) && stack1.ss_sp) {
			free(stack1.ss_sp);
		}	
	}
		
	int set_predefined_signal_handlers() noexcept
	{
		struct sigaction 	sa, sa2;
		int			ret;

		sa.sa_sigaction = psigint;

		::sigemptyset (&sa.sa_mask);
		sa.sa_flags = SA_RESTART | SA_SIGINFO;

		::sigaction(SIGINT, &sa, nullptr);
		::sigaction(SIGTERM, &sa, nullptr);
		::sigaction(SIGXFSZ, &sa, nullptr);
		::sigaction(SIGXCPU, &sa, nullptr);

		if (use_altstack && stack1.ss_sp) {
			::sigaltstack(&stack1, nullptr);
			sa.sa_flags |= SA_ONSTACK;
		}

		sa.sa_sigaction = psigsegv;

		::sigaction(SIGSEGV, &sa, nullptr); 
		::sigaction(SIGBUS, &sa, nullptr); 
		::sigaction(SIGILL, &sa, nullptr); 
		::sigaction(SIGQUIT, &sa, nullptr); 
		ret = ::sigaction(SIGFPE, &sa, nullptr); 
	
		::sigemptyset (&sa2.sa_mask);
		sa2.sa_flags = SA_SIGINFO;
		sa2.sa_sigaction = gempty_sighdlr;
		::sigaction(SIGUSR2, &sa2, nullptr);

		::signal(SIGPIPE, SIG_IGN);
		::signal(SIGUSR1, SIG_IGN);
#ifdef SIGTTOU
		::signal(SIGTTOU, SIG_IGN);
		::signal(SIGTTIN, SIG_IGN);
		::signal(SIGTSTP, SIG_IGN);
#endif
		return ret;
	}	

		
	int set_signal_handler(int signo, SA_SIGACTION_HDLR handler, bool use_restart = true) noexcept 
	{
		struct sigaction 	sa;
		int			ret;

		sa.sa_sigaction = handler;

		::sigemptyset (&sa.sa_mask);
		sa.sa_flags = (use_restart ? SA_RESTART : 0) | SA_SIGINFO;

		switch (signo) {
			case SIGSEGV :
			case SIGBUS :
			case SIGILL :
			case SIGQUIT :
			case SIGFPE :

				if (use_altstack && stack1.ss_sp) {
					::sigaltstack(&stack1, nullptr);
					sa.sa_flags |= SA_ONSTACK;
				}
				break;

			default :
				break;	
		}

		ret = ::sigaction(signo, &sa, nullptr);

		return ret;
	}	

	static SA_SIGACTION_HDLR	get_current_handler(int signo) noexcept
	{
		struct sigaction 	sa;

		::sigaction(signo, nullptr, &sa);

		return sa.sa_sigaction;
	}
			
	void set_default_handler(int signo) noexcept
	{
		::signal(signo, SIG_DFL);
	}
		
	void ignore_signal(int signo) noexcept
	{
		::signal(signo, SIG_IGN);
	}

	void enable_further_signals() noexcept
	{
		enable_more_sigints = true;
	}
		
	/*
	 * Use set_signal_param() to set new name for nameproc and add signal handler callbacks.
	 *
	 * Set to_exit_on_signals to false in case you do not need the SIGINT handler to exit or abort respectively. 
	 * Currently SIGSEGV handler will always abort and exit irrespective if the to_exit_on_signals.
	 * In case the to_exit_on_signals is false, exit/abort is the user's responsibility and the signal handlers will print the signal messages
	 * and return. You may need to set alarm(5) in the callback so that the process exits after 5 sec in case of a 
	 * deadlock
	 */ 
	void set_signal_param(const char *pnameprocin, SIGNAL_CALLBACK_HDLR psignal_callbackin = nullptr, bool to_exit_on_signals = true) noexcept
	{
		if (pnameprocin && *pnameprocin) {
			GY_STRNCPY(nameproc, pnameprocin, sizeof(nameproc) - 1);
		}

		GY_WRITE_ONCE(psignal_callback,	psignal_callbackin);

		init_pid		= getpid();

		if (psignal_callbackin) {
			exit_on_signals = to_exit_on_signals;
		}	
		else {
			exit_on_signals = true;
		}	
	}	

	bool validate_pid() noexcept
	{
		if (init_pid == getpid()) {
			return true;	
		}	 	

		set_signal_param("Program", nullptr);
		return false;
	}		

	const char * get_name_proc() noexcept
	{
		validate_pid();
		return (const char *)this->nameproc;
	}	

	int call_signal_callback(int signo) noexcept
	{
		auto pcb = GY_READ_ONCE(psignal_callback);

		if (pcb) {
			try {
				return (*pcb)(signo);
			}
			catch(...) {
			}		
		}
		
		return 0;	
	}	

	static constexpr bool is_signal_fatal(int signo) noexcept
	{
		switch (signo) {
			case SIGSEGV :
			case SIGBUS :
			case SIGILL :
			case SIGQUIT :
			case SIGFPE :
				return true;

			default :
				return false;	
		}	
	}	

	static int 				init_singleton(const char *pnameproc = "Program", SIGNAL_CALLBACK_HDLR signal_callback = nullptr, \
							bool to_exit_on_signals = true, bool use_altstack = true, \
							SA_SIGACTION_HDLR sigint_hdlr = gsighdlr, SA_SIGACTION_HDLR sigsegv_hdlr = gsigseg_hdlr);

	static GY_SIGNAL_HANDLER *		get_singleton() noexcept;
};	


/*
 * Callback wrappers to use for pthread thread creation callbacks.
 *
 * Use the macros MAKE_CLASS_FUNC_WRAPPER_WITH_ARG to define a pthread callback to call a class member with an argument.
 *
 * Use MAKE_CLASS_FUNC_WRAPPER_NO_ARG to define a pthread callback for a class member with no argument. 
 *
 * Use MAKE_PTHREAD_FUNC_WRAPPER to define a normal callback wrapper for an already pthread callback compliant function.
 *
 * These wrappers call the thread specific gy_get_thread_local() to allocate the thread local init methods and also
 * provide a thread specific uncaught exception protection.
 *
 * For the class declaration, use the macros as shown below :
 *
class RESP_THR_C
{
	ebpf::BPFPerfBuffer		*pipv4_perf_buffer;
	ebpf::BPFPerfBuffer		*pipv6_perf_buffer;

public :
	RESP_THR_C() : pipv4_perf_buffer(nullptr), pipv6_perf_buffer(nullptr) {}
	
	void *ipv4_resp_thr(void *parg);
	void *ipv6_resp_thr(void *parg);
	void *debug_thread();

	MAKE_CLASS_FUNC_WRAPPER_WITH_ARG(RESP_THR_C, ipv4_resp_thr);
	MAKE_CLASS_FUNC_WRAPPER_WITH_ARG(RESP_THR_C, ipv6_resp_thr);

	MAKE_CLASS_FUNC_WRAPPER_NO_ARG(RESP_THR_C, debug_thread);
};	


Then, when the gy_create_thread() or pthread_create() is to be called, use as below. respthr is the class object...

RESP_THR_C		respthr;		
pthread_t		thrid4;

ret = gy_create_thread(&thrid4, RESP_THR_C::GET_PTHREAD_WRAPPER(ipv4_resp_thr), alloc_thread_args(&respthr, (void *)"ipv4_xmit_perf")); 
if (ret) {
	PERRORPRINT("Could not create IPv4 handling thread");
	return -1;
}	

 * 
 * The alloc_thread_args() will create a std::pair of the class object and the argument to the class member.
 * It should be used for the MAKE_CLASS_FUNC_WRAPPER_WITH_ARG only. 
 *
 * For the MAKE_CLASS_FUNC_WRAPPER_NO_ARG, use as :
 *
pthread_t		thrid6;

ret = gy_create_thread(&thrid6, RESP_THR_C::GET_PTHREAD_WRAPPER(debug_thread), &respthr); 
if (ret) {
	PERRORPRINT("Could not create debug handling thread");
	return -1;
}	

 * The MAKE* macros will create a static class member function of the name wrapper_<member_function>() 
 *
 */ 

#define MAKE_CLASS_FUNC_WRAPPER_NO_ARG(_class, _callback)						\
static void * wrapper_##_callback(void *arg)								\
{													\
	_class		*pclass = static_cast<_class *>(arg);						\
													\
	gy_get_thread_local().set_name(#_callback);							\
													\
	try {												\
		return (void *)(uintptr_t)pclass->_callback();						\
	}												\
	catch (abi::__forced_unwind&) {									\
		INFOPRINT("Forced exception probably due to thread cancellation "			\
			"seen in thread %d (%s) Thread exiting...\n\n", 				\
				gy_get_thread_local().get_tid(), 					\
				gy_get_thread_local().get_name());					\
		throw;											\
	}												\
	GY_CATCH_EXCEPTION(										\
		ERRORPRINT("Uncaught Exception seen in thread %d (%s) Thread exiting... : %s\n\n", 	\
				gy_get_thread_local().get_tid(), 					\
				gy_get_thread_local().get_name(), 					\
				GY_GET_EXCEPT_STRING);							\
		return nullptr;										\
	);	 											\
}		

/*
 * See comment above. The arg is created in a std::pair object
 */ 
#define MAKE_CLASS_FUNC_WRAPPER_WITH_ARG(_class, _callback)						\
static void * wrapper_##_callback(void *arg)								\
{													\
	std::pair<_class *, void *>	*p = reinterpret_cast<decltype(p)>(arg);			\
													\
	if (p) {											\
		_class			*pclass = p->first;						\
		void 			*parg = p->second;						\
													\
		gy_get_thread_local().set_name(#_callback);						\
													\
		try {											\
			delete p;									\
													\
			return (void *)(uintptr_t)pclass->_callback(parg);				\
		}											\
		catch (abi::__forced_unwind&) {								\
			INFOPRINT("Forced exception probably due to thread cancellation "		\
				"seen in thread %d (%s) Thread exiting...\n\n", 			\
					gy_get_thread_local().get_tid(), 				\
					gy_get_thread_local().get_name());				\
			throw;										\
		}											\
		GY_CATCH_EXCEPTION(									\
			ERRORPRINT("Uncaught Exception seen in thread %d (%s) Thread exiting : %s\n\n",	\
				gy_get_thread_local().get_tid(), 					\
				gy_get_thread_local().get_name(), GY_GET_EXCEPT_STRING);		\
			return nullptr;									\
		);	 										\
	}												\
	return nullptr;											\
}

#define MAKE_PTHREAD_FUNC_WRAPPER(_callback)								\
static void * wrapper_##_callback(void *arg)								\
{													\
	gy_get_thread_local().set_name(#_callback);							\
													\
	try {												\
		return (void *)(uintptr_t)_callback(arg);						\
	}												\
	catch (abi::__forced_unwind&) {									\
		INFOPRINT("Forced exception probably due to thread cancellation "			\
			"seen in thread %d (%s) Thread exiting...\n\n", 				\
				gy_get_thread_local().get_tid(), 					\
				gy_get_thread_local().get_name());					\
		throw;											\
	}												\
	GY_CATCH_EXCEPTION(										\
		ERRORPRINT("Uncaught Exception seen in thread %d (%s) Thread exiting... : %s\n\n", 	\
				gy_get_thread_local().get_tid(), 					\
				gy_get_thread_local().get_name(), GY_GET_EXCEPT_STRING);		\
		return nullptr;										\
	);	 											\
}		

#define GET_PTHREAD_WRAPPER(_callback)		wrapper_##_callback

/*
 * Define a wrapper within a function to be called from within a pthread function
 *
 * e.g. 
	auto lamthr = [](void *arg) -> void *
	{
		GY_THREAD	*pthr = (GY_THREAD *)arg;
		TLISTEN_HDLR	*pthis = (TLISTEN_HDLR *)pthr->get_opt_arg1();

		MAKE_PTHREAD_WRAP("handle_accept", pthis->handle_accept(pthr));

		return nullptr;
	};

 * lamthr is a lambda used as a pthread callback. pthis->handle_accept() is the class method
 * containing the core logic. The above lambda assumes that GY_THREAD was the class used 
 * and pthis is passed with opt_thread_arg1_ although this is not mandataory and a 
 * simple pthread_craete can be used as well.
 *
 * Use of this wrapper is to catch __forced_unwind and any uncaught exception and set the thread 
 * name for debugging.
 */
#define MAKE_PTHREAD_WRAP(_name, _callback)								\
do {													\
	gy_get_thread_local().set_name(_name);								\
													\
	try {												\
		return (void *)(uintptr_t)_callback;							\
	}												\
	catch (abi::__forced_unwind&) {									\
		INFOPRINT("Forced exception probably due to thread cancellation "			\
			"seen in thread %d (%s) Thread exiting...\n\n", 				\
				gy_get_thread_local().get_tid(), 					\
				gy_get_thread_local().get_name());					\
		throw;											\
	}												\
	GY_CATCH_EXCEPTION(										\
		ERRORPRINT("Uncaught Exception seen in thread %d (%s) Thread exiting... : %s\n\n", 	\
				gy_get_thread_local().get_tid(), 					\
				gy_get_thread_local().get_name(), GY_GET_EXCEPT_STRING);		\
		return nullptr;										\
	);	 											\
} while (0)		


typedef void * (* PTHREAD_FUNC_PTR) (void *);

template <typename T>
std::pair<T *, void *> * alloc_thread_args(T *pclass, void *parg)
{
	return new (std::nothrow) std::pair<T *, void *>(pclass, parg);
}
	
/*
 * Create a pthread with default 128 KB stack and joinable state
 * Returns 0 on success -1 on error with errno set 
 */ 
static int gy_create_thread(pthread_t *pthrid, void *(*pstartroutine) (void *), void *parg = nullptr, size_t stacksz = 128 * 1024, bool is_joinable = true) noexcept
{
	pthread_attr_t 		th_attr;
	int			ret, olderr = 0, detachstate = is_joinable ? PTHREAD_CREATE_JOINABLE : PTHREAD_CREATE_DETACHED;

	pthread_attr_init(&th_attr); 

	pthread_attr_setstacksize(&th_attr, stacksz); 
	pthread_attr_setdetachstate(&th_attr, detachstate);	

	if ((ret = pthread_create(pthrid, &th_attr, pstartroutine, parg))) {
		olderr = ret;
		ret = -1;
	}

	pthread_attr_destroy(&th_attr);

	if (olderr) {
		errno = olderr;
	}
		
	return ret;
}

/*
 * Create a pthread with thread attributes as per pattr
 * Returns0 on success  -1 on error with errno set
 */
static int gy_create_thread_from_attr(pthread_t *pthrid, pthread_attr_t *pattr, void *(*pstartroutine) (void *), void *parg = nullptr) noexcept
{
	int			ret;

	assert(pattr);

	if (!pattr) {
		return -1;
	}
		
	if ((ret = pthread_create(pthrid, pattr, pstartroutine, parg))) {
		errno = ret;
		ret = -1;
	}

	return ret;
}

/*
 * pthread_join with options :
 *
 * Specify max_millsecs_to_wait_at_start as > 0 in case the thread has been signalled externally using a shared variable to quit. After
 * max_millsecs_to_wait_at_start timeout, if use_signal_after_timeout is specified, the tid will be pthread_killed using SIGUSR2 and then
 * a blocking pthread_join will be attempted.
 *
 * If wait_indefinitely_if_timeout is false and max_millsecs_to_wait_at_start is non zero, then on pthread timed join timeout,
 * the function returns without using signal as well.
 */ 
static int gy_pthread_join(pthread_t tid, void ** retval, int max_millsecs_to_wait_at_start, bool use_signal_after_timeout, bool wait_indefinitely_if_timeout = true) noexcept 
{
	int			ret;
	struct timespec 	ts;

	if (tid == 0) {
		return -1;
	}

	assert(max_millsecs_to_wait_at_start < 1000 * 100);

	if (max_millsecs_to_wait_at_start > 0) {
		clock_gettime(CLOCK_REALTIME, &ts);

		ts.tv_nsec += max_millsecs_to_wait_at_start * GY_NSEC_PER_MSEC;

		if ((uint64_t)ts.tv_nsec > GY_NSEC_PER_SEC) {
			ts.tv_sec += ts.tv_nsec / GY_NSEC_PER_SEC;
			ts.tv_nsec = ts.tv_nsec % GY_NSEC_PER_SEC;
		}	

		ret = pthread_timedjoin_np(tid, retval, &ts);
		errno = ret;

		if ((ret == 0) || (ret != ETIMEDOUT)) {
			return ret;
		}	
		else if (wait_indefinitely_if_timeout == false) {
			return ret;
		}	
	}

	if (use_signal_after_timeout) {
		if (GY_SIGNAL_HANDLER::gempty_sighdlr == GY_SIGNAL_HANDLER::get_current_handler(SIGUSR2)) {

			DEBUGEXECN(1, 
				INFOPRINT("Signalling thread %d using SIGUSR2 as pthread_join timed out after %d millsec\n", (int)tid, max_millsecs_to_wait_at_start);
			);	
			pthread_kill(tid, SIGUSR2);
		}
		else {
			DEBUGEXECN(1, 
				WARNPRINT("pthread join timed out for thread %d after %d millsec : But not sending SIGUSR2 as custom SIGUSR2 handler is set\n", 
					(int)tid, max_millsecs_to_wait_at_start);
			);	
		}	
	}

	ret = pthread_join(tid, retval);
	errno = ret;

	return ret;
}

class GY_MMAP
{
public :	
	GY_MMAP() noexcept : pmmap(nullptr), mapped_sz(0), use_proc_shared(false) {}

	GY_MMAP(size_t size, bool use_proc_shared) 
		: pmmap(nullptr), mapped_sz(0), use_proc_shared(use_proc_shared) 
	{
		create_mmap(size, use_proc_shared);
	}	

	~GY_MMAP() noexcept
	{
		unmap();
	}

	GY_MMAP(GY_MMAP && other) noexcept 
	{
		pmmap 		= other.pmmap;
		mapped_sz	= other.mapped_sz;
		use_proc_shared	= other.use_proc_shared;

		other.pmmap 	= nullptr;
		other.mapped_sz	= 0;
	}	

	GY_MMAP & operator= (GY_MMAP && other) noexcept
	{
		if (this != &other) {
			this->unmap();

			pmmap 		= other.pmmap;
			mapped_sz	= other.mapped_sz;
			use_proc_shared	= other.use_proc_shared;

			other.pmmap 	= nullptr;
			other.mapped_sz	= 0;
		}
		
		return *this;
	}

	GY_MMAP(const GY_MMAP & other) 				= delete;

	GY_MMAP & operator= (const GY_MMAP & other) 		= delete;

	void * get_map_addr() const noexcept
	{
		return pmmap;
	}
	
	size_t get_mapped_size() const noexcept
	{
		return mapped_sz;
	}

	void create_mmap(size_t size, bool use_proc_sharedin)
	{
		if (gy_unlikely(pmmap)) {
			unmap();
		}
		
		use_proc_shared = use_proc_sharedin;
			
		pmmap = gy_mmap_alloc(size, &mapped_sz, use_proc_shared);
		if (!pmmap) {
			GY_THROW_SYS_EXCEPTION("mmap allocation failed for size %lu", size);
		}	
	}
		
	void unmap() noexcept
	{
		if (pmmap) {
			gy_mmap_free(pmmap, mapped_sz);
			pmmap = nullptr;
		}
	}	
			
	void		*pmmap;
	size_t		mapped_sz;
	bool		use_proc_shared;
};	

static inline char * gy_get_pct_diff_str(int64_t tnew, int64_t told, char bufout[64]) noexcept
{
	int64_t			toldupd = (told ? told : 1);
	
	snprintf(bufout, 64, "%.03f", ((tnew - told) * 100.0f)/toldupd);

	return bufout;
}	

static inline char * gy_get_pct_diff_str(double tnew, double told, char bufout[64]) noexcept
{
	double		toldupd = (told >= 0.00 ? told : 1.0);
	
	snprintf(bufout, 64, "%.03f", ((tnew - told) * 100.0f)/toldupd);

	return bufout;
}	

static char * string_delete_char(char *pinputstr, size_t buflen, char delchar) noexcept
{
	char		*ptmp = pinputstr, *pend = pinputstr + buflen, *porigstart = pinputstr;
	int		nskips = 0;

	assert(pinputstr);

	do {
		ptmp = (char *)memchr(ptmp, delchar, pend - ptmp);
		if (ptmp) {
			memmove(ptmp, ptmp + 1, pend - ptmp - 1);
			ptmp++;
			pend--;
			nskips++;
		}
		else {
			break;
		}
	} while (ptmp + 1 < pend && pend > porigstart);

	if (nskips) {
		*pend = '\0';
	}	

	return porigstart;
}

static char * string_replace_char(char *pinputstr, size_t buflen, char replacec, char replace_with) noexcept
{
	char		*ptmp = pinputstr, *pend = pinputstr + buflen;

	assert(pinputstr);

	do {
		ptmp = (char *)memchr(ptmp, replacec, pend - ptmp);
		if (ptmp) {
			*ptmp = replace_with;
			ptmp++;
		}
		else {
			break;
		}
	} while (ptmp + 1 < pend);

	return pinputstr;
}

// strdup with Exceptions if malloc failed
static char * gy_strdup_safe(const char *pinput, size_t szinput = 0, size_t szmax = 0)
{
	char			*poutput;

	if (szinput == 0) {
		if (szmax == 0) {
			poutput = strdup(pinput);
		}
		else {
			// May truncate UTF8 strings...
			poutput = strndup(pinput, szmax);
		}	

		if (poutput) {
			return poutput;
		}
	}	
	else {
		if (szmax > 0 && szmax < szinput) {
			// May truncate UTF8 strings...
			szinput = szmax;
		}	

		poutput = (char *)::malloc(szinput + 1);

		if (poutput) {
			std::memcpy(poutput, pinput, szinput);
			poutput[szinput] = 0;

			return poutput;
		}
	}	

	throw std::bad_alloc();
}	

static constexpr const char	gy_html_escape_chars[] = {"<>&\"\'"};

static std::string & gy_html_encode(std::string &str)
{
	size_t 			index, i;
	const char		findchars[] = {'&', '"', '\'', '<', '>'};
	const char *		replacestr[] = {"&amp;", "&quot;", "&#39;", "&lt;", "&gt;"};		

	for (i = 0, index = 0; i < sizeof(findchars)/sizeof(*findchars); ++i, index = 0) {
		while ((index = str.find(findchars[i], index)) != std::string::npos) {
			str.replace(index, 1, replacestr[i]);
			index += strlen(replacestr[i]);
		}
	}

	return str;	
}	

static std::string & gy_html_decode(std::string &str)
{
	size_t 			index, i;
	const char *		replacechar[] = {"&", "\"", "'", "<", ">"};
	const char *		findstr[] = {"&amp;", "&quot;", "&#39;", "&lt;", "&gt;"};		

	if ((str == "&nbsp;") || (str == "\xa0" /* 160 */)) {
		str = "";
		return str;
	}
		
	for (i = 0, index = 0; i < sizeof(findstr)/sizeof(*findstr); ++i, index = 0) {
		while ((index = str.find(findstr[i], index)) != std::string::npos) {
			str.replace(index, strlen(findstr[i]), replacechar[i]);
			index += 1;
		}
	}

	return str;	
}	

/*
 * Binary buffer to Hex string. Returns new strlen. Will truncate if szout < 2 * szin + 1
 */
static size_t binary_to_hex_string(const uint8_t * pin, size_t szin, char *pout, size_t szout) noexcept
{
	static constexpr const char 	hex[] = "0123456789abcdef";
	int 				s, d;

	if (szout < 2 * szin + 1) {
		if (szout <= 2) return 0;
		szin = szout / 2 - 1;	
	}	

	for (d = 0, s = 0; (unsigned)d < szin; d++, s += 2) {
		pout[s + 0] 	= 	hex[ (pin[d] >> 4) & 0x0F ];
		pout[s + 1] 	= 	hex[ (pin[d] >> 0) & 0x0F ];
	}

	pout[s] = 0;
	return s;
}

/*
 * Search for whole word. '_' and alphanumeric chars are considered part of the word while finding the whole word
 * Works only on ASCII strings. For UTF8 strings, use the is_whole_word_in_utf8_str()
 */ 
static bool is_whole_word_in_str(const char *pinput, const char *pword, const char **ppwordlocation = nullptr, bool ignore_case = false, size_t leninput = 0, size_t lenword = 0) noexcept
{
	const char		*pstart = pinput, * const porigstart = pstart, *pwordend, *ptmp, *pend;
	char			c1, c2;
	size_t			wordlen, inputlen;
	
	assert(pinput);
	assert(pword);

	if (lenword == 0) {
		wordlen = strlen(pword);	
	}
	else {
		wordlen = lenword;
	}

	pwordend = pword + wordlen;

	if (leninput == 0) {
		inputlen = strlen(pinput);
	}
	else {
		inputlen = leninput;	
	}		
	
	pend = pstart + inputlen;

	const auto iscontchar = [](char c) noexcept -> bool
	{
		if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c == '_')) {
			return true;
		}	

		return false;
	};	

	do {
		if (ignore_case == false) {
			ptmp = (const char *)memmem(pstart, pend - pstart, pword, wordlen);
		}
		else {
			ptmp = strcasestr(pstart, pword);
		}		

		if (!ptmp) {
			return false;
		}	

		if (ptmp > pstart) {
			c1 = *(ptmp - 1);

			if (iscontchar(c1)) {
				pstart = ptmp + wordlen - 1;
				continue;
			}
		}		

		if (ptmp + wordlen < pend) {
			c2 = *(ptmp + wordlen);

			if (iscontchar(c2)) {
				pstart = ptmp + wordlen - 1;
				continue;
			}
		}

		if (ppwordlocation) {
			*ppwordlocation = ptmp;
		}	

		return true;

	} while (pstart + wordlen <= pend && pstart > porigstart);	

	return false;
}	


// Returns pointer to start of suffix substr or nullptr if no substring found : ignore_case will only work on ASCII strings
static char * string_ends_with(const char *pinput, const char *substr, bool ignore_case = false, size_t leninput = 0, size_t lensub = 0) noexcept 
{
	assert(pinput);
	assert(substr);

	if (leninput == 0) {
		leninput = strlen(pinput);
	}
	
	if (lensub == 0) {	
		lensub = strlen(substr);
	}	

	if (lensub == 0) {
		return nullptr;
	}	

	if (leninput < lensub) {
		return nullptr;
	}	

	if (ignore_case == false) {
		if (memcmp(pinput + leninput - lensub, substr, lensub) != 0) {
			return nullptr;
		}
	}
	else {
		if (strcasecmp(pinput + leninput - lensub, substr) != 0) {
			return nullptr;
		}
	}	

	return (char *)pinput + leninput - lensub;
}

// Returns true on match. ignore_case will only work on ASCII strings
static bool string_starts_with(const char *pinput, const char *substr, bool ignore_case = false, size_t lensub = 0) noexcept 
{
	assert(pinput);
	assert(substr);

	if (lensub == 0) {	
		lensub = strlen(substr);
	}	

	if (lensub == 0) {
		return false;
	}	

	if (ignore_case == false) {
		if (memcmp(pinput, substr, lensub) != 0) {
			return false;
		}
	}
	else {
		if (strncasecmp(pinput, substr, lensub) != 0) {
			return false;
		}
	}	

	return true;
}


/*
 * Static Char arr with strlen and optional start offset
 */
template <uint32_t szarr>
class STR_ARRAY
{
	char				arr_[szarr];
public :	
	uint32_t			len_		{0};
	uint32_t			offset_		{0};
	
	static_assert(szarr > 1);

	STR_ARRAY() noexcept 
	{ 
		arr_[0] 		= 0;
	}

	STR_ARRAY(const char *pstr) noexcept
	{
		(void)strset(pstr);
	}

	STR_ARRAY(const char *pstr, uint32_t len) noexcept
	{
		(void)strset(pstr, len);
	}

	~STR_ARRAY() noexcept 		= default;

	STR_ARRAY(const STR_ARRAY & a) noexcept 
		: len_(a.len_), offset_(a.offset_)
	{
		std::memcpy(arr_ + offset_, a.get(), len_);
		arr_[len_ + offset_] = 0;
	}

	STR_ARRAY<szarr> & operator=(const STR_ARRAY & a) noexcept
	{
		if (this != &a) {
			len_ = a.len_;
			offset_ = a.offset_;
			std::memcpy(arr_ + offset_, a.get(), len_);
			arr_[len_ + offset_] = 0;
		}	

		return *this;
	}	

	STR_ARRAY(STR_ARRAY && a) noexcept 
		: len_(a.len_), offset_(a.offset_)
	{
		std::memcpy(arr_ + offset_, a.get(), len_);
		arr_[len_ + offset_] = 0;
	}

	STR_ARRAY<szarr> & operator=(STR_ARRAY && a) noexcept
	{
		if (this != &a) {
			len_ = a.len_;
			offset_ = a.offset_;
			std::memcpy(arr_ + offset_, a.get(), len_);
			arr_[len_ + offset_] = 0;
		}	

		return *this;
	}	

	char *buffer() noexcept
	{
		return arr_ + offset_;
	}	

	const char *buffer() const noexcept
	{
		return arr_ + offset_;
	}	

	char *get() noexcept
	{
		return buffer();
	}	

	const char *get() const noexcept
	{
		return buffer();
	}	

	char *data() noexcept
	{
		return buffer();
	}	

	const char *data() const noexcept
	{
		return buffer();
	}	

	uint32_t length() const noexcept
	{
		return len_;
	}	

	uint32_t size() const noexcept
	{
		return len_;
	}	

	size_t strset(const char *pstr) noexcept
	{
		if (pstr) {
			uint32_t	len = ::strnlen(pstr, szarr - 1);		

			std::memcpy(arr_, pstr, len);

			arr_[len] 	= '\0';
			len_ 		= len;
			offset_		= 0;
		}
		else {
			arr_[0] 	= '\0';
			len_ 		= 0;
			offset_		= 0;
		}

		return len_;
	}

	size_t strset(const char *pstr, uint32_t len) noexcept
	{
		uint32_t		sz = std::min<uint32_t>(szarr - 1, len);

		std::memcpy(arr_, pstr, sz);
		arr_[sz] = 0;

		len_ 		= sz;
		offset_		= 0;
		
		return sz;
	}

	/*
	 * Use this if the arr_ is externally modified first
	 */
	void set_len_offset(size_t len, size_t offset = 0) noexcept
	{
		if (len + offset > maxsz() || std::max(len, offset) > maxsz()) {
			arr_[0]	 	= 0;
			len_ 		= 0;
			offset_ 	= 0;
			return;
		}	

		len_ 			= len;
		offset_ 		= offset;
		arr_[len_ + offset_] 	= 0;
	}	

	void set_len(size_t len) noexcept
	{
		set_len_offset(len, 0);
	}	

	constexpr size_t maxsz() const noexcept
	{
		return szarr - 1;
	}	

	std::string_view get_view() const noexcept
	{
		return std::string_view(get(), length());
	}

	template <uint32_t newsz>
	bool operator== (const STR_ARRAY <newsz> & rhs) const noexcept
	{
		return ((len_ == rhs.len_) && (0 == std::memcmp(get(), rhs.get(), len_)));
	}

	template <uint32_t newsz>
	bool operator< (const STR_ARRAY <newsz> &other) const noexcept
	{
		uint32_t 		maxcmp = (len_ > other.len_ ? other.len_ + 1 : len_ + 1);
		int			cmp = std::memcmp(get(), other.get(), maxcmp);

		return (cmp < 0);
	}

	size_t get_hash() const noexcept
	{
		return gy_cityhash64(get(), length());
	}

	friend std::ostream & operator<< (std::ostream & stream, const STR_ARRAY & str) 
	{
		return stream << str.get_view();
	}
};


template <typename StrClass>
class STR_HASHER 
{
public :
	size_t operator()(const StrClass & k) const noexcept
	{
		return gy_cityhash64((const char*) k.buffer(), k.length());
	}
};

template <typename StrClass>
class STR_EQUAL
{
public :
	bool operator()(const StrClass &arr1, const StrClass &arr2) const noexcept 
	{
		return arr1 == arr2;
	}
};

template <size_t sz_ = 128>
[[gnu::format (printf, 1, 2)]] 
STR_ARRAY<sz_> gy_to_strarray(const char *fmt, ...) noexcept
{
	STR_ARRAY<sz_>		cbuf;
	va_list 		va;
	int			nwr;

	va_start(va, fmt);

	nwr = vsnprintf(cbuf.get(), sz_, fmt, va);

	if (nwr < 0) {
		*(cbuf.get()) = 0;
		nwr = 0;
	}	

	va_end(va);

	cbuf.set_len(std::min<size_t>(nwr, sz_ - 1));

	return cbuf;
}	

template <size_t sz>
class CARRHASH 
{
public :
	size_t operator()(const std::array<char, sz> & k) const noexcept
	{
		return gy_cityhash64((const char*) k.buffer(), strnlen(k.buffer(), sz));
	}
};

template <size_t sz>
class CARR_EQUAL
{
public :
	bool operator()(const std::array<char, sz> &arr1, const std::array<char, sz> &arr2) const noexcept
	{
		return (0 == strncmp(arr1.data(), arr2.data(), sz));
	}
};



/*
 * Stateful string parsing of an already populated string buffer.
 * If case insensitive searches needed, the input string must be a NULL terminated string.
 */ 
class STR_RD_BUF
{
protected :	
	const char 			* const	prdbuf_;
	const char 			* const pendbuf_;
	const char			* pcurrbuf_; 

public :		
	STR_RD_BUF(const char *pbuffer, size_t buf_strlen) noexcept
		: prdbuf_(pbuffer), pendbuf_(prdbuf_ + buf_strlen), pcurrbuf_(pbuffer)
	{
		assert(pbuffer);
	}		

	explicit STR_RD_BUF(const char *pbuffer) noexcept
		: STR_RD_BUF(pbuffer, pbuffer ? strlen(pbuffer) : 0)
	{}	

	/* 
	 * Returns the next line starting from current postion. Number of bytes in line is set in nbytes
	 * Does not include the delim within the nbytes unless ignore_delim_in_nbytes is set to false
	 *
	 * If ignore_empty_lines is true, then all 0 length lines are skipped (consecutive delim skipped) and all leading (initial) empty lines
	 * also skipped. IOW, if ignore_empty_lines == false, 0 length lines will be seen for strings with consecutive delimitters.
	 * Setting ignore_delim_in_nbytes to true and ignore_empty_lines to true, will not work for initial empty lines.
	 *
	 * delim needs to be an ASCII char
	 *
	 * Returns nullptr in case the end of string is reached
	 */ 
	const char * get_next_line(size_t & nbytes, bool ignore_delim_in_nbytes = true, char delim = '\n', bool ignore_empty_lines = false) noexcept
	{
		size_t			nrd = 0;
		char			c;
		const char		*ptmp = pcurrbuf_;

		if (ignore_empty_lines) {
			while (pcurrbuf_ < pendbuf_ && *pcurrbuf_ == delim) {
				pcurrbuf_++;
			}
		}	

		if (gy_unlikely(pcurrbuf_ == pendbuf_)) {
			nbytes = 0;
			return nullptr;
		}	

		while (pcurrbuf_ < pendbuf_) {
			c = *pcurrbuf_++;
			nrd++;

			if (c == delim) {
				if (ignore_delim_in_nbytes) {
					nrd--;
				}	

				if (ignore_empty_lines) {
					while (pcurrbuf_ < pendbuf_ && *pcurrbuf_ == delim) {
						pcurrbuf_++;

						if (!ignore_delim_in_nbytes) {
							nrd++;
						}	
					}	
				}	

				break;
			}	
		}	
		
		nbytes = nrd;
		return ptmp;
	}	

	/*
	 * Get previous line without updating current position. Does not include previous delim in nbytes
 	 * delim needs to be an ASCII char
	 * Returns prev line start with nbytes updated or nullptr if already at start
	 */
	const char * peek_prev_line(size_t & nbytes, char delim = '\n') const noexcept
	{
		size_t			nrd = 0;
		char			c;
		const char		*ptmp = pcurrbuf_ - 1;

		if (gy_unlikely(pcurrbuf_ == prdbuf_)) {
			nbytes = 0;
			return nullptr;
		}	
		
		if (ptmp > prdbuf_ && *ptmp == delim) {
			nrd++;
			ptmp--;
		}	

		while (ptmp >= prdbuf_) {
			c = *ptmp;

			if (c == delim) {
				break;
			}	

			nrd++;
			ptmp--;
		}	
		
		nbytes = nrd;
		return ptmp;
	}	

	/* 
	 * Returns the next word starting from current postion (Will skip leading spaces by default). Number of bytes in line is set in nbytes
	 * Does not include the separators byte within the nbytes unless ignore_separator_in_nbytes is set to false
	 *
	 * If leading spaces present and skip_leading_space is set, will ignore these and nbytes will not include the leading space bytes.
	 *
	 * If ignore_escape is false, then the string will be checked for separators *without* a preceding '\' character
	 *
	 * If skip_multi_separators is true, then all 0 length words are skipped (consecutive separators skipped) and all leading (initial) separators
	 * also skipped. IOW, if skip_multi_separators == false, 0 length words will be seen for strings with consecutive separators if separators
	 * specified are non space chars.
	 * Setting ignore_separator_in_nbytes to false and skip_multi_separators to true, will not work for leading separators.
	 *
	 * The separators characters need to be ASCII chars
	 *
	 * Returns nullptr in case the end of string is reached
	 */ 
	const char * get_next_word(size_t & nbytes, bool ignore_separator_in_nbytes = true, const char *separators = " \t\n\r", bool skip_leading_space = true, \
					bool ignore_escape = true, bool skip_multi_separators = false) noexcept
	{
		size_t			nrd = 0;
		char			c, prevc;
		const char		*ptmp;
		bool			nonspaceseen = false;

		if (skip_leading_space) {
			while ((pcurrbuf_ < pendbuf_) && (strchr(" \t\n\r\f\v", *pcurrbuf_))) {
				pcurrbuf_++;
			}
		}

		if (skip_multi_separators) {
			while (pcurrbuf_ < pendbuf_ && strchr(separators, *pcurrbuf_)) {
				pcurrbuf_++;
			}
		}
	
		if (pcurrbuf_ == pendbuf_) {
			nbytes = 0;
			return nullptr;
		}		

		prevc = '\0';
			
		ptmp = pcurrbuf_;
			
		while (pcurrbuf_ < pendbuf_) {
			c = *pcurrbuf_++;
			nrd++;

			if (strchr(separators, c)) {
				if (ignore_escape || (prevc != '\\')) {
					if (ignore_separator_in_nbytes) {
						nrd--;
					}	

					if (skip_multi_separators) {
						while (pcurrbuf_ < pendbuf_ && strchr(separators, *pcurrbuf_)) {
							pcurrbuf_++;

							if (!ignore_separator_in_nbytes) {
								nrd++;
							}	
						}	
					}	

					break;
				}	
			}	

			prevc = c;
		}	
		
		nbytes = nrd;
		return ptmp;
	}	

	// Skip to delim + 1 char 
	const char * skip_till_next_delim(char delim, bool ignore_escape = true) noexcept
	{
		char			c, prevc = '\0';
		const char		*ptmp = pcurrbuf_;

		if (gy_unlikely(pcurrbuf_ == pendbuf_)) {
			return nullptr;
		}	

		while (pcurrbuf_ < pendbuf_) {
			c = *pcurrbuf_++;

			if (c == delim) {
				if (ignore_escape || (prevc != '\\')) {
					return pcurrbuf_;
				}	
			}	

			prevc = c;
		}	

		return nullptr;
	}
		
	// Skip to delimitter + 1 char
	const char * skip_till_next_delim(const char delimarr[], uint32_t ndelim, bool ignore_escape = true) noexcept
	{
		char			c, prevc = '\0';
		const char		*ptmp = pcurrbuf_;

		if (gy_unlikely(pcurrbuf_ == pendbuf_)) {
			return nullptr;
		}	

		while (pcurrbuf_ < pendbuf_) {
			c = *pcurrbuf_++;

			for (uint32_t i = 0; i < ndelim; ++i) {
				if (c == delimarr[i]) {
					if (ignore_escape || (prevc != '\\')) {
						return pcurrbuf_;
					}	
					break;
				}	
			}

			prevc = c;
		}	

		return nullptr;
	}

	/*
	 * Skips to substring + strlen(substring) 
	 * Will first attempt the check from the current offset and then if chk_from_start == true from the start.
	 *
	 * NOTE : If ignore_case == true, requires that the input string be a NULL terminated one as strcasestr() used.
	 *
	 * Returns nullptr on no match.
	 */
	const char * skip_till_substring(const char *psubstr, bool chk_from_start = true, bool ignore_case = false, bool is_utf8 = false, size_t substrlen = 0) noexcept
	{
		const char		*ptmp;
		const size_t		sublen = (substrlen > 0 ? substrlen : strlen(psubstr));

		if (!ignore_case) {
			ptmp = (const char *)memmem(pcurrbuf_, pendbuf_ - pcurrbuf_, psubstr, sublen);
		}
		else {
			if (false == is_utf8) {
				ptmp = strcasestr(pcurrbuf_, psubstr);
			}
			else {
				ptmp = (const char *)gy_utf8_casestr(pcurrbuf_, psubstr);	
			}		
		}		

		if (!ptmp) {
			if (chk_from_start && pcurrbuf_ > prdbuf_) {
				if (!ignore_case) {
					ptmp = (const char *)memmem(prdbuf_, pendbuf_ - prdbuf_, psubstr, sublen);
				}
				else {
					if (false == is_utf8) {
						ptmp = strcasestr(prdbuf_, psubstr);
					}	
					else {
						ptmp = (const char *)gy_utf8_casestr(prdbuf_, psubstr);	
					}		
				}		
				if (!ptmp) {
					return nullptr;
				}	
			}
			else {	
				return nullptr;
			}	
		}	

		pcurrbuf_ = ptmp + sublen;

		return pcurrbuf_;
	}
	
	/*
	 * Use with string literals
	 * See comments for skip_till_substring() above 
	 */
	template <size_t N>
	const char * skip_till_substring_const(const char (&substr)[N], bool chk_from_start = true, bool ignore_case = false, bool is_utf8 = false) noexcept
	{
		return skip_till_substring(substr, chk_from_start, ignore_case, is_utf8, N - 1);
	}

	template <size_t N>
	const char * skip_till_substring_const(char (&substr)[N], bool chk_from_start = true, bool ignore_case = false, bool is_utf8 = false) 	= delete;

	/*
	 * Skips to pword + strlen(pword) 
	 * Will attempt the check from the start directly if chk_from_start == true
	 *
	 * NOTE : If ignore_case == true, requires that the input string be a NULL terminated one as strcasestr() used.
	 *
	 * Returns nullptr on no match.
	 */
	const char * skip_till_whole_word(const char *pword, bool chk_from_start = true, bool ignore_case = false, bool is_utf8 = false, size_t wordlen = 0) noexcept
	{
		const char		*pstart = (chk_from_start == false ? pcurrbuf_ : prdbuf_), *ptmp = nullptr;
		char			c;
		bool			is_found;
		size_t			szword = (wordlen > 0 ? wordlen : strlen(pword));
	
		if (!ignore_case || (false == is_utf8)) {
			is_found = is_whole_word_in_str(pstart, pword, &ptmp, ignore_case, pendbuf_ - pstart, szword);
		}
		else {
			is_found = is_whole_word_in_utf8_str(pstart, pword, &ptmp, ignore_case, pendbuf_ - pstart, szword);
		}		

		if (is_found == false) {
			return nullptr;
		}	

		pcurrbuf_ = ptmp + szword;

		return pcurrbuf_;
	}

	/*
	 * Use with string literals
	 * See comments for skip_till_whole_word() above 
	 */
	template <size_t N>
	const char * skip_till_whole_word_const(const char (&word)[N], bool chk_from_start = true, bool ignore_case = false, bool is_utf8 = false) noexcept
	{
		return skip_till_whole_word(word, chk_from_start, ignore_case, is_utf8, N - 1);
	}	

	template <size_t N>
	const char * skip_till_whole_word_const(char (&word)[N], bool chk_from_start = true, bool ignore_case = false, bool is_utf8 = false) 	= delete;

	/*
	 * Get the list of words with pointers to each word stored in pstrarr and size in szarr. The pstrarr will not be null terminated words and szarr
	 * must be used to find strlen of each word.
	 *
	 * Returns number of words from start of string if from_start == true or else from current location
	 *
	 * See comments for get_next_word() above. 
	 */
	size_t get_word_list(const char *pstrarr[], size_t szarr[], size_t maxarrlen, bool ignore_separator_in_nbytes = true, const char *separators = " \t\n\r", 
					bool ignore_escape = true, bool skip_multi_separators = false, bool from_start = true) noexcept
	{
		const char			*ptmp, *poldcurr = from_start ? std::exchange(pcurrbuf_, prdbuf_) : pcurrbuf_;
		size_t				nbytes, nwords = 0;
		
		while (nwords < maxarrlen) {
			ptmp = get_next_word(nbytes, ignore_separator_in_nbytes, separators, true, ignore_escape, skip_multi_separators);

			if (!ptmp) {
				break;
			}

			pstrarr[nwords]		= ptmp;
			szarr[nwords]		= nbytes;

			nwords++;
		};

		pcurrbuf_ = poldcurr;

		return nwords;
	}	

	/*
	 * Get the list of lines with pointers to each line stored in pstrarr and size in szarr. The pstrarr will not be null terminated lines and szarr
	 * must be used to find strlen of each line.
	 *
	 * Returns number of words from start of string if from_start == true or else from current location
	 *
	 * See comments for get_next_line() above. 
	 */
	size_t get_line_list(const char *pstrarr[], size_t szarr[], size_t maxarrlen, bool ignore_delim_in_nbytes = true, char delim = '\n', 
					bool ignore_empty_lines = false, bool from_start = true) noexcept
	{
		const char			*ptmp, *poldcurr = from_start ? std::exchange(pcurrbuf_, prdbuf_) : pcurrbuf_;
		size_t				nbytes, nlines = 0;
		
		while (nlines < maxarrlen) {
			ptmp = get_next_line(nbytes, ignore_delim_in_nbytes, delim, ignore_empty_lines);

			if (!ptmp) {
				break;
			}

			pstrarr[nlines]		= ptmp;
			szarr[nlines]		= nbytes;

			nlines++;
		};

		pcurrbuf_ = poldcurr;

		return nlines;
	}	

	// returns number of bytes copied
	size_t peek_next_nchars(char *poutput, size_t bytes_to_copy) const noexcept
	{
		if (gy_unlikely(pcurrbuf_ == pendbuf_)) {
			return 0;
		}	
		
		size_t			nrd = 0;
		const char		*ptmp = pcurrbuf_;

		while ((ptmp < pendbuf_) && (nrd < bytes_to_copy)) {
			poutput[nrd] = *ptmp;
			ptmp++;
			nrd ++;
		}	

		return nrd;
	}	

	// returns number of bytes copied
	size_t peek_prev_nchars(char *poutput, size_t bytes_to_copy) const noexcept
	{
		if (gy_unlikely(pcurrbuf_ == prdbuf_)) {
			return 0;
		}	
		
		size_t			nrd = 0;
		const char		*ptmp = pcurrbuf_ - 1;

		while ((ptmp >= prdbuf_) && (nrd < bytes_to_copy)) {
			poutput[nrd] = *ptmp;
			ptmp--;
			nrd ++;
		}	

		return nrd;
	}	

	const char * operator+= (size_t nbytes) noexcept
	{
		size_t			noff = std::min(nbytes, bytes_left());

		pcurrbuf_ += noff;

		return pcurrbuf_;
	}

	const char * operator++() noexcept
	{
		return this->operator+= (1ul);
	}

	const char * operator++(int) noexcept
	{
		return this->operator+= (1ul);
	}

	const char * operator-= (size_t nbytes) noexcept
	{
		size_t			noff = std::min(nbytes, curr_offset());

		pcurrbuf_ -= noff;

		return pcurrbuf_;
	}

	const char * operator--() noexcept
	{
		return this->operator-= (1ul);
	}

	const char * operator--(int) noexcept
	{
		return this->operator-= (1ul);
	}

	size_t bytes_left() const noexcept
	{
		return pendbuf_ - pcurrbuf_;
	}	

	size_t curr_offset() const noexcept
	{
		return pcurrbuf_ - prdbuf_;
	}	

	const char * get_curr_pos() const noexcept
	{
		return pcurrbuf_;
	}	

	const char * set_cur_pos(size_t offset_from_start) noexcept
	{
		size_t			maxsz = pendbuf_ - prdbuf_;

		if (offset_from_start > maxsz) {
			offset_from_start = maxsz;
		}
		
		pcurrbuf_ = prdbuf_ + offset_from_start;	

		return pcurrbuf_;
	}

	void reset() noexcept
	{
		pcurrbuf_ = prdbuf_;
	}	
};

/*
 * Stateful string updation and manipulation of a preallocated fixed size char buffer (upto 4 GB). No heap allocations done. 
 * On overflow, string is truncated to max buffer len.
 * Callback options are available to handle string truncation (buffer overflows). See comments for appendfmtcb() below...
 *
 * Example Use : (First 2 examples have STR_WR_BUF encompassed within)
 *
 * STRING_BUFFER<1024>		strbuf;					// STRING_BUFFER encapsulates an internal char buf along with STR_WR_BUF
 * 	OR
 * STRING_HEAP			strbuf(1024);				// STRING_HEAP encapsulates a Heap allocated buffer along with STR_WR_BUF
 *
 *  	OR (if the buffer was allocated separately)
 *
 * char				buf[1024];
 * STR_WR_BUF			strbuf(buf, sizeof(buf));	
 * 
 *
 * Usage :
 *
 * strbuf << "Str " << "Strview "sv << 1 << ',' << 3.2f << '\n';	// Allowed data types include string, stringview, integral, float, double, uint8_t, char, bool, void * pointer
 * strbuf.appendconst("This is a string literal ");			// Use appendconst() for string literals to skip compute of strlen at run time or use << with sv operator
 * strbuf.appendutf("नमस्ते");						// UTF8 safe Append (Default append() may result in multibyte UTF8 char truncation on overflow)
 * strbuf.appendfmt("Samples : %s %.3f", teststr, testfloat);		// sprintf style formatted append	
 * strbuf.appendptr(&myobject);						// Add Pointer Address in %p format
 * strbuf.append(cstring);  					
 */ 
class STR_WR_BUF
{
protected :	
	char				*pwritebuf_		{nullptr};
	uint32_t			currsz_			{0};
	uint32_t			maxsz_			{0};

public :		
	STR_WR_BUF(char *pbuffer, size_t maxsz)
		: pwritebuf_(pbuffer), currsz_(0), maxsz_(uint32_t(maxsz ? maxsz - 1 : 0))
	{
		if (gy_unlikely(!pbuffer)) {
			GY_THROW_EXCEPTION("String Buffer : Nullptr passed as buffer");
		}

		if (maxsz >= ~0u) {
			maxsz_ = ~0u - 1;
		}	

		*pbuffer = 0;
	}		

	STR_WR_BUF() 							= delete;

	~STR_WR_BUF() noexcept						= default;

	STR_WR_BUF(const STR_WR_BUF &) noexcept				= default;
	STR_WR_BUF & operator= (const STR_WR_BUF & other) noexcept	= default;

	STR_WR_BUF(STR_WR_BUF && other) noexcept
		: pwritebuf_(other.pwritebuf_), currsz_(std::exchange(other.currsz_, 0)), maxsz_(std::exchange(other.maxsz_, 0))
	{}	

	STR_WR_BUF & operator= (STR_WR_BUF && other) noexcept
	{
		if (this != &other) {
			pwritebuf_	= other.pwritebuf_;
			currsz_		= std::exchange(other.currsz_, 0);
			maxsz_		= std::exchange(other.maxsz_, 0);
		}

		return *this;
	}	

	/*
	 * Max 2 GB writes per call or else EOVERFLOW will result...
	 */
	[[gnu::format (printf, 2, 3)]] 
	char * appendfmt(const char *pfmt, ...) noexcept
	{
		va_list 		va;
		int			nwr;

		if (gy_unlikely(currsz_ >= maxsz_)) {
			return pwritebuf_;
		}	

		va_start(va, pfmt);
		nwr = vsnprintf(pwritebuf_ + currsz_, maxsz_ - currsz_, pfmt, va);
		va_end(va);

		if (nwr < 0) {
			// Ignore errors such as EOVERFLOW
			pwritebuf_[currsz_] = 0;
		}	
		else if ((size_t)nwr >= maxsz_ - currsz_) {
			currsz_ = maxsz_;
		}	
		else {
			currsz_ += nwr;
		}

		return pwritebuf_;
	}
		
	char *append(const char *pstr, size_t lenstr) noexcept
	{
		if (gy_unlikely(currsz_ >= maxsz_)) {
			return pwritebuf_;
		}	

		size_t			sz;

		GY_SAFE_MEMCPY(pwritebuf_ + currsz_, maxsz_ - currsz_, pstr, lenstr, sz);
		
		currsz_ += sz;
		pwritebuf_[currsz_] = 0;

		return pwritebuf_;
	}	

	/*
	 * Optimized append for String literals. 
	 * Use only for string literals and not char arrays as no run time strlen calculated...
	 */
	template <size_t N>
	char * appendconst(const char (&str)[N]) noexcept
	{
		return append(static_cast<const char *>(str), N - 1);
	}

	template <size_t N>
	char * appendconst(char (&str)[N]) 	= delete;

	char *append(const char *pstr) noexcept
	{
		size_t 		dlen;
		
		dlen = gy_strnlen(pstr, maxsz_ - currsz_);

		return append(pstr, dlen);
	}	

	/*
	 * cast as (uint8_t *) for UTF8
	 */
	char *append(const uint8_t *utf8str) noexcept
	{
		return appendutf(reinterpret_cast<const char *>(utf8str));
	}	

	char *appendutf(const char *utf8str) noexcept
	{
		size_t 		dlen;
		
		(void)gy_utf8_nlen(utf8str, maxsz_ - currsz_, &dlen);	

		return append(utf8str, dlen);
	}	

	char *append(const STR_WR_BUF & strbuf) noexcept
	{
		return append(strbuf.buffer(), strbuf.length());
	}	

	/*
	 * Same as appendfmt but will call overflowcb(const char * pstr, size_t szstr, bool istrunc, bool newupdates) if overflow occurs and after fcb call will 
	 * reset this buffer and retry adding any pending data. If the repeat add again results in overflow will truncate to max and again call 
	 * callback with istrunc = true and return 
	 * NOTE : This will only call the callback for calls to appendfmtcb(). if other methods are used such as append, appendfmt, etc no callbacks will be invoked.
	 * as the callback is not stored in the object
	 *
	 * If the overflowcb() returns false, will not attempt further updates and return nullptr immediately.
	 *
	 * Callback arguments passed are pstr => Current string, szstr => len, istrunc => true if overflow with truncation, false if buffer exact len fill,
	 * newupdates => true if the overflowcb() is called adding data from the current call, false indicates no current data and pstr contains previous data.
	 */
	template <typename FCB>
	[[gnu::format (printf, 3, 4)]] 
	char * appendfmtcb(FCB & overflowcb, const char *pfmt, ...) noexcept(noexcept(overflowcb(nullptr, 0, false, false)))
	{
		va_list 		va, vacopy;
		int			nwr;
		char			c;
		bool			bret;

		if (gy_unlikely(currsz_ >= maxsz_)) {
			bret = overflowcb(pwritebuf_, currsz_, false, false);
			if (bret == false) {
				return nullptr;
			}	

			currsz_ = 0;
			*pwritebuf_ = 0;
		}	

		va_start(va, pfmt);
		va_copy(vacopy, va);
		
		nwr = vsnprintf(pwritebuf_ + currsz_, maxsz_ - currsz_, pfmt, va);
		va_end(va);

		if (nwr < 0) {
			// Ignore errors such as EOVERFLOW
			pwritebuf_[currsz_] = 0;
		}	
		else if ((size_t)nwr >= maxsz_ - currsz_) {
			// Call the overflowcb

			if (currsz_) {
				pwritebuf_[currsz_] = 0;

				bret = overflowcb(pwritebuf_, currsz_, false, false);
				if (bret == false) {
					return nullptr;
				}	

				if ((unsigned)nwr > maxsz_ - currsz_) {
					// Retry

					currsz_ = 0;

					va_start(va, pfmt);
					nwr = vsnprintf(pwritebuf_, maxsz_, pfmt, vacopy);
					va_end(va);

					if ((size_t)nwr >= maxsz_) {
						
						currsz_ = maxsz_;

						bret = overflowcb(pwritebuf_, maxsz_, (size_t)nwr > maxsz_, true);
						if (bret == false) {
							return nullptr;
						}	

						currsz_ = 0;
						*pwritebuf_ = 0;
					}	
					else {
						currsz_ = nwr;
					}	
				}
				else {
					currsz_ = 0;
					*pwritebuf_ = 0;
				}
			}
			else {
				currsz_ = nwr;

				bret = overflowcb(pwritebuf_, maxsz_, (size_t)nwr > maxsz_, true);
				if (bret == false) {
					return nullptr;
				}

				currsz_ = 0;
				*pwritebuf_ = 0;
			}	
		}	
		else {
			currsz_ += nwr;
		}

		va_end(vacopy);
		
		return pwritebuf_;
	}

	/*
	 * Same as append() but will call overflowcb(const char * pstr, size_t szstr, bool istrunc, bool newupdates) if overflow occurs and after fcb call 
	 * will reset this buffer. If the lenstr >= maxsz_ will set istrunc to true and call overflowcb.
	 * NOTE : This will only call the callback for calls to appendcb(). if other methods are used such as append, appendfmt, etc no callbacks will be invoked.
	 * as the callback is not stored in the object
	 *
	 * If the overflowcb() returns false, will not attempt further updates and return nullptr immediately.
	 *
	 * Callback arguments passed are pstr => Current string, szstr => len, istrunc => true if overflow with truncation, false if buffer exact len fill,
	 * newupdates => true if the overflowcb() is called adding data from the current call, false indicates no current data and pstr contains previous data.
	 */
	template <typename FCB>
	char *appendcb(FCB & overflowcb, const char *pstr, size_t lenstr) noexcept(noexcept(overflowcb(nullptr, 0, false, false)))
	{
		bool			bret;

		if (gy_unlikely(currsz_ >= maxsz_)) {

			bret = overflowcb(pwritebuf_, currsz_, false, false);
			if (bret == false) {
				return nullptr;
			}	

			currsz_ = 0;
			*pwritebuf_ = 0;
		}	

		bool			istrunc = false;
		
		if (gy_unlikely(lenstr >= maxsz_ - currsz_)) {
			if (currsz_) {
				bret = overflowcb(pwritebuf_, currsz_, false, false);
				if (bret == false) {
					return nullptr;
				}	

				currsz_ = 0;
				*pwritebuf_ = 0;
			}

			istrunc = (lenstr > maxsz_);
		}

		size_t			sz;

		GY_SAFE_MEMCPY(pwritebuf_ + currsz_, maxsz_ - currsz_, pstr, lenstr, sz);

		currsz_ += sz;
		pwritebuf_[currsz_] = 0;

		if (gy_unlikely(currsz_ >= maxsz_)) {

			bret = overflowcb(pwritebuf_, currsz_, istrunc, true);
			if (bret == false) {
				return nullptr;
			}	

			currsz_ = 0;
			*pwritebuf_ = 0;
		}	

		return pwritebuf_;
	}	

	/*
	 * Same as appendcb() but for String lieterals only
	 * See comments for appendcb() and appendconst() above
	 */
	template <typename FCB, size_t N>
	char *appendconstcb(FCB & overflowcb, const char (&str)[N]) noexcept(noexcept(overflowcb(nullptr, 0, false, false)))
	{
		return appendcb(overflowcb, static_cast<const char *>(str), N - 1);
	}	

	template <typename FCB, size_t N>
	char *appendconstcb(FCB & overflowcb, char (&str)[N]) 	= delete;

	// Will ignore '\0'. If need to add '\0' within string, use appendconst("\x0") method
	char *append(char c) noexcept
	{
		if (gy_unlikely((currsz_ >= maxsz_) || (c == 0))) {
			return pwritebuf_;
		}	

		pwritebuf_[currsz_++] 	= c;
		pwritebuf_[currsz_] 	= 0;

		return pwritebuf_;
	}	

	char *appendptr(void *ptr) noexcept
	{
		return appendtype<void *>(ptr, "%p");
	}	

	char * append(std::pair<const char *, size_t> p) noexcept
	{
		return append(p.first, p.second);
	}

	char * append(std::string_view v) noexcept
	{
		return append(v.data(), v.size());
	}

	char *append(uint32_t num) noexcept
	{
		return appendtype<uint32_t>(num, "%u");
	}	
	char *append(int32_t num) noexcept
	{
		return appendtype<int32_t>(num, "%d");
	}	
	char *append(uint64_t num) noexcept
	{
		return appendtype<uint64_t>(num, "%lu");
	}	
	char *append(int64_t num) noexcept
	{
		return appendtype<int64_t>(num, "%ld");
	}	
	char *append(int16_t num) noexcept
	{
		return appendtype<int16_t>(num, "%hd");
	}	
	char *append(uint16_t num) noexcept
	{
		return appendtype<uint16_t>(num, "%hu");
	}	

	char *append(uint8_t c) noexcept
	{
		return appendtype<uint8_t>(c, "%hhu");
	}

	char *append(bool b) noexcept
	{
		if (b == false) {
			return appendconst("false");
		}	
		return appendconst("true");
	}
	
	// upto 3 decimals 
	char *append(double d, const char *fmt = "%.4g") noexcept
	{
		return appendtype<double>(d, fmt);
	}	
	
	// upto 3 decimals 
	char *append(float f, const char *fmt = "%.4f") noexcept
	{
		return appendtype<float>(f, fmt);
	}	

	// upto 3 decimals 
	char *append(long double d, const char *fmt = "%.4Lg") noexcept
	{
		return appendtype<long double>(d, fmt);
	}	

	/*
	 * NOTE : Do not overload the non-template const char * << function to enable string literal
	 * handling using the const char array ref method below...
	 */
	template <typename T>
	STR_WR_BUF & operator<< (T val) noexcept
	{
		append(val);
		return *this;
	}

	template <size_t N>
	STR_WR_BUF & operator<< (const char (&str)[N]) noexcept
	{
		/*
		 * Disabing the optimization as compiler will invoke this for a class array member in a const method as well :(
		 *
			append(static_cast<const char *>(str), N - 1);
		 */	
		append(static_cast<const char *>(str), ::strnlen(str, std::min<size_t>(N - 1, maxsz_ - currsz_)));
		return *this;
	}

	/*
	 * See comment above for the const char array
	template <size_t N>
	STR_WR_BUF & operator<< (char (&str)[N]) noexcept
	{
		append(static_cast<const char *>(str), ::strnlen(str, std::min<size_t>(N - 1, maxsz_ - currsz_)));
		return *this;
	}
	*/

	// Cast as (void *) to print Address of a pointer
	STR_WR_BUF & operator<< (void *pval) noexcept
	{
		appendptr(pval);
		return *this;
	}

	void reset() noexcept
	{
		*pwritebuf_ 	= '\0';
		currsz_ 	= 0;
	}

		
	/*
	 * Reduce the strlen by truncate_bytes bytes
	 */
	char * truncate_by(size_t truncate_bytes) noexcept
	{
		if (currsz_ == 0) {
			return pwritebuf_;
		}	
		
		if (truncate_bytes <= currsz_) {
			currsz_ -= truncate_bytes;	
		}
		else {
			currsz_ = 0;
		}	
				
		pwritebuf_[currsz_] = '\0';

		return pwritebuf_;
	}
			
	/*
	 * Set the strlen to str_len bytes
	 */
	char * truncate_to(size_t str_len) noexcept
	{
		if (currsz_ > str_len) {
			currsz_ = str_len;
			pwritebuf_[currsz_] = '\0';
		}	
		return pwritebuf_;
	}	

	// Truncate by nbytes
	char * operator-= (size_t nbytes) noexcept
	{
		return truncate_by(nbytes);
	}

	// Truncate by 1 byte
	char * operator--() noexcept
	{
		return truncate_by(1);
	}

	// Truncate by 1 byte
	char * operator--(int) noexcept
	{
		return truncate_by(1);
	}

	/*
	 * Set the strlen to str_len bytes to be used if buffer is externally modified
	 */
	char * set_len_external(size_t str_len) noexcept
	{
		if (str_len <= maxsz_) {
			currsz_ = str_len;
		}	

		pwritebuf_[currsz_] = '\0';
		return pwritebuf_;
	}	
			
	bool is_overflow() const noexcept
	{
		return currsz_ >= maxsz_;
	}	

	size_t length() const noexcept
	{
		return currsz_;
	}	

	size_t size() const noexcept
	{
		return length();
	}	

	// same as size() but with int as return type
	int sizeint() const noexcept
	{
		return (int)length();
	}	

	size_t bytes_left() const noexcept
	{
		return maxsz_ - currsz_;
	}	

	char *get_current() const noexcept
	{
		return pwritebuf_ + currsz_;
	}	

	char *buffer() noexcept
	{
		return pwritebuf_;
	}	

	const char *buffer() const noexcept
	{
		return pwritebuf_;
	}	

	char *data() noexcept
	{
		return buffer();
	}	

	const char *data() const noexcept
	{
		return buffer();
	}	

	// Returns '\0' on invalid id
	char operator[](size_t id) const noexcept
	{
		if (id < currsz_) {
			return pwritebuf_[id];
		}	
		
		return '\0';
	}

	std::string_view get_view() const noexcept
	{
		return std::string_view(data(), size());
	}

	/*
	 * Can be used to change the last char updated. Use case is of a loop and then breaking out of loop
	 * and resetting the last char to say ' '
	 * Use c as '\0' to truncate the last char
	 */ 
	char * set_last_char(char c) noexcept
	{
		if (currsz_ == 0) {
			return pwritebuf_;
		}	
		
		pwritebuf_[currsz_ - 1] = c;

		if (c == '\0') {
			currsz_--;
		}	

		return pwritebuf_;
	}


	template <typename T>
	char *appendtype(const T t, const char *fmt) noexcept
	{
		if (gy_unlikely(currsz_ >= maxsz_)) {
			return pwritebuf_;
		}	

		int 		ret = snprintf(pwritebuf_ + currsz_, maxsz_ - currsz_, fmt, t);

		if (ret < 0) {
			pwritebuf_[currsz_] = 0;
			return pwritebuf_;
		}	
		else if ((uint32_t)ret >= maxsz_ - currsz_) {
			currsz_ = maxsz_;
			return pwritebuf_;
		}	

		currsz_ += ret;

		return pwritebuf_;
	}

	size_t max_buf_size() const noexcept
	{
		return maxsz_ + 1;
	}	

	void infoprint(const char *prefix = "", bool use_offload = true) const noexcept
	{
#ifdef 		INFOPRINT_OFFLOAD
		if (use_offload) {
			INFOPRINT_OFFLOAD("%s%*s\n", prefix, sizeint(), buffer());
			return;
		}
#endif		

		INFOPRINT("%s%*s\n", prefix, sizeint(), buffer());
	}

};	


/*
 * Class with inline buffer and STR_WR_BUF associated with that buffer
 * See comments for STR_WR_BUF above
 */
template <size_t szbuf_>
class STRING_BUFFER : public CHAR_BUF<szbuf_>, public STR_WR_BUF 
{
public :	
	static_assert(szbuf_ > 1 && szbuf_ < ~0u);

	STRING_BUFFER() noexcept 
		: STR_WR_BUF(this->buf_, szbuf_)
	{}

	~STRING_BUFFER() noexcept		= default;

	STRING_BUFFER(const STRING_BUFFER & other) noexcept
		: STR_WR_BUF(this->buf_, szbuf_)
	{
		append(other.buf_, other.size());
	}	

	STRING_BUFFER & operator= (const STRING_BUFFER & other) noexcept
	{
		if (this != &other) {
			this->reset();
			this->append(other.buf_, other.size());
		}	

		return *this;
	}	

	STRING_BUFFER(STRING_BUFFER && other) noexcept
		: STR_WR_BUF(this->buf_, szbuf_)
	{
		append(other.buf_, other.size());
		other.reset();
	}	

	STRING_BUFFER & operator= (STRING_BUFFER && other) noexcept
	{
		if (this != &other) {
			this->reset();
			this->append(other.buf_, other.size());
			other.reset();
		}	

		return *this;
	}

	template <size_t osz>
	friend bool operator== (const STRING_BUFFER & lhs, const STRING_BUFFER<osz> & rhs) noexcept
	{
		const auto len = lhs.length();

		return ((len == rhs.length()) && (0 == std::memcmp(lhs.buffer(), rhs.buffer(), len)));
	}

	template <size_t osz>
	bool operator< (const STRING_BUFFER<osz> &other) const noexcept
	{
		size_t 			maxcmp = 1 + std::min(this->length(), other.length());
		int			cmp = std::memcmp(this->buffer(), other.buffer(), maxcmp);

		return (cmp < 0);
	}

	// Get an lvalue ref to STR_WR_BUF (For a temporary object, ensure not used after the statement) 
	STR_WR_BUF & get_str_buf() noexcept
	{
		return *this;
	}	
};	


/*
 * Class with Heap allocated buffer and STR_WR_BUF associated with that buffer
 * See comments for STR_WR_BUF above
 */
class STRING_HEAP final : public std::unique_ptr<char []>, public STR_WR_BUF 
{
public :	
	using CharUniq		= std::unique_ptr<char []>;
	
	using STR_WR_BUF::reset;

	explicit STRING_HEAP(size_t szbuf) 
		:  CharUniq(
			({
				if (szbuf == 0 || szbuf >= ~0u) {
					GY_THROW_EXCEPTION("String Heap size limited to 4 GB : %lu", szbuf);
				}	
				new char[szbuf];
			})	
			), STR_WR_BUF(CharUniq::get(), szbuf)
	{}

	STRING_HEAP()			= delete;

	~STRING_HEAP() noexcept		= default;

	STRING_HEAP(const STRING_HEAP & other) 
		: CharUniq(new char[other.max_buf_size()]), STR_WR_BUF(CharUniq::get(), other.max_buf_size())
	{
		append(other.buffer(), other.size());
	}	

	STRING_HEAP & operator= (const STRING_HEAP & other)
	{
		if (this != &other) {
			if (max_buf_size() > other.size()) {
				reset();
				append(other.buffer(), other.size());
			}
			else {
				this->~STRING_HEAP();

				new (this) STRING_HEAP(other);
			}	
		}	

		return *this;
	}	

	STRING_HEAP(STRING_HEAP && other) noexcept	= default;

	STRING_HEAP & operator= (STRING_HEAP && other) noexcept	= default;

	friend bool operator== (const STRING_HEAP & lhs, const STRING_HEAP & rhs) noexcept
	{
		const auto len = lhs.length();

		return ((len == rhs.length()) && (0 == std::memcmp(lhs.buffer(), rhs.buffer(), len)));
	}

	bool operator<(const STRING_HEAP &other) const noexcept
	{
		size_t 			maxcmp = 1 + std::min(this->length(), other.length());
		int			cmp = std::memcmp(this->buffer(), other.buffer(), maxcmp);

		return (cmp < 0);
	}

	STR_WR_BUF & get_str_buf() noexcept
	{
		return *this;
	}	

	CharUniq & get_unique_ptr() noexcept
	{
		return *this;
	}	
};	


/*
 * std::string like class with configurable SSO inline buffer size upto 255 bytes.
 * SSO Buffer size is calculated as (sso_sz_ aligned up to 8) - 2 bytes.
 */
template <size_t sso_sz_ = 48>
class SSO_STRING
{
public :
	static_assert(sso_sz_ < 255 && sso_sz_ > 24, "sso_sz_ must be between 24 and 255 bytes");

	static constexpr uint8_t	MAGIC_HEAP	= 0xFF;	
	static constexpr size_t		MAX_SSO_SZ	= gy_align_up_2(sso_sz_, 8) - 2;

	struct STACK_STRING
	{
		char 			buffer_[MAX_SSO_SZ + 1];
		uint8_t	 		size_;

		size_t size() const noexcept 
		{
			return size_;
		} 

		size_t capacity() const noexcept
		{
			return MAX_SSO_SZ;
		}

		const char * c_str() const noexcept 
		{
			return buffer_;
		} 

		char * data() noexcept
		{
			return buffer_;
		}	
	};

	struct HEAP_STRING
	{
		char  			*pextbuf_;
		size_t 			size_;
		size_t 			capacity_;

		size_t size() const noexcept
		{
			return size_;
		}
		
		size_t capacity() const noexcept
		{
			return capacity_;
		}
		
		const char * c_str() const noexcept
		{
			return pextbuf_;
		}

		char * data() noexcept
		{
			return pextbuf_;
		}	
	};

	union
	{
		STACK_STRING 		stack_;
		HEAP_STRING 		heap_;
	};

	SSO_STRING() noexcept 
	{
		stack_.size_		= 0;
		stack_.buffer_[0] 	= 0;
	}	

	SSO_STRING(const char * str)
		: SSO_STRING(str, std::strlen(str))
	{}	

	SSO_STRING(const char *str, size_t len)
	{
		if (len <= MAX_SSO_SZ) {
			std::memcpy(stack_.buffer_, str, len);
			stack_.buffer_[len] 	= 0;
			stack_.size_ 		= (uint8_t)len;
		}
		else {
			size_t		nlen = gy_align_up_2(len + 1, 8);

			heap_.pextbuf_ 	= (char *)malloc_or_throw(nlen);

			heap_.size_	= len;
			heap_.capacity_	= nlen - 1;
			stack_.size_ 	= MAGIC_HEAP;

			std::memcpy(heap_.pextbuf_, str, len);
			heap_.pextbuf_[len] = 0;
		}	
	}	

	SSO_STRING(const SSO_STRING & other)
		: SSO_STRING(other.c_str(), other.size())
	{}	

	SSO_STRING(SSO_STRING && other) noexcept
	{
		std::memcpy((void *)this, &other, sizeof(*this));

		other.stack_.size_	= 0;
		other.stack_.buffer_[0] = 0;
	}	

	SSO_STRING & operator=(const SSO_STRING & other)
	{
		if (this != &other) {
			strset(other.c_str(), other.size());
		}

		return *this;
	}	

	SSO_STRING(const STR_WR_BUF & strbuf)
		: SSO_STRING(strbuf.buffer(), strbuf.length())
	{}	

	template <size_t newsz>
	SSO_STRING & operator=(const SSO_STRING<newsz> & other)
	{
		strset(other.c_str(), other.size());

		return *this;
	}	

	SSO_STRING & operator=(SSO_STRING && other) noexcept
	{
		if (this != &other) {
			destroy();
			std::memcpy((void *)this, &other, sizeof(*this));
	
			other.stack_.size_	= 0;
			other.stack_.buffer_[0] = 0;
		}

		return *this;
	}	

	template <size_t newsz>
	SSO_STRING & operator=(SSO_STRING <newsz> && other) noexcept
	{
		destroy();

		if (other.is_heap()) {
			std::memcpy(&heap_, &other.heap_, sizeof(heap_));
			stack_.size_	= other.stack_.size_;
		}	
		else {
			strset(other.c_str(), other.size());
		}

		other.stack_.size_	= 0;
		other.stack_.buffer_[0] = 0;

		return *this;
	}	

	~SSO_STRING() noexcept
	{
		destroy();
	}	

	const char * strset(const char *str, size_t len, bool free_heap = true)
	{
		bool		isheap = is_heap();

		if (!isheap) {
			if (len <= MAX_SSO_SZ) {
				if (!(str >= stack_.buffer_ && str <= stack_.buffer_ + MAX_SSO_SZ)) {
					std::memcpy(stack_.buffer_, str, len);
				}
				else {
					std::memmove(stack_.buffer_, str, len);
				}	
				stack_.buffer_[len] 	= 0;

				GY_CC_BARRIER();

				stack_.size_ 		= (uint8_t)len;

				return stack_.c_str();
			}
			else {
				size_t		oldlen = stack_.size_;
				size_t		nlen = gy_align_up_2(len + 1, 8);

				stack_.size_ 	= MAGIC_HEAP;
				heap_.size_	= 0;

				heap_.pextbuf_ 	= (char *)::malloc(nlen);

				if (!heap_.pextbuf_) {
					stack_.size_ 	= oldlen;

					throw std::bad_alloc();
				}

				heap_.capacity_	= nlen - 1;

				std::memcpy(heap_.pextbuf_, str, len);
				heap_.pextbuf_[len] = 0;

				GY_CC_BARRIER();

				heap_.size_	= len;

				return heap_.c_str();
			}	
		}
		else {
			if (len <= heap_.capacity_) {
				bool		overlap = false;

				if (!(str >= heap_.pextbuf_ && str <= heap_.pextbuf_ + heap_.capacity_)) {
					overlap = true;
				}

				if (!overlap && len <= MAX_SSO_SZ && free_heap) {
					::free(heap_.pextbuf_);

					std::memcpy(stack_.buffer_, str, len);
					stack_.buffer_[len] 	= 0;

					GY_CC_BARRIER();
					
					stack_.size_ 		= (uint8_t)len;

					GY_CC_BARRIER();
					heap_.pextbuf_		= nullptr;

					return stack_.c_str();
				}	
				else {
					heap_.size_		= 0;
					if (!overlap) {
						std::memcpy(heap_.pextbuf_, str, len);
					}
					else {
						std::memmove(heap_.pextbuf_, str, len);
					}	

					heap_.pextbuf_[len] 	= 0;
					
					GY_CC_BARRIER();

					heap_.size_		= len;
					
					return heap_.c_str();
				}	
			}
			else {
				size_t		nlen = gy_align_up_2(len + 1, 8);
				char 		*ptmp = (char *)malloc_or_throw(nlen);

				std::memcpy(ptmp, str, len);
				ptmp[len] = 0;
				
				::free(heap_.pextbuf_);

				heap_.pextbuf_ 	= ptmp;
				heap_.capacity_	= nlen - 1;

				GY_CC_BARRIER();

				heap_.size_	= len;

				return heap_.c_str();
			}	
		}
	}	

	const char * strset(const char *str)
	{
		return strset(str, std::strlen(str));
	}	

	const char * assign(const char *str)
	{
		return strset(str, std::strlen(str));
	}	

	const char * assign(const char *str, size_t len)
	{
		return strset(str, len);
	}

	const char * assign(const STR_WR_BUF & strbuf)
	{
		return strset(strbuf.buffer(), strbuf.length());
	}	

	const char * assign(std::string_view v)
	{
		return strset(v.data(), v.size());
	}

	/*
	 * Use only for string literals as no runtime strlen done...
	 */
	template <size_t N>
	const char *assignconst(const char (&str)[N])
	{
		return strset(static_cast<const char *>(str), N - 1);
	}

	template <size_t N>
	char * assignconst(char (&str)[N])	= delete;

	const char * append(const char *str, size_t len)
	{
		const bool		isheap = is_heap();
		const size_t		currlen = size(), newlen = len + currlen;

		if (!isheap) {
			if (newlen <= MAX_SSO_SZ) {
				std::memcpy(stack_.buffer_ + currlen, str, len);
				stack_.buffer_[newlen] 	= 0;

				GY_CC_BARRIER();
				
				stack_.size_ 		= (uint8_t)newlen;

				return stack_.c_str();
			}
			else {
				heap_.size_	= 0;
				GY_CC_BARRIER();
				stack_.size_ 	= MAGIC_HEAP;

				size_t		nlen = gy_align_up_2(newlen + 1, 8);
				char *ptmp 	= (char *)::malloc(nlen);

				if (!ptmp) {
					stack_.size_ 	= currlen;

					throw std::bad_alloc();
				}

				std::memcpy(ptmp, stack_.buffer_, currlen);
				std::memcpy(ptmp + currlen, str, len);

				ptmp[newlen] = 0;

				GY_CC_BARRIER();
			
				heap_.pextbuf_	= ptmp;
				heap_.capacity_	= nlen - 1;

				GY_CC_BARRIER();

				heap_.size_	= newlen;

				return heap_.c_str();
			}	
		}
		else {
			if (newlen <= heap_.capacity_) {
				std::memcpy(heap_.pextbuf_ + currlen, str, len);

				heap_.pextbuf_[newlen] 	= 0;
				heap_.size_		= newlen;
				
				return heap_.c_str();
			}
			else {
				size_t		nlen = gy_align_up_2(newlen + 56, 8);
				char 		*ptmp = (char *)realloc_or_throw(heap_.pextbuf_, nlen);

				heap_.pextbuf_ 	= ptmp;
				
				std::memcpy(heap_.pextbuf_ + currlen, str, len);
				heap_.pextbuf_[newlen] = 0;

				heap_.capacity_	= nlen - 1;

				GY_CC_BARRIER();

				heap_.size_	= newlen;
				
				return heap_.c_str();
			}	
		}
	}	

	/*
	 * Use only for string literals as no runtime strlen done...
	 */
	template <size_t N>
	const char *appendconst(const char (&str)[N])
	{
		return append(static_cast<const char *>(str), N - 1);
	}

	template <size_t N>
	const char *appendconst(char (&str)[N])		= delete;

	const char * operator+= (const char *str)
	{
		return append(str, std::strlen(str));
	}	

	const char * append(const char *str)
	{
		return append(str, std::strlen(str));
	}

	const char * append(std::string_view v)
	{
		return append(v.data(), v.size());
	}

	/*
	 * Truncate to length len
	 */
	const char *truncate_to(size_t len, bool free_heap = true) noexcept
	{
		const size_t		currlen = size();
		
		if (currlen <= len) {
			return data();
		}	

		if (!is_heap()) {
			if (len <= MAX_SSO_SZ) {
				stack_.buffer_[len] 	= 0;
				stack_.size_ 		= (uint8_t)len;
			}
		}
		else {
			if (len <= MAX_SSO_SZ && free_heap) {
				const char		*pbuf = heap_.pextbuf_;

				GY_CC_BARRIER();

				std::memcpy(stack_.buffer_, pbuf, len);
				stack_.buffer_[len] 	= 0;

				GY_CC_BARRIER();
				
				stack_.size_ 		= (uint8_t)len;
				heap_.pextbuf_		= nullptr;

				::free((void *)pbuf);
			}	
			else {
				heap_.pextbuf_[len] = 0;

				GY_CC_BARRIER();

				heap_.size_	= len;
			}	
		}

		return data();
	}

	/*
	 * Truncate by len bytes
	 */
	const char *truncate_by(size_t len, bool free_heap = true) noexcept
	{
		size_t		currlen = size();

		return truncate_to(currlen > len ? currlen - len : 0, free_heap);
	}

	void destroy() noexcept
	{
		if (is_heap()) {
			::free(heap_.pextbuf_);
			heap_.pextbuf_ = nullptr;
		}	

		stack_.size_		= 0;
		stack_.buffer_[0] 	= 0;
	}	

	bool is_heap() const noexcept
	{
		return stack_.size_ == MAGIC_HEAP;
	}

	size_t size() const noexcept
	{
		return is_heap() ? heap_.size() : stack_.size();
	}

	size_t length() const noexcept
	{
		return size();
	}

	size_t capacity() const noexcept
	{
		return is_heap() ? heap_.capacity() : stack_.capacity();
	}

	const char * c_str() const noexcept
	{
		return is_heap() ? heap_.c_str() : stack_.c_str();
	}

	const char * data() const noexcept
	{
		return c_str();
	}

	/*
	 * Modifications, if any, must be done only within the size() bytes...
	 */
	char * data() noexcept
	{
		return is_heap() ? heap_.data() : stack_.data();
	}

	const char * buffer() const noexcept
	{
		return c_str();
	}

	std::string_view get_view() const noexcept
	{
		return std::string_view(data(), size());
	}

	template <size_t l2>
	bool operator< (const SSO_STRING <l2> & other) const noexcept
	{
		size_t	 		maxcmp = std::min(size(), other.size()) + 1;
		int			cmp = std::memcmp(data(), other.data(), maxcmp);

		return (cmp < 0);
	}

	template <size_t l2>
	bool operator== (const SSO_STRING <l2> & rhs) const noexcept
	{
		auto		sz = size();

		return ((sz == rhs.size()) && (0 == std::memcmp(data(), rhs.data(), sz + 1)));
	}

	template <size_t l2>
	bool operator!= (const SSO_STRING <l2> & rhs) const noexcept
	{
		return !(*this == rhs);
	}

	friend std::ostream & operator<< (std::ostream & stream, const SSO_STRING & str)
	{
		return stream << str.get_view();
	}
};	

/*
 * src must be pointer to struct in6_addr or struct in_addr (in Network Byte Order)
 * szbuf must be minimum INET_ADDRSTRLEN (16) for IPv4 and INET6_ADDRSTRLEN (48) for IPv6
 */ 
static const char *gy_print_ipaddr(int af, const void *src, char *pdstbuf, ssize_t szbuf) noexcept
{
	const char			*ptmp;

	assert(pdstbuf);

	ptmp = inet_ntop(af, src, pdstbuf, szbuf);
	if (ptmp) {
		return ptmp;
	}
	else {
		GY_STRNCPY(pdstbuf, "[Invalid IP]", szbuf);
		return pdstbuf;
	}
}	

union IP_UNION 
{
	unsigned __int128		v6_;
	uint32_t			v4_;
};

struct IPv4_v6
{
 	IP_UNION			addr_;
	bool				is_v6_;

	IPv4_v6(IP_UNION addr, bool is_v6) noexcept
		: addr_(addr), is_v6_(is_v6)
	{}

	IPv4_v6(unsigned __int128 v6addr, uint32_t v4addr, bool is_v6) noexcept
		: is_v6_(is_v6)
	{
		if (is_v6) {
			addr_.v6_ 	= v6addr;
		}	
		else {
			addr_.v4_	= v4addr;
		}	
	}

	bool is_ipv4() const noexcept
	{
		return !is_v6_;
	}	

	bool is_ipv6() const noexcept
	{
		return is_v6_;
	}	
};	

/*
 * IPv4/IPv6 storage class. 
 * Packed with alignment 8 to save up on 8 bytes. Uses 24 bytes per IP
 */
class [[gnu::packed]] [[gnu::aligned(8)]] GY_IP_ADDR 
{
protected :	
	unsigned __int128		ip128_be_		{0};	

	union {
		uint32_t		ip32_be_		{0};
		uint32_t		embedded_ipv4_;
	};

	int16_t				aftype_			{AF_INET};
	uint16_t			ipflags_		{IP_MISC};

	enum IP_ADDR_TYPE_E : uint16_t
	{
		IP_MISC			= 0,

		IPv4_ANY 		= 1 << 0,	
		IPv4_MULTICAST		= 1 << 1,
		IPv4_LINK_LOCAL		= 1 << 2,
		IPv4_LOOPBACK		= 1 << 3,
		IPv4_GLOBAL_ADDR	= 1 << 4,
		IPv4_PRIVATE_ADDR	= 1 << 5,

		IPv6_ANY		= 1 << 6,
		IPv6_v4_MAPPED_v6	= 1 << 7,
		IPv6_NAT64_v4		= 1 << 8,
		IPv6_LINK_LOCAL		= 1 << 9,
		IPv6_MULTICAST		= 1 << 10,
		IPv6_6_TO_4_TUNNEL	= 1 << 11,
		IPv6_LOOPBACK		= 1 << 12,
		IPv6_GLOBAL_ADDR	= 1 << 13,
		IPv6_UNIQUE_LOCAL	= 1 << 14,

		// Please update IPv4_v6_MAX_FLAGS in case new flags added. If more than 15 flags need to make ipflags_ int32_t

		IPv4_v6_MAX_FLAGS	= 1 << 14
	};

	static constexpr int 		IP_MAX_FLAGS = gy_least_bit_set(IPv4_v6_MAX_FLAGS);

	static_assert(IP_MAX_FLAGS <= 15, "ipflags_ needs to be made uint32_t");

public :

	GY_IP_ADDR() noexcept 		= default;
	 
	GY_IP_ADDR(uint32_t ip32_be) noexcept 
	{
		set_ip(ip32_be);
	}	

	GY_IP_ADDR(struct in_addr sin_addr) noexcept
	{
		set_ip((uint32_t)sin_addr.s_addr);
	}	

	GY_IP_ADDR(unsigned __int128 ip128_be) noexcept
	{
		set_ip(ip128_be);
	}	

	GY_IP_ADDR(struct in6_addr sin6_addr) noexcept
	{
		set_ip(sin6_addr);
	}	

	GY_IP_ADDR(struct sockaddr_storage *psockaddr)
	{
		auto 		sockfamily = psockaddr->ss_family;

		if (sockfamily == AF_INET) {
			struct sockaddr_in 	*paddr = (sockaddr_in *)psockaddr;

			set_ip((uint32_t)paddr->sin_addr.s_addr);
		}	
		else if (sockfamily == AF_INET6) {
			struct sockaddr_in6 	*paddr = (sockaddr_in6 *)psockaddr;

			set_ip(paddr->sin6_addr);
		}	
		else {
			GY_THROW_EXCEPTION("Invalid Socket Address Family %u seen", sockfamily);
		}	
	}	

	GY_IP_ADDR(struct sockaddr *psockaddr, socklen_t addrlen)
	{
		if ((psockaddr->sa_family == AF_INET) && (addrlen >= sizeof(sockaddr_in))) {
			struct sockaddr_in 	*paddr = (sockaddr_in *)psockaddr;

			set_ip((uint32_t)paddr->sin_addr.s_addr);
		}	
		else if ((psockaddr->sa_family == AF_INET6) && (addrlen >= sizeof(sockaddr_in6))) {
			struct sockaddr_in6 	*paddr = (sockaddr_in6 *)psockaddr;

			set_ip(paddr->sin6_addr);
		}	
		else {
			GY_THROW_EXCEPTION("Invalid socket Address family %u or len %u seen", psockaddr->sa_family, addrlen);
		}	
	}	

	// noexcept constructor : will return false in is_valid in case of invalid IPv4/v6 address and object state is undefined
	GY_IP_ADDR(const char *ipstring, bool & is_valid) noexcept 
	{ 
		is_valid = set_ip(ipstring, false /* throw_except */);
	}

	// Will throw exception if ipstring not a valid IPv4/v6 address
	GY_IP_ADDR(const char *ipstring) 
	{ 
		set_ip(ipstring);
	}

	GY_IP_ADDR(IPv4_v6 ip) noexcept
	{
		if (ip.is_ipv4()) {
			set_ip(ip.addr_.v4_);
		}	
		else {
			set_ip(ip.addr_.v6_);
		}	
	}	

	~GY_IP_ADDR() noexcept					= default;
	
	GY_IP_ADDR(const GY_IP_ADDR &) noexcept			= default;
	GY_IP_ADDR(GY_IP_ADDR &&) noexcept			= default;

	GY_IP_ADDR & operator=(const GY_IP_ADDR &) noexcept	= default;
	GY_IP_ADDR & operator=(GY_IP_ADDR &&) noexcept		= default;

	/*
	 * IPv4 Mapped IPv6 addresses will be considered as IPv4 for equality operator
	 * Also, IP Any Address will be considered as IPv6 irrespective of original family
	 */ 
	friend bool operator== (const GY_IP_ADDR &lhs, const GY_IP_ADDR &rhs) noexcept
	{
		if (lhs.ip32_be_ || rhs.ip32_be_) {
			return lhs.ip32_be_ == rhs.ip32_be_;
		}	

		return lhs.ip128_be_ == rhs.ip128_be_;
	}

	friend bool operator!= (const GY_IP_ADDR &lhs, const GY_IP_ADDR &rhs) noexcept
	{
		return (!(lhs == rhs));
	}

	// Returns a 32 bit hash extended to 64 bit. i.e. distribution is not over entire 64 bits
	class IP_HASH 
	{
	public :
		size_t operator()(const GY_IP_ADDR & k) const noexcept
		{
			return k.get_hash();
		}
	};

	void operator= (uint32_t ip32_be_) noexcept
	{
		set_ip(ip32_be_);	
	}
			
	void operator= (unsigned __int128 ip128_be) noexcept
	{
		set_ip(ip128_be);	
	}

	void operator= (struct in6_addr sin6_addr) noexcept
	{
		set_ip(sin6_addr);	
	}
			
	void operator= (const char *pipstr)
	{
		set_ip(pipstr);
	}

	void set_ip(uint32_t ip32_be) noexcept
	{
		ip128_be_ 	= 0;
		ip32_be_ 	= ip32_be;
		aftype_ 	= AF_INET;
		ipflags_ 	= get_ipv4_type_flags(); 
	}	

	void set_ip(struct in_addr sin_addr) noexcept
	{
		set_ip((uint32_t)sin_addr.s_addr);
	}	

	void set_ip(unsigned __int128 ip128_be) noexcept
	{
		ip128_be_ 	= ip128_be;
		ip32_be_ 	= 0;
		aftype_ 	= AF_INET6;
		ipflags_ 	= get_ipv6_type_flags();
	}	

	void set_ip(struct in6_addr sin6_addr) noexcept
	{
		unsigned __int128	ip128_be;
		
		std::memcpy(&ip128_be, &sin6_addr, sizeof(ip128_be));

		set_ip(ip128_be);
	}
		
	bool set_ip(const char *pipstr, bool throw_except = true)
	{
		assert(pipstr);
			
		if (nullptr != strchr(pipstr, ':')) {
			
			alignas(8) uint8_t			buf[sizeof(struct in6_addr)];
			int					ret;

			ret = inet_pton(AF_INET6, pipstr, buf);

			if (ret <= 0) {
				char 				emsg[128];

				if (ret == 0) {
					snprintf(emsg, sizeof(emsg), " Address not in presentation format");
				} 
				else {
					*emsg = '\0';
				}	
				
				if (throw_except) {
					if (ret < 0) GY_THROW_SYS_EXCEPTION("Invalid IP %s%s", pipstr, emsg);
					GY_THROW_EXCEPTION("Invalid IP %s%s", pipstr, emsg);
				}
				else {
					return false;
				}	
			}

			ip32_be_ 	= 0;
			aftype_ 	= AF_INET6;

			std::memcpy(&ip128_be_, buf, sizeof(ip128_be_));
			ipflags_ 	= get_ipv6_type_flags();
		}
		else {
			alignas(8) uint8_t			buf[sizeof(struct in_addr)];
			char 					emsg[256];
			int					ret;

			ret = inet_pton(AF_INET, pipstr, buf);

			if (ret <= 0) {
				char 				emsg[128];

				if (ret == 0) {
					snprintf(emsg, sizeof(emsg), " Address not in presentation format");
				} 
				else {
					*emsg = '\0';
				}	
				
				if (throw_except) {
					if (ret < 0) GY_THROW_SYS_EXCEPTION("Invalid IP %s%s", pipstr, emsg);
					GY_THROW_EXCEPTION("Invalid IP %s%s", pipstr, emsg);
				}
				else {
					return false;
				}	
			}
			
			ip128_be_ 	= 0;
			aftype_ 	= AF_INET;

			memcpy(&ip32_be_, buf, sizeof(ip32_be_));
			ipflags_ = get_ipv4_type_flags();
		}	

		return true;
	}	

	// size must be minimum INET_ADDRSTRLEN (16) for IPv4 and INET6_ADDRSTRLEN (48) for IPv6
	const char * printaddr(char *pdstbuf, size_t size) const noexcept
	{
		if (aftype_ == AF_INET) {
			struct in_addr		addr;

			memcpy(&addr, &ip32_be_, sizeof(ip32_be_));
			
			return gy_print_ipaddr(AF_INET, &addr, pdstbuf, size);
		}	
		
		struct in6_addr 		addr;
		
		memcpy(&addr, &ip128_be_, sizeof(ip128_be_));

		return gy_print_ipaddr(AF_INET6, &addr, pdstbuf, size);
	}

	// bytes_left() must be minimum INET_ADDRSTRLEN (16) for IPv4 and INET6_ADDRSTRLEN (48) for IPv6
	const char * printaddr(STR_WR_BUF & strbuf) const noexcept
	{
		char			tbuf[INET6_ADDRSTRLEN + 1];

		return strbuf.append(printaddr(tbuf, sizeof(tbuf) - 1));
	}

	CHAR_BUF<64> printaddr() const noexcept
	{
		CHAR_BUF<64>		cbuf;

		printaddr(cbuf.get(), 64);
		return cbuf;
	}	
		
	const char * print_mapped_ipv4(char *pdstbuf, size_t size) const noexcept
	{
		if (is_mapped_ipv4() || (is_nat64_ipv4()) || (is_ipv6_v4_tunnel())) {
			struct in_addr		addr;

			memcpy(&addr, &embedded_ipv4_, sizeof(embedded_ipv4_));
			
			return gy_print_ipaddr(AF_INET, &addr, pdstbuf, size);
		}	
		
		snprintf(pdstbuf, size, "[No Mapped IP]");

		return pdstbuf;
	}

	const char * print_mapped_ipv4(STR_WR_BUF & strbuf) const noexcept
	{
		char			tbuf[INET6_ADDRSTRLEN + 1];

		return strbuf.append(print_mapped_ipv4(tbuf, sizeof(tbuf) - 1));
	}

	CHAR_BUF<64> print_mapped_ipv4() const noexcept
	{
		CHAR_BUF<64>		cbuf;

		print_mapped_ipv4(cbuf.get(), 64);
		return cbuf;
	}	

	int get_ipflags() const noexcept
	{
		return ipflags_;
	}	

	/*
	 * Will return false for embedded IPv4 types such as ::ffff:192.168.0.1
	 * To use this IP for connect(), instead call is_pure_ipv6() to figure if its an actual IPv6/v4
	 */
	bool is_ipv4_addr() const noexcept
	{
		return aftype_ == AF_INET;
	}	

	/*
	 * Will return true for embedded IPv4 types such as ::ffff:192.168.0.1
	 * To use this IP for connect(), instead call is_pure_ipv6() to figure if its an actual IPv6/v4
	 */
	bool is_ipv6_addr() const noexcept
	{
		return aftype_ == AF_INET6;
	}	

	/*
	 * Returns true if the IP is a pure IPv6 (i.e. neither an IPv4 nor an IPv4 embedded IPv6)
	 * Will return false for IPv6 addresses such as ::ffff:192.168.0.1
	 * This method should be used for connect() to figure out whether AF_INET/AF_INET6 is to be used
	 * or get_sockfamily() can also be used.
	 */
	bool is_pure_ipv6() const noexcept
	{
		return ((aftype_ == AF_INET6) && (embedded_ipv4_ == 0));
	}	

	/*
	 * Will return true for embedded IPv4 types such as ::ffff:192.168.0.1 but false for IPv4 such as 192.168.0.1
	 */
	bool is_embedded_ipv4() const noexcept
	{
		return ((aftype_ == AF_INET6) && (embedded_ipv4_ != 0));
	}

	/*
	 * Will return AF_INET for both IPv4 and embedded IPv4 based IPv6 such as ::ffff:192.168.0.1
	 * This method should be used for bind() or connect() sockets to figure out whether AF_INET/AF_INET6 is to be used.
	 */
	int get_sockfamily() const noexcept
	{
		return (false == is_pure_ipv6() ? AF_INET : AF_INET6);
	}

	bool is_multicast() const noexcept
	{
		return ipflags_ & (IPv4_MULTICAST | IPv6_MULTICAST);
	}

	bool is_link_local_addr() const noexcept
	{
		return ipflags_ & (IPv4_LINK_LOCAL | IPv6_LINK_LOCAL);
	}

	bool is_global_ip() const noexcept
	{
		return ipflags_ & (IPv4_GLOBAL_ADDR | IPv6_GLOBAL_ADDR);
	}

	bool is_private_ip() const noexcept
	{
		return ipflags_ & (IPv4_PRIVATE_ADDR | IPv6_UNIQUE_LOCAL);
	}

	bool is_loopback() const noexcept
	{
		return ipflags_ & (IPv4_LOOPBACK | IPv6_LOOPBACK);
	}

	bool is_any_address() const noexcept
	{
		return ipflags_ & (IPv4_ANY | IPv6_ANY);
	}

	bool is_mapped_ipv4() const noexcept
	{
		return ipflags_ & IPv6_v4_MAPPED_v6;
	}

	bool is_nat64_ipv4() const noexcept
	{
		return ipflags_ & IPv6_NAT64_v4;
	}

	bool is_ipv6_v4_tunnel() const noexcept
	{
		return ipflags_ & IPv6_6_TO_4_TUNNEL;
	}

	unsigned __int128 get_ipv6_addr_be() const noexcept
	{
		return ip128_be_;
	}
	
	uint32_t get_ipv4_be() const noexcept
	{
		return ip32_be_;		
	}		

	/*
	 * Populates pbuf with the IP in binary (in_addr/in6_addr) format and returns len of data. pbuf must be at least 16 bytes.
	 * IPv4 Mapped IPv6 addresses will be returned as IPv4
	 * Also, IP Any Address will be considered as IPv6 irrespective of original family
	 */ 
	size_t get_as_inaddr(void *pbuf) const noexcept
	{
		if (ip32_be_) {
			memcpy(pbuf, &ip32_be_, sizeof(ip32_be_));
			return sizeof(ip32_be_);
		}	

		std::memcpy(pbuf, &ip128_be_, sizeof(ip128_be_));
		return sizeof(ip128_be_);
	}	

	uint32_t get_embedded_ipv4_be() const noexcept
	{
		return embedded_ipv4_;
	}	

	bool is_valid_ip() const noexcept
	{
		return !((ip32_be_ == 0) && (ip128_be_ == 0));
	}	

	/*
	 * IPv4 Mapped IPv6 addresses will be considered as IPv4 for hashing
	 * Also, IP Any Address will be considered as IPv6 irrespective of original family
	 */ 
	uint32_t get_hash() const noexcept
	{
		alignas(4) uint8_t	buf1[16];
		int			len;

		len = get_as_inaddr(buf1);
			
		return jhash2((uint32_t *)buf1, len / sizeof(uint32_t), 0xceedfead);
	}	

	bool is_init() const noexcept
	{
		return ipflags_ != IP_MISC;
	}

	char * get_ipdescription(char *buffer, size_t sz) const noexcept
	{
		int		ret = ipflags_;

		*buffer = '\0';

		for (int i = 0; i < IP_MAX_FLAGS; i++) {
			if (ret & (1 << i)) {
				const char * pstr = get_iptype_desc((IP_ADDR_TYPE_E)(1 << i));

				GY_STRNCAT(buffer, sz, pstr, strlen(pstr));
				GY_STRNCAT(buffer, sz, " ", 1);
			}	
		}
		
		return buffer;
	}

	static constexpr const char *get_iptype_desc(IP_ADDR_TYPE_E type) noexcept
	{
		switch (type) {
		
		case IP_MISC 		:	return "Uninitialized/Misc IPv4/IPv6 Address";

		case IPv4_ANY		:	return "IPv4 - 0.0.0.0 Any Local IPv4";
		case IPv4_MULTICAST	: 	return "IPv4 - Multicast IP";
		case IPv4_LINK_LOCAL	:	return "IPv4 - Link Local IP - Not addressable across routers";
		case IPv4_LOOPBACK	:	return "IPv4 - Loopback Address of type 127.x.x.x";	
		case IPv4_GLOBAL_ADDR	: 	return "IPv4 - Globally Addressable";
		case IPv4_PRIVATE_ADDR	:	return "IPv4 - Private Address - Not Globally Routable";

		case IPv6_ANY		:	return "IPv6 - :: Any Local IPv4";	
		case IPv6_v4_MAPPED_v6	:	return "IPv6 - IPv4 mapped IPv6 address";
		case IPv6_NAT64_v4	:	return "IPv6 - IPv4 embedded NAT64 IPv6 address";
		case IPv6_LINK_LOCAL	: 	return "IPv6 - Link Local IP - Not addressable across routers";
		case IPv6_MULTICAST	:	return "IPv6 - Multicast IP";
		case IPv6_6_TO_4_TUNNEL	:	return "IPv6 - 6to4 tunnel with embedded IPv4 address";
		case IPv6_LOOPBACK	:	return "IPv6 - ::1 Loopback Address";
		case IPv6_GLOBAL_ADDR	:	return "IPv6 - Globally Addressable";
		case IPv6_UNIQUE_LOCAL	:	return "IPv6 - Unique Local Address - Not Globally Routable";

		default			:	return "Unknown Type";

		}	
	}	

protected :
	/*
	 * Refer to https://wiki.ubuntu.com/IPv6
	 */
	int get_ipv6_type_flags() noexcept
	{
		const uint8_t 			*pipbuf = reinterpret_cast<const uint8_t *>(&ip128_be_);
		int				atype = IP_MISC;	

		embedded_ipv4_ = 0;

		if (ip128_be_ == 0) {
			atype = IPv6_ANY;
			return atype;
		}

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__		
		if (((0ul == (ip128_be_ & ~0ul))) && ((1ul << 56) == (ip128_be_ >> 64ul))) 
#else
		if (((1ul == (ip128_be_ & ~0ul))) && (0 == (ip128_be_ >> 64ul))) 
#endif			
		{
			// ::1	
			atype = IPv6_LOOPBACK;
			return atype;
		}	
		
		if ((pipbuf[0] & 0xF0) == 0x20)	{
			if (pipbuf[0] == 0x20 && pipbuf[1] == 0x02) {
				// 2002::
				atype |= IPv6_6_TO_4_TUNNEL;

				memcpy(&embedded_ipv4_, pipbuf + 2, sizeof(embedded_ipv4_));
			}	
			else if (!(pipbuf[0] == 0x20 && pipbuf[1] == 0x01 && pipbuf[2] == 0x0d && pipbuf[3] == 0xb8)) {
				// 2000:: onwards
				atype |= IPv6_GLOBAL_ADDR;
			}	

			return atype;
		}

		if (
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__		
			(0 == (ip128_be_ & ~0ull))  
#else
			(0 == (ip128_be_ >> 64ull))  
#endif		
			
			&& (pipbuf[8] == 0x0 && pipbuf[9] == 0x0 && pipbuf[10] == 0xFF && pipbuf[11] == 0xFF)) {

			// ::ffff:1.2.3.4
			atype |= IPv6_v4_MAPPED_v6;

			memcpy(&embedded_ipv4_, pipbuf + 12, sizeof(embedded_ipv4_));

			return atype;
		}	

		if (pipbuf[0] == 0x0 && pipbuf[1] == 0x64 && pipbuf[2] == 0xFF && pipbuf[3] == 0x9B) {
			// 64:ff9b::192.0.2.33 (NAT64) : We handle only the well known 96 prefix NAT64 (https://tools.ietf.org/html/rfc6052)
			atype |= IPv6_NAT64_v4;

			memcpy(&embedded_ipv4_, pipbuf + 12, sizeof(embedded_ipv4_));

			return atype;
		}	

		switch (*pipbuf) {
		
		case 0xFE :
			if (0x80 == (pipbuf[1] & 0xF0)) {

				// fe80::
				atype |= IPv6_LINK_LOCAL;
				return atype;
			}	
			break;
		
		case 0xFC :
		case 0xFD :
			atype |= IPv6_UNIQUE_LOCAL;
			return atype;

		case 0xFF :
			atype |= IPv6_MULTICAST;
			return atype;

		default :
			break;
		}	
		
		return atype;
	}	

	int get_ipv4_type_flags() const noexcept
	{
		const uint8_t		*pipbuf = reinterpret_cast<const uint8_t *>(&ip32_be_);

		if (ip32_be_ == 0) {
			return IPv4_ANY;
		}

		if (*pipbuf == 0x7F) {
			return IPv4_LOOPBACK;
		}

		if ((*pipbuf == 0x0A) || (pipbuf[0] == 0xAC && (0x10 == (pipbuf[1] & 0xF0))) || (pipbuf[0] == 0xC0 && pipbuf[1] == 0xA8)) {
			return IPv4_PRIVATE_ADDR;
		}

		// 224.x.x.x to 239.x.x.x
		if (0xE0 == (*pipbuf & 0xE0)) {
			return IPv4_MULTICAST;
		}	
		
		// 169.254.x.x/16
		if (*pipbuf == 0xA9 && pipbuf[1] == 0xFE) {
			return IPv4_LINK_LOCAL;
		}	

		return IPv4_GLOBAL_ADDR;
	}	
	
};

class IP_PORT
{
public :	
	GY_IP_ADDR			ipaddr_;
	uint16_t			port_		{0};

	static constexpr uint16_t	EPHEMERAL_PORT_START = 16000;	// We do not check the /proc/sys/net/ipv4/ip_local_port_range

	IP_PORT() noexcept 		= default;

	IP_PORT(const GY_IP_ADDR & addr, uint16_t port) noexcept : ipaddr_(addr), port_(port) 
	{}

	IP_PORT(uint32_t ip32_be, uint16_t port) noexcept : ipaddr_(ip32_be), port_(port)
	{}

	IP_PORT(unsigned __int128 ip128_be, uint16_t port) noexcept : ipaddr_(ip128_be), port_(port)
	{}

	IP_PORT(struct sockaddr *psockaddr, socklen_t addrlen)
	{
		assert(psockaddr);

		if ((psockaddr->sa_family == AF_INET) && (addrlen >= sizeof(sockaddr_in))) {
			struct sockaddr_in 	*paddr = (sockaddr_in *)psockaddr;

			ipaddr_.set_ip((uint32_t)paddr->sin_addr.s_addr);
			port_ = ntohs(paddr->sin_port);
		}	
		else if ((psockaddr->sa_family == AF_INET6) && (addrlen >= sizeof(sockaddr_in6))) {
			struct sockaddr_in6 	*paddr = (sockaddr_in6 *)psockaddr;

			ipaddr_.set_ip(paddr->sin6_addr);
			port_ = ntohs(paddr->sin6_port);
		}	
		else {
			GY_THROW_EXCEPTION("Invalid socket Address family %u or len %u seen for IP_PORT", psockaddr->sa_family, addrlen);
		}	
	}
	
	IP_PORT(struct sockaddr_storage *psockaddr) 
	{
		auto 		sockfamily = psockaddr->ss_family;

		if (sockfamily == AF_INET) {
			struct sockaddr_in 	*paddr = (sockaddr_in *)psockaddr;

			ipaddr_.set_ip((uint32_t)paddr->sin_addr.s_addr);
			port_ = ntohs(paddr->sin_port);
		}	
		else if (sockfamily == AF_INET6) {
			struct sockaddr_in6 	*paddr = (sockaddr_in6 *)psockaddr;

			ipaddr_.set_ip(paddr->sin6_addr);
			port_ = ntohs(paddr->sin6_port);
		}	
		else {
			GY_THROW_EXCEPTION("Invalid Socket Address Family %u seen for IP_PORT", sockfamily);
		}	
	}

	IP_PORT(const char *pipstr, uint16_t port) : ipaddr_(pipstr), port_(port)
	{}

	uint32_t get_hash() const noexcept
	{
		alignas(4) uint8_t	buf1[sizeof(GY_IP_ADDR) + sizeof(uint32_t)];
		int			len;

		len = ipaddr_.get_as_inaddr(buf1);

		buf1[len++] = (port_ >> 8);
		buf1[len++] = (port_ & 0xFF);
		buf1[len++] = 0;		// Align to 4 bytes
		buf1[len++] = 0;
			
		return jhash2((uint32_t *)buf1, len / sizeof(uint32_t), 0xceedfead);
	}	
	
	bool is_ephemeral_port() const noexcept
	{
		return port_ >= EPHEMERAL_PORT_START;
	}
		
	char * print_string(STR_WR_BUF & strbuf) const noexcept
	{
		strbuf.appendconst("IP ");
		ipaddr_.printaddr(strbuf);
		
		strbuf.appendconst(" Port ");
		strbuf.append(port_);

		return strbuf.buffer();
	}	

	char * print_string(char *sbuf, size_t szbuf) const noexcept
	{
		if (!sbuf) {
			return nullptr;
		}

		STR_WR_BUF		strbuf(sbuf, szbuf);
		return print_string(strbuf);
	}

	CHAR_BUF<128> print_string() const noexcept
	{
		CHAR_BUF<128>		cbuf;

		return print_string(cbuf.get(), sizeof(cbuf));
	}	

	void get_as_sockaddr(struct sockaddr_storage & sockaddr, socklen_t & socklen, int & sockfamily) const noexcept
	{
		if (false == (ipaddr_.is_pure_ipv6())) {
			struct sockaddr_in 	*paddr = (sockaddr_in *)&sockaddr;

			std::memset(paddr, 0, sizeof(*paddr));

			paddr->sin_family 	= AF_INET;
			paddr->sin_port 	= htons(port_);
			
			ipaddr_.get_as_inaddr(&paddr->sin_addr.s_addr);
			
			socklen			= sizeof(sockaddr_in);
			sockfamily		= AF_INET;
		}	
		else {
			struct sockaddr_in6 	*paddr = (sockaddr_in6 *)&sockaddr;

			std::memset(paddr, 0, sizeof(*paddr));

			paddr->sin6_family 	= AF_INET6;
			paddr->sin6_port 	= htons(port_);
			
			ipaddr_.get_as_inaddr(&paddr->sin6_addr);

			socklen			= sizeof(sockaddr_in6);
			sockfamily		= AF_INET6;
		}	
	}

	// Returns a 32 bit hash extended to 64 bit. i.e. distribution is not over entire 64 bits
	class IP_PORT_HASH 
	{
	public :
		size_t operator()(const IP_PORT & k) const noexcept
		{
			return k.get_hash();
		}
	};
	
	friend inline bool operator== (const IP_PORT &lhs, const IP_PORT &rhs) noexcept
	{
		return ((lhs.port_ == rhs.port_) && (lhs.ipaddr_ == rhs.ipaddr_));	
	}

	friend inline bool operator!= (const IP_PORT &lhs, const IP_PORT &rhs) noexcept
	{
		return !(lhs == rhs);
	}	
};

class DOMAIN_PORT
{
public :	
	char				domain_[MAX_DOMAINNAME_SIZE]	{};
	uint16_t			port_				{0};
	
	DOMAIN_PORT() noexcept		= default;

	DOMAIN_PORT(const char *domain, uint16_t port) noexcept : port_(port)
	{
		GY_STRNCPY(domain_, domain, sizeof(domain_));
	}	

	const char * get_domain() const noexcept
	{
		return domain_;
	}

	uint16_t get_port() const noexcept
	{
		return port_;
	}	

	void set_domain(const char *pdomain) noexcept
	{
		GY_STRNCPY(domain_, pdomain, sizeof(domain_));
	}

	void set_port(uint16_t port) noexcept
	{
		port_ = port;
	}	

	void set(const char *newdomain, uint16_t newport) noexcept
	{
		GY_STRNCPY(domain_, newdomain, sizeof(domain_));
		port_ = newport;
	}	

	uint64_t get_hash() const noexcept
	{
		return get_domain_port_hash(domain_, port_);
	}

	char * print_string(STR_WR_BUF & strbuf) const noexcept
	{
		strbuf.appendfmt("Domain \'%s\' Port %hu ", domain_, port_);

		return strbuf.buffer();
	}	

	class DOMAIN_PORT_HASH 
	{
	public :
		size_t operator()(const DOMAIN_PORT & k) const noexcept
		{
			return k.get_hash();
		}
	};

	static uint64_t get_domain_port_hash(const char * domain, uint16_t port) noexcept
	{
		alignas(8) char			tbuf[MAX_DOMAINNAME_SIZE + 8];

		auto 				len = GY_STRNCPY_LEN(tbuf, domain, MAX_DOMAINNAME_SIZE);
		
		std::memcpy(tbuf + len, &port, sizeof(port));

		return gy_cityhash64(tbuf, len + sizeof(port));
	}

	friend inline bool operator== (const DOMAIN_PORT & lhs, const DOMAIN_PORT & rhs) noexcept
	{
		return ((lhs.port_ == rhs.port_) && (0 == strncmp(lhs.domain_, rhs.domain_, sizeof(lhs.domain_))));
	}
};


/*
 * Periodic on demand CPU/IO/Memory monitor for any process/thread. This is to be used for further statistical analysis.
 * 
 * To periodically monitor the process wide stats, use either of the following :
 *
	PROC_CPU_IO_STATS::init_singleton(5);  // 5 indicates the duration (secs) of each collection call. This will spawn a thread as well.

		OR 

	PROC_CPU_IO_STATS	procstats(getpid(), getpid());
	
	while (to_exit == 0) {
		gy_nanosleep(duration_sec, 0);

		procstats.get_current_stats(true);	// Pass true in case the stats need to be printed to stdout
	}
 *
 * The Act Bytes Read/Write indicate Bytes read/written to block-backed filesystems.
 * 
 * Sample Output :

 [2019-03-15 14:12:53.555569]:[INFO]: Process ireplay 24009 Statistics : CPU/Mem/IO Stats for Interval of 4.996476650 sec : [Interval User CPU Usage 26.854%, Sys CPU Usage 88.176%, Blkio Delay 0.000%, Previous 2 Stats : User CPU %% [128.400%,89.860%], Sys CPU %% [93.200%,105.812%], Blkio Delay %% [0.000%,0.000%], Avg CPU Use 122%, Max CPU Use 356%, Current Interval User Time 134 ticks, Sys Time 440 ticks, Blkio delay 0 ticks], [Current Virtual Memory 1162 MB, RSS 1062 MB, Diff VM 0 MB, Diff RSS 0 MB, Startup VM 1123 MB], [Num Threads 71, Diff Threads 0], [Interval Minor Page Faults 0, Major Page Fault 0, Last 3 periods Major Faults 0, Total Minor Faults 272854, Total Major Faults 0], [Interval Bytes Read 0, Bytes Written 1654653, Read Syscalls 0, Write Syscalls 58965, Disk Bytes Read 0, Disk Bytes Written 4096], [Total Bytes Read 70559, Total Bytes Written 46700642, Total Read Syscalls 92, Total Write Syscalls 1661268, Total Disk Bytes Read 106496, Total Disk Bytes Written 221184], [Process Uptime : 0 days : 00 hrs : 02 min : 08 sec]
 
 *
 */ 

class PROC_CPU_IO_STATS
{
public :	
	static constexpr int		MAX_PROC_HIST_STATS = 3;

	uint64_t			cumul_minflt, cumul_majflt, usertime, systime, blkio_ticks, vmsize, rss, num_threads;
	int64_t				diff_vmsize, diff_rss; 
	uint64_t			cumul_rchar, cumul_wchar, cumul_syscr, cumul_syscw, cumul_read_bytes, cumul_write_bytes;
	int64_t				diff_rchar, diff_wchar, diff_syscr, diff_syscw, diff_read_bytes, diff_write_bytes;
	uint64_t			tstartstats, toldstart;

	float				usercpu_pct_hist[MAX_PROC_HIST_STATS];
	float				syscpu_pct_hist[MAX_PROC_HIST_STATS];
	float				blkiodelay_pct_hist[MAX_PROC_HIST_STATS];

	int				diff_minflt, diff_majflt, diff_usertime, diff_systime, diff_blkio_ticks;
	int				diff_num_threads;
	int				max_cpu_pct;
	int				total_cpu_pct;
	int				nitervals;
	int				init_vm_mb;

	pid_t				pid, tid;	
	int				last_errno;

	int16_t				majflt_hist[MAX_PROC_HIST_STATS];

	union {
		int			task_stopped_int;
		char			task_stopped_hist[MAX_PROC_HIST_STATS];
	};
	bool				monitor_whole_proc : 1;
	bool				is_kthread : 1;

	/*
	 * Default constructor to be only used for subsequent copy assignment
	 */ 
	PROC_CPU_IO_STATS() noexcept :
		cumul_minflt(
			({
				gy_safe_memset(this);
				0;
			})
		)	
	{
	}	

	// Pass pis_kthread as true for Kernel kthreads or processes where syscall/IO stats not needed
	PROC_CPU_IO_STATS(pid_t pidin, pid_t tidin = 0, bool monitor_whole_procin = true, const bool * pis_kthread = nullptr) noexcept : 
		cumul_minflt(
			({
				gy_safe_memset(this);
				0;
			})	
		), 
		tstartstats(get_nsec_clock()), toldstart(0), pid(pidin), tid(tidin ? tidin : pidin), monitor_whole_proc(monitor_whole_procin)
	{ 
		char 			task_state;

		int ret = get_task_cpu_mem_stats(pid, tid, &cumul_minflt, &cumul_majflt, &usertime, &systime, &num_threads, &vmsize, &rss, &blkio_ticks, monitor_whole_proc, &task_state);
		if (ret != 0) {
			last_errno = errno;

			CONDEXEC(
				DEBUGEXECN(25, PERRORPRINT("Could not get Thread/Proc CPU/Memory statistics for PID %d Thread %d", pid, tid););	
			);	

			tstartstats = 0;
			return;
		}
		
		if (task_state == 'Z') {
			CONDEXEC(
				DEBUGEXECN(25, INFOPRINTCOLOR(GY_COLOR_YELLOW_ITALIC, "PID %d is a Zombie Task. Process IO will not be checked\n", pid););
			);	

			tstartstats = 0;
			return;
		}	

		init_vm_mb = GY_DOWN_MB(vmsize);

		task_stopped_hist[0] = ((task_state == 'T' || task_state == 'D') ? task_state : 0);

		if (pis_kthread) {
			is_kthread = *pis_kthread;
		}	
		else {
			uint32_t 		task_flags, task_rt_priority, task_sched_policy;
			uint64_t 		starttimeusec; 
			int64_t 		task_priority, task_nice; 
			pid_t			tppid;
			char			tstate;

			ret = get_proc_stat(pid, tppid, tstate, task_flags, starttimeusec, task_priority, task_nice, task_rt_priority, task_sched_policy);
			if (ret == 0) {
				is_kthread = is_task_kthread(task_flags);
			}	

			DEBUGEXECN(25, INFOPRINTCOLOR(GY_COLOR_YELLOW_ITALIC, "PID %d is a Kernel Thread. Process IO will not be checked\n", pid););
		}
			
		if (false == is_kthread) {	
			ret = gy_task_io_stats(pid, tid, &cumul_rchar, &cumul_wchar, &cumul_syscr, &cumul_syscw, &cumul_read_bytes, &cumul_write_bytes, monitor_whole_proc);
			if (ret != 0) {
				last_errno = errno;

				CONDEXEC(
					DEBUGEXECN(25, PERRORPRINT("Could not get Thread/Proc IO statistics for PID %d Thread %d", pid, tid););
				);	
				tstartstats = 0;
			}
		}	
	}

	PROC_CPU_IO_STATS(const PROC_CPU_IO_STATS &) noexcept			= default;
	PROC_CPU_IO_STATS(PROC_CPU_IO_STATS &&) noexcept			= default;
	PROC_CPU_IO_STATS & operator=(const PROC_CPU_IO_STATS &) noexcept	= default;
	PROC_CPU_IO_STATS & operator=(PROC_CPU_IO_STATS &&)	noexcept	= default;

	~PROC_CPU_IO_STATS() noexcept						= default;
	
	int get_current_stats(bool print_stats = false) noexcept
	{
		uint64_t		aminflt = 0, amajflt = 0, ausertime = 0, asystime = 0, avmsize = 0, arss = 0, ablkio_ticks = 0, anum_threads = 0;
		uint64_t		archar = 0, awchar = 0, asyscr = 0, asyscw = 0, aread_bytes = 0, awrite_bytes = 0;
		char			task_state;

		if (gy_unlikely(tstartstats == 0)) {
			return -1;
		}
			
		int ret = get_task_cpu_mem_stats(pid, tid, &aminflt, &amajflt, &ausertime, &asystime, &anum_threads, &avmsize, &arss, &ablkio_ticks, monitor_whole_proc, &task_state);
		if (ret != 0) {
			last_errno = errno;
			CONDEXEC(
				DEBUGEXECN(25, PERRORPRINT("Could not get Thread/Proc CPU/Memory statistics for PID %d Thread %d", pid, tid););
			);	
			tstartstats = 0;
			return -1;
		}
		else {
			uint64_t		currtime = get_nsec_clock();

			if (false == is_kthread) {	
				ret = gy_task_io_stats(pid, tid, &archar, &awchar, &asyscr, &asyscw, &aread_bytes, &awrite_bytes, monitor_whole_proc);
				if (ret != 0) {
					tstartstats = 0;
					last_errno = errno;
					CONDEXEC(
						DEBUGEXECN(25, PERRORPRINT("Could not get Thread/Proc IO statistics for PID %d Thread %d", pid, tid););
					);	
					return -1;
				}

				diff_rchar 		= gy_diff_counter_safe(archar, cumul_rchar);
				diff_wchar 		= gy_diff_counter_safe(awchar, cumul_wchar);
				diff_syscr 		= gy_diff_counter_safe(asyscr, cumul_syscr);
				diff_syscw 		= gy_diff_counter_safe(asyscw, cumul_syscw);
				diff_read_bytes 	= gy_diff_counter_safe(aread_bytes, cumul_read_bytes);
				diff_write_bytes 	= gy_diff_counter_safe(awrite_bytes, cumul_write_bytes);
			}	

			diff_minflt 		= gy_diff_counter_safe(aminflt, cumul_minflt);
			diff_majflt 		= gy_diff_counter_safe(amajflt, cumul_majflt);
			diff_usertime 		= gy_diff_counter_safe(ausertime, usertime);
			diff_systime 		= gy_diff_counter_safe(asystime, systime);
			diff_blkio_ticks 	= gy_diff_counter_safe(ablkio_ticks, blkio_ticks);

			int64_t			diffticks = (currtime - tstartstats) / (GY_NSEC_PER_SEC / gy_clk_tck());
			float			usercpupct, syscpupct, blkiodelaypct;

			if (diffticks == 0) 	diffticks = 1;

			usercpupct 		= (float)diff_usertime /  diffticks * 100;
			syscpupct 		= (float)diff_systime /  diffticks * 100;
			blkiodelaypct 		= (float)diff_blkio_ticks /  diffticks * 100;

			array_shift_right(usercpu_pct_hist, 	MAX_PROC_HIST_STATS);
			array_shift_right(syscpu_pct_hist,	MAX_PROC_HIST_STATS);
			array_shift_right(blkiodelay_pct_hist,	MAX_PROC_HIST_STATS);
			array_shift_right(majflt_hist,		MAX_PROC_HIST_STATS);
			array_shift_right(task_stopped_hist,	MAX_PROC_HIST_STATS);

			usercpu_pct_hist[0] 	= usercpupct;
			syscpu_pct_hist[0] 	= syscpupct;
			blkiodelay_pct_hist[0] 	= blkiodelaypct;
			majflt_hist[0]		= (int16_t)diff_majflt;
			task_stopped_hist[0] 	= ((task_state == 'T' || task_state == 'D') ? task_state : 0);
		
			int			cpupct = usercpupct + syscpupct;

			if (cpupct > max_cpu_pct) {
				max_cpu_pct 	= cpupct;
			}	
			total_cpu_pct		+= cpupct;

			nitervals++;
			
			diff_vmsize 		= avmsize - vmsize;
			diff_rss 		= arss - rss;
			diff_num_threads 	= anum_threads - num_threads;

			toldstart 		= tstartstats;
			tstartstats 		= currtime;

			cumul_minflt 		= aminflt;
			cumul_majflt 		= amajflt;
			usertime 		= ausertime;
			systime 		= asystime;
			blkio_ticks 		= ablkio_ticks;

			cumul_rchar 		= archar;
			cumul_wchar 		= awchar;
			cumul_syscr 		= asyscr;
			cumul_syscw 		= asyscw;
			cumul_read_bytes 	= aread_bytes;
			cumul_write_bytes 	= awrite_bytes;

			vmsize 			= avmsize;
			rss 			= arss;
			num_threads 		= anum_threads;

			if (print_stats) {
				print_current();
			}
				
			return 0;
		}
	}

	int get_last_errno() const noexcept
	{
		return last_errno;
	}
		
	uint64_t get_last_stats_time() const noexcept
	{
		return tstartstats;	
	}
			
	uint64_t get_rss_mb() const noexcept
	{
		return GY_DOWN_MB(rss);
	}

	void print_current(uint64_t uptime_sec = 0, const char * comm = nullptr) const noexcept
	{
		if (toldstart && tstartstats) {
			char			tbuf[1200];
			STR_WR_BUF		strbuf(tbuf, sizeof(tbuf));

			print_current(strbuf, uptime_sec, comm);

			INFOPRINTCOLOR(GY_COLOR_YELLOW_ITALIC, "%s\n", tbuf);
		}
	}

	char * print_current(STR_WR_BUF & strbuf, uint64_t uptime_sec = 0, const char * comm = nullptr) const noexcept
	{
		if (toldstart && tstartstats && nitervals) {
			int			majflt3 = 0;

			strbuf.appendfmt("%s %s %d Statistics : CPU/Mem/IO Stats for Interval of %.09f sec : "
				"[Interval User CPU Usage %.03f%%, Sys CPU Usage %.03f%%, Blkio Delay %.03f%%, ",

				monitor_whole_proc ? "Process" : "Thread", comm ? comm : "ID", monitor_whole_proc ? pid : tid, 
				(tstartstats - toldstart)/1.0f/GY_NSEC_PER_SEC, 
				usercpu_pct_hist[0], syscpu_pct_hist[0], blkiodelay_pct_hist[0]);

			strbuf.appendfmt("Previous %d Stats :", MAX_PROC_HIST_STATS - 1);

			strbuf.appendconst(" User CPU %% [");
			for (int i = 1; i < MAX_PROC_HIST_STATS; i++) {
				strbuf.appendfmt("%.03f%%,", usercpu_pct_hist[i]);
			}
			strbuf.set_last_char(']');
				 
			strbuf.appendconst(", Sys CPU %% [");
			for (int i = 1; i < MAX_PROC_HIST_STATS; i++) {
				strbuf.appendfmt("%.03f%%,", syscpu_pct_hist[i]);
			}
			strbuf.set_last_char(']');

			strbuf.appendconst(", Blkio Delay %% [");
			for (int i = 1; i < MAX_PROC_HIST_STATS; i++) {
				strbuf.appendfmt("%.03f%%,", blkiodelay_pct_hist[i]);
			}
			strbuf.set_last_char(']');

			strbuf.appendconst(", ");

			for (int i = 0; i < MAX_PROC_HIST_STATS; i++) {
				majflt3 += majflt_hist[i];
			}

			strbuf.appendfmt(
				"Avg CPU Use %d%%, Max CPU Use %d%%, Current Interval User Time %d ticks, Sys Time %d ticks, Blkio delay %d ticks], %s"
				"[Current Virtual Memory %lu MB, RSS %lu MB, Diff VM %ld MB, Diff RSS %ld MB, Startup VM %d MB], "
				"[Num Threads %lu, Diff Threads %d], "
				"[Interval Minor Page Faults %d, Major Page Fault %d, Last %d periods Major Faults %d, Total Minor Faults %lu, Total Major Faults %lu], "
				"[Interval Bytes Read %ld, Bytes Written %ld, Read Syscalls %ld, Write Syscalls %ld, Disk Bytes Read %ld, Disk Bytes Written %ld], "
				"[Total Bytes Read %lu, Total Bytes Written %lu, Total Read Syscalls %lu, Total Write Syscalls %lu"
				", Total Disk Bytes Read %lu, Total Disk Bytes Written %lu]",
				total_cpu_pct/nitervals, max_cpu_pct, diff_usertime, diff_systime, diff_blkio_ticks, 
				task_stopped_hist[0] ? "[State : Stopped], " : task_stopped_int ? "[State : Recently Stopped], " : "",
				GY_DOWN_MB(vmsize), GY_DOWN_MB(rss), GY_DOWN_MB(diff_vmsize), GY_DOWN_MB(diff_rss), init_vm_mb, num_threads, diff_num_threads,
				diff_minflt, diff_majflt, MAX_PROC_HIST_STATS, majflt3, cumul_minflt, cumul_majflt,
				diff_rchar, diff_wchar, diff_syscr, diff_syscw, diff_read_bytes, diff_write_bytes, 
				cumul_rchar, cumul_wchar, cumul_syscr, cumul_syscw, cumul_read_bytes, cumul_write_bytes);

			if (!uptime_sec && pid == getpid()) {
				uptime_sec = get_process_uptime_sec();
			}
					
			if (uptime_sec) {
				char		uptime_buf[128];

				strbuf.appendfmt(", [Process Uptime : %s]", get_time_diff_string(uptime_sec, uptime_buf, sizeof(uptime_buf)));
			}
		}

		strbuf.append('\n');

		return strbuf.buffer();
	}

	static PROC_CPU_IO_STATS * 		get_singleton() noexcept;

	static int				init_singleton(int secs_duration = 60, const char * identifier = nullptr);
};


/*
 * Scope based locking class for safe locking.
 *
 * To extend the scope of the lock, a nullptr plock can be called in the constructor and later obj1.setlock(<Pointer to actual mutex>)
 * can be called from a reduced scope OR the move constructor OR move assignment may be invoked.
 *
 * To use the trylock() method, use the is_non_block constructor.
 */ 
template <
	typename Tlock 			= ::pthread_mutex_t, 
	int (*M_Lock)(Tlock *) 		= ::pthread_mutex_lock, 
	int (*M_unlock)(Tlock *) 	= ::pthread_mutex_unlock, 
	int (*M_trylock)(Tlock *) 	= ::pthread_mutex_trylock,
	void (*M_sleepcallback)(void)	= nullptr			// Callback to indicate the thread may be blocked
	>
class SCOPE_LOCK_INT
{
protected :	
	Tlock				*plock_		{nullptr};	

public :
	using SLEEP_CB_TYPE 		= decltype(M_sleepcallback);

	/*
	 * The default constructor is purposefully deleted so as to error out any unintended constructor call
	 * with no locks. If a delayed/lazy locking is needed, the lock can be specified as nullptr in the constructor
	 * below, followed by a subsequent setlock() call later...
	 */
	SCOPE_LOCK_INT()		= delete;

	explicit SCOPE_LOCK_INT(Tlock *plock) noexcept : plock_(plock) 
	{
		if (plock) {
			M_Lock(plock);
		}
	}	

	explicit SCOPE_LOCK_INT(Tlock & lock) noexcept : plock_(&lock) 
	{
		M_Lock(&lock);
	}	

	// Non blocking constructor. After construction, check is_success to see if non block lock was successful
	SCOPE_LOCK_INT(Tlock *plock, const bool is_non_block, bool & is_success) noexcept
	{
		if (plock) {
			if (is_non_block) {
				is_success = !trylock(plock);
			}
			else {
				plock_	 	= plock;
				
				is_success = !M_Lock(plock);
			}
		}
		else {
			is_success = false;
		}	
	}	
		
	SCOPE_LOCK_INT(SCOPE_LOCK_INT && other) noexcept 
	{
		plock_ 		= std::exchange(other.plock_, nullptr);
	}	

	SCOPE_LOCK_INT & operator= (SCOPE_LOCK_INT && other) noexcept
	{
		if (this != &other) {

			if (this->plock_ != other.plock_) {
				(void)this->unlock();
			}

			plock_ 	= std::exchange(other.plock_, nullptr);
		}
		
		return *this;
	}

	~SCOPE_LOCK_INT() noexcept
	{
		(void)this->unlock();
	}

	SCOPE_LOCK_INT(const SCOPE_LOCK_INT &)				= delete;

	SCOPE_LOCK_INT & operator= (const SCOPE_LOCK_INT & other) 	= delete;

	int setlock(Tlock *plock) noexcept
	{
		assert(plock_ == nullptr);

		plock_ = plock;
		
		if (plock) {
			return M_Lock(plock);
		}
		return 0;	
	}

	// Returns 0 if lock successful
	int trylock(Tlock *plock) noexcept
	{
		assert(plock_ == nullptr);
		
		int		ret = M_trylock(plock);

		if (ret == 0) {
			plock_ = plock;
			return 0;
		}

		return ret;
	}
		
	int unlock(void) noexcept
	{
		if (plock_) {
			int 		ret = M_unlock(plock_);

			plock_ = nullptr;
			return ret;
		}
		
		return 0;
	}
	
	void force_set_locked(Tlock *plock) noexcept
	{
		plock_ = plock;
	}	

	bool is_locked() const noexcept
	{
		return (plock_ != nullptr);
	}	

	static constexpr SLEEP_CB_TYPE get_sleep_callback() noexcept
	{
		return M_sleepcallback;
	}	
};

using 		SCOPE_PTHR_MUTEX = SCOPE_LOCK_INT<::pthread_mutex_t, ::pthread_mutex_lock, ::pthread_mutex_unlock, ::pthread_mutex_trylock>;
using 		SCOPE_GY_MUTEX = SCOPE_LOCK_INT<GY_MUTEX, gyeeta::gy_mutex_proc_lock, gyeeta::gy_mutex_proc_unlock, gyeeta::gy_mutex_proc_trylock>;

// 		Use NULL_MUTEX or NULL_PTHR_MUTEX only for single threaded cases or where external sync done...
using 		NULL_PTHR_MUTEX = SCOPE_LOCK_INT<pthread_mutex_t, gyeeta::no_mutex_lock, gyeeta::no_mutex_lock, gyeeta::no_mutex_lock>; // No locking/unlocking
using 		NULL_MUTEX = SCOPE_LOCK_INT<GY_MUTEX, gyeeta::gy_no_mutex_lock, gyeeta::gy_no_mutex_lock, gyeeta::gy_no_mutex_lock>; // No locking/unlocking

using 		SCOPE_SPINLOCK = SCOPE_LOCK_INT<::pthread_spinlock_t, ::pthread_spin_lock, ::pthread_spin_unlock, ::pthread_spin_trylock>;

// 		Anonymous scope constructor
#define		SET_SCOPE_GY_MUTEX(_mutex)	SCOPE_GY_MUTEX(_mutex)

class MULTI_PROC_MUTEX_INFO
{
public :	
	typedef 			void (*MUTEX_DEAD_CB)(void *arg1, void * arg2);

	std::atomic <int>		nprocs_attached_	{0};
	MUTEX_DEAD_CB			const callback_;
	void				* const arg1_;
	void				* const arg2_;
	pid_t				cb_pid_;		// Call the callback only from this PID. Set as 0 if needed in all procs, -1 if none

	MULTI_PROC_MUTEX_INFO(pid_t cb_pid = -1, MUTEX_DEAD_CB callback = nullptr, void *arg1 = nullptr, void *arg2 = nullptr) noexcept
		: callback_(callback), arg1_(arg1), arg2_(arg2), cb_pid_(cb_pid)
	{}	
};
		
class GY_MUTEX
{
protected :	
	::pthread_mutex_t			mutex_;
	union {
		MULTI_PROC_MUTEX_INFO		*pshm_info_;
		uint64_t			is_multi_proc_;
	};						

public :	
	GY_MUTEX() noexcept : is_multi_proc_(0ul)
	{ 	
		init_mutex(false);
	}	

	explicit GY_MUTEX(bool is_multi_proc) : is_multi_proc_(is_multi_proc ? 1ul : 0ul)
	{
		int			ret;

		ret = init_mutex(is_multi_proc);
		if (ret != 0) {
			GY_THROW_SYS_EXCEPTION("Failed to initialize mutex");
		}	
	}	

	/*
	 * Use a placement new operator with mmap'ed memory...
	 *
	 * XXX The pshm_info must be initialized externally and the pshm_info must be a part of a mmap'ed memory
	 * segment as it will be shared across processes.
	 */ 
	explicit GY_MUTEX(MULTI_PROC_MUTEX_INFO *pshm_info) : pshm_info_(pshm_info)
	{
		int			ret;

		assert(pshm_info);

		ret = init_mutex(true);
		if (ret != 0) {
			GY_THROW_SYS_EXCEPTION("Failed to initialize multi process mutex");
		}	

		pshm_info_->nprocs_attached_.fetch_add(1, std::memory_order_release);
	}	

	GY_MUTEX(const GY_MUTEX & other)		= delete;
	GY_MUTEX(GY_MUTEX && other)			= delete;

	GY_MUTEX & operator= (const GY_MUTEX &)		= delete;
	GY_MUTEX & operator= (GY_MUTEX &&)		= delete;

	~GY_MUTEX() noexcept
	{
		if (gy_unlikely(multi_proc_mutex_info())) {
			int		nproc = pshm_info_->nprocs_attached_.fetch_sub(1, std::memory_order_acquire);
			
			if (nproc <= 1) {
				::pthread_mutex_destroy(&mutex_);
			}	
		}	
		else {
			::pthread_mutex_destroy(&mutex_);
		}	
	}	

	pthread_mutex_t * get() noexcept
	{
		return &mutex_;
	}	

	bool is_multi_process() const noexcept
	{
		return !!is_multi_proc_;
	}	

	bool multi_proc_mutex_info() const noexcept
	{
		return (is_multi_proc_ > 1ul);
	}	

	int get_nprocs_attached() const noexcept
	{
		if (gy_unlikely(multi_proc_mutex_info())) {
			return pshm_info_->nprocs_attached_.load(std::memory_order_acquire);
		}
		return 1;	
	}	

	void call_proc_dead_callback() noexcept
	{
		if (multi_proc_mutex_info()) {
			pshm_info_->nprocs_attached_.fetch_sub(1);

			try {
				if ((pshm_info_->cb_pid_ == getpid()) || (pshm_info_->cb_pid_ == 0)) {
					pshm_info_->callback_(pshm_info_->arg1_, pshm_info_->arg2_);	
				}	
			}
			catch(...) {
			}		
		}
	}
			
private :

	int init_mutex(bool is_multi_proc) noexcept
	{
		int			ret;
		::pthread_mutexattr_t 	sh_mattr, *pattr = nullptr;

		if (gy_unlikely(is_multi_proc)) {
			ret = ::pthread_mutexattr_init(&sh_mattr);
			if (ret != 0) {
				errno = ret;
				return -1;
			}	
			::pthread_mutexattr_setpshared(&sh_mattr, PTHREAD_PROCESS_SHARED);
			::pthread_mutexattr_setrobust(&sh_mattr, PTHREAD_MUTEX_ROBUST);

			pattr = &sh_mattr;
		}

		ret = ::pthread_mutex_init(&mutex_, pattr); 
		if (ret != 0 && ret == EBUSY) {
			ret = 0;
		}	

		if (gy_unlikely(pattr)) {
			::pthread_mutexattr_destroy(&sh_mattr);
		}	

		if (ret != 0) {
			errno = ret;
		}	
		return ret;
	}		
};
	
/*
 * A simple condition variable wrapper class
 */ 
template <typename ScopeLock = SCOPE_GY_MUTEX>	
class COND_VAR
{
protected :	
	GY_MUTEX			mutex_;
	::pthread_cond_t		cond_;

public :
	/*
	 * Single Process constructor
	 */
	COND_VAR() noexcept 
	{ 	
		init_cond(false);
	}	

	/*
	 * For is_multi_proc, use a placement new operator with mmap'ed memory...
	 */ 
	explicit COND_VAR(bool is_multi_proc) : mutex_(is_multi_proc)
	{ 	
		int		ret;

		ret = init_cond(is_multi_proc);
		if (ret != 0) {
			GY_THROW_SYS_EXCEPTION("Failed to initialize cond variable");
		}	
	}	

	/*
	 * Multi-Process constructor : Use a placement new operator with mmap'ed memory...
	 *
	 * XXX The pshm_info must be initialized externally and the pshm_info must be a part of a mmap'ed memory
	 * segment as it will be shared across processes.
	 */ 
	explicit COND_VAR(MULTI_PROC_MUTEX_INFO *pshm_info) : mutex_(pshm_info)
	{ 	
		int		ret;

		ret = init_cond(true);
		if (ret != 0) {
			GY_THROW_SYS_EXCEPTION("Failed to initialize multi process cond variable");
		}	
	}	

	COND_VAR(const COND_VAR & other)	= delete;
	COND_VAR(COND_VAR && other)		= delete;

	COND_VAR & operator= (const COND_VAR &)	= delete;
	COND_VAR & operator= (COND_VAR &&)	= delete;

	~COND_VAR() noexcept
	{
		// For multi-process, we may leave the process-shared cond undestroyed if attached process exited ungracefully
		if ((!is_multi_process()) || (mutex_.multi_proc_mutex_info() && (1 == mutex_.get_nprocs_attached()))) {
			::pthread_cond_destroy(&cond_);
		}
	}	
	
	/*
	 * The FCB to_signal_cb is called under mutex lock. It can be used to do stuff under mutex lock and check whether signal is needed or not.
	 * Return true from fcb if pthread_cond_signal() needed
	 *
	 * Returns whether signal done or not.
	 */ 
	template <typename FCB>
	bool cond_signal(FCB & to_signal_cb) noexcept(noexcept(to_signal_cb()))
	{
		ScopeLock	lock(&mutex_);
		
		bool		to_signal = to_signal_cb();	
		
		if (to_signal) {
			::pthread_cond_signal(&cond_);
		}	

		return to_signal;
	}	

	/*
	 * The FCB to_signal_cb is called under mutex lock. It can be used to do stuff under mutex lock and check whether signal is needed or not.
	 * Return true from fcb if pthread_cond_broadcast() needed
	 *
	 * Returns whether signal done or not.
	 */ 
	template <typename FCB>
	bool cond_broadcast(FCB & to_signal_cb) noexcept(noexcept(to_signal_cb()))
	{
		ScopeLock	lock(&mutex_);
		
		bool		to_signal = to_signal_cb();	
		
		if (to_signal) {
			::pthread_cond_broadcast(&cond_);
		}	

		return to_signal;
	}	

	/*
	 * The FCB to_wait_cb is called under mutex lock. It can be used to do stuff under mutex lock and finally wait for the signal
	 *
	 * The FCB success_fcb is also called under mutex lock only if the cond wait was successful. It can be used to do cleanup stuff under mutex lock. 
	 *
	 * Return true from to_wait_cb if conditional wait needed. The to_wait_cb() may be called multiple times.
	 */ 
	template <typename FCB, typename FCB2>
	int cond_wait(FCB & to_wait_cb, FCB2 & success_fcb) noexcept(noexcept(to_wait_cb()) && noexcept(success_fcb()))
	{
		int		ret = 0;	

		if (ScopeLock::get_sleep_callback()) {
			try {
				(*ScopeLock::get_sleep_callback())();
			}
			catch(...) {
			}	
		}
			
		ScopeLock	lock(&mutex_);
		
		while ((true == to_wait_cb()) && ret == 0) {
			ret = ::pthread_cond_wait(&cond_, mutex_.get());
		}	

		if ((ret == 0) || (false == to_wait_cb())) {
			success_fcb();

			return 0;
		}	
		else if (ret == EOWNERDEAD) {
			if (is_multi_process()) {
				ret = ::pthread_mutex_consistent(mutex_.get());

				mutex_.call_proc_dead_callback();
			}	
		}	
		
		return ret;
	}	

	/*
	 * Timed Conditional Wait. The msec_to_wait msec will be considered from the time seen after locking the internal mutex.
	 * If an absolute time is needed, use the cond_timed_wait() with the timespec param instead.
	 * 
	 * The FCBwait to_wait_cb is called under mutex_ lock. It can be used to do stuff under mutex_ lock and finally wait for the signal.
	 * The to_wait_cb() will be called multiple times.  Return true from to_wait_cb() if conditional wait is needed.
	 *
	 * The FCBerr timeout_cb will be called if the timed wait failed, for e.g. on timeout or if the other process exited while holding the mutex
	 * The timeout_cb is also called under mutex locking.
	 *
	 * The FCBsuccess success_cb will be called only if the timed wait was successful and is also called under mutex locking
	 */ 
	template <typename FCBwait, typename FCBerr, typename FCBsuccess>
	int cond_timed_wait(FCBwait & to_wait_cb, FCBerr & timeout_cb, FCBsuccess & success_cb, uint64_t msec_to_wait) 
					noexcept(noexcept(to_wait_cb()) && noexcept(timeout_cb()) && noexcept(success_cb()))
	{
		int			ret = 0;	
		struct timespec		ts;

		if (ScopeLock::get_sleep_callback()) {
			try {
				(*ScopeLock::get_sleep_callback())();
			}
			catch(...) {
			}	
		}
			
		ScopeLock		lock(&mutex_);
		
		if (false == to_wait_cb()) {
			success_cb();
			return 0;	
		}		

		clock_gettime(CLOCK_REALTIME, &ts);

		add_to_timespec(ts, msec_to_wait);

		while ((true == to_wait_cb()) && ret == 0) {
			ret = ::pthread_cond_timedwait(&cond_, mutex_.get(), &ts);
		}	

		if ((ret == 0) || (false == to_wait_cb())) {
			success_cb();
			return 0;
		}	
		else if (ret == EOWNERDEAD) {
			if (is_multi_process()) {
				ret = ::pthread_mutex_consistent(mutex_.get());

				mutex_.call_proc_dead_callback();
			}	
		}	
		
		timeout_cb();

		return ret;
	}	

	/*
	 * Timed Conditional Wait with the future timeout CLOCK_REALTIME timespec passed. Also see the above relative timeout comments.
	 */ 
	template <typename FCBwait, typename FCBerr, typename FCBsuccess>
	int cond_timed_wait(FCBwait & to_wait_cb, FCBerr & timeout_cb, FCBsuccess & success_cb, struct timespec tstimeout) 
					noexcept(noexcept(to_wait_cb()) && noexcept(timeout_cb()) && noexcept(success_cb()))
	{
		int			ret = 0;	

		if (ScopeLock::get_sleep_callback()) {
			try {
				(*ScopeLock::get_sleep_callback())();
			}
			catch(...) {
			}	
		}
			
		ScopeLock		lock(&mutex_);
		
		if (false == to_wait_cb()) {
			success_cb();
			return 0;	
		}		

		while ((true == to_wait_cb()) && ret == 0) {
			ret = ::pthread_cond_timedwait(&cond_, mutex_.get(), &tstimeout);
		}	

		if ((ret == 0) || (false == to_wait_cb())) {
			success_cb();
			return 0;
		}	
		else if (ret == EOWNERDEAD) {
			if (is_multi_process()) {
				ret = ::pthread_mutex_consistent(mutex_.get());

				mutex_.call_proc_dead_callback();
			}	
		}	
		
		timeout_cb();

		return ret;
	}	

	bool is_multi_process() const noexcept
	{
		return mutex_.is_multi_process();
	}	

private :
	int init_cond(bool is_multi_proc) noexcept
	{
		::pthread_condattr_t 	sh_cattr, *pattr;
		int			ret;	

		if (false == is_multi_proc) {
			pattr = nullptr;
		}
		else {	
			ret = ::pthread_condattr_init(&sh_cattr);	
			if (ret) {
				errno = ret;
				return -1;
			}

			::pthread_condattr_setpshared(&sh_cattr, PTHREAD_PROCESS_SHARED);
			
			pattr = &sh_cattr;
		}

		ret = ::pthread_cond_init(&cond_, pattr); 
		if (ret != 0 && ret != EBUSY) {

			if (pattr) {
				int olderr = errno;

				::pthread_condattr_destroy(&sh_cattr);
				errno = olderr;
			}
				
			return -1;
		}	

		if (pattr) {
			::pthread_condattr_destroy(&sh_cattr);
		}

		return 0;
	}		
};
	
	
/*
 * Wrapper for pthread spinlock
 */
class GY_SPINLOCK
{
public :	
	::pthread_spinlock_t		spinlock_;

	/*
	 * If is_multi_proc, use a placement new operator with mmap'ed memory...
	 */ 
	GY_SPINLOCK(bool is_multi_proc = false) noexcept 
	{ 	
		::pthread_spin_init(&spinlock_, is_multi_proc ? PTHREAD_PROCESS_SHARED : PTHREAD_PROCESS_PRIVATE);
	}	

	GY_SPINLOCK(const GY_SPINLOCK & other)		= delete;
	GY_SPINLOCK(GY_SPINLOCK && other)		= delete;

	GY_SPINLOCK & operator= (const GY_SPINLOCK &)	= delete;
	GY_SPINLOCK & operator= (GY_SPINLOCK &&)	= delete;

	~GY_SPINLOCK() noexcept
	{
		::pthread_spin_destroy(&spinlock_);
	}	

	pthread_spinlock_t * get() noexcept
	{
		return &spinlock_;
	}	
};
		

/*
 * Wrapper for pthread barriers
 */
class GY_PTHR_BARRIER
{
public :	
	::pthread_barrier_t		barrier_;
	gy_atomic<int>			nwaits_		{0};
	const uint32_t			nthreads_;

	GY_PTHR_BARRIER()		= delete;

	/*
	 * If is_multi_proc, use a placement new operator with mmap'ed memory...
	 */ 
	GY_PTHR_BARRIER(uint32_t nthreads, bool is_multi_proc = false) 
		: nthreads_(nthreads)
	{ 	
		::pthread_barrierattr_t	attr, *pattr = nullptr;
		int			ret;

		assert(nthreads > 0);

		if (is_multi_proc) {
			pattr = &attr;

			::pthread_barrierattr_init(pattr);
			::pthread_barrierattr_setpshared(pattr, PTHREAD_PROCESS_SHARED);
		}	

		ret = ::pthread_barrier_init(&barrier_, pattr, nthreads_);

		if (pattr) {
			::pthread_barrierattr_destroy(pattr);
		}

		if (ret) {
			errno = ret;
			GY_THROW_SYS_EXCEPTION("Failed to initialize barrier");
		}	
	}	

	GY_PTHR_BARRIER(const GY_PTHR_BARRIER & other)		= delete;
	GY_PTHR_BARRIER(GY_PTHR_BARRIER && other)		= delete;

	GY_PTHR_BARRIER & operator= (const GY_PTHR_BARRIER &)	= delete;
	GY_PTHR_BARRIER & operator= (GY_PTHR_BARRIER &&)	= delete;

	~GY_PTHR_BARRIER() noexcept
	{
		::pthread_barrier_destroy(&barrier_);
	}	

	void wait_barrier() noexcept
	{
		nwaits_.fetch_add_relaxed(1, std::memory_order_relaxed);

		::pthread_barrier_wait(&barrier_);

		nwaits_.store(0, std::memory_order_relaxed);
	}	

	size_t get_approx_waiting_threads() const noexcept
	{
		return nwaits_.load(std::memory_order_relaxed);
	}	

	size_t get_max_threads() const noexcept
	{
		return nthreads_;
	}	

	pthread_barrier_t * get() noexcept
	{
		return &barrier_;
	}	
};
		
/*
 * std::thread analogous class for joinable pthreads but with RAII (similar to C++20 std::jthread)
 * On Destructor, the thread created will be waited for (unless wait_indefinitely_if_timeout_quit argument is specified false)
 * with optional signal SIGUSR2 done to specify exit. 
 * Also with option to signal the constructor that init within spawned thread is completed.
 * 
 * See comments for the constructor below
 */ 	
class GY_THREAD
{
public :
	typedef void 					(* PTHREAD_STOP_PTR) (void *);

	enum {
		THR_STATUS_UNINIT	= 0,
		THR_STATUS_SPAWNING,
		THR_STATUS_FAILED_INIT,
		THR_STATUS_INIT,
		THR_STATUS_STOP,
	};
		
	pthread_t					tid_					{0};
	PTHREAD_FUNC_PTR				func_					{nullptr};
	void						*arg_					{nullptr};
	void						*opt_thread_arg1_			{nullptr};
	void						*opt_thread_arg2_			{nullptr};
	std::unique_ptr<COND_VAR <SCOPE_GY_MUTEX>>	cond_;
	char						pname_[32]				{};
	PTHREAD_STOP_PTR				stop_func_				{nullptr};
	void *						stop_func_arg_				{nullptr};
	std::atomic <int>				status_					{THR_STATUS_UNINIT};	
	uint32_t					max_stack_sz_				{128 * 1024};
	uint32_t					max_msecs_for_thr_init_			{0};
	int 						max_msecs_to_wait_for_quit_signal_	{0};
	bool						thr_func_calls_init_done_		{false};
	bool						throw_on_init_timeout_			{false};
	bool 						use_signal_after_timeout_quit_		{false};
	bool 						wait_indefinitely_if_timeout_quit_	{true};

	/*
	 * Constructor arguments :
	 *
	 * thread_desc				=>	Name/Description for logging
	 * func					=>	The function the new thread will run
	 * arg					=>	The thread function argument. Set as nullptr if 'this' itself needs to be set as argument. See set_arg_as_this_if_null below
	 * opt_thread_arg1			=>	Any additional argument to be referenced by the spawned thread subsequently using this->get_opt_args()
	 * opt_thread_arg2			=>	Any additional argument to be referenced by the spawned thread subsequently using this->get_opt_args()
	 *
	 * start_immed				=>	Start the new thread within the constructor itself. If false, users need to explicitly call start_thread() method when needed
	 *
	 * max_stack_sz				=>	The new thread stack space (Default is 128 KB)
	 *
	 * max_msecs_to_wait_for_quit_signal	=>	On stop_thread() or on destructor, will run the stop_func() and then wait for these msecs (if < 0 indefinite) before 
	 * 						sending a SIGUSR2 signal if configured.
	 * use_signal_after_timeout_quit	=>	If max_msecs_to_wait_for_quit_signal time has expired while waiting for thread exit, will send SIGUSR2
	 *
	 * wait_indefinitely_if_timeout_quit	=>	After signal sent, will do a blocking wait for the thread to return : Note if false then do not reference 'this'
	 * 						within the spawned thread as it may result in a dangling pointer reference as the destructor will return without
	 *						joining the spawned thread
	 *
	 * thr_func_calls_init_done		=>	If true and max_msecs_for_thr_init > 0, the constructor will wait for the spawned thread to call set_thread_init_done(). If
	 * 						the thread init has failed, the spawned thread should call this->set_thread_init_done(false) so that the waiting constructor 
	 * 						will then throw an exception. Max wait time for constructor is max_msecs_for_thr_init argument.
	 * max_msecs_for_thr_init		=>	See comment above for thr_func_calls_init_done. 
	 *
	 * throw_on_init_timeout		=>	If the max_msecs_for_thr_init has expired, should the constructor throw an exception. If false, an error msg is printed.
	 * 						If true, will pthread_detach the spawned thread first and then throw an exception. We do not wait for thread to exit...
	 *						XXX Use caution here as the GY_THREAD object will not be constructed completely if this is true. Please ensure that
	 *						the thread spawned does not access the thread object after the init timeout...
	 *
	 * stop_func				=>	If non-nullptr, on stop_thread(), will invoke this callback passing the stop_func_arg as well
	 * stop_func_arg			=>	Argument to be passed to the stop_func_arg see above
	 *
	 * pthread_attr				=>	Specify if custom pthread attributes needed. max_stack_sz will be ignored as assumed it is set within pthread_attr.
	 * 						If start_immed == false, then pass the same pthread_attr to start_thread()
	 *
	 * set_arg_as_this_if_null		=>	If arg == nullptr and set_arg_as_this_if_null == true, will set arg_ as 'this' pointer	
	 *						This handles the case when the address of the GY_THREAD object needs to be itself passed as arg to thread
	 *
	 * NOTE : The SIGUSR2 signal will only be sent if the current SIGUSR2 handler is the GY_SIGNAL_HANDLER::gempty_sighdlr()
	 *
	 * The spawned thread should periodically call this->is_thread_stop_signalled() in case another way to signal thread to quit is not implemented as
	 * when stop_thread() is invoked, the atomic variable to stop is set which will be checked within the is_thread_stop_signalled()
	 *
	 */
	GY_THREAD(const char * thread_desc, PTHREAD_FUNC_PTR func, void *arg, void * opt_thread_arg1 = nullptr, void *opt_thread_arg2 = nullptr, bool start_immed = true, \
		uint32_t max_stack_sz = 128 * 1024, int max_msecs_to_wait_for_quit_signal = 0, bool use_signal_after_timeout_quit = false, \
		bool wait_indefinitely_if_timeout_quit = true, bool thr_func_calls_init_done = false, uint32_t max_msecs_for_thr_init = 0, bool throw_on_init_timeout = false, \
		PTHREAD_STOP_PTR stop_func = nullptr, void * stop_func_arg = nullptr, pthread_attr_t *pthread_attr = nullptr, bool set_arg_as_this_if_null = true)

		: 
		func_(func), arg_(arg), opt_thread_arg1_(opt_thread_arg1), opt_thread_arg2_(opt_thread_arg2), stop_func_(stop_func), stop_func_arg_(stop_func_arg), 
		max_stack_sz_(max_stack_sz), max_msecs_for_thr_init_(max_msecs_for_thr_init), 		
		max_msecs_to_wait_for_quit_signal_(max_msecs_to_wait_for_quit_signal),
		thr_func_calls_init_done_(thr_func_calls_init_done), throw_on_init_timeout_(throw_on_init_timeout),
		use_signal_after_timeout_quit_(use_signal_after_timeout_quit),
		wait_indefinitely_if_timeout_quit_(wait_indefinitely_if_timeout_quit)
	{
		if (nullptr == arg_ && set_arg_as_this_if_null) {
			arg_ = this;
		}

		GY_STRNCPY(pname_, thread_desc, sizeof(pname_));

		if (thr_func_calls_init_done_ && max_msecs_for_thr_init_) {
			cond_ = std::make_unique<COND_VAR <SCOPE_GY_MUTEX>>();
		}
			
		if (start_immed) {
			start_thread(pthread_attr);	
		}		
	}		
	
	GY_THREAD(GY_THREAD && other) noexcept
		: tid_(other.tid_), func_(other.func_), arg_(other.arg_), opt_thread_arg1_(other.opt_thread_arg1_), opt_thread_arg2_(other.opt_thread_arg2_),
		cond_(std::move(other.cond_)), stop_func_(other.stop_func_), stop_func_arg_(other.stop_func_arg_), status_(other.status_.load(std::memory_order_relaxed)),
		max_stack_sz_(other.max_stack_sz_), max_msecs_for_thr_init_(other.max_msecs_for_thr_init_),  
		max_msecs_to_wait_for_quit_signal_(other.max_msecs_to_wait_for_quit_signal_), thr_func_calls_init_done_(other.thr_func_calls_init_done_),
		throw_on_init_timeout_(other.throw_on_init_timeout_), 
		use_signal_after_timeout_quit_(other.use_signal_after_timeout_quit_), wait_indefinitely_if_timeout_quit_(other.wait_indefinitely_if_timeout_quit_)
	{
		assert(other.opt_thread_arg1_ != &other && other.opt_thread_arg2_ != &other);

		GY_STRNCPY(pname_, other.pname_, sizeof(pname_));
		other.reset();
	}	

	GY_THREAD(const GY_THREAD &)			= delete;
	GY_THREAD & operator=(const GY_THREAD &)	= delete;
	GY_THREAD & operator=(GY_THREAD &&)		= delete;
		
	~GY_THREAD() noexcept
	{
		stop_thread();
	}

	void start_thread(pthread_attr_t *pthread_attr = nullptr)
	{
		int			ret;

		if (gy_unlikely(tid_ != 0 && (status_.load(std::memory_order_acquire) != THR_STATUS_UNINIT))) {
			// Already spawned
			return;
		}

		status_.store(THR_STATUS_SPAWNING, std::memory_order_release);
			
		if (nullptr == pthread_attr) {	
			ret = gy_create_thread(&tid_, func_, arg_, max_stack_sz_); 
		}
		else {
			ret = gy_create_thread_from_attr(&tid_, pthread_attr, func_, arg_);
		}		

		if (ret != 0) {
			GY_THROW_SYS_EXCEPTION("Failed to create thread for %s", pname_);
		}	

		if (thr_func_calls_init_done_ && max_msecs_for_thr_init_ && cond_) {

			DEBUGEXECN(1, INFOPRINTCOLOR(GY_COLOR_GREEN, "Thread Object for %s spawned thread and now waiting for %d msecs for init done signal\n",
				pname_, max_msecs_for_thr_init_);
			);

			auto lamchk = [this]() noexcept
			{ 
				if (THR_STATUS_SPAWNING == status_.load(std::memory_order_acquire)) {
					return true;
				}
				else {
					return false;
				}	
			};

			auto lamerr = [this]() noexcept 
			{
				PERRORPRINTCOLOR(GY_COLOR_RED, "Thread spawn initialization wait timed out for %s %s...", pname_, 
					throw_on_init_timeout_ == false ? "Not erroring out" : "");
			};	

			auto lamsuccess = []() noexcept {};

			ret = cond_->template cond_timed_wait<decltype(lamchk), decltype(lamerr), decltype(lamsuccess)>(lamchk, lamerr, lamsuccess, max_msecs_for_thr_init_);

			auto tstat = status_.load(std::memory_order_acquire);

			if (THR_STATUS_INIT != tstat) {

				if (tstat == THR_STATUS_FAILED_INIT) {
					ERRORPRINTCOLOR(GY_COLOR_RED, "Thread Object %s : Thread signalled init failed. Waiting for thread to return...\n", pname_);

					stop_thread();

					GY_THROW_EXCEPTION("Thread spawn for %s failed as thread has exited with failure after spawning", pname_);
				}
				else if (true == is_thread_exited()) {
					GY_THROW_EXCEPTION("Thread spawn for %s failed as thread has exited after spawning", pname_);
				}	
				else if (throw_on_init_timeout_ == true) {
					ERRORPRINTCOLOR(GY_COLOR_RED, "Thread spawn for %s initialization wait failed. Throwing an exception now...\n",
						pname_);

					pthread_detach(tid_);

					GY_THROW_EXCEPTION("Thread %s (tid %ld) spawned but thread initialization wait of %u msec expired", 
						pname_, tid_, max_msecs_for_thr_init_);
				}	
			}	
		}
		else {
			DEBUGEXECN(1, INFOPRINTCOLOR(GY_COLOR_GREEN, "Thread Object for %s spawned thread successfully\n", pname_););
		}
	}	

	int stop_thread() noexcept
	{
		int		ret = 0;
			
		if ((tid_ != 0) && (status_.load(std::memory_order_acquire) != THR_STATUS_STOP)) {
			status_.store(THR_STATUS_STOP, std::memory_order_release);

			DEBUGEXECN(1, INFOPRINTCOLOR(GY_COLOR_GREEN, "Thread Object for %s : Now signalling thread to stop : waiting...\n", pname_););

			auto		stopfunc = GY_READ_ONCE(stop_func_);

			if (stopfunc) {
				try {
					(*stopfunc)(GY_READ_ONCE(stop_func_arg_));
				}
				catch(...) 
				{}		
			}

			ret = gy_pthread_join(tid_, nullptr, max_msecs_to_wait_for_quit_signal_, use_signal_after_timeout_quit_, wait_indefinitely_if_timeout_quit_); 

			if (ret == 0 || ret == ESRCH) {
				tid_ = 0;
			}

			if (ret != 0) {
				PERRORPRINTCOLOR(GY_COLOR_RED, "Thread joining failed for thread %s...", pname_);
			}
		}

		return ret;
	}
	
	void * get_opt_arg1() const noexcept
	{
		return opt_thread_arg1_;
	}

	void * get_opt_arg2() const noexcept
	{
		return opt_thread_arg2_;
	}

	std::pair<void *, void *> get_opt_args() const noexcept
	{
		return {opt_thread_arg1_, opt_thread_arg2_};
	}	

	const char * get_description() const noexcept
	{
		return pname_;
	}		
		
	void set_thread_stop_function(PTHREAD_STOP_PTR stop_func, void *stop_func_arg) noexcept
	{
		stop_func_ 	= stop_func;
		stop_func_arg_	= stop_func_arg;
	}
		
	int wait_for_thread_join() noexcept
	{
		pthread_t		tid = GY_READ_ONCE(tid_);
		int			ret = 0;

		if (tid != 0) {
			ret = pthread_join(tid, nullptr);

			if (ret == 0 || ret == ESRCH) {
				tid_ = 0;
			}
			else {
				errno = ret;
			}	
		}
		
		return ret;		
	}		
		
	// Requires CLOCK_REALTIME tv_sec
	int wait_for_thread_join_until(struct timespec abs_ts) noexcept
	{
		pthread_t		tid = GY_READ_ONCE(tid_);
		int			ret = 0;

		if (tid != 0) {
			ret = pthread_timedjoin_np(tid, nullptr, &abs_ts);

			if (ret == 0 || ret == ESRCH) {
				tid_ = 0;
			}
			else {
				errno = ret;
			}	
		}
		
		return ret;		
	}		

	void set_thread_init_done(bool init_failed = false) noexcept
	{
		auto lam1 = [&]() -> bool { 
			
			if (status_.load(std::memory_order_acquire) == THR_STATUS_INIT) {
				return false;
			}
				
			if (init_failed == false) {
				status_.store(THR_STATUS_INIT, std::memory_order_release);
			}
			else {
				status_.store(THR_STATUS_FAILED_INIT, std::memory_order_release);
			}		

			return true;
		};

		if (thr_func_calls_init_done_ && max_msecs_for_thr_init_ && cond_) {
			cond_->cond_signal(lam1);
		}
		else {
			lam1();
		}	
	}	

	bool is_thread_initialized() const noexcept
	{
		return (THR_STATUS_INIT == status_.load(std::memory_order_acquire));
	}	

	[[gnu::noinline]] 
	bool is_thread_stop_signalled(std::memory_order order = std::memory_order_acquire) const noexcept
	{
		return (THR_STATUS_STOP == status_.load(order));
	}	

	/*
	 * Non-blocking check to see if thread has exited...
	 */ 
	bool is_thread_exited() noexcept
	{
		pthread_t		tid = GY_READ_ONCE(tid_);
		int			ret;

		if (tid != 0) {
			ret = pthread_tryjoin_np(tid, nullptr);
			if (ret == 0 || ret == ESRCH) {
				tid_ = 0;
				return true;
			}
			
			return false;
		}
		return true;		
	}	

	void clear_cond() noexcept
	{
		if (cond_) {
			cond_.reset();
		}	
	}	

	void reset() noexcept
	{
		tid_ = 0;
		status_.store(THR_STATUS_UNINIT, std::memory_order_relaxed);
	}
		
	pthread_t get_tid() const noexcept
	{
		return tid_;
	}	
};	
		
/*
 * XXX : Recommend using folly::SharedMutex instead of this class...
 *
 * Scope based Read-Write locking class for safe locking.
 *
 * The lock will be automatically unlocked at the scope end. Users can explicitly unlock calling obj1.unlock() if
 * needed before the scope end.
 *
 * To extend the scope of the lock, a nullptr pthread_rwlock_t can be passed and later
 * obj1.setlock(<Pointer to pthread_rwlock_t>, GY_READ_LOCK_E OR GY_WRITE_LOCK_E) can be called from a reduced scope.
 */ 
class SCOPE_RWLOCK
{
public :
	enum SCOPE_RWLOCK_TYPE_E : uint8_t
	{
		READ_LOCK	= 1,
		WRITE_LOCK	= 2,
	};

	pthread_rwlock_t	*plock_;	
	SCOPE_RWLOCK_TYPE_E	type_;

	SCOPE_RWLOCK(pthread_rwlock_t *plock, SCOPE_RWLOCK_TYPE_E type = READ_LOCK) noexcept : plock_(plock), type_(type) 
	{
		if (plock) {
			if (type != WRITE_LOCK) {
				pthread_rwlock_rdlock(plock);
			}
			else {
				pthread_rwlock_wrlock(plock);
			}
		}
	}	
		
	SCOPE_RWLOCK(const SCOPE_RWLOCK &)	= delete;

	SCOPE_RWLOCK(SCOPE_RWLOCK && other) noexcept : plock_(std::exchange(other.plock_, nullptr)), type_(other.type_) {}

	int setlock(pthread_rwlock_t *plock, SCOPE_RWLOCK_TYPE_E type) noexcept
	{
		assert(plock_ == nullptr);

		plock_ 	= plock;
		type_ 	= type;
		
		if (plock) {
			if (type != WRITE_LOCK) {
				return pthread_rwlock_rdlock(plock);
			}
			else {
				return pthread_rwlock_wrlock(plock);
			}
		}
		return 0;	
	}

	int unlock(void) noexcept
	{
		int		ret;

		if (plock_) {
			ret = pthread_rwlock_unlock(plock_);
			plock_ = nullptr;
		}
		else {
			ret = 0;
		}

		return ret;
	}

	~SCOPE_RWLOCK() noexcept
	{
		(void)this->unlock();
	}
};

/*
 * Scope based FILE fopen/fmemopen/fdopen stuff. 
 * The FILE pointer is not protected against concurrent access by parallel threads unless use_unlockio is false
 */ 
class SCOPE_FILE
{
	FILE			*pfp_		{nullptr};
	int			savederrno_	{0};

public :
	SCOPE_FILE() noexcept 		= default;
	
	SCOPE_FILE(FILE *pfp) noexcept : pfp_(pfp) 
	{}

	SCOPE_FILE(const char *path, const char *mode, bool use_unlockio = true) noexcept
	{
		if (path && mode) {
			pfp_ = ::fopen(path, mode);	

			if (pfp_) {
				if (use_unlockio) ::__fsetlocking(pfp_, FSETLOCKING_BYCALLER);
			}	
			else {
				savederrno_ = errno;
			}	
		}	
	}

	SCOPE_FILE(GY_TAG_EXCEPTION etag, const char *path, const char *mode, bool use_unlockio = true)
		: SCOPE_FILE(path, mode, use_unlockio)
	{
		if (!pfp_) {
			if (savederrno_) {
				GY_THROW_SYS_EXCEPTION("Failed to open file %s", path);
			}	
			else {
				GY_THROW_EXCEPTION("Failed to open file %s", path);
			}	
		}	
	}	
	
	// Open FILE from existing buffer using fmemopen : Can be used for both read and write
	SCOPE_FILE(void *buffer, size_t szbuffer, const char *mode, bool use_unlockio = true) noexcept
	{
		if (buffer && szbuffer) {
			pfp_ = ::fmemopen(buffer, szbuffer, mode);	

			if (pfp_) {
				if (use_unlockio) ::__fsetlocking(pfp_, FSETLOCKING_BYCALLER);
			}	
			else {
				savederrno_ = errno;
			}	
		}	
	}

	SCOPE_FILE(int dirfd, const char *path, const char *mode, bool use_unlockio = true) noexcept
	{
		if (dirfd > 0 && path && mode) {
			int 		fd, flags = 0;

			if ((0 == strcmp(mode, "r")) || (0 == strcmp(mode, "re")) || (0 == strcmp(mode, "rb"))) {
				flags = O_RDONLY | O_CLOEXEC;
			}
			else if ((0 == strcmp(mode, "w")) || (0 == strcmp(mode, "we")) || (0 == strcmp(mode, "wb"))) {
				flags = O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC;		
			}
			else if ((0 == strcmp(mode, "a")) || (0 == strcmp(mode, "ae")) || (0 == strcmp(mode, "ab"))) {
				flags =  O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC;
			}
			else if ((0 == strncmp(mode, "r+", 2)) || (0 == strcmp(mode, "re+")) || (0 == strcmp(mode, "rb+"))) {
				flags = O_RDWR | O_CLOEXEC;
			}
			else if ((0 == strncmp(mode, "w+", 2)) || (0 == strcmp(mode, "we+")) || (0 == strcmp(mode, "wb+"))) {
				flags = O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC;		
			}
			else if ((0 == strncmp(mode, "a+", 2)) || (0 == strcmp(mode, "ae+")) || (0 == strcmp(mode, "ab+"))) {
				flags =  O_RDWR | O_CREAT | O_APPEND | O_CLOEXEC;
			}
			else {
				assert((0 == strcmp(mode, "Please specify a mode in the format shown above")));	
				flags = O_RDWR | O_CLOEXEC;
			}	

			fd = ::openat(dirfd, path, flags, 0640);
			if (fd > 0) {
				pfp_ = ::fdopen(fd, mode);	

				if (pfp_) {
					if (use_unlockio) ::__fsetlocking(pfp_, FSETLOCKING_BYCALLER);
				}	
				else {
					savederrno_ = errno;
					(void)::close(fd);
				}	
			}
			else {
				savederrno_ = errno;
			}	
		}	
	}

	SCOPE_FILE(const SCOPE_FILE & other)		= delete;

	SCOPE_FILE(SCOPE_FILE && other) noexcept 
		: pfp_(std::exchange(other.pfp_, nullptr)), savederrno_(std::exchange(other.savederrno_, 0)) 
	{}

	SCOPE_FILE & operator= (const SCOPE_FILE &)	= delete;

	SCOPE_FILE & operator= (SCOPE_FILE && other) noexcept
	{
		if (this != &other) {
			this->close();

			pfp_		= std::exchange(other.pfp_, nullptr);
			savederrno_	= std::exchange(other.savederrno_, 0);
		}

		return *this;
	}

	~SCOPE_FILE() noexcept
	{
		int		tolderrno = errno;

		this->close();
		errno = tolderrno;
	}	
	
	void set_file(FILE *pfp, bool use_unlockio = true) noexcept
	{
		assert(pfp_ == nullptr); 
		
		// Close pfp first
		if (pfp_ && pfp) {
			this->close();
		}

		savederrno_ = 0;

		pfp_ 	= pfp;

		if (pfp_) {
			if (use_unlockio) ::__fsetlocking(pfp_, FSETLOCKING_BYCALLER);
		}
	}
		
	void reset() noexcept
	{
		pfp_ = nullptr;
		savederrno_ = 0;
	}
		
	int close() noexcept
	{
		int		ret;

		if (pfp_) {
			ret = ::fclose(pfp_);
			pfp_ = nullptr;
			savederrno_ = 0;
		}	
		else {
			ret = 0;
		}	

		return ret;
	}	

	FILE * get() const noexcept
	{
		if (!pfp_ && savederrno_) {
			errno = savederrno_;
		}	
		return pfp_;
	}	 
};	

class SCOPE_FD
{
	int			fd_		{-1};
	int			savederrno_	{0};

public :
	SCOPE_FD() noexcept 		= default;
	
	explicit SCOPE_FD(int fd) noexcept : fd_(fd), savederrno_(0) 
	{}

	SCOPE_FD(const char *path, int flags, mode_t mode = 0640) noexcept
	{
		if (path) {
			fd_ = ::open(path, flags, mode);	
			if (fd_ < 0) {
				savederrno_ = errno;
			}	
		}	
	}

	SCOPE_FD(GY_TAG_EXCEPTION etag, const char *path, int flags, mode_t mode = 0640)
		: SCOPE_FD(path, flags, mode)
	{
		if (fd_ < 0) {
			if (savederrno_) {
				GY_THROW_SYS_EXCEPTION("Failed to open file %s", path);
			}	
			else {
				GY_THROW_EXCEPTION("Failed to open file %s", path);
			}	
		}	
	}	

	SCOPE_FD(int dirfd, const char *path, int flags, mode_t mode = 0640) noexcept
	{
		if (path) {
			fd_ = ::openat(dirfd, path, flags, mode);	
			if (fd_ < 0) {
				savederrno_ = errno;
			}	
		}	
	}

	SCOPE_FD(const char *path, int flags, int & output_fd, mode_t mode = 0640) noexcept
	{
		if (path) {
			fd_ = ::open(path, flags, mode);	

			output_fd = fd_;

			if (fd_ < 0) {
				savederrno_ = errno;
			}	
		}
		else {
			output_fd = -1;
		}	
	}

	SCOPE_FD(int dirfd, const char *path, int flags, int & output_fd, mode_t mode = 0640) noexcept
	{
		if (path) {
			fd_ = ::openat(dirfd, path, flags, mode);	

			output_fd = fd_;

			if (fd_ < 0) {
				savederrno_ = errno;
			}	
		}	
	}


	SCOPE_FD(const SCOPE_FD & other)		= delete;

	SCOPE_FD(SCOPE_FD && other) noexcept 
		: fd_(std::exchange(other.fd_, -1)), savederrno_(std::exchange(other.savederrno_, 0)) 
	{}	

	SCOPE_FD & operator= (const SCOPE_FD &)		= delete;

	SCOPE_FD & operator= (SCOPE_FD && other) noexcept
	{
		if (this != &other) {
			this->close();

			fd_		= std::exchange(other.fd_, -1);
			savederrno_	= std::exchange(other.savederrno_, 0);
		}

		return *this;
	}	

	~SCOPE_FD() noexcept
	{
		int		tolderrno = errno;

		this->close();

		errno = tolderrno;
	}	
	
	void set_fd(int fd) noexcept
	{
		assert(fd_ == -1); 
		
		// close fd_ first
		if ((fd_ >= 0) && (fd >= 0)) {
			this->close();
		}

		fd_ 		= fd;
		savederrno_ 	= 0;
	}
		
	void reset() noexcept
	{
		fd_ 		= -1;
		savederrno_ 	= 0;
	}

	// Release fd from object
	int release() noexcept
	{
		int		fd = fd_;

		reset();
		return fd;
	}	
		
	int close() noexcept
	{
		int		ret = 0;

		if (fd_ >= 0) {
			ret = ::close(fd_);
			fd_ = -1;
			savederrno_ = 0;
		}	
		
		return ret;	
	}	

	// get fd and set errno if error
	int get() const noexcept
	{
		if (fd_ < 0 && savederrno_) {
			errno = savederrno_;
		}	
		return fd_;
	}	

	int getfd() const noexcept
	{
		return fd_;
	}	

	bool isvalid() const noexcept
	{
		return fd_ >= 0;
	}	
};

template <typename T>
struct SHARED_PTR_COMP 
{
	bool operator()(const std::shared_ptr<T> &a, const std::shared_ptr<T> &b) 
	{
		return std::less<T>()(*a, *b);
	}
};

template <typename T>
struct SHARED_PTR_EQUAL 
{
	bool operator()(const std::shared_ptr<T> &a, const std::shared_ptr<T> &b) noexcept
	{
		return *a == *b;
	}
};

template <typename T>
struct SHARED_PTR_HASH 
{
	size_t operator()(const std::shared_ptr<T> &a) const noexcept
	{
		if (a) {
			return a->hash();
		}
		return 0;	
	}
};


template <typename T, typename U>
bool weak_shared_equal(const std::weak_ptr<T> &t, const std::shared_ptr<U> &u)
{
	return !t.owner_before(u) && !u.owner_before(t);
}


template <typename T, typename U>
bool weak_ptr_equal(const std::weak_ptr<T> &t, const std::weak_ptr<U> &u)
{
	return !t.owner_before(u) && !u.owner_before(t);
}	

template <typename T>
struct WEAK_PTR_EQUAL 
{
	bool operator()(const std::weak_ptr<T> &a, const std::weak_ptr<T> &b) 
	{
		return weak_ptr_equal(a, b);
	}
};

static char * get_string_from_version_num(uint32_t version, char (&verbuf)[32], int num_octets = 3) noexcept
{
	std::memset(verbuf, 0, sizeof(verbuf));

	switch (num_octets) {

	case 1 :	sprintf(verbuf, "%hhu", version & 0xFF); break;

	case 2 :	sprintf(verbuf, "%hhu.%hhu", (version >> 8) & 0xFF, version & 0xFF); break;

	case 3 :	sprintf(verbuf, "%hhu.%hhu.%hhu", (version >> 16) & 0xFF, (version >> 8) & 0xFF, version & 0xFF); break;
	
	default :	sprintf(verbuf, "%hhu.%hhu.%hhu.%hhu", (version >> 24) & 0xFF, (version >> 16) & 0xFF, (version >> 8) & 0xFF, version & 0xFF); break;
	}	

	return verbuf;
}

static CHAR_BUF<32> get_string_from_version_num(uint32_t version, int num_octets = 3) noexcept
{
	char			buf[32];

	return CHAR_BUF<32>(get_string_from_version_num(version, buf, num_octets));
}	

static constexpr uint32_t gy_crc32_table[256] = {
	0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9, 0x130476dc, 0x17c56b6b,
	0x1a864db2, 0x1e475005, 0x2608edb8, 0x22c9f00f, 0x2f8ad6d6, 0x2b4bcb61,
	0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd, 0x4c11db70, 0x48d0c6c7,
	0x4593e01e, 0x4152fda9, 0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75,
	0x6a1936c8, 0x6ed82b7f, 0x639b0da6, 0x675a1011, 0x791d4014, 0x7ddc5da3,
	0x709f7b7a, 0x745e66cd, 0x9823b6e0, 0x9ce2ab57, 0x91a18d8e, 0x95609039,
	0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5, 0xbe2b5b58, 0xbaea46ef,
	0xb7a96036, 0xb3687d81, 0xad2f2d84, 0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d,
	0xd4326d90, 0xd0f37027, 0xddb056fe, 0xd9714b49, 0xc7361b4c, 0xc3f706fb,
	0xceb42022, 0xca753d95, 0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1,
	0xe13ef6f4, 0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d, 0x34867077, 0x30476dc0,
	0x3d044b19, 0x39c556ae, 0x278206ab, 0x23431b1c, 0x2e003dc5, 0x2ac12072,
	0x128e9dcf, 0x164f8078, 0x1b0ca6a1, 0x1fcdbb16, 0x018aeb13, 0x054bf6a4,
	0x0808d07d, 0x0cc9cdca, 0x7897ab07, 0x7c56b6b0, 0x71159069, 0x75d48dde,
	0x6b93dddb, 0x6f52c06c, 0x6211e6b5, 0x66d0fb02, 0x5e9f46bf, 0x5a5e5b08,
	0x571d7dd1, 0x53dc6066, 0x4d9b3063, 0x495a2dd4, 0x44190b0d, 0x40d816ba,
	0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e, 0xbfa1b04b, 0xbb60adfc,
	0xb6238b25, 0xb2e29692, 0x8aad2b2f, 0x8e6c3698, 0x832f1041, 0x87ee0df6,
	0x99a95df3, 0x9d684044, 0x902b669d, 0x94ea7b2a, 0xe0b41de7, 0xe4750050,
	0xe9362689, 0xedf73b3e, 0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2,
	0xc6bcf05f, 0xc27dede8, 0xcf3ecb31, 0xcbffd686, 0xd5b88683, 0xd1799b34,
	0xdc3abded, 0xd8fba05a, 0x690ce0ee, 0x6dcdfd59, 0x608edb80, 0x644fc637,
	0x7a089632, 0x7ec98b85, 0x738aad5c, 0x774bb0eb, 0x4f040d56, 0x4bc510e1,
	0x46863638, 0x42472b8f, 0x5c007b8a, 0x58c1663d, 0x558240e4, 0x51435d53,
	0x251d3b9e, 0x21dc2629, 0x2c9f00f0, 0x285e1d47, 0x36194d42, 0x32d850f5,
	0x3f9b762c, 0x3b5a6b9b, 0x0315d626, 0x07d4cb91, 0x0a97ed48, 0x0e56f0ff,
	0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623, 0xf12f560e, 0xf5ee4bb9,
	0xf8ad6d60, 0xfc6c70d7, 0xe22b20d2, 0xe6ea3d65, 0xeba91bbc, 0xef68060b,
	0xd727bbb6, 0xd3e6a601, 0xdea580d8, 0xda649d6f, 0xc423cd6a, 0xc0e2d0dd,
	0xcda1f604, 0xc960ebb3, 0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7,
	0xae3afba2, 0xaafbe615, 0xa7b8c0cc, 0xa379dd7b, 0x9b3660c6, 0x9ff77d71,
	0x92b45ba8, 0x9675461f, 0x8832161a, 0x8cf30bad, 0x81b02d74, 0x857130c3,
	0x5d8a9099, 0x594b8d2e, 0x5408abf7, 0x50c9b640, 0x4e8ee645, 0x4a4ffbf2,
	0x470cdd2b, 0x43cdc09c, 0x7b827d21, 0x7f436096, 0x7200464f, 0x76c15bf8,
	0x68860bfd, 0x6c47164a, 0x61043093, 0x65c52d24, 0x119b4be9, 0x155a565e,
	0x18197087, 0x1cd86d30, 0x029f3d35, 0x065e2082, 0x0b1d065b, 0x0fdc1bec,
	0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088, 0x2497d08d, 0x2056cd3a,
	0x2d15ebe3, 0x29d4f654, 0xc5a92679, 0xc1683bce, 0xcc2b1d17, 0xc8ea00a0,
	0xd6ad50a5, 0xd26c4d12, 0xdf2f6bcb, 0xdbee767c, 0xe3a1cbc1, 0xe760d676,
	0xea23f0af, 0xeee2ed18, 0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4,
	0x89b8fd09, 0x8d79e0be, 0x803ac667, 0x84fbdbd0, 0x9abc8bd5, 0x9e7d9662,
	0x933eb0bb, 0x97ffad0c, 0xafb010b1, 0xab710d06, 0xa6322bdf, 0xa2f33668,
	0xbcb4666d, 0xb8757bda, 0xb5365d03, 0xb1f740b4
};

static constexpr uint32_t gy_crc32(const char * pdata, size_t len) noexcept 
{
	uint32_t	crc = ~0u;

	while ((ssize_t)len-- > 0) {
		crc = (crc >> 8) ^ gy_crc32_table[(crc & 0xFF) ^ *pdata];
		pdata++;
	}	
	return ~crc;
}

// constexpr hash
static constexpr inline uint32_t gy_crc32_constexpr(const char * str) noexcept 
{
	return gy_crc32(str, gy_strlen_constexpr(str));
}

static constexpr uint32_t fnv1_hash(const char * str, size_t len) noexcept
{
	constexpr uint32_t 		default_offset_basis	= 0x811C9DC5;
	constexpr uint32_t 		fnv_prime 		= 0x01000193;
	
	uint32_t			hash = default_offset_basis;

	while ((ssize_t)len-- > 0) {
		hash ^= *str++;
		hash *= fnv_prime;
	}

	return hash;
}	

// constexpr hash
static constexpr inline uint32_t fnv1_consthash(const char * str) noexcept
{
	return fnv1_hash(str, gy_strlen_constexpr(str));
}


} // namespace gyeeta


#pragma 		GCC diagnostic pop

