//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include 		"gy_common_inc.h"
#include		<queue>
#include		<map>

#include 		"gy_file_api.h"
#include		"gy_misc.h"
#include		"gy_sys_hardware.h"
#include 		"gy_inet_inc.h"
#include		"gy_statistics.h"

#include		"gy_scheduler.h"

#include 		<sys/ioctl.h>
#include 		<sys/types.h>
#include 		<sys/param.h>
#include 		<sys/mount.h>
#include 		<libgen.h>
#include 		<sys/socket.h>
#include 		<sys/wait.h>
#include 		<sys/time.h>
#include 		<sys/statvfs.h>
#include 		<sys/resource.h>

#include 		<netinet/in_systm.h>
#include 		<netinet/in.h>
#include 		<netinet/ip.h>
#include 		<netinet/tcp.h>
#include 		<arpa/inet.h>
#include 		<netinet/ip_icmp.h>
#include 		<netdb.h>
#include 		<time.h>
#include 		<ctype.h>
#include 		<sys/types.h> 
#include 		<sys/socket.h>
#include 		<poll.h>
#include 		<sys/mman.h>
#ifndef __u32
#include 		<asm/types.h>
#endif
#include 		<linux/ethtool.h>
#include 		<linux/sockios.h>
#include 		<sys/prctl.h>
#include 		<dirent.h>
#include 		<sys/file.h>
#include 		<sys/sendfile.h>
#include 		<execinfo.h>
#include 		<ucontext.h>

#include 		<chrono>

#ifdef GY_MALLOC_HOOKED
#include		"gy_malloc_hook.h"
#endif

namespace gyeeta {

int					gdebugexecn = 0;	
bool					guse_utc_time = false, gunbuffered_stdout = false;

thread_local 	GY_THR_LOCAL		gthrdata_local_;
thread_local 	pid_t			gtid_local_ = -1, gtid_startpid_ = getpid();

size_t 					gpgsz_local_ = 0;
uint32_t 				gclktck_local_ = 0;

constexpr const char *			Level_5s_5min_5days_all::level_string[];
constexpr std::chrono::seconds		Level_5s_5min_5days_all::dist_seconds[];

constexpr const char *			Level_300_all::level_string[];
constexpr std::chrono::seconds		Level_300_all::dist_seconds[];

constexpr int64_t			RESP_TIME_HASH::nthresholds[];

constexpr int64_t			SEMI_LOG_HASH::nthresholds[];
constexpr int64_t			SEMI_LOG_HASH_LO::nthresholds[];
constexpr int64_t			HASH_10_5000::nthresholds[];
constexpr int64_t			HASH_5_250::nthresholds[];
constexpr int64_t			HASH_1_3000::nthresholds[];

TASK_NS_INODES				SYS_HARDWARE::rootns_inodes;

GY_TIMEZONE				gtzone_;

pid_t					gproc_start_pid = getpid(), gproc_curr_pid = getpid();
uint64_t				gproc_start_usec = get_usec_time(), gproc_start_clock = get_usec_clock(), gproc_start_boot = get_usec_bootclock();

int gy_no_mutex_lock(GY_MUTEX * pmutex) noexcept
{
	return 0;
}	

int no_mutex_lock(pthread_mutex_t * pmutex) noexcept
{
	return 0;
}	

int gy_mutex_proc_lock(GY_MUTEX * pmutex) noexcept
{
	int			ret;

	ret = ::pthread_mutex_lock(pmutex->get());
	if (ret == 0) {
		return 0;
	}
	
	if (ret == EOWNERDEAD && pmutex->is_multi_process()) {
		ret = ::pthread_mutex_consistent(pmutex->get());
		
		pmutex->call_proc_dead_callback();
	}	
		
	return ret;	
}
	
int gy_mutex_proc_unlock(GY_MUTEX * pmutex) noexcept
{
	return ::pthread_mutex_unlock(pmutex->get());
}
	
int gy_mutex_proc_trylock(GY_MUTEX * pmutex) noexcept
{
	int			ret;

	ret = ::pthread_mutex_trylock(pmutex->get());
	if (ret == 0) {
		return 0;
	}
	
	if (ret == EOWNERDEAD && pmutex->is_multi_process()) {
		ret = ::pthread_mutex_consistent(pmutex->get());
		
		pmutex->call_proc_dead_callback();
	}	
		
	return ret;	
}

int set_proc_file_limit(uint32_t max_files) noexcept
{
	struct rlimit		rlim;
	int			ret;

	rlim.rlim_cur = rlim.rlim_max = max_files;
	
	ret = setrlimit(RLIMIT_NOFILE, &rlim);
	if (ret) {
		return -errno;
	}

	return 0;
}

int set_proc_rtprio_limit(uint32_t max_rtprio) noexcept
{
	struct rlimit		rlim;
	int			ret;

	rlim.rlim_cur = rlim.rlim_max = max_rtprio;
	
#	ifdef RLIMIT_RTPRIO
	ret = setrlimit(RLIMIT_RTPRIO, &rlim);
	if (ret) {
		return -errno;
	}
#	else 
	ret = -1;
#	endif

	return 0;
}

int set_proc_nproc_limit(uint32_t max_procs) noexcept
{
	struct rlimit		rlim;
	int			ret;

	rlim.rlim_cur = rlim.rlim_max = max_procs;
	
	ret = setrlimit(RLIMIT_NPROC, &rlim);
	if (ret) {
		return -errno;
	}

	return 0;
}

void set_stdout_buffer_mode(bool use_buffering) noexcept
{
	setvbuf(stdout, nullptr, use_buffering ? _IOLBF : _IONBF, 0);
	gunbuffered_stdout = !use_buffering;
}	

int set_fd_nonblock(int fd, bool nonblock) noexcept
{
	int 		flags, nflags;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		return -errno;
	}	

	if (nonblock) {
		nflags = flags | O_NONBLOCK;
	}	
	else {
		nflags = flags & ~O_NONBLOCK;
	}	

	if (nflags == flags) {
		return 0;
	}	

	if (fcntl(fd, F_SETFL, nflags) < 0) {
		return -errno;
	}	

	return 0;
}

int duplicate_fd(int fd, bool cloexec) noexcept
{
	int 		newfd;
	
	newfd = fcntl(fd, cloexec ? F_DUPFD_CLOEXEC : F_DUPFD, 3); 
	if (newfd < 0) {
		return -errno;
	}	

	return newfd;
}


/*
 * Disable Nagle Algo
 */ 
int set_sock_nodelay(int sock, int to_set) noexcept
{
	int 		ret;

	ret = setsockopt(sock, SOL_TCP, TCP_NODELAY, &to_set, sizeof (to_set));

	if (ret < 0) {
		return -errno;
	}

	return 0;
}

int set_sock_keepalive(int sock, int to_set) noexcept
{
	int 		ret;

	ret = setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &to_set, sizeof (to_set));

	if (ret < 0) {
		return -errno;
	}

	return 0;
}

int set_sock_tcpcork(int sock, int to_set) noexcept
{
	int 		ret;

	ret = setsockopt(sock, SOL_TCP, TCP_CORK, &to_set, sizeof (to_set));

	if (ret < 0) {
		return -errno;
	}

	return 0;
}

int set_sock_nonblocking(int sock, int to_set) noexcept
{
	int 		ret;

	ret = ioctl(sock, FIONBIO, &to_set);

	if (ret < 0) {
		return -errno;
	}

	return 0;
}

void gy_print_proc_status(char *pstr, int fdout) noexcept
{
	int 		fd_, ret_;
	char 		readbuf_[2048], *pbuf, *ptmp, vmpk[64], vmsz[64], vmdt[64], thr[64];

	if (pstr) {
		INFOFDUNLOCKPRINT(fdout, "--------Printing Process Status Info...%s-----------------\n\n", pstr);
	}
	
	fd_ = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
	if (fd_ > 0) {
		ret_ = read(fd_, readbuf_, sizeof(readbuf_) - 1);
		if (ret_ > 0) {
			readbuf_[ret_] = '\0';
		}
		else {
			(void)close(fd_);
			return;
		}

		(void)close(fd_);

		pbuf = readbuf_;
		ptmp = strstr(pbuf, "VmPeak:");
		if (ptmp) {
			sscanf(ptmp, "%63[^\n]", vmpk);
		}
		else {
			*vmpk = '\0';
		}

		ptmp = strstr(pbuf, "VmSize:");
		if (ptmp) {
			sscanf(ptmp, "%63[^\n]", vmsz);
		}
		else {
			*vmsz = '\0';
		}

		ptmp = strstr(pbuf, "VmData:");
		if (ptmp) {
			sscanf(ptmp, "%63[^\n]", vmdt);
		}
		else {
			*vmdt = '\0';
		}

		ptmp = strstr(pbuf, "Threads:");
		if (ptmp) {
			sscanf(ptmp, "%63[^\n]", thr);
		}
		else {
			*thr = '\0';
		}

		INFOFDUNLOCKPRINT(fdout, "Process PID %u Stats : %s, %s, %s, %s\n", getpid(), vmpk, vmsz, vmdt, thr);
	}
}

uint64_t gy_get_proc_vmsize(pid_t pid) noexcept
{
	char 		readbuf[128], path[64];
	int		fd, ret;
	uint64_t	vmsize;

	if (pid == 0) {
		snprintf(path, sizeof(path), "/proc/self/statm");
	}
	else {
		snprintf(path, sizeof(path), "/proc/%d/statm", pid);
	}

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd > 0) {
		ret = read(fd, readbuf, sizeof(readbuf) - 1);
		if (ret > 0) {
			readbuf[ret] = '\0';
		}
		else {
			(void)close(fd);
			return ~0ul;
		}

		(void)close(fd);

		if (string_to_number(readbuf, vmsize)) {
			vmsize *= gy_page_size();
		}
		else {
			vmsize = ~0ul;
		}
	}
	else {
		vmsize = ~0ul;
	}

	return vmsize;
}

ssize_t gy_get_proc_cpus_allowed(pid_t pid) noexcept
{
	try {
		int				ret, fd;
		char				buf[64], *pbuf = nullptr;
		const char			*ptmp;
		bool				is_malloc;
		const int			szalloc = 10 * 1024; 
		ssize_t				szread;
		size_t				nbytes;
		
		snprintf(buf, sizeof(buf), "/proc/%d/status", pid);

		SCOPE_FD			scopefd(buf, O_RDONLY);
		
		fd = scopefd.get();
		if (fd < 0) {
			return -errno;
		}	

		SAFE_STACK_ALLOC(pbuf, szalloc, is_malloc);

		szread = gy_readbuffer(fd, pbuf, szalloc - 1);
		if (szread <= 0) {
			return -errno;
		}

		pbuf[szread] = '\0';

		STR_RD_BUF			taskstr(pbuf, szread);

		ptmp = taskstr.skip_till_substring_const("Cpus_allowed_list:", false);
		if (!ptmp) {
			return -1;
		}	
		
		ptmp = taskstr.get_next_line(nbytes);
		if (!ptmp) {
			return -1;
		}	

		std::bitset<4096>		cpus_allowed;

		ret = set_bitset_from_buffer(cpus_allowed, ptmp, nbytes);
		if (ret != 0) {
			return ret;
		}	

		return cpus_allowed.count();
	}
	catch(...) {
		return -1;
	}	
}

void gy_host_to_nw_bo(void *pd, void *ps, size_t size, bool is_little_endian) noexcept
{
	char 		*pdest = (char *)pd;
	char 		*psrc = (char *)ps;
	unsigned char 	ctemp[128];
	int 		i;

	if (size == 2) {
		*(short *)pdest = htons(*(short *)psrc);
	}
	else if (size == 4) {
		*(int *)pdest = htonl(*(int *)psrc);
	}
	else {
		if (!is_little_endian) {
			if (pdest != psrc) {
				for (i = 0; i < (int)size; i++) {
					*(pdest + i) = *(psrc + i);
				}
			}
		}
		else {
			if (pdest == psrc) {
				size &= 0x7F;
				std::memcpy(ctemp, psrc, size);
				psrc = (char *)ctemp;
			}

			for (i = 0; i < (int)size; i++) {
				*(pdest + i) = *(psrc + size - 1 - i);
			}
		}
	}
}

void gy_nw_to_host_bo(void *pd, void *ps, size_t size, bool is_little_endian) noexcept
{
	char 		*pdest = (char *)pd;
	char 		*psrc = (char *)ps;
	unsigned char 	ctemp[128];
	int 		i;

	if (size == 2) {
		*(short *)pdest = ntohs(*(short *)psrc);
	}
	else if (size == 4) {
		*(int *)pdest = ntohl(*(int *)psrc);
	}
	else {
		if (!is_little_endian) {
			if (pdest != psrc) {
				for (i = 0; i < (int)size; i++) {
					*(pdest + i) = *(psrc + i);
				}
			}
		}
		else {
			if (pdest == psrc) {
				size &= 0x7F;
				std::memcpy(ctemp, psrc, size);
				psrc = (char *)ctemp;
			}

			for (i = 0; i < (int)size; i++) {
				*(pdest + i) = *(psrc + size - 1 - i);
			}
		}
	}
}


const char * const signalstr[] = {
	"Unknown Signal",
	"SIGHUP : Death of controlling or parent process",       "SIGINT : Interrupt from keyboard",       
	"SIGQUIT : Quit from keyboard",      "SIGILL : Illegal Instruction (Unsupported Processor Instruction)",
	"SIGTRAP : Trace/breakpoint trap",      "SIGABRT : Abort Signal",      "SIGBUS : Bus error (bad memory access)",
	"SIGFPE : Floating point exception", "SIGKILL : Kill -9 Signal",     "SIGUSR1 : User-defined signal 1",     
	"SIGSEGV : Invalid memory reference",     "SIGUSR2 : User-defined signal 2",
	"SIGPIPE : Broken pipe: write to pipe with no readers",     "SIGALRM : Timer signal from alarm",     
	"SIGTERM : Termination Signal",  "Unknown Signal",   "SIGCHLD : Child stopped or terminated"
	"SIGCONT",     "SIGSTOP",     "SIGTSTP",     "SIGTTIN",
	"SIGTTOU",     "SIGURG",      "SIGXCPU : CPU time limit exceeded",     "SIGXFSZ : File size limit exceeded",
	"SIGVTALRM : Virtual alarm clock",   "SIGPROF : Profiling timer expired",     "SIGWINCH",    "SIGIO",
	"SIGPWR : Power failure",      "SIGSYS : Bad argument to routine", 
	"Unknown Signal", "Unknown Signal", "Unknown Signal", "SIGRTMIN",    "SIGRTMIN+1",
	"SIGRTMIN+2",  "SIGRTMIN+3",  "SIGRTMIN+4",  "SIGRTMIN+5",
	"SIGRTMIN+6",  "SIGRTMIN+7",  "SIGRTMIN+8",  "SIGRTMIN+9",
	"SIGRTMIN+10", "SIGRTMIN+11", "SIGRTMIN+12", "SIGRTMIN+13",
	"SIGRTMIN+14", "SIGRTMIN+15", "SIGRTMAX-14", "SIGRTMAX-13",
	"SIGRTMAX-12", "SIGRTMAX-11", "SIGRTMAX-10", "SIGRTMAX-9",
	"SIGRTMAX-8",  "SIGRTMAX-7",  "SIGRTMAX-6",  "SIGRTMAX-5",
	"SIGRTMAX-4",  "SIGRTMAX-3",  "SIGRTMAX-2",  "SIGRTMAX-1",
	"SIGRTMAX"
};

const char *gy_signal_str(int signo) noexcept
{
	if ((signo > SIGRTMAX) || (signo < SIGHUP)) {
		return "Unknown Signal";
	}

	return signalstr[signo];
}

/*
 * Use gy_mmap_alloc() when multi-process memory access is needed.
 * Use with care as each access is aligned to pagesize. 
 * Consider using Buffer Pools for multiple small allocations.
 */ 
void * gy_mmap_alloc(size_t size, size_t *pnewsize, int use_proc_shared) noexcept
{
	void 		*palloc; 
	
	if (gy_unlikely(size == 0)) {
		return nullptr;
	}

	size = gy_align_up_2(size, gy_page_size());

	if (pnewsize) *pnewsize = size;

	palloc = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | (use_proc_shared ? MAP_SHARED : MAP_PRIVATE), -1, 0);
	if (palloc == MAP_FAILED) {
		palloc = nullptr;
	}

	return palloc;
}

void gy_mmap_free(void *pbuf, size_t size) noexcept
{
	void		*ptarg;
	int		pgsz = gy_page_size();

	if (gy_unlikely((pbuf == nullptr) || (size == 0))) {
		return;
	}

	ptarg = (void *)gy_align_down_2((unsigned long)pbuf, pgsz);

	size = gy_align_up_2(size + ((char *)pbuf - (char *)ptarg), pgsz);

	mprotect(ptarg, size, PROT_NONE);
	
	GY_CC_BARRIER();

	munmap(ptarg, size);
}


/*
 * Function to convert base64-encoded string to ASCII format name in the buffer passed 
 * Returns Length of Output data or -1 on error
 */
int base64_2ascii(uint8_t *src, int src_len, uint8_t *dest, int dest_len) noexcept
{
	int8_t t1, t2, t3, t4;
	int i ,j = 0, rem;

	int base64_ascii[] = {  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
				-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
				-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1,
				52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
				-1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
				15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63,
				-1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
				41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1  };

	for (i = 0; ((i < (src_len - 3)) && ((j + 2) < dest_len)); i += 4) {
		t1 = base64_ascii[*(src + i)];
		t2 = base64_ascii[*(src + i + 1)];
		t3 = base64_ascii[*(src + i + 2)];
		t4 = base64_ascii[*(src + i + 3)];
		
		if ((t1 < 0) || (t2 < 0))
			return -1;
				
		sprintf((char *)dest + j++, (char *)"%c", ((t1 << 2) | ((t2 & 0x30) >> 4)));

		if (t3 < 0) {
			return j;
		}

		sprintf((char *)dest + j++, (char *)"%c", (((t2 & 0x0f) << 4) | ((t3 & 0x3c) >> 2)));

		if (t4 < 0) {
			return j;
		}
		sprintf((char *)dest + j++, (char *)"%c", (((t3 & 0x03) << 6) | t4));
	}

	if (((rem = (src_len % 4)) == 1) && (j < dest_len)) {
		t1 = base64_ascii[*(src + i)];
		if (t1 < 0)
			return -1;
		
		sprintf((char*)dest + j++, (char *)"%c", (t1 << 2));
		
	}
	else if ((rem == 2) && ((j + 1) < dest_len)) {
		t1 = base64_ascii[*(src + i)];
		t2 = base64_ascii[*(src + i + 1)];
		if ((t1 < 0) || (t2 < 0))
			return -1;

		sprintf((char *)dest + j++, (char *)"%c", ((t1 << 2) | ((t2 & 0x30) >> 4)));
		sprintf((char *)dest + j++, (char *)"%c", ((t2 & 0x0f) << 4));
	}
	else if ((rem == 3) && ((j + 2) < dest_len)) {
		t1 = base64_ascii[*(src + i)];
		t2 = base64_ascii[*(src + i + 1)];
		t3 = base64_ascii[*(src + i + 2)];

		if ((t1 < 0) || (t2 < 0) || (t3 < 0))
			return -1;
				
		sprintf((char *)dest + j++, (char *)"%c", ((t1 << 2) | ((t2 & 0x30) >> 4)));
		sprintf((char *)dest + j++, (char *)"%c", (((t2 & 0x0f) << 4) | ((t3 & 0x3c) >> 2)));
		sprintf((char *)dest + j++, (char *)"%c", ((t3 & 0x03) << 6));
	}
	
	return j;
}

void GY_SIGNAL_HANDLER::gsigseg_hdlr(int signo, siginfo_t *info, void *secret)
{
	const char		cmsg[] = "\n------------- Stack Trace Follows... ---------------------\n\n";
	const char		emsg[] = "\n------------- Stack Trace Completed... ---------------------\n\n";
	const char		*psignalstr, *pnameproc;	
	char			statusbuf[128];

	auto 			psignal_param = GY_SIGNAL_HANDLER::get_singleton();

	int			texp = 0, tdes = 1;
	static std::atomic<int>	sig_rcvd(0);

	if (false == sig_rcvd.compare_exchange_strong(texp, tdes)) {
		return;
	}

	alarm(5);

	psignalstr = gy_signal_str(signo);

	if (psignal_param) {
		pnameproc = psignal_param->get_name_proc();
	}
	else {
		pnameproc = "Program";	
	}		

	ERRORFDUNLOCKPRINTCOLOR(STDERR_FILENO, GY_COLOR_RED, "[FATAL ERROR]: %s : Received Signal : %s : %d\n\n", pnameproc, psignalstr, signo);

#if defined(__GNUC__) && defined (__linux__)	// Print Signal Stack Trace
	void			*trace[MAX_STACK_FRAMES], *orig_trace;
	int 			i, trace_size = 0, reg;

#	if 	defined(REG_RIP)
# 		define IR_REGFORMAT "%016llx"
# 		define IR_REG_TYPE long long

#	elif 	defined(REG_EIP)
# 		define IR_REGFORMAT "%08x"
# 		define IR_REG_TYPE int

#	else
#		define SIGSEGV_STACK_GENERIC
#		define IR_REGFORMAT "%x"
# 		define IR_REG_TYPE int
#	endif

	ucontext_t *uc = (ucontext_t *)secret;

#	if 	defined(REG_RIP)			
	reg = REG_RIP;
#	elif 	defined(REG_EIP)				
	reg = REG_EIP;
#	endif				

	trace_size = backtrace(trace, MAX_STACK_FRAMES);

	/* overwrite sigaction with caller's address */
	orig_trace = trace[1];

#	if 	defined(REG_RIP)			
	trace[1] = (void *) uc->uc_mcontext.gregs[REG_RIP];
#	elif 	defined(REG_EIP)				
	trace[1] = (void *) uc->uc_mcontext.gregs[REG_EIP];
#	endif				

	write(STDERR_FILENO, cmsg, sizeof(cmsg) - 1);
	
	backtrace_symbols_fd(trace, trace_size, STDERR_FILENO);

	write(STDERR_FILENO, emsg, sizeof(emsg) - 1);

	/* Do something useful with siginfo_t */
	if (signo == SIGSEGV) {
		ERRORFDUNLOCKPRINT(STDERR_FILENO, "%s ---- Got signal %d, faulty address is %p, from 0x" IR_REGFORMAT "\n", pnameproc, signo, info->si_addr, 
			(__typeof__(IR_REG_TYPE))uc->uc_mcontext.gregs[reg]);
	}		
	else {
		ERRORFDUNLOCKPRINT(STDERR_FILENO, "%s  ---- Got signal %d\n", pnameproc, signo);
	}

	INFOFDUNLOCKPRINT(STDERR_FILENO, "info.si_signo = %d\n", signo);
	INFOFDUNLOCKPRINT(STDERR_FILENO, "info.si_errno = %d\n", info->si_errno);
	INFOFDUNLOCKPRINT(STDERR_FILENO, "info.si_addr  = %p\n", info->si_addr);
	for (i = 0; i < NGREG; i++) {
		INFOFDUNLOCKPRINT(STDERR_FILENO, "reg[%02d] = 0x" IR_REGFORMAT "\n", i, (__typeof__(IR_REG_TYPE))uc->uc_mcontext.gregs[i]);
	}		

	int			fdmap1, r1;

	fdmap1 = open("/proc/self/maps", O_RDONLY);
	if (fdmap1 > 0) {
		char			buf[512];
		
		INFOFDUNLOCKPRINT(STDERR_FILENO, "--------------- Printing Process Memory Map -------------------\n");
		do {
			r1 = read(fdmap1, buf, sizeof(buf));
			if (r1 > 0) {
				r1 = write(STDERR_FILENO, buf, r1);
			}
		} while (r1 > 0);

		(void)close(fdmap1);

		gy_print_proc_status(nullptr, STDERR_FILENO);
	}

#endif

	if (info) {
		char			causebuf[128];

		strcpy(causebuf, "unknown");

		switch (info->si_code) {
	
		case SI_USER 	: snprintf(causebuf, sizeof(causebuf), "Signal sent by kill or raise syscall"); break;
		case SI_KERNEL 	: snprintf(causebuf, sizeof(causebuf), "Signal sent by Kernel"); break;
		case SI_QUEUE 	: snprintf(causebuf, sizeof(causebuf), "Signal sent by sigqueue"); break;
		case SI_TIMER 	: snprintf(causebuf, sizeof(causebuf), "Signal sent by timer expiration"); break;
		case SI_MESGQ 	: snprintf(causebuf, sizeof(causebuf), "Signal sent by real time mesq state change"); break;
		case SI_ASYNCIO	: snprintf(causebuf, sizeof(causebuf), "Signal sent by AIO completion"); break;
		case SI_SIGIO	: snprintf(causebuf, sizeof(causebuf), "Signal sent by queued SIGIO"); break;
		case SI_TKILL	: snprintf(causebuf, sizeof(causebuf), "Signal sent by tkill syscall"); break;
		case SI_ASYNCNL	: snprintf(causebuf, sizeof(causebuf), "Signal sent by glibc async name lookup completion"); break;

		default : 
			switch (signo) {

			case SIGILL : 
				
				switch (info->si_code) {
				
				case ILL_ILLOPC :
					snprintf(causebuf, sizeof(causebuf), "Signal sent due to illegal opcode");break; 

				case ILL_ILLOPN :
					snprintf(causebuf, sizeof(causebuf), "Signal sent due to illegal operand");break; 

				case ILL_ILLADR :
					snprintf(causebuf, sizeof(causebuf), "Signal sent due to illegal addressing mode");break; 

				case ILL_ILLTRP :
					snprintf(causebuf, sizeof(causebuf), "Signal sent due to illegal trap");break; 

				case ILL_PRVOPC :
					snprintf(causebuf, sizeof(causebuf), "Signal sent due to privileged opcode");break; 

				case ILL_PRVREG :
					snprintf(causebuf, sizeof(causebuf), "Signal sent due to privileged register");break; 

				case ILL_COPROC :
					snprintf(causebuf, sizeof(causebuf), "Signal sent due to coprocessor error");break; 

				case ILL_BADSTK :
					snprintf(causebuf, sizeof(causebuf), "Signal sent due to internal stack error");break; 

				case 9 /* ILL_BADIADDR */ :
					snprintf(causebuf, sizeof(causebuf), "Signal sent due to unimplemented instruction address");break; 

				default : break;
				}
				break;

			case SIGFPE :

				switch (info->si_code) {
				
				case FPE_INTDIV :
					snprintf(causebuf, sizeof(causebuf), "Signal sent due to integer divide by zero");break; 

				case FPE_INTOVF :
					snprintf(causebuf, sizeof(causebuf), "Signal sent due to integer overflow");break; 

				case FPE_FLTDIV :
					snprintf(causebuf, sizeof(causebuf), "Signal sent due to floating-point divide by zero");break; 

				case FPE_FLTOVF :
					snprintf(causebuf, sizeof(causebuf), "Signal sent due to floating-point overflow");break; 

				case FPE_FLTUND :
					snprintf(causebuf, sizeof(causebuf), "Signal sent due to floating-point underflow");break; 

				case FPE_FLTRES :
					snprintf(causebuf, sizeof(causebuf), "Signal sent due to floating-point inexact result");break; 

				case FPE_FLTINV :
					snprintf(causebuf, sizeof(causebuf), "Signal sent due to floating-point invalid operation");break; 

				case FPE_FLTSUB :
					snprintf(causebuf, sizeof(causebuf), "Signal sent due to subscript out of range");break; 

				default : break;
				}
				break;

			case SIGSEGV :

				switch (info->si_code) {
				
				case SEGV_MAPERR :
					snprintf(causebuf, sizeof(causebuf), "Signal sent due to address not mapped to object");break; 

				case SEGV_ACCERR :
					snprintf(causebuf, sizeof(causebuf), "Signal sent due to invalid permissions for mapped object");break; 
				
				case 3 /* SEGV_BNDERR */ :
					snprintf(causebuf, sizeof(causebuf), "Signal sent due to failed address bound checks");break; 
					
				case 4 /* SEGV_PKUERR */ :
					snprintf(causebuf, sizeof(causebuf), "Signal sent due to failed protection key checks");break; 
					
				default : break;
				}
				break;


			case SIGBUS :

				switch (info->si_code) {
				
				case BUS_ADRALN :
					snprintf(causebuf, sizeof(causebuf), "Signal sent due to invalid address alignment");break; 

				case BUS_ADRERR :
					snprintf(causebuf, sizeof(causebuf), "Signal sent due to nonexistent physical address");break; 

				case BUS_OBJERR :
					snprintf(causebuf, sizeof(causebuf), "Signal sent due to object-specific hardware error");break; 
				
				case 4 /* BUS_MCEERR_AR */ :
					snprintf(causebuf, sizeof(causebuf), "Signal sent due to hardware memory error consumed on a machine check: action required");break; 

				case 5 /* BUS_MCEERR_AR */ :
					snprintf(causebuf, sizeof(causebuf), "Signal sent due to hardware memory error detected in process but not consumed: action optional");break; 

				default : break;
				}
				break;

			default : break;
			}
			break;
			
		}

		NOTEFDUNLOCKPRINT(STDERR_FILENO, "%s : PID of process sending the signal %d : UID %d : Cause of signal %s : Code %d\n",
			 pnameproc, info->si_pid, info->si_uid, causebuf, info->si_code);
	}

	if (psignal_param) {
		psignal_param->call_signal_callback(signo);
	}

	ERRORFDUNLOCKPRINTCOLOR(STDERR_FILENO, GY_COLOR_RED, "%s aborting now...due to %s\n\n", pnameproc, psignalstr);

	abort();
}

void GY_SIGNAL_HANDLER::gsighdlr(int signo, siginfo_t *info, void *secret)
{
	char 			cmdbuf[256], statusbuf[128], pidstr[24];
	int			is_proc = 0, is_ext_stop = 1;
	const char		*pnameproc;

	auto 			psignal_param = GY_SIGNAL_HANDLER::get_singleton();

	int			texp = 0, tdes = 1;
	static std::atomic<int>	sig_rcvd(0);

	if (false == sig_rcvd.compare_exchange_strong(texp, tdes)) {
		if (psignal_param && psignal_param->enable_more_sigints) {
			sig_rcvd.store(0);
		}
		else {	
			return;
		}	
	}

	alarm(5);

	if (psignal_param) {
		pnameproc = psignal_param->get_name_proc();
	}
	else {
		pnameproc = "Program";	
	}		

	if (signo != SIGXFSZ) {
		INFOFDUNLOCKPRINTCOLOR(STDERR_FILENO, GY_COLOR_RED, "%s : Received Signal %s:%d ...\n", pnameproc, gy_signal_str(signo), signo);
	}
	else {
		ERRORFDUNLOCKPRINTCOLOR(STDERR_FILENO, GY_COLOR_RED, "%s : Received File Size Limit Exceeded Signal : "
			"Please upgrade to a larger limit FileSystem such as ext4 or XFS for Linux or check user file size limit.\n", pnameproc);
	}

	gy_print_proc_status(nullptr, STDERR_FILENO);

	if (info) {
		char			causebuf[64];

		switch (info->si_code) {
	
		case SI_USER 	: snprintf(causebuf, sizeof(causebuf), "Signal sent by kill or raise syscall"); break;
		case SI_KERNEL 	: snprintf(causebuf, sizeof(causebuf), "Signal sent by Kernel"); break;
		case SI_QUEUE 	: snprintf(causebuf, sizeof(causebuf), "Signal sent by sigqueue syscall"); break;
		case SI_TIMER	: snprintf(causebuf, sizeof(causebuf), "Signal sent as POSIX timer expired"); break;
		case SI_MESGQ	: snprintf(causebuf, sizeof(causebuf), "Signal sent as POSIX message queue state changed"); break;
		case SI_ASYNCIO	: snprintf(causebuf, sizeof(causebuf), "Signal sent as AIO completed"); break;
		case SI_SIGIO	: snprintf(causebuf, sizeof(causebuf), "Signal sent as queued SIGIO seen"); break;
		case SI_TKILL	: snprintf(causebuf, sizeof(causebuf), "Signal sent by tkill or tgkill syscall"); break;
				
		default : snprintf(causebuf, sizeof(causebuf), "unknown"); break;
			
		}

		NOTEFDUNLOCKPRINT(STDERR_FILENO, "%s : PID of process sending the signal %d : UID %d : Cause of signal %s : Code %d\n",
			pnameproc, info->si_pid, info->si_uid, causebuf, info->si_code);
	}

	if (psignal_param) {
		psignal_param->call_signal_callback(signo);

		if (psignal_param->exit_on_signals == false) {
			alarm(0);
			return;
		}	
	}

	_exit(0);
}

int init_forked_child(const char *pname, bool set_thr_name, const char *pdesc, const char *pstdout_log, const char *pstderr_log, int log_flags, int start_fd_close, int end_fd_close, int *pignore_fd_close, size_t nignore_fd_close, bool exit_on_parent_kill, uid_t chown_uid, gid_t chown_gid, SIGNAL_CALLBACK_HDLR psignal_callbackin, bool signal_callback_will_exit) noexcept
{
	int			i, ret, fd_stdout = -1, fd_stderr = -1;
	auto 			psignal_param = GY_SIGNAL_HANDLER::get_singleton();

	assert(psignal_param);

	if (!psignal_param) {
		ERRORPRINT("Global Signal Object not yet initialized. Please initialize it first...\n");
		return -1;
	}	

	psignal_param->set_signal_param(pname, psignal_callbackin, !signal_callback_will_exit);

	if (set_thr_name) {
		prctl(PR_SET_NAME, (unsigned long)pname);
	}

	if (exit_on_parent_kill) {
		psignal_param->set_signal_handler(SIGHUP, GY_SIGNAL_HANDLER::gsighdlr);

		prctl(PR_SET_PDEATHSIG, SIGHUP);
	}
	else {
		psignal_param->ignore_signal(SIGHUP);
	}	

	if (!pignore_fd_close && nignore_fd_close) {
		nignore_fd_close = 0;
	}

	for (i = start_fd_close; i < end_fd_close; i++) {
		for (size_t j = 0; j < nignore_fd_close; j++) {
			if (i == pignore_fd_close[j]) {
				goto ignore_cl;	
			}	
		}
		(void)close(i);
ignore_cl :
		;
	}

	if (pstdout_log) {
		fd_stdout = open(pstdout_log, O_RDWR | O_CREAT | log_flags, 0660);
		if (fd_stdout < 0) {
			PERRORUNLOCKPRINT("Could not open %s child stdout log file %s", pname, pstdout_log);
		}
		else {
			dup2(fd_stdout, STDOUT_FILENO);

			if (chown_uid || chown_gid) {
				fchown(fd_stdout, chown_uid, chown_gid);
			}	

			if (!pstderr_log || (0 == strcmp(pstdout_log, pstderr_log))) {
				dup2(fd_stdout, STDERR_FILENO);
				pstderr_log = nullptr;
			}	
		}
	}

	if (pstderr_log) {
		fd_stderr = open(pstderr_log, O_RDWR | O_CREAT | log_flags, 0660);
		if (fd_stderr < 0) {
			PERRORUNLOCKPRINT("Could not open %s child stderr log file %s", pname, pstderr_log);
		}
		else {
			if (chown_uid || chown_gid) {
				fchown(fd_stderr, chown_uid, chown_gid);
			}	

			dup2(fd_stderr, STDERR_FILENO);
		}
	}

	IRPRINT("\n\n");

	INFOPRINT("%s Child PID %d starting %s...\n\n", pname, getpid(), pdesc ? pdesc : ""); 
	
	return 0;
}

int truncate_file_wrap_last(char *filename, size_t truncate_if_size_over, size_t last_bytes_to_wrap) noexcept
{
	int 			fd, ret, olderrno = 0;
	char			buf[2048], *pbuf;
	struct stat		stat1;
	size_t			nbytes = 0;
	ssize_t			sret, sret2;
	off_t			oread, owrite = 0;

	fd = open(filename, O_RDWR | O_CREAT | O_CLOEXEC, 0660);
	if (fd == -1) {
		return -1;
	}	

	fstat(fd, &stat1);
	if ((size_t)stat1.st_size <= last_bytes_to_wrap) {
		(void)close(fd);
		return 0;
	}
	else if ((size_t)stat1.st_size <= truncate_if_size_over) {
		(void)close(fd);
		return 0;
	}	

	oread = stat1.st_size - last_bytes_to_wrap;

	while (nbytes < last_bytes_to_wrap) {
		sret = pread(fd, buf, sizeof(buf), oread);
		if (sret < 0) {
			if (errno == EINTR) {
				continue;
			}	
			else {
				olderrno = errno;
				(void)close(fd);
				errno = olderrno;
				return -1;
			}	
		}	
		else if (sret == 0) {
			break;
		}	

		sret2 = pwrite(fd, buf, sret, owrite);
		if (sret2 != sret) {
			olderrno = errno;
			(void)close(fd);
			errno = olderrno;
			return -1;	
		}	

		owrite += sret2;
		oread += sret2;
		nbytes += sret2;
	}	

	ret = ftruncate(fd, nbytes);
	if (ret != 0) {
		olderrno = errno;
		(void)close(fd);
		errno = olderrno;
		return -1;	
	}	

	(void)close(fd);
	return 0;
}	

/*
 * Returns the dirname ptr. Users need to pass a local uninitialized UNIQUE_C_PTR which
 * will be updated by this func
 */
const char * gy_dirname(const char *pathorig, UNIQUE_C_PTR & retuniq) noexcept
{
	char 			*path, *pdir, *ptemp, *pendptr, lastc;
	const char		*pres = "";

	if (!pathorig) return nullptr;

	path = strdup(pathorig);
	if (!path) {
		return nullptr;
	}

	if ((strcmp(path, "/") == 0) || (strcmp(path, ".") == 0) || (strcmp(path, "..") == 0)) {
		pres = path;
		goto end_func;
	}

	pdir = path;

	pendptr = pdir + strlen(pdir) - 1;
	lastc = *pendptr;

	ptemp = strrchr(pdir, '/');
	if (!ptemp) {
		pres = ".";
		goto end_func;
	}

	if (ptemp > pdir) {
		*ptemp = '\0';
		ptemp--;
	}
	else {
		*(ptemp + 1) = '\0';
		pres = pdir;
		goto end_func;
	}

	while (ptemp > pdir) {
		if (*ptemp == '/') ptemp--;
		else break;
	}

	*(ptemp + 1) = '\0';

	if (lastc != '/') {
		pres = pdir;
		goto end_func;
	}

	while (ptemp > pdir) {
		if (*ptemp != '/') ptemp--;
		else break;
	}

	if (ptemp != pdir) {
		pres = pdir;
		*ptemp = '\0';
	}
	else {
		pres = ".";
	}

end_func:

	retuniq.reset(path);

	return pres;
}

/*
 * Returns the basename ptr. Users need to pass a local uninitialized UNIQUE_C_PTR which
 * will be updated by this func
 */
const char * gy_basename(const char *pathorig, UNIQUE_C_PTR & retuniq) noexcept
{
	char 		*path, *pdir, *ptemp, *pendptr, lastc;
	const char 	*pres = "";

	if (!pathorig) return nullptr;

	path = strdup(pathorig);
	if (!path) {
		return nullptr;
	}

	if ((strcmp(path, "/") == 0) || (strcmp(path, ".") == 0) || (strcmp(path, "..") == 0)) {
		pres = path;
		goto end_func;
	}

	pdir = path;

	pendptr = pdir + strlen(pdir) - 1;
	lastc = *pendptr;

	ptemp = strrchr(pdir, '/');
	if (!ptemp) {
		pres = pdir;
		goto end_func;
	}

	if (lastc != '/') {
		pres = ptemp + 1;
		goto end_func;
	}

	while (ptemp > pdir) {
		if (*ptemp == '/') ptemp--;
		else break;
	}

	*(ptemp + 1) = '\0';

	ptemp = strrchr(pdir, '/');
	if (!ptemp) {
		pres = pdir;
		goto end_func;
	}
	else {
		if (ptemp <= pendptr) {
			pres = ptemp + 1;
			goto end_func;
		}
		else {
			pres = pdir;
			goto end_func;
		}
	}

end_func :

	retuniq.reset(path);

	return pres;
}

/*
 * Copied from systemd ...
 */
char * gy_path_cleanup(char *path, bool kill_dots) noexcept 
{
	char 			*f, *t;
	bool 			slash = false, ignore_slash = false, absolute;

	assert(path);

	/* Removes redundant inner and trailing slashes. Also removes unnecessary dots
	 * if kill_dots is true. Modifies the passed string in-place.
	 *
	 * ///foo//./bar/.   becomes /foo/./bar/.  (if kill_dots is false)
	 * ///foo//./bar/.   becomes /foo/bar      (if kill_dots is true)
	 * .//./foo//./bar/. becomes ./foo/bar     (if kill_dots is false)
	 * .//./foo//./bar/. becomes foo/bar       (if kill_dots is true)
	 */

	absolute = path_is_absolute(path);

	f = path;
	if (kill_dots && *f == '.' && ((f[1] == '\0') || (f[1] == '/'))) {
		ignore_slash = true;
		f++;
	}

	for (t = path; *f; f++) {

		if (*f == '/') {
			slash = true;
			continue;
		}

		if (slash) {
			if (kill_dots && *f == '.' && ((f[1] == '\0') || (f[1] == '/'))) {
				continue;
			}	

			slash = false;
			if (ignore_slash)
				ignore_slash = false;
			else
				*(t++) = '/';
		}

		*(t++) = *f;
	}

	/* Special rule, if we are talking of the root directory, a trailing slash is good */
	if (absolute && t == path) {
		*(t++) = '/';
	}	

	*t = 0;
	return path;
}

int gy_mkdir_recurse(const char *pdir, mode_t mode, uid_t chown_uid, gid_t chown_gid) noexcept
{
	int			ret;
	struct stat		stat1;

	assert(pdir);

	ret = mkdir(pdir, mode);
	if ((ret == 0) || (errno == EEXIST)) {

		if (ret == 0) {
			if (chown_uid || chown_gid) {
				chown(pdir, chown_uid, chown_gid);
			}
		}

		ret = stat(pdir, &stat1);
		if ((ret == 0) && (!S_ISREG(stat1.st_mode))) {
			return 0;
		}
		else {
			if (errno == 0) {
				errno = EEXIST;
			}	
			return -1;
		}	
	}	
	else if (errno != ENOENT) {
		return -1;
	}	

	// Need to create a dir component
	
	char			path[GY_PATH_MAX];
	char			*ptmp, *pend;	

	GY_STRNCPY(path, pdir, sizeof(path));
	
	gy_path_cleanup(path, true /* kill_dots */);
	
	ptmp 	= path;
	pend 	= path + strlen(path);

	if (*ptmp == '/') ptmp++;

	do {
		ptmp = strchr(ptmp, '/');
		if (!ptmp) {
			ret = mkdir(path, mode);
			if ((ret == 0) || (errno == EEXIST)) {

				if (ret == 0) {	
					if (chown_uid || chown_gid) {
						chown(pdir, chown_uid, chown_gid);
					}
			 	}

				ret = stat(pdir, &stat1);
				if ((ret == 0) && (!S_ISREG(stat1.st_mode))) {

					return 0;
				}
				else {
					if (errno == 0) {
						errno = EEXIST;
					}	
					return -1;
				}	
			}
			else {
				return -1;
			}	
		}	
		*ptmp = '\0';

		ret = mkdir(path, mode);
		if ((ret == 0) || (errno == EEXIST)) {
			if (ret == 0) {
				if (chown_uid || chown_gid) {
					chown(pdir, chown_uid, chown_gid);
				}
			}

			*ptmp++ = '/';
			continue;
		}
		else {
			return -1;
		}	

	} while (ptmp < pend);

	return -1;
}	

/*
 * Rename files (works across mount partions) 
 */ 
int gy_rename(char *poldpath, char *pnewpath, bool rename_across_mounts, uid_t chown_uid, gid_t chown_gid) noexcept
{
	int			ret, fdo, fdn, retw;
	uint64_t		nbytes;

	ret = rename(poldpath, pnewpath);
	if (ret < 0) {
		if (errno != EXDEV) {
			PERRORPRINT("Rename of file %s to %s failed", poldpath, pnewpath);
			return -1;
		}
		if (rename_across_mounts == false) {
			PERRORPRINT("Rename of file %s to %s failed", poldpath, pnewpath);
			return -1;
		}
	}
	else {
		return 0;
	}

	ret = gy_copyfile(poldpath, pnewpath, true /* ignore_stat_size_0 */, chown_uid, chown_gid);
		
	if (ret != 0) {
		unlink(pnewpath);
	}
	else {		
		unlink(poldpath);
	}

	return 0;
}

int gy_create_tmpfs(char *dest_dir, uint32_t size_mb, mode_t mode, int is_noatime) noexcept
{
	int			ret;
	char			databuf[128];

	INFOPRINT("Creating a new swap mounted partition on %s path of size %d MB opt = 0%o : %d\n", dest_dir, size_mb, mode, is_noatime);

	ret = mkdir(dest_dir, mode);
	if (ret) {
		PERRORPRINT("Could not create Destination dir for swap : %s", dest_dir);
		return -1;
	}

	snprintf(databuf, sizeof(databuf), "mode=%o,size=%uM", mode, size_mb);
	ret = mount("none", dest_dir, "tmpfs", MS_MGC_VAL | (is_noatime ? MS_NOATIME : 0), databuf);
	if (ret) {
		PERRORPRINT("Failed to mount destination dir %s", dest_dir);

		rmdir(dest_dir);
		return -1;
	}

	return 0;	
}


int gy_check_dir_mounttype(char *dest_dir, int *pis_tmpfs) noexcept
{
	int			fd, ret;
	char			buf[2048], dbuf[255], *ptmp, *pend;

	fd = open("/proc/self/mounts", O_RDONLY);
	if (fd < 0) {
		PERRORPRINT("open mount file failed");
		return -1;
	}	

	ret = read(fd, buf, sizeof(buf) - 1);
	if (ret < 0) {
		PERRORPRINT("read mount file failed");
		(void)close(fd);
		return -1;
	}
	(void)close(fd);

	buf[ret] = '\0';

	pend = buf + ret - 1;

	ret = GY_SAFE_SNPRINTF(dbuf, sizeof(dbuf), "%s", dest_dir);
	if (ret > 1 && dbuf[ret - 1] == '/') {
		dbuf[ret - 1] = '\0';
	}

	ptmp = (char *)strstr(buf, dbuf);
	if (!ptmp) {
		INFOPRINT("Could not locate mount type of dir : %s\n", dbuf);
		return -1;
	}

	ptmp += strlen(dbuf);
	while (ptmp < pend) {
		if (*ptmp != ' ') {
			ptmp++;
		}
		else {
			break;
		}
	}

	if (ptmp == pend) {
		return 0;
	}
	ptmp++; 

	if (strncmp(ptmp, "tmpfs", 5) == 0) {
		*pis_tmpfs = 1;
		return 0;
	}

	return 0;
}

static inline int gy_print_row(int fd, const uint8_t *buf, uint32_t len, int print_ascii) noexcept
{
	uint32_t 	i = 0, nchar = 0, slen;
	uint8_t		printbuf[512], *ptemp, c;
	const uint8_t	*pinput = buf;
	int		ret;

	assert(len <= 16);
	
	if (len > 16) {
		len = 16;
	}	

	ptemp = printbuf;

	for (i = 0; i < len; i++) {
		slen = sprintf((char *)ptemp, "%02X ", *pinput++);
		ptemp += slen;
		nchar += slen;
	}

	for (i = len; i < 16; i++) {
		*ptemp++ = ' ';
		*ptemp++ = ' ';
		*ptemp++ = ' ';
		nchar += 3;
	}

	if (print_ascii) {
		pinput = buf;

		*ptemp++ = '\t';
		nchar++;

		for (i = 0; i < len; i++) {
			c = *pinput++;
			if (isprint(c)) {
				slen = sprintf((char *)ptemp, "%c", c);
			}
			else {
				slen = sprintf((char *)ptemp, ".");

			}
			ptemp += slen;
			nchar += slen;
		}
	}

	*ptemp++ = '\n';
	*ptemp = '\0';
	nchar += 1;

	ret = write(fd, printbuf, nchar);
	if (ret != (int32_t)nchar) {
		PERRORPRINT("write of print buf failed");
		return -1;
	}			

	return ret;
}

/*
 * Function to print the buffer onto a file fd.
 * Example usage :
 * gy_print_buf(STDERR_FILENO, pthr->payload, pthr->payload_len, 1, "Test Message");
 */ 
void gy_print_buf(int fd, const uint8_t *buf, uint32_t len, int print_ascii, const char *msg) noexcept
{
	uint32_t	nrows, lenleft, tlen;
	uint8_t		sbuf[128];
	const uint8_t	*tbuf;
	int		ret, i;

	ret = GY_SAFE_SNPRINTF((char *)sbuf, sizeof(sbuf), "\nPrinting buffer : %s\n", msg ? msg : "");

	write(fd, sbuf, ret);

	nrows = len / 16;
	if (nrows == 0) {
		gy_print_row(fd, buf, len, print_ascii);
		return;
	}

	lenleft = len % 16;

	tbuf = buf;
	tlen = len;

	for (i = 0; i < (int32_t)nrows; i++) {
		ret = gy_print_row(fd, tbuf, 16, print_ascii);
		if (ret < 0) {
			return;
		}
		tbuf += 16;
		tlen -= 16;
	}

	if (lenleft) {
		ret = gy_print_row(fd, tbuf, lenleft, print_ascii);
	}

	write(fd, "\n", 1);
}


int gy_linkpath(const char *pfilename, char *bufpath, int szbuf) noexcept
{
	char		buf1[PATH_MAX];
	char 		*ptmp = buf1, *pret;

	pret = realpath(pfilename, ptmp);
	if (!pret) {
		return -errno;
	}	

	GY_STRNCPY(bufpath, ptmp, szbuf > 0 ? szbuf - 1 : 0);
		
	return 0;
}

void gy_argv_free(char **argv) noexcept
{
	if (argv) {
		argv--;
		free((void *)argv[0]);
		free((void *)argv);
	}
}

/*
 * Function to split up a single string into argv style buffers.
 * Use the <return value>.get() to get the char **argv
 */ 
FUNC_DELETE_PTR<char *, gy_argv_free> gy_argv_split(const char *poriginput, int & argc, size_t max_strlen) noexcept
{
	char		*pinput, **argv, **argv_ret, *ptmp, *pend;
	int		max_str, was_space;

	argc = 0;

	pinput = strndup(poriginput, max_strlen);
	if (!pinput) {
		PERRORUNLOCKPRINT("strdup failed %s", __FUNCTION__);
		return nullptr;
	}

	ptmp = pinput;

	for (max_str = 0, was_space = 1; *ptmp; ptmp++) {
		if (isspace(*ptmp)) {
			was_space++;
		}
		else if (was_space > 0) {
			was_space = 0;
			max_str++;
		}
	}

	pend = ptmp;

	if (max_str == 0) {
		free(pinput);
		return nullptr;
	}

	argv = (char **)calloc(max_str + 2, sizeof(char *));
	if (!argv) {
		PERRORUNLOCKPRINT("calloc failed in %s", __FUNCTION__);
		free(pinput);
		return nullptr;
	}

	*argv = pinput;
	argv_ret = ++argv;

	for (was_space = 1; *pinput; pinput++) {
		if (isspace(*pinput)) {
			was_space++;
			*pinput = 0;
		}
		else if (was_space > 0) {
			was_space = 0;
			*argv++ = pinput;
		}
	}

	*argv = nullptr;

	argc = max_str;

	return FUNC_DELETE_PTR<char *, gy_argv_free>(argv_ret);
}


/*
 * This buffer will create an email compliant buffer stream. 
 * It will replace all '\n' by \r\n
 * poutput should be of size twice len.
 *
 * It will return number of bytes written to output buffer.
 */  
int gy_create_mail_buffer(char *pmsg, int len, char *poutput, int maxlen) noexcept
{
	char		lastc = 0, c, *pstart, *pend, *postart, *poend;

	pstart = pmsg;
	pend = pmsg + len - 1;

	postart = poutput;
	poend = poutput + maxlen - 1;

	while ((pstart <= pend) && (postart < poend)) {
		if (((c = *pstart++) == '\n') && (lastc != '\r')) {
			*postart++ = '\r';
		}

		*postart++ = c;
		lastc = c;
	}

	return postart - poutput;
}

int gy_close_socket(int sock) noexcept
{
	int		ret;

	::shutdown(sock, SHUT_RDWR);

	ret = close(sock);

	return ret;	
}

int set_thread_prio(pthread_t thread_id, int policy, int prio) noexcept 
{
	struct sched_param 	param;
	int 			ret;

	// To set the scheduling priority of the thread
	param.sched_priority = prio;
	ret = pthread_setschedparam(thread_id, policy, &param);
	if (ret) {
		return -errno;
	}

	return 0;
}

int gy_clean_recur_dir(const char *pstr, int del_subdir, time_t file_del_time, const char *pmemcmpstr, const char *psubstr) noexcept
{
	DIR			*pdir;
	struct dirent		*pdent;
	char			*pfile, path[256];
	struct stat		stat1;
	int			ret;

	pdir = opendir(pstr);
	if (!pdir) {
		return -1;
	}

	while ((pdent = readdir(pdir)) != nullptr) {

		pfile = pdent->d_name;	

		if (strcmp(pfile, ".") == 0) {
			continue;
		}

		if (strcmp(pfile, "..") == 0) {
			continue;
		}

		if (pmemcmpstr) {
			if (0 != memcmp(pfile, pmemcmpstr, strlen(pmemcmpstr))) {
				continue;
			}
		}

		if (!pmemcmpstr && psubstr) {
			if (nullptr == (strstr(pfile, psubstr))) {
				continue;
			}
		}

		snprintf(path, sizeof(path), "%s/%s", pstr, pfile);

		ret = stat(path, &stat1);
		if (ret == 0) {
			if (!S_ISDIR(stat1.st_mode)) {
				if ((file_del_time == 0) || ((unsigned long)stat1.st_mtime <= (unsigned long)file_del_time)) {
					unlink(path);
				}
			}
			else if (del_subdir) {
				ret = gy_clean_recur_dir(path, del_subdir, file_del_time, pmemcmpstr, psubstr);
				rmdir(path);
			}
		}
	}

	closedir(pdir);

	return 0;
}

uint64_t gy_get_dir_disk_usage(const char *pdirname, const char *psearchname) noexcept
{
	DIR			*pdir;
	struct dirent		*pdent;
	char			*pfile, path[256];
	struct stat		stat1;
	int			ret;
	uint64_t		tot = 0ull;

	if (!pdirname) {
		return 0ull;
	}

	pdir = opendir(pdirname);
	if (!pdir) {
		return 0ull;
	}

	while ((pdent = readdir(pdir)) != nullptr) {

		pfile = pdent->d_name;	

		if (strcmp(pfile, ".") == 0) {
			continue;
		}

		if (strcmp(pfile, "..") == 0) {
			continue;
		}

		snprintf(path, sizeof(path), "%s/%s", pdirname, pfile);

		ret = stat(path, &stat1);
		if (ret == 0) {
			if (!S_ISDIR(stat1.st_mode)) {
				if (psearchname) {
					if (0 != memcmp(pfile, psearchname, strlen(psearchname))) {
						continue;
					}
				}

				tot += stat1.st_size;
			}
			else {
				tot += gy_get_dir_disk_usage(path, psearchname);
			}
		}
	}

	closedir(pdir);

	return tot;
}


int gy_hex_to_string(const uint8_t *phexstr, const uint32_t len, uint8_t *pstrout, uint32_t lenout, int null_terminate) noexcept
{
	uint32_t		i, tot = 0;
	int			ret;

	if (gy_unlikely(lenout < 2 * len + 2)) {
		return -1;	
	}

	strcpy((char *)pstrout, "0x");
	tot = 2;

	for (i = 0; i < len; i++) {
		ret = sprintf((char *)pstrout + tot, "%.2x", phexstr[i]);
		if (ret != 2) {
			if (tot > 2) {
				break;
			}	
			return -1;	
		}

		tot += ret;
	}

	if (null_terminate) {
		if (tot + 1 <= lenout) {
			pstrout[tot] = '\0';
		}
	}

	return 0;
}

/*
 * Returns Number of bytes updated to phexout
 * or -1 for errors.
 */ 
int gy_string_to_hex(const uint8_t *pstrinput, const uint32_t len, uint8_t *phexout, uint32_t lenout) noexcept
{
	uint32_t		i = 0, tot = 0, temp;
	int			ret;

	if ((len >= 2) && (pstrinput[0] == '0') && (tolower(pstrinput[1]) == 'x')) {
		i = 2;
	}

	if (gy_unlikely(lenout < (len - i)/2)) {
		return -1;	
	}

	for (; i < len; i += 2) {
		ret = sscanf((char *)pstrinput + i, "%2x", &temp);
		if (ret != 1) {
			if (tot > 0) {
				break;
			}	
			return -1;	
		}

		phexout[tot++] = temp;
	}

	return tot;
}

/*
 * Reverse memcmp function
 */ 
int gy_memrcmp(const void *s1, const void *s2, size_t n) noexcept
{
	char			*p1 = (char *)s1, *p2 = (char *)s2;
	uint32_t		i;

	if (gy_unlikely(n == 0)) {
		return -1;
	}

	for (i = n - 1; (int)i >= 0; i--) {
		if (p1[i] != p2[i]) {
			return p1[i] - p2[i];
		}
	}

	return 0;
}

/*
 * Case insensitive memcmp function
 */ 
int gy_memcasecmp(const void *s1, const void *s2, size_t n) noexcept
{
	char			*p1 = (char *)s1, *p2 = (char *)s2;
	uint32_t		i;

	if (gy_unlikely(n == 0)) {
		return -1;
	}

	for (i = 0; i < n; i++) {
		if ((gy_toupper_ascii(p1[i])) != (gy_toupper_ascii(p2[i]))) {
			return p1[i] - p2[i];
		}
	}

	return 0;
}


bool get_version_from_string(const char *pversion, uint32_t & version, uint8_t *poctet_array, int num_octets) noexcept
{
	const char		*verfmt;
	int			ret;

	assert(pversion && poctet_array);

	version = 0;

	switch (num_octets) {
	
	case 1 :	ret = sscanf(pversion, "%hhu", &poctet_array[0]); break;
	case 2 :	ret = sscanf(pversion, "%hhu.%hhu", &poctet_array[0], &poctet_array[1]); break;
	case 3 :	ret = sscanf(pversion, "%hhu.%hhu.%hhu", &poctet_array[0], &poctet_array[1], &poctet_array[2]); break;
	case 4 :	ret = sscanf(pversion, "%hhu.%hhu.%hhu.%hhu", &poctet_array[0], &poctet_array[1], &poctet_array[2], &poctet_array[3]); break;

	default : 	return false;
	}	

	if (ret != num_octets) {
		return false;
	}	

	for (int i = num_octets - 1, j = 0; i >= 0; --i, ++j) {
		version |= (poctet_array[i] << (j * 8));
	}	

	return true;
}
	
uint32_t get_version_from_string(const char *pversion, int num_octets) noexcept
{
	uint32_t		version = 0;
	uint8_t			ver_sub[4];
	bool			bret;

	if ((unsigned)num_octets > 4) {
		return ~0u;
	}
	
	bret = get_version_from_string(pversion, version, ver_sub, num_octets);
	if (bret == true) {
		return version;
	}	

	return ~0u;
}

int gy_fork_system(char *systemcmd, char *pdirchange, int to_wait, pid_t *pchldpid, int prctlsigno, const char *plogpath, uid_t ch_uid, gid_t ch_gid, bool ignore_sighup, bool drop_all_cap) noexcept
{
	pid_t 			cpid, w;	
	int 			status, ret = -1, i, argc, fdlog;
	char			**argv;
		
	cpid = fork();
	if (cpid == -1) { 
		PERRORUNLOCKPRINT("fork of process failed"); 
		return -1;
	}

	if (cpid == 0) { 
		// Now reset all permissions.

		if (ch_uid) {
			setuid(ch_uid);
		}

		if (ch_gid) {
			setgid(ch_gid);
		}

		for (i = 8192; i > 2; i--) close(i);

		if (prctlsigno) {
			prctl(PR_SET_PDEATHSIG, prctlsigno);
		}

		if (pdirchange) chdir(pdirchange);

		if (ignore_sighup) {
			signal(SIGHUP, SIG_IGN);
		}

		auto argptr = gy_argv_split(systemcmd, argc);
		if (!argptr) {
			ERRORFDPRINT(STDERR_FILENO, "Failed to parse input fork string, fork child exiting...\n");
			_exit(1);
		}

		argv = argptr.get();

		if (plogpath) {
			fdlog = open(plogpath, O_RDWR | O_CREAT | O_APPEND, 0664);

			if (fdlog < 0) {
				PERRORPRINT("Opening Log file %s failed", plogpath);
			}
			else {
				if (dup2(fdlog, STDOUT_FILENO) != STDOUT_FILENO) {
					PERRORPRINT("Duplicating %s Log file to stdout failed", plogpath);
				}
				if (dup2(fdlog, STDERR_FILENO) != STDERR_FILENO) {
					PERRORPRINT("Duplicating %s Log file to stderr failed", plogpath);
				}
			}
		}

		// Now drop all capabilities if required
		if (drop_all_cap) {
			GY_CAPABILITIES	::proc_clear_all_cap();
		}
			
		ret = execv(argv[0], argv);

		PERRORUNLOCKPRINT("execv on fork proc failed for process %s", argv[0]); 

		_exit(ret);
	} 
	else {
		if (to_wait == 0) {
			if (pchldpid) {
				*pchldpid = cpid;
			}
			return 0;
		}

try_again :
		w = waitpid(cpid, &status, WUNTRACED);
		if (w == -1) { 
			if (errno == EINTR) {
				goto try_again;
			}
			PERRORUNLOCKPRINT("waitpid on fork proc failed"); 
			return -1;
		}

		if (WIFEXITED(status)) {
			ret = WEXITSTATUS(status);
		} 
	}

	return ret;
}

ssize_t gy_copy_file_range(int fdin, int fdout, size_t bytes_to_copy, loff_t *poffin, loff_t *poffout, uint32_t flags) noexcept
{
	static int 				ghave_sys_copy = -1;
	ssize_t					ret, bytes = 0;

	if (ghave_sys_copy == 0) {
		errno = ENOSYS;
		return -1;
	}	

#	ifndef __NR_copy_file_range

#	ifdef __x86_64__
#	define __NR_copy_file_range 		326	/* Valid on x86_64 only */
#	else
#	error "__NR_copy_file_range is not defined in your system header file. Please define the appropriate macro for your processor."
#	endif

#	endif

	do {
		ret = syscall(__NR_copy_file_range, fdin, poffin, fdout, poffout, bytes_to_copy, flags);
	
		if (ghave_sys_copy < 0) ghave_sys_copy = (ret >= 0 || errno != ENOSYS);

		if (ret <= 0) {
			if (bytes == 0) {
				bytes = -1;
			}	
			break;
		}

		bytes += ret;
		bytes_to_copy -= ret;

	} while (bytes_to_copy > 0);

	return bytes;
}	

/*
 * Note : File offset of infd is not modified
 */
ssize_t gy_sendfilefd(int infd, int outfd, size_t bytes_to_send) noexcept
{
	ssize_t		oret, bytes = 0;
	off_t 		ioff = 0;

	while (bytes_to_send > 0) {

		oret = sendfile(outfd, infd, &ioff, bytes_to_send);
		if (oret <= 0) {
			if (bytes == 0) {
				bytes = -1;
			}	
			break;
		}	

		bytes += oret;
		bytes_to_send -= oret;
	}
	
	return bytes;
}

int gy_copyfile(const char *infile, const char *outfile, bool ignore_stat_size_0, uid_t chown_uid, gid_t chown_gid) noexcept
{
	ssize_t		bytes, bytes_to_copy, obytes = 0;
	int		ifd, ofd, olderrno, ret = 0;
	struct stat	sb;
	off_t 		ioff = 0;

	ifd = open(infile, O_RDONLY);
	if (ifd == -1) {
		return -1;
	}

	if (0 != fstat(ifd, &sb)) {
		olderrno = errno;
		(void)close(ifd);
		errno = olderrno;
		return -1;
	}

	bytes_to_copy = sb.st_size;

	ofd = open(outfile, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (ofd == -1) {
		olderrno = errno;
		(void)close(ifd);
		errno = olderrno;
		return -1;
	}	

	if (chown_uid || chown_gid) {
		fchown(ofd, chown_uid, chown_gid);
	}	

	if (bytes_to_copy == 0 && ignore_stat_size_0) {
		// Virtual FS type file likely. Just use normal read/write with max file size as 100 MB
		bytes_to_copy = 100 * 1024 * 1024; 
		goto readwr;
	}
		
	/*
	 * First try using using copy_file_range() syscall. If it errors then try sendfile(). If that fails as well,
	 * use normal read write. 
	 */
	bytes = gy_copy_file_range(ifd, ofd, bytes_to_copy);
	
	olderrno = errno;

	if (bytes != -1) {
		close(ifd);
		close(ofd);
		errno = olderrno;

		if (bytes != bytes_to_copy) {
			return -1;
		}	

		return 0;
	}	

	DEBUGEXECN(5,
		PERRORPRINT("Copying files using copy_file_range failed for files %s to %s : Using sendfile", infile, outfile);
	);	

	bytes = gy_sendfilefd(ifd, ofd, bytes_to_copy);
	
	olderrno = errno;

	if (bytes != -1) {
		close(ifd);
		close(ofd);
		errno = olderrno;

		if (bytes != bytes_to_copy) {
			return -1;
		}	

		return 0;
	}	

	DEBUGEXECN(5,
		PERRORPRINT("Copying files using sendfile failed for files %s to %s : Using read/write", infile, outfile);
	);	

readwr :
	// Use normal read/write : File offset of ifd has not been modified

	uint8_t			buf[4096];

	ret = 0;

	while (bytes_to_copy > 0) {
		bytes = gy_readbuffer(ifd, buf, sizeof(buf));

		olderrno = errno;

		if (bytes > 0) {
			obytes = gy_writebuffer(ofd, buf, bytes);
			
			olderrno = errno;
			if (obytes != bytes) {
				ret = -1;
				break;
			}	

			bytes_to_copy -= obytes;
		}	
		else if (ignore_stat_size_0 && obytes > 0) {
			break;
		}	
		else {
			ret = -1;
			break;
		}	
	}	

	close(ifd);
	close(ofd);
	errno = olderrno;
				
	return ret;
}	
	
ssize_t gy_filesend(int sockfd, const char *fname) noexcept
{
	ssize_t		bytes;
	int		ifd, olderrno;
	struct stat	sb;
	off_t 		ioff = 0;

	ifd = open(fname, O_RDONLY);
	if (ifd == -1) {
		return -1;
	}

	if (0 != fstat(ifd, &sb)) {
		olderrno = errno;
		close(ifd);
		errno = olderrno;
		return -1;
	}

	if (sb.st_size > 0) {
		bytes = gy_sendfilefd(ifd, sockfd, sb.st_size);
	}
	else {
		// Use normal read/send as we do not know the size of the file

		uint8_t			buf[4096];
		ssize_t			tbytes, obytes;

		bytes = 0;

		while (true) {
			tbytes = ::read(ifd, buf, sizeof(buf));

			if (tbytes > 0) {
				obytes = gy_sendbuffer(sockfd, buf, tbytes);
				
				if (obytes != tbytes) {
					if (obytes > 0) {
						bytes += obytes;
					}	
					else if (bytes == 0) {
						bytes = -1;
					}	

					break;
				}	

				bytes += obytes;
			}	
			else if (bytes == 0) {
				break;
			}	
			else if (errno != EINTR) {
				if (bytes == 0) {
					bytes = -1;
				}	
				break;
			}	
		}	
	}	
	
	olderrno = errno;
	close(ifd);
	errno = olderrno;

	return bytes;
}


ssize_t gy_sendbuffer(int sockfd, const void *buf, size_t buflen, int flags, bool ignore_epipe) noexcept
{
	const char 		*pbuf = static_cast<const char *>(buf);
	ssize_t			bytes_to_send = buflen, bytes;

	if (ignore_epipe) {
		flags |= MSG_NOSIGNAL;
	}
		
	do {
		bytes = ::send(sockfd, pbuf, bytes_to_send, flags);

		if (bytes > 0) {
			bytes_to_send -= bytes;
			pbuf += bytes;
		}
		else if (bytes == 0) {
			continue;
		}	
		else if (errno == EINTR) {
			continue;
		}
		else if (errno == EAGAIN) {
			return buflen - bytes_to_send;
		}	
		else {
			return -1;
		}

	} while (bytes_to_send > 0);

	return buflen;
}

/*
 * Specify no_block_after_first_recv as false if you know how many bytes are expected to be received. 
 * Default is true, which means recv all data blocking till the first payload arrives but don't block thereafter.
 *
 * min_bytes_to_recv can be specified as non-zero if any recv less than that should error out
 */ 
ssize_t gy_recvbuffer(int sockfd, void *buf, size_t bytes_to_recv, int flags, bool no_block_after_first_recv, size_t min_bytes_to_recv) noexcept
{
	char 			*pbuf = static_cast<char *>(buf);
	ssize_t			tbytes_to_recv = bytes_to_recv, bytes;

	do {
		bytes = ::recv(sockfd, pbuf, tbytes_to_recv, flags);

		if (bytes > 0) {
			tbytes_to_recv -= bytes;
			pbuf += bytes;

			if (no_block_after_first_recv) {
				flags |= MSG_DONTWAIT;
			}	
		}
		else if (bytes == 0) {
			if (bytes_to_recv) {
				if (min_bytes_to_recv && (bytes_to_recv - (size_t)tbytes_to_recv < min_bytes_to_recv)) {
					return -1;
				}
				if ((size_t)tbytes_to_recv < bytes_to_recv) {
					return bytes_to_recv - tbytes_to_recv;	
				}
				return -1;	
			}
			else {
				// Most likely a check for socket validity
				return 0;	
			}		
		}	
		else if (errno == EINTR) {
			continue;
		}
		else {
			if (min_bytes_to_recv && (bytes_to_recv - (size_t)tbytes_to_recv < min_bytes_to_recv)) {
				return -1;
			}	
			if (tbytes_to_recv > 0) {
				return bytes_to_recv - tbytes_to_recv;	
			}
			else if (errno == EAGAIN) {
				return 0;
			}	
			return -1;
		}

	} while (tbytes_to_recv > 0);

	return bytes_to_recv;
}

bool is_socket_still_connected(int sock, bool is_peer_writeable) noexcept
{
	int			ret;
	struct pollfd 		pfds[1];

	pfds[0].fd 	= sock;
	pfds[0].events 	= POLLIN | POLLOUT | (is_peer_writeable ? POLLRDHUP : 0);
	pfds[0].revents = 0;

	ret = ::poll(pfds, 1, 0);
	if (ret > 0) {
		if (pfds[0].revents & (POLLHUP | POLLERR | POLLNVAL | POLLRDHUP)) {
			return false;
		}
	} 
	
	return true;
}	

/*
 * Returns > 0 on success, 0 on timeout and -1 on errors. 
 * The poll output events are updated to revents. If close_on_errors is specified and revents shows sock close will close the socket
 * poll_events should be specified with the required poll events such as POLLIN for recv and POLLOUT if send blocked
 * If close_on_errors is true, then socket will be closed on timeout or if POLLHUP or if poll failed
 */
int poll_socket(int sock, int timeout_msec, int & revents, int poll_events, bool close_on_errors) noexcept
{
	int			ret;
	struct pollfd 		pfds[1];

	if (sock < 0) {
		return -1;
	}
		
try_again :
	pfds[0].fd 		= sock;
	pfds[0].events 		= poll_events;
	pfds[0].revents 	= 0;

	ret = ::poll(pfds, 1, timeout_msec);
	if (ret > 0) {
		revents = pfds[0].revents;

		if (pfds[0].revents & (POLLHUP | POLLERR | POLLNVAL)) {
			if (close_on_errors) {
				close(sock);
			}
			return -1;
		}

		return ret;
	} 
	else if (ret == 0) {
		if (close_on_errors) {
			close(sock);
		}
		return 0;
	}		
	else if (errno == EINTR) {
		goto try_again;
	}
	else {	
		if (close_on_errors) {
			close(sock);
		}	
		return -1;
	}
}	

ssize_t sock_peek_recv_data(int sock, void *peek_buf, size_t max_peek_len, bool is_non_block) noexcept
{
	ssize_t			sret;
	uint8_t			*pbuf = static_cast<uint8_t *>(peek_buf);
	
	assert(peek_buf);

try_again :
	sret = ::recv(sock, pbuf, max_peek_len, (is_non_block ? MSG_DONTWAIT : 0) | MSG_PEEK);
	if (sret > 0) {
		return sret;
	}	
	else if (sret < 0) {
		if (errno == EINTR) {
			goto try_again;
		}	
		else if (errno != EAGAIN) {
			return -1;
		}	

		return 0;
	}
	else if (max_peek_len) {
		return -1;
	}	
	else {
		return 0;
	}	
}


int sock_queued_recv_bytes(int sock) noexcept
{
	int			ret = 0, err;

	err = ioctl(sock, SIOCINQ, &ret);

	if (err >= 0) {
		return ret;
	}	

	return err;
}
	
int sock_queued_send_bytes(int sock) noexcept
{
	int			ret = 0, err;

	err = ioctl(sock, SIOCOUTQNSD, &ret);

	if (err >= 0) {
		return ret;
	}	

	return err;
}
	

/* 
 * Synchronous call to getaddrinfo(). Async getaddrinfo_a() not used...
 */
int gy_resolve_hostname(const char *phost, GY_IP_ADDR * ip_array, size_t nmax_ips, char (&error_buf)[128], bool only_ipv4) noexcept
{
	assert(phost && ip_array && nmax_ips);

	if ((0 != isxdigit(*phost)) || (':' == *phost)) {
		bool			is_valid = false;
		GY_IP_ADDR		ipaddr(phost, is_valid);	
		
		if (false == is_valid) {
			goto do_resol;
		}

		ip_array[0]		= ipaddr;

		return 1;
	}
	else {
do_resol :
		struct addrinfo		*res, hints;
		int			ret, nentries = 0;
		const struct addrinfo 	*r;

		memset(&hints, 0, sizeof(hints));

		hints.ai_family 	= only_ipv4 ? AF_INET : AF_UNSPEC;
		hints.ai_socktype 	= SOCK_STREAM;

		ret = ::getaddrinfo(phost, nullptr, &hints, &res);
		if (ret != 0) {
			snprintf(error_buf, sizeof(error_buf), "Could not resolve \'%s\' due to %s", phost, gai_strerror(ret));
			return -1;
		}

		GY_SCOPE_EXIT {
			::freeaddrinfo(res);
		};	

		*error_buf = '\0';

		for (r = res; r != nullptr && (unsigned)nentries < nmax_ips; r = r->ai_next) {

			if (r->ai_family == AF_INET) {
				struct sockaddr_in 	*paddr = (sockaddr_in *)r->ai_addr;

				ip_array[nentries] 	= paddr->sin_addr.s_addr;
				nentries++;
			}
			else if (r->ai_family == AF_INET6) {
				struct sockaddr_in6 	*paddr = (sockaddr_in6 *)r->ai_addr;
				
				ip_array[nentries]	 = paddr->sin6_addr;
				nentries++;
			}	
			else {
				continue;
			}	
		}	

		return nentries;
	}		
}

int gy_resolve_hostname(const char *phost, const char * pservice, IP_PORT * ip_port_array, size_t nmax_ips, char (&error_buf)[128], bool only_ipv4)
{
	assert(phost && pservice && ip_port_array && nmax_ips);

	struct addrinfo		*res, hints;
	int			ret, nentries = 0;
	const struct addrinfo 	*r;

	memset(&hints, 0, sizeof(hints));

	hints.ai_family 	= only_ipv4 ? AF_INET : AF_UNSPEC;
	hints.ai_socktype 	= SOCK_STREAM;

	ret = ::getaddrinfo(phost, pservice, &hints, &res);
	if (ret != 0) {
		snprintf(error_buf, sizeof(error_buf), "Could not resolve \'%s\' due to %s", phost, gai_strerror(ret));
		return -1;
	}

	GY_SCOPE_EXIT {
		::freeaddrinfo(res);
	};	

	*error_buf = '\0';

	for (r = res; r != nullptr && (unsigned)nentries < nmax_ips; r = r->ai_next) {

		if (r->ai_family == AF_INET) {
			ip_port_array[nentries].~IP_PORT();

			new (&ip_port_array[nentries]) IP_PORT(r->ai_addr, r->ai_addrlen);

			nentries++;
		}
		else if (r->ai_family == AF_INET6) {
			ip_port_array[nentries].~IP_PORT();

			new (&ip_port_array[nentries]) IP_PORT(r->ai_addr, r->ai_addrlen);

			nentries++;
		}	
		else {
			continue;
		}	
	}	

	return nentries;
}

/*
 * Returns a pair of socketfd and is_connected which can be false if set_nonblock is true
 * DNS resolution is done synchronously using call to getaddrinfo() even if set_nonblock is true.
 *
 * If set_nonblock is true and is_connected is returned false, the caller will need to poll the socketfd 
 * for writing followed by getsockopt() to check if the connection completed successfully. (man 2 connect)
 *
 * If always_resolve_dns == false and the serverhostname_ip is infact a Domain name instead of an IP, the DNS is handled 
 * on IP error. 
 */
std::pair <int, bool> gy_tcp_connect(const char *phost, uint16_t port, char (&error_buf)[128], const char *server_describe, bool set_nodelay, bool always_resolve_dns, struct sockaddr_storage *pconnect_sockaddr, socklen_t *psocklen, bool use_ipv4_only, bool cloexec, bool set_nonblock) noexcept
{
	int 				cfd = -1, rc = 0, ret;
	int 				to_set = set_nodelay;
	bool				is_connected = false;
	struct addrinfo			*res, hints;
	char				buf[64];

	if (psocklen) {
		*psocklen = 0;
	}	

	if (always_resolve_dns == false && phost) {

		struct sockaddr_storage		sockaddr	{};
		socklen_t			socklen;
		int				sockfamily;
		bool				is_valid = false;
		GY_IP_ADDR			tip(phost, is_valid);	

		if (false == is_valid) {
			goto retry1;
		}	
	
		if (false == tip.is_pure_ipv6()) {
			struct sockaddr_in 	*paddr = (sockaddr_in *)&sockaddr;

			tip.get_as_inaddr(&paddr->sin_addr.s_addr);

			paddr->sin_family 	= AF_INET;
			paddr->sin_port 	= htons(port);

			socklen			= sizeof(*paddr);	
			sockfamily 		= AF_INET;
		}
		else {
			struct sockaddr_in6 	*paddr = (sockaddr_in6 *)&sockaddr;
			
			tip.get_as_inaddr(&paddr->sin6_addr);

			paddr->sin6_family 	= AF_INET6;
			paddr->sin6_port 	= htons(port);

			socklen			= sizeof(*paddr);	
			sockfamily 		= AF_INET6;
		}	

		cfd = ::socket(sockfamily, SOCK_STREAM | (cloexec ? SOCK_CLOEXEC : 0) | (set_nonblock ? SOCK_NONBLOCK : 0), 0);
		if (cfd < 0) {
			char		ebuf[64];
			snprintf(error_buf, sizeof(error_buf), "Socket creation failed due to %s for \'%s\' connection", 
				strerror_r(errno, ebuf, sizeof(ebuf) - 1), server_describe);
			return {-1, false};
		}

		ret = ::connect(cfd, (const struct sockaddr *)&sockaddr, socklen); 		
		if ((ret == 0) || (errno == EINPROGRESS)) {
			if (pconnect_sockaddr && psocklen) {
				*psocklen 	= socklen;

				std::memcpy(pconnect_sockaddr, &sockaddr, sizeof(*pconnect_sockaddr));
			}	

			is_connected = (ret == 0);
		}
		else {
			char		ebuf[64];

			snprintf(error_buf, sizeof(error_buf), "Could not connect due to %s to \'%s\' (%s port %d)", 
				strerror_r(errno, ebuf, sizeof(ebuf) - 1), server_describe, phost, port);

			(void)close(cfd);	

			return {-1, false};
		}	
	}
	else {
retry1 :		
		const struct addrinfo 		*r;
		int				last_errno;

		sprintf(buf, "%hu", port);

		memset(&hints, 0, sizeof(hints));

		hints.ai_family 	= use_ipv4_only ? AF_INET : AF_UNSPEC;
		hints.ai_socktype 	= SOCK_STREAM;

		ret = ::getaddrinfo(phost, buf, &hints, &res);
		if (ret != 0) {
			snprintf(error_buf, sizeof(error_buf), "Remote server connect failed due to getaddrinfo %s for \'%s\' (%s_%hu)", gai_strerror(ret), server_describe, phost, port);
			return {-1, false};
		}	

		GY_SCOPE_EXIT {
			::freeaddrinfo(res);
		};	

		for (r = res; r != nullptr; r = r->ai_next) {

			cfd = ::socket(r->ai_family, r->ai_socktype | (cloexec ? SOCK_CLOEXEC : 0) | (set_nonblock ? SOCK_NONBLOCK : 0), r->ai_protocol);
			if (cfd < 0) {
				continue;
			}

			ret = ::connect(cfd, r->ai_addr, r->ai_addrlen);
			if ((ret == 0) || (errno == EINPROGRESS)) {
				if (pconnect_sockaddr && psocklen && (r->ai_addrlen <= sizeof(*pconnect_sockaddr))) {

					if (r->ai_addrlen <= sizeof(*pconnect_sockaddr)) {
						std::memcpy(pconnect_sockaddr, r->ai_addr, r->ai_addrlen);
						*psocklen = r->ai_addrlen;
					}	
				}	

				is_connected = (ret == 0);
				break;
			}
			
			last_errno = errno;

			::close(cfd);

			errno = last_errno;
		}	

		if (r == nullptr) {
			if (ret) {
				char		ebuf[64];
				snprintf(error_buf, sizeof(error_buf), "Unable to connect due to %s to \'%s\' (%s port %d)", strerror_r(errno, ebuf, sizeof(ebuf) - 1), server_describe, phost, port);
			}
			else {
				snprintf(error_buf, sizeof(error_buf), "Unable to connect to \'%s\' (%s port %d)", server_describe, phost, port);
			}

			return {-1, false};
		}
	}

	if (to_set && is_connected) {
		::setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &to_set, sizeof (to_set));
	}	

	return {cfd, is_connected};
}	


std::string read_file_to_string(const char *pfilename, size_t max_sz, size_t min_sz, const char *perrprefix)
{
	int			fd, ret;
	struct stat		stat1;
	ssize_t			sret;

	if (!perrprefix) {
		perrprefix = "";
	}	

	fd = open(pfilename, O_RDONLY);
	if (fd == -1) {
		GY_THROW_SYS_EXCEPTION("%sFailed to open file %s : ", perrprefix, pfilename);
	}	

	SCOPE_FD		fdscope(fd);

	fstat(fd, &stat1);

	if ((size_t)stat1.st_size > max_sz) {
		stat1.st_size = max_sz;
	}
	else if (stat1.st_size == 0) {
		/*
		 * Some filesystems such as /proc or /sys do not return a valid stat syscall.
		 */
		stat1.st_size = (min_sz > 0 ? min_sz : 8192);
	}	
		
	std::string		str;
	
	str.reserve(stat1.st_size + 1);
	str.append(stat1.st_size, '\0');
	
	char 			*pstr = &str[0];

	sret = gy_readbuffer(fd, pstr, stat1.st_size); 	
	
	if (sret >= 0) {
		str.resize(sret);

		return str;
	}	
	else {
		GY_THROW_SYS_EXCEPTION("%sFailed to read file %s : ", perrprefix, pfilename);
	}		
}	

char * read_fd_to_alloc_buffer(int fd, size_t *preadsize, size_t max_sz) noexcept
{
	char			*pbuf = nullptr, *ptmp;
	struct stat		stat1;
	size_t			alloc_slab, readsz = 0;
	int			old_errno, ret;
	ssize_t			sret;

	if (max_sz == 0) {
		return nullptr;
	}

	ret = fstat(fd, &stat1);
	if (ret < 0) {
		if (preadsize) *preadsize = 0;
		return nullptr;
	}	

	if (stat1.st_size > 0) {
		if ((uint64_t)stat1.st_size >= max_sz) {
			stat1.st_size = max_sz - 1;
		}	

		alloc_slab = stat1.st_size + 16;
	}	
	else {
		// Valid for Virtual FS like procfs, sysfs
		alloc_slab = 2048;
	}	
	
	do {
		ptmp = (char *)realloc(pbuf, readsz + alloc_slab + 8);
		if (!ptmp) {
			goto onerr;
		}	
		pbuf = ptmp;

		sret = gy_readbuffer(fd, pbuf + readsz, alloc_slab); 
		if (sret < 0) {
			goto onerr;
		}	

		readsz += sret;

		if (((uint64_t)sret < alloc_slab) || (readsz >= max_sz)) {

			if (readsz > max_sz) {
				readsz = max_sz;
			}
				
			pbuf[readsz] = '\0';

			if (preadsize) *preadsize = readsz;
			return pbuf;
		}	

	} while (1);	


onerr :
	old_errno = errno;
	if (pbuf) free(pbuf);
	errno = old_errno;
	
	if (preadsize) *preadsize = 0;

	return nullptr;
}	

char * read_file_to_alloc_buffer(const char *pfilename, size_t *preadsize, size_t max_sz, int dir_fd) noexcept 
{
	int			fd, old_errno;
	char			*pbuf;

	fd = openat(dir_fd, pfilename, O_RDONLY | O_CLOEXEC);
	if (fd == -1) {
		return nullptr;
	}	

	pbuf = read_fd_to_alloc_buffer(fd, preadsize, max_sz);

	old_errno = errno;
	close(fd);
	errno = old_errno;
		
	return pbuf;
}	

ssize_t read_file_to_buffer(const char *pfilename, void *buf, size_t max_readlen, int dir_fd, bool read_syscall_till_err) noexcept 
{
	int			fd, old_errno;
	char			*pbuf;
	ssize_t			bytes;
	
	fd = openat(dir_fd, pfilename, O_RDONLY | O_CLOEXEC);
	if (fd == -1) {
		return -1;
	}	

	if (read_syscall_till_err) {
		bytes = gy_readbuffer(fd, buf, max_readlen);
	}
	else {
try1 :		
		bytes = ::read(fd, buf, max_readlen);
		if (bytes == -1 && ((errno == EINTR) || (errno == EAGAIN))) {
			goto try1;
		}
	}	

	old_errno = errno;
	close(fd);
	errno = old_errno;
		
	return bytes;
}	

bool write_string_to_file(const char *pinput, size_t szin, const char *outfilename, int flags, mode_t mode) noexcept
{
	int			ofd, olderrno;
	ssize_t			sret;
	SCOPE_FD		sfd(outfilename, flags | O_WRONLY, ofd, mode);

	if (ofd < 0) {
		return false;
	}	

	sret = gy_writebuffer(ofd, pinput, szin);

	if (sret != (ssize_t)szin) {
		return false;
	}

	return true;
}


std::string & string_delete_char(std::string & str, char c)
{
	str.erase(std::remove(str.begin(), str.end(), c), str.end());
	return str;
}


int get_host_cpu_ctxt(char *pbuf, size_t szbuf, uint64_t *ptotal_util_ticks, uint64_t *pcontext_switch, uint64_t *puser_util_ticks, uint64_t *psys_util_ticks) noexcept
{
	int				ret, fd;
	const char			*ptmp;
	ssize_t				szread;
	size_t				nbytes;
	uint64_t			user_ticks, nice_ticks, system_ticks, irq_ticks, softirq_ticks, guest_ticks = 0, guest_nice_ticks = 0;

	assert(ptotal_util_ticks);
	assert(pbuf);
	assert(szbuf >= 8192);
	
	*ptotal_util_ticks = 0;

	SCOPE_FD			scopefd("/proc/stat", O_RDONLY, 0600);
	
	fd = scopefd.get();
	if (fd < 0) {
		return -1;
	}	

	szread = gy_readbuffer(fd, pbuf, szbuf - 1);
	if (szread <= 0) {
		return -1;
	}

	pbuf[szread] = '\0';

	STR_RD_BUF			procstr(pbuf, szread);

	ptmp = procstr.get_next_word(nbytes);
	if (!ptmp || (0 != memcmp(ptmp, "cpu", 3))) {
		return 1;
	}	

	ptmp = procstr.get_next_line(nbytes);
	if (!ptmp) {
		return 1;
	}	
	
	ret = sscanf(ptmp, "%lu %lu %lu %*u %*u %lu %lu %*u %lu %lu", &user_ticks, &nice_ticks, &system_ticks, &irq_ticks, &softirq_ticks, 
		&guest_ticks, &guest_nice_ticks);
	if (ret < 5) {
		return 1;
	}	

	*ptotal_util_ticks = user_ticks + nice_ticks + system_ticks + irq_ticks + softirq_ticks + guest_ticks + guest_nice_ticks;

	if (puser_util_ticks) {
		*puser_util_ticks = user_ticks + nice_ticks;
	}

	if (psys_util_ticks) {
		*psys_util_ticks = system_ticks + irq_ticks + softirq_ticks;
	}	

	if (!pcontext_switch) {
		return 0;	
	}

	*pcontext_switch = 0;

	ptmp = procstr.skip_till_substring_const("ctxt", false);
	if (!ptmp) { 
		return 1;
	}	
	
	ptmp = procstr.get_next_word(nbytes);
	if (!ptmp) {
		return 1;
	}	
	
	return !string_to_number(ptmp, *pcontext_switch, nullptr, 10);
}	

int get_host_meminfo(uint64_t * memtotal, uint64_t * memrss, float * pctmemrss, uint64_t * memfree_immed, uint64_t * memcached, uint64_t * memlocked, uint64_t * memcommitted, float * pctcommit, uint64_t * swaptotal, uint64_t * swapfree) noexcept
{
	int				ret, fd;
	bool				bret;
	char				rdbuf[4096];
	const char			*ptmp;
	ssize_t				szread;
	size_t				nbytes;
	uint64_t			val, valrss, valtotal, valfree, valbuf, valcache, valshmem, valslab, valcommitlimit, valcommitted;

	assert(memtotal);
	assert(memrss);

	*memtotal 	= 0;
	*memrss		= 0;

	SCOPE_FD			scopefd("/proc/meminfo", O_RDONLY, 0600);
	
	fd = scopefd.get();
	if (fd < 0) {
		return -1;
	}	

	szread = gy_readbuffer(fd, rdbuf, sizeof(rdbuf) - 1);
	if (szread <= 0) {
		return -1;
	}

	rdbuf[szread] = '\0';

	STR_RD_BUF			procstr(rdbuf, szread);

	ptmp = procstr.skip_till_substring_const("MemTotal:", false);
	if (!ptmp) { 
		return 1;
	}	
	
	ptmp = procstr.get_next_word(nbytes);
	if (!ptmp) {
		return 1;
	}	
	
	bret = string_to_number(ptmp, valtotal, nullptr, 10);
	if (!bret) {
		return 1;
	}	
	
	valtotal <<= 10;

	if (valtotal == 0) {
		return 1;
	}	

	*memtotal = valtotal;

	ptmp = procstr.skip_till_substring_const("MemFree:", false);
	if (!ptmp) { 
		return 1;
	}	
	
	ptmp = procstr.get_next_word(nbytes);
	if (!ptmp) {
		return 1;
	}	
	
	bret = string_to_number(ptmp, valfree, nullptr, 10);
	if (!bret) {
		return 1;
	}	

	valfree <<= 10;
	
	if (memfree_immed) {
		*memfree_immed = valfree;
	}	

	ptmp = procstr.skip_till_substring_const("Buffers:", false);
	if (!ptmp) { 
		return 1;
	}	
	
	ptmp = procstr.get_next_word(nbytes);
	if (!ptmp) {
		return 1;
	}	
	
	bret = string_to_number(ptmp, valbuf, nullptr, 10);
	if (!bret) {
		return 1;
	}	

	valbuf <<= 10;
	
	ptmp = procstr.skip_till_substring_const("Cached:", false);
	if (!ptmp) { 
		return 1;
	}	
	
	ptmp = procstr.get_next_word(nbytes);
	if (!ptmp) {
		return 1;
	}	
	
	bret = string_to_number(ptmp, valcache, nullptr, 10);
	if (!bret) {
		return 1;
	}	

	valcache <<= 10;

	if (memcached) {
		*memcached = valcache;
	}

	if (memlocked) {
	
		ptmp = procstr.skip_till_substring_const("Mlocked:", false);
		if (!ptmp) { 
			return 1;
		}	
		
		ptmp = procstr.get_next_word(nbytes);
		if (!ptmp) {
			return 1;
		}	
		
		bret = string_to_number(ptmp, val, nullptr, 10);
		if (!bret) {
			return 1;
		}	

		val <<= 10;

		*memlocked = val;
	}

	if (swaptotal) {
	
		ptmp = procstr.skip_till_substring_const("SwapTotal:", false);
		if (!ptmp) { 
			return 1;
		}	
		
		ptmp = procstr.get_next_word(nbytes);
		if (!ptmp) {
			return 1;
		}	
		
		bret = string_to_number(ptmp, val, nullptr, 10);
		if (!bret) {
			return 1;
		}	

		val <<= 10;

		*swaptotal = val;
	}

	if (swapfree) {
	
		ptmp = procstr.skip_till_substring_const("SwapFree:", false);
		if (!ptmp) { 
			return 1;
		}	
		
		ptmp = procstr.get_next_word(nbytes);
		if (!ptmp) {
			return 1;
		}	
		
		bret = string_to_number(ptmp, val, nullptr, 10);
		if (!bret) {
			return 1;
		}	

		val <<= 10;

		*swapfree = val;
	}

	ptmp = procstr.skip_till_substring_const("Shmem:", false);
	if (!ptmp) { 
		return 1;
	}	
	
	ptmp = procstr.get_next_word(nbytes);
	if (!ptmp) {
		return 1;
	}	

	bret = string_to_number(ptmp, valshmem, nullptr, 10);
	if (!bret) {
		return 1;
	}	

	valshmem <<= 10;

	ptmp = procstr.skip_till_substring_const("Slab:", false);
	if (!ptmp) { 
		return 1;
	}	
	
	ptmp = procstr.get_next_word(nbytes);
	if (!ptmp) {
		return 1;
	}	
	
	bret = string_to_number(ptmp, valslab, nullptr, 10);
	if (!bret) {
		return 1;
	}	

	valslab <<= 10;

	val = valfree + valbuf + valcache + valslab;

	if (val > valtotal) {
		val = valtotal;
	}
	
	valrss = valtotal - val + valshmem;	
	if (valrss > valtotal) {
		valrss = valtotal;
	}	

	*memrss = valrss;

	if (pctmemrss) {
		*pctmemrss = *memrss * 100.0f/valtotal;
	}	

	if (pctcommit || memcommitted) {
		ptmp = procstr.skip_till_substring_const("CommitLimit:", false);
		if (!ptmp) { 
			return 1;
		}	
		
		ptmp = procstr.get_next_word(nbytes);
		if (!ptmp) {
			return 1;
		}	
		
		bret = string_to_number(ptmp, valcommitlimit, nullptr, 10);
		if (!bret) {
			return 1;
		}	

		valcommitlimit <<= 10;
	
		if (valcommitlimit == 0) {
			valcommitlimit = 1;
		}	

		ptmp = procstr.skip_till_substring_const("Committed_AS:", false);
		if (!ptmp) { 
			return 1;
		}	
		
		ptmp = procstr.get_next_word(nbytes);
		if (!ptmp) {
			return 1;
		}	
		
		bret = string_to_number(ptmp, valcommitted, nullptr, 10);
		if (!bret) {
			return 1;
		}	

		valcommitted <<= 10;

		if (memcommitted) {
			*memcommitted = valcommitted;
		}	
	
		if (pctcommit) {
			*pctcommit = valcommitted * 100.0f/valcommitlimit; 
		}	
	}	
	
	return 0;
}	

int get_host_vmstat(uint64_t & pgpgin, uint64_t & pgpgout, uint64_t & pswpin, uint64_t & pswpout, uint64_t & allocstall, uint64_t & pgmajfault, uint64_t & oom_kill) noexcept
{
	int				ret, fd;
	bool				bret;
	char				rdbuf[4096];	// As the last stat needed is oom_kill : Ideally we need 8192
	const char			*ptmp;
	ssize_t				szread;
	size_t				nbytes;
	uint64_t			val1 = 0, val2 = 0;

	pgpgin		= 0;
	pgpgout		= 0;
	pswpin		= 0;
	pswpout		= 0;
	pgmajfault	= 0;
	oom_kill	= 0;

	SCOPE_FD			scopefd("/proc/vmstat", O_RDONLY, 0600);
	
	fd = scopefd.get();
	if (fd < 0) {
		return -1;
	}	

	szread = gy_readbuffer(fd, rdbuf, sizeof(rdbuf) - 1);
	if (szread <= 0) {
		return -1;
	}

	rdbuf[szread] = '\0';

	STR_RD_BUF			procstr(rdbuf, szread);

	ptmp = procstr.skip_till_substring_const("pgpgin", false);
	if (!ptmp) { 
		return 1;
	}	
	
	ptmp = procstr.get_next_word(nbytes);
	if (!ptmp) {
		return 1;
	}	
	
	bret = string_to_number(ptmp, pgpgin, nullptr, 10);
	if (!bret) {
		return 1;
	}	
	
	ptmp = procstr.skip_till_substring_const("pgpgout", false);
	if (!ptmp) { 
		return 1;
	}	
	
	ptmp = procstr.get_next_word(nbytes);
	if (!ptmp) {
		return 1;
	}	
	
	bret = string_to_number(ptmp, pgpgout, nullptr, 10);
	if (!bret) {
		return 1;
	}	

	ptmp = procstr.skip_till_substring_const("pswpin", false);
	if (!ptmp) { 
		return 1;
	}	
	
	ptmp = procstr.get_next_word(nbytes);
	if (!ptmp) {
		return 1;
	}	
	
	bret = string_to_number(ptmp, pswpin, nullptr, 10);
	if (!bret) {
		return 1;
	}	
	
	ptmp = procstr.skip_till_substring_const("pswpout", false);
	if (!ptmp) { 
		return 1;
	}	
	
	ptmp = procstr.get_next_word(nbytes);
	if (!ptmp) {
		return 1;
	}	
	
	bret = string_to_number(ptmp, pswpout, nullptr, 10);
	if (!bret) {
		return 1;
	}	

	static int		gno_allocstall_breakup = -1, gno_oom_kill = -1;

	if (gy_unlikely(gno_allocstall_breakup == -1)) {
		ptmp = procstr.skip_till_substring_const("allocstall_normal", true);
		if (ptmp) {
			gno_allocstall_breakup = 0;
			goto nxt1;
		}	
		gno_allocstall_breakup = 1;
	}	

	if (gno_allocstall_breakup == 0) {
		ptmp = procstr.skip_till_substring_const("allocstall_normal", false);
		if (!ptmp) { 
			return 1;
		}	
nxt1 :		
		ptmp = procstr.get_next_word(nbytes);
		if (!ptmp) {
			return 1;
		}	
		
		bret = string_to_number(ptmp, val1, nullptr, 10);
		if (!bret) {
			return 1;
		}	
		
		ptmp = procstr.skip_till_substring_const("allocstall_movable", false);
		if (ptmp) { 
			
			ptmp = procstr.get_next_word(nbytes);
			if (!ptmp) {
				return 1;
			}	
			
			bret = string_to_number(ptmp, val2, nullptr, 10);
			if (!bret) {
				return 1;
			}	
		}
	}
	else {
		ptmp = procstr.skip_till_substring_const("allocstall", false);
		if (!ptmp) { 
			return 1;
		}	

		ptmp = procstr.get_next_word(nbytes);
		if (!ptmp) {
			return 1;
		}	
		
		bret = string_to_number(ptmp, val1, nullptr, 10);
		if (!bret) {
			return 1;
		}	
	}	

	allocstall = val1 + val2;
	
	ptmp = procstr.skip_till_substring_const("pgmajfault", true);		// Search entire string as pgmajfault comes earlier for older kernels
	if (!ptmp) { 
		return 1;
	}	
	
	ptmp = procstr.get_next_word(nbytes);
	if (!ptmp) {
		return 1;
	}	
	
	bret = string_to_number(ptmp, pgmajfault, nullptr, 10);
	if (!bret) {
		return 1;
	}	

	if (gy_unlikely(gno_oom_kill == -1)) {
		ptmp = procstr.skip_till_substring_const("oom_kill", true);
		if (ptmp) {
			gno_oom_kill = 0;
			goto nxt2;
		}	
		gno_oom_kill = 1;
	}	
	
	if (gno_oom_kill == 0) {
		ptmp = procstr.skip_till_substring_const("oom_kill", false);
		if (!ptmp) { 
			return 1;
		}	
nxt2 :		
		ptmp = procstr.get_next_word(nbytes);
		if (!ptmp) {
			return 1;
		}	
		
		bret = string_to_number(ptmp, oom_kill, nullptr, 10);
		if (!bret) {
			return 1;
		}	
	}

	return 0;
}	

// Returns number of inodes updated on success -errno on error
int get_proc_ns_inodes(pid_t pid, const char * nsstr[], ino_t nsinode[], size_t nitems, int proc_dir_fd, pid_t tid) noexcept 
{
	struct stat 			stbuf;
	int				dirfd, nupd = 0, olderrno;
	char				path[256];

	if (proc_dir_fd > 0) {
		snprintf(path, sizeof(path), "./%d/task/%d/ns", pid, tid > 0 ? tid : pid);
	}
	else {
		snprintf(path, sizeof(path), "/proc/%d/task/%d/ns", pid, tid > 0 ? tid : pid);
	}	

	dirfd = openat(proc_dir_fd, path, O_DIRECTORY | O_CLOEXEC | O_RDONLY);
	if (dirfd < 0) {
		return -errno;
	}


	for (size_t i = 0; i < nitems; i++) {
		if (fstatat(dirfd, nsstr[i], &stbuf, 0) < 0) {
			nsinode[i] = 0;
			continue;
		}

		nsinode[i] = stbuf.st_ino;
		nupd++;
	}

	olderrno = errno;

	close(dirfd);

	errno = olderrno;

	if (nupd == 0) {
		return -errno;
	}	

	return nupd;
}

// Returns inode number on success or 0 on failure
ino_t get_proc_ns_inode(pid_t pid, const char * nsstr, int proc_dir_fd, pid_t tid) noexcept
{
	ino_t			inode;
	int			ret;

	ret = get_proc_ns_inodes(pid, &nsstr, &inode, 1, proc_dir_fd, tid);
	if (ret == 1) {
		return inode;
	}	

	return 0;
}	


int get_proc_stat(pid_t pid, pid_t & task_ppid, char & task_state, uint32_t & task_flags, uint64_t & starttimeusec, int64_t & task_priority, int64_t & task_nice, uint32_t & task_rt_priority, uint32_t & task_sched_policy, int proc_dir_fd, bool is_tgid, pid_t tid) noexcept
{
	int				ret, fd;
	char				buf[64], databuf[1024], *ptmp;
	ssize_t				szread;
	size_t				nbytes;
	const char		* const	pdirproc = (proc_dir_fd > 0 ? "." : "/proc");
	char				c;
	uint32_t			ppid, flags, rt_prio, policy;	
	int64_t				priority, nice;	
	uint64_t			startclock, starttime, currtime, currclock;
		
	if (is_tgid || tid == 0) {
		snprintf(buf, sizeof(buf), "%s/%d/stat", pdirproc, pid);
	}
	else {
		snprintf(buf, sizeof(buf), "%s/%d/task/%d/stat", pdirproc, pid, tid);
	}		

	fd = openat(proc_dir_fd, buf, O_RDONLY);
	if (fd < 0) {
		return -1;
	}	

try_again :
	szread = ::read(fd, databuf, sizeof(databuf) - 1);
	if (szread <= 5) {
		if (szread == -1 && (errno == EINTR || errno == EAGAIN)) {
			goto try_again;
		}	
		int olderrno = errno;
		close(fd);
		errno = olderrno;
		return -1;
	}

	databuf[szread] = '\0';

	close(fd);

	c = 0;

	if (szread > 50) {
		c = databuf[50];
		databuf[50] = 0;
	}
		
	ptmp = strrchr(databuf, ')');
	if (!ptmp) {
		return -1;
	}	

	ptmp++;

	if (c) {
		databuf[50] = c;
	}

	while ((c = *ptmp) && (c != ' ')) {
		ptmp++;
	}

	while ((c = *ptmp) && (c == ' ')) {
		ptmp++;
	}	
	
	ret = sscanf(ptmp, "%c %d %*d %*d %*d %*d %u %*u %*u %*u %*u %*u %*u %*d %*d %ld %ld %*d %*d %lu %*u %*d %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*d %*d %u %u", 
		&c, &ppid, &flags, &priority, &nice, &startclock, &rt_prio, &policy);
	
	if (ret != 8) {
		return -1;
	}	

	currtime = get_usec_time();
	currclock = get_usec_clock();

	startclock *= (GY_USEC_PER_SEC / gy_clk_tck());

	if (startclock > currclock) startclock = currclock;

	starttime = currtime - (currclock - startclock);

	task_ppid		= ppid;
	task_state		= c;
	task_flags 		= flags;
	starttimeusec 		= starttime;
	task_priority 		= priority;
	task_nice 		= nice;
	task_rt_priority	= rt_prio;
	task_sched_policy	= policy;

	return 0;
}

// Returns exe strlen on success -errno on error
ssize_t get_task_exe_path(pid_t pid, char *pbuf, size_t maxlen, int proc_dir_fd, bool * is_deleted) noexcept
{
	ssize_t				sret;
	char				path[256], *ptmp;
	bool				isdel = false;
	constexpr size_t		delstrlen = GY_CONST_STRLEN(" (deleted)");

	assert(pbuf && maxlen);

	if (proc_dir_fd > 0) {
		snprintf(path, sizeof(path), "./%u/exe", pid);
	}
	else {
		snprintf(path, sizeof(path), "/proc/%u/exe", pid);
	}		

	sret = readlinkat(proc_dir_fd, path, pbuf, maxlen - 1);

	if (sret == -1) {
		*pbuf = '\0';
		return -errno;	
	}	

	pbuf[sret] = '\0';

	if (sret > (ssize_t)delstrlen) {
		ptmp = pbuf + sret - delstrlen;
		if (0 == memcmp(ptmp, " (deleted)", delstrlen)) {
			// exe has been deleted
			*ptmp = 0;
			sret -= delstrlen;
			isdel = true;
		}	
	}	

	if (is_deleted) {
		*is_deleted = isdel;
	}	

	return sret;
}

/*
 * Returns strlen of cmdline on success or -errno on failure
 */
ssize_t get_task_comm(pid_t pid, char *pbuf, size_t maxlen, int proc_dir_fd) noexcept
{
	int				ret, fd;
	char				buf[64];
	ssize_t				szread;
	
	assert(pbuf && maxlen);

	if (proc_dir_fd > 0) {
		snprintf(buf, sizeof(buf), "./%u/comm", pid);
	}	
	else {
		snprintf(buf, sizeof(buf), "/proc/%u/comm", pid);
	}	

	SCOPE_FD			scopefd(proc_dir_fd, buf, O_RDONLY, 0640);
	
	fd = scopefd.get();
	if (fd < 0) {
		return -errno;
	}	

try_again :
	szread = ::read(fd, pbuf, maxlen - 1);

	if (gy_unlikely(szread <= 0)) {
		if (szread == -1 && (errno == EINTR || errno == EAGAIN)) {
			goto try_again;
		}	
		return -errno;
	}

	if (pbuf[szread - 1] == '\n') szread--;

	pbuf[szread] = '\0';

	return szread;
}	

/*
 * Returns strlen of cmdline on success or -errno on failure
 */
ssize_t get_task_cmdline(pid_t pid, char *pbuf, size_t maxlen, int proc_dir_fd) noexcept
{
	int				ret, fd;
	char				buf[64];
	ssize_t				szread;
	
	assert(pbuf && maxlen);

	if (proc_dir_fd > 0) {
		snprintf(buf, sizeof(buf), "./%u/cmdline", pid);
	}
	else {
		snprintf(buf, sizeof(buf), "/proc/%u/cmdline", pid);
	}		

	SCOPE_FD			scopefd(proc_dir_fd, buf, O_RDONLY, 0640);
	
	fd = scopefd.get();
	if (fd < 0) {
		return -errno;
	}	

	szread = gy_readbuffer(fd, pbuf, maxlen - 1);
	if (gy_unlikely(szread <= 0)) {
		if (szread == 0) {
			/*
			 * Kernel threads have no argv
			 * Try /proc/pid/comm instead
			 */
			szread = get_task_comm(pid, pbuf + 1, maxlen - 3, proc_dir_fd); 
			if (szread < 0) {
				return szread;
			}

			*pbuf = '[';
			pbuf[szread + 1] = ']';
			pbuf[szread + 2] = '\0';

			return szread + 2;
		}

		return -errno;
	}

	pbuf[szread] = '\0';

	string_replace_char(pbuf, szread, '\0', ' ');

	return szread;
}	

/*
 * Returns number of cgroup paths updated,  -errno on failure
 * For cgroupv2, specify pcg2dir && maxcg2sz
 */
int get_proc_cgroups(pid_t pid, const char *ptypecg1[], char *pdircg1[], size_t maxcg1sz[], int maxcg1types, char *pdircg2, size_t maxcg2sz, bool is_tgid, pid_t tid, int proc_dir_fd) noexcept
{
	try {
		int				fd = -1, ret, nupd = 0, len1;
		char				*pbuf;
		const char			*pdata, *path, *pdirproc;
		bool				is_malloc, is_word;	
		const size_t			linesz = 8192;
		ssize_t				szread;
		size_t				lenword, lenpath, lencopy;
		char				cgname[128];
		
		for (int i = 0; i < maxcg1types; i++) {
			if (ptypecg1[i] && pdircg1[i]) {
				pdircg1[i][0] = '\0';
			}
		}		
		if (pdircg2) *pdircg2 = '\0';

		SAFE_STACK_ALLOC(pbuf, linesz, is_malloc);
		
		if (proc_dir_fd > 0) {
			pdirproc = ".";
		}	
		else {
			pdirproc = "/proc";
		}
			
		if (is_tgid || tid == 0) {
			snprintf(pbuf, linesz, "%s/%d/cgroup", pdirproc, pid);
		}
		else {
			snprintf(pbuf, linesz, "%s/%d/task/%d/cgroup", pdirproc, pid, tid);
		}		

		SCOPE_FD			scopefd(proc_dir_fd, pbuf, O_RDONLY, fd);
		
		if (fd < 0) {
			return -errno;
		}	

try_again :		
		szread = ::read(fd, pbuf, linesz - 1);
		if (gy_unlikely(szread < 0)) {

			if (szread == -1 && (errno == EINTR || errno == EAGAIN)) {
				goto try_again;
			}	
			return -errno;
		}	

		pbuf[szread] = '\0';

		if (szread < 2) {
			return 0;
		}	

		STR_RD_BUF			taskstr(pbuf, szread);

		while (nupd < maxcg1types) {
			pdata = taskstr.get_next_word(lenword, true, ":");
			if (!pdata) {
				break;
			}	

			pdata = taskstr.get_next_word(lenword, true, ":");
			if (!pdata) {
				break;
			}	

			GY_SAFE_MEMCPY(cgname, sizeof(cgname) - 1, pdata, lenword, lencopy);
			cgname[lencopy] = '\0';

			path = taskstr.get_next_word(lenpath);
			if (!path) {
				break;
			}

			if (string_ends_with(path, " (deleted)", lenpath, GY_CONST_STRLEN(" (deleted)"))) {
				// Process is a zombie
				return 0;
			}	
				
			for (int i = 0; i < maxcg1types; i++) {
				if (ptypecg1[i] && pdircg1[i]) {
					is_word = is_whole_word_in_str(cgname, ptypecg1[i], nullptr, false, lencopy, strlen(ptypecg1[i]));
					
					if (is_word) {
						GY_SAFE_MEMCPY(pdircg1[i], maxcg1sz[i] - 1, path, lenpath, lencopy);

						pdircg1[i][lencopy] = '\0';	
						nupd++;
					}
				}	
			}
		}

		if (pdircg2 && maxcg2sz) {
			path = taskstr.skip_till_substring_const("0::", true);
			if (!path) {
				*pdircg2 = '\0';
				return nupd;
			}	

			path = taskstr.get_next_word(lenpath);
			if (path) {
				if (string_ends_with(path, " (deleted)", lenpath, GY_CONST_STRLEN(" (deleted)"))) {
					// Process is a zombie
					return 0;
				}	
				
				GY_SAFE_MEMCPY(pdircg2, maxcg2sz - 1, path, lenpath, lencopy);

				pdircg2[lencopy] = '\0';
				nupd++;
			}
		}	

		return nupd;	
	}
	catch(...) {
		return -1;
	}	
}


/*
 * Requires log files to be opened using O_APPEND or else no use
 */
int gy_log_dir_cleanup(const char * plogdir, const char * pexten_arr[], size_t nextensions, size_t max_log_size, int nbackup_level, uid_t chown_uid, gid_t chown_gid) noexcept
{
	GY_MT_COLLECT_PROFILE(1000, "Log dir cleanup");

	DIR			*pdir;
	struct dirent		*pdent;
	const char		*pfile;
	char			*ptmp;
	int			ret;
	struct stat		stat1;
	struct statvfs		statvfs1;
	uint64_t		freesize = 0;
	char			path[GY_PATH_MAX], tpath1[GY_PATH_MAX], tpath2[GY_PATH_MAX];
	size_t			i;

	assert(plogdir);
	assert(pexten_arr);

	for (i = 0; i < nextensions; i++) {
		if (strstr(pexten_arr[i], "bak")) {
			ERRORPRINT("Cannot handle Log backup for files already with extension bak*\n");
			return -1;
		}	
	}

	pdir = opendir(plogdir);
	if (!pdir) {
		return -1;
	}

	GY_SCOPE_EXIT {
		closedir(pdir);
	};

	ret = statvfs(plogdir, &statvfs1);
	if (ret == 0) {
		freesize = statvfs1.f_bavail * statvfs1.f_frsize;

		if (freesize < 1024 * 1024 * 1024ul) {
			WARNPRINT("Log Dir %s Mount point free space less than 1 GB : %lu MB : Please free up disk space...\n",
				plogdir, GY_DOWN_MB(freesize));
		}
	}	

	while ((pdent = readdir(pdir)) != nullptr) {

		pfile = pdent->d_name;	
	
		for (i = 0; i < nextensions; i++) {
			if (nullptr != string_ends_with(pfile, pexten_arr[i])) {
				break;
			}
		}

		if (i == nextensions) {
			continue;
		}	

		snprintf(path, sizeof(path), "%s/%s", plogdir, pfile);

		ret = stat(path, &stat1);
		if ((ret != 0) || (!S_ISREG(stat1.st_mode)) || ((uint64_t)stat1.st_size < max_log_size)) {
			continue;
		}	
		
		INFOPRINT("Log file %s size too large %lu MB. Backing up...\n", path, GY_DOWN_MB(stat1.st_size)); 
		
		for (int b = nbackup_level - 1; b >= 1; b--) {
			snprintf(tpath1, sizeof(tpath1), "%s.bak%d", path, b);
			snprintf(tpath2, sizeof(tpath2), "%s.bak%d", path, b + 1);

			rename(tpath1, tpath2);
		}	

		snprintf(tpath1, sizeof(tpath1), "%s.bak1", path);
		
		// Now copy the path to tpath1
		ret = gy_copyfile(path, tpath1, true, chown_uid, chown_gid);

		if (ret != 0) {
			PERRORPRINT("Could not copy log file %s to backup %s : Truncating in place to 100 KB", path, tpath1);
			truncate_file_wrap_last(path, 1, 100 * 1024);
		}	
		else {
			ret = truncate(path, 0);
			if (ret != 0) {
				PERRORPRINT("Could not truncate log file %s to size 0", path);
			}	
		}	
	}

	return 0;
}	

GY_TIMEZONE * GY_TIMEZONE::get_singleton() noexcept
{
	return &gtzone_;
}	

int GY_TIMEZONE::init_singleton()
{
	int					texp = 0, tdes = 1;
	static std::atomic<int>			is_init_done(0);

	if (false == is_init_done.compare_exchange_strong(texp, tdes)) {
		return 0;
	}
	
	GY_SCHEDULER::init_singleton_maintenance();

	auto schedshrno = GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_MAINTENANCE);

	if (!schedshrno) {
		GY_THROW_EXCEPTION("Global Scheduler Maintenance object not yet initialized");
	}	
	
	try {
		schedshrno->add_schedule(900'000, 900'000 /* Every 15 min */, 0, "Check for Timezone changes", 
		[] { 
			GY_TIMEZONE::get_singleton()->get_utc_tzoffset(true /* force_check */);
		});

		GY_TIMEZONE::get_singleton()->set_periodic_check_on();
		GY_TIMEZONE::get_singleton()->set_tz_env_updated();

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT("Exception caught while creating process Timezone monitor object : %s\n", GY_GET_EXCEPT_STRING);
		throw;
	);
}	

static PROC_CPU_IO_STATS			*pgcpu_io_;

PROC_CPU_IO_STATS * PROC_CPU_IO_STATS::get_singleton() noexcept
{
	return pgcpu_io_;
}	
	
int PROC_CPU_IO_STATS::init_singleton(int secs_duration, const char * identifier)
{
	int					texp = 0, tdes = 1;
	static std::atomic<int>			is_init_done(0);

	if (false == is_init_done.compare_exchange_strong(texp, tdes)) {
		return 0;
	}
	
	assert(secs_duration > 0);

	GY_SCHEDULER::init_singleton_maintenance();

	auto schedshrno = GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_MAINTENANCE);

	if (!schedshrno) {
		GY_THROW_EXCEPTION("Global Scheduler Maintenance object not yet initialized");
	}	
	
	try {
		pgcpu_io_ = new PROC_CPU_IO_STATS(getpid(), getpid(), true /* monitor_whole_proc */);

		if (identifier == nullptr) identifier = "ID";

		std::string			tident(identifier);

		schedshrno->add_schedule(secs_duration * 1000, secs_duration * 1000, 0, "Get process cpu/io stats", 
		[ident = std::move(tident)] { 
			auto 		pcpu = PROC_CPU_IO_STATS::get_singleton();

			if (pcpu) {
				pcpu->get_current_stats();
				pcpu->print_current(0, ident.c_str());
			}	
		});

#ifdef GY_MALLOC_HOOKED
		GY_MALLOC_HOOK::gy_malloc_init("Process Malloc Stats");
#endif

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT("Exception caught while creating process CPU / IO monitor object : %s\n", GY_GET_EXCEPT_STRING);
		throw;
	);
}


static GY_SIGNAL_HANDLER		*pgsignal_param_;

int GY_SIGNAL_HANDLER::init_singleton(const char *pnameproc, SIGNAL_CALLBACK_HDLR signal_callback, bool to_exit_on_signals, bool use_altstack, SA_SIGACTION_HDLR sigint_hdlr, SA_SIGACTION_HDLR sigsegv_hdlr)
{
	int					texp = 0, tdes = 1;
	static std::atomic<int>			is_init_done(0);

	if (false == is_init_done.compare_exchange_strong(texp, tdes)) {
		return 0;
	}

	try {
		pgsignal_param_ = new GY_SIGNAL_HANDLER(pnameproc, signal_callback, to_exit_on_signals, use_altstack, sigint_hdlr, sigsegv_hdlr);

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT("Exception caught while creating process signal handler object : %s\n", GY_GET_EXCEPT_STRING);
		throw;
	);
}
	
GY_SIGNAL_HANDLER * GY_SIGNAL_HANDLER::get_singleton() noexcept
{
	return pgsignal_param_;
}	


#ifdef GY_MALLOC_HOOKED

int GY_MALLOC_HOOK::init_singleton(int secs_duration)
{
	assert(secs_duration > 0);

	GY_SCHEDULER::init_singleton_maintenance();

	auto schedshrno = GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_MAINTENANCE);

	if (!schedshrno) {
		GY_THROW_EXCEPTION("Global Scheduler Maintenance object not yet initialized");
	}	
	
	try {
		char			buf[128];

		snprintf(buf, sizeof(buf), "Process %d Malloc Stats", getpid());

		schedshrno->add_schedule(secs_duration * 1000, secs_duration * 1000, 0, "Print process malloc stats", 
		[objpr = std::string(buf)] { 
			GY_MALLOC_HOOK::gy_print_memuse(objpr.c_str(), true /* reset_after_print */);
		});

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT("Exception caught while creating process malloc stats object : %s\n", GY_GET_EXCEPT_STRING);
		throw;
	);
}

#endif

} // namespace gyeeta

