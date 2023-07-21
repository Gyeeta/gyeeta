//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma 			once
	
extern 		uint64_t CityHash64(const char *s, size_t len);
extern 		uint32_t CityHash32(const char *s, size_t len);

namespace gyeeta {

typedef 	void (*SA_SIGACTION_HDLR)(int, siginfo_t *, void *);
typedef 	int (* SIGNAL_CALLBACK_HDLR) (int signo);

class 		GY_MUTEX;

int 		gy_create_tmpfs(char *dest_dir, uint32_t size_mb, mode_t mode, int is_noatime) noexcept;
int 		gy_check_dir_mounttype(char *dest_dir, int *pis_tmpfs) noexcept;
char 		* gy_path_cleanup(char *path, bool kill_dots = true) noexcept; 
void 		gy_print_buf(int fd, const uint8_t *buf, uint32_t len, int print_ascii, const char *msg = "") noexcept;
int 		gy_linkpath(const char *pfilename, char *bufpath, int szbuf) noexcept;
int 		gy_create_mail_buffer(char *pmsg, int len, char *poutput, int maxlen) noexcept;
int 		gy_close_socket(int sock) noexcept;
int 		set_thread_prio(pthread_t thread_id, int policy, int prio) noexcept; 
int 		gy_rename(char *poldpath, char *pnewpath, bool rename_across_mounts, uid_t chown_uid = 0, gid_t chown_gid = 0) noexcept;
int 		gy_mkdir_recurse(const char *pdir, mode_t mode, uid_t chown_uid = 0, gid_t chown_gid = 0) noexcept;
int 		gy_clean_recur_dir(const char *pstr, int del_subdir, time_t file_del_time = LONG_MAX - 1, const char *pmemcmpstr = nullptr, const char *psubstr = nullptr) noexcept;
uint64_t 	gy_get_dir_disk_usage(const char *pdirname, const char *pfilename = nullptr) noexcept;
int 		gy_hex_to_string(const uint8_t *phexstr, const uint32_t len, uint8_t *pstrout, uint32_t lenout, int null_terminate) noexcept;
int 		gy_string_to_hex(const uint8_t *pstrinput, const uint32_t len, uint8_t *phexout, uint32_t lenout) noexcept;
int 		gy_memrcmp(const void *s1, const void *s2, size_t n) noexcept;
int 		gy_memcasecmp(const void *s1, const void *s2, size_t n) noexcept;
int 		gy_no_mutex_lock(GY_MUTEX * pmutex) noexcept;
int 		no_mutex_lock(pthread_mutex_t * pmutex) noexcept;

int		gy_mutex_proc_lock(GY_MUTEX * pmutex) noexcept;
int		gy_mutex_proc_unlock(GY_MUTEX * pmutex) noexcept;
int		gy_mutex_proc_trylock(GY_MUTEX * pmutex) noexcept;

int 		gy_fork_system(char *systemcmd, char *pdirchange, int to_wait, pid_t *pchldpid, int prctlsigno, const char *plogpath = nullptr, \
			uid_t ch_uid = 0, gid_t ch_gid = 0, bool ignore_sighup = true, bool drop_all_cap = true) noexcept;


ssize_t 	gy_copy_file_range(int fdin, int fdout, size_t bytes_to_copy, loff_t *poffin = nullptr, loff_t *poffout = nullptr, uint32_t flags = 0) noexcept;
ssize_t 	gy_sendfilefd(int infd, int outfd, size_t bytes_to_send) noexcept;
int 		gy_copyfile(const char *infile, const char *outfile, bool ignore_stat_size_0 = false, uid_t ch_uid = 0, gid_t ch_gid = 0) noexcept;

// Blocking read and send
ssize_t 	gy_filesend(int sockfd, const char *fname) noexcept;

// Returns bytes sent or -1 on error. If non-blocking, may result in partial sends 
ssize_t 	gy_sendbuffer(int sockfd, const void *buf, size_t buflen, int flags = 0, bool ignore_epipe = true) noexcept;

class 		GY_IP_ADDR;
class 		IP_PORT;

// Synchronous call to getaddrinfo(). Async getaddrinfo_a() not used...
// Returns number of resolved IPs or -1 on error
int 		gy_resolve_hostname(const char *phost, GY_IP_ADDR * ip_array, size_t nmax_ips, char (&error_buf)[128], bool only_ipv4 = false) noexcept;
int 		gy_resolve_hostname(const char *phost, const char * pservice, IP_PORT * ip_port_array, size_t nmax_ips, char (&error_buf)[128], bool only_ipv4);

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
std::pair<int, bool> gy_tcp_connect(const char *serverhostname_ip, uint16_t port, char (&error_buf)[128], const char *server_describe = "server", \
			bool set_nodelay = true, bool always_resolve_dns = false, struct sockaddr_storage *pconnect_sockaddr = nullptr, socklen_t *psocklen = nullptr, \
			bool use_ipv4_only = false, bool cloexec = true, bool set_nonblock = false) noexcept;

/*
 * Specify no_block_after_first_recv as false if you know how many bytes are expected to be received. Default is false,
 * which means recv all data blocking till it arrives but don't block thereafter.
 * min_bytes_to_recv can be specified as non-zero if any recv < that should error out
 */ 
ssize_t 	gy_recvbuffer(int sockfd, void *buf, size_t bytes_to_recv, int flags = 0, bool no_block_after_first_recv = true, size_t min_bytes_to_recv = 0) noexcept;

bool 		is_socket_still_connected(int sock, bool is_peer_writeable = true) noexcept;

/*
 * Returns > 0 on success, 0 on timeout and -1 on errors. 
 * The poll output events are updated to revents. If close_on_errors is specified and revents shows sock close will close the socket
 * poll_events should be specified with the required poll events such as POLLIN for recv and POLLOUT if send blocked
 * If close_on_errors is true, then socket will be closed on timeout or if POLLHUP or if poll failed
 */
int 		poll_socket(int sock, int timeout_msec, int & revents, int poll_events, bool close_on_errors = true) noexcept;

/*
 * Returns peek return len on success, 0 if no data (for non-block) and -1 on errors
 */ 
ssize_t 	sock_peek_recv_data(int sock, void *peek_buf, size_t max_peek_len, bool is_non_block = true) noexcept;

/*
 * (Only for TCP sockets)
 * Returns the  byte count of queued unread data in the socket receive buffer waiting to be recv'ed
 * and -1 on errors
 */
int		sock_queued_recv_bytes(int sock) noexcept;

/*
 * (Only for TCP sockets)
 * Returns the  byte count of queued data in the socket send buffer waiting to be sent
 * and -1 on errors
 */
int		sock_queued_send_bytes(int sock) noexcept;

/*
 * min_sz in case fstat() syscall fails
 */ 
std::string    	read_file_to_string(const char *pfilename, size_t max_sz = ~0u, size_t min_sz = 0, const char *perrprefix = nullptr);

std::string & 	string_delete_char(std::string & str, char c);

/*
 * The next 2 functions will read a file to a malloc'ed buffer. Responsibility of user to free the returned buffer
 * subsequently. dir_fd is optional. After return, users need to call free() XXX and not delete[];
 */ 
char * 		read_fd_to_alloc_buffer(int fd, size_t *preadsize, size_t max_sz = ~0u) noexcept;
char * 		read_file_to_alloc_buffer(const char *pfilename, size_t *preadsize, size_t max_sz = ~0u, int dir_fd = -1) noexcept; 

// Specify read_syscall_till_err as false in case reads can be less than max_readlen and a single read call is sufficient
ssize_t 	read_file_to_buffer(const char *pfilename, void *buf, size_t max_readlen, int dir_fd = -1, bool read_syscall_till_err = true) noexcept; 

bool		write_string_to_file(const char *pinput, size_t szin, const char *outfilename, int flags = O_CREAT | O_WRONLY, mode_t mode = 0640) noexcept;

void 		gy_host_to_nw_bo(void *pd, void *ps, size_t size, bool is_little_endian = (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)) noexcept;
void 		gy_nw_to_host_bo(void *pd, void *ps, size_t size, bool is_little_endian = (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)) noexcept;

/*
 * Get the version number from a version string of formats : a.b.c.d, a.b.c. or a.b
 * num_octets is the number of byte octets. For e.g. for the version 2.3.5, num_octets should be 3
 * poctet_array is the individual byte array if needed. The first function will return ~0u on error.
 */
uint32_t 	get_version_from_string(const char *pversion, int num_octets = 3) noexcept;
bool 		get_version_from_string(const char *pversion, uint32_t & version, uint8_t *poctet_array, int num_octets) noexcept;

int 		set_proc_file_limit(uint32_t max_files) noexcept; 
int 		set_proc_rtprio_limit(uint32_t max_rtprio) noexcept; 
int 		set_proc_nproc_limit(uint32_t max_procs) noexcept; 
void 		set_stdout_buffer_mode(bool use_buffering) noexcept; 	// Use ideally at init

int 		set_fd_nonblock(int fd, bool nonblock = true) noexcept; 
int 		duplicate_fd(int fd, bool cloexec = true) noexcept;
int 		set_sock_nodelay(int sock, int to_set = 1) noexcept;
int 		set_sock_keepalive(int sock, int to_set = 1) noexcept;
int 		set_sock_tcpcork(int sock, int to_set = 1) noexcept;
int 		set_sock_nonblocking(int sock, int to_set = 1) noexcept;

void 		gy_print_proc_status(char *pstr, int fdout = STDOUT_FILENO) noexcept;
uint64_t 	gy_get_proc_vmsize(pid_t) noexcept;
ssize_t		gy_get_proc_cpus_allowed(pid_t pid = getpid()) noexcept;
const char 	*gy_signal_str(int signo) noexcept;
void * 		gy_mmap_alloc(size_t size, size_t *pnewsize, int use_proc_shared) noexcept;
void 		gy_mmap_free(void *pbuf, size_t size) noexcept;
int 		base64_2ascii(uint8_t *src, int src_len, uint8_t *dest, int dest_len) noexcept;
int 		truncate_file_wrap_last(char *filename, size_t truncate_if_size_over, size_t last_bytes_to_wrap) noexcept;

/*
 * pname 			=> Name of new child process for logging purposes.
 * set_thr_name			=> Set the child process main thread name
 * pdesc			=> Description of child process
 * pstdout_log/pstderr_log	=> Path of new log files for child proc : Specify null for pstdout_log if to use parent log files
 * start_fd_close, end_fd_close	=> Start to end fd numbers to close()
 * pignore_fd_close, nignore_fd_close	=> Close all fds from start_fd_close to end_fd_close except for these fds
 * exit_on_parent_kill		=> Child proc to exit on parent process exit 
 * chown_uid, chown_gid		=> If running as root, chown fds of log files created
 * psignal_callback		=> Signal Callback to be invoked on a SIGINT / SIGSEGV after handler completes. 
 * signal_callback_will_exit	=> If specified and psignal_callback != nullptr, the SIGINT signal handler will not call _exit(). exit() to be called by the user directly. 
 * 				   Not applicable for SIGSEGV type signals, which will always abort().
 */ 	
int 		init_forked_child(const char *pname, bool set_thr_name, const char *pdesc, const char *pstdout_log, const char *pstderr_log, int log_flags, \
			int start_fd_close, int end_fd_close, int *pignore_fd_close, size_t nignore_fd_close, bool exit_on_parent_kill, \
			uid_t chown_uid = 0, gid_t chown_gid = 0, SIGNAL_CALLBACK_HDLR psignal_callbackin = nullptr, bool signal_callback_will_exit = false) noexcept;

/*
 * Updates the CPU util ticks and context switches. Uses the passed buffer to read /proc/stat. The szbuf should be > 10 KB to handle large core count hosts
 * Returns 0 on success, -1 on syscall error and 1 on format error
 */
int 		get_host_cpu_ctxt(char *pbuf, size_t szbuf, uint64_t *ptotal_util_ticks, uint64_t *pcontext_switch = nullptr, \
			uint64_t *puser_util_ticks = nullptr, uint64_t *psys_util_ticks = nullptr) noexcept;

int 		get_host_meminfo(uint64_t * memtotal, uint64_t * memrss, float * pctmemrss = nullptr, uint64_t * memfree_immed = nullptr, \
			uint64_t * memcached = nullptr, uint64_t * memlocked = nullptr, uint64_t * memcommitted = nullptr, float * pctcommit = nullptr, \
			uint64_t * swaptotal = nullptr, uint64_t * swapfree = nullptr) noexcept;

int 		get_host_vmstat(uint64_t & pgpgin, uint64_t & pgpgout, uint64_t & pswpin, uint64_t & pswpout, uint64_t & allocstall, uint64_t & pgmajfault, uint64_t & oom_kill) noexcept;

int 		get_proc_ns_inodes(pid_t pid, const char * nsstr[], ino_t nsinode[], size_t nitems, int proc_dir_fd = -1, pid_t tid = -1) noexcept; 

int 		get_proc_stat(pid_t pid, pid_t & task_ppid, char & task_state, uint32_t & task_flags, uint64_t & starttimeusec, int64_t & task_priority, \
			int64_t & task_nice, uint32_t & task_rt_priority, uint32_t & task_sched_policy, int proc_dir_fd = -1, bool is_tgid = true, pid_t tid = 0) noexcept;

ssize_t 	get_task_exe_path(pid_t pid, char *pbuf, size_t maxlen, int proc_dir_fd = -1) noexcept;
ssize_t 	get_task_comm(pid_t pid, char *pbuf, size_t maxlen, int proc_dir_fd = -1) noexcept;
ssize_t 	get_task_cmdline(pid_t pid, char *pbuf, size_t maxlen, int proc_dir_fd = -1) noexcept;
int 		get_proc_cgroups(pid_t pid, const char *ptypecg1[], char *pdircg1[], size_t maxcg1sz[], int maxcg1types, char *pdircg2, size_t maxcg2sz, \
			bool is_tgid = true, pid_t tid = 0, int proc_dir_fd = -1) noexcept;


/*
 * Requires log files to be opened using O_APPEND or else no use
 */
int 		gy_log_dir_cleanup(const char * plogdir, const char * pexten_arr[], size_t nextensions, size_t max_log_size, int nbackup_level = 2, uid_t chown_uid = 0, gid_t chown_gid = 0) noexcept;

extern uint64_t	gproc_start_usec, gproc_start_clock, gproc_start_boot;
extern pid_t	gproc_start_pid, gproc_curr_pid;

// Checks if current process is a forked child of the gproc_start_pid
static bool is_process_forked() noexcept
{
	return getpid() != gproc_start_pid;
}	

// Returns CLOCK_REALTIME sec
static time_t get_proc_start() noexcept
{
	return gproc_start_usec/1000'000;
}
	
// Returns CLOCK_REALTIME usec
static uint64_t	get_proc_start_tusec() noexcept
{
	return gproc_start_usec;
}
	
// Returns CLOCK_MONOTONIC usec
static uint64_t	get_proc_start_cusec() noexcept
{
	return gproc_start_clock;
}

// Returns CLOCK_BOOTTIME usec
static uint64_t get_proc_start_bootusec() noexcept
{
	return gproc_start_boot;
}	

static bool is_task_kthread(uint32_t flags) noexcept
{
	static const uint32_t 	TASK_PF_KTHREAD = 0x00200000;

	return (flags & TASK_PF_KTHREAD);
}	

static int proc_mutex_lock(pthread_mutex_t * pmutex, bool is_multi_process) noexcept
{
	int			ret;

	ret = ::pthread_mutex_lock(pmutex);
	if (ret == 0) {
		return 0;
	}
	
	if (ret == EOWNERDEAD && is_multi_process) {
		ret = ::pthread_mutex_consistent(pmutex);
		ret = 0;
	}	
		
	return ret;	
}
	
static int proc_mutex_trylock(pthread_mutex_t * pmutex, bool is_multi_process) noexcept
{
	int			ret;

	ret = ::pthread_mutex_trylock(pmutex);
	if (ret == 0) {
		return 0;
	}
	
	if (ret == EOWNERDEAD && is_multi_process) {
		ret = ::pthread_mutex_consistent(pmutex);
		ret = 0;
	}	
		
	return ret;	
}
	
static uint64_t gy_cityhash64(const char *s, size_t len) noexcept
{
	return CityHash64(s, len);
}	

static uint32_t gy_cityhash32(const char *s, size_t len) noexcept
{
	return CityHash32(s, len);
}

#include		"gy_common_inc.h"


} // namespace gyeeta	


