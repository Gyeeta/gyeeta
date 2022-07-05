

#pragma 			once

#include			"gy_common_inc.h"
#include			"gy_pkt_pool.h"
#include			"gy_msg_comm.h"

#include 			<sys/wait.h>

namespace gyeeta {

class CHILD_PROC
{
public :	
	static constexpr int	MAGIC_START_				{0x0ABBCCDD};	
	static constexpr int	MAGIC_END_				{0x11223344};	

	int			magic_start_				{MAGIC_START_};
	pid_t			pid_					{-1};
	pid_t			ppid_					{0};
	int			magic_end_				{MAGIC_END_};
	int			socket_pair_[2]				{-1, -1};
	int			socket_					{-1};
	int			child_proc_socket_			{-1};
	char			stdout_logfile_[GY_PATH_MAX]		{};
	char			stderr_logfile_[GY_PATH_MAX]		{};
	pthread_mutex_t		sockmutex_;
	GY_PKT_POOL		*pshrpool_				{nullptr};
	SIGNAL_CALLBACK_HDLR	signal_callback_			{nullptr};
	bool			use_parent_log_files_			{false};
	bool 			exit_on_parent_kill_			{false};
	bool			use_socket_pair_			{false};
	bool			signal_callback_will_exit_		{false};
	bool			is_child_proc_				{false};
	
	CHILD_PROC(bool use_parent_log_files, const char *pstdout_log, const char *pstderr_log, bool exit_on_parent_kill, bool use_socket_pair, bool use_shared_pool, uint32_t pool_bufcnt, uint32_t pool_maxpktlen, SIGNAL_CALLBACK_HDLR psignal_callback = nullptr, bool signal_callback_will_exit = false) :
		ppid_(getpid()), signal_callback_(psignal_callback), use_parent_log_files_(use_parent_log_files), exit_on_parent_kill_(exit_on_parent_kill), 
		use_socket_pair_(use_socket_pair), signal_callback_will_exit_(signal_callback_will_exit)
	{
		if (use_parent_log_files == false) {
			assert(pstdout_log);

			GY_STRNCPY(stdout_logfile_, pstdout_log, sizeof(stdout_logfile_));
			if (pstderr_log) {
				GY_STRNCPY(stderr_logfile_, pstderr_log, sizeof(stderr_logfile_));
			}	
			else {
				strcpy(stderr_logfile_, stdout_logfile_);
			}	
		}	
		
		if (use_shared_pool) {
			pshrpool_ = GY_PKT_POOL::alloc_shared_proc_pool(pool_bufcnt, pool_maxpktlen, false /* is_single_writer */, "Child Process Communication Pool");
		}
			
		if (use_socket_pair) {
			int			ret;

			ret = ::socketpair(AF_LOCAL, SOCK_STREAM, 0, socket_pair_);
			if (ret == -1) {
				GY_THROW_SYS_EXCEPTION("Failed to create socketpair for child process");
			}	

			socket_ = socket_pair_[0];
			child_proc_socket_ = socket_pair_[1];
		}	

		pthread_mutex_init(&sockmutex_, nullptr);
	}	

	~CHILD_PROC()
	{
		pid_t 		tpid = -1;
		
		if ((pid_ > 0) && (is_child_proc_ == false)) {
			tpid = ::waitpid(pid_, nullptr, WNOHANG);

			if (pid_ == tpid) {
				INFOPRINT("Child process PID %d already exited...\n", pid_);
				pid_ = -1;
			}
		}		

		if (socket_ > 0) {
			if (exit_on_parent_kill_ || pid_ < 0 || (tpid == pid_)) { 

				if (socket_pair_[0] > 0) {
					(void)::close(socket_pair_[0]);
					socket_pair_[0] = -1;
				}	

				if (socket_pair_[1] > 0) {
					(void)::close(socket_pair_[1]);
					socket_pair_[1] = -1;
				}	

				socket_ = -1;
				child_proc_socket_ = -1;
			}
		}
		
		if (exit_on_parent_kill_ && is_child_proc_ == false && pid_ > 0 && pid_ != getpid() && ppid_ == getpid() && is_no_corruption()) {

			if (pshrpool_) {
				pshrpool_->pool_set_wr_exited();
			}
				
			INFOPRINT("Killing Child process PID %d as destructor called. Also waiting for child exit...\n", pid_);

			::kill(pid_, SIGINT);
			::waitpid(pid_, nullptr, 0);
		}		

		if (pshrpool_) {
			GY_PKT_POOL::dealloc_shared_proc_pool(pshrpool_, (false == is_child_proc_), (true == is_child_proc_));
		}	

		pthread_mutex_destroy(&sockmutex_);

		pid_ = -1;
	}	

	CHILD_PROC(const CHILD_PROC &)			= delete;
	CHILD_PROC(CHILD_PROC &&)			= delete;

	CHILD_PROC & operator= (const CHILD_PROC &)	= delete;
	CHILD_PROC & operator= (CHILD_PROC &&)		= delete;

	// Returns 0 in child pid and non zero in parent
	pid_t fork_child(const char *pname, bool set_thr_name, const char *pdesc, int log_flags, int start_fd_close, int end_fd_close, uid_t chown_uid = 0, gid_t chown_gid = 0, int *pignore_fd_close = nullptr, size_t nignore_fd_close = 0, bool chk_child_fork_status = true)
	{
		assert(pname);
		assert(pdesc);

		assert(pid_ == -1);

		if (pid_ > 0) {
			GY_THROW_SYS_EXCEPTION("Child process for %s : %s already forked : PID %d", pname, pdesc, pid_);
		}	

		pid_t			pid;
		
		pid = fork();

		if (pid == -1) {
			GY_THROW_SYS_EXCEPTION("Failed to fork child process for %s : %s", pname, pdesc);
		}
	
		if (pid == 0) {
			pid_ = getpid(); 
					
			is_child_proc_ = true;
			
			int		*ignore_fd_close_arr;
			bool		is_malloc;	

			if (nignore_fd_close < 500) {
				ignore_fd_close_arr = (int *)alloca((nignore_fd_close + 2) * sizeof(int));
				is_malloc = false;
			}	
			else {
				ignore_fd_close_arr = (int *)malloc((nignore_fd_close + 2) * sizeof(int));
				is_malloc = true;

				if (!ignore_fd_close_arr) {
					PERRORPRINT("Child process %d for %s : %s : Failed to alloc memory for init", pid_, pname, pdesc);
					exit(1);
				}	
			}			

			GY_SCOPE_EXIT {
				if (is_malloc && ignore_fd_close_arr) {
					free(ignore_fd_close_arr);
				}	
			};	

			std::memset(ignore_fd_close_arr, 0, (nignore_fd_close + 2) * sizeof(int));

			if (pignore_fd_close) {
				memcpy(ignore_fd_close_arr, pignore_fd_close, nignore_fd_close * sizeof(int));
			}	
			
			if (use_socket_pair_) {
				ignore_fd_close_arr[nignore_fd_close++] = socket_pair_[1];

				socket_ = socket_pair_[1];
				(void)::close(socket_pair_[0]);
				socket_pair_[0] = -1;
			}	

			init_forked_child(pname, set_thr_name, pdesc, !use_parent_log_files_ ? stdout_logfile_ : nullptr, !use_parent_log_files_ ? stderr_logfile_ : nullptr,
				log_flags, start_fd_close, end_fd_close, ignore_fd_close_arr, nignore_fd_close, exit_on_parent_kill_, chown_uid, chown_gid, 
				signal_callback_, signal_callback_will_exit_);

			return 0;
		}	
		else {
			pid_ = pid;

			if (use_socket_pair_) {
				socket_ = socket_pair_[0];
				(void)::close(socket_pair_[1]);
				socket_pair_[1] = -1;
			}	

			gy_nanosleep(0, 10 * GY_NSEC_PER_MSEC);
		
			if (chk_child_fork_status) {	
				pid_t 	tpid = ::waitpid(pid_, nullptr, WNOHANG);

				if (tpid == pid_) {
					GY_THROW_EXCEPTION("Child process %d exited at start itself", pid_);
				}
			}
				
			INFOPRINT("Spawned Child process PID %d for %s : %s\n", pid_, pname, pdesc);
				
			return pid_;
		}	
	}	

	int get_socket() const noexcept
	{
		return socket_;
	}	

	pthread_mutex_t * get_mutex() noexcept
	{
		return &sockmutex_;
	}	

	GY_PKT_POOL * get_shared_pool() noexcept
	{
		return pshrpool_;
	}
			
	pid_t get_child_pid() const noexcept
	{
		return pid_;
	}	

	bool is_child_forked() const noexcept
	{
		return (pid_ > 0);
	}	

	bool is_no_corruption() const noexcept
	{
		return ((magic_start_ == MAGIC_START_) && (magic_end_ == MAGIC_END_));
	}	
};

} // namespace gyeeta

