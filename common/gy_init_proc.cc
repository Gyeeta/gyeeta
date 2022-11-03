//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include		"gy_init_proc.h"
#include		"gy_file_api.h"
#include		"gy_misc.h"
#include		"gy_task_stat.h"
#include		"gy_scheduler.h"

#include 		<sys/file.h>
#include 		<sys/resource.h>

namespace gyeeta {

INIT_PROC::INIT_PROC(int argc, char **argv, bool handle_signals, bool exit_on_parent_kill, bool chown_if_root, const char *logdir, const char *stdout_logfile, const char *stderr_logfile, size_t log_wrap_size, bool rename_old_log, const char * description, bool disable_core, bool set_sessionid, const char *cfgdir, const char *tmpdir, const char * lockfilename, bool close_stdin, uint32_t max_stacksize, uint32_t min_stacksize, uint32_t min_openfiles, uint32_t min_nproc, bool throw_if_ulimit, bool log_use_utc_time, bool unbuffered_stdout)
	:
	argv_(argv), argc_(argc), max_stacksize_(max_stacksize), min_stacksize_(min_stacksize), min_openfiles_(min_openfiles), min_nproc_(min_nproc),
	handle_signals_(handle_signals), exit_on_parent_kill_(exit_on_parent_kill), disable_core_(disable_core), set_sessionid_(set_sessionid), close_stdin_(close_stdin) 
{
	int			ret;
	rlimit			rl;
	struct stat		stat1 {};

	tzset();

	umask(0006);
		
	assert(argv);
	
	guse_utc_time 		= log_use_utc_time;

	if (min_stacksize_ > max_stacksize_ && max_stacksize_) {
		min_stacksize_ = max_stacksize_;
	}	

	if (nullptr == getcwd(init_dir_, sizeof(init_dir_))) {
		GY_THROW_SYS_EXCEPTION("Current Directory Path length likely too long"); 
	}	

	if (handle_signals_) {
		GY_SIGNAL_HANDLER::init_singleton(argv_[0]);
	}	

	if (exit_on_parent_kill) {
		if (handle_signals_) {
			GY_SIGNAL_HANDLER::get_singleton()->set_default_handler(SIGHUP);
		}
		else {
			signal(SIGHUP, SIG_DFL);
		}
		
		prctl(PR_SET_PDEATHSIG, SIGHUP);
	}	
	else {
		if (handle_signals_) {
			GY_SIGNAL_HANDLER::get_singleton()->ignore_signal(SIGHUP);
		}
		else {
			signal(SIGHUP, SIG_IGN);
		}	
	}	
	
	if (set_sessionid) {
		setsid();
	}

	uid_t		uid;
	gid_t		gid;

	if (chown_if_root && (0 == geteuid())) {
		// Check if the binary install dir is also root owned
		char			bdir[GY_PATH_MAX];

		get_task_exe_path(getpid(), bdir, sizeof(bdir));

		ret = stat(bdir, &stat1);
		if (ret == 0 && ((stat1.st_uid != 0) || (stat1.st_gid != getegid()))) {
			chown_uid_ 	= stat1.st_uid;
			chown_gid_	= stat1.st_gid;
		}	
	}	

	if (close_stdin) {
		int fd_in = open("/dev/null", O_RDONLY | O_CLOEXEC);
		if (fd_in) {
			dup2(fd_in, STDIN_FILENO);
		}	
	}	

	if (disable_core) {
		rl.rlim_cur	= 0;
		rl.rlim_max	= 0;

		(void)setrlimit(RLIMIT_CORE, &rl);
	}	
	else {
		rl.rlim_cur	= RLIM_INFINITY;
		rl.rlim_max	= RLIM_INFINITY;

		(void)setrlimit(RLIMIT_CORE, &rl);
		// Ignore return status
	}	

	if (max_stacksize || min_stacksize || min_openfiles || min_nproc) {
		check_ulimits(throw_if_ulimit);
	}	

	if (cfgdir && *cfgdir) {
		ret = access(cfgdir, R_OK | X_OK);
		if (ret != 0) {
			GY_THROW_SYS_EXCEPTION("Access to cfgdir path %s denied", cfgdir);
		}

		if (false == path_is_absolute(cfgdir)) {
			snprintf(cfgdir_, sizeof(cfgdir_), "%s/%s", init_dir_, cfgdir);
		}
		else {
			GY_STRNCPY(cfgdir_, cfgdir, sizeof(cfgdir_));
		}
	}

	if (tmpdir && *tmpdir) {
		ret = gy_mkdir_recurse(tmpdir, 0755, chown_uid_, chown_gid_);
		if (ret != 0) {
			GY_THROW_SYS_EXCEPTION("Failed to create tmpdir path %s", tmpdir);
		}

		if (false == path_is_absolute(tmpdir)) {
			snprintf(tmpdir_, sizeof(tmpdir_), "%s/%s", init_dir_, tmpdir);
		}
		else {
			GY_STRNCPY(tmpdir_, tmpdir, sizeof(tmpdir_));
		}
	}
		 
	if (tmpdir && lockfilename && *tmpdir && *lockfilename) {
		bool		to_chg = false;

		
		if (false == path_is_absolute(tmpdir)) {
			snprintf(lockfile_, sizeof(lockfile_), "%s/%s/%s", init_dir_, tmpdir, lockfilename);
		}
		else {
			snprintf(lockfile_, sizeof(lockfile_), "%s/%s", tmpdir, lockfilename);
		}

		ret = stat(lockfile_, &stat1);
		if (ret == -1) {
			to_chg = true;
		}

		fd_lock_ = open(lockfile_, O_RDWR | O_CREAT | O_CLOEXEC, 0660);
		if (fd_lock_ == -1) {
			GY_THROW_SYS_EXCEPTION("Could not create lock file %s", lockfile_);
		}

		ret = flock(fd_lock_, LOCK_EX | LOCK_NB);
		if (ret) {
			if (errno == EWOULDBLOCK) {
				GY_THROW_EXCEPTION("Another instance of the process %s with the same lock file seems to be running...", argv[0]);
			}
			else {
				GY_THROW_SYS_EXCEPTION("Setting Lock on lock file %s failed", lockfile_);
			}
		}

		ftruncate(fd_lock_, 0);

		if (to_chg) {
			if (chown_uid_ || chown_gid_) {
				fchown(fd_lock_, chown_uid_, chown_gid_);
			}	
		}

		ret = gy_fdprintf(fd_lock_, 0, "PID=%d\n", getpid());
		if (ret <= 0) {
			GY_THROW_SYS_EXCEPTION("Write to lock file %s failed", lockfile_);
		}

		// Keep the fd_lock_ open for the process duration
	}	

	if (logdir && stdout_logfile && *logdir && *stdout_logfile) {
		ret = gy_mkdir_recurse(logdir, 0755, chown_uid_, chown_gid_);
		if (ret != 0) {
			GY_THROW_SYS_EXCEPTION("Failed to create stdout log dir path %s", logdir);
		}

		if (false == path_is_absolute(logdir)) {
			snprintf(logdir_, sizeof(logdir_), "%s/%s", init_dir_, logdir);
		}
		else {
			GY_STRNCPY(logdir_, logdir, sizeof(logdir_));
		}

		snprintf(stdout_logfile_, sizeof(stdout_logfile_), "%s/%s", logdir_, stdout_logfile);

		if (stderr_logfile) {
			snprintf(stderr_logfile_, sizeof(stderr_logfile_), "%s/%s", logdir_, stderr_logfile);
		}
		else {
			strcpy(stderr_logfile_, stdout_logfile_);
		}	

		if (rename_old_log) {
			char		oldbuf[GY_PATH_MAX];

			snprintf(oldbuf, sizeof(oldbuf) - 1, "%s.old", stdout_logfile_);
			rename(stdout_logfile_, oldbuf);

			snprintf(oldbuf, sizeof(oldbuf) - 1, "%s.old", stderr_logfile_);
			rename(stderr_logfile_, oldbuf);
		}

		bool		to_chg = false;

		ret = stat(stdout_logfile_, &stat1);
		if (ret == -1) {
			to_chg = true;
		}
		else if (!rename_old_log && log_wrap_size) {
			truncate_file_wrap_last(stdout_logfile_, 1, log_wrap_size);
		}

		fd_stdout_ = open(stdout_logfile_, O_RDWR | O_CREAT | O_APPEND | O_CLOEXEC, 0660);
		if (fd_stdout_ == -1) {
			GY_THROW_SYS_EXCEPTION("Could not open log file for stdout %s", stdout_logfile_);
		}
		
		if (to_chg) {
			if (chown_uid_ || chown_gid_) {
				fchown(fd_stdout_, chown_uid_, chown_gid_);
			}
		}

		fstat(fd_stdout_, &stat1);

		init_log_offset_ = stat1.st_size;

		if (0 == strcmp(stdout_logfile_, stderr_logfile_)) {
			fd_stderr_ = fd_stdout_;
		}
		else {
			to_chg = false;

			ret = stat(stderr_logfile_, &stat1);
			if (ret == -1) {
				to_chg = true;
			}
			else if (!rename_old_log && log_wrap_size) {
				truncate_file_wrap_last(stderr_logfile_, 1, log_wrap_size);
			}

			fd_stderr_ = open(stderr_logfile_, O_RDWR | O_CREAT | O_APPEND | O_CLOEXEC, 0660);
			if (fd_stderr_ == -1) {
				GY_THROW_SYS_EXCEPTION("Could not open log file for stderr %s", stderr_logfile_);
			}

			if (to_chg) {
				if (chown_uid_ || chown_gid_) {
					fchown(fd_stderr_, chown_uid_, chown_gid_);
				}
			}
		}	

		// Set stdout as line buffered by default and stderr as unbuffered
		setvbuf(stdout, nullptr, unbuffered_stdout ? _IONBF : _IOLBF, 0);
		setvbuf(stderr, nullptr, _IONBF, 0);

		gunbuffered_stdout = unbuffered_stdout;

		INFOFDPRINT(STDOUT_FILENO, "Starting process %s PID %d : All further logs will be redirected to file %s\n", argv[0], getpid(), stdout_logfile_);

		ret = dup2(fd_stdout_, STDOUT_FILENO);
		if (ret == -1) {
			GY_THROW_SYS_EXCEPTION("Failed to dup stdout log fd");
		}	

		ret = dup2(fd_stderr_, STDERR_FILENO);
		if (ret == -1) {
			GY_THROW_SYS_EXCEPTION("Failed to dup stderr log fd");
		}	
	}

	IRPRINT("\n\n");

	INFOPRINT("Starting process %s PID %d : %s\n\n", argv[0], getpid(), description);

	if (*logdir_) {
		INFOPRINT("Logdir %s : stdout log file %s : stderr log file %s\n", logdir_, stdout_logfile_, stderr_logfile_);
	}
	else {
		INFOPRINT("No Log file specified. Will use stdout and stderr directly...\n");		
	}		

	if (*cfgdir_) {
		INFOPRINT("Config directory cfgdir : %s\n", cfgdir_);
	}
	
	if (*tmpdir_) {
		INFOPRINT("Temporary File directory tmpdir : %s\n", tmpdir_);	
	}		

	pthread_atfork(nullptr, nullptr, 
		[]() 
		{
			gproc_curr_pid = getpid();
			gproc_start_usec = get_usec_time(); 
			gproc_start_clock = get_usec_clock(); 
			gproc_start_boot = get_usec_bootclock();
		
			GY_TIMEZONE::get_singleton()->set_periodic_check_on(false);
		}
	);		
}	

void INIT_PROC::check_ulimits(bool throw_if_ulimit)
{
	struct rlimit		rlim;
	int			ret;
	uint32_t		tcur;

	if (max_stacksize_ || min_stacksize_) {
		ret = getrlimit(RLIMIT_STACK, &rlim);

		if (ret == 0) {
			if (rlim.rlim_cur > max_stacksize_) {
				tcur = rlim.rlim_cur;

				rlim.rlim_cur = rlim.rlim_max = max_stacksize_;

				ret = setrlimit(RLIMIT_STACK, &rlim);
				if (ret) {
					if (throw_if_ulimit) {
						GY_THROW_SYS_EXCEPTION("Setting ulimit resource limit for Max Stack Size failed : Current Max size %u : Required %u", tcur, max_stacksize_);
					}	
				}
			}
			else if (rlim.rlim_cur < min_stacksize_) {
				tcur = rlim.rlim_cur;

				rlim.rlim_cur = rlim.rlim_max = min_stacksize_;

				ret = setrlimit(RLIMIT_STACK, &rlim);
				if (ret) {
					if (throw_if_ulimit) {
						GY_THROW_SYS_EXCEPTION("Setting ulimit resource limit for Min Stack Size failed : Current Max size %u : Required %u", tcur, min_stacksize_);
					}	
				}
			}	
		}
	}

	if (min_openfiles_) {
		ret = getrlimit(RLIMIT_NOFILE, &rlim);

		if (ret == 0 && (rlim.rlim_cur < min_openfiles_)) {
			rlim.rlim_cur = rlim.rlim_max = min_openfiles_;

			ret = setrlimit(RLIMIT_NOFILE, &rlim);
			if (ret) {
				if (throw_if_ulimit) {
					GY_THROW_SYS_EXCEPTION("Setting ulimit resource limit for open files failed : Please increase max allowed open files to at least %u", min_openfiles_);
				}	
			}
		}
	}

	if (min_nproc_) {
		ret = getrlimit(RLIMIT_NPROC, &rlim);

		if (ret == 0 && (rlim.rlim_cur < min_nproc_)) {

			rlim.rlim_cur = rlim.rlim_max = min_nproc_;

			ret = setrlimit(RLIMIT_NPROC, &rlim);
			if (ret) {
				if (throw_if_ulimit) {
					GY_THROW_SYS_EXCEPTION("Setting ulimit resource limit for nproc failed : Please increase max allowed user processes to at least %u", min_nproc_);
				}	
			}
		}
	}
}

int INIT_PROC::set_log_file_monitor(const char * pexten_arr[], size_t nextensions, size_t max_log_size, int nbackup_level, uint64_t sec_log_cleanup_check, bool sched_init_backup, uint64_t msec_for_init_log, size_t init_log_sz) 
{
	if (log_cleanup_chk_enabled_) {
		return -1;
	}	

	assert(pexten_arr);
	assert(nextensions);
	assert(sec_log_cleanup_check);

	log_cleanup_chk_enabled_ = true;

	nextensions_ = nextensions;

	ppexten_arr_ = new char * [nextensions];
	
	for (size_t i = 0; i < nextensions; i++) {
		ppexten_arr_[i] = new char [strlen(pexten_arr[i]) + 1];
		strcpy(ppexten_arr_[i], pexten_arr[i]);
	}

	GY_SCHEDULER::init_singletons();
	
	auto schedshrmain = GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_MAINTENANCE);

	if (!schedshrmain) {
		GY_THROW_EXCEPTION("Global Scheduler Shared objects not yet initialized");
	}	

	if (sched_init_backup) {
		schedshrmain->add_oneshot_schedule(msec_for_init_log, "init log backup", 
		[this, init_log_sz] { 
			backup_init_log_file(init_log_sz);
		});
	}

	schedshrmain->add_schedule(sec_log_cleanup_check * 1000, sec_log_cleanup_check * 1000, 0, "log dir cleanup check", 
	[=] { 
		gy_log_dir_cleanup(get_log_dir(), const_cast<const char **>(this->ppexten_arr_), nextensions, max_log_size, nbackup_level, chown_uid_, chown_gid_);
	});

	return 0;
}	

int INIT_PROC::backup_init_log_file(size_t init_log_sz) 
{
	try {
		if (!is_log_to_file()) {
			return 1;
		}	

		uint8_t			*pbuf;
		bool			is_malloc;
		ssize_t			sret;
		int			ret, fd;
		char			path[GY_PATH_MAX];

		snprintf(path, sizeof(path), "%s.init.log", stdout_logfile_);

		SCOPE_FD		fdscope(path, O_RDWR | O_CREAT | O_CLOEXEC | O_TRUNC, 0640);

		fd = fdscope.get();
		if (fd < 0) {
			PERRORPRINT("Failed to open init.log file %s for log backup", path);
			return -1;
		}	

		if (chown_uid_ || chown_gid_) {
			fchown(fd, chown_uid_, chown_gid_);
		}

		SAFE_STACK_ALLOC(pbuf, init_log_sz, is_malloc);

		sret = gy_preadbuffer(get_stdout_fd(), pbuf, init_log_sz, init_log_offset_);
		if (sret <= 0) {
			PERRORPRINT("Failed to read stdout log for init log");
			return -1;
		}	

		sret = gy_writebuffer(fd, pbuf, sret);
		if (sret <= 0) {
			PERRORPRINT("Failed to write stdout log to init log file %s", path);
			return -1;
		}	

		return 0;
	}
	catch(...) {
		return -1;
	}	
}	

} // namespace gyeeta
