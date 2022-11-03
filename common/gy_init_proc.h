//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma 			once

#include			"gy_common_inc.h"

namespace gyeeta {

class INIT_PROC
{
public :
	char			**argv_;
	int			argc_;

	char			logdir_[GY_PATH_MAX]			{};
	char			init_dir_[GY_PATH_MAX]			{};
	char			tmpdir_[GY_PATH_MAX]			{};
	char			cfgdir_[GY_PATH_MAX]			{};

	char			stdout_logfile_[GY_PATH_MAX]		{};
	char			stderr_logfile_[GY_PATH_MAX]		{};
	char			lockfile_[GY_PATH_MAX]			{};

	uint32_t		max_stacksize_;
	uint32_t		min_stacksize_;
	uint32_t		min_openfiles_;
	uint32_t		min_nproc_;
	uid_t			chown_uid_				{0};
	gid_t			chown_gid_				{0};
	off_t			init_log_offset_			{0};
	int			fd_stdout_				{-1};
	int			fd_stderr_				{-1};
	int			fd_lock_				{-1};
	char			**ppexten_arr_				{nullptr};
	size_t			nextensions_				{0};

	bool			log_cleanup_chk_enabled_		{false};
	
	bool			handle_signals_;
	bool			exit_on_parent_kill_;

	bool			disable_core_;
	bool			set_sessionid_;
	bool			close_stdin_;

	INIT_PROC(int argc, char **argv, bool handle_signals, bool exit_on_parent_kill, bool chown_if_root, const char *logdir, const char *stdout_logfile, const char *stderr_logfile, size_t log_wrap_size, bool rename_old_log, const char * description,  bool disable_core, bool set_sessionid, const char *cfgdir, const char *tmpdir, const char * lockfilename, bool close_stdin, uint32_t max_stacksize, uint32_t min_stacksize, uint32_t min_openfiles, uint32_t min_nproc, bool throw_if_ulimit, bool log_use_utc_time = false, bool unbuffered_stdout = false); 

	~INIT_PROC()		= delete;	

	bool 			is_log_to_file() const noexcept 
	{
		return (fd_stdout_ > 0);
	}	

	int			get_stdout_fd() const noexcept
	{
		return fd_stdout_;	
	}
			
	int			get_stderr_fd() const noexcept
	{
		return fd_stderr_;	
	}

	const char *		get_log_dir() const noexcept
	{
		return logdir_;
	}	

	const char *		get_stdout_log_file() const noexcept
	{
		return stdout_logfile_;
	}	

	const char *		get_stderr_log_file() const noexcept
	{
		return stderr_logfile_;
	}	

	bool			is_chown_uid_gid(uid_t & uid, gid_t & gid) const noexcept
	{
		if (chown_uid_ || chown_gid_) {
			uid 	= chown_uid_;
			gid 	= chown_gid_;

			return true;
		}	

		uid = 0;
		gid = 0;
		return false;
	}
		
	const char *		get_init_dir() const noexcept
	{
		return init_dir_;
	}

	const char *		get_tmp_dir() const noexcept
	{
		return tmpdir_;
	}

	const char *		get_cfg_dir() const noexcept
	{
		return cfgdir_;
	}

	void			get_argc_argv(int & argc, char ** & argv) const noexcept
	{
		argc 		= argc_;
		argv		= argv_;
	}			

	int			get_max_stacksize() const noexcept
	{
		return max_stacksize_;
	}	
			
	off_t			get_init_log_offset() const noexcept
	{
		return init_log_offset_;	
	}
	
	bool			is_exclusive_proc() const noexcept
	{
		return (*lockfile_ != '\0');	
	}				
				
	int 			backup_init_log_file(size_t init_log_sz = 32 * 1024); 

	int 			set_log_file_monitor(const char * pexten_arr[], size_t nextensions, size_t max_log_size, int nbackup_level = 2, uint64_t sec_log_cleanup_check = 5, bool sched_init_backup = true, uint64_t msec_for_init_log = 1000, size_t init_log_sz = 32 * 1024); 

private :
	
	void			check_ulimits(bool throw_if_ulimit);
};


} // namespace gyeeta

