//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include		"gy_server_int.h"
#include		"gy_task_handler.h"
#include		"gy_cgroup_stat.h"
#include		"gy_scheduler.h"
#include		"gy_sys_hardware.h"
#include		"gy_async_func.h"			
#include		"gy_ebpf_kernel.h"			
#include		"gy_sys_stat.h"			

#include 		<dirent.h>
#include 		<linux/netlink.h>
#include 		<linux/connector.h>
#include 		<linux/cn_proc.h>

namespace gyeeta {
	
using namespace comm;

TASK_HANDLER::TASK_HANDLER(bool stats_updated_by_sock_in, bool is_kubernetes_in)
	: 
	tasktable(128), 
	toptask(comm::TASK_TOP_PROCS::TASK_MAX_TOP_N), pg_toptask(comm::TASK_TOP_PROCS::TASK_MAX_TOPPG_N), 
	toprss(comm::TASK_TOP_PROCS::TASK_MAX_RSS_TOP_N), topforks(comm::TASK_TOP_PROCS::TASK_MAX_FORKS_TOP_N), 
	stats_updated_by_sock(stats_updated_by_sock_in), is_kubernetes(is_kubernetes_in),
	proc_dir_fd(
		({
			if (nullptr == SYS_HARDWARE::get_singleton()) {
				GY_THROW_EXCEPTION("Global System hardware Singleton not yet initialized");
			}	

			auto pmount = MOUNT_HDLR::get_singleton();
			if (!pmount) {
				GY_THROW_EXCEPTION("Global Mount Shared pointer is not yet initialized");
			}
			pmount->get_proc_dir_fd();
		})
		),
	sysfs_dir_fd(MOUNT_HDLR::get_singleton()->get_sysfs_dir_fd()),
	nltaskthr("Task Handler Thread", TASK_HANDLER::GET_PTHREAD_WRAPPER(nltask_thread), this, nullptr, nullptr, true, 512 * 1024, 2000, true, true, true, 5000, false)
{
	if (proc_dir_fd == -1 || sysfs_dir_fd == -1) {
		GY_THROW_EXCEPTION("/proc or /sysfs mount points not seen");
	}	

	init_psi_fds();
}

int TASK_HANDLER::init_task_list()
{
	try {
		/*
		 * Scan all current tasks in system 
		 */
		DIR				*pdir = nullptr; 
		struct dirent			*pdent;
		char				*pfile, *pstr1;
		int				ret, nadded = 0;
		pid_t				pidval;

		pdir = opendir("/proc");
		if (!pdir) {
			GY_THROW_SYS_EXCEPTION("Could not open proc filesystem for populating task table");
		}

		GY_SCOPE_EXIT {
			closedir(pdir);
		};

		while ((pdent = readdir(pdir)) != nullptr) {

			pstr1 = nullptr;
			
			pfile = pdent->d_name;	
			
			if (!gy_isdigit_ascii(*pfile)) {
				continue;
			}

			if (string_to_number(pfile, pidval, &pstr1, 10)) {
				if (pstr1 && *pstr1) {
					continue;
				}	

				ret = task_add(pidval, 0, true);
				if (ret == 0) {
					nadded++;
				}	
			}	
			else {
				continue;
			}	
		}

		INFOPRINT_OFFLOAD("Populated task map with existing processes : Current PID Count = %d\n", nadded);

		auto lambda_upd_par = [this](TASK_ELEM_TYPE *pdatanode, void *arg1) -> CB_RET_E
		{
			auto		ptask = pdatanode->get_cref().get();

			if (ptask == nullptr) {
				return CB_OK;
			}

			if (ptask->task_ppid <= 1) {
				if (ptask->task_pid > 1) {
					ptask->is_execv_task	= true;
				}
				return CB_OK;
			}	
		
			// Update parent info
			auto updtask = [&](TASK_STAT *ptaskpar)
			{ 
				std::memcpy(ptask->task_parent_comm, ptaskpar->task_comm, sizeof(ptask->task_parent_comm));
				ptask->weak_parent_task = ptaskpar->weak_from_this();
				ptask->is_execv_task 	= (0 != strcmp(ptask->task_cmdline, ptaskpar->task_cmdline));
				ptask->is_forked_task	= true;
				ptask->parent_ppid	= ptaskpar->task_ppid;
				ptask->parent_pgid	= ptaskpar->task_pgid;
			};

			get_task(ptask->task_ppid, updtask);
				 
			return CB_OK;
		};	

		tasktable.walk_hash_table(lambda_upd_par, nullptr); 	

		if (stats_updated_by_sock == false) {
			set_init_table_done();
		}

	 	return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT_OFFLOAD("Caught Exception while populating initial task list : %s\n", GY_GET_EXCEPT_STRING);
		throw;
	);
}	

int TASK_HANDLER::task_add(pid_t pid, pid_t ppid, bool add_cgroup, bool from_main_thread) noexcept
{
	GY_NOMT_COLLECT_PROFILE(10000, "Task Table Process Add");

	try {
		bool				bret, new_task = false;
		TASK_STAT			*ptask = nullptr;
		FREE_FPTR			free_fp, free_fp_elem;

		if (ppid > 0) {
			TASK_ELEM_TYPE		elem_parent;

			/*
			 * First check if the parent PID is present in task table 
			 */
			bret = tasktable.lookup_single_elem(ppid, get_pid_hash(ppid), elem_parent);

			if (bret == true) {
				auto			ptaskpar = elem_parent.get_cref().get();

				if (ptaskpar) {
					ptask = (TASK_STAT *)pool_task_.safe_malloc(free_fp, true /* use_malloc_hdr */);

					try {
						new (ptask) TASK_STAT(ptaskpar, pid, proc_dir_fd, from_main_thread);
					}
					catch(...) {
						THR_POOL_ALLOC::dealloc(ptask);
						return -1;
					}	
				}
				else {
					bret = false;
				}	
			}	
		}	

		if (!ptask) {
			// Could not find parent task
			ptask = (TASK_STAT *)pool_task_.safe_malloc(free_fp, true /* use_malloc_hdr */);

			try {
				new (ptask) TASK_STAT(proc_dir_fd, pid, ppid);
			}
			catch(...) {
				THR_POOL_ALLOC::dealloc(ptask);
				return -1;
			}	
			new_task = true;
		}	

		if (!ptask->is_task_valid()) {
			DEBUGEXECN(11, INFOPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to populate data for new fork task PID %d. Ignoring...\n", pid););
			
			missed_fork.fetch_add_relaxed(1, std::memory_order_relaxed);

			ptask->~TASK_STAT();
			THR_POOL_ALLOC::dealloc(ptask);
			return 1;
		}

		TASK_ELEM_TYPE		*pelem;

		try {
			pelem = (TASK_ELEM_TYPE *)pool_elem_task_.safe_malloc(free_fp_elem, true /* use_malloc_hdr */);

			try {
				new (pelem) TASK_ELEM_TYPE(ptask, TPOOL_DEALLOC<TASK_STAT>());
			}
			catch(...) {
				THR_POOL_ALLOC::dealloc(pelem);
				throw;
			}	

			if (add_cgroup) {
				ptask->set_task_cgroups(proc_dir_fd);
			}	
		}
		GY_CATCH_EXCEPTION(
			DEBUGEXECN(1, ERRORPRINT_OFFLOAD("Caught exception while allocating memory for task table for PID %d : %s\n", pid, GY_GET_EXCEPT_STRING););

			ptask->~TASK_STAT();
			THR_POOL_ALLOC::dealloc(ptask);
			return -1;
		);

		CONDEXEC(DEBUGEXECN(15, INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Fork of new process : PID %d PPID %d UID %d GID %d : %s\n", 
				ptask->task_pid, ptask->task_ppid, ptask->task_effuid, ptask->task_effgid, ptask->task_cmdline);););

		bret = tasktable.insert_or_replace(pelem, pid, get_pid_hash(pid));

		return 0;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINT_OFFLOAD("Caught exception while inserting new task for PID %d : %s\n", pid, GY_GET_EXCEPT_STRING);); 
		missed_fork.fetch_add_relaxed(1, std::memory_order_relaxed);
		return -1;
	);
}	

int TASK_HANDLER::task_exit(pid_t pid, int exit_code) noexcept
{
	try {
		auto 		lambda_exit_task = [this, exit_code](TASK_ELEM_TYPE *pdatanode, void *arg1, void *arg2) -> CB_RET_E
		{
			auto			ptask = pdatanode->get_cref().get();
			TASK_KILL_INFO		kone;
			int			ret;

			if (ptask == nullptr) {
				return CB_DELETE_ELEM;
			}

			ret = ptask->set_task_exited(exit_code, kone);

			if (ret && kone.tkill_ - task_kill_arr_[3].tkill_ > 3) {
				// Note the recent tasks killed
				array_shift_right(task_kill_arr_, MAX_KILL_PROCS);
				task_kill_arr_[0] = kone;
			}	

			return CB_DELETE_ELEM;
		};	

		tasktable.lookup_single_elem(pid, get_pid_hash(pid), lambda_exit_task);

		return 0;
	}
	GY_CATCH_EXCEPTION(DEBUGEXECN(1, ERRORPRINT_OFFLOAD("Caught exception while deleting task from task map for PID %d : %s\n", pid, GY_GET_EXCEPT_STRING);); return -1;);
}

int TASK_HANDLER::task_exec(pid_t pid) noexcept
{
	try {
		auto lamexec = [this](TASK_ELEM_TYPE *pdatanode, void *arg1, void *arg2) -> CB_RET_E
		{
			auto			ptask = pdatanode->get_cref().get();

			if (ptask) {
				ptask->set_task_exec(proc_dir_fd);
			}

			return CB_OK;
		};	

		tasktable.lookup_single_elem(pid, get_pid_hash(pid), lamexec);

		return 0;
	}
	GY_CATCH_EXCEPTION(DEBUGEXECN(1, ERRORPRINT_OFFLOAD("Caught exception for task exec handling for PID %d : %s\n", pid, GY_GET_EXCEPT_STRING);); return -1;);
}	

int TASK_HANDLER::task_uid_gid_change(pid_t pid, uid_t realid, uid_t effid, bool is_uid) noexcept
{
	try {
		TASK_ELEM_TYPE		elem;
		bool			bret;
		
		auto lambda_uid_task = [=](TASK_ELEM_TYPE *pdatanode, void *arg1, void *arg2) -> CB_RET_E
		{
			auto			ptask = pdatanode->get_cref().get();

			if (ptask == nullptr) {
				return CB_OK;
			}

			if (is_uid) {
				ptask->set_task_uid_change(effid);
			}
			else {
				ptask->set_task_gid_change(effid);
			}	

			return CB_OK;
		};	

		bret = tasktable.lookup_single_elem(pid, get_pid_hash(pid), lambda_uid_task);

		return 0;

	}
	GY_CATCH_EXCEPTION(DEBUGEXECN(1, ERRORPRINT_OFFLOAD("Caught exception for task uid / gid change handling for PID %d : %s\n", pid, GY_GET_EXCEPT_STRING);); return -1;);
}	


int TASK_HANDLER::task_sid_change(pid_t pid) noexcept
{
	try {
		TASK_ELEM_TYPE		elem;
		bool			bret;

		auto lambda_sid_task = [](TASK_ELEM_TYPE *pdatanode, void *arg1, void *arg2) -> CB_RET_E
		{
			auto			ptask = pdatanode->get_cref().get();

			if (ptask == nullptr) {
				return CB_OK;
			}

			ptask->set_task_sid_change();		

			return CB_OK;
		};	

		bret = tasktable.lookup_single_elem(pid, get_pid_hash(pid), lambda_sid_task);

		return 0;

	}
	GY_CATCH_EXCEPTION(DEBUGEXECN(1, ERRORPRINT_OFFLOAD("Caught exception for task sid change handling for PID %d : %s\n", pid, GY_GET_EXCEPT_STRING);); return -1;);
}

int TASK_HANDLER::task_ptrace(pid_t pid, pid_t tracer_pid, bool is_attach_ptrace) noexcept
{
	try {
		TASK_ELEM_TYPE		elem;
		bool			bret;

		auto 			lambda_task = [=](TASK_ELEM_TYPE *pdatanode, void *arg1, void *arg2) -> CB_RET_E
		{
			auto			ptask = pdatanode->get_cref().get();

			if (ptask == nullptr) {
				return CB_OK;
			}

			ptask->set_task_ptrace(tracer_pid, is_attach_ptrace);		

			return CB_OK;
		};	

		bret = tasktable.lookup_single_elem(pid, get_pid_hash(pid), lambda_task);

		return 0;

	}
	GY_CATCH_EXCEPTION(DEBUGEXECN(1, ERRORPRINT_OFFLOAD("Caught exception for task ptrace handling for PID %d : %s\n", pid, GY_GET_EXCEPT_STRING);); return -1;);
}

int TASK_HANDLER::task_cgroup_change(pid_t pid, pid_t tid) noexcept
{
	try {
		TASK_ELEM_TYPE		elem;
		bool			bret;

		auto 			lambda_cgroup_task = [this](TASK_ELEM_TYPE *pdatanode, void *arg1, void *arg2) -> CB_RET_E
		{
			auto			ptask = pdatanode->get_cref().get();

			if (ptask == nullptr) {
				return CB_OK;
			}

			// Lazily update using the same thread as the normal updater
			ptask->cgroups_changed.store(true, std::memory_order_release);

			return CB_OK;
		};	

		bret = tasktable.lookup_single_elem(pid, get_pid_hash(pid), lambda_cgroup_task);

		return 0;
	}
	GY_CATCH_EXCEPTION(DEBUGEXECN(1, ERRORPRINT_OFFLOAD("Caught exception for task cgroup change handling for PID %d : %s\n", pid, GY_GET_EXCEPT_STRING);); return -1;);
}

void TASK_HANDLER::handle_cgroup_change_event(cgroup_migrate_event_t *pevent, bool more_data) noexcept
{
	/*
	 * XXX We currently do not handle the case where threads within a process are placed in separate cgroups.
	 * i.e. Threaded cgroupsv2 is not supported.
	 */
	if (!pevent->threadgroup) {
		return;	
	}	
	
	task_cgroup_change(pevent->pid, pevent->tid); 
}	

int TASK_HANDLER::handle_cpuset_change(CGROUP1_CPUSET *prawcpuset, CGROUP2 *prawcpuset2, bool cpus_changed, const CPU_CORES_BITSET & cpus_allowed, 
							bool mems_changed, const MEM_NODE_BITSET & mems_allowed) noexcept
{
	try {
		TASK_ELEM_TYPE		elem;
		bool			bret;
		int			nupd = 0;

		auto lambda_cgroup_task = [=, &nupd](TASK_ELEM_TYPE *pdatanode, void *arg) -> CB_RET_E
		{
			auto			ptask = pdatanode->get_cref().get();

			if (ptask == nullptr) {
				return CB_OK;
			}

			if (ptask->cgroups_updated.load(std::memory_order_acquire) == true) {
				if ((prawcpuset && ptask->cg_cpuset_shr.get() == prawcpuset) || (prawcpuset2 && ptask->cg_2_shr.get() == prawcpuset2)) {
					if (cpus_changed) {
						ptask->ncpus_allowed = cpus_allowed.count();
					}

					if (mems_changed) {
						ptask->nmems_allowed = mems_allowed.count();
					}	

					nupd++;
				}	
			}	

			return CB_OK;
		};	

		tasktable.walk_hash_table_const(lambda_cgroup_task);

		if (nupd) {
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Updated %d tasks cpus_allowed / mems_allowed for cpuset cgroup dir %s\n", nupd, 
				prawcpuset ? prawcpuset->get_dir_path() : prawcpuset2->get_dir_path());
		}	

		return nupd;
	}
	GY_CATCH_EXCEPTION(DEBUGEXECN(1, ERRORPRINT_OFFLOAD("Caught exception for cpuset cgroup task change handling : %s\n", GY_GET_EXCEPT_STRING);); return -1;);
}

void TASK_HANDLER::tasks_cpu_stats_print() const noexcept
{
	try {
		if (!init_table_done) {
			return;
		}	

		auto 				lambda_cpu_print = [](TASK_ELEM_TYPE *pdatanode, void *arg1) -> CB_RET_E
		{
			auto			ptask = pdatanode->get_cref().get();
			int			ret;

			if (ptask == nullptr) {
				return CB_OK;
			}
		
			if (ptask->pext_stats && ptask->pext_stats->pdelay_stats_) {
				char		printbuf[8192];
				STR_WR_BUF	strbuf(printbuf, sizeof(printbuf));
				
				strbuf.appendfmt(GY_COLOR_MAGENTA "Task Statistics : PID %d Comm \'%s\' : TCP Listeners %d : TCP Client %d : \n" GY_COLOR_CYAN_ITALIC, 
					ptask->task_pid, ptask->task_comm, ptask->ntcp_listeners.load(std::memory_order_relaxed), ptask->is_tcp_client);
				
				ptask->pext_stats->print_stats(strbuf);

				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN_ITALIC, "%.*s\n\n", strbuf.sizeint(), strbuf.buffer());
			}

			return CB_OK;
		};	

		DEBUGEXECN(10, 
			tasktable.walk_hash_table_const(lambda_cpu_print); 	
		);	
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while printing CPU util of tasks : %s\n", GY_GET_EXCEPT_STRING););
	);
}

int TASK_HANDLER::tasks_non_tcp_check() noexcept
{
	try {
		if (!init_table_done || last_ndelay_tasks > MAX_NDELAY_TASKS) {
			return 0;
		}	

		int			nnew = 0;
		uint64_t		curr_usec_time = get_usec_time();

		auto lambda_imp_task = [&, this, curr_usec_time](TASK_ELEM_TYPE *pdatanode,void *arg1)
		{
			auto			ptask = pdatanode->get_cref().get();
			int			ret, last_pct;
			bool			is_imp;

			if (ptask == nullptr || !ptask->pext_stats) {
				return CB_OK;
			}

			if (false == bool(ptask->pext_stats->pdelay_stats_)) {
				is_imp = ptask->pext_stats->is_important_task(curr_usec_time);
				
				if (is_imp) { 	 
					ptask->pext_stats->pdelay_stats_ = std::make_unique<TASK_DELAY_STATS>(ptask, is_kubernetes);
					nnew++;
				}	
			}

			return CB_OK;
		};	

		tasktable.walk_hash_table(lambda_imp_task); 	

		if (nnew) {
			INFOPRINT_OFFLOAD("Added Task Stats for %d non-TCP tasks\n", nnew);
			last_new_delay_cusec = get_usec_clock();
		}
			
		return 0;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while checking non-TCP important tasks : %s\n", GY_GET_EXCEPT_STRING););
		return -1;
	);		
}

std::tuple<int, int, int> TASK_HANDLER::tasks_cpu_stats_update(bool from_scheduler, bool only_imp_procs, uint64_t last_all_procs_tusec, const std::shared_ptr<SERVER_CONNTRACK> & servshr) noexcept
{
	try {
		if (from_scheduler && !init_table_done) {
			return {0, 0, 0};
		}	

		GY_NOMT_COLLECT_PROFILE(40, "Task Table CPU Utilization and delay collection");

		struct AggrNotify : public comm::AGGR_TASK_STATE_NOTIFY
		{
			char			issue_string_[comm::AGGR_TASK_STATE_NOTIFY::MAX_ISSUE_LEN];

			AggrNotify() noexcept
			{
				*issue_string_ = 0;
			}	

			const comm::AGGR_TASK_STATE_NOTIFY & get_base() const noexcept
			{
				return *this;
			}	
		};	

		// Need at least 700 KB Stack
		assert(gy_get_thread_local().get_thread_stack_freespace() > 700 * 1024);

		using PGStackmap 		= INLINE_STACK_HASH_MAP<pid_t, PG_TASK_CPU_PCT, 230 * 1024, GY_JHASHER<pid_t>>;
		using AggrNotifyMap		= INLINE_STACK_HASH_MAP<uint64_t, AggrNotify, 400 * 1024, GY_JHASHER<uint64_t>>;

		PGStackmap			pg_cpumap;
		AggrNotifyMap			aggrnotmap;

		uint64_t			total_cpu_delus = 0, total_vm_delus = 0, total_io_delus = 0;
		int				ntotal, nupd = 0, ndelays = 0, ntaskpg = 0, nnewdelays = 0, nissues = 0, nsevere = 0, nothertasks = 0, lastnother = 0;
		bool				bret;
			
		pg_cpumap.reserve(128);
		aggrnotmap.reserve(256);
			
		if (only_imp_procs == false) {
			toptask.clear(); 	
			pg_toptask.clear(); 	
			toprss.clear(); 	
			topforks.clear();	
		}

		uint64_t			curr_usec_clock = get_usec_clock();
		int64_t				start_fork_tsec = last_all_procs_tusec/GY_USEC_PER_SEC;
		size_t				szstring = 0, nsent = 0;
		bool				send_server = bool(servshr), all_aggr = false, send_netstats = (curr_usec_clock >= last_netstats_cusec + 15 * GY_USEC_PER_SEC);
		
		if (send_netstats) {
			last_netstats_cusec = curr_usec_clock;
		}	
			
		if (only_imp_procs == false && curr_usec_clock - last_all_aggr_state_cusec >= 18 * GY_USEC_PER_SEC) {
			all_aggr = true;
			last_all_aggr_state_cusec = curr_usec_clock;
		}	

		auto lambda_cpu_task = [&, only_imp_procs, all_aggr, curr_usec_clock, start_fork_tsec, send_netstats](TASK_ELEM_TYPE *pdatanode, void *arg1) -> CB_RET_E
		{
			auto			ptask = pdatanode->get_cref().get();
			int			ret;
			float			curr_cpu_pct, last_pct_fl;
			bool			is_imp_proc;

			if (ptask == nullptr) {
				return CB_OK;
			}
		
			is_imp_proc = ((ptask->pext_stats && ptask->pext_stats->pdelay_stats_) ||
					((true == GY_READ_ONCE(ptask->is_tcp_server)) || (true == GY_READ_ONCE(ptask->is_tcp_client))));

			if (only_imp_procs && !is_imp_proc) {
				return CB_OK;
			}
				 
			if (ptask->pext_stats) {
				ptask->pext_stats->update_stats();

				auto 			pcpustat = &ptask->pext_stats->cpu_mem_io_;
				uint64_t		rssmb = pcpustat->get_rss_mb();

				++nupd;

				curr_cpu_pct = pcpustat->usercpu_pct_hist[0] + pcpustat->syscpu_pct_hist[0];

				if (only_imp_procs == false) {
					if (is_imp_proc) {
						// We need to take the avg of last 2 periods
						last_pct_fl = (pcpustat->usercpu_pct_hist[0] + pcpustat->usercpu_pct_hist[1])/2 +
							 (pcpustat->syscpu_pct_hist[0] + pcpustat->syscpu_pct_hist[1])/2;
					}
					else {
						last_pct_fl = curr_cpu_pct;
					}	
						
					if ((last_pct_fl >= 0.1f) || (rssmb >= 5)) {
						TASK_CPU_MEM		util(ptask->aggr_task_id_.load(std::memory_order_relaxed), 
										ptask->task_pid, ptask->task_ppid, rssmb, ptask->task_comm, last_pct_fl);

						if (last_pct_fl >= 0.1f) {
							toptask.push(util);
						}

						if (rssmb >= 5) {
							toprss.push(util);
						}	
					}	

					if ((last_pct_fl >= 0.1f && ptask->task_pgid > 0) || (ptask->task_pgid == ptask->task_pid)) {

						auto cit = pg_cpumap.find(ptask->task_pgid);
						if (cit != pg_cpumap.end()) {
							auto && pcpu = cit->second;
							
							pcpu.tot_rss_mb_ += rssmb;
							pcpu.tot_cpupct_ += last_pct_fl;
							pcpu.ntasks_++;

							if (ptask->task_pgid == ptask->task_pid) {
								GY_STRNCPY(pcpu.pg_comm_, ptask->task_comm, sizeof(pcpu.child_comm_));
							}
						}	
						else {
							PG_TASK_CPU_PCT		cpupg;

							cpupg.aggr_task_id_	= ptask->aggr_task_id_.load(std::memory_order_relaxed);
							cpupg.pg_pid_		= ptask->task_pgid;
							cpupg.cpid_		= ptask->task_pid;
							cpupg.ntasks_ 		= 1;
							cpupg.tot_rss_mb_	= rssmb;
							cpupg.tot_cpupct_ 	= last_pct_fl;

							GY_STRNCPY(cpupg.child_comm_, ptask->task_comm, sizeof(cpupg.child_comm_));
								
							if (ptask->task_pgid == ptask->task_pid) {
								GY_STRNCPY(cpupg.pg_comm_, ptask->task_comm, sizeof(cpupg.child_comm_));
							}		

							pg_cpumap.emplace(ptask->task_pgid, std::move(cpupg));
							ntaskpg++;
						}	
					}	

					auto last_fork_tsec = GY_READ_ONCE(ptask->last_fork_tsec_);
					auto nchild_recent_forks = GY_READ_ONCE(ptask->nchild_recent_forks_);

					ptask->nchild_recent_forks_	= 0;

					if (nchild_recent_forks > 10 && last_fork_tsec > start_fork_tsec) {
						int		nfork_per_sec = nchild_recent_forks/(last_fork_tsec - start_fork_tsec);

						const auto compfork = [nfork_per_sec](const TASK_FORKS_SEC & rhs) noexcept
						{
							return nfork_per_sec > rhs.nfork_per_sec_;
						};	

						topforks.try_emplace(compfork, ptask->aggr_task_id_.load(std::memory_order_relaxed), ptask->task_pid, ptask->task_ppid, nfork_per_sec, ptask->task_comm);
					}	
				}	
				else if (nullptr == ptask->pext_stats->pdelay_stats_.get()) {
					// This is an imp task so create the delay stats
					ptask->pext_stats->pdelay_stats_ = std::make_unique<TASK_DELAY_STATS>(ptask, is_kubernetes);
					nnewdelays++;
				}	
					
				if (ptask->pext_stats->pdelay_stats_) {
					STRING_BUFFER<512>	tstrbuf;
					bool			is_issue = false, is_severe = false;
					auto			pext = ptask->pext_stats.get();
					auto			pdelay = pext->pdelay_stats_.get();
					uint64_t		cpu_delay_nsec = 0, vm_delay_nsec = 0, blkio_delay_nsec = 0;

					++ndelays;

					ret = pext->update_delay_stats(&delaystats, is_issue, is_severe, tstrbuf, curr_usec_clock);

					if (ret == 0) {
						cpu_delay_nsec 		= pdelay->cpu_delay_nsec_[0];
						total_cpu_delus		+= cpu_delay_nsec / GY_NSEC_PER_USEC;

						vm_delay_nsec		= pdelay->swapin_delay_nsec_[0] + pdelay->reclaim_delay_nsec_[0] + pdelay->thrashing_delay_nsec_[0]
										+ pdelay->compact_delay_nsec_[0];
						total_vm_delus		+= vm_delay_nsec / GY_NSEC_PER_USEC;

						blkio_delay_nsec 	= pdelay->blkio_delay_nsec_[0];
						total_io_delus		+= blkio_delay_nsec / GY_NSEC_PER_USEC;
					}

					nissues += int(is_issue);
					nsevere += int(is_severe);

					pext->serv_notify_miss_ <<= 1;

					if (send_server && (is_issue || all_aggr || 
						(((curr_cpu_pct >= 1) || (cpu_delay_nsec + vm_delay_nsec + blkio_delay_nsec >= 10 * GY_NSEC_PER_MSEC) || 
						(send_netstats && pext->last_sent_tcp_kbytes_ > 0)) && (nothertasks++ < 200)))) {

						uint64_t		agid = ptask->aggr_task_id_.load(std::memory_order_relaxed);

						try {
							auto 		[ait, success] = aggrnotmap.try_emplace(agid);
							auto &		aelem = ait->second;

							if (is_issue) {
								if (aelem.ntasks_issue_ < 2) {
									aelem.pid_arr_[aelem.ntasks_issue_] = ptask->task_pid;
								}
								aelem.ntasks_issue_++;

								aelem.curr_issue_		= pext->issue_hist_[0].issue;

								aelem.issue_bit_hist_ 		|= pext->issue_bit_hist_;
								aelem.severe_issue_bit_hist_ 	|= pext->severe_issue_bit_hist_;

								if (aelem.issue_string_len_ == 0) {
									aelem.issue_string_len_	= std::min<uint8_t>(tstrbuf.size(), sizeof(aelem.issue_string_) - 1);

									if (aelem.issue_string_len_) {
										std::memcpy(aelem.issue_string_, tstrbuf.buffer(), aelem.issue_string_len_);
										aelem.issue_string_[aelem.issue_string_len_] = 0;
										aelem.issue_string_len_++;
										aelem.set_padding_len();

										szstring += (aelem.get_elem_size() - sizeof(AGGR_TASK_STATE_NOTIFY));
									}	
								}
							}

							if (aelem.curr_state_ < pext->issue_hist_[0].state) {
								aelem.curr_state_ 		= pext->issue_hist_[0].state;
							}	

							if (send_netstats) {
								/*
								 * We delay sending network stats till every 15 sec to account for a standard count as the
								 * Network data is mostly calculated every 15 sec
								 */
								uint64_t	ntcp_bytes = GY_READ_ONCE(pext->ntcp_bytes_), ntcp_conn = GY_READ_ONCE(pext->ntcp_conn_);
								uint64_t	diffbytes = gy_diff_counter_safe(ntcp_bytes, pext->last_ntcp_bytes_);

								if (diffbytes > 0) {
									pext->last_sent_tcp_kbytes_	= GY_DOWN_KB(diffbytes);
									pext->last_sent_tcp_conns_	= gy_diff_counter_safe(ntcp_conn, pext->last_ntcp_conn_);

									aelem.tcp_kbytes_		+= pext->last_sent_tcp_kbytes_;
									aelem.tcp_conns_		+= pext->last_sent_tcp_conns_;
								}	
								else {
									pext->last_sent_tcp_kbytes_	= 0;
									pext->last_sent_tcp_conns_	= 0;
								}	
								
								pext->last_ntcp_bytes_ 		= ntcp_bytes;
								pext->last_ntcp_conn_		= ntcp_conn;
							}
							else {
								/*
								 * Commented the code below. This implies that the intermediate periods will
								 * report tcp_kbytes_ as 0 resulting in a see-saw Network Traffic chart
								 */
								/*aelem.tcp_kbytes_	+= pext->last_sent_tcp_kbytes_;*/
								/*aelem.tcp_conns_	+= pext->last_sent_tcp_conns_;*/
							}	

							float				avg_cpu_pct = curr_cpu_pct;
							int				npct = 1;

							static_assert(pcpustat->MAX_PROC_HIST_STATS <= MAX_TASK_STAT_HISTORY);

							// Add up the missed CPU pcts : We can add only upto MAX_PROC_HIST_STATS stats
							for (size_t b = 1; b < pcpustat->MAX_PROC_HIST_STATS; ++b) {
								if (pext->serv_notify_miss_[b]) {
									avg_cpu_pct 	+= pcpustat->usercpu_pct_hist[b] + pcpustat->syscpu_pct_hist[b];
									++npct;
								}	
								else {
									break;
								}	
							}

							aelem.total_cpu_pct_ 		+= avg_cpu_pct/npct;
							aelem.rss_mb_			+= rssmb;

							uint64_t	last_cpu_delay_nsec = cpu_delay_nsec, last_vm_delay_nsec = vm_delay_nsec, last_blkio_delay_nsec = blkio_delay_nsec;

							// Add up the missed task delays
							for (size_t b = 1; b < MAX_TASK_STAT_HISTORY; ++b) {
								if (pext->serv_notify_miss_[b]) {

									last_cpu_delay_nsec 	+= pdelay->cpu_delay_nsec_[b];
									last_vm_delay_nsec	+= pdelay->swapin_delay_nsec_[b] + pdelay->reclaim_delay_nsec_[b] + 
													pdelay->thrashing_delay_nsec_[b] + pdelay->compact_delay_nsec_[b];
									last_blkio_delay_nsec	+= pdelay->blkio_delay_nsec_[b];
								}	
								else {
									break;
								}	
							}

							aelem.cpu_delay_msec_ 		+= last_cpu_delay_nsec/GY_NSEC_PER_MSEC;
							aelem.vm_delay_msec_ 		+= last_vm_delay_nsec/GY_NSEC_PER_MSEC;
							aelem.blkio_delay_msec_ 	+= last_blkio_delay_nsec/GY_NSEC_PER_MSEC;

							aelem.ntasks_total_++;

							if (aelem.ntasks_total_ == 2) {
								aelem.pid_arr_[1] 	= ptask->task_pid;
							}	

							if (success == true) {
								aelem.aggr_task_id_	= agid;
								std::memcpy(aelem.onecomm_, ptask->task_comm, sizeof(aelem.onecomm_));

								aelem.pid_arr_[0]	= ptask->task_pid;

								if ((aggrnotmap.bytes_left() < 2 * sizeof(AGGR_TASK)) || (aggrnotmap.size() >= AGGR_TASK_STATE_NOTIFY::MAX_NUM_TASKS - 1)) {
									// Don't send any more procs
									send_server = false;
								}	
							}
							else if (nothertasks == lastnother + 1) {
								nothertasks--;
							}

							lastnother = nothertasks;
						}
						catch(...) {
							send_server = false;
						}	
					}	
					else {
						pext->serv_notify_miss_ |= 1;
						
						if (false == send_server) {	
							pext->last_ntcp_bytes_ 	= pext->ntcp_bytes_;
							pext->last_ntcp_conn_	= pext->ntcp_conn_;
						}
					}	
				}	
			}

			return CB_OK;
		};	

		ntotal = tasktable.walk_hash_table(lambda_cpu_task); 	

		if (only_imp_procs == false) {
			last_top_clock_usec	= curr_usec_clock;

			for (auto && cpuit : pg_cpumap) {
				if (cpuit.second.tot_cpupct_ >= 0.1f) {
					pg_toptask.push(std::move(cpuit.second));
				}	
			}	
		}
		
		last_ndelay_tasks = ndelays;	
		last_delay_stat_cusec = curr_usec_clock;
		
		GY_CC_BARRIER();

		last_nissue_tasks = nissues;
		
		if (nnewdelays) {
			last_new_delay_cusec = curr_usec_clock;
		}	
			
		bret = get_psi_stats();

		if (bret == false) {
			last_cpu_delayms_ 	= total_cpu_delus / GY_USEC_PER_MSEC;
			last_vm_delayms_	= total_vm_delus / GY_USEC_PER_MSEC;
			last_io_delayms_	= total_io_delus / GY_USEC_PER_MSEC;
		}	

		if (aggrnotmap.size() > 0 && servshr) {
			const size_t			maxsz = sizeof(comm::COMM_HEADER) + sizeof(comm::EVENT_NOTIFY) + 
								aggrnotmap.size() * sizeof(comm::AGGR_TASK_STATE_NOTIFY) + szstring;

			assert(szstring < comm::AGGR_TASK_STATE_NOTIFY::MAX_NUM_TASKS * AGGR_TASK_STATE_NOTIFY::get_max_elem_size());

			void				*palloc = ::malloc(maxsz + 256), *pendptr = (uint8_t *)palloc + maxsz;
			if (!palloc) {
				return {0, 0, 0};
			}	
			auto				pser = SERVER_COMM::get_singleton();

			COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
			EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1); 
			AGGR_TASK_STATE_NOTIFY		*pcurtask = reinterpret_cast<AGGR_TASK_STATE_NOTIFY *>(pnot + 1);
			bool				bret;
			size_t				nsz = sizeof(comm::COMM_HEADER) + sizeof(comm::EVENT_NOTIFY), esz;

			for (const auto & it : aggrnotmap) {

				*pcurtask = it.second.get_base();
				if (pcurtask->issue_string_len_) {
					std::memcpy((uint8_t *)pcurtask + sizeof(*pcurtask), it.second.issue_string_, pcurtask->issue_string_len_); // Limited to 256 as uint8_t
				}

				esz = pcurtask->get_elem_size();
				nsz += esz;
				nsent++;

				pcurtask = (AGGR_TASK_STATE_NOTIFY *)((uint8_t *)pcurtask + esz);

				if ((void *)pcurtask >= pendptr) {
					break;
				}	
			}	

			new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, nsz, pser->get_conn_magic());
			new (pnot) EVENT_NOTIFY(comm::NOTIFY_AGGR_TASK_STATE, nsent);	
			
			pser->send_server_data(EPOLL_IOVEC_ARR(2, false, phdr, phdr->get_act_len(), ::free, pser->gpadbuf, phdr->get_pad_len(), nullptr), 
							comm::CLI_TYPE_REQ_ONLY, COMM_EVENT_NOTIFY, servshr);
		}	
			
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Task Stats : Total Tasks %d : %d Tasks have issues (%d severe), Updated %d Task CPU Utilization, %d Task Delay Stats, %d new Delay Tasks, "
			"%d Tasks are Process Group Leaders, Sent %lu Aggr Task states to Madhava\n", 
			ntotal, nissues, nsevere, nupd, ndelays, nnewdelays, ntaskpg, nsent);

		return {nissues, nsevere, ntotal};
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while updating Task stats : %s\n", GY_GET_EXCEPT_STRING););
		return {0, 0, 0};
	);		
}	

int TASK_HANDLER::send_top_tasks(const std::shared_ptr<SERVER_CONNTRACK> & servshr) noexcept
{
	using namespace		comm;

	try {
		if (!init_table_done) {
			return 0;
		}	

		auto			pser = SERVER_COMM::get_singleton();
		auto			pconn1 = servshr.get();

		if (!pconn1) {
			return 1;
		}
	
		if (true) {

			CONDDECLARE(STRING_BUFFER<4096>		strbuf);
			NOTCONDDECLARE(STRING_BUFFER<1024>	strbuf);

			CONDEXEC(
				DEBUGEXECN(10, strbuf.appendfmt("Top %lu CPU Utilizing Processes : \n", comm::TASK_TOP_PROCS::TASK_MAX_TOP_N););
			);	
			
			static constexpr size_t		fixed_sz = comm::TASK_TOP_PROCS::get_max_elem_size() + sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY);

			void				*palloc = ::malloc(fixed_sz);
			if (!palloc) {
				return -1;
			}	

			GY_SCOPE_EXIT {
				if (palloc) {
					::free(palloc);
				}	
			};	

			COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
			EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>((uint8_t *)phdr + sizeof(COMM_HEADER)); 
			TASK_TOP_PROCS			*ptask = reinterpret_cast<TASK_TOP_PROCS *>((uint8_t *)pnot + sizeof(*pnot));
			TASK_TOP_PROCS::TOP_TASK	*ptopcputask = decltype(ptopcputask)(ptask + 1), *ptoprsstask = nullptr;
			TASK_TOP_PROCS::TOP_PG_TASK	*ptoppgtask = nullptr;
			TASK_TOP_PROCS::TOP_FORK_TASK	*ptopforktask = nullptr;
			uint32_t			nprocs = 0, npg_procs = 0, nrss = 0, nfork_procs = 0;
			bool				bret;

			new (ptask) TASK_TOP_PROCS();

			auto walk = [&](TASK_CPU_MEM & datanode, void *arg1, void *arg2) -> CB_RET_E 
			{ 
				datanode.update_comm_task(ptopcputask[nprocs]);

				++nprocs;

				CONDEXEC(
					DEBUGEXECN(10,
						strbuf.appendfmt("\t\t\t\t\t#%-2d : CPU %7.2f%% : RSS %8u MB : PPID %8d : PID %8d (%s)\n", 
							nprocs, datanode.cpupct_, datanode.rss_mb_, datanode.ppid_, datanode.pid_, datanode.comm_);
					);	
				);

				if (nprocs == comm::TASK_TOP_PROCS::TASK_MAX_TOP_N) {
					return CB_BREAK_LOOP;
				}

				return CB_OK;
			};

			toptask.walk_queue(walk, nullptr, nullptr, true /* sort_queue */, false /* heap_on_return */);
			
			GY_CC_BARRIER();

			ptoppgtask = decltype(ptoppgtask)(ptopcputask + nprocs);
			
			CONDEXEC(
				DEBUGEXECN(10, 
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "%.*s\n\n", strbuf.sizeint(), strbuf.buffer());
					strbuf.reset();
					strbuf.appendfmt("Top %lu CPU Utilizing Related Process Groups : \n", comm::TASK_TOP_PROCS::TASK_MAX_TOPPG_N);
				);
			);	

			auto walkpg = [&](PG_TASK_CPU_PCT & datanode, void *arg1, void *arg2) -> CB_RET_E 
			{ 
				datanode.update_comm_task(ptoppgtask[npg_procs]);

				++npg_procs;

				CONDEXEC(
					DEBUGEXECN(10,
						strbuf.appendfmt("\t\t\t\t\t#%-2d : CPU %7.2f%% : RSS %8u MB : #Tasks %4d :  Task Group %8d (%s) :%sSample Task %d (%s)\n", 
							npg_procs, datanode.tot_cpupct_, datanode.tot_rss_mb_, datanode.ntasks_, datanode.pg_pid_, datanode.pg_comm_,
							*datanode.pg_comm_ ? "\t\t" : "\t\t\t", datanode.cpid_, datanode.child_comm_);
					);
				);	

				if (npg_procs == comm::TASK_TOP_PROCS::TASK_MAX_TOP_N) {
					return CB_BREAK_LOOP;
				}

				return CB_OK;
			};

			pg_toptask.walk_queue(walkpg, nullptr, nullptr, true /* sort_queue */, false /* heap_on_return */);

			GY_CC_BARRIER();

			ptoprsstask = decltype(ptoprsstask)(ptoppgtask + npg_procs);

			CONDEXEC(
				DEBUGEXECN(10, 
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "%.*s\n\n", strbuf.sizeint(), strbuf.buffer());
					strbuf.reset();
				);
			);	

			strbuf.appendfmt("Top %lu Resident Memory Processes : \n", comm::TASK_TOP_PROCS::TASK_MAX_RSS_TOP_N);

			auto walkrss = [&](TASK_CPU_MEM & datanode, void *arg1, void *arg2) -> CB_RET_E 
			{ 
				datanode.update_comm_task(ptoprsstask[nrss]);

				++nrss;

				CONDEXEC(
					DEBUGEXECN(10,
						strbuf.appendfmt("\t\t\t\t\t#%-2d : RSS %8u MB : CPU %7.2f%% : PPID %8d : PID %8d (%s)\n", 
							nrss, datanode.rss_mb_, datanode.cpupct_, datanode.ppid_, datanode.pid_, datanode.comm_);
					);	
				);

				if (nrss == comm::TASK_TOP_PROCS::TASK_MAX_RSS_TOP_N) {
					return CB_BREAK_LOOP;
				}

				return CB_OK;
			};

			toprss.walk_queue(walkrss, nullptr, nullptr, true /* sort_queue */, false /* heap_on_return */);

			GY_CC_BARRIER();

			ptopforktask = decltype(ptopforktask)(ptoprsstask + nrss);

			CONDEXEC(
				DEBUGEXECN(10, 
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "%.*s\n\n", strbuf.sizeint(), strbuf.buffer());
					strbuf.reset();
				);
			);	

			strbuf.appendfmt("Top %lu Processes forking new child processes : \n", comm::TASK_TOP_PROCS::TASK_MAX_FORKS_TOP_N);
			
			auto walkf = [&](TASK_FORKS_SEC & datanode, void *arg1, void *arg2) mutable -> CB_RET_E 
			{ 
				datanode.update_comm_task(ptopforktask[nfork_procs]);

				nfork_procs++;

				strbuf.appendfmt("\t\t\t\t\t#%-2d : Forks/sec %5d : PPID %8d : PID %8d (%s)\n", 
						nfork_procs, datanode.nfork_per_sec_, datanode.ppid_, datanode.pid_, datanode.comm_);

				if (nfork_procs == comm::TASK_TOP_PROCS::TASK_MAX_FORKS_TOP_N) {
					return CB_BREAK_LOOP;
				}

				return CB_OK;
			};

			auto nf = topforks.walk_queue(walkf, nullptr, nullptr, true /* sort_queue */, false /* heap_on_return */);

			if (nf > 0) {
				// Check SYS_CPU_STATS
				auto pcpustat = SYS_CPU_STATS::get_singleton();

				if (pcpustat) {
					if ((pcpustat->issue_hist[0].issue == ISSUE_FORKS_HIGH) || (pcpustat->issue_hist[1].issue == ISSUE_FORKS_HIGH)) {
						strbuf.appendconst(
							"\n\t\t\t\tOS CPU Status indicates an Issue with too many Forks which is being caused by the above fork'ing processes...\n\n");	
					}	
				}	
				
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "%.*s\n\n", strbuf.sizeint(), strbuf.buffer());
			}	

			CONDEXEC(
				DEBUGEXECN(10,
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "%.*s\n\n", strbuf.sizeint(), strbuf.buffer());
					strbuf.reset();
				);
			);	

			GY_CC_BARRIER();

			size_t				nsz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + sizeof(TASK_TOP_PROCS) + 
								nprocs * sizeof(TASK_TOP_PROCS::TOP_TASK) + npg_procs * sizeof(TASK_TOP_PROCS::TOP_PG_TASK) +
								nrss * sizeof(TASK_TOP_PROCS::TOP_TASK) + nfork_procs * sizeof(TASK_TOP_PROCS::TOP_FORK_TASK);

			assert(nsz <= fixed_sz);
			
			if (nsz > fixed_sz) {
				return 1;
			}	

			new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, nsz, pser->get_conn_magic());

			new (pnot) EVENT_NOTIFY(NOTIFY_TASK_TOP_PROCS, 1);
			
			ptask->nprocs_			= nprocs;
			ptask->npg_procs_		= npg_procs;
			ptask->nrss_procs_		= nrss;
			ptask->nfork_procs_		= nfork_procs;
			ptask->ext_data_len_		= nsz - sizeof(COMM_HEADER) - sizeof(EVENT_NOTIFY) - sizeof(TASK_TOP_PROCS);

			palloc				= nullptr;	// So as to prevent ::free()

			bret = pser->send_server_data(EPOLL_IOVEC_ARR(2, false, phdr, phdr->get_act_len(), ::free, pser->gpadbuf, phdr->get_pad_len(), nullptr), 
							comm::CLI_TYPE_REQ_ONLY, COMM_EVENT_NOTIFY, servshr);
			if (bret == false) {
				return 1;
			}	

			CONDEXEC(
				DEBUGEXECN(15, INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, 
					"Sent %u Top Procs, %u Top Proc Groups, %u Top RSS Procs, %u Top Forking Procs to Madhava server.\n\n", nprocs, npg_procs, nrss, nfork_procs);
				);
			);
		}

		return 0;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while sending task info : %s\n", GY_GET_EXCEPT_STRING););
		return -1;
	);		
}	

int TASK_HANDLER::send_new_tasks() noexcept
{
	using namespace		comm;

	try {
		uint64_t			curr_clock = get_usec_clock();

		if (!init_table_done || ((last_new_sent_cusec > last_new_delay_cusec) && (curr_clock - last_new_sent_cusec < GY_USEC_PER_HOUR))) {
			return 0;
		}	

		/*
		 * Currently, we do not store individual tasks in madhava and so the following is commented out...
		 */
#if 0

		auto		pser = SERVER_COMM::get_singleton();
		auto		shrp = pser->get_server_conn(comm::CLI_TYPE_REQ_ONLY);
		auto		pconn1 = shrp.get();

		if (!pconn1) {
			return 1;
		}
	
		if (true) {

			/*
			 * We send in batches of max 32 (MAX_NUM_FULL_ADD) tasks in each iteration...
			 * Also we keep sending the tasks every 12 hours to account for changes in task state such as Listeners, tags, etc...
			 */
			static constexpr size_t		max_iter_tasks = comm::TASK_FULL_ADD::MAX_NUM_FULL_ADD;
			static constexpr size_t		fixed_sz = sizeof(gyeeta::comm::TASK_FULL_ADD) + 128 + 128 + 512;
			static constexpr size_t		max_buf_sz = fixed_sz * (max_iter_tasks + 1);

			void				*palloc = malloc(max_buf_sz);
			if (!palloc) {
				return -1;
			}	

			GY_SCOPE_EXIT {
				if (palloc) {
					::free(palloc);
				}	
			};	

			COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
			EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1); 
			TASK_FULL_ADD			*pcurtask = reinterpret_cast<TASK_FULL_ADD *>(pnot + 1);
			ssize_t				max_bytes = max_buf_sz, total_bytes = 0;
			uint32_t			nprocs = 0;
			bool				bret;

			auto lsend_task = [&, this, tcur = get_usec_time()](TASK_ELEM_TYPE *pdatanode, void *arg1) -> CB_RET_E
			{
				auto			ptask = pdatanode->get_cref().get();
				size_t			elem_bytes;
				bool			bret;

				if (!ptask || (false == ptask->is_task_server_store_valid(tcur))) {
					return CB_OK;
				}

				bret = ptask->save_task_full(pcurtask, max_bytes, elem_bytes, tcur);
				if (bret == false) {
					return CB_BREAK_LOOP;
				}

				nprocs++;
				total_bytes += elem_bytes;
				max_bytes -= elem_bytes;

				if ((max_bytes < (ssize_t)fixed_sz) || (nprocs >= max_iter_tasks))  {
					return CB_BREAK_LOOP;
				}	

				pcurtask = (decltype(pcurtask))((uint8_t *)pcurtask + elem_bytes);

				return CB_OK;
			};	

			tasktable.walk_hash_table(lsend_task); 	

			// Set last_new_sent_cusec only if all procs have been sent
			if (nprocs < max_iter_tasks) {
				last_new_sent_cusec = get_usec_clock();
			}	

			if (nprocs == 0) {
				return 0;
			}	

			size_t				nsz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + total_bytes;

			if (nsz > max_buf_sz) {
				return -1;
			}

			new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, nsz, pser->get_conn_magic());

			new (pnot) EVENT_NOTIFY(comm::NOTIFY_TASK_FULL_ADD, nprocs);
			
			palloc				= nullptr;	// So as to prevent ::free()

			bret = pser->send_server_data(EPOLL_IOVEC_ARR(2, false, phdr, phdr->get_act_len(), ::free, pser->gpadbuf, phdr->get_pad_len(), nullptr), 
							comm::CLI_TYPE_REQ_ONLY, COMM_EVENT_NOTIFY, shrp);
			if (bret == false) {
				return 1;
			}	

			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Sent %u Tasks Full Info to Madhava server.\n\n", nprocs);
		}
#endif		

		return 0;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while sending task info : %s\n", GY_GET_EXCEPT_STRING););
		return -1;
	);		
}	

// Currently not used...
int TASK_HANDLER::send_task_stats(uint64_t stats_interval_msec) noexcept
{
	using namespace		comm;

	try {
		size_t		ndelay = GY_READ_ONCE(last_ndelay_tasks);

		if (ndelay > MAX_NDELAY_SERVER_TASKS) { 
			ndelay = MAX_NDELAY_SERVER_TASKS;
		}

		if (!init_table_done || (0 == ndelay)) {
			return 0;
		}	

		auto		pser = SERVER_COMM::get_singleton();
		auto		shrp = pser->get_server_conn(comm::CLI_TYPE_REQ_ONLY);
		auto		pconn1 = shrp.get();

		if (!pconn1) {
			return 1;
		}
	
		if (true) {

			const size_t			max_buf_sz = sizeof(comm::COMM_HEADER) + sizeof(comm::EVENT_NOTIFY) + ndelay * sizeof(comm::TASK_HISTOGRAM);

			void				*palloc = malloc(max_buf_sz);
			if (!palloc) {
				return -1;
			}	

			GY_SCOPE_EXIT {
				if (palloc) {
					::free(palloc);
				}	
			};	

			COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
			EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>((uint8_t *)phdr + sizeof(COMM_HEADER)); 
			TASK_HISTOGRAM			*pcurtask = reinterpret_cast<TASK_HISTOGRAM *>((uint8_t *)pnot + sizeof(*pnot));
			ssize_t				max_bytes = max_buf_sz, total_bytes = 0;
			uint32_t			nprocs = 0;
			bool				bret;
			uint64_t			currclocknsec = get_nsec_clock(), currclocksec = currclocknsec/GY_NSEC_PER_SEC;
			uint64_t			currtimesec = time(nullptr);
			int64_t				diffsec = (int64_t)currtimesec - (int64_t)currclocksec;

			auto lsend_task = [&, this, currclocknsec, currtimesec, diffsec](TASK_ELEM_TYPE *pdatanode, void *arg1) -> CB_RET_E
			{
				auto			ptask = pdatanode->get_cref().get();
				size_t			elem_bytes;
				bool			bret;

				if (!ptask || (0 == ptask->last_server_tusec)) {
					return CB_OK;
				}

				bret = ptask->save_task_stats(pcurtask, currclocknsec, currtimesec, diffsec);
				if (bret == false) {
					return CB_OK;
				}

				nprocs++;
				pcurtask++;

				if (nprocs == ndelay) {
					return CB_BREAK_LOOP;
				}	

				return CB_OK;
			};	

			tasktable.walk_hash_table(lsend_task); 	

			if (nprocs == 0) {
				return 0;
			}	

			size_t				nsz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + nprocs * sizeof(TASK_HISTOGRAM);

			new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, nsz, pser->get_conn_magic());

			pnot->subtype_			= comm::NOTIFY_TASK_HISTOGRAM;
			pnot->nevents_			= nprocs;
			
			palloc				= nullptr;	// So as to prevent ::free()

			bret = pser->send_server_data(EPOLL_IOVEC_ARR(2, false, phdr, phdr->get_act_len(), ::free, pser->gpadbuf, phdr->get_pad_len(), nullptr), 
							comm::CLI_TYPE_REQ_ONLY, COMM_EVENT_NOTIFY, shrp);
			if (bret == false) {
				return 1;
			}	

			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Sent %u Task Stats to Madhava server.\n\n", nprocs);
		}

		return 0;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while sending task stats : %s\n", GY_GET_EXCEPT_STRING););
		return -1;
	);		
}	

int TASK_HANDLER::tasks_lazy_update(bool from_scheduler) noexcept
{
	try {
		if (from_scheduler && !init_table_done) {
			return 0;
		}	

		GY_NOMT_COLLECT_PROFILE(500, "Task Table Process Lazy state updation");

		uint64_t			tcur = get_usec_time();
		int				nupd = 0;
			
		auto 				lambda_upd_task = [&, tcur](TASK_ELEM_TYPE *pdatanode, void *arg1) -> CB_RET_E
		{
			auto			ptask = pdatanode->get_cref().get();
			int			ret;

			if (gy_unlikely(ptask == nullptr)) {
				return CB_OK;
			}	

			uint8_t			tsent = ptask->sent_aggr_server_.load(std::memory_order_relaxed);

			if (gy_unlikely(tsent != 3 && tsent)) {
				ptask->sent_aggr_server_.store(tsent + 1, std::memory_order_relaxed);
			}	

			if (false == ptask->task_needs_update()) {
				if (gy_likely(false == ptask->cgroups_changed.load(std::memory_order_relaxed))) {
					return CB_OK;
				}
				
				ptask->cgroups_changed.store(false, std::memory_order_relaxed);

				ptask->upd_task_cgroup_on_change(proc_dir_fd);

				return CB_OK;
			}	

			if ((labs((int64_t)tcur - (int64_t)ptask->get_task_start_time()) > 3L * (signed)GY_USEC_PER_SEC) || 
				(GY_READ_ONCE(ptask->is_tcp_server) || (GY_READ_ONCE(ptask->is_tcp_client)))) {

				ret = ptask->update_task_info(proc_dir_fd);

				if (ret == 0) {
					++nupd;
				}
			}
				 
			return CB_OK;
		};	

		tasktable.walk_hash_table(lambda_upd_task, nullptr); 	

		if (nupd) {
			CONDEXEC(DEBUGEXECN(1, INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN_UNDERLINE, "Updated %d task states by lazy update\n", nupd);););
		}	
		
		return 0;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while lazy updation of tasks : %s\n", GY_GET_EXCEPT_STRING););
		return -1;
	);		
}	

void TASK_HANDLER::get_task_pgtree(TASK_PGTREE_MAP & treemap) const
{
	auto lambda_inittree = [&](TASK_ELEM_TYPE *pdatanode, void *arg1) -> CB_RET_E
	{
		auto			ptask = pdatanode->get_cref().get();
		TASK_PGTREE_ELEM	elem;

		if ((ptask == nullptr) || (false == ptask->is_task_valid()) || (0 == ptask->task_pgid)) {
			return CB_OK;
		}
		
		elem.taskweak_ 		= ptask->weak_from_this();
		elem.pid_		= ptask->task_pid;
		elem.ppid_		= ptask->task_ppid;

		treemap.insert({ptask->task_pgid, std::move(elem)});		 

		return CB_OK;
	};	

	tasktable.walk_hash_table_const(lambda_inittree); 	
}

bool get_total_psi_stats(int dirfd, const char * filename, uint64_t & tusec) noexcept
{
	ssize_t				sret;
	const char			*ptmp;
	bool				bret;
	char				buf[512];

	sret = read_file_to_buffer(filename, buf, sizeof(buf) - 1, dirfd, false /* read_syscall_till_err */);

	if (sret > 0) {
		buf[sret] = 0;

		ptmp = strstr(buf, "total=");
		if (ptmp) {
			ptmp += GY_CONST_STRLEN("total=");
			
			bret = string_to_number(ptmp, tusec);

			if (bret) {
				return true;;
			}
		}
	}	

	return false;
}


void TASK_HANDLER::init_psi_fds() noexcept
{
	uint64_t			cpuusec, vmusec, iousec;
	int				dirfd;
	bool				bret1, bret2, bret3;

	dirfd = open("/proc/pressure", O_PATH | O_CLOEXEC);
	
	if (dirfd >= 0) {
		bret1 = get_total_psi_stats(dirfd, "./cpu", cpuusec);
		bret2 = get_total_psi_stats(dirfd, "./memory", vmusec);
		bret3 = get_total_psi_stats(dirfd, "./io", iousec);

		if (bret1 && bret2 && bret3) {
			INFOPRINT_OFFLOAD("Pressure Stall Statistics available on this host...\n");

			total_cpu_delayus_ 	= cpuusec;
			total_vm_delayus_	= vmusec;
			total_io_delayus_	= iousec;
			
			psi_dir_fd.set_fd(dirfd);
			return;
		}
	}	

	close(dirfd);
}	

bool TASK_HANDLER::get_psi_stats() noexcept
{
	if (!is_proc_pressure()) {
		return false;	
	}	

	uint64_t			total_cpu_delus = 0, total_vm_delus = 0, total_io_delus = 0;
	bool				bret;

	bret = get_total_psi_stats(psi_dir_fd.get(), "./cpu", total_cpu_delus);
	if (bret) {
		last_cpu_delayms_ 	= gy_diff_counter_safe(total_cpu_delus, total_cpu_delayus_) / GY_USEC_PER_MSEC;
		total_cpu_delayus_	= total_cpu_delus;
	}	
	else {
		last_cpu_delayms_	= 0;

		if (++npsi_err_ > 20) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Too many Pressure Stall Errors seen. Disabling PSI...\n");
			psi_dir_fd.close();
			return false;
		}	
	}	

	bret = get_total_psi_stats(psi_dir_fd.get(), "./memory", total_vm_delus);
	if (bret) {
		last_vm_delayms_ 	= gy_diff_counter_safe(total_vm_delus, total_vm_delayus_) / GY_USEC_PER_MSEC;
		total_vm_delayus_	= total_vm_delus;
	}	
	else {
		last_vm_delayms_	= 0;

		if (++npsi_err_ > 20) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Too many Pressure Stall Errors seen. Disabling PSI...\n");
			psi_dir_fd.close();
			return false;
		}	
	}	

	bret = get_total_psi_stats(psi_dir_fd.get(), "./io", total_io_delus);
	if (bret) {
		last_io_delayms_ 	= gy_diff_counter_safe(total_io_delus, total_io_delayus_) / GY_USEC_PER_MSEC;
		total_io_delayus_	= total_io_delus;
	}	
	else {
		last_io_delayms_	= 0;

		if (++npsi_err_ > 20) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Too many Pressure Stall Errors seen. Disabling PSI...\n");
			psi_dir_fd.close();
			return false;
		}	
	}	

	return true;
}	


void TASK_HANDLER::reset_server_stats() noexcept
{
	auto lp = [this](TASK_ELEM_TYPE *pdatanode, void *arg1) -> CB_RET_E
	{
		auto			ptask = pdatanode->get_cref().get();

		if ((ptask == nullptr) || (false == ptask->is_task_valid())) {
			return CB_OK;
		}
		
		ptask->last_server_tusec 	= 0;
		ptask->sent_aggr_server_.store(0, std::memory_order_relaxed);

		return CB_OK;
	};	

	reset_glob_aggr.store(true, std::memory_order_relaxed);

	tasktable.walk_hash_table_const(lp); 	
}

/*
 * Periodically verify that the tasktable and /proc are in sync. It could go out of sync in case NL Messages are dropped.
 * Also save new aggr objects to be sent to server
 */
int TASK_HANDLER::tasks_verify_from_proc(size_t & total_cmdlen, AggrTaskStackMap *paggrmap) noexcept
{
	try {
		GY_NOMT_COLLECT_PROFILE(100, "Task Table Process Verification and Aggr server stats");

		using Stackmap 				= INLINE_STACK_HASH_MAP<pid_t, bool, 40 * 1024, GY_JHASHER<pid_t>>;

		Stackmap				pidmap;

		assert(gy_get_thread_local().get_thread_stack_freespace() > 100 * 1024);

		int					ndel = 0, nadd = 0;
			
		DIR					*pdir = nullptr; 
		struct dirent				*pdent;
		char					*pfile, *pstr1;
		int					ret;
		pid_t					pidval;

		pdir = opendir("/proc");
		if (!pdir) {
			PERRORPRINT_OFFLOAD("Could not open /proc dir for populating task table");
			return -1;
		}

		GY_SCOPE_EXIT {
			if (pdir) {
				closedir(pdir);
			}	
		};

		while ((pdent = readdir(pdir)) != nullptr) {

			pstr1 = nullptr;
			
			pfile = pdent->d_name;	
			
			if (!gy_isdigit_ascii(*pfile)) {
				continue;
			}

			if (string_to_number(pfile, pidval, &pstr1, 10)) {
				if (pstr1 && *pstr1) {
					continue;
				}	

				pidmap.insert({pidval, false});
			}	
			else {
				continue;
			}	
		}

		closedir(pdir);
		pdir = nullptr;

		uint64_t			tcur = get_usec_time();
		RCU_LOCK_SLOW			slowlock;

		auto lambda_scan_task = [&, paggrmap, tcur, tcursec = tcur/GY_USEC_PER_SEC](TASK_ELEM_TYPE *pdatanode, void *arg1) -> CB_RET_E
		{
			auto			ptask = pdatanode->get_cref().get();

			if (ptask == nullptr) {
				ndel++;
				return CB_DELETE_ELEM;
			}
		
			auto it = pidmap.find(ptask->task_pid);
			if (it != pidmap.end()) {
				it->second = true;
			}
			else {	
				// We need to check if the task was spawned a long time back and if so, delete

				if ((int64_t)tcur - (int64_t)ptask->get_task_start_time() > 3 * (int64_t)GY_USEC_PER_SEC) {

					DEBUGEXECN(5, 
						INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Task PID %d already exited but task table contains entry. Deleting...\n",
							ptask->task_pid);
					);

					TASK_KILL_INFO		kone;

					ptask->set_task_exited(0, kone);
					ndel++;	

					return CB_DELETE_ELEM;
				}						
			}		

			if (true == ptask->cgroups_updated.load(std::memory_order_acquire)) {
				// Update cgroup timestamps
				if (ptask->cg_cpu_shr) {
					ptask->cg_cpu_shr->set_cgroup_updated(tcursec);
					ptask->is_throttled_cgroup = ptask->cg_cpu_shr->is_cpu_throttled_cgroup();
					ptask->is_cpu_cgroup_mini_procs = (ptask->cg_cpu_shr->get_approx_task_count() <= 5);
				}
				else if (ptask->cg_2_shr) {
					ptask->cg_2_shr->set_cgroup_updated(tcursec);
					ptask->is_throttled_cgroup = ptask->cg_2_shr->is_cpu_throttled_cgroup();
					ptask->is_cpu_cgroup_mini_procs = (ptask->cg_2_shr->get_approx_task_count() <= 5);
				}

				if (ptask->cg_cpuset_shr) {
					ptask->cg_cpuset_shr->set_cgroup_updated(tcursec);
				}	

				if (ptask->cg_memory_shr) {
					ptask->cg_memory_shr->set_cgroup_updated(tcursec);
					ptask->is_mem_cgroup_limited = ptask->cg_memory_shr->is_max_memory_limited();
				}	
				else if (ptask->cg_2_shr) {
					ptask->cg_2_shr->set_cgroup_updated(tcursec);
					ptask->is_mem_cgroup_limited = ptask->cg_2_shr->is_max_memory_limited();
				}
			}	

			uint64_t		agid = ptask->aggr_task_id_.load(std::memory_order_relaxed);

			if (agid && paggrmap && paggrmap->size() < comm::TASK_AGGR_NOTIFY::MAX_NUM_AGGR_TASK && ptask->sent_aggr_server_.load(std::memory_order_relaxed) == 0) {

				TASK_DELAY_STATS	*pdelay_stats = nullptr;
				uint64_t		related_listen_id = 0;
				uint8_t			tag_len = 0;
				bool			toupd = false;					

				if (ptask->pext_stats && ptask->pext_stats->pdelay_stats_) {
					pdelay_stats = ptask->pext_stats->pdelay_stats_.get();
				}	

				if (0 != ptask->ntcp_listeners.load(std::memory_order_relaxed)) {
					related_listen_id = int64_t(ptask->related_listen_.load(std::memory_order_relaxed).get());
				}
				
				if (pdelay_stats) {
					tag_len = GY_READ_ONCE(pdelay_stats->tag_len_);

					if (tag_len >= sizeof(pdelay_stats->tagbuf_)) {
						tag_len = 0;

						pdelay_stats->tag_len_ = 0;
					}	
				}	

				ptask->sent_aggr_server_.store(1, std::memory_order_relaxed);

				try {
					// Check and add task aggr id in global map
					auto [ait, success] = glob_aggr_tasks_map_.try_emplace(agid, agid, ptask->task_comm, related_listen_id,
							0 /* calc cmdline_len_ */, tag_len, ptask->task_realuid, ptask->task_realgid,
							bool(ptask->is_high_cap), bool(ptask->is_throttled_cgroup), bool(ptask->is_mem_cgroup_limited), 
							ptask->task_rt_priority > 0 && ptask->task_sched_policy > 0, bool(ptask->is_container_proc), 
							ptask->task_cmdline, pdelay_stats->tagbuf_);

					auto & caggr = ait->second.caggr_;
					
					if (!success && ((related_listen_id != caggr.related_listen_id_ && related_listen_id) || 
							(!caggr.is_high_cap_ && ptask->is_high_cap) || (!caggr.is_cpu_cgroup_throttled_ && ptask->is_throttled_cgroup) ||
							(!caggr.is_mem_cgroup_limited_ && ptask->is_mem_cgroup_limited) || (!caggr.is_container_proc_ && ptask->is_container_proc) ||
							(tag_len && (0 != std::memcmp(ait->second.tagbuf_, pdelay_stats->tagbuf_, tag_len))))) {

						if (related_listen_id) {
							caggr.related_listen_id_ = related_listen_id;
						}

						if (tag_len && tag_len < sizeof(AGGR_TASK::tagbuf_)) {
							caggr.tag_len_ = tag_len + 1;
							std::memcpy(ait->second.tagbuf_, pdelay_stats->tagbuf_, tag_len);
							ait->second.tagbuf_[tag_len] = 0;

							caggr.set_padding_len();
						}

						caggr.is_high_cap_ 		|= ptask->is_high_cap;
						caggr.is_cpu_cgroup_throttled_ 	|= ptask->is_throttled_cgroup;
						caggr.is_mem_cgroup_limited_ 	|= ptask->is_mem_cgroup_limited;
						caggr.is_rt_proc_ 		|= (ptask->task_rt_priority > 0 && ptask->task_sched_policy > 0);
						caggr.is_container_proc_ 	|= ptask->is_container_proc;

						toupd = true;
					}	

					if (success || toupd) {

						auto [mit, msuccess] = paggrmap->try_emplace(agid, ait->second, agid);

						if (msuccess) {
							total_cmdlen += caggr.cmdline_len_ + caggr.tag_len_ + caggr.padding_len_;
						}	
						else if (toupd) {

							if (mit->second.caggr_.tag_len_ < caggr.tag_len_) {
								total_cmdlen += caggr.tag_len_ - mit->second.caggr_.tag_len_;
							}

							mit->second.update_task(ait->second, agid); 
						}	
					}	

					// Reuse ait->second.caggr_.aggr_task_id_ with last update time for subsequent cleanup
					ait->second.caggr_.aggr_task_id_ = tcur;
				}
				catch(...) {
					ptask->sent_aggr_server_.store(0, std::memory_order_relaxed);
				}	
			}

			return CB_OK;
		};	

		size_t 			ntasks_cur = tasktable.walk_hash_table(lambda_scan_task); 	
		uint64_t		currtusec = get_usec_time();
		pid_t			tpid1;
		
		// Now scan the tasks in pidmap which are not yet added. If the task exited in the interim, the add will fail anyway
		
		for (const auto & it : pidmap) {
			if (it.second == false) {

				tpid1 = it.first;

				if (true == tasktable.lookup_single_elem(tpid1, get_pid_hash(tpid1))) {
					continue;
				}

				/*
				 * Check if Task just started. If so, allow Main thread to add it first.
				 * Also ignore if Zombie task
				 */
				uint32_t 	ttask_flags, ttask_rt_priority, ttask_sched_policy; 
				uint64_t 	tstarttimeusec; 
				int64_t 	ttask_priority, ttask_nice; 
				pid_t		ppid1;
				char		ttask_state;
				int		tret;
				
				tret = get_proc_stat(tpid1, ppid1, ttask_state, ttask_flags, tstarttimeusec, ttask_priority, ttask_nice, 
					ttask_rt_priority, ttask_sched_policy);

				if (tret == 0 && tstarttimeusec < currtusec - 100 * GY_USEC_PER_MSEC && ttask_state != 'Z') { 
					DEBUGEXECN(5, 
						INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, 
							"Task PID %d present in /proc but missing from task table. Adding...\n", tpid1);
					);
				
					nadd++;

					if (ppid1 == 1) {
						ppid1 = 0;
					}	
					task_add(tpid1, ppid1, false /* add_cgroup */, false /* from_main_thread */);
				}
			}	
		}	

		INFOPRINT_OFFLOAD("Current PIDs in Task Table is %lu : New PIDs added by scan %d : deleted %d : Total Aggr Tasks %lu\n", ntasks_cur, nadd, ndel, glob_aggr_tasks_map_.size());
			
	 	return 0;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Caught Exception while checking task list with /proc : %s\n", GY_GET_EXCEPT_STRING););
		return -1;
	);
}	

int TASK_HANDLER::tasks_send_aggr(AggrTaskStackMap & aggmap, void *pconnshr, size_t total_cmdlen) noexcept
{
	try {
		if (!init_table_done) {
			return 0;
		}	

		auto					pser = SERVER_COMM::get_singleton();
		const std::shared_ptr<SERVER_CONNTRACK>	& shrp = *(std::shared_ptr<SERVER_CONNTRACK> *)pconnshr;
		SERVER_CONNTRACK			*pconn = shrp.get();	

		if (!pconn || 0 == aggmap.size()) {
			return 0;
		}	

		const size_t				max_buf_sz = sizeof(comm::COMM_HEADER) + sizeof(comm::EVENT_NOTIFY) + aggmap.size() * sizeof(comm::TASK_AGGR_NOTIFY) +
								 total_cmdlen + comm::TASK_AGGR_NOTIFY::get_max_elem_size();

		void					*palloc = ::malloc(max_buf_sz);
		if (!palloc) {
			return -1;
		}	

		COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
		EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1); 
		TASK_AGGR_NOTIFY		*pcurtask = reinterpret_cast<TASK_AGGR_NOTIFY *>(pnot + 1);
		uint8_t				*pendptr = (uint8_t *)palloc + max_buf_sz;
		bool				bret;
		size_t				nsz = sizeof(comm::COMM_HEADER) + sizeof(comm::EVENT_NOTIFY), esz, nelem = 0;

		for (auto && it : aggmap) {
			*pcurtask = it.second.caggr_;

			std::memcpy((uint8_t *)pcurtask + sizeof(*pcurtask), it.second.cmdline_, pcurtask->cmdline_len_);

			if (pcurtask->tag_len_) {	
				std::memcpy((uint8_t *)pcurtask + sizeof(*pcurtask) + pcurtask->cmdline_len_, it.second.tagbuf_, pcurtask->tag_len_);
			}

			esz = pcurtask->get_elem_size();
			nsz += esz;

			pcurtask = (TASK_AGGR_NOTIFY *)((uint8_t *)pcurtask + esz);

			nelem++;

			if ((uint8_t *)pcurtask + comm::TASK_AGGR_NOTIFY::get_max_elem_size() >= pendptr) {
				break;
			}	
		}	

		new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, nsz, pser->get_conn_magic());
		new (pnot) EVENT_NOTIFY(comm::NOTIFY_TASK_AGGR, nelem);	
		
		bret = pser->send_server_data(EPOLL_IOVEC_ARR(2, false, phdr, phdr->get_act_len(), ::free, pser->gpadbuf, phdr->get_pad_len(), nullptr), 
						comm::CLI_TYPE_REQ_ONLY, COMM_EVENT_NOTIFY, shrp);

		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Sent %lu Aggregated Tasks to Madhava server\n\n", aggmap.size());
	
		return 0;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while sending Aggregated Tasks to Madhava : %s\n", GY_GET_EXCEPT_STRING););
		return -1;
	);		
}

int TASK_HANDLER::send_ping_aggr() noexcept
{
	try {
		if (!init_table_done) {
			return 0;
		}	

		auto					pser = SERVER_COMM::get_singleton();
		std::shared_ptr<SERVER_CONNTRACK>	shrp = pser->get_server_conn(comm::CLI_TYPE_REQ_ONLY);
		SERVER_CONNTRACK			*pconn = shrp.get();	

		if (!pconn) {
			if (glob_aggr_tasks_map_.size() < 1024) {
				return 0;
			}
		}	

		using PING_MAP				= GY_STACK_HASH_MAP<uint64_t, PING_TASK_AGGR, 200 * 1024, GY_JHASHER<uint64_t>>;
		using Arena				= PING_MAP::allocator_type::arena_type;

		Arena					arena;
		PING_MAP 				pingmap(arena), removemap(arena);
		
		auto lp = [&, this, min_listen_tusec = get_usec_time() - PING_TASK_INTERVAL_MSEC * 1000 - GY_USEC_PER_SEC](TASK_ELEM_TYPE *pdatanode, void *arg1) -> CB_RET_E
		{
			auto			ptask = pdatanode->get_cref().get();

			if ((ptask == nullptr) || (false == ptask->is_task_valid()) || (0 == ptask->sent_aggr_server_.load(std::memory_order_relaxed))) {
				return CB_OK;
			}
			
			uint64_t		agid = ptask->aggr_task_id_.load(std::memory_order_relaxed);
			auto [it, success]	= pingmap.try_emplace(agid, agid);

			if ((it->second.related_listen_id_ == 0) && (GY_READ_ONCE(ptask->last_listen_tusec_) > min_listen_tusec)) {
				it->second.related_listen_id_ 	= int64_t(ptask->related_listen_.load(std::memory_order_relaxed).get());
			}

			it->second.ntasks_++;
			it->second.keep_task_ = true;

			return CB_OK;
		};	

		tasktable.walk_hash_table_const(lp); 	

		auto			tcur = get_usec_time(), tremoveusec = tcur - (2 * VERIFY_PROC_INTERVAL_MSEC/1000 + 10) * GY_USEC_PER_SEC /* -60 sec */;

		for (auto ait = glob_aggr_tasks_map_.begin(); ait != glob_aggr_tasks_map_.end();) {
			auto sit = pingmap.find(ait->first);

			if (sit == pingmap.end()) {
				auto lastusec = ait->second.caggr_.aggr_task_id_;

				if (lastusec < tremoveusec) {
					auto [it, success]	= removemap.try_emplace(ait->first, ait->first);

					it->second.ntasks_++;
					it->second.keep_task_	= false;

					if (lastusec < tcur - 2 * PING_TASK_INTERVAL_MSEC * 1000 - GY_USEC_PER_SEC) {
						ait = glob_aggr_tasks_map_.erase(ait);
						continue;
					}	
				}	
			}	
			else {
				ait->second.caggr_.aggr_task_id_ = tcur;
			}	

			++ait;
		}	

		if (!pconn || ((pingmap.size() + removemap.size()) == 0)) {
			return 0;
		}	

		const size_t			totsz = sizeof(comm::COMM_HEADER) + sizeof(comm::EVENT_NOTIFY) + (pingmap.size() + removemap.size()) * sizeof(comm::PING_TASK_AGGR);

		void				*palloc = ::malloc(totsz);
		if (!palloc) {
			return -1;
		}	

		GY_SCOPE_EXIT {
			if (palloc) {
				::free(palloc);
			}	
		};	

		COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
		EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1); 
		PING_TASK_AGGR			*pcurtask = reinterpret_cast<PING_TASK_AGGR *>(pnot + 1);
		bool				bret;

		for (const auto & it : pingmap) {
			*pcurtask++ = it.second;
		}	

		for (const auto & it : removemap) {
			*pcurtask++ = it.second;
		}	

		new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, totsz, pser->get_conn_magic());

		new (pnot) EVENT_NOTIFY(comm::NOTIFY_PING_TASK_AGGR, pingmap.size() + removemap.size());

		palloc			= nullptr;	// So as to prevent ::free()

		bret = pser->send_server_data(EPOLL_IOVEC_ARR(2, false, phdr, phdr->get_act_len(), ::free, pser->gpadbuf, phdr->get_pad_len(), nullptr), 
						comm::CLI_TYPE_REQ_ONLY, COMM_EVENT_NOTIFY, shrp);
		if (bret == false) {
			return 1;
		}	

		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Aggregated Tasks : Sent %lu Pings and %lu Remove Pings to Madhava server.\n\n", pingmap.size(), removemap.size());
	
		return 0;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while sending Pings of Aggregated Tasks to Madhava : %s\n", GY_GET_EXCEPT_STRING););
		return -1;
	);		
}

int TASK_HANDLER::send_hist_stats() noexcept
{
	try {
		if (!init_table_done) {
			return 0;
		}	

		auto					pser = SERVER_COMM::get_singleton();
		std::shared_ptr<SERVER_CONNTRACK>	shrp = pser->get_server_conn(comm::CLI_TYPE_REQ_ONLY);
		SERVER_CONNTRACK			*pconn = shrp.get();	

		if (!pconn) {
			return 0;
		}	

		using STAT_MAP				= INLINE_STACK_HASH_MAP<uint64_t, AGGR_TASK_HIST_STATS, 
									AGGR_TASK_HIST_STATS::MAX_NUM_TASKS * sizeof(AGGR_TASK_HIST_STATS) + 2048, GY_JHASHER<uint64_t>>;
		STAT_MAP 				statmap(128);
		
		auto lp = [&, this](TASK_ELEM_TYPE *pdatanode, void *arg1) -> CB_RET_E
		{
			auto			ptask = pdatanode->get_cref().get();

			if ((ptask == nullptr) || (false == ptask->is_task_valid()) || (0 == ptask->sent_aggr_server_.load(std::memory_order_relaxed)) || 
				!ptask->pext_stats || !ptask->pext_stats->pdelay_stats_) {
				return CB_OK;
			}
			
			auto 			*pdelay_stats = ptask->pext_stats->pdelay_stats_.get();

			uint64_t		agid = ptask->aggr_task_id_.load(std::memory_order_relaxed);
			auto [it, success]	= statmap.try_emplace(agid, agid, ptask->starttimeusec);

			auto & 			stats = it->second;

			HIST_DATA 		hist_data[] {95};
			size_t			total_val;
			int			max_val;

			if (stats.starttimeusec_ > ptask->starttimeusec) {
				stats.starttimeusec_ = ptask->starttimeusec;
			}

			stats.nprocs_++;
			stats.nthreads_ += ptask->pext_stats->cpu_mem_io_.num_threads;

			ptask->pext_stats->cpu_pct_histogram_.get_percentiles(hist_data, GY_ARRAY_SIZE(hist_data), total_val, max_val);
			stats.p95_cpu_pct_ += hist_data[0].data_value;
			
			pdelay_stats->cpu_delay_histogram_.get_percentiles(hist_data, GY_ARRAY_SIZE(hist_data), total_val, max_val);
			stats.p95_cpu_delay_ms_ += hist_data[0].data_value;

			pdelay_stats->blkio_delay_histogram_.get_percentiles(hist_data, GY_ARRAY_SIZE(hist_data), total_val, max_val);
			stats.p95_blkio_delay_ms_ += hist_data[0].data_value;

			if (stats.max_cores_allowed_ < ptask->ncpus_allowed) {
				stats.max_cores_allowed_ = ptask->ncpus_allowed;
			}	
			
			if (ptask->cgroups_updated.load(std::memory_order_acquire) == true) {
				
				if (ptask->is_throttled_cgroup) {
					if (ptask->cg_cpu_shr) {
						stats.cpu_cg_pct_limit_ = ptask->cg_cpu_shr->stats.cfs_bw_pct;
					}
					else if (ptask->cg_2_shr) {
						stats.cpu_cg_pct_limit_ = ptask->cg_2_shr->stats.cfs_bw_pct;
					}	
				}	

				if (ptask->cg_memory_shr) {
					uint8_t 		pct = ptask->cg_memory_shr->get_rss_pct_used();

					if (stats.max_mem_cg_pct_rss_ < pct) {
						stats.max_mem_cg_pct_rss_ = pct;
					}	
				}	
				else if (ptask->cg_2_shr) {
					uint8_t 		pct = ptask->cg_2_shr->get_rss_pct_used();

					if (stats.max_mem_cg_pct_rss_ < pct) {
						stats.max_mem_cg_pct_rss_ = pct;
					}	
				}	
			}

			if (success && statmap.size() >= AGGR_TASK_HIST_STATS::MAX_NUM_TASKS - 1) {
				return CB_BREAK_LOOP;
			}	

			return CB_OK;
		};	

		tasktable.walk_hash_table_const(lp); 	

		if (!pconn || (0 == statmap.size())) {
			return 0;
		}	

		const size_t			totsz = sizeof(comm::COMM_HEADER) + sizeof(comm::EVENT_NOTIFY) + statmap.size() * sizeof(comm::AGGR_TASK_HIST_STATS);

		void				*palloc = ::malloc(totsz);
		if (!palloc) {
			return -1;
		}	

		GY_SCOPE_EXIT {
			if (palloc) {
				::free(palloc);
			}	
		};	

		COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
		EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1); 
		AGGR_TASK_HIST_STATS		*pcurtask = reinterpret_cast<AGGR_TASK_HIST_STATS *>(pnot + 1);
		bool				bret;

		for (const auto & it : statmap) {
			*pcurtask++ = it.second;
		}	

		new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, totsz, pser->get_conn_magic());

		new (pnot) EVENT_NOTIFY(comm::NOTIFY_AGGR_TASK_HIST_STATS, statmap.size());

		palloc			= nullptr;	// So as to prevent ::free()

		bret = pser->send_server_data(EPOLL_IOVEC_ARR(2, false, phdr, phdr->get_act_len(), ::free, pser->gpadbuf, phdr->get_pad_len(), nullptr), 
						comm::CLI_TYPE_REQ_ONLY, COMM_EVENT_NOTIFY, shrp);
		if (bret == false) {
			return 1;
		}	

		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Aggregated Tasks : Sent %lu Histogram Stats to Madhava server.\n\n", statmap.size());
	
		return 0;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while sending Hist Stats of Aggregated Tasks to Madhava : %s\n", GY_GET_EXCEPT_STRING););
		return -1;
	);		
}

int TASK_HANDLER::sockconn_send(int nl_sock) noexcept
{
	struct sockaddr_nl 		addr;
	int				ret;
	
	std::memset(&addr, 0, sizeof(addr));

	addr.nl_pid = getpid();
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = CN_IDX_PROC;

	if (bind(nl_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		PERRORPRINT("Failed to bind nl connector socket");
		return -1;
	}

	enum proc_cn_mcast_op 		op;
	struct nlmsghdr 		nlmsghdr;
	struct cn_msg 			cn_msg;
	struct iovec 			iov[3];

	std::memset(&nlmsghdr, 0, sizeof(nlmsghdr));

	nlmsghdr.nlmsg_len 	= NLMSG_LENGTH(sizeof(cn_msg) + sizeof(op));
	nlmsghdr.nlmsg_pid 	= getpid();
	nlmsghdr.nlmsg_type 	= NLMSG_DONE;

	iov[0].iov_base 	= &nlmsghdr;
	iov[0].iov_len 		= sizeof(nlmsghdr);

	std::memset(&cn_msg, 0, sizeof(cn_msg));

	cn_msg.id.idx 		= CN_IDX_PROC;
	cn_msg.id.val 		= CN_VAL_PROC;
	cn_msg.len 		= sizeof(enum proc_cn_mcast_op);

	iov[1].iov_base 	= &cn_msg;
	iov[1].iov_len 		= sizeof(cn_msg);

	op 			= PROC_CN_MCAST_LISTEN;

	iov[2].iov_base 	= &op;
	iov[2].iov_len 		= sizeof(op);

	ret = writev(nl_sock, iov, 3);
	if (ret < 0) {
		PERRORPRINT("Could not send nl connector listen command");
		return -1;
	}	

	return 0;
}

int TASK_HANDLER::parse_conn_msg(GY_PROC_EVENT *proc_ev) noexcept
{
	int			ret;

	switch (proc_ev->what) {
		case PROC_EVENT_NONE:
			break;

		case PROC_EVENT_FORK :
			if (proc_ev->event_data.fork.child_pid != proc_ev->event_data.fork.child_tgid) {
				// Thread spawn ignored
				break;
			}	
			
			ret = task_add(proc_ev->event_data.fork.child_tgid, proc_ev->event_data.fork.parent_tgid);			

			break;

		case PROC_EVENT_EXEC :
			ret = task_exec(proc_ev->event_data.exec.process_tgid);			

			break;

		case PROC_EVENT_UID:

			ret = task_uid_gid_change(proc_ev->event_data.id.process_tgid, proc_ev->event_data.id.r.ruid, proc_ev->event_data.id.e.euid, true);
			break;

		case PROC_EVENT_GID:

			ret = task_uid_gid_change(proc_ev->event_data.id.process_tgid, proc_ev->event_data.id.r.ruid, proc_ev->event_data.id.e.euid, false);
			break;

		case PROC_EVENT_EXIT:

			if (proc_ev->event_data.exit.process_pid != proc_ev->event_data.exit.process_tgid) {
				// Thread exit
				break;
			}	

			ret = task_exit(proc_ev->event_data.exit.process_tgid, proc_ev->event_data.exit.exit_code);
			break;

		case PROC_EVENT_COMM:
			break;
		
		case PROC_EVENT_COREDUMP:
			break;
			
		case PROC_EVENT_PTRACE:

			if (proc_ev->event_data.ptrace.process_pid == proc_ev->event_data.ptrace.process_tgid) {
				if (proc_ev->event_data.ptrace.tracer_tgid > 0) {
					// New ptrace
					ret = task_ptrace(proc_ev->event_data.ptrace.process_tgid, proc_ev->event_data.ptrace.tracer_tgid, true);
				}	
				else {
					ret = task_ptrace(proc_ev->event_data.ptrace.process_tgid, 0, false);
				}	
			}
			break;

		case PROC_EVENT_SID:
			if (proc_ev->event_data.sid.process_pid == proc_ev->event_data.sid.process_tgid) {
				ret = task_sid_change(proc_ev->event_data.sid.process_tgid);
			}

			break;

		default:
			CONDEXEC(DEBUGEXECN(15, INFOPRINT_OFFLOAD("unhandled proc event 0x%08x\n", proc_ev->what);););
			break;
	}

	return 0;
}	

int TASK_HANDLER::nltask(bool & init_done, int nerrors) noexcept
{
	int					inet_ret = -1;
	 
	try {
		static constexpr int		GY_NL_BUFFER_SIZE = 16 * 1024;
		int 				nl_sock = 0, numbytes = 0, rtalen = 0, ret;
		struct nlmsghdr 		*nlh;
		uint8_t 			*pbuf = nullptr;
		struct inet_diag_msg 		*pdiag_msg;
		struct pollfd 			pfds[1] = {};
		struct sockaddr_nl 		addr;

		init_done = false;

		if (nerrors == 0) {
			init_task_list();
		}	

		pbuf = new (std::nothrow) uint8_t[GY_NL_BUFFER_SIZE];
		if (!pbuf) {
			PERRORPRINT("Failed to allocate memory for task netlink handler");
			return -1;
		}	

		GY_SCOPE_EXIT { delete [] pbuf; };

		struct iovec iov = {
			.iov_base	= pbuf,
			.iov_len	= GY_NL_BUFFER_SIZE,
		};

		struct msghdr msg = {
			.msg_name	= &addr,
			.msg_namelen	= sizeof(struct sockaddr_nl),
			.msg_iov	= &iov,
			.msg_iovlen	= 1,
			.msg_control	= nullptr,
			.msg_controllen	= 0,
			.msg_flags	= 0,
		};

		if ((nl_sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR)) == -1) {
			PERRORPRINT("netlink task connector socket failed");
			return -1;
		}

		GY_SCOPE_EXIT {
			(void)close(nl_sock);
		};	

		if (sockconn_send(nl_sock) < 0) {
			return -1;
		}

		init_done = true;
	
		if (nerrors == 0) {
			nltaskthr.set_thread_init_done();
		}	

		pfds[0].fd 	= nl_sock;
		pfds[0].events 	= POLLIN | POLLRDHUP;
		pfds[0].revents = 0;

		while (false == nltaskthr.is_thread_stop_signalled()) {

			int			msglen = 0;
			struct nlmsghdr 	*h;
			bool			found_done = false, dump_intr = false;
			struct cn_msg 		*cn_msg;
			GY_PROC_EVENT 		proc_ev;

			ret = poll(pfds, 1, 1000);
			if (ret < 0) {
				if (errno == EINTR) {
					continue;
				}
				PERRORPRINT("poll for netlink task socket recv failed");
				return -1;
			}
			else if (ret == 0) {
				continue;
			}

			ret = recvmsg(nl_sock, &msg, 0);
			if (ret == -1) {
				if (errno == EINTR || errno == EAGAIN) {
					if (nltaskthr.is_thread_stop_signalled()) {
						break;
					}	
					continue;
				}	

				PERRORPRINT("recv of netlink task socket connector failed");
				return -1;
			}	
			else if (ret == 0) {
				PERRORPRINT("netlink task socket recv failed as kernel has shut the socket");
				return -1;
			}	

			if (msg.msg_namelen != sizeof(struct sockaddr_nl)) {
				errno = EINVAL;
				PERRORPRINT("recv of netlink task socket connector failed due to invalid data len");
				return -1;
			}

			h = (struct nlmsghdr *)pbuf;

			msglen = ret;

			RCU_DEFER_OFFLINE		deferlock;

			while (NLMSG_OK(h, (unsigned)msglen)) {
				if (h->nlmsg_flags & NLM_F_DUMP_INTR) {
					dump_intr = true;
				}	

				if (h->nlmsg_type == NLMSG_ERROR || h->nlmsg_type == NLMSG_NOOP) {
					continue;
				}

				cn_msg = decltype(cn_msg) (NLMSG_DATA(h));

				if ((cn_msg->id.idx != CN_IDX_PROC) || (cn_msg->id.val != CN_VAL_PROC)) {
					continue;
				}	

				std::memcpy(&proc_ev, cn_msg->data, sizeof(proc_ev));

				try {
					parse_conn_msg(&proc_ev);
				}
				GY_CATCH_EXCEPTION(
					DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while parsing netlink task event : %s\n", GY_GET_EXCEPT_STRING););
				);	

				h = NLMSG_NEXT(h, msglen);
			}

			if (msg.msg_flags & MSG_TRUNC) {
				continue;
			}
		}	
		
		inet_ret = 0;
		
	}
	GY_CATCH_EXCEPTION(ERRORPRINT_OFFLOAD("Exception caught in Task Netlink thread  : %s\n", GY_GET_EXCEPT_STRING); return -1;);

	return inet_ret;
}


int TASK_HANDLER::nltask_thread() noexcept
{
	bool			init_done;
	int			ret, nerrors = 0, nsuccess = 0;
	uint64_t		startsec, currsec;

	pool_task_.set_alloc_thrid();
	pool_elem_task_.set_alloc_thrid();
	
	nltaskid = pthread_self();

	do {
		startsec = get_sec_clock();
		
		ret = nltask(init_done, nerrors);
		if (ret != 0) {
			if (init_done) {
				nsuccess++;

				currsec = get_sec_clock();

				if (currsec - startsec > 10) {
					INFOPRINT_OFFLOAD("Netlink task handler returned with an error after some time. Trying again...\n");

					// Reset nerrors
					nerrors = 1;
					continue;
				}
				
				if (++nerrors < 1024) {
					ERRORPRINT("Netlink task handler returned with an error. Trying again...\n");
					gy_nanosleep(50 * nerrors * GY_NSEC_PER_MSEC);
					continue;
				}
				else {
					ERRORPRINT("Netlink task handler returned with an error. Too many errors. Quitting...\n");
					return -1;
				}		
			}	
			else {
				if (nsuccess) {
					nsuccess = 0;
					gy_nanosleep(0, 50 * GY_USEC_PER_MSEC);
					continue;
				}	
				ERRORPRINT("Netlink task handler returned with an error. Quitting...\n");

				nltaskthr.set_thread_init_done(true /* init_failed */);
				return -1;
			}	
		}	
		else {
			break;
		}	
	} while (1);

	INFOPRINT_OFFLOAD("Netlink Task Thread exiting now...\n");
	return 0;
}	


static TASK_HANDLER				*pgtask_ = nullptr;

TASK_HANDLER * TASK_HANDLER::get_singleton() noexcept
{
	return pgtask_;
}	
	
int TASK_HANDLER::init_singleton(bool stats_updated_by_sock, bool is_kubernetes)
{
	int					texp = 0, tdes = 1;
	static std::atomic<int>			is_init_done(0);

	if (false == is_init_done.compare_exchange_strong(texp, tdes)) {
		return 0;
	}
	
	/*
	 * Initialize all singletons we need, if not already done
	 */
	ASYNC_FUNC_HDLR::init_singleton();	// For RCU Hashtable
	 
	MOUNT_HDLR::init_singleton();

	auto pmountshr = MOUNT_HDLR::get_singleton();
	if (!pmountshr) {
		GY_THROW_EXCEPTION("Global Mount Shared pointer is not yet initialized");
	}	

	SYS_HARDWARE::init_singleton();

	GY_SCHEDULER::init_singletons();

	auto schedshrlong = GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_LONG2_DURATION);
	auto schedshrmain = GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_MAINTENANCE);

	if (!schedshrlong || !schedshrmain || !get_task_prio_scheduler()) {
		GY_THROW_EXCEPTION("Global Scheduler Shared objects not yet initialized");
	}	

	CGROUP_HANDLE::init_singleton();

	try {
		int ret = posix_memalign((void **)&pgtask_, 128, sizeof(TASK_HANDLER) + 16);

		if (ret || !pgtask_) {
			errno = ret;
			GY_THROW_SYS_EXCEPTION("Failed to allocate memory for Task Handler singleton");
		}

		new (pgtask_) TASK_HANDLER(stats_updated_by_sock, is_kubernetes);

		schedshrlong->add_schedule(3000, 3000, 0, "task lazy info updation", 
		[ptaskhdlr = pgtask_] { 
			ptaskhdlr->tasks_lazy_update(true /* from_scheduler */);
		});

		// Keep this the same thread as the "Send Ping Aggr Tasks" below and the tasks_lazy_update above
		schedshrlong->add_schedule(3200, VERIFY_PROC_INTERVAL_MSEC /* 30'000 */, 0, "verify task table from /proc and send aggr stats to server", 
		[ptaskhdlr = pgtask_] { 
		try {	
			if (ptaskhdlr->init_table_done) {
				AggrTaskStackMap			aggmap;			// Approx 450 KB Stack Map
				std::shared_ptr<SERVER_CONNTRACK>	shrconn;
				SERVER_CONNTRACK			*pconn1 = nullptr;	
				size_t					total_cmdlen = 0;
				int					ret;
				auto					pser = SERVER_COMM::get_singleton();

				shrconn = pser->get_server_conn(comm::CLI_TYPE_REQ_ONLY);
				pconn1 = shrconn.get();

				if (gy_unlikely(true == ptaskhdlr->reset_glob_aggr.load(std::memory_order_relaxed))) {
					ptaskhdlr->reset_glob_aggr.store(false, std::memory_order_relaxed);
					ptaskhdlr->glob_aggr_tasks_map_.clear();
				}	
				
				if (pconn1) {
					aggmap.reserve(1024);
				}

				ret = ptaskhdlr->tasks_verify_from_proc(total_cmdlen, pconn1 ? &aggmap : nullptr);

				if ((ret == 0) && pconn1 && aggmap.size()) {
					ptaskhdlr->tasks_send_aggr(aggmap, &shrconn, total_cmdlen);
				}	
			}	
		}
		GY_CATCH_EXCEPTION(
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while verifing procs from /proc and sending aggr tasks to Madhava %s\n", GY_GET_EXCEPT_STRING);
		);
		});

		schedshrlong->add_schedule(PING_TASK_INTERVAL_MSEC + 150, PING_TASK_INTERVAL_MSEC, 0, "Send Ping Aggr Tasks to Madhava", 
		[ptaskhdlr = pgtask_] { 
			ptaskhdlr->send_ping_aggr();
		});

		schedshrlong->add_schedule(5 * GY_MSEC_PER_MINUTE + 650, 5 * GY_MSEC_PER_MINUTE, 0, "Send Aggr Task Hist Stats to Madhava", 
		[ptaskhdlr = pgtask_] { 
			ptaskhdlr->send_hist_stats();
		});

		/*
		 * The following schedule is to be invoked by TCP_SOCK_HANDLER()...
		 */
		if (stats_updated_by_sock == false) {
			get_task_prio_scheduler()->add_schedule(5050, TASK_STATS_UPDATE_MSEC /* 5000 */, 0, "Tasks CPU Mem Util", 
				[next_imp_procs = bool(true), last_all_procs_tusec = get_usec_time()] () mutable 
				{ 
					auto pgtask = TASK_HANDLER::get_singleton();
					if (pgtask) {
						pgtask->tasks_cpu_stats_update(true /* from_scheduler */, next_imp_procs /* only_imp_procs */, last_all_procs_tusec);
					
						if (next_imp_procs == false) {
							last_all_procs_tusec = get_usec_time();
						}
					
						next_imp_procs = !next_imp_procs;
					}	
				});
		}

		// Keep this thread same as the tasks_cpu_stats_update thread
		get_task_prio_scheduler()->add_schedule(200'300, 60'000, 0, "Check for Non TCP Important Tasks", 
		[ptaskhdlr = pgtask_] { 
			ptaskhdlr->tasks_non_tcp_check();
		});

		// Keep this thread same as the tasks_cpu_stats_update thread
		get_task_prio_scheduler()->add_schedule(900'310, 900'000, 0, "Send New Tasks to Madhava", 
		[ptaskhdlr = pgtask_] { 
			ptaskhdlr->send_new_tasks();
		});

#		if 0
		// XXX Currently Madhava is not using these stats...
		// Keep this thread same as the tasks_cpu_stats_update thread
		static constexpr uint64_t		stats_inter = 60 * GY_MSEC_PER_MINUTE;		// 60 min

		get_task_prio_scheduler()->add_schedule(stats_inter + 130, stats_inter, 0, "Send Task Stats to Madhava", 
		[ptaskhdlr = pgtask_] { 
			ptaskhdlr->send_task_stats(stats_inter);
		});

#		endif

		CONDEXEC(
			DEBUGEXECN(12,
				schedshrmain->add_schedule(100'300, 150'000, 0, "Print Tasks CPU and delay Statistics", 
				[ptaskhdlr = pgtask_] { 
					ptaskhdlr->tasks_cpu_stats_print();

					STRING_BUFFER<1024>		strbuf;

					strbuf.appendconst("Task Handler Pool Stats : \n\t\t");
					ptaskhdlr->pool_task_.print_stats(strbuf);
					strbuf.appendconst("\n\t\t");
					ptaskhdlr->pool_elem_task_.print_stats(strbuf);

					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "%.*s\n", strbuf.sizeint(), strbuf.buffer());
				});
			);
		);

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT("Exception caught while creating global task handler object : %s\n", GY_GET_EXCEPT_STRING);
		throw;
	);
}


GY_SCHEDULER * TASK_HANDLER::get_task_prio_scheduler() noexcept
{
	return GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_HIGH_PRIO);
}

} // namespace gyeeta

