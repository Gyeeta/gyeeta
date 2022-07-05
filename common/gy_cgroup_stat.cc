
#include		"gy_cgroup_stat.h"
#include		"gy_task_handler.h"
#include		"gy_mount_disk.h"
#include		"gy_scheduler.h"
#include		"gy_async_func.h"
#include		"gy_print_offload.h"

namespace gyeeta {


template <typename T>
static int get_cgroup_stats(const char *pdir, const char *pstatfile, int cg_root_fd, T & output_data)
{
	char			buf[GY_PATH_MAX];
	int			ret, fd;
	bool			bret;

	output_data = 0;

	snprintf(buf, sizeof(buf), "./%s/%s", pdir, pstatfile);
	
	SCOPE_FD		scopefd(cg_root_fd, buf, O_RDONLY, 0600);

	fd = scopefd.get();
	if (fd < 0) {
		return -1;
	}	
	
	ret = read(fd, buf, sizeof(buf) - 1);
	if (ret > 0) {
		buf[ret] = '\0';

		bret = string_to_number(buf, output_data);

		if (bret) {
			return 0;
		}
	}	

	return -1;
}
		
static int get_cgroup_stats_string(const char *pdir, const char *pstatfile, int cg_root_fd, char *poutput, size_t szout)
{
	char			buf[GY_PATH_MAX];
	int			ret, fd;

	*poutput = '\0';

	snprintf(buf, sizeof(buf), "./%s/%s", pdir, pstatfile);
	
	SCOPE_FD		scopefd(cg_root_fd, buf, O_RDONLY, 0600);

	fd = scopefd.get();
	if (fd < 0) {
		return -1;
	}	
	
	ret = read(fd, poutput, szout > 0 ? szout - 1 : 0);
	if (ret > 0) {
		buf[ret] = '\0';
	}	

	return ret;
}
		
int CGROUP1_CPUACCT::update_cpu_usage() noexcept
{
	try {
		time_t			tcur = time(nullptr);

		if (false == is_recently_updated(tcur)) {
			// No tasks 
			return 1;
		}	

		double 			cpupct = 0;
		uint64_t		last_cpuusage = stats.cpuusage_ticks;
		int			ret;
		uint64_t		oldstatstime = stats.tstatstime;
		bool			is_flushed = false;
		
		stats.tstatstime = get_nsec_clock();

		uint64_t		diffticks = (stats.tstatstime - oldstatstime);

		if (diffticks == 0) diffticks = 1;

		ret = get_cgroup_stats<uint64_t>(get_dir_path(), "cpuacct.usage", pcghandle->get_fd_mount_root(), stats.cpuusage_ticks);
		if (ret != 0) {
			return ret;
		}	

		if (!(stats.cpuusage_ticks > last_cpuusage && last_cpuusage)) {
			return 0;	
		}
			 
		stats.cpuusage_pct = (double)(stats.cpuusage_ticks - last_cpuusage) /  diffticks * 100;

		cpupct = stats.cpuusage_pct;

		if (nullptr == GY_READ_ONCE(phistcpu)) {
			phistcpu = new CG_CPUACCT_HISTOGRAM(tcur);
		}	

		phistcpu->add_data((int)stats.cpuusage_pct, tcur);

		CONDEXEC(
			DEBUGEXECN(10, 
				if (cpupct > 10) {
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN_ITALIC, "cgroup CPU Utilization %8.03f%% : cgroup %s\n", cpupct, get_dir_path()); 
				}
			);
		);

		return 0;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while getting cpuacct cpu usage for %s : %s\n", get_dir_path(), GY_GET_EXCEPT_STRING););
		return -1;	
	);	
}	
	
int CGROUP_HANDLE::get_cpu_usage(void) noexcept
{
	try  {
		auto			root_shr = cpuacct_cg.get_cg_from_dir("/", false);
		auto			praw_cgroot = root_shr.get();	
		int			ret;

		if (!praw_cgroot) {
			return -1;
		}	
			
		ret = praw_cgroot->update_cpu_usage();

		auto ptbl = praw_cgroot->pchildtable.load(std::memory_order_relaxed);
		if (gy_unlikely(ptbl == nullptr)) {
			// no child cgroups
			return 0;
		}	

		using WRAP_T_ = RCU_HASH_WRAPPER<RCU_KEY_CHAR_POINTER, std::shared_ptr<CGROUP1_CPUACCT>>;

		auto dlambda = [](WRAP_T_ *pdatanode, void *arg) noexcept -> CB_RET_E
		{
			CGROUP1_CPUACCT		*praw = pdatanode->get_data()->get();
			int				ret;

			if (praw == nullptr) {
				return CB_OK;
			}

			ret = praw->update_cpu_usage();
			
			return CB_OK;
		};	

		ptbl->walk_hash_table(dlambda, nullptr); 	

		return 0;
	}
	GY_CATCH_EXCEPTION(ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while checking for cgroup cpu utilization : %s\n", GY_GET_EXCEPT_STRING); return -1;);
}

static int get_cgroup_cpu_throttle_stats(const char *pdir, int cg_root_fd, int &nr_periods, int &nr_throttled, uint64_t &throttled_time) noexcept
{
	char			buf[1024];
	int			ret, fd;
	bool			bret;

	snprintf(buf, sizeof(buf), "./%s/cpu.stat", pdir);
	
	SCOPE_FD		scopefd(cg_root_fd, buf, O_RDONLY, 0600);

	fd = scopefd.get();
	if (fd < 0) {
		return -1;
	}	
	
	ret = read(fd, buf, sizeof(buf) - 1);
	if (ret <= 0) {
		return -1;
	}
	buf[ret] = '\0';
		
	STR_RD_BUF		strbuf(buf, ret);
	const char		*ptmp;
	size_t			nbytes;
	
	ptmp = strbuf.skip_till_substring_const("nr_periods");
	if (!ptmp) {
		return -1;
	}	

	ptmp = strbuf.get_next_word(nbytes);
	if (!ptmp) {
		return -1;	
	}
	
	bret = string_to_number(ptmp, nr_periods);
	if (!bret) {
		return -1;	
	}
		 	 
	ptmp = strbuf.skip_till_substring_const("nr_throttled");
	if (!ptmp) {
		return -1;
	}	

	ptmp = strbuf.get_next_word(nbytes);
	if (!ptmp) {
		return -1;	
	}
	
	bret = string_to_number(ptmp, nr_throttled);
	if (!bret) {
		return -1;	
	}

	ptmp = strbuf.skip_till_substring_const("throttled_time");
	if (!ptmp) {
		return -1;
	}	

	ptmp = strbuf.get_next_word(nbytes);
	if (!ptmp) {
		return -1;	
	}
	
	bret = string_to_number(ptmp, throttled_time);
	if (!bret) {
		return -1;	
	}

	return 0;
}


int CGROUP1_CPU::update_throttle_stats() noexcept
{
	try {
		time_t			tcur = time(nullptr);

		if (false == is_recently_updated(tcur)) {
			// No tasks 
			return 1;
		}
		
		if (gy_unlikely(stats.tupdateclock == 0)) {
			verify_info();
		}

		int 			num_throttled = 0, num_period = 0;
		double 			pct_throttled = 0;
		int			last_nr_periods = stats.nr_periods, last_nr_throttled = stats.nr_throttled;
		uint64_t		last_throttled_time = stats.throttled_time, last_tupdateclock = stats.tupdateclock, time_throttled;
		int			ret;
		bool			is_flushed = false;
		
		if (stats.is_cfs_bw_limited == false) {
			// No CFS BW limit
			return 0;
		}	

		ret = get_cgroup_cpu_throttle_stats(get_dir_path(), pcghandle->get_fd_mount_root(), stats.nr_periods, stats.nr_throttled, stats.throttled_time);
		if (ret != 0) {
			return ret;
		}	

		stats.tupdateclock = get_nsec_clock();

		if (last_nr_periods == 0) {
			return 0;
		}
			
		num_throttled = gy_diff_counter_safe(stats.nr_throttled, last_nr_throttled);
		num_period = gy_diff_counter_safe(stats.nr_periods, last_nr_periods);
		time_throttled = gy_diff_counter_safe(stats.throttled_time, last_throttled_time);

		stats.throttled_pct = (time_throttled * 100.0)/(stats.tupdateclock > last_tupdateclock ? stats.tupdateclock - last_tupdateclock : 1);

		pct_throttled = stats.throttled_pct;

		if (nullptr == GY_READ_ONCE(phistcpu)) {
			if (stats.nr_throttled == 0) {
				return 0;
			}
				
			phistcpu = new CG_CPU_HISTOGRAM(tcur);
		}	

		ret = phistcpu->add_data((int)stats.throttled_pct, tcur);

		CONDEXEC(
			DEBUGEXECN(10, 
				if ((pct_throttled > 10) || (pct_throttled >= 0.1 && gdebugexecn >= 15)) {
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN_ITALIC, 
					"cgroup Throttled : #times %d : %% Throttled %.03f %% : CPU shares %3d%% : CPU Limit %3d%% : cgroup %s\n", 
					num_throttled, pct_throttled, stats.shares_pct, stats.cfs_bw_pct, get_dir_path()); 
				}
			);
		);

		return 0;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while getting cpu throttling stats for %s : %s\n", get_dir_path(), GY_GET_EXCEPT_STRING););
		return -1;	
	);	
}	

int CGROUP1_CPU::verify_info() noexcept
{
	try {
		int			ret;
		CPU_STATS		localstats;
		bool			is_upd = false;

		ret = get_cgroup_stats<int64_t>(get_dir_path(), "cpu.cfs_period_us", pcghandle->get_fd_mount_root(), localstats.cfs_period_us);
		if (ret != 0) {
			return ret;
		}	
		ret = get_cgroup_stats<int64_t>(get_dir_path(), "cpu.cfs_quota_us", pcghandle->get_fd_mount_root(), localstats.cfs_quota_us);
		if (ret != 0) {
			return ret;
		}	
		ret = get_cgroup_stats<int>(get_dir_path(), "cpu.shares", pcghandle->get_fd_mount_root(), localstats.shares);
		if (ret != 0) {
			return ret;
		}	

		get_cgroup_stats<int64_t>(get_dir_path(), "cpu.rt_period_us", pcghandle->get_fd_mount_root(), localstats.rt_period_us);
		get_cgroup_stats<int64_t>(get_dir_path(), "cpu.rt_runtime_us", pcghandle->get_fd_mount_root(), localstats.rt_runtime_us);

		if (localstats.cfs_period_us != this->stats.cfs_period_us) {
			if (stats.tupdateclock) INFOPRINT_OFFLOAD("cpu cgroup dir %s has changed cfs_period_us from %ld usec to %ld usec\n",
				get_dir_path(), this->stats.cfs_period_us, localstats.cfs_period_us);

			this->stats.cfs_period_us = localstats.cfs_period_us;
			is_upd = true;
		}	
		if (localstats.cfs_quota_us != this->stats.cfs_quota_us) {
			if (stats.tupdateclock) INFOPRINT_OFFLOAD("cpu cgroup dir %s has changed cfs_quota_us from %ld usec to %ld usec\n",
				get_dir_path(), this->stats.cfs_quota_us, localstats.cfs_quota_us);

			this->stats.cfs_quota_us = localstats.cfs_quota_us;
			is_upd = true;
		}	
		if (localstats.rt_period_us != this->stats.rt_period_us) {
			if (stats.tupdateclock) INFOPRINT_OFFLOAD("cpu cgroup dir %s has changed rt_period_us from %ld usec to %ld usec\n",
				get_dir_path(), this->stats.rt_period_us, localstats.rt_period_us);

			this->stats.rt_period_us = localstats.rt_period_us;
			is_upd = true;
		}	
		if (localstats.rt_runtime_us != this->stats.rt_runtime_us) {
			if (stats.tupdateclock) INFOPRINT_OFFLOAD("cpu cgroup dir %s has changed rt_runtime_us from %ld usec to %ld usec\n",
				get_dir_path(), this->stats.rt_runtime_us, localstats.rt_runtime_us);

			this->stats.rt_runtime_us = localstats.rt_runtime_us;
			is_upd = true;
		}	
		if (localstats.shares != this->stats.shares) {
			if (stats.tupdateclock) INFOPRINT_OFFLOAD("cpu cgroup dir %s has changed cpu shares from %d to %d\n",
				get_dir_path(), this->stats.shares, localstats.shares);

			this->stats.shares = localstats.shares;
			is_upd = true;
		}	

		if (is_upd == false) {
			if (stats.tupdateclock) {
				return 0;
			}
		}
		
		if (stats.cfs_period_us < 1000) stats.cfs_period_us = 1000;
		if (stats.shares < 2) stats.shares = 2;

		stats.is_share_limited 	= false;
		stats.shares_pct	= 100;

		auto topparentshr = weak_top_parent.lock();

		if (topparentshr) {
			if (topparentshr->stats.tupdateclock) {

				decltype(stats.shares) topparent_shares = topparentshr->stats.shares;

				if ((unsigned)stats.shares < (unsigned)topparent_shares) {
					stats.is_share_limited = true;			
					stats.shares_pct = (stats.shares * 100)/topparent_shares;
				}	
			}	
		}	

		if (stats.cfs_quota_us != -1L) {
			auto 		pcpumem = CPU_MEM_INFO::get_singleton();
			int		numcore = 2;

			assert(pcpumem);

			if (pcpumem) {
				numcore = pcpumem->get_number_of_cores();
				assert(numcore);
			}
				
			if ((stats.cfs_quota_us < stats.cfs_period_us) || (stats.cfs_quota_us/stats.cfs_period_us < numcore)) {
				stats.is_cfs_bw_limited = true;
				stats.cfs_bw_pct = (stats.cfs_quota_us * 100)/(stats.cfs_period_us * numcore);

				DEBUGEXECN(1, INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_GREEN, "cpu cgroup dir %s has limit on CPU util %d%% with min Share %d %%\n", 
					get_dir_path(), stats.cfs_bw_pct, stats.shares_pct););
			}	
			else {
				stats.is_cfs_bw_limited = false;
				stats.cfs_bw_pct 	= 100;
			}
		}
		else {
			stats.is_cfs_bw_limited = false;
			stats.cfs_bw_pct 	= 100;
		}

		stats.tupdateclock = get_nsec_clock();

		return 0;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while verifying cpu cgroup dir %s : %s\n", get_dir_path(), GY_GET_EXCEPT_STRING););
		return -1;	
	);	
}	

int CGROUP1_CPUSET::verify_info() noexcept
{
	try {
		int			ret, cret, mret;
		CPUSET_STATS		localstats;
		bool			is_upd = false, cpus_changed, mems_changed, is_tudated = (stats.tupdateclock > 0);
		char			cbuf[256], mbuf[256];

		get_cgroup_stats<bool>(get_dir_path(), "cpuset.cpu_exclusive", pcghandle->get_fd_mount_root(), localstats.cpu_exclusive);
		get_cgroup_stats<bool>(get_dir_path(), "cpuset.mem_exclusive", pcghandle->get_fd_mount_root(), localstats.mem_exclusive);
		get_cgroup_stats<bool>(get_dir_path(), "cpuset.sched_load_balance", pcghandle->get_fd_mount_root(), localstats.sched_load_balance);

		if (is_root_cgroup) {
			if (is_tudated) {
				if (pcghandle->stats.cpu_exclusive != localstats.cpu_exclusive) {
					INFOPRINT_OFFLOAD("cpuset cpu_exclusive setting changed for root cgroup from %d to %d\n", 
						pcghandle->stats.cpu_exclusive, localstats.cpu_exclusive);
					pcghandle->stats.cpu_exclusive = localstats.cpu_exclusive;	
				}	 

				if (pcghandle->stats.mem_exclusive != localstats.mem_exclusive) {
					INFOPRINT_OFFLOAD("cpuset mem_exclusive setting changed for root cgroup from %d to %d\n", 
						pcghandle->stats.mem_exclusive, localstats.mem_exclusive);
					pcghandle->stats.mem_exclusive = localstats.mem_exclusive;	
				}	

				if (pcghandle->stats.sched_load_balance != localstats.sched_load_balance) {
					INFOPRINT_OFFLOAD("cpuset sched_load_balance setting changed for root cgroup from %d to %d\n", 
						pcghandle->stats.sched_load_balance, localstats.sched_load_balance);
					pcghandle->stats.sched_load_balance = localstats.sched_load_balance;	
				}	
			}
			else {
				pcghandle->stats.cpu_exclusive = localstats.cpu_exclusive;
				pcghandle->stats.mem_exclusive = localstats.mem_exclusive;
				pcghandle->stats.sched_load_balance = localstats.sched_load_balance;
			}	
		}	

		cret = get_cgroup_stats_string(get_dir_path(), !stats.effective_not_avail ? "cpuset.effective_cpus" : "cpuset.cpus", 
				pcghandle->get_fd_mount_root(), cbuf, sizeof(cbuf));
		if (cret > 0) {
			set_bitset_from_buffer(localstats.cpus_allowed, cbuf, cret);
		}	
		else if ((is_tudated == false) && (cret == -1)) {
			stats.effective_not_avail = true;

			cret = get_cgroup_stats_string(get_dir_path(), "cpuset.cpus", pcghandle->get_fd_mount_root(), cbuf, sizeof(cbuf));
			if (cret > 0) {
				set_bitset_from_buffer(localstats.cpus_allowed, cbuf, cret);
			}	
		}	

		mret = get_cgroup_stats_string(get_dir_path(), !stats.effective_not_avail ? "cpuset.effective_mems" : "cpuset.mems", 
				pcghandle->get_fd_mount_root(), mbuf, sizeof(mbuf));

		if (mret > 0) {
			set_bitset_from_buffer(localstats.mems_allowed, mbuf, mret);
		}	

		if (is_cg_changed(localstats, this->stats, cpus_changed, mems_changed)) {
			// Not atomic
			this->stats = localstats;

			if (is_tudated) {
				INFOPRINT_OFFLOAD("cpuset cgroup dir %s : Change seen : CPUs Changed %s Mems Changed %s cpu_exclusive %d mem_exclusive %d\n", 
					get_dir_path(), cpus_changed ? "(Yes)" : "(No)",  mems_changed ? "(Yes)" : "(No)", stats.cpu_exclusive, stats.mem_exclusive);

				if (cpus_changed || mems_changed) {
					auto ptaskhdlr = TASK_HANDLER::get_singleton();
					
					if (ptaskhdlr) {
						ptaskhdlr->handle_cpuset_change(this, cpus_changed, stats.cpus_allowed, mems_changed, stats.mems_allowed);
					}
				}
			}	
		}	
		else if (is_root_cgroup && is_tudated) {
			return 0;
		}
		
		if (false == is_root_cgroup) {
			/*
			 * cpu_exclusive, mem_exclusive and sched_load_balance depend on whether the root cgroup have these defined.
			 */
			stats.cpu_exclusive &= pcghandle->stats.cpu_exclusive;
			stats.mem_exclusive &= pcghandle->stats.mem_exclusive;

			if (pcghandle->stats.sched_load_balance == true) {
				stats.sched_load_balance = true;
			}	
		}	

		stats.tupdateclock = get_nsec_clock();

		return 0;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while verifying cpu cgroup dir %s : %s\n", get_dir_path(), GY_GET_EXCEPT_STRING););
		return -1;	
	);	
}	

int CGROUP_HANDLE::get_cpu_throttle_stats(void) noexcept
{
	try  {
		auto			root_shr = cpu_cg.get_cg_from_dir("/", false);
		auto			praw_cgroot = root_shr.get();	
		int			ret;

		if (!praw_cgroot) {
			return -1;
		}	
			
		ret = praw_cgroot->update_throttle_stats();

		auto ptbl 	= praw_cgroot->pchildtable.load(std::memory_order_relaxed);

		if (gy_unlikely(ptbl == nullptr)) {
			// no child cgroups
			return 0;	
		}	

		using WRAP_T_ = RCU_HASH_WRAPPER<RCU_KEY_CHAR_POINTER, std::shared_ptr<CGROUP1_CPU>>;

		auto dlambda = [](WRAP_T_ *pdatanode, void *arg) noexcept -> CB_RET_E
		{
			CGROUP1_CPU			*praw = pdatanode->get_data()->get();
			int				ret;

			if (praw == nullptr) {
				return CB_OK;
			}

			ret = praw->update_throttle_stats();

			return CB_OK;
		};	

		ptbl->walk_hash_table(dlambda, nullptr); 	

		return 0;
	}
	GY_CATCH_EXCEPTION(ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while checking for cgroup cpu throttling : %s\n", GY_GET_EXCEPT_STRING); return -1;);
}	

static int get_memory_stat(const char *pdir, int cg_root_fd, CGROUP1_MEMORY::MEMORY_STATS & memstat, uint64_t total_memory) noexcept
{
	char			buf[2048];
	int			ret, fd;
	uint64_t		total_cache = 0, total_rss = 0, total_swap = 0, old_pgmajfault = memstat.last_pgmajfault;
	float			pct1, pct2, pct3, pct4;

	memstat.cache 				= 0;
	memstat.rss 				= 0;
	memstat.swap				= 0;
	memstat.int_pgmajfault			= 0;
	memstat.hierarchical_memory_limit	= ~0lu;
	memstat.pct_memory_limit		= 0;
	memstat.pct_hier_memory_limit		= 0;
	memstat.pct_rss_limit			= 0;
	memstat.pct_hier_rss_limit		= 0;

	snprintf(buf, sizeof(buf), "./%s/memory.stat", pdir);
	
	SCOPE_FD		scopefd(cg_root_fd, buf, O_RDONLY, 0600);

	fd = scopefd.get();
	if (fd < 0) {
		return -1;
	}	
	
	ret = read(fd, buf, sizeof(buf) - 1);
	if (ret <= 0) {
		return -1;
	}
	buf[ret] = '\0';

	memstat.tstatstime 	= get_nsec_clock();
		
	STR_RD_BUF		strbuf(buf, ret);
	const char		*ptmp;
	size_t			nbytes;
	
	ptmp = strbuf.skip_till_whole_word_const("cache", true);
	if (ptmp) {
		ptmp = strbuf.get_next_word(nbytes);
		if (ptmp) {
			string_to_number(ptmp, memstat.cache);
		}
	}		 
		 	 
	ptmp = strbuf.skip_till_whole_word_const("rss", true);
	if (ptmp) {
		ptmp = strbuf.get_next_word(nbytes);
		if (ptmp) {
			string_to_number(ptmp, memstat.rss);
		}
	}		 

	ptmp = strbuf.skip_till_whole_word_const("swap", true);
	if (ptmp) {
		ptmp = strbuf.get_next_word(nbytes);
		if (ptmp) {
			string_to_number(ptmp, memstat.swap);
		}
	}		 

	ptmp = strbuf.skip_till_whole_word_const("pgmajfault", true);
	if (ptmp) {
		ptmp = strbuf.get_next_word(nbytes);
		if (ptmp) {
			string_to_number(ptmp, memstat.last_pgmajfault);
			memstat.int_pgmajfault = gy_diff_counter_safe(memstat.last_pgmajfault, old_pgmajfault);
		}
	}		 

	ptmp = strbuf.skip_till_whole_word_const("hierarchical_memory_limit", true);
	if (ptmp) {
		ptmp = strbuf.get_next_word(nbytes);
		if (ptmp) {
			string_to_number(ptmp, memstat.hierarchical_memory_limit);
		}
	}		 

	ptmp = strbuf.skip_till_whole_word_const("total_cache", true);
	if (ptmp) {
		ptmp = strbuf.get_next_word(nbytes);
		if (ptmp) {
			string_to_number(ptmp, total_cache);
		}
	}		 
		 	 
	ptmp = strbuf.skip_till_whole_word_const("total_rss", true);
	if (ptmp) {
		ptmp = strbuf.get_next_word(nbytes);
		if (ptmp) {
			string_to_number(ptmp, total_rss);
		}
	}		 

	ptmp = strbuf.skip_till_whole_word_const("total_swap", true);
	if (ptmp) {
		ptmp = strbuf.get_next_word(nbytes);
		if (ptmp) {
			string_to_number(ptmp, total_swap);
		}
	}		 

	if (memstat.hierarchical_memory_limit == 0) {
		memstat.hierarchical_memory_limit = ~0lu;
	}	

	if (memstat.hierarchical_memory_limit >= 0x7ffffffffffff000UL) {
		memstat.hierarchical_memory_limit = total_memory;
		memstat.is_memory_limited = false;
	}	
	else {
		memstat.is_memory_limited = true;
	}

	pct1 = ((memstat.cache + memstat.rss + memstat.swap) * 100.0)/memstat.hierarchical_memory_limit;
	pct3 = (memstat.rss * 100.0)/memstat.hierarchical_memory_limit;

	pct2 = ((total_cache + total_rss + total_swap) * 100.0)/memstat.hierarchical_memory_limit;
	pct4 = (total_rss * 100.0)/memstat.hierarchical_memory_limit;
	
	memstat.pct_memory_limit 	= (uint8_t)pct1;
	memstat.pct_hier_memory_limit 	= (uint8_t)pct2;

	memstat.pct_rss_limit 		= (uint8_t)pct3;
	memstat.pct_hier_rss_limit 	= (uint8_t)pct4;

	if (memstat.pct_rss_limit > 85) {
		WARNPRINT_OFFLOAD("Memory cgroup %s has used up over %hhu%% of total memory allowed (%lu MB out of allowed %lu MB). OOM check may be invoked...\n",
			pdir, memstat.pct_rss_limit, GY_DOWN_MB(memstat.rss), GY_DOWN_MB(memstat.hierarchical_memory_limit));
	}	
	else if (memstat.pct_hier_rss_limit > 85) {
		WARNPRINT_OFFLOAD("Memory cgroup %s descendents have used up over %hhu%% of total memory allowed (%lu MB out of allowed %lu MB). OOM check may be invoked...\n",
			pdir, memstat.pct_hier_rss_limit, GY_DOWN_MB(total_rss), GY_DOWN_MB(memstat.hierarchical_memory_limit));
	}	

	return 0;
}	

int CGROUP1_MEMORY::verify_info() noexcept
{
	try {
		int			ret;

		if (is_top_parent || !stats.tstatstime) {
			get_cgroup_stats<bool>(get_dir_path(), "memory.use_hierarchy", pcghandle->get_fd_mount_root(), stats.is_hierarchical);
		}

		time_t			tlast = last_task_time.load(std::memory_order_relaxed);

		if ((tlast == 0) || (is_task_table_valid() && tasktable->is_empty())) {
			// No tasks : Get the hierarchial stats
			get_memory_stat(get_dir_path(), pcghandle->get_fd_mount_root(), stats, CPU_MEM_INFO::get_singleton()->get_total_memory());
			return 1;
		}

		return 0;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while verifying memory cgroup dir %s : %s\n", get_dir_path(), GY_GET_EXCEPT_STRING););
		return -1;	
	);
}
	
int CGROUP1_MEMORY::update_mem_usage() noexcept
{
	try {
		time_t			tcur = time(nullptr);
		int			ret;

		if (false == is_recently_updated(tcur)) {
			// No tasks 
			return 1;
		}	

		ret = get_memory_stat(get_dir_path(), pcghandle->get_fd_mount_root(), stats, CPU_MEM_INFO::get_singleton()->get_total_memory());

		if (ret != 0) {
			return 1;
		}
			
		if (nullptr == GY_READ_ONCE(phistmem)) {
			phistmem = new CG_MEMORY_HISTOGRAM(tcur);
		}	

		phistmem->add_data(GY_DOWN_MB(stats.rss), tcur);

		CONDEXEC(
			DEBUGEXECN(10, 
				if (stats.pct_rss_limit > 10) {
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN_ITALIC, "Memory cgroup %s has used up %hhu %% of total memory allowed (%lu MB out of allowed %lu MB)\n",
						get_dir_path(), stats.pct_rss_limit, GY_DOWN_MB(stats.rss), GY_DOWN_MB(stats.hierarchical_memory_limit));
				}

				if (stats.int_pgmajfault > 0) {
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN_ITALIC, "Memory cgroup %s processes have incurred %lu Major Page Faults\n", 
						get_dir_path(), stats.int_pgmajfault);
				}
			);
		);

		return 0;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while getting memory cgroup usage for %s : %s\n", get_dir_path(), GY_GET_EXCEPT_STRING););
		return -1;	
	);	
}	
	
int CGROUP_HANDLE::get_mem_usage(void) noexcept
{
	try  {
		auto			root_shr = memory_cg.get_cg_from_dir("/", false);
		auto			praw_cgroot = root_shr.get();	
		int			ret;

		if (!praw_cgroot) {
			return -1;
		}	
			
		ret = praw_cgroot->update_mem_usage();

		auto ptbl = praw_cgroot->pchildtable.load(std::memory_order_relaxed);
		if (gy_unlikely(ptbl == nullptr)) {
			// no child cgroups
			return 0;
		}	

		using WRAP_T_ = RCU_HASH_WRAPPER<RCU_KEY_CHAR_POINTER, std::shared_ptr<CGROUP1_MEMORY>>;

		auto dlambda = [](WRAP_T_ *pdatanode, void *arg) noexcept -> CB_RET_E
		{
			CGROUP1_MEMORY		*praw = pdatanode->get_data()->get();
			int				ret;

			if (praw == nullptr) {
				return CB_OK;
			}

			ret = praw->update_mem_usage();
			
			return CB_OK;
		};	

		ptbl->walk_hash_table(dlambda, nullptr); 	

		return 0;
	}
	GY_CATCH_EXCEPTION(ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while checking for cgroup memory utilization : %s\n", GY_GET_EXCEPT_STRING); return -1;);
}

static int get_blkio_stat(const char *pdir, int cg_root_fd, CGROUP1_BLKIO::BLKIO_STATS & blkiostat) noexcept
{
	char			buf[2048], tbuf[128];
	int			ret, fd;
	uint64_t		old_total_io = blkiostat.last_total_io;

	blkiostat.int_total_io	= 0;

	// XXX throttle.io_serviced will likely be double if LVM is in use as the stats will include both 
	// LVM and the raw disk stats

	snprintf(buf, sizeof(buf), "./%s/blkio.throttle.io_serviced", pdir);
	
	SCOPE_FD		scopefd(cg_root_fd, buf, O_RDONLY, 0600);

	fd = scopefd.get();
	if (fd < 0) {
		return -1;
	}	
	
	std::memset(buf, ' ', 128);

	do {
		ret = read(fd, buf + 128, sizeof(buf) - 128 - 1);
		if (ret < 0) {
			return -1;
		}
	
		if (ret + 128 == sizeof(buf) - 1) {
			std::memcpy(buf, buf + ret, 128);	
			continue;
		}		
			
		ret += 128;
		break;

	} while (1);
	
	buf[ret] = '\0';

	blkiostat.tstatstime 	= get_nsec_clock();
		
	STR_RD_BUF		strbuf(buf, ret);
	const char		*ptmp;
	size_t			nbytes;
	
	ptmp = strbuf.skip_till_substring_const("\nTotal", true);
	if (ptmp) {
		ptmp = strbuf.get_next_word(nbytes);
		if (ptmp) {
			if (string_to_number(ptmp, blkiostat.last_total_io)) {
				blkiostat.int_total_io = gy_diff_counter_safe(blkiostat.last_total_io, old_total_io);
				return 0;
			}	
		}
	}		 
		 	 
	return -1;
}

int CGROUP1_BLKIO::update_blkio_usage() noexcept
{
	try {
		time_t			tcur = time(nullptr);
		int			ret;

		if (false == is_recently_updated(tcur)) {
			// No tasks 
			return 1;
		}	

		ret = get_blkio_stat(get_dir_path(), pcghandle->get_fd_mount_root(), stats);
		if (ret != 0) {
			return 1;
		}
			
		if (nullptr == GY_READ_ONCE(phistblkio)) {
			if (stats.int_total_io == 0) {
				return 1;
			}
				
			phistblkio = new CG_BLKIO_HISTOGRAM(tcur);

			// Ignore 1st record
			stats.int_total_io = 0;
		}	
		else {
			phistblkio->add_data(stats.int_total_io, tcur);
		}	

		CONDEXEC(
			DEBUGEXECN(10, 
				/*
				 * XXX Note : As of Kernel 4.17, IO statistics for Memory Writeback are attributed to the correct cgroup only for ext4 and btrfs.
				 * For other FS, the / root blkio cgroup will be updated instead.
				 */ 
				if (stats.int_total_io > 100) {
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN_ITALIC, "Blkio cgroup %s has used total Blkio's of %lu during last few seconds\n",
						get_dir_path(), stats.int_total_io);
				}
			);
		);

		return 0;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while getting blkio cgroup usage for %s : %s\n", get_dir_path(), GY_GET_EXCEPT_STRING););
		return -1;	
	);	
}	
	
int CGROUP_HANDLE::get_blkio_usage(void) noexcept
{
	try  {
		auto			root_shr = blkio_cg.get_cg_from_dir("/", false);
		auto			praw_cgroot = root_shr.get();	
		int			ret;

		if (!praw_cgroot) {
			return -1;
		}	
			
		ret = praw_cgroot->update_blkio_usage();

		auto ptbl = praw_cgroot->pchildtable.load(std::memory_order_relaxed);
		if (gy_unlikely(ptbl == nullptr)) {
			// no child cgroups
			return 0;
		}	

		using WRAP_T_ = RCU_HASH_WRAPPER<RCU_KEY_CHAR_POINTER, std::shared_ptr<CGROUP1_BLKIO>>;

		auto dlambda = [](WRAP_T_ *pdatanode, void *arg) noexcept -> CB_RET_E
		{
			CGROUP1_BLKIO			*praw = pdatanode->get_data()->get();
			int				ret;

			if (praw == nullptr) {
				return CB_OK;
			}

			ret = praw->update_blkio_usage();
			
			return CB_OK;
		};	

		ptbl->walk_hash_table(dlambda, nullptr); 	

		return 0;
	}
	GY_CATCH_EXCEPTION(ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while checking for cgroup blkio utilization : %s\n", GY_GET_EXCEPT_STRING); return -1;);
}


void CGROUP_HANDLE::check_mount_changes(bool cancel_schedule_if_done) noexcept
{
	try {
		/*
		 * If a previously unmounted cgroup is seen we need to activate the new mount point.
		 */
		int			no_mounts = 0;
		bool			chk_cpuacct = false, chk_cpu = false, chk_cpuset = false, chk_memory = false, chk_blkio = false; 
		
		{
			auto			pdir = cpuacct_cg.get_root_mount_point();

			if (pdir && *pdir) {
				// cpuacct exists
			}	
			else {
				chk_cpuacct = true;
				no_mounts++;
			}
		}

		{
			auto			pdir = cpu_cg.get_root_mount_point();

			if (pdir && *pdir) {
				// cpu cg exists
			}	
			else {
				chk_cpu = true;
				no_mounts++;
			}
		}

		{
			auto			pdir = cpuset_cg.get_root_mount_point();

			if (pdir && *pdir) {
				// cpuset cg exists
			}	
			else {
				chk_cpuset = true;
				no_mounts++;
			}
		}

		{
			auto			pdir = memory_cg.get_root_mount_point();

			if (pdir && *pdir) {
				// memory exists
			}	
			else {
				chk_memory = true;
				no_mounts++;
			}
		}

		{
			auto			pdir = blkio_cg.get_root_mount_point();

			if (pdir && *pdir) {
				// memory exists
			}	
			else {
				chk_blkio = true;
				no_mounts++;
			}
		}

		auto pmountshr = MOUNT_HDLR::get_singleton();
		if (!pmountshr) {
			return;
		}

		char			dir_cpuacct[GY_PATH_MAX], dir_cpu[GY_PATH_MAX], dir_cpuset[GY_PATH_MAX], 
					dir_memory[GY_PATH_MAX], dir_blkio[GY_PATH_MAX];

		int			ret;
		
		if (chk_cpuacct) {
			ret = pmountshr->get_cgroup_mount(MTYPE_CPUACCT, dir_cpuacct, sizeof(dir_cpuacct));		
			if (ret == 0) {
				ret = set_new_mount_root_cpuacct(dir_cpuacct);
				if (ret == 0) {
					no_mounts--;
				}	
			}
		}

		if (chk_cpu) {
			ret = pmountshr->get_cgroup_mount(MTYPE_CPU, dir_cpu, sizeof(dir_cpu));		
			if (ret == 0) {
				ret = set_new_mount_root_cpu(dir_cpu);
				if (ret == 0) {
					no_mounts--;
				}	
			}
		}

		if (chk_cpuset) {
			ret = pmountshr->get_cgroup_mount(MTYPE_CPUSET, dir_cpuset, sizeof(dir_cpuset));		
			if (ret == 0) {
				ret = set_new_mount_root_cpuset(dir_cpuset);
				if (ret == 0) {
					no_mounts--;
				}	
			}
		}

		if (chk_memory) {
			ret = pmountshr->get_cgroup_mount(MTYPE_MEMORY, dir_memory, sizeof(dir_memory));		
			if (ret == 0) {
				ret = set_new_mount_root_memory(dir_memory);
				if (ret == 0) {
					no_mounts--;
				}	
			}
		}

		if (chk_blkio) {
			ret = pmountshr->get_cgroup_mount(MTYPE_BLKIO, dir_blkio, sizeof(dir_blkio));		
			if (ret == 0) {
				ret = set_new_mount_root_blkio(dir_blkio);
				if (ret == 0) {
					no_mounts--;
				}	
			}
		}

		if (cancel_schedule_if_done && (no_mounts == 0)) {
			// All required cgroups mounted

			auto schedshr = GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_LONG_DURATION);
			if (schedshr) {
				schedshr->cancel_schedule("check for new cgroup mounts");
			}
		}	
	}
	GY_CATCH_EXCEPTION(ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while checking for new cgroup mounts : %s\n", GY_GET_EXCEPT_STRING););
}
		
static CGROUP_HANDLE			*pgcgroup_ = nullptr;

CGROUP_HANDLE* CGROUP_HANDLE::get_singleton() noexcept
{
	return pgcgroup_;
}	
	
int CGROUP_HANDLE::init_singleton()
{
	int				texp = 0, tdes = 1;
	static std::atomic<int>		is_init_done(0);

	if (false == is_init_done.compare_exchange_strong(texp, tdes)) {
		return 0;
	}
	
	/*
	 * Initialize all singletons we need, if not already done
	 */
	GY_SCHEDULER::init_singletons();

	auto schedshrstats = GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_NO_CATCHUP);
	auto schedshrlong = GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_LONG_DURATION);

	if (!schedshrstats || !schedshrlong) {
		GY_THROW_EXCEPTION("Global Scheduler Shared objects not yet initialized");
	}	

	ASYNC_FUNC_HDLR::init_singleton();	// For RCU Hashtable
	 
	MOUNT_HDLR::init_singleton();

	auto pmountshr = MOUNT_HDLR::get_singleton();
	if (!pmountshr) {
		GY_THROW_EXCEPTION("Global Mount Shared object is not yet initialized");
	}	

	SYS_HARDWARE::init_singleton();
	
	try {
		char			dir_cpuacct[GY_PATH_MAX], dir_cpu[GY_PATH_MAX], dir_cpuset[GY_PATH_MAX], 
					dir_mem[GY_PATH_MAX], dir_blkio[GY_PATH_MAX];

		int			ret, no_mounts = 0;
		
		ret = pmountshr->get_cgroup_mount(MTYPE_CPUACCT, dir_cpuacct, sizeof(dir_cpuacct));		
		if (ret != 0) {
			*dir_cpuacct = '\0';
			no_mounts++;
		}	

		ret = pmountshr->get_cgroup_mount(MTYPE_CPU, dir_cpu, sizeof(dir_cpu));		
		if (ret != 0) {
			*dir_cpu= '\0';
			no_mounts++;
		}	

		ret = pmountshr->get_cgroup_mount(MTYPE_CPUSET, dir_cpuset, sizeof(dir_cpuset));		
		if (ret != 0) {
			*dir_cpuset = '\0';
			no_mounts++;
		}	

		ret = pmountshr->get_cgroup_mount(MTYPE_MEMORY, dir_mem, sizeof(dir_mem));		
		if (ret != 0) {
			*dir_mem = '\0';
			no_mounts++;
		}	

		ret = pmountshr->get_cgroup_mount(MTYPE_BLKIO, dir_blkio, sizeof(dir_blkio));		
		if (ret != 0) {
			*dir_blkio = '\0';
			no_mounts++;
		}	

		pgcgroup_ = new CGROUP_HANDLE(dir_cpuacct, dir_cpu, dir_cpuset, dir_mem, dir_blkio);

		if (no_mounts) {
			/*
			 * Schedule a periodic 30 sec cgroup mount change check
			 */
			INFOPRINT("Required cgroupv1 mount points %d not yet mounted. Scheduling periodic mount point check...\n", no_mounts);

			schedshrlong->add_schedule(30123, 30'000, 0, "check for new cgroup mounts", 
			[pcg = pgcgroup_] { 
				pcg->check_mount_changes(true /* cancel_schedule_if_done */);
			});
		}	

		schedshrlong->add_schedule(72020, 75000, 0, "verify all cgroup tasks/processes", 
		[pcg = pgcgroup_] { 
			pcg->verify_procs();
		});


		schedshrlong->add_schedule(7500, 17'000, 0, "verify all cgroup directories", 
		[pcg = pgcgroup_] { 
			pcg->verify_dirs();
		});

		schedshrstats->add_schedule(4900, CG_STATS_UPDATE_SEC * GY_MSEC_PER_SEC /* 15000 */, 0, "cgroup periodic statistics usage scan", 
		[pcg = pgcgroup_] { 
			GY_NOMT_COLLECT_PROFILE(100, "cgroup periodic stats collection");

			RCU_DEFER_OFFLINE	deferlock;

			pcg->get_cpu_usage();
			pcg->get_cpu_throttle_stats();
			pcg->get_mem_usage();
			pcg->get_blkio_usage();
		});
		
		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT("Exception caught while creating global cgroup handler object : %s\n", GY_GET_EXCEPT_STRING);
		throw;
	);
}		

} // namespace gyeeta	

