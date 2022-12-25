//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include		"gy_server_int.h"
#include		"gy_sys_stat.h"
#include		"gy_print_offload.h"
#include		"gy_scheduler.h"

namespace gyeeta {

SYS_CPU_STATS::SYS_CPU_STATS() :
	pcpuarr(
		({
			auto pglobcpu = CPU_MEM_INFO::get_singleton();
			if (!pglobcpu) {
				GY_THROW_EXCEPTION("CPU Memory singleton not yet initialized");
			}
			
			auto ncpu = pglobcpu->get_max_possible_cores();
			if (ncpu <= 0) {
				ncpu = 0;
			}
			else if (ncpu > MAX_PROCESSOR_CORES) {
				ncpu = MAX_PROCESSOR_CORES;	
			}		

			max_cores_possible 	= ncpu;
			curr_cores_online	= pglobcpu->get_number_of_cores();

			if (curr_cores_online > max_cores_possible) {
				curr_cores_online = max_cores_possible;
			}	

			new CPU_ONE_STATS[ncpu];
		})
	),
	pcore_cpu_hist(
		({
			auto ptmp = new (std::nothrow) CORE_CPU_HIST[max_cores_possible];
			if (!ptmp) {
				int		olderrno = errno;
				
				delete [] pcpuarr;

				errno 		= olderrno;
				GY_THROW_SYS_EXCEPTION("Failed to allocate memory for System CPU Stats");
			}	
			ptmp;
		})	
	),
	cpuhistogram("Host CPU"), cshistogram("Host Context Switch"), 
	fork_histogram("Process Forks"), procs_running_histogram("Procs Running")	
{
	int		ret;
	
	ret = get_cpu_stats();
	if (ret != 0) {
		GY_THROW_SYS_EXCEPTION("Failed to read /proc/stat");
	}	
}


int SYS_CPU_STATS::get_cpu_stats() noexcept
{
	GY_NOMT_COLLECT_PROFILE(1000, "Host CPU Statistics");

	// Need at least 130 KB Stack
	assert(gy_get_thread_local().get_thread_stack_freespace() > MAX_PROC_STAT_SIZE + 4096);

	char			pgreadbuf[MAX_PROC_STAT_SIZE];

	SCOPE_FD		scopefd("/proc/stat", O_RDONLY);
	int			fd, ret, noffline = 0;
	const char		*ptmp;
	ssize_t			szread;
	size_t			nbytes, bucketcpu, bucket1;
	uint64_t		diffticks, tval, cswitch, processes = 0, procs_running = 0, clock_nsec;
	float			cumpct = 0;
	time_t			tnow;
	bool			to_calc, bret;

	fd = scopefd.get();

	if (fd < 0) {
		return -1;
	}

	ret = gy_readbuffer(fd, pgreadbuf, MAX_PROC_STAT_SIZE - 1);

	if (ret < 0) {
		return -1;
	}	
	
	pgreadbuf[ret] = '\0';

	CPU_ONE_STATS		tstat;
	STR_RD_BUF		strbuf(pgreadbuf, ret);

	ptmp = strbuf.get_next_line(nbytes);
	if (!ptmp) {
		return -1;
	}

	if (0 != memcmp(ptmp, "cpu ", 4)) {
		return -1;
	}	

	ret = sscanf(ptmp + 5, "%lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
	       &tstat.cpu_user, &tstat.cpu_nice, &tstat.cpu_sys, &tstat.cpu_idle, &tstat.cpu_iowait,
	       &tstat.cpu_hardirq, &tstat.cpu_softirq, &tstat.cpu_steal, &tstat.cpu_guest, &tstat.cpu_guest_nice);

	if (ret < 3) {
		return -1;
	}	

	clock_nsec 		= get_nsec_clock();

	if (last_clock_nsec && curr_clock_nsec) {
		to_calc = true;

		if (clock_nsec - curr_clock_nsec < GY_NSEC_PER_SEC) {
			// Delay between successive get_cpu_stats() too low, probably due to the scheduler object having been overrun
			return 1;
		}
		
	}
	else {
		to_calc = false;
	}	
		
	last_clock_nsec 	= curr_clock_nsec;
	curr_clock_nsec		= clock_nsec;
	tnow			= time(nullptr);
	
	if (to_calc) {

		tstat.clock_nsec = curr_clock_nsec;

		diffticks = get_diffticks(&tstat, &overall_stats);
		calc_cpu_pct(&tstat, &overall_stats, diffticks);
	}

	do {
		CPU_ONE_STATS		tstat1, *pstats;
		uint32_t		corenum;

		ptmp = strbuf.get_next_line(nbytes);
		if (!ptmp) {
			break;
		}

		if (0 != memcmp(ptmp, "cpu", 3)) {
			break;
		}	

		ret = sscanf(ptmp + 3, "%u %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
			       &corenum, &tstat1.cpu_user, &tstat1.cpu_nice, &tstat1.cpu_sys, &tstat1.cpu_idle,
			       &tstat1.cpu_iowait, &tstat1.cpu_hardirq, &tstat1.cpu_softirq, &tstat1.cpu_steal, &tstat1.cpu_guest, &tstat1.cpu_guest_nice);
		if (ret < 4) {
			break;	
		}		

		if (corenum >= max_cores_possible) {
			break;
		}	
		
		pstats = pcpuarr + corenum;

		pstats->clock_nsec = curr_clock_nsec;

		if (to_calc) {
			tstat1.clock_nsec = curr_clock_nsec;

			diffticks = get_diffticks(&tstat1, pstats);
			calc_cpu_pct(&tstat1, pstats, diffticks);
		}	
	} while (true);	
	
	cswitch = 0;

	ptmp = strbuf.skip_till_substring_const("ctxt", false);
	if (ptmp) {
		ptmp = strbuf.get_next_word(nbytes);
		if (ptmp) {
			bret = string_to_number(ptmp, tval, nullptr, 10);
			if (bret) {
				cswitch = gy_diff_counter_safe(tval, cumul_context_switch);
				cumul_context_switch	= tval;
			}	
		}
	}

	ptmp = strbuf.skip_till_substring_const("processes", false);
	if (ptmp) {
		ptmp = strbuf.get_next_word(nbytes);
		if (ptmp) {
			bret = string_to_number(ptmp, tval, nullptr, 10);
			if (bret) {
				processes = gy_diff_counter_safe(tval, cumul_forks);
				cumul_forks	= tval;
			}	
		}
	}

	ptmp = strbuf.skip_till_substring_const("procs_running", false);
	if (ptmp) {
		ptmp = strbuf.get_next_word(nbytes);
		if (ptmp) {
			string_to_number(ptmp, procs_running, nullptr, 10);
		}
	}

	if (!to_calc) {
		return 0;
	}
		
	curr_context_switch	= cswitch;

	for (size_t i = 0; i < max_cores_possible; ++i) {
		if (pcpuarr[i].clock_nsec < curr_clock_nsec) {
			noffline++;

			pcpuarr[i].pct_user = 0;
			pcpuarr[i].pct_sys = 0;
			pcpuarr[i].pct_iowait = 0;
		}	

		auto	pcore = pcore_cpu_hist[i];
		
		array_shift_right(pcore.cpu_pct_hist, MAX_SYS_HIST_STATS);

		pcore.cpu_pct_hist[0]		= pcpuarr[i].pct_user + pcpuarr[i].pct_sys;
		cumpct				+= pcpuarr[i].pct_user + pcpuarr[i].pct_sys;
	}	

	array_shift_right(usercpu_pct_hist, MAX_SYS_HIST_STATS);
	array_shift_right(syscpu_pct_hist, MAX_SYS_HIST_STATS);
	array_shift_right(cpu_pct_hist, MAX_SYS_HIST_STATS);
	array_shift_right(fork_hist, MAX_SYS_HIST_STATS);
	array_shift_right(procs_running_hist, MAX_SYS_HIST_STATS);

	usercpu_pct_hist[0]		= overall_stats.pct_user;
	syscpu_pct_hist[0]		= overall_stats.pct_sys;
	cpu_pct_hist[0]			= usercpu_pct_hist[0] + syscpu_pct_hist[0];
	cumul_core_cpu_pct		= cumpct;

	if (curr_cores_online != max_cores_possible - noffline) {
		curr_cores_online		= max_cores_possible - noffline;
		if (curr_cores_online == 0)	curr_cores_online = 1;
	}	

	context_switch_hist[0]		= curr_context_switch;
	fork_hist[0]			= (uint32_t)processes;
	procs_running_hist[0]		= (uint32_t)procs_running;

	cpuhistogram.add_data(cpu_pct_hist[0], tnow, bucketcpu, true /* flush_data */);
	cshistogram.add_data(context_switch_hist[0], tnow, bucket1, true /* flush_data */);
	fork_histogram.add_data(fork_hist[0], tnow, bucket1, true /* flush_data */);
	procs_running_histogram.add_data(procs_running_hist[0], tnow, bucket1, true /* flush_data */);

	return 0;
}	

uint64_t SYS_CPU_STATS::get_diffticks(CPU_ONE_STATS *pnewstats, CPU_ONE_STATS *poldstats) noexcept
{
	uint64_t		ishift = 0;

	if ((pnewstats->cpu_user - pnewstats->cpu_guest) < (poldstats->cpu_user - poldstats->cpu_guest)) {
		/*
		 * Sometimes the nr of jiffies spent in guest mode given by the guest
		 * counter in /proc/stat is slightly higher than that included in
		 * the user counter. Update the interval value accordingly.
		 */
		ishift += (poldstats->cpu_user - poldstats->cpu_guest) - (pnewstats->cpu_user - pnewstats->cpu_guest);
	}
	if ((pnewstats->cpu_nice - pnewstats->cpu_guest_nice) < (poldstats->cpu_nice - poldstats->cpu_guest_nice)) {
		/*
		 * Idem for nr of jiffies spent in guest_nice mode.
		 */
		ishift += (poldstats->cpu_nice - poldstats->cpu_guest_nice) - (pnewstats->cpu_nice - pnewstats->cpu_guest_nice);
	}

	/*
	 * Workaround for CPU coming back online:
	 * Some fields (user, nice, system) restart from their previous value,
	 * whereas others (idle, iowait) restart from zero.
	 */
	if ((pnewstats->cpu_idle < poldstats->cpu_idle) && (poldstats->cpu_idle < (ULONG_MAX - 0x7ffff))) {
		poldstats->cpu_idle = 0;
	}
	if ((pnewstats->cpu_iowait < poldstats->cpu_iowait) && (poldstats->cpu_iowait < (ULONG_MAX - 0x7ffff))) {
		poldstats->cpu_iowait = 0;
	}

	/*
	 * Don't take cpu_guest and cpu_guest_nice into account
	 * because cpu_user and cpu_nice already include them.
	 */
	return (pnewstats->cpu_user    + pnewstats->cpu_nice   + pnewstats->cpu_sys     + pnewstats->cpu_iowait +
		pnewstats->cpu_idle    + pnewstats->cpu_steal  + pnewstats->cpu_hardirq + pnewstats->cpu_softirq) 

	-	(poldstats->cpu_user    + poldstats->cpu_nice   + poldstats->cpu_sys     + poldstats->cpu_iowait +
		 poldstats->cpu_idle    + poldstats->cpu_steal  + poldstats->cpu_hardirq + poldstats->cpu_softirq) 

	+	ishift;
}
	
void SYS_CPU_STATS::calc_cpu_pct(CPU_ONE_STATS *pnewstats, CPU_ONE_STATS *poldstats, uint64_t diffticks) noexcept
{
	if (diffticks == 0) 	diffticks = 1;

	pnewstats->pct_user	= gy_diff_counter_safe(pnewstats->cpu_user + pnewstats->cpu_nice, poldstats->cpu_user + poldstats->cpu_nice) * 100.0f/diffticks;
	pnewstats->pct_sys	= gy_diff_counter_safe(pnewstats->cpu_sys + pnewstats->cpu_hardirq + pnewstats->cpu_softirq, 
							poldstats->cpu_sys + poldstats->cpu_hardirq + poldstats->cpu_softirq) * 100.0f/diffticks;
	pnewstats->pct_iowait	= gy_diff_counter_safe(pnewstats->cpu_iowait, poldstats->cpu_iowait) * 100.0f/diffticks;
	
	*poldstats		= *pnewstats;
}

int SYS_CPU_STATS::get_curr_state(OBJ_STATE_E & cpustate, CPU_ISSUE_SOURCE & cpu_issue, STR_WR_BUF & strbuf, bool update_stats) noexcept
{
	// We check the last 2 states
	int			currpct, lastpct, iowaitpct;
	bool			core_saturated = false, core_in_use = false, iowait_issue = false;	
	TIME_HIST_VAL		cpu_statsarr5[] {75, 95}, cpu_statsarra[] {95}, cs_statsarr5[] {95}, cs_statsarra[] {95, 90}, 
				fork_statsarr5[] {95}, fork_statsarra[] {95}, procs_statsarr5[] {95}, procs_statsarra[] {95};
	int64_t 		tcount5 = 0, tsum5, tcounta = 0, tsuma;
	double 			mean_val5, mean_vala;
	uint64_t		currcs, lastcs, morecs, diffsecs;
	uint32_t		currcore = curr_cores_online, maxforks, maxprocs;
	bool 			is_prolonged;
	 
	currpct			= (int)cpu_pct_hist[0];
	lastpct			= (int)cpu_pct_hist[1];
	iowaitpct 		= (int)overall_stats.pct_iowait;

	currcs			= context_switch_hist[0];
	lastcs			= context_switch_hist[1];
	
	morecs			= std::max(currcs, lastcs);
	maxforks		= std::max(fork_hist[0], fork_hist[1]);
	maxprocs		= std::max(procs_running_hist[0], procs_running_hist[1]);	

	diffsecs		= gy_div_round_near((curr_clock_nsec - last_clock_nsec), GY_NSEC_PER_SEC);
	if (diffsecs == 0)	diffsecs = 1;

	cpuhistogram.get_stats(std::chrono::seconds(300), cpu_statsarr5, GY_ARRAY_SIZE(cpu_statsarr5), tcount5, tsum5, mean_val5);
	cpuhistogram.get_stats(std::chrono::seconds(0), cpu_statsarra, GY_ARRAY_SIZE(cpu_statsarra), tcounta, tsuma, mean_vala);

	fork_histogram.get_stats(std::chrono::seconds(0), fork_statsarra, GY_ARRAY_SIZE(fork_statsarra), tcounta, tsuma, mean_vala);
	procs_running_histogram.get_stats(std::chrono::seconds(0), procs_statsarra, GY_ARRAY_SIZE(procs_statsarra), tcounta, tsuma, mean_vala);
	cshistogram.get_stats(std::chrono::seconds(0), cs_statsarra, GY_ARRAY_SIZE(cs_statsarra), tcounta, tsuma, mean_vala);

	if (update_stats) {
		int64_t 		tc5 = 0, ts5;
		double			m5;
		
		fork_histogram.get_stats(std::chrono::seconds(300), fork_statsarr5, GY_ARRAY_SIZE(fork_statsarr5), tc5, ts5, m5);
		procs_running_histogram.get_stats(std::chrono::seconds(300), procs_statsarr5, GY_ARRAY_SIZE(procs_statsarr5), tc5, ts5, m5);
		cshistogram.get_stats(std::chrono::seconds(300), cs_statsarr5, GY_ARRAY_SIZE(cs_statsarr5), tc5, ts5, m5);

		cpu_p95_		= cpu_statsarra[0].data_value;
		cpu_5min_p95_		= cpu_statsarr5[1].data_value;

		fork_p95_		= fork_statsarra[0].data_value;
		fork_5min_p95_		= fork_statsarr5[0].data_value;

		procs_p95_		= procs_statsarra[0].data_value;
		procs_5min_p95_		= procs_statsarr5[0].data_value;

		cs_p95_			= cs_statsarra[0].data_value;
		cs_5min_p95_		= cs_statsarr5[0].data_value;
	}

	if ((currpct > CPU_SATURATION_PERCENT) || (lastpct > CPU_SATURATION_PERCENT && currpct > CPU_SATURATION_PERCENT >> 1)) {
		if (cpu_statsarr5[0].data_value >= currpct) {
			is_prolonged = true;
		}
		else {
			is_prolonged = false;	
		}		
		
		if (currpct > 95 && lastpct > 95 && tcount5 > 20 && is_prolonged) {
			cpustate 	= STATE_SEVERE;
			cpu_issue	= ISSUE_CPU_SATURATED;
			
			strbuf.appendfmt("State SEVERE : CPU Utilization is saturated at a very high percent %d%%. Last 5 minutes is around %ld%% : Overall p95 is %ld%%.", 
					currpct, cpu_statsarr5[0].data_value, cpu_p95_);
			return 0;
		}
			
		cpustate 	= STATE_BAD;
		cpu_issue	= ISSUE_CPU_SATURATED;

		strbuf.appendfmt("State Bad : CPU Utilization is saturated at a very high percent %d%%. Overall p95 is %ld%%.", currpct, cpu_p95_);

		return 0;
	}	
	
	/*
	 * Now check if any individual cores saturated
	 */
	for (uint32_t i = 0; i < max_cores_possible; ++i) {
		auto 		pcoreh = pcore_cpu_hist + i;
		float		corecurr = pcoreh->cpu_pct_hist[0], corelast = pcoreh->cpu_pct_hist[1];

		if ((corecurr > CPU_SATURATION_PERCENT) || (corelast > CPU_SATURATION_PERCENT && corecurr > CPU_SATURATION_PERCENT >> 1)) {
			core_saturated = true;
			break;
		}	
		else if (corecurr > CPU_LOW_USE_PERCENT && corelast > CPU_LOW_USE_PERCENT) {
			core_in_use = true;
		}	
		else if (core_in_use == false) {
			float		coreio = pcpuarr[i].pct_iowait;

			if (coreio > CPU_IOWAIT_LOW_PERCENT) {
				core_saturated 	= true;
				iowait_issue	= true;
				break;
			}	
		}	
	}
		 
	if (currpct < CPU_LOW_USE_PERCENT && lastpct < CPU_LOW_USE_PERCENT && iowaitpct < CPU_IOWAIT_LOW_PERCENT && morecs <= currcore * 200 * diffsecs) {
		if (core_saturated) {
			strbuf.appendconst("State OK : ");
			cpustate	= STATE_OK;

			if (iowait_issue) {
				cpu_issue	= ISSUE_CPU_IOWAIT;
				strbuf.appendconst("IO Wait is high");
			}
			else {	
				cpu_issue	= ISSUE_CORE_SATURATED;
				strbuf.appendconst("Individual CPU cores are saturated");
			}	
			return 0;
		}
			
		if (currpct < CPU_IDLE_PERCENT && lastpct < CPU_IDLE_PERCENT && core_in_use == false) {
			cpustate	= STATE_IDLE;
			cpu_issue	= ISSUE_CPU_NONE;

			strbuf.appendconst("State Idle : CPU Utilization is very low currently");
			return 0;	
		}
				
		if ((currpct < cpu_p95_ + 5) || (tcounta < 300)) {		
			cpustate	= STATE_GOOD;
			cpu_issue	= ISSUE_CPU_NONE;
			
			strbuf.appendconst("State Good : CPU Utilization is not high currently");
		}
		else {
			cpustate	= STATE_OK;
			cpu_issue	= ISSUE_CPU_NONE;
			
			strbuf.appendfmt("State OK : CPU Utilization %d%% is not high but is higher than p95 %ld%%", currpct, cpu_p95_);
		}	

		return 0;	
	}	

	if (iowaitpct >= CPU_IOWAIT_LOW_PERCENT) {
		if ((currpct > CPU_LOW_USE_PERCENT) || (iowaitpct >= CPU_LOW_USE_PERCENT)) {
			if (iowaitpct >= CPU_SATURATION_PERCENT) {
				cpustate	= STATE_SEVERE;
				cpu_issue	= ISSUE_CPU_IOWAIT;
				
				strbuf.appendconst("State Bad : CPU IO Wait is extremely high currently");
				strbuf.appendfmt(" : %d%%", iowaitpct);
			}	
			else {
				cpustate	= STATE_BAD;
				cpu_issue	= ISSUE_CPU_IOWAIT;
			
				strbuf.appendconst("State Bad : CPU IO Wait is high currently");
				strbuf.appendfmt(" : %d%%", iowaitpct);
			}
			return 0;	
		}	
		else if (morecs <= currcore * 100 * diffsecs) {
			cpustate	= STATE_OK;
			cpu_issue	= ISSUE_CPU_IOWAIT;

			strbuf.appendconst("State OK : CPU IO Wait is slightly high currently");
			return 0;	
		}
	}	
	
	/*
	 * State seems OK. Lets check if Context Switches is too high. If not high, then set STATE_GOOD. 
	 */
	if (morecs > currcore * 150 * diffsecs) {
		// Get all history stats

		if (tcounta > 100) {
			if ((int64_t)morecs > cs_statsarra[1].data_value) {
				if (currpct > CPU_LOW_USE_PERCENT && (int64_t)morecs > cs_statsarra[0].data_value) {
					
					if (morecs > currcore * 5000 * diffsecs) {	
						strbuf.appendconst("State SEVERE : Context Switches is very high currently");
						cpustate	= STATE_SEVERE;
					}
					else {
						strbuf.appendconst("State Bad : Context Switches is high currently");
						cpustate	= STATE_BAD;
					}	
					cpu_issue	= ISSUE_CPU_CONTEXT_SWITCH;
					
					strbuf.appendfmt(" : %lu", morecs);
					return 0;	
				}	
				
				if (currpct > CPU_LOW_USE_PERCENT) {
					if (maxforks > fork_statsarra[0].data_value) {
						strbuf.appendconst("State SEVERE : Context Switches is high and Forked Processes very high currently");
						cpustate	= STATE_SEVERE;
					}
					else {	
						strbuf.appendconst("State Bad : Context Switches is high currently");
						cpustate	= STATE_BAD;
					}
					cpu_issue	= ISSUE_CPU_CONTEXT_SWITCH;
					strbuf.appendfmt(" : %lu", morecs);
					return 0;	
				}
				else if (maxforks > fork_statsarra[0].data_value && maxforks > 50 * diffsecs) {
					strbuf.appendconst("State Bad : Forked Processes is high and Context Switches is high currently");
					cpustate	= STATE_BAD;

					cpu_issue	= ISSUE_FORKS_HIGH;
					strbuf.appendfmt(" : Forks %u CS %lu", maxforks, morecs);
					return 0;	
				}	
				else if (maxprocs > procs_statsarra[0].data_value && maxprocs > 1.5 * currcore) {
					strbuf.appendconst("State Bad : Runnable Processes count is high and Context Switches is high currently");
					cpustate	= STATE_BAD;

					cpu_issue	= ISSUE_PROCS_RUNNING_HIGH;
					strbuf.appendfmt(" : Procs %u CS %lu", maxprocs, morecs);
					return 0;	
				}	
				else {
					strbuf.appendconst("State OK : Context Switches is slightly high currently");

					cpustate	= STATE_OK;
					cpu_issue	= ISSUE_CPU_CONTEXT_SWITCH;
					return 0;	
				}		
			}	
			if (maxforks > fork_statsarra[0].data_value && maxforks > 50 * diffsecs) {
				strbuf.appendconst("State Bad : Forked Processes is high and Context Switches is high currently");
				cpustate	= STATE_BAD;

				cpu_issue	= ISSUE_FORKS_HIGH;
				strbuf.appendfmt(" : %u", maxforks);
				return 0;	
			}	
			else if (maxprocs > procs_statsarra[0].data_value && maxprocs > 1.5 * currcore) {
				strbuf.appendconst("State Bad : Runnable Processes count is high and Context Switches is high currently");
				cpustate	= STATE_BAD;

				cpu_issue	= ISSUE_PROCS_RUNNING_HIGH;
				strbuf.appendfmt(" : %u", maxprocs);
				return 0;	
			}	
		}	

		if (morecs > currcore * 10000 * diffsecs) {
			strbuf.appendconst("State Bad : Context Switches is consistently extremely high currently");

			cpustate	= STATE_BAD;
			cpu_issue	= ISSUE_CPU_CONTEXT_SWITCH;
			strbuf.appendfmt(" : %lu", morecs);
			return 0;	
		}	
		else if (morecs > currcore * 1000 * diffsecs) {
			strbuf.appendconst("State OK : Context Switches is consistently high currently");

			cpustate	= STATE_OK;
			cpu_issue	= ISSUE_CPU_CONTEXT_SWITCH;
			return 0;	
		}	
	}	
	 
	if (core_saturated) {
		strbuf.appendconst("State OK : ");
		cpustate	= STATE_OK;

		if (iowait_issue) {
			cpu_issue	= ISSUE_CPU_IOWAIT;
			strbuf.appendconst("IO Wait is high");
		}
		else {	
			cpu_issue	= ISSUE_CORE_SATURATED;
			strbuf.appendconst("Individual CPU cores are saturated");
		}	
		return 0;
	}

	strbuf.appendconst("State Good : CPU Utilization is not high");

	cpustate	= STATE_GOOD;
	cpu_issue	= ISSUE_CPU_NONE;

	return 0;
}
	
void SYS_CPU_STATS::print_stats(bool print_core_util, bool print_histogram) noexcept
{
	STRING_BUFFER<6000>	strbuf;

	int64_t			diffsecs;

	diffsecs		= gy_div_round_near((curr_clock_nsec - last_clock_nsec), GY_NSEC_PER_SEC);
	if (diffsecs == 0)	diffsecs = 1;

	strbuf.appendfmt(GY_COLOR_YELLOW "\n\tHost CPU Utilization for a duration of %.09f sec : \n", 
		(curr_clock_nsec - last_clock_nsec)/1.0f/GY_NSEC_PER_SEC);

	strbuf.appendfmt("\tHost CPU Util %.03f%% (p95 %ld%% - 5m %ld%%) : User %7.03f%% : System %7.03f%% : IOWait %7.03f%% : All Cores Util %7.03f%% : "
		"Context Switches %lu (%lu/sec) (p95 %ld/sec - 5m %ld/sec) : \n\tCores Online %u : Max Cores %u : Forked Processes %u (%lu/sec) (p95 %ld/sec) : Processes Running %u (p95 %ld)\n", 
		cpu_pct_hist[0], cpu_p95_, cpu_5min_p95_, usercpu_pct_hist[0], syscpu_pct_hist[0], overall_stats.pct_iowait, cumul_core_cpu_pct, 
		curr_context_switch, curr_context_switch/diffsecs, cs_p95_/diffsecs, cs_5min_p95_/diffsecs, curr_cores_online, max_cores_possible, 
		fork_hist[0], fork_hist[0]/diffsecs, fork_p95_/diffsecs, procs_running_hist[0], procs_p95_);

	if (print_core_util) {
		for (uint32_t i = 0; i < max_cores_possible; ++i) {
			strbuf.appendfmt(GY_COLOR_CYAN "\t\t\t\tCPU Core %4d %7.03f%% : User CPU %7.03f%% : System CPU %7.03f%% : IOWait %7.03f%%\n", 
				i, pcpuarr[i].pct_user + pcpuarr[i].pct_sys, pcpuarr[i].pct_user, pcpuarr[i].pct_sys, pcpuarr[i].pct_iowait);
		}	
	}

	if (print_histogram) {
		strbuf.appendconst(GY_COLOR_YELLOW "\n");
		cpuhistogram.get_print_str(strbuf, 99);

		strbuf.appendconst(GY_COLOR_CYAN "\n");
		cshistogram.get_print_str(strbuf, 99);

		strbuf.appendconst(GY_COLOR_BLUE "\n");
		fork_histogram.get_print_str(strbuf, 99);

		strbuf.appendconst(GY_COLOR_YELLOW "\n");
		procs_running_histogram.get_print_str(strbuf, 99);
	}	

	INFOPRINT_OFFLOAD("%.*s" GY_COLOR_RESET "\n", strbuf.sizeint(), strbuf.buffer());
}	

void SYS_CPU_STATS::upd_comm_state(comm::CPU_MEM_STATE_NOTIFY *pcpumem, STR_WR_BUF strbuf) const noexcept
{
	int64_t				diffsecs;

	static_assert(SYS_STAT_COMM_MSEC == SYS_STAT_UPDATE_MSEC * 2, "Madhava Comm Update currently assumed to be alternate records...");

	diffsecs			= gy_div_round_near((curr_clock_nsec - last_clock_nsec), GY_NSEC_PER_SEC);
	if (diffsecs == 0)		diffsecs = 1;

	pcpumem->cpu_pct_		= cpu_pct_hist[0];
	pcpumem->usercpu_pct_		= usercpu_pct_hist[0];
	pcpumem->syscpu_pct_		= syscpu_pct_hist[0];
	pcpumem->iowait_pct_		= overall_stats.pct_iowait;
	pcpumem->cumul_core_cpu_pct_	= cumul_core_cpu_pct;	

	pcpumem->forks_sec_		= (fork_hist[0] + fork_hist[1])/(diffsecs * 2);
	pcpumem->procs_running_		= procs_running_hist[0];
	pcpumem->cs_sec_		= (context_switch_hist[0] + context_switch_hist[1])/(diffsecs * 2);

	pcpumem->cs_p95_sec_		= cs_p95_/diffsecs;
	pcpumem->cs_5min_p95_sec_	= cs_5min_p95_/diffsecs;
	pcpumem->cpu_p95_		= cpu_p95_;
	pcpumem->cpu_5min_p95_		= cpu_5min_p95_;
	pcpumem->fork_p95_sec_		= fork_p95_/diffsecs;
	pcpumem->fork_5min_p95_sec_	= fork_5min_p95_/diffsecs;
	pcpumem->procs_p95_		= procs_p95_;
	pcpumem->procs_5min_p95_	= procs_5min_p95_;

	pcpumem->cpu_state_		= (uint8_t)issue_hist[0].state;
	pcpumem->cpu_issue_		= (uint8_t)issue_hist[0].issue;
	pcpumem->cpu_issue_bit_hist_	= issue_bit_hist;
	pcpumem->cpu_severe_issue_hist_	= severe_issue_bit_hist;
	pcpumem->cpu_state_string_len_	= std::min(strbuf.size(), 254ul);

	if (pcpumem->cpu_state_string_len_) {
		char			*pcpustr = (char *)(pcpumem + 1);

		std::memcpy(pcpustr, strbuf.buffer(), pcpumem->cpu_state_string_len_);
		pcpustr[pcpumem->cpu_state_string_len_] = 0;

		pcpumem->cpu_state_string_len_++;
	}	
}	

int SYS_MEM_STATS::get_mem_stats() noexcept
{
	GY_NOMT_COLLECT_PROFILE(1000, "Host Memory Statistics");

	bool			to_calc;
	int			ret;
	uint64_t		currsec, clock_nsec;
	uint64_t 		pgpgin, pgpgout, pswpin, pswpout, allocstall, pgmajfault, oom_kill;

	clock_nsec 		= get_nsec_clock();

	if (last_clock_nsec && curr_clock_nsec) {
		to_calc = true;

		if (clock_nsec - curr_clock_nsec < GY_NSEC_PER_SEC) {
			// Delay between successive get_mem_stats() too low, probably due to the scheduler object having been overrun
			return 1;
		}
	}
	else {
		to_calc = false;
	}	

	array_shift_right(pct_rss_hist, 	MAX_SYS_HIST_STATS);
	array_shift_right(pct_committed_hist,	MAX_SYS_HIST_STATS);
	array_shift_right(pginout_hist,		MAX_SYS_HIST_STATS);
	array_shift_right(swpinout_hist,	MAX_SYS_HIST_STATS);
	array_shift_right(allocstall_hist,	MAX_SYS_HIST_STATS);
	array_shift_right(pgmajfault_hist,	MAX_SYS_HIST_STATS);
	array_shift_right(oom_kill_hist,	MAX_SYS_HIST_STATS);
		
	last_clock_nsec				= curr_clock_nsec;
	curr_clock_nsec 			= clock_nsec;
	currsec					= clock_nsec / GY_NSEC_PER_SEC;

	ret = get_host_meminfo(&total_memory, &rss_memory, &pct_rss_hist[0], &free_immed_memory, &cached_memory, &locked_memory, 
		&committed_memory, &pct_committed_hist[0], &total_swap, &free_swap);

	if (ret != 0) {
		return ret;
	}
		
	ret = get_host_vmstat(pgpgin, pgpgout, pswpin, pswpout, allocstall, pgmajfault, oom_kill);
	if (ret == 0) {
		if (to_calc) {
			pginout_hist[0] 	= gy_diff_counter_safe(pgpgin + pgpgout, last_pginout);
			swpinout_hist[0] 	= gy_diff_counter_safe(pswpin + pswpout, last_swpinout);
			allocstall_hist[0] 	= gy_diff_counter_safe(allocstall, last_allocstall);
			pgmajfault_hist[0] 	= gy_diff_counter_safe(pgmajfault, last_pgmajfault);
			oom_kill_hist[0] 	= gy_diff_counter_safe(oom_kill, last_oom_kill);

			pct_rss_histogram.add_data(pct_rss_hist[0], currsec);	
			pginout_histogram.add_data(pginout_hist[0], currsec);
			swpinout_histogram.add_data(swpinout_hist[0], currsec);
			allocstall_histogram.add_data(allocstall_hist[0], currsec);
		}	

		last_pginout			= pgpgin + pgpgout;
		last_swpinout			= pswpin + pswpout;
		last_allocstall			= allocstall;
		last_pgmajfault			= pgmajfault;
		last_oom_kill			= oom_kill;
	}	

	return ret;
}	

int SYS_MEM_STATS::get_curr_state(OBJ_STATE_E & memstate, MEM_ISSUE_SOURCE & mem_issue, STR_WR_BUF & strbuf, bool update_stats) noexcept
{
	// We check the last 2 states
	float			currpct, lastpct, commitpct;
	int			maxvalswp, maxvalpg, maxallocstall, maxflt;	
	HIST_DATA 		stats_rss[] {95}, stats_pg[] {95}, stats_swp[] {95}, stats_alloc[] {95};
	size_t 			tcountrss, tcountpg, tcountswp, tcountalloc;
	int			tmax;
	 
	if (oom_kill_hist[0] || oom_kill_hist[1]) {
		
		strbuf.appendconst("State SEVERE : OOM has been triggered recently");

		memstate	= STATE_SEVERE;
		mem_issue	= ISSUE_OOM_KILL;
		
		return 0;	
	}	
	
	currpct		= pct_rss_hist[0];
	lastpct		= pct_rss_hist[1];
	commitpct	= std::max(pct_committed_hist[0], pct_committed_hist[1]);	 

	pct_rss_histogram.get_percentiles(stats_rss, GY_ARRAY_SIZE(stats_rss), tcountrss, tmax);

	maxvalpg 	= std::max(pginout_hist[0], pginout_hist[1]);
	maxvalswp 	= std::max(swpinout_hist[0], swpinout_hist[1]);
	maxallocstall	= std::max(allocstall_hist[0], allocstall_hist[1]);
	maxflt		= std::max(pgmajfault_hist[0], pgmajfault_hist[1]);

	pginout_histogram.get_percentiles(stats_pg, GY_ARRAY_SIZE(stats_pg), tcountpg, tmax);
	swpinout_histogram.get_percentiles(stats_swp, GY_ARRAY_SIZE(stats_swp), tcountswp, tmax);
	allocstall_histogram.get_percentiles(stats_alloc, GY_ARRAY_SIZE(stats_alloc), tcountalloc, tmax);

	if (update_stats) {
		pct_rss_p95_	= stats_rss[0].data_value;
		pginout_p95_	= stats_pg[0].data_value;
		swpinout_p95_	= stats_swp[0].data_value;
		allocstall_p95_	= stats_alloc[0].data_value;
	}

	if (maxallocstall && maxvalpg) {
		if (maxallocstall > stats_alloc[0].data_value) {

			if (maxallocstall > 50 && maxvalswp > 50) {
				strbuf.appendconst("State SEVERE : Large Page Reclaim Stalls, Swapping and Paging Activity");

				if (issue_bit_hist > 0x0F) {
					strbuf.appendconst(" : System may be thrashing");
				}	

				strbuf.appendfmt(" : Reclaim Stalls %d : Swaps %d Paging %d", maxallocstall, maxvalswp, maxvalpg);

				memstate	= STATE_SEVERE;
				mem_issue	= ISSUE_MEM_ALLOCSTALL;

				return 0;
			}	
			else {
				strbuf.appendconst("State Bad : Page Reclaim Stalls and High Paging Activity");
				strbuf.appendfmt(" : Reclaim Stalls %d : Swaps %d Paging %d", maxallocstall, maxvalswp, maxvalpg);

				memstate	= STATE_BAD;
				mem_issue	= ISSUE_MEM_ALLOCSTALL;

				return 0;
			}	
		}	
	}
	
	if (maxvalswp && maxvalpg) {

		if (maxvalpg > stats_pg[0].data_value) {
			strbuf.appendconst("State SEVERE : Large Paging and Swapping Activity");

			memstate	= STATE_SEVERE;
			mem_issue	= ISSUE_MEM_PG_INOUT;

			strbuf.appendfmt(" : Swaps %d Paging %d", maxvalswp, maxvalpg);
			return 0;
		}	
		else if (maxvalswp > stats_swp[0].data_value) {
			strbuf.appendconst("State SEVERE : Large Swapping and Paging Activity");

			memstate	= STATE_SEVERE;
			mem_issue	= ISSUE_MEM_SWP_INOUT;

			strbuf.appendfmt(" : Swaps %d Paging %d", maxvalswp, maxvalpg);
			return 0;
		}	
		
		if (maxallocstall) {
			strbuf.appendconst("State Bad : Page Reclaim Stalls, Swapping and Paging Activity");

			memstate	= STATE_BAD;
			mem_issue	= ISSUE_MEM_ALLOCSTALL;
			strbuf.appendfmt(" : Reclaim Stalls %d : Swaps %d Paging %d", maxallocstall, maxvalswp, maxvalpg);
			return 0;	
		}
		else if (currpct > MEM_RSS_SATURATION_PCT) {
			strbuf.appendconst("State Bad : Page Swapping and Paging Activity along with High RSS Utilization");

			memstate	= STATE_BAD;
			mem_issue	= ISSUE_MEM_SWP_INOUT;
			strbuf.appendfmt(" : Swaps %d Paging %d", maxvalswp, maxvalpg);
			return 0;	
		}
		
		strbuf.appendconst("State OK : Paging and Swapping Activity currently");
		strbuf.appendfmt(" : Swaps %d Paging %d", maxvalswp, maxvalpg);

		memstate	= STATE_OK;
		mem_issue	= ISSUE_MEM_SWP_INOUT;
		return 0;	
	}	
	else if (maxvalpg && maxvalpg > stats_pg[0].data_value) {
		memstate	= STATE_BAD;

		strbuf.appendconst("State Bad : High Paging Activity currently");
		strbuf.appendfmt(" : %d" , maxvalpg);
		
		return 0;	
	}	
	else if (maxvalpg > 100) {
		strbuf.appendconst("State OK : Paging Activity currently");
		strbuf.appendfmt(" : Paging %d", maxvalpg);

		memstate	= STATE_OK;
		mem_issue	= ISSUE_MEM_PG_INOUT;
		return 0;	
	}	
	
	if ((currpct > MEM_RSS_SATURATION_PCT) || (lastpct > MEM_RSS_SATURATION_PCT && currpct > MEM_RSS_SATURATION_PCT >> 1)) {
		if (currpct >= pct_rss_p95_ + 15) {
			strbuf.appendfmt("State Bad : RSS Memory Utilization near saturated %.2f%% : p95 RSS is %ld%%", currpct, pct_rss_p95_);

			mem_issue	= ISSUE_RSS_SATURATED;
			memstate	= STATE_BAD;
			return 0;
		}
		else {
			strbuf.appendconst("State OK : RSS Memory Utilization near saturated");

			mem_issue	= ISSUE_RSS_SATURATED;
			memstate	= STATE_OK;
			return 0;
		}
	}	
	else if (commitpct > MEM_COMMIT_SATURATION_PCT) {
		strbuf.appendconst("State OK : Commit Memory Saturated : OOM may be triggered if more memory needed");

		mem_issue	= ISSUE_COMMIT_SATURATED;
		memstate	= STATE_OK;
		return 0;	
	}
	
	if (free_swap < GY_UP_GB(2) && total_swap >= GY_UP_GB(8)) {
		strbuf.appendconst("State OK : Low Free Swap Space");

		mem_issue	= ISSUE_SWAP_FULL;
		memstate	= STATE_OK;
		return 0;	
	}
		 	
	if ((currpct < MEM_RSS_LOW_USE_PCT) && !maxflt && (maxvalpg < 1000)) {
		strbuf.appendconst("State Idle : Very Low Memory Utilization currently");

		mem_issue	= ISSUE_MEM_NONE;
		memstate	= STATE_IDLE;
		return 0;	
	}	

	strbuf.appendconst("State Good : Low Memory Utilization currently");

	mem_issue	= ISSUE_MEM_NONE;
	memstate	= STATE_GOOD;

	return 0;
}	
	
void SYS_MEM_STATS::print_stats(bool print_histogram) noexcept
{
	STRING_BUFFER<4096>	strbuf;
	
	int64_t			diffsecs;
	float			pctarr[] {95.0f, 99.0f, 25.0f};

	diffsecs		= gy_div_round_near((curr_clock_nsec - last_clock_nsec), GY_NSEC_PER_SEC);
	if (diffsecs == 0)	diffsecs = 1;

	strbuf.appendfmt("\n\tHost Memory Utilization : \n");

	strbuf.appendfmt("\tRSS %lu MB : %% RSS Used %.03f%% (p95 %ld%%) : Total %lu MB : Cached %lu MB : Locked %lu MB : "
			"Committed %lu MB : %% of Committed Used %.03f%% : Swap Free %lu MB : Total Swap %lu MB\n", 
			GY_DOWN_MB(rss_memory), pct_rss_hist[0], pct_rss_p95_, GY_DOWN_MB(total_memory), GY_DOWN_MB(cached_memory), GY_DOWN_MB(locked_memory),
			GY_DOWN_MB(committed_memory), pct_committed_hist[0], GY_DOWN_MB(free_swap), GY_DOWN_MB(total_swap));

	strbuf.appendfmt("\tPageIn + PageOut %d (%ld/sec) (p95 %ld/sec) : SwapIn + SwapOut %d (%ld/sec) (p95 %ld/sec) : Reclaim Stalls %d (%ld/sec) (p95 %ld/sec) : "
			"Major Page Faults %d : OOM Kills %d\n", 
			pginout_hist[0], pginout_hist[0]/diffsecs, pginout_p95_/diffsecs, swpinout_hist[0], swpinout_hist[0]/diffsecs, swpinout_p95_/diffsecs, 
			allocstall_hist[0], allocstall_hist[0]/diffsecs, allocstall_p95_/diffsecs, pgmajfault_hist[0], oom_kill_hist[0]);

	if (print_histogram) {
		strbuf.append('\n');
		pginout_histogram.print_stats(strbuf, pctarr, GY_ARRAY_SIZE(pctarr), "PageInOut");
		strbuf.append('\n');
		swpinout_histogram.print_stats(strbuf, pctarr, GY_ARRAY_SIZE(pctarr), "SwapInOut");
		strbuf.append('\n');
		allocstall_histogram.print_stats(strbuf, pctarr, GY_ARRAY_SIZE(pctarr), "AllocStalls");
	}	
	
	if (pct_rss_hist[0] > MEM_RSS_SATURATION_PCT) {
		strbuf.appendfmt(GY_COLOR_RED "\n\t[WARN]: RSS Memory too high %.03f%% of Total Memory\n", pct_rss_hist[0]);
	}

	if (free_swap < GY_UP_GB(2) && total_swap >= GY_UP_GB(8)) {
		strbuf.appendfmt(GY_COLOR_RED "\n\t[WARN]: Free swap space too low %lu MB\n", GY_DOWN_MB(free_swap));	
	}
				
	if (swpinout_hist[0] > 10) {
		strbuf.appendfmt(GY_COLOR_RED "\n\t[WARN]: Process Page Swapping is active : %d pages\n", swpinout_hist[0]);	
	}			

	if (allocstall_hist[0] > 10) {
		strbuf.appendfmt(GY_COLOR_RED "\n\t[WARN]: Process Stalls for Page Reclaims is active : %d pages\n", allocstall_hist[0]);	
	}			

	if (oom_kill_hist[0]) {
		strbuf.appendfmt(GY_COLOR_RED "\n\t[WARN]: %d process(es) were OOM Killed...\n", oom_kill_hist[0]);	
	}	
			
	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "%.*s\n", strbuf.sizeint(), strbuf.buffer());
}
	
void SYS_MEM_STATS::upd_comm_state(comm::CPU_MEM_STATE_NOTIFY *pcpumem, STR_WR_BUF strbuf) const noexcept
{
	int64_t				diffsecs;

	static_assert(SYS_STAT_COMM_MSEC == SYS_STAT_UPDATE_MSEC * 2, "Madhava Comm Update currently assumed to be alternate records...");

	diffsecs			= gy_div_round_near((curr_clock_nsec - last_clock_nsec), GY_NSEC_PER_SEC);
	if (diffsecs == 0)		diffsecs = 1;

	pcpumem->rss_pct_		= pct_rss_hist[0];
	pcpumem->rss_memory_mb_		= GY_DOWN_MB(rss_memory);
	pcpumem->total_memory_mb_	= GY_DOWN_MB(total_memory);
	pcpumem->cached_memory_mb_	= GY_DOWN_MB(cached_memory);
	pcpumem->locked_memory_mb_	= GY_DOWN_MB(locked_memory);
	pcpumem->committed_memory_mb_	= GY_DOWN_MB(committed_memory);
	pcpumem->committed_pct_		= pct_committed_hist[0];
	pcpumem->swap_free_mb_		= GY_DOWN_MB(free_swap);
	pcpumem->swap_total_mb_		= GY_DOWN_MB(total_swap);

	pcpumem->pg_inout_sec_		= (pginout_hist[0] + pginout_hist[1])/(diffsecs * 2);
	pcpumem->swap_inout_sec_	= (swpinout_hist[0] + swpinout_hist[1])/(diffsecs * 2);
	pcpumem->reclaim_stalls_	= allocstall_hist[0] + allocstall_hist[1];
	pcpumem->pgmajfault_		= pgmajfault_hist[0] + pgmajfault_hist[1];
	pcpumem->oom_kill_		= oom_kill_hist[0] + oom_kill_hist[1];

	pcpumem->rss_pct_p95_		= pct_rss_p95_;
	pcpumem->pginout_p95_		= pginout_p95_;
	pcpumem->swpinout_p95_		= swpinout_p95_;
	pcpumem->allocstall_p95_	= allocstall_p95_;

	pcpumem->mem_state_		= (uint8_t)issue_hist[0].state;
	pcpumem->mem_issue_		= (uint8_t)issue_hist[0].issue;
	pcpumem->mem_issue_bit_hist_	= issue_bit_hist;
	pcpumem->mem_severe_issue_hist_	= severe_issue_bit_hist;

	pcpumem->mem_state_string_len_	= std::min(strbuf.size(), 254ul);

	if (pcpumem->mem_state_string_len_) {
		char			*pmemstr = (char *)((char *)pcpumem + sizeof(*pcpumem) + pcpumem->cpu_state_string_len_);

		std::memcpy(pmemstr, strbuf.buffer(), pcpumem->mem_state_string_len_);
		pmemstr[pcpumem->mem_state_string_len_] = 0;

		pcpumem->mem_state_string_len_++;
	}	
}


static SYSTEM_STATS			*pgsystemstats = nullptr;
static SYS_CPU_STATS			*pgsyscpustats = nullptr;

SYS_CPU_STATS * SYS_CPU_STATS::get_singleton() noexcept
{
	if (pgsystemstats) {
		return &pgsystemstats->cpustats;
	}	

	return pgsyscpustats;
}	

/*
 * Call this only if you need just the CPU stats and no Memory stats
 */
int SYS_CPU_STATS::init_singleton(uint32_t delay_seconds)
{
	int				texp = 0, tdes = 1;
	static std::atomic<int>		is_init_done(0);

	assert(delay_seconds);

	if (false == is_init_done.compare_exchange_strong(texp, tdes)) {
		return 0;
	}

	GY_SCHEDULER::init_singleton_maintenance(false);

	auto schedshrmain = GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_MAINTENANCE);

	if (!schedshrmain) {
		GY_THROW_EXCEPTION("Global Scheduler Shared object not yet initialized");
	}	
	 
	try {
		pgsyscpustats = new SYS_CPU_STATS();

		schedshrmain->add_schedule(delay_seconds * GY_MSEC_PER_SEC, delay_seconds * GY_MSEC_PER_SEC, 0, "Get Host CPU statistics", 
		[pcpu = pgsyscpustats] { 
			pcpu->get_cpu_stats();
			pcpu->print_stats(false /* print_core_util */, false /* print_histogram */);
		});
		
		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT("Exception caught while creating global CPU Util stats object ... : %s\n", GY_GET_EXCEPT_STRING);
		throw;
	);	
}	


SYS_MEM_STATS * SYS_MEM_STATS::get_singleton() noexcept
{
	if (pgsystemstats) {
		return &pgsystemstats->memstats;
	}	

	return nullptr;
}	

SYSTEM_STATS * SYSTEM_STATS::get_singleton() noexcept
{
	return pgsystemstats;
}
	
int SYSTEM_STATS::init_singleton()
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

	/*
	 * Keep the same Scheduler thread as the Task Stats and TCP Listeners Stats updation thread i.e. SCHEDULER_HIGH_PRIO
	 */
	auto schedshrprio = GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_HIGH_PRIO);

	if (!schedshrprio) {
		GY_THROW_EXCEPTION("Global Scheduler Shared object not yet initialized");
	}	
	 
	try {
		pgsystemstats = new SYSTEM_STATS();

		/*
		 * Schedule a periodic 2 sec check for CPU/Memory statistics on a 5 sec boundary
		 */
		time_t			tcurr = time(nullptr), tnxt = (tcurr / 5) * 5;
		uint64_t		startmsec = 5116 + 5000 - (tcurr - tnxt) * 1000;

		schedshrprio->add_schedule(startmsec, SYS_STAT_UPDATE_MSEC /* 2000 */, 0, "Get Host CPU Memory Util statistics", 
		[psys = pgsystemstats, sendstats = false] () mutable 
		{ 
			GY_NOMT_COLLECT_PROFILE(1000, "Host CPU / Memory Statistics Collection and send");

			using namespace				comm;

			void					*palloc = nullptr;
			constexpr size_t			fixedsz = sizeof(comm::COMM_HEADER) + sizeof(comm::EVENT_NOTIFY) + CPU_MEM_STATE_NOTIFY::get_max_elem_size();
			std::shared_ptr<SERVER_CONNTRACK>	shrp;
			SERVER_COMM				*pser = nullptr;
			int					ret;

			if (sendstats) {
				pser = SERVER_COMM::get_singleton();

				if (pser) {
					shrp = pser->get_server_conn(comm::CLI_TYPE_REQ_ONLY);

					if (shrp) {
						palloc 	= ::malloc(fixedsz);
					}
				}
			}

			COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
			EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1); 
			CPU_MEM_STATE_NOTIFY		*pcpumem = reinterpret_cast<CPU_MEM_STATE_NOTIFY *>(pnot + 1);

			ret = psys->get_stats(palloc ? pcpumem : nullptr);

			if (palloc) {
				if (ret != 0) {
					::free(palloc);
				}
				else {
					size_t		newsz;

					pcpumem->set_padding_len();
					newsz = sizeof(comm::COMM_HEADER) + sizeof(comm::EVENT_NOTIFY) + pcpumem->get_elem_size();

					new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, newsz, pser->get_conn_magic());
					new (pnot) EVENT_NOTIFY(comm::NOTIFY_CPU_MEM_STATE, 1);	
					
					pser->send_server_data(EPOLL_IOVEC_ARR(2, false, phdr, phdr->get_act_len(), ::free, pser->gpadbuf, phdr->get_pad_len(), nullptr), 
									comm::CLI_TYPE_REQ_ONLY, COMM_EVENT_NOTIFY, shrp);
				}
			}	

			sendstats = !sendstats;
		});
		
		/*
		 * Schedule a periodic 10 sec print of statistics
		 */
		schedshrprio->add_schedule(10'000 + startmsec + 5, 10'000, 0, "Print CPU Memory Util statistics", 
		[psys = pgsystemstats, nstatsprints = (int)0] () mutable 
		{ 
			psys->print_stats(false);

			CONDEXEC(
				bool print_hist = ({
							++nstatsprints; 
							bool 	bret = false; 

							if (nstatsprints > 30) {
								bret = true; 
								nstatsprints = 0;
							} 
							bret;
						}); 

				if (print_hist) {
					float		pctarr[] {95.0f, 99.0f, 25.0f};

					STRING_BUFFER<2000>	strbuf;

					psys->cpustats.cpuhistogram.get_print_str(strbuf, 99);

					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Host CPU Util histogram : \n%.*s\n", strbuf.sizeint(), strbuf.buffer());

					strbuf.reset();

					psys->memstats.pginout_histogram.print_stats(strbuf, pctarr, GY_ARRAY_SIZE(pctarr), "PageInOut");
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Host PageIn/PageOut histogram : \n%.*s\n", strbuf.sizeint(), strbuf.buffer());
				}	
			);
		});

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT("Exception caught while creating global CPU / Memory Util stats object ... : %s\n", GY_GET_EXCEPT_STRING);
		throw;
	);	
}	

} // namespace gyeeta
	
