
#include		"gy_task_stat.h"
#include		"gy_cgroup_stat.h"
#include		"gy_sys_hardware.h"
#include		"gy_acct_taskstat.h"
#include		"gy_socket_stat.h"

#include 		<linux/netlink.h>
#include 		<linux/connector.h>
#include 		<linux/cn_proc.h>

namespace gyeeta {

char * get_escaped_comm(char (&comm)[TASK_COMM_LEN], const char *pcomm) noexcept
{
	char			*ptmp = comm, *pend = comm + TASK_COMM_LEN - 1, c;

	while (ptmp < pend) {
		c = *pcomm++;

		if (c == 0) {
			break;
		}	
		else if (c == '\'') {
			c = '_';
		}	

		*ptmp++ = c;
	}

	*ptmp = 0;
	return comm;
}	

char * get_escaped_comm(char (&comm)[TASK_COMM_LEN], const char *pcomm, uint32_t len) noexcept
{
	char			*ptmp = comm, *pend = comm + std::min<uint32_t>(TASK_COMM_LEN - 1, len), c;

	while (ptmp < pend) {
		c = *pcomm++;

		if (c == '\'') {
			c = '_';
		}	

		*ptmp++ = c;
	}

	*ptmp = 0;
	return comm;
}	


TASK_DELAY_STATS::TASK_DELAY_STATS(TASK_STAT *pthis, bool is_kubernetes, uint64_t clock_nsec) 
	: cpu_delay_histogram_(clock_nsec), blkio_delay_histogram_(clock_nsec), vol_cs_histogram_(clock_nsec), invol_cs_histogram_(clock_nsec)
{
	(void)pthis->get_set_aggr_id();

	if (is_kubernetes) {
		bool		bret = get_k8s_podname(pthis->task_pid, tagbuf_, sizeof(tagbuf_));

		if (bret) {
			tag_len_ = strlen(tagbuf_);

			if (tag_len_) {
				pthis->is_tags_seen = true;
			}	
		}	
	}	
}	

TASK_EXT_STATS::TASK_EXT_STATS(TASK_STAT *pthis) 
	: cpu_mem_io_(pthis->task_pid), pthis_obj_(pthis)
{
	GY_CAPABILITIES			taskcap(pthis->task_pid);

	taskcap.set_cap_bitflags(cap_flag_);
			
	pthis_obj_->is_high_cap = cap_flag_.is_elevated_cap;

	if (cap_flag_.is_elevated_cap) {
		CONDEXEC(
			DEBUGEXECN(11, INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN_UNDERLINE, 
				"PID %d (%s) (UID %d) has elevated capabilities 0x%08X : is_cap_net_admin %d : is_cap_sys_admin %d\n",
					pthis_obj_->task_pid, pthis_obj_->task_comm, pthis_obj_->task_effuid, 
					cap_flag_.is_elevated_cap, cap_flag_.is_cap_net_admin, cap_flag_.is_cap_sys_admin);
			);
		);
	}		
}	

char * TASK_EXT_STATS::print_stats(STR_WR_BUF & strbuf) const noexcept
{
	const float		pctarr[] = {95, 99, 25};
	int			max_cpu;
	size_t			total_val;
	uint64_t		last_total;
	OBJ_STATE_E		taskstate;
	TASK_ISSUE_SOURCE	task_issue;	

	cpu_pct_histogram_.get_total_max(total_val, max_cpu);
	if (max_cpu > 0) {
		strbuf.appendconst("\n\tProcess CPU Utilization Histogram follows : ");
		cpu_pct_histogram_.print_stats(strbuf, pctarr, GY_ARRAY_SIZE(pctarr), "CPU %%", GY_NSEC_PER_SEC);
	}

	if (pdelay_stats_) {
		pdelay_stats_->print_stats(strbuf);
	}	

	if ((last_total = array_summ(cpu_mem_io_.majflt_hist, PROC_CPU_IO_STATS::MAX_PROC_HIST_STATS))) {
		strbuf.appendfmt("\n\n\tProcess has incurred %lu Major Page Faults in the last few seconds\n\n", last_total);
	}
	else {
		strbuf.append('\n');
	}	

	strbuf.append('\t');
	
	if (max_cpu > 0) {
		cpu_mem_io_.print_current(strbuf, (get_usec_time() - pthis_obj_->starttimeusec) / GY_USEC_PER_SEC, pthis_obj_->task_comm);
		strbuf.appendconst("\n\t");
	}	

	if (ntcp_bytes_) {
		strbuf.appendfmt("Process Total TCP Connections %lu TCP Bytes %lu (%lu KB)\n\t", ntcp_conn_, ntcp_bytes_, GY_DOWN_KB(ntcp_bytes_));
	}	
	
	strbuf.appendfmt("Process Issue Recent History %02hhx\n\t", (issue_bit_hist_ & 0x3F));

	STRING_BUFFER<128>	sbuf;

	get_curr_state(taskstate, task_issue, sbuf);
	
	switch (taskstate) {
	
	case STATE_IDLE 	:	strbuf.appendconst(GY_COLOR_BOLD_GREEN); break;
	case STATE_GOOD 	:	strbuf.appendconst(GY_COLOR_GREEN); break;
	case STATE_OK 		:	strbuf.appendconst(GY_COLOR_YELLOW); break;
	case STATE_BAD 		:	strbuf.appendconst(GY_COLOR_RED); break;
	case STATE_SEVERE 	:	strbuf.appendconst(GY_COLOR_BOLD_RED); break;

	default			: 	break;		
	}	

	strbuf.append(sbuf);
	
	strbuf.appendconst(GY_COLOR_RESET);

	return strbuf.buffer();
}	 

void TASK_EXT_STATS::update_stats() noexcept
{
	int			last_pct;

	cpu_mem_io_.get_current_stats(false);
	
	last_pct = (int)(cpu_mem_io_.usercpu_pct_hist[0] + cpu_mem_io_.syscpu_pct_hist[0]);

	cpu_pct_histogram_.add_data(last_pct, cpu_mem_io_.get_last_stats_time());
}	

int TASK_EXT_STATS::get_curr_state(OBJ_STATE_E & taskstate, TASK_ISSUE_SOURCE & task_issue, STR_WR_BUF & strbuf, uint64_t clock_nsec) const noexcept
{
	if ((int64_t)clock_nsec - (int64_t)cpu_mem_io_.get_last_stats_time() > (int64_t)GY_NSEC_PER_SEC * 15) {	
		// No recent records	
		taskstate 	= STATE_IDLE;
		task_issue	= ISSUE_TASK_NONE;

		strbuf.appendconst("No recent stats available");
		return -1;
	}

	uint64_t		max_cpu_delay = 0, max_blkio_delay = 0, max_swapin_delay = 0, max_reclaim_delay = 0, max_thrashing_delay = 0, max_compact_delay = 0,
				max_vol_cs = 0, max_invol_cs, delay_secs;

	HIST_DATA 		hist_data_1[] {95}, hist_data_2[] {95, 99.9}; 
	size_t 			total_count;
	int 			max_val;
	int			is_cpu_delay = 0, is_blkio_delay = 0, is_swapin_delay = 0, is_reclaim_delay = 0, is_thrashing_delay = 0, is_vol_cs = 0, is_invol_cs = 0;
		 
	delay_secs		= gy_div_round_near((pdelay_stats_->delay_clock_nsec_[0] - pdelay_stats_->delay_clock_nsec_[1]), GY_NSEC_PER_SEC);

	if (delay_secs == 0) {
		delay_secs	= 1;
	}	

	auto lfltmax = [](float currval, float prevval) noexcept -> float
	{
		if (currval >= prevval) return currval;

		// Use the prevval if currval is at least half the prevval
		if (currval * 2 > prevval) {
			return prevval;
		}	

		return currval;
	};	


	auto lintmax = [](uint64_t currval, uint64_t prevval) noexcept -> uint64_t
	{
		if (currval >= prevval) return currval;

		// Use the prevval if currval is at least half the prevval
		if (currval > (prevval >> 1)) {
			return prevval;
		}	

		return currval;
	};	

	if (!pdelay_stats_) {
		goto no_delay;
	}
	
	max_cpu_delay 		= lintmax(pdelay_stats_->cpu_delay_nsec_[0], pdelay_stats_->cpu_delay_nsec_[1]);
	max_blkio_delay		= lintmax(pdelay_stats_->blkio_delay_nsec_[0], pdelay_stats_->blkio_delay_nsec_[1]);
	max_swapin_delay	= lintmax(pdelay_stats_->swapin_delay_nsec_[0], pdelay_stats_->swapin_delay_nsec_[1]);
	max_reclaim_delay	= lintmax(pdelay_stats_->reclaim_delay_nsec_[0], pdelay_stats_->reclaim_delay_nsec_[1]);
	max_thrashing_delay	= lintmax(pdelay_stats_->thrashing_delay_nsec_[0], pdelay_stats_->thrashing_delay_nsec_[1]);
	max_compact_delay	= lintmax(pdelay_stats_->compact_delay_nsec_[0], pdelay_stats_->compact_delay_nsec_[1]);
	max_vol_cs		= lintmax(pdelay_stats_->vol_cs_[0], pdelay_stats_->vol_cs_[1]);
	max_invol_cs		= lintmax(pdelay_stats_->invol_cs_[0], pdelay_stats_->invol_cs_[1]);
	
	if (gy_unlikely(pthis_obj_->is_ptrace_active)) {
		taskstate 	= STATE_BAD;
		task_issue 	= ISSUE_TASK_PTRACED;

		strbuf.appendconst("State Bad : Process is under Kernel Suspension or ptrace debugging");
		return 0;
	}
	else if (gy_unlikely(cpu_mem_io_.task_stopped_int)) {
		/*
		 * We need to check if the task_stopped_hist[] contains a 'D' or a 'T'. If 'D', flag only if more than 1 'D'
		 */
		int		nds = 0;
			 
		for (int i = 0; i < cpu_mem_io_.MAX_PROC_HIST_STATS; ++i) {
			if (cpu_mem_io_.task_stopped_hist[i] == 'T') {
				nds = 100;
				break;	
			}		
			else if (cpu_mem_io_.task_stopped_hist[i] == 'D') {
				nds++;
			}	
		}	 
		if (nds > 1) {
			if (nds != 100) {

				if (max_reclaim_delay >= GY_NSEC_PER_MSEC) {
					
					taskstate 	= STATE_SEVERE;
					task_issue 	= ISSUE_RECLAIM_DELAY;

					strbuf.appendconst("State SEVERE : Process was suspended by the kernel due to Memory Page Reclaiming");
					strbuf.appendfmt(" : Reclaim Delay %lu msec", max_reclaim_delay/GY_NSEC_PER_MSEC);
				}	 
				else if (max_thrashing_delay >= GY_NSEC_PER_MSEC) {
					
					taskstate 	= STATE_SEVERE;
					task_issue 	= ISSUE_THRASHING_DELAY;

					strbuf.appendconst("State SEVERE : Process was suspended by the kernel due to Memory Thrashing");
					strbuf.appendfmt(" : Thrashing Delay %lu msec", max_thrashing_delay/GY_NSEC_PER_MSEC);
				}	 
				else {
					taskstate 	= STATE_BAD;
					task_issue 	= ISSUE_TASK_STOPPED;

					strbuf.appendconst("State Bad : Process was suspended by the kernel");
				}

			}	
			else {
				if ((pthis_obj_->task_rt_priority > 0) || (pthis_obj_->is_tcp_server)) {
					taskstate 	= STATE_SEVERE;
					strbuf.appendconst("State SEVERE : Process was stopped by a signal");
				}
				else {
					taskstate 	= STATE_BAD;
					strbuf.appendconst("State Bad : Process was stopped by a signal");
				}

				task_issue 	= ISSUE_TASK_STOPPED;
			}

			return 0;
		}
	}	

	if (max_swapin_delay > 10 * GY_NSEC_PER_MSEC) {
		if (max_swapin_delay > 10 * GY_NSEC_PER_MSEC * delay_secs && max_swapin_delay > max_cpu_delay && max_swapin_delay > max_blkio_delay && max_swapin_delay > max_reclaim_delay) {
			if (max_swapin_delay > delay_secs * 1000 * GY_NSEC_PER_MSEC) {

				taskstate 	= STATE_SEVERE;
				task_issue 	= ISSUE_SWAPIN_DELAY;

				strbuf.appendconst("State SEVERE : Process Swapin Delay is very high");
				strbuf.appendfmt(" : %lu msec", max_swapin_delay/GY_NSEC_PER_MSEC);
				return 0;
			}

			taskstate 	= STATE_BAD;
			task_issue 	= ISSUE_SWAPIN_DELAY;

			strbuf.appendconst("State Bad : Process Swapin Delay is high");
			strbuf.appendfmt(" : %lu msec", max_swapin_delay/GY_NSEC_PER_MSEC);
			return 0;
		}	
		is_swapin_delay	= 1;
	}	
		
	if (max_reclaim_delay > 10 * GY_NSEC_PER_MSEC) {
		if (max_reclaim_delay > 10 * GY_NSEC_PER_MSEC * delay_secs && max_reclaim_delay > max_cpu_delay && max_reclaim_delay > max_blkio_delay && max_reclaim_delay > max_thrashing_delay) {
			if (max_reclaim_delay > delay_secs * 1000 * GY_NSEC_PER_MSEC) {

				taskstate 	= STATE_SEVERE;
				task_issue 	= ISSUE_RECLAIM_DELAY;

				strbuf.appendconst("State SEVERE : Process Reclaim Delay is very high");
				strbuf.appendfmt(" : %lu msec", max_swapin_delay/GY_NSEC_PER_MSEC);
				return 0;
			}

			taskstate 	= STATE_BAD;
			task_issue 	= ISSUE_RECLAIM_DELAY;

			strbuf.appendconst("State Bad : Process Reclaim Delay is high");
			strbuf.appendfmt(" : %lu msec", max_reclaim_delay/GY_NSEC_PER_MSEC);
			return 0;
		}	
		is_reclaim_delay = 1;
	}	

	if (max_thrashing_delay > 10 * GY_NSEC_PER_MSEC) {
		if (max_thrashing_delay > 10 * GY_NSEC_PER_MSEC * delay_secs && max_thrashing_delay > max_cpu_delay && max_thrashing_delay > max_blkio_delay) {
			if (max_thrashing_delay > delay_secs * 1000 * GY_NSEC_PER_MSEC) {

				taskstate 	= STATE_SEVERE;
				task_issue 	= ISSUE_THRASHING_DELAY;

				strbuf.appendconst("State SEVERE : Process Thrashing Delay is very high");
				strbuf.appendfmt(" : %lu msec", max_thrashing_delay/GY_NSEC_PER_MSEC);
				return 0;
			}

			taskstate 	= STATE_BAD;
			task_issue 	= ISSUE_THRASHING_DELAY;

			strbuf.appendconst("State Bad : Process Thrashing Delay is high");
			strbuf.appendfmt(" : %lu msec", max_thrashing_delay/GY_NSEC_PER_MSEC);
			return 0;
		}	
		is_thrashing_delay = 1;
	}	

	if (max_cpu_delay > 10 * GY_NSEC_PER_MSEC) {
		pdelay_stats_->cpu_delay_histogram_.get_percentiles(hist_data_1, GY_ARRAY_SIZE(hist_data_1), total_count, max_val);

		if (max_cpu_delay/GY_NSEC_PER_MSEC > (uint64_t)hist_data_1[0].data_value && total_count > 50) {
			if (max_cpu_delay > delay_secs * 5000 * GY_NSEC_PER_MSEC) {
				// More than 5 threads could be throttled
				taskstate 	= STATE_SEVERE;
				task_issue 	= ISSUE_CPU_DELAY;

				strbuf.appendconst("State SEVERE : Process CPU Delay is very high");
				strbuf.appendfmt(" : %lu msec", max_cpu_delay/GY_NSEC_PER_MSEC);
				return 0;
			}
			else {		
				taskstate 	= STATE_BAD;
				task_issue 	= ISSUE_CPU_DELAY;

				strbuf.appendconst("State Bad : Process CPU Delay is high");
				strbuf.appendfmt(" : %lu msec", max_cpu_delay/GY_NSEC_PER_MSEC);
				return 0;
			}	
		}	
		else {
			is_cpu_delay = 1;
		}	
	}		

	if (max_blkio_delay > 10 * GY_NSEC_PER_MSEC) {
		pdelay_stats_->blkio_delay_histogram_.get_percentiles(hist_data_1, GY_ARRAY_SIZE(hist_data_1), total_count, max_val);

		if (max_blkio_delay/GY_NSEC_PER_MSEC > (uint64_t)hist_data_1[0].data_value && total_count > 50) {
			if (max_blkio_delay > delay_secs * 1000 * GY_NSEC_PER_MSEC) {

				taskstate 	= STATE_SEVERE;
				task_issue 	= ISSUE_BLKIO_DELAY;

				strbuf.appendconst("State SEVERE : Process Blkio Delay is very high");
				strbuf.appendfmt(" : %lu msec", max_blkio_delay/GY_NSEC_PER_MSEC);
				return 0;
				
			}
			else {		
				taskstate 	= STATE_BAD;
				task_issue 	= ISSUE_BLKIO_DELAY;

				strbuf.appendconst("State Bad : Process Blkio Delay is high");
				strbuf.appendfmt(" : %lu msec", max_blkio_delay/GY_NSEC_PER_MSEC);
				return 0;
			}	
		}	
		else {
			is_blkio_delay = 1;
		}	
	}		

	if ((is_cpu_delay || is_blkio_delay) && (is_reclaim_delay || is_thrashing_delay)) {
		taskstate 	= STATE_BAD;
		task_issue 	= is_reclaim_delay ? ISSUE_RECLAIM_DELAY : ISSUE_THRASHING_DELAY;

		strbuf.appendconst("State Bad : Process Multiple Delays CPU/Blkio Delays with Reclaim/Thrashing");
		strbuf.appendfmt(" : cpu %lu msec : blkio %lu msec : reclaim %lu msec : thrashing %lu msec", 
			max_cpu_delay/GY_NSEC_PER_MSEC, max_blkio_delay/GY_NSEC_PER_MSEC, max_reclaim_delay/GY_NSEC_PER_MSEC, max_thrashing_delay/GY_NSEC_PER_MSEC);
		return 0;
	}	

	if (max_vol_cs > 500) {
		pdelay_stats_->vol_cs_histogram_.get_percentiles(hist_data_2, GY_ARRAY_SIZE(hist_data_2), total_count, max_val);

		if ((int64_t)max_vol_cs > hist_data_2[0].data_value && total_count > 100) {
			if ((max_vol_cs > 10000 * delay_secs) && (int64_t)max_vol_cs > hist_data_2[1].data_value) {

				taskstate 	= STATE_SEVERE;
				task_issue 	= ISSUE_VOL_CONTEXT_SWITCH;

				strbuf.appendconst("State SEVERE : Process Voluntary Context Switches are very high");
				strbuf.appendfmt(" : %lu", max_vol_cs);
				return 0;
			}
			else if (is_cpu_delay && max_vol_cs > 2000 * delay_secs) {		
				taskstate 	= STATE_BAD;
				task_issue 	= ISSUE_VOL_CONTEXT_SWITCH;

				strbuf.appendconst("State Bad : Process Voluntary Context Switches are high");
				strbuf.appendfmt(" : %lu", max_vol_cs);
				return 0;
			}	
		}	
		else if (max_vol_cs > 10000 * delay_secs && max_cpu_delay > max_blkio_delay) {
			taskstate 	= STATE_OK;
			task_issue 	= ISSUE_VOL_CONTEXT_SWITCH;

			strbuf.appendconst("State OK : Process has consistently high Voluntary Context Switches");
			return 0;
		}	
		else {
			is_vol_cs = 1;
		}	
	}		

	if (max_invol_cs) {
		pdelay_stats_->invol_cs_histogram_.get_percentiles(hist_data_2, GY_ARRAY_SIZE(hist_data_2), total_count, max_val);

		if ((int64_t)max_invol_cs > hist_data_2[0].data_value && total_count > 100) {
			if ((max_invol_cs > 1000 * delay_secs) && (int64_t)max_invol_cs > hist_data_2[1].data_value && max_cpu_delay > 100 * GY_NSEC_PER_MSEC) {

				taskstate 	= STATE_SEVERE;
				task_issue 	= ISSUE_INVOL_CONTEXT_SWITCH;

				strbuf.appendconst("State SEVERE : Process Involuntary Context Switches are very high");
				strbuf.appendfmt(" : %lu", max_invol_cs);
				return 0;
			}
			else if (max_invol_cs > 50 * delay_secs && max_cpu_delay > delay_secs * 20 * GY_NSEC_PER_MSEC) {		
				taskstate 	= STATE_BAD;
				task_issue 	= ISSUE_INVOL_CONTEXT_SWITCH;

				strbuf.appendconst("State Bad : Process Involuntary Context Switches are high");
				strbuf.appendfmt(" : %lu", max_invol_cs);
				return 0;
			}	
		}	
		else if (max_invol_cs > 100 * delay_secs && is_cpu_delay && max_cpu_delay > max_blkio_delay) {
			taskstate 	= STATE_OK;
			task_issue 	= ISSUE_INVOL_CONTEXT_SWITCH;

			strbuf.appendconst("State OK : Process has consistently high Involuntary Context Switches");
			return 0;
		}	
		else {
			is_invol_cs = 1;
		}	
	}		

no_delay :

	float			max_cpu_pct, max_blkio_pct;
	int16_t			max_majflt;
	
	max_cpu_pct		= lfltmax(cpu_mem_io_.usercpu_pct_hist[0] + cpu_mem_io_.syscpu_pct_hist[0], 
						cpu_mem_io_.usercpu_pct_hist[1] + cpu_mem_io_.syscpu_pct_hist[1]);

	max_blkio_pct		= lfltmax(cpu_mem_io_.blkiodelay_pct_hist[0], cpu_mem_io_.blkiodelay_pct_hist[1]);

	max_majflt		= lfltmax(cpu_mem_io_.majflt_hist[0], cpu_mem_io_.majflt_hist[1]);

	if (max_majflt > 0) {
		if (((is_cpu_delay || is_blkio_delay) && (is_vol_cs)) || (max_majflt > 10)) {
			taskstate 	= STATE_BAD;
			task_issue 	= ISSUE_MAJOR_PAGE_FAULT;

			strbuf.appendconst("State Bad : Process Has encountered Major Page Faults");
			strbuf.appendfmt(" : %d", max_majflt);
			return 0;
		}	
	}
	else if (max_cpu_pct >= pthis_obj_->ncpus_allowed * 100 * 0.9) {
		if (is_invol_cs) {
			taskstate 	= STATE_BAD;
			task_issue 	= ISSUE_CPU_UTIL_HIGH;

			strbuf.appendconst("State Bad : Process CPU Utilization has reached Saturation level : Any sudden increase will cause delays");
			strbuf.appendfmt(" : %.3f%%", max_cpu_pct);
			return 0;
		}	

		taskstate 	= STATE_OK;
		task_issue 	= ISSUE_CPU_UTIL_HIGH;

		strbuf.appendconst("State OK : Process CPU Utilization has reached Saturation level : Any sudden increase will cause delays");
		strbuf.appendfmt(" : %.3f%%", max_cpu_pct);
		return 0;
	}	
	else if (max_blkio_pct > CPU_IOWAIT_LOW_PERCENT) {
		if (is_blkio_delay && is_vol_cs && is_cpu_delay) {				
			taskstate 	= STATE_OK;
			task_issue 	= ISSUE_BLKIO_DELAY;

			strbuf.appendconst("State OK : Process Has a large Blkio Delay");
			strbuf.appendfmt(" : %.3f%%", max_blkio_pct);
			return 0;
		}	
	}	

	if (is_cpu_delay || is_blkio_delay) {
		if (max_cpu_delay > max_blkio_delay) {
			taskstate 	= STATE_OK;
			task_issue 	= ISSUE_CPU_DELAY;

			strbuf.appendconst("State OK : Process Has consistent CPU delay");
			return 0;
		}
		else {
			taskstate 	= STATE_OK;
			task_issue 	= ISSUE_BLKIO_DELAY;

			strbuf.appendconst("State OK : Process Has consistent Blkio delay");
			return 0;
		}
	}

	if (max_vol_cs > 2000 * delay_secs) {
		taskstate 	= STATE_OK;
		task_issue 	= ISSUE_VOL_CONTEXT_SWITCH;

		strbuf.appendconst("State OK : Process Has a high consistent Context Switch count");
		return 0;
	}	

	if (max_cpu_pct < CPU_LOW_USE_PERCENT) {
		taskstate	= STATE_IDLE;
		task_issue	= ISSUE_TASK_NONE;

		strbuf.appendconst("State Idle : Process CPU Utilization is very low currently");
		return 0;	
	}			

	taskstate	= STATE_GOOD;
	task_issue	= ISSUE_TASK_NONE;

	strbuf.appendconst("State Idle : Process CPU Utilization is not high and no delays");
			
	return 0;	
}			

int TASK_EXT_STATS::update_delay_stats(TASKSTATS_HDLR *ptaskstats, bool & is_issue, bool & is_severe, STR_WR_BUF & strbuf, uint64_t curr_usec_clock) noexcept
{
	GY_TASKSTATS		dstat;
	int			ret;
	uint64_t		curr_nsec;
	OBJ_STATE_E		taskstate;
	TASK_ISSUE_SOURCE	task_issue;	

	ret = ptaskstats->template get_taskstats_sync <NULL_MUTEX>(pthis_obj_->task_pid, dstat, true /* is_tgid */, true /* retry_conn_on_error */, curr_usec_clock);
	if (gy_unlikely(ret != 0)) {
		return ret;
	}	

	// No need to check pdelay_stats_ as already validated

	curr_nsec = get_nsec_clock();

	ret = pdelay_stats_->add_stats(dstat.cpu_delay_total, dstat.blkio_delay_total, dstat.swapin_delay_total, dstat.freepages_delay_total, dstat.thrashing_delay_total, 
						dstat.compact_delay_total, dstat.nvcsw, dstat.nivcsw, curr_nsec);
	if (gy_unlikely(ret != 0)) {
		return ret;	
	}	 	
		
	ret = get_curr_state(taskstate, task_issue, strbuf, curr_nsec);
	
	if (gy_unlikely(ret != 0)) {
		return ret;	
	}	 	

	array_shift_right(issue_hist_, GY_ARRAY_SIZE(issue_hist_));
	issue_hist_[0] = {taskstate, task_issue};

	issue_bit_hist_ 	<<= 1;
	severe_issue_bit_hist_	<<= 1;

	if (taskstate >= STATE_BAD) {
		is_issue = true;

		issue_bit_hist_ |= 1;	
		
		if (taskstate >= STATE_SEVERE) {
			severe_issue_bit_hist_ |= 1;
			is_severe = true;
		}
			
		CONDEXEC(
			DEBUGEXECN(10,
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Process PID %d Comm \'%s\' : Issue History 0x%02hhx Status : %s%s\n", 
					pthis_obj_->task_pid, pthis_obj_->task_comm, issue_bit_hist_, taskstate == STATE_BAD ? "" : GY_COLOR_BOLD_RED, 
					strbuf.buffer());
			);	
		);	
	}	

	return 0;
}	

bool get_k8s_podname(pid_t pid, char *pbuf, size_t szbuf) noexcept
{
	char				tbuf[4096], *ptmp, *pend, *pval, *porigtmp, tval[64], pfilename[128];
	int				fd, ret, n, offn;
	static constexpr size_t		szhoststr = GY_CONST_STRLEN("HOSTNAME="), szkuberstr = GY_CONST_STRLEN("KUBERNETES_SERVICE_PORT=");
	bool				hostfound = false, k8sfound = false;
	
	*pbuf = 0;

	snprintf(pfilename, sizeof(pfilename), "/proc/%d/environ", pid);

	SCOPE_FD			scopefd(pfilename, O_RDONLY);

	fd = scopefd.get();
	if (fd < 0) {
		return false;
	}	

	ptmp = tbuf;
	pend = tbuf + sizeof(tbuf) - 1;

	do {
		porigtmp 	= ptmp;

		n = read(fd, ptmp, pend - ptmp);

		if (n <= 0) {
			break;
		}

		ptmp[n] = 0;

		n += ptmp - tbuf;

		ptmp = tbuf;
		offn = n;
		
		if (hostfound == false) {
try1 :			
			pval = (char *)memmem(ptmp, n, "HOSTNAME=", szhoststr);

			if (pval) {
				if (pval > tbuf && pval[-1] != 0) {
					ptmp = pval + szhoststr;
					n = tbuf + offn - ptmp;
					goto try1;
				}	

				ret = sscanf(pval + szhoststr, "%63s", tval);
				if (ret != 1) {
					return false;
				}	

				GY_STRNCPY(pbuf, tval, szbuf);

				if (k8sfound == true) {
					return true;
				}	

				hostfound = true;
			}	
		}

		if (k8sfound == false) {
			ptmp = tbuf;
			n = offn;

try2 :			
			pval = (char *)memmem(ptmp, n, "KUBERNETES_SERVICE_PORT=", szkuberstr);

			if (pval) {
				if (pval > ptmp && pval[-1] != 0) {
					ptmp = pval + szkuberstr;
					n = tbuf + offn - ptmp;
					goto try2;
				}	

				if (hostfound == true) {
					return true;
				}	

				k8sfound = true;
			}	
		}	

		if (n > 128) {
			memmove(tbuf, porigtmp + n - 128, 128); 
			ptmp = tbuf + 128;
		}	
		
	} while (ptmp >= tbuf);	

	return false;
}


/*
 * Check for non TCP tasks to enable delay stats
 */
bool TASK_EXT_STATS::is_important_task(uint64_t curr_usec) const noexcept
{
	int			max_cpu;
	size_t			total_val;
	uint64_t		last_total;
	int64_t			usecs_run;
	OBJ_STATE_E		taskstate;
	TASK_ISSUE_SOURCE	task_issue;	
			
	/*
	 * Check if the task has been running for at least 100 sec and has had a 
	 * CPU Util of over 5% for at least 20% of the intervals, or has a p80 of > 1% and 
	 * a Mem RSS of at least 10 MB with a Thread count of 3+ OR 
	 * a read + write syscall rate of at least 10 calls/sec.
	 */

	if (cpu_mem_io_.is_kthread) {
		return false;
	}	

	usecs_run = (int64_t)curr_usec - (int64_t)pthis_obj_->starttimeusec;

	if (usecs_run < int64_t(100 * GY_USEC_PER_SEC)) {
		return false;
	}
	
	HIST_DATA 		hist_data_1[] {80};

	cpu_pct_histogram_.get_total_max(total_val, max_cpu);

	// Set max as at least 2%
	if (max_cpu < 2) {
		return false;
	}	

	if (pthis_obj_->task_rt_priority > 0 && pthis_obj_->task_sched_policy > 0 && max_cpu > 10) {
		return true;
	}	

	cpu_pct_histogram_.get_percentiles(hist_data_1, GY_ARRAY_SIZE(hist_data_1), total_val, max_cpu);

	if (hist_data_1[0].data_value > 5) {
		return true;
	}	
	else if (hist_data_1[0].data_value > 1) {
		if ((cpu_mem_io_.rss >= 10 * 1024 * 1024) && (cpu_mem_io_.num_threads > 3)) {
			return true;
		}
		else if (cpu_mem_io_.rss >= 3 * 1024 * 1024) {
			auto nsys = cpu_mem_io_.cumul_syscr + cpu_mem_io_.cumul_syscw;

			if (nsys/(usecs_run/GY_USEC_PER_SEC) > 10) {
				return true;
			}	
		}
	}	

	return false;
}	 


int TASK_DELAY_STATS::add_stats(uint64_t cpu_delay_nsec, uint64_t blkio_delay_nsec, uint64_t swapin_delay_nsec, uint64_t reclaim_delay_nsec, uint64_t thrashing_delay_nsec, \
					uint64_t compact_delay_nsec, uint64_t vol_cs, uint64_t invol_cs, uint64_t curr_nsec) noexcept
{
	try {
		if (gy_unlikely(0 == delay_clock_nsec_[1])) {
			last_cpu_delay_nsec_ 		= cpu_delay_nsec;
			last_blkio_delay_nsec_		= blkio_delay_nsec;
			last_swapin_delay_nsec_		= swapin_delay_nsec;
			last_reclaim_delay_nsec_	= reclaim_delay_nsec;
			last_thrashing_delay_nsec_	= thrashing_delay_nsec;
			last_compact_delay_nsec_	= compact_delay_nsec;
			last_vol_cs_			= vol_cs;
			last_invol_cs_			= invol_cs;

			for (int i = 1; i < MAX_TASK_STAT_HISTORY; ++i) {
				delay_clock_nsec_[i]	= curr_nsec - 1 - i;
			}
		}	
		else {
			if (curr_nsec - delay_clock_nsec_[0] < GY_NSEC_PER_SEC) {
				// Delay between successive add_stats too low, probably due to the scheduler object having been overrun
				return 1;
			}
				
			array_shift_right(cpu_delay_nsec_,		MAX_TASK_STAT_HISTORY);
			array_shift_right(blkio_delay_nsec_,		MAX_TASK_STAT_HISTORY);
			array_shift_right(swapin_delay_nsec_, 		MAX_TASK_STAT_HISTORY);
			array_shift_right(reclaim_delay_nsec_, 		MAX_TASK_STAT_HISTORY);
			array_shift_right(thrashing_delay_nsec_, 	MAX_TASK_STAT_HISTORY);
			array_shift_right(compact_delay_nsec_, 		MAX_TASK_STAT_HISTORY);
			array_shift_right(vol_cs_, 			MAX_TASK_STAT_HISTORY);
			array_shift_right(invol_cs_, 			MAX_TASK_STAT_HISTORY);
			array_shift_right(delay_clock_nsec_, 		MAX_TASK_STAT_HISTORY);
		}

		cpu_delay_nsec_[0] 		= gy_diff_counter_safe(cpu_delay_nsec, last_cpu_delay_nsec_);
		blkio_delay_nsec_[0]		= gy_diff_counter_safe(blkio_delay_nsec, last_blkio_delay_nsec_);
		swapin_delay_nsec_[0]		= gy_diff_counter_safe(swapin_delay_nsec, last_swapin_delay_nsec_);
		reclaim_delay_nsec_[0]		= gy_diff_counter_safe(reclaim_delay_nsec, last_reclaim_delay_nsec_);
		thrashing_delay_nsec_[0]	= gy_diff_counter_safe(thrashing_delay_nsec, last_thrashing_delay_nsec_);
		compact_delay_nsec_[0]		= gy_diff_counter_safe(compact_delay_nsec, last_compact_delay_nsec_);
		vol_cs_[0]			= gy_diff_counter_safe(vol_cs, last_vol_cs_);
		invol_cs_[0]			= gy_diff_counter_safe(invol_cs, last_invol_cs_);

		delay_clock_nsec_[0]		= curr_nsec;
		
		last_cpu_delay_nsec_ 		= cpu_delay_nsec;
		last_blkio_delay_nsec_		= blkio_delay_nsec;
		last_swapin_delay_nsec_		= swapin_delay_nsec;
		last_reclaim_delay_nsec_	= reclaim_delay_nsec;
		last_thrashing_delay_nsec_	= thrashing_delay_nsec;
		last_compact_delay_nsec_	= compact_delay_nsec;
		last_vol_cs_			= vol_cs;
		last_invol_cs_			= invol_cs;

		vol_cs_histogram_.add_data(vol_cs_[0], curr_nsec);
		invol_cs_histogram_.add_data(invol_cs_[0], curr_nsec);
		
		cpu_delay_histogram_.add_data(cpu_delay_nsec_[0]/GY_NSEC_PER_MSEC, curr_nsec);
		blkio_delay_histogram_.add_data(blkio_delay_nsec_[0]/GY_NSEC_PER_MSEC, curr_nsec);

		return 0;
	}
	catch(...) {	
		return -1;
	}
}
	
char * TASK_DELAY_STATS::print_stats(STR_WR_BUF & strbuf) const noexcept
{
	const float		pctarr[] = {95, 99, 25};
	int			max_val;
	size_t			total_val;
	uint64_t		last_total;
	uint64_t		tdiffsec = gy_div_round_near((delay_clock_nsec_[0] - delay_clock_nsec_[MAX_TASK_STAT_HISTORY -  1]), GY_NSEC_PER_SEC);

	cpu_delay_histogram_.get_total_max(total_val, max_val);
	if ((max_val > 0) && (last_total = array_summ(cpu_delay_nsec_, MAX_TASK_STAT_HISTORY))) {
		strbuf.appendconst("\n\n\tProcess CPU Delay Histogram follows : ");
		cpu_delay_histogram_.print_stats(strbuf, pctarr, GY_ARRAY_SIZE(pctarr), "CPU Delay msec", GY_NSEC_PER_SEC);

		strbuf.appendfmt("\n\tLast %d Records (%lu seconds) CPU Delay Total = %lu nsec (%lu msec) : Last 2 Delays [%lu msec, %lu msec]\n", 
			MAX_TASK_STAT_HISTORY, tdiffsec, last_total, last_total/GY_NSEC_PER_MSEC, cpu_delay_nsec_[0]/GY_NSEC_PER_MSEC, cpu_delay_nsec_[1]/GY_NSEC_PER_MSEC);
	}

	blkio_delay_histogram_.get_total_max(total_val, max_val);
	if ((max_val > 0) && (last_total = array_summ(blkio_delay_nsec_, MAX_TASK_STAT_HISTORY))) {
		strbuf.appendconst("\n\n\tProcess Blkio Delay Histogram follows : ");
		blkio_delay_histogram_.print_stats(strbuf, pctarr, GY_ARRAY_SIZE(pctarr), "Blkio Delay msec", GY_NSEC_PER_SEC);

		strbuf.appendfmt("\n\tLast %d Records (%lu seconds) Blkio Delay Total = %lu nsec (%lu msec) : Last 2 Delays [%lu msec, %lu msec]\n", 
			MAX_TASK_STAT_HISTORY, tdiffsec, last_total, last_total/GY_NSEC_PER_MSEC, blkio_delay_nsec_[0]/GY_NSEC_PER_MSEC, blkio_delay_nsec_[1]/GY_NSEC_PER_MSEC);
	}

	if ((last_total = array_summ(swapin_delay_nsec_, MAX_TASK_STAT_HISTORY))) {
		strbuf.appendfmt("\n\tLast %d Records (%lu seconds) Swapin Delay Total = %lu nsec (%lu msec) : Last 2 Delays [%lu msec, %lu msec]\n", 
			MAX_TASK_STAT_HISTORY, tdiffsec, last_total, last_total/GY_NSEC_PER_MSEC, swapin_delay_nsec_[0]/GY_NSEC_PER_MSEC, swapin_delay_nsec_[1]/GY_NSEC_PER_MSEC);
	}	

	if ((last_total = array_summ(reclaim_delay_nsec_, MAX_TASK_STAT_HISTORY))) {
		strbuf.appendfmt("\n\tLast %d Records (%lu seconds) Reclaim Delay Total = %lu nsec (%lu msec) : Last 2 Delays [%lu msec, %lu msec]\n", 
			MAX_TASK_STAT_HISTORY, tdiffsec, last_total, last_total/GY_NSEC_PER_MSEC, reclaim_delay_nsec_[0]/GY_NSEC_PER_MSEC, reclaim_delay_nsec_[1]/GY_NSEC_PER_MSEC);
	}

	if ((last_total = array_summ(thrashing_delay_nsec_, MAX_TASK_STAT_HISTORY))) {
		strbuf.appendfmt("\n\tLast %d Records (%lu seconds) Thrashing Delay Total = %lu nsec (%lu msec) : Last 2 Delays [%lu msec, %lu msec]\n", 
			MAX_TASK_STAT_HISTORY, tdiffsec, last_total, last_total/GY_NSEC_PER_MSEC, thrashing_delay_nsec_[0]/GY_NSEC_PER_MSEC, thrashing_delay_nsec_[1]/GY_NSEC_PER_MSEC);
	}

	if ((last_total = array_summ(compact_delay_nsec_, MAX_TASK_STAT_HISTORY))) {
		strbuf.appendfmt("\n\tLast %d Records (%lu seconds) Compaction Delay Total = %lu nsec (%lu msec) : Last 2 Delays [%lu msec, %lu msec]\n", 
			MAX_TASK_STAT_HISTORY, tdiffsec, last_total, last_total/GY_NSEC_PER_MSEC, compact_delay_nsec_[0]/GY_NSEC_PER_MSEC, compact_delay_nsec_[1]/GY_NSEC_PER_MSEC);
	}

	vol_cs_histogram_.get_total_max(total_val, max_val);
	if ((max_val > 0) && (last_total = array_summ(vol_cs_, MAX_TASK_STAT_HISTORY))) {
		strbuf.appendconst("\n\n\tProcess Voluntary Context Switches Histogram follows : ");
		vol_cs_histogram_.print_stats(strbuf, pctarr, GY_ARRAY_SIZE(pctarr), "Vol CS", GY_NSEC_PER_SEC);

		strbuf.appendfmt("\n\tLast %d Records (%lu seconds) Voluntary Context Switches Total = %lu : Last 2 Values [%lu, %lu]\n", 
			MAX_TASK_STAT_HISTORY, tdiffsec, last_total, vol_cs_[0], vol_cs_[1]);
	}

	invol_cs_histogram_.get_total_max(total_val, max_val);
	if ((max_val > 0) && (last_total = array_summ(invol_cs_, MAX_TASK_STAT_HISTORY))) {
		strbuf.appendconst("\n\n\tProcess Involuntary Context Switches Histogram follows : ");
		invol_cs_histogram_.print_stats(strbuf, pctarr, GY_ARRAY_SIZE(pctarr), "Invol CS", GY_NSEC_PER_SEC);

		strbuf.appendfmt("\n\tLast %d Records (%lu seconds) Involuntary Context Switches Total = %lu : Last 2 Values [%lu, %lu]\n", 
			MAX_TASK_STAT_HISTORY, tdiffsec, last_total, invol_cs_[0], invol_cs_[1]);
	}

	return strbuf.buffer();
}	 

char * TASK_STAT::get_task_print_str(char *pbuf, size_t maxsz) noexcept
{
	char				tbuf[64];

	if ((is_ready.load(std::memory_order_relaxed) >= TASK_UPD_INIT_ONLY) && is_task_valid()) {
		struct timeval 		tv = GY_USEC_TO_TIMEVAL(starttimeusec);

		snprintf(pbuf, maxsz, "PID %d Comm %s : PPID %d (%s) PGID %d SID %d 1st pid namespace nspid %d nspgid %d nssid %d "
			": realuid %u effuid %u : realgid %u effgid %u : Process Start Time %s : "
			"is ipc in Root ns %d mnt ns %d net ns %d pid ns %d user ns %d uts ns %d : Process exe & cmdline : %s : %s", 
			task_pid, task_comm, task_ppid, task_parent_comm, task_pgid, task_sid, task_nspid, task_nspgid, task_nssid, task_realuid, task_effuid, 
			task_realgid, task_effgid, gy_localtime_iso8601(tv, tbuf, sizeof(tbuf)),
			ns_inodes.ipc_in_root_ns, ns_inodes.mnt_in_root_ns, ns_inodes.net_in_root_ns, ns_inodes.pid_in_root_ns, 
			ns_inodes.user_in_root_ns, ns_inodes.uts_in_root_ns, task_exe_path, task_cmdline);
	}
	else {
		snprintf(pbuf, maxsz, "PID %d PPID %d : [ERROR] : Process in unintialized or errored state", task_pid, task_ppid);		
	}			
	return pbuf;
}
	
int TASK_STAT::set_task_proc_status(int proc_dir_fd, pid_t pidin) noexcept
{
	try {
		constexpr int			szalloc = 10 * 1024; 
		char				pbuf[szalloc], buf[64];
		char				*ptmp;
		int				ret, fd;
		ssize_t				szread;
		size_t				nbytes;
		
		snprintf(buf, sizeof(buf), "./%u/status", pidin);

		SCOPE_FD			scopefd(proc_dir_fd, buf, O_RDONLY);
		
		fd = scopefd.get();
		if (fd < 0) {
			CONDEXEC(DEBUGEXECN(20, PERRORPRINT_OFFLOAD("Failed to open proc/status of PID %d", pidin)));
			return -1;
		}	

		szread = gy_readbuffer(fd, pbuf, szalloc - 1);
		if (szread <= 0) {
			CONDEXEC(DEBUGEXECN(20, PERRORPRINT_OFFLOAD("Failed to read proc/status of PID %d", pidin)));
			return -1;
		}

		pbuf[szread] = '\0';

		STR_RD_BUF			taskstr(pbuf, szread);

		// First Name (comm)
		ptmp = (char *)taskstr.skip_till_substring_const("Name:");
		if (!ptmp) {
			goto errexit;
		}	
		else {
			ptmp = (char *)taskstr.get_next_word(nbytes);
			if (nbytes == 0) {
				goto errexit;
			}
				
			if (nbytes >= TASK_COMM_LEN) {
				nbytes = TASK_COMM_LEN - 1;
			}

			if ((0 == task_exe_path[0]) || (0 == task_comm[0])) {
				get_escaped_comm(task_comm, ptmp, nbytes);
			}	

			get_escaped_comm(task_orig_comm, ptmp, nbytes);

			if (gy_unlikely(true == is_task_kthread(this->task_flags))) {
				task_cmdline[0] = '[';
				memcpy(task_cmdline + 1, task_comm, nbytes);
				task_cmdline[nbytes + 1] = ']';
				task_cmdline[nbytes + 2] = '\0';
			}	
		}

		ptmp = (char *)taskstr.skip_till_substring_const("State:", false);
		if (ptmp) {
			ptmp = (char *)taskstr.get_next_word(nbytes, true, "\n");
			if (ptmp && nbytes >= GY_CONST_STRLEN("Z (zombie)")) {
				if (gy_unlikely(0 == memcmp(ptmp, "Z (zombie)", GY_CONST_STRLEN("Z (zombie)")))) {
					return -1;
				}
			}
		}			

		ptmp = (char *)taskstr.skip_till_substring_const("PPid:", false);
		if (!ptmp) {
			goto errexit;
		}	
		
		ptmp = (char *)taskstr.get_next_word(nbytes);
		if (!ptmp) {
			goto errexit;
		}	
		this->task_ppid = atoi(ptmp);


		ptmp = (char *)taskstr.skip_till_substring_const("Uid:", false);
		if (!ptmp) {
			goto errexit;
		}	
		
		ptmp = (char *)taskstr.get_next_line(nbytes);
		if (!ptmp) {
			goto errexit;
		}	

		ret = sscanf_large_str(ptmp, nbytes, "%u %u %u %u", &this->task_realuid, &this->task_effuid, &this->task_saveduid, &this->task_fsuid);
		if (ret != 4) {
			goto errexit;
		}	
		
		ptmp = (char *)taskstr.skip_till_substring_const("Gid:", false);
		if (!ptmp) {
			goto errexit;
		}	
		
		ptmp = (char *)taskstr.get_next_line(nbytes);
		if (!ptmp) {
			goto errexit;
		}	

		ret = sscanf_large_str(ptmp, nbytes, "%u %u %u %u", &this->task_realgid, &this->task_effgid, &this->task_savedgid, &this->task_fsgid);
		if (ret != 4) {
			goto errexit;
		}	

		ptmp = (char *)taskstr.skip_till_substring_const("NStgid:", false);
		if (ptmp) {
			ptmp = (char *)taskstr.get_next_line(nbytes);
			if (!ptmp) {
				goto errexit;
			}	

			ret = sscanf_large_str(ptmp, nbytes, "%d %d", &this->task_pid, &this->task_nspid);
			if (ret < 1) {
				goto errexit;
			}	
		}
		else {
			this->task_nspid = 0;
		}	

		ptmp = (char *)taskstr.skip_till_substring_const("NSpgid:", false);
		if (ptmp) {
			ptmp = (char *)taskstr.get_next_line(nbytes);
			if (!ptmp) {
				goto errexit;
			}	

			ret = sscanf_large_str(ptmp, nbytes, "%d %d", &this->task_pgid, &this->task_nspgid);
			if (ret < 1) {
				goto errexit;
			}	
		}
		else {
			this->task_pgid = 0;
			this->task_nspgid = 0;
		}	

		ptmp = (char *)taskstr.skip_till_substring_const("NSsid:", false);
		if (ptmp) {
			ptmp = (char *)taskstr.get_next_line(nbytes);
			if (!ptmp) {
				goto errexit;
			}	

			ret = sscanf_large_str(ptmp, nbytes, "%d %d", &this->task_sid, &this->task_nssid);
			if (ret < 1) {
				goto errexit;
			}	
		}
		else {
			this->task_sid = 0;
			this->task_nssid = 0;
		}	

		ptmp = (char *)taskstr.skip_till_substring_const("Threads:", false);
		if (!ptmp) {
			goto errexit;
		}	
		
		ptmp = (char *)taskstr.get_next_word(nbytes);
		if (!ptmp) {
			goto errexit;
		}	

		ptmp = (char *)taskstr.skip_till_substring_const("Cpus_allowed_list:", false);
		if (!ptmp) {
			goto errexit;
		}	
		
		ptmp = (char *)taskstr.get_next_line(nbytes);
		if (!ptmp) {
			goto errexit;
		}	
		else {
			CPU_CORES_BITSET		cpus_allowed;

			ret = set_bitset_from_buffer(cpus_allowed, ptmp, nbytes);
			ncpus_allowed = cpus_allowed.count();
		}

		ptmp = (char *)taskstr.skip_till_substring_const("Mems_allowed_list:", false);
		if (!ptmp) {
			goto errexit;
		}	
		else {
			MEM_NODE_BITSET			mems_allowed;	

			ptmp = (char *)taskstr.get_next_line(nbytes);
			if (!ptmp) {
				goto errexit;
			}	

			ret = set_bitset_from_buffer(mems_allowed, ptmp, nbytes);
			nmems_allowed = mems_allowed.count();
		}
		
		return 0;

errexit :
		DEBUGEXECN(1, ERRORPRINT_OFFLOAD("Failed to parse proc/status for PID %d\n", pidin););
		return -1;	
	}	
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Process PID %d proc/status initialization threw an exception : %s\n", task_pid, GY_GET_EXCEPT_STRING););
		return -1;
	);
}	

int TASK_STAT::set_task_cgroups(int proc_dir_fd) noexcept
{
	try {
		int			ret;
		const char 		*pcglist[] = {"cpu", "cpuset", "memory"};
		char			pdirbuf[GY_ARRAY_SIZE(pcglist) * GY_PATH_MAX + 512];

		auto pcgroup = CGROUP_HANDLE::get_singleton();

		if (!pcgroup) {
			return 0;
		}

		char			*pdircg1 [GY_ARRAY_SIZE(pcglist)];
		size_t			maxcg1sz [GY_ARRAY_SIZE(pcglist)];
		char			pdircg2 [GY_PATH_MAX + 1];

		for (size_t i = 0; i < GY_ARRAY_SIZE(pcglist); i++) {
			pdircg1[i]	= pdirbuf + i * GY_PATH_MAX + 1;
			maxcg1sz[i]	= GY_PATH_MAX;
		}	

		ret = get_proc_cgroups(task_pid, pcglist, pdircg1, maxcg1sz, GY_ARRAY_SIZE(pcglist), pdircg2, sizeof(pdircg2) - 1, proc_dir_fd);
		if (ret <= 0) {
			CONDEXEC(
				DEBUGEXECN(20, PERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get cgroup paths for PID %d", this->task_pid););
			);	
			return -1;
		}	
		
		auto 			weakptr = this->weak_from_this();
		time_t			tcur = time(nullptr);	

		if (pdircg1[0][0]) {
			cg_cpu_shr = std::move(pcgroup->add_task_to_cpu(pdircg1[0], weakptr, task_pid, tcur));
		}	
		else {
			cg_cpu_shr.reset();
		}	
		
		if (pdircg1[1][0]) {
			cg_cpuset_shr = std::move(pcgroup->add_task_to_cpuset(pdircg1[1], weakptr, task_pid, tcur));
		}	
		else {
			cg_cpuset_shr.reset();
		}	

		if (pdircg1[2][0]) {
			cg_memory_shr = std::move(pcgroup->add_task_to_memory(pdircg1[2], weakptr, task_pid, tcur));
		}	
		else {
			cg_memory_shr.reset();
		}	

		if (pdircg2) {
			cg_2_shr = std::move(pcgroup->add_task_to_cgroup2(pdircg2, weakptr, task_pid, tcur));
		}	
		else {
			cg_2_shr.reset();
		}	

		cgroups_updated.store(true, std::memory_order_seq_cst);

		return 0;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Process PID %d cgroup initialization threw an exception : %s\n", task_pid, GY_GET_EXCEPT_STRING););
		return -1;
	);
}
	
int TASK_STAT::upd_task_cgroup_on_change(int proc_dir_fd) noexcept
{
	try {
		int			ret;
		const char 		*pcglist[] = {"cpu", "cpuset", "memory"};
		char			pdirbuf[GY_ARRAY_SIZE(pcglist) * GY_PATH_MAX + 512];

		if (cgroups_updated.load(std::memory_order_acquire) == false) {
			return 0;
		}

		cgroups_updated.store(false, std::memory_order_release);

		GY_SCOPE_EXIT {
			cgroups_updated.store(true, std::memory_order_release);
		};	
			
		auto pcgroup = CGROUP_HANDLE::get_singleton();

		if (!pcgroup) {
			return 0;
		}

		char			*pdircg1 [GY_ARRAY_SIZE(pcglist)];
		size_t			maxcg1sz [GY_ARRAY_SIZE(pcglist)];
		char			pdircg2 [GY_PATH_MAX + 1];

		for (size_t i = 0; i < GY_ARRAY_SIZE(pcglist); i++) {
			pdircg1[i]	= pdirbuf + i * GY_PATH_MAX + 1;
			maxcg1sz[i]	= GY_PATH_MAX;
		}	

		ret = get_proc_cgroups(task_pid, pcglist, pdircg1, maxcg1sz, GY_ARRAY_SIZE(pcglist), pdircg2, sizeof(pdircg2) - 1, proc_dir_fd);
		if (ret <= 0) {
			CONDEXEC(
				DEBUGEXECN(20, PERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get cgroup paths for PID %d", this->task_pid););
			);	
			return -1;
		}	
		
		auto 			weakptr = this->weak_from_this();
		time_t			tcur = time(nullptr);

		if (pdircg1[0][0]) {
			bool		to_chg = true;

			if (cg_cpu_shr) {
				if (strcmp(cg_cpu_shr->get_dir_path(), pdircg1[0])) {
					DEBUGEXECN(1, INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "PID %d cpu cgroup path changed to %s\n", task_pid, pdircg1[0]););

					cg_cpu_shr->delete_task(task_pid, tcur);
				}	
				else {
					to_chg = false;
				}		
			}	

			if (to_chg) {
				cg_cpu_shr = std::move(pcgroup->add_task_to_cpu(pdircg1[0], weakptr, task_pid, tcur));
			}	
		}	
		else {
			cg_cpu_shr.reset();
		}	
		
		if (pdircg1[1][0]) {
			bool		to_chg = true;

			if (cg_cpuset_shr) {
				if (strcmp(cg_cpuset_shr->get_dir_path(), pdircg1[1])) {
					DEBUGEXECN(1, INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "PID %d cpuset cgroup path changed to %s\n", task_pid, pdircg1[1]););

					cg_cpuset_shr->delete_task(task_pid, tcur);
				}	
				else {
					to_chg = false;
				}		
			}	

			if (to_chg) {
				cg_cpuset_shr = std::move(pcgroup->add_task_to_cpuset(pdircg1[1], weakptr, task_pid, tcur));

				if (cg_cpuset_shr) {
					ncpus_allowed		= cg_cpuset_shr->stats.cpus_allowed.count();
					nmems_allowed		= cg_cpuset_shr->stats.mems_allowed.count();
				}	
			}	
		}	
		else {
			cg_cpuset_shr.reset();
		}	

		if (pdircg1[2][0]) {
			bool		to_chg = true;

			if (cg_memory_shr) {
				if (strcmp(cg_memory_shr->get_dir_path(), pdircg1[2])) {
					DEBUGEXECN(1, INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "PID %d memory cgroup path changed to %s\n", task_pid, pdircg1[2]););

					cg_memory_shr->delete_task(task_pid, tcur);
				}	
				else {
					to_chg = false;
				}		
			}	

			if (to_chg) {
				cg_memory_shr = std::move(pcgroup->add_task_to_memory(pdircg1[2], weakptr, task_pid, tcur));
			}	
		}	
		else {
			cg_memory_shr.reset();
		}	

		if (pdircg2) {
			bool		to_chg = true;

			if (cg_2_shr) {
				if (strcmp(cg_2_shr->get_dir_path(), pdircg2)) {
					DEBUGEXECN(1, INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "PID %d cgroup2 path changed to %s\n", task_pid, pdircg2););

					cg_2_shr->delete_task(task_pid, tcur);
				}	
				else {
					to_chg = false;
				}		
			}	

			if (to_chg) {
				cg_2_shr = std::move(pcgroup->add_task_to_cgroup2(pdircg2, weakptr, task_pid, tcur));

				if (cg_2_shr) {
					ncpus_allowed		= cg_2_shr->stats.cpus_allowed.count();
					nmems_allowed		= cg_2_shr->stats.mems_allowed.count();
				}	
			}	
		}	
		else {
			cg_2_shr.reset();
		}	
		
		return 0;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Process PID %d cgroup change handling threw an exception : %s\n", task_pid, GY_GET_EXCEPT_STRING););
		return -1;
	);
}	

int TASK_STAT::set_task_proc_stat_misc(int proc_dir_fd, pid_t pidin) noexcept
{
	int			ret;
	pid_t			tppid;
	char			tstate;

	ret = get_proc_stat(pidin, tppid, tstate, task_flags, starttimeusec, task_priority, task_nice, task_rt_priority, task_sched_policy, proc_dir_fd);

	CONDEXEC(
		if (ret != 0) {
			DEBUGEXECN(20, PERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get /proc/PID/stat for pid %d", pidin););
		}
	);	

	return ret;
}

bool TASK_STAT::save_task_full(comm::TASK_FULL_ADD * __restrict__ pfulltask, const size_t max_bytes, size_t & elem_bytes, uint64_t curr_tusec) noexcept
{
	if (max_bytes < sizeof(*pfulltask) + 512) {
		return false;
	}

	pfulltask->task_pid_		= task_pid;
	pfulltask->task_ppid_		= task_ppid;
	pfulltask->task_pgid_		= task_pgid;
	pfulltask->task_sid_		= task_sid;
	pfulltask->task_nspid_		= task_nspid;
	pfulltask->task_nspgid_		= task_nspgid;
	pfulltask->task_nssid_		= task_nssid;

	std::memcpy(pfulltask->task_comm_, task_comm, sizeof(pfulltask->task_comm_));
	std::memcpy(pfulltask->task_parent_comm_, task_parent_comm, sizeof(pfulltask->task_parent_comm_));

	pfulltask->aggr_task_id_	= aggr_task_id_.load(std::memory_order_relaxed);

	pfulltask->task_realuid_	= task_realuid;
	pfulltask->task_effuid_		= task_effuid;
	pfulltask->task_realgid_	= task_realgid;
	pfulltask->task_effgid_		= task_effgid;
	
	pfulltask->ncpus_allowed_	= ncpus_allowed;
	pfulltask->nmems_allowed_	= nmems_allowed;

	pfulltask->task_flags_		= task_flags;
	pfulltask->start_tusec_		= starttimeusec;
	pfulltask->task_priority_	= task_priority;
	pfulltask->task_nice_		= task_nice;
	pfulltask->task_rt_priority_	= task_rt_priority;
	pfulltask->task_sched_policy_	= task_sched_policy;
	
	pfulltask->ntcp_listeners_		= ntcp_listeners.load(std::memory_order_relaxed);
	pfulltask->is_tcp_server_		= is_tcp_server;
	pfulltask->is_tcp_client_		= is_tcp_client;
	pfulltask->is_parent_tcp_client_	= is_parent_tcp_client;
	pfulltask->is_high_cap_			= is_high_cap;
	pfulltask->listen_tbl_inherited_	= !!listen_tbl_inherited.load(std::memory_order_relaxed);

	pfulltask->task_exe_path_len_	= strlen(task_exe_path) + 1;
	pfulltask->task_cmdline_len_	= strlen(task_cmdline) + 1;
	pfulltask->task_tags_len_	= 0; // (bool(pext_stats) ? pext_stats->task_tags_.length() : 0);

	size_t				newsz = sizeof(*pfulltask) + pfulltask->task_exe_path_len_ + pfulltask->task_cmdline_len_ + pfulltask->task_tags_len_;
	size_t				totsz = gy_align_up_2(newsz, 8);

	pfulltask->padding_len_		= totsz - newsz;

	if (max_bytes < totsz) {
		return false;
	}
	
	char			*pvar = (char *)pfulltask + sizeof(*pfulltask);

	std::memcpy(pvar, task_exe_path, pfulltask->task_exe_path_len_);
	pvar += pfulltask->task_exe_path_len_;

	std::memcpy(pvar, task_cmdline, pfulltask->task_cmdline_len_);
	pvar += pfulltask->task_cmdline_len_;

	if (pfulltask->task_tags_len_) {
		/*std::memcpy(pvar, pext_stats->task_tags_.c_str(), pfulltask->task_tags_len_);*/
	}

	elem_bytes			= totsz;
	last_server_tusec		= curr_tusec;

	return true;
}	

bool TASK_STAT::save_task_stats(comm::TASK_HISTOGRAM * __restrict__ ptaskhist, uint64_t curr_clock_nsec, int64_t currtimesec, int64_t diffsec) noexcept
{
	if (gy_unlikely(pext_stats.get() == nullptr || pext_stats->pdelay_stats_.get() == nullptr)) {
		return false;
	}
	
	auto			pdelay = pext_stats->pdelay_stats_.get();
	size_t			nstats = pdelay->get_histogram_count();
	uint64_t		lastcnsec = pdelay->get_last_histogram_clock_nsec();

	if (nstats < 200 || lastcnsec < curr_clock_nsec - 15 * GY_NSEC_PER_MINUTE) {
		return false;
	}	

	int64_t			last_update_tsec = (lastcnsec < curr_clock_nsec ? currtimesec - (curr_clock_nsec - lastcnsec)/GY_NSEC_PER_SEC : currtimesec);
	HIST_SERIAL		stats[comm::TASK_HISTOGRAM::MAX_HIST_HASH_BUCKETS];
	size_t 			total_count;
	uint64_t		start_clock, end_clock;
	int 			max_val;

	pdelay->cpu_delay_histogram_.get_serialized(stats, total_count, max_val, end_clock, start_clock);
	new (&ptaskhist->cpu_delay_histogram_) comm::TASK_HISTOGRAM::TASK_ONE(stats, total_count, max_val, pdelay->cpu_delay_histogram_.maxbuckets_);

	pdelay->blkio_delay_histogram_.get_serialized(stats, total_count, max_val, end_clock, start_clock);
	new (&ptaskhist->blkio_delay_histogram_) comm::TASK_HISTOGRAM::TASK_ONE(stats, total_count, max_val, pdelay->blkio_delay_histogram_.maxbuckets_);

	pdelay->vol_cs_histogram_.get_serialized(stats, total_count, max_val, end_clock, start_clock);
	new (&ptaskhist->vol_cs_histogram_) comm::TASK_HISTOGRAM::TASK_ONE(stats, total_count, max_val, pdelay->vol_cs_histogram_.maxbuckets_);

	pdelay->invol_cs_histogram_.get_serialized(stats, total_count, max_val, end_clock, start_clock);
	new (&ptaskhist->invol_cs_histogram_) comm::TASK_HISTOGRAM::TASK_ONE(stats, total_count, max_val, pdelay->invol_cs_histogram_.maxbuckets_);

	pext_stats->cpu_pct_histogram_.get_serialized(stats, total_count, max_val, end_clock, start_clock);
	new (&ptaskhist->cpu_pct_histogram_) comm::TASK_HISTOGRAM::TASK_ONE(stats, total_count, max_val, pext_stats->cpu_pct_histogram_.maxbuckets_);

	ptaskhist->last_update_tsec_	= last_update_tsec;
	ptaskhist->aggr_task_id_	= aggr_task_id_.load(std::memory_order_relaxed);

	std::memcpy(ptaskhist->comm_, task_comm, sizeof(ptaskhist->comm_));
	ptaskhist->pid_			= task_pid;

	return true;
}	

int TASK_STAT::set_task_exited(int exit_code, TASK_KILL_INFO & kone) noexcept
{
	// Set task_valid to exited as the task destructor may be called after RCU grace period

	time_t			tcursec = 0;
	
	task_valid.store(TASK_STATE_EXITED, std::memory_order_relaxed);

	if (is_ready.load(std::memory_order_relaxed) == TASK_UPD_FULL) {
		if (0 != ntcp_listeners.load(std::memory_order_relaxed)) {
			clear_listener_table();
		}	
	}

	if (cgroups_updated.load(std::memory_order_acquire) == true) {
		tcursec = time(nullptr);

		if (cg_cpu_shr) {
			cg_cpu_shr->delete_task(task_pid, tcursec);
		}	
		if (cg_cpuset_shr) {
			cg_cpuset_shr->delete_task(task_pid, tcursec);
		}	
		if (cg_memory_shr) {
			cg_memory_shr->delete_task(task_pid, tcursec);
		}	
		if (cg_2_shr) {
			cg_2_shr->delete_task(task_pid, tcursec);
		}	
	}

	int			sigcode = (exit_code >= 128 ? exit_code - 128 : exit_code), ret = 0;
		
	switch (sigcode) {
	
	case SIGKILL :
	case SIGILL :
	case SIGABRT :
	case SIGBUS :
	case SIGFPE :
	case SIGSEGV :
		DEBUGEXECN(1, 
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Process %d (%s) exited with fatal signal %s\n", task_pid, task_comm, gy_signal_str(sigcode));
		);	

		kone.set_kill(task_comm, task_pid, sigcode, tcursec > 0 ? tcursec : time(nullptr));
		ret = 1;
		break;
	
	default :
		break;	
	}	

	CONDEXEC( 
		DEBUGEXECN(15,
		uint64_t	tcur = get_usec_time();

		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_LIGHT_BLUE, "Exit of process after %lu usec (%lu sec) : PID %d PPID %d Exit Code %d Signal %d : %s\n", 
				tcur - starttimeusec, (tcur - starttimeusec) / GY_USEC_PER_SEC, 
				task_pid, task_ppid, exit_code, sigcode, task_cmdline);
		);
	);
			
	return ret;
}
	
int TASK_STAT::set_task_uid_change(uid_t new_uid) noexcept
{
	CONDEXEC(DEBUGEXECN(10, INFOPRINTCOLOR_OFFLOAD(GY_COLOR_LIGHT_BLUE, "UID Change for PID %d PPID %d Comm %s : from %d to %d\n", 
			task_pid, task_ppid, task_comm, task_effuid, new_uid);););
	
	task_effuid = new_uid;

	return 0;
}		

int TASK_STAT::set_task_gid_change(gid_t new_gid) noexcept
{
	CONDEXEC(DEBUGEXECN(10, INFOPRINTCOLOR_OFFLOAD(GY_COLOR_LIGHT_BLUE, "GID Change for PID %d PPID %d Comm %s : from %d to %d\n", 
			task_pid, task_ppid, task_comm, task_effgid, new_gid);););
	
	task_effgid = new_gid;

	return 0;
}
	
int TASK_STAT::set_task_sid_change() noexcept
{
	CONDEXEC(DEBUGEXECN(15, INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_GREEN, "setsid called : SID / PGID Change for PID %d PPID %d Comm %s : older SID %d PGID %d\n", 
			task_pid, task_ppid, task_comm, task_sid, task_pgid);););

	task_sid 	= task_pid;
	task_pgid	= task_pid;

	return 0;
}

int TASK_STAT::set_task_ptrace(pid_t tracer_pid, bool is_attach_ptrace) noexcept
{
	CONDEXEC(
		DEBUGEXECN(10, 
			if (is_attach_ptrace) {
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_RED_UNDERLINE, "PID %d PPID %d Comm %s is being ptraced by PID %d\n", 
					task_pid, task_ppid, task_comm, tracer_pid);
			}
			else {
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_RED_UNDERLINE, "PID %d PPID %d Comm %s ptrace disabled\n", 
					task_pid, task_ppid, task_comm);
			}		
		);
	);

	is_ptrace_active = is_attach_ptrace;

	return 0;
}	

int TASK_STAT::set_task_exec(int proc_dir_fd) noexcept
{
	int			ret = -1;
	pid_t			pidin = this->task_pid;

	GY_SCOPE_EXIT {
		if (ret != 0) {
			is_ready.store(TASK_UPD_ERROR, std::memory_order_relaxed);
			task_valid.store(TASK_STATE_ERROR, std::memory_order_relaxed);
		}	
	};
		
	try {
		ret = get_task_exe_path(pidin, task_exe_path, sizeof(task_exe_path), proc_dir_fd); 
		if (ret < 0) {
			DEBUGEXECN(20, PERRORPRINT_OFFLOAD("Failed to get exe_path of PID %d", pidin));
			return ret;
		}	

		const char		*ptmp1 = (const char *)memrchr(task_exe_path, '/', ret);

		if (!ptmp1) {
			ptmp1 = task_exe_path;
		}	
		else {
			ptmp1++;	
		}	

		get_escaped_comm(task_comm, ptmp1);

		bin_type = typeinfo::get_binary_type(task_comm);
				
		ret = get_cmdline(pidin, proc_dir_fd); 
		if (ret < 0) {
			DEBUGEXECN(20, PERRORPRINT_OFFLOAD("Failed to get cmdline of PID %d", pidin));
			return ret;
		}	

		cwd_inode = get_cwd_inode(pidin);

		ret = set_task_proc_status(proc_dir_fd, task_pid);
		if (ret < 0) {
			return ret;
		}	

		is_execv_task = true;
		sent_aggr_server_.store(0, std::memory_order_relaxed);	// Set as false so that new aggr stats are sent
		aggr_task_id_.store(0, std::memory_order_relaxed);

		if (is_ready.load(std::memory_order_relaxed) > TASK_UPD_INIT_ONLY) {
			if (is_ready.load(std::memory_order_relaxed) == TASK_UPD_COPIED) {
				is_ready.store(TASK_UPD_COPIED_EXEC, std::memory_order_relaxed);
			}	
		}	
		else {
			is_ready.store(TASK_UPD_INIT_ONLY, std::memory_order_relaxed);
		}

		CONDEXEC( 
			DEBUGEXECN(15,
			char		buf1[1024];

			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Exec of process : %s\n", get_task_print_str(buf1, sizeof(buf1) - 1));
			);
		);
		
		ret = 0;
		return 0;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINT_OFFLOAD("Task PID %d update after exec threw an exception : %s\n", pidin, GY_GET_EXCEPT_STRING););
		return -1;
	);
}	

ino_t TASK_STAT::get_cwd_inode(pid_t pid) noexcept
{
	char				buf[128];
	struct stat			stat1;
	int				ret;

	snprintf(buf, sizeof(buf), "/proc/%u/cwd", pid);

	ret = stat(buf, &stat1);
	if (ret == 0) {
		return stat1.st_ino;
	}

	return -1;
}	

ssize_t TASK_STAT::get_cmdline(pid_t pid, int proc_dir_fd) noexcept
{
	int				ret, fd;
	const bool			not_mach = (bin_type != typeinfo::BIN_TYPE::BIN_MACHINE);
	char				buf[64];
	char				tbuf[4096], *ptmp = (not_mach ? tbuf : task_cmdline);
	ssize_t				szread, maxsz = (not_mach ? sizeof(tbuf) - 1 : sizeof(task_cmdline) - 1);

	
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

try_again :	
	szread = ::read(fd, ptmp, maxsz);

	if (gy_unlikely(szread <= 0)) {
		if (szread == -1 && (errno == EINTR || errno == EAGAIN)) {
			goto try_again;
		}	
		else if (szread == 0) {
			/*
			 * Kernel threads have no argv
			 * Use task_comm instead
			 */
			return GY_SAFE_SNPRINTF(task_cmdline, sizeof(task_cmdline), "[%s]", task_comm); 
		}

		return -errno;
	}

	if (not_mach) {
		static_assert(sizeof(task_cmdline) >= 128);

		if ((size_t)szread > sizeof(task_cmdline) - 1) {

			/*
			 * Using an Interpreter or JVM : We copy 100 bytes from start and last bytes from end of buffer as we would like to get the end of the cmdline params as well.
			 */	

			std::memcpy(task_cmdline, ptmp, 100);
			std::memcpy(task_cmdline + 100, "...", 3);
			std::memcpy(task_cmdline + 100 + 3, ptmp + szread - (sizeof(task_cmdline) - 103 - 1), sizeof(task_cmdline) - 103 - 1);

			szread = sizeof(task_cmdline) - 1;
		}	
		else {
			std::memcpy(task_cmdline, ptmp, szread);
		}	
	}	

	task_cmdline[szread] = '\0';

	string_replace_char(task_cmdline, szread, '\0', ' ');
	
	task_cmdline[szread] = '\0';

	return szread;
}	

void TASK_STAT::clear_listener_table() noexcept
{
	last_listen_tusec_ = 0;
	ntcp_listeners.store(0, std::memory_order_relaxed);

	auto shrlisten = listen_tbl_shr.load(std::memory_order_relaxed);
	auto plisten_table = shrlisten.get();

	if (plisten_table) {
		plisten_table->delete_single_elem(task_pid, get_pid_hash(task_pid));
	}

	listen_tbl_shr.store({}, std::memory_order_release);
	related_listen_.store({}, std::memory_order_release);

	is_tcp_server = false;

	listen_tbl_inherited.store(0, std::memory_order_release);
}	

int TASK_STAT::update_task_info(int proc_dir_fd) noexcept
{
	int			ret = -1;

	if (is_ready.load(std::memory_order_relaxed) == TASK_UPD_FULL) {
		return 1;
	}	
	else if (TASK_STATE_VALID != task_valid.load(std::memory_order_relaxed)) {
		return 1;
	}	

	GY_SCOPE_EXIT {
		if (ret != 0) {
			is_ready.store(TASK_UPD_ERROR, std::memory_order_relaxed);
			task_valid.store(TASK_STATE_ERROR, std::memory_order_relaxed);
		}	
	};

	try {
		if (is_ready.load(std::memory_order_relaxed) == TASK_UPD_COPIED) {
			ret = set_task_proc_stat_misc(proc_dir_fd, task_pid);
			if (ret < 0) {
				return ret;
			}	

			ret = set_task_proc_status(proc_dir_fd, task_pid);
			if (ret < 0) {
				return ret;
			}	
		}	
		else if (is_ready.load(std::memory_order_relaxed) == TASK_UPD_COPIED_EXEC) {
			ret = set_task_proc_status(proc_dir_fd, task_pid);
			if (ret < 0) {
				return ret;
			}	
		}	
		
		if (nullptr == pext_stats.get()) {
			pext_stats = std::make_unique<TASK_EXT_STATS>(this);
		}	

		set_task_cgroups(proc_dir_fd);

		if (0 != ntcp_listeners.load(std::memory_order_relaxed)) {

			if (is_execv_task) {
				uint8_t		inhval = listen_tbl_inherited.load(std::memory_order_acquire);
				 
				if (1 == inhval && task_pgid != parent_pgid) {
					/*
					 * We clear out this process from the listener monitor list as we are likely an unrelated process.
					 * If the listener socket was in fact being used (no O_CLOEXEC), the listener inode verify will
					 * again update this proc later.
					 */
					if (true == listen_tbl_inherited.compare_exchange_strong(inhval, 2)) {
						clear_listener_table();
					}
				}
			}
			else {
				is_tcp_client |= is_parent_tcp_client;
			}	

			auto shrlisten = listen_tbl_shr.load(std::memory_order_relaxed);
			auto plisten_table = shrlisten.get();

			if (plisten_table) {
				if (false == plisten_table->template lookup_single_elem<RCU_LOCK_FAST>(task_pid, get_pid_hash(task_pid))) {
					SHR_TASK_ELEM_TYPE		*pshrtask;

					pshrtask = new SHR_TASK_ELEM_TYPE(shared_from_this());	

					plisten_table->template insert_or_replace<RCU_LOCK_SLOW>(pshrtask, task_pid, get_pid_hash(task_pid));
				}
				is_tcp_server = true;
			}
		}

		is_ready.store(TASK_UPD_FULL, std::memory_order_relaxed);
		ret = 0;

		return 0;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINT_OFFLOAD("Task PID %d lazy updation threw an exception : %s\n", task_pid, GY_GET_EXCEPT_STRING););
		return -1;
	);
}	

TASK_STAT::TASK_STAT(int proc_dir_fd, pid_t pidin, pid_t ppidin, char *exe_path_in, char *cmdline_in) 
	: task_pid(pidin), is_ready(TASK_UPD_UNINIT), task_valid(TASK_STATE_UNINIT)
{
	/*GY_MT_COLLECT_PROFILE(100'000, "New Task unknown Parent");*/

	try {
		int			ret;
		
		*task_comm		= '\0';
		*task_orig_comm		= '\0';
		*task_exe_path		= '\0';
		*task_cmdline		= '\0';
		*task_parent_comm	= '\0';

		ret = set_task_proc_stat_misc(proc_dir_fd, task_pid);
		if (ret < 0) {
			return;
		}	

		if (gy_unlikely(true == is_task_kthread(this->task_flags))) {
			*task_exe_path = '\0';
			*task_orig_comm = '\0';
			*task_cmdline = '\0';
			*task_parent_comm = '\0';
		}
		else {	
			if (exe_path_in && *exe_path_in) {
				ret = GY_STRNCPY_LEN(task_exe_path, exe_path_in, sizeof(task_exe_path));
			}
			else {
				ret = get_task_exe_path(pidin, task_exe_path, sizeof(task_exe_path), proc_dir_fd); 
				if (ret < 0) {
					DEBUGEXECN(20, PERRORPRINT_OFFLOAD("Failed to get exe_path of PID %d", pidin));
					return;
				}	
			}
			const char		*ptmp1 = (const char *)memrchr(task_exe_path, '/', ret);

			if (!ptmp1) {
				ptmp1 = task_exe_path;
			}	
			else {
				ptmp1++;	
			}	

			get_escaped_comm(task_comm, ptmp1);
					
			bin_type = typeinfo::get_binary_type(task_comm);
				
			if (cmdline_in && *cmdline_in) {
				ret = GY_STRNCPY_LEN(task_cmdline, cmdline_in, sizeof(task_cmdline));
			}
			else {
				ret = get_cmdline(pidin, proc_dir_fd); 
				if (ret < 0) {
					DEBUGEXECN(20, PERRORPRINT_OFFLOAD("Failed to get cmdline of PID %d", pidin));
					return;
				}	
			}		

			cwd_inode = get_cwd_inode(pidin);
		}

		ret = set_task_proc_status(proc_dir_fd, task_pid);
		if (ret < 0) {
			return;
		}	

		ret = ns_inodes.populate_ns_inodes(proc_dir_fd, pidin, SYS_HARDWARE::get_root_ns_inodes());
		if (ret < 0) {
			DEBUGEXECN(20, PERRORPRINT_OFFLOAD("Failed to get process %d task inodes", pidin));
			return;
		}	

		is_container_proc = ns_inodes.in_container();

		is_ready.store(TASK_UPD_INIT_ONLY, std::memory_order_relaxed);
		task_valid.store(TASK_STATE_VALID, std::memory_order_relaxed);
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINT_OFFLOAD("Task PID %d initialization threw an exception : %s\n", pidin, GY_GET_EXCEPT_STRING););
		is_ready.store(TASK_UPD_ERROR, std::memory_order_relaxed);
		task_valid.store(TASK_STATE_ERROR, std::memory_order_relaxed);
	);
}		


TASK_STAT::TASK_STAT(TASK_STAT *parent, pid_t pid, int proc_dir_fd, bool from_main_thread) 
	: task_pid(pid), is_ready(TASK_UPD_UNINIT), task_valid(TASK_STATE_UNINIT)
{
	/*GY_MT_COLLECT_PROFILE(100'000, "New Forked Task from known Parent");*/

	/*
	 * Copy from parent task
	 */
	int				ret;
	 
	CONDEXEC(DEBUGEXECN(15, INFOPRINT_OFFLOAD("New Task %d : Populating from task table parent task %d : %s\n", pid, parent->task_pid, parent->task_comm)););

	task_ppid 			= parent->task_pid;
	task_pgid 			= parent->task_pgid;
	task_sid 			= parent->task_sid;

	task_nspgid			= 0;		// Will be updated later
	task_nspgid			= 0;
	task_nssid			= 0;

	memcpy(task_comm, parent->task_comm, sizeof(task_comm));
	memcpy(task_orig_comm, parent->task_orig_comm, sizeof(task_orig_comm));
	memcpy(task_exe_path, parent->task_exe_path, sizeof(task_exe_path));
	memcpy(task_cmdline, parent->task_cmdline, sizeof(task_cmdline));
	memcpy(task_parent_comm, parent->task_comm, sizeof(task_parent_comm));

	task_realuid			= parent->task_realuid;
	task_effuid			= parent->task_effuid;
	task_saveduid			= parent->task_saveduid;
	task_fsuid			= parent->task_fsuid;

	task_realgid			= parent->task_realgid;
	task_effgid			= parent->task_effgid;
	task_savedgid			= parent->task_savedgid;
	task_fsgid			= parent->task_fsgid;

	ncpus_allowed			= parent->ncpus_allowed;
	nmems_allowed			= parent->nmems_allowed;

	bin_type			= parent->bin_type;
	cwd_inode			= parent->cwd_inode;

	aggr_task_id_.store(parent->aggr_task_id_.load(std::memory_order_relaxed), std::memory_order_relaxed);

	task_flags			= parent->task_flags;

	starttimeusec			= get_usec_time();	// Will be updated later

	task_priority			= parent->task_priority;
	task_nice			= parent->task_nice;
	task_rt_priority 		= parent->task_rt_priority;
	task_sched_policy		= parent->task_sched_policy;
	
	parent->nchild_recent_forks_++;
	parent->last_fork_tsec_		= starttimeusec/GY_USEC_PER_SEC;
	
	/*
	 * NS should not be copied as CLONE_NEW* flags could have been used
	 */
	ret = ns_inodes.populate_ns_inodes(proc_dir_fd, task_pid, SYS_HARDWARE::get_root_ns_inodes());
	if (ret < 0) {
		CONDEXEC(DEBUGEXECN(20, PERRORPRINT_OFFLOAD("Failed to get process %d task inodes", pid)););
		is_ready.store(TASK_UPD_ERROR, std::memory_order_relaxed);
		task_valid.store(TASK_STATE_ERROR, std::memory_order_relaxed);
		return;
	}	

	is_container_proc 		= ns_inodes.in_container();

	weak_parent_task		= parent->weak_from_this();
	parent_ppid			= parent->task_ppid;
	parent_pgid			= parent->task_pgid;

	is_parent_tcp_client 		= parent->is_tcp_client;
	
	is_forked_task			= true;
	sent_aggr_server_.store(parent->sent_aggr_server_.load(std::memory_order_relaxed), std::memory_order_relaxed);

	if (from_main_thread && (true == parent->cgroups_updated.load(std::memory_order_acquire))) {
#if 0
		cg_cpu_shr		= parent->cg_cpu_shr;
		cg_cpuset_shr		= parent->cg_cpuset_shr;
		cg_memory_shr		= parent->cg_memory_shr;
		cg_2_shr		= parent->cg_2_shr;
#endif	
		time_t			tcur = starttimeusec/GY_USEC_PER_SEC;

		/*
		 * Set cgroup changed flag
		 * cgroup task table will be updated lazily later
		 */
		if (parent->cg_cpu_shr) {
			parent->cg_cpu_shr->set_cgroup_updated(tcur);
		}	
		if (parent->cg_cpuset_shr) {
			parent->cg_cpuset_shr->set_cgroup_updated(tcur);
		}	
		if (parent->cg_memory_shr) {
			parent->cg_memory_shr->set_cgroup_updated(tcur);
		}	
		if (parent->cg_2_shr) {
			parent->cg_2_shr->set_cgroup_updated(tcur);
		}	
	}

	auto nlist = parent->ntcp_listeners.load(std::memory_order_acquire);
	if (nlist) {
		last_listen_tusec_ = starttimeusec;
		ntcp_listeners.store(nlist, std::memory_order_release);
		listen_tbl_shr.store(parent->listen_tbl_shr.load(std::memory_order_acquire), std::memory_order_relaxed);
		related_listen_.store(parent->related_listen_.load(std::memory_order_acquire), std::memory_order_relaxed);

		listen_tbl_inherited.store(1, std::memory_order_release);
	}	

	is_ready.store(TASK_UPD_COPIED, std::memory_order_relaxed);
	task_valid.store(TASK_STATE_VALID, std::memory_order_relaxed);
}	

} // namespace gyeeta
	
