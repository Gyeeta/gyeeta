
#include		"gy_common_inc.h"
#include 		"gy_acct_taskstat.h"
#include 		"gy_statistics.h"

using namespace 	gyeeta;

int create_taskstats_sock(struct mnl_socket **ppnl, uint32_t & portid)
{
	struct mnl_socket	*pnl;

	pnl = mnl_socket_open(NETLINK_GENERIC);
	if (pnl == nullptr) {
		PERRORPRINT("mnl_socket_open failed");
		return -1;
	}
	
	*ppnl = pnl;

	if (mnl_socket_bind(pnl, 0, MNL_SOCKET_AUTOPID) < 0) {
		PERRORPRINT("mnl_socket_bind failed");
	
		mnl_socket_close(pnl);
		return -1;
	}

	portid = mnl_socket_get_portid(pnl);
	
	return 0;
}

int init_taskstats_sock(struct mnl_socket *pnl, uint32_t portid, uint16_t & familyid)
{
	char 			buf[GY_MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr 	*pnlh;
	struct genlmsghdr 	*pgenl;
	int 			ret;
	uint32_t 		seq;
	uint16_t		famid = 0;

	pnlh 			= mnl_nlmsg_put_header(buf);
	pnlh->nlmsg_type	= GENL_ID_CTRL;
	pnlh->nlmsg_flags 	= NLM_F_REQUEST | NLM_F_ACK;
	pnlh->nlmsg_seq 	= seq = time(nullptr);

	pgenl 			= static_cast<genlmsghdr *>(mnl_nlmsg_put_extra_header(pnlh, sizeof(struct genlmsghdr)));
	pgenl->cmd 		= CTRL_CMD_GETFAMILY;
	pgenl->version 		= 1;

	mnl_attr_put_u16(pnlh, CTRL_ATTR_FAMILY_ID, GENL_ID_CTRL);
	mnl_attr_put_strz(pnlh, CTRL_ATTR_FAMILY_NAME, TASKSTATS_GENL_NAME);

	if (mnl_socket_sendto(pnl, pnlh, pnlh->nlmsg_len) < 0) {
		PERRORPRINT("mnl_socket_sendto for family id");
		return -1;
	}
	
	auto lam_cb = [](const struct nlmsghdr *pnlh, void *data) noexcept
	{
		struct genlmsghdr 		*pdata = static_cast<genlmsghdr *>(mnl_nlmsg_get_payload(pnlh));
		struct nlattr 			*pattr;
		uint16_t 			attr_len;
		uint16_t			*pfamilyid = static_cast<uint16_t *>(data);

		if (mnl_nlmsg_get_payload_len(pnlh) < sizeof(*pdata)) {
			DEBUGEXECN(1, ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Invalid Netlink message length seen %lu while getting taskstats family id info\n", 
				mnl_nlmsg_get_payload_len(pnlh)););
			return MNL_CB_STOP;
		}	

		gy_mnl_attr_for_each(pattr, pnlh, sizeof(*pdata)) {
			int type = mnl_attr_get_type(pattr);

			if (mnl_attr_type_valid(pattr, CTRL_ATTR_MAX) < 0) {
				continue;
			}	

			switch (type) {
			
			case CTRL_ATTR_FAMILY_ID : 
				if (mnl_attr_validate(pattr, MNL_TYPE_U16) >= 0) {
					*pfamilyid = mnl_attr_get_u16(pattr);
					return MNL_CB_OK;
				}	
				break;
			
			default :
				break;
			}
		}	
			
		return MNL_CB_OK;
	};

	ret = mnl_socket_recvfrom(pnl, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, seq, portid, lam_cb, &famid);
		if (ret <= 0)
			break;
		ret = mnl_socket_recvfrom(pnl, buf, sizeof(buf));
	}

	if (ret < 0 || famid == 0) {
		ERRORPRINT("error while receiving family id for taskstats\n");
		return -1;
	}
	
	familyid = famid;

	return 0;
}	


int get_stats(struct mnl_socket *pnl, uint32_t portid, uint16_t familyid, pid_t pid, bool is_tgid, struct GY_TASKSTATS *pstats)
{
	char 			buf[GY_MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr 	*pnlh;
	struct genlmsghdr 	*pgenl;
	int 			ret;
	uint32_t 		seq;

	pnlh 			= mnl_nlmsg_put_header(buf);
	pnlh->nlmsg_type	= familyid;
	pnlh->nlmsg_flags 	= NLM_F_REQUEST | NLM_F_ACK;
	pnlh->nlmsg_seq 	= seq = time(nullptr);

	pgenl 			= static_cast<genlmsghdr *>(mnl_nlmsg_put_extra_header(pnlh, sizeof(struct genlmsghdr)));
	pgenl->cmd 		= TASKSTATS_CMD_GET;
	pgenl->version 		= 1;

	mnl_attr_put_u32(pnlh, (is_tgid ? TASKSTATS_CMD_ATTR_TGID : TASKSTATS_CMD_ATTR_PID), (uint32_t)pid);

	if (mnl_socket_sendto(pnl, pnlh, pnlh->nlmsg_len) < 0) {
		PERRORPRINT("mnl_socket_sendto for TASKSTATS_CMD_GET");
		return -1;
	}

	auto lam_cb = [](const struct nlmsghdr *pnlh, void *data) noexcept
	{
		struct genlmsghdr 		*pdata = static_cast<genlmsghdr *>(mnl_nlmsg_get_payload(pnlh));
		struct nlattr 			*pattr;
		uint16_t 			attr_len;
		struct GY_TASKSTATS		*pstats = static_cast<GY_TASKSTATS *>(data);

		if (mnl_nlmsg_get_payload_len(pnlh) < sizeof(*pdata)) {
			DEBUGEXECN(1, ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Invalid Netlink message length seen %lu while getting taskstats family id info\n", 
				mnl_nlmsg_get_payload_len(pnlh)););
			return MNL_CB_STOP;
		}	

		std::memset(pstats, 0, sizeof(*pstats));

		gy_mnl_attr_for_each(pattr, pnlh, sizeof(*pdata)) {
			int type = mnl_attr_get_type(pattr);

			if (mnl_attr_type_valid(pattr, TASKSTATS_TYPE_MAX) < 0) {
				continue;
			}	

			switch (type) {
			
			case TASKSTATS_TYPE_AGGR_TGID : 
			case TASKSTATS_TYPE_AGGR_PID : 
			{
				const struct nlattr 		*pattr_nest;
				pid_t				pid = 0;
				bool				is_tgid = false;
				
				gy_mnl_attr_for_each_nested(pattr_nest, pattr) {
					int type_nest = mnl_attr_get_type(pattr_nest);

					switch (type_nest) {
					
					case TASKSTATS_TYPE_PID :
						pid = mnl_attr_get_u32(pattr_nest);
						is_tgid = false;
						break;

					case TASKSTATS_TYPE_TGID :
						pid = mnl_attr_get_u32(pattr_nest);
						is_tgid = true;
						break;

					case TASKSTATS_TYPE_STATS :
						attr_len = mnl_attr_get_payload_len(pattr_nest);

						if (attr_len >= MIN_TASKSTATS_LEN) {
							struct GY_TASKSTATS 	*pstatsin = static_cast<GY_TASKSTATS *>(mnl_attr_get_payload(pattr_nest));

							std::memcpy(pstats, pstatsin, attr_len);
						}	
						else {
							ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Taskstats reply is of an invalid length %u instead of %lu\n",
								attr_len, sizeof(*pstats));

							return MNL_CB_STOP;
						}	

						break;

					default :
						break;
					}	
				}	
			}

			break;
			
			default :
				break;
			}
		}	
			
		return MNL_CB_OK;
	};

	ret = mnl_socket_recvfrom(pnl, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, seq, portid, lam_cb, pstats);
		if (ret <= 0)
			break;
		ret = mnl_socket_recvfrom(pnl, buf, sizeof(buf));
	}

	if (ret < 0) {
		PERRORPRINT("error while receiving taskstats data");
		return -1;
	}

	return 0;
}	

static constexpr 	double ms_per_ns = 1e6;


int main(int argc, char *argv[])
{
	pid_t			pid = getppid();

	if (argc == 2) {
		pid = atoi(argv[1]);
	}

	IRPRINT("\n\n");

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Starting taskstats for PID %d\n", pid);
	
	struct GY_TASKSTATS	taskstat_tgid, taskstat_pid;
	struct mnl_socket 	*pnl;
	uint32_t		portid;
	uint16_t		familyid;
	int			ret;

	ret = create_taskstats_sock(&pnl, portid);
	if (ret != 0) {
		return ret;
	}	

	ret = init_taskstats_sock(pnl, portid, familyid);
	if (ret != 0) {
		return ret;
	}	

	for (int i = 0; i < 10000; i++) {
		GY_NOMT_COLLECT_PROFILE(10000, "Time for getting taskstats from netlink");

		ret = get_stats(pnl, portid, familyid, pid, true, &taskstat_tgid);
		if (ret != 0) {
			return ret;
		}
	}
	
	for (int i = 0; i < 10000; i++) {
		GY_NOMT_COLLECT_PROFILE(10000, "Time for getting /proc/PID/stat");

		uint64_t		aminflt = 0, amajflt = 0, ausertime = 0, asystime = 0, avmsize = 0, arss = 0, ablkio_ticks = 0;
		uint64_t			anum_threads = 0;
		
		ret = get_task_cpu_mem_stats(pid, pid, &aminflt, &amajflt, &ausertime, &asystime, &anum_threads, &avmsize, &arss, &ablkio_ticks, true);
		if (ret != 0) {
			PERRORPRINT("Could not get Thread/Proc CPU/Memory statistics for PID %d", pid);
			return -1;
		}
	}

	ret = get_stats(pnl, portid, familyid, pid, false, &taskstat_pid);
	if (ret != 0) {
		return ret;
	}

	IRPRINT("\n\n");
	INFOPRINT(GY_COLOR_GREEN "Process wide stats for PID %d : \n", pid);
	TASKSTATS_HDLR::print_stats(&taskstat_tgid);
	
	IRPRINT("\n\n");

	INFOPRINT(GY_COLOR_CYAN "Thread Task stats for TID %d : \n", pid);
	TASKSTATS_HDLR::print_stats(&taskstat_pid);

	IRPRINT("\n\n");

	INFOPRINT(GY_COLOR_YELLOW "Now starting per second process wide delay analysis of PID %d for the next 60 seconds\n\n", pid);

	using DELAY_HISTOGRAM 		= GY_HISTOGRAM<int, SEMI_LOG_HASH>;
	using CSWITCH_HISOGRAM		= GY_HISTOGRAM<int, SEMI_LOG_HASH>;

	PROC_CPU_IO_STATS		proc_cpu(pid);
	min_max_counter<false>		acpu_delay, ablkio_delay, aswapin_delay, avol_switch, ainvol_switch;
	uint64_t			last_cpu_delay = 0, last_blkio_delay = 0, last_swapin_delay = 0, last_vol_switch = 0, last_invol_switch = 0;
	uint64_t			tot_delay, min_delay, max_delay, niter;
	double				avg_delay;
	DELAY_HISTOGRAM			cpu_delay_histogram_;
	DELAY_HISTOGRAM			blkio_delay_histogram_;
	CSWITCH_HISOGRAM		vol_cs_histogram_;
	CSWITCH_HISOGRAM		invol_cs_histogram_;

	ret = get_stats(pnl, portid, familyid, pid, true, &taskstat_tgid);
	if (ret != 0) {
		return ret;
	}

	last_cpu_delay		= taskstat_tgid.cpu_delay_total;
	last_blkio_delay	= taskstat_tgid.blkio_delay_total;
	last_swapin_delay	= taskstat_tgid.swapin_delay_total;

	last_vol_switch		= taskstat_tgid.nvcsw;
	last_invol_switch	= taskstat_tgid.nivcsw;

	for (int i = 0; i < 60; ++i) {
		ret = get_stats(pnl, portid, familyid, pid, true, &taskstat_tgid);
		if (ret != 0) {
			break;
		}

		acpu_delay.add(gy_diff_counter(taskstat_tgid.cpu_delay_total, last_cpu_delay));
		ablkio_delay.add(gy_diff_counter(taskstat_tgid.blkio_delay_total, last_blkio_delay));
		aswapin_delay.add(gy_diff_counter(taskstat_tgid.swapin_delay_total, last_swapin_delay));

		avol_switch.add(gy_diff_counter_safe(taskstat_tgid.nvcsw, last_vol_switch));
		ainvol_switch.add(gy_diff_counter_safe(taskstat_tgid.nivcsw, last_invol_switch));

		cpu_delay_histogram_.add_data(gy_diff_counter_safe(taskstat_tgid.cpu_delay_total, last_cpu_delay)/GY_NSEC_PER_MSEC);
		blkio_delay_histogram_.add_data(gy_diff_counter_safe(taskstat_tgid.blkio_delay_total, last_blkio_delay)/GY_NSEC_PER_MSEC);
		vol_cs_histogram_.add_data(gy_diff_counter_safe(taskstat_tgid.nvcsw, last_vol_switch));
		invol_cs_histogram_.add_data(gy_diff_counter_safe(taskstat_tgid.nivcsw, last_invol_switch));

		last_cpu_delay 		= taskstat_tgid.cpu_delay_total;
		last_blkio_delay	= taskstat_tgid.blkio_delay_total;
		last_swapin_delay 	= taskstat_tgid.swapin_delay_total;

		last_vol_switch		= taskstat_tgid.nvcsw;
		last_invol_switch	= taskstat_tgid.nivcsw;
		
		gy_nanosleep(1, 0);
	}

	proc_cpu.get_current_stats(true);
		
	acpu_delay.get_current(&tot_delay, &min_delay, &max_delay, &niter, &avg_delay);

	INFOPRINT("CPU Delay msec per sec stats	: Min %15.3f 	Max %15.3f 	Avg %15.3f\n", 
			min_delay/ms_per_ns, max_delay/ms_per_ns, avg_delay/ms_per_ns);

	ablkio_delay.get_current(&tot_delay, &min_delay, &max_delay, &niter, &avg_delay);

	INFOPRINT("Blkio Delay msec per sec stats	: Min %15.3f 	Max %15.3f 	Avg %15.3f\n", 
			min_delay/ms_per_ns, max_delay/ms_per_ns, avg_delay/ms_per_ns);

	aswapin_delay.get_current(&tot_delay, &min_delay, &max_delay, &niter, &avg_delay);

	INFOPRINT("Swapin Delay msec per sec stats	: Min %15.3f 	Max %15.3f 	Avg %15.3f\n\n", 
			min_delay/ms_per_ns, max_delay/ms_per_ns, avg_delay/ms_per_ns);

	avol_switch.get_current(&tot_delay, &min_delay, &max_delay, &niter, &avg_delay);
	INFOPRINT("Voluntary Context Switches/sec	: Min %15lu 	Max %15lu 	Avg %15.3f\n", min_delay, max_delay, avg_delay);

	ainvol_switch.get_current(&tot_delay, &min_delay, &max_delay, &niter, &avg_delay);
	INFOPRINT("Involuntary Context Switches/sec	: Min %15lu 	Max %15lu 	Avg %15.3f\n", min_delay, max_delay, avg_delay);

	const float			pctarr[] = {25, 50, 95, 99.9};
	STRING_BUFFER<8192>	strbuf;
	
	strbuf.appendconst("\n\n\tCPU Delay Histogram follows : ");
	cpu_delay_histogram_.print_stats(strbuf, pctarr, GY_ARRAY_SIZE(pctarr), "CPU Delay msec");

	strbuf.appendconst("\n\n\tBlkio Delay Histogram follows : ");
	blkio_delay_histogram_.print_stats(strbuf, pctarr, GY_ARRAY_SIZE(pctarr), "Blkio Delay msec");
	
	strbuf.appendconst("\n\n\tVoluntary Context Switches Histogram follows : ");
	vol_cs_histogram_.print_stats(strbuf, pctarr, GY_ARRAY_SIZE(pctarr), "Vol CS");

	strbuf.appendconst("\n\n\tInvoluntary Context Switches Histogram follows : ");
	invol_cs_histogram_.print_stats(strbuf, pctarr, GY_ARRAY_SIZE(pctarr), "Invol CS");

	INFOPRINT("%s\n\n", strbuf.buffer());
	
	ret = get_stats(pnl, portid, familyid, pid, true, &taskstat_tgid);
	if (ret != 0) {
		return ret;
	}

	IRPRINT("\n\n");
	INFOPRINT(GY_COLOR_GREEN "Final Process wide stats for PID %d : \n", pid);
	TASKSTATS_HDLR::print_stats(&taskstat_tgid);

	ret = get_stats(pnl, portid, familyid, pid, false, &taskstat_pid);
	if (ret != 0) {
		return ret;
	}

	IRPRINT("\n\n");

	INFOPRINT(GY_COLOR_CYAN "Final Thread Task stats for TID %d : \n", pid);
	TASKSTATS_HDLR::print_stats(&taskstat_pid);

	mnl_socket_close(pnl);
	
	return 0;
}

