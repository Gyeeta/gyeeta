
#pragma				once

#include			"gy_common_inc.h"
#include 			"gy_inet_inc.h"
#include 			"gy_print_offload.h"

#include 			<libmnl/libmnl.h>
#include 			<linux/genetlink.h>

namespace gyeeta {

/*
 * Definitions for GY_TASKSTATS copied from linux/taskstats.h
 */

#define TS_COMM_LEN		32	/* should be >= TASK_COMM_LEN in linux/sched.h */

struct GY_TASKSTATS 
{
	/* The version number of this struct. This field is always set to
	 * TASKSTATS_VERSION, which is defined in <linux/taskstats.h>.
	 * Each time the struct is changed, the value should be incremented.
	 */
	uint16_t	version;
	uint32_t	ac_exitcode;		/* Exit status */

	/* The accounting flags of a task as defined in <linux/acct.h>
	 * Defined values are AFORK, ASU, ACOMPAT, ACORE, and AXSIG.
	 */
	uint8_t		ac_flag;		/* Record flags */
	uint8_t		ac_nice;		/* task_nice */

	/* Delay accounting fields start
	 *
	 * All values, until comment "Delay accounting fields end" are
	 * available only if delay accounting is enabled, even though the last
	 * few fields are not delays
	 *
	 * xxx_count is the number of delay values recorded
	 * xxx_delay_total is the corresponding cumulative delay in nanoseconds
	 *
	 * xxx_delay_total wraps around to zero on overflow
	 * xxx_count incremented regardless of overflow
	 */

	/* Delay waiting for cpu, while runnable
	 * count, delay_total NOT updated atomically
	 */
	uint64_t	cpu_count __attribute__((aligned(8)));
	uint64_t	cpu_delay_total;

	/* Following four fields atomically updated using task->delays->lock */

	/* Delay waiting for synchronous block I/O to complete
	 * does not account for delays in I/O submission
	 */
	uint64_t	blkio_count;
	uint64_t	blkio_delay_total;

	/* Delay waiting for page fault I/O (swap in only) */
	uint64_t	swapin_count;
	uint64_t	swapin_delay_total;

	/* cpu "wall-clock" running time
	 * On some architectures, value will adjust for cpu time stolen
	 * from the kernel in involuntary waits due to virtualization.
	 * Value is cumulative, in nanoseconds, without a corresponding count
	 * and wraps around to zero silently on overflow
	 */
	uint64_t	cpu_run_real_total;

	/* cpu "virtual" running time
	 * Uses time intervals seen by the kernel i.e. no adjustment
	 * for kernel's involuntary waits due to virtualization.
	 * Value is cumulative, in nanoseconds, without a corresponding count
	 * and wraps around to zero silently on overflow
	 */
	uint64_t	cpu_run_virtual_total;
	/* Delay accounting fields end */
	/* version 1 ends here */

	/* Basic Accounting Fields start */
	char		ac_comm[TS_COMM_LEN];	/* Command name */
	uint8_t		ac_sched __attribute__((aligned(8)));
					/* Scheduling discipline */
	uint8_t		ac_pad[3];
	uint32_t	ac_uid __attribute__((aligned(8)));
					/* User ID */
	uint32_t	ac_gid;			/* Group ID */
	uint32_t	ac_pid;			/* Process ID */
	uint32_t	ac_ppid;		/* Parent process ID */
	uint32_t	ac_btime;		/* Begin time [sec since 1970] */
	uint64_t	ac_etime __attribute__((aligned(8)));
					/* Elapsed time [usec] */
	uint64_t	ac_utime;		/* User CPU time [usec] */
	uint64_t	ac_stime;		/* SYstem CPU time [usec] */
	uint64_t	ac_minflt;		/* Minor Page Fault Count */
	uint64_t	ac_majflt;		/* Major Page Fault Count */
	/* Basic Accounting Fields end */

	/* Extended accounting fields start */
	/* Accumulated RSS usage in duration of a task, in MBytes-usecs.
	 * The current rss usage is added to this counter every time
	 * a tick is charged to a task's system time. So, at the end we
	 * will have memory usage multiplied by system time. Thus an
	 * average usage per system time unit can be calculated.
	 */
	uint64_t	coremem;		/* accumulated RSS usage in MB-usec */
	/* Accumulated virtual memory usage in duration of a task.
	 * Same as acct_rss_mem1 above except that we keep track of VM usage.
	 */
	uint64_t	virtmem;		/* accumulated VM  usage in MB-usec */

	/* High watermark of RSS and virtual memory usage in duration of
	 * a task, in KBytes.
	 */
	uint64_t	hiwater_rss;		/* High-watermark of RSS usage, in KB */
	uint64_t	hiwater_vm;		/* High-water VM usage, in KB */

	/* The following four fields are I/O statistics of a task. */
	uint64_t	read_char;		/* bytes read */
	uint64_t	write_char;		/* bytes written */
	uint64_t	read_syscalls;		/* read syscalls */
	uint64_t	write_syscalls;		/* write syscalls */
	/* Extended accounting fields end */

	/* Per-task storage I/O accounting starts */
	uint64_t	read_bytes;		/* bytes of read I/O */
	uint64_t	write_bytes;		/* bytes of write I/O */
	uint64_t	cancelled_write_bytes;	/* bytes of cancelled write I/O */

	uint64_t  	nvcsw;			/* voluntary_ctxt_switches */
	uint64_t  	nivcsw;			/* nonvoluntary_ctxt_switches */

	/* time accounting for SMT machines */
	uint64_t	ac_utimescaled;		/* utime scaled on frequency etc */
	uint64_t	ac_stimescaled;		/* stime scaled on frequency etc */
	uint64_t	cpu_scaled_run_real_total; /* scaled cpu_run_real_total */

	/* Delay waiting for memory reclaim */
	uint64_t	freepages_count;
	uint64_t	freepages_delay_total;

	/* Delay waiting for thrashing page */	/* From 4.20 Kernel onwards */
	uint64_t	thrashing_count;
	uint64_t	thrashing_delay_total;

	/* v10: 64-bit btime to avoid overflow */
	uint64_t	ac_btime64;		/* 64-bit begin time */

	/* Delay waiting for memory compact */
	uint64_t	compact_count;
	uint64_t	compact_delay_total;
};

/*
 * Commands sent from userspace
 * Not versioned. New commands should only be inserted at the enum's end
 * prior to __TASKSTATS_CMD_MAX
 */

enum {
	TASKSTATS_CMD_UNSPEC = 0,	/* Reserved */
	TASKSTATS_CMD_GET,		/* user->kernel request/get-response */
	TASKSTATS_CMD_NEW,		/* kernel->user event */
	__TASKSTATS_CMD_MAX,
};

#define TASKSTATS_CMD_MAX (__TASKSTATS_CMD_MAX - 1)

enum {
	TASKSTATS_TYPE_UNSPEC = 0,	/* Reserved */
	TASKSTATS_TYPE_PID,		/* Process id */
	TASKSTATS_TYPE_TGID,		/* Thread group id */
	TASKSTATS_TYPE_STATS,		/* taskstats structure */
	TASKSTATS_TYPE_AGGR_PID,	/* contains pid + stats */
	TASKSTATS_TYPE_AGGR_TGID,	/* contains tgid + stats */
	TASKSTATS_TYPE_NULL,		/* contains nothing */
	__TASKSTATS_TYPE_MAX,
};

#define TASKSTATS_TYPE_MAX (__TASKSTATS_TYPE_MAX - 1)

enum {
	TASKSTATS_CMD_ATTR_UNSPEC = 0,
	TASKSTATS_CMD_ATTR_PID,
	TASKSTATS_CMD_ATTR_TGID,
	TASKSTATS_CMD_ATTR_REGISTER_CPUMASK,
	TASKSTATS_CMD_ATTR_DEREGISTER_CPUMASK,
	__TASKSTATS_CMD_ATTR_MAX,
};

#define TASKSTATS_CMD_ATTR_MAX (__TASKSTATS_CMD_ATTR_MAX - 1)

/* NETLINK_GENERIC related info */

#define TASKSTATS_GENL_NAME		"TASKSTATS"
#define TASKSTATS_GENL_VERSION		0x1

static constexpr size_t MIN_TASKSTATS_LEN = offsetof(GY_TASKSTATS, ac_utimescaled); 


/*
 * The actual collection class
 */
class TASKSTATS_HDLR
{
	struct mnl_socket	*pnl_					{nullptr};
	char 			mnlbuf_[GY_MNL_SOCKET_BUFFER_SIZE]	{};
	GY_MUTEX		mutex_;
	gy_atomic<int>		nretries_				{0};
	uint32_t 		portid_					{0};
	uint16_t		familyid_				{0};

	static constexpr int	MAX_TASKSTATS_REINIT 			{1024};

public :
	TASKSTATS_HDLR()
	{
		create_sock();
		init_taskstats_sock();
	}	

	TASKSTATS_HDLR(const TASKSTATS_HDLR &)			= delete;
	TASKSTATS_HDLR & operator= (const TASKSTATS_HDLR &)	= delete;

	TASKSTATS_HDLR(TASKSTATS_HDLR && other) noexcept 
		: pnl_(std::exchange(other.pnl_, nullptr)), nretries_(other.nretries_), portid_(other.portid_), familyid_(other.familyid_)
	{
		std::memcpy(mnlbuf_, other.mnlbuf_, sizeof(mnlbuf_));
	}	

	TASKSTATS_HDLR & operator= (TASKSTATS_HDLR && other) noexcept 
	{
		if (this != &other) {
			close_sock();
			
			pnl_ 		= std::exchange(other.pnl_, nullptr);
			nretries_	= other.nretries_;
			familyid_	= other.familyid_;
					
			std::memcpy(mnlbuf_, other.mnlbuf_, sizeof(mnlbuf_));
		}	
		return *this;
	}

	~TASKSTATS_HDLR() noexcept
	{
		close_sock();
	}	

	// Thread-safe if ScopeLock is not set to NULL_MUTEX
	// Returns 0 on success. > 0 on receive error which can happen if the process exits and < 0 on send error if the netlink conn was closed
	// If retry_conn_on_error is set, will try one retry on error
	template <typename ScopeLock = SCOPE_GY_MUTEX>
	int get_taskstats_sync(pid_t pid, GY_TASKSTATS & stats, bool is_tgid = true, bool retry_conn_on_error = true, uint64_t curr_usec_clock = get_usec_clock()) noexcept
	{
		int				ret, ntries = 0;
tryagain :
		{
			ScopeLock		scopelock(&mutex_);
		
			ret = get_taskstats(pid, stats, is_tgid, curr_usec_clock);
		}
			
		if (ret < 0 && retry_conn_on_error && ntries == 0) {
			try {
				retry_taskstats_init();

				++ntries;
				goto tryagain;
			}
			catch (...) {
				return -1;
			}	
		}	

		return ret;
	}	

	void retry_taskstats_init()
	{
		try {
			int			nt = 1 + nretries_.fetch_add(1, std::memory_order_relaxed);
			
			if (nt > MAX_TASKSTATS_REINIT) {
				GY_THROW_EXCEPTION("Too many Taskstats init retries %d : Bailing out...", nt);
			}	

			INFOPRINT("Retrying Taskstats initialization : Current # retries %d...\n", nt);

			SCOPE_GY_MUTEX		scopelock(&mutex_);

			close_sock();

			create_sock();
			init_taskstats_sock();
		}
		GY_CATCH_EXCEPTION(
			ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Taskstats Re-initialization failed : %s\n", GY_GET_EXCEPT_STRING);
			throw;
		);	
	}

	static void print_stats(const GY_TASKSTATS *ps) noexcept
	{
		static constexpr 	double ms_per_ns = 1e6;

		STRING_BUFFER<4096>	strbuf;

		auto average_ms = [](uint64_t total, uint64_t count) noexcept -> double
		{
			if (!count) {
				return 0;
			}
			return ((double)total) / count / ms_per_ns;
		};

		strbuf.appendconst("\n\nBasic task statistics\n");
		strbuf.appendconst("---------------------\n");

		strbuf.appendfmt("%-25s%d\n", "Stats version:", ps->version);
		strbuf.appendfmt("%-25s%d\n", "Exit code:", ps->ac_exitcode);
		strbuf.appendfmt("%-25s0x%x\n", "Flags:", ps->ac_flag);
		strbuf.appendfmt("%-25s%d\n", "Nice value:", ps->ac_nice);
		strbuf.appendfmt("%-25s%s\n", "Command name:", ps->ac_comm);
		strbuf.appendfmt("%-25s%d\n", "Scheduling discipline:", ps->ac_sched);
		strbuf.appendfmt("%-25s%d\n", "UID:", ps->ac_uid);
		strbuf.appendfmt("%-25s%d\n", "GID:", ps->ac_gid);
		strbuf.appendfmt("%-25s%d\n", "PID:", ps->ac_pid);
		strbuf.appendfmt("%-25s%d\n", "PPID:", ps->ac_ppid);

		time_t begin_time = ps->ac_btime;
		strbuf.appendfmt("%-25s%s", "Begin time:", ctime(&begin_time));

		strbuf.appendfmt("%-25s%lu usec\n", "Elapsed time:", ps->ac_etime);
		strbuf.appendfmt("%-25s%lu usec\n", "User CPU time:", ps->ac_utime);
		strbuf.appendfmt("%-25s%lu\n", "Minor page faults:", ps->ac_minflt);
		strbuf.appendfmt("%-25s%lu\n", "Major page faults:", ps->ac_majflt);
		strbuf.appendfmt("%-25s%lu usec\n", "Scaled user time:", ps->ac_utimescaled);
		strbuf.appendfmt("%-25s%lu usec\n", "Scaled system time:", ps->ac_stimescaled);

		strbuf.appendconst("\n\n");
		strbuf.appendconst("Delay accounting\n");
		strbuf.appendconst("----------------\n");

		strbuf.appendfmt("       %15s%15s%15s%15s%15s%15s\n",
				"Count",
				"Delay (ms)",
				"Average delay",
				"Real Run Time",
				"Scaled Real",
				"Virtual Run");
		strbuf.appendfmt("CPU    %15lu%15.3f%15.3f%15.3f%15.3f%15.3f\n",
				ps->cpu_count,
				ps->cpu_delay_total / ms_per_ns,
				average_ms(ps->cpu_delay_total, ps->cpu_count),
				ps->cpu_run_real_total / ms_per_ns,
				ps->cpu_scaled_run_real_total / ms_per_ns,
				ps->cpu_run_virtual_total / ms_per_ns);
		strbuf.appendfmt("IO     %15lu%15.3f%15.3f\n",
				ps->blkio_count,
				ps->blkio_delay_total / ms_per_ns,
				average_ms(ps->blkio_delay_total, ps->blkio_count));
		strbuf.appendfmt("Swap   %15lu%15.3f%15.3f\n",
				ps->swapin_count,
				ps->swapin_delay_total / ms_per_ns,
				average_ms(ps->swapin_delay_total, ps->swapin_count));
		strbuf.appendfmt("Reclaim%15lu%15.3f%15.3f\n",
				ps->freepages_count,
				ps->freepages_delay_total / ms_per_ns,
				average_ms(ps->freepages_delay_total, ps->freepages_count));
		strbuf.appendfmt("Thrashing%13lu%15.3f%15.3f\n",
				ps->thrashing_count,
				ps->thrashing_delay_total / ms_per_ns,
				average_ms(ps->thrashing_delay_total, ps->thrashing_count));
		strbuf.appendfmt("Compaction%13lu%15.3f%15.3f\n",
				ps->compact_count,
				ps->compact_delay_total / ms_per_ns,
				average_ms(ps->compact_delay_total, ps->compact_count));

		strbuf.appendconst("\nExtended accounting fields\n");
		strbuf.appendconst("--------------------------\n");

		strbuf.appendfmt("%-25s%.3f MB\n", "Average RSS usage:",
				(double)ps->coremem / (ps->ac_stime ? ps->ac_stime : 1));
		strbuf.appendfmt("%-25s%.3f MB\n", "Average VM usage:",
				(double)ps->virtmem / (ps->ac_stime ? ps->ac_stime : 1));
		strbuf.appendfmt("%-25s%lu KB\n", "RSS high water mark:", ps->hiwater_rss);
		strbuf.appendfmt("%-25s%lu KB\n", "VM high water mark:", ps->hiwater_vm);
		strbuf.appendfmt("%-25s%lu\n", "IO bytes read:", ps->read_char);
		strbuf.appendfmt("%-25s%lu\n", "IO bytes written:", ps->write_char);
		strbuf.appendfmt("%-25s%lu\n", "IO read syscalls:", ps->read_syscalls);
		strbuf.appendfmt("%-25s%lu\n", "IO write syscalls:", ps->write_syscalls);

		strbuf.appendconst("\nPer-task/thread statistics\n");
		strbuf.appendconst("--------------------------\n");
		strbuf.appendfmt("%-25s%lu\n", "Voluntary switches:", ps->nvcsw);
		strbuf.appendfmt("%-25s%lu\n", "Involuntary switches:", ps->nivcsw);

		INFOPRINT_OFFLOAD("Taskstats : %s\n\n", strbuf.buffer());
	}

	static int			init_singleton();

	static TASKSTATS_HDLR 	*	get_singleton() noexcept;


private :
	
	void create_sock()
	{
		struct mnl_socket	*pnl;

		pnl = mnl_socket_open(NETLINK_GENERIC);
		if (pnl == nullptr) {
			GY_THROW_SYS_EXCEPTION("Taskstats socket open failed");
		}
		
		if (mnl_socket_bind(pnl, 0, MNL_SOCKET_AUTOPID) < 0) {
			int		olderrno = errno;

			mnl_socket_close(pnl);

			errno = olderrno;
			GY_THROW_SYS_EXCEPTION("Taskstats socket bind failed");
		}
		
		pnl_ 	= pnl;
		portid_ = mnl_socket_get_portid(pnl);
	}	

	void init_taskstats_sock()
	{
		struct nlmsghdr 	*pnlh;
		struct genlmsghdr 	*pgenl;
		int 			ret;
		uint32_t 		seq;
		uint16_t		famid = 0;

		pnlh 			= mnl_nlmsg_put_header(mnlbuf_);
		pnlh->nlmsg_type	= GENL_ID_CTRL;
		pnlh->nlmsg_flags 	= NLM_F_REQUEST | NLM_F_ACK;
		pnlh->nlmsg_seq 	= seq = time(nullptr);

		pgenl 			= static_cast<genlmsghdr *>(mnl_nlmsg_put_extra_header(pnlh, sizeof(struct genlmsghdr)));
		pgenl->cmd 		= CTRL_CMD_GETFAMILY;
		pgenl->version 		= 1;

		mnl_attr_put_u16(pnlh, CTRL_ATTR_FAMILY_ID, GENL_ID_CTRL);
		mnl_attr_put_strz(pnlh, CTRL_ATTR_FAMILY_NAME, TASKSTATS_GENL_NAME);

		if (mnl_socket_sendto(pnl_, pnlh, pnlh->nlmsg_len) < 0) {
			int		olderrno = errno;
			
			close_sock();
			
			errno = olderrno;
			GY_THROW_SYS_EXCEPTION("Taskstats initialization failed in send for family id");
		}
		
		auto lam_cb = [](const struct nlmsghdr *pnlh, void *data) noexcept
		{
			struct genlmsghdr 		*pdata = static_cast<genlmsghdr *>(mnl_nlmsg_get_payload(pnlh));
			struct nlattr 			*pattr;
			uint16_t 			attr_len;
			uint16_t			*pfamilyid = static_cast<uint16_t *>(data);

			if (mnl_nlmsg_get_payload_len(pnlh) < sizeof(*pdata)) {
				ERRORPRINT("Invalid Netlink message length seen %lu while getting taskstats family id info\n", mnl_nlmsg_get_payload_len(pnlh));
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

		ret = mnl_socket_recvfrom(pnl_, mnlbuf_, sizeof(mnlbuf_));
		while (ret > 0) {
			ret = mnl_cb_run(mnlbuf_, ret, seq, portid_, lam_cb, &famid);
			if (ret <= 0)
				break;
			ret = mnl_socket_recvfrom(pnl_, mnlbuf_, sizeof(mnlbuf_));
		}

		if (ret < 0 || famid == 0) {
			close_sock();

			GY_THROW_EXCEPTION("Invalid familyid received during taskstats initialization. Please confirm if CONFIG_TASKSTATS is enabled in kernel");
		}
		
		familyid_ = famid;
	}	

	void close_sock() noexcept
	{
		if (pnl_) {
			mnl_socket_close(pnl_);
			pnl_ = nullptr;
		}
	}	

	// Returns 0 on success. > 0 on receive error which can happen if the process exits and < 0 on send error if the netlink conn was closed
	int get_taskstats(pid_t pid, GY_TASKSTATS & stats, bool is_tgid, uint64_t curr_usec_clock) noexcept
	{
		struct nlmsghdr 	*pnlh;
		struct genlmsghdr 	*pgenl;
		int 			ret;
		uint32_t 		seq;

		if (nullptr == GY_READ_ONCE(pnl_)) {
			return -1;
		}
			
		pnlh 			= mnl_nlmsg_put_header(mnlbuf_);
		pnlh->nlmsg_type	= familyid_;
		pnlh->nlmsg_flags 	= NLM_F_REQUEST | NLM_F_ACK;
		pnlh->nlmsg_seq 	= seq = curr_usec_clock;

		pgenl 			= static_cast<genlmsghdr *>(mnl_nlmsg_put_extra_header(pnlh, sizeof(struct genlmsghdr)));
		pgenl->cmd 		= TASKSTATS_CMD_GET;
		pgenl->version 		= 1;

		mnl_attr_put_u32(pnlh, (is_tgid ? TASKSTATS_CMD_ATTR_TGID : TASKSTATS_CMD_ATTR_PID), static_cast<uint32_t>(pid));

		if (mnl_socket_sendto(pnl_, pnlh, pnlh->nlmsg_len) < 0) {
			DEBUGEXECN(1, PERRORPRINT("Task statistics send command failed"););
			return -1;
		}

		// Set stats.version to 0 to verify whether we got data
		stats.version = 0; 	

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
					pid_t				pidin = 0;
					
					gy_mnl_attr_for_each_nested(pattr_nest, pattr) {
						int type_nest = mnl_attr_get_type(pattr_nest);

						switch (type_nest) {
						
						case TASKSTATS_TYPE_PID :
							pidin = mnl_attr_get_u32(pattr_nest);
							break;

						case TASKSTATS_TYPE_TGID :
							pidin = mnl_attr_get_u32(pattr_nest);
							break;

						case TASKSTATS_TYPE_STATS :
							attr_len = mnl_attr_get_payload_len(pattr_nest);

							if (attr_len >= MIN_TASKSTATS_LEN) {
								struct GY_TASKSTATS 	*pstatsin = static_cast<GY_TASKSTATS *>(mnl_attr_get_payload(pattr_nest));

								std::memcpy(pstats, pstatsin, std::min<uint16_t>(attr_len, sizeof(*pstats)));

								if (attr_len < sizeof(*pstats)) {
									std::memset(reinterpret_cast<char *>(pstats) + attr_len, 0, sizeof(*pstats) - attr_len); 
								}	
							}	
							else {
								DEBUGEXECN(1,
									ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Taskstats reply is of an invalid length %u instead of %lu\n",
										attr_len, sizeof(*pstats));
								);
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

		ret = mnl_socket_recvfrom(pnl_, mnlbuf_, sizeof(mnlbuf_));
		while (ret > 0) {
			ret = mnl_cb_run(mnlbuf_, ret, seq, portid_, lam_cb, &stats);
			if (ret <= 0)
				break;
			ret = mnl_socket_recvfrom(pnl_, mnlbuf_, sizeof(mnlbuf_));
		}

		if (ret < 0) {
			return errno;
		}

		if (stats.version) {
			return 0;
		}	
		return 1;
	}	


};	

} // namespace gyeeta

