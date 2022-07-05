
/*
 * Process (task) related classes
 */
 
#pragma				once

#include 			"gy_common_inc.h"
#include 			"gy_file_api.h"
#include 			"gy_print_offload.h"
#include			"gy_misc.h"
#include			"gy_atomic.h"
#include 			"gy_rcu_inc.h"
#include 			"gy_mount_disk.h"
#include 			"gy_pkt_pool.h"
#include 			"gy_inet_inc.h"
#include 			"gy_comm_proto.h"
#include 			"gy_statistics.h"
#include 			"gy_task_types.h"

#include			"folly/concurrency/AtomicSharedPtr.h" 

#include			<bitset>
#include 			<sys/prctl.h>

namespace gyeeta {

[[gnu::pure]] static uint32_t get_pid_hash(pid_t pid) noexcept
{
	return jhash2((uint32_t *)&pid, sizeof(pid)/sizeof(uint32_t), 0xceedfead);
}	

class CGROUP1_CPUACCT;
class CGROUP1_CPU;
class CGROUP1_MEMORY;
class CGROUP1_BLKIO;
class CGROUP1_CPUSET;
	
class TASKSTATS_HDLR;
class TASK_STAT;

class RELATED_LISTENERS;

static constexpr int				MAX_PROC_STAT_LEN 	= 1024; 	// 52 words * ~20	
static constexpr int				TASK_STATS_UPDATE_MSEC	= 5000;		// Every 5 sec for main tasks
static constexpr int				MAX_TASK_STAT_HISTORY 	= 5;
static constexpr int				MAX_TASK_TAG_LEN	= 63;

struct TASK_KILL_INFO
{
	char				comm_[TASK_COMM_LEN];
	time_t				tkill_;
	pid_t				pid_;
	int				killsig_;

	void set_kill(const char *comm, pid_t pid, int killsig, time_t tcurr) noexcept
	{
		std::memcpy(comm_, comm, TASK_COMM_LEN - 1);
		comm_[TASK_COMM_LEN - 1] = 0;

		tkill_ 			= tcurr;
		pid_			= pid;
		killsig_		= killsig;
	}	

};	

class WEAK_TASK
{
public :	
	RCU_HASH_CLASS_MEMBERS(pid_t, WEAK_TASK);

	pid_t				taskpid;		
	std::weak_ptr<TASK_STAT>	taskptr_weak;

	WEAK_TASK() noexcept : taskpid(0) {}

	WEAK_TASK(const std::weak_ptr<TASK_STAT> & weakptr, pid_t pid) noexcept
		: taskpid(pid), taskptr_weak(weakptr)
	{}
	
	WEAK_TASK(const WEAK_TASK &other) noexcept			= default;
		
	WEAK_TASK & operator= (const WEAK_TASK &other) noexcept		= default;
		
	WEAK_TASK(WEAK_TASK && other) noexcept
		: taskpid(other.taskpid), taskptr_weak(std::move(other.taskptr_weak))
	{
		other.taskpid 		= 0;
	}
		
	WEAK_TASK & operator= (WEAK_TASK && other) noexcept
	{
		if (this != &other) {
			taskpid 	= other.taskpid;
			other.taskpid	= 0;
			taskptr_weak 	= std::move(other.taskptr_weak);
		}	

		return *this;
	}	
		
	~WEAK_TASK() noexcept			= default;	

	friend bool operator== (const WEAK_TASK &lhs, const pid_t rhs) noexcept
	{
		return lhs.taskpid == rhs;
	}
};	

using WEAK_TASK_TBL				= RCU_HASH_TABLE<pid_t, WEAK_TASK>;

using 	SHR_TASK_ELEM_TYPE 			= RCU_HASH_WRAPPER <pid_t, std::shared_ptr<TASK_STAT>>;
using 	SHR_TASK_HASH_TABLE			= RCU_HASH_TABLE <pid_t, SHR_TASK_ELEM_TYPE>;

bool get_k8s_podname(pid_t pid, char *pbuf, size_t szbuf) noexcept;
char * get_escaped_comm(char (&comm)[TASK_COMM_LEN], const char *pcomm) noexcept;
char * get_escaped_comm(char (&comm)[TASK_COMM_LEN], const char *pcomm, uint32_t len) noexcept;

enum TASK_UPD_E : int 
{
	TASK_UPD_UNINIT				= 0,
	TASK_UPD_ERROR,
	TASK_UPD_INIT_ONLY,
	TASK_UPD_COPIED,
	TASK_UPD_COPIED_EXEC,
	TASK_UPD_FULL
};	
			
enum {
	TASK_STATE_UNINIT			= 0,
	TASK_STATE_VALID,
	TASK_STATE_ERROR,
	TASK_STATE_EXITED,			
};				

struct TaskAggrHash
{
	uint64_t			machid_[2];
	uint32_t			uid_;
	uint32_t			gid_;
	uint32_t			cwd_inode_;
	uint32_t			mnt_inode_;
	uint32_t			user_inode_;
	uint32_t			cmdline_len_;
	char				cmdline_[comm::MAX_PROC_CMDLINE_LEN];

	TaskAggrHash(const GY_MACHINE_ID & machid, uid_t uid, gid_t gid, ino_t cwd_inode, ino_t mnt_inode, ino_t user_inode, const char *cmdline) noexcept
		: uid_(uid), gid_(gid), cwd_inode_(cwd_inode), mnt_inode_(mnt_inode), user_inode_(user_inode)
	{
		std::memcpy(machid_, &machid, sizeof(machid_));

		cmdline_len_ = ::strnlen(cmdline, sizeof(cmdline_) - 1);
		std::memcpy(cmdline_, cmdline, cmdline_len_);
		cmdline_[cmdline_len_] = 0;
	}	
	
	uint64_t get_hash() const noexcept
	{
		return gy_cityhash64((const char *)this, sizeof(*this) - sizeof(cmdline_) + cmdline_len_ + 1);
	}	
};


class TASK_DELAY_STATS
{
public :	
	using MSEC_HISTOGRAM 			= GY_HISTOGRAM<int, DURATION_HASH>;
	using CS_HISTOGRAM 			= GY_HISTOGRAM<int, SEMI_LOG_HASH>;

	MSEC_HISTOGRAM				cpu_delay_histogram_;
	MSEC_HISTOGRAM				blkio_delay_histogram_;
	CS_HISTOGRAM				vol_cs_histogram_;
	CS_HISTOGRAM				invol_cs_histogram_;

	uint64_t				cpu_delay_nsec_[MAX_TASK_STAT_HISTORY]		{};
	uint64_t				blkio_delay_nsec_[MAX_TASK_STAT_HISTORY]	{};
	uint64_t				swapin_delay_nsec_[MAX_TASK_STAT_HISTORY]	{};
	uint64_t				reclaim_delay_nsec_[MAX_TASK_STAT_HISTORY]	{};
	uint64_t				thrashing_delay_nsec_[MAX_TASK_STAT_HISTORY]	{};
	uint64_t				compact_delay_nsec_[MAX_TASK_STAT_HISTORY]	{};
	uint64_t				vol_cs_[MAX_TASK_STAT_HISTORY]			{};
	uint64_t				invol_cs_[MAX_TASK_STAT_HISTORY]		{};

	uint64_t				delay_clock_nsec_[MAX_TASK_STAT_HISTORY]	{};

	uint64_t				last_cpu_delay_nsec_ 				{0};
	uint64_t				last_blkio_delay_nsec_ 				{0};
	uint64_t				last_swapin_delay_nsec_				{0};
	uint64_t				last_reclaim_delay_nsec_			{0};
	uint64_t				last_thrashing_delay_nsec_			{0};
	uint64_t				last_compact_delay_nsec_			{0};
	uint64_t				last_vol_cs_					{0};
	uint64_t				last_invol_cs_ 					{0};

	char					tagbuf_[MAX_TASK_TAG_LEN]			{};
	uint8_t					tag_len_					{0};

	TASK_DELAY_STATS(TASK_STAT *pthis, bool is_kubernetes = false, uint64_t clock_nsec = get_nsec_clock()); 

	static_assert(std::max(decltype(cpu_delay_histogram_)::maxbuckets_, decltype(vol_cs_histogram_)::maxbuckets_) <= comm::TASK_HISTOGRAM::MAX_HIST_HASH_BUCKETS);

	int add_stats(uint64_t cpu_delay_nsec, uint64_t blkio_delay_nsec, uint64_t swapin_delay_nsec, uint64_t reclaim_delay_nsec, uint64_t thrashing_delay_nsec, \
			uint64_t compact_delay_nsec, uint64_t vol_cs, uint64_t invol_cs, uint64_t curr_nsec = get_nsec_clock()) noexcept;

	char * print_stats(STR_WR_BUF & strbuf) const noexcept; 

	size_t get_histogram_count() const noexcept
	{
		return cpu_delay_histogram_.get_total_count();
	}	

	uint64_t get_last_histogram_clock_nsec() const noexcept
	{
		return cpu_delay_histogram_.get_end_time();
	}	
};
	
class TASK_EXT_STATS
{
public :	
	struct TASK_ISSUE_STAT
	{
		OBJ_STATE_E			state 	{STATE_IDLE};
		TASK_ISSUE_SOURCE		issue	{ISSUE_TASK_NONE};
	};	

	using CPU_PCT_HISTOGRAM 		= GY_HISTOGRAM<int, HASH_1_3000>;

	PROC_CPU_IO_STATS			cpu_mem_io_;
	CPU_PCT_HISTOGRAM			cpu_pct_histogram_			{get_nsec_clock()};
	
	uint64_t				ntcp_bytes_				{0};
	uint64_t				ntcp_conn_				{0};

 	CAP_BITFLAGS				cap_flag_;

	std::bitset<MAX_TASK_STAT_HISTORY>	serv_notify_miss_ 			{0};	

	std::unique_ptr<TASK_DELAY_STATS>	pdelay_stats_;

	TASK_ISSUE_STAT				issue_hist_[MAX_TASK_STAT_HISTORY]	{};
	uint8_t					issue_bit_hist_				{0};	// 8 * 5 = 40 sec history
	uint8_t					severe_issue_bit_hist_			{0};	// 8 * 5 = 40 sec history
	
	bool					threads_in_diff_netns_ 			{false};		// TODO

	uint32_t				last_sent_tcp_kbytes_			{0};
	uint32_t				last_sent_tcp_conns_			{0};
	uint64_t				last_ntcp_bytes_			{0};
	uint64_t				last_ntcp_conn_				{0};

	TASK_STAT			* const pthis_obj_;

	TASK_EXT_STATS(TASK_STAT *pthis); 

	static_assert(CPU_PCT_HISTOGRAM::maxbuckets_ <= comm::TASK_HISTOGRAM::MAX_HIST_HASH_BUCKETS);

	void update_stats() noexcept;
	
	char * print_stats(STR_WR_BUF & strbuf) const noexcept; 

	int get_curr_state(OBJ_STATE_E & taskstate, TASK_ISSUE_SOURCE & task_issue, STR_WR_BUF & strbuf, uint64_t clock_nsec = get_nsec_clock()) const noexcept;		

	int update_delay_stats(TASKSTATS_HDLR *ptaskstats, bool & is_issue, bool & is_severe, STR_WR_BUF & strbuf, uint64_t curr_usec_clock = get_usec_clock()) noexcept;

	bool is_important_task(uint64_t curr_usec_time) const noexcept;

	std::tuple<bool /* is_issue */, bool /* is_severe */, OBJ_STATE_E /* state */, TASK_ISSUE_SOURCE /* issue */>
	is_recent_task_issue(int bitmap = 0x3F) const noexcept
	{
		// Default is 0x3F for the least 6 bits for last 30 sec check

		bool			is_issue = (issue_bit_hist_ & bitmap), is_severe = (severe_issue_bit_hist_ & bitmap);

		return {is_issue, is_severe, issue_hist_[0].state, issue_hist_[0].issue};
	}
};	

class TASK_STAT : public std::enable_shared_from_this<TASK_STAT>
{
public :	
	pid_t					task_pid;		// In root PID namespace
	pid_t					task_ppid;		// In root PID namespace
	pid_t					task_pgid;		// In root PID namespace
	pid_t					task_sid;		// In root PID namespace
	
	pid_t					task_nspid;		// 1st level PID namespace
	pid_t					task_nspgid;		// 1st level PID namespace
	pid_t					task_nssid;		// 1st level PID namespace

	char					task_comm[TASK_COMM_LEN];		// 16 byte exe name (task_orig_comm is actual task comm instead)
	char					task_orig_comm[TASK_COMM_LEN];
	char					task_exe_path[comm::MAX_PROC_CMDLINE_LEN];
	char					task_cmdline[comm::MAX_PROC_CMDLINE_LEN];
	char					task_parent_comm[TASK_COMM_LEN];

	uid_t					task_realuid;
	uid_t					task_effuid;
	uid_t					task_saveduid;
	uid_t					task_fsuid;

	gid_t					task_realgid;
	gid_t					task_effgid;
	gid_t					task_savedgid;
	gid_t					task_fsgid;
	
	gy_atomic<uint64_t>			aggr_task_id_		{0};		// Unique across partha's

	uint64_t				starttimeusec;
	int64_t					task_priority;
	int64_t					task_nice;
	uint32_t				task_flags;
	uint32_t				task_rt_priority;
	uint32_t				task_sched_policy;

	int					nchild_recent_forks_	{0};
	int64_t					last_fork_tsec_		{0};

	pid_t					parent_ppid		{0};
	pid_t					parent_pgid		{0};

	uint16_t				ncpus_allowed		{0};
	uint16_t				nmems_allowed		{0};
	
	typeinfo::BIN_TYPE			bin_type		{typeinfo::BIN_TYPE::BIN_MACHINE};

	ino_t					cwd_inode		{0};
	TASK_NS_INODES				ns_inodes;

	gy_atomic <TASK_UPD_E>			is_ready;
	gy_atomic <int>				task_valid;

	uint64_t				last_server_tusec	{0};

	/*
	 * The subsequent fields will be lazily updated...
	 */ 
	std::unique_ptr <TASK_EXT_STATS>		pext_stats;

	uint64_t					last_listen_tusec_	{0};
	gy_atomic <int>					ntcp_listeners 		{0};
	folly::atomic_shared_ptr<SHR_TASK_HASH_TABLE>	listen_tbl_shr;
	folly::atomic_shared_ptr<RELATED_LISTENERS>	related_listen_;	// Will be sent as related_listen_id_ to madhava

	std::weak_ptr <TASK_STAT>		weak_parent_task;

	std::shared_ptr <CGROUP1_CPUACCT>	cg_cpuacct_shr;
	std::shared_ptr <CGROUP1_CPU>		cg_cpu_shr;
	std::shared_ptr <CGROUP1_CPUSET>	cg_cpuset_shr;
	std::shared_ptr <CGROUP1_MEMORY>	cg_memory_shr;
	std::shared_ptr <CGROUP1_BLKIO>		cg_blkio_shr;

	gy_atomic <bool>			cgroups_updated 	{false};
	gy_atomic <bool>			cgroups_changed 	{false};

	// These should not be included in dbit_fields_ as updated by separate threads
	bool					is_tcp_server		{false};	
	bool					is_tcp_client		{false};
	bool					is_ptrace_active	{false};
	bool					is_execv_task		{false};
	bool					is_parent_tcp_client	{false};

	gy_atomic<uint8_t>			sent_aggr_server_ 	{0};
	gy_atomic<uint8_t>			listen_tbl_inherited	{0};

	union {
		uint16_t			dbit_fields_		{0};

		struct {
			bool			is_forked_task : 1;	
			bool			is_high_cap : 1;	
			bool			is_throttled_cgroup : 1;
			bool			is_cpu_cgroup_mini_procs : 1;
			bool			is_mem_cgroup_limited : 1;
			bool			is_tags_seen : 1;
			bool			is_container_proc : 1;
		};
	};

	TASK_STAT() : task_pid(0), task_ppid(0), is_ready(TASK_UPD_UNINIT), task_valid(TASK_STATE_UNINIT)
	{
		/*GY_MT_COLLECT_PROFILE(100'000, "new task with default constructor");*/

		*task_comm			= 0;
		*task_orig_comm			= 0;
		*task_exe_path			= 0;
		*task_cmdline			= 0;
	}

	TASK_STAT(int proc_dir_fd, pid_t pidin, pid_t ppidin = 0, char *exe_path_in = nullptr, char *cmdline_in = nullptr);

	TASK_STAT(TASK_STAT *pparent, pid_t pid, int proc_dir_fd, bool from_main_thread = true);

	TASK_STAT(const TASK_STAT & other)			= delete;
	TASK_STAT & operator =(const TASK_STAT & other)		= delete;

	TASK_STAT(TASK_STAT && other)				= delete;
	TASK_STAT & operator =(TASK_STAT && other)		= delete;

	~TASK_STAT() noexcept					= default;
	
	int		copy_from_parent(TASK_STAT *ptask_ppid) noexcept;	
	int		set_task_exec(int proc_dir_fd) noexcept;

	ssize_t 	get_cmdline(pid_t pid, int proc_dir_fd) noexcept;

	int		set_task_exited(int exit_code, TASK_KILL_INFO & kone) noexcept;	

	int		set_task_uid_change(uid_t new_uid) noexcept;	
	int		set_task_gid_change(gid_t new_gid) noexcept;	
	int		set_task_sid_change() noexcept;
	int 		set_task_ptrace(pid_t tracer_pid, bool is_ptrace_active_in) noexcept;

	int		set_task_cgroups(int proc_dir_fd) noexcept;
	int 		upd_task_cgroup_on_change(int proc_dir_fd) noexcept;
	int 		set_task_proc_status(int proc_dir_fd, pid_t pid) noexcept;
	int 		set_task_proc_stat_misc(int proc_dir_fd, pid_t pidin) noexcept;
	int		update_task_info(int proc_dir_fd) noexcept;
	bool 		save_task_full(comm::TASK_FULL_ADD * __restrict__ pfulltask, const size_t max_bytes, size_t & elem_bytes, uint64_t curr_tusec) noexcept;
	bool 		save_task_stats(comm::TASK_HISTOGRAM * __restrict__ ptaskhist, uint64_t curr_clock_nsec, int64_t currtimesec, int64_t diffsec) noexcept;

	void		clear_listener_table() noexcept;

	char *		get_task_print_str(char *pbuf, size_t maxsz) noexcept;

	bool		is_task_valid() const noexcept
	{
		return (TASK_STATE_VALID == task_valid.load(std::memory_order_relaxed));
	}
		
	bool		is_task_exited() const noexcept
	{
		return (TASK_STATE_EXITED == task_valid.load(std::memory_order_relaxed));
	}

	TASK_UPD_E	get_task_update_state() const noexcept
	{
		return is_ready;	
	}

	bool		task_needs_update() const noexcept
	{
		auto 	rdy = is_ready.load(std::memory_order_relaxed);

		return ((rdy < TASK_UPD_FULL) && (rdy > TASK_UPD_ERROR) && is_task_valid());
	}	

	bool		task_update_complete() const noexcept
	{
		auto 	rdy = is_ready.load(std::memory_order_relaxed);

		return (rdy == TASK_UPD_FULL && is_task_valid());
	}	

	uint64_t	get_task_start_time() const noexcept
	{
		return starttimeusec;
	}	

	// We do not store task info on server for forked child processes except in case it is also execv'd
	bool		is_task_server_store_valid(uint64_t tcur) const noexcept
	{
		return ((!is_forked_task || is_execv_task) && (tcur > starttimeusec + 10 * GY_USEC_PER_MINUTE) && 
			((tcur > last_server_tusec + 12 * GY_USEC_PER_HOUR) && pext_stats && pext_stats->pdelay_stats_));
	}

	/*
	 * We set the aggr_task_id_ based on partha, uid, gid, cwd_inode, mnt_inode, user_inode and cmdline to identify
	 * a unique process or a set of related processes. Forked processes will retain the parent aggr_task_id_
	 * till an exec is done even if the cmdline is changed at runtime after startup.
	 */
	uint64_t get_set_aggr_id() noexcept
	{
		uint64_t		id;

		id = aggr_task_id_.load(std::memory_order_relaxed);

		if (id == 0) {
			TaskAggrHash		thash(SYS_HARDWARE::get_singleton()->get_machineid(), task_realuid, task_realgid, cwd_inode,
										ns_inodes.mnt_inode, ns_inodes.user_inode, task_cmdline);

			static_assert(std::has_unique_object_representations_v<TaskAggrHash>, "Padded structs cannot be hashed");

			id = thash.get_hash();
			aggr_task_id_.store(id, std::memory_order_relaxed);
		}

		return id;
	}	

	std::pair<const char *, uint32_t> get_task_tags() const noexcept
	{
		if (pext_stats && pext_stats->pdelay_stats_) {
			return {pext_stats->pdelay_stats_->tagbuf_, pext_stats->pdelay_stats_->tag_len_};
		}	

		return {};
	}	

	static ino_t get_cwd_inode(pid_t pid) noexcept;

	friend bool operator== (const std::shared_ptr<TASK_STAT> &lhs, const pid_t pid) noexcept
	{
		return (lhs && ((*lhs).task_pid == pid));
	}
};	

} // namespace gyeeta

