
#pragma				once

#include 			"gy_common_inc.h"
#include			"gy_task_stat.h"
#include			"gy_statistics.h"
#include 			"gy_acct_taskstat.h"
#include 			"gy_comm_proto.h"
#include 			"gy_pool_alloc.h"
#include			"gy_stack_container.h"

namespace gyeeta {

class 	GY_SCHEDULER;
struct 	cgroup_migrate_event_t;

using 	TASK_ELEM_TYPE 			= RCU_HASH_WRAPPER <pid_t, std::shared_ptr<TASK_STAT>>;
using 	TASK_HASH_TABLE			= RCU_HASH_TABLE <pid_t, TASK_ELEM_TYPE, TPOOL_DEALLOC<TASK_ELEM_TYPE>>;

class TASK_CPU_MEM
{
public :	
	uint64_t				aggr_task_id_		{0};
	pid_t					pid_			{0};
	pid_t					ppid_			{0};
	uint32_t				rss_mb_			{0};
	float					cpupct_			{0};
	char					comm_[TASK_COMM_LEN]	{};

	TASK_CPU_MEM() noexcept			= default;

	TASK_CPU_MEM(uint64_t aggr_task_id, pid_t pid, pid_t ppid, uint32_t rss_mb, const char *comm, float pct) noexcept : 
		aggr_task_id_(aggr_task_id), pid_(pid), ppid_(ppid), rss_mb_(rss_mb), cpupct_(pct)
	{
		GY_STRNCPY(comm_, comm, sizeof(comm_));
	}

	TASK_CPU_MEM(const TASK_CPU_MEM &) noexcept			= default;
	TASK_CPU_MEM(TASK_CPU_MEM &&) noexcept				= default;
	TASK_CPU_MEM & operator= (const TASK_CPU_MEM &) noexcept	= default;
	TASK_CPU_MEM & operator= (TASK_CPU_MEM &&) noexcept		= default;

	~TASK_CPU_MEM() noexcept					= default;

	void update_comm_task(comm::TASK_TOP_PROCS::TOP_TASK & ctask) const noexcept
	{
		ctask.aggr_task_id_	= aggr_task_id_;
		ctask.pid_		= pid_;
		ctask.ppid_		= ppid_;
		ctask.rss_mb_		= rss_mb_;
		ctask.cpupct_		= cpupct_;

		std::memcpy(ctask.comm_, comm_, sizeof(ctask.comm_));
		ctask.comm_[sizeof(ctask.comm_) - 1] = 0;
	}	

	struct TASK_CPU_PCT_TOPN
	{
		bool operator() (const TASK_CPU_MEM & lhs, const TASK_CPU_MEM & rhs) const noexcept
		{
			return lhs.cpupct_ > rhs.cpupct_;
		}	
	};	

	struct TASK_MEM_RSS_TOPN
	{
		bool operator() (const TASK_CPU_MEM & lhs, const TASK_CPU_MEM & rhs) const noexcept
		{
			return lhs.rss_mb_ > rhs.rss_mb_;
		}	
	};	

};	

struct TASK_PGTREE_ELEM
{
	std::weak_ptr<TASK_STAT>	taskweak_;
	pid_t				pid_			{0};
	pid_t				ppid_			{0};
};	

using TASK_PGTREE_MAP			= std::multimap<pid_t, TASK_PGTREE_ELEM>;

struct PG_TASK_CPU_PCT
{
	uint64_t			aggr_task_id_			{0};
	pid_t				pg_pid_				{0};
	pid_t				cpid_				{0};
	int				ntasks_				{0};
	uint32_t			tot_rss_mb_			{0};
	float				tot_cpupct_			{0};
	char				pg_comm_[TASK_COMM_LEN]		{};
	char				child_comm_[TASK_COMM_LEN]	{};

	PG_TASK_CPU_PCT() noexcept						= default;
	PG_TASK_CPU_PCT(const PG_TASK_CPU_PCT &) noexcept			= default;
	PG_TASK_CPU_PCT(PG_TASK_CPU_PCT &&) noexcept				= default;
	PG_TASK_CPU_PCT & operator= (PG_TASK_CPU_PCT &) noexcept		= default;
	PG_TASK_CPU_PCT & operator= (PG_TASK_CPU_PCT &&) noexcept		= default;

	~PG_TASK_CPU_PCT() noexcept						= default;

	void update_comm_task(comm::TASK_TOP_PROCS::TOP_PG_TASK & ctask) const noexcept
	{
		ctask.aggr_task_id_	= aggr_task_id_;
		ctask.pg_pid_		= pg_pid_;
		ctask.cpid_		= cpid_;
		ctask.ntasks_		= ntasks_;
		ctask.tot_rss_mb_	= tot_rss_mb_;
		ctask.tot_cpupct_	= tot_cpupct_;

		std::memcpy(ctask.pg_comm_, pg_comm_, sizeof(ctask.pg_comm_));
		ctask.pg_comm_[sizeof(ctask.pg_comm_) - 1] = 0;

		std::memcpy(ctask.child_comm_, child_comm_, sizeof(ctask.child_comm_));
		ctask.child_comm_[sizeof(ctask.child_comm_) - 1] = 0;
	}	

	struct PG_TASK_CPU_PCT_TOPN
	{
		bool operator() (const PG_TASK_CPU_PCT & lhs, const PG_TASK_CPU_PCT & rhs) const noexcept
		{
			return lhs.tot_cpupct_ > rhs.tot_cpupct_;
		}	
	};	
};	

class TASK_FORKS_SEC
{
public :	
	uint64_t			aggr_task_id_		{0};
	pid_t				pid_			{0};
	pid_t				ppid_			{0};
	int				nfork_per_sec_		{0};
	char				comm_[TASK_COMM_LEN]	{};

	TASK_FORKS_SEC() noexcept	= default;

	TASK_FORKS_SEC(uint64_t aggr_task_id, pid_t pid, pid_t ppid, int nfork_per_sec, const char *comm) noexcept : 
		aggr_task_id_(aggr_task_id), pid_(pid), ppid_(ppid), nfork_per_sec_(nfork_per_sec)
	{
		GY_STRNCPY(comm_, comm, sizeof(comm_));
	}

	TASK_FORKS_SEC(const TASK_FORKS_SEC &) noexcept			= default;
	TASK_FORKS_SEC(TASK_FORKS_SEC &&) noexcept			= default;
	TASK_FORKS_SEC & operator= (const TASK_FORKS_SEC &) noexcept	= default;
	TASK_FORKS_SEC & operator= (TASK_FORKS_SEC &&) noexcept		= default;

	~TASK_FORKS_SEC() noexcept					= default;

	void update_comm_task(comm::TASK_TOP_PROCS::TOP_FORK_TASK & ctask) const noexcept
	{
		ctask.aggr_task_id_	= aggr_task_id_;
		ctask.pid_		= pid_;
		ctask.ppid_		= ppid_;
		ctask.nfork_per_sec_	= nfork_per_sec_;

		std::memcpy(ctask.comm_, comm_, sizeof(ctask.comm_));
		ctask.comm_[sizeof(ctask.comm_) - 1] = 0;
	}	

	struct TASK_FORKS_SEC_TOPN
	{
		bool operator() (const TASK_FORKS_SEC & lhs, const TASK_FORKS_SEC & rhs) const noexcept
		{
			return lhs.nfork_per_sec_ > rhs.nfork_per_sec_;
		}	
	};	
};	

static constexpr uint64_t		VERIFY_PROC_INTERVAL_MSEC = 30000;	// 30 sec : Keep this as 30 sec as cgroup also depends on this

class SERVER_CONNTRACK;

class TASK_HANDLER
{
public :	
	using CPU_VEC			= INLINE_STACK_VECTOR<TASK_CPU_MEM, sizeof(TASK_CPU_MEM) * (comm::TASK_TOP_PROCS::TASK_MAX_TOP_N + 1)>;
	using TASK_CPU_TOP_N 		= BOUNDED_PRIO_QUEUE<TASK_CPU_MEM, TASK_CPU_MEM::TASK_CPU_PCT_TOPN, NULL_MUTEX, CPU_VEC>;

	using PG_CPU_VEC		= INLINE_STACK_VECTOR<PG_TASK_CPU_PCT, sizeof(PG_TASK_CPU_PCT) * (comm::TASK_TOP_PROCS::TASK_MAX_TOPPG_N + 1)>;
	using PG_TASK_CPU_TOP_N 	= BOUNDED_PRIO_QUEUE<PG_TASK_CPU_PCT, PG_TASK_CPU_PCT::PG_TASK_CPU_PCT_TOPN, NULL_MUTEX, PG_CPU_VEC>;

	using FORKS_VEC			= INLINE_STACK_VECTOR<TASK_FORKS_SEC, sizeof(TASK_FORKS_SEC) * (comm::TASK_TOP_PROCS::TASK_MAX_FORKS_TOP_N + 1)>;
	using TASK_FORKS_SEC_TOP_N 	= BOUNDED_PRIO_QUEUE<TASK_FORKS_SEC, TASK_FORKS_SEC::TASK_FORKS_SEC_TOPN, NULL_MUTEX, FORKS_VEC>;

	using RSS_VEC			= INLINE_STACK_VECTOR<TASK_CPU_MEM, sizeof(TASK_CPU_MEM) * (comm::TASK_TOP_PROCS::TASK_MAX_RSS_TOP_N + 1)>;
	using TASK_RSS_TOP_N 		= BOUNDED_PRIO_QUEUE<TASK_CPU_MEM, TASK_CPU_MEM::TASK_MEM_RSS_TOPN, NULL_MUTEX, RSS_VEC>;

	class AGGR_TASK
	{
	public :	
		comm::TASK_AGGR_NOTIFY		caggr_;
		char 				cmdline_[comm::MAX_PROC_CMDLINE_LEN];
		char				tagbuf_[MAX_TASK_TAG_LEN];

		AGGR_TASK(uint64_t aggr_task_id, const char *comm, uint64_t related_listen_id, uint16_t cmdline_len, uint8_t tag_len, uid_t uid, gid_t gid, \
				bool is_high_cap, bool is_cpu_cgroup_throttled, bool is_mem_cgroup_limited, bool is_rt_proc, bool is_container_proc, 
				const char *cmdline, const char *tagbuf) noexcept
			: caggr_(aggr_task_id, comm, related_listen_id, cmdline_len ? cmdline_len : strlen(cmdline) + 1, tag_len && tag_len < sizeof(tagbuf_) ? tag_len + 1 : 0, uid, gid,
				is_high_cap, is_cpu_cgroup_throttled, is_mem_cgroup_limited, is_rt_proc, is_container_proc)
		{
			if (caggr_.cmdline_len_ >= sizeof(cmdline_)) {
				caggr_.cmdline_len_ = sizeof(cmdline_) - 1;

				caggr_.set_padding_len();
			}

			std::memcpy(cmdline_, cmdline, caggr_.cmdline_len_);
			std::memcpy(tagbuf_, tagbuf, caggr_.tag_len_);
		}	

		AGGR_TASK(const AGGR_TASK & other, uint64_t aggr_task_id) noexcept
		{
			update_task(other, aggr_task_id);
		}	

		void update_task(const AGGR_TASK & other, uint64_t aggr_task_id) noexcept
		{
			caggr_ 			= other.caggr_;
			caggr_.aggr_task_id_	= aggr_task_id;

			if (caggr_.cmdline_len_ >= sizeof(cmdline_)) {
				caggr_.cmdline_len_ = sizeof(cmdline_) - 1;
			}	
			std::memcpy(cmdline_, other.cmdline_, caggr_.cmdline_len_);

			if (caggr_.tag_len_ <= MAX_TASK_TAG_LEN) {
				std::memcpy(tagbuf_, other.tagbuf_, caggr_.tag_len_);
			}
			else {
				caggr_.tag_len_ = 0;
			}	
		}	
	};	

	using AGGR_TASK_MAP		= std::unordered_map<uint64_t, AGGR_TASK, GY_JHASHER<uint64_t>>;
	using AggrTaskStackMap		= INLINE_STACK_HASH_MAP<uint64_t, AGGR_TASK, (comm::TASK_AGGR_NOTIFY::MAX_NUM_AGGR_TASK - 100) * (sizeof(AGGR_TASK) + 8 + 8), GY_JHASHER<uint64_t>>;

	static constexpr int		MAX_NDELAY_TASKS		{3000};		// Not a Hard Limit
	static constexpr int		MAX_NDELAY_SERVER_TASKS		{512};		// Hard Limit : We store upto 512 task stats only per Partha
	static constexpr int		PING_TASK_INTERVAL_MSEC		{5 * GY_MSEC_PER_MINUTE};
	static constexpr int 		MAX_KILL_PROCS			{8};

	TASK_HASH_TABLE			tasktable;	

	THR_POOL_ALLOC			pool_task_			{sizeof(TASK_STAT) + 16, 32 * 1024, false};
	THR_POOL_ALLOC			pool_elem_task_			{sizeof(TASK_ELEM_TYPE) + 8, 32 * 1024, false};

	TASKSTATS_HDLR			delaystats;

	uint64_t			last_all_aggr_state_cusec	{0};

	TASK_CPU_TOP_N			toptask; 
	PG_TASK_CPU_TOP_N		pg_toptask;
	TASK_RSS_TOP_N			toprss;
	TASK_FORKS_SEC_TOP_N		topforks;
	
	AGGR_TASK_MAP			glob_aggr_tasks_map_;
	std::atomic<bool>		reset_glob_aggr			{false};

	TASK_KILL_INFO			task_kill_arr_[MAX_KILL_PROCS]	{};

	int				last_ndelay_tasks		{0};
	int				last_nissue_tasks		{0};
	uint64_t			last_new_sent_cusec		{0};
	uint64_t			last_new_delay_cusec		{0};
	uint64_t			last_top_clock_usec		{0};
	uint64_t			last_delay_stat_cusec		{0};
	uint64_t			last_netstats_cusec		{0};

	bool				init_table_done			{false};
	bool				stats_updated_by_sock;
	bool				is_kubernetes			{false};

	int				proc_dir_fd;
	int				sysfs_dir_fd;

	GY_THREAD			nltaskthr;
	pthread_t			nltaskid			{0};

	gy_atomic<uint32_t>		missed_fork			{0};

	int				init_task_list();

	int				nltask_thread() noexcept;
	int				nltask(bool & init_done, int nerrors) noexcept;
	int 				parse_conn_msg(GY_PROC_EVENT *proc_ev) noexcept;
	int 				sockconn_send(int nl_sock) noexcept;

	int				tasks_verify_from_proc(size_t & total_cmdlen, AggrTaskStackMap *paggrmap = nullptr) noexcept;
	std::tuple<int, int, int> 	tasks_cpu_stats_update(bool from_scheduler = false, bool only_tcp_procs = false, uint64_t last_all_procs_tusec = 0, \
						const std::shared_ptr<SERVER_CONNTRACK> & servshr = {}) noexcept;
	int				tasks_non_tcp_check() noexcept;
	int				tasks_send_aggr(AggrTaskStackMap & aggmap, void *pconnshr, size_t total_cmdlen) noexcept;
	int 				send_ping_aggr() noexcept;
	int 				send_hist_stats() noexcept;
	int				tasks_lazy_update(bool from_scheduler = false) noexcept;
	void				tasks_cpu_stats_print() const noexcept;	
	int				send_top_tasks(const std::shared_ptr<SERVER_CONNTRACK> & servshr) noexcept;
	int				send_new_tasks() noexcept;
	int				send_task_stats(uint64_t stats_interval_msec) noexcept;

	int 				task_sid_change(pid_t pid) noexcept;
	int 				task_uid_gid_change(pid_t pid, uid_t realid, uid_t effid, bool is_uid) noexcept;
	int 				task_ptrace(pid_t pid, pid_t tracer_pid, bool is_attach_ptrace) noexcept;
	int 				task_exec(pid_t pid) noexcept;
	int 				task_exit(pid_t pid, int exit_code) noexcept;
	int 				task_add(pid_t pid, pid_t ppid, bool add_cgroup = false, bool from_main_thread = true) noexcept;

	int				task_cgroup_change(pid_t pid, pid_t tid) noexcept;
	void				handle_cgroup_change_event(cgroup_migrate_event_t *pevent, bool more_data) noexcept;
	int				handle_cpuset_change(CGROUP1_CPUSET *prawcpuset, CGROUP2 *prawcpuset2, bool cpus_changed, const CPU_CORES_BITSET & cpus_allowed, \
						bool mems_changed, const MEM_NODE_BITSET & mems_allowed) noexcept;

	void				get_task_pgtree(TASK_PGTREE_MAP & treemap) const;

	void				reset_server_stats() noexcept;

	// Returns true if weak_ptr updated
	template <typename LockType = RCU_LOCK_SLOW>
	bool get_task_weak_ptr(pid_t pid, std::weak_ptr <TASK_STAT> & task_weak) noexcept
	{
		try {
			TASK_ELEM_TYPE		elem;
			bool			bret = false;

			auto 			lambda_task = [&](TASK_ELEM_TYPE *pdatanode, void *arg1, void *arg2) noexcept -> CB_RET_E
			{
				auto			ptask = pdatanode->get_cref().get();

				if (ptask == nullptr) {
					return CB_OK;
				}

				task_weak = ptask->weak_from_this();		
				bret = true;

				return CB_OK;
			};	

			tasktable.template lookup_single_elem<decltype(lambda_task), LockType>(pid, get_pid_hash(pid), lambda_task);

			return bret;
		}
		GY_CATCH_EXCEPTION(
			DEBUGEXECN(1, ERRORPRINT("Caught exception for task weak ptr handling for PID %d : %s\n", pid, GY_GET_EXCEPT_STRING);); 
			return false;
		);
	}	

	// Returns true if shared_ptr updated
	template <typename LockType = RCU_LOCK_SLOW>
	bool get_task_shared_ptr(pid_t pid, std::shared_ptr <TASK_STAT> & task_shr) noexcept
	{
		try {
			TASK_ELEM_TYPE		elem;
			bool			bret = false;

			auto 			lambda_task = [&](TASK_ELEM_TYPE *pdatanode, void *arg1, void *arg2) noexcept -> CB_RET_E
			{
				auto			ptask = pdatanode->get_cref().get();

				if (ptask == nullptr) {
					return CB_OK;
				}

				task_shr = ptask->shared_from_this();		
				bret = true;

				return CB_OK;
			};	

			tasktable.template lookup_single_elem<decltype(lambda_task), LockType>(pid, get_pid_hash(pid), lambda_task);

			return bret;
		}
		GY_CATCH_EXCEPTION(
			DEBUGEXECN(1, ERRORPRINT("Caught exception for task shared ptr handling for PID %d : %s\n", pid, GY_GET_EXCEPT_STRING);); 
			return false;
		);
	}	

	// Returns 0 if callback is invoked
	template <typename FCB, typename LockType = RCU_LOCK_SLOW>
	int get_task(pid_t pid, FCB & handle_elem) noexcept(noexcept(handle_elem(std::declval<TASK_STAT *>()))) 
	{
		try {
			TASK_ELEM_TYPE		elem;
			int			ret = -1;

			auto 			lambda_task = [&](TASK_ELEM_TYPE *pdatanode, void *arg1, void *arg2) noexcept -> CB_RET_E
			{
				auto			ptask = pdatanode->get_cref().get();

				if (ptask == nullptr) {
					return CB_OK;
				}

				handle_elem(ptask);

				ret = 0;
					
				return CB_OK;
			};	

			tasktable.template lookup_single_elem<decltype(lambda_task), LockType>(pid, get_pid_hash(pid), lambda_task);

			return ret;
		}
		GY_CATCH_EXCEPTION(DEBUGEXECN(1, ERRORPRINT("Caught exception for task ptr handling for PID %d : %s\n", pid, GY_GET_EXCEPT_STRING);); return -1;);

	}	

	pthread_t get_main_thread_id() const noexcept
	{
		return nltaskid;
	}

	void set_init_table_done() noexcept
	{
		init_table_done = true;
	}	

	size_t get_last_num_issue_tasks(int64_t curr_usec_clock = get_usec_clock()) const noexcept
	{
		int64_t		lastc = GY_READ_ONCE(last_delay_stat_cusec);

		if (curr_usec_clock - lastc < (int64_t)GY_USEC_PER_SEC * 8) {
			return GY_READ_ONCE(last_nissue_tasks);
		}	

		return 0;
	}	

	void set_is_kubernetes(bool enable) noexcept
	{
		if (is_kubernetes != enable) {
			is_kubernetes = enable;
			INFOPRINT_OFFLOAD("%s Kubernetes Tag Collection for newer processes\n", enable ? "Enabling" : "Disabling");
		}	
	}	

	TASK_HANDLER(bool stats_updated_by_sock_in = true, bool is_kubernetes_in = false);
	
	TASK_HANDLER(const TASK_HANDLER &)		= delete;
	TASK_HANDLER(TASK_HANDLER &&)			= delete;	
	TASK_HANDLER & operator=(const TASK_HANDLER &)	= delete;
	TASK_HANDLER & operator=(TASK_HANDLER &&)	= delete;

	~TASK_HANDLER()					= default;

	static GY_SCHEDULER *			get_task_prio_scheduler() noexcept;

	static TASK_HANDLER *	 		get_singleton() noexcept;

	static int				init_singleton(bool stats_updated_by_sock = true, bool is_kubernetes_in = false);

	MAKE_CLASS_FUNC_WRAPPER_NO_ARG(TASK_HANDLER, nltask_thread);
};	


} // namespace gyeeta

