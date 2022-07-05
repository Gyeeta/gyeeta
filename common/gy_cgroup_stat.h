
#pragma				once

#include 			"gy_common_inc.h"
#include			"gy_task_stat.h"
#include 			"gy_rcu_inc.h"
#include			"gy_sys_hardware.h"
#include			"gy_statistics.h"
#include			"gy_print_offload.h"

#include			<tuple>
#include			<optional>

namespace gyeeta {

/*
 * We handle only a subset of cgroups.
 * XXX TODO Handle cgroup2, Also handle Threaded cgroups with different threads in a process in separate cgroups 
 */
enum CGROUP1_TYPES_E 
{
	CG_TYPE_CPUACCT 		= 1,
	CG_TYPE_CPU,
	CG_TYPE_CPUSET,
	CG_TYPE_MEMORY,
	CG_TYPE_BLKIO,

	// Add New types if needed
};	

template <typename T, typename RTABLE>
class CGROUP1_INT;

static constexpr int				CG_STATS_UPDATE_SEC = 15;
static constexpr int				CG_HIST_LAST_STATS = 5;
	
/*
 * Currently we do not maintain task weak pointers within the cgroup tasktable for reverse mapping from cg to tasks. 
 * The code to add weak task pointers is present but not invoked. Change update_task_table to true if needed...
 */
template <typename T>	
class CGROUP1_BASE 
{
public :	
	std::string				pathname;
	CGROUP1_TYPES_E				type;
	const char				*ptypestr;
	
	bool					is_root_cgroup;
	bool					is_top_parent;
	bool					possibly_deleted		{false};
	bool					tcp_servers_present		{false};	// Only if update_task_table is true
	bool					tcp_clients_present		{false};	// Only if update_task_table is true
	bool					update_task_table		{false};

	std::optional<WEAK_TASK_TBL>		tasktable;					// Will be updated only if update_task_table is true
	gy_atomic<time_t>			last_task_time			{0};
	gy_atomic<size_t>			approx_task_count		{0};		

	CGROUP1_BASE()				= delete;

	CGROUP1_BASE(CGROUP1_TYPES_E type, const char *ptypestr) 
		: type(type), ptypestr(ptypestr), is_root_cgroup(false), is_top_parent(false), last_task_time(0)
	{
		if (update_task_table) {
			tasktable.emplace(32, 32, 0, false, false);
		}	
	}
	
	CGROUP1_BASE(CGROUP1_TYPES_E type, const char *ptypestr, const char *pdir, bool is_top_parent) 
		: pathname(pdir), type(type), ptypestr(ptypestr), is_root_cgroup(0 == strcmp(pdir, "/")), is_top_parent(is_top_parent), last_task_time(0)
	{ 
		if (update_task_table) {
			tasktable.emplace(32, 32, 0, false, false);
		}	
	}  

	CGROUP1_BASE(const CGROUP1_BASE &other)				= default;

	CGROUP1_BASE(CGROUP1_BASE && other) noexcept			= default;
	
	CGROUP1_BASE & operator= (const CGROUP1_BASE &other)		= default;

	CGROUP1_BASE & operator= (CGROUP1_BASE && other) noexcept	= default;

	~CGROUP1_BASE() noexcept 					= default;

	const char * get_dir_path() const noexcept
	{
		return pathname.c_str();
	}

	T * get_derived_ptr() const noexcept
	{
		return static_cast<T *>(this);
	}	

	int add_task(WEAK_TASK *ptask, pid_t pid, time_t tcurr = time(nullptr)) noexcept
	{
		assert(ptask != nullptr);

		if (is_task_table_valid()) {
			tasktable->insert_or_replace(ptask, pid, get_pid_hash(pid));
		}
		else {
			approx_task_count.fetch_add_relaxed(1);
		}	

		last_task_time.store(tcurr, std::memory_order_relaxed);

		CONDEXEC(DEBUGEXECN(15, INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Added task PID %d to cgroupv1 %s : dir %s\n", pid, ptypestr, pathname.c_str());););
		return 0;
	}	

	// Called from Task Handler
	int delete_task(pid_t pid, time_t tcurr = time(nullptr)) noexcept
	{
		last_task_time.store(tcurr, std::memory_order_relaxed);

		if (is_task_table_valid()) {
			tasktable->delete_single_elem(pid, get_pid_hash(pid));
		}
		else {
			approx_task_count.fetch_sub_relaxed_0(1);
		}	

		CONDEXEC(DEBUGEXECN(15, INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Deleted task PID %d from cgroupv1 %s : dir %s\n", pid, ptypestr, pathname.c_str());););

		return 0;
	}	

	int verify_tasks() noexcept
	{
		if (false == is_task_table_valid()) {
			return 0;
		}

		int				ret = 0;
		size_t				ntasks;
		bool				check_tcp_server = !tcp_servers_present, check_tcp_client = !tcp_clients_present;

		auto proc_lambda = [&](WEAK_TASK *pdatanode, void *arg) noexcept -> CB_RET_E
		{
			try {
				if (pdatanode->taskptr_weak.expired()) {
					++ret;
					return CB_DELETE_ELEM;
				}
				else if (check_tcp_server == false && check_tcp_client == false) {
					return CB_OK;	
				}
						
				auto		ptaskshr = pdatanode->taskptr_weak.lock();
				auto		ptask = ptaskshr.get();

				if (!ptask) {
					++ret;
					return CB_DELETE_ELEM;
				}

				if (check_tcp_server) {
					if (GY_READ_ONCE(ptask->is_tcp_server)) {
						tcp_servers_present = true;
						check_tcp_server = false;
					}	
				}	
				
				if (check_tcp_client) {
					if (GY_READ_ONCE(ptask->is_tcp_client)) {
						tcp_clients_present = true;
						check_tcp_client = false;
					}	
				}

				return CB_OK;
			}
			GY_CATCH_EXCEPTION(return CB_DELETE_ELEM);
		};	

		ntasks = tasktable->walk_hash_table(proc_lambda); 	
					
		if (ret > 0) {
			DEBUGEXECN(1, 
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Deleted %d exited tasks out of %lu total tasks from cgroupv1 %s : dir %s\n", 
					ret, ntasks, ptypestr, pathname.c_str());
			);
		}	

		return ret;
	}	

	void set_cgroup_updated(time_t tcur = time(nullptr)) noexcept
	{
		last_task_time.store(tcur, std::memory_order_relaxed);
	}	

	bool is_recently_updated(time_t tcur = time(nullptr)) const noexcept
	{
		time_t			tlast = last_task_time.load(std::memory_order_relaxed);

		if (tcur - tlast > 4 * CG_STATS_UPDATE_SEC) {
			return false;
		}	

		return true;
	}	

	bool is_task_table_valid() const noexcept
	{
		return update_task_table && bool(tasktable);
	}	

	size_t get_approx_task_count() const noexcept
	{
		if (false == is_task_table_valid()) {
			return approx_task_count.load(std::memory_order_acquire);
		}

		return tasktable->approx_count_fast();
	}	
};	

class CGROUP1_CPUACCT;

using RCU_HASH_CG_CPUACCT_ELEM			= RCU_HASH_WRAPPER<RCU_KEY_CHAR_POINTER, std::shared_ptr<CGROUP1_CPUACCT>>;
using RCU_CG_CPUACCT_HASHTBL			= RCU_HASH_TABLE<RCU_KEY_CHAR_POINTER, RCU_HASH_CG_CPUACCT_ELEM>;

class CGROUP1_CPUACCT : public CGROUP1_BASE <CGROUP1_CPUACCT>
{
public :	
	using CG_CPUACCT_HISTOGRAM		= GY_HISTOGRAM_DATA<int, HASH_10_5000, CG_HIST_LAST_STATS>;

	gy_atomic<RCU_CG_CPUACCT_HASHTBL *>	pchildtable;
		
	std::weak_ptr<CGROUP1_CPUACCT>		weak_parent;
	std::weak_ptr<CGROUP1_CPUACCT>		weak_top_parent;		// Top non-root parent 

	const CGROUP1_INT<CGROUP1_CPUACCT, 	RCU_CG_CPUACCT_HASHTBL> 	*pcghandle;
	
	struct CPUACCT_STATS
	{
		uint64_t			cpuusage_ticks	{0};
		double				cpuusage_pct	{0};
		uint64_t			tstatstime	{0};
	};	

	CPUACCT_STATS				stats;
	CG_CPUACCT_HISTOGRAM			*phistcpu;

	CGROUP1_CPUACCT() 
		: CGROUP1_BASE<CGROUP1_CPUACCT>(CG_TYPE_CPUACCT, "cpuacct"), pchildtable(nullptr), pcghandle(nullptr), phistcpu(nullptr)
	{}
		
	CGROUP1_CPUACCT(const char *pdir, CGROUP1_INT<CGROUP1_CPUACCT, RCU_CG_CPUACCT_HASHTBL> *pcghandle, \
		const std::weak_ptr<CGROUP1_CPUACCT> &parent, const std::weak_ptr<CGROUP1_CPUACCT> & top_parent, bool is_top_parent) 
		 :
		 CGROUP1_BASE<CGROUP1_CPUACCT>(CG_TYPE_CPUACCT, "cpuacct", pdir, is_top_parent), 
		 pchildtable(nullptr), weak_parent(parent), weak_top_parent(top_parent), pcghandle(pcghandle), phistcpu(nullptr) 
	{
		verify_info();
	}

	CGROUP1_CPUACCT(const CGROUP1_CPUACCT &other)			= delete;

	CGROUP1_CPUACCT(CGROUP1_CPUACCT && other) 			= delete;

	CGROUP1_CPUACCT & operator= (const CGROUP1_CPUACCT &other)	= delete;

	CGROUP1_CPUACCT & operator= (CGROUP1_CPUACCT && other) 		= delete;

	~CGROUP1_CPUACCT()
	{
		auto pc = pchildtable.load(std::memory_order_relaxed);

		if (pc) {
			delete pc;
			pchildtable.store(nullptr, std::memory_order_relaxed);
		}	

		if (GY_READ_ONCE(phistcpu)) {
			delete phistcpu;
			phistcpu = nullptr;
		}	
	}	

	int update_cpu_usage() noexcept;

	int verify_info() noexcept
	{
		return 0;
	}	

	friend bool operator== (const std::shared_ptr<CGROUP1_CPUACCT> &lhs, RCU_KEY_CHAR_POINTER dir) noexcept
	{
		return (lhs && (0 == strcmp(dir.pdata, (*lhs).pathname.c_str())));
	}
};	


class CGROUP1_CPU;

using RCU_HASH_CG_CPU_ELEM		= RCU_HASH_WRAPPER<RCU_KEY_CHAR_POINTER, std::shared_ptr<CGROUP1_CPU>>;
using RCU_CG_CPU_HASHTBL		= RCU_HASH_TABLE<RCU_KEY_CHAR_POINTER, RCU_HASH_CG_CPU_ELEM>;

class CGROUP1_CPU : public CGROUP1_BASE<CGROUP1_CPU>
{
public :	
	using CG_CPU_HISTOGRAM			= GY_HISTOGRAM_DATA<int, PERCENT_HASH, CG_HIST_LAST_STATS>;

	std::atomic<RCU_CG_CPU_HASHTBL *>	pchildtable;
		
	std::weak_ptr<CGROUP1_CPU>		weak_parent;			// Immediate parent
	std::weak_ptr<CGROUP1_CPU>		weak_top_parent;		// Top non-root parent 

	const CGROUP1_INT<CGROUP1_CPU, 		RCU_CG_CPU_HASHTBL> 	*pcghandle;
	
	struct CPU_STATS
	{
		int				nr_periods;
		int				nr_throttled;
		
		double				throttled_pct;
		uint64_t			throttled_time;
			
		uint64_t			tupdateclock;	
			
		int64_t				cfs_period_us;
		int64_t				cfs_quota_us;
		int64_t				rt_period_us;
		int64_t				rt_runtime_us;
		int				shares;

		int				shares_pct;
		int				cfs_bw_pct;
	
		bool				is_share_limited;
		bool				is_cfs_bw_limited;

		CPU_STATS() 
		{
			gy_safe_memset(this);
		}	
	};	

	CPU_STATS				stats;
	CG_CPU_HISTOGRAM			*phistcpu;

	CGROUP1_CPU() 
		: CGROUP1_BASE<CGROUP1_CPU>(CG_TYPE_CPU, "cpu"), pchildtable(nullptr), pcghandle(nullptr), phistcpu(nullptr)
	{ }
		
	CGROUP1_CPU(const char *pdir, CGROUP1_INT<CGROUP1_CPU, RCU_CG_CPU_HASHTBL> *pcghandle, \
			const std::weak_ptr<CGROUP1_CPU> &parent, const std::weak_ptr<CGROUP1_CPU> &top_parent, bool is_top_parent) 
		 :
		 CGROUP1_BASE<CGROUP1_CPU>(CG_TYPE_CPU, "cpu", pdir, is_top_parent), 
		 pchildtable(nullptr), weak_parent(parent), weak_top_parent(top_parent), pcghandle(pcghandle), phistcpu(nullptr) 
	{
		verify_info();
	}

	CGROUP1_CPU(const CGROUP1_CPU &other)			= delete;

	CGROUP1_CPU(CGROUP1_CPU && other) 			= delete;

	CGROUP1_CPU & operator= (const CGROUP1_CPU &other)	= delete;

	CGROUP1_CPU & operator= (CGROUP1_CPU && other)		= delete;

	~CGROUP1_CPU()
	{
		auto pc = pchildtable.load(std::memory_order_relaxed);

		if (pc) {
			delete pc;
			pchildtable.store(nullptr, std::memory_order_relaxed);
		}	

		if (GY_READ_ONCE(phistcpu)) {
			delete phistcpu;
			phistcpu = nullptr;
		}	
	}	

	int update_throttle_stats() noexcept;

	int verify_info() noexcept;

	bool is_cpu_throttled_cgroup() const noexcept
	{
		return stats.is_cfs_bw_limited;
	}	

	uint64_t get_throttled_nsec(int64_t curr_clock_nsec = get_nsec_clock()) const noexcept
	{
		if (curr_clock_nsec - (int64_t)stats.tupdateclock < CG_STATS_UPDATE_SEC * (int64_t)GY_NSEC_PER_SEC) {
			return stats.throttled_time;
		}	

		return 0;
	}	

	friend bool operator== (const std::shared_ptr<CGROUP1_CPU> & lhs, RCU_KEY_CHAR_POINTER dir) noexcept
	{
		return (lhs && (0 == strcmp(dir.pdata, (*lhs).pathname.c_str())));
	}
};

class CGROUP1_CPUSET;

using RCU_HASH_CG_CPUSET_ELEM			= RCU_HASH_WRAPPER<RCU_KEY_CHAR_POINTER, std::shared_ptr<CGROUP1_CPUSET>>;
using RCU_CG_CPUSET_HASHTBL			= RCU_HASH_TABLE<RCU_KEY_CHAR_POINTER, RCU_HASH_CG_CPUSET_ELEM>;

class CGROUP1_CPUSET : public CGROUP1_BASE<CGROUP1_CPUSET>
{
public :	
	std::atomic<RCU_CG_CPUSET_HASHTBL *>	pchildtable;
		
	std::weak_ptr<CGROUP1_CPUSET>		weak_parent;			// Immediate parent
	std::weak_ptr<CGROUP1_CPUSET>		weak_top_parent;		// Top non-root parent 

	CGROUP1_INT<CGROUP1_CPUSET, 		RCU_CG_CPUSET_HASHTBL> 	*pcghandle;
	
	struct CPUSET_STATS
	{
		CPU_CORES_BITSET		cpus_allowed;
		MEM_NODE_BITSET			mems_allowed;	

		uint64_t			tupdateclock			{0};	

		int				sched_relax_domain_level	{0};

		bool				cpu_exclusive			{false};
		bool				mem_exclusive			{false};
		bool				sched_load_balance		{false};
		bool				effective_not_avail		{false};

		friend bool is_cg_changed(const CPUSET_STATS & first, const CPUSET_STATS & second, bool & cpus_changed, bool & mems_changed) 
		{
			bool		is_chg = false;

			cpus_changed = false;
			mems_changed = false;

			if (first.cpus_allowed != second.cpus_allowed) {
				cpus_changed = true;
				is_chg = true;
			}	

			if (first.mems_allowed != second.mems_allowed) {
				mems_changed = true;
				is_chg = true;
			}	

			if (is_chg) {
				return true;
			}
				
			return (!((first.sched_load_balance == second.sched_load_balance) && (first.cpu_exclusive == second.cpu_exclusive) &&
				(first.mem_exclusive == second.mem_exclusive) && (first.sched_load_balance == second.sched_load_balance)));
		}	
	};	

	CPUSET_STATS				stats;

	CGROUP1_CPUSET() 
		: CGROUP1_BASE<CGROUP1_CPUSET>(CG_TYPE_CPU, "cpuset"), pchildtable(nullptr), pcghandle(nullptr)
	{}
		
	CGROUP1_CPUSET(const char *pdir, CGROUP1_INT<CGROUP1_CPUSET, RCU_CG_CPUSET_HASHTBL> *pcghandle, \
		const std::weak_ptr<CGROUP1_CPUSET> &parent, const std::weak_ptr<CGROUP1_CPUSET> &top_parent, bool is_top_parent) 
		 :
		 CGROUP1_BASE<CGROUP1_CPUSET>(CG_TYPE_CPUSET, "cpuset", pdir, is_top_parent), 
		 pchildtable(nullptr), weak_parent(parent), weak_top_parent(top_parent), pcghandle(pcghandle) 
	{
		verify_info();
	}

	CGROUP1_CPUSET(const CGROUP1_CPUSET &other)			= delete;

	CGROUP1_CPUSET(CGROUP1_CPUSET && other) 			= delete;

	CGROUP1_CPUSET & operator= (const CGROUP1_CPUSET &other)	= delete;

	CGROUP1_CPUSET & operator= (CGROUP1_CPUSET && other) 		= delete;

	~CGROUP1_CPUSET()
	{
		auto pc = pchildtable.load(std::memory_order_relaxed);

		if (pc) {
			delete pc;
			pchildtable.store(nullptr, std::memory_order_relaxed);
		}	
	}	

	int verify_info() noexcept;

	friend bool operator== (const std::shared_ptr<CGROUP1_CPUSET> & lhs, RCU_KEY_CHAR_POINTER dir) noexcept
	{
		return (lhs && (0 == strcmp(dir.pdata, (*lhs).pathname.c_str())));
	}
};

class CGROUP1_MEMORY;

using RCU_HASH_CG_MEMORY_ELEM			= RCU_HASH_WRAPPER<RCU_KEY_CHAR_POINTER, std::shared_ptr<CGROUP1_MEMORY>>;
using RCU_CG_MEMORY_HASHTBL			= RCU_HASH_TABLE<RCU_KEY_CHAR_POINTER, RCU_HASH_CG_MEMORY_ELEM>;

class CGROUP1_MEMORY : public CGROUP1_BASE<CGROUP1_MEMORY>
{
public :	
	using CG_MEMORY_HISTOGRAM		= GY_HISTOGRAM_DATA<int, SEMI_LOG_HASH, CG_HIST_LAST_STATS>;

	std::atomic<RCU_CG_MEMORY_HASHTBL *>	pchildtable;
		
	std::weak_ptr<CGROUP1_MEMORY>		weak_parent;
	std::weak_ptr<CGROUP1_MEMORY>		weak_top_parent;		// Top non-root parent 

	const CGROUP1_INT<CGROUP1_MEMORY, 	RCU_CG_MEMORY_HASHTBL> 	*pcghandle;
	
	struct MEMORY_STATS
	{
		uint64_t			cache;
		uint64_t			rss;
		uint64_t			swap;
		uint64_t			last_pgmajfault;
		uint64_t			int_pgmajfault;

		uint64_t			hierarchical_memory_limit;
		uint64_t			tstatstime;

		uint8_t				pct_memory_limit;
		uint8_t				pct_rss_limit;
		uint8_t				pct_hier_memory_limit;
		uint8_t				pct_hier_rss_limit;

		bool				is_hierarchical;
		bool				is_memory_limited;

		MEMORY_STATS() 
		{
			gy_safe_memset(this);
		}	
	};	

	MEMORY_STATS				stats;
	CG_MEMORY_HISTOGRAM			*phistmem;

	CGROUP1_MEMORY() 
		: CGROUP1_BASE<CGROUP1_MEMORY>(CG_TYPE_MEMORY, "memory"), pchildtable(nullptr), pcghandle(nullptr), phistmem(nullptr)
	{ }
		
	CGROUP1_MEMORY(const char *pdir, CGROUP1_INT<CGROUP1_MEMORY, RCU_CG_MEMORY_HASHTBL> *pcghandle, \
		const std::weak_ptr<CGROUP1_MEMORY> &parent, const std::weak_ptr<CGROUP1_MEMORY> &top_parent, bool is_top_parent) 
		 :
		 CGROUP1_BASE<CGROUP1_MEMORY>(CG_TYPE_MEMORY, "memory", pdir, is_top_parent), 
		 pchildtable(nullptr), weak_parent(parent), weak_top_parent(top_parent), pcghandle(pcghandle), phistmem(nullptr) 
	{ 
		verify_info();
	}

	CGROUP1_MEMORY(const CGROUP1_MEMORY &other)			= delete;

	CGROUP1_MEMORY(CGROUP1_MEMORY && other) 			= delete;

	CGROUP1_MEMORY & operator= (const CGROUP1_MEMORY &other)	= delete;

	CGROUP1_MEMORY & operator= (CGROUP1_MEMORY && other) 		= delete;

	~CGROUP1_MEMORY()
	{
		auto pc = pchildtable.load(std::memory_order_relaxed);

		if (pc) {
			delete pc;
			pchildtable.store(nullptr, std::memory_order_relaxed);
		}	

		if (GY_READ_ONCE(phistmem)) {
			delete phistmem;
			phistmem = nullptr;
		}	
	}	

	int verify_info() noexcept;

	int update_mem_usage() noexcept;

	bool is_max_memory_limited() const noexcept
	{
		return stats.is_memory_limited;
	}	

	uint8_t get_rss_pct_used() const noexcept
	{
		return stats.pct_rss_limit;
	}	

	friend bool operator== (const std::shared_ptr<CGROUP1_MEMORY> &lhs, RCU_KEY_CHAR_POINTER dir) noexcept
	{
		return (lhs && (0 == strcmp(dir.pdata, (*lhs).pathname.c_str())));
	}
};	

class CGROUP1_BLKIO;

using RCU_HASH_CG_BLKIO_ELEM			= RCU_HASH_WRAPPER<RCU_KEY_CHAR_POINTER, std::shared_ptr<CGROUP1_BLKIO>>;
using RCU_CG_BLKIO_HASHTBL			= RCU_HASH_TABLE<RCU_KEY_CHAR_POINTER, RCU_HASH_CG_BLKIO_ELEM>;

class CGROUP1_BLKIO : public CGROUP1_BASE<CGROUP1_BLKIO>
{
public :	
	using CG_BLKIO_HISTOGRAM		= GY_HISTOGRAM_DATA<int, SEMI_LOG_HASH, CG_HIST_LAST_STATS>;

	std::atomic<RCU_CG_BLKIO_HASHTBL *>	pchildtable;
		
	std::weak_ptr<CGROUP1_BLKIO>		weak_parent;
	std::weak_ptr<CGROUP1_BLKIO>		weak_top_parent;		// Top non-root parent 

	const CGROUP1_INT<CGROUP1_BLKIO, 	RCU_CG_BLKIO_HASHTBL> 	*pcghandle;
	
	struct BLKIO_STATS
	{
		uint64_t			last_total_io		{0};
		uint64_t			int_total_io		{0};
		uint64_t			tstatstime		{0};
	};	

	BLKIO_STATS				stats;
	CG_BLKIO_HISTOGRAM			*phistblkio;

	CGROUP1_BLKIO() 
		: CGROUP1_BASE<CGROUP1_BLKIO>(CG_TYPE_BLKIO, "blkio"), pchildtable(nullptr), pcghandle(nullptr), phistblkio(nullptr)
	{ }
		
	CGROUP1_BLKIO(const char *pdir, CGROUP1_INT<CGROUP1_BLKIO, RCU_CG_BLKIO_HASHTBL> *pcghandle, \
		const std::weak_ptr<CGROUP1_BLKIO> &parent, const std::weak_ptr<CGROUP1_BLKIO> &top_parent, bool is_top_parent) 
		 :
		 CGROUP1_BASE<CGROUP1_BLKIO>(CG_TYPE_BLKIO, "blkio", pdir, is_top_parent), 
		 pchildtable(nullptr), weak_parent(parent), weak_top_parent(top_parent), pcghandle(pcghandle), phistblkio(nullptr) 
	{ 
		verify_info();
	}

	CGROUP1_BLKIO(const CGROUP1_BLKIO &other)			= delete;

	CGROUP1_BLKIO(CGROUP1_BLKIO && other)				= delete;

	CGROUP1_BLKIO & operator= (const CGROUP1_BLKIO &other)		= delete;

	CGROUP1_BLKIO & operator= (CGROUP1_BLKIO && other)		= delete;

	~CGROUP1_BLKIO()
	{
		auto pc = pchildtable.load(std::memory_order_relaxed);

		if (pc) {
			delete pc;
			pchildtable.store(nullptr, std::memory_order_relaxed);
		}	

		if (GY_READ_ONCE(phistblkio)) {
			delete phistblkio;
			phistblkio = nullptr;
		}	
	}	

	int verify_info() noexcept
	{
		return 0;
	}	

	int update_blkio_usage() noexcept;

	friend bool operator== (const std::shared_ptr<CGROUP1_BLKIO> &lhs, RCU_KEY_CHAR_POINTER dir) noexcept
	{
		return (lhs && (0 == strcmp(dir.pdata, (*lhs).pathname.c_str())));
	}
};	

class CG_CPU_ACCT
{
public :	
	std::weak_ptr<CGROUP1_CPUACCT>		cgweak;
	double					stat;		// Total CPU %
	double					stat_user;
	double					stat_sys;

	CG_CPU_ACCT(std::weak_ptr<CGROUP1_CPUACCT> && weakp, double cpu_util_in, double cpu_user, double cpu_sys) noexcept : 
		cgweak(std::move(weakp)), stat(cpu_util_in), stat_user(cpu_user), stat_sys(cpu_sys)
	{}
	
	CG_CPU_ACCT(const CG_CPU_ACCT & other) noexcept 			= default;
	CG_CPU_ACCT(CG_CPU_ACCT && other) noexcept 				= default;
	CG_CPU_ACCT & operator= (const CG_CPU_ACCT & other) noexcept		= default; 
	CG_CPU_ACCT & operator= (CG_CPU_ACCT && other) noexcept 		= default;
};	

class CG_CPU_THROTTLE
{
public :	
	std::weak_ptr<CGROUP1_CPU>		cgweak;
	int					stat;		// nr_throttled
	int					stat_periods;
	uint64_t				stat_throttled_time;

	CG_CPU_THROTTLE(std::weak_ptr<CGROUP1_CPU> && weakp, int nr_throttled, int nr_periods, uint64_t throttled_time) noexcept : 
		cgweak(std::move(weakp)), stat(nr_throttled), stat_periods(nr_periods), stat_throttled_time(throttled_time)
	{}
	
	CG_CPU_THROTTLE(const CG_CPU_THROTTLE & other) noexcept				= default;
	CG_CPU_THROTTLE(CG_CPU_THROTTLE && other) noexcept 				= default;
	CG_CPU_THROTTLE & operator= (const CG_CPU_THROTTLE & other) noexcept		= default;
	CG_CPU_THROTTLE & operator= (CG_CPU_THROTTLE && other) noexcept 		= default;
};	


template <typename T>
class CG_STAT_COMP
{
public :	
	bool operator() (const T & lhs, const T & rhs) const noexcept
	{
		return lhs.stat > rhs.stat;
	}	
};	

class CGROUP1_GLOB_STATS
{
public :	
	bool					cpu_exclusive		{false};
	bool					mem_exclusive		{false};
	bool					sched_load_balance	{false};
	bool					memory_use_hierarchy	{false};
};	

class CGROUP_HANDLE;

template <typename T, typename RTABLE>
class CGROUP1_INT
{
public :	
	using WRAP_T				= RCU_HASH_WRAPPER<RCU_KEY_CHAR_POINTER, std::shared_ptr<T>>;

	std::shared_ptr<T>			root_cg_shr;
	int					fd_cg_root;
	char					dir_cg_root[GY_PATH_MAX];
	CGROUP_HANDLE			* const	pglobhandle;
	const char				*pcgtype;
	bool					is_hierarchical;
	CGROUP1_GLOB_STATS			stats;
	std::atomic<bool>			is_init_completed;
	
	CGROUP1_INT(const char *pdir_cg, const char *pcgtype, CGROUP_HANDLE *phandle, bool is_hierarchical)
		: fd_cg_root(-1), pglobhandle(phandle), pcgtype(pcgtype), is_hierarchical(is_hierarchical), is_init_completed(false)
	{
		if (pdir_cg && *pdir_cg) {
			GY_STRNCPY(dir_cg_root, pdir_cg, sizeof(dir_cg_root));

			fd_cg_root = open(dir_cg_root, O_PATH | O_CLOEXEC);

			if (fd_cg_root < 0) {
				GY_THROW_SYS_EXCEPTION("Failed to get cgroup dir fd for %s at %s", pcgtype, dir_cg_root);
			}

			try {
				std::weak_ptr<T>	weakp;

				root_cg_shr		= std::make_shared<T>("/", this, weakp, weakp, false);

				is_init_completed = true;
			}
			catch(...) {
				close(fd_cg_root);
				fd_cg_root = -1;

				throw;	
			}		
		}	
		else {
			*dir_cg_root = '\0';
		}	
	}		

	~CGROUP1_INT()
	{
		if (fd_cg_root > 0) {
			close(fd_cg_root);
			fd_cg_root = -1;
		}	
	}	
	

	int set_new_mount_root(const char *pdir_cg) noexcept
	{
		if (!pdir_cg) {
			return -1;
		}
			
		/*
		 * We ignore new mounts in case root cg already previously initialized as fd_cg_root is already open
		 */
		if (fd_cg_root < 0) {
			GY_STRNCPY(dir_cg_root, pdir_cg, sizeof(dir_cg_root));

			fd_cg_root = open(dir_cg_root, O_PATH | O_CLOEXEC);

			if (fd_cg_root < 0) {
				PERRORPRINT_OFFLOAD("Failed to get new cgroup dir fd for %s at %s", pcgtype, dir_cg_root);
				return -1;
			}

			try {
				std::weak_ptr<T>	weakp;

				root_cg_shr		= std::make_shared<T>("/", this, weakp, weakp, false);

				INFOPRINT("cgroup root handler initialized for newly created mount of %s at %s\n", pcgtype, dir_cg_root);

				is_init_completed = true;
				return 0;
			}
			GY_CATCH_EXCEPTION(
				ERRORPRINT_OFFLOAD("Exception caught while creating new cgroup root handler for %s at %s : %s\n", pcgtype, dir_cg_root, GY_GET_EXCEPT_STRING);

				close(fd_cg_root);
				fd_cg_root = -1;

				return -1;
			);		
		}	
		
		return 1;
	}	

	int cg_verify_dirs()
	{
		auto				shr_root = root_cg_shr;
		T				*praw_cgroot = shr_root.get();

		if (gy_unlikely((fd_cg_root < 0) || (false == is_init_completed.load(std::memory_order_relaxed)) || !praw_cgroot))  {
			return -1;
		}
		
		praw_cgroot->verify_info();
		
		auto ptbl = praw_cgroot->pchildtable.load(std::memory_order_relaxed);

		if (nullptr == ptbl) {
			return 1;
		}	
			
		auto dir_lambda = [=, fd = fd_cg_root](WRAP_T *pdatanode, void *arg) -> CB_RET_E
		{
			char				buf[GY_PATH_MAX];
			T				*praw = pdatanode->get_data()->get();

			int				ret;
			struct stat			stat1;

			if (praw == nullptr) {
				return CB_DELETE_ELEM;
			}

			snprintf(buf, sizeof(buf), "./%s", praw->pathname.c_str());
			ret = fstatat(fd, buf, &stat1, AT_NO_AUTOMOUNT);

			if ((ret == 0) || (errno == ENOMEM)) {
				praw->verify_info();

				if (praw->possibly_deleted == true) {
					praw->possibly_deleted = false;	
				}
				return CB_OK;
			}	
			
			if (praw->possibly_deleted == false) {
				praw->possibly_deleted = true;	
				
				// Delete on next check : No call to verify_info()

				return CB_OK;
			}
					
			DEBUGEXECN(1, INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_YELLOW, "Deleting cgroup1 dir %s for %s as it no longer exists...\n", buf, praw->ptypestr););

			return CB_DELETE_ELEM;
		};	

		auto sret = ptbl->walk_hash_table(dir_lambda); 	

		DEBUGEXECN(1, INFOPRINTCOLOR_OFFLOAD(GY_COLOR_MAGENTA_UNDERLINE, "Total number of subdirs in cgroup1 %s is %lu\n", pcgtype, sret);); 
		return sret;
	}

	int cg_verify_procs()
	{
		auto				shr_root = root_cg_shr;
		T				*praw_cgroot = shr_root.get();

		if (gy_unlikely((fd_cg_root < 0) || (false == is_init_completed.load(std::memory_order_relaxed)) || !praw_cgroot))  {
			return -1;
		}
		
		praw_cgroot->verify_tasks();

		if (false == praw_cgroot->is_task_table_valid()) {
			return 0;
		}

		auto 				ptbl = praw_cgroot->pchildtable.load(std::memory_order_relaxed);

		if (nullptr == ptbl) {
			return 0;
		}	
			
		auto proc_lambda = [](WRAP_T *pdatanode, void *arg) -> CB_RET_E
		{
			T			*praw = pdatanode->get_data()->get();

			if (praw) {
				praw->verify_tasks();
			}	

			return CB_OK;
		};	

		ptbl->walk_hash_table(proc_lambda, nullptr); 	

		return 0;
	}

	/*
	 * Returns a shared_ptr to the cgroup object or a null shared ptr if none.
	 *
	 * We first check if the pcgdir is already present by directly querying the root cg pchildtable
	 * as the root cg pchildtable includes all subdirectorires

	 * If is_hierarchical == true, all cgroup directories including intermediate parents cgroup objects are created.
	 *
	 * If the dir is not present and mkdir_if_none, if is_hierarchical, we will walk the entire dir path of pcgdir and create 
	 * intermediate subdir objects if not already done. If is_hierarchical == false, we will just create jjust the new subdir within the 
	 * root cg pchildtable.
	 * 
	 */
	std::shared_ptr <T> get_cg_from_dir(const char *pcgdir, bool mkdir_if_none = true)
	{
		std::shared_ptr<T>	shrp = root_cg_shr;
		T			*praw_cgroot = shrp.get(), *prawchild, *prawparent;
		WRAP_T			*pwrap;
		bool			bret;

		if (gy_unlikely((fd_cg_root < 0) || (false == is_init_completed.load(std::memory_order_relaxed)) || (praw_cgroot == nullptr) || !pcgdir || (*pcgdir != '/'))) {
			return {};	
		}
		
		if ((pcgdir[0] == '/') && (pcgdir[1] == '\0')) {
			return root_cg_shr;
		}		

		auto 			ptbl = praw_cgroot->pchildtable.load(std::memory_order_acquire);

		if (gy_unlikely(ptbl == nullptr)) {
			if (mkdir_if_none == false) {
				return {};	
			}

			auto ptmp 		= new RTABLE(1);
			decltype(ptmp)		poldtmp = nullptr;
			
			if (false == praw_cgroot->pchildtable.compare_exchange_strong(poldtmp, ptmp)) {
				delete ptmp;
				ptbl = praw_cgroot->pchildtable.load();
			}
			else {
				ptbl = ptmp;	
			}		

			// We do not store / (root cgdir) within the pchildtable
		}	 
		else {
			WRAP_T				wrap;
			RCU_KEY_CHAR_POINTER		key(pcgdir);
				
			bret = ptbl->template lookup_single_elem<RCU_LOCK_SLOW>(key, gy_cityhash32(pcgdir, strlen(pcgdir)), wrap);

			if (bret == true) {
				// Already present
				return wrap.get_ref();
			}
			else if (mkdir_if_none == false) {
				return {};	
			}	
		}

		DEBUGEXECN(1, INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Creating new cgroup1 %s dir %s\n", pcgtype, pcgdir););

		if (is_hierarchical == false) {
			// Just add this directory directly without adding any preceding parent dirs
			std::weak_ptr<T>		weakp(root_cg_shr);
			RCU_KEY_CHAR_POINTER		key(pcgdir);

			prawchild			= new T(pcgdir, this, weakp, weakp, true);

			try {
				pwrap			= new WRAP_T(prawchild);
			}	
			catch(...) {
				delete prawchild;
				throw;
			}

			ptbl->template insert_or_replace<RCU_LOCK_SLOW>(pwrap, key, gy_cityhash32(pcgdir, strlen(pcgdir)));
			return pwrap->get_ref();
		}

		char				dirfull[GY_PATH_MAX], c, *ptmp, *pchg;
		size_t				slen1 = std::min<size_t>(GY_PATH_MAX - 1, strlen(pcgdir));
		
		std::memcpy(dirfull, pcgdir, slen1);
		dirfull[slen1] = 0;

		STR_RD_BUF			pathstr(dirfull, slen1);
		char				*pdata;
		size_t				lenword;
		int				nsubdirs = 0;
		std::weak_ptr<T>		weakp, weaktopp;
		WRAP_T				wrap;
		bool				top_parent_seen = false; 	// First non root dir
		
		while (1) {

			pdata = const_cast<char *>(pathstr.get_next_word(lenword, true, "/", true, false /* ignore_escape */));
			if (!pdata) {
				return std::move(shrp);
			}	
			
			pchg = pdata + lenword;

			c = *pchg;
			*pchg = '\0';

			GY_SCOPE_EXIT {
				*pchg = c;
			};
				
			if (nsubdirs++ == 0) {
				continue;	// Ignore /
			}	

			RCU_KEY_CHAR_POINTER		key(dirfull);
				
			uint32_t			hashdir = gy_cityhash32(dirfull, strlen(dirfull));

			bret = ptbl->template lookup_single_elem<RCU_LOCK_SLOW>(key, hashdir, wrap);

			if (bret == true) {
				shrp = wrap.get_cref();

				if (top_parent_seen == false) {
					top_parent_seen = true;
					weaktopp = shrp;
				}	

				// Already present
				continue;
			}

			CONDEXEC(DEBUGEXECN(1, INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Creating new subdir for cgroup1 %s dir %s\n", pcgtype, dirfull);););

			prawparent		= shrp.get();

			if (!prawparent) {
				return {};
			}

			pwrap 			= nullptr;
			weakp			= shrp;

			prawchild		= new T(dirfull, this, weakp, weaktopp, !top_parent_seen);

			try {
				pwrap		= new WRAP_T(prawchild);
				shrp 		= pwrap->get_ref();

				if (top_parent_seen == false) {
					top_parent_seen = true;
					weaktopp = shrp;
				}	
			}	
			catch(...) {
				delete prawchild;
				throw;
			}

			ptbl->template insert_or_replace<RCU_LOCK_SLOW>(pwrap, key, hashdir);
		} 	
	}	

	std::shared_ptr <T> add_task_to_cg(const char *pcgdir, const std::weak_ptr<TASK_STAT> & task_weak, pid_t pid, time_t tcurr = time(nullptr))
	{
		assert(pcgdir != nullptr);

		T		*praw_cgroot = root_cg_shr.get();

		if (gy_unlikely((fd_cg_root < 0) || (false == is_init_completed.load(std::memory_order_relaxed)) || (praw_cgroot == nullptr) || (*pcgdir != '/'))) {

			/*
			 * If praw_cgroot == nullptr && pcgdir is non root /, it implies that a new cgroup mount point has been created.
			 */
			return {};
		}	
		
		try {
			std::shared_ptr<T>		cgroup_shr;
			int				ret;
			T				*prawcg;

			cgroup_shr = std::move(get_cg_from_dir(pcgdir, true /* mkdir_if_none */));

			prawcg = cgroup_shr.get();

			if (prawcg) {
				WEAK_TASK		*pweaktask;

				if (prawcg->is_task_table_valid()) {
					pweaktask = new WEAK_TASK(task_weak, pid);	
				
					ret = prawcg->add_task(pweaktask, pid, tcurr);
				}
				else {
					prawcg->set_cgroup_updated(tcurr);
				}

				return std::move(cgroup_shr);
			}	
		}
		GY_CATCH_EXCEPTION(
			DEBUGEXECN(1, ERRORPRINT_OFFLOAD("Failed to add task PID %d to cgroup %s due to exception %s\n", pid, pcgtype, GY_GET_EXCEPT_STRING););
		);

		return {};
	}

	int get_fd_mount_root() const noexcept
	{
		return fd_cg_root;
	}	

	const char * get_root_mount_point() const noexcept
	{
		return dir_cg_root;
	}		

	const char * get_cgroup_type_string() const noexcept
	{
		return pcgtype;
	}	
};

class CGROUP_HANDLE
{
public :	
	const CPU_MEM_INFO 				* const	pgcpumem;
	CGROUP1_INT<CGROUP1_CPUACCT, RCU_CG_CPUACCT_HASHTBL>	cpuacct_cg;
	CGROUP1_INT<CGROUP1_CPU, RCU_CG_CPU_HASHTBL>		cpu_cg;
	CGROUP1_INT<CGROUP1_CPUSET, RCU_CG_CPUSET_HASHTBL>	cpuset_cg;
	CGROUP1_INT<CGROUP1_MEMORY, RCU_CG_MEMORY_HASHTBL>	memory_cg;
	CGROUP1_INT<CGROUP1_BLKIO, RCU_CG_BLKIO_HASHTBL>	blkio_cg;
	
	CGROUP_HANDLE(const char *pdir_cpuacct, const char *pdir_cpu, const char *pdir_cpuset, const char *pdir_memory, const char *pdir_blkio)
		: 
		pgcpumem(
		({
			auto pcpumem = CPU_MEM_INFO::get_singleton();
			if (!pcpumem) {
				GY_THROW_EXCEPTION("CPU Memory singleton not yet initialized");
			}
			pcpumem;
		})
		),
		cpuacct_cg(pdir_cpuacct, "cpuacct", this, true /* is_hierarchical */),
		cpu_cg(pdir_cpu, "cpu", this, true /* is_hierarchical */),
		cpuset_cg(pdir_cpuset, "cpuset", this, false /* is_hierarchical */),
		memory_cg(pdir_memory, "memory", this, true /* is_hierarchical */),
		blkio_cg(pdir_blkio, "blkio", this, false /* is_hierarchical */)
	{}	

	std::shared_ptr <CGROUP1_CPUACCT> 	add_task_to_cpuacct(const char *pcgdir, const std::weak_ptr<TASK_STAT> & weaktask, pid_t pid, time_t tcurr = time(nullptr))
	{
		/*GY_MT_COLLECT_PROFILE(10000, "add task to cgroup cpuacct");	*/

		return cpuacct_cg.add_task_to_cg(pcgdir, weaktask, pid, tcurr);
	}	

	std::shared_ptr <CGROUP1_CPU> 		add_task_to_cpu(const char *pcgdir, const std::weak_ptr<TASK_STAT> & weaktask, pid_t pid, time_t tcurr = time(nullptr))
	{
		return cpu_cg.add_task_to_cg(pcgdir, weaktask, pid, tcurr);
	}	

	std::shared_ptr <CGROUP1_CPUSET> 	add_task_to_cpuset(const char *pcgdir, const std::weak_ptr<TASK_STAT> & weaktask, pid_t pid, time_t tcurr = time(nullptr))
	{
		return cpuset_cg.add_task_to_cg(pcgdir, weaktask, pid, tcurr);
	}	

	std::shared_ptr <CGROUP1_MEMORY> 	add_task_to_memory(const char *pcgdir, const std::weak_ptr<TASK_STAT> & weaktask, pid_t pid, time_t tcurr = time(nullptr))
	{
		return memory_cg.add_task_to_cg(pcgdir, weaktask, pid, tcurr);
	}	

	std::shared_ptr <CGROUP1_BLKIO> 	add_task_to_blkio(const char *pcgdir, const std::weak_ptr<TASK_STAT> & weaktask, pid_t pid, time_t tcurr = time(nullptr))
	{
		return blkio_cg.add_task_to_cg(pcgdir, weaktask, pid, tcurr);
	}	


	int set_new_mount_root_cpuacct(const char *pdir_cg) noexcept
	{
		return cpuacct_cg.set_new_mount_root(pdir_cg);
	}	

	int set_new_mount_root_cpu(const char *pdir_cg) noexcept
	{
		return cpu_cg.set_new_mount_root(pdir_cg);
	}	

	int set_new_mount_root_cpuset(const char *pdir_cg) noexcept
	{
		return cpuset_cg.set_new_mount_root(pdir_cg);
	}	

	int set_new_mount_root_memory(const char *pdir_cg) noexcept
	{
		return memory_cg.set_new_mount_root(pdir_cg);
	}	

	int set_new_mount_root_blkio(const char *pdir_cg) noexcept
	{
		return blkio_cg.set_new_mount_root(pdir_cg);
	}	


	int mkdir_cpuacct(const char *pcgdir) noexcept
	{
		try {
			auto 	shrp = cpuacct_cg.get_cg_from_dir(pcgdir, true /* mkdir_if_none */);
			if (shrp) {
				return 0;
			}
		}
		GY_CATCH_EXCEPTION(ERRORPRINT_OFFLOAD("Exception caught while creating new cgroup subdir for cpuacct at path %s : %s\n", pcgdir, GY_GET_EXCEPT_STRING););
					
		return -1;	
	}	

	int mkdir_cpu(const char *pcgdir) noexcept
	{
		try {
			auto 	shrp = cpu_cg.get_cg_from_dir(pcgdir, true /* mkdir_if_none */);
			if (shrp) {
				return 0;
			}
		}
		GY_CATCH_EXCEPTION(ERRORPRINT_OFFLOAD("Exception caught while creating new cgroup subdir for cpu at path %s : %s\n", pcgdir, GY_GET_EXCEPT_STRING););
					
		return -1;	
	}	

	int mkdir_cpuset(const char *pcgdir) noexcept
	{
		try {
			auto 	shrp = cpuset_cg.get_cg_from_dir(pcgdir, true /* mkdir_if_none */);
			if (shrp) {
				return 0;
			}
		}
		GY_CATCH_EXCEPTION(ERRORPRINT_OFFLOAD("Exception caught while creating new cgroup subdir for cpuset at path %s : %s\n", pcgdir, GY_GET_EXCEPT_STRING););
					
		return -1;	
	}	

	int mkdir_memory(const char *pcgdir) noexcept
	{
		try {
			auto 	shrp = memory_cg.get_cg_from_dir(pcgdir, true /* mkdir_if_none */);
			if (shrp) {
				return 0;
			}
		}
		GY_CATCH_EXCEPTION(ERRORPRINT_OFFLOAD("Exception caught while creating new cgroup subdir for memory at path %s : %s\n", pcgdir, GY_GET_EXCEPT_STRING););
					
		return -1;	
	}	

	int mkdir_blkio(const char *pcgdir) noexcept
	{
		try {
			auto 	shrp = blkio_cg.get_cg_from_dir(pcgdir, true /* mkdir_if_none */);
			if (shrp) {
				return 0;
			}
		}
		GY_CATCH_EXCEPTION(ERRORPRINT_OFFLOAD("Exception caught while creating new cgroup subdir for blkio at path %s : %s\n", pcgdir, GY_GET_EXCEPT_STRING););
					
		return -1;	
	}	

	int get_cpu_usage() noexcept;

	int get_cpu_throttle_stats() noexcept;
		
	int get_mem_usage() noexcept;

	int get_blkio_usage() noexcept;

	void verify_dirs() noexcept
	{
		GY_NOMT_COLLECT_PROFILE(100, "cgroup dir validity check");

		RCU_DEFER_OFFLINE		deferlock;

		try {
			cpuacct_cg.cg_verify_dirs();
			cpu_cg.cg_verify_dirs();
			cpuset_cg.cg_verify_dirs();
			memory_cg.cg_verify_dirs();
			blkio_cg.cg_verify_dirs();

			// TODO Add cgroup2
		}
		GY_CATCH_EXCEPTION(ERRORPRINT_OFFLOAD("Exception caught while verifying cgroup directories : %s\n", GY_GET_EXCEPT_STRING););
	}
		
	void verify_procs() noexcept
	{
		GY_NOMT_COLLECT_PROFILE(100, "cgroup task verification");

		RCU_DEFER_OFFLINE		deferlock;

		try {
			cpuacct_cg.cg_verify_procs();
			cpu_cg.cg_verify_procs();
			cpuset_cg.cg_verify_procs();
			memory_cg.cg_verify_procs();
			blkio_cg.cg_verify_procs();
		}
		GY_CATCH_EXCEPTION(ERRORPRINT_OFFLOAD("Exception caught while verifying cgroup processes : %s\n", GY_GET_EXCEPT_STRING););
	}
		
	void check_mount_changes(bool cancel_schedule_if_done = false) noexcept;
			
	static CGROUP_HANDLE * 			get_singleton() noexcept;

	static int				init_singleton();

};	

} // namespace gyeeta


