
#pragma			once

#include		"gy_common_inc.h"
#include		"gy_print_offload.h"
#include		"gy_file_api.h"
#include		"gy_sys_hardware.h"
#include		"gy_statistics.h"
#include		"gy_misc.h"
#include		"gy_comm_proto.h"

namespace gyeeta {

static constexpr int			SYS_STAT_UPDATE_MSEC	= 2000;	// Every 2 sec	
static constexpr int			SYS_STAT_COMM_MSEC	= SYS_STAT_UPDATE_MSEC * 2; // Every alternate record to be sent to Madhava

static constexpr int			MAX_SYS_HIST_STATS 	= 5;
static constexpr int			MAX_SYS_ISSUE_HIST	= 8;

struct CPU_ISSUE_STAT
{
	OBJ_STATE_E			state 	{STATE_IDLE};
	CPU_ISSUE_SOURCE		issue	{ISSUE_CPU_NONE};
};	

class SYS_CPU_STATS
{
public :
	using CPU_TIME_HISTOGRAM	= PERCENT_TIME_HISTOGRAM <Level_300_all, SCOPE_GY_MUTEX>;
	using CSWITCH_TIME_HISTOGRAM	= TIME_HISTOGRAM <SEMI_LOG_HASH, Level_300_all, SCOPE_GY_MUTEX>;
	using FORKS_TIME_HISTOGRAM	= TIME_HISTOGRAM <HASH_10_5000, Level_300_all, SCOPE_GY_MUTEX>;
	using PROCS_TIME_HISTOGRAM	= TIME_HISTOGRAM <HASH_5_250, Level_300_all, SCOPE_GY_MUTEX>;

	struct CPU_ONE_STATS
	{
		uint64_t 		cpu_user;
		uint64_t 		cpu_nice;
		uint64_t 		cpu_sys;
		uint64_t 		cpu_idle;
		uint64_t 		cpu_iowait;
		uint64_t 		cpu_steal;
		uint64_t 		cpu_hardirq;
		uint64_t 		cpu_softirq;
		uint64_t 		cpu_guest;
		uint64_t 		cpu_guest_nice;
		
		uint64_t		clock_nsec;

		float			pct_user;
		float			pct_sys;
		float			pct_iowait;

		CPU_ONE_STATS()
		{
			gy_safe_memset(this);
		}	
	};

	struct CORE_CPU_HIST 
	{
		float			cpu_pct_hist[MAX_SYS_HIST_STATS]	{};
	};	
	
	static constexpr size_t		MAX_PROC_STAT_SIZE			{128 * 1024};	 

	uint32_t			max_cores_possible			{0};
	uint32_t			curr_cores_online			{0};

	CPU_ONE_STATS			*pcpuarr				{nullptr};
	CORE_CPU_HIST			*pcore_cpu_hist				{nullptr};

	CPU_ONE_STATS			overall_stats;
	uint64_t			cumul_context_switch			{0};
	uint64_t			curr_context_switch			{0};

	uint64_t			cumul_forks				{0};

	uint64_t			curr_clock_nsec				{0};
	uint64_t			last_clock_nsec				{0};
		 
	float				usercpu_pct_hist[MAX_SYS_HIST_STATS]	{};
	float				syscpu_pct_hist[MAX_SYS_HIST_STATS]	{};
	float				cpu_pct_hist[MAX_SYS_HIST_STATS]	{};

	uint64_t			context_switch_hist[MAX_SYS_HIST_STATS]	{};
	uint32_t			fork_hist[MAX_SYS_HIST_STATS]		{};
	uint32_t			procs_running_hist[MAX_SYS_HIST_STATS]	{};
	
	CPU_ISSUE_STAT			issue_hist[MAX_SYS_ISSUE_HIST]		{};
	uint8_t				issue_bit_hist				{0};	// 8 * 2 = 16 sec history
	uint8_t				severe_issue_bit_hist			{0};	// 8 * 2 = 16 sec history

	float				cumul_core_cpu_pct			{0};
	
	int64_t				cpu_p95_				{0};
	int64_t				cpu_5min_p95_				{0};
	int64_t				cs_p95_					{0};
	int64_t				cs_5min_p95_				{0};
	int64_t				fork_p95_				{0};
	int64_t				fork_5min_p95_				{0};
	int64_t				procs_p95_				{0};
	int64_t				procs_5min_p95_				{0};

	CPU_TIME_HISTOGRAM		cpuhistogram;
	CSWITCH_TIME_HISTOGRAM		cshistogram;
	FORKS_TIME_HISTOGRAM		fork_histogram;
	PROCS_TIME_HISTOGRAM		procs_running_histogram;

	SYS_CPU_STATS();
	
	SYS_CPU_STATS(const SYS_CPU_STATS &)					= delete;
	SYS_CPU_STATS & operator= (const SYS_CPU_STATS &)			= delete;

	~SYS_CPU_STATS() noexcept
	{
		if (pcore_cpu_hist) {
			delete [] pcore_cpu_hist;
			pcore_cpu_hist = nullptr;
		}	

		if (pcpuarr) {
			delete [] pcpuarr;
			pcpuarr = nullptr;
		}	
	}	

	int				get_cpu_stats() noexcept;
	void				print_stats(bool print_core_util = false, bool print_histogram = false) noexcept;	// Call get_cpu_stats() before calling print_stats()
	int				get_curr_state(OBJ_STATE_E & cpustate, CPU_ISSUE_SOURCE & cpu_issue, STR_WR_BUF & strbuf, bool update_stats = false) noexcept;		
	void 				upd_comm_state(comm::CPU_MEM_STATE_NOTIFY *pcpumem, STR_WR_BUF strbuf) const noexcept;

	// Use this init_singleton() if only System CPU Util stats needed and no Memory stats needed
	static int			init_singleton(uint32_t delay_seconds = 60);

	static SYS_CPU_STATS *		get_singleton() noexcept;

private :	
	uint64_t 			get_diffticks(CPU_ONE_STATS *pnewstats, CPU_ONE_STATS *poldstats) noexcept;
	void 				calc_cpu_pct(CPU_ONE_STATS *pnewstats, CPU_ONE_STATS *poldstats, uint64_t diffticks) noexcept;
};

struct MEM_ISSUE_STAT
{
	OBJ_STATE_E			state 	{STATE_IDLE};
	MEM_ISSUE_SOURCE		issue	{ISSUE_MEM_NONE};
};	

class SYS_MEM_STATS
{
public :
	using PAGE_HISTOGRAM		= GY_HISTOGRAM <int, SEMI_LOG_HASH>;
	using PCT_HISTOGRAM		= GY_HISTOGRAM <int, PERCENT_HASH>;

	uint64_t			rss_memory				{0};
	uint64_t			cached_memory				{0};
	uint64_t			locked_memory				{0};
	uint64_t			total_memory				{0};
	uint64_t			free_immed_memory			{0};
	uint64_t			committed_memory			{0};

	float				pct_rss_hist[MAX_SYS_HIST_STATS]	{};
	float				pct_committed_hist[MAX_SYS_HIST_STATS]	{};

	uint32_t			pginout_hist[MAX_SYS_HIST_STATS]	{};
	uint32_t			swpinout_hist[MAX_SYS_HIST_STATS]	{};
	uint32_t			allocstall_hist[MAX_SYS_HIST_STATS]	{};
	uint32_t			pgmajfault_hist[MAX_SYS_HIST_STATS]	{};
	uint32_t			oom_kill_hist[MAX_SYS_HIST_STATS]	{};
	
	MEM_ISSUE_STAT			issue_hist[MAX_SYS_ISSUE_HIST]		{};
	uint8_t				issue_bit_hist				{0};	// 8 * 2 = 32 sec history
	uint8_t				severe_issue_bit_hist			{0};	// 8 * 2 = 32 sec history
	
	uint64_t			last_pginout				{0};
	uint64_t			last_swpinout				{0};
	uint64_t			last_allocstall				{0};
	uint64_t			last_pgmajfault				{0};
	uint64_t			last_oom_kill				{0};

	uint64_t			free_swap				{0};
	uint64_t			total_swap				{0};
	
	uint64_t			curr_clock_nsec				{0};
	uint64_t			last_clock_nsec				{0};
		 
	int64_t				pct_rss_p95_				{0};
	int64_t				pginout_p95_				{0};
	int64_t				swpinout_p95_				{0};
	int64_t				allocstall_p95_				{0};

	PCT_HISTOGRAM			pct_rss_histogram;	
	PAGE_HISTOGRAM			pginout_histogram;
	PAGE_HISTOGRAM			swpinout_histogram;
	PAGE_HISTOGRAM			allocstall_histogram;
		 
	SYS_MEM_STATS()
	{
		int			ret;

		ret = get_mem_stats();
		if (ret != 0) {
			if (ret < 0) {
				GY_THROW_SYS_EXCEPTION("Failed to get Host Memory Stats from /proc filesystem");
			}

			GY_THROW_EXCEPTION("Failed to get Host Memory Stats from /proc filesystem");
		}	
	}	

	int				get_mem_stats() noexcept;
	void				print_stats(bool print_histogram = false) noexcept;		// Call get_mem_stats() before calling print_stats()
	int				get_curr_state(OBJ_STATE_E & memstate, MEM_ISSUE_SOURCE & mem_issue, STR_WR_BUF & strbuf, bool update_stats = false) noexcept;		
	void 				upd_comm_state(comm::CPU_MEM_STATE_NOTIFY *pcpumem, STR_WR_BUF strbuf) const noexcept;

	static SYS_MEM_STATS *		get_singleton() noexcept;
};	

class SYSTEM_STATS
{
public :
	SYS_CPU_STATS		cpustats;
	SYS_MEM_STATS		memstats;	

	SYSTEM_STATS() 		= default;
	
	int get_stats(comm::CPU_MEM_STATE_NOTIFY *pcpumem = nullptr) noexcept
	{
		int				ret;
		OBJ_STATE_E			cpustate, memstate;
		CPU_ISSUE_SOURCE  		cpu_issue; 
		MEM_ISSUE_SOURCE  		mem_issue; 

		STRING_BUFFER<256>		strbufcpu, strbufmem;

		// Minimum 1 sec diff needed between successive calls to get_stats() or else it will return an error
		ret = cpustats.get_cpu_stats();
		if (ret != 0) {
			return ret;
		}
			
		cpustats.get_curr_state(cpustate, cpu_issue, strbufcpu, true /* update_stats */);
		
		array_shift_right(cpustats.issue_hist, GY_ARRAY_SIZE(cpustats.issue_hist));
		cpustats.issue_hist[0] = {cpustate, cpu_issue};

		cpustats.issue_bit_hist <<= 1;
		cpustats.severe_issue_bit_hist <<= 1;

		if (cpustate >= STATE_BAD) {
			cpustats.issue_bit_hist |= 1;	

			if (cpustate >= STATE_SEVERE) {
				cpustats.severe_issue_bit_hist |= 1;
			}	
			
			CONDEXEC(
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Host CPU Status : %.*s\n\n", strbufcpu.sizeint(), strbufcpu.buffer());
			);	
		}	

		if (pcpumem) {
			cpustats.upd_comm_state(pcpumem, strbufcpu);
		}	
		
		ret = memstats.get_mem_stats();
		if (ret != 0) {
			return ret;
		}
			
		memstats.get_curr_state(memstate, mem_issue, strbufmem, true /* update_stats */);
		
		array_shift_right(memstats.issue_hist, GY_ARRAY_SIZE(memstats.issue_hist));
		memstats.issue_hist[0] = {memstate, mem_issue};

		memstats.issue_bit_hist <<= 1;
		memstats.severe_issue_bit_hist <<= 1;

		if (memstate >= STATE_BAD) {
			memstats.issue_bit_hist |= 1;	
			
			if (memstate >= STATE_SEVERE) {
				memstats.severe_issue_bit_hist |= 1;
			}	

			CONDEXEC(
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Host Memory Status : %.*s\n\n", strbufmem.sizeint(), strbufmem.buffer());
			);	
		}	

		if (pcpumem) {
			memstats.upd_comm_state(pcpumem, strbufmem);
		}	

		return 0;
	}

	bool is_recent_cpu_issue(uint8_t bitmap = 0x07 /* 3 * 2 = 6 sec */) const noexcept
	{
		return ((cpustats.issue_bit_hist & bitmap) > 0);
	}	

	bool is_recent_mem_issue(uint8_t bitmap = 0x07 /* 3 * 2 = 6 sec */) const noexcept
	{
		return ((memstats.issue_bit_hist & bitmap) > 0);
	}	

	bool is_severe_cpu_issue(uint8_t bitmap = 0x07 /* 3 * 2 = 6 sec */) const noexcept
	{
		return ((cpustats.severe_issue_bit_hist & bitmap) > 0);
	}	

	bool is_severe_mem_issue(uint8_t bitmap = 0x07 /* 3 * 2 = 6 sec */) const noexcept
	{
		return ((memstats.severe_issue_bit_hist & bitmap) > 0);
	}	

	void get_issue_stats(bool & cpu_issue, bool & mem_issue, bool & severe_cpu_issue, bool & severe_mem_issue, bool & cpu_idle, bool & mem_idle, uint8_t bitmap = 0x07 /* 3 * 2 = 6 sec */) const noexcept
	{
		cpu_issue		= is_recent_cpu_issue(bitmap);
		mem_issue		= is_recent_mem_issue(bitmap);
		severe_cpu_issue	= is_severe_cpu_issue(bitmap);
		severe_mem_issue	= is_severe_mem_issue(bitmap);
		
		int			nslots = gy_count_bits_set((uint32_t)bitmap);
		
		if (nslots > MAX_SYS_HIST_STATS) {
			nslots = MAX_SYS_HIST_STATS;
		}	

		for (int i = 0; i < nslots; ++i) {
			cpu_idle |= (cpustats.issue_hist[i].state == STATE_IDLE);
			mem_idle |= (memstats.issue_hist[i].state == STATE_IDLE);
		}	
	}	

	void print_stats(bool print_histogram = false) noexcept
	{
		STRING_BUFFER<512>	strbuf;

		OBJ_STATE_E		cpustate, memstate;
		CPU_ISSUE_SOURCE  	cpu_issue; 
		MEM_ISSUE_SOURCE  	mem_issue; 
		
		cpustats.print_stats(false /* print_core_util */, print_histogram);

		cpustats.get_curr_state(cpustate, cpu_issue, strbuf);
		
		IRPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN_UNDERLINE, "\tCPU Status : %s%.*s\n\n", get_state_color(cpustate), strbuf.sizeint(), strbuf.buffer());

		strbuf.reset();

		memstats.print_stats(print_histogram);

		memstats.get_curr_state(memstate, mem_issue, strbuf);

		IRPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN_UNDERLINE, "\tMemory Status : %s%.*s\n\n", get_state_color(memstate), strbuf.sizeint(), strbuf.buffer());
	}

	static int			init_singleton();

	static SYSTEM_STATS *		get_singleton() noexcept;
};	

} // namespace gyeeta	
