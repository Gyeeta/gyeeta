
#include		"gy_sys_stat.h"
#include		"gy_sys_hardware.h"
#include		"gy_print_offload.h"

using namespace gyeeta;

int main(int argc, char *argv[])
{
	SYS_HARDWARE::init_singleton();

	PROC_CPU_IO_STATS::init_singleton();

	STRING_BUFFER<2048>	strbuf;

	SYS_CPU_STATS		cpustats;
	SYS_MEM_STATS		memstats;
	int			i = 0;
	bool			is_prolonged;	
	OBJ_STATE_E 		cpustate, memstate; 
	CPU_ISSUE_SOURCE  	cpu_issue; 
	MEM_ISSUE_SOURCE  	mem_issue; 

	while (true) {
		bool		print_hist = ({++i; bool bret = false; if (i > 10) {bret = true; i = 0;} bret;}); 

		gy_nanosleep_safe(2, 0);
		
		cpustats.get_cpu_stats();
		cpustats.print_stats(true, print_hist);
		
		cpustats.get_curr_state(cpustate, cpu_issue, strbuf);

		IRPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN_UNDERLINE, "\tCPU Status : %s\n\n", strbuf.buffer());
		strbuf.reset();

		memstats.get_mem_stats();
		memstats.print_stats(print_hist);

		memstats.get_curr_state(memstate, mem_issue, strbuf);

		IRPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN_UNDERLINE, "\tMemory Status : %s\n\n", strbuf.buffer());
		strbuf.reset();
	}	

	return 0;
}	

