//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include		"gy_sys_hardware.h"

using 			namespace gyeeta;

int main(int argc, char ** argv)
{
	int				niter = 10;

	if (argc > 1) 
		niter = atoi(argv[1]);

	gdebugexecn	= 10;

	try {

		PROC_CPU_IO_STATS		procstats(getpid(), getpid(), true);

		procstats.get_current_stats(true);

		int				ret, sib[1];
		SYS_HARDWARE			sys_hw(true /* ignore_min_kern */);
		char				buf[1024];
		uint64_t			hi, lo;

		sys_hw.get_machine_id_num(hi, lo);

		INFOPRINTCOLOR(GY_COLOR_CYAN, "Host Machine ID is 0x%016lx%016lx\n\n", hi, lo);
		INFOPRINTCOLOR(GY_COLOR_GREEN, "Host CPU Memory info : %s\n", sys_hw.cpumem_info->get_cpu_mem_print_str(buf, sizeof(buf) - 1));
		
		for (int i = 0; i < niter; i++) {	
			gy_nanosleep(10, 0);

			sys_hw.cpumem_info->check_for_changes();
			sys_hw.net_info->check_for_changes();

			procstats.get_current_stats(true);
		}
	}
	GY_CATCH_EXCEPTION(ERRORPRINTCOLOR(GY_COLOR_RED, "Exception Caught while getting Hardware/System Info : %s\n", GY_GET_EXCEPT_STRING); return -1;);

	return 0;
}	

