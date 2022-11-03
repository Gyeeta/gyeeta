//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include 		"gy_socket_stat.h"
#include 		"gy_init_proc.h"
#include 		"gy_task_handler.h"
#include 		"gy_cgroup_stat.h"
#include 		"gy_child_proc.h"
#include 		"gy_ebpf.h"

using namespace gyeeta;

std::atomic<int>	gsig_rcvd(0);	

int handle_signal(int signo)
{
	alarm(0);

	gsig_rcvd.store(1);

	return signo;
}	


int main(int argc, char **argv)
{
	try {
		bool resp_sample = false;

		gdebugexecn = 5;	
	
		if (argc > 1) {
			gdebugexecn = atoi(argv[1]);

			if (argc > 2) {
				resp_sample = atoi(argv[2]);
			}	
		}	


		INIT_PROC		*pinit;
		
		pinit = new INIT_PROC(argc, argv, true /* handle_signals */, false /* exit_on_parent_kill */, true /* chown_if_root */, 
				"./log", "tcp_sock_monitor.log", "tcp_sock_monitor.log", 0, false /*rename_old_log */, 
				"TCP Socket Monitor", false /* disable_core */, false /* set_sessionid */, 
				"./cfg", "./tmp", "tcp_sock_monitor.lock", true /* close_stdin */, 
				1024 * 1024 /* max_stacksize */, 65535 /* min_stacksize */, 65535 /* min_openfiles */, 2048 /* min_nproc */, false /* throw_if_ulimit */);

		GY_SIGNAL_HANDLER::get_singleton()->set_signal_param(nullptr, handle_signal, false);
		
		CHILD_PROC		childproc(false /* use_parent_log_files */, "./log/tcp_sock_monitor_cleanup_child.log", nullptr, false /* exit_on_parent_kill */, 
					true /* use_socket_pair */, false /* use_shared_pool */, 0, 0, [](int signo) { return signo;}, true /* signal_callback_will_exit */);

		pid_t			childpid;
		uid_t			chown_uid;
		gid_t			chown_gid;
		
		pinit->is_chown_uid_gid(chown_uid, chown_gid);

		INFOPRINTCOLOR(GY_COLOR_LIGHT_BLUE, "Spawning the TCP Socket bpf cleanup proc...\n"); 

		childpid = childproc.fork_child("tcp_sock_monitor_cleanup_child", true /* set_thr_name */, "TCP Socket Monitor and bpf cleanup", O_APPEND,
					3, 1024, chown_uid, chown_gid); 
		if (childpid == 0) {
			// Within child
			static pid_t		bpf_parent;
			const char 		*old_argv0 = strdup(argv[0]);	
			
			strcpy(argv[0], "mon_tcp");
			prctl(PR_SET_NAME, (unsigned long)argv[0]);
			
			bpf_parent = childproc.ppid_;

			setsid();

			atexit([]() { clear_bpf_kprobes(bpf_parent);});

			while (true) {
				COMM_MSG_C		msg;
				uint8_t			tbuf[512];
				int			ret;

				ret = COMM_MSG_C::recv_msg(childproc.get_socket(), msg, tbuf, sizeof(tbuf), true /* exec_func */, false /* is_nonblock */); 
				if (ret == -1) {
					if (false == is_socket_still_connected(childproc.get_socket())) {
						INFOPRINTCOLOR(GY_COLOR_GREEN, "TCP Socket Monitor process %d : Parent process %d seems to be exited. "
								"Cleaning up for kprobes of PID %d and exiting...\n", 
							getpid(), childproc.ppid_, childproc.ppid_);
						clear_bpf_kprobes(childproc.ppid_);
						_exit(0);
					}	
				}	
			}	
		}	

		const char		*pext[] = {".log", ".tmp"};

		pinit->set_log_file_monitor(pext, GY_ARRAY_SIZE(pext), 30 * 1024 * 1024, 2);

		PROC_CPU_IO_STATS::init_singleton();

		CGROUP_HANDLE::init_singleton();

		TASK_HANDLER::init_singleton();

		TCP_SOCK_HANDLER::init_singleton(resp_sample);

		while (0 == gsig_rcvd.load()) {
			gy_nanosleep(1, 0);
		}

		INFOPRINTCOLOR(GY_COLOR_BOLD_GREEN, "Exiting now...\n");

		return 0;
	}
	GY_CATCH_EXCEPTION(ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Exception caught : %s : Exiting...\n", GY_GET_EXCEPT_STRING););
}	
