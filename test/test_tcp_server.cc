
#include 		"gy_common_inc.h"
#include 		"gy_listen_sock.h"
#include 		<sys/wait.h>

using namespace 	gyeeta;

const char		*gservaddr;
int			spawn_proc = 0;
uint32_t		num_reuseports = 1;

int start_listener(uint16_t sport)
{
	try {
		int 			ssfd;	
		char			tbuf1[16];
		
		INFOPRINTCOLOR(GY_COLOR_GREEN, "Server %s : PID = %d TID = %d for %s port %hu\n", spawn_proc ? "process" : "thread", getpid(), gy_gettid(), gservaddr, sport);

		snprintf(tbuf1, sizeof(tbuf1), "Port_%hu", sport);

		gy_get_thread_local().set_name(tbuf1, true /* set_comm */);
		
		LISTEN_SOCK		lsock(sport, gservaddr, 128, false /* set_nonblock */, true /* reuseaddr */, num_reuseports > 1 /* reuseport */, false /* ipv6_only */);

		lsock.set_delete_cb(
			[](const int lsock, void *arg1, void *arg2) 
			{
				uint16_t		sport1 = (uint16_t)(uintptr_t)arg1;

				INFOPRINTCOLOR(GY_COLOR_YELLOW, "Server Exiting : PID = %d TID = %d for %s port %hu\n", getpid(), gy_gettid(), gservaddr, sport1);
			}, (void *)(uintptr_t)sport);

		ssfd = lsock.get_sock();
		
		int				fd, ret, sdclient;
		struct sockaddr_storage 	client_address;
		socklen_t 			sin_size = sizeof(client_address);
		char				resbuf[512];
		size_t				nres;

		nres = 1 + GY_SAFE_SNPRINTF(resbuf, sizeof(resbuf), "Test from server PID = %d TID = %d for %s port %hu\n", getpid(), gy_gettid(), gservaddr, sport);

		while (1) {
			if ((sdclient = accept(ssfd, (struct sockaddr *)&client_address, &sin_size)) > 0) {
				(void)gy_sendbuffer(sdclient, resbuf, nres);
			}
		}

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Could not start TCP listener for port %hu : %s\n", sport, GY_GET_EXCEPT_STRING);
		return -1;
	);
}

void * serfunc(void * pport)
{
	uint16_t		port = (uint16_t)(uintptr_t)pport;

	start_listener(port);
	return nullptr;
}	

int main(int argc, char *argv[])
{
	int			ret;
	bool			bret;
	uint16_t		startport = 0, nport = 0, port1;

	if (argc < 4) {
usage :		
		IRPRINT("\n\nUsage : %s <IP to listen on e.g. 0.0.0.0> <Start Port number to listen> <Number of ports upto 16000 thereafter> <Optional spawn process 1/0 : Default 0> <Optional Multi Threads per port (Reuseport <Num threads> : Default 0)>\n\n", argv[0]);
		return -1;
	}
	else {
		gservaddr = argv[1];

		bret = string_to_number(argv[2], startport);
		if (!bret) {
			goto usage;
		}	

		bret = string_to_number(argv[3], nport);
		if (!bret || nport == 0 || nport > 16000) {
			goto usage;
		}	

		if (argc >= 5) {
			spawn_proc = atoi(argv[4]);
		}	
		
		if (argc >= 6) {
			num_reuseports = atoi(argv[5]);
			if (num_reuseports == 0) num_reuseports = 1;
			if (num_reuseports > 1024) num_reuseports = 1024;
		}	
	}

	INFOPRINTCOLOR(GY_COLOR_GREEN, "%s Main thread PID = %d TID = %d : Spawning %hu %s for TCP servers from port %hu onwards with %u accept handlers per port\n", 
		argv[0], getpid(), gy_gettid(), nport, spawn_proc ? "processes" : "threads", startport, num_reuseports);

	if (spawn_proc == 0) {
		pthread_t		*serarr[num_reuseports];

		for (uint32_t n = 0; n < num_reuseports; ++n) {
			serarr[n] = new pthread_t[nport];
			
			for (uint16_t i = 0; i < nport; ++i) {
				port1 = startport + i;

				ret = gy_create_thread(&serarr[n][i], serfunc, (void *)(uintptr_t)port1);
				if (ret) {
					PERRORPRINT("Failed to allocate thread number %hu. Skipping remaining threads", i);
					nport = i;
					break;
				}	
			}	
		}


		for (uint32_t n = 0; n < num_reuseports; ++n) {
			for (uint16_t i = 0; i < nport; ++i) {
				pthread_join(serarr[n][i], nullptr);
			}

			delete [] serarr[n];
		}	
	}
	else {
		/*
		 * We will spawn 1 thread for this process and spawn nport - 1 procs
		 */
		pthread_t		tid[num_reuseports];
		pid_t			*pidarr[num_reuseports];

		for (uint32_t n = 0; n < num_reuseports; ++n) {
			ret = gy_create_thread(&tid[n], serfunc, (void *)(uintptr_t)startport);
			if (ret) {
				PERRORPRINT("Failed to allocate thread. Exiting");
				return -1;
			}	
		}
		
		gy_nanosleep(0, 100 * GY_NSEC_PER_MSEC);

		for (uint32_t n = 0; n < num_reuseports; ++n) {

			pidarr[n] = new pid_t[nport];

			for (uint16_t i = 1; i < nport; ++i) {
				port1 = startport + i;

				pidarr[n][i] = fork();

				if (pidarr[n][i] == -1) {
					PERRORPRINT("Failed to allocate process number %hu. Skipping remaining threads", i);
					nport = i;
					break;
				}	
				else if (pidarr[n][i] == 0) {
					signal(SIGHUP, SIG_DFL);
					prctl(PR_SET_PDEATHSIG, SIGINT);

					serfunc((void *)(uintptr_t)port1);
					_exit(1);
				}
			}	
		}

		for (uint32_t n = 0; n < num_reuseports; ++n) {
			for (uint16_t i = 1; i < nport; ++i) {
				waitpid(pidarr[n][i], nullptr, WUNTRACED);
			}	
			pthread_join(tid[n], nullptr);
			
			delete [] pidarr[n];
		}
	}	

	return 0;
}	
