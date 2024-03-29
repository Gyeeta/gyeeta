//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include 		"gy_common_inc.h"
#include		"gy_cli_socket.h"

#include 		<sys/wait.h>
#include 		<list>

using namespace gyeeta;

const char		*gservaddr = "localhost";
int			spawn_proc = 0, nconn_per_thread = 1;

void *	clifunc(void * pport)
{
	uint16_t			port = (uint16_t)(uintptr_t)pport;

	try {
		INFOPRINTCOLOR(GY_COLOR_GREEN, "Client %s : PID = %d TID = %d for Server %s Port %hu\n", spawn_proc ? "process" : "thread", getpid(), gy_gettid(), gservaddr, port);

		CLI_SOCKET			sock(port, gservaddr, false, true);
		STRING_BUFFER<256>		strbuf1;
		char				resbuf[512], rcvbuf[1024];
		size_t				nres;

		nres = 1 + GY_SAFE_SNPRINTF(resbuf, sizeof(resbuf), "Test from client PID = %d TID = %d for Server %s port %hu\n", getpid(), gy_gettid(), gservaddr, port);

		INFOPRINTCOLOR(GY_COLOR_YELLOW, "Connection Status : %s\n", sock.print_tuple(strbuf1));
		
		std::list<CLI_SOCKET>		socklist(nconn_per_thread, sock);
		
		sock.destroy();

		while (1) {
			socklist.remove_if(
				[&, resbuf, nres, maxrcv = sizeof(rcvbuf) - 1](CLI_SOCKET & csock)
				{
					int 			f = csock.get_sock();
					ssize_t			sret = send(f, resbuf, nres, MSG_DONTWAIT | MSG_NOSIGNAL);

					if (sret < 0 && errno != EAGAIN) {
						return true;
					}	
					
					sret = recv(f, rcvbuf, maxrcv, MSG_DONTWAIT);
					if (sret < 0 && errno != EAGAIN) {
						return true;
					}	

					return false;
				}
			);

			if (socklist.empty()) {
				INFOPRINTCOLOR(GY_COLOR_GREEN, "Exiting thread now as no connections exist for Client %s : PID = %d TID = %d for Server %s Port %hu\n", 
					spawn_proc ? "process" : "thread", getpid(), gy_gettid(), gservaddr, port);
				break;
			}	
			
			gy_msecsleep(100);
		}

		return nullptr;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to connect to server %s port %hu : %s\n", gservaddr, port, GY_GET_EXCEPT_STRING);
		return nullptr;
	);
}


int main(int argc, char *argv[])
{
	int			ret;
	bool			bret;
	uint16_t		startport = 0, nport = 0, port1;

	if (argc < 4) {
usage :		
		IRPRINT("\n\nUsage : %s <Server IP/Hostname> <Start Port number> <Number of ports upto 16000 thereafter> <Optional spawn process 1/0 : Default 0> <Number of connections per thread/process Optional : Default 1>\n\n", argv[0]);
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
			nconn_per_thread = atoi(argv[5]);
			if (nconn_per_thread > 10000) {
				nconn_per_thread = 10000;
			}
			else if (nconn_per_thread == 0) {
				nconn_per_thread = 1;
			}	
		}	
	}

	INFOPRINTCOLOR(GY_COLOR_GREEN, "%s Main thread PID = %d TID = %d : Spawning %hu %s for TCP clients to %s from port %hu onwards : %d connections per client\n", 
		argv[0], getpid(), gy_gettid(), nport, spawn_proc ? "processes" : "threads", gservaddr, startport, nconn_per_thread);

	if (spawn_proc == 0) {
		pthread_t		*cliarr;

		cliarr = new pthread_t[nport];

		for (uint16_t i = 0; i < nport; ++i) {
			port1 = startport + i;

			ret = gy_create_thread(&cliarr[i], clifunc, (void *)(uintptr_t)port1);
			if (ret) {
				PERRORPRINT("Failed to allocate thread number %hu. Skipping remaining threads", i);
				nport = i;
				break;
			}	
		}	

		for (uint16_t i = 0; i < nport; ++i) {
			pthread_join(cliarr[i], nullptr);
		}	

		delete [] cliarr;
	}
	else {
		pid_t			*pidarr;

		pidarr = new pid_t[nport];
		
		for (uint16_t i = 0; i < nport; ++i) {
			port1 = startport + i;

			pidarr[i] = fork();

			if (pidarr[i] == -1) {
				PERRORPRINT("Failed to allocate process number %hu. Skipping remaining threads", i);
				nport = i;
				break;
			}	
			else if (pidarr[i] == 0) {
				signal(SIGHUP, SIG_DFL);
				prctl(PR_SET_PDEATHSIG, SIGINT);

				clifunc((void *)(uintptr_t)port1);
				_exit(1);
			}
		}	

		for (uint16_t i = 0; i < nport; ++i) {
			waitpid(pidarr[i], nullptr, WUNTRACED);
		}	

		delete [] pidarr;
	}	

	return 0;

}	

