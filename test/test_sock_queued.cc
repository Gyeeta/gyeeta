//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_cli_socket.h"

using namespace gyeeta;

int main(int argc, char **argv)
{
	if (argc < 3) {
		IRPRINT("\nUsage : %s <Server IP/Hostname> <Server Port>\n\n", argv[0]);
		return -1;
	}

	try {
		CLI_SOCKET		csock(atoi(argv[2]), argv[1]);
		int			sock = csock.get_sock();
		uint32_t		iter = 0;

		csock.send_data("Test data", 9);

		while (true) {
			int 		nrecv = sock_queued_recv_bytes(sock);

			if (nrecv >= 0) {
				INFOPRINT("Socket recv bytes queued = %u\n", nrecv);
			}
			else {
				PERRORPRINT("Socket recv bytes info failed");
				break;
			}	

			char			lbuf[8000]	{};
			ssize_t			sret;

			snprintf(lbuf, sizeof(lbuf), "Write Iter %u...\n", ++iter);

			sret = csock.send_data(lbuf, sizeof(lbuf), MSG_DONTWAIT);
			if (sret < 0) {
				PERRORPRINT("Failed to send data to server");
			}	
			else if (sret == 0) {
				PERRORPRINT("EAGAIN returned send blocked");
			}	

			int 		nsend = sock_queued_send_bytes(sock);

			if (nsend >= 0) {
				INFOPRINT("Socket send bytes queued = %u\n", nsend);
			}
			else {
				PERRORPRINT("Socket send bytes info failed");
				break;
			}	

			gy_msecsleep(5000);
		}	
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT("Exception caught while connecting to server : %s\n\n", GY_GET_EXCEPT_STRING);
	);
}


