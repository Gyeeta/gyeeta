
#include		"gy_common_inc.h"
#include 		"gy_rcu_inc.h"
#include 		"gy_inet_inc.h"
#include 		"gy_socket_stat.h"
#include		"gy_file_api.h"

#include 		<dirent.h>
#include 		<unistd.h>
#include 		<cstdlib>
#include 		<string>
#include		<cstdint>
#include		<arpa/inet.h>

#include 		<poll.h>
#include 		<linux/netlink.h>
#include 		<linux/rtnetlink.h>
#include 		<netinet/in.h>
#include 		<linux/sock_diag.h>
#include 		<linux/inet_diag.h>

#include 		<vector>
#include 		<sched.h>

using namespace 	gyeeta;

NETNS_HASH_TABLE			netns_tbl_(1);	

#define GY_TCP_ALL_FLAGS 		((1 << GY_TCP_MAX_STATES) - 1)
#define GY_SOCK_DIAG_FLAGS 		(GY_TCP_ALL_FLAGS & ~(/* (1 << GY_TCP_LISTEN) | */ (1 << GY_TCP_CLOSE) | (1 << GY_TCP_TIME_WAIT) | (1 << GY_TCP_SYN_RECV) | (1 << GY_TCP_NEW_SYN_RECV)))

#define GY_TCP_MAGIC_SEQ 		123456
#define GY_INET_BUFFER_SIZE 		(16 * 1024)

static int sockdiag_send(int sockfd)
{
	struct sockaddr_nl 		nladdr = { .nl_family = AF_NETLINK };
	struct {
		struct nlmsghdr 	nlh;
		struct inet_diag_req 	r;
	} req = {};
	struct msghdr 			msg;
	struct iovec 			iov[3];
	int 				iovlen = 1;

	req.nlh.nlmsg_len 		= sizeof(req),
	req.nlh.nlmsg_flags 		= NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST,
	req.nlh.nlmsg_seq 		= GY_TCP_MAGIC_SEQ,
	req.nlh.nlmsg_type 		= TCPDIAG_GETSOCK;
	req.r.idiag_family 		= AF_UNSPEC,
	req.r.idiag_states 		= GY_SOCK_DIAG_FLAGS,

	req.r.idiag_ext 		|= (1 << (INET_DIAG_INFO - 1));

	iov[0] = (struct iovec) {
		.iov_base 		= &req,
		.iov_len 		= sizeof(req)
	};

	msg = (struct msghdr) {
		.msg_name 		= (void *)&nladdr,
		.msg_namelen 		= sizeof(nladdr),
		.msg_iov 		= iov,
		.msg_iovlen 		= (size_t)iovlen,
	};

	if (sendmsg(sockfd, &msg, 0) < 0) {
		PERRORPRINT("Could not send nl inet diag message");
		return -1;
	}

	return 0;
}

static int parse_diag_msg(struct inet_diag_msg *pdiag_msg, int rta_len, bool print_recent, ino_t inode, char *pstr)
{
	struct rtattr 			*attr;
	GY_TCP_CONN			connstat = {};

	uint8_t				idiag_family = pdiag_msg->idiag_family;
	uint32_t			addr32_be, interface_num;
	unsigned __int128		addr128_be;
	uid_t				uid;
	GY_TCP_INFO	 		*info;
	TCP_INFO_STATS		tcpi;
	char				infobuf[512], tcpstatbuf[512];
	STR_WR_BUF 			tcpss {tcpstatbuf, sizeof(tcpstatbuf)};

	connstat.conn_state = (GY_TCP_STATE_E)pdiag_msg->idiag_state;

	if (idiag_family == AF_INET) {
		memcpy(&addr32_be, pdiag_msg->id.idiag_src, sizeof(addr32_be));
		connstat.client_conn.ipaddr.set_ip(addr32_be);

		memcpy(&addr32_be, pdiag_msg->id.idiag_dst, sizeof(addr32_be));
		connstat.server_conn.ipaddr.set_ip(addr32_be);

	}	
	else {
		memcpy(&addr128_be, pdiag_msg->id.idiag_src, sizeof(addr128_be));
		connstat.client_conn.ipaddr.set_ip(addr128_be);

		memcpy(&addr128_be, pdiag_msg->id.idiag_dst, sizeof(addr128_be));
		connstat.server_conn.ipaddr.set_ip(addr128_be);
	}	

	connstat.client_conn.port = ntohs(pdiag_msg->id.idiag_sport);
	connstat.server_conn.port = ntohs(pdiag_msg->id.idiag_dport);

	uid 		= pdiag_msg->idiag_uid;
	interface_num 	= pdiag_msg->id.idiag_if;

	connstat.client_conn.interface_num = pdiag_msg->id.idiag_if;

	*infobuf = '\0';
	*tcpstatbuf = '\0';

	connstat.get_conn_info_str(infobuf, sizeof(infobuf));

	if (connstat.conn_state != GY_TCP_LISTEN) {
		for (attr = (struct rtattr *) (pdiag_msg + 1); RTA_OK(attr, rta_len); attr = RTA_NEXT(attr, rta_len)) {
			if (attr->rta_type == INET_DIAG_INFO) {

				int len = RTA_PAYLOAD(attr);

				/* workaround for older kernels with less fields */
				if (len < (int)sizeof(*info)) {
					info = (decltype(info))alloca(sizeof(*info));
					memcpy(info, RTA_DATA(attr), len);
					memset((char *)info + len, 0, sizeof(*info) - len);
				} else
					info = (decltype(info))RTA_DATA(attr);

				tcpi.populate_tcp_info(info);

				if (!print_recent || (tcpi.is_recent_activity(1000))) {
					tcpi.print_tcpinfo_str(tcpss);
				}	
				
				break;
			}
		}
	}

	if (*tcpstatbuf || *infobuf) {	
		INFOPRINT("[%s]: TCP Connection : %s : UID %u : Inode %u : Interface = %u idiag_wqueue = %u : Stats %s\n\n", 
				pstr, infobuf, pdiag_msg->idiag_uid, pdiag_msg->idiag_inode, interface_num, pdiag_msg->idiag_wqueue, tcpstatbuf);
	}	

	return 0;
}	

static int do_inet_diag_info(int niter, ino_t inode, char *pstr)
{
	EXEC_TIME		prof1(__FUNCTION__, __LINE__);

	int 			nl_sock = 0, numbytes = 0, rtalen = 0, inet_ret = -1, ret;
	struct nlmsghdr 	*nlh;
	uint8_t 		buf[GY_INET_BUFFER_SIZE];
	struct inet_diag_msg 	*pdiag_msg;

	struct sockaddr_nl 	addr;

	struct iovec iov = {
		.iov_base	= buf,
		.iov_len	= GY_INET_BUFFER_SIZE,
	};

	struct msghdr msg = {
		.msg_name	= &addr,
		.msg_namelen	= sizeof(struct sockaddr_nl),
		.msg_iov	= &iov,
		.msg_iovlen	= 1,
		.msg_control	= NULL,
		.msg_controllen	= 0,
		.msg_flags	= 0,
	};

	if ((nl_sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG)) == -1) {
		PERRORPRINT("inet diag socket failed");
		goto done_ret;
	}

	try {
		if (sockdiag_send(nl_sock) < 0) {
			goto done_ret;
		}

		while (1) {
			int			msglen = 0;
			struct nlmsghdr 	*h;
			bool			found_done = false, dump_intr = false;

			ret = recvmsg(nl_sock, &msg, 0);
			if (ret == -1) {
				if (errno == EINTR || errno == EAGAIN) {
					continue;
				}	

				PERRORPRINT("recv of inet diag failed");
				break;
			}	
			else if (ret == 0) {
				break;
			}	

			if (msg.msg_namelen != sizeof(struct sockaddr_nl)) {
				errno = EINVAL;
				PERRORPRINT("recv of inet diag failed due to invalid data len msg_namelen %u, sizeof len %lu", msg.msg_namelen, sizeof(struct sockaddr_nl));
				break;
			}

			h = (struct nlmsghdr *)buf;

			msglen = ret;

			while (NLMSG_OK(h, (unsigned)msglen)) {
				if (h->nlmsg_flags & NLM_F_DUMP_INTR) {
					dump_intr = true;
				}	

				if (h->nlmsg_type == NLMSG_DONE) {
					found_done = true;
					break; 
				}

				if (h->nlmsg_type == NLMSG_ERROR) {
					ERRORPRINT("recv of inet diag failed due to invalid data\n");
					goto done_ret;
				}

				pdiag_msg = (struct inet_diag_msg *) NLMSG_DATA(h);

				rtalen = h->nlmsg_len - NLMSG_LENGTH(sizeof(*pdiag_msg));

				parse_diag_msg(pdiag_msg, rtalen, niter > 1, inode, pstr);

				h = NLMSG_NEXT(h, msglen);
			}

			if (found_done) {
				if (dump_intr) {
					DEBUGEXECN(1, INFOPRINT("inet diag dump was interrupted and may be inconsistent.\n"););
				}	
				break;
			}

			if (msg.msg_flags & MSG_TRUNC) {
				continue;
			}
			if (msglen) {
				ERRORPRINT("inet diag messgae still remains of size %d\n", msglen);
				goto done_ret;
			}
		}	
		
		inet_ret = 0;
		
	}
	GY_CATCH_EXCEPTION(ERRORPRINT("Exception caught while query inet info : %s\n", GY_GET_EXCEPT_STRING));

done_ret :
	if (nl_sock > 0) {
		close(nl_sock);
	}	

	return inet_ret;
}	


int populate_ns_tbl()
{
	try {
		/*
		 * Scan all tasks in system to get the list of unique Network Namespaces
		 */

		EXEC_TIME			prof1(__FUNCTION__, __LINE__);

		DIR				*pdir = nullptr, *ptaskdir = nullptr;
		struct dirent			*pdent, *ptaskdent;
		char				*pfile, path[256], readstr[64], *pstr1, *ptaskfile;
		struct stat			stat1;
		uint64_t			ulval, ultaskval, inoval, pidnsval;
		int				ret, nspaces = 0;
		bool				bret;
		NETNS_ELEM			*pnetns;

		pdir = opendir("/proc");
		if (!pdir) {
			PERRORPRINT("Could not open proc filesystem");
			return -1;
		}

		GY_SCOPE_EXIT {
			if (pdir) {
				closedir(pdir);
			}	

			gy_thread_rcu().gy_rcu_thread_offline();
		};

		while ((pdent = readdir(pdir)) != NULL) {

			pfile = pdent->d_name;	
			
			pstr1 = nullptr;

			bret = string_to_number(pfile, ulval, &pstr1, 10);
			if (bret && (ulval > 0)) {
				if (pstr1 && *pstr1) {
					continue;
				}	
			}	
			else {
				continue;
			}	

			pidnsval = 0;

			snprintf(path, sizeof(path), "/proc/%lu/task", ulval);

			ptaskdir = opendir(path);
			if (!ptaskdir) {
				continue;
			}	

			GY_SCOPE_EXIT {
				closedir(ptaskdir);
			};	

			while ((ptaskdent = readdir(ptaskdir)) != NULL) {

				ptaskfile = ptaskdent->d_name;	
				
				pstr1 = nullptr;

				bret = string_to_number(ptaskfile, ultaskval, &pstr1, 10);
				if (bret && (ultaskval > 0)) {
					if (pstr1 && *pstr1) {
						continue;
					}	
				}	
				else {
					continue;
				}	

				snprintf(path, sizeof(path), "/proc/%lu/task/%lu/ns/net", ulval, ultaskval);

				ret = readlink(path, readstr, sizeof(readstr) - 1);
				if (ret > 5) {
					readstr[ret] = '\0';

					bret = string_to_number(readstr + 5, inoval, nullptr, 10);

					if (!(bret && inoval > 0)) {
						continue;
					}

					if (pidnsval == inoval) {
						continue;
					}	

					pidnsval = inoval;

					bret = netns_tbl_.template lookup_single_elem<RCU_LOCK_FAST>(inoval, get_uint64_hash((uint64_t)inoval));

					if (bret == false) {
						INFOPRINT("New Network Namespace %lu seen for PID %lu Thread %lu\n", inoval, ulval, ultaskval);
						nspaces++;
						
						pnetns = new NETNS_ELEM(inoval, pid_t(ulval), pid_t(ultaskval));

						netns_tbl_.template insert_or_replace<RCU_LOCK_FAST>(pnetns, inoval, get_uint64_hash((uint64_t)inoval));
					}	
				}	
			}
		}

	 	INFOPRINT("Total number of Network Namespaces is %d\n", nspaces);

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Exception caught while getting Net NS list : %s\n", GY_GET_EXCEPT_STRING);
		return -1;
	);
}	


int handle_inet_diag(int niter)
{
	try {
		int			ret;

		ret = populate_ns_tbl();
		if (ret == -1) {
			return ret;
		}	

		// Now loop through all namespaces for niter times

		auto 			lambda_ns = [&](NETNS_ELEM *pdatanode, void *arg1) noexcept -> CB_RET_E
		{
			try {
				int		ret, niter = (intptr_t)arg1;
				char		strbuf[64];

				INFOPRINTCOLOR(GY_COLOR_BLUE, "Starting inet diag for NetNS %lu\n", pdatanode->inode_);

				ret = setns(pdatanode->fd_netns_, CLONE_NEWNET);
				if (ret == -1) {
					PERRORPRINT("Failed to setns for NetNS %lu", pdatanode->inode_);
					return CB_OK;
				}	

				snprintf(strbuf, sizeof(strbuf), "NetNS %lu : Start PID %d", pdatanode->inode_, pdatanode->pid_start_);

				do_inet_diag_info(niter, pdatanode->inode_, strbuf);

				return CB_OK;
			}
			GY_CATCH_EXCEPTION(
				ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Exception caught while getting inet diag for NetNS : %s\n", GY_GET_EXCEPT_STRING);
				return CB_BREAK_LOOP;
			);
		};	


		for (int i = 0; i < niter; i++) {
			SCOPE_NANOSLEEP			scopesleep(10, 0, false);
			
			netns_tbl_.walk_hash_table(lambda_ns, (void *)(intptr_t)i); 	

			if (i == niter - 1) {
				scopesleep.reset_sleep();
			}	
		}	

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Exception caught while handling inet diag : %s\n", GY_GET_EXCEPT_STRING);
		return -1;
	);	

}	

int main(int argc, char **argv)
{
	int			niter = 1;

	gdebugexecn = 10;

	if (argc > 1) {
		niter = atoi(argv[1]);
	}	

	return handle_inet_diag(niter);
}	

