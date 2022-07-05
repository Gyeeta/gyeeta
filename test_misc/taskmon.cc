
#include 		"gy_common_inc.h"
#include 		"gy_file_api.h"
#include 		"gy_task_stat.h"
#include 		"gy_mount_disk.h"
#include 		"gy_rcu_inc.h"
#include 		"gy_cgroup_stat.h"
#include		"gy_async_func.h"			

#include		<dirent.h>
#include 		<linux/netlink.h>
#include 		<linux/connector.h>
#include 		<linux/cn_proc.h>

using namespace gyeeta;


namespace {

using 	TASK_ELEM_TYPE 			= RCU_HASH_WRAPPER <pid_t, std::shared_ptr<TASK_STAT>>;
using 	TASK_HASH_TABLE 		= RCU_HASH_TABLE <pid_t, TASK_ELEM_TYPE>;

TASK_HASH_TABLE			*pgtaskhash;

std::atomic<int>			gsig_rcvd;	
int					gprocfd;

int task_add(pid_t pid, pid_t ppid, bool add_cgroup = false)
{
	try {
		TASK_ELEM_TYPE		*pelem = nullptr;
		bool				bret, new_task = false;
		TASK_STAT			*ptask = nullptr;

		if (ppid > 0) {
			TASK_ELEM_TYPE		elem_parent{};

			/*
			 * First check if the parent PID is present in task table 
			 */
			bret = pgtaskhash->template lookup_single_elem<RCU_LOCK_SLOW>(ppid, get_pid_hash(ppid), elem_parent);

			if (bret == true) {
				const auto		ptaskpar = elem_parent.get_data()->get();

				if (ptaskpar) {
					ptask = new TASK_STAT(ptaskpar, pid, gprocfd);
				}
				else {
					bret = false;
				}	
			}	
		}	

		if (!ptask) {
			ptask = new TASK_STAT(gprocfd, pid, ppid);
			new_task = true;
		}	

		if (!ptask->is_task_valid()) {
			DEBUGEXECN(1, INFOPRINTCOLOR(GY_COLOR_RED, "Failed to populate data for new fork task %d. Ignoring...\n", pid););

			delete ptask;
			return 1;
		}

		try {
			pelem = new TASK_ELEM_TYPE(ptask);
		}
		GY_CATCH_EXCEPTION(
			DEBUGEXECN(1, ERRORPRINT("Caught exception while allocating memory for task table for PID %d : %s\n", pid, GY_GET_EXCEPT_STRING););
			delete ptask;
			return -1;
		);

		DEBUGEXECN(1, INFOPRINTCOLOR(GY_COLOR_CYAN, "Fork of new process : PID %d PPID %d UID %d GID %d : %s\n", 
				ptask->task_pid, ptask->task_ppid, ptask->task_effuid, ptask->task_effgid, ptask->task_cmdline););

		bret = pgtaskhash->template insert_or_replace<RCU_LOCK_SLOW>(pelem, pid, get_pid_hash(pid));

		if (add_cgroup) {
			ptask->set_task_cgroups(gprocfd);
		}	

		return 0;
	}
	GY_CATCH_EXCEPTION(DEBUGEXECN(1, ERRORPRINT("Caught exception while inserting new mini task for PID %d : %s\n", pid, GY_GET_EXCEPT_STRING);); return -1;);
}	

int task_exit(pid_t pid, int exit_code)
{
	try {
		if (gy_likely(gdebugexecn == 0)) {
			return (int)pgtaskhash->delete_single_elem(pid, get_pid_hash(pid));
		}
		else {
			bool		bret;

			auto 		lambda_exit_task = [](TASK_ELEM_TYPE *pdatanode, void *arg1, void *arg2) noexcept -> CB_RET_E
			{
				auto			ptask = pdatanode->get_data()->get();
				int			*pexit_code = (int *)arg1;
				TASK_KILL_INFO		kone;

				if (ptask == nullptr) {
					return CB_DELETE_ELEM;
				}
	
				ptask->set_task_exited(*pexit_code, kone);

				return CB_DELETE_ELEM;
			};	

			bret = pgtaskhash->template lookup_single_elem<decltype(lambda_exit_task), RCU_LOCK_SLOW>(pid, get_pid_hash(pid), lambda_exit_task, &exit_code, nullptr);

			if (bret == false) {
				DEBUGEXECN(2, INFOPRINTCOLOR(GY_COLOR_RED, "Exit of process PID %d : PID not found in task table...\n", pid););
			}	
			return 0;
		}	
	}
	GY_CATCH_EXCEPTION(DEBUGEXECN(1, ERRORPRINT("Caught exception while deleting task from task map for PID %d : %s\n", pid, GY_GET_EXCEPT_STRING);); return -1;);
}	

int task_exec(pid_t pid)
{
	try {
		TASK_ELEM_TYPE	elem;
		bool			bret;

		bret = pgtaskhash->template lookup_single_elem<RCU_LOCK_SLOW>(pid, get_pid_hash(pid), elem);

		if (bret == true) {

			auto			ptask = elem.get_data()->get();
			
			if (ptask) {
				ptask->set_task_exec(gprocfd);
			}
			else {
				bret = false;
			}	
		}	

		if (bret == false) {
			DEBUGEXECN(2, INFOPRINTCOLOR(GY_COLOR_RED, "Exec of process PID %d : PID not found in task table...\n", pid););
		}	

		return 0;
	}
	GY_CATCH_EXCEPTION(DEBUGEXECN(1, ERRORPRINT("Caught exception for task exec handling for PID %d : %s\n", pid, GY_GET_EXCEPT_STRING);); return -1;);
}	

int task_uid_gid_change(pid_t pid, uid_t realid, uid_t effid, bool is_uid)
{
	try {
		TASK_ELEM_TYPE	elem;
		bool			bret;
		std::pair<uid_t, bool>	uidpair {realid, is_uid};
		
		auto 			lambda_uid_task = [](TASK_ELEM_TYPE *pdatanode, void *arg1, void *arg2) noexcept -> CB_RET_E
		{
			auto			ptask = pdatanode->get_data()->get();

			std::pair<uid_t, bool>	*puidpair = decltype(puidpair)(arg1);
			uid_t			*peffid = (uid_t *)arg2;

			if (ptask == nullptr) {
				return CB_OK;
			}

			if (puidpair->second) {
				ptask->set_task_uid_change(*peffid);
			}
			else {
				ptask->set_task_gid_change(*peffid);
			}	

			return CB_OK;
		};	

		bret = pgtaskhash->template lookup_single_elem<decltype(lambda_uid_task), RCU_LOCK_SLOW>(pid, get_pid_hash(pid), lambda_uid_task, &uidpair, &effid);

		return 0;

	}
	GY_CATCH_EXCEPTION(DEBUGEXECN(1, ERRORPRINT("Caught exception for task uid / gid change handling for PID %d : %s\n", pid, GY_GET_EXCEPT_STRING);); return -1;);

	return 0;
}	


int task_sid_change(pid_t pid)
{
	try {
		TASK_ELEM_TYPE	elem;
		bool			bret;

		auto 			lambda_sid_task = [](TASK_ELEM_TYPE *pdatanode, void *arg1, void *arg2) noexcept -> CB_RET_E
		{
			auto			ptask = pdatanode->get_data()->get();

			if (ptask == nullptr) {
				return CB_OK;
			}

			ptask->set_task_sid_change();		

			return CB_OK;
		};	

		bret = pgtaskhash->template lookup_single_elem<decltype(lambda_sid_task), RCU_LOCK_SLOW>(pid, get_pid_hash(pid), lambda_sid_task, nullptr, nullptr);

		return 0;

	}
	GY_CATCH_EXCEPTION(DEBUGEXECN(1, ERRORPRINT("Caught exception for task sid change handling for PID %d : %s\n", pid, GY_GET_EXCEPT_STRING);); return -1;);

	return 0;
}

#if 0
int task_comm_change(pid_t pid, char *comm)
{
	try {
		TASK_ELEM_TYPE	elem;
		bool			bret;

		auto 			lambda_comm_task = [](TASK_ELEM_TYPE *pdatanode, void *arg1, void *arg2) noexcept -> CB_RET_E
		{
			auto			ptask = pdatanode->get_data()->get();
			char			*comm = (char *)arg1;

			if (ptask == nullptr) {
				return CB_OK;
			}

			ptask->set_task_comm_change(comm);

			return CB_OK;
		};	

		bret = pgtaskhash->template lookup_single_elem<decltype(lambda_comm_task), RCU_LOCK_SLOW>(pid, get_pid_hash(pid), lambda_comm_task, comm, nullptr);

		return 0;

	}
	GY_CATCH_EXCEPTION(DEBUGEXECN(1, ERRORPRINT("Caught exception for task comm change handling for PID %d : %s\n", pid, GY_GET_EXCEPT_STRING);); return -1;);

	return 0;
}	
#endif

int sockconn_send(int nl_sock)
{
	struct sockaddr_nl 		addr;
	int				ret;
	
	std::memset(&addr, 0, sizeof(addr));

	addr.nl_pid = getpid();
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = CN_IDX_PROC;

	if (bind(nl_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		PERRORPRINT("Failed to bind nl connector socket");
		return -1;
	}

	enum proc_cn_mcast_op 		op;
	struct nlmsghdr 		nlmsghdr;
	struct cn_msg 			cn_msg;
	struct iovec 			iov[3];

	std::memset(&nlmsghdr, 0, sizeof(nlmsghdr));

	nlmsghdr.nlmsg_len 	= NLMSG_LENGTH(sizeof(cn_msg) + sizeof(op));
	nlmsghdr.nlmsg_pid 	= getpid();
	nlmsghdr.nlmsg_type 	= NLMSG_DONE;

	iov[0].iov_base 	= &nlmsghdr;
	iov[0].iov_len 		= sizeof(nlmsghdr);

	std::memset(&cn_msg, 0, sizeof(cn_msg));

	cn_msg.id.idx 		= CN_IDX_PROC;
	cn_msg.id.val 		= CN_VAL_PROC;
	cn_msg.len 		= sizeof(enum proc_cn_mcast_op);

	iov[1].iov_base 	= &cn_msg;
	iov[1].iov_len 		= sizeof(cn_msg);

	op 			= PROC_CN_MCAST_LISTEN;

	iov[2].iov_base 	= &op;
	iov[2].iov_len 		= sizeof(op);

	ret = writev(nl_sock, iov, 3);
	if (ret < 0) {
		PERRORPRINT("Could not send nl connector listen command");
		return -1;
	}	

	return 0;
}

int parse_conn_msg(GY_PROC_EVENT *proc_ev)
{
	int			ret;

	switch (proc_ev->what) {
		case PROC_EVENT_NONE:
			break;

		case PROC_EVENT_FORK :
			if (proc_ev->event_data.fork.child_pid != proc_ev->event_data.fork.child_tgid) {
				// Thread spawn
				break;
			}	
			
			ret = task_add(proc_ev->event_data.fork.child_tgid, proc_ev->event_data.fork.parent_tgid);			

			break;

		case PROC_EVENT_EXEC :
			ret = task_exec(proc_ev->event_data.exec.process_tgid);			

			break;

		case PROC_EVENT_UID:

			ret = task_uid_gid_change(proc_ev->event_data.id.process_tgid, proc_ev->event_data.id.r.ruid, proc_ev->event_data.id.e.euid, true);
			break;

		case PROC_EVENT_GID:

			ret = task_uid_gid_change(proc_ev->event_data.id.process_tgid, proc_ev->event_data.id.r.ruid, proc_ev->event_data.id.e.euid, false);
			break;

		case PROC_EVENT_EXIT:

			if (proc_ev->event_data.exit.process_pid != proc_ev->event_data.exit.process_tgid) {
				// Thread exit
				break;
			}	

			ret = task_exit(proc_ev->event_data.exit.process_tgid, proc_ev->event_data.exit.exit_code);
			break;

		case PROC_EVENT_COMM:

			if (proc_ev->event_data.comm.process_pid == proc_ev->event_data.comm.process_tgid) {
				/*ret = task_comm_change(proc_ev->event_data.comm.process_tgid, proc_ev->event_data.comm.comm);*/
			}
			break;
		
		case PROC_EVENT_COREDUMP:
			break;
			
		case PROC_EVENT_PTRACE:
			break;

		case PROC_EVENT_SID:
			ret = task_sid_change(proc_ev->event_data.sid.process_tgid);

			break;

		default:
			DEBUGEXECN(1, INFOPRINT("unhandled proc event 0x%08x\n", proc_ev->what););
			break;
	}

	return 0;
}	

int nltask_thread(void *arg)
{
	static constexpr int		GY_NL_BUFFER_SIZE = 16 * 1024;
	int 				nl_sock = 0, numbytes = 0, rtalen = 0, inet_ret = -1, ret;
	struct nlmsghdr 		*nlh;
	uint8_t 			*pbuf = nullptr;
	struct inet_diag_msg 		*pdiag_msg;
	struct pollfd 			pfds[1] = {};
	struct sockaddr_nl 		addr;

	pbuf = new (std::nothrow) uint8_t[GY_NL_BUFFER_SIZE];
	if (!pbuf) {
		PERRORPRINT("Failed to allocate memory for task nl handler");
		return -1;
	}	

	GY_SCOPE_EXIT { delete [] pbuf; };

	struct iovec iov = {
		.iov_base	= pbuf,
		.iov_len	= GY_NL_BUFFER_SIZE,
	};

	struct msghdr msg = {
		.msg_name	= &addr,
		.msg_namelen	= sizeof(struct sockaddr_nl),
		.msg_iov	= &iov,
		.msg_iovlen	= 1,
		.msg_control	= nullptr,
		.msg_controllen	= 0,
		.msg_flags	= 0,
	};

	if ((nl_sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR)) == -1) {
		PERRORPRINT("netlink connector socket failed");
		return -1;
	}

	GY_SCOPE_EXIT {
		close(nl_sock);
	};	

	if (sockconn_send(nl_sock) < 0) {
		return -1;
	}

	pfds[0].fd 	= nl_sock;
	pfds[0].events 	= POLLIN | POLLRDHUP;
	pfds[0].revents = 0;

	try {

		while (0 == gsig_rcvd.load(std::memory_order_relaxed)) {
			int			msglen = 0;
			struct nlmsghdr 	*h;
			bool			found_done = false, dump_intr = false;
			struct cn_msg 		*cn_msg;
			GY_PROC_EVENT 	*proc_ev;

			ret = poll(pfds, 1, 1000);
			if (ret < 0) {
				if (errno == EINTR) {
					continue;
				}
				PERRORPRINT("poll for nl socket recv failed");
				return -1;
			}
			else if (ret == 0) {
				continue;
			}

			ret = recvmsg(nl_sock, &msg, 0);
			if (ret == -1) {
				if (errno == EINTR || errno == EAGAIN) {
					if (gsig_rcvd.load()) {
						break;
					}	
					continue;
				}	

				PERRORPRINT("recv of nl socket connector failed");
				return -1;
			}	
			else if (ret == 0) {
				break;
			}	

			if (msg.msg_namelen != sizeof(struct sockaddr_nl)) {
				errno = EINVAL;
				PERRORPRINT("recv of nl socket connector failed due to invalid data len");
				break;
			}

			h = (struct nlmsghdr *)pbuf;

			msglen = ret;

			while (NLMSG_OK(h, (unsigned)msglen)) {
				if (h->nlmsg_flags & NLM_F_DUMP_INTR) {
					dump_intr = true;
				}	

				if (h->nlmsg_type == NLMSG_ERROR || h->nlmsg_type == NLMSG_NOOP) {
					continue;
				}

				cn_msg = decltype(cn_msg) (NLMSG_DATA(h));

				if ((cn_msg->id.idx != CN_IDX_PROC) || (cn_msg->id.val != CN_VAL_PROC)) {
					continue;
				}	

				proc_ev = (GY_PROC_EVENT *)cn_msg->data;

				parse_conn_msg(proc_ev);

				h = NLMSG_NEXT(h, msglen);
			}

			if (msg.msg_flags & MSG_TRUNC) {
				continue;
			}
			if (msglen) {
				ERRORPRINT("nl connector messgae still remains of size %d\n", msglen);
				return -1;
			}
		}	
		
		inet_ret = 0;
		
	}
	GY_CATCH_EXCEPTION(ERRORPRINT("Exception caught while query nl connector info : %s\n", GY_GET_EXCEPT_STRING));

	return inet_ret;
}

MAKE_PTHREAD_FUNC_WRAPPER(nltask_thread);

void *debug_thread(void *arg)
{
	PROC_CPU_IO_STATS		procstats(getpid(), getpid(), true);

	while (0 == gsig_rcvd.load()) {

		gy_nanosleep(60, 0);

		procstats.get_current_stats(true);

		INFOPRINTCOLOR(GY_COLOR_YELLOW_UNDERLINE, "Current Number of tasks in task map is %lu\n", pgtaskhash->count_slow());
	}

	return nullptr;
}
MAKE_PTHREAD_FUNC_WRAPPER(debug_thread);

int init_task_list()
{
	try {
		/*
		 * Scan all current tasks in system 
		 */
		DIR				*pdir = nullptr; 
		struct dirent			*pdent;
		char				*pfile, path[256], *pstr1;
		int				ret;
		uint64_t			ulval;
		pid_t				pidval;

		pdir = opendir("/proc");
		if (!pdir) {
			PERRORPRINT("Could not open proc filesystem");
			return -1;
		}

		GY_SCOPE_EXIT {
			closedir(pdir);
		};

		while ((pdent = readdir(pdir)) != nullptr) {

			pstr1 = nullptr;
			
			pfile = pdent->d_name;	
			
			if (!gy_isdigit_ascii(*pfile)) {
				continue;
			}

			ulval = strtoul(pfile, &pstr1, 10);
			if ((ulval > 0) && (ulval < ULONG_MAX)) {
				if (pstr1 && *pstr1) {
					continue;
				}	

				pidval = (pid_t)ulval;
				ret = task_add(pidval, 0, true);
			}	
			else {
				continue;
			}	
		}

		INFOPRINTCOLOR(GY_COLOR_BOLD_GREEN, "Populated task map : Total Count = %lu\n", pgtaskhash->count_slow());

	 	return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT("Caught Exception while getting list of tasks : %s\n", GY_GET_EXCEPT_STRING);
		return -1;
	);
}	

} // namespace	

int handle_signal(int signo)
{
	alarm(5);

	gsig_rcvd.store(signo);

	return signo;
}	


int main(int argc, char **argv)
{
	GY_SIGNAL_HANDLER::init_singleton(argv[0], handle_signal, false);

	gy_get_thread_local().set_name("main thread");

	if (argc > 1) {
		gdebugexecn = atoi(argv[1]);
	}	
	else {
		gdebugexecn = 1;
	}	

	int					ret;
	pthread_t 				dbgtid, nltid;
	
	gy_create_thread(&dbgtid, GET_PTHREAD_WRAPPER(debug_thread), nullptr);

	try {
		ASYNC_FUNC_HDLR::init_singleton();
		MOUNT_HDLR::init_singleton();
		CGROUP_HANDLE::init_singleton();

		gprocfd = MOUNT_HDLR::get_singleton()->get_proc_dir_fd();
		if (gprocfd < 0) {
			ERRORPRINT("Could not get /proc dirfd\n");
			return -1;
		}	

		pgtaskhash = new TASK_HASH_TABLE(1);
		
		ret = init_task_list();
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT("Exception caught while handling task hash table : %s\n", GY_GET_EXCEPT_STRING);
		return -1;
	);

	GY_SCOPE_EXIT {
		delete pgtaskhash;
	};	

	gy_create_thread(&nltid, GET_PTHREAD_WRAPPER(nltask_thread), nullptr);

	pthread_join(nltid, nullptr);

	handle_signal(SIGINT);
/* 	pthread_cancel(dbgtid); */
	pthread_join(dbgtid, nullptr);

	INFOPRINTCOLOR(GY_COLOR_BOLD_GREEN, "All threads exited. Waiting for RCU free calls to complete...\n");

	wait_for_all_call_rcu_free();

	return 0;
}	



