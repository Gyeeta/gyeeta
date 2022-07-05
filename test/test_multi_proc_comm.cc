
#include		"gy_multi_proc_comm.h"
#include 		"gy_child_proc.h"
#include		"gy_print_offload.h"
#include		"gy_pkt_pool.h"
#include		"gy_scheduler.h"

using namespace gyeeta;

CHILD_PROC		*pgchild;

static constexpr size_t	TMAX_ELEM = 512;
using TMULTI_COMM	= MULTI_PROC_COMM_HDLR<true, TMAX_ELEM, 4096>;

TMULTI_COMM		*pgmultihdlr;
GY_PKT_POOL		*pgprocpool;

static constexpr size_t	MAX_OPT_SZ = 512;

struct TEST_ELEM
{
	uint64_t		tclocknsec_;
	uint64_t		tclockresp_;
	size_t			id_;
	pid_t			tid_;
	bool			use_delay_;
};	

void * reader_thread(void * arg)
{
	GY_THREAD			*pthread = (GY_THREAD *)arg;
	GY_PKT_POOL			*pfuncpool = (GY_PKT_POOL *)pthread->get_opt_arg1();
	alignas (8) uint8_t		comm[sizeof(COMM_MSG_C) + MAX_OPT_SZ];
	COMM_MSG_C			*pcomm;
	TMULTI_COMM::MULTI_PROC_ELEM	*pelem;
	PKT_RET_E 			retp;
	uint32_t			count;
	int				ret;

	do {
		retp = pfuncpool->pool_read_buffer(comm, sizeof(comm), &count, 0 /* is_non_block */);

		if (retp != PKT_RET_SUCCESS) {
			INFOPRINT("Reader Thread exiting as writer seems to have exited.\n");
			break;
		}

		if (count < sizeof(COMM_MSG_C)) {
			ERRORPRINT("Internal Error (%u) : Invalid number of bytes %u from pool read\n", __LINE__, count); 
			continue;
		}

		pcomm = reinterpret_cast<COMM_MSG_C *>(comm);

		pcomm->exec_func(comm + sizeof(COMM_MSG_C));

	} while (1);

	return nullptr;
}	
MAKE_PTHREAD_FUNC_WRAPPER(reader_thread);

int init_child()
{
	PRINT_OFFLOAD::init_singleton();

	GY_SCHEDULER::cancel_rcu_schedules();

	alignas(128) GY_PKT_POOL	funcpool(64, sizeof(COMM_MSG_C) + MAX_OPT_SZ, 0, 0, 0, 1, "Socket handler pool");
	GY_THREAD			readertid("Socket pool reader thread", GET_PTHREAD_WRAPPER(reader_thread), &readertid, &funcpool);
	GY_THREAD			pooltid("Shared Pool reader thread", GET_PTHREAD_WRAPPER(reader_thread), &pooltid, pgprocpool);

	auto poolstop = [](void *arg)
	{
		GY_PKT_POOL		*pfpool = (GY_PKT_POOL *)arg;

		if (pfpool) {
			pfpool->pool_set_wr_exited();
		}	
	};

	readertid.set_thread_stop_function(poolstop, &funcpool);
	pooltid.set_thread_stop_function(poolstop, pgprocpool);

	const int			sock = pgchild->get_socket();

	while (true) {
		COMM_MSG_C		msg;
		uint8_t			tbuf[MAX_OPT_SZ];
		struct iovec		iov[2];
		int			ret;
		uint32_t		count;

		ret = COMM_MSG_C::recv_msg(sock, msg, tbuf, sizeof(tbuf), false /* exec_func */, false /* is_nonblock */); 
		if (ret == -1) {
			if (false == is_socket_still_connected(sock)) {
				INFOPRINTCOLOR(GY_COLOR_GREEN, "Test child process %d : Parent process %d seems to be exited. Exiting...\n",
					getpid(), pgchild->ppid_);
				CONDEXEC(
					funcpool.print_cumul_stats(1);
				);	
				_exit(0);
			}
		}
		else if (ret != 0) {
			continue;
		}	

		iov[0].iov_base 	= &msg;
		iov[0].iov_len		= sizeof(msg);

		iov[1].iov_base 	= tbuf;
		iov[1].iov_len		= msg.opt_bufsize_;

		funcpool.pool_write_buffer(iov, 2, &count, 0);
	}	

	return 1;
}	



void * send_commands(void *arg)
{
	size_t				startn, enditer;

	GY_PKT_POOL			*pshrpool = (GY_PKT_POOL *)arg;
	if ((intptr_t)arg > 1) {
		arg = nullptr;
		startn = 1;
		enditer = 10;
		INFOPRINTCOLOR(GY_COLOR_YELLOW, "Sending a bunch of commands using a shared memory pool only...\n");
	}	
	else {
		pshrpool = pgprocpool;
		startn = 0;
		enditer = 1000;
		INFOPRINTCOLOR(GY_COLOR_YELLOW, "Sending a bunch of commands with first using a socket and next using a shared memory pool...\n");
	}	
	const bool			use_delay = !!(uint64_t *)arg;
	COMM_MSG_C			msg, msg2;
	constexpr size_t		max_data_len = TMULTI_COMM::get_max_data_len();
	uint8_t				tbuf[512]; 
	alignas(8) uint8_t		resbuf[max_data_len];
	size_t				reslen;
	int				ret, respcode;
	bool				bret;
	TMULTI_COMM::MULTI_PROC_ELEM	*parrelem[TMAX_ELEM/4];

	
	for (size_t ntype = startn; ntype < 2; ++ntype) {

		min_max_counter<false>		tcounter;
		uint64_t			totalres, minres, maxres, iterval;
		double				avgres;

		if (ntype == 0) {
			INFOPRINTCOLOR(GY_COLOR_YELLOW, "First testing with socket communication...\n");
		}
		else {
			INFOPRINTCOLOR(GY_COLOR_YELLOW, "Now testing with pool communication...\n");
		}	

		for (size_t niter = 0; niter < enditer; ++niter) {
			for (size_t i = 0; i < GY_ARRAY_SIZE(parrelem); ++i) {

				COMM_MSG_C			tmsg;
				TEST_ELEM			*pdata;

				parrelem[i] = pgmultihdlr->get_proc_buf(false, 10000, 10);

				assert(parrelem[i]);

				pdata = (TEST_ELEM *)parrelem[i]->get_data_buf();

				pdata->tclocknsec_ 	= get_nsec_clock();
				pdata->tclockresp_ 	= 0;
				pdata->id_		= i;
				pdata->tid_		= gy_gettid();
				pdata->use_delay_	= use_delay;

				tmsg.arg1_ = (uint64_t)(uintptr_t)parrelem[i];
				tmsg.arg2_ = (uint64_t)(uintptr_t)pgmultihdlr;
				
				tmsg.func_ = [](uint64_t arg1, uint64_t arg2, uint64_t arg3, const uint8_t *poptbuf, size_t opt_bufsize)
				{
					TMULTI_COMM::MULTI_PROC_ELEM	*pelem;
					TMULTI_COMM			*phdlr;
					TEST_ELEM			*pdata;
					size_t				szmax;

					pelem = decltype(pelem)((uintptr_t)arg1);
					phdlr = decltype(phdlr)((uintptr_t)arg2);

					assert(pelem && phdlr);
					
					pdata = (TEST_ELEM *)pelem->get_data_buf();
					pdata->tclockresp_ = get_nsec_clock();
					
					if (pdata->use_delay_) {
						gy_msecsleep(1);
					}		

					pelem->signal_completion(0, sizeof(*pdata));

					return 0;
				};	

				if (ntype == 0) {
					ret = COMM_MSG_C::send_msg_locked(pgchild->get_socket(), pgchild->get_mutex(), tmsg, nullptr, false /* is_nonblock */); 
					assert (ret == 0);
				}
				else {
					struct iovec		iov[1] = {{&tmsg, sizeof(tmsg)}};
					uint32_t		count;	
					PKT_RET_E		retp;

					retp = pshrpool->pool_write_buffer(iov, 1, &count, false /* is_nonblock */); 
					assert (retp == PKT_RET_SUCCESS);
				}	
			}	

			for (size_t i = 0; i < GY_ARRAY_SIZE(parrelem); ++i) {

				if (niter < 10) {
					do {
						bret = parrelem[i]->dispatch_poll(resbuf, reslen, respcode);
						if (bret == false) {
							gy_nanosleep(0, GY_NSEC_PER_MSEC);
						}
					} while (bret == false);
				}
				else if (niter < 40) {
					bret = parrelem[i]->dispatch_timed_wait(5000, resbuf, reslen, respcode);
					assert(bret == true);
				}	
				else {
					parrelem[i]->dispatch_wait(resbuf, reslen, respcode);
				}	

				assert(reslen == sizeof(TEST_ELEM) && (respcode == 0));

				TEST_ELEM	*pdata;

				pdata = (TEST_ELEM *)resbuf;

				assert(pdata->tclockresp_ >= pdata->tclocknsec_);
				assert(pdata->id_ == i);
				assert(pdata->tid_ == gy_gettid());

				tcounter.add(pdata->tclockresp_ - pdata->tclocknsec_);
			}
		}

		tcounter.get_current(totalres, minres, maxres, iterval, avgres);

		INFOPRINTCOLOR(GY_COLOR_YELLOW, "%lu Iterations of %s completed : Min Response %lu nsec (%lu usec) Max %lu nsec (%lu usec) Avg %.3f nsec (%.3f usec)...\n", 
			iterval, ntype == 0 ? "socket communication" : "pool communication", minres, minres/1000, maxres, maxres/1000, avgres, avgres/1000);
	}

	return nullptr;
}	
MAKE_PTHREAD_FUNC_WRAPPER(send_commands);


int send_init()
{
	COMM_MSG_C			msg, msg2;
	constexpr size_t		max_data_len = TMULTI_COMM::get_max_data_len();
	uint8_t				tbuf[512]; 
	alignas(8) uint8_t		resbuf[max_data_len];
	size_t				reslen;
	int				ret, respcode;
	bool				bret;
	TMULTI_COMM::MULTI_PROC_ELEM	*pelem;

	gy_nanosleep(0, 100 * GY_NSEC_PER_MSEC);

	pelem = pgmultihdlr->get_proc_buf();

	assert(pelem);

	msg.arg1_ = (uint64_t)(uintptr_t)pelem;
	msg.arg2_ = (uint64_t)(uintptr_t)pgmultihdlr;
	
	msg.opt_bufsize_ = 1 + GY_SAFE_SNPRINTF((char *)tbuf, sizeof(tbuf), "----- Hi This is a test message---------");

	msg.func_ = [](uint64_t arg1, uint64_t arg2, uint64_t arg3, const uint8_t *poptbuf, size_t opt_bufsize)
	{
		INFOPRINTCOLOR(GY_COLOR_GREEN, "Testing function dispatch from within child PID %d...\n", getpid());
		
		TMULTI_COMM::MULTI_PROC_ELEM	*pelem;
		TMULTI_COMM			*phdlr;
		char				*pdata;
		size_t				szmax;

		pelem = decltype(pelem)((uintptr_t)arg1);
		phdlr = decltype(phdlr)((uintptr_t)arg2);

		assert(pelem && phdlr);
		
		pdata = (char *)pelem->get_data_buf();
		szmax = pelem->get_max_data_len();

		STR_WR_BUF			strbuf(pdata, szmax);

		auto vm = gy_get_proc_vmsize(getpid());

		strbuf.appendfmt("Current Child PID %d VM Size = %lu (%lu MB) : ", getpid(), vm, GY_DOWN_MB(vm));

		strbuf.appendfmt("String Data sent from parent is \'%s\' of length %lu\n\n", poptbuf, opt_bufsize);

		pelem->signal_completion(0, strbuf.length() + 1);

		return 0;
	};	

	ret = COMM_MSG_C::send_msg_locked(pgchild->get_socket(), pgchild->get_mutex(), msg, tbuf, false /* is_nonblock */); 
	assert (ret == 0);
	
	// Now wait for response
	pelem->dispatch_wait(resbuf, reslen, respcode);

	INFOPRINTCOLOR(GY_COLOR_CYAN, "Received response from child process of len %lu : %s\n", reslen, resbuf);

	pelem = pgmultihdlr->get_proc_buf();

	assert(pelem);

	msg2.arg1_ = (uint64_t)(uintptr_t)pelem;
	msg2.arg2_ = (uint64_t)(uintptr_t)pgmultihdlr;

	msg2.opt_bufsize_ = 0;

	msg2.func_ = [](uint64_t arg1, uint64_t arg2, uint64_t arg3, const uint8_t *poptbuf, size_t opt_bufsize)
	{
		INFOPRINTCOLOR(GY_COLOR_GREEN, "Testing grandchild response updation from child PID %d...\n", getpid());
		
		pid_t chpid = fork();

		if (chpid == 0) {
			gy_nanosleep(2, 0);

			TMULTI_COMM::MULTI_PROC_ELEM	*pelem;
			TMULTI_COMM			*phdlr;
			char				*pdata;
			size_t				szmax;

			pelem = decltype(pelem)((uintptr_t)arg1);
			phdlr = decltype(phdlr)((uintptr_t)arg2);

			assert(pelem && phdlr);
			
			pdata = (char *)pelem->get_data_buf();
			szmax = pelem->get_max_data_len();

			STR_WR_BUF			strbuf(pdata, szmax);

			auto vm = gy_get_proc_vmsize(getpid());

			strbuf.appendfmt("Current Grand Child PID %d VM Size = %lu (%lu MB)\n", getpid(), vm, GY_DOWN_MB(vm));

			pelem->signal_completion(0, strbuf.length() + 1);

			_exit(0);
		}
		else {
			wait(nullptr);
			INFOPRINTCOLOR(GY_COLOR_GREEN, "Testing grand child process exited..\n");
		}	

		return 0;
	};

	ret = COMM_MSG_C::send_msg_locked(pgchild->get_socket(), pgchild->get_mutex(), msg2, nullptr, false /* is_nonblock */); 
	assert (ret == 0);
	
	// Now wait for response
	bret = pelem->dispatch_timed_wait(50000, resbuf, reslen, respcode);
	assert(bret == true);

	INFOPRINTCOLOR(GY_COLOR_CYAN, "Received response from grandchild process of len %lu : %s\n", reslen, resbuf);

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Now testing sending a large number of requests single producer single consumer...\n");

	{
		GY_PKT_POOL		spsc(TMAX_ELEM, sizeof(COMM_MSG_C), 0, 0, 0, 1 /* is_single_writer */, "spsc queue");
		GY_THREAD		pooltid("Shared SPSC Pool reader thread", GET_PTHREAD_WRAPPER(reader_thread), &pooltid, &spsc);

		pooltid.set_thread_stop_function(
			[](void *arg) 
			{
				GY_PKT_POOL	*pspsc = (GY_PKT_POOL *)arg;

				pspsc->pool_set_wr_exited();
			}, &spsc);

		send_commands(&spsc);
	}

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Now testing sending a large number of requests with sleeping reads...The Response Times will be at least 1 msec...\n");

	send_commands((void *)1);

	return 0;
}
int spawn_child()
{
	try {
		GY_SIGNAL_HANDLER::init_singleton();

		pgmultihdlr = TMULTI_COMM::allocate_handler();

		GY_SCOPE_EXIT {
			TMULTI_COMM::deallocate_handler(pgmultihdlr);
		};	

		CHILD_PROC		childproc(true /* use_parent_log_files */, nullptr, nullptr, true /* exit_on_parent_kill */, true /* use_socket_pair */, 
						true /* use_shared_pool */, 128, sizeof(COMM_MSG_C), [](int signo) { return 0;}, true /* signal_callback_will_exit */);

		INFOPRINTCOLOR(GY_COLOR_LIGHT_BLUE, "Spawning the child process for testing...\n"); 

		pid_t childpid = childproc.fork_child("test_child", false /* set_thr_name */, "Test Child", O_APPEND, 3, 1024); 

		pgchild 	= &childproc;
		pgprocpool 	= childproc.get_shared_pool();

		if (childpid == 0) {
			// Within child
			try {
				init_child();
			}
			GY_CATCH_EXCEPTION(
				ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Exception caught in child process handling : %s : Exiting...\n",
					GY_GET_EXCEPT_STRING);

			);

			_exit(0);
		}	
		else {
			try {
				INFOPRINT("Spawned child process. Now sending commands...\n\n\n");

				PRINT_OFFLOAD::init_singleton();

				send_init();

				GY_THREAD		wrtid1("Socket pool writer thread 1", GET_PTHREAD_WRAPPER(send_commands), nullptr);
				GY_THREAD		wrtid2("Socket pool writer thread 2", GET_PTHREAD_WRAPPER(send_commands), nullptr);
				GY_THREAD		wrtid3("Socket pool writer thread 3", GET_PTHREAD_WRAPPER(send_commands), nullptr);

				wrtid1.wait_for_thread_join();
				wrtid2.wait_for_thread_join();
				wrtid3.wait_for_thread_join();

				INFOPRINTCOLOR(GY_COLOR_CYAN, "Now exiting...\n");
			}
			GY_CATCH_EXCEPTION(
				ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Exception caught while sending commands : %s : Exiting...\n",
					GY_GET_EXCEPT_STRING);

			);
		}	

		return 0;
	}
	GY_CATCH_EXCEPTION(ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Exception caught : %s : Exiting...\n", GY_GET_EXCEPT_STRING););

	return -1;
}

int main()
{
	gdebugexecn	= 10;

	return spawn_child();
}	

