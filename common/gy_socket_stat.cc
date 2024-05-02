//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_server_int.h"
#include			"gy_socket_stat.h"
#include			"gy_file_api.h"
#include			"gy_print_offload.h"
#include			"gy_misc.h"
#include			"gy_task_handler.h"
#include			"gy_dns_mapping.h"
#include			"gy_scheduler.h"
#include			"gy_ebpf.h"
#include			"gy_sys_stat.h"
#include			"gy_epoll_conntrack.h"
#include			"gy_netif.h"
#include			"gy_task_types.h"
#include			"gy_ssl_cap_common.h"

#include 			<dirent.h>
#include 			<poll.h>

#include			"libmnl/libmnl.h"
#include 			"linux/netfilter/nfnetlink.h"
#include 			"linux/netfilter/nfnetlink_conntrack.h"

#include			<utility>
#include			<algorithm>

#include			<arpa/inet.h>

#include 			<linux/netlink.h>
#include 			<linux/rtnetlink.h>
#include 			<netinet/in.h>
#include 			<linux/sock_diag.h>
#include 			<linux/inet_diag.h>
#include 			<pwd.h>

namespace gyeeta {

using namespace gyeeta::comm;	

TCP_SOCK_HANDLER::TCP_SOCK_HANDLER(uint8_t resp_sampling_percent, bool capture_errcode, bool disable_api_capture, uint32_t api_max_len) : 
	ptask_handler_( 
		({	
			if (nullptr == SYSTEM_STATS::get_singleton()) {
				GY_THROW_EXCEPTION("System Stats singleton not yet initialized");
			}

			TASK_HANDLER::init_singleton(true); 
			if (nullptr == TASK_HANDLER::get_singleton()) GY_THROW_EXCEPTION("Task Handler singleton not available"); 

			auto schedshr = GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_LONG2_DURATION);
			auto schedshrmain = GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_MAINTENANCE);

			if (!schedshr || !schedshrmain || !TASK_HANDLER::get_task_prio_scheduler()) {
				GY_THROW_EXCEPTION("Global Scheduler Shared objects not yet initialized");
			}	
			
			TASK_HANDLER::get_singleton();	
		})
	),
	pdns_mapping_(
		({
			DNS_MAPPING::init_singleton();
			if (nullptr == DNS_MAPPING::get_singleton()) GY_THROW_EXCEPTION("DNS Mapping singleton not available"); 
			DNS_MAPPING::get_singleton();	
		})	
	),		
	machineid_(
		({
			if (nullptr == SYS_HARDWARE::get_singleton()) GY_THROW_EXCEPTION("SYS_HARDWARE singleton not available");
			if (nullptr == SERVER_COMM::get_singleton()) GY_THROW_EXCEPTION("SERVER_COMM singleton not available");

			SYS_HARDWARE::get_singleton()->get_machineid();
		})	
	),
	nat_tbl_(128), nat_cache_tbl_(128),
	nat_thr_("NAT Conntrack Thread", TCP_SOCK_HANDLER::GET_PTHREAD_WRAPPER(nat_conntrack_thread), this, nullptr, nullptr, true, 512 * 1024, 2000, true, true, true, 10000, false),
	conn_v4_cache_(comm::TCP_CONN_NOTIFY::get_max_elem_size(), 256, 16, 64, sizeof(comm::COMM_HEADER) + sizeof(comm::EVENT_NOTIFY), false), 
	tcp_tbl_(128), 
	conn_v6_cache_(comm::TCP_CONN_NOTIFY::get_max_elem_size(), 128, 16, 64, sizeof(comm::COMM_HEADER) + sizeof(comm::EVENT_NOTIFY), false), 
	listener_tbl_(128), 
	listen_cache_(comm::NEW_LISTENER::get_max_elem_size(), 128, 8, 64, sizeof(comm::COMM_HEADER) + sizeof(comm::EVENT_NOTIFY), false),
	topnxput_(TCP_MAX_TOP_N),
	diag_cache_(comm::TCP_CONN_NOTIFY::get_max_elem_size(), 4096, 256, comm::TCP_CONN_NOTIFY::MAX_NUM_CONNS, sizeof(comm::COMM_HEADER) + sizeof(comm::EVENT_NOTIFY), false), 
	netns_tbl_(128),
	inet_diag_thr_("Inet Diag Thread", TCP_SOCK_HANDLER::GET_PTHREAD_WRAPPER(inet_diag_thread), this, nullptr, nullptr, true, 1024 * 1024, 2000, true, true, true, 10000, false),
	capture_errcode_(capture_errcode), disable_api_capture_(disable_api_capture), api_max_len_(api_max_len),
	missed_cache_(comm::TCP_CONN_NOTIFY::get_max_elem_size(), 128, 16, 64, sizeof(comm::COMM_HEADER) + sizeof(comm::EVENT_NOTIFY), false), 
	pebpf_(
		({
			diag_cache_.set_alloc_thrid(inet_diag_thr_.get_tid());
			std::make_unique <GY_EBPF> (this, ptask_handler_, resp_sampling_percent);
		})	
	)	
{
	tcp_v4_perf_tid_ 	= pebpf_->get_perf_tid(PROBE_TCP_CONN_IPv4);
	tcp_v6_perf_tid_ 	= pebpf_->get_perf_tid(PROBE_TCP_CONN_IPv6);

	listen_perf_tid_ 	= pebpf_->get_perf_tid(PROBE_TCP_LISTENER);
	resp_v4_perf_tid_	= pebpf_->get_perf_tid(PROBE_TCP_RESPONSE_IPv4);
	resp_v6_perf_tid_	= pebpf_->get_perf_tid(PROBE_TCP_RESPONSE_IPv6);

	listen_cache_.set_alloc_thrid(listen_perf_tid_);

	conn_v4_pool_.set_alloc_thrid(tcp_v4_perf_tid_);
	conn_v4_elem_pool_.set_alloc_thrid(tcp_v4_perf_tid_);

	conn_v6_pool_.set_alloc_thrid(tcp_v6_perf_tid_);
	conn_v6_elem_pool_.set_alloc_thrid(tcp_v6_perf_tid_);

	conn_v4_cache_.set_alloc_thrid(tcp_v4_perf_tid_);
	conn_v6_cache_.set_alloc_thrid(tcp_v6_perf_tid_);

	pebpf_->get_ipvs_existing_conns();

	auto schedshrlong = GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_LONG_DURATION);
	auto schedshr = GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_LONG2_DURATION);
	auto schedshrmain = GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_MAINTENANCE);

	svcnetcap_.emplace(SYS_HARDWARE::get_root_ns_inodes()->net_inode, disable_api_capture_, api_max_len_);

	schedshr->add_schedule(1400, 1000, 0, "Check for NAT from cache", 
	[this] { 
		nat_check_cache();
	});

	/*
	 * We try to schedule NAT Collection on a 2 + 30 sec boundary to enable better co-relation with Inet Diag amongst 
	 * individual Partha's.
	 */
	time_t			tcurr = time(nullptr), tnxt = (tcurr / 30) * 30;

	schedshr->add_schedule(30'300 + 2000 + 30'000 - (tcurr - tnxt) * 1000, 30'000, 0, "Check for NAT from main NAT table", 
	[this] { 
		nat_check_conns();
	});

	schedshrlong->add_schedule(61'800, 75'000, 0, "Check for TCP conn table connections", 
	[this] { 
		missed_cache_.set_alloc_thrid(pthread_self());
		tcp_check_conns();
	});
	
	/*
	 * We try to schedule all Partha Task and Listener State Collection on a 5 sec boundary to enable better corelation amongst 
	 * individual Partha's.
	 */
	tcurr = time(nullptr);
	tnxt = (tcurr / 5) * 5;
		
	TASK_HANDLER::get_task_prio_scheduler()->add_schedule(5150 + 5000 - (tcurr - tnxt) * 1000, 5000, 0, "Task Stats and TCP Listeners Stats updation", 
	[this, next_imp_procs = bool(true), last_all_procs_tusec = get_usec_time(), ptaskhdlr = TASK_HANDLER::get_singleton()] () mutable { 

		GY_NOMT_COLLECT_PROFILE(40, "Task Stats and TCP Listeners Stats updation");

		auto					pser = SERVER_COMM::get_singleton();
		std::shared_ptr<SERVER_CONNTRACK>	sendshr;

		sendshr = pser->get_server_conn(comm::CLI_TYPE_REQ_ONLY);

		auto				psysstat = SYSTEM_STATS::get_singleton();
		GlobIDInodeMap			delidmap;
		bool				cpu_issue, mem_issue, severe_cpu_issue, severe_mem_issue, cpu_idle = false, mem_idle = false;

		psysstat->get_issue_stats(cpu_issue, mem_issue, severe_cpu_issue, severe_mem_issue, cpu_idle, mem_idle);

		/*
		 * First update the Task stats and then the Listener Stats
		 */
		auto [ntaskissue, ntasksevere, ntasks] 	= ptaskhdlr->tasks_cpu_stats_update(true /* from_scheduler */, next_imp_procs /* only_imp_procs */, last_all_procs_tusec, sendshr);

		auto [nlistissue, nlistsevere, nlisten] = listener_stats_update(sendshr, cpu_issue, mem_issue, delidmap);

		host_status_update(sendshr, cpu_issue, mem_issue, severe_cpu_issue, severe_mem_issue, cpu_idle, mem_idle, ntaskissue, ntasksevere, ntasks, nlistissue, nlistsevere, nlisten);

		if (next_imp_procs == false) {
			last_all_procs_tusec = get_usec_time();

			ptaskhdlr->send_top_tasks(sendshr);
		}

		next_imp_procs = !next_imp_procs;

		if (delidmap.size() > 0 && bool(svcnetcap_)) {
			try {
				svcnetcap_->sched_del_listeners(0, gy_to_charbuf<128>("Service Network Capture Delete Listeners %ld", time(nullptr)).get(), std::move(delidmap));
			}
			catch(...) {
			}	
		}	
	});

	tcurr = time(nullptr);
	tnxt = (tcurr / 5) * 5;

	static_assert(LISTENER_CLUSTER_NOTIFY::INODE_CLUSTER_MSEC >= 60000, "At least 60 sec needed");

	schedshrmain->add_schedule(60'000 + 3000 + 5000 - (tcurr - tnxt) * 1000, LISTENER_CLUSTER_NOTIFY::INODE_CLUSTER_MSEC /* 100'000 */, 0, 
	"Check for TCP Listener socket inode process match and Clustered Listeners", 
	[this] { 
		int			nclconfirm = 0;

		listener_inode_validate(nclconfirm);

		if (nclconfirm > 0) {
			listener_cluster_check();
		}	
	});

	tcurr = time(nullptr);
	tnxt = (tcurr / 5) * 5;

	schedshrmain->add_schedule(90'000 + 1790 - (tcurr - tnxt) * 1000, 300'000, 0, "Send Listener Task Map data", 
	[this] { 
		send_listen_taskmap();
	});

	CONDEXEC(
		DEBUGEXECN(1,
			schedshrmain->add_schedule(61'000, 100'000, 0, "Print TCP Conn Pool Stats", 
			[this] { 
				STRING_BUFFER<2048>	strbuf;

				strbuf.appendconst("TCP Connection Memory Pool Stats (IPv4 and IPv6) follow : \n\t\t");
				conn_v4_pool_.print_stats(strbuf);
				strbuf.appendconst("\n\t\t");
				conn_v4_elem_pool_.print_stats(strbuf);
				strbuf.appendconst("\n\t\t");
				conn_v6_pool_.print_stats(strbuf);
				strbuf.appendconst("\n\t\t");
				conn_v6_elem_pool_.print_stats(strbuf);
				
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "%.*s\n", strbuf.sizeint(), strbuf.buffer());
			});
		);	
	);
}

// Called from ebpf tcp_conn_ipv4_thread 
void TCP_SOCK_HANDLER::handle_ipv4_conn_event(tcp_ipv4_event_t * pevent, bool more_data) noexcept
{
	CONN_BPF_EVENT		evt(pevent);

	switch (pevent->type) {
		
	case TCP_EVENT_TYPE_CONNECT :
		handle_bpf_connect(evt, more_data, true /* from_v4_thread */, conn_v4_pool_, conn_v4_elem_pool_);
		break;
	
	case TCP_EVENT_TYPE_ACCEPT :
		handle_bpf_accept(evt, more_data, true /* from_v4_thread */, conn_v4_pool_, conn_v4_elem_pool_);
		break;	

	case TCP_EVENT_TYPE_CLOSE_CLI :
		handle_bpf_close_cli(evt, more_data, true /* from_v4_thread */);
		break;

	case TCP_EVENT_TYPE_CLOSE_SER :
		handle_bpf_close_ser(evt, more_data, true /* from_v4_thread */);
		break;

	default :
		break;		
	}	
}	

// Called from ebpf tcp_conn_ipv6_thread
void TCP_SOCK_HANDLER::handle_ipv6_conn_event(tcp_ipv6_event_t * pevent, bool more_data) noexcept
{
	CONN_BPF_EVENT		evt(pevent);

	switch (pevent->type) {
		
	case TCP_EVENT_TYPE_CONNECT :
		handle_bpf_connect(evt, more_data, false /* from_v4_thread */, conn_v6_pool_, conn_v6_elem_pool_);
		break;
	
	case TCP_EVENT_TYPE_ACCEPT :
		handle_bpf_accept(evt, more_data, false /* from_v4_thread */, conn_v6_pool_, conn_v6_elem_pool_);
		break;	

	case TCP_EVENT_TYPE_CLOSE_CLI :
		handle_bpf_close_cli(evt, more_data, false /* from_v4_thread */);
		break;

	case TCP_EVENT_TYPE_CLOSE_SER :
		handle_bpf_close_ser(evt, more_data, false /* from_v4_thread */);
		break;

	default :
		break;		
	}	
}

int TCP_SOCK_HANDLER::handle_bpf_connect(const CONN_BPF_EVENT & evt, bool more_data, bool from_v4_thread, THR_POOL_ALLOC & connpool, THR_POOL_ALLOC & connelempool) noexcept
{
	RCU_DEFER_OFFLINE		deferlock(more_data);

	try {
		IP_PORT					cli_ip_port(evt.saddr_, evt.sport_), ser_ip_port(evt.daddr_, evt.dport_);
		PAIR_IP_PORT				ctuple(cli_ip_port, ser_ip_port);
		const uint32_t				lhash = ctuple.get_hash();

		FREE_FPTR				free_fp;
		std::shared_ptr <TASK_STAT>		task_shr;
		bool					bret, conn_updated = false, is_new_cli_task = true;
		int					task_shr_upd;
		ino_t					inode = evt.netns_;
		const uint32_t				inode_hash = get_uint64_hash(inode);
		std::shared_ptr<RELATED_LISTENERS>	relatedshr;
		uint64_t				cli_task_aggr_id = 0;
		char					task_comm[TASK_COMM_LEN] {};

		bret = netns_tbl_.lookup_single_elem(inode, inode_hash);

		if (bret == false) {
			CONDEXEC(
				DEBUGEXECN(1, 
					INFOPRINT_OFFLOAD("New Network Namespace %lu seen for PID %u Thread %u from TCP Connect handler\n", inode, evt.pid_, evt.tid_);
				);
			);	
			
			try {
				NETNS_ELEM		*pnetns = new NETNS_ELEM(inode, evt.pid_, evt.tid_, false);

				netns_tbl_.insert_or_replace(pnetns, inode, inode_hash);
			}
			GY_CATCH_EXCEPTION(
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while adding new NetNS in bpf TCP Connect event : %s\n", GY_GET_EXCEPT_STRING);
				return -1;
			);
		}	

		auto newtaskcb = [&](TASK_STAT *ptask) 
		{ 
			ptask->is_tcp_client 	= true;
			is_new_cli_task		= (ptask->sent_aggr_server_.load(std::memory_order_relaxed) != 3);
			task_shr 		= ptask->shared_from_this();
			cli_task_aggr_id 	= ptask->get_set_aggr_id();
			
			std::memcpy(task_comm, ptask->task_comm, sizeof(task_comm) - 1);

			relatedshr 		= ptask->related_listen_.load(std::memory_order_acquire);
		};

		task_shr_upd = ptask_handler_->get_task(evt.pid_, newtaskcb);

		auto 	lambda_chkconn = [&](TCP_CONN_ELEM_TYPE *pdatanode, void *arg1, void *arg2) -> CB_RET_E
		{
			TCP_CONN	*ptcp = pdatanode->get_cref().get();

			if (gy_unlikely(ptcp == nullptr)) {
				return CB_OK;
			}

			conn_updated 			= true;

			ptcp->cli_ns_inode_		= inode;
			ptcp->is_tcp_connect_event_	= true;

			ptcp->is_client_local_.store(true, std::memory_order_relaxed);

			ptcp->cli_pid_			= evt.pid_;
			ptcp->cli_tid_			= evt.tid_;
			ptcp->cli_task_shr_		= std::move(task_shr);
			ptcp->cli_task_updated_.store((task_shr_upd == 0), std::memory_order_relaxed);
			ptcp->cli_task_aggr_id_		= cli_task_aggr_id;
			
			if (relatedshr) {
				ptcp->cli_related_listen_shr_	= std::move(relatedshr);
				ptcp->cli_listener_checked_	= true;
			}
			else {
				ptcp->is_new_cli_task_ 	= is_new_cli_task;
			}	
				
			if (0 == *task_comm) {	
				GY_STRNCPY(ptcp->cli_comm_, evt.comm_, sizeof(ptcp->cli_comm_));
			}
			else {
				std::memcpy(ptcp->cli_comm_, task_comm, sizeof(ptcp->cli_comm_) - 1);
				ptcp->cli_comm_[sizeof(ptcp->cli_comm_) - 1] = 0;
			}	

			CONDEXEC(
				DEBUGEXECN(11,
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "[TCP Connect event] : Existing Conn : %s : Is new Client Task %d\n", 
						ptcp->print_string(STRING_BUFFER<512>().get_str_buf(), false), ptcp->is_new_cli_task_); 
				);
			);	
			 
			return CB_OK;
		};

		bret = tcp_tbl_.lookup_single_elem(ctuple, lhash, lambda_chkconn);

		if (conn_updated) {
			return 0;
		}	

		// Add a new TCP conn
		TCP_CONN			*ptcp;
		TCP_CONN_ELEM_TYPE		*pelem;
		
		ptcp = (TCP_CONN *)connpool.safe_malloc(free_fp, true /* use_malloc_hdr */);

		try {
			new (ptcp) TCP_CONN(cli_ip_port, ser_ip_port, evt.pid_, evt.tid_, 0, 0, get_usec_clock());	
		}
		catch(...) {
			THR_POOL_ALLOC::dealloc(ptcp);
			return -1;
		}	
		
		ptcp->cli_ns_inode_		= inode;
		ptcp->cli_task_shr_		= std::move(task_shr);
		ptcp->cli_task_updated_.store((task_shr_upd == 0), std::memory_order_relaxed);
		ptcp->cli_task_aggr_id_		= cli_task_aggr_id;
		ptcp->is_tcp_connect_event_	= true;
		ptcp->conn_hash_		= lhash;

		ptcp->is_client_local_.store(true, std::memory_order_relaxed);

		if (relatedshr) {
			ptcp->cli_related_listen_shr_	= std::move(relatedshr);
			ptcp->cli_listener_checked_	= true;
		}

		ptcp->is_new_cli_task_ 	= is_new_cli_task;

		if (0 == *task_comm) {	
			GY_STRNCPY(ptcp->cli_comm_, evt.comm_, sizeof(ptcp->cli_comm_));
		}
		else {
			std::memcpy(ptcp->cli_comm_, task_comm, sizeof(ptcp->cli_comm_) - 1);
			ptcp->cli_comm_[sizeof(ptcp->cli_comm_) - 1] = 0;
		}	

		try {
			pelem = (TCP_CONN_ELEM_TYPE *)connelempool.safe_malloc(free_fp, true /* use_malloc_hdr */);

			try {
				new (pelem) TCP_CONN_ELEM_TYPE(ptcp, TPOOL_DEALLOC<TCP_CONN>());
			}
			catch(...) {
				THR_POOL_ALLOC::dealloc(pelem);
				throw;
			}
		}
		GY_CATCH_EXCEPTION(
			DEBUGEXECN(1, ERRORPRINT_OFFLOAD("Caught exception while allocating memory for new TCP Connection : %s\n", GY_GET_EXCEPT_STRING););

			ptcp->~TCP_CONN();
			THR_POOL_ALLOC::dealloc(ptcp);
			return -1;
		);
		
		CONDEXEC(
			DEBUGEXECN(11,
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "[TCP Connect event] : New Conn : %s : Is new Client Task %d\n", 
					ptcp->print_string(STRING_BUFFER<512>().get_str_buf(), false), ptcp->is_new_cli_task_); 
			);
		);	

		// We use insert_or_replace() as only 1 IPv4/v6 thread inserting into tcp_tbl_
		bret = tcp_tbl_.insert_or_replace(pelem, ctuple, lhash);

		return 0;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while handling bpf TCP Connect event : %s\n", GY_GET_EXCEPT_STRING););
		return -1;
	);		
}

int TCP_SOCK_HANDLER::handle_bpf_accept(const CONN_BPF_EVENT & evt, bool more_data, bool from_v4_thread, THR_POOL_ALLOC & connpool, THR_POOL_ALLOC & connelempool) noexcept
{
	RCU_DEFER_OFFLINE		deferlock(more_data);

	try {
		/*
		 * First check the NAT table as NAT may be active. The NAT element weak_ptr will be also be updated if found.
		 */
		IP_PORT				orig_cli_ip_port(evt.daddr_, evt.dport_), orig_ser_ip_port(evt.saddr_, evt.sport_);
		PAIR_IP_PORT			nat_tup(orig_cli_ip_port, orig_ser_ip_port);

		FREE_FPTR			free_fp;
		std::shared_ptr <TASK_STAT>	task_shr;
		bool				bret, conn_updated = false;
		int				task_shr_upd;
		uint64_t			ser_task_aggr_id = 0;
		NAT_ELEM_TYPE			nat;
		NAT_ELEM			*pnat = nullptr;
		char				task_comm[TASK_COMM_LEN] {};

		bret = nat_tbl_.lookup_single_elem(nat_tup, nat_tup.get_hash(), nat);
		if (bret == true) {
			pnat = nat.get_cref().get();

			if (pnat) {
				orig_cli_ip_port 	= pnat->orig_tup_.cli_;
				orig_ser_ip_port	= pnat->orig_tup_.ser_;
			}
		}	

		auto newtaskcb = [&](TASK_STAT *ptask)
		{ 
			task_shr 		= ptask->shared_from_this();
			ser_task_aggr_id 	= ptask->get_set_aggr_id();

			std::memcpy(task_comm, ptask->task_comm, sizeof(task_comm) - 1);

			if (ptask->is_tcp_server == false) {
				ptask->is_tcp_server 	= true;
			}
		};

		task_shr_upd = ptask_handler_->get_task(evt.pid_, newtaskcb);

		PAIR_IP_PORT		act_tup  {orig_cli_ip_port, orig_ser_ip_port};
		const auto		ahash = act_tup.get_hash();

		static_assert(4 == sizeof(ahash), "Require 4 byte hash for PAIR_IP_PORT::get_hash() as ser_conn_hash_ is of 4 bytes"); 

		auto 	lambda_chkconn = [&](TCP_CONN_ELEM_TYPE *pdatanode, void *arg1, void *arg2) -> CB_RET_E
		{
			TCP_CONN	*ptcp = pdatanode->get_cref().get();

			if (gy_unlikely(ptcp == nullptr)) {
				return CB_OK;
			}

			conn_updated 			= true;

			ptcp->ser_ns_inode_.store(evt.netns_, std::memory_order_relaxed);
			ptcp->is_tcp_accept_event_	= true;

			ptcp->ser_pid_			= evt.pid_;
			ptcp->ser_tid_			= evt.tid_;
			ptcp->ser_task_shr_		= std::move(task_shr);
			ptcp->ser_task_updated_.store((task_shr_upd == 0), std::memory_order_relaxed);
			ptcp->ser_task_aggr_id_		= ser_task_aggr_id;
			 
			ptcp->is_server_local_.store(true, std::memory_order_release);

			if (0 == *task_comm) {	
				GY_STRNCPY(ptcp->ser_comm_, evt.comm_, sizeof(ptcp->ser_comm_));
			}
			else {
				std::memcpy(ptcp->ser_comm_, task_comm, sizeof(ptcp->ser_comm_) - 1);
				ptcp->ser_comm_[sizeof(ptcp->ser_comm_) - 1] = 0;
			}	

			if (pnat) {
				pnat->shrconn_		= ptcp->shared_from_this();

				ptcp->nat_updated_	= true;
				ptcp->is_snat_		= pnat->is_snat_;
				ptcp->is_dnat_		= pnat->is_dnat_;

				ptcp->nat_cli_		= pnat->nat_tup_.cli_;
				ptcp->nat_ser_		= pnat->nat_tup_.ser_;

				GY_CC_BARRIER();

				pnat->shr_updated_.store(true, std::memory_order_release);
			}
					
			CONDEXEC(
				DEBUGEXECN(11, 
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "[TCP Accept event] : Existing Conn : %s\n", 
						ptcp->print_string(STRING_BUFFER<512>().get_str_buf(), false)); 
				);
			);	


			return CB_OK;
		};

		bret = tcp_tbl_.lookup_single_elem(act_tup, ahash, lambda_chkconn);

		if (conn_updated) {
			return 0;
		}	

		/*
		 * Add a new TCP conn
		 *
		 * NOTE : For local connections with NAT, there is a race condition here as the NAT table may not have been updated
		 * by this time resulting in 2 separate TCP conns instead of 1. This will be reconciled later by the NAT cleanup functions.
		 */
		TCP_CONN			*ptcp;
		TCP_CONN_ELEM_TYPE		*pelem;
		
		ptcp = (TCP_CONN *)connpool.safe_malloc(free_fp, true /* use_malloc_hdr */);

		try {
			new (ptcp) TCP_CONN(orig_cli_ip_port, orig_ser_ip_port, 0, 0, evt.pid_, evt.tid_, get_usec_clock());	
		}
		catch(...) {
			THR_POOL_ALLOC::dealloc(ptcp);
			return -1;
		}	

		ptcp->ser_ns_inode_.store(evt.netns_, std::memory_order_relaxed);
		ptcp->ser_task_shr_		= std::move(task_shr);
		ptcp->ser_task_updated_.store((task_shr_upd == 0), std::memory_order_relaxed);
		ptcp->ser_task_aggr_id_		= ser_task_aggr_id;
		ptcp->is_tcp_accept_event_	= true;
		ptcp->conn_hash_		= ahash;

		ptcp->is_server_local_.store(true, std::memory_order_relaxed);

		if (0 == *task_comm) {	
			GY_STRNCPY(ptcp->ser_comm_, evt.comm_, sizeof(ptcp->ser_comm_));
		}
		else {
			std::memcpy(ptcp->ser_comm_, task_comm, sizeof(ptcp->ser_comm_) - 1);
			ptcp->ser_comm_[sizeof(ptcp->ser_comm_) - 1] = 0;
		}	

		try {
			pelem = (TCP_CONN_ELEM_TYPE *)connelempool.safe_malloc(free_fp, true /* use_malloc_hdr */);

			try {
				new (pelem) TCP_CONN_ELEM_TYPE(ptcp, TPOOL_DEALLOC<TCP_CONN>());
			}
			catch(...) {
				THR_POOL_ALLOC::dealloc(pelem);
				throw;
			}	

			if (pnat) {
				pnat->shrconn_		= ptcp->shared_from_this();

				ptcp->nat_updated_	= true;
				ptcp->is_snat_		= pnat->is_snat_;
				ptcp->is_dnat_		= pnat->is_dnat_;

				ptcp->nat_cli_		= pnat->nat_tup_.cli_;
				ptcp->nat_ser_		= pnat->nat_tup_.ser_;

				GY_CC_BARRIER();

				pnat->shr_updated_.store(true, std::memory_order_release);
			}
		}
		GY_CATCH_EXCEPTION(
			DEBUGEXECN(1, ERRORPRINT_OFFLOAD("Caught exception while allocating memory for new TCP Connection : %s\n", GY_GET_EXCEPT_STRING););

			ptcp->~TCP_CONN();
			THR_POOL_ALLOC::dealloc(ptcp);
			return -1;
		);
		
		CONDEXEC(
			DEBUGEXECN(11,
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "[TCP Accept event] : New Conn : %s\n", 
					ptcp->print_string(STRING_BUFFER<512>().get_str_buf(), false)); 
			);
		);	

		bret = tcp_tbl_.insert_or_replace(pelem, act_tup, ahash);

		return 0;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while handling bpf TCP Accept event : %s\n", GY_GET_EXCEPT_STRING););

		return -1;
	);		
}
	
int TCP_SOCK_HANDLER::handle_bpf_close_cli(const CONN_BPF_EVENT & evt, bool more_data, bool from_v4_thread) noexcept
{
	RCU_DEFER_OFFLINE		deferlock(more_data);

	try {	
		IP_PORT				cli_ip_port(evt.saddr_, evt.sport_), ser_ip_port(evt.daddr_, evt.dport_);
		PAIR_IP_PORT			ctuple(cli_ip_port, ser_ip_port);
		const uint32_t			lhash = ctuple.get_hash();

		auto 	lam_conn = [&, this, from_v4_thread](TCP_CONN_ELEM_TYPE *pdatanode, void *arg1, void *arg2) -> CB_RET_E
		{
			TCP_CONN		*ptcp = pdatanode->get_cref().get();
			uint64_t		currusectime = get_usec_time();	

			if (gy_unlikely(ptcp == nullptr)) {
				return CB_DELETE_ELEM;
			}

						// Ignore wraparound here
			int64_t			diffbytes = 0;
			bool			skip_exist = false;
			
			if ((ptcp->is_existing_conn_ == false) || ptcp->stats_.curr_usec_clock.load(std::memory_order_relaxed)) {
				diffbytes = evt.bytes_acked_ + evt.bytes_received_ - (ptcp->stats_.bytes_acked + ptcp->stats_.bytes_received);
			}
			else {
				skip_exist = true;
			}	

			if (diffbytes > 8) {
				// Update the cli task and server task if local server

				if (true == ptcp->cli_task_updated_.load(std::memory_order_relaxed)) {

					if (ptcp->cli_task_shr_ && ptcp->cli_task_shr_->pext_stats) {
						ptcp->cli_task_shr_->pext_stats->ntcp_bytes_ += diffbytes;

						if (false == ptcp->tcp_info_seen_) {
							ptcp->cli_task_shr_->pext_stats->ntcp_conn_++;
						}	
					}	
				}	
			}

			if (false == ptcp->is_server_local_.load(std::memory_order_relaxed)) {
				if (labs(diffbytes) < 8) {
					ptcp->stats_.bytes_acked 	= 0;
					ptcp->stats_.bytes_received 	= 0;
				}	
				else {
					uint64_t bytes_sent 		= gy_diff_counter_safe(evt.bytes_acked_, GY_READ_ONCE(ptcp->stats_.bytes_acked));
					uint64_t bytes_rcvd		= gy_diff_counter_safe(evt.bytes_received_, GY_READ_ONCE(ptcp->stats_.bytes_received));

					ptcp->stats_.bytes_acked 	= bytes_sent;
					ptcp->stats_.bytes_received 	= bytes_rcvd;
				}

				if (false == ptcp->tcp_info_seen_) {
					ptcp->cli_madhava_id_	= local_madhava_id_;
				}
			}
			else {
				// Loopback conn

				if (diffbytes > 8 && true == ptcp->ser_task_updated_.load(std::memory_order_relaxed)) {

					if (ptcp->ser_task_shr_ && ptcp->ser_task_shr_->pext_stats) {
						ptcp->ser_task_shr_->pext_stats->ntcp_bytes_ += diffbytes;

						if (false == ptcp->tcp_info_seen_) {
							ptcp->ser_task_shr_->pext_stats->ntcp_conn_++;
						}	
					}	
				}	

				if (ptcp->ser_glob_id_ != 0) {
					if (labs(diffbytes) < 8) {
						ptcp->stats_.bytes_acked 	= 0;
						ptcp->stats_.bytes_received 	= 0;
					}	
					else {
						uint64_t bytes_sent 		= gy_diff_counter_safe(evt.bytes_acked_, GY_READ_ONCE(ptcp->stats_.bytes_received));
						uint64_t bytes_rcvd		= gy_diff_counter_safe(evt.bytes_received_, GY_READ_ONCE(ptcp->stats_.bytes_acked));

						ptcp->stats_.bytes_acked	= bytes_sent;
						ptcp->stats_.bytes_received	= bytes_rcvd;

						if (ptcp->listen_shr_) {
							auto			plistener = ptcp->listen_shr_.get();

							plistener->close_bytes_in_	+= bytes_sent;
							plistener->close_bytes_out_	+= bytes_rcvd;

							if ((ptcp->is_dnat_) && (GY_READ_ONCE(ptcp->listen_updated_) == false)) {
								plistener->set_nat_ip_port(ptcp->ser_, currusectime/GY_USEC_PER_SEC);
							}
						}
					}	
				}
				else {
					ptcp->stats_.bytes_acked		= evt.bytes_acked_;
					ptcp->stats_.bytes_received		= evt.bytes_received_;

					// We need to locate the ser_glob_id_
					NS_IP_PORT			nsipport (ptcp->nat_ser_, ptcp->ser_ns_inode_.load(std::memory_order_relaxed)); 
					const uint32_t			hash_nsipport = nsipport.get_hash(true /* ignore_ip */);
					
					const auto lam_listen = [&, ptcp](TCP_LISTENER_ELEM_TYPE *pdatanode, void *arg1, void *arg2) -> CB_RET_E
					{
						auto 		plistener = pdatanode->get_cref().get();

						if (plistener) {
							ptcp->ser_glob_id_ 		= plistener->glob_id_;
							ptcp->ser_related_listen_id_	= plistener->related_listen_id_;

							plistener->close_bytes_in_	+= evt.bytes_acked_;
							plistener->close_bytes_out_	+= evt.bytes_received_;

							if ((ptcp->is_dnat_) && (GY_READ_ONCE(ptcp->listen_updated_) == false)) {
								plistener->set_nat_ip_port(ptcp->ser_, currusectime/GY_USEC_PER_SEC);
							}
						}	

						return CB_OK;
					};	
					
					listener_tbl_.lookup_single_elem(nsipport, hash_nsipport, lam_listen);

					ptcp->cli_madhava_id_	= local_madhava_id_;
					ptcp->ser_madhava_id_	= local_madhava_id_;
					ptcp->peer_machine_id_ 	= machineid_;
				}	
			}	

			if (currusectime - ptcp->tusec_start_ <= 500 * GY_USEC_PER_MSEC) {
				auto tcip 	= ptcp->cli_.ipaddr_;
				auto nchash 	= tcip.get_hash();

				auto ln = [currusectime](CLI_IP *pnat, void *arg1, void *arg2) -> CB_RET_E
				{
					pnat->last_tsec_ = currusectime/GY_USEC_PER_SEC;
					return CB_OK;
				};	

				if (false == nat_cli_ip_tbl_.lookup_single_elem(tcip, nchash, ln)) {
					auto pcli = new CLI_IP(tcip, currusectime/GY_USEC_PER_SEC);

					nat_cli_ip_tbl_.insert_or_replace(pcli, tcip, nchash);
				}							
			}	

			CONDEXEC(
				DEBUGEXECN(11, 
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "[TCP Close Client event] : %s : Final Bytes Sent %lu Bytes Received %lu\n", 
						ptcp->print_string(STRING_BUFFER<512>().get_str_buf(), false), evt.bytes_acked_, evt.bytes_received_); 
				);
			);

			DATA_BUFFER 		& cache = (from_v4_thread ? conn_v4_cache_ : conn_v6_cache_);

			notify_tcp_conn(ptcp, currusectime, true /* more_data Always batch */, cache);

			return CB_DELETE_ELEM;
		};

		tcp_tbl_.lookup_single_elem(ctuple, lhash, lam_conn);

		return 0;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while handling bpf TCP Close Client event : %s\n", GY_GET_EXCEPT_STRING););
		return -1;
	);		
}
	
int TCP_SOCK_HANDLER::handle_bpf_close_ser(const CONN_BPF_EVENT & evt, bool more_data, bool from_v4_thread) noexcept
{
	RCU_DEFER_OFFLINE		deferlock(more_data);

	try {	
		/*
		 * First check the NAT table as NAT may be active. 
		 * We delete the NAT entry first and then delete the tcp_tbl_ entry. 
		 */
		IP_PORT				orig_cli_ip_port(evt.daddr_, evt.dport_), orig_ser_ip_port(evt.saddr_, evt.sport_);
		PAIR_IP_PORT			nat_tup(orig_cli_ip_port, orig_ser_ip_port);

		NAT_ELEM_TYPE			nat;
		NAT_ELEM			*pnat = nullptr;

		auto 	lam_nat = [&](NAT_ELEM_TYPE *pdatanode, void *arg1, void *arg2) -> CB_RET_E
		{
			auto			pnat = pdatanode->get_cref().get();

			if (pnat) {
				orig_cli_ip_port 	= pnat->orig_tup_.cli_;
				orig_ser_ip_port	= pnat->orig_tup_.ser_;
			}

			return CB_DELETE_ELEM;
		};

		nat_tbl_.lookup_single_elem(nat_tup, nat_tup.get_hash(), lam_nat);
		
		PAIR_IP_PORT		act_tup(orig_cli_ip_port, orig_ser_ip_port);
		const uint32_t		ahash = act_tup.get_hash();

		auto 	lam_conn = [&, this, from_v4_thread](TCP_CONN_ELEM_TYPE *pdatanode, void *arg1, void *arg2) -> CB_RET_E
		{
			TCP_CONN		*ptcp = pdatanode->get_cref().get();
			uint64_t		currusectime = get_usec_time();

			if (gy_unlikely(ptcp == nullptr)) {
				return CB_DELETE_ELEM;
			}

			int64_t			diffbytes = 0;
			bool			skip_exist = false;

			if ((ptcp->is_existing_conn_ == false) || ptcp->stats_.curr_usec_clock.load(std::memory_order_relaxed)) {
				// Ignore wraparound here
				diffbytes = evt.bytes_acked_ + evt.bytes_received_ - (ptcp->stats_.bytes_acked + ptcp->stats_.bytes_received);

				if (diffbytes > 8) {
					// Update the server task and cli task if local

					if (true == ptcp->ser_task_updated_.load(std::memory_order_relaxed)) {

						if (ptcp->ser_task_shr_ && ptcp->ser_task_shr_->pext_stats) {
							ptcp->ser_task_shr_->pext_stats->ntcp_bytes_ += diffbytes;

							if (false == ptcp->tcp_info_seen_) {
								ptcp->ser_task_shr_->pext_stats->ntcp_conn_++;
							}	
						}	
					}	
					
					if (true == ptcp->cli_task_updated_.load(std::memory_order_relaxed)) {

						if (ptcp->cli_task_shr_ && ptcp->cli_task_shr_->pext_stats) {
							ptcp->cli_task_shr_->pext_stats->ntcp_bytes_ += diffbytes;

							if (false == ptcp->tcp_info_seen_) {
								ptcp->cli_task_shr_->pext_stats->ntcp_conn_++;
							}	
						}	
					}	
				}
			}
			else {
				skip_exist = true;
			}	

			if (ptcp->ser_glob_id_ == 0) {
				// We need to locate the ser_glob_id_
				NS_IP_PORT			nsipport (ptcp->nat_ser_, ptcp->ser_ns_inode_.load(std::memory_order_relaxed)); 
				const uint32_t			hash_nsipport = nsipport.get_hash(true /* ignore_ip */);
				
				const auto lam_listen = [&, ptcp](TCP_LISTENER_ELEM_TYPE *pdatanode, void *arg1, void *arg2) -> CB_RET_E
				{
					auto 		plistener = pdatanode->get_cref().get();

					if (plistener) {
						ptcp->ser_glob_id_ 		= plistener->glob_id_;
						ptcp->ser_related_listen_id_	= plistener->related_listen_id_;

						plistener->close_bytes_in_	+= evt.bytes_received_;
						plistener->close_bytes_out_	+= evt.bytes_acked_;

						if ((ptcp->is_dnat_) && (GY_READ_ONCE(ptcp->listen_updated_) == false)) {
							plistener->set_nat_ip_port(ptcp->ser_, currusectime/GY_USEC_PER_SEC);
						}
					}	

					return CB_OK;
				};	
				
				listener_tbl_.lookup_single_elem(nsipport, hash_nsipport, lam_listen);

				// Reverse stats as from cli perspective
				ptcp->stats_.bytes_acked		= evt.bytes_received_;
				ptcp->stats_.bytes_received		= evt.bytes_acked_;
			}	
			else {
				if (false == ptcp->tcp_info_seen_ && false == skip_exist) {
					ptcp->stats_.bytes_acked	= evt.bytes_received_;
					ptcp->stats_.bytes_received	= evt.bytes_acked_;
				}	
				else if (labs(diffbytes) < 8) {
					ptcp->stats_.bytes_acked 	= 0;
					ptcp->stats_.bytes_received 	= 0;
				}	
				else {
					uint64_t bytes_sent 		= gy_diff_counter_safe(evt.bytes_acked_, GY_READ_ONCE(ptcp->stats_.bytes_acked));
					uint64_t bytes_rcvd		= gy_diff_counter_safe(evt.bytes_received_, GY_READ_ONCE(ptcp->stats_.bytes_received));

					// Reverse
					ptcp->stats_.bytes_acked	= bytes_rcvd;
					ptcp->stats_.bytes_received	= bytes_sent;
				}	

				if (ptcp->listen_shr_) {
					auto			plistener = ptcp->listen_shr_.get();

					if (ptcp->stats_.bytes_received + ptcp->stats_.bytes_acked) {
						plistener->close_bytes_in_	+= ptcp->stats_.bytes_acked;
						plistener->close_bytes_out_	+= ptcp->stats_.bytes_received;
					}	

					if ((ptcp->is_dnat_) && (GY_READ_ONCE(ptcp->listen_updated_) == false)) {
						plistener->set_nat_ip_port(ptcp->ser_, currusectime/GY_USEC_PER_SEC);
					}
				}
			}	

			if (false == ptcp->tcp_info_seen_) {
				ptcp->ser_madhava_id_			= local_madhava_id_;

				if (ptcp->is_tcp_connect_event_) {
					ptcp->cli_madhava_id_		= local_madhava_id_;
					ptcp->peer_machine_id_ 		= machineid_;
				}
			}

			CONDEXEC(
				DEBUGEXECN(11, 
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "[TCP Close Server event] : %s : "
						"Final Bytes Sent %lu Bytes Received %lu : Close Server PID %d\n", 
						ptcp->print_string(STRING_BUFFER<512>().get_str_buf(), false), evt.bytes_acked_, evt.bytes_received_, evt.pid_); 
				);
			);

			DATA_BUFFER 		& cache = (from_v4_thread ? conn_v4_cache_ : conn_v6_cache_);

			notify_tcp_conn(ptcp, currusectime, true /* more_data Always batch */, cache);
			
			return CB_DELETE_ELEM;
		};

		tcp_tbl_.lookup_single_elem(act_tup, ahash, lam_conn);

		return 0;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while handling bpf TCP Close Server event : %s\n", GY_GET_EXCEPT_STRING););
		return -1;
	);		
}

bool TCP_SOCK_HANDLER::notify_tcp_conn(TCP_CONN *ptcp, uint64_t close_usec_time, bool more_data, DATA_BUFFER & cache, const char *pcli_cmdline, size_t cli_cmdline_len) noexcept
{
	try {
		using namespace 		comm;

		auto				pser =  SERVER_COMM::get_singleton();
		size_t				elemsz = 0;

		if (gy_unlikely(false == pser->is_server_connected())) {
			return false;
		}	

		if (ptcp) {
			comm::TCP_CONN_NOTIFY		*pone = (comm::TCP_CONN_NOTIFY *)cache.get_next_buffer();

			ptcp->set_notify_elem(pone, close_usec_time, pcli_cmdline, cli_cmdline_len);
			
			elemsz = pone->get_elem_size();
		}
		
		auto sendcb = [&, this](void *palloc, size_t sz, FREE_FPTR free_fp, size_t nelems) -> bool
		{
			DEBUGEXECN(1,
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Sending %lu TCP Conn info to Madhava server : Payload size %lu\n",
					nelems, sz);
			);

			auto		pser = SERVER_COMM::get_singleton();

			return pser->send_event_cache(cache, palloc, sz, free_fp, nelems, comm::NOTIFY_TCP_CONN, pser->get_server_conn(comm::CLI_TYPE_REQ_ONLY));
		};	

		return cache.set_buffer_sz(sendcb, elemsz, !more_data);
	}
	catch(...) {
		cache.purge_all();

		return false;
	}	
}

void TCP_SOCK_HANDLER::upd_new_listen_task(TCP_LISTENER *pnewlistener, TASK_STAT *ptask, uint64_t curr_tusec) noexcept
{
	try {
		auto 		task_shrlisten = ptask->listen_tbl_shr.load(std::memory_order_acquire);
		auto 		ptask_listen_table = task_shrlisten.get();

		auto 		task_relshrlisten = ptask->related_listen_.load(std::memory_order_acquire);
		auto 		ptask_rellisten_table = task_relshrlisten.get();

		uint8_t		inhval = ptask->listen_tbl_inherited.load(std::memory_order_acquire);
	
		if ((0 != inhval) && (ptask->is_execv_task)) {

			if (inhval == 1 && (true == ptask->listen_tbl_inherited.compare_exchange_strong(inhval, 2))) {
				ptask->clear_listener_table();
			}
			else if (inhval == 2) {
				int		ntimes = 0;

				while (++ntimes < 4 && (0 != ptask->listen_tbl_inherited.load(std::memory_order_relaxed))) {
					sched_yield();	
				}

				if (ntimes >= 4) {
					return;
				}	
			}
			
			ptask_listen_table 	= nullptr;
			ptask_rellisten_table 	= nullptr; 
		}	

		ptask->is_tcp_server = true;
		ptask->ntcp_listeners.fetch_add(1, std::memory_order_relaxed);

		std::memcpy(pnewlistener->comm_, ptask->task_comm, sizeof(pnewlistener->comm_));

		auto shrlisten 		= pnewlistener->listen_task_table_.load(std::memory_order_relaxed);
		auto relshrlisten 	= pnewlistener->related_listen_.load(std::memory_order_relaxed);

		if (!ptask_listen_table || !ptask_rellisten_table) {
			if (!shrlisten || !relshrlisten) {
				shrlisten = std::make_shared<SHR_TASK_HASH_TABLE>(8, 8, 1024, true, false);

				pnewlistener->listen_task_table_.store(shrlisten, std::memory_order_release);

				relshrlisten = std::make_shared<RELATED_LISTENERS>(pnewlistener, false);

				pnewlistener->related_listen_.store(relshrlisten, std::memory_order_release);
				pnewlistener->related_listen_id_ = (int64_t)relshrlisten.get();

				TCP_LISTENER_PTR	key(pnewlistener);
				
				WEAK_LISTEN_RAW		*praw = new WEAK_LISTEN_RAW(pnewlistener->weak_from_this(), pnewlistener);

				relshrlisten->related_table_.template insert_or_replace<RCU_LOCK_FAST>(praw, key, get_pointer_hash(pnewlistener));
			}
				
			task_shrlisten = shrlisten;

			ptask->listen_tbl_shr.store(task_shrlisten, std::memory_order_release);
			ptask->related_listen_.store(relshrlisten, std::memory_order_release);
			ptask->last_listen_tusec_ = curr_tusec;
		
			ptask->listen_tbl_inherited.store(0, std::memory_order_release);

			if (task_shrlisten) {
				SHR_TASK_ELEM_TYPE		*pshrelem;

				pshrelem = new SHR_TASK_ELEM_TYPE(ptask->shared_from_this());	

				task_shrlisten->template insert_or_replace<RCU_LOCK_FAST>(pshrelem, ptask->task_pid, get_pid_hash(ptask->task_pid));
			}
		}	
		else if (ptask_listen_table != shrlisten.get()) {

			TCP_LISTENER_PTR	key(pnewlistener);
			const uint32_t		khash = get_pointer_hash(pnewlistener);

			// Overwrite with task listen table as that may contain references to other listener tasks
			pnewlistener->listen_task_table_.store(task_shrlisten, std::memory_order_release);

			if (relshrlisten) {
				// Delete this listener from the older related listener list
				relshrlisten->related_table_.template delete_single_elem<RCU_LOCK_FAST>(key, khash);
			}
				
			relshrlisten = task_relshrlisten;

			pnewlistener->related_listen_.store(relshrlisten, std::memory_order_release);
			pnewlistener->related_listen_id_ = (int64_t)relshrlisten.get();
				
			// Set server_stats_fetched_ to enable intimation to server
			pnewlistener->server_stats_fetched_ = false;

			WEAK_LISTEN_RAW		*praw = new WEAK_LISTEN_RAW(pnewlistener->weak_from_this(), pnewlistener);

			relshrlisten->related_table_.insert_or_replace(praw, key, khash);

		}	
		pnewlistener->task_weak_ = ptask->weak_from_this();
		GY_STRNCPY(pnewlistener->cmdline_, ptask->task_cmdline, sizeof(pnewlistener->cmdline_));
		pnewlistener->ser_aggr_task_id_ = ptask->get_set_aggr_id();

		pnewlistener->set_aggr_glob_id();
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while updating Listener Task Table for bpf TCP Listen event : %s\n", 
							GY_GET_EXCEPT_STRING);
	);
}	

void TCP_SOCK_HANDLER::handle_listener_event(tcp_listener_event_t * pevent, bool more_data) noexcept
{
	RCU_DEFER_OFFLINE		deferlock(more_data);
		
	try {
		std::weak_ptr <TASK_STAT>		task_weak;
		std::shared_ptr <SHR_TASK_HASH_TABLE>	listen_table;
		TCP_LISTENER 				*pnewlistener = nullptr;
		TCP_LISTENER_ELEM_TYPE			*pelem;
		GY_IP_ADDR				laddr;
		const uint64_t				curr_tusec = get_usec_time();
		ino_t					inode = pevent->netns;
		const uint32_t				inode_hash = get_uint64_hash(inode);
		bool					bret, recheck = false;
		int					ret;

		bret = netns_tbl_.lookup_single_elem(inode, inode_hash);

		if (bret == false) {
			try {
				NETNS_ELEM		*pnetns = new NETNS_ELEM(inode, pevent->pid, pevent->tid, false);

				netns_tbl_.insert_or_replace(pnetns, inode, inode_hash);

				DEBUGEXECN(1, 
					INFOPRINT_OFFLOAD("New Network Namespace %lu seen for PID %u Thread %u from TCP New Listener handler\n", 
						inode, pevent->pid, pevent->tid);
				);
			}
			GY_CATCH_EXCEPTION(
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while adding new NetNS in bpf TCP Listener event : %s\n", GY_GET_EXCEPT_STRING);
				return;
			);
		}	

		if (pevent->ipver == 4) {
			laddr.set_ip(pevent->addr.v4addr);
		}
		else {
			laddr.set_ip(pevent->addr.v6addr);
		}
				
		NS_IP_PORT			nsipport (laddr, pevent->lport, pevent->netns); 
		const uint32_t			hash_nsipport = nsipport.get_hash(true /* ignore_ip */);
		
		auto newtaskcb = [&](TASK_STAT *ptask) noexcept 
		{ 
			upd_new_listen_task(pnewlistener, ptask, curr_tusec);
		};

		auto 	lam_chk = [&, this](TCP_LISTENER_ELEM_TYPE *pdatanode, void *arg1, void *arg2) -> CB_RET_E
		{
			auto 		plistener = pdatanode->get_cref().get();

			if (gy_unlikely(plistener == nullptr)) {
				return CB_DELETE_ELEM;
			}
			
			uint64_t	clock_diag	= get_usec_clock(),
					tclock		= plistener->clock_usec_.load(std::memory_order_relaxed),
					tstart_clock 	= plistener->start_clock_usec_.load(std::memory_order_relaxed);
			int		old_ntasks 	= GY_READ_ONCE(plistener->ntasks_associated_);

			if (gy_unlikely((0 == old_ntasks) && (tclock + TIMEOUT_INET_DIAG_SECS * GY_USEC_PER_SEC - GY_USEC_PER_SEC < clock_diag && tclock))) {
				recheck = true;
			}
			else {
				recheck = false;
			}	
			
			plistener->clock_usec_.store(clock_diag, std::memory_order_release);
			plistener->start_clock_usec_.store(clock_diag, std::memory_order_relaxed);
			plistener->tstart_usec_	= curr_tusec;
			
			if (recheck) {
				return CB_OK;
			}
				
			plistener->ns_ip_port_ 	= nsipport;
			
			GY_CC_BARRIER();

			pnewlistener 		= plistener;

			if ((plistener->pid_ == (pid_t)pevent->pid) && (0 == strcmp(plistener->orig_comm_, pevent->comm))) {
				if (false == plistener->task_weak_.expired()) {
					return CB_OK;	
				}
			}	
			else {
				if ((0 == strcmp(plistener->orig_comm_, pevent->comm)) && (0 != old_ntasks)) {
					auto 			ptaskshr = plistener->task_weak_.lock();

					if (ptaskshr && ptaskshr->is_task_valid()) {
						// New listener process added probably SO_REUSEPORT
						return CB_OK;	
					}
				}	
			}	

			// New process (e.g. separate procs for IPv4/v6 Any or Listener process restarted before the listener entry was deleted) 
			plistener->pid_ = pevent->pid;
			
			if (0 == old_ntasks) {
				if (0 == GY_READ_ONCE(plistener->ntasks_associated_)) {
					plistener->ntasks_associated_++;
				}	
			}	

			GY_STRNCPY(plistener->comm_, pevent->comm, sizeof(plistener->comm_));
			std::memcpy(plistener->orig_comm_, plistener->comm_, sizeof(plistener->orig_comm_));

			// Reset Service Error and API Network Capture : Currently if restart happens within 30 sec we keep the old state...
			plistener->httperr_cap_started_.store(indeterminate, mo_relaxed);
			plistener->is_http_svc_ = indeterminate;

			if (plistener->api_cap_started_.load(mo_relaxed) >= CAPSTAT_STARTING) {
				// Stop capture
				plistener->tapi_cap_stop_.store(curr_tusec/GY_USEC_PER_SEC, mo_relaxed);
			}

			plistener->api_is_ssl_.store(indeterminate, mo_relaxed);
			plistener->api_proto_.store(PROTO_UNINIT, mo_relaxed);

			ptask_handler_->get_task(pevent->pid, newtaskcb);

			// Need to intimate madhava
			GY_WRITE_ONCE(plistener->server_stats_fetched_, false);

			// Reset the last_nat_chg_ip_tsec_ and last_nat_ref_ip_tsec_
			if (plistener->last_nat_chg_ip_tsec_ > 0 && plistener->last_nat_ref_ip_tsec_[0] > 0) {

				plistener->nat_ip_port_arr_[0] = {};
				plistener->nat_ip_port_arr_[1] = {};

				plistener->last_nat_ref_ip_tsec_[0] = 0;
				GY_WRITE_ONCE(plistener->last_nat_chg_ip_tsec_, curr_tusec/GY_USEC_PER_SEC);
			}
			
			return CB_OK;
		};	
		
		// First check if the Listener is already present
		bret = listener_tbl_.lookup_single_elem(nsipport, hash_nsipport, lam_chk);
		if (bret) {
			GY_CC_BARRIER();

			if (recheck) {
				bret = listener_tbl_.lookup_single_elem(nsipport, hash_nsipport, lam_chk);
			}	

			if (bret == true && pnewlistener) {
				DEBUGEXECN(5, 
					INFOPRINT_OFFLOAD("[TCP Listener event] : Re-adding TCP Listener entry : %s\n", 
						pnewlistener->print_string(STRING_BUFFER<512>().get_str_buf(), false));
				);
				return; 
			}	
		}	

		pnewlistener = new TCP_LISTENER(laddr, pevent->lport, pevent->netns, pevent->pid, hash_nsipport, pevent->backlog, task_weak, listen_table, pevent->comm, 
				nullptr /* pcmdline */, false /* is_pre_existing */, curr_tusec);

		try {
			pelem = new TCP_LISTENER_ELEM_TYPE(pnewlistener);

			ret = ptask_handler_->get_task(pevent->pid, newtaskcb);

			auto shrlisten 		= pnewlistener->listen_task_table_.load(std::memory_order_relaxed);
			auto relshrlisten 	= pnewlistener->related_listen_.load(std::memory_order_relaxed);

			if (!shrlisten || !relshrlisten) {
				// The Task has not yet been populated or it has already exited
				pnewlistener->listen_task_table_.store(std::make_shared<SHR_TASK_HASH_TABLE>(8, 8, 1024, true, false), std::memory_order_release);

				relshrlisten = std::make_shared<RELATED_LISTENERS>(pnewlistener, false);

				pnewlistener->related_listen_.store(relshrlisten, std::memory_order_release);
				pnewlistener->related_listen_id_ = (int64_t)relshrlisten.get();

				TCP_LISTENER_PTR	key(pnewlistener);
				
				WEAK_LISTEN_RAW		*praw = new WEAK_LISTEN_RAW(pnewlistener->weak_from_this(), pnewlistener);

				relshrlisten->related_table_.insert_or_replace(praw, key, get_pointer_hash(pnewlistener));
			}	
		}
		GY_CATCH_EXCEPTION(
			DEBUGEXECN(1, ERRORPRINT_OFFLOAD("Caught exception while allocating memory for new TCP Listener : %s\n", GY_GET_EXCEPT_STRING););

			delete pnewlistener;
			return;
		);

		// We use insert_or_replace() as only 1 thread inserting into listener_tbl_
		listener_tbl_.insert_or_replace(pelem, nsipport, hash_nsipport);

		INFOPRINT_OFFLOAD("[TCP Listener event] : Adding new Listener : %s\n", pnewlistener->print_string(STRING_BUFFER<512>().get_str_buf(), false));
	
		notify_new_listener(pnewlistener, true /* Batch always */, true /* is_listen_event_thread */);
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while handling bpf TCP Listen event : %s\n", GY_GET_EXCEPT_STRING);
	);		
}	

bool TCP_SOCK_HANDLER::notify_new_listener(TCP_LISTENER *plistener, bool more_data, bool is_listen_event_thread) 
{
	using namespace 		comm;

	auto				pser =  SERVER_COMM::get_singleton();
	size_t				elemsz = 0, fixedsz = 0;
	void				*palloc1 = nullptr;

	if (gy_unlikely(false == pser->is_server_connected())) {
		return false;
	}	

	if (plistener) {
		comm::NEW_LISTENER		*pone;
		
		if (is_listen_event_thread) {
			pone = (comm::NEW_LISTENER *)listen_cache_.get_next_buffer();
		}
		else {
			fixedsz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + sizeof(NEW_LISTENER);

			palloc1 = ::malloc(fixedsz);
			if (!palloc1) {
				return false;
			}	

			pone = (comm::NEW_LISTENER *)((uint8_t *)palloc1 + sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY));
		}	

		new (pone) comm::NEW_LISTENER(plistener->ns_ip_port_, plistener->glob_id_, 0 /* Set as 0 as validation will be done in inode check */,
						plistener->related_listen_id_, plistener->tstart_usec_, plistener->ser_aggr_task_id_, 
						plistener->is_any_ip_, false /* is_pre_existing */,
						false /* no_aggr_stats */, true /* no_resp_stats */, plistener->comm_, plistener->pid_, 0 /* Set cmdline_len_ as 0 */);

		elemsz = pone->get_elem_size();
	}
	
	auto sendcb = [this](void *palloc, size_t sz, FREE_FPTR free_fp, size_t nelems) -> bool
	{
		auto		pser = SERVER_COMM::get_singleton();

		return pser->send_event_cache(listen_cache_, palloc, sz, free_fp, nelems, comm::NOTIFY_NEW_LISTENER, pser->get_server_conn(comm::CLI_TYPE_REQ_ONLY));
	};	

	if (is_listen_event_thread) {
		return listen_cache_.set_buffer_sz(sendcb, elemsz, !more_data);
	}
	else if (palloc1) {
		COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc1);
		EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1); 

		new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, fixedsz, pser->get_conn_magic());

		new (pnot) EVENT_NOTIFY(NOTIFY_NEW_LISTENER, 1);

		return pser->send_server_data(EPOLL_IOVEC_ARR(2, false, phdr, phdr->get_act_len(), ::free, pser->gpadbuf, phdr->get_pad_len(), nullptr), 
						comm::CLI_TYPE_REQ_ONLY, COMM_EVENT_NOTIFY, pser->get_server_conn(comm::CLI_TYPE_REQ_ONLY));
	}
	else {
		return false;
	}	
}

void TCP_SOCK_HANDLER::handle_create_netns(create_ns_data_t * pevent, ino_t inode) noexcept
{
	try {
		NETNS_ELEM		*pnetns = new NETNS_ELEM(inode, pevent->pid, pevent->tid, true);

		CONDEXEC(
			DEBUGEXECN(1,
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "[New NetNS event] : Adding new NetNS : %s\n", 
					pnetns->print_string(STRING_BUFFER<512>().get_str_buf()));
			);
		);

		netns_tbl_.template insert_or_replace<RCU_LOCK_SLOW>(pnetns, inode, get_uint64_hash(inode));
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while handling bpf New NetNS event : %s\n", GY_GET_EXCEPT_STRING););
	);		
}	

void TCP_SOCK_HANDLER::handle_create_ns_event(create_ns_data_t *pevent, bool more_data) noexcept
{
	CONDEXEC(
		DEBUGEXECN(1, 
			STRING_BUFFER<512>	ss;

			if (pevent->flags & CLONE_NEWNS) {
				ss.appendconst(" New Mount Namespace,");
			}	
			if (pevent->flags & CLONE_NEWUTS) {
				ss.appendconst(" New utsname Namespace,");
			}	
			if (pevent->flags & CLONE_NEWIPC) {
				ss.appendconst(" New IPC Namespace,");
			}	
			if (pevent->flags & CLONE_NEWPID) {
				ss.appendconst(" New PID Namespace,");
			}	
			if (pevent->flags & CLONE_NEWNET) {
				ss.appendconst(" New network Namespace,");
			}	
			if (pevent->flags & CLONE_NEWCGROUP) {
				ss.appendconst(" New cgroup Namespace,");
			}	

			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_YELLOW, "Namespace Event : Process PID : %u, Process TID : %u, Process name : %s, %.*s\n\n", 
					pevent->pid, pevent->tid, pevent->comm, ss.sizeint(), ss.buffer());
		);
	);

	// Currently we handle only NetNS events

	if (!(pevent->flags & CLONE_NEWNET)) {
		return;
	}	

	int			ret;
	ino_t			ns_net[1];
	const char *		ns_str_net[] = {"net"};

	ret = get_proc_ns_inodes(pevent->pid, ns_str_net, ns_net, 1, -1, pevent->tid);
	if (ret < 0) {
		errno = -ret;

		DEBUGEXECN(1, PERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Failed to get NetNS inode for new netns event for PID %d", pevent->pid););
		return;
	}

	handle_create_netns(pevent, ns_net[0]);
}	


void TCP_SOCK_HANDLER::handle_ipv4_resp_event(tcp_ipv4_resp_event_t * pevent, bool more_data) noexcept
{
	int				tresp_msec = pevent->lsndtime - pevent->lrcvtime;

	// Ignore responses > 1000 sec or negative 
	if (gy_unlikely((uint32_t)tresp_msec > 1000'000u)) {
		return;
	}	

	pevent->tup.sport 		= ntohs(pevent->tup.sport);
	pevent->tup.dport 		= ntohs(pevent->tup.dport);

	NS_IP_PORT			nsipport (pevent->tup.saddr, pevent->tup.sport, pevent->tup.netns);
	IP_PORT				cli_ip_port (GY_IP_ADDR(pevent->tup.daddr), pevent->tup.dport);

	handle_tcp_resp_event(nsipport, cli_ip_port, pevent->lsndtime, tresp_msec, true, more_data);
}	

void TCP_SOCK_HANDLER::handle_ipv6_resp_event(tcp_ipv6_resp_event_t * pevent, bool more_data) noexcept
{
	int				tresp_msec = pevent->lsndtime - pevent->lrcvtime;

	// Ignore responses > 1000 sec or negative 
	if (gy_unlikely((uint32_t)tresp_msec > 1000'000u)) {
		return;
	}	

	pevent->tup.sport 		= ntohs(pevent->tup.sport);
	pevent->tup.dport 		= ntohs(pevent->tup.dport);

	NS_IP_PORT			nsipport (pevent->tup.saddr, pevent->tup.sport, pevent->tup.netns);
	IP_PORT				cli_ip_port (GY_IP_ADDR(pevent->tup.daddr), pevent->tup.dport);

	handle_tcp_resp_event(nsipport, cli_ip_port, pevent->lsndtime, tresp_msec, false, more_data);
}	


void TCP_SOCK_HANDLER::handle_tcp_resp_event(const NS_IP_PORT & ser_nsipport, IP_PORT cli_ip_port, uint32_t tcur, int tresp_msec, bool is_ipv4, bool more_data) noexcept
{
	RCU_DEFER_OFFLINE		deferlock(more_data);

	try {
		thread_local 	uint32_t	glast_sndtime = 0, glast_cache_time = 0;
		thread_local	time_t		glast_time_t = time(nullptr);
		bool				bret, tupdated = false;
		int				ret;
		
		if (gy_unlikely(glast_sndtime != tcur/100)) { 
			/*
			 * Update glast_sndtime every 100 msec
			 */
			glast_sndtime 	= tcur/100;
			glast_time_t 	= time(nullptr);

			tupdated	= true;
		}

		auto lam_listen = [&, this, tresp_msec, is_ipv4](TCP_LISTENER *plistener)
		{
			size_t			bucket_id;
			
			if (is_ipv4) {
				plistener->resp_cache_v4_.add_cache(tresp_msec, bucket_id, glast_time_t);	
				plistener->resp_bitmap_v4_.add_response(glast_time_t, cli_ip_port.port_, bucket_id);	
				plistener->curr_query_v4_++;
				plistener->resp_conn_v4_.add_resp_conn(glast_time_t, cli_ip_port, ser_nsipport.ip_port_, tresp_msec);

			}
			else {
				plistener->resp_cache_v6_.add_cache(tresp_msec, bucket_id, glast_time_t);	
				plistener->resp_bitmap_v6_.add_response(glast_time_t, cli_ip_port.port_, bucket_id);	
				plistener->curr_query_v6_++;
				plistener->resp_conn_v6_.add_resp_conn(glast_time_t, cli_ip_port, ser_nsipport.ip_port_, tresp_msec);
			}	
		};	

		auto lam_tbl = [&, this, tresp_msec, is_ipv4](TCP_LISTENER_ELEM_TYPE *pdatanode, void *arg1, void *arg2) -> CB_RET_E
		{
			auto 		plistener = pdatanode->get_cref().get();

			if (gy_unlikely(plistener == nullptr)) {
				return CB_OK;
			}
			
			lam_listen(plistener);
			
			// Update cache every 5 msec
			if (gy_unlikely(tcur - glast_cache_time > 5 && plistener->last_qps_count_ > 50))  {

				if (is_ipv4) {
					glast_cache_time = tcur;

					array_shift_right(ipv4_listen_cache_, MAX_LISTENER_CACHE_SZ);
					ipv4_listen_cache_[0] = *pdatanode->get_data();
				}		
				else {
					glast_cache_time = tcur;

					array_shift_right(ipv6_listen_cache_, MAX_LISTENER_CACHE_SZ);
					ipv6_listen_cache_[0] = *pdatanode->get_data();
				}	
			}
				
			return CB_OK;
		};	

		
		auto lam_cache = [&, this, tresp_msec, is_ipv4](std::shared_ptr <TCP_LISTENER> *pcache) -> int
		{
			for (size_t i = 0; i < MAX_LISTENER_CACHE_SZ; ++i) {
				if (pcache[i]) {
					if (pcache[i] == ser_nsipport) {

						TCP_LISTENER		*plistener = pcache[i].get();
						
						/*
						 * We check if this shared_ptr has been updated recently by the listener_stats_update().
						 * If not, the listener may have been replaced in which case we use the listener_tbl_
						 */
							
						if (glast_time_t - GY_READ_ONCE(plistener->tlast_stats_flush_) < 10) {
							lam_listen(plistener);
						}
						else {
							// Reset table 
							for (size_t j = 0; j < MAX_LISTENER_CACHE_SZ; ++j) {
								pcache[j].reset();
							}

							return -1;
						}	

						return 0;
					}	
				}
				else {
					return -1;
				}		
			}		

			return -1;
		};

		/*
		 * First check the cache
		 */
		if (is_ipv4) {
			ret = lam_cache(ipv4_listen_cache_);
		}
		else {
			ret = lam_cache(ipv6_listen_cache_);
		}	
		
		if (ret != 0) {
			listener_tbl_.template lookup_single_elem<decltype(lam_tbl), RCU_LOCK_FAST>(ser_nsipport, ser_nsipport.get_hash(true /* ignore_ip */), lam_tbl);
		}	
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while handling bpf TCP Response event : %s\n", GY_GET_EXCEPT_STRING););
	);	
}	

const char * TCP_CONN::print_string(STR_WR_BUF & strbuf, bool print_stats) const 
{
	strbuf.appendconst("TCP Connection Info : Original Client ");
	cli_.print_string(strbuf);
	strbuf.appendconst(" : Server ");
	ser_.print_string(strbuf);
	
	if (is_snat_ || is_dnat_) {
		if (is_snat_) {
			strbuf.appendconst(" [SNAT] ");
		}	
		if (is_dnat_) {
			strbuf.appendconst(" [DNAT] ");
		}	

		strbuf.appendconst(" NAT Client ");
		nat_cli_.print_string(strbuf);
		strbuf.appendconst(" NAT Server ");
		nat_ser_.print_string(strbuf);
	}	
	else {
		strbuf.appendconst(" [No NAT] ");
	}	

	if (is_client_local_.load(std::memory_order_relaxed)) {
		strbuf.appendfmt(" Client \'%s\' is from this host : Client PID %d TID %d NetNS Inode %ld : Client Socket Inode %ld : Client UID %u ", 
				cli_comm_, cli_pid_, cli_tid_, cli_ns_inode_, cli_sock_inode_, cli_uid_);
	}	
	else if (cli_task_aggr_id_) {
		strbuf.appendfmt(" Remote Client \'%s\' : Remote Client Madhava ID %016lx ", cli_comm_, cli_madhava_id_);
	}	

	if (is_server_local_.load(std::memory_order_relaxed)) {
		strbuf.appendfmt(" : Server \'%s\' is from this host : Server PID %d TID %d NetNS Inode %ld : Server Socket Inode %ld : Server UID %u ", 
				ser_comm_, ser_pid_, ser_tid_, ser_ns_inode_.load(std::memory_order_relaxed), ser_sock_inode_, ser_uid_);
	}	
	else if (ser_glob_id_) {
		strbuf.appendfmt(" : Remote Server \'%s\' : Remote Server Madhava ID %016lx : %s Cluster ", ser_comm_, ser_madhava_id_, cli_ser_diff_clusters_ ? "Different" : "Same");
	}	

	if (ser_glob_id_) {
		strbuf.appendfmt(" : Server Global ID %016lx ", ser_glob_id_);
	}	

	if (true == is_cluster_listen_) {
		strbuf.appendconst(" : Service Mesh Listener ");
	}	

	if (*server_domain_) {
		strbuf.appendfmt(" : Server DNS %s ", server_domain_);
	}	

	if (print_stats) {
		stats_.print_tcpinfo_str(strbuf);
	}	

	return strbuf.buffer();
}	

void TCP_CONN::set_notify_elem(comm::TCP_CONN_NOTIFY *pnot, uint64_t close_usec_time, const char *pcli_cmdline, size_t cli_cmdline_len) const noexcept
{
	using namespace			comm;

	pnot->cli_			= cli_;
	pnot->ser_			= ser_;
	pnot->nat_cli_			= nat_cli_;
	pnot->nat_ser_			= nat_ser_;

	pnot->tusec_start_		= tusec_start_;
	pnot->tusec_close_		= close_usec_time;

	pnot->cli_task_aggr_id_		= cli_task_aggr_id_;
	pnot->cli_related_listen_id_	= (uint64_t)(uintptr_t)(cli_related_listen_shr_.get());
	pnot->cli_madhava_id_		= cli_madhava_id_;

	pnot->ser_related_listen_id_	= ser_related_listen_id_;
	pnot->ser_glob_id_		= ser_glob_id_;
	pnot->ser_madhava_id_		= ser_madhava_id_;

	pnot->bytes_sent_		= stats_.bytes_acked;
	pnot->bytes_rcvd_		= stats_.bytes_received;

	pnot->cli_pid_			= cli_pid_;
	pnot->ser_pid_			= ser_pid_;
	pnot->ser_conn_hash_		= conn_hash_;
	pnot->ser_sock_inode_		= uint32_t(ser_sock_inode_);

	pnot->is_tcp_connect_event_	= is_tcp_connect_event_;
	pnot->is_tcp_accept_event_	= is_tcp_accept_event_;
	pnot->is_loopback_conn_		= is_tcp_connect_event_ && is_tcp_accept_event_;
	pnot->is_pre_existing_		= is_existing_conn_;
	
	pnot->cli_ser_machine_id_	= peer_machine_id_;

	pnot->notified_before_		= server_updated_.load(std::memory_order_acquire);
	
	server_updated_.store(true, std::memory_order_release);

	std::memcpy(pnot->cli_comm_, cli_comm_, sizeof(cli_comm_));
	std::memcpy(pnot->ser_comm_, ser_comm_, sizeof(ser_comm_));
	
	if (pcli_cmdline && cli_cmdline_len) {
		pnot->cli_cmdline_len_	= 1 + std::min(comm::MAX_PROC_CMDLINE_LEN - 1, cli_cmdline_len);
		std::memcpy((char *)(pnot + 1), pcli_cmdline, pnot->cli_cmdline_len_);
		*((char *)pnot + sizeof(*pnot) + pnot->cli_cmdline_len_ - 1) = 0;
	}
	else {
		pnot->cli_cmdline_len_	= 0;
	}	

	pnot->set_padding_len();
}


TCP_LISTENER::TCP_LISTENER(const GY_IP_ADDR & addr, uint16_t port, ino_t nsinode, pid_t pid, uint32_t listen_hash, int backlog, std::weak_ptr <TASK_STAT> task, \
			std::shared_ptr <SHR_TASK_HASH_TABLE> listen_table, const char *pcomm, const char *pcmdline, bool is_pre_existing, uint64_t curr_tusec)
		: 
		ns_ip_port_(addr, port, nsinode), is_any_ip_(addr.is_any_address()), is_root_netns_(SYS_HARDWARE::get_root_ns_inodes()->net_inode == nsinode),
		task_weak_(std::move(task)), listen_task_table_(std::move(listen_table)), pid_(pid), backlog_(backlog),  
		clock_usec_(get_usec_clock()), start_clock_usec_(clock_usec_.load(std::memory_order_relaxed)), tstart_usec_(curr_tusec), listen_hash_(listen_hash),
		last_query_clock_(get_sec_clock()), qps_hist_(last_query_clock_), last_conn_clock_(last_query_clock_), active_conn_hist_(last_query_clock_),
		resp_cache_v4_(&resp_hist_), is_pre_existing_(is_pre_existing), resp_cache_v6_(&resp_hist_)
{
	if (pcomm) {
		GY_STRNCPY(comm_, pcomm, sizeof(comm_));
	}	

	if (pcmdline) {
		GY_STRNCPY(cmdline_, pcmdline, sizeof(cmdline_));

		if (pcomm) {
			set_aggr_glob_id();
		}	
	}	

	alignas(4) char		hashbuf[2 * sizeof(uint64_t) + TASK_COMM_LEN + sizeof(uint32_t)];
	char			comm[TASK_COMM_LEN] {};
	uint32_t		nsipport_hash = ns_ip_port_.get_hash(false /* ignore_ip */);

	GY_STRNCPY(comm, comm_, sizeof(comm));

	std::memcpy(hashbuf, &TCP_SOCK_HANDLER::get_singleton()->machineid_.machid_, 2 * sizeof(uint64_t));
	std::memcpy(hashbuf + 2 * sizeof(uint64_t), comm, TASK_COMM_LEN);
	std::memcpy(hashbuf + 2 * sizeof(uint64_t) + TASK_COMM_LEN, &nsipport_hash, sizeof(uint32_t));

	glob_id_ = gy_cityhash64(hashbuf, sizeof(hashbuf));
}	

void TCP_LISTENER::set_aggr_glob_id() noexcept
{
	alignas(8) char			hashbuf[TASK_COMM_LEN + sizeof(uint32_t)] {};
	uint32_t			ipport_hash = ns_ip_port_.ip_port_.get_hash();

	GY_STRNCPY(hashbuf, comm_, TASK_COMM_LEN);
	std::memcpy(hashbuf + TASK_COMM_LEN, &ipport_hash, sizeof(uint32_t));

	aggr_glob_id_ = gy_cityhash64(hashbuf, sizeof(hashbuf));
}	

size_t TCP_LISTENER::get_pids_for_uprobe(pid_t *pidarr, size_t maxpids) const noexcept
{
	try {
		using PID_HASH_MAP		= INLINE_STACK_HASH_MAP<pid_t, std::pair<int, bool>, 24 * 1024, GY_JHASHER<pid_t>>;

		PID_HASH_MAP			pidmap;
		auto 				shrlisten = listen_task_table_.load(mo_relaxed);

		if (!shrlisten) {
			return 0;
		}
		
		auto proc_lambda = [&](SHR_TASK_ELEM_TYPE *pdatanode, void *arg) -> CB_RET_E
		{
			auto			ptask = pdatanode->get_cref().get();

			if (ptask && (TASK_STATE_EXITED != ptask->task_valid.load(std::memory_order_relaxed))) {
				
				auto			[it, success] = pidmap.try_emplace(ptask->task_pid, 0, true);

				if (!success) {
					it->second.second = true;
				}

				if (ptask->parent_pgid > 1 && ptask->is_execv_task == false) {
					auto			[it2, success2] = pidmap.try_emplace(ptask->parent_pgid, 1, false);				

					if (!success2) {
						it2->second.first++;
					}	
				}	
				return CB_OK;
			}

			return CB_OK;
		};	
		
		shrlisten->walk_hash_table_const(proc_lambda); 	

		pid_t				tarr[MAX_SVC_SSL_PROCS] 	{};
		int				n = 0;

		for (const auto & [key, val] : pidmap) {
			if (val.second && val.first > 0) {
				tarr[n] = key;

				if (++n == GY_ARRAY_SIZE(tarr)) {
					break;
				}	
			}	
		}	
		
		if ((unsigned)n < GY_ARRAY_SIZE(tarr) - 1) {
			for (const auto & [key, val] : pidmap) {
				if (val.second && val.first == 0) {
					tarr[n] = key;

					if (++n == GY_ARRAY_SIZE(tarr)) {
						break;
					}	
				}	
			}	
		}	

		maxpids = std::min(maxpids, (size_t)n);

		std::memcpy(pidarr, tarr, maxpids * sizeof(*pidarr));

		return maxpids;
	}
	GY_CATCH_EXPRESSION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while checking listener for pids to probe %s\n", GY_GET_EXCEPT_STRING););
		return 0;
	);
}

bool TCP_LISTENER::is_task_issue(uint64_t clock_usec, uint32_t & tasks_delay_usec, uint32_t & tasks_cpudelay_usec, uint32_t & tasks_blkiodelay_usec, bool & is_severe, bool & is_delay, int & ntasks_issue, int & ntasks_noissue, int & tasks_user_cpu, int & tasks_sys_cpu, int & tasks_rss_mb) noexcept
{
	int 			ret;
	uint8_t			issue_bit, severe_bit;
	bool			is_issue = false, severe = false;
	size_t			sret;
	int64_t			totdelnsec = 0, totcpudelaynsec = 0, totblkiodelaynsec = 0, totrss;
	float			ucpu, scpu;

	is_severe		= false;
	is_delay		= false;
	ntasks_issue 		= 0;
	ntasks_noissue 		= 0;

	auto relshrlisten 	= related_listen_.load(std::memory_order_relaxed);
	auto shrlisten 		= listen_task_table_.load(std::memory_order_relaxed);

	if (!shrlisten || !relshrlisten) {
		return false;
	}
	
	auto 			& status = relshrlisten->task_status_;
	
	ret = status.recent_task_issue(clock_usec, tasks_delay_usec, tasks_cpudelay_usec, tasks_blkiodelay_usec, issue_bit, severe_bit, is_delay, ntasks_issue, ntasks_noissue, 
				tasks_user_cpu, tasks_sys_cpu, tasks_rss_mb);

	if (ret == 0) {
		is_issue 	= !!issue_bit;
		is_severe	= !!severe_bit;
	}
	else {
		ucpu 	= 0;
		scpu 	= 0;
		totrss = 0; 

		// We need to scan individual task weak ptrs again : Update the shared_ptr task_status_ for subsequent related listeners
		auto proc_lambda = [&](SHR_TASK_ELEM_TYPE *pdatanode, void *arg) mutable -> CB_RET_E
		{
			auto			ptask = pdatanode->get_cref().get();

			if (ptask && (TASK_STATE_EXITED != ptask->task_valid.load(std::memory_order_relaxed))) {
				if (!ptask->pext_stats) {
					return CB_OK;
				}

				auto			pext = ptask->pext_stats.get();
				auto 			pcpustat = &pext->cpu_mem_io_;

				ucpu 			+= pcpustat->usercpu_pct_hist[0];
				scpu			+= pcpustat->syscpu_pct_hist[0];

				totrss 			+= pcpustat->rss;

				auto 			[lis_issue, lsevere, lstate, lissue] = pext->is_recent_task_issue(0x3);

				auto			pdelay = pext->pdelay_stats_.get();

				if (pdelay) {
					/*
					 * We add up delays of all Listener procs...
					 */
					uint64_t		cpudel = pdelay->cpu_delay_nsec_[0], blkiodel = pdelay->blkio_delay_nsec_[0];

					totdelnsec += cpudel + blkiodel + pdelay->swapin_delay_nsec_[0] + pdelay->reclaim_delay_nsec_[0] + pdelay->thrashing_delay_nsec_[0];
					totcpudelaynsec += cpudel;
					totblkiodelaynsec += blkiodel;
				}

				if (lstate > STATE_OK) {
					is_issue = true;
					is_severe |= lsevere;
					
					ntasks_issue++;
				}
				else {
					ntasks_noissue++;
				}

				is_delay |= ((lissue > ISSUE_TASK_NONE && lissue < ISSUE_VOL_CONTEXT_SWITCH) || (totdelnsec > 50 * (int64_t)GY_NSEC_PER_MSEC));
				
				return CB_OK;
			}

			return CB_DELETE_ELEM;
		};	
		
		sret = shrlisten->walk_hash_table(proc_lambda); 	
		
		if (sret > 0) {
			tasks_user_cpu 		= ucpu;
			tasks_sys_cpu 		= scpu;

			tasks_delay_usec	= totdelnsec/1000;
			tasks_cpudelay_usec	= totcpudelaynsec/1000;
			tasks_blkiodelay_usec	= totblkiodelaynsec/1000;

			tasks_rss_mb		= GY_DOWN_MB(totrss);

			status.set_task_issue(clock_usec, totdelnsec/1000, totcpudelaynsec/1000, totblkiodelaynsec/1000, is_issue, is_severe, is_delay, ntasks_issue, ntasks_noissue, 
							tasks_user_cpu, tasks_sys_cpu, tasks_rss_mb);		
		}		
	}	

	return is_issue;
}	

void TCP_LISTENER::get_curr_state(OBJ_STATE_E & lstate, LISTENER_ISSUE_SRC & lissue, STR_WR_BUF & strbuf, time_t tcur, uint64_t clock_usec, int curr_active_conn, float multiple_factor, bool cpu_issue, bool mem_issue, uint32_t ser_errors, void *ptaskstatus, comm::LISTENER_DAY_STATS *pstatn) noexcept
{
	GY_NOMT_COLLECT_PROFILE(1000, "Get the Current Listener Response State");

	try {
		const time_t			last_add_time = resp_hist_.get_last_add_time(), inittime = resp_hist_.get_init_time();
		const time_t			tdiff_start = (last_add_time > inittime ?  last_add_time - inittime + 1 : (tcur > inittime + 1 ? tcur - inittime + 1 : 1));

		int				ret, ntasks_issue, ntasks_noissue, tmax_qps, tmax_active, avg_5day_qps, curr_qps;
		const int			nconn = last_chk_nconn_;
		size_t				nqrys_5s, tcount_qps, tcount_active, b5, b300, b5day, b;

		uint64_t			total_resp_msec, tasks_delay_msec;
		bool				is_severe, is_delay;

		auto 				& taskstatus = *(RELATED_LISTENERS::LISTENER_TASK_STATUS *)ptaskstatus;

		const bool			task_issue = is_task_issue(clock_usec, taskstatus.tasks_delay_usec_, taskstatus.tasks_cpudelay_usec_, taskstatus.tasks_blkiodelay_usec_, 
								is_severe, is_delay, ntasks_issue, ntasks_noissue, taskstatus.tasks_user_cpu_, taskstatus.tasks_sys_cpu_, taskstatus.tasks_rss_mb_);

		taskstatus.last_ntasks_issue_	= ntasks_issue;
		taskstatus.last_ntasks_noissue_	= ntasks_noissue;
		tasks_delay_msec 		= taskstatus.tasks_delay_usec_/1000;

		time_t				sec_dist_arr[RESP_HISTOGRAM::ntime_levels]; 
		int64_t				r5p95, r5p99, r300p95, r300p99, r5daysp95, rallp95, r5daysp99, r5daysp25, rallp99;
		HIST_DATA 			stats_qps[] {95, 25}, stats_active[] {95, 25};

		static constexpr int		n5 	= get_level_from_time_offset<RESP_HISTOGRAM>(std::chrono::seconds(5));
		static constexpr int		n300 	= get_level_from_time_offset<RESP_HISTOGRAM>(std::chrono::seconds(300));
		static constexpr int		n5days 	= get_level_from_time_offset<RESP_HISTOGRAM>(std::chrono::seconds(5 * 24 * 3600));
		static constexpr int		nall 	= get_level_from_time_offset<RESP_HISTOGRAM>(std::chrono::seconds(0));

		static_assert(n5 >= 0, 		"Please sync with the RESP_HISTOGRAM time levels");
		static_assert(n300 >= 0, 	"Please sync with the RESP_HISTOGRAM time levels");
		static_assert(n5days >= 0, 	"Please sync with the RESP_HISTOGRAM time levels");
		static_assert(nall >= 0, 	"Please sync with the RESP_HISTOGRAM time levels");
		
		static constexpr int64_t	msec1_bucket = get_bucketid_from_threshold<RESP_TIME_HASH>(1L);

		for (size_t i = 0; i < RESP_HISTOGRAM::ntime_levels; i++) {
			if (RESP_HISTOGRAM::dist_seconds[i].count() > 0) {
				sec_dist_arr[i] = (RESP_HISTOGRAM::dist_seconds[i].count() < tdiff_start ? RESP_HISTOGRAM::dist_seconds[i].count() : tdiff_start);
			}
			else {	
				sec_dist_arr[i] = tdiff_start;
			}
		}

		/*
		 * Get the 5 sec, last 5 days and all p95/p99 Response 
		 */
		nqrys_5s	= histstat_[n5].tcount_;
		 
		r5p95 		= histstat_[n5].stats_[0].data_value;
		r5p99 		= histstat_[n5].stats_[1].data_value;
		r300p95		= histstat_[n300].stats_[0].data_value;
		r300p99		= histstat_[n300].stats_[1].data_value;
		r5daysp95	= histstat_[n5days].stats_[0].data_value;
		r5daysp99	= histstat_[n5days].stats_[1].data_value;
		r5daysp25	= histstat_[n5days].stats_[2].data_value;
		rallp95		= histstat_[nall].stats_[0].data_value;
		rallp99		= histstat_[nall].stats_[1].data_value;
		 
		curr_qps	= std::max<int>(last_qps_count_, histstat_[n5].tcount_/5);

		b5 		= get_bucketid_from_threshold<RESP_TIME_HASH>(r5p95);
		b300 		= get_bucketid_from_threshold<RESP_TIME_HASH>(r300p95);
		b5day		= get_bucketid_from_threshold<RESP_TIME_HASH>(r5daysp95);

		qps_hist_.get_percentiles(stats_qps, GY_ARRAY_SIZE(stats_qps), tcount_qps, tmax_qps);
		active_conn_hist_.get_percentiles(stats_active, GY_ARRAY_SIZE(stats_active), tcount_active, tmax_active);
			
		if (pstatn) {
			if ((uint64_t)tcur > tstart_usec_/GY_USEC_PER_SEC + 15 * 60) {
				pstatn->glob_id_	= glob_id_;
				pstatn->tcount_5d_	= histstat_[n5days].tcount_;
				pstatn->tsum_5d_	= histstat_[n5days].tsum_;
				pstatn->p95_5d_respms_	= r5daysp95;
				pstatn->p25_5d_respms_	= r5daysp25;

				pstatn->p95_qps_	= stats_qps[0].data_value;
				pstatn->p25_qps_	= stats_qps[1].data_value;

				pstatn->p95_nactive_	= stats_active[0].data_value;
				pstatn->p25_nactive_	= stats_active[1].data_value;
			}
			else {
				std::memset(pstatn, 0, sizeof(*pstatn));
			}	
		}	
			
		high_resp_bit_hist_ <<= 1;
			
		if (curr_qps == 0) {
			if (!task_issue || !is_severe || !ser_errors) {
				lissue		= ISSUE_LISTEN_NONE;
				lstate		= STATE_IDLE;
				
				if (nqrys_5s) {
					strbuf.appendconst("State Idle : Very few Queries seen recently");
				}
				else {
					strbuf.appendconst("State Idle : No Queries seen recently");
				}	
				return;	
			}		
		}
				
		total_resp_msec 	= histstat_[n5].tsum_;

		if ((b5 == msec1_bucket) || (r5p95 < r5daysp95)) {
			/*
			 * 5 sec p95 <= 1 msec or < 5 days p95. Check if QPS is too low
			 */ 
			if (curr_qps <= stats_qps[1].data_value && stats_qps[1].data_value < stats_qps[0].data_value) {
				// QPS too low. Check if procs OK. If so, no issues
				if (!task_issue && !ser_errors) {
					lissue		= ISSUE_LISTEN_NONE;
					lstate		= STATE_IDLE;
					
					strbuf.appendconst("State Idle : Low Response Time and Low QPS currently");
					strbuf.appendfmt(" : Response %ld msec : QPS %d", r5p95, curr_qps);
					return;	
				}		
				else if (!task_issue && ser_errors) {
					if (ser_errors * 2 > nqrys_5s) {
						lissue		= ISSUE_SERVER_ERRORS;
						lstate		= STATE_SEVERE;
						
						strbuf.appendconst("State SEVERE : Many Server Errors seen with no Process Issues and Low Response Time and Low QPS ");
						strbuf.appendfmt(" : Response %ld msec : QPS %d : Server Errors %u", r5p95, curr_qps, ser_errors);
						return;	
					}
					else if (ser_errors * 5 > nqrys_5s) {
						lissue		= ISSUE_SERVER_ERRORS;
						lstate		= STATE_BAD;
						
						strbuf.appendconst("State Bad : Server Errors seen with no Process Issues and Low Response Time and Low QPS ");
						strbuf.appendfmt(" : Response %ld msec : QPS %d : Server Errors %u", r5p95, curr_qps, ser_errors);
						return;	
					}
					else if (ser_errors < nqrys_5s * 0.1) {
						lissue		= ISSUE_SERVER_ERRORS;
						lstate		= STATE_OK;
						
						strbuf.appendconst("State Idle : Low Response Time and Low QPS currently but few Server Errors seen");
						strbuf.appendfmt(" : Response %ld msec : QPS %d : Server Errors %u", r5p95, curr_qps, ser_errors);
						return;	
					}
				}		
				else {
					// There is a task issue 
					if (ser_errors * 2 > nqrys_5s) {
						lissue		= ISSUE_SERVER_ERRORS;
						lstate		= STATE_SEVERE;
						
						strbuf.appendconst("State SEVERE : Many Server Errors seen with Process Issues and Low Response Time and Low QPS ");
						strbuf.appendfmt(" : Response %ld msec : QPS %d : Server Errors %u : Listener Procs with issues %d", r5p95, curr_qps, ser_errors, ntasks_issue);
						return;	
					}
					else if (ser_errors * 5 > nqrys_5s) {
						lissue		= ISSUE_SERVER_ERRORS;
						lstate		= STATE_BAD;
						
						strbuf.appendconst("State Bad : Server Errors seen with Process Issues and Low Response Time and Low QPS ");
						strbuf.appendfmt(" : Response %ld msec : QPS %d : Server Errors %u : Listener Procs with issues %d", r5p95, curr_qps, ser_errors, ntasks_issue);
						return;	
					}
					else if (ser_errors) {
						lissue	= ISSUE_LISTENER_TASKS;
						lstate	= STATE_BAD;

						strbuf.appendconst("State Bad : Low Response Time but Listener Processes have issues and Server Errors seen which may be causing the Low QPS and Response");
						strbuf.appendfmt(" : Response %ld msec : QPS %d : Server Errors %u : Listener Procs with issues %d", r5p95, curr_qps, ser_errors, ntasks_issue);
						return;
					}

					if (is_severe && (ntasks_issue > 0) && (ntasks_noissue == 0)) {
						lissue	= ISSUE_LISTENER_TASKS;
						lstate	= STATE_BAD;

						strbuf.appendconst(
							"State Bad : Low Response Time but all Listener Processes have severe issues which may be causing the Low QPS and Response");
						strbuf.appendfmt(" : Response %ld msec : QPS %d : Listener Procs with issues %d", r5p95, curr_qps, ntasks_issue);
						return;
					}	
					// Check if the number of conns is > p25 of active conns
					if (nconn > stats_active[1].data_value) {
						// We can't determine if the low qps is due to low client traffic or due to task issue
						lissue	= ISSUE_LISTENER_TASKS;
						lstate	= STATE_OK;

						strbuf.appendconst(
							"State OK : Low Response Time but some Listener Processes have issues which may be causing the Low QPS and Response");
						strbuf.appendfmt(" : Response %ld msec : QPS %d : Listener Procs with issues %d", r5p95, curr_qps, ntasks_issue);
						return;
					}	
				}	
			}	 

			if (ser_errors) {
				if (ser_errors * 2 > nqrys_5s) {
					lissue		= ISSUE_SERVER_ERRORS;
					lstate		= STATE_SEVERE;
					
					if (!task_issue) {
						strbuf.appendconst("State SEVERE : Many Server Errors seen with no Process Issues and lower Response Time");
						strbuf.appendfmt(" : Response %ld msec : QPS %d : Server Errors %u", r5p95, curr_qps, ser_errors);
					}
					else {
						strbuf.appendconst("State SEVERE : Many Server Errors and Listener Processes have issues");
						strbuf.appendfmt(" : Response %ld msec : QPS %d : Server Errors %u : Listener Procs with issues %d", r5p95, curr_qps, ser_errors, ntasks_issue);
					}	
					return;	
				}
				else if (ser_errors * 5 > nqrys_5s) {
					lissue		= ISSUE_SERVER_ERRORS;
					lstate		= STATE_BAD;
					
					if (!task_issue) {
						strbuf.appendconst("State Bad : Server Errors seen with no Process Issues and Lower Response Time");
						strbuf.appendfmt(" : Response %ld msec : QPS %d : Server Errors %u", r5p95, curr_qps, ser_errors);
					}
					else {
						strbuf.appendconst("State Bad : Many Server Errors and Listener Processes have issues");
						strbuf.appendfmt(" : Response %ld msec : QPS %d : Server Errors %u : Listener Procs with issues %d", r5p95, curr_qps, ser_errors, ntasks_issue);
					}	
					return;	
				}
			}		

			if (task_issue && is_severe && (ntasks_issue > 0) && (ntasks_noissue == 0)) {
				lissue	= ISSUE_LISTENER_TASKS;
				lstate	= STATE_BAD;

				if (ser_errors == 0) {
					strbuf.appendconst("State Bad : Low Response Time but all Listener Processes have severe issues which may be causing the Low Response");
					strbuf.appendfmt(" : Response %ld msec : QPS %d : Listener Procs with issues %d", r5p95, curr_qps, ntasks_issue);
				}
				else {
					strbuf.appendconst("State Bad : Server Errors and Listener Processes have issues");
					strbuf.appendfmt(" : Response %ld msec : QPS %d : Server Errors %u : Listener Procs with issues %d", r5p95, curr_qps, ser_errors, ntasks_issue);
				}	
				return;
			}	
			
			if (!ser_errors) {
				if (curr_qps <= stats_qps[0].data_value || (b5 + 2 <= b5day /* Too Fast a response */))  {
					lissue	= ISSUE_LISTEN_NONE;
					lstate	= STATE_GOOD;

					if (curr_qps <= stats_qps[0].data_value) {
						strbuf.appendconst("State Good : Low Response Time with QPS not too high");
					}
					else {	
						strbuf.appendconst("State Good : Extremely low response time with high QPS");
					}
					strbuf.appendfmt(" : Response %ld msec : QPS %d", r5p95, curr_qps);
				}
				else if (curr_qps > stats_qps[0].data_value) {
					lissue	= ISSUE_QPS_HIGH;
					lstate	= STATE_OK;
					
					strbuf.appendconst("State OK : Current Response is lower than historical Response but QPS is higher than the 95th percentile QPS");
					strbuf.appendfmt(" : Response %ld msec : QPS %d", r5p95, curr_qps);
				}	
			}
			else {
				lissue	= ISSUE_SERVER_ERRORS;
				lstate	= STATE_OK;
				
				strbuf.appendconst("State OK : Some Server Errors seen but Current Response is lower than historical Response but QPS is higher than the 95th percentile QPS");
				strbuf.appendfmt(" : Response %ld msec : QPS %d : Server Errors %u", r5p95, curr_qps, ser_errors);
			}	
				
			return;
		}	
		
		if (r5p95 == r5daysp95) {
			if (ser_errors) {
				if (ser_errors * 2 > nqrys_5s) {
					lissue		= ISSUE_SERVER_ERRORS;
					lstate		= STATE_SEVERE;
					
					if (!task_issue) {
						strbuf.appendconst("State SEVERE : Many Server Errors seen with no Process Issues");
						strbuf.appendfmt(" : Response %ld msec : QPS %d : Server Errors %u", r5p95, curr_qps, ser_errors);
					}
					else {
						strbuf.appendconst("State SEVERE : Many Server Errors and Listener Processes have issues");
						strbuf.appendfmt(" : Response %ld msec : QPS %d : Server Errors %u : Listener Procs with issues %d", r5p95, curr_qps, ser_errors, ntasks_issue);
					}	
					return;	
				}
				else if (ser_errors * 5 > nqrys_5s) {
					lissue		= ISSUE_SERVER_ERRORS;
					lstate		= STATE_BAD;
					
					if (!task_issue) {
						strbuf.appendconst("State Bad : Server Errors seen with no Process Issues");
						strbuf.appendfmt(" : Response %ld msec : QPS %d : Server Errors %u", r5p95, curr_qps, ser_errors);
					}
					else {
						strbuf.appendconst("State Bad : Many Server Errors and Listener Processes have issues");
						strbuf.appendfmt(" : Response %ld msec : QPS %d : Server Errors %u : Listener Procs with issues %d", r5p95, curr_qps, ser_errors, ntasks_issue);
					}	
					return;	
				}
			}		

			// First check the overall avg for the 2 durations
			if (histstat_[n5].mean_val_ <= histstat_[n5days].mean_val_ * 0.8f) {

				if (curr_qps <= stats_qps[1].data_value) {
					// QPS too low. Check if procs OK. If so, no issues
					if (ser_errors) {
						lissue		= ISSUE_SERVER_ERRORS;
						lstate		= STATE_BAD;
						
						if (!task_issue) {
							strbuf.appendconst("State Bad : Some Server Errors seen with no Process Issues and low QPS");
							strbuf.appendfmt(" : Response %ld msec : QPS %d : Server Errors %u", r5p95, curr_qps, ser_errors);
						}
						else {
							strbuf.appendconst("State Bad : Some Server Errors and Listener Processes have issues with low QPS");
							strbuf.appendfmt(" : Response %ld msec : QPS %d : Server Errors %u : Listener Procs with issues %d", r5p95, curr_qps, ser_errors, ntasks_issue);
						}	
						return;	
					}	
					else if (!task_issue) {
						lissue		= ISSUE_LISTEN_NONE;
						lstate		= STATE_IDLE;
						
						strbuf.appendconst("State Idle : Low Response Time and Low QPS currently");
						strbuf.appendfmt(" : Response %ld msec : QPS %d", r5p95, curr_qps);
						return;	
					}		
					else if ((ntasks_issue > 0) && (ntasks_noissue == 0)) {
						lissue	= ISSUE_LISTENER_TASKS;
						lstate	= STATE_BAD;

						strbuf.appendconst(
							"State Bad : Low Response but all Listener Processes have issues which may be causing the Low QPS and Response");
						strbuf.appendfmt(" : Response %ld msec : QPS %d : Listener Procs with issues %d", r5p95, curr_qps, ntasks_issue);
						return;
					}	
					else if (ntasks_issue > 0 && tasks_delay_msec >= 1000) {
						lissue	= ISSUE_LISTENER_TASKS;
						lstate	= STATE_BAD;

						strbuf.appendconst(
							"State Bad : Low Response but some of the Listener Processes have issues and delays which may be causing the Low QPS and Response");
						strbuf.appendfmt(" : Response %ld msec : QPS %d : Listener Procs with issues %d", r5p95, curr_qps, ntasks_issue);
						return;
					}	
				}

				if (!task_issue && !ser_errors) {
					lissue		= ISSUE_LISTEN_NONE;
					lstate		= STATE_GOOD;
						
					strbuf.appendconst("State Good : Low Response Time currently");
					strbuf.appendfmt(" : Response %ld msec : QPS %d", r5p95, curr_qps);
					return;	
				}	
				else if (ser_errors) {
					if (task_issue) {
						lissue		= ISSUE_LISTENER_TASKS;
						lstate		= STATE_BAD;
							
						strbuf.appendconst("State Bad : Some Server Errors and Listener Processes have issues");
						strbuf.appendfmt(" : Response %ld msec : QPS %d : Server Errors %u : Listener Procs with issues %d", r5p95, curr_qps, ser_errors, ntasks_issue);
						return;	
					}

					lissue		= ISSUE_SERVER_ERRORS;
					lstate		= STATE_OK;
						
					strbuf.appendconst("State OK : Some Server Errors seen with no Process Issues");
					strbuf.appendfmt(" : Response %ld msec : QPS %d : Server Errors %u", r5p95, curr_qps, ser_errors);
				}	

				lissue	= ISSUE_LISTENER_TASKS;
				lstate	= STATE_OK;

				strbuf.appendconst("State OK : Current Response is less than historical Response but Listener Process(es) have issues");
				strbuf.appendfmt(" : Response %ld msec : QPS %d : Listener Procs with issues %d", r5p95, curr_qps, ntasks_issue);
				return;
			}

			if (histstat_[n5].mean_val_ <= histstat_[n5days].mean_val_ * 1.2f) {

				lissue	= ISSUE_LISTEN_NONE;
				lstate	= STATE_OK;

				strbuf.appendconst("State OK : Current Response is similar to historical Response");
				strbuf.appendfmt(" : Response %ld msec : QPS %d", r5p95, curr_qps);
				return;
			}
		}	

		high_resp_bit_hist_ |= 1;

		if (ser_errors) {
			if (ser_errors * 2 > nqrys_5s) {
				lissue		= ISSUE_SERVER_ERRORS;
				lstate		= STATE_SEVERE;
				
				if (!task_issue) {
					strbuf.appendconst("State SEVERE : Many Server Errors seen with no Process Issues and High Response");
					strbuf.appendfmt(" : Response %ld msec : QPS %d : Server Errors %u", r5p95, curr_qps, ser_errors);
				}
				else {
					strbuf.appendconst("State SEVERE : Many Server Errors and Listener Processes have issues with High Response");
					strbuf.appendfmt(" : Response %ld msec : QPS %d : Server Errors %u : Listener Procs with issues %d", r5p95, curr_qps, ser_errors, ntasks_issue);
				}	
				return;	
			}
			else if (ser_errors * 5 > nqrys_5s) {
				lissue		= ISSUE_SERVER_ERRORS;
				lstate		= STATE_BAD;
				
				if (!task_issue) {
					strbuf.appendconst("State Bad : Server Errors seen with no Process Issues and High Response");
					strbuf.appendfmt(" : Response %ld msec : QPS %d : Server Errors %u", r5p95, curr_qps, ser_errors);
				}
				else {
					strbuf.appendconst("State Bad : Many Server Errors and Listener Processes have issues with High Response");
					strbuf.appendfmt(" : Response %ld msec : QPS %d : Server Errors %u : Listener Procs with issues %d", r5p95, curr_qps, ser_errors, ntasks_issue);
				}	
				return;	
			}
		}		

		// Check if QPS too high
		if ((curr_qps > stats_qps[0].data_value) && (curr_qps - stats_qps[0].data_value > 5) && (curr_qps > stats_qps[0].data_value * 1.1f)) {
			lissue	= ISSUE_QPS_HIGH;

			if ((b5 > b5day + 2) && (b5 > b300)) {
				lstate	= STATE_SEVERE;
				strbuf.appendconst("State SEVERE : Current Response is much higher than historical Response likely due to QPS being very high");
				if (ser_errors) {
					strbuf.appendconst(" and some Server Errors");
				}
				strbuf.appendfmt(" : Response %ld msec : QPS %d : p95 QPS %ld", r5p95, curr_qps, stats_qps[0].data_value);
			}
			else {	
				lstate	= STATE_BAD;
				strbuf.appendconst("State Bad : Current Response is higher than historical Response likely due to QPS being very high");
				if (ser_errors) {
					strbuf.appendconst(" and some Server Errors");
				}
				strbuf.appendfmt(" : Response %ld msec : QPS %d : p95 QPS %ld", r5p95, curr_qps, stats_qps[0].data_value);
			}	
			
			if (ser_errors) {
				strbuf.appendfmt(" : Server Errors %u", ser_errors);
			}

			return;
		}	

		/*
		 * Check if task_issue is flagged. Else check if multiple listener procs and delays across multiple procs is at least 25% of total response.
		 */
		if (task_issue || (is_delay && ntasks_issue + ntasks_noissue > 2 && tasks_delay_msec * 4 > total_resp_msec)) {
			lissue	= ISSUE_LISTENER_TASKS;

			if ((b5 > b5day + 2) && (b5 > b300)) {
				lstate	= STATE_SEVERE;
				strbuf.appendconst("State SEVERE : Current Response is much higher than historical Response as Listener Process(es) have issues");
			}
			else {	
				lstate	= STATE_BAD;
				strbuf.appendconst("State Bad : Current Response is higher than historical Response as Listener Process(es) have issues");
			}	

			if (ser_errors) {
				strbuf.appendconst(" and some Server Errors");
			}

			if (task_issue) {
				strbuf.appendfmt(" : Response %ld msec : QPS %d : Listener Procs with issues %d", r5p95, curr_qps, ntasks_issue);
			}	
			else {
				strbuf.appendfmt(" : Listener procs delay %lu msec : Response %ld msec : QPS %d", tasks_delay_msec, r5p95, curr_qps);
			}	

			if (ser_errors) {
				strbuf.appendfmt(" : Server Errors %u", ser_errors);
			}

			return;
		}	 	

		// Check if Active Conns too high
		if (curr_active_conn > stats_active[0].data_value && (curr_active_conn - stats_active[0].data_value > 1)) {
			lissue	= ISSUE_ACTIVE_CONN_HIGH;

			if (((b5 > b5day + 2) && (b5 > b300)) && (curr_active_conn > 10)) {
				lstate	= STATE_SEVERE;
				strbuf.appendconst("State SEVERE : Current Response is much higher than the historical and last 5 min Response");
			}
			else {	
				lstate	= STATE_BAD;
				strbuf.appendconst("State Bad : Current Response is higher than historical Response");
			}	

			strbuf.appendconst(" likely due to Active Connections being higher than usual");
			if (ser_errors) {
				strbuf.appendconst(" and some Server Errors");
			}

			strbuf.appendfmt(" : Response %ld msec : QPS %d : Active Connections %d : p95 Active Conns %ld", 
				r5p95, curr_qps, curr_active_conn, stats_active[0].data_value);

			if (ser_errors) {
				strbuf.appendfmt(" : Server Errors %u", ser_errors);
			}

			return;
		}	

		if (r5p95 == r5daysp95) {
			// Check if 5 sec p99 is > 5 days p99. If so, then the higher overall avg of 5 sec is due to some outlier queries
			if (r5p99 > r5daysp99) {
				lissue	= ISSUE_LISTEN_NONE;
				lstate	= STATE_OK;

				strbuf.appendconst("State OK : Current Response is similar to historical Response though a few queries are much slower");
				
				if (ser_errors) {
					lissue	= ISSUE_SERVER_ERRORS;
					strbuf.appendconst(" and some Server Errors");
				}

				strbuf.appendfmt(" : Response %ld msec : QPS %d", r5p95, curr_qps);

				if (ser_errors) {
					strbuf.appendfmt(" : Server Errors %u", ser_errors);
				}

				return;
			}	
		}
		
		// Check if QPS is too low and nconn is < p25 of active conn
		if ((curr_qps <= stats_qps[1].data_value) && (nconn <= stats_active[1].data_value)) {
			if (is_delay && cpu_issue && mem_issue) {
				lissue	= ISSUE_LISTENER_TASKS;
				lstate	= STATE_BAD;

				strbuf.appendconst("State Bad : Current Response is higher than historical but with low QPS and active connections"
							"due to Listener Process(es) delays and Host CPU and Memory Issues");
				
				if (ser_errors) {
					strbuf.appendconst(" and some Server Errors");
				}

				strbuf.appendfmt(" : Response %ld msec : QPS %d : Listener Procs with issues %d", r5p95, curr_qps, ntasks_issue);
				
				if (ser_errors) {
					strbuf.appendfmt(" : Server Errors %u", ser_errors);
				}

				return;
			}
			else if (is_delay && (cpu_issue || mem_issue) && (tasks_delay_msec * 4 > total_resp_msec)) {
				lissue	= ISSUE_LISTENER_TASKS;
				lstate	= STATE_BAD;

				strbuf.appendconst("State Bad : Current Response is higher than historical but with low QPS and active connections due to Listener Process(es) delays and Host Issues");
				
				if (ser_errors) {
					strbuf.appendconst(" and some Server Errors");
				}

				strbuf.appendfmt(" : Response %ld msec : QPS %d : Listener Procs with issues %d", r5p95, curr_qps, ntasks_issue);
				
				if (ser_errors) {
					strbuf.appendfmt(" : Server Errors %u", ser_errors);
				}

				return;
			}	

			lissue	= ISSUE_LISTEN_NONE;
			lstate	= STATE_OK;

			strbuf.appendconst("State OK : Current Response is higher than historical but client QPS and active connections are low which may account for this");
				
			if (ser_errors) {
				lissue	= ISSUE_SERVER_ERRORS;
				strbuf.appendconst(" and some Server Errors");
			}

			strbuf.appendfmt(" : Response %ld msec : QPS %d : Connections %d", r5p95, curr_qps, nconn);

			if (ser_errors) {
				strbuf.appendfmt(" : Server Errors %u", ser_errors);
			}

			return;
		}
		
		/*
		 * Check if Avg QPS over last 5 days is less than half of curr_qps and if r5p95 <= rallp95, things are OK
		 * as it could have been a long weekend earlier
		 */
		avg_5day_qps = histstat_[n5days].tcount_/sec_dist_arr[n5days];

		if ((avg_5day_qps < (curr_qps >> 1)) && (r5p95 <= rallp95) && (histstat_[n5].mean_val_ <= histstat_[nall].mean_val_ * 1.1f)) {
			lissue	= ISSUE_LISTEN_NONE;
			lstate	= STATE_OK;

			strbuf.appendconst("State OK : Current Response is similar to previous history although higher than historical response as historical QPS low");
				
			if (ser_errors) {
				lissue	= ISSUE_SERVER_ERRORS;
				strbuf.appendconst(" and some Server Errors");
			}

			strbuf.appendfmt(" : Response %ld msec : QPS %d", r5p95, curr_qps);

			if (ser_errors) {
				strbuf.appendfmt(" : Server Errors %u", ser_errors);
			}

			return;
		}

		// Check if curr_active_conn < p25 of active and qps is also very low and not too large a Response degradation
		if ((curr_qps <= stats_qps[1].data_value) && (curr_active_conn <= stats_active[1].data_value) && (b5 <= b5day + 1)) {
			lissue	= ISSUE_LISTEN_NONE;
			lstate	= STATE_OK;

			strbuf.appendconst("State OK : Current Response is higher than historical but client queries and active connections are very low which may account for this");
				
			if (ser_errors) {
				lissue	= ISSUE_SERVER_ERRORS;
				strbuf.appendconst(" and some Server Errors");
			}

			strbuf.appendfmt(" : Response %ld msec : QPS %d : Active Connections %d", r5p95, curr_qps, curr_active_conn);

			if (ser_errors) {
				strbuf.appendfmt(" : Server Errors %u", ser_errors);
			}

			return;
		}
		  
		/*
		 * Check if only the 5 sec p95 is higher, but the 300 sec p95 is similar which may be due to a transient effect
		 */  
		if ((b5 <= b5day + 1) && (b300 == b5day)) {
			if ((histstat_[n5].mean_val_ > histstat_[n300].mean_val_) && (histstat_[n300].mean_val_ < histstat_[n5days].mean_val_ * 1.1f)) {
				lissue	= ISSUE_LISTEN_NONE;
				lstate	= STATE_OK;

				strbuf.appendconst("State OK : Current Response is higher than historical but this may be a transient issue as the last 5 minutes is not high");
				
				if (ser_errors) {
					lissue	= ISSUE_SERVER_ERRORS;
					strbuf.appendconst(" and some Server Errors");
				}

				strbuf.appendfmt(" : Response %ld msec : QPS %d", r5p95, curr_qps);

				if (ser_errors) {
					strbuf.appendfmt(" : Server Errors %u", ser_errors);
				}

				return;
			}				
		}
			 
		/*
		 * Now check if the connection counts causing the higher response is not more than 3. If so,
		 * it could be a localized issue maybe a deadlock or something not affecting the other connections.
		 */
		if (curr_active_conn >= 15 && (b5 == b5day + 1)) {

			for (b = b5; b < RESP_TIME_HASH::max_buckets; ++b) {
				/*
				 * This is not foolproof as different client conns may be hashed to the same CONN_BITMAP hash slow 
				 */
				if (nactive_conn_arr_[b] > 3) {
					break;
				}	
			}	

			if (b > b5) {
				lissue	= ISSUE_LISTEN_NONE;
				lstate	= STATE_OK;

				strbuf.appendconst("State OK : Current Response is higher than historical but only a few connections may be affected by this");

				if (ser_errors) {
					lissue	= ISSUE_SERVER_ERRORS;
					strbuf.appendconst(" and some Server Errors");
				}

				strbuf.appendfmt(" : Response %ld msec : QPS %d : Active Connections %d", r5p95, curr_qps, curr_active_conn);

				if (ser_errors) {
					strbuf.appendfmt(" : Server Errors %u", ser_errors);
				}

				return;
			}	
		}	

		/*
		 * This may still be a transient spike or the response may be have large variations. We confirm using the high_resp_bit_hist_
		 */
		uint32_t		bithist = high_resp_bit_hist_;  
		int			nhigh;  
		
		nhigh = gy_count_bits_set(bithist);
		if (nhigh < 5) {
			// The response is high only upto half the time
			lissue	= ISSUE_LISTEN_NONE;
			lstate	= STATE_OK;

			strbuf.appendconst("State OK : Current Response is higher than historical but this is not consistent for the last few iterations");

			if (ser_errors) {
				lissue	= ISSUE_SERVER_ERRORS;
				strbuf.appendconst(" and some Server Errors");
			}

			strbuf.appendfmt(" : Response %ld msec : QPS %d : High Response Iteration Count %d", r5p95, curr_qps, nhigh);

			if (ser_errors) {
				strbuf.appendfmt(" : Server Errors %u", ser_errors);
			}

			return;
		}	  
		
		/*
		 * We have exhausted almost all explanations of the slowdown. 
		 */
		if ((b5 > b5day + 2) && (b5 > b300)) {
			lstate	= STATE_SEVERE;
			strbuf.appendconst("State SEVERE : Current Response is much higher than historical Response");
		}
		else {	
			lstate	= STATE_BAD;
			strbuf.appendconst("State Bad : Current Response is higher than historical Response");
		}	

		uint32_t			tasks_cpudelay_msec = taskstatus.tasks_cpudelay_usec_/1000, 
						tasks_blkiodelay_msec = taskstatus.tasks_blkiodelay_usec_/1000,
						tasks_vmdelay_msec = tasks_delay_msec - tasks_cpudelay_msec - tasks_blkiodelay_msec;

		/*
		 * Check if tasks were delayed though not more than historical delays. This could cause 
		 * Response Delays if the delays were within the Task Histogram p95 slot but within the same slot
		 * higher delays may be causing the response spike.
		 */
		if ((tasks_delay_msec * 4 > total_resp_msec) && (lstate == STATE_BAD)) {
			lissue	= ISSUE_LISTENER_TASKS;

			if (tasks_cpudelay_msec > 0 && tasks_vmdelay_msec && cpu_issue && mem_issue) {
				strbuf.appendconst(" which may be likely due to Listener Process CPU and VM Delays as Host CPU and Memory Issues exist");

			}
			else if (tasks_cpudelay_msec && cpu_issue) {
				strbuf.appendconst(" which may be likely due to Listener Process Delays though not too high as well as Host CPU Issues");
			}
			else {
				strbuf.appendconst(" which may be likely due to Listener Process Delays though not too high");
			}

			if (ser_errors) {
				strbuf.appendconst(" and some Server Errors");
			}

			strbuf.appendfmt(" : Response %ld msec : QPS %d : Active Connections %d : Proc Delays %lu msec", r5p95, curr_qps, curr_active_conn, tasks_delay_msec);

			if (ser_errors) {
				strbuf.appendfmt(" : Server Errors %u", ser_errors);
			}

			return;
		}	
		
		auto 		relshrlisten 	= related_listen_.load(std::memory_order_relaxed);
		size_t 		nserdepends = 0;
		
		if (relshrlisten) {
			nserdepends = relshrlisten->id_depends_.approx_count_fast();
		}
			
		if (nserdepends > 0) {
			lissue 	= ISSUE_DEPENDENT_SERVER_LISTENER;
			strbuf.appendconst(" which may be likely due to a dependent Server Issue");
		}		 
		else if (tasks_delay_msec * 10 > total_resp_msec) {
			lissue	= ISSUE_LISTENER_TASKS;

			if (tasks_cpudelay_msec > 0 && tasks_vmdelay_msec && cpu_issue && mem_issue) {
				strbuf.appendconst(" which may be likely due to Listener Process CPU and VM Delays as Host CPU and Memory Issues exist");
			}
			else if (tasks_cpudelay_msec && cpu_issue) {
				strbuf.appendconst(" which may be likely due to Listener Process Delays though not too high as well as Host CPU Issues");
			}
			else {
				strbuf.appendconst(" which may be likely due to Listener Process Delays though not too high");
			}

			if (ser_errors) {
				strbuf.appendconst(" and some Server Errors");
			}

			strbuf.appendfmt(" : Response %ld msec : QPS %d : Active Connections %d : Proc Delays %lu msec", r5p95, curr_qps, curr_active_conn, tasks_delay_msec);

			if (ser_errors) {
				strbuf.appendfmt(" : Server Errors %u", ser_errors);
			}

			return;
		}	
		else if (ser_errors) {
			lissue = ISSUE_SERVER_ERRORS;
			strbuf.appendconst(" which may be due to some Server Errors");
		}	
		else {		
			lissue = ISSUE_SRC_UNKNOWN;
			strbuf.appendconst(" cause of which cannot be determined");
		}	

		strbuf.appendfmt(" : Response %ld msec : Historical Response %ld msec : QPS %d : Active Connections %d", 
			r5p95, r5daysp95, curr_qps, curr_active_conn);

		if (ser_errors) {
			strbuf.appendfmt(" : Server Errors %u", ser_errors);
		}
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while checking Listener issue : %s\n", GY_GET_EXCEPT_STRING););
	);
}
	
const char * TCP_LISTENER::print_string(STR_WR_BUF & strbuf, bool print_stats) 
{
	strbuf.appendconst("TCP Listener Info : ");
	ns_ip_port_.print_string(strbuf);
	
	strbuf.appendfmt(" ID %016lx PID %d Comm \'%s\' Backlog %d : IPv4 Socket Inode %ld : IPv6 Inode %ld : UID %u ", 
			glob_id_, pid_, comm_, backlog_, sock_ipv4_inode_, sock_ipv6_inode_, uid_);

	if (print_stats) {
		char		uptime_buf[128];
		uint64_t	curr_usec = get_usec_clock(), uptime_sec = (curr_usec -  start_clock_usec_.load(std::memory_order_relaxed)) / GY_USEC_PER_SEC;
		int64_t		nsec_bytes = gy_div_round_near((curr_usec - clock_usec_.load(std::memory_order_relaxed)), GY_USEC_PER_SEC);
		
		strbuf.appendfmt("\n\tNumber of approx connections %d : Recently active connections [%d,%d] : # Listener Processes %d : ", 
			nconn_.load(std::memory_order_acquire), nconn_recent_active_.load(std::memory_order_acquire), 
			last_nconn_recent_active_.load(std::memory_order_acquire), GY_READ_ONCE(ntasks_associated_));

		strbuf.appendfmt(" Listener Uptime %s\n\tListener Process cmdline \'%s\'\n\tLast %ld seconds BytesIn %lu KB : BytesOut %lu KB : ", 
			get_time_diff_string(uptime_sec, uptime_buf, sizeof(uptime_buf)), cmdline_, nsec_bytes, GY_DOWN_KB(curr_bytes_inbound_), GY_DOWN_KB(curr_bytes_outbound_));

		if (nat_ip_port_arr_[0].port_ != 0) {
			strbuf.appendconst("NAT Service 1 ");
			nat_ip_port_arr_[0].print_string(strbuf);
			strbuf.appendconst(" : ");
		}

		if (nat_ip_port_arr_[1].port_ != 0) {
			strbuf.appendconst("NAT Service 2 ");
			nat_ip_port_arr_[1].print_string(strbuf);
			strbuf.appendconst(" : ");
		}

		if (cumul_cli_errors_ + cumul_ser_errors_) {
			strbuf.appendfmt("Total Client Errors %u Server Errors %u from start : ", cumul_cli_errors_, cumul_ser_errors_);
		}	

		strbuf.appendfmt("Server DNS \'%s\'\n\n", server_domain_);

		CONDEXEC(
			DEBUGEXECN(10, 
				strbuf.appendfmt("\tListener Address %p\n\n", this);
			);
		);

		const time_t			last_add_time = resp_hist_.get_last_add_time(), inittime = resp_hist_.get_init_time(), tcur = time(nullptr);
		const time_t			tdiff_start = (last_add_time > inittime ?  last_add_time - inittime + 1 : (tcur > inittime + 1 ? tcur - inittime + 1 : 1));
		float				multiple_factor = TCP_SOCK_HANDLER::get_bpf_qps_multiple();	
		float				pct_arr[] {95.0f, 99.0f, 25.0f};
		int				ret, n300 = get_level_from_time_offset<RESP_HISTOGRAM>(std::chrono::seconds(300));

		if (n300 >= 0 && histstat_[n300].tcount_ == 0) {
			goto done;
		}		

		for (size_t i = 0; i < RESP_HISTOGRAM::ntime_levels; i++) {

			time_t			sec_dist; 

			if (RESP_HISTOGRAM::dist_seconds[i].count() > 0) {
				sec_dist = (RESP_HISTOGRAM::dist_seconds[i].count() < tdiff_start ? RESP_HISTOGRAM::dist_seconds[i].count() : tdiff_start);
			}
			else {	
				sec_dist = tdiff_start;
			}

			if (histstat_[i].tcount_) {
				strbuf.appendfmt("\tResponse Distribution in %s : ", RESP_HISTOGRAM::level_string[i]);

				for (size_t h = 0; h < GY_ARRAY_SIZE(histstat_[i].stats_); ++h) {	
					strbuf.appendfmt("p%.3f Response <= %ld msec : ", histstat_[i].stats_[h].percentile, histstat_[i].stats_[h].data_value);
				}

				strbuf.appendfmt("Avg Response %.3f msec : Total Query Count %ld : Total Sum %ld msec : Avg Queries/sec (sampled) is %ld : "
						"Avg Queries/sec extrapolated is %ld\n", 
						histstat_[i].mean_val_, histstat_[i].tcount_, histstat_[i].tsum_, histstat_[i].tcount_/sec_dist, 
						(int64_t)(histstat_[i].tcount_ * multiple_factor)/sec_dist);
					
			}
		}

		strbuf.append('\n');
		
		CONN_BITMAP::print_string(strbuf, nactive_conn_arr_);

		resp_conn_v4_.print_string(strbuf, "IPv4 Connection info : ");
		resp_conn_v6_.print_string(strbuf, "IPv6 Connection info : ");

		strbuf.appendconst("\n\tListener QPS (Extrapolated) Stats : ");

		qps_hist_.print_stats(strbuf, pct_arr, GY_ARRAY_SIZE(pct_arr), "QPS", 1);
		strbuf.appendfmt("\n\tLast QPS : %u\n", last_qps_count_);

		strbuf.appendconst("\n\tListener # Active Connection Stats : ");
		active_conn_hist_.print_stats(strbuf, pct_arr, GY_ARRAY_SIZE(pct_arr), "# Active Conn", 1);

		strbuf.append('\n');

done :
		int 		ntasks_issue, ntasks_noissue, tasks_user_cpu, tasks_sys_cpu, tasks_rss_mb;
		uint32_t	tasks_delay_usec, tasks_cpudelay_usec, tasks_blkiodelay_usec;
		uint8_t		is_issue, is_severe;
		bool		is_delay;

		auto 		relshrlisten = related_listen_.load(std::memory_order_relaxed);
		
		if (relshrlisten) {
			auto & status = relshrlisten->task_status_;

			ret = status.recent_task_issue(curr_usec, tasks_delay_usec, tasks_cpudelay_usec, tasks_blkiodelay_usec, is_issue, is_severe, is_delay, 
						ntasks_issue, ntasks_noissue, tasks_user_cpu, tasks_sys_cpu, tasks_rss_mb);		
			if (ret != 0) {
				strbuf.appendconst("\tNo Task Issue Updates seen recently\n");
			}
			else {
				strbuf.appendfmt("\tTasks Issue Status : Recent Issue Status 0x%02x : Current interval # Tasks with issue %d : Without issue %d : Tasks User CPU %d%% : Sys CPU %d%%\n\t\t"
					"Tasks Delay msec %u : Tasks CPU Delay msec %u : Tasks Blkio Delay msec %u : Tasks VM Delay msec %u : Tasks RSS %dMB\n", 
					is_issue, ntasks_issue, ntasks_noissue, tasks_user_cpu, tasks_sys_cpu, tasks_delay_usec, tasks_cpudelay_usec, tasks_blkiodelay_usec,
					tasks_delay_usec - tasks_cpudelay_usec - tasks_blkiodelay_usec, tasks_rss_mb);
			}	

			auto nrelated = relshrlisten->related_table_.count_slow();		

			if (nrelated > 1) {
				strbuf.appendfmt("\n\t%lu Listeners are related to this Listener : \n", nrelated - 1);

				auto rellam = [&, this](WEAK_LISTEN_RAW *pdatanode, void *arg) -> CB_RET_E
				{
					auto 		pshrlist = pdatanode->weaklisten_.lock();
					auto		prellisten = pshrlist.get();

					if (prellisten && prellisten != this) {
						strbuf.appendconst("\t\t[");
						prellisten->print_short_string(strbuf);
						strbuf.appendconst("]\n");
					}
						
					return CB_OK;
				};	
				
				if (nrelated < 8) {
					relshrlisten->related_table_.walk_hash_table_const(rellam); 	
				}
			}	

			size_t 		ndepend = relshrlisten->id_depends_.approx_count_fast(), nunresolved = relshrlisten->ipport_depends_.approx_count_fast();

			auto lam_dep = [&](DEPENDS_LISTENER *pdepend, void *arg1) -> CB_RET_E
			{
				if (arg1) {
					if (false == pdepend->is_valid_depend()) {
						return CB_OK;
					}	
				}
				else if (true == pdepend->is_valid_depend()) {
					return CB_OK;
				}	

				if (pdepend->plistener_  != this) {
					strbuf.appendfmt("\t\t[%s]", pdepend->identifier_str_);
					if (pdepend->domain_name_[0]) {
						strbuf.appendfmt(" : [%s]", pdepend->domain_name_);
					}

					DEBUGEXECN(10,
						strbuf.appendfmt(" [ Address %p : Total Bytes Sent %lu Rcvd %lu : Status Bits 0x%lX ]", 
							pdepend->plistener_, pdepend->total_bytes_sent_, pdepend->total_bytes_rcvd_, pdepend->status_bits_);
					);
					strbuf.append('\n');
				}
				return CB_OK;
			};

			if (ndepend) {
				strbuf.appendfmt("\n\tListener is Dependent or Potentially Dependent on following Listeners (approx count %lu) : "
						"\n\tDependent Listeners are :  \n", ndepend);
				relshrlisten->id_depends_.walk_hash_table_const(lam_dep, (void *)1);
				strbuf.appendconst("\n\tPotentially Dependent Listeners are : \n");
				relshrlisten->id_depends_.walk_hash_table_const(lam_dep, (void *)0);
			}
			
			if (nunresolved) {
				strbuf.appendfmt("\n\tListener Dependent on external unresolved Listeners : \n");
				relshrlisten->ipport_depends_.walk_hash_table_const(lam_dep, (void *)1);
				strbuf.appendfmt("\n\tListener Potentially Dependent on external unresolved Listeners : \n");
				relshrlisten->ipport_depends_.walk_hash_table_const(lam_dep, (void *)0);
			}		
		}
			
	}	

	return strbuf.buffer();
}	

void TCP_LISTENER::set_nat_ip_port(const IP_PORT & ip_port, int64_t tcurr) noexcept
{
	auto 			ipportarr = nat_ip_port_arr_;

	if (ipportarr[0] == ip_port) {
		last_nat_ref_ip_tsec_[0] = tcurr;
	}	
	else if (ipportarr[1] == ip_port) {
		last_nat_ref_ip_tsec_[1] = tcurr;
	}
	else {
		if (false == NET_IF_HDLR::get_singleton()->is_remote_universal_ip(ip_port.ipaddr_)) {
			return;
		}	

		if (ipportarr[0].port_ == 0) {
			ipportarr[0] = ip_port;

			last_nat_ref_ip_tsec_[0] = tcurr;
			last_nat_chg_ip_tsec_ = tcurr;

			return;
		}	
		else if (ipportarr[1].port_ == 0) {
			ipportarr[1] = ip_port;

			last_nat_ref_ip_tsec_[1] = tcurr;
			last_nat_chg_ip_tsec_ = tcurr;

			return;
		}	

		uint8_t			natskips = nat_ip_skipped_.load(mo_relaxed);

		if (last_nat_ref_ip_tsec_[0] < tcurr - 300 && natskips >= 5) {
			ipportarr[0] = ip_port;

			last_nat_ref_ip_tsec_[0] = tcurr;
			last_nat_chg_ip_tsec_ = tcurr;
		}	
		else if (last_nat_ref_ip_tsec_[1] < tcurr - 300 && natskips >= 5) {
			ipportarr[1] = ip_port;

			last_nat_ref_ip_tsec_[1] = tcurr;
			last_nat_chg_ip_tsec_ = tcurr;
		}	
		else if (natskips < 100) {
			nat_ip_skipped_.store(natskips + 1, mo_relaxed);
		}	
	}
}	

int RELATED_LISTENERS::update_dependency(TCP_SOCK_HANDLER *pglobhdlr, TCP_CONN *ptcp, uint64_t bytes_sent, uint64_t bytes_rcvd, uint64_t clock_usec, TCP_LISTENER * pdependlisten) noexcept
{
	try {
		/*
		 * If pdependlisten || ptcp->ser_glob_id_, then check the id_depends_ table, else check the ipport_depends_ table.
		 * Initially set as not dependent
		 */
		DEPENDS_LISTENER	*pnewdepend;
		uint64_t		listener_glob_id;
		uint32_t		lhash;
		bool			bret; 
		
		auto lam_chk = [=](DEPENDS_LISTENER *pdepend, void *arg1, void *arg2) -> CB_RET_E
		{
			pdepend->last_clock_usec_ 	= clock_usec;
			pdepend->inter_bytes_sent_ 	+= bytes_sent;

			pdepend->total_bytes_sent_	+= bytes_sent;
			pdepend->total_bytes_rcvd_	+= bytes_rcvd;

			pdepend->curr_nconns_active_++;

			// Listener Object changed
			if (pdependlisten) {
				if (pdepend->plistener_ != pdependlisten) {
					pdepend->weaklisten_    = pdependlisten->weak_from_this();
					pdepend->is_any_ip_     = pdependlisten->is_any_ip_;

					STR_WR_BUF              sbuf(pdepend->identifier_str_, sizeof(pdepend->identifier_str_));

					pdependlisten->print_short_string(sbuf);

					GY_WRITE_ONCE(pdepend->plistener_, pdependlisten);
				}
			}
			else if (pdepend->listener_glob_id_ > 0) {
				auto & idmap = pglobhdlr->diag_lbl_map_[IP_PORT(ptcp->ser_.ipaddr_, ptcp->ser_.port_)];

				auto [sit, success] = idmap.try_emplace(pdepend->listener_glob_id_, clock_usec);

				if (success == false) {
					sit->second = clock_usec;
				}	
			}

			return CB_OK;
		};

		if (pdependlisten || (ptcp->ser_glob_id_ && ptcp->ser_madhava_id_)) {
			if (pdependlisten) {
				listener_glob_id = pdependlisten->glob_id_;
			}
			else {
				listener_glob_id = ptcp->ser_glob_id_;
			}

			lhash = get_uint64_hash(listener_glob_id);

			bret = id_depends_.lookup_single_elem(listener_glob_id, lhash, lam_chk);
			
			if (bret == false && id_depends_.count_slow() < comm::LISTENER_DEPENDENCY_NOTIFY::MAX_DEPENDS_PER_LISTEN) {
				if (pdependlisten) {
					TCP_LISTENER_PTR	key(pdependlisten);

					/*
					 * We do not consider inter dependency amongst related listeners. Revisit this if needed...
					 */
					if (false == related_table_.lookup_single_elem(key, get_pointer_hash(pdependlisten))) {
						pnewdepend = new DEPENDS_LISTENER(pdependlisten->ns_ip_port_, clock_usec, 
							pdependlisten->print_short_string(STRING_BUFFER<128>().get_str_buf()), pdependlisten->is_any_ip_, 
							pdependlisten->weak_from_this(), pdependlisten, listener_glob_id, pdependlisten->server_domain_);
					}
					else {
						return 1;
					}	
				}	
				else {
					/* 
					 * Set the original (without NAT) server IP/Port. Also update the diag_lbl_map_ to check for external load balancers
					 * We do not update for localhost load balancers assuming that the Server IP/Port may be different. Revisit this if needed...
					 */
					pnewdepend = new DEPENDS_LISTENER(ptcp->ser_.ipaddr_, ptcp->ser_.port_, ptcp->ser_comm_, clock_usec, listener_glob_id, 
							ptcp->ser_madhava_id_, ptcp->server_domain_);
				}
				
				lam_chk(pnewdepend, nullptr, nullptr);
				
				id_depends_.insert_or_replace(pnewdepend, listener_glob_id, lhash);
			}	
		}
		else {
			// Set the original (without NAT) server IP/Port
			IP_PORT		ip_port(ptcp->ser_.ipaddr_, ptcp->ser_.port_);

			lhash = ip_port.get_hash();

			bret = ipport_depends_.lookup_single_elem(ip_port, lhash, lam_chk);
			
			if (bret == false && ipport_depends_.count_slow() < comm::LISTENER_DEPENDENCY_NOTIFY::MAX_DEPENDS_PER_LISTEN) {
				pnewdepend = new DEPENDS_LISTENER(ip_port, clock_usec, ptcp->server_domain_);
				
				lam_chk(pnewdepend, nullptr, nullptr);
				
				ipport_depends_.insert_or_replace(pnewdepend, ip_port, lhash);
			}	
		}	
		return 0;
	}
	GY_CATCH_EXCEPTION(	
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while checking TCP Conn Listener Dependency : %s\n", GY_GET_EXCEPT_STRING););
		return -1;
	);		
}	

int TCP_SOCK_HANDLER::nat_check_cache() noexcept
{
	try {
		/*GY_NOMT_COLLECT_PROFILE(600, "Nat Check for TCP Connections");*/
		
		/*
		 * We walk the nat_cache_tbl_ and search the tcp_tbl_ for connections not yet updated and simultaneously delete each elem
		 * from the nat_cache_tbl_. Also if the tcp conn is updated, and it is a remote server conn with DNAT only, then that
		 * entry is also deleted from nat_tbl_ then and there itself.
		 * Also, if tcp conn not updated, check if SNAT is active and local server conn. If so, we need to delete the extra TCP conn.
		 */
		
		const uint64_t		min_clock_expiry = get_usec_clock() - 500 * GY_USEC_PER_MSEC;
		int			ncoalesce = 0;

		auto lam_nat_cache = [&, this, min_clock_expiry, curr_usec_time = get_usec_time()](NAT_ELEM_TYPE *pdatanode, void *arg1) -> CB_RET_E
		{
			auto			pnat = pdatanode->get_cref().get();

			if (pnat == nullptr) {
				return CB_DELETE_ELEM;
			}
			else if (pnat->clock_usec_ > min_clock_expiry) {
				// Wait for some time to get the tcp tbl populated
				return CB_OK;
			}	
			
			bool			bret, bret2;
			TCP_CONN_ELEM_TYPE	tcpelem;

			if (pnat->shr_updated_.load(std::memory_order_acquire) == false) {
				
				bret = tcp_tbl_.lookup_single_elem(pnat->orig_tup_, pnat->orig_tup_.get_hash(), tcpelem);

				if (bret && (pnat->shr_updated_.load(std::memory_order_acquire) == false)) {

					TCP_CONN		*ptcp = tcpelem.get_cref().get();

					if (ptcp) {
						pnat->shrconn_		= ptcp->shared_from_this();

						ptcp->nat_updated_	= true;
						ptcp->is_snat_		= pnat->is_snat_;
						ptcp->is_dnat_		= pnat->is_dnat_;

						ptcp->nat_cli_		= pnat->nat_tup_.cli_;
						ptcp->nat_ser_		= pnat->nat_tup_.ser_;

						auto 	lam_tcp = [&](TCP_CONN_ELEM_TYPE *pdatanode, void *arg1, void *arg2) -> CB_RET_E
						{
							auto			ptcp2 = pdatanode->get_cref().get();
							decltype(ptcp2)		ptcp = static_cast<decltype(ptcp2)>(arg1);

							if (ptcp2) {
								// Move stuff to ptcp before deletion
								ptcp->ser_ns_inode_.store(ptcp2->ser_ns_inode_.load(std::memory_order_relaxed), std::memory_order_relaxed);

								ptcp->is_tcp_accept_event_	= true;
								ptcp->is_dns_queried_ 		= false; // Reset as we will need to search for NAT server

								ptcp->ser_pid_			= ptcp2->ser_pid_;
								ptcp->ser_tid_			= ptcp2->ser_tid_;
								ptcp->ser_task_shr_		= std::move(ptcp2->ser_task_shr_);
								ptcp->ser_task_updated_.store(ptcp2->ser_task_updated_.load(std::memory_order_relaxed), std::memory_order_relaxed);
								ptcp->ser_task_aggr_id_		= ptcp2->ser_task_aggr_id_;

								ptcp->is_server_local_.store(true, std::memory_order_release);
								
								CONDEXEC(
									ncoalesce++;
								);	

								GY_STRNCPY(ptcp->ser_comm_, ptcp2->ser_comm_, sizeof(ptcp->ser_comm_));
							}

							return CB_DELETE_ELEM;
						};	

						if (false == ptcp->is_server_local_.load(std::memory_order_acquire)) {
							// We need to delete any extra TCP conn if its created which would be the case if the server side of conn is local

							bret2 = tcp_tbl_.lookup_single_elem(pnat->nat_tup_, pdatanode->get_rcu_hash(), lam_tcp, ptcp);

							if (pnat->is_dnat_ && ptcp->is_server_local_.load(std::memory_order_acq_rel) == false) {
								// We also need to delete the nat_tbl_ element and add the Client IP for NAT check	

								nat_tbl_.delete_single_elem(pnat->nat_tup_, pdatanode->get_rcu_hash());

								auto tcip 	= pnat->orig_tup_.cli_.ipaddr_;
								auto nchash 	= tcip.get_hash();

								auto ln = [curr_usec_time](CLI_IP *pnat, void *arg1, void *arg2) -> CB_RET_E
								{
									pnat->last_tsec_ = curr_usec_time/GY_USEC_PER_SEC;
									return CB_OK;
								};	

								if (false == nat_cli_ip_tbl_.lookup_single_elem(tcip, nchash, ln)) {
									auto pcli = new CLI_IP(tcip, curr_usec_time/GY_USEC_PER_SEC);

									nat_cli_ip_tbl_.insert_or_replace(pcli, tcip, nchash);
								}									
							}
						}	

						pnat->shr_updated_.store(true, std::memory_order_release);
					}	
				}	
			}	
			else {
				// Check if TCP Conn still valid
				if (pnat->shrconn_.use_count() <= 1) {
					// We also need to delete the nat_tbl_ element	
					nat_tbl_.delete_single_elem(pnat->nat_tup_, pdatanode->get_rcu_hash());
				}		
			}	

			return CB_DELETE_ELEM;	// Delete each elem
		};	

		auto nc = nat_cache_tbl_.walk_hash_table(lam_nat_cache, nullptr); 	

		CONDEXEC(
			DEBUGEXECN(10,
				if (ncoalesce) {
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "NAT Check resulted in %d TCP connections being coalesced. Total NAT elems checked = %lu\n",
						ncoalesce, nc);
				}	
			);
		);
		
		return 0;
	}
	GY_CATCH_EXCEPTION(	
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while checking NAT cache elements : %s\n", GY_GET_EXCEPT_STRING););
		return -1;
	);		
}	

int TCP_SOCK_HANDLER::nat_check_conns() noexcept
{
	using namespace			comm;

	try {
		const uint64_t				min_valid_clock_usec = get_usec_clock() - 30 * GY_USEC_PER_SEC;

		auto					pser = SERVER_COMM::get_singleton();
		std::shared_ptr<SERVER_CONNTRACK>	shrp;
		SERVER_CONNTRACK			*pconn1 = nullptr;

		shrp = pser->get_server_conn(comm::CLI_TYPE_REQ_ONLY);
		pconn1 = shrp.get();

		size_t				batchsz = std::min(nat_tbl_.approx_count_fast(), 50ul), currcnt = 0, totcnt = 0;	
		const size_t			fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + batchsz * sizeof(NAT_TCP_NOTIFY);
		void				*palloc = nullptr;
		
		if (batchsz) {
			if (pconn1) {
				palloc = ::malloc(fixed_sz);
				if (!palloc) {
					batchsz = 0;
				}	
			}
			else {
				batchsz = 0;
			}	
		}

		GY_SCOPE_EXIT {
			if (palloc) {
				::free(palloc);
			}	
		};	

		NAT_TCP_NOTIFY			*pnot = reinterpret_cast<NAT_TCP_NOTIFY *>((uint8_t *)palloc + sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY));
	

		auto send_batch = [&, this](void *pstart, size_t nnat) noexcept
		{
			COMM_HEADER		*phdr = reinterpret_cast<COMM_HEADER *>(pstart);
			EVENT_NOTIFY		*pevt = reinterpret_cast<EVENT_NOTIFY *>((uint8_t *)phdr + sizeof(COMM_HEADER)); 

			size_t			nsz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + nnat * sizeof(NAT_TCP_NOTIFY);

			totcnt += nnat;

			new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, nsz, pser->get_conn_magic());

			new (pevt) EVENT_NOTIFY(comm::NOTIFY_NAT_TCP, nnat);

			return pser->send_server_data(EPOLL_IOVEC_ARR(2, false, phdr, phdr->get_act_len(), ::free, pser->gpadbuf, phdr->get_pad_len(), nullptr), 
							comm::CLI_TYPE_REQ_ONLY, COMM_EVENT_NOTIFY, shrp);
		};	

		auto sendnat = [&, this](const NAT_ELEM * const pnat)
		{
			if (currcnt < batchsz) {
				pnat->set_comm_nat(pnot);

				pnot++;
				currcnt++;

				if (currcnt == batchsz) {
					bool bret = send_batch(palloc, currcnt);

					currcnt = 0;
					palloc = nullptr;
					
					if (bret == true) {
						palloc = ::malloc(fixed_sz);
						if (!palloc) {
							batchsz = 0;
						}	
						pnot = reinterpret_cast<NAT_TCP_NOTIFY *>((uint8_t *)palloc + sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY));
					}
					else {
						batchsz = 0;
					}	
				}	
			}	
		};	

		auto lam_nat_conn = [&, min_valid_clock_usec](NAT_ELEM_TYPE *pdatanode, void *arg1) -> CB_RET_E
		{
			auto			pnat = pdatanode->get_cref().get();

			if ((pnat == nullptr) || (true == GY_READ_ONCE(pnat->is_deleted_))) {
				return CB_DELETE_ELEM;
			}
			
			if (pnat->shr_updated_.load(std::memory_order_acquire) == true) {
				// Check if TCP Conn still valid
				if (pnat->shrconn_.use_count() <= 1) {
					return CB_DELETE_ELEM;
				}		
			}
			else if (min_valid_clock_usec > pnat->clock_usec_) {
				/*
				 * No NAT TCP conn shr_updated_ since last 30 sec. We send this entry to the Madhava server and delete this entry...
				 * But we validate whether this NAT was for a short lived Client connection by checking the pnat->orig_tup_.cli_.ipaddr_
				 * and whether that same Orig Client IP was seen recently in a local connection. This is because we need to send only those
				 * NATs which possibly would be from a load balancer (NAT gateway) and not local conn NATs to Madhava.
				 */
				if (pnat->is_dnat_ && false == nat_cli_ip_tbl_.lookup_single_elem(pnat->orig_tup_.cli_.ipaddr_, pnat->orig_tup_.cli_.ipaddr_.get_hash())) {
					sendnat(pnat);
				}	
				return CB_DELETE_ELEM;
			}	

			return CB_OK;
		};	

		size_t 			natelem = nat_tbl_.walk_hash_table(lam_nat_conn); 	
		
		if (currcnt > 0) {
			send_batch(palloc, currcnt);

			palloc = nullptr;
		}

		size_t 			nip = nat_cli_ip_tbl_.approx_count_fast();
		int			ndel = 0;

		if (nip > 256 && min_valid_clock_usec > next_cli_check_cusec_) {
			
			uint32_t			cutoffsec = (uint32_t)get_sec_time() - 60 * 60;

			auto lam_cli = [&](CLI_IP *pcli, void *arg1) -> CB_RET_E
			{
				if (pcli->last_tsec_ < cutoffsec) {
					ndel++;
					return CB_DELETE_ELEM;
				}	
				return CB_OK;
			};
			
			nat_cli_ip_tbl_.walk_hash_table(lam_cli);

			if (ndel < 128) {
				cutoffsec += 45 * 60;
				nat_cli_ip_tbl_.walk_hash_table(lam_cli);
			}

			next_cli_check_cusec_ = min_valid_clock_usec + 300 * GY_USEC_PER_SEC;
		}	

		INFOPRINT_OFFLOAD("Current # NAT Elements before any recent deletions is %lu : Number of NAT Elements sent to Madhava is %lu : "
			"Number of local Client IPs is %lu : IPs recently deleted = %d\n", 
			natelem, totcnt, nip, ndel);

		return 0;
	}
	GY_CATCH_EXCEPTION(	
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while checking NAT elements : %s\n", GY_GET_EXCEPT_STRING););
		return -1;
	);		
}	

int TCP_SOCK_HANDLER::tcp_check_conns() noexcept
{
	/*
	 * Check for TCP cons which have not been updated lately. If not updated, delete them
	 * 
	 * If there was a recent severe CPU or a Memory issue, postpone this check
	 */
	uint64_t		curr_usec_clock = get_usec_clock();
	uint64_t		curr_usec_time = get_usec_time();

	if ((int64_t)(curr_usec_clock - last_inet_diag_cusec_) > 2 * INET_DIAG_INTERVAL_SECS * (int64_t)GY_USEC_PER_SEC) {
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Inet Diagnostics has not been run for a long time : %ld secs : Lot of statistics will be faulty...\n",
			(curr_usec_clock - last_inet_diag_cusec_)/GY_USEC_PER_SEC);

		// We cannot delete conns as update has not happened...
		return -1;
	}	
	
	auto psys = SYSTEM_STATS::get_singleton();
	if (psys) {
		if (psys->is_severe_cpu_issue() || psys->is_severe_mem_issue()) {
			return 0;
		}	
	}

	int			nmissed = 0;

	auto lambda_chkconn = [&, this, curr_usec_clock, curr_usec_time](TCP_CONN_ELEM_TYPE *pdatanode, void *arg1) noexcept -> CB_RET_E
	{
		try {
			TCP_CONN		*ptcp = pdatanode->get_cref().get();
			uint64_t		tclock, tclocknew, last_stats_clock;

			if (gy_unlikely(ptcp == nullptr)) {
				return CB_DELETE_ELEM;
			}
				
			tclock = ptcp->stats_.curr_usec_clock.load(std::memory_order_relaxed);
			if (0 == tclock) {
				tclock = ptcp->clock_usec_start_;
			}	
				
			if (gy_unlikely(tclock + INET_DIAG_INTERVAL_SECS * 6 * GY_USEC_PER_SEC < curr_usec_clock && tclock)) { 

				GY_CC_BARRIER();

				tclocknew = ptcp->stats_.curr_usec_clock.load(std::memory_order_acquire);

				if (tclocknew + INET_DIAG_INTERVAL_SECS * 6 * GY_USEC_PER_SEC > curr_usec_clock) { 
					return CB_OK;
				}	

				if (ptcp->nat_updated_) {
					PAIR_IP_PORT			nat_tup {ptcp->nat_cli_, ptcp->nat_ser_};

					nat_tbl_.delete_single_elem(nat_tup, nat_tup.get_hash());
				}	

				notify_tcp_conn(ptcp, curr_usec_time, true /* more_data Always batch */, missed_cache_);

				nmissed++;

				DEBUGEXECN(1,
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN_UNDERLINE, 
						"[TCP Close Missed Event] : Deleting TCP Conn as no statistics since last %lu sec : %s\n", 
						(curr_usec_clock - tclock)/GY_USEC_PER_SEC, ptcp->print_string(STRING_BUFFER<512>().get_str_buf(), false)); 
				);

				return CB_DELETE_ELEM;
			}		

			return CB_OK;
		}
		GY_CATCH_EXCEPTION(
			DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while checking TCP Connection : %s\n", GY_GET_EXCEPT_STRING););
			return CB_BREAK_LOOP;
		);
	};	

	size_t tcpelem = tcp_tbl_.walk_hash_table(lambda_chkconn); 	
	
	if (nmissed > 0) {	
		flush_missed_tcp_cache();
	}

	INFOPRINT_OFFLOAD("Total # of TCP Connections across all network namespaces is %lu : # missed TCP Close events is %d\n", tcpelem, nmissed);

	return 0;
}	

int TCP_SOCK_HANDLER::update_cli_conn_info_madhava(const comm::MP_CLI_TCP_INFO *pinfo, int nevents, const uint8_t * const pendptr) noexcept
{
	using namespace		comm;

	try {
		RCU_LOCK_SLOW			slowlock;

		const MP_CLI_TCP_INFO		*ptmp;
		int				nconns = 0;
		
		CONDDECLARE(
			STRING_BUFFER<8192>	strbuf;
		);

		const auto lam_tcp = [&](TCP_CONN_ELEM_TYPE *pdatanode, void *arg1, void *arg2) -> CB_RET_E
		{
			auto			ptcp = pdatanode->get_cref().get();
			const MP_CLI_TCP_INFO	*pone = (const MP_CLI_TCP_INFO *)arg1;

			if (ptcp && GY_READ_ONCE(ptcp->ser_glob_id_) == 0) {

				GY_STRNCPY(ptcp->ser_comm_, pone->ser_comm_, sizeof(ptcp->ser_comm_));

				ptcp->ser_madhava_id_		= pone->ser_madhava_id_;
				ptcp->cli_ser_diff_clusters_	= pone->cli_ser_diff_clusters_;
				ptcp->peer_machine_id_		= pone->ser_partha_machine_id_;
				ptcp->ser_related_listen_id_	= pone->ser_related_listen_id_;

				GY_WRITE_ONCE(ptcp->ser_glob_id_, pone->ser_glob_id_);

				nconns++;

				CONDEXEC(
					DEBUGEXECN(10, 
						strbuf << "\n\t\t#"sv << nconns << " : "sv;
						ptcp->print_string(strbuf);
					);
				);
			}

			return CB_OK;
		};	

		for (ptmp = pinfo; (uint8_t *)ptmp < pendptr; ++ptmp) {
			tcp_tbl_.lookup_single_elem(ptmp->tup_, ptmp->tup_.get_hash(), lam_tcp, (void *)ptmp);
		}	

		if (nconns > 0) {
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Updated %d TCP Client connection Listener Info : Madhava server sent %d Info events\n", nconns, nevents);

			CONDEXEC(
				DEBUGEXECN(10, 
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "%.*s\n", strbuf.sizeint(), strbuf.buffer());
				);
			);
		}	

		return nconns;
	}	
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Caught Exception while updating TCP Client Conn Info from Madhava : %s\n", GY_GET_EXCEPT_STRING););
		return -1;
	);
}	

static int match_listen_shr(struct cds_lfht_node *pht_node, const void *pkey) noexcept
{
	const std::shared_ptr<TCP_LISTENER> 	*pshrlisten = (const std::shared_ptr<TCP_LISTENER> *)pkey;
	TCP_LISTENER_ELEM_TYPE			*pwrap = GY_CONTAINER_OF(pht_node, TCP_LISTENER_ELEM_TYPE, cds_node_);
	const auto				plistener = pwrap->get_cref().get();

	return (*pshrlisten).get() == plistener;
};


bool TCP_SOCK_HANDLER::is_listener_deleted(const std::shared_ptr<TCP_LISTENER> & shrlisten) const noexcept
{
	const NS_IP_PORT		*pdummy = (const NS_IP_PORT *)(void *)&shrlisten;

	return !(bool(shrlisten) && listener_tbl_.template lookup_single_elem<RCU_LOCK_SLOW, match_listen_shr>(*pdummy, shrlisten->listen_hash_));
}

static int match_ser_conn(struct cds_lfht_node *pht_node, const void *pkey) noexcept
{
	using namespace			comm;

	const MP_SER_TCP_INFO		*pinfo = (const MP_SER_TCP_INFO *)pkey;
	TCP_CONN_ELEM_TYPE		*pwrap = GY_CONTAINER_OF(pht_node, TCP_CONN_ELEM_TYPE, cds_node_);
	const auto			ptcp = pwrap->get_cref().get();

	return ptcp && pinfo && uint32_t(ptcp->ser_sock_inode_) == pinfo->ser_sock_inode_ && ptcp->conn_hash_ == pinfo->ser_conn_hash_;	
};


int TCP_SOCK_HANDLER::update_ser_conn_info_madhava(const comm::MP_SER_TCP_INFO *pinfo, int nevents, const uint8_t * const pendptr) noexcept
{
	using namespace		comm;

	try {
		RCU_LOCK_SLOW			slowlock;

		const MP_SER_TCP_INFO		*ptmp;
		int64_t				tcurr = get_sec_time();
		int				nconns = 0;
		
		CONDDECLARE(
			STRING_BUFFER<8192>	strbuf;
		);

		const auto lam_tcp = [&](TCP_CONN_ELEM_TYPE *pdatanode, void *arg1, void *arg2) -> CB_RET_E
		{
			auto			ptcp = pdatanode->get_cref().get();
			const MP_SER_TCP_INFO	*pone = (const MP_SER_TCP_INFO *)arg1;

			if (ptcp && GY_READ_ONCE(ptcp->cli_task_aggr_id_) == 0) {
				ptcp->cli_madhava_id_		= pone->cli_madhava_id_;
				ptcp->cli_task_aggr_id_		= pone->cli_task_aggr_id_;
				ptcp->peer_machine_id_		= pone->cli_partha_machine_id_;

				GY_STRNCPY(ptcp->cli_comm_, pone->cli_comm_, sizeof(ptcp->cli_comm_));
				ptcp->cli_listener_proc_	= !!pone->cli_related_listen_id_;

				if (pone->ser_nat_ip_port_.port_ && true == GY_READ_ONCE(ptcp->listen_updated_) && ptcp->listen_shr_) {
					if (pone->ser_nat_ip_port_ != ptcp->listen_shr_->ns_ip_port_.ip_port_) {
						ptcp->listen_shr_->set_nat_ip_port(pone->ser_nat_ip_port_, tcurr);
					}	
				}	

				nconns++;

				CONDEXEC(
					DEBUGEXECN(10, 
						strbuf << "\n\t\t#"sv << nconns << " : "sv;
						ptcp->print_string(strbuf);
					);
				);
			}

			return CB_OK;
		};	

		for (ptmp = pinfo; (uint8_t *)ptmp < pendptr; ++ptmp) {
			/*
			 * The MP_SER_TCP_INFO lookup here uses a custom match_ser_conn function to match the exact conn. This is
			 * due to the factthat the IP/Ports may have been overwritten by the intermediate NAT servers and also
			 * to avoid any extra lookup within the nat_tbl_. We basically matchup the hash and socket inode ignoring
			 * any IP/Port matches.
			 *
			 * We pass ptmp as a PAIR_IP_PORT pointer as the lookup_single_elem requires a pointer to the Key type while
			 * the match_ser_conn will reinterpret_cast it as MP_SER_TCP_INFO
			 */
			const PAIR_IP_PORT		*pdummy = (const PAIR_IP_PORT *)(void *)ptmp;

			tcp_tbl_.template lookup_single_elem<decltype(lam_tcp), RCU_LOCK_SLOW, match_ser_conn>(*pdummy, ptmp->ser_conn_hash_, lam_tcp, (void *)ptmp);
		}	

		if (nconns > 0) {
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Updated %d TCP Server connection Listener Info : Madhava server sent %d Info events\n", nconns, nevents);

			CONDEXEC(
				DEBUGEXECN(10, 
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "%.*s\n", strbuf.sizeint(), strbuf.buffer());
				);
			);
		}	

		return nconns;
	}	
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Caught Exception while updating TCP Server Conn Info from Madhava : %s\n", GY_GET_EXCEPT_STRING););
		return -1;
	);
}

int TCP_SOCK_HANDLER::handle_api_trace_set(const comm::REQ_TRACE_SET *preq, int nreq) noexcept
{
	using namespace		comm;

	try {
		GlobIDInodeMap			delidmap;
		int64_t				nadd = 0, ndel;
		time_t				tcurr = time(nullptr);
		bool				isnocaperr = false;
		
		RCU_LOCK_SLOW			slowlock;

		auto lam_chk = [&, this](TCP_LISTENER_ELEM_TYPE *pdatanode, void *arg1, void *arg2) -> CB_RET_E
		{
			auto 			plistener = pdatanode->get_cref().get();
			const REQ_TRACE_SET	*ptmp = (const REQ_TRACE_SET *)arg1;

			if (gy_unlikely(plistener == nullptr)) {
				return CB_OK;
			}
			
			plistener->tapi_cap_stop_.store(ptmp->tend_, mo_release);

			if (ptmp->tend_ > tcurr + 60) {
				if (bool(svcnetcap_) && svcnetcap_->is_svc_cap_allowed(true /* isapicall */)) {

					nadd += svcnetcap_->sched_add_listener(0, gy_to_charbuf<128>("API Capture for Svc %s %016lx", plistener->comm_, plistener->glob_id_).get(),
						plistener->ns_ip_port_.get_ns_inode(), plistener->shared_from_this(), true /* isapicall */);
				}
				else {
					if (!isnocaperr) {
						isnocaperr = true;
						ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Request Trace Enable called but Trace API Capture is disabled. Cannot enable Capture for \'%s\'\n",
							ptmp->comm_);
					}
				}	
			}
			else {
				auto			[it, success] = delidmap.try_emplace(plistener->ns_ip_port_.get_ns_inode());
				auto			& vec = it->second;		
					
				vec.emplace_back(plistener->glob_id_, plistener->ns_ip_port_.get_port());
			}	

			return CB_OK;
		};

		const REQ_TRACE_SET		*ptmp = preq;

		for (int i = 0; i < nreq; ++i, ++ptmp) {
			listener_tbl_.lookup_single_elem(ptmp->ns_ip_port_, ptmp->ns_ip_port_.get_hash(true /* ignore_ip */), lam_chk, (void *)ptmp);
		}	

		slowlock.unlock();

		ndel = delidmap.size();

		if (ndel > 0) {
			svcnetcap_->sched_del_listeners(0, gy_to_charbuf<128>("Request Trace Delete Listeners %ld", get_usec_time()).get(), std::move(delidmap));
		}

		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Request Trace Set : Scheduled Trace Capture for %ld listeners and Scheduled Trace disabled for %ld\n",
			nadd, ndel);

		return 0;
	}	
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Caught Exception while handling Req Trace Set messages from Madhava : %s\n", GY_GET_EXCEPT_STRING););
		return -1;
	);
}

TCP_LISTENER * TCP_SOCK_HANDLER::get_listener_by_globid_slow_locked(uint64_t globid) const noexcept
{
	TCP_LISTENER			*pret = nullptr;

	auto lam_listen = [&](TCP_LISTENER_ELEM_TYPE *pdatanode, void *arg1) noexcept -> CB_RET_E
	{
		auto 			plistener = pdatanode->get_cref().get();

		if (gy_unlikely(plistener == nullptr)) {
			return CB_OK;
		}

		if (plistener->glob_id_ == globid) {
			pret = plistener;
			return CB_BREAK_LOOP;
		}

		return CB_OK;
	};

	assert(false == gy_thread_rcu().is_rcu_thread_offline());
	
	listener_tbl_.walk_hash_table_const(lam_listen); 	

	return pret;
}	

std::tuple<int, int, int> TCP_SOCK_HANDLER::listener_stats_update(const std::shared_ptr<SERVER_CONNTRACK> & servshr, bool cpu_issue, bool mem_issue, GlobIDInodeMap & delidmap) noexcept
{
	GY_NOMT_COLLECT_PROFILE(40, "Listener Stats updation and checks");

	try {
		using namespace 		comm;

		const float			multiple_factor = get_bpf_qps_multiple();
		const int64_t			tcurr = get_sec_time();
		int				nlist = 0, nissue = 0, nsevere = 0, ndepend = 0, ndeleted = 0, nstatsend = 0;
		std::optional<DATA_BUFFER>	scache, statcache;

		if (servshr) {
			size_t			sl = listener_tbl_.approx_count_fast() + 8;

			scache.emplace(LISTENER_STATE_NOTIFY::get_max_elem_size(), std::min(200ul, sl), LISTENER_STATE_NOTIFY::MAX_NUM_LISTENERS, 
				sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY));

			if (tcurr > next_listen_stat_tsec_) {
				statcache.emplace(LISTENER_DAY_STATS::get_max_elem_size(), std::min(256ul, sl), LISTENER_DAY_STATS::MAX_NUM_LISTENERS, 
					sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY));
			}	
		}

		CONDDECLARE(
			static int 		ncheck_prints = 0;
		);

		CONDEXEC(
			ncheck_prints++;
			if (ncheck_prints == 12) {
				ncheck_prints = 0;
			}	
		);

		RCU_LOCK_SLOW			slowlock;

		const auto sendcb = [&](void *palloc, size_t sz, FREE_FPTR free_fp, size_t nelems) -> bool
		{
			auto		pser = SERVER_COMM::get_singleton();

			return pser->send_event_cache(*scache, palloc, sz, free_fp, nelems, comm::NOTIFY_LISTENER_STATE, servshr);
		};	

		const auto sendstat = [&](void *palloc, size_t sz, FREE_FPTR free_fp, size_t nelems) -> bool
		{
			auto		pser = SERVER_COMM::get_singleton();

			nstatsend += (int)nelems;

			return pser->send_event_cache(*statcache, palloc, sz, free_fp, nelems, comm::NOTIFY_LISTENER_DAY_STATS, servshr);
		};	

		const auto lam_listen = [&, multiple_factor, cpu_issue, mem_issue](TCP_LISTENER_ELEM_TYPE *pdatanode, void *arg1) noexcept -> CB_RET_E
		{
			try {
				auto 			plistener = pdatanode->get_cref().get();

				if (gy_unlikely(plistener == nullptr)) {
					return CB_DELETE_ELEM;
				}
					
				uint64_t		clock_diag = get_usec_clock();
				uint64_t		clock_sec = clock_diag/GY_USEC_PER_SEC;	

				uint64_t		tclock		= plistener->clock_usec_.load(std::memory_order_relaxed),
							tstart_clock 	= plistener->start_clock_usec_.load(std::memory_order_relaxed);

				int64_t			diffstartusec 	= (int64_t)clock_diag - (int64_t)tstart_clock;

				if (gy_unlikely((GY_READ_ONCE(plistener->ntasks_associated_) == 0) && (tclock + TIMEOUT_INET_DIAG_SECS * GY_USEC_PER_SEC < clock_diag 
					&& tclock && (tstart_clock + 2 * TIMEOUT_INET_DIAG_SECS * GY_USEC_PER_SEC < clock_diag)))) { 

					if (tclock == plistener->clock_usec_.load(std::memory_order_acquire)) {

						time_t		tnow = time(nullptr);
						time_t		last_add_time = plistener->resp_hist_.get_last_add_time();

						if ((plistener->resp_cache_v4_.get_last_rec_time() + TIMEOUT_INET_DIAG_SECS < tnow) && 
							(plistener->resp_cache_v6_.get_last_rec_time() + TIMEOUT_INET_DIAG_SECS < tnow) &&
							last_add_time + TIMEOUT_INET_DIAG_SECS <= tnow) {

							INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN_UNDERLINE, 
								"[TCP Listener Deletion] : Deleting TCP Listener as no statistics since last %lu sec : %s\n", 
								(clock_diag - tclock)/GY_USEC_PER_SEC, plistener->print_string(STRING_BUFFER<1200>().get_str_buf(), true)); 

							auto relshrlisten 	= plistener->related_listen_.load(std::memory_order_relaxed);
							
							if (relshrlisten) {
								// We need to delete this listener from related_table_
								TCP_LISTENER_PTR	key(plistener);

								relshrlisten->related_table_.delete_single_elem(key, get_pointer_hash(plistener));
							}	
							
							// Now remove the entry from listen_aggr_map_
							if (plistener->aggr_glob_id_) {
								SCOPE_GY_MUTEX		scopelock(listen_aggr_lock_);

								auto it = listen_aggr_map_.find(plistener->aggr_glob_id_);
								if (it != listen_aggr_map_.end()) {

									auto & lset = it->second;

									lset.erase((int64_t)plistener); 
									
									// Now check if the set contains only 1 elem. If so, we need to inform madhava to restart aggr stats
									if (lset.size() == 1) {
										TCP_LISTENER 		*plp = (TCP_LISTENER *)(*lset.begin());

										DEBUGEXECN(1, 
											INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN,
												"Enabling Madhava Listen Aggregate Stats for %s\n",
													plp->print_short_string(STRING_BUFFER<256>().get_str_buf()));
										);
										plp->server_stats_fetched_ = false;
									}	
									else if (lset.size() == 0) {
										listen_aggr_map_.erase(it);
									}	
								}
							}	

							++ndeleted;

							if (bool(scache)) {
								LISTENER_STATE_NOTIFY		*pone = (LISTENER_STATE_NOTIFY *)scache->get_next_buffer();

								new (pone) LISTENER_STATE_NOTIFY();

								pone->glob_id_			= plistener->glob_id_;
								pone->query_flags_		= LISTEN_FLAG_DELETE;

								pone->set_padding_len();

								scache->set_buffer_sz(sendcb, pone->get_elem_size());
							}

							return CB_DELETE_ELEM;
						}
					}
				}		
				else if (diffstartusec < (signed)GY_USEC_PER_SEC) {
					return CB_OK;
				}

				uint32_t		total_queries = 0, c4 = GY_READ_ONCE(plistener->curr_query_v4_), c6 = GY_READ_ONCE(plistener->curr_query_v6_);
				int64_t			diffsec = clock_sec - plistener->last_query_clock_;
				bool			is_stale = false, stale_dur2 = false;
				int			curr_qps_extra, curr_active_conn, old_curr_active_conn;

				total_queries += gy_diff_counter(c4, plistener->last_query_v4_);
				total_queries += gy_diff_counter(c6, plistener->last_query_v6_);

				plistener->last_query_v4_	= c4;
				plistener->last_query_v6_	= c6;	
				plistener->last_query_clock_ 	= clock_sec;

				if (gy_unlikely(diffsec <= 0)) {
					// New Listener
					return CB_OK;
				}
					
				uint32_t		cli_errors = 0, ser_errors = 0, ccerr = GY_READ_ONCE(plistener->cumul_cli_errors_), cserr = GY_READ_ONCE(plistener->cumul_ser_errors_);
				bool			is_apicap = false;

				if (plistener->api_cap_started_.load(mo_acquire) == CAPSTAT_ACTIVE) {
					SCOPE_GY_MUTEX			slock(plistener->svcweak_lock_);

					auto				svcshr = plistener->api_svcweak_.lock();
					
					slock.unlock();

					if (svcshr) {
						uint64_t			acerr, aserr;

						acerr = GY_READ_ONCE(svcshr->stats_.ncli_errors_);
						aserr = GY_READ_ONCE(svcshr->stats_.nser_errors_);

						cli_errors = (uint32_t)gy_diff_counter(acerr, plistener->last_api_ncli_errors_);
						ser_errors = (uint32_t)gy_diff_counter(aserr, plistener->last_api_nser_errors_);

						plistener->last_api_ncli_errors_ = acerr;
						plistener->last_api_nser_errors_ = aserr;

						is_apicap = true;
					}	
				}	

				if (!is_apicap) {
					cli_errors = gy_diff_counter(ccerr, plistener->last_cli_errors_);
					ser_errors = gy_diff_counter(cserr, plistener->last_ser_errors_);
				}

				plistener->last_cli_errors_ = ccerr;
				plistener->last_ser_errors_ = cserr;

				if (total_queries == 0 && ((int64_t)clock_diag - (int64_t)tclock > (INET_DIAG_INTERVAL_SECS + 5) * (signed)GY_USEC_PER_SEC)) {
					is_stale = true;
					plistener->last_qps_count_ = 0;

					if ((int64_t)clock_diag - (int64_t)tclock > 2 * INET_DIAG_INTERVAL_SECS * (signed)GY_USEC_PER_SEC) {
						stale_dur2 = true;
					}	
				}	
				else {
					curr_qps_extra = total_queries * multiple_factor/diffsec;

					plistener->last_qps_count_ = curr_qps_extra;
					plistener->qps_hist_.add_data(curr_qps_extra, clock_sec);
				}

				if (plistener->last_conn_clock_ + GY_USEC_PER_SEC < tclock) {
					plistener->last_conn_clock_ = tclock;

					if (is_stale == false) {
						plistener->active_conn_hist_.add_data(plistener->last_nconn_recent_active_.load(std::memory_order_acquire), clock_sec);
					}
				}	

				if (is_stale) {
					// The nconn_ && nconn_recent_active_ is stale
					plistener->last_nconn_.store(plistener->nconn_.exchange_relaxed(0, std::memory_order_acquire), std::memory_order_release);
					plistener->last_nconn_recent_active_.store(plistener->nconn_recent_active_.exchange_relaxed(0, std::memory_order_acquire), 
						std::memory_order_release);
				}	
				
				old_curr_active_conn = curr_active_conn = plistener->nconn_recent_active_.load(std::memory_order_acquire);

				time_t			tcur = time(nullptr);
				bool			actconnupd = false;

				uint8_t 		ipv4_conn[RESP_HISTOGRAM::max_buckets], ipv6_conn[RESP_HISTOGRAM::max_buckets];

				plistener->resp_bitmap_v4_.get_conn_breakup(ipv4_conn, tcur);
				plistener->resp_bitmap_v6_.get_conn_breakup(ipv6_conn, tcur);

				for (uint8_t r = 0; r < RESP_HISTOGRAM::max_buckets; ++r) {
					plistener->nactive_conn_arr_[r] = ipv4_conn[r] + ipv6_conn[r];

					if (curr_active_conn < plistener->nactive_conn_arr_[r]) {
						curr_active_conn = plistener->nactive_conn_arr_[r];
						actconnupd = true;
					}	
				}	

				if (actconnupd == true) {
					plistener->nconn_recent_active_.compare_exchange_relaxed(old_curr_active_conn, curr_active_conn);
				}	
				
				plistener->last_chk_nconn_ 		= plistener->nconn_.load(std::memory_order_acquire);
				plistener->last_chk_nconn_active_	= curr_active_conn;

				if (tcur > plistener->resp_cache_v4_.get_last_rec_time()) {
					// Not thread safe...
					plistener->resp_cache_v4_.flush_to_histogram();
				}

				if (tcur > plistener->resp_cache_v6_.get_last_rec_time()) {
					plistener->resp_cache_v6_.flush_to_histogram();
				}	

				plistener->tlast_stats_flush_ = tcur;

				plistener->resp_hist_.flush(tcur);

				if (is_stale) {
					// XXX Don't send to Madhava : Do we need to send STATE_DOWN message if ntasks_associated_ == 0 ?

					if (stale_dur2) {
						if (true == plistener->httperr_cap_started_.load(std::memory_order_relaxed)) {
							ino_t			inode = plistener->ns_ip_port_.inode_;
							uint16_t		port = plistener->ns_ip_port_.ip_port_.port_;
							
							// Send delete msg
							try {
								auto		[it, success] = delidmap.try_emplace(inode);
								auto		& vec = it->second;		
								
								vec.emplace_back(plistener->glob_id_, port);
							}
							catch(...) {

							}	
						}	
						else if (plistener->api_cap_started_.load(mo_relaxed) >= CAPSTAT_STARTING) {
							plistener->tapi_cap_stop_.store(time(nullptr), mo_relaxed);

							svcnetcap_->sched_del_one_listener(0, plistener->glob_id_, plistener->ns_ip_port_.inode_,
									plistener->ns_ip_port_.ip_port_.port_, true /* onlyapi */);
						}	

						// Set the last_nat_chg_ip_tsec_ to inform Madhava and Shyama
						if (plistener->last_nat_chg_ip_tsec_ > 0 && plistener->last_nat_ref_ip_tsec_[0] > 0) {
							plistener->nat_ip_port_arr_[0] = {};
							plistener->nat_ip_port_arr_[1] = {};

							GY_WRITE_ONCE(plistener->last_nat_chg_ip_tsec_, tcur);
							plistener->last_nat_ref_ip_tsec_[0] = 0;
						}

					}
					return CB_OK;
				}
					
				for (size_t i = 0; i < RESP_HISTOGRAM::ntime_levels; i++) {
					plistener->resp_hist_.get_stats(RESP_HISTOGRAM::dist_seconds[i], plistener->histstat_[i].stats_, 
						GY_ARRAY_SIZE(plistener->histstat_[i].stats_), plistener->histstat_[i].tcount_, plistener->histstat_[i].tsum_, 
						plistener->histstat_[i].mean_val_);
				}	

				char					issue_source[256];
				STR_WR_BUF				sbuf(issue_source, sizeof(issue_source));
				OBJ_STATE_E				lstate = STATE_OK;
				LISTENER_ISSUE_SRC			lissue = ISSUE_LISTEN_NONE;
				RELATED_LISTENERS::LISTENER_TASK_STATUS	taskstatus;
				LISTENER_DAY_STATS			statn;
					
				plistener->get_curr_state(lstate, lissue, sbuf, tcur, clock_diag, curr_active_conn, multiple_factor, cpu_issue, mem_issue, ser_errors,
								&taskstatus, bool(statcache) ? &statn : nullptr);

				if ((diffstartusec > (int64_t)GY_USEC_PER_SEC * 100) || (ser_errors)) {
					plistener->issue_bit_hist_ <<= 1;

					if (lstate >= STATE_BAD) {
						plistener->issue_bit_hist_ |= 1;

						nissue++;

						if (lstate >= STATE_SEVERE) {
							nsevere++;
						}

						if (lissue == ISSUE_DEPENDENT_SERVER_LISTENER) {
							ndepend++;
						}	

						array_shift_right(plistener->issue_hist_, GY_ARRAY_SIZE(plistener->issue_hist_));

						plistener->issue_hist_[0] = {lissue, ISSUE_LISTEN_NONE, clock_sec};
					}
				}
				else {
					plistener->issue_bit_hist_ = 0;

					sbuf.reset();

					lissue		= ISSUE_LISTEN_NONE;
					lstate		= STATE_OK;

					sbuf.appendconst("State OK : Listener Just recently started. No status possible currently");
				}		

				plistener->curr_state_ 	= lstate;
				plistener->curr_issue_	= lissue;
				
				nlist++;

				if (bool(scache)) {
					LISTENER_STATE_NOTIFY		*pnotify = (LISTENER_STATE_NOTIFY *)scache->get_next_buffer();
					const char 			*pissue	= sbuf.buffer();
					size_t 				sz_issue = sbuf.size() + 1;
					uint32_t			curr_bytes_inbound	{0};
					uint32_t			curr_bytes_outbound	{0};

					static constexpr int		n5 	= get_level_from_time_offset<RESP_HISTOGRAM>(std::chrono::seconds(5));
					static constexpr int		n300 	= get_level_from_time_offset<RESP_HISTOGRAM>(std::chrono::seconds(300));
					
					static_assert(n5 >= 0 && n300 >= 0);

					new (pnotify) comm::LISTENER_STATE_NOTIFY();

					pnotify->glob_id_			= plistener->glob_id_;

					pnotify->nqrys_5s_			= plistener->histstat_[n5].tcount_;
					pnotify->total_resp_5sec_		= plistener->histstat_[n5].tsum_;
					pnotify->nconns_			= plistener->last_chk_nconn_;
					pnotify->nconns_active_			= plistener->last_chk_nconn_active_;
					pnotify->ntasks_			= plistener->ntasks_associated_;

					pnotify->p95_5s_resp_ms_		= plistener->histstat_[n5].stats_[0].data_value;
					pnotify->p95_5min_resp_ms_		= plistener->histstat_[n300].stats_[0].data_value;

					/*
					 * We split the Network Bytes stats across 3 notify instances as Network stats updated every 15 sec 
					 * So 5 sec * 3 updates will match up...
					 */
					curr_bytes_inbound		+= gy_diff_counter_safe(GY_READ_ONCE(plistener->cumul_bytes_inbound_), plistener->last_cumul_bytes_inbound_);
					curr_bytes_outbound		+= gy_diff_counter_safe(GY_READ_ONCE(plistener->cumul_bytes_outbound_), plistener->last_cumul_bytes_outbound_);
					 
					if (++plistener->bytes_slot_ > 2) {
						plistener->bytes_slot_	= 0;
					}	
					else {
						if (curr_bytes_inbound > 3 * 1024) {
							curr_bytes_inbound 	/= 3;
						}
						else if (curr_bytes_inbound < 1024) {
							curr_bytes_inbound = 0;		// Accumulate for a couple of iters
						}	

						if (curr_bytes_outbound > 3 * 1024) {
							curr_bytes_outbound	/= 3;
						}
						else if (curr_bytes_outbound < 1024) {
							curr_bytes_outbound = 0;	// Accumulate for a couple of iters
						}	
					}	

					plistener->last_cumul_bytes_inbound_	+= curr_bytes_inbound;
					plistener->last_cumul_bytes_outbound_	+= curr_bytes_outbound;

					pnotify->curr_kbytes_inbound_		= GY_DOWN_KB(curr_bytes_inbound);
					pnotify->curr_kbytes_outbound_		= GY_DOWN_KB(curr_bytes_outbound);
					
					pnotify->ser_errors_			= ser_errors;
					pnotify->cli_errors_			= cli_errors;

					pnotify->tasks_delay_usec_		= taskstatus.tasks_delay_usec_;
					pnotify->tasks_cpudelay_usec_		= taskstatus.tasks_cpudelay_usec_;
					pnotify->tasks_blkiodelay_usec_		= taskstatus.tasks_blkiodelay_usec_;
					pnotify->tasks_user_cpu_		= taskstatus.tasks_user_cpu_;
					pnotify->tasks_sys_cpu_			= taskstatus.tasks_sys_cpu_;
					pnotify->tasks_rss_mb_			= taskstatus.tasks_rss_mb_;

					pnotify->ntasks_issue_			= taskstatus.last_ntasks_issue_;

					pnotify->is_http_svc_			= plistener->is_http_svc_ == true;
					pnotify->curr_state_			= plistener->curr_state_;
					pnotify->curr_issue_			= plistener->curr_issue_;
					pnotify->issue_bit_hist_		= plistener->issue_bit_hist_;
					pnotify->high_resp_bit_hist_		= plistener->high_resp_bit_hist_;
					pnotify->last_issue_subsrc_		= plistener->issue_hist_[0].subsrc_;
					pnotify->query_flags_			= LISTEN_FLAG_NONE;

					pnotify->issue_string_len_		= std::min(sz_issue, 254ul); 
					pnotify->set_padding_len();

					if (pnotify->issue_string_len_ > 0) {
						std::memcpy((char *)(pnotify + 1), pissue, pnotify->issue_string_len_ - 1);
						*((char *)pnotify + sizeof(*pnotify) + pnotify->issue_string_len_ - 1) = 0;
					}	

					scache->set_buffer_sz(sendcb, pnotify->get_elem_size());
				}

				if (gy_unlikely(bool(statcache) && statn.glob_id_)) {
					LISTENER_DAY_STATS		*pone = (LISTENER_DAY_STATS *)statcache->get_next_buffer();

					*pone		= statn;

					statcache->set_buffer_sz(sendstat, pone->get_elem_size());
				}

				DEBUGEXECN(1, 
					if (lstate >= STATE_BAD) {
						INFOPRINT_OFFLOAD("%s Listener %s Status : %.*s%s\n\n", 
							lstate == STATE_BAD ? GY_COLOR_RED : GY_COLOR_BOLD_RED,
							plistener->print_short_string(STRING_BUFFER<512>().get_str_buf()), sbuf.sizeint(), sbuf.buffer(), GY_COLOR_RESET);
					}
				);
						
				CONDEXEC(
					DEBUGEXECN(1, 
						if (ncheck_prints == 0) {
							if ((gdebugexecn >= 10) || (plistener->nconn_recent_active_.load(std::memory_order_relaxed))) {

								STRING_BUFFER<8000>	strbuf;
								
								plistener->print_string(strbuf, true);

								IRPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "\t------------------- [TCP Listener Stats] -----------------------\n"
											"\t%s\n\tCurrent Status : %s%.*s\n\n", 
											strbuf.buffer(), get_state_color(lstate), sbuf.sizeint(), sbuf.buffer()); 
							}
						}
					);
				);

				return CB_OK;
			}
			GY_CATCH_EXCEPTION(
				DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Caught Exception while checking listener stats : %s\n", GY_GET_EXCEPT_STRING););
				return CB_OK;
			)	
		};	

		size_t ntotal = listener_tbl_.walk_hash_table(lam_listen); 	

		// Offline the thread now
		slowlock.unlock();

		if (bool(scache)) {
			scache->flush_cache(sendcb);
		}

		if (bool(statcache)) {
			statcache->flush_cache(sendstat);

			next_listen_stat_tsec_ = tcurr + 5 * 60;
		}

		STRING_BUFFER<1024>		strbuf;

		strbuf.appendfmt("Current # of TCP Listeners is %lu Active %d : Listeners with Issues %d (severe %d) : Listeners with issues likely caused by Dependent Listeners %d", 
			ntotal, nlist, nissue, nsevere, ndepend);

		if (ndeleted > 0) {
			strbuf.appendfmt(" : %d TCP Listeners have been deleted as no stats seen", ndeleted);
			last_listener_del_cusec_.store(get_usec_clock(), std::memory_order_release);
		}	

		if (nstatsend > 0) {
			strbuf.appendfmt(" : %d Listener 5 day Stats sent to server\n", nstatsend);
		}	

		INFOPRINT_OFFLOAD("%s\n", strbuf.buffer());

		return {nissue, nsevere, nlist};
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Caught Exception while updating Listener Stats : %s\n", GY_GET_EXCEPT_STRING););
		return {0, 0, 0};
	);
}	

bool TCP_SOCK_HANDLER::host_status_update(const std::shared_ptr<SERVER_CONNTRACK> & servshr, bool cpu_issue, bool mem_issue, bool severe_cpu_issue, bool severe_mem_issue, bool cpu_idle, bool mem_idle, uint32_t ntaskissue, uint32_t ntasksevere, uint32_t ntasks, uint32_t nlistissue, uint32_t nlistsevere, uint32_t nlisten) noexcept
{
	using namespace			comm;

	try {
		OBJ_STATE_E			curr_state = STATE_IDLE;

		if ((ntasksevere || nlistsevere) && (severe_cpu_issue || severe_mem_issue)) {
			curr_state = STATE_SEVERE;
			goto done;
		}	

		if (!cpu_issue && !mem_issue && !ntaskissue && !nlistissue) {
			if (cpu_idle) {
				curr_state = STATE_IDLE;
			}
			else {
				curr_state = STATE_GOOD;
			}

			goto done;
		}	

		if ((ntaskissue || nlistissue) && (cpu_issue || mem_issue)) {
			if (ntaskissue > 5 || nlistissue > 5) {
				curr_state = STATE_SEVERE;
				goto done;
			}		

			curr_state = STATE_BAD;
			goto done;
		}	
		else if (cpu_issue || mem_issue) {
			if (severe_cpu_issue || severe_mem_issue) {
				curr_state = STATE_BAD;
				goto done;
			}

			curr_state = STATE_OK;
			goto done;
		}	

		if (nlistissue) {
			if (nlistsevere || ntaskissue) {
				if (nlistissue > 5) {
					curr_state = STATE_SEVERE;
					goto done;
				}	

				curr_state = STATE_BAD;
				goto done;
			}	
			else if (nlistissue > 2) {
				curr_state = STATE_BAD;
				goto done;
			}	
			else {
				curr_state = STATE_OK;
				goto done;
			}	
		}

		if (ntaskissue) {
			if (ntasksevere) {
				curr_state = STATE_BAD;
				goto done;
			}	
			else if (ntaskissue > 5) {
				curr_state = STATE_BAD;
				goto done;
			}	
		}

		curr_state = STATE_OK;

done :
		curr_host_status_.curr_time_usec_	= get_usec_time();
		curr_host_status_.ntasks_issue_		= ntaskissue;
		curr_host_status_.ntasks_severe_	= ntasksevere;
		curr_host_status_.ntasks_		= ntasks;
		curr_host_status_.nlisten_issue_	= nlistissue;
		curr_host_status_.nlisten_severe_	= nlistsevere;
		curr_host_status_.nlisten_		= nlisten;
		curr_host_status_.curr_state_		= curr_state;

		curr_host_status_.issue_bit_hist_	<<= 1;
		curr_host_status_.issue_bit_hist_	|= (curr_state >= STATE_BAD);

		curr_host_status_.cpu_issue_		= cpu_issue;
		curr_host_status_.mem_issue_		= mem_issue;
		curr_host_status_.severe_cpu_issue_	= severe_cpu_issue;
		curr_host_status_.severe_mem_issue_	= severe_mem_issue;

		curr_host_status_.total_cpu_delayms_	= ptask_handler_->last_cpu_delayms_;
		curr_host_status_.total_vm_delayms_	= ptask_handler_->last_vm_delayms_;
		curr_host_status_.total_io_delayms_	= ptask_handler_->last_io_delayms_;

		INFOPRINT_OFFLOAD("%sHost State %s : #Procs with issues %d, #Total Procs %d : "
			"#Listeners with issue %d, #Total Listeners %d : #CPU Delay %u ms, #VM Delay %u ms, #IO Delay %u ms, CPU Issue %s : Memory Issue %s%s\n",
			get_state_color(curr_state), state_to_string(curr_state), ntaskissue, ntasks, nlistissue, nlisten, 
			curr_host_status_.total_cpu_delayms_, curr_host_status_.total_vm_delayms_, curr_host_status_.total_io_delayms_, 
			severe_cpu_issue ? "Severe" : cpu_issue ? "Yes" : "No", severe_mem_issue ? "Severe" : mem_issue ? "Yes" : "No", GY_COLOR_RESET);
		
		if (!servshr) {
			return false;
		}	

		auto				pser = SERVER_COMM::get_singleton();
		constexpr size_t		fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + sizeof(HOST_STATE_NOTIFY);
		void				*palloc = malloc(fixed_sz);

		if (!palloc) {
			return false;
		}	

		HOST_STATE_NOTIFY		*phost = (HOST_STATE_NOTIFY *)((uint8_t *)palloc + sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY));
		
		new (phost) HOST_STATE_NOTIFY(curr_host_status_);
		
		return pser->send_event_msg(palloc, fixed_sz, ::free, 1, comm::NOTIFY_HOST_STATE, servshr);
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Caught Exception while sending Host Status : %s\n", GY_GET_EXCEPT_STRING););
		return false;
	);
}	


int TCP_SOCK_HANDLER::send_listen_taskmap() noexcept
{
	using namespace			comm;

	try {
		auto				pser = SERVER_COMM::get_singleton();

		if (gy_unlikely(false == pser->is_server_connected())) {
			return 1;
		}	

		// Need at least 850 KB Stack
		assert(gy_get_thread_local().get_thread_stack_freespace() >= 850 * 1024);

		using TaskHashSet		= GY_STACK_HASH_SET<uint64_t, 256 * 1024, GY_JHASHER<uint64_t>>;
		using ListenVec			= GY_STACK_VECTOR<uint64_t, 256 * 1024>;

		using Arenaset			= TaskHashSet::allocator_type::arena_type;
		using Arenavector		= ListenVec::allocator_type::arena_type;

		Arenavector			avec;
		Arenaset			aset;

		struct RelOne
		{
			uint64_t		related_listen_id_;
			char			ser_comm_[TASK_COMM_LEN];
			ListenVec		listenvec_;
			TaskHashSet		taskset_;
			
			RelOne(uint64_t related_listen_id, const char *ser_comm, Arenavector & arenavec, Arenaset & arenaset) noexcept
				: related_listen_id_(related_listen_id), listenvec_(arenavec), taskset_(arenaset)
			{
				GY_STRNCPY(ser_comm_, ser_comm, sizeof(ser_comm_));
			}	
		};	

		using RelTable			= GY_STACK_HASH_MAP<uint64_t, RelOne, 200 * 1024, GY_JHASHER<uint64_t>>;
		using ArenaRel			= RelTable::allocator_type::arena_type;
		
		ArenaRel			arel;
		RelTable			reltbl(arel);
		uint32_t			ntasks = 0, nlisten = 0;

		reltbl.reserve(64);

		const auto lam_listen = [&](TCP_LISTENER_ELEM_TYPE *pdatanode, void *arg1) -> CB_RET_E
		{
			auto 			plistener = pdatanode->get_cref().get();
			size_t			nproc, ndel = 0;

			if (gy_unlikely(plistener == nullptr || plistener->cmdline_[0] == 0 || plistener->related_listen_id_ == 0)) {
				return CB_OK;
			}
			
			auto relshrlisten 		= plistener->related_listen_.load(std::memory_order_acquire);

			if (!relshrlisten) {
				return CB_OK;
			}

			auto [rit, rsuccess] = reltbl.try_emplace(plistener->related_listen_id_, plistener->related_listen_id_, plistener->comm_, avec, aset);

			rit->second.listenvec_.emplace_back(plistener->glob_id_);
			nlisten++;

			if (rit->second.listenvec_.size() == LISTEN_TASKMAP_NOTIFY::MAX_NUM_LISTENERS) {
				return CB_BREAK_LOOP;
			}	

			if (rsuccess == false) {
				// Tasks already populated
				return CB_OK;
			}

			auto task_tbl_shr	= plistener->listen_task_table_.load(std::memory_order_acquire);

			if (!task_tbl_shr) {
				return CB_OK;
			}	

			const auto proc_lambda = [&](SHR_TASK_ELEM_TYPE *pdatanode, void *arg) -> CB_RET_E
			{
				auto ptask = pdatanode->get_cref().get();

				if (!ptask) {
					return CB_OK;
				}

				uint64_t		aggr_task_id = ptask->aggr_task_id_.load(std::memory_order_relaxed);

				if (aggr_task_id) {
					rit->second.taskset_.emplace(aggr_task_id);

					if (rit->second.taskset_.size() == LISTEN_TASKMAP_NOTIFY::MAX_NUM_TASKS) {
						return CB_BREAK_LOOP;
					}	
				}

				return CB_OK;
			};	

			task_tbl_shr->walk_hash_table_const(proc_lambda); 	
			
			ntasks += rit->second.taskset_.size();

			if (rsuccess && reltbl.size() == LISTEN_TASKMAP_NOTIFY::MAX_NUM_LISTENERS) {
				return CB_BREAK_LOOP;
			}

			return CB_OK;
		};	

		listener_tbl_.walk_hash_table_const(lam_listen);

		auto				shrp = pser->get_server_conn(comm::CLI_TYPE_REQ_ONLY);
		auto				pconn1 = shrp.get();

		if (!pconn1 || !reltbl.size()) {
			return 1;
		}
	
		size_t				totallen = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + 
								sizeof(LISTEN_TASKMAP_NOTIFY) * reltbl.size() + (nlisten + ntasks) * sizeof(uint64_t), nl = 0;

		void				*palloc = malloc(totallen + 512);
		if (!palloc) {
			return -1;
		}	

		GY_SCOPE_EXIT {
			if (palloc) {
				::free(palloc);
			}	
		};	

		COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
		EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1); 
		LISTEN_TASKMAP_NOTIFY		*pone = reinterpret_cast<LISTEN_TASKMAP_NOTIFY *>(pnot + 1);
		uint8_t				*pendptr = (uint8_t *)palloc + totallen;
		size_t				elemsz, totsz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY);
		bool				bret;
		int				naggr;

		for (const auto & sit : reltbl) {
			const auto & 		relelem = sit.second;

			new (pone) LISTEN_TASKMAP_NOTIFY(relelem.related_listen_id_, relelem.ser_comm_, relelem.listenvec_.size(), relelem.taskset_.size());

			elemsz = pone->get_elem_size();

			totsz += elemsz;
			nl++;

			std::memcpy((uint8_t *)(pone + 1), &relelem.listenvec_[0], relelem.listenvec_.size() * sizeof(uint64_t));

			uint64_t		*ptaskid = (uint64_t *)(pone + 1) + relelem.listenvec_.size();

			for (uint64_t taskid : relelem.taskset_) {
				*ptaskid++ = taskid;
			}	

			pone = (decltype(pone))((uint8_t *)pone + elemsz);
			
			if ((uint8_t *)pone + sizeof(*pone) > pendptr) {
				break;
			}	
		}	

		new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, totsz, pser->get_conn_magic());

		new (pnot) EVENT_NOTIFY(NOTIFY_LISTEN_TASKMAP_EVENT, nl);

		palloc				= nullptr;	// So as to prevent ::free()

		pser->send_server_data(EPOLL_IOVEC_ARR(2, false, phdr, phdr->get_act_len(), ::free, pser->gpadbuf, phdr->get_pad_len(), nullptr), 
						comm::CLI_TYPE_REQ_ONLY, COMM_EVENT_NOTIFY, shrp);

		DEBUGEXECN(1, INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Sent Listener Taskmap Notify for %lu Distinct Listener sets (%u Listeners : %u Aggr Tasks) to Madhava server\n", 
				nl, nlisten, ntasks););

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while sending Listener Taskmap Notify : %s\n", GY_GET_EXCEPT_STRING);
		return -1;
	);		
}

int TCP_SOCK_HANDLER::listener_inode_validate(int & nclconfirm) noexcept
{
	GY_NOMT_COLLECT_PROFILE(10, "Check for TCP Listener socket inode process match");

	try {
		// Need at least 850 KB Stack
		assert(gy_get_thread_local().get_thread_stack_freespace() >= 850 * 1024);
		
		class LISTEN_INODE
		{
		public :	
			ino_t					inode_			{0};
			std::shared_ptr <TCP_LISTENER>		listen_shr_;
			std::shared_ptr <SHR_TASK_HASH_TABLE>	task_table_;
			SHR_TASK_HASH_TABLE			*ptask_table_raw_	{nullptr};
		};	

		using LinodeTable			= INLINE_STACK_HASH_MAP<ino_t, LISTEN_INODE, 800 * 1024, GY_JHASHER<ino_t>>;

		LinodeTable				inolistbl;

		inolistbl.reserve(8192);

		STRING_BUFFER<1024>			strbuf;

		std::unique_ptr<LISTEN_STATS_CB_TBL>	statstbl_uniq = std::make_unique<LISTEN_STATS_CB_TBL>(); // This needs to be heap allocated as its passed to async cb
		LISTEN_STATS_CB_TBL			*pstatstbl = statstbl_uniq.get();
		size_t					statslen = 0;
		uint64_t				curr_usec_clock = get_usec_clock(), curr_usec_time = get_usec_time();
		uint64_t				min_stats_tusec = curr_usec_time - 10 * GY_USEC_PER_SEC;
		bool					reset_stats = to_reset_stats_.exchange(false);
		
		RCU_LOCK_SLOW				slowlock;

		// First get the list of all Listener inodes

		auto aggradd = [&, this](TCP_LISTENER *plistener) -> bool
		{
			SCOPE_GY_MUTEX		scopelock(listen_aggr_lock_);

			auto & lset = listen_aggr_map_[plistener->aggr_glob_id_];

			lset.emplace((int64_t)plistener); 

			return (lset.size() == 1);
		};	

		auto lam_listen = [&, min_stats_tusec, reset_stats](TCP_LISTENER_ELEM_TYPE *pdatanode, void *arg1) -> CB_RET_E
		{
			try {
				auto 			plistener = pdatanode->get_cref().get();
				size_t			nproc, ndel = 0;

				if (gy_unlikely(plistener == nullptr)) {
					return CB_DELETE_ELEM;
				}
				
				if (gy_unlikely(reset_stats)) {
					plistener->server_stats_fetched_ = false;
				}

				LISTEN_INODE		elem, elem1;
				
				if ((int64_t)GY_USEC_PER_SEC > (int64_t)curr_usec_clock - (int64_t)plistener->start_clock_usec_.load(std::memory_order_relaxed)) {
					// Recently added
					return CB_OK;
				}	
				
				auto relshrlisten 		= plistener->related_listen_.load(std::memory_order_acquire);

				if (relshrlisten) {
					auto rellam = [this](WEAK_LISTEN_RAW *pdatanode, void *arg) -> CB_RET_E
					{
						if (pdatanode->weaklisten_.expired()) {
							return CB_DELETE_ELEM;
						}
							
						return CB_OK;
					};	
					relshrlisten->related_table_.walk_hash_table(rellam); 	
					relshrlisten->inode_check_cusec_ = curr_usec_clock;
				}	
				
				auto task_tbl_shr	= plistener->listen_task_table_.load(std::memory_order_acquire);

				elem1.task_table_	= task_tbl_shr;
				elem1.ptask_table_raw_	= elem1.task_table_.get();
				
				if (!elem1.ptask_table_raw_) {
					return CB_OK;
				}	

				auto proc_lambda = [&](SHR_TASK_ELEM_TYPE *pdatanode, void *arg) -> CB_RET_E
				{
					auto ptask = pdatanode->get_cref().get();

					if (ptask && (TASK_STATE_EXITED != ptask->task_valid.load(std::memory_order_relaxed))) {

						if (ptask->is_tags_seen && relshrlisten && relshrlisten->tag_len_ == 0) {

							auto		[tagbuf, taglen] = ptask->get_task_tags();

							if (taglen && taglen < sizeof(relshrlisten->tagbuf_)) {
								std::memcpy(relshrlisten->tagbuf_, tagbuf, taglen);

								relshrlisten->tag_len_ = taglen;

								GY_CC_BARRIER();
								relshrlisten->tlast_tag_ = curr_usec_time;
							}	
						}

						CONDEXEC(
							strbuf.appendfmt("%d (%s), ", ptask->task_pid, ptask->task_comm);
						);	
						return CB_OK;
					}
					else {
						ndel++;
						return CB_DELETE_ELEM;
					}
				};	

				CONDEXEC(
					strbuf.reset();
					plistener->print_short_string(strbuf);
					strbuf.appendconst(" : Tasks Associated : [");
				);

				nproc = elem1.ptask_table_raw_->walk_hash_table(proc_lambda); 	

				CONDEXEC(
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW_ITALIC, 
						"%.*s] : %lu processes associated : deleted %lu weak tasks from Listener Task Table\n",
							strbuf.sizeint(), strbuf.buffer(), nproc - ndel, ndel);
					strbuf.reset();
				);

				GY_WRITE_ONCE(plistener->ntasks_associated_, nproc - ndel);

				if (plistener->sock_ipv4_inode_ > 0) {
					elem.inode_		= plistener->sock_ipv4_inode_;
					elem.listen_shr_	= *pdatanode->get_data();
					elem.task_table_	= task_tbl_shr;
					elem.ptask_table_raw_	= elem1.ptask_table_raw_;

					inolistbl.emplace(elem.inode_, std::move(elem));
				}

				if (plistener->sock_ipv6_inode_ > 0) {
					elem.inode_		= plistener->sock_ipv6_inode_;
					elem.listen_shr_	= *pdatanode->get_data();
					elem.task_table_	= task_tbl_shr;
					elem.ptask_table_raw_	= elem1.ptask_table_raw_;

					inolistbl.emplace(elem.inode_, std::move(elem));
				}


				if ((GY_READ_ONCE(plistener->server_stats_fetched_) == false) && (pstatstbl->size() < comm::NEW_LISTENER::MAX_NUM_LISTENERS) && 
					plistener->cmdline_[0] && plistener->tstart_usec_ < min_stats_tusec) {

					bool 		is_uniq;

					is_uniq = aggradd(plistener);

					/*
					 * XXX : Currently we do not fetch the prior Listener stats (prior to Listener start).
					 * Delete the following line if needed...
					 */
					is_uniq = false; plistener->server_stats_updated_ = true; 

					auto [mit, msuccess] = pstatstbl->try_emplace(plistener->glob_id_, plistener->weak_from_this(), plistener->ns_ip_port_, 
						plistener->glob_id_, plistener->aggr_glob_id_, 
						(uint64_t)(uintptr_t)relshrlisten.get(), plistener->tstart_usec_, plistener->ser_aggr_task_id_, plistener->is_any_ip_, 
						plistener->is_pre_existing_, !is_uniq, plistener->server_stats_updated_, plistener->pid_, plistener->comm_, plistener->cmdline_);
					if (msuccess) {
						statslen += mit->second.info_.get_elem_size();
					}	
				}
			
				return CB_OK;
			}
			GY_CATCH_EXCEPTION(
				DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Caught Exception while checking listener table : %s\n", GY_GET_EXCEPT_STRING););
				return CB_OK;
			)	
		};	

		listener_tbl_.walk_hash_table(lam_listen, nullptr); 	

		/*
		 * Now get the list of inodes for all server side TCP connections upto a max of 32000 server side connections
		 * We also search for clustered Listeners.
		 */

		const auto is_match_comm = [](TCP_CONN *ptcp, RELATED_LISTENERS *prel) -> bool
		{
			const char 		*ser_comm = (const char *)GY_READ_ONCE(ptcp->ser_comm_);
			auto			bintype = typeinfo::get_binary_type(ser_comm);

			// This extra check needed if the client TCP task was lazily updated after the initial connection
			if (ptcp->is_server_local_.load(std::memory_order_relaxed) && ptcp->cli_pid_ == ptcp->ser_pid_ && bool(ptcp->cli_task_shr_)) {
				return false;
			}

			if (((strcmp(ptcp->cli_comm_, ser_comm)) && (strcmp(prel->init_comm_, ser_comm))) || (bintype != typeinfo::BIN_TYPE::BIN_MACHINE)) {
				/*
				 * We need to check all listeners from prel->related_table_ if comms match
				 * We can directly dereference pdatanode->plistener_ as we are under same RCU lock as above where the weak listens were validated.
				 * For Interpreted or JVM binaries, we consider clustered listeners only for same/adjacent listener ports
				 */

				bool			is_same = false;

				const auto rellam = [&](WEAK_LISTEN_RAW *pdatanode, void *arg) -> CB_RET_E
				{
					if (pdatanode && pdatanode->plistener_ && (0 == strcmp(pdatanode->plistener_->comm_, ser_comm))) {
						if (bintype != typeinfo::BIN_TYPE::BIN_MACHINE) {	

							if (16 >= abs(pdatanode->plistener_->ns_ip_port_.ip_port_.port_ - ptcp->nat_cli_.port_)) {
								is_same = true;

								DEBUGEXECN(1,
									INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW_ITALIC, "Clustered Listener match seen for %s "
										"based on binary with TCP Port adjacency\n", 
										pdatanode->plistener_->print_short_string(STRING_BUFFER<512>().get_str_buf()));
								);

								return CB_BREAK_LOOP;
							}	
						}	
						else {
							DEBUGEXECN(1,
								INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW_ITALIC, "Clustered Listener match seen for %s based on binary match\n", 
									pdatanode->plistener_->print_short_string(STRING_BUFFER<512>().get_str_buf()));
							);

							is_same = true;
							return CB_BREAK_LOOP;
						}	
					}
						
					return CB_OK;
				};	

				prel->related_table_.walk_hash_table(rellam); 	
				
				return is_same;
			}	

			DEBUGEXECN(1,
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW_ITALIC, "Clustered Listener match seen for Related Listener \'%s\' based on binary from Client TCP connection %s\n",
					prel->init_comm_, ptcp->print_string(STRING_BUFFER<512>().get_str_buf()));
			);

			return true;
		};	

		curr_usec_clock = get_usec_clock();

		auto lam_tcp = [&, this, reset_stats, ign_inode = false, curr_usec_clock](TCP_CONN_ELEM_TYPE *pdatanode, void *arg1) mutable noexcept -> CB_RET_E
		{
			try {
				auto 			ptcp = pdatanode->get_cref().get();
				size_t			nproc, ndel = 0;

				if (gy_unlikely(ptcp == nullptr)) {
					return CB_DELETE_ELEM;
				}
				
				if (indeterminate(ptcp->is_cluster_listen_) && curr_usec_clock > ptcp->clock_usec_start_ + GY_USEC_PER_SEC) {
					if (false == ptcp->is_tcp_connect_event_) {
						ptcp->is_cluster_listen_ = false;
					}
					else if (ptcp->cli_listener_checked_) {
						auto			prel = ptcp->cli_related_listen_shr_.get();

						if (!prel) {
							ptcp->is_cluster_listen_ = false;
						}
						else if (GY_READ_ONCE(ptcp->ser_glob_id_) && ptcp->ser_related_listen_id_ && *ptcp->ser_comm_ && *ptcp->cli_comm_) {

							if ((GY_READ_ONCE(ptcp->cli_ser_diff_clusters_)) || 
								(prel->get_related_id() == (uint64_t)ptcp->ser_related_listen_id_ && ptcp->is_server_local_.load(std::memory_order_relaxed))) {

								ptcp->is_cluster_listen_ = false;
							}
							else {
								if (true == is_match_comm(ptcp, prel)) {
									if (prel->is_cluster_match_seen_ == false) {
										prel->is_cluster_match_seen_ = true;
										// Wait for next interval...
									}
									else {
										ptcp->is_cluster_listen_ = true;
										nclconfirm++;
									}
								}	
								else {
									ptcp->is_cluster_listen_ = false;
								}	
							}	
						}
					}
				}	
				else if (true == ptcp->is_cluster_listen_) {
					nclconfirm++;
				}	

				if (ign_inode == true) {
					return CB_OK;
				}	
		
				if (gy_unlikely(true == reset_stats)) {
					ptcp->server_updated_.store(false, std::memory_order_relaxed);
				}

				if ((0 == GY_READ_ONCE(ptcp->ser_sock_inode_)) || (false == ptcp->is_server_local_.load(std::memory_order_relaxed)) || 
					(false == GY_READ_ONCE(ptcp->listen_updated_))) {
					
					return CB_OK;
				}

				auto			listenshr = ptcp->listen_shr_;
				auto			plistener = listenshr.get();
				
				if (gy_unlikely(plistener == nullptr)) {
					GY_WRITE_ONCE(ptcp->listen_updated_, false);
					return CB_OK;	
				}		
				
				LISTEN_INODE		elem;

				if ((int64_t)GY_USEC_PER_SEC > (int64_t)curr_usec_clock - (int64_t)plistener->start_clock_usec_.load(std::memory_order_relaxed)) {
					// Recently added
					return CB_OK;
				}	
				
				auto task_tbl_shr	= plistener->listen_task_table_.load(std::memory_order_acquire);

				elem.task_table_	= task_tbl_shr;
				elem.ptask_table_raw_	= elem.task_table_.get();
				elem.inode_		= ptcp->ser_sock_inode_;
				elem.listen_shr_	= std::move(listenshr);
				
				if (!elem.ptask_table_raw_) {
					return CB_OK;
				}	

				inolistbl.emplace(elem.inode_, std::move(elem));

				if (inolistbl.size() > 32 * 1024) {
					ign_inode = true;
				}	
				
				return CB_OK;
			}
			GY_CATCH_EXCEPTION(
				DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Caught Exception while checking tcp table for listener conns : %s\n", GY_GET_EXCEPT_STRING););
				return CB_OK;
			)	
		};	

		tcp_tbl_.walk_hash_table(lam_tcp); 	

		slowlock.~RCU_LOCK_SLOW();

		strbuf.reset();
	
		new (&slowlock) RCU_LOCK_SLOW();

		/*
		 * Now walk the /proc/PID inode list
		 */

		DIR				*pdir = nullptr, *pdirfd = nullptr;
		struct dirent			*pdent, *ptaskdent;
		uint64_t			curr_tusec = get_usec_time();
		char				*pfile, path[256], readstr[256], *pstr1, *pfdname;
		pid_t				ulval, pid;
		uint32_t			inoval;
		int				ret, nadded = 0;

		pdir = opendir("/proc");
		if (!pdir) {
			PERRORPRINT("Could not open /proc dir");
			return -1;
		}

		GY_SCOPE_EXIT {
			closedir(pdir);
		};

		while ((pdent = readdir(pdir)) != nullptr) {

			pfile = pdent->d_name;	
			
			pstr1 = nullptr;

			if ((string_to_number(pfile, ulval, &pstr1, 10)) && (ulval > 0)) {
				if (pstr1 && *pstr1) {
					continue;
				}	
			}	
			else {
				continue;
			}	

			pid = ulval;

			snprintf(path, sizeof(path), "/proc/%d/fd", pid);

			pdirfd = opendir(path);
			if (!pdirfd) {
				continue;
			}	

			GY_SCOPE_EXIT {
				closedir(pdirfd);
			};	

			while ((ptaskdent = readdir(pdirfd)) != nullptr) {

				pfdname = ptaskdent->d_name;	
				
				snprintf(path, sizeof(path), "/proc/%d/fd/%s", pid, pfdname);

				ret = readlink(path, readstr, sizeof(readstr) - 1);
				if (ret > 0) {
					readstr[ret] = '\0';
					
					if (std::memcmp(readstr, "socket:[", 8)) {
						continue;	
					}
							
					if (string_to_number(readstr + 8, inoval, nullptr, 10)) {
						
						auto it = inolistbl.find((ino_t)inoval);

						if (it != inolistbl.end()) {
							auto ptask_table = it->second.ptask_table_raw_;

							if (false == ptask_table->lookup_single_elem(pid, get_pid_hash(pid))) {
								std::shared_ptr <TASK_STAT> 	ptaskshr;
								bool				bret;
									
								bret = ptask_handler_->get_task_shared_ptr(pid, ptaskshr);

								if (bret == true) {
									auto			ptask = ptaskshr.get();
									auto			plistener = it->second.listen_shr_.get();
									
									if (ptask && plistener && true == ptask->task_update_complete()) {	
										ptask->is_tcp_server = true;
										ptask->ntcp_listeners.fetch_add(1, std::memory_order_relaxed);

										plistener->ntasks_associated_++;
										nadded++;

										auto task_shrlisten = ptask->listen_tbl_shr.load(std::memory_order_acquire);
										auto ptask_listen_table = task_shrlisten.get();

										if (!ptask_listen_table) {
											ptask->listen_tbl_shr.store(it->second.task_table_, std::memory_order_release);
											ptask->listen_tbl_inherited.store(0, std::memory_order_release);
											ptask->related_listen_.store(plistener->related_listen_.load(std::memory_order_acquire), 
																std::memory_order_release);
											ptask->last_listen_tusec_ = curr_tusec;
										}	
										else if (plistener->cmdline_[0] == 0) {

											/*
											 * First check if plistener->cmdline_[0] == 0. That would imply
											 * we missed the task updation when Listener start event occured and that 
											 * another related listener was subsequently started and the task was 
											 * updated there. So we need to coalesce the 2 listeners into a single
											 * related listener.
											 */

											auto 		task_relshrlisten = ptask->related_listen_.load(std::memory_order_acquire);

											if (task_relshrlisten) {

												DEBUGEXECN(1, 
													plistener->ns_ip_port_.print_string(strbuf);

													INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW_ITALIC,
														"Listener %s : Missed Updating Task Info : "
														"Added new task PID %d (%s) to Listener Task Table from inode check "
														"and coalesced Listeners\n",
														strbuf.buffer(), pid, ptask->task_comm);
													strbuf.reset();
												);

												plistener->task_weak_ = ptask->weak_from_this();
												GY_STRNCPY(plistener->cmdline_, ptask->task_cmdline, sizeof(plistener->cmdline_));
												plistener->ser_aggr_task_id_ = ptask->get_set_aggr_id();
												plistener->set_aggr_glob_id();

												plistener->listen_task_table_.store(task_shrlisten, std::memory_order_release);
												plistener->related_listen_.store(task_relshrlisten, std::memory_order_release);
												plistener->related_listen_id_ = (int64_t)task_relshrlisten.get();

												plistener->server_stats_fetched_ = false;

												if (pstatstbl->size() < comm::NEW_LISTENER::MAX_NUM_LISTENERS && 
													plistener->tstart_usec_ < min_stats_tusec) {

													bool 		is_uniq;

													is_uniq = aggradd(plistener);

													/*
													 * XXX : Currently we do not fetch the prior Listener stats (prior to Listener start).
													 * Delete the following line if needed...
													 */
													is_uniq = false; plistener->server_stats_updated_ = true; 

													auto [mit, msuccess] = pstatstbl->try_emplace(plistener->glob_id_, 
														plistener->weak_from_this(), 
														plistener->ns_ip_port_, plistener->glob_id_, plistener->aggr_glob_id_, 
														(uint64_t)(uintptr_t)task_relshrlisten.get(), plistener->tstart_usec_, 
														plistener->ser_aggr_task_id_, plistener->is_any_ip_, !is_uniq, 
														plistener->server_stats_updated_,
														plistener->is_pre_existing_, plistener->pid_, plistener->comm_, 
														plistener->cmdline_);

													if (msuccess) {
														statslen += mit->second.info_.get_elem_size();
													}	
												}

												TCP_LISTENER_PTR	key(plistener);
												
												WEAK_LISTEN_RAW		*praw = new WEAK_LISTEN_RAW(plistener->weak_from_this(), plistener);

												task_relshrlisten->related_table_.insert_or_replace(praw, key, get_pointer_hash(plistener));

												// Update the it->second as well
												it->second.task_table_ 		= task_shrlisten;
												it->second.ptask_table_raw_	= task_shrlisten.get();

												continue;
											}	

										}	

										SHR_TASK_ELEM_TYPE	*pshrelem;

										pshrelem = new SHR_TASK_ELEM_TYPE(ptask->shared_from_this());	
										
										ptask_table->insert_or_replace(pshrelem, pid, get_pid_hash(pid));
										
										if (plistener->cmdline_[0] == 0) {
											plistener->task_weak_ = ptask->weak_from_this();
											GY_STRNCPY(plistener->cmdline_, ptask->task_cmdline, sizeof(plistener->cmdline_));
											plistener->ser_aggr_task_id_ = ptask->get_set_aggr_id();
											plistener->set_aggr_glob_id();
										}

										CONDEXEC(
											plistener->ns_ip_port_.print_string(strbuf);

											INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW_ITALIC, 
												"Listener %.*s : Added new task PID %d (%s) to Listener Task Table from inode check\n",
												strbuf.sizeint(), strbuf.buffer(), pid, ptask->task_comm);
											strbuf.reset();

										);
									}
								}
							}
						}
					}	
				}
			}
		}

		// Now offline the thread
		slowlock.unlock();

	 	if (nadded) {
			INFOPRINT_OFFLOAD("Listener Task Table : Added %d tasks from /proc for the complete listener table tasks...\n", nadded);
		}	

		if (pstatstbl->size()) {
			fetch_tcp_listeners(std::move(statstbl_uniq), statslen);
		}	

		return 0;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Caught Exception while checking listener table inode procs : %s\n", GY_GET_EXCEPT_STRING););
		return -1;
	);
}	


int TCP_SOCK_HANDLER::fetch_tcp_listeners(std::unique_ptr<LISTEN_STATS_CB_TBL> && statstbl_uniq, size_t statslen) noexcept
{
	using namespace			comm;

	try {
		auto				pser = SERVER_COMM::get_singleton();
		auto				shrp = pser->get_server_conn(comm::CLI_TYPE_REQ_RESP);
		auto				pconn1 = shrp.get();

		const auto			pstatstbl = statstbl_uniq.get();

		if (!pconn1) {
			return 1;
		}
	
		size_t				totallen = sizeof(COMM_HEADER) + sizeof(QUERY_CMD) + sizeof(comm::LISTENER_INFO_REQ), nl = 0;
		size_t				fixedsz = totallen + statslen; 

		void				*palloc = malloc(fixedsz + 256);
		if (!palloc) {
			return -1;
		}	

		GY_SCOPE_EXIT {
			if (palloc) {
				::free(palloc);
			}	
		};	

		COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
		QUERY_CMD			*pqry = reinterpret_cast<QUERY_CMD *>(phdr + 1); 
		comm::LISTENER_INFO_REQ		*plist = reinterpret_cast<comm::LISTENER_INFO_REQ *>(pqry + 1);
		comm::NEW_LISTENER		*pone = reinterpret_cast<decltype(pone)>(plist + 1);
		uint8_t				*pendptr = (uint8_t *)palloc + fixedsz;
		size_t				elemsz;
		bool				bret;
		int				naggr;

		for (const auto & sit : *pstatstbl) {
			new (pone) std::decay_t<decltype(*pone)>(sit.second.info_);

			elemsz = pone->get_elem_size();

			totallen += elemsz;
			nl++;
			std::memcpy((uint8_t *)(pone + 1), sit.second.cmdline_, pone->cmdline_len_);

			pone = (decltype(pone))((uint8_t *)pone + elemsz);
			
			if ((uint8_t *)pone + sizeof(*pone) > pendptr) {
				break;
			}	
		}	

		new (phdr) COMM_HEADER(COMM_QUERY_CMD, totallen, pser->get_conn_magic());

		new (pqry) QUERY_CMD(pconn1->next_callback_seqid(), time(nullptr) + 25 /* timeout */, QUERY_LISTENER_INFO_STATS, RESP_BINARY);

		new (plist) LISTENER_INFO_REQ(nl);

		bret = pser->send_server_data(
			ASYNC_SOCK_CB(
			[statstbl_uniq = std::move(statstbl_uniq), this](EPOLL_CONNTRACK *pconn, void * pact_resp, size_t nact_resp, void * presphdr, bool is_expiry, bool is_error) noexcept
			{
				if (is_expiry || is_error) {
					WARNPRINT_OFFLOAD("TCP Listener Stats fetch from Madhava server %s. Will retry later...\n", is_expiry ? "expired" : "errored out");
					return false;
				}	

				// pact_resp has already been validated
				handle_server_tcp_listeners((comm::LISTENERS_INFO_STATS_RESP *)pact_resp, (uint8_t *)pact_resp + nact_resp, *statstbl_uniq.get());
				return true;
			},
			pqry->get_seqid(), pqry->get_expiry_sec()
			),
			EPOLL_IOVEC_ARR(2, false, phdr, phdr->get_act_len(), ::free, pser->gpadbuf, phdr->get_pad_len(), nullptr), shrp);

		palloc = nullptr;	// So as to prevent ::free()

		if (bret == false) {
			return 1;
		}	

		DEBUGEXECN(1, INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Sent TCP Listener Stats Request for %lu listeners to Madhava server.\n\n", nl););

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while sending TCP Listener Fetch Request : %s\n", GY_GET_EXCEPT_STRING);
		return -1;
	);		
}

int TCP_SOCK_HANDLER::listener_cluster_check() noexcept
{
	try {
		using ClustSet			= GY_STACK_HASH_SET<RELSVC_CLUSTER_ONE, 500 * 1024, GY_JHASHER<RELSVC_CLUSTER_ONE, true /* ignore_uniq_obj_trait */>>;
		using ArenaClust		= ClustSet::allocator_type::arena_type;

		using RelTable			= INLINE_STACK_HASH_MAP<uint64_t, ClustSet, 100 * 1024, GY_JHASHER<uint64_t>>;

		auto				pser = SERVER_COMM::get_singleton();
		auto				shrp = pser->get_server_conn(comm::CLI_TYPE_REQ_ONLY);
		auto				pconn1 = shrp.get();

		if (!pconn1) {
			return 0;
		}

		ArenaClust			aclust;
		RelTable			reltbl;
		size_t				ncluster_elems = 0;
		
		auto lam_tcp = [&](TCP_CONN_ELEM_TYPE *pdatanode, void *arg1) -> CB_RET_E
		{
			auto 			ptcp = pdatanode->get_cref().get();

			if (!ptcp || (true != ptcp->is_cluster_listen_)) {
				return CB_OK;
			}	

			auto			prel = ptcp->cli_related_listen_shr_.get();

			if (!prel || !ptcp->ser_glob_id_) {
				ptcp->is_cluster_listen_ = false;
				return CB_OK;
			}

			if (!ptcp->cluster_checked_ && (strcmp(ptcp->cli_comm_, ptcp->ser_comm_))) {
				/*
				 * We need to check all listeners from prel->related_table_ if comms match
				 */

				bool			is_same = false;

				const auto rellam = [&](WEAK_LISTEN_RAW *pdatanode, void *arg) -> CB_RET_E
				{
					if (!pdatanode) {
						return CB_OK;
					}

					const auto 			listenshr = pdatanode->weaklisten_.lock();

					if (listenshr && (0 == strcmp(listenshr->comm_, ptcp->ser_comm_))) {
						is_same = true;
						return CB_BREAK_LOOP;
					}
						
					return CB_OK;
				};	

				if (prel->related_table_.approx_count_fast() > 1) {
					prel->related_table_.walk_hash_table(rellam); 	
				}

				if (!is_same) {
					ptcp->is_cluster_listen_ = false;
					return CB_OK;
				}	

				ptcp->cluster_checked_ = true;
			}
			else if (!ptcp->cluster_checked_) {
				ptcp->cluster_checked_ = true;
			}	

			if (prel->is_cluster_listen_ == false) {
				prel->is_cluster_listen_ = true;
				prel->is_cluster_mesh_ = true;

				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Related Listener \'%s\' detected as a Clustered Listener based on connection %s...\n", 
					prel->init_comm_, ptcp->print_string(STRING_BUFFER<512>().get_str_buf()));
			}

			auto			relid = prel->get_related_id();

			auto			[it, success] = reltbl.try_emplace(relid, aclust);
			auto			& clset = it->second;
			auto			[cit, cadded] = clset.emplace(ptcp->peer_machine_id_, ptcp->ser_madhava_id_, ptcp->ser_related_listen_id_);

			if (cadded) {
				ncluster_elems++;

				if (aclust.bytes_left() < 1024 || clset.size() >= LISTENER_CLUSTER_NOTIFY::MAX_CLUSTER_ELEMS) {
					return CB_BREAK_LOOP;
				}	
			}

			if (success && reltbl.size() >= LISTENER_CLUSTER_NOTIFY::MAX_NUM_LISTENERS) {
				return CB_BREAK_LOOP;
			}	
			
			return CB_OK;
		};	

		tcp_tbl_.walk_hash_table(lam_tcp); 	


		size_t			nlist = reltbl.size(), totalsz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY);
		
		if (nlist == 0) {
			return 0;
		}	

		size_t			fixedsz = totalsz + nlist * sizeof(LISTENER_CLUSTER_NOTIFY) + ncluster_elems * sizeof(RELSVC_CLUSTER_ONE), nelems = 0, maxclust = 0;
		void			*palloc = ::malloc(fixedsz + 128);

		if (!palloc) {
			return -1;
		}	

		GY_SCOPE_EXIT {
			if (palloc) {
				::free(palloc);
			}	
		};	

		auto			pone = (LISTENER_CLUSTER_NOTIFY *)((uint8_t *)palloc + totalsz);

		for (const auto & [relid, clset] : reltbl) {
			new (pone) LISTENER_CLUSTER_NOTIFY(relid, clset.size());
			
			size_t			szelem = pone->get_elem_size();

			if (totalsz + szelem > fixedsz) {
				break;
			}	

			nelems++;

			if (maxclust < pone->ncluster_elems_) {
				maxclust = pone->ncluster_elems_;
			}	
			
			auto			*pclone = (RELSVC_CLUSTER_ONE *)(pone + 1);

			for (const auto & clone : clset) {
				new (pclone) RELSVC_CLUSTER_ONE(clone);
				pclone++;
			}	

			totalsz += szelem;
			pone = decltype(pone)((const char *)pone + szelem);
		};

		COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
		EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1); 

		new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, totalsz, pser->get_conn_magic());

		new (pnot) EVENT_NOTIFY(NOTIFY_LISTEN_CLUSTER_INFO, nelems);

		palloc				= nullptr;	// So as to prevent ::free()

		pser->send_server_data(EPOLL_IOVEC_ARR(2, false, phdr, phdr->get_act_len(), ::free, pser->gpadbuf, phdr->get_pad_len(), nullptr), 
						comm::CLI_TYPE_REQ_ONLY, COMM_EVENT_NOTIFY, shrp);

		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "%lu Clustered Listeners seen : Max Clustered Listener Instances = %lu\n", nelems, maxclust + 1);

		return nelems;

	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while handling Listener Cluster Checks : %s\n", GY_GET_EXCEPT_STRING);
		return -1;
	);
}	

void TCP_SOCK_HANDLER::handle_server_tcp_listeners(comm::LISTENERS_INFO_STATS_RESP *plist, uint8_t *pendptr, LISTEN_STATS_CB_TBL & statstbl) noexcept
{
	try {
		const int			nlisten = plist->ntcp_listeners_;
		comm::LISTENER_DAY_STATS	*porigstats = reinterpret_cast<decltype(porigstats)>(plist + 1), *pone = porigstats;

		for (int n = 0; n < nlisten && (uint8_t *)pone < pendptr; ++n, pone = decltype(pone)((uint8_t *)pone + pone->get_elem_size())) {
			auto it = statstbl.find(pone->glob_id_);

			if (gy_unlikely(it == statstbl.end())) {
				continue;
			}	

			auto listenshr = it->second.weaklisten_.lock();
			
			auto plisten = listenshr.get();

			if (nullptr == plisten) {
				statstbl.erase(it);
				continue;
			}	
			
			/*plisten->last_stats_5d_ = pone->stats_5d_;*/

			GY_CC_BARRIER();

			plisten->server_stats_fetched_ = true;
			plisten->server_stats_updated_ = true;

			statstbl.erase(it);
		}

		// We need to set all listeners server_stats_fetched_
		for (const auto & it : statstbl) {
			auto listenshr = it.second.weaklisten_.lock();
			auto plisten = listenshr.get();

			if (plisten) {
				plisten->server_stats_fetched_ = true;
				plisten->server_stats_updated_ = true;
			}
		}	
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while handling Listener Stats Server response : %s\n", GY_GET_EXCEPT_STRING);
	);
}


int TCP_SOCK_HANDLER::populate_ns_tbl()
{
	try {
		/*
		 * Scan all tasks in system to get the list of unique Network Namespaces
		 */

		DIR				*pdir = nullptr, *ptaskdir = nullptr;
		struct dirent			*pdent, *ptaskdent;
		char				*pfile, path[256], readstr[64], *pstr1, *ptaskfile;
		struct stat			stat1;
		uint64_t			ulval, ulinoval, inoval, pidnsval;
		int				ret, nspaces = 0;
		bool				bret;
		NETNS_ELEM			*pnetns;

		pdir = opendir("/proc");
		if (!pdir) {
			PERRORPRINT("Could not open /proc dir");
			return -1;
		}

		RCU_DEFER_OFFLINE		deferlock;

		GY_SCOPE_EXIT {
			closedir(pdir);
		};

		while ((pdent = readdir(pdir)) != nullptr) {

			pfile = pdent->d_name;	
			
			pstr1 = nullptr;

			if ((string_to_number(pfile, ulval, &pstr1, 10)) && (ulval > 0)) {
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

			while ((ptaskdent = readdir(ptaskdir)) != nullptr) {

				ptaskfile = ptaskdent->d_name;	
				
				pstr1 = nullptr;

				if ((string_to_number(ptaskfile, ulinoval, &pstr1, 10)) && (ulinoval > 0)) {
					if (pstr1 && *pstr1) {
						continue;
					}	
				}	
				else {
					continue;
				}	

				snprintf(path, sizeof(path), "/proc/%lu/task/%lu/ns/net", ulval, ulinoval);

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

					bret = netns_tbl_.template lookup_single_elem<RCU_LOCK_FAST>(inoval, get_uint64_hash(inoval));

					if (bret == false) {
						DEBUGEXECN(1, INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "New Network Namespace %lu seen for PID %lu Thread %lu\n", inoval, ulval, ulinoval););
						nspaces++;
						
						pnetns = new NETNS_ELEM(inoval, pid_t(ulval), pid_t(ulinoval));

						netns_tbl_.template insert_or_replace<RCU_LOCK_FAST>(pnetns, inoval, get_uint64_hash(inoval));
					}	
				}	
			}
		}

	 	INFOPRINT_OFFLOAD("Total number of Network Namespaces currently active is %d\n", nspaces);

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT_OFFLOAD("Exception caught while getting Net NS list : %s\n", GY_GET_EXCEPT_STRING);
		return -1;
	);
}

int TCP_SOCK_HANDLER::populate_inode_tbl(SOCK_INODE_TABLE & socktbl, bool get_all)
{
	RCU_DEFER_OFFLINE		deferlock;

	try {
		/*
		 * Scan all tasks in system to get the list of inodes and PIDs
		 */

		DIR				*pdir = nullptr, *pdirfd = nullptr;
		struct dirent			*pdent, *ptaskdent;
		char				*pfile, path[256], readstr[256], *pstr1, *pfdname;
		struct stat			stat1;
		pid_t				ulval;
		ino_t				inoval;
		size_t				existsize = 0, nadded = 0;
		int				ret;

		pdir = opendir("/proc");
		if (!pdir) {
			PERRORPRINT("Could not open /proc dir");
			return -1;
		}

		GY_SCOPE_EXIT {
			if (pdir) {
				closedir(pdir);
			}	
		};

		if (false == get_all) {
			existsize = socktbl.size();
		}	

		while ((pdent = readdir(pdir)) != nullptr) {

			std::weak_ptr <TASK_STAT>	task_weak;
			bool				weak_valid = false, bret;
			char				comm[TASK_COMM_LEN];
			
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

			snprintf(path, sizeof(path), "/proc/%d/fd", ulval);

			pdirfd = opendir(path);
			if (!pdirfd) {
				continue;
			}	

			GY_SCOPE_EXIT {
				closedir(pdirfd);
			};	

			while ((ptaskdent = readdir(pdirfd)) != nullptr) {

				pfdname = ptaskdent->d_name;	
				
				snprintf(path, sizeof(path), "/proc/%d/fd/%s", ulval, pfdname);

				ret = readlink(path, readstr, sizeof(readstr) - 1);
				if (ret > 0) {
					readstr[ret] = '\0';
					if (0 != memcmp(readstr, "socket:[", GY_CONST_STRLEN("socket:["))) {
						continue;
					}
					
					inoval = atol(readstr + GY_CONST_STRLEN("socket:["));
					if (inoval > 0) {
						
						auto it = socktbl.find(inoval);

						if (get_all == true) {
							if (it != socktbl.end()) {
								it->second.pid_list_.push_back(ulval);
							}
							else {	
								SOCK_INODE_INFO		sock;	
								
								sock.sock_inode_ 	= inoval;
								sock.pid_		= ulval;

								if (weak_valid == false) {
									weak_valid = true;
									*comm = '\0';

									auto tlam = [&](TASK_STAT *ptask) 
									{
										task_weak = ptask->weak_from_this();
										GY_STRNCPY(comm, ptask->task_comm, sizeof(comm));
									};

									ptask_handler_->get_task(sock.pid_, tlam);
								}	

								sock.task_weak_ = task_weak;	// Use Copy instead of move
								sock.pid_list_.push_back(sock.pid_);

								GY_STRNCPY(sock.comm_, comm, sizeof(sock.comm_));
								
								socktbl.emplace(inoval, std::move(sock));
							}
						}
						else if (it != socktbl.end()) {
							// We need to populate this elem
							SOCK_INODE_INFO		& sock = it->second;	
							
							if (sock.pid_ != 0) {
								continue;
							}

							sock.sock_inode_ 	= inoval;
							sock.pid_		= ulval;

							if (weak_valid == false) {
								weak_valid = true;
								*comm = '\0';

								auto tlam = [&](TASK_STAT *ptask) 
								{
									task_weak = ptask->weak_from_this();
									GY_STRNCPY(comm, ptask->task_comm, sizeof(comm));
								};

								ptask_handler_->get_task(sock.pid_, tlam);
							}	

							sock.task_weak_ = task_weak;	// Use Copy instead of move
							// Ignore sock.pid_list_

							GY_STRNCPY(sock.comm_, comm, sizeof(sock.comm_));

							nadded++;

							if (nadded >= existsize) {
								return 0;
							}	
						}	
					}	
				}
			}
		}

		if (get_all) {
	 		DEBUGEXECN(1, INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Total number of socket inodes currently active is %lu\n", socktbl.size()););
		}
		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT_OFFLOAD("Exception caught while getting socket inode list : %s\n", GY_GET_EXCEPT_STRING);
		return -1;
	);
}	

bool TCP_SOCK_HANDLER::send_active_stats() noexcept
{
	using namespace				comm;

	GY_SCOPE_EXIT {
		/*
		 * Exception safe so no try catch needed here...
		 */
		activeconnmap_.clear();
	};	

	try {

		time_t				tcur = time(nullptr);

		if (activeconnmap_.size() == 0) {
			if (tlast_active_send_ + 10 >= tcur) {
				return false;
			}

			/*
			 * We need to send an empty msg to enable flushing of any short lived connections in madhava
			 */
		}	

		auto				pser =  SERVER_COMM::get_singleton();
		auto				shrp = pser->get_server_conn(comm::CLI_TYPE_REQ_ONLY);
		auto				pconn1 = shrp.get();

		if (!pconn1) {
			return false;
		}
		
		CONDDECLARE(
			STRING_BUFFER<4096>	strbuf;
		);

		size_t				nelem = 0, totalsz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY), elemsz, nlisten = 0;
		size_t				fixedsz = (activeconnmap_.size() + 1) * sizeof(ACTIVE_CONN_STATS) + totalsz;
		uint8_t				*palloc = (uint8_t *)malloc(fixedsz);

		if (!palloc) {
			return false;
		}	
		
		uint8_t				*pendptr = palloc + fixedsz;

		COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
		EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1); 
		ACTIVE_CONN_STATS		*pconn = reinterpret_cast<ACTIVE_CONN_STATS *>(pnot + 1);

		for (auto && cstat : activeconnmap_) {
			if ((uint8_t *)pconn + sizeof(ACTIVE_CONN_STATS) > pendptr) {
				break;
			}	

			new (pconn) ACTIVE_CONN_STATS(cstat.second);

			CONDEXEC(
				DEBUGEXECN(10,
					strbuf.appendfmt("\n\t%s Listener \'%s\' %s Client Task Stats : "
						"Task \'%s\' : Bytes Sent %lu : Rcvd %lu : Conns %hu : "
						"Client Delay msec %u : Server Delay msec %u : Max RTT msec %.3f : Is Listener Proc %d",
							pconn->is_remote_listen_ ? "Remote" : "Local", pconn->ser_comm_, pconn->is_remote_cli_ ? "Remote" : "Local",
							pconn->cli_comm_, pconn->bytes_sent_, pconn->bytes_received_, pconn->active_conns_, 
							pconn->cli_delay_msec_, pconn->ser_delay_msec_, pconn->max_rtt_msec_, pconn->cli_listener_proc_);
				);
			);	
		
			nelem++;
			pconn++;
		}	
		
		new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, totalsz + nelem * sizeof(ACTIVE_CONN_STATS), pser->get_conn_magic());

		new (pnot) EVENT_NOTIFY(NOTIFY_ACTIVE_CONN_STATS, nelem);

		pser->send_server_data(EPOLL_IOVEC_ARR(2, false, phdr, phdr->get_act_len(), ::free, pser->gpadbuf, phdr->get_pad_len(), nullptr), 
						comm::CLI_TYPE_REQ_ONLY, COMM_EVENT_NOTIFY, shrp);

		tlast_active_send_ = tcur;

		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Active Conn Stats : Sent %lu Active Listener stats to Madhava : Size of message %lu\n", nelem, totalsz);
			
		CONDEXEC(
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "%.*s\n", strbuf.sizeint(), strbuf.buffer());
		);

		return true;

	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINT_OFFLOAD("Exception caught while sending Active Conn Stats : %s\n", GY_GET_EXCEPT_STRING););
		return false;
	);
}	

// Already under RCU Lock
int TCP_SOCK_HANDLER::upd_conn_from_diag(struct inet_diag_msg *pdiag_msg, int rta_len, NETNS_ELEM *pnetns, uint64_t clock_diag, uint64_t tusec_diag, SOCK_INODE_TABLE *psocktbl, SOCK_INODE_SET *pchkset, LIST_HASH_SET * plisten_filter)
{
	struct rtattr 				*attr;
	uint8_t					idiag_family = pdiag_msg->idiag_family;
	uint32_t				addr32_be, uid;
	ino_t					sock_inode;
	unsigned __int128			addr128_be;
	GY_IP_ADDR				lhs_addr, rhs_addr;
	uint16_t				lhs_port, rhs_port;
	TCP_INFO_STATS				tcpi;
	GY_TCP_STATE_E				conn_state;
	int					ret;
	bool					bret;
	const int64_t				tsec_diag = tusec_diag/GY_USEC_PER_SEC;

	conn_state = (GY_TCP_STATE_E)pdiag_msg->idiag_state;

	if (gy_unlikely(conn_state >= GY_TCP_FIN_WAIT1 && conn_state <= GY_TCP_CLOSE_WAIT)) {
		return 0;
	}	

	if (idiag_family == AF_INET) {
		memcpy(&addr32_be, pdiag_msg->id.idiag_src, sizeof(addr32_be));
		lhs_addr.set_ip(addr32_be);

		memcpy(&addr32_be, pdiag_msg->id.idiag_dst, sizeof(addr32_be));
		rhs_addr.set_ip(addr32_be);
	}	
	else {
		memcpy(&addr128_be, pdiag_msg->id.idiag_src, sizeof(addr128_be));
		lhs_addr.set_ip(addr128_be);

		memcpy(&addr128_be, pdiag_msg->id.idiag_dst, sizeof(addr128_be));
		rhs_addr.set_ip(addr128_be);
	}	

	lhs_port 	= ntohs(pdiag_msg->id.idiag_sport);
	rhs_port 	= ntohs(pdiag_msg->id.idiag_dport);

	uid 		= pdiag_msg->idiag_uid;
	sock_inode	= pdiag_msg->idiag_inode;

	if (pnetns->clock_usec_.load(std::memory_order_relaxed) < clock_diag) {
		pnetns->clock_usec_.store(clock_diag, std::memory_order_relaxed);
	}

	NS_IP_PORT	l_ns_ip_port(lhs_addr, lhs_port, pnetns->get_ns_inode());	 
	NS_IP_PORT	r_ns_ip_port(rhs_addr, rhs_port, pnetns->get_ns_inode());	 

	uint32_t	lhash = l_ns_ip_port.get_hash(true /* ignore_ip */);

	auto check_cli_related = [this](TCP_CONN *ptcp, uint64_t clock_diag, bool is_listener)
	{
		bool					bret;

		if (false == ptcp->cli_task_updated_.load(std::memory_order_relaxed)) {
			auto newtaskcb = [&](TASK_STAT *ptask) 
			{ 
				ptask->is_tcp_client = true;
				ptcp->cli_task_shr_ = ptask->shared_from_this();

				std::memcpy(ptcp->cli_comm_, ptask->task_comm, sizeof(ptcp->cli_comm_));

				ptcp->cli_task_updated_.store(true, std::memory_order_relaxed);
				ptcp->cli_task_aggr_id_	= ptask->get_set_aggr_id();
			};
			bret = ptask_handler_->get_task(ptcp->cli_pid_, newtaskcb);
			
			if ((bret == false) && (ptcp->clock_usec_start_ < clock_diag - 31 * GY_USEC_PER_SEC)) {
				ptcp->cli_task_updated_.store(true, std::memory_order_relaxed);
			}	
		}

		if (ptcp->cli_listener_checked_ == false) {
			if (ptcp->cli_task_shr_) {
				ptcp->cli_related_listen_shr_ = ptcp->cli_task_shr_->related_listen_.load(std::memory_order_acquire);

				if (ptcp->cli_related_listen_shr_.get()) {
					ptcp->cli_listener_checked_ = true;
				}	
				else if ((false == is_listener && ptcp->clock_usec_start_ < clock_diag - 2 * GY_USEC_PER_SEC) || 
					(true == is_listener && ptcp->clock_usec_start_ < clock_diag - 110 * GY_USEC_PER_SEC)) {

					// Give time for NAT checks (2 sec) and inode checks (110 sec)
					ptcp->cli_listener_checked_ = true;
				}	
			}	
			else if (ptcp->clock_usec_start_ < clock_diag - 31 * GY_USEC_PER_SEC) {
				// Task likely exited
				ptcp->cli_listener_checked_ = true;
			}	
		}
	};

	const auto update_active_stats = [&](const TCP_CONN *ptcp, uint64_t bytes_sent, uint64_t bytes_rcvd, uint32_t cli_delay_msec, uint32_t ser_delay_msec, float rtt_msec, bool cli_listener_proc)
	{
		try {
			auto [cit, csuccess] = activeconnmap_.try_emplace(std::pair(ptcp->ser_glob_id_, ptcp->cli_task_aggr_id_), std::pair(ptcp->ser_glob_id_, ptcp->cli_task_aggr_id_),
						ptcp->ser_comm_, ptcp->cli_comm_, ptcp->peer_machine_id_, ptcp->is_tcp_accept_event_ ? ptcp->cli_madhava_id_ : ptcp->ser_madhava_id_,
						!ptcp->is_tcp_accept_event_, !ptcp->is_tcp_connect_event_);

			auto & 			clione = cit->second;

			clione.bytes_sent_ 	+= bytes_sent;
			clione.bytes_received_	+= bytes_rcvd;
			clione.cli_delay_msec_	+= cli_delay_msec;
			clione.ser_delay_msec_	+= ser_delay_msec;
			clione.active_conns_++;
			clione.cli_listener_proc_ |= cli_listener_proc;
			
			if (clione.max_rtt_msec_ < rtt_msec) {
				clione.max_rtt_msec_ = rtt_msec;
			}

			if ((cit->second.ser_comm_[0] == 0) && ptcp->ser_comm_[0]) {
				std::memcpy(cit->second.ser_comm_, ptcp->ser_comm_, sizeof(cit->second.ser_comm_));
				cit->second.ser_comm_[sizeof(cit->second.ser_comm_) - 1] = 0;
			}	

			if ((cit->second.cli_comm_[0] == 0) && ptcp->cli_comm_[0]) {
				std::memcpy(cit->second.cli_comm_, ptcp->cli_comm_, sizeof(cit->second.cli_comm_));
				cit->second.cli_comm_[sizeof(cit->second.cli_comm_) - 1] = 0;
			}	

			if (gy_unlikely(activeconnmap_.bytes_left() < 2 * sizeof(comm::ACTIVE_CONN_STATS))) {
				send_active_stats();
			}	
		}
		catch(...) {
		}	
	};

	if (conn_state != GY_TCP_LISTEN) {
		for (attr = (struct rtattr *) (pdiag_msg + 1); RTA_OK(attr, rta_len); attr = RTA_NEXT(attr, rta_len)) {

			if (attr->rta_type != INET_DIAG_INFO) {
				continue;
			}	
			
			GY_TCP_INFO		tinfo, *pinfo = &tinfo;
			int 			len = RTA_PAYLOAD(attr);

			if (gy_unlikely((size_t)len < sizeof(*pinfo))) {
				/* workaround for older kernels with less fields */
				std::memcpy(pinfo, RTA_DATA(attr), len);
				std::memset((char *)pinfo + len, 0, sizeof(*pinfo) - len);
			} 
			else {
				std::memcpy(pinfo, RTA_DATA(attr), sizeof(*pinfo));
			}	
			
			tcpi.populate_tcp_info(pinfo, clock_diag);

			ntcp_conns_++;

			if (tcpi.is_recent_activity(INET_DIAG_INTERVAL_SECS * 1000)) {
				nconn_recent_active_++;
			}

			/*
			 * Extra processing needed, if this an incoming connection and NAT active.
			 *
			 * First check from plisten_filter whether lhs or rhs is a listener. If so, then search the nat_tbl_ for
			 * the corresponding Client IP/Port without NAT. Then if the NAT elem has been updated with shared_ptr of TCP_CONN
			 * use that and update the TCP_CONN. If the shared_ptr has not been updated, search the main tcp_tbl_ with
			 * updated original client IP/Port
			 * 
			 * If no listener or no NAT found, then search directly the tcp_tbl_ for lhs
			 */

			bool					conn_updated = false, update_listener = false;
			TCP_CONN				*ptcp_new = nullptr;
			TCP_LISTENER				*pservlistener = nullptr;
			int64_t					ser_related_listen_id = 0; 
			uint64_t				ser_glob_id = 0;

			if (plisten_filter->end() != plisten_filter->find(lhash)) {
				
				/* This diag is likely from the server side of the conn */

				auto 	lambda_listchk = [&](TCP_LISTENER_ELEM_TYPE *pdatanode, void *arg1, void *arg2) -> CB_RET_E
				{
					auto 		plistener = pdatanode->get_cref().get();

					if (gy_unlikely(plistener == nullptr)) {
						return CB_OK;
					}
					
					if (gy_unlikely(plistener->clock_usec_.load(std::memory_order_relaxed) < start_inet_usec_)) { 
						plistener->clock_usec_.store(clock_diag, std::memory_order_relaxed);

						plistener->last_nconn_.store(plistener->nconn_.exchange_relaxed(0, std::memory_order_relaxed), std::memory_order_release);
						plistener->last_nconn_recent_active_.store(plistener->nconn_recent_active_.exchange_relaxed(0, std::memory_order_relaxed), 
											std::memory_order_release);

						plistener->curr_bytes_inbound_	= 0;	
						plistener->curr_bytes_outbound_	= 0;	

						uint64_t		last_close_bytes_in = plistener->last_close_bytes_in_;
						uint64_t		last_close_bytes_out = plistener->last_close_bytes_out_;

						plistener->last_close_bytes_in_	 	= GY_READ_ONCE(plistener->close_bytes_in_);
						plistener->last_close_bytes_out_	= GY_READ_ONCE(plistener->close_bytes_out_);

						plistener->curr_bytes_inbound_		+= gy_diff_counter_safe(plistener->last_close_bytes_in_, last_close_bytes_in);
						plistener->curr_bytes_outbound_		+= gy_diff_counter_safe(plistener->last_close_bytes_out_, last_close_bytes_out);

						plistener->cumul_bytes_inbound_		+= plistener->curr_bytes_inbound_;
						plistener->cumul_bytes_outbound_	+= plistener->curr_bytes_outbound_;
					}

					plistener->nconn_.fetch_add_relaxed(1, std::memory_order_relaxed);

					// Directly store the pointer as we are already under an RCU Lock
					pservlistener 		= plistener;	
					ser_related_listen_id	= GY_READ_ONCE(plistener->related_listen_id_);
					ser_glob_id		= plistener->glob_id_;

					if (tcpi.is_recent_activity(INET_DIAG_INTERVAL_SECS * 1000)) {
						plistener->nconn_recent_active_.fetch_add_relaxed(1, std::memory_order_relaxed);
					}
						
					if (0 == *plistener->server_domain_) {
						update_listener = true;
					}

					return CB_OK;
				};	

				bret = listener_tbl_.lookup_single_elem(l_ns_ip_port, lhash, lambda_listchk);
				if (bret == true) {
					/*
					 * Now check the NAT table as NAT may be active
					 */
	
					PAIR_IP_PORT		nat_tup  {r_ns_ip_port.ip_port_, l_ns_ip_port.ip_port_};
					IP_PORT			orig_cli_ip_port {r_ns_ip_port.ip_port_}, orig_ser_ip_port {l_ns_ip_port.ip_port_};

					auto 	lam_tcp_upd = [&](TCP_CONN *ptcp) 
					{
						uint64_t 		bytes_sent = 0, bytes_rcvd = 0;

						if (ptcp->clock_usec_start_ > clock_diag - 100 * GY_USEC_PER_MSEC) {
							// Ignore just started connections
							return;
						}

						if (pservlistener && (GY_READ_ONCE(ptcp->listen_updated_) == false)) {
							ptcp->listen_shr_ 		= pservlistener->shared_from_this();
							ptcp->ser_glob_id_		= ser_glob_id;
							ptcp->ser_madhava_id_		= local_madhava_id_;
							ptcp->ser_related_listen_id_	= ser_related_listen_id;

							if (ptcp->is_dnat_) {
								pservlistener->set_nat_ip_port(ptcp->ser_, tsec_diag);
							}	

							GY_WRITE_ONCE(ptcp->listen_updated_, true);
						}

						if (ptcp->ser_sock_inode_ != sock_inode) {
							ptcp->ser_sock_inode_ 	= sock_inode;
							ptcp->ser_uid_		= uid;
						}	

						if (false == ptcp->ser_task_updated_.load(std::memory_order_relaxed)) {
							auto newtaskcb = [&](TASK_STAT *ptask) 
							{ 
								ptask->is_tcp_server 	= true;
								ptcp->ser_task_shr_ 	= ptask->shared_from_this();
								ptcp->ser_task_aggr_id_	= ptask->get_set_aggr_id();

								if (ptcp->ser_task_shr_ && ptcp->ser_task_shr_->pext_stats) {
									ptcp->ser_task_shr_->pext_stats->ntcp_conn_++;
								}

								std::memcpy(ptcp->ser_comm_, ptask->task_comm, sizeof(ptcp->ser_comm_));
							};

							ptask_handler_->get_task(ptcp->ser_pid_, newtaskcb);

							ptcp->ser_task_updated_.store(true, std::memory_order_relaxed);

						}

						if ((ptcp->is_existing_conn_ == false) || ptcp->stats_.curr_usec_clock.load(std::memory_order_relaxed)) {
							bytes_sent 	= gy_diff_counter_safe(tcpi.bytes_acked, ptcp->stats_.bytes_acked);
							bytes_rcvd	= gy_diff_counter_safe(tcpi.bytes_received, ptcp->stats_.bytes_received);
						}	

						if (bytes_sent + bytes_rcvd) {

							int64_t 		statbytes = bytes_sent + bytes_rcvd;

							CONDEXEC( 
								DEBUGEXECN(10,
									const auto compxput = [statbytes](const TCP_XPUT_STATS & rhs) noexcept
									{
										return statbytes > rhs.stat_;
									};	
	
									topnxput_.try_emplace(compxput, ptcp->weak_from_this(), statbytes);
								);
							);	

							if (ptcp->ser_task_shr_ && ptcp->ser_task_shr_->pext_stats) {
								ptcp->ser_task_shr_->pext_stats->ntcp_bytes_ += statbytes;
							}	
						}	

						if (ptcp->is_client_local_.load(std::memory_order_relaxed) == true) {
							check_cli_related(ptcp, clock_diag, true);									

							if (ptcp->tcp_info_seen_ == false && ptcp->cli_task_shr_ && ptcp->cli_task_shr_->pext_stats) {
								ptcp->cli_task_shr_->pext_stats->ntcp_conn_++;
							}

							if (ptcp->tcp_info_seen_ == false) {
								ptcp->cli_madhava_id_	= local_madhava_id_;
								ptcp->peer_machine_id_ 	= machineid_;
							}

							if (ptcp->cli_related_listen_shr_) {
								ptcp->cli_listener_proc_ = true;
								
								ptcp->cli_related_listen_shr_->update_dependency(this, ptcp, bytes_rcvd, bytes_sent /* bytes sent/rcvd is reverse for cli */, 
														clock_diag, pservlistener); 
							}	

							if ((bytes_sent + bytes_rcvd) && ptcp->cli_task_shr_ && ptcp->cli_task_shr_->pext_stats) {
								ptcp->cli_task_shr_->pext_stats->ntcp_bytes_ += bytes_sent + bytes_rcvd;
							}	
						}	

						if ((ptcp->ser_comm_[0] == 0) && pservlistener) {
							std::memcpy(ptcp->ser_comm_, pservlistener->comm_, sizeof(ptcp->ser_comm_));
							ptcp->ser_comm_[sizeof(ptcp->ser_comm_) - 1] = 0;
						}

						if (bytes_sent + bytes_rcvd) {
							float			rtt_msec = 0; 
							uint32_t		cli_delay_msec = 0, ser_delay_msec = 0;

							if (tcpi.rtt_usec > 0) {
								rtt_msec = tcpi.rtt_usec/1000.0f;
							}	

							if (tcpi.busy_time_msec != ptcp->stats_.busy_time_msec) {
								ser_delay_msec 	= gy_diff_counter_safe(tcpi.busy_send_buf_time_msec, ptcp->stats_.busy_send_buf_time_msec);
								cli_delay_msec	= gy_diff_counter_safe(tcpi.busy_recv_win_time_msec, ptcp->stats_.busy_recv_win_time_msec);
							}	

							// Bytes sent/rcvd and delays are to be sent wrt Client side
							update_active_stats(ptcp, bytes_rcvd, bytes_sent, cli_delay_msec, ser_delay_msec, rtt_msec, ptcp->cli_listener_proc_);
						}

						GY_CC_BARRIER();

						ptcp->stats_ 		= tcpi;
						ptcp->tcp_info_seen_ 	= true;

						if (pservlistener) {
							pservlistener->curr_bytes_inbound_	+= bytes_rcvd;
							pservlistener->curr_bytes_outbound_	+= bytes_sent;

							pservlistener->cumul_bytes_inbound_	+= bytes_rcvd;
							pservlistener->cumul_bytes_outbound_	+= bytes_sent;
						}	

						if (0 == *ptcp->server_domain_ && (false == ptcp->is_dns_queried_)) {
							if (!ptcp->ser_.ipaddr_.is_loopback()) { 
								auto dp = pdns_mapping_->get_domain_from_ip(ptcp->ser_.ipaddr_, ptcp->server_domain_, sizeof(ptcp->server_domain_), tusec_diag);
								if (dp == true) {
									ptcp->is_dns_queried_ = true;	
								}	
								else if (ptcp->clock_usec_start_ < clock_diag - 2 * GY_USEC_PER_SEC) {
									ptcp->is_dns_queried_ = true;	
								}
							}	
							else {
								ptcp->is_dns_queried_ = true;	
							}	
						}	 

						if (*ptcp->server_domain_ && update_listener) {
							if (pservlistener) {
								pservlistener->last_dns_query_tsec_ = tusec_diag;
								GY_STRNCPY(pservlistener->server_domain_, ptcp->server_domain_, sizeof(pservlistener->server_domain_));
							}	
						}	

						if (ptcp->server_updated_.load(std::memory_order_acquire) == false) {
							char			cli_cmdline[comm::MAX_PROC_CMDLINE_LEN], *pclistr = nullptr;	
							size_t			cli_cmdline_len = 0;

							if ((ptcp->is_new_cli_task_) && (true == ptcp->cli_task_updated_.load(std::memory_order_relaxed))) {
								if (ptcp->cli_task_shr_) {
									pclistr		= cli_cmdline;
									cli_cmdline_len = std::min(comm::MAX_PROC_CMDLINE_LEN - 1, strlen(ptcp->cli_task_shr_->task_cmdline));

									std::memcpy(cli_cmdline, ptcp->cli_task_shr_->task_cmdline, cli_cmdline_len);
									cli_cmdline[cli_cmdline_len] = 0;
								}	
							}
							
							notify_tcp_conn(ptcp, 0ul, true /* more_data Always batch */, diag_cache_, pclistr, cli_cmdline_len);
						}	
					};	

					std::shared_ptr<NAT_ELEM>	natshr;

					auto lam_nat_listen = [&](NAT_ELEM_TYPE *pdatanode, void *arg1, void *arg2) -> CB_RET_E
					{
						auto			pnat = pdatanode->get_cref().get();

						if (pnat == nullptr) {
							return CB_DELETE_ELEM;
						}

						if (pnat->shr_updated_.load(std::memory_order_acquire)) {
							if (pnat->shrconn_) {
								lam_tcp_upd(pnat->shrconn_.get());	
							}
							conn_updated		= true;
						}
						else {
							natshr = *pdatanode->get_data();

							orig_cli_ip_port = pnat->orig_tup_.cli_;
							orig_ser_ip_port = pnat->orig_tup_.ser_;
						}	
								
						return CB_OK;
					};	

					bret = nat_tbl_.lookup_single_elem(nat_tup, nat_tup.get_hash(), lam_nat_listen);
						
					if (conn_updated == true) {
						return 0;
					}	
					
					PAIR_IP_PORT		orig_tup  {orig_cli_ip_port, orig_ser_ip_port};

					// Now search the tcp_tbl_ directly as this is a server side diag msg for a non NAT connection or NAT updation was missed

					auto 	lambda_chkconn = [&](TCP_CONN_ELEM_TYPE *pdatanode, void *arg1, void *arg2) -> CB_RET_E
					{
						TCP_CONN	*ptcp = pdatanode->get_cref().get();

						if (gy_unlikely(ptcp == nullptr)) {
							return CB_OK;
						}

						if (ptcp->clock_usec_start_ > clock_diag - 100 * GY_USEC_PER_MSEC && ptcp->is_tcp_accept_event_) {
							// Ignore just started connections
							return CB_OK;
						}
					
						auto 		pnat = natshr.get();

						if (gy_unlikely(pnat != nullptr)) {
							/*
							 * This implies that the nat_check_cache() missed updating the TCP connection 
							 */
							pnat->shrconn_		= ptcp->shared_from_this();

							ptcp->nat_updated_	= true;
							ptcp->is_snat_		= pnat->is_snat_;
							ptcp->is_dnat_		= pnat->is_dnat_;

							ptcp->nat_cli_		= pnat->nat_tup_.cli_;
							ptcp->nat_ser_		= pnat->nat_tup_.ser_;

							if (false == ptcp->is_server_local_.load(std::memory_order_acquire)) {
								// We need to delete the extra TCP conn as this is definitely a local conn

								auto 	lam_tcp = [this](TCP_CONN_ELEM_TYPE *pdatanode, void *arg1, void *arg2) -> CB_RET_E
								{
									auto			ptcp2 = pdatanode->get_cref().get();
									decltype(ptcp2)		ptcp = static_cast<decltype(ptcp2)>(arg1);

									if (ptcp2) {
										// Move stuff to ptcp before deletion
										ptcp->ser_ns_inode_.store(ptcp2->ser_ns_inode_.load(std::memory_order_relaxed), std::memory_order_relaxed);

										ptcp->is_tcp_connect_event_	= true;
										ptcp->is_tcp_accept_event_	= true;
										ptcp->is_dns_queried_ 		= false; // Reset as we will need to search for NAT server

										ptcp->is_server_local_.store(true, std::memory_order_relaxed);

										ptcp->ser_pid_			= ptcp2->ser_pid_;
										ptcp->ser_tid_			= ptcp2->ser_tid_;
										ptcp->ser_task_shr_		= std::move(ptcp2->ser_task_shr_);
										ptcp->ser_task_aggr_id_		= ptcp2->ser_task_aggr_id_;

										ptcp->cli_madhava_id_		= local_madhava_id_;
										ptcp->ser_madhava_id_		= local_madhava_id_;
										ptcp->peer_machine_id_ 		= machineid_;
										
										GY_STRNCPY(ptcp->ser_comm_, ptcp2->ser_comm_, sizeof(ptcp->ser_comm_));

										ntcp_coalesced_++;

										ptcp->ser_task_updated_.store(ptcp2->ser_task_updated_.load(std::memory_order_relaxed), std::memory_order_acq_rel);
									}

									return CB_DELETE_ELEM;
								};	

								tcp_tbl_.lookup_single_elem(pnat->nat_tup_, pnat->nat_tup_.get_hash(), lam_tcp, ptcp);

								if (pnat->is_dnat_ && ptcp->is_server_local_.load(std::memory_order_acq_rel) == false) {
									// We also need to delete the nat_tbl_ element	
									nat_tbl_.delete_single_elem(pnat->nat_tup_, pdatanode->get_rcu_hash());
								}
							}	

							pnat->shr_updated_.store(true, std::memory_order_release);
						}


						if (gy_unlikely(ptcp->is_tcp_accept_event_ == false)) {
							
							auto it = psocktbl->find(sock_inode);
								
							if (it != psocktbl->end()) {

								// This conn was missed and just recently added using inet diag
								ptcp->ser_ns_inode_.store(l_ns_ip_port.inode_, std::memory_order_relaxed);
								ptcp->ser_sock_inode_ 		= sock_inode;
								ptcp->ser_uid_			= uid;
								ptcp->ser_task_shr_		= it->second.task_weak_.lock();
								
								ptcp->is_existing_conn_		= true;

								auto ptask = ptcp->ser_task_shr_.get();

								if (ptask) {
									ptask->is_tcp_server 	= true;
									ptcp->ser_task_aggr_id_	= ptask->get_set_aggr_id();

									if (ptask->pext_stats) {
										ptask->pext_stats->ntcp_conn_++;
									}

									ptcp->ser_task_updated_.store(true, std::memory_order_relaxed);

									std::memcpy(ptcp->ser_comm_, ptask->task_comm, sizeof(ptcp->ser_comm_));
								}
									
								ptcp->is_tcp_accept_event_	= true;

								GY_STRNCPY(ptcp->ser_comm_, it->second.comm_, sizeof(ptcp->ser_comm_));

								ptcp->is_server_local_.store(true, std::memory_order_acq_rel); 
							}
						}

						conn_updated = true;

						lam_tcp_upd(ptcp);	

						return CB_OK;
					};

					bret = tcp_tbl_.lookup_single_elem(orig_tup, orig_tup.get_hash(), lambda_chkconn);

					if (gy_unlikely(bret == false)) {
						if (pinfo->tcpi_state == GY_TCP_ESTABLISHED && sock_inode != 0) {
							// Not an error as the conn may have been concurrently deleted... 

							// We check if pchkset is populated for this inode. If true, then
							// insert inode into psocktbl and wait for next iteration.
							// This 2 step process is done to ensure concurrent deletes do not
							// result in unnecessary /proc inode searches.

							auto it = psocktbl->find(sock_inode);
								
							if (it == psocktbl->end()) {
								try {
									auto cit = pchkset->find(sock_inode);

									if (cit == pchkset->end()) {
										pchkset->insert(sock_inode);
									}
									else {
										pchkset->erase(cit);

										SOCK_INODE_INFO		sock;	
									
										sock.sock_inode_ 	= sock_inode;
										
										psocktbl->emplace(sock_inode, std::move(sock));

										DEBUGEXECN(10, 
											INFOPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "TCP Conn not found for %s : will try adding later\n", 
												orig_tup.print_string(STRING_BUFFER<512>().get_str_buf())); 
										);
									}
								}
								catch(...) {

								}	
							}	
							else {
								// Add a new TCP conn : Directly use conn_v6_pool_ and conn_v6_elem_pool_ as anyways ::malloc will be used
								TCP_CONN  			*ptcp;
								TCP_CONN_ELEM_TYPE		*pelem;
								FREE_FPTR			free_fp;
								
								ptcp = (TCP_CONN *)conn_v6_pool_.safe_malloc(free_fp, true /* use_malloc_hdr */);

								try {
									new (ptcp) TCP_CONN(orig_cli_ip_port, orig_ser_ip_port, 0, 0, it->second.pid_, it->second.pid_, clock_diag);	
								}
								catch(...) {
									THR_POOL_ALLOC::dealloc(ptcp);
									return 0;
								}	
								
								uint32_t			onhash = orig_tup.get_hash();

								ptcp->ser_ns_inode_.store(l_ns_ip_port.inode_, std::memory_order_relaxed);
								ptcp->ser_sock_inode_ 		= sock_inode;
								ptcp->ser_uid_			= uid;
								ptcp->ser_task_shr_		= it->second.task_weak_.lock();
								ptcp->conn_hash_		= onhash;
								
								ptcp->is_existing_conn_		= true;

								auto ptask = ptcp->ser_task_shr_.get();

								if (ptask) {
									ptask->is_tcp_server 	= true;
									ptcp->ser_task_aggr_id_	= ptask->get_set_aggr_id();

									if (ptask->pext_stats) {
										ptask->pext_stats->ntcp_conn_++;
									}

									ptcp->ser_task_updated_.store(true, std::memory_order_relaxed);
								}
									
								ptcp->is_tcp_accept_event_	= true;
								ptcp->ser_madhava_id_		= local_madhava_id_;

								ptcp->is_server_local_.store(true, std::memory_order_release);

								GY_STRNCPY(ptcp->ser_comm_, it->second.comm_, sizeof(ptcp->ser_comm_));

								try {
									pelem = (TCP_CONN_ELEM_TYPE *)conn_v6_elem_pool_.safe_malloc(free_fp, true /* use_malloc_hdr */);

									try {
										new (pelem) TCP_CONN_ELEM_TYPE(ptcp, TPOOL_DEALLOC<TCP_CONN>());
									}
									catch(...) {
										THR_POOL_ALLOC::dealloc(pelem);
										throw;
									}	

									// Do not update natshr
									
									INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Adding new TCP Server Conn as TCP Conn add missed for %s\n", 
										ptcp->print_string(STRING_BUFFER<512>().get_str_buf(), false)); 

									bret = tcp_tbl_.insert_or_replace(pelem, orig_tup, onhash);
								}
								GY_CATCH_EXCEPTION(
									DEBUGEXECN(1, ERRORPRINT_OFFLOAD("Caught exception while allocating memory for new TCP Connection : %s\n", 
										GY_GET_EXCEPT_STRING););

									ptcp->~TCP_CONN();
									THR_POOL_ALLOC::dealloc(ptcp);
								);
							}
						}	
					}	
							
					return 0;
				}	
			}

			// Directly search the tcp_tbl_ as lhs is the client side
			PAIR_IP_PORT		act_tup  {l_ns_ip_port.ip_port_, r_ns_ip_port.ip_port_};
			
			auto 	lambda_chkconn2 = [&](TCP_CONN_ELEM_TYPE *pdatanode, void *arg1, void *arg2) -> CB_RET_E
			{
				TCP_CONN	*ptcp = pdatanode->get_cref().get();
				uint64_t	bytes_sent = 0, bytes_rcvd = 0;

				if (gy_unlikely(ptcp == nullptr)) {
					return CB_OK;
				}

				conn_updated 			= true;

				if ((gy_unlikely(ptcp->is_tcp_connect_event_ == false)) && psocktbl) {
					
					auto it = psocktbl->find(sock_inode);
						
					if (it != psocktbl->end()) {
						// This conn was missed and added on the fly

						ptcp->cli_ns_inode_		= l_ns_ip_port.inode_;
						ptcp->cli_sock_inode_ 		= sock_inode;
						ptcp->cli_uid_			= uid;
						ptcp->cli_pid_			= it->second.pid_;
						ptcp->cli_tid_			= it->second.pid_;
						ptcp->cli_task_shr_		= it->second.task_weak_.lock();

						ptcp->is_existing_conn_		= true;

						auto ptask = ptcp->cli_task_shr_.get();

						if (ptask) {
							ptask->is_tcp_client 	= true;
							ptcp->cli_task_aggr_id_	= ptask->get_set_aggr_id();
							ptcp->cli_task_updated_.store(true, std::memory_order_relaxed);

							std::memcpy(ptcp->cli_comm_, ptask->task_comm, sizeof(ptcp->cli_comm_));
						}

						ptcp->is_tcp_connect_event_	= true;

						ptcp->is_client_local_.store(true, std::memory_order_relaxed);

						GY_STRNCPY(ptcp->cli_comm_, it->second.comm_, sizeof(ptcp->cli_comm_));
					}
				}

				if (ptcp->clock_usec_start_ > clock_diag - 100 * GY_USEC_PER_MSEC) {
					// Ignore just started connections
					return CB_OK;
				}
					

				if (ptcp->cli_sock_inode_ != sock_inode) {
					ptcp->cli_sock_inode_ 	= sock_inode;
					ptcp->cli_uid_		= uid;
				}	
				 
				check_cli_related(ptcp, clock_diag, false);									

				if (false == ptcp->is_server_local_.load(std::memory_order_relaxed)) {
					if (ptcp->tcp_info_seen_ == false) {
						ptcp->cli_madhava_id_	= local_madhava_id_;
					}

					if ((ptcp->is_existing_conn_ == false) || ptcp->stats_.curr_usec_clock.load(std::memory_order_relaxed)) {
						bytes_sent 	= gy_diff_counter_safe(tcpi.bytes_acked, ptcp->stats_.bytes_acked);
						bytes_rcvd	= gy_diff_counter_safe(tcpi.bytes_received, ptcp->stats_.bytes_received);

						if (bytes_sent + bytes_rcvd) {
							int64_t			statbytes = bytes_sent + bytes_rcvd;

							CONDEXEC(
								DEBUGEXECN(10,
									const auto compxput = [statbytes](const TCP_XPUT_STATS & rhs) noexcept
									{
										return statbytes > rhs.stat_;
									};	

									topnxput_.try_emplace(compxput, ptcp->weak_from_this(), statbytes);
								);	
							);

							if (ptcp->cli_task_shr_ && ptcp->cli_task_shr_->pext_stats) {
								ptcp->cli_task_shr_->pext_stats->ntcp_bytes_ += statbytes;
							}	

							float			rtt_msec = 0;
							uint32_t		cli_delay_msec = 0, ser_delay_msec = 0;

							if (tcpi.rtt_usec > 0) {
								rtt_msec = tcpi.rtt_usec/1000.0f;
							}	

							if (tcpi.busy_time_msec != ptcp->stats_.busy_time_msec) {
								cli_delay_msec 	= gy_diff_counter_safe(tcpi.busy_send_buf_time_msec, ptcp->stats_.busy_send_buf_time_msec);
								ser_delay_msec	= gy_diff_counter_safe(tcpi.busy_recv_win_time_msec, ptcp->stats_.busy_recv_win_time_msec);
							}	

							update_active_stats(ptcp, bytes_sent, bytes_rcvd, cli_delay_msec, ser_delay_msec, rtt_msec, ptcp->cli_listener_proc_ /* already updated */);
						}	
					}
					else {
						if (ptcp->cli_task_shr_ && ptcp->cli_task_shr_->pext_stats) {
							ptcp->cli_task_shr_->pext_stats->ntcp_conn_++;
						}	
					}	

					GY_CC_BARRIER();

					ptcp->stats_ 			= tcpi;
					ptcp->tcp_info_seen_ 		= true;

					if (ptcp->clock_usec_start_ < clock_diag - 500 * GY_USEC_PER_MSEC) {
						if (0 == *ptcp->server_domain_ && (false == ptcp->is_dns_queried_)) {
							if (!ptcp->ser_.ipaddr_.is_loopback()) { 
								pdns_mapping_->get_domain_from_ip(ptcp->ser_.ipaddr_, ptcp->server_domain_, sizeof(ptcp->server_domain_), tusec_diag);
							}
								
							ptcp->is_dns_queried_ = true;	
						}	
					}

					if (ptcp->cli_related_listen_shr_) {
						ptcp->cli_listener_proc_ = true;
						
						if (ptcp->clock_usec_start_ < clock_diag - 500 * GY_USEC_PER_MSEC) {
							// Give time for NAT checks
							ptcp->cli_related_listen_shr_->update_dependency(this, ptcp, bytes_sent, bytes_rcvd, clock_diag); 
						}	
					}	
				
					if (ptcp->server_updated_.load(std::memory_order_acquire) == false) {
						char			cli_cmdline[comm::MAX_PROC_CMDLINE_LEN], *pclistr = nullptr;	
						size_t			cli_cmdline_len = 0;

						if (ptcp->is_new_cli_task_) {
							if (true == ptcp->cli_task_updated_.load(std::memory_order_relaxed)) {
								if (ptcp->cli_task_shr_) {
									pclistr		= cli_cmdline;
									cli_cmdline_len = std::min(comm::MAX_PROC_CMDLINE_LEN - 1, strlen(ptcp->cli_task_shr_->task_cmdline));

									std::memcpy(cli_cmdline, ptcp->cli_task_shr_->task_cmdline, cli_cmdline_len);
									cli_cmdline[cli_cmdline_len] = 0;
								}	
							}
						}	
						notify_tcp_conn(ptcp, 0ul, true /* more_data Always batch */, diag_cache_, pclistr, cli_cmdline_len);
					}	
				}

				return CB_OK;
			};

			bret = tcp_tbl_.lookup_single_elem(act_tup, act_tup.get_hash(), lambda_chkconn2);

			if (gy_unlikely(bret == false)) {
				if (pinfo->tcpi_state == GY_TCP_ESTABLISHED && sock_inode != 0) {
					// Not an error as the conn may have been concurrently deleted... See comment above

					auto it = psocktbl->find(sock_inode);
						
					if (it == psocktbl->end()) {
						try {
							auto cit = pchkset->find(sock_inode);

							if (cit == pchkset->end()) {
								pchkset->insert(sock_inode);
							}
							else {
								pchkset->erase(cit);

								SOCK_INODE_INFO		sock;	
								
								sock.sock_inode_ 	= sock_inode;
										
								psocktbl->emplace(sock_inode, std::move(sock));

								DEBUGEXECN(10, 
									INFOPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "TCP Conn not found for %s : will try adding later\n", 
										act_tup.print_string(STRING_BUFFER<512>().get_str_buf())); 
								);
							}
						}
						catch(...) {

						}	
					}	
					else {

						// Add a new TCP conn : Directly use conn_v6_pool_ and conn_v6_elem_pool_ as anyways ::malloc will be used
						TCP_CONN			*ptcp;
						TCP_CONN_ELEM_TYPE		*pelem;
						FREE_FPTR			free_fp;
						
						ptcp = (TCP_CONN *)conn_v6_pool_.safe_malloc(free_fp, true /* use_malloc_hdr */);

						try {
							new (ptcp) TCP_CONN(act_tup.cli_, act_tup.ser_, it->second.pid_, it->second.pid_, 0, 0, clock_diag);	
						}
						catch(...) {
							THR_POOL_ALLOC::dealloc(ptcp);
							return 0;
						}	

						uint32_t			anhash = act_tup.get_hash();
						
						ptcp->cli_ns_inode_		= l_ns_ip_port.inode_;
						ptcp->cli_sock_inode_ 		= sock_inode;
						ptcp->cli_uid_			= uid;
						ptcp->cli_pid_			= it->second.pid_;
						ptcp->cli_tid_			= it->second.pid_;
						ptcp->cli_task_shr_		= it->second.task_weak_.lock();
						ptcp->conn_hash_		= anhash;

						ptcp->is_existing_conn_		= true;

						auto ptask = ptcp->cli_task_shr_.get();

						if (ptask) {
							ptask->is_tcp_client 	= true;
							ptcp->cli_task_aggr_id_	= ptask->get_set_aggr_id();
							ptcp->cli_task_updated_.store(true, std::memory_order_relaxed);
						}

						ptcp->is_tcp_connect_event_	= true;

						ptcp->is_client_local_.store(true, std::memory_order_relaxed);

						GY_STRNCPY(ptcp->cli_comm_, it->second.comm_, sizeof(ptcp->cli_comm_));

						try {
							pelem = (TCP_CONN_ELEM_TYPE *)conn_v6_elem_pool_.safe_malloc(free_fp, true /* use_malloc_hdr */);

							try {
								new (pelem) TCP_CONN_ELEM_TYPE(ptcp, TPOOL_DEALLOC<TCP_CONN>());
							}
							catch (...) {
								THR_POOL_ALLOC::dealloc(pelem);
								throw;
							}	

							INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Adding new TCP Client Conn as TCP Conn add missed for %s\n", 
								ptcp->print_string(STRING_BUFFER<512>().get_str_buf(), false)); 

							tcp_tbl_.insert_or_replace(pelem, act_tup, anhash);
						}
						GY_CATCH_EXCEPTION(
							DEBUGEXECN(1, ERRORPRINT_OFFLOAD("Caught exception while allocating memory for new TCP Connection : %s\n", GY_GET_EXCEPT_STRING););

							ptcp->~TCP_CONN();
							THR_POOL_ALLOC::dealloc(ptcp);
						);
					}
				}
			}
			return 0;
		}
	}
	else if (lhs_port == 0) {
		return 0;	
	}
					
	/*
	 * This logic assumes that all Inet Diag messages have Listener info at the start as per 
	 * Kernel source inet_diag_dump_icsk() XXX If this logic changes, will need to revisit the following...
	 */				

	auto lambda_list = [&, plisten_filter](TCP_LISTENER_ELEM_TYPE *pdatanode, void *arg1, void *arg2) -> CB_RET_E
	{
		auto 			plistener = pdatanode->get_cref().get();
		

		if (gy_unlikely(plistener == nullptr)) {
			return CB_DELETE_ELEM;
		}

		try {
			auto		[it, success] = plisten_filter->emplace(lhash);

			if (success) {
				plistener->uid_ 	= uid;

				if (indeterminate(plistener->httperr_cap_started_.load(std::memory_order_relaxed)) && capture_errcode_) {
					ino_t			inode = plistener->ns_ip_port_.inode_;
					uint16_t		port = plistener->ns_ip_port_.ip_port_.port_;

					if (true == typeinfo::not_http_service(port, plistener->comm_, plistener->cmdline_)) {

						plistener->httperr_cap_started_.store(false, std::memory_order_relaxed);
						plistener->is_http_svc_ = false;
					}
					else if (bool(svcnetcap_) && svcnetcap_->is_svc_cap_allowed(false /* isapicall */)) {
						auto		[it, success] = svcinodemap_.try_emplace(inode);
						auto		& vec = it->second;

						vec.emplace_back(plistener->shared_from_this());
					}
				}	
			}
		}
		catch(...) {
		}	

		if (lhs_addr.is_ipv4_addr()) {
			if (plistener->sock_ipv4_inode_ != sock_inode) {
				plistener->sock_ipv4_inode_ 	= sock_inode;
			}	
		}
		else {
			if (plistener->sock_ipv6_inode_ != sock_inode) {
				plistener->sock_ipv6_inode_ 	= sock_inode;
			}	
		}		

		if (plistener->clock_usec_.load(std::memory_order_relaxed) < start_inet_usec_) { 
			plistener->clock_usec_.store(clock_diag, std::memory_order_relaxed);

			plistener->last_nconn_.store(plistener->nconn_.exchange_relaxed(0, std::memory_order_relaxed), std::memory_order_release);
			plistener->last_nconn_recent_active_.store(plistener->nconn_recent_active_.exchange_relaxed(0, std::memory_order_relaxed), std::memory_order_release);
			
			plistener->curr_bytes_inbound_	= 0;	
			plistener->curr_bytes_outbound_	= 0;	

			uint64_t		last_close_bytes_in = plistener->last_close_bytes_in_;
			uint64_t		last_close_bytes_out = plistener->last_close_bytes_out_;

			plistener->last_close_bytes_in_	 	= GY_READ_ONCE(plistener->close_bytes_in_);
			plistener->last_close_bytes_out_ 	= GY_READ_ONCE(plistener->close_bytes_out_);

			plistener->curr_bytes_inbound_		+= gy_diff_counter_safe(plistener->last_close_bytes_in_, last_close_bytes_in);
			plistener->curr_bytes_outbound_		+= gy_diff_counter_safe(plistener->last_close_bytes_out_, last_close_bytes_out);

			plistener->cumul_bytes_inbound_		+= plistener->curr_bytes_inbound_;
			plistener->cumul_bytes_outbound_	+= plistener->curr_bytes_outbound_;

			if (0 == *plistener->server_domain_ && plistener->last_nat_chg_ip_tsec_) {

				if ((plistener->nat_ip_port_arr_[0].port_ != 0) && (plistener->last_dns_query_tsec_ < tsec_diag - 300)) {
					bool			dfound;

					plistener->last_dns_query_tsec_ = tsec_diag;

					dfound = pdns_mapping_->get_domain_from_ip(plistener->nat_ip_port_arr_[0].ipaddr_, plistener->server_domain_,
							sizeof(plistener->server_domain_), tusec_diag);

					if (!dfound && plistener->nat_ip_port_arr_[1].port_) {
						pdns_mapping_->get_domain_from_ip(plistener->nat_ip_port_arr_[1].ipaddr_, plistener->server_domain_, 
							sizeof(plistener->server_domain_), tusec_diag);
					}	
				}	
			}	
		}		

		return CB_OK;
	};	

	bret = listener_tbl_.lookup_single_elem(l_ns_ip_port, lhash, lambda_list);

	if (!bret) {
		nlisten_missed_++;
	}	
	
	return 0;
}	

// Called from under a RCU_LOCK_SLOW
int TCP_SOCK_HANDLER::add_conn_from_diag(struct inet_diag_msg *pdiag_msg, int rta_len, NETNS_ELEM *pnetns, uint64_t clock_diag, SOCK_INODE_TABLE *psocktbl, LIST_HASH_SET * plisten_filter, TASK_PGTREE_MAP *ptreemap, bool only_listen)
{
	struct rtattr 			*attr;
	uint8_t				idiag_family = pdiag_msg->idiag_family;
	uint32_t			addr32_be, uid;
	ino_t				sock_inode;
	unsigned __int128		addr128_be;
	GY_IP_ADDR			lhs_addr, rhs_addr;
	uint16_t			lhs_port, rhs_port;
	GY_TCP_STATE_E			conn_state;
	int				ret;
	bool				bret;

	conn_state = (GY_TCP_STATE_E)pdiag_msg->idiag_state;

	if (conn_state >= GY_TCP_FIN_WAIT1 && conn_state <= GY_TCP_CLOSE_WAIT) {
		return 0;
	}	

	if (only_listen && (conn_state != GY_TCP_LISTEN)) {
		return 0;
	}	

	if (idiag_family == AF_INET) {
		memcpy(&addr32_be, pdiag_msg->id.idiag_src, sizeof(addr32_be));
		lhs_addr.set_ip(addr32_be);

		memcpy(&addr32_be, pdiag_msg->id.idiag_dst, sizeof(addr32_be));
		rhs_addr.set_ip(addr32_be);
	}	
	else {
		memcpy(&addr128_be, pdiag_msg->id.idiag_src, sizeof(addr128_be));
		lhs_addr.set_ip(addr128_be);

		memcpy(&addr128_be, pdiag_msg->id.idiag_dst, sizeof(addr128_be));
		rhs_addr.set_ip(addr128_be);

		if ((lhs_addr.is_mapped_ipv4()) || (rhs_addr.is_mapped_ipv4())) {
			// The ebpf callbacks strip off the mapped addresses. Sync with that
			uint32_t	taddr1 = lhs_addr.get_embedded_ipv4_be(), taddr2 = rhs_addr.get_embedded_ipv4_be();

			lhs_addr.set_ip(taddr1);
			rhs_addr.set_ip(taddr2);
		}	
	}	

	lhs_port 	= ntohs(pdiag_msg->id.idiag_sport);
	rhs_port 	= ntohs(pdiag_msg->id.idiag_dport);

	uid 		= pdiag_msg->idiag_uid;
	sock_inode	= pdiag_msg->idiag_inode;

	NS_IP_PORT	l_ns_ip_port(lhs_addr, lhs_port, pnetns->get_ns_inode());	 
	NS_IP_PORT	r_ns_ip_port(rhs_addr, rhs_port, pnetns->get_ns_inode());	 

	uint32_t	lhash = l_ns_ip_port.get_hash(true /* ignore_ip */);

	auto it = psocktbl->find(sock_inode);

	if (pnetns->clock_usec_.load(std::memory_order_relaxed) < clock_diag) {
		pnetns->clock_usec_.store(clock_diag, std::memory_order_relaxed);
	}
					
	if (conn_state != GY_TCP_LISTEN) {

		bool			conn_updated = false;
		TCP_CONN		*ptcp_new = nullptr;

		if (plisten_filter->end() != plisten_filter->find(lhash)) {
			
			/* This diag is from the server side of the conn. But we still need to verify from listener_tbl_ */

			bret = listener_tbl_.template lookup_single_elem<RCU_LOCK_FAST>(l_ns_ip_port, lhash);
			if (bret == true) {

				/*
				 * Now check the NAT table as NAT may be active. The NAT element weak_ptr will alse be updated.
				 */
				PAIR_IP_PORT		nat_tup  {r_ns_ip_port.ip_port_, l_ns_ip_port.ip_port_};
				IP_PORT			orig_cli_ip_port {r_ns_ip_port.ip_port_}, orig_ser_ip_port {l_ns_ip_port.ip_port_};

				NAT_ELEM_TYPE		nat;
				NAT_ELEM  		*pnat = nullptr;

				bret = nat_tbl_.template lookup_single_elem<RCU_LOCK_FAST>(nat_tup, nat_tup.get_hash(), nat);
				
				if (bret == true) {
					pnat = nat.get_cref().get();

					if (pnat) {
						orig_cli_ip_port 	= pnat->orig_tup_.cli_;
						orig_ser_ip_port	= pnat->orig_tup_.ser_;
					}
				}	

				PAIR_IP_PORT  		act_tup  {orig_cli_ip_port, orig_ser_ip_port};

				auto 	lambda_chkconn = [&](TCP_CONN_ELEM_TYPE *pdatanode, void *arg1, void *arg2) -> CB_RET_E
				{
					TCP_CONN  	*ptcp = pdatanode->get_cref().get();

					if (gy_unlikely(ptcp == nullptr)) {
						return CB_OK;
					}

					conn_updated 			= true;

					ptcp->ser_ns_inode_.store(l_ns_ip_port.inode_, std::memory_order_relaxed);
					ptcp->ser_sock_inode_ 		= sock_inode;
					ptcp->ser_uid_			= uid;
					ptcp->is_tcp_accept_event_	= true;

					ptcp->is_server_local_.store(true, std::memory_order_release);

					if (it != psocktbl->end()) {
						ptcp->ser_pid_		= it->second.pid_;
						ptcp->ser_tid_		= it->second.pid_;
						ptcp->ser_task_shr_	= it->second.task_weak_.lock();
						
						auto ptask = ptcp->ser_task_shr_.get();

						if (ptask) {
							ptask->is_tcp_server = true;
						}
							
						GY_STRNCPY(ptcp->ser_comm_, it->second.comm_, sizeof(ptcp->ser_comm_));
					}	
					 
					if (pnat) {
						pnat->shrconn_		= ptcp->shared_from_this();

						ptcp->nat_updated_	= true;
						ptcp->is_snat_		= pnat->is_snat_;
						ptcp->is_dnat_		= pnat->is_dnat_;

						ptcp->nat_cli_		= pnat->nat_tup_.cli_;
						ptcp->nat_ser_		= pnat->nat_tup_.ser_;

						pnat->shr_updated_.store(true, std::memory_order_release);
					}
							
					CONDEXEC(
						DEBUGEXECN(5, 
							INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "[TCP Accept] : Updating existing Conn : %s\n", 
								ptcp->print_string(STRING_BUFFER<512>().get_str_buf(), false)); 
						);
					);	


					return CB_OK;
				};

				bret = tcp_tbl_.template lookup_single_elem<decltype(lambda_chkconn), RCU_LOCK_FAST>(act_tup, act_tup.get_hash(), 
							lambda_chkconn);

				if (conn_updated) {
					return 0;
				}	

				if (it != psocktbl->end()) {

					// Add a new TCP conn : Directly use conn_v6_pool_ and conn_v6_elem_pool_ as anyways ::malloc will be used
					TCP_CONN  			*ptcp;
					TCP_CONN_ELEM_TYPE		*pelem;
					FREE_FPTR			free_fp;

					ptcp = (TCP_CONN *)conn_v6_pool_.safe_malloc(free_fp, true /* use_malloc_hdr */);

					try {
						new (ptcp) TCP_CONN(orig_cli_ip_port, orig_ser_ip_port, 0, 0, it->second.pid_, it->second.pid_, clock_diag);	
					}
					catch(...) {
						THR_POOL_ALLOC::dealloc(ptcp);
						return -1;
					}
					
					uint32_t			anhash = act_tup.get_hash();

					ptcp->ser_ns_inode_.store(l_ns_ip_port.inode_, std::memory_order_relaxed);
					ptcp->ser_sock_inode_ 		= sock_inode;
					ptcp->ser_uid_			= uid;
					ptcp->ser_task_shr_		= it->second.task_weak_.lock();
					ptcp->conn_hash_		= anhash;
					
					ptcp->is_existing_conn_		= true;

					auto ptask = ptcp->ser_task_shr_.get();

					if (ptask) {
						ptask->is_tcp_server 	= true;
						ptcp->ser_task_aggr_id_	= ptask->get_set_aggr_id();
						ptcp->ser_task_updated_.store(true, std::memory_order_relaxed);
					}
						
					ptcp->is_tcp_accept_event_	= true;

					ptcp->is_server_local_.store(true, std::memory_order_release);

					GY_STRNCPY(ptcp->ser_comm_, it->second.comm_, sizeof(ptcp->ser_comm_));

					try {

						pelem = (TCP_CONN_ELEM_TYPE *)conn_v6_elem_pool_.safe_malloc(free_fp, true /* use_malloc_hdr */);

						try {
							new (pelem) TCP_CONN_ELEM_TYPE(ptcp, TPOOL_DEALLOC<TCP_CONN>());
						}
						catch(...) {
							THR_POOL_ALLOC::dealloc(pelem);
							throw;
						}

						if (pnat) {
							pnat->shrconn_		= ptcp->shared_from_this();

							ptcp->nat_updated_	= true;
							ptcp->is_snat_		= pnat->is_snat_;
							ptcp->is_dnat_		= pnat->is_dnat_;

							ptcp->nat_cli_		= pnat->nat_tup_.cli_;
							ptcp->nat_ser_		= pnat->nat_tup_.ser_;

							pnat->shr_updated_.store(true, std::memory_order_release);
						}
					}
					GY_CATCH_EXCEPTION(
						DEBUGEXECN(1, ERRORPRINT_OFFLOAD("Caught exception while allocating memory for new TCP Connection : %s\n", GY_GET_EXCEPT_STRING););

						ptcp->~TCP_CONN();
						THR_POOL_ALLOC::dealloc(ptcp);
						return -1;
					);
					
					CONDEXEC(
						DEBUGEXECN(5, 
							INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "[TCP Accept] : Updating existing Conn : %s\n",
								ptcp->print_string(STRING_BUFFER<512>().get_str_buf(), false)); 
						);
					);	

					bret = tcp_tbl_.template insert_or_replace<RCU_LOCK_FAST>(pelem, act_tup, anhash);
				}

				return 0;
			}	
		}

		// Directly add an entry as lhs is the client side
		PAIR_IP_PORT		act_tup  {l_ns_ip_port.ip_port_, r_ns_ip_port.ip_port_};

		auto 	lambda_chkconn2 = [&](TCP_CONN_ELEM_TYPE *pdatanode, void *arg1, void *arg2) -> CB_RET_E
		{
			TCP_CONN	*ptcp = pdatanode->get_cref().get();

			if (gy_unlikely(ptcp == nullptr)) {
				return CB_OK;
			}

			conn_updated 			= true;

			ptcp->cli_ns_inode_		= l_ns_ip_port.inode_;
			ptcp->cli_sock_inode_ 		= sock_inode;
			ptcp->cli_uid_			= uid;
			ptcp->is_tcp_connect_event_	= true;

			ptcp->is_client_local_.store(true, std::memory_order_relaxed);

			if (it != psocktbl->end()) {
				ptcp->cli_pid_		= it->second.pid_;
				ptcp->cli_tid_		= it->second.pid_;
				ptcp->cli_task_shr_	= it->second.task_weak_.lock();

				auto ptask = ptcp->cli_task_shr_.get();

				if (ptask) {
					ptask->is_tcp_client 	= true;
					ptcp->cli_task_aggr_id_	= ptask->get_set_aggr_id();
					ptcp->cli_task_updated_.store(true, std::memory_order_relaxed);
				}

				GY_STRNCPY(ptcp->cli_comm_, it->second.comm_, sizeof(ptcp->cli_comm_));
			}	

			CONDEXEC(
				DEBUGEXECN(5, 
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "[TCP Connect] : Updating existing Conn : %s\n", 
						ptcp->print_string(STRING_BUFFER<512>().get_str_buf(), false)); 
				);
			);	

			return CB_OK;
		};

		bret = tcp_tbl_.template lookup_single_elem<decltype(lambda_chkconn2), RCU_LOCK_FAST>(act_tup, act_tup.get_hash(), 
					lambda_chkconn2);

		if (conn_updated) {
			return 0;
		}	

		if (it != psocktbl->end()) {

			// Add a new TCP conn : Directly use conn_v6_pool_ and conn_v6_elem_pool_ as anyways ::malloc will be used
			TCP_CONN			*ptcp;
			TCP_CONN_ELEM_TYPE		*pelem;
			FREE_FPTR			free_fp;
			
			ptcp = (TCP_CONN *)conn_v6_pool_.safe_malloc(free_fp, true /* use_malloc_hdr */);

			try {
				new (ptcp) TCP_CONN(act_tup.cli_, act_tup.ser_, it->second.pid_, it->second.pid_, 0, 0, clock_diag);	
			}
			catch(...) {
				THR_POOL_ALLOC::dealloc(ptcp);
				return -1;
			}	
			
			uint32_t			anhash = act_tup.get_hash();

			ptcp->cli_ns_inode_		= l_ns_ip_port.inode_;
			ptcp->cli_sock_inode_ 		= sock_inode;
			ptcp->cli_uid_			= uid;
			ptcp->cli_pid_			= it->second.pid_;
			ptcp->cli_tid_			= it->second.pid_;
			ptcp->cli_task_shr_		= it->second.task_weak_.lock();
			ptcp->conn_hash_		= anhash;

			ptcp->is_existing_conn_		= true;

			auto ptask = ptcp->cli_task_shr_.get();

			if (ptask) {
				ptask->is_tcp_client = true;
				ptcp->cli_task_aggr_id_	= ptask->get_set_aggr_id();
				ptcp->cli_task_updated_.store(true, std::memory_order_relaxed);
			}

			ptcp->is_tcp_connect_event_	= true;

			ptcp->is_client_local_.store(true, std::memory_order_relaxed);

			GY_STRNCPY(ptcp->cli_comm_, it->second.comm_, sizeof(ptcp->cli_comm_));

			pelem = nullptr;

			try {
				pelem = (TCP_CONN_ELEM_TYPE *)conn_v6_elem_pool_.safe_malloc(free_fp, true /* use_malloc_hdr */);
				new (pelem) TCP_CONN_ELEM_TYPE(ptcp, TPOOL_DEALLOC<TCP_CONN>());
			}
			GY_CATCH_EXCEPTION(
				DEBUGEXECN(1, ERRORPRINT_OFFLOAD("Caught exception while allocating memory for new TCP Connection : %s\n", GY_GET_EXCEPT_STRING););

				ptcp->~TCP_CONN();
				THR_POOL_ALLOC::dealloc(ptcp);
				THR_POOL_ALLOC::dealloc(pelem);
				return -1;
			);
			
			CONDEXEC(
				DEBUGEXECN(5, 
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "[TCP Connect] : Updating existing Conn : %s\n", 
						ptcp->print_string(STRING_BUFFER<512>().get_str_buf(), false)); 
				);
			);	

			bret = tcp_tbl_.template insert_or_replace<RCU_LOCK_FAST>(pelem, act_tup, anhash);
		}

		return 0;
	}
	else if (lhs_port == 0) {
		return 0;	
	}
		 
	// Add a new Listener
	if (it != psocktbl->end()) {

		if (only_listen) {
			if (true == listener_tbl_.lookup_single_elem(l_ns_ip_port, lhash)) {
				return 0;
			}	
		}

		plisten_filter->emplace(lhash);

		TCP_LISTENER 			*pnewlistener;
		TCP_LISTENER_ELEM_TYPE		*pelem;
		std::shared_ptr <TASK_STAT>	taskshr;
		std::shared_ptr <SHR_TASK_HASH_TABLE>	listen_task_table;
		
		pnewlistener = new TCP_LISTENER(lhs_addr, lhs_port, pnetns->get_ns_inode(), it->second.pid_, lhash, pdiag_msg->idiag_wqueue /* backlog */, 
						it->second.task_weak_, listen_task_table, it->second.comm_, nullptr, !only_listen /* is_pre_existing */);

		if (lhs_addr.is_ipv4_addr()) {
			pnewlistener->sock_ipv4_inode_ 	= sock_inode;
		}
		else {
			pnewlistener->sock_ipv6_inode_ 	= sock_inode;
		}		
		pnewlistener->uid_ 			= uid;

		try {
			pelem = new TCP_LISTENER_ELEM_TYPE(pnewlistener);

			/*
			 * First check the PGID of this process. If the PGID has a valid listen_tbl_shr, then use that for the listen_task_table_
			 */
			auto 			ptaskshr = it->second.task_weak_.lock();
			auto 			ptaskelem = ptaskshr.get();
			pid_t			lpgid = 0;

			if (ptaskelem) {
				decltype(ptaskelem)	ptaskpg = nullptr;
				
				lpgid 			= ptaskelem->task_pgid;

				if (lpgid != 0 && ptaskelem->task_pid != lpgid) {
					auto && itrange = ptreemap->equal_range(lpgid);
					
					for (auto && lit = itrange.first; lit != itrange.second; ++lit) {
						if (lit->second.pid_ == lpgid) {
							ptaskshr = lit->second.taskweak_.lock();
							ptaskpg = ptaskshr.get();
						}	
					}	
				}
				else if (ptaskelem->task_pid == lpgid) {
					ptaskpg = ptaskelem;	
				}				

				if (ptaskpg) {
					// Check if task cmdline's are same. If diff, we assume an execv done
					if ((ptaskelem->task_pid == lpgid) || (0 == strcmp(ptaskelem->task_cmdline, ptaskpg->task_cmdline))) {
						if (0 == ptaskpg->listen_tbl_inherited.load(std::memory_order_acquire)) {

							auto 		task_shrlisten = ptaskpg->listen_tbl_shr.load(std::memory_order_acquire);
							auto 		task_relshrlisten = ptaskpg->related_listen_.load(std::memory_order_acquire);

							if (task_shrlisten && task_relshrlisten) {
								pnewlistener->listen_task_table_.store(task_shrlisten, std::memory_order_relaxed);
								pnewlistener->related_listen_.store(task_relshrlisten, std::memory_order_relaxed);
								pnewlistener->related_listen_id_ = (int64_t)task_relshrlisten.get();

								// Set listener comm_ and cmdline_ as per ptaskpg
								pnewlistener->task_weak_ = ptaskpg->weak_from_this();
								GY_STRNCPY(pnewlistener->comm_, ptaskpg->task_comm, sizeof(pnewlistener->comm_));
								GY_STRNCPY(pnewlistener->cmdline_, ptaskpg->task_cmdline, sizeof(pnewlistener->cmdline_));
								pnewlistener->ser_aggr_task_id_ = ptaskpg->get_set_aggr_id();

								TCP_LISTENER_PTR	key(pnewlistener);
							
								WEAK_LISTEN_RAW		*praw = new WEAK_LISTEN_RAW(pnewlistener->weak_from_this(), pnewlistener);

								task_relshrlisten->related_table_.template insert_or_replace<RCU_LOCK_FAST>(praw, key, get_pointer_hash(pnewlistener));
							}
						}
					}
				}

				if (0 == pnewlistener->cmdline_[0]) {
					GY_STRNCPY(pnewlistener->cmdline_, ptaskelem->task_cmdline, sizeof(pnewlistener->cmdline_));
					pnewlistener->ser_aggr_task_id_ = ptaskelem->get_set_aggr_id();
				}	
			}	 

			/*
			 * Iterate over all tasks which have a reference to the Listener inode first. If the pnewlistener->listen_task_table_ is null,
			 * then check if the task has a current valid listen_tbl_shr and if so use that.
			 *
			 * After iterating over the Listener inode tasks, iterate over the ptreemap same pgid tasks and add the tasks to the listen_task_table_
			 * if not already added.
			 *
			 * The reason for using the ptreemap and PGID is that we do not know the originating Listener task which may have already exited as well.
			 * So we use the PGID as the originating task.
			 */
			if (it->second.pid_list_.size() > 0) {
				int			ntasks = 0;	
				bool			bret;

				auto lam1 = [&](TASK_STAT *ptask, bool is_pg_proc = false)
				{
					auto 		task_shrlisten = ptask->listen_tbl_shr.load(std::memory_order_acquire);
					auto 		ptask_listen_table = task_shrlisten.get();

					auto 		task_relshrlisten = ptask->related_listen_.load(std::memory_order_acquire);
					auto 		ptask_rellisten_table = task_relshrlisten.get();

					uint8_t		inhval = ptask->listen_tbl_inherited.load(std::memory_order_acquire);
				
					if (!is_pg_proc && (0 != inhval)) {

						if (inhval == 1 && (true == ptask->listen_tbl_inherited.compare_exchange_strong(inhval, 2))) {
							ptask->clear_listener_table();
						}
						else if (inhval == 2) {
							int		ntimes = 0;

							while (++ntimes < 4 && (0 != ptask->listen_tbl_inherited.load(std::memory_order_relaxed))) {
								sched_yield();	
							}

							if (ntimes >= 4) {
								return;
							}	
						}
						
						ptask_listen_table = nullptr;
						ptask_rellisten_table 	= nullptr; 
					}	

					int nlist 		= ptask->ntcp_listeners.load(std::memory_order_relaxed);

					auto shrlisten 		= pnewlistener->listen_task_table_.load(std::memory_order_relaxed);
					auto relshrlisten 	= pnewlistener->related_listen_.load(std::memory_order_relaxed);

					if (!is_pg_proc && nlist && !shrlisten) {
						if ((0 == ptask->listen_tbl_inherited.load(std::memory_order_acquire)) || (ptask->task_pgid == ptask->parent_pgid)) {

							shrlisten = ptask->listen_tbl_shr.load(std::memory_order_acquire);
							pnewlistener->listen_task_table_.store(shrlisten, std::memory_order_relaxed);
				
							relshrlisten = task_relshrlisten;
							pnewlistener->related_listen_.store(relshrlisten, std::memory_order_release);
							pnewlistener->related_listen_id_ = (int64_t)relshrlisten.get();

							if (shrlisten && relshrlisten) {
								TCP_LISTENER_PTR	key(pnewlistener);
							
								WEAK_LISTEN_RAW		*praw = new WEAK_LISTEN_RAW(pnewlistener->weak_from_this(), pnewlistener);

								relshrlisten->related_table_.template insert_or_replace<RCU_LOCK_FAST>(praw, key, get_pointer_hash(pnewlistener));
							}
						}
					}

					if (!shrlisten || !relshrlisten) {
						shrlisten = std::make_shared<SHR_TASK_HASH_TABLE>(8, 8, 1024, true, false);
						pnewlistener->listen_task_table_.store(shrlisten, std::memory_order_relaxed);

						relshrlisten = std::make_shared<RELATED_LISTENERS>(pnewlistener, true);
						pnewlistener->related_listen_.store(relshrlisten, std::memory_order_release);
						pnewlistener->related_listen_id_ = (int64_t)relshrlisten.get();

						TCP_LISTENER_PTR	key(pnewlistener);
					
						WEAK_LISTEN_RAW		*praw = new WEAK_LISTEN_RAW(pnewlistener->weak_from_this(), pnewlistener);

						relshrlisten->related_table_.template insert_or_replace<RCU_LOCK_FAST>(praw, key, get_pointer_hash(pnewlistener));
					}	
						
					if (!ptask_listen_table || !ptask_rellisten_table) {
						ptask->listen_tbl_shr.store(shrlisten, std::memory_order_release);
						ptask->listen_tbl_inherited.store(is_pg_proc, std::memory_order_release);
						ptask->related_listen_.store(relshrlisten, std::memory_order_release);
						ptask->last_listen_tusec_ = get_usec_time();
					}	
					else if (is_pg_proc) {
						// Check if this task cmdline is the same as that of the originating task or if its a direct descendent. If so, overwrite
						if (ptaskelem && ptask->listen_tbl_inherited.load(std::memory_order_relaxed) && 
							((0 == strcmp(ptaskelem->task_cmdline, ptask->task_cmdline)) || (ptask->task_ppid == ptaskelem->task_pid))) {

							inhval = ptask->listen_tbl_inherited.load(std::memory_order_acquire);
						
							if (0 != inhval) {

								if (inhval == 1 && (true == ptask->listen_tbl_inherited.compare_exchange_strong(inhval, 2))) {
									ptask->clear_listener_table();
								}
								else if (inhval == 2) {
									int		ntimes = 0;

									while (++ntimes < 4 && (0 != ptask->listen_tbl_inherited.load(std::memory_order_relaxed))) {
										sched_yield();	
									}

									if (ntimes >= 4) {
										return;
									}	
								}

								nlist = 0;

								ptask->listen_tbl_shr.store(shrlisten, std::memory_order_release);
								ptask->listen_tbl_inherited.store(is_pg_proc, std::memory_order_release);
								ptask->related_listen_.store(relshrlisten, std::memory_order_release);
								ptask->last_listen_tusec_ = get_usec_time();
							}	
							else {
								return;
							}	
						}	
						else {
							return;
						}	
					}	

					nlist++;

					ptask->is_tcp_server = true;
					ptask->ntcp_listeners.store(nlist, std::memory_order_relaxed); 

					SHR_TASK_ELEM_TYPE		*pshrelem;

					pshrelem = new SHR_TASK_ELEM_TYPE(ptask->shared_from_this());	

					shrlisten->template insert_or_replace<RCU_LOCK_FAST>(pshrelem, ptask->task_pid, get_pid_hash(ptask->task_pid));
				};
									
				// Add the list of processes accessing this inode as connected procs
				for (auto lit : it->second.pid_list_) {
					ptask_handler_->template get_task<decltype(lam1), RCU_LOCK_FAST>(lit, lam1); 		
				}

				auto && itrange = ptreemap->equal_range(lpgid);
				
				for (auto && lit = itrange.first; lit != itrange.second; ++lit) {
					if (std::end(it->second.pid_list_) == std::find(std::begin(it->second.pid_list_), std::end(it->second.pid_list_), lit->second.pid_)) {
						ptaskshr = lit->second.taskweak_.lock();
						auto ptask = ptaskshr.get();
						
						if (ptask) {
							lam1(ptask, true);
						}
					}	
				}	
			}	

			auto shrlisten 		= pnewlistener->listen_task_table_.load(std::memory_order_relaxed);
			auto relshrlisten 	= pnewlistener->related_listen_.load(std::memory_order_relaxed);

			if (!shrlisten || !relshrlisten) {
				// The Task has not yet been populated or it has already exited
				pnewlistener->listen_task_table_.store(std::make_shared<SHR_TASK_HASH_TABLE>(8, 8, 1024, true, false), std::memory_order_release);

				relshrlisten = std::make_shared<RELATED_LISTENERS>(pnewlistener, true);

				pnewlistener->related_listen_.store(relshrlisten, std::memory_order_release);
				pnewlistener->related_listen_id_ = (int64_t)relshrlisten.get();

				TCP_LISTENER_PTR	key(pnewlistener);
				
				WEAK_LISTEN_RAW		*praw = new WEAK_LISTEN_RAW(pnewlistener->weak_from_this(), pnewlistener);

				relshrlisten->related_table_.template insert_or_replace<RCU_LOCK_FAST>(praw, key, get_pointer_hash(pnewlistener));
			}			
		}
		GY_CATCH_EXCEPTION(
			DEBUGEXECN(1, ERRORPRINT_OFFLOAD("Caught exception while allocating memory for new TCP Listener from inet : %s\n", GY_GET_EXCEPT_STRING););

			delete pnewlistener;
			return -1;
		);

		if (pnewlistener->comm_[0] && pnewlistener->cmdline_[0]) {
			pnewlistener->set_aggr_glob_id();
		}

		if (gdebugexecn >= 1 || only_listen) {
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Adding new TCP Listener from manual inet handling : %s\n", 
				pnewlistener->print_string(STRING_BUFFER<512>().get_str_buf(), false));
		}

		if (!only_listen) {
			listener_tbl_.template insert_or_replace<RCU_LOCK_FAST>(pelem, l_ns_ip_port, lhash);
		}
		else {
			bret = listener_tbl_.template insert_unique<RCU_LOCK_FAST>(pelem, l_ns_ip_port, lhash);

			if (bret && *pnewlistener->comm_) {
				notify_new_listener(pnewlistener, false, false /* is_listen_event_thread */);
			}	
		}
	}	

	return 0;
}

int TCP_SOCK_HANDLER::check_listener_depends_misc() noexcept
{
	using namespace		comm;

	const uint64_t		curr_usec_clock = get_usec_clock();
	const int64_t		curr_time_usec = get_usec_time();
	const uint64_t		min_chk_usec = curr_usec_clock - GY_USEC_PER_MINUTE * 30, min_ext_usec = curr_usec_clock - 5 * GY_USEC_PER_MINUTE;
	const uint64_t		start_inet_usec = start_inet_usec_, min_depends_cusec = GY_READ_ONCE(last_depends_cusec_); 
	const int64_t		min_nat_tsec = GY_READ_ONCE(last_listener_nat_tsec_);

	// Approx 64 KB Stack Vector
	using DepVector		= GY_STACK_VECTOR<comm::LISTENER_DEPENDENCY_NOTIFY::DEPENDS_ONE, 
					(LISTENER_DEPENDENCY_NOTIFY::MAX_DEPENDS_PER_LISTEN + 1) * sizeof(LISTENER_DEPENDENCY_NOTIFY::DEPENDS_ONE)>;
	using ArenaDep		= DepVector::allocator_type::arena_type;

	DATA_BUFFER		scache(comm::LISTENER_DEPENDENCY_NOTIFY::get_max_elem_size(), 2, LISTENER_DEPENDENCY_NOTIFY::MAX_NUM_LISTENERS, 
					sizeof(comm::COMM_HEADER) + sizeof(comm::EVENT_NOTIFY));
	DATA_BUFFER		natcache(sizeof(LISTENER_NAT_IP_EVENT), 16, LISTENER_NAT_IP_EVENT::MAX_NUM_LISTENERS, 
					sizeof(comm::COMM_HEADER) + sizeof(comm::EVENT_NOTIFY));
	DATA_BUFFER		domaincache(comm::LISTENER_DOMAIN_NOTIFY::get_max_elem_size(), 16, LISTENER_DOMAIN_NOTIFY::MAX_NUM_LISTENERS, 
					sizeof(comm::COMM_HEADER) + sizeof(comm::EVENT_NOTIFY));

	const auto		pser = SERVER_COMM::get_singleton();
	auto			shrconn = pser->get_server_conn(comm::CLI_TYPE_REQ_ONLY);
	bool			server_ok = bool(shrconn);
	size_t			serv_sz = 0, serv_nelem = 0, nat_sz = 0, nat_nelem = 0;
	
	RCU_LOCK_SLOW		slowlock;

	const auto sendcb = [&](void *palloc, size_t sz, FREE_FPTR free_fp, size_t nelems) -> bool
	{
		serv_sz 	+= sz;
		serv_nelem 	+= nelems;

		return pser->send_event_cache(scache, palloc, sz, free_fp, nelems, comm::NOTIFY_LISTENER_DEPENDENCY, shrconn);
	};	

	const auto natsendcb = [&](void *palloc, size_t sz, FREE_FPTR free_fp, size_t nelems) -> bool
	{
		nat_sz 		+= sz;
		nat_nelem 	+= nelems;

		return pser->send_event_cache(natcache, palloc, sz, free_fp, nelems, comm::NOTIFY_LISTENER_NAT_IP_EVENT, shrconn);
	};	

	const auto domainsendcb = [&](void *palloc, size_t sz, FREE_FPTR free_fp, size_t nelems) -> bool
	{
		return pser->send_event_cache(domaincache, palloc, sz, free_fp, nelems, comm::NOTIFY_LISTENER_DOMAIN_EVENT, shrconn);
	};	

	// First update the individual Related Listener inbound/outbound stats
	auto lam_listen = [start_inet_usec, curr_usec_clock](TCP_LISTENER_ELEM_TYPE *pdatanode, void *arg1) noexcept
	{
		try {
			auto plistener 		= pdatanode->get_cref().get();

			if (gy_unlikely((plistener == nullptr || start_inet_usec > plistener->clock_usec_.load(std::memory_order_relaxed)))) {
				return CB_OK;
			}
			
			auto relshrlisten 	= plistener->related_listen_.load(std::memory_order_relaxed);
			auto prelated		= relshrlisten.get();

			if (!prelated) {
				return CB_OK;
			}

			if (prelated->updated_clock_usec_ < curr_usec_clock - 1) {
				prelated->curr_bytes_inbound_ = 0;

				prelated->last_nconns_active_ = prelated->curr_nconns_active_;
				prelated->curr_nconns_active_ = 0;

				prelated->updated_clock_usec_ = curr_usec_clock - 1; // Set this as will be checked in lam_upd_dep()
			}	

			prelated->curr_bytes_inbound_ += plistener->curr_bytes_inbound_; 
			prelated->curr_nconns_active_ += plistener->nconn_recent_active_.load(std::memory_order_acquire);

			return CB_OK;
		}		
		GY_CATCH_EXCEPTION(
			DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Caught Exception while checking listener table for dependency : %s\n", GY_GET_EXCEPT_STRING););
			return CB_OK;
		)	
	};	

	listener_tbl_.walk_hash_table(lam_listen); 	
	
	auto lam_upd_dep = [&, start_inet_usec, curr_usec_clock, min_nat_tsec, last_del_cusec = last_listener_del_cusec_.load(std::memory_order_acquire)]
			(TCP_LISTENER_ELEM_TYPE *pdatanode, void *arg1) noexcept
	{
		try {
			auto plistener 		= pdatanode->get_cref().get();
			bool			dnsupd = false;

			if (gy_unlikely(plistener == nullptr)) {
				return CB_OK;
			}

			if (plistener->last_nat_chg_ip_tsec_ > min_nat_tsec) {
				auto		*pone = (LISTENER_NAT_IP_EVENT *)natcache.get_next_buffer();

				std::memcpy(pone->nat_ip_port_arr_, plistener->nat_ip_port_arr_, sizeof(pone->nat_ip_port_arr_));
				pone->glob_id_	= plistener->glob_id_;

				natcache.set_buffer_sz(natsendcb, sizeof(*pone));
			}

			if (start_inet_usec > plistener->clock_usec_.load(std::memory_order_relaxed)) {
				// Not updated recently
				return CB_OK;
			}

			auto relshrlisten 	= plistener->related_listen_.load(std::memory_order_relaxed);
			auto prelated		= relshrlisten.get();

			if (!prelated) {
				return CB_OK;
			}
			
			if (plistener->last_dns_query_tsec_ > min_nat_tsec && *plistener->server_domain_ && (0 != memcmp(plistener->server_domain_, "localhost", 9))) {
				auto		*pone = (LISTENER_DOMAIN_NOTIFY *)domaincache.get_next_buffer();

				new (pone) LISTENER_DOMAIN_NOTIFY();

				pone->glob_id_			= plistener->glob_id_;
				pone->domain_string_len_	= 1 + strnlen(plistener->server_domain_, 254);

				if (prelated->tag_len_ && prelated->tlast_tag_ > min_nat_tsec && prelated->updated_clock_usec_ == curr_usec_clock - 1) {
					pone->tag_len_		= prelated->tag_len_ + 1;
				}	
				else {
					pone->tag_len_		= 0;
				}	

				std::memcpy((char *)(pone + 1), plistener->server_domain_, pone->domain_string_len_);
				*((char *)pone + sizeof(*pone) + pone->domain_string_len_ - 1) = 0;

				if (pone->tag_len_) {
					std::memcpy((char *)(pone + 1) + pone->domain_string_len_, prelated->tagbuf_, pone->tag_len_);
					*((char *)pone + sizeof(*pone) + pone->domain_string_len_ + pone->tag_len_ - 1) = 0;
				}	

				pone->set_padding_len();
				
				domaincache.set_buffer_sz(domainsendcb, pone->get_elem_size());

				dnsupd = true;
			}

			if (prelated->updated_clock_usec_ != curr_usec_clock - 1 /* already updated */) {
				return CB_OK;
			}

			prelated->updated_clock_usec_ = curr_usec_clock;

			if (false == dnsupd && prelated->tag_len_ && prelated->tlast_tag_ > min_nat_tsec) {
				auto		*pone = (LISTENER_DOMAIN_NOTIFY *)domaincache.get_next_buffer();

				new (pone) LISTENER_DOMAIN_NOTIFY();

				pone->glob_id_			= plistener->glob_id_;
				pone->domain_string_len_	= 0;
				pone->tag_len_			= prelated->tag_len_ + 1;

				std::memcpy((char *)(pone + 1) + 0, prelated->tagbuf_, pone->tag_len_);
				*((char *)pone + sizeof(*pone) + 0 + pone->tag_len_ - 1) = 0;

				pone->set_padding_len();
				
				domaincache.set_buffer_sz(domainsendcb, pone->get_elem_size());
			}	

			prelated->req_seen_status_ <<= 1;
		
			if (prelated->curr_bytes_inbound_ > 1) {
				prelated->req_seen_status_ |= 1;
			}	

			ArenaDep		arena_dep;
			DepVector		depvec(arena_dep);		

			if (server_ok) {
				depvec.reserve(LISTENER_DEPENDENCY_NOTIFY::MAX_DEPENDS_PER_LISTEN);
			}

			const int 		ntimes_data_seen = gy_count_bits_set(prelated->req_seen_status_);
			
			/*
			 * Now we scan the id_depends_ and ipport_depends_ tables for dependency
			 */
			auto lam_dep = [&, start_inet_usec, min_chk_usec, min_ext_usec](DEPENDS_LISTENER *pdepend, void *arg1) -> CB_RET_E
			{
				pdepend->status_bits_ <<= 1;

				if (pdepend->last_clock_usec_ < start_inet_usec) {
					// No data for this interval

					if (pdepend->last_clock_usec_ < min_chk_usec) {
						goto delete_elem;
					}
					else if ((pdepend->listener_glob_id_ == 0) && (pdepend->last_clock_usec_ < min_ext_usec)) {
						goto delete_elem;
					}	
					else if ((false == pdepend->is_remote_listener()) && (pdepend->last_clock_usec_ < last_del_cusec)) {
						if (pdepend->weaklisten_.expired()) {
							goto delete_elem;
						}	
					}	
				}	
				else if (pdepend->inter_bytes_sent_ > 1) {
					// Check whether any req was sent or only responses seen
					pdepend->status_bits_ |= 1;
				}

				if (true) {
					int		dep_ntimes_seen = gy_count_bits_set(pdepend->status_bits_);
					size_t		nload_balanced = 1, min_multiple = 3;

					// Now clear out interval stats
					pdepend->inter_bytes_sent_	= 0;
					pdepend->curr_nconns_active_	= 0;
			 
					/*
					 * We check if at least 9 times in last 64 * 15 sec = 16 min, inbound client data was seen on this Related Lisneter.
					 * We also check if at least a third of that time, outbound data was sent from this set of related listeners to the
					 * potential dependent listener. We do not match up individual intervals, just the number of intervals is checked.
					 */	
					if ((ntimes_data_seen >= 9) || (dep_ntimes_seen >= 12 && ntimes_data_seen >= 4)) {

						if (pdepend->listener_glob_id_ && nullptr == pdepend->plistener_) {
							auto			mit = diag_lbl_map_.find(pdepend->ns_ip_port_.ip_port_);

							if (mit != diag_lbl_map_.end()) {
								nload_balanced = mit->second.size();

								if (nload_balanced == 0) {
									nload_balanced = 1;
								}	
							}	
						}

						if (dep_ntimes_seen * min_multiple * nload_balanced >= (size_t)ntimes_data_seen) {

							if (pdepend->is_valid_depend_ == false) {

								pdepend->is_valid_depend_ = true;

								if (server_ok && depvec.size() < comm::LISTENER_DEPENDENCY_NOTIFY::MAX_DEPENDS_PER_LISTEN) {
									depvec.emplace_back(pdepend->listener_glob_id_, pdepend->listener_madhava_id_, pdepend->ns_ip_port_,
										pdepend->last_chg_cusec_ > min_depends_cusec /* is_new */, !!pdepend->plistener_, 
										false /* delete_depends */, nload_balanced > 1); 
								}	

								if (pdepend->plistener_) {
									prelated->nlocal_id_depends_.fetch_add_relaxed(1);
								}	

								DEBUGEXECN(1,
									INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, 
										"Related Listener %s : New Listener Dependency seen on %s : "
										"Outbound Traffic sent for %d times (vs %d) (%lu #load balancers) in last few minutes\n",
										prelated->init_comm_, pdepend->identifier_str_, dep_ntimes_seen, ntimes_data_seen, 
										nload_balanced);
								);
							}
							else if ((pdepend->last_chg_cusec_ > min_depends_cusec) && 
								server_ok && depvec.size() < comm::LISTENER_DEPENDENCY_NOTIFY::MAX_DEPENDS_PER_LISTEN) {

								depvec.emplace_back(pdepend->listener_glob_id_, pdepend->listener_madhava_id_, pdepend->ns_ip_port_,
									pdepend->last_chg_cusec_ > min_depends_cusec /* is_new */, !!pdepend->plistener_, 
									false /* delete_depends */, nload_balanced > 1); 
							}	

							return CB_OK;
						}	
					}

					if (pdepend->is_valid_depend_ == true) {
						// Seems to be no longer dependent. 
					
						pdepend->is_valid_depend_ = false;

						if (server_ok && depvec.size() < comm::LISTENER_DEPENDENCY_NOTIFY::MAX_DEPENDS_PER_LISTEN) {
							depvec.emplace_back(pdepend->listener_glob_id_, pdepend->listener_madhava_id_, pdepend->ns_ip_port_,
								false /* is_new */, !!pdepend->plistener_, true /* delete_depends */); 
						}	

						if (pdepend->plistener_) {
							prelated->nlocal_id_depends_.fetch_sub_relaxed_0(1);
						}	

						DEBUGEXECN(1,
							INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, 
								"Related Listener %s : Listener Dependency no longer seen on %s : "
								"Outbound Traffic sent for %d times (vs %d) (%lu #load balancers) in last few minutes\n",
								prelated->init_comm_, pdepend->identifier_str_, dep_ntimes_seen, ntimes_data_seen, nload_balanced);
						);
					}	

					 
					return CB_OK;
				}

			delete_elem :
				
				if ((pdepend->is_valid_depend_ == true) && server_ok && depvec.size() < comm::LISTENER_DEPENDENCY_NOTIFY::MAX_DEPENDS_PER_LISTEN) {
					depvec.emplace_back(pdepend->listener_glob_id_, pdepend->listener_madhava_id_, pdepend->ns_ip_port_,
						false /* is_new */, !!pdepend->plistener_, true /* delete_depends */); 
				}	

				if (pdepend->is_valid_depend_ && pdepend->plistener_) {
					prelated->nlocal_id_depends_.fetch_sub_relaxed_0(1);
				}	

				return CB_DELETE_ELEM;
			};

			prelated->id_depends_.walk_hash_table(lam_dep);
			
			prelated->ipport_depends_.walk_hash_table(lam_dep);
			
			if (depvec.size() > 0) {
				auto		*pone = (LISTENER_DEPENDENCY_NOTIFY *)scache.get_next_buffer();
				size_t		tsz = sizeof(LISTENER_DEPENDENCY_NOTIFY::DEPENDS_ONE) * depvec.size();

				new (pone) LISTENER_DEPENDENCY_NOTIFY(prelated->get_related_id(), plistener->glob_id_, depvec.size(), prelated->related_table_.approx_count_fast());

				std::memcpy((char *)pone + sizeof(LISTENER_DEPENDENCY_NOTIFY), depvec.data(), tsz);

				scache.set_buffer_sz(sendcb, pone->get_elem_size());
			}

			return CB_OK;

		}		
		GY_CATCH_EXCEPTION(
			DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Caught Exception while updating listener table for dependency : %s\n", GY_GET_EXCEPT_STRING););
			server_ok = false;
			return CB_OK;
		)	
	};	

	listener_tbl_.walk_hash_table(lam_upd_dep); 	

	slowlock.unlock();

	scache.flush_cache(sendcb);
	natcache.flush_cache(natsendcb);
	domaincache.flush_cache(domainsendcb);

	if (serv_nelem + nat_nelem > 0) {
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Listener Dependency : Sent %lu Related Listeners dependency of total size %lu to Madhava : "
			"Listener NAT Event : Sent %lu Listener NAT events of total size %lu to Madhava\n", serv_nelem, serv_sz, nat_nelem, nat_sz);
	}	

	GY_CC_BARRIER();

	// Check if reset_server_stats() was invoked
	if (GY_READ_ONCE(last_depends_cusec_) == min_depends_cusec) {
		last_depends_cusec_ = curr_usec_clock;
		last_listener_nat_tsec_ = curr_time_usec/GY_USEC_PER_SEC;
	}
	
	return 0;
}	

void TCP_SOCK_HANDLER::cleanup_lbl_map() noexcept
{
	try {
		uint64_t		curr_cusec = get_usec_clock(), min_cutoff_cusec = curr_cusec - 5 * GY_USEC_PER_MINUTE; 
		int			n = 0;
		size_t			totset = 0;

		next_lbl_check_cusec_ = curr_cusec + 5 * GY_USEC_PER_MINUTE;

		CONDDECLARE(
			STRING_BUFFER<4096>	strbuf;
		);

		for (auto mit = diag_lbl_map_.begin(); mit != diag_lbl_map_.end(); ) {
			auto & idmap = mit->second;
			
			for (auto sit = idmap.begin(); sit != idmap.end(); ) {
				if (sit->second < min_cutoff_cusec) {
					sit = idmap.erase(sit);
				}	
				else {
					++sit;
				}	
			}
			
			CONDEXEC(
				DEBUGEXECN(1,
					strbuf.appendfmt("\n\t#%d : External Server ", ++n);
					mit->first.print_string(strbuf);
					
					if (idmap.size() > 1) {
						strbuf.appendfmt(" : seems to be a Load Balanced server with %lu external Listeners", idmap.size());
					}	
					else {
						strbuf.appendconst(" : seems to not be a Load Balanced server");
					}	
				);
			);

			totset += idmap.size();

			if (0 != idmap.size()) {
				++mit;
			}
			else {
				mit = diag_lbl_map_.erase(mit);
			}	
		}

		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Listener Process External Connection info : Current # external IP/Ports = %lu : Total external Listeners connected is %lu\n",
			diag_lbl_map_.size(), totset);

		CONDEXEC(
			DEBUGEXECN(1,
				IRPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "%.*s\n\n", strbuf.sizeint(), strbuf.buffer());
			);	
		);
		

	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Caught Exception while cleaning Listener Load Balancer Map : %s\n", GY_GET_EXCEPT_STRING););
	);
}	

int TCP_SOCK_HANDLER::notify_init_listeners() noexcept
{
	using namespace 		comm;

	try {
		auto			pser =  SERVER_COMM::get_singleton();
		auto			shrp = pser->get_server_conn(comm::CLI_TYPE_REQ_ONLY);
		auto			pconn1 = shrp.get();

		if (!pconn1) {
			return 0;
		}
		
		size_t			maxelems = listener_tbl_.approx_count_fast(), totalsz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY), nelems = 0;
		
		if (maxelems + 16 >= comm::NEW_LISTENER::MAX_NUM_LISTENERS) {
			maxelems = comm::NEW_LISTENER::MAX_NUM_LISTENERS;
		}	
		else if (maxelems == 0) {
			return 0;
		}	
		else {
			maxelems += 16;
		}	

		size_t			fixedsz = totalsz + maxelems * sizeof(comm::NEW_LISTENER); 
		void			*palloc = ::malloc(fixedsz);

		if (!palloc) {
			return -1;
		}	

		comm::NEW_LISTENER	*pone = (comm::NEW_LISTENER *)((uint8_t *)palloc + totalsz);

		GY_SCOPE_EXIT {
			if (palloc) {
				::free(palloc);
			}	
		};	

		auto lam_listen = [&, palloc, maxelems, fixedsz](TCP_LISTENER_ELEM_TYPE *pdatanode, void *arg1) -> CB_RET_E
		{
			auto 			plistener = pdatanode->get_cref().get();

			if (gy_unlikely(plistener == nullptr)) {
				return CB_OK;
			}

			new (pone) comm::NEW_LISTENER(plistener->ns_ip_port_, plistener->glob_id_, 0 /* Set as 0 as validation will be done in inode check */,
							plistener->related_listen_id_, plistener->tstart_usec_, plistener->ser_aggr_task_id_, 
							plistener->is_any_ip_, plistener->is_pre_existing_,
							false /* no_aggr_stats */, true /* no_resp_stats */, plistener->comm_, plistener->pid_, 0 /* Set cmdline_len_ as 0 */);

			totalsz += pone->get_elem_size();
			nelems++;

			if (nelems >= maxelems || totalsz + sizeof(NEW_LISTENER) >= fixedsz) {
				return CB_BREAK_LOOP;
			}	

			pone = (comm::NEW_LISTENER *)((uint8_t *)palloc + totalsz);

			return CB_OK;
		};

		listener_tbl_.walk_hash_table(lam_listen, nullptr); 	

		if (nelems == 0) {
			return 0;
		}	

		DEBUGEXECN(1,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Sending %lu Pre-existing Listener info to Madhava server : Payload size %lu\n", nelems, totalsz);
		);

		COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
		EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1); 

		new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, totalsz, pser->get_conn_magic());

		new (pnot) EVENT_NOTIFY(NOTIFY_NEW_LISTENER, nelems);

		palloc				= nullptr;	// So as to prevent ::free()

		pser->send_server_data(EPOLL_IOVEC_ARR(2, false, phdr, phdr->get_act_len(), ::free, pser->gpadbuf, phdr->get_pad_len(), nullptr), 
						comm::CLI_TYPE_REQ_ONLY, COMM_EVENT_NOTIFY, shrp);
		return nelems;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Caught Exception while sending init listeners to server : %s\n", GY_GET_EXCEPT_STRING););
		return -1;
	);
}	

int TCP_SOCK_HANDLER::notify_init_tcp_conns() noexcept
{
	using namespace 		comm;

	try {
		auto			pser =  SERVER_COMM::get_singleton();
		auto			shrp = pser->get_server_conn(comm::CLI_TYPE_REQ_ONLY);
		auto			pconn1 = shrp.get();

		if (!pconn1) {
			return 0;
		}
		
		size_t			telem = tcp_tbl_.approx_count_fast();

		if (telem == 0) {
			return 0;
		}	

		size_t			maxelems = std::min(telem + 64, comm::TCP_CONN_NOTIFY::MAX_NUM_CONNS), totalsz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY), nelems = 0;
		size_t			fixedsz = totalsz + maxelems * comm::TCP_CONN_NOTIFY::get_max_elem_size();
		void			*palloc = ::malloc(fixedsz);

		if (!palloc) {
			return -1;
		}	

		comm::TCP_CONN_NOTIFY	*pone = (comm::TCP_CONN_NOTIFY *)((uint8_t *)palloc + totalsz);

		GY_SCOPE_EXIT {
			if (palloc) {
				::free(palloc);
			}	
		};	

		auto lam_conn = [&, palloc, maxelems](TCP_CONN_ELEM_TYPE *pdatanode, void *arg1) -> CB_RET_E
		{
			TCP_CONN		*ptcp = pdatanode->get_cref().get();
			char			cli_cmdline[comm::MAX_PROC_CMDLINE_LEN], *pclistr = nullptr;
			size_t			cli_cmdline_len = 0;

			if (gy_unlikely(ptcp == nullptr)) {
				return CB_OK;
			}

			if (ptcp->server_updated_.load(std::memory_order_relaxed) == true) {
				return CB_OK;	
			}

			if (true == ptcp->cli_task_updated_.load(std::memory_order_relaxed)) {
				if (ptcp->cli_task_shr_) {
					pclistr		= cli_cmdline;
					cli_cmdline_len = std::min(MAX_PROC_CMDLINE_LEN - 1, strlen(ptcp->cli_task_shr_->task_cmdline));

					std::memcpy(cli_cmdline, ptcp->cli_task_shr_->task_cmdline, cli_cmdline_len);
					cli_cmdline[cli_cmdline_len] = 0;
				}	
			}

			ptcp->set_notify_elem(pone, 0ul, pclistr, cli_cmdline_len);

			totalsz += pone->get_elem_size();
			nelems++;

			if (nelems >= maxelems) {
				return CB_BREAK_LOOP;
			}	

			pone = (comm::TCP_CONN_NOTIFY *)((uint8_t *)palloc + totalsz);

			return CB_OK;
		};

		tcp_tbl_.walk_hash_table(lam_conn, nullptr); 	

		if (nelems == 0) {
			return 0;
		}	

		DEBUGEXECN(1,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Sending %lu Pre-existing TCP Conn info to Madhava server : Payload size %lu\n", nelems, totalsz);
		);

		COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
		EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1); 

		new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, totalsz, pser->get_conn_magic());

		new (pnot) EVENT_NOTIFY(NOTIFY_TCP_CONN, nelems);

		palloc				= nullptr;	// So as to prevent ::free()

		pser->send_server_data(EPOLL_IOVEC_ARR(2, false, phdr, phdr->get_act_len(), ::free, pser->gpadbuf, phdr->get_pad_len(), nullptr), 
						comm::CLI_TYPE_REQ_ONLY, COMM_EVENT_NOTIFY, shrp);
		return nelems;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Caught Exception while sending init tcp conns to server : %s\n", GY_GET_EXCEPT_STRING););
		return -1;
	);
}	


static int sockdiag_send(int sockfd, bool only_listen)
{
	// We are only interested in Established TCP conns and existing TCP Listeners
	
	static constexpr uint32_t	GY_TCP_MAGIC_SEQ = 123456;
	
	struct sockaddr_nl 		nladdr = { .nl_family = AF_NETLINK };
	struct {
		struct nlmsghdr 	nlh;
		struct inet_diag_req 	r;
	} req = {};
	struct msghdr 			msg;
	struct iovec 			iov[3];
	int 				iovlen = 1;
	uint32_t 			idiag_states = (1 | (!only_listen ? (1 << GY_TCP_ESTABLISHED) : 0) | (1 << GY_TCP_LISTEN));

	req.nlh.nlmsg_len 		= sizeof(req);
	req.nlh.nlmsg_flags 		= NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
	req.nlh.nlmsg_seq 		= GY_TCP_MAGIC_SEQ;
	req.nlh.nlmsg_type 		= TCPDIAG_GETSOCK;
	req.r.idiag_family 		= AF_UNSPEC;
	req.r.idiag_states 		= idiag_states;

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
		PERRORPRINT_OFFLOAD("Could not send inet diag message");
		return -1;
	}

	return 0;
}

static constexpr int				DIAG_BUF_SIZE = 16 * 1024;	

int TCP_SOCK_HANDLER::do_inet_diag_info(NETNS_ELEM *pnetns, uint8_t *pdiagbuf, bool add_conn, bool add_listen, SOCK_INODE_TABLE *psocktbl, SOCK_INODE_SET *pchkset, TASK_PGTREE_MAP * ptreemap) noexcept
{
	try {
		assert(gy_get_thread_local().get_thread_stack_freespace() > 128 * 1024 + sizeof(LIST_HASH_SET));

		int 				nl_sock = 0, numbytes = 0, rtalen = 0, ret;
		struct nlmsghdr 		*nlh;
		struct inet_diag_msg 		*pdiag_msg;
		uint64_t			clock_diag, tusec_diag;
		struct sockaddr_nl 		addr;
		LIST_HASH_SET			listen_filter;

		listen_filter.reserve(8192);

		struct iovec iov = {
			.iov_base		= pdiagbuf,
			.iov_len		= DIAG_BUF_SIZE,
		};

		struct msghdr msg = {
			.msg_name		= &addr,
			.msg_namelen		= sizeof(struct sockaddr_nl),
			.msg_iov		= &iov,
			.msg_iovlen		= 1,
			.msg_control		= nullptr,
			.msg_controllen		= 0,
			.msg_flags		= 0,
		};

		if ((nl_sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG)) == -1) {
			PERRORPRINT_OFFLOAD("inet diag socket failed");
			return -1;
		}

		GY_SCOPE_EXIT {
			close(nl_sock);
		};
		
		if (sockdiag_send(nl_sock, add_listen /* only_listen */) < 0) {
			return -1;
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

				PERRORPRINT_OFFLOAD("recv of inet diag failed");
				break;
			}	
			else if (ret == 0) {
				break;
			}	

			clock_diag = get_usec_clock();
			tusec_diag = get_usec_time();

			if (msg.msg_namelen != sizeof(struct sockaddr_nl)) {
				errno = EINVAL;
				DEBUGEXECN(1, PERRORPRINT_OFFLOAD("recv of inet diag failed due to invalid data len msg_namelen %u, sizeof len %lu", 
					msg.msg_namelen, sizeof(struct sockaddr_nl)););
				break;
			}

			h = (struct nlmsghdr *)pdiagbuf;

			msglen = ret;

			RCU_LOCK_SLOW		slowlock;

			while (NLMSG_OK(h, (unsigned)msglen)) {
				if (h->nlmsg_flags & NLM_F_DUMP_INTR) {
					dump_intr = true;
				}	

				if (h->nlmsg_type == NLMSG_DONE) {
					found_done = true;
					break; 
				}

				if (h->nlmsg_type == NLMSG_ERROR) {
					return -1;
				}

				pdiag_msg = (struct inet_diag_msg *) NLMSG_DATA(h);

				rtalen = h->nlmsg_len - NLMSG_LENGTH(sizeof(*pdiag_msg));

				if (gy_likely(!add_conn && !add_listen)) {
					upd_conn_from_diag(pdiag_msg, rtalen, pnetns, clock_diag, tusec_diag, psocktbl, pchkset, &listen_filter);
				}
				else {
					add_conn_from_diag(pdiag_msg, rtalen, pnetns, clock_diag, psocktbl, &listen_filter, ptreemap, add_listen /* only_listen */);	
				}		

				h = NLMSG_NEXT(h, msglen);
			}

			if (found_done) {
				if (dump_intr) {
					DEBUGEXECN(1, INFOPRINT_OFFLOAD("inet diag dump was interrupted and may be inconsistent.\n"););
				}	
				break;
			}

			if (msg.msg_flags & MSG_TRUNC) {
				continue;
			}
			if (msglen) {
				DEBUGEXECN(1, ERRORPRINT_OFFLOAD("inet diag message still remains of size %d\n", msglen););
				return -1;
			}
		}	
		
		return 0;
	}
	GY_CATCH_EXCEPTION(ERRORPRINT_OFFLOAD("Exception caught while querying for inet diag info : %s\n", GY_GET_EXCEPT_STRING));

	return -1;
}	


int TCP_SOCK_HANDLER::inet_diag_thread() noexcept
{
	bool			init_done = false;

	try {
		int				ret;
		bool				add_conn = true, add_listen = false;
		uint8_t 			*pdiagbuf;
		bool				is_malloc;
		SOCK_INODE_TABLE		socktbl, *psocktbl = &socktbl;
		SOCK_INODE_SET			chkset, *pchkset = &chkset;
		TASK_PGTREE_MAP		 	treemap, *ptreemap = &treemap;
		auto				pser = SERVER_COMM::get_singleton();

		SAFE_STACK_ALLOC(pdiagbuf, DIAG_BUF_SIZE, is_malloc);

		auto lambda_ns = [&](NETNS_ELEM *pdatanode, void *arg1) -> CB_RET_E
		{
			int			ret;

			CONDEXEC(
				DEBUGEXECN(10, INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Starting inet diag for NetNS %lu\n", pdatanode->inode_););
			);	

			if (gy_unlikely(pdatanode->fd_netns_ == -1)) {
				pdatanode->open_ns_inode();
				
				if (pdatanode->fd_netns_ < 0) {
					return CB_DELETE_ELEM;
				}	
			}	

			ret = setns(pdatanode->fd_netns_, CLONE_NEWNET);
			if ((ret == -1) && (errno != ENOSYS)) {
				if (errno != ENOMEM) {
					DEBUGEXECN(11, PERRORPRINT_OFFLOAD("Failed to setns for NetNS %lu for PID %d", pdatanode->inode_, pdatanode->pid_start_););
					return CB_DELETE_ELEM;
				}
				else {
					return CB_OK;
				}	
			}	

			do_inet_diag_info(pdatanode, pdiagbuf, add_conn, add_listen, psocktbl, pchkset, ptreemap);

			if (add_listen) {
				return CB_OK;
			}

			uint64_t		clock_diag = get_usec_clock();
			uint64_t		tclock		= pdatanode->clock_usec_.load(std::memory_order_acquire),
						tstart_clock 	= pdatanode->start_clock_usec_.load(std::memory_order_relaxed);

			if (clock_diag - tclock > 3 * INET_DIAG_INTERVAL_SECS * GY_USEC_PER_SEC && tclock && 
				(clock_diag - tstart_clock > 6 * INET_DIAG_INTERVAL_SECS * GY_USEC_PER_SEC)) {

				// Delete this NetNS as no connections since last min
				DEBUGEXECN(1, 
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN_UNDERLINE, "Deleting NetNS %lu for PID %d as no connections seen since last %lu sec...\n", 
							pdatanode->inode_, pdatanode->pid_start_, (clock_diag - tclock)/GY_USEC_PER_SEC);
				);

				return CB_DELETE_ELEM;
			}
				 
			return CB_OK;
		};	
	
		ret = populate_ns_tbl();
		if (ret == -1) {
			inet_diag_thr_.set_thread_init_done(true /* init_failed */);
			return ret;
		}	

		ptask_handler_->get_task_pgtree(treemap);

		ret = populate_inode_tbl(socktbl, true /* get_all */);
		if (ret == -1) {
			inet_diag_thr_.set_thread_init_done(true /* init_failed */);
			return ret;
		}	

		// First run with add_conn so as to init conn list and listeners
		netns_tbl_.walk_hash_table(lambda_ns); 	

		init_done = true;

		ptask_handler_->set_init_table_done();

		inet_diag_thr_.set_thread_init_done();

		add_conn = false;
		socktbl.clear();
		treemap.clear();

		GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_MAINTENANCE)->add_oneshot_schedule(5000, "Notify Init Listeners and TCP conns", 
			[this] {
				notify_init_listeners();
				notify_init_tcp_conns();
			});	

		/*
		 * We try to schedule all Partha Inet Diagnostics Collection on a 15 sec boundary to enable faster TCP connection resolution amongst 
		 * individual Partha's.
		 */
		time_t			tcurr = time(nullptr), tnxt = (tcurr / INET_DIAG_INTERVAL_SECS) * INET_DIAG_INTERVAL_SECS;

		for (int i = 0; (i < INET_DIAG_INTERVAL_SECS + 1 + INET_DIAG_INTERVAL_SECS - (tcurr - tnxt)) && (false == inet_diag_thr_.is_thread_stop_signalled()); i++) {
			gy_nanosleep(1, 0);
		}

		while (false == inet_diag_thr_.is_thread_stop_signalled()) {

			SCOPE_NANOSLEEP			delay1(INET_DIAG_INTERVAL_SECS, 0);

			try {
				size_t 			nsnum;
				bool			inode_chked = false;

				if (socktbl.size()) {
					try {
						for (ino_t sock_inode : chkset) {
							SOCK_INODE_INFO		sock;	
									
							sock.sock_inode_ 	= sock_inode;
								
							psocktbl->emplace(sock_inode, std::move(sock));
						}	

						chkset.clear();

						populate_inode_tbl(socktbl, false /* get_all */);
						inode_chked = true;
					}
					catch(...) {
						socktbl.clear();
						inode_chked = false;
					}	
				}
				else if (chkset.size() > 4096) {
					chkset.clear();
				}	

				topnxput_.clear(); 

				ntcp_conns_ 		= 0;
				nconn_recent_active_ 	= 0;
				ntcp_coalesced_		= 0;
				nlisten_missed_		= 0;
	
				if (auto mid = pser->get_madhava_id(); local_madhava_id_ != mid) {
					local_madhava_id_ = mid;
				}

				start_inet_usec_ 	= get_usec_clock();

				// Loop through all namespaces for inet diag
				nsnum = netns_tbl_.walk_hash_table(lambda_ns); 	

				check_listener_depends_misc();
				 
				flush_diag_tcp_cache();

				send_active_stats();

				if (start_inet_usec_ >= next_lbl_check_cusec_) {
					cleanup_lbl_map();
				}	

				last_inet_diag_cusec_ = get_usec_clock();

				INFOPRINT_OFFLOAD("Current # of TCP Half Connections %lu : Recently Active Half connections (sampled) %lu : "
					"Active Net Namespaces is %lu : # connections coalesced %d : Conn diagnostics took %lu msec\n", 
					ntcp_conns_, nconn_recent_active_, nsnum, ntcp_coalesced_, (last_inet_diag_cusec_ - start_inet_usec_)/GY_USEC_PER_MSEC);

				if (inode_chked) {
					socktbl.clear();
				}

				if (nlisten_missed_ > 0) {
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Missed adding %d listeners. Trying to add manually...\n", nlisten_missed_);

					try {
						ptask_handler_->get_task_pgtree(treemap);

						ret = populate_inode_tbl(socktbl, true /* get_all */);
						if (ret == 0) {
							add_listen = true;
							GY_CC_BARRIER();

							netns_tbl_.walk_hash_table(lambda_ns); 	
						}	
					}
					catch(...) {

					}	

					nlisten_missed_ = 0;

					add_listen = false;
					socktbl.clear();
					treemap.clear();
				}	

				if (svcinodemap_.size() > 0 && bool(svcnetcap_)) {
					// Need to send svc net captures
					svcnetcap_->sched_add_listeners(0, "Service Network Capture Add Listeners", std::move(svcinodemap_), false /* isapicall */);
				}
				
				CONDEXEC( 
					DEBUGEXECN(10,
						INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Top N TCP Connections by Throughput transferred in last %d seconds : \n", 
							INET_DIAG_INTERVAL_SECS);
						
						auto walk = [](TCP_XPUT_STATS & datanode, void *arg1, void *arg2) -> CB_RET_E 
						{ 
							auto shrp = datanode.connweak_.lock();
							if (shrp) {
								if (datanode.stat_ > 1) {
									STRING_BUFFER<512>	sbuf;

									INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "TCP Conn %s : Bytes Transferred %lu (%lu MB)\n",
										shrp->print_string(sbuf, false), datanode.stat_, GY_DOWN_MB(datanode.stat_));
								}
							}
							return CB_OK;
						};

						topnxput_.walk_queue(walk, nullptr, nullptr, true /* sort_queue */, false /* heap_on_return */);
					);
				);
				
			}
			GY_CATCH_EXCEPTION(
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception caught while getting TCP Diag stats %s\n", GY_GET_EXCEPT_STRING);
			);
		}	

		INFOPRINT_OFFLOAD("Inet Diag Thread exiting now...\n");

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT_OFFLOAD("Exception caught for inet diag thread : %s\n", GY_GET_EXCEPT_STRING);

		if (init_done == false) {
			inet_diag_thr_.set_thread_init_done(true /* init_failed */);
		}	
		return -1;
	);	
}	


void TCP_SOCK_HANDLER::handle_ip_vs_conn_event(ip_vs_conn_event_t * pevent, bool more_data) noexcept
{
	try {
		ip_vs_conn_event_t		evt = *pevent;
		GY_IP_ADDR			cliaddr, virtaddr, destaddr;
	
		if (evt.af == AF_INET) {
			cliaddr.set_ip((uint32_t)evt.cliaddr.v4addr);
			virtaddr.set_ip((uint32_t)evt.virtaddr.v4addr);
		}	
		else {
			cliaddr.set_ip((unsigned __int128)evt.cliaddr.v6addr);
			virtaddr.set_ip((unsigned __int128)evt.virtaddr.v6addr);
		}	

		if (evt.daf == AF_INET) {
			destaddr.set_ip((uint32_t)evt.destaddr.v4addr);
		}
		else {
			destaddr.set_ip((unsigned __int128)evt.destaddr.v6addr);
		}	

		CONDEXEC(
			DEBUGEXECN(11,
				STRING_BUFFER<1024>		strbuf;

				strbuf.appendconst("Client IP ");
				cliaddr.printaddr(strbuf);

				strbuf.appendconst(" Port ");
				strbuf.append(evt.cliport);

				strbuf.appendconst(" : Virtual Service IP ");
				virtaddr.printaddr(strbuf);

				strbuf.appendconst(" Port ");
				strbuf.append(evt.virtport);

				strbuf.appendconst(" : Actual Dest IP ");
				destaddr.printaddr(strbuf);

				strbuf.appendconst(" Port ");
				strbuf.append(evt.destport);

				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "[New IPVS DNAT] %.*s\n", strbuf.sizeint(), strbuf.buffer());
			);	
		);

		PAIR_IP_PORT			orig_tup  {IP_PORT(cliaddr, evt.cliport), IP_PORT(virtaddr, evt.virtport)};
		PAIR_IP_PORT			nat_tup  {IP_PORT(cliaddr, evt.cliport), IP_PORT(destaddr, evt.destport)};
		const uint32_t			nhash = nat_tup.get_hash();

		NAT_ELEM			*pnat;
		NAT_ELEM_TYPE			*pelem, *pelem_cache;
		
		pnat 		= new NAT_ELEM(orig_tup, nat_tup, false /* is_snat */, true /* is_dnat */, true /* is_ipvs */);
		
		pelem 		= new NAT_ELEM_TYPE(pnat);
		pelem_cache	= new NAT_ELEM_TYPE(*pelem);

		// Use RCU_LOCK_SLOW for transaction lock with more_data
		RCU_LOCK_SLOW		scopelock(more_data);

		nat_tbl_.insert_or_replace(pelem, nat_tup, nhash);
		nat_cache_tbl_.insert_or_replace(pelem_cache, nat_tup, nhash);
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINT_OFFLOAD("Exception caught while populating IPVS Conntrack Entry : %s\n", GY_GET_EXCEPT_STRING););

		RCU_LOCK_SLOW	slowlock;
	);
}	
	
int TCP_SOCK_HANDLER::handle_nat_info(const struct nlmsghdr *pnlh) noexcept
{
	try {
		struct nfgenmsg		 	*pdata = (nfgenmsg *)mnl_nlmsg_get_payload(pnlh);
		struct nlattr 			*pattr;
		uint16_t 			attr_len;
		bool				is_new_conn;
		GY_IP_ADDR 			cli_addr, ser_addr, cli_nat_addr, ser_nat_addr, dflt_addr;
		uint16_t			cli_port = 0, ser_port = 0, cli_nat_port = 0, ser_nat_port = 0;

		if (mnl_nlmsg_get_payload_len(pnlh) < sizeof(*pdata)) {
			DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Invalid Netlink message length seen %lu while getting NAT info\n", 
				mnl_nlmsg_get_payload_len(pnlh)););
			return MNL_CB_STOP;
		}	

		if (nat_curr_req_  == false) {
			switch (pnlh->nlmsg_type & 0xFF) {
				case IPCTNL_MSG_CT_NEW:
					if (pnlh->nlmsg_flags & (NLM_F_CREATE|NLM_F_EXCL)) {
						is_new_conn = true;
					}	
					else {
						return MNL_CB_OK;
					}
					break;

				case IPCTNL_MSG_CT_DELETE:
					is_new_conn = false;
					break;

				default :
					return MNL_CB_OK;	
			}
		}
		else {
			is_new_conn = true;
		}	

		gy_mnl_attr_for_each(pattr, pnlh, sizeof(*pdata)) {
			int type = mnl_attr_get_type(pattr);

			/* skip unsupported attribute in user-space */
			if (mnl_attr_type_valid(pattr, CTA_MAX) < 0) {
				continue;
			}	

			switch (type) {
			
			case CTA_TUPLE_ORIG : {
				const struct nlattr 		*pattr_nest;

				gy_mnl_attr_for_each_nested(pattr_nest, pattr) {
					int type_nest = mnl_attr_get_type(pattr_nest);

					if (type_nest == CTA_TUPLE_PROTO) {
						const struct nlattr 		*pattr_nest2;

						gy_mnl_attr_for_each_nested(pattr_nest2, pattr_nest) {
							int type_nest2 = mnl_attr_get_type(pattr_nest2);
								
							if (type_nest2 == CTA_PROTO_NUM) {
								int proto = mnl_attr_get_u8(pattr_nest2);
								
								if (proto != IP_PROTO_TCP) {
									// XXX We currently ignore UDP Connections
									return MNL_CB_OK;
								}	
							}		
							else if (type_nest2 == CTA_PROTO_SRC_PORT) {
								if (mnl_attr_validate(pattr_nest2, MNL_TYPE_U16) >= 0) {
									cli_port = ntohs(mnl_attr_get_u16(pattr_nest2));
								}		
							}
							else if (type_nest2 == CTA_PROTO_DST_PORT) {
								if (mnl_attr_validate(pattr_nest2, MNL_TYPE_U16) >= 0) {
									ser_port = ntohs(mnl_attr_get_u16(pattr_nest2));
								}		
							}		
						}
					}
					else if (type_nest == CTA_TUPLE_IP) {
						const struct nlattr 		*pattr_nest2;

						gy_mnl_attr_for_each_nested(pattr_nest2, pattr_nest) {
							int type_nest2 = mnl_attr_get_type(pattr_nest2);
						
							if (type_nest2 == CTA_IP_V4_SRC) {

								if (mnl_attr_validate(pattr_nest2, MNL_TYPE_U32) >= 0) {
									cli_addr.set_ip(mnl_attr_get_u32(pattr_nest2));
								}
							}
							else if (type_nest2 == CTA_IP_V6_SRC) {

								attr_len = mnl_attr_get_payload_len(pattr_nest2);

								if (attr_len == sizeof(__int128)) {
									unsigned __int128	ip;
									uint8_t 		*paddr = (uint8_t *)mnl_attr_get_payload(pattr_nest2);

									std::memcpy(&ip, paddr, sizeof(ip));
									cli_addr.set_ip(ip);
								}	
							}
							else if (type_nest2 == CTA_IP_V4_DST) {

								if (mnl_attr_validate(pattr_nest2, MNL_TYPE_U32) >= 0) {
									ser_addr.set_ip(mnl_attr_get_u32(pattr_nest2));
								}
							}
							else if (type_nest2 == CTA_IP_V6_DST) {

								attr_len = mnl_attr_get_payload_len(pattr_nest2);

								if (attr_len == sizeof(__int128)) {
									unsigned __int128		ip;
									uint8_t 			*paddr = (uint8_t *)mnl_attr_get_payload(pattr_nest2);

									std::memcpy(&ip, paddr, sizeof(ip));
									ser_addr.set_ip(ip);
								}	
							}
						}
					}	
				}	

				break;
			}

			case CTA_TUPLE_REPLY : {
				const struct nlattr 		*pattr_nest;

				gy_mnl_attr_for_each_nested(pattr_nest, pattr) {
					int type_nest = mnl_attr_get_type(pattr_nest);

					if (type_nest == CTA_TUPLE_PROTO) {
						const struct nlattr 		*pattr_nest2;

						gy_mnl_attr_for_each_nested(pattr_nest2, pattr_nest) {
							int type_nest2 = mnl_attr_get_type(pattr_nest2);
								
							if (type_nest2 == CTA_PROTO_NUM) {
								int proto = mnl_attr_get_u8(pattr_nest2);
								
								if (proto != IP_PROTO_TCP) {
									// XXX We currently ignore UDP Connections
									return MNL_CB_OK;
								}	
							}		
							else if (type_nest2 == CTA_PROTO_SRC_PORT) {
								if (mnl_attr_validate(pattr_nest2, MNL_TYPE_U16) >= 0) {
									ser_nat_port = ntohs(mnl_attr_get_u16(pattr_nest2));
								}		
							}
							else if (type_nest2 == CTA_PROTO_DST_PORT) {
								if (mnl_attr_validate(pattr_nest2, MNL_TYPE_U16) >= 0) {
									cli_nat_port = ntohs(mnl_attr_get_u16(pattr_nest2));
								}		
							}		
						}
					}
					else if (type_nest == CTA_TUPLE_IP) {
						const struct nlattr 		*pattr_nest2;

						gy_mnl_attr_for_each_nested(pattr_nest2, pattr_nest) {
							int type_nest2 = mnl_attr_get_type(pattr_nest2);
						
							if (type_nest2 == CTA_IP_V4_SRC) {

								if (mnl_attr_validate(pattr_nest2, MNL_TYPE_U32) >= 0) {
									ser_nat_addr.set_ip(mnl_attr_get_u32(pattr_nest2));
								}
							}
							else if (type_nest2 == CTA_IP_V6_SRC) {

								attr_len = mnl_attr_get_payload_len(pattr_nest2);

								if (attr_len == sizeof(__int128)) {
									unsigned __int128	ip;
									uint8_t 		*paddr = (uint8_t *)mnl_attr_get_payload(pattr_nest2);

									std::memcpy(&ip, paddr, sizeof(ip));
									ser_nat_addr.set_ip(ip);
								}	
							}
							else if (type_nest2 == CTA_IP_V4_DST) {

								if (mnl_attr_validate(pattr_nest2, MNL_TYPE_U32) >= 0) {
									cli_nat_addr.set_ip(mnl_attr_get_u32(pattr_nest2));
								}
							}
							else if (type_nest2 == CTA_IP_V6_DST) {

								attr_len = mnl_attr_get_payload_len(pattr_nest2);

								if (attr_len == sizeof(__int128)) {
									unsigned __int128		ip;
									uint8_t 			*paddr = (uint8_t *)mnl_attr_get_payload(pattr_nest2);

									std::memcpy(&ip, paddr, sizeof(ip));
									cli_nat_addr.set_ip(ip);
								}	
							}
						}
					}	
				}	

				break;
			}
			
			default :
				break;
			}		
		}	

		if ((cli_port == 0) || (ser_port == 0) || (cli_nat_port == 0) || (ser_nat_port == 0)) {
			return MNL_CB_OK;
		}	

		if ((cli_addr == dflt_addr) || (ser_addr == dflt_addr) || (cli_nat_addr == dflt_addr) || (ser_nat_addr == dflt_addr)) {
			return MNL_CB_OK;
		}	

		PAIR_IP_PORT				nat_tup  {IP_PORT(cli_nat_addr, cli_nat_port), IP_PORT(ser_nat_addr, ser_nat_port)};
		const uint32_t				nhash = nat_tup.get_hash();

		if (is_new_conn) {
			bool				is_snat {(cli_addr != cli_nat_addr) || (cli_port != cli_nat_port)}; 
			bool				is_dnat {(ser_addr != ser_nat_addr) || (ser_port != ser_nat_port)}; 

			if (!is_snat && !is_dnat) {
				// Ignore
				return MNL_CB_OK;
			}	

			NAT_ELEM			*pnat;
			NAT_ELEM_TYPE			*pelem, *pelem_cache;

			pnat = new NAT_ELEM(PAIR_IP_PORT(IP_PORT(cli_addr, cli_port), IP_PORT(ser_addr, ser_port)), nat_tup, is_snat, is_dnat, false /* is_ipvs */);
			
			CONDEXEC( 
				DEBUGEXECN(11,
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "[New CT] %s\n", pnat->print_string(STRING_BUFFER<512>().get_str_buf()));
				);
			);	

			pelem 		= new NAT_ELEM_TYPE(pnat);
			pelem_cache	= new NAT_ELEM_TYPE(*pelem);

			RCU_LOCK_SLOW		scopelock;

			nat_tbl_.insert_or_replace(pelem, nat_tup, nhash);
			nat_cache_tbl_.insert_or_replace(pelem_cache, nat_tup, nhash);
		}
		else {	

			auto 	lam_chk = [](NAT_ELEM_TYPE *pdatanode, void *arg1, void *arg2) -> CB_RET_E
			{
				auto			pnat = pdatanode->get_cref().get();

				if (pnat == nullptr) {
					return CB_DELETE_ELEM;
				}

				CONDEXEC( 
					DEBUGEXECN(11, 
						INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "[Close CT] %s\n", pnat->print_string(STRING_BUFFER<512>().get_str_buf()));
					);
				);

				// Check if the TCP Conn has been deleted. If not we need to keep this entry for some more time
				if (pnat->shr_updated_.load(std::memory_order_acquire)) {
					if (pnat->shrconn_.use_count() <= 1) {
						return CB_DELETE_ELEM;
					}
				}

				pnat->is_deleted_ = true;
						
				return CB_OK;
			};	

			RCU_LOCK_SLOW		scopelock;

			nat_tbl_.lookup_single_elem(nat_tup, nhash, lam_chk);
			nat_cache_tbl_.delete_single_elem(nat_tup, nhash);
		}		

		return MNL_CB_OK;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT_OFFLOAD("Exception caught while populating NAT Conntrack from netlink : %s\n", GY_GET_EXCEPT_STRING);

		RCU_LOCK_SLOW	slowlock;
		return MNL_CB_STOP;
	);
}	

int TCP_SOCK_HANDLER::nl_conntrack_get_current() noexcept
{
	try {
		struct mnl_socket 		*pnl;
		uint8_t				*pmnlbuf;
		int 				ret;
		struct nlmsghdr 		*pnlh;
		struct nfgenmsg 		*pnfh;
		uint32_t 			seq, portid;

		pmnlbuf = new uint8_t[GY_MNL_SOCKET_BUFFER_SIZE];
		
		GY_SCOPE_EXIT {
			delete [] pmnlbuf;
		};	

		pnl = mnl_socket_open(NETLINK_NETFILTER);
		if (pnl == nullptr) {
			PERRORPRINT("netlink conntrack current socket open failed");
			return -1;
		}

		GY_SCOPE_EXIT {
			mnl_socket_close(pnl);
		};

		if (mnl_socket_bind(pnl, 0, MNL_SOCKET_AUTOPID) < 0) {
			PERRORPRINT("netlink conntrack current socket bind failed");
			return -1;
		}

		pnlh 			= mnl_nlmsg_put_header(pmnlbuf);
		pnlh->nlmsg_type 	= (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET;
		pnlh->nlmsg_flags 	= NLM_F_REQUEST | NLM_F_DUMP;
		pnlh->nlmsg_seq 	= seq = time(nullptr);

		pnfh 			= (nfgenmsg *)mnl_nlmsg_put_extra_header(pnlh, sizeof(struct nfgenmsg));
		pnfh->nfgen_family 	= AF_UNSPEC;
		pnfh->version 		= NFNETLINK_V0;
		pnfh->res_id 		= 0;

		ret = mnl_socket_sendto(pnl, pnlh, pnlh->nlmsg_len);
		if (ret == -1) {
			PERRORPRINT_OFFLOAD("netlink conntrack current socket sendto failed");
			return -1;
		}
		portid 			= mnl_socket_get_portid(pnl);

		auto mnlcb = [](const struct nlmsghdr *pnlh, void *arg) -> int
		{
			TCP_SOCK_HANDLER 		*pthis = static_cast<TCP_SOCK_HANDLER *>(arg);

			return 	pthis->handle_nat_info(pnlh);
		};

		nat_curr_req_ = true;

		while (true) {

			ret = mnl_socket_recvfrom(pnl, pmnlbuf, GY_MNL_SOCKET_BUFFER_SIZE);
			if (ret == -1) {
				if (errno == EINTR) {
					continue;
				}	
				PERRORPRINT_OFFLOAD("netlink conntrack current socket recv failed");
				return -1;
			}

			ret = mnl_cb_run(pmnlbuf, ret, seq, portid, mnlcb, this);
			if (ret == -1) {
				PERRORPRINT_OFFLOAD("netlink conntrack current callback failed");
				return -1;
			}
			else if (ret <= MNL_CB_STOP) {
				break;
			}	
		}

		return 0;
	}
	GY_CATCH_EXCEPTION(ERRORPRINT_OFFLOAD("Exception caught in Netlink conntrack current thread  : %s\n", GY_GET_EXCEPT_STRING); return -1;);
}

int TCP_SOCK_HANDLER::nl_conntrack_event_mon(bool & init_done, int nerrors) noexcept
{
	try {
		struct mnl_socket 		*pnl;
		uint8_t				*pmnlbuf;
		int 				ret;
		struct pollfd 			pfds[1] = {};

		init_done = false;

		pmnlbuf = new uint8_t[GY_MNL_SOCKET_BUFFER_SIZE];
		
		GY_SCOPE_EXIT {
			delete [] pmnlbuf;
		};	

		pnl = mnl_socket_open(NETLINK_NETFILTER);
		if (pnl == nullptr) {
			PERRORPRINT_OFFLOAD("netlink conntrack socket open failed");
			return -1;
		}

		GY_SCOPE_EXIT {
			mnl_socket_close(pnl);
		};

		if (mnl_socket_bind(pnl, NF_NETLINK_CONNTRACK_NEW | NF_NETLINK_CONNTRACK_DESTROY, MNL_SOCKET_AUTOPID) < 0) {
			PERRORPRINT_OFFLOAD("netlink conntrack socket bind failed");
			return -1;
		}

		init_done = true;

		if (nerrors == 0) {
			nat_thr_.set_thread_init_done();
		}

		pfds[0].fd 	= mnl_socket_get_fd(pnl);
		pfds[0].events 	= POLLIN | POLLRDHUP;
		pfds[0].revents = 0;

		auto mnlcb = [](const struct nlmsghdr *pnlh, void *arg) -> int
		{
			TCP_SOCK_HANDLER 		*pthis = static_cast<TCP_SOCK_HANDLER *>(arg);

			return 	pthis->handle_nat_info(pnlh);
		};

		while (false == nat_thr_.is_thread_stop_signalled()) {

			ret = poll(pfds, 1, 1000);
			if (ret < 0) {
				if (errno == EINTR) {
					continue;
				}
				PERRORPRINT_OFFLOAD("poll for netlink conntrack socket recv failed");
				return -1;
			}
			else if (ret == 0) {
				continue;
			}

			ret = mnl_socket_recvfrom(pnl, pmnlbuf, GY_MNL_SOCKET_BUFFER_SIZE);
			if (ret == -1) {
				if (errno == EINTR || errno == EAGAIN) {
					continue;
				}	
				if (errno != ENOBUFS) {
					PERRORPRINT_OFFLOAD("netlink conntrack socket recv failed");
				}
				else {
					INFOPRINT_OFFLOAD("netlink conntrack socket buffer not available. Will retry...\n");
				}	
				return -1;
			}

			ret = mnl_cb_run(pmnlbuf, ret, 0, 0, mnlcb, this);
			if (ret == -1) {
				PERRORPRINT_OFFLOAD("netlink conntrack callback failed");
				return -1;
			}
		}

		return 0;
	}
	GY_CATCH_EXCEPTION(ERRORPRINT_OFFLOAD("Exception caught in Netlink conntrack thread  : %s\n", GY_GET_EXCEPT_STRING); return -1;);
}	
	

int TCP_SOCK_HANDLER::nat_conntrack_thread() noexcept
{
	bool			init_done;
	int			ret, nerrors = 0, nsuccess = 0;
	uint64_t		startsec, currsec;

	ret = nl_conntrack_get_current();
	if (ret != 0) {
		ERRORPRINT("Netlink conntrack Thread exiting now as Conntrack init failed...\n");
		
		nat_thr_.set_thread_init_done(true /* init_failed */);
		return -1;
	}
	
	nat_curr_req_ = false;
		
	do {
		startsec = get_sec_clock();

		ret = nl_conntrack_event_mon(init_done, nerrors);
		if (ret != 0) {
			if (init_done) {
				nsuccess++;

				currsec = get_sec_clock();

				if (currsec - startsec > 10) {
					INFOPRINT_OFFLOAD("Netlink conntrack returned with an error after some time. Trying again...\n");

					// Reset nerrors
					nerrors = 1;
					continue;
				}
					
				if (++nerrors < 1024) {
					ERRORPRINT("Netlink conntrack returned with an error. Trying again...\n");
					gy_nanosleep(50 * nerrors * GY_NSEC_PER_MSEC);
					continue;
				}
				else {
					ERRORPRINT("Netlink conntrack returned with an error. Too many errors. Quitting...\n");
					return -1;
				}		
			}	
			else {
				if (nsuccess) {
					nsuccess = 0;
					gy_nanosleep(0, 50 * GY_USEC_PER_MSEC);
					continue;
				}	
				ERRORPRINT("Netlink conntrack returned with an error. Quitting...\n");

				nat_thr_.set_thread_init_done(true /* init_failed */);
				return -1;
			}	
		}	
		else {
			break;
		}	
	} while (1);

	INFOPRINT_OFFLOAD("Netlink conntrack Thread exiting now...\n");
	return 0;
}	

static TCP_SOCK_HANDLER			*pgtcp_sock_ = nullptr;

TCP_SOCK_HANDLER * TCP_SOCK_HANDLER::get_singleton() noexcept
{
	return pgtcp_sock_;
}	
	
int TCP_SOCK_HANDLER::init_singleton(uint8_t resp_sampling_percent, bool capture_errcode, bool disable_api_capture, uint32_t api_max_len)
{
	int					texp = 0, tdes = 1;
	static std::atomic<int>			is_init_done(0);

	if (false == is_init_done.compare_exchange_strong(texp, tdes)) {
		return 0;
	}
	
	char				*ptmpalloc = nullptr;
	int				ret;
		
	// Using placement new as new will not allocate 128 byte aligned memory before C++17
	ret = posix_memalign((void **)&ptmpalloc, 128, sizeof(TCP_SOCK_HANDLER) + 16);

	try {
		if (ret || !ptmpalloc) {
			errno = ret;
			GY_THROW_SYS_EXCEPTION("Failed to allocate memory for TCP sock singleton");
		}

		pgtcp_sock_ = (TCP_SOCK_HANDLER *)ptmpalloc;

		new (pgtcp_sock_) TCP_SOCK_HANDLER(resp_sampling_percent, capture_errcode, disable_api_capture, api_max_len);

		return 0;
	}
	GY_CATCH_EXCEPTION(
		if (ptmpalloc) {
			free(ptmpalloc);
		}
		pgtcp_sock_ = nullptr;
		ERRORPRINT("Exception caught while creating global TCP sock handler object : %s\n", GY_GET_EXCEPT_STRING);
		throw;
	);
}


} // namespace gyeeta
	
