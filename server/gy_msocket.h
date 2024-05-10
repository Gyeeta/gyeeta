//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"
#include			"gy_inet_inc.h"
#include			"gy_pool_alloc.h"
#include			"gy_stack_container.h"
#include			"gy_statistics.h"
#include			"gy_query_common.h"
#include			"gy_proto_common.h"
#include			"gy_trace_def.h"

#include			"folly/concurrency/AtomicSharedPtr.h" 
#include			"folly/MicroLock.h"
#include 			"folly/SharedMutex.h"
#include 			"folly/container/F14Map.h"

#include			<unordered_map>
#include			<optional>

using 				folly::SharedMutex;

namespace gyeeta {
namespace madhava {

class LISTENER_ISSUE_RESOL
{
public:
	comm::MM_LISTENER_ISSUE_RESOL	resol_;
	gy_atomic<uint64_t>		upd_tusec_		{0};
	uint64_t 			downstream_glob_id_	{0};
	uint8_t				src_upstream_tier_	{0};
};	

class CPU_MEM_STATE
{
public :	
	int64_t				tusec_			{0};
	comm::CPU_MEM_STATE_NOTIFY	cpu_mem_		{};
	char				cpu_state_str_[256]	{};
	char				mem_state_str_[256]	{};

	void set_new_state(const comm::CPU_MEM_STATE_NOTIFY *pcpumem, int64_t currtusec = get_usec_time()) noexcept
	{
		cpu_mem_		= *pcpumem;

		if (pcpumem->cpu_state_string_len_) {
			std::memcpy(cpu_state_str_, (const char *)(pcpumem + 1), pcpumem->cpu_state_string_len_ & 0xFF);
			cpu_state_str_[pcpumem->cpu_state_string_len_ - 1] = 0;
		}	
		else {
			*cpu_state_str_ = 0;
		}	

		if (pcpumem->mem_state_string_len_) {
			std::memcpy(mem_state_str_, (const char *)((const char *)pcpumem + sizeof(*pcpumem) + pcpumem->cpu_state_string_len_), pcpumem->mem_state_string_len_ & 0xFF);
			mem_state_str_[pcpumem->mem_state_string_len_ - 1] = 0;
		}	
		else {
			*mem_state_str_ = 0;
		}	

		GY_CC_BARRIER();

		tusec_ = currtusec;
	}

	bool is_recent_cpu_issue(int64_t currtusec, uint8_t bitmap = 0x0F /* 4 * 2 = 8 sec */) const noexcept
	{
		if (currtusec - tusec_ >= 8 * (int64_t)GY_USEC_PER_SEC) {
			return false;
		}

		return ((cpu_mem_.cpu_issue_bit_hist_ & bitmap) > 0);
	}	

	bool is_recent_mem_issue(int64_t currtusec, uint8_t bitmap = 0x0F /* 4 * 2 = 8 sec */) const noexcept
	{
		if (currtusec - tusec_ >= 8 * (int64_t)GY_USEC_PER_SEC) {
			return false;
		}

		return ((cpu_mem_.mem_issue_bit_hist_ & bitmap) > 0);
	}	

	bool is_severe_cpu_issue(int64_t currtusec, uint8_t bitmap = 0x0F /* 4 * 2 = 8 sec */) const noexcept
	{
		if (currtusec - tusec_ >= 8 * (int64_t)GY_USEC_PER_SEC) {
			return false;
		}

		return ((cpu_mem_.cpu_severe_issue_hist_ & bitmap) > 0);
	}	

	bool is_severe_mem_issue(int64_t currtusec, uint8_t bitmap = 0x0F /* 4 * 2 = 8 sec */) const noexcept
	{
		if (currtusec - tusec_ >= 8 * (int64_t)GY_USEC_PER_SEC) {
			return false;
		}

		return ((cpu_mem_.mem_severe_issue_hist_ & bitmap) > 0);
	}	

	bool is_state_bad(int64_t currtusec) const noexcept
	{
		if (currtusec - tusec_ >= 8 * (int64_t)GY_USEC_PER_SEC) {
			return false;
		}

		return (cpu_mem_.cpu_state_ >= (uint8_t)STATE_BAD) || (cpu_mem_.mem_state_ >= (uint8_t)STATE_BAD);
	}	

	bool is_state_severe(int64_t currtusec) const noexcept
	{
		if (currtusec - tusec_ >= 8 * (int64_t)GY_USEC_PER_SEC) {
			return false;
		}

		return (cpu_mem_.cpu_state_ >= (uint8_t)STATE_SEVERE) || (cpu_mem_.mem_state_ >= (uint8_t)STATE_SEVERE);
	}	
};	

class TASK_TOP_PROCS_INFO
{
public :	
	uint64_t			tusec_		{0};
	comm::TASK_TOP_PROCS		topinfo_;
	alignas(8) uint8_t		topn_data_[comm::TASK_TOP_PROCS::get_max_elem_size() - sizeof(comm::TASK_TOP_PROCS)];

	TASK_TOP_PROCS_INFO() noexcept	= default;

	TASK_TOP_PROCS_INFO(const TASK_TOP_PROCS_INFO &other) noexcept
		: tusec_(other.tusec_), topinfo_(other.topinfo_)
	{
		if (topinfo_.ext_data_len_ <= sizeof(topn_data_)) {
			std::memcpy(topn_data_, other.topn_data_, topinfo_.ext_data_len_);
		}
		else {
			tusec_ = 0;
		}	
	}	

	void update_stats(const comm::TASK_TOP_PROCS *ptask, const uint8_t *pendptr, uint64_t tusec = get_usec_time()) noexcept
	{
		if (ptask->ext_data_len_ <= sizeof(topn_data_)) {
			tusec_		= tusec;
			topinfo_ 	= *ptask;

			std::memcpy(topn_data_, (const uint8_t *)(ptask + 1), ptask->ext_data_len_);
		}
	}
};	



class MIP_PORT
{
public :	
	RCU_HASH_CLASS_MEMBERS(IP_PORT, MIP_PORT);

	IP_PORT				ip_port_;
	uint64_t			last_update_tusec_	{0};

	MIP_PORT(IP_PORT ip_port, uint64_t curr_tusec = get_usec_time()) noexcept
		: ip_port_(ip_port), last_update_tusec_(curr_tusec)
	{}

	friend inline bool operator== (const MIP_PORT & lhs, IP_PORT ip_port) noexcept
	{
		return lhs.ip_port_ == ip_port;
	}
};

using MIP_PORT_TBL			= RCU_HASH_TABLE <IP_PORT, MIP_PORT>;

static constexpr size_t			MAX_CLOSE_CONN_ELEM		{256};

struct CONN_PEER_ONE
{
	char				comm_[TASK_COMM_LEN]		{};
	GY_MACHINE_ID 			remote_machine_id_;
	uint64_t			remote_madhava_id_		{0};
	uint64_t			bytes_sent_			{0};
	uint64_t			bytes_received_			{0};
	uint32_t			nconns_				{0};
	bool				cli_listener_proc_		{false};

	CONN_PEER_ONE() noexcept 	= default;

	CONN_PEER_ONE(const char *comm, GY_MACHINE_ID remote_machine_id, uint64_t remote_madhava_id) noexcept
		: remote_machine_id_(remote_machine_id), remote_madhava_id_(remote_madhava_id)
	{
		GY_STRNCPY(comm_, comm, sizeof(comm_));
	}	

	comm::ACTIVE_CONN_STATS get_active_conn(uint64_t listener_glob_id, uint64_t cli_aggr_task_id, const char *ser_comm, const GY_MACHINE_ID & svc_machine_id_) const noexcept
	{
		comm::ACTIVE_CONN_STATS		aconn;

		aconn.listener_glob_id_		= listener_glob_id;
		aconn.cli_aggr_task_id_		= cli_aggr_task_id;
		std::memcpy(aconn.ser_comm_, ser_comm, sizeof(aconn.ser_comm_));
		std::memcpy(aconn.cli_comm_, comm_, sizeof(aconn.cli_comm_));
		aconn.remote_machine_id_	= remote_machine_id_;
		aconn.remote_madhava_id_	= remote_madhava_id_;
		aconn.bytes_sent_		= bytes_sent_;
		aconn.bytes_received_		= bytes_received_;
		aconn.active_conns_		= nconns_;
		aconn.cli_listener_proc_	= cli_listener_proc_;
		aconn.is_remote_listen_		= false;
		aconn.is_remote_cli_		= (svc_machine_id_ != remote_machine_id_);

		return aconn;
	}	

	comm::ACTIVE_CONN_STATS get_remote_conn(uint64_t listener_glob_id, uint64_t cli_aggr_task_id, const char *cli_comm, bool cli_listener_proc) const noexcept
	{
		comm::ACTIVE_CONN_STATS		aconn;

		aconn.listener_glob_id_		= listener_glob_id;
		aconn.cli_aggr_task_id_		= cli_aggr_task_id;
		std::memcpy(aconn.ser_comm_, comm_, sizeof(aconn.ser_comm_));
		std::memcpy(aconn.cli_comm_, cli_comm, sizeof(aconn.cli_comm_));
		aconn.remote_machine_id_	= remote_machine_id_;
		aconn.remote_madhava_id_	= remote_madhava_id_;
		aconn.bytes_sent_		= bytes_sent_;
		aconn.bytes_received_		= bytes_received_;
		aconn.active_conns_		= nconns_;
		aconn.cli_listener_proc_	= cli_listener_proc;
		aconn.is_remote_listen_		= true;
		aconn.is_remote_cli_		= false;

		return aconn;
	}	

};	

using ConnPeerMap			= GY_STACK_HASH_MAP<uint64_t, CONN_PEER_ONE, 600 * (sizeof(CONN_PEER_ONE) + 8 + 8), GY_JHASHER<uint64_t>>;
using ConnPeerMapArena			= ConnPeerMap::allocator_type::arena_type;

struct CONN_LISTEN_ONE
{
	char				ser_comm_[TASK_COMM_LEN];
	ConnPeerMap			climap_;

	CONN_LISTEN_ONE(const char * ser_comm, ConnPeerMapArena & arena) 
		: climap_(arena)
	{
		GY_STRNCPY(ser_comm_, ser_comm, sizeof(ser_comm_));
	}	
};	

using ConnListenMap			= INLINE_STACK_HASH_MAP<uint64_t /* glob_id_ */, CONN_LISTEN_ONE, MAX_CLOSE_CONN_ELEM * (sizeof(CONN_LISTEN_ONE) + 8 + 8), GY_JHASHER<uint64_t>>;

struct CONN_CLIENT_ONE
{
	char				cli_comm_[TASK_COMM_LEN];
	bool				cli_listener_proc_		{false};
	ConnPeerMap			listmap_;

	CONN_CLIENT_ONE(const char * cli_comm, bool cli_listener_proc, ConnPeerMapArena & arena) 
		: cli_listener_proc_(cli_listener_proc), listmap_(arena)
	{
		GY_STRNCPY(cli_comm_, cli_comm, sizeof(cli_comm_));
	}	
};	

using ConnClientMap			= INLINE_STACK_HASH_MAP<uint64_t, CONN_CLIENT_ONE, MAX_CLOSE_CONN_ELEM * (sizeof(CONN_CLIENT_ONE) + 8 + 8), GY_JHASHER<uint64_t>>;

struct CONN_PEER_UNKNOWN
{
	uint64_t			bytes_sent_			{0};
	uint64_t			bytes_received_			{0};
	uint32_t			nconns_				{0};
	bool				cli_listener_proc_		{false};
	char				cli_ser_comm_[TASK_COMM_LEN]	{};

	CONN_PEER_UNKNOWN(const char *comm, bool cli_listener_proc = false) noexcept
		: cli_listener_proc_(cli_listener_proc)
	{
		GY_STRNCPY(cli_ser_comm_, comm, sizeof(cli_ser_comm_));
	}	
};	

using ConnUnknownMap			= INLINE_STACK_HASH_MAP<uint64_t, CONN_PEER_UNKNOWN, gy_align_up_2(uint64_t(MAX_CLOSE_CONN_ELEM * 0.67) * (sizeof(CONN_PEER_UNKNOWN) + 8 + 8), 16), 
									GY_JHASHER<uint64_t>>;

struct CLI_UN_SERV_INFO
{
	time_t				tstart_;
	uint64_t 			cli_task_aggr_id_;
	char 				cli_comm_[TASK_COMM_LEN];
	uint64_t			cli_related_listen_id_;
	uint64_t			ser_glob_id_;
	uint64_t			ser_related_listen_id_;
	char 				ser_comm_[TASK_COMM_LEN];
	GY_MACHINE_ID 			ser_partha_machine_id_;
	uint64_t			close_cli_bytes_sent_;
	uint64_t			close_cli_bytes_rcvd_;
	uint64_t			ser_madhava_id_;

	CLI_UN_SERV_INFO(time_t tstart, uint64_t cli_task_aggr_id, const char *cli_comm, uint64_t cli_related_listen_id, uint64_t ser_glob_id, uint64_t ser_related_listen_id,
				const char *ser_comm, GY_MACHINE_ID ser_partha_machine_id, uint64_t close_cli_bytes_sent, uint64_t close_cli_bytes_rcvd, uint64_t ser_madhava_id) noexcept
		: tstart_(tstart), cli_task_aggr_id_(cli_task_aggr_id), cli_related_listen_id_(cli_related_listen_id), ser_glob_id_(ser_glob_id), 
		ser_related_listen_id_(ser_related_listen_id), ser_partha_machine_id_(ser_partha_machine_id), close_cli_bytes_sent_(close_cli_bytes_sent), 
		close_cli_bytes_rcvd_(close_cli_bytes_rcvd), ser_madhava_id_(ser_madhava_id)

	{
		GY_STRNCPY(cli_comm_, cli_comm, sizeof(cli_comm_));
		GY_STRNCPY(ser_comm_, ser_comm, sizeof(ser_comm_));
	}

	CLI_UN_SERV_INFO(const comm::SHYAMA_CLI_TCP_INFO & obj) noexcept
		: tstart_(obj.tusec_mstart_/GY_USEC_PER_SEC), cli_task_aggr_id_(obj.cli_task_aggr_id_), cli_related_listen_id_(obj.cli_related_listen_id_), ser_glob_id_(obj.ser_glob_id_), 
		ser_related_listen_id_(obj.ser_related_listen_id_), ser_partha_machine_id_(obj.ser_partha_machine_id_), close_cli_bytes_sent_(obj.close_cli_bytes_sent_), 
		close_cli_bytes_rcvd_(obj.close_cli_bytes_rcvd_), ser_madhava_id_(obj.ser_madhava_id_)
	{
		GY_STRNCPY(cli_comm_, obj.cli_comm_, sizeof(cli_comm_));
		GY_STRNCPY(ser_comm_, obj.ser_comm_, sizeof(ser_comm_));
	}

};

struct SER_UN_CLI_INFO
{
	time_t				tstart_;
	uint64_t			ser_glob_id_;
	char 				ser_comm_[TASK_COMM_LEN];
	uint64_t 			cli_task_aggr_id_;
	uint64_t			cli_related_listen_id_;
	char 				cli_comm_[TASK_COMM_LEN];
	GY_MACHINE_ID 			cli_partha_machine_id_;
	uint64_t			close_cli_bytes_sent_;
	uint64_t			close_cli_bytes_rcvd_;
	uint64_t			cli_madhava_id_;

	SER_UN_CLI_INFO(time_t tstart, uint64_t ser_glob_id, const char *ser_comm, uint64_t cli_task_aggr_id, uint64_t cli_related_listen_id, \
				const char *cli_comm, GY_MACHINE_ID cli_partha_machine_id, uint64_t close_cli_bytes_sent, uint64_t close_cli_bytes_rcvd, uint64_t cli_madhava_id) noexcept
		: tstart_(tstart), ser_glob_id_(ser_glob_id), cli_task_aggr_id_(cli_task_aggr_id), cli_related_listen_id_(cli_related_listen_id),
		cli_partha_machine_id_(cli_partha_machine_id), close_cli_bytes_sent_(close_cli_bytes_sent), close_cli_bytes_rcvd_(close_cli_bytes_rcvd), cli_madhava_id_(cli_madhava_id)
	{
		GY_STRNCPY(ser_comm_, ser_comm, sizeof(ser_comm_));
		GY_STRNCPY(cli_comm_, cli_comm, sizeof(cli_comm_));
	}

	SER_UN_CLI_INFO(const comm::SHYAMA_SER_TCP_INFO & obj) noexcept
		: tstart_(obj.tusec_mstart_/GY_USEC_PER_SEC), ser_glob_id_(obj.ser_glob_id_), cli_task_aggr_id_(obj.cli_task_aggr_id_), cli_related_listen_id_(obj.cli_related_listen_id_),
		cli_partha_machine_id_(obj.cli_partha_machine_id_), close_cli_bytes_sent_(obj.close_cli_bytes_sent_), close_cli_bytes_rcvd_(obj.close_cli_bytes_rcvd_), 
		cli_madhava_id_(obj.cli_madhava_id_)
	{
		GY_STRNCPY(ser_comm_, obj.ser_comm_, sizeof(ser_comm_));
		GY_STRNCPY(cli_comm_, obj.cli_comm_, sizeof(cli_comm_));
	}
	
};


class MULTI_HOST_IDENT
{
public :
	char				hostname_[MAX_DOMAINNAME_SIZE];
	char				cluster_name_[comm::MAX_CLUSTER_NAME_LEN];
	char				machine_id_str_[33];
	uint16_t			lenhost_;
	uint16_t			lencluster_;

	MULTI_HOST_IDENT() noexcept
	{
		*hostname_ 		= 0;
		*cluster_name_		= 0;
		*machine_id_str_	= 0;
		lenhost_		= 0;
		lencluster_		= 0;
	}

	MULTI_HOST_IDENT(const char *hostname, const char *cluster_name, const char *machine_id_str) noexcept
	{
		lenhost_ 	= strnlen(hostname, sizeof(hostname_) - 1);
		lencluster_	= strnlen(cluster_name, sizeof(cluster_name_) - 1);

		std::memcpy(hostname_, hostname, lenhost_);
		hostname_[lenhost_] = 0;

		std::memcpy(cluster_name_, cluster_name, lencluster_);
		cluster_name_[lencluster_] = 0;

		std::memcpy(machine_id_str_, machine_id_str, sizeof(machine_id_str_) - 1);
		machine_id_str_[sizeof(machine_id_str_) - 1] = 0;
	}	

	MULTI_HOST_IDENT(const MULTI_HOST_IDENT & other) noexcept
		: lenhost_(other.lenhost_), lencluster_(other.lencluster_)
	{
		std::memcpy(hostname_, other.hostname_, lenhost_);
		hostname_[lenhost_] = 0;

		std::memcpy(cluster_name_, other.cluster_name_, lencluster_);
		cluster_name_[lencluster_] = 0;

		std::memcpy(machine_id_str_, other.machine_id_str_, sizeof(machine_id_str_) - 1);
		machine_id_str_[sizeof(machine_id_str_) - 1] = 0;
	}	

	MULTI_HOST_IDENT & operator=(const MULTI_HOST_IDENT & other) noexcept
	{
		if (this != &other) {
			lenhost_ = other.lenhost_;
			lencluster_ = other.lencluster_;

			std::memcpy(hostname_, other.hostname_, lenhost_);
			hostname_[lenhost_] = 0;

			std::memcpy(cluster_name_, other.cluster_name_, lencluster_);
			cluster_name_[lencluster_] = 0;

			std::memcpy(machine_id_str_, other.machine_id_str_, sizeof(machine_id_str_) - 1);
			machine_id_str_[sizeof(machine_id_str_) - 1] = 0;
		}

		return *this;
	}
};

class MREQ_TRACE_DEFS
{
public :
	using					DefMap = folly::F14VectorMap<uint32_t, REQ_TRACE_DEF, GY_JHASHER<uint32_t>>;

	SharedMutex				def_rwmutex_;
	DefMap					defmap_;
	gy_atomic<uint64_t>			lastupdcusec_		{0};
	gy_atomic<uint64_t>			lastchkcusec_		{0};
};


class MAGGR_TASK_STATE
{
public :
	uint64_t				last_usec_time_		{0};
	comm::AGGR_TASK_STATE_NOTIFY		task_state_;

	MAGGR_TASK_STATE() noexcept		= default;

	MAGGR_TASK_STATE(const comm::AGGR_TASK_STATE_NOTIFY & task_state, uint64_t curr_tusec = get_usec_time()) noexcept
		: last_usec_time_(curr_tusec), task_state_(task_state)
	{}	

	MAGGR_TASK_STATE(const MAGGR_TASK_STATE &) noexcept		= default;

	MAGGR_TASK_STATE & operator=(const MAGGR_TASK_STATE &) noexcept	= default;

	static inline bool is_comp_net(const comm::AGGR_TASK_STATE_NOTIFY & lhs_state, const MAGGR_TASK_STATE & rhs) noexcept
	{
		return lhs_state.tcp_kbytes_ > rhs.task_state_.tcp_kbytes_;
	}	
	
	struct TOP_NET
	{
		bool operator() (const MAGGR_TASK_STATE & lhs, const MAGGR_TASK_STATE & rhs) const noexcept
		{
			return is_comp_net(lhs.task_state_, rhs);
		}	
	};	

	static inline bool is_comp_cpu(const comm::AGGR_TASK_STATE_NOTIFY & lhs_state, const MAGGR_TASK_STATE & rhs) noexcept
	{
		return lhs_state.total_cpu_pct_ > rhs.task_state_.total_cpu_pct_;
	}	
	
	struct TOP_CPU
	{
		bool operator() (const MAGGR_TASK_STATE & lhs, const MAGGR_TASK_STATE & rhs) const noexcept
		{
			return is_comp_cpu(lhs.task_state_, rhs);
		}	
	};	

	static inline bool is_comp_rss(const comm::AGGR_TASK_STATE_NOTIFY & lhs_state, const MAGGR_TASK_STATE & rhs) noexcept
	{
		return lhs_state.rss_mb_ > rhs.task_state_.rss_mb_;
	}	
	
	struct TOP_RSS
	{
		bool operator() (const MAGGR_TASK_STATE & lhs, const MAGGR_TASK_STATE & rhs) const noexcept
		{
			return is_comp_rss(lhs.task_state_, rhs);
		}	
	};	

	static inline bool is_comp_cpu_delay(const comm::AGGR_TASK_STATE_NOTIFY & lhs_state, const MAGGR_TASK_STATE & rhs) noexcept
	{
		return lhs_state.cpu_delay_msec_ > rhs.task_state_.cpu_delay_msec_;
	}	
	
	struct TOP_CPU_DELAY
	{
		bool operator() (const MAGGR_TASK_STATE & lhs, const MAGGR_TASK_STATE & rhs) const noexcept
		{
			return is_comp_cpu_delay(lhs.task_state_, rhs);
		}	
	};	

	static inline bool is_comp_vm_delay(const comm::AGGR_TASK_STATE_NOTIFY & lhs_state, const MAGGR_TASK_STATE & rhs) noexcept
	{
		return lhs_state.vm_delay_msec_ > rhs.task_state_.vm_delay_msec_;
	}	

	struct TOP_VM_DELAY
	{
		bool operator() (const MAGGR_TASK_STATE & lhs, const MAGGR_TASK_STATE & rhs) const noexcept
		{
			return is_comp_vm_delay(lhs.task_state_, rhs);
		}	
	};	

	static inline bool is_comp_io_delay(const comm::AGGR_TASK_STATE_NOTIFY & lhs_state, const MAGGR_TASK_STATE & rhs) noexcept
	{
		return lhs_state.blkio_delay_msec_ > rhs.task_state_.blkio_delay_msec_;
	}	

	struct TOP_IO_DELAY
	{
		bool operator() (const MAGGR_TASK_STATE & lhs, const MAGGR_TASK_STATE & rhs) const noexcept
		{
			return is_comp_io_delay(lhs.task_state_, rhs);
		}	
	};	
};

class MULTI_MAGGR_TASK_STATE : public MULTI_HOST_IDENT, public MAGGR_TASK_STATE
{
public :
	MULTI_MAGGR_TASK_STATE() noexcept		= default;

	MULTI_MAGGR_TASK_STATE(const char *hostname, const char *cluster_name, const char *machine_id_str, const comm::AGGR_TASK_STATE_NOTIFY & task_state, uint64_t curr_tusec = get_usec_time()) noexcept
		: MULTI_HOST_IDENT(hostname, cluster_name, machine_id_str), MAGGR_TASK_STATE(task_state, curr_tusec)
	{}	

	MULTI_MAGGR_TASK_STATE(const char *hostname, const char *cluster_name, const char *machine_id_str, const MAGGR_TASK_STATE & elem) noexcept
		: MULTI_HOST_IDENT(hostname, cluster_name, machine_id_str), MAGGR_TASK_STATE(elem)
	{}	

	MULTI_MAGGR_TASK_STATE(const MULTI_MAGGR_TASK_STATE &) noexcept			= default;
	MULTI_MAGGR_TASK_STATE(MULTI_MAGGR_TASK_STATE &&) noexcept			= default;

	MULTI_MAGGR_TASK_STATE & operator=(const MULTI_MAGGR_TASK_STATE &) noexcept	= default;
	MULTI_MAGGR_TASK_STATE & operator=(MULTI_MAGGR_TASK_STATE &&) noexcept		= default;

	~MULTI_MAGGR_TASK_STATE() noexcept						= default;
};

class MTASK_ISSUE
{
public :
	uint64_t				last_usec_time_			{0};
	comm::AGGR_TASK_STATE_NOTIFY		task_state_			{};
	char					issue_string_[comm::AGGR_TASK_STATE_NOTIFY::MAX_ISSUE_LEN];

	MTASK_ISSUE() noexcept
	{
		*issue_string_ = 0;
	}	

	MTASK_ISSUE(const comm::AGGR_TASK_STATE_NOTIFY & task_state, uint64_t curr_tusec = get_usec_time()) noexcept
	{
		set_task_state(&task_state, curr_tusec);
	}	

	MTASK_ISSUE(const MTASK_ISSUE & other) noexcept
		: last_usec_time_(other.last_usec_time_), task_state_(other.task_state_)
	{
		if (other.task_state_.issue_string_len_ > 1 && other.task_state_.issue_string_len_ <= sizeof(issue_string_)) {
			std::memcpy(issue_string_, other.issue_string_, other.task_state_.issue_string_len_ - 1);
			issue_string_[other.task_state_.issue_string_len_ - 1] = 0;
		}	
		else {
			*issue_string_ = 0;
		}	
	}	

	MTASK_ISSUE & operator=(const MTASK_ISSUE & other) noexcept
	{
		if (this != &other) {
			last_usec_time_		= other.last_usec_time_;
			task_state_		= other.task_state_;

			if (other.task_state_.issue_string_len_ > 1 && other.task_state_.issue_string_len_ <= sizeof(issue_string_)) {
				std::memcpy(issue_string_, other.issue_string_, other.task_state_.issue_string_len_ - 1);
				issue_string_[other.task_state_.issue_string_len_ - 1] = 0;
			}	
			else {
				*issue_string_ = 0;
			}	
		}

		return *this;
	}	

	static inline bool is_comp_issue(const comm::AGGR_TASK_STATE_NOTIFY & lhs_state, const MTASK_ISSUE & rhs) noexcept
	{
		return ((lhs_state.ntasks_issue_ > rhs.task_state_.ntasks_issue_) || 
				((0 == (rhs.task_state_.severe_issue_bit_hist_ & 0x1)) && (lhs_state.ntasks_issue_ && (lhs_state.severe_issue_bit_hist_ & 0x1))));
	}	

	struct TOP_ISSUE
	{
		bool operator() (const MTASK_ISSUE & lhs, const MTASK_ISSUE & rhs) const noexcept
		{
			return is_comp_issue(lhs.task_state_, rhs);
		}	
	};	

	void set_task_state(const comm::AGGR_TASK_STATE_NOTIFY *ptask, uint64_t curr_tusec = get_usec_time()) noexcept
	{
		task_state_ = *ptask;

		if (ptask->issue_string_len_ > 1 && ptask->issue_string_len_ <= sizeof(issue_string_)) {
			std::memcpy(issue_string_, (const char *)ptask + sizeof(*ptask), ptask->issue_string_len_ - 1);
			issue_string_[ptask->issue_string_len_ - 1] = 0;
		}	
		else {
			*issue_string_ = 0;
		}	

		GY_CC_BARRIER();

		last_usec_time_ = curr_tusec;
	}
		
	// Returns false if no recent update
	bool recent_task_issue(uint64_t curr_tusec, char (&issuebuf)[256], uint8_t & is_severe, int & ntasks_issue, float & total_cpu_pct, int bitmap = 0x3) const noexcept
	{
		pid_t			pid = 0;
		bool			is_issue;

		if ((int64_t)curr_tusec - (int64_t)last_usec_time_ >= (int64_t)GY_USEC_PER_SEC * 8) {
			// Stale data
			return false;
		}	
		
		total_cpu_pct	= task_state_.total_cpu_pct_;

		// By default we just check the last 2 states (0x3) 10 sec
		
		is_issue	= (task_state_.issue_bit_hist_ & bitmap);	
		is_severe	= (task_state_.severe_issue_bit_hist_ & bitmap);	

		ntasks_issue 	= task_state_.ntasks_issue_;

		size_t		len = std::min<size_t>(sizeof(issuebuf) - 1, task_state_.issue_string_len_);	

		if (len > 0) {
			std::memcpy(issuebuf, issue_string_, len);
			issuebuf[len - 1] = 0;
		}

		return is_issue; 
	}

	bool recent_task_issue(uint64_t curr_tusec, int bitmap = 0x3) const noexcept
	{
		if ((int64_t)curr_tusec - (int64_t)last_usec_time_ >= (int64_t)GY_USEC_PER_SEC * 8) {
			// Stale data
			return false;
		}	
		return	(task_state_.issue_bit_hist_ & bitmap);	
	}

	bool recent_task_severe_issue(uint64_t curr_tusec, int bitmap = 0x3) const noexcept
	{
		if ((int64_t)curr_tusec - (int64_t)last_usec_time_ >= (int64_t)GY_USEC_PER_SEC * 8) {
			// Stale data
			return false;
		}	
		return	(task_state_.severe_issue_bit_hist_ & bitmap);	
	}
};	

class MULTI_MTASK_ISSUE : public MULTI_HOST_IDENT, public MTASK_ISSUE
{
public :
	MULTI_MTASK_ISSUE() noexcept		= default;

	MULTI_MTASK_ISSUE(const char *hostname, const char *cluster_name, const char *machine_id_str, const comm::AGGR_TASK_STATE_NOTIFY & task_state, uint64_t curr_tusec = get_usec_time()) noexcept
		: MULTI_HOST_IDENT(hostname, cluster_name, machine_id_str), MTASK_ISSUE(task_state, curr_tusec)
	{}	

	MULTI_MTASK_ISSUE(const char *hostname, const char *cluster_name, const char *machine_id_str, const MTASK_ISSUE & elem) noexcept
		: MULTI_HOST_IDENT(hostname, cluster_name, machine_id_str), MTASK_ISSUE(elem)
	{}	

	MULTI_MTASK_ISSUE(const MULTI_MTASK_ISSUE &) noexcept			= default;
	MULTI_MTASK_ISSUE(MULTI_MTASK_ISSUE &&) noexcept			= default;

	MULTI_MTASK_ISSUE & operator=(const MULTI_MTASK_ISSUE &) noexcept	= default;
	MULTI_MTASK_ISSUE & operator=(MULTI_MTASK_ISSUE &&) noexcept		= default;

	~MULTI_MTASK_ISSUE() noexcept						= default;
};

class MTASK_HIST
{
public :
	using CPU_PCT_HISTOGRAM 		= GY_HISTOGRAM<int, HASH_1_3000>;
	using MSEC_HISTOGRAM 			= GY_HISTOGRAM<int, DURATION_HASH>;
	
	CPU_PCT_HISTOGRAM			cpu_pct_histogram_;
	MSEC_HISTOGRAM				cpu_delay_histogram_;
	MSEC_HISTOGRAM				blkio_delay_histogram_;

	MTASK_HIST(uint64_t curr_tusec) :
		cpu_pct_histogram_(curr_tusec), cpu_delay_histogram_(curr_tusec), blkio_delay_histogram_(curr_tusec)
	{}	
};


class LISTEN_TOPN
{
public :
	comm::LISTENER_STATE_NOTIFY	state_;
	char				comm_[TASK_COMM_LEN];
	IP_PORT				ip_port_;
	uint64_t			tusec_			{0};				
	uint64_t			tusec_start_		{0};				
	bool				is_load_balanced_	{false};	// Possible Load Balanced as per Dependent Listener

	LISTEN_TOPN(const comm::LISTENER_STATE_NOTIFY & state, const char * comm, const NS_IP_PORT & ns_ip_port, uint64_t tusec, uint64_t tusec_start, bool is_load_balanced) noexcept : 
		state_(state), ip_port_(ns_ip_port.ip_port_), tusec_(tusec), tusec_start_(tusec_start), is_load_balanced_(is_load_balanced)
	{
		std::memcpy(comm_, comm, sizeof(comm_));
	}

	LISTEN_TOPN() noexcept					= default;

	LISTEN_TOPN(const LISTEN_TOPN &)			= default;
	LISTEN_TOPN(LISTEN_TOPN &&) noexcept			= default;
	LISTEN_TOPN & operator= (const LISTEN_TOPN &)		= default;
	LISTEN_TOPN & operator= (LISTEN_TOPN &&) noexcept	= default;

	~LISTEN_TOPN() noexcept					= default;

	static inline bool is_comp_issue(const comm::LISTENER_STATE_NOTIFY & lhs_state, const LISTEN_TOPN & rhs) noexcept
	{
		return (lhs_state.curr_state_ > rhs.state_.curr_state_) || (lhs_state.curr_state_ == rhs.state_.curr_state_ && lhs_state.tasks_delay_usec_ > rhs.state_.tasks_delay_usec_);
	}	

	struct TOP_ISSUE
	{
		bool operator() (const LISTEN_TOPN & lhs, const LISTEN_TOPN & rhs) const noexcept
		{
			return is_comp_issue(lhs.state_, rhs);
		}	
	};	
	
	static inline bool is_comp_qps(const comm::LISTENER_STATE_NOTIFY & lhs_state, const LISTEN_TOPN & rhs) noexcept
	{
		return lhs_state.nqrys_5s_ > rhs.state_.nqrys_5s_;
	}	

	struct TOP_QPS
	{
		bool operator() (const LISTEN_TOPN & lhs, const LISTEN_TOPN & rhs) const noexcept
		{
			return is_comp_qps(lhs.state_, rhs);
		}	
	};	

	static inline bool is_comp_active_conn(const comm::LISTENER_STATE_NOTIFY & lhs_state, const LISTEN_TOPN & rhs) noexcept
	{
		return lhs_state.nconns_active_ > rhs.state_.nconns_active_;
	}	

	struct TOP_ACTIVE_CONN
	{
		bool operator() (const LISTEN_TOPN & lhs, const LISTEN_TOPN & rhs) const noexcept
		{
			return is_comp_active_conn(lhs.state_, rhs);
		}	
	};	

	static inline bool is_comp_net(const comm::LISTENER_STATE_NOTIFY & lhs_state, const LISTEN_TOPN & rhs) noexcept
	{
		return (lhs_state.curr_kbytes_inbound_ + lhs_state.curr_kbytes_outbound_) > (rhs.state_.curr_kbytes_inbound_ + rhs.state_.curr_kbytes_outbound_);
	}	

	struct TOP_NET
	{
		bool operator() (const LISTEN_TOPN & lhs, const LISTEN_TOPN & rhs) const noexcept
		{
			return is_comp_net(lhs.state_, rhs);
		}	
	};	
};	

class LISTEN_MULTI_TOPN : public MULTI_HOST_IDENT, public LISTEN_TOPN
{
public :
	LISTEN_MULTI_TOPN(const char *hostname, const char *cluster_name, const char *machine_id_str, const comm::LISTENER_STATE_NOTIFY & state, const char * comm, const NS_IP_PORT & ns_ip_port, uint64_t tusec, uint64_t tusec_start, bool is_load_balanced) noexcept
		: MULTI_HOST_IDENT(hostname, cluster_name, machine_id_str), LISTEN_TOPN(state, comm, ns_ip_port, tusec, tusec_start, is_load_balanced)
	{}	

	LISTEN_MULTI_TOPN(const char *hostname, const char *cluster_name, const char *machine_id_str, const LISTEN_TOPN & elem) noexcept
		: MULTI_HOST_IDENT(hostname, cluster_name, machine_id_str), LISTEN_TOPN(elem)
	{}	
		
	LISTEN_MULTI_TOPN() noexcept					= default;

	LISTEN_MULTI_TOPN(const LISTEN_MULTI_TOPN &)			= default;
	LISTEN_MULTI_TOPN(LISTEN_MULTI_TOPN &&) noexcept		= default;
	LISTEN_MULTI_TOPN & operator= (const LISTEN_MULTI_TOPN &)	= default;
	LISTEN_MULTI_TOPN & operator= (LISTEN_MULTI_TOPN &&) noexcept	= default;

	~LISTEN_MULTI_TOPN() noexcept					= default;
};	

class NOTIFY_MSG_ONE
{
public :
	GY_MACHINE_ID			machid_;
	time_t				tmsg_			{0};
	NOTIFY_MSGTYPE_E		type_			{NOTIFY_INFO};
	STR_ARRAY<512>			msgbuf_;

	NOTIFY_MSG_ONE(NOTIFY_MSGTYPE_E type, const char * pmsg, uint16_t msglen, time_t tmsg = time(nullptr), GY_MACHINE_ID machid = {}) noexcept
		: machid_(machid), tmsg_(tmsg), type_(type), msgbuf_(pmsg, msglen)
	{}	

	struct ORDER_NOTIFY
	{
		bool operator() (const NOTIFY_MSG_ONE & lhs, const NOTIFY_MSG_ONE & rhs) const noexcept
		{
			return lhs.tmsg_ > rhs.tmsg_;
		}	
	};	
};	

template <typename T = int>
class LISTEN_SUMM_STATS
{
public :	
	T			nstates_[OBJ_STATE_E::STATE_DOWN + 1] 	{};
	T			tot_qps_		{0};
	T			tot_act_conn_		{0};
	T			tot_kb_inbound_		{0};
	T			tot_kb_outbound_	{0};
	T			tot_ser_errors_		{0};
	T			nlisteners_		{0};
	T			nactive_		{0};

	void update(const comm::LISTENER_STATE_NOTIFY & state) noexcept
	{
		nstates_[state.curr_state_]++;
		tot_qps_ 		+= state.nqrys_5s_/5;
		tot_act_conn_		+= state.nconns_active_;
		tot_kb_inbound_		+= state.curr_kbytes_inbound_;
		tot_kb_outbound_	+= state.curr_kbytes_outbound_;
		tot_ser_errors_		+= state.ser_errors_;

		nlisteners_++;
		nactive_		+= !!state.nqrys_5s_;
	}	

	template <typename F>
	void update(const LISTEN_SUMM_STATS<F> & stats) noexcept
	{
		for (uint32_t i = 0; i < GY_ARRAY_SIZE(nstates_); ++i) {
			nstates_[i] 	+= stats.nstates_[i];
		}	
		tot_qps_ 		+= stats.tot_qps_;
		tot_act_conn_		+= stats.tot_act_conn_;
		tot_kb_inbound_		+= stats.tot_kb_inbound_;
		tot_kb_outbound_	+= stats.tot_kb_outbound_;
		tot_ser_errors_		+= stats.tot_ser_errors_;

		nlisteners_		+= stats.nlisteners_;
		nactive_		+= stats.nactive_;
	}	
};	


template <class ParthaInfo, class MadhavaInfo, class ShyamaInfo, class WeakRemoteMadhavaTbl>
class MSOCKET_HDLR_T
{
public :
	class MTCP_LISTENER;
	class MRELATED_LISTENER;
	class MAGGR_LISTENER;
	class MAGGR_TASK;

	class MWEAK_LISTEN_ID
	{
	public :	
		RCU_HASH_CLASS_MEMBERS(uint64_t, MWEAK_LISTEN_ID);

		gy_atomic<int>				ntimes_		{1};
		std::weak_ptr<MTCP_LISTENER>		weaklisten_;
		uint64_t				glob_id_	{0};

		MWEAK_LISTEN_ID() noexcept		= default;
		
		MWEAK_LISTEN_ID(std::weak_ptr<MTCP_LISTENER> weakp, uint64_t glob_id) noexcept 
			: weaklisten_(std::move(weakp)), glob_id_(glob_id)
		{}
		
		friend inline bool operator== (const MWEAK_LISTEN_ID & lhs, uint64_t glob_id) noexcept
		{
			return lhs.glob_id_ == glob_id;
		}
	};	

	using MWEAK_LISTEN_TABLE			= RCU_HASH_TABLE <uint64_t /* glob_id_ */, MWEAK_LISTEN_ID>;


	class MAGGR_TASK : public std::enable_shared_from_this<MAGGR_TASK>
	{
	public :	
		const uint64_t				aggr_task_id_;
		uint64_t				last_tusec_;
		gy_atomic<int>				ntasks_			{1};
		
		MTASK_ISSUE				task_issue_;

		uid_t					uid_;
		gid_t					gid_;

		union {
			uint8_t				flags_			{0};

			struct {
				uint8_t			is_high_cap_ : 1;
				uint8_t			is_cpu_cgroup_throttled_ : 1;
				uint8_t			is_mem_cgroup_limited_ : 1;
				uint8_t			is_rt_proc_ : 1;
				uint8_t			is_container_proc_ : 1;
			};
		};

		bool					is_remote_task_		{false};
		uint8_t					comm_len_		{0};

		std::unique_ptr<MTASK_HIST>		task_hist_;
		std::unique_ptr<MWEAK_LISTEN_TABLE>	cli_listener_tbl_;	// Listener Table for connect tasks for listeners handled by local Madhava
		folly::MicroLock			uniqlock_;		// MicroLock for task_hist_, cli_listener_tbl_, remote_listener_tbl_ construction
		std::unique_ptr<MWEAK_LISTEN_TABLE>	remote_listener_tbl_;	// Remote Listener Table for connect tasks handled by Remote Madhava

		gy_atomic<int>				tcp_cli_in_use_		{0};
		
		gy_atomic<uint8_t>			cmdline_len_		{0};	
		SSO_STRING<80>				cmdline_;
		char					comm_[TASK_COMM_LEN]	{};
	
		uint64_t				related_listen_id_	{0};	// We do not store refs to the MRELATED_LISTENER as we maintain a separate listener_table_
		
		comm::AGGR_TASK_HIST_STATS		histstats_;

		char					tagbuf_[63]		{};
		uint8_t					tag_len_		{0};

		std::weak_ptr <ParthaInfo>		partha_weak_;
		GY_MACHINE_ID				partha_machine_id_;

		std::weak_ptr <MadhavaInfo>		madhava_weak_;
		uint64_t				madhava_id_		{0};

		static_assert(comm::MAX_PROC_CMDLINE_LEN <= 256, "Please change cmdline_len_ to uint16_t");

		MAGGR_TASK(uint64_t aggr_task_id, const char *comm, const char * cmdline, std::weak_ptr <ParthaInfo> partha_weak, GY_MACHINE_ID partha_machine_id, \
			std::weak_ptr <MadhavaInfo> madhava_weak, uint64_t madhava_id, uint32_t cmdline_len, uint64_t related_listen_id, 
			const char *tagbuf, uint8_t taglen, uint64_t curr_tusec = get_usec_time()) 
			: aggr_task_id_(aggr_task_id), last_tusec_(curr_tusec), cmdline_len_(cmdline_len > 1 ? cmdline_len - 1 : 0), cmdline_(cmdline, cmdline_len_), 
			related_listen_id_(related_listen_id), partha_weak_(std::move(partha_weak)), partha_machine_id_(partha_machine_id), 
			madhava_weak_(std::move(madhava_weak)), madhava_id_(madhava_id)
		{
			GY_STRNCPY(comm_, comm, sizeof(comm_));
			comm_len_ = strlen(comm_);

			if (taglen > 1 && taglen <= sizeof(tagbuf_)) {
				tag_len_ = taglen - 1;

				std::memcpy(tagbuf_, tagbuf, tag_len_);
				tagbuf_[tag_len_] = 0;

				if (tagbuf_[tag_len_ - 1] == 0) {
					tag_len_--;
				}	
			}

			uniqlock_.init();

			histstats_.starttimeusec_	= curr_tusec;
		}	

		/*
		 * Remote Madhava Handled Task placeholder
		 */
		MAGGR_TASK(uint64_t aggr_task_id, const char *comm, const char * cmdline, GY_MACHINE_ID remote_partha_machine_id, \
			std::weak_ptr <MadhavaInfo> madhava_weak, uint64_t madhava_id, uint32_t cmdline_len, uint64_t curr_tusec = get_usec_time()) 
			: aggr_task_id_(aggr_task_id), last_tusec_(curr_tusec), is_remote_task_(true), cmdline_len_(cmdline_len > 1 ? cmdline_len - 1 : 0), cmdline_(cmdline, cmdline_len_),
			partha_machine_id_(remote_partha_machine_id), madhava_weak_(std::move(madhava_weak)), madhava_id_(madhava_id)
		{
			GY_STRNCPY(comm_, comm, sizeof(comm_));
			comm_len_ = strlen(comm_);
			uniqlock_.init();
		}	

		void set_local_task_state(const comm::AGGR_TASK_STATE_NOTIFY *ptask, uint64_t curr_tusec = get_usec_time()) noexcept
		{
			task_issue_.set_task_state(ptask, curr_tusec);

			if (task_hist_) {
				task_hist_->cpu_pct_histogram_.add_data((int)ptask->total_cpu_pct_, curr_tusec);
				task_hist_->cpu_delay_histogram_.add_data(ptask->cpu_delay_msec_, curr_tusec);
				task_hist_->blkio_delay_histogram_.add_data(ptask->blkio_delay_msec_, curr_tusec);
			}	
		}

		void init_task_hist(uint64_t curr_tusec = get_usec_time()) 
		{
			auto		phist = task_hist_.get();

			if (nullptr == phist) {
				auto pl = std::make_unique<MTASK_HIST>(curr_tusec);

				uniqlock_.lock(2);

				if (nullptr == task_hist_.get()) {
					task_hist_.swap(pl);
				}
				uniqlock_.unlock(2);
			}
		}	

		MWEAK_LISTEN_TABLE * get_cli_listener_table() 
		{
			auto		plisten = cli_listener_tbl_.get();

			if (nullptr == plisten) {
				auto pl = std::make_unique<MWEAK_LISTEN_TABLE>(8, 8, 1024, true, false);

				uniqlock_.lock(0);

				if (nullptr == cli_listener_tbl_.get()) {
					cli_listener_tbl_.swap(pl);
				}
				uniqlock_.unlock(0);

				plisten = cli_listener_tbl_.get();
			}

			return plisten;
		}	

		MWEAK_LISTEN_TABLE * get_remote_listener_table() 
		{
			auto		plisten = remote_listener_tbl_.get();

			if (nullptr == remote_listener_tbl_.get()) {
				auto pl = std::make_unique<MWEAK_LISTEN_TABLE>(8, 8, 1024, true, false);

				uniqlock_.lock(1);

				if (nullptr == remote_listener_tbl_.get()) {
					remote_listener_tbl_.swap(pl);
				}
				uniqlock_.unlock(1);

				plisten = remote_listener_tbl_.get();
			}

			return plisten;
		}	

		friend bool operator== (const std::shared_ptr<MAGGR_TASK> &lhs, uint64_t id) noexcept
		{
			return (lhs && ((*lhs).aggr_task_id_ == id));
		}
	};	

	// Use Pool Allocated Element
	using MAGGR_TASK_ELEM_TYPE		= RCU_HASH_WRAPPER<uint64_t, std::shared_ptr<MAGGR_TASK>>;
	using MAGGR_TASK_HASH_TABLE		= RCU_HASH_TABLE <uint64_t, MAGGR_TASK_ELEM_TYPE, TPOOL_DEALLOC<MAGGR_TASK_ELEM_TYPE>>;


	class MAGGR_TASK_WEAK
	{
	public :	
		RCU_HASH_CLASS_MEMBERS(uint64_t, MAGGR_TASK_WEAK);

		gy_atomic<int>			ntimes_			{1};
		std::weak_ptr<MAGGR_TASK>	task_weak_;
		uint64_t			aggr_task_id_		{0};

		MAGGR_TASK_WEAK() noexcept 				= default;

		MAGGR_TASK_WEAK(std::weak_ptr<MAGGR_TASK> task_weak, uint64_t aggr_task_id) noexcept
			: task_weak_(std::move(task_weak)), aggr_task_id_(aggr_task_id)
		{}	
	
		friend inline bool operator== (const MAGGR_TASK_WEAK & lhs, uint64_t id) noexcept
		{
			return (lhs.aggr_task_id_ == id);
		}
	};	

	// Use Pool Allocated Element
	using 	MWEAK_AGGR_TASK_TABLE 		= RCU_HASH_TABLE <uint64_t, MAGGR_TASK_WEAK, TPOOL_DEALLOC<MAGGR_TASK_WEAK>>;

	class MTCP_CONN
	{
	public :	
		RCU_HASH_CLASS_MEMBERS(PAIR_IP_PORT, MTCP_CONN);
		
		IP_PORT					cli_;
		IP_PORT					ser_;
		
		IP_PORT					cli_nat_cli_;			// Client Host Side NAT and Key to the class
		IP_PORT					cli_nat_ser_;

		std::shared_ptr <ParthaInfo>		cli_shr_host_;

		uint64_t				cli_task_aggr_id_		{0};
		uint64_t				cli_related_listen_id_		{0};
		SSO_STRING<108>				cli_cmdline_;
		char					cli_comm_[TASK_COMM_LEN]	{};

		pid_t					cli_pid_			{0};
		pid_t					ser_pid_			{0};
		
		uint64_t				cli_ser_cluster_hash_		{0};

		IP_PORT					ser_nat_cli_;			// Server Host Side NAT
		IP_PORT					ser_nat_ser_;

		uint64_t				ser_glob_id_			{0};
		std::shared_ptr <MTCP_LISTENER>		ser_listen_shr_;
		uint64_t				ser_tusec_pstart_		{0};
		uint64_t				ser_nat_conn_hash_		{0};
		uint32_t				ser_conn_hash_			{0};
		uint32_t				ser_sock_inode_			{0};
		char					ser_comm_[TASK_COMM_LEN]	{};

		uint64_t				close_cli_bytes_sent_		{0};		// Will be non-zero only for closed conns
		uint64_t				close_cli_bytes_rcvd_		{0};

		uint64_t				tusec_mstart_			{0};

		MTCP_CONN() 						= default;
	
		MTCP_CONN(const MTCP_CONN & other)			= default;
		MTCP_CONN(MTCP_CONN && other)	noexcept		= default;

		MTCP_CONN & operator= (const MTCP_CONN & other) 	= default;
		MTCP_CONN & operator= (MTCP_CONN && other) noexcept	= default;

		~MTCP_CONN() noexcept					= default;

		bool is_server_updated() const noexcept
		{
			return (0 != ser_glob_id_);
		}	

		bool is_conn_closed() const noexcept
		{
			return close_cli_bytes_sent_ + close_cli_bytes_rcvd_ > 0;
		}

		void set_notify_elem(comm::MS_TCP_CONN_NOTIFY *pnot) const noexcept
		{
			using namespace			comm;

			
			pnot->cli_			= cli_;
			pnot->ser_			= ser_;

			pnot->cli_ser_cluster_hash_	= cli_ser_cluster_hash_;	 

			pnot->close_cli_bytes_sent_	= close_cli_bytes_sent_;
			pnot->close_cli_bytes_rcvd_	= close_cli_bytes_rcvd_;
			pnot->tusec_mstart_		= tusec_mstart_;

			if (false == is_server_updated()) {
				pnot->nat_cli_			= cli_nat_cli_;
				pnot->nat_ser_			= cli_nat_ser_;
				
				pnot->cli_task_aggr_id_		= cli_task_aggr_id_;
				pnot->cli_related_listen_id_	= cli_related_listen_id_;
				pnot->ser_glob_id_		= 0;
				pnot->ser_tusec_pstart_		= 0;
				pnot->ser_related_listen_id_	= 0;
				pnot->ser_nat_conn_hash_	= 0;
				pnot->ser_conn_hash_		= 0;
				pnot->ser_sock_inode_		= 0;

				if (cli_shr_host_) {
					pnot->cli_ser_partha_machine_id_ 	= cli_shr_host_->machine_id_;
				}

				std::memcpy(pnot->cli_ser_comm_, cli_comm_, sizeof(pnot->cli_ser_comm_));

				pnot->cli_ser_cmdline_len_	= std::min(sizeof(pnot->cli_ser_cmdline_trunc_) - 1, cli_cmdline_.size()) + 1;

				std::memcpy(pnot->cli_ser_cmdline_trunc_, cli_cmdline_.data(), pnot->cli_ser_cmdline_len_ - 1);
				pnot->cli_ser_cmdline_trunc_[pnot->cli_ser_cmdline_len_ - 1] = 0;
			}
			else {
				pnot->nat_cli_			= ser_nat_cli_;
				pnot->nat_ser_			= ser_nat_ser_;
				
				pnot->cli_task_aggr_id_		= 0;
				pnot->cli_related_listen_id_	= 0;

				pnot->ser_glob_id_		= ser_glob_id_;
				pnot->ser_tusec_pstart_		= ser_tusec_pstart_;
				pnot->ser_nat_conn_hash_	= ser_nat_conn_hash_;
				pnot->ser_conn_hash_		= ser_conn_hash_;
				pnot->ser_sock_inode_		= ser_sock_inode_;

				std::memcpy(pnot->cli_ser_comm_, ser_comm_, sizeof(pnot->cli_ser_comm_));

				if (ser_listen_shr_) {
					if (ser_listen_shr_->parthashr_) {
						pnot->cli_ser_partha_machine_id_ 	= ser_listen_shr_->parthashr_->machine_id_;
					}

					pnot->ser_related_listen_id_	= ser_listen_shr_->related_listen_id_;
					pnot->cli_ser_cmdline_len_	= strnlen(ser_listen_shr_->cmdline_, sizeof(pnot->cli_ser_cmdline_len_) - 1) + 1;

					std::memcpy(pnot->cli_ser_cmdline_trunc_, ser_listen_shr_->cmdline_, pnot->cli_ser_cmdline_len_ - 1);
					pnot->cli_ser_cmdline_trunc_[pnot->cli_ser_cmdline_len_ - 1] = 0;

				}
				else {
					pnot->ser_related_listen_id_	= 0;
					pnot->cli_ser_cmdline_len_	= 0;
				}	
			}
		}

		friend inline bool operator== (const MTCP_CONN & lhs, const PAIR_IP_PORT & tup) noexcept
		{
			return (lhs.cli_nat_cli_ == tup.cli_) && (lhs.cli_nat_ser_ == tup.ser_);
		}
	};	

	// Use Pool Allocated Element
	using MTCP_CONN_HASH_TABLE 		= RCU_HASH_TABLE <PAIR_IP_PORT, MTCP_CONN, TPOOL_DEALLOC<MTCP_CONN>>;

	class MREQ_TRACE_SVC
	{
	public :
		uint64_t				glob_id_		{0};
		uint64_t				nrequests_		{0};
		uint64_t				nerrors_		{0};
		time_t					tlaststat_		{0};
		time_t					tstart_			{0};
		time_t					tend_			{0};
		uint32_t				curr_trace_defid_	{0};
		gy_atomic<PROTO_TYPES>			api_proto_		{PROTO_UNKNOWN};
		gy_atomic<PROTO_CAP_STATUS_E>		api_cap_status_		{CAPSTAT_STOPPED};
		gy_atomic<bool>				api_is_ssl_		{false};
		
		MREQ_TRACE_SVC(uint64_t glob_id) noexcept : glob_id_(glob_id)
		{}	

		void reset_restart() noexcept
		{
			tlaststat_ = 0;
			tstart_ = 0;
			tend_ = 0;

			api_cap_status_.store(CAPSTAT_STOPPED, mo_relaxed);
		}	
	};


	using MRELATED_LISTENER_ELEM_TYPE	= RCU_HASH_WRAPPER <uint64_t, std::shared_ptr<MRELATED_LISTENER>>;
	using MRELATED_LISTENER_HASH_TABLE	= RCU_HASH_TABLE <uint64_t, MRELATED_LISTENER_ELEM_TYPE>;

	class MTCP_LISTENER : public std::enable_shared_from_this <MTCP_LISTENER>
	{
	public :	
		static constexpr size_t				MAX_NAT_IP_ELEM				{2};

		NS_IP_PORT					ns_ip_port_;
		
		uint64_t					tusec_start_				{get_usec_time()};
		uint64_t					cusec_start_				{get_usec_clock()};

		uint64_t					glob_id_				{0};
		uint64_t					aggr_glob_id_				{0};
		uint64_t					related_listen_id_			{0};

		gy_atomic<uint64_t>				ser_aggr_task_id_			{0};
		std::weak_ptr<MAGGR_TASK>			ser_task_weak_;

		char						comm_[TASK_COMM_LEN]			{};
		char						cmdline_[comm::MAX_PROC_CMDLINE_LEN];
	
		gy_atomic<uint64_t>				last_state_tusec_			{tusec_start_};
		comm::LISTENER_STATE_NOTIFY			state_;
		char						issue_string_[256];

		uint64_t					rem_madhava_ping_tusec_ 		{tusec_start_};	

		uint64_t					last_day_stats_tusec_			{0};
		comm::LISTENER_DAY_STATS			day_stats_				{};
		char						server_domain_[MAX_DOMAINNAME_SIZE];

		IP_PORT						nat_ip_port_arr_[MAX_NAT_IP_ELEM];
		int64_t						last_nat_chg_ip_tsec_			{0};
		
		uint64_t					last_svcinfo_chg_tusec_			{tusec_start_};

		std::shared_ptr <ParthaInfo>			parthashr_;
		GY_MACHINE_ID					partha_machine_id_;
		uint64_t					madhava_id_				{0};
		std::weak_ptr <MadhavaInfo>			madhava_weak_;

		gy_atomic<uint64_t>				eff_mesh_cluster_id_			{0};
		time_t						tlast_mesh_upd_				{0};
		uint32_t					ntotal_mesh_svc_			{0};
		bool						is_cluster_mesh_			{false};
		bool						is_cluster_nat_ip_[MAX_NAT_IP_ELEM]	{};
		gy_atomic<uint64_t>				nat_ip_cluster_id_[MAX_NAT_IP_ELEM]	{};
		uint32_t					ntotal_nat_ip_svc_[MAX_NAT_IP_ELEM]	{};

		folly::atomic_shared_ptr<MRELATED_LISTENER>	related_listen_shr_;

		std::weak_ptr<MAGGR_LISTENER>			aggr_weak_;
		
		std::optional<MWEAK_AGGR_TASK_TABLE>		cli_aggr_task_tbl_;
		std::optional<WeakRemoteMadhavaTbl>		remote_madhava_tbl_;		

		MRELATED_LISTENER_HASH_TABLE			depending_related_tbl_			{8, 8, 1024, true, false};	// Valid both for local and remote MTCP_LISTENER  
		
		std::shared_ptr<MREQ_TRACE_SVC>			rtraceshr_;

		uint8_t						comm_len_				{0};
		uint8_t						cmdline_len_				{0};
		uint8_t						domain_string_len_			{0};
		bool						is_remote_madhava_			{false};
		bool						is_any_ip_				{false};
		bool						is_load_balanced_			{false};	// Possible Load Balanced as per Dependent Listener

		MTCP_LISTENER()
		{
			*issue_string_ = 0;
		}	

		MTCP_LISTENER(const NS_IP_PORT & ns_ip_port, bool is_any_ip, uint64_t glob_id, uint64_t aggr_glob_id, \
				std::shared_ptr <ParthaInfo> parthashr, const GY_MACHINE_ID & partha_machine_id, uint64_t madhava_id, \
				std::weak_ptr<MadhavaInfo> madhava_weak, const char *comm, const char *cmdline, uint32_t cmdline_len = 0)

			: ns_ip_port_(ns_ip_port), glob_id_(glob_id), aggr_glob_id_(aggr_glob_id), parthashr_(std::move(parthashr)),
			partha_machine_id_(partha_machine_id), madhava_id_(madhava_id), madhava_weak_(std::move(madhava_weak)), 
			cli_aggr_task_tbl_(std::in_place, 8, 8, 1024, true, false),
			remote_madhava_tbl_(std::in_place, 8, 8, 1024, true, false), rtraceshr_(std::make_shared<MREQ_TRACE_SVC>(glob_id)), 
			is_any_ip_(is_any_ip)
		{
			comm_len_ = GY_STRNCPY_LEN(comm_, comm, sizeof(comm_));
			
			*cmdline_ = 0;

			if (cmdline_len > 1 && cmdline_len <= sizeof(cmdline_)) {
				cmdline_len_ = cmdline_len - 1;

				std::memcpy(cmdline_, cmdline, cmdline_len_);
				cmdline_[cmdline_len_] = 0;
			}	
		
			*issue_string_ = 0;
			*server_domain_ = 0;
		}	

		/*
		 * Remote Madhava Handled Listener placeholder
		 */
		MTCP_LISTENER(const IP_PORT & remote_ip_port, uint64_t glob_id, GY_MACHINE_ID remote_partha_machine_id, \
			uint64_t remote_madhava_id, std::weak_ptr<MadhavaInfo> madhava_weak, const char *comm, const char *cmdline, uint32_t cmdline_len)
			: ns_ip_port_(remote_ip_port, 0), glob_id_(glob_id), partha_machine_id_(remote_partha_machine_id),
			madhava_id_(remote_madhava_id), madhava_weak_(std::move(madhava_weak)), is_remote_madhava_(true)
		{
			comm_len_ = GY_STRNCPY_LEN(comm_, comm, sizeof(comm_));
		
			*cmdline_ = 0;

			if (cmdline_len > 1 && cmdline_len <= sizeof(cmdline_)) {
				cmdline_len_ = cmdline_len - 1;

				std::memcpy(cmdline_, cmdline, cmdline_len_);
				cmdline_[cmdline_len_] = 0;
			}	

			*issue_string_ = 0;
			*server_domain_ = 0;
		}	

		MTCP_LISTENER(const MTCP_LISTENER & other)			= default;
		MTCP_LISTENER(MTCP_LISTENER && other)	noexcept		= default;

		MTCP_LISTENER & operator= (const MTCP_LISTENER & other) 	= default;
		MTCP_LISTENER & operator= (MTCP_LISTENER && other) noexcept	= default;

		~MTCP_LISTENER() noexcept					= default;

		void set_state(const comm::LISTENER_STATE_NOTIFY *pnot, uint64_t curr_tusec = get_usec_time()) noexcept
		{
			state_ 		= *pnot;
			
			if (pnot->issue_string_len_ > 0) {
				std::memcpy(issue_string_, (const char *)(pnot + 1), (pnot->issue_string_len_ - 1) & 0xFF);
				issue_string_[pnot->issue_string_len_ - 1] = 0;
			}	

			// Set the related listener state
			if (false == is_remote_madhava_) {
				auto relshr = related_listen_shr_.load(mo_relaxed);

				if (relshr) {
					auto lastt = relshr->updated_tusec_.load(mo_relaxed);

					if (lastt < curr_tusec - 3 * GY_USEC_PER_SEC) {
						relshr->any_state_ok_bad_ = false;
					}

					relshr->any_state_ok_bad_ |= (pnot->curr_state_ >= STATE_OK);
					relshr->updated_tusec_.store(curr_tusec, mo_relaxed);
				}
			}	

			last_state_tusec_.store(curr_tusec, mo_release);
		}	

		const char * print_string(STR_WR_BUF & strbuf) const noexcept 
		{
			strbuf.appendconst("TCP Listener : ");
			ns_ip_port_.ip_port_.print_string(strbuf);
			
			strbuf.appendfmt("ID %016lx Comm \'%s\'", glob_id_, comm_);

			if (is_remote_madhava_ == false) {
				if (parthashr_) {
					strbuf.appendfmt(" from Partha \'%s\'", parthashr_->hostname_);
				}	
			}
			else {
				strbuf.appendfmt(" : Remote Partha %016lx%016lx : Madhava ID %016lx", 
					partha_machine_id_.machid_.first, partha_machine_id_.machid_.second, madhava_id_);
			}	

			return strbuf.buffer();
		}	

		PROTO_CAP_STATUS_E get_trace_cap_status(std::memory_order order = mo_relaxed) const noexcept
		{
			if (rtraceshr_) {
				return rtraceshr_->api_cap_status_.load(order);
			}	

			return CAPSTAT_STOPPED;
		}	

		friend inline bool operator== (const std::shared_ptr<MTCP_LISTENER> &lhs, const uint64_t glob_id) noexcept
		{
			auto 			pdata = lhs.get();
		
			return (pdata && pdata->glob_id_ == glob_id);
		}

		friend inline bool operator== (const std::shared_ptr<MTCP_LISTENER> &lhs, const IP_PORT & ip_port) noexcept
		{
			auto 			pdata = lhs.get();
		
			return (pdata && (pdata->ns_ip_port_.ip_port_.port_ == ip_port.port_) && 
				(pdata->is_any_ip_ || (pdata->ns_ip_port_.ip_port_.ipaddr_ == ip_port.ipaddr_)));
		}
	};	

	using MTCP_LISTENER_ELEM_TYPE		= RCU_HASH_WRAPPER<uint64_t /* glob_id_ */, std::shared_ptr<MTCP_LISTENER>>;
	using MTCP_LISTENER_HASH_TABLE		= RCU_HASH_TABLE <uint64_t /* glob_id_ */, MTCP_LISTENER_ELEM_TYPE>;

	class MRELATED_LISTENER : public std::enable_shared_from_this <MRELATED_LISTENER>
	{
	public :	
		uint64_t				related_listen_id_		{0};		// Partha specific, not global
		MTCP_LISTENER_HASH_TABLE		listener_table_			{8, 8, 1024, true, false};	
		MTCP_LISTENER_HASH_TABLE		depended_id_tbl_		{8, 8, 1024, true, false};

		/*
		 * We currently do not use the depended_ipport_tbl_ . Uncomment this if needed
		 */
		/*MIP_PORT_TBL				depended_ipport_tbl_		{1, 1, 512, true, false};*/

		uint64_t				last_aggr_task_id_		{0};
		LISTENER_ISSUE_RESOL			issue_resol_;
		char					init_comm_[TASK_COMM_LEN]	{};
		uint64_t				svc_mesh_cluster_id_		{0};

		char					tagbuf_[63]			{};
		uint8_t					tag_len_			{0};

		gy_atomic<uint64_t>			updated_tusec_			{0};
		bool					any_state_ok_bad_		{false};

		bool					is_cluster_listen_		{false};
		bool					is_cluster_mesh_		{false};
		bool					is_cluster_service_ip_		{false};
		bool					has_service_ip_			{false};

		MRELATED_LISTENER(uint64_t related_listen_id, const char *comm) : related_listen_id_(related_listen_id)
		{
			GY_STRNCPY(init_comm_, comm, sizeof(init_comm_));
		}	

		const char * print_string(STR_WR_BUF & strbuf) const noexcept 
		{
			strbuf.appendfmt("Related TCP Listener ID 0x%016lx based on Listener \'%s\' : ", related_listen_id_, init_comm_);

			return strbuf.buffer();
		}	

		static uint32_t new_cluster_id(uint64_t madhava_id) noexcept
		{
			std::tuple<uint64_t, uint64_t, uint64_t>	t {get_nsec_time(), gy_gettid(), madhava_id};

			return GY_JHASHER<decltype(t), true>()(t);
		}	

		friend inline bool operator== (const std::shared_ptr<MRELATED_LISTENER> &lhs, const uint64_t id) noexcept
		{
			auto 			pdata = lhs.get();
		
			return (pdata && pdata->related_listen_id_ == id); 
		}
	};	


	/*
	 * Currently not in use
	 */
	class MAGGR_LISTENER : public std::enable_shared_from_this <MAGGR_LISTENER>
	{
	public :
		IP_PORT				ip_port_;
		uint64_t			aggr_glob_id_		{0};
		bool				is_any_ip_		{false};
		
		char				comm_[TASK_COMM_LEN]	{};
		char				cmdline_[comm::MAX_PROC_CMDLINE_LEN];

		MWEAK_LISTEN_TABLE		listen_tbl_		{1, 1, 1024, true, false};

		/*uint64_t			last_stats_tusec_	{0};*/
		/*comm::LISTENER_DAY_STATS	day_stats_		{};*/

		MAGGR_LISTENER(const IP_PORT & ip_port, uint64_t aggr_glob_id, bool is_any_ip, const char *comm, const char *cmdline, uint32_t cmdline_len = 0)
			: ip_port_(ip_port), aggr_glob_id_(aggr_glob_id), is_any_ip_(is_any_ip)
		{
			GY_STRNCPY(comm_, comm, sizeof(comm_));

			if (cmdline_len) {
				cmdline_len = std::min(cmdline_len, (uint32_t)sizeof(cmdline_) - 1);
				std::memcpy(cmdline_, cmdline, cmdline_len);
				std::memset(cmdline_ + cmdline_len, 0, sizeof(cmdline_) - cmdline_len);
			}
			else {
				GY_STRNCPY_0(cmdline_, cmdline, sizeof(cmdline_));
			}	
		}

		MAGGR_LISTENER() 		= default;

		const char * print_string(STR_WR_BUF & strbuf) const noexcept 
		{
			strbuf.appendconst("Aggregated TCP Listener : ");
			strbuf.appendfmt("ID %016lx : Comm \'%s\' : ", aggr_glob_id_, comm_);

			ip_port_.print_string(strbuf);

			return strbuf.buffer();
		}	

		friend inline bool operator== (const std::shared_ptr<MAGGR_LISTENER> & lhs, const uint64_t id) noexcept
		{
			auto 			pdata = lhs.get();

			return pdata && pdata->aggr_glob_id_ == id;
		}
	};
	
	using MAGGR_LISTENER_ELEM_TYPE		= RCU_HASH_WRAPPER<uint64_t, std::shared_ptr<MAGGR_LISTENER>>;
	using MAGGR_LISTENER_HASH_TABLE		= RCU_HASH_TABLE <uint64_t, MAGGR_LISTENER_ELEM_TYPE>;

};

} // namespace madhava
} // namespace gyeeta

