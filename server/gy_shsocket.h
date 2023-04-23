//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"
#include			"gy_inet_inc.h"
#include			"gy_pool_alloc.h"
#include			"gy_comm_proto.h"

#include 			"folly/SharedMutex.h"

using folly::SharedMutex;

namespace gyeeta {
namespace shyama {

class RelClusterElem
{
public :
	time_t				tlast_upd_			{0};
	char				init_comm_[TASK_COMM_LEN]	{};

	RelClusterElem(const char * init_comm, time_t tcurr) noexcept
		: tlast_upd_(tcurr)
	{
		GY_STRNCPY(init_comm_, init_comm, sizeof(init_comm_));
	}	
};	

class SvcClusterMeshOne
{
public :
	using RelClusterElemTbl		= std::unordered_map<comm::RELSVC_CLUSTER_ONE, RelClusterElem, comm::RELSVC_CLUSTER_ONE::RHash>;

	RCU_HASH_CLASS_MEMBERS(uint64_t, SvcClusterMeshOne);

	GY_MUTEX			elemmutex_;
	RelClusterElemTbl		elemtbl_;

	uint64_t			svc_cluster_id_				{0};
	uint64_t			eff_cluster_id_				{0};
	time_t				tstart_					{0};
	gy_atomic<time_t>		tlast_upd_				{0};
	char				cluster_name_[comm::MAX_CLUSTER_NAME_LEN];
	char				init_comm_[TASK_COMM_LEN];

	SvcClusterMeshOne(uint64_t svc_cluster_id, const char * cluster_name, const char * init_comm, time_t tcurr)
		: svc_cluster_id_(svc_cluster_id), tstart_(tcurr), tlast_upd_(tcurr)
	{
		GY_STRNCPY_0(cluster_name_, cluster_name, sizeof(cluster_name_));
		GY_STRNCPY_0(init_comm_, init_comm, sizeof(init_comm_));
	}	

	SvcClusterMeshOne() noexcept 						= default;
	~SvcClusterMeshOne() noexcept						= default;

	friend inline bool operator== (const SvcClusterMeshOne & lhs, uint64_t svc_cluster_id) noexcept
	{
		return lhs.svc_cluster_id_ == svc_cluster_id;
	}

};	

using 	SvcClusterMeshTbl 		= RCU_HASH_TABLE <uint64_t, SvcClusterMeshOne>;

struct ClusterMeshStat
{
	uint64_t			svc_cluster_id_				{0};
	uint32_t			ntotal_cluster_svc_			{0};
	uint32_t			nmadhava_				{0};
	char				init_comm_[TASK_COMM_LEN]		{};

	ClusterMeshStat(uint64_t svc_cluster_id, uint32_t ntotal_cluster_svc, uint32_t nmadhava, const char * init_comm) noexcept
		: svc_cluster_id_(svc_cluster_id), ntotal_cluster_svc_(ntotal_cluster_svc), nmadhava_(nmadhava)
	{
		GY_STRNCPY(init_comm_, init_comm, sizeof(init_comm_));
	}	

	ClusterMeshStat(uint64_t svc_cluster_id) noexcept
		: svc_cluster_id_(svc_cluster_id)
	{}	

	bool operator==(const ClusterMeshStat & other) const noexcept
	{
		return svc_cluster_id_ == other.svc_cluster_id_;
	}	

	struct SHash
	{
		size_t operator()(const ClusterMeshStat & one) const noexcept
		{
			return get_uint64_hash(one.svc_cluster_id_);
		}	
	};	

};	

class SvcNatElem
{
public :
	RCU_HASH_CLASS_MEMBERS(uint64_t, SvcNatElem);

	GY_MACHINE_ID			partha_machine_id_;
	uint64_t			madhava_id_		{0};
	uint64_t			glob_id_		{0};
	gy_atomic<time_t>		tlast_upd_		{0};

	SvcNatElem(const GY_MACHINE_ID & partha_machine_id, uint64_t madhava_id, uint64_t glob_id, time_t tcurr) noexcept
		: partha_machine_id_(partha_machine_id), madhava_id_(madhava_id), glob_id_(glob_id), tlast_upd_(tcurr)
	{}	

	SvcNatElem() noexcept 					= default;

	SvcNatElem(const SvcNatElem & other)			= default;
	SvcNatElem(SvcNatElem && other) noexcept		= default;

	SvcNatElem & operator= (const SvcNatElem & other) 	= default;
	SvcNatElem & operator= (SvcNatElem && other) noexcept	= default;

	~SvcNatElem() noexcept					= default;

	friend inline bool operator== (const SvcNatElem & lhs, uint64_t glob_id) noexcept
	{
		return lhs.glob_id_ == glob_id;
	}
};	

using 	SvcNatElemTbl 			= RCU_HASH_TABLE <uint64_t, SvcNatElem>;

struct NatIPComm
{
	IP_PORT				nat_ip_port_;
	char				comm_[TASK_COMM_LEN]		{};
	uint64_t			svc_cluster_id_			{0};

	NatIPComm() noexcept		= default;

	NatIPComm(const IP_PORT & nat_ip_port, const char * comm, uint64_t cluster_hash) noexcept
		: nat_ip_port_(nat_ip_port)
	{
		GY_STRNCPY_0(comm_, comm, sizeof(comm_));

		uint64_t			iphash = nat_ip_port_.get_hash();
		CHAR_BUF<TASK_COMM_LEN + 16>	cbuf;

		std::memcpy(cbuf.get(), comm_, sizeof(comm_));
		std::memcpy(cbuf.get() + sizeof(comm_), &iphash, sizeof(iphash));
		std::memcpy(cbuf.get() + sizeof(comm_) + sizeof(iphash), &cluster_hash, sizeof(cluster_hash));

		static_assert(sizeof(comm_) + sizeof(iphash) + sizeof(cluster_hash) == sizeof(cbuf));

		svc_cluster_id_ = GY_JHASHER<decltype(cbuf)>()(cbuf);
	}	

	NatIPComm(const IP_PORT & nat_ip_port, const char * comm, const char * cluster_name) noexcept
		: NatIPComm(nat_ip_port, comm, gy_cityhash64(cluster_name, strlen(cluster_name)))
	{}	


	bool operator== (const NatIPComm & other) const noexcept
	{
		return svc_cluster_id_ == other.svc_cluster_id_;
	}	

	uint64_t get_hash() const noexcept
	{
		return get_uint64_hash(svc_cluster_id_);
	}	

	struct Chash
	{
		uint64_t operator()(const NatIPComm & key, const char * cluster_name) const noexcept
		{
			return key.get_hash();
		}	
	};	
};	

class SvcNatIPOne
{
public :
	RCU_HASH_CLASS_MEMBERS(NatIPComm, SvcNatIPOne);

	SvcNatElemTbl			elemtbl_		{8, 8, 1024, true, false};
	NatIPComm			natipcomm_;

	time_t				tstart_			{0};
	gy_atomic<time_t>		tlast_upd_		{0};

	SvcNatIPOne(const IP_PORT & nat_ip_port, const char * comm, const char * cluster_name, time_t tcurr)
		: natipcomm_(nat_ip_port, comm, cluster_name), tstart_(tcurr), tlast_upd_(tcurr)
	{}	

	SvcNatIPOne(const NatIPComm & natipcomm, time_t tcurr)
		: natipcomm_(natipcomm), tstart_(tcurr), tlast_upd_(tcurr)
	{}	

	SvcNatIPOne() noexcept 						= default;

	SvcNatIPOne(SvcNatIPOne && other) noexcept			= default;
	SvcNatIPOne & operator= (SvcNatIPOne && other) noexcept		= default;

	~SvcNatIPOne() noexcept						= default;

	uint64_t get_cluster_id() const noexcept
	{
		return natipcomm_.svc_cluster_id_;
	}	

	friend inline bool operator== (const SvcNatIPOne & lhs, const NatIPComm & key) noexcept
	{
		return lhs.natipcomm_ == key;
	}

};	

using 	SvcNatIPTbl 			= RCU_HASH_TABLE <NatIPComm, SvcNatIPOne>;
using 	ClusterNameBuf			= CHAR_BUF<comm::MAX_CLUSTER_NAME_LEN>;


class SvcClusterMapsOne
{
public :
	using ClusterMeshStatMap	= std::unordered_map<ClusterMeshStat, std::vector<comm::RELSVC_CLUSTER_ONE>, ClusterMeshStat::SHash>;

	RCU_HASH_CLASS_MEMBERS(ClusterNameBuf, SvcClusterMapsOne);

	ClusterNameBuf			cluster_;
	
	SvcClusterMeshTbl		meshtbl_				{1};
	SharedMutex			meshrwlock_;
	ClusterMeshStatMap		meshstatmap_;

	SvcNatIPTbl			natiptbl_				{1};

	time_t				tstart_					{0};
	gy_atomic<time_t>		tlast_upd_				{0};

	SvcClusterMapsOne(const char * cluster, time_t tcurr = time(nullptr))
		: cluster_(cluster), tstart_(tcurr), tlast_upd_(tcurr)
	{}	

	SvcClusterMapsOne() noexcept 						= default;

	SvcClusterMapsOne(SvcClusterMapsOne && other) noexcept			= default;
	SvcClusterMapsOne & operator= (SvcClusterMapsOne && other) noexcept	= default;

	~SvcClusterMapsOne() noexcept						= default;

	friend inline bool operator== (const SvcClusterMapsOne & lhs, const ClusterNameBuf & cluster) noexcept
	{
		return lhs.cluster_ == cluster;
	}
	
};	

using 	SvcClusterMapsTbl 		= RCU_HASH_TABLE <ClusterNameBuf, SvcClusterMapsOne>;


template <class ParthaInfo, class MadhavaInfo, class NodeInfo>
class SHSOCKET_HDLR_T
{
public :
	class SHTCP_CONN
	{
	public :	
		RCU_HASH_CLASS_MEMBERS(PAIR_IP_PORT, SHTCP_CONN);
		
		IP_PORT					cli_;
		IP_PORT					ser_;
		
		IP_PORT					cli_nat_cli_;			// Client Host Side NAT and Key to the class
		IP_PORT					cli_nat_ser_;

		uint64_t				cli_madhava_id_			{0};
		uint64_t				cli_task_aggr_id_		{0};
		uint64_t				cli_related_listen_id_		{0};
		char					cli_comm_[TASK_COMM_LEN]	{};

		char					cli_ser_cmdline_trunc_[63];	// Whichever is first
		uint8_t					cli_ser_cmdline_len_;
		std::shared_ptr <MadhavaInfo>		cli_ser_madhava_shr_;
		GY_MACHINE_ID				cli_ser_partha_machine_id_;
		uint64_t				cli_ser_cluster_hash_		{0};
		
		IP_PORT					ser_nat_cli_;			// Server Host Side NAT
		IP_PORT					ser_nat_ser_;
		uint64_t				ser_glob_id_			{0};
		uint64_t				ser_madhava_id_			{0};
		uint64_t				ser_related_listen_id_		{0};
		char					ser_comm_[TASK_COMM_LEN]	{};
		uint32_t				ser_conn_hash_			{0};
		uint32_t				ser_sock_inode_			{0};

		uint64_t				close_cli_bytes_sent_		{0};	// Will be non-zero only for closed conns
		uint64_t				close_cli_bytes_rcvd_		{0};

		uint64_t				tusec_start_			{0};	// Start usec when conn was added in Madhava rather than at Partha level
		uint64_t				tusec_shstart_			{0};	// Start usec when conn was added in Shyama rather than at Partha level

		SHTCP_CONN() noexcept 					= default;
	
		SHTCP_CONN(const SHTCP_CONN & other)			= default;
		SHTCP_CONN(SHTCP_CONN && other)	noexcept		= default;

		SHTCP_CONN & operator= (const SHTCP_CONN & other) 	= default;
		SHTCP_CONN & operator= (SHTCP_CONN && other) noexcept	= default;

		~SHTCP_CONN() noexcept					= default;

		bool is_server_updated() const noexcept
		{
			return (0 != ser_glob_id_);
		}	

		bool is_conn_closed() const noexcept
		{
			return close_cli_bytes_sent_ + close_cli_bytes_rcvd_ > 0;
		}

		friend inline bool operator== (const SHTCP_CONN & lhs, const PAIR_IP_PORT & tup) noexcept
		{
			return (lhs.cli_nat_cli_ == tup.cli_) && (lhs.cli_nat_ser_ == tup.ser_);
		}
	};	

	// Use Pool Allocated Element
	using 	SHTCP_CONN_HASH_TABLE 		= RCU_HASH_TABLE <PAIR_IP_PORT, SHTCP_CONN, TPOOL_DEALLOC<SHTCP_CONN>>;

};

} // namespace shyama
} // namespace gyeeta

