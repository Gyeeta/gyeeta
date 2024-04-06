//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"
#include			"gy_file_api.h"
#include			"gy_misc.h"
#include			"gy_task_handler.h"
#include			"gy_cgroup_stat.h"
#include			"gy_inet_inc.h"
#include			"gy_dns_mapping.h"
#include			"gy_statistics.h"
#include			"gy_ebpf.h"
#include			"gy_pool_alloc.h"
#include			"gy_stack_container.h"
#include			"gy_svc_net_capture.h"

#include			<unordered_map>
#include			<unordered_set>
#include			<set>

struct inet_diag_msg;

namespace gyeeta {

/*
 * Currently only TCP sockets are handled...
 * XXX TODO Handle Unix Domain and UDP Sockets ... 
 */

class NETNS_ELEM
{
public :	
	RCU_HASH_CLASS_MEMBERS(ino_t, NETNS_ELEM);

	ino_t				inode_			{0};
	pid_t				pid_start_		{0};
	pid_t				tid_start_		{0};
	std::atomic <uint64_t>		clock_usec_		{0};
	std::atomic <uint64_t>		start_clock_usec_	{0};
	int				fd_netns_		{-1};

	NETNS_ELEM(ino_t inode, pid_t pid, pid_t tid, bool open_ns = true) noexcept
		: inode_(inode), pid_start_(pid), tid_start_(tid), clock_usec_(get_usec_clock()), start_clock_usec_(clock_usec_.load(std::memory_order_relaxed))
	{
		if (open_ns) {
			open_ns_inode();
		}
	}

	NETNS_ELEM(const NETNS_ELEM & other) 			= delete;

	NETNS_ELEM & operator= (const NETNS_ELEM & other) 	= delete;
			
	NETNS_ELEM(NETNS_ELEM && other) noexcept
		: inode_(std::exchange(other.inode_, 0)), pid_start_(other.pid_start_), tid_start_(other.tid_start_), 
		clock_usec_(other.clock_usec_.load(std::memory_order_relaxed)), start_clock_usec_(other.start_clock_usec_.load(std::memory_order_relaxed)), 
		fd_netns_(std::exchange(other.fd_netns_, -1))
	{}
			
	NETNS_ELEM & operator= (NETNS_ELEM && other) noexcept
	{
		if (this != &other) {
			inode_ 			= std::exchange(other.inode_, 0);
			pid_start_		= other.pid_start_;
			tid_start_		= other.tid_start_;

			clock_usec_.store(other.clock_usec_.load(std::memory_order_relaxed), std::memory_order_relaxed);
			start_clock_usec_.store(other.start_clock_usec_.load(std::memory_order_relaxed), std::memory_order_relaxed);

			if (fd_netns_ > 0) {
				(void)close(fd_netns_);
			}	
			fd_netns_		= std::exchange(other.fd_netns_, -1);
		}
		
		return *this;	
	}	
	
	~NETNS_ELEM() noexcept	
	{
		if (fd_netns_ > 0) {
			(void)close(fd_netns_);
			fd_netns_ = -1;	
		}		

		inode_ 		= 0;
	}		

	int open_ns_inode() noexcept
	{
		if (fd_netns_ <= 0) {
			char			path[256];
			int			ret;

			snprintf(path,	sizeof(path), "/proc/%d/task/%d/ns/net", pid_start_, tid_start_);
			
			ret = open(path, O_RDONLY | O_CLOEXEC);	
			if (ret == -1) {
				CONDEXEC(
					DEBUGEXECN(15, 
						PERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Could not open Net Namespace file for PID %d Thread %d Inode %lu", 
							pid_start_, tid_start_, inode_););
				);
				fd_netns_ = -2;
				return -1;
			}	

			fd_netns_ = ret;
		}

		return 0;
	}	

	ino_t get_ns_inode() const noexcept
	{
		return inode_;
	}

	int get_ns_fd() const noexcept
	{
		return fd_netns_;
	}

	const char * print_string(STR_WR_BUF & strbuf) const noexcept
	{
		strbuf.appendfmt("NetNS Info : inode %ld Start PID %d TID %d ", inode_, pid_start_, tid_start_);
		return strbuf.buffer();
	}	

	friend inline bool operator== (const NETNS_ELEM &lhs, ino_t inode) noexcept
	{
		return lhs.inode_ == inode;
	}
};	

using 	NETNS_HASH_TABLE		= RCU_HASH_TABLE<ino_t, NETNS_ELEM>;

class TCP_CONN;

class NAT_ELEM
{
public :	
	PAIR_IP_PORT			orig_tup_;
	PAIR_IP_PORT			nat_tup_;

	uint64_t			clock_usec_	{0};

	std::shared_ptr <TCP_CONN>	shrconn_;
	gy_atomic <bool>		shr_updated_	{false};

	bool				is_snat_ 	{false};
	bool				is_dnat_	{false};
	bool				is_deleted_	{false};
	bool				is_ipvs_	{false};

	NAT_ELEM() noexcept 		= default;

	NAT_ELEM(const GY_IP_ADDR & cli_addr, uint16_t cli_port, const GY_IP_ADDR & ser_addr, uint16_t ser_port, const GY_IP_ADDR & cli_nat_addr, uint16_t cli_nat_port, \
			const GY_IP_ADDR & ser_nat_addr, uint16_t ser_nat_port, bool is_ipvs = false) noexcept
		: orig_tup_(IP_PORT(cli_addr, cli_port), IP_PORT(ser_addr, ser_port)), 
		nat_tup_(IP_PORT(cli_nat_addr, cli_nat_port), IP_PORT(ser_nat_addr, ser_nat_port)),
		clock_usec_(get_usec_clock()),
		is_snat_((cli_addr != cli_nat_addr) || (cli_port != cli_nat_port)),
		is_dnat_((ser_addr != ser_nat_addr) || (ser_port != ser_nat_port)), is_ipvs_(is_ipvs)
	{}

	NAT_ELEM(PAIR_IP_PORT orig_tup, PAIR_IP_PORT nat_tup, bool is_snat, bool is_dnat, bool is_ipvs) noexcept
		: orig_tup_(orig_tup), nat_tup_(nat_tup),
		clock_usec_(get_usec_clock()), is_snat_(is_snat), is_dnat_(is_dnat), is_ipvs_(is_ipvs)
	{}

	NAT_ELEM(const NAT_ELEM &)				= default;
	NAT_ELEM(NAT_ELEM &&) noexcept				= default;

	NAT_ELEM & operator= (const NAT_ELEM &)			= default;
	NAT_ELEM & operator= (NAT_ELEM &&) noexcept		= default;

	~NAT_ELEM() noexcept					= default;

	const char * print_string(STR_WR_BUF & strbuf) const noexcept
	{
		strbuf.appendfmt("[ %s%s %s ] : Original ", is_ipvs_ ? "IPVS " : "", is_snat_ ? "SNAT" : "", is_dnat_ ? "DNAT" : "");
		orig_tup_.print_string(strbuf);
		strbuf.appendconst(" : NAT ");
		nat_tup_.print_string(strbuf);
		strbuf.append(' ');

		return strbuf.buffer();
	}	

	void set_comm_nat(comm::NAT_TCP_NOTIFY *pnat) const noexcept
	{
		pnat->orig_tup_		= orig_tup_;
		pnat->nat_tup_		= nat_tup_;
		pnat->is_snat_		= is_snat_;
		pnat->is_dnat_		= is_dnat_;
		pnat->is_ipvs_		= is_ipvs_;
	}	

	friend inline bool operator== (const NAT_ELEM & elem, const PAIR_IP_PORT & tup) noexcept
	{
		return (elem.nat_tup_ == tup);
	}	

	friend inline bool operator== (const std::shared_ptr<NAT_ELEM> & elem, const PAIR_IP_PORT & tup) noexcept
	{
		auto pdata = elem.get();

		return (pdata && pdata->nat_tup_ == tup);
	}	
};	

using NAT_ELEM_TYPE			= RCU_HASH_WRAPPER<PAIR_IP_PORT /* nat_tup_ */, std::shared_ptr<NAT_ELEM>>;
using NAT_HASH_TABLE			= RCU_HASH_TABLE <PAIR_IP_PORT, NAT_ELEM_TYPE>;

class TCP_LISTENER;
class RELATED_LISTENERS;

class TCP_CONN : public std::enable_shared_from_this <TCP_CONN>
{
public :	
	IP_PORT					cli_;
	IP_PORT					ser_;
	
	IP_PORT					nat_cli_;
	IP_PORT					nat_ser_;

	ino_t					cli_ns_inode_		{0};
	pid_t					cli_pid_		{0};
	pid_t					cli_tid_		{0};
	bool					is_tcp_connect_event_	{false};
	gy_atomic <bool>			cli_task_updated_	{false};
	gy_atomic <bool>			is_client_local_	{false};
	uint64_t				cli_task_aggr_id_	{0};
	std::shared_ptr <TASK_STAT>		cli_task_shr_;				// Updated only once and will be valid even if the task exits till the conn is active
	uint64_t				cli_madhava_id_		{0};

	GY_MACHINE_ID 				peer_machine_id_;			// For conns with a remote peer and resolved
	
	gy_atomic<ino_t>			ser_ns_inode_		{0};
	pid_t					ser_pid_		{0};
	pid_t					ser_tid_		{0};
	bool					is_tcp_accept_event_	{false};
	bool					is_dns_queried_		{false};
	gy_atomic <bool>			ser_task_updated_	{false};
	gy_atomic <bool>			is_server_local_	{false};
	uint64_t				ser_task_aggr_id_	{0};
	std::shared_ptr <TASK_STAT>		ser_task_shr_;				// Updated only once and will be valid even if the task exits till the conn is active
	char					server_domain_[128];			// Limit TCP conn server_domain_ to 128

	uint64_t				clock_usec_start_	{0};
	uint64_t				tusec_start_		{get_usec_time()};

	std::shared_ptr <TCP_LISTENER>		listen_shr_;
	uint64_t				ser_glob_id_		{0};
	int64_t					ser_related_listen_id_	{0};
	ino_t					ser_sock_inode_		{0};
	uid_t					ser_uid_		{0};
	bool					cli_ser_diff_clusters_	{false};
	char 					ser_comm_[TASK_COMM_LEN] {};
	uint64_t				ser_madhava_id_		{0};

	TCP_INFO_STATS				stats_;
	std::shared_ptr<RELATED_LISTENERS>	cli_related_listen_shr_;

	tribool					is_cluster_listen_	{indeterminate};						

	uint32_t				conn_hash_		{0};
	union {
		int				conn_flags_		{0};
		struct {		
			bool			nat_updated_ : 1;
			bool			is_snat_ : 1;
			bool			is_dnat_ : 1;
			bool			cli_listener_proc_ : 1;
			bool			cli_listener_checked_ : 1;
			bool			tcp_info_seen_ : 1;	
			bool			is_existing_conn_ : 1;
			bool			is_new_cli_task_ : 1;
			bool			cluster_checked_ : 1;
		};	
	};

	char 					cli_comm_[TASK_COMM_LEN] {};

	ino_t					cli_sock_inode_		{0};
	uid_t					cli_uid_		{0};

	bool					listen_updated_		{false};
	bool					depends_updated_	{false};

	mutable std::atomic<bool>		server_updated_		{false};

	TCP_CONN() noexcept 			= default;

	TCP_CONN(IP_PORT cli, IP_PORT ser, pid_t cli_pid, pid_t cli_tid, pid_t ser_pid, pid_t ser_tid, uint64_t clock_usec, const char * pdomain = "")
		: cli_(cli), ser_(ser), nat_cli_(cli), nat_ser_(ser), cli_pid_(cli_pid), cli_tid_(cli_tid), ser_pid_(ser_pid), ser_tid_(ser_tid), 
		clock_usec_start_(clock_usec)
	{
		GY_STRNCPY(server_domain_, pdomain, sizeof(server_domain_));
	}		

	TCP_CONN(const TCP_CONN & other)			= default;
	TCP_CONN(TCP_CONN && other) noexcept			= default;

	TCP_CONN & operator= (const TCP_CONN & other) 		= default;
	TCP_CONN & operator= (TCP_CONN && other) noexcept	= default;

	~TCP_CONN() noexcept					= default;

	const char * print_string(STR_WR_BUF & strbuf, bool print_stats = false) const;
	
	void set_notify_elem(comm::TCP_CONN_NOTIFY *pnot, uint64_t close_usec_time, const char *pcli_cmdline = nullptr, size_t cli_cmdline_len = 0) const noexcept;

	friend inline bool operator== (const std::shared_ptr<TCP_CONN> &lhs, const PAIR_IP_PORT & tup) noexcept
	{
		auto pdata = lhs.get();

		return (pdata && (pdata->cli_ == tup.cli_) && (pdata->ser_ == tup.ser_));
	}
};	

using 	TCP_CONN_ELEM_TYPE 		= RCU_HASH_WRAPPER <PAIR_IP_PORT /* Non NAT tuple */, std::shared_ptr<TCP_CONN>>;
using 	TCP_CONN_HASH_TABLE 		= RCU_HASH_TABLE <PAIR_IP_PORT, TCP_CONN_ELEM_TYPE, TPOOL_DEALLOC<TCP_CONN_ELEM_TYPE>>;

using RESP_HISTOGRAM			= RESP_TIME_HISTOGRAM<SCOPE_GY_MUTEX>;

class TCP_LISTENER;

using TCP_LISTENER_PTR			= RCU_KEY_POINTER<TCP_LISTENER *>;

class WEAK_LISTEN_RAW
{
public :	
	RCU_HASH_CLASS_MEMBERS(TCP_LISTENER_PTR, WEAK_LISTEN_RAW);

	std::weak_ptr<TCP_LISTENER>	weaklisten_;
	TCP_LISTENER			*plistener_		{nullptr};

	WEAK_LISTEN_RAW() noexcept				= default;
	
	WEAK_LISTEN_RAW(std::weak_ptr<TCP_LISTENER> weakp, TCP_LISTENER *plist) noexcept 
		: weaklisten_(std::move(weakp)), plistener_(plist)
	{}
	
	WEAK_LISTEN_RAW(const WEAK_LISTEN_RAW &) noexcept		= default;
	WEAK_LISTEN_RAW(WEAK_LISTEN_RAW &&) noexcept			= default;
	WEAK_LISTEN_RAW & operator=(const WEAK_LISTEN_RAW &) noexcept	= default;
	WEAK_LISTEN_RAW & operator=(WEAK_LISTEN_RAW &&) noexcept	= default;
	
	~WEAK_LISTEN_RAW() noexcept					= default; 		
			
	friend inline bool operator== (const WEAK_LISTEN_RAW & lhs, const TCP_LISTENER_PTR pkey) noexcept
	{
		return lhs.plistener_ == pkey.get_data();
	}
};	

using WEAK_LISTEN_TABLE			= RCU_HASH_TABLE <TCP_LISTENER_PTR, WEAK_LISTEN_RAW>;

class SVC_INFO_CAP;

class TCP_LISTENER : public std::enable_shared_from_this <TCP_LISTENER>
{
public :	
	class LISTENER_ISSUE_HIST
	{
	public :	
		uint64_t			tclocksec_		{0};
		LISTENER_ISSUE_SRC		mainsrc_		{ISSUE_LISTEN_NONE};
		LISTENER_ISSUE_SRC		subsrc_			{ISSUE_LISTEN_NONE};	// Will be updated if Madhava sends the listener issue resolution

		LISTENER_ISSUE_HIST() noexcept	= default;

		LISTENER_ISSUE_HIST(LISTENER_ISSUE_SRC mainsrc, LISTENER_ISSUE_SRC subsrc, uint64_t tclocksec = get_sec_clock()) noexcept :
			tclocksec_(tclocksec), mainsrc_(mainsrc), subsrc_(subsrc)
		{}	
	};
		
	/*
	 * Gives an approx count (upto a max of 32) of whether many connections caused a spike in response or just a few. 
	 *
	 * Assumption is that get_conn_breakup() will be regularly called
	 *
	 * We do not create buckets for a sliding window type case. So there is a discontinuity whenever clear() is called as 
	 * the next iteration will just return the last few seconds data...
	 */ 
	class CONN_BITMAP
	{
	public :	
		static constexpr int		max_port_hash_ 				= 32;		
		static constexpr int		bit_map_mask_				= 0x1F;		// Least 5 bits of the Port Number (32 - 1)
		static constexpr int		secs_to_reset_ 				= 5;
		static constexpr uint8_t	max_resp_buckets_	 		= (uint8_t)RESP_HISTOGRAM::get_max_buckets();	

		std::bitset<max_resp_buckets_>	respmap_[max_port_hash_];	 	
		time_t				tnext_clear_	 			{time(nullptr) + secs_to_reset_};

		static_assert(true == gy_is_power_of_2(max_port_hash_ ) && (bit_map_mask_ == max_port_hash_ - 1));

		void add_response(time_t tnow, uint16_t cli_port, uint8_t resp_bucket_num)
		{
			auto pbitmap = &respmap_[cli_port & bit_map_mask_];

			assert(resp_bucket_num < max_resp_buckets_);

			pbitmap->set(resp_bucket_num);
		}	

		void get_conn_breakup(uint8_t nconn_arr[max_resp_buckets_], time_t tnow = time(nullptr)) noexcept
		{
			uint8_t			nconns;

			for (uint8_t j = 0; j < max_resp_buckets_; j++) {
				nconns = 0;

				for (int i = 0; i < max_port_hash_; i++) {
					if (respmap_[i].test(j)) {
						nconns++;
					}
				}
				
				nconn_arr[j] = nconns;	
			}

			if (tnow >= tnext_clear_) {
				clear(tnow);
			}
		}	

		void clear(time_t tnow = time(nullptr)) noexcept
		{
			tnext_clear_ = tnow + secs_to_reset_;

			for (int i = 0; i < max_port_hash_; i++) {
				respmap_[i].reset();
			}
		}
			
		static const char * print_string(STR_WR_BUF & strbuf, uint8_t nconn_arr[max_resp_buckets_]) noexcept
		{
			strbuf.appendfmt("\tPartial # Connections (upto max 32) for Response Distribution in last %d sec : ", secs_to_reset_);

			for (size_t i = 0; i < max_resp_buckets_; ++i) {
				strbuf.appendfmt("[ < %ld msec %hhu ] ", get_bucket_max_threshold<RESP_TIME_HASH>(i), nconn_arr[i]);
			}	

			strbuf.append('\n');

			return strbuf.buffer();
		}	
	};


	struct RESP_STATS
	{
		TIME_HIST_VAL			stats_[3]		{95.0f, 99.0f, 25.0f};
		int64_t 			tcount_ 		{0};
		int64_t				tsum_ 			{0};
		double 				mean_val_ 		{0};
	};	

	struct RESP_TO_CONN
	{
		struct RESP_TO_CONN_ONE
		{
			PAIR_IP_PORT		conn_;
			time_t			tnoted_;
			int 			tresp_msec_;
		};	

		static constexpr int		MAX_STATS_CONNS = 5;
		
		/*
		 * We maintain last 5 stats for response time > 1000 msec and last 5 for resp > 100 msec
		 */ 
		time_t				tlast_added_				{0};

		uint8_t				curr_100_				{0};
		RESP_TO_CONN_ONE		over_100_msec_[MAX_STATS_CONNS]		{};	

		uint8_t				curr_1000_				{0};
		RESP_TO_CONN_ONE		over_1000_msec_[MAX_STATS_CONNS]	{};	

		void add_resp_conn(time_t tnow, const IP_PORT & cli, const IP_PORT & ser, int tresp_msec_) noexcept
		{
			if (tresp_msec_ < 100) {
				return;
			}
			
			tlast_added_ = tnow;

			if (tresp_msec_ >= 1000) {
				over_1000_msec_[curr_1000_++ % MAX_STATS_CONNS] = {{cli, ser}, tnow, tresp_msec_};
			}		
			else {
				over_100_msec_[curr_100_++ % MAX_STATS_CONNS] = {{cli, ser}, tnow, tresp_msec_};
			}	
		}	

		const char * print_string(STR_WR_BUF & strbuf, const char *prefix)
		{
			time_t			tcur = time(nullptr);
			bool			is_hdr = false;

			for (int i = 0; i < MAX_STATS_CONNS; i++) {
				auto			data = over_1000_msec_[i];	
				int64_t			tdiff = data.tnoted_ - tcur;

				if (labs(tdiff) < 5) {
					if (!is_hdr) {
						strbuf.appendfmt("\n\t%s : Last 5 Client Connection in last 5 sec Queries with response >= 1000 msec : \n", prefix);
						is_hdr = true;
					}	
					strbuf.append('\t');
					data.conn_.print_string(strbuf);
					strbuf.appendfmt(" : Record time %ld sec from current time : Response time %d msec\n", tdiff, data.tresp_msec_);
				}	
			}	

			is_hdr = false;
			for (int i = 0; i < MAX_STATS_CONNS; i++) {
				auto			data = over_100_msec_[i];	
				int64_t			tdiff = data.tnoted_ - tcur;

				if (labs(tdiff) < 5) {
					if (!is_hdr) {
						strbuf.appendfmt("\n\t%s : Last 5 Client Connection Queries in last 5 sec with response >= 100 msec : \n", prefix);
						is_hdr = true;
					}	
					strbuf.append('\t');
					data.conn_.print_string(strbuf);
					strbuf.appendfmt(" : Record time %ld sec from current time : Response time %d msec\n", tdiff, data.tresp_msec_);
				}	
			}	

			return strbuf.buffer();
		}	
	};



	static constexpr int				MAX_ISSUE_HIST 			{3};

	using RESP_CACHE				= TIME_HIST_CACHE<RESP_HISTOGRAM, RESP_TIME_HASH>;
	using QPS_HISTOGRAM				= GY_HISTOGRAM <int, SEMI_LOG_HASH_LO>;
	using ACTIVE_CONN_HISTOGRAM			= GY_HISTOGRAM <int, HASH_1_3000>;

	NS_IP_PORT					ns_ip_port_;
	uint64_t					glob_id_			{0};
	uint64_t					aggr_glob_id_			{0};

	const bool					is_any_ip_;
	const bool					is_root_netns_;

	uint32_t					last_qps_count_			{0};

	std::weak_ptr <TASK_STAT>			task_weak_;
	
	folly::atomic_shared_ptr<SHR_TASK_HASH_TABLE>	listen_task_table_;
	folly::atomic_shared_ptr<RELATED_LISTENERS>	related_listen_;
	int64_t						related_listen_id_		{0};
	int						ntasks_associated_		{1};

	uint64_t					close_bytes_in_			{0};		// Updated by the Conn Close Callback
	uint64_t					close_bytes_out_		{0};		// Updated by the Conn Close Callback
	
	pid_t						pid_				{0};
	int						backlog_			{0};
	ino_t						sock_ipv4_inode_		{0};
	ino_t						sock_ipv6_inode_		{0};
	uid_t						uid_				{0};
	
	gy_atomic<uint8_t>				nat_ip_skipped_			{0};		
	
	char						comm_[TASK_COMM_LEN]		{};
	char						orig_comm_[TASK_COMM_LEN]	{};
	char						cmdline_[comm::MAX_PROC_CMDLINE_LEN]	{};
	uint64_t					ser_aggr_task_id_		{0};

	gy_atomic <uint64_t>				clock_usec_			{0};
	gy_atomic <uint64_t>				start_clock_usec_		{0};
	uint64_t					tstart_usec_			{0};

	tribool						is_http_svc_			{indeterminate};
	std::atomic<tribool>				httperr_cap_started_		{indeterminate};

	static_assert(decltype(httperr_cap_started_)::is_always_lock_free == true, "Boost Tribool Atomics not lock free!");
	
	gy_atomic<PROTO_CAP_STATUS_E>			api_cap_started_		{CAPSTAT_UNINIT};
	gy_atomic<time_t>				tapi_cap_stop_			{0};
	gy_atomic<PROTO_TYPES>				api_proto_			{PROTO_UNINIT};
	std::atomic<tribool>				api_is_ssl_			{indeterminate};

	GY_MUTEX					svcweak_lock_;
	std::weak_ptr<SVC_INFO_CAP>			api_svcweak_;
	uint64_t					last_api_ncli_errors_		{0};
	uint64_t					last_api_nser_errors_		{0};

	gy_atomic <int>					nconn_				{0};
	gy_atomic <int>					nconn_recent_active_		{0};
	gy_atomic <int>					last_nconn_			{0};
	gy_atomic <int>					last_nconn_recent_active_	{0};

	uint32_t					cumul_cli_errors_		{0};		// Currently only for HTTP1.x/HTTP2 (GRPC) and if Error code network capture on
	uint32_t					cumul_ser_errors_		{0};

	uint64_t					cumul_bytes_inbound_		{0};
	uint64_t					cumul_bytes_outbound_		{0};
	uint64_t					curr_bytes_inbound_		{0};
	uint64_t					curr_bytes_outbound_		{0};
	uint64_t					last_close_bytes_in_		{0};
	uint64_t					last_close_bytes_out_		{0};

	IP_PORT						nat_ip_port_arr_[2];
	int64_t						last_nat_ref_ip_tsec_[2]	{};
	int64_t						last_nat_chg_ip_tsec_		{};

	int64_t						last_dns_query_tsec_		{0};
	char						server_domain_[128]		{};		// Limit server_domain_ to 128 bytes

	uint32_t					last_cli_errors_		{0};
	uint32_t					last_ser_errors_		{0};

	uint32_t					listen_hash_			{0};

	uint32_t					last_chk_nconn_			{0};
	uint32_t					last_chk_nconn_active_		{0};
	uint32_t					last_avg_qps_			{0};
	uint32_t					last_query_v4_			{0};	
	uint32_t					last_query_v6_			{0};	
	uint64_t					last_query_clock_		{0};
	QPS_HISTOGRAM					qps_hist_;
	uint64_t					last_conn_clock_		{0};
	ACTIVE_CONN_HISTOGRAM				active_conn_hist_;
	uint8_t 					nactive_conn_arr_[RESP_HISTOGRAM::max_buckets]	{};

	time_t						tlast_stats_flush_		{0};
	RESP_STATS					histstat_[RESP_HISTOGRAM::ntime_levels];

	const uint64_t					init_start_tusec_		{tstart_usec_};
	/*comm::LISTENER_DAY_STATS			last_stats_5d_;*/

	RESP_CACHE					resp_cache_v4_;
	CONN_BITMAP					resp_bitmap_v4_;
	uint32_t					curr_query_v4_			{0};
	RESP_TO_CONN					resp_conn_v4_;	

	RESP_HISTOGRAM					resp_hist_;
	
	uint64_t					last_cumul_bytes_inbound_	{0};
	uint64_t					last_cumul_bytes_outbound_	{0};
	LISTENER_ISSUE_HIST				issue_hist_[MAX_ISSUE_HIST];	
	OBJ_STATE_E					curr_state_			{STATE_OK};
	LISTENER_ISSUE_SRC				curr_issue_			{ISSUE_LISTEN_NONE};
	uint8_t						issue_bit_hist_			{0};		
	uint8_t						high_resp_bit_hist_		{0};
	uint8_t						bytes_slot_			{0};

	bool						server_stats_fetched_		{false};
	bool						server_stats_updated_		{false};
	bool						is_pre_existing_		{false};

	RESP_CACHE					resp_cache_v6_;
	CONN_BITMAP					resp_bitmap_v6_;
	uint32_t					curr_query_v6_			{0};
	RESP_TO_CONN					resp_conn_v6_;	

	TCP_LISTENER(const GY_IP_ADDR & addr, uint16_t port, ino_t nsinode, pid_t pid, uint32_t listen_hash, int backlog = 0, std::weak_ptr <TASK_STAT> task = {}, \
			std::shared_ptr <SHR_TASK_HASH_TABLE> listen_table = {}, const char *pcomm = nullptr, const char *pcmdline = nullptr, bool is_pre_existing = false, \
			uint64_t curr_tusec = get_usec_time());

	TCP_LISTENER(const TCP_LISTENER &)			= default;
	TCP_LISTENER(TCP_LISTENER &&)				= default;

	TCP_LISTENER & operator= (const TCP_LISTENER &)		= default;
	TCP_LISTENER & operator= (TCP_LISTENER &&)		= default;

	~TCP_LISTENER() noexcept				= default;

	const char * print_string(STR_WR_BUF & strbuf, bool print_stats = true);

	const char * print_short_string(STR_WR_BUF & strbuf) const noexcept 
	{
		strbuf.appendconst("TCP Listener : ");
		ns_ip_port_.print_string(strbuf);
		
		strbuf.appendfmt("ID %016lx Comm \'%s\'", glob_id_, comm_);

		return strbuf.buffer();
	}	

	void set_aggr_glob_id() noexcept;

	void get_curr_state(OBJ_STATE_E & lstate, LISTENER_ISSUE_SRC & lissue, STR_WR_BUF & strbuf, time_t tcur, uint64_t clock_usec, int curr_active_conn, \
					float multiple_factor, bool cpu_issue, bool mem_issue, uint32_t ser_errors, void * ptaskstatus, comm::LISTENER_DAY_STATS *pstatsn) noexcept;

	bool is_task_issue(uint64_t clock_usec, uint32_t & tasks_delay_usec, uint32_t & tasks_cpudelay_usec, uint32_t & tasks_blkiodelay_usec, bool & is_severe, bool & is_delay, \
					int & ntasks_issue, int & ntasks_noissue, int & tasks_user_cpu, int & tasks_sys_cpu, int & tasks_rss_mb) noexcept;
	
	void set_nat_ip_port(const IP_PORT & nat_ip_port, int64_t tcurr) noexcept;

	size_t get_pids_for_uprobe(pid_t *pidarr, size_t maxpids) const noexcept;

	friend inline bool operator== (const std::shared_ptr<TCP_LISTENER> &lhs, const NS_IP_PORT & ser) noexcept
	{
		auto 			pdata = lhs.get();
		
		return (pdata && (pdata->ns_ip_port_.inode_ == ser.inode_) && (pdata->ns_ip_port_.ip_port_.port_ == ser.ip_port_.port_) && 
				(pdata->is_any_ip_ || (pdata->ns_ip_port_.ip_port_.ipaddr_ == ser.ip_port_.ipaddr_)));
	}

};	

using TCP_LISTENER_ELEM_TYPE		= RCU_HASH_WRAPPER<NS_IP_PORT, std::shared_ptr<TCP_LISTENER>>;
using TCP_LISTENER_HASH_TABLE		= RCU_HASH_TABLE <NS_IP_PORT, TCP_LISTENER_ELEM_TYPE>;

class DEPENDS_LISTENER
{
public :	
	RCU_HASH_CLASS_MEMBERS(uint64_t, DEPENDS_LISTENER);

	uint64_t			last_clock_usec_	{0};
	uint64_t			inter_bytes_sent_	{0};
	uint64_t			total_bytes_sent_	{0};
	uint64_t			total_bytes_rcvd_	{0};

	uint64_t			status_bits_		{0};

	uint64_t			last_chg_cusec_		{0};
	std::weak_ptr<TCP_LISTENER>	weaklisten_;
	TCP_LISTENER			*plistener_		{nullptr};
	NS_IP_PORT			ns_ip_port_;
	uint64_t			listener_glob_id_	{0};
	uint64_t			listener_madhava_id_	{0};

	int				curr_nconns_active_	{0};

	bool				is_valid_depend_	{false};	// Initially set as rejected
	bool				is_any_ip_		{false};
	char				identifier_str_[118];
	char				domain_name_[64];

	// Used for a local listener
	DEPENDS_LISTENER(const NS_IP_PORT & ns_ip_port, uint64_t clock_usec, const char * ident_str, bool is_any_ip, std::weak_ptr<TCP_LISTENER> weaklisten, TCP_LISTENER * plistener, uint64_t listener_glob_id, const char *domain_name = nullptr) noexcept
		: last_clock_usec_(clock_usec), last_chg_cusec_(clock_usec), weaklisten_(std::move(weaklisten)), plistener_(plistener), 
		ns_ip_port_(ns_ip_port), listener_glob_id_(listener_glob_id), is_any_ip_(is_any_ip)
	{
		GY_STRNCPY(identifier_str_, ident_str, sizeof(identifier_str_));

		if (domain_name) {
			GY_STRNCPY(domain_name_, domain_name, sizeof(domain_name_));
		}	
		else {
			*domain_name_ = 0;
		}	
	}	
	
	// For external listeners which have been resolved by Madhava
	DEPENDS_LISTENER(const GY_IP_ADDR & server_ip, uint16_t server_port, const char * ser_comm, uint64_t clock_usec, uint64_t listener_glob_id, uint64_t listener_madhava_id, const char *domain_name) noexcept
		: last_clock_usec_(clock_usec), last_chg_cusec_(clock_usec), ns_ip_port_(server_ip, server_port, 0), 
		listener_glob_id_(listener_glob_id), listener_madhava_id_(listener_madhava_id)
	{

		STR_WR_BUF			strbuf(identifier_str_, sizeof(identifier_str_));

		strbuf.appendconst("External Listener : ");
		ns_ip_port_.ip_port_.print_string(strbuf);

		strbuf.appendfmt(" : ID %016lx : \'%s\'", listener_glob_id_, ser_comm);

		if (*domain_name) {
			GY_STRNCPY(domain_name_, domain_name, sizeof(domain_name_));
		}	
		else {
			*domain_name_ = 0;
		}	
	}	

	// For external unresolved listeners 
	DEPENDS_LISTENER(const IP_PORT & ip_port, uint64_t clock_usec, const char *domain_name) noexcept
		: last_clock_usec_(clock_usec), last_chg_cusec_(clock_usec), ns_ip_port_(ip_port, 0)
	{
		STR_WR_BUF			strbuf(identifier_str_, sizeof(identifier_str_));

		strbuf.appendconst("External Unresolved Listener : ");
		ns_ip_port_.ip_port_.print_string(strbuf);

		if (*domain_name) {
			GY_STRNCPY(domain_name_, domain_name, sizeof(domain_name_));
		}	
		else {
			*domain_name_ = 0;
		}	
	}	

	bool is_valid_depend() const noexcept
	{
		return is_valid_depend_;
	}

	bool is_rejected_depend() const noexcept
	{
		return !is_valid_depend_;
	}

	bool is_remote_listener() const noexcept
	{
		return plistener_ == nullptr;
	}	

	friend inline bool operator== (const DEPENDS_LISTENER & lhs, uint64_t ser_glob_id) noexcept
	{
		return lhs.listener_glob_id_ == ser_glob_id;
	}

	static int rcu_match_ip_port(struct cds_lfht_node *pht_node, const void *pkey) noexcept
	{
		const DEPENDS_LISTENER	*pactdata = GY_CONTAINER_OF(pht_node, DEPENDS_LISTENER, cds_node_);	
		const IP_PORT		*pipport = static_cast<decltype(pipport)>(pkey);						
																	
		return pactdata->ns_ip_port_.ip_port_ == *pipport;
	}	
};

using DEPENDS_LISTEN_ID_TBL			= RCU_HASH_TABLE <uint64_t /* listener_glob_id_ */, DEPENDS_LISTENER>;
using DEPENDS_LISTEN_IP_PORT_TBL		= RCU_HASH_TABLE <IP_PORT, DEPENDS_LISTENER, std::default_delete<DEPENDS_LISTENER>, DEPENDS_LISTENER::rcu_match_ip_port>;

class TCP_SOCK_HANDLER;

class RELATED_LISTENERS
{
public :	
	struct LISTENER_TASK_STATUS
	{
		uint64_t			last_usec_clock_		{0};
		uint32_t			tasks_delay_usec_		{0};
		uint32_t			tasks_cpudelay_usec_		{0};
		uint32_t			tasks_blkiodelay_usec_		{0};
		int				tasks_user_cpu_			{0};
		int				tasks_sys_cpu_			{0};
		int				tasks_rss_mb_			{0};
		int				last_ntasks_issue_		{0};	// Gives only the current interval (5 sec) task count
		int				last_ntasks_noissue_		{0};	// Gives only the current interval (5 sec) task count
		uint8_t				issue_bit_hist_			{0};	// 8 * 5 = 40 sec history
		uint8_t				severe_issue_bit_hist_		{0};	// 8 * 5 = 40 sec history
		bool				is_delay_			{false};

		inline void set_task_issue(uint64_t clock_usec, uint32_t tasks_delay_usec, uint32_t tasks_cpudelay_usec, uint32_t tasks_blkiodelay_usec, \
				bool is_issue, bool is_severe, bool is_delay, int ntasks_issue, int ntasks_noissue, int tasks_user_cpu, int tasks_sys_cpu, int tasks_rss_mb) noexcept
		{
			issue_bit_hist_ 	<<= 1;
			severe_issue_bit_hist_ 	<<= 1;

			last_ntasks_issue_	= 0;
			last_ntasks_noissue_	= 0;

			last_usec_clock_ 	= clock_usec;

			tasks_delay_usec_	= tasks_delay_usec;
			tasks_cpudelay_usec_	= tasks_cpudelay_usec;
			tasks_blkiodelay_usec_	= tasks_blkiodelay_usec;

			tasks_user_cpu_		= tasks_user_cpu;
			tasks_sys_cpu_		= tasks_sys_cpu;
			tasks_rss_mb_		= tasks_rss_mb;

			last_ntasks_issue_ 	= ntasks_issue;
			last_ntasks_noissue_	= ntasks_noissue;

			issue_bit_hist_		|= uint8_t(is_issue);
			severe_issue_bit_hist_	|= uint8_t(is_severe);

			is_delay_		= is_delay;
		}	

		int recent_task_issue(uint64_t curr_clock_usec, uint32_t & tasks_delay_usec, uint32_t & tasks_cpudelay_usec, uint32_t & tasks_blkiodelay_usec, \
				uint8_t & is_issue, uint8_t & is_severe, bool & is_delay, int & ntasks_issue, int & ntasks_noissue, \
				int & tasks_user_cpu, int & tasks_sys_cpu, int & tasks_rss_mb, int bitmap = 0x3) const noexcept
		{
			if ((int64_t)curr_clock_usec - (int64_t)last_usec_clock_ > (int64_t)GY_USEC_PER_SEC * 4) {
				// Stale data
				return -1;
			}	
			
			tasks_delay_usec	= tasks_delay_usec_;
			tasks_cpudelay_usec	= tasks_cpudelay_usec_;
			tasks_blkiodelay_usec	= tasks_blkiodelay_usec_;
			tasks_user_cpu		= tasks_user_cpu_;
			tasks_sys_cpu		= tasks_sys_cpu_;
			tasks_rss_mb		= tasks_rss_mb_;

			// By default we just check the last 2 states (0x3) 10 sec
			
			is_issue		= (issue_bit_hist_ & bitmap);	
			is_severe		= (severe_issue_bit_hist_ & bitmap);	

			is_delay		= is_delay_;

			ntasks_issue 		= last_ntasks_issue_;
			ntasks_noissue		= last_ntasks_noissue_;

			return 0; 
		}
	};	

	WEAK_LISTEN_TABLE			related_table_			{8, 8, 1024, true, false};
	LISTENER_TASK_STATUS			task_status_;		

	DEPENDS_LISTEN_ID_TBL			id_depends_			{8, 8, 1024, true, false};
	DEPENDS_LISTEN_IP_PORT_TBL		ipport_depends_			{8, 8, 1024, true, false};

	uint64_t				tstart_usec_			{0};
	uint64_t				inode_check_cusec_		{0};

	uint64_t				curr_bytes_inbound_		{0};

	uint64_t				updated_clock_usec_		{0};

	uint64_t				req_seen_status_		{0};

	gy_atomic<uint32_t>			nlocal_id_depends_		{0};	
	int					curr_nconns_active_		{0};
	int					last_nconns_active_		{0};

	union {
		uint32_t			dflags_				{0};
		struct {
			bool			is_pre_existing_ : 1;
			bool			is_cluster_listen_ : 1;
			bool			is_cluster_mesh_ : 1;
			bool			is_cluster_service_ip_ : 1;
			bool			is_cluster_match_seen_ : 1;
		};
	};

	char					init_comm_[TASK_COMM_LEN]	{};

	char					tagbuf_[63]			{};
	uint8_t					tag_len_			{0};
	time_t					tlast_tag_			{0};

	
	RELATED_LISTENERS(TCP_LISTENER * plistener, bool is_pre_existing = false) 
		: tstart_usec_(plistener->tstart_usec_)
	{
		is_pre_existing_  = is_pre_existing;
		std::memcpy(init_comm_, plistener->comm_, sizeof(init_comm_));
	}		

	uint64_t get_related_id() const noexcept
	{
		return (int64_t)this;
	}

	LISTENER_TASK_STATUS get_task_stats() const noexcept
	{
		return task_status_;
	}	

	int update_dependency(TCP_SOCK_HANDLER *pglobhdlr, TCP_CONN *ptcp, uint64_t bytes_sent, uint64_t bytes_rcvd, uint64_t clock_usec, TCP_LISTENER * pdependlisten = nullptr) noexcept;
};	

class TCP_XPUT_STATS
{
public :	
	std::weak_ptr<TCP_CONN>		connweak_;
	int64_t				stat_			{0};

	TCP_XPUT_STATS(std::weak_ptr<TCP_CONN> weakc, int64_t nbytes) noexcept : 
		connweak_(std::move(weakc)), stat_(nbytes)
	{}

	TCP_XPUT_STATS(const TCP_XPUT_STATS &)				= default;
	TCP_XPUT_STATS(TCP_XPUT_STATS &&) noexcept			= default;
	TCP_XPUT_STATS & operator= (const TCP_XPUT_STATS &)		= default;
	TCP_XPUT_STATS & operator= (TCP_XPUT_STATS &&) noexcept		= default;

	~TCP_XPUT_STATS() noexcept					= default;

	struct TCP_XPUT_STATS_TOP
	{
		bool operator() (const TCP_XPUT_STATS & lhs, const TCP_XPUT_STATS & rhs) const noexcept
		{
			return lhs.stat_ > rhs.stat_;
		}	
	};	
};	


class DNS_MAPPING;

static constexpr int				INET_DIAG_INTERVAL_SECS = 15;
static constexpr int				TIMEOUT_INET_DIAG_SECS = 300;

class TCP_SOCK_HANDLER final
{
public :	
	static constexpr size_t			TCP_MAX_TOP_N = 20;

	using XPUT_VEC				= INLINE_STACK_VECTOR<TCP_XPUT_STATS, sizeof(TCP_XPUT_STATS) * TCP_MAX_TOP_N>;
	using TCP_XPUT_TOP_N 			= BOUNDED_PRIO_QUEUE<TCP_XPUT_STATS, TCP_XPUT_STATS::TCP_XPUT_STATS_TOP, NULL_MUTEX, XPUT_VEC>;
	
	using TCP_LISTEN_AGGR_MAP		= std::unordered_map<uint64_t, std::unordered_set<int64_t, GY_JHASHER<int64_t>>, GY_JHASHER<uint64_t>>;
	using DIAG_LOAD_BL_MAP			= std::unordered_map<IP_PORT, std::unordered_map<uint64_t, uint64_t, GY_JHASHER<uint64_t>>, IP_PORT::IP_PORT_HASH>;
	
	using LIST_HASH_SET			= INLINE_STACK_HASH_SET<uint32_t, 256 * 1024, GY_JHASHER<uint32_t>>;
	using ActiveConnMap	 		= INLINE_STACK_HASH_MAP<std::pair<uint64_t, uint64_t>, comm::ACTIVE_CONN_STATS, 1024 * (sizeof(comm::ACTIVE_CONN_STATS) + 16 + 8), 
									GY_JHASHER<std::pair<uint64_t, uint64_t>, true>>;
	
	using CLI_IP_HASH_TABLE			= RCU_HASH_TABLE <GY_IP_ADDR, CLI_IP>;

	static constexpr size_t			MAX_LISTENER_CACHE_SZ = 4;

	TASK_HANDLER				*ptask_handler_;
	DNS_MAPPING				*pdns_mapping_;
	GY_MACHINE_ID				machineid_;

	NAT_HASH_TABLE				nat_tbl_;
	NAT_HASH_TABLE				nat_cache_tbl_;
	bool					nat_curr_req_		{false};
	GY_THREAD				nat_thr_;

	MAKE_CLASS_FUNC_WRAPPER_NO_ARG(TCP_SOCK_HANDLER, nat_conntrack_thread);

	THR_POOL_ALLOC				conn_v4_pool_		{sizeof(TCP_CONN) + 16, 16 * 1024, false};
	THR_POOL_ALLOC				conn_v4_elem_pool_	{sizeof(TCP_CONN_ELEM_TYPE) + 8, 16 * 1024, false};
	DATA_BUFFER				conn_v4_cache_;
	TCP_CONN_HASH_TABLE			tcp_tbl_;
	pthread_t				tcp_v4_perf_tid_	{0};
	pthread_t				tcp_v6_perf_tid_	{0};
	THR_POOL_ALLOC				conn_v6_pool_		{sizeof(TCP_CONN) + 16, 16 * 1024, false};
	THR_POOL_ALLOC				conn_v6_elem_pool_	{sizeof(TCP_CONN_ELEM_TYPE) + 8, 16 * 1024, false};
	DATA_BUFFER				conn_v6_cache_;

	alignas(64) std::shared_ptr <TCP_LISTENER>	ipv4_listen_cache_[MAX_LISTENER_CACHE_SZ];
	alignas(64) TCP_LISTENER_HASH_TABLE		listener_tbl_;
	alignas(64) std::shared_ptr <TCP_LISTENER>	ipv6_listen_cache_[MAX_LISTENER_CACHE_SZ];

	DATA_BUFFER				listen_cache_; 		
	pthread_t				listen_perf_tid_	{0};
	pthread_t				resp_v4_perf_tid_	{0};
	pthread_t				resp_v6_perf_tid_	{0};

	GY_MUTEX				listen_aggr_lock_;
	TCP_LISTEN_AGGR_MAP			listen_aggr_map_;
	
	std::atomic<uint64_t>			last_listener_del_cusec_	{0};

	ActiveConnMap				activeconnmap_;		// To be referenced only from inet_diag_thread() as no mutex protection
	TCP_XPUT_TOP_N				topnxput_;		// Use only from within the inet_diag_thread() as NULL_MUTEX specified
	time_t					tlast_active_send_	{0};
	size_t					ntcp_conns_		{0};
	size_t					nconn_recent_active_	{0};
	int					ntcp_coalesced_		{0};
	int					nlisten_missed_		{0};

	DATA_BUFFER				diag_cache_;
	NETNS_HASH_TABLE			netns_tbl_;
	GY_THREAD				inet_diag_thr_;
	uint64_t				start_inet_usec_	{get_usec_clock()};
	uint64_t				last_inet_diag_cusec_	{start_inet_usec_};
	uint64_t				last_depends_cusec_	{0};
	uint64_t				next_lbl_check_cusec_	{start_inet_usec_ + 5 * GY_USEC_PER_MINUTE};
	DIAG_LOAD_BL_MAP			diag_lbl_map_;
	int64_t					last_listener_nat_tsec_	{get_sec_time()};

	SvcInodeMap				svcinodemap_;		// Only updated by inet_diag_thr_
	std::optional<SVC_NET_CAPTURE>		svcnetcap_;
	bool					capture_errcode_	{true};
	bool					disable_api_capture_	{false};
	uint32_t				api_max_len_		{0};

	int64_t					next_listen_stat_tsec_	{last_listener_nat_tsec_ + 5 * 60};

	uint64_t				local_madhava_id_	{0};
	comm::HOST_STATE_NOTIFY			curr_host_status_;

	gy_atomic<uint64_t>			server_reset_cusec_	{0};

	CLI_IP_HASH_TABLE			nat_cli_ip_tbl_		{1};
	uint64_t				next_cli_check_cusec_	{0};

	DATA_BUFFER				missed_cache_;

	gy_atomic<bool>				to_reset_stats_		{false};

	std::unique_ptr <GY_EBPF>		pebpf_;

	MAKE_CLASS_FUNC_WRAPPER_NO_ARG(TCP_SOCK_HANDLER, inet_diag_thread);


	TCP_SOCK_HANDLER(uint8_t resp_sampling_percent = 50, bool capture_errcode = true, bool disable_api_capture = false, uint32_t api_max_len = 0);

	~TCP_SOCK_HANDLER()			= delete;		// No deletion allowed	

	static float get_bpf_qps_multiple(const GY_EBPF * pbpf = GY_EBPF::get_singleton()) noexcept
	{
		float		multiple_factor = 1.0f;

		/*
		 * Currently we set the response sampling period to 10 sec and split the sampling
		 * within that in 500 msec slots. If this changes, this needs to be updated...
		 */
		if (pbpf) {
			auto	samp_pct = pbpf->get_curr_sampling_pct();
			
			if (samp_pct > 0 && samp_pct <= 50) {
				// Be a bit conservative
				multiple_factor = 1.4;
			}
			else {
				multiple_factor = 1.0;
			}	
		}
		
		return multiple_factor;
	}

	bool flush_tcp_v4_cache() noexcept
	{
		return notify_tcp_conn(nullptr, 0ul /* is_conn_close */, false /* more_data */, conn_v4_cache_);
	}	

	bool flush_tcp_v6_cache() noexcept
	{
		return notify_tcp_conn(nullptr, 0ul /* is_conn_close */, false /* more_data */, conn_v6_cache_);
	}	

	bool flush_diag_tcp_cache() noexcept
	{
		return notify_tcp_conn(nullptr, 0ul /* is_conn_close */, false /* more_data */, diag_cache_);
	}	

	bool flush_missed_tcp_cache() noexcept
	{
		return notify_tcp_conn(nullptr, 0ul /* is_conn_close */, false /* more_data */, missed_cache_);
	}	

	class CONN_BPF_EVENT
	{
	public :	
		uint64_t		clock_usec_;
		uint64_t		bytes_received_;
		uint64_t		bytes_acked_;
		uint32_t		pid_;
		uint32_t		tid_;
		GY_IP_ADDR		saddr_;
		GY_IP_ADDR		daddr_;
		uint64_t		netns_;
		char 			comm_[TASK_COMM_LEN];
		uint16_t		sport_;
		uint16_t		dport_;
		uint8_t			type_;

		CONN_BPF_EVENT() noexcept
		{
			gy_safe_memset(this);
		}
		
		CONN_BPF_EVENT(struct tcp_ipv4_event_t *pevent) noexcept
			:
			clock_usec_(pevent->ts_ns/1000), bytes_received_(pevent->bytes_received), bytes_acked_(pevent->bytes_acked),
			pid_(pevent->pid), tid_(pevent->tid), saddr_(pevent->saddr), daddr_(pevent->daddr), netns_(pevent->netns),
			sport_(pevent->sport), dport_(pevent->dport), type_(pevent->type)
		{
			GY_STRNCPY(comm_, pevent->comm, sizeof(comm_));
		}		

		CONN_BPF_EVENT(struct tcp_ipv6_event_t *pevent) noexcept
			:
			clock_usec_(pevent->ts_ns/1000), bytes_received_(pevent->bytes_received), bytes_acked_(pevent->bytes_acked),
			pid_(pevent->pid), tid_(pevent->tid), saddr_(pevent->saddr), daddr_(pevent->daddr), netns_(pevent->netns),
			sport_(pevent->sport), dport_(pevent->dport), type_(pevent->type)
		{
			GY_STRNCPY(comm_, pevent->comm, sizeof(comm_));
		}		
	};	

	class SOCK_INODE_INFO
	{
	public :	
		ino_t				sock_inode_		{0};
		pid_t				pid_			{0};
		std::weak_ptr <TASK_STAT>	task_weak_;
		std::vector <pid_t>		pid_list_;
		char				comm_[TASK_COMM_LEN]	{};
	};	

	using SOCK_INODE_TABLE			= std::unordered_map<ino_t, SOCK_INODE_INFO, GY_JHASHER<ino_t>>;

	using SOCK_INODE_SET			= std::unordered_set<ino_t, GY_JHASHER<ino_t>>;

	static TCP_SOCK_HANDLER *		get_singleton() noexcept;
	static int				init_singleton(uint8_t resp_sampling_percent = 30, bool capture_errcode = true, bool disable_api_capture = false, uint32_t api_max_len = 0);

	struct LISTEN_STATS_CB
	{
		std::weak_ptr<TCP_LISTENER>	weaklisten_;
		comm::NEW_LISTENER		info_		{};
		char				cmdline_[comm::MAX_PROC_CMDLINE_LEN];

		LISTEN_STATS_CB(std::weak_ptr<TCP_LISTENER> weaklisten, const NS_IP_PORT & ns_ip_port, uint64_t glob_id, uint64_t aggr_glob_id, \
				uint64_t related_listen_id, uint64_t tstart_usec, uint64_t ser_aggr_task_id, bool is_any_ip, bool is_pre_existing, \
				bool no_aggr_stats, bool no_resp_stats, pid_t start_pid, const char *pcomm, const char *pcmdline) noexcept

				: weaklisten_(std::move(weaklisten)), info_(ns_ip_port, glob_id, aggr_glob_id, related_listen_id, tstart_usec, ser_aggr_task_id, 
				is_any_ip, is_pre_existing, no_aggr_stats, no_resp_stats, pcomm, start_pid, strlen(pcmdline) + 1)
		{
			std::memcpy(cmdline_, pcmdline, info_.cmdline_len_ - 1);
			cmdline_[info_.cmdline_len_ - 1] = 0;
		}

	};	

	using LISTEN_STATS_CB_TBL = std::unordered_map<uint64_t, LISTEN_STATS_CB, GY_JHASHER<uint64_t>>;

	uint32_t machine_id_hash() const noexcept
	{
		return machineid_.get_hash();
	}	
	
	void handle_ip_vs_conn_event(ip_vs_conn_event_t * pevent, bool more_data) noexcept;
	int nat_check_cache() noexcept;
	int nat_check_conns() noexcept;
	int nat_conntrack_thread() noexcept;

	void handle_ipv4_conn_event(tcp_ipv4_event_t * pevent, bool more_data) noexcept;
	void handle_ipv6_conn_event(tcp_ipv6_event_t * pevent, bool more_data) noexcept;
	int tcp_check_conns() noexcept;
	bool notify_tcp_conn(TCP_CONN *pconn, uint64_t close_usec_time, bool more_data, DATA_BUFFER & cache, const char *pcli_cmdline = nullptr, size_t cli_cmdline_len = 0) noexcept;
	int notify_init_tcp_conns() noexcept;

	int update_cli_conn_info_madhava(const comm::MP_CLI_TCP_INFO *pinfo, int nevents, const uint8_t * const pendptr) noexcept;
	int update_ser_conn_info_madhava(const comm::MP_SER_TCP_INFO *pinfo, int nevents, const uint8_t * const pendptr) noexcept;
	int handle_api_trace_set(const comm::REQ_TRACE_SET *preq, int pinfo) noexcept;

	void handle_listener_event(tcp_listener_event_t * pevent, bool more_data) noexcept;
	bool notify_new_listener(TCP_LISTENER *plistener, bool more_data, bool is_listen_event_thread); 
	int notify_init_listeners() noexcept;
	int send_listen_taskmap() noexcept;

	int listener_inode_validate(int & nclconfirm) noexcept;
	int listener_cluster_check() noexcept;

	bool is_listener_deleted(const std::shared_ptr<TCP_LISTENER> & shrlisten) const noexcept;

	std::tuple<int, int, int> listener_stats_update(const std::shared_ptr<SERVER_CONNTRACK> & servshr, bool cpu_issue, bool mem_issue, GlobIDInodeMap &delidmap) noexcept;
	bool host_status_update(const std::shared_ptr<SERVER_CONNTRACK> & servshr, bool cpu_issue, bool mem_issue, bool severe_cpu_issue, bool severe_mem_issue, \
		bool cpu_idle, bool mem_idle, uint32_t ntaskissue, uint32_t ntasksevere, uint32_t ntasks, uint32_t nlistissue, uint32_t nlistsevere, uint32_t nlisten) noexcept;

	void handle_ipv4_resp_event(tcp_ipv4_resp_event_t * pevent, bool more_data) noexcept;
	void handle_ipv6_resp_event(tcp_ipv6_resp_event_t * pevent, bool more_data) noexcept;
	
	int inet_diag_thread() noexcept;
	void handle_create_netns(create_ns_data_t * pevent, ino_t inode) noexcept;
	void handle_create_ns_event(create_ns_data_t *pevent, bool more_data) noexcept;

	NETNS_ELEM * get_netns_locked(ino_t inode) const noexcept
	{
		assert(false == gy_thread_rcu().is_rcu_thread_offline());
		
		return netns_tbl_.lookup_single_elem_locked(inode, get_uint64_hash(inode));
	}

	void reset_server_stats() noexcept
	{
		to_reset_stats_.store(true, std::memory_order_release);

		last_depends_cusec_ = 0;
		last_listener_nat_tsec_ = get_proc_start();

		server_reset_cusec_.store(get_usec_clock());
	}	


private :

	int handle_bpf_connect(const CONN_BPF_EVENT & evt, bool more_data, bool from_v4_thread, THR_POOL_ALLOC & connpool, THR_POOL_ALLOC & connelempool) noexcept;
	int handle_bpf_accept(const CONN_BPF_EVENT & evt, bool more_data, bool from_v4_thread, THR_POOL_ALLOC & connpool, THR_POOL_ALLOC & connelempool) noexcept;
	int handle_bpf_close_cli(const CONN_BPF_EVENT & evt, bool more_data, bool from_v4_thread) noexcept;
	int handle_bpf_close_ser(const CONN_BPF_EVENT & evt, bool more_data, bool from_v4_thread) noexcept;

	void handle_tcp_resp_event(const NS_IP_PORT & ser_nsipport, IP_PORT cli_ip_port, uint32_t tcur, int tresp_msec, bool is_ipv4, bool more_data) noexcept;
	int fetch_tcp_listeners(std::unique_ptr<LISTEN_STATS_CB_TBL> && statstbl_uniq, size_t statslen) noexcept;
	void handle_server_tcp_listeners(comm::LISTENERS_INFO_STATS_RESP *plist, uint8_t *pendptr, LISTEN_STATS_CB_TBL & statstbl) noexcept;

	int handle_nat_info(const struct nlmsghdr *pnlh) noexcept;
	int nat_conntrack_thread(bool & init_done, int nerrors) noexcept;
	int nl_conntrack_get_current() noexcept;
	int nl_conntrack_event_mon(bool & init_done, int nerrors) noexcept;

	int populate_ns_tbl();
	int populate_inode_tbl(SOCK_INODE_TABLE & socktbl, bool get_all);

	void upd_new_listen_task(TCP_LISTENER *pnewlistener, TASK_STAT *ptask, uint64_t curr_tusec) noexcept;

	int upd_conn_from_diag(struct inet_diag_msg *pdiag_msg, int rta_len, NETNS_ELEM *pnetns, uint64_t clock_diag, uint64_t tusec_diag, \
			SOCK_INODE_TABLE *psocktbl, SOCK_INODE_SET * pchkset, LIST_HASH_SET *);
	int add_conn_from_diag(struct inet_diag_msg *pdiag_msg, int rta_len, NETNS_ELEM *pnetns, uint64_t clock_diag, \
			SOCK_INODE_TABLE *psocktbl, LIST_HASH_SET *, TASK_PGTREE_MAP * ptreemap, bool only_listen);
	int do_inet_diag_info(NETNS_ELEM *pnetns, uint8_t *pdiagbuf, bool add_conn, bool add_listen,	\
			SOCK_INODE_TABLE *psocktbl, SOCK_INODE_SET *pchkset, TASK_PGTREE_MAP * ptreemap) noexcept;
	void cleanup_lbl_map() noexcept;					

	int check_listener_depends_misc() noexcept;
	bool send_active_stats() noexcept;
};	

} // namespace gyeeta

