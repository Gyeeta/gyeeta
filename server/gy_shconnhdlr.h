//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma			once

#include		"gy_common_inc.h"
#include		"gy_msg_comm.h"
#include		"gy_multi_proc_comm.h"
#include		"gy_pool_alloc.h"
#include		"gy_epoll_conntrack.h"
#include		"gy_rcu_inc.h"
#include		"gy_refcnt.h"
#include		"gy_comm_proto.h"
#include		"gy_web_proto.h"
#include		"gy_host_conn_flist.h"
#include		"gy_listen_sock.h"
#include		"gy_sys_hardware.h"
#include		"gy_shsocket.h"
#include		"gy_sdb_schema.h"
#include		"gy_stack_container.h"
#include		"gy_folly_stack_map.h"
#include		"gy_stream_json.h"
#include		"gy_postgres.h"
#include		"gy_scheduler.h"
#include		"gy_query_common.h"

#include		"folly/MPMCQueue.h"
#include 		"folly/Function.h"
#include		"folly/concurrency/AtomicSharedPtr.h" 

#include 		<forward_list>
#include 		<unordered_map>

namespace gyeeta {
namespace shyama {

class SHYAMA_C;
class SA_SETTINGS_C;
class SHALERT_HDLR;
class ALERTMGR;

using S512_PROC_ELEM 	= MULTI_COMM_SINGLETON::SINGLE_PROC_SZ_512::MULTI_PROC_ELEM;
using STATS_STR_MAP	= std::unordered_map<const char *, int64_t, GY_JHASHER<const char *>>;

class SHCONN_HANDLER
{
public :	
	static constexpr size_t			MAX_ACCEPT_THREADS		= 2;
	static constexpr size_t			MAX_L1_THREADS			= 8;
	static constexpr size_t			MAX_L2_DB_THREADS		= 4;
	static constexpr size_t			MAX_L2_MISC_THREADS		= 8;
	static constexpr size_t			MAX_L2_ALERT_THREADS		= 1;
	static constexpr size_t			MAX_L2_THREADS			= MAX_L2_DB_THREADS + MAX_L2_MISC_THREADS + MAX_L2_ALERT_THREADS;

	// Multiple L2 threads will handle each pool
	static constexpr size_t			MAX_L2_DB_POOLS 		= 1;
	static constexpr size_t			MAX_L2_MISC_POOLS 		= 2;
	static constexpr size_t			MAX_L2_ALERT_POOLS 		= 1;
	static constexpr size_t			MAX_MPMC_ELEMS			= 1024 * 16;

	static constexpr size_t			MAX_CONCURRENT_ACCEPT_CONNS	= 2048;
	static constexpr size_t			MAX_TCP_LISTENERS		= 16;

	// Partial Message Reads / Writes will wait for min this timeout interval and subsequently the conn will close
	static constexpr uint64_t 		MAX_CONN_DATA_TIMEOUT_USEC 	{60 * GY_USEC_PER_SEC}; 	// 60 sec

	// Max Idle time to close persistent connections with no traffic to avoid build up of reqs/callbacks...
	static constexpr uint64_t 		MAX_CONN_IDLE_TIMEOUT_USEC 	{15 * GY_USEC_PER_MINUTE}; 	// 15 min

	// Max Time to keep a Host entry in RAM when that host is not connected
	static constexpr uint64_t 		MAX_HOST_DISCONNECT_RAM_USEC 	{1 * GY_USEC_PER_DAY}; 		// 1 day

	static constexpr size_t			MAX_PERSISTENT_CONNS_PER_HOST	{64};

	static constexpr size_t			MAX_NODE_INSTANCES		{64};

	struct MADHAVA_INFO;
	struct NODE_INFO;
	struct L1_PARAMS;
	class SHCONNTRACK;

	using ASYNC_SOCK_CB			= T_ASYNC_SOCK_CB<SHCONNTRACK>;

	class SHCONNTRACK : public EPOLL_CONNTRACK, public ASYNC_CB_HANDLER <SHCONNTRACK>, public std::enable_shared_from_this <SHCONNTRACK>
	{
	public :	
		std::shared_ptr <MADHAVA_INFO>	madhava_shr_;
		std::shared_ptr <NODE_INFO>	node_shr_;
		const L1_PARAMS			*pl1_				{nullptr};

		comm::HOST_TYPES_E		host_type_			{comm::HOST_INVALID};
		comm::COMM_HEADER::HDR_MAGIC_E	comm_magic_			{comm::COMM_HEADER::INV_HDR_MAGIC};
		comm::CLI_TYPE_E		cli_type_			{comm::CLI_TYPE_REQ_RESP};

		bool				is_registered_			{false};
		bool				is_adhoc_			{false};

		// See EPOLL_CONNTRACK constructor for comments regarding arguments
		SHCONNTRACK(struct sockaddr_storage *psockaddr, int sockfd, int epollfd, void *epoll_data, size_t init_rdbuf_sz, size_t init_wrbuf_sz, bool use_pipeline, uint64_t max_idle_usec = 0, uint64_t pending_timeout_usec = 0, bool close_conn_on_wr_complete = false, bool is_outgoing = false, uint64_t start_clock_usec = get_usec_clock())
			: EPOLL_CONNTRACK(psockaddr, sockfd, epollfd, epoll_data, init_rdbuf_sz, init_wrbuf_sz, use_pipeline, max_idle_usec, pending_timeout_usec, 
					close_conn_on_wr_complete, is_outgoing, start_clock_usec),
			ASYNC_CB_HANDLER<SHCONNTRACK>(this)
		{}	

		// See EPOLL_CONNTRACK constructor for comments regarding arguments
		SHCONNTRACK(const IP_PORT & peer_ipport, int sockfd, int epollfd, void *epoll_data, size_t init_rdbuf_sz, size_t init_wrbuf_sz, bool use_pipeline, uint64_t max_idle_usec = 0, uint64_t pending_timeout_usec = 0, bool close_conn_on_wr_complete = false, bool is_outgoing = false, uint64_t start_clock_usec = get_usec_clock()) 
			: EPOLL_CONNTRACK(peer_ipport, sockfd, epollfd, epoll_data, init_rdbuf_sz, init_wrbuf_sz, use_pipeline, max_idle_usec, pending_timeout_usec, 
					close_conn_on_wr_complete, is_outgoing, start_clock_usec),
			ASYNC_CB_HANDLER<SHCONNTRACK>(this)
		{}	

		~SHCONNTRACK() noexcept
		{
			if (host_type_ == comm::HOST_MADHAVA && madhava_shr_) {
				madhava_shr_->del_conn(this, host_type_);
			}	
			else if (host_type_ == comm::HOST_NODE_WEB && node_shr_) {
				node_shr_->del_conn(this, host_type_);
			}	
		}	

		std::shared_ptr<MADHAVA_INFO> get_madhava_shared() const noexcept
		{
			return madhava_shr_;
		}	

		std::shared_ptr<NODE_INFO> get_node_shared() const noexcept
		{
			return node_shr_;
		}	

		char * print_conn(STR_WR_BUF & strbuf) const noexcept
		{
			strbuf.appendfmt("Connection from Remote %s Conn Type %s ", comm::host_type_string(host_type_), comm::cli_type_string(cli_type_));

			this->print_peer(strbuf);

			this->print_cb_stats(strbuf);

			return strbuf.buffer();
		}	

		bool is_registered() const noexcept
		{
			return is_registered_;
		}
		
		void set_registered() noexcept
		{
			GY_WRITE_ONCE(is_registered_, true);
		}	

		void set_comm_magic(comm::COMM_HEADER::HDR_MAGIC_E hdr) noexcept
		{
			comm_magic_ = hdr;
		}	

		comm::COMM_HEADER::HDR_MAGIC_E get_comm_magic() const noexcept
		{
			return comm_magic_;
		}	

		void set_adhoc_conn(bool adhoc) noexcept
		{
			is_adhoc_ = adhoc;
			EPOLL_CONNTRACK::set_close_conn_on_wr_complete(adhoc);
		}	

		bool is_adhoc() const noexcept
		{
			return is_adhoc_;
		}	
	};	

	using MAP_CONNTRACK 			= std::unordered_map<int, std::shared_ptr<SHCONNTRACK>, GY_JHASHER<int>>;
	using CONN_NODE_ELEM			= MAP_CONNTRACK::node_type; 

	enum TTYPE_E : uint8_t
	{
		TTYPE_ACCEPT		= 0,
		TTYPE_L1,
		TTYPE_L2_DB,
		TTYPE_L2_MISC,
		TTYPE_L2_ALERT,
	};

	enum SHNOTIFY_TYPE_E : uint32_t
	{
		NOTIFY_IGNORE		= 0,
		NOTIFY_ACCEPT,
		NOTIFY_DB_WRITE_ARR,
		NOTIFY_L1_SEND_DATA,
		NOTIFY_L1_MISC_CMD,
		NOTIFY_UNIQ_DATA,
	};

	struct ACC_NOTIFY_ONE
	{
		CONN_NODE_ELEM			connnode_;			// Map node allocated in the accept thread
		uint64_t			start_clock_usec_	{0};
		int				sockfd_			{0};

		ACC_NOTIFY_ONE() noexcept				= default;

		ACC_NOTIFY_ONE(CONN_NODE_ELEM && connnode, uint64_t start_clock_usec, int sockfd) noexcept
			: connnode_(std::move(connnode)), start_clock_usec_(start_clock_usec), sockfd_(sockfd)
		{}	

		ACC_NOTIFY_ONE(const ACC_NOTIFY_ONE &)			= delete;

		ACC_NOTIFY_ONE(ACC_NOTIFY_ONE &&) 			= default;
	
		~ACC_NOTIFY_ONE() 					= default;
	};	

	struct DB_WRITE_ARR final
	{
		struct DB_WRITE_ONE
		{
			uint8_t			*pwrbuf_;
			uint32_t		wrlen_;
			comm::COMM_TYPE_E	data_type_;
		};	

		const L1_PARAMS			*pl1_src_		{nullptr};
		uint64_t			start_clock_usec_	{0};
		std::shared_ptr <SHCONNTRACK>	shrconn_;
		DB_WRITE_ONE			dbonearr_[8]		{};
		void				*pbufstart_		{nullptr};
		FREE_FPTR			free_fp_		{nullptr};		// Will be called for pbufstart_
		uint32_t			ndbs_			{0};	
		comm::COMM_HEADER::HDR_MAGIC_E 	comm_magic_		{comm::COMM_HEADER::INV_HDR_MAGIC};
		TTYPE_E				dest_thr_type_		{TTYPE_L2_MISC};

		DB_WRITE_ARR(comm::COMM_HEADER::HDR_MAGIC_E comm_magic) noexcept
			: comm_magic_(comm_magic)
		{}	

		DB_WRITE_ARR(const DB_WRITE_ARR &) 			= delete;

		DB_WRITE_ARR & operator= (const DB_WRITE_ARR &)		= delete;

		DB_WRITE_ARR(DB_WRITE_ARR && other) noexcept :
			pl1_src_(other.pl1_src_), start_clock_usec_(other.start_clock_usec_), shrconn_(std::move(other.shrconn_)), pbufstart_(std::exchange(other.pbufstart_, nullptr)),
			free_fp_(std::exchange(other.free_fp_, nullptr)), ndbs_(std::exchange(other.ndbs_, 0)), comm_magic_(other.comm_magic_), dest_thr_type_(other.dest_thr_type_)
		{
			std::memcpy(dbonearr_, other.dbonearr_, sizeof(dbonearr_));
		}	

		DB_WRITE_ARR & operator= (DB_WRITE_ARR && other) noexcept	
		{
			if (this != &other) {
				this->~DB_WRITE_ARR();

				new (this) DB_WRITE_ARR(std::move(other));
			}	

			return *this;
		}	

		~DB_WRITE_ARR() noexcept
		{
			dealloc();
		}

		TTYPE_E get_dest_thr_type() const noexcept
		{
			return dest_thr_type_;
		}	

		void dealloc()
		{
			if (pbufstart_ && free_fp_) {
				(*free_fp_)(pbufstart_);
			}	
			reset();
		}

		// Reset only the data buffers. Keep the shrconn_ and other params
		void reset()
		{
			pbufstart_ 	= nullptr;
			ndbs_		= 0;
		}	

		bool validate() const noexcept
		{
			if ((ndbs_ > GY_ARRAY_SIZE(dbonearr_)) || (!shrconn_)) {
				return false;
			}

			for (size_t i = 0; i < ndbs_; ++i) {
				auto & dbone 		= dbonearr_[i];

				if (!dbone.pwrbuf_ || dbone.wrlen_ < sizeof(comm::COMM_HEADER)) {
					return false;
				}	
				
				comm::COMM_HEADER	*phdr = (comm::COMM_HEADER *)dbone.pwrbuf_;

				if (phdr->get_total_len() != dbone.wrlen_) {
					return false;
				}
			}
			
			return true;
		}	

	};

	struct L1_SEND_DATA
	{
		const L1_PARAMS			*pl1_src_		{nullptr};
		std::weak_ptr <SHCONNTRACK>	weakconn_;
		SHCONNTRACK			*pconn_			{nullptr};

		std::optional <ASYNC_SOCK_CB>	async_cb_;
		uint64_t			resp_usec_		{0};

		comm::COMM_TYPE_E		output_data_type_	{comm::COMM_MIN_TYPE};
		comm::COMM_HEADER::HDR_MAGIC_E 	comm_magic_		{comm::COMM_HEADER::INV_HDR_MAGIC};
		bool				close_conn_on_send_	{false};	

		L1_SEND_DATA() noexcept					= default;

		L1_SEND_DATA(const L1_PARAMS *pl1_src, std::weak_ptr<SHCONNTRACK> && weakconn, SHCONNTRACK *pconn, comm::COMM_HEADER::HDR_MAGIC_E comm_magic, comm::COMM_TYPE_E output_data_type, bool close_conn_on_send = false, uint64_t resp_usec = 0) noexcept
			: pl1_src_(pl1_src), weakconn_(std::move(weakconn)), pconn_(pconn), resp_usec_(resp_usec), 
			output_data_type_(output_data_type), comm_magic_(comm_magic), close_conn_on_send_(close_conn_on_send)
		{}
	
		L1_SEND_DATA(ASYNC_SOCK_CB && async_cb, const L1_PARAMS *pl1_src, std::weak_ptr<SHCONNTRACK> && weakconn, SHCONNTRACK *pconn, comm::COMM_HEADER::HDR_MAGIC_E comm_magic) noexcept
			: pl1_src_(pl1_src), weakconn_(std::move(weakconn)), pconn_(pconn), async_cb_(std::move(async_cb)), output_data_type_(comm::COMM_QUERY_CMD), comm_magic_(comm_magic)
		{}

		L1_SEND_DATA(const L1_SEND_DATA &) 				= delete;
		L1_SEND_DATA & operator= (const L1_SEND_DATA &)			= delete;

		L1_SEND_DATA(L1_SEND_DATA && other) noexcept			= default;
		L1_SEND_DATA & operator= (L1_SEND_DATA && other) noexcept	= default;

		~L1_SEND_DATA() noexcept
		{
			if (bool(async_cb_) && async_cb_->is_valid()) {
				try {
					async_cb_->fcb_(nullptr, nullptr, 0, nullptr, false /* is_expiry */, true /* is_error */);
				}
				catch(...) {
				}	
			}	
		}	

		bool is_cli_active() const noexcept
		{
			return !weakconn_.expired();
		}	

		bool to_close_conn() const noexcept
		{
			return close_conn_on_send_;
		}	

		bool is_async_cb() const noexcept
		{
			return async_cb_.has_value();
		}	
	};	

	enum L1_MISC_TYPE : int
	{
		L1_MISC_CLOSE_CONN		= 0,
	};

	struct L1_MISC_NOTIFY
	{
		const L1_PARAMS			*pl1_src_		{nullptr};
		std::weak_ptr <SHCONNTRACK>	weakconn_;
		SHCONNTRACK			*pconn_			{nullptr};
		L1_MISC_TYPE			misc_type_		{L1_MISC_CLOSE_CONN};
		alignas(8) char			errstr_[128]		{};
		uint32_t			errlen_			{0};

		L1_MISC_NOTIFY() noexcept					= default;

		L1_MISC_NOTIFY(const L1_PARAMS *pl1_src, std::weak_ptr<SHCONNTRACK> && weakconn, SHCONNTRACK *pconn, const char *errstr = nullptr, uint32_t errlen = 0) noexcept
			: pl1_src_(pl1_src), weakconn_(std::move(weakconn)), pconn_(pconn), misc_type_(L1_MISC_CLOSE_CONN)
		{
			if (errstr) {
				errlen_ = std::min<uint32_t>(errlen, sizeof(errstr_) - 1);
				std::memcpy(errstr_, errstr, errlen_);
			}			
		}

		L1_MISC_NOTIFY(const L1_MISC_NOTIFY &) 				= delete;
		L1_MISC_NOTIFY & operator= (const L1_MISC_NOTIFY &)		= delete;

		L1_MISC_NOTIFY(L1_MISC_NOTIFY && other) noexcept		= default;
		L1_MISC_NOTIFY & operator= (L1_MISC_NOTIFY && other) noexcept	= default;

		~L1_MISC_NOTIFY() noexcept					= default;

		bool is_cli_active() const noexcept
		{
			return !weakconn_.expired();
		}	
	};	
 
 	struct UNIQ_DATA
	{
		std::unique_ptr<char []>	uniq_;
		uint32_t			lenuniq_		{0};
		uint32_t			type_			{0};
		alignas(8) uint8_t		extdata_[128]		{};				
		uint8_t				lenext_			{0};

		UNIQ_DATA() noexcept					= default;

		UNIQ_DATA(std::unique_ptr<char []> && uniq, uint32_t lenuniq, uint32_t type, const void *extdata = nullptr, uint8_t lenext = 0) noexcept
			: uniq_(std::move(uniq)), lenuniq_(lenuniq), type_(type)
		{
			if (extdata && lenext && lenext <= sizeof(extdata_)) {
				std::memcpy(extdata_, extdata, lenext);
				lenext_ = lenext;
			}	
		}

		UNIQ_DATA(uint32_t type, const void *extdata, uint8_t lenext) noexcept
		{
			if (extdata && lenext && lenext <= sizeof(extdata_)) {
				type_ = type;
				std::memcpy(extdata_, extdata, lenext);
				lenext_ = lenext;
			}	
		}	

		UNIQ_DATA(const UNIQ_DATA &) 				= delete;
		UNIQ_DATA & operator= (const UNIQ_DATA &)		= delete;

		UNIQ_DATA(UNIQ_DATA && other) noexcept			= default;
		UNIQ_DATA & operator= (UNIQ_DATA && other) noexcept	= default;

		~UNIQ_DATA() noexcept					= default;

		bool validate(uint32_t minlenuniq, uint32_t minlenext = 0) const noexcept
		{
			if ((minlenuniq && !uniq_) || lenuniq_ < minlenuniq || lenext_ < minlenext) {
				return false;
			}	

			return true;
		}	
	};	

	class EV_NOTIFY_ONE final
	{
	public :	
		union EV_DATA_ONE 
		{
			ACC_NOTIFY_ONE			acc_;
			DB_WRITE_ARR			dbwrarr_;
			L1_SEND_DATA			l1_data_;
			L1_MISC_NOTIFY			l1_misc_;
			UNIQ_DATA			uniq_data_;

			void				*pdummy_;

			EV_DATA_ONE() : pdummy_(nullptr)
			{}

			~EV_DATA_ONE()
			{}
		};
		
		EV_DATA_ONE				data_;
		SHNOTIFY_TYPE_E				ntype_			{NOTIFY_IGNORE};	

		EV_NOTIFY_ONE() 			= default;

		EV_NOTIFY_ONE(ACC_NOTIFY_ONE && acc) noexcept
			: ntype_(NOTIFY_ACCEPT)
		{
			new (&data_.acc_) ACC_NOTIFY_ONE(std::move(acc));	
		}	

		EV_NOTIFY_ONE(DB_WRITE_ARR && dbwrarr) noexcept
			: ntype_(NOTIFY_DB_WRITE_ARR)
		{
			new (&data_.dbwrarr_) DB_WRITE_ARR(std::move(dbwrarr));	
		}	

		EV_NOTIFY_ONE(L1_SEND_DATA && l1data) noexcept
			: ntype_(NOTIFY_L1_SEND_DATA)
		{
			new (&data_.l1_data_) L1_SEND_DATA(std::move(l1data));
		}	
		
		EV_NOTIFY_ONE(L1_MISC_NOTIFY && l1_close) noexcept
			: ntype_(NOTIFY_L1_MISC_CMD)
		{
			new (&data_.l1_misc_) L1_MISC_NOTIFY(std::move(l1_close));
		}	

		EV_NOTIFY_ONE(UNIQ_DATA && uniq_data) noexcept
			: ntype_(NOTIFY_UNIQ_DATA)
		{
			new (&data_.uniq_data_) UNIQ_DATA(std::move(uniq_data));
		}	

		EV_NOTIFY_ONE(const EV_NOTIFY_ONE &)	= delete;	

		EV_NOTIFY_ONE(EV_NOTIFY_ONE && other) noexcept
			: ntype_(other.ntype_)
		{
			switch (ntype_) {
			
			case NOTIFY_ACCEPT :
				new (&data_.acc_) 	ACC_NOTIFY_ONE(std::move(other.data_.acc_));
				break;
			
			case NOTIFY_DB_WRITE_ARR :
				new (&data_.dbwrarr_)	DB_WRITE_ARR(std::move(other.data_.dbwrarr_));
				break;

			case NOTIFY_L1_SEND_DATA :
				new (&data_.l1_data_)	L1_SEND_DATA(std::move(other.data_.l1_data_));
				break;

			case NOTIFY_L1_MISC_CMD :
				new (&data_.l1_misc_) 	L1_MISC_NOTIFY(std::move(other.data_.l1_misc_));
				break;

			case NOTIFY_UNIQ_DATA :
				new (&data_.uniq_data_) UNIQ_DATA(std::move(other.data_.uniq_data_));
				break;


			default :
				break;
			}	
		}	

		EV_NOTIFY_ONE & operator=(EV_NOTIFY_ONE && other) noexcept
		{
			if (this != &other) {
				this->~EV_NOTIFY_ONE();
				
				new (this) EV_NOTIFY_ONE(std::move(other));
			}

			return *this;
		}

		~EV_NOTIFY_ONE() noexcept
		{
			switch (ntype_) {
			
			case NOTIFY_ACCEPT :
				data_.acc_.~ACC_NOTIFY_ONE();
				break;
			
			case NOTIFY_DB_WRITE_ARR :
				data_.dbwrarr_.~DB_WRITE_ARR();
				break;

			case NOTIFY_L1_SEND_DATA :
				data_.l1_data_.~L1_SEND_DATA();
				break;

			case NOTIFY_L1_MISC_CMD :
				data_.l1_misc_.~L1_MISC_NOTIFY();
				break;

			case NOTIFY_UNIQ_DATA :
				data_.uniq_data_.~UNIQ_DATA();
				break;

			default :
				break;
			}	

			ntype_	= NOTIFY_IGNORE;
		}	

		SHNOTIFY_TYPE_E get_type() const noexcept
		{
			return ntype_;
		}	
	};	

	using MPMCQ_COMM			= folly::MPMCQueue<EV_NOTIFY_ONE>;

	struct ACC_PARAMS
	{
		GY_THREAD			*pthread_	{nullptr};
		LISTEN_SOCK			*plisten_	{nullptr};
		int				listen_fd_	{-1};
		int				epollfd_	{-1};
		uint32_t			thr_num_	{0};
		TTYPE_E				thr_type_	{TTYPE_ACCEPT};
		char				descbuf_[64]	{};
	};	

	struct L1_PARAMS
	{
		GY_THREAD			*pthread_	{nullptr};
		MPMCQ_COMM			*psignalq_	{nullptr};
		int				epollfd_	{-1};
		int				signal_fd_	{-1};
		uint32_t			thr_num_	{0};
		TTYPE_E				thr_type_	{TTYPE_L1};
		char				descbuf_[64]	{};
	};	

	struct L2_PARAMS
	{
		GY_THREAD			*pthread_	{nullptr};
		MPMCQ_COMM			*pmpmc_		{nullptr};
		uint32_t			thr_num_	{0};
		TTYPE_E				thr_type_	{TTYPE_L2_DB};
		char				descbuf_[64]	{};
	};	


	class PARTHA_INFO;
	class MADHAVA_INFO;
	class NODE_INFO;

	using SHSOCKET_HDLR			= SHSOCKET_HDLR_T <PARTHA_INFO, MADHAVA_INFO, NODE_INFO>;

	using SHTCP_CONN			= SHSOCKET_HDLR::SHTCP_CONN;
	using SHTCP_CONN_HASH_TABLE		= SHSOCKET_HDLR::SHTCP_CONN_HASH_TABLE;

	using SHSTREAM_JSON_EPOLL		= STREAM_JSON_EPOLL<SHCONNTRACK, SHCONN_HANDLER, EPOLL_NODE_CACHE>;

	using HOST_CONN_LIST			= HOST_CONN_FLIST <SHCONNTRACK, L1_PARAMS, MAX_PERSISTENT_CONNS_PER_HOST>;

	using SHSTREAM_EVENT_BUF		= STREAM_EVENT_BUF<SHCONNTRACK, SHCONN_HANDLER>;
	using MadCacheMap			= INLINE_STACK_HASH_MAP<uint64_t, std::optional<SHSTREAM_EVENT_BUF>, 80 * 1024, GY_JHASHER<uint64_t>>;
	using StringHeapVec			= std::vector<std::optional<STRING_HEAP>>;

	using ClusterStateMap			= INLINE_STACK_F14_MAP<CHAR_BUF<comm::MAX_CLUSTER_NAME_LEN>, comm::MS_CLUSTER_STATE::STATE_ONE, 20 * 1024, 
								CHAR_BUF<comm::MAX_CLUSTER_NAME_LEN>::CHAR_BUF_HASH>;
	using ClusterNameSet			= INLINE_STACK_F14_SET<CHAR_BUF<comm::MAX_CLUSTER_NAME_LEN>, 8 * 1024, CHAR_BUF<comm::MAX_CLUSTER_NAME_LEN>::CHAR_BUF_HASH>;
	using AggrClusterStateMap 		= INLINE_STACK_F14_MAP<CHAR_BUF<comm::MAX_CLUSTER_NAME_LEN>, comm::MS_CLUSTER_STATE::STATE_ONE, 100 * 1024, 
								CHAR_BUF<comm::MAX_CLUSTER_NAME_LEN>::CHAR_BUF_HASH>;

	class MADHAVA_INFO : public HOST_CONN_LIST, public std::enable_shared_from_this <MADHAVA_INFO>
	{	
	public :	
		GY_MUTEX			mutex_;

		uint64_t			madhava_id_		{0};
		DOMAIN_PORT			listener_port_;
		GY_IP_ADDR			remote_ip_;
		char				region_name_[comm::MAX_ZONE_LEN]		{};
		char				zone_name_[comm::MAX_ZONE_LEN]			{};
		char				madhava_name_[comm::MAX_CLUSTER_NAME_LEN]	{};

		uint64_t			init_tusec_		{get_usec_time()};

		uint64_t			last_reg_tusec_		{0};
		uint64_t			last_par_assign_tusec_	{0};
		uint64_t			last_alertdefs_tusec_	{0};

		uint64_t			last_status_tsec_	{0};
		uint64_t			last_status_csec_	{0};	
		std::atomic<uint32_t>		npartha_nodes_		{0};
		uint32_t			max_partha_nodes_	{0};	
		uint32_t			approx_partha_conns_	{0};
		std::atomic<uint32_t>		curr_par_adds_		{0};
		std::atomic<uint32_t>		last_par_adds_		{0};

		GY_MUTEX			cluststate_mutex_;
		time_t				tclustersec_		{0};
		ClusterStateMap			clusterstatemap_;
		/*ClusterNameSet			clusternameset_;*/

		int64_t				diff_sys_sec_		{0};

		uint32_t			comm_version_		{1};
		uint32_t			madhava_version_	{0};
		uint32_t			kern_version_num_	{0};
		
		DOMAIN_PORT			prev_instance_;
		time_t				tignore_till_		{0};

		/*uint32_t			host_taglen_		{0};*/
		/*char 				host_tagname_[comm::MAX_TOTAL_TAG_LEN]		{};*/

		MADHAVA_INFO(const char *pdomain, uint16_t port, uint64_t madhava_id)
			: madhava_id_(madhava_id), listener_port_(pdomain, port)
		{}

		const char * get_hostname() const noexcept
		{
			return listener_port_.get_domain();
		}

		uint16_t get_port() const noexcept
		{
			return listener_port_.get_port();
		}

		char * print_string(STR_WR_BUF & strbuf) const noexcept
		{
			return strbuf.appendfmt("Madhava %s Host %s port %hu ID %016lx ", 
				madhava_name_, listener_port_.get_domain(), listener_port_.get_port(), madhava_id_);
		}

		CHAR_BUF<256> print_string() const noexcept
		{
			CHAR_BUF<256>		cbuf;
			STR_WR_BUF		strbuf(cbuf.get(), cbuf.maxsz() - 1);

			print_string(strbuf);

			return cbuf;
		}	

		bool new_partha_allowed() const noexcept
		{
			return (npartha_nodes_.load(mo_acquire) < max_partha_nodes_);
		}	

		friend inline bool operator== (const std::shared_ptr<MADHAVA_INFO> & lhs, uint64_t id) noexcept
		{
			auto		plhs = lhs.get();

			return (plhs && plhs->madhava_id_ == id);
		}
	};	

	using 	MADHAVA_INFO_ELEM		= RCU_HASH_WRAPPER <uint64_t, std::shared_ptr<MADHAVA_INFO>>;
	using 	MADHAVA_INFO_HTABLE		= RCU_HASH_TABLE <uint64_t, MADHAVA_INFO_ELEM>;

	class NODE_INFO : public HOST_CONN_LIST, public std::enable_shared_from_this <NODE_INFO>
	{
	public :	
		DOMAIN_PORT			listener_port_;
		GY_IP_ADDR			remote_ip_;

		uint32_t			node_version_		{0};
		uint32_t			comm_version_		{1};
		uint64_t			init_tusec_		{get_usec_time()};
		int64_t				diff_sys_sec_		{0};

		NODE_INFO(DOMAIN_PORT listener_port) : listener_port_(listener_port)
		{}

		CHAR_BUF<256> print_string() const noexcept
		{
			CHAR_BUF<256>		cbuf;

			snprintf(cbuf.get(), cbuf.maxsz(), "Node Host %s port %hu ", listener_port_.get_domain(), listener_port_.get_port());

			return cbuf;
		}	
	};	
	
	using 	NODE_STATS_HTABLE		= std::unordered_map<DOMAIN_PORT, std::shared_ptr<NODE_INFO>, DOMAIN_PORT::DOMAIN_PORT_HASH>;
	
	class PARTHA_INFO 
	{	
	public :	
		RCU_HASH_CLASS_MEMBERS(GY_MACHINE_ID, PARTHA_INFO);

		uint32_t			comm_version_					{1};
		uint32_t			partha_version_					{0};

		GY_MACHINE_ID			machine_id_;		

		uint64_t			last_register_tusec_				{0};
		uint64_t			partha_ident_key_				{0};		// To be sent to madhava as ident key
		
		char				hostname_[MAX_DOMAINNAME_SIZE]			{};
		char				cluster_name_[comm::MAX_CLUSTER_NAME_LEN]	{};
		char				region_name_[comm::MAX_ZONE_LEN]		{};
		char				zone_name_[comm::MAX_ZONE_LEN]			{};

		gy_atomic<time_t>		tdb_updated_					{0};
		time_t				tinit_						{time(nullptr)};
		bool				new_registered_					{true};		

		uint32_t			kern_version_num_				{0};
		GY_IP_ADDR			remote_ip_;							// Will be empty for new_registered_ == false

		std::weak_ptr <MADHAVA_INFO>	madhava_weak_;
		uint64_t			madhava_id_					{0};

		PARTHA_INFO() 			= default;
		
		uint64_t set_ident_key(uint64_t curr_tusec = get_usec_time()) noexcept
		{
			alignas(8) char			tbuf[sizeof(uint64_t) + comm::MAX_CLUSTER_NAME_LEN + MAX_DOMAINNAME_SIZE] {};

			std::memcpy(tbuf, &curr_tusec, sizeof(curr_tusec));
			
			GY_STRNCPY(tbuf + sizeof(uint64_t), cluster_name_, comm::MAX_CLUSTER_NAME_LEN);
			GY_STRNCPY(tbuf + sizeof(uint64_t) + comm::MAX_CLUSTER_NAME_LEN, hostname_, MAX_DOMAINNAME_SIZE);

			last_register_tusec_	= curr_tusec;
			partha_ident_key_	= gy_cityhash64(tbuf, sizeof(tbuf));

			return partha_ident_key_;
		}	

		uint64_t get_last_register_usec() const noexcept
		{
			return last_register_tusec_;
		}

		char * print_string(STR_WR_BUF & strbuf) const noexcept
		{
			strbuf.appendfmt("Partha Host \'%s\' ", hostname_);
			return machine_id_.print_string(strbuf);	
		}
		
		CHAR_BUF<256> print_string() const noexcept
		{
			CHAR_BUF<256>		cbuf;
			STR_WR_BUF		strbuf(cbuf.get(), cbuf.maxsz() - 1);

			print_string(strbuf);

			return cbuf;
		}	

		CHAR_BUF<48> get_machid_str() const noexcept
		{
			CHAR_BUF<48>		cbuf;

			snprintf(cbuf.get(), sizeof(cbuf), "%016lx%016lx", machine_id_.machid_.first, machine_id_.machid_.second);
			
			return cbuf;
		}

		friend inline bool operator== (const PARTHA_INFO &lhs, const GY_MACHINE_ID id) noexcept
		{
			return lhs.machine_id_ == id;
		}
	};	

	using 	PARTHA_INFO_HTABLE		= RCU_HASH_TABLE <GY_MACHINE_ID, PARTHA_INFO>;

	class ParthaDbStat
	{
	public :
		char				cluster_name_[comm::MAX_CLUSTER_NAME_LEN]	{};
		char				region_name_[comm::MAX_ZONE_LEN]		{};
		char				zone_name_[comm::MAX_ZONE_LEN]			{};
		uint64_t			madhava_id_					{0};
		time_t				tdel_after_					{0};
		time_t				tping_						{0};

		ParthaDbStat() noexcept		= default;

		ParthaDbStat(const char *cluster, const char *region, const char *zone, uint64_t madhava_id, time_t tdel_after, time_t tcurr) noexcept
			: madhava_id_(madhava_id), tdel_after_(tdel_after), tping_(tcurr)
		{
			GY_STRNCPY(cluster_name_, cluster, sizeof(cluster_name_));
			GY_STRNCPY(region_name_, region, sizeof(region_name_));
			GY_STRNCPY(zone_name_, zone, sizeof(zone_name_));
		}	
	};	

	using ParthaDbMap			= folly::F14NodeMap<GY_MACHINE_ID, ParthaDbStat, GY_MACHINE_ID::MAC_HASH>;

	// To be called with SHCONNTRACK shared_ptr active
	template <typename T, comm::COMM_TYPE_E type_>
	bool send_l1_register_connect_error(const L1_PARAMS *pl1_src, std::weak_ptr <SHCONNTRACK> && weakconn, SHCONNTRACK *pconn, comm::COMM_HEADER::HDR_MAGIC_E comm_magic, \
				STATS_STR_MAP & statsmap, ERR_CODES_E errcode, const char *errstr, POOL_ALLOC_ARRAY *pthrpoolarr, bool close_conn = true)
	{
		uint8_t				*palloc;
		FREE_FPTR			free_fp_hdr;
		static constexpr size_t		fixed_sz = sizeof(comm::COMM_HEADER) + sizeof(T);
		uint32_t			act_size;

		palloc = (uint8_t *)pthrpoolarr->safe_malloc(fixed_sz, free_fp_hdr, act_size);
	
		comm::COMM_HEADER		*phdr = reinterpret_cast<comm::COMM_HEADER *>(palloc);
		T				*presp = reinterpret_cast<T *>((uint8_t *)phdr + sizeof(comm::COMM_HEADER)); 
		
		phdr->~COMM_HEADER();

		new (phdr) comm::COMM_HEADER(type_, fixed_sz, comm_magic);

		std::memset((void *)presp, 0, sizeof(*presp));

		presp->error_code_	= errcode;
		GY_STRNCPY(presp->error_string_, errstr, sizeof(presp->error_string_));

		struct iovec			iov[3] {{phdr, sizeof(*phdr)}, {presp, sizeof(*presp)}, {(void *)gpadbuf, phdr->get_pad_len()}};	
		FREE_FPTR			free_fp_arr[3] {free_fp_hdr, nullptr, nullptr};
		
		// SHCONNTRACK shared_ptr already created when this is called. So pconn can be safely used
		pconn->schedule_ext_send(EPOLL_IOVEC_ARR(iov, GY_ARRAY_SIZE(iov), free_fp_arr, false));

		L1_SEND_DATA			l1data(pl1_src, std::move(weakconn), pconn, comm_magic, type_, close_conn);

		bool				bret;
		int				ntries = 0;

		do { 
			bret = pl1_src->psignalq_->write(std::move(l1data));
		} while (bret == false && ntries++ < 10);

		if (bret == false) {
			statsmap["L1 Notify Blocked"]++;
			return false;
		}

		int64_t			n = 1;

		(void)::write(pl1_src->signal_fd_, &n, sizeof(int64_t));
		
		return true;
	}	

	/*
	 * To be called only from L1 threads as send_immediate() is directly invoked
	 */
	template <typename T, comm::COMM_TYPE_E type_>
	ssize_t send_register_connect_error(SHCONNTRACK *pconn1, ERR_CODES_E errcode, const char *errstr, POOL_ALLOC_ARRAY *pthrpoolarr)
	{
		uint8_t				*palloc;
		static constexpr size_t		fixed_sz = sizeof(comm::COMM_HEADER) + sizeof(T);
		bool				is_malloc;

		// We can allocate memory from stack as the conn will be closed right after this call
		SAFE_STACK_ALLOC(palloc, fixed_sz, is_malloc);
	
		comm::COMM_HEADER		*phdr = reinterpret_cast<comm::COMM_HEADER *>(palloc);
		T				*presp = reinterpret_cast<T *>((uint8_t *)phdr + sizeof(comm::COMM_HEADER)); 
		
		phdr->~COMM_HEADER();

		new (phdr) comm::COMM_HEADER(type_, fixed_sz, pconn1->get_comm_magic());

		std::memset((void *)presp, 0, sizeof(*presp));

		presp->error_code_		= errcode;
		GY_STRNCPY(presp->error_string_, errstr, sizeof(presp->error_string_));

		struct iovec			iov[3] {{phdr, sizeof(*phdr)}, {presp, sizeof(*presp)}, {(void *)gpadbuf, phdr->get_pad_len()}};	
		FREE_FPTR			free_fp_arr[3] {nullptr, nullptr, nullptr};
		
		pconn1->schedule_ext_send(EPOLL_IOVEC_ARR(iov, 3, free_fp_arr, false));

		return send_immediate(pconn1, false /* throw_on_error */);
	}	

	/*
	 * Direct socket non blocking write skipping conntracks (Assumes non-blocking sock)
	 */
	template <typename T, comm::COMM_TYPE_E type_>
	ssize_t sock_register_connect_error(int sock, ERR_CODES_E errcode, const char *errstr, comm::COMM_HEADER::HDR_MAGIC_E magic)
	{
		uint8_t				*palloc;
		static constexpr size_t		fixed_sz = sizeof(comm::COMM_HEADER) + sizeof(T);
		bool				is_malloc;

		// We can allocate memory from stack as the conn will be closed right after this call
		SAFE_STACK_ALLOC(palloc, fixed_sz, is_malloc);
	
		comm::COMM_HEADER		*phdr = reinterpret_cast<comm::COMM_HEADER *>(palloc);
		T				*presp = reinterpret_cast<T *>((uint8_t *)phdr + sizeof(comm::COMM_HEADER)); 
		
		phdr->~COMM_HEADER();

		new (phdr) comm::COMM_HEADER(type_, fixed_sz, magic);

		std::memset((void *)presp, 0, sizeof(*presp));

		presp->error_code_		= errcode;
		GY_STRNCPY(presp->error_string_, errstr, sizeof(presp->error_string_));

		struct iovec			iov[3] {{phdr, sizeof(*phdr)}, {presp, sizeof(*presp)}, {(void *)gpadbuf, phdr->get_pad_len()}};	
		
		return gy_writev(sock, iov, GY_ARRAY_SIZE(iov));
	}	

	// Memory will be alocated for header + resp_len
	bool send_query_response(const std::shared_ptr<SHCONNTRACK> & connshr, uint64_t seqid, comm::RESP_TYPE_E resptype, ERR_CODES_E errcode, comm::RESP_FORMAT_E respfmt, \
			const void *prespdata, uint32_t resp_len, POOL_ALLOC_ARRAY *pthrpoolarr = nullptr)
	{
		using namespace		comm;

		size_t			fixed_sz = sizeof(COMM_HEADER) + sizeof(QUERY_RESPONSE) + resp_len;
		FREE_FPTR		free_fp;
		uint32_t		act_size;
		void			*palloc;

		palloc = POOL_ALLOC_ARRAY::opt_safe_malloc(pthrpoolarr, fixed_sz, free_fp, act_size);
		
		COMM_HEADER		*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
		QUERY_RESPONSE		*presp = reinterpret_cast<QUERY_RESPONSE *>((uint8_t *)phdr + sizeof(COMM_HEADER)); 
		
		new (phdr) COMM_HEADER(COMM_QUERY_RESP, fixed_sz, connshr->get_comm_magic());
		new (presp) QUERY_RESPONSE(seqid, resptype, errcode, respfmt, resp_len);

		if (resp_len) {
			std::memcpy((uint8_t *)(presp + 1), prespdata, resp_len);
		}	
		
		return schedule_l1_send_data(connshr, comm::COMM_QUERY_RESP, EPOLL_IOVEC_ARR(2, false, palloc, fixed_sz, free_fp, gpadbuf, phdr->get_pad_len(), nullptr));
	};

	bool send_json_error_resp(const std::shared_ptr<SHCONNTRACK> & connshr, ERR_CODES_E errcode, uint64_t resp_seqid, const char *errortxt, size_t lenerr = 0, \
						POOL_ALLOC_ARRAY *parrpool = nullptr) noexcept
	{
		using namespace			comm;

		try {
			if (lenerr == 0) {
				lenerr = strlen(errortxt);
			}	

			SHSTREAM_JSON_EPOLL			stream(connshr, *this, RESP_WEB_JSON, resp_seqid, parrpool, errcode);
			SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL>	writer(stream);
			
			stream.reserve(max_json_escape_size(lenerr) + 80);

			writer.StartObject();

			writer.KeyConst("error");
			writer.Int(errcode);

			writer.KeyConst("errmsg");
			writer.String(errortxt, lenerr);
				
			writer.KeyConst("shyamaid");
			writer.String(gshyama_id_str_, 16);
		
			writer.EndObject();

			return stream.set_resp_completed();
		}
		GY_CATCH_EXCEPTION(
			DEBUGEXECN(1,
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while sending Web JSON Error response to %s : %s\n",
					connshr->print_conn(STRING_BUFFER<256>().get_str_buf()), GY_GET_EXCEPT_STRING);
			);	

			return false;
		);
	}	

	/*
	 * allocunq must contain a GY_REFCNT allocated buffer
	 */
	template <typename FilterCb = bool(*)(MADHAVA_INFO *)>
	size_t send_all_madhava_event(UNIQ_REFCNT && allocunq, size_t msgsz, size_t padlen, const FilterCb * const pfiltercb = nullptr)
	{
		size_t 				nsent = 0;	
		auto				puniq = std::move(allocunq);
		void				*palloc = puniq.get();

		if (!palloc || padlen >= 8) {
			return 0;
		}	

		auto lammad = [&, palloc, msgsz, padlen](MADHAVA_INFO_ELEM *pdatanode, void *arg1) -> CB_RET_E
		{
			auto			pmad = pdatanode->get_data()->get();
			
			if (gy_unlikely(pmad == nullptr)) {
				return CB_OK;
			}	

			if (pfiltercb) {
				bool			bret = (*pfiltercb)(pmad);

				if (false == bret) {
					return CB_OK;
				}
			}

			auto			madshrconn = pmad->get_last_conn(comm::CLI_TYPE_RESP_REQ);
			auto 			pconn1 = madshrconn.get();

			if (pconn1) {
				GY_REFCNT::add_refcount(palloc);

				nsent += (size_t)schedule_l1_send_data(madshrconn, comm::COMM_EVENT_NOTIFY, 
								EPOLL_IOVEC_ARR(2, false, palloc, msgsz, GY_REFCNT::sub_refcount_free, gpadbuf, padlen, nullptr));
			}
			return CB_OK;
		};

		madhava_tbl_.walk_hash_table(lammad);

		return nsent;
	}	

	// Close all conns for a Madhava or a Node Instance
	void close_all_conns(HOST_CONN_LIST & minfo) noexcept
	{
		auto lwalk = [&, this](HOST_CONN_LIST::HOST_CONN_L1 & lconn) noexcept
		{
			if (lconn.is_cli_active()) {
				// This is executed under mutex lock. But OK as we need to clear all conns
				send_l1_close_conn(lconn.pl1_, std::weak_ptr <SHCONNTRACK>(lconn.weakconn_), lconn.pconn_);
			}
			return CB_DELETE_ELEM;
		};	

		minfo.walk_conn_list(lwalk);
	}	



	
	ACC_PARAMS 				*paccept_arr_		{nullptr};

	L1_PARAMS 				*pl1_arr_		{nullptr};

	L2_PARAMS 				*pl2_db_arr_		{nullptr};
	L2_PARAMS 				*pl2_misc_arr_		{nullptr};
	L2_PARAMS 				*pl2_alert_arr_		{nullptr};

	MPMCQ_COMM				**ppmpmc_db_arr_	{nullptr};
	MPMCQ_COMM				**ppmpmc_misc_arr_	{nullptr};
	MPMCQ_COMM				**ppmpmc_alert_arr_	{nullptr};

	GY_MUTEX				node_mutex_;
	NODE_STATS_HTABLE			node_tbl_;
	uint32_t				last_node_cnt_		{0};
	uint32_t				last_node_version_	{0};

	uint32_t				last_madhava_cnt_	{0};
	MADHAVA_INFO_HTABLE			madhava_tbl_		{1};
	PARTHA_INFO_HTABLE			partha_tbl_		{1};

	SHTCP_CONN_HASH_TABLE			glob_tcp_conn_tbl_	{1};

	folly::atomic_shared_ptr<MADHAVA_INFO>	curr_madhava_;
	std::atomic<uint64_t>			curr_madhava_id_	{0};
	std::atomic<uint64_t>			nmadhava_partha_	{0};
	std::atomic<uint64_t>			last_madhava_chg_tusec_	{0};

	GY_MUTEX				pardb_mutex_;
	ParthaDbMap				pardbmap_;

	uint64_t				last_mn_db_upd_tusec_	{0};

	SHYAMA_C			* const pshyama_;

	mutable GY_MUTEX			cluststate_mutex_;
	gy_atomic<time_t>			tclustersec_		{0};
	AggrClusterStateMap			clusterstatemap_;

	SvcClusterMapsTbl			svcclusters_		{1};

	COND_VAR <SCOPE_GY_MUTEX>		barcond_;
	std::atomic<size_t>			nblocked_acc_		{0};
	std::atomic<size_t>			nblocked_l1_		{0};
	std::atomic<size_t>			nblocked_l2_		{0};
	std::atomic<bool>			all_spawned_		{false};
	bool					is_master_		{false};

	std::atomic<int64_t>			gtconncount		{0};

	std::vector<std::string>		listen_host_vec_;
	std::vector<uint16_t>			listen_port_vec_;

	SHALERT_HDLR				*pshalerthdlr_		{nullptr};
	ALERTMGR				*palertmgr_		{nullptr};

	std::optional<GY_THREAD>		instance_thr_;
	time_t					tlast_instance_		{0};

	GY_SCHEDULER				*pdb_scheduler_		{nullptr};
	std::unique_ptr<PGConnPool>		db_scheduler_pool_;

	GY_SCHEDULER				*pdbmain_scheduler_	{nullptr};
	std::unique_ptr<PGConnPool>		dbmain_scheduler_pool_;
	uint64_t				curr_db_size_		{0};
	time_t					tlast_db_size_		{time(nullptr)};

	DBFailStats				db_stats_;

	uint64_t				gshyama_id_					{0};
	char					gshyama_id_str_[17]				{};

	uint32_t				min_madhava_					{0};
	uint32_t				db_storage_days_				{0};
	char					region_name_[comm::MAX_ZONE_LEN]		{};
	char					zone_name_[comm::MAX_ZONE_LEN]			{};
	char					shyama_name_[comm::MAX_CLUSTER_NAME_LEN]	{};
	char					shyama_secret_[comm::MAX_CLUSTER_NAME_LEN]	{};
	char					cloud_type_[64]					{};

	static constexpr uint8_t		gpadbuf[8] = "\x0\x0\x0\x0\x0\x0\x0";
	static constexpr size_t			RD_DB_POOL_CONNS = 2;	

	using CLI_INFO_VEC			= GY_STACK_VECTOR<comm::SHYAMA_CLI_TCP_INFO, 250 * 1024>;
	using CLI_INFO_VEC_ARENA		= CLI_INFO_VEC::allocator_type::arena_type;
	using CLI_INFO_VEC_MAP			= GY_STACK_HASH_MAP<std::shared_ptr<MADHAVA_INFO>, CLI_INFO_VEC, 16 * 1024>;
	using CLI_INFO_VEC_MAP_ARENA		= CLI_INFO_VEC_MAP::allocator_type::arena_type;

	using SER_INFO_VEC			= GY_STACK_VECTOR<comm::SHYAMA_SER_TCP_INFO, 250 * 1024>;
	using SER_INFO_VEC_ARENA		= SER_INFO_VEC::allocator_type::arena_type;
	using SER_INFO_VEC_MAP			= GY_STACK_HASH_MAP<std::shared_ptr<MADHAVA_INFO>, SER_INFO_VEC, 16 * 1024>;
	using SER_INFO_VEC_MAP_ARENA		= SER_INFO_VEC_MAP::allocator_type::arena_type;

	SHCONN_HANDLER(SHYAMA_C *pshyama);

	~SHCONN_HANDLER() 						= delete;

	SHCONN_HANDLER(const SHCONN_HANDLER &)				= delete;
	SHCONN_HANDLER(SHCONN_HANDLER &&)				= delete;
	SHCONN_HANDLER & operator=(const SHCONN_HANDLER &)		= delete;
	SHCONN_HANDLER & operator=(SHCONN_HANDLER &&)			= delete;

	static SHCONN_HANDLER * get_singleton() noexcept;

	bool	multiple_madhava_active() const noexcept
	{
		return (nmadhava_partha_.load(mo_relaxed) > 1);
	}

	CHAR_BUF<comm::MAX_CLUSTER_NAME_LEN> get_dbname() const noexcept
	{
		return CHAR_BUF<comm::MAX_CLUSTER_NAME_LEN>(shyama_name_);
	}	

	std::pair<int, int> 	init_set_instance_master(PGConnPool & dbpool);
	int 			instance_thread() noexcept;

	MAKE_CLASS_FUNC_WRAPPER_NO_ARG(SHCONN_HANDLER, instance_thread);
	
	SA_SETTINGS_C * get_settings() const noexcept;

	time_t get_last_tclusterstate(std::memory_order order = mo_relaxed) const noexcept
	{
		return tclustersec_.load(order);
	}	

	int 	handle_accept(GY_THREAD *pthr);
	int 	handle_l1(GY_THREAD *pthr);
	int 	handle_l2(GY_THREAD *pthr);

	int 	handle_l2_db(L2_PARAMS & param, POOL_ALLOC_ARRAY * pthrpoolarr, PGConnPool & dbpool);

	int 	handle_l2_misc(L2_PARAMS & param, POOL_ALLOC_ARRAY * pthrpoolarr);
	int 	handle_misc_madhava_reg(comm::MS_REGISTER_REQ_S *pms, const DB_WRITE_ARR & dbarr, L2_PARAMS & param, POOL_ALLOC_ARRAY *pthrpoolarr, STATS_STR_MAP & statsmap);
	int 	handle_misc_partha_reg(comm::PS_REGISTER_REQ_S *preg, const DB_WRITE_ARR & dbarr, L2_PARAMS & param, POOL_ALLOC_ARRAY *pthrpoolarr, STATS_STR_MAP & statsmap);
	int 	handle_misc_node_reg(comm::NS_REGISTER_REQ_S *pns, const DB_WRITE_ARR & dbarr, L2_PARAMS & param, POOL_ALLOC_ARRAY *pthrpoolarr, STATS_STR_MAP & statsmap);
	
	bool 	handle_madhava_reg_partha(const std::shared_ptr<MADHAVA_INFO> & madhava_shr, const comm::MS_REG_PARTHA * pone, int nelems);

	int 	handle_alert_mgr(L2_PARAMS & param);
	bool 	send_madhava_all_alertdefs(MADHAVA_INFO *pmad, const std::shared_ptr<SHCONNTRACK> & connshr) noexcept;

	void 	init_db_glob_conns();
	bool 	db_cleanup_old_partitions(PGConnPool & dbpool, bool is_non_block) noexcept;
	bool 	db_add_partitions() noexcept;
	bool 	db_set_part_logged() noexcept;
	bool 	set_db_disk_space_used() noexcept;

	GyPGConn get_new_db_conn(bool auto_reconnect = false);

	void 	read_db_partha_info(PGConnPool & dbpool) noexcept;
	void	cleanup_db_partha_entries() noexcept;

	bool 	madhava_tcp_conn_info(const std::shared_ptr<MADHAVA_INFO> & madhava_shr, const comm::MS_TCP_CONN_NOTIFY * pone, int nconns, POOL_ALLOC_ARRAY *pthrpoolarr);
	bool 	madhava_tcp_close(const std::shared_ptr<MADHAVA_INFO> & madhava_shr, const comm::MS_TCP_CONN_CLOSE * pone, int nconns);
	bool 	handle_madhava_nat_notify(comm::NAT_TCP_NOTIFY * pone, int nconns, POOL_ALLOC_ARRAY *pthrpoolarr);

	bool 	handle_ms_partha_ping(const std::shared_ptr<MADHAVA_INFO> & madhava_shr, const comm::MS_PARTHA_PING * pone, int nelems, PGConnPool & dbpool);

	bool 	handle_cluster_state(const std::shared_ptr<MADHAVA_INFO> & madhava_shr, comm::MS_CLUSTER_STATE * pone, int nconns, uint8_t *pendptr, POOL_ALLOC_ARRAY *pthrpoolarr);
	void 	aggregate_cluster_state(bool to_print) noexcept;

	bool 	handle_svc_cluster_mesh(const std::shared_ptr<MADHAVA_INFO> & madhava_shr, comm::MS_SVC_CLUSTER_MESH * pone, int nconns, uint8_t *pendptr, POOL_ALLOC_ARRAY *pthrpoolarr);
	CB_RET_E coalesce_svc_mesh_locked(SvcClusterMapsOne *pcluster, MadCacheMap & madcachemap, StringHeapVec & dbstrvec, const char *ptimestr, const char *pdatestr);
	void 	coalesce_svc_mesh_clusters() noexcept;

	void 	handle_svc_nat_ip(const std::shared_ptr<MADHAVA_INFO> & madhava_shr, comm::MS_LISTENER_NAT_IP * pone, int nconns, uint8_t *pendptr, POOL_ALLOC_ARRAY *pthrpoolarr);
	CB_RET_E check_svc_nat_ip_locked(SvcClusterMapsOne *pcluster, MadCacheMap & madcachemap, StringHeapVec & dbstrvec, const char *ptimestr, const char *pdatestr);
	void 	check_svc_nat_ip_clusters() noexcept;

	std::pair<bool, bool> add_tcp_conn_cli(const std::shared_ptr<MADHAVA_INFO> & madhava_shr, const comm::MS_TCP_CONN_NOTIFY * pone, uint64_t tusec_start, \
				CLI_INFO_VEC_MAP & climap, CLI_INFO_VEC_ARENA & cli_vec_arena, SER_INFO_VEC_MAP & sermap, SER_INFO_VEC_ARENA & ser_vec_arena, POOL_ALLOC_ARRAY *pthrpoolarr);

	std::pair<bool, bool> add_tcp_conn_ser(const std::shared_ptr<MADHAVA_INFO> & madhava_shr, const comm::MS_TCP_CONN_NOTIFY * pone, uint64_t tusec_start, \
				CLI_INFO_VEC_MAP & climap, CLI_INFO_VEC_ARENA & cli_vec_arena, SER_INFO_VEC_MAP & sermap, SER_INFO_VEC_ARENA & ser_vec_arena, POOL_ALLOC_ARRAY *pthrpoolarr);
	bool 	send_madhava_cli_conn_info(MADHAVA_INFO *pmadhava, const comm::SHYAMA_CLI_TCP_INFO *pone, size_t nconns, POOL_ALLOC_ARRAY *pthrpoolarr);
	bool 	send_madhava_ser_conn_info(MADHAVA_INFO *pmadhava, const comm::SHYAMA_SER_TCP_INFO *pone, size_t nconns, POOL_ALLOC_ARRAY *pthrpoolarr);

	bool 	send_db_array(DB_WRITE_ARR && dbarr, uint32_t caller_thr_num, STATS_STR_MAP & statsmap, bool is_json_resp = false);
	void 	send_json_block_error(const DB_WRITE_ARR & dbarr) noexcept;

	void 	cleanup_tcp_conn_table() noexcept;

	ssize_t send_immediate(SHCONNTRACK *pconn1, bool throw_on_error = true);

	bool	send_l1_close_conn(const L1_PARAMS *pl1_src, std::weak_ptr <SHCONNTRACK> && weakconn, SHCONNTRACK *pconn, const char *errstr = nullptr, uint32_t errlen = 0) noexcept;	
	
	bool	send_l1_close_conn(const std::shared_ptr<SHCONNTRACK> & connshr, const char *errstr = nullptr, uint32_t errlen = 0) noexcept	
	{
		return connshr && send_l1_close_conn(connshr->pl1_, connshr, connshr.get(), errstr, errlen);
	}

	void 	spawn_init_threads();

	std::shared_ptr<MADHAVA_INFO> assign_partha_madhava(const char *hostname, const GY_MACHINE_ID & machid, const char *region, const char *zone, uint64_t last_madhava_id, \
			const char *cluster, uint64_t ign_madid); 
	
	int	sync_partha_madhava_node_stats() noexcept;

	void	send_madhava_status() noexcept;

	std::tuple<void *, size_t, size_t> populate_madhava_list() const noexcept;
	void	send_all_list_madhava() noexcept;

	void 	send_madhava_all_info(MADHAVA_INFO *pminfo, const std::shared_ptr<SHCONNTRACK> & connshr) noexcept;

	bool 	schedule_l1_send_data(const std::shared_ptr<SHCONNTRACK> & connshr, comm::COMM_TYPE_E data_type, EPOLL_IOVEC_ARR && data_arr, bool close_conn_on_send = false) noexcept;
	
	bool 	schedule_l1_query(ASYNC_SOCK_CB && async_cb, const std::shared_ptr<SHCONNTRACK> & connshr, EPOLL_IOVEC_ARR && data_arr) noexcept;

	bool 	get_node_response_blocking(const char *rawqueryarr[], uint32_t lenarr[], uint32_t narr, const std::shared_ptr<COND_JSON_PARAM> & condshr, int waitms = 10'000);

	std::shared_ptr<SHCONNTRACK> get_any_node_conn() noexcept;
	

	bool	handle_node_query(const std::shared_ptr<SHCONNTRACK> & connshr, const comm::QUERY_CMD *pquery, char *pjson, char *pendptr, \
				POOL_ALLOC_ARRAY *pthrpoolarr, STATS_STR_MAP & statsmap, PGConnPool & dbpool);
	bool 	web_query_route_qtype(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, \
		const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, STATS_STR_MAP & statsmap, PGConnPool & dbpool);
	bool 	web_multi_query(const std::shared_ptr<SHCONNTRACK> & connshr, const GEN_JSON_VALUE & jdoc, const comm::QUERY_CMD *pquery, \
				POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool, STATS_STR_MAP & statsmap);
	
	static 	void noextracolcb(SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer) noexcept;

	CRIT_RET_E 	madhavalist_filter_match(const CRITERIA_SET & criteria, const MADHAVA_INFO * pmad, bool ignore_other_subsys) const;
	bool 	web_query_madhavalist(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, \
				const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);

	bool 	web_curr_clusterstate(SOCK_JSON_WRITER<SHCONN_HANDLER::SHSTREAM_JSON_EPOLL> & writer, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool) const;
	bool 	web_db_detail_clusterstate(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
				SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);
	bool 	web_db_aggr_clusterstate(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
				SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);
	bool 	web_query_clusterstate(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
				SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);

	bool 	web_db_detail_svcmeshcluster(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
				SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);
	bool 	web_query_svcmeshcluster(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
				SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);

	bool 	web_db_detail_svcipcluster(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
				SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);
	bool 	web_query_svcipcluster(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
				SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);

	bool 	web_db_detail_alerts(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
				SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);
	bool 	web_db_aggr_alerts(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
				SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);
	bool 	web_query_alerts(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
				SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);

	bool 	web_db_detail_alertdef(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
				SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);
	bool 	web_query_alertdef(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
				SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);

	bool 	web_db_detail_inhibits(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
				SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);
	bool 	web_query_inhibits(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
				SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);

	bool 	web_db_detail_silences(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
				SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);
	bool 	web_query_silences(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
				SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);

	bool 	web_db_detail_actions(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
				SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);
	bool 	web_query_actions(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
				SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);

	bool 	web_query_shyamastatus(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, \
				const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);


	void 	upgrade_db_schemas(int olddbver, int oldprocver, PGConnUniq & pconn);
	const char * get_sglobtables() const noexcept;
	const char * get_sglob_part_tables() const noexcept;

};

} // namespace shyama
} // namespace gyeeta

namespace rapidjson {

template<>
inline void PutN(gyeeta::shyama::SHCONN_HANDLER::SHSTREAM_JSON_EPOLL & stream, char c, size_t n) 
{
	stream.PutN(c, n);
}

} // namespace rapidjson

