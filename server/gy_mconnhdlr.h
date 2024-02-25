//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma			once

#include		"gy_common_inc.h"
#include		"gy_msg_comm.h"
#include		"gy_multi_proc_comm.h"
#include		"gy_pool_alloc.h"
#include		"gy_epoll_conntrack.h"
#include		"gy_rcu_inc.h"
#include		"gy_comm_proto.h"
#include		"gy_host_conn_flist.h"
#include		"gy_listen_sock.h"
#include		"gy_scheduler.h"
#include		"gy_sys_hardware.h"
#include		"gy_sys_stat.h"
#include		"gy_msocket.h"
#include		"gy_mfields.h"
#include		"gy_mdb_schema.h"
#include		"gy_stack_container.h"
#include		"gy_stream_json.h"
#include		"gy_web_proto.h"
#include		"gy_postgres.h"
#include		"gy_query_common.h"
#include		"gy_statistics.h"

#include		"folly/MPMCQueue.h"
#include 		"folly/Function.h"
#include		"folly/concurrency/AtomicSharedPtr.h" 
/*#include 		"folly/Synchronized.h"*/
#include 		"folly/SharedMutex.h"

#include 		<variant>
#include 		<unordered_map>

using folly::SharedMutex;

namespace gyeeta {
namespace madhava {

class MADHAVA_C;
class MA_SETTINGS_C;
class MALERT_HDLR;
class MRT_ALERTDEF;


using S512_PROC_ELEM 	= MULTI_COMM_SINGLETON::SINGLE_PROC_SZ_512::MULTI_PROC_ELEM;
using STATS_STR_MAP	= std::unordered_map<const char *, int64_t, GY_JHASHER<const char *>>;

/*using SYNC_STRING	= folly::Synchronized<std::string, std::mutex>;*/

class MCONN_HANDLER
{
public :	
	static constexpr size_t			MAX_ACCEPT_THREADS		= 2;

	static constexpr size_t			MAX_L1_CLI_THREADS		= 8;
	static constexpr size_t			MAX_L1_SHYAMA_THREADS		= 1;
	static constexpr size_t			MAX_L1_THREADS			= MAX_L1_CLI_THREADS + MAX_L1_SHYAMA_THREADS;
	
	static constexpr size_t			MAX_L2_DB_READERS 		= 8; 
	static constexpr size_t			MAX_L2_MISC_THREADS 		= 16; 
	static constexpr size_t			MAX_L2_ALERT_THREADS		= 1;	// This thread will in turn spawn 2 DB and 1 realtime thread
	static constexpr size_t			MAX_L2_TRACE_THREADS 		= 2; 	// For Trace Requests only
	static constexpr size_t			MAX_L2_THREADS			= MAX_L2_DB_READERS + MAX_L2_MISC_THREADS + MAX_L2_ALERT_THREADS + MAX_L2_TRACE_THREADS;
	
	// Multiple L2 threads will handle each pool
	static constexpr size_t			MAX_L2_DB_RD_POOLS 		= 1;
	static constexpr size_t			MAX_L2_MISC_POOLS 		= 4;
	static constexpr size_t			MAX_L2_ALERT_POOLS 		= 1;
	static constexpr size_t			MAX_L2_TRACE_POOLS 		= 1;
	static constexpr size_t			MAX_MPMC_ELEMS			= 64 * 1024;
	
	// 2 Alert DB Threads and 1 Realtime Alert Thread
	static constexpr size_t			MAX_ALERT_DB_THREADS		= 2;
	
	static constexpr size_t			MAX_CONCURRENT_ACCEPT_CONNS	= 2048;
	static constexpr size_t			MAX_TCP_LISTENERS		= 16;

	// Partial Message Reads / Writes will wait for min this timeout interval and subsequently the conn will close
	static constexpr uint64_t 		MAX_CONN_DATA_TIMEOUT_USEC 	{60 * GY_USEC_PER_SEC}; 	// 60 sec

	// Max Idle time to close persistent connections with no traffic to avoid build up of reqs/callbacks...
	static constexpr uint64_t 		MAX_CONN_IDLE_TIMEOUT_USEC 	{15 * GY_USEC_PER_MINUTE}; 	// 15 min

	// Max Time to keep a Partha Host entry when that host is not connected. After Deletion, only DB data present
	static constexpr uint64_t 		MAX_PARTHA_CONN_DELETE_USEC 	{6 * GY_USEC_PER_HOUR}; 

	// Max Time to keep a Madhava Host entry when that host is not connected
	static constexpr uint64_t 		MAX_MADHAVA_CONN_DELETE_USEC 	{30 * GY_USEC_PER_MINUTE};		

	static constexpr size_t			MAX_PERSISTENT_CONNS_PER_HOST	{64};

	static constexpr size_t			MAX_NODE_INSTANCES		{64};

	static constexpr size_t			MAX_UNRESOLVED_TCP_CONNS	{100'000};		// Approx max

	static_assert(MAX_L1_SHYAMA_THREADS == 1u, "Shyama L1 to be handled by a single thread only");

	struct SHYAMA_INFO;
	struct MADHAVA_INFO;
	struct PARTHA_INFO;
	struct NODE_INFO;

	struct L1_PARAMS;
	class MCONNTRACK;

	using HOST_VARIANT_SHR			= std::variant<std::shared_ptr <PARTHA_INFO>, std::shared_ptr <MADHAVA_INFO>, std::shared_ptr <NODE_INFO>>;
	using HOST_VARIANT_WEAK			= std::variant<std::weak_ptr <PARTHA_INFO>, std::weak_ptr <MADHAVA_INFO>, std::weak_ptr <NODE_INFO>>;

	using ASYNC_SOCK_CB			= T_ASYNC_SOCK_CB<MCONNTRACK>;

	class MCONNTRACK : public EPOLL_CONNTRACK, public ASYNC_CB_HANDLER <MCONNTRACK>, public std::enable_shared_from_this <MCONNTRACK>
	{
	public :	

		const L1_PARAMS			*pl1_			{nullptr};
		HOST_VARIANT_SHR		host_shr_;		// Not valid for Shyama conns
		comm::HOST_TYPES_E		host_type_		{comm::HOST_INVALID};

		GY_MACHINE_ID			partha_machine_id_;	// Only for Partha hosts

		comm::COMM_HEADER::HDR_MAGIC_E	comm_magic_		{comm::COMM_HEADER::INV_HDR_MAGIC};
		comm::CLI_TYPE_E		cli_type_		{comm::CLI_TYPE_REQ_RESP};

		bool				is_registered_		{false};
		bool				is_adhoc_		{false};

		// See EPOLL_CONNTRACK constructor for comments regarding arguments
		MCONNTRACK(struct sockaddr_storage *psockaddr, int sockfd, int epollfd, void *epoll_data, size_t init_rdbuf_sz, size_t init_wrbuf_sz, bool use_pipeline, uint64_t max_idle_usec = 0, uint64_t pending_timeout_usec = 0, bool close_conn_on_wr_complete = false, bool is_outgoing = false, uint64_t start_clock_usec = get_usec_clock())
			: EPOLL_CONNTRACK(psockaddr, sockfd, epollfd, epoll_data, init_rdbuf_sz, init_wrbuf_sz, use_pipeline, max_idle_usec, pending_timeout_usec, 
					close_conn_on_wr_complete, is_outgoing, start_clock_usec),
			ASYNC_CB_HANDLER<MCONNTRACK>(this)
		{}	

		// See EPOLL_CONNTRACK constructor for comments regarding arguments
		MCONNTRACK(const IP_PORT & peer_ipport, int sockfd, int epollfd, void *epoll_data, size_t init_rdbuf_sz, size_t init_wrbuf_sz, bool use_pipeline, uint64_t max_idle_usec = 0, uint64_t pending_timeout_usec = 0, bool close_conn_on_wr_complete = false, bool is_outgoing = false, uint64_t start_clock_usec = get_usec_clock()) 
			: EPOLL_CONNTRACK(peer_ipport, sockfd, epollfd, epoll_data, init_rdbuf_sz, init_wrbuf_sz, use_pipeline, max_idle_usec, pending_timeout_usec, 
					close_conn_on_wr_complete, is_outgoing, start_clock_usec),
			ASYNC_CB_HANDLER<MCONNTRACK>(this)
		{}	

		~MCONNTRACK() noexcept
		{
			switch (host_type_) {
			
			case comm::HOST_PARTHA :	
				if (true) {
					auto pshrp = std::get_if<std::shared_ptr<PARTHA_INFO>>(&host_shr_);
					if (pshrp && *pshrp) {
						size_t nconn = (*pshrp)->del_conn(this, host_type_);

						if (nconn == 0) {
							(*pshrp)->handle_disconnect();
						}	
					}	
				}	
				break;

			case comm::HOST_SHYAMA :	
				if (true) {
					MCONN_HANDLER::get_singleton()->get_shyama()->handle_disconnect(this, host_type_, cli_type_);
				}	
				break;

			case comm::HOST_MADHAVA :	
				if (true) {
					auto pshrp = std::get_if<std::shared_ptr<MADHAVA_INFO>>(&host_shr_);
					if (pshrp && *pshrp) {
						(*pshrp)->del_conn(this, host_type_);
					}	
				}	
				break;

			case comm::HOST_NODE_WEB :	
				if (true) {
					auto pshrp = std::get_if<std::shared_ptr<NODE_INFO>>(&host_shr_);
					if (pshrp && *pshrp) {
						(*pshrp)->del_conn(this, host_type_);
					}	
				}	
				break;
	
			default :
				break;
			}
		}	

		std::shared_ptr<PARTHA_INFO> get_partha_shared() const noexcept
		{
			auto 		pshrp = std::get_if<std::shared_ptr<PARTHA_INFO>>(&host_shr_);

			if (pshrp && (host_type_ == comm::HOST_PARTHA)) {
				return *pshrp;
			}	

			return {};
		}	

		std::shared_ptr<MADHAVA_INFO> get_madhava_shared() const noexcept
		{
			auto 		pshrp = std::get_if<std::shared_ptr<MADHAVA_INFO>>(&host_shr_);

			if (pshrp && (host_type_ == comm::HOST_MADHAVA)) {
				return *pshrp;
			}	

			return {};
		}	

		std::shared_ptr<NODE_INFO> get_node_shared() const noexcept
		{
			auto 		pshrp = std::get_if<std::shared_ptr<NODE_INFO>>(&host_shr_);

			if (pshrp && (host_type_ == comm::HOST_NODE_WEB)) {
				return *pshrp;
			}	

			return {};
		}	

		char * print_conn(STR_WR_BUF & strbuf) const noexcept
		{
			strbuf.appendfmt("Connection %s Remote %s Conn Type %s ", is_outgoing_conn() == false ? "from" : "to",
				comm::host_type_string(host_type_), comm::cli_type_string(cli_type_));

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

	using MAP_CONNTRACK 			= std::unordered_map<int, std::shared_ptr<MCONNTRACK>, GY_JHASHER<int>>;
	using CONN_NODE_ELEM			= MAP_CONNTRACK::node_type; 

	enum TTYPE_E : uint8_t
	{
		TTYPE_ACCEPT		= 0,
		TTYPE_L1_CLI,
		TTYPE_L1_SHYAMA,
		TTYPE_L2_DB_RD,
		TTYPE_L2_MISC,
		TTYPE_L2_ALERT,
	};

	enum MNOTIFY_TYPE_E : uint32_t
	{
		NOTIFY_IGNORE		= 0,
		NOTIFY_ACCEPT,
		NOTIFY_CONNECT,
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
		ACC_NOTIFY_ONE & operator=(const ACC_NOTIFY_ONE &)	= delete;

		ACC_NOTIFY_ONE(ACC_NOTIFY_ONE &&) 			= default;
		ACC_NOTIFY_ONE & operator=(ACC_NOTIFY_ONE &&)		= default;
	
		~ACC_NOTIFY_ONE() 					= default;
	};	

	struct CONN_NOTIFY_ONE
	{
		std::unique_ptr<sockaddr_storage>	pconnect_sockaddr_;
		SCOPE_FD				sockfd_			{0};
		ASYNC_SOCK_CB				cb_success_;	
		comm::COMM_HEADER::HDR_MAGIC_E 		comm_magic_		{comm::COMM_HEADER::INV_HDR_MAGIC};
		comm::HOST_TYPES_E			host_type_		{comm::HOST_INVALID};
		comm::CLI_TYPE_E			cli_type_		{comm::CLI_TYPE_REQ_RESP};
		bool					is_connected_		{false};

		CONN_NOTIFY_ONE() noexcept				= default;

		CONN_NOTIFY_ONE(std::unique_ptr<sockaddr_storage> && pconnect_sockaddr, int sockfd, ASYNC_SOCK_CB && cb_success, \
				comm::HOST_TYPES_E host_type, comm::COMM_HEADER::HDR_MAGIC_E comm_magic, comm::CLI_TYPE_E cli_type, bool is_connected) noexcept

				: pconnect_sockaddr_(std::move(pconnect_sockaddr)), sockfd_(sockfd), cb_success_(std::move(cb_success)),
				comm_magic_(comm_magic), host_type_(host_type), cli_type_(cli_type), is_connected_(is_connected)
		{}	

		CONN_NOTIFY_ONE(const CONN_NOTIFY_ONE &)		= delete;
		CONN_NOTIFY_ONE & operator=(const CONN_NOTIFY_ONE &)	= delete;

		CONN_NOTIFY_ONE(CONN_NOTIFY_ONE &&) 			= default;
		CONN_NOTIFY_ONE & operator=(CONN_NOTIFY_ONE &&)		= default;
	
		~CONN_NOTIFY_ONE() noexcept
		{
			if (cb_success_.is_valid()) {
				try {
					cb_success_.fcb_(nullptr, nullptr, -1, nullptr, false /* is_expiry */, true /* is_error */);
				}
				catch(...) {
				}	
			}	
		}	
	};	

	/*
	 * Use for Requests all allocated from one buffer only.
	 */
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
		std::shared_ptr <MCONNTRACK>	shrconn_;
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
		std::weak_ptr <MCONNTRACK>	weakconn_;
		MCONNTRACK			*pconn_			{nullptr};

		std::optional <ASYNC_SOCK_CB>	async_cb_;		// Called after a send and on the subsequent recv
		uint64_t			resp_usec_		{0};

		comm::COMM_TYPE_E		output_data_type_	{comm::COMM_MIN_TYPE};
		comm::COMM_HEADER::HDR_MAGIC_E 	comm_magic_		{comm::COMM_HEADER::INV_HDR_MAGIC};
		bool				close_conn_on_send_	{false};	

		L1_SEND_DATA() noexcept					= default;

		L1_SEND_DATA(const L1_PARAMS *pl1_src, std::weak_ptr<MCONNTRACK> && weakconn, MCONNTRACK *pconn, comm::COMM_HEADER::HDR_MAGIC_E comm_magic, comm::COMM_TYPE_E output_data_type, bool close_conn_on_send = false, uint64_t resp_usec = 0) noexcept
			: pl1_src_(pl1_src), weakconn_(std::move(weakconn)), pconn_(pconn), resp_usec_(resp_usec), 
			output_data_type_(output_data_type), comm_magic_(comm_magic), close_conn_on_send_(close_conn_on_send)
		{}
	
		L1_SEND_DATA(ASYNC_SOCK_CB && async_cb, const L1_PARAMS *pl1_src, std::weak_ptr<MCONNTRACK> && weakconn, MCONNTRACK *pconn, comm::COMM_HEADER::HDR_MAGIC_E comm_magic) noexcept
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
		L1_MISC_SHYAMA_RECONNECT,
	};

	struct SHYAMA_RECONNECT
	{};

	struct L1_MISC_NOTIFY
	{
		const L1_PARAMS			*pl1_src_		{nullptr};
		std::weak_ptr <MCONNTRACK>	weakconn_;
		MCONNTRACK			*pconn_			{nullptr};
		L1_MISC_TYPE			misc_type_		{L1_MISC_CLOSE_CONN};
		comm::CLI_TYPE_E		cli_type_		{comm::CLI_TYPE_REQ_RESP};
		alignas(8) char			errstr_[128]		{};
		uint32_t			errlen_			{0};

		L1_MISC_NOTIFY() noexcept					= default;

		L1_MISC_NOTIFY(const L1_PARAMS *pl1_src, std::weak_ptr<MCONNTRACK> && weakconn, MCONNTRACK *pconn, const char *errstr = nullptr, uint32_t errlen = 0) noexcept
			: pl1_src_(pl1_src), weakconn_(std::move(weakconn)), pconn_(pconn), misc_type_(L1_MISC_CLOSE_CONN)
		{
			if (errstr) {
				errlen_ = std::min<uint32_t>(errlen, sizeof(errstr_) - 1);
				std::memcpy(errstr_, errstr, errlen_);
			}			
		}
	
		L1_MISC_NOTIFY(const L1_PARAMS *pl1_src, comm::CLI_TYPE_E cli_type, SHYAMA_RECONNECT dummy1) noexcept
			: pl1_src_(pl1_src), misc_type_(L1_MISC_SHYAMA_RECONNECT), cli_type_(cli_type)
		{}

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
			CONN_NOTIFY_ONE			conn_;
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
		MNOTIFY_TYPE_E				ntype_			{NOTIFY_IGNORE};	

		EV_NOTIFY_ONE() 			= default;

		EV_NOTIFY_ONE(ACC_NOTIFY_ONE && acc) noexcept
			: ntype_(NOTIFY_ACCEPT)
		{
			new (&data_.acc_) ACC_NOTIFY_ONE(std::move(acc));	
		}	

		EV_NOTIFY_ONE(CONN_NOTIFY_ONE && conn) noexcept
			: ntype_(NOTIFY_CONNECT)
		{
			new (&data_.conn_) CONN_NOTIFY_ONE(std::move(conn));	
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
		
		EV_NOTIFY_ONE(L1_MISC_NOTIFY && l1_misc) noexcept
			: ntype_(NOTIFY_L1_MISC_CMD)
		{
			new (&data_.l1_misc_) L1_MISC_NOTIFY(std::move(l1_misc));
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
			
			case NOTIFY_CONNECT :
				new (&data_.conn_) 	CONN_NOTIFY_ONE(std::move(other.data_.conn_));
				break;
			
			case NOTIFY_DB_WRITE_ARR :
				new (&data_.dbwrarr_)	DB_WRITE_ARR(std::move(other.data_.dbwrarr_));
				break;

			case NOTIFY_L1_SEND_DATA :
				new (&data_.l1_data_)	L1_SEND_DATA(std::move(other.data_.l1_data_));
				break;

			case NOTIFY_L1_MISC_CMD :
				new (&data_.l1_misc_) L1_MISC_NOTIFY(std::move(other.data_.l1_misc_));
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
			
			case NOTIFY_CONNECT :
				data_.conn_.~CONN_NOTIFY_ONE();
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

		MNOTIFY_TYPE_E get_type() const noexcept
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
		TTYPE_E				thr_type_	{TTYPE_L1_CLI};
		char				descbuf_[64]	{};
	};	

	struct L2_PARAMS
	{
		GY_THREAD			*pthread_	{nullptr};
		MPMCQ_COMM			*pmpmc_		{nullptr};
		uint32_t			thr_num_	{0};
		TTYPE_E				thr_type_	{TTYPE_L2_MISC};
		char				descbuf_[64]	{};
	};	

	class PARTHA_INFO;
	class MADHAVA_INFO;
	class SHYAMA_INFO;


	class WEAK_REMOTE_MADHAVA
	{
	public :	
		RCU_HASH_CLASS_MEMBERS(uint64_t, WEAK_REMOTE_MADHAVA);

		std::weak_ptr<MADHAVA_INFO>		weakmad_;
		uint64_t				madhava_id_		{0};
		uint64_t				tlast_usec_		{0};
		gy_atomic<int>				ntimes_			{1};
		bool					listen_depends_		{false};

		WEAK_REMOTE_MADHAVA() noexcept		= default;
		
		WEAK_REMOTE_MADHAVA(std::weak_ptr<MADHAVA_INFO> weakmad, uint64_t madhava_id, uint64_t tlast_usec = get_usec_time()) noexcept 
			: weakmad_(std::move(weakmad)), madhava_id_(madhava_id), tlast_usec_(tlast_usec)
		{}
		
		friend inline bool operator== (const WEAK_REMOTE_MADHAVA & lhs, uint64_t madhava_id) noexcept
		{
			return lhs.madhava_id_ == madhava_id;
		}
	};	

	using WEAK_REMOTE_MADHAVA_TBL		= RCU_HASH_TABLE <uint64_t /* madhava_id */, WEAK_REMOTE_MADHAVA, TPOOL_DEALLOC<WEAK_REMOTE_MADHAVA>>;


	static constexpr size_t			AGGR_TASK_DB_STORE_SEC = 6 * 3600; 	// 6 hours
	static constexpr size_t			LISTENER_DB_STORE_SEC = 3 * 3600 * 24; 	// 3 days

	using STACK_ID_SET			= GY_STACK_HASH_SET<uint64_t, 32 * 1024, GY_JHASHER<uint64_t>>;
	using STACK_ID_SET_ARENA		= STACK_ID_SET::allocator_type::arena_type;

	using REMOTE_PING_MAP			= GY_STACK_HASH_MAP<uint64_t, std::pair<std::weak_ptr<MADHAVA_INFO>, STACK_ID_SET>, 16 * 1024, GY_JHASHER<uint64_t>>;
	using REMOTE_PING_MAP_ARENA		= REMOTE_PING_MAP::allocator_type::arena_type;

	using MP_CLI_TCP_INFO_VEC		= GY_STACK_VECTOR<comm::MP_CLI_TCP_INFO, 32 * 1024>;
	using MP_CLI_TCP_INFO_VEC_ARENA		= MP_CLI_TCP_INFO_VEC::allocator_type::arena_type;

	using MP_CLI_TCP_INFO_MAP		= GY_STACK_HASH_MAP<std::shared_ptr<PARTHA_INFO>, MP_CLI_TCP_INFO_VEC, 8192>;
	using MP_CLI_TCP_INFO_MAP_ARENA		= MP_CLI_TCP_INFO_MAP::allocator_type::arena_type;

	using MP_SER_TCP_INFO_VEC		= GY_STACK_VECTOR<comm::MP_SER_TCP_INFO, 32 * 1024>;
	using MP_SER_TCP_INFO_VEC_ARENA		= MP_SER_TCP_INFO_VEC::allocator_type::arena_type;

	using MP_SER_TCP_INFO_MAP		= GY_STACK_HASH_MAP<std::shared_ptr<PARTHA_INFO>, MP_SER_TCP_INFO_VEC, 8192>;
	using MP_SER_TCP_INFO_MAP_ARENA		= MP_SER_TCP_INFO_MAP::allocator_type::arena_type;


	using CLI_UN_SERV_INFO_VEC		= GY_STACK_VECTOR<CLI_UN_SERV_INFO, 32 * 1024>;
	using CLI_UN_SERV_INFO_VEC_ARENA	= CLI_UN_SERV_INFO_VEC::allocator_type::arena_type;

	using CLI_UN_SERV_INFO_MAP		= GY_STACK_HASH_MAP<std::shared_ptr<PARTHA_INFO>, CLI_UN_SERV_INFO_VEC, 8192>;
	using CLI_UN_SERV_INFO_MAP_ARENA	= CLI_UN_SERV_INFO_MAP::allocator_type::arena_type;

	using SER_UN_CLI_INFO_VEC		= GY_STACK_VECTOR<SER_UN_CLI_INFO, 32 * 1024>;
	using SER_UN_CLI_INFO_VEC_ARENA		= SER_UN_CLI_INFO_VEC::allocator_type::arena_type;

	using SER_UN_CLI_INFO_MAP		= GY_STACK_HASH_MAP<std::shared_ptr<PARTHA_INFO>, SER_UN_CLI_INFO_VEC, 8192>;
	using SER_UN_CLI_INFO_MAP_ARENA		= SER_UN_CLI_INFO_MAP::allocator_type::arena_type;


	using DOWNSTREAM_VEC			= GY_STACK_VECTOR<comm::MM_LISTENER_ISSUE_RESOL::DOWNSTREAM_ONE, 200 * 1024>;
	using DOWNSTREAM_VEC_ARENA		= DOWNSTREAM_VEC::allocator_type::arena_type;

	struct ConnUnknown {
		time_t				tstartunknown_			{0};
		ConnUnknownMap			serunclimap_;
		ConnUnknownMap			cliunsermap_;

		void reset_locked(time_t tstart) noexcept
		{
			tstartunknown_ = tstart;
			serunclimap_.clear();
			cliunsermap_.clear();
		}	
	};

	class RESOL_LISTENER_ONE
	{
	public :
		comm::MM_LISTENER_ISSUE_RESOL	resol_;
		DOWNSTREAM_VEC			downvec_;	
		
		RESOL_LISTENER_ONE(const comm::MM_LISTENER_ISSUE_RESOL & resol, DOWNSTREAM_VEC_ARENA & arena) noexcept
			: resol_(resol), downvec_(arena)
		{}	
	};	

	using RESOL_MM_MAP			= GY_STACK_HASH_MAP<uint64_t /* issue_src_glob_id_ */, RESOL_LISTENER_ONE, 200 * 1024, GY_JHASHER<uint64_t>>;
	using RESOL_MM_MAP_ARENA		= RESOL_MM_MAP::allocator_type::arena_type;

	class RESOL_LISTENER_ISSUE
	{
	public :
		RESOL_MM_MAP			resmap_;
		std::shared_ptr<MCONNTRACK>	shrconn_;
		size_t				totaldownvec_count_	{0};

		RESOL_LISTENER_ISSUE(RESOL_MM_MAP_ARENA & arena) noexcept
			: resmap_(arena)
		{}	
	};	

	using MM_LISTENER_ISSUE_MAP		= GY_STACK_HASH_MAP<uint64_t /* madhava_id_ */, RESOL_LISTENER_ISSUE, 64 * 1024, GY_JHASHER<uint64_t>>;
	using MM_LISTENER_ISSUE_MAP_ARENA	= MM_LISTENER_ISSUE_MAP::allocator_type::arena_type;

	using MSOCKET_HDLR			= MSOCKET_HDLR_T <PARTHA_INFO, MADHAVA_INFO, SHYAMA_INFO, WEAK_REMOTE_MADHAVA_TBL>;

	using MAGGR_TASK			= MSOCKET_HDLR::MAGGR_TASK;
	using MAGGR_TASK_ELEM_TYPE		= MSOCKET_HDLR::MAGGR_TASK_ELEM_TYPE;
	using MAGGR_TASK_HASH_TABLE		= MSOCKET_HDLR::MAGGR_TASK_HASH_TABLE;
	using MAGGR_TASK_WEAK			= MSOCKET_HDLR::MAGGR_TASK_WEAK;

	using MTCP_CONN				= MSOCKET_HDLR::MTCP_CONN;
	using MTCP_CONN_HASH_TABLE 		= MSOCKET_HDLR::MTCP_CONN_HASH_TABLE;
	
	using MTCP_LISTENER			= MSOCKET_HDLR::MTCP_LISTENER;
	
	using MWEAK_LISTEN_ID			= MSOCKET_HDLR::MWEAK_LISTEN_ID;
	using MWEAK_LISTEN_TABLE		= MSOCKET_HDLR::MWEAK_LISTEN_TABLE;
	
	using MTCP_LISTENER_ELEM_TYPE		= MSOCKET_HDLR::MTCP_LISTENER_ELEM_TYPE;
	using MTCP_LISTENER_HASH_TABLE		= MSOCKET_HDLR::MTCP_LISTENER_HASH_TABLE;
	
	using MRELATED_LISTENER			= MSOCKET_HDLR::MRELATED_LISTENER;
	using MRELATED_LISTENER_ELEM_TYPE	= MSOCKET_HDLR::MRELATED_LISTENER_ELEM_TYPE;
	using MRELATED_LISTENER_HASH_TABLE	= MSOCKET_HDLR::MRELATED_LISTENER_HASH_TABLE;
	
	using MAGGR_LISTENER			= MSOCKET_HDLR::MAGGR_LISTENER;
	using MAGGR_LISTENER_ELEM_TYPE		= MSOCKET_HDLR::MAGGR_LISTENER_ELEM_TYPE;
	using MAGGR_LISTENER_HASH_TABLE		= MSOCKET_HDLR::MAGGR_LISTENER_HASH_TABLE;

	using MSTREAM_JSON_EPOLL		= STREAM_JSON_EPOLL<MCONNTRACK, MCONN_HANDLER, EPOLL_NODE_CACHE>;
	using MSTREAM_EVENT_BUF			= STREAM_EVENT_BUF<MCONNTRACK, MCONN_HANDLER>;

	using HOST_CONN_LIST			= HOST_CONN_FLIST <MCONNTRACK, L1_PARAMS, MAX_PERSISTENT_CONNS_PER_HOST>;

	using PARTHAID_HTABLE			= std::unordered_map<GY_MACHINE_ID, comm::SM_PARTHA_IDENT_NOTIFY, GY_MACHINE_ID::MAC_HASH>;
	
	static constexpr size_t			MAX_LISTEN_TOPN		{10};

	using LISTEN_TOP_VEC			= INLINE_STACK_VECTOR<LISTEN_TOPN, sizeof(LISTEN_TOPN) * MAX_LISTEN_TOPN + 48>;

	using LISTEN_TOP_ISSUE	 		= BOUNDED_PRIO_QUEUE<LISTEN_TOPN, LISTEN_TOPN::TOP_ISSUE, NULL_MUTEX, LISTEN_TOP_VEC>;
	using LISTEN_TOP_QPS 			= BOUNDED_PRIO_QUEUE<LISTEN_TOPN, LISTEN_TOPN::TOP_QPS, NULL_MUTEX, LISTEN_TOP_VEC>;
	using LISTEN_TOP_ACTIVE_CONN 		= BOUNDED_PRIO_QUEUE<LISTEN_TOPN, LISTEN_TOPN::TOP_ACTIVE_CONN, NULL_MUTEX, LISTEN_TOP_VEC>;
	using LISTEN_TOP_NET 			= BOUNDED_PRIO_QUEUE<LISTEN_TOPN, LISTEN_TOPN::TOP_NET, NULL_MUTEX, LISTEN_TOP_VEC>;

	static constexpr size_t			MAX_NOTIFY_MSG_Q	{128};

	using NOTIFY_MSG_VEC			= INLINE_STACK_VECTOR<NOTIFY_MSG_ONE, sizeof(NOTIFY_MSG_ONE) * MAX_NOTIFY_MSG_Q + 48>;
	using NOTIFY_MSG_PQ			= BOUNDED_PRIO_QUEUE<NOTIFY_MSG_ONE, NOTIFY_MSG_ONE::ORDER_NOTIFY, SCOPE_GY_MUTEX, NOTIFY_MSG_VEC>;

	static constexpr size_t			MAX_AGGR_TASK_TOPN		{10};

	using AGGR_TASK_TOP_VEC			= INLINE_STACK_VECTOR<MAGGR_TASK_STATE, sizeof(MAGGR_TASK_STATE) * MAX_AGGR_TASK_TOPN + 48>;
	using AGGR_TASK_TOP_ISSUE_VEC		= INLINE_STACK_VECTOR<MTASK_ISSUE, sizeof(MTASK_ISSUE) * MAX_AGGR_TASK_TOPN + 48>;

	using AGGR_TASK_TOP_ISSUE		= BOUNDED_PRIO_QUEUE<MTASK_ISSUE, MTASK_ISSUE::TOP_ISSUE, NULL_MUTEX, AGGR_TASK_TOP_ISSUE_VEC>;
	using AGGR_TASK_TOP_NET 		= BOUNDED_PRIO_QUEUE<MAGGR_TASK_STATE, MAGGR_TASK_STATE::TOP_NET, NULL_MUTEX, AGGR_TASK_TOP_VEC>;
	using AGGR_TASK_TOP_CPU			= BOUNDED_PRIO_QUEUE<MAGGR_TASK_STATE, MAGGR_TASK_STATE::TOP_CPU, NULL_MUTEX, AGGR_TASK_TOP_VEC>;
	using AGGR_TASK_TOP_RSS 		= BOUNDED_PRIO_QUEUE<MAGGR_TASK_STATE, MAGGR_TASK_STATE::TOP_RSS, NULL_MUTEX, AGGR_TASK_TOP_VEC>;
	using AGGR_TASK_TOP_CPU_DELAY 		= BOUNDED_PRIO_QUEUE<MAGGR_TASK_STATE, MAGGR_TASK_STATE::TOP_CPU_DELAY, NULL_MUTEX, AGGR_TASK_TOP_VEC>;
	using AGGR_TASK_TOP_VM_DELAY 		= BOUNDED_PRIO_QUEUE<MAGGR_TASK_STATE, MAGGR_TASK_STATE::TOP_VM_DELAY, NULL_MUTEX, AGGR_TASK_TOP_VEC>;
	using AGGR_TASK_TOP_IO_DELAY 		= BOUNDED_PRIO_QUEUE<MAGGR_TASK_STATE, MAGGR_TASK_STATE::TOP_IO_DELAY, NULL_MUTEX, AGGR_TASK_TOP_VEC>;

	using RT_ADEF_VEC			= std::vector<std::shared_ptr<MRT_ALERTDEF>>;				

	using MFields				= MFIELDS_T <PARTHA_INFO, MADHAVA_INFO, SHYAMA_INFO, MTCP_LISTENER, MAGGR_TASK>;
	using HostFields			= MFields::HostFields;
	using HostStateFields			= MFields::HostStateFields;
	using CpuMemFields			= MFields::CpuMemFields;
	using SvcSummFields			= MFields::SvcSummFields;
	using SvcInfoFields			= MFields::SvcInfoFields;
	using SvcStateFields			= MFields::SvcStateFields;
	using ExtSvcStateFields			= MFields::ExtSvcStateFields;
	using ProcStateFields			= MFields::ProcStateFields;
	using ExtProcStateFields		= MFields::ExtProcStateFields;
	using ProcInfoFields			= MFields::ProcInfoFields;
	using ActiveClientConnFields		= MFields::ActiveClientConnFields;
	using ExtActiveConnFields		= MFields::ExtActiveConnFields;
	using ExtClientConnFields		= MFields::ExtClientConnFields;
	using TopCpuRssFields			= MFields::TopCpuRssFields;
	using TopPgCpuFields			= MFields::TopPgCpuFields;
	using TopForkFields			= MFields::TopForkFields;

	static constexpr uint64_t		INFO_DB_UPDATE_SEC			{300};		// 5 min

	class RT_ALERT_VECS
	{
	public :	
		SharedMutex				adef_rwmutex_;

		RT_ADEF_VEC				adef_hoststate_;
		RT_ADEF_VEC				adef_cpumem_;
		RT_ADEF_VEC				adef_svcsumm_;
		RT_ADEF_VEC				adef_svcstate_;
		RT_ADEF_VEC				adef_svcinfo_;
		RT_ADEF_VEC				adef_activeconn_;
		RT_ADEF_VEC				adef_clientconn_;
		RT_ADEF_VEC				adef_procstate_;
		RT_ADEF_VEC				adef_procinfo_;
		RT_ADEF_VEC				adef_topcpu_;
		RT_ADEF_VEC				adef_toppgcpu_;
		RT_ADEF_VEC				adef_toprss_;
		RT_ADEF_VEC				adef_topfork_;

		uint32_t				nextact_		{0};
		uint32_t				nextcli_		{0};

		gy_atomic<uint64_t>			last_upd_cusec_		{0};

		void reset_locked();

		RT_ADEF_VEC * get_subsys_vec(SUBSYS_CLASS_E csubsys) noexcept;
	};	


	class PARTHA_INFO : public HOST_CONN_LIST, public std::enable_shared_from_this <PARTHA_INFO>
	{	
	public :	
		GY_MUTEX			mutex_;

		uint32_t			comm_version_				{1};
		uint32_t			partha_version_				{0};

		GY_MACHINE_ID			machine_id_;	

		uint64_t			last_register_tusec_			{0};
		uint64_t			last_register_cusec_			{0};

		int64_t				ident_key_expiry_tsec_			{0};
		uint64_t			partha_ident_key_			{0};	
		int64_t				boot_time_sec_				{0};

		gy_atomic<uint64_t>		last_db_upd_tusec_			{0};
		gy_atomic<uint64_t>		last_db_register_tusec_			{0};
		gy_atomic<time_t>		last_disconnect_tsec_			{0};

		uint64_t			madhava_id_				{0};
		std::weak_ptr<MADHAVA_INFO>	madhava_weak_;

		RT_ALERT_VECS	 		rtalerts_;	
		
		char				hostname_[MAX_DOMAINNAME_SIZE]				{};
		char				cluster_name_[comm::MAX_CLUSTER_NAME_LEN]		{};
		uint64_t			cluster_hash_						{0};

		char				region_name_[comm::MAX_ZONE_LEN]			{};
		char				zone_name_[comm::MAX_ZONE_LEN]				{};

		char				machine_id_str_[GY_MACHINE_ID::MACHID_STRLEN + 1]	{};
		uint8_t				hostname_len_				{0};
		uint8_t				cluster_len_				{0};
		uint8_t				region_len_				{0};
		uint8_t				zone_len_				{0};

		uint8_t				ndel_times_				{0};
		bool				is_shyama_pinged_			{false};

		bool				is_virtual_cpu_				{false};
		uint16_t			cores_online_				{0};
		uint16_t			cores_offline_				{0};
		uint32_t			ram_mb_					{0};

		uint32_t			kern_version_num_			{0};
		GY_IP_ADDR			remote_ip_;
		/*SYNC_STRING			node_tagname_;*/

		MTCP_LISTENER_HASH_TABLE	listen_tbl_				{1};
		MRELATED_LISTENER_HASH_TABLE	related_listen_tbl_			{1};
		MAGGR_LISTENER_HASH_TABLE	aggr_listen_tbl_			{1, 1, 1024, true, false};
		uint64_t			last_listen_state_tusec_		{0};
		uint64_t			last_all_listen_state_tusec_		{0};
		uint64_t			last_shyama_nat_ping_tusec_		{0};
		uint64_t			last_svcinfo_tsec_			{0};
		LISTEN_SUMM_STATS<int>		summstats_;
		LISTEN_TOP_ISSUE		top_issue_listen_			{MAX_LISTEN_TOPN};
		LISTEN_TOP_QPS			top_qps_listen_				{MAX_LISTEN_TOPN};	
		LISTEN_TOP_ACTIVE_CONN		top_active_conn_listen_			{MAX_LISTEN_TOPN};	
		LISTEN_TOP_NET			top_net_listen_				{MAX_LISTEN_TOPN};	

		static constexpr size_t		MAX_UNKNOWN_MAPS			{3};		// Wait max 20 * 3 (60) sec for unknown entries
		GY_MUTEX			connlistenmutex_;
		time_t				tconnlistensec_				{0};
		time_t				tdbconnlistensec_			{0};
		time_t				tlast_active_insert_			{0};
		ConnPeerMapArena		connpeerarena_;
		ConnListenMap			connlistenmap_;
		ConnClientMap			connclientmap_;
		ConnUnknown			unknownmaps_[MAX_UNKNOWN_MAPS];
		
		uint64_t			last_aggr_state_tusec_			{0};
		uint64_t			last_aggrinfo_tsec_			{0};
		AGGR_TASK_TOP_ISSUE		atask_top_issue_			{MAX_AGGR_TASK_TOPN};
		AGGR_TASK_TOP_NET		atask_top_net_				{MAX_AGGR_TASK_TOPN};
		AGGR_TASK_TOP_CPU		atask_top_cpu_				{MAX_AGGR_TASK_TOPN};
		AGGR_TASK_TOP_RSS		atask_top_rss_				{MAX_AGGR_TASK_TOPN};
		AGGR_TASK_TOP_CPU_DELAY		atask_top_cpu_delay_			{MAX_AGGR_TASK_TOPN};
		AGGR_TASK_TOP_VM_DELAY		atask_top_vm_delay_			{MAX_AGGR_TASK_TOPN};
		AGGR_TASK_TOP_IO_DELAY		atask_top_io_delay_			{MAX_AGGR_TASK_TOPN};

		MAGGR_TASK_HASH_TABLE		task_aggr_tbl_				{1};
		int64_t				cli_task_missed_			{0};

		SCOPE_FD			trace_req_sock_;
		time_t				trace_tsec_				{0};

		CPU_MEM_STATE			cpu_mem_state_;	
		comm::HOST_STATE_NOTIFY		host_state_;
		TASK_TOP_PROCS_INFO		toptasks_;
		
		uint64_t			init_tusec_				{get_usec_time()};

		PARTHA_INFO() 			= default;
		
		void handle_disconnect() noexcept
		{
			last_disconnect_tsec_.store(time(nullptr), mo_release);
			
			trace_req_sock_.close();

			INFOPRINT_OFFLOAD("Partha Host %s disconnected all connections...\n", hostname_);
		}

		uint64_t get_last_register_usec() const noexcept
		{
			return last_register_tusec_;
		}

		uint64_t get_last_host_state_tusec() const noexcept
		{
			return host_state_.curr_time_usec_;
		}

		// Returns {Slot start sec, slot index}
		static inline std::pair<time_t, uint8_t> get_unknown_slot(time_t tcur) noexcept
		{
			time_t			tmod = (tcur % 60);

			return { tcur - tmod, tmod / (60 / MAX_UNKNOWN_MAPS) }; 
		}	

		ConnUnknown & get_curr_unknown_locked(time_t tcur, bool reset_old) noexcept
		{
			const auto 			[ tstart, slot ] = get_unknown_slot(tcur);
			auto				& curr = unknownmaps_[slot];

			if (reset_old && curr.tstartunknown_ < tstart) {
				curr.reset_locked(tstart);
			}	

			return curr;
		}	

		ConnUnknown * get_curr_unknown_locked(time_t tcur) noexcept
		{
			const auto 			[ tstart, slot ] = get_unknown_slot(tcur);
			auto				& curr = unknownmaps_[slot];

			if (curr.tstartunknown_ == tstart) {
				return &curr;
			}	

			return nullptr;
		}	

		void handle_unknown_conns(bool is_multi_madhava) noexcept;

		char * print_string(STR_WR_BUF & strbuf) const noexcept
		{
			strbuf.appendconst("Partha Host ");
			strbuf.append(hostname_, hostname_len_);
			strbuf.appendconst(" ID ");
			strbuf.append(machine_id_str_, sizeof(machine_id_str_) - 1);
			strbuf.append(' ');

			return strbuf.buffer();
		}

		CHAR_BUF<64> get_db_schema() const noexcept
		{
			CHAR_BUF<64>		buf;

			std::memcpy(buf.get(), "sch", 3);
			std::memcpy(buf.get() + 3, machine_id_str_, sizeof(machine_id_str_));

			static_assert(sizeof(buf) > 3 + sizeof(machine_id_str_));

			return buf;
		}	

		friend inline bool operator== (const std::shared_ptr<PARTHA_INFO> & lhs, const GY_MACHINE_ID id) noexcept
		{
			auto		plhs = lhs.get();

			return (plhs && plhs->machine_id_ == id);
		}

		friend inline bool operator== (const PARTHA_INFO & lhs, const GY_MACHINE_ID id) noexcept
		{
			return lhs.machine_id_ == id;
		}
	};	

	using 	PARTHA_INFO_ELEM		= RCU_HASH_WRAPPER <GY_MACHINE_ID, std::shared_ptr<PARTHA_INFO>>;
	using 	PARTHA_INFO_HTABLE		= RCU_HASH_TABLE <GY_MACHINE_ID, PARTHA_INFO_ELEM>;

	class MADHAVA_INFO : public HOST_CONN_LIST, public std::enable_shared_from_this <MADHAVA_INFO>
	{	
	public :	
		uint64_t			madhava_id_		{0};
		DOMAIN_PORT			listener_port_;
		GY_IP_ADDR			remote_ip_;

		MTCP_LISTENER_HASH_TABLE	listen_tbl_		{8, 8, 1024, true, false};	// Used only for remote Madhava instances
		MAGGR_TASK_HASH_TABLE		task_aggr_tbl_		{8, 8, 1024, true, false};	// Used only for remote Madhava instances

		uint64_t			init_tusec_		{get_usec_time()};

		uint64_t			last_reg_tsec_		{0};
		uint64_t			last_upd_tusec_		{init_tusec_};
		std::atomic<int>		npartha_nodes_		{0};
		int				max_partha_nodes_	{0};	

		uint32_t			comm_version_					{0};
		uint32_t			madhava_version_				{0};
		char				region_name_[comm::MAX_ZONE_LEN]		{};
		char				zone_name_[comm::MAX_ZONE_LEN]			{};
		char				madhava_name_[comm::MAX_CLUSTER_NAME_LEN]	{};
		
		/*SYNC_STRING			node_tagname_;*/

		MADHAVA_INFO(const char *pdomain, uint16_t port, uint64_t madhava_id)
			: madhava_id_(madhava_id), listener_port_(pdomain, port)
		{}

		const char * get_domain() const noexcept
		{
			return listener_port_.get_domain();
		}

		uint16_t get_port() const noexcept
		{
			return listener_port_.get_port();
		}	

		char * print_string(STR_WR_BUF & strbuf) const noexcept
		{
			strbuf.appendconst("Madhava ");
			listener_port_.print_string(strbuf);
			strbuf.appendfmt(" Madhava %s ID %016lx ", madhava_name_, madhava_id_);

			return strbuf.buffer();
		}

		friend inline bool operator== (const std::shared_ptr<MADHAVA_INFO> & lhs, uint64_t id) noexcept
		{
			auto		plhs = lhs.get();

			return (plhs && plhs->madhava_id_ == id);
		}
	};	

	using 	MADHAVA_INFO_ELEM		= RCU_HASH_WRAPPER <uint64_t, std::shared_ptr<MADHAVA_INFO>>;
	using 	MADHAVA_INFO_HTABLE		= RCU_HASH_TABLE <uint64_t, MADHAVA_INFO_ELEM>;

	class SHYAMA_INFO : public HOST_CONN_LIST
	{
	public :	
		uint64_t			nmadhava_					{0};	

		int64_t				last_reg_csec_					{get_sec_clock()};
		time_t				last_reg_tsec_					{0};
		time_t				tlast_conn_sched_				{0};
		char				last_error_buf_[128]				{};
		uint64_t			shyama_id_					{0};
		uint32_t			comm_version_					{0};
		uint32_t			shyama_version_					{0};
		char				region_name_[comm::MAX_ZONE_LEN]		{};
		char				zone_name_[comm::MAX_ZONE_LEN]			{};
		char				shyama_name_[comm::MAX_CLUSTER_NAME_LEN]	{};
		char				shyama_secret_[comm::MAX_CLUSTER_NAME_LEN]	{};
		
		std::vector<std::string>	shyama_host_vec_;
		std::vector<uint16_t>		shyama_port_vec_;
		char				curr_shyama_host_[MAX_DOMAINNAME_SIZE]		{};
		uint16_t			curr_shyama_port_				{0};
		uint16_t			curr_shyama_index_				{0};
		uint8_t				nfails_						{0};

		comm::SHYAMA_MADHAVA_STATUS	last_status_					{};

		void handle_disconnect(MCONNTRACK *pconn, comm::HOST_TYPES_E host_type, comm::CLI_TYPE_E cli_type) noexcept
		{
			HOST_CONN_LIST::del_conn(pconn, host_type);

			time_t			tcurr = time(nullptr);

			start_connect_scheduler(pconn->pl1_, cli_type, tcurr > tlast_conn_sched_ + 30 ? 0 : 10 * 1000);

			tlast_conn_sched_ = tcurr;
		}	

		char * print_string(STR_WR_BUF & strbuf) const noexcept
		{
			return strbuf.appendfmt("Shyama '%s\' Host %s Port %hu ID %016lx ", shyama_name_, curr_shyama_host_, curr_shyama_port_, shyama_id_);
		}

		static void start_connect_scheduler(const L1_PARAMS *pl1, comm::CLI_TYPE_E cli_type, uint64_t init_delay_ms = 0) noexcept
		{
			GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_LONG_DURATION)->add_schedule(init_delay_ms, 30'000, 0, connect_scheduler_name(cli_type), 
				[pl1, cli_type] {
					L1_MISC_NOTIFY		l1not(pl1, cli_type, SHYAMA_RECONNECT());

					bool			bret;
					int			ntries = 0;

					do { 
						bret = pl1->psignalq_->write(std::move(l1not));
					} while (bret == false && ntries++ < 10);

					if (bret == false) {
						return;
					}

					int64_t			n = 1;

					(void)::write(pl1->signal_fd_, &n, sizeof(int64_t));
				}, false);	
		}	

		static void stop_shyama_scheduler(comm::CLI_TYPE_E cli_type) noexcept
		{
			GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_LONG_DURATION)->cancel_schedule(connect_scheduler_name(cli_type));
		}	
	
		static constexpr const char * connect_scheduler_name(comm::CLI_TYPE_E cli_type) noexcept
		{
			switch (cli_type) {
			
			case comm::CLI_TYPE_REQ_RESP	: return "Shyama Req Resp Connect";

			case comm::CLI_TYPE_RESP_REQ 	: return "Shyama Resp Req Connect";

			default 			: return "Invalid Shyama Connection Type";
			}	
		}
	};	

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
	};	
	
	using NODE_STATS_HTABLE		= std::unordered_map<DOMAIN_PORT, std::shared_ptr<NODE_INFO>, DOMAIN_PORT::DOMAIN_PORT_HASH>;
	
	// Nested Classes Definitions completed

	// To be called with MCONNTRACK shared_ptr active
	template <typename T, comm::COMM_TYPE_E type_>
	bool send_l1_register_connect_error(const L1_PARAMS *pl1_src, std::weak_ptr <MCONNTRACK> weakconn, MCONNTRACK *pconn, comm::COMM_HEADER::HDR_MAGIC_E comm_magic, \
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
		
		// MCONNTRACK shared_ptr already created when this is called. So pconn can be safely used
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
	ssize_t send_register_connect_error(MCONNTRACK *pconn1, ERR_CODES_E errcode, const char *errstr, POOL_ALLOC_ARRAY *pthrpoolarr)
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

	// Memory will be alocated for header + resp_len
	bool send_query_response(const std::shared_ptr<MCONNTRACK> & connshr, uint64_t seqid, comm::RESP_TYPE_E resptype, ERR_CODES_E errcode, comm::RESP_FORMAT_E respfmt, \
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

	bool send_json_error_resp(const std::shared_ptr<MCONNTRACK> & connshr, ERR_CODES_E errcode, uint64_t resp_seqid, const char *errortxt, \
						size_t lenerr = 0, POOL_ALLOC_ARRAY *parrpool = nullptr) noexcept
	{
		using namespace			comm;

		try {
			if (lenerr == 0) {
				lenerr = strlen(errortxt);
			}	

			MSTREAM_JSON_EPOLL			stream(connshr, *this, RESP_WEB_JSON, resp_seqid, parrpool, errcode);
			SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL>	writer(stream);
			
			stream.reserve(max_json_escape_size(lenerr) + 80);

			writer.StartObject();

			writer.KeyConst("error");
			writer.Int(errcode);

			writer.KeyConst("errmsg");
			writer.String(errortxt, lenerr);
				
			writer.KeyConst("madid");
			writer.String(gmadhava_id_str_, 16);
		
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

	SHYAMA_INFO * get_shyama() noexcept
	{
		return &gshyama_;
	}	

	bool add_notificationq(NOTIFY_MSGTYPE_E ntype, time_t currtsec, const char * pmsg, uint16_t msglen = 0, GY_MACHINE_ID machid = {})
	{
		const auto retcb = [this, currtsec](bool bret) noexcept
		{
			if (bret) {
				tlastq_.store(currtsec, mo_relaxed);
			}	
		};	

		const auto compcb = [currtsec](const NOTIFY_MSG_ONE & rhs) noexcept
		{
			return currtsec > rhs.tmsg_;
		};	

		return notifyq_.try_emplace_check(retcb, compcb, ntype, pmsg, msglen ? msglen : strlen(pmsg), currtsec, machid);
	}	

	// Close all conns for a Partha, Shyama, a remote Madhava or a Node Instance
	void close_all_conns(HOST_CONN_LIST & minfo) noexcept
	{
		auto lwalk = [&, this](HOST_CONN_LIST::HOST_CONN_L1 & lconn) noexcept
		{
			if (lconn.is_cli_active()) {
				// This is executed under mutex lock. But OK as we need to clear all conns
				send_l1_close_conn(lconn.pl1_, std::weak_ptr <MCONNTRACK>(lconn.weakconn_), lconn.pconn_);
			}
			return CB_DELETE_ELEM;
		};	

		minfo.walk_conn_list(lwalk);
	}	



	/*
	 * Class variables declaration follows
	 */

	ACC_PARAMS 				*paccept_arr_		{nullptr};

	L1_PARAMS 				*pl1_cli_arr_		{nullptr};
	L1_PARAMS 				*pl1_shyama_		{nullptr};

	L2_PARAMS 				*pl2_db_rd_arr_		{nullptr};
	L2_PARAMS 				*pl2_misc_arr_		{nullptr};
	L2_PARAMS 				*pl2_alert_arr_		{nullptr};

	MPMCQ_COMM				**ppmpmc_db_rd_arr_	{nullptr};
	MPMCQ_COMM				**ppmpmc_misc_arr_	{nullptr};
	MPMCQ_COMM				**ppmpmc_alert_arr_	{nullptr};

	GY_MUTEX				node_partha_mutex_;
	NODE_STATS_HTABLE			node_tbl_;
	PARTHAID_HTABLE				partha_id_tbl_;
	uint32_t				last_node_cnt_		{0};

	uint32_t				last_madhava_cnt_	{0};

	PARTHA_INFO_HTABLE			partha_tbl_		{1};
	uint64_t				last_partha_conns_	{0};
	
	MTCP_CONN_HASH_TABLE			glob_tcp_conn_tbl_	{1};

	uint64_t				last_par_db_upd_tusec_	{0};
	gy_atomic<uint64_t>			last_partha_chg_tusec_	{0};

	MADHAVA_C			* const pmadhava_;
	uint32_t				max_partha_allowed_	{0};

	uint32_t				db_storage_days_	{0};
	char					gmadhava_id_str_[17]	{};
	uint64_t				gmadhava_id_		{0};
	std::shared_ptr<MADHAVA_INFO>		gmadhava_shr_;
	std::weak_ptr<MADHAVA_INFO>		gmadhava_weak_;
	MADHAVA_INFO_HTABLE			madhava_tbl_		{1};
	
	SHYAMA_INFO				gshyama_;
	bool					shyama_reset_stats_	{false};
	bool					shyama_send_parthas_	{false};
	time_t					tpartha_pingall_	{time(nullptr) + 5 * 3600};

	MTCP_LISTENER_HASH_TABLE		glob_listener_tbl_	{1};

	GY_SCHEDULER				*pdb_scheduler_		{nullptr};
	std::unique_ptr<PGConnPool>		db_scheduler_pool_;
	uint64_t				curr_db_size_		{0};
	time_t					tlast_db_size_		{time(nullptr)};

	std::optional<GY_THREAD>		instance_thr_;
	time_t					tlast_instance_		{0};
	GY_SCHEDULER				*pdbmain_scheduler_	{nullptr};
	GY_SCHEDULER				db_part_scheduler_	{false};

	DBFailStats				db_stats_;

	NOTIFY_MSG_PQ				notifyq_		{MAX_NOTIFY_MSG_Q};
	gy_atomic<time_t>			tlastq_			{0};

	MALERT_HDLR				*palerthdlr_		{nullptr};

	COND_VAR <SCOPE_GY_MUTEX>		barcond_;
	std::atomic<size_t>			nblocked_acc_		{0};
	std::atomic<size_t>			nblocked_l1_		{0};
	std::atomic<size_t>			nblocked_l2_		{0};
	std::atomic<bool>			all_spawned_		{false};
	bool					is_master_		{false};

	std::atomic<int64_t>			gtconncount		{0};

	std::vector<std::string>		& listen_host_vec_;
	std::vector<uint16_t>			& listen_port_vec_;
	char					service_hostname_[MAX_DOMAINNAME_SIZE]		{};
	uint16_t				service_port_					{0};
	char					region_name_[comm::MAX_ZONE_LEN]		{};
	char					zone_name_[comm::MAX_ZONE_LEN]			{};
	char					madhava_name_[comm::MAX_CLUSTER_NAME_LEN]	{};
	char					cloud_type_[64]					{};

	static constexpr uint8_t		gpadbuf[8] = "\x0\x0\x0\x0\x0\x0\x0";
	static constexpr size_t			MISC_DB_POOL_CONNS = 3;	
	static constexpr size_t			RD_DB_POOL_CONNS = 2;	

	MCONN_HANDLER(MADHAVA_C *pmadhava);

	~MCONN_HANDLER() 						= delete;

	MCONN_HANDLER(const MCONN_HANDLER &)				= delete;
	MCONN_HANDLER(MCONN_HANDLER &&)					= delete;
	MCONN_HANDLER & operator=(const MCONN_HANDLER &)		= delete;
	MCONN_HANDLER & operator=(MCONN_HANDLER &&)			= delete;

	static MCONN_HANDLER * get_singleton() noexcept;

	int 	handle_accept(GY_THREAD *pthr);
	
	int 	handle_l1(GY_THREAD *pthr);

	int 	handle_l2(GY_THREAD *pthr);

	int 	handle_l2_db(L2_PARAMS & param, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);
	int 	handle_l2_misc(L2_PARAMS & param, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);

	void	init_alert_handlers();
	int 	handle_alert_mgr(L2_PARAMS & param);
	int 	alert_realtime_thread() noexcept;
	int 	alert_db_thread(void *arg) noexcept;

	MAKE_CLASS_FUNC_WRAPPER_NO_ARG(MCONN_HANDLER, alert_realtime_thread);
	MAKE_CLASS_FUNC_WRAPPER_WITH_ARG(MCONN_HANDLER, alert_db_thread);

	int 	handle_misc_partha_reg(comm::PM_CONNECT_CMD_S *preg, const DB_WRITE_ARR & dbarr, L2_PARAMS & param, POOL_ALLOC_ARRAY *pthrpoolarr, STATS_STR_MAP & statsmap, PGConnPool & dbpool);
	int 	handle_misc_madhava_reg(comm::MM_CONNECT_CMD_S *preg, const DB_WRITE_ARR & dbarr, L2_PARAMS & param, POOL_ALLOC_ARRAY *pthrpoolarr, STATS_STR_MAP & statsmap);

	ssize_t send_immediate(MCONNTRACK *pconn1, bool throw_on_error = true);

	int 	connect_shyama_blocking(comm::CLI_TYPE_E clitype, MAP_CONNTRACK & mconntrack, int epollfd, const L1_PARAMS *pl1, STATS_STR_MAP & statsmap, POOL_ALLOC_ARRAY * pthrpoolarr);
	void 	send_shyama_registration(MCONNTRACK *pconn);
	bool 	handle_shyama_reg_resp(MCONNTRACK *pconn1, comm::MS_REGISTER_RESP_S *preg, STATS_STR_MAP & statsmap);
	
	void 	send_madhava_registration(MCONNTRACK *pconn, uint64_t remote_madhava_id);
	bool 	handle_madhava_reg_resp(MCONNTRACK *pconn1, comm::MM_CONNECT_RESP_S *preg, STATS_STR_MAP & statsmap);

	int 	handle_misc_node_reg(comm::NM_CONNECT_CMD_S *pnm, const DB_WRITE_ARR & dbarr, L2_PARAMS & param, POOL_ALLOC_ARRAY *pthrpoolarr, STATS_STR_MAP & statsmap);

	bool 	send_mp_cli_tcp_info(PARTHA_INFO *prawpartha, const comm::MP_CLI_TCP_INFO *pone, size_t nconns, POOL_ALLOC_ARRAY *pthrpoolarr);
	bool 	send_mp_ser_tcp_info(PARTHA_INFO *prawpartha, const comm::MP_SER_TCP_INFO *pone, size_t nconns, POOL_ALLOC_ARRAY *pthrpoolarr);

	bool 	set_partha_ident(MCONNTRACK *pconn1, comm::SM_PARTHA_IDENT_NOTIFY *preq, STATS_STR_MAP & statsmap) noexcept;

	bool	send_l1_close_conn(const L1_PARAMS *pl1_src, std::weak_ptr <MCONNTRACK> && weakconn, MCONNTRACK *pconn, const char *errstr = nullptr, uint32_t errlen = 0) noexcept;	
	
	bool	send_l1_close_conn(const std::shared_ptr<MCONNTRACK> & connshr, const char *errstr = nullptr, uint32_t errlen = 0) noexcept
	{
		return connshr && send_l1_close_conn(connshr->pl1_, connshr, connshr.get(), errstr, errlen);
	}

	bool 	schedule_l1_send_data(const std::shared_ptr<MCONNTRACK> & connshr, comm::COMM_TYPE_E data_type, EPOLL_IOVEC_ARR && data_arr, bool close_conn_on_send = false) noexcept;

	bool 	schedule_l1_query(ASYNC_SOCK_CB && async_cb, const std::shared_ptr<MCONNTRACK> & connshr, EPOLL_IOVEC_ARR && data_arr) noexcept;

	void 	spawn_init_threads();

	void	init_db_glob_conns();

	GyPGConn get_new_db_conn(bool auto_reconnect = false);

	int	sync_partha_node_stats() noexcept;
	bool 	schedule_remote_madhava_conn(const char *madhava_hostname, uint16_t madhava_port, uint64_t madhava_id, uint64_t sched_after_msec, \
			int l1_id, std::weak_ptr<MADHAVA_INFO> weak_info) noexcept;

	void	send_cluster_state() noexcept;
	void 	send_shyama_status() noexcept;
	void 	send_partha_status() noexcept;
	void 	send_remote_madhava_status() noexcept;

	bool	multiple_madhava_active() const noexcept
	{
		return ((GY_READ_ONCE(gshyama_.last_status_.nmadhava_partha_)) > 1);
	}

	bool	is_active_madhava() const noexcept
	{
		return (GY_READ_ONCE(gshyama_.last_status_.active_madhava_id_) == gmadhava_id_);
	}	

	MA_SETTINGS_C * get_settings() const noexcept;

	CHAR_BUF<comm::MAX_CLUSTER_NAME_LEN> get_dbname() const noexcept
	{
		return CHAR_BUF<comm::MAX_CLUSTER_NAME_LEN>(madhava_name_);
	}	

	std::pair<int, int> 	init_set_instance_master(PGConnPool & dbpool);
	int 			instance_thread() noexcept;
	
	MAKE_CLASS_FUNC_WRAPPER_NO_ARG(MCONN_HANDLER, instance_thread);

	typedef void (*ExtraColWriteFP)(SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer);

	void 	insert_db_mini_task(const std::shared_ptr<PARTHA_INFO> & partha_shr, const comm::TASK_MINI_ADD * ptask, int ntasks, uint8_t *pendptr);
	void 	insert_db_full_task(const std::shared_ptr<PARTHA_INFO> & partha_shr, const comm::TASK_FULL_ADD * ptask, int ntasks, uint8_t *pendptr, PGConnPool & dbpool);
	void 	insert_db_top_procs(const std::shared_ptr<PARTHA_INFO> & partha_shr, const comm::TASK_TOP_PROCS * ptask, uint8_t *pendptr, PGConnPool & dbpool);
	void 	insert_db_task_stats(const std::shared_ptr<PARTHA_INFO> & partha_shr, const comm::TASK_HISTOGRAM * ptask, int ntasks, uint8_t *pendptr);

	std::tuple<bool, bool, bool> add_tcp_conn_cli(const std::shared_ptr<PARTHA_INFO> & partha_shr, comm::TCP_CONN_NOTIFY *pone, uint64_t tcurrusec, \
				MP_CLI_TCP_INFO_MAP & parclimap, MP_CLI_TCP_INFO_VEC_ARENA & parclivecarena, \
				MP_SER_TCP_INFO_MAP & parsermap, MP_SER_TCP_INFO_VEC_ARENA & parservecarena, \
				SER_UN_CLI_INFO_MAP & serunmap, SER_UN_CLI_INFO_VEC_ARENA & serunvecarena, POOL_ALLOC_ARRAY *pthrpoolarr); 
	std::tuple<bool, bool, bool> add_tcp_conn_ser(const std::shared_ptr<PARTHA_INFO> & partha_shr, comm::TCP_CONN_NOTIFY *pone, uint64_t tcurrusec, \
				MP_CLI_TCP_INFO_MAP & parclimap, MP_CLI_TCP_INFO_VEC_ARENA & parclivecarena, \
				MP_SER_TCP_INFO_MAP & parsermap, MP_SER_TCP_INFO_VEC_ARENA & parservecarena, \
				CLI_UN_SERV_INFO_MAP & cliunmap, CLI_UN_SERV_INFO_VEC_ARENA & cliunvecarena, POOL_ALLOC_ARRAY *pthrpoolarr); 
	bool 	cleanup_local_cli_tcp_conn(PARTHA_INFO *prawpartha, uint64_t cli_task_aggr_id, uint64_t ser_glob_id, uint64_t ser_madhava_id, int nconns_closed); 
	bool 	add_local_conn_task_ref(PARTHA_INFO *pcli_partha, uint64_t aggr_task_id, MTCP_LISTENER *plistener, \
				const char *pcli_comm, uint32_t cli_cmdline_len, const char *pcli_cmdline, POOL_ALLOC_ARRAY *pthrpoolarr, uint64_t tusec_start);
	bool 	cleanup_remote_cli_tcp_conn(MADHAVA_INFO *pcli_madhava, uint64_t cli_task_aggr_id, uint64_t ser_glob_id, int nconns_closed); 
	bool 	add_remote_conn_task_ref(MADHAVA_INFO *pcli_madhava, uint64_t aggr_task_id, GY_MACHINE_ID remote_machine_id, MTCP_LISTENER *plistener, \
				const char *pcli_comm, uint32_t cli_cmdline_len, const char *pcli_cmdline, POOL_ALLOC_ARRAY *pthrpoolarr, uint64_t tusec_start);
	int 	upd_cli_ser_unknown_conns(CLI_UN_SERV_INFO_MAP & cliunmap);
	int 	upd_ser_cli_unknown_conns(SER_UN_CLI_INFO_MAP & serunmap);
	void 	cleanup_tcp_conn_table() noexcept;
	bool 	send_shyama_conn_close(const comm::MS_TCP_CONN_CLOSE *pone, size_t nconns, POOL_ALLOC_ARRAY *pthrpoolarr);
	bool 	partha_tcp_conn_info(const std::shared_ptr<PARTHA_INFO> & partha_shr, comm::TCP_CONN_NOTIFY * pone, int nconns, uint8_t *pendptr, POOL_ALLOC_ARRAY *pthrpoolarr);
	bool 	handle_partha_nat_notify(comm::NAT_TCP_NOTIFY * pone, int nconns, uint8_t *pendptr, POOL_ALLOC_ARRAY *pthrpoolarr, bool is_last_elem, DB_WRITE_ARR && dbarr);
	void 	handle_shyama_tcp_cli(comm::SHYAMA_CLI_TCP_INFO * pone, int nconns, uint8_t *pendptr, POOL_ALLOC_ARRAY *pthrpoolarr);
	void 	handle_shyama_tcp_ser(comm::SHYAMA_SER_TCP_INFO * pone, int nconns, uint8_t *pendptr, POOL_ALLOC_ARRAY *pthrpoolarr);
	
	bool 	handle_madhava_list(comm::MADHAVA_LIST * pone, int nelems, uint8_t *pendptr, STATS_STR_MAP & statsmap);

	bool 	partha_aggr_task_state(const std::shared_ptr<PARTHA_INFO> & partha_shr, const comm::AGGR_TASK_STATE_NOTIFY * pone, int ntasks, \
				uint8_t *pendptr, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);
	bool 	handle_mm_aggr_task_state(const std::shared_ptr<MADHAVA_INFO> & madhava_shr, const comm::AGGR_TASK_STATE_NOTIFY * pone, int ntasks, uint8_t *pendptr);
	void 	handle_aggr_task_deletion(MAGGR_TASK *pmtask, PARTHA_INFO *prawpartha, REMOTE_PING_MAP & remote_map, STACK_ID_SET_ARENA & stacksetarena);

	uint64_t send_remote_aggr_task_ping(REMOTE_PING_MAP & remote_map, POOL_ALLOC_ARRAY *pthrpoolarr);
	uint64_t send_remote_aggr_task_deletion(REMOTE_PING_MAP & remote_map, POOL_ALLOC_ARRAY *pthrpoolarr);

	bool 	handle_add_aggr_task(const std::shared_ptr<MCONNTRACK> &connshr, comm::TASK_AGGR_NOTIFY *ptask, int nevents, uint8_t *pendptr, \
				STATS_STR_MAP & statsmap, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);

	bool 	handle_aggr_task_hist_stats(const std::shared_ptr<MCONNTRACK> &connshr, comm::AGGR_TASK_HIST_STATS *ptask, int nevents, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);
	void 	ping_remote_aggr_task(MAGGR_TASK *pmtask, MWEAK_LISTEN_TABLE *plistentbl, REMOTE_PING_MAP & remote_map, STACK_ID_SET_ARENA & stacksetarena);
	bool 	handle_ping_aggr_task(const std::shared_ptr<PARTHA_INFO> &partha_shr, comm::PING_TASK_AGGR *ptask, int nevents, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool, bool isdummycall = false);
	
	bool 	handle_mm_ping_aggr_task(const std::shared_ptr<MADHAVA_INFO> &madshr, comm::MM_TASK_AGGR_PING *ptask, int nevents);
	bool 	handle_mm_del_aggr_task(const std::shared_ptr<MADHAVA_INFO> &madshr, comm::MM_TASK_AGGR_DEL *ptask, int nevents, bool isdummycall = false);

	MTCP_LISTENER * upd_remote_listener(MADHAVA_INFO *premotemad, const comm::SHYAMA_CLI_TCP_INFO *pone, bool & is_new, uint64_t tusec);

	void 	handle_cpu_mem_state(const std::shared_ptr<PARTHA_INFO> & partha_shr, const comm::CPU_MEM_STATE_NOTIFY * pcpumem, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);
	void 	handle_host_state(const std::shared_ptr<PARTHA_INFO> & partha_shr, const comm::HOST_STATE_NOTIFY * phost, PGConnPool & dbpool);
	void 	handle_host_info(const std::shared_ptr<PARTHA_INFO> & partha_shr, const comm::HOST_INFO_NOTIFY * phost, PGConnPool & dbpool);
	void 	handle_host_cpu_mem_change(const std::shared_ptr<PARTHA_INFO> & partha_shr, const comm::HOST_CPU_MEM_CHANGE * phost, PGConnPool & dbpool);
	void 	handle_listen_taskmap(const std::shared_ptr<PARTHA_INFO> & partha_shr, comm::LISTEN_TASKMAP_NOTIFY * prel, int nitems, uint8_t *pendptr, \
				POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);
	bool 	handle_listener_req(const std::shared_ptr<MCONNTRACK> & connshr, const std::shared_ptr<PARTHA_INFO> & partha_shr, comm::QUERY_CMD *pquery, \
				comm::LISTENER_INFO_REQ * plist, uint8_t *pendptr, POOL_ALLOC_ARRAY *pthrpoolarr, STATS_STR_MAP & statsmap, PGConnPool & dbpool) noexcept;
	bool 	partha_listener_info(const std::shared_ptr<PARTHA_INFO> & partha_shr, comm::NEW_LISTENER *pone, int nlisteners, uint8_t *pendptr, \
				comm::LISTENER_DAY_STATS *prespone, uint32_t nrespelem, uint32_t & nresplisten, uint32_t & szresp, \
				POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool) noexcept;
	bool 	partha_listener_state(const std::shared_ptr<PARTHA_INFO> & partha_shr, const comm::LISTENER_STATE_NOTIFY * pone, int nconns, uint8_t *pendptr, \
				POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool, bool isdummycall = false);
	
	bool 	handle_mm_listener_ping(const std::shared_ptr<MCONNTRACK> &connshr, const comm::MM_LISTENER_PING *pone, int nevents);
	bool 	handle_mm_listener_delete(const std::shared_ptr<MADHAVA_INFO> &madshr, const comm::MM_LISTENER_DELETE *pone, int nevents, bool isdummycall = false);

	size_t 	handle_dependency_issue(MTCP_LISTENER *plistener, const comm::MM_LISTENER_ISSUE_RESOL & resol, uint8_t src_upstream_tier, \
				MM_LISTENER_ISSUE_MAP & mmissue_map, RESOL_MM_MAP_ARENA & resol_arena, DOWNSTREAM_VEC_ARENA & downvec_arena);
	bool 	partha_listener_dependency(const std::shared_ptr<PARTHA_INFO> & partha_shr, const comm::LISTENER_DEPENDENCY_NOTIFY * ponelisten, int nelems, \
				uint8_t *pendptr, STATS_STR_MAP & statsmap, POOL_ALLOC_ARRAY *pthrpoolarr);
	bool 	handle_mm_listener_issue(const std::shared_ptr<MADHAVA_INFO> & connshr, const comm::MM_LISTENER_ISSUE_RESOL * pone, int nevents, \
				uint8_t *pendptr, POOL_ALLOC_ARRAY *pthrpoolarr);
	size_t 	send_mm_listener_issue(MM_LISTENER_ISSUE_MAP & mmissue_map, bool is_remote, POOL_ALLOC_ARRAY *pthrpoolarr);
	bool 	handle_mm_listener_depends(const std::shared_ptr<MADHAVA_INFO> & madshr, const comm::MM_LISTENER_DEPENDS * pone, int nevents, POOL_ALLOC_ARRAY *pthrpoolarr);
	bool 	handle_listener_domain_notify(const std::shared_ptr<PARTHA_INFO> & partha_shr, const comm::LISTENER_DOMAIN_NOTIFY * porigone, int nevents);

	bool 	handle_listener_cluster_info(const std::shared_ptr<PARTHA_INFO> & partha_shr, const comm::LISTENER_CLUSTER_NOTIFY * porigone, int nevents, \
				uint8_t *pendptr, POOL_ALLOC_ARRAY *pthrpoolarr);
	void 	handle_shyama_svc_mesh(const comm::SM_SVC_CLUSTER_MESH * porigone, int nevents, uint8_t *pendptr, POOL_ALLOC_ARRAY *pthrpoolarr);
	void 	handle_shyama_svc_natip_clust(const comm::SM_SVC_NAT_IP_CLUSTER * porigone, int nevents, uint8_t *pendptr, POOL_ALLOC_ARRAY *pthrpoolarr);

	bool 	handle_listener_day_stats(const std::shared_ptr<PARTHA_INFO> & partha_shr, const comm::LISTENER_DAY_STATS * porigone, int nevents);

	void 	handle_notification_msg(const std::shared_ptr<PARTHA_INFO> & partha_shr, const comm::NOTIFICATION_MSG * pmsg, int nevents, const uint8_t *pendptr, PGConnPool & dbpool);
	bool 	handle_listener_natip_notify(const std::shared_ptr<PARTHA_INFO> & partha_shr, const comm::LISTENER_NAT_IP_EVENT * porigone, int nevents, POOL_ALLOC_ARRAY *pthrpoolarr);
	
	bool 	handle_partha_active_conns(const std::shared_ptr<PARTHA_INFO> & partha_shr, const comm::ACTIVE_CONN_STATS * pconn, int nitems, uint8_t *pendptr, \
			POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool); 
	std::pair<int, int> insert_active_conns(PARTHA_INFO *prawpartha, time_t tcur, const comm::ACTIVE_CONN_STATS * pconn, int nconn, uint8_t *pendptr, PGConnPool & dbpool); 
	std::pair<int, int> insert_close_conn_records(PARTHA_INFO *prawpartha, time_t currtsec, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);

	bool	handle_node_query(const std::shared_ptr<MCONNTRACK> & connshr, const comm::QUERY_CMD *pquery, char *pjson, char *pendptr, \
			POOL_ALLOC_ARRAY *pthrpoolarr, STATS_STR_MAP & statsmap, PGConnPool & dbpool);

	bool 	web_db_set_partha_hostinfo(SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, QUERY_OPTIONS & qryopt) const;

	bool 	web_query_route_qtype(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, \
			const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, STATS_STR_MAP & statsmap, PGConnPool & dbpool);
	bool 	web_multi_query(const std::shared_ptr<MCONNTRACK> & connshr, const GEN_JSON_VALUE & jdoc, const comm::QUERY_CMD *pquery, \
			POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool, STATS_STR_MAP & statsmap);

	static 	void noextracolcb(SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer) noexcept;

	bool 	web_curr_partha_hoststate(SOCK_JSON_WRITER<MCONN_HANDLER::MSTREAM_JSON_EPOLL> & writer, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool) const;
	bool 	web_db_detail_hoststate(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
			SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);
	bool 	web_db_aggr_hoststate(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
			SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);
	bool 	web_query_hoststate(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, \
			const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);

	bool 	web_curr_cpu_mem(SOCK_JSON_WRITER<MCONN_HANDLER::MSTREAM_JSON_EPOLL> & writer, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool) const;
	bool 	web_db_detail_cpu_mem(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, \
			const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);
	bool 	web_db_aggr_cpu_mem(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, \
			const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);
	bool 	web_query_cpu_mem(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, \
			const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);

	bool 	web_curr_listener_summ(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, \
			const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr);
	bool 	web_db_detail_listener_summ(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, \
			const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);
	bool 	web_db_aggr_listener_summ(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, \
			const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);
	bool 	web_query_listener_summ(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, \
			const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);
	
	CRIT_RET_E 	top_listeners_filter_match(const CRITERIA_SET & criteria, const PARTHA_INFO & rawpartha, bool ignore_other_subsys) const;
	bool 	web_curr_top_listeners(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, \
			const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr);
	bool 	web_db_top_listeners(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, \
			const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);
	bool 	web_query_top_listeners(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, \
			const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);

	bool 	web_db_detail_active_conn(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, \
			const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool, bool is_extended);
	bool 	web_db_aggr_active_conn(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, \
			const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool, bool is_extended);
	bool 	web_query_active_conn(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, \
			const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool, bool is_extended);

	bool 	web_db_detail_client_conn(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, \
			const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool, bool is_extended);
	bool 	web_db_aggr_client_conn(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, \
			const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool, bool is_extended);
	bool 	web_query_client_conn(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, \
			const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool, bool is_extended);

	bool 	web_db_listenproc_map(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, \
			const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);
	bool 	web_query_listenproc_map(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, \
			const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);

	bool 	web_curr_listener_info(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, \
			const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr);
	bool 	web_db_listener_info(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, \
			const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);
	bool 	web_db_aggr_listener_info(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
			SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);
	bool 	web_query_listener_info(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, \
			const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);

	bool 	web_curr_listener_state(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, \
			const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, bool is_extended);
	bool 	web_db_detail_listener_state(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, \
			const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool, bool is_extended);
	bool 	web_db_aggr_listener_state(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, \
			const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool, bool is_extended);
	bool 	web_query_listener_state(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, \
			const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool, bool is_extended);

	CRIT_RET_E 	top_aggr_procs_filter_match(const CRITERIA_SET & criteria, const PARTHA_INFO & rawpartha, bool ignore_other_subsys) const;
	bool 	web_curr_top_aggr_procs(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
			SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr);
	bool 	web_db_top_aggr_procs(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
			SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);
	bool 	web_query_top_aggr_procs(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
			SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);

	bool 	web_curr_top_host_procs(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
			SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr);
	bool 	web_db_top_host_procs(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
			SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);
	bool 	web_query_top_host_procs(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
			SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);

	bool 	web_curr_proc_state(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
			SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, bool is_extended);
	bool 	web_db_detail_proc_state(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
			SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool, bool is_extended);
	bool 	web_db_aggr_proc_state(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
			SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool, bool is_extended);
	bool 	web_query_proc_state(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
			SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool, bool is_extended);

	bool 	web_curr_proc_info(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
			SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr);
	bool 	web_db_proc_info(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
			SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);
	bool 	web_db_aggr_proc_info(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
			SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);
	bool 	web_query_proc_info(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
			SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);

	CRIT_RET_E 	notify_msg_filter_match(const CRITERIA_SET & criteria, const NOTIFY_MSG_ONE & msg, bool ignore_other_subsys) const;
	bool 	web_curr_notify_msg(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
			SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr);
	bool 	web_db_notify_msg(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
			SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);
	bool 	web_query_notify_msg(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
			SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);

	bool 	web_db_host_info(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
			SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);
	bool 	web_db_aggr_host_info(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
			SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);
	bool 	web_query_host_info(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
			SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);

	bool 	web_query_madhavastatus(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
			SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);

	CRIT_RET_E 	parthalist_filter_match(const CRITERIA_SET & criteria, const PARTHA_INFO * prawpartha, bool ignore_other_subsys) const;
	bool 	web_query_parthalist(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, \
			SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool);

	size_t 	hoststate_rtalert_rwlocked(PARTHA_INFO & partha, const comm::HOST_STATE_NOTIFY & hstate, time_t tcurr, const char *timebuf) noexcept;

	size_t 	cpumem_rtalert_rwlocked(PARTHA_INFO & partha, const CPU_MEM_STATE & cpu_mem_state, time_t tcurr, const char *timebuf) noexcept;
	
	size_t 	svcsumm_rtalert_rwlocked(PARTHA_INFO & partha, const LISTEN_SUMM_STATS<int> & stats, time_t tcurr, const char *timebuf) noexcept;
	
	size_t 	svcstate_rtalert_rwlocked(PARTHA_INFO & partha, const MTCP_LISTENER & listener, time_t tcurr, const char *timebuf) noexcept;
	size_t 	svcinfo_rtalert_rwlocked(PARTHA_INFO & partha, const MTCP_LISTENER & listener, time_t tcurr, const char *timebuf) noexcept;
	
	size_t 	procstate_rtalert_rwlocked(PARTHA_INFO & partha, const MAGGR_TASK & task, time_t tcurr, const char *timebuf) noexcept;
	size_t 	procinfo_rtalert_rwlocked(PARTHA_INFO & partha, const MAGGR_TASK & task, time_t tcurr, const char *timebuf) noexcept;
	
	size_t 	activeconn_rtalert_rwlocked(PARTHA_INFO & partha, const comm::ACTIVE_CONN_STATS & aconn, time_t tcurr, const char *timebuf, const MTCP_LISTENER *plistener = nullptr) noexcept;
	size_t 	clientconn_rtalert_rwlocked(PARTHA_INFO & partha, const comm::ACTIVE_CONN_STATS & aconn, time_t tcurr, const char *timebuf, const MAGGR_TASK * ptask = nullptr) noexcept;

	size_t 	topcpurss_rtalert_rwlocked(PARTHA_INFO & partha, const comm::TASK_TOP_PROCS::TOP_TASK & task, int rank, SUBSYS_CLASS_E csubsys, time_t tcurr, const char *timebuf) noexcept;
	size_t 	toppgcpu_rtalert_rwlocked(PARTHA_INFO & partha, const comm::TASK_TOP_PROCS::TOP_PG_TASK & task, int rank, time_t tcurr, const char *timebuf) noexcept;
	size_t 	topfork_rtalert_rwlocked(PARTHA_INFO & partha, const comm::TASK_TOP_PROCS::TOP_FORK_TASK & task, int rank, time_t tcurr, const char *timebuf) noexcept;

	bool 	send_db_array(DB_WRITE_ARR && dbarr, uint32_t caller_thr_num, STATS_STR_MAP & statsmap, bool is_json_resp = false);
	void 	send_json_block_error(const DB_WRITE_ARR & dbarr) noexcept;

	std::shared_ptr<MCONNTRACK> get_any_node_conn() noexcept;

	void 	cleanup_partha_unused_listeners(const std::shared_ptr<PARTHA_INFO> & parshr, POOL_ALLOC_ARRAY & thrpool, PGConnPool & dbpool);
	void 	cleanup_mm_unused_listeners(const std::shared_ptr<MADHAVA_INFO> & madshr);
	void 	cleanup_partha_unused_aggr_tasks(const std::shared_ptr<PARTHA_INFO> & parshr, POOL_ALLOC_ARRAY & thrpool, PGConnPool & dbpool);
	void 	cleanup_mm_unused_aggr_tasks(const std::shared_ptr<MADHAVA_INFO> & madshr);
	void 	cleanup_rem_madhava_unused_structs() noexcept;
	void 	cleanup_partha_unused_structs() noexcept;
	bool 	send_partha_reset_stats(PARTHA_INFO *prawpartha);

	bool 	db_add_init_partitions() noexcept;
	bool 	db_add_partitions() noexcept;
	bool 	db_set_part_logged() noexcept;
	bool 	db_cleanup_old_partitions(PGConnPool & dbpool, bool is_non_block) noexcept;
	bool	db_add_partha(PARTHA_INFO *pinfo, PGConnPool & dbpool);
	bool 	db_del_entries(bool is_check = false) noexcept;
	bool 	db_trunc_init_entries(const char * tblarrstr, const char *ns_regex) noexcept;
	bool 	set_db_disk_space_used() noexcept;
	void 	set_max_partha_allowed() noexcept;

	void 	upgrade_db_schemas(int olddbver, int oldprocver, PGConnUniq & pconn);
	const char * get_glob_part_tables() const noexcept;
	const char * get_globtables() const noexcept;
	const char * get_add_partha() const noexcept;
	const char * get_views_cleanup_procs() const noexcept;

};

} // namespace madhava
} // namespace gyeeta

// template specialization for better performance
namespace rapidjson {

template<>
inline void PutN(gyeeta::madhava::MCONN_HANDLER::MSTREAM_JSON_EPOLL & stream, char c, size_t n) 
{
	stream.PutN(c, n);
}

} // namespace rapidjson

