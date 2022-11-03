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
#include		"gy_server_int.h"
#include		"gy_scheduler.h"
#include		"gy_host_conn_flist.h"

#include		"folly/MPMCQueue.h"
#include 		"folly/Function.h"
#include		"folly/concurrency/AtomicSharedPtr.h" 

#include 		<forward_list>
#include 		<variant>
#include 		<unordered_map>

namespace gyeeta {
namespace partha {

using STATS_STR_MAP	= std::unordered_map<const char *, int64_t>;

class PARTHA_C;

class PACONN_HANDLER : public SERVER_COMM
{
public :
	static constexpr size_t			MAX_MPMC_ELEMS			= 16 * 1024;
	
	// Partial Message Reads / Writes will wait for min this timeout interval and subsequently the conn will close
	static constexpr uint64_t 		MAX_CONN_DATA_TIMEOUT_USEC 	{60 * GY_USEC_PER_SEC}; 	// 60 sec

	// Max Idle time to close persistent connections with no traffic to avoid build up of reqs/callbacks...
	static constexpr uint64_t 		MAX_CONN_IDLE_TIMEOUT_USEC 	{15 * GY_USEC_PER_MINUTE}; 	// 15 min

	static constexpr size_t			MAX_PERSISTENT_CONNS_PER_HOST	{8};

	class 	PACONNTRACK;
	struct 	SERVER_SIGNAL;

	class PACONNTRACK : public SERVER_CONNTRACK, public std::enable_shared_from_this <PACONNTRACK>
	{
	public :	
		SERVER_SIGNAL			*pl1_			{nullptr};

		comm::HOST_TYPES_E		host_type_		{comm::HOST_INVALID};
		comm::COMM_HEADER::HDR_MAGIC_E	comm_magic_		{comm::COMM_HEADER::INV_HDR_MAGIC};
		comm::CLI_TYPE_E		cli_type_		{comm::CLI_TYPE_REQ_RESP};

		bool				is_registered_		{false};
		bool				is_adhoc_		{false};

		using SERVER_CONNTRACK::SERVER_CONNTRACK;

		~PACONNTRACK() noexcept
		{
			if (host_type_ == comm::HOST_MADHAVA) {
				PACONN_HANDLER::get_singleton()->gmadhava_.handle_disconnect(this, host_type_, cli_type_);
			}	
		}	

		char * print_conn(STR_WR_BUF & strbuf) const noexcept
		{
			strbuf.appendfmt("Connection to Remote %s Conn Type %s ", comm::host_type_string(host_type_), comm::cli_type_string(cli_type_));

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

	using MAP_CONNTRACK 			= std::unordered_map<int, std::shared_ptr<PACONNTRACK>>;

	enum PANOTIFY_TYPE_E : uint32_t
	{
		NOTIFY_IGNORE		= 0,
		NOTIFY_SEND_DATA,
		NOTIFY_L1_MISC_CMD,
	};

	struct SOCK_SEND_DATA
	{
		std::weak_ptr <PACONNTRACK>	weakconn_;
		PACONNTRACK			*pconn_			{nullptr};
		SERVER_SIGNAL			*pl1_			{nullptr};
		std::optional <ASYNC_SOCK_CB>	async_cb_;
		comm::COMM_TYPE_E		comm_type_		{comm::COMM_MIN_TYPE};
		comm::COMM_HEADER::HDR_MAGIC_E 	comm_magic_		{comm::COMM_HEADER::INV_HDR_MAGIC};
		bool				close_conn_on_send_	{false};	

		SOCK_SEND_DATA() noexcept					= default;

		SOCK_SEND_DATA(SERVER_SIGNAL *pl1, std::weak_ptr<PACONNTRACK> weakconn, PACONNTRACK *pconn, comm::COMM_HEADER::HDR_MAGIC_E comm_magic, comm::COMM_TYPE_E comm_type, bool close_conn_on_send) noexcept
			: weakconn_(std::move(weakconn)), pconn_(pconn), pl1_(pl1), comm_type_(comm_type), comm_magic_(comm_magic), close_conn_on_send_(close_conn_on_send)
		{}
	
		SOCK_SEND_DATA(ASYNC_SOCK_CB && async_cb, SERVER_SIGNAL *pl1, std::weak_ptr<PACONNTRACK> weakconn, PACONNTRACK *pconn, comm::COMM_HEADER::HDR_MAGIC_E comm_magic) noexcept
			: weakconn_(std::move(weakconn)), pconn_(pconn), pl1_(pl1), async_cb_(std::move(async_cb)), comm_type_(comm::COMM_QUERY_CMD), comm_magic_(comm_magic)
		{}

		SOCK_SEND_DATA(const SOCK_SEND_DATA &) 				= delete;
		SOCK_SEND_DATA & operator= (const SOCK_SEND_DATA &)		= delete;

		SOCK_SEND_DATA(SOCK_SEND_DATA && other) noexcept		= default;
		SOCK_SEND_DATA & operator= (SOCK_SEND_DATA && other) noexcept	= default;

		~SOCK_SEND_DATA() noexcept
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
		L1_MISC_MADHAVA_NEW_CONN,
	};

	struct L1_MISC_NOTIFY
	{
		SERVER_SIGNAL				*pl1_			{nullptr};
		std::weak_ptr <PACONNTRACK>		weakconn_;
		PACONNTRACK				*pconn_			{nullptr};
		comm::CLI_TYPE_E			cli_type_		{comm::CLI_TYPE_REQ_RESP};
		L1_MISC_TYPE				misc_type_		{L1_MISC_CLOSE_CONN};
		union {
			struct {
				char			errstr_[128]		{};
				uint32_t		errlen_			{0};
			};

			struct {
				sockaddr_storage	saddr_;
				int			newsockfd_;
			};
		};	

		L1_MISC_NOTIFY() noexcept					= default;

		L1_MISC_NOTIFY(SERVER_SIGNAL *pl1, std::weak_ptr<PACONNTRACK> weakconn, PACONNTRACK *pconn, const char *errstr = nullptr, uint32_t errlen = 0) noexcept
			: pl1_(pl1), weakconn_(std::move(weakconn)), pconn_(pconn), misc_type_(L1_MISC_CLOSE_CONN)
		{
			if (errstr) {
				errlen_ = std::min<uint32_t>(errlen, sizeof(errstr_) - 1);
				std::memcpy(errstr_, errstr, errlen_);
			}
		}
	
		L1_MISC_NOTIFY(SERVER_SIGNAL *pl1, comm::CLI_TYPE_E cli_type, struct sockaddr_storage & saddr, int newsockfd) noexcept
			: pl1_(pl1), cli_type_(cli_type), misc_type_(L1_MISC_MADHAVA_NEW_CONN), saddr_(saddr), newsockfd_(newsockfd)
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
	 
	class EV_NOTIFY_ONE final
	{
	public :	
		union EV_DATA_ONE 
		{
			SOCK_SEND_DATA			sock_data_;
			L1_MISC_NOTIFY			l1_misc_;

			void				*pdummy_;

			EV_DATA_ONE() : pdummy_(nullptr)
			{}

			~EV_DATA_ONE()
			{}
		};
		
		EV_DATA_ONE				data_;
		PANOTIFY_TYPE_E				ntype_			{NOTIFY_IGNORE};	

		EV_NOTIFY_ONE() 			= default;

		EV_NOTIFY_ONE(SOCK_SEND_DATA && sockdata) noexcept
			: ntype_(NOTIFY_SEND_DATA)
		{
			new (&data_.sock_data_) SOCK_SEND_DATA(std::move(sockdata));
		}	
		
		EV_NOTIFY_ONE(L1_MISC_NOTIFY && l1_misc) noexcept
			: ntype_(NOTIFY_L1_MISC_CMD)
		{
			new (&data_.l1_misc_) L1_MISC_NOTIFY(std::move(l1_misc));
		}	

		EV_NOTIFY_ONE(const EV_NOTIFY_ONE &)	= delete;	

		EV_NOTIFY_ONE(EV_NOTIFY_ONE && other) noexcept
			: ntype_(other.ntype_)
		{
			switch (ntype_) {
			
			case NOTIFY_SEND_DATA :
				new (&data_.sock_data_) SOCK_SEND_DATA(std::move(other.data_.sock_data_));
				break;

			case NOTIFY_L1_MISC_CMD :
				new (&data_.l1_misc_) L1_MISC_NOTIFY(std::move(other.data_.l1_misc_));
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
			
			case NOTIFY_SEND_DATA :
				data_.sock_data_.~SOCK_SEND_DATA();
				break;

			case NOTIFY_L1_MISC_CMD :
				data_.l1_misc_.~L1_MISC_NOTIFY();
				break;

			default :
				break;
			}	

			ntype_	= NOTIFY_IGNORE;
		}	

		PANOTIFY_TYPE_E get_type() const noexcept
		{
			return ntype_;
		}	
	};	

	using MPMCQ_COMM			= folly::MPMCQueue<EV_NOTIFY_ONE>;

	using HOST_CONN_LIST			= HOST_CONN_FLIST <PACONNTRACK, SERVER_SIGNAL, MAX_PERSISTENT_CONNS_PER_HOST>;

	class MADHAVA_INFO : public HOST_CONN_LIST
	{	
	public :	
		uint64_t			madhava_id_					{0};
		char				madhava_hostname_[MAX_DOMAINNAME_SIZE]		{};
		uint16_t			madhava_port_					{0};
		uint64_t			partha_ident_key_				{0};	
		time_t				madhava_expiry_sec_				{0};					
		char				region_name_[comm::MAX_ZONE_LEN]		{};
		char				zone_name_[comm::MAX_ZONE_LEN]			{};
		char				madhava_name_[comm::MAX_CLUSTER_NAME_LEN]	{};

		comm::MADHAVA_PARTHA_STATUS	last_status_					{};

		int64_t				last_success_tsec_				{0};
		time_t				last_reg_tsec_					{0};
		int64_t				last_disconn_tsec_				{0};
		uint32_t			comm_version_					{1};
		uint32_t			madhava_version_				{0};
		
		uint64_t			last_madhava_id_				{0};
		char				last_madhava_hostname_[MAX_DOMAINNAME_SIZE]	{};
		uint16_t			last_madhava_port_				{0};

		char				last_error_buf_[256]				{};

		uint64_t			init_tusec_					{get_usec_time()};

		static constexpr const char *	madhava_schedule_name_ 				{"Madhava Registration Schedule"};

		char * print_string(STR_WR_BUF & strbuf) const noexcept
		{
			return strbuf.appendfmt("Madhava \'%s\' Host %s port %hu Madhava ID 0x%016lx ", madhava_name_, madhava_hostname_, madhava_port_, madhava_id_);
		}

		void handle_disconnect(PACONNTRACK *pconn, comm::HOST_TYPES_E host_type, comm::CLI_TYPE_E cli_type) noexcept
		{
			HOST_CONN_LIST::del_conn(pconn, host_type);

			last_disconn_tsec_ = time(nullptr);

			PACONN_HANDLER::schedule_madhava_register();
		}	

		std::shared_ptr<PACONNTRACK> get_last_conn(comm::CLI_TYPE_E ctype) noexcept
		{
			auto			shrp = HOST_CONN_LIST::get_last_conn(ctype);
			
			if (!shrp) {
				/*
				 * Check if Madhava connection was attempted in the last 35 secs. If not, start the 
				 * Madhava connect schedule
				 */
				if (time(nullptr) - last_reg_tsec_ > 35) {
					PACONN_HANDLER::schedule_madhava_register();
				}	
			}	

			return shrp;
		}	

	};	

	class SHYAMA_INFO
	{
	public :	
		int64_t				last_success_tsec_			{0};
		time_t				last_reg_tsec_				{0};
		uint32_t			comm_version_				{0};

		uint32_t			shyama_version_				{0};
		const std::vector<std::string>	& shyama_host_vec_;
		const std::vector<uint16_t>	& shyama_port_vec_;
		char				curr_shyama_host_[MAX_DOMAINNAME_SIZE]	{};
		uint16_t			curr_shyama_port_			{0};
		uint16_t			curr_shyama_index_			{0};
		uint8_t				nfails_					{0};
		uint64_t			first_fail_csec_			{0};
		
		char				last_error_buf_[256]			{};
		
		static constexpr const char *	shyama_schedule_name_ = "Shyama Registration Schedule";

		SHYAMA_INFO(const std::vector<std::string> & shyama_host_vec, const std::vector<uint16_t> & shyama_port_vec) noexcept
			: shyama_host_vec_(shyama_host_vec), shyama_port_vec_(shyama_port_vec)
		{
			GY_STRNCPY(curr_shyama_host_, shyama_host_vec_[0].data(), sizeof(curr_shyama_host_));
			curr_shyama_port_	= shyama_port_vec_[0];
		}	
	};	


	struct SERVER_SIGNAL
	{
		MPMCQ_COMM			signalq_;
		GY_THREAD			*pthread_	{nullptr};		
		int				epollfd_	{-1};
		int				signalfd_	{-1};
		int				timerfd_	{-1};
		char				descbuf_[64]	{};

		SERVER_SIGNAL(size_t maxcomm) : signalq_(maxcomm)
		{}
	};	
	
	PARTHA_C			* const ppartha_;		
	SHYAMA_INFO				gshyama_;
	MADHAVA_INFO				gmadhava_;
	char					last_error_buf_[256]				{};
	char					cluster_name_[comm::MAX_CLUSTER_NAME_LEN]	{};
	char					region_name_[comm::MAX_ZONE_LEN]		{};
	char					zone_name_[comm::MAX_ZONE_LEN]			{};
	char					instance_id_[comm::MAX_INSTANCE_ID_LEN]		{};
	char					cloud_type_[64]					{};
	
	SERVER_SIGNAL				evt_hdlr_		{MAX_MPMC_ELEMS};
	SERVER_SIGNAL				req_rsp_hdlr_		{MAX_MPMC_ELEMS};

	GY_SCHEDULER				scheduler_		{false};

	std::atomic<int64_t>			gtconncount		{0};

	PACONN_HANDLER(PARTHA_C *ppartha);
	~PACONN_HANDLER() 						= delete;

	PACONN_HANDLER(const PACONN_HANDLER &)				= delete;
	PACONN_HANDLER(PACONN_HANDLER &&)				= delete;
	PACONN_HANDLER & operator=(const PACONN_HANDLER &)		= delete;
	PACONN_HANDLER & operator=(PACONN_HANDLER &&)			= delete;
	
	static PACONN_HANDLER * get_singleton() noexcept;

	static int schedule_shyama_register() noexcept;

	static int schedule_madhava_register(uint64_t startaftermsec = 0) noexcept;

	static void stop_shyama_scheduler() noexcept
	{
		if (!PACONN_HANDLER::get_singleton()) {
			return;
		}

		PACONN_HANDLER::get_singleton()->scheduler_.cancel_schedule(SHYAMA_INFO::shyama_schedule_name_);
	}	

	static void stop_madhava_scheduler() noexcept
	{
		if (!PACONN_HANDLER::get_singleton()) {
			return;
		}

		PACONN_HANDLER::get_singleton()->scheduler_.cancel_schedule(MADHAVA_INFO::madhava_schedule_name_);
	}	

	int handle_l1(GY_THREAD *pthr, bool is_req_rsp);

	int blocking_shyama_register() noexcept;

	int blocking_madhava_register() noexcept;

	int connect_madhava(comm::CLI_TYPE_E cli_type, struct sockaddr_storage & sockaddr, socklen_t & socklen);

	void close_all_conns(MADHAVA_INFO & madhava) noexcept;

	ssize_t l1_handle_send(PACONNTRACK *pconn1, bool throw_on_error = true);

	bool notify_close_conn(const SERVER_SIGNAL *pl1, std::weak_ptr <PACONNTRACK> weakconn, PACONNTRACK *pconn) noexcept;

	bool notify_new_conn(SERVER_SIGNAL *pl1, comm::CLI_TYPE_E cli_type, struct sockaddr_storage & saddr, int newsockfd) noexcept;

	void send_madhava_status() noexcept;

	uint64_t get_madhava_id() const noexcept
	{
		return gmadhava_.madhava_id_;
	}

	bool is_server_connected() const noexcept
	{
		return gmadhava_.is_conn_available();
	}

	std::shared_ptr<SERVER_CONNTRACK> get_server_conn(comm::CLI_TYPE_E cli_type) noexcept
	{
		return std::static_pointer_cast<SERVER_CONNTRACK>(gmadhava_.get_last_conn(cli_type));
	}

	bool send_server_data(EPOLL_IOVEC_ARR && iovarr, comm::CLI_TYPE_E cli_type, comm::COMM_TYPE_E comm_type, const std::shared_ptr<SERVER_CONNTRACK> & shrconn) noexcept
	{
		bool			bret;
		auto			pbase = shrconn.get();
		auto			pconn1 = static_cast<PACONNTRACK *>(pbase);

		if (!pconn1) {
			return false;
		}

		bret = pconn1->schedule_ext_send(std::move(iovarr), false /* throw_on_error */);
		if (bret == false) {
			return false;
		}	

		SOCK_SEND_DATA			l1data(pconn1->pl1_, pconn1->weak_from_this(), pconn1, pconn1->get_comm_magic(), comm_type, false /* close_conn_on_send */);

		bret = pconn1->pl1_->signalq_.write(std::move(l1data));
		if (bret == true) {
			int64_t		n = 1;

			(void)::write(pconn1->pl1_->signalfd_, &n, sizeof(int64_t));

			return true;
		}
		
		return false;
	}	

	bool send_server_data(ASYNC_SOCK_CB && async_cb, EPOLL_IOVEC_ARR && iovarr, const std::shared_ptr<SERVER_CONNTRACK> & shrconn) noexcept
	{
		bool			bret;
		auto			pbase = shrconn.get();
		auto			pconn1 = static_cast<PACONNTRACK *>(pbase);

		if (!pconn1) {
			if (async_cb.is_valid()) {
				try {
					async_cb.fcb_(pconn1, nullptr, 0, nullptr, false /* is_expiry */, true /* is_error */);
				}
				catch(...) {
				}	
			}	

			return false;
		}

		bret = pconn1->schedule_ext_send(std::move(iovarr), false /* throw_on_error */);
		if (bret == false) {

			if (async_cb.is_valid()) {
				try {
					async_cb.fcb_(pconn1, nullptr, 0, nullptr, false /* is_expiry */, true /* is_error */);
				}
				catch(...) {
				}	
			}	

			return false;
		}	

		SOCK_SEND_DATA		l1data(std::move(async_cb), pconn1->pl1_, pconn1->weak_from_this(), pconn1, pconn1->get_comm_magic());

		bret = pconn1->pl1_->signalq_.write(std::move(l1data));
		if (bret == true) {
			int64_t		n = 1;

			(void)::write(pconn1->pl1_->signalfd_, &n, sizeof(int64_t));

			return true;
		}
		
		return false;
	}	

};	

} // namespace partha
} // namespace gyeeta
