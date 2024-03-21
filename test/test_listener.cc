//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include		"gy_common_inc.h"
#include		"gy_listen_sock.h"
#include		"gy_print_offload.h"
#include		"gy_msg_comm.h"
#include		"gy_multi_proc_comm.h"
#include		"gy_pool_alloc.h"
#include		"gy_epoll_conntrack.h"

#include 		"folly/ThreadCachedInt.h"
#include 		"folly/Function.h"

#include 		<sys/epoll.h>
#include 		<sys/eventfd.h>
#include 		<sys/timerfd.h>

#include 		<algorithm>

using namespace 	gyeeta;

struct TL_C {};

using TCONN_COUNTER = folly::ThreadCachedInt<int64_t, TL_C>;

TCONN_COUNTER			gtreqcount(0, 32);

namespace testcomm {

enum TEST_DATA_TYPES_E : uint32_t
{
	TYPE_MIN_TYPE			= 0xECACF000,

	TYPE_REGISTER,
	TYPE_TASK,
	TYPE_TCP_CONN,
	TYPE_QUERY,
	TYPE_RESPONSE,

	TYPE_WEB_QUERY,

	TYPE_MAX_TYPE
};	

enum TEST_DATA_SUBTYPE_E : uint32_t
{
	SUBTYPE_MIN_TYPE		= 0x12345000,

	SUBTYPE_LISTENER_REQ,
	SUBTYPE_LISTENER_RESP,
	SUBTYPE_REQUEST_CURR_TIME,
	SUBTYPE_RESPONSE_CURR_TIME,
	SUBTYPE_REQUEST_READ_FILE,
	SUBTYPE_RESPONSE_READ_FILE,

	SUBTYPE_NULL_RESPONSE,

	SUBTYPE_MAX_TYPE
};	

enum TERR_CODES_E : int
{
	TERR_SUCCESS			= 0,
	
	TERR_INVALID_REQUEST		= 101,
	TERR_TIMED_OUT,
	TERR_DATA_NOT_FOUND,
	TERR_BLOCKING_ERROR,
	TERR_MAX_SZ_BREACHED,
	TERR_SYSERROR,
};

static constexpr const char * get_error_string(TERR_CODES_E code) noexcept
{
	switch (code) {
	
	case TERR_SUCCESS 		: return "No Error";

	case TERR_INVALID_REQUEST	: return "Invalid Request seen";
	case TERR_TIMED_OUT		: return "Request Timed Out waiting for response";
	case TERR_DATA_NOT_FOUND	: return "Requested Data not found";
	case TERR_BLOCKING_ERROR	: return "Too many Requests being handled currently. Please try after some time...";
	case TERR_MAX_SZ_BREACHED	: return "Maximum Bytes Allowed limit breached";
	case TERR_SYSERROR		: return "System call error";
	
	default 			: return "Unknown Error";
	}	
}


static constexpr int			HDR_MAGIC_STREAM 	= 0x03112203;
static constexpr int			HDR_MAGIC_CLI		= 0x434c4943;	// "CLIC"

// We allow a max Record size of 128 MB
static constexpr uint32_t		MAX_TEST_DATA_SZ 	= GY_UP_MB(128);

struct TEST_HEADER1
{
	uint32_t			magic_		{HDR_MAGIC_STREAM};
	uint32_t			data_sz_	{0};		// Inclusive of TEST_HEADER1 length and padding_sz_
	TEST_DATA_TYPES_E		data_type_	{TYPE_MIN_TYPE};
	uint32_t			padding_sz_	{0};
	
	TEST_HEADER1(TEST_DATA_TYPES_E data_type, uint32_t data_sz) noexcept 
	{
		bool			bret;

		bret = set_type_len(data_type, data_sz);
		if (gy_unlikely(bret == false)) {
			magic_		= 0;
		}	
	}

	bool set_type_len(TEST_DATA_TYPES_E data_type, uint32_t data_sz) noexcept
	{
		data_sz 		+= sizeof(TEST_HEADER1);

		uint32_t		new_data_sz = gy_align_up_2(data_sz, 8);

		if (new_data_sz < MAX_TEST_DATA_SZ && data_type > TYPE_MIN_TYPE && data_type < TYPE_MAX_TYPE) {
			magic_		= HDR_MAGIC_STREAM;
			data_sz_	= new_data_sz;
			data_type_	= data_type;
			padding_sz_	= new_data_sz - data_sz;

			return true;
		}	
		return false;
	}	
	
	uint32_t get_pad_len() const noexcept
	{
		return padding_sz_;
	}

	bool validate(const uint8_t *pdata) const noexcept;
};

struct TEST_REGISTER
{
	uint64_t			start_identifier_		{0};
	uint32_t			comm_version_			{0};
	uint32_t			version_			{0};
	char				machine_id_[256]		{};	
	char				domain_[256]			{};
	char				access_key_[256]		{};

	TEST_REGISTER(uint64_t start_identifier, uint32_t comm_version, uint32_t version, const char * machine_id, const char * domain, const char * access_key) noexcept
		: start_identifier_(start_identifier), comm_version_(comm_version), version_(version)
	{
		GY_STRNCPY(machine_id_, machine_id, sizeof(machine_id_));
		GY_STRNCPY(domain_, domain, sizeof(domain_));
		GY_STRNCPY(access_key_, access_key, sizeof(access_key_));
	}

	bool validate(const TEST_HEADER1 *phdr) const noexcept
	{
		if (phdr->data_sz_ - phdr->padding_sz_ != sizeof(TEST_HEADER1) + sizeof(TEST_REGISTER)) {
			return false;
		}

		GY_CC_BARRIER();

		if (*machine_id_ && *access_key_ && (256 > strnlen(machine_id_, 256)) && (256 > strnlen(access_key_, 256))) {
			return true;
		}

		return false;
	}	
};	

struct TEST_TASK
{
	pid_t				pid_;
	pid_t				ppid_;
	uint64_t			start_time_usec_;
	char				comm_[16];
	uint16_t			exepath_len_;
	uint16_t			ext_data_sz_;
	// First {char exepath_[exepath_len_]}
	// Then {char ext_data_[ext_data_sz_]};

	static bool validate(const TEST_HEADER1 *phdr, const TEST_TASK *ptask, uint8_t *pend) noexcept
	{
		int			extsz = phdr->data_sz_ - phdr->padding_sz_ - sizeof(TEST_TASK) - sizeof(TEST_HEADER1), next;

		if (extsz < 0) {
			return false;
		}

		GY_CC_BARRIER();

		pend -= phdr->padding_sz_;

		if ((unsigned)extsz != ptask->exepath_len_ + ptask->ext_data_sz_) {
			return false;
		}

		return true;
	}	

};	

struct TEST_TCP_CONN
{
	IP_PORT				cli_;
	IP_PORT				ser_;
	pid_t				cli_pid_		{0};
	uint64_t			start_time_usec_	{get_usec_time()};

	uint16_t			server_domain_len_	{0};
	// {char server_domain_[server_domain_len_] follows}

	static bool validate(const TEST_HEADER1 *phdr, const TEST_TCP_CONN *ptcp, uint8_t *pend) noexcept
	{
		int			extsz = phdr->data_sz_ - phdr->padding_sz_ - sizeof(TEST_TCP_CONN) - sizeof(TEST_HEADER1), next;

		if (extsz < 0) {
			return false;
		}

		GY_CC_BARRIER();

		pend -= phdr->padding_sz_;

		if ((unsigned)extsz != ptcp->server_domain_len_) {
			return false;
		}	

		return true;
	}	
};	

struct TEST_QUERY
{
	uint64_t			seqid_;
	TEST_DATA_SUBTYPE_E		subtype_;
	uint64_t			timeoutusec_;
};

struct TEST_RESPONSE
{
	uint64_t			seqid_;
	TEST_DATA_SUBTYPE_E		subtype_;
	TERR_CODES_E			respcode_;

	static bool validate(const TEST_HEADER1 *phdr) noexcept
	{
		if (phdr->data_sz_ - phdr->padding_sz_ >= sizeof(TEST_HEADER1) + sizeof(TEST_RESPONSE)) {
			return true;
		}	
		return false;
	}	
};	

struct TEST_WEB_QUERY
{
	uint64_t			seqid_;
	uint64_t			timeoutusec_;
	char				web_userid_[64];
};

struct TEST_LISTENER_REQ
{
	IP_PORT				ip_port_;
	size_t				ndays_history_;

	static bool validate(const TEST_HEADER1 *phdr) noexcept
	{
		if (phdr->data_sz_ - phdr->padding_sz_ == sizeof(TEST_HEADER1) + sizeof(TEST_QUERY) + sizeof(TEST_LISTENER_REQ)) {
			return true;
		}	
		return false;
	}	
};	

struct TEST_LISTENER_RESP
{
	uint64_t			listener_start_usec_	{get_usec_time()};
	size_t				misc_data_		{0};
	/*uint8_t			misc_data_arr_ follows*/

	TEST_LISTENER_RESP(size_t misc_data) noexcept :
		misc_data_(misc_data)
	{}

	static bool validate(const TEST_HEADER1 *phdr, const TEST_LISTENER_RESP *plist) noexcept
	{
		static constexpr size_t fixed_sz_	= sizeof(TEST_HEADER1) + sizeof(TEST_RESPONSE) + sizeof(TEST_LISTENER_RESP);

		if (phdr->data_sz_ < fixed_sz_) {
			return false;
		}	
		
		GY_CC_BARRIER();

		if (phdr->data_sz_ - phdr->padding_sz_ < fixed_sz_ + plist->misc_data_) {
			return false;
		}	

		if (plist->misc_data_ + fixed_sz_ + 7 > MAX_TEST_DATA_SZ) {
			return false;
		}	

		return true;
	}	
};	

struct TEST_REQUEST_CURR_TIME
{
	uint64_t			curr_usec_clock_;
	uint64_t			curr_usec_time_;

	static bool validate(const TEST_HEADER1 *phdr) noexcept
	{
		if (phdr->data_sz_ - phdr->padding_sz_ == sizeof(TEST_HEADER1) + sizeof(TEST_QUERY) + sizeof(TEST_REQUEST_CURR_TIME)) {
			return true;
		}	
		return false;
	}	
};	

struct TEST_RESPONSE_CURR_TIME
{
	uint64_t			curr_usec_clock_;
	uint64_t			curr_usec_time_;	
	int64_t				req_proc_time_;

	static bool validate(const TEST_HEADER1 *phdr) noexcept
	{
		if (phdr->data_sz_ - phdr->padding_sz_ == sizeof(TEST_HEADER1) + sizeof(TEST_RESPONSE) + sizeof(TEST_RESPONSE_CURR_TIME)) {
			return true;
		}	
		return false;
	}	
};

struct TEST_REQUEST_READ_FILE
{
	off_t				offset_				{0};
	uint32_t			nbytes_				{0};
	uint64_t			trequsec_			{get_usec_time()};
	char				pathname_[512]			{};

	bool validate(const TEST_HEADER1 *phdr) noexcept
	{
		if (!(phdr->data_sz_ - phdr->padding_sz_ == sizeof(TEST_HEADER1) + sizeof(TEST_QUERY) + sizeof(TEST_REQUEST_READ_FILE))) {
			return false;
		}	

		if (nbytes_ + sizeof(TEST_HEADER1) + sizeof(TEST_QUERY) + sizeof(TEST_REQUEST_READ_FILE) + 7 /* padding_sz_ */ > MAX_TEST_DATA_SZ) {
			return false;
		}

		return true;
	}	
};	

struct TEST_RESPONSE_READ_FILE
{
	int64_t				response_usec_			{0};
	int				respcode_			{0};
	uint32_t			nbytes_				{0};
	// char filebuf_[nbytes_] follows

	static bool validate(const TEST_HEADER1 *phdr, const TEST_RESPONSE_READ_FILE *pfiler) noexcept
	{
		static constexpr size_t fixed_sz_ = sizeof(TEST_HEADER1) + sizeof(TEST_RESPONSE) + sizeof(TEST_RESPONSE_READ_FILE);

		if (phdr->data_sz_ < fixed_sz_) {
			return false;
		}	

		GY_CC_BARRIER();

		if (phdr->data_sz_ - phdr->padding_sz_ != fixed_sz_ + pfiler->nbytes_) {
			return false;
		}	

		return true;
	}	
};	

bool TEST_HEADER1::validate(const uint8_t *pdata) const noexcept
{
	if (!((magic_ == HDR_MAGIC_STREAM || magic_ == HDR_MAGIC_CLI) && 
		data_sz_ < MAX_TEST_DATA_SZ && data_sz_ >= sizeof(TEST_HEADER1) && padding_sz_ < 8 &&
		data_type_ > TYPE_MIN_TYPE && data_type_ < TYPE_MAX_TYPE)) {

		return false;
	}	

	if (data_sz_ & (8 - 1)) {
		return false;
	}	

	// Check if pdata is 8 bytes aligned : We will terminate connections resulting in unaligned accesses
	if (0 != (((uint64_t)pdata) & (8 - 1))) {
		return false;
	}	

	const uint32_t		act_data_sz = data_sz_ - padding_sz_;

	switch (data_type_) {
	
	case TYPE_TASK :
		if (act_data_sz < sizeof(TEST_HEADER1) + sizeof(TEST_TASK)) {
			return false;
		}	
		return true;

	case TYPE_TCP_CONN :
		if (act_data_sz < sizeof(TEST_HEADER1) + sizeof(TEST_TCP_CONN)) {
			return false;
		}	
		return true;	

	case TYPE_QUERY :
		if (act_data_sz < sizeof(TEST_HEADER1) + sizeof(TEST_QUERY)) {
			return false;
		}	
		return true;	
	
	case TYPE_RESPONSE :
		if (act_data_sz < sizeof(TEST_HEADER1) + sizeof(TEST_RESPONSE)) {
			return false;
		}	
		return true;	

	case TYPE_REGISTER :
		if (act_data_sz < sizeof(TEST_HEADER1) + sizeof(TEST_REGISTER)) {
			return false;
		}	
		return true;	

	case TYPE_WEB_QUERY :
		if (act_data_sz < sizeof(TEST_HEADER1) + sizeof(TEST_WEB_QUERY)) {
			return false;
		}	
		return true;

	default :
		return false;
	}	
}

}; // namespace testcomm

using namespace 	testcomm;

class TLISTEN_HDLR
{
public :	
	static constexpr size_t			MAX_ACCEPT_THREADS		= 2;

	static constexpr size_t			MAX_L1_STREAMERS		= 8;
	static constexpr size_t			MAX_L1_CLI_SERV			= 4;

	static constexpr size_t			MAX_L2_DB_WRITERS		= 8;
	static constexpr size_t			MAX_L2_DB_READERS 		= 8; 
	static constexpr size_t			MAX_L2_IO_THREADS 		= 4; 
	static constexpr size_t			MAX_L2_ALERT_THREADS		= 4;

	static constexpr size_t			MAX_L1_THREADS			= MAX_L1_STREAMERS + MAX_L1_CLI_SERV;
	static constexpr size_t			MAX_L2_THREADS			= MAX_L2_DB_WRITERS + MAX_L2_DB_READERS + MAX_L2_IO_THREADS + MAX_L2_ALERT_THREADS;

	// Multiple L2 threads will handle each pool
	static constexpr size_t			MAX_L2_DB_WR_POOLS 		= 2;
	static constexpr size_t			MAX_L2_DB_RD_POOLS 		= 2;
	static constexpr size_t			MAX_L2_IO_POOLS 		= 2;
	static constexpr size_t			MAX_L2_ALERT_POOLS 		= 2;
	static constexpr size_t			MAX_MPMC_ELEMS			= 4096;

	static constexpr size_t			MAX_CONCURRENT_ACCEPT_CONNS	= 2048;

	// Incomplete Reads / Writes will wait for min this timeout interval and subsequently the conn will close
	static constexpr uint64_t 		MAX_CONN_DATA_TIMEOUT_USEC 	{60 * GY_USEC_PER_SEC}; 

	// Connection Idle Timeout for persistent connections
	static constexpr uint64_t 		MAX_CONN_IDLE_TIMEOUT_USEC 	{10 * 60 * GY_USEC_PER_SEC}; 

	class TCONNTRACK : public EPOLL_CONNTRACK, public std::enable_shared_from_this <TCONNTRACK>
	{
	public :	
		uint32_t			comm_version_			{0};
		uint32_t			version_			{0};
		char				machine_id_[64];	

		char				ui_login_name_[64];					
		uint64_t			ui_access_flags_		{0};

		bool				is_stream_			{false};
		bool				is_validated_			{false};
		bool				is_admin_user_			{false};

		using EPOLL_CONNTRACK::EPOLL_CONNTRACK;

		bool is_auth_done() const noexcept
		{
			return is_validated_;
		}	

		bool set_registration(testcomm::TEST_REGISTER *preg) noexcept
		{
			comm_version_	= preg->comm_version_;
			version_	= preg->version_;
			
			GY_STRNCPY(machine_id_, preg->machine_id_, sizeof(machine_id_));
			
			if (is_stream_ && *machine_id_) {
				is_validated_	= true;
				return true;
			}	
			return false;
		}	
	};	

	using MAP_CONNTRACK 			= std::unordered_map<int, std::shared_ptr<TCONNTRACK>>;
	using CONN_NODE_ELEM			= MAP_CONNTRACK::node_type; 

	enum TTYPE_E : uint8_t
	{
		TTYPE_ACCEPT		= 0,
		TTYPE_L1_STREAMER,
		TTYPE_L1_CLI_SERV,
		TTYPE_L2_DB_WR,
		TTYPE_L2_DB_RD,
		TTYPE_L2_IO_THR,
		TTYPE_L2_ALERT,
	};

	enum NOTIFY_TYPE_E : uint32_t
	{
		NOTIFY_IGNORE		= 0,
		NOTIFY_ACCEPT,
		NOTIFY_L1_STREAM_REQ,
		NOTIFY_L1_CLI_REQ,
		NOTIFY_DB_WRITE,
		NOTIFY_DB_READ,
		NOTIFY_ALERT_CHECK,
		NOTIFY_IO_REQ,
		NOTIFY_L2_DATA,
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

	/*
	 * Use for DB requests all allocated from one buffer only.
	 */
	struct DB_WRITE_ARR
	{
		struct DB_WRITE_ONE
		{
			uint8_t			*pwrbuf_;
			uint32_t		wrlen_;
			TEST_DATA_TYPES_E	data_type_;
		};	

		char				dbname_[64]		{};
		DB_WRITE_ONE			dbonearr_[8]		{};
		size_t				ndbs_			{0};	
		void				*pbufstart_		{nullptr};
		FREE_FPTR			free_fp_		{nullptr};		// Will be called for pbufstart_

		DB_WRITE_ARR() noexcept					= default;

		DB_WRITE_ARR(const DB_WRITE_ARR &) 			= delete;

		DB_WRITE_ARR & operator= (const DB_WRITE_ARR &)		= delete;

		DB_WRITE_ARR(DB_WRITE_ARR && other) noexcept
		{
			std::memcpy(this, &other, sizeof(*this));
			other.reset();
		}	

		DB_WRITE_ARR & operator= (DB_WRITE_ARR && other) noexcept	
		{
			if (this != &other) {
				dealloc();
				std::memcpy(this, &other, sizeof(*this));
				other.reset();
			}	

			return *this;
		}	

		~DB_WRITE_ARR() noexcept
		{
			dealloc();
		}

		void dealloc() noexcept
		{
			if (pbufstart_ && free_fp_) {
				(*free_fp_)(pbufstart_);
			}	
			reset();
		}

		void reset() noexcept
		{
			pbufstart_ 	= nullptr;
			ndbs_		= 0;
		}	
	};

	struct L1_PARAMS;

	struct DB_READ_CMD final
	{
		const L1_PARAMS			*pl1_src_		{nullptr};
		uint8_t				*pwrbuf_		{nullptr};
		FREE_FPTR			free_fp_		{nullptr};
		uint32_t			wrlen_			{0};
		std::weak_ptr <TCONNTRACK>	weakconn_;
		TCONNTRACK			*pconn_			{nullptr};
		char				dbname_[64]		{};
		uint64_t			start_clock_usec_	{get_usec_clock()};
		TEST_DATA_TYPES_E		data_type_		{TYPE_MIN_TYPE};

		DB_READ_CMD() noexcept					= default;

		DB_READ_CMD(L1_PARAMS *pl1_src, uint8_t *pwrbuf, FREE_FPTR free_fp, uint32_t wrlen, std::weak_ptr<TCONNTRACK> weakconn, TCONNTRACK *pconn, const char *dbname, TEST_DATA_TYPES_E data_type) noexcept
			: pl1_src_(pl1_src), pwrbuf_(pwrbuf), free_fp_(free_fp), wrlen_(wrlen), weakconn_(std::move(weakconn)), pconn_(pconn), data_type_(data_type)
		{
			GY_STRNCPY(dbname_, dbname, sizeof(dbname_));
		}	
	
		DB_READ_CMD(const DB_READ_CMD &) 			= delete;

		DB_READ_CMD & operator= (const DB_READ_CMD &)		= delete;

		DB_READ_CMD(DB_READ_CMD && other) noexcept
			: pl1_src_(other.pl1_src_), pwrbuf_(std::exchange(other.pwrbuf_, nullptr)), free_fp_(other.free_fp_),
			wrlen_(other.wrlen_), weakconn_(std::move(other.weakconn_)), pconn_(std::exchange(other.pconn_, nullptr)), start_clock_usec_(other.start_clock_usec_), 
			data_type_(other.data_type_)
		{
			std::memcpy(dbname_, other.dbname_, sizeof(dbname_));
		}	

		DB_READ_CMD & operator= (DB_READ_CMD && other) noexcept
		{
			if (this != &other) {
				dealloc();
				new (this) DB_READ_CMD(std::move(other));
			}

			return *this;
		}

		~DB_READ_CMD() noexcept
		{
			dealloc();
		}	

		void dealloc() noexcept
		{
			if (pwrbuf_) { 
				if (free_fp_) {
					(*free_fp_)(pwrbuf_);
				}

				pwrbuf_	= nullptr;
			}
		}	

		bool is_cli_active() const noexcept
		{
			return !weakconn_.expired();
		}	
	};	

	struct IO_CMD final
	{
		const L1_PARAMS			*pl1_src_		{nullptr};
		uint8_t				*pwrbuf_		{nullptr};
		FREE_FPTR			free_fp_		{nullptr};
		uint32_t			wrlen_			{0};
		std::weak_ptr <TCONNTRACK>	weakconn_;
		TCONNTRACK			*pconn_			{nullptr};
		uint64_t			start_clock_usec_	{get_usec_clock()};
		TEST_DATA_TYPES_E		data_type_		{TYPE_MIN_TYPE};

		IO_CMD() noexcept					= default;

		IO_CMD(L1_PARAMS *pl1_src, uint8_t *pwrbuf, FREE_FPTR free_fp, uint32_t wrlen, std::weak_ptr<TCONNTRACK> weakconn, TCONNTRACK *pconn, TEST_DATA_TYPES_E data_type) noexcept
			: pl1_src_(pl1_src), pwrbuf_(pwrbuf), free_fp_(free_fp), wrlen_(wrlen), weakconn_(std::move(weakconn)), pconn_(pconn), data_type_(data_type)
		{}
	
		IO_CMD(const IO_CMD &) 					= delete;

		IO_CMD & operator= (const IO_CMD &)			= delete;

		IO_CMD(IO_CMD && other) noexcept
			: pl1_src_(other.pl1_src_), pwrbuf_(std::exchange(other.pwrbuf_, nullptr)), free_fp_(other.free_fp_),
			wrlen_(other.wrlen_), weakconn_(std::move(other.weakconn_)), pconn_(std::exchange(other.pconn_, nullptr)), 
			start_clock_usec_(other.start_clock_usec_), data_type_(other.data_type_)
		{}	

		IO_CMD & operator= (IO_CMD && other) noexcept
		{
			if (this != &other) {
				dealloc();
				new (this) IO_CMD(std::move(other));
			}

			return *this;
		}

		~IO_CMD() noexcept
		{
			dealloc();
		}	

		void dealloc() noexcept
		{
			if (pwrbuf_) { 
				if (free_fp_) {
					(*free_fp_)(pwrbuf_);
				}

				pwrbuf_	= nullptr;
			}
		}	

		bool is_cli_active() const noexcept
		{
			return !weakconn_.expired();
		}	
	};	

	struct L2_DATA
	{
		const L1_PARAMS			*pl1_src_		{nullptr};
		std::weak_ptr <TCONNTRACK>	weakconn_;
		TCONNTRACK			*pconn_			{nullptr};
		uint64_t			resp_usec_		{0};
		TEST_DATA_TYPES_E		input_data_type_	{TYPE_MIN_TYPE};

		L2_DATA() noexcept					= default;

		L2_DATA(const L1_PARAMS *pl1_src, std::weak_ptr<TCONNTRACK> && weakconn, TCONNTRACK *pconn, uint64_t resp_usec, TEST_DATA_TYPES_E input_data_type) noexcept
			: pl1_src_(pl1_src), weakconn_(std::move(weakconn)), pconn_(pconn), resp_usec_(resp_usec), input_data_type_(input_data_type)
		{}
	
		L2_DATA(const L2_DATA &) 				= delete;
		L2_DATA & operator= (const L2_DATA &)			= delete;

		L2_DATA(L2_DATA && other) noexcept			= default;
		L2_DATA & operator= (L2_DATA && other) noexcept		= default;

		~L2_DATA() noexcept					= default;

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
			ACC_NOTIFY_ONE			acc_;
			DB_WRITE_ARR			dbwrarr_;
			DB_READ_CMD			dbrdcmd_;
			IO_CMD				iocmd_;
			L2_DATA				l2data_;

			void				*pdummy_;

			EV_DATA_ONE() : pdummy_(nullptr)
			{}

			~EV_DATA_ONE()
			{}
		};
		
		EV_DATA_ONE				data_;
		NOTIFY_TYPE_E				ntype_			{NOTIFY_IGNORE};	

		EV_NOTIFY_ONE() 			= default;

		EV_NOTIFY_ONE(ACC_NOTIFY_ONE && acc) noexcept
			: ntype_(NOTIFY_ACCEPT)
		{
			new (&data_.acc_) ACC_NOTIFY_ONE(std::move(acc));	
		}	

		EV_NOTIFY_ONE(DB_WRITE_ARR && dbwrarr) noexcept
			: ntype_(NOTIFY_DB_WRITE)
		{
			new (&data_.dbwrarr_) DB_WRITE_ARR(std::move(dbwrarr));	
		}	

		EV_NOTIFY_ONE(DB_READ_CMD && dbrdcmd) noexcept
			: ntype_(NOTIFY_DB_READ)
		{
			new (&data_.dbrdcmd_) DB_READ_CMD(std::move(dbrdcmd));
		}	
		
		EV_NOTIFY_ONE(IO_CMD && iocmd) noexcept
			: ntype_(NOTIFY_IO_REQ)
		{
			new (&data_.iocmd_) IO_CMD(std::move(iocmd));
		}	
		
		EV_NOTIFY_ONE(L2_DATA && l2data) noexcept
			: ntype_(NOTIFY_L2_DATA)
		{
			new (&data_.l2data_) L2_DATA(std::move(l2data));
		}	
		

		EV_NOTIFY_ONE(const EV_NOTIFY_ONE &)	= delete;	

		EV_NOTIFY_ONE(EV_NOTIFY_ONE && other) noexcept
			: ntype_(other.ntype_)
		{
			switch (ntype_) {
			
			case NOTIFY_ACCEPT :
				new (&data_.acc_) 	ACC_NOTIFY_ONE(std::move(other.data_.acc_));
				break;
			
			case NOTIFY_DB_WRITE :
				new (&data_.dbwrarr_)	DB_WRITE_ARR(std::move(other.data_.dbwrarr_));
				break;

			case NOTIFY_DB_READ :
				new (&data_.dbrdcmd_)	DB_READ_CMD(std::move(other.data_.dbrdcmd_));
				break;

			case NOTIFY_IO_REQ :
				new (&data_.iocmd_)	IO_CMD(std::move(other.data_.iocmd_));
				break;

			case NOTIFY_L2_DATA :
				new (&data_.l2data_)	L2_DATA(std::move(other.data_.l2data_));
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
			
			case NOTIFY_DB_WRITE :
				data_.dbwrarr_.~DB_WRITE_ARR();
				break;

			case NOTIFY_DB_READ :
				data_.dbrdcmd_.~DB_READ_CMD();
				break;

			case NOTIFY_IO_REQ :
				data_.iocmd_.~IO_CMD();
				break;

			case NOTIFY_L2_DATA :
				data_.l2data_.~L2_DATA();
				break;


			default :
				break;
			}	

			ntype_	= NOTIFY_IGNORE;
		}	

		NOTIFY_TYPE_E get_type() const noexcept
		{
			return ntype_;
		}	
	};	

	using MPMCQ_COMM			= folly::MPMCQueue<EV_NOTIFY_ONE>;

	static constexpr size_t			SZ_COMM_SIGNAL_DATA = 128;
	using COMM_SIGNAL			= MULTI_PROC_COMM_HDLR<false, 512, SZ_COMM_SIGNAL_DATA>;

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
		TTYPE_E				thr_type_	{TTYPE_L1_CLI_SERV};
		char				descbuf_[64]	{};
	};	

	struct L2_PARAMS
	{
		GY_THREAD			*pthread_	{nullptr};
		MPMCQ_COMM			*pmpmc_		{nullptr};
		uint32_t			thr_num_	{0};
		TTYPE_E				thr_type_	{TTYPE_L2_DB_RD};
		char				descbuf_[64]	{};
	};	

	static_assert(sizeof(ACC_PARAMS) <= SZ_COMM_SIGNAL_DATA && sizeof(L1_PARAMS) <= SZ_COMM_SIGNAL_DATA && sizeof(L2_PARAMS) <= SZ_COMM_SIGNAL_DATA);


	ACC_PARAMS 				*paccept_arr_		{nullptr};

	L1_PARAMS 				*pl1_streamer_arr_	{nullptr};
	L1_PARAMS 				*pl1_cli_arr_		{nullptr};

	L2_PARAMS 				*pl2_db_wr_arr_		{nullptr};
	L2_PARAMS 				*pl2_db_rd_arr_		{nullptr};
	L2_PARAMS 				*pl2_io_arr_		{nullptr};
	L2_PARAMS 				*pl2_alert_arr_		{nullptr};

	MPMCQ_COMM				**ppmpmc_db_wr_arr_	{nullptr};
	MPMCQ_COMM				**ppmpmc_db_rd_arr_	{nullptr};
	MPMCQ_COMM				**ppmpmc_io_arr_	{nullptr};
	MPMCQ_COMM				**ppmpmc_alert_arr_	{nullptr};

	COMM_SIGNAL				*pcommsignal_		{nullptr};	

	COND_VAR <SCOPE_GY_MUTEX>		barcond_;
	std::atomic<size_t>			nblocked_acc_		{0};
	std::atomic<size_t>			nblocked_l1_		{0};
	std::atomic<size_t>			nblocked_l2_		{0};
	std::atomic<bool>			all_spawned_		{false};

	std::atomic<int64_t>			gtconncount		{0};

	std::string				listen_host_;
	uint16_t				listen_port_;

	static constexpr uint8_t		gpadbuf[8] = "\x0\x0\x0\x0\x0\x0\x0";

	TLISTEN_HDLR(const char * listen_host, uint16_t lport);

	~TLISTEN_HDLR() 			= delete;

	int 	handle_accept(GY_THREAD *pthr);
	int 	handle_l1(GY_THREAD *pthr);
	int 	handle_l2(GY_THREAD *pthr);

	int 	handle_l2_db_wr(L2_PARAMS & param);
	int 	handle_l2_db_rd(L2_PARAMS & param, POOL_ALLOC_ARRAY * pthrpoolarr);
	int 	handle_l2_io_thr(L2_PARAMS & param);
	int 	handle_l2_alert(L2_PARAMS & param);

	void 	spawn_init_threads();

	bool	alert_defined_for_type(TEST_DATA_TYPES_E type) const noexcept
	{
		// Simulate checks for alerts depending on type of input data. Return true for TYPE_TCP_CONN
		switch (type) {
		case TYPE_TCP_CONN 		: return true;

		default 			: return false;
		}	
	}	

	static bool is_streamer_conn(uint8_t *precvbuf, size_t nbytes) noexcept
	{
		return (nbytes && *precvbuf <= 0x04);
	}	
};

int TLISTEN_HDLR::handle_accept(GY_THREAD *pthr)
{
	LISTEN_SOCK			*plsock;
	uint32_t			acc_thr_num = 0;
	int				tsock, tepollfd, ttimerfd;
	ACC_PARAMS			param;
	const pid_t			tid = gy_gettid();
	
	{
		int				retsig = -1;
		COMM_SIGNAL::MULTI_PROC_ELEM	*psignal = (decltype(psignal))pthr->get_opt_arg2();	

		assert(psignal);

		ACC_PARAMS			*psigdata = (ACC_PARAMS *)psignal->get_data_buf();

		acc_thr_num = psigdata->thr_num_;

		GY_SCOPE_EXIT {
			psignal->signal_completion(retsig, sizeof(ACC_PARAMS));
		};	

		try {
			plsock = new LISTEN_SOCK(listen_port_, listen_host_.c_str(), 128, true /* set_nonblock */, true /* reuseaddr */, true /* reuseport */);
		}
		GY_CATCH_EXCEPTION(
			ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to start Listener %u : %s\n\n", acc_thr_num, GY_GET_EXCEPT_STRING);
			GY_STRNCPY(psigdata->descbuf_, GY_GET_EXCEPT_STRING, sizeof(psigdata->descbuf_));

			return -1;
		);

		tsock = plsock->get_sock();

		tepollfd = epoll_create1(EPOLL_CLOEXEC);
		if (tepollfd == -1) {
			PERRORPRINTCOLOR(GY_COLOR_RED, "Failed to create Accept epoll socket");
			GY_STRNCPY(psigdata->descbuf_, "Failed to create Accept epoll socket", sizeof(psigdata->descbuf_));

			return -1;
		}

		ttimerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
		if (ttimerfd == -1) {
			PERRORPRINTCOLOR(GY_COLOR_RED, "Failed to create Accept timerfd");
			GY_STRNCPY(psigdata->descbuf_, "Failed to create Accept timerfd", sizeof(psigdata->descbuf_));

			return -1;
		}	

		psigdata->pthread_ 	= pthr;
		psigdata->plisten_	= plsock;
		psigdata->listen_fd_	= tsock;
		psigdata->epollfd_	= tepollfd;

		snprintf(psigdata->descbuf_, sizeof(psigdata->descbuf_), "Accept Thread %u : TID %d", acc_thr_num, tid);

		param			= *psigdata;

		retsig			= 0;
	}

	const int			listen_sock = tsock, epollfd = tepollfd, timerfd = ttimerfd;

	/*
	 * Now wait for the main thread to signal all other threads have been initialized...
	 */
	bool 				is_inc = false; 

	auto waitcb = [&, this]() noexcept
	{
		if (is_inc == false) {
			nblocked_acc_.fetch_add(1, std::memory_order_relaxed);
			is_inc = true;
		}	
		return !all_spawned_.load(std::memory_order_relaxed);
	};

	auto waitsuc = [this]() noexcept 
	{
		nblocked_acc_.fetch_sub(1, std::memory_order_relaxed);
	};

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Accept Thread #%u now waiting for signal...\n", acc_thr_num);

	barcond_.cond_wait(waitcb, waitsuc);

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Accept Thread #%u received signal...Now continuing...\n", acc_thr_num);

	try {

		static constexpr int		max_events = 128;
		struct epoll_event		levent, tevent, *pevarr, *pevcache;
		size_t				nstreamers = 0, ncli = 0;
		int				ret;	
		MAP_CONNTRACK			mconntrack;
		TCONNTRACK	 		*pconn;
		uint64_t			curr_usec_clock, last_usec_clock = 0;
		int64_t				last_tcount = 0, curr_tcount = 0;
		struct itimerspec		tspec;
		std::unordered_map<const char *, int64_t>	statsmap;
		
		levent.data.ptr			= (void *)(uintptr_t)listen_sock;
		levent.events 			= EPOLLIN | EPOLLRDHUP | EPOLLET;

		ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, listen_sock, &levent);
		if (ret == -1) {
			PERRORPRINTCOLOR(GY_COLOR_RED, "Received error while adding listener socket %s to epoll : Exiting...", param.descbuf_);
			exit(EXIT_FAILURE);
		}	

		tspec.it_interval.tv_sec	= 1;
		tspec.it_interval.tv_nsec	= 0;

		tspec.it_value.tv_sec		= 2;
		tspec.it_value.tv_nsec		= 0;

		ret = timerfd_settime(timerfd, 0, &tspec, nullptr);
		if (ret == -1) {
			PERRORPRINTCOLOR(GY_COLOR_RED, "Received error while setting timerfd interval for %s : Exiting...", param.descbuf_);
			exit(EXIT_FAILURE);
		}	

		tevent.data.ptr			= (void *)(uintptr_t)timerfd;
		tevent.events 			= EPOLLIN;

		ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, timerfd, &tevent);
		if (ret == -1) {
			PERRORPRINTCOLOR(GY_COLOR_RED, "Received error while adding timerfd %s to epoll : Exiting...", param.descbuf_);
			exit(EXIT_FAILURE);
		}	

		pevarr 		= new epoll_event[max_events];
		pevcache	= new epoll_event[max_events];

		auto comp_epoll = [](const epoll_event & ev1, const epoll_event & ev2) noexcept -> bool
		{
			return (uint8_t *)ev2.data.ptr < (uint8_t *)ev1.data.ptr;
		};	

		auto check_conn = [&, this](TCONNTRACK *pnewconn, const int cfd, decltype(mconntrack.find(0)) cit, const bool is_conn_closed) noexcept
		{
			try {
				ssize_t 		nb;
				uint8_t			tbuf[4];
				struct epoll_event	ev;
				bool			bret;
				L1_PARAMS		*pl1;	
				int			iret;

				/*
				 * XXX Currently we do not forward connections to L1 which just send some data and immediately close the 
				 * conn or close the reader half without waiting for response back 
				 *
				 * Change the handling below if thats needed
				 */
				if (gy_unlikely(is_conn_closed)) {
					mconntrack.erase(cit);
					return;
				}	

				nb = sock_peek_recv_data(cfd, tbuf, sizeof(tbuf), true);
				if (nb > 0) {
					/*
					 * We need to signal the L1 thread using its epoll and EPOLLOUT. Also 
					 * remove this fd from the accept epoll
					 */
					ACC_NOTIFY_ONE		acc (std::move(mconntrack.extract(cit)), pnewconn->start_clock_usec_, pnewconn->sockfd_);
					int			ntries = 0;

					epoll_ctl(epollfd, EPOLL_CTL_DEL, cfd, nullptr);

					bret = is_streamer_conn(tbuf, nb);

					if (bret == true) {
						pl1 = pl1_streamer_arr_ + (nstreamers++ % MAX_L1_STREAMERS);
					}
					else {
						pl1 = pl1_cli_arr_ + (ncli++ % MAX_L1_CLI_SERV);
					}	

					/*
					 * Now signal the L1 thread using pl1->psignalq_ and pl1->signal_fd_
					 */
					do { 
						bret = pl1->psignalq_->write(std::move(acc));
					} while (bret == false && ntries++ < 10);

					if (bret == false) {
						statsmap["L1 Notify Blocked"]++;
						return;
					}
					
					// ::write() will act as the memory barrier...

					int64_t			n = 1;

					iret = ::write(pl1->signal_fd_, &n, sizeof(int64_t));
					if (iret == sizeof(int64_t)) {
						return;
					}	
					return;
				}	
				else if (nb == 0) {
					return;
				}
				else {
					mconntrack.erase(cit);
				}	
			}
			GY_CATCH_EXCEPTION(
				ERRORPRINTCOLOR(GY_COLOR_RED, "Caught exception while handling new accept conn : %s\n", GY_GET_EXCEPT_STRING);
				mconntrack.erase(cit);
			);
		};	

		curr_usec_clock		= get_usec_clock();

		do {
			try {
				int			nevents;
				size_t			nfind;

				nevents = epoll_wait(epollfd, pevarr, max_events, -1);
				
				if (nevents == -1) {
					if (errno == EINTR) {
						continue;
					}	
					PERRORPRINTCOLOR(GY_COLOR_RED, "poll on %s failed : Exiting...", param.descbuf_);
					exit(EXIT_FAILURE);
				}	

				std::memcpy(pevcache, pevarr, nevents * sizeof(epoll_event));

				std::stable_sort(pevcache,  pevcache + nevents, comp_epoll);

				for (int i = 0; i < nevents; ++i) {
					auto 			pcache = pevcache + i;
					int			cfd;
					void			*pepdata = pcache->data.ptr;
					uint32_t		cevents = 0;

					pconn = nullptr;

					if (!(pepdata == (void *)(uintptr_t)listen_sock || pepdata == (void *)(uintptr_t)timerfd)) {
						cevents = pcache->events;

						while (i + 1 < nevents) {
							if (pevcache[i + 1].data.ptr == pepdata) {
								cevents |= pevcache[i + 1].events;
								++i;
							}	
							else {
								break;
							}	
						}	

						pconn = (TCONNTRACK *)pepdata;

						cfd = pconn->get_sockfd();

						auto it = mconntrack.find(cfd);
						if (it != mconntrack.end()) {
							// This condition should always be true
							check_conn(pconn, pconn->get_sockfd(), it, (cevents & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)));
						}
					}	
					else if (pepdata == (void *)(uintptr_t)listen_sock) {
						while (mconntrack.size() < MAX_CONCURRENT_ACCEPT_CONNS) {
							struct sockaddr_storage		saddr;
							socklen_t			slen = sizeof(saddr);
tagain :						
							cfd = ::accept4(listen_sock, (sockaddr *)&saddr, &slen, SOCK_NONBLOCK | SOCK_CLOEXEC);

							if (cfd == -1) {
								if (errno == EAGAIN) {
									break;
								}	
								else if (errno == EINTR) {
									goto tagain;
								}	
								else if ((errno == ECONNABORTED) || (errno == EAGAIN) || (errno == ENOBUFS) || (errno == ENOMEM) || (errno == EPERM)) {
									DEBUGEXECN(1, PERRORPRINTCOLOR(GY_COLOR_RED, "Accept failed"); );
									statsmap["Accept Failed"]++;
									continue;
								}	
								else if (errno == EMFILE) {
									PERRORPRINTCOLOR(GY_COLOR_RED, "Accept failed due to process open files"); 
									continue;
								}	
								else {
									PERRORPRINTCOLOR(GY_COLOR_RED, "accept4 on %s failed : Exiting...", param.descbuf_);
									exit(EXIT_FAILURE);
								}
							}	

							try {
								auto 			[it, success] = mconntrack.try_emplace(cfd, nullptr);
								struct epoll_event	ev;

								if (success == true) {
									try {
										it->second = std::make_shared<TCONNTRACK>(&saddr, cfd, epollfd, nullptr, 
												0, 0, false, MAX_CONN_DATA_TIMEOUT_USEC, MAX_CONN_DATA_TIMEOUT_USEC);
									}
									GY_CATCH_EXCEPTION(
										ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught while creating map element for new connection %s\n", 
											GY_GET_EXCEPT_STRING);

										mconntrack.erase(it);
										continue;
									);

									TCONNTRACK	*pnewconn = it->second.get();

									pnewconn->set_epoll_data(pnewconn);

									ev.data.ptr	= pnewconn;
									ev.events 	= EPOLLIN | EPOLLET;

									ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, cfd, &ev);
									if (ret == 0) {
										// Set TCP_NODELAY and SO_KEEPALIVE
										set_sock_nodelay(cfd);
										set_sock_keepalive(cfd);

										continue;
									}	
									else {
										PERRORPRINTCOLOR(GY_COLOR_RED, "Accept epoll add failed");
										mconntrack.erase(it);

										continue;
									}	
								}
								else {
									if (it != mconntrack.end()) {
										mconntrack.erase(it);
									}	
									else {
										close(cfd);
									}
									continue;
								}	
							}
							GY_CATCH_EXCEPTION(
								ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught while accepting new connection %s\n", GY_GET_EXCEPT_STRING);
								close(cfd);
								continue;
							);
						} // accept4 loop
					}
					else {
						uint64_t	tt;

						ret = ::read(timerfd, &tt, sizeof(uint64_t));
					}	
				}	
				
				curr_usec_clock = get_usec_clock();

				if (nevents < max_events && curr_usec_clock - last_usec_clock > MAX_CONN_DATA_TIMEOUT_USEC) {
					last_usec_clock	= curr_usec_clock;

					for (auto it = mconntrack.begin(); it != mconntrack.end(); ) {
						auto pconn1 = it->second.get();

						if (pconn1 && ((true == pconn1->is_idle_timedout(curr_usec_clock)) || (true == pconn1->is_pending_timeout(curr_usec_clock)))) {
							STRING_BUFFER<512>	strbuf;

							INFOPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Closing connection from %s due to idle timeout or pending bytes timeout from %s\n",
								pconn1->print_peer(strbuf), param.descbuf_);

							it = mconntrack.erase(it);
						}	
						else {
							++it;
						}	
					}		

					STRING_BUFFER<1024>	strbuf;

					for (auto && it : statsmap) {
						strbuf.appendfmt(" {\"%s\" : %ld},", it.first, it.second);
					}	
					strbuf.set_last_char(' ');

					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "%s : Connections %lu : Stats : %s\n", param.descbuf_, mconntrack.size(), strbuf.buffer());
				}	
				
				last_tcount 		= curr_tcount;
				curr_tcount		= mconntrack.size();

				gtconncount.fetch_add(curr_tcount - last_tcount, std::memory_order_relaxed);
			}	
			GY_CATCH_EXCEPTION(
				ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught in %s : %s\n", param.descbuf_, GY_GET_EXCEPT_STRING);
			);
		} while (true);	

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Fatal Exception caught in %s : %s : Exiting...\n\n", param.descbuf_, GY_GET_EXCEPT_STRING);
		exit(EXIT_FAILURE);
	);
}	

int TLISTEN_HDLR::handle_l1(GY_THREAD *pthr)
{
	L1_PARAMS			param;
	MPMCQ_COMM			*psignalq = nullptr;
	uint32_t			tl1_thr_num;
	int				tepollfd, tsignalfd, ttimerfd;
	const pid_t			tid = gy_gettid();
	POOL_ALLOC_ARRAY		poolarr;

	{
		int				retsig = -1, spair[2], ret;
		COMM_SIGNAL::MULTI_PROC_ELEM	*psignal = (decltype(psignal))pthr->get_opt_arg2();	

		assert(psignal);

		L1_PARAMS			*psigdata = (L1_PARAMS *)psignal->get_data_buf();

		tl1_thr_num = psigdata->thr_num_;

		GY_SCOPE_EXIT {
			psignal->signal_completion(retsig, sizeof(L1_PARAMS));
		};	

		tepollfd = epoll_create1(EPOLL_CLOEXEC);
		if (tepollfd == -1) {
			PERRORPRINTCOLOR(GY_COLOR_RED, "Failed to create Level 1 epoll socket");
			GY_STRNCPY(psigdata->descbuf_, "Failed to create Level 1 epoll socket", sizeof(psigdata->descbuf_));

			return -1;
		}

		tsignalfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
		if (tsignalfd == -1) {
			PERRORPRINTCOLOR(GY_COLOR_RED, "Failed to create Level 1 eventfd");
			GY_STRNCPY(psigdata->descbuf_, "Failed to create Level 1 eventfd", sizeof(psigdata->descbuf_));

			return -1;
		}	
	
		ttimerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
		if (ttimerfd == -1) {
			PERRORPRINTCOLOR(GY_COLOR_RED, "Failed to create Level 1 timerfd");
			GY_STRNCPY(psigdata->descbuf_, "Failed to create Level 1 timerfd", sizeof(psigdata->descbuf_));

			return -1;
		}	

		try {
			psignalq = new MPMCQ_COMM(MAX_MPMC_ELEMS >> 1);
		}
		GY_CATCH_EXCEPTION(
			ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to create Level 1 signal queue : %s\n", GY_GET_EXCEPT_STRING);
			GY_STRNCPY(psigdata->descbuf_, "Failed to create Level 1 signal queue", sizeof(psigdata->descbuf_));
	
			return -1;
		);

		try {
			size_t			pool_szarr[8], pool_maxarr[8], npoolarr = 0;
			
			if (psigdata->thr_type_ == TTYPE_L1_STREAMER) {
				pool_szarr[0] 	= 32767;
				pool_maxarr[0]	= 128;
				
				pool_szarr[1]	= 4096;
				pool_maxarr[1]	= 2048;

				pool_szarr[2] 	= 512;
				pool_maxarr[2]	= 4096;

				pool_szarr[3]	= 256;
				pool_maxarr[3]	= 2048;

				npoolarr 	= 4;
			}
			else {
				pool_szarr[0]	= 4096;
				pool_maxarr[0]	= 1024;

				pool_szarr[1] 	= 512;
				pool_maxarr[1]	= 2048;

				pool_szarr[2]	= 256;
				pool_maxarr[2]	= 2048;

				npoolarr 	= 3;
			}	

			poolarr.pool_alloc(pool_szarr, pool_maxarr, npoolarr, true);
		}
		GY_CATCH_EXCEPTION(
			ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to create Level 1 memory pool : %s\n", GY_GET_EXCEPT_STRING);
			GY_STRNCPY(psigdata->descbuf_, "Failed to create Level 1 memory pool", sizeof(psigdata->descbuf_));
	
			return -1;
		);
	
		psigdata->pthread_ 	= pthr;
		psigdata->psignalq_	= psignalq;
		psigdata->epollfd_	= tepollfd;
		psigdata->signal_fd_	= tsignalfd;

		snprintf(psigdata->descbuf_, sizeof(psigdata->descbuf_), "Level 1 %s Thread %u TID %d", psigdata->thr_type_ == TTYPE_L1_STREAMER ? "Streaming" : "Client", tl1_thr_num, tid);

		param			= *psigdata;

		retsig			= 0;
	}

	/*
	 * Now wait for the main thread to signal all other threads have been initialized...
	 */
	bool 				is_inc = false; 

	auto waitcb = [&, this]() noexcept
	{
		if (is_inc == false) {
			nblocked_l1_.fetch_add(1, std::memory_order_relaxed);
			is_inc = true;
		}	
		return !all_spawned_.load(std::memory_order_relaxed);
	};

	auto waitsuc = [this]() noexcept 
	{
		nblocked_l1_.fetch_sub(1, std::memory_order_relaxed);
	};

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "%s now waiting for signal...\n", param.descbuf_);

	barcond_.cond_wait(waitcb, waitsuc);

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "%s received signal...Now continuing...\n", param.descbuf_);

	try {
		const int			epollfd = tepollfd, signalfd = tsignalfd, timerfd = ttimerfd;
		const uint32_t			l1_thr_num = tl1_thr_num;
		const bool			is_stream = (param.thr_type_ == TTYPE_L1_STREAMER);
		static constexpr int		max_events = 128, max_retry_events = 32, max_signals_no_read = 256;

		struct epoll_event		levent, tevent, *pevarr, *pevcache, *pevretry;
		size_t				nstreamers = 0, ncli = 0;
		int				ret;	
		MAP_CONNTRACK			mconntrack;
		TCONNTRACK			*pconn;
		uint64_t			curr_usec_clock, last_usec_clock = 0;
		int64_t				last_tcount = 0, curr_tcount = 0, nsignals_seen = 0;
		bool				lastdbwr = false;

		std::unordered_map<const char *, int64_t>	statsmap;

		levent.data.ptr	= (void *)(uintptr_t)signalfd;
		levent.events 	= EPOLLIN | EPOLLET;

		ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, signalfd, &levent);
		if (ret == -1) {
			PERRORPRINTCOLOR(GY_COLOR_RED, "Received error while adding L1 eventfd %s to poll : Exiting...", param.descbuf_);
			exit(EXIT_FAILURE);
		}	

		if (true) {
			struct itimerspec		tspec;

			tspec.it_interval.tv_sec	= 1;
			tspec.it_interval.tv_nsec	= 0;

			tspec.it_value.tv_sec		= 2;
			tspec.it_value.tv_nsec		= 0;

			ret = timerfd_settime(timerfd, 0, &tspec, nullptr);
			if (ret == -1) {
				PERRORPRINTCOLOR(GY_COLOR_RED, "Received error while setting timerfd interval for %s : Exiting...", param.descbuf_);
				exit(EXIT_FAILURE);
			}	
		}

		tevent.data.ptr			= (void *)(uintptr_t)timerfd;
		tevent.events 			= EPOLLIN;

		ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, timerfd, &tevent);
		if (ret == -1) {
			PERRORPRINTCOLOR(GY_COLOR_RED, "Received error while adding timerfd %s to epoll : Exiting...", param.descbuf_);
			exit(EXIT_FAILURE);
		}	

		pevarr 		= new epoll_event[max_events];
		pevcache	= new epoll_event[max_events];

		auto comp_epoll = [](const epoll_event & ev1, const epoll_event & ev2) noexcept -> bool
		{
			return (uint8_t *)ev2.data.ptr < (uint8_t *)ev1.data.ptr;
		};	

		auto send_db_writer = [&, this](DB_WRITE_ARR && dbarr, TCONNTRACK *pconn1) -> bool
		{
			L2_PARAMS		*pdbwr 	= pl2_db_wr_arr_ + (l1_thr_num + lastdbwr) % MAX_L2_DB_WRITERS;
			bool			bret;
			int			ntries = 0;

			do { 
				bret = pdbwr->pmpmc_->write(std::move(dbarr));
			} while (bret == false && ntries++ < 5);

			if (bret == false) {
				// Try the next db writer once
				pdbwr = pl2_db_wr_arr_ + (l1_thr_num + !lastdbwr) % MAX_L2_DB_WRITERS;

				bret = pdbwr->pmpmc_->write(std::move(dbarr));

				if (bret == false) {
					dbarr.dealloc();
				}	
			}
			
			if (bret == true) {
				statsmap["DB Write Req Submitted"]++;
			}	
			else {
				statsmap["DB Write Thread Blocked"]++;
			}	

			lastdbwr = !lastdbwr;

			return bret;
		};

		auto send_db_reader = [&, this](uint8_t *pwrbuf, FREE_FPTR free_fp, uint32_t wrlen, TCONNTRACK *pconn1, TEST_DATA_TYPES_E data_type) -> bool
		{
			L2_PARAMS		*pdbrd 	= pl2_db_rd_arr_ + l1_thr_num % MAX_L2_DB_READERS;
			bool			bret;
			int			ntries = 0;
			
			DB_READ_CMD		dbrdcmd(&param, pwrbuf, free_fp, wrlen, pconn1->weak_from_this(), pconn1, pconn1->machine_id_, data_type); 

			do { 
				bret = pdbrd->pmpmc_->write(std::move(dbrdcmd));
			} while (bret == false && ntries++ < 5);

			if (bret == false) {
				// Try the next db reader once
				pdbrd = pl2_db_rd_arr_ + (l1_thr_num + 1) % MAX_L2_DB_READERS;

				bret = pdbrd->pmpmc_->write(std::move(dbrdcmd));
			}
			
			if (bret == true) {
				statsmap["DB Read Req Submitted"]++;
			}	
			else {
				statsmap["DB Read Thread Blocked"]++;
			}	

			return bret;
		};

		auto send_io_cmd = [&, this](uint8_t *pwrbuf, FREE_FPTR free_fp, uint32_t wrlen, TCONNTRACK *pconn1, TEST_DATA_TYPES_E data_type) -> bool
		{
			L2_PARAMS		*pio 	= pl2_io_arr_ + l1_thr_num % MAX_L2_IO_THREADS;
			bool			bret;
			int			ntries = 0;
			
			IO_CMD			iocmd(&param, pwrbuf, free_fp, wrlen, pconn1->weak_from_this(), pconn1, data_type); 

			do { 
				bret = pio->pmpmc_->write(std::move(iocmd));
			} while (bret == false && ntries++ < 5);

			if (bret == false) {
				// Try the next io reader once
				pio = pl2_io_arr_ + (l1_thr_num + 1) % MAX_L2_IO_THREADS;

				bret = pio->pmpmc_->write(std::move(iocmd));
			}
			
			if (bret == true) {
				statsmap["IO Req Submitted"]++;
			}	
			else {
				statsmap["IO Thread Blocked"]++;
			}	

			return bret;
		};


		auto handle_send = [](TCONNTRACK *pconn1, bool throw_on_error = true) -> ssize_t
		{
			bool			is_closed = false, is_blocked = false;
			ssize_t			sret;

			auto wr_cb = [](EPOLL_CONNTRACK * ptconn, ssize_t total_bytes) noexcept
			{};	
			
			auto again_cb = [](EPOLL_CONNTRACK * ptconn, ssize_t total_bytes) noexcept
			{
				ptconn->wrstat_.pending_clock_usec_ 	= get_usec_clock();
				ptconn->wrstat_.pending_sz_		= total_bytes;
			};	

			auto close_cb = [&](EPOLL_CONNTRACK *ptconn, int tsock) noexcept
			{
				is_closed = true;
			};

			if (pconn1->send_data_pending()) {
				sret = pconn1->send_data(wr_cb, again_cb, close_cb, is_blocked);

				if (is_closed) {
					if (throw_on_error) {
						GY_THROW_EXCEPTION("Failed to send message");
					}
					else {
						return -1;
					}	
				}	

				return sret;
			}
			else {
				return 0;
			}	
		};


		auto send_error_response = [&, this](TCONNTRACK *pconn1, uint64_t identifier, TERR_CODES_E errcode) -> ssize_t
		{

			if (pconn1->is_stream_) {
				static constexpr size_t	fixed_sz = sizeof(TEST_HEADER1) + sizeof(TEST_RESPONSE);

				FREE_FPTR		free_fp;
				uint32_t		act_size;
				void			*palloc = poolarr.safe_malloc(fixed_sz, free_fp, act_size);

				TEST_HEADER1		*phdr = reinterpret_cast<TEST_HEADER1 *>(palloc);
				TEST_RESPONSE		*presp = reinterpret_cast<TEST_RESPONSE *>((uint8_t *)phdr + sizeof(TEST_HEADER1)); 
				
				new (phdr) TEST_HEADER1(TYPE_RESPONSE, fixed_sz - sizeof(TEST_HEADER1));

				*presp			= {identifier, SUBTYPE_NULL_RESPONSE, errcode};

				struct iovec		iov[3] {{phdr, sizeof(*phdr)}, {presp, sizeof(*presp)}, {(void *)gpadbuf, phdr->get_pad_len()}};	
				FREE_FPTR		free_fp_arr[3] {free_fp, nullptr, nullptr};
				
				pconn1->schedule_ext_send(EPOLL_IOVEC_ARR(iov, 3, free_fp_arr, false));
			}	
			else {
				const char 		*perrstr = testcomm::get_error_string(errcode);
				const size_t		nerrstr = 128 + strlen(perrstr);

				FREE_FPTR		free_fp;
				uint32_t		act_size;
				void			*palloc = poolarr.safe_malloc(nerrstr, free_fp, act_size);

				int			ret;

				ret = GY_SAFE_SNPRINTF((char *)palloc, act_size, "{\"retcode\" : %d, \"errormsg\" : \"%s\"}", -errcode, perrstr);

				pconn1->schedule_ext_send(EPOLL_IOVEC_ARR(palloc, ret, free_fp));
			}	

			if (errcode != TERR_SUCCESS) {
				statsmap["Errored Response"]++; 
			}	

			return handle_send(pconn1);
		};

		auto send_response_curr_time = [&, this](TCONNTRACK *pconn1, uint64_t identifier, TEST_REQUEST_CURR_TIME *preq) -> ssize_t
		{
			static constexpr size_t	fixed_sz = sizeof(TEST_HEADER1) + sizeof(TEST_RESPONSE) + sizeof(TEST_RESPONSE_CURR_TIME);

			uint64_t		curtimeusec = get_usec_time();

			FREE_FPTR		free_fp;
			uint32_t		act_size;
			void			*palloc = poolarr.safe_malloc(fixed_sz, free_fp, act_size);

			TEST_HEADER1		*phdr = reinterpret_cast<TEST_HEADER1 *>(palloc);
			TEST_RESPONSE		*presp = reinterpret_cast<TEST_RESPONSE *>((uint8_t *)phdr + sizeof(TEST_HEADER1)); 
			TEST_RESPONSE_CURR_TIME	*pcurtime = reinterpret_cast<TEST_RESPONSE_CURR_TIME *>((uint8_t *)presp + sizeof(TEST_RESPONSE));
			
			new (phdr) TEST_HEADER1(TYPE_RESPONSE, fixed_sz - sizeof(TEST_HEADER1));

			*presp			= {identifier, SUBTYPE_RESPONSE_CURR_TIME, TERR_SUCCESS};
			*pcurtime		= {get_usec_clock(), curtimeusec, (int64_t)curtimeusec - (int64_t)preq->curr_usec_time_};

			struct iovec		iov[2] {{phdr, fixed_sz}, {(void *)gpadbuf, phdr->get_pad_len()}};	
			FREE_FPTR		free_fp_arr[2] {free_fp, nullptr};
				
			pconn1->schedule_ext_send(EPOLL_IOVEC_ARR(iov, 2, free_fp_arr, false));

			statsmap["Time Response"]++; 

			return handle_send(pconn1);
		};

		/*
		 * Currently max_syscall is ignored 
		 */
		auto handle_recv = [&, this](TCONNTRACK *pconn1, int sock, const bool is_stream_conn, const bool is_conn_closed, const bool peer_wr_closed, int max_syscall = INT_MAX - 1) -> ssize_t
		{
			ssize_t				sret, max_bytes, totbytes = 0;
			ssize_t				max_buf_sz, data_sz;
			uint8_t				*prdbuf;
			int				nsyscall = 0, ret;
			auto				&rdstat_ = pconn1->rdstat_;
			bool				is_again = false, bret, bsent, is_pendrecv = (rdstat_.pending_sz_ > 0);
			TEST_HEADER1			hdr(TYPE_MIN_TYPE, 0);

			DB_WRITE_ARR			dbarr;

			GY_SCOPE_EXIT {
				if (dbarr.pbufstart_ && dbarr.free_fp_ && rdstat_.pdirbuf_ == dbarr.pbufstart_) {
					dbarr.reset();
				}	
			};

			auto schedule_dbrd = [&](uint8_t *pwrbuf, uint32_t wrlen, TEST_DATA_TYPES_E data_type) -> bool
			{
				if (gy_unlikely(data_sz < 0 || max_buf_sz < data_sz)) {
					statsmap["Internal L1 Error"]++; 
					GY_THROW_EXCEPTION("Internal Error : DB read stats invalid");
				}

				uint32_t		act_size = 0;
				void			*palloc = nullptr;
				FREE_FPTR		free_fp;

				palloc = poolarr.safe_malloc(wrlen, free_fp, act_size);

				std::memcpy(palloc, pwrbuf, wrlen);

				return send_db_reader((uint8_t *)palloc, free_fp, act_size, pconn1, data_type);
			};	

			auto schedule_iocmd = [&](uint8_t *pwrbuf, uint32_t wrlen, TEST_DATA_TYPES_E data_type) -> bool
			{
				if (gy_unlikely(data_sz < 0 || max_buf_sz < data_sz)) {
					statsmap["Internal L1 Error"]++; 
					GY_THROW_EXCEPTION("Internal Error : io cmd stats invalid");
				}

				uint32_t		act_size = 0;
				void			*palloc = nullptr;
				FREE_FPTR		free_fp;

				palloc = poolarr.safe_malloc(wrlen, free_fp, act_size);

				std::memcpy(palloc, pwrbuf, wrlen);

				return send_io_cmd((uint8_t *)palloc, free_fp, act_size, pconn1, data_type);
			};	


			auto schedule_dbwr = [&](uint8_t *pwrbuf, uint32_t wrlen, TEST_DATA_TYPES_E data_type) 
			{
				if (gy_unlikely((unsigned)dbarr.ndbs_ >= GY_ARRAY_SIZE(dbarr.dbonearr_))) {
					statsmap["Internal L1 Error"]++; 
					GY_THROW_EXCEPTION("Internal Error : dbarr stats invalid");
				}

				dbarr.dbonearr_[dbarr.ndbs_] = {pwrbuf, wrlen, data_type};

				if (dbarr.ndbs_ == 0) {
					GY_STRNCPY(dbarr.dbname_, pconn1->machine_id_, sizeof(dbarr.dbname_));

					dbarr.pbufstart_	= rdstat_.pdirbuf_;
					dbarr.free_fp_		= rdstat_.get_dirbuf_freeptr();
				}	
				
				dbarr.ndbs_++;
			};	

			auto set_variables = [&]() 
			{
				max_buf_sz 	= rdstat_.max_buf_sz_;
				data_sz		= rdstat_.data_sz_;
				prdbuf		= rdstat_.pdirbuf_;
			};

			if (!rdstat_.pdirbuf_) {
				FREE_FPTR		free_fp;
				uint32_t		act_size;
				void			*palloc = poolarr.safe_malloc(4096, free_fp, act_size);

				rdstat_.set_buf((uint8_t *)palloc, free_fp, act_size, 0);
			}	

			do {
				set_variables();

				max_bytes = max_buf_sz - data_sz;

				if (gy_unlikely(max_bytes <= 0)) {
					statsmap["Internal L1 Error"]++; 
					GY_THROW_EXCEPTION("Internal Error : max_bytes <= 0");
				}	

				sret = ::recv(sock, prdbuf + data_sz, max_bytes, 0);

				if (sret <= 0) {
					if (errno == EINTR) {
						continue;
					}
					else if (errno == EAGAIN) {
						break;
					}	
					else {
						if (dbarr.ndbs_ > 0) {
							send_db_writer(std::move(dbarr), pconn1);
						}

						return -1;
					}
				}

				is_again 			= (sret < max_bytes);

				if (is_pendrecv) {
					pconn1->pending_recv_seen(sret);
				}	
					
				nsyscall++;

				rdstat_.last_oper_cusec_ 	= get_usec_clock();
				rdstat_.nbytes_seen_ 		+= sret;
				rdstat_.data_sz_		+= sret;
			
				totbytes			+= sret;	
				data_sz				+= sret;

				do {
					if (data_sz >= (ssize_t)sizeof(TEST_HEADER1)) {
						std::memcpy(&hdr, prdbuf, sizeof(hdr));

						if (false == hdr.validate(prdbuf)) {
							statsmap["Invalid Message Error"]++; 
							GY_THROW_EXCEPTION("Invalid Message received. Closing connection");
						}	
						else if (gy_unlikely(is_stream_conn && hdr.data_type_ != TYPE_REGISTER && (false == pconn1->is_auth_done()))) {
							statsmap["Invalid Message Error"]++; 
							GY_THROW_EXCEPTION("Invalid Message received. Closing connection");
						}	
					}
					else {
						hdr.data_sz_	= sizeof(TEST_HEADER1);
					}

					if ((data_sz < hdr.data_sz_ && dbarr.ndbs_ > 0) || (max_buf_sz < (ssize_t)hdr.data_sz_)) {

						FREE_FPTR		free_fp;
						uint32_t		act_size;
						uint8_t			*palloc = (uint8_t *)poolarr.safe_malloc(std::max(4096u, hdr.data_sz_), free_fp, act_size);

						std::memcpy(palloc, prdbuf, data_sz);

						if (dbarr.ndbs_ > 0) {
							send_db_writer(std::move(dbarr), pconn1);
							rdstat_.reset_buf(false);
						}
						else {
							rdstat_.reset_buf(true);
						}	

						rdstat_.set_buf(palloc, free_fp, act_size, data_sz);
						
						set_variables();
					}
			
					if (data_sz < hdr.data_sz_) {
						if (data_sz != rdstat_.data_sz_) {
							// This implies dbarr.ndbs_ == 0 and we just need to move data to the start

							std::memmove(rdstat_.pdirbuf_, prdbuf, data_sz);
							rdstat_.data_sz_	= data_sz;

							set_variables();
						}	
						break;
					}

					rdstat_.nrequests_++;

					switch (hdr.data_type_) {
				
					case TYPE_TASK :
						if (true) {
							statsmap["Task Msg"]++;

							TEST_TASK 	*ptask = (TEST_TASK *)(prdbuf + sizeof(TEST_HEADER1));

							bret = TEST_TASK::validate(&hdr, ptask, prdbuf + hdr.data_sz_);

							if (bret == false) {
								statsmap["Invalid Message Error"]++; 
								GY_THROW_EXCEPTION("Invalid Message received. Closing connection");
							}

							schedule_dbwr(prdbuf, hdr.data_sz_, hdr.data_type_);
						}
						break;

					case TYPE_TCP_CONN :
						if (true) {
							statsmap["TCP Conn Msg"]++;

							TEST_TCP_CONN 	*ptask = (TEST_TCP_CONN *)(prdbuf + sizeof(TEST_HEADER1));

							bret = TEST_TCP_CONN::validate(&hdr, ptask, prdbuf + hdr.data_sz_);

							if (bret == false) {
								statsmap["Invalid Message Error"]++; 
								GY_THROW_EXCEPTION("Invalid Message received. Closing connection");
							}

							schedule_dbwr(prdbuf, hdr.data_sz_, hdr.data_type_);
						}
						break;

					case TYPE_WEB_QUERY :
						if (true) {
							statsmap["Web Query Msg"]++;

							if (gy_unlikely(is_stream_conn)) {
								statsmap["Invalid Message Error"]++; 
								GY_THROW_EXCEPTION("Invalid Message received. Closing connection");
							}	

							TEST_WEB_QUERY	*pweb = (TEST_WEB_QUERY *)(prdbuf + sizeof(TEST_HEADER1));

							bret = schedule_dbrd(prdbuf, hdr.data_sz_, hdr.data_type_);
							if (bret == true) {
								break;
							}	
							
							send_error_response(pconn1, 0, TERR_BLOCKING_ERROR);
						}
						break;

					case TYPE_QUERY :

						if (true) {
							TEST_QUERY		*pquery = (TEST_QUERY *)(prdbuf + sizeof(TEST_HEADER1));

							switch (pquery->subtype_) {

							case SUBTYPE_LISTENER_REQ :
								statsmap["Listener Req"]++;

								if (false == is_conn_closed) {
									TEST_LISTENER_REQ 	*plist = (TEST_LISTENER_REQ *)((char *)pquery + sizeof(TEST_QUERY));

									bret = TEST_LISTENER_REQ::validate(&hdr);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received. Closing connection");
									}

									bret = schedule_dbrd(prdbuf, hdr.data_sz_, hdr.data_type_);
									if (bret == true) {
										break;
									}	
									
									send_error_response(pconn1, pquery->seqid_, TERR_BLOCKING_ERROR);
								}
								break;
							
							case SUBTYPE_REQUEST_READ_FILE :
								statsmap["Read File Req"]++;

								if (false == is_conn_closed) {
									TEST_REQUEST_READ_FILE 	*pfile = (TEST_REQUEST_READ_FILE *)((char *)pquery + sizeof(TEST_QUERY));

									bret = pfile->validate(&hdr);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received. Closing connection");
									}

									bret = schedule_iocmd(prdbuf, hdr.data_sz_, hdr.data_type_);
									if (bret == true) {
										break;
									}	
									
									send_error_response(pconn1, pquery->seqid_, TERR_BLOCKING_ERROR);
								}
								break;

							case SUBTYPE_REQUEST_CURR_TIME :
								statsmap["Time Req"]++;

								if (false == is_conn_closed) {
									TEST_REQUEST_CURR_TIME 	*ptime = (TEST_REQUEST_CURR_TIME *)((char *)pquery + sizeof(TEST_QUERY));

									bret = TEST_REQUEST_CURR_TIME::validate(&hdr);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received. Closing connection");
									}

									// Directly respond here itself
									send_response_curr_time(pconn1, pquery->seqid_, ptime);
								}
								break;
		
							default :
								statsmap["Invalid Message Error"]++; 
								GY_THROW_EXCEPTION("Invalid Message received. Closing connection");
							}	
						}
						break;

					case TYPE_REGISTER :
						if (true) {
							statsmap["Register Req"]++;

							if (pconn1->is_auth_done()) {
								statsmap["Invalid Message Error"]++; 
								GY_THROW_EXCEPTION("Invalid Message received. Closing connection");
							}	

							TEST_REGISTER 		*preg = (TEST_REGISTER *)(rdstat_.pdirbuf_ + sizeof(TEST_HEADER1));

							bret = preg->validate(&hdr);
							if (bret == false) {
								statsmap["Invalid Message Error"]++; 
								GY_THROW_EXCEPTION("Invalid Message received. Closing connection");
							}

							bret = pconn1->set_registration(preg);
							if (bret == false) {
								statsmap["Invalid Message Error"]++; 
								GY_THROW_EXCEPTION("Invalid Message received. Closing connection");
							}	
							
							CONDEXEC(
								DEBUGEXECN(10,
									STRING_BUFFER<256>	strbuf;

									strbuf.appendconst("Stream Registration Successful for ");
									pconn1->print_peer(strbuf);

									INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "%s\n", strbuf.buffer());
								);	
							);

							send_error_response(pconn1, 0, TERR_SUCCESS);
						}
						break;

					default :
						statsmap["Invalid Message Error"]++; 
						GY_THROW_EXCEPTION("Invalid Message received. Closing connection");
					}

					data_sz 	-= hdr.data_sz_;
					max_buf_sz	-= hdr.data_sz_;
					prdbuf 		+= hdr.data_sz_;

					if (gy_unlikely(data_sz < 0 || max_buf_sz < data_sz)) {
						GY_THROW_EXCEPTION("Internal Error : dbarr stats invalid");
					}

					if ((dbarr.ndbs_ == GY_ARRAY_SIZE(dbarr.dbonearr_)) || (dbarr.ndbs_ > 0 && (max_buf_sz - data_sz < (ssize_t)sizeof(TEST_HEADER1)))) {
						uint32_t		act_size = 0;
						void			*palloc = nullptr;
						FREE_FPTR		free_fp;

						if (!is_again || (data_sz > 0) || ((max_buf_sz - data_sz < (ssize_t)sizeof(TEST_HEADER1)) && max_buf_sz > 0)) {
							palloc = poolarr.safe_malloc(data_sz > 4096 ? data_sz + 1024 : 4096, free_fp, act_size);

							if (data_sz > 0) {
								std::memcpy(palloc, prdbuf, data_sz);
							}	
						}

						send_db_writer(std::move(dbarr), pconn1);
						rdstat_.reset_buf(false);

						if (palloc) {
							rdstat_.set_buf((uint8_t *)palloc, free_fp, act_size, data_sz);
							set_variables();
						}	
					}	
					else if ((data_sz != rdstat_.data_sz_) && (max_buf_sz - data_sz < (ssize_t)sizeof(TEST_HEADER1))) {
						// This implies dbarr.ndbs_ == 0 and we just need to move data to the start

						std::memmove(rdstat_.pdirbuf_, prdbuf, data_sz);
						rdstat_.data_sz_	= data_sz;

						set_variables();
					}	

				} while (data_sz > 0);

			} while (is_again == false && nsyscall < max_syscall);

			if (dbarr.ndbs_ > 0) {
				FREE_FPTR		free_fp;
				uint32_t		act_size;
				void			*palloc = nullptr;
				
				if (data_sz > 0) {
					palloc = poolarr.safe_malloc(std::max(4096, (int)data_sz + 1024), free_fp, act_size);
					std::memcpy(palloc, prdbuf, data_sz);
				}

				send_db_writer(std::move(dbarr), pconn1);
				rdstat_.reset_buf(false);

				if (palloc) {
					rdstat_.set_buf((uint8_t *)palloc, free_fp, act_size, data_sz);
				}
				else {
					rdstat_.reset_buf(true);
				}	
			}
			else if (data_sz == 0) {
				rdstat_.reset_buf(true);	// Free up the buffer
			}	
			else if (totbytes > 0) {
				// Set rdstat_.pending_sz_ for timeout handling
				rdstat_.pending_sz_		= hdr.data_sz_ - data_sz;
				rdstat_.pending_clock_usec_	= rdstat_.last_oper_cusec_;
			}	

			return totbytes;
		};	

		auto handle_notify = [&, this](EV_NOTIFY_ONE & evn) -> bool
		{
			switch (evn.get_type()) {
			
			case NOTIFY_ACCEPT :
				if (evn.data_.acc_.connnode_) {
					ACC_NOTIFY_ONE		*pacc = &evn.data_.acc_;

					statsmap["Accept Conn Notify"]++;

					try {
						auto			[it, success, node] = mconntrack.insert(std::move(evn.data_.acc_.connnode_));
						struct epoll_event	ev;

						if (success == true) {
							TCONNTRACK		*pnewconn = it->second.get();

							ev.data.ptr		= pnewconn;
							ev.events 		= EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLET;

							ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, pacc->sockfd_, &ev);
							if (ret == 0) {
								/*
								 * Now read the existing data as we may not receive a new EPOLLIN if all data received.
								 */
								try { 
									auto 			pconn = it->second.get();
									ssize_t			sret;

									pconn->set_epollfd(epollfd);

									pconn->set_max_idle_usec(MAX_CONN_IDLE_TIMEOUT_USEC);

									pconn->set_wr_pipeline();

									pconn->is_stream_	= is_stream;

									if (is_stream) {
										pconn->set_close_conn_on_wr_complete(false);
									}
									else {
										pconn->set_close_conn_on_wr_complete(true);
									}	

									sret = handle_recv(pconn, pacc->sockfd_, is_stream, false, false);
									if (sret == -1) {
										mconntrack.erase(it);
										return false;
									}	
									 
									return true;
								}
								GY_CATCH_EXCEPTION(
									mconntrack.erase(it);
									return false;
								);
							}	
							else {
								PERRORPRINTCOLOR(GY_COLOR_RED, "Level 1 epoll add failed");
								mconntrack.erase(it);
								return false;
							}	
						}
						else {
							// node destructor will cleanup
						}	
					}
					GY_CATCH_EXCEPTION(
						statsmap["Accept Notify Failure"]++;
						ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught while adding connection to Level 1 map : %s\n", GY_GET_EXCEPT_STRING);
						return false;
					);
				}
				else {
					return false;
				}
				break;
			
			case NOTIFY_L2_DATA :
				statsmap["L2 Data Notify"]++;

				if (true == evn.data_.l2data_.is_cli_active() && evn.data_.l2data_.pconn_) {
					auto			pconn = evn.data_.l2data_.pconn_;
					const int		cfd = pconn->get_sockfd();
					ssize_t			sret;

					if (cfd == -1) {
						// Already closed
						return false;
					}	

					try {
						sret = handle_send(pconn, false /* throw_on_error */);
						if (sret == -1) {
							mconntrack.erase(cfd);
							return false;
						}

						return true;
					}
					GY_CATCH_EXCEPTION(
						mconntrack.erase(cfd);
						return false;
					);
				}	
				break;

			default :
				break;
			}	
			return false;
		};	
	
		curr_usec_clock		= get_usec_clock();

		do {
			try {
				int			nevents, nretry_events = 0;
				size_t			nfind;
				bool			bret;

				nevents = epoll_wait(epollfd, pevarr, max_events, -1);
				
				if (nevents == -1) {
					if (errno == EINTR) {
						continue;
					}	
					PERRORPRINTCOLOR(GY_COLOR_RED, "poll on %s failed : Exiting...", param.descbuf_);
					exit(EXIT_FAILURE);
				}	

				std::memcpy(pevcache, pevarr, nevents * sizeof(epoll_event));

				std::stable_sort(pevcache,  pevcache + nevents, comp_epoll);

				for (int i = 0; i < nevents; ++i) {
					auto 			pcache = pevcache + i;
					void			*pepdata = pcache->data.ptr;
					uint32_t		cevents = 0;

					if (!(pepdata == (void *)(uintptr_t)signalfd || pepdata == (void *)(uintptr_t)timerfd)) {
						cevents = pcache->events;

						while (i + 1 < nevents) {
							if (pevcache[i + 1].data.ptr == pepdata) {
								cevents |= pevcache[i + 1].events;
								++i;
							}	
							else {
								break;
							}	
						}	

						pconn = (TCONNTRACK *)pepdata;
						
						const int cfd = pconn->get_sockfd();

						try {
							const bool		conn_closed = (cevents & (EPOLLERR | EPOLLHUP));
							const bool		peer_wr_closed = (conn_closed || (cevents & EPOLLRDHUP));
							ssize_t			sret = 0;

							if (cevents & EPOLLIN) {
								sret = handle_recv(pconn, cfd, is_stream, conn_closed, peer_wr_closed);

								if (sret == -1) {
									mconntrack.erase(cfd);
									continue;
								}	
							}	
							
							if (cevents & EPOLLOUT) {
								if (false == conn_closed) {
									sret = handle_send(pconn, false /* throw_on_error */);
								}	
							}	

							if (sret == -1 || conn_closed) {
								mconntrack.erase(cfd);
								continue;
							}	
						}
						GY_CATCH_EXCEPTION(
							INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Caught exception while handling L1 conn : %s\n", GY_GET_EXCEPT_STRING);
							mconntrack.erase(cfd);
							continue;
						);
					}	
					else if (pepdata == (void *)(uintptr_t)signalfd) {
						if (gy_unlikely(nsignals_seen++ > max_signals_no_read)) {
							uint64_t		n;

							nsignals_seen = 0;
							
							ret = ::read(signalfd, &n, sizeof(uint64_t));
							if (ret != sizeof(uint64_t)) {
								if (errno != EAGAIN) {
									PERRORPRINTCOLOR(GY_COLOR_RED, "Received error while reading L1 eventfd %s : Exiting...", param.descbuf_);
									exit(EXIT_FAILURE);
								}	
							}	
						}	

						do {
							EV_NOTIFY_ONE		evn;

							bret = psignalq->read(evn);
							if (bret) {
								try {
									handle_notify(evn);
								}
								GY_CATCH_EXCEPTION(
				
								);
							}	
						} while (bret == true);	
					}	
					else {
						uint64_t		n;
							
						ret = ::read(timerfd, &n, sizeof(uint64_t));
						if (ret != sizeof(uint64_t)) {
							if (errno != EAGAIN) {
								PERRORPRINTCOLOR(GY_COLOR_RED, "Received error while reading L1 timerfd %s : Exiting...", param.descbuf_);
								exit(EXIT_FAILURE);
							}
						}	
					}	
				}	
				
				curr_usec_clock = get_usec_clock();

				if (nevents < max_events && (curr_usec_clock - last_usec_clock > MAX_CONN_DATA_TIMEOUT_USEC)) {
					last_usec_clock = curr_usec_clock;

					for (auto it = mconntrack.begin(); it != mconntrack.end(); ) {
						bool		is_pend = false, is_idle = false;

						auto pconn1 = it->second.get();

						if (pconn1 && (true == pconn1->is_pending_timeout(curr_usec_clock))) {
							is_pend = true;

							statsmap["Pending data Timeout"]++;
						}
						else if (pconn1 && (true == pconn1->is_idle_timedout(curr_usec_clock))) {
							is_idle = true;

							statsmap["Idle Timeout"]++;
						}	

						if (is_pend || is_idle) {
							STRING_BUFFER<512>	strbuf;

							if (is_idle) {
								strbuf.appendconst("Idle Timeout from ");
							}
							else {
								strbuf.appendconst("Pending data Timeout from ");
							}	

							INFOPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Closing connection due to %s : %s\n",
								pconn1->print_peer(strbuf), param.descbuf_);

							it = mconntrack.erase(it);
						}	
						else {
							++it;
						}	
					}		

					STRING_BUFFER<1024>	strbuf;

					for (auto && it : statsmap) {
						strbuf.appendfmt(" {\"%s\" : %ld},", it.first, it.second);
					}	
					strbuf.set_last_char(' ');

					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "%s : Connections %lu (of Total %lu) : Stats : %s\n", 
						param.descbuf_, mconntrack.size(), gtconncount.load(std::memory_order_relaxed), strbuf.buffer());
				}	
				
				last_tcount 		= curr_tcount;
				curr_tcount		= mconntrack.size();

				gtconncount.fetch_add(curr_tcount - last_tcount, std::memory_order_relaxed);
			}	
			GY_CATCH_EXCEPTION(
				ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught in %s : %s\n", param.descbuf_, GY_GET_EXCEPT_STRING);
			);
				
		} while (true);	
	
		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught in %s : %s\n\n", param.descbuf_, GY_GET_EXCEPT_STRING);
		return -1;
	);
}	

int TLISTEN_HDLR::handle_l2(GY_THREAD *pthr)
{
	uint32_t			l2_thr_num = 0;
	L2_PARAMS			param;
	POOL_ALLOC_ARRAY		*pthrpoolarr = nullptr;
	const pid_t			tid = gy_gettid();

	{
		int				retsig = -1;
		COMM_SIGNAL::MULTI_PROC_ELEM	*psignal = (decltype(psignal))pthr->get_opt_arg2();	

		assert(psignal);

		L2_PARAMS			*psigdata = (L2_PARAMS *)psignal->get_data_buf();

		l2_thr_num = psigdata->thr_num_;

		GY_SCOPE_EXIT {
			psignal->signal_completion(retsig, sizeof(L2_PARAMS));
		};	

		psigdata->pthread_ 	= pthr;

		const char		*ptype;

		switch (psigdata->thr_type_) {
		
		case TTYPE_L2_DB_WR 	:	ptype = "DB Writer"; break;
		case TTYPE_L2_DB_RD 	:	ptype = "DB Reader"; break;
		case TTYPE_L2_IO_THR 	:	ptype = "IO Handler"; break;
		case TTYPE_L2_ALERT 	:	ptype = "Alert Handler"; break;

		default 		:
			ERRORPRINTCOLOR(GY_COLOR_RED, "Invalid L2 Thread Type specified : %u\n", psigdata->thr_type_);
			GY_STRNCPY(psigdata->descbuf_, "Invalid L2 Thread Type specified", sizeof(psigdata->descbuf_));

			return -1;
		}

		try {
			if (psigdata->thr_type_ == TTYPE_L2_DB_RD) {
				size_t			pool_szarr[2], pool_maxarr[2];
			
				pool_szarr[0]	= 256;
				pool_maxarr[0]	= 1024;

				pool_szarr[1] 	= 512;
				pool_maxarr[1]	= 1024;

				pthrpoolarr = new POOL_ALLOC_ARRAY(pool_szarr, pool_maxarr, 2, true);
			}	
		}
		GY_CATCH_EXCEPTION(
			ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to create Level 2 memory pool : %s\n", GY_GET_EXCEPT_STRING);
			GY_STRNCPY(psigdata->descbuf_, "Failed to create Level 2 memory pool", sizeof(psigdata->descbuf_));
	
			return -1;
		);

		snprintf(psigdata->descbuf_, sizeof(psigdata->descbuf_), "Level 2 %s Thread %u TID %d", ptype, l2_thr_num, tid);
		
		param			= *psigdata;

		retsig			= 0;
	}

	/*
	 * Now wait for the main thread to signal all other threads have been initialized...
	 */
	bool is_inc = false; 

	auto waitcb = [&, this]() noexcept
	{
		if (is_inc == false) {
			nblocked_l2_.fetch_add(1, std::memory_order_relaxed);
			is_inc = true;
		}	
		return !all_spawned_.load(std::memory_order_relaxed);
	};

	auto waitsuc = [this]() noexcept 
	{
		nblocked_l2_.fetch_sub(1, std::memory_order_relaxed);
	};

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "%s now waiting for signal...\n", param.descbuf_);

	barcond_.cond_wait(waitcb, waitsuc);

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "%s received signal...Now continuing...\n", param.descbuf_);

	switch (param.thr_type_) {
	
	case TTYPE_L2_DB_WR 	:	return handle_l2_db_wr(param);

	case TTYPE_L2_DB_RD 	:	return handle_l2_db_rd(param, pthrpoolarr);

	case TTYPE_L2_IO_THR 	:	return handle_l2_io_thr(param);

	case TTYPE_L2_ALERT 	:	return handle_l2_alert(param);

	default 		: 	return -1;
	}
}


int TLISTEN_HDLR::handle_l2_db_wr(L2_PARAMS & param)
{
	try {
		MPMCQ_COMM			* const pl2pool = param.pmpmc_;
		const uint32_t			l2_thr_num = param.thr_num_;
		const pid_t			tid = gy_gettid();
		uint64_t			curr_usec_clock = get_usec_clock() + ((tid * 10) % 10000), last_usec_clock = curr_usec_clock;

		std::unordered_map<const char *, int64_t>	statsmap;

		do {
			EV_NOTIFY_ONE		ev;

			pl2pool->blockingRead(ev);

			if (NOTIFY_DB_WRITE != ev.get_type()) {
				statsmap["Invalid Notify"]++;
				continue;
			}

			statsmap["Total Notify"]++;

			try {	
				DB_WRITE_ARR		&dbarr = ev.data_.dbwrarr_;
				bool			is_alert = false;
				int			ndelays = 0;

				auto send_db = [&](const char *dbname, uint8_t *pwrbuf, uint32_t wrlen, TEST_DATA_TYPES_E data_type)
				{
					// Simulate DB request using FILE IO
					SCOPE_FD		sfd("/tmp/test1.dat.1111__", O_WRONLY | O_TRUNC | O_CREAT, 0640);
					int			fd = sfd.get();
					
					if (fd > 0) {
						write(fd, pwrbuf, wrlen);
					}	

					// Simulate a 1 msec delay every 5 records
					if (++ndelays == 5) {
						ndelays = 0;
						gy_msecsleep(1);
					}	
				};	

				auto send_to_alert = [&, this]() -> bool
				{
					L2_PARAMS		*palert	= pl2_alert_arr_ + l2_thr_num % MAX_L2_ALERT_THREADS;
					bool			bret;
					int			ntries = 0;
					
					bret = palert->pmpmc_->write(std::move(dbarr));

					if (bret == true) {
						statsmap["Alert Sends"]++;
					}
					else {
						statsmap["Alert Notify Blocked"]++;
					}
					
					return bret;
				};

				for (size_t i = 0; i < dbarr.ndbs_; ++i) {
					auto & dbone 		= dbarr.dbonearr_[i];

					send_db(dbarr.dbname_, dbone.pwrbuf_, dbone.wrlen_, dbone.data_type_);	
					
					/*
					 * Now check if Alert defined for this data_type_
					 * If so we need to forward this message to the Alert Handler
					 */
					if (alert_defined_for_type(dbone.data_type_)) {
						is_alert = true;
					}	
					else {
						dbone.wrlen_ = 0;
					}	
				}

				if (is_alert) {
					send_to_alert();
				}	

				curr_usec_clock = get_usec_clock();

				if (curr_usec_clock - last_usec_clock > MAX_CONN_DATA_TIMEOUT_USEC) {
					last_usec_clock = curr_usec_clock;

					STRING_BUFFER<1024>	strbuf;

					for (auto && it : statsmap) {
						strbuf.appendfmt(" {\"%s\" : %ld},", it.first, it.second);
					}	
					strbuf.set_last_char(' ');

					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_GREEN, "%s : Stats : %s\n", param.descbuf_, strbuf.buffer());
				}
			}
			GY_CATCH_EXCEPTION(
				ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught in %s while handling message : %s\n\n", param.descbuf_, GY_GET_EXCEPT_STRING);
				statsmap["Exception Occurred"]++;
			);

		} while (true);	

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught in %s : %s\n\n", param.descbuf_, GY_GET_EXCEPT_STRING);
		return -1;
	);
}

int TLISTEN_HDLR::handle_l2_db_rd(L2_PARAMS & param, POOL_ALLOC_ARRAY *pthrpoolarr)
{
	try {
		MPMCQ_COMM			* const pl2pool = param.pmpmc_;
		const uint32_t			l2_thr_num = param.thr_num_;
		const pid_t			tid = gy_gettid();
		uint64_t			curr_usec_clock = get_usec_clock() + ((tid * 10) % 10000), last_usec_clock = curr_usec_clock;

		std::unordered_map<const char *, int64_t>	statsmap;

		do {
			EV_NOTIFY_ONE		ev;

			pl2pool->blockingRead(ev);

			if (NOTIFY_DB_READ != ev.get_type()) {
				statsmap["Invalid Notify"]++;
				continue;
			}

			statsmap["Total Notify"]++;

			try {	
				DB_READ_CMD		&dbrdcmd = ev.data_.dbrdcmd_;
				uint8_t			*poutput = nullptr;
				FREE_FPTR		free_fp = nullptr, free_fp_hdr = nullptr;
				uint32_t		szoutput = 0;
				int			nresp = 0;

				auto send_db_response = [&](uint8_t *pwrbuf, uint32_t wrlen, TEST_DATA_TYPES_E data_type) -> bool
				{
					size_t			fixed_sz = 0;	
					TEST_DATA_SUBTYPE_E	subtype = SUBTYPE_MIN_TYPE;
					uint64_t		identifier = 0;
					TEST_HEADER1		*phdr1 = reinterpret_cast<TEST_HEADER1 *>(pwrbuf);

					switch (phdr1->data_type_) {
					
					case TYPE_WEB_QUERY :
						if (true) {
							// fixed_sz = 0 as output in json directly
							statsmap["Web Query"]++;
						}
						break;
						
					case TYPE_QUERY :

						if (true) {
							TEST_QUERY		*pquery = (TEST_QUERY *)(pwrbuf + sizeof(TEST_HEADER1));

							switch (pquery->subtype_) {

							case SUBTYPE_LISTENER_REQ :
								fixed_sz 	= sizeof(TEST_HEADER1) + sizeof(TEST_RESPONSE) + sizeof(TEST_LISTENER_RESP);
								subtype 	= SUBTYPE_LISTENER_RESP;
								identifier	= pquery->seqid_;
							
								statsmap["Listener Req"]++;

								break;
			
							default :
								statsmap["Invalid Query"]++;
								return false;							
							}
						}
						break;

					default :
						statsmap["Invalid Query"]++;
						return false;
					};

					// Simulate DB request using FILE IO and response by waiting for 1 msec
					SCOPE_FD		sfd("/tmp/test1.dat.2222__", O_WRONLY | O_TRUNC | O_CREAT, 0640);
					int			fd = sfd.get();
					
					if (fd > 0) {
						write(fd, pwrbuf, wrlen);
					}	

					gy_msecsleep(1);
					
					// Simulate a large query response every 50th query
					if (++nresp == 50) {
						nresp = 0;
						gy_msecsleep(500);
					}	

					// Now send the response 
					static constexpr size_t		nszresp[] {101, 510, 3045, 1025, 40, 10, 345, GY_UP_MB(2), 10222, 3203};

					szoutput = nszresp[nresp % GY_ARRAY_SIZE(nszresp)];

					poutput = (uint8_t *)malloc(szoutput);
					if (!poutput) {
						GY_THROW_SYS_EXCEPTION("Failed to allocate memory for db response");
					}
					free_fp = ::free;

					GY_SCOPE_EXIT {
						if (poutput) {
							free(poutput);
						}
					};

					std::memset(poutput, 0xCC, szoutput);

					auto					shconn = dbrdcmd.weakconn_.lock();

					if (!shconn) {
						statsmap["Client Disconnected"]++;
						return false;
					}	

					L2_DATA					l2data;	
					std::optional<EPOLL_IOVEC_ARR>		resp_arr;
					
					if (fixed_sz > 0 && subtype > SUBTYPE_MIN_TYPE) {
						// We need to prepend headers

						uint32_t		act_size;
						uint8_t			*palloc = (uint8_t *)pthrpoolarr->safe_malloc(fixed_sz, free_fp_hdr, act_size);
						TEST_HEADER1		*phdr = reinterpret_cast<TEST_HEADER1 *>(palloc);
						TEST_RESPONSE		*presp = reinterpret_cast<TEST_RESPONSE *>((uint8_t *)phdr + sizeof(TEST_HEADER1)); 
						void			*psubresp = ((uint8_t *)presp + sizeof(TEST_RESPONSE));
						size_t			sublen = 0;

						new (phdr) TEST_HEADER1(TYPE_RESPONSE, fixed_sz - sizeof(TEST_HEADER1) + szoutput);

						if (gy_likely(true == phdr->validate(poutput))) {
							*presp			= {identifier, subtype, TERR_SUCCESS};

							switch (subtype) {
							
							case SUBTYPE_LISTENER_RESP :
								if (true) {
									TEST_LISTENER_RESP	*plistres = reinterpret_cast<TEST_LISTENER_RESP *>(psubresp);

									new (plistres) TEST_LISTENER_RESP(szoutput);
									sublen = sizeof(TEST_LISTENER_RESP);
									
									statsmap["Listener Response"]++;
								}	
								break;
							
							default :
								break;
							}	

							struct iovec		iov[5] {{phdr, sizeof(*phdr)}, {presp, sizeof(*presp)}, {psubresp, sublen}, {poutput, szoutput}, 
											{(void *)gpadbuf, phdr->get_pad_len()}};	
							FREE_FPTR		free_fp_arr[5] {free_fp_hdr, nullptr, nullptr, free_fp, nullptr};
							
							resp_arr.emplace(iov, GY_ARRAY_SIZE(iov), free_fp_arr);
							
							poutput 		= nullptr;
						}
						else {
							// Send an error response 

							phdr->~TEST_HEADER1();

							new (phdr) TEST_HEADER1(TYPE_RESPONSE, sizeof(TEST_RESPONSE));

							*presp			= {identifier, SUBTYPE_NULL_RESPONSE, TERR_MAX_SZ_BREACHED};

							struct iovec		iov[3] {{phdr, sizeof(*phdr)}, {presp, sizeof(*presp)}, {(void *)gpadbuf, phdr->get_pad_len()}};	
							FREE_FPTR		free_fp_arr[3] {free_fp_hdr, nullptr, nullptr};
							
							statsmap["Error Response"]++;

							resp_arr.emplace(iov, GY_ARRAY_SIZE(iov), free_fp_arr);
						}	
					}					
					else {
						// Directly send the poutput

						statsmap["Direct Response"]++;

						resp_arr.emplace(poutput, szoutput, free_fp);

						poutput 		= nullptr;
					}	

					l2data.pl1_src_		= dbrdcmd.pl1_src_;
					l2data.weakconn_	= std::move(dbrdcmd.weakconn_);
					l2data.pconn_		= dbrdcmd.pconn_;
					l2data.resp_usec_	= get_usec_clock() - dbrdcmd.start_clock_usec_;
					l2data.input_data_type_	= dbrdcmd.data_type_;

					bool			bret;
					int			ntries = 0;

					/*
					 * Now signal the L1 thread using psignalq_ and signal_fd_
					 */
					
					shconn->schedule_ext_send(std::move(*resp_arr));

					do { 
						bret = dbrdcmd.pl1_src_->psignalq_->write(std::move(l2data));
					} while (bret == false && ntries++ < 10);

					if (bret == false) {
						statsmap["L1 Notify Blocked"]++;
						return false;
					}

					// ::write() will act as the memory barrier...

					int64_t			n = 1;

					(void)::write(dbrdcmd.pl1_src_->signal_fd_, &n, sizeof(int64_t));

					return true;
				};	

				// First check if the original client is still active
				if (!dbrdcmd.pconn_ || (false == dbrdcmd.is_cli_active())) {
					statsmap["Client Disconnected"]++;
				}
				else {
					send_db_response(dbrdcmd.pwrbuf_, dbrdcmd.wrlen_, dbrdcmd.data_type_);
				}

				curr_usec_clock = get_usec_clock();

				if (curr_usec_clock - last_usec_clock > MAX_CONN_DATA_TIMEOUT_USEC) {
					last_usec_clock = curr_usec_clock;

					STRING_BUFFER<1024>	strbuf;

					for (auto && it : statsmap) {
						strbuf.appendfmt(" {\"%s\" : %ld},", it.first, it.second);
					}	
					strbuf.set_last_char(' ');

					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN_ITALIC, "%s : Stats : %s\n", param.descbuf_, strbuf.buffer());
				}
			}
			GY_CATCH_EXCEPTION(
				ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught in %s while handling message : %s\n\n", param.descbuf_, GY_GET_EXCEPT_STRING);
				statsmap["Exception Occurred"]++;
			);

		} while (true);	

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught in %s : %s\n\n", param.descbuf_, GY_GET_EXCEPT_STRING);
		return -1;
	);
}

int TLISTEN_HDLR::handle_l2_io_thr(L2_PARAMS & param)
{
	try {
		MPMCQ_COMM			* const pl2pool = param.pmpmc_;
		const uint32_t			l2_thr_num = param.thr_num_;
		const pid_t			tid = gy_gettid();
		uint64_t			curr_usec_clock = get_usec_clock(), last_usec_clock = curr_usec_clock;

		std::unordered_map<const char *, int64_t>	statsmap;

		do {
			EV_NOTIFY_ONE		ev;

			pl2pool->blockingRead(ev);

			if (NOTIFY_IO_REQ != ev.get_type()) {
				statsmap["Invalid Notify"]++;
				continue;
			}

			statsmap["Total Notify"]++;

			try {	
				IO_CMD			&iocmd = ev.data_.iocmd_;
				uint8_t			*poutput = nullptr;
				FREE_FPTR		free_fp = nullptr;
				uint32_t		szoutput = 0;
				int			nresp = 0;

				auto send_io_response = [&](uint8_t *pwrbuf, uint32_t wrlen, TEST_DATA_TYPES_E data_type) -> bool
				{
					size_t			fixed_sz = 0;	
					TEST_DATA_SUBTYPE_E	subtype = SUBTYPE_MIN_TYPE;
					uint64_t		identifier = 0;
					TEST_HEADER1		*phdr1 = reinterpret_cast<TEST_HEADER1 *>(pwrbuf);
					TEST_REQUEST_READ_FILE	*pfile = nullptr;

					switch (phdr1->data_type_) {
					
					case TYPE_QUERY :

						if (true) {
							TEST_QUERY		*pquery = (TEST_QUERY *)(pwrbuf + sizeof(TEST_HEADER1));

							switch (pquery->subtype_) {

							case SUBTYPE_REQUEST_READ_FILE :

								pfile = (TEST_REQUEST_READ_FILE *)((char *)pquery + sizeof(TEST_QUERY));

								fixed_sz 	= sizeof(TEST_HEADER1) + sizeof(TEST_RESPONSE) + sizeof(TEST_RESPONSE_READ_FILE);
								subtype 	= SUBTYPE_RESPONSE_READ_FILE;
								identifier	= pquery->seqid_;

								statsmap["Read File Req"]++;
								break;
			
							default :
								statsmap["Invalid Query"]++;
								return false;							
							}
						}
						break;

					default :
						statsmap["Invalid Query"]++;
						return false;
					};

					if (!pfile) {
						return false;
					}	

					auto				shconn = iocmd.weakconn_.lock();

					if (!shconn) {
						statsmap["Client Disconnected"]++;
						return false;
					}	

					// Now read the file and send the response
					char				pathname[512];
					L2_DATA				l2data;	
					std::optional<EPOLL_IOVEC_ARR>	resp_arr;

					auto schedule_signal = [&]() -> bool
					{
						shconn->schedule_ext_send(std::move(*resp_arr));

						l2data.pl1_src_		= iocmd.pl1_src_;
						l2data.weakconn_	= std::move(iocmd.weakconn_);
						l2data.pconn_		= iocmd.pconn_;
						l2data.resp_usec_	= get_usec_clock() - iocmd.start_clock_usec_;
						l2data.input_data_type_	= iocmd.data_type_;

						bool			bret;
						int			ntries = 0;

						/*
						 * Now signal the L1 thread using psignalq_ and signal_fd_
						 */
						do { 
							bret = iocmd.pl1_src_->psignalq_->write(std::move(l2data));
						} while (bret == false && ntries++ < 10);

						if (bret == false) {
							statsmap["L1 Notify Blocked"]++;
							return false;
						}
						else {
							statsmap["L1 Notify"]++;
						}	

						// ::write() will act as the memory barrier...

						int64_t			n = 1;

						(void)::write(iocmd.pl1_src_->signal_fd_, &n, sizeof(int64_t));

						return true;
					};

					auto send_error = [&](int terrno, TERR_CODES_E tcode, uint8_t * palloc)
					{
						if (!palloc) {
							GY_THROW_SYS_EXCEPTION("Failed to allocate memory");
						}

						assert(fixed_sz > 0);

						TEST_HEADER1		*phdr = reinterpret_cast<TEST_HEADER1 *>(palloc);
						TEST_RESPONSE		*presp = reinterpret_cast<TEST_RESPONSE *>((uint8_t *)phdr + sizeof(TEST_HEADER1)); 
						TEST_RESPONSE_READ_FILE	*pfileresp = reinterpret_cast<TEST_RESPONSE_READ_FILE *>((uint8_t *)presp + sizeof(TEST_RESPONSE));

						new (phdr) TEST_HEADER1(TYPE_RESPONSE, fixed_sz - sizeof(TEST_HEADER1));

						*presp			= {identifier, SUBTYPE_RESPONSE_READ_FILE, tcode};
						*pfileresp		= {(int64_t)(get_usec_time() - pfile->trequsec_), terrno, 0};

						struct iovec		iov[2] {{phdr, fixed_sz}, {(void *)gpadbuf, phdr->get_pad_len()}};	
						FREE_FPTR		free_fp_arr[2] {::free, nullptr};
						
						if (tcode != TERR_SUCCESS) {
							statsmap["Error Response"]++;
						}

						resp_arr.emplace(iov, GY_ARRAY_SIZE(iov), free_fp_arr);

						schedule_signal();
					};

					GY_STRNCPY(pathname, pfile->pathname_, sizeof(pathname));
					SCOPE_FD		sfd(pathname, O_RDONLY);
					int			ret, fd = sfd.get();
					
					if (fd > 0) {
						struct stat		stat1;
						uint32_t		maxsz;

						if (pfile->nbytes_ > 16 * 1024) {
							fstat(fd, &stat1);
							maxsz = std::min(stat1.st_size, (off_t)pfile->nbytes_);
						}
						else {
							maxsz = pfile->nbytes_;
						}

						uint8_t			*palloc = (uint8_t *)malloc(fixed_sz + maxsz);

						if (!palloc) {
							GY_THROW_SYS_EXCEPTION("Failed to allocate memory");
						}

						TEST_HEADER1		*phdr = reinterpret_cast<TEST_HEADER1 *>(palloc);
						TEST_RESPONSE		*presp = reinterpret_cast<TEST_RESPONSE *>((uint8_t *)phdr + sizeof(TEST_HEADER1)); 
						TEST_RESPONSE_READ_FILE	*pfileresp = reinterpret_cast<TEST_RESPONSE_READ_FILE *>((uint8_t *)presp + sizeof(TEST_RESPONSE));

						new (phdr) TEST_HEADER1(TYPE_RESPONSE, fixed_sz - sizeof(TEST_HEADER1) + maxsz);

						if (false == phdr->validate(palloc)) {
							send_error(0, TERR_MAX_SZ_BREACHED, palloc);
							return false;
						}	

						if (pfile->offset_ > 0) {
							lseek(fd, pfile->offset_, SEEK_SET);	
						}
						
						ret = gy_readbuffer(fd, palloc + fixed_sz, maxsz);
						if (ret == -1) {
							phdr->~TEST_HEADER1();
							send_error(errno, TERR_SYSERROR, palloc);
							return false;
						}	

						*presp			= {identifier, SUBTYPE_RESPONSE_READ_FILE, TERR_SUCCESS};
						*pfileresp		= {(int64_t)(get_usec_time() - pfile->trequsec_), 0, maxsz};

						struct iovec		iov[2] {{phdr, maxsz + fixed_sz}, {(void *)gpadbuf, phdr->get_pad_len()}};	
						FREE_FPTR		free_fp_arr[2] {::free, nullptr};
						
						resp_arr.emplace(iov, GY_ARRAY_SIZE(iov), free_fp_arr);

						schedule_signal();

						statsmap["File Read Response"]++;

						return true;

					}	
					else {
						send_error(errno, TERR_SYSERROR,  (uint8_t *)malloc(fixed_sz));
						return false;
					}	
				};


				// First check if the original client is still active
				if (!iocmd.pconn_ || (false == iocmd.is_cli_active())) {
					statsmap["Client Disconnected"]++;
				}	
				else {
					send_io_response(iocmd.pwrbuf_, iocmd.wrlen_, iocmd.data_type_);
				}

				curr_usec_clock = get_usec_clock();

				if (curr_usec_clock - last_usec_clock > MAX_CONN_DATA_TIMEOUT_USEC) {
					last_usec_clock = curr_usec_clock;

					STRING_BUFFER<1024>	strbuf;

					for (auto && it : statsmap) {
						strbuf.appendfmt(" {\"%s\" : %ld},", it.first, it.second);
					}	
					strbuf.set_last_char(' ');

					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN_UNDERLINE, "%s : Stats : %s\n", param.descbuf_, strbuf.buffer());
				}
			}
			GY_CATCH_EXCEPTION(
				ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught in %s while handling message : %s\n\n", param.descbuf_, GY_GET_EXCEPT_STRING);
				statsmap["Exception Occurred"]++;
			);

		} while (true);	

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught in %s : %s\n\n", param.descbuf_, GY_GET_EXCEPT_STRING);
		return -1;
	);
}

int TLISTEN_HDLR::handle_l2_alert(L2_PARAMS & param)
{
	try {
		MPMCQ_COMM			* const pl2pool = param.pmpmc_;
		const uint32_t			l2_thr_num = param.thr_num_;

		int64_t				total_req = 0, total_err = 0, total_ign = 0, total_except = 0;

		do {
			EV_NOTIFY_ONE		ev;

			pl2pool->blockingRead(ev);

		} while (true);	

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught in %s : %s\n\n", param.descbuf_, GY_GET_EXCEPT_STRING);
		return -1;
	);
}

void TLISTEN_HDLR::spawn_init_threads()
{
	/*
	 * We first spawn the accept threads (REUSEPORTs)
	 */
	auto acclam = [](void *arg) -> void *
	{
		GY_THREAD	*pthr = (GY_THREAD *)arg;
		TLISTEN_HDLR	*pthis = (TLISTEN_HDLR *)pthr->get_opt_arg1();

		MAKE_PTHREAD_WRAP("handle_accept", pthis->handle_accept(pthr));

		return nullptr;
	};

	for (uint32_t na = 0; na < MAX_ACCEPT_THREADS; ++na) {	
		GY_THREAD	*pthr = nullptr;	
		auto 		psignal = pcommsignal_->get_proc_buf();
		int		nretry = 0, respcode;
		uint8_t		retdata[SZ_COMM_SIGNAL_DATA];	
		ACC_PARAMS	*pretdata;
		size_t		sz1;
		
		assert(psignal);

		pretdata = (ACC_PARAMS *)psignal->get_data_buf();

		new (pretdata) ACC_PARAMS();

		pretdata->thr_num_ = na;
		pretdata->thr_type_ = TTYPE_ACCEPT;

		do {
			try {
				pthr = new GY_THREAD("accept handler", acclam, nullptr, this, psignal);
			}
			GY_CATCH_EXCEPTION(
				if (++nretry < 4) {
					ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to start accept thread %s : Retrying after 3 sec", GY_GET_EXCEPT_STRING);
					gy_nanosleep(3, 0);
				}
			);
		} 
		while (!pthr && nretry < 4);

		if (!pthr) {
			ERRORPRINTCOLOR(GY_COLOR_RED, "Too many thread spawn failures. Exiting...\n\n");
			exit(EXIT_FAILURE);
		}	

		// Now wait
		psignal->dispatch_wait(retdata, sz1, respcode);

		pretdata = (ACC_PARAMS *)retdata;

		if (respcode != 0) {
			pretdata->descbuf_[sizeof(pretdata->descbuf_) - 1] = '\0';
			ERRORPRINTCOLOR(GY_COLOR_RED, "Accept thread returned error %s (%d). Exiting...\n\n", pretdata->descbuf_, respcode);
			exit(EXIT_FAILURE);
		}	

		assert(pretdata->plisten_ && pretdata->listen_fd_ > 0 && pretdata->epollfd_ > 0 && pretdata->pthread_ == pthr);

		if (!(pretdata->plisten_ && pretdata->listen_fd_ > 0 && pretdata->epollfd_ > 0 && pretdata->pthread_ == pthr)) {
			ERRORPRINTCOLOR(GY_COLOR_RED, "Internal error : Accept thread returned invalid parameters. Exiting...\n\n");
			exit(EXIT_FAILURE);
		}	

		paccept_arr_[na] = *pretdata;
	}	

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "All Accept threads spawned successfully. Now spawning Level 1 Handler threads...\n");

	/*
	 * Now spawn the Level 1 epoll handler threads
	 */
	auto l1lam = [](void *arg) -> void *
	{
		GY_THREAD	*pthr = (GY_THREAD *)arg;
		TLISTEN_HDLR	*pthis = (TLISTEN_HDLR *)pthr->get_opt_arg1();

		MAKE_PTHREAD_WRAP("Level 1 Handler", pthis->handle_l1(pthr));

		return nullptr;
	};

	for (uint32_t n = 0; n < MAX_L1_THREADS; ++n) {	
		GY_THREAD	*pthr = nullptr;	
		auto 		psignal = pcommsignal_->get_proc_buf();
		int		nretry = 0, respcode;
		uint8_t		retdata[SZ_COMM_SIGNAL_DATA];	
		L1_PARAMS	*pretdata, *parray;
		size_t		sz1;
		
		assert(psignal);

		pretdata = (L1_PARAMS *)psignal->get_data_buf();

		new (pretdata) L1_PARAMS();

		if (n < MAX_L1_STREAMERS) {	
			pretdata->thr_num_ 	= n;
			pretdata->thr_type_	= TTYPE_L1_STREAMER;
			parray			= pl1_streamer_arr_ + pretdata->thr_num_;
		}
		else {
			pretdata->thr_num_ 	= n - MAX_L1_STREAMERS;
			pretdata->thr_type_	= TTYPE_L1_CLI_SERV;
			parray			= pl1_cli_arr_ + pretdata->thr_num_;
		}	

		do {
			try {
				pthr = new GY_THREAD("Level 1 handler", l1lam, nullptr, this, psignal);
			}
			GY_CATCH_EXCEPTION(
				if (++nretry < 4) {
					ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to start L1 thread %s : Retrying after 3 sec", GY_GET_EXCEPT_STRING);
					gy_nanosleep(3, 0);
				}
			);
		} 
		while (!pthr && nretry < 4);

		if (!pthr) {
			ERRORPRINTCOLOR(GY_COLOR_RED, "Too many thread spawn failures. Exiting...\n\n");
			exit(EXIT_FAILURE);
		}	

		// Now wait
		psignal->dispatch_wait(retdata, sz1, respcode);

		pretdata = (L1_PARAMS *)retdata;

		if (respcode != 0) {
			pretdata->descbuf_[sizeof(pretdata->descbuf_) - 1] = '\0';
			ERRORPRINTCOLOR(GY_COLOR_RED, "Level 1 thread returned error %s (%d). Exiting...\n\n", pretdata->descbuf_, respcode);
			exit(EXIT_FAILURE);
		}	

		assert(pretdata->epollfd_ > 0);

		if (!(pretdata->epollfd_ > 0 && pretdata->pthread_ == pthr)) {
			ERRORPRINTCOLOR(GY_COLOR_RED, "Internal error : Level 1 thread returned invalid parameters. Exiting...\n\n");
			exit(EXIT_FAILURE);
		}	

		*parray = *pretdata;
	}	

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "All Level 1 threads spawned successfully. Now spawning Level 2 Handler threads...\n");

	/*
	 * Now spawn the Level 2 MPMC handler threads
	 */
	auto l2lam = [](void *arg) -> void *
	{
		GY_THREAD	*pthr = (GY_THREAD *)arg;
		TLISTEN_HDLR	*pthis = (TLISTEN_HDLR *)pthr->get_opt_arg1();

		MAKE_PTHREAD_WRAP("Level 2 Handler", pthis->handle_l2(pthr));

		return nullptr;
	};

	for (uint32_t n = 0; n < MAX_L2_THREADS; ++n) {	
		GY_THREAD	*pthr = nullptr;	
		auto 		psignal = pcommsignal_->get_proc_buf();
		int		nretry = 0, respcode;
		uint8_t		retdata[SZ_COMM_SIGNAL_DATA];	
		L2_PARAMS	*pretdata, *parray;
		size_t		sz1;
		MPMCQ_COMM	*pmq;
		
		assert(psignal);

		pretdata = (L2_PARAMS *)psignal->get_data_buf();

		new (pretdata) L2_PARAMS();
		
		if (n < MAX_L2_DB_WRITERS) {
			pretdata->thr_num_ 	= n;
			pretdata->thr_type_ 	= TTYPE_L2_DB_WR;
			pretdata->pmpmc_	= ppmpmc_db_wr_arr_[pretdata->thr_num_ % MAX_L2_DB_WR_POOLS];

			parray			= pl2_db_wr_arr_ + pretdata->thr_num_;
		}
		else if (n < MAX_L2_DB_WRITERS + MAX_L2_DB_READERS) {
			pretdata->thr_num_ 	= n - MAX_L2_DB_WRITERS;
			pretdata->thr_type_ 	= TTYPE_L2_DB_RD;
			pretdata->pmpmc_	= ppmpmc_db_rd_arr_[pretdata->thr_num_ % MAX_L2_DB_RD_POOLS];

			parray			= pl2_db_rd_arr_ + pretdata->thr_num_;
		}
		else if (n < MAX_L2_DB_WRITERS + MAX_L2_DB_READERS + MAX_L2_IO_THREADS) {
			pretdata->thr_num_ 	= n - MAX_L2_DB_WRITERS - MAX_L2_DB_READERS;
			pretdata->thr_type_ 	= TTYPE_L2_IO_THR;
			pretdata->pmpmc_	= ppmpmc_io_arr_[pretdata->thr_num_ % MAX_L2_IO_POOLS];

			parray			= pl2_io_arr_ + pretdata->thr_num_;
		}
		else {
			pretdata->thr_num_ 	= n - MAX_L2_DB_WRITERS - MAX_L2_DB_READERS - MAX_L2_IO_THREADS;
			pretdata->thr_type_ 	= TTYPE_L2_ALERT;
			pretdata->pmpmc_	= ppmpmc_alert_arr_[pretdata->thr_num_ % MAX_L2_ALERT_POOLS];

			parray			= pl2_alert_arr_ + pretdata->thr_num_;
		}	

		do {
			try {
				pthr = new GY_THREAD("Level 2 handler", l2lam, nullptr, this, psignal);
			}
			GY_CATCH_EXCEPTION(
				if (++nretry < 4) {
					ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to start L2 thread %s : Retrying after 3 sec", GY_GET_EXCEPT_STRING);
					gy_nanosleep(3, 0);
				}
			);
		} 
		while (!pthr && nretry < 4);

		if (!pthr) {
			ERRORPRINTCOLOR(GY_COLOR_RED, "Too many thread spawn failures. Exiting...\n\n");
			exit(EXIT_FAILURE);
		}	

		// Now wait
		psignal->dispatch_wait(retdata, sz1, respcode);

		pretdata = (L2_PARAMS *)retdata;

		if (respcode != 0) {
			pretdata->descbuf_[sizeof(pretdata->descbuf_) - 1] = '\0';
			ERRORPRINTCOLOR(GY_COLOR_RED, "Level 2 thread returned error %s (%d). Exiting...\n\n", pretdata->descbuf_, respcode);
			exit(EXIT_FAILURE);
		}	

		if (!(pretdata->pthread_ == pthr)) {
			ERRORPRINTCOLOR(GY_COLOR_RED, "Internal error : Level 2 thread returned invalid parameters. Exiting...\n\n");
			exit(EXIT_FAILURE);
		}	

		*parray = *pretdata;
	}	

	all_spawned_.store(true);
	
	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "All threads spawned successfully. Now signalling the threads to start processing...\n");

	bool		bret;

	// Now check if all threads have received the signal and started
	auto lamchk = [this]() noexcept -> bool
	{
		auto bacc 	= nblocked_acc_.load(std::memory_order_relaxed);
		auto bl1 	= nblocked_l1_.load(std::memory_order_relaxed);
		auto bl2 	= nblocked_l2_.load(std::memory_order_relaxed);

		if (bacc + bl1 + bl2 > 0) {
			return true;
		}	
		return false;
	};	
	
	do {
		gy_msecsleep(100);
		bret = barcond_.cond_broadcast(lamchk);
	} while (bret == true);
	
	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "All threads signalled successfully : Listener is now active. Clients can connect now...\n");
}	


TLISTEN_HDLR::TLISTEN_HDLR(const char * listen_host, uint16_t lport)
	: pcommsignal_(COMM_SIGNAL::allocate_handler()), listen_host_(listen_host), listen_port_(lport)
{
	/*
	 * First try to see if the listener IP/Port is already used. We cannot rely on the accept thread as
	 * it will use SO_REUSEPORT and that may succeed if the userid permits even though that IP/Port is already bound.
	 */

	try {
		LISTEN_SOCK		tsock(listen_port_, listen_host_.c_str());
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to start Listener : %s : Exiting...\n\n", GY_GET_EXCEPT_STRING);
		exit(EXIT_FAILURE);
	);
	 
	INFOPRINT("Starting Listener Threads spawning...\n");

	paccept_arr_ 		= new ACC_PARAMS[MAX_ACCEPT_THREADS];

	pl1_streamer_arr_	= new L1_PARAMS[MAX_L1_STREAMERS];
	pl1_cli_arr_		= new L1_PARAMS[MAX_L1_CLI_SERV];

	pl2_db_wr_arr_		= new L2_PARAMS[MAX_L2_DB_WRITERS];
	pl2_db_rd_arr_		= new L2_PARAMS[MAX_L2_DB_READERS];
	pl2_io_arr_		= new L2_PARAMS[MAX_L2_IO_THREADS];
	pl2_alert_arr_		= new L2_PARAMS[MAX_L2_ALERT_THREADS];

	ppmpmc_db_wr_arr_	= new MPMCQ_COMM *[MAX_L2_DB_WR_POOLS];
	ppmpmc_db_rd_arr_	= new MPMCQ_COMM *[MAX_L2_DB_RD_POOLS];
	ppmpmc_io_arr_		= new MPMCQ_COMM *[MAX_L2_IO_POOLS];
	ppmpmc_alert_arr_	= new MPMCQ_COMM *[MAX_L2_ALERT_POOLS];

	for (size_t i = 0; i < MAX_L2_DB_WR_POOLS; ++i) {
		ppmpmc_db_wr_arr_[i]	= new MPMCQ_COMM(MAX_MPMC_ELEMS * 3);
	}	

	for (size_t i = 0; i < MAX_L2_DB_RD_POOLS; ++i) {
		ppmpmc_db_rd_arr_[i]	= new MPMCQ_COMM(MAX_MPMC_ELEMS);
	}	

	for (size_t i = 0; i < MAX_L2_IO_POOLS; ++i) {
		ppmpmc_io_arr_[i]	= new MPMCQ_COMM(MAX_MPMC_ELEMS);
	}	

	for (size_t i = 0; i < MAX_L2_ALERT_POOLS; ++i) {
		ppmpmc_alert_arr_[i]	= new MPMCQ_COMM(MAX_MPMC_ELEMS);
	}	

	spawn_init_threads();
}	

class TCLI_CONNTRACK;

class TASYNC_SOCK_CB
{
public :
	using TREAD_CB = folly::Function<void(TCLI_CONNTRACK *, uint8_t *, size_t, TEST_HEADER1 *, TEST_RESPONSE *)>;

	TREAD_CB		fcb_;
	uint64_t		seqid_		{0};	
};	

class TCLI_CONNTRACK : public EPOLL_CONNTRACK
{
public :
	static constexpr size_t				MAX_ASYNC_CBS = 8;

	std::array<TASYNC_SOCK_CB, MAX_ASYNC_CBS>	tcbarr_;
	uint64_t					start_seqid_		{get_usec_clock() & 0xFFFF};
	char						printbuf_[512];
	bool						is_stream_		{true};

	using EPOLL_CONNTRACK::EPOLL_CONNTRACK;

	uint64_t get_next_seqid() noexcept
	{
		return ++start_seqid_;
	}	

	ssize_t avail_recv_cb_id() const noexcept
	{
		for (size_t i = 0; i < tcbarr_.size(); ++i) {
			if (nullptr == tcbarr_[i].fcb_) {
				return i;
			}	
		}	

		return -1;
	}

	ssize_t get_recv_cb_by_seqid(uint64_t seqid) const noexcept
	{
		for (size_t i = 0; i < tcbarr_.size(); ++i) {
			if (seqid == tcbarr_[i].seqid_ && tcbarr_[i].fcb_ != nullptr) {
				return i;
			}	
		}	

		return -1;
	}

	size_t get_nrecv_cbs() const noexcept
	{
		size_t			ncbs = 0;

		for (size_t i = 0; i < tcbarr_.size(); ++i) {
			if (nullptr != tcbarr_[i].fcb_) {
				ncbs++;
			}	
		}	

		return ncbs;
	}	

	// No bounds check
	TASYNC_SOCK_CB & get_recv_cb(size_t id) noexcept
	{
		return tcbarr_[id];
	}	

	// No bounds check
	void reset_recv_cb(size_t id) noexcept
	{
		tcbarr_[id].fcb_ 	= nullptr;
		tcbarr_[id].seqid_	= 0;
	}	

};	


void * cli_thread(void *arg)
{
	try {
		GY_THREAD				*pthread = (GY_THREAD *)arg;
		const char				*phost = (const char *)pthread->get_opt_arg1();
		uint64_t				tar1 = (uint64_t)pthread->get_opt_arg2();
		POOL_ALLOC_ARRAY			poolarr;
		uint16_t				port1 = tar1 & 0xFFFF;
		uint32_t				conns_per_thr = tar1 >> 16;
		char					serverstr[512];
		std::unordered_map<int, TCLI_CONNTRACK>	conntrack;
		int					epollfd;
		static constexpr int			max_events = 128;
		struct epoll_event			*pevarr, *pevcache;
		const pid_t				tid = gy_gettid();
		std::unordered_map<const char *, int64_t>	statsmap;

		snprintf(serverstr, sizeof(serverstr), "Server %s : Port %hu", phost, port1);

		if (conns_per_thr > 5) {
			size_t			pool_szarr[8], pool_maxarr[8], npoolarr = 0;

			pool_szarr[0] 	= 32767;
			pool_maxarr[0]	= 128;
			
			pool_szarr[1]	= 4096;
			pool_maxarr[1]	= conns_per_thr * 16;

			pool_szarr[2] 	= 512;
			pool_maxarr[2]	= conns_per_thr * 16;

			pool_szarr[3]	= 256;
			pool_maxarr[3]	= conns_per_thr * 16;

			npoolarr 	= 4;

			poolarr.pool_alloc(pool_szarr, pool_maxarr, npoolarr, true);
		}	
		else {
			size_t			pool_szarr[1], pool_maxarr[1], npoolarr = 1;

			pool_szarr[0]	= 4096;
			pool_maxarr[0]	= conns_per_thr * 16;

			poolarr.pool_alloc(pool_szarr, pool_maxarr, npoolarr, true);
		}

		epollfd = epoll_create1(EPOLL_CLOEXEC);
		if (epollfd == -1) {
			PERRORPRINTCOLOR(GY_COLOR_RED, "Failed to create client epoll socket");
			return nullptr;
		}
	
		pevarr 		= new epoll_event[max_events];
		pevcache	= new epoll_event[max_events];	

		GY_SCOPE_EXIT {
			delete [] pevcache;
			delete [] pevarr;
		};	

		auto comp_epoll = [](const epoll_event & ev1, const epoll_event & ev2) noexcept -> bool
		{
			return (uint8_t *)ev2.data.ptr < (uint8_t *)ev1.data.ptr;
		};	

		auto do_connect = [&]()
		{
			int				ret, revents;
			ssize_t				sret;
			uint64_t			start_clock_usec, start_seqid;
			char				ebuf[128];
			struct sockaddr_storage		sockaddr;
			socklen_t			socklen;	
			char				printbuf[512];
			STR_WR_BUF			strbuf(printbuf, sizeof(printbuf));
			
			auto [ sock, success ] = gy_tcp_connect(phost, port1, ebuf, "Server", true, false, &sockaddr, &socklen);
			if (sock > 0) {

				GY_SCOPE_EXIT {
					if (sock > 0) {
						::close(sock);
					}	
				};

				struct sockaddr_storage		csockaddr;
				socklen_t			clen = sizeof(csockaddr);
				IP_PORT				sipport((struct sockaddr *)&sockaddr, socklen);

				start_clock_usec 	= get_usec_clock();
				start_seqid		= start_clock_usec & 0xFFFF;

				ret = ::getsockname(sock, (struct sockaddr *)&csockaddr, &clen);

				if (ret == 0) {
					try {
						IP_PORT		cipport((struct sockaddr *)&csockaddr, clen);
						
						strbuf.appendconst("TCP Client ");
						cipport.print_string(strbuf);
						strbuf.appendconst(" : Server ");
						sipport.print_string(strbuf);
					}
					catch(...) {
					}	
				}


				statsmap["Server Connects"]++;

				/*
				 * Now send registration and wait for response
				 */
				static constexpr size_t 	fixed_sz = sizeof(TEST_HEADER1) + sizeof(TEST_REGISTER); 
				static constexpr size_t 	fixed_sz_resp = sizeof(TEST_HEADER1) + sizeof(TEST_RESPONSE); 

				alignas (8) uint8_t		regreq[std::max(fixed_sz, fixed_sz_resp)];

				new (regreq) TEST_HEADER1(TYPE_REGISTER, sizeof(TEST_REGISTER));
				
				new (regreq + sizeof(TEST_HEADER1)) TEST_REGISTER(start_seqid, 1, 1, "Mach 1", "testdomain", "aaa");

				sret = gy_writebuffer(sock, regreq, fixed_sz);
				if (sret < 0) {
					PERRORPRINTCOLOR(GY_COLOR_RED, "Registration request send failed for %s", printbuf);
					
					statsmap["Register Errors"]++;
					return false;
				}

				// Now wait for response OK max upto 10 sec
				ret = poll_socket(sock, 10 * 1000, revents, POLLIN, true);
				if (ret <= 0) {
					if (ret == 0) {
						ERRORPRINTCOLOR(GY_COLOR_RED, "Registration request failed as server read timed out for connection for %s\n", printbuf);
					}
					else {
						PERRORPRINTCOLOR(GY_COLOR_RED, "Registration request failed as server closed connection for %s", printbuf);
					}	
					statsmap["Register Errors"]++;
					return false;
				}

				sret = gy_recvbuffer(sock, regreq, fixed_sz_resp, 0, true /* no_block_after_first_recv */);
				if (sret < 0) {
					PERRORPRINTCOLOR(GY_COLOR_RED, "Registration request failed  as server read failed for connection for %s", printbuf);
					statsmap["Register Errors"]++;
					return false;
				}

				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Registration succeeded for client %s\n", printbuf);

				set_sock_nonblocking(sock);

				struct epoll_event	ev;

				auto [it, success] = conntrack.try_emplace(sock, sipport, sock, epollfd, nullptr, 0, 0, 8, 0, 60 * GY_USEC_PER_SEC, false, start_clock_usec);
				if (success) {
					TCLI_CONNTRACK		*pnewconn = &it->second;

					pnewconn->set_epoll_data(pnewconn);

					ev.data.ptr	= pnewconn;
					ev.events 	= EPOLLIN | EPOLLOUT | EPOLLET;

					ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, sock, &ev);

					sock = -1;

					if (ret != 0) {
						PERRORPRINTCOLOR(GY_COLOR_RED, "Client conn epoll add failed");
						conntrack.erase(it);

						return false;
					}	

					pnewconn->start_seqid_ = start_seqid;
					GY_STRNCPY(pnewconn->printbuf_, printbuf, sizeof(pnewconn->printbuf_));

					return true;
				}

				return false;
			}	

			ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to connect to server : %s\n", ebuf);

			statsmap["Connect Failed"]++;
			return false;
		};	
		
		for (uint32_t i = 0; i < conns_per_thr; ++i) {
			do_connect();
		}

		auto fill_sample_task = [&](uint8_t *pdata, size_t maxsz) -> size_t
		{
			size_t			tsz = sizeof(TEST_TASK) + 500 + 500;

			assert(maxsz > sizeof(TEST_HEADER1) + tsz + 7);
				
			TEST_HEADER1		*phdr 	= reinterpret_cast<TEST_HEADER1 *>(pdata);
			TEST_TASK		*ptask 	= reinterpret_cast<TEST_TASK *>((uint8_t *)phdr + sizeof(TEST_HEADER1));

			ptask->start_time_usec_	= get_usec_time();
			ptask->ppid_		= ptask->start_time_usec_ & 0xFFFF;
			ptask->pid_		= ptask->ppid_ + 1;

			snprintf(ptask->comm_, sizeof(ptask->comm_), "testproc%d", ptask->pid_);	
			
			ptask->exepath_len_	= 500;
			ptask->ext_data_sz_	= 500;

			std::memset((uint8_t *)ptask + sizeof(*ptask), 'C', 500);
			std::memset((uint8_t *)ptask + sizeof(*ptask) + 500, 'A', 500);

			new (phdr) TEST_HEADER1(TYPE_TASK, tsz);

			statsmap["Task Msg"]++;

			if (true == phdr->validate(pdata)) {
				return phdr->data_sz_;
			}	

			return 0;
		};	

		auto fill_sample_tcp_conn = [&](uint8_t *pdata, size_t maxsz) -> size_t
		{
			size_t			tsz = sizeof(TEST_TCP_CONN) + 250;

			assert(maxsz > sizeof(TEST_HEADER1) + tsz + 7);
				
			TEST_HEADER1		*phdr 	= reinterpret_cast<TEST_HEADER1 *>(pdata);
			TEST_TCP_CONN		*ptcp 	= reinterpret_cast<TEST_TCP_CONN *>((uint8_t *)phdr + sizeof(TEST_HEADER1));

			new (&ptcp->cli_) IP_PORT("192.168.0.1", 36211);
			new (&ptcp->ser_) IP_PORT("192.168.0.2", 3000);

			ptcp->cli_pid_			= 2122;
			ptcp->start_time_usec_		= get_usec_time();
			ptcp->server_domain_len_	= 250;

			std::memset((uint8_t *)ptcp + sizeof(*ptcp), 'D', 250);

			new (phdr) TEST_HEADER1(TYPE_TCP_CONN, tsz);

			statsmap["TCP Conn Msg"]++;

			if (true == phdr->validate(pdata)) {
				return phdr->data_sz_;
			}	

			return 0;
		};	

		auto fill_sample_listener_req = [&](uint8_t *pdata, size_t maxsz, TCLI_CONNTRACK *pconn1, uint64_t & seqid) -> size_t
		{
			size_t			tsz = sizeof(TEST_QUERY) + sizeof(TEST_LISTENER_REQ); 

			assert(maxsz > sizeof(TEST_HEADER1) + tsz + 7);
				
			TEST_HEADER1		*phdr 		= reinterpret_cast<TEST_HEADER1 *>(pdata);
			TEST_QUERY		*pquery 	= reinterpret_cast<TEST_QUERY *>((uint8_t *)phdr + sizeof(TEST_HEADER1));
			TEST_LISTENER_REQ	*plist		= reinterpret_cast<TEST_LISTENER_REQ *>((uint8_t *)pquery + sizeof(TEST_QUERY));

			pquery->seqid_		= pconn1->get_next_seqid();
			pquery->subtype_	= SUBTYPE_LISTENER_REQ;
			pquery->timeoutusec_	= get_usec_time() + 60 * GY_USEC_PER_SEC;

			seqid			= pquery->seqid_;

			new (&plist->ip_port_) IP_PORT("192.168.0.2", 3000);
			plist->ndays_history_	= 5;

			new (phdr) TEST_HEADER1(TYPE_QUERY, tsz);

			statsmap["Listener Req"]++;

			if (true == phdr->validate(pdata)) {
				return phdr->data_sz_;
			}	

			return 0;
		};	

		auto fill_sample_time_req = [&](uint8_t *pdata, size_t maxsz, TCLI_CONNTRACK *pconn1, uint64_t & seqid) -> size_t
		{
			size_t			tsz = sizeof(TEST_QUERY) + sizeof(TEST_REQUEST_CURR_TIME); 

			assert(maxsz > sizeof(TEST_HEADER1) + tsz + 7);
				
			TEST_HEADER1		*phdr 		= reinterpret_cast<TEST_HEADER1 *>(pdata);
			TEST_QUERY		*pquery 	= reinterpret_cast<TEST_QUERY *>((uint8_t *)phdr + sizeof(TEST_HEADER1));
			TEST_REQUEST_CURR_TIME	*ptime		= reinterpret_cast<TEST_REQUEST_CURR_TIME *>((uint8_t *)pquery + sizeof(TEST_QUERY));

			pquery->seqid_		= pconn1->get_next_seqid();
			pquery->subtype_	= SUBTYPE_REQUEST_CURR_TIME;
			pquery->timeoutusec_	= get_usec_time() + 60 * GY_USEC_PER_SEC;

			seqid			= pquery->seqid_;

			ptime->curr_usec_clock_	= get_usec_clock();
			ptime->curr_usec_time_	= get_usec_time();

			new (phdr) TEST_HEADER1(TYPE_QUERY, tsz);

			statsmap["Time Req"]++;

			if (true == phdr->validate(pdata)) {
				return phdr->data_sz_;
			}	

			return 0;
		};	

		auto fill_sample_read_file = [&](uint8_t *pdata, size_t maxsz, TCLI_CONNTRACK *pconn1, uint64_t & seqid) -> size_t
		{
			static constexpr const char 	*tfilenamearr[5] = {"/tmp/test1.dat.1111__", "/invalid/aa", "/tmp/test1.dat.2222__", "/proc/sched_debug", "/proc/mounts"};
			static constexpr const off_t	tfileoffarr[5] 	=  {10, 111, 2, 0, 0};

			size_t				tsz = sizeof(TEST_QUERY) + sizeof(TEST_REQUEST_READ_FILE); 

			assert(maxsz > sizeof(TEST_HEADER1) + tsz + 7);
				
			TEST_HEADER1		*phdr 		= reinterpret_cast<TEST_HEADER1 *>(pdata);
			TEST_QUERY		*pquery 	= reinterpret_cast<TEST_QUERY *>((uint8_t *)phdr + sizeof(TEST_HEADER1));
			TEST_REQUEST_READ_FILE	*pfile		= reinterpret_cast<TEST_REQUEST_READ_FILE *>((uint8_t *)pquery + sizeof(TEST_QUERY));

			pquery->seqid_		= pconn1->get_next_seqid();
			pquery->subtype_	= SUBTYPE_REQUEST_READ_FILE;
			pquery->timeoutusec_	= get_usec_time() + 60 * GY_USEC_PER_SEC;

			seqid			= pquery->seqid_;

			size_t			nid = (seqid >> 1) % GY_ARRAY_SIZE(tfilenamearr);
			
			pfile->offset_		= tfileoffarr[nid];
			pfile->nbytes_		= 32 * 1024;
			pfile->trequsec_	= get_usec_time();
			GY_STRNCPY(pfile->pathname_, tfilenamearr[nid], sizeof(pfile->pathname_));
			
			new (phdr) TEST_HEADER1(TYPE_QUERY, tsz);

			statsmap["File Read Req"]++;

			if (true == phdr->validate(pdata)) {
				return phdr->data_sz_;
			}	

			return 0;
		};	

		auto handle_send = [](TCLI_CONNTRACK *pconn1) -> ssize_t
		{
			bool			is_closed = false, is_blocked = false;
			ssize_t			sret;

			auto wr_cb = [](EPOLL_CONNTRACK * ptconn, ssize_t total_bytes) noexcept
			{};	
			
			auto again_cb = [](EPOLL_CONNTRACK * ptconn, ssize_t total_bytes) noexcept
			{
				ptconn->wrstat_.pending_clock_usec_ 	= get_usec_clock();
				ptconn->wrstat_.pending_sz_		= total_bytes;
			};	

			auto close_cb = [&](EPOLL_CONNTRACK *ptconn, int tsock) noexcept
			{
				is_closed = true;
			};

			if (pconn1->send_data_pending()) {
				sret = pconn1->send_data(wr_cb, again_cb, close_cb, is_blocked);

				if (is_closed) {
					GY_THROW_EXCEPTION("Failed to send message");
				}	

				return sret;
			}
			else {
				return 0;
			}	
		};

		auto handle_recv = [&](TCLI_CONNTRACK *pconn1, int sock, const bool is_conn_closed, const bool peer_wr_closed) -> ssize_t
		{
			ssize_t				sret, max_bytes, totbytes = 0;
			ssize_t				max_buf_sz, data_sz;
			uint8_t				*prdbuf;
			int				nsyscall = 0, ret;
			bool				is_again = false, bret, bsent;
			auto				&rdstat_ = pconn1->rdstat_;
			TEST_HEADER1			hdr(TYPE_MIN_TYPE, 0);

			auto call_recv_cb = [&](TCLI_CONNTRACK *pconn1, uint8_t *pdata, size_t szdata, TEST_HEADER1 *phdr, TEST_RESPONSE * presp) 
			{
				ssize_t			sret;

				sret = pconn1->get_recv_cb_by_seqid(presp->seqid_);
				if (sret == -1) {
					return;
				}	

				statsmap["Recv CBs"]++;

				GY_SCOPE_EXIT {
					pconn1->reset_recv_cb(sret);
				};

				pconn1->get_recv_cb(sret).fcb_(pconn1, pdata, szdata, phdr, presp);
			};


			auto set_variables = [&]() 
			{
				max_buf_sz 	= rdstat_.max_buf_sz_;
				data_sz		= rdstat_.data_sz_;
				prdbuf		= rdstat_.pdirbuf_;
			};

			if (!rdstat_.pdirbuf_) {
				FREE_FPTR		free_fp;
				uint32_t		act_size;
				void			*palloc = poolarr.safe_malloc(4096, free_fp, act_size);

				rdstat_.set_buf((uint8_t *)palloc, free_fp, act_size, 0);
			}	
			
			do {
				set_variables();

				max_bytes = max_buf_sz - data_sz;

				if (gy_unlikely(max_bytes <= 0)) {
					statsmap["Internal Error"]++;
					GY_THROW_EXCEPTION("Internal Error : max_bytes <= 0");
				}	

				sret = ::recv(sock, prdbuf + data_sz, max_bytes, 0);

				if (sret == -1) {
					if (errno == EINTR) {
						continue;
					}
					else if (errno == EAGAIN) {
						break;
					}	
					else {
						statsmap["Recv Failed"]++;
						return -1;
					}
				}
				else if (sret == 0) {
					return -1;
				}	

				is_again 			= (sret < max_bytes);

				nsyscall++;

				rdstat_.last_oper_cusec_ 	= get_usec_clock();
				rdstat_.nbytes_seen_ 		+= sret;
				rdstat_.data_sz_		+= sret;
			
				totbytes			+= sret;	
				data_sz				+= sret;

				do {
					if (data_sz >= (ssize_t)sizeof(TEST_HEADER1)) {
						std::memcpy(&hdr, prdbuf, sizeof(hdr));

						if (false == hdr.validate(prdbuf)) {
							statsmap["Invalid Response"]++;
							GY_THROW_EXCEPTION("Invalid Message received. Closing connection");
						}	
					}
					else {
						hdr.data_sz_	= sizeof(TEST_HEADER1);
					}

					if (max_buf_sz < (ssize_t)hdr.data_sz_) {

						FREE_FPTR		free_fp;
						uint32_t		act_size;
						uint8_t			*palloc = (uint8_t *)poolarr.safe_malloc(std::max(4096u, hdr.data_sz_), free_fp, act_size);

						std::memcpy(palloc, prdbuf, data_sz);

						rdstat_.reset_buf(true);

						rdstat_.set_buf(palloc, free_fp, act_size, data_sz);
						
						set_variables();
					}
			
					if (data_sz < hdr.data_sz_) {
						if (data_sz != rdstat_.data_sz_) {
							// This implies we just need to move data to the start

							std::memmove(rdstat_.pdirbuf_, prdbuf, data_sz);
							rdstat_.data_sz_	= data_sz;

							set_variables();
						}	
						break;
					}

					if (data_sz < hdr.data_sz_) {
						break;
					}

					rdstat_.nrequests_++;

					switch (hdr.data_type_) {
				
					case TYPE_RESPONSE :

						if (true) {
							statsmap["Response Msg"]++;

							TEST_RESPONSE		*presp = (TEST_RESPONSE *)(prdbuf + sizeof(TEST_HEADER1));
							
							if (false == TEST_RESPONSE::validate(&hdr)) {
								statsmap["Invalid Response"]++;
								GY_THROW_EXCEPTION("Invalid Message received. Closing connection");
							}	

							call_recv_cb(pconn1, prdbuf, hdr.data_sz_, &hdr, presp);
						}
						break;


					default :
						statsmap["Invalid Response"]++;
						GY_THROW_EXCEPTION("Invalid Message received. Closing connection");
					}

					data_sz 	-= hdr.data_sz_;
					max_buf_sz	-= hdr.data_sz_;
					prdbuf 		+= hdr.data_sz_;

					if (gy_unlikely(data_sz < 0 || max_buf_sz < data_sz)) {
						statsmap["Internal Error"]++;
						GY_THROW_EXCEPTION("Internal Error : stats invalid");
					}

					if ((data_sz != rdstat_.data_sz_) && (max_buf_sz - data_sz < (ssize_t)sizeof(TEST_HEADER1))) {

						std::memmove(rdstat_.pdirbuf_, prdbuf, data_sz);
						rdstat_.data_sz_	= data_sz;

						set_variables();
					}	

				} while (data_sz > 0);

			} while (is_again == false);

			if (data_sz == 0) {
				rdstat_.reset_buf(true);	// Free up the buffer
			}	
			else if (totbytes > 0) {
				// Set rdstat_.pending_sz_ for timeout handling
				rdstat_.pending_sz_		= hdr.data_sz_ - data_sz;
				rdstat_.pending_clock_usec_	= rdstat_.last_oper_cusec_;
			}	

			return totbytes;
		};

		uint64_t		curr_usec_clock	= get_usec_clock(), last_usec_clock = curr_usec_clock;

		do {
			if (gy_unlikely(0 == conntrack.size())) {
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "All connections handled by thread %d exited. Thread returning back\n", tid);
				return nullptr;
			}	

			for (auto cit = conntrack.begin(); cit != conntrack.end(); ) {
				auto pconn = &cit->second;
	
				try {

					if (true == pconn->sends_possible()) {

						FREE_FPTR		free_fp;
						uint32_t		act_size;
						void			*palloc = poolarr.safe_malloc(4096, free_fp, act_size);
						size_t			nbytes;

						nbytes = fill_sample_task((uint8_t *)palloc, act_size);
						if (nbytes > 0) {
							pconn->schedule_ext_send(EPOLL_IOVEC_ARR(palloc, nbytes, free_fp));
						}	
						else {
							(*free_fp)(palloc);
						}	
					}

					if (true == pconn->sends_possible()) {

						FREE_FPTR		free_fp;
						uint32_t		act_size;
						void			*palloc = poolarr.safe_malloc(512, free_fp, act_size);
						size_t			nbytes;

						nbytes = fill_sample_tcp_conn((uint8_t *)palloc, act_size);
						if (nbytes > 0) {
							pconn->schedule_ext_send(EPOLL_IOVEC_ARR(palloc, nbytes, free_fp));
						}
						else {
							(*free_fp)(palloc);
						}	
					}

					if (ssize_t rcbid = pconn->avail_recv_cb_id(); (rcbid >= 0 && true == pconn->sends_possible()))  {

						FREE_FPTR		free_fp;
						uint32_t		act_size;
						void			*palloc = poolarr.safe_malloc(4096, free_fp, act_size);
						size_t			nbytes;
						uint64_t		seqid;

						nbytes = fill_sample_listener_req((uint8_t *)palloc, act_size, pconn, seqid);
						if (nbytes > 0) {
							pconn->schedule_ext_send(EPOLL_IOVEC_ARR(palloc, nbytes, free_fp));

							auto rcvl = [seqid](TCLI_CONNTRACK *pconn1, uint8_t *pdata, size_t szdata, TEST_HEADER1 *phdr, TEST_RESPONSE * presp)
							{
								if (presp->respcode_ != TERR_SUCCESS) {
									// Handle Error
									return;
								}
								if (presp->subtype_ != SUBTYPE_LISTENER_RESP) {
									// Handle Error
									return;
								}	
								if (presp->seqid_ != seqid) {
									// Handle Error
									return;
								}	

								TEST_LISTENER_RESP	*plistresp = reinterpret_cast<TEST_LISTENER_RESP *>(presp + 1);
								
								if (false == TEST_LISTENER_RESP::validate(phdr, plistresp)) {
									// Handle Error
									return;
								}	
								// Do something
							};	

							auto & recvcb 	= pconn->get_recv_cb(rcbid);

							recvcb.fcb_ 	= std::move(rcvl);
							recvcb.seqid_	= seqid;
						}
						else {
							(*free_fp)(palloc);
						}	
					}

					if (ssize_t rcbid = pconn->avail_recv_cb_id(); (rcbid >= 0 && true == pconn->sends_possible()))  {

						FREE_FPTR		free_fp;
						uint32_t		act_size;
						void			*palloc = poolarr.safe_malloc(256, free_fp, act_size);
						size_t			nbytes;
						uint64_t		seqid;

						nbytes = fill_sample_time_req((uint8_t *)palloc, act_size, pconn, seqid);
						if (nbytes > 0) {
							pconn->schedule_ext_send(EPOLL_IOVEC_ARR(palloc, nbytes, free_fp));

							auto rcvl = [seqid](TCLI_CONNTRACK *pconn1, uint8_t *pdata, size_t szdata, TEST_HEADER1 *phdr, TEST_RESPONSE * presp)
							{
								if (presp->respcode_ != TERR_SUCCESS) {
									// Handle Error
									return;
								}
								if (presp->subtype_ != SUBTYPE_RESPONSE_CURR_TIME) {
									// Handle Error
									return;
								}	
								if (presp->seqid_ != seqid) {
									// Handle Error
									return;
								}	

								TEST_RESPONSE_CURR_TIME	*ptimeresp = reinterpret_cast<TEST_RESPONSE_CURR_TIME *>(presp + 1);
								
								if (false == TEST_RESPONSE_CURR_TIME::validate(phdr)) {
									// Handle Error
									return;
								}	
								// Do something
							};	

							auto & recvcb 	= pconn->get_recv_cb(rcbid);

							recvcb.fcb_ 	= std::move(rcvl);
							recvcb.seqid_	= seqid;
						}
						else {
							(*free_fp)(palloc);
						}	
					}

					if (ssize_t rcbid = pconn->avail_recv_cb_id(); (rcbid >= 0 && true == pconn->sends_possible()))  {

						FREE_FPTR		free_fp;
						uint32_t		act_size;
						void			*palloc = poolarr.safe_malloc(4096, free_fp, act_size);
						size_t			nbytes;
						uint64_t		seqid;

						nbytes = fill_sample_read_file((uint8_t *)palloc, act_size, pconn, seqid);
						if (nbytes > 0) {
							pconn->schedule_ext_send(EPOLL_IOVEC_ARR(palloc, nbytes, free_fp));

							auto rcvl = [seqid](TCLI_CONNTRACK *pconn1, uint8_t *pdata, size_t szdata, TEST_HEADER1 *phdr, TEST_RESPONSE * presp)
							{
								if (presp->respcode_ != TERR_SUCCESS) {
									// Handle Error
									return;
								}
								if (presp->subtype_ != SUBTYPE_RESPONSE_READ_FILE) {
									// Handle Error
									return;
								}	
								if (presp->seqid_ != seqid) {
									// Handle Error
									return;
								}	

								TEST_RESPONSE_READ_FILE	*pfileresp = reinterpret_cast<TEST_RESPONSE_READ_FILE *>(presp + 1);
								
								if (false == TEST_RESPONSE_READ_FILE::validate(phdr, pfileresp)) {
									// Handle Error
									return;
								}	
								// Do something
							};	

							auto & recvcb 	= pconn->get_recv_cb(rcbid);

							recvcb.fcb_ 	= std::move(rcvl);
							recvcb.seqid_	= seqid;
						}
						else {
							(*free_fp)(palloc);
						}	
					}

					handle_send(pconn);

					++cit;
				}
				GY_CATCH_EXCEPTION(
					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Caught exception while handling client conn : Closing conn %s : %s\n", pconn->printbuf_, GY_GET_EXCEPT_STRING);

					statsmap["Conn Exception"]++;
					cit = conntrack.erase(cit);
				);
			}

			if (gy_unlikely(0 == conntrack.size())) {
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "All connections handled by thread %d exited. Thread returning back\n", tid);
				return nullptr;
			}	

			try {
				int			nevents, nretry_events = 0;
				size_t			nfind;
				bool			bret;

				nevents = epoll_wait(epollfd, pevarr, max_events, 100 /* 100 msec wait */);
				
				if (nevents == -1) {
					if (errno == EINTR) {
						continue;
					}	
					PERRORPRINTCOLOR(GY_COLOR_RED, "poll on client thread %d failed : Returning...", tid);
					return nullptr;
				}	
				else if (nevents == 0) {
					goto next1;
				}	

				std::memcpy(pevcache, pevarr, nevents * sizeof(epoll_event));

				std::stable_sort(pevcache,  pevcache + nevents, comp_epoll);

				for (int i = 0; i < nevents; ++i) {
					auto 			pcache = pevcache + i;
					void			*pepdata = pcache->data.ptr;
					uint32_t		cevents = 0;

					cevents = pcache->events;

					while (i + 1 < nevents) {
						if (pevcache[i + 1].data.ptr == pepdata) {
							cevents |= pevcache[i + 1].events;
							++i;
						}	
						else {
							break;
						}	
					}	

					TCLI_CONNTRACK 			*pconn = (TCLI_CONNTRACK *)pepdata;
					
					const int cfd = pconn->get_sockfd();

					try {
						const bool		conn_closed = (cevents & (EPOLLERR | EPOLLHUP));
						const bool		peer_wr_closed = (conn_closed || (cevents & EPOLLRDHUP));
						ssize_t			sret = 0;

						if (cevents & EPOLLIN) {
							sret = handle_recv(pconn, cfd, conn_closed, peer_wr_closed);

							if (sret == -1) {
								conntrack.erase(cfd);
								continue;
							}	
						}	
						
						if (cevents & EPOLLOUT) {
							if (false == conn_closed) {
								sret = handle_send(pconn);
							}	
						}	

						if (sret == -1 || conn_closed) {
							conntrack.erase(cfd);
							continue;
						}	
					}
					GY_CATCH_EXCEPTION(
						INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Caught exception while handling client conn : %s\n", GY_GET_EXCEPT_STRING);

						statsmap["Conn Exception"]++;
						conntrack.erase(cfd);
						continue;
					);
				}	

next1 :
				curr_usec_clock = get_usec_clock();

				if (curr_usec_clock - last_usec_clock > 60 * GY_USEC_PER_SEC) {
					last_usec_clock = curr_usec_clock;

					STRING_BUFFER<1024>	strbuf;

					for (auto && it : statsmap) {
						strbuf.appendfmt(" {\"%s\" : %ld},", it.first, it.second);
					}	
					strbuf.set_last_char(' ');

					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_MAGENTA, "Client Thread TID %d : Connections %lu : Stats : %s\n", 
						tid, conntrack.size(), strbuf.buffer());

				}
			}
			GY_CATCH_EXCEPTION(
				ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught in client thread %d : %s\n", tid, GY_GET_EXCEPT_STRING);
			);

		} while (true);

		return nullptr;

	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught in client handling thread : %s\n", GY_GET_EXCEPT_STRING);
		return nullptr;
	);
}	

void spawn_test_clients(int nparallel, const char *phost, uint16_t port1)
{
	std::vector<GY_THREAD>		clithrvec;
	int				nthreads, conns_per_thr;
	char				desc[64];

	nthreads = std::min(nparallel, 10);
	
	conns_per_thr = nparallel/nthreads;
	
	for (int i = 0; i < nthreads; ++i) {
		uint64_t		targ1 = ((uint64_t)conns_per_thr << 16) | port1;

		snprintf(desc, sizeof(desc), "Cli Thread %d", i);

		clithrvec.emplace_back(desc, cli_thread, nullptr, (void *)phost, (void *)(uintptr_t)targ1);
	}	

	gy_msecsleep(1000);

	// Now wait for threads indefinitely
}

int start_listen(const char * listen_host, uint16_t lport)
{
	try {
		gdebugexecn = 10;

		GY_SIGNAL_HANDLER::init_singleton("test_listener");

		PRINT_OFFLOAD::init_singleton();

		PROC_CPU_IO_STATS::init_singleton(120);

		setsid();

		MULTI_COMM_SINGLETON::init_singleton();

		TLISTEN_HDLR		*phdlr = new TLISTEN_HDLR(listen_host, lport);
	
		return 0;
	}	
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to construct Listener object : %s\n\n", GY_GET_EXCEPT_STRING);
		return -1;
	);
}	

void usage(int argc, char *argv[])
{
	IRPRINT("\nUsage %s <Listen IP/Hostname> <Listen Port> <# Parallel Client connections in 10 mutiples>\n\ne.g. %s 0.0.0.0 1234 1000\n\n", argv[0], argv[0]);
	IRPRINT("\nUsage to spawn only Test Clients to remote server : %s :: 0 <# Test Client connections> <Remote Server IP/Hostname> <Remote Port>\n\ne.g. %s :: 0 1000 192.168.0.120 1234\n\n",
		argv[0], argv[0]);
	exit(EXIT_FAILURE);
}	

int main(int argc, char *argv[])
{
	int			ret, nspawncli;
	uint16_t		port1;
	bool			no_listen = false, bret;

	if (argc < 4) {
		usage(argc, argv);
	}	

	bret = string_to_number(argv[2], port1);
	if (!bret) {
		usage(argc, argv);
	}	
	else if (port1 == 0) {
		if (argc < 6) {
			usage(argc, argv);
		}	

		no_listen = true;

		bret = string_to_number(argv[5], port1);
		if (!bret) {
			usage(argc, argv);
		}	

		INFOPRINTCOLOR(GY_COLOR_YELLOW, "No Local Listeners specified. Will spawn %s parallel client connections to remote %s %hu server\n\n",
			argv[3], argv[4], port1);
	}	
	
	nspawncli = atoi(argv[3]);
	
	if (no_listen == false) {
		start_listen(argv[1], port1);
	}

	if (nspawncli > 0) {
		spawn_test_clients(nspawncli, no_listen == false ? argv[1] : argv[4], port1);
	}

	do {
		pause();
	} while (true);	

	return EXIT_SUCCESS;
}	

