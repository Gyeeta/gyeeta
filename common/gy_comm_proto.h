//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"
#include			"gy_sys_hardware.h"
#include			"gy_statistics.h"
#include			"gy_inet_inc.h"
#include			"gy_json_field_maps.h"
#include			"gy_proto_common.h"

namespace gyeeta {
namespace comm {

static constexpr uint32_t 		COMM_VERSION_NUM		{1};
static constexpr uint32_t 		MIN_COMM_VERSION_NUM		{1};
static constexpr size_t			MAX_TOTAL_TAG_LEN		{1024};
static constexpr size_t			ACCESS_KEY_LEN			{64};
static constexpr size_t			MAX_ZONE_LEN			{64};
static constexpr size_t			COMM_MAX_ERROR_LEN		{256};
static constexpr size_t			MAX_PROC_CMDLINE_LEN 		{256}; 	
static constexpr size_t			MAX_CLUSTER_NAME_LEN 		{64}; 	
static constexpr size_t			MAX_INSTANCE_ID_LEN		{128};

/*
 * The max network payload size is 16 MB for all messages except for JSON Query Responses which are limited to 4 GB
 * The JSON Responses are sent in batches with each batch size limited to max 16 MB.
 */

static constexpr uint32_t		MAX_COMM_DATA_SZ 		{GY_UP_MB(16)};		// For each individual Message
static constexpr uint64_t		MAX_COMM_JSON_DATA_SZ 		{GY_UP_GB(4)};		// Will span multiple response messages
static constexpr uint64_t		MAX_JSON_RECORDS		{10'000'000};		// Max Records that can fetched per query	

static constexpr size_t			MAX_MADHAVA_PER_SHYAMA		{1024};
static constexpr size_t			MAX_PARTHA_PER_MADHAVA		{512};


/*
 * Communication Protocol for interaction between Partha nodes, Shyama and Madhava servers and 
 * Node Web servers when Node is the client.
 *
 * All communication is in Little Endian byte order. Each message is preceeded by COMM_HEADER specifying 
 * the type and len of the msg.
 * 
 * Connections to Shyama and Madhava may be persistent or adhoc (only 1 req/response pair).
 * 
 * All connections to Shyama and Madhava from Madhava are persistent connections.
 * All connections to Madhava from Partha are persistent connections.
 * All connections to Shyama from Partha are adhoc.
 * Connections to Shyama and Madhava from Node Web servers are usually persistent but adhoc conns also allowed
 * 
 * Request / Response Multiplexing is supported with upto 4K outstanding responses (for persistent conns : this is variable).
 * 
 * Shyama and Madhava servers will support upto 2 previous Partha versions. Currently, Shyama and Madhava servers need to be on
 * the same version. Older version connections within the Shyama and Madhava servers will be rejected.
 *
 * All string length fields include the '\0' character i.e. length = strlen + 1
 *
 * XXX Please ensure any changes related to underlying protocol for Node to other hosts is in sync with Node gyeeta_comm.js file.
 */

enum HOST_TYPES_E : int8_t
{
	HOST_INVALID 		= 0,

	HOST_PARTHA		= 1,
	HOST_MADHAVA		= 2,
	HOST_SHYAMA		= 3,
	HOST_NODE_WEB		= 4,

	HOST_MAX_TYPE,
};

static constexpr const char * host_type_string(HOST_TYPES_E type) noexcept
{
	switch (type) {
	
	case HOST_PARTHA	: return "Partha";
	case HOST_MADHAVA	: return "Madhava";
	case HOST_SHYAMA	: return "Shyama";
	case HOST_NODE_WEB	: return "Node Web Server";

	default			: return "Unknown Host Type";
	}	
}	

/*
 * Client Connection Types
 */
enum CLI_TYPE_E : uint32_t
{
	CLI_TYPE_REQ_RESP		= 0,	// Normal Connection with Req/Resp only in the direction of the socket
	CLI_TYPE_REQ_ONLY		= 1,	// Only used for Incoming Event Notification; No Responses expected on this conn
	CLI_TYPE_RESP_ONLY		= 2,	// Only used for Outgoing Event Notification; No Requests expected on this conn
	CLI_TYPE_RESP_REQ		= 3,	// Reverse Connection to be used by Server for Requests with Client sending Responses

	CLI_TYPE_MAX
};

static constexpr const char * cli_type_string(CLI_TYPE_E type) noexcept
{
	switch (type) {
	
	case CLI_TYPE_REQ_RESP		: return "Incoming Request/Response";
	case CLI_TYPE_REQ_ONLY		: return "Incoming Event Notification";
	case CLI_TYPE_RESP_ONLY		: return "Outgoing Event Notification";
	case CLI_TYPE_RESP_REQ		: return "Outgoing Request/Response";
	
	default				: return "Unknown Client Type";
	}	
}	

/*
 * Main Message Types :
 * 
 * 3 Main Types of Messages : Event Notifications, Queries and their Responses.
 * Types from PS_REGISTER_REQ to NM_CONNECT_RESP are only used during init registration phase.
 *
 * COMM_EVENT_NOTIFY is used for Streaming Events or Async Queries where immediate Response not expected.
 * COMM_QUERY_CMD used where immediate Response expected and Async Callbacks are used to handle corresponding Response
 * COMM_QUERY_RESP is the Response sent for a prior COMM_QUERY_CMD
 */
enum COMM_TYPE_E : uint32_t
{
	COMM_INVALID_TYPE		= 0,

	COMM_MIN_TYPE			= 1,

	PS_REGISTER_REQ			= 2,		// partha to shyama
	PM_CONNECT_CMD			= 3,		// partha to madhava
	MS_REGISTER_REQ			= 4,		// madhava to shyama
	MM_CONNECT_CMD			= 5,		// madhava to madhava
	NS_REGISTER_REQ			= 6,		// node web server to shyama
	NM_CONNECT_CMD			= 7,		// node web server to madhava

	PS_REGISTER_RESP		= 8,		
	PM_CONNECT_RESP			= 9,		
	MS_REGISTER_RESP		= 10,		
	MM_CONNECT_RESP			= 11,		
	NS_REGISTER_RESP		= 12,		
	NM_CONNECT_RESP			= 13,		

	COMM_EVENT_NOTIFY		= 14,		// Streaming Events. No immediate Response expected

	COMM_QUERY_CMD			= 15,		
	COMM_QUERY_RESP			= 16,

	NS_ALERT_REGISTER		= 17,

	COMM_MAX_TYPE,
};	

// Event Notify types
enum NOTIFY_TYPE_E : uint32_t
{
	NOTIFY_MIN_TYPE			= 0x100,

	NOTIFY_PARTHA_STATUS		= 0x101,				
	NOTIFY_MADHAVA_PARTHA_STATUS,		
	NOTIFY_MADHAVA_SHYAMA_STATUS,
	NOTIFY_SHYAMA_MADHAVA_STATUS,		
	NOTIFY_MADHAVA_MADHAVA_STATUS,
	NOTIFY_MADHAVA_LIST,			


	NOTIFY_TASK_MINI_ADD		= 0x301,
	NOTIFY_TASK_FULL_ADD,
	NOTIFY_TASK_TOP_PROCS,
	NOTIFY_TASK_HISTOGRAM,
	NOTIFY_TASK_AGGR,
	NOTIFY_PING_TASK_AGGR,
	NOTIFY_NEW_LISTENER,
	NOTIFY_LISTENER_DAY_STATS,
	NOTIFY_LISTENER_STATE,
	NOTIFY_LISTENER_DEPENDENCY,
	NOTIFY_LISTENER_NAT_IP_EVENT,
	NOTIFY_TCP_CONN,
	NOTIFY_NAT_TCP,
	NOTIFY_MP_CLI_TCP_INFO,
	NOTIFY_CPU_MEM_STATE,
	NOTIFY_AGGR_TASK_STATE,
	NOTIFY_HOST_STATE__V000100,		// v0.1.0 
	NOTIFY_ACTIVE_CONN_STATS,
	NOTIFY_LISTENER_DOMAIN_EVENT,
	NOTIFY_LISTEN_TASKMAP_EVENT,
	NOTIFY_MP_RESET_STATS,
	NOTIFY_MP_SER_TCP_INFO,
	NOTIFY_HOST_INFO,
	NOTIFY_HOST_CPU_MEM_CHANGE,
	NOTIFY_NOTIFICATION_MSG,
	NOTIFY_AGGR_TASK_HIST_STATS,
	NOTIFY_LISTEN_CLUSTER_INFO,
	NOTIFY_HOST_STATE,
	NOTIFY_REQ_TRACE_TRAN,
	NOTIFY_REQ_TRACE_SET,
	NOTIFY_REQ_TRACE_STATUS,

	NOTIFY_PM_EVT_MAX,

	NOTIFY_MS_TCP_CONN		= 0x501,
	NOTIFY_MS_TCP_CONN_CLOSE,
	NOTIFY_SHYAMA_SER_TCP_INFO,
	NOTIFY_SHYAMA_CLI_TCP_INFO,
	NOTIFY_MS_SVC_CLUSTER_MESH,
	NOTIFY_SM_SVC_CLUSTER_MESH,
	NOTIFY_MS_LISTENER_NAT_IP,
	NOTIFY_SM_SVC_NAT_IP_CLUSTER,
	NOTIFY_SM_ALERT_ADEF_NEW,
	NOTIFY_SM_ALERT_ADEF_UPD,
	NOTIFY_SM_ALERT_STAT_DISABLE,
	NOTIFY_ALERT_STAT_INFO,
	NOTIFY_ALERT_STAT_CLOSE,
	NOTIFY_MS_CLUSTER_STATE,
	NOTIFY_MS_PARTHA_PING,
	NOTIFY_MS_REG_PARTHA,
	NOTIFY_SM_REQ_TRACE_DEF_NEW,
	NOTIFY_SM_REQ_TRACE_DEF_DISABLE,

	NOTIFY_MS_EVT_MAX,

	NOTIFY_MM_TASK_AGGR_PING	= 0x701,
	NOTIFY_MM_TASK_AGGR_DEL,
	NOTIFY_MM_TCP_CONN_TASK_CLOSE,
	NOTIFY_MM_AGGR_TASK_STATE,
	NOTIFY_MM_LISTENER_ISSUE_RESOL,
	NOTIFY_MM_LISTENER_PING,
	NOTIFY_MM_LISTENER_DELETE,
	NOTIFY_MM_LISTENER_DEPENDS,
	NOTIFY_MM_ACTIVE_CONN_STATS,

	NOTIFY_MM_EVT_MAX,

	NOTIFY_SM_PARTHA_IDENT		= 0x901,

	NOTIFY_SM_EVT_MAX,
	
	NOTIFY_PING_CONN		= 0xA01,
	NOTIFY_JSON_EVENT		= 0xA02,		// EVENT_NOTIFY immediately followed by JSON 

	NOTIFY_ERROR			= 0xB01,

	NOTIFY_MAX_TYPE,
};	

enum QUERY_TYPE_E : uint32_t
{
	QUERY_MIN_TYPE			= 0,

	QUERY_WEB_JSON			= 1,			// Query command subtype and params are sent in json 
	CRUD_GENERIC_JSON		= 2,			// Update Query command subtype and params are sent in json 
	CRUD_ALERT_JSON			= 3,			// Update Query command subtype and params are sent in json 

	QUERY_LISTENER_INFO_STATS	= 200,
	QUERY_PARTHA_MADHAVA,

	QUERY_MAX_TYPE,
};	

enum RESP_TYPE_E : uint32_t
{
	RESP_MIN_TYPE			= 0,

	RESP_PARTHA_MADHAVA		= 1,
	RESP_NUM_PARTHA,
	RESP_LISTENER_HISTORY,
	RESP_TASK_HISTORY,
	RESP_LISTENER_DEPENDS,
	RESP_LISTENER_INFO_STATS,
	
	RESP_WEB_JSON			= 1000,		// Response subtype and payload in json

	RESP_ERROR_STRING		= 1001,
	RESP_NULL_PAYLOAD,				// No further Response struct will be sent for this query

	RESP_MAX_TYPE,
};	

enum RESP_FORMAT_E : uint32_t
{
	RESP_BINARY			= 0,
	RESP_JSON_WITH_HEADER		= 1,		// Response will be sent in json with preceding COMM_HDR and QUERY_RESPONSE
	RESP_CSV_WITH_HEADER		= 3,		// Comma separated format
};

// Keep the error string limited to json compliant characters
static constexpr const char * comm_error_string(ERR_CODES_E code) noexcept
{
	switch (code) {
	
	case ERR_SUCCESS 			: return "No Error";
	
	case ERR_PROTOCOL_VERSION		: return "Invalid Protocol Version";
	case ERR_MADHAVA_VERSION		: return "Madhava Version not supported";
	case ERR_PARTHA_VERSION			: return "Partha Version not supported";
	case ERR_SHYAMA_VERSION			: return "Shyama Version not supported";
	case ERR_NODE_VERSION			: return "Node Version not supported";
	case ERR_SYSTEM_TIME_MISMATCH		: return "System Host Timestamp differs between the 2 hosts";
	case ERR_INVALID_ACCESS_KEY		: return "Invalid Access Key";	
	case ERR_ACCESS_KEY_EXPIRED		: return "Access Key Expired";
	case ERR_ACCESS_KEY_HOSTS_EXCEEDED	: return "Access Key Host Limit exceeded";
	case ERR_HOST_OVERLOADED		: return "Host overloaded";
	case ERR_ID_REUSED			: return "ID reused or same ID already active";
	case ERR_INVALID_MACHINE_ID		: return "Invalid Machine ID";
	case ERR_INVALID_ID			: return "Invalid ID seen";
	case ERR_NOT_VALIDATED			: return "Registration Request could not be validated";
	case ERR_MISMATCH_ID			: return "IDs do not match";
	case ERR_MAX_LIMIT			: return "Max Limit reached";
	case ERR_MADHAVA_UNAVAIL		: return "Madhava Host is not currently connected";
	case ERR_INVALID_SECRET			: return "Shyama Secret sent is invalid";

	case ERR_INVALID_REQUEST		: return "Invalid Request seen";
	case ERR_SERV_ERROR			: return "Server Error Occured while handling request";
	case ERR_TIMED_OUT			: return "Request Timed Out waiting for response";
	case ERR_DATA_NOT_FOUND			: return "Requested Data not found";
	case ERR_BLOCKING_ERROR			: return "Too many Requests being handled currently. Please try after some time...";
	case ERR_MAX_SZ_BREACHED		: return "Maximum Message Size Allowed limit breached";
	case ERR_SYSERROR			: return "System call error";
	
	case ERR_WARN_1 ... ERR_WARN_100	: return "Warning";

	default 				: return "Unknown Error";
	}	
}

static inline bool is_comm_error(ERR_CODES_E errcode) noexcept
{
	return errcode >= ERR_MIN_VALUE;
}	

static inline bool is_comm_warning(ERR_CODES_E errcode) noexcept
{
	return errcode >= ERR_WARN_1 && errcode < ERR_MIN_VALUE;
}	

struct alignas(8) COMM_HEADER
{
	enum HDR_MAGIC_E : uint32_t
	{
		INV_HDR_MAGIC			= 0,

		PS_ADHOC_MAGIC			= 0x05555505u,		// partha to shyama adhoc : Keep this first
		PM_HDR_MAGIC			= 0x05666605u,		// partha to madhava
		MS_HDR_MAGIC			= 0x05777705u,		// madhava to shyama
		MM_HDR_MAGIC			= 0x05888805u,		// madhava to madhava
		NS_HDR_MAGIC			= 0x05999905u,		// node web server to shyama persistent
		NM_HDR_MAGIC			= 0x05AAAA05u,		// node web server to madhava persistent
		NS_ADHOC_MAGIC			= 0x05B00105u,		// node web server to shyama adhoc
		NM_ADHOC_MAGIC			= 0x05C00105u,		// node web server to madhava adhoc : Keep this last

		// Ensure that any new types start and end with 0x05...

		MAX_HDR_MAGIC,

		MIN_HDR_MAGIC			= PS_ADHOC_MAGIC - 1,
	};	

	HDR_MAGIC_E				magic_		{INV_HDR_MAGIC};
	uint32_t				total_sz_	{0};			// sizeof(*this) + <any data length specified> + padding_sz_
	COMM_TYPE_E				data_type_	{COMM_INVALID_TYPE};
	uint32_t				padding_sz_	{0};			// Will not be set for Node Response : Required for Node Queries though
	
	 /* total_sz includes sizeof(*this) but no padding size */	
	COMM_HEADER(COMM_TYPE_E data_type, uint32_t total_sz, HDR_MAGIC_E magic) noexcept 
	{
		set_type_len(data_type, total_sz, magic);
	}

	bool set_type_len(COMM_TYPE_E data_type, uint32_t total_sz, HDR_MAGIC_E magic) noexcept
	{
		uint32_t		new_total_sz;
		
		if (gy_likely(false == is_host_node(magic))) {
			new_total_sz = gy_align_up_2(total_sz, 8);
		}
		else {
			new_total_sz = total_sz;
		}	

		if (new_total_sz < MAX_COMM_DATA_SZ && total_sz >= sizeof(*this) && 
			data_type > COMM_MIN_TYPE && data_type < COMM_MAX_TYPE && magic > MIN_HDR_MAGIC && magic < MAX_HDR_MAGIC) {

			magic_		= magic;
			total_sz_	= new_total_sz;
			data_type_	= data_type;
			padding_sz_	= new_total_sz - total_sz;

			return true;
		}	
		else {
			magic_		= INV_HDR_MAGIC;
			return false;
		}	
	}	
	
	uint32_t get_pad_len() const noexcept
	{
		return padding_sz_;
	}

	// Return Non-Padding length
	uint32_t get_act_len() const noexcept
	{
		return total_sz_ - padding_sz_;
	}

	// Return total length including padding
	uint32_t get_total_len() const noexcept
	{
		return total_sz_;
	}

	static inline std::pair<HOST_TYPES_E, HOST_TYPES_E> get_host_types(HDR_MAGIC_E magic) noexcept
	{
		HOST_TYPES_E 		host1, host2;

		switch (magic) {

		case PS_ADHOC_MAGIC	: host1 = HOST_PARTHA;		host2 = HOST_SHYAMA; 	break;
		case PM_HDR_MAGIC	: host1 = HOST_PARTHA; 		host2 = HOST_MADHAVA; 	break;
		case MS_HDR_MAGIC	: host1 = HOST_MADHAVA; 	host2 = HOST_SHYAMA; 	break;
		case MM_HDR_MAGIC	: host1 = HOST_MADHAVA; 	host2 = HOST_MADHAVA; 	break;
		case NS_HDR_MAGIC	: host1 = HOST_NODE_WEB; 	host2 = HOST_SHYAMA; 	break;
		case NM_HDR_MAGIC	: host1 = HOST_NODE_WEB; 	host2 = HOST_MADHAVA; 	break;
			
		case NS_ADHOC_MAGIC	: host1 = HOST_NODE_WEB; 	host2 = HOST_SHYAMA; 	break;
		case NM_ADHOC_MAGIC	: host1 = HOST_NODE_WEB; 	host2 = HOST_MADHAVA; 	break;

		default			: host1 = HOST_INVALID; 	host2 = HOST_INVALID; 	break;
		}	

		return {host1, host2};
	}

	// Check if the pdata is 8 bytes aligned and magic same as req_magic and other fields proper
	bool validate(const uint8_t *pdata, HDR_MAGIC_E req_magic) const noexcept;

	// Use this is certain that this is 8 bytes aligned and from a proper source
	bool validate() const noexcept
	{
		return validate((const uint8_t *)this, magic_);
	}	

	// Check only the 1st byte of the data to check if valid
	static bool is_valid_header_byte(const uint8_t c) noexcept
	{
		return (c == 0x05);
	}	

	static inline bool is_host_node(HDR_MAGIC_E magic) noexcept
	{
		auto [host1, host2] = get_host_types(magic);

		return host1 == HOST_NODE_WEB;
	}	

	bool is_valid_register_req() const noexcept
	{
		switch (magic_) {

		case PS_ADHOC_MAGIC	: return (data_type_ == PS_REGISTER_REQ);
		case PM_HDR_MAGIC	: return (data_type_ == PM_CONNECT_CMD);
		case MS_HDR_MAGIC	: return (data_type_ == MS_REGISTER_REQ);
		case MM_HDR_MAGIC	: return (data_type_ == MM_CONNECT_CMD);
		case NS_HDR_MAGIC	: return (data_type_ == NS_REGISTER_REQ || data_type_ == NS_ALERT_REGISTER);
		case NM_HDR_MAGIC	: return (data_type_ == NM_CONNECT_CMD);
			
		case NS_ADHOC_MAGIC	: return true;		// Always true for Adhoc conns from Node
		case NM_ADHOC_MAGIC	: return true;		// Always true for Adhoc conns from Node

		default			: return false;
		}	
	}	

	bool is_adhoc() const noexcept
	{
		return (magic_ == PS_ADHOC_MAGIC || magic_ == NS_ADHOC_MAGIC || magic_ == NM_ADHOC_MAGIC);
	}	

	bool is_node_action() const noexcept
	{
		return is_host_node(magic_) && (data_type_ == NS_ALERT_REGISTER);
	}	
};

struct alignas(8) EVENT_NOTIFY
{
	NOTIFY_TYPE_E			subtype_;
	uint32_t			nevents_;

	EVENT_NOTIFY() noexcept		= default;

	EVENT_NOTIFY(NOTIFY_TYPE_E subtype, uint32_t nevents) noexcept 
		: subtype_(subtype), nevents_(nevents)
	{}	

	static_assert(NOTIFY_PM_EVT_MAX < NOTIFY_MS_TCP_CONN, 		"Event ID Overflow detected");
	static_assert(NOTIFY_MS_EVT_MAX < NOTIFY_MM_TASK_AGGR_PING, 	"Event ID Overflow detected");
	static_assert(NOTIFY_SM_EVT_MAX < NOTIFY_PING_CONN, 		"Event ID Overflow detected");
};

struct alignas(8) QUERY_CMD
{
	uint64_t			seqid_;			// Can be an incrementing counter : need not be unique across conns
	time_t				timeoutsec_;		// In time_t 64 bit absolute sec format or 0 in case no timeout
	QUERY_TYPE_E			subtype_;
	RESP_FORMAT_E			respformat_;	

	QUERY_CMD() noexcept		= default;

	QUERY_CMD(uint64_t seqid, time_t abs_timeoutsec, QUERY_TYPE_E subtype, RESP_FORMAT_E respformat = RESP_BINARY) noexcept
		: seqid_(seqid), timeoutsec_(abs_timeoutsec), subtype_(subtype), respformat_(respformat)
	{}	

	uint64_t get_seqid() const noexcept
	{
		return seqid_;
	}

	time_t get_expiry_sec() const noexcept
	{
		return timeoutsec_;
	}	

	bool is_expired(time_t tcurr = time(nullptr)) const noexcept
	{
		return tcurr > timeoutsec_;
	}	

	int64_t get_time_to_expiry(time_t tcurr = time(nullptr)) const noexcept
	{
		return timeoutsec_ - tcurr;
	}	
};

struct alignas(8) QUERY_RESPONSE
{
	enum RESP_FLAGS_E : uint32_t
	{
		FLAG_NONE		= 0,
		FLAG_NODE_CACHE_10_MIN	= 1 << 0,		
		FLAG_NODE_CACHE_1_MIN	= 1 << 1,		
	};	

	uint64_t			seqid_;
	RESP_TYPE_E			subtype_;
	ERR_CODES_E			respcode_;
	RESP_FORMAT_E			respformat_;	
	uint32_t			resp_len_;		// Length of only the subsequent data with data of format as specified by respformat_
	RESP_FLAGS_E			respflags_;
	uint32_t			is_resp_complete_;	// Streaming Response, if zero, expect another COMM_HEADER and QUERY_RESPONSE set

	QUERY_RESPONSE(uint64_t seqid, RESP_TYPE_E subtype, ERR_CODES_E respcode, RESP_FORMAT_E respformat, const COMM_HEADER & hdr, bool is_resp_complete = true, \
		RESP_FLAGS_E respflags = FLAG_NONE) noexcept
		: seqid_(seqid), subtype_(subtype), respcode_(respcode), respformat_(respformat), 
		resp_len_(hdr.get_act_len() - sizeof(COMM_HEADER) - sizeof(QUERY_RESPONSE)), respflags_(respflags), is_resp_complete_(is_resp_complete)
	{}

	QUERY_RESPONSE(uint64_t seqid, RESP_TYPE_E subtype, ERR_CODES_E respcode, RESP_FORMAT_E respformat, uint32_t resp_len, bool is_resp_complete = true, \
		RESP_FLAGS_E respflags = FLAG_NONE) noexcept
		: seqid_(seqid), subtype_(subtype), respcode_(respcode), respformat_(respformat), resp_len_(resp_len), respflags_(respflags), 
		is_resp_complete_(is_resp_complete)
	{}

	bool validate(const COMM_HEADER *phdr) const noexcept;

	bool is_completed() const noexcept
	{
		return !!is_resp_complete_;
	}	
};	

struct alignas(8) ERROR_NOTIFY
{
	ERR_CODES_E			error_code_;
	uint32_t			error_string_len_;

	/*char				error_string_[error_string_len_]; follows */

	bool validate(const COMM_HEADER *phdr) const noexcept;
};


struct alignas(8) PS_REGISTER_REQ_S
{
	uint32_t			comm_version_;
	uint32_t			partha_version_;
	uint32_t			min_shyama_version_;
	uint64_t			machine_id_hi_;
	uint64_t			machine_id_lo_;
	char				hostname_[MAX_DOMAINNAME_SIZE];
	char				write_access_key_[ACCESS_KEY_LEN];
	char				cluster_name_[MAX_CLUSTER_NAME_LEN];
	char				region_name_[comm::MAX_ZONE_LEN];
	char				zone_name_[comm::MAX_ZONE_LEN];
	uint32_t			kern_version_num_;
	int64_t				curr_sec_;
	int64_t				last_mdisconn_sec_;
	uint64_t			last_madhava_id_;
	uint64_t			flags_;
	uint8_t				extra_bytes_[512];				

	bool validate(const COMM_HEADER *phdr) const noexcept
	{
		return (phdr->get_act_len() == sizeof(COMM_HEADER) + sizeof(*this));
	}	

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	bool validate_fields(uint32_t min_partha_version, uint32_t shyama_version, char (&ebuf)[COMM_MAX_ERROR_LEN], ERR_CODES_E & errcode) noexcept;
};	

struct alignas(8) PS_REGISTER_RESP_S
{
	ERR_CODES_E			error_code_;
	char				error_string_[COMM_MAX_ERROR_LEN];
	uint32_t			comm_version_;
	uint32_t			shyama_version_;
	uint64_t			shyama_id_;
	uint64_t			flags_;
	uint64_t			partha_ident_key_;				// To be sent to madhava as ident key
	int64_t				madhava_expiry_sec_;					
	uint64_t			madhava_id_;
	uint16_t			madhava_port_;
	char				madhava_hostname_[MAX_DOMAINNAME_SIZE];
	char				madhava_name_[MAX_CLUSTER_NAME_LEN];
	uint8_t				extra_bytes_[800];				

	bool validate(const COMM_HEADER *phdr) noexcept
	{
		error_string_[sizeof(error_string_) - 1] = 0;
		madhava_hostname_[sizeof(madhava_hostname_) - 1] = 0;
		madhava_name_[sizeof(madhava_name_) - 1] = 0;

		return (phdr->get_act_len() == sizeof(COMM_HEADER) + sizeof(*this));
	}	

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

};	

struct alignas(8) PM_CONNECT_CMD_S
{
	enum : uint64_t
	{
		CONN_FLAGS_NONE		= 0,
		CONN_FLAGS_REQ_TRACING	= 1 << 0,
	};
	
	uint32_t			comm_version_;
	uint32_t			partha_version_;
	uint32_t			min_madhava_version_;
	uint64_t			machine_id_hi_;
	uint64_t			machine_id_lo_;
	uint64_t			partha_ident_key_;
	char				hostname_[MAX_DOMAINNAME_SIZE];
	char				write_access_key_[ACCESS_KEY_LEN];
	char				cluster_name_[MAX_CLUSTER_NAME_LEN];
	char				region_name_[comm::MAX_ZONE_LEN];
	char				zone_name_[comm::MAX_ZONE_LEN];
	uint64_t			madhava_id_;
	CLI_TYPE_E			cli_type_;
	uint32_t			kern_version_num_;
	int64_t				curr_sec_;
	int64_t				clock_sec_;
	int64_t				process_uptime_sec_;
	int64_t				last_connect_sec_;
	uint64_t			flags_;
	uint8_t				extra_bytes_[512];				

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	bool validate(const COMM_HEADER *phdr) const noexcept
	{
		return (phdr->get_act_len() == sizeof(COMM_HEADER) + sizeof(*this));
	}	

	bool validate_fields(uint64_t madhava_id, uint32_t min_partha_version, uint32_t madhava_version, char (&ebuf)[COMM_MAX_ERROR_LEN], ERR_CODES_E & errcode) noexcept;
};

struct alignas(8) PM_CONNECT_RESP_S
{
	enum : uint64_t
	{
		CONN_FLAGS_NONE			= 0,
		CONN_FLAGS_RESET_STATS		= 1 << 0,
	};

	ERR_CODES_E			error_code_;
	char				error_string_[COMM_MAX_ERROR_LEN];
	uint64_t			madhava_id_;
	uint32_t			comm_version_;
	uint32_t			madhava_version_;
	char				region_name_[comm::MAX_ZONE_LEN];
	char				zone_name_[comm::MAX_ZONE_LEN];
	char				madhava_name_[MAX_CLUSTER_NAME_LEN];
	int64_t				curr_sec_;
	uint64_t			clock_sec_;
	uint64_t			flags_;
	uint8_t				extra_bytes_[512];

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	bool validate(const COMM_HEADER *phdr) noexcept
	{
		error_string_[sizeof(error_string_) - 1] = 0;
		region_name_[sizeof(region_name_) - 1] = 0;
		zone_name_[sizeof(zone_name_) - 1] = 0;
		madhava_name_[sizeof(madhava_name_) - 1] = 0;

		return (phdr->get_act_len() == sizeof(COMM_HEADER) + sizeof(*this));
	}	
};
	
struct alignas(8) MS_REGISTER_REQ_S
{
	uint32_t			comm_version_;
	uint32_t			madhava_version_;
	uint32_t			min_shyama_version_;
	uint64_t			madhava_id_;
	char				madhava_hostname_[MAX_DOMAINNAME_SIZE];
	uint16_t			madhava_port_;
	char				region_name_[MAX_ZONE_LEN];
	char				zone_name_[MAX_ZONE_LEN];
	char				madhava_name_[MAX_CLUSTER_NAME_LEN];
	char				shyama_secret_[MAX_CLUSTER_NAME_LEN];
	CLI_TYPE_E			cli_type_;
	uint32_t			kern_version_num_;
	int64_t				curr_sec_;
	int64_t				clock_sec_;
	uint32_t			max_partha_nodes_;
	uint32_t 			last_partha_nodes_;
	uint8_t				extra_bytes_[800];				

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	bool validate(const COMM_HEADER *phdr) const noexcept
	{
		return (phdr->get_act_len() == sizeof(COMM_HEADER) + sizeof(*this));
	}	

	bool validate_fields(uint32_t min_madhava_version, uint32_t shyama_version, const char * shyama_secret, char (&ebuf)[COMM_MAX_ERROR_LEN], ERR_CODES_E & errcode) noexcept;
};

struct alignas(8) MS_REGISTER_RESP_S
{
	enum : uint64_t
	{
		CONN_FLAGS_NONE			= 0,
		CONN_FLAGS_RESET_STATS		= 1 << 0,
		CONN_FLAGS_SEND_PARTHAS		= 1 << 1,
	};

	ERR_CODES_E			error_code_;
	char				error_string_[COMM_MAX_ERROR_LEN];
	uint32_t			comm_version_;
	uint32_t			shyama_version_;
	uint64_t			shyama_id_;
	uint64_t			madhava_id_;
	uint64_t			nmadhava_reg_;
	uint64_t			nmadhava_partha_;
	char				region_name_[comm::MAX_ZONE_LEN];
	char				zone_name_[comm::MAX_ZONE_LEN];
	char				shyama_name_[MAX_CLUSTER_NAME_LEN];
	int64_t				curr_sec_;
	uint64_t			clock_sec_;
	uint64_t			flags_;
	uint8_t				extra_bytes_[512];

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	bool validate(const COMM_HEADER *phdr) noexcept
	{
		error_string_[sizeof(error_string_) - 1] = 0;
		region_name_[sizeof(region_name_) - 1] = 0;
		zone_name_[sizeof(zone_name_) - 1] = 0;
		shyama_name_[sizeof(shyama_name_) - 1] = 0;

		return (phdr->get_act_len() == sizeof(COMM_HEADER) + sizeof(*this));
	}	
};

struct alignas(8) MM_CONNECT_CMD_S
{
	uint32_t			comm_version_;
	uint32_t			local_version_;
	uint32_t			min_remote_version_;
	char				madhava_hostname_[MAX_DOMAINNAME_SIZE];
	uint16_t			madhava_port_;
	char				region_name_[comm::MAX_ZONE_LEN];
	char				zone_name_[comm::MAX_ZONE_LEN];
	char				madhava_name_[MAX_CLUSTER_NAME_LEN];
	uint64_t			local_madhava_id_;
	uint64_t			remote_madhava_id_;
	CLI_TYPE_E			cli_type_;
	uint32_t			kern_version_num_;
	int64_t				curr_sec_;
	uint64_t			clock_sec_;
	uint32_t 			curr_partha_nodes_;
	uint8_t				extra_bytes_[512];				

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	bool validate(const COMM_HEADER *phdr) const noexcept
	{
		return (phdr->get_act_len() == sizeof(COMM_HEADER) + sizeof(*this));
	}	

	bool validate_fields(uint64_t madhava_id, uint32_t min_madhava_version, uint32_t curr_madhava_version, char (&ebuf)[COMM_MAX_ERROR_LEN], ERR_CODES_E & errcode) noexcept;
};

struct alignas(8) MM_CONNECT_RESP_S
{
	ERR_CODES_E			error_code_;
	char				error_string_[COMM_MAX_ERROR_LEN];
	uint32_t			comm_version_;
	char				region_name_[comm::MAX_ZONE_LEN];
	char				zone_name_[comm::MAX_ZONE_LEN];
	char				madhava_name_[MAX_CLUSTER_NAME_LEN];
	int64_t				curr_sec_;
	uint64_t			clock_sec_;
	uint64_t			flags_;
	uint8_t				extra_bytes_[512];

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	bool validate(const COMM_HEADER *phdr) noexcept
	{
		error_string_[sizeof(error_string_) - 1] = 0;
		region_name_[sizeof(region_name_) - 1] = 0;
		zone_name_[sizeof(zone_name_) - 1] = 0;
		madhava_name_[sizeof(madhava_name_) - 1] = 0;

		return (phdr->get_act_len() == sizeof(COMM_HEADER) + sizeof(*this));
	}	
};

struct alignas(8) NS_REGISTER_REQ_S
{
	int64_t				curr_sec_;			// Date.now() / 1000 | 0
	uint32_t			comm_version_;
	uint32_t			node_version_;
	uint32_t			min_shyama_version_;
	CLI_TYPE_E			cli_type_;
	uint32_t			node_port_;
	char				node_hostname_[MAX_DOMAINNAME_SIZE];
	uint8_t				extra_bytes_[128];

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	bool validate(const COMM_HEADER *phdr) const noexcept
	{
		return (phdr->get_act_len() == sizeof(COMM_HEADER) + sizeof(*this));
	}	

	bool validate_fields(uint32_t min_node_version, uint32_t shyama_version, char (&ebuf)[COMM_MAX_ERROR_LEN], ERR_CODES_E & errcode) noexcept;
};	

struct alignas(8) NS_REGISTER_RESP_S
{
	ERR_CODES_E			error_code_;
	uint32_t			shyama_version_;
	char				shyama_id_[32];
	char				error_string_[COMM_MAX_ERROR_LEN];
	uint8_t				extra_bytes_[128];

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	bool validate(const COMM_HEADER *phdr) const noexcept
	{
		return (phdr->get_act_len() == sizeof(COMM_HEADER) + sizeof(*this));
	}	
};

struct alignas(8) NM_CONNECT_CMD_S
{
	int64_t				curr_sec_;
	uint32_t			comm_version_;
	uint32_t			node_version_;
	uint32_t			min_madhava_version_;
	CLI_TYPE_E			cli_type_;
	uint32_t			node_port_;
	char				node_hostname_[MAX_DOMAINNAME_SIZE];
	uint8_t				extra_bytes_[128];

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	bool validate(const COMM_HEADER *phdr) const noexcept
	{
		return (phdr->get_act_len() == sizeof(COMM_HEADER) + sizeof(*this));
	}	

	bool validate_fields(uint32_t min_node_version, uint32_t shyama_version, char (&ebuf)[COMM_MAX_ERROR_LEN], ERR_CODES_E & errcode) noexcept;
};	

struct alignas(8) NM_CONNECT_RESP_S
{
	ERR_CODES_E			error_code_;
	uint32_t			madhava_version_;
	char				madhava_id_[32];
	char				error_string_[COMM_MAX_ERROR_LEN];
	uint8_t				extra_bytes_[128];

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	bool validate(const COMM_HEADER *phdr) const noexcept
	{
		static_assert(sizeof(NM_CONNECT_RESP_S) == sizeof(NS_REGISTER_RESP_S), "Please ensure struct sizes are same and members same");

		return (phdr->get_act_len() == sizeof(COMM_HEADER) + sizeof(*this));
	}	

	bool validate_fields() noexcept;
};


struct alignas(8) SM_PARTHA_IDENT_NOTIFY
{
	uint64_t			machine_id_hi_;
	uint64_t			machine_id_lo_;
	uint64_t			partha_ident_key_;
	int64_t				texpiry_sec_;
	int				is_new_host_;
	char				hostname_[MAX_DOMAINNAME_SIZE];

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
	{
		return (phdr->get_act_len() >= sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + pnotify->nevents_ * sizeof(SM_PARTHA_IDENT_NOTIFY));
	}	
};


struct alignas(8) PARTHA_STATUS
{
	bool				is_ok_;

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	bool validate(const COMM_HEADER *phdr) const noexcept
	{
		return (phdr->get_act_len() == sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + sizeof(*this));
	}	
};	
	
struct alignas(8) MADHAVA_PARTHA_STATUS	
{
	uint64_t			madhava_id_;
	uint64_t			npartha_nodes_;
	bool				is_active_madhava_id_;

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	bool validate(const COMM_HEADER *phdr) const noexcept
	{
		return (phdr->get_act_len() == sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + sizeof(*this));
	}	
};

struct alignas(8) MADHAVA_SHYAMA_STATUS
{
	uint64_t			madhava_id_;
	uint64_t			npartha_nodes_;
	uint64_t			approx_partha_conns_;

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	bool validate(const COMM_HEADER *phdr) const noexcept
	{
		return (phdr->get_act_len() == sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + sizeof(*this));
	}	
};	

struct alignas(8) SHYAMA_MADHAVA_STATUS
{
	uint64_t			nmadhava_reg_;
	uint64_t			nmadhava_partha_;
	uint64_t			active_madhava_id_;

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	bool validate(const COMM_HEADER *phdr) const noexcept
	{
		return (phdr->get_act_len() == sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + sizeof(*this));
	}	
};	

struct alignas(8) MADHAVA_MADHAVA_STATUS
{
	uint64_t			madhava_id_;
	uint64_t			npartha_nodes_;

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	bool validate(const COMM_HEADER *phdr) const noexcept
	{
		return (phdr->get_act_len() == sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + sizeof(*this));
	}	
};	

struct alignas(8) ERROR_STRING_RESP
{
	char				error_string_[COMM_MAX_ERROR_LEN];

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	bool validate(const COMM_HEADER *phdr, const QUERY_RESPONSE *presp) const noexcept
	{
		return ((phdr->get_act_len() == sizeof(COMM_HEADER) + sizeof(QUERY_RESPONSE) + sizeof(*this)) && (presp->resp_len_ == sizeof(*this)));
	}	
};	

// Lookup can be done on either of the 3 params or a combination if multiple specified
struct alignas(8) PARTHA_MADHAVA_REQ
{
	uint64_t			partha_machine_id_hi_;
	uint64_t			partha_machine_id_lo_;		// partha_machine_id_lo_ && partha_machine_id_hi_ should be 0 in case partha_hostname_len_ or extra_tags_len_

	uint32_t			partha_hostname_len_;
	uint32_t			extra_tags_len_;

	/*char				partha_hostname_[partha_hostname_len_]; '\0\' terminated follows */
	/*char				extra_tags_[extra_tags_len_]; '\0' terminated */
	
	bool validate(const COMM_HEADER *phdr) const noexcept;

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

};	

struct alignas(8) PARTHA_MADHAVA_RESP
{
	uint64_t			madhava_id_;
	char				madhava_svc_hostname_[MAX_DOMAINNAME_SIZE];
	uint16_t			madhava_svc_port_;

	bool validate(const COMM_HEADER *phdr, const QUERY_RESPONSE *presp) const noexcept;

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

};	

struct alignas(8) NUM_PARTHA_REQ
{
	bool				send_state_;

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	bool validate(const COMM_HEADER *phdr) const noexcept
	{
		return (phdr->get_act_len() == sizeof(COMM_HEADER) + sizeof(QUERY_CMD) + sizeof(*this));
	}	
};

struct alignas(8) NUM_PARTHA_RESP
{
	uint64_t			nconnected_;
	uint64_t			nhandled_;

	uint64_t			ngood_;
	uint64_t			nok_;
	uint64_t			nbad_;
	uint64_t			nsevere_;

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	bool validate(const COMM_HEADER *phdr, const QUERY_RESPONSE *presp) const noexcept
	{
		return ((phdr->get_act_len() == sizeof(COMM_HEADER) + sizeof(QUERY_RESPONSE) + sizeof(*this)) && (presp->resp_len_ == sizeof(*this)));
	}	
};	

struct alignas(8) MADHAVA_LIST	
{
	uint64_t			madhava_id_;
	uint64_t			npartha_nodes_;
	uint32_t			madhava_version_;
	char				madhava_svc_hostname_[MAX_DOMAINNAME_SIZE];
	uint16_t			madhava_svc_port_;

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
	{
		static constexpr size_t fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY);

		if (phdr->get_act_len() < fixed_sz) {
			return false;
		}	

		GY_CC_BARRIER();

		return phdr->get_act_len() == fixed_sz + pnotify->nevents_ * sizeof(MADHAVA_LIST);
	}	
};

struct alignas(8) MP_RESET_STATS
{
	bool				reset_stats_;

	MP_RESET_STATS(bool reset_stats) noexcept : reset_stats_(reset_stats)
	{}

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	bool validate(const COMM_HEADER *phdr) const noexcept
	{
		return (phdr->get_act_len() == sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + sizeof(*this));
	}	
};

struct alignas(8) TASK_MINI_ADD
{
	static constexpr size_t		MAX_MINI_CMDLINE_LEN 		{128};

	uint64_t			start_tusec_;
	uint64_t			exit_tusec_;			// If exited before add data could be sent 

	pid_t				task_pid_;
	pid_t				task_ppid_;
	pid_t				task_pgid_;	

	char				task_comm_[TASK_COMM_LEN];
	char				task_parent_comm_[TASK_COMM_LEN];

	uint64_t			aggr_task_id_;

	uid_t				task_effuid_;
	gid_t				task_effgid_;

	bool				is_rt_process_;
	uint32_t			task_cmdline_len_;

	uint32_t			padding_len_;

	/*char				task_cmdline_[task_cmdline_len_] follows */
	/*char				padding_[padding_len_]; follows to make the entire 8 byte aligned */

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this) + task_cmdline_len_ + padding_len_;
	}

	bool validate(const COMM_HEADER *phdr, size_t & elem_sz) noexcept;

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept;
};	


class alignas(8) TASK_FULL_ADD
{
public :	
	pid_t				task_pid_;		// In root PID namespace
	pid_t				task_ppid_;		// In root PID namespace
	pid_t				task_pgid_;		// In root PID namespace
	pid_t				task_sid_;		// In root PID namespace
	
	pid_t				task_nspid_;		// 1st level PID namespace
	pid_t				task_nspgid_;		// 1st level PID namespace
	pid_t				task_nssid_;		// 1st level PID namespace

	char				task_comm_[TASK_COMM_LEN];
	char				task_parent_comm_[TASK_COMM_LEN];

	uint64_t			aggr_task_id_;

	uid_t				task_realuid_;
	uid_t				task_effuid_;

	gid_t				task_realgid_;
	gid_t				task_effgid_;
	
	uint32_t			ncpus_allowed_;
	uint32_t			nmems_allowed_;	

	uint32_t			task_flags_;
	uint64_t			start_tusec_;

	int64_t				task_priority_;
	int64_t				task_nice_;
	uint32_t			task_rt_priority_;
	uint32_t			task_sched_policy_;

	int				ntcp_listeners_; 

	bool				is_tcp_server_;	
	bool				is_tcp_client_;
	bool				is_parent_tcp_client_;
	bool				is_high_cap_;	
	bool				listen_tbl_inherited_;

	uint16_t			task_exe_path_len_;
	uint16_t			task_cmdline_len_;
	uint16_t			task_tags_len_;
	uint8_t				padding_len_;

	/*char				task_exe_path_[task_exe_path_len_] follows;*/
	/*char				task_cmdline_[task_cmdline_len_] follows;*/
	/*char				task_tags_[task_tags_len_] follows;*/
	/*char				padding_[padding_len_]; follows to make the entire 8 byte aligned */

	static constexpr size_t		MAX_NUM_FULL_ADD = 32;	// Send in batches

	bool validate(const COMM_HEADER *phdr, size_t & elem_sz) noexcept;

	size_t get_elem_size() const noexcept
	{
		return sizeof(*this) + task_exe_path_len_ + task_cmdline_len_ + task_tags_len_ + padding_len_;
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept;
};

class alignas(8) TASK_AGGR_NOTIFY
{
public :	
	uint64_t			aggr_task_id_;
	uint64_t			related_listen_id_;
	char				comm_[TASK_COMM_LEN];
	uid_t				uid_;
	gid_t				gid_;
	uint16_t			cmdline_len_;
	uint8_t				tag_len_;

	uint8_t				is_high_cap_ : 1;
	uint8_t				is_cpu_cgroup_throttled_ : 1;
	uint8_t				is_mem_cgroup_limited_ : 1;
	uint8_t				is_rt_proc_ : 1;
	uint8_t				is_container_proc_ : 1;

	uint8_t				padding_len_;

	/*char				cmdline_[cmdline_len_] follows;*/
	/*char				tag_[tag_len_] follows;*/
	/*char				padding_[padding_len_]; follows to make the entire 8 byte aligned */

	static constexpr size_t		MAX_NUM_AGGR_TASK 	{1200};

	static constexpr size_t	get_max_elem_size() noexcept
	{
		return sizeof(TASK_AGGR_NOTIFY) + MAX_PROC_CMDLINE_LEN + (1ul << (sizeof(tag_len_) * CHAR_BIT));
	}	

	TASK_AGGR_NOTIFY(uint64_t aggr_task_id, const char *comm, uint64_t related_listen_id, uint16_t cmdline_len, uint8_t tag_len, uid_t uid, gid_t gid, \
				bool is_high_cap, bool is_cpu_cgroup_throttled, bool is_mem_cgroup_limited, bool is_rt_proc, bool is_container_proc) noexcept

		: aggr_task_id_(aggr_task_id), related_listen_id_(related_listen_id), uid_(uid), gid_(gid), cmdline_len_(cmdline_len), tag_len_(tag_len), is_high_cap_(is_high_cap),
		is_cpu_cgroup_throttled_(is_cpu_cgroup_throttled), is_mem_cgroup_limited_(is_mem_cgroup_limited), is_rt_proc_(is_rt_proc), is_container_proc_(is_container_proc)
	{
		static_assert(get_max_elem_size() * MAX_NUM_AGGR_TASK < MAX_COMM_DATA_SZ, "Max Network Payload size limit breached");

		GY_STRNCPY(comm_, comm, sizeof(comm_));

		set_padding_len();
	}

	TASK_AGGR_NOTIFY() noexcept	= default;

	size_t get_elem_size() const noexcept
	{
		return get_act_size() + padding_len_;
	}

	void set_padding_len() noexcept
	{
		size_t 			currsz, newsz;

		currsz = get_act_size();
		newsz = gy_align_up_2(currsz, 8);

		padding_len_		= newsz - currsz;
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept;

private :
	inline size_t get_act_size() const noexcept
	{
		return sizeof(*this) + cmdline_len_ + tag_len_; 
	}	

};

struct alignas(8) PING_TASK_AGGR
{
	uint64_t			aggr_task_id_		{0};
	uint64_t			related_listen_id_	{0};		// Only valid if recently updated Otherwise will be 0 even for listeners
	uint32_t			ntasks_			{0};
	bool				keep_task_		{false};

	PING_TASK_AGGR(uint64_t aggr_task_id) noexcept
		: aggr_task_id_(aggr_task_id)
	{}

	PING_TASK_AGGR() noexcept	= default;

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
	{
		return (phdr->get_act_len() >= sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + pnotify->nevents_ * sizeof(PING_TASK_AGGR));
	}
};

struct alignas(8) MM_TASK_AGGR_PING
{
	uint64_t			aggr_task_id_;

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
	{
		return (phdr->get_act_len() >= sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + pnotify->nevents_ * sizeof(MM_TASK_AGGR_PING));
	}
};

struct alignas(8) MM_TASK_AGGR_DEL
{
	uint64_t			aggr_task_id_;

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
	{
		return (phdr->get_act_len() >= sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + pnotify->nevents_ * sizeof(MM_TASK_AGGR_DEL));
	}
};


class alignas(8) TASK_TOP_PROCS
{
public :
	static constexpr size_t		TASK_MAX_TOP_N 		{15};	// For TOP_TASK (CPU PCT)
	static constexpr size_t		TASK_MAX_TOPPG_N 	{10};	// For TOP_PG_TASK
	static constexpr size_t		TASK_MAX_RSS_TOP_N 	{8};	// For TOP_TASK (Mem RSS)
	static constexpr size_t		TASK_MAX_FORKS_TOP_N 	{5};	// For TOP_FORK_TASK

	struct TOP_TASK
	{
		uint64_t		aggr_task_id_;
		pid_t			pid_;
		pid_t			ppid_;
		uint32_t		rss_mb_;
		float			cpupct_;
		char			comm_[TASK_COMM_LEN];
	};	

	struct TOP_PG_TASK
	{
		uint64_t		aggr_task_id_;
		pid_t			pg_pid_;
		pid_t			cpid_;
		int			ntasks_;
		uint32_t		tot_rss_mb_;
		float			tot_cpupct_;
		char			pg_comm_[TASK_COMM_LEN];
		char			child_comm_[TASK_COMM_LEN];
	};	

	struct TOP_FORK_TASK
	{
		uint64_t		aggr_task_id_;
		pid_t			pid_;
		pid_t			ppid_;
		int			nfork_per_sec_;
		char			comm_[TASK_COMM_LEN];
	};

	uint16_t			nprocs_			{0};
	uint16_t			npg_procs_		{0};
	uint16_t			nrss_procs_		{0};
	uint16_t			nfork_procs_		{0};
	uint16_t			ext_data_len_		{0};		// Len of subsequent data 
	
	/*TOP_TASK			toptask_[nprocs_] follows;*/
	/*TOP_PG_TASK			toppgtask_[npg_procs_] follows;*/
	/*TOP_TASK			toprsstask_[nrss_procs_] follows;*/
	/*TOP_FORK_TASK			topfork_[nfork_procs_] follows;*/

	bool validate(const COMM_HEADER *phdr) noexcept;

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this) + nprocs_ * sizeof(TOP_TASK) + npg_procs_ * sizeof(TOP_PG_TASK) + nrss_procs_ * sizeof(TOP_TASK) + nfork_procs_ * sizeof(TOP_FORK_TASK);
	}

	static constexpr size_t get_max_elem_size() noexcept
	{
		return sizeof(TASK_TOP_PROCS) + TASK_MAX_TOP_N * sizeof(TOP_TASK) + TASK_MAX_TOPPG_N * sizeof(TOP_PG_TASK) + TASK_MAX_RSS_TOP_N * sizeof(TOP_TASK)
			+ TASK_MAX_FORKS_TOP_N * sizeof(TOP_FORK_TASK);
	}	
};	

class alignas(8) TASK_HISTOGRAM
{
public :
	static constexpr size_t		MAX_HIST_HASH_BUCKETS = std::max(SEMI_LOG_HASH::get_max_buckets(), DURATION_HASH::get_max_buckets());

	struct TASK_ONE
	{
		HIST_SERIAL		stats_[MAX_HIST_HASH_BUCKETS];
		size_t 			total_count_; 
		ssize_t 		max_val_;

		uint32_t		nbuckets_;
		
		TASK_ONE() noexcept	= default;

		TASK_ONE(HIST_SERIAL *pstats, size_t total_count, ssize_t max_val, uint32_t nbuckets) noexcept
		{
			assert(nbuckets <= MAX_HIST_HASH_BUCKETS);
			
			if (nbuckets > MAX_HIST_HASH_BUCKETS) {
				nbuckets = MAX_HIST_HASH_BUCKETS;
			}

			std::memcpy(stats_, pstats, nbuckets * sizeof(*stats_));
			total_count_	= total_count;
			max_val_	= max_val;
			nbuckets_	= nbuckets;
		}	
	};	

	TASK_ONE			cpu_delay_histogram_;
	TASK_ONE			blkio_delay_histogram_;
	TASK_ONE			vol_cs_histogram_;
	TASK_ONE			invol_cs_histogram_;
	TASK_ONE			cpu_pct_histogram_;
	
	int64_t				last_update_tsec_;			// In time_t format
	uint64_t			aggr_task_id_;
	char				comm_[TASK_COMM_LEN];
	pid_t				pid_;

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
	{
		return (phdr->get_act_len() >= sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + pnotify->nevents_ * sizeof(TASK_HISTOGRAM));
	}	
};	

struct alignas(8) NEW_LISTENER
{
	NS_IP_PORT			ns_ip_port_;
	uint64_t			glob_id_;
	uint64_t			aggr_glob_id_;
	uint64_t			related_listen_id_;
	uint64_t			tstart_usec_;
	uint64_t			ser_aggr_task_id_;		// NEW_LISTENER contains TASK_AGGR_NOTIFY 
	bool				is_any_ip_;
	bool				is_pre_existing_;
	bool				no_aggr_stats_;
	bool				no_resp_stats_;
	char				comm_[TASK_COMM_LEN];
	pid_t				start_pid_;
	uint16_t			cmdline_len_;
	uint8_t				padding_len_;

	/*char				cmdline_[cmdline_len_] follows;*/
	/*char				padding_[padding_len_]; follows to make the entire 8 byte aligned */

	static constexpr size_t		MAX_NUM_LISTENERS 	{2048};	// Send in batches

	static constexpr size_t	get_max_elem_size() noexcept
	{
		return sizeof(NEW_LISTENER) + MAX_PROC_CMDLINE_LEN;
	}	

	NEW_LISTENER() noexcept		= default;

	NEW_LISTENER(const NS_IP_PORT & ns_ip_port, uint64_t glob_id, uint64_t aggr_glob_id, uint64_t related_listen_id, uint64_t tstart_usec, \
		uint64_t ser_aggr_task_id, bool is_any_ip, bool is_pre_existing, bool no_aggr_stats, bool no_resp_stats, const char *pcomm, pid_t start_pid, uint32_t cmdline_len) noexcept
		:
		ns_ip_port_(ns_ip_port), glob_id_(glob_id), aggr_glob_id_(aggr_glob_id), related_listen_id_(related_listen_id), tstart_usec_(tstart_usec), ser_aggr_task_id_(ser_aggr_task_id),
		is_any_ip_(is_any_ip), is_pre_existing_(is_pre_existing), no_aggr_stats_(no_aggr_stats), no_resp_stats_(no_resp_stats), start_pid_(start_pid),
		cmdline_len_(cmdline_len)
	{
		static_assert(get_max_elem_size() * MAX_NUM_LISTENERS < MAX_COMM_DATA_SZ, "Max Network Payload size limit breached");

		GY_STRNCPY(comm_, pcomm, sizeof(comm_));

		if (cmdline_len_ > MAX_PROC_CMDLINE_LEN) {
			cmdline_len_ = MAX_PROC_CMDLINE_LEN;
		}	

		set_padding_len();
	}	

	inline size_t get_elem_size() const noexcept
	{
		return get_act_size() + padding_len_;
	}	

	void set_padding_len() noexcept
	{
		size_t 			currsz, newsz;

		currsz = get_act_size();
		newsz = gy_align_up_2(currsz, 8);

		padding_len_		= newsz - currsz;
	}

	bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) const noexcept;

private :
	inline size_t get_act_size() const noexcept
	{
		return sizeof(*this) + cmdline_len_; 
	}	
};	


struct alignas(8) LISTENER_INFO_REQ
{
	uint32_t			ntcp_listeners_;
	/*NEW_LISTENER			tcp_[ntcp_listeners_] follows;*/

	LISTENER_INFO_REQ(uint32_t ntcp_listeners) noexcept
		: ntcp_listeners_(ntcp_listeners)
	{}

	uint32_t get_elem_size() const noexcept;

	bool validate(const COMM_HEADER *phdr) const noexcept;
};

/*
 * Can be contained both within EVENT_NOTIFY and within the Response to LISTENER_INFO_REQ
 */
struct alignas(8) LISTENER_DAY_STATS
{
	uint64_t			glob_id_;
	int64_t 			tcount_5d_;
	int64_t				tsum_5d_;
	uint32_t			p95_5d_respms_;
	uint32_t			p25_5d_respms_;
	uint32_t			p95_qps_;
	uint32_t			p25_qps_;
	uint32_t			p95_nactive_;
	uint32_t			p25_nactive_;

	static constexpr size_t		MAX_NUM_LISTENERS 	{2048};	// Send in batches

	static constexpr size_t	get_max_elem_size() noexcept
	{
		return sizeof(LISTENER_DAY_STATS);
	}	

	inline size_t get_elem_size() const noexcept
	{
		return get_act_size();
	}

	static bool validate(LISTENER_DAY_STATS *pone, uint32_t nelems, ssize_t totallen) noexcept;

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept;

private :
	inline size_t get_act_size() const noexcept
	{
		return sizeof(*this);
	}
};	

struct alignas(8) LISTENERS_INFO_STATS_RESP
{
	uint32_t			ntcp_listeners_;
	/*LISTENER_DAY_STATS		tcp_[ntcp_listeners_] follows;*/

	uint32_t get_elem_size() const noexcept;

	bool validate(const COMM_HEADER *phdr, const QUERY_RESPONSE *presp) const noexcept;
};	

struct alignas(8) TCP_CONN_NOTIFY
{
	IP_PORT				cli_;
	IP_PORT				ser_;
	
	IP_PORT				nat_cli_;
	IP_PORT				nat_ser_;
	
	uint64_t			tusec_start_;
	uint64_t			tusec_close_;

	uint64_t			cli_task_aggr_id_;
	uint64_t			cli_related_listen_id_;
	uint64_t			cli_madhava_id_;

	GY_MACHINE_ID			cli_ser_machine_id_;		// Remote peer

	uint64_t			ser_related_listen_id_;
	uint64_t			ser_glob_id_;
	uint64_t			ser_madhava_id_;

	uint64_t			bytes_sent_;			// From Client perspective
	uint64_t			bytes_rcvd_;			// From Client perspective

	pid_t				cli_pid_;
	pid_t				ser_pid_;

	uint32_t			ser_conn_hash_;
	uint32_t			ser_sock_inode_;

	char 				cli_comm_[TASK_COMM_LEN];
	char 				ser_comm_[TASK_COMM_LEN];

	uint16_t			cli_cmdline_len_;

	bool				is_tcp_connect_event_;
	bool				is_tcp_accept_event_;
	bool				is_loopback_conn_;
	bool				is_pre_existing_;
	bool				notified_before_;

	uint8_t				padding_len_;

	/*char				cli_cmdline_[cli_cmdline_len_]; follows*/
	/*char				padding_[padding_len_]; follows to make the entire 8 byte aligned */

	static constexpr size_t		MAX_NUM_CONNS 		{2048};	// Send in batches

	static constexpr size_t	get_max_elem_size() noexcept
	{
		return sizeof(TCP_CONN_NOTIFY) + MAX_PROC_CMDLINE_LEN;
	}	

	inline size_t get_elem_size() const noexcept
	{
		return get_act_size() + padding_len_;
	}

	void set_padding_len() noexcept
	{
		static_assert(get_max_elem_size() * MAX_NUM_CONNS < MAX_COMM_DATA_SZ, "Max Network Payload size limit breached");

		size_t 			currsz, newsz;

		currsz = get_act_size();
		newsz = gy_align_up_2(currsz, 8);

		padding_len_		= newsz - currsz;
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept;

private :
	inline size_t get_act_size() const noexcept
	{
		return sizeof(*this) + cli_cmdline_len_;
	}
};	

struct alignas(8) NAT_TCP_NOTIFY
{
	PAIR_IP_PORT			orig_tup_;
	PAIR_IP_PORT			nat_tup_;

	bool				is_snat_;
	bool				is_dnat_;
	bool				is_ipvs_;

	static constexpr size_t		MAX_NUM_CONNS 		{2048};	// Send in batches

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
	{
		return (phdr->get_act_len() >= sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + pnotify->nevents_ * sizeof(NAT_TCP_NOTIFY) && pnotify->nevents_ <= MAX_NUM_CONNS);
	}	
};

struct alignas(8) MS_TCP_CONN_CLOSE
{
	PAIR_IP_PORT			tup_;
	uint64_t			close_cli_bytes_sent_;
	uint64_t			close_cli_bytes_rcvd_;

	static constexpr size_t		MAX_NUM_CONNS 		{2048};	// Send in batches

	MS_TCP_CONN_CLOSE(const PAIR_IP_PORT & tup, uint64_t close_cli_bytes_sent, uint64_t close_cli_bytes_rcvd) noexcept
		: tup_(tup), close_cli_bytes_sent_(close_cli_bytes_sent), close_cli_bytes_rcvd_(close_cli_bytes_rcvd)
	{}

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
	{
		return (phdr->get_act_len() >= sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + pnotify->nevents_ * sizeof(MS_TCP_CONN_CLOSE) && pnotify->nevents_ <= MAX_NUM_CONNS);
	}	
};

struct alignas(8) MP_CLI_TCP_INFO
{
	PAIR_IP_PORT			tup_;
	GY_MACHINE_ID 			ser_partha_machine_id_;
	uint64_t			ser_glob_id_;
	uint64_t			ser_madhava_id_;
	uint64_t			ser_related_listen_id_;
	bool				cli_ser_diff_clusters_;
	char 				ser_comm_[TASK_COMM_LEN];

	static constexpr size_t		MAX_NUM_CONNS 		{2048};	// Send in batches

	MP_CLI_TCP_INFO(const PAIR_IP_PORT & tup, GY_MACHINE_ID ser_partha_machine_id, uint64_t ser_glob_id, uint64_t ser_madhava_id, uint64_t ser_related_listen_id, bool cli_ser_diff_clusters, \
		const char *ser_comm) noexcept
		: tup_(tup), ser_partha_machine_id_(ser_partha_machine_id), ser_glob_id_(ser_glob_id), ser_madhava_id_(ser_madhava_id), ser_related_listen_id_(ser_related_listen_id),
		cli_ser_diff_clusters_(cli_ser_diff_clusters)
	{
		GY_STRNCPY(ser_comm_, ser_comm, sizeof(ser_comm_));
	}

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
	{
		return (phdr->get_act_len() >= sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + pnotify->nevents_ * sizeof(MP_CLI_TCP_INFO) && pnotify->nevents_ <= MAX_NUM_CONNS);
	}	
};

struct alignas(8) MP_SER_TCP_INFO
{
	GY_MACHINE_ID 			cli_partha_machine_id_;
	uint64_t			cli_task_aggr_id_;
	uint64_t			cli_madhava_id_;
	uint64_t			cli_related_listen_id_;
	char 				cli_comm_[TASK_COMM_LEN];
	IP_PORT				ser_nat_ip_port_;
	uint64_t			ser_nat_conn_hash_;
	uint32_t			ser_conn_hash_;
	uint32_t			ser_sock_inode_;

	static constexpr size_t		MAX_NUM_CONNS 		{2048};	// Send in batches

	MP_SER_TCP_INFO(GY_MACHINE_ID cli_partha_machine_id, uint64_t cli_task_aggr_id, uint64_t cli_madhava_id, uint64_t cli_related_listen_id, \
		const char *cli_comm, const IP_PORT & ser_nat_ip_port, uint32_t ser_conn_hash, uint32_t ser_sock_inode) noexcept
		: cli_partha_machine_id_(cli_partha_machine_id), cli_task_aggr_id_(cli_task_aggr_id), cli_madhava_id_(cli_madhava_id), cli_related_listen_id_(cli_related_listen_id),
		ser_nat_ip_port_(ser_nat_ip_port), ser_conn_hash_(ser_conn_hash), ser_sock_inode_(ser_sock_inode)
	{
		GY_STRNCPY(cli_comm_, cli_comm, sizeof(cli_comm_));
	}

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
	{
		return (phdr->get_act_len() >= sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + pnotify->nevents_ * sizeof(MP_SER_TCP_INFO) && pnotify->nevents_ <= MAX_NUM_CONNS);
	}	
};


struct alignas(8) MS_TCP_CONN_NOTIFY
{
	IP_PORT				cli_;
	IP_PORT				ser_;
	
	IP_PORT				nat_cli_;
	IP_PORT				nat_ser_;
	
	uint64_t			tusec_mstart_			{0};		// Time when conn was added to madhava (not partha start)

	uint64_t			cli_task_aggr_id_		{0};
	uint64_t			cli_related_listen_id_		{0};

	uint64_t			ser_glob_id_			{0};
	uint64_t			ser_tusec_pstart_		{0};		// Time when conn was added to partha
	uint64_t			ser_nat_conn_hash_		{0};
	uint32_t			ser_conn_hash_			{0};
	uint32_t			ser_sock_inode_			{0};
	uint64_t			ser_related_listen_id_		{0};

	uint64_t			close_cli_bytes_sent_		{0};		// Will be non-zero only for closed conns
	uint64_t			close_cli_bytes_rcvd_		{0};

	GY_MACHINE_ID 			cli_ser_partha_machine_id_;
	uint64_t			cli_ser_cluster_hash_		{0};

	char 				cli_ser_comm_[TASK_COMM_LEN]	{};
	char				cli_ser_cmdline_trunc_[63];
	uint8_t				cli_ser_cmdline_len_		{0};

	static constexpr size_t		MAX_NUM_CONNS 			{2048};		// Send in batches

	bool is_server_updated() const noexcept
	{
		return (0 != ser_glob_id_);
	}	

	bool is_conn_closed() const noexcept
	{
		return close_cli_bytes_sent_ + close_cli_bytes_rcvd_ > 0;
	}

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
	{
		return (phdr->get_act_len() >= sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + pnotify->nevents_ * sizeof(MS_TCP_CONN_NOTIFY) && pnotify->nevents_ <= MAX_NUM_CONNS);
	}	
};	

struct alignas(8) SHYAMA_SER_TCP_INFO
{
	uint64_t			ser_glob_id_			{0};
	uint64_t			cli_madhava_id_			{0};
	uint64_t			cli_task_aggr_id_		{0};
	uint64_t			cli_related_listen_id_		{0};
	GY_MACHINE_ID			cli_partha_machine_id_;
	char 				ser_comm_[TASK_COMM_LEN];
	GY_MACHINE_ID 			ser_partha_machine_id_;
	IP_PORT				ser_nat_ip_port_;
	uint64_t			ser_nat_conn_hash_		{0};
	uint32_t			ser_conn_hash_			{0};
	uint32_t			ser_sock_inode_			{0};
	uint64_t			close_cli_bytes_sent_		{0};		// Will be non-zero only for closed conns
	uint64_t			close_cli_bytes_rcvd_		{0};
	uint64_t			tusec_pstart_			{0};
	uint64_t			tusec_mstart_			{0};
	char 				cli_comm_[TASK_COMM_LEN];
	char				cli_cmdline_trunc_[63];
	uint8_t				cli_cmdline_len_		{0};

	static constexpr size_t		MAX_NUM_CONNS 			{2048};		// Send in batches

	SHYAMA_SER_TCP_INFO(uint64_t ser_glob_id, uint64_t cli_madhava_id, uint64_t cli_task_aggr_id, uint64_t cli_related_listen_id, \
		const GY_MACHINE_ID & cli_partha_machine_id, const char *ser_comm, const GY_MACHINE_ID & ser_partha_machine_id, const IP_PORT & ser_nat_ip_port, \
		uint64_t ser_nat_conn_hash, uint32_t ser_conn_hash, uint32_t ser_sock_inode, uint64_t close_cli_bytes_sent, uint64_t close_cli_bytes_rcvd, 
		uint64_t tusec_pstart, uint64_t tusec_mstart, const char *cli_comm, const char *cli_cmdline, uint8_t cli_cmdline_len) noexcept

		: ser_glob_id_(ser_glob_id), cli_madhava_id_(cli_madhava_id), cli_task_aggr_id_(cli_task_aggr_id), cli_related_listen_id_(cli_related_listen_id),
		cli_partha_machine_id_(cli_partha_machine_id), ser_partha_machine_id_(ser_partha_machine_id), ser_nat_ip_port_(ser_nat_ip_port), 
		ser_nat_conn_hash_(ser_nat_conn_hash), ser_conn_hash_(ser_conn_hash), ser_sock_inode_(ser_sock_inode), close_cli_bytes_sent_(close_cli_bytes_sent), 
		close_cli_bytes_rcvd_(close_cli_bytes_rcvd), tusec_pstart_(tusec_pstart), tusec_mstart_(tusec_mstart)
	{
		GY_STRNCPY(ser_comm_, ser_comm, sizeof(ser_comm_));
		GY_STRNCPY(cli_comm_, cli_comm, sizeof(cli_comm_));

		auto len = std::min<uint32_t>(sizeof(cli_cmdline_trunc_) - 1, cli_cmdline_len);

		std::memcpy(cli_cmdline_trunc_, cli_cmdline, len);

		cli_cmdline_trunc_[len] = 0;
		cli_cmdline_len_ = len + 1;
	}

	bool is_conn_closed() const noexcept
	{
		return close_cli_bytes_sent_ + close_cli_bytes_rcvd_ > 0;
	}

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
	{
		return (phdr->get_act_len() >= sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + pnotify->nevents_ * sizeof(SHYAMA_SER_TCP_INFO) && pnotify->nevents_ <= MAX_NUM_CONNS);
	}	
};

struct alignas(8) SHYAMA_CLI_TCP_INFO
{
	PAIR_IP_PORT			tup_;
	uint64_t			ser_glob_id_;
	uint64_t			ser_madhava_id_;
	uint64_t			ser_related_listen_id_;
	IP_PORT 			ser_ip_port_;
	uint64_t			cli_task_aggr_id_;
	uint64_t			cli_related_listen_id_;
	GY_MACHINE_ID 			cli_partha_machine_id_;
	char 				cli_comm_[TASK_COMM_LEN];
	GY_MACHINE_ID 			ser_partha_machine_id_;
	uint64_t			close_cli_bytes_sent_;		// Will be non-zero only for closed conns
	uint64_t			close_cli_bytes_rcvd_;
	uint64_t			tusec_mstart_;
	bool				cli_ser_diff_clusters_;
	char 				ser_comm_[TASK_COMM_LEN];
	char				ser_cmdline_trunc_[63];
	uint8_t				ser_cmdline_len_;

	static constexpr size_t		MAX_NUM_CONNS 			{2048};	// Send in batches

	SHYAMA_CLI_TCP_INFO(const PAIR_IP_PORT & tup, uint64_t ser_glob_id, uint64_t ser_madhava_id, uint64_t ser_related_listen_id, const IP_PORT & ser_ip_port, uint64_t cli_task_aggr_id, \
		uint64_t cli_related_listen_id, const GY_MACHINE_ID & cli_partha_machine_id, const char *cli_comm, const GY_MACHINE_ID & ser_partha_machine_id, uint64_t close_cli_bytes_sent, \
		uint64_t close_cli_bytes_rcvd, uint64_t tusec_mstart, bool cli_ser_diff_clusters, const char *ser_comm, const char *ser_cmdline, uint8_t ser_cmdline_len) noexcept

		: tup_(tup), ser_glob_id_(ser_glob_id), ser_madhava_id_(ser_madhava_id), ser_related_listen_id_(ser_related_listen_id), ser_ip_port_(ser_ip_port), 
		cli_task_aggr_id_(cli_task_aggr_id), cli_related_listen_id_(cli_related_listen_id), cli_partha_machine_id_(cli_partha_machine_id), ser_partha_machine_id_(ser_partha_machine_id), 
		close_cli_bytes_sent_(close_cli_bytes_sent), close_cli_bytes_rcvd_(close_cli_bytes_rcvd), tusec_mstart_(tusec_mstart), cli_ser_diff_clusters_(cli_ser_diff_clusters)
	{
		GY_STRNCPY(cli_comm_, cli_comm, sizeof(cli_comm_));
		GY_STRNCPY(ser_comm_, ser_comm, sizeof(ser_comm_));

		auto len = std::min<uint32_t>(sizeof(ser_cmdline_trunc_) - 1, ser_cmdline_len);

		std::memcpy(ser_cmdline_trunc_, ser_cmdline, len);

		ser_cmdline_trunc_[len] = 0;
		ser_cmdline_len_ = len + 1;
	}

	bool is_conn_closed() const noexcept
	{
		return close_cli_bytes_sent_ + close_cli_bytes_rcvd_ > 0;
	}

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
	{
		return (phdr->get_act_len() >= sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + pnotify->nevents_ * sizeof(SHYAMA_CLI_TCP_INFO) && pnotify->nevents_ <= MAX_NUM_CONNS);
	}	
};

struct alignas(8) CPU_MEM_STATE_NOTIFY
{
	float				cpu_pct_		{0};
	float				usercpu_pct_		{0};
	float				syscpu_pct_		{0};
	float				iowait_pct_		{0};
	float				cumul_core_cpu_pct_	{0};
	uint32_t			forks_sec_		{0};		
	uint32_t			procs_running_		{0};
	uint32_t			cs_sec_			{0};

	uint32_t			cs_p95_sec_		{0};
	uint32_t			cs_5min_p95_sec_	{0};
	uint32_t			cpu_p95_		{0};
	uint32_t			cpu_5min_p95_		{0};
	uint32_t			fork_p95_sec_		{0};
	uint32_t			fork_5min_p95_sec_	{0};
	uint32_t			procs_p95_		{0};
	uint32_t			procs_5min_p95_		{0};

	uint8_t				cpu_state_		{0};
	uint8_t				cpu_issue_		{0};
	uint8_t				cpu_issue_bit_hist_	{0};
	uint8_t				cpu_severe_issue_hist_	{0};
	uint8_t				cpu_state_string_len_	{0};	// Keep as uint8_t

	float				rss_pct_		{0};
	uint64_t			rss_memory_mb_		{0};
	uint64_t			total_memory_mb_	{0};
	uint64_t			cached_memory_mb_	{0};
	uint64_t			locked_memory_mb_	{0};
	uint64_t			committed_memory_mb_	{0};
	float				committed_pct_		{0};
	uint64_t			swap_free_mb_		{0};
	uint64_t			swap_total_mb_		{0};
	uint32_t			pg_inout_sec_		{0};
	uint32_t			swap_inout_sec_		{0};
	uint32_t			reclaim_stalls_		{0};
	uint32_t			pgmajfault_		{0};
	uint32_t			oom_kill_		{0};

	uint32_t			rss_pct_p95_		{0};
	uint64_t			pginout_p95_		{0};
	uint64_t			swpinout_p95_		{0};
	uint64_t			allocstall_p95_		{0};

	uint8_t				mem_state_		{0};
	uint8_t				mem_issue_		{0};
	uint8_t				mem_issue_bit_hist_	{0};
	uint8_t				mem_severe_issue_hist_	{0};
	uint8_t				mem_state_string_len_	{0};	// Keep as uint8_t

	uint8_t				padding_len_		{0};

	// char				cpu_state_string_[cpu_state_string_len_] follows
	// char				mem_state_string_[mem_state_string_len_] follows
	// char				padding_[padding_len_]; follows to make the entire 8 byte aligned 

	static constexpr size_t	get_max_elem_size() noexcept
	{
		return sizeof(CPU_MEM_STATE_NOTIFY) + (1ul << (sizeof(cpu_state_string_len_) * CHAR_BIT)) + (1ul << (sizeof(mem_state_string_len_) * CHAR_BIT));
	}	

	inline size_t get_elem_size() const noexcept
	{
		return get_act_size() + padding_len_;
	}

	void set_padding_len() noexcept
	{
		size_t 			currsz, newsz;

		currsz = get_act_size();
		newsz = gy_align_up_2(currsz, 8);

		padding_len_		= newsz - currsz;
	}

	bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept;
	
private :
	inline size_t get_act_size() const noexcept
	{
		return sizeof(*this) + cpu_state_string_len_ + mem_state_string_len_;
	}
};	

/*
 * Sent within NOTIFY_AGGR_TASK_STATE and NOTIFY_MM_AGGR_TASK_STATE event messages
 */
struct alignas(8) AGGR_TASK_STATE_NOTIFY
{
	uint64_t			aggr_task_id_		{0};
	char				onecomm_[TASK_COMM_LEN]	{};
	pid_t				pid_arr_[2]		{};
	uint32_t			tcp_kbytes_		{0};
	uint32_t			tcp_conns_		{0};
	float				total_cpu_pct_		{0};
	uint32_t			rss_mb_			{0};
	uint32_t			cpu_delay_msec_		{0};
	uint32_t			vm_delay_msec_		{0};
	uint32_t			blkio_delay_msec_	{0};
	uint16_t			ntasks_total_		{0};
	uint16_t			ntasks_issue_		{0};
	uint8_t				curr_state_		{0};
	uint8_t				curr_issue_		{0};
	uint8_t				issue_bit_hist_		{0};
	uint8_t				severe_issue_bit_hist_	{0};
	uint8_t				issue_string_len_	{0};
	uint8_t				padding_len_		{0};

	/*char				issue_string_[issue_string_len_]; follows*/
	/*char				padding_[padding_len_]; follows to make the entire 8 byte aligned */

	static constexpr size_t		MAX_NUM_TASKS 		{1200};
	static constexpr size_t		MAX_ISSUE_LEN 		{160};

	static constexpr size_t	get_max_elem_size() noexcept
	{
		return sizeof(AGGR_TASK_STATE_NOTIFY) + MAX_ISSUE_LEN;
	}	

	inline size_t get_elem_size() const noexcept
	{
		return get_act_size() + padding_len_;
	}

	void set_padding_len() noexcept
	{
		static_assert(AGGR_TASK_STATE_NOTIFY::get_max_elem_size() * MAX_NUM_TASKS < MAX_COMM_DATA_SZ, "Max Network Payload size limit breached");

		size_t 		currsz, newsz;

		currsz 		= get_act_size();
		newsz 		= gy_align_up_2(currsz, 8);

		padding_len_	= newsz - currsz;
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept;

private :
	inline size_t get_act_size() const noexcept
	{
		return sizeof(*this) + issue_string_len_;
	}

};

enum LISTENER_QUERY_FLAGS : uint8_t
{
	LISTEN_FLAG_NONE		= 0,
	LISTEN_FLAG_ALERT		= 1 << 0,	

	// Keep the query flags limited to 5 bits

	LISTEN_FLAG_DELETE		= ((1 << 7) | (1 << 6)),
};

struct alignas(8) LISTENER_STATE_NOTIFY
{
	uint64_t			glob_id_		{0};

	uint32_t			nqrys_5s_		{0};
	uint32_t			total_resp_5sec_	{0};
	uint32_t			nconns_			{0};
	uint32_t			nconns_active_		{0};
	uint32_t			ntasks_			{0};

	uint32_t			p95_5s_resp_ms_		{0};
	uint32_t			p95_5min_resp_ms_	{0};
	uint32_t			curr_kbytes_inbound_	{0};
	uint32_t			curr_kbytes_outbound_	{0};
	uint32_t			ser_errors_		{0};
	uint32_t			cli_errors_		{0};

	uint32_t 			tasks_delay_usec_	{0};
	uint32_t			tasks_cpudelay_usec_	{0};
	uint32_t			tasks_blkiodelay_usec_	{0};
	uint32_t 			tasks_user_cpu_		{0};
	uint32_t 			tasks_sys_cpu_		{0};
	uint32_t			tasks_rss_mb_		{0};

	uint16_t 			ntasks_issue_		{0};

	bool				is_http_svc_		{false};
	uint8_t				curr_state_		{0};
	uint8_t				curr_issue_		{0};
	uint8_t				issue_bit_hist_		{0};
	uint8_t				high_resp_bit_hist_	{0};
	uint8_t				last_issue_subsrc_	{0};
	LISTENER_QUERY_FLAGS		query_flags_		{LISTEN_FLAG_NONE};
	uint8_t				issue_string_len_	{0};
	uint8_t				padding_len_		{0};

	/*char				issue_string_[issue_string_len_]; follows*/
	/*char				padding_[padding_len_]; follows to make the entire 8 byte aligned */

	static constexpr size_t		MAX_NUM_LISTENERS 	{512};		// Send in small batches

	static constexpr size_t	get_max_elem_size() noexcept
	{
		return sizeof(LISTENER_STATE_NOTIFY) + (1ul << (sizeof(issue_string_len_) * CHAR_BIT));
	}	

	inline size_t get_elem_size() const noexcept
	{
		return get_act_size() + padding_len_;
	}

	void set_padding_len() noexcept
	{
		static_assert(LISTENER_STATE_NOTIFY::get_max_elem_size() * MAX_NUM_LISTENERS < MAX_COMM_DATA_SZ, "Max Network Payload size limit breached");

		size_t 		currsz, newsz;

		currsz 		= get_act_size();
		newsz 		= gy_align_up_2(currsz, 8);

		padding_len_	= newsz - currsz;
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept;

private :
	inline size_t get_act_size() const noexcept
	{
		return sizeof(*this) + issue_string_len_;
	}

};

struct alignas(8) HOST_STATE_NOTIFY__V000100
{
	uint64_t			curr_time_usec_		{0};

	uint32_t			ntasks_issue_		{0};
	uint32_t			ntasks_severe_		{0};
	uint32_t			ntasks_			{0};

	uint32_t			nlisten_issue_		{0};
	uint32_t			nlisten_severe_		{0};
	uint32_t			nlisten_		{0};

	uint8_t				curr_state_		{STATE_DOWN};
	uint8_t				issue_bit_hist_		{0};
	bool				cpu_issue_		{false};
	bool				mem_issue_		{false};
	bool				severe_cpu_issue_	{false};
	bool				severe_mem_issue_	{false};


	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
	{
		return ((phdr->get_act_len() >= sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + sizeof(HOST_STATE_NOTIFY__V000100)) && (pnotify->nevents_ == 1));
	}
};



struct alignas(8) HOST_STATE_NOTIFY
{
	uint64_t			curr_time_usec_		{0};

	uint32_t			ntasks_issue_		{0};
	uint32_t			ntasks_severe_		{0};
	uint32_t			ntasks_			{0};

	uint32_t			nlisten_issue_		{0};
	uint32_t			nlisten_severe_		{0};
	uint32_t			nlisten_		{0};

	uint8_t				curr_state_		{STATE_DOWN};
	uint8_t				issue_bit_hist_		{0};
	bool				cpu_issue_		{false};
	bool				mem_issue_		{false};
	bool				severe_cpu_issue_	{false};
	bool				severe_mem_issue_	{false};

	alignas(8) uint32_t		total_cpu_delayms_	{0};
	uint32_t			total_vm_delayms_	{0};
	uint32_t			total_io_delayms_	{0};

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
	{
		return ((phdr->get_act_len() >= sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + sizeof(HOST_STATE_NOTIFY)) && (pnotify->nevents_ == 1));
	}

	HOST_STATE_NOTIFY() noexcept	= default;

	HOST_STATE_NOTIFY(const HOST_STATE_NOTIFY__V000100 & ohost) noexcept
	{
		static_assert(offsetof(HOST_STATE_NOTIFY, total_cpu_delayms_) == sizeof(HOST_STATE_NOTIFY__V000100), "Alignment of field change needed");

		std::memcpy((void *)this, &ohost, sizeof(ohost));
	}	

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}
};


struct alignas(8) LISTENER_DEPENDENCY_NOTIFY
{
	struct alignas(8) DEPENDS_ONE
	{
		uint64_t		glob_id_		{0};
		uint64_t		madhava_id_		{0};
		NS_IP_PORT		ns_ip_port_;
		bool			is_new_			{false};
		bool			is_localhost_		{false};
		bool			delete_depends_		{false};
		bool			is_load_balanced_	{false};

		DEPENDS_ONE(uint64_t glob_id, uint64_t madhava_id, const NS_IP_PORT & ns_ip_port, bool is_new, bool is_localhost, bool delete_depends, bool is_load_balanced = false) noexcept
			: glob_id_(glob_id), madhava_id_(madhava_id), ns_ip_port_(ns_ip_port),
			is_new_(is_new), is_localhost_(is_localhost), delete_depends_(delete_depends)
		{}	
	};	

	uint64_t			related_listen_id_	{0};
	uint64_t			one_listener_glob_id_	{0};		// First listener ID from the set of related listeners
	uint32_t			ndepends_		{0};
	uint32_t			nlisteners_		{0};

	/* DEPENDS_ONE			deparr_[ndepends_] follow */

	static constexpr size_t		MAX_DEPENDS_PER_LISTEN	{512};		// Max batch to be sent per listener
	static constexpr size_t		MAX_NUM_LISTENERS 	{256};		

	LISTENER_DEPENDENCY_NOTIFY(uint64_t related_listen_id, uint64_t one_listener_glob_id, uint32_t ndepends, uint32_t nlisteners) noexcept
		: related_listen_id_(related_listen_id), one_listener_glob_id_(one_listener_glob_id), ndepends_(ndepends), nlisteners_(nlisteners)
	{}	

	static constexpr size_t	get_max_elem_size() noexcept
	{
		return sizeof(LISTENER_DEPENDENCY_NOTIFY) + MAX_DEPENDS_PER_LISTEN * sizeof(DEPENDS_ONE);
	}	

	inline size_t get_elem_size() const noexcept
	{
		return sizeof(*this) + ndepends_ * sizeof(DEPENDS_ONE);
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept;
};	


struct alignas(8) RELSVC_CLUSTER_ONE
{
	GY_MACHINE_ID		partha_machine_id_;
	uint64_t		madhava_id_		{0};
	uint64_t		related_listen_id_	{0};

	RELSVC_CLUSTER_ONE() noexcept			= default;

	RELSVC_CLUSTER_ONE(const GY_MACHINE_ID & partha_machine_id, uint64_t madhava_id, uint64_t related_listen_id) noexcept
		: partha_machine_id_(partha_machine_id), madhava_id_(madhava_id), related_listen_id_(related_listen_id)
	{}	

	bool operator==(const RELSVC_CLUSTER_ONE & other) const noexcept
	{
		static_assert(sizeof(RELSVC_CLUSTER_ONE) == 32, "Please ensure no padding in this struct and change the static_assert sizeof value");
		
		return (0 == std::memcmp(this, &other, sizeof(*this)));
	}	

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	uint32_t get_hash() const noexcept
	{
		return GY_JHASHER<RELSVC_CLUSTER_ONE, true>()(*this);
	}	

	struct RHash
	{
		size_t operator()(const RELSVC_CLUSTER_ONE & one) const noexcept
		{
			return one.get_hash();
		}	
	};	
};	


struct alignas(8) LISTENER_CLUSTER_NOTIFY
{
	uint64_t			related_listen_id_	{0};
	uint32_t			ncluster_elems_		{0};

	/* RELSVC_CLUSTER_ONE		clarr_[ncluster_elems_] follow */

	static constexpr size_t		MAX_CLUSTER_ELEMS	{1024};		// Max batch to be sent per listener
	static constexpr size_t		MAX_NUM_LISTENERS 	{256};		
	
	static constexpr uint64_t	INODE_CLUSTER_MSEC	{100'000};	// Used in partha scheduling

	LISTENER_CLUSTER_NOTIFY(uint64_t related_listen_id, uint32_t ncluster_elems) noexcept
		: related_listen_id_(related_listen_id), ncluster_elems_(ncluster_elems)
	{}	

	static constexpr size_t	get_max_elem_size() noexcept
	{
		return sizeof(LISTENER_CLUSTER_NOTIFY) + MAX_CLUSTER_ELEMS * sizeof(RELSVC_CLUSTER_ONE);
	}	

	inline size_t get_elem_size() const noexcept
	{
		return sizeof(*this) + ncluster_elems_ * sizeof(RELSVC_CLUSTER_ONE);
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept;
};	

struct alignas(8) MS_SVC_CLUSTER_MESH
{
	uint64_t			svc_cluster_id_		{0};
	uint32_t			ncluster_elems_		{0};
	char				cluster_name_[MAX_CLUSTER_NAME_LEN];
	char				init_comm_[TASK_COMM_LEN];

	/* RELSVC_CLUSTER_ONE		clarr_[ncluster_elems_] follow */

	static constexpr size_t		MAX_CLUSTER_ELEMS	{1024};		// Max batch to be sent per svc set
	static constexpr size_t		MAX_NUM_CLUSTERS 	{256};		

	MS_SVC_CLUSTER_MESH(uint64_t svc_cluster_id, uint32_t ncluster_elems, const char *cluster_name, const char * init_comm) noexcept
		: svc_cluster_id_(svc_cluster_id), ncluster_elems_(ncluster_elems)
	{
		GY_STRNCPY(cluster_name_, cluster_name, sizeof(cluster_name_));
		GY_STRNCPY(init_comm_, init_comm, sizeof(init_comm_));
	}	

	static constexpr size_t	get_max_elem_size() noexcept
	{
		return sizeof(MS_SVC_CLUSTER_MESH) + MAX_CLUSTER_ELEMS * sizeof(RELSVC_CLUSTER_ONE);
	}	

	inline size_t get_elem_size() const noexcept
	{
		return sizeof(*this) + ncluster_elems_ * sizeof(RELSVC_CLUSTER_ONE);
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept;
};	

struct alignas(8) SM_SVC_CLUSTER_MESH
{
	uint64_t			svc_cluster_id_		{0};
	uint32_t			ntotal_cluster_svc_	{0};
	uint32_t			nmadhava_elems_		{0};
	char				cluster_name_[MAX_CLUSTER_NAME_LEN];
	char				init_comm_[TASK_COMM_LEN];

	/* RELSVC_CLUSTER_ONE		clarr_[nmadhava_elems_] follow */

	static constexpr size_t		MAX_CLUSTER_ELEMS	{2048};		// Max nmadhava_elems_
	static constexpr size_t		MAX_NUM_CLUSTERS 	{1024};		

	SM_SVC_CLUSTER_MESH(uint64_t svc_cluster_id, uint32_t ntotal_cluster_svc, uint32_t nmadhava_elems, const char *cluster_name, const char * init_comm) noexcept
		: svc_cluster_id_(svc_cluster_id), ntotal_cluster_svc_(ntotal_cluster_svc), nmadhava_elems_(nmadhava_elems)
	{
		GY_STRNCPY(cluster_name_, cluster_name, sizeof(cluster_name_));
		GY_STRNCPY(init_comm_, init_comm, sizeof(init_comm_));
	}	

	inline size_t get_elem_size() const noexcept
	{
		return sizeof(*this) + nmadhava_elems_ * sizeof(RELSVC_CLUSTER_ONE);
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept;
};	


struct alignas(8) LISTENER_NAT_IP_EVENT
{
	IP_PORT				nat_ip_port_arr_[2];
	uint64_t			glob_id_		{0};

	static constexpr size_t		MAX_NUM_LISTENERS 	{512};		// Send in batches

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
	{
		return ((phdr->get_act_len() >= sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + pnotify->nevents_ * sizeof(LISTENER_NAT_IP_EVENT)) &&
			pnotify->nevents_ <= MAX_NUM_LISTENERS);
	}
};	

struct alignas(8) MS_LISTENER_NAT_IP
{
	GY_MACHINE_ID			partha_machine_id_;
	uint64_t			madhava_id_				{0};
	uint64_t			glob_id_				{0};
	char				cluster_name_[MAX_CLUSTER_NAME_LEN];
	char				comm_[TASK_COMM_LEN];
	uint8_t				nelems_new_				{0};
	uint8_t				nelems_del_				{0};

	/* IP_PORT			nat_ip_ports_[nelems_new_] follow */
	/* IP_PORT			del_ip_ports_[nelems_del_] follow */

	static constexpr size_t		MAX_ELEMS				{8};		// nelems_new_ + nelems_del_
	static constexpr size_t		MAX_NUM_LISTENERS 			{256};		

	MS_LISTENER_NAT_IP(const GY_MACHINE_ID & partha_machine_id, uint64_t madhava_id, uint64_t glob_id, const char *cluster_name, const char * comm, uint8_t nelems_new, uint8_t nelems_del) noexcept
		: partha_machine_id_(partha_machine_id), madhava_id_(madhava_id), glob_id_(glob_id), nelems_new_(nelems_new), nelems_del_(nelems_del)
	{
		GY_STRNCPY(cluster_name_, cluster_name, sizeof(cluster_name_));
		GY_STRNCPY(comm_, comm, sizeof(comm_));
	}	

	static constexpr size_t	get_max_elem_size() noexcept
	{
		return sizeof(MS_LISTENER_NAT_IP) + MAX_ELEMS * sizeof(IP_PORT);
	}	

	inline size_t get_elem_size() const noexcept
	{
		return sizeof(*this) + (nelems_new_ + nelems_del_) * sizeof(IP_PORT);
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept;
};	

struct alignas(8) SM_SVC_NAT_IP_CLUSTER
{
	uint64_t			nat_ip_cluster_id_			{0};
	uint64_t			glob_id_				{0};
	IP_PORT				nat_ip_port_;
	uint32_t			ntotal_cluster_svc_			{0};

	static constexpr size_t		MAX_NUM_LISTENERS 			{2048};		

	SM_SVC_NAT_IP_CLUSTER(uint64_t nat_ip_cluster_id, uint64_t glob_id, const IP_PORT & nat_ip_port, uint32_t ntotal_cluster_svc) noexcept
		: nat_ip_cluster_id_(nat_ip_cluster_id), glob_id_(glob_id), nat_ip_port_(nat_ip_port), ntotal_cluster_svc_(ntotal_cluster_svc)
	{}	

	inline size_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
	{
		return (phdr->get_act_len() >= sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + pnotify->nevents_ * sizeof(SM_SVC_NAT_IP_CLUSTER)) && pnotify->nevents_ <= MAX_NUM_LISTENERS;
	}	
};	


struct alignas(8) MM_LISTENER_ISSUE_RESOL
{
	struct DOWNSTREAM_ONE
	{
		uint8_t			downstream_glob_id_buf_[8]	{};
		uint8_t			downstream_state_		{0};
		uint8_t			downstream_issue_		{0};
		uint8_t			downstream_issue_bit_hist_	{0};
		uint8_t			src_upstream_tier_		{0};	

		DOWNSTREAM_ONE(uint64_t downstream_glob_id, uint8_t downstream_state, uint8_t downstream_issue, uint8_t downstream_issue_bit_hist, uint8_t src_upstream_tier) noexcept
			: downstream_state_(downstream_state), downstream_issue_(downstream_issue), 
			downstream_issue_bit_hist_(downstream_issue_bit_hist), src_upstream_tier_(src_upstream_tier)
		{
			// As all Madhava's will of the same byteorder arch
			std::memcpy(downstream_glob_id_buf_, &downstream_glob_id, sizeof(downstream_glob_id_buf_));
		}	

		std::tuple<uint64_t, uint8_t, uint8_t, uint8_t, uint8_t> get_data() const noexcept
		{
			uint64_t		downstream_glob_id;

			std::memcpy(&downstream_glob_id, downstream_glob_id_buf_, sizeof(downstream_glob_id));

			return {downstream_glob_id, downstream_state_, downstream_issue_, downstream_issue_bit_hist_, src_upstream_tier_};
		}	
	};	

	uint64_t			issue_src_glob_id_		{0};
	uint64_t			issue_src_madhava_id_		{0};
	uint64_t			issue_src_time_usec_		{0};

	char				issue_src_comm_[TASK_COMM_LEN]	{};
	uint16_t			ndownstreams_			{0};
	bool				src_is_load_balanced_		{false};
	uint8_t				src_state_			{0};
	uint8_t				src_issue_			{0};
	uint8_t				issue_bit_hist_			{0};
	uint8_t				padding_len_			{0};

	static constexpr size_t		MAX_NUM_LISTENERS 		{512};		// Send in batches
	static constexpr size_t		MAX_DOWNSTREAM_IDS		{2048};
	static constexpr uint8_t	MAX_DOWNSTREAM_TIERS		{8};		// We scan only upto this many tiers downstream

	static constexpr size_t	get_max_elem_size() noexcept
	{
		return sizeof(MM_LISTENER_ISSUE_RESOL) + gy_align_up_2(sizeof(DOWNSTREAM_ONE) * sizeof(MAX_DOWNSTREAM_IDS), 8);
	}	

	inline size_t get_elem_size() const noexcept
	{
		return get_act_size() + padding_len_;
	}

	void set_padding_len() noexcept
	{
		static_assert(MM_LISTENER_ISSUE_RESOL::get_max_elem_size() * MAX_NUM_LISTENERS < MAX_COMM_DATA_SZ, "Max Network Payload size limit breached");

		size_t 		currsz, newsz;

		currsz 		= get_act_size();
		newsz 		= gy_align_up_2(currsz, 8);

		padding_len_	= newsz - currsz;
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept;

private :
	inline size_t get_act_size() const noexcept
	{
		return sizeof(*this) + ndownstreams_ * sizeof(DOWNSTREAM_ONE);
	}

};

struct alignas(8) MM_LISTENER_PING
{
	uint64_t			glob_id_;

	MM_LISTENER_PING(uint64_t glob_id) noexcept
		: glob_id_(glob_id)
	{}	

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
	{
		return (phdr->get_act_len() >= sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + pnotify->nevents_ * sizeof(MM_LISTENER_PING));
	}
};

struct alignas(8) MM_LISTENER_DELETE
{
	uint64_t			glob_id_;

	MM_LISTENER_DELETE(uint64_t glob_id) noexcept
		: glob_id_(glob_id)
	{}	

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
	{
		return (phdr->get_act_len() >= sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + pnotify->nevents_ * sizeof(MM_LISTENER_DELETE));
	}
};

struct alignas(8) MM_LISTENER_DEPENDS
{
	uint64_t			glob_id_;
	bool				delete_depends_;
	bool				is_load_balanced_;

	MM_LISTENER_DEPENDS(uint64_t glob_id, bool delete_depends, bool is_load_balanced = false) noexcept
		: glob_id_(glob_id), delete_depends_(delete_depends), is_load_balanced_(is_load_balanced)
	{}	

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
	{
		return (phdr->get_act_len() >= sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + pnotify->nevents_ * sizeof(MM_LISTENER_DEPENDS));
	}
};	


struct alignas(8) LISTENER_DOMAIN_NOTIFY
{
	uint64_t			glob_id_		{0};
	uint8_t				domain_string_len_	{0};
	uint8_t				tag_len_		{0};
	uint8_t				padding_len_		{0};

	/*char				domain_string_[issue_string_len_]; follows*/
	/*char				tag_[tag_len_]; follows*/
	/*char				padding_[padding_len_]; follows to make the entire 8 byte aligned */

	static constexpr size_t		MAX_NUM_LISTENERS 	{512};		// Send in small batches

	static constexpr size_t	get_max_elem_size() noexcept
	{
		return sizeof(LISTENER_DOMAIN_NOTIFY) + (1ul << (sizeof(domain_string_len_) * CHAR_BIT)) + (1ul << (sizeof(tag_len_) * CHAR_BIT));
	}	

	inline size_t get_elem_size() const noexcept
	{
		return get_act_size() + padding_len_;
	}

	void set_padding_len() noexcept
	{
		size_t 		currsz, newsz;

		currsz 		= get_act_size();
		newsz 		= gy_align_up_2(currsz, 8);

		padding_len_	= newsz - currsz;
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept;

private :
	inline size_t get_act_size() const noexcept
	{
		return sizeof(*this) + domain_string_len_ + tag_len_;
	}
};

struct alignas(8) ACTIVE_CONN_STATS
{
	uint64_t			listener_glob_id_		{0};
	uint64_t			cli_aggr_task_id_		{0};
	char				ser_comm_[TASK_COMM_LEN]	{};
	char				cli_comm_[TASK_COMM_LEN]	{};
	GY_MACHINE_ID 			remote_machine_id_;
	uint64_t			remote_madhava_id_		{0};
	uint64_t			bytes_sent_			{0};
	uint64_t			bytes_received_			{0};
	uint32_t			cli_delay_msec_			{0};
	uint32_t			ser_delay_msec_			{0};
	float				max_rtt_msec_			{0};
	uint16_t			active_conns_			{0};
	bool				cli_listener_proc_ : 1;
	bool				is_remote_listen_ : 1;
	bool				is_remote_cli_ : 1;

	static constexpr size_t		MAX_NUM_CONNS 			{2048};		// Send in batches

	// Default constructor not all fields are initialized...
	ACTIVE_CONN_STATS() noexcept	= default;	

	ACTIVE_CONN_STATS(std::pair<uint64_t, uint64_t> glob_id_cli_id, const char * ser_comm, const char * cli_comm, GY_MACHINE_ID remote_machine_id, uint64_t remote_madhava_id, \
				bool is_remote_listen, bool is_remote_cli) noexcept
		: listener_glob_id_(glob_id_cli_id.first), cli_aggr_task_id_(glob_id_cli_id.second), remote_machine_id_(remote_machine_id), remote_madhava_id_(remote_madhava_id)
	{

		GY_STRNCPY(ser_comm_, ser_comm, sizeof(ser_comm_));
		GY_STRNCPY(cli_comm_, cli_comm, sizeof(cli_comm_));

		cli_listener_proc_	= false;
		is_remote_listen_	= is_remote_listen;
		is_remote_cli_		= is_remote_cli;
	}	

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
	{
		return (phdr->get_act_len() >= sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + pnotify->nevents_ * sizeof(ACTIVE_CONN_STATS) && pnotify->nevents_ <= MAX_NUM_CONNS);
	}
};

struct alignas(8) LISTEN_TASKMAP_NOTIFY
{
	uint64_t			related_listen_id_;
	char				ser_comm_[TASK_COMM_LEN]	{};
	uint16_t			nlisten_			{0};
	uint16_t			naggr_taskid_			{0};

	/*
	 * uint64_t			listen_glob_id_[nlisten_] follows
	 * uint64_t			ser_aggr_task_id_[naggr_taskid_] follows
	 */

	static constexpr size_t		MAX_NUM_LISTENERS		{2048};		// Across a single event and total events as well
	static constexpr size_t		MAX_NUM_TASKS			{128};		// Across a single event
	

	LISTEN_TASKMAP_NOTIFY(uint64_t related_listen_id, const char * ser_comm, uint16_t nlisten, uint16_t naggr_taskid) noexcept
		: related_listen_id_(related_listen_id), nlisten_(nlisten), naggr_taskid_(naggr_taskid)
	{
		GY_STRNCPY(ser_comm_, ser_comm, sizeof(ser_comm_));
	}

	inline size_t get_elem_size() const noexcept
	{
		return sizeof(*this) + nlisten_ * sizeof(uint64_t) + naggr_taskid_ * sizeof(uint64_t);
	}	

	bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) const noexcept;
};	

struct alignas(8) HOST_INFO_NOTIFY
{
	char				distribution_name_[128]			{};
	char				kern_version_string_[64]		{};
	uint32_t			kern_version_num_			{0};	// 4.15.0-32-generic returns 0x040F00
	char				instance_id_[MAX_INSTANCE_ID_LEN]	{};
	char				cloud_type_[64]				{};

	char				processor_model_[128]			{};
	char				cpu_vendor_[64]				{};
	uint16_t			cores_online_				{0};
	uint16_t			cores_offline_				{0};
	uint16_t			max_cores_				{0};
	uint16_t			isolated_cores_				{0};
	
	uint32_t			ram_mb_					{0};
	uint32_t			corrupted_ram_mb_			{0};

	uint16_t			num_numa_nodes_				{0};
	uint16_t			max_cores_per_socket_			{0};
	uint16_t			threads_per_core_			{0};

	time_t				boot_time_sec_				{0};

	uint32_t			l1_dcache_kb_				{0};
	uint32_t			l2_cache_kb_				{0};
	uint32_t			l3_cache_kb_				{0};
	uint32_t			l4_cache_kb_				{0};

	bool				is_virtual_cpu_				{false};
	char				virtualization_type_[64]		{};

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
	{
		return ((phdr->get_act_len() >= sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + sizeof(HOST_INFO_NOTIFY)) && pnotify->nevents_ == 1);
	}
};	

struct alignas(8) HOST_CPU_MEM_CHANGE
{
	bool				cpu_changed_			{false};
	uint16_t			new_cores_online_		{0};
	uint16_t			new_cores_offline_		{0};
	uint16_t			old_cores_online_		{0};
	uint16_t			old_cores_offline_		{0};

	bool				mem_changed_			{false};
	uint32_t			new_ram_mb_			{0};
	uint32_t			old_ram_mb_			{0};

	bool				mem_corrupt_changed_		{false};
	uint32_t			new_corrupted_ram_mb_		{0};
	uint32_t			old_corrupted_ram_mb_		{0};

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
	{
		return ((phdr->get_act_len() >= sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + sizeof(HOST_CPU_MEM_CHANGE)) && pnotify->nevents_ == 1);
	}
};	

struct alignas(8) NOTIFICATION_MSG
{
	NOTIFY_MSGTYPE_E		type_			{NOTIFY_INFO};
	uint16_t			msglen_			{0};
	uint8_t				padding_len_		{0};

	/*char				msg_[msglen_]; follows*/
	/*char				padding_[padding_len_]; follows to make the entire 8 byte aligned */

	static constexpr size_t		MAX_NOTIFY_LEN		{512};
	static constexpr size_t		MAX_NUM_MSG		{128};

	NOTIFICATION_MSG()		= default;

	NOTIFICATION_MSG(NOTIFY_MSGTYPE_E type, uint16_t msglen) noexcept
		: type_(type), msglen_(msglen)
	{
		set_padding_len();
	}

	static constexpr size_t	get_max_elem_size() noexcept
	{
		return sizeof(NOTIFICATION_MSG) + MAX_NOTIFY_LEN;
	}	

	inline size_t get_elem_size() const noexcept
	{
		return get_act_size() + padding_len_;
	}

	void set_padding_len() noexcept
	{
		size_t 		currsz, newsz;

		currsz 		= get_act_size();
		newsz 		= gy_align_up_2(currsz, 8);

		padding_len_	= newsz - currsz;
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept;

private :
	inline size_t get_act_size() const noexcept
	{
		return sizeof(*this) + msglen_;
	}
};	

struct NOTIFICATION_MSG_BUF : public NOTIFICATION_MSG, public CHAR_BUF<NOTIFICATION_MSG::MAX_NOTIFY_LEN> 
{};


struct alignas(8) AGGR_TASK_HIST_STATS
{
	uint64_t			aggr_task_id_		{0};
	uint64_t			starttimeusec_		{0};
	uint32_t			p95_cpu_pct_		{0};
	uint32_t			p95_cpu_delay_ms_	{0};
	uint32_t			p95_blkio_delay_ms_	{0};
	uint32_t			nprocs_			{0};
	uint32_t			nthreads_		{0};
	uint16_t			max_cores_allowed_	{0};
	uint8_t				cpu_cg_pct_limit_	{0};
	uint8_t				max_mem_cg_pct_rss_	{0};

	static constexpr size_t		MAX_NUM_TASKS 	{1200};

	AGGR_TASK_HIST_STATS() noexcept	= default;

	AGGR_TASK_HIST_STATS(uint64_t aggr_task_id, uint64_t starttimeusec) noexcept :
		aggr_task_id_(aggr_task_id), starttimeusec_(starttimeusec)
	{}

	static constexpr size_t	get_max_elem_size() noexcept
	{
		return sizeof(AGGR_TASK_HIST_STATS);
	}	

	inline size_t get_elem_size() const noexcept
	{
		return get_act_size();
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
	{
		return (phdr->get_act_len() >= sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + pnotify->nevents_ * sizeof(AGGR_TASK_HIST_STATS));
	}

private :
	inline size_t get_act_size() const noexcept
	{
		return sizeof(*this);
	}
};

struct alignas(8) SM_ALERT_ADEF_NEW
{
	uint32_t			adef_id_		{0};
	ADEF_STATE_E			state_			{ADEFSTATE_ENABLED};
	SUBSYS_CLASS_E			asubsys_		{SUBSYS_HOST};
	bool				isrealtime_		{false};
	bool				for_partha_		{false};
	uint16_t			lenjson_		{0};
	uint8_t				padding_len_		{0};

	/*char				json_[lenjson_] follows;*/
	/*char				padding_[padding_len_]; follows to make the entire 8 byte aligned */

	static constexpr size_t		MAX_NUM_DEFS 		{128};	// Send in batches

	SM_ALERT_ADEF_NEW() noexcept		= default;

	SM_ALERT_ADEF_NEW(uint32_t adef_id, uint32_t lenjson, ADEF_STATE_E state, SUBSYS_CLASS_E asubsys, bool isrealtime, bool for_partha) noexcept
		: adef_id_(adef_id), state_(state), asubsys_(asubsys), isrealtime_(isrealtime), for_partha_(for_partha), lenjson_(lenjson)
	{
		set_padding_len();
	}	

	inline size_t get_elem_size() const noexcept
	{
		return get_act_size() + padding_len_;
	}	

	void set_padding_len() noexcept
	{
		size_t 			currsz, newsz;

		currsz = get_act_size();
		newsz = gy_align_up_2(currsz, 8);

		padding_len_		= newsz - currsz;
	}

	bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) const noexcept;

private :
	inline size_t get_act_size() const noexcept
	{
		return sizeof(*this) + lenjson_; 
	}	
};	

struct alignas(8) SM_ALERT_ADEF_UPD
{
	uint32_t			adef_id_		{0};
	ALERT_MSG_TYPE			type_			{ALERT_ADEF_ENABLE};
	bool				isrealtime_		{false};
	bool				for_partha_		{false};
	
	SM_ALERT_ADEF_UPD() noexcept	= default;

	SM_ALERT_ADEF_UPD(uint32_t adef_id, ALERT_MSG_TYPE type, bool isrealtime, bool for_partha) noexcept :
		adef_id_(adef_id), type_(type), isrealtime_(isrealtime), for_partha_(for_partha)
	{}

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
	{
		return (phdr->get_act_len() >= sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + pnotify->nevents_ * sizeof(SM_ALERT_ADEF_UPD));
	}
};


struct alignas(8) SM_ALERT_STAT_DISABLE
{
	time_t				tdisable_end_;
	
	SM_ALERT_STAT_DISABLE() noexcept	= default;

	SM_ALERT_STAT_DISABLE(time_t tdisable_end) noexcept :
		tdisable_end_(tdisable_end)
	{}

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
	{
		return ((phdr->get_act_len() >= sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + sizeof(SM_ALERT_STAT_DISABLE)) && pnotify->nevents_ == 1);
	}
};

struct alignas(8) ALERT_STAT_INFO
{
	time_t				talert_			{0};
	uint32_t			alertid_		{0};
	uint32_t			adef_id_		{0};
	ADEF_HDLR_E			ahdlr_			{AHDLR_MADHAVA};
	SUBSYS_CLASS_E			asubsys_		{SUBSYS_HOST};
	uint8_t				numhits_		{1};
	uint8_t				numcheckfor_		{0};
	uint8_t				nrepeats_		{0};
	bool				isrealtime_		{false};
	uint16_t			lenjson_		{0};
	uint8_t				padding_len_		{0};

	/*char				json_[lenjson_] follows;*/
	/*char				padding_[padding_len_]; follows to make the entire 8 byte aligned */

	static constexpr size_t		MAX_NUM_STATS 		{128};	// Send in batches

	ALERT_STAT_INFO() noexcept		= default;

	ALERT_STAT_INFO(time_t talert, uint32_t alertid, uint32_t adef_id, ADEF_HDLR_E ahdlr, SUBSYS_CLASS_E asubsys, uint8_t numhits, uint8_t numcheckfor, uint8_t nrepeats, \
					bool isrealtime, uint32_t lenjson) noexcept
		: talert_(talert), alertid_(alertid), adef_id_(adef_id), ahdlr_(ahdlr), asubsys_(asubsys), numhits_(numhits), numcheckfor_(numcheckfor), nrepeats_(nrepeats), 
		isrealtime_(isrealtime), lenjson_(lenjson)
	{
		set_padding_len();
	}	

	inline size_t get_elem_size() const noexcept
	{
		return get_act_size() + padding_len_;
	}	

	void set_padding_len() noexcept
	{
		size_t 			currsz, newsz;

		currsz = get_act_size();
		newsz = gy_align_up_2(currsz, 8);

		padding_len_		= newsz - currsz;
	}

	bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) const noexcept;

private :
	inline size_t get_act_size() const noexcept
	{
		return sizeof(*this) + lenjson_; 
	}	
};	

struct alignas(8) ALERT_STAT_CLOSE
{
	time_t				tlast_hit_		{0};
	time_t				tcurr_			{0};
	uint32_t			alertid_		{0};
	uint32_t			adef_id_		{0};
	bool				is_force_close_		{false};		
	bool				isrealtime_		{false};
	
	ALERT_STAT_CLOSE() noexcept	= default;

	ALERT_STAT_CLOSE(time_t tlast_hit, time_t tcurr, uint32_t alertid, uint32_t adef_id, bool is_force_close, bool isrealtime) noexcept :
		tlast_hit_(tlast_hit), tcurr_(tcurr), alertid_(alertid), adef_id_(adef_id), is_force_close_(is_force_close), isrealtime_(isrealtime)
	{}

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
	{
		return (phdr->get_act_len() >= sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + pnotify->nevents_ * sizeof(ALERT_STAT_CLOSE));
	}
};

struct alignas(8) MS_CLUSTER_STATE
{
	struct alignas(8) STATE_ONE
	{
		uint32_t			nhosts_			{0};

		uint32_t			ntasks_issue_		{0};
		uint32_t			ntaskissue_hosts_	{0};
		uint32_t			ntasks_			{0};

		uint32_t			nsvc_issue_		{0};
		uint32_t			nsvcissue_hosts_	{0};
		uint32_t			nsvc_			{0};
		uint32_t			total_qps_		{0};
		uint32_t			svc_net_mb_		{0};

		uint32_t			ncpu_issue_		{0};
		uint32_t			nmem_issue_		{0};

		void add_stats(const STATE_ONE & state) noexcept
		{
			nhosts_			+= state.nhosts_;
			ntasks_issue_		+= state.ntasks_issue_;
			ntaskissue_hosts_	+= state.ntaskissue_hosts_;
			ntasks_			+= state.ntasks_;

			nsvc_issue_		+= state.nsvc_issue_;
			nsvcissue_hosts_	+= state.nsvcissue_hosts_;
			nsvc_			+= state.nsvc_;
			total_qps_		+= state.total_qps_;
			svc_net_mb_		+= state.svc_net_mb_;

			ncpu_issue_		+= state.ncpu_issue_;
			nmem_issue_		+= state.nmem_issue_;
		}	
	};

	STATE_ONE			state_;
	char				clustname_[MAX_CLUSTER_NAME_LEN];

	static constexpr size_t		MAX_NUM_CLUSTERS 		{512};	// Send in batches

	MS_CLUSTER_STATE(const STATE_ONE & state, const char *clustname) noexcept
		: state_(state)
	{
		GY_STRNCPY(clustname_, clustname, sizeof(clustname_));
	}	

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
	{
		return (phdr->get_act_len() >= sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + pnotify->nevents_ * sizeof(MS_CLUSTER_STATE) && pnotify->nevents_ <= MAX_NUM_CLUSTERS);
	}	

};

struct alignas(8) MS_PARTHA_PING
{
	GY_MACHINE_ID 			machine_id_;
	bool				is_deleted_		{false};

	static constexpr size_t		MAX_PARTHA_PING		{MAX_PARTHA_PER_MADHAVA};

	MS_PARTHA_PING(GY_MACHINE_ID machine_id, bool is_deleted = false) noexcept
		: machine_id_(machine_id), is_deleted_(is_deleted)
	{}

	MS_PARTHA_PING() noexcept	= default;

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
	{
		return (phdr->get_act_len() >= sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + pnotify->nevents_ * sizeof(MS_PARTHA_PING) && pnotify->nevents_ <= MAX_PARTHA_PING);
	}
};

struct alignas(8) MS_REG_PARTHA
{
	GY_MACHINE_ID 			machine_id_;
	uint32_t			comm_version_;
	uint32_t			partha_version_;
	char				hostname_[MAX_DOMAINNAME_SIZE];
	char				cluster_name_[MAX_CLUSTER_NAME_LEN];
	char				region_name_[comm::MAX_ZONE_LEN];
	char				zone_name_[comm::MAX_ZONE_LEN];
	uint32_t			kern_version_num_;

	static constexpr size_t		MAX_REG_PARTHA		{MAX_PARTHA_PER_MADHAVA};

	MS_REG_PARTHA() noexcept	= default;

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept;
};

struct alignas(8) REQ_TRACE_TRAN : public API_TRAN
{
	using API_TRAN::API_TRAN;

	static bool validate(const comm::COMM_HEADER *phdr, const comm::EVENT_NOTIFY *pnotify) noexcept;
};	

struct alignas(8) REQ_TRACE_SET
{
	uint64_t			glob_id_		{0};
	NS_IP_PORT			ns_ip_port_;
	time_t				tend_			{0};
	char				comm_[TASK_COMM_LEN]	{};
	bool				enable_cap_		{false};

	static constexpr size_t		MAX_REQ_TRACE_ELEM	{128};

	// To enable capture
	REQ_TRACE_SET(uint64_t glob_id, const NS_IP_PORT & ns_ip_port, const char *comm, time_t tend) noexcept
		: glob_id_(glob_id), ns_ip_port_(ns_ip_port), tend_(tend), enable_cap_(true)
	{
		GY_STRNCPY_0(comm_, comm, sizeof(comm_));
	}	

	// To disable capture
	REQ_TRACE_SET(uint64_t glob_id, const NS_IP_PORT & ns_ip_port, const char *comm) noexcept
		: glob_id_(glob_id), ns_ip_port_(ns_ip_port), enable_cap_(false)
	{
		GY_STRNCPY_0(comm_, comm, sizeof(comm_));
	}	

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) const noexcept
	{	
		return (phdr->get_act_len() >= sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + pnotify->nevents_ * sizeof(REQ_TRACE_SET) && pnotify->nevents_ <= MAX_REQ_TRACE_ELEM);
	}	
};	

struct alignas(8) REQ_TRACE_STATUS
{
	uint64_t			glob_id_			{0};
	NS_IP_PORT			ns_ip_port_;
	uint64_t			nrequests_			{0};
	uint64_t			nerrors_			{0};
	char				comm_[TASK_COMM_LEN]		{};
	PROTO_CAP_STATUS_E		status_				{CAPSTAT_UNINIT};
	char				errstr_[COMM_MAX_ERROR_LEN];

	static constexpr size_t		MAX_REQ_TRACE_ELEM		{128};

	REQ_TRACE_STATUS(uint64_t glob_id, const NS_IP_PORT & ns_ip_port, const char *comm, PROTO_CAP_STATUS_E status, 
					const char *errstr = nullptr, uint64_t nrequests = 0, uint64_t nerrors = 0) noexcept
		: glob_id_(glob_id), ns_ip_port_(ns_ip_port), nrequests_(nrequests), nerrors_(nerrors), status_(status)
	{
		GY_STRNCPY_0(comm_, comm, sizeof(comm_));

		if (errstr && *errstr) {
			GY_STRNCPY(errstr_, errstr, sizeof(errstr_));
		}	
		else {
			*errstr_ = 0;
		}	
	}	

	REQ_TRACE_STATUS() noexcept	= default;

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) const noexcept
	{	
		return (phdr->get_act_len() >= sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + pnotify->nevents_ * sizeof(REQ_TRACE_STATUS) && pnotify->nevents_ <= MAX_REQ_TRACE_ELEM);
	}	
};	


struct alignas(8) SM_REQ_TRACE_DEF_NEW
{
	uint32_t			reqdefid_		{0};
	bool				enable_cap_		{false};
	time_t				tend_			{0};
	char				name_[64]		{};
	uint16_t			ncap_glob_id_arr_	{0};
	uint16_t			lencrit_		{0};
	uint8_t				padding_len_		{0};

	// Either ncap_glob_id_arr_ or lencrit_ can be specified

	/*uint64_t			cap_glob_id_arr_[ncap_glob_id_arr_] follows;*/
	/*char				crit_[lencrit_] follows;*/
	/*char				padding_[padding_len_]; follows to make the entire 8 byte aligned */

	static constexpr size_t		MAX_GLOB_ID_ARR 	{2048};
	static constexpr size_t		MAX_NUM_DEFS 		{128};	// Send in batches

	SM_REQ_TRACE_DEF_NEW() noexcept				= default;

	SM_REQ_TRACE_DEF_NEW(uint32_t reqdefid, const char *name, bool enable_cap, time_t tend, uint16_t lencrit) noexcept
		: reqdefid_(reqdefid), enable_cap_(enable_cap), tend_(tend), lencrit_(lencrit)
	{
		GY_STRNCPY_0(name_, name, sizeof(name_));
		set_padding_len();
	}	

	// Only fixed svcs as per ncap_glob_id_arr
	SM_REQ_TRACE_DEF_NEW(uint32_t reqdefid, uint16_t ncap_glob_id_arr, const char *name, bool enable_cap, time_t tend) noexcept
		: reqdefid_(reqdefid), enable_cap_(enable_cap), tend_(tend), ncap_glob_id_arr_(ncap_glob_id_arr)
	{
		GY_STRNCPY_0(name_, name, sizeof(name_));
	}	

	inline size_t get_elem_size() const noexcept
	{
		return get_act_size() + padding_len_;
	}	

	void set_padding_len() noexcept
	{
		size_t 			currsz, newsz;

		currsz = get_act_size();
		newsz = gy_align_up_2(currsz, 8);

		padding_len_		= newsz - currsz;
	}


	bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) const noexcept;

private :
	inline size_t get_act_size() const noexcept
	{
		return sizeof(*this) + ncap_glob_id_arr_ * sizeof(uint64_t) + lencrit_; 
	}
};	

struct alignas(8) SM_REQ_TRACE_DEF_DISABLE
{
	uint32_t			reqdefid_		{0};
	time_t				tend_			{0};
	
	SM_REQ_TRACE_DEF_DISABLE() noexcept	= default;

	SM_REQ_TRACE_DEF_DISABLE(uint32_t reqdefid, time_t tend) noexcept :
		reqdefid_(reqdefid), tend_(tend)
	{}

	uint32_t get_elem_size() const noexcept
	{
		return sizeof(*this);
	}

	static bool validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
	{
		return (phdr->get_act_len() >= sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + pnotify->nevents_ * sizeof(SM_REQ_TRACE_DEF_DISABLE));
	}
};


} // namespace comm
} // namespace gyeeta

