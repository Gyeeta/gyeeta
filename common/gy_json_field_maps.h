//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"
#include			"gy_web_proto.h"

namespace gyeeta {

/*
 * Structures for mapping fields between JSON web queries and Postgres, Class Objects 
 * for use by Web Queries, Alert definitions, Scheduled queries, etc.
 */
static constexpr size_t		MAX_COLUMN_LIST			{50};
static constexpr size_t		MAX_ONE_CRITERION_LEN		{4096};				// Max strlen of a single criterion string
static constexpr size_t		MAX_COMP_IN_ELEMS		{64};				// Max Elements within 1 in / notin comparator
static constexpr size_t		MAX_ONE_GROUP_CRITERIA		{64};				// Max Criteria within one Criteria Group
static constexpr size_t		MAX_CRITERIA_GROUPS		{MAX_ONE_GROUP_CRITERIA};	// Max Criteria groups within a query
static constexpr size_t		MAX_QUERY_CRITERIA		{256};				// Max # Criteria after Disjunctive Normalization of a query
static constexpr size_t		MAX_QUERY_STRLEN  		{10 * 1024};

enum SUBSYS_CLASS_E : int
{
	SUBSYS_HOST		= 0,
	SUBSYS_HOSTSTATE,
	SUBSYS_CPUMEM,
	SUBSYS_SVCSTATE,
	SUBSYS_SVCINFO,
	SUBSYS_EXTSVCSTATE,
	SUBSYS_SVCSUMM,		
	SUBSYS_ACTIVECONN,
	SUBSYS_EXTACTIVECONN,
	SUBSYS_CLIENTCONN,		
	SUBSYS_EXTCLIENTCONN,
	SUBSYS_SVCPROCMAP,
	SUBSYS_NOTIFYMSG,
	SUBSYS_PROCSTATE,
	SUBSYS_PROCINFO,
	SUBSYS_EXTPROCSTATE,
	SUBSYS_TOPCPU,
	SUBSYS_TOPPGCPU,
	SUBSYS_TOPRSS,
	SUBSYS_TOPFORK,
	SUBSYS_HOSTINFO,
	SUBSYS_CLUSTERSTATE,
	SUBSYS_SVCMESHCLUST,
	SUBSYS_SVCIPCLUST,
	SUBSYS_ALERTS,
	SUBSYS_ALERTDEF,
	SUBSYS_INHIBITS,
	SUBSYS_SILENCES,
	SUBSYS_ACTIONS,

	SUBSYS_MADHAVALIST,
	SUBSYS_TAGS,

	SUBSYS_SHYAMASTATUS,
	SUBSYS_MADHAVASTATUS,
	SUBSYS_PARTHALIST,

	SUBSYS_CGROUPSTATE,

	SUBSYS_MAX
};	


enum JSON_TYPES_E : uint8_t
{
	JSON_NUMBER		= 0,
	JSON_STRING,
	JSON_BOOL,
	
	JSON_MAX_TYPE
};	

static const char * get_json_type_str(uint8_t type) noexcept
{
	static constexpr const char	*typestr[JSON_MAX_TYPE] { "number", "string", "bool", }; 

	if (type < JSON_MAX_TYPE) {
		return typestr[type];
	}

	return "unknown";
}	


static constexpr uint8_t	JSON_EXPR_TYPE = JSON_MAX_TYPE;

enum NUMBER_TYPES_E : uint8_t
{
	NUM_INT8		= 0,
	NUM_INT16,
	NUM_INT32,
	NUM_INT64,
	NUM_DOUBLE,

	NUM_NAN,
};

enum DB_STR_TYPE_E : uint8_t
{
	DB_STR_NONE		= 0,
	DB_STR_TEXT,		// text and varchar types
	DB_STR_OCHAR,		// OIDchar type
	DB_RAW_STRING,		// Another data type saved as a string in DB e.g. JSON Array stored as a string and which should not be sent as a string for a query output
};	

enum AGGR_OPER_E : uint8_t
{
	AOPER_UNSPEC		= 0,
	AOPER_SUM,
	AOPER_AVG,
	AOPER_MAX,
	AOPER_MIN,
	AOPER_COUNT,
	AOPER_PERCENTILE,
	AOPER_FIRST_ELEM,
	AOPER_LAST_ELEM,
	AOPER_BOOL_OR,
	AOPER_BOOL_AND,

	AOPER_GROUPBY,		// text field
};	

enum ADEF_HDLR_E : uint8_t
{
	AHDLR_PARTHA		= 0,
	AHDLR_MADHAVA,
	AHDLR_SHYAMA,
};

enum ALERT_KEY_TYPE_E : uint8_t
{
	AKEY_INVALID		= 0,
	AKEY_ID,
	AKEY_MACHID,
	AKEY_VOID_PTR,
};	

enum ALERT_MSG_TYPE : uint8_t
{
	ALERT_ASTAT_ID		= 0,
	ALERT_ASTAT_MACHID,

	// Do not change the order of the following states
	ALERT_ADEF_NEW,

	ALERT_ADEF_ENABLE,
	ALERT_ADEF_DISABLE,
	ALERT_ADEF_MUTE,
	ALERT_ADEF_SILENCE,
	ALERT_ADEF_INHIBIT,
	ALERT_ADEF_DELETE,

	ALERT_ADEF_MAX
};

enum ADEF_STATE_E : uint8_t
{
	ADEFSTATE_DISABLED		= 0,
	ADEFSTATE_MUTED,
	ADEFSTATE_INHIBITED,
	ADEFSTATE_SILENCED,

	ADEFSTATE_ENABLED,
};	

enum ERR_CODES_E : int
{
	ERR_SUCCESS			= 0,
	
	/*
	 * Warnings from 1 to 100
	 */
	ERR_WARN_1			= 1,

	ERR_WARN_TEMP_UNAVAIL,

	ERR_WARN_100			= 100,

	/*
	 * Errors from 101 - 199 
	 * Initial errors during registration/connect phase
	 */
	ERR_MIN_VALUE			= 101,

	ERR_PROTOCOL_VERSION		= 101,
	ERR_MADHAVA_VERSION,
	ERR_PARTHA_VERSION,
	ERR_SHYAMA_VERSION,
	ERR_NODE_VERSION,
	ERR_SYSTEM_TIME_MISMATCH,
	ERR_INVALID_ACCESS_KEY,
	ERR_ACCESS_KEY_EXPIRED,
	ERR_ACCESS_KEY_HOSTS_EXCEEDED,
	ERR_HOST_OVERLOADED,
	ERR_ID_REUSED,
	ERR_INVALID_MACHINE_ID,
	ERR_INVALID_ID,
	ERR_NOT_VALIDATED,
	ERR_MISMATCH_ID,
	ERR_MAX_LIMIT,	
	ERR_MADHAVA_UNAVAIL,
	ERR_INVALID_SECRET,

	ERR_INTERNAL_MAX		= 199,

	/*
	 * Web Client Facing Error codes
	 */
	ERR_STATUS_OK			= 200,

	ERR_INVALID_REQUEST		= 400,
	ERR_CONFLICTS			= 409,
	ERR_DATA_NOT_FOUND		= 410,
	ERR_SERV_ERROR			= 500,
	ERR_TIMED_OUT			= 504,
	ERR_BLOCKING_ERROR		= 503,
	ERR_MAX_SZ_BREACHED		= 507,
	ERR_SYSERROR			= 510,

	ERR_MAX_NUM
};

/*
 * System Object states.
 *
 * For example in case of CPU utilization, the following could be a criteria :
 *
 * CPU <  10% -> Idle
 * CPU <  40% -> Good
 * CPU <  60% -> OK
 * CPU <  80% -> Bad
 * CPU >= 80% -> Severe
 */ 
enum OBJ_STATE_E : uint8_t
{
	STATE_IDLE		= 0,
	STATE_GOOD		= 1,
	STATE_OK		= 2,
	STATE_BAD		= 3,
	STATE_SEVERE		= 4,
	STATE_DOWN		= 5,
};	

static constexpr const char * get_state_color(OBJ_STATE_E lstate) noexcept
{
	switch (lstate) {
	
	case STATE_IDLE 	:	return GY_COLOR_BOLD_GREEN;
	case STATE_GOOD 	:	return GY_COLOR_GREEN;
	case STATE_OK 		:	return GY_COLOR_YELLOW;
	case STATE_BAD 		:	return GY_COLOR_RED;
	case STATE_SEVERE 	:	return GY_COLOR_BOLD_RED;
	case STATE_DOWN		:	return GY_COLOR_BOLD_RED_UNDERLINE;

	default			: 	return "";		
	}	
}	

static constexpr const char * state_to_string(OBJ_STATE_E lstate) noexcept
{
	switch (lstate) {
	
	case STATE_IDLE 	:	return "Idle";
	case STATE_GOOD 	:	return "Good";
	case STATE_OK 		:	return "OK";
	case STATE_BAD 		:	return "Bad";
	case STATE_SEVERE 	:	return "Severe";
	case STATE_DOWN		:	return "Down";

	default			: 	return "Unknown";		
	}	
}

static std::pair<const char *, size_t> state_to_stringlen(OBJ_STATE_E lstate) noexcept
{
	switch (lstate) {
	
	case STATE_IDLE 	:	return {"Idle", GY_CONST_STRLEN("Idle")};
	case STATE_GOOD 	:	return {"Good", GY_CONST_STRLEN("Good")};
	case STATE_OK 		:	return {"OK", GY_CONST_STRLEN("OK")};
	case STATE_BAD 		:	return {"Bad", GY_CONST_STRLEN("Bad")};
	case STATE_SEVERE 	:	return {"Severe", GY_CONST_STRLEN("Severe")};
	case STATE_DOWN		:	return {"Down", GY_CONST_STRLEN("Down")};

	default			: 	return {"Unknown", GY_CONST_STRLEN("Unknown")};		
	}	
}



static OBJ_STATE_E state_from_string(const char *state) noexcept
{
	static constexpr uint32_t 	shash[] = { 
						fnv1_consthash("Idle"), fnv1_consthash("Good"), fnv1_consthash("OK"), 
						fnv1_consthash("Bad"), fnv1_consthash("Severe"), fnv1_consthash("Down"),
					};

	uint32_t			rhash = fnv1_hash(state, strlen(state));

	for (uint32_t i = 0; i < GY_ARRAY_SIZE(shash); i++) {
		if (rhash == shash[i]) {
			return OBJ_STATE_E(i);
		}	
	}	

	return STATE_DOWN;
}

enum CPU_ISSUE_SOURCE : uint8_t
{
	ISSUE_CPU_NONE			= 0,
	ISSUE_CPU_SATURATED,
	ISSUE_CORE_SATURATED,
	ISSUE_CPU_IOWAIT,
	ISSUE_CPU_CONTEXT_SWITCH,			 
	ISSUE_FORKS_HIGH,
	ISSUE_PROCS_RUNNING_HIGH,
};
	
static constexpr const char * issue_to_string(CPU_ISSUE_SOURCE issue) noexcept
{
	switch (issue) {

	case ISSUE_CPU_NONE :			return "None";
	case ISSUE_CPU_SATURATED :		return "CPU Utilization Saturated";
	case ISSUE_CORE_SATURATED : 		return "Individual CPU core Saturation";
	case ISSUE_CPU_IOWAIT :			return "CPU IO Waits Issue";
	case ISSUE_CPU_CONTEXT_SWITCH :		return "Context Switches Issue";
	case ISSUE_FORKS_HIGH :			return "High New Process Creation Rate";
	case ISSUE_PROCS_RUNNING_HIGH :		return "Runnable Processes Count High";

	default : 				return "Unknown";
	}
}	

enum MEM_ISSUE_SOURCE : uint8_t
{
	ISSUE_MEM_NONE			= 0,
	ISSUE_RSS_SATURATED,
	ISSUE_COMMIT_SATURATED,
	ISSUE_MEM_PG_INOUT,
	ISSUE_MEM_SWP_INOUT,
	ISSUE_MEM_ALLOCSTALL,
	ISSUE_OOM_KILL,
	ISSUE_SWAP_FULL,
};
	
static constexpr const char * issue_to_string(MEM_ISSUE_SOURCE issue) noexcept
{
	switch (issue) {

	case ISSUE_MEM_NONE :			return "None";
	case ISSUE_RSS_SATURATED :		return "Resident Memory RSS Saturated";
	case ISSUE_COMMIT_SATURATED :		return "Commit Memory Saturated";
	case ISSUE_MEM_PG_INOUT :		return "High Memory Paging";
	case ISSUE_MEM_SWP_INOUT :		return "Memory Paging and Swapping";
	case ISSUE_MEM_ALLOCSTALL :		return "Memory Page Reclaim Stalls";
	case ISSUE_OOM_KILL :			return "Out of Memory OOM process kills";
	case ISSUE_SWAP_FULL :			return "Low Free Swap Space";

	default : 				return "Unknown";
	}
}	

enum TASK_ISSUE_SOURCE : uint8_t
{
	ISSUE_TASK_NONE				= 0,

	/*
	 * Keep the order of delays before ISSUE_VOL_CONTEXT_SWITCH
	 * as it is checked in socket handler
	 */
	ISSUE_CPU_DELAY,
	ISSUE_BLKIO_DELAY,
	ISSUE_SWAPIN_DELAY,
	ISSUE_RECLAIM_DELAY,
	ISSUE_THRASHING_DELAY,

	ISSUE_VOL_CONTEXT_SWITCH,
	ISSUE_INVOL_CONTEXT_SWITCH,

	ISSUE_MAJOR_PAGE_FAULT,
	ISSUE_CPU_UTIL_HIGH,

	ISSUE_TASK_STOPPED,
	ISSUE_TASK_PTRACED,
};

static constexpr const char * issue_to_string(TASK_ISSUE_SOURCE issue) noexcept
{
	switch (issue) {

	case ISSUE_TASK_NONE :			return "None";
	case ISSUE_CPU_DELAY :			return "Process CPU Delay"; 
	case ISSUE_BLKIO_DELAY :		return "Process Block IO Delay"; 
	case ISSUE_SWAPIN_DELAY :		return "Process Memory SwapIn Delay"; 
	case ISSUE_RECLAIM_DELAY :		return "Process Memory Reclaim Delay"; 
	case ISSUE_THRASHING_DELAY :		return "Process Memory Thrashing Delay"; 
	case ISSUE_VOL_CONTEXT_SWITCH :		return "Process Voluntary Context Switches"; 
	case ISSUE_INVOL_CONTEXT_SWITCH :	return "Process Involuntary Context Switches"; 
	case ISSUE_MAJOR_PAGE_FAULT :		return "Process Major Page Fault"; 
	case ISSUE_CPU_UTIL_HIGH :		return "Process High CPU Utilization"; 
	case ISSUE_TASK_STOPPED :		return "Process Suspended"; 
	case ISSUE_TASK_PTRACED :		return "Process is under ptrace debugging"; 

	default : 				return "Unknown";
	}	
}


enum LISTENER_ISSUE_SRC : uint8_t
{
	ISSUE_LISTEN_NONE		= 0,

	ISSUE_LISTENER_TASKS,
	
	ISSUE_QPS_HIGH,
	ISSUE_ACTIVE_CONN_HIGH,
	ISSUE_HTTP_SERVER_ERRORS,
	
	ISSUE_OS_CPU,
	ISSUE_OS_MEMORY,

	ISSUE_DEPENDENT_SERVER_LISTENER,

	ISSUE_SRC_UNKNOWN,
};	

static constexpr const char * issue_to_string(LISTENER_ISSUE_SRC issue) noexcept
{
	switch (issue) {

	case ISSUE_LISTEN_NONE :		return "None";

	case ISSUE_LISTENER_TASKS :	 	return "Listener Task (Process) Issue";
	
	case ISSUE_QPS_HIGH :			return "High QPS (Queries/sec)";
	case ISSUE_ACTIVE_CONN_HIGH :		return "High Active Connections count";
	case ISSUE_HTTP_SERVER_ERRORS :		return "HTTP 5xx Server Errors";
				
	case ISSUE_OS_CPU :			return "Host CPU Issue";
	case ISSUE_OS_MEMORY :			return "Host Virtual Memory Issue";
	case ISSUE_DEPENDENT_SERVER_LISTENER :	return "Dependent Listener Issue";

	case ISSUE_SRC_UNKNOWN :
	default :
						return "Issue Source cannot be determined";
	}	
}

enum NOTIFY_MSGTYPE_E : uint8_t
{
	NOTIFY_INFO		= 0,
	NOTIFY_WARN,
	NOTIFY_ERROR,
	NOTIFY_SEVERE
};

static constexpr const char * notify_to_string(NOTIFY_MSGTYPE_E type) noexcept
{
	switch (type) {

	case NOTIFY_INFO	:		return "Info";
	case NOTIFY_WARN	:		return "Warn";
	case NOTIFY_ERROR	:		return "Error";
	case NOTIFY_SEVERE	:		return "Severe";

	default 		:		return "Unknown";
	}	
}


static constexpr size_t		MAX_MULTI_TOPN				{50};

#define GYSLEN			GY_CONST_STRLEN

typedef std::pair<const char *, size_t> (*DB_FIELD_OPER)(const void *, size_t, char *pscratch, uint32_t szscrath);

struct JSON_DB_MAPPING
{
	const char		*jsonfield		{nullptr};
	const char		*dbcolname		{nullptr};
	int			szjson			{0};
	uint32_t		jsoncrc			{0};
	SUBSYS_CLASS_E		subsys			{SUBSYS_HOST};
	JSON_TYPES_E		jsontype		{JSON_NUMBER};
	NUMBER_TYPES_E		numtype			{NUM_INT8};
	const char		*dbtype			{0};
	DB_STR_TYPE_E		dbstrtype		{DB_STR_NONE};
	DB_FIELD_OPER		oper			{nullptr};
	DB_FIELD_OPER		dboper			{nullptr};
	const char		*coldesc		{nullptr};
};	

struct DB_AGGR_INFO
{
	const char		*dbexpr			{nullptr};
	uint32_t		jsoncrc			{0};	
	const char		*dbfieldname		{nullptr};
	const char		*dbfieldtype		{nullptr};
	AGGR_OPER_E		dflt_aggr		{AOPER_UNSPEC};			
	bool			ignore_sum		{false};
	double			extarg			{0};
};


static std::pair<const char *, size_t> statetojson(const void *vstate, size_t sz, char *pscratch, uint32_t szscrath) noexcept
{
	const char		*state = static_cast<const char *>(vstate);

	if (sz == 0) {
		return {"Unknown", GY_CONST_STRLEN("Unknown")};
	}

	OBJ_STATE_E		ostate = (OBJ_STATE_E)atoi(state);

	return state_to_stringlen(ostate); 
}	

static std::pair<const char *, size_t> statefromjson(const void *vstate, size_t sz, char *pscratch, uint32_t szscrath) noexcept
{
	const char		*state = static_cast<const char *>(vstate);

	if (sz == 0) {
		return {"", 0};
	}

	OBJ_STATE_E		ostate = state_from_string(state);

	switch (ostate) {
	
	case STATE_IDLE 	:	return {"0", 1};
	case STATE_GOOD 	:	return {"1", 1};
	case STATE_OK 		:	return {"2", 1};
	case STATE_BAD 		:	return {"3", 1};
	case STATE_SEVERE 	:	return {"4", 1};
	case STATE_DOWN		:	return {"5", 1};

	default			: 	return {"", 0};
	}	
}	

static std::pair<const char *, size_t> booltojson(const void *vstate, size_t sz, char *pscratch, uint32_t szscrath) noexcept
{
	const char		*state = static_cast<const char *>(vstate);

	if (sz == 0) {
		return {"false", GY_CONST_STRLEN("false")};
	}

	if (*state == 'f') return {"false", GY_CONST_STRLEN("false")};

	return {"true", GY_CONST_STRLEN("true")}; 
}	

template <typename T>
static const T * get_jsoncrc_mapping(const char *jsonfield, size_t lenfield, const T * pjson_map, size_t szmap, uint32_t & idindex) noexcept
{
	const uint32_t		crc = fnv1_hash(jsonfield, lenfield);

	for (size_t i = 0; i < szmap; ++i) {

		const auto		pdata = pjson_map + i;

		if (crc == pdata->jsoncrc) {
			idindex = i;
			return pdata;
		}	
	}	

	return nullptr;
}

template <typename T>
static const T * get_jsoncrc_mapping(const char *jsonfield, size_t lenfield, const T * pjson_map, size_t szmap) noexcept
{
	uint32_t		idindex;

	return get_jsoncrc_mapping(jsonfield, lenfield, pjson_map, szmap, idindex);
}


static const JSON_DB_MAPPING * get_jsoncrc_mapping(const char *jsonfield, size_t lenfield, const JSON_DB_MAPPING **pjson_map, size_t szmap, uint32_t & idindex) noexcept
{
	const uint32_t		crc = fnv1_hash(jsonfield, lenfield);

	for (size_t i = 0; i < szmap; ++i) {

		const JSON_DB_MAPPING	*pdata = pjson_map[i];

		if (crc == pdata->jsoncrc) {
			idindex = i;
			return pdata;
		}	
	}	

	return nullptr;
}

static const JSON_DB_MAPPING * get_jsoncrc_mapping(const char *jsonfield, size_t lenfield, const JSON_DB_MAPPING **pjson_map, size_t szmap) noexcept
{
	uint32_t		idindex;

	return get_jsoncrc_mapping(jsonfield, lenfield, pjson_map, szmap, idindex);
}

template <typename T>
static const char * dbcol_from_jsoncol(const char *jsonfield, size_t lenfield, const T * pjson_map, size_t szmap) noexcept
{
	const uint32_t		crc = fnv1_hash(jsonfield, lenfield);

	for (size_t i = 0; i < szmap; ++i) {

		const auto		pdata = pjson_map + i;

		if (crc == pdata->jsoncrc) {
			return pdata->dbcolname;
		}	
	}	

	return nullptr;
}

template <typename T>
static const char * jsoncol_from_dbcol(const char *jsonfield, const T * pjson_map, size_t szmap) noexcept
{
	for (size_t i = 0; i < szmap; ++i) {

		const auto		pdata = pjson_map + i;

		if (0 == strcmp(pdata->dbcolname, jsonfield)) {
			return pdata->jsonfield;
		}	
	}	

	return nullptr;
}


template <typename T>
static const T * get_jsoncrc_mapping(uint32_t jsoncrc, const T * pjson_map, uint32_t szmap, uint32_t startindex = 0) noexcept
{
	for (uint32_t i = startindex; i < szmap; ++i) {

		const auto		pdata = pjson_map + i;

		if (jsoncrc == pdata->jsoncrc) {
			return pdata;
		}	
	}	

	if (startindex == 0) return nullptr;

	if (startindex > szmap) startindex = szmap;

	for (uint32_t i = 0; i < startindex; ++i) {

		const auto		pdata = pjson_map + i;

		if (jsoncrc == pdata->jsoncrc) {
			return pdata;
		}	
	}	

	return nullptr;
}

template <typename T>
static const T * get_jsoncrc_mapping_or_throw(uint32_t jsoncrc, const T * pjson_map, size_t szmap)
{
	uint32_t		idindex;

	auto			pcol = get_jsoncrc_mapping(jsoncrc, pjson_map, szmap);

	if (pcol) {
		return pcol;
	}	

	GY_THROW_EXPRESSION("JSON Column to DB Mapping failed for JSON column %u", jsoncrc);
}



static const DB_AGGR_INFO * get_dbaggr_by_field(const char *jsonfield, size_t lenfield, const DB_AGGR_INFO * paggr_map, size_t szmap) noexcept
{
	const uint32_t		crc = fnv1_hash(jsonfield, lenfield);

	for (size_t i = 0; i < szmap; ++i) {

		const auto		pdata = paggr_map + i;

		if (crc == pdata->jsoncrc) {
			return pdata;
		}	
	}	

	return nullptr;
}


enum TOP_LISTEN_E : uint8_t
{
	TOP_LISTEN_ISSUE		= 0,
	TOP_LISTEN_QPS,
	TOP_LISTEN_ACTIVE_CONN,
	TOP_LISTEN_NET,

	TOP_LISTEN_MAX,
};	

enum TOP_APROC_E : uint8_t
{
	TOP_APROC_ISSUE		= 0,
	TOP_APROC_NET,
	TOP_APROC_CPU,
	TOP_APROC_RSS,
	TOP_APROC_CPU_DELAY,
	TOP_APROC_VM_DELAY,
	TOP_APROC_IO_DELAY,

	TOP_APROC_MAX,
};	


enum : uint32_t
{
	FIELD_PARID		= fnv1_consthash("parid"),
	FIELD_HOST		= fnv1_consthash("host"),
	FIELD_MADID		= fnv1_consthash("madid"),
	FIELD_CLUSTER		= fnv1_consthash("cluster"),
	FIELD_NULL_JSON		= fnv1_consthash(""),		
};	


static constexpr JSON_DB_MAPPING json_db_host_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys			jsontype	numtype		dbtype 		dbstrtype	oper		dboper			coldesc
{ "parid", 		"machid", 		GYSLEN("parid"),	FIELD_PARID,		SUBSYS_HOST,		JSON_STRING,	NUM_NAN,	"char(32)",	DB_STR_OCHAR,	nullptr,	nullptr, 		"Partha Host ID of the System Monitored", },
{ "host",		"hostname",	 	GYSLEN("host"),		FIELD_HOST,		SUBSYS_HOST,		JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr, 		"Hostname of System monitored by Partha", },
{ "madid",		"madhavaid", 		GYSLEN("madid"),	FIELD_MADID,		SUBSYS_HOST,		JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr,	nullptr, 		"Madhava Server ID interacting with Partha", },
{ "cluster",		"clustername", 		GYSLEN("cluster"),	FIELD_CLUSTER,		SUBSYS_HOST,		JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr, 		"Cluster Name assigned to Partha Host", },
};	

static constexpr DB_AGGR_INFO host_aggr_info[] = 
{
	// dbexpr								// jsoncrc		// dbfieldname		// dbfieldtype	// dflt_aggr	// ignore_sum	// extarg	
	{ "machid",								FIELD_PARID,		"machid",		"char(32)",	AOPER_GROUPBY,	false, 		0 },		
	{ "hostname",								FIELD_HOST,		"hostname",		"text",		AOPER_GROUPBY,	false, 		0 },		
	{ "madhavaid",								FIELD_MADID,		"madhavaid",		"char(16)",	AOPER_GROUPBY,	false, 		0 },		
	{ "clustername",							FIELD_CLUSTER,		"clustername",		"text",		AOPER_GROUPBY,	false, 		0 },		
};	


static constexpr size_t		MAX_MULTI_HOST_COLUMN_LIST	{MAX_COLUMN_LIST + GY_ARRAY_SIZE(json_db_host_arr)};

enum : uint32_t
{
	FIELD_TIME		= fnv1_consthash("time"),
	FIELD_NPROCISSUE	= fnv1_consthash("nprocissue"),
	FIELD_NPROCSEVERE	= fnv1_consthash("nprocsevere"),
	FIELD_NPROC		= fnv1_consthash("nproc"),
	FIELD_NLISTISSUE	= fnv1_consthash("nlistissue"),
	FIELD_NLISTSEVERE	= fnv1_consthash("nlistsevere"),
	FIELD_NLISTEN		= fnv1_consthash("nlisten"),
	FIELD_STATE		= fnv1_consthash("state"),
	FIELD_CPUISSUE		= fnv1_consthash("cpuissue"),
	FIELD_MEMISSUE		= fnv1_consthash("memissue"),
	FIELD_SEVERECPU		= fnv1_consthash("severecpu"),
	FIELD_SEVEREMEM		= fnv1_consthash("severemem"),
};	


static constexpr JSON_DB_MAPPING json_db_hoststate_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys			jsontype	numtype		dbtype 		dbstrtype	oper		dboper			coldesc
{ "time", 		"time", 		GYSLEN("time"),		FIELD_TIME,		SUBSYS_HOSTSTATE,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr, 		"Timestamp", },
{ "nprocissue",		"ntasks_issue", 	GYSLEN("nprocissue"),	FIELD_NPROCISSUE,	SUBSYS_HOSTSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr, 		"Number of Grouped Processes with issues", },
{ "nprocsevere",	"ntasks_severe", 	GYSLEN("nprocsevere"),	FIELD_NPROCSEVERE,	SUBSYS_HOSTSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr, 		"Number of Grouped Processes with Severe Issues", },
{ "nproc",		"ntasks", 		GYSLEN("nproc"),	FIELD_NPROC,		SUBSYS_HOSTSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"Total Number of Grouped Processes",  },
{ "nlistissue",		"nlisten_issue",	GYSLEN("nlistissue"),	FIELD_NLISTISSUE,	SUBSYS_HOSTSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"Number of Listeners (Services) with issues", },
{ "nlistsevere",	"nlisten_severe",	GYSLEN("nlistsevere"),	FIELD_NLISTSEVERE,	SUBSYS_HOSTSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"Number of Listeners with Severe issues", },
{ "nlisten",		"nlisten",		GYSLEN("nlisten"),	FIELD_NLISTEN,		SUBSYS_HOSTSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"Total Number of Listeners (Services)", },
{ "state",		"state",		GYSLEN("state"),	FIELD_STATE,		SUBSYS_HOSTSTATE,	JSON_STRING,	NUM_INT16,	"smallint",	DB_STR_NONE,	statefromjson, 	statetojson, 		"Host State as per Gyeeta analysis", },		
{ "",			"issue_bit_hist",	GYSLEN(""),		FIELD_NULL_JSON,	SUBSYS_HOSTSTATE,	JSON_NUMBER,	NUM_INT16,	"smallint",	DB_STR_NONE,	nullptr, 	nullptr,		"" },		
{ "cpuissue",		"cpu_issue",		GYSLEN("cpuissue"),	FIELD_CPUISSUE,		SUBSYS_HOSTSTATE,	JSON_BOOL,	NUM_NAN,	"boolean",	DB_STR_NONE,	nullptr, 	booltojson, 		"Is Host facing a CPU Issue", },		
{ "memissue",		"mem_issue",		GYSLEN("memissue"),	FIELD_MEMISSUE,		SUBSYS_HOSTSTATE,	JSON_BOOL,	NUM_NAN,	"boolean",	DB_STR_NONE,	nullptr, 	booltojson, 		"Is Host facing a Memory Issue", },		
{ "severecpu",		"severe_cpu_issue",	GYSLEN("severecpu"),	FIELD_SEVERECPU,	SUBSYS_HOSTSTATE,	JSON_BOOL,	NUM_NAN,	"boolean",	DB_STR_NONE,	nullptr, 	booltojson,		"Is Host facing a Severe CPU Issue",  },		
{ "severemem",		"severe_mem_issue",	GYSLEN("severemem"),	FIELD_SEVEREMEM,	SUBSYS_HOSTSTATE,	JSON_BOOL,	NUM_NAN,	"boolean",	DB_STR_NONE,	nullptr, 	booltojson,		"Is Host facing a Severe Memory Issue", },		

// Additional fields not present in DB
};	

enum : uint32_t
{
	FIELD_ISSUE		= fnv1_consthash("issue"),
	FIELD_INRECS		= fnv1_consthash("inrecs"),
};

// Aggregated Hoststate query cols
static constexpr JSON_DB_MAPPING json_db_aggr_hoststate_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys			jsontype	numtype		dbtype 		dbstrtype	oper		dboper			coldesc
{ "time", 		"atime", 		GYSLEN("time"),		FIELD_TIME,		SUBSYS_HOSTSTATE,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,		"Aggregation Timestamp", },
{ "nprocissue",		"ntasks_issue", 	GYSLEN("nprocissue"),	FIELD_NPROCISSUE,	SUBSYS_HOSTSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"Aggregated (Default Avg) Number of Grouped Processes with issues", },
{ "nprocsevere",	"ntasks_severe", 	GYSLEN("nprocsevere"),	FIELD_NPROCSEVERE,	SUBSYS_HOSTSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"Aggregated Number of Grouped Processes with Severe Issues", },
{ "nproc",		"ntasks", 		GYSLEN("nproc"),	FIELD_NPROC,		SUBSYS_HOSTSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"Aggregated Total Number of Grouped Processes",  },
{ "nlistissue",		"nlisten_issue",	GYSLEN("nlistissue"),	FIELD_NLISTISSUE,	SUBSYS_HOSTSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"Aggregated Number of Listeners (Services) with issues", },
{ "nlistsevere",	"nlisten_severe",	GYSLEN("nlistsevere"),	FIELD_NLISTSEVERE,	SUBSYS_HOSTSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"Aggregated Number of Listeners with Severe issues", },
{ "nlisten",		"nlisten",		GYSLEN("nlisten"),	FIELD_NLISTEN,		SUBSYS_HOSTSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"Aggregated Total Number of Listeners (Services)", },
{ "issue",		"issue",		GYSLEN("issue"),	FIELD_ISSUE,		SUBSYS_HOSTSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"Aggregated Number of times a Host Issue was seen", },
{ "cpuissue",		"cpu_issue",		GYSLEN("cpuissue"),	FIELD_CPUISSUE,		SUBSYS_HOSTSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"Aggregated Number of times a Host CPU Issue was seen", },
{ "memissue",		"mem_issue",		GYSLEN("memissue"),	FIELD_MEMISSUE,		SUBSYS_HOSTSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"Aggregated Number of times a Host Memory Issue was seen", },
{ "severecpu",		"severe_cpu_issue",	GYSLEN("severecpu"),	FIELD_SEVERECPU,	SUBSYS_HOSTSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"Aggregated Number of times a Severe Host CPU Issue was seen", },
{ "severemem",		"severe_mem_issue",	GYSLEN("severemem"),	FIELD_SEVEREMEM,	SUBSYS_HOSTSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"Aggregated Number of times a Severe Host Memory Issue was seen", },
{ "inrecs",		"inrecs",		GYSLEN("inrecs"),	FIELD_INRECS,		SUBSYS_HOSTSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"Total Detailed Records used for this Aggregation", },
};	

static constexpr DB_AGGR_INFO hoststate_aggr_info[] = 
{
	// dbexpr								// jsoncrc		// dbfieldname		// dbfieldtype	// dflt_aggr	// ignore_sum	// extarg	
	{ "",									FIELD_TIME,		"atime",		"timestamptz",	AOPER_GROUPBY,	false, 		0},		
	{ "%s(ntasks_issue)::int as ntasks_issue",				FIELD_NPROCISSUE,	"ntasks_issue",		"int",		AOPER_AVG,	false, 		0},			
	{ "%s(ntasks_severe)::int as ntasks_severe",				FIELD_NPROCSEVERE,	"ntasks_severe",	"int",		AOPER_AVG,	false, 		0},		
	{ "%s(ntasks)::int as ntasks",						FIELD_NPROC,		"ntasks",		"int",		AOPER_AVG,	false, 		0},		
	{ "%s(nlisten_issue)::int as nlisten_issue",				FIELD_NLISTISSUE,	"nlisten_issue",	"int",		AOPER_AVG,	false, 		0},		
	{ "%s(nlisten_severe)::int as nlisten_severe",				FIELD_NLISTSEVERE,	"nlisten_severe",	"int",		AOPER_AVG,	false, 		0},		
	{ "%s(nlisten)::int as nlisten",					FIELD_NLISTEN,		"nlisten",		"int",		AOPER_AVG,	false, 		0},		
	{ "count(*) filter (where state > 2)::int as issue",			FIELD_ISSUE,		"issue",		"int",		AOPER_COUNT,	false, 		0},		
	{ "%s(cpu_issue::int)::int as cpu_issue",				FIELD_CPUISSUE,		"cpu_issue",		"int",		AOPER_SUM,	false, 		0},		
	{ "%s(mem_issue::int)::int as mem_issue",				FIELD_MEMISSUE,		"mem_issue",		"int",		AOPER_SUM,	false, 		0},		
	{ "%s(severe_cpu_issue::int)::int as severe_cpu_issue",			FIELD_SEVERECPU,	"severe_cpu_issue",	"int",		AOPER_SUM,	false, 		0},		
	{ "%s(severe_mem_issue::int)::int as severe_mem_issue",			FIELD_SEVEREMEM,	"severe_mem_issue",	"int",		AOPER_SUM,	false, 		0},		
	{ "count(*)::int as inrecs",						FIELD_INRECS,		"inrecs",		"int",		AOPER_COUNT,	false, 		0},		
};	


enum : uint32_t
{
	/*FIELD_TIME		= fnv1_consthash("time"),*/
	FIELD_CPU_PCT		= fnv1_consthash("cpu_pct"),
	FIELD_USERCPU_PCT	= fnv1_consthash("usercpu_pct"),
	FIELD_SYSCPU_PCT	= fnv1_consthash("syscpu_pct"),
	FIELD_IOWAIT_PCT	= fnv1_consthash("iowait_pct"),
	FIELD_CUMUL_CPU_PCT	= fnv1_consthash("cumul_cpu_pct"),
	FIELD_FORKS_SEC		= fnv1_consthash("forks_sec"),
	FIELD_PROCS		= fnv1_consthash("procs"),
	FIELD_CS_SEC		= fnv1_consthash("cs_sec"),
	FIELD_CS_P95_SEC	= fnv1_consthash("cs_p95_sec"),
	FIELD_CPU_P95		= fnv1_consthash("cpu_p95"),
	FIELD_FORK_P95_SEC	= fnv1_consthash("fork_p95_sec"),
	FIELD_PROCS_P95		= fnv1_consthash("procs_p95"),
	FIELD_CPU_STATE		= fnv1_consthash("cpu_state"),
	/*FIELD_CPUISSUE		= fnv1_consthash("cpuissue"),*/

	FIELD_RSS_PCT		= fnv1_consthash("rss_pct"),
	FIELD_RSS_MB		= fnv1_consthash("rss_mb"),
	FIELD_TOTAL_MB		= fnv1_consthash("total_mb"),
	FIELD_LOCKED_MB		= fnv1_consthash("locked_mb"),
	FIELD_COMMIT_MB		= fnv1_consthash("commit_mb"),
	FIELD_COMMIT_PCT	= fnv1_consthash("commit_pct"),
	FIELD_SWAP_FREE_MB	= fnv1_consthash("swap_free_mb"),
	FIELD_PG_INOUT_SEC	= fnv1_consthash("pg_inout_sec"),
	FIELD_SWAP_INOUT_SEC	= fnv1_consthash("swap_inout_sec"),
	FIELD_RECLAIM_STALLS	= fnv1_consthash("reclaim_stalls"),
	FIELD_PGMAJFAULT	= fnv1_consthash("pgmajfault"),
	FIELD_OOM_KILL		= fnv1_consthash("oom_kill"),
	FIELD_RSS_PCT_P95	= fnv1_consthash("rss_pct_p95"),
	FIELD_PGINOUT_P95	= fnv1_consthash("pginout_p95"),
	FIELD_SWPINOUT_P95	= fnv1_consthash("swpinout_p95"),
	FIELD_MEM_STATE		= fnv1_consthash("mem_state"),
	/*FIELD_MEMISSUE		= fnv1_consthash("memissue"),*/
	
	FIELD_CPU_STATE_STR	= fnv1_consthash("cpu_state_str"),
	FIELD_MEM_STATE_STR	= fnv1_consthash("mem_state_str"),

	FIELD_CS_5MIN_P95_SEC	= fnv1_consthash("cs_5min_p95_sec"),
	FIELD_CPU_5MIN_P95	= fnv1_consthash("cpu_5min_p95"),
	FIELD_FORK_5MIN_P95_SEC	= fnv1_consthash("fork_5min_p95_sec"),
	FIELD_PROCS_5MIN_P95	= fnv1_consthash("procs_5min_p95"),
};	

static constexpr JSON_DB_MAPPING json_db_cpumem_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys		jsontype	numtype		dbtype 		dbstrtype	oper		dboper				coldesc	
{ "time", 		"time", 		GYSLEN("time"),		FIELD_TIME,		SUBSYS_CPUMEM,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,			"Timestamp", },
{ "cpu_pct", 		"cpu_pct",		GYSLEN("cpu_pct"),	FIELD_CPU_PCT,		SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_DOUBLE,	"real",		DB_STR_NONE,	nullptr, 	nullptr,			"Host Total CPU Utilization normalized to 100 pct" },
{ "usercpu_pct",	"usercpu_pct",		GYSLEN("usercpu_pct"),	FIELD_USERCPU_PCT,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_DOUBLE,	"real",		DB_STR_NONE,	nullptr, 	nullptr,			"Host User CPU Utilization normalized to 100 pct" },
{ "syscpu_pct",		"syscpu_pct",		GYSLEN("syscpu_pct"),	FIELD_SYSCPU_PCT,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_DOUBLE,	"real",		DB_STR_NONE,	nullptr, 	nullptr,			"Host System CPU Utilization normalized to 100 pct" },		
{ "iowait_pct",		"iowait_pct",		GYSLEN("iowait_pct"),	FIELD_IOWAIT_PCT,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_DOUBLE,	"real",		DB_STR_NONE,	nullptr, 	nullptr,			"Host IO Wait CPU Utilization normalized to 100 pct" },		
{ "cumul_cpu_pct",	"cumul_core_cpu_pct",	GYSLEN("cumul_cpu_pct"),FIELD_CUMUL_CPU_PCT,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_DOUBLE,	"real",		DB_STR_NONE,	nullptr, 	nullptr,			 "Host Total CPU Utilization across all Cores", },		
{ "forks_sec",		"forks_sec",		GYSLEN("forks_sec"),	FIELD_FORKS_SEC,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"Count of New Processes spawned per sec", },		
{ "procs",		"procs_running",	GYSLEN("procs"),	FIELD_PROCS,		SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"Runnable (Active or Waiting for CPU) Process count", },		
{ "cs_sec",		"cs_sec",		GYSLEN("cs_sec"),	FIELD_CS_SEC,		SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"Host Context Switches/sec (Voluntary and Involuntary)", },		
{ "cs_p95_sec",		"cs_p95_sec",		GYSLEN("cs_p95_sec"),	FIELD_CS_P95_SEC,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"p95 of Context Switches/sec", },		
{ "cpu_p95",		"cpu_p95",		GYSLEN("cpu_p95"),	FIELD_CPU_P95,		SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"p95 of Total Host CPU Utilization", },		
{ "fork_p95_sec",	"fork_p95_sec",		GYSLEN("fork_p95_sec"),	FIELD_FORK_P95_SEC,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"p95 of New Processes/sec count", },		
{ "procs_p95",		"procs_p95",		GYSLEN("procs_p95"),	FIELD_PROCS_P95,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"p95 of Runnable Process count", },		
{ "cpu_state",		"cpu_state",		GYSLEN("cpu_state"),	FIELD_CPU_STATE,	SUBSYS_CPUMEM,	JSON_STRING,	NUM_NAN,	"smallint",	DB_STR_NONE,	statefromjson, 	statetojson,			"State of Host CPU as per Gyeeta analysis", },		
{ "cpuissue",		"cpu_issue",		GYSLEN("cpuissue"),	FIELD_CPUISSUE,		SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT16,	"smallint",	DB_STR_NONE,	nullptr, 	nullptr,			"Reason Number for CPU Issue if any", },		
{ "",			"cpu_issue_bit_hist",	GYSLEN(""),		FIELD_NULL_JSON,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT16,	"smallint",	DB_STR_NONE,	nullptr, 	nullptr,			"" },		
{ "",			"cpu_severe_issue_hist",GYSLEN(""),		FIELD_NULL_JSON,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT16,	"smallint",	DB_STR_NONE,	nullptr, 	nullptr,			"" },		

{ "rss_pct",		"rss_pct",		GYSLEN("rss_pct"),	FIELD_RSS_PCT,		SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_DOUBLE,	"real",		DB_STR_NONE,	nullptr, 	nullptr,			"Host Resident Memory (RSS) as pct of Total Memory" },		
{ "rss_mb",		"rss_memory_mb",	GYSLEN("rss_mb"),	FIELD_RSS_MB,		SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"Host Resident Memory (RSS) in MB", },		
{ "total_mb",		"total_memory_mb",	GYSLEN("total_mb"),	FIELD_TOTAL_MB,		SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"Host Total RAM Memory Available in MB" },		
{ "",			"cached_memory_mb",	GYSLEN(""),		FIELD_NULL_JSON,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"Host Cached Memory in MB", },		
{ "locked_mb",		"locked_memory_mb",	GYSLEN("locked_mb"),	FIELD_LOCKED_MB,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"Host Locked (Non Pageable) Memory in MB", },		
{ "commit_mb",		"committed_memory_mb",	GYSLEN("commit_mb"),	FIELD_COMMIT_MB,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"Host Total Allocated (Committed) Memory in MB", },		
{ "commit_pct",		"committed_pct",	GYSLEN("commit_pct"),	FIELD_COMMIT_PCT,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_DOUBLE,	"real",		DB_STR_NONE,	nullptr, 	nullptr,			"Host Total Committed Memory as pct of Total Memory available", },		
{ "swap_free_mb",	"swap_free_mb",		GYSLEN("swap_free_mb"),	FIELD_SWAP_FREE_MB,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"Free Swap Space in MB", },		
{ "",			"swap_total_mb",	GYSLEN(""),		FIELD_NULL_JSON,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"" },		
{ "pg_inout_sec",	"pg_inout_sec",		GYSLEN("pg_inout_sec"),	FIELD_PG_INOUT_SEC,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"Number of Memory Page In/Outs per sec", },		
{ "swap_inout_sec",	"swap_inout_sec",	GYSLEN("swap_inout_sec"),FIELD_SWAP_INOUT_SEC,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"Number of Memory Page Swap In/Out per sec", },		
{ "reclaim_stalls",	"reclaim_stalls",	GYSLEN("reclaim_stalls"),FIELD_RECLAIM_STALLS,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"Number of Process Stalls due to Page Reclaiming", },		
{ "pgmajfault",		"pgmajfault",		GYSLEN("pgmajfault"),	FIELD_PGMAJFAULT,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"Number of Major Page Faults", },		
{ "oom_kill",		"oom_kill",		GYSLEN("oom_kill"),	FIELD_OOM_KILL,		SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"Number of Processes killed by kernel due to Out of Memory OOM handling", },		
{ "rss_pct_p95",	"rss_pct_p95",		GYSLEN("rss_pct_p95"),	FIELD_RSS_PCT_P95,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"p95 of Resident Memory as pct of Total Memory", },		
{ "pginout_p95",	"pginout_p95",		GYSLEN("pginout_p95"),	FIELD_PGINOUT_P95,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"p95 of Memory Page In/Out per sec count" },		
{ "swpinout_p95",	"swpinout_p95",		GYSLEN("swpinout_p95"),	FIELD_SWPINOUT_P95,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"p95 of Memory Page Swap In/Out per sec count", },		
{ "",			"allocstall_p95",	GYSLEN(""),		FIELD_NULL_JSON,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"" },		
{ "mem_state",		"mem_state",		GYSLEN("mem_state"),	FIELD_MEM_STATE,	SUBSYS_CPUMEM,	JSON_STRING,	NUM_NAN,	"smallint",	DB_STR_NONE,	statefromjson, 	statetojson,			"State of Host Memory as per Gyeeta analysis", },		
{ "memissue",		"mem_issue",		GYSLEN("memissue"),	FIELD_MEMISSUE,		SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT16,	"smallint",	DB_STR_NONE,	nullptr, 	nullptr,			"Reason Number for Memory Issue if any", },		
{ "",			"mem_issue_bit_hist",	GYSLEN(""),		FIELD_NULL_JSON,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT16,	"smallint",	DB_STR_NONE,	nullptr, 	nullptr,			"" },		
{ "",			"mem_severe_issue_hist",GYSLEN(""),		FIELD_NULL_JSON,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT16,	"smallint",	DB_STR_NONE,	nullptr, 	nullptr,			"" },		

{ "cpu_state_str",	"cpu_state_str",	GYSLEN("cpu_state_str"),FIELD_CPU_STATE_STR,	SUBSYS_CPUMEM,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,			"Extended Analysis of Host CPU State", },		
{ "mem_state_str",	"mem_state_str",	GYSLEN("mem_state_str"),FIELD_MEM_STATE_STR,	SUBSYS_CPUMEM,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,			"Extended Analysis of Host Memory State", },		

// Additional fields not present in DB

{ "cs_5min_p95_sec",	"",		GYSLEN("cs_5min_p95_sec"),	FIELD_CS_5MIN_P95_SEC,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"p95 of 5 min Context Switches count", },
{ "cpu_5min_p95",	"",		GYSLEN("cpu_5min_p95"),		FIELD_CPU_5MIN_P95,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"p95 of 5 min Total CPU Utilization pct", },
{ "fork_5min_p95_sec",	"",		GYSLEN("fork_5min_p95_sec"),	FIELD_FORK_5MIN_P95_SEC,SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"p95 of 5 min New Process per sec count", },		
{ "procs_5min_p95",	"",		GYSLEN("procs_5min_p95"),	FIELD_PROCS_5MIN_P95,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"p95 of 5 min Runnable Process count", },		
};	

enum : uint32_t
{
	FIELD_MAX_CPU_PCT	= fnv1_consthash("max_cpu_pct"),
	FIELD_INCPUSAT		= fnv1_consthash("incpusat"),
	FIELD_INCORESAT		= fnv1_consthash("incoresat"),
	FIELD_INIOWAIT		= fnv1_consthash("iniowait"),
	FIELD_INCS		= fnv1_consthash("incs"),
	FIELD_INFORK		= fnv1_consthash("infork"),
	FIELD_INRPROC		= fnv1_consthash("inrproc"),

	FIELD_INRSSSAT		= fnv1_consthash("inrsssat"),
	FIELD_INCMMSAT		= fnv1_consthash("incmmsat"),
	FIELD_INPGINOUT		= fnv1_consthash("inpginout"),
	FIELD_INSWPINOUT	= fnv1_consthash("inswpinout"),
	FIELD_INRECLAIM		= fnv1_consthash("inreclaim"),
	FIELD_INOOM		= fnv1_consthash("inoom"),
	FIELD_INSWPSPC		= fnv1_consthash("inswpspc"),

	/*FIELD_INRECS		= fnv1_consthash("inrecs"),*/
};

// Aggregated CPU Memory fields
static constexpr JSON_DB_MAPPING json_db_aggr_cpumem_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys		jsontype	numtype		dbtype 		dbstrtype	oper		dboper				coldesc
{ "time", 		"atime", 		GYSLEN("time"),		FIELD_TIME,		SUBSYS_CPUMEM,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,			"Aggregation Timestamp", },
{ "cpu_pct", 		"cpu_pct",		GYSLEN("cpu_pct"),	FIELD_CPU_PCT,		SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_DOUBLE,	"real",		DB_STR_NONE,	nullptr, 	nullptr,			"Aggregated (Default Avg) Host Total CPU Utilization normalized to 100 pct" },
{ "max_cpu_pct", 	"max_cpu_pct",		GYSLEN("max_cpu_pct"),	FIELD_MAX_CPU_PCT,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_DOUBLE,	"real",		DB_STR_NONE,	nullptr, 	nullptr,			"Max CPU Utilization normalized to 100 pct" },
{ "usercpu_pct",	"usercpu_pct",		GYSLEN("usercpu_pct"),	FIELD_USERCPU_PCT,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_DOUBLE,	"real",		DB_STR_NONE,	nullptr, 	nullptr,			"Aggregated Host User CPU Utilization normalized to 100 pct" },
{ "syscpu_pct",		"syscpu_pct",		GYSLEN("syscpu_pct"),	FIELD_SYSCPU_PCT,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_DOUBLE,	"real",		DB_STR_NONE,	nullptr, 	nullptr,			"Aggregated Host System CPU Utilization normalized to 100 pct" },
{ "iowait_pct",		"iowait_pct",		GYSLEN("iowait_pct"),	FIELD_IOWAIT_PCT,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_DOUBLE,	"real",		DB_STR_NONE,	nullptr, 	nullptr,			"Aggregated Host IO Wait CPU Utilization normalized to 100 pct" },
{ "cumul_cpu_pct",	"cumul_core_cpu_pct",	GYSLEN("cumul_cpu_pct"),FIELD_CUMUL_CPU_PCT,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_DOUBLE,	"real",		DB_STR_NONE,	nullptr, 	nullptr,			 "Aggregated Host Total CPU Utilization across all Cores", },	
{ "forks_sec",		"forks_sec",		GYSLEN("forks_sec"),	FIELD_FORKS_SEC,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"Aggregated Count of New Processes spawned per sec", },	
{ "procs",		"procs_running",	GYSLEN("procs"),	FIELD_PROCS,		SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"Aggregated Runnable (Active or Waiting for CPU) Process count", },	
{ "cs_sec",		"cs_sec",		GYSLEN("cs_sec"),	FIELD_CS_SEC,		SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT64,	"bigint",	DB_STR_NONE,	nullptr, 	nullptr,			"Aggregated Host Context Switches/sec (Voluntary and Involuntary)", },		
{ "cpuissue",		"cpuissue",		GYSLEN("cpuissue"),	FIELD_CPUISSUE,		SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"Total Number of Host CPU Issues seen within the Aggregated time", },
{ "incpusat",		"incpusat",		GYSLEN("incpusat"),	FIELD_INCPUSAT,		SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"Number of CPU Issues caused by overall CPU Saturation (High CPU usage across cores)", },
{ "incoresat",		"incoresat",		GYSLEN("incoresat"),	FIELD_INCORESAT,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"Number of CPU Issues caused by individual CPU core Saturation", },
{ "iniowait",		"iniowait",		GYSLEN("iniowait"),	FIELD_INIOWAIT,		SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"Number of CPU Issues caused by large IO Waits", },
{ "incs",		"incs",			GYSLEN("incs"),		FIELD_INCS,		SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"Number of CPU Issues caused by large Context Switch counts", },
{ "infork",		"infork",		GYSLEN("infork"),	FIELD_INFORK,		SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"Number of CPU Issues caused by large New Process Create counts", },
{ "inrproc",		"inrproc",		GYSLEN("inrproc"),	FIELD_INRPROC,		SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"Number of CPU Issues caused by large Process Runnable counts", },

{ "rss_pct",		"rss_pct",		GYSLEN("rss_pct"),	FIELD_RSS_PCT,		SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_DOUBLE,	"real",		DB_STR_NONE,	nullptr, 	nullptr,			"Aggregated Host Resident Memory (RSS) as pct of Total Memory", },
{ "rss_mb",		"rss_memory_mb",	GYSLEN("rss_mb"),	FIELD_RSS_MB,		SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT64,	"bigint",	DB_STR_NONE,	nullptr, 	nullptr,			"Aggregated Host Resident Memory (RSS) in MB", },	
{ "locked_mb",		"locked_memory_mb",	GYSLEN("locked_mb"),	FIELD_LOCKED_MB,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT64,	"bigint",	DB_STR_NONE,	nullptr, 	nullptr,			"Aggregated Locked (Non Pageable) Memory in MB", },	
{ "commit_mb",		"committed_memory_mb",	GYSLEN("commit_mb"),	FIELD_COMMIT_MB,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT64,	"bigint",	DB_STR_NONE,	nullptr, 	nullptr,			"Aggregated Allocated (Committed) Memory in MB", },	
{ "commit_pct",		"committed_pct",	GYSLEN("commit_pct"),	FIELD_COMMIT_PCT,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_DOUBLE,	"real",		DB_STR_NONE,	nullptr, 	nullptr,			"Aggregated Committed Memory as pct of Total Memory available", },
{ "swap_free_mb",	"swap_free_mb",		GYSLEN("swap_free_mb"),	FIELD_SWAP_FREE_MB,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT64,	"bigint",	DB_STR_NONE,	nullptr, 	nullptr,			"Aggregated Free Swap Space in MB", },	
{ "pg_inout_sec",	"pg_inout_sec",		GYSLEN("pg_inout_sec"),	FIELD_PG_INOUT_SEC,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"Aggregated Number of Memory Page In/Outs per sec", },	
{ "swap_inout_sec",	"swap_inout_sec",	GYSLEN("swap_inout_sec"),FIELD_SWAP_INOUT_SEC,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"Aggregated Number of Memory Page Swap In/Out per sec", },		
{ "reclaim_stalls",	"reclaim_stalls",	GYSLEN("reclaim_stalls"),FIELD_RECLAIM_STALLS,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"Aggregated Number of Process Stalls due to Page Reclaiming", },	
{ "pgmajfault",		"pgmajfault",		GYSLEN("pgmajfault"),	FIELD_PGMAJFAULT,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"Aggregated Number of Major Page Faults", },
{ "oom_kill",		"oom_kill",		GYSLEN("oom_kill"),	FIELD_OOM_KILL,		SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"Aggregated (Default Sum) Number of Processes killed by kernel due to Out of Memory handling", },	
{ "memissue",		"memissue",		GYSLEN("memissue"),	FIELD_MEMISSUE,		SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"Total Number of Host Memory Issues seen within the Aggregated time", },
{ "inrsssat",		"inrsssat",		GYSLEN("inrsssat"),	FIELD_INRSSSAT,		SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"Number of Memory Issues caused by High Resident Memory RSS Saturation", },
{ "incmmsat",		"incmmsat",		GYSLEN("incmmsat"),	FIELD_INCMMSAT,		SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"Number of Memory Issues caused by High Commit Memory Saturation", },
{ "inpginout",		"inpginout",		GYSLEN("inpginout"),	FIELD_INPGINOUT,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"Number of Memory Issues caused by Large Page In/Outs", },
{ "inswpinout",		"inswpinout",		GYSLEN("inswpinout"),	FIELD_INSWPINOUT,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"Number of Memory Issues caused by Large Page Swap In/Outs", },
{ "inreclaim",		"inreclaim",		GYSLEN("inreclaim"),	FIELD_INRECLAIM,	SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"Number of Memory Issues caused by Process Stalls due to Page Reclaiming", },
{ "inoom",		"inoom",		GYSLEN("inoom"),	FIELD_INOOM,		SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"Number of Memory Issues caused by Process Kills due to Out of Memory OOM", },
{ "inswpspc",		"inswpspc",		GYSLEN("inswpspc"),	FIELD_INSWPSPC,		SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"Number of Memory Issues caused by Low Free Swap Space", },
{ "inrecs",		"inrecs",		GYSLEN("inrecs"),	FIELD_INRECS,		SUBSYS_CPUMEM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,
	"Total Detailed Records used for this Aggregation", },
};	

static constexpr DB_AGGR_INFO cpumem_aggr_info[] = 
{
	// dbexpr								// jsoncrc		// dbfieldname		// dbfieldtype	// dflt_aggr	// ignore_sum	// extarg	
	{ "",									FIELD_TIME,		"atime",		"timestamptz",	AOPER_GROUPBY,	false, 		0},		
	{ "avg(cpu_pct)::real as cpu_pct",					FIELD_CPU_PCT,		"cpu_pct",		"real",		AOPER_AVG,	false, 		0},		
	{ "max(cpu_pct)::real as max_cpu_pct",					FIELD_MAX_CPU_PCT,	"max_cpu_pct",		"real",		AOPER_MAX,	false, 		0},		
	{ "%s(usercpu_pct)::real as usercpu_pct",				FIELD_USERCPU_PCT,	"usercpu_pct",		"real",		AOPER_AVG,	true, 		0},		
	{ "%s(syscpu_pct)::real as syscpu_pct",					FIELD_SYSCPU_PCT,	"syscpu_pct",		"real",		AOPER_AVG,	true, 		0},		
	{ "%s(iowait_pct)::real as iowait_pct",					FIELD_IOWAIT_PCT,	"iowait_pct",		"real",		AOPER_AVG,	true, 		0},		
	{ "%s(cumul_core_cpu_pct)::real as cumul_core_cpu_pct",			FIELD_CUMUL_CPU_PCT,	"cumul_core_cpu_pct",	"real",		AOPER_AVG,	true, 		0},		
	{ "%s(forks_sec)::int as forks_sec",					FIELD_FORKS_SEC,	"forks_sec",		"int",		AOPER_AVG,	true, 		0},		
	{ "%s(procs_running)::int as procs_running",				FIELD_PROCS,		"procs_running",	"int",		AOPER_AVG,	true, 		0},		
	{ "%s(cs_sec)::bigint as cs_sec",					FIELD_CS_SEC,		"cs_sec",		"bigint",	AOPER_AVG,	true, 		0},		
	{ "count(*) filter (where cpu_state > 2)::int as cpuissue",		FIELD_CPUISSUE,		"cpuissue",		"int",		AOPER_COUNT,	false, 		0},		
	{ "count(*) filter (where cpu_issue = 1)::int as incpusat",		FIELD_INCPUSAT,		"incpusat",		"int",		AOPER_COUNT,	false, 		0},		
	{ "count(*) filter (where cpu_issue = 2)::int as incoresat",		FIELD_INCORESAT,	"incoresat",		"int",		AOPER_COUNT,	false, 		0},		
	{ "count(*) filter (where cpu_issue = 3)::int as iniowait",		FIELD_INIOWAIT,		"iniowait",		"int",		AOPER_COUNT,	false, 		0},		
	{ "count(*) filter (where cpu_issue = 4)::int as incs",			FIELD_INCS,		"incs",			"int",		AOPER_COUNT,	false, 		0},		
	{ "count(*) filter (where cpu_issue = 5)::int as infork",		FIELD_INFORK,		"infork",		"int",		AOPER_COUNT,	false, 		0},		
	{ "count(*) filter (where cpu_issue = 6)::int as inrproc",		FIELD_INRPROC,		"inrproc",		"int",		AOPER_COUNT,	false, 		0},		

	{ "%s(rss_pct)::real as rss_pct",					FIELD_RSS_PCT,		"rss_pct",		"real",		AOPER_AVG,	true, 		0},		
	{ "%s(rss_memory_mb)::bigint as rss_memory_mb",				FIELD_RSS_MB,		"rss_memory_mb",	"bigint",	AOPER_AVG,	true, 		0},		
	{ "%s(locked_memory_mb)::bigint as locked_memory_mb",			FIELD_LOCKED_MB,	"locked_memory_mb",	"bigint",	AOPER_AVG,	true, 		0},		
	{ "%s(committed_memory_mb)::bigint as committed_memory_mb",		FIELD_COMMIT_MB,	"committed_memory_mb",	"bigint",	AOPER_AVG,	true, 		0},		
	{ "%s(committed_pct)::real as committed_pct",				FIELD_COMMIT_PCT,	"committed_pct",	"real",		AOPER_AVG,	true, 		0},		
	{ "%s(swap_free_mb)::bigint as swap_free_mb",				FIELD_SWAP_FREE_MB,	"swap_free_mb",		"bigint",	AOPER_AVG,	true, 		0},		
	{ "%s(pg_inout_sec)::int as pg_inout_sec",				FIELD_PG_INOUT_SEC,	"pg_inout_sec",		"int",		AOPER_AVG,	true, 		0},		
	{ "%s(swap_inout_sec)::int as swap_inout_sec",				FIELD_SWAP_INOUT_SEC,	"swap_inout_sec",	"int",		AOPER_AVG,	true, 		0},		
	{ "%s(reclaim_stalls)::int as reclaim_stalls",				FIELD_RECLAIM_STALLS,	"reclaim_stalls",	"int",		AOPER_AVG,	false, 		0},		
	{ "%s(pgmajfault)::int as pgmajfault",					FIELD_PGMAJFAULT,	"pgmajfault",		"int",		AOPER_AVG,	false, 		0},		
	{ "%s(oom_kill)::int as oom_kill",					FIELD_OOM_KILL,		"oom_kill",		"int",		AOPER_SUM,	false, 		0},		

	{ "count(*) filter (where mem_state > 2)::int as memissue",		FIELD_MEMISSUE,		"memissue",		"int",		AOPER_COUNT,	false, 		0},		
	{ "count(*) filter (where mem_issue = 1)::int as inrsssat",		FIELD_INRSSSAT,		"inrsssat",		"int",		AOPER_COUNT,	false, 		0},		
	{ "count(*) filter (where mem_issue = 2)::int as incmmsat",		FIELD_INCMMSAT,		"incmmsat",		"int",		AOPER_COUNT,	false, 		0},		
	{ "count(*) filter (where mem_issue = 3)::int as inpginout",		FIELD_INPGINOUT,	"inpginout",		"int",		AOPER_COUNT,	false, 		0},		
	{ "count(*) filter (where mem_issue = 4)::int as inswpinout",		FIELD_INSWPINOUT,	"inswpinout",		"int",		AOPER_COUNT,	false, 		0},		
	{ "count(*) filter (where mem_issue = 5)::int as inreclaim",		FIELD_INRECLAIM,	"inreclaim",		"int",		AOPER_COUNT,	false, 		0},		
	{ "count(*) filter (where mem_issue = 6)::int as inoom",		FIELD_INOOM,		"inoom",		"int",		AOPER_COUNT,	false, 		0},		
	{ "count(*) filter (where mem_issue = 7)::int as inswpspc",		FIELD_INSWPSPC,		"inswpspc",		"int",		AOPER_COUNT,	false, 		0},		
	{ "count(*)::int as inrecs",						FIELD_INRECS,		"inrecs",		"int",		AOPER_COUNT,	false, 		0},		
};	

enum : uint32_t
{
	/*FIELD_TIME		= fnv1_consthash("time"),*/
	FIELD_SVCID		= fnv1_consthash("svcid"),
	FIELD_NAME		= fnv1_consthash("name"),
	FIELD_QPS5S		= fnv1_consthash("qps5s"),
	FIELD_NQRY5S		= fnv1_consthash("nqry5s"),
	FIELD_RESP5S		= fnv1_consthash("resp5s"),
	FIELD_P95RESP5S		= fnv1_consthash("p95resp5s"),
	FIELD_P95RESP5M		= fnv1_consthash("p95resp5m"),
	FIELD_NCONNS		= fnv1_consthash("nconns"),
	FIELD_NACTIVE		= fnv1_consthash("nactive"),
	FIELD_NPROCS		= fnv1_consthash("nprocs"),

	FIELD_KBIN15S		= fnv1_consthash("kbin15s"),
	FIELD_KBOUT15S		= fnv1_consthash("kbout15s"),
	FIELD_SERERR		= fnv1_consthash("sererr"),
	FIELD_CLIERR		= fnv1_consthash("clierr"),

	FIELD_DELAYUS		= fnv1_consthash("delayus"),
	FIELD_CPUDELUS		= fnv1_consthash("cpudelus"),
	FIELD_IODELUS		= fnv1_consthash("iodelus"),
	FIELD_VMDELUS		= fnv1_consthash("vmdelus"),
	FIELD_USERCPU		= fnv1_consthash("usercpu"),
	FIELD_SYSCPU		= fnv1_consthash("syscpu"),
	FIELD_RSSMB		= fnv1_consthash("rssmb"),

	FIELD_NISSUE		= fnv1_consthash("nissue"),
	/*FIELD_STATE		= fnv1_consthash("state"),*/
	/*FIELD_ISSUE		= fnv1_consthash("issue"),*/
	FIELD_ISHTTP		= fnv1_consthash("ishttp"),
	FIELD_DESC		= fnv1_consthash("desc"),
};	

static constexpr JSON_DB_MAPPING json_db_svcstate_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys			jsontype	numtype		dbtype 		dbstrtype	oper		dboper			coldesc
{ "time", 		"time", 		GYSLEN("time"),		FIELD_TIME,		SUBSYS_SVCSTATE,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,		"Timestamp", },
{ "svcid", 		"glob_id", 		GYSLEN("svcid"),	FIELD_SVCID,		SUBSYS_SVCSTATE,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"Service (Listener) Gyeeta assigned ID", },
{ "name", 		"comm", 		GYSLEN("name"),		FIELD_NAME,		SUBSYS_SVCSTATE,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"Service Name based on the Process name", },
{ "qps5s", 		"qps_5s", 		GYSLEN("qps5s"),	FIELD_QPS5S,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"Queries/sec QPS based on the last 5 sec query count (nqry5s)", },
{ "nqry5s", 		"nqrys_5s", 		GYSLEN("nqry5s"),	FIELD_NQRY5S,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"Number of Queries seen in the last 5 sec", },
{ "resp5s", 		"avg_5s_resp_ms", 	GYSLEN("resp5s"),	FIELD_RESP5S,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"Avg Response Time (Latency) in msec based on the queries seen in last 5 sec", },
{ "p95resp5s", 		"p95_5s_resp_ms", 	GYSLEN("p95resp5s"),	FIELD_P95RESP5S,	SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"p95 of the Response Time in msec based on the queries seen in last 5 sec", },
{ "p95resp5m", 		"p95_5m_resp_ms", 	GYSLEN("p95resp5m"),	FIELD_P95RESP5M,	SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"p95 of the Response Time in msec based on the queries seen in last 5 min",},
{ "nconns", 		"nconns", 		GYSLEN("nconns"),	FIELD_NCONNS,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"Total Connections connected to the service at time of record", },
{ "nactive", 		"nconns_active", 	GYSLEN("nactive"),	FIELD_NACTIVE,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"Approx Number of Active connections seen in last 5 sec", },
{ "nprocs", 		"ntasks", 		GYSLEN("nprocs"),	FIELD_NPROCS,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"Number of processes associated with Service at time of record", },
{ "kbin15s", 		"curr_kb_inbound", 	GYSLEN("kbin15s"),	FIELD_KBIN15S,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"Network Inbound Traffic to Service in KB updated every 15 sec", },
{ "kbout15s", 		"curr_kb_outbound", 	GYSLEN("kbout15s"),	FIELD_KBOUT15S,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"Network Outbound Traffic from Service in KB updated every 15 sec", },
{ "sererr", 		"ser_http_errors", 	GYSLEN("sererr"),	FIELD_SERERR,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"HTTP Server 5xx Errors seen for HTTP or GRPC services without TLS encryption", },
{ "clierr", 		"cli_http_errors", 	GYSLEN("clierr"),	FIELD_CLIERR,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"HTTP Client 4xx Errors seen for HTTP or GRPC services without TLS encryption", },
{ "delayus", 		"tasks_delay_usec", 	GYSLEN("delayus"),	FIELD_DELAYUS,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"Total Service Processes Delays seen in usec", },
{ "cpudelus", 		"tasks_cpudelay_usec", 	GYSLEN("cpudelus"),	FIELD_CPUDELUS,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"Service Processes CPU related Delays in usec", },
{ "iodelus", 		"tasks_blkiodelay_usec",GYSLEN("iodelus"),	FIELD_IODELUS,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"Service Processes Block IO related Delays in usec", },
{ "vmdelus", 		"tasks_vmdelay_usec", 	GYSLEN("vmdelus"),	FIELD_VMDELUS,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"Service Processes Memory related Delays in usec",  },
{ "usercpu", 		"tasks_user_cpu", 	GYSLEN("usercpu"),	FIELD_USERCPU,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"Service Processes User CPU pct", },
{ "syscpu", 		"tasks_sys_cpu", 	GYSLEN("syscpu"),	FIELD_SYSCPU,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"Service Processes System CPU pct", },
{ "rssmb", 		"tasks_rss_mb", 	GYSLEN("rssmb"),	FIELD_RSSMB,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"Service Processes Resident Memory RSS in MB", },
{ "nissue", 		"ntasks_issue", 	GYSLEN("nissue"),	FIELD_NISSUE,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT16,	"smallint",	DB_STR_NONE,	nullptr, 	nullptr,		"Count of Service Processes with issues", },
{ "state",		"curr_state",		GYSLEN("state"),	FIELD_STATE,		SUBSYS_SVCSTATE,	JSON_STRING,	NUM_NAN,	"smallint",	DB_STR_NONE,	statefromjson, 	statetojson,		"State of Service as per Gyeeta analysis", },		
{ "issue",		"curr_issue",		GYSLEN("issue"),	FIELD_ISSUE,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT16,	"smallint",	DB_STR_NONE,	nullptr, 	nullptr,		"Reason Number for Service Issue if any", },		
{ "",			"issue_bit_hist",	GYSLEN(""),		FIELD_NULL_JSON,	SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT16,	"smallint",	DB_STR_NONE,	nullptr, 	nullptr,		"", },		

{ "ishttp",		"is_http_svc",		GYSLEN("ishttp"),	FIELD_ISHTTP,		SUBSYS_SVCSTATE,	JSON_BOOL,	NUM_NAN,	"boolean",	DB_STR_NONE,	nullptr, 	booltojson,		"Is Service an HTTP or GRPC Service without TLS", },		
{ "desc",		"issue_string",		GYSLEN("desc"),		FIELD_DESC,		SUBSYS_SVCSTATE,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,		"Extended Analysis of Service State", },		

// Additional fields not present in DB

};

enum : uint32_t
{
	FIELD_SVCISSUE		= fnv1_consthash("svcissue"),
	FIELD_INPROC		= fnv1_consthash("inproc"),
	FIELD_INQPS		= fnv1_consthash("inqps"),
	FIELD_INACONN		= fnv1_consthash("inaconn"),
	FIELD_INHTTPERR		= fnv1_consthash("inhttperr"),
	FIELD_INOSCPU		= fnv1_consthash("inoscpu"),
	FIELD_INOSMEM		= fnv1_consthash("inosmem"),
	FIELD_INDEPSVC		= fnv1_consthash("indepsvc"),
	FIELD_INUNKNOWN		= fnv1_consthash("inunknown"),
};

static constexpr JSON_DB_MAPPING json_db_aggr_svcstate_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys			jsontype	numtype		dbtype 		dbstrtype	oper		dboper			coldesc	
{ "time", 		"atime", 		GYSLEN("time"),		FIELD_TIME,		SUBSYS_SVCSTATE,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "svcid", 		"glob_id", 		GYSLEN("svcid"),	FIELD_SVCID,		SUBSYS_SVCSTATE,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "name", 		"comm", 		GYSLEN("name"),		FIELD_NAME,		SUBSYS_SVCSTATE,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },

{ "qps5s", 		"qps_5s", 		GYSLEN("qps5s"),	FIELD_QPS5S,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "nqry5s", 		"nqrys_5s", 		GYSLEN("nqry5s"),	FIELD_NQRY5S,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "resp5s", 		"avg_5s_resp_ms", 	GYSLEN("resp5s"),	FIELD_RESP5S,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "p95resp5s", 		"p95_5s_resp_ms", 	GYSLEN("p95resp5s"),	FIELD_P95RESP5S,	SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "p95resp5m", 		"p95_5m_resp_ms", 	GYSLEN("p95resp5m"),	FIELD_P95RESP5M,	SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "nconns", 		"nconns", 		GYSLEN("nconns"),	FIELD_NCONNS,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "nactive", 		"nconns_active", 	GYSLEN("nactive"),	FIELD_NACTIVE,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "nprocs", 		"ntasks", 		GYSLEN("nprocs"),	FIELD_NPROCS,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },

{ "kbin15s", 		"curr_kb_inbound", 	GYSLEN("kbin15s"),	FIELD_KBIN15S,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT64,	"bigint",	DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "kbout15s", 		"curr_kb_outbound", 	GYSLEN("kbout15s"),	FIELD_KBOUT15S,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT64,	"bigint",	DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "sererr", 		"ser_http_errors", 	GYSLEN("sererr"),	FIELD_SERERR,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "clierr", 		"cli_http_errors", 	GYSLEN("clierr"),	FIELD_CLIERR,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },

{ "delayus", 		"tasks_delay_usec", 	GYSLEN("delayus"),	FIELD_DELAYUS,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT64,	"bigint",	DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "cpudelus", 		"tasks_cpudelay_usec", 	GYSLEN("cpudelus"),	FIELD_CPUDELUS,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT64,	"bigint",	DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "iodelus", 		"tasks_blkiodelay_usec",GYSLEN("iodelus"),	FIELD_IODELUS,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT64,	"bigint",	DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "vmdelus", 		"tasks_vmdelay_usec", 	GYSLEN("vmdelus"),	FIELD_VMDELUS,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT64,	"bigint",	DB_STR_NONE,	nullptr, 	nullptr,		"", },

{ "usercpu", 		"tasks_user_cpu", 	GYSLEN("usercpu"),	FIELD_USERCPU,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "syscpu", 		"tasks_sys_cpu", 	GYSLEN("syscpu"),	FIELD_SYSCPU,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "rssmb", 		"tasks_rss_mb", 	GYSLEN("rssmb"),	FIELD_RSSMB,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },

{ "svcissue",		"svcissue",		GYSLEN("svcissue"),	FIELD_SVCISSUE,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "inproc",		"inproc",		GYSLEN("inproc"),	FIELD_INPROC,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "inqps",		"inqps",		GYSLEN("inqps"),	FIELD_INQPS,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "inaconn",		"inaconn",		GYSLEN("inaconn"),	FIELD_INACONN,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "inhttperr",		"inhttperr",		GYSLEN("inhttperr"),	FIELD_INHTTPERR,	SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "inoscpu",		"inoscpu",		GYSLEN("inoscpu"),	FIELD_INOSCPU,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "inosmem",		"inosmem",		GYSLEN("inosmem"),	FIELD_INOSMEM,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "indepsvc",		"indepsvc",		GYSLEN("indepsvc"),	FIELD_INDEPSVC,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "inunknown",		"inunknown",		GYSLEN("inunknown"),	FIELD_INUNKNOWN,	SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		

{ "ishttp",		"is_http_svc",		GYSLEN("ishttp"),	FIELD_ISHTTP,		SUBSYS_SVCSTATE,	JSON_BOOL,	NUM_NAN,	"boolean",	DB_STR_NONE,	nullptr, 	booltojson,		"", },		

{ "inrecs",		"inrecs",		GYSLEN("inrecs"),	FIELD_INRECS,		SUBSYS_SVCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		

// Additional fields not present in DB
};

static constexpr DB_AGGR_INFO svcstate_aggr_info[] = 
{
	// dbexpr								// jsoncrc		// dbfieldname		// dbfieldtype	// dflt_aggr	// ignore_sum	// extarg	
	{ "",									FIELD_TIME,		"atime",		"timestamptz",	AOPER_GROUPBY,	false, 		0 },		
	{ "glob_id",								FIELD_SVCID,		"glob_id",		"char(16)",	AOPER_GROUPBY,	false, 		0 },		
	{ "comm",								FIELD_NAME,		"comm",			"char(16)",	AOPER_GROUPBY,	false, 		0 },			
	{ "%s(qps_5s)::int as qps_5s",						FIELD_QPS5S,		"qps_5s",		"int",		AOPER_AVG,	true, 		0 },		
	{ "%s(nqrys_5s)::int as nqrys_5s",					FIELD_NQRY5S,		"nqrys_5s",		"int",		AOPER_AVG,	false, 		0 },		
	{ "%s(avg_5s_resp_ms)::int as avg_5s_resp_ms",				FIELD_RESP5S,		"avg_5s_resp_ms",	"int",		AOPER_AVG,	true, 		0 },		
	{ "%s(p95_5s_resp_ms)::int as p95_5s_resp_ms",				FIELD_P95RESP5S,	"p95_5s_resp_ms",	"int",		AOPER_AVG,	true, 		0 },		
	{ "%s(p95_5m_resp_ms)::int as p95_5m_resp_ms",				FIELD_P95RESP5M,	"p95_5m_resp_ms",	"int",		AOPER_AVG,	true, 		0 },		
	{ "%s(nconns)::int as nconns",						FIELD_NCONNS,		"nconns",		"int",		AOPER_AVG,	true, 		0 },		
	{ "%s(nconns_active)::int as nconns_active",				FIELD_NACTIVE,		"nconns_active",	"int",		AOPER_AVG,	true, 		0 },		
	{ "%s(ntasks)::int as ntasks",						FIELD_NPROCS,		"ntasks",		"int",		AOPER_AVG,	true, 		0 },		
	{ "%s(curr_kb_inbound)::bigint as curr_kb_inbound",			FIELD_KBIN15S,		"curr_kb_inbound",	"bigint",	AOPER_SUM,	false, 		0 },		
	{ "%s(curr_kb_outbound)::bigint as curr_kb_outbound",			FIELD_KBOUT15S,		"curr_kb_outbound",	"bigint",	AOPER_SUM,	false, 		0 },		
	{ "%s(ser_http_errors)::int as ser_http_errors",			FIELD_SERERR,		"ser_http_errors",	"int",		AOPER_SUM,	false, 		0 },		
	{ "%s(cli_http_errors)::int as cli_http_errors",			FIELD_CLIERR,		"cli_http_errors",	"int",		AOPER_SUM,	false, 		0 },		
	{ "%s(tasks_delay_usec)::bigint as tasks_delay_usec",			FIELD_DELAYUS,		"tasks_delay_usec",	"bigint",	AOPER_AVG,	false, 		0 },		
	{ "%s(tasks_cpudelay_usec)::bigint as tasks_cpudelay_usec",		FIELD_CPUDELUS,		"tasks_cpudelay_usec",	"bigint",	AOPER_AVG,	false, 		0 },		
	{ "%s(tasks_blkiodelay_usec)::bigint as tasks_blkiodelay_usec",		FIELD_IODELUS,		"tasks_blkiodelay_usec","bigint",	AOPER_AVG,	false, 		0 },		
	{ "%s(tasks_vmdelay_usec)::bigint as tasks_vmdelay_usec",		FIELD_VMDELUS,		"tasks_vmdelay_usec",	"bigint",	AOPER_AVG,	false, 		0 },		
	{ "%s(tasks_user_cpu)::int as tasks_user_cpu",				FIELD_USERCPU,		"tasks_user_cpu",	"int",		AOPER_AVG,	true, 		0 },		
	{ "%s(tasks_sys_cpu)::int as tasks_sys_cpu",				FIELD_SYSCPU,		"tasks_sys_cpu",	"int",		AOPER_AVG,	true, 		0 },		
	{ "%s(tasks_rss_mb)::int as tasks_rss_mb",				FIELD_RSSMB,		"tasks_rss_mb",		"int",		AOPER_AVG,	true, 		0 },		
	{ "count(*) filter (where curr_state > 2)::int as svcissue",		FIELD_SVCISSUE,		"svcissue",		"int",		AOPER_COUNT,	false, 		0 },		
	{ "count(*) filter (where curr_issue = 1)::int as inproc",		FIELD_INPROC,		"inproc",		"int",		AOPER_COUNT,	false, 		0 },		
	{ "count(*) filter (where curr_issue = 2)::int as inqps",		FIELD_INQPS,		"inqps",		"int",		AOPER_COUNT,	false, 		0 },		
	{ "count(*) filter (where curr_issue = 3)::int as inaconn",		FIELD_INACONN,		"inaconn",		"int",		AOPER_COUNT,	false, 		0 },		
	{ "count(*) filter (where curr_issue = 4)::int as inhttperr",		FIELD_INHTTPERR,	"inhttperr",		"int",		AOPER_COUNT,	false, 		0 },		
	{ "count(*) filter (where curr_issue = 5)::int as inoscpu",		FIELD_INOSCPU,		"inoscpu",		"int",		AOPER_COUNT,	false, 		0 },		
	{ "count(*) filter (where curr_issue = 6)::int as inosmem",		FIELD_INOSMEM,		"inosmem",		"int",		AOPER_COUNT,	false, 		0 },		
	{ "count(*) filter (where curr_issue = 7)::int as indepsvc",		FIELD_INDEPSVC,		"indepsvc",		"int",		AOPER_COUNT,	false, 		0 },		
	{ "count(*) filter (where curr_issue = 8)::int as inunknown",		FIELD_INUNKNOWN,	"inunknown",		"int",		AOPER_COUNT,	false, 		0 },		
	{ "bool_or(is_http_svc) as is_http_svc",				FIELD_ISHTTP,		"is_http_svc",		"boolean",	AOPER_BOOL_OR,	false, 		0 },		
	{ "count(*)::int as inrecs",						FIELD_INRECS,		"inrecs",		"int",		AOPER_COUNT,	false, 		0 },		
};

// SUBSYS_EXTSVCSTATE fields will be updated at run time

enum : uint32_t
{
	/*FIELD_TIME		= fnv1_consthash("time"),*/
	/*FIELD_SVCID		= fnv1_consthash("svcid"),*/
	/*FIELD_NAME		= fnv1_consthash("name"),*/
	FIELD_IP		= fnv1_consthash("ip"),
	FIELD_PORT		= fnv1_consthash("port"),
	FIELD_RELSVCID		= fnv1_consthash("relsvcid"),
	FIELD_TSTART		= fnv1_consthash("tstart"),
	FIELD_CMDLINE		= fnv1_consthash("cmdline"),

	FIELD_P95RESP5D		= fnv1_consthash("p95resp5d"),
	FIELD_AVGRESP5D		= fnv1_consthash("avgresp5d"),
	FIELD_P95QPS		= fnv1_consthash("p95qps"),
	FIELD_P95ACONN		= fnv1_consthash("p95aconn"),

	FIELD_SVCIP1		= fnv1_consthash("svcip1"),
	FIELD_SVCPORT1		= fnv1_consthash("svcport1"),
	FIELD_SVCIP2		= fnv1_consthash("svcip2"),
	FIELD_SVCPORT2		= fnv1_consthash("svcport2"),
	FIELD_SVCDNS		= fnv1_consthash("svcdns"),
	FIELD_SVCTAG		= fnv1_consthash("svctag"),
	FIELD_SVCMESHID		= fnv1_consthash("svcmeshid"),
	FIELD_NSVCMESH		= fnv1_consthash("nsvcmesh"),
	FIELD_IP1CLUID		= fnv1_consthash("ip1cluid"),
	FIELD_NIP1SVC		= fnv1_consthash("nip1svc"),		
	FIELD_IP2CLUID		= fnv1_consthash("ip2cluid"),
	FIELD_NIP2SVC		= fnv1_consthash("nip2svc"),		

	FIELD_REGION		= fnv1_consthash("region"),
	FIELD_ZONE		= fnv1_consthash("zone"),
};	

static constexpr JSON_DB_MAPPING json_db_svcinfo_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys		jsontype	numtype		dbtype 		dbstrtype	oper		dboper				coldesc	
{ "time", 		"time", 		GYSLEN("time"),		FIELD_TIME,		SUBSYS_SVCINFO,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,			"", },
{ "svcid", 		"glob_id", 		GYSLEN("svcid"),	FIELD_SVCID,		SUBSYS_SVCINFO,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,			"", },
{ "name", 		"comm", 		GYSLEN("name"),		FIELD_NAME,		SUBSYS_SVCINFO,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,			"", },
{ "", 			"ns", 			GYSLEN(""),		FIELD_NULL_JSON,	SUBSYS_SVCINFO,	JSON_NUMBER,	NUM_INT64,	"bigint",	DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "ip", 		"ip", 			GYSLEN("ip"),		FIELD_IP,		SUBSYS_SVCINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,			"", },
{ "port", 		"port", 		GYSLEN("port"),		FIELD_PORT,		SUBSYS_SVCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "relsvcid", 		"related_listen_id", 	GYSLEN("relsvcid"),	FIELD_RELSVCID,		SUBSYS_SVCINFO,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,			"", },
{ "tstart", 		"starttime", 		GYSLEN("tstart"),	FIELD_TSTART,		SUBSYS_SVCINFO,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,			"", },
{ "cmdline", 		"cmdline", 		GYSLEN("cmdline"),	FIELD_CMDLINE,		SUBSYS_SVCINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,			"", },

{ "p95resp5d", 		"p95resp5d", 		GYSLEN("p95resp5d"),	FIELD_P95RESP5D,	SUBSYS_SVCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "avgresp5d", 		"avgresp5d", 		GYSLEN("avgresp5d"),	FIELD_AVGRESP5D,	SUBSYS_SVCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "p95qps", 		"p95qps", 		GYSLEN("p95qps"),	FIELD_P95QPS,		SUBSYS_SVCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "p95aconn", 		"p95aconn", 		GYSLEN("p95aconn"),	FIELD_P95ACONN,		SUBSYS_SVCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "svcip1", 		"svcip1", 		GYSLEN("svcip1"),	FIELD_SVCIP1,		SUBSYS_SVCINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,			"", },
{ "svcport1", 		"svcport1",	 	GYSLEN("svcport1"),	FIELD_SVCPORT1,		SUBSYS_SVCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "svcip2", 		"svcip2", 		GYSLEN("svcip2"),	FIELD_SVCIP2,		SUBSYS_SVCINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,			"", },
{ "svcport2", 		"svcport2",	 	GYSLEN("svcport2"),	FIELD_SVCPORT2,		SUBSYS_SVCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "svcdns", 		"svcdns", 		GYSLEN("svcdns"),	FIELD_SVCDNS,		SUBSYS_SVCINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,			"", },
{ "svctag", 		"svctag", 		GYSLEN("svctag"),	FIELD_SVCTAG,		SUBSYS_SVCINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,			"", },
{ "svcmeshid", 		"svcmeshid", 		GYSLEN("svcmeshid"),	FIELD_SVCMESHID,	SUBSYS_SVCINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,			"", },
{ "nsvcmesh", 		"nsvcmesh",	 	GYSLEN("nsvcmesh"),	FIELD_NSVCMESH,		SUBSYS_SVCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "ip1cluid", 		"ip1cluid", 		GYSLEN("ip1cluid"),	FIELD_IP1CLUID,		SUBSYS_SVCINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,			"", },
{ "nip1svc", 		"nip1svc",	 	GYSLEN("nip1svc"),	FIELD_NIP1SVC,		SUBSYS_SVCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "ip2cluid", 		"ip2cluid", 		GYSLEN("ip2cluid"),	FIELD_IP2CLUID,		SUBSYS_SVCINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,			"", },
{ "nip2svc", 		"nip2svc",		GYSLEN("nip2svc"),	FIELD_NIP2SVC,		SUBSYS_SVCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "region",		"region", 		GYSLEN("region"),	FIELD_REGION,		SUBSYS_SVCINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,			"", },
{ "zone",		"zone", 		GYSLEN("zone"),		FIELD_ZONE,		SUBSYS_SVCINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,			"", },

// Additional fields not present in DB
};


static constexpr JSON_DB_MAPPING json_db_aggr_svcinfo_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys		jsontype	numtype		dbtype 		dbstrtype	oper		dboper				coldesc	
{ "time", 		"atime", 		GYSLEN("time"),		FIELD_TIME,		SUBSYS_SVCINFO,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "svcid", 		"glob_id", 		GYSLEN("svcid"),	FIELD_SVCID,		SUBSYS_SVCINFO,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,			"", },
{ "name", 		"comm", 		GYSLEN("name"),		FIELD_NAME,		SUBSYS_SVCINFO,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,			"", },
{ "ip", 		"ip", 			GYSLEN("ip"),		FIELD_IP,		SUBSYS_SVCINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,			"", },
{ "port", 		"port", 		GYSLEN("port"),		FIELD_PORT,		SUBSYS_SVCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "relsvcid", 		"related_listen_id", 	GYSLEN("relsvcid"),	FIELD_RELSVCID,		SUBSYS_SVCINFO,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,			"", },
{ "tstart", 		"starttime", 		GYSLEN("tstart"),	FIELD_TSTART,		SUBSYS_SVCINFO,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,			"", },
{ "cmdline", 		"cmdline", 		GYSLEN("cmdline"),	FIELD_CMDLINE,		SUBSYS_SVCINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,			"", },

{ "p95resp5d", 		"p95resp5d", 		GYSLEN("p95resp5d"),	FIELD_P95RESP5D,	SUBSYS_SVCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "avgresp5d", 		"avgresp5d", 		GYSLEN("avgresp5d"),	FIELD_AVGRESP5D,	SUBSYS_SVCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "p95qps", 		"p95qps", 		GYSLEN("p95qps"),	FIELD_P95QPS,		SUBSYS_SVCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "p95aconn", 		"p95aconn", 		GYSLEN("p95aconn"),	FIELD_P95ACONN,		SUBSYS_SVCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },

{ "svcip1", 		"svcip1", 		GYSLEN("svcip1"),	FIELD_SVCIP1,		SUBSYS_SVCINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,			"", },
{ "svcport1", 		"svcport1",	 	GYSLEN("svcport1"),	FIELD_SVCPORT1,		SUBSYS_SVCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "svcip2", 		"svcip2", 		GYSLEN("svcip2"),	FIELD_SVCIP2,		SUBSYS_SVCINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,			"", },
{ "svcport2", 		"svcport2",	 	GYSLEN("svcport2"),	FIELD_SVCPORT2,		SUBSYS_SVCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "svcdns", 		"svcdns", 		GYSLEN("svcdns"),	FIELD_SVCDNS,		SUBSYS_SVCINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,			"", },
{ "svctag", 		"svctag", 		GYSLEN("svctag"),	FIELD_SVCTAG,		SUBSYS_SVCINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,			"", },
{ "svcmeshid", 		"svcmeshid", 		GYSLEN("svcmeshid"),	FIELD_SVCMESHID,	SUBSYS_SVCINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,			"", },
{ "nsvcmesh", 		"nsvcmesh",	 	GYSLEN("nsvcmesh"),	FIELD_NSVCMESH,		SUBSYS_SVCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "ip1cluid", 		"ip1cluid", 		GYSLEN("ip1cluid"),	FIELD_IP1CLUID,		SUBSYS_SVCINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,			"", },
{ "nip1svc", 		"nip1svc",	 	GYSLEN("nip1svc"),	FIELD_NIP1SVC,		SUBSYS_SVCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "ip2cluid", 		"ip2cluid", 		GYSLEN("ip2cluid"),	FIELD_IP2CLUID,		SUBSYS_SVCINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,			"", },
{ "nip2svc", 		"nip2svc",		GYSLEN("nip2svc"),	FIELD_NIP2SVC,		SUBSYS_SVCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "region",		"region", 		GYSLEN("region"),	FIELD_REGION,		SUBSYS_SVCINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,			"", },
{ "zone",		"zone", 		GYSLEN("zone"),		FIELD_ZONE,		SUBSYS_SVCINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,			"", },
{ "inrecs",		"inrecs",		GYSLEN("inrecs"),	FIELD_INRECS,		SUBSYS_SVCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		

// Additional fields not present in DB
};


static constexpr DB_AGGR_INFO svcinfo_aggr_info[] = 
{
	// dbexpr								// jsoncrc		// dbfieldname		// dbfieldtype	// dflt_aggr	// ignore_sum	// extarg	
	{ "",									FIELD_TIME,		"atime",		"timestamptz",	AOPER_GROUPBY,	false, 		0 },		
	{ "glob_id",								FIELD_SVCID,		"glob_id",		"char(16)",	AOPER_GROUPBY,	false, 		0 },		
	{ "comm",								FIELD_NAME,		"comm",			"char(16)",	AOPER_GROUPBY,	false, 		0 },			
	{ "ip",									FIELD_IP,		"ip",			"text",		AOPER_GROUPBY,	false, 		0 },			
	{ "port",								FIELD_PORT,		"port",			"int",		AOPER_GROUPBY,	false, 		0 },			
	{ "related_listen_id",							FIELD_RELSVCID,		"related_listen_id",	"char(16)",	AOPER_GROUPBY,	false, 		0 },			
	{ "starttime",								FIELD_TSTART,		"starttime",		"timestamptz",	AOPER_GROUPBY,	false, 		0 },			
	{ "cmdline",								FIELD_CMDLINE,		"cmdline",		"text",		AOPER_GROUPBY,	false, 		0 },			
	{ "%s(p95resp5d)::int as p95resp5d",					FIELD_P95RESP5D,	"p95resp5d",		"int",		AOPER_AVG,	true, 		0 },		
	{ "%s(avgresp5d)::int as avgresp5d",					FIELD_AVGRESP5D,	"avgresp5d",		"int",		AOPER_AVG,	true, 		0 },		
	{ "%s(p95qps)::int as p95qps",						FIELD_P95QPS,		"p95qps",		"int",		AOPER_AVG,	true, 		0 },		
	{ "%s(p95aconn)::int as p95aconn",					FIELD_P95ACONN,		"p95aconn",		"int",		AOPER_AVG,	true, 		0 },		
	{ "svcip1",								FIELD_SVCIP1,		"svcip1",		"text",		AOPER_GROUPBY,	false, 		0 },			
	{ "svcport1",								FIELD_SVCPORT1,		"svcport1",		"int",		AOPER_GROUPBY,	false, 		0 },			
	{ "svcip2",								FIELD_SVCIP2,		"svcip2",		"text",		AOPER_GROUPBY,	false, 		0 },			
	{ "svcport2",								FIELD_SVCPORT2,		"svcport2",		"int",		AOPER_GROUPBY,	false, 		0 },			
	{ "svcdns",								FIELD_SVCDNS,		"svcdns",		"text",		AOPER_GROUPBY,	false, 		0 },			
	{ "svctag",								FIELD_SVCTAG,		"svctag",		"text",		AOPER_GROUPBY,	false, 		0 },			
	{ "public.last_elem(svcmeshid) as svcmeshid",				FIELD_SVCMESHID,	"svcmeshid",		"text",		AOPER_LAST_ELEM,false, 		0 },			
	{ "%s(nsvcmesh)::int as nsvcmesh",					FIELD_NSVCMESH,		"nsvcmesh",		"int",		AOPER_AVG,	true, 		0 },			
	{ "public.last_elem(ip1cluid) as ip1cluid",				FIELD_IP1CLUID,		"ip1cluid",		"text",		AOPER_LAST_ELEM,false, 		0 },			
	{ "%s(nip1svc)::int as nip1svc",					FIELD_NIP1SVC,		"nip1svc",		"int",		AOPER_AVG,	true, 		0 },			
	{ "public.last_elem(ip2cluid) as ip2cluid",				FIELD_IP2CLUID,		"ip2cluid",		"text",		AOPER_LAST_ELEM,false, 		0 },			
	{ "%s(nip2svc)::int as nip2svc",					FIELD_NIP2SVC,		"nip2svc",		"int",		AOPER_AVG,	true, 		0 },			
	{ "region",								FIELD_REGION,		"region",		"text",		AOPER_GROUPBY,	false, 		0 },		
	{ "zone",								FIELD_ZONE,		"zone",			"text",		AOPER_GROUPBY,	false, 		0 },		
	{ "count(*)::int as inrecs",						FIELD_INRECS,		"inrecs",		"int",		AOPER_COUNT,	false, 		0 },		
};


enum : uint32_t
{
	/*FIELD_TIME		= fnv1_consthash("time"),*/
	FIELD_NIDLE		= fnv1_consthash("nidle"),
	FIELD_NGOOD		= fnv1_consthash("ngood"),
	FIELD_NOK		= fnv1_consthash("nok"),
	FIELD_NBAD		= fnv1_consthash("nbad"),
	FIELD_NSEVERE		= fnv1_consthash("nsevere"),
	FIELD_NDOWN		= fnv1_consthash("ndown"),
	FIELD_TOTQPS		= fnv1_consthash("totqps"),
	FIELD_TOTACONN		= fnv1_consthash("totaconn"),
	FIELD_TOTKBIN		= fnv1_consthash("totkbin"),
	FIELD_TOTKBOUT		= fnv1_consthash("totkbout"),
	FIELD_TOTSERERR		= fnv1_consthash("totsererr"),
	FIELD_NSVC		= fnv1_consthash("nsvc"),
	/*FIELD_NACTIVE		= fnv1_consthash("nactive"),*/
};	

static constexpr JSON_DB_MAPPING json_db_svcsumm_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys		jsontype	numtype		dbtype 		dbstrtype	oper		dboper				coldesc	
{ "time", 		"time", 		GYSLEN("time"),		FIELD_TIME,		SUBSYS_SVCSUMM,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,			"", },
{ "nidle", 		"nidle", 		GYSLEN("nidle"),	FIELD_NIDLE,		SUBSYS_SVCSUMM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "ngood", 		"ngood", 		GYSLEN("ngood"),	FIELD_NGOOD,		SUBSYS_SVCSUMM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "nok", 		"nok", 			GYSLEN("nok"),		FIELD_NOK,		SUBSYS_SVCSUMM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "nbad", 		"nbad", 		GYSLEN("nbad"),		FIELD_NBAD,		SUBSYS_SVCSUMM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "nsevere", 		"nsevere", 		GYSLEN("nsevere"),	FIELD_NSEVERE,		SUBSYS_SVCSUMM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "ndown", 		"ndown", 		GYSLEN("ndown"),	FIELD_NDOWN,		SUBSYS_SVCSUMM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "totqps", 		"tot_qps", 		GYSLEN("totqps"),	FIELD_TOTQPS,		SUBSYS_SVCSUMM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "totaconn", 		"tot_act_conn",		GYSLEN("totaconn"),	FIELD_TOTACONN,		SUBSYS_SVCSUMM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "totkbin", 		"tot_kb_inbound",	GYSLEN("totkbin"),	FIELD_TOTKBIN,		SUBSYS_SVCSUMM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "totkbout", 		"tot_kb_outbound",	GYSLEN("totkbout"),	FIELD_TOTKBOUT,		SUBSYS_SVCSUMM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "totsererr", 		"tot_ser_errors",	GYSLEN("totsererr"),	FIELD_TOTSERERR,	SUBSYS_SVCSUMM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "nsvc", 		"nlisteners",		GYSLEN("nsvc"),		FIELD_NSVC,		SUBSYS_SVCSUMM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "nactive", 		"nactive",		GYSLEN("nactive"),	FIELD_NACTIVE,		SUBSYS_SVCSUMM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },

// Additional fields not present in DB

};

static constexpr JSON_DB_MAPPING json_db_aggr_svcsumm_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys		jsontype	numtype		dbtype 		dbstrtype	oper		dboper				coldesc
{ "time", 		"atime", 		GYSLEN("time"),		FIELD_TIME,		SUBSYS_SVCSUMM,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,			"", },
{ "nidle", 		"nidle", 		GYSLEN("nidle"),	FIELD_NIDLE,		SUBSYS_SVCSUMM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "ngood", 		"ngood", 		GYSLEN("ngood"),	FIELD_NGOOD,		SUBSYS_SVCSUMM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "nok", 		"nok", 			GYSLEN("nok"),		FIELD_NOK,		SUBSYS_SVCSUMM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "nbad", 		"nbad", 		GYSLEN("nbad"),		FIELD_NBAD,		SUBSYS_SVCSUMM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "nsevere", 		"nsevere", 		GYSLEN("nsevere"),	FIELD_NSEVERE,		SUBSYS_SVCSUMM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "ndown", 		"ndown", 		GYSLEN("ndown"),	FIELD_NDOWN,		SUBSYS_SVCSUMM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "totqps", 		"tot_qps", 		GYSLEN("totqps"),	FIELD_TOTQPS,		SUBSYS_SVCSUMM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "totaconn", 		"tot_act_conn",		GYSLEN("totaconn"),	FIELD_TOTACONN,		SUBSYS_SVCSUMM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "totkbin", 		"tot_kb_inbound",	GYSLEN("totkbin"),	FIELD_TOTKBIN,		SUBSYS_SVCSUMM,	JSON_NUMBER,	NUM_INT32,	"bigint",	DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "totkbout", 		"tot_kb_outbound",	GYSLEN("totkbout"),	FIELD_TOTKBOUT,		SUBSYS_SVCSUMM,	JSON_NUMBER,	NUM_INT32,	"bigint",	DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "totsererr", 		"tot_ser_errors",	GYSLEN("totsererr"),	FIELD_TOTSERERR,	SUBSYS_SVCSUMM,	JSON_NUMBER,	NUM_INT32,	"bigint",	DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "nsvc", 		"nlisteners",		GYSLEN("nsvc"),		FIELD_NSVC,		SUBSYS_SVCSUMM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "nactive", 		"nactive",		GYSLEN("nactive"),	FIELD_NACTIVE,		SUBSYS_SVCSUMM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },
{ "inrecs",		"inrecs",		GYSLEN("inrecs"),	FIELD_INRECS,		SUBSYS_SVCSUMM,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		

// Additional fields not present in DB

};

static constexpr DB_AGGR_INFO svcsumm_aggr_info[] = 
{
	// dbexpr								// jsoncrc		// dbfieldname		// dbfieldtype	// dflt_aggr	// ignore_sum	// extarg	
	{ "",									FIELD_TIME,		"atime",		"timestamptz",	AOPER_GROUPBY,	false, 		0 },		
	{ "%s(nidle)::int as nidle",						FIELD_NIDLE,		"nidle",		"int",		AOPER_AVG,	false, 		0 },		
	{ "%s(ngood)::int as ngood",						FIELD_NGOOD,		"ngood",		"int",		AOPER_AVG,	false, 		0 },		
	{ "%s(nok)::int as nok",						FIELD_NOK,		"nok",			"int",		AOPER_AVG,	false, 		0 },		
	{ "%s(nbad)::int as nbad",						FIELD_NBAD,		"nbad",			"int",		AOPER_AVG,	false, 		0 },		
	{ "%s(nsevere)::int as nsevere",					FIELD_NSEVERE,		"nsevere",		"int",		AOPER_AVG,	false, 		0 },		
	{ "%s(ndown)::int as ndown",						FIELD_NDOWN,		"ndown",		"int",		AOPER_AVG,	false, 		0 },		
	{ "%s(tot_qps)::int as tot_qps",					FIELD_TOTQPS,		"tot_qps",		"int",		AOPER_AVG,	true, 		0 },		
	{ "%s(tot_act_conn)::int as tot_act_conn",				FIELD_TOTACONN,		"tot_act_conn",		"int",		AOPER_AVG,	true, 		0 },		
	{ "%s(tot_kb_inbound)::bigint as tot_kb_inbound",			FIELD_TOTKBIN,		"tot_kb_inbound",	"bigint",	AOPER_AVG,	false, 		0 },		
	{ "%s(tot_kb_outbound)::bigint as tot_kb_outbound",			FIELD_TOTKBOUT,		"tot_kb_outbound",	"bigint",	AOPER_AVG,	false, 		0 },		
	{ "%s(tot_ser_errors)::bigint as tot_ser_errors",			FIELD_TOTSERERR,	"tot_ser_errors",	"bigint",	AOPER_AVG,	false, 		0 },		
	{ "%s(nlisteners)::int as nlisteners",					FIELD_NSVC,		"nlisteners",		"int",		AOPER_AVG,	true, 		0 },		
	{ "%s(nactive)::int as nactive",					FIELD_NACTIVE,		"nactive",		"int",		AOPER_AVG,	true, 		0 },		
	{ "count(*)::int as inrecs",						FIELD_INRECS,		"inrecs",		"int",		AOPER_COUNT,	false, 		0 },		
};

enum : uint32_t
{
	/*FIELD_TIME		= fnv1_consthash("time"),*/
	/*FIELD_SVCID		= fnv1_consthash("svcid"),*/
	FIELD_SVCNAME		= fnv1_consthash("svcname"),
	FIELD_CPROCID		= fnv1_consthash("cprocid"),
	FIELD_CNAME		= fnv1_consthash("cname"),
	FIELD_CPARID		= fnv1_consthash("cparid"),
	FIELD_CMADID		= fnv1_consthash("cmadid"),
	FIELD_CNETOUT		= fnv1_consthash("cnetout"),
	FIELD_CNETIN		= fnv1_consthash("cnetin"),
	FIELD_CDELMS		= fnv1_consthash("cdelms"),
	FIELD_SDELMS		= fnv1_consthash("sdelms"),
	FIELD_RTTMS		= fnv1_consthash("rttms"),
	/*FIELD_NCONNS		= fnv1_consthash("nconns"),*/
	FIELD_CSVC		= fnv1_consthash("csvc"),
};	

static constexpr JSON_DB_MAPPING json_db_activeconn_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys			jsontype	numtype		dbtype 		dbstrtype	oper		dboper			coldesc
{ "time", 		"time", 		GYSLEN("time"),		FIELD_TIME,		SUBSYS_ACTIVECONN,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "svcid", 		"listen_id", 		GYSLEN("svcid"),	FIELD_SVCID,		SUBSYS_ACTIVECONN,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "svcname", 		"listen_comm", 		GYSLEN("svcname"),	FIELD_SVCNAME,		SUBSYS_ACTIVECONN,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "cprocid", 		"cli_aggr_task_id",	GYSLEN("cprocid"),	FIELD_CPROCID,		SUBSYS_ACTIVECONN,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "cname", 		"cli_comm", 		GYSLEN("cname"),	FIELD_CNAME,		SUBSYS_ACTIVECONN,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "cparid", 		"cli_parthaid", 	GYSLEN("cparid"),	FIELD_CPARID,		SUBSYS_ACTIVECONN,	JSON_STRING,	NUM_NAN,	"char(32)",	DB_STR_OCHAR,	nullptr,	nullptr,		"", },
{ "cmadid",		"cli_madhavaid", 	GYSLEN("cmadid"),	FIELD_CMADID,		SUBSYS_ACTIVECONN,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr,	nullptr,		"", },
{ "cnetout",		"cli_bytes_sent", 	GYSLEN("cnetout"),	FIELD_CNETOUT,		SUBSYS_ACTIVECONN,	JSON_NUMBER,	NUM_INT64,	"bigint",	DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "cnetin",		"cli_bytes_received", 	GYSLEN("cnetin"),	FIELD_CNETIN,		SUBSYS_ACTIVECONN,	JSON_NUMBER,	NUM_INT64,	"bigint",	DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "cdelms",		"cli_delay_msec",	GYSLEN("cdelms"),	FIELD_CDELMS,		SUBSYS_ACTIVECONN,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "sdelms",		"ser_delay_msec",	GYSLEN("sdelms"),	FIELD_SDELMS,		SUBSYS_ACTIVECONN,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "rttms",		"max_rtt_msec",		GYSLEN("rttms"),	FIELD_RTTMS,		SUBSYS_ACTIVECONN,	JSON_NUMBER,	NUM_DOUBLE,	"real",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "nconns",		"cli_active_conns",	GYSLEN("nconns"),	FIELD_NCONNS,		SUBSYS_ACTIVECONN,	JSON_NUMBER,	NUM_INT16,	"smallint",	DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "csvc",		"cli_listener_proc",	GYSLEN("csvc"),		FIELD_CSVC,		SUBSYS_ACTIVECONN,	JSON_BOOL,	NUM_NAN,	"boolean",	DB_STR_NONE,	nullptr, 	booltojson,		"", },		

// Additional fields not present in DB

};

static constexpr JSON_DB_MAPPING json_db_aggr_activeconn_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys			jsontype	numtype		dbtype 		dbstrtype	oper		dboper			coldesc
{ "time", 		"atime", 		GYSLEN("time"),		FIELD_TIME,		SUBSYS_ACTIVECONN,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "svcid", 		"listen_id", 		GYSLEN("svcid"),	FIELD_SVCID,		SUBSYS_ACTIVECONN,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "svcname", 		"listen_comm", 		GYSLEN("svcname"),	FIELD_SVCNAME,		SUBSYS_ACTIVECONN,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "cprocid", 		"cli_aggr_task_id",	GYSLEN("cprocid"),	FIELD_CPROCID,		SUBSYS_ACTIVECONN,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "cname", 		"cli_comm", 		GYSLEN("cname"),	FIELD_CNAME,		SUBSYS_ACTIVECONN,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "cparid", 		"cli_parthaid", 	GYSLEN("cparid"),	FIELD_CPARID,		SUBSYS_ACTIVECONN,	JSON_STRING,	NUM_NAN,	"char(32)",	DB_STR_OCHAR,	nullptr,	nullptr,		"", },
{ "cmadid",		"cli_madhavaid", 	GYSLEN("cmadid"),	FIELD_CMADID,		SUBSYS_ACTIVECONN,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr,	nullptr,		"", },
{ "cnetout",		"cli_bytes_sent", 	GYSLEN("cnetout"),	FIELD_CNETOUT,		SUBSYS_ACTIVECONN,	JSON_NUMBER,	NUM_INT64,	"bigint",	DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "cnetin",		"cli_bytes_received", 	GYSLEN("cnetin"),	FIELD_CNETIN,		SUBSYS_ACTIVECONN,	JSON_NUMBER,	NUM_INT64,	"bigint",	DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "cdelms",		"cli_delay_msec",	GYSLEN("cdelms"),	FIELD_CDELMS,		SUBSYS_ACTIVECONN,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "sdelms",		"ser_delay_msec",	GYSLEN("sdelms"),	FIELD_SDELMS,		SUBSYS_ACTIVECONN,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "rttms",		"max_rtt_msec",		GYSLEN("rttms"),	FIELD_RTTMS,		SUBSYS_ACTIVECONN,	JSON_NUMBER,	NUM_DOUBLE,	"real",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "nconns",		"cli_active_conns",	GYSLEN("nconns"),	FIELD_NCONNS,		SUBSYS_ACTIVECONN,	JSON_NUMBER,	NUM_INT16,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "csvc",		"cli_listener_proc",	GYSLEN("csvc"),		FIELD_CSVC,		SUBSYS_ACTIVECONN,	JSON_BOOL,	NUM_NAN,	"boolean",	DB_STR_NONE,	nullptr, 	booltojson,		"", },		
{ "inrecs",		"inrecs",		GYSLEN("inrecs"),	FIELD_INRECS,		SUBSYS_ACTIVECONN,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		

// Additional fields not present in DB

};

static constexpr DB_AGGR_INFO activeconn_aggr_info[] = 
{
	// dbexpr								// jsoncrc		// dbfieldname		// dbfieldtype	// dflt_aggr	// ignore_sum	// extarg	
	{ "",									FIELD_TIME,		"atime",		"timestamptz",	AOPER_GROUPBY,	false, 		0 },		
	{ "listen_id",								FIELD_SVCID,		"listen_id",		"char(16)",	AOPER_GROUPBY,	false, 		0 },		
	{ "listen_comm",							FIELD_SVCNAME,		"listen_comm",		"char(16)",	AOPER_GROUPBY,	false, 		0 },		
	{ "cli_aggr_task_id",							FIELD_CPROCID,		"cli_aggr_task_id",	"char(16)",	AOPER_GROUPBY,	false, 		0 },		
	{ "cli_comm",								FIELD_CNAME,		"cli_comm",		"char(16)",	AOPER_GROUPBY,	false, 		0 },		
	{ "cli_parthaid",							FIELD_CPARID,		"cli_parthaid",		"char(32)",	AOPER_GROUPBY,	false, 		0 },		
	{ "cli_madhavaid",							FIELD_CMADID,		"cli_madhavaid",	"char(16)",	AOPER_GROUPBY,	false, 		0 },		
	{ "%s(cli_bytes_sent)::bigint as cli_bytes_sent",			FIELD_CNETOUT,		"cli_bytes_sent",	"bigint",	AOPER_SUM,	false, 		0 },		
	{ "%s(cli_bytes_received)::bigint as cli_bytes_received",		FIELD_CNETIN,		"cli_bytes_received",	"bigint",	AOPER_SUM,	false, 		0 },		
	{ "%s(cli_delay_msec)::int as cli_delay_msec",				FIELD_CDELMS,		"cli_delay_msec",	"int",		AOPER_AVG,	false, 		0 },		
	{ "%s(ser_delay_msec)::int as ser_delay_msec",				FIELD_SDELMS,		"ser_delay_msec",	"int",		AOPER_AVG,	false, 		0 },		
	{ "%s(max_rtt_msec)::real as max_rtt_msec",				FIELD_RTTMS,		"max_rtt_msec",		"real",		AOPER_AVG,	true, 		0 },		
	{ "%s(cli_active_conns)::int as cli_active_conns",			FIELD_NCONNS,		"cli_active_conns",	"int",		AOPER_AVG,	true, 		0 },		
	{ "bool_or(cli_listener_proc) as cli_listener_proc",			FIELD_CSVC,		"cli_listener_proc",	"boolean",	AOPER_BOOL_OR,	false, 		0 },		
	{ "count(*)::int as inrecs",						FIELD_INRECS,		"inrecs",		"int",		AOPER_COUNT,	false, 		0 },		

};	

enum : uint32_t
{
	/*FIELD_TIME		= fnv1_consthash("time"),*/
	/*FIELD_CPROCID		= fnv1_consthash("cprocid"),*/
	/*FIELD_CNAME		= fnv1_consthash("cname"),*/
	/*FIELD_SVCID		= fnv1_consthash("svcid"),*/
	/*FIELD_SVCNAME		= fnv1_consthash("svcname"),*/
	FIELD_SPARID		= fnv1_consthash("sparid"),
	FIELD_SMADID		= fnv1_consthash("smadid"),
	/*FIELD_CNETOUT		= fnv1_consthash("cnetout"),*/
	/*FIELD_CNETIN		= fnv1_consthash("cnetin"),*/
	/*FIELD_NCONNS		= fnv1_consthash("nconns"),*/
	/*FIELD_CSVC		= fnv1_consthash("csvc"),*/
};	

static constexpr JSON_DB_MAPPING json_db_clientconn_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys			jsontype	numtype		dbtype 		dbstrtype	oper		dboper			coldesc
{ "time", 		"time", 		GYSLEN("time"),		FIELD_TIME,		SUBSYS_CLIENTCONN,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "cprocid", 		"cli_aggr_task_id",	GYSLEN("cprocid"),	FIELD_CPROCID,		SUBSYS_CLIENTCONN,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "cname", 		"cli_comm", 		GYSLEN("cname"),	FIELD_CNAME,		SUBSYS_CLIENTCONN,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "svcid", 		"listen_id", 		GYSLEN("svcid"),	FIELD_SVCID,		SUBSYS_CLIENTCONN,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "svcname", 		"listen_comm", 		GYSLEN("svcname"),	FIELD_SVCNAME,		SUBSYS_CLIENTCONN,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "sparid", 		"listen_parthaid", 	GYSLEN("sparid"),	FIELD_SPARID,		SUBSYS_CLIENTCONN,	JSON_STRING,	NUM_NAN,	"char(32)",	DB_STR_OCHAR,	nullptr,	nullptr,		"", },
{ "smadid",		"listen_madhavaid", 	GYSLEN("smadid"),	FIELD_SMADID,		SUBSYS_CLIENTCONN,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr,	nullptr,		"", },
{ "cnetout",		"cli_bytes_sent", 	GYSLEN("cnetout"),	FIELD_CNETOUT,		SUBSYS_CLIENTCONN,	JSON_NUMBER,	NUM_INT64,	"bigint",	DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "cnetin",		"cli_bytes_received", 	GYSLEN("cnetin"),	FIELD_CNETIN,		SUBSYS_CLIENTCONN,	JSON_NUMBER,	NUM_INT64,	"bigint",	DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "nconns",		"cli_active_conns",	GYSLEN("nconns"),	FIELD_NCONNS,		SUBSYS_CLIENTCONN,	JSON_NUMBER,	NUM_INT16,	"smallint",	DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "csvc",		"cli_listener_proc",	GYSLEN("csvc"),		FIELD_CSVC,		SUBSYS_CLIENTCONN,	JSON_BOOL,	NUM_NAN,	"boolean",	DB_STR_NONE,	nullptr, 	booltojson,		"", },		

// Additional fields not present in DB

};

static constexpr JSON_DB_MAPPING json_db_aggr_clientconn_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys			jsontype	numtype		dbtype 		dbstrtype	oper		dboper			coldesc
{ "time", 		"atime", 		GYSLEN("time"),		FIELD_TIME,		SUBSYS_CLIENTCONN,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "cprocid", 		"cli_aggr_task_id",	GYSLEN("cprocid"),	FIELD_CPROCID,		SUBSYS_CLIENTCONN,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "cname", 		"cli_comm", 		GYSLEN("cname"),	FIELD_CNAME,		SUBSYS_CLIENTCONN,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "svcid", 		"listen_id", 		GYSLEN("svcid"),	FIELD_SVCID,		SUBSYS_CLIENTCONN,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "svcname", 		"listen_comm", 		GYSLEN("svcname"),	FIELD_SVCNAME,		SUBSYS_CLIENTCONN,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "sparid", 		"listen_parthaid", 	GYSLEN("sparid"),	FIELD_SPARID,		SUBSYS_CLIENTCONN,	JSON_STRING,	NUM_NAN,	"char(32)",	DB_STR_OCHAR,	nullptr,	nullptr,		"", },
{ "smadid",		"listen_madhavaid", 	GYSLEN("smadid"),	FIELD_SMADID,		SUBSYS_CLIENTCONN,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr,	nullptr,		"", },
{ "cnetout",		"cli_bytes_sent", 	GYSLEN("cnetout"),	FIELD_CNETOUT,		SUBSYS_CLIENTCONN,	JSON_NUMBER,	NUM_INT64,	"bigint",	DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "cnetin",		"cli_bytes_received", 	GYSLEN("cnetin"),	FIELD_CNETIN,		SUBSYS_CLIENTCONN,	JSON_NUMBER,	NUM_INT64,	"bigint",	DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "nconns",		"cli_active_conns",	GYSLEN("nconns"),	FIELD_NCONNS,		SUBSYS_CLIENTCONN,	JSON_NUMBER,	NUM_INT16,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "csvc",		"cli_listener_proc",	GYSLEN("csvc"),		FIELD_CSVC,		SUBSYS_CLIENTCONN,	JSON_BOOL,	NUM_NAN,	"boolean",	DB_STR_NONE,	nullptr, 	booltojson,		"", },		
{ "inrecs",		"inrecs",		GYSLEN("inrecs"),	FIELD_INRECS,		SUBSYS_CLIENTCONN,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		

// Additional fields not present in DB

};

static constexpr DB_AGGR_INFO clientconn_aggr_info[] = 
{
	// dbexpr								// jsoncrc		// dbfieldname		// dbfieldtype	// dflt_aggr	// ignore_sum	// extarg	
	{ "",									FIELD_TIME,		"atime",		"timestamptz",	AOPER_GROUPBY,	false, 		0 },		
	{ "cli_aggr_task_id",							FIELD_CPROCID,		"cli_aggr_task_id",	"char(16)",	AOPER_GROUPBY,	false, 		0 },		
	{ "cli_comm",								FIELD_CNAME,		"cli_comm",		"char(16)",	AOPER_GROUPBY,	false, 		0 },		
	{ "listen_id",								FIELD_SVCID,		"listen_id",		"char(16)",	AOPER_GROUPBY,	false, 		0 },		
	{ "listen_comm",							FIELD_SVCNAME,		"listen_comm",		"char(16)",	AOPER_GROUPBY,	false, 		0 },		
	{ "listen_parthaid",							FIELD_SPARID,		"listen_parthaid",	"char(32)",	AOPER_GROUPBY,	false, 		0 },		
	{ "listen_madhavaid",							FIELD_SMADID,		"listen_madhavaid",	"char(16)",	AOPER_GROUPBY,	false, 		0 },		
	{ "%s(cli_bytes_sent)::bigint as cli_bytes_sent",			FIELD_CNETOUT,		"cli_bytes_sent",	"bigint",	AOPER_SUM,	false, 		0 },		
	{ "%s(cli_bytes_received)::bigint as cli_bytes_received",		FIELD_CNETIN,		"cli_bytes_received",	"bigint",	AOPER_SUM,	false, 		0 },		
	{ "%s(cli_active_conns)::int as cli_active_conns",			FIELD_NCONNS,		"cli_active_conns",	"int",		AOPER_AVG,	true, 		0 },		
	{ "bool_or(cli_listener_proc) as cli_listener_proc",			FIELD_CSVC,		"cli_listener_proc",	"boolean",	AOPER_BOOL_OR,	false, 		0 },		
	{ "count(*)::int as inrecs",						FIELD_INRECS,		"inrecs",		"int",		AOPER_COUNT,	false, 		0 },		
};	


enum : uint32_t
{
	/*FIELD_TIME		= fnv1_consthash("time"),*/
	/*FIELD_RELSVCID	= fnv1_consthash("relsvcid"),*/
	/*FIELD_SVCNAME		= fnv1_consthash("svcname"),*/
	FIELD_SVCIDARR		= fnv1_consthash("svcidarr"),
	FIELD_PROCIDARR		= fnv1_consthash("procidarr"),
};	

static constexpr JSON_DB_MAPPING json_db_svcprocmap_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys			jsontype	numtype		dbtype 		dbstrtype	oper		dboper			coldesc
{ "time", 		"time", 		GYSLEN("time"),		FIELD_TIME,		SUBSYS_SVCPROCMAP,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "relsvcid",		"related_listen_id",	GYSLEN("relsvcid"),	FIELD_RELSVCID,		SUBSYS_SVCPROCMAP,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "svcname", 		"ser_comm", 		GYSLEN("svcname"),	FIELD_SVCNAME,		SUBSYS_SVCPROCMAP,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "svcidarr", 		"glob_id_arr", 		GYSLEN("svcidarr"),	FIELD_SVCIDARR,		SUBSYS_SVCPROCMAP,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "procidarr", 		"aggr_task_id_arr", 	GYSLEN("procidarr"),	FIELD_PROCIDARR,	SUBSYS_SVCPROCMAP,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,		"", },

// Additional fields not present in DB
};

enum : uint32_t
{
	/*FIELD_TIME		= fnv1_consthash("time"),*/
	FIELD_TYPE		= fnv1_consthash("type"),
	/*FIELD_PARID		= fnv1_consthash("parid"),*/
	FIELD_MSG		= fnv1_consthash("msg"),
};	

static constexpr JSON_DB_MAPPING json_db_notifymsg_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys			jsontype	numtype		dbtype 		dbstrtype	oper		dboper			coldesc
{ "time", 		"time", 		GYSLEN("time"),		FIELD_TIME,		SUBSYS_NOTIFYMSG,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "type", 		"type",			GYSLEN("type"),		FIELD_TYPE,		SUBSYS_NOTIFYMSG,	JSON_STRING,	NUM_NAN,	"char(8)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "parid", 		"machid", 		GYSLEN("parid"),	FIELD_PARID,		SUBSYS_NOTIFYMSG,	JSON_STRING,	NUM_NAN,	"char(32)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "msg", 		"msg", 			GYSLEN("msg"),		FIELD_MSG,		SUBSYS_NOTIFYMSG,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,		"", },

// Additional fields not present in DB
};

enum : uint32_t
{
	/*FIELD_TIME		= fnv1_consthash("time"),*/
	FIELD_PROCID		= fnv1_consthash("procid"),
	/*FIELD_NAME		= fnv1_consthash("name"),*/
	FIELD_PID1		= fnv1_consthash("pid1"),
	FIELD_PID2		= fnv1_consthash("pid2"),
	FIELD_NETKB		= fnv1_consthash("netkb"),
	FIELD_NCONN		= fnv1_consthash("nconn"),
	FIELD_CPU		= fnv1_consthash("cpu"),
	FIELD_RSS		= fnv1_consthash("rss"),
	FIELD_CPUDEL		= fnv1_consthash("cpudel"),
	FIELD_VMDEL		= fnv1_consthash("vmdel"),
	FIELD_IODEL		= fnv1_consthash("iodel"),
	/*FIELD_NPROCS		= fnv1_consthash("nprocs"),*/
	/*FIELD_NISSUE		= fnv1_consthash("nissue"),*/
	/*FIELD_STATE		= fnv1_consthash("state"),*/
	/*FIELD_ISSUE		= fnv1_consthash("issue"),*/
	/*FIELD_DESC		= fnv1_consthash("desc"),*/
};	

static constexpr JSON_DB_MAPPING json_db_procstate_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys			jsontype	numtype		dbtype 		dbstrtype	oper		dboper			coldesc
{ "time", 		"time", 		GYSLEN("time"),		FIELD_TIME,		SUBSYS_PROCSTATE,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "procid", 		"aggr_task_id", 	GYSLEN("procid"),	FIELD_PROCID,		SUBSYS_PROCSTATE,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "name", 		"comm", 		GYSLEN("name"),		FIELD_NAME,		SUBSYS_PROCSTATE,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "pid1",		"pid1",			GYSLEN("pid1"),		FIELD_PID1,		SUBSYS_PROCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "pid2",		"pid2",			GYSLEN("pid2"),		FIELD_PID2,		SUBSYS_PROCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "netkb",		"tcp_kbytes",		GYSLEN("netkb"),	FIELD_NETKB,		SUBSYS_PROCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "nconn",		"tcp_conns",		GYSLEN("nconn"),	FIELD_NCONN,		SUBSYS_PROCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "cpu",		"total_cpu_pct",	GYSLEN("cpu"),		FIELD_CPU,		SUBSYS_PROCSTATE,	JSON_NUMBER,	NUM_DOUBLE,	"real",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "rss",		"rss_mb",		GYSLEN("rss"),		FIELD_RSS,		SUBSYS_PROCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "cpudel",		"cpu_delay_msec",	GYSLEN("cpudel"),	FIELD_CPUDEL,		SUBSYS_PROCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "vmdel",		"vm_delay_msec",	GYSLEN("vmdel"),	FIELD_VMDEL,		SUBSYS_PROCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "iodel",		"blkio_delay_msec",	GYSLEN("iodel"),	FIELD_IODEL,		SUBSYS_PROCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "nprocs",		"ntasks_total",		GYSLEN("nprocs"),	FIELD_NPROCS,		SUBSYS_PROCSTATE,	JSON_NUMBER,	NUM_INT16,	"smallint",	DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "nissue", 		"ntasks_issue", 	GYSLEN("nissue"),	FIELD_NISSUE,		SUBSYS_PROCSTATE,	JSON_NUMBER,	NUM_INT16,	"smallint",	DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "state",		"curr_state",		GYSLEN("state"),	FIELD_STATE,		SUBSYS_PROCSTATE,	JSON_STRING,	NUM_NAN,	"smallint",	DB_STR_NONE,	statefromjson, 	statetojson,		"", },		
{ "issue",		"curr_issue",		GYSLEN("issue"),	FIELD_ISSUE,		SUBSYS_PROCSTATE,	JSON_NUMBER,	NUM_INT16,	"smallint",	DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "",			"issue_bit_hist",	GYSLEN(""),		FIELD_NULL_JSON,	SUBSYS_PROCSTATE,	JSON_NUMBER,	NUM_INT16,	"smallint",	DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "",			"severe_issue_bit_hist",GYSLEN(""),		FIELD_NULL_JSON,	SUBSYS_PROCSTATE,	JSON_NUMBER,	NUM_INT16,	"smallint",	DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "desc",		"issue_string",		GYSLEN("desc"),		FIELD_DESC,		SUBSYS_PROCSTATE,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,		"", },		

// Additional fields not present in DB
};

enum : uint32_t
{
	FIELD_INCPUDEL		= fnv1_consthash("incpudel"),
	FIELD_INIODEL		= fnv1_consthash("iniodel"),
	FIELD_INSWPDEL		= fnv1_consthash("inswpdel"),
	FIELD_INRECDEL		= fnv1_consthash("inrecdel"),
	FIELD_INTHRDEL		= fnv1_consthash("inthrdel"),
	FIELD_INVCSW		= fnv1_consthash("invcsw"),
	FIELD_INIVCSW		= fnv1_consthash("inivcsw"),
	FIELD_INPGFLT		= fnv1_consthash("inpgflt"),
	FIELD_INCPU		= fnv1_consthash("incpu"),
	FIELD_INSTOP		= fnv1_consthash("instop"),
	FIELD_INPTR		= fnv1_consthash("inptr"),
};

static constexpr JSON_DB_MAPPING json_db_aggr_procstate_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys			jsontype	numtype		dbtype 		dbstrtype	oper		dboper			coldesc
{ "time", 		"atime", 		GYSLEN("time"),		FIELD_TIME,		SUBSYS_PROCSTATE,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "procid", 		"aggr_task_id", 	GYSLEN("procid"),	FIELD_PROCID,		SUBSYS_PROCSTATE,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "name", 		"comm", 		GYSLEN("name"),		FIELD_NAME,		SUBSYS_PROCSTATE,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "netkb",		"tcp_kbytes",		GYSLEN("netkb"),	FIELD_NETKB,		SUBSYS_PROCSTATE,	JSON_NUMBER,	NUM_INT64,	"bigint",	DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "nconn",		"tcp_conns",		GYSLEN("nconn"),	FIELD_NCONN,		SUBSYS_PROCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "cpu",		"total_cpu_pct",	GYSLEN("cpu"),		FIELD_CPU,		SUBSYS_PROCSTATE,	JSON_NUMBER,	NUM_DOUBLE,	"real",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "rss",		"rss_mb",		GYSLEN("rss"),		FIELD_RSS,		SUBSYS_PROCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "cpudel",		"cpu_delay_msec",	GYSLEN("cpudel"),	FIELD_CPUDEL,		SUBSYS_PROCSTATE,	JSON_NUMBER,	NUM_INT64,	"bigint",	DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "vmdel",		"vm_delay_msec",	GYSLEN("vmdel"),	FIELD_VMDEL,		SUBSYS_PROCSTATE,	JSON_NUMBER,	NUM_INT64,	"bigint",	DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "iodel",		"blkio_delay_msec",	GYSLEN("iodel"),	FIELD_IODEL,		SUBSYS_PROCSTATE,	JSON_NUMBER,	NUM_INT64,	"bigint",	DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "nprocs",		"ntasks_total",		GYSLEN("nprocs"),	FIELD_NPROCS,		SUBSYS_PROCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "issue",		"issue",		GYSLEN("issue"),	FIELD_ISSUE,		SUBSYS_PROCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "incpudel",		"incpudel",		GYSLEN("incpudel"),	FIELD_INCPUDEL,		SUBSYS_PROCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "iniodel",		"iniodel",		GYSLEN("iniodel"),	FIELD_INIODEL,		SUBSYS_PROCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "inswpdel",		"inswpdel",		GYSLEN("inswpdel"),	FIELD_INSWPDEL,		SUBSYS_PROCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "inrecdel",		"inrecdel",		GYSLEN("inrecdel"),	FIELD_INRECDEL,		SUBSYS_PROCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "inthrdel",		"inthrdel",		GYSLEN("inthrdel"),	FIELD_INTHRDEL,		SUBSYS_PROCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "invcsw",		"invcsw",		GYSLEN("invcsw"),	FIELD_INVCSW,		SUBSYS_PROCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "inivcsw",		"inivcsw",		GYSLEN("inivcsw"),	FIELD_INIVCSW,		SUBSYS_PROCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "inpgflt",		"inpgflt",		GYSLEN("inpgflt"),	FIELD_INPGFLT,		SUBSYS_PROCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "incpu",		"incpu",		GYSLEN("incpu"),	FIELD_INCPU,		SUBSYS_PROCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "instop",		"instop",		GYSLEN("instop"),	FIELD_INSTOP,		SUBSYS_PROCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "inptr",		"inptr",		GYSLEN("inptr"),	FIELD_INPTR,		SUBSYS_PROCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "inrecs",		"inrecs",		GYSLEN("inrecs"),	FIELD_INRECS,		SUBSYS_PROCSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		

// Additional fields not present in DB
};

static constexpr DB_AGGR_INFO procstate_aggr_info[] = 
{
	// dbexpr								// jsoncrc		// dbfieldname		// dbfieldtype	// dflt_aggr	// ignore_sum	// extarg	
	{ "",									FIELD_TIME,		"atime",		"timestamptz",	AOPER_GROUPBY,	false, 		0 },		
	{ "aggr_task_id",							FIELD_PROCID,		"aggr_task_id",		"char(16)",	AOPER_GROUPBY,	false, 		0 },		
	{ "comm",								FIELD_NAME,		"comm",			"char(16)",	AOPER_GROUPBY,	false, 		0 },		
	{ "%s(tcp_kbytes)::bigint as tcp_kbytes",				FIELD_NETKB,		"tcp_kbytes",		"bigint",	AOPER_AVG,	false, 		0 },		
	{ "%s(tcp_conns)::int as tcp_conns",					FIELD_NCONN,		"tcp_conns",		"int",		AOPER_AVG,	false, 		0 },		
	{ "%s(total_cpu_pct)::real as total_cpu_pct",				FIELD_CPU,		"total_cpu_pct",	"real",		AOPER_AVG,	true, 		0 },		
	{ "%s(rss_mb)::int as rss_mb",						FIELD_RSS,		"rss_mb",		"int",		AOPER_AVG,	true, 		0 },		
	{ "%s(cpu_delay_msec)::bigint as cpu_delay_msec",			FIELD_CPUDEL,		"cpu_delay_msec",	"bigint",	AOPER_AVG,	false, 		0 },		
	{ "%s(vm_delay_msec)::bigint as vm_delay_msec",				FIELD_VMDEL,		"vm_delay_msec",	"bigint",	AOPER_AVG,	false, 		0 },		
	{ "%s(blkio_delay_msec)::bigint as blkio_delay_msec",			FIELD_IODEL,		"blkio_delay_msec",	"bigint",	AOPER_AVG,	false, 		0 },		
	{ "%s(ntasks_total)::int as ntasks_total",				FIELD_NPROCS,		"ntasks_total",		"int",		AOPER_AVG,	true, 		0 },		
	{ "count(*) filter (where curr_state > 2)::int as issue",		FIELD_ISSUE,		"issue",		"int",		AOPER_COUNT,	false, 		0 },		
	{ "count(*) filter (where curr_issue = 1)::int as incpudel",		FIELD_INCPUDEL,		"incpudel",		"int",		AOPER_COUNT,	false, 		0 },		
	{ "count(*) filter (where curr_issue = 2)::int as iniodel",		FIELD_INIODEL,		"iniodel",		"int",		AOPER_COUNT,	false, 		0 },		
	{ "count(*) filter (where curr_issue = 3)::int as inswpdel",		FIELD_INSWPDEL,		"inswpdel",		"int",		AOPER_COUNT,	false, 		0 },		
	{ "count(*) filter (where curr_issue = 4)::int as inrecdel",		FIELD_INRECDEL,		"inrecdel",		"int",		AOPER_COUNT,	false, 		0 },		
	{ "count(*) filter (where curr_issue = 5)::int as inthrdel",		FIELD_INTHRDEL,		"inthrdel",		"int",		AOPER_COUNT,	false, 		0 },		
	{ "count(*) filter (where curr_issue = 6)::int as invcsw",		FIELD_INVCSW,		"invcsw",		"int",		AOPER_COUNT,	false, 		0 },		
	{ "count(*) filter (where curr_issue = 7)::int as inivcsw",		FIELD_INIVCSW,		"inivcsw",		"int",		AOPER_COUNT,	false, 		0 },		
	{ "count(*) filter (where curr_issue = 8)::int as inpgflt",		FIELD_INPGFLT,		"inpgflt",		"int",		AOPER_COUNT,	false, 		0 },		
	{ "count(*) filter (where curr_issue = 9)::int as incpu",		FIELD_INCPU,		"incpu",		"int",		AOPER_COUNT,	false, 		0 },		
	{ "count(*) filter (where curr_issue = 10)::int as instop",		FIELD_INSTOP,		"instop",		"int",		AOPER_COUNT,	false, 		0 },		
	{ "count(*) filter (where curr_issue = 11)::int as inptr",		FIELD_INPTR,		"inptr",		"int",		AOPER_COUNT,	false, 		0 },		
	{ "count(*)::int as inrecs",						FIELD_INRECS,		"inrecs",		"int",		AOPER_COUNT,	false, 		0 },		

};
	
enum : uint32_t
{
	/*FIELD_TIME		= fnv1_consthash("time"),*/
	/*FIELD_PROCID		= fnv1_consthash("procid"),*/
	/*FIELD_NAME		= fnv1_consthash("name"),*/
	/*FIELD_RELSVCID	= fnv1_consthash("relsvcid"),*/
	/*FIELD_CMDLINE		= fnv1_consthash("cmdline"),*/
	FIELD_TAG		= fnv1_consthash("tag"),
	FIELD_UID		= fnv1_consthash("uid"),
	FIELD_GID		= fnv1_consthash("gid"),
	FIELD_HICAP		= fnv1_consthash("hicap"),
	FIELD_CPUTHR		= fnv1_consthash("cputhr"),
	FIELD_MEMLIM		= fnv1_consthash("memlim"),
	FIELD_RTPROC		= fnv1_consthash("rtproc"),
	FIELD_CONPROC		= fnv1_consthash("conproc"),
	/*FIELD_TSTART		= fnv1_consthash("tstart"),*/
	FIELD_P95CPUPCT		= fnv1_consthash("p95cpupct"),
	FIELD_P95CPUDEL		= fnv1_consthash("p95cpudel"),
	FIELD_P95IODEL		= fnv1_consthash("p95iodel"),
	/*FIELD_NPROC		= fnv1_consthash("nproc"),*/
	FIELD_NTHR		= fnv1_consthash("nthr"),
	FIELD_MAXCORE		= fnv1_consthash("maxcore"),
	FIELD_CGCPULIMPCT	= fnv1_consthash("cgcpulimpct"),
	FIELD_CGRSSPCT		= fnv1_consthash("cgrsspct"),
};	

static constexpr JSON_DB_MAPPING json_db_procinfo_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys			jsontype	numtype		dbtype 		dbstrtype	oper		dboper			coldesc
{ "time", 		"time", 		GYSLEN("time"),		FIELD_TIME,		SUBSYS_PROCINFO,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "procid", 		"aggr_task_id", 	GYSLEN("procid"),	FIELD_PROCID,		SUBSYS_PROCINFO,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "name", 		"comm", 		GYSLEN("name"),		FIELD_NAME,		SUBSYS_PROCINFO,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "relsvcid", 		"related_listen_id", 	GYSLEN("relsvcid"),	FIELD_RELSVCID,		SUBSYS_PROCINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "cmdline", 		"cmdline", 		GYSLEN("cmdline"),	FIELD_CMDLINE,		SUBSYS_PROCINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "tag", 		"tag", 			GYSLEN("tag"),		FIELD_TAG,		SUBSYS_PROCINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "uid",		"uid",			GYSLEN("uid"),		FIELD_UID,		SUBSYS_PROCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "gid",		"gid",			GYSLEN("gid"),		FIELD_GID,		SUBSYS_PROCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "hicap",		"high_cap",		GYSLEN("hicap"),	FIELD_HICAP,		SUBSYS_PROCINFO,	JSON_BOOL,	NUM_NAN,	"boolean",	DB_STR_NONE,	nullptr, 	booltojson,		"", },		
{ "cputhr",		"cpu_cg_throttled",	GYSLEN("cputhr"),	FIELD_CPUTHR,		SUBSYS_PROCINFO,	JSON_BOOL,	NUM_NAN,	"boolean",	DB_STR_NONE,	nullptr, 	booltojson,		"", },		
{ "memlim",		"mem_cg_limited",	GYSLEN("memlim"),	FIELD_MEMLIM,		SUBSYS_PROCINFO,	JSON_BOOL,	NUM_NAN,	"boolean",	DB_STR_NONE,	nullptr, 	booltojson,		"", },		
{ "rtproc",		"rt_proc",		GYSLEN("rtproc"),	FIELD_RTPROC,		SUBSYS_PROCINFO,	JSON_BOOL,	NUM_NAN,	"boolean",	DB_STR_NONE,	nullptr, 	booltojson,		"", },		
{ "conproc",		"container_proc",	GYSLEN("conproc"),	FIELD_CONPROC,		SUBSYS_PROCINFO,	JSON_BOOL,	NUM_NAN,	"boolean",	DB_STR_NONE,	nullptr, 	booltojson,		"", },		
{ "tstart", 		"tstart", 		GYSLEN("tstart"),	FIELD_TSTART,		SUBSYS_PROCINFO,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "p95cpupct",		"p95cpupct",		GYSLEN("p95cpupct"),	FIELD_P95CPUPCT,	SUBSYS_PROCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "p95cpudel",		"p95cpudel",		GYSLEN("p95cpudel"),	FIELD_P95CPUDEL,	SUBSYS_PROCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "p95iodel",		"p95iodel",		GYSLEN("p95iodel"),	FIELD_P95IODEL,		SUBSYS_PROCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "nproc",		"nproc",		GYSLEN("nproc"),	FIELD_NPROC,		SUBSYS_PROCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "nthr",		"nthr",			GYSLEN("nthr"),		FIELD_NTHR,		SUBSYS_PROCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "maxcore",		"maxcore",		GYSLEN("maxcore"),	FIELD_MAXCORE,		SUBSYS_PROCINFO,	JSON_NUMBER,	NUM_INT16,	"smallint",	DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "cgcpulimpct",	"cgcpulimpct",		GYSLEN("cgcpulimpct"),	FIELD_CGCPULIMPCT,	SUBSYS_PROCINFO,	JSON_NUMBER,	NUM_INT16,	"smallint",	DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "cgrsspct",		"cgrsspct",		GYSLEN("cgrsspct"),	FIELD_CGRSSPCT,		SUBSYS_PROCINFO,	JSON_NUMBER,	NUM_INT16,	"smallint",	DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "region",		"region", 		GYSLEN("region"),	FIELD_REGION,		SUBSYS_PROCINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,		"", },
{ "zone",		"zone", 		GYSLEN("zone"),		FIELD_ZONE,		SUBSYS_PROCINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,		"", },

// Additional fields not present in DB
};

static constexpr JSON_DB_MAPPING json_db_aggr_procinfo_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys			jsontype	numtype		dbtype 		dbstrtype	oper		dboper			coldesc
{ "time", 		"atime", 		GYSLEN("time"),		FIELD_TIME,		SUBSYS_PROCINFO,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "procid", 		"aggr_task_id", 	GYSLEN("procid"),	FIELD_PROCID,		SUBSYS_PROCINFO,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "name", 		"comm", 		GYSLEN("name"),		FIELD_NAME,		SUBSYS_PROCINFO,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "relsvcid", 		"related_listen_id", 	GYSLEN("relsvcid"),	FIELD_RELSVCID,		SUBSYS_PROCINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "cmdline", 		"cmdline", 		GYSLEN("cmdline"),	FIELD_CMDLINE,		SUBSYS_PROCINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "tag", 		"tag", 			GYSLEN("tag"),		FIELD_TAG,		SUBSYS_PROCINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "uid",		"uid",			GYSLEN("uid"),		FIELD_UID,		SUBSYS_PROCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "gid",		"gid",			GYSLEN("gid"),		FIELD_GID,		SUBSYS_PROCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "hicap",		"high_cap",		GYSLEN("hicap"),	FIELD_HICAP,		SUBSYS_PROCINFO,	JSON_BOOL,	NUM_NAN,	"boolean",	DB_STR_NONE,	nullptr, 	booltojson,		"", },		
{ "cputhr",		"cpu_cg_throttled",	GYSLEN("cputhr"),	FIELD_CPUTHR,		SUBSYS_PROCINFO,	JSON_BOOL,	NUM_NAN,	"boolean",	DB_STR_NONE,	nullptr, 	booltojson,		"", },		
{ "memlim",		"mem_cg_limited",	GYSLEN("memlim"),	FIELD_MEMLIM,		SUBSYS_PROCINFO,	JSON_BOOL,	NUM_NAN,	"boolean",	DB_STR_NONE,	nullptr, 	booltojson,		"", },		
{ "rtproc",		"rt_proc",		GYSLEN("rtproc"),	FIELD_RTPROC,		SUBSYS_PROCINFO,	JSON_BOOL,	NUM_NAN,	"boolean",	DB_STR_NONE,	nullptr, 	booltojson,		"", },		
{ "conproc",		"container_proc",	GYSLEN("conproc"),	FIELD_CONPROC,		SUBSYS_PROCINFO,	JSON_BOOL,	NUM_NAN,	"boolean",	DB_STR_NONE,	nullptr, 	booltojson,		"", },		
{ "tstart", 		"tstart", 		GYSLEN("tstart"),	FIELD_TSTART,		SUBSYS_PROCINFO,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "p95cpupct",		"p95cpupct",		GYSLEN("p95cpupct"),	FIELD_P95CPUPCT,	SUBSYS_PROCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "p95cpudel",		"p95cpudel",		GYSLEN("p95cpudel"),	FIELD_P95CPUDEL,	SUBSYS_PROCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "p95iodel",		"p95iodel",		GYSLEN("p95iodel"),	FIELD_P95IODEL,		SUBSYS_PROCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "nproc",		"nproc",		GYSLEN("nproc"),	FIELD_NPROC,		SUBSYS_PROCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "nthr",		"nthr",			GYSLEN("nthr"),		FIELD_NTHR,		SUBSYS_PROCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "maxcore",		"maxcore",		GYSLEN("maxcore"),	FIELD_MAXCORE,		SUBSYS_PROCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "cgcpulimpct",	"cgcpulimpct",		GYSLEN("cgcpulimpct"),	FIELD_CGCPULIMPCT,	SUBSYS_PROCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "cgrsspct",		"cgrsspct",		GYSLEN("cgrsspct"),	FIELD_CGRSSPCT,		SUBSYS_PROCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "region",		"region", 		GYSLEN("region"),	FIELD_REGION,		SUBSYS_PROCINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,		"", },
{ "zone",		"zone", 		GYSLEN("zone"),		FIELD_ZONE,		SUBSYS_PROCINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,		"", },
{ "inrecs",		"inrecs",		GYSLEN("inrecs"),	FIELD_INRECS,		SUBSYS_PROCINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		

// Additional fields not present in DB
};


static constexpr DB_AGGR_INFO procinfo_aggr_info[] = 
{
	// dbexpr								// jsoncrc		// dbfieldname		// dbfieldtype	// dflt_aggr	// ignore_sum	// extarg	
	{ "",									FIELD_TIME,		"atime",		"timestamptz",	AOPER_GROUPBY,	false, 		0 },		
	{ "aggr_task_id",							FIELD_PROCID,		"aggr_task_id",		"char(16)",	AOPER_GROUPBY,	false, 		0 },		
	{ "comm",								FIELD_NAME,		"comm",			"char(16)",	AOPER_GROUPBY,	false, 		0 },		
	{ "related_listen_id",							FIELD_RELSVCID,		"related_listen_id",	"text",		AOPER_GROUPBY,	false, 		0 },		
	{ "cmdline",								FIELD_CMDLINE,		"cmdline",		"text",		AOPER_GROUPBY,	false, 		0 },		
	{ "tag",								FIELD_TAG,		"tag",			"text",		AOPER_GROUPBY,	false, 		0 },		
	{ "uid",								FIELD_UID,		"uid",			"int",		AOPER_GROUPBY,	false, 		0 },		
	{ "gid",								FIELD_GID,		"gid",			"int",		AOPER_GROUPBY,	false, 		0 },		
	{ "bool_or(high_cap) as high_cap",					FIELD_HICAP,		"high_cap",		"boolean",	AOPER_BOOL_OR,	false, 		0 },		
	{ "bool_or(cpu_cg_throttled) as cpu_cg_throttled",			FIELD_CPUTHR,		"cpu_cg_throttled",	"boolean",	AOPER_BOOL_OR,	false, 		0 },		
	{ "bool_or(mem_cg_limited) as mem_cg_limited",				FIELD_MEMLIM,		"mem_cg_limited",	"boolean",	AOPER_BOOL_OR,	false, 		0 },		
	{ "bool_or(rt_proc) as rt_proc",					FIELD_RTPROC,		"rt_proc",		"boolean",	AOPER_BOOL_OR,	false, 		0 },		
	{ "bool_or(container_proc) as container_proc",				FIELD_CONPROC,		"container_proc",	"boolean",	AOPER_BOOL_OR,	false, 		0 },		
	{ "tstart",								FIELD_TSTART,		"tstart",		"timestamptz",	AOPER_GROUPBY,	false, 		0 },		
	{ "%s(p95cpupct)::int as p95cpupct",					FIELD_P95CPUPCT,	"p95cpupct",		"int",		AOPER_AVG,	true, 		0 },		
	{ "%s(p95cpudel)::int as p95cpudel",					FIELD_P95CPUDEL,	"p95cpudel",		"int",		AOPER_AVG,	true, 		0 },		
	{ "%s(p95iodel)::int as p95iodel",					FIELD_P95IODEL,		"p95iodel",		"int",		AOPER_AVG,	true, 		0 },		
	{ "%s(nproc)::int as nproc",						FIELD_NPROC,		"nproc",		"int",		AOPER_AVG,	true, 		0 },		
	{ "%s(nthr)::int as nthr",						FIELD_NTHR,		"nthr",			"int",		AOPER_AVG,	true, 		0 },		
	{ "%s(maxcore)::int as maxcore",					FIELD_MAXCORE,		"maxcore",		"int",		AOPER_AVG,	true, 		0 },		
	{ "%s(cgcpulimpct)::int as cgcpulimpct",				FIELD_CGCPULIMPCT,	"cgcpulimpct",		"int",		AOPER_AVG,	true, 		0 },		
	{ "%s(cgrsspct)::int as cgrsspct",					FIELD_CGRSSPCT,		"cgrsspct",		"int",		AOPER_AVG,	true, 		0 },		
	{ "region",								FIELD_REGION,		"region",		"text",		AOPER_GROUPBY,	false, 		0 },		
	{ "zone",								FIELD_ZONE,		"zone",			"text",		AOPER_GROUPBY,	false, 		0 },		
	{ "count(*)::int as inrecs",						FIELD_INRECS,		"inrecs",		"int",		AOPER_COUNT,	false, 		0 },		

};
	


enum : uint32_t
{
	/*FIELD_TIME		= fnv1_consthash("time"),*/
	/*FIELD_PROCID		= fnv1_consthash("procid"),*/
	FIELD_PID		= fnv1_consthash("pid"),
	FIELD_PPID		= fnv1_consthash("ppid"),
	/*FIELD_RSS		= fnv1_consthash("rss"),*/
	/*FIELD_CPU		= fnv1_consthash("cpu"),*/
	/*FIELD_NAME		= fnv1_consthash("name"),*/
	FIELD_RANK		= fnv1_consthash("rank"),
};	

static constexpr JSON_DB_MAPPING json_db_topcpu_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys		jsontype	numtype		dbtype 		dbstrtype	oper		dboper				coldesc
{ "time", 		"time", 		GYSLEN("time"),		FIELD_TIME,		SUBSYS_TOPCPU,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,			"", },
{ "procid", 		"aggr_task_id", 	GYSLEN("procid"),	FIELD_PROCID,		SUBSYS_TOPCPU,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,			"", },
{ "pid",		"pid",			GYSLEN("pid"),		FIELD_PID,		SUBSYS_TOPCPU,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },		
{ "ppid",		"ppid",			GYSLEN("ppid"),		FIELD_PPID,		SUBSYS_TOPCPU,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },		
{ "rss",		"rss_mb",		GYSLEN("rss"),		FIELD_RSS,		SUBSYS_TOPCPU,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },		
{ "cpu",		"cpupct",		GYSLEN("cpu"),		FIELD_CPU,		SUBSYS_TOPCPU,	JSON_NUMBER,	NUM_DOUBLE,	"real",		DB_STR_NONE,	nullptr, 	nullptr,			"", },		
{ "name", 		"comm", 		GYSLEN("name"),		FIELD_NAME,		SUBSYS_TOPCPU,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,			"", },
{ "rank",		"ranknum",		GYSLEN("rank"),		FIELD_RANK,		SUBSYS_TOPCPU,	JSON_NUMBER,	NUM_INT16,	"smallint",	DB_STR_NONE,	nullptr, 	nullptr,			"", },		

// Additional fields not present in DB
};

enum : uint32_t
{
	/*FIELD_TIME		= fnv1_consthash("time"),*/
	/*FIELD_PROCID		= fnv1_consthash("procid"),*/
	FIELD_PGPID		= fnv1_consthash("pgpid"),
	FIELD_CPID		= fnv1_consthash("cpid"),
	/*FIELD_NPROCS		= fnv1_consthash("nprocs"),*/
	FIELD_TRSS		= fnv1_consthash("trss"),
	FIELD_TCPU		= fnv1_consthash("tcpu"),
	FIELD_PGNAME		= fnv1_consthash("pgname"),
	/*FIELD_CNAME		= fnv1_consthash("cname"),*/
	/*FIELD_RANK		= fnv1_consthash("rank"),*/
};	

static constexpr JSON_DB_MAPPING json_db_toppgcpu_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys			jsontype	numtype		dbtype 		dbstrtype	oper		dboper			coldesc
{ "time", 		"time", 		GYSLEN("time"),		FIELD_TIME,		SUBSYS_TOPPGCPU,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "procid", 		"aggr_task_id", 	GYSLEN("procid"),	FIELD_PROCID,		SUBSYS_TOPPGCPU,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "pgpid",		"pg_pid",		GYSLEN("pgpid"),	FIELD_PGPID,		SUBSYS_TOPPGCPU,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "cpid",		"cpid",			GYSLEN("cpid"),		FIELD_CPID,		SUBSYS_TOPPGCPU,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "nprocs",		"ntasks",		GYSLEN("nprocs"),	FIELD_NPROCS,		SUBSYS_TOPPGCPU,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "trss",		"tot_rss_mb",		GYSLEN("trss"),		FIELD_TRSS,		SUBSYS_TOPPGCPU,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "tcpu",		"tot_cpupct",		GYSLEN("tcpu"),		FIELD_TCPU,		SUBSYS_TOPPGCPU,	JSON_NUMBER,	NUM_DOUBLE,	"real",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "pgname", 		"pg_comm", 		GYSLEN("pgname"),	FIELD_PGNAME,		SUBSYS_TOPPGCPU,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "cname", 		"child_comm", 		GYSLEN("cname"),	FIELD_CNAME,		SUBSYS_TOPPGCPU,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "rank",		"ranknum",		GYSLEN("rank"),		FIELD_RANK,		SUBSYS_TOPPGCPU,	JSON_NUMBER,	NUM_INT16,	"smallint",	DB_STR_NONE,	nullptr, 	nullptr,		"", },		

// Additional fields not present in DB
};

enum : uint32_t
{
	/*FIELD_TIME		= fnv1_consthash("time"),*/
	/*FIELD_PROCID		= fnv1_consthash("procid"),*/
	/*FIELD_PID		= fnv1_consthash("pid"),*/
	/*FIELD_PPID		= fnv1_consthash("ppid"),*/
	/*FIELD_RSS		= fnv1_consthash("rss"),*/
	/*FIELD_CPU		= fnv1_consthash("cpu"),*/
	/*FIELD_NAME		= fnv1_consthash("name"),*/
	/*FIELD_RANK		= fnv1_consthash("rank"),*/
};	

static constexpr JSON_DB_MAPPING json_db_toprss_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys		jsontype	numtype		dbtype 		dbstrtype	oper		dboper				coldesc
{ "time", 		"time", 		GYSLEN("time"),		FIELD_TIME,		SUBSYS_TOPRSS,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,			"", },
{ "procid", 		"aggr_task_id", 	GYSLEN("procid"),	FIELD_PROCID,		SUBSYS_TOPRSS,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,			"", },
{ "pid",		"pid",			GYSLEN("pid"),		FIELD_PID,		SUBSYS_TOPRSS,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },		
{ "ppid",		"ppid",			GYSLEN("ppid"),		FIELD_PPID,		SUBSYS_TOPRSS,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },		
{ "rss",		"rss_mb",		GYSLEN("rss"),		FIELD_RSS,		SUBSYS_TOPRSS,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,			"", },		
{ "cpu",		"cpupct",		GYSLEN("cpu"),		FIELD_CPU,		SUBSYS_TOPRSS,	JSON_NUMBER,	NUM_DOUBLE,	"real",		DB_STR_NONE,	nullptr, 	nullptr,			"", },		
{ "name", 		"comm", 		GYSLEN("name"),		FIELD_NAME,		SUBSYS_TOPRSS,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,			"", },
{ "rank",		"ranknum",		GYSLEN("rank"),		FIELD_RANK,		SUBSYS_TOPRSS,	JSON_NUMBER,	NUM_INT16,	"smallint",	DB_STR_NONE,	nullptr, 	nullptr,			"", },		

// Additional fields not present in DB
};

enum : uint32_t
{
	/*FIELD_TIME		= fnv1_consthash("time"),*/
	/*FIELD_PROCID		= fnv1_consthash("procid"),*/
	/*FIELD_PID		= fnv1_consthash("pid"),*/
	/*FIELD_PPID		= fnv1_consthash("ppid"),*/
	FIELD_FORKSEC		= fnv1_consthash("forksec"),
	/*FIELD_NAME		= fnv1_consthash("name"),*/
	/*FIELD_RANK		= fnv1_consthash("rank"),*/
};	

static constexpr JSON_DB_MAPPING json_db_topfork_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys			jsontype	numtype		dbtype 		dbstrtype	oper		dboper			coldesc
{ "time", 		"time", 		GYSLEN("time"),		FIELD_TIME,		SUBSYS_TOPFORK,		JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "procid", 		"aggr_task_id", 	GYSLEN("procid"),	FIELD_PROCID,		SUBSYS_TOPFORK,		JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "pid",		"pid",			GYSLEN("pid"),		FIELD_PID,		SUBSYS_TOPFORK,		JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "ppid",		"ppid",			GYSLEN("ppid"),		FIELD_PPID,		SUBSYS_TOPFORK,		JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "forksec",		"nfork_per_sec",	GYSLEN("forksec"),	FIELD_FORKSEC,		SUBSYS_TOPFORK,		JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "name", 		"comm", 		GYSLEN("name"),		FIELD_NAME,		SUBSYS_TOPFORK,		JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "rank",		"ranknum",		GYSLEN("rank"),		FIELD_RANK,		SUBSYS_TOPFORK,		JSON_NUMBER,	NUM_INT16,	"smallint",	DB_STR_NONE,	nullptr, 	nullptr,		"", },		

// Additional fields not present in DB
};

enum : uint32_t
{
	/*FIELD_HOST		= fnv1_consthash("host"),*/
	/*FIELD_MADID		= fnv1_consthash("madid"),*/
	/*FIELD_CLUSTER		= fnv1_consthash("cluster"),*/
	/*FIELD_REGION		= fnv1_consthash("region"),*/
	/*FIELD_ZONE		= fnv1_consthash("zone"),*/
	/*FIELD_PARID		= fnv1_consthash("parid"),*/
	FIELD_DIST		= fnv1_consthash("dist"),
	FIELD_KERNVERSTR	= fnv1_consthash("kernverstr"),
	FIELD_KERNVERNUM	= fnv1_consthash("kernvernum"),
	FIELD_CPUTYPE		= fnv1_consthash("cputype"),
	FIELD_CPUVEND		= fnv1_consthash("cpuvend"),
	FIELD_CORESON		= fnv1_consthash("coreson"),
	FIELD_CORESOFF		= fnv1_consthash("coresoff"),
	/*FIELD_MAXCORE		= fnv1_consthash("maxcore"),*/
	FIELD_ISOCORE		= fnv1_consthash("isocore"),
	FIELD_RAMMB		= fnv1_consthash("rammb"),
	FIELD_CORRAM		= fnv1_consthash("corram"),
	FIELD_NNUMA		= fnv1_consthash("nnuma"),
	FIELD_SOCKCORE		= fnv1_consthash("sockcore"),
	FIELD_THRCORE		= fnv1_consthash("thrcore"),
	FIELD_L1KB		= fnv1_consthash("l1kb"),
	FIELD_L2KB		= fnv1_consthash("l2kb"),
	FIELD_L3KB		= fnv1_consthash("l3kb"),
	FIELD_L4KB		= fnv1_consthash("l4kb"),
	FIELD_BOOT		= fnv1_consthash("boot"),
	FIELD_VIRT		= fnv1_consthash("virt"),
	FIELD_VIRTTYPE		= fnv1_consthash("virttype"),
	FIELD_INSTANCEID	= fnv1_consthash("instanceid"),
	FIELD_CLOUDTYPE		= fnv1_consthash("cloudtype"),
};	

static constexpr JSON_DB_MAPPING json_db_hostinfo_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys			jsontype	numtype		dbtype 		dbstrtype	oper		dboper			coldesc
{ "host",		"hostname",	 	GYSLEN("host"),		FIELD_HOST,		SUBSYS_HOSTINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,		"", },
{ "madid",		"madhavaid", 		GYSLEN("madid"),	FIELD_MADID,		SUBSYS_HOSTINFO,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr,	nullptr,		"", },
{ "cluster",		"clustername", 		GYSLEN("cluster"),	FIELD_CLUSTER,		SUBSYS_HOSTINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,		"", },
{ "region",		"region", 		GYSLEN("region"),	FIELD_REGION,		SUBSYS_HOSTINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,		"", },
{ "zone",		"zone", 		GYSLEN("zone"),		FIELD_ZONE,		SUBSYS_HOSTINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,		"", },
{ "parid", 		"machid", 		GYSLEN("parid"),	FIELD_PARID,		SUBSYS_HOSTINFO,	JSON_STRING,	NUM_NAN,	"char(32)",	DB_STR_OCHAR,	nullptr,	nullptr,		"", },
{ "dist",		"distribution_name", 	GYSLEN("dist"),		FIELD_DIST,		SUBSYS_HOSTINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,		"", },
{ "kernverstr",		"kern_version_string", 	GYSLEN("kernverstr"),	FIELD_KERNVERSTR,	SUBSYS_HOSTINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,		"", },
{ "kernvernum",		"kern_version_num", 	GYSLEN("kernvernum"),	FIELD_KERNVERNUM,	SUBSYS_HOSTINFO,	JSON_NUMBER,	NUM_INT64,	"bigint",	DB_STR_NONE,	nullptr,	nullptr,		"", },
{ "cputype",		"processor_model", 	GYSLEN("cputype"),	FIELD_CPUTYPE,		SUBSYS_HOSTINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,		"", },
{ "cpuvend",		"cpu_vendor", 		GYSLEN("cpuvend"),	FIELD_CPUVEND,		SUBSYS_HOSTINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,		"", },
{ "coreson",		"cores_online", 	GYSLEN("coreson"),	FIELD_CORESON,		SUBSYS_HOSTINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr,	nullptr,		"", },
{ "coresoff",		"cores_offline", 	GYSLEN("coresoff"),	FIELD_CORESOFF,		SUBSYS_HOSTINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr,	nullptr,		"", },
{ "maxcore",		"max_cores", 		GYSLEN("maxcore"),	FIELD_MAXCORE,		SUBSYS_HOSTINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr,	nullptr,		"", },
{ "isocore",		"isolated_cores", 	GYSLEN("isocore"),	FIELD_ISOCORE,		SUBSYS_HOSTINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr,	nullptr,		"", },
{ "rammb",		"ram_mb", 		GYSLEN("rammb"),	FIELD_RAMMB,		SUBSYS_HOSTINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr,	nullptr,		"", },
{ "corram",		"corrupted_ram_mb", 	GYSLEN("corram"),	FIELD_CORRAM,		SUBSYS_HOSTINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr,	nullptr,		"", },
{ "nnuma",		"num_numa_nodes", 	GYSLEN("nnuma"),	FIELD_NNUMA,		SUBSYS_HOSTINFO,	JSON_NUMBER,	NUM_INT16,	"smallint",	DB_STR_NONE,	nullptr,	nullptr,		"", },
{ "sockcore",		"max_cores_per_socket", GYSLEN("sockcore"),	FIELD_SOCKCORE,		SUBSYS_HOSTINFO,	JSON_NUMBER,	NUM_INT16,	"smallint",	DB_STR_NONE,	nullptr,	nullptr,		"", },
{ "thrcore",		"threads_per_core", 	GYSLEN("thrcore"),	FIELD_THRCORE,		SUBSYS_HOSTINFO,	JSON_NUMBER,	NUM_INT16,	"smallint",	DB_STR_NONE,	nullptr,	nullptr,		"", },
{ "l1kb",		"l1_dcache_kb", 	GYSLEN("l1kb"),		FIELD_L1KB,		SUBSYS_HOSTINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr,	nullptr,		"", },
{ "l2kb",		"l2_cache_kb", 		GYSLEN("l2kb"),		FIELD_L2KB,		SUBSYS_HOSTINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr,	nullptr,		"", },
{ "l3kb",		"l3_cache_kb", 		GYSLEN("l3kb"),		FIELD_L3KB,		SUBSYS_HOSTINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr,	nullptr,		"", },
{ "l4kb",		"l4_cache_kb", 		GYSLEN("l4kb"),		FIELD_L4KB,		SUBSYS_HOSTINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr,	nullptr,		"", },
{ "boot", 		"boot_time", 		GYSLEN("boot"),		FIELD_BOOT,		SUBSYS_HOSTINFO,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "", 			"updtime", 		GYSLEN(""),		FIELD_NULL_JSON,	SUBSYS_HOSTINFO,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "virt",		"is_virtual_cpu",	GYSLEN("virt"),		FIELD_VIRT,		SUBSYS_HOSTINFO,	JSON_BOOL,	NUM_NAN,	"boolean",	DB_STR_NONE,	nullptr, 	booltojson,		"", },		
{ "virttype", 		"virtualization_type",	GYSLEN("virttype"),	FIELD_VIRTTYPE,		SUBSYS_HOSTINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "instanceid", 	"instance_id",		GYSLEN("instanceid"),	FIELD_INSTANCEID,	SUBSYS_HOSTINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "cloudtype", 		"cloud_type",		GYSLEN("cloudtype"),	FIELD_CLOUDTYPE,	SUBSYS_HOSTINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,		"", },

// Additional fields not present in DB
};

static constexpr JSON_DB_MAPPING json_db_aggr_hostinfo_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys			jsontype	numtype		dbtype 		dbstrtype	oper		dboper			coldesc
{ "host",		"hostname",	 	GYSLEN("host"),		FIELD_HOST,		SUBSYS_HOSTINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,		"", },
{ "madid",		"madhavaid", 		GYSLEN("madid"),	FIELD_MADID,		SUBSYS_HOSTINFO,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr,	nullptr,		"", },
{ "cluster",		"clustername", 		GYSLEN("cluster"),	FIELD_CLUSTER,		SUBSYS_HOSTINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,		"", },
{ "region",		"region", 		GYSLEN("region"),	FIELD_REGION,		SUBSYS_HOSTINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,		"", },
{ "zone",		"zone", 		GYSLEN("zone"),		FIELD_ZONE,		SUBSYS_HOSTINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,		"", },
{ "parid", 		"machid", 		GYSLEN("parid"),	FIELD_PARID,		SUBSYS_HOSTINFO,	JSON_STRING,	NUM_NAN,	"char(32)",	DB_STR_OCHAR,	nullptr,	nullptr,		"", },
{ "dist",		"distribution_name", 	GYSLEN("dist"),		FIELD_DIST,		SUBSYS_HOSTINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,		"", },
{ "kernverstr",		"kern_version_string", 	GYSLEN("kernverstr"),	FIELD_KERNVERSTR,	SUBSYS_HOSTINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,		"", },
{ "kernvernum",		"kern_version_num", 	GYSLEN("kernvernum"),	FIELD_KERNVERNUM,	SUBSYS_HOSTINFO,	JSON_NUMBER,	NUM_INT64,	"bigint",	DB_STR_NONE,	nullptr,	nullptr,		"", },
{ "cputype",		"processor_model", 	GYSLEN("cputype"),	FIELD_CPUTYPE,		SUBSYS_HOSTINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,		"", },
{ "cpuvend",		"cpu_vendor", 		GYSLEN("cpuvend"),	FIELD_CPUVEND,		SUBSYS_HOSTINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,		"", },
{ "coreson",		"cores_online", 	GYSLEN("coreson"),	FIELD_CORESON,		SUBSYS_HOSTINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr,	nullptr,		"", },
{ "coresoff",		"cores_offline", 	GYSLEN("coresoff"),	FIELD_CORESOFF,		SUBSYS_HOSTINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr,	nullptr,		"", },
{ "maxcore",		"max_cores", 		GYSLEN("maxcore"),	FIELD_MAXCORE,		SUBSYS_HOSTINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr,	nullptr,		"", },
{ "isocore",		"isolated_cores", 	GYSLEN("isocore"),	FIELD_ISOCORE,		SUBSYS_HOSTINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr,	nullptr,		"", },
{ "rammb",		"ram_mb", 		GYSLEN("rammb"),	FIELD_RAMMB,		SUBSYS_HOSTINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr,	nullptr,		"", },
{ "nnuma",		"num_numa_nodes", 	GYSLEN("nnuma"),	FIELD_NNUMA,		SUBSYS_HOSTINFO,	JSON_NUMBER,	NUM_INT16,	"smallint",	DB_STR_NONE,	nullptr,	nullptr,		"", },
{ "thrcore",		"threads_per_core", 	GYSLEN("thrcore"),	FIELD_THRCORE,		SUBSYS_HOSTINFO,	JSON_NUMBER,	NUM_INT16,	"smallint",	DB_STR_NONE,	nullptr,	nullptr,		"", },
{ "boot", 		"boot_time", 		GYSLEN("boot"),		FIELD_BOOT,		SUBSYS_HOSTINFO,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "virt",		"is_virtual_cpu",	GYSLEN("virt"),		FIELD_VIRT,		SUBSYS_HOSTINFO,	JSON_BOOL,	NUM_NAN,	"boolean",	DB_STR_NONE,	nullptr, 	booltojson,		"", },		
{ "virttype", 		"virtualization_type",	GYSLEN("virttype"),	FIELD_VIRTTYPE,		SUBSYS_HOSTINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "instanceid", 	"instance_id",		GYSLEN("instanceid"),	FIELD_INSTANCEID,	SUBSYS_HOSTINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "cloudtype", 		"cloud_type",		GYSLEN("cloudtype"),	FIELD_CLOUDTYPE,	SUBSYS_HOSTINFO,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "inrecs",		"inrecs",		GYSLEN("inrecs"),	FIELD_INRECS,		SUBSYS_HOSTINFO,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		

};

static constexpr DB_AGGR_INFO hostinfo_aggr_info[] = 
{
	// dbexpr								// jsoncrc		// dbfieldname		// dbfieldtype	// dflt_aggr	// ignore_sum	// extarg	
	{ "hostname",								FIELD_HOST,		"hostname",		"text",		AOPER_GROUPBY,	false, 		0 },		
	{ "madhavaid",								FIELD_MADID,		"madhavaid",		"char(16)",	AOPER_GROUPBY,	false, 		0 },		
	{ "clustername",							FIELD_CLUSTER,		"clustername",		"text",		AOPER_GROUPBY,	false, 		0 },		
	{ "region",								FIELD_REGION,		"region",		"text",		AOPER_GROUPBY,	false, 		0 },		
	{ "zone",								FIELD_ZONE,		"zone",			"text",		AOPER_GROUPBY,	false, 		0 },		
	{ "machid",								FIELD_PARID,		"machid",		"char(32)",	AOPER_GROUPBY,	false, 		0 },		
	{ "distribution_name",							FIELD_DIST,		"distribution_name",	"text",		AOPER_GROUPBY,	false, 		0 },		
	{ "kern_version_string",						FIELD_KERNVERSTR,	"kern_version_string",	"text",		AOPER_GROUPBY,	false, 		0 },		
	{ "kern_version_num",							FIELD_KERNVERNUM,	"kern_version_num",	"bigint",	AOPER_GROUPBY,	false, 		0 },		
	{ "processor_model",							FIELD_CPUTYPE,		"processor_model",	"text",		AOPER_GROUPBY,	false, 		0 },		
	{ "cpu_vendor",								FIELD_CPUVEND,		"cpu_vendor",		"text",		AOPER_GROUPBY,	false, 		0 },		
	{ "%s(cores_online)::int as cores_online",				FIELD_CORESON,		"cores_online",		"int",		AOPER_SUM,	false, 		0 },		
	{ "%s(cores_offline)::int as cores_offline",				FIELD_CORESOFF,		"cores_offline",	"int",		AOPER_SUM,	false, 		0 },		
	{ "%s(max_cores)::int as max_cores",					FIELD_MAXCORE,		"max_cores",		"int",		AOPER_SUM,	false, 		0 },		
	{ "%s(isolated_cores)::int as isolated_cores",				FIELD_ISOCORE,		"isolated_cores",	"int",		AOPER_SUM,	false, 		0 },		
	{ "%s(ram_mb)::int as ram_mb",						FIELD_RAMMB,		"ram_mb",		"int",		AOPER_SUM,	false, 		0 },		
	{ "%s(num_numa_nodes)::int as num_numa_nodes",				FIELD_NNUMA,		"num_numa_nodes",	"int",		AOPER_SUM,	false, 		0 },		
	{ "%s(threads_per_core)::int as threads_per_core",			FIELD_THRCORE,		"threads_per_core",	"int",		AOPER_SUM,	false, 		0 },		
	{ "boot_time",								FIELD_BOOT,		"boot_time",		"timestamptz",	AOPER_GROUPBY,	false, 		0 },		
	{ "bool_or(is_virtual_cpu) as is_virtual_cpu",				FIELD_VIRT,		"is_virtual_cpu",	"boolean",	AOPER_BOOL_OR,	false, 		0 },		
	{ "virtualization_type",						FIELD_VIRTTYPE,		"virtualization_type",	"text",		AOPER_GROUPBY,	false, 		0 },		
	{ "instance_id",							FIELD_INSTANCEID,	"instance_id",		"text",		AOPER_GROUPBY,	false, 		0 },		
	{ "cloud_type",								FIELD_CLOUDTYPE,	"cloud_type",		"text",		AOPER_GROUPBY,	false, 		0 },		
	{ "count(*)::int as inrecs",						FIELD_INRECS,		"inrecs",		"int",		AOPER_COUNT,	false, 		0 },		

};
	


enum : uint32_t
{
	/*FIELD_TIME		= fnv1_consthash("time"),*/
	/*FIELD_CLUSTER		= fnv1_consthash("cluster"),*/
	FIELD_NHOSTS		= fnv1_consthash("nhosts"),
	/*FIELD_NPROCISSUE	= fnv1_consthash("nprocissue"),*/
	FIELD_NPROCHOSTS	= fnv1_consthash("nprochosts"),
	/*FIELD_NPROC		= fnv1_consthash("nproc"),*/
	/*FIELD_NLISTISSUE	= fnv1_consthash("nlistissue"),*/
	FIELD_NLISTHOSTS	= fnv1_consthash("nlisthosts"),
	/*FIELD_NLISTEN		= fnv1_consthash("nlisten"),*/
	/*FIELD_TOTQPS		= fnv1_consthash("totqps"),*/
	FIELD_SVCNETMB		= fnv1_consthash("svcnetmb"),
	FIELD_NCPUISSUE		= fnv1_consthash("ncpuissue"),
	FIELD_NMEMISSUE		= fnv1_consthash("nmemissue"),
};

static constexpr JSON_DB_MAPPING json_db_clusterstate_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys			jsontype	numtype		dbtype 		dbstrtype	oper		dboper			coldesc
{ "time", 		"time", 		GYSLEN("time"),		FIELD_TIME,		SUBSYS_CLUSTERSTATE,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "cluster",		"clustername", 		GYSLEN("cluster"),	FIELD_CLUSTER,		SUBSYS_CLUSTERSTATE,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,		"", },
{ "nhosts",		"nhosts", 		GYSLEN("nhosts"),	FIELD_NHOSTS,		SUBSYS_CLUSTERSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "nprocissue",		"ntasks_issue", 	GYSLEN("nprocissue"),	FIELD_NPROCISSUE,	SUBSYS_CLUSTERSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "nprochosts",		"ntaskissue_hosts", 	GYSLEN("nprochosts"),	FIELD_NPROCHOSTS,	SUBSYS_CLUSTERSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "nproc",		"ntasks", 		GYSLEN("nproc"),	FIELD_NPROC,		SUBSYS_CLUSTERSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "nlistissue",		"nsvc_issue",		GYSLEN("nlistissue"),	FIELD_NLISTISSUE,	SUBSYS_CLUSTERSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "nlisthosts",		"nsvcissue_hosts",	GYSLEN("nlisthosts"),	FIELD_NLISTHOSTS,	SUBSYS_CLUSTERSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "nlisten",		"nsvc",			GYSLEN("nlisten"),	FIELD_NLISTEN,		SUBSYS_CLUSTERSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "totqps",		"total_qps",		GYSLEN("totqps"),	FIELD_TOTQPS,		SUBSYS_CLUSTERSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "svcnetmb",		"svc_net_mb",		GYSLEN("svcnetmb"),	FIELD_SVCNETMB,		SUBSYS_CLUSTERSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "ncpuissue",		"ncpu_issue",		GYSLEN("ncpuissue"),	FIELD_NCPUISSUE,	SUBSYS_CLUSTERSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "nmemissue",		"nmem_issue",		GYSLEN("nmemissue"),	FIELD_NMEMISSUE,	SUBSYS_CLUSTERSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		

// Additional fields not present in DB
};	

// Agregated Clusterstate query cols
static constexpr JSON_DB_MAPPING json_db_aggr_clusterstate_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys			jsontype	numtype		dbtype 		dbstrtype	oper		dboper			coldesc
{ "time", 		"atime", 		GYSLEN("time"),		FIELD_TIME,		SUBSYS_CLUSTERSTATE,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "cluster",		"clustername", 		GYSLEN("cluster"),	FIELD_CLUSTER,		SUBSYS_CLUSTERSTATE,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,		"", },
{ "nhosts",		"nhosts", 		GYSLEN("nhosts"),	FIELD_NHOSTS,		SUBSYS_CLUSTERSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "nprocissue",		"ntasks_issue", 	GYSLEN("nprocissue"),	FIELD_NPROCISSUE,	SUBSYS_CLUSTERSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "nprochosts",		"ntaskissue_hosts", 	GYSLEN("nprochosts"),	FIELD_NPROCHOSTS,	SUBSYS_CLUSTERSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "nproc",		"ntasks", 		GYSLEN("nproc"),	FIELD_NPROC,		SUBSYS_CLUSTERSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "nlistissue",		"nsvc_issue",		GYSLEN("nlistissue"),	FIELD_NLISTISSUE,	SUBSYS_CLUSTERSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "nlisthosts",		"nsvcissue_hosts",	GYSLEN("nlisthosts"),	FIELD_NLISTHOSTS,	SUBSYS_CLUSTERSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "nlisten",		"nsvc",			GYSLEN("nlisten"),	FIELD_NLISTEN,		SUBSYS_CLUSTERSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "totqps",		"total_qps",		GYSLEN("totqps"),	FIELD_TOTQPS,		SUBSYS_CLUSTERSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "svcnetmb",		"svc_net_mb",		GYSLEN("svcnetmb"),	FIELD_SVCNETMB,		SUBSYS_CLUSTERSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "ncpuissue",		"ncpu_issue",		GYSLEN("ncpuissue"),	FIELD_NCPUISSUE,	SUBSYS_CLUSTERSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "nmemissue",		"nmem_issue",		GYSLEN("nmemissue"),	FIELD_NMEMISSUE,	SUBSYS_CLUSTERSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
{ "inrecs",		"inrecs",		GYSLEN("inrecs"),	FIELD_INRECS,		SUBSYS_CLUSTERSTATE,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },		
};	

static constexpr DB_AGGR_INFO clusterstate_aggr_info[] = 
{
	// dbexpr								// jsoncrc		// dbfieldname		// dbfieldtype	// dflt_aggr	// ignore_sum	// extarg	
	{ "",									FIELD_TIME,		"atime",		"timestamptz",	AOPER_GROUPBY,	false, 		0 },		
	{ "clustername",							FIELD_CLUSTER,		"clustername",		"text",		AOPER_GROUPBY,	false, 		0 },		
	{ "%s(nhosts)::int as nhosts",						FIELD_NHOSTS,		"nhosts",		"int",		AOPER_AVG,	false, 		0 },		
	{ "%s(ntasks_issue)::int as ntasks_issue",				FIELD_NPROCISSUE,	"ntasks_issue",		"int",		AOPER_AVG,	false, 		0 },		
	{ "%s(ntaskissue_hosts)::int as ntaskissue_hosts",			FIELD_NPROCHOSTS,	"ntaskissue_hosts",	"int",		AOPER_AVG,	false, 		0 },		
	{ "%s(ntasks)::int as ntasks",						FIELD_NPROC,		"ntasks",		"int",		AOPER_AVG,	false, 		0 },		
	{ "%s(nsvc_issue)::int as nsvc_issue",					FIELD_NLISTISSUE,	"nsvc_issue",		"int",		AOPER_AVG,	false, 		0 },		
	{ "%s(nsvcissue_hosts)::int as nsvcissue_hosts",			FIELD_NLISTHOSTS,	"nsvcissue_hosts",	"int",		AOPER_AVG,	false, 		0 },		
	{ "%s(nsvc)::int as nsvc",						FIELD_NLISTEN,		"nsvc",			"int",		AOPER_AVG,	false, 		0 },		
	{ "%s(total_qps)::int as total_qps",					FIELD_TOTQPS,		"total_qps",		"int",		AOPER_AVG,	false, 		0 },		
	{ "%s(svc_net_mb)::int as svc_net_mb",					FIELD_SVCNETMB,		"svc_net_mb",		"int",		AOPER_AVG,	false, 		0 },		
	{ "%s(ncpu_issue)::int as ncpu_issue",					FIELD_NCPUISSUE,	"ncpu_issue",		"int",		AOPER_AVG,	false, 		0 },		
	{ "%s(nmem_issue)::int as nmem_issue",					FIELD_NMEMISSUE,	"nmem_issue",		"int",		AOPER_AVG,	false, 		0 },		
	{ "count(*)::int as inrecs",						FIELD_INRECS,		"inrecs",		"int",		AOPER_COUNT,	false, 		0 },		

};

enum : uint32_t
{
	/*FIELD_TIME		= fnv1_consthash("time"),*/
	FIELD_CLUSTID		= fnv1_consthash("clustid"),
	/*FIELD_NAME		= fnv1_consthash("name"),*/
	/*FIELD_CLUSTER		= fnv1_consthash("cluster"),*/
	/*FIELD_NSVC		= fnv1_consthash("nsvc"),*/
	FIELD_RELIDARR		= fnv1_consthash("relidarr"),
};

static constexpr JSON_DB_MAPPING json_db_svcmeshclust_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys			jsontype	numtype		dbtype 		dbstrtype	oper		dboper			coldesc
{ "time", 		"time", 		GYSLEN("time"),		FIELD_TIME,		SUBSYS_SVCMESHCLUST,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "clustid", 		"svcclustid", 		GYSLEN("clustid"),	FIELD_CLUSTID,		SUBSYS_SVCMESHCLUST,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "name", 		"comm", 		GYSLEN("name"),		FIELD_NAME,		SUBSYS_SVCMESHCLUST,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "cluster",		"clustername", 		GYSLEN("cluster"),	FIELD_CLUSTER,		SUBSYS_SVCMESHCLUST,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,		"", },
{ "nsvc",		"ntotal_svc", 		GYSLEN("nsvc"),		FIELD_NSVC,		SUBSYS_SVCMESHCLUST,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "relidarr",		"relidobjs", 		GYSLEN("relidarr"),	FIELD_RELIDARR,		SUBSYS_SVCMESHCLUST,	JSON_STRING,	NUM_NAN,	"text",		DB_RAW_STRING,	nullptr,	nullptr,		"", },

// Additional fields not present in DB
};	

enum : uint32_t
{
	/*FIELD_TIME		= fnv1_consthash("time"),*/
	/*FIELD_CLUSTID		= fnv1_consthash("clustid"),*/
	/*FIELD_NAME		= fnv1_consthash("name"),*/
	/*FIELD_CLUSTER		= fnv1_consthash("cluster"),*/
	FIELD_SVCIP		= fnv1_consthash("svcip"),
	FIELD_SVCPORT		= fnv1_consthash("svcport"),
	/*FIELD_NSVC		= fnv1_consthash("nsvc"),*/
	/*FIELD_SVCIDARR	= fnv1_consthash("svcidarr"),*/
};

static constexpr JSON_DB_MAPPING json_db_svcipclust_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys			jsontype	numtype		dbtype 		dbstrtype	oper		dboper			coldesc
{ "time", 		"time", 		GYSLEN("time"),		FIELD_TIME,		SUBSYS_SVCIPCLUST,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "clustid", 		"svcclustid", 		GYSLEN("clustid"),	FIELD_CLUSTID,		SUBSYS_SVCIPCLUST,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "name", 		"comm", 		GYSLEN("name"),		FIELD_NAME,		SUBSYS_SVCIPCLUST,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "cluster",		"clustername", 		GYSLEN("cluster"),	FIELD_CLUSTER,		SUBSYS_SVCIPCLUST,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,		"", },
{ "svcip", 		"natip",		GYSLEN("svcip"),	FIELD_SVCIP,		SUBSYS_SVCIPCLUST,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "svcport", 		"port", 		GYSLEN("svcport"),	FIELD_SVCPORT,		SUBSYS_SVCIPCLUST,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "nsvc",		"ntotal_svc", 		GYSLEN("nsvc"),		FIELD_NSVC,		SUBSYS_SVCIPCLUST,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "svcidarr",		"svcidobjs", 		GYSLEN("svcidarr"),	FIELD_SVCIDARR,		SUBSYS_SVCIPCLUST,	JSON_STRING,	NUM_NAN,	"text",		DB_RAW_STRING,	nullptr,	nullptr,		"", },

// Additional fields not present in DB
};	

enum : uint32_t
{
	// XXX Do NOT Use any of the Alert Fields for other non-alert subsystems : Need to static_assert() this...

	FIELD_ALERTTIME		= fnv1_consthash("alerttime"),
	FIELD_ALERTID		= fnv1_consthash("alertid"),	
	FIELD_ALERTNAME		= fnv1_consthash("alertname"),
	FIELD_ASTATE		= fnv1_consthash("astate"),
	FIELD_SEVERITY		= fnv1_consthash("severity"),
	FIELD_EXPIRY		= fnv1_consthash("expiry"),
	FIELD_TACTION		= fnv1_consthash("taction"),
	FIELD_TCLOSE		= fnv1_consthash("tclose"),
	FIELD_ADEFID		= fnv1_consthash("adefid"),
	FIELD_ACTIONS		= fnv1_consthash("actions"),
	FIELD_ANNOT		= fnv1_consthash("annot"),
	FIELD_ACKNOTES		= fnv1_consthash("acknotes"),
	FIELD_NREPEATS		= fnv1_consthash("nrepeats"),
	FIELD_SUBSYS		= fnv1_consthash("subsys"),
	FIELD_LABELS		= fnv1_consthash("labels"),
	FIELD_ALERTDATA		= fnv1_consthash("alertdata"),
};

/*
 * NOTE : For alerts subsystem the time field is set as alerttime as we need the time field for the actual alertdata
 */
static constexpr JSON_DB_MAPPING json_db_alerts_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys			jsontype	numtype		dbtype 		dbstrtype	oper		dboper			coldesc
{ "alerttime", 		"time", 		GYSLEN("alerttime"),	FIELD_ALERTTIME,	SUBSYS_ALERTS,		JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,		"Time at which Alert occured", },
{ "alertid", 		"alertid", 		GYSLEN("alertid"),	FIELD_ALERTID,		SUBSYS_ALERTS,		JSON_STRING,	NUM_NAN,	"char(8)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"Alert ID", },
{ "alertname",		"alertname",		GYSLEN("alertname"),	FIELD_ALERTNAME,	SUBSYS_ALERTS,		JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,		"Alert Definition Name", },		
{ "astate",		"astate",		GYSLEN("astate"),	FIELD_ASTATE,		SUBSYS_ALERTS,		JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,		"State of Alert whether Active, Acked, or Resolved/Expired", },		
{ "severity",		"severity",		GYSLEN("severity"),	FIELD_SEVERITY,		SUBSYS_ALERTS,		JSON_STRING,	NUM_NAN,	"char(8)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"Severity as per Alert Definition", },		
{ "expiry", 		"expiry", 		GYSLEN("expiry"),	FIELD_EXPIRY,		SUBSYS_ALERTS,		JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,		"Time at which Alert will expire if not resolved", },
{ "taction", 		"taction", 		GYSLEN("taction"),	FIELD_TACTION,		SUBSYS_ALERTS,		JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,		"Time at which Alert Action was initiated. Can be different from alerttime for Grouped Alerts", },
{ "tclose", 		"tclose", 		GYSLEN("tclose"),	FIELD_TCLOSE,		SUBSYS_ALERTS,		JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,		"Time at which the Alert was marked closed by either resolve or expiry", },
{ "adefid", 		"adefid", 		GYSLEN("adefid"),	FIELD_ADEFID,		SUBSYS_ALERTS,		JSON_STRING,	NUM_NAN,	"char(8)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"Alert Definition ID for this alert", },
{ "actions",		"actions",		GYSLEN("actions"),	FIELD_ACTIONS,		SUBSYS_ALERTS,		JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,		"Action Names triggered for this alert", },		
{ "annot",		"annot", 		GYSLEN("annot"),	FIELD_ANNOT,		SUBSYS_ALERTS,		JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,		"Annotations defined for the Alert Definition", },
{ "acknotes",		"acknotes", 		GYSLEN("acknotes"),	FIELD_ACKNOTES,		SUBSYS_ALERTS,		JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,		"Alert Acknowledgement Notes (for Acknowledged Alerts only)", },
{ "nrepeats",		"nrepeats",		GYSLEN("nrepeats"),	FIELD_NREPEATS,		SUBSYS_ALERTS,		JSON_NUMBER,	NUM_INT16,	"smallint",	DB_STR_NONE,	nullptr, 	nullptr,		"Alert Repeat count", },		
{ "subsys",		"subsys",		GYSLEN("subsys"),	FIELD_SUBSYS,		SUBSYS_ALERTS,		JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,		"Subsystem used in Alert Definition", },		
{ "labels",		"labels",		GYSLEN("labels"),	FIELD_LABELS,		SUBSYS_ALERTS,		JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,		"Labels defined in Alert Definition", },		
{ "alertdata",		"alertdata",		GYSLEN("alertdata"),	FIELD_ALERTDATA,	SUBSYS_ALERTS,		JSON_STRING,	NUM_NAN,	"text",		DB_RAW_STRING,	nullptr, 	nullptr,		"Alert Data Payload as per Subsystem used", },		

// Additional fields not present in DB
};	

enum : uint32_t
{
	FIELD_NTOTALALT		= fnv1_consthash("ntotalalt"),
	FIELD_NOPENALT		= fnv1_consthash("nopenalt"),
	FIELD_NACKALT		= fnv1_consthash("nackalt"),
	FIELD_NRESOLVEDALT	= fnv1_consthash("nresolvedalt"),
	FIELD_NEXPIREDALT	= fnv1_consthash("nexpiredalt"),
	FIELD_TOTALCRIT		= fnv1_consthash("totalcrit"),
	FIELD_OPENCRIT		= fnv1_consthash("opencrit"),
	FIELD_TOTALWARN		= fnv1_consthash("totalwarn"),
	FIELD_OPENWARN		= fnv1_consthash("openwarn"),
	FIELD_MAXTRESOLVE	= fnv1_consthash("maxtresolve"),
	FIELD_MEANTRESOLVE	= fnv1_consthash("meantresolve"),
};	

static constexpr JSON_DB_MAPPING json_db_aggr_alerts_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys			jsontype	numtype		dbtype 		dbstrtype	oper		dboper			coldesc
{ "alerttime", 		"atime", 		GYSLEN("alerttime"),	FIELD_ALERTTIME,	SUBSYS_ALERTS,		JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,		"Aggregation Timestamp", },
{ "ntotalalt",		"ntotalalt",		GYSLEN("ntotalalt"),	FIELD_NTOTALALT,	SUBSYS_ALERTS,		JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"Total Alerts seen for specified time period", },		
{ "nopenalt",		"nopenalt",		GYSLEN("nopenalt"),	FIELD_NOPENALT,		SUBSYS_ALERTS,		JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"# Alerts Open (Active/Ack) for alerts started within time period specified", },		
{ "nackalt",		"nackalt",		GYSLEN("nackalt"),	FIELD_NACKALT,		SUBSYS_ALERTS,		JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"# Alerts Acknowledged for alerts started within time period specified", },		
{ "nresolvedalt",	"nresolvedalt",		GYSLEN("nresolvedalt"),	FIELD_NRESOLVEDALT,	SUBSYS_ALERTS,		JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"# Alerts Resolved for alerts started within time period specified", },		
{ "nexpiredalt",	"nexpiredalt",		GYSLEN("nexpiredalt"),	FIELD_NEXPIREDALT,	SUBSYS_ALERTS,		JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"# Alerts Expired for alerts started within time period specified", },		
{ "totalcrit",		"totalcrit",		GYSLEN("totalcrit"),	FIELD_TOTALCRIT,	SUBSYS_ALERTS,		JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"# Total Alerts with Severity as Critical", },		
{ "opencrit",		"opencrit",		GYSLEN("opencrit"),	FIELD_OPENCRIT,		SUBSYS_ALERTS,		JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"# Open Alerts with Severity as Critical", },		
{ "totalwarn",		"totalwarn",		GYSLEN("totalwarn"),	FIELD_TOTALWARN,	SUBSYS_ALERTS,		JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"# Total Alerts with Severity as Warning", },		
{ "openwarn",		"openwarn",		GYSLEN("openwarn"),	FIELD_OPENWARN,		SUBSYS_ALERTS,		JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"# Open Alerts with Severity as Warning", },		
{ "maxtresolve",	"maxtresolve",		GYSLEN("maxtresolve"),	FIELD_MAXTRESOLVE,	SUBSYS_ALERTS,		JSON_STRING,	NUM_NAN,	"interval",	DB_STR_TEXT,	nullptr, 	nullptr,		"Max Time seen for Resolve of an Alert started with time interval in HH:MM:SS", },		
{ "meantresolve",	"meantresolve",		GYSLEN("meantresolve"),	FIELD_MEANTRESOLVE,	SUBSYS_ALERTS,		JSON_STRING,	NUM_NAN,	"interval",	DB_STR_TEXT,	nullptr, 	nullptr,		"Mean (Avg) Time seen for Resolve of an Alert started with time interval in HH:MM:SS", },		
{ "inrecs",		"inrecs",		GYSLEN("inrecs"),	FIELD_INRECS,		SUBSYS_ALERTS,		JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"Total Detailed Records used for this Aggregation", },		

};

static constexpr DB_AGGR_INFO alerts_aggr_info[] = 
{
	// dbexpr											// jsoncrc		// dbfieldname		// dbfieldtype	// dflt_aggr	// ignore_sum	// extarg
	{ "",												FIELD_ALERTTIME,	"atime",		"timestamptz",	AOPER_GROUPBY,	false, 		0 },
	{ "count(*)::int as ntotalalt",									FIELD_NTOTALALT,	"ntotalalt",		"int",		AOPER_COUNT,	false, 		0 },
	{ "count(*) filter (where tclose is null)::int as nopenalt",					FIELD_NOPENALT,		"nopenalt",		"int",		AOPER_COUNT,	false, 		0 },
	{ "count(*) filter (where astate = 'acked')::int as nackalt",					FIELD_NACKALT,		"nackalt",		"int",		AOPER_COUNT,	false, 		0 },
	{ "count(*) filter (where astate = 'resolved')::int as nresolvedalt",				FIELD_NRESOLVEDALT,	"nresolvedalt",		"int",		AOPER_COUNT,	false, 		0 },
	{ "count(*) filter (where astate = 'expired')::int as nexpiredalt",				FIELD_NEXPIREDALT,	"nexpiredalt",		"int",		AOPER_COUNT,	false, 		0 },
	{ "count(*) filter (where severity = 'critical')::int as totalcrit",				FIELD_TOTALCRIT,	"totalcrit",		"int",		AOPER_COUNT,	false, 		0 },
	{ "count(*) filter (where severity = 'critical' and tclose is null)::int as opencrit",		FIELD_OPENCRIT,		"opencrit",		"int",		AOPER_COUNT,	false, 		0 },
	{ "count(*) filter (where severity = 'warning')::int as totalwarn",				FIELD_TOTALWARN,	"totalwarn",		"int",		AOPER_COUNT,	false, 		0 },
	{ "count(*) filter (where severity = 'warning' and tclose is null)::int as openwarn",		FIELD_OPENWARN,		"openwarn",		"int",		AOPER_COUNT,	false, 		0 },
	{ "max(tclose - time)::interval as maxtresolve",						FIELD_MAXTRESOLVE,	"maxtresolve",		"interval",	AOPER_MAX,	false, 		0 },
	{ "date_trunc('sec', avg(tclose - time)::interval) as meantresolve",				FIELD_MEANTRESOLVE,	"meantresolve",		"interval",	AOPER_AVG,	false, 		0 },
	{ "count(*)::int as inrecs",									FIELD_INRECS,		"inrecs",		"int",		AOPER_COUNT,	false, 		0 },		
};	

enum : uint32_t
{
	/*FIELD_ADEFID		= fnv1_consthash("adefid"),*/
	/*FIELD_ALERTNAME		= fnv1_consthash("alertname"),*/
	FIELD_TCREATED		= fnv1_consthash("tcreated"),
	FIELD_DISABLED		= fnv1_consthash("disabled"),
	FIELD_DEFINITION	= fnv1_consthash("definition"),
};

static constexpr JSON_DB_MAPPING json_db_alertdef_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys			jsontype	numtype		dbtype 		dbstrtype	oper		dboper			coldesc
{ "adefid", 		"adefid", 		GYSLEN("adefid"),	FIELD_ADEFID,		SUBSYS_ALERTDEF,	JSON_STRING,	NUM_NAN,	"char(8)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "alertname",		"alertname",		GYSLEN("alertname"),	FIELD_ALERTNAME,	SUBSYS_ALERTDEF,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,		"Alert Definition Name", },		
{ "tcreated", 		"tcreated", 		GYSLEN("tcreated"),	FIELD_TCREATED,		SUBSYS_ALERTDEF,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "disabled",		"disabled",		GYSLEN("disabled"),	FIELD_DISABLED,		SUBSYS_ALERTDEF,	JSON_BOOL,	NUM_NAN,	"boolean",	DB_STR_NONE,	nullptr, 	booltojson,		"", },		
{ "definition",		"definition",		GYSLEN("definition"),	FIELD_DEFINITION,	SUBSYS_ALERTDEF,	JSON_STRING,	NUM_NAN,	"text",		DB_RAW_STRING,	nullptr, 	nullptr,		"", },		
};

enum : uint32_t
{
	FIELD_INHID		= fnv1_consthash("inhid"),
	FIELD_INHNAME		= fnv1_consthash("inhname"),
	/*FIELD_TCREATED	= fnv1_consthash("tcreated"),*/
	/*FIELD_DISABLED	= fnv1_consthash("disabled"),*/
	FIELD_INHIBIT		= fnv1_consthash("inhibit"),
};

static constexpr JSON_DB_MAPPING json_db_inhibits_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys			jsontype	numtype		dbtype 		dbstrtype	oper		dboper			coldesc
{ "inhid", 		"inhid", 		GYSLEN("inhid"),	FIELD_INHID,		SUBSYS_INHIBITS,	JSON_STRING,	NUM_NAN,	"char(8)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "inhname", 		"inhname", 		GYSLEN("inhname"),	FIELD_INHNAME,		SUBSYS_INHIBITS,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "tcreated", 		"tcreated", 		GYSLEN("tcreated"),	FIELD_TCREATED,		SUBSYS_INHIBITS,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "disabled",		"disabled",		GYSLEN("disabled"),	FIELD_DISABLED,		SUBSYS_INHIBITS,	JSON_BOOL,	NUM_NAN,	"boolean",	DB_STR_NONE,	nullptr, 	booltojson,		"", },		
{ "inhibit",		"inhibit",		GYSLEN("inhibit"),	FIELD_INHIBIT,		SUBSYS_INHIBITS,	JSON_STRING,	NUM_NAN,	"text",		DB_RAW_STRING,	nullptr, 	nullptr,		"", },		
};

enum : uint32_t
{
	FIELD_SILID		= fnv1_consthash("silid"),
	FIELD_SILNAME		= fnv1_consthash("silname"),
	/*FIELD_TCREATED	= fnv1_consthash("tcreated"),*/
	/*FIELD_DISABLED	= fnv1_consthash("disabled"),*/
	FIELD_SILENCE		= fnv1_consthash("silence"),
};

static constexpr JSON_DB_MAPPING json_db_silences_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys			jsontype	numtype		dbtype 		dbstrtype	oper		dboper			coldesc
{ "silid", 		"silid", 		GYSLEN("silid"),	FIELD_SILID,		SUBSYS_SILENCES,	JSON_STRING,	NUM_NAN,	"char(8)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "silname", 		"silname", 		GYSLEN("silname"),	FIELD_SILNAME,		SUBSYS_SILENCES,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "tcreated", 		"tcreated", 		GYSLEN("tcreated"),	FIELD_TCREATED,		SUBSYS_SILENCES,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "disabled",		"disabled",		GYSLEN("disabled"),	FIELD_DISABLED,		SUBSYS_SILENCES,	JSON_BOOL,	NUM_NAN,	"boolean",	DB_STR_NONE,	nullptr, 	booltojson,		"", },		
{ "silence",		"silence",		GYSLEN("silence"),	FIELD_SILENCE,		SUBSYS_SILENCES,	JSON_STRING,	NUM_NAN,	"text",		DB_RAW_STRING,	nullptr, 	nullptr,		"", },		
};

enum : uint32_t
{
	FIELD_ACTIONID		= fnv1_consthash("actionid"),
	FIELD_ACTNAME		= fnv1_consthash("actname"),
	FIELD_ACTTYPE		= fnv1_consthash("acttype"),
	/*FIELD_TCREATED	= fnv1_consthash("tcreated"),*/
	FIELD_ACTION		= fnv1_consthash("action"),
};

static constexpr JSON_DB_MAPPING json_db_actions_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys			jsontype	numtype		dbtype 		dbstrtype	oper		dboper			coldesc
{ "actionid", 		"actionid", 		GYSLEN("actionid"),	FIELD_ACTIONID,		SUBSYS_ACTIONS,		JSON_STRING,	NUM_NAN,	"char(8)",	DB_STR_OCHAR,	nullptr, 	nullptr,		"", },
{ "actname",		"actname",		GYSLEN("actname"),	FIELD_ACTNAME,		SUBSYS_ACTIONS,		JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,		"", },		
{ "acttype",		"acttype",		GYSLEN("acttype"),	FIELD_ACTTYPE,		SUBSYS_ACTIONS,		JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr, 	nullptr,		"", },		
{ "tcreated", 		"tcreated", 		GYSLEN("tcreated"),	FIELD_TCREATED,		SUBSYS_ACTIONS,		JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "action",		"action",		GYSLEN("action"),	FIELD_ACTION,		SUBSYS_ACTIONS,		JSON_STRING,	NUM_NAN,	"text",		DB_RAW_STRING,	nullptr, 	nullptr,		"", },		
};



enum : uint32_t
{
	/*FIELD_MADID		= fnv1_consthash("madid"),*/
	/*FIELD_HOST		= fnv1_consthash("host"),*/
	/*FIELD_PORT		= fnv1_consthash("port"),*/
	FIELD_COMMVER		= fnv1_consthash("commver"),
	FIELD_NPARTHA		= fnv1_consthash("npartha"),
	FIELD_VERSION		= fnv1_consthash("version"),
	FIELD_MAXPARTHA		= fnv1_consthash("maxpartha"),
	/*FIELD_REGION		= fnv1_consthash("region"),*/
	/*FIELD_ZONE		= fnv1_consthash("zone"),*/
	FIELD_MADHAVANAME	= fnv1_consthash("madhavaname"),
	FIELD_ISCONN		= fnv1_consthash("isconn"),
	FIELD_LASTSEEN		= fnv1_consthash("lastseen"),
};	

static constexpr JSON_DB_MAPPING json_db_madhavalist_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys			jsontype	numtype		dbtype 		dbstrtype	oper		dboper			coldesc

// Additional fields not present in DB
{ "madid",		"", 			GYSLEN("madid"),	FIELD_MADID,		SUBSYS_MADHAVALIST,	JSON_STRING,	NUM_NAN,	"char(16)",	DB_STR_OCHAR,	nullptr,	nullptr,		"", },
{ "host",		"",		 	GYSLEN("host"),		FIELD_HOST,		SUBSYS_MADHAVALIST,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,		"", },
{ "port", 		"", 			GYSLEN("port"),		FIELD_PORT,		SUBSYS_MADHAVALIST,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "commver", 		"", 			GYSLEN("commver"),	FIELD_COMMVER,		SUBSYS_MADHAVALIST,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "npartha", 		"", 			GYSLEN("npartha"),	FIELD_NPARTHA,		SUBSYS_MADHAVALIST,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "maxpartha", 		"", 			GYSLEN("maxpartha"),	FIELD_MAXPARTHA,	SUBSYS_MADHAVALIST,	JSON_NUMBER,	NUM_INT32,	"int",		DB_STR_NONE,	nullptr, 	nullptr,		"", },
{ "region",		"",		 	GYSLEN("region"),	FIELD_REGION,		SUBSYS_MADHAVALIST,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,		"", },
{ "zone",		"",		 	GYSLEN("zone"),		FIELD_ZONE,		SUBSYS_MADHAVALIST,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,		"", },
{ "madhavaname",	"",		 	GYSLEN("madhavaname"),	FIELD_MADHAVANAME,	SUBSYS_MADHAVALIST,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,		"", },
{ "version",		"",		 	GYSLEN("version"),	FIELD_VERSION,		SUBSYS_MADHAVALIST,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,		"", },
{ "isconn",		"",			GYSLEN("isconn"),	FIELD_ISCONN,		SUBSYS_MADHAVALIST,	JSON_BOOL,	NUM_NAN,	"boolean",	DB_STR_NONE,	nullptr, 	booltojson,		"", },		
{ "lastseen", 		"", 			GYSLEN("lastseen"),	FIELD_LASTSEEN,		SUBSYS_MADHAVALIST,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr, 		"", },

};

enum : uint32_t
{
	/*FIELD_PARID		= fnv1_consthash("parid"),*/
	/*FIELD_HOST		= fnv1_consthash("host"),*/
	/*FIELD_CLUSTER		= fnv1_consthash("cluster"),*/
	/*FIELD_REGION		= fnv1_consthash("region"),*/
	/*FIELD_ZONE		= fnv1_consthash("zone"),*/
	/*FIELD_VERSION		= fnv1_consthash("version"),*/
	/*FIELD_BOOT		= fnv1_consthash("boot"),*/
	/*FIELD_KERNVERSTR	= fnv1_consthash("kernverstr"),*/
	/*FIELD_ISCONN		= fnv1_consthash("isconn"),*/
	/*FIELD_LASTSEEN	= fnv1_consthash("lastseen"),*/
};	


static constexpr JSON_DB_MAPPING json_db_parthalist_arr[] =
{
// jsonfield		dbcolname		szjson			jsoncrc JSON hash	subsys			jsontype	numtype		dbtype 		dbstrtype	oper		dboper			coldesc

// Additional fields not present in DB
{ "parid", 		"", 			GYSLEN("parid"),	FIELD_PARID,		SUBSYS_PARTHALIST,	JSON_STRING,	NUM_NAN,	"char(32)",	DB_STR_OCHAR,	nullptr,	nullptr,		"", },
{ "host",		"",		 	GYSLEN("host"),		FIELD_HOST,		SUBSYS_PARTHALIST,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,		"", },
{ "cluster",		"", 			GYSLEN("cluster"),	FIELD_CLUSTER,		SUBSYS_PARTHALIST,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,		"", },
{ "region",		"",		 	GYSLEN("region"),	FIELD_REGION,		SUBSYS_PARTHALIST,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,		"", },
{ "zone",		"",		 	GYSLEN("zone"),		FIELD_ZONE,		SUBSYS_PARTHALIST,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,		"", },
{ "version",		"",		 	GYSLEN("version"),	FIELD_VERSION,		SUBSYS_PARTHALIST,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,		"", },
{ "boot", 		"", 			GYSLEN("boot"),		FIELD_BOOT,		SUBSYS_PARTHALIST,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr,		"", },
{ "kernverstr",		"", 			GYSLEN("kernverstr"),	FIELD_KERNVERSTR,	SUBSYS_PARTHALIST,	JSON_STRING,	NUM_NAN,	"text",		DB_STR_TEXT,	nullptr,	nullptr,		"", },
{ "isconn",		"",			GYSLEN("isconn"),	FIELD_ISCONN,		SUBSYS_PARTHALIST,	JSON_BOOL,	NUM_NAN,	"boolean",	DB_STR_NONE,	nullptr, 	booltojson,		"", },		
{ "lastseen", 		"", 			GYSLEN("lastseen"),	FIELD_LASTSEEN,		SUBSYS_PARTHALIST,	JSON_STRING,	NUM_NAN,	"timestamptz",	DB_STR_TEXT,	nullptr, 	nullptr, 		"", },

};


struct SUBSYS_CLASS
{
	const char *			jsonstr			{nullptr};
	SUBSYS_CLASS_E			subsysval		{SUBSYS_MAX};
	uint32_t			jsoncrc			{0};
	const JSON_DB_MAPPING		*pjsonmap		{nullptr};
	size_t				szjsonmap		{0};
	const char			*machidfilstr		{nullptr};
};	

struct DB_AGGR_CLASS
{
	SUBSYS_CLASS_E			subsysval		{SUBSYS_MAX};
	const JSON_DB_MAPPING		*pajsonmap		{nullptr};
	size_t				szajsonmap		{0};
	const DB_AGGR_INFO		*paggrinfo		{nullptr};
	uint32_t			szaggrinfo		{0};
	uint32_t			minqrysec		{0};
};	

enum ASYS_TYPE_E : uint8_t
{
	ASYS_NONE			= 0,
	ASYS_PROC_SVC,
	ASYS_HOST,
	ASYS_CLUSTER,
};

struct SUBSYS_STATS
{
	SUBSYS_CLASS_E			subsysval		{SUBSYS_MAX};
	uint32_t			upd_inter_sec		{0};
	ALERT_KEY_TYPE_E		akeytype		{AKEY_INVALID};
	ADEF_HDLR_E			ahandler		{AHDLR_PARTHA};
	ASYS_TYPE_E			systype			{ASYS_NONE};
};	

extern SUBSYS_CLASS subsys_class_list[SUBSYS_MAX];
extern DB_AGGR_CLASS subsys_aggr_list[SUBSYS_MAX];
extern SUBSYS_STATS subsys_stats_list[SUBSYS_MAX];

static const SUBSYS_CLASS * get_subsys_info(SUBSYS_CLASS_E subsys) noexcept
{
	if ((size_t)subsys < (size_t)SUBSYS_MAX) {
		return subsys_class_list + subsys;
	}	

	return nullptr;
}	

static const char * get_subsys_name(SUBSYS_CLASS_E subsys) noexcept
{
	if ((size_t)subsys < (size_t)SUBSYS_MAX) {
		return subsys_class_list[subsys].jsonstr;
	}	

	return "unknown";
}	

static const DB_AGGR_CLASS * get_subsys_aggr_info(SUBSYS_CLASS_E subsys) noexcept
{
	if ((size_t)subsys < (size_t)SUBSYS_MAX) {
		return subsys_aggr_list + subsys;
	}	

	return nullptr;
}	

static const SUBSYS_STATS * get_subsys_stats(SUBSYS_CLASS_E subsys) noexcept
{
	if ((size_t)subsys < (size_t)SUBSYS_MAX) {
		return subsys_stats_list + subsys;
	}	

	return nullptr;
}	

static ADEF_HDLR_E get_subsys_handler(SUBSYS_CLASS_E subsys) noexcept
{
	if ((size_t)subsys < (size_t)SUBSYS_MAX) {
		return subsys_stats_list[subsys].ahandler;
	}	

	return AHDLR_MADHAVA;
}	

static size_t get_subsys_columns(const JSON_DB_MAPPING **colarr, size_t maxcol, SUBSYS_CLASS_E subsys) noexcept 
{
	size_t			n = 0;

	if ((size_t)subsys >= (size_t)SUBSYS_MAX || !colarr || !maxcol) {
		return 0;
	}

	auto			*pmap = subsys_class_list[subsys].pjsonmap;
	size_t			szmap = subsys_class_list[subsys].szjsonmap;

	for (size_t i = 0; i < szmap && n < maxcol; ++i) {
		colarr[n++] = &pmap[i];
	}

	return n;
}	

static const char * subsys_to_string(SUBSYS_CLASS_E subsys) noexcept
{
	if ((size_t)subsys < (size_t)SUBSYS_MAX) {
		return subsys_class_list[subsys].jsonstr;
	}	

	return "unknown";
}	

static bool force_subsys_multihost(SUBSYS_CLASS_E subsys) noexcept
{
	return subsys == SUBSYS_HOSTINFO;
}	


static size_t upd_subsys_from_qtype(NODE_QUERY_TYPE_E qtype, SUBSYS_CLASS_E *psubsyarr, size_t maxarr) noexcept
{
	if (!psubsyarr || !maxarr) {
		return 0;
	}

	switch (qtype) {

	case NQUERY_NM_HOST_STATE		:	psubsyarr[0] = SUBSYS_HOSTSTATE; return 1;

	case NQUERY_NM_CPU_MEM			:	psubsyarr[0] = SUBSYS_CPUMEM; return 1;	

	case NQUERY_NM_LISTENER_STATE		:	psubsyarr[0] = SUBSYS_SVCSTATE; return 1;

	case NQUERY_NM_EXTSVCSTATE		:	psubsyarr[0] = SUBSYS_EXTSVCSTATE; return 1;

	case NQUERY_NM_TOP_HOST_PROCS		:	
		if (maxarr >= 4) {
			psubsyarr[0] = SUBSYS_TOPCPU;
			psubsyarr[1] = SUBSYS_TOPPGCPU;
			psubsyarr[2] = SUBSYS_TOPRSS;
			psubsyarr[3] = SUBSYS_TOPFORK;

			return 4;
		}

		psubsyarr[0] = SUBSYS_TOPCPU;
		return 1;

	case NQUERY_NM_TOP_LISTENERS		:
		if (maxarr >= 3) {
			psubsyarr[0] = SUBSYS_SVCSTATE;
			psubsyarr[1] = SUBSYS_SVCSUMM;
			psubsyarr[2] = SUBSYS_SVCINFO;

			return 3;
		}

		psubsyarr[0] = SUBSYS_SVCSTATE;
		return 1;


	case NQUERY_NM_LISTENER_INFO		:	psubsyarr[0] = SUBSYS_SVCINFO; return 1;

	case NQUERY_NM_ACTIVE_CONN		:	psubsyarr[0] = SUBSYS_ACTIVECONN; return 1;

	case NQUERY_NM_EXTACTIVECONN		:	psubsyarr[0] = SUBSYS_EXTACTIVECONN; return 1;

	case NQUERY_NM_LISTENER_SUMM		:	psubsyarr[0] = SUBSYS_SVCSUMM; return 1;

	case NQUERY_NM_LISTENPROC_MAP		:	psubsyarr[0] = SUBSYS_SVCPROCMAP; return 1;

	case NQUERY_NM_CLIENT_CONN		:	psubsyarr[0] = SUBSYS_CLIENTCONN; return 1;

	case NQUERY_NM_EXTCLIENTCONN		:	psubsyarr[0] = SUBSYS_EXTCLIENTCONN; return 1;

	case NQUERY_NM_NOTIFY_MSG		:	psubsyarr[0] = SUBSYS_NOTIFYMSG; return 1;

	case NQUERY_NM_HOST_INFO		:	psubsyarr[0] = SUBSYS_HOSTINFO; return 1;

	case NQUERY_NM_PROC_INFO		:	psubsyarr[0] = SUBSYS_PROCINFO; return 1;

	case NQUERY_NM_PROC_STATE		:	psubsyarr[0] = SUBSYS_PROCSTATE; return 1;

	case NQUERY_NM_EXTPROCSTATE		:	psubsyarr[0] = SUBSYS_EXTPROCSTATE; return 1;

	case NQUERY_NM_TOP_AGGR_PROCS		:	psubsyarr[0] = SUBSYS_PROCSTATE; return 1;

	case NQUERY_NM_CLUSTER_STATE		:	psubsyarr[0] = SUBSYS_CLUSTERSTATE; return 1;

	case NQUERY_NS_SVC_MESH_CLUST		:	psubsyarr[0] = SUBSYS_SVCMESHCLUST; return 1;

	case NQUERY_NS_SVC_IP_CLUST		:	psubsyarr[0] = SUBSYS_SVCIPCLUST; return 1;

	case NQUERY_NS_ALERTS			:	psubsyarr[0] = SUBSYS_ALERTS; return 1;

	case NQUERY_NS_ALERTDEF			:	psubsyarr[0] = SUBSYS_ALERTDEF; return 1;

	case NQUERY_NS_INHIBITS			:	psubsyarr[0] = SUBSYS_INHIBITS; return 1;

	case NQUERY_NS_SILENCES			:	psubsyarr[0] = SUBSYS_SILENCES; return 1;

	case NQUERY_NS_ACTIONS			:	psubsyarr[0] = SUBSYS_ACTIONS; return 1;

	case NQUERY_NS_MADHAVA_LIST		:	psubsyarr[0] = SUBSYS_MADHAVALIST; return 1;

	case NQUERY_NS_SHYAMASTATUS		: 	psubsyarr[0] = SUBSYS_SHYAMASTATUS; return 1;

	case NQUERY_NM_MADHAVASTATUS		:	psubsyarr[0] = SUBSYS_MADHAVASTATUS; return 1;

	case NQUERY_NM_PARTHALIST		:	psubsyarr[0] = SUBSYS_PARTHALIST; return 1;

	default					: 	return 0;	

	}	
}	

static void set_ext_svcstate_fields()
{
	uint32_t			nextsvcstate_arr = 0, nextsvcstate_aggr_arr = 0, nextsvcstate_aggr_info = 0;
	JSON_DB_MAPPING			*pextsvcstate_arr = new JSON_DB_MAPPING[GY_ARRAY_SIZE(json_db_svcstate_arr) + GY_ARRAY_SIZE(json_db_svcinfo_arr)];
	
	std::memcpy(pextsvcstate_arr, json_db_svcstate_arr, GY_ARRAY_SIZE(json_db_svcstate_arr) * sizeof(*json_db_svcstate_arr));
	nextsvcstate_arr = GY_ARRAY_SIZE(json_db_svcstate_arr);
	
	pextsvcstate_arr[nextsvcstate_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_IP, json_db_svcinfo_arr, GY_ARRAY_SIZE(json_db_svcinfo_arr));
	pextsvcstate_arr[nextsvcstate_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_PORT, json_db_svcinfo_arr, GY_ARRAY_SIZE(json_db_svcinfo_arr));
	pextsvcstate_arr[nextsvcstate_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_RELSVCID, json_db_svcinfo_arr, GY_ARRAY_SIZE(json_db_svcinfo_arr));
	pextsvcstate_arr[nextsvcstate_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_TSTART, json_db_svcinfo_arr, GY_ARRAY_SIZE(json_db_svcinfo_arr));
	pextsvcstate_arr[nextsvcstate_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_CMDLINE, json_db_svcinfo_arr, GY_ARRAY_SIZE(json_db_svcinfo_arr));
	pextsvcstate_arr[nextsvcstate_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_P95RESP5D, json_db_svcinfo_arr, GY_ARRAY_SIZE(json_db_svcinfo_arr));
	pextsvcstate_arr[nextsvcstate_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_AVGRESP5D, json_db_svcinfo_arr, GY_ARRAY_SIZE(json_db_svcinfo_arr));
	pextsvcstate_arr[nextsvcstate_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_P95QPS, json_db_svcinfo_arr, GY_ARRAY_SIZE(json_db_svcinfo_arr));
	pextsvcstate_arr[nextsvcstate_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_P95ACONN, json_db_svcinfo_arr, GY_ARRAY_SIZE(json_db_svcinfo_arr));
	pextsvcstate_arr[nextsvcstate_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_SVCIP1, json_db_svcinfo_arr, GY_ARRAY_SIZE(json_db_svcinfo_arr));
	pextsvcstate_arr[nextsvcstate_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_SVCPORT1, json_db_svcinfo_arr, GY_ARRAY_SIZE(json_db_svcinfo_arr));
	pextsvcstate_arr[nextsvcstate_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_SVCDNS, json_db_svcinfo_arr, GY_ARRAY_SIZE(json_db_svcinfo_arr));
	pextsvcstate_arr[nextsvcstate_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_SVCTAG, json_db_svcinfo_arr, GY_ARRAY_SIZE(json_db_svcinfo_arr));
	pextsvcstate_arr[nextsvcstate_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_REGION, json_db_svcinfo_arr, GY_ARRAY_SIZE(json_db_svcinfo_arr));
	pextsvcstate_arr[nextsvcstate_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_ZONE, json_db_svcinfo_arr, GY_ARRAY_SIZE(json_db_svcinfo_arr));

	ASSERT_OR_THROW(nextsvcstate_arr < MAX_COLUMN_LIST, "Internal Error : Number of columns of extended svcstate %u exceeds max allowed %lu", 
				nextsvcstate_arr, MAX_COLUMN_LIST);

	for (uint32_t i = 0; i < nextsvcstate_arr; ++i) {
		pextsvcstate_arr[i].subsys = SUBSYS_EXTSVCSTATE;
	}	
	
	// Now update subsys_class_list
	subsys_class_list[SUBSYS_EXTSVCSTATE].pjsonmap 	= pextsvcstate_arr;
	subsys_class_list[SUBSYS_EXTSVCSTATE].szjsonmap = nextsvcstate_arr;


	JSON_DB_MAPPING			*pextsvcstate_aggr_arr = new JSON_DB_MAPPING[GY_ARRAY_SIZE(json_db_aggr_svcstate_arr) + GY_ARRAY_SIZE(json_db_aggr_svcinfo_arr)];

	std::memcpy(pextsvcstate_aggr_arr, json_db_aggr_svcstate_arr, GY_ARRAY_SIZE(json_db_aggr_svcstate_arr) * sizeof(*json_db_aggr_svcstate_arr));
	nextsvcstate_aggr_arr = GY_ARRAY_SIZE(json_db_aggr_svcstate_arr);
	
	pextsvcstate_aggr_arr[nextsvcstate_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_IP, json_db_aggr_svcinfo_arr, GY_ARRAY_SIZE(json_db_aggr_svcinfo_arr));
	pextsvcstate_aggr_arr[nextsvcstate_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_PORT, json_db_aggr_svcinfo_arr, GY_ARRAY_SIZE(json_db_aggr_svcinfo_arr));
	pextsvcstate_aggr_arr[nextsvcstate_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_RELSVCID, json_db_aggr_svcinfo_arr, GY_ARRAY_SIZE(json_db_aggr_svcinfo_arr));
	pextsvcstate_aggr_arr[nextsvcstate_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_TSTART, json_db_aggr_svcinfo_arr, GY_ARRAY_SIZE(json_db_aggr_svcinfo_arr));
	pextsvcstate_aggr_arr[nextsvcstate_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_CMDLINE, json_db_aggr_svcinfo_arr, GY_ARRAY_SIZE(json_db_aggr_svcinfo_arr));
	pextsvcstate_aggr_arr[nextsvcstate_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_P95RESP5D, json_db_aggr_svcinfo_arr, GY_ARRAY_SIZE(json_db_aggr_svcinfo_arr));
	pextsvcstate_aggr_arr[nextsvcstate_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_AVGRESP5D, json_db_aggr_svcinfo_arr, GY_ARRAY_SIZE(json_db_aggr_svcinfo_arr));
	pextsvcstate_aggr_arr[nextsvcstate_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_P95QPS, json_db_aggr_svcinfo_arr, GY_ARRAY_SIZE(json_db_aggr_svcinfo_arr));
	pextsvcstate_aggr_arr[nextsvcstate_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_P95ACONN, json_db_aggr_svcinfo_arr, GY_ARRAY_SIZE(json_db_aggr_svcinfo_arr));
	pextsvcstate_aggr_arr[nextsvcstate_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_SVCIP1, json_db_aggr_svcinfo_arr, GY_ARRAY_SIZE(json_db_aggr_svcinfo_arr));
	pextsvcstate_aggr_arr[nextsvcstate_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_SVCPORT1, json_db_aggr_svcinfo_arr, GY_ARRAY_SIZE(json_db_aggr_svcinfo_arr));
	pextsvcstate_aggr_arr[nextsvcstate_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_SVCDNS, json_db_aggr_svcinfo_arr, GY_ARRAY_SIZE(json_db_aggr_svcinfo_arr));
	pextsvcstate_aggr_arr[nextsvcstate_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_SVCTAG, json_db_aggr_svcinfo_arr, GY_ARRAY_SIZE(json_db_aggr_svcinfo_arr));
	pextsvcstate_aggr_arr[nextsvcstate_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_REGION, json_db_aggr_svcinfo_arr, GY_ARRAY_SIZE(json_db_aggr_svcinfo_arr));
	pextsvcstate_aggr_arr[nextsvcstate_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_ZONE, json_db_aggr_svcinfo_arr, GY_ARRAY_SIZE(json_db_aggr_svcinfo_arr));

	ASSERT_OR_THROW(nextsvcstate_aggr_arr < MAX_COLUMN_LIST, "Internal Error : Number of columns of extended svcstate aggregates %u exceeds max allowed %lu", 
				nextsvcstate_aggr_arr, MAX_COLUMN_LIST);

	for (uint32_t i = 0; i < nextsvcstate_aggr_arr; ++i) {
		pextsvcstate_aggr_arr[i].subsys = SUBSYS_EXTSVCSTATE;
	}	
	

	DB_AGGR_INFO			*pextsvcstate_aggr_info	= new DB_AGGR_INFO[GY_ARRAY_SIZE(svcstate_aggr_info) + GY_ARRAY_SIZE(svcinfo_aggr_info)];

	std::memcpy(pextsvcstate_aggr_info, svcstate_aggr_info, GY_ARRAY_SIZE(svcstate_aggr_info) * sizeof(*svcstate_aggr_info));
	nextsvcstate_aggr_info = GY_ARRAY_SIZE(svcstate_aggr_info);
	
	pextsvcstate_aggr_info[nextsvcstate_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_IP, svcinfo_aggr_info, GY_ARRAY_SIZE(svcinfo_aggr_info));
	pextsvcstate_aggr_info[nextsvcstate_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_PORT, svcinfo_aggr_info, GY_ARRAY_SIZE(svcinfo_aggr_info));
	pextsvcstate_aggr_info[nextsvcstate_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_RELSVCID, svcinfo_aggr_info, GY_ARRAY_SIZE(svcinfo_aggr_info));
	pextsvcstate_aggr_info[nextsvcstate_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_TSTART, svcinfo_aggr_info, GY_ARRAY_SIZE(svcinfo_aggr_info));
	pextsvcstate_aggr_info[nextsvcstate_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_CMDLINE, svcinfo_aggr_info, GY_ARRAY_SIZE(svcinfo_aggr_info));
	pextsvcstate_aggr_info[nextsvcstate_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_P95RESP5D, svcinfo_aggr_info, GY_ARRAY_SIZE(svcinfo_aggr_info));
	pextsvcstate_aggr_info[nextsvcstate_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_AVGRESP5D, svcinfo_aggr_info, GY_ARRAY_SIZE(svcinfo_aggr_info));
	pextsvcstate_aggr_info[nextsvcstate_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_P95QPS, svcinfo_aggr_info, GY_ARRAY_SIZE(svcinfo_aggr_info));
	pextsvcstate_aggr_info[nextsvcstate_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_P95ACONN, svcinfo_aggr_info, GY_ARRAY_SIZE(svcinfo_aggr_info));
	pextsvcstate_aggr_info[nextsvcstate_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_SVCIP1, svcinfo_aggr_info, GY_ARRAY_SIZE(svcinfo_aggr_info));
	pextsvcstate_aggr_info[nextsvcstate_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_SVCPORT1, svcinfo_aggr_info, GY_ARRAY_SIZE(svcinfo_aggr_info));
	pextsvcstate_aggr_info[nextsvcstate_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_SVCDNS, svcinfo_aggr_info, GY_ARRAY_SIZE(svcinfo_aggr_info));
	pextsvcstate_aggr_info[nextsvcstate_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_SVCTAG, svcinfo_aggr_info, GY_ARRAY_SIZE(svcinfo_aggr_info));
	pextsvcstate_aggr_info[nextsvcstate_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_REGION, svcinfo_aggr_info, GY_ARRAY_SIZE(svcinfo_aggr_info));
	pextsvcstate_aggr_info[nextsvcstate_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_ZONE, svcinfo_aggr_info, GY_ARRAY_SIZE(svcinfo_aggr_info));

	ASSERT_OR_THROW(nextsvcstate_aggr_info < MAX_COLUMN_LIST, "Internal Error : Number of columns of extended svcstate aggregate info %u exceeds max allowed %lu", 
				nextsvcstate_aggr_info, MAX_COLUMN_LIST);

	// Now update subsys_aggr_list
	subsys_aggr_list[SUBSYS_EXTSVCSTATE].pajsonmap 	= pextsvcstate_aggr_arr;
	subsys_aggr_list[SUBSYS_EXTSVCSTATE].szajsonmap = nextsvcstate_aggr_arr;

	subsys_aggr_list[SUBSYS_EXTSVCSTATE].paggrinfo 	= pextsvcstate_aggr_info;
	subsys_aggr_list[SUBSYS_EXTSVCSTATE].szaggrinfo = nextsvcstate_aggr_info;

}	

static void set_ext_activeconn_fields()
{
	uint32_t			nextactiveconn_arr = 0, nextactiveconn_aggr_arr = 0, nextactiveconn_aggr_info = 0;
	JSON_DB_MAPPING			*pextactiveconn_arr = new JSON_DB_MAPPING[GY_ARRAY_SIZE(json_db_activeconn_arr) + GY_ARRAY_SIZE(json_db_svcinfo_arr)];
	
	std::memcpy(pextactiveconn_arr, json_db_activeconn_arr, GY_ARRAY_SIZE(json_db_activeconn_arr) * sizeof(*json_db_activeconn_arr));
	nextactiveconn_arr = GY_ARRAY_SIZE(json_db_activeconn_arr);
	
	pextactiveconn_arr[nextactiveconn_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_IP, json_db_svcinfo_arr, GY_ARRAY_SIZE(json_db_svcinfo_arr));
	pextactiveconn_arr[nextactiveconn_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_PORT, json_db_svcinfo_arr, GY_ARRAY_SIZE(json_db_svcinfo_arr));
	pextactiveconn_arr[nextactiveconn_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_RELSVCID, json_db_svcinfo_arr, GY_ARRAY_SIZE(json_db_svcinfo_arr));
	pextactiveconn_arr[nextactiveconn_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_TSTART, json_db_svcinfo_arr, GY_ARRAY_SIZE(json_db_svcinfo_arr));
	pextactiveconn_arr[nextactiveconn_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_CMDLINE, json_db_svcinfo_arr, GY_ARRAY_SIZE(json_db_svcinfo_arr));
	pextactiveconn_arr[nextactiveconn_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_P95RESP5D, json_db_svcinfo_arr, GY_ARRAY_SIZE(json_db_svcinfo_arr));
	pextactiveconn_arr[nextactiveconn_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_AVGRESP5D, json_db_svcinfo_arr, GY_ARRAY_SIZE(json_db_svcinfo_arr));
	pextactiveconn_arr[nextactiveconn_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_P95QPS, json_db_svcinfo_arr, GY_ARRAY_SIZE(json_db_svcinfo_arr));
	pextactiveconn_arr[nextactiveconn_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_P95ACONN, json_db_svcinfo_arr, GY_ARRAY_SIZE(json_db_svcinfo_arr));
	pextactiveconn_arr[nextactiveconn_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_SVCIP1, json_db_svcinfo_arr, GY_ARRAY_SIZE(json_db_svcinfo_arr));
	pextactiveconn_arr[nextactiveconn_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_SVCPORT1, json_db_svcinfo_arr, GY_ARRAY_SIZE(json_db_svcinfo_arr));
	pextactiveconn_arr[nextactiveconn_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_SVCDNS, json_db_svcinfo_arr, GY_ARRAY_SIZE(json_db_svcinfo_arr));
	pextactiveconn_arr[nextactiveconn_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_SVCTAG, json_db_svcinfo_arr, GY_ARRAY_SIZE(json_db_svcinfo_arr));
	pextactiveconn_arr[nextactiveconn_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_REGION, json_db_svcinfo_arr, GY_ARRAY_SIZE(json_db_svcinfo_arr));
	pextactiveconn_arr[nextactiveconn_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_ZONE, json_db_svcinfo_arr, GY_ARRAY_SIZE(json_db_svcinfo_arr));

	ASSERT_OR_THROW(nextactiveconn_arr < MAX_COLUMN_LIST, "Internal Error : Number of columns of extended activeconn %u exceeds max allowed %lu", 
				nextactiveconn_arr, MAX_COLUMN_LIST);

	for (uint32_t i = 0; i < nextactiveconn_arr; ++i) {
		pextactiveconn_arr[i].subsys	= SUBSYS_EXTACTIVECONN;
	}

	// Now update subsys_class_list
	subsys_class_list[SUBSYS_EXTACTIVECONN].pjsonmap 	= pextactiveconn_arr;
	subsys_class_list[SUBSYS_EXTACTIVECONN].szjsonmap 	= nextactiveconn_arr;


	JSON_DB_MAPPING			*pextactiveconn_aggr_arr = new JSON_DB_MAPPING[GY_ARRAY_SIZE(json_db_aggr_activeconn_arr) + GY_ARRAY_SIZE(json_db_aggr_svcinfo_arr)];

	std::memcpy(pextactiveconn_aggr_arr, json_db_aggr_activeconn_arr, GY_ARRAY_SIZE(json_db_aggr_activeconn_arr) * sizeof(*json_db_aggr_activeconn_arr));
	nextactiveconn_aggr_arr = GY_ARRAY_SIZE(json_db_aggr_activeconn_arr);
	
	pextactiveconn_aggr_arr[nextactiveconn_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_IP, json_db_aggr_svcinfo_arr, GY_ARRAY_SIZE(json_db_aggr_svcinfo_arr));
	pextactiveconn_aggr_arr[nextactiveconn_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_PORT, json_db_aggr_svcinfo_arr, GY_ARRAY_SIZE(json_db_aggr_svcinfo_arr));
	pextactiveconn_aggr_arr[nextactiveconn_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_RELSVCID, json_db_aggr_svcinfo_arr, GY_ARRAY_SIZE(json_db_aggr_svcinfo_arr));
	pextactiveconn_aggr_arr[nextactiveconn_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_TSTART, json_db_aggr_svcinfo_arr, GY_ARRAY_SIZE(json_db_aggr_svcinfo_arr));
	pextactiveconn_aggr_arr[nextactiveconn_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_CMDLINE, json_db_aggr_svcinfo_arr, GY_ARRAY_SIZE(json_db_aggr_svcinfo_arr));
	pextactiveconn_aggr_arr[nextactiveconn_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_P95RESP5D, json_db_aggr_svcinfo_arr, GY_ARRAY_SIZE(json_db_aggr_svcinfo_arr));
	pextactiveconn_aggr_arr[nextactiveconn_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_AVGRESP5D, json_db_aggr_svcinfo_arr, GY_ARRAY_SIZE(json_db_aggr_svcinfo_arr));
	pextactiveconn_aggr_arr[nextactiveconn_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_P95QPS, json_db_aggr_svcinfo_arr, GY_ARRAY_SIZE(json_db_aggr_svcinfo_arr));
	pextactiveconn_aggr_arr[nextactiveconn_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_P95ACONN, json_db_aggr_svcinfo_arr, GY_ARRAY_SIZE(json_db_aggr_svcinfo_arr));
	pextactiveconn_aggr_arr[nextactiveconn_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_SVCIP1, json_db_aggr_svcinfo_arr, GY_ARRAY_SIZE(json_db_aggr_svcinfo_arr));
	pextactiveconn_aggr_arr[nextactiveconn_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_SVCPORT1, json_db_aggr_svcinfo_arr, GY_ARRAY_SIZE(json_db_aggr_svcinfo_arr));
	pextactiveconn_aggr_arr[nextactiveconn_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_SVCDNS, json_db_aggr_svcinfo_arr, GY_ARRAY_SIZE(json_db_aggr_svcinfo_arr));
	pextactiveconn_aggr_arr[nextactiveconn_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_SVCTAG, json_db_aggr_svcinfo_arr, GY_ARRAY_SIZE(json_db_aggr_svcinfo_arr));
	pextactiveconn_aggr_arr[nextactiveconn_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_REGION, json_db_aggr_svcinfo_arr, GY_ARRAY_SIZE(json_db_aggr_svcinfo_arr));
	pextactiveconn_aggr_arr[nextactiveconn_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_ZONE, json_db_aggr_svcinfo_arr, GY_ARRAY_SIZE(json_db_aggr_svcinfo_arr));

	ASSERT_OR_THROW(nextactiveconn_aggr_arr < MAX_COLUMN_LIST, "Internal Error : Number of columns of extended activeconn aggregates %u exceeds max allowed %lu", 
				nextactiveconn_aggr_arr, MAX_COLUMN_LIST);

	for (uint32_t i = 0; i < nextactiveconn_aggr_arr; ++i) {
		pextactiveconn_aggr_arr[i].subsys	= SUBSYS_EXTACTIVECONN;
	}	

	DB_AGGR_INFO			*pextactiveconn_aggr_info	= new DB_AGGR_INFO[GY_ARRAY_SIZE(activeconn_aggr_info) + GY_ARRAY_SIZE(svcinfo_aggr_info)];

	std::memcpy(pextactiveconn_aggr_info, activeconn_aggr_info, GY_ARRAY_SIZE(activeconn_aggr_info) * sizeof(*activeconn_aggr_info));
	nextactiveconn_aggr_info = GY_ARRAY_SIZE(activeconn_aggr_info);
	
	pextactiveconn_aggr_info[nextactiveconn_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_IP, svcinfo_aggr_info, GY_ARRAY_SIZE(svcinfo_aggr_info));
	pextactiveconn_aggr_info[nextactiveconn_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_PORT, svcinfo_aggr_info, GY_ARRAY_SIZE(svcinfo_aggr_info));
	pextactiveconn_aggr_info[nextactiveconn_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_RELSVCID, svcinfo_aggr_info, GY_ARRAY_SIZE(svcinfo_aggr_info));
	pextactiveconn_aggr_info[nextactiveconn_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_TSTART, svcinfo_aggr_info, GY_ARRAY_SIZE(svcinfo_aggr_info));
	pextactiveconn_aggr_info[nextactiveconn_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_CMDLINE, svcinfo_aggr_info, GY_ARRAY_SIZE(svcinfo_aggr_info));
	pextactiveconn_aggr_info[nextactiveconn_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_P95RESP5D, svcinfo_aggr_info, GY_ARRAY_SIZE(svcinfo_aggr_info));
	pextactiveconn_aggr_info[nextactiveconn_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_AVGRESP5D, svcinfo_aggr_info, GY_ARRAY_SIZE(svcinfo_aggr_info));
	pextactiveconn_aggr_info[nextactiveconn_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_P95QPS, svcinfo_aggr_info, GY_ARRAY_SIZE(svcinfo_aggr_info));
	pextactiveconn_aggr_info[nextactiveconn_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_P95ACONN, svcinfo_aggr_info, GY_ARRAY_SIZE(svcinfo_aggr_info));
	pextactiveconn_aggr_info[nextactiveconn_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_SVCIP1, svcinfo_aggr_info, GY_ARRAY_SIZE(svcinfo_aggr_info));
	pextactiveconn_aggr_info[nextactiveconn_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_SVCPORT1, svcinfo_aggr_info, GY_ARRAY_SIZE(svcinfo_aggr_info));
	pextactiveconn_aggr_info[nextactiveconn_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_SVCDNS, svcinfo_aggr_info, GY_ARRAY_SIZE(svcinfo_aggr_info));
	pextactiveconn_aggr_info[nextactiveconn_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_SVCTAG, svcinfo_aggr_info, GY_ARRAY_SIZE(svcinfo_aggr_info));
	pextactiveconn_aggr_info[nextactiveconn_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_REGION, svcinfo_aggr_info, GY_ARRAY_SIZE(svcinfo_aggr_info));
	pextactiveconn_aggr_info[nextactiveconn_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_ZONE, svcinfo_aggr_info, GY_ARRAY_SIZE(svcinfo_aggr_info));

	ASSERT_OR_THROW(nextactiveconn_aggr_info < MAX_COLUMN_LIST, "Internal Error : Number of columns of extended activeconn aggregate info %u exceeds max allowed %lu", 
				nextactiveconn_aggr_info, MAX_COLUMN_LIST);

	// Now update subsys_aggr_list
	subsys_aggr_list[SUBSYS_EXTACTIVECONN].pajsonmap 	= pextactiveconn_aggr_arr;
	subsys_aggr_list[SUBSYS_EXTACTIVECONN].szajsonmap 	= nextactiveconn_aggr_arr;

	subsys_aggr_list[SUBSYS_EXTACTIVECONN].paggrinfo 	= pextactiveconn_aggr_info;
	subsys_aggr_list[SUBSYS_EXTACTIVECONN].szaggrinfo	= nextactiveconn_aggr_info;

}

static void set_ext_clientconn_fields()
{
	uint32_t			nextclientconn_arr = 0, nextclientconn_aggr_arr = 0, nextclientconn_aggr_info = 0;
	JSON_DB_MAPPING			*pextclientconn_arr = new JSON_DB_MAPPING[GY_ARRAY_SIZE(json_db_clientconn_arr) + GY_ARRAY_SIZE(json_db_procinfo_arr)];
	
	std::memcpy(pextclientconn_arr, json_db_clientconn_arr, GY_ARRAY_SIZE(json_db_clientconn_arr) * sizeof(*json_db_clientconn_arr));
	nextclientconn_arr = GY_ARRAY_SIZE(json_db_clientconn_arr);
	
	pextclientconn_arr[nextclientconn_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_CMDLINE, json_db_procinfo_arr, GY_ARRAY_SIZE(json_db_procinfo_arr));
	pextclientconn_arr[nextclientconn_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_TAG, json_db_procinfo_arr, GY_ARRAY_SIZE(json_db_procinfo_arr));
	pextclientconn_arr[nextclientconn_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_UID, json_db_procinfo_arr, GY_ARRAY_SIZE(json_db_procinfo_arr));
	pextclientconn_arr[nextclientconn_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_GID, json_db_procinfo_arr, GY_ARRAY_SIZE(json_db_procinfo_arr));
	pextclientconn_arr[nextclientconn_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_TSTART, json_db_procinfo_arr, GY_ARRAY_SIZE(json_db_procinfo_arr));
	pextclientconn_arr[nextclientconn_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_P95CPUPCT, json_db_procinfo_arr, GY_ARRAY_SIZE(json_db_procinfo_arr));
	pextclientconn_arr[nextclientconn_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_P95CPUDEL, json_db_procinfo_arr, GY_ARRAY_SIZE(json_db_procinfo_arr));
	pextclientconn_arr[nextclientconn_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_P95IODEL, json_db_procinfo_arr, GY_ARRAY_SIZE(json_db_procinfo_arr));
	pextclientconn_arr[nextclientconn_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_NPROC, json_db_procinfo_arr, GY_ARRAY_SIZE(json_db_procinfo_arr));
	pextclientconn_arr[nextclientconn_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_REGION, json_db_procinfo_arr, GY_ARRAY_SIZE(json_db_procinfo_arr));
	pextclientconn_arr[nextclientconn_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_ZONE, json_db_procinfo_arr, GY_ARRAY_SIZE(json_db_procinfo_arr));

	ASSERT_OR_THROW(nextclientconn_arr < MAX_COLUMN_LIST, "Internal Error : Number of columns of extended clientconn %u exceeds max allowed %lu", 
				nextclientconn_arr, MAX_COLUMN_LIST);

	for (uint32_t i = 0; i < nextclientconn_arr; ++i) {
		pextclientconn_arr[i].subsys	= SUBSYS_EXTCLIENTCONN;
	}	

	// Now update subsys_class_list
	subsys_class_list[SUBSYS_EXTCLIENTCONN].pjsonmap 	= pextclientconn_arr;
	subsys_class_list[SUBSYS_EXTCLIENTCONN].szjsonmap 	= nextclientconn_arr;

	JSON_DB_MAPPING			*pextclientconn_aggr_arr = new JSON_DB_MAPPING[GY_ARRAY_SIZE(json_db_aggr_clientconn_arr) + GY_ARRAY_SIZE(json_db_aggr_procinfo_arr)];

	std::memcpy(pextclientconn_aggr_arr, json_db_aggr_clientconn_arr, GY_ARRAY_SIZE(json_db_aggr_clientconn_arr) * sizeof(*json_db_aggr_clientconn_arr));
	nextclientconn_aggr_arr = GY_ARRAY_SIZE(json_db_aggr_clientconn_arr);
	
	pextclientconn_aggr_arr[nextclientconn_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_CMDLINE, json_db_aggr_procinfo_arr, GY_ARRAY_SIZE(json_db_aggr_procinfo_arr));
	pextclientconn_aggr_arr[nextclientconn_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_TAG, json_db_aggr_procinfo_arr, GY_ARRAY_SIZE(json_db_aggr_procinfo_arr));
	pextclientconn_aggr_arr[nextclientconn_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_UID, json_db_aggr_procinfo_arr, GY_ARRAY_SIZE(json_db_aggr_procinfo_arr));
	pextclientconn_aggr_arr[nextclientconn_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_GID, json_db_aggr_procinfo_arr, GY_ARRAY_SIZE(json_db_aggr_procinfo_arr));
	pextclientconn_aggr_arr[nextclientconn_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_TSTART, json_db_aggr_procinfo_arr, GY_ARRAY_SIZE(json_db_aggr_procinfo_arr));
	pextclientconn_aggr_arr[nextclientconn_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_P95CPUPCT, json_db_aggr_procinfo_arr, GY_ARRAY_SIZE(json_db_aggr_procinfo_arr));
	pextclientconn_aggr_arr[nextclientconn_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_P95CPUDEL, json_db_aggr_procinfo_arr, GY_ARRAY_SIZE(json_db_aggr_procinfo_arr));
	pextclientconn_aggr_arr[nextclientconn_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_P95IODEL, json_db_aggr_procinfo_arr, GY_ARRAY_SIZE(json_db_aggr_procinfo_arr));
	pextclientconn_aggr_arr[nextclientconn_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_NPROC, json_db_aggr_procinfo_arr, GY_ARRAY_SIZE(json_db_aggr_procinfo_arr));
	pextclientconn_aggr_arr[nextclientconn_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_REGION, json_db_aggr_procinfo_arr, GY_ARRAY_SIZE(json_db_aggr_procinfo_arr));
	pextclientconn_aggr_arr[nextclientconn_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_ZONE, json_db_aggr_procinfo_arr, GY_ARRAY_SIZE(json_db_aggr_procinfo_arr));

	ASSERT_OR_THROW(nextclientconn_aggr_arr < MAX_COLUMN_LIST, "Internal Error : Number of columns of extended clientconn aggregates %u exceeds max allowed %lu", 
				nextclientconn_aggr_arr, MAX_COLUMN_LIST);

	for (uint32_t i = 0; i < nextclientconn_aggr_arr; ++i) {
		pextclientconn_aggr_arr[i].subsys	= SUBSYS_EXTCLIENTCONN;
	}	

	DB_AGGR_INFO			*pextclientconn_aggr_info	= new DB_AGGR_INFO[GY_ARRAY_SIZE(clientconn_aggr_info) + GY_ARRAY_SIZE(procinfo_aggr_info)];

	std::memcpy(pextclientconn_aggr_info, clientconn_aggr_info, GY_ARRAY_SIZE(clientconn_aggr_info) * sizeof(*clientconn_aggr_info));
	nextclientconn_aggr_info = GY_ARRAY_SIZE(clientconn_aggr_info);
	
	pextclientconn_aggr_info[nextclientconn_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_CMDLINE, procinfo_aggr_info, GY_ARRAY_SIZE(procinfo_aggr_info));
	pextclientconn_aggr_info[nextclientconn_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_TAG, procinfo_aggr_info, GY_ARRAY_SIZE(procinfo_aggr_info));
	pextclientconn_aggr_info[nextclientconn_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_UID, procinfo_aggr_info, GY_ARRAY_SIZE(procinfo_aggr_info));
	pextclientconn_aggr_info[nextclientconn_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_GID, procinfo_aggr_info, GY_ARRAY_SIZE(procinfo_aggr_info));
	pextclientconn_aggr_info[nextclientconn_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_TSTART, procinfo_aggr_info, GY_ARRAY_SIZE(procinfo_aggr_info));
	pextclientconn_aggr_info[nextclientconn_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_P95CPUPCT, procinfo_aggr_info, GY_ARRAY_SIZE(procinfo_aggr_info));
	pextclientconn_aggr_info[nextclientconn_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_P95CPUDEL, procinfo_aggr_info, GY_ARRAY_SIZE(procinfo_aggr_info));
	pextclientconn_aggr_info[nextclientconn_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_P95IODEL, procinfo_aggr_info, GY_ARRAY_SIZE(procinfo_aggr_info));
	pextclientconn_aggr_info[nextclientconn_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_NPROC, procinfo_aggr_info, GY_ARRAY_SIZE(procinfo_aggr_info));
	pextclientconn_aggr_info[nextclientconn_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_REGION, procinfo_aggr_info, GY_ARRAY_SIZE(procinfo_aggr_info));
	pextclientconn_aggr_info[nextclientconn_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_ZONE, procinfo_aggr_info, GY_ARRAY_SIZE(procinfo_aggr_info));

	ASSERT_OR_THROW(nextclientconn_aggr_info < MAX_COLUMN_LIST, "Internal Error : Number of columns of extended clientconn aggregate info %u exceeds max allowed %lu", 
				nextclientconn_aggr_info, MAX_COLUMN_LIST);

	// Now update subsys_aggr_list
	subsys_aggr_list[SUBSYS_EXTCLIENTCONN].pajsonmap 	= pextclientconn_aggr_arr;
	subsys_aggr_list[SUBSYS_EXTCLIENTCONN].szajsonmap 	= nextclientconn_aggr_arr;

	subsys_aggr_list[SUBSYS_EXTCLIENTCONN].paggrinfo 	= pextclientconn_aggr_info;
	subsys_aggr_list[SUBSYS_EXTCLIENTCONN].szaggrinfo 	= nextclientconn_aggr_info;

}

static void set_ext_procstate_fields()
{
	uint32_t			nextprocstate_arr = 0, nextprocstate_aggr_arr = 0, nextprocstate_aggr_info = 0;
	JSON_DB_MAPPING			*pextprocstate_arr = new JSON_DB_MAPPING[GY_ARRAY_SIZE(json_db_procstate_arr) + GY_ARRAY_SIZE(json_db_procinfo_arr)];
	
	std::memcpy(pextprocstate_arr, json_db_procstate_arr, GY_ARRAY_SIZE(json_db_procstate_arr) * sizeof(*json_db_procstate_arr));
	nextprocstate_arr = GY_ARRAY_SIZE(json_db_procstate_arr);
	
	pextprocstate_arr[nextprocstate_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_RELSVCID, json_db_procinfo_arr, GY_ARRAY_SIZE(json_db_procinfo_arr));
	pextprocstate_arr[nextprocstate_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_CMDLINE, json_db_procinfo_arr, GY_ARRAY_SIZE(json_db_procinfo_arr));
	pextprocstate_arr[nextprocstate_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_TAG, json_db_procinfo_arr, GY_ARRAY_SIZE(json_db_procinfo_arr));
	pextprocstate_arr[nextprocstate_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_UID, json_db_procinfo_arr, GY_ARRAY_SIZE(json_db_procinfo_arr));
	pextprocstate_arr[nextprocstate_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_GID, json_db_procinfo_arr, GY_ARRAY_SIZE(json_db_procinfo_arr));
	pextprocstate_arr[nextprocstate_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_CPUTHR, json_db_procinfo_arr, GY_ARRAY_SIZE(json_db_procinfo_arr));
	pextprocstate_arr[nextprocstate_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_MEMLIM, json_db_procinfo_arr, GY_ARRAY_SIZE(json_db_procinfo_arr));
	pextprocstate_arr[nextprocstate_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_TSTART, json_db_procinfo_arr, GY_ARRAY_SIZE(json_db_procinfo_arr));
	pextprocstate_arr[nextprocstate_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_P95CPUPCT, json_db_procinfo_arr, GY_ARRAY_SIZE(json_db_procinfo_arr));
	pextprocstate_arr[nextprocstate_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_P95CPUDEL, json_db_procinfo_arr, GY_ARRAY_SIZE(json_db_procinfo_arr));
	pextprocstate_arr[nextprocstate_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_P95IODEL, json_db_procinfo_arr, GY_ARRAY_SIZE(json_db_procinfo_arr));
	pextprocstate_arr[nextprocstate_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_CGCPULIMPCT, json_db_procinfo_arr, GY_ARRAY_SIZE(json_db_procinfo_arr));
	pextprocstate_arr[nextprocstate_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_CGRSSPCT, json_db_procinfo_arr, GY_ARRAY_SIZE(json_db_procinfo_arr));
	pextprocstate_arr[nextprocstate_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_REGION, json_db_procinfo_arr, GY_ARRAY_SIZE(json_db_procinfo_arr));
	pextprocstate_arr[nextprocstate_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_ZONE, json_db_procinfo_arr, GY_ARRAY_SIZE(json_db_procinfo_arr));

	ASSERT_OR_THROW(nextprocstate_arr < MAX_COLUMN_LIST, "Internal Error : Number of columns of extended procstate %u exceeds max allowed %lu", 
				nextprocstate_arr, MAX_COLUMN_LIST);

	for (uint32_t i = 0; i < nextprocstate_arr; ++i) {
		pextprocstate_arr[i].subsys	= SUBSYS_EXTPROCSTATE;
	}

	// Now update subsys_class_list
	subsys_class_list[SUBSYS_EXTPROCSTATE].pjsonmap 	= pextprocstate_arr;
	subsys_class_list[SUBSYS_EXTPROCSTATE].szjsonmap 	= nextprocstate_arr;

	JSON_DB_MAPPING			*pextprocstate_aggr_arr = new JSON_DB_MAPPING[GY_ARRAY_SIZE(json_db_aggr_procstate_arr) + GY_ARRAY_SIZE(json_db_aggr_procinfo_arr)];

	std::memcpy(pextprocstate_aggr_arr, json_db_aggr_procstate_arr, GY_ARRAY_SIZE(json_db_aggr_procstate_arr) * sizeof(*json_db_aggr_procstate_arr));
	nextprocstate_aggr_arr = GY_ARRAY_SIZE(json_db_aggr_procstate_arr);
	
	pextprocstate_aggr_arr[nextprocstate_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_RELSVCID, json_db_aggr_procinfo_arr, GY_ARRAY_SIZE(json_db_aggr_procinfo_arr));
	pextprocstate_aggr_arr[nextprocstate_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_CMDLINE, json_db_aggr_procinfo_arr, GY_ARRAY_SIZE(json_db_aggr_procinfo_arr));
	pextprocstate_aggr_arr[nextprocstate_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_TAG, json_db_aggr_procinfo_arr, GY_ARRAY_SIZE(json_db_aggr_procinfo_arr));
	pextprocstate_aggr_arr[nextprocstate_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_UID, json_db_aggr_procinfo_arr, GY_ARRAY_SIZE(json_db_aggr_procinfo_arr));
	pextprocstate_aggr_arr[nextprocstate_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_GID, json_db_aggr_procinfo_arr, GY_ARRAY_SIZE(json_db_aggr_procinfo_arr));
	pextprocstate_aggr_arr[nextprocstate_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_CPUTHR, json_db_aggr_procinfo_arr, GY_ARRAY_SIZE(json_db_aggr_procinfo_arr));
	pextprocstate_aggr_arr[nextprocstate_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_MEMLIM, json_db_aggr_procinfo_arr, GY_ARRAY_SIZE(json_db_aggr_procinfo_arr));
	pextprocstate_aggr_arr[nextprocstate_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_TSTART, json_db_aggr_procinfo_arr, GY_ARRAY_SIZE(json_db_aggr_procinfo_arr));
	pextprocstate_aggr_arr[nextprocstate_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_P95CPUPCT, json_db_aggr_procinfo_arr, GY_ARRAY_SIZE(json_db_aggr_procinfo_arr));
	pextprocstate_aggr_arr[nextprocstate_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_P95CPUDEL, json_db_aggr_procinfo_arr, GY_ARRAY_SIZE(json_db_aggr_procinfo_arr));
	pextprocstate_aggr_arr[nextprocstate_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_P95IODEL, json_db_aggr_procinfo_arr, GY_ARRAY_SIZE(json_db_aggr_procinfo_arr));
	pextprocstate_aggr_arr[nextprocstate_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_CGCPULIMPCT, json_db_aggr_procinfo_arr, GY_ARRAY_SIZE(json_db_aggr_procinfo_arr));
	pextprocstate_aggr_arr[nextprocstate_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_CGRSSPCT, json_db_aggr_procinfo_arr, GY_ARRAY_SIZE(json_db_aggr_procinfo_arr));
	pextprocstate_aggr_arr[nextprocstate_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_REGION, json_db_aggr_procinfo_arr, GY_ARRAY_SIZE(json_db_aggr_procinfo_arr));
	pextprocstate_aggr_arr[nextprocstate_aggr_arr++] = *get_jsoncrc_mapping_or_throw(FIELD_ZONE, json_db_aggr_procinfo_arr, GY_ARRAY_SIZE(json_db_aggr_procinfo_arr));

	ASSERT_OR_THROW(nextprocstate_aggr_arr < MAX_COLUMN_LIST, "Internal Error : Number of columns of extended procstate aggregates %u exceeds max allowed %lu", 
				nextprocstate_aggr_arr, MAX_COLUMN_LIST);

	for (uint32_t i = 0; i < nextprocstate_aggr_arr; ++i) {
		pextprocstate_aggr_arr[i].subsys	= SUBSYS_EXTPROCSTATE;
	}	

	DB_AGGR_INFO			*pextprocstate_aggr_info	= new DB_AGGR_INFO[GY_ARRAY_SIZE(procstate_aggr_info) + GY_ARRAY_SIZE(procinfo_aggr_info)];

	std::memcpy(pextprocstate_aggr_info, procstate_aggr_info, GY_ARRAY_SIZE(procstate_aggr_info) * sizeof(*procstate_aggr_info));
	nextprocstate_aggr_info = GY_ARRAY_SIZE(procstate_aggr_info);
	
	pextprocstate_aggr_info[nextprocstate_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_RELSVCID, procinfo_aggr_info, GY_ARRAY_SIZE(procinfo_aggr_info));
	pextprocstate_aggr_info[nextprocstate_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_CMDLINE, procinfo_aggr_info, GY_ARRAY_SIZE(procinfo_aggr_info));
	pextprocstate_aggr_info[nextprocstate_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_TAG, procinfo_aggr_info, GY_ARRAY_SIZE(procinfo_aggr_info));
	pextprocstate_aggr_info[nextprocstate_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_UID, procinfo_aggr_info, GY_ARRAY_SIZE(procinfo_aggr_info));
	pextprocstate_aggr_info[nextprocstate_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_GID, procinfo_aggr_info, GY_ARRAY_SIZE(procinfo_aggr_info));
	pextprocstate_aggr_info[nextprocstate_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_CPUTHR, procinfo_aggr_info, GY_ARRAY_SIZE(procinfo_aggr_info));
	pextprocstate_aggr_info[nextprocstate_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_MEMLIM, procinfo_aggr_info, GY_ARRAY_SIZE(procinfo_aggr_info));
	pextprocstate_aggr_info[nextprocstate_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_TSTART, procinfo_aggr_info, GY_ARRAY_SIZE(procinfo_aggr_info));
	pextprocstate_aggr_info[nextprocstate_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_P95CPUPCT, procinfo_aggr_info, GY_ARRAY_SIZE(procinfo_aggr_info));
	pextprocstate_aggr_info[nextprocstate_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_P95CPUDEL, procinfo_aggr_info, GY_ARRAY_SIZE(procinfo_aggr_info));
	pextprocstate_aggr_info[nextprocstate_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_P95IODEL, procinfo_aggr_info, GY_ARRAY_SIZE(procinfo_aggr_info));
	pextprocstate_aggr_info[nextprocstate_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_CGCPULIMPCT, procinfo_aggr_info, GY_ARRAY_SIZE(procinfo_aggr_info));
	pextprocstate_aggr_info[nextprocstate_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_CGRSSPCT, procinfo_aggr_info, GY_ARRAY_SIZE(procinfo_aggr_info));
	pextprocstate_aggr_info[nextprocstate_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_REGION, procinfo_aggr_info, GY_ARRAY_SIZE(procinfo_aggr_info));
	pextprocstate_aggr_info[nextprocstate_aggr_info++] = *get_jsoncrc_mapping_or_throw(FIELD_ZONE, procinfo_aggr_info, GY_ARRAY_SIZE(procinfo_aggr_info));

	ASSERT_OR_THROW(nextprocstate_aggr_info < MAX_COLUMN_LIST, "Internal Error : Number of columns of extended procstate aggregate info %u exceeds max allowed %lu", 
				nextprocstate_aggr_info, MAX_COLUMN_LIST);

	// Now update subsys_aggr_list
	subsys_aggr_list[SUBSYS_EXTPROCSTATE].pajsonmap 	= pextprocstate_aggr_arr;
	subsys_aggr_list[SUBSYS_EXTPROCSTATE].szajsonmap 	= nextprocstate_aggr_arr;

	subsys_aggr_list[SUBSYS_EXTPROCSTATE].paggrinfo 	= pextprocstate_aggr_info;
	subsys_aggr_list[SUBSYS_EXTPROCSTATE].szaggrinfo 	= nextprocstate_aggr_info;

}

#undef GYSLEN

} // namespace gyeeta
