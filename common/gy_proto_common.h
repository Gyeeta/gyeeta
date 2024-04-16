//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"

namespace gyeeta {

static constexpr uint32_t			MAX_PARSE_API_LEN	{16 * 1024};	
static constexpr uint32_t			DFLT_MAX_API_LEN	{4096};
static constexpr uint32_t			MAX_PARSE_EXT_LEN	{1400};	

enum PROTO_TYPES : uint16_t 
{
	PROTO_UNINIT				= 0,

	PROTO_HTTP1,
	PROTO_HTTP2,
	PROTO_POSTGRES,
	PROTO_MYSQL,
	PROTO_MONGO,
	PROTO_REDIS,

	PROTO_INVALID,
};	

static constexpr const char 			*proto_type_str[PROTO_INVALID + 1] = 
{
		"Uninitialized", "HTTP1", "HTTP2", "Postgres", "MySQL", "Mongo", "Redis", 
		"Invalid",
};	


static constexpr const char * proto_to_string(PROTO_TYPES proto) noexcept
{
	if ((unsigned)proto < PROTO_INVALID) {
		return proto_type_str[proto];
	}	

	return proto_type_str[PROTO_INVALID];
}	

static PROTO_TYPES string_to_proto(const char *str) noexcept
{
	for (int i = 0; i < (int)PROTO_INVALID; ++i) {
		if (0 == strcasecmp(proto_type_str[i], str)) {
			return (PROTO_TYPES)i;
		}	
	}

	return PROTO_INVALID;
};	

enum PROTO_CAP_STATUS_E : uint8_t
{
	CAPSTAT_UNINIT			= 0,
	CAPSTAT_FAILED,
	CAPSTAT_STARTING,		// Do not change the order...
	CAPSTAT_ACTIVE,

	CAPSTAT_MAX,
};	

static constexpr const char			*cap_status_str[CAPSTAT_MAX] = 
{
	"Uninitialized", "Failed", "Starting", "Active",
};	

static constexpr const char * cap_status_to_string(PROTO_CAP_STATUS_E status) noexcept
{
	if ((unsigned)status < CAPSTAT_MAX) {
		return cap_status_str[status];
	}	

	return "Invalid";
}	

static PROTO_CAP_STATUS_E string_to_cap_status(const char *str) noexcept
{
	for (int i = 0; i < (int)CAPSTAT_MAX; ++i) {
		if (0 == strcasecmp(cap_status_str[i], str)) {
			return (PROTO_CAP_STATUS_E)i;
		}	
	}

	return CAPSTAT_MAX;
};	

enum PARSE_FIELD_E : uint16_t
{
	EFIELD_NONE		= 0,

	EFIELD_APPNAME,		/* AppName : Data Type char* */
	EFIELD_USERNAME,	/* UserName : Data Type char* */
	EFIELD_DBNAME,		/* DBName : Data Type char* */
	EFIELD_ERRTXT,		/* Error Text : Data Type char* */
	EFIELD_ERRCLASS,	/* Error Class : Data Type uint16_t */
	EFIELD_SESSID,		/* DB Session ID : Data Type uint32_t */
	EFIELD_PREP_REQNUM,	/* DB Prepare SQL reqnum_ : Data Type uint64_t */
	EFIELD_PREP_REQTIME,	/* DB Prepare SQL treq : Data Type time_t */
	EFIELD_HOSTPID,		/* DB Process ID : Data Type uint32_t */
	EFIELD_NROWS,		/* Number of rows returned : Data Type uint32_t */
	EFIELD_CURSORNAME,	/* DB Cursor Name : Data Type char* */
	EFIELD_STATUSCODE,	/* Status Code (e.g. HTTP) : Data Type int */

	EFIELD_MAX,
};	

static constexpr const char			*parse_field_str[EFIELD_MAX] =
{
	"", "appname", "username", "dbname", "errtxt", "errclass", "sessid", "prep_reqnum", "prep_reqtime", "hostpid",
	"nrows", "cursorname", "statuscode",
};	


/*
 * NOTE : There is no padding added and direct dereference is not to be done...
 */
struct PARSE_FIELD_LEN
{
	PARSE_FIELD_E				field_		{EFIELD_NONE};
	uint16_t				len_		{0};

	/*uint8_t				field_[len_] follows;*/		// No padding done

	PARSE_FIELD_LEN() noexcept		= default;

	PARSE_FIELD_LEN(PARSE_FIELD_E field, uint16_t len) noexcept
		: field_(field), len_(len)
	{}	
};	


struct API_TRAN
{
	uint64_t				treq_usec_		{0};		/* Time of Request Start */	
	uint64_t				tres_usec_		{0};		/* Time of Response Start */	
	uint64_t				tupd_usec_		{0};		/* last in/out data timestamp for processing */

	uint64_t				reqlen_			{0};		/* Total Bytes In for Request */
	uint64_t				reslen_			{0};		/* Total Bytes Out for Request */
	uint64_t				reqnum_			{0};		/* Session Request Counter from 1 onwards */
	uint64_t				response_usec_		{0};		/* Response Time in usec */
	uint64_t				reaction_usec_		{0};		/* Reaction Time in usec */
	uint64_t				tconnect_usec_		{0};		/* Session Connect Time */

	GY_IP_ADDR				cliip_;
	GY_IP_ADDR				serip_;
	uint64_t				glob_id_		{0};
	uint64_t				conn_id_		{0};		/* Connection Identifier */
	char					comm_[TASK_COMM_LEN]	{};
	
	int					errorcode_		{0};
	uint32_t				app_sleep_ms_		{0};		/* Delay between a request and preceding response */
	uint32_t				tran_type_		{0};
	
	PROTO_TYPES				proto_			{PROTO_UNINIT};
	uint16_t				cliport_		{0};
	uint16_t				serport_		{0};

	// Succeeding Payload info
	uint16_t				request_len_		{0};		/* Request Length (includes '\0' byte) : Directly follows after this struct */

	// Length of extra data following the Reqstring : 1 byte (next_fields_) + next_fields_ * sizeof(PARSE_FIELD_LENs) + data 
	uint16_t				lenext_			{0};		

	uint8_t					padlen_			{0};		/* Pad to 8 bytes */

	/*char					request_[request_len_] follows;*/
	/*uint8_t				ext_[lenext_] follows;*/
	/*char					padding_[padding_len_]; follows to make the entire 8 byte aligned */

	static constexpr size_t			MAX_NUM_REQS 		{256};		// Send in batches
	static constexpr size_t			MAX_SEND_SZ 		{512 * 1024};	// Approx Max sz to send to Madhava per call

	API_TRAN() noexcept			= default;

	API_TRAN(uint64_t tlastpkt_usec, uint64_t tconnect_usec, const IP_PORT & cli_ipport, const IP_PORT & ser_ipport, uint64_t glob_id, PROTO_TYPES proto, const char *comm) noexcept
		: treq_usec_(tlastpkt_usec), tupd_usec_(treq_usec_), tconnect_usec_(tconnect_usec),
		cliip_(cli_ipport.ipaddr_), serip_(ser_ipport.ipaddr_), glob_id_(glob_id), conn_id_(get_connid_hash(cli_ipport, ser_ipport, glob_id)),
		proto_(proto), cliport_(cli_ipport.port_), serport_(ser_ipport.port_)
	{
		if (comm) {
			GY_STRNCPY(comm_, comm, sizeof(comm_));
		}	
	}

	~API_TRAN() noexcept			= default;

	// Returns the Request string len and ext fields len and padding
	uint32_t get_elem_size() const noexcept
	{
		return get_act_len() + padlen_;
	}	

	// Includes sizeof(*this)
	uint32_t get_act_len() const noexcept
	{
		return sizeof(*this) + request_len_ + lenext_;
	}	

	void set_padding_len() noexcept
	{
		size_t 			currsz, newsz;

		currsz = get_act_len();
		newsz = gy_align_up_2(currsz, 8);

		padlen_			= newsz - currsz;
	}

	uint8_t get_pad_len() const noexcept
	{
		return padlen_;
	}	

	// Currently we skip connect time in hash as the timestamp of packet will differ from the timestamp reported by ebpf
	static uint64_t get_connid_hash(const IP_PORT & cli_ipport, const IP_PORT & ser_ipport, uint64_t glob_id) noexcept
	{
		BIN_BUFFER<2 * sizeof(GY_IP_ADDR) + 2 * sizeof(uint16_t) + sizeof(uint64_t)>	hbuf;

		hbuf << cli_ipport.ipaddr_ << ser_ipport.ipaddr_ << cli_ipport.port_ << ser_ipport.port_ << glob_id;

		return gy_cityhash64((const char *)hbuf.buffer(), hbuf.size());
	}

	static inline uint32_t get_max_elem_size(uint32_t api_max_len) noexcept
	{
		return sizeof(API_TRAN) + api_max_len + MAX_PARSE_EXT_LEN + 32;
	}	

	static constexpr size_t get_max_actual_send_size() noexcept
	{
		// 1 struct over MAX_SEND_SZ along with comm headers
		return MAX_SEND_SZ + MAX_PARSE_API_LEN + MAX_PARSE_EXT_LEN + sizeof(API_TRAN) + 512;
	}	

	/* Reset request specific fields : Will not change session related fields */
	void reset() noexcept
	{
		tres_usec_			= 0;
		tupd_usec_			= 0;
		reqlen_				= 0;
		reslen_				= 0;
		reqnum_				= 0;
		response_usec_			= 0;
		reaction_usec_			= 0;
		errorcode_			= 0;
		app_sleep_ms_			= 0;
		tran_type_			= 0;
		request_len_			= 0;
		lenext_				= 0;
		padlen_				= 0;
	}	

	void update_req_stats(uint64_t tlastpkt_usec, uint32_t datalen) noexcept
	{
		tupd_usec_		= tlastpkt_usec;
		reqlen_			+= datalen;
	}	

	void update_resp_stats(uint64_t tlastpkt_usec, uint32_t datalen) noexcept
	{
		tupd_usec_		= tlastpkt_usec;

		if (tres_usec_ == 0) {
			tres_usec_	= tlastpkt_usec;
		}

		reslen_			+= datalen;
	}	

	void set_resp_times() noexcept
	{
		response_usec_ 	= tupd_usec_ - treq_usec_;
		reaction_usec_	= tres_usec_ - treq_usec_;
	}	

};	

static constexpr uint32_t			MAX_PARSE_TOT_EXT_LEN	{MAX_PARSE_EXT_LEN + sizeof(API_TRAN)};
static constexpr uint32_t			MAX_PARSE_TRAN_SZ	{MAX_PARSE_API_LEN + MAX_PARSE_TOT_EXT_LEN + 1 + 7};
static constexpr uint32_t			MAX_TRAN_STR_ELEM	{25000};

static constexpr uint16_t			MAX_USER_DB_LEN		{128};

// Returns number of bytes copied. Will return 0 on truncation. Also updates tran with the tdstrbuf and ustrbuf lens
static size_t copy_tran_data(uint8_t *pdest, uint32_t maxsz, API_TRAN & tran, const STR_WR_BUF & tdstrbuf, const STR_WR_BIN & ustrbuf) noexcept
{
	size_t				tlen = sizeof(API_TRAN) + tdstrbuf.size() + 1 + ustrbuf.size();

	if (!pdest || maxsz < tlen || tdstrbuf.size() == 0) {
		return 0;
	}	

	tran.request_len_		= tdstrbuf.size() + 1;
	tran.lenext_			= ustrbuf.size();

	std::memcpy(pdest, &tran, sizeof(API_TRAN));

	std::memcpy(pdest + sizeof(API_TRAN), tdstrbuf.buffer(), tdstrbuf.size());
	pdest[sizeof(API_TRAN) + tdstrbuf.size()] = 0;
	
	std::memcpy(pdest + sizeof(API_TRAN) + tran.request_len_, ustrbuf.buffer(), tran.lenext_);

	return tlen;
}	

struct PARSE_EXT_FIELDS
{
	std::string_view		appname_		{"", 0};
	std::string_view		username_		{"", 0};
	std::string_view		dbname_			{"", 0};
	std::string_view		errtxt_			{"", 0};
	uint16_t			errclass_		{0};
	uint32_t			sessid_			{0};
	uint64_t			dyn_prep_reqnum_	{0};
	time_t				dyn_prep_time_t_	{0};
	uint32_t			hostpid_		{0};
	uint32_t			nrows_			{0};
	std::string_view		cursorname_		{"", 0};
	int				statuscode_		{0};

	PARSE_EXT_FIELDS() noexcept	= default;

	PARSE_EXT_FIELDS(const uint8_t *pext, uint32_t lenext) noexcept
	{
		get_fields(pext, lenext);
	}	

	int get_fields(const uint8_t *pext, uint32_t lenext) noexcept
	{
		if (lenext <= 1) return 0;

		STR_RD_BIN			ustr(pext, lenext);
		uint8_t				nfl;

		ustr >> nfl;

		for (int i = 0; i < (int)nfl; ++i) {
			PARSE_FIELD_LEN			fl;

			if (ustr.bytes_left() >= sizeof(PARSE_FIELD_LEN)) {
				ustr >> fl;
			}
			else {
				return i;
			}	
			
			switch (fl.field_) {
			
			case EFIELD_APPNAME :
				if (ustr.bytes_left() >= fl.len_) {
					appname_ = std::string_view((const char *)ustr.get_curr_pos(), fl.len_ > 1 ? fl.len_ - 1 : 0);
					ustr += fl.len_;
				}
				else {
					return i;
				}	
				break;

			case EFIELD_USERNAME :
				if (ustr.bytes_left() >= fl.len_) {
					username_ = std::string_view((const char *)ustr.get_curr_pos(), fl.len_ > 1 ? fl.len_ - 1 : 0);
					ustr += fl.len_;
				}
				else {
					return i;
				}	
				break;

			case EFIELD_DBNAME :
				if (ustr.bytes_left() >= fl.len_) {
					dbname_ = std::string_view((const char *)ustr.get_curr_pos(), fl.len_ > 1 ? fl.len_ - 1 : 0);
					ustr += fl.len_;
				}
				else {
					return i;
				}	
				break;

			case EFIELD_ERRTXT :
				if (ustr.bytes_left() >= fl.len_) {
					errtxt_ = std::string_view((const char *)ustr.get_curr_pos(), fl.len_ > 1 ? fl.len_ - 1 : 0);
					ustr += fl.len_;
				}
				else {
					return i;
				}	
				break;

			case EFIELD_ERRCLASS :
				ustr >> errclass_;
				break;

			case EFIELD_SESSID :
				ustr >> sessid_;
				break;

			case EFIELD_PREP_REQNUM :
				ustr >> dyn_prep_reqnum_;
				break;

			case EFIELD_PREP_REQTIME :
				ustr >> dyn_prep_time_t_;
				break;

			case EFIELD_HOSTPID :
				ustr >> hostpid_;
				break;

			case EFIELD_NROWS :
				ustr >> nrows_;
				break;

			case EFIELD_CURSORNAME :
				if (ustr.bytes_left() >= fl.len_) {
					cursorname_ = std::string_view((const char *)ustr.get_curr_pos(), fl.len_ > 1 ? fl.len_ - 1 : 0);
					ustr += fl.len_;
				}
				else {
					return i;
				}	
				break;

			case EFIELD_STATUSCODE :
				ustr >> statuscode_;
				break;

			default :
				return i;
			}	
		}

		return nfl;
	}	
};	

// Returns the Request string view and populates the PARSE_EXT_FIELDS
static std::string_view get_api_tran(const API_TRAN *ptran, PARSE_EXT_FIELDS & extfields) noexcept
{
	const char			*preq = (const char *)(ptran + 1);

	if (ptran->request_len_ <= 1) {
		return {};
	}

	extfields.get_fields((uint8_t *)ptran + sizeof(*ptran) + ptran->request_len_, ptran->lenext_);

	return {preq, (size_t)ptran->request_len_ - 1};
}	


} // namespace gyeeta

