
#pragma				once

#include			"gy_common_inc.h"
#include			"gy_query_common.h"
#include			"gy_atomic.h"
#include 			"gy_json_field_maps.h"
#include 			"gy_comm_proto.h"
#include 			"gy_print_offload.h"
#include			"gy_rapidjson.h"

namespace gyeeta {

static constexpr size_t		MAX_ALERT_DEFS				{1000};			// Includes disabled alert defs
static constexpr size_t		MAX_ONE_ALERT_ROWS			{128};			// Max Alert Rows per DB Query 
static constexpr size_t		MAX_ONE_ACTION_ALERTS			{7};			// Max Grouped Alerts per Action Payload (e.g. Max Grouped Alerts within 1 email)

static constexpr size_t		MAX_TOTAL_ALERTS_PER_MIN		{3000};			// All Alerts will be muted for 3 min thereafter
static constexpr size_t		MAX_TOTAL_ALERTS_PER_HOUR		{30'000};		// All Alerts will be muted for 30 min thereafter
static constexpr size_t		MAX_UNRESOLVED_ALERTS			{200'000};		// Will ignore newer alerts once this is crossed till alerts get resolved

static constexpr int64_t	MAX_ALERT_NUM_CHECK_FOR			{60};	

static constexpr int64_t	MAX_ALERT_QUERY_PERIOD_SEC		{7 * 3600 * 24};	// 1 week	

static constexpr int64_t	MIN_ALERT_QUERY_INTERVAL_SEC		{60};
static constexpr int64_t	DFLT_ALERT_QUERY_INTERVAL_SEC		{60};

static constexpr int64_t	MIN_ALERT_REPEAT_INTERVAL_SEC		{900};
static constexpr int64_t	DFLT_ALERT_REPEAT_INTERVAL_SEC		{2 * 3600};		

static constexpr int64_t	MIN_ALERT_FORCE_CLOSE_SEC		{30 * 60};	
static constexpr int64_t	MAX_ALERT_FORCE_CLOSE_SEC		{3600 * 24};		// 24 hours
static constexpr int64_t	DFLT_ALERT_FORCE_CLOSE_SEC		{10 * 3600};		

static constexpr int64_t	MAX_GROUP_WAIT_SEC			{600};
static constexpr int64_t	DFLT_GROUP_WAIT_SEC			{30};

static constexpr size_t		MAX_ALERT_NAME_LEN			{512};

class ALERTDEF_COMMON
{
public :	
	std::unique_ptr<char []>		colstr_;		// Keep this the first elem as other fields will use the mem allocated 

	SSO_STRING<32>				name_;
	
	time_t					tstart_sec_		{0};
	time_t					tend_sec_		{0};

	uint32_t				adef_id_		{0};

	gy_atomic<ADEF_STATE_E>			state_			{ADEFSTATE_ENABLED};

	ADEF_HDLR_E				ahdlr_			{AHDLR_PARTHA};
	ALERT_KEY_TYPE_E			akeytype_		{AKEY_ID};

	SUBSYS_CLASS_E				asubsys_		{SUBSYS_HOST};
	const char				*pasubsys_		{""};


	std::unique_ptr<QUERY_OPTIONS>		rtqrtopt_;				// For Realtime Alerts only : Will contain actual criteria along with host filters if any
	bool					isrealtime_		{false};
	bool					rt_host_filter_		{false};
	bool					is_multi_host_		{false};

	std::unique_ptr<char []>		dbquery_;				// For DB Query Alerts only : Will contain the host filters as well if any
	const JSON_DB_MAPPING *			keyid_col_		{nullptr};
	uint16_t				keyid_colnum_		{0};
	uint16_t				ncols_			{0};
	JSON_DB_MAPPING				*pcolarr_		{nullptr};	// For DB Query Alerts only
	const JSON_DB_MAPPING			**pconstcolarr_		{nullptr};
	uint32_t				dbquery_len_		{0};

	bool					manual_resolve_		{false};

	uint16_t				numcheckfor_		{1};
	uint16_t				subsys_inter_sec_	{0};
	uint32_t				query_period_sec_	{0};

	uint32_t				query_interval_sec_	{DFLT_ALERT_QUERY_INTERVAL_SEC};
	uint32_t				repeataftersec_		{DFLT_ALERT_REPEAT_INTERVAL_SEC};
	uint32_t				forceclosesec_		{DFLT_ALERT_FORCE_CLOSE_SEC};
	uint32_t				groupwaitsec_		{DFLT_GROUP_WAIT_SEC};

	static constexpr time_t			tplaceholderstart_	{9999998999};
	static constexpr time_t			tplaceholderend_	{9999999999};
	static constexpr const char		*partplaceholder_	{"_99991234"};

	ALERTDEF_COMMON(GEN_JSON_VALUE & jdoc, JSON_ALLOCATOR & allocator, uint32_t adef_id = 0, time_t tcurr = time(nullptr));

	ALERTDEF_COMMON(const ALERTDEF_COMMON &)			= delete;
	ALERTDEF_COMMON & operator=(const ALERTDEF_COMMON &)		= delete;

	ALERTDEF_COMMON(ALERTDEF_COMMON &&) noexcept			= default;
	ALERTDEF_COMMON & operator=(ALERTDEF_COMMON &&) noexcept	= default;

	~ALERTDEF_COMMON() noexcept					= default;

	QUERY_OPTIONS * get_rt_options() const noexcept
	{
		return rtqrtopt_.get();
	}

	bool get_db_query(STR_WR_BUF & strbuf, time_t tstart, time_t end) noexcept;

	void set_aggr_query(QUERY_OPTIONS & qryopt);
	
	bool is_enabled() const noexcept
	{
		return state_.load(mo_relaxed) == ADEFSTATE_ENABLED;
	}	

	void set_state(ADEF_STATE_E state) noexcept
	{
		state_.store(state, mo_relaxed);
	}	

	bool is_muted_state() const noexcept
	{
		auto		state = state_.load(mo_relaxed);

		switch (state) {
		
		case ADEFSTATE_MUTED :
		case ADEFSTATE_INHIBITED :
		case ADEFSTATE_SILENCED :
			return true;

		default :
			return false;
		}	
	}	

	bool is_manual_resolve() const noexcept
	{
		return manual_resolve_;
	}

	bool is_realtime() const noexcept
	{
		return isrealtime_;
	}	

	bool is_repeat_disabled() const noexcept
	{
		return repeataftersec_ == 0;
	}

	bool has_rt_host_filter() const noexcept
	{
		return rt_host_filter_;
	}	

	const char * name() const noexcept
	{
		return name_.c_str();
	}

	uint32_t get_defid() const noexcept
	{
		return adef_id_;
	}

	bool is_db_defid_key() const noexcept
	{
		return pcolarr_ && nullptr == keyid_col_;
	}

	bool is_madhava_handled() const noexcept
	{
		return ahdlr_ == AHDLR_MADHAVA;
	}	

	bool is_shyama_handled() const noexcept
	{
		return ahdlr_ == AHDLR_SHYAMA;
	}	

	bool is_partha_handled() const noexcept
	{
		return ahdlr_ == AHDLR_PARTHA;
	}	

	bool is_valid_column(uint32_t jsoncrc) const noexcept
	{
		if (pconstcolarr_) {
			for (uint32_t i = 0; i < ncols_; ++i) {
				if (pconstcolarr_[i]->jsoncrc == jsoncrc) {
					return true;
				}
			}	

			return false;
		}

		return true;
	}

	uint64_t get_nextcheck_tusec(uint64_t currtusec, uint8_t curr_numhits) const noexcept;

	std::pair<const JSON_DB_MAPPING * const *, size_t> get_column_list() const noexcept
	{
		return {pconstcolarr_, ncols_};
	}	
	
	friend bool operator==(const ALERTDEF_COMMON & adef, uint32_t adef_id) noexcept
	{
		return adef.adef_id_ == adef_id;
	}	

private :
	void create_queryopt_obj(GEN_JSON_VALUE & jdoc, JSON_ALLOCATOR & allocator);

};	

struct ALERT_STAT_HASH
{
	GY_MACHINE_ID			machid_;
	uint64_t			id_			{0};
	uint64_t			madhava_id_		{0};
	uint32_t			adef_id_		{0};
	uint32_t			time_			{0};		

	ALERT_STAT_HASH(const GY_MACHINE_ID & machid, uint64_t id, uint32_t adef_id, uint64_t madhava_id, time_t tstart) noexcept
		: machid_(machid), id_(id), madhava_id_(madhava_id), adef_id_(adef_id), time_(uint32_t(tstart))
	{}

	uint32_t get_hash() noexcept
	{
		return jhash2(reinterpret_cast<const uint32_t *>(this), sizeof(*this)/sizeof(uint32_t), 0xceedfead);
	}	
};	

extern ALERT_KEY_TYPE_E get_subsys_key_type(SUBSYS_CLASS_E asubsys, const char *pasubsys = "", const char *pname = "");

extern ADEF_HDLR_E get_subsys_handler(SUBSYS_CLASS_E asubsys, const char *pasubsys = "", const char *pname = "");

extern std::pair<const JSON_DB_MAPPING *, uint16_t> get_aggr_subsys_keyid(SUBSYS_CLASS_E asubsys, const JSON_DB_MAPPING *acolarr, uint32_t ncols) noexcept;

static uint32_t get_adef_id(const char *name, size_t namelen) noexcept
{
	return gy_cityhash32(name, namelen);
}	

} // namespace gyeeta

