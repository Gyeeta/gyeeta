
#pragma				once

#include			"gy_common_inc.h"
#include			"gy_alerts.h"
#include			"gy_shconnhdlr.h"
#include 			"gy_rcu_inc.h"
#include			"gy_misc.h"
#include			"gy_pool_alloc.h"
#include			"gy_postgres.h"
#include			"gy_json_field_maps.h"
#include			"gy_comm_proto.h"
#include			"gy_refcnt.h"

#include			<list>

#include			"boost/container/small_vector.hpp"
#include			"boost/intrusive_ptr.hpp"

#pragma 			GCC diagnostic push
#pragma 			GCC diagnostic ignored "-Wsign-compare"

#include			"folly/MPMCQueue.h"
#include 			"folly/container/F14Map.h"

#pragma 			GCC diagnostic pop

using 				gyeeta::intrusive_ptr_add_ref;
using 				gyeeta::intrusive_ptr_release;
using 				boost::intrusive_ptr;

namespace gyeeta {
namespace shyama {

template <typename T, size_t numinline = 3>
using SmallVec				= boost::container::small_vector<T, numinline>;

class AlertStatFilter;
class ALERT_STATS;
class ALERTDEF;
class ADEF_ACTION;
struct AlertRollStats;

using AlertstatsVec			= SmallVec<intrusive_ptr<ALERT_STATS>, 4>;
using AActionVec			= SmallVec<intrusive_ptr<ADEF_ACTION>, 2>;


enum AL_ACTION_E : uint16_t
{
	ACTION_NULL		= 0,
	ACTION_EMAIL,
	ACTION_SLACK,
	ACTION_PAGERDUTY,
	ACTION_WEBHOOK,

	ACTION_MAX
};	

/*
 * Ensure that the strings output are JSON escaped
 */
static constexpr std::pair<const char *, uint32_t> action_to_stringlen(AL_ACTION_E action) noexcept
{
	switch (action) {
	
	case ACTION_NULL 	:	return { "null", GY_CONST_STRLEN("null") };
	case ACTION_EMAIL 	:	return { "email", GY_CONST_STRLEN("email") };
	case ACTION_SLACK 	:	return { "slack", GY_CONST_STRLEN("slack") };
	case ACTION_PAGERDUTY	:	return { "pagerduty", GY_CONST_STRLEN("pagerduty") };
	case ACTION_WEBHOOK 	:	return { "webhook", GY_CONST_STRLEN("webhook") };

	default			: 	return { "unknown", GY_CONST_STRLEN("unknown") };		
	}	
}

static AL_ACTION_E string_to_action(const char *acttype, bool throw_on_err = true)
{
	if (0 == strcasecmp(acttype, "null")) {
		return ACTION_NULL;
	}	
	else if (0 == strcasecmp(acttype, "email")) {
		return ACTION_EMAIL;
	}	
	else if (0 == strcasecmp(acttype, "slack")) {
		return ACTION_SLACK;
	}	
	else if (0 == strcasecmp(acttype, "pagerduty")) {
		return ACTION_PAGERDUTY;
	}	
	else if (0 == strcasecmp(acttype, "webhook")) {
		return ACTION_WEBHOOK;
	}	
	else {
		if (throw_on_err) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Alert Action : action type specified \'%s\' not supported", acttype);
		}

		return ACTION_MAX;
	}	
}

class ALERT_ACTION : public INT_REF_CNT<gy_noatomic>
{
public :
	SSO_STRING<32>			name_;
	std::string			config_;
	time_t				tcreate_			{0};
	uint32_t			actionid_			{0};
	uint32_t			configid_			{0};		// Hash of config_
	AL_ACTION_E			acttype_			{ACTION_NULL};
	bool				send_resolved_			{false};
	gy_atomic<bool>			is_deleted_			{false};

	static constexpr size_t		MAX_ACTIONS			{1024};

	ALERT_ACTION(const GEN_JSON_VALUE & jval, uint32_t actionid = 0, time_t tcreate = time(nullptr));

	ALERT_ACTION() noexcept						= default;

	ALERT_ACTION(const ALERT_ACTION & other)			= default;
	ALERT_ACTION(ALERT_ACTION && other)	noexcept		= default;
	ALERT_ACTION & operator= (const ALERT_ACTION & other) 		= default;
	ALERT_ACTION & operator= (ALERT_ACTION && other) noexcept	= default;

	~ALERT_ACTION() noexcept					= default;

	void set_new_config(const GEN_JSON_VALUE & jval, time_t tcreate);

	void set_deleted() noexcept
	{
		is_deleted_.store(true, mo_relaxed);
	}

	bool is_deleted() const noexcept
	{
		return is_deleted_.load(mo_relaxed);
	}	

	const char *name() const noexcept
	{
		return name_.c_str();
	}

	friend bool operator== (const intrusive_ptr<ALERT_ACTION> & actshr, uint32_t id) noexcept
	{
		return bool(actshr) && actshr->actionid_ == id;
	}	

	static void verify_null_config(const GEN_JSON_VALUE & jval, STACK_JSON_WRITER<4096, 2048> & writer, bool is_override, time_t tcreate = 0);
	static void verify_email_config(const GEN_JSON_VALUE & jval, STACK_JSON_WRITER<4096, 2048> & writer, bool is_override, time_t tcreate = 0);
	static void verify_slack_config(const GEN_JSON_VALUE & jval, STACK_JSON_WRITER<4096, 2048> & writer, bool is_override, time_t tcreate = 0);
	static void verify_pagerduty_config(const GEN_JSON_VALUE & jval, STACK_JSON_WRITER<4096, 2048> & writer, bool is_override, time_t tcreate = 0);
	static void verify_webhook_config(const GEN_JSON_VALUE & jval, STACK_JSON_WRITER<4096, 2048> & writer, bool is_override, time_t tcreate = 0);
};	

class ADEF_ACTION : public INT_REF_CNT<gy_noatomic>
{
public :
	intrusive_ptr<ALERT_ACTION>	actionshr_;
	std::string			newconfig_;
	CRITERIA_SET			match_;
	bool				send_resolved_		{false};
	bool				continue_		{true};

	ADEF_ACTION(const intrusive_ptr<ALERT_ACTION> & actionshr, const GEN_JSON_VALUE * pjval, SUBSYS_CLASS_E asubsys, const char *subsys_str, \
				const JSON_DB_MAPPING **pcolmap, uint32_t nmap_fields, bool is_multihost, bool is_last_elem);

	ADEF_ACTION() noexcept		= default;

	bool to_string(STR_WR_BUF & strbuf) const noexcept;
};	

struct TIME_HHMM : public GY_PAIR<uint8_t>
{};

struct TIME_HHMM_RANGE
{
	TIME_HHMM		start;
	TIME_HHMM		end;

	TIME_HHMM_RANGE(TIME_HHMM start, TIME_HHMM end) noexcept
		: start(start), end(end)
	{}

	TIME_HHMM_RANGE() noexcept	= default;

	bool in_range(const struct tm & tm) const noexcept
	{
		uint8_t			hour = tm.tm_hour, min = tm.tm_min;

		if (start.first > hour) {
			return false;
		}	
		else if (start.first == hour) {
			if (start.second > min) return false;
		}	

		if (end.first < hour) {
			return false;
		}
		else if (end.first == hour) {
			if (end.second < min) return false;
		}

		return true;
	}	

};

struct DATE_MMDD : public GY_PAIR<uint8_t>
{};

struct DATE_MMDD_RANGE
{
	DATE_MMDD		start;
	DATE_MMDD		end;

	DATE_MMDD_RANGE(DATE_MMDD start, DATE_MMDD end) noexcept
		: start(start), end(end)
	{}

	DATE_MMDD_RANGE() noexcept	= default;

	bool in_range(const struct tm & tm) const noexcept
	{
		uint8_t			mon = tm.tm_mon + 1, day = tm.tm_mday;

		if (start.first > mon) {
			return false;
		}	
		else if (start.first == mon) {
			if (start.second > day) return false;
		}	

		if (end.first < mon) {
			return false;
		}
		else if (end.first == mon) {
			if (end.second < day) return false;
		}

		return true;
	}	
};

class MUTE_ONE
{
public :
	SmallVec<DATE_MMDD_RANGE, 3>	daterange_;
	std::bitset<31>			dayofmonth_		{~0u};
	std::bitset<12>			months_			{0xFFF};
	std::bitset<7>			dayofweek_		{0xFF};
	SmallVec<TIME_HHMM_RANGE, 3>	timerange_;
	int				tzoffset_		{0};

	MUTE_ONE(const GEN_JSON_VALUE & jval);

	bool is_mmdd() const noexcept
	{
		return !!daterange_.size();
	}	

	bool is_timerange() const noexcept
	{
		return !!timerange_.size();
	}	

	bool is_utc() const noexcept
	{
		return !tzoffset_;
	}	

	bool in_range(const struct tm & tm, time_t tcurr) const;

	std::pair<bool, bool> in_same_range(const struct tm & tm1, time_t tcurr1, const struct tm & tm2, time_t tcurr2) const;
};	

class MUTE_TIMES
{
public :
	SmallVec<MUTE_ONE, 2>		mutevec_;
	time_t				tmutestart_		{0};
	time_t				tmuteend_		{0};

	MUTE_TIMES() 			= default;

	MUTE_TIMES(const GEN_JSON_VALUE & jval);

	bool in_range(const struct tm & tm, time_t tcurr) noexcept;

	bool in_range(const struct tm & tm1, time_t tcurr1, const struct tm & tm2, time_t tcurr2) noexcept;

	bool is_mute_time(time_t tcurr) const noexcept
	{
		return (tcurr <= tmuteend_ and tcurr >= tmutestart_);
	}	
};	

class ALERT_SILENCE
{
public :
	MUTE_TIMES			mutetimes_;
	CRITERIA_SET			match_;
	time_t				tcreate_		{0};
	time_t				tend_sec_		{0};
	std::string			name_;
	uint32_t			silid_			{0};
	bool				is_disabled_		{false};

	static constexpr size_t		MAX_SILENCES		{1024};

	ALERT_SILENCE()			= default;

	ALERT_SILENCE(const GEN_JSON_VALUE & jval, uint32_t silid = 0, time_t tcreate = time(nullptr), bool is_disabled = false);

	void disable() noexcept
	{
		is_disabled_ = true;
	}

	void enable() noexcept
	{
		is_disabled_ = false;
	}

	bool is_disabled() const noexcept
	{
		return is_disabled_;
	}	

	bool is_alert_silenced(const AlertStatFilter & filter, time_t tcurr) const;
};	

class ALERT_INHIBIT
{
public :
	struct SrcStats
	{
		intrusive_ptr<ALERT_STATS>	pstat_;
		std::vector<std::string>	cols_;

		SrcStats(ALERT_STATS *pstat) noexcept
			: pstat_(pstat)
		{}	
	};	

	using SrcStatsList		= std::list<SrcStats>;
	using EqualColVec		= std::vector<const JSON_DB_MAPPING *>;

	CRITERIA_SET			src_match_;
	CRITERIA_SET			target_match_;
	EqualColVec			equal_cols_;	
	SrcStatsList			srcstatslist_;

	time_t				tcreate_		{0};
	std::string			name_;
	uint32_t			inhid_			{0};
	bool				is_disabled_		{false};

	static constexpr size_t		MAX_INHIBITS		{1024};
	static constexpr size_t		MAX_SRC_ASTATS		{128};

	ALERT_INHIBIT()			= default;

	ALERT_INHIBIT(const GEN_JSON_VALUE & jval, uint32_t inhid = 0, time_t tcreate = time(nullptr), bool is_disabled = false);

	void disable() noexcept
	{
		is_disabled_ = true;
	}

	void enable() noexcept
	{
		is_disabled_ = false;
	}

	bool is_disabled() const noexcept
	{
		return is_disabled_;
	}

	std::pair<bool, bool> is_alert_inhibited(const AlertStatFilter & filter);
};	



enum ADEF_SEVERITY_E : uint8_t
{
	ASEVERITY_DEBUG			= 0,
	ASEVERITY_INFO,
	ASEVERITY_WARNING,
	ASEVERITY_CRITICAL,

	ASEVERITY_UNKNOWN,
};	

extern ADEF_SEVERITY_E severity_from_string(const char *pstr) noexcept;

static std::pair<const char *, uint32_t> severity_to_stringlen(ADEF_SEVERITY_E severity) noexcept
{
	switch (severity) {
	
	case ASEVERITY_DEBUG 		:	return {"debug", GY_CONST_STRLEN("debug")};
	case ASEVERITY_INFO	 	:	return {"info", GY_CONST_STRLEN("info")};
	case ASEVERITY_WARNING 		:	return {"warning", GY_CONST_STRLEN("warning")};
	case ASEVERITY_CRITICAL 	:	return {"critical", GY_CONST_STRLEN("critical")};

	default				: 	return {"unknown", GY_CONST_STRLEN("unknown")};		
	}	
}

class ALERT_SEVERITY
{
public :
	class DynSeverity
	{
	public :
		CRITERIA_SET		match_;
		ADEF_SEVERITY_E		severity_		{ASEVERITY_INFO};

		DynSeverity(ADEF_SEVERITY_E severity, const char *dynstr, uint32_t szstr, SUBSYS_CLASS_E asubsys, const char *subsys_str, \
						const JSON_DB_MAPPING **pcolmap, uint32_t nmap_fields, bool is_multihost = true)
			: 
			match_(dynstr, szstr, asubsys, subsys_str, pcolmap, nmap_fields, nullptr /* pextpool */, is_multihost, true /* allocregex */), 
			severity_(severity)
		{}	

		DynSeverity(ADEF_SEVERITY_E fallback) noexcept 
			: severity_(fallback)
		{}	

		DynSeverity() noexcept		= default;

		bool is_fallback() const noexcept
		{
			return !match_.has_filter_criteria();
		}	
	};	

	std::vector<DynSeverity>	dynvec_;
	ADEF_SEVERITY_E			fseverity_;
	
	ALERT_SEVERITY(ADEF_SEVERITY_E severity = ASEVERITY_INFO) noexcept
		: fseverity_(severity)
	{}

	ALERT_SEVERITY(const GEN_JSON_VALUE & jdoc, SUBSYS_CLASS_E asubsys, const char *subsys_str, const JSON_DB_MAPPING **pcolmap, uint32_t nmap_fields, bool is_multihost = true);

	bool is_fixed_severity() const noexcept
	{
		return dynvec_.empty();
	}	

	ADEF_SEVERITY_E get_severity(const AlertStatFilter & filter) const;
};	

class ALERT_GROUPBY
{
public :
	using GroupbyCols		= SmallVec<const JSON_DB_MAPPING *, 3>;

	GroupbyCols			groups_;
	
	ALERT_GROUPBY(const GEN_JSON_VALUE & jdoc, SUBSYS_CLASS_E asubsys, const char *subsys_str, const JSON_DB_MAPPING **pcolmap, uint32_t nmap_fields);

	ALERT_GROUPBY() noexcept	= default;

	// Returns false if no grouping is to be done
	bool get_group_str(const AlertStatFilter & filter, STR_WR_BUF & strbuf) const;

	bool is_grouped() const noexcept
	{
		return !!groups_.size();
	}	
};	

class ALERT_TMPL_STRING
{
public :
	struct Offsets
	{
		const JSON_DB_MAPPING	*pcol_		{nullptr};
		uint16_t		start_		{0};
		uint16_t		end_		{0};

		Offsets(const JSON_DB_MAPPING *pcol, uint16_t start, uint16_t end) noexcept
			: pcol_(pcol), start_(start), end_(end)
		{}

		Offsets() noexcept	= default;
	};

	std::unique_ptr<char[]>		str_;
	SmallVec<Offsets, 1>		toffsets_;
	uint32_t			lenstr_		{0};

	ALERT_TMPL_STRING(const char *pstr, uint32_t sz, const JSON_DB_MAPPING **pcolmap, uint32_t nmap_fields);	

	bool has_template() const noexcept
	{
		return !!toffsets_.size();
	}	

	void set_string(STR_WR_BUF & strbuf, const AlertStatFilter & filter) const;
};	


class ALERT_ANNOTATIONS
{
public :
	SmallVec<ALERT_TMPL_STRING, 1>	annotvec_;

	ALERT_ANNOTATIONS(const GEN_JSON_VALUE & jdoc, const JSON_DB_MAPPING **pcolmap, uint32_t nmap_fields);

	ALERT_ANNOTATIONS() noexcept	= default;

	STRING_BUFFER<8192> get_annotations(const AlertStatFilter & filter) const;
};	


class ALERTDEF : public INT_REF_CNT<gy_noatomic>, public ALERTDEF_COMMON
{
public :
	ALERT_SEVERITY			severity_;
	ALERT_ANNOTATIONS		annotations_;
	AActionVec			action_;
	std::unique_ptr<MUTE_TIMES>	pmute_;
	std::string			labels_;
	std::string			defstr_;
	ALERT_GROUPBY			groupby_;
	time_t				tinit_			{0};
	time_t				tcreate_		{0};
	bool				is_deleted_		{false};

	static constexpr size_t		MAX_DEF_ACTIONS		{8};

	ALERTDEF(GEN_JSON_VALUE & jdoc, JSON_ALLOCATOR & allocator,  const char *pdefstr, uint32_t szdef, uint32_t adefid = 0, time_t tcurr = time(nullptr), \
						time_t tcreate = time(nullptr), bool is_disabled = false);

	bool is_grouped() const noexcept
	{
		return groupby_.is_grouped();
	}	

	void set_deleted() noexcept
	{
		is_deleted_ = true;	
	}	

	bool is_deleted() const noexcept
	{
		return is_deleted_;
	}

	bool is_init_from_db() const noexcept
	{
		return tcreate_ < tinit_ && tcreate_ > 0;
	}	

	AActionVec get_actions(const AlertStatFilter & filter, STR_WR_BUF & actstrbuf) const;

	void check_actions() noexcept;
};	


enum AGROUP_STATE_E : uint8_t
{
	AGROUP_IDLE			= 0,
	AGROUP_WAIT,
};

class ALERT_GROUP : public INT_REF_CNT<gy_noatomic>
{
public :
	uint64_t			groupid_		{0};
	time_t				tstart_			{0};
	uint64_t			tnextchkusec_		{0};			// Acts as the key to the atimemap_

	AlertstatsVec			statvec_;
	uint32_t			groupwaitsec_		{0};
	AGROUP_STATE_E			state_			{AGROUP_IDLE};
	bool				is_deleted_		{false};

	ALERT_GROUP(uint64_t groupid, uint32_t grp_waitsec, time_t tcurr);

	void set_deleted() noexcept
	{
		is_deleted_		= true;	
	}	

	bool is_deleted() const noexcept
	{
		return is_deleted_;
	}
};	

/*
 * Do not change the order of the enums below
 */
enum ALERT_STATE_E : uint8_t
{
	ASTATE_GROUP_WAIT		=	0,
	ASTATE_SUPPRESSED,		// By Silencing/Inhibition
	ASTATE_ACTIVE,			// Fired
	ASTATE_ACKED,
	ASTATE_RESOLVED,
	ASTATE_EXPIRED,

	ASTATE_UNKNOWN,
};	

extern ALERT_STATE_E astate_from_string(const char *pstr, uint32_t len) noexcept;

static std::pair<const char *, uint32_t> astate_to_stringlen(ALERT_STATE_E astate) noexcept
{
	switch (astate) {
	
	case ASTATE_GROUP_WAIT 		:	return {"groupwait", GY_CONST_STRLEN("groupwait")};
	case ASTATE_SUPPRESSED		:	return {"suppressed", GY_CONST_STRLEN("suppressed")};
	case ASTATE_ACTIVE		:	return {"active", GY_CONST_STRLEN("active")};
	case ASTATE_ACKED		:	return {"acked", GY_CONST_STRLEN("acked")};
	case ASTATE_RESOLVED		:	return {"resolved", GY_CONST_STRLEN("resolved")};
	case ASTATE_EXPIRED		:	return {"expired", GY_CONST_STRLEN("expired")};

	case ASTATE_UNKNOWN		: 	
	default				:
						return {"unknown", GY_CONST_STRLEN("unknown")};		

	}	
}

class ALERT_STATS : public INT_REF_CNT<gy_noatomic>
{
public :
	time_t				tstart_			{0};
	time_t				tforce_close_		{0};
	time_t				trepeat_alert_		{0};
	time_t				taction_		{0};
	time_t				tclose_			{0};

	uint64_t			groupid_		{0};
	intrusive_ptr<ALERT_GROUP>	pgroup_;
	intrusive_ptr<ALERTDEF>		pdef_;

	comm::ALERT_STAT_INFO		info_;
	std::shared_ptr<std::string>	palertdata_;

	AActionVec			actionvec_;
	SmallVec<uint32_t, 4>		src_inhib_vec_;

	std::unique_ptr<char []>	annotstr_;
	std::unique_ptr<char []>	actionstr_;
	uint32_t			lenannot_		{0};
	uint32_t			lenaction_		{0};
	
	ALERT_STATE_E			state_			{ASTATE_GROUP_WAIT};
	ADEF_SEVERITY_E			fseverity_		{ASEVERITY_INFO};
	uint8_t				nacks_			{0};
	bool				is_deleted_		{false};
	bool				is_force_close_		{false};

	ALERT_STATS(comm::ALERT_STAT_INFO & info, intrusive_ptr<ALERTDEF> pdef);

	uint32_t get_alertid() const noexcept
	{
		return info_.alertid_;
	}

	void set_deleted() noexcept
	{
		is_deleted_		= true;	
	}	

	bool is_deleted() const noexcept
	{
		return is_deleted_;
	}

	void clear_strings() noexcept
	{
		pgroup_.reset();
		palertdata_.reset();
		annotstr_.reset();
		actionstr_.reset();
		lenannot_ = 0;
		lenaction_ = 0;
	}	

	STRING_BUFFER<512> print_string() const noexcept;

	friend class AlertStatFilter;
};

class AlertStatFilter
{
public :
	ALERT_STATS			& astat;
	const GEN_JSON_VALUE		*pjdoc_			{nullptr};
	std::string_view		annotview_;	
	std::string_view		actionview_;
	time_t				tcurr_			{0};

	AlertStatFilter(ALERT_STATS & astat, const GEN_JSON_VALUE & jdoc, time_t tcurr) noexcept
		: astat(astat), pjdoc_(&jdoc), tcurr_(tcurr)
	{}

	// Called by Group Handler for individual Alerts
	AlertStatFilter(ALERT_STATS & astat, time_t tcurr) noexcept
		: astat(astat), tcurr_(tcurr)
	{
		if (astat.lenannot_ && bool(astat.annotstr_)) {
			set_annot_view(astat.annotstr_.get(), astat.lenannot_);
		}	

		if (astat.lenaction_ && bool(astat.actionstr_)) {
			set_action_view(astat.actionstr_.get(), astat.lenaction_);
		}	
	}

	const ALERT_STATS & get_alert_stat() const noexcept
	{
		return astat;
	}

	void set_annot_view(const char *str, size_t sz) noexcept
	{
		annotview_ = std::string_view(str, sz);
	}	

	void set_action_view(const char *str, size_t sz) noexcept
	{
		actionview_ = std::string_view(str, sz);
	}	

	NUMBER_CRITERION astat_num_field(const JSON_DB_MAPPING *pfield) const;

	std::pair<const char *, uint32_t> astat_str_field(const JSON_DB_MAPPING *pfield, char * tbuf, size_t szbuf, bool *pisvalid = nullptr) const;
	
	BOOL_CRITERION astat_bool_field(const JSON_DB_MAPPING *pfield) const;

	bool astat_field_to_string(const JSON_DB_MAPPING *pfield, STR_WR_BUF & strbuf) const;

	CRIT_RET_E filter_match(const CRITERIA_SET & criteria) const;

	void get_alerts_json(STR_WR_BUF & strbuf, bool ign_alertdata, bool ign_nulls) const;
};	


// Blocking sockets used by Action Handler
class NODE_ACTION_SOCK
{
public :
	int				sock_			{-1};
	uint32_t			nodeid_			{0};
	time_t				tlast_			{0};
	time_t				tlast_recv_		{0};
	size_t				nact_sent_		{0};
	time_t				tstart_			{0};
	CHAR_BUF<MAX_DOMAINNAME_SIZE>	desc_;

	NODE_ACTION_SOCK() noexcept	= default;

	NODE_ACTION_SOCK(int sock, uint32_t nodeid, const char *desc, uint32_t lendesc, time_t tcurr) noexcept
		: sock_(sock), nodeid_(nodeid), tlast_(tcurr), tstart_(tcurr), desc_(desc, lendesc)
	{}

	void reset() noexcept
	{
		sock_ 		= -1;
		nodeid_		= 0;
		tlast_		= 0;
		tlast_recv_	= 0;
		nact_sent_ 	= 0;
		tstart_		= 0;
	}

	void close_conn(bool graceful_close = true) noexcept;

	bool is_valid() const noexcept
	{
		return sock_ >= 0;
	}	

	int get_sock() const noexcept
	{
		return sock_;
	}	
};	

struct ACT_MSG final
{
	enum ActType : uint8_t
	{
		ANewAlert		= 0,
		ACloseAlert,
		ANodeRegister,
	};

	std::unique_ptr<char []>	conf_json_;
	uint32_t			lenconf_				{0};
	uint16_t			nalerts_				{0};	
	ActType				atype_					{ANewAlert};
	SCOPE_FD			sockfd_;				// Only used by ANodeRegister
	std::unique_ptr<char []>	alertstrarr_[MAX_ONE_ACTION_ALERTS];
	uint32_t			lenalertstr_[MAX_ONE_ACTION_ALERTS]	{};	
	std::shared_ptr<std::string>	alertdataarr_[MAX_ONE_ACTION_ALERTS];

	// If set to more than 15, need to split call to gy_writev()
	static_assert(MAX_ONE_ACTION_ALERTS < 16, "Please ensure that the max is limited to 15");

	ACT_MSG() noexcept		= default;

	// For ANodeRegister
	ACT_MSG(SCOPE_FD && sockfd, uint8_t *pregbuf, uint32_t lenbuf)
		: conf_json_(std::make_unique<char []>(lenbuf)), lenconf_(lenbuf), atype_(ANodeRegister), sockfd_(std::move(sockfd))
	{
		std::memcpy(conf_json_.get(), pregbuf, lenbuf);
	}	
};	



class ACTION_HDLR
{
public :
	static constexpr size_t		MAX_NODE_CONNS			{16};
	static constexpr size_t		MAX_SOCKS_PER_NODE		{2};

	using ACTIONQ			= folly::MPMCQueue<ACT_MSG>;

	ACTIONQ				aqueue_				{2 * MAX_TOTAL_ALERTS_PER_MIN};

	NODE_ACTION_SOCK		nodearr_[MAX_NODE_CONNS];
	uint16_t			ntotalconns_			{0};
	uint16_t			ntotalprocs_			{0};
	uint32_t			last_node_version_		{0};

	time_t				tdescprint_			{0};

	size_t				nsent_				{0};
	size_t				nfailed_			{0};
	size_t				nnoconns_			{0};
	size_t				npoolblocks_			{0};
	size_t				nstrbufovf_			{0};

	size_t				lastnsent_			{0};
	size_t				lastnfailed_			{0};
	size_t				lastnnoconns_			{0};
	size_t				lastnpoolblocks_		{0};
	size_t				lastnstrbufovf_			{0};

	NODE_ACTION_SOCK * get_action_conn(time_t tcurr, int16_t events, int timeoutmsec = 5000);
	
	void send_alert(ACT_MSG && amsg, time_t tcurr) noexcept;

	void node_register(ACT_MSG && amsg, time_t tcurr) noexcept;

	void check_node_recv(time_t tcurr) noexcept;

	void print_stats(int64_t tsec, time_t tcurr) noexcept;

	uint16_t count_conns() noexcept
	{
		uint16_t		nconns = 0;

		for (uint32_t i = 0; i < MAX_NODE_CONNS; ++i) {
			nconns += (nodearr_[i].sock_ >= 0);
		}

		ntotalconns_ = nconns;

		ntotalprocs_ = ntotalconns_/2;

		return nconns;
	}	
};	

struct ADB_MSG final
{
	enum MsgType : uint8_t
	{
		MsgNew			= 0,
		MsgResolved,
		MsgExpired,
		MsgAck,
	};

	time_t				talert_						{0};
	const char			*parambufs_[GY_ARRAY_SIZE(json_db_alerts_arr)]	{};
	std::string			alertstr_;
	std::shared_ptr<std::string>	palertdata_;
	time_t				tupdate_					{0};		// Not used for MsgNew
	uint32_t			alertid_					{0};
	MsgType				mtype_						{MsgNew};

	ADB_MSG() noexcept		= default;

	ADB_MSG(time_t talert, time_t tupdate, uint32_t alertid, MsgType mtype, std::string && alertstr = {}) noexcept
		: talert_(talert), alertstr_(std::move(alertstr)), tupdate_(tupdate), alertid_(alertid), mtype_(mtype)
	{}

};	

class ALERT_DB_HDLR
{
public :
	static constexpr size_t		NUM_DB_CONNS			{2};

	using ALERTDBQ			= folly::MPMCQueue<ADB_MSG>;
	
	ALERTDBQ			aqueue_				{2 * MAX_TOTAL_ALERTS_PER_MIN};
	PGConnPool			dbpool_;

	size_t				nnew_				{0};
	size_t				nresolved_			{0};
	size_t				nexpired_			{0};
	size_t				nack_				{0};
	size_t				npoolblocks_			{0};
	size_t				nstrbufovf_			{0};
	
	size_t				lastnnew_			{0};
	size_t				lastnresolved_			{0};
	size_t				lastnexpired_			{0};
	size_t				lastnack_			{0};
	size_t				lastnpoolblocks_		{0};
	size_t				lastnstrbufovf_			{0};

	ALERT_DB_HDLR(const char *dbhost, uint16_t dbport, const char *user, const char *passwd, const char *dbname)
		: dbpool_("Alertmgr Alert Writer", NUM_DB_CONNS, dbhost, dbport, user, passwd, dbname, 
				"dbalertwriter", get_db_init_commands().get(), true /* auto_reconnect */, 12, 10, 10)
	{}	

	bool db_new_alert_stat(ADB_MSG & amsg) noexcept;

	bool db_upd_alert_stat(ADB_MSG & amsg) noexcept;

	void print_stats(int64_t tsec) noexcept;
};	

class SA_SETTINGS_C;
class SHCONN_HANDLER;

/*
 * We use 1 Action Handler thread and 1 DB Alert thread. 
 */
class ALERTMGR
{
public :
	enum class ACmd : uint8_t
	{
		CmdNull		= 0,

		CmdCheckADef,
		CmdCheckSilence,
		CmdAlertStatCheck,
		CmdAlertGroupCheck,
		CmdConnReset,
		CmdAlertStats,

		CmdGroupSendAlerts,
	};	
	
	struct CmdParam
	{
		intrusive_ptr<ALERT_GROUP>	pgroup_;
		uint32_t			repeat_sec_	{0};
		ACmd				cmd_		{ACmd::CmdNull};

		CmdParam(ACmd cmd, uint32_t repeat_sec) noexcept
			: repeat_sec_(repeat_sec), cmd_(cmd)
		{}

		CmdParam(intrusive_ptr<ALERT_GROUP> pgroup, ACmd cmd, uint32_t repeat_sec = 0) noexcept
			: pgroup_(std::move(pgroup)), repeat_sec_(repeat_sec), cmd_(cmd)
		{}	
	};	
	
	using ATimeMap			= std::multimap<uint64_t, CmdParam>;

	using InhibitMap		= std::unordered_map<uint32_t, std::unique_ptr<ALERT_INHIBIT>, GY_JHASHER<uint32_t>>;
	using SilenceMap		= std::unordered_map<uint32_t, std::unique_ptr<ALERT_SILENCE>, GY_JHASHER<uint32_t>>;
	using ActionMap			= std::unordered_map<uint32_t, intrusive_ptr<ALERT_ACTION>, GY_JHASHER<uint32_t>>;
	using AlertdefMap		= std::unordered_map<uint32_t, intrusive_ptr<ALERTDEF>, GY_JHASHER<uint32_t>>;
	using AGroupMap			= folly::F14ValueMap<uint64_t, intrusive_ptr<ALERT_GROUP>, GY_JHASHER<uint64_t>>;
	using AStatMap			= folly::F14ValueMap<uint32_t, intrusive_ptr<ALERT_STATS>, GY_JHASHER<uint32_t>>;

	
	uint64_t			cusec_init_;
	time_t				tinit_			{time(nullptr)};

	PGConnPool			dbmgrpool_;

	InhibitMap			inhibitmap_;
	SilenceMap			silencemap_;
	ActionMap			actionmap_;
	AlertdefMap			adefmap_;
	AGroupMap			agroupmap_;
	AStatMap			astatmap_;

	ATimeMap			atimemap_;
	bool				multierase_		{false};
	time_t				tnextdefping_		{tinit_ + 600};
	time_t				tleastalert_		{tinit_};

	time_t				tmin_start_		{0};
	time_t				thour_start_		{0};
	uint32_t			nalerts_min_		{0};
	uint32_t			nalerts_hour_		{0};
	
	time_t				tdisable_end_		{0};
	uint64_t			silencechk_usec_	{0};
	time_t				tany_silence_end_	{0};

	uint64_t			nalerts_		{0};
	uint64_t			ninvalid_alerts_	{0};
	uint64_t			nalerts_skipped_	{0};
	uint64_t			nalerts_silenced_	{0};
	uint64_t			nalerts_inhib_		{0};

	std::unique_ptr<AlertRollStats>	rollstats_;
	
	ACTION_HDLR			acthdlr_;
	ALERT_DB_HDLR			dbhdlr_;
	pthread_t			thrid_			{};
	GY_THREAD			act_thr_;
	GY_THREAD			db_thr_;

	static constexpr size_t		NUM_DB_CONNS		{2};

	ALERTMGR(SA_SETTINGS_C & settings, SHCONN_HANDLER *pconnhdlr);

	time_t min_active_alert_time() const noexcept
	{
		return tleastalert_;
	}	

	uint32_t get_action_conn_count() const noexcept
	{
		return GY_READ_ONCE(acthdlr_.ntotalconns_);
	}	

	uint32_t get_action_proc_count() const noexcept
	{
		return GY_READ_ONCE(acthdlr_.ntotalprocs_);
	}	

	uint32_t get_action_node_version() const noexcept
	{
		return acthdlr_.last_node_version_;
	}	

	int alert_act_thread() noexcept;
	int alert_db_thread() noexcept;
	
	MAKE_CLASS_FUNC_WRAPPER_NO_ARG(ALERTMGR, alert_act_thread);
	MAKE_CLASS_FUNC_WRAPPER_NO_ARG(ALERTMGR, alert_db_thread);

	// Called under SHCONN_HANDLER Accept thread context (sock is non-blocking) (Will close sock on errors)
	void add_node_action_sock(int sock, uint8_t *pregbuf, uint32_t lenbuf) noexcept;

	void read_db_alert_info();

	void read_db_inhibits();
	void read_db_silences();
	void read_db_actions();
	void read_db_alert_defs();

	void set_cfg_inhibits(const char *pfilename, const char *pcfg, size_t lencfg);
	void set_cfg_silences(const char *pfilename, const char *pcfg, size_t lencfg);
	void set_cfg_actions(const char *pfilename, const char *pcfg, size_t lencfg);
	void set_cfg_alertdefs(const char *pfilename, const char *pcfg, size_t lencfg);

	void check_schedules(time_t & tnext) noexcept;
	
	void check_silences_active() noexcept;
	std::pair<uint32_t, bool> is_alert_silenced(const AlertStatFilter & filter) const;
	std::pair<uint32_t, bool> is_alert_inhibited(const AlertStatFilter & filter) const;

	bool check_set_alerts_allowed(time_t tcurr, const char *pdefname);
	void set_alerts_disabled(time_t tcurr, int64_t disable_sec);

	bool send_shyama_all_alertdefs() noexcept;
	void check_adef_status() noexcept;
	void check_alert_stats() noexcept;
	void check_agroup_status() noexcept;
	void update_alert_stats();
	
	// Returns {day_alerts_, day_silenced_, day_inhib_}
	std::tuple<uint32_t, uint32_t, uint32_t> get_alert_day_stats() const noexcept;

	bool add_alert_stat(comm::ALERT_STAT_INFO & stat, time_t tcurr, uint64_t currtusec, const char *srcstr);
	void set_astat_group(const intrusive_ptr<ALERT_STATS> & pstatint, const intrusive_ptr<ALERTDEF> & pdefintr, const AlertStatFilter & filter, time_t tcurr, uint64_t currtusec);
	bool cleanup_alert_stat(uint32_t alertid, ALERT_STATS & astat, time_t tclose, bool is_close, bool is_force_close) noexcept;
	bool erase_group_timemap(const ALERT_GROUP *pgroup, uint64_t keyusec);
	void handle_alert_stat_info(const char *srcstr, comm::ALERT_STAT_INFO *pstat, int nevents, uint8_t *pendptr);

	void send_alert_now(const intrusive_ptr<ALERT_STATS> & pstatint, const AlertStatFilter & filter, time_t tcurr);
	bool send_multi_action_msg(const intrusive_ptr<ALERT_STATS> *pstatarr, uint32_t nstats, time_t tcurr, const AlertStatFilter *pfilterarr = nullptr);
	bool send_msg_to_dbhdlr(ADB_MSG && dbmsg);
	bool send_close_action_msg(ALERT_STATS &astat, bool is_force_close);
	bool send_alert_to_dbhdlr(const AlertStatFilter & filter);
	void agroup_send_alerts(ALERT_GROUP & group);

	void handle_alert_stat_close(const char *srcstr, comm::ALERT_STAT_CLOSE *pstat, int nevents, uint8_t *pendptr);
	void handle_node_alert_stat_update(const std::shared_ptr<SHCONN_HANDLER::SHCONNTRACK> & connshr, GEN_JSON_VALUE & jdoc, comm::QUERY_CMD *pquery, time_t tcurr);

	void handle_crud_cmd(const std::shared_ptr<SHCONN_HANDLER::SHCONNTRACK> & connshr, comm::QUERY_CMD *pquery, char *pjson, char *pendptr);

	void handle_node_alertdef_add(const std::shared_ptr<SHCONN_HANDLER::SHCONNTRACK> & connshr, GEN_JSON_VALUE & jdoc, JSON_ALLOCATOR & allocator, comm::QUERY_CMD *pquery);
	void handle_node_alertdef_delete(const std::shared_ptr<SHCONN_HANDLER::SHCONNTRACK> & connshr, GEN_JSON_VALUE & jdoc, comm::QUERY_CMD *pquery);
	void handle_node_alertdef_update(const std::shared_ptr<SHCONN_HANDLER::SHCONNTRACK> & connshr, GEN_JSON_VALUE & jdoc, comm::QUERY_CMD *pquery);

	void handle_node_inhibits_add(const std::shared_ptr<SHCONN_HANDLER::SHCONNTRACK> & connshr, GEN_JSON_VALUE & jdoc, comm::QUERY_CMD *pquery);
	void handle_node_inhibits_delete(const std::shared_ptr<SHCONN_HANDLER::SHCONNTRACK> & connshr, GEN_JSON_VALUE & jdoc, comm::QUERY_CMD *pquery);
	void handle_node_inhibits_update(const std::shared_ptr<SHCONN_HANDLER::SHCONNTRACK> & connshr, GEN_JSON_VALUE & jdoc, comm::QUERY_CMD *pquery);

	void handle_node_silences_add(const std::shared_ptr<SHCONN_HANDLER::SHCONNTRACK> & connshr, GEN_JSON_VALUE & jdoc, comm::QUERY_CMD *pquery);
	void handle_node_silences_delete(const std::shared_ptr<SHCONN_HANDLER::SHCONNTRACK> & connshr, GEN_JSON_VALUE & jdoc, comm::QUERY_CMD *pquery);
	void handle_node_silences_update(const std::shared_ptr<SHCONN_HANDLER::SHCONNTRACK> & connshr, GEN_JSON_VALUE & jdoc, comm::QUERY_CMD *pquery);

	void handle_node_actions_add(const std::shared_ptr<SHCONN_HANDLER::SHCONNTRACK> & connshr, GEN_JSON_VALUE & jdoc, comm::QUERY_CMD *pquery);
	void handle_node_actions_delete(const std::shared_ptr<SHCONN_HANDLER::SHCONNTRACK> & connshr, GEN_JSON_VALUE & jdoc, comm::QUERY_CMD *pquery);
	void handle_node_actions_update(const std::shared_ptr<SHCONN_HANDLER::SHCONNTRACK> & connshr, GEN_JSON_VALUE & jdoc, comm::QUERY_CMD *pquery);
	
	std::tuple<ERR_CODES_E, uint32_t, const ALERTDEF *> add_alertdef(uint32_t adefid, GEN_JSON_VALUE & jdoc, JSON_ALLOCATOR & allocator, const char *pjson, size_t szjson, \
					STR_WR_BUF & strbuf, time_t tcurr, time_t tcreate, bool is_disabled = false) noexcept;
	bool db_insert_alertdef(uint32_t adefid, const char *name, time_t tcreate, const char *pjson, uint32_t szjson, bool is_disabled);

	std::tuple<ERR_CODES_E, uint32_t, AL_ACTION_E, const char *> add_action(uint32_t actionid, GEN_JSON_VALUE & jdoc, STR_WR_BUF & strbuf, time_t tcurr, time_t tcreate) noexcept;
	bool db_insert_update_action(uint32_t actionid, const char *name, AL_ACTION_E acttype, time_t tcreate, const char *pjson, uint32_t szjson);
	
	std::tuple<ERR_CODES_E, uint32_t, const char *> add_inhibit(uint32_t inhid, GEN_JSON_VALUE & jdoc, STR_WR_BUF & strbuf, \
					time_t tcurr, time_t tcreate, bool is_disabled = false) noexcept;
	bool db_insert_inhibit(uint32_t inhid, const char *name, time_t tcreate, const char *pjson, uint32_t szjson);

	std::tuple<ERR_CODES_E, uint32_t, const char *> add_silence(uint32_t silid, GEN_JSON_VALUE & jdoc, STR_WR_BUF & strbuf, \
					time_t tcurr, time_t tcreate, bool is_disabled = false) noexcept;
	bool db_insert_silence(uint32_t silid, const char *name, time_t tcreate, const char *pjson, uint32_t szjson);

	bool db_update_alertdef(uint32_t *pdefidarr, uint32_t ndefs, ALERT_MSG_TYPE newstate);
	bool db_update_inhibit(uint32_t inhid, bool is_deleted, bool is_disabled);
	bool db_update_silence(uint32_t *psilidarr, uint32_t nid, bool is_deleted, bool is_disabled);
	bool db_delete_action(uint32_t actionid);

	static ALERTMGR	* get_singleton() noexcept;
};	

} // namespace shyama
} // namespace gyeeta

