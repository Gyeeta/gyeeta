//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"
#include			"gy_alerts.h"
#include			"gy_sys_hardware.h"
#include 			"gy_rcu_inc.h"
#include			"gy_misc.h"
#include			"gy_pool_alloc.h"
#include			"gy_postgres.h"
#include			"gy_json_field_maps.h"
#include			"gy_comm_proto.h"

#include 			<variant>

#pragma 			GCC diagnostic push
#pragma 			GCC diagnostic ignored "-Wsign-compare"

#include			"folly/MPMCQueue.h"

#pragma 			GCC diagnostic pop


namespace gyeeta {
namespace madhava {

class MCONN_HANDLER;
class MRT_ALERTDEF;
class MRT_ADEF_ELEM;
class MDB_ALERTDEF;
class MDB_ALERT_STATS;
class MALERT_HDLR;
struct MALERT_MSG;

enum MALERT_STATE_E : uint8_t
{
	MALERT_PENDING		= 0, 		/* In numcheckfor condition */
	MALERT_FIRED,				/* Waiting for Resolution */
};	

class MRT_ALERT_STATS
{
public :	
	RCU_HASH_CLASS_MEMBERS(uint64_t, MRT_ALERT_STATS);

	time_t				tstart_			{0};
	gy_atomic<time_t>		tlast_hit_		{tstart_};
	gy_atomic<time_t>		tlast_alert_		{0};
	gy_atomic<time_t>		trepeat_alert_		{0};
	time_t				tforce_close_		{0};
	time_t				tmsg_sent_		{0};
	time_t				tlast_validate_		{tstart_ + 60};

	GY_MACHINE_ID			machid_;
	uint64_t			id_			{0};

	MRT_ADEF_ELEM			*pdefelem_		{nullptr};		// Must be accessed only under RCU Lock
	uint64_t			tnextchkusec_		{0};			// Acts as the key to the atimemap_

	uint32_t			adef_id_		{0};
	uint32_t			alertid_		{0};

	uint16_t			subsys_inter_sec_	{0};
	uint16_t			multi_iter_chk_sec_	{0};
	SUBSYS_CLASS_E			asubsys_		{SUBSYS_HOST};
	gy_atomic<uint8_t>		numhits_		{1};
	uint8_t				numcheckfor_		{0};
	uint8_t				nrepeats_		{0};
	gy_atomic<MALERT_STATE_E>	state_			{MALERT_PENDING};

	MRT_ALERT_STATS(uint64_t id, MRT_ADEF_ELEM *pdefelem, MRT_ALERTDEF *pdef, time_t tcurr, uint8_t numcheckfor, MALERT_STATE_E state, SUBSYS_CLASS_E asubsys, const GY_MACHINE_ID machid) noexcept;

	MRT_ALERT_STATS(const GY_MACHINE_ID machid, MRT_ADEF_ELEM *pdefelem, MRT_ALERTDEF *pdef, time_t tcurr, uint8_t numcheckfor, MALERT_STATE_E state, SUBSYS_CLASS_E asubsys) noexcept;

	MRT_ALERT_STATS(const MRT_ALERT_STATS &)		= delete;
	
	MRT_ALERT_STATS & operator= (const MRT_ALERT_STATS &)	= delete;

	~MRT_ALERT_STATS() noexcept
	{
		tstart_		= 0;
		pdefelem_ 	= nullptr;
	}

	bool is_deleted() const noexcept
	{
		return tstart_ == 0 || pdefelem_ == nullptr;
	}

	bool del_from_def_table_locked(MRT_ALERTDEF *pdef = nullptr);

	static void operator delete(void * ptr) noexcept
	{
		THR_POOL_ALLOC::dealloc(ptr);
	}

	static inline int rcu_match_machid(struct cds_lfht_node *pht_node, const void *pkey) noexcept	
	{											
		const MRT_ALERT_STATS		*pactdata = GY_CONTAINER_OF(pht_node, MRT_ALERT_STATS, cds_node_);
		const GY_MACHINE_ID		*pkeydata = static_cast<decltype(pkeydata)>(pkey);	
											
		return *pactdata == *pkeydata;
	}			

	friend bool operator== (const MRT_ALERT_STATS & astats, uint64_t id) noexcept
	{
		return astats.id_ == id;
	}	

	friend bool operator== (const MRT_ALERT_STATS & astats, const GY_MACHINE_ID machid) noexcept
	{
		return astats.machid_ == machid;
	}	
};	

using MRT_ALERT_ID_TBL			= RCU_HASH_TABLE <uint64_t, MRT_ALERT_STATS>;
using MRT_ALERT_MACHID_TBL		= RCU_HASH_TABLE <GY_MACHINE_ID, MRT_ALERT_STATS, std::default_delete<MRT_ALERT_STATS>, MRT_ALERT_STATS::rcu_match_machid>;


class MRT_ALERTDEF : public ALERTDEF_COMMON
{
public :	
	using ALERT_TBL_VAR			= std::variant<std::monostate, MRT_ALERT_ID_TBL, MRT_ALERT_MACHID_TBL>;

	time_t					tlast_alert_		{0};
	int64_t					nalert_sent_		{0};		// To Shyama
	int64_t					nresolved_		{0};

	ALERT_TBL_VAR				avar_tbl_;

	uint16_t				multi_iter_chk_sec_	{0};
	gy_atomic<bool>				is_deleted_		{false};
	
	// For realtime alerts
	MRT_ALERTDEF(GEN_JSON_VALUE & jdoc, JSON_ALLOCATOR & allocator, uint32_t adef_id, time_t tcurr);

	void set_deleted() noexcept
	{
		is_deleted_.store(mo_relaxed);
	}	

	bool is_deleted() const noexcept
	{
		return is_deleted_.load(mo_relaxed);
	}	

	// Returns nullptr if of type MRT_ALERT_MACHID_TBL
	MRT_ALERT_ID_TBL * get_id_def_tbl() noexcept
	{
		return std::get_if<MRT_ALERT_ID_TBL>(&avar_tbl_);
	}

	// Returns nullptr if of type MRT_ALERT_ID_TBL
	MRT_ALERT_MACHID_TBL * get_machid_def_tbl() noexcept
	{
		return std::get_if<MRT_ALERT_MACHID_TBL>(&avar_tbl_);
	}

	bool is_astat_msg(uint64_t id, MALERT_MSG & amsg, time_t tcurr, GY_MACHINE_ID machid);

	bool is_astat_msg(GY_MACHINE_ID machid, MALERT_MSG & amsg, time_t tcurr)
	{
		return is_astat_msg(0, amsg, tcurr, machid);
	}	

	bool has_id_tbl() const noexcept
	{
		return akeytype_ != AKEY_MACHID;
	}
};	

class MRT_ADEF_ELEM
{
public :
	std::shared_ptr<MRT_ALERTDEF>		defshr_;
	uint32_t				adef_id_		{0};
	uint32_t				tstart_			{0};

	static inline POOL_ALLOC		*pdefmempool_		{nullptr};

	MRT_ADEF_ELEM() noexcept		= default;

	explicit MRT_ADEF_ELEM(MRT_ALERTDEF *pdef) 
		: defshr_(pdef)
	{
		if (pdef) {
			adef_id_ 	= pdef->adef_id_;
			tstart_		= uint32_t(pdef->tstart_sec_);
		}	
	}

	~MRT_ADEF_ELEM() noexcept
	{
		tstart_ = 0;
	}	
	
	MRT_ALERTDEF * get_def() const noexcept
	{
		return defshr_.get();
	}

	bool is_valid() const noexcept
	{
		return (tstart_ && defshr_.get());
	}	

	static void operator delete(void * ptr) noexcept
	{
		POOL_ALLOC::dealloc_free(ptr, pdefmempool_);
	}

	friend bool operator== (const MRT_ADEF_ELEM & aelem, uint32_t id) noexcept
	{
		return aelem.adef_id_ == id;
	}	

	friend bool operator== (const MRT_ADEF_ELEM & aelem, const MRT_ADEF_ELEM &aelem2) noexcept
	{
		return aelem.adef_id_ == aelem2.adef_id_;
	}	
};	

struct MDB_ADEL
{
	POOL_ALLOC			& mempool_;

	MDB_ADEL() 			= delete;

	MDB_ADEL(POOL_ALLOC & mempool) noexcept
		: mempool_(mempool)
	{}

	void operator()(MDB_ALERTDEF *pdef) const noexcept;

	void operator()(MDB_ALERT_STATS *pstat) const noexcept;
};


class MDB_ALERT_STATS
{
public :	
	time_t				tstart_			{0};
	time_t				tlast_hit_		{tstart_};
	time_t				tlast_alert_		{0};
	time_t				trepeat_alert_		{0};
	time_t				tforce_close_		{0};
	time_t				tquery_start_		{0};
	time_t				tlast_validate_		{tstart_ + 60};

	uint64_t			id_			{0};

	MDB_ALERTDEF			*pdef_			{nullptr};
	uint64_t			tnextchkusec_		{0};			// Acts as the key to the atimemap_

	uint32_t			adef_id_		{0};
	uint32_t			alertid_		{0};

	uint16_t			subsys_inter_sec_	{0};
	SUBSYS_CLASS_E			asubsys_		{SUBSYS_HOST};
	uint8_t				numhits_		{1};
	uint8_t				numcheckfor_		{0};
	uint8_t				nrepeats_		{0};
	MALERT_STATE_E			state_			{MALERT_PENDING};

	MDB_ALERT_STATS(uint64_t id, MDB_ALERTDEF *pdef, time_t tcurr, uint8_t numcheckfor, MALERT_STATE_E state, SUBSYS_CLASS_E asubsys) noexcept;

	MDB_ALERT_STATS(const MDB_ALERT_STATS &)		= delete;
	
	MDB_ALERT_STATS & operator= (const MDB_ALERT_STATS &)	= delete;

	~MDB_ALERT_STATS() noexcept
	{
		tstart_		= 0;
		pdef_ 		= nullptr;
	}

	bool is_deleted() const noexcept
	{
		return tstart_ == 0 || pdef_ == nullptr;
	}
};	


class MDB_ALERTDEF : public ALERTDEF_COMMON
{
public :	
	using MDB_ASTAT_TBL			= std::unordered_map<uint64_t, std::unique_ptr<MDB_ALERT_STATS, MDB_ADEL>, GY_JHASHER<uint64_t>>;
	
	time_t					tnxt_query_start_	{0};
	time_t					tlast_query_		{0};

	time_t					tlast_alert_		{0};
	time_t					tlast_hit_		{0};
	int64_t					nalert_sent_		{0};		// To Shyama
	int64_t					nresolved_		{0};
	int64_t					nerrors_		{0};
	int64_t					ndbskips_		{0};
	
	MDB_ASTAT_TBL				astat_tbl_;

	bool					is_deleted_		{false};

	// For db query alerts
	MDB_ALERTDEF(GEN_JSON_VALUE & jdoc, JSON_ALLOCATOR & allocator, uint32_t adef_id, time_t tcurr);

	~MDB_ALERTDEF() noexcept
	{
		tstart_sec_ 	= 0;
		is_deleted_	= false;
	}	

	bool is_valid() const noexcept
	{
		return (tstart_sec_ && !is_deleted_);
	}	

	void set_disabled() noexcept
	{
		tnxt_query_start_ = LONG_MAX - 3600 * 24 * 365;
	}

	void set_enabled() noexcept
	{
		tnxt_query_start_ = 0;
	}

	void set_deleted() noexcept
	{
		tstart_sec_ 	= 0;
		is_deleted_	= true;
	}	
};	

struct MALERT_MSG final
{
	GY_MACHINE_ID				machid_;
	uint64_t				id_			{0};
	time_t					tmsg_			{0};
	char					*pjson_			{nullptr};
	FREE_FPTR				free_fp_		{nullptr};
	uint32_t				lenjson_		{0};
	uint32_t				adef_id_		{0};
	uint16_t				lenact_json_		{0};		// Used for alert stats only
	uint8_t					numhits_		{0};
	ALERT_MSG_TYPE				type_			{ALERT_ASTAT_ID};
	ADEF_STATE_E				state_			{ADEFSTATE_ENABLED};
	SUBSYS_CLASS_E				asubsys_		{SUBSYS_HOST};

	MALERT_MSG() noexcept			= default;

	// For ADEF_* messages
	MALERT_MSG(ALERT_MSG_TYPE type, uint32_t adef_id, time_t tmsg, char *pjson = nullptr, FREE_FPTR free_fp = nullptr, uint32_t lenjson = 0, \
					ADEF_STATE_E state = ADEFSTATE_ENABLED, SUBSYS_CLASS_E asubsys = SUBSYS_HOST) noexcept
		: tmsg_(tmsg), pjson_(pjson), free_fp_(free_fp), lenjson_(lenjson), adef_id_(adef_id), type_(type), state_(state), asubsys_(asubsys)
	{}	

	// Only for realtime alerts with id key
	MALERT_MSG(uint64_t id, uint32_t adef_id, time_t tmsg, uint8_t numhits, SUBSYS_CLASS_E asubsys, GY_MACHINE_ID machid = {}) noexcept
		: machid_(machid), id_(id), tmsg_(tmsg), adef_id_(adef_id), numhits_(numhits), type_(ALERT_ASTAT_ID), asubsys_(asubsys)
	{}	

	// Only for realtime alerts with machid key
	MALERT_MSG(GY_MACHINE_ID machid, uint32_t adef_id, time_t tmsg, uint8_t numhits, SUBSYS_CLASS_E asubsys) noexcept
		: machid_(machid), tmsg_(tmsg), adef_id_(adef_id), numhits_(numhits), type_(ALERT_ASTAT_MACHID), asubsys_(asubsys)
	{}	

	MALERT_MSG(const MALERT_MSG &)			= delete;
	MALERT_MSG & operator= (const MALERT_MSG &)	= delete;

	MALERT_MSG(MALERT_MSG && other) noexcept
		: machid_(other.machid_), id_(other.id_), tmsg_(other.tmsg_), pjson_(std::exchange(other.pjson_, nullptr)), 
		free_fp_(std::exchange(other.free_fp_, nullptr)), lenjson_(other.lenjson_), adef_id_(other.adef_id_), lenact_json_(other.lenact_json_),
		numhits_(other.numhits_), type_(other.type_), state_(other.state_), asubsys_(other.asubsys_)
	{}

	MALERT_MSG & operator= (MALERT_MSG && other) noexcept
	{
		if (this != &other) {
			this->~MALERT_MSG();

			new (this) MALERT_MSG(std::move(other));
		}

		return *this;
	}	

	~MALERT_MSG() noexcept
	{
		destroy_json();
	}	

	void set_json(char *pjson, FREE_FPTR free_fp, uint32_t lenjson, uint16_t lenact_json = 0) noexcept
	{
		destroy_json();

		pjson_		= pjson;
		free_fp_	= free_fp;
		lenjson_	= lenjson;
		lenact_json_	= lenact_json;
	}

	bool validate() const noexcept
	{
		using namespace	comm;

		if (uint8_t(type_) < ALERT_ADEF_MAX) {
			return true;
		}	
		
		if (lenact_json_ > 0 && lenjson_ < sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + sizeof(comm::ALERT_STAT_INFO) + lenact_json_) {
			return false;
		}

		return false;
	}	

	void destroy_json() noexcept
	{
		if (pjson_) {
			if (free_fp_) {
				(*free_fp_)(pjson_);
			}

			pjson_ = nullptr;
			free_fp_ = nullptr;
		}
	}	

	void reset() noexcept
	{
		pjson_ 		= nullptr;
		free_fp_	= nullptr;
		lenjson_	= 0;
		lenact_json_	= 0;
	}	
};	

using MPSC_AMSGQ			= folly::MPMCQueue<MALERT_MSG>;

class MRT_ALERT_HDLR
{
public :
	using MRT_ADEF_TABLE 			= std::unordered_map <uint32_t, std::unique_ptr<MRT_ADEF_ELEM>, GY_JHASHER<uint32_t>>;
	using MATIME_MAP			= std::multimap<uint64_t, MRT_ALERT_STATS *>;

	static_assert(MAX_ALERT_DEFS <= 1024, "The max alert definitions need to be less than 1024 for the max limits set here...");

	GY_MUTEX				adefmutex_;
	MRT_ADEF_TABLE				adeftbl_;
	
	gy_atomic<uint64_t>			last_chk_cusec_		{0};

	MPSC_AMSGQ				aqueue_			{MAX_TOTAL_ALERTS_PER_MIN};
	POOL_ALLOC				defpool_		{sizeof(MRT_ADEF_ELEM), MAX_ALERT_DEFS + 128};

	// Need THR_POOL_ALLOC as deallocation will happen from RCU Thread
	THR_POOL_ALLOC				mempool_		{sizeof(MRT_ALERT_STATS), MAX_TOTAL_ALERTS_PER_HOUR + 128, true};
	MATIME_MAP				atimemap_;
	
	gy_atomic<uint64_t>			last_upd_cusec_		{0};

	gy_atomic<time_t>			tdisable_end_		{0};
	time_t					tlast_timemap_chk_	{0};
	time_t					tlast_stat_chk_		{0};

	gy_atomic<uint64_t>			nmissed_		{0};
	uint64_t				nalerts_		{0};
	uint64_t				nrepeats_		{0};
	uint64_t				nrtskips_		{0};
	uint64_t				nalertclose_		{0};
	uint64_t				nforceclose_		{0};
	uint64_t				nmsgerr_ 		{0};
	
	uint64_t				lastnmissed_		{0};
	uint64_t				lastnalerts_		{0};
	uint64_t				lastnrepeats_		{0};
	uint64_t				lastnrtskips_		{0};
	uint64_t				lastnalertclose_	{0};
	uint64_t				lastnforceclose_	{0};
	uint64_t				lastnmsgerr_		{0};

	MRT_ALERT_HDLR()
	{
		MRT_ADEF_ELEM::pdefmempool_	= &defpool_;
	}

	bool new_alerts_disabled(time_t tcurr) const noexcept
	{
		return tcurr < tdisable_end_.load(mo_relaxed);
	}

	void handle_rt_alerts(MALERT_HDLR *palerthdlr);

	void handle_astat_msg(MALERT_MSG & emsg, time_t tcurr) noexcept;

	void add_new_def(MALERT_MSG & emsg, time_t tcurr) noexcept;

	void set_alert_state(uint32_t adef_id, time_t tcurr, ALERT_MSG_TYPE type, ADEF_STATE_E state) noexcept;

	void handle_def_reset(MRT_ALERTDEF *pdef, bool is_deleted, bool only_pending);
	
	void upd_astat_id(MALERT_MSG & emsg, MRT_ALERTDEF *pdef, MRT_ADEF_ELEM *pdefelem, MRT_ALERT_ID_TBL & stattbl, time_t tcurr);

	void upd_astat_machid(MALERT_MSG & emsg, MRT_ALERTDEF *pdef, MRT_ADEF_ELEM *pdefelem, MRT_ALERT_MACHID_TBL & stattbl, time_t tcurr);

	bool send_shyama_rtalert(MALERT_MSG & emsg, MRT_ALERT_STATS *pstat, MRT_ALERTDEF *pdef, time_t tcurr);

	void validate_timemap(time_t tcurr, bool check_all) noexcept;

	void validate_stats(time_t tcurr) noexcept;

	void common_astats_update(MALERT_MSG & emsg, MRT_ALERT_STATS *pstat, MRT_ALERTDEF *pdef, time_t tcurr, bool is_fired, bool isnew);

	void print_stats(int64_t tdiff, time_t tcurr) noexcept;
};	


class MDB_ALERT_HDLR
{
public :
	using MDB_ADEF_TABLE			= std::unordered_map<uint64_t, std::unique_ptr<MDB_ALERTDEF, MDB_ADEL>, GY_JHASHER<uint64_t>>;
	using MATIME_MAP			= std::multimap<time_t, MDB_ALERT_STATS *>;

	static constexpr size_t			NUM_DB_CONNS		{2};
	static constexpr int			QRY_START_OFFSET_SEC	{30};

	gy_atomic<uint64_t>			last_upd_cusec_		{0};

	MDB_ADEF_TABLE				adeftbl_;
	MPSC_AMSGQ				aqueue_			{MAX_TOTAL_ALERTS_PER_MIN};
	POOL_ALLOC				mempool_		{sizeof(MDB_ALERT_STATS), MAX_TOTAL_ALERTS_PER_HOUR + 128};
	POOL_ALLOC				defpool_		{sizeof(MDB_ALERTDEF), MAX_ALERT_DEFS + 128};
	MATIME_MAP				atimemap_;
	PGConnPool				dbpool_;
	
	gy_atomic<time_t>			tdisable_end_		{0};
	time_t					tnext_query_		{time(nullptr) + MIN_ALERT_QUERY_INTERVAL_SEC};
	time_t					tquery_start_		{0};
	time_t					treset_conns_		{tnext_query_ + 5 * 60};
	time_t					tlast_timemap_chk_	{0};
	time_t					tlast_stat_chk_		{0};

	uint64_t				nalerts_		{0};
	uint64_t				nrepeats_		{0};
	uint64_t				ndbskips_		{0};
	uint64_t				nkeyskips_		{0};
	uint64_t				ndberrors_		{0};
	uint64_t				ngetdberrors_		{0};
	uint64_t				nconnmiss_		{0};
	uint64_t				nalertclose_		{0};
	uint64_t				nforceclose_		{0};

	uint64_t				lastnalerts_		{0};
	uint64_t				lastnrepeats_		{0};
	uint64_t				lastndbskips_		{0};
	uint64_t				lastnkeyskips_		{0};
	uint64_t				lastndberrors_		{0};
	uint64_t				lastngetdberrors_	{0};
	uint64_t				lastnconnmiss_		{0};
	uint64_t				lastnalertclose_	{0};
	uint64_t				lastnforceclose_	{0};

	uint32_t				curr_nalerts_		{0};
	int					dbhandlerid_		{0};

	MDB_ALERT_HDLR(int dbhandlerid, const char *dbhost, uint16_t dbport, const char *user, const char *passwd, const char *dbname)
		: dbpool_(gy_to_charbuf<128>("DB Alert Pool %d", dbhandlerid).get(), NUM_DB_CONNS, dbhost, dbport, user, passwd, dbname, 
				gy_to_charbuf<128>("madhava_dbalert%d", dbhandlerid).get(), get_db_init_commands().get(), true /* auto_reconnect */, 12, 10, 10),
		dbhandlerid_(dbhandlerid)		
	{}	

	bool new_alerts_disabled(time_t tcurr) const noexcept
	{
		return tcurr < tdisable_end_.load(mo_relaxed);
	}

	void handle_db_alerts(MALERT_HDLR *palerthdlr);

	void add_new_def(MALERT_MSG & emsg, time_t tcurr) noexcept;

	void set_alert_state(uint32_t adef_id, time_t tcurr, ALERT_MSG_TYPE type, ADEF_STATE_E state) noexcept;
	
	void handle_def_reset(MDB_ALERTDEF *pdef, bool is_deleted, bool only_pending); 

	void run_alert_queries(time_t tcurr) noexcept;

	template <typename TStreamBuf>
	bool db_resp_cb(GyPGConn & conn, GyPGresult && gyres, bool is_completed, TStreamBuf & streambuf, int & total_rows, bool & is_error, MDB_ALERTDEF & adef);

	void validate_timemap(time_t tcurr, bool check_all) noexcept;

	void validate_stats(time_t tcurr) noexcept;

	void print_stats(int64_t tdiff, time_t tcurr) noexcept;
	
};	

class MALERT_HDLR
{
public :
	/*
	 * We use 1 realtime Alert Handler thread and 2 DB Alert threads. The Realtime Alerts thread count must be 1 as POOL_ALLOC is used...
	 */
	uint64_t				cusec_start_;

	MRT_ALERT_HDLR				rthdlr_;
	MDB_ALERT_HDLR				dbhdlr1_;
	MDB_ALERT_HDLR				dbhdlr2_;

	GY_THREAD				rt_thr_	;
	GY_THREAD				db_thr1_;
	GY_THREAD				db_thr2_;

	MALERT_HDLR(MCONN_HANDLER *pconnhdlr);

	MDB_ALERT_HDLR & get_alertdef_db_hdlr(uint32_t adef_id) noexcept
	{
		if ((adef_id >> 8) & 1) {
			return dbhdlr1_;
		}	

		return dbhdlr2_;
	}	

	bool send_rt_amsg(MALERT_MSG && amsg, const char *pstackjson, size_t szjson);

	void handle_adef_new(comm::SM_ALERT_ADEF_NEW *pdef, int nevents, const uint8_t *pendptr);

	void handle_adef_upd(comm::SM_ALERT_ADEF_UPD *pdef, int nevents, const uint8_t *pendptr);

	void handle_astat_disable(const comm::SM_ALERT_STAT_DISABLE & astat);

	void check_partha_rtalert_defs(MCONN_HANDLER *pconnhdlr, uint64_t curr_usec_clock) noexcept;

	static MALERT_HDLR * get_singleton() noexcept;
};	

} // namespace madhava
} // namespace gyeeta	

