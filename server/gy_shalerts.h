//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"
#include			"gy_alerts.h"
#include			"gy_misc.h"
#include			"gy_postgres.h"
#include			"gy_json_field_maps.h"
#include			"gy_comm_proto.h"
#include			"gy_pool_alloc.h"

#pragma 			GCC diagnostic push
#pragma 			GCC diagnostic ignored "-Wsign-compare"

#include			"folly/MPMCQueue.h"

#pragma 			GCC diagnostic pop


namespace gyeeta {
namespace shyama {

class SHCONN_HANDLER;
class SHALERTDEF;
class SHALERT_STATS;

enum SHALERT_STATE_E : uint8_t
{
	SHALERT_PENDING		= 0, 		/* In numcheckfor condition */
	SHALERT_FIRED,				/* Waiting for Resolution */
};	


struct SHALERT_MSG final
{
	enum MsgType : uint8_t
	{
		MsgNewDef			= 0,

		MsgDefEnable,
		MsgDefDisable,
		MsgDefMute,
		MsgDefSilence,
		MsgDefInhibit,
		MsgDefDelete,

		MsgPingAll,
	};

	time_t					tmsg_			{0};
	std::unique_ptr<char []>		msg_;
	uint32_t				lenmsg_			{0};
	uint32_t				adef_id_		{0};
	SUBSYS_CLASS_E				asubsys_		{SUBSYS_HOST};
	MsgType					msgtype_		{MsgNewDef};
	bool					isrealtime_		{false};

	SHALERT_MSG() noexcept			= default;

	// Use with New Alertdef or MsgPingAll
	SHALERT_MSG(time_t tcurr, std::unique_ptr<char []> && msg, uint32_t lenmsg, MsgType msgtype, uint32_t adef_id = 0, SUBSYS_CLASS_E asubsys = SUBSYS_HOST, bool isrealtime = false) noexcept
		: tmsg_(tcurr), msg_(std::move(msg)), lenmsg_(lenmsg), adef_id_(adef_id), asubsys_(asubsys), msgtype_(msgtype), isrealtime_(isrealtime)
	{}

	// Use for MsgDef*
	SHALERT_MSG(uint32_t adef_id, MsgType msgtype, bool isrealtime, time_t tcurr = 0) noexcept
		: tmsg_(tcurr), adef_id_(adef_id), msgtype_(msgtype), isrealtime_(isrealtime)
	{}

	SHALERT_MSG(const SHALERT_MSG &)				= delete;

	SHALERT_MSG & operator= (const SHALERT_MSG &)			= delete;

	SHALERT_MSG(SHALERT_MSG && other) noexcept			= default;

	SHALERT_MSG & operator= (SHALERT_MSG && other) noexcept		= default;

	~SHALERT_MSG() noexcept						= default;

};	

struct SHADEL
{
	POOL_ALLOC			& mempool_;

	SHADEL() 			= delete;

	SHADEL(POOL_ALLOC & mempool) noexcept
		: mempool_(mempool)
	{}

	void operator()(SHALERTDEF *pdef) const noexcept;

	void operator()(SHALERT_STATS *pstat) const noexcept;
};


class SHALERT_STATS
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

	SHALERTDEF			*pdef_			{nullptr};
	uint64_t			tnextchkusec_		{0};			// Acts as the key to the atimemap_

	uint32_t			adef_id_		{0};
	uint32_t			alertid_		{0};

	uint16_t			subsys_inter_sec_	{0};
	SUBSYS_CLASS_E			asubsys_		{SUBSYS_HOST};
	uint8_t				numhits_		{1};
	uint8_t				numcheckfor_		{0};
	uint8_t				nrepeats_		{0};
	SHALERT_STATE_E			state_			{SHALERT_PENDING};

	SHALERT_STATS(uint64_t id, SHALERTDEF *pdef, time_t tcurr, uint8_t numcheckfor, SHALERT_STATE_E state, SUBSYS_CLASS_E asubsys) noexcept;

	SHALERT_STATS(const SHALERT_STATS &)			= delete;
	
	SHALERT_STATS & operator= (const SHALERT_STATS &)	= delete;

	~SHALERT_STATS() noexcept
	{
		tstart_		= 0;
		pdef_ 		= nullptr;
	}

	bool is_deleted() const noexcept
	{
		return tstart_ == 0 || pdef_ == nullptr;
	}
};	


class SHALERTDEF : public ALERTDEF_COMMON
{
public :	
	using SHASTAT_TBL			= std::unordered_map<uint64_t, std::unique_ptr<SHALERT_STATS, SHADEL>, GY_JHASHER<uint64_t>>;
	
	time_t					tnxt_query_start_	{0};
	time_t					tlast_query_		{0};

	time_t					tlast_alert_		{0};
	time_t					tlast_hit_		{0};
	int64_t					nerrors_		{0};
	int64_t					ndbskips_		{0};
	
	SHASTAT_TBL				astat_tbl_;

	bool					is_deleted_		{false};

	SHALERTDEF(GEN_JSON_VALUE & jdoc, JSON_ALLOCATOR & allocator, uint32_t adef_id, time_t tcurr);

	~SHALERTDEF() noexcept
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

	uint32_t get_rt_max_multi_iter_sec() const noexcept
	{
		return subsys_inter_sec_ + std::min<uint32_t>((subsys_inter_sec_ >> 1) + 1, 10);
	}	
};	


class SHALERT_HDLR
{
public :
	using MPSC_MSGQ				= folly::MPMCQueue<SHALERT_MSG>;
	using SHADEF_TABLE			= std::unordered_map<uint64_t, std::unique_ptr<SHALERTDEF, SHADEL>, GY_JHASHER<uint64_t>>;
	using SHATIME_MAP			= std::multimap<time_t, SHALERT_STATS *>;

	static constexpr size_t			NUM_DB_CONNS		{2};
	static constexpr int			QRY_START_OFFSET_SEC	{30};

	/*
	 * Nov 2021 : We use the same thread for RT and DB Alerts as currently only Cluster State Alerts to be handled
	 */

	uint64_t				cusec_start_;
	MPSC_MSGQ				aqueue_			{MAX_ALERT_DEFS * 2};
	PGConnPool				dbpool_;

	SHADEF_TABLE				artdeftbl_;
	SHADEF_TABLE				adbdeftbl_;
	POOL_ALLOC				mempool_		{sizeof(SHALERT_STATS), MAX_TOTAL_ALERTS_PER_HOUR + 128};
	POOL_ALLOC				defpool_		{sizeof(SHALERTDEF), MAX_ALERT_DEFS + 128};
	SHATIME_MAP				atimemap_;
	
	gy_atomic<time_t>			tdisable_end_		{0};
	
	time_t					tnextdb_query_		{time(nullptr) + MIN_ALERT_QUERY_INTERVAL_SEC};
	time_t					tquery_start_		{0};
	time_t					treset_conns_		{tnextdb_query_ + 5 * 60};
	time_t					tlast_timemap_chk_	{0};
	time_t					tlast_stat_chk_		{0};
	time_t					tlast_rt_check_		{0};
	time_t					tlast_clusterstate_	{0};

	uint64_t				nrtalerts_		{0};
	uint64_t				nrtrepeats_		{0};
	uint64_t				ndbalerts_		{0};
	uint64_t				ndbrepeats_		{0};
	uint64_t				ndbskips_		{0};
	uint64_t				npoolskips_		{0};
	uint64_t				ndberrors_		{0};
	uint64_t				ngetdberrors_		{0};
	uint64_t				nconnmiss_		{0};
	uint64_t				nalertclose_		{0};
	uint64_t				nforceclose_		{0};

	uint64_t				lastnrtalerts_		{0};
	uint64_t				lastnrtrepeats_		{0};
	uint64_t				lastndbalerts_		{0};
	uint64_t				lastndbrepeats_		{0};
	uint64_t				lastndbskips_		{0};
	uint64_t				lastnpoolskips_		{0};
	uint64_t				lastndberrors_		{0};
	uint64_t				lastngetdberrors_	{0};
	uint64_t				lastnconnmiss_		{0};
	uint64_t				lastnalertclose_	{0};
	uint64_t				lastnforceclose_	{0};

	// Keep this last so that all prior members init
	GY_THREAD				salert_thr_;

	SHALERT_HDLR(SHCONN_HANDLER *pconnhdlr);

	int shyama_alert_thread() noexcept;

	MAKE_CLASS_FUNC_WRAPPER_NO_ARG(SHALERT_HDLR, shyama_alert_thread);

	bool new_alerts_disabled(time_t tcurr) const noexcept
	{
		return tcurr < tdisable_end_.load(mo_relaxed);
	}

	// Called directly by Alertmgr
	void set_disable_alerts(time_t tdisable_end) noexcept
	{
		tdisable_end_.store(mo_relaxed);
	}	

	void handle_alerts();

	void handle_def_pings(void *pdata, size_t len, time_t tcurr);

	void check_rt_clusterstate(time_t tcurr) noexcept;

	bool set_astat_on_alert(comm::ALERT_STAT_INFO & astat, SHALERTDEF *pdef, uint64_t keyid, time_t tcurr, uint64_t currtusec);

	bool sdb_resp_cb(GyPGConn & conn, GyPGresult && gyres, bool is_completed, int & total_rows, bool & is_error, SHALERTDEF & adef);

	bool send_alert_info(comm::ALERT_STAT_INFO & astat, const char *pjson, size_t szjson);

	bool send_alert_close(uint64_t alertid, uint32_t adef_id, time_t tlast_hit, time_t tcurr, bool is_force_close, bool isrealtime);

	void run_alert_queries(time_t tcurr) noexcept;

	void validate_stats(time_t tcurr, bool isrt) noexcept;

	void print_stats(int64_t tdiff, time_t tcurr) noexcept;

	void validate_timemap(time_t tcurr, bool check_all) noexcept;

	void add_new_def(SHALERT_MSG & emsg, time_t tcurr) noexcept;

	void set_alert_state(uint32_t adef_id, bool is_realtime, time_t tcurr, ALERT_MSG_TYPE type, ADEF_STATE_E state) noexcept;

	void handle_def_reset(SHALERTDEF *pdef, bool is_deleted, bool only_pending);

	// Called by Alertmgr
	bool send_new_alertdef(time_t tmsg, const char *pjson, size_t lenjson, uint32_t adefid, SUBSYS_CLASS_E asubsys, bool is_realtime);

	// Called by Alertmgr
	bool send_alertdef_update(uint32_t adef_id, ALERT_MSG_TYPE type, bool isrealtime) noexcept;
};	



} // namespace shyama
} // namespace gyeeta

