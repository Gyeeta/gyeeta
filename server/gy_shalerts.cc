

#include			"gy_shalerts.h"
#include			"gy_shconnhdlr.h"
#include			"gy_shfields.h"
#include			"gyshyama.h"

using namespace gyeeta::comm;

namespace gyeeta {
namespace shyama {

static SHCONN_HANDLER		*gshconnhdlr = nullptr;
static uint64_t			g_shyama_id = 0;

SHALERT_HDLR::SHALERT_HDLR(SHCONN_HANDLER *pconnhdlr)
	:
	cusec_start_(({
			gshconnhdlr 	= pconnhdlr;
			g_shyama_id 	= pconnhdlr->gshyama_id_;

			get_usec_clock();
			})),
	dbpool_("Shyama Alert Pool", NUM_DB_CONNS, pconnhdlr->get_settings()->postgres_hostname, pconnhdlr->get_settings()->postgres_port, pconnhdlr->get_settings()->postgres_user, 
			pconnhdlr->get_settings()->postgres_password, pconnhdlr->get_dbname().get(), "shyama_alerts", get_db_init_commands().get(), true /* auto_reconnect */, 12, 10, 10),
	salert_thr_("Shyama Alert Thread", GET_PTHREAD_WRAPPER(shyama_alert_thread), this, nullptr, nullptr, 
		true, 2 * 1024 * 1024 /* Stack */, 2000, true, true, true /* thr_func_calls_init_done */, 5000, true)
	
{
	salert_thr_.clear_cond();

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Initialized Shyama Alerts Object successfully...\n");
}


int SHALERT_HDLR::shyama_alert_thread() noexcept
{
	salert_thr_.set_thread_init_done();

	do {
		try {
			handle_alerts();
		}
		GY_CATCH_EXCEPTION(
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught in Shyama Alert thread : %s\n\n", GY_GET_EXCEPT_STRING);
		);
		
	} while (true);

	return -1;
}

void SHALERT_HDLR::handle_alerts() 
{
	tlast_stat_chk_	= tlast_timemap_chk_  = time(nullptr);
	
	time_t				tlastprint = tlast_timemap_chk_;

	do {
		time_t				tcurr = time(nullptr) + 1, tstart = tcurr + 10, tmap1;
		int				ncache;
		bool				bret, is_all = false;
		
		if (auto cit = atimemap_.begin(); cit != atimemap_.end()) {
			tmap1 = cit->first/GY_USEC_PER_SEC;

			if (tmap1 < tstart) {
				tstart = std::max(tmap1, tcurr);
			}	
		}	
		else {
			tmap1 = tstart + 1000;
		}	

		if (artdeftbl_.size() > 0) {
			tstart = tcurr;
		}
		else if (tnextdb_query_ < tstart) {
			tstart = std::max(tnextdb_query_, tcurr);
		}	

		SHALERT_MSG			emsg;

		bret = aqueue_.tryReadUntil(std::chrono::system_clock::from_time_t(tstart), emsg);

		tcurr = time(nullptr);

		if (bret) {
			switch (emsg.msgtype_) {
			
			case SHALERT_MSG::MsgNewDef :

				if (bool(emsg.msg_) && emsg.lenmsg_) {
					add_new_def(emsg, tcurr);
				}	
				break;

			case SHALERT_MSG::MsgDefEnable :
				set_alert_state(emsg.adef_id_, emsg.isrealtime_, tcurr, ALERT_ADEF_ENABLE, ADEFSTATE_ENABLED);
				break;

			case SHALERT_MSG::MsgDefDisable :
				set_alert_state(emsg.adef_id_, emsg.isrealtime_, tcurr, ALERT_ADEF_DISABLE, ADEFSTATE_DISABLED);
				break;

			case SHALERT_MSG::MsgDefMute :
				set_alert_state(emsg.adef_id_, emsg.isrealtime_, tcurr, ALERT_ADEF_MUTE, ADEFSTATE_MUTED);
				break;

			case SHALERT_MSG::MsgDefSilence :
				set_alert_state(emsg.adef_id_, emsg.isrealtime_, tcurr, ALERT_ADEF_SILENCE, ADEFSTATE_SILENCED);
				break;

			case SHALERT_MSG::MsgDefInhibit :
				set_alert_state(emsg.adef_id_, emsg.isrealtime_, tcurr, ALERT_ADEF_INHIBIT, ADEFSTATE_INHIBITED);
				break;

			case SHALERT_MSG::MsgDefDelete :
				set_alert_state(emsg.adef_id_, emsg.isrealtime_, tcurr, ALERT_ADEF_DELETE, ADEFSTATE_DISABLED);
				break;

			case SHALERT_MSG::MsgPingAll :
				handle_def_pings(emsg.msg_.get(), emsg.lenmsg_, tcurr);
				break;

			default :
				break;
			}	
		}	

next :
		if (artdeftbl_.size() > 0) {
			/*
			 * XXX NOTE : Currently the only RT Alerts handled in Shyama is for clusterstate subsystem.
			 * Change the logic below if more subsystems added...
			 *
			 * Also, we may miss an interval check due to DB queries below taking too long,
			 */
			if (tcurr > tlast_rt_check_) {
				check_rt_clusterstate(tcurr);
				tlast_rt_check_ = tcurr;
			}	 
		}	

		if (tcurr >= tnextdb_query_) {
			/*
			 * The below assignment implies that if we miss an interval due to queries taking too long,
			 * we will skip those interval(s)...
			 */
			tnextdb_query_ 	= tcurr + MIN_ALERT_QUERY_INTERVAL_SEC;
			tquery_start_ 	= tcurr;

			run_alert_queries(tcurr);

			tcurr = time(nullptr);
		}	
	
		if (tcurr > tlast_timemap_chk_ + 60) {

			tlast_timemap_chk_ = tcurr;
			validate_timemap(tcurr, true /* check_all */);
			is_all = true;

			if (tcurr > tlast_stat_chk_ + 180) {
				tlast_stat_chk_ = tcurr;
				validate_stats(tcurr, true /* isrt */);
				validate_stats(tcurr, false /* isrt */);
			}	
		}	

		if (tcurr >= tlastprint + 300) {
			tcurr = time(nullptr);
			print_stats(tcurr - tlastprint, tcurr);

			tlastprint = tcurr;
		}

		if (!is_all && tmap1 <= tcurr) {
			validate_timemap(tcurr, false /* check_all */);
		}	

		if (tcurr >= treset_conns_) {
			treset_conns_ = time(nullptr) + 5 * 60;
			dbpool_.reset_idle_conns();
		}	

	} while (true);
}

void SHALERT_HDLR::handle_def_pings(void *pdata, size_t len, time_t tcurr)
{
	if (!pdata || len < sizeof(SM_ALERT_ADEF_UPD)) return;

	const SM_ALERT_ADEF_UPD		*pone = (const SM_ALERT_ADEF_UPD *)pdata;
	int				nevents = len/sizeof(SM_ALERT_ADEF_UPD);

	for (int i = 0; i < nevents; ++i, ++pone) {

		switch (pone->type_) {

		case ALERT_ADEF_ENABLE :
			set_alert_state(pone->adef_id_, pone->isrealtime_, tcurr, ALERT_ADEF_ENABLE, ADEFSTATE_ENABLED);
			break;

		case ALERT_ADEF_DISABLE :
			set_alert_state(pone->adef_id_, pone->isrealtime_, tcurr, ALERT_ADEF_DISABLE, ADEFSTATE_DISABLED);
			break;

		case ALERT_ADEF_MUTE :
			set_alert_state(pone->adef_id_, pone->isrealtime_, tcurr, ALERT_ADEF_MUTE, ADEFSTATE_MUTED);
			break;

		case ALERT_ADEF_SILENCE :
			set_alert_state(pone->adef_id_, pone->isrealtime_, tcurr, ALERT_ADEF_SILENCE, ADEFSTATE_SILENCED);
			break;

		case ALERT_ADEF_INHIBIT :
			set_alert_state(pone->adef_id_, pone->isrealtime_, tcurr, ALERT_ADEF_INHIBIT, ADEFSTATE_INHIBITED);
			break;

		case ALERT_ADEF_DELETE :
			set_alert_state(pone->adef_id_, pone->isrealtime_, tcurr, ALERT_ADEF_DELETE, ADEFSTATE_DISABLED);
			break;

		default :
			break;
		}
	}


}	

SHALERT_STATS::SHALERT_STATS(uint64_t id, SHALERTDEF *pdef, time_t tcurr, uint8_t numcheckfor, SHALERT_STATE_E state, SUBSYS_CLASS_E asubsys) noexcept
	: 
	tstart_(tcurr), id_(id), pdef_(pdef), adef_id_(pdef->adef_id_), subsys_inter_sec_(pdef->subsys_inter_sec_), asubsys_(asubsys), numcheckfor_(numcheckfor), state_(state)
{
	alertid_ = ALERT_STAT_HASH({}, id_, adef_id_, g_shyama_id, tcurr).get_hash();	
}

SHALERTDEF::SHALERTDEF(GEN_JSON_VALUE & jdoc, JSON_ALLOCATOR & allocator, uint32_t adef_id, time_t tcurr)
	: ALERTDEF_COMMON(jdoc, allocator, adef_id, tcurr)
{
	if (false == is_enabled()) {
		set_disabled();
	}	
}


void SHALERT_HDLR::check_rt_clusterstate(time_t tcurr) noexcept
{
	try {
		using AggrClusterStateMap	= SHCONN_HANDLER::AggrClusterStateMap;

		using OptStackJsonWriter	= std::optional<STACK_JSON_WRITER<8192, 4096>>;

		if (new_alerts_disabled(tcurr)) {
			return;
		}	

		time_t				tclusterstate = gshconnhdlr->get_last_tclusterstate(mo_acquire);

		if (tclusterstate <= tlast_clusterstate_) {
			return;
		}	

		SCOPE_GY_MUTEX			scopelock(&gshconnhdlr->cluststate_mutex_);

		tlast_clusterstate_ 		= gshconnhdlr->get_last_tclusterstate();

		AggrClusterStateMap		clustermap(gshconnhdlr->clusterstatemap_);
		
		scopelock.unlock();

		if (clustermap.size() == 0) {
			return;
		}	
		
		uint64_t			currtusec = get_usec_time();
		time_t				tcurr = currtusec/GY_USEC_PER_SEC;
		auto				timebuf = gy_localtime_iso8601_sec(tcurr);
		int				nalerts = 0;

		for (const auto & [name, state] : clustermap) {

			size_t				lenclust = strlen(name.get());
			ClusterStateFields		clustfields(state, name.get(), lenclust, tcurr);
			OptStackJsonWriter		writer;

			for (const auto & [adefid, pdefuniq] : artdeftbl_) {
				auto				*pdef = pdefuniq.get();

				if (!pdef || !pdef->is_enabled()) {
					continue;
				}	

				auto				popt = pdef->get_rt_options();

				if (!popt) {
					continue;
				}	

				if (CRIT_PASS != clustfields.filter_match(popt->get_filter_criteria())) {
					continue;
				}	

				ALERT_STAT_INFO			astat;
				bool				bret;

				bret = set_astat_on_alert(astat, pdef, gy_cityhash64(name.get(), lenclust), tcurr, currtusec);

				if (!bret || 0 == astat.alertid_) {
					continue;
				}	

				nalerts++;
	
				auto [colarr, ncols]		= pdef->get_column_list();
				size_t				szjson = 0;
				const char			*pstackjson = nullptr;
				
				if (!bool(writer)) {
					new (&writer) (decltype(writer))(std::in_place);
				}
				else {
					writer->Reset();
				}	

				clustfields.print_json(colarr, ncols, writer.value(), timebuf.get());

				szjson = writer->get_size() + 1;
				pstackjson = writer->get_string();
				
				send_alert_info(astat, pstackjson, szjson);
		
				if ((uint64_t)nalerts >= MAX_TOTAL_ALERTS_PER_MIN) {
					goto done1;
				}	
			}
		}
done1 :
		if (nalerts > 0) {
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Shyama Alerts : Sent %d RT Clusterstate Alerts to Alertmgr\n", nalerts);
		}	
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught in Shyama Alerts RT Clusterstate Alert Check : %s\n", GY_GET_EXCEPT_STRING);
	);
}

bool SHALERT_HDLR::set_astat_on_alert(comm::ALERT_STAT_INFO & astat, SHALERTDEF *pdef,  uint64_t keyid, time_t tcurr, uint64_t currtusec)
{
	bool				isalert = false, bret;
	uint8_t				numhits = 1;
	SHALERT_STATS			*pstat = nullptr;
	bool				is_fired = false, isnew = false;

	if (!pdef) {
		return false;
	}	

	auto				it = pdef->astat_tbl_.find(keyid);

	if (it == pdef->astat_tbl_.end()) {
		numhits = 1;
		is_fired = (1 == pdef->numcheckfor_);

		pstat = (decltype(pstat))mempool_.malloc();

		if (!pstat) {
			ndbskips_++;
			return false;
		}	

		new (pstat) SHALERT_STATS(keyid, pdef, tcurr, pdef->numcheckfor_, is_fired ? SHALERT_FIRED : SHALERT_PENDING, pdef->asubsys_);

		auto			puniq = std::unique_ptr<SHALERT_STATS, SHADEL>(pstat, mempool_);

		auto			[kit, ktrue] = pdef->astat_tbl_.try_emplace(keyid, std::move(puniq));

		pstat->tnextchkusec_ = pdef->get_nextcheck_tusec(currtusec, numhits);

		try {
			atimemap_.emplace(pstat->tnextchkusec_, pstat);
		}
		catch(...) {
			pdef->astat_tbl_.erase(kit);
			return false;
		}	

		DEBUGEXECN(5, 
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW_UNDERLINE, "Shyama Alerts : New RT Alert Object of Alert ID %08x for Definition \'%s\' : "
				"Total Timemap entries %lu\n", pstat->alertid_, pdef->name(), atimemap_.size());
		);

		isnew = true;

		if (!is_fired) {
			return false;
		}	
	}	
	else {
		pstat = it->second.get();

		if (!pstat) {
			pdef->astat_tbl_.erase(it);
			return false;
		}	

		pstat->numhits_++;
		numhits = pstat->numhits_;

		time_t			toldlasthit = pstat->tlast_hit_;

		if (numhits > 1 && pstat->numcheckfor_ > 1 && toldlasthit + pdef->get_rt_max_multi_iter_sec() <= tcurr) {
			// Flapping Alert : Reset checks

			DEBUGEXECN(15, 
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW_UNDERLINE, "Shyama Alerts : Flapping RT Alert seen for Alert ID %08x of Definition \'%s\' : "
					"numcheckfor_ %u, numhits %u, Time since last hit %ld sec\n", 
					pstat->alertid_, pdef->name(), pstat->numcheckfor_, numhits, tcurr - toldlasthit);
			);

			pstat->numhits_ = 1;
		}	
		else if (pstat->numhits_ >= pdef->numcheckfor_) {
			// Reset count
			pstat->numhits_ = 1;
			is_fired = true;
		}	

		pstat->tlast_hit_ = tcurr;
	}	

	time_t			tlast_alert = pstat->tlast_alert_;

	if (is_fired && (tlast_alert == 0 || tlast_alert + pdef->repeataftersec_ < tcurr)) {
		
		if (tlast_alert == 0) {
			pstat->state_ 		= SHALERT_FIRED;
			pstat->tforce_close_ 	= tcurr + pdef->forceclosesec_;

			nrtalerts_++;
		}
		else if (pdef->repeataftersec_ == 0) {
			// No repeat alerts
			return false;
		}	
		else {
			nrtrepeats_++;
			pstat->nrepeats_++;
		}	

		astat.~ALERT_STAT_INFO();

		new (&astat) ALERT_STAT_INFO(tcurr, pstat->alertid_, pdef->adef_id_, AHDLR_SHYAMA, pdef->asubsys_, numhits, pdef->numcheckfor_, pstat->nrepeats_, true /* isrealtime */, 0);

		pstat->tlast_alert_ = tcurr;
		
		if (pdef->repeataftersec_ > 0) {
			pstat->trepeat_alert_ = tcurr + pdef->repeataftersec_;
		}
		else {
			pstat->trepeat_alert_ = 0;
		}	
	}

	if (isnew) {
		return true;
	}

	uint64_t		oldtusec = pstat->tnextchkusec_, newtusec = pdef->get_nextcheck_tusec(currtusec, is_fired ? 1 /* reset */ : pstat->numhits_);

	pstat->tnextchkusec_  	= newtusec;

	auto 			range = atimemap_.equal_range(oldtusec);
	
	for (auto it = range.first; it != range.second; ++it) {
		if (it->second == pstat) {
			auto			mnode = atimemap_.extract(it);

			if (bool(mnode)) {
				mnode.key() = newtusec;
				atimemap_.insert(std::move(mnode));
			}	

			break;
		}
	}	

	return true;
}	

bool SHALERT_HDLR::sdb_resp_cb(GyPGConn & conn, GyPGresult && gyres, bool is_completed, int & total_rows, bool & is_error, SHALERTDEF & adef)
{
	SHALERTDEF			*pdef = &adef;

	if (is_completed) {
		conn.make_available();

		if (total_rows) {
			DEBUGEXECN(11, 
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Shyama Alertdef \'%s\' : DB Query returned %d rows...\n", pdef->name(), total_rows);

			);
		}

		pdef->tlast_query_ = time(nullptr);

		return true;
	}	

	if (is_error) {
		return false;
	}	
	
	const char			*name = pdef->name();

	if (true == gyres.is_error()) {

		if (pdef->nerrors_ < 3 || gdebugexecn >= 1) {
			WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to query Shyama Alert \'%s\' from DB (Total errors so far %ld) : Error due to %s\n", 
					name, pdef->nerrors_, gyres.get_error_msg());
		}

		ndberrors_++;
		pdef->nerrors_++;
		is_error = true;

		return false;
	}	

	char				tbuf[512];
	const PGresult *		pres = gyres.get();
	int				nfields = PQnfields(pres);
	int				ntuples = PQntuples(gyres.get());

	if (ntuples == 0) {
		return true;
	}	

	if ((unsigned)nfields > pdef->ncols_) {
		if (pdef->nerrors_ < 3 || gdebugexecn >= 1) {
			WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Shyama Alert \'%s\' : Invalid DB Column count seen : %d instead of %u", name, nfields, pdef->ncols_);
		}

		ndberrors_++;
		pdef->nerrors_++;
		is_error = true;
		return false;
	}	

	const auto			colarr = pdef->pcolarr_;
	uint16_t			keyid_colnum = pdef->keyid_colnum_;
	bool				defid_key = pdef->is_db_defid_key();

	if (keyid_colnum >= (unsigned)nfields && !defid_key) {
		if (pdef->nerrors_ < 3 || gdebugexecn >= 1) {
			WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Shyama Alert \'%s\' : Invalid DB Column count seen : Key Column %u : Number of fields seen %d", 
				name, keyid_colnum + 1, nfields);
		}

		ndberrors_++;
		pdef->nerrors_++;
		is_error = true;
		return false;
	}	

	if (total_rows + ntuples > (int)MAX_ONE_ALERT_ROWS) {
		if (total_rows < (int)MAX_ONE_ALERT_ROWS) {
			ntuples = MAX_ONE_ALERT_ROWS - total_rows;
		}	
		else {
			return false;
		}
	}	

	if (total_rows == 0) {
		total_rows += ntuples;
		
		for (int col = 0; col < nfields; ++col) {
			const char	*pfname = PQfname(pres, col);

			if (!pfname) {
				break;
			}	

			// Validate colarr
			if (strcmp(pfname, colarr[col].dbcolname)) {
				if (pdef->nerrors_ < 3 || gdebugexecn >= 1) {
					WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Shyama Alert \'%s\' : Invalid DB Column name seen : %s instead of %s", 
						name, pfname, colarr[col].dbcolname);
				}

				ndberrors_++;
				pdef->nerrors_++;
				is_error = true;
				return false;
			}	

			if ((colarr[col].dbstrtype == DB_STR_OCHAR) && (PG_BPCHAROID != PQftype(pres, col))) {
				if (pdef->nerrors_ < 3 || gdebugexecn >= 1) {
					WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Shyama Alert \'%s\' : Invalid DB Column type seen : %d instead of %d", 
						name, PQftype(pres, col), PG_BPCHAROID);
				}

				ndberrors_++;
				pdef->nerrors_++;
				is_error = true;
				return false;
			}	
		}
	}
	else {
		total_rows += ntuples;
	}	

	uint64_t			currtusec = get_usec_time();
	time_t				tcurr = currtusec/GY_USEC_PER_SEC;

	for (int row = 0; row < ntuples; ++row) {
		uint64_t			keyid = 0;
		SHALERT_STATS			*pstat = nullptr;
		uint16_t			numhits;
		bool				is_fired = false, isnew = false;

		if (!defid_key) {
			int			len = PQgetlength(pres, row, keyid_colnum);

			if (len == 0) {
				continue;
			}	
			
			const char		*pdata = PQgetvalue(pres, row, keyid_colnum);

			keyid = gy_cityhash64(pdata, len);
		}	
		else {
			keyid = pdef->adef_id_;
		}	

		auto			it = pdef->astat_tbl_.find(keyid);

		if (it == pdef->astat_tbl_.end()) {
			numhits = 1;
			is_fired = (1 == pdef->numcheckfor_);
	
			pstat = (decltype(pstat))mempool_.malloc();

			if (!pstat) {
				ndbskips_++;
				continue;
			}	

			new (pstat) SHALERT_STATS(keyid, pdef, tcurr, pdef->numcheckfor_, is_fired ? SHALERT_FIRED : SHALERT_PENDING, pdef->asubsys_);

			auto			puniq = std::unique_ptr<SHALERT_STATS, SHADEL>(pstat, mempool_);

			auto			[kit, ktrue] = pdef->astat_tbl_.try_emplace(keyid, std::move(puniq));

			pstat->tnextchkusec_ = pdef->get_nextcheck_tusec(currtusec, numhits);

			try {
				atimemap_.emplace(pstat->tnextchkusec_, pstat);
			}
			catch(...) {
				pdef->astat_tbl_.erase(kit);
				is_error = true;
				return false;
			}	

			DEBUGEXECN(5, 
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW_UNDERLINE, "Shyama Alert : New DB Alert Object of Alert ID %08x for Definition \'%s\' : "
					"Total Timemap entries %lu\n", pstat->alertid_, name, atimemap_.size());
			);

			isnew = true;

			if (!is_fired) {
				continue;
			}	
		}	
		else {
			pstat = it->second.get();

			if (!pstat) {
				pdef->astat_tbl_.erase(it);
				continue;
			}	

			if (pstat->tquery_start_ == tquery_start_) {
				// We hit a case where multiple rows with the same key in same query resultset. Need to skp this row
				continue;
			}

			pstat->tquery_start_ = tquery_start_;

			pstat->numhits_++;
			numhits = pstat->numhits_;

			time_t			toldlasthit = pstat->tlast_hit_;

			if (numhits > 1 && pstat->numcheckfor_ > 1 && ((toldlasthit + 30 < pdef->tlast_query_) || (toldlasthit + 2 * pdef->query_interval_sec_ + 10 <= tcurr))) {
				// Flapping Alert : Reset checks

				DEBUGEXECN(15, 
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW_UNDERLINE, "Shyama Alert : Flapping DB Alert seen for Alert ID %08x of Definition \'%s\' : "
						"numcheckfor_ %u, numhits %u, Time since last hit %ld sec\n", 
						pstat->alertid_, name, pstat->numcheckfor_, numhits, tcurr - toldlasthit);
				);

				pstat->numhits_ = 1;
			}	
			else if (pstat->numhits_ >= pdef->numcheckfor_) {
				// Reset count
				pstat->numhits_ = 1;
				is_fired = true;
			}	

			pstat->tlast_hit_ = tcurr;
		}	
	
		time_t			tlast_alert = pstat->tlast_alert_;

		if (is_fired && (tlast_alert == 0 || tlast_alert + pdef->repeataftersec_ < tcurr)) {
			
			if (tlast_alert == 0) {
				pstat->state_ 		= SHALERT_FIRED;
				pstat->tforce_close_ 	= tcurr + pdef->forceclosesec_;

				ndbalerts_++;
			}
			else if (pdef->repeataftersec_ == 0) {
				// No repeat alerts
				continue;
			}	
			else {
				ndbrepeats_++;
				pstat->nrepeats_++;
			}	

			STACK_JSON_WRITER<8192, 4096>	writer;

			writer.StartObject();

			for (int col = 0; col < nfields; ++col) {
				const char		*pfname = PQfname(pres, col);

				if (!pfname) {
					break;
				}	

				if (colarr[col].szjson == 0) {
					// Ignore this field
					continue;
				}	

				const char 		*pdata;
				int			len = PQgetlength(pres, row, col), rlen;

				if (len == 0) {
					if (true == PQgetisnull(pres, row, col)) {
						// Ignore Null columns
						continue;
					}	

					pdata = "";
				}
				else {
					pdata = PQgetvalue(pres, row, col);
				}

				if (len && colarr[col].dbstrtype == DB_STR_OCHAR) {
					rlen = get_rtrim_len(pdata, len);
				}
				else {
					rlen = len;
				}	

				if (colarr[col].dboper) {
					auto p = colarr[col].dboper(pdata, rlen, tbuf, sizeof(tbuf));

					pdata = p.first;
					rlen = p.second;
				}	
				
				writer.Key(colarr[col].jsonfield, colarr[col].szjson);

				if ((colarr[col].jsontype != JSON_STRING) || (colarr[col].dbstrtype == DB_RAW_STRING)) {
					writer.RawValue(pdata, rlen, rapidjson::kNumberType);
				}
				else {
					writer.String(pdata, rlen);
				}
			}	

			writer.EndObject();

			const char		*pstackjson = writer.get_string();
			size_t			szjson = writer.get_size() + 1;

			ALERT_STAT_INFO		astat(tcurr, pstat->alertid_, pdef->adef_id_, AHDLR_SHYAMA, pdef->asubsys_, numhits, pdef->numcheckfor_, pstat->nrepeats_, 
								false /* isrealtime */, 0);

			send_alert_info(astat, pstackjson, szjson);

			pstat->tlast_alert_ = tcurr;
			
			if (pdef->repeataftersec_ > 0) {
				pstat->trepeat_alert_ = tcurr + pdef->repeataftersec_;
			}
			else {
				pstat->trepeat_alert_ = 0;
			}	
		}

		if (isnew) {
			continue;
		}	

		uint64_t		oldtusec = pstat->tnextchkusec_, newtusec = pdef->get_nextcheck_tusec(currtusec, is_fired ? 1 /* reset */ : pstat->numhits_);

		pstat->tnextchkusec_  	= newtusec;

		auto 			range = atimemap_.equal_range(oldtusec);
		
		for (auto it = range.first; it != range.second; ++it) {
			if (it->second == pstat) {
				auto			mnode = atimemap_.extract(it);

				if (bool(mnode)) {
					mnode.key() = newtusec;
					atimemap_.insert(std::move(mnode));
				}	

				break;
			}
		}	
	}	

	return true;
}

bool SHALERT_HDLR::send_alert_info(comm::ALERT_STAT_INFO & astat, const char *pjson, size_t szjson)
{
	using UNIQ_DATA			= SHCONN_HANDLER::UNIQ_DATA;
	using L2_PARAMS			= SHCONN_HANDLER::L2_PARAMS;

	astat.lenjson_			= szjson;
	astat.set_padding_len();

	auto				puniq = std::make_unique<char []>(astat.get_elem_size());
	char				*pstart = puniq.get();

	std::memcpy(pstart, &astat, sizeof(astat));
	std::memcpy(pstart + sizeof(astat), pjson, szjson);

	UNIQ_DATA			udata(std::move(puniq), astat.get_elem_size(), NOTIFY_ALERT_STAT_INFO);	

	L2_PARAMS			*palert = gshconnhdlr->pl2_alert_arr_;
	bool				bret;

	bret = palert->pmpmc_->write(std::move(udata));

	if (!bret) {
		npoolskips_++;
	}	

	return bret;
}	

bool SHALERT_HDLR::send_alert_close(uint64_t alertid, uint32_t adef_id, time_t tlast_hit, time_t tcurr, bool is_force_close, bool isrealtime)
{
	using UNIQ_DATA			= SHCONN_HANDLER::UNIQ_DATA;
	using L2_PARAMS			= SHCONN_HANDLER::L2_PARAMS;

	ALERT_STAT_CLOSE		aclose(tlast_hit, tcurr, alertid, adef_id, is_force_close, isrealtime);

	UNIQ_DATA			udata(NOTIFY_ALERT_STAT_CLOSE, &aclose, sizeof(aclose));	

	L2_PARAMS			*palert = gshconnhdlr->pl2_alert_arr_;
	bool				bret;

	bret = palert->pmpmc_->write(std::move(udata));

	if (!bret) {
		npoolskips_++;
	}	

	return bret;
	
}	

void SHALERT_HDLR::run_alert_queries(time_t tcurr) noexcept
{
	try {
		time_t				tquery_start;
		int				nqueries = 0;
		bool				bret;

		if (new_alerts_disabled(tcurr)) {
			return;
		}	

		for (auto it = adbdeftbl_.begin(); it != adbdeftbl_.end(); ++it) {
			auto			*pdef = it->second.get();

			if (!pdef) {
				continue;
			}	

			if (false == pdef->is_enabled()) {
				continue;
			}

			if (pdef->tnxt_query_start_ > tcurr + 1) {
				continue;
			}	

			/*
			 * We keep an offset of QRY_START_OFFSET_SEC (30 sec) for query end time to allow in flight transactions to be flushed to DB
			 */
			tquery_start			= tcurr - pdef->query_interval_sec_ - QRY_START_OFFSET_SEC;
			pdef->tnxt_query_start_		= tcurr + pdef->query_interval_sec_;

			try {
				STRING_BUFFER<48 * 1024>	strbuf;
				
				bret = pdef->get_db_query(strbuf, tquery_start, tquery_start + pdef->query_interval_sec_);

				if (!bret) {
					ngetdberrors_++;
					continue;
				}	

				DEBUGEXECN(11,
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Shyama Alert DB Handler : Executing Alert \'%s\' query : %s\n", pdef->name(), strbuf.buffer()); 
				);

				auto				pconn = dbpool_.get_conn(true /* wait_response_if_unavail */, 10000 /* max_msec_wait */, true /* reset_on_timeout */);

				if (!pconn) {
					DEBUGEXECN(1, 
						ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection for Shyama DB Alert Query for Alert \'%s\'\n", pdef->name());
					);
					
					nconnmiss_++;
					continue;
				}

				bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());

				if (bret == false) {
					DEBUGEXECN(1, 
						ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to schedule DB Shyama Alert Query for Alert \'%s\'\n", pdef->name());
					);	
					continue;
				}	
				
				pconn->set_single_row_mode();

				pconn->set_resp_cb(
					/*
					 * NOTE : Capture by value those variables defined within the for loop 
					 */
					[this, pdef, total_rows = 0, is_error = false](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
					{
						return sdb_resp_cb(conn, std::move(gyres), is_completed, total_rows, is_error, *pdef);
					}
				);

			}
			GY_CATCH_EXCEPTION(
				DEBUGEXECN(1, 
					WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while running Shyama DB Alert Query for Alert \'%s\' : %s\n", 
						pdef->name(), GY_GET_EXCEPT_STRING);
				);	
			);
		}	

		dbpool_.wait_all_responses(30'000, 50'000);

	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, 
			WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while running Shyama DB Alert Queries : %s\n", GY_GET_EXCEPT_STRING);
		);	
	);
}	

void SHALERT_HDLR::validate_stats(time_t tcurr, bool isrt) noexcept
{
	try {
		const time_t			tmin_validate = tcurr - 150;
		int				ndefs = 0, ndefsenabled = 0, nastats = 0, nerase = 0;

		auto				& deftbl = (isrt ? artdeftbl_ : adbdeftbl_);

		for (const auto & [adefid, pdefelem] : deftbl) {
			if (!pdefelem) {
				continue;
			}

			auto			pdef = pdefelem.get();
			if (!pdef) {
				continue;
			}	

			ndefs++;
			ndefsenabled += pdef->is_enabled();
			nastats += pdef->astat_tbl_.size();
			
			for (auto it = pdef->astat_tbl_.begin(); it != pdef->astat_tbl_.end();) {
				auto			*pstat = it->second.get();
				
				if (pstat && pstat->tlast_validate_ < tmin_validate) {
					nerase++;
					it = pdef->astat_tbl_.erase(it);
					continue;
				}	

				++it;
			}	
		}	

		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Shyama Alert Handler : %s Definition Stats : %d Total Alert Defs, %d Enabled Defs, %d Alert Stats allocated, "
				"%d Alert Stats Deleted by Reference Time Out\n", isrt ? "RT" : "DB", ndefs, ndefsenabled, nastats, nerase);
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while checking Shyama Alerts Stat entries : %s\n", GY_GET_EXCEPT_STRING);
	);
}	

void SHALERT_HDLR::print_stats(int64_t tdiff, time_t tcurr) noexcept
{
	STRING_BUFFER<1024>		strbuf;

	strbuf << "Stats for the last " << tdiff << " secs : " 
		<< nrtalerts_ - lastnrtalerts_ << " New RT Alerts, "  << nrtrepeats_ - lastnrtrepeats_ << " Repeat RT Alerts, "
		<< ndbalerts_ - lastndbalerts_ << " New DB Alerts, "  << ndbrepeats_ - lastndbrepeats_ << " Repeat DB Alerts, "
		<< ndbskips_ - lastndbskips_ << " Skipped Alerts, " 
		<< "\n\t\t\t" << npoolskips_ - lastnpoolskips_ << " Skipped due to Pool Blocks, " 
		<< ndberrors_ - lastndberrors_ << " DB Alert Query Issues, " 
		<< ngetdberrors_ - lastngetdberrors_ << " DB Query String Overflows, "
		<< nconnmiss_ - lastnconnmiss_ << " DB Connection Issue by long exec time, "
		<< nalertclose_ - lastnalertclose_ << " Close Alerts sent, " << nforceclose_ - lastnforceclose_ << " Force Closed Alerts ";
	
	strbuf  << "\n\n\t\t\tCumulative Alert Stats : " 
		<< nrtalerts_ << " Total RT Alerts, " << nrtrepeats_ << " Repeat RT Alerts, "
		<< ndbalerts_ << " Total DB Alerts, " << ndbrepeats_ << " Repeat DB Alerts, "
		<< ndbskips_ << " Skipped Alerts, " << npoolskips_ << " Skipped due to Pool Blocks, "
		<< ndberrors_ << " DB Alert Query Issues, " 
		<< "\n\t\t\t" << ngetdberrors_ << " DB Query String Overflows, "
		<< nconnmiss_ << " DB Connection Issue by long exec time, "
		<< nalertclose_ << " Close Alerts sent, " << nforceclose_ << " Force Closed Alerts ";

	strbuf	<< "\n\n\t\t\tCurrent RT Alert definitions : " << artdeftbl_.size() << ", Current DB Alert definitions : " << adbdeftbl_.size() 
		<< ", Timemap Entries : " << atimemap_.size();

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Shyama Alert Stats : %s\n\n", strbuf.buffer());

	lastnrtalerts_			= nrtalerts_;
	lastnrtrepeats_			= nrtrepeats_;
	lastndbalerts_			= ndbalerts_;
	lastndbrepeats_			= ndbrepeats_;
	lastndbskips_			= ndbskips_;
	lastnpoolskips_			= npoolskips_;
	lastndberrors_			= ndberrors_;
	lastngetdberrors_		= ngetdberrors_;
	lastnconnmiss_			= nconnmiss_;
	lastnalertclose_		= nalertclose_;
	lastnforceclose_		= nforceclose_;
}	


void SHALERT_HDLR::validate_timemap(time_t tcurr, bool check_all) noexcept
{
	try {
		const uint64_t			currusec = tcurr * GY_USEC_PER_SEC, minusec = currusec + (check_all * GY_USEC_PER_YEAR);
		size_t				nelems = 0, nchecks = 0;

		/*
		 * NOTE : Please do not call any method which may later call aother function resulting in erasing of
		 * elements from atimemap_ as this may result in nextit becoming invalid.
		 */

		for (auto it = atimemap_.begin(), nextit = it; it != atimemap_.end(); it = nextit) {

			++nextit;

			uint64_t		tusec = it->first;
			auto			*pstat = it->second;

			if (tusec >= minusec + GY_USEC_PER_SEC) {
				break;
			}	
			
			if (nchecks++ > MAX_TOTAL_ALERTS_PER_HOUR * 10) {
				break;
			}	
			
			/*
			 * We can safely dereference pstat as it is allocated from mempool_ and use after free is fine
			 */
			if (gy_unlikely(!pstat || pstat->is_deleted())) {
				// We missed deleting this entry
				atimemap_.erase(it);
				continue;
			}	
			else if (pstat->tnextchkusec_ > tusec) {
				// Extra entries created
				atimemap_.erase(it);
				continue;
			}	

			++nelems;

			time_t			tlast_hit = pstat->tlast_hit_;
			SHALERTDEF 		*pdef = nullptr;

			if (pstat->pdef_ && true == pstat->pdef_->is_valid()) {
				pdef = pstat->pdef_;
			}

			if (pdef == nullptr) {
				atimemap_.erase(it);
				continue;
			}	

			pstat->tlast_validate_	= tcurr;

			if ((pdef->is_realtime() && tlast_hit + pdef->get_rt_max_multi_iter_sec() <= tcurr) || 
				(!pdef->is_realtime() && ((tlast_hit + 30 < pdef->tlast_query_) || (tlast_hit + 2 * pdef->query_interval_sec_ + 10 <= tcurr)))) {

				if (pstat->state_ != SHALERT_PENDING) {
					send_alert_close(pstat->alertid_, pdef->adef_id_, tlast_hit, tcurr, false /* is_force_close */, pdef->is_realtime());

					nalertclose_++;
				}

				pdef->astat_tbl_.erase(pstat->id_);

				GY_CC_BARRIER();

				DEBUGEXECN(5, 
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW_UNDERLINE, "Shyama Alert : Erasing by hit timeout for Alert for Alert ID %08x of Definition \'%s\' : "
						"numcheckfor %u, numhits %u, Time since last hit %ld sec\n", 
						pstat->alertid_, pdef->name(), pstat->numcheckfor_, pstat->numhits_, tcurr - tlast_hit);
				);

				atimemap_.erase(it);

				continue;
			}	
			
			if (pstat->tlast_alert_ > 0 && tcurr >= pstat->tforce_close_) {
				send_alert_close(pstat->alertid_, pdef->adef_id_, tlast_hit, tcurr, true /* is_force_close */, pdef->is_realtime());

				nalertclose_++;
				nforceclose_++;

				DEBUGEXECN(5, 
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW_UNDERLINE, "Shyama Alert : Erasing by Alert Expiry for Alert for Alert ID %08x of Definition \'%s\' : "
						"numcheckfor %u, numhits %u, Time since last hit %ld sec\n", 
						pstat->alertid_, pdef->name(), pstat->numcheckfor_, pstat->numhits_, tcurr - tlast_hit);
				);

				pdef->astat_tbl_.erase(pstat->id_);

				GY_CC_BARRIER();

				atimemap_.erase(it);

				continue;
			}

			if (check_all && tusec > currusec + GY_USEC_PER_SEC) {
				continue;
			}	

			uint8_t			numhits = pstat->numhits_;				

			pstat->tnextchkusec_ 	= pdef->get_nextcheck_tusec(currusec, numhits >= pstat->numcheckfor_ ? 1 /* reset */ : numhits);

			auto			oldit = it;
			auto			mnode = atimemap_.extract(oldit);

			if (bool(mnode)) {
				mnode.key() = pstat->tnextchkusec_;
				atimemap_.insert(std::move(mnode));
			}	
		}	
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while checking Shyama Alerts Time Map entries : %s\n", GY_GET_EXCEPT_STRING);
	);
}

void SHALERT_HDLR::add_new_def(SHALERT_MSG & emsg, time_t tcurr) noexcept
{
	try {
		if (emsg.adef_id_ == 0 || !emsg.msg_ || !emsg.lenmsg_) {
			return;
		}	

		JSON_DOCUMENT<16 * 1024, 8192>	doc;
		auto				& jdoc = doc.get_doc();
		char				*pjson = emsg.msg_.get(), *pendptr = emsg.msg_.get() + emsg.lenmsg_;
		bool				bret;

		if (*(pendptr - 1) == 0) {
			jdoc.ParseInsitu(pjson);	
		}
		else {
			jdoc.Parse(pjson, pendptr - pjson);
		}	

		if (jdoc.HasParseError()) {
			const char		*perrorstr = rapidjson::GetParseError_En(jdoc.GetParseError());

			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Shyama Alerts : Invalid New DB Alert Definition : Error at json offset %lu : Error is \'%s\'\n\n", 
				jdoc.GetErrorOffset(), perrorstr);

			return;
		}	
		
		// Delete all existing Alert Stats if existing def
		set_alert_state(emsg.adef_id_, emsg.isrealtime_, tcurr, ALERT_ADEF_DELETE, ADEFSTATE_DISABLED);

		SHALERTDEF			*pdef;
		auto				& adeftbl = (emsg.isrealtime_ ? artdeftbl_ : adbdeftbl_);
		
		pdef = (SHALERTDEF *)defpool_.malloc();

		if (!pdef) {
			GY_THROW_EXCEPTION("Shyama Alerts : Failed to allocate DB alert definition as Max definition objects exceeded : Curent Defs size %lu", adeftbl.size());
		}	

		try {
			new (pdef) SHALERTDEF(jdoc, jdoc.GetAllocator(), emsg.adef_id_, tcurr);
		}	
		catch(...) {
			defpool_.free(pdef);
			throw;
		}	

		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Shyama Alerts : adding new %s Alert Definition \'%s\'\n", emsg.isrealtime_ ? "RT" : "DB", pdef->name());

		auto				puniq = std::unique_ptr<SHALERTDEF, SHADEL>(pdef, defpool_);

		adeftbl.try_emplace(emsg.adef_id_, std::move(puniq));
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while adding new Shyama Alert def : %s\n\n", GY_GET_EXCEPT_STRING);
	);
}	

void SHALERT_HDLR::set_alert_state(uint32_t adef_id, bool is_realtime, time_t tcurr, ALERT_MSG_TYPE type, ADEF_STATE_E state) noexcept
{
	try {
		if (adef_id == 0) {
			return;
		}	

		auto				& adeftbl = (is_realtime ? artdeftbl_ : adbdeftbl_);

		auto				ait = adeftbl.find(adef_id);	// Locking not needed as only this thread is a writer

		if (ait != adeftbl.end()) {
			auto 				pdef = ait->second.get();

			if (pdef) {
				if ((state == ADEFSTATE_ENABLED) && (false == pdef->is_enabled())) {
					pdef->set_enabled();
				}

				pdef->set_state(state);

				if (false == pdef->is_enabled()) {
					pdef->set_disabled();
				}	

				if (type >= ALERT_ADEF_DISABLE) {
					handle_def_reset(pdef, type == ALERT_ADEF_DELETE, pdef->is_muted_state());
				}

				if (type == ALERT_ADEF_DELETE) {
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Shyama Alerts : Deleting Alert Definition \'%s\'\n", pdef->name());

					adeftbl.erase(ait);
				}
			}	
		}
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while setting state of Shyama Alert def : %s\n\n", GY_GET_EXCEPT_STRING);
	);
}

void SHALERT_HDLR::handle_def_reset(SHALERTDEF *pdef, bool is_deleted, bool only_pending) 
{
	if (is_deleted) {
		pdef->set_deleted();
	}

	const auto deltimes = [&](SHALERT_STATS *pstat, uint64_t key) 
	{
		auto 			range = atimemap_.equal_range(key);
		
		for (auto it = range.first; it != range.second; ++it) {
			if (it->second == pstat) {
				atimemap_.erase(it);
				return;
			}
		}	
	};	

	auto			& astat_tbl = pdef->astat_tbl_;

	for (auto it = astat_tbl.begin(); it != astat_tbl.end(); ) {
		auto			*pstat = it->second.get();
		
		if (only_pending && SHALERT_PENDING != pstat->state_) {
			++it;
			continue;
		}	

		deltimes(pstat, pstat->tnextchkusec_);

		it = astat_tbl.erase(it);
	}
}	


void SHADEL::operator()(SHALERTDEF *pdef) const noexcept
{
	if (pdef) {
		pdef->~SHALERTDEF();
		POOL_ALLOC::dealloc_free(pdef, &mempool_);
	}
}	

void SHADEL::operator()(SHALERT_STATS *pstat) const noexcept
{
	if (pstat) {
		pstat->~SHALERT_STATS();
		POOL_ALLOC::dealloc_free(pstat, &mempool_);
	}
}	


bool SHALERT_HDLR::send_new_alertdef(time_t tmsg, const char *pjson, size_t lenjson, uint32_t adefid, SUBSYS_CLASS_E asubsys, bool is_realtime)
{
	auto				pmsg = std::make_unique<char []>(lenjson);

	std::memcpy(pmsg.get(), pjson, lenjson);

	SHALERT_MSG			msg(tmsg, std::move(pmsg), lenjson, SHALERT_MSG::MsgNewDef, adefid, asubsys, is_realtime);
	bool				bret;

	bret = aqueue_.write(std::move(msg));

	if (!bret) {
		WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Alertmgr : Failed to send new Shyama Alert Definition due to pool block...\n");
	}	

	return bret;
}	

bool SHALERT_HDLR::send_alertdef_update(uint32_t adef_id, ALERT_MSG_TYPE type, bool isrealtime) noexcept
{
	SHALERT_MSG::MsgType		msgtype;

	switch (type) {
	
	case ALERT_ADEF_ENABLE		: msgtype = SHALERT_MSG::MsgDefEnable; break;

	case ALERT_ADEF_DISABLE		: msgtype = SHALERT_MSG::MsgDefDisable; break;

	case ALERT_ADEF_MUTE		: msgtype = SHALERT_MSG::MsgDefMute; break;

	case ALERT_ADEF_SILENCE		: msgtype = SHALERT_MSG::MsgDefSilence; break;

	case ALERT_ADEF_INHIBIT		: msgtype = SHALERT_MSG::MsgDefInhibit; break;

	case ALERT_ADEF_DELETE		: msgtype = SHALERT_MSG::MsgDefDelete; break;

	default 			: return false;

	}	

	SHALERT_MSG			msg(adef_id, msgtype, isrealtime);
	bool				bret;

	bret = aqueue_.write(std::move(msg));

	if (!bret) {
		DEBUGEXECN(1,
			WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Alertmgr : Failed to send Shyama Alert Definition Update due to pool block...\n");
		);
	}	

	return bret;

}	

} // namespace shyama
} // namespace gyeeta

