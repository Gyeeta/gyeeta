
#include			"gy_malerts.h"
#include			"gy_mconnhdlr.h"
#include			"gymadhava.h"

using namespace gyeeta::comm;

namespace gyeeta {
namespace madhava {

using OptStackJsonWriter	= std::optional<STACK_JSON_WRITER<8192, 4096>>;

static MALERT_HDLR 		*galerthdlr = nullptr;
static uint64_t			g_madhava_id = 0;

MRT_ALERT_STATS::MRT_ALERT_STATS(uint64_t id, MRT_ADEF_ELEM *pdefelem, MRT_ALERTDEF *pdef, time_t tcurr, uint8_t numcheckfor, MALERT_STATE_E state, \
					SUBSYS_CLASS_E asubsys, const GY_MACHINE_ID machid) noexcept
	: tstart_(tcurr), machid_(machid), id_(id), pdefelem_(pdefelem), adef_id_(pdef->adef_id_), 
	subsys_inter_sec_(pdef->subsys_inter_sec_), multi_iter_chk_sec_(pdef->multi_iter_chk_sec_), asubsys_(asubsys), numcheckfor_(numcheckfor), state_(state)
{
	alertid_ = ALERT_STAT_HASH(machid_, id_, adef_id_, g_madhava_id, tcurr).get_hash();	
}

MRT_ALERT_STATS::MRT_ALERT_STATS(const GY_MACHINE_ID machid, MRT_ADEF_ELEM *pdefelem, MRT_ALERTDEF *pdef, time_t tcurr, uint8_t numcheckfor, \
					MALERT_STATE_E state, SUBSYS_CLASS_E asubsys) noexcept
	: tstart_(tcurr), machid_(machid), pdefelem_(pdefelem), adef_id_(pdef->adef_id_), 
	subsys_inter_sec_(pdef->subsys_inter_sec_), multi_iter_chk_sec_(pdef->multi_iter_chk_sec_), asubsys_(asubsys), numcheckfor_(numcheckfor), state_(state)
{
	alertid_ = ALERT_STAT_HASH(machid_, id_, adef_id_, g_madhava_id, tcurr).get_hash();	
}

MDB_ALERT_STATS::MDB_ALERT_STATS(uint64_t id, MDB_ALERTDEF *pdef, time_t tcurr, uint8_t numcheckfor, MALERT_STATE_E state, SUBSYS_CLASS_E asubsys) noexcept
	: 
	tstart_(tcurr), id_(id), pdef_(pdef), adef_id_(pdef->adef_id_), subsys_inter_sec_(pdef->subsys_inter_sec_), asubsys_(asubsys), numcheckfor_(numcheckfor), state_(state)
{
	alertid_ = ALERT_STAT_HASH({}, id_, adef_id_, g_madhava_id, tcurr).get_hash();	
}

// For realtime alerts
MRT_ALERTDEF::MRT_ALERTDEF(GEN_JSON_VALUE & jdoc, JSON_ALLOCATOR & allocator, uint32_t adef_id, time_t tcurr)
	: ALERTDEF_COMMON(jdoc, allocator, adef_id, tcurr)
{
	switch (akeytype_) {
	
	case AKEY_MACHID	:	avar_tbl_.emplace<MRT_ALERT_MACHID_TBL>(1); break;

	case AKEY_ID		: 	avar_tbl_.emplace<MRT_ALERT_ID_TBL>(1); break;

	default			:	GY_THROW_EXCEPTION("Alert Definition : Invalid subsystem specified for Real Time Alerts : %s", pasubsys_);
	}	

	if (subsys_inter_sec_ < 60) { 
		/*
		 * For SUBSYS_PROCSTATE or SUBSYS_EXTPROCSTATE, we need to set the multi_iter_chk_sec_ to at least 23 sec as the Partha process
		 * will limit Procstate events for low utilization processes.
		 */
		if (asubsys_ != SUBSYS_PROCSTATE && asubsys_ != SUBSYS_EXTPROCSTATE) {
			multi_iter_chk_sec_ = subsys_inter_sec_ + std::min<uint32_t>((subsys_inter_sec_ >> 1) + 1, 10);
		}
		else {
			multi_iter_chk_sec_ = std::max<uint32_t>(2 * subsys_inter_sec_, 23);
		}	
	}
	else {
		multi_iter_chk_sec_ = subsys_inter_sec_ + 30;
	}	

}	

// For AFILTER_DB_QUERY
MDB_ALERTDEF::MDB_ALERTDEF(GEN_JSON_VALUE & jdoc, JSON_ALLOCATOR & allocator, uint32_t adef_id, time_t tcurr)
	: ALERTDEF_COMMON(jdoc, allocator, adef_id, tcurr)
{
	if (false == is_enabled()) {
		set_disabled();
	}	
}	


bool MRT_ALERT_STATS::del_from_def_table_locked(MRT_ALERTDEF *pdef)
{
	bool			bret = false;	

	if (!pdef) {
		/*
		 * We can safely dereference pdefelem_ as it is allocated from defpool_ and use after free is fine
		 */
		if (pdefelem_ && true == pdefelem_->is_valid()) {
			pdef = pdefelem_->get_def();

			if (!pdef) {
				return false;
			}	
		}	
		else {
			return false;
		}
	}

	if (pdef->has_id_tbl()) {
		if (auto ptbl = pdef->get_id_def_tbl(); ptbl) {
			bret = ptbl->delete_elem_locked(this);
		}	
	}
	else if (auto ptbl = pdef->get_machid_def_tbl(); ptbl) {
		bret = ptbl->delete_elem_locked(this);
	}	
	
	return bret;
}	

int MCONN_HANDLER::handle_alert_mgr(L2_PARAMS & param)
{
	try {
		MPMCQ_COMM			* const pl2pool = param.pmpmc_;
		const uint32_t			l2_thr_num = param.thr_num_;
		const pid_t			tid = gy_gettid();
		uint64_t			curr_usec_clock = get_usec_clock(), last_rtchk_clock = curr_usec_clock;
		bool				bret;
		MALERT_HDLR			& alerthdlr = *palerthdlr_;

		do {
			gy_thread_rcu().gy_rcu_thread_offline();

			EV_NOTIFY_ONE		ev;

			bret = pl2pool->tryReadUntil(std::chrono::steady_clock::now() + std::chrono::seconds(30), ev);

			try {
				if (bret && NOTIFY_DB_WRITE_ARR != ev.get_type()) {
					DEBUGEXECN(11, WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Invalid Alert Notify seen\n"););
					bret = false;
				}

				if (bret == true) {
					DB_WRITE_ARR		& dbarr = ev.data_.dbwrarr_;

					if (false == dbarr.validate()) {
						goto nxt1;
					}

					for (size_t i = 0; i < dbarr.ndbs_; ++i) {
						auto 			& dbone		= dbarr.dbonearr_[i];

						uint8_t			*prdbuf 	= dbone.pwrbuf_;
						COMM_HEADER		*phdr 		= (COMM_HEADER *)prdbuf;
						uint8_t			*pendptr	= prdbuf + phdr->get_act_len();	
						const bool		is_last_elem	= (i + 1 == dbarr.ndbs_);
						EVENT_NOTIFY		*pevtnot;

						switch (phdr->data_type_) {

						case COMM_EVENT_NOTIFY :
					
							pevtnot = (EVENT_NOTIFY *)(phdr + 1);

							switch (pevtnot->subtype_) {

							case NOTIFY_SM_ALERT_ADEF_NEW :
								try {
									SM_ALERT_ADEF_NEW 	*pdef = (SM_ALERT_ADEF_NEW *)(pevtnot + 1);
									int			nevents = pevtnot->nevents_;

									alerthdlr.handle_adef_new(pdef, nevents, pendptr);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling New Alert Def Notify : %s\n", GY_GET_EXCEPT_STRING);
								);

								break;
												

							case NOTIFY_SM_ALERT_ADEF_UPD :
								try {
									SM_ALERT_ADEF_UPD 	*pdef = (SM_ALERT_ADEF_UPD *)(pevtnot + 1);
									int			nevents = pevtnot->nevents_;

									alerthdlr.handle_adef_upd(pdef, nevents, pendptr);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Alert Def Update Notify : %s\n", GY_GET_EXCEPT_STRING);
								);

								break;


							case NOTIFY_SM_ALERT_STAT_DISABLE :
								try {
									auto		 	*pstat = (SM_ALERT_STAT_DISABLE *)(pevtnot + 1);

									alerthdlr.handle_astat_disable(*pstat);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Alert Stat Disable Notify : %s\n", GY_GET_EXCEPT_STRING);
								);

								break;

							default :
								DEBUGEXECN(11, WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Invalid Alert Event Type seen\n"););
								break;
							
							}

							break;

						default :
							DEBUGEXECN(11, WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Invalid Alert Cmd Type seen\n"););
							break;
						}	
					}	
				}

nxt1 :
				curr_usec_clock = get_usec_clock();

				if (curr_usec_clock - last_rtchk_clock >= 60 * GY_USEC_PER_SEC) {

					// Update Partha RT Alert Vecs
					alerthdlr.check_partha_rtalert_defs(this, curr_usec_clock);

					last_rtchk_clock = get_usec_clock();
				}	
			}			
			GY_CATCH_EXCEPTION(
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught in Alert Manager while handling messages : %s\n\n", GY_GET_EXCEPT_STRING);
			);

		} while (true);	

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught in %s : %s\n\n", param.descbuf_, GY_GET_EXCEPT_STRING);
		return -1;
	);
}

int MCONN_HANDLER::alert_realtime_thread() noexcept
{
	MALERT_HDLR			*palerthdlr = palerthdlr_;

	palerthdlr->rt_thr_.set_thread_init_done();

	do {
		try {
			palerthdlr->rthdlr_.handle_rt_alerts(palerthdlr);
		}
		GY_CATCH_EXCEPTION(
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught in Realtime Alert Handler thread : %s\n\n", GY_GET_EXCEPT_STRING);
		);

	} while (true);
	
	return -1;
}	

int MCONN_HANDLER::alert_db_thread(void *arg) noexcept
{
	MDB_ALERT_HDLR			*pdbhdlr = static_cast<MDB_ALERT_HDLR *>(arg);
	MALERT_HDLR			*palerthdlr = palerthdlr_;

	if (pdbhdlr == &palerthdlr->dbhdlr1_) {
		palerthdlr->db_thr1_.set_thread_init_done();
	}	
	else if (pdbhdlr == &palerthdlr->dbhdlr2_) {
		palerthdlr->db_thr2_.set_thread_init_done();
	}
	else {
		ERRORPRINTCOLOR(GY_COLOR_RED, "Internal Error : Invalid argument passed to alert_db_thread. Thread exiting...\n");
		return -1;
	}

	do {
		try {
			pdbhdlr->handle_db_alerts(palerthdlr);
		}
		GY_CATCH_EXCEPTION(
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught in DB Alert Handler thread : %s\n\n", GY_GET_EXCEPT_STRING);
		);
		
	} while (true);
	
	return -1;
}	

bool MRT_ALERTDEF::is_astat_msg(uint64_t id, MALERT_MSG & amsg, time_t tcurr, GY_MACHINE_ID machid)
{
	bool				isalert = false, bret;
	uint8_t				numhits = 1;

	const auto lam = [&](MRT_ALERT_STATS *pstat, void *, void *) -> CB_RET_E
	{
		numhits = pstat->numhits_.load(mo_relaxed) + 1;

		time_t			toldlasthit = pstat->tlast_hit_.load(mo_relaxed);

		pstat->tlast_hit_.store(tcurr, mo_relaxed);

		if (numhits > 1 && pstat->numcheckfor_ > 1 && toldlasthit + pstat->multi_iter_chk_sec_ <= tcurr) {
			// Flapping Alert : Reset checks

			DEBUGEXECN(15, 
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW_UNDERLINE, "Alert Handler : Flapping Realtime Alert seen for Alert ID %08x of Definition \'%08x\' : "
					"numcheckfor_ %u, numhits %u, Time since last hit %ld sec\n", 
					pstat->alertid_, pstat->adef_id_, pstat->numcheckfor_, pstat->numhits_.load(mo_relaxed), tcurr - toldlasthit);
			);

			pstat->numhits_.store(1, mo_relaxed);
			return CB_OK;
		}	

		if (numhits >= pstat->numcheckfor_) {
			time_t			tlast_alert = pstat->tlast_alert_.load(mo_relaxed);

			if (tlast_alert == 0 && ((pstat->tmsg_sent_ == 0) || (tcurr > pstat->tmsg_sent_ + 60))) {
				isalert = true;
				pstat->numhits_.store(numhits, mo_relaxed);
				return CB_OK;
			}	
			else if (tlast_alert == 0) {
				// Reset count as we have already sent msg 
				pstat->numhits_.store(1, mo_relaxed);
				return CB_OK;
			}	
			
			time_t			trepeat_alert = pstat->trepeat_alert_.load(mo_relaxed);

			if (tcurr >= trepeat_alert && trepeat_alert > 0) {
				isalert = true;
				pstat->numhits_.store(numhits, mo_relaxed);
				return CB_OK;
			}	

			// Reset count as we are currently in Repeat Alert Wait interval
			pstat->numhits_.store(1, mo_relaxed);
			return CB_OK;
		}	
		else {
			pstat->numhits_.store(numhits, mo_relaxed);
			return CB_OK;
		}
	};	

	if (true == has_id_tbl()) {
		auto 			ptbl = get_id_def_tbl(); 
		if (!ptbl) {
			return false;
		}

		bret = ptbl->lookup_single_elem(id, get_uint64_hash(id), lam);

		if (bret && !isalert) {
			return false;
		}	

		DEBUGEXECN(11,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN_UNDERLINE, "Realtime Alert seen for Alert Definition \'%s\'\n", name());
		);
		
		// Update amsg
		amsg.~MALERT_MSG();
	
		new (&amsg) MALERT_MSG(id, adef_id_, tcurr, numhits, asubsys_, machid);
	}
	else {
		auto 			ptbl = get_machid_def_tbl();
		if (!ptbl) {
			return false;
		}

		bret = ptbl->lookup_single_elem(machid, machid.get_hash(), lam);

		if (bret && !isalert) {
			return false;
		}	

		// Update amsg
		amsg.~MALERT_MSG();
	
		new (&amsg) MALERT_MSG(machid, adef_id_, tcurr, numhits, asubsys_);
	}	

	return true;
}	

size_t MCONN_HANDLER::hoststate_rtalert_rwlocked(PARTHA_INFO & partha, const comm::HOST_STATE_NOTIFY & hstate, time_t tcurr, const char *timebuf) noexcept
{
	try {
		size_t				nalerts = 0;
		auto				& hoststatevec = partha.rtalerts_.adef_hoststate_;
		HostStateFields			hoststatefields(partha, hstate, gmadhava_id_str_, tcurr);
		OptStackJsonWriter		writer;

		for (size_t i = 0; i < hoststatevec.size(); ++i) {
			auto			*pdef = hoststatevec[i].get();

			if (!pdef || pdef->is_deleted() || !pdef->is_enabled()) {
				continue;
			}	

			auto			popt = pdef->get_rt_options();

			if (!popt) {
				continue;
			}	

			if (CRIT_PASS != hoststatefields.filter_match(popt->get_filter_criteria())) {
				continue;
			}	

			MALERT_MSG			amsg;
			bool				bret;

			bret = pdef->is_astat_msg(partha.machine_id_, amsg, tcurr);

			if (!bret) {
				continue;
			}	

			auto [colarr, ncols]		= pdef->get_column_list();
			size_t				szjson = 0;
			const char			*pstackjson = nullptr;
			
			nalerts++;
				
			if (!bool(writer)) {
				new (&writer) (decltype(writer))(std::in_place);
			}
			else {
				writer->Reset();
			}	

			hoststatefields.print_json(colarr, ncols, writer.value(), timebuf);

			szjson = writer->get_size();
			pstackjson = writer->get_string();
			
			palerthdlr_->send_rt_amsg(std::move(amsg), pstackjson, szjson);
		}	

		return nalerts;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while checking for Host State RT Alerts : %s\n", GY_GET_EXCEPT_STRING);
		);
		
		return 0;
	);
}

size_t MCONN_HANDLER::cpumem_rtalert_rwlocked(PARTHA_INFO & partha, const CPU_MEM_STATE & cpu_mem_state, time_t tcurr, const char *timebuf) noexcept
{
	try {
		size_t				nalerts = 0;
		auto				& cpumemvec = partha.rtalerts_.adef_cpumem_;
		CpuMemFields			cpumemfields(partha, cpu_mem_state, gmadhava_id_str_, tcurr);
		OptStackJsonWriter		writer;

		for (size_t i = 0; i < cpumemvec.size(); ++i) {
			auto			*pdef = cpumemvec[i].get();

			if (!pdef || pdef->is_deleted() || !pdef->is_enabled()) {
				continue;
			}	

			auto			popt = pdef->get_rt_options();

			if (!popt) {
				continue;
			}	

			if (CRIT_PASS != cpumemfields.filter_match(popt->get_filter_criteria())) {
				continue;
			}	

			MALERT_MSG			amsg;
			bool				bret;

			bret = pdef->is_astat_msg(partha.machine_id_, amsg, tcurr);

			if (!bret) {
				continue;
			}	

			auto [colarr, ncols]		= pdef->get_column_list();
			size_t				szjson = 0;
			const char			*pstackjson = nullptr;
			
			nalerts++;
				
			if (!bool(writer)) {
				new (&writer) (decltype(writer))(std::in_place);
			}
			else {
				writer->Reset();
			}	

			cpumemfields.print_json(colarr, ncols, writer.value(), timebuf);

			szjson = writer->get_size();
			pstackjson = writer->get_string();
			
			palerthdlr_->send_rt_amsg(std::move(amsg), pstackjson, szjson);
		}	

		return nalerts;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while checking for CPU Mem State RT Alerts : %s\n", GY_GET_EXCEPT_STRING);
		);
		
		return 0;
	);
}

size_t MCONN_HANDLER::svcsumm_rtalert_rwlocked(PARTHA_INFO & partha, const LISTEN_SUMM_STATS<int> & stats, time_t tcurr, const char *timebuf) noexcept
{
	try {
		size_t				nalerts = 0;
		auto				& svcvec = partha.rtalerts_.adef_svcsumm_;
		SvcSummFields			svcsummfields(partha, stats, gmadhava_id_str_, tcurr);
		OptStackJsonWriter		writer;

		for (size_t i = 0; i < svcvec.size(); ++i) {
			auto			*pdef = svcvec[i].get();

			if (!pdef || pdef->is_deleted() || !pdef->is_enabled()) {
				continue;
			}	

			auto			popt = pdef->get_rt_options();

			if (!popt) {
				continue;
			}	

			if (CRIT_PASS != svcsummfields.filter_match(popt->get_filter_criteria())) {
				continue;
			}	

			MALERT_MSG			amsg;
			bool				bret;

			bret = pdef->is_astat_msg(partha.machine_id_, amsg, tcurr);

			if (!bret) {
				continue;
			}	

			auto [colarr, ncols]		= pdef->get_column_list();
			size_t				szjson = 0;
			const char			*pstackjson = nullptr;
			
			nalerts++;
				
			if (!bool(writer)) {
				new (&writer) (decltype(writer))(std::in_place);
			}
			else {
				writer->Reset();
			}	

			svcsummfields.print_json(colarr, ncols, writer.value(), timebuf);

			szjson = writer->get_size();
			pstackjson = writer->get_string();
			
			palerthdlr_->send_rt_amsg(std::move(amsg), pstackjson, szjson);
		}	

		return nalerts;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while checking for Svc Summ RT Alerts : %s\n", GY_GET_EXCEPT_STRING);
		);
		
		return 0;
	);
}	

size_t MCONN_HANDLER::svcinfo_rtalert_rwlocked(PARTHA_INFO & partha, const MTCP_LISTENER & listener, time_t tcurr, const char *timebuf) noexcept
{
	try {
		size_t				nalerts = 0;
		auto				& svcvec = partha.rtalerts_.adef_svcinfo_;
		SvcInfoFields			svcinfofields(partha, listener, gmadhava_id_str_, tcurr);
		OptStackJsonWriter		writer;

		for (size_t i = 0; i < svcvec.size(); ++i) {
			auto			*pdef = svcvec[i].get();

			if (!pdef || pdef->is_deleted() || !pdef->is_enabled()) {
				continue;
			}	

			auto			popt = pdef->get_rt_options();

			if (!popt) {
				continue;
			}	

			if (CRIT_PASS != svcinfofields.filter_match(popt->get_filter_criteria())) {
				continue;
			}	

			MALERT_MSG			amsg;
			bool				bret;

			bret = pdef->is_astat_msg(listener.glob_id_, amsg, tcurr, partha.machine_id_);

			if (!bret) {
				continue;
			}	

			auto [colarr, ncols]		= pdef->get_column_list();
			size_t				szjson = 0;
			const char			*pstackjson = nullptr;
			
			nalerts++;
				
			if (!bool(writer)) {
				new (&writer) (decltype(writer))(std::in_place);
			}
			else {
				writer->Reset();
			}	

			svcinfofields.print_json(colarr, ncols, writer.value(), timebuf);

			szjson = writer->get_size();
			pstackjson = writer->get_string();
			
			palerthdlr_->send_rt_amsg(std::move(amsg), pstackjson, szjson);
		}	

		return nalerts;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while checking for Svc Info RT Alerts : %s\n", GY_GET_EXCEPT_STRING);
		);
		
		return 0;
	);
}

size_t MCONN_HANDLER::svcstate_rtalert_rwlocked(PARTHA_INFO & partha, const MTCP_LISTENER & listener, time_t tcurr, const char *timebuf) noexcept
{
	try {
		size_t				nalerts = 0;
		auto				& svcvec = partha.rtalerts_.adef_svcstate_;
		ExtSvcStateFields		extsvcstatefields(partha, listener, gmadhava_id_str_, tcurr);
		SvcStateFields			& svcstatefields = extsvcstatefields.svcstatefields_;
		OptStackJsonWriter		writer;

		for (size_t i = 0; i < svcvec.size(); ++i) {
			auto			*pdef = svcvec[i].get();

			if (!pdef || pdef->is_deleted() || !pdef->is_enabled()) {
				continue;
			}	

			auto			popt = pdef->get_rt_options();

			if (!popt) {
				continue;
			}	

			if (pdef->asubsys_ != SUBSYS_EXTSVCSTATE) {
				if (CRIT_PASS != svcstatefields.filter_match(popt->get_filter_criteria())) {
					continue;
				}	
			}
			else {
				if (CRIT_PASS != extsvcstatefields.filter_match(popt->get_filter_criteria())) {
					continue;
				}	
			}	

			MALERT_MSG			amsg;
			bool				bret;

			bret = pdef->is_astat_msg(listener.glob_id_, amsg, tcurr, partha.machine_id_);

			if (!bret) {
				continue;
			}	

			auto [colarr, ncols]		= pdef->get_column_list();
			size_t				szjson = 0;
			const char			*pstackjson = nullptr;
			
			nalerts++;
				
			if (!bool(writer)) {
				new (&writer) (decltype(writer))(std::in_place);
			}
			else {
				writer->Reset();
			}	

			if (pdef->asubsys_ != SUBSYS_EXTSVCSTATE) {
				svcstatefields.print_json(colarr, ncols, writer.value(), timebuf);
			}
			else {
				extsvcstatefields.print_json(colarr, ncols, writer.value(), timebuf);
			}	

			szjson = writer->get_size();
			pstackjson = writer->get_string();
			
			palerthdlr_->send_rt_amsg(std::move(amsg), pstackjson, szjson);
		}	

		return nalerts;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while checking for Svc State RT Alerts : %s\n", GY_GET_EXCEPT_STRING);
		);
		
		return 0;
	);
}	

size_t MCONN_HANDLER::procstate_rtalert_rwlocked(PARTHA_INFO & partha, const MAGGR_TASK & task, time_t tcurr, const char *timebuf) noexcept
{
	try {
		size_t				nalerts = 0;
		auto				& procvec = partha.rtalerts_.adef_procstate_;
		ExtProcStateFields		extprocstatefields(partha, task, gmadhava_id_str_, tcurr);
		ProcStateFields			& procstatefields = extprocstatefields.procstatefields_;
		OptStackJsonWriter		writer;

		for (size_t i = 0; i < procvec.size(); ++i) {
			auto			*pdef = procvec[i].get();

			if (!pdef || pdef->is_deleted() || !pdef->is_enabled()) {
				continue;
			}	

			auto			popt = pdef->get_rt_options();

			if (!popt) {
				continue;
			}	

			if (pdef->asubsys_ != SUBSYS_EXTPROCSTATE) {
				if (CRIT_PASS != procstatefields.filter_match(popt->get_filter_criteria())) {
					continue;
				}	
			}
			else {
				if (CRIT_PASS != extprocstatefields.filter_match(popt->get_filter_criteria())) {
					continue;
				}	
			}	

			MALERT_MSG			amsg;
			bool				bret;

			bret = pdef->is_astat_msg(task.aggr_task_id_, amsg, tcurr, partha.machine_id_);

			if (!bret) {
				continue;
			}	

			auto [colarr, ncols]		= pdef->get_column_list();
			size_t				szjson = 0;
			const char			*pstackjson = nullptr;
			
			nalerts++;
				
			if (!bool(writer)) {
				new (&writer) (decltype(writer))(std::in_place);
			}
			else {
				writer->Reset();
			}	

			if (pdef->asubsys_ != SUBSYS_EXTPROCSTATE) {
				procstatefields.print_json(colarr, ncols, writer.value(), timebuf);
			}
			else {
				extprocstatefields.print_json(colarr, ncols, writer.value(), timebuf);
			}	

			szjson = writer->get_size();
			pstackjson = writer->get_string();
			
			palerthdlr_->send_rt_amsg(std::move(amsg), pstackjson, szjson);
		}	

		return nalerts;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while checking for Proc State RT Alerts : %s\n", GY_GET_EXCEPT_STRING);
		);
		
		return 0;
	);
}

size_t MCONN_HANDLER::procinfo_rtalert_rwlocked(PARTHA_INFO & partha, const MAGGR_TASK & task, time_t tcurr, const char *timebuf) noexcept
{
	try {
		size_t				nalerts = 0;
		auto				& procvec = partha.rtalerts_.adef_procinfo_;
		ProcInfoFields			procinfofields(partha, task, gmadhava_id_str_, tcurr);
		OptStackJsonWriter		writer;

		for (size_t i = 0; i < procvec.size(); ++i) {
			auto			*pdef = procvec[i].get();

			if (!pdef || pdef->is_deleted() || !pdef->is_enabled()) {
				continue;
			}	

			auto			popt = pdef->get_rt_options();

			if (!popt) {
				continue;
			}	

			if (CRIT_PASS != procinfofields.filter_match(popt->get_filter_criteria())) {
				continue;
			}	

			MALERT_MSG			amsg;
			bool				bret;

			bret = pdef->is_astat_msg(task.aggr_task_id_, amsg, tcurr, partha.machine_id_);

			if (!bret) {
				continue;
			}	

			auto [colarr, ncols]		= pdef->get_column_list();
			size_t				szjson = 0;
			const char			*pstackjson = nullptr;
			
			nalerts++;
				
			if (!bool(writer)) {
				new (&writer) (decltype(writer))(std::in_place);
			}
			else {
				writer->Reset();
			}	

			procinfofields.print_json(colarr, ncols, writer.value(), timebuf);

			szjson = writer->get_size();
			pstackjson = writer->get_string();
			
			palerthdlr_->send_rt_amsg(std::move(amsg), pstackjson, szjson);
		}	

		return nalerts;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while checking for Proc Info RT Alerts : %s\n", GY_GET_EXCEPT_STRING);
		);
		
		return 0;
	);
}

size_t MCONN_HANDLER::activeconn_rtalert_rwlocked(PARTHA_INFO & partha, const comm::ACTIVE_CONN_STATS & aconn, time_t tcurr, const char *timebuf, const MTCP_LISTENER *plistener) noexcept
{
	try {
		size_t					nalerts = 0;
		auto					& actvec = partha.rtalerts_.adef_activeconn_;
		ActiveClientConnFields			actclifields(partha, aconn, gmadhava_id_str_, SUBSYS_ACTIVECONN, tcurr);	
		std::optional<ExtActiveConnFields>	extactiveconnfields;
		OptStackJsonWriter			writer;

		if (plistener) {
			extactiveconnfields.emplace(partha, aconn, *plistener, gmadhava_id_str_, tcurr);
		}

		for (size_t i = 0; i < actvec.size(); ++i) {
			auto			*pdef = actvec[i].get();

			if (!pdef || pdef->is_deleted() || !pdef->is_enabled()) {
				continue;
			}	

			auto			popt = pdef->get_rt_options();

			if (!popt) {
				continue;
			}	

			if (pdef->asubsys_ != SUBSYS_EXTACTIVECONN) {
				if (CRIT_PASS != actclifields.filter_match(popt->get_filter_criteria())) {
					continue;
				}	
			}
			else {
				if (!extactiveconnfields) {
					continue;
				}

				if (CRIT_PASS != extactiveconnfields->filter_match(popt->get_filter_criteria())) {
					continue;
				}	
			}	

			MALERT_MSG			amsg;
			bool				bret;

			bret = pdef->is_astat_msg(aconn.listener_glob_id_, amsg, tcurr, partha.machine_id_);

			if (!bret) {
				continue;
			}	

			auto [colarr, ncols]		= pdef->get_column_list();
			size_t				szjson = 0;
			const char			*pstackjson = nullptr;
			
			nalerts++;
				
			if (!bool(writer)) {
				new (&writer) (decltype(writer))(std::in_place);
			}
			else {
				writer->Reset();
			}	

			if (pdef->asubsys_ != SUBSYS_EXTACTIVECONN) {
				actclifields.print_json(colarr, ncols, writer.value(), timebuf);
			}
			else {
				extactiveconnfields->print_json(colarr, ncols, writer.value(), timebuf);
			}	

			szjson = writer->get_size();
			pstackjson = writer->get_string();
			
			palerthdlr_->send_rt_amsg(std::move(amsg), pstackjson, szjson);
		}	

		return nalerts;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while checking for Active Conn RT Alerts : %s\n", GY_GET_EXCEPT_STRING);
		);
		
		return 0;
	);
}

size_t MCONN_HANDLER::clientconn_rtalert_rwlocked(PARTHA_INFO & partha, const comm::ACTIVE_CONN_STATS & aconn, time_t tcurr, const char *timebuf, const MAGGR_TASK * ptask) noexcept
{
	try {
		size_t					nalerts = 0;
		auto					& clivec = partha.rtalerts_.adef_clientconn_;
		ActiveClientConnFields			clientconnfields(partha, aconn, gmadhava_id_str_, SUBSYS_CLIENTCONN, tcurr);	
		std::optional<ExtClientConnFields>	extclientconnfields;
		OptStackJsonWriter			writer;

		if (ptask) {
			extclientconnfields.emplace(partha, aconn, *ptask, gmadhava_id_str_, tcurr);
		}	

		for (size_t i = 0; i < clivec.size(); ++i) {
			auto			*pdef = clivec[i].get();

			if (!pdef || pdef->is_deleted() || !pdef->is_enabled()) {
				continue;
			}	

			auto			popt = pdef->get_rt_options();

			if (!popt) {
				continue;
			}	

			if (pdef->asubsys_ != SUBSYS_EXTCLIENTCONN) {
				if (CRIT_PASS != clientconnfields.filter_match(popt->get_filter_criteria())) {
					continue;
				}	
			}
			else {
				if (!extclientconnfields) {
					continue;
				}

				if (CRIT_PASS != extclientconnfields->filter_match(popt->get_filter_criteria())) {
					continue;
				}	
			}	

			MALERT_MSG			amsg;
			bool				bret;

			bret = pdef->is_astat_msg(aconn.cli_aggr_task_id_, amsg, tcurr, partha.machine_id_);

			if (!bret) {
				continue;
			}	

			auto [colarr, ncols]		= pdef->get_column_list();
			size_t				szjson = 0;
			const char			*pstackjson = nullptr;
			
			nalerts++;
				
			if (!bool(writer)) {
				new (&writer) (decltype(writer))(std::in_place);
			}
			else {
				writer->Reset();
			}	

			if (pdef->asubsys_ != SUBSYS_EXTCLIENTCONN) {
				clientconnfields.print_json(colarr, ncols, writer.value(), timebuf);
			}
			else {
				extclientconnfields->print_json(colarr, ncols, writer.value(), timebuf);
			}	

			szjson = writer->get_size();
			pstackjson = writer->get_string();
			
			palerthdlr_->send_rt_amsg(std::move(amsg), pstackjson, szjson);
		}	

		return nalerts;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while checking for Client Conn RT Alerts : %s\n", GY_GET_EXCEPT_STRING);
		);
		
		return 0;
	);
}


size_t MCONN_HANDLER::topcpurss_rtalert_rwlocked(PARTHA_INFO & partha, const comm::TASK_TOP_PROCS::TOP_TASK & task, int rank, SUBSYS_CLASS_E csubsys, time_t tcurr, const char *timebuf) noexcept
{
	try {
		size_t				nalerts = 0;
		auto				& topvec = csubsys == SUBSYS_TOPCPU ? partha.rtalerts_.adef_topcpu_ : partha.rtalerts_.adef_toprss_;
		TopCpuRssFields			topfields(partha, task, gmadhava_id_str_, rank, csubsys, tcurr);
		OptStackJsonWriter		writer;

		for (size_t i = 0; i < topvec.size(); ++i) {
			auto			*pdef = topvec[i].get();

			if (!pdef || pdef->is_deleted() || !pdef->is_enabled()) {
				continue;
			}	

			auto			popt = pdef->get_rt_options();

			if (!popt) {
				continue;
			}	

			if (CRIT_PASS != topfields.filter_match(popt->get_filter_criteria())) {
				continue;
			}	

			MALERT_MSG			amsg;
			bool				bret;

			bret = pdef->is_astat_msg(task.pid_, amsg, tcurr, partha.machine_id_);

			if (!bret) {
				continue;
			}	

			auto [colarr, ncols]		= pdef->get_column_list();
			size_t				szjson = 0;
			const char			*pstackjson = nullptr;
			
			nalerts++;
				
			if (!bool(writer)) {
				new (&writer) (decltype(writer))(std::in_place);
			}
			else {
				writer->Reset();
			}	

			topfields.print_json(colarr, ncols, writer.value(), timebuf);

			szjson = writer->get_size();
			pstackjson = writer->get_string();
			
			palerthdlr_->send_rt_amsg(std::move(amsg), pstackjson, szjson);
		}	

		return nalerts;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while checking for Top CPU/RSS RT Alerts : %s\n", GY_GET_EXCEPT_STRING);
		);
		
		return 0;
	);
}

size_t MCONN_HANDLER::toppgcpu_rtalert_rwlocked(PARTHA_INFO & partha, const comm::TASK_TOP_PROCS::TOP_PG_TASK & task, int rank, time_t tcurr, const char *timebuf) noexcept
{
	try {
		size_t				nalerts = 0;
		auto				& topvec = partha.rtalerts_.adef_toppgcpu_;
		TopPgCpuFields			topfields(partha, task, gmadhava_id_str_, rank, tcurr);
		OptStackJsonWriter		writer;

		for (size_t i = 0; i < topvec.size(); ++i) {
			auto			*pdef = topvec[i].get();

			if (!pdef || pdef->is_deleted() || !pdef->is_enabled()) {
				continue;
			}	

			auto			popt = pdef->get_rt_options();

			if (!popt) {
				continue;
			}	

			if (CRIT_PASS != topfields.filter_match(popt->get_filter_criteria())) {
				continue;
			}	

			MALERT_MSG			amsg;
			bool				bret;

			bret = pdef->is_astat_msg(task.pg_pid_, amsg, tcurr, partha.machine_id_);

			if (!bret) {
				continue;
			}	

			auto [colarr, ncols]		= pdef->get_column_list();
			size_t				szjson = 0;
			const char			*pstackjson = nullptr;
			
			nalerts++;
				
			if (!bool(writer)) {
				new (&writer) (decltype(writer))(std::in_place);
			}
			else {
				writer->Reset();
			}	

			topfields.print_json(colarr, ncols, writer.value(), timebuf);

			szjson = writer->get_size();
			pstackjson = writer->get_string();
			
			palerthdlr_->send_rt_amsg(std::move(amsg), pstackjson, szjson);
		}	

		return nalerts;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while checking for Top Pg CPU RT Alerts : %s\n", GY_GET_EXCEPT_STRING);
		);
		
		return 0;
	);
}

size_t MCONN_HANDLER::topfork_rtalert_rwlocked(PARTHA_INFO & partha, const comm::TASK_TOP_PROCS::TOP_FORK_TASK & task, int rank, time_t tcurr, const char *timebuf) noexcept
{
	try {
		size_t				nalerts = 0;
		auto				& topvec = partha.rtalerts_.adef_topfork_;
		TopForkFields			topfields(partha, task, gmadhava_id_str_, rank, tcurr);
		OptStackJsonWriter		writer;

		for (size_t i = 0; i < topvec.size(); ++i) {
			auto			*pdef = topvec[i].get();

			if (!pdef || pdef->is_deleted() || !pdef->is_enabled()) {
				continue;
			}	

			auto			popt = pdef->get_rt_options();

			if (!popt) {
				continue;
			}	

			if (CRIT_PASS != topfields.filter_match(popt->get_filter_criteria())) {
				continue;
			}	

			MALERT_MSG			amsg;
			bool				bret;

			bret = pdef->is_astat_msg(task.pid_, amsg, tcurr, partha.machine_id_);

			if (!bret) {
				continue;
			}	

			auto [colarr, ncols]		= pdef->get_column_list();
			size_t				szjson = 0;
			const char			*pstackjson = nullptr;
			
			nalerts++;
				
			if (!bool(writer)) {
				new (&writer) (decltype(writer))(std::in_place);
			}
			else {
				writer->Reset();
			}	

			topfields.print_json(colarr, ncols, writer.value(), timebuf);

			szjson = writer->get_size();
			pstackjson = writer->get_string();
			
			palerthdlr_->send_rt_amsg(std::move(amsg), pstackjson, szjson);
		}	

		return nalerts;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while checking for Top Fork RT Alerts : %s\n", GY_GET_EXCEPT_STRING);
		);
		
		return 0;
	);
}


void MDB_ADEL::operator()(MDB_ALERTDEF *pdef) const noexcept
{
	if (pdef) {
		pdef->~MDB_ALERTDEF();
		POOL_ALLOC::dealloc_free(pdef, &mempool_);
	}
}	

void MDB_ADEL::operator()(MDB_ALERT_STATS *pstat) const noexcept
{
	if (pstat) {
		pstat->~MDB_ALERT_STATS();
		POOL_ALLOC::dealloc_free(pstat, &mempool_);
	}
}	

void MRT_ALERT_HDLR::add_new_def(MALERT_MSG & emsg, time_t tcurr) noexcept
{
	try {
		if (emsg.adef_id_ == 0) {
			nmsgerr_++;
			return;
		}	

		JSON_DOCUMENT<16 * 1024, 8192>	doc;
		auto				& jdoc = doc.get_doc();
		char				*pjson = emsg.pjson_, *pendptr = emsg.pjson_ + emsg.lenjson_;
		bool				bret;

		assert(emsg.pjson_);

		if (pjson && pendptr > pjson) {
			if (*(pendptr - 1) == 0) {
				jdoc.ParseInsitu(pjson);	
			}
			else {
				jdoc.Parse(pjson, pendptr - pjson);
			}	
		}
		else {
			nmsgerr_++;
			return;
		}	

		if (jdoc.HasParseError()) {
			const char		*perrorstr = rapidjson::GetParseError_En(jdoc.GetParseError());

			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Alertmgr Realtime Handler : Invalid New Realtime Alert Definition : Error at json offset %lu : Error is \'%s\'\n\n", 
				jdoc.GetErrorOffset(), perrorstr);

			nmsgerr_++;
			return;
		}	
		
		// Delete all existing Alert Stats if existing def
		set_alert_state(emsg.adef_id_, tcurr, ALERT_ADEF_DELETE, ADEFSTATE_DISABLED);

		MRT_ALERTDEF			*padef;
		
		padef = new MRT_ALERTDEF(jdoc, jdoc.GetAllocator(), emsg.adef_id_, tcurr);

		try {
			MRT_ADEF_ELEM			*pdefelem;
			
			pdefelem = (MRT_ADEF_ELEM *)defpool_.malloc();

			if (!pdefelem) {
				GY_THROW_EXCEPTION("Failed to allocate Realtime Alert Definition as Max number of definition objects already allocated : Current # Defs %lu",
					adeftbl_.size());
			}	
			
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Alertmgr Realtime Handler : Adding new Alert Definition \'%s\'\n", padef->name());

			new (pdefelem) MRT_ADEF_ELEM(padef);

			SCOPE_GY_MUTEX			scopelock(adefmutex_);

			adeftbl_.try_emplace(emsg.adef_id_, pdefelem);

			last_upd_cusec_.store(get_usec_clock(), mo_relaxed);
		}
		catch(...) {
			delete padef;
			throw;
		}	
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while adding new Realtime Alert def : %s\n\n", GY_GET_EXCEPT_STRING);
	);
}	

void MRT_ALERT_HDLR::set_alert_state(uint32_t adef_id, time_t tcurr, ALERT_MSG_TYPE type, ADEF_STATE_E state) noexcept
{
	try {
		if (adef_id == 0) {
			return;
		}	

		auto				ait = adeftbl_.find(adef_id);	// Locking not needed as only this thread is a writer

		if (ait != adeftbl_.end()) {
			auto 				pdefelem = ait->second.get();

			if (pdefelem) {
				auto			pdef = pdefelem->get_def();

				if (pdef) {
					pdef->set_state(state);

					if (type >= ALERT_ADEF_DISABLE) {
						handle_def_reset(pdef, type == ALERT_ADEF_DELETE, pdef->is_muted_state());
					}
				}

				if (type == ALERT_ADEF_DELETE) {
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Alertmgr Realtime Handler : Deleting Alert Definition \'%s\'\n", pdef->name());

					SCOPE_GY_MUTEX			scopelock(&adefmutex_);

					adeftbl_.erase(ait);

					last_upd_cusec_.store(get_usec_clock(), mo_relaxed);
				}
			}	
		}
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while setting state of Realtime Alert def : %s\n\n", GY_GET_EXCEPT_STRING);
	);
}

void MRT_ALERT_HDLR::handle_def_reset(MRT_ALERTDEF *pdef, bool is_deleted, bool only_pending) 
{
	if (is_deleted) {
		pdef->set_deleted();
	}

	const auto deltimes = [&](MRT_ALERT_STATS *pstat, uint64_t key) 
	{
		auto 			range = atimemap_.equal_range(key);
		
		for (auto it = range.first; it != range.second; ++it) {
			if (it->second == pstat) {
				atimemap_.erase(it);
				return;
			}
		}	
	};	

	const auto lwalk = [&, only_pending](MRT_ALERT_STATS *pstat, void *arg) -> CB_RET_E
	{
		if (only_pending && MALERT_PENDING != pstat->state_.load(mo_relaxed)) {
			return CB_OK;
		}

		deltimes(pstat, pstat->tnextchkusec_);
		
		return CB_DELETE_ELEM;
	};	


	if (auto ptbl = pdef->get_id_def_tbl(); ptbl) {
		ptbl->walk_hash_table(lwalk);
	}
	else if (auto ptbl = pdef->get_machid_def_tbl(); ptbl) {
		ptbl->walk_hash_table(lwalk);
	}
}	

void MRT_ALERT_HDLR::handle_astat_msg(MALERT_MSG & emsg, time_t tcurr) noexcept
{
	try {
		if (emsg.adef_id_ == 0) return;

		uint32_t			adef_id = emsg.adef_id_;

		auto				ait = adeftbl_.find(adef_id);	// No Locking needed
		if (ait == adeftbl_.end()) {
			return;
		}

		auto 				pdefelem = ait->second.get();
		if (!pdefelem) return;

		auto				pdef = pdefelem->get_def();
		if (!pdef) return;

		if (false == pdef->is_enabled()) {
			return;
		}	

		if (emsg.type_ == ALERT_ASTAT_ID) {
			if (auto ptbl = pdef->get_id_def_tbl(); ptbl && emsg.id_ != 0) {
				upd_astat_id(emsg, pdef, pdefelem, *ptbl, tcurr);
			}
		}	
		else {
			if (auto ptbl = pdef->get_machid_def_tbl(); ptbl) {
				upd_astat_machid(emsg, pdef, pdefelem, *ptbl, tcurr);
			}
		}	
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while handling Realtime Alert Stat Message : %s\n", GY_GET_EXCEPT_STRING);
	);
}	

void MRT_ALERT_HDLR::upd_astat_id(MALERT_MSG & emsg, MRT_ALERTDEF *pdef, MRT_ADEF_ELEM *pdefelem, MRT_ALERT_ID_TBL & stattbl, time_t tcurr)
{
	uint64_t			id = emsg.id_, idhash = get_uint64_hash(id);
	bool				is_fired = (emsg.numhits_ >= pdef->numcheckfor_), isnew = false;
	
	RCU_LOCK_SLOW			slowlock;

	auto pstat = stattbl.lookup_single_elem_locked(id, idhash);
	if (!pstat) {
		pstat = (decltype(pstat))mempool_.malloc();

		if (!pstat) {
			nrtskips_++;
			return;
		}	

		new (pstat) MRT_ALERT_STATS(id, pdefelem, pdef, emsg.tmsg_, pdef->numcheckfor_, is_fired ? MALERT_FIRED : MALERT_PENDING, emsg.asubsys_, emsg.machid_);

		stattbl.insert_duplicate_elem(pstat, idhash);

		pstat->tnextchkusec_ = pdef->get_nextcheck_tusec(get_usec_time(), emsg.numhits_);

		try {
			atimemap_.emplace(pstat->tnextchkusec_, pstat);
		}
		catch(...) {
			stattbl.delete_elem_locked(pstat);
			throw;
		}	

		isnew = true;
	}	
	
	slowlock.unlock();

	common_astats_update(emsg, pstat, pdef, tcurr, is_fired, isnew);
}	

void MRT_ALERT_HDLR::upd_astat_machid(MALERT_MSG & emsg, MRT_ALERTDEF *pdef, MRT_ADEF_ELEM *pdefelem, MRT_ALERT_MACHID_TBL & stattbl, time_t tcurr)
{
	uint64_t			mhash = emsg.machid_.get_hash();
	bool				is_fired = (emsg.numhits_ >= pdef->numcheckfor_), isnew = false;
	
	RCU_LOCK_SLOW			slowlock;

	auto pstat = stattbl.lookup_single_elem_locked(emsg.machid_, mhash);
	if (!pstat) {
		pstat = (decltype(pstat))mempool_.malloc();

		if (!pstat) {
			nrtskips_++;
			return;
		}	

		new (pstat) MRT_ALERT_STATS(emsg.machid_, pdefelem, pdef, emsg.tmsg_, pdef->numcheckfor_, is_fired ? MALERT_FIRED : MALERT_PENDING, emsg.asubsys_);

		stattbl.insert_duplicate_elem(pstat, mhash);

		pstat->tnextchkusec_ = pdef->get_nextcheck_tusec(get_usec_time(), emsg.numhits_);

		try {
			atimemap_.emplace(pstat->tnextchkusec_, pstat);
		}
		catch(...) {
			stattbl.delete_elem_locked(pstat);
			throw;
		}	

		isnew = true;
	}	
	
	slowlock.unlock();

	common_astats_update(emsg, pstat, pdef, tcurr, is_fired, isnew);
}	


void MRT_ALERT_HDLR::common_astats_update(MALERT_MSG & emsg, MRT_ALERT_STATS *pstat, MRT_ALERTDEF *pdef, time_t tcurr, bool is_fired, bool isnew)
{
	if (isnew && !is_fired) {
		return;
	}	

	auto			tlast_alert = pstat->tlast_alert_.load(mo_relaxed);

	if (is_fired && (tlast_alert == 0 || tlast_alert + pdef->repeataftersec_ < tcurr)) {

		if (tlast_alert == 0) {
			pstat->state_.store(MALERT_FIRED, mo_relaxed);
			pstat->tforce_close_ = tcurr + pdef->forceclosesec_;

			nalerts_++;
		}
		else if (pdef->repeataftersec_ == 0) {
			// No repeat alerts
			return;
		}	
		else {
			pstat->nrepeats_++;
			nrepeats_++;
		}	

		send_shyama_rtalert(emsg, pstat, pdef, tcurr);

		pstat->tlast_alert_.store(tcurr, mo_relaxed);
		
		if (pdef->repeataftersec_ > 0) {
			pstat->trepeat_alert_.store(tcurr + pdef->repeataftersec_, mo_relaxed);
		}
		else {
			pstat->trepeat_alert_.store(0, mo_relaxed);
		}	
	}
	
	if (isnew) {
		return;
	}	

	uint64_t		oldtusec = pstat->tnextchkusec_, newtusec = pdef->get_nextcheck_tusec(get_usec_time(), 1 /* reset */);

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

bool MRT_ALERT_HDLR::send_shyama_rtalert(MALERT_MSG & emsg, MRT_ALERT_STATS *pstat, MRT_ALERTDEF *pdef, time_t tcurr)
{
	if (new_alerts_disabled(tcurr)) {
		nrtskips_++;
		return false;
	}

	if (!emsg.pjson_ || (emsg.lenjson_ <= sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + sizeof(comm::ALERT_STAT_INFO)) || !emsg.lenact_json_) {
		return false;
	}	

	auto				pconnhdlr = MCONN_HANDLER::get_singleton();
	auto				shrconn = pconnhdlr->gshyama_.get_last_conn(comm::CLI_TYPE_REQ_RESP);

	if (!shrconn) {
		nrtskips_++;
		return false;
	}

	/*
	 * The caller thread has already allocated heap memory of len emsg.lenjson_
	 */
	COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(emsg.pjson_);
	EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1);
	ALERT_STAT_INFO			*pinfo = reinterpret_cast<ALERT_STAT_INFO *>(pnot + 1);
	
	FREE_FPTR			free_fp = emsg.free_fp_;

	new (pinfo) ALERT_STAT_INFO(emsg.tmsg_, pstat->alertid_, pdef->adef_id_, pdef->ahdlr_, pdef->asubsys_, emsg.numhits_, pdef->numcheckfor_, pstat->nrepeats_, 
					true /* isrealtime */, emsg.lenact_json_);

	new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + pinfo->get_elem_size(), shrconn->get_comm_magic());
	new (pnot) EVENT_NOTIFY(comm::NOTIFY_ALERT_STAT_INFO, 1);

	emsg.reset();

	return pconnhdlr->schedule_l1_send_data(shrconn, comm::COMM_EVENT_NOTIFY, EPOLL_IOVEC_ARR(2, false, phdr, phdr->get_act_len(), free_fp, 
						pconnhdlr->gpadbuf, phdr->get_pad_len(), nullptr));
}	

static void send_shyama_alert_close(MCONN_HANDLER::MSTREAM_EVENT_BUF & streambuf, uint64_t alertid, uint32_t adef_id, time_t tlast_hit, time_t tcurr, bool is_force_close, bool isrealtime)
{
	auto			*pinfo = (ALERT_STAT_CLOSE *)streambuf.get_buf(sizeof(ALERT_STAT_CLOSE));

	new (pinfo) ALERT_STAT_CLOSE(tlast_hit, tcurr, alertid, adef_id, is_force_close, isrealtime);

	streambuf.set_buf_sz(sizeof(*pinfo), 1 /* nevents */);
}	

void MRT_ALERT_HDLR::validate_timemap(time_t tcurr, bool check_all) noexcept
{
	try {
		const uint64_t			currusec = tcurr * GY_USEC_PER_SEC, minusec = currusec + (check_all * GY_USEC_PER_YEAR);
		size_t				nelems = 0, nchecks = 0;

		using OptStreamBuf		= std::optional<MCONN_HANDLER::MSTREAM_EVENT_BUF>;

		auto				pconnhdlr = MCONN_HANDLER::get_singleton();
		auto				shrconn = pconnhdlr->gshyama_.get_last_conn(comm::CLI_TYPE_REQ_RESP);

		OptStreamBuf			streambuf;

		if (shrconn) {
			streambuf.emplace(shrconn, *pconnhdlr, NOTIFY_ALERT_STAT_CLOSE, 128);
		}

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

			time_t			tlast_hit = pstat->tlast_hit_.load(mo_relaxed);
			MRT_ALERTDEF 		*pdef = nullptr;

			if (pstat->pdefelem_ && true == pstat->pdefelem_->is_valid()) {
				pdef = pstat->pdefelem_->get_def();
			}

			if (pdef == nullptr) {
				atimemap_.erase(it);
				continue;
			}	

			pstat->tlast_validate_	= tcurr;

			if (tlast_hit + pstat->multi_iter_chk_sec_ <= tcurr) {

				if (pstat->state_.load(mo_relaxed) != MALERT_PENDING) {
					if (streambuf) {
						send_shyama_alert_close(*streambuf, pstat->alertid_, pdef->adef_id_, tlast_hit, tcurr, false /* is_force_close */, true /* isrealtime */);
					}	
					
					nalertclose_++;
				}

				DEBUGEXECN(5, 
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW_UNDERLINE, "Alert Handler : Erasing by hit timeout for Realtime Alert for Alert ID %08x of Definition \'%s\' : "
						"numcheckfor %u, numhits %u, Time since last hit %ld sec\n", 
						pstat->alertid_, pdef->name(), pstat->numcheckfor_, pstat->numhits_.load(mo_relaxed), tcurr - tlast_hit);
				);

				RCU_LOCK_SLOW			slowlock;

				pstat->del_from_def_table_locked(pdef);
				atimemap_.erase(it);

				continue;
			}	
			
			if (pstat->tlast_alert_.load(mo_relaxed) > 0 && tcurr >= pstat->tforce_close_) {
				if (streambuf) {
					send_shyama_alert_close(*streambuf, pstat->alertid_, pdef->adef_id_, tlast_hit, tcurr, true /* is_force_close */, true /* isrealtime */);
				}
					
				nalertclose_++;
				nforceclose_++;

				DEBUGEXECN(5, 
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW_UNDERLINE, "Alert Handler : Erasing by Alert Expiry for Realtime Alert for Alert ID %08x of Definition \'%s\' : "
						"numcheckfor %u, numhits %u, Time since last hit %ld sec\n", 
						pstat->alertid_, pdef->name(), pstat->numcheckfor_, pstat->numhits_.load(mo_relaxed), tcurr - tlast_hit);
				);

				RCU_LOCK_SLOW			slowlock;

				pstat->del_from_def_table_locked(pdef);
				atimemap_.erase(it);

				continue;
			}

			if (check_all && tusec > currusec + GY_USEC_PER_SEC) {
				continue;
			}	

			uint8_t			numhits = pstat->numhits_.load(mo_relaxed);				

			pstat->tnextchkusec_ = pdef->get_nextcheck_tusec(currusec, numhits >= pstat->numcheckfor_ ? 1 /* reset */ : numhits);

			auto			oldit = it;
			auto			mnode = atimemap_.extract(oldit);

			if (bool(mnode)) {
				mnode.key() = pstat->tnextchkusec_;
				atimemap_.insert(std::move(mnode));
			}	
		}	
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while checking Realtime Alerts Time Map entries : %s\n", GY_GET_EXCEPT_STRING);
	);
}	

void MRT_ALERT_HDLR::validate_stats(time_t tcurr) noexcept
{
	try {
		RCU_LOCK_SLOW			slowlock;
		int				ndefs = 0, ndefsenabled = 0, nastats = 0, nerase = 0;

		const auto lwalk = [tmin_validate = tcurr - 150, &nerase](MRT_ALERT_STATS *pstat, void *arg) -> CB_RET_E
		{
			if (pstat->tlast_validate_ < tmin_validate) {
				nerase++;
				return CB_DELETE_ELEM;
			}

			return CB_OK;
		};	

		for (const auto & [adefid, pdefelem] : adeftbl_) {
			if (!pdefelem) {
				continue;
			}

			auto			pdef = pdefelem->get_def();
			if (!pdef) {
				continue;
			}	

			ndefs++;
			ndefsenabled += pdef->is_enabled();

			if (auto ptbl = pdef->get_id_def_tbl(); ptbl) {
				nastats += ptbl->walk_hash_table(lwalk);
			}
			else if (auto ptbl = pdef->get_machid_def_tbl(); ptbl) {
				nastats += ptbl->walk_hash_table(lwalk);
			}
		}	

		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Realtime Alert Definition Stats : %d Total Realtime Defs, %d Enabled Defs, %d Alert Stats allocated, "
				"%d Alert Stats Deleted by Reference Time Out\n", ndefs, ndefsenabled, nastats, nerase);
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while checking Realtime Alerts Stat entries : %s\n", GY_GET_EXCEPT_STRING);
	);
}	

void MRT_ALERT_HDLR::print_stats(int64_t tdiff, time_t tcurr) noexcept
{
	STRING_BUFFER<1024>		strbuf;
	auto				nmissed = nmissed_.load(mo_relaxed);

	strbuf << "Realtime Alert Stats for the last " << tdiff << " secs : " 
		<< nalerts_ - lastnalerts_ << " New Alerts, "  << nrepeats_ - lastnrepeats_ << " Repeat Alerts, "
		<< nrtskips_ - lastnrtskips_ << " Skipped Alerts, " 
		<< nalertclose_ - lastnalertclose_ << " Close Alerts sent, " << nforceclose_ - lastnforceclose_ << " Force Closed Alerts, ";
	
	if (nmissed) {
		strbuf << nmissed - lastnmissed_ << " Missed by Pool Block, ";
	}	

	if (nmsgerr_) {
		strbuf << nmsgerr_ - lastnmsgerr_ << " Internal Msg Errors";
	}	
	
	strbuf  << "\n\t\t\tCumulative Realtime Alert Stats : " 
		<< nalerts_ << " Total Alerts, " << nrepeats_ << " Repeat Alerts, "
		<< nrtskips_ << " Skipped Alerts, " << nalertclose_ << " Close Alerts sent, " << nforceclose_ << " Force Closed Alerts, ";

	if (nmissed) {
		strbuf << nmissed << " Missed by Pool Block, ";
	}	

	if (nmsgerr_) {	
		strbuf << nmsgerr_  << " Internal Msg Errors";
	}	
	
	strbuf	<< "\n\n\t\t\tCurrent Realtime Alert definitions : " << adeftbl_.size() // No locking needed
		<< " , Timemap Entries : " << atimemap_.size();

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "%s\n\n", strbuf.buffer());

	lastnalerts_			= nalerts_;
	lastnrepeats_			= nrepeats_;
	lastnmissed_			= nmissed;
	lastnrtskips_			= nrtskips_;
	lastnalertclose_		= nalertclose_;
	lastnforceclose_		= nforceclose_;
	lastnmsgerr_			= nmsgerr_;
}	

void MRT_ALERT_HDLR::handle_rt_alerts(MALERT_HDLR *palerthdlr) 
{
	mempool_.set_alloc_thrid();

	tlast_stat_chk_	= tlast_timemap_chk_  = time(nullptr);

	time_t				tlastprint = tlast_timemap_chk_;

	do {
		gy_thread_rcu().gy_rcu_thread_offline();

		time_t				tcurr = time(nullptr) + 1, tstart = tcurr + 30, tmap1;
		int				ncache;
		bool				bret, is_all = false;
		auto				cit = atimemap_.cbegin();

		if (cit != atimemap_.cend()) {
			tmap1 = cit->first/GY_USEC_PER_SEC;

			if (tmap1 < tstart) {
				tstart = std::max(tmap1, tcurr);
			}	
		}	
		else {
			tmap1 = tstart + 1000;
		}	

		MALERT_MSG			emsg;

		bret = aqueue_.tryReadUntil(std::chrono::system_clock::from_time_t(tstart), emsg);

		tcurr = time(nullptr);

		if (bret) {
			if (false == emsg.validate()) {
				nmsgerr_++;
				goto next;
			}	

			switch (emsg.type_) {
			
			case ALERT_ASTAT_ID :
			case ALERT_ASTAT_MACHID :	
				
				handle_astat_msg(emsg, tcurr);
				break;

			case ALERT_ADEF_NEW :

				if (emsg.pjson_ && emsg.lenjson_) {
					add_new_def(emsg, tcurr);
				}	
				else {
					nmsgerr_++;
				}	
				break;

			case ALERT_ADEF_ENABLE :
				set_alert_state(emsg.adef_id_, tcurr, ALERT_ADEF_ENABLE, ADEFSTATE_ENABLED);
				break;

			case ALERT_ADEF_DISABLE :
				set_alert_state(emsg.adef_id_, tcurr, ALERT_ADEF_DISABLE, ADEFSTATE_DISABLED);
				break;

			case ALERT_ADEF_MUTE :
				set_alert_state(emsg.adef_id_, tcurr, ALERT_ADEF_MUTE, ADEFSTATE_MUTED);
				break;

			case ALERT_ADEF_SILENCE :
				set_alert_state(emsg.adef_id_, tcurr, ALERT_ADEF_SILENCE, ADEFSTATE_SILENCED);
				break;

			case ALERT_ADEF_INHIBIT :
				set_alert_state(emsg.adef_id_, tcurr, ALERT_ADEF_INHIBIT, ADEFSTATE_INHIBITED);
				break;

			case ALERT_ADEF_DELETE :
				set_alert_state(emsg.adef_id_, tcurr, ALERT_ADEF_DELETE, ADEFSTATE_DISABLED);
				break;

			default :
				nmsgerr_++;
				break;
			}	
		}	

next :
		if (tcurr > tlast_timemap_chk_ + 60) {

			tlast_timemap_chk_ = tcurr;
			validate_timemap(tcurr, true /* check_all */);
			is_all = true;

			if (tcurr > tlast_stat_chk_ + 180) {
				tlast_stat_chk_ = tcurr;
				validate_stats(tcurr);
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

	} while (true);
}	

void MDB_ALERT_HDLR::handle_db_alerts(MALERT_HDLR *palerthdlr) 
{
	tlast_stat_chk_	= tlast_timemap_chk_  = time(nullptr);
	
	time_t				tlastprint = tlast_timemap_chk_;

	do {
		gy_thread_rcu().gy_rcu_thread_offline();

		time_t				tcurr = time(nullptr) + 1, tstart = tcurr + 10, tmap1;
		int				ncache;
		bool				bret, is_all = false;
		auto				cit = atimemap_.cbegin();

		if (cit != atimemap_.cend()) {
			tmap1 = cit->first/GY_USEC_PER_SEC;

			if (tmap1 < tstart) {
				tstart = std::max(tmap1, tcurr);
			}	
		}	
		else {
			tmap1 = tstart + 1000;
		}	

		if (tnext_query_ < tstart) {
			tstart = std::max(tnext_query_, tcurr);
		}	

		MALERT_MSG			emsg;

		bret = aqueue_.tryReadUntil(std::chrono::system_clock::from_time_t(tstart), emsg);

		tcurr = time(nullptr);

		if (bret) {
			if (false == emsg.validate()) {
				goto next;
			}	

			switch (emsg.type_) {
			
			case ALERT_ADEF_NEW :

				if (emsg.pjson_ && emsg.lenjson_) {
					add_new_def(emsg, tcurr);
				}	
				break;

			case ALERT_ADEF_ENABLE :
				set_alert_state(emsg.adef_id_, tcurr, ALERT_ADEF_ENABLE, ADEFSTATE_ENABLED);
				break;

			case ALERT_ADEF_DISABLE :
				set_alert_state(emsg.adef_id_, tcurr, ALERT_ADEF_DISABLE, ADEFSTATE_DISABLED);
				break;

			case ALERT_ADEF_MUTE :
				set_alert_state(emsg.adef_id_, tcurr, ALERT_ADEF_MUTE, ADEFSTATE_MUTED);
				break;

			case ALERT_ADEF_SILENCE :
				set_alert_state(emsg.adef_id_, tcurr, ALERT_ADEF_SILENCE, ADEFSTATE_SILENCED);
				break;

			case ALERT_ADEF_INHIBIT :
				set_alert_state(emsg.adef_id_, tcurr, ALERT_ADEF_INHIBIT, ADEFSTATE_INHIBITED);
				break;

			case ALERT_ADEF_DELETE :
				set_alert_state(emsg.adef_id_, tcurr, ALERT_ADEF_DELETE, ADEFSTATE_DISABLED);
				break;

			default :
				break;
			}	
		}	

next :
		if (tcurr >= tnext_query_) {
			/*
			 * The below assignment implies that if we miss an interval due to queries taking too long,
			 * we will skip those interval(s)...
			 */
			tnext_query_ 	= tcurr + MIN_ALERT_QUERY_INTERVAL_SEC;
			tquery_start_ 	= tcurr;
			curr_nalerts_	= 0;

			run_alert_queries(tcurr);

			tcurr = time(nullptr);
		}	
	
		if (tcurr > tlast_timemap_chk_ + 60) {

			tlast_timemap_chk_ = tcurr;
			validate_timemap(tcurr, true /* check_all */);
			is_all = true;

			if (tcurr > tlast_stat_chk_ + 180) {
				tlast_stat_chk_ = tcurr;
				validate_stats(tcurr);
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

template <>
bool MDB_ALERT_HDLR::db_resp_cb(GyPGConn & conn, GyPGresult && gyres, bool is_completed, MCONN_HANDLER::MSTREAM_EVENT_BUF & streambuf, int & total_rows, bool & is_error, MDB_ALERTDEF & adef)
{
	MDB_ALERTDEF			*pdef = &adef;

	if (is_completed) {
		conn.make_available();

		if (total_rows) {
			DEBUGEXECN(11, 
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Alertdef \'%s\' : DB Query returned %d rows...\n", pdef->name(), total_rows);

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
			WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to query Alert \'%s\' from DB (Total errors so far %ld) : Error due to %s\n", 
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
			WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Alert \'%s\' : Invalid DB Column count seen : %d instead of %u", name, nfields, pdef->ncols_);
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
			WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Alert \'%s\' : Invalid DB Column count seen : Key Column %u : Number of fields seen %d", 
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
					WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Alert \'%s\' : Invalid DB Column name seen : %s instead of %s", 
						name, pfname, colarr[col].dbcolname);
				}

				ndberrors_++;
				pdef->nerrors_++;
				is_error = true;
				return false;
			}	

			if ((colarr[col].dbstrtype == DB_STR_OCHAR) && (PG_BPCHAROID != PQftype(pres, col))) {
				if (pdef->nerrors_ < 3 || gdebugexecn >= 1) {
					WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Alert \'%s\' : Invalid DB Column type seen : %d instead of %d", 
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
		MDB_ALERT_STATS			*pstat = nullptr;
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

			new (pstat) MDB_ALERT_STATS(keyid, pdef, tcurr, pdef->numcheckfor_, is_fired ? MALERT_FIRED : MALERT_PENDING, pdef->asubsys_);

			auto			puniq = std::unique_ptr<MDB_ALERT_STATS, MDB_ADEL>(pstat, mempool_);

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

			DEBUGEXECN(1, 
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW_UNDERLINE, "Alert Handler : New DB Alert Object of Alert ID %08x for Definition \'%s\' : "
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
				nkeyskips_++;
				continue;
			}

			pstat->tquery_start_ = tquery_start_;

			pstat->numhits_++;
			numhits = pstat->numhits_;

			time_t			toldlasthit = pstat->tlast_hit_;

			if (numhits > 1 && pstat->numcheckfor_ > 1 && ((toldlasthit + 30 < pdef->tlast_query_) || (toldlasthit + 2 * pdef->query_interval_sec_ + 10 <= tcurr))) {
				// Flapping Alert : Reset checks

				DEBUGEXECN(15, 
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW_UNDERLINE, "Alert Handler : Flapping DB Alert seen for Alert ID %08x of Definition \'%s\' : "
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
				pstat->state_ 		= MALERT_FIRED;
				pstat->tforce_close_ 	= tcurr + pdef->forceclosesec_;

				nalerts_++;
			}
			else if (pdef->repeataftersec_ == 0) {
				// No repeat alerts
				continue;
			}	
			else {
				nrepeats_++;
				pstat->nrepeats_++;
			}	

			STACK_JSON_WRITER<8192, 4096>	writer;

			writer.StartObject();

			for (int col = 0; col < nfields; ++col) {
				const char	*pfname = PQfname(pres, col);

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
			size_t			szjson = writer.get_size() + 1, newsz = sizeof(ALERT_STAT_INFO) + szjson + 7;

			auto			*pinfo = (ALERT_STAT_INFO *)streambuf.get_buf(newsz, false, curr_nalerts_++ == 0 ? newsz * 4 : 0);

			new (pinfo) ALERT_STAT_INFO(tcurr, pstat->alertid_, pdef->adef_id_, pdef->ahdlr_, pdef->asubsys_, numhits, pdef->numcheckfor_, pstat->nrepeats_, 
					false /* isrealtime */, szjson);

			std::memcpy((char *)pinfo + sizeof(*pinfo), pstackjson, szjson);

			streambuf.set_buf_sz(pinfo->get_elem_size(), 1 /* nevents */);

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


void MDB_ALERT_HDLR::run_alert_queries(time_t tcurr) noexcept
{
	try {
		time_t				tquery_start;
		int				nqueries = 0;
		bool				bret;

		if (new_alerts_disabled(tcurr)) {
			return;
		}	

		auto				pconnhdlr = MCONN_HANDLER::get_singleton();
		auto				shrconn = pconnhdlr->gshyama_.get_last_conn(comm::CLI_TYPE_REQ_RESP);

		if (!shrconn) {
			return;
		}

		MCONN_HANDLER::MSTREAM_EVENT_BUF	streambuf(shrconn, *pconnhdlr, NOTIFY_ALERT_STAT_INFO, ALERT_STAT_INFO::MAX_NUM_STATS);
		
		for (auto it = adeftbl_.begin(); it != adeftbl_.end(); ++it) {
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
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Alertmgr DB Handler %d : Executing Alert \'%s\' query : %s\n", 
							dbhandlerid_, pdef->name(), strbuf.buffer()); 
				);

				auto				pconn = dbpool_.get_conn(true /* wait_response_if_unavail */, 10000 /* max_msec_wait */, true /* reset_on_timeout */);

				if (!pconn) {
					DEBUGEXECN(1, 
						ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection for DB Alert Query for Alert \'%s\'\n", pdef->name());
					);
					
					nconnmiss_++;
					continue;
				}

				bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());

				if (bret == false) {
					DEBUGEXECN(1, 
						ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to schedule DB Alert Query for Alert \'%s\'\n", pdef->name());
					);	
					continue;
				}	
				
				pconn->set_single_row_mode();

				pconn->set_resp_cb(
					/*
					 * NOTE : Capture by value those variables defined within the for loop 
					 */
					[this, &streambuf, pdef, total_rows = 0, is_error = false](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
					{
						return db_resp_cb(conn, std::move(gyres), is_completed, streambuf, total_rows, is_error, *pdef);
					}
				);

				if (gy_unlikely(shrconn->is_conn_close_signalled())) {
					streambuf.reset_if_not_sent();
					break;
				}	
			}
			GY_CATCH_EXCEPTION(
				DEBUGEXECN(1, 
					WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while running DB Alert Query for Alert \'%s\' : %s\n", 
						pdef->name(), GY_GET_EXCEPT_STRING);
				);	
			);
		}	

		dbpool_.wait_all_responses(30'000, 50'000);

	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, 
			WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while running DB Alert Queries : %s\n", GY_GET_EXCEPT_STRING);
		);	
	);
}	

void MDB_ALERT_HDLR::validate_stats(time_t tcurr) noexcept
{
	try {
		const time_t			tmin_validate = tcurr - 150;
		int				ndefs = 0, ndefsenabled = 0, nastats = 0, nerase = 0;

		for (const auto & [adefid, pdefelem] : adeftbl_) {
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

		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "DB Handler %d Alert Definition Stats : %d Total DB Alert Defs, %d Enabled Defs, %d Alert Stats allocated, "
				"%d Alert Stats Deleted by Reference Time Out\n", dbhandlerid_, ndefs, ndefsenabled, nastats, nerase);
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while checking DB Alerts Stat entries : %s\n", GY_GET_EXCEPT_STRING);
	);
}	

void MDB_ALERT_HDLR::print_stats(int64_t tdiff, time_t tcurr) noexcept
{
	STRING_BUFFER<1024>		strbuf;

	strbuf << "DB Alert Stats for the last " << tdiff << " secs : " 
		<< nalerts_ - lastnalerts_ << " New Alerts, "  << nrepeats_ - lastnrepeats_ << " Repeat Alerts, "
		<< ndbskips_ - lastndbskips_ << " Skipped Alerts, " << nkeyskips_ - lastnkeyskips_ << " Skipped due to Key Issues, " 
		<< ndberrors_ - lastndberrors_ << " DB Alert Query Issues, " 
		<< "\n\t\t\t" << ngetdberrors_ - lastngetdberrors_ << " DB Query String Overflows, "
		<< nconnmiss_ - lastnconnmiss_ << " DB Connection Issue by long exec time, "
		<< nalertclose_ - lastnalertclose_ << " Close Alerts sent, " << nforceclose_ - lastnforceclose_ << " Force Closed Alerts ";
	
	strbuf  << "\n\n\t\t\tCumulative DB Alert Stats : " 
		<< nalerts_ << " Total Alerts, " << nrepeats_ << " Repeat Alerts, "
		<< ndbskips_ << " Skipped Alerts, " << nkeyskips_ << " Skipped due to Key Issues, "
		<< ndberrors_ << " DB Alert Query Issues, " 
		<< "\n\t\t\t" << ngetdberrors_ << " DB Query String Overflows, "
		<< nconnmiss_ << " DB Connection Issue by long exec time, "
		<< nalertclose_ << " Close Alerts sent, " << nforceclose_ << " Force Closed Alerts ";

	strbuf	<< "\n\n\t\t\tCurrent DB Alert definitions : " << adeftbl_.size()
		<< " , Timemap Entries : " << atimemap_.size();

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "DB Handler %d Stats : %s\n\n", dbhandlerid_, strbuf.buffer());

	lastnalerts_			= nalerts_;
	lastnrepeats_			= nrepeats_;
	lastndbskips_			= ndbskips_;
	lastnkeyskips_			= nkeyskips_;
	lastndberrors_			= ndberrors_;
	lastngetdberrors_		= ngetdberrors_;
	lastnconnmiss_			= nconnmiss_;
	lastnalertclose_		= nalertclose_;
	lastnforceclose_		= nforceclose_;
}	


void MDB_ALERT_HDLR::validate_timemap(time_t tcurr, bool check_all) noexcept
{
	try {
		const uint64_t			currusec = tcurr * GY_USEC_PER_SEC, minusec = currusec + (check_all * GY_USEC_PER_YEAR);
		size_t				nelems = 0, nchecks = 0;

		using OptStreamBuf		= std::optional<MCONN_HANDLER::MSTREAM_EVENT_BUF>;

		auto				pconnhdlr = MCONN_HANDLER::get_singleton();
		auto				shrconn = pconnhdlr->gshyama_.get_last_conn(comm::CLI_TYPE_REQ_RESP);

		OptStreamBuf			streambuf;

		if (shrconn) {
			streambuf.emplace(shrconn, *pconnhdlr, NOTIFY_ALERT_STAT_CLOSE, 128);
		}

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
			MDB_ALERTDEF 		*pdef = nullptr;

			if (pstat->pdef_ && true == pstat->pdef_->is_valid()) {
				pdef = pstat->pdef_;
			}

			if (pdef == nullptr) {
				atimemap_.erase(it);
				continue;
			}	

			pstat->tlast_validate_	= tcurr;

			if ((tlast_hit + 30 < pdef->tlast_query_) || (tlast_hit + 2 * pdef->query_interval_sec_ + 10 <= tcurr)) {

				if (pstat->state_ != MALERT_PENDING) {
					if (streambuf) {
						send_shyama_alert_close(*streambuf, pstat->alertid_, pdef->adef_id_, tlast_hit, tcurr, false /* is_force_close */, false /* isrealtime */);
					}	

					nalertclose_++;
				}

				pdef->astat_tbl_.erase(pstat->id_);

				GY_CC_BARRIER();

				DEBUGEXECN(5, 
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW_UNDERLINE, "Alert Handler : Erasing by hit timeout for DB Alert for Alert ID %08x of Definition \'%s\' : "
						"numcheckfor %u, numhits %u, Time since last hit %ld sec\n", 
						pstat->alertid_, pdef->name(), pstat->numcheckfor_, pstat->numhits_, tcurr - tlast_hit);
				);

				atimemap_.erase(it);

				continue;
			}	
			
			if (pstat->tlast_alert_ > 0 && tcurr >= pstat->tforce_close_) {
				if (streambuf) {
					send_shyama_alert_close(*streambuf, pstat->alertid_, pdef->adef_id_, tlast_hit, tcurr, true /* is_force_close */, false /* isrealtime */);
				}

				nalertclose_++;
				nforceclose_++;

				DEBUGEXECN(5, 
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW_UNDERLINE, "Alert Handler : Erasing by Alert Expiry for DB Alert for Alert ID %08x of Definition \'%s\' : "
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
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while checking DB Alerts Time Map entries : %s\n", GY_GET_EXCEPT_STRING);
	);
}

void MDB_ALERT_HDLR::add_new_def(MALERT_MSG & emsg, time_t tcurr) noexcept
{
	try {
		if (emsg.adef_id_ == 0) {
			return;
		}	

		JSON_DOCUMENT<16 * 1024, 8192>	doc;
		auto				& jdoc = doc.get_doc();
		char				*pjson = emsg.pjson_, *pendptr = emsg.pjson_ + emsg.lenjson_;
		bool				bret;

		assert(emsg.pjson_);

		if (pjson && pendptr > pjson) {
			if (*(pendptr - 1) == 0) {
				jdoc.ParseInsitu(pjson);	
			}
			else {
				jdoc.Parse(pjson, pendptr - pjson);
			}	
		}
		else {
			return;
		}	

		if (jdoc.HasParseError()) {
			const char		*perrorstr = rapidjson::GetParseError_En(jdoc.GetParseError());

			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Alertmgr DB Handler %d : Invalid New DB Alert Definition : Error at json offset %lu : Error is \'%s\'\n\n", 
				dbhandlerid_, jdoc.GetErrorOffset(), perrorstr);

			return;
		}	
		
		// Delete all existing Alert Stats if existing def
		set_alert_state(emsg.adef_id_, tcurr, ALERT_ADEF_DELETE, ADEFSTATE_DISABLED);

		MDB_ALERTDEF			*pdef;
		
		pdef = (MDB_ALERTDEF *)defpool_.malloc();

		if (!pdef) {
			GY_THROW_EXCEPTION("Alertmgr DB Handler %d : Failed to allocate DB alert definition as Max definition objects exceeded : Curent Defs size %lu",
				dbhandlerid_, adeftbl_.size());
		}	

		try {
			new (pdef) MDB_ALERTDEF(jdoc, jdoc.GetAllocator(), emsg.adef_id_, tcurr);
		}	
		catch(...) {
			defpool_.free(pdef);
			throw;
		}	

		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Alertmgr DB Handler %d adding new Alert Definition \'%s\'\n", dbhandlerid_, pdef->name());

		auto				puniq = std::unique_ptr<MDB_ALERTDEF, MDB_ADEL>(pdef, defpool_);

		adeftbl_.try_emplace(emsg.adef_id_, std::move(puniq));

		last_upd_cusec_.store(get_usec_clock(), mo_relaxed);
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while adding new DB Alert def : %s\n\n", GY_GET_EXCEPT_STRING);
	);
}	

void MDB_ALERT_HDLR::set_alert_state(uint32_t adef_id, time_t tcurr, ALERT_MSG_TYPE type, ADEF_STATE_E state) noexcept
{
	try {
		if (adef_id == 0) {
			return;
		}	

		auto				ait = adeftbl_.find(adef_id);	// Locking not needed as only this thread is a writer

		if (ait != adeftbl_.end()) {
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
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Alertmgr DB Handler %d Deleting Alert Definition \'%s\'\n", dbhandlerid_, pdef->name());

					adeftbl_.erase(ait);

					last_upd_cusec_.store(get_usec_clock(), mo_relaxed);
				}
			}	
		}
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while setting state of DB Alert def : %s\n\n", GY_GET_EXCEPT_STRING);
	);
}

void MDB_ALERT_HDLR::handle_def_reset(MDB_ALERTDEF *pdef, bool is_deleted, bool only_pending) 
{
	if (is_deleted) {
		pdef->set_deleted();
	}

	const auto deltimes = [&](MDB_ALERT_STATS *pstat, uint64_t key) 
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
		
		if (only_pending && MALERT_PENDING != pstat->state_) {
			++it;
			continue;
		}	

		deltimes(pstat, pstat->tnextchkusec_);

		it = astat_tbl.erase(it);
	}
}	


void MALERT_HDLR::handle_adef_new(comm::SM_ALERT_ADEF_NEW *pdef, int nevents, const uint8_t *pendptr)
{
	time_t				tcurr = time(nullptr);
	auto				pone = pdef;

	for (int i = 0; i < nevents && (uint8_t *)pone < pendptr; ++i, pone = (decltype(pone))((uint8_t *)pone + pone->get_elem_size())) {
		
		if (pone->lenjson_ <= 1) {
			continue;
		}	

		if (pone->for_partha_) {
			// XXX Not currently handled
			continue;
		}	

		MPSC_AMSGQ			*pqueue;
		char				*pjson = (char *)malloc_or_throw(pone->lenjson_);

		std::memcpy(pjson, (char *)(pone + 1), pone->lenjson_);

		if (pone->isrealtime_) {
			pqueue = &rthdlr_.aqueue_;	
		}
		else {
			auto		& hdlr = get_alertdef_db_hdlr(pone->adef_id_);

			pqueue = &hdlr.aqueue_;
		}	

		pqueue->blockingWrite(ALERT_ADEF_NEW, pone->adef_id_, tcurr, pjson, ::free, pone->lenjson_ - 1, pone->state_, pone->asubsys_);
	}
}	

void MALERT_HDLR::handle_adef_upd(comm::SM_ALERT_ADEF_UPD *pdef, int nevents, const uint8_t *pendptr)
{
	time_t				tcurr = time(nullptr);
	auto				pone = pdef;

	for (int i = 0; i < nevents && (uint8_t *)pone < pendptr; ++i, ++pone) {
		MPSC_AMSGQ			*pqueue;

		if (pone->type_ <= ALERT_ADEF_NEW) {
			continue;
		}

		if (pone->isrealtime_) {
			pqueue = &rthdlr_.aqueue_;	
		}
		else {
			auto		& hdlr = get_alertdef_db_hdlr(pone->adef_id_);

			pqueue = &hdlr.aqueue_;
		}	

		pqueue->blockingWrite(pone->type_, pone->adef_id_, tcurr);
	}
}	

void MALERT_HDLR::handle_astat_disable(const comm::SM_ALERT_STAT_DISABLE & astat)
{
	time_t				tcurr = time(nullptr);

	rthdlr_.tdisable_end_.store(astat.tdisable_end_, mo_relaxed);
	dbhdlr1_.tdisable_end_.store(astat.tdisable_end_, mo_relaxed);
	dbhdlr2_.tdisable_end_.store(astat.tdisable_end_, mo_relaxed);

	/*
	 * TODO : Once Partha based Alerts is done, we will need to send this to Partha's as well...
	 */

	if (tcurr > astat.tdisable_end_) {
		NOTEPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Received Shyama Alert Stat Disable Message : All subsequent alerts disabled for next %ld sec\n", tcurr - astat.tdisable_end_);
	}
	else {
		NOTEPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Received Shyama Alert Stat Enable Message : All subsequent alerts are now enabled\n");
	}	
}


bool MALERT_HDLR::send_rt_amsg(MALERT_MSG && amsg, const char *pstackjson, size_t szjson) 
{
	if (pstackjson && szjson) {
		// Allocate extra space to allow this to be sent as Alert Stat to Shyama

		char			*pjson;
		size_t			newsz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + sizeof(comm::ALERT_STAT_INFO) + szjson + 1 + 8;

		pjson = (char *)malloc_or_throw(newsz);

		std::memcpy(pjson + sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + sizeof(comm::ALERT_STAT_INFO), pstackjson, szjson + 1);
	
		amsg.set_json(pjson, ::free, newsz, szjson + 1);
	}	
	
	if (false == rthdlr_.aqueue_.write(std::move(amsg))) {
		rthdlr_.nmissed_.fetch_add_relaxed(1);
		return false;
	}	

	return true;
}	

void MALERT_HDLR::check_partha_rtalert_defs(MCONN_HANDLER *pconnhdlr, uint64_t curr_usec_clock) noexcept
{
	try {
		using				StackVec = INLINE_STACK_VECTOR<std::shared_ptr<MRT_ALERTDEF>, 20 * 1024>;
		StackVec			defvec;

		SCOPE_GY_MUTEX			scopelock(rthdlr_.adefmutex_);
		uint64_t			last_upd_cusec = rthdlr_.last_upd_cusec_.load(mo_relaxed);
		int				nextact = 0, nextcli = 0;

		defvec.reserve(rthdlr_.adeftbl_.size());
		
		for (const auto & [id, puniq] : rthdlr_.adeftbl_) {
			const auto			pdefelem = puniq.get();

			if (!pdefelem || !pdefelem->is_valid() || pdefelem->get_def()->is_deleted()) {
				continue;
			}	

			auto			*pdef = pdefelem->get_def();

			if (pdef->asubsys_ == SUBSYS_EXTACTIVECONN) {
				nextact++;
			}	
			else if (pdef->asubsys_ == SUBSYS_EXTCLIENTCONN) {
				nextcli++;
			}	

			defvec.emplace_back(pdefelem->defshr_);
		}	

		scopelock.unlock();
		
		const auto hostvalid = [&](const MCONN_HANDLER::PARTHA_INFO *prawpartha, const MRT_ALERTDEF *pdef)
		{
			if (false == pdef->has_rt_host_filter()) {
				return true;
			}
			
			const auto			*poptions = pdef->get_rt_options();

			if (!poptions) return false;

			if (false == pdef->is_multi_host_) {
				return prawpartha->machine_id_ == poptions->get_parid();
			}	
			
			const auto			& criteria = poptions->get_filter_criteria();
			
			return CRIT_FAIL != MCONN_HANDLER::HostFields(*prawpartha, pconnhdlr->gmadhava_id_str_).filter_match(criteria); 
		};	

		const auto lampar = [&, last_upd_cusec](MCONN_HANDLER::PARTHA_INFO_ELEM *pdatanode, void *arg1) -> CB_RET_E
		{
			auto				prawpartha = pdatanode->get_cref().get();

			if (!prawpartha) return CB_OK;

			auto				& rtalerts = prawpartha->rtalerts_;
			
			if (rtalerts.last_upd_cusec_.load(mo_relaxed) == last_upd_cusec) {
				return CB_OK;
			}	

			SharedMutex::WriteHolder	rtscope(rtalerts.adef_rwmutex_);
			
			rtalerts.reset_locked();

			for (const auto & defshr : defvec) {
				if (true == hostvalid(prawpartha, defshr.get())) {
					auto		*pvec = rtalerts.get_subsys_vec(defshr->asubsys_);

					if (pvec) {
						pvec->emplace_back(defshr);
					}	
				}	
			}	

			rtalerts.nextact_ 	= nextact;
			rtalerts.nextcli_	= nextcli;

			rtalerts.last_upd_cusec_.store(last_upd_cusec, mo_relaxed);

			return CB_OK;
		};

		pconnhdlr->partha_tbl_.walk_hash_table(lampar);

	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while checking Partha Realtime Alert Defs : %s\n", GY_GET_EXCEPT_STRING);
	);
}	


MALERT_HDLR::MALERT_HDLR(MCONN_HANDLER *pconnhdlr)
	:
	cusec_start_(({
			galerthdlr 	= this;
			g_madhava_id 	= pconnhdlr->gmadhava_id_;
			get_usec_clock();
			})),
	dbhdlr1_(1, pconnhdlr->get_settings()->postgres_hostname, pconnhdlr->get_settings()->postgres_port, pconnhdlr->get_settings()->postgres_user, 
			pconnhdlr->get_settings()->postgres_password, pconnhdlr->get_dbname().get()),
	dbhdlr2_(2, pconnhdlr->get_settings()->postgres_hostname, pconnhdlr->get_settings()->postgres_port, pconnhdlr->get_settings()->postgres_user, 
			pconnhdlr->get_settings()->postgres_password, pconnhdlr->get_dbname().get()),
	rt_thr_("Realtime Alert Thread", MCONN_HANDLER::GET_PTHREAD_WRAPPER(alert_realtime_thread), pconnhdlr, nullptr, nullptr, 
		true, 2 * 1024 * 1024 /* Stack */, 2000, true, true, true /* thr_func_calls_init_done */, 5000, true),
	db_thr1_("DB Alert Thread 1", MCONN_HANDLER::GET_PTHREAD_WRAPPER(alert_db_thread), alloc_thread_args(pconnhdlr, &dbhdlr1_), nullptr, nullptr, 
		true, 2 * 1024 * 1024 /* Stack */, 2000, true, true, true /* thr_func_calls_init_done */, 5000, true),
	db_thr2_("DB Alert Thread 2", MCONN_HANDLER::GET_PTHREAD_WRAPPER(alert_db_thread), alloc_thread_args(pconnhdlr, &dbhdlr2_), nullptr, nullptr,
		true, 2 * 1024 * 1024 /* Stack */, 2000, true, true, true /* thr_func_calls_init_done */, 5000, true)
	
{
	rt_thr_.clear_cond();
	db_thr1_.clear_cond();
	db_thr2_.clear_cond();

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Initialized Alert Handler Objects successfully...\n");
}

MALERT_HDLR * MALERT_HDLR::get_singleton() noexcept
{
	return galerthdlr;
}	

} // namespace madhava
} // namespace gyeeta	

