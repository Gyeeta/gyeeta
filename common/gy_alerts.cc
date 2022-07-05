
#include			"gy_alerts.h"


namespace gyeeta {

ALERTDEF_COMMON::ALERTDEF_COMMON(GEN_JSON_VALUE & jdoc, JSON_ALLOCATOR & allocator, uint32_t adef_id, time_t tcurr)
	: adef_id_(adef_id)
{
	if (false == jdoc.IsObject()) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition : Not of a JSON Object type");
	}	

	int			ret;
	const char		*pname = nullptr, *ptmp;

	auto 			aiter = jdoc.FindMember("alertname"); 

	if ((aiter != jdoc.MemberEnd()) && (aiter->value.IsString())) {
		size_t			namelen = aiter->value.GetStringLength();

		pname = aiter->value.GetString();

		validate_json_name(pname, namelen, MAX_ALERT_NAME_LEN, "Alert Definition");

		name_.assign(pname, namelen);

		if (adef_id == 0) {
			adef_id_ = get_adef_id(pname, namelen);
		}	
	}	
	else {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition : Invalid field or missing mandatory field \'alertname\'");
	}	
	
	aiter = jdoc.FindMember("startsat");
	if ((aiter != jdoc.MemberEnd()) && (aiter->value.IsString())) {
		tstart_sec_ = gy_iso8601_to_time_t(aiter->value.GetString());

		if (tstart_sec_ == 0) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : Invalid field \'startsat\' time : \'%s\'", pname, aiter->value.GetString());
		}	
		else if (tstart_sec_ > tcurr + 60) {
			state_.store(ADEFSTATE_DISABLED, mo_relaxed);
		}	
	}
	else if (aiter != jdoc.MemberEnd()) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : Invalid field \'startsat\' format : Needs to be an ISO8601 string", pname);
	}	
	else {
		tstart_sec_ = tcurr;
	}	

	aiter = jdoc.FindMember("endsat");
	if ((aiter != jdoc.MemberEnd()) && (aiter->value.IsString())) {
		tend_sec_ = gy_iso8601_to_time_t(aiter->value.GetString());

		if (tend_sec_ == 0) {
			tend_sec_ = LONG_MAX - 1;
		}	
		else if (tend_sec_ < tstart_sec_) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : Invalid time : \'endsat\' time is less than \'startsat\' : \'%s\'", 
					pname, aiter->value.GetString());
		}	
		else if (tend_sec_ <= tcurr + 5) {
			state_.store(ADEFSTATE_DISABLED, mo_relaxed);
		}	
	}
	else if (aiter != jdoc.MemberEnd()) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : Invalid field \'endsat\' format : Needs to be an ISO8601 string", pname);
	}	
	else {
		tend_sec_ = LONG_MAX - 1;
	}	

	aiter = jdoc.FindMember("queryopt");
	if (aiter != jdoc.MemberEnd()) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : Internal reserved field \'queryopt\' already present in JSON", pname); 
	}	

	aiter = jdoc.FindMember("starttime");
	if (aiter != jdoc.MemberEnd()) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : invalid field \'starttime\' specified for Alert JSON", pname); 
	}

	aiter = jdoc.FindMember("multiqueryarr");

	if (aiter != jdoc.MemberEnd()) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : multiqueryarr field seen : Cannot club multiple definitions into one", pname); 
	}	

	aiter = jdoc.FindMember("subsys");

	if (aiter == jdoc.MemberEnd()) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : Required field \'subsys\' is missing", pname); 
	}	
	else if (false == aiter->value.IsString()) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : Required field \'subsys\' is not of string type", pname); 
	}	

	auto			psubsys = get_jsoncrc_mapping(aiter->value.GetString(), aiter->value.GetStringLength(), subsys_class_list, SUBSYS_MAX);
	
	if (!psubsys) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : Invalid Subsystem \'%s\' specified within field \'subsys\'", 
				pname, aiter->value.GetString());
	}

	asubsys_		= psubsys->subsysval;
	pasubsys_		= psubsys->jsonstr;

	auto			*psubsys_stat = get_subsys_stats(asubsys_);

	if (!psubsys_stat || psubsys_stat->akeytype == AKEY_INVALID) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : Invalid \'subsys\' specified \'%s\' : Alerts not supported for this subsystem", 
				pname, pasubsys_);
	}	

	// Create the options json object
	create_queryopt_obj(jdoc, allocator);

	aiter = jdoc.FindMember("queryopt");
	if (aiter == jdoc.MemberEnd()) {
		GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "[Internal Error] Alert Definition for alertname \'%s\' : \'queryopt\' field not found", pname); 
	}

	const auto		& qval = aiter->value;
	
	if (false == isrealtime_) {
		auto			pdbclass = get_subsys_aggr_info(psubsys->subsysval);

		if (!pdbclass) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : "
							"Invalid Subsystem \'%s\' specified within field \'subsys\' as Aggregation not supported", pname, pasubsys_);
		}	

		if (pdbclass->paggrinfo == nullptr) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : Invalid Subsystem \'%s\' specified as Aggregation not allowed for this subsystem", 
							pname, pasubsys_);
		}	

		if (query_period_sec_ < pdbclass->minqrysec) {
			query_period_sec_ = pdbclass->minqrysec;
		}	

		STACK_POOL_ALLOC_32K		stackpool;
		QUERY_OPTIONS			qryopt(qval, stackpool, false /* is_multiquery */, 0, false /* allocregex */, &asubsys_);
		
		auto				aggropt = qryopt.get_aggr_options();

		if (!bool(aggropt)) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : Query Period specified without Aggregation : Please set Aggregation options", pname);
		}	
		
		if (aggropt->first != 0) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : Query Period specified along with Aggregation Period : "
						"Please reset Aggregation period", pname);
		}	

		if (qryopt.get_max_records() > MAX_ONE_ALERT_ROWS) {
			qryopt.set_max_records(MAX_ONE_ALERT_ROWS);
		}

		qryopt.set_timestamps(tplaceholderstart_, tplaceholderend_, false);

		is_multi_host_ = qryopt.is_multi_host();

		set_aggr_query(qryopt);
	}	
	else {
		// Populate criteria_
		colstr_.reset(new char[16 * 1024]);
		
		EXT_POOL_ALLOC			extpool(colstr_.get(), 16 * 1024);

		rtqrtopt_.reset(new QUERY_OPTIONS(qval, extpool, false /* is_multiquery */, 0, true /* allocregex */, &asubsys_));
		
		const auto			& criteria = rtqrtopt_->get_filter_criteria();

		if (false == criteria.has_filter_criteria()) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : no \'filter\' criteria seen for Realtime Alerts", pname);
		}	

		extpool.set_heap_allowed(false);

		if (rtqrtopt_->is_column_list()) {
			ncols_		= rtqrtopt_->ncols_;
			pconstcolarr_ 	= rtqrtopt_->columnarr_;

			if (rtqrtopt_->is_multi_host()) {
				/*
				 * Host subsystem fields may not be set by Options handler
				 */
				
				size_t				n = 0;

				for (; n < ncols_; ++n) {
					if (pconstcolarr_[n]->subsys == SUBSYS_HOST) {
						break;
					}	
				}	

				if (n == ncols_) {
					// Already allocated extra fields : We don't update rtqrtopt_->ncols_
					for (n = 0; n < GY_ARRAY_SIZE(json_db_host_arr); ++n) {
						pconstcolarr_[ncols_++] = json_db_host_arr + n;
					}
				}
			}	
		}
		else {
			if (rtqrtopt_->is_multi_host()) {
				ncols_ = psubsys->szjsonmap + GY_ARRAY_SIZE(json_db_host_arr);
			}
			else {
				ncols_ = psubsys->szjsonmap;
			}	


			try {
				pconstcolarr_ = (const JSON_DB_MAPPING **)extpool.safe_malloc(ncols_ * sizeof(const JSON_DB_MAPPING *));
			}
			catch(...) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : Filters set too large : Memory assigned used up : Please reduce the filters", pname);
			}	

			size_t			n = 0;

			if (rtqrtopt_->is_multi_host()) {
				for (; n < GY_ARRAY_SIZE(json_db_host_arr); ++n) {
					pconstcolarr_[n] = json_db_host_arr + n;
				}
			}	

			for (size_t i = 0; i < psubsys->szjsonmap; ++i) {
				pconstcolarr_[n + i] = psubsys->pjsonmap + i;
			}	
		}
		
		rt_host_filter_ = ((false == rtqrtopt_->is_multi_host()) || criteria.has_subsystem(SUBSYS_HOST));
		is_multi_host_ = rtqrtopt_->is_multi_host();
	}	
	
	ahdlr_		= get_subsys_handler(asubsys_, pasubsys_, pname);
	akeytype_ 	= get_subsys_key_type(asubsys_, pasubsys_, pname);

	aiter = jdoc.FindMember("manualresolve");
	if (aiter != jdoc.MemberEnd() && aiter->value.IsBool()) {
		manual_resolve_ = aiter->value.GetBool();
	}	

	aiter = jdoc.FindMember("numcheckfor");
	if (aiter != jdoc.MemberEnd()) {
		if (false == aiter->value.IsInt()) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : \'numcheckfor\' field must be of int type", pname);
		}	

		ret = aiter->value.GetInt();

		if (ret > MAX_ALERT_NUM_CHECK_FOR || ret < 0) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : \'numcheckfor\' field must at most %ld", pname, MAX_ALERT_NUM_CHECK_FOR);
		}

		if (ret > 1) {
			numcheckfor_ = ret;
		}	
	}	

	subsys_inter_sec_ = psubsys_stat->upd_inter_sec;

	if (false == isrealtime_) {

		aiter = jdoc.FindMember("queryevery");
		
		if (aiter != jdoc.MemberEnd()) {
			if (false == aiter->value.IsNumber()) {
				if (false == aiter->value.IsString()) {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : field \'queryevery\' not of int/string type", pname); 
				}

				auto			onum = get_time_modifier_secs(aiter->value.GetString(), aiter->value.GetStringLength(), 0);

				if (!onum) {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : field \'queryevery\' value \'%s\' is not a valid time modifier like \'10m\'", 
										pname, aiter->value.GetString()); 
				}	
				
				ret = *onum;
			}	
			else {
				ret = (int)aiter->value.GetDouble();
			}

			if (ret < MIN_ALERT_QUERY_INTERVAL_SEC && ret != 0) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : \'queryevery\' value must be at least %ld sec", 
								pname, MIN_ALERT_QUERY_INTERVAL_SEC);
			}	

			if (ret != DFLT_ALERT_QUERY_INTERVAL_SEC && ret) {
				query_interval_sec_ = ret;
			}	
		}	

		if (query_interval_sec_ < subsys_inter_sec_) {
			query_interval_sec_ = subsys_inter_sec_;
		}	
	}

	aiter = jdoc.FindMember("repeatafter");
	if (aiter != jdoc.MemberEnd()) {
		if (false == aiter->value.IsNumber()) {
			if (false == aiter->value.IsString()) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : field \'repeatafter\' not of int/string type", pname); 
			}

			auto			onum = get_time_modifier_secs(aiter->value.GetString(), aiter->value.GetStringLength(), 0);

			if (!onum) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : field \'repeatafter\' value \'%s\' is not a valid time modifier like \'10h\'", 
									pname, aiter->value.GetString()); 
			}	
			
			ret = *onum;
		}	
		else {
			ret = (int)aiter->value.GetDouble();
		}

		if (ret < MIN_ALERT_REPEAT_INTERVAL_SEC && ret != 0) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : \'repeatafter\' value must be at least %ld sec", pname, MIN_ALERT_REPEAT_INTERVAL_SEC);
		}	

		if (ret != DFLT_ALERT_REPEAT_INTERVAL_SEC) {
			repeataftersec_ = ret;
		}	
	}	

	aiter = jdoc.FindMember("groupwait");
	if (aiter != jdoc.MemberEnd()) {
		if (false == aiter->value.IsNumber()) {
			if (false == aiter->value.IsString()) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : field \'groupwait\' not of int/string type", pname); 
			}

			auto			onum = get_time_modifier_secs(aiter->value.GetString(), aiter->value.GetStringLength(), 0);

			if (!onum) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : field \'groupwait\' value \'%s\' is not a valid time modifier like \'10s\'", 
									pname, aiter->value.GetString()); 
			}	
			
			ret = *onum;
		}	
		else {
			ret = (int)aiter->value.GetDouble();
		}

		if ((uint32_t)ret > MAX_GROUP_WAIT_SEC) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : \'groupwait\' value must be less than %ld sec", pname, MAX_GROUP_WAIT_SEC);
		}	

		if (ret != DFLT_GROUP_WAIT_SEC) {
			groupwaitsec_ = ret;
		}	
	}	

	aiter = jdoc.FindMember("forceclose");
	if (aiter != jdoc.MemberEnd()) {
		if (false == aiter->value.IsNumber()) {
			if (false == aiter->value.IsString()) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : field \'forceclose\' not of int/string type", pname); 
			}

			auto			onum = get_time_modifier_secs(aiter->value.GetString(), aiter->value.GetStringLength(), MAX_ALERT_FORCE_CLOSE_SEC);

			if (!onum) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : field \'forceclose\' value \'%s\' is not a valid time modifier like \'6h\'", 
									pname, aiter->value.GetString()); 
			}	
			
			ret = *onum;
		}	
		else {
			ret = (int)aiter->value.GetDouble();
		}

		if (ret > MAX_ALERT_FORCE_CLOSE_SEC || ret < MIN_ALERT_FORCE_CLOSE_SEC) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : \'forceclose\' value must be a value between %ld minutes and max %ld hours", 
							pname, MIN_ALERT_FORCE_CLOSE_SEC/60, MAX_ALERT_FORCE_CLOSE_SEC/3600);
		}	

		if (ret != DFLT_ALERT_FORCE_CLOSE_SEC && ret) {
			forceclosesec_ = ret;
		}	
	}	
}	

void ALERTDEF_COMMON::create_queryopt_obj(GEN_JSON_VALUE & jdoc, JSON_ALLOCATOR & allocator)
{
	/*
	 * We consider the following fields to be added :
	 *
		"queryopt" : {
			"timeoffsetsec"		: 60,
			"parid"			: "...",
			"madid" 		: "...",
			"options" : {
				"aggregate" : true,	// Only for DB Alerts
				"aggroper" : "max",	
				"columns" : ["..."],	
				"filter" : "...",
				"aggrfilter" : "...",	// Only for DB Alerts
				"onlyremote" : false	// Currently ignored 
			}
		}
	 * 	
	 * From the original json, we remove/move the members :
	 * 	
	 * alerttype, queryperiod, filter, aggrfilter, columns
	 */

	const char			*pname = name_.c_str();
	bool				is_type_set = false;

	rapidjson::Value		qoptval(rapidjson::kObjectType), optval(rapidjson::kObjectType);

	auto				it = jdoc.FindMember("alerttype");

	if (it != jdoc.MemberEnd()) {
		if (false == it->value.IsString()) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : field \'alerttype\' not of string type", pname); 
		}
		
		const char		*alerttype = it->value.GetString();

		if (0 == strcmp(alerttype, "realtime")) {
			isrealtime_ 		= true;
			query_period_sec_ 	= 0;
		}	
		else if (0 == strcmp(alerttype, "dbaggr")) {
			isrealtime_ 		= false;
		}	
		else {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : field \'alerttype\' value \'%s\' not valid. "
							"Please specify either \'realtime\' or \'dbaggr\'", pname, alerttype); 
		}	

		jdoc.RemoveMember("alerttype");

		is_type_set = true;
	}	

	it = jdoc.FindMember("queryperiod");

	if (it == jdoc.MemberEnd()) {
		if (is_type_set && isrealtime_ == false) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : \'dbaggr\' type set but mandatory field \'queryperiod\' missing", pname); 
		}

		isrealtime_ 		= true;
		query_period_sec_ 	= 0;
	}	
	else {
		if (is_type_set && isrealtime_ == true) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : \'realtime\' type set but \'queryperiod\' specified."
						"\'queryperiod\' not valid for \'realtime\' alerts...", pname); 
		}

		if (false == it->value.IsInt()) {
			if (false == it->value.IsString()) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : field \'queryperiod\' not of int/string type", pname); 
			}

			auto			onum = get_time_modifier_secs(it->value.GetString(), it->value.GetStringLength(), 0);

			if (!onum) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : field \'queryperiod\' value \'%s\' is not a valid time modifier like \'10m\'", 
									pname, it->value.GetString()); 
			}	

			query_period_sec_ = *onum;
		}
		else {
			query_period_sec_ = it->value.GetUint();
		}	

		if (query_period_sec_ < 10) {
			isrealtime_ 		= true;
			query_period_sec_ 	= 0;
		}	
		else if (query_period_sec_ > MAX_ALERT_QUERY_PERIOD_SEC) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : Query Period (\'queryperiod\') too large : %d hours : Max allowed is %ld hours", 
								pname, query_period_sec_/3600, MAX_ALERT_QUERY_PERIOD_SEC/3600);	
		}
		else {
			isrealtime_ = false;
			optval.AddMember("aggregate", true, allocator);
		}
	
		jdoc.RemoveMember("queryperiod");
		qoptval.AddMember("timeoffsetsec", query_period_sec_, allocator);
	}	

	it = jdoc.FindMember("filter");

	if (it != jdoc.MemberEnd()) {
		optval.AddMember("filter", std::move(it->value), allocator);
		jdoc.RemoveMember("filter");
	}

	it = jdoc.FindMember("aggrfilter");

	if (it != jdoc.MemberEnd()) {
		if (isrealtime_) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : "
				"\'aggrfilter\' field not allowed for realtime alerts : Please specify all required fields for real time alerts in \'filter\' field", pname); 
		}

		optval.AddMember("aggrfilter", std::move(it->value), allocator);
		jdoc.RemoveMember("aggrfilter");
	}
	else if (false == isrealtime_) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : "
			"Mandatory \'aggrfilter\' field not specified for DB Aggregated (dbaggr) alerts. Please specify the Post Aggregation filter in this field. ", pname); 

	}	

	it = jdoc.FindMember("columns");

	if (it != jdoc.MemberEnd()) {
		optval.AddMember("columns", std::move(it->value), allocator);
		jdoc.RemoveMember("columns");
	}

	if (false == isrealtime_) {
		it = jdoc.FindMember("aggroper");
		
		if (it != jdoc.MemberEnd()) {
			if (false == it->value.IsString()) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : field \'aggroper\' not of string type", pname); 
			}	
			
			optval.AddMember("aggroper", std::move(it->value), allocator);
			jdoc.RemoveMember("aggroper");
		}	

	}	

	qoptval.AddMember("options", std::move(optval), allocator);
	jdoc.AddMember("queryopt", std::move(qoptval), allocator);
}	


void ALERTDEF_COMMON::set_aggr_query(QUERY_OPTIONS & qryopt) 
{
	JSON_DB_MAPPING			acolarr[QUERY_OPTIONS::MAX_AGGR_COLUMNS];
	STRING_BUFFER<48 * 1024>	strbuf;
	uint32_t			ncols;
	const char			*madhava_id_str;

	colstr_.reset(new char[qryopt.MAX_AGGR_COL_BUFSZ + 1600]);

	EXT_POOL_ALLOC			strpool(colstr_.get(), qryopt.MAX_AGGR_COL_BUFSZ + 1600, nullptr, true /* noheap_alloc */);

	switch (asubsys_) {

	case SUBSYS_HOSTSTATE :	
		ncols = get_hoststate_aggr_query(strbuf, qryopt, partplaceholder_, acolarr, &strpool);
		break;

	case SUBSYS_CPUMEM :	
		ncols = get_cpumem_aggr_query(strbuf, qryopt, partplaceholder_, acolarr, &strpool);
		break;

	case SUBSYS_SVCSUMM :
		ncols = get_svcsumm_aggr_query(strbuf, qryopt, partplaceholder_, acolarr, &strpool);
		break;

	case SUBSYS_SVCSTATE :
	case SUBSYS_EXTSVCSTATE :
		ncols = get_svcstate_aggr_query(strbuf, qryopt, partplaceholder_, acolarr, &strpool, asubsys_ == SUBSYS_EXTSVCSTATE);
		break;
		
	case SUBSYS_SVCINFO :
		ncols = get_svcinfo_aggr_query(strbuf, qryopt, partplaceholder_, acolarr, &strpool);
		break;
		
	case SUBSYS_ACTIVECONN :
	case SUBSYS_EXTACTIVECONN :
		ncols = get_activeconn_aggr_query(strbuf, qryopt, partplaceholder_, acolarr, &strpool, asubsys_ == SUBSYS_EXTACTIVECONN);
		break;

	case SUBSYS_CLIENTCONN :
	case SUBSYS_EXTCLIENTCONN :
		madhava_id_str = qryopt.get_madhava_id();
		if (!madhava_id_str) {
			madhava_id_str = "0000000000000000";
		}	

		ncols = get_clientconn_aggr_query(strbuf, qryopt, partplaceholder_, acolarr, madhava_id_str, &strpool, asubsys_ == SUBSYS_EXTCLIENTCONN);
		break;

	case SUBSYS_PROCSTATE :	
	case SUBSYS_EXTPROCSTATE :	
		ncols = get_procstate_aggr_query(strbuf, qryopt, partplaceholder_, acolarr, &strpool, asubsys_ == SUBSYS_EXTPROCSTATE);
		break;
		
	case SUBSYS_PROCINFO :	
		ncols = get_procinfo_aggr_query(strbuf, qryopt, partplaceholder_, acolarr, &strpool);
		break;
		
	case SUBSYS_CLUSTERSTATE :	
		ncols = get_clusterstate_aggr_query(strbuf, qryopt, partplaceholder_, acolarr, &strpool);
		break;
		
	default :
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : Alert DB Aggregated Querying not supported for subsystem specified \'%s\'",
			name_.c_str(), pasubsys_);
	}

	if (false == qryopt.has_aggr_filters()) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : Mandatory Post Aggregation Filter missing. Please set an Aggregation filter...", name_.c_str());
	}
	
	dbquery_len_ = strbuf.length();
	
	dbquery_.reset(new char[dbquery_len_ + 1]);
	std::memcpy(dbquery_.get(), strbuf.buffer(), dbquery_len_ + 1);

	ncols_ = uint16_t(ncols);

	try {
		pcolarr_ 	= (decltype(pcolarr_))strpool.safe_malloc(ncols * sizeof(JSON_DB_MAPPING));
		pconstcolarr_ 	= (const JSON_DB_MAPPING **)strpool.safe_malloc(ncols_ * sizeof(const JSON_DB_MAPPING *));
	}
	catch(...) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : Aggregation Filters or columns set too large : Memory assigned used up : Please reduce the filters", 
				name_.c_str());
	}

	std::memcpy(pcolarr_, acolarr, ncols * sizeof(JSON_DB_MAPPING));

	for (size_t i = 0; i < ncols_; ++i) {
		pconstcolarr_[i] = pcolarr_ + i;
	}	

	if (get_jsoncrc_mapping(FIELD_TIME, pcolarr_, ncols_)) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alertname \'%s\' : "
			"DB Aggregated Querying specified along with \'time\' column specified using \'aggrsec\' option which is not allowed", name_.c_str());
	}	

	auto		pkey = get_aggr_subsys_keyid(asubsys_, pcolarr_, ncols_);

	keyid_col_ 	= pkey.first;
	keyid_colnum_	= pkey.second;
}	

static void replace_string(char *pstart, char *pend, const char *placehold, uint32_t nplace, const char *newbuf) noexcept
{
	char			*ptmp = pstart;

	while (ptmp < pend) {
		ptmp = (char *)memmem(ptmp, pend - ptmp, placehold, nplace);
		if (ptmp) {
			std::memcpy(ptmp, newbuf, nplace);
		}	
		else {
			break;
		}	
		
		ptmp += nplace;
	}	
}	

bool ALERTDEF_COMMON::get_db_query(STR_WR_BUF & strbuf, time_t tstart, time_t tend) noexcept
{
	if (!bool(dbquery_) || !dbquery_len_) {
		return false;
	}	

	const char			*pqry = dbquery_.get();

	if (strbuf.bytes_left() <= dbquery_len_) {
		return false;
	}	

	char				starttime[32], endtime[32], startplace[32], endplace[32];
	auto 				datetbl = get_db_day_partition(tstart, tend, 0);
	uint32_t			nplace, ntime;
	char				*pcurr = strbuf.get_current(), *pend = pcurr + dbquery_len_, *ptmp, placehold[16], newbuf[32];

	strbuf.append(pqry, dbquery_len_);

	ntime = snprintf(startplace, sizeof(startplace), "to_timestamp(%010ld)", tplaceholderstart_);
	snprintf(endplace, sizeof(endplace), "to_timestamp(%010ld)", tplaceholderend_);
	
	snprintf(starttime, sizeof(starttime), "to_timestamp(%010ld)", tstart);
	snprintf(endtime, sizeof(endtime), "to_timestamp(%010ld)", tend);

	if (is_multi_host_ && is_madhava_handled()) {
		nplace = GY_SAFE_SNPRINTF(placehold, sizeof(placehold), "\'%s\'", partplaceholder_);
		snprintf(newbuf, sizeof(newbuf), "\'%s\'            ", datetbl.get());
	}	
	else {
		nplace = GY_SAFE_SNPRINTF(placehold, sizeof(placehold), "%s", partplaceholder_);
		snprintf(newbuf, sizeof(newbuf), "%s            ", datetbl.get());
	}	

	replace_string(pcurr, pend, placehold, nplace, newbuf);
	
	replace_string(pcurr, pend, startplace, ntime, starttime);

	replace_string(pcurr, pend, endplace, ntime, endtime);

	return true;
}	

uint64_t ALERTDEF_COMMON::get_nextcheck_tusec(uint64_t currtusec, uint8_t curr_numhits) const noexcept
{
	uint64_t			nxt_tusec;
	uint8_t				nfor, npend = (curr_numhits < numcheckfor_ ? numcheckfor_ - curr_numhits : 1);

	if (npend > 1) {
		if (subsys_inter_sec_ >= 60) {
			nfor = 2;
		}
		else if (npend < 10) {
			nfor = npend;
		}	
		else {
			nfor = 10;
		}	
	}
	else {
		nfor = 1;
	}	

	nxt_tusec = currtusec + (nfor * subsys_inter_sec_ + 15) * GY_USEC_PER_SEC;

	if (nfor > 3 && nxt_tusec - currtusec > 100 * GY_USEC_PER_SEC) {
		nxt_tusec = currtusec + (3 * subsys_inter_sec_ + 15) * GY_USEC_PER_SEC;
	}	

	return nxt_tusec;
}	

ALERT_KEY_TYPE_E get_subsys_key_type(SUBSYS_CLASS_E asubsys, const char *pasubsys, const char *pname)
{
	ALERT_KEY_TYPE_E		akeytype;

	auto				*psubsys = get_subsys_stats(asubsys);

	if (!psubsys || psubsys->akeytype == AKEY_INVALID) {
		GY_THROW_EXCEPTION("Invalid Alert Definition for alertname \'%s\' : Invalid subsystem specified \'%s\' (%d) : Alerts not supported for this subsys", 
				pname, pasubsys, asubsys);
	}	

	return psubsys->akeytype;
}

ADEF_HDLR_E get_subsys_handler(SUBSYS_CLASS_E asubsys, const char *pasubsys, const char *pname)
{
	ADEF_HDLR_E			ahdlr;

	auto				*psubsys = get_subsys_stats(asubsys);

	if (!psubsys) {
		GY_THROW_EXCEPTION("Invalid Alert Definition for alertname \'%s\' : Invalid subsystem specified \'%s\' (%d) : Alerts not supported for this subsys", 
				pname, pasubsys, asubsys);
	}	

	return psubsys->ahandler;
}

std::pair<const JSON_DB_MAPPING *, uint16_t> get_aggr_subsys_keyid(SUBSYS_CLASS_E asubsys, const JSON_DB_MAPPING *acolarr, uint32_t ncols) noexcept
{
	/*
	 * Columns are arranged in decreasing order of uniqueness and significance within each subsystem
	 * NOTE : Keep only those columns which will always have value as else query response with rows
	 * having null keys will not be considered for alerts...
	 */
	static constexpr const uint32_t		hoststate_cols[] 	{ FIELD_PARID, FIELD_HOST, FIELD_CLUSTER };	
	static constexpr const uint32_t		cpumem_cols[] 		{ FIELD_PARID, FIELD_HOST, FIELD_CLUSTER };	
	static constexpr const uint32_t		svcstate_cols[] 	{ FIELD_SVCID, FIELD_PARID, FIELD_HOST, FIELD_NAME, FIELD_CLUSTER };	
	static constexpr const uint32_t		extsvcstate_cols[] 	{ FIELD_SVCID, FIELD_PARID, FIELD_HOST, FIELD_NAME, FIELD_CMDLINE, FIELD_PORT, FIELD_CLUSTER, FIELD_ZONE, FIELD_REGION };	
	static constexpr const uint32_t		svcinfo_cols[] 		{ FIELD_SVCID, FIELD_PARID, FIELD_HOST, FIELD_NAME, FIELD_CMDLINE, FIELD_PORT, FIELD_CLUSTER, FIELD_ZONE, FIELD_REGION };	
	static constexpr const uint32_t		svcsumm_cols[] 		{ FIELD_PARID, FIELD_HOST, FIELD_CLUSTER };	
	static constexpr const uint32_t		activeconn_cols[] 	{ FIELD_SVCID, FIELD_PARID, FIELD_HOST, FIELD_SVCNAME, FIELD_CPROCID, FIELD_CPARID, FIELD_CNAME, FIELD_CLUSTER };	
	static constexpr const uint32_t		extactiveconn_cols[] 	{ FIELD_SVCID, FIELD_PARID, FIELD_HOST, FIELD_SVCNAME, FIELD_CPROCID, FIELD_CPARID, FIELD_CNAME, FIELD_CMDLINE, FIELD_PORT, \
										FIELD_CLUSTER, FIELD_ZONE, FIELD_REGION };	
	static constexpr const uint32_t		clientconn_cols[] 	{ FIELD_CPROCID, FIELD_PARID, FIELD_HOST, FIELD_CNAME, FIELD_SVCID, FIELD_SPARID, FIELD_SVCNAME, FIELD_CLUSTER };	
	static constexpr const uint32_t		extclientconn_cols[] 	{ FIELD_CPROCID, FIELD_PARID, FIELD_HOST, FIELD_CNAME, FIELD_SVCID, FIELD_SPARID, FIELD_SVCNAME, FIELD_CMDLINE, \
										FIELD_CLUSTER, FIELD_ZONE, FIELD_REGION };	
	static constexpr const uint32_t		procstate_cols[] 	{ FIELD_PROCID, FIELD_PARID, FIELD_HOST, FIELD_NAME, FIELD_CLUSTER };	
	static constexpr const uint32_t		extprocstate_cols[] 	{ FIELD_PROCID, FIELD_PARID, FIELD_HOST, FIELD_NAME, FIELD_CMDLINE, FIELD_CLUSTER, FIELD_ZONE, FIELD_REGION };	
	static constexpr const uint32_t		procinfo_cols[] 	{ FIELD_PROCID, FIELD_PARID, FIELD_HOST, FIELD_NAME, FIELD_CMDLINE, FIELD_CLUSTER, FIELD_ZONE, FIELD_REGION };	
	static constexpr const uint32_t		clusterstate_cols[] 	{ FIELD_CLUSTER };	
	
	const uint32_t				*jcols = nullptr;
	uint32_t				nsubsyscol = 0;
	
	switch (asubsys) {
	
	case SUBSYS_HOSTSTATE 		:	jcols = hoststate_cols; nsubsyscol = GY_ARRAY_SIZE(hoststate_cols); break;

	case SUBSYS_CPUMEM 		:	jcols = cpumem_cols; nsubsyscol = GY_ARRAY_SIZE(cpumem_cols); break;
		
	case SUBSYS_SVCSTATE 		:	jcols = svcstate_cols; nsubsyscol = GY_ARRAY_SIZE(svcstate_cols); break;

	case SUBSYS_EXTSVCSTATE 	:	jcols = extsvcstate_cols; nsubsyscol = GY_ARRAY_SIZE(extsvcstate_cols); break;

	case SUBSYS_SVCINFO 		:	jcols = svcinfo_cols; nsubsyscol = GY_ARRAY_SIZE(svcinfo_cols); break;

	case SUBSYS_SVCSUMM 		:	jcols = svcsumm_cols; nsubsyscol = GY_ARRAY_SIZE(svcsumm_cols); break;
	
	case SUBSYS_ACTIVECONN 		:	jcols = activeconn_cols; nsubsyscol = GY_ARRAY_SIZE(activeconn_cols); break;

	case SUBSYS_EXTACTIVECONN 	:	jcols = extactiveconn_cols; nsubsyscol = GY_ARRAY_SIZE(extactiveconn_cols); break;

	case SUBSYS_CLIENTCONN 		:	jcols = clientconn_cols; nsubsyscol = GY_ARRAY_SIZE(clientconn_cols); break;

	case SUBSYS_EXTCLIENTCONN 	:	jcols = extclientconn_cols; nsubsyscol = GY_ARRAY_SIZE(extclientconn_cols); break;
						
	case SUBSYS_PROCSTATE 		:	jcols = procstate_cols; nsubsyscol = GY_ARRAY_SIZE(procstate_cols); break;

	case SUBSYS_EXTPROCSTATE 	:	jcols = extprocstate_cols; nsubsyscol = GY_ARRAY_SIZE(extprocstate_cols); break;
						
	case SUBSYS_PROCINFO 		:	jcols = procinfo_cols; nsubsyscol = GY_ARRAY_SIZE(procinfo_cols); break;

	case SUBSYS_CLUSTERSTATE 	:	jcols = clusterstate_cols; nsubsyscol = GY_ARRAY_SIZE(clusterstate_cols); break;

	default				:	return {};

	}

	for (size_t n = 0; n < nsubsyscol; ++n) {
		auto			crc = jcols[n];

		for (uint32_t i = 0; i < ncols; ++i) {
			const auto		pdata = acolarr + i;

			if (crc == pdata->jsoncrc) {
				assert(pdata->jsontype == JSON_STRING);

				return {pdata, i};
			}	
		}	
	}	
	
	return {};
}	


} // namespace gyeeta

