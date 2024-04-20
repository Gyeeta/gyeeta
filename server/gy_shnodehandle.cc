//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later


#include		"gy_common_inc.h"
#include		"gy_shconnhdlr.h"
#include		"gyshyama.h"
#include		"gy_print_offload.h"
#include		"gy_sdb_schema.h"
#include		"gy_shfields.h"
#include		"gy_alertmgr.h"

using namespace 	gyeeta::comm;

namespace gyeeta {
namespace shyama {

bool SHCONN_HANDLER::handle_node_query(const std::shared_ptr<SHCONNTRACK> & connshr, const comm::QUERY_CMD *pquery, char *pjson, char *pendptr, \
				POOL_ALLOC_ARRAY *pthrpoolarr, STATS_STR_MAP & statsmap, PGConnPool & dbpool)
{
	try {
		time_t				tcurr = time(nullptr);
		uint64_t			resp_seqid = pquery->get_seqid();

		if (gy_unlikely(pquery->is_expired(tcurr))) {
			statsmap["Conn Web Query Expired"]++;
			WARNPRINTCOLOR_OFFLOAD(GY_COLOR_LIGHT_RED, "Node Query received but Query already expired before starting processing...\n");
			
			send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), "Query already timed out before starting processing",
				GY_CONST_STRLEN("Query already timed out before starting processing"), pthrpoolarr);

			return false;
		}

		if (pjson + MAX_QUERY_STRLEN < pendptr) {
			send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), 
				gy_to_charbuf<256>("Max Query Length %lu exceeded : Please reduce the query size", MAX_QUERY_STRLEN).get());

			return false;
		}	

		CONDEXEC(
			DEBUGEXECN(12,
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Node Query seen : [%s]\n", CHAR_BUF<1024>(pjson, pendptr - pjson).get()); 
			);
		);

		JSON_DOCUMENT<16 * 1024, 8192>	doc;
		auto				& jdoc = doc.get_doc();

		if (pendptr > pjson && *(pendptr - 1) == 0) {
			jdoc.ParseInsitu(pjson);	
		}
		else {
			DEBUGEXECN(11, 
				WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Input JSON from Node not null terminated...\n");
			);	

			if (pendptr <= pjson) {
				return false;
			}

			jdoc.Parse(pjson, pendptr - pjson);
		}	

		if (jdoc.HasParseError()) {
			char			ebuf[256];
			const char		*perrorstr = rapidjson::GetParseError_En(jdoc.GetParseError());

			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Invalid Node Query : Error at offset %lu : Error is \'%s\'\n\n", 
				jdoc.GetErrorOffset(), perrorstr);

			auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Invalid Node Query : Error is %s", perrorstr);

			send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr, pthrpoolarr);
			return false;
		}	
		
		auto			mtype = gy_get_json_mtype(jdoc);
			
		if (mtype == NODE_MSG_QUERY) {

			auto 					qtype = gy_get_json_qtype(jdoc);

			if (qtype == NQUERY_NM_MULTI_QUERY) {
				constexpr const char		emsg[] = "Invalid Node Query : Multi Query Requests not allowed for Shyama Servers";

				send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), emsg, sizeof(emsg) - 1, pthrpoolarr);
				return false;
				
				// Currently not supported
				/*return web_multi_query(connshr, jdoc, pquery, pthrpoolarr, dbpool, statsmap);*/
			}	

			STACK_POOL_ALLOC_32K			stackpool;
			QUERY_OPTIONS				qryopt(jdoc, stackpool);

			SHSTREAM_JSON_EPOLL			stream(connshr, *this, RESP_WEB_JSON, pquery->get_seqid(), pthrpoolarr);
			SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL>	writer(stream);

			return web_query_route_qtype(connshr, qryopt, stackpool, pquery, writer, pthrpoolarr, statsmap, dbpool);
		}
		else if ((mtype == NODE_MSG_ADD) || (mtype == NODE_MSG_UPDATE) || (mtype == NODE_MSG_DELETE)) {
			// CRUD messages
			auto 					qtype = gy_get_json_qtype(jdoc);

			switch (qtype) {
			
			case NQUERY_NS_TRACEDEF :
				if (mtype == NODE_MSG_ADD) {
					handle_node_tracedef_add(connshr, jdoc, pquery, dbpool);
				}
				else if (mtype == NODE_MSG_DELETE) {
					handle_node_tracedef_delete(connshr, jdoc, pquery, dbpool);
				}
				else {
					handle_node_tracedef_update(connshr, jdoc, pquery, dbpool);
				}	
				break;

			default :			
				if (true) {
					char			ebuf[256];

					auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node CRUD Command received with invalid Query Type %d", qtype);

					send_json_error_resp(connshr, ERR_SERV_ERROR, pquery->get_seqid(), ebuf, lenerr);
				}

				return false;
			}	
		}	
		else if (mtype == NODE_MSG_PING) {
			SHSTREAM_JSON_EPOLL			stream(connshr, *this, RESP_WEB_JSON, resp_seqid, pthrpoolarr);
			SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL>	writer(stream);
			
			writer.StartObject();
			writer.KeyConst("id");
			writer.String(gshyama_id_str_, 16);
			writer.KeyConst("hosttime");
			writer.Uint64(get_usec_time()/1000);
			writer.KeyConst("lastchgmsec");	
			writer.Uint64(last_madhava_chg_tusec_.load(std::memory_order_acquire)/1000);
			writer.EndObject();

			return stream.set_resp_completed();
		}
		else {
			char			ebuf[256];

			auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Query with invalid / not handled Msg Type %d", mtype);

			send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr, pthrpoolarr);
			return false;
		}

		return false;

	}
	GY_CATCH_EXPRESSION(
		char			ebuf[256];
		int			ecode = GY_GET_EXCEPT_CODE();

		if (ecode == 0) ecode = ERR_SERV_ERROR;

		statsmap["Web Query Exception"]++;

		DEBUGEXECN(1,
			WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Web Query Exception caught : %s\n", GY_GET_EXCEPT_STRING);
		);
		
		auto sret = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Query Exception : %s", GY_GET_EXCEPT_STRING);

		send_json_error_resp(connshr, ERR_CODES_E(ecode), pquery->get_seqid(), ebuf, sret, pthrpoolarr);
		return false;
	);
}	

bool SHCONN_HANDLER::web_query_route_qtype(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, \
		const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, STATS_STR_MAP & statsmap, PGConnPool & dbpool)
{
	NODE_QUERY_TYPE_E		qtype;

	qtype = qryopt.get_query_type();

	switch (qtype) {
	
	case NQUERY_NS_MADHAVA_LIST :	
		statsmap["Node Madhava List Query"]++;
		return web_query_madhavalist(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);
	
	case NQUERY_NM_CLUSTER_STATE :	
		statsmap["Node Cluster State Query"]++;
		return web_query_clusterstate(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);
	
	case NQUERY_NS_SVC_MESH_CLUST :	
		statsmap["Node Svc Mesh Query"]++;
		return web_query_svcmeshcluster(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);
	
	case NQUERY_NS_SVC_IP_CLUST :	
		statsmap["Node Svc IP Query"]++;
		return web_query_svcipcluster(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);
	
	case NQUERY_NS_ALERTS :	
		statsmap["Node Alerts Query"]++;
		return web_query_alerts(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);
	
	case NQUERY_NS_ALERTDEF :	
		statsmap["Node Alert Def Query"]++;
		return web_query_alertdef(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);
	
	case NQUERY_NS_INHIBITS :	
		statsmap["Node Alert Inhibits Query"]++;
		return web_query_inhibits(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);
	
	case NQUERY_NS_SILENCES :	
		statsmap["Node Alert Silences Query"]++;
		return web_query_silences(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);
	
	case NQUERY_NS_ACTIONS :	
		statsmap["Node Alert Actions Query"]++;
		return web_query_actions(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);
	
	case NQUERY_NS_SHYAMASTATUS :	
		statsmap["Node Shyama Status Query"]++;
		return web_query_shyamastatus(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);
	
	case NQUERY_NS_TRACEDEF :	
		statsmap["Node Trace Def Query"]++;
		return web_query_tracedef(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);
	

	default :			
		if (writer.get_stream()->reset_if_not_sent(ERR_INVALID_REQUEST)) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Unhandled or invalid Query Type %d seen for Shyama server", qtype);
		}
		return false;
	}	
}	

// Currently not supported for Shyama servers
bool SHCONN_HANDLER::web_multi_query(const std::shared_ptr<SHCONNTRACK> & connshr, const GEN_JSON_VALUE & jdoc, const comm::QUERY_CMD *pquery, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool, STATS_STR_MAP & statsmap)
{
	STACK_POOL_ALLOC_64K			stackpool;
	std::optional<QUERY_OPTIONS>		qryoptarr[MAX_MULTI_QUERIES];
	uint8_t					nmulti_query;

	statsmap["Node Multi Query"]++;

	qryoptarr[0].emplace(jdoc, stackpool, true /* is_multiquery */, 0);

	nmulti_query = qryoptarr[0]->get_num_multiqueries();
	if (nmulti_query > MAX_MULTI_QUERIES) {
		
		char			errbuf[128];

		auto n = GY_SAFE_SNPRINTF(errbuf, sizeof(errbuf), "Multiquery Error : Max Multiquery count %lu exceeded : %u", MAX_MULTI_QUERIES, nmulti_query);

		send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), errbuf, n, pthrpoolarr);
		return false;
	}	

	for (uint8_t i = 1; i < nmulti_query; ++i) {
		qryoptarr[i].emplace(jdoc, stackpool, true /* is_multiquery */, i);
	}	

	SHSTREAM_JSON_EPOLL			stream(connshr, *this, RESP_WEB_JSON, pquery->get_seqid(), pthrpoolarr);
	SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL>	writer(stream);

	writer.StartObject();

	writer.KeyConst("shyamaid");
	writer.String(gshyama_id_str_, 16);

	for (uint8_t i = 0; i < nmulti_query; ++i) {
		auto				& qryopt = qryoptarr[i].value();
		bool				bret;

		writer.Key(qryopt.get_multiquery_id());

		bret = web_query_route_qtype(connshr, qryopt, stackpool, pquery, writer, pthrpoolarr, statsmap, dbpool);

		if (bret == false) {
			// Terminate the multi query
			return false;
		}	
	}	

	writer.EndObject();

	return true;
}

void SHCONN_HANDLER::noextracolcb(SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer) noexcept
{}


CRIT_RET_E SHCONN_HANDLER::madhavalist_filter_match(const CRITERIA_SET & criteria, const MADHAVA_INFO * pmad, bool ignore_other_subsys) const 
{
	const SUBSYS_CLASS_E		subsysarr[] {SUBSYS_MADHAVALIST};

	auto get_num_field = [&](const JSON_DB_MAPPING *pfield, SUBSYS_CLASS_E subsys) -> NUMBER_CRITERION
	{
		switch (pfield->jsoncrc) {

		case FIELD_PORT 		: 	return NUMBER_CRITERION((int)pmad->listener_port_.get_port());
		case FIELD_COMMVER 		: 	return NUMBER_CRITERION((int)pmad->comm_version_);
		case FIELD_NPARTHA 		: 	return NUMBER_CRITERION((int)pmad->npartha_nodes_.load(std::memory_order_relaxed));
		case FIELD_MAXPARTHA 		: 	return NUMBER_CRITERION((int)pmad->max_partha_nodes_);
		case FIELD_LASTSEEN		:	return NUMBER_CRITERION((int64_t)(pmad->last_status_tsec_));
		
		default				:	return {};
		}	
	};

	auto get_str_field = [&](const JSON_DB_MAPPING *pfield, char * tbuf, size_t szbuf, SUBSYS_CLASS_E subsys) -> std::pair<const char *, uint32_t>
	{

		switch (pfield->jsoncrc) {

		case FIELD_MADID		:
				if (tbuf && szbuf > 16) {
					std::pair<const char *, uint32_t>	p;

					p.first		= tbuf;
					p.second 	= snprintf(tbuf, szbuf, "%016lx", pmad->madhava_id_);

					return p;
				}
				return {};

		case FIELD_HOST 		: 	return { pmad->listener_port_.get_domain(),	strlen(pmad->listener_port_.get_domain()) };
		
		case FIELD_REGION		:	return { pmad->region_name_, strlen(pmad->region_name_) };

		case FIELD_ZONE			:	return { pmad->zone_name_, strlen(pmad->zone_name_) };

		case FIELD_MADHAVANAME		:	return { pmad->madhava_name_, strlen(pmad->madhava_name_) };

		case FIELD_VERSION		:	
						if (tbuf && szbuf > 16) {
							char			verbuf[32];
						
							uint32_t		lenv = GY_STRNCPY_LEN(tbuf, get_string_from_version_num(pmad->madhava_version_, verbuf, 3), szbuf);

							return { tbuf, lenv };
						}
						return {};

		default				:	return {};
		}	
	};	

	auto get_bool_field = [&](const JSON_DB_MAPPING *pfield, SUBSYS_CLASS_E subsys) -> BOOL_CRITERION
	{
		switch (pfield->jsoncrc) {

		case FIELD_ISCONN		:	return BOOL_CRITERION(!!pmad->get_num_conns());

		default				:	return {};
		}	
	};

	return criteria.match_criteria(get_num_field, get_str_field, get_bool_field, 0, ignore_other_subsys ? subsysarr : nullptr, ignore_other_subsys ? GY_ARRAY_SIZE(subsysarr) : 0);
}


bool SHCONN_HANDLER::web_query_madhavalist(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	try {
		const auto			*poption = qryopt.get_options_json();
		uint64_t			minchgusec = 0;
		int				nmad = 0;
		bool				nodefields = false;

		qryopt.comp_criteria_init();

		if (poption) {
			const auto		& optobj = poption->GetObject();

			auto			miter = optobj.FindMember("minchgmsec");

			if ((miter != optobj.MemberEnd()) && (miter->value.IsUint64())) {
				minchgusec = miter->value.GetUint64() * 1000;

				if (minchgusec > GY_USEC_PER_MINUTE) {
					minchgusec -= GY_USEC_PER_MINUTE;
				}	
			}	

			miter = optobj.FindMember("nodefields");

			if ((miter != optobj.MemberEnd()) && (miter->value.IsBool())) {
				nodefields = miter->value.GetBool();
			}
		}

		writer.StartObject();

		writer.KeyConst("shyamaid");
		writer.String(gshyama_id_str_, 16);

		writer.KeyConst("madhavalist");
		writer.StartArray();

		auto lammad = [&, minchgusec, nodefields, maxrecs = qryopt.get_max_records()](MADHAVA_INFO_ELEM *pdatanode, void *arg1) -> CB_RET_E
		{
			auto			pmad = pdatanode->get_data()->get();
			uint32_t		npar;
			
			if (gy_unlikely(pmad == nullptr)) {
				return CB_OK;
			}	
		
			npar = pmad->npartha_nodes_.load(std::memory_order_relaxed);

			if (npar == 0) {
				if (nodefields) {
					return CB_OK;
				}
			}
			else if ((GY_READ_ONCE(pmad->last_reg_tusec_) < minchgusec) && (GY_READ_ONCE(pmad->last_par_assign_tusec_) < minchgusec)) {
				return CB_OK;
			}	

			if (qryopt.has_filter()) {
				auto 			cret = madhavalist_filter_match(qryopt.get_filter_criteria(), pmad, true /* ignore_other_subsys */);

				if (cret == CRIT_FAIL) {
					return CB_OK;
				}
			}	

			writer.StartObject();

			writer.KeyConst("madid");
			writer.String(number_to_string(pmad->madhava_id_, "%016lx").get());
			
			writer.KeyConst("host");
			writer.String(pmad->listener_port_.get_domain());

			writer.KeyConst("port");
			writer.Int(pmad->listener_port_.get_port());

			writer.KeyConst("commver");
			writer.Int(pmad->comm_version_);

			writer.KeyConst("npartha");
			writer.Int(npar);
			
			if (!nodefields) {
				char			verbuf[32];

				writer.KeyConst("maxpartha");
				writer.Int(pmad->max_partha_nodes_);

				writer.KeyConst("region");
				writer.String(pmad->region_name_);

				writer.KeyConst("zone");
				writer.String(pmad->zone_name_);
				
				writer.KeyConst("madhavaname");
				writer.String(pmad->madhava_name_);
				
				writer.KeyConst("version");
				writer.String(get_string_from_version_num(pmad->madhava_version_, verbuf, 3));

				writer.KeyConst("isconn");
				writer.Bool(!!pmad->get_num_conns());

				writer.KeyConst("lastseen");
				writer.String(gy_localtime_iso8601_sec(pmad->last_status_tsec_).get());

			}

			writer.EndObject();

			nmad++;

			if ((uint32_t)nmad >= maxrecs) {
				return CB_BREAK_LOOP;
			}	

			return CB_OK;
		};

		madhava_tbl_.walk_hash_table_const(lammad);

		writer.EndArray();

		writer.KeyConst("nmad");
		writer.Int(nmad);

		writer.KeyConst("lastchgmsec");	
		writer.Uint64(last_madhava_chg_tusec_.load(std::memory_order_acquire)/1000);

		writer.EndObject();

		return true;
	}
	catch(...) {
		writer.get_stream()->reset_if_not_sent(ERR_SERV_ERROR);
		throw;
	}	
}	

bool SHCONN_HANDLER::web_curr_clusterstate(SOCK_JSON_WRITER<SHCONN_HANDLER::SHSTREAM_JSON_EPOLL> & writer, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool) const
{
	using STATE_ONE			= comm::MS_CLUSTER_STATE::STATE_ONE;

	AggrClusterStateMap		clustermap;
	time_t				tcurr = time(nullptr);

	qryopt.comp_criteria_init();

	SCOPE_GY_MUTEX			scopelock(&cluststate_mutex_);

	if (tclustersec_ < tcurr - 10) {
		scopelock.unlock();

		GY_THROW_EXPR_CODE(ERR_DATA_NOT_FOUND, "Cluster State has not been updated recently. Please try later...");
	}	

	time_t				tcluster = tclustersec_;

	clustermap = clusterstatemap_;

	scopelock.unlock();

	uint64_t			maxrecs = qryopt.get_max_records(), nrecs = 0;
	auto				timebuf = gy_localtime_iso8601_sec(tcluster);
	const size_t			sztime = strlen(timebuf.get());

	const JSON_DB_MAPPING		*colarr[MAX_MULTI_HOST_COLUMN_LIST];
	
	auto [ncol, colspec] 		= qryopt.get_column_list(colarr, GY_ARRAY_SIZE(colarr), SUBSYS_CLUSTERSTATE);

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("shyamaid");
	writer.String(gshyama_id_str_, 16);

	writer.KeyConst("clusterstate");
	writer.StartArray();
		
	const auto sendone = [&, tcurr](const char *pcluster, const STATE_ONE & cstate) -> bool
	{
		size_t			szcluster = strlen(pcluster);
		ClusterStateFields	clusterstatefields(cstate, pcluster, szcluster, tcurr);

		if (qryopt.has_filter()) {
			auto 			cret = clusterstatefields.filter_match(qryopt.get_filter_criteria());

			if (cret == CRIT_FAIL) {
				return false;
			}
		}	
		
		clusterstatefields.print_json(colarr, ncol, writer, timebuf.get());
		
		return true;
	};
		
	for (const auto & [name, state] : clustermap) {
		nrecs += sendone(name.get(), state);	
		
		if (nrecs >= maxrecs) {
			break;
		}	
	}	

	writer.EndArray();
	writer.EndObject();

	return true;
}

bool SHCONN_HANDLER::web_db_detail_clusterstate(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Clusterstate info\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Cluster State Query : Database Querying Error : Failed to get an idle connection. Please try later...";
		
		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	int				ret;
	bool				bret;
	time_t				tcurr = time(nullptr);
	struct timeval			tvstart = qryopt.get_start_timeval(), tvend = qryopt.get_end_timeval();
	auto 				datetbl = get_db_day_partition(tvstart.tv_sec, tvend.tv_sec, 0);

	const JSON_DB_MAPPING		*colarr[MAX_MULTI_HOST_COLUMN_LIST];
	
	auto [ncol, colspec] 		= qryopt.get_column_list(colarr, GY_ARRAY_SIZE(colarr), SUBSYS_CLUSTERSTATE);

	if (tcurr - db_storage_days_ * GY_SEC_PER_DAY > (uint64_t)tvend.tv_sec) {
		char			ebuf[256];
		size_t			esz;
		
		esz = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Cluster State Query : Time Requested not present in DB : Max Days of DB storage = %u", db_storage_days_);

		if (writer.get_stream()->reset_if_not_sent(ERR_DATA_NOT_FOUND)) {
			send_json_error_resp(connshr, ERR_DATA_NOT_FOUND, pquery->get_seqid(), ebuf, esz, pthrpoolarr);
		}

		return false;
	}	
	
	if (true) {	
		STRING_BUFFER<48 * 1024>	strbuf;
		char				tablename[128];

		snprintf(tablename, sizeof(tablename), "public.clusterstatetbl%s",  datetbl.get());

		qryopt.get_db_select_query(strbuf, SUBSYS_CLUSTERSTATE, tablename);

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}

	if (bret == false) {
		constexpr const char errbuf[] = "Cluster State Query : Failed to schedule query to Database. Please retry later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();

	writer.KeyConst("shyamaid");
	writer.String(gshyama_id_str_, 16);

	writer.KeyConst("clusterstate");
	writer.StartArray();

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_json_cb(conn, std::move(gyres), is_completed, "Cluster State", colarr, ncol, writer, total_rows, noextracolcb);
		}
	);
	
	auto		expirysec = std::max<int64_t>(10, pquery->get_time_to_expiry(tcurr));

	ret = dbpool.wait_one_response(expirysec * 1000, pconn.getintconn());

	if (ret != 0) {
		if (ret == 2) {
			db_stats_.ndbquery_timeout_.fetch_add_relaxed(1);
		}

		if (writer.get_stream()->reset_if_not_sent(ret == 2 ? ERR_TIMED_OUT : ERR_SYSERROR)) {
			if (ret == 2) {
				constexpr const char errbuf[] = "Clusterstate Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Clusterstate Query : Database Connection Error. Please try later...";

				send_json_error_resp(connshr, ERR_SYSERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}	

			return false;
		}	

		writer.EndArray();
		writer.EndObject();
		
		return false;
	}	

	writer.EndArray();
	writer.EndObject();

	return true;
}

bool SHCONN_HANDLER::web_db_aggr_clusterstate(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Aggregated Clusterstate info\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Aggregated Cluster State Query : Database Querying Error : Failed to get an idle connection. Please try later...";
		
		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	int				ret;
	bool				bret;
	time_t				tcurr = time(nullptr);
	struct timeval			tvstart = qryopt.get_start_timeval(), tvend = qryopt.get_end_timeval();
	auto 				datetbl = get_db_day_partition(tvstart.tv_sec, tvend.tv_sec, 0);

	if (tcurr - db_storage_days_ * GY_SEC_PER_DAY > (uint64_t)tvend.tv_sec) {
		char			ebuf[256];
		size_t			esz;
		
		esz = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Aggregated Cluster State Query : Time Requested not present in DB : Max Days of DB storage = %u", db_storage_days_);

		if (writer.get_stream()->reset_if_not_sent(ERR_DATA_NOT_FOUND)) {
			send_json_error_resp(connshr, ERR_DATA_NOT_FOUND, pquery->get_seqid(), ebuf, esz, pthrpoolarr);
		}

		return false;
	}	

	const JSON_DB_MAPPING		*colarr[QUERY_OPTIONS::MAX_AGGR_COLUMNS];
	JSON_DB_MAPPING			acolarr[QUERY_OPTIONS::MAX_AGGR_COLUMNS];
	uint32_t			ncol;

	if (true) {
		STRING_BUFFER<48 * 1024>	strbuf;

		ncol = get_clusterstate_aggr_query(strbuf, qryopt, datetbl.get(), acolarr);

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());

		if (bret == false) {
			constexpr const char errbuf[] = "Aggregated Clusterstate Query : Failed to schedule query to Database. Please retry later...";

			if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
				send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}

			return false;
		}	

		for (uint32_t i = 0; i < ncol; ++i) {
			colarr[i] = acolarr + i;
		}	
	}	

	writer.StartObject();

	writer.KeyConst("shyamaid");
	writer.String(gshyama_id_str_, 16);

	writer.KeyConst("clusterstate");
	writer.StartArray();

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_json_cb(conn, std::move(gyres), is_completed, "Aggregated Cluster State", colarr, ncol, writer, total_rows, noextracolcb);
		}
	);
	
	auto		expirysec = std::max<int64_t>(10, pquery->get_time_to_expiry(tcurr));

	ret = dbpool.wait_one_response(expirysec * 1000, pconn.getintconn());

	if (ret != 0) {
		if (ret == 2) {
			db_stats_.ndbquery_timeout_.fetch_add_relaxed(1);
		}

		if (writer.get_stream()->reset_if_not_sent(ret == 2 ? ERR_TIMED_OUT : ERR_SYSERROR)) {
			if (ret == 2) {
				constexpr const char errbuf[] = "Aggregated Cluster State Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Aggregated Cluster State Query : Database Connection Error. Please try later...";

				send_json_error_resp(connshr, ERR_SYSERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}	

			return false;
		}	

		writer.EndArray();
		writer.EndObject();
		
		return false;
	}	

	writer.EndArray();

	set_json_column_list(writer, colarr, ncol);

	writer.EndObject();

	return true;
}

bool SHCONN_HANDLER::web_query_clusterstate(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	bool				bret, is_aggregated = qryopt.is_aggregated();

	if (false == qryopt.is_multi_host()) {
		writer.get_stream()->reset_if_not_sent(ERR_INVALID_REQUEST);
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Cluster State Query : Partha ID Specified : Cluster Lookup from Partha ID not supported");
	}	

	try {
		if (!qryopt.is_historical()) {
			bret = web_curr_clusterstate(writer, qryopt, extpool);
		}
		else {
			if (false == is_aggregated) {
				bret = web_db_detail_clusterstate(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);
			}
			else {
				bret = web_db_aggr_clusterstate(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);
			}	
		}	

		if (bret == true) {
			return true;
		}	

		writer.get_stream()->reset_if_not_sent();
		return false;
	}
	catch(...) {
		writer.get_stream()->reset_if_not_sent();
		throw;
	}	
}


bool SHCONN_HANDLER::web_db_detail_svcmeshcluster(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Svc Mesh Cluster info\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Svc Mesh Cluster Query : Database Querying Error : Failed to get an idle connection. Please try later...";
		
		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	int				ret;
	bool				bret, origpointintime = qryopt.is_pointintime(), pointintime = origpointintime, updqryopt = false;
	time_t				tcurr = time(nullptr);
	struct timeval			tvstart, tvend, origtvstart, origtvend;
	char				origstarttime[48], origendtime[48];
	
	GY_SCOPE_EXIT {
		if (updqryopt == true) {
			qryopt.set_timestamps(origstarttime, origendtime, origtvstart, origtvend, origpointintime);
		}
	};	

	if (!qryopt.is_historical()) {
		origtvstart 	= {};
		origtvend 	= {};
		*origstarttime 	= 0;
		*origendtime	= 0;
		updqryopt 	= true;

		tvstart.tv_sec 	= tcurr - 350;
		tvstart.tv_usec = 0;

		tvend.tv_sec	= tcurr + 1;
		tvend.tv_usec	= 0;
		
		pointintime 	= true;

		qryopt.set_timestamps(gy_localtime_iso8601_sec(tvstart.tv_sec).get(), gy_localtime_iso8601_sec(tvend.tv_sec).get(), tvstart, tvend, true /* pointintime */);
	}	
	else {
		tvstart = qryopt.get_start_timeval(); 
		tvend 	= qryopt.get_end_timeval();

		if (tvend.tv_sec - tvstart.tv_sec < 350) {
			origtvstart	= tvstart;
			origtvend	= tvend;
			GY_STRNCPY(origstarttime, qryopt.get_starttime(), sizeof(origstarttime));
			GY_STRNCPY(origendtime, qryopt.get_endtime(), sizeof(origendtime));
			updqryopt	= true;
			
			tvstart.tv_sec = tvend.tv_sec - 350;
			qryopt.set_timestamps(gy_localtime_iso8601_sec(tvstart.tv_sec).get(), gy_localtime_iso8601_sec(tvend.tv_sec).get(), tvstart, tvend, true /* pointintime */);
		
			pointintime 	= true;
		}	
	}

	auto 				datetbl = get_db_day_partition(tvstart.tv_sec, tvend.tv_sec, 0);

	const JSON_DB_MAPPING		*colarr[MAX_MULTI_HOST_COLUMN_LIST];
	
	auto [ncol, colspec] 		= qryopt.get_column_list(colarr, GY_ARRAY_SIZE(colarr), SUBSYS_SVCMESHCLUST);

	if (tcurr - db_storage_days_ * GY_SEC_PER_DAY > (uint64_t)tvend.tv_sec) {
		char			ebuf[256];
		size_t			esz;
		
		esz = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Svc Mesh Cluster Query : Time Requested not present in DB : Max Days of DB storage = %u", db_storage_days_);

		if (writer.get_stream()->reset_if_not_sent(ERR_DATA_NOT_FOUND)) {
			send_json_error_resp(connshr, ERR_DATA_NOT_FOUND, pquery->get_seqid(), ebuf, esz, pthrpoolarr);
		}

		return false;
	}	
	
	if (true) {
		STRING_BUFFER<48 * 1024>	strbuf;
		char				tablename[128];

		snprintf(tablename, sizeof(tablename), "public.svcmeshtbl%s", datetbl.get());

		qryopt.get_db_select_query(strbuf, SUBSYS_SVCMESHCLUST, tablename);

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}	

	if (bret == false) {
		constexpr const char errbuf[] = "Svc Mesh Cluster Query : Failed to schedule query to Database. Please retry later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("shyamaid");
	writer.String(gshyama_id_str_, 16);

	writer.KeyConst("svcmeshclust");
	writer.StartArray();

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_json_cb(conn, std::move(gyres), is_completed, "Svc Mesh Cluster", colarr, ncol, writer, total_rows, noextracolcb);
		}
	);
	
	auto		expirysec = std::max<int64_t>(10, pquery->get_time_to_expiry(tcurr));

	ret = dbpool.wait_one_response(expirysec * 1000, pconn.getintconn());

	if (ret != 0) {
		if (ret == 2) {
			db_stats_.ndbquery_timeout_.fetch_add_relaxed(1);
		}

		if (writer.get_stream()->reset_if_not_sent(ret == 2 ? ERR_TIMED_OUT : ERR_SYSERROR)) {
			if (ret == 2) {
				constexpr const char errbuf[] = "Svc Mesh Cluster Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Svc Mesh Cluster Query : Database Connection Error. Please try later...";

				send_json_error_resp(connshr, ERR_SYSERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}	

			return false;
		}	

		writer.EndArray();
		writer.EndObject();
		
		return false;
	}	

	writer.EndArray();

	writer.EndObject();

	return true;
}

bool SHCONN_HANDLER::web_query_svcmeshcluster(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	bool				bret;

	try {
		bret = web_db_detail_svcmeshcluster(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);

		if (bret == true) {
			return true;
		}	

		writer.get_stream()->reset_if_not_sent();
		return false;
	}
	catch(...) {
		writer.get_stream()->reset_if_not_sent();
		throw;
	}	
}

bool SHCONN_HANDLER::web_db_detail_svcipcluster(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Svc IP Cluster info\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Svc IP Cluster Query : Database Querying Error : Failed to get an idle connection. Please try later...";
		
		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	int				ret;
	bool				bret, origpointintime = qryopt.is_pointintime(), pointintime = origpointintime, updqryopt = false;
	time_t				tcurr = time(nullptr);
	struct timeval			tvstart, tvend, origtvstart, origtvend;
	char				origstarttime[48], origendtime[48];
	
	GY_SCOPE_EXIT {
		if (updqryopt == true) {
			qryopt.set_timestamps(origstarttime, origendtime, origtvstart, origtvend, origpointintime);
		}
	};	

	if (!qryopt.is_historical()) {
		origtvstart 	= {};
		origtvend 	= {};
		*origstarttime 	= 0;
		*origendtime	= 0;
		updqryopt 	= true;

		tvstart.tv_sec 	= tcurr - 400;
		tvstart.tv_usec = 0;

		tvend.tv_sec	= tcurr + 1;
		tvend.tv_usec	= 0;
		
		pointintime 	= true;

		qryopt.set_timestamps(gy_localtime_iso8601_sec(tvstart.tv_sec).get(), gy_localtime_iso8601_sec(tvend.tv_sec).get(), tvstart, tvend, true /* pointintime */);
	}	
	else {
		tvstart = qryopt.get_start_timeval(); 
		tvend 	= qryopt.get_end_timeval();

		if (tvend.tv_sec - tvstart.tv_sec < 400) {
			origtvstart	= tvstart;
			origtvend	= tvend;
			GY_STRNCPY(origstarttime, qryopt.get_starttime(), sizeof(origstarttime));
			GY_STRNCPY(origendtime, qryopt.get_endtime(), sizeof(origendtime));
			updqryopt	= true;
			
			tvstart.tv_sec = tvend.tv_sec - 400;
			qryopt.set_timestamps(gy_localtime_iso8601_sec(tvstart.tv_sec).get(), gy_localtime_iso8601_sec(tvend.tv_sec).get(), tvstart, tvend, true /* pointintime */);
		
			pointintime 	= true;
		}	
	}

	auto 				datetbl = get_db_day_partition(tvstart.tv_sec, tvend.tv_sec, 0);

	const JSON_DB_MAPPING		*colarr[MAX_MULTI_HOST_COLUMN_LIST];
	
	auto [ncol, colspec] 		= qryopt.get_column_list(colarr, GY_ARRAY_SIZE(colarr), SUBSYS_SVCIPCLUST);

	if (tcurr - db_storage_days_ * GY_SEC_PER_DAY > (uint64_t)tvend.tv_sec) {
		char			ebuf[256];
		size_t			esz;
		
		esz = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Svc IP Cluster Query : Time Requested not present in DB : Max Days of DB storage = %u", db_storage_days_);

		if (writer.get_stream()->reset_if_not_sent(ERR_DATA_NOT_FOUND)) {
			send_json_error_resp(connshr, ERR_DATA_NOT_FOUND, pquery->get_seqid(), ebuf, esz, pthrpoolarr);
		}

		return false;
	}	
	
	if (true) {
		STRING_BUFFER<48 * 1024>	strbuf;
		char				tablename[128];

		snprintf(tablename, sizeof(tablename), "public.svcnatiptbl%s", datetbl.get());

		qryopt.get_db_select_query(strbuf, SUBSYS_SVCIPCLUST, tablename);

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}	

	if (bret == false) {
		constexpr const char errbuf[] = "Svc IP Cluster Query : Failed to schedule query to Database. Please retry later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("shyamaid");
	writer.String(gshyama_id_str_, 16);

	writer.KeyConst("svcipclust");
	writer.StartArray();

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_json_cb(conn, std::move(gyres), is_completed, "Svc IP Cluster", colarr, ncol, writer, total_rows, noextracolcb);
		}
	);
	
	auto		expirysec = std::max<int64_t>(10, pquery->get_time_to_expiry(tcurr));

	ret = dbpool.wait_one_response(expirysec * 1000, pconn.getintconn());

	if (ret != 0) {
		if (ret == 2) {
			db_stats_.ndbquery_timeout_.fetch_add_relaxed(1);
		}

		if (writer.get_stream()->reset_if_not_sent(ret == 2 ? ERR_TIMED_OUT : ERR_SYSERROR)) {
			if (ret == 2) {
				constexpr const char errbuf[] = "Svc IP Cluster Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Svc IP Cluster Query : Database Connection Error. Please try later...";

				send_json_error_resp(connshr, ERR_SYSERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}	

			return false;
		}	

		writer.EndArray();
		writer.EndObject();
		
		return false;
	}	

	writer.EndArray();

	writer.EndObject();

	return true;
}

bool SHCONN_HANDLER::web_query_svcipcluster(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	bool				bret;

	try {
		bret = web_db_detail_svcipcluster(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);

		if (bret == true) {
			return true;
		}	

		writer.get_stream()->reset_if_not_sent();
		return false;
	}
	catch(...) {
		writer.get_stream()->reset_if_not_sent();
		throw;
	}	
}


bool SHCONN_HANDLER::web_db_detail_alerts(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Alerts info\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Alerts Query : Database Querying Error : Failed to get an idle connection. Please try later...";
		
		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	int				ret;
	bool				bret, origpointintime = qryopt.is_pointintime(), pointintime = origpointintime, updqryopt = false;
	time_t				tcurr = time(nullptr);
	struct timeval			tvstart, tvend, origtvstart, origtvend;
	char				origstarttime[48], origendtime[48];
	
	GY_SCOPE_EXIT {
		if (updqryopt == true) {
			qryopt.set_timestamps(origstarttime, origendtime, origtvstart, origtvend, origpointintime);
		}
	};	

	if (!qryopt.is_historical()) {
		origtvstart 	= {};
		origtvend 	= {};
		*origstarttime 	= 0;
		*origendtime	= 0;
		updqryopt 	= true;

		/*
		 * We need to set the start time to the min time of all open alerts
		 */
		time_t			tmin = palertmgr_->min_active_alert_time();
		
		if (tmin == 0) {
			tmin = tcurr - 3600;
		}	
		else if (tmin < tcurr - 24 * 3600 - 300) {
			tmin = tcurr - 24 * 3600 - 300;
		}	
		else if (tmin > tcurr - 3600) {
			tmin = tcurr - 3600;
		}	

		tvstart.tv_sec 	= tmin;
		tvstart.tv_usec = 0;

		tvend.tv_sec	= tcurr + 1;
		tvend.tv_usec	= 0;
		
		pointintime 	= false;

		qryopt.set_timestamps(gy_localtime_iso8601_sec(tvstart.tv_sec).get(), gy_localtime_iso8601_sec(tvend.tv_sec).get(), tvstart, tvend, false /* pointintime */);
	}	
	else {
		tvstart = qryopt.get_start_timeval(); 
		tvend 	= qryopt.get_end_timeval();
	}

	auto 				datetbl = get_db_day_partition(tvstart.tv_sec, tvend.tv_sec, 0);

	const JSON_DB_MAPPING		*colarr[MAX_MULTI_HOST_COLUMN_LIST];
	
	auto [ncol, colspec] 		= qryopt.get_column_list(colarr, GY_ARRAY_SIZE(colarr), SUBSYS_ALERTS);

	if (tcurr - db_storage_days_ * GY_SEC_PER_DAY > (uint64_t)tvend.tv_sec) {
		char			ebuf[256];
		size_t			esz;
		
		esz = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Alerts Query : Time Requested not present in DB : Max Days of DB storage = %u", db_storage_days_);

		if (writer.get_stream()->reset_if_not_sent(ERR_DATA_NOT_FOUND)) {
			send_json_error_resp(connshr, ERR_DATA_NOT_FOUND, pquery->get_seqid(), ebuf, esz, pthrpoolarr);
		}

		return false;
	}	
	
	if (true) {
		STRING_BUFFER<48 * 1024>	strbuf;
		char				tablename[128];

		snprintf(tablename, sizeof(tablename), "public.alertstbl%s", datetbl.get());

		qryopt.get_db_select_query(strbuf, SUBSYS_ALERTS, tablename);

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}	

	if (bret == false) {
		constexpr const char errbuf[] = "Alerts Query : Failed to schedule query to Database. Please retry later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("shyamaid");
	writer.String(gshyama_id_str_, 16);
	
	writer.KeyConst("starttime");
	writer.String(gy_localtime_iso8601_sec(tvstart.tv_sec).get());

	if (!qryopt.is_historical() || tvend.tv_sec + 60 > tcurr) {
		auto			[dayalerts, daysilence, dayinhibit] = palertmgr_->get_alert_day_stats();
		
		writer.KeyConst("daystats");
		writer.StartObject();

		writer.KeyConst("dayalerts");
		writer.Int(dayalerts);

		writer.KeyConst("daysilence");
		writer.Int(daysilence);

		writer.KeyConst("dayinhibit");
		writer.Int(dayinhibit);

		writer.EndObject();
	}

	writer.KeyConst("alerts");
	writer.StartArray();

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_json_cb(conn, std::move(gyres), is_completed, "Alerts", colarr, ncol, writer, total_rows, noextracolcb);
		}
	);
	
	auto		expirysec = std::max<int64_t>(10, pquery->get_time_to_expiry(tcurr));

	ret = dbpool.wait_one_response(expirysec * 1000, pconn.getintconn());

	if (ret != 0) {
		if (ret == 2) {
			db_stats_.ndbquery_timeout_.fetch_add_relaxed(1);
		}

		if (writer.get_stream()->reset_if_not_sent(ret == 2 ? ERR_TIMED_OUT : ERR_SYSERROR)) {
			if (ret == 2) {
				constexpr const char errbuf[] = "Alerts Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Alerts Query : Database Connection Error. Please try later...";

				send_json_error_resp(connshr, ERR_SYSERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}	

			return false;
		}	

		writer.EndArray();
		writer.EndObject();
		
		return false;
	}	

	writer.EndArray();

	writer.EndObject();

	return true;
}

bool SHCONN_HANDLER::web_db_aggr_alerts(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Aggregated Alerts info\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Aggregated Alerts Query : Database Querying Error : Failed to get an idle connection. Please try later...";
		
		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	int				ret;
	bool				bret;
	time_t				tcurr = time(nullptr);
	struct timeval			tvstart = qryopt.get_start_timeval(), tvend = qryopt.get_end_timeval();
	auto 				datetbl = get_db_day_partition(tvstart.tv_sec, tvend.tv_sec, 0);

	if (tcurr - db_storage_days_ * GY_SEC_PER_DAY > (uint64_t)tvend.tv_sec) {
		char			ebuf[256];
		size_t			esz;
		
		esz = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Aggregated Alerts Query : Time Requested not present in DB : Max Days of DB storage = %u", db_storage_days_);

		if (writer.get_stream()->reset_if_not_sent(ERR_DATA_NOT_FOUND)) {
			send_json_error_resp(connshr, ERR_DATA_NOT_FOUND, pquery->get_seqid(), ebuf, esz, pthrpoolarr);
		}

		return false;
	}	

	const JSON_DB_MAPPING		*colarr[QUERY_OPTIONS::MAX_AGGR_COLUMNS];
	JSON_DB_MAPPING			acolarr[QUERY_OPTIONS::MAX_AGGR_COLUMNS];
	uint32_t			ncol;

	if (true) {
		STRING_BUFFER<48 * 1024>	strbuf;

		ncol = get_alerts_aggr_query(strbuf, qryopt, datetbl.get(), acolarr);

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());

		if (bret == false) {
			constexpr const char errbuf[] = "Aggregated Alerts Query : Failed to schedule query to Database. Please retry later...";

			if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
				send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}

			return false;
		}	

		for (uint32_t i = 0; i < ncol; ++i) {
			colarr[i] = acolarr + i;
		}	
	}	

	writer.StartObject();

	writer.KeyConst("shyamaid");
	writer.String(gshyama_id_str_, 16);

	writer.KeyConst("alerts");
	writer.StartArray();

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_json_cb(conn, std::move(gyres), is_completed, "Aggregated Alerts", colarr, ncol, writer, total_rows, noextracolcb);
		}
	);
	
	auto		expirysec = std::max<int64_t>(10, pquery->get_time_to_expiry(tcurr));

	ret = dbpool.wait_one_response(expirysec * 1000, pconn.getintconn());

	if (ret != 0) {
		if (ret == 2) {
			db_stats_.ndbquery_timeout_.fetch_add_relaxed(1);
		}

		if (writer.get_stream()->reset_if_not_sent(ret == 2 ? ERR_TIMED_OUT : ERR_SYSERROR)) {
			if (ret == 2) {
				constexpr const char errbuf[] = "Aggregated Alerts Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Aggregated Alerts Query : Database Connection Error. Please try later...";

				send_json_error_resp(connshr, ERR_SYSERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}	

			return false;
		}	

		writer.EndArray();
		writer.EndObject();
		
		return false;
	}	

	writer.EndArray();

	set_json_column_list(writer, colarr, ncol);

	writer.EndObject();

	return true;
}

bool SHCONN_HANDLER::web_query_alerts(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	bool				bret, is_aggregated = qryopt.is_aggregated();

	try {
		if (false == is_aggregated) {
			bret = web_db_detail_alerts(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);
		}
		else {
			bret = web_db_aggr_alerts(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);
		}	

		if (bret == true) {
			return true;
		}	

		writer.get_stream()->reset_if_not_sent();
		return false;
	}
	catch(...) {
		writer.get_stream()->reset_if_not_sent();
		throw;
	}	
}


bool SHCONN_HANDLER::web_db_detail_alertdef(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Alert Definition info\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Alert Definition Query : Database Querying Error : Failed to get an idle connection. Please try later...";
		
		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	time_t				tcurr = time(nullptr);
	int				ret;
	bool				bret;

	const JSON_DB_MAPPING		*colarr[MAX_MULTI_HOST_COLUMN_LIST];
	
	auto [ncol, colspec] 		= qryopt.get_column_list(colarr, GY_ARRAY_SIZE(colarr), SUBSYS_ALERTDEF);

	if (true) {
		STRING_BUFFER<48 * 1024>	strbuf;

		qryopt.get_db_select_query(strbuf, SUBSYS_ALERTDEF, "public.alertdeftbl");

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}	

	if (bret == false) {
		constexpr const char errbuf[] = "Alert Definition Query : Failed to schedule query to Database. Please retry later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("shyamaid");
	writer.String(gshyama_id_str_, 16);

	writer.KeyConst("alertdef");
	writer.StartArray();

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_json_cb(conn, std::move(gyres), is_completed, "Alert Definition", colarr, ncol, writer, total_rows, noextracolcb);
		}
	);
	
	auto		expirysec = std::max<int64_t>(10, pquery->get_time_to_expiry(tcurr));

	ret = dbpool.wait_one_response(expirysec * 1000, pconn.getintconn());

	if (ret != 0) {
		if (ret == 2) {
			db_stats_.ndbquery_timeout_.fetch_add_relaxed(1);
		}

		if (writer.get_stream()->reset_if_not_sent(ret == 2 ? ERR_TIMED_OUT : ERR_SYSERROR)) {
			if (ret == 2) {
				constexpr const char errbuf[] = "Alert Definition Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Alert Definition Query : Database Connection Error. Please try later...";

				send_json_error_resp(connshr, ERR_SYSERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}	

			return false;
		}	

		writer.EndArray();
		writer.EndObject();
		
		return false;
	}	

	writer.EndArray();

	writer.EndObject();

	return true;
}

bool SHCONN_HANDLER::web_query_alertdef(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	bool				bret;

	try {
		bret = web_db_detail_alertdef(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);

		if (bret == true) {
			return true;
		}	

		writer.get_stream()->reset_if_not_sent();
		return false;
	}
	catch(...) {
		writer.get_stream()->reset_if_not_sent();
		throw;
	}	
}

bool SHCONN_HANDLER::web_db_detail_inhibits(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Alert Inhibits info\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Alert Inhibits Query : Database Querying Error : Failed to get an idle connection. Please try later...";
		
		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	time_t				tcurr = time(nullptr);
	int				ret;
	bool				bret;

	const JSON_DB_MAPPING		*colarr[MAX_MULTI_HOST_COLUMN_LIST];
	
	auto [ncol, colspec] 		= qryopt.get_column_list(colarr, GY_ARRAY_SIZE(colarr), SUBSYS_INHIBITS);

	if (true) {
		STRING_BUFFER<48 * 1024>	strbuf;

		qryopt.get_db_select_query(strbuf, SUBSYS_INHIBITS, "public.inhibitstbl");

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}	

	if (bret == false) {
		constexpr const char errbuf[] = "Alert Inhibits Query : Failed to schedule query to Database. Please retry later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("shyamaid");
	writer.String(gshyama_id_str_, 16);

	writer.KeyConst("inhibits");
	writer.StartArray();

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_json_cb(conn, std::move(gyres), is_completed, "Alert Inhibits", colarr, ncol, writer, total_rows, noextracolcb);
		}
	);
	
	auto		expirysec = std::max<int64_t>(10, pquery->get_time_to_expiry(tcurr));

	ret = dbpool.wait_one_response(expirysec * 1000, pconn.getintconn());

	if (ret != 0) {
		if (ret == 2) {
			db_stats_.ndbquery_timeout_.fetch_add_relaxed(1);
		}

		if (writer.get_stream()->reset_if_not_sent(ret == 2 ? ERR_TIMED_OUT : ERR_SYSERROR)) {
			if (ret == 2) {
				constexpr const char errbuf[] = "Alert Inhibits Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Alert Inhibits Query : Database Connection Error. Please try later...";

				send_json_error_resp(connshr, ERR_SYSERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}	

			return false;
		}	

		writer.EndArray();
		writer.EndObject();
		
		return false;
	}	

	writer.EndArray();

	writer.EndObject();

	return true;
}

bool SHCONN_HANDLER::web_query_inhibits(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	bool				bret;

	try {
		bret = web_db_detail_inhibits(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);

		if (bret == true) {
			return true;
		}	

		writer.get_stream()->reset_if_not_sent();
		return false;
	}
	catch(...) {
		writer.get_stream()->reset_if_not_sent();
		throw;
	}	
}


bool SHCONN_HANDLER::web_db_detail_silences(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Alert Silences info\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Alert Silences Query : Database Querying Error : Failed to get an idle connection. Please try later...";
		
		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	time_t				tcurr = time(nullptr);
	int				ret;
	bool				bret;

	const JSON_DB_MAPPING		*colarr[MAX_MULTI_HOST_COLUMN_LIST];
	
	auto [ncol, colspec] 		= qryopt.get_column_list(colarr, GY_ARRAY_SIZE(colarr), SUBSYS_SILENCES);

	if (true) {
		STRING_BUFFER<48 * 1024>	strbuf;

		qryopt.get_db_select_query(strbuf, SUBSYS_SILENCES, "public.silencestbl");

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}	

	if (bret == false) {
		constexpr const char errbuf[] = "Alert Silences Query : Failed to schedule query to Database. Please retry later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("shyamaid");
	writer.String(gshyama_id_str_, 16);

	writer.KeyConst("silences");
	writer.StartArray();

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_json_cb(conn, std::move(gyres), is_completed, "Alert Silences", colarr, ncol, writer, total_rows, noextracolcb);
		}
	);
	
	auto		expirysec = std::max<int64_t>(10, pquery->get_time_to_expiry(tcurr));

	ret = dbpool.wait_one_response(expirysec * 1000, pconn.getintconn());

	if (ret != 0) {
		if (ret == 2) {
			db_stats_.ndbquery_timeout_.fetch_add_relaxed(1);
		}

		if (writer.get_stream()->reset_if_not_sent(ret == 2 ? ERR_TIMED_OUT : ERR_SYSERROR)) {
			if (ret == 2) {
				constexpr const char errbuf[] = "Alert Silences Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Alert Silences Query : Database Connection Error. Please try later...";

				send_json_error_resp(connshr, ERR_SYSERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}	

			return false;
		}	

		writer.EndArray();
		writer.EndObject();
		
		return false;
	}	

	writer.EndArray();

	writer.EndObject();

	return true;
}

bool SHCONN_HANDLER::web_query_silences(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	bool				bret;

	try {
		bret = web_db_detail_silences(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);

		if (bret == true) {
			return true;
		}	

		writer.get_stream()->reset_if_not_sent();
		return false;
	}
	catch(...) {
		writer.get_stream()->reset_if_not_sent();
		throw;
	}	
}

bool SHCONN_HANDLER::web_db_detail_actions(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Alert Actions info\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Alert Actions Query : Database Querying Error : Failed to get an idle connection. Please try later...";
		
		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	time_t				tcurr = time(nullptr);
	int				ret;
	bool				bret;

	const JSON_DB_MAPPING		*colarr[MAX_MULTI_HOST_COLUMN_LIST];
	
	auto [ncol, colspec] 		= qryopt.get_column_list(colarr, GY_ARRAY_SIZE(colarr), SUBSYS_ACTIONS);

	if (true) {
		STRING_BUFFER<48 * 1024>	strbuf;

		qryopt.get_db_select_query(strbuf, SUBSYS_ACTIONS, "public.actionstbl");

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}	

	if (bret == false) {
		constexpr const char errbuf[] = "Alert Silences Query : Failed to schedule query to Database. Please retry later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("shyamaid");
	writer.String(gshyama_id_str_, 16);

	writer.KeyConst("actions");
	writer.StartArray();

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_json_cb(conn, std::move(gyres), is_completed, "Alert Actions", colarr, ncol, writer, total_rows, noextracolcb);
		}
	);
	
	auto		expirysec = std::max<int64_t>(10, pquery->get_time_to_expiry(tcurr));

	ret = dbpool.wait_one_response(expirysec * 1000, pconn.getintconn());

	if (ret != 0) {
		if (ret == 2) {
			db_stats_.ndbquery_timeout_.fetch_add_relaxed(1);
		}

		if (writer.get_stream()->reset_if_not_sent(ret == 2 ? ERR_TIMED_OUT : ERR_SYSERROR)) {
			if (ret == 2) {
				constexpr const char errbuf[] = "Alert Actions Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Alert Actions Query : Database Connection Error. Please try later...";

				send_json_error_resp(connshr, ERR_SYSERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}	

			return false;
		}	

		writer.EndArray();
		writer.EndObject();
		
		return false;
	}	

	writer.EndArray();

	writer.EndObject();

	return true;
}

bool SHCONN_HANDLER::web_query_actions(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	bool				bret;

	try {
		bret = web_db_detail_actions(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);

		if (bret == true) {
			return true;
		}	

		writer.get_stream()->reset_if_not_sent();
		return false;
	}
	catch(...) {
		writer.get_stream()->reset_if_not_sent();
		throw;
	}	
}

bool SHCONN_HANDLER::web_query_shyamastatus(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	try {
		const auto			*psettings = get_settings();
		char				verbuf[32];

		// qryopt.comp_criteria_init();		// As no filtering to be done...

		writer.StartObject();

		writer.KeyConst("shyamaid");
		writer.String(gshyama_id_str_, 16);

		writer.KeyConst("shyamaname");
		writer.String(shyama_name_);

		writer.KeyConst("nmadhava");
		writer.Int(madhava_tbl_.approx_count_fast());

		writer.KeyConst("nmadactive");
		writer.Int(last_madhava_cnt_);

		writer.KeyConst("minmadhava");
		writer.Int(min_madhava_);

		writer.KeyConst("npartha");
		writer.Int(partha_tbl_.approx_count_fast());

		writer.KeyConst("nwebserver");
		writer.Int(last_node_cnt_);

		writer.KeyConst("nactionhdlr");
		writer.Int(palertmgr_->get_action_proc_count());

		writer.KeyConst("svchost");
		writer.String(psettings->service_hostname);

		writer.KeyConst("svcport");
		writer.Int(psettings->service_port);

		writer.KeyConst("shyamaname");
		writer.String(psettings->shyama_name);

		writer.KeyConst("region");
		writer.String(region_name_);

		writer.KeyConst("zone");
		writer.String(zone_name_);

		writer.KeyConst("dbhost");
		writer.String(psettings->postgres_hostname);

		writer.KeyConst("dbport");
		writer.Int(psettings->postgres_port);

		writer.KeyConst("dbdays");
		writer.Int(db_storage_days_);

		writer.KeyConst("dbdiskmb");
		writer.Int64(GY_DOWN_MB(curr_db_size_));

		writer.KeyConst("dblogmode");
		writer.String(get_db_logging_level_str(psettings->db_logging));

		writer.KeyConst("dbconn");
		writer.Bool(!!dbpool.num_connected());

		writer.KeyConst("procstart");
		writer.String(gy_localtime_iso8601_sec(get_proc_start()).get());

		writer.KeyConst("kernverstr");
		writer.String(OS_INFO::get_singleton()->get_kernel_version_str());

		writer.KeyConst("version");
		writer.String(get_string_from_version_num(gversion_num, verbuf, 3));

		writer.KeyConst("dbversion");
		writer.String(dbpool.db_version_string().get());

		writer.KeyConst("webversion");
		writer.String(get_string_from_version_num(last_node_version_, verbuf, 3));
	
		writer.KeyConst("actionversion");
		writer.String(get_string_from_version_num(palertmgr_->get_action_node_version(), verbuf, 3));
	
		writer.KeyConst("hostname");
		writer.String(OS_INFO::get_singleton()->get_node_hostname());

		writer.EndObject();

		return true;
	}
	catch(...) {
		writer.get_stream()->reset_if_not_sent(ERR_SERV_ERROR);
		throw;
	}	
}

bool SHCONN_HANDLER::web_db_detail_tracedef(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Trace Definition info\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Trace Definition Query : Database Querying Error : Failed to get an idle connection. Please try later...";
		
		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	time_t				tcurr = time(nullptr);
	int				ret;
	bool				bret;

	const JSON_DB_MAPPING		*colarr[MAX_MULTI_HOST_COLUMN_LIST];
	
	auto [ncol, colspec] 		= qryopt.get_column_list(colarr, GY_ARRAY_SIZE(colarr), SUBSYS_TRACEDEF);

	if (true) {
		STRING_BUFFER<48 * 1024>	strbuf;

		qryopt.get_db_select_query(strbuf, SUBSYS_ALERTDEF, "public.tracedeftbl");

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}	

	if (bret == false) {
		constexpr const char errbuf[] = "Trace Definition Query : Failed to schedule query to Database. Please retry later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("shyamaid");
	writer.String(gshyama_id_str_, 16);

	writer.KeyConst("tracedef");
	writer.StartArray();

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_json_cb(conn, std::move(gyres), is_completed, "Trace Definition", colarr, ncol, writer, total_rows, noextracolcb);
		}
	);
	
	auto		expirysec = std::max<int64_t>(10, pquery->get_time_to_expiry(tcurr));

	ret = dbpool.wait_one_response(expirysec * 1000, pconn.getintconn());

	if (ret != 0) {
		if (ret == 2) {
			db_stats_.ndbquery_timeout_.fetch_add_relaxed(1);
		}

		if (writer.get_stream()->reset_if_not_sent(ret == 2 ? ERR_TIMED_OUT : ERR_SYSERROR)) {
			if (ret == 2) {
				constexpr const char errbuf[] = "Trace Definition Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Trace Definition Query : Database Connection Error. Please try later...";

				send_json_error_resp(connshr, ERR_SYSERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}	

			return false;
		}	

		writer.EndArray();
		writer.EndObject();
		
		return false;
	}	

	writer.EndArray();

	writer.EndObject();

	return true;
}

bool SHCONN_HANDLER::web_query_tracedef(const std::shared_ptr<SHCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<SHSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	bool				bret;

	try {
		bret = web_db_detail_tracedef(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);

		if (bret == true) {
			return true;
		}	

		writer.get_stream()->reset_if_not_sent();
		return false;
	}
	catch(...) {
		writer.get_stream()->reset_if_not_sent();
		throw;
	}	
}

} // namespace shyama
} // namespace gyeeta

