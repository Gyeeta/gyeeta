//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include		"gy_common_inc.h"
#include		"gy_mconnhdlr.h"
#include		"gymadhava.h"
#include		"gy_print_offload.h"

using namespace 	gyeeta::comm;

namespace gyeeta {
namespace madhava {

bool MCONN_HANDLER::handle_node_query(const std::shared_ptr<MCONNTRACK> & connshr, const comm::QUERY_CMD *pquery, char *pjson, char *pendptr, \
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

			auto 		qtype = gy_get_json_qtype(jdoc);

			if (qtype == NQUERY_NM_MULTI_QUERY) {
				return web_multi_query(connshr, jdoc, pquery, pthrpoolarr, dbpool, statsmap);
			}	

			STACK_POOL_ALLOC_32K			stackpool;
			QUERY_OPTIONS				qryopt(jdoc, stackpool);

			MSTREAM_JSON_EPOLL			stream(connshr, *this, RESP_WEB_JSON, pquery->get_seqid(), pthrpoolarr);
			SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL>	writer(stream);

			return web_query_route_qtype(connshr, qryopt, stackpool, pquery, writer, pthrpoolarr, statsmap, dbpool);
		}
		else if (mtype == NODE_MSG_ADD) {
		}
		else if (mtype == NODE_MSG_UPDATE) {
			// Update settings
		}
		else if (mtype == NODE_MSG_DELETE) {
		}
		else if (mtype == NODE_MSG_PING) {
			MSTREAM_JSON_EPOLL			stream(connshr, *this, RESP_WEB_JSON, resp_seqid, pthrpoolarr);
			SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL>	writer(stream);
			
			writer.StartObject();
			writer.KeyConst("id");
			writer.String(gmadhava_id_str_, 16);
			writer.KeyConst("hosttime");
			writer.Uint64(get_usec_time()/1000);
			writer.KeyConst("lastchgmsec");	
			writer.Uint64(last_partha_chg_tusec_.load(mo_acquire)/1000);
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

bool MCONN_HANDLER::web_multi_query(const std::shared_ptr<MCONNTRACK> & connshr, const GEN_JSON_VALUE & jdoc, const comm::QUERY_CMD *pquery, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool, STATS_STR_MAP & statsmap)
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

	MSTREAM_JSON_EPOLL			stream(connshr, *this, RESP_WEB_JSON, pquery->get_seqid(), pthrpoolarr);
	SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL>	writer(stream);

	writer.StartObject();

	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	for (uint8_t i = 0; i < nmulti_query; ++i) {
		auto				& qryopt = qryoptarr[i].value();
		bool				bret;

		writer.Key(qryopt.get_multiquery_id());

		bret = web_query_route_qtype(connshr, qryopt, stackpool, pquery, writer, pthrpoolarr, statsmap, dbpool);

		if (bret == false) {
			if (writer.get_stream()->get_errorcode() == ERR_SUCCESS) {
				writer.get_stream()->set_errorcode(ERR_SERV_ERROR);
			}	

			// Terminate the multi query
			return false;
		}	
	}	

	writer.EndObject();

	return true;
}


bool MCONN_HANDLER::web_query_route_qtype(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, \
		const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, STATS_STR_MAP & statsmap, PGConnPool & dbpool)
{
	NODE_QUERY_TYPE_E		qtype;

	qtype = qryopt.get_query_type();

	switch (qtype) {
	
	case NQUERY_NM_HOST_STATE :	
		statsmap["Host State Query"]++;
		return web_query_hoststate(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);
	
	case NQUERY_NM_CPU_MEM :	
		statsmap["CPU Mem Query"]++;
		return web_query_cpu_mem(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);

	case NQUERY_NM_TOP_LISTENERS :	
		statsmap["Top Listeners Query"]++;
		return web_query_top_listeners(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);

	case NQUERY_NM_LISTENER_INFO :	
		statsmap["Listener Info Query"]++;
		return web_query_listener_info(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);

	case NQUERY_NM_LISTENER_SUMM :	
		statsmap["Listener Summary Query"]++;
		return web_query_listener_summ(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);

	case NQUERY_NM_ACTIVE_CONN :	
		statsmap["Active Conn Query"]++;
		return web_query_active_conn(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool, false /* is_extended */);

	case NQUERY_NM_EXTACTIVECONN :
		statsmap["extactiveconn Query"]++;
		return web_query_active_conn(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool, true /* is_extended */);

	case NQUERY_NM_CLIENT_CONN :	
		statsmap["Client Conn Query"]++;
		return web_query_client_conn(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool, false /* is_extended */);

	case NQUERY_NM_EXTCLIENTCONN :
		statsmap["Ext Client Conn Query"]++;
		return web_query_client_conn(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool, true /* is_extended */);

	case NQUERY_NM_LISTENPROC_MAP :	
		statsmap["ListenProc Map Query"]++;
		return web_query_listenproc_map(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);

	case NQUERY_NM_LISTENER_STATE :	
		statsmap["Service State Query"]++;
		return web_query_listener_state(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool, false /* is_extended */);

	case NQUERY_NM_EXTSVCSTATE :	
		statsmap["Ext Service State Query"]++;
		return web_query_listener_state(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool, true /* is_extended */);

	case NQUERY_NM_TOP_AGGR_PROCS :	
		statsmap["Top Aggr Procs Query"]++;
		return web_query_top_aggr_procs(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);

	case NQUERY_NM_TOP_HOST_PROCS :	
		statsmap["Top Host Procs Query"]++;
		return web_query_top_host_procs(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);

	case NQUERY_NM_NOTIFY_MSG :	
		statsmap["Notify Msg Query"]++;
		return web_query_notify_msg(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);

	case NQUERY_NM_HOST_INFO :	
		statsmap["Host Info Query"]++;
		return web_query_host_info(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);

	case NQUERY_NM_PROC_INFO :	
		statsmap["Proc Info Query"]++;
		return web_query_proc_info(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);

	case NQUERY_NM_PROC_STATE :	
		statsmap["Proc State Query"]++;
		return web_query_proc_state(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool, false /* is_extended */);

	case NQUERY_NM_EXTPROCSTATE :
		statsmap["Ext Proc State Query"]++;
		return web_query_proc_state(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool, true /* is_extended */);

	case NQUERY_NM_MADHAVASTATUS :	
		statsmap["Madhava Status Query"]++;
		return web_query_madhavastatus(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);
	
	case NQUERY_NM_PARTHALIST :
		statsmap["Partha List Query"]++;
		return web_query_parthalist(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);

	case NQUERY_NM_TRACEREQ :
		statsmap["Req Trace Query"]++;
		return web_query_tracereq(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool, false /* is_extended */);

	case NQUERY_NM_EXTTRACEREQ :
		statsmap["Ext Req Trace Query"]++;
		return web_query_tracereq(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool, true /* is_extended */);

	case NQUERY_NM_TRACECONN :
		statsmap["Req Trace Conn Query"]++;
		return web_query_traceconn(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);

	case NQUERY_NM_TRACEUNIQ :
		statsmap["Req Trace Uniq Query"]++;
		return web_query_traceuniq(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);

	case NQUERY_NM_TRACESTATUS :
		statsmap["Req Trace Status Query"]++;
		return web_query_tracestatus(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);

	case NQUERY_NM_TRACEHISTORY :
		statsmap["Req Trace History Query"]++;
		return web_query_tracehistory(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);



	default :			
		if (writer.get_stream()->reset_if_not_sent(ERR_INVALID_REQUEST)) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Unhandled or invalid Query Type %d seen for Madhava server", qtype);
		}
		return false;
	}	
}	

static char * get_db_multihost_top_listeners_query(STR_WR_BUF & strbuf, QUERY_OPTIONS & qryopt, const char *datetbl, TOP_LISTEN_E type)
{
	static constexpr const char		*whereclause[TOP_LISTEN_MAX] {
		/* TOP_LISTEN_ISSUE */		" s.curr_state > 2 ",
		/* TOP_LISTEN_QPS */		" s.qps_5s > 0 ",
		/* TOP_LISTEN_ACTIVE_CONN */	" s.nconns_active > 0 ",
		/* TOP_LISTEN_NET */		" (s.curr_kb_inbound + s.curr_kb_outbound > 0) ",
	};	

	static constexpr const char		*orderby[TOP_LISTEN_MAX] {
		/* TOP_LISTEN_ISSUE */		" curr_state desc ",
		/* TOP_LISTEN_QPS */		" qps_5s desc ",
		/* TOP_LISTEN_ACTIVE_CONN */	" nconns_active desc ",
		/* TOP_LISTEN_NET */		" (curr_kb_inbound + curr_kb_outbound) desc ",
	};	

	if (type >= TOP_LISTEN_MAX) {
		return strbuf.buffer();
	}	
	
	size_t					limit = qryopt.get_max_records();

	if (limit > MAX_MULTI_TOPN || limit == 0) {
		limit = MAX_MULTI_TOPN;
	}

	strbuf.appendconst(" select * from (select * from gy_multihostselect( $a$ ");

	qryopt.get_db_where_clause(strbuf, SUBSYS_HOST, "listenstatetbl", datetbl, "");

	// Abuse the function parameters for joins
	strbuf.appendfmt(" $a$, \'listenstatetbl\', \'%s\', \' s left join listentbl l on s.glob_id = l.glob_id  \', \'s.*, l.ip, l.port \', $b$ where ", datetbl);

	qryopt.get_db_time_param(strbuf, SUBSYS_SVCSTATE, "listenstatetbl", datetbl, "s.");

	strbuf.appendfmt(" and %s ", whereclause[type]);
	
	strbuf.appendconst(" $b$) as (machid char(32), hostname text, madhavaid char(16), clustername text, ");

	qryopt.get_db_column_definition(strbuf, SUBSYS_SVCSTATE, true /* ign_col_list */);

	strbuf.appendconst(", ip text, port int )) t order by ");

	strbuf.appendfmt("%s limit %lu; ", orderby[type], limit);

	CONDEXEC(
		DEBUGEXECN(11,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Postgres Multi Host Top Listeners Query is : \"%s\"\n", strbuf.buffer());
		);
	);

	return strbuf.buffer();
}

static char * get_db_top_listeners_query(STR_WR_BUF & strbuf, QUERY_OPTIONS & qryopt, const char *datetbl, TOP_LISTEN_E type)
{
	static constexpr const char		*whereclause[TOP_LISTEN_MAX] {
		/* TOP_LISTEN_ISSUE */		" s.curr_state > 2 ",
		/* TOP_LISTEN_QPS */		" s.qps_5s > 0 ",
		/* TOP_LISTEN_ACTIVE_CONN */	" s.nconns_active > 0 ",
		/* TOP_LISTEN_NET */		" (s.curr_kb_inbound + s.curr_kb_outbound > 0) ",
	};	

	static constexpr const char		*orderby[TOP_LISTEN_MAX] {
		/* TOP_LISTEN_ISSUE */		" s.curr_state desc ",
		/* TOP_LISTEN_QPS */		" s.qps_5s desc ",
		/* TOP_LISTEN_ACTIVE_CONN */	" s.nconns_active desc ",
		/* TOP_LISTEN_NET */		" (s.curr_kb_inbound + s.curr_kb_outbound) desc ",
	};	

	if (type >= TOP_LISTEN_MAX) {
		return strbuf.buffer();
	}	

	size_t					limit = qryopt.get_max_records();

	if (limit > MAX_MULTI_TOPN || limit == 0) {
		limit = MAX_MULTI_TOPN;
	}

	const auto				parid = qryopt.get_parid_str();

	strbuf.appendfmt(" select s.*, l.ip, l.port from sch%s.listenstatetbl%s  s left join sch%s.listentbl l on s.glob_id = l.glob_id  where ", 
		parid.get(), datetbl, parid.get());

	qryopt.get_db_time_param(strbuf, SUBSYS_SVCSTATE, "listenstatetbl", datetbl, "s.");

	strbuf.appendfmt(" and %s order by %s limit %lu; ", whereclause[type], orderby[type], limit);

	CONDEXEC(
		DEBUGEXECN(11,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Postgres Single Host Top Listeners Query is : \"%s\"\n", strbuf.buffer());
		);
	);

	return strbuf.buffer();
}

static char * get_db_listen_summ_stats_query(STR_WR_BUF & strbuf, QUERY_OPTIONS & qryopt, const char *datetbl, bool ign_col_list = false)
{
	if ((false == qryopt.is_multi_host()) && (qryopt.is_pointintime())) {
		char				tablename[128];

		snprintf(tablename, sizeof(tablename), "sch%s.listensummtbl%s", qryopt.get_parid_str().get(), datetbl);
		
		return qryopt.get_db_select_query(strbuf, SUBSYS_SVCSUMM, tablename, "", ign_col_list);
	}	

	const char		*paggr = (qryopt.is_pointintime() ? "sum" : "avg");

	strbuf.appendconst("\n select max(time) as time,");
	
	for (size_t i = 1; i < GY_ARRAY_SIZE(json_db_svcsumm_arr); ++i) {
		const char		*pdbcol = json_db_svcsumm_arr[i].dbcolname;

		if (0 == *pdbcol) break;

		strbuf.appendfmt(" %s(%s::bigint)::bigint as %s,", paggr, pdbcol, pdbcol);
	}

	strbuf.set_last_char(' ');

	strbuf.appendconst("from ( ");

	if (qryopt.is_multi_host()) {
		qryopt.get_db_select_multihost_query(strbuf, SUBSYS_SVCSUMM, "listensummtbl", datetbl, ign_col_list);
	}
	else {
		char				tablename[128];

		snprintf(tablename, sizeof(tablename), "sch%s.listensummtbl%s", qryopt.get_parid_str().get(), datetbl);
		
		qryopt.get_db_select_query(strbuf, SUBSYS_SVCSUMM, tablename, "", ign_col_list);
	}

	strbuf.appendconst(" ) s; ");

	return strbuf.buffer();
}	

static char * get_db_multihost_top_aggr_procs_query(STR_WR_BUF & strbuf, QUERY_OPTIONS & qryopt, const char *datetbl, TOP_APROC_E type)
{
	static constexpr const char		*whereclause[TOP_APROC_MAX] {
		/* TOP_APROC_ISSUE */		" s.curr_state > 2 order by s.curr_state desc limit 50 ",
		/* TOP_APROC_NET */		" s.tcp_kbytes > 0 order by s.tcp_kbytes desc limit 50 ",
		/* TOP_APROC_CPU */		" s.total_cpu_pct > 0.1 order by s.total_cpu_pct desc limit 50 ",
		/* TOP_APROC_RSS */		" s.rss_mb > 5 order by s.rss_mb desc limit 50 ",
		/* TOP_APROC_CPU_DELAY */	" s.cpu_delay_msec > 0 order by s.cpu_delay_msec desc limit 50 ",
		/* TOP_APROC_VM_DELAY */	" s.vm_delay_msec > 0 order by s.vm_delay_msec desc limit 50 ",
		/* TOP_APROC_IO_DELAY */	" s.blkio_delay_msec > 0 order by s.blkio_delay_msec desc limit 50 ",
	};	

	static constexpr const char		*orderby[TOP_APROC_MAX] {
		/* TOP_APROC_ISSUE */		" curr_state desc ",
		/* TOP_APROC_NET */		" tcp_kbytes desc ",
		/* TOP_APROC_CPU */		" total_cpu_pct desc ",
		/* TOP_APROC_RSS */		" rss_mb desc ",
		/* TOP_APROC_CPU_DELAY */	" cpu_delay_msec desc ",
		/* TOP_APROC_VM_DELAY */	" vm_delay_msec desc ",
		/* TOP_APROC_IO_DELAY */	" blkio_delay_msec desc ",
	};	

	if (unsigned(type) >= TOP_APROC_MAX) {
		return strbuf.buffer();
	}	
	
	size_t					limit = qryopt.get_max_records();

	if (limit > MAX_MULTI_TOPN || limit == 0) {
		limit = MAX_MULTI_TOPN;
	}

	strbuf.appendconst(" select * from (select * from gy_multihostselect( $a$ ");

	qryopt.get_db_where_clause(strbuf, SUBSYS_HOST, "aggrtaskstatetbl", datetbl, "");

	strbuf.appendfmt(" $a$, \'aggrtaskstatetbl\', \'%s\', \'s\', \'s.*\', $b$ where ", datetbl);

	qryopt.get_db_time_param(strbuf, SUBSYS_PROCSTATE, "aggrtaskstatetbl", datetbl, "s.");

	strbuf.appendfmt(" and %s ", whereclause[type]);
	
	strbuf.appendconst(" $b$) as (machid char(32), hostname text, madhavaid char(16), clustername text, ");

	qryopt.get_db_column_definition(strbuf, SUBSYS_PROCSTATE, true /* ign_col_list */);

	strbuf.appendconst(" )) t order by ");

	strbuf.appendfmt("%s limit %lu; ", orderby[type], limit);

	CONDEXEC(
		DEBUGEXECN(11,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Postgres Multi Host Top Aggr Process Query is : \"%s\"\n", strbuf.buffer());
		);
	);

	return strbuf.buffer();
}

static char * get_db_top_aggr_procs_query(STR_WR_BUF & strbuf, QUERY_OPTIONS & qryopt, const char *datetbl, TOP_APROC_E type)
{
	static constexpr const char		*whereclause[TOP_APROC_MAX] {
		/* TOP_APROC_ISSUE */		" s.curr_state > 2 ",
		/* TOP_APROC_NET */		" s.tcp_kbytes > 0 ",
		/* TOP_APROC_CPU */		" s.total_cpu_pct > 0.1 ",
		/* TOP_APROC_RSS */		" s.rss_mb > 5 ",
		/* TOP_APROC_CPU_DELAY */	" s.cpu_delay_msec > 0 ",
		/* TOP_APROC_VM_DELAY */	" s.vm_delay_msec > 0 ",
		/* TOP_APROC_IO_DELAY */	" s.blkio_delay_msec > 0 ",
	};	

	static constexpr const char		*orderby[TOP_APROC_MAX] {
		/* TOP_APROC_ISSUE */		" curr_state desc ",
		/* TOP_APROC_NET */		" tcp_kbytes desc ",
		/* TOP_APROC_CPU */		" total_cpu_pct desc ",
		/* TOP_APROC_RSS */		" rss_mb desc ",
		/* TOP_APROC_CPU_DELAY */	" cpu_delay_msec desc ",
		/* TOP_APROC_VM_DELAY */	" vm_delay_msec desc ",
		/* TOP_APROC_IO_DELAY */	" blkio_delay_msec desc ",
	};	

	if (unsigned(type) >= TOP_APROC_MAX) {
		return strbuf.buffer();
	}	

	size_t					limit = qryopt.get_max_records();

	if (limit > MAX_MULTI_TOPN || limit == 0) {
		limit = MAX_MULTI_TOPN;
	}

	const auto				parid = qryopt.get_parid_str();

	strbuf.appendfmt(" select s.* from sch%s.aggrtaskstatetbl%s s where ", parid.get(), datetbl);

	qryopt.get_db_time_param(strbuf, SUBSYS_PROCSTATE, "aggrtaskstatetbl", datetbl, "s.");

	strbuf.appendfmt(" and %s order by %s limit %lu; ", whereclause[type], orderby[type], limit);

	CONDEXEC(
		DEBUGEXECN(11,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Postgres Single Host Top Aggr Proc Query is : \"%s\"\n", strbuf.buffer());
		);
	);

	return strbuf.buffer();
}

void MCONN_HANDLER::noextracolcb(SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer) noexcept
{}


bool MCONN_HANDLER::web_db_set_partha_hostinfo(SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, QUERY_OPTIONS & qryopt) const
{
	bool			bret;

	assert(false == qryopt.is_multi_host());

	auto parlam = [&](PARTHA_INFO_ELEM *pelem, void *arg1, void *arg2) -> CB_RET_E
	{
		auto			prawpartha = pelem->get_cref().get();

		if (gy_unlikely(prawpartha == nullptr)) {
			return CB_OK;
		}	

		writer.KeyConst("hostinfo");
		writer.StartObject();

		writer.KeyConst("parid");
		writer.String(prawpartha->machine_id_str_, sizeof(prawpartha->machine_id_str_) - 1);
		
		writer.KeyConst("host");
		writer.String(prawpartha->hostname_, GY_READ_ONCE(prawpartha->hostname_len_));

		writer.KeyConst("madid");
		writer.String(gmadhava_id_str_, 16);

		writer.KeyConst("cluster");
		writer.String(prawpartha->cluster_name_, GY_READ_ONCE(prawpartha->cluster_len_));

		writer.EndObject();

		return CB_OK;
	};	

	bret = partha_tbl_.lookup_single_elem(qryopt.get_parid(), qryopt.get_parid().get_hash(), parlam);

	if (bret == false) {
		writer.KeyConst("hostinfo");
		writer.StartObject();

		writer.KeyConst("parid");
		writer.String(qryopt.get_parid_str().get());
		
		writer.KeyConst("host");
		writer.String("", 0);

		writer.KeyConst("madid");
		writer.String(gmadhava_id_str_, 16);

		writer.KeyConst("cluster");
		writer.String("", 0);

		writer.EndObject();
	}	

	return bret;
}	


bool MCONN_HANDLER::web_curr_partha_hoststate(SOCK_JSON_WRITER<MCONN_HANDLER::MSTREAM_JSON_EPOLL> & writer, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool) const
{
	uint64_t			minchgusec = 0, min_state_tusec = get_usec_time() - 10 * GY_USEC_PER_SEC;
	uint64_t			maxrecs = qryopt.get_max_records();
	uint32_t			nhosts = 0, nhosts_offline = 0, ntotal_hosts = 0;
	bool				is_minchg_filter = false, is_multi_host = qryopt.is_multi_host(), bret;

	const auto			*poption = qryopt.get_options_json();

	if (poption) {
		const auto	& optobj = poption->GetObject();
		auto		miter = optobj.FindMember("minchgmsec");

		if ((miter != optobj.MemberEnd()) && (miter->value.IsUint64())) {
			minchgusec = miter->value.GetUint64() * 1000;

			if (minchgusec > GY_USEC_PER_MINUTE) {
				minchgusec -= GY_USEC_PER_MINUTE;
				
				is_minchg_filter = true;
			}	
		}	
	}

	qryopt.comp_criteria_init();

	const JSON_DB_MAPPING		*colarr[MAX_MULTI_HOST_COLUMN_LIST];
	
	auto [ncol, colspec] 		= qryopt.get_all_column_list(colarr, GY_ARRAY_SIZE(colarr), SUBSYS_HOSTSTATE);

	writer.StartObject();

	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	writer.KeyConst("hoststate");
	writer.StartArray();

	auto lampar = [&, minchgusec, is_minchg_filter, min_state_tusec, maxrecs, tcurr = time(nullptr)](PARTHA_INFO_ELEM *pdatanode, void *arg1) -> CB_RET_E
	{
		auto			prawpartha = pdatanode->get_data()->get();
		bool			bret;

		if (gy_unlikely(prawpartha == nullptr)) {
			return CB_OK;
		}	

		ntotal_hosts++;
	
		comm::HOST_STATE_NOTIFY		hstate(prawpartha->host_state_);

		if (hstate.curr_time_usec_ < min_state_tusec) {

			if (!is_minchg_filter || GY_READ_ONCE(prawpartha->last_register_tusec_) < minchgusec) {
				if (false == prawpartha->is_conn_available()) {
					nhosts_offline++;
				}
				return CB_OK;
			}	

			// State unknown
			hstate.~HOST_STATE_NOTIFY();

			new (&hstate) comm::HOST_STATE_NOTIFY();
		}	

		HostStateFields			hstatefields(*prawpartha, hstate, gmadhava_id_str_, tcurr);

		if (qryopt.has_filter()) {
			auto 			cret = hstatefields.filter_match(qryopt.get_filter_criteria());

			if (cret == CRIT_FAIL) {
				return CB_OK;
			}
		}	

		if (is_minchg_filter && GY_READ_ONCE(prawpartha->last_register_tusec_) < minchgusec) {
			return CB_OK;
		}

		hstatefields.print_json(colarr, ncol, writer);

		nhosts++;

		if (nhosts >= maxrecs) {
			return CB_BREAK_LOOP;
		}	

		return CB_OK;
	};

	if (is_multi_host) {
		partha_tbl_.walk_hash_table_const(lampar);

		writer.EndArray();
	}	
	else {
		auto parlam = [&](PARTHA_INFO_ELEM *pelem, void *arg1, void *arg2) -> CB_RET_E
		{
			auto				prawpartha = pelem->get_cref().get();

			if (gy_unlikely(prawpartha == nullptr)) {
				return CB_OK;
			}	

			lampar(pelem, arg1);

			writer.EndArray();
			
			writer.KeyConst("hostinfo");
			writer.StartObject();

			writer.KeyConst("parid");
			writer.String(prawpartha->machine_id_str_, sizeof(prawpartha->machine_id_str_) - 1);
			
			writer.KeyConst("host");
			writer.String(prawpartha->hostname_, GY_READ_ONCE(prawpartha->hostname_len_));

			writer.KeyConst("madid");
			writer.String(gmadhava_id_str_, 16);

			writer.KeyConst("cluster");
			writer.String(prawpartha->cluster_name_, GY_READ_ONCE(prawpartha->cluster_len_));

			writer.EndObject();

			return CB_OK;
		};	

		bret = partha_tbl_.lookup_single_elem(qryopt.get_parid(), qryopt.get_parid().get_hash(), parlam);
		
		if (bret == false) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Hoststate Query : Partha ID Specified not found or was deleted recently");
		}	
	}	

	if (!is_multi_host || maxrecs <= ntotal_hosts) {
		ntotal_hosts = partha_tbl_.approx_count_fast();
	}	

	writer.KeyConst("lastchgmsec");	
	writer.Uint64(last_partha_chg_tusec_.load(mo_acquire)/1000);

	writer.KeyConst("ntotal_hosts");	
	writer.Uint64(ntotal_hosts);

	writer.KeyConst("nhosts");	
	writer.Uint64(nhosts);

	writer.KeyConst("nhosts_offline");	
	writer.Uint64(nhosts_offline);

	writer.EndObject();

	return true;
}	
	
bool MCONN_HANDLER::web_db_detail_hoststate(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Hoststate info\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Hoststate Query : Database Querying Error : Failed to get an idle connection. Please try later...";
		
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
	
	auto [ncol, colspec] 		= qryopt.get_all_column_list(colarr, GY_ARRAY_SIZE(colarr), SUBSYS_HOSTSTATE);

	if (tcurr - db_storage_days_ * GY_SEC_PER_DAY > (uint64_t)tvend.tv_sec) {
		char			ebuf[256];
		size_t			esz;
		
		esz = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Hoststate Query : Time Requested not present in DB : Max Days of DB storage = %u", db_storage_days_);

		if (writer.get_stream()->reset_if_not_sent(ERR_DATA_NOT_FOUND)) {
			send_json_error_resp(connshr, ERR_DATA_NOT_FOUND, pquery->get_seqid(), ebuf, esz, pthrpoolarr);
		}

		return false;
	}	
	
	if (qryopt.is_multi_host()) {

		STRING_BUFFER<48 * 1024>		strbuf;
		
		qryopt.get_db_select_multihost_query(strbuf, SUBSYS_HOSTSTATE, "hoststatetbl", datetbl.get());

		strbuf.appendconst(";\n reset search_path; ");

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}
	else {
		STRING_BUFFER<48 * 1024>	strbuf;
		char				tablename[128];

		snprintf(tablename, sizeof(tablename), "sch%s.hoststatetbl%s", qryopt.get_parid_str().get(), datetbl.get());

		qryopt.get_db_select_query(strbuf, SUBSYS_HOSTSTATE, tablename);

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}	

	if (bret == false) {
		constexpr const char errbuf[] = "Hoststate Query : Failed to schedule query to Database. Please retry later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	writer.StartObject();

	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	writer.KeyConst("hoststate");
	writer.StartArray();

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_json_cb(conn, std::move(gyres), is_completed, "HostState", colarr, ncol, writer, total_rows, noextracolcb);
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
				constexpr const char errbuf[] = "Hoststate Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Hoststate Query : Database Connection Error. Please try later...";

				send_json_error_resp(connshr, ERR_SYSERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}	

			return false;
		}	

		writer.EndArray();
		writer.EndObject();
		
		return false;
	}	

	writer.EndArray();

	if (false == qryopt.is_multi_host()) {
		web_db_set_partha_hostinfo(writer, qryopt);
	}

	writer.KeyConst("lastchgmsec");	
	writer.Uint64(last_partha_chg_tusec_.load(mo_acquire)/1000);

	writer.KeyConst("ntotal_hosts");	
	writer.Uint64(0);

	writer.KeyConst("nhosts");	
	writer.Uint64(0);

	writer.KeyConst("nhosts_offline");	
	writer.Uint64(0);

	writer.EndObject();

	return true;
}

bool MCONN_HANDLER::web_db_aggr_hoststate(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Aggregated Hoststate info\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Aggregated Hoststate Query : Database Querying Error : Failed to get an idle connection. Please try later...";
		
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
		
		esz = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Aggregated Hoststate Query : Time Requested not present in DB : Max Days of DB storage = %u", db_storage_days_);

		if (writer.get_stream()->reset_if_not_sent(ERR_DATA_NOT_FOUND)) {
			send_json_error_resp(connshr, ERR_DATA_NOT_FOUND, pquery->get_seqid(), ebuf, esz, pthrpoolarr);
		}

		return false;
	}	

	const JSON_DB_MAPPING		*colarr[QUERY_OPTIONS::MAX_AGGR_COLUMNS];
	JSON_DB_MAPPING			acolarr[QUERY_OPTIONS::MAX_AGGR_COLUMNS];
	uint32_t			ncol;

	assert(gy_get_thread_local().get_thread_stack_freespace() >= 256 * 1024);

	if (true) {
		STRING_BUFFER<48 * 1024>		strbuf;
		
		ncol = get_hoststate_aggr_query(strbuf, qryopt, datetbl.get(), acolarr);

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());

		if (bret == false) {
			constexpr const char errbuf[] = "Aggregated Hoststate Query : Failed to schedule query to Database. Please retry later...";

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

	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	writer.KeyConst("hoststate");
	writer.StartArray();

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_json_cb(conn, std::move(gyres), is_completed, "Aggregated HostState", colarr, ncol, writer, total_rows, noextracolcb);
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
				constexpr const char errbuf[] = "Aggregated Hoststate Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Aggregated Hoststate Query : Database Connection Error. Please try later...";

				send_json_error_resp(connshr, ERR_SYSERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}	

			return false;
		}	

		writer.EndArray();
		writer.EndObject();
		
		return false;
	}	

	writer.EndArray();

	if (false == qryopt.is_multi_host()) {
		web_db_set_partha_hostinfo(writer, qryopt);
	}

	set_json_column_list(writer, colarr, ncol);

	writer.KeyConst("lastchgmsec");	
	writer.Uint64(last_partha_chg_tusec_.load(mo_acquire)/1000);

	writer.KeyConst("ntotal_hosts");	
	writer.Uint64(0);

	writer.KeyConst("nhosts");	
	writer.Uint64(0);

	writer.KeyConst("nhosts_offline");	
	writer.Uint64(0);

	writer.EndObject();

	return true;
}

bool MCONN_HANDLER::web_query_hoststate(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	bool					bret, is_aggregated = qryopt.is_aggregated();

	try {
		if (false == qryopt.match_madhava_option(gmadhava_id_str_)) {
			// Skip this query
			writer.StartObject();	
			
			writer.KeyConst("madid");
			writer.String(gmadhava_id_str_, 16);

			writer.EndObject();

			return true;
		}

		if (!qryopt.is_historical()) {
			bret = web_curr_partha_hoststate(writer, qryopt, extpool);
		}
		else {
			if (false == is_aggregated) {
				bret = web_db_detail_hoststate(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);
			}
			else {
				bret = web_db_aggr_hoststate(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);
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


bool MCONN_HANDLER::web_curr_cpu_mem(SOCK_JSON_WRITER<MCONN_HANDLER::MSTREAM_JSON_EPOLL> & writer, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool) const
{
	uint64_t			maxrecs = qryopt.get_max_records(), nhosts = 0;
	bool				bret, is_multi_host = qryopt.is_multi_host();

	qryopt.comp_criteria_init();

	const JSON_DB_MAPPING		*colarr[MAX_MULTI_HOST_COLUMN_LIST];
	
	auto [ncol, colspec] 		= qryopt.get_all_column_list(colarr, GY_ARRAY_SIZE(colarr), SUBSYS_CPUMEM);

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	writer.KeyConst("cpumem");
	writer.StartArray();
		
	auto lampar = [&, maxrecs, is_multi_host, curr_tusec = (int64_t)get_usec_time()](PARTHA_INFO_ELEM *pdatanode, void *arg1) -> CB_RET_E
	{
		auto				prawpartha = pdatanode->get_cref().get();
		bool				bret;

		if (gy_unlikely(prawpartha == nullptr)) {
			return CB_OK;
		}	
	
		if (prawpartha->cpu_mem_state_.tusec_ < curr_tusec - 10 * (int64_t)GY_USEC_PER_SEC) {
			if (is_multi_host == false) {
				GY_THROW_EXPR_CODE(ERR_DATA_NOT_FOUND, "CPU Memory Query : Partha Host %s has not updated its data recently", prawpartha->hostname_);
			}	

			return CB_OK;
		}	
	
		CpuMemFields			cpumemfields(*prawpartha, prawpartha->cpu_mem_state_, gmadhava_id_str_);

		if (qryopt.has_filter()) {
			auto 			cret = cpumemfields.filter_match(qryopt.get_filter_criteria());

			if (cret == CRIT_FAIL) {
				return CB_OK;
			}
		}	

		cpumemfields.print_json(colarr, ncol, writer);	
			
		nhosts++;

		if (nhosts >= maxrecs) {
			return CB_BREAK_LOOP;
		}	

		return CB_OK;
	};

	if (is_multi_host) {
		partha_tbl_.walk_hash_table_const(lampar);
	
		writer.EndArray();
	}	
	else {
		auto parlam = [&](PARTHA_INFO_ELEM *pelem, void *arg1, void *arg2) -> CB_RET_E
		{
			auto				prawpartha = pelem->get_cref().get();

			if (gy_unlikely(prawpartha == nullptr)) {
				return CB_OK;
			}	

			lampar(pelem, arg1);

			writer.EndArray();
			
			writer.KeyConst("hostinfo");
			writer.StartObject();

			writer.KeyConst("parid");
			writer.String(prawpartha->machine_id_str_, sizeof(prawpartha->machine_id_str_) - 1);
			
			writer.KeyConst("host");
			writer.String(prawpartha->hostname_, GY_READ_ONCE(prawpartha->hostname_len_));

			writer.KeyConst("madid");
			writer.String(gmadhava_id_str_, 16);

			writer.KeyConst("cluster");
			writer.String(prawpartha->cluster_name_, GY_READ_ONCE(prawpartha->cluster_len_));

			writer.EndObject();

			return CB_OK;
		};	

		bret = partha_tbl_.lookup_single_elem(qryopt.get_parid(), qryopt.get_parid().get_hash(), parlam);
		
		if (bret == false) {
			GY_THROW_EXPR_CODE(ERR_DATA_NOT_FOUND, "Partha CPU Memory Query : Partha ID Specified not found or was deleted recently");
		}	
	}	

	writer.EndObject();

	return true;
}	

bool MCONN_HANDLER::web_db_detail_cpu_mem(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for CPU Memory info\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "CPU Memory Query : Database Querying Error : Failed to get an idle connection. Please try later...";

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
	
	auto [ncol, colspec] 		= qryopt.get_all_column_list(colarr, GY_ARRAY_SIZE(colarr), SUBSYS_CPUMEM);

	if (tcurr - db_storage_days_ * GY_SEC_PER_DAY > (uint64_t)tvend.tv_sec) {
		char			ebuf[256];
		size_t			esz;
		
		esz = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "CPU Memory Query : Time Requested not present in DB : Max Days of DB storage = %u", db_storage_days_);

		if (writer.get_stream()->reset_if_not_sent(ERR_DATA_NOT_FOUND)) {
			send_json_error_resp(connshr, ERR_DATA_NOT_FOUND, pquery->get_seqid(), ebuf, esz, pthrpoolarr);
		}

		return false;
	}	
	
	if (qryopt.is_multi_host()) {
		STRING_BUFFER<48 * 1024>		strbuf;
		
		qryopt.get_db_select_multihost_query(strbuf, SUBSYS_CPUMEM, "cpumemstatetbl", datetbl.get());

		strbuf.appendconst(";\n reset search_path; ");

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}
	else {
		STRING_BUFFER<48 * 1024>	strbuf;
		char				tablename[128];

		snprintf(tablename, sizeof(tablename), "sch%s.cpumemstatetbl%s", qryopt.get_parid_str().get(), datetbl.get());

		qryopt.get_db_select_query(strbuf, SUBSYS_CPUMEM, tablename);

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}	

	if (bret == false) {
		constexpr const char errbuf[] = "CPU Memory Query : Failed to schedule query to Database. Please retry later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	const auto extracb = [colarr, ncol](SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer1)
	{
		const auto isvalidextracol = [&](uint32_t jsoncrc)
		{
			for (size_t i = 0; i < ncol; ++i) {
				if (colarr[i]->jsoncrc == jsoncrc) {
					return true;
				}	
			}

			return false;
		};	

		if (true == isvalidextracol(FIELD_CS_5MIN_P95_SEC)) {
			writer1.KeyConst("cs_5min_p95_sec");
			writer1.Uint(0);
		}

		if (true == isvalidextracol(FIELD_CPU_5MIN_P95)) {
			writer1.KeyConst("cpu_5min_p95");
			writer1.Uint(0);
		}

		if (true == isvalidextracol(FIELD_FORK_5MIN_P95_SEC)) {
			writer1.KeyConst("fork_5min_p95_sec");
			writer1.Uint(0);
		}

		if (true == isvalidextracol(FIELD_PROCS_5MIN_P95)) {
			writer1.KeyConst("procs_5min_p95");
			writer1.Uint(0);
		}
	};	

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	writer.KeyConst("cpumem");
	writer.StartArray();

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_json_cb(conn, std::move(gyres), is_completed, "CPU Memory", colarr, ncol, writer, total_rows, extracb);
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
				constexpr const char errbuf[] = "CPU Memory Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "CPU Memory Query : Database Connection Error. Please try later...";

				send_json_error_resp(connshr, ERR_SYSERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}	

			return false;
		}	

		writer.EndArray();
		writer.EndObject();

		return false;
	}	

	writer.EndArray();

	if (false == qryopt.is_multi_host()) {
		web_db_set_partha_hostinfo(writer, qryopt);
	}

	writer.EndObject();

	return true;
}	

bool MCONN_HANDLER::web_db_aggr_cpu_mem(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Aggregated CPU Memory info\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Aggregated CPU Memory Query : Database Querying Error : Failed to get an idle connection. Please try later...";

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
		
		esz = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Aggregated CPU Memory Query : Time Requested not present in DB : Max Days of DB storage = %u", db_storage_days_);

		if (writer.get_stream()->reset_if_not_sent(ERR_DATA_NOT_FOUND)) {
			send_json_error_resp(connshr, ERR_DATA_NOT_FOUND, pquery->get_seqid(), ebuf, esz, pthrpoolarr);
		}

		return false;
	}	

	const JSON_DB_MAPPING		*colarr[QUERY_OPTIONS::MAX_AGGR_COLUMNS];
	JSON_DB_MAPPING			acolarr[QUERY_OPTIONS::MAX_AGGR_COLUMNS];
	uint32_t			ncol;

	assert(gy_get_thread_local().get_thread_stack_freespace() >= 256 * 1024);

	if (true) {
		STRING_BUFFER<48 * 1024>	strbuf;

		ncol = get_cpumem_aggr_query(strbuf, qryopt, datetbl.get(), acolarr);

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());

		if (bret == false) {
			constexpr const char errbuf[] = "Aggregated CPU Memory Query : Failed to schedule query to Database. Please retry later...";

			if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
				send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			
			return false;
		}	

		for (uint32_t i = 0; i < ncol; ++i) {
			colarr[i] = acolarr + i;
		}	
	}

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	writer.KeyConst("cpumem");
	writer.StartArray();

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_json_cb(conn, std::move(gyres), is_completed, "Aggregated CPU Memory", colarr, ncol, writer, total_rows, noextracolcb);
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
				constexpr const char errbuf[] = "Aggregated CPU Memory Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Aggregated CPU Memory Query : Database Connection Error. Please try later...";

				send_json_error_resp(connshr, ERR_SYSERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}	

			return false;
		}	

		writer.EndArray();
		writer.EndObject();

		return false;
	}	

	writer.EndArray();

	if (false == qryopt.is_multi_host()) {
		web_db_set_partha_hostinfo(writer, qryopt);
	}

	set_json_column_list(writer, colarr, ncol);

	writer.EndObject();

	return true;
}

bool MCONN_HANDLER::web_query_cpu_mem(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	bool				bret, is_aggregated = qryopt.is_aggregated();

	try {
		if (false == qryopt.match_madhava_option(gmadhava_id_str_)) {
			// Skip this query
			writer.StartObject();	

			writer.KeyConst("madid");
			writer.String(gmadhava_id_str_, 16);

			writer.EndObject();

			return true;
		}

		if (!qryopt.is_historical()) {
			bret = web_curr_cpu_mem(writer, qryopt, extpool);
		}
		else {
			if (false == is_aggregated) {
				bret = web_db_detail_cpu_mem(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);
			}
			else {
				bret = web_db_aggr_cpu_mem(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);
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

template <typename T>
static void send_listen_one_summ_stats(SOCK_JSON_WRITER<MCONN_HANDLER::MSTREAM_JSON_EPOLL> & writer, const LISTEN_SUMM_STATS<T> & stats, const char *ptime)
{
	writer.StartObject();

	writer.KeyConst("time");
	writer.String(ptime);

	writer.KeyConst("nidle");
	writer.Int64(stats.nstates_[STATE_IDLE]);

	writer.KeyConst("ngood");
	writer.Int64(stats.nstates_[STATE_GOOD]);

	writer.KeyConst("nok");
	writer.Int64(stats.nstates_[STATE_OK]);

	writer.KeyConst("nbad");
	writer.Int64(stats.nstates_[STATE_BAD]);

	writer.KeyConst("nsevere");
	writer.Int64(stats.nstates_[STATE_SEVERE]);

	writer.KeyConst("ndown");
	writer.Int64(stats.nstates_[STATE_DOWN]);

	writer.KeyConst("totqps");
	writer.Int64(stats.tot_qps_);

	writer.KeyConst("totaconn");
	writer.Int64(stats.tot_act_conn_);

	writer.KeyConst("totkbin");
	writer.Int64(stats.tot_kb_inbound_);

	writer.KeyConst("totkbout");
	writer.Int64(stats.tot_kb_outbound_);

	writer.KeyConst("totsererr");
	writer.Int64(stats.tot_ser_errors_);

	writer.KeyConst("nsvc");
	writer.Int64(stats.nlisteners_);

	writer.KeyConst("nactive");
	writer.Int64(stats.nactive_);

	writer.EndObject();	
}	
	

bool MCONN_HANDLER::web_curr_listener_summ(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr)
{
	uint64_t			maxrecs = qryopt.get_max_records(), nhosts = 0;
	bool				bret, is_multi_host = qryopt.is_multi_host();

	qryopt.comp_criteria_init();

	const JSON_DB_MAPPING		*colarr[MAX_MULTI_HOST_COLUMN_LIST];
	
	auto [ncol, colspec] 		= qryopt.get_all_column_list(colarr, GY_ARRAY_SIZE(colarr), SUBSYS_SVCSUMM);

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	writer.KeyConst("summstats");
	writer.StartArray();

	const auto lampar = [&, maxrecs, is_multi_host, min_tusec = (uint64_t)get_usec_time() - 10 * (int64_t)GY_USEC_PER_SEC](PARTHA_INFO_ELEM *pdatanode, void *arg1) -> CB_RET_E
	{
		auto				prawpartha = pdatanode->get_cref().get();
		bool				bret;

		if (gy_unlikely(prawpartha == nullptr)) {
			return CB_OK;
		}	
	
		if (GY_READ_ONCE(prawpartha->last_listen_state_tusec_) < min_tusec) {
			if (is_multi_host == false) {
				GY_THROW_EXPR_CODE(ERR_DATA_NOT_FOUND, "Listener Summary Query : Partha Host %s has not updated its data recently", prawpartha->hostname_);
			}	

			return CB_OK;
		}	
	
		const auto 			stats = prawpartha->summstats_;	// Copy

		SvcSummFields			svcsummfields(*prawpartha, stats, gmadhava_id_str_);

		if (qryopt.has_filter()) {
			auto 			cret = svcsummfields.filter_match(qryopt.get_filter_criteria());

			if (cret == CRIT_FAIL) {
				return CB_OK;
			}
		}	


		svcsummfields.print_json(colarr, ncol, writer);

		return CB_OK;
	};

	if (is_multi_host) {
		partha_tbl_.walk_hash_table_const(lampar);
	
		writer.EndArray();
	}	
	else {
		auto parlam = [&](PARTHA_INFO_ELEM *pelem, void *arg1, void *arg2) -> CB_RET_E
		{
			auto				prawpartha = pelem->get_cref().get();

			if (gy_unlikely(prawpartha == nullptr)) {
				return CB_OK;
			}	

			lampar(pelem, arg1);

			writer.EndArray();
			
			writer.KeyConst("hostinfo");
			writer.StartObject();

			writer.KeyConst("parid");
			writer.String(prawpartha->machine_id_str_, sizeof(prawpartha->machine_id_str_) - 1);
			
			writer.KeyConst("host");
			writer.String(prawpartha->hostname_, GY_READ_ONCE(prawpartha->hostname_len_));

			writer.KeyConst("madid");
			writer.String(gmadhava_id_str_, 16);

			writer.KeyConst("cluster");
			writer.String(prawpartha->cluster_name_, GY_READ_ONCE(prawpartha->cluster_len_));

			writer.EndObject();

			return CB_OK;
		};	

		bret = partha_tbl_.lookup_single_elem(qryopt.get_parid(), qryopt.get_parid().get_hash(), parlam);
		
		if (bret == false) {
			GY_THROW_EXPR_CODE(ERR_DATA_NOT_FOUND, "Listener Summary Query : Partha ID Specified not found or was deleted recently");
		}	
	}	

	writer.EndObject();

	return true;
}


bool MCONN_HANDLER::web_db_detail_listener_summ(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Listener Summary query\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Listener Summary Query : Database Querying Error : Failed to get an idle connection. Please try later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	int				ret;
	bool				bret;
	time_t				tcurr = time(nullptr);
	struct timeval			tvstart = qryopt.get_start_timeval(), tvend = qryopt.get_end_timeval();

	if (tcurr - db_storage_days_ * GY_SEC_PER_DAY > (uint64_t)tvend.tv_sec) {
		char			ebuf[256];
		size_t			esz;
		
		esz = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Listener Summary Query : Time Requested not present in DB : Max Days of DB storage = %u", db_storage_days_);

		if (writer.get_stream()->reset_if_not_sent(ERR_DATA_NOT_FOUND)) {
			send_json_error_resp(connshr, ERR_DATA_NOT_FOUND, pquery->get_seqid(), ebuf, esz, pthrpoolarr);
		}

		return false;
	}	

	const JSON_DB_MAPPING		*colarr[MAX_MULTI_HOST_COLUMN_LIST];
	
	auto [ncol, colspec] 		= qryopt.get_all_column_list(colarr, GY_ARRAY_SIZE(colarr), SUBSYS_SVCSUMM);

	auto 				datetbl = get_db_day_partition(tvstart.tv_sec, tvend.tv_sec, 0);
	
	if (qryopt.is_multi_host()) {
		STRING_BUFFER<48 * 1024>		strbuf;
		
		qryopt.get_db_select_multihost_query(strbuf, SUBSYS_SVCSUMM, "listensummtbl", datetbl.get());

		strbuf.appendconst(";\n reset search_path; ");

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}
	else {
		STRING_BUFFER<48 * 1024>	strbuf;
		char				tablename[128];

		snprintf(tablename, sizeof(tablename), "sch%s.listensummtbl%s", qryopt.get_parid_str().get(), datetbl.get());

		qryopt.get_db_select_query(strbuf, SUBSYS_SVCSUMM, tablename);

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}	

	if (bret == false) {
		constexpr const char errbuf[] = "Listener Summary Query : Failed to schedule query to Database. Please retry later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	writer.KeyConst("svcsumm");
	writer.StartArray();

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_json_cb(conn, std::move(gyres), is_completed, "Listener Summary", colarr, ncol, writer, total_rows, noextracolcb);
		}
	);
	
	auto		expirysec = std::max<int64_t>(30, pquery->get_time_to_expiry(tcurr));

	ret = dbpool.wait_one_response(expirysec * 1000, pconn.getintconn());

	if (ret != 0) {
		if (ret == 2) {
			db_stats_.ndbquery_timeout_.fetch_add_relaxed(1);
		}

		if (writer.get_stream()->reset_if_not_sent(ret == 2 ? ERR_TIMED_OUT : ERR_SYSERROR)) {
			if (ret == 2) {
				constexpr const char errbuf[] = "Listener Summary Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Listener Summary Query : Database Connection Error. Please try later...";

				send_json_error_resp(connshr, ERR_SYSERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}	

			return false;
		}	

		writer.EndArray();
		writer.EndObject();

		return false;
	}	

	writer.EndArray();

	if (false == qryopt.is_multi_host()) {
		web_db_set_partha_hostinfo(writer, qryopt);
	}

	writer.EndObject();

	return true;
}

bool MCONN_HANDLER::web_db_aggr_listener_summ(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Aggregated Listener Summary query\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Aggregated Listener Summary Query : Database Querying Error : Failed to get an idle connection. Please try later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	int				ret;
	bool				bret;
	time_t				tcurr = time(nullptr);
	struct timeval			tvstart = qryopt.get_start_timeval(), tvend = qryopt.get_end_timeval();

	if (tcurr - db_storage_days_ * GY_SEC_PER_DAY > (uint64_t)tvend.tv_sec) {
		char			ebuf[256];
		size_t			esz;
		
		esz = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Aggregated Listener Summary Query : Time Requested not present in DB : Max Days of DB storage = %u", db_storage_days_);

		if (writer.get_stream()->reset_if_not_sent(ERR_DATA_NOT_FOUND)) {
			send_json_error_resp(connshr, ERR_DATA_NOT_FOUND, pquery->get_seqid(), ebuf, esz, pthrpoolarr);
		}

		return false;
	}	
	
	auto 				datetbl = get_db_day_partition(tvstart.tv_sec, tvend.tv_sec, 0);

	const JSON_DB_MAPPING		*colarr[QUERY_OPTIONS::MAX_AGGR_COLUMNS];
	JSON_DB_MAPPING			acolarr[QUERY_OPTIONS::MAX_AGGR_COLUMNS];
	uint32_t			ncol;

	assert(gy_get_thread_local().get_thread_stack_freespace() >= 256 * 1024);

	if (true) {
		STRING_BUFFER<48 * 1024>		strbuf;
		
		ncol = get_svcsumm_aggr_query(strbuf, qryopt, datetbl.get(), acolarr);

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());

		if (bret == false) {
			constexpr const char errbuf[] = "Aggregated Listener Summary Query : Failed to schedule query to Database. Please retry later...";

			if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
				send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}

			return false;
		}	

		for (uint32_t i = 0; i < ncol; ++i) {
			colarr[i] = acolarr + i;
		}	
	}

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	writer.KeyConst("svcsumm");
	writer.StartArray();

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_json_cb(conn, std::move(gyres), is_completed, "Aggregated Listener Summary", colarr, ncol, writer, total_rows, noextracolcb);
		}
	);
	
	auto		expirysec = std::max<int64_t>(30, pquery->get_time_to_expiry(tcurr));

	ret = dbpool.wait_one_response(expirysec * 1000, pconn.getintconn());

	if (ret != 0) {
		if (ret == 2) {
			db_stats_.ndbquery_timeout_.fetch_add_relaxed(1);
		}

		if (writer.get_stream()->reset_if_not_sent(ret == 2 ? ERR_TIMED_OUT : ERR_SYSERROR)) {
			if (ret == 2) {
				constexpr const char errbuf[] = "Aggregated Listener Summary Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Aggregated Listener Summary Query : Database Connection Error. Please try later...";

				send_json_error_resp(connshr, ERR_SYSERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}	

			return false;
		}	

		writer.EndArray();
		writer.EndObject();

		return false;
	}	

	writer.EndArray();

	if (false == qryopt.is_multi_host()) {
		web_db_set_partha_hostinfo(writer, qryopt);
	}

	set_json_column_list(writer, colarr, ncol);

	writer.EndObject();

	return true;
}


bool MCONN_HANDLER::web_query_listener_summ(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	bool					bret, is_aggregated = qryopt.is_aggregated();

	try {
		if (false == qryopt.match_madhava_option(gmadhava_id_str_)) {
			// Skip this query
			writer.StartObject();	
	
			writer.KeyConst("madid");
			writer.String(gmadhava_id_str_, 16);

			writer.EndObject();

			return true;
		}

		if (!qryopt.is_historical()) {
			bret = web_curr_listener_summ(connshr, qryopt, extpool, pquery, writer, pthrpoolarr);
		}
		else {
			if (false == is_aggregated) {
				bret = web_db_detail_listener_summ(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);
			}
			else {
				bret = web_db_aggr_listener_summ(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);
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


bool MCONN_HANDLER::web_curr_listener_info(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr)
{
	uint64_t			maxrecs = qryopt.get_max_records(), nrecs = 0;
	const auto			& critset = qryopt.get_filter_criteria();
	bool				bret, is_multi_host = qryopt.is_multi_host();
	const auto			timebuf = gy_localtime_iso8601_sec(time(nullptr));

	qryopt.comp_criteria_init();

	const JSON_DB_MAPPING		*colarr[MAX_MULTI_HOST_COLUMN_LIST];
	
	auto [ncol, colspec] 		= qryopt.get_all_column_list(colarr, GY_ARRAY_SIZE(colarr), SUBSYS_SVCINFO);

	const auto sendsvc = [&, colarr, ncol](const MTCP_LISTENER & listener, bool check_filter = false) -> bool
	{
		const auto			prawpartha = listener.parthashr_.get();

		if (!prawpartha) {
			return false;
		}

		SvcInfoFields			svcinfofields(*prawpartha, listener, gmadhava_id_str_);

		if (check_filter && qryopt.has_filter()) {
			auto 			cret = svcinfofields.filter_match(qryopt.get_filter_criteria());

			if (cret == CRIT_FAIL) {
				return false;
			}
		}	

		nrecs++;

		svcinfofields.print_json(colarr, ncol, writer, timebuf.get());

		return true;
	};

	const auto listl = [&](MSOCKET_HDLR::MTCP_LISTENER_ELEM_TYPE *pdatanode, void *arg)
	{
		const auto			plistener = pdatanode->get_cref().get();

		if (plistener) {
			sendsvc(*plistener, true /* check_filter */);
		}	

		if (nrecs >= maxrecs) {
			return CB_BREAK_LOOP;
		}	

		return CB_OK;
	};	

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	writer.KeyConst("svcinfo");
	writer.StartArray();

	/*
	 * We first search if only svcid filters specified. If no, we check if multihost specified.
	 * If multihost, check if the host fiters are set. If yes, we iterate over the partha_tbl_ first. If multihost and no host filters set,
	 * we iterate over the entire glob_listener_tbl_ :(
	 */
	if (qryopt.has_filter() && critset.is_only_l1() && critset.is_l1_oper_or() && critset.has_subsystem(SUBSYS_SVCINFO, true /* match_all */)) {
		const auto 		& l1_grp = critset.l1_grp_;
		uint32_t		neval = 0;

		// First validate
		for (uint32_t i = 0; i < l1_grp.ncrit_; ++i) {
			const auto		pcrit = l1_grp.pcritarr_ + i;
			
			if (SUBSYS_SVCINFO != pcrit->get_subsys()) {
				neval = 0;
				break;
			}

			if (FIELD_SVCID != pcrit->get_field_crc()) {
				neval = 0;
				break;
			}	

			if (!((COMP_EQ == pcrit->get_comparator()) || (COMP_IN == pcrit->get_comparator()))) {
				neval = 0;
				break;
			}	

			if (false == pcrit->is_value_string() || true == pcrit->is_value_expression()) {
				neval = 0;
				break;
			}

			neval++;
		}	
	
		if (neval) {
			RCU_LOCK_SLOW			slowlock;

			PARTHA_INFO_ELEM		*pelem = nullptr;
			PARTHA_INFO			*prawpartha = nullptr;

			if (!is_multi_host) {
				pelem = partha_tbl_.lookup_single_elem_locked(qryopt.get_parid(), qryopt.get_parid().get_hash());
				
				if (pelem == nullptr) {
					GY_THROW_EXPR_CODE(ERR_DATA_NOT_FOUND, "Listener Info Query : Partha ID Specified not found or was deleted recently");
				}	
				prawpartha = pelem->get_cref().get();

				if (prawpartha == nullptr) {
					GY_THROW_EXPR_CODE(ERR_DATA_NOT_FOUND, "Listener Info Query : Partha ID Specified was deleted recently");
				}	
			}
			
			for (uint32_t i = 0; i < l1_grp.ncrit_; ++i) {
				const auto		pcrit = l1_grp.pcritarr_ + i;
				auto [pstrarr, nstr] 	= pcrit->get_str_values();

				if (!pstrarr) {
					continue;
				}	

				for (uint32_t i = 0; i < nstr; i++) {
					uint64_t			glob_id;
					int				ret;
					
					if (pstrarr[i].size() != 16) {
						continue;
					}	

					if (!string_to_number(pstrarr[i].get(), glob_id, nullptr, 16)) {
						continue;
					}	

					const uint32_t			lhash = get_uint64_hash(glob_id);
					MTCP_LISTENER_ELEM_TYPE		*plistelem;
					MTCP_LISTENER			*plistener;
				
					if (prawpartha) {
						plistelem = prawpartha->listen_tbl_.lookup_single_elem_locked(glob_id, lhash);
					}
					else {
						plistelem = glob_listener_tbl_.lookup_single_elem_locked(glob_id, lhash);
					}

					if (gy_unlikely(plistelem == nullptr)) {
						continue;
					}	
					
					plistener = plistelem->get_cref().get();

					if (gy_unlikely(plistener == nullptr)) {
						continue;
					}	

					sendsvc(*plistener, true /* check_filter */);

					if (nrecs >= maxrecs) {
						goto donesvc;
					}	
				}
			}	

donesvc:
			writer.EndArray();

			if (prawpartha) {
					
				writer.KeyConst("hostinfo");
				writer.StartObject();

				writer.KeyConst("parid");
				writer.String(prawpartha->machine_id_str_, sizeof(prawpartha->machine_id_str_) - 1);
				
				writer.KeyConst("host");
				writer.String(prawpartha->hostname_, GY_READ_ONCE(prawpartha->hostname_len_));

				writer.KeyConst("madid");
				writer.String(gmadhava_id_str_, 16);

				writer.KeyConst("cluster");
				writer.String(prawpartha->cluster_name_, GY_READ_ONCE(prawpartha->cluster_len_));

				writer.EndObject();
			}	

			goto done;
		}	
	}

	if (!is_multi_host) {

		const auto parlam = [&](PARTHA_INFO_ELEM *pelem, void *arg1, void *arg2) -> CB_RET_E
		{
			auto				prawpartha = pelem->get_cref().get();

			if (gy_unlikely(prawpartha == nullptr)) {
				return CB_OK;
			}	

			prawpartha->listen_tbl_.walk_hash_table_const(listl);

			writer.EndArray();
			
			writer.KeyConst("hostinfo");
			writer.StartObject();

			writer.KeyConst("parid");
			writer.String(prawpartha->machine_id_str_, sizeof(prawpartha->machine_id_str_) - 1);
			
			writer.KeyConst("host");
			writer.String(prawpartha->hostname_, GY_READ_ONCE(prawpartha->hostname_len_));

			writer.KeyConst("madid");
			writer.String(gmadhava_id_str_, 16);

			writer.KeyConst("cluster");
			writer.String(prawpartha->cluster_name_, GY_READ_ONCE(prawpartha->cluster_len_));

			writer.EndObject();

			return CB_OK;
		};	

		bret = partha_tbl_.lookup_single_elem(qryopt.get_parid(), qryopt.get_parid().get_hash(), parlam);
		
		if (bret == false) {
			GY_THROW_EXPR_CODE(ERR_DATA_NOT_FOUND, "Listener Info Query : Partha ID Specified not found or was deleted recently");
		}	

		goto done;
	}
	else if (critset.has_subsystem(SUBSYS_HOST)) {

		const auto lampar = [&](PARTHA_INFO_ELEM *pelem, void *arg) -> CB_RET_E
		{
			auto				prawpartha = pelem->get_cref().get();

			if (gy_unlikely(prawpartha == nullptr)) {
				return CB_OK;
			}	

			auto 			cret = HostFields(*prawpartha, gmadhava_id_str_).filter_match(critset);

			if (cret == CRIT_FAIL) {
				return CB_OK;
			}

			prawpartha->listen_tbl_.walk_hash_table_const(listl);
			
			if (nrecs >= maxrecs) {
				return CB_BREAK_LOOP;
			}	

			return CB_OK;
		};	

		partha_tbl_.walk_hash_table_const(lampar);

		writer.EndArray();
	}	
	else {
		// We need to scan the entire glob_listener_tbl_

		const auto lamsvc = [&](MTCP_LISTENER_ELEM_TYPE *pelem, void *arg) -> CB_RET_E
		{
			auto				plistener = pelem->get_cref().get();

			if (gy_unlikely(plistener == nullptr)) {
				return CB_OK;
			}	

			sendsvc(*plistener, true /* check_filter */);

			if (nrecs >= maxrecs) {
				return CB_BREAK_LOOP;
			}	

			return CB_OK;
		};	

		glob_listener_tbl_.walk_hash_table_const(lamsvc);

		writer.EndArray();
	}	

done :
	writer.EndObject();

	return true;
}

bool MCONN_HANDLER::web_db_listener_info(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Listener Info\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Service Info Query : Database Querying Error : Failed to get an idle connection. Please try later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	int				ret;
	bool				bret, origpointintime = qryopt.is_pointintime(), pointintime = origpointintime, multihost = qryopt.is_multi_host(), updqryopt = false;
	time_t				tcurr = time(nullptr);
	struct timeval			tvstart, tvend, origtvstart, origtvend;
	char				origstarttime[48], origendtime[48];
	
	GY_SCOPE_EXIT {
		if (updqryopt == true) {
			qryopt.set_timestamps(origstarttime, origendtime, origtvstart, origtvend, origpointintime);
		}
	};	

	tvstart = qryopt.get_start_timeval(); 
	tvend 	= qryopt.get_end_timeval();

	if (tvend.tv_sec - tvstart.tv_sec < (int64_t)INFO_DB_UPDATE_SEC) {
		origtvstart	= tvstart;
		origtvend	= tvend;
		GY_STRNCPY(origstarttime, qryopt.get_starttime(), sizeof(origstarttime));
		GY_STRNCPY(origendtime, qryopt.get_endtime(), sizeof(origendtime));
		updqryopt	= true;
		
		tvstart.tv_sec = tvend.tv_sec - INFO_DB_UPDATE_SEC;
		tvend.tv_sec += INFO_DB_UPDATE_SEC/3;
		qryopt.set_timestamps(gy_localtime_iso8601_sec(tvstart.tv_sec).get(), gy_localtime_iso8601_sec(tvend.tv_sec).get(), tvstart, tvend, true /* pointintime */);
	
		pointintime 	= true;
	}	

	auto 				datetbl = get_db_day_partition(tvstart.tv_sec, tvend.tv_sec, 0);

	const JSON_DB_MAPPING		*colarr[MAX_MULTI_HOST_COLUMN_LIST];
	
	auto [ncol, colspec] 		= qryopt.get_all_column_list(colarr, GY_ARRAY_SIZE(colarr), SUBSYS_SVCINFO);

	if (tcurr - db_storage_days_ * GY_SEC_PER_DAY > (uint64_t)tvend.tv_sec) {
		char			ebuf[256];
		size_t			esz;
		
		esz = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Listener Info Query : Time Requested not present in DB : Max Days of DB storage = %u", db_storage_days_);

		if (writer.get_stream()->reset_if_not_sent(ERR_DATA_NOT_FOUND)) {
			send_json_error_resp(connshr, ERR_DATA_NOT_FOUND, pquery->get_seqid(), ebuf, esz, pthrpoolarr);
		}

		return false;
	}	
	
	if (multihost) {
		STRING_BUFFER<48 * 1024>		strbuf;
		
		qryopt.get_db_select_multihost_query(strbuf, SUBSYS_SVCINFO, "listeninfotbl", datetbl.get());

		strbuf.appendconst(";\n reset search_path; ");

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}
	else {
		STRING_BUFFER<48 * 1024>	strbuf;
		char				tablename[128];

		snprintf(tablename, sizeof(tablename), "sch%s.listeninfotbl%s", qryopt.get_parid_str().get(), datetbl.get());

		qryopt.get_db_select_query(strbuf, SUBSYS_SVCINFO, tablename);

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}	

	if (bret == false) {
		constexpr const char errbuf[] = "Service Info Query : Failed to schedule query to Database. Please retry later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	writer.KeyConst("svcinfo");
	writer.StartArray();

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_json_cb(conn, std::move(gyres), is_completed, "Service Info", colarr, ncol, writer, total_rows, noextracolcb);
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
				constexpr const char errbuf[] = "Service Info Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Service Info Query : Database Connection Error. Please try later...";

				send_json_error_resp(connshr, ERR_SYSERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}	

			return false;
		}	

		writer.EndArray();
		writer.EndObject();
		
		return false;
	}	

	writer.EndArray();

	if (false == qryopt.is_multi_host()) {
		web_db_set_partha_hostinfo(writer, qryopt);
	}

	writer.EndObject();

	return true;
}

bool MCONN_HANDLER::web_db_aggr_listener_info(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Aggregated Service Info query\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Aggregated Service Info Query : Database Querying Error : Failed to get an idle connection. Please try later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	int				ret;
	bool				bret, updqryopt = false;
	time_t				tcurr = time(nullptr);
	struct timeval			tvstart, tvend, origtvstart, origtvend;
	char				origstarttime[48], origendtime[48];
	
	GY_SCOPE_EXIT {
		if (updqryopt == true) {
			qryopt.set_timestamps(origstarttime, origendtime, origtvstart, origtvend, false);
		}
	};	

	tvstart = qryopt.get_start_timeval(); 
	tvend 	= qryopt.get_end_timeval();

	if (tvend.tv_sec - tvstart.tv_sec < (int64_t)INFO_DB_UPDATE_SEC) {
		origtvstart	= tvstart;
		origtvend	= tvend;
		GY_STRNCPY(origstarttime, qryopt.get_starttime(), sizeof(origstarttime));
		GY_STRNCPY(origendtime, qryopt.get_endtime(), sizeof(origendtime));
		updqryopt	= true;
		
		tvstart.tv_sec = tvend.tv_sec - INFO_DB_UPDATE_SEC;
		tvend.tv_sec += INFO_DB_UPDATE_SEC/3;
		qryopt.set_timestamps(gy_localtime_iso8601_sec(tvstart.tv_sec).get(), gy_localtime_iso8601_sec(tvend.tv_sec).get(), tvstart, tvend, false /* pointintime */);
	}	

	if (tcurr - db_storage_days_ * GY_SEC_PER_DAY > (uint64_t)tvend.tv_sec) {
		char			ebuf[256];
		size_t			esz;
		
		esz = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Aggregated Service Info Query : Time Requested not present in DB : Max Days of DB storage = %u", db_storage_days_);

		if (writer.get_stream()->reset_if_not_sent(ERR_DATA_NOT_FOUND)) {
			send_json_error_resp(connshr, ERR_DATA_NOT_FOUND, pquery->get_seqid(), ebuf, esz, pthrpoolarr);
		}

		return false;
	}	
	
	auto 				datetbl = get_db_day_partition(tvstart.tv_sec, tvend.tv_sec, 0);

	const JSON_DB_MAPPING		*colarr[QUERY_OPTIONS::MAX_AGGR_COLUMNS];
	JSON_DB_MAPPING			acolarr[QUERY_OPTIONS::MAX_AGGR_COLUMNS];
	uint32_t			ncol;

	assert(gy_get_thread_local().get_thread_stack_freespace() >= 256 * 1024);

	if (true) {
		STRING_BUFFER<48 * 1024>		strbuf;
		
		ncol = get_svcinfo_aggr_query(strbuf, qryopt, datetbl.get(), acolarr);

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());

		if (bret == false) {
			constexpr const char errbuf[] = "Aggregated Service Info Query : Failed to schedule query to Database. Please retry later...";

			if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
				send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}

			return false;
		}	

		for (uint32_t i = 0; i < ncol; ++i) {
			colarr[i] = acolarr + i;
		}	
	}

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	writer.KeyConst("svcinfo");
	writer.StartArray();

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_json_cb(conn, std::move(gyres), is_completed, "Aggregated Service Info", colarr, ncol, writer, total_rows, noextracolcb);
		}
	);
	
	auto		expirysec = std::max<int64_t>(30, pquery->get_time_to_expiry(tcurr));

	ret = dbpool.wait_one_response(expirysec * 1000, pconn.getintconn());

	if (ret != 0) {
		if (ret == 2) {
			db_stats_.ndbquery_timeout_.fetch_add_relaxed(1);
		}

		if (writer.get_stream()->reset_if_not_sent(ret == 2 ? ERR_TIMED_OUT : ERR_SYSERROR)) {
			if (ret == 2) {
				constexpr const char errbuf[] = "Aggregated Service Info Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Aggregated Service Info Query : Database Connection Error. Please try later...";

				send_json_error_resp(connshr, ERR_SYSERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}	

			return false;
		}	

		writer.EndArray();
		writer.EndObject();

		return false;
	}	

	writer.EndArray();

	if (false == qryopt.is_multi_host()) {
		web_db_set_partha_hostinfo(writer, qryopt);
	}

	set_json_column_list(writer, colarr, ncol);

	writer.EndObject();

	return true;
}

bool MCONN_HANDLER::web_query_listener_info(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	bool					bret;

	try {
		if (false == qryopt.match_madhava_option(gmadhava_id_str_)) {
			// Skip this query
			writer.StartObject();	
	
			writer.KeyConst("madid");
			writer.String(gmadhava_id_str_, 16);

			writer.EndObject();

			return true;
		}

		if (!qryopt.is_historical()) {
			bret = web_curr_listener_info(connshr, qryopt, extpool, pquery, writer, pthrpoolarr);
		}
		else {
			if (false == qryopt.is_aggregated()) {
				bret = web_db_listener_info(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);
			}
			else {
				bret = web_db_aggr_listener_info(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);
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


CRIT_RET_E MCONN_HANDLER::top_listeners_filter_match(const CRITERIA_SET & criteria, const PARTHA_INFO & rawpartha, bool ignore_other_subsys) const
{
	/*
	 * Currently we only support Host filters for Top Listener querying
	 */
	auto 			cret = HostFields(rawpartha, gmadhava_id_str_).filter_match(criteria);

	return cret;
}	

bool MCONN_HANDLER::web_curr_top_listeners(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr)
{
	uint64_t			tcurrusec = get_usec_time(), min_tusec = tcurrusec - 6 * GY_USEC_PER_SEC;
	bool				bret, is_multi_host = qryopt.is_multi_host();
	bool				send_topissue = true, send_topqps = false, send_topactconn = false, send_topnet = false, send_summstats = false;

	const auto			*poptions = qryopt.get_options_json();

	qryopt.comp_criteria_init();

	if (poptions) {
		const auto	& optobj = poptions->GetObject();
		auto		miter = optobj.FindMember("send_topissue");

		if ((miter != optobj.MemberEnd()) && (miter->value.IsBool())) {
			send_topissue = miter->value.GetBool();
		}	
		
		miter = optobj.FindMember("send_topqps");

		if ((miter != optobj.MemberEnd()) && (miter->value.IsBool())) {
			send_topqps = miter->value.GetBool();
		}	

		miter = optobj.FindMember("send_topactconn");

		if ((miter != optobj.MemberEnd()) && (miter->value.IsBool())) {
			send_topactconn = miter->value.GetBool();
		}

		miter = optobj.FindMember("send_topnet");

		if ((miter != optobj.MemberEnd()) && (miter->value.IsBool())) {
			send_topnet = miter->value.GetBool();
		}

		miter = optobj.FindMember("send_summstats");

		if ((miter != optobj.MemberEnd()) && (miter->value.IsBool())) {
			send_summstats = miter->value.GetBool();

		}

		if (false == send_topissue && false == send_topqps && false == send_topactconn && false == send_topnet) {
			constexpr const char errbuf[] = "Top Listeners Query : Query requested with no valid Top criteria ...";

			if (writer.get_stream()->reset_if_not_sent(ERR_INVALID_REQUEST)) {
				send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}

			return false;
		}	
	}	
	
	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	const auto stream_top = [&](const LISTEN_TOPN & elem, const char *phostname, uint16_t lenhost, const char *pcluster, uint16_t lencluster, const char *pmachid)
	{
		const auto		& state = elem.state_;

		writer.StartObject();
		
		if (pmachid) {	
			writer.KeyConst("parid");
			writer.String(pmachid, 32);
		}
		
		if (phostname) {	
			writer.KeyConst("host");
			writer.String(phostname, lenhost);

			writer.KeyConst("madid");
			writer.String(gmadhava_id_str_, 16);
		}

		if (pcluster) {	
			writer.KeyConst("cluster");
			writer.String(pcluster, lencluster);
		}

		// svcstate fields follow

		writer.KeyConst("time");
		writer.String(gy_localtime_iso8601(elem.tusec_/GY_USEC_PER_SEC, CHAR_BUF<64>().get(), 64));	

		writer.KeyConst("svcid");
		writer.String(number_to_string(state.glob_id_, "%016lx").get(), 16);

		writer.KeyConst("name");
		writer.String(elem.comm_);

		writer.KeyConst("qps5s");
		writer.Uint(state.nqrys_5s_/5);

		writer.KeyConst("nqry5s");
		writer.Uint(state.nqrys_5s_);

		writer.KeyConst("resp5s");
		writer.Uint(state.total_resp_5sec_/(state.nqrys_5s_ ? state.nqrys_5s_ : 1));

		writer.KeyConst("p95resp5s");
		writer.Uint(state.p95_5s_resp_ms_);

		writer.KeyConst("p95resp5m");
		writer.Uint(state.p95_5min_resp_ms_);

		writer.KeyConst("nconns");
		writer.Uint(state.nconns_);

		writer.KeyConst("nactive");
		writer.Uint(state.nconns_active_);

		writer.KeyConst("nprocs");
		writer.Uint(state.ntasks_);

		writer.KeyConst("kbin15s");
		writer.Uint(state.curr_kbytes_inbound_);

		writer.KeyConst("kbout15s");
		writer.Uint(state.curr_kbytes_outbound_);

		writer.KeyConst("sererr");
		writer.Uint(state.ser_errors_);

		writer.KeyConst("clierr");
		writer.Uint(state.cli_errors_);

		writer.KeyConst("delayus");
		writer.Uint(state.tasks_delay_usec_);

		writer.KeyConst("cpudelus");
		writer.Uint(state.tasks_cpudelay_usec_);

		writer.KeyConst("iodelus");
		writer.Uint(state.tasks_blkiodelay_usec_);

		writer.KeyConst("vmdelus");
		writer.Uint(state.tasks_delay_usec_ - state.tasks_cpudelay_usec_ - state.tasks_blkiodelay_usec_);

		writer.KeyConst("usercpu");
		writer.Uint(state.tasks_user_cpu_);

		writer.KeyConst("syscpu");
		writer.Uint(state.tasks_sys_cpu_);

		writer.KeyConst("rssmb");
		writer.Uint(state.tasks_rss_mb_);

		writer.KeyConst("nissue");
		writer.Uint(state.ntasks_issue_);

		writer.KeyConst("state");
		writer.String(state_to_stringlen((OBJ_STATE_E)state.curr_state_));

		writer.KeyConst("issue");
		writer.Uint(state.curr_issue_);

		writer.KeyConst("ishttp");
		writer.Bool(state.is_http_svc_);

		writer.KeyConst("desc");
		writer.String(issue_to_string((LISTENER_ISSUE_SRC)state.curr_issue_));	// Since we do not store the original issue string for Top Listeners

		// Add extra fields
		writer.KeyConst("ip");
		writer.String(elem.ip_port_.ipaddr_.printaddr().get());

		writer.KeyConst("port");
		writer.Uint(elem.ip_port_.port_);

		writer.EndObject();
	};	

	if (is_multi_host) {
		using LISTEN_MULTI_TOP_VEC		= INLINE_STACK_VECTOR<LISTEN_MULTI_TOPN, sizeof(LISTEN_MULTI_TOPN) * MAX_MULTI_TOPN + 48>;

		using LISTEN_MULTI_TOP_ISSUE	 	= BOUNDED_PRIO_QUEUE<LISTEN_MULTI_TOPN, LISTEN_MULTI_TOPN::TOP_ISSUE, NULL_MUTEX, LISTEN_MULTI_TOP_VEC>;
		using LISTEN_MULTI_TOP_QPS 		= BOUNDED_PRIO_QUEUE<LISTEN_MULTI_TOPN, LISTEN_MULTI_TOPN::TOP_QPS, NULL_MUTEX, LISTEN_MULTI_TOP_VEC>;
		using LISTEN_MULTI_TOP_ACTIVE_CONN 	= BOUNDED_PRIO_QUEUE<LISTEN_MULTI_TOPN, LISTEN_MULTI_TOPN::TOP_ACTIVE_CONN, NULL_MUTEX, LISTEN_MULTI_TOP_VEC>;
		using LISTEN_MULTI_TOP_NET	 	= BOUNDED_PRIO_QUEUE<LISTEN_MULTI_TOPN, LISTEN_MULTI_TOPN::TOP_NET, NULL_MUTEX, LISTEN_MULTI_TOP_VEC>;

		assert(gy_get_thread_local().get_thread_stack_freespace() >= sizeof(LISTEN_MULTI_TOP_VEC) * 4 + 64 * 1024);

		LISTEN_MULTI_TOP_ISSUE			top_issue_listen		{MAX_MULTI_TOPN};
		LISTEN_MULTI_TOP_QPS			top_qps_listen			{MAX_MULTI_TOPN};	
		LISTEN_MULTI_TOP_ACTIVE_CONN		top_active_conn_listen		{MAX_MULTI_TOPN};	
		LISTEN_MULTI_TOP_NET			top_net_listen			{MAX_MULTI_TOPN};	

		LISTEN_SUMM_STATS<int64_t>		summstats;

		const char				*phostname = nullptr, *pcluster_name = nullptr, *pmachine_id_str = nullptr;
		const LISTEN_TOPN			*pone = nullptr;
		
		const auto compissue = [&](const LISTEN_MULTI_TOPN & elem) noexcept
		{
			return pone && LISTEN_TOPN::is_comp_issue(pone->state_, elem);
		};

		const auto compqps = [&](const LISTEN_MULTI_TOPN & elem) noexcept
		{
			return pone && LISTEN_TOPN::is_comp_qps(pone->state_, elem);
		};

		const auto compactiveconn = [&](const LISTEN_MULTI_TOPN & elem) noexcept
		{
			return pone && LISTEN_TOPN::is_comp_active_conn(pone->state_, elem);
		};

		const auto compnet = [&](const LISTEN_MULTI_TOPN & elem) noexcept
		{
			return pone && LISTEN_TOPN::is_comp_net(pone->state_, elem);
		};


		const auto walkissue = [&](const LISTEN_TOPN & elem, void * arg1, void * arg2) -> CB_RET_E
		{
			pone = &elem;

			if (phostname) {
				top_issue_listen.try_emplace_locked(compissue, phostname, pcluster_name, pmachine_id_str, elem);
			}

			return CB_OK;
		};	

		const auto walkqps = [&](const LISTEN_TOPN & elem, void * arg1, void * arg2) -> CB_RET_E
		{
			pone = &elem;

			if (phostname) {
				top_qps_listen.try_emplace_locked(compqps, phostname, pcluster_name, pmachine_id_str, elem);
			}

			return CB_OK;
		};	

		const auto walkactive = [&](const LISTEN_TOPN & elem, void * arg1, void * arg2) -> CB_RET_E
		{
			pone = &elem;

			if (phostname) {
				top_active_conn_listen.try_emplace_locked(compactiveconn, phostname, pcluster_name, pmachine_id_str, elem);
			}

			return CB_OK;
		};	

		const auto walknet = [&](const LISTEN_TOPN & elem, void * arg1, void * arg2) -> CB_RET_E
		{
			pone = &elem;

			if (phostname) {
				top_net_listen.try_emplace_locked(compnet, phostname, pcluster_name, pmachine_id_str, elem);
			}

			return CB_OK;
		};	

		const auto lampar = [&, send_topissue, send_topqps, send_topactconn, send_topnet, send_summstats, min_tusec](PARTHA_INFO_ELEM *pdatanode, void *arg1) -> CB_RET_E
		{
			auto				prawpartha = pdatanode->get_cref().get();
			bool				bret;

			if (gy_unlikely(prawpartha == nullptr)) {
				return CB_OK;
			}	

			if (GY_READ_ONCE(prawpartha->last_listen_state_tusec_) < min_tusec) {
				return CB_OK;
			}	

			if (qryopt.has_filter()) {
				auto cret = top_listeners_filter_match(qryopt.get_filter_criteria(), *prawpartha, true /* ignore_other_subsys */);

				if (cret == CRIT_FAIL) {
					return CB_OK;
				}
			}	

			// Use the top_issue_listen_ mutex for all top structs
			SCOPE_GY_MUTEX			topmutex(&prawpartha->top_issue_listen_.mutex_);

			phostname 	= prawpartha->hostname_;
			pcluster_name	= prawpartha->cluster_name_;
			pmachine_id_str	= prawpartha->machine_id_str_;

			if (send_topissue) { 
				prawpartha->top_issue_listen_.walk_queue_const(walkissue);
			}

			if (send_topqps) {
				prawpartha->top_qps_listen_.walk_queue_const(walkqps);
			}

			if (send_topactconn) {
				prawpartha->top_active_conn_listen_.walk_queue_const(walkactive);
			}

			if (send_topnet) {
				prawpartha->top_net_listen_.walk_queue_const(walknet);
			}

			if (send_summstats) {
				summstats.update(prawpartha->summstats_);
			}	

			topmutex.unlock();

			return CB_OK;
		};
				
		partha_tbl_.walk_hash_table_const(lampar);

		const auto wstream = [&](const LISTEN_MULTI_TOPN & elem, void * arg1, void * arg2) -> CB_RET_E
		{
			stream_top(elem, elem.hostname_, elem.lenhost_, elem.cluster_name_, elem.lencluster_, elem.machine_id_str_);
			return CB_OK;
		};	

		if (send_topissue) {
			writer.KeyConst("topissue");
			writer.StartArray();

			top_issue_listen.walk_queue(wstream, nullptr, nullptr, true /* sort_queue */, false /* heap_on_return */);

			writer.EndArray();
		}

		if (send_topqps) {
			writer.KeyConst("topqps");
			writer.StartArray();

			top_qps_listen.walk_queue(wstream, nullptr, nullptr, true /* sort_queue */, false /* heap_on_return */);

			writer.EndArray();
		}

		if (send_topactconn) {
			writer.KeyConst("topactconn");
			writer.StartArray();

			top_active_conn_listen.walk_queue(wstream, nullptr, nullptr, true /* sort_queue */, false /* heap_on_return */);

			writer.EndArray();
		}

		if (send_topnet) {
			writer.KeyConst("topnet");
			writer.StartArray();

			top_net_listen.walk_queue(wstream, nullptr, nullptr, true /* sort_queue */, false /* heap_on_return */);

			writer.EndArray();
		}

		if (send_summstats) {
			const auto			tvsec = tcurrusec/GY_USEC_PER_SEC;
			auto				timebuf = gy_localtime_iso8601_sec(tvsec);
			
			writer.KeyConst("summstats");

			send_listen_one_summ_stats(writer, summstats, timebuf.get());
		}	
	}	
	else {

		const auto wstream = [&](const LISTEN_TOPN & elem, void * arg1, void * arg2) -> CB_RET_E
		{
			stream_top(elem, nullptr, 0, nullptr, 0, nullptr);
			return CB_OK;
		};	

		const auto lampar = [&](PARTHA_INFO_ELEM *pdatanode, void *arg1, void *arg2) -> CB_RET_E
		{
			auto				prawpartha = pdatanode->get_cref().get();
			bool				bret;

			if (gy_unlikely(prawpartha == nullptr)) {
				return CB_OK;
			}	

			auto				tlastusec = GY_READ_ONCE(prawpartha->last_listen_state_tusec_);

			if (tlastusec < min_tusec) {
				GY_THROW_EXPR_CODE(ERR_DATA_NOT_FOUND, "Top Listeners Query : Partha Host %s has not updated its data recently", prawpartha->hostname_);
			}	

			// Use the top_issue_listen_ mutex for all top structs
			SCOPE_GY_MUTEX			topmutex(&prawpartha->top_issue_listen_.mutex_);

			// Copy locally
			std::optional<LISTEN_TOP_ISSUE>		top_issue;
			std::optional<LISTEN_TOP_QPS>		top_qps;
			std::optional<LISTEN_TOP_ACTIVE_CONN>	top_active_conn;
			std::optional<LISTEN_TOP_NET>		top_net;

			auto					summstats = prawpartha->summstats_;	// Copy

			if (send_topissue) {
				top_issue.emplace(prawpartha->top_issue_listen_);
			}

			if (send_topqps) {
				top_qps.emplace(prawpartha->top_qps_listen_);
			}	

			if (send_topactconn) {
				top_active_conn.emplace(prawpartha->top_active_conn_listen_);
			}	

			if (send_topnet) {
				top_net.emplace(prawpartha->top_net_listen_);
			}	

			topmutex.unlock();

			if (send_topissue) {
				writer.KeyConst("topissue");
				writer.StartArray();

				top_issue->walk_queue(wstream, nullptr, nullptr, true /* sort_queue */, false /* heap_on_return */);

				writer.EndArray();
			}

			if (send_topqps) {
				writer.KeyConst("topqps");
				writer.StartArray();

				top_qps->walk_queue(wstream, nullptr, nullptr, true /* sort_queue */, false /* heap_on_return */);

				writer.EndArray();
			}

			if (send_topactconn) {
				writer.KeyConst("topactconn");
				writer.StartArray();

				top_active_conn->walk_queue(wstream, nullptr, nullptr, true /* sort_queue */, false /* heap_on_return */);

				writer.EndArray();
			}

			if (send_topnet) {
				writer.KeyConst("topnet");
				writer.StartArray();

				top_net->walk_queue(wstream, nullptr, nullptr, true /* sort_queue */, false /* heap_on_return */);

				writer.EndArray();
			}


			if (send_summstats) {
				const auto			tvsec = tlastusec/GY_USEC_PER_SEC;
				auto				timebuf = gy_localtime_iso8601_sec(tvsec);
			
				writer.KeyConst("summstats");

				send_listen_one_summ_stats(writer, summstats, timebuf.get());
			}	

			writer.KeyConst("hostinfo");
			writer.StartObject();

			writer.KeyConst("parid");
			writer.String(prawpartha->machine_id_str_, sizeof(prawpartha->machine_id_str_) - 1);
			
			writer.KeyConst("host");
			writer.String(prawpartha->hostname_, GY_READ_ONCE(prawpartha->hostname_len_));

			writer.KeyConst("madid");
			writer.String(gmadhava_id_str_, 16);

			writer.KeyConst("cluster");
			writer.String(prawpartha->cluster_name_, GY_READ_ONCE(prawpartha->cluster_len_));

			writer.EndObject();

			return CB_OK;
		};
				
		bret = partha_tbl_.lookup_single_elem(qryopt.get_parid(), qryopt.get_parid().get_hash(), lampar);
		
		if (bret == false) {
			GY_THROW_EXPR_CODE(ERR_DATA_NOT_FOUND, "Partha Top Listeners Query : Partha ID Specified not found or was deleted recently");
		}	
	}	
	
	writer.EndObject();

	return true;
}


bool MCONN_HANDLER::web_db_top_listeners(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Top Listeners query\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Top Listeners Query : Database Querying Error : Failed to get an idle connection. Please try later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	int				ret;
	bool				bret;
	time_t				tcurr = time(nullptr);
	struct timeval			tvstart = qryopt.get_start_timeval(), tvend = qryopt.get_end_timeval();

	if (false == qryopt.is_pointintime() && qryopt.is_multi_host()) {
		constexpr const char errbuf[] = "Top Listeners Query : Query requested for a time range for Multiple hosts instead of a Point in time. Currently not supported...";

		if (writer.get_stream()->reset_if_not_sent(ERR_INVALID_REQUEST)) {
			send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}

	if (tcurr - db_storage_days_ * GY_SEC_PER_DAY > (uint64_t)tvend.tv_sec) {
		char			ebuf[256];
		size_t			esz;
		
		esz = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Top Listeners Query : Time Requested not present in DB : Max Days of DB storage = %u", db_storage_days_);

		if (writer.get_stream()->reset_if_not_sent(ERR_DATA_NOT_FOUND)) {
			send_json_error_resp(connshr, ERR_DATA_NOT_FOUND, pquery->get_seqid(), ebuf, esz, pthrpoolarr);
		}

		return false;
	}	
	
	const JSON_DB_MAPPING		*colarr[GY_ARRAY_SIZE(json_db_svcstate_arr) + GY_ARRAY_SIZE(json_db_host_arr) + 4];
	const JSON_DB_MAPPING		*summcolarr[GY_ARRAY_SIZE(json_db_svcsumm_arr)];
	size_t				ncol, nsummcol;

	auto 				datetbl = get_db_day_partition(tvstart.tv_sec, tvend.tv_sec, 0);
	bool				send_topissue = true, send_topqps = false, send_topactconn = false, send_topnet = false, send_summstats = false;

	const auto			*poptions = qryopt.get_options_json();

	if (poptions) {
		const auto	& optobj = poptions->GetObject();
		auto		miter = optobj.FindMember("send_topissue");

		if ((miter != optobj.MemberEnd()) && (miter->value.IsBool())) {
			send_topissue = miter->value.GetBool();
		}	
		
		miter = optobj.FindMember("send_topqps");

		if ((miter != optobj.MemberEnd()) && (miter->value.IsBool())) {
			send_topqps = miter->value.GetBool();
		}	

		miter = optobj.FindMember("send_topactconn");

		if ((miter != optobj.MemberEnd()) && (miter->value.IsBool())) {
			send_topactconn = miter->value.GetBool();
		}

		miter = optobj.FindMember("send_topnet");

		if ((miter != optobj.MemberEnd()) && (miter->value.IsBool())) {
			send_topnet = miter->value.GetBool();
		}

		miter = optobj.FindMember("send_summstats");

		if ((miter != optobj.MemberEnd()) && (miter->value.IsBool())) {
			send_summstats = miter->value.GetBool();

		}

		if (false == send_topissue && false == send_topqps && false == send_topactconn && false == send_topnet) {
			constexpr const char errbuf[] = "Top Listeners Query : Query requested with no valid Top criteria ...";

			if (writer.get_stream()->reset_if_not_sent(ERR_INVALID_REQUEST)) {
				send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}

			return false;
		}	
	}	
	
	auto 		p = qryopt.get_all_column_list(colarr, GY_ARRAY_SIZE(colarr), SUBSYS_SVCSTATE);
	ncol 		= p.first;

	if (ncol + 2 < GY_ARRAY_SIZE(colarr)) {
		auto		pcolip = get_jsoncrc_mapping(FIELD_IP, json_db_svcinfo_arr, GY_ARRAY_SIZE(json_db_svcinfo_arr));
		auto		pcolport = get_jsoncrc_mapping(FIELD_PORT, json_db_svcinfo_arr, GY_ARRAY_SIZE(json_db_svcinfo_arr));

		if (!pcolip || !pcolport) {
			constexpr const char errbuf[] = "Top Listeners Query : Internal Error : IP and Port column definitions not found";

			send_json_error_resp(connshr, ERR_SERV_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			return false;
		}	 
		
		colarr[ncol++] = pcolip;
		colarr[ncol++] = pcolport;
	}	

	if (send_summstats) {
		auto p 		= qryopt.get_column_list(summcolarr, GY_ARRAY_SIZE(summcolarr), SUBSYS_SVCSUMM);
		nsummcol 	= p.first;
	}	
	else {
		nsummcol	= 0;
	}	

	if (qryopt.is_multi_host()) {
		STRING_BUFFER<48 * 1024>		strbuf;
		
		if (send_topissue) {
			strbuf.appendconst("select \'topissue\'::text as separator_topissue;");
			get_db_multihost_top_listeners_query(strbuf, qryopt, datetbl.get(), TOP_LISTEN_ISSUE);
			strbuf.appendconst("select \'completed\'::text as separator;");
		}

		if (send_topqps) {
			strbuf.appendconst("\nselect \'topqps\'::text as separator_topqps;");
			get_db_multihost_top_listeners_query(strbuf, qryopt, datetbl.get(), TOP_LISTEN_QPS);
			strbuf.appendconst("select \'completed\'::text as separator;");
		}

		if (send_topactconn) {
			strbuf.appendconst("\nselect \'topactconn\'::text as separator_topactconn;");
			get_db_multihost_top_listeners_query(strbuf, qryopt, datetbl.get(), TOP_LISTEN_ACTIVE_CONN);
			strbuf.appendconst("select \'completed\'::text as separator;");
		}

		if (send_topnet) {
			strbuf.appendconst("\nselect \'topnet\'::text as separator_topnet;");
			get_db_multihost_top_listeners_query(strbuf, qryopt, datetbl.get(), TOP_LISTEN_NET);
			strbuf.appendconst("select \'completed\'::text as separator;");
		}

		if (send_summstats) {
			strbuf.appendconst("\nselect \'summstats\'::text as separator_summstats;");
			get_db_listen_summ_stats_query(strbuf, qryopt, datetbl.get(), true /* ign_col_list */);
			strbuf.appendconst(";select \'completed\'::text as separator;");
		}

		strbuf.appendconst("\n reset search_path; \n");

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}
	else {
		STRING_BUFFER<48 * 1024>	strbuf;

		if (send_topissue) {
			strbuf.appendconst("select \'topissue\'::text as separator_topissue;");
			get_db_top_listeners_query(strbuf, qryopt, datetbl.get(), TOP_LISTEN_ISSUE);
			strbuf.appendconst("select \'completed\'::text as separator;");
		}

		if (send_topqps) {
			strbuf.appendconst("\nselect \'topqps\'::text as separator_topqps;");
			get_db_top_listeners_query(strbuf, qryopt, datetbl.get(), TOP_LISTEN_QPS);
			strbuf.appendconst("select \'completed\'::text as separator;");
		}

		if (send_topactconn) {
			strbuf.appendconst("\nselect \'topactconn\'::text as separator_topactconn;");
			get_db_top_listeners_query(strbuf, qryopt, datetbl.get(), TOP_LISTEN_ACTIVE_CONN);
			strbuf.appendconst("select \'completed\'::text as separator;");
		}

		if (send_topnet) {
			strbuf.appendconst("\nselect \'topnet\'::text as separator_topnet;");
			get_db_top_listeners_query(strbuf, qryopt, datetbl.get(), TOP_LISTEN_NET);
			strbuf.appendconst("select \'completed\'::text as separator;");
		}

		if (send_summstats) {
			strbuf.appendconst("\nselect \'summstats\'::text as separator_summstats;");
			get_db_listen_summ_stats_query(strbuf, qryopt, datetbl.get(), true /* ign_col_list */);
			strbuf.appendconst("; select \'completed\'::text as separator;");
		}

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}	

	if (bret == false) {
		constexpr const char errbuf[] = "Top Listeners Query : Failed to schedule query to Database. Please retry later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, total_rows = 0, ncol, nsummcol, ntotcol = 0, pcolarr = (const JSON_DB_MAPPING **)nullptr](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			if (is_completed) {
				conn.make_available();
				return true;
			}	
			
			if (true == gyres.is_error()) {
				DEBUGEXECN(10,
					WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to query Top Listeners from DB due to %s (Total tuples returned so far %d)\n", 
							gyres.get_error_msg(), total_rows);
				);

				if (0 == strcmp(gyres.get_sqlcode(), "42P01")) {
					GY_THROW_EXPR_CODE(ERR_DATA_NOT_FOUND, "Failed to query Top Listeners from DB for the time range specified as no data present");
				}	

				GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "Failed to query Top Listeners from DB due to %s", gyres.get_error_msg());
			}	

			char				tbuf[512];
			const PGresult *		pres = gyres.get();
			const int			nfields = PQnfields(pres);
			const int			ntuples = PQntuples(gyres.get());

			if (nfields == 1 && ntuples == 1) {
				const char	*pfname = PQfname(pres, 0);

				if (!pfname) {
					return false;
				}	
				
				if (0 == strncmp(pfname, "separator_", GY_CONST_STRLEN("separator_"))) {
					const char 		*pkey = pfname + GY_CONST_STRLEN("separator_");

					writer.Key(pkey);

					if (0 == strcmp(pkey, "summstats")) {
						pcolarr = summcolarr;
						ntotcol = nsummcol;

						writer.StartObject();
					}
					else {
						pcolarr = colarr;
						ntotcol = ncol;
					
						writer.StartArray();
					}	
					total_rows = 0;

					return true;
				}	
				else if (0 == strcmp(pfname, "separator")) {
					if (pcolarr && pcolarr != summcolarr) {
						writer.EndArray();
					}
					else if (pcolarr == summcolarr) {
						writer.EndObject();
					}	

					pcolarr = nullptr;
					ntotcol = 0;
					return true;
				}	
			}	

			if (ntuples > 0) {
				if (pcolarr == nullptr) {
					GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "Top Listeners DB Response Internal issue : Separator not sent by DB");
				}

				if ((unsigned)nfields > (unsigned)ntotcol) {
					GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "Invalid DB Column count seen for Top Listener query : %d instead of %d", nfields, ntotcol);
				}	
			}	

			for (int row = 0; row < ntuples; ++row) {
				if (pcolarr != summcolarr) {
					writer.StartObject();
				}

				for (int col = 0; col < nfields; ++col) {
					const char	*pfname = PQfname(pres, col);

					if (!pfname) {
						break;
					}	

					if (total_rows == 0) {
						// Validate schema
						if (strcmp(pfname, pcolarr[col]->dbcolname)) {
							GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "Invalid DB Column name seen for Top Listener query : %s instead of %s", 
								pfname, pcolarr[col]->dbcolname);
						}	

						if ((pcolarr[col]->dbstrtype == DB_STR_OCHAR) && (PG_BPCHAROID != PQftype(pres, col))) {
							GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "Invalid DB Column type seen for Top Listener query : %d instead of %d", 
								PQftype(pres, col), PG_BPCHAROID);
						}	
					}	

					if (pcolarr[col]->szjson == 0) {
						// Ignore this field
						continue;
					}	

					const char 		*pdata;
					int			len = PQgetlength(pres, row, col), rlen;

					if (len == 0) {
						pdata = "";

						if (true == PQgetisnull(pres, row, col)) {
							if (pcolarr[col]->jsontype == JSON_NUMBER) {
								pdata = "0";
								len = 1;
							}	
							else if (pcolarr[col]->jsontype == JSON_BOOL) {
								pdata = "false";
								len = 5;
							}	
						}	
					}
					else {
						pdata = PQgetvalue(pres, row, col);
					}

					if (pcolarr[col]->dbstrtype == DB_STR_OCHAR) {
						rlen = get_rtrim_len(pdata, len);
					}
					else {
						rlen = len;
					}	

					if (pcolarr[col]->dboper) {
						auto p = pcolarr[col]->dboper(pdata, rlen, tbuf, sizeof(tbuf));

						pdata = p.first;
						rlen = p.second;
					}	
					
					writer.Key(pcolarr[col]->jsonfield, pcolarr[col]->szjson);

					if ((pcolarr[col]->jsontype != JSON_STRING) || (pcolarr[col]->dbstrtype == DB_RAW_STRING)) {
						writer.RawValue(pdata, rlen, rapidjson::kNumberType);
					}
					else {
						writer.String(pdata, rlen);
					}	
				}	

				if (pcolarr != summcolarr) {
					writer.EndObject();
				}

				total_rows++;
			}	

			return true;
		}
	);
	
	auto		expirysec = std::max<int64_t>(30, pquery->get_time_to_expiry(tcurr));

	ret = dbpool.wait_one_response(expirysec * 1000, pconn.getintconn());

	if (ret != 0) {
		if (ret == 2) {
			db_stats_.ndbquery_timeout_.fetch_add_relaxed(1);
		}

		if (writer.get_stream()->reset_if_not_sent(ret == 2 ? ERR_TIMED_OUT : ERR_SYSERROR)) {
			if (ret == 2) {
				constexpr const char errbuf[] = "Top Listener Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Top Listener Query : Database Connection Error. Please try later...";

				send_json_error_resp(connshr, ERR_SYSERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}	

			return false;
		}	

		writer.EndObject();

		return false;
	}	

	if (false == qryopt.is_multi_host()) {
		web_db_set_partha_hostinfo(writer, qryopt);
	}

	writer.EndObject();

	return true;
}	

bool MCONN_HANDLER::web_query_top_listeners(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	bool					bret;

	try {
		if (false == qryopt.match_madhava_option(gmadhava_id_str_)) {
			// Skip this query
			writer.StartObject();	
	
			writer.KeyConst("madid");
			writer.String(gmadhava_id_str_, 16);

			writer.EndObject();

			return true;
		}

		if (!qryopt.is_historical()) {
			bret = web_curr_top_listeners(connshr, qryopt, extpool, pquery, writer, pthrpoolarr);
		}
		else {
			bret = web_db_top_listeners(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);
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


bool MCONN_HANDLER::web_db_detail_active_conn(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool, bool is_extended)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Active Conn query\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Active Conn query : Database Querying Error : Failed to get an idle connection. Please try later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	int				ret;
	bool				bret, origpointintime = qryopt.is_pointintime(), pointintime = origpointintime, multihost = qryopt.is_multi_host(), updqryopt = false;
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

		tvstart.tv_sec 	= tcurr - 25;
		tvstart.tv_usec = 0;

		tvend.tv_sec	= tcurr + 1;
		tvend.tv_usec	= 0;
		
		pointintime 	= true;

		qryopt.set_timestamps(gy_localtime_iso8601_sec(tvstart.tv_sec).get(), gy_localtime_iso8601_sec(tvend.tv_sec).get(), tvstart, tvend, true /* pointintime */);
	}	
	else {
		tvstart = qryopt.get_start_timeval(); 
		tvend 	= qryopt.get_end_timeval();

		if (tvend.tv_sec - tvstart.tv_sec < 25) {
			origtvstart	= tvstart;
			origtvend	= tvend;
			GY_STRNCPY(origstarttime, qryopt.get_starttime(), sizeof(origstarttime));
			GY_STRNCPY(origendtime, qryopt.get_endtime(), sizeof(origendtime));
			updqryopt	= true;
			
			tvstart.tv_sec = tvend.tv_sec - 25;
			qryopt.set_timestamps(gy_localtime_iso8601_sec(tvstart.tv_sec).get(), gy_localtime_iso8601_sec(tvend.tv_sec).get(), tvstart, tvend, true /* pointintime */);
		
			pointintime 	= true;
		}	
	}

	SUBSYS_CLASS_E			subsys = (false == is_extended ? SUBSYS_ACTIVECONN : SUBSYS_EXTACTIVECONN);
	const char			*acttbl = (false == is_extended ? "activeconntbl" : "extactiveconntbl");

	auto 				datetbl = get_db_day_partition(tvstart.tv_sec, tvend.tv_sec, 0);

	const JSON_DB_MAPPING		*colarr[MAX_MULTI_HOST_COLUMN_LIST];
	
	auto [ncol, colspec] 		= qryopt.get_all_column_list(colarr, GY_ARRAY_SIZE(colarr), subsys);

	if (tcurr - db_storage_days_ * GY_SEC_PER_DAY > (uint64_t)tvend.tv_sec) {
		char			ebuf[256];
		size_t			esz;
		
		esz = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Active Conn Query : Time Requested not present in DB : Max Days of DB storage = %u", db_storage_days_);

		if (writer.get_stream()->reset_if_not_sent(ERR_DATA_NOT_FOUND)) {
			send_json_error_resp(connshr, ERR_DATA_NOT_FOUND, pquery->get_seqid(), ebuf, esz, pthrpoolarr);
		}

		return false;
	}	
	

	if (multihost) {
		STRING_BUFFER<48 * 1024>		strbuf;
		
		qryopt.get_db_select_multihost_query(strbuf, subsys, acttbl, datetbl.get());

		strbuf.appendconst(";\n reset search_path; ");

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}
	else {
		STRING_BUFFER<48 * 1024>	strbuf;
		char				tablename[128];

		snprintf(tablename, sizeof(tablename), "sch%s.%s%s", qryopt.get_parid_str().get(), acttbl, datetbl.get());

		qryopt.get_db_select_query(strbuf, subsys, tablename);

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}	

	if (bret == false) {
		constexpr const char errbuf[] = "Active Conn Query : Failed to schedule query to Database. Please retry later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	if (!is_extended) {
		writer.KeyConst("activeconn");
	}
	else {
		writer.KeyConst("extactiveconn");
	}	
	writer.StartArray();

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_json_cb(conn, std::move(gyres), is_completed, "Active Conn", colarr, ncol, writer, total_rows, noextracolcb);
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
				constexpr const char errbuf[] = "Active Conn Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Active Conn Query : Database Connection Error. Please try later...";

				send_json_error_resp(connshr, ERR_SYSERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}	

			return false;
		}	

		writer.EndArray();
		writer.EndObject();
		
		return false;
	}	

	writer.EndArray();

	if (false == qryopt.is_multi_host()) {
		web_db_set_partha_hostinfo(writer, qryopt);
	}

	writer.EndObject();

	return true;
}	


bool MCONN_HANDLER::web_db_aggr_active_conn(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool, bool is_extended)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Aggregated Active Conns\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Aggregated Active Conns Query : Database Querying Error : Failed to get an idle connection. Please try later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	int				ret;
	bool				bret, updqryopt = false;
	time_t				tcurr = time(nullptr);
	struct timeval			tvstart = qryopt.get_start_timeval(), tvend = qryopt.get_end_timeval(), origtvstart, origtvend;
	char				origstarttime[48], origendtime[48];

	GY_SCOPE_EXIT {
		if (updqryopt == true) {
			qryopt.set_timestamps(origstarttime, origendtime, origtvstart, origtvend, false);
		}
	};	

	if (tvend.tv_sec - tvstart.tv_sec < 25) {
		origtvstart	= tvstart;
		origtvend	= tvend;
		GY_STRNCPY(origstarttime, qryopt.get_starttime(), sizeof(origstarttime));
		GY_STRNCPY(origendtime, qryopt.get_endtime(), sizeof(origendtime));
		updqryopt	= true;
		
		tvstart.tv_sec = tvend.tv_sec - 25;
		qryopt.set_timestamps(gy_localtime_iso8601_sec(tvstart.tv_sec).get(), gy_localtime_iso8601_sec(tvend.tv_sec).get(), tvstart, tvend, false /* pointintime */);
	}	

	if (tcurr - db_storage_days_ * GY_SEC_PER_DAY > (uint64_t)tvend.tv_sec) {
		char			ebuf[256];
		size_t			esz;
		
		esz = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Aggregated Active Conns Query : Time Requested not present in DB : Max Days of DB storage = %u", db_storage_days_);

		if (writer.get_stream()->reset_if_not_sent(ERR_DATA_NOT_FOUND)) {
			send_json_error_resp(connshr, ERR_DATA_NOT_FOUND, pquery->get_seqid(), ebuf, esz, pthrpoolarr);
		}

		return false;
	}	

	auto 				datetbl = get_db_day_partition(tvstart.tv_sec, tvend.tv_sec, 0);

	const JSON_DB_MAPPING		*colarr[QUERY_OPTIONS::MAX_AGGR_COLUMNS];
	JSON_DB_MAPPING			acolarr[QUERY_OPTIONS::MAX_AGGR_COLUMNS];
	uint32_t			ncol;

	assert(gy_get_thread_local().get_thread_stack_freespace() >= 256 * 1024);

	if (true) {
		STRING_BUFFER<48 * 1024>		strbuf;

		ncol = get_activeconn_aggr_query(strbuf, qryopt, datetbl.get(), acolarr, nullptr, is_extended);

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());

		if (bret == false) {
			constexpr const char errbuf[] = "Aggregated Active Conns Query : Failed to schedule query to Database. Please retry later...";

			if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
				send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}

			return false;
		}	

		for (uint32_t i = 0; i < ncol; ++i) {
			colarr[i] = acolarr + i;
		}	
	}

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	if (is_extended) {
		writer.KeyConst("extactiveconn");
	}
	else {
		writer.KeyConst("activeconn");
	}	
	writer.StartArray();

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, this, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_json_cb(conn, std::move(gyres), is_completed, "Aggregated Active Conn", colarr, ncol, writer, total_rows, noextracolcb);
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
				constexpr const char errbuf[] = "Aggregated Active Conns Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Aggregated Active Conns Query : Database Connection Error. Please try later...";

				send_json_error_resp(connshr, ERR_SYSERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}	

			return false;
		}	

		writer.EndArray();
		writer.EndObject();
		
		return false;
	}	

	writer.EndArray();

	if (false == qryopt.is_multi_host()) {
		web_db_set_partha_hostinfo(writer, qryopt);
	}

	set_json_column_list(writer, colarr, ncol);

	writer.EndObject();

	return true;
}


bool MCONN_HANDLER::web_query_active_conn(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool, bool is_extended)
{
	bool				bret, is_aggregated = qryopt.is_aggregated();

	try {
		if (false == qryopt.match_madhava_option(gmadhava_id_str_)) {
			// Skip this query
			writer.StartObject();	
	
			writer.KeyConst("madid");
			writer.String(gmadhava_id_str_, 16);

			writer.EndObject();

			return true;
		}

		if (false == is_aggregated) {
			bret = web_db_detail_active_conn(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool, is_extended);
		}
		else {
			bret = web_db_aggr_active_conn(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool, is_extended);
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

bool MCONN_HANDLER::web_db_detail_client_conn(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool, bool is_extended)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Client Conn query\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Client Conn query : Database Querying Error : Failed to get an idle connection. Please try later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	int				ret;
	bool				bret, origpointintime = qryopt.is_pointintime(), pointintime = origpointintime, updqryopt = false, onlyremote = false;
	time_t				tcurr = time(nullptr);
	struct timeval			tvstart, tvend, origtvstart, origtvend;
	char				origstarttime[48], origendtime[48];
	const auto			*poptions = qryopt.get_options_json();

	if (poptions) {
		const auto	& optobj = poptions->GetObject();
		auto		miter = optobj.FindMember("onlyremote");

		if ((miter != optobj.MemberEnd()) && (miter->value.IsBool())) {
			onlyremote = miter->value.GetBool();

			if (is_extended && onlyremote) {
				constexpr const char errbuf[] = "Extended Client Conn query : Only Remote Connections requested. Currently Extended Query support for only remote conns not available...";

				if (writer.get_stream()->reset_if_not_sent(ERR_INVALID_REQUEST)) {
					send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
				}

				return false;
			}	
		}	
	}	

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

		tvstart.tv_sec 	= tcurr - 25;
		tvstart.tv_usec = 0;

		tvend.tv_sec	= tcurr + 1;
		tvend.tv_usec	= 0;
		
		pointintime 	= true;

		qryopt.set_timestamps(gy_localtime_iso8601_sec(tvstart.tv_sec).get(), gy_localtime_iso8601_sec(tvend.tv_sec).get(), tvstart, tvend, true /* pointintime */);
	}	
	else {
		tvstart = qryopt.get_start_timeval(); 
		tvend 	= qryopt.get_end_timeval();

		if (tvend.tv_sec - tvstart.tv_sec < 25) {
			origtvstart	= tvstart;
			origtvend	= tvend;
			GY_STRNCPY(origstarttime, qryopt.get_starttime(), sizeof(origstarttime));
			GY_STRNCPY(origendtime, qryopt.get_endtime(), sizeof(origendtime));
			updqryopt	= true;
			
			tvstart.tv_sec = tvend.tv_sec - 25;
			qryopt.set_timestamps(gy_localtime_iso8601_sec(tvstart.tv_sec).get(), gy_localtime_iso8601_sec(tvend.tv_sec).get(), tvstart, tvend, true /* pointintime */);
		
			pointintime 	= true;
		}	
	}

	SUBSYS_CLASS_E			subsys = (is_extended ? SUBSYS_EXTCLIENTCONN : SUBSYS_CLIENTCONN);
	const char			*clitbl = (is_extended ? "extclientconntbl" : onlyremote ? "remoteconntbl" : "clientconntbl");

	auto 				datetbl = get_db_day_partition(tvstart.tv_sec, tvend.tv_sec, 0);

	const JSON_DB_MAPPING		*colarr[MAX_MULTI_HOST_COLUMN_LIST];
	
	auto [ncol, colspec] 		= qryopt.get_all_column_list(colarr, GY_ARRAY_SIZE(colarr), subsys);

	if (tcurr - db_storage_days_ * GY_SEC_PER_DAY > (uint64_t)tvend.tv_sec) {
		char			ebuf[256];
		size_t			esz;
		
		esz = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Client Conn Query : Time Requested not present in DB : Max Days of DB storage = %u", db_storage_days_);

		if (writer.get_stream()->reset_if_not_sent(ERR_DATA_NOT_FOUND)) {
			send_json_error_resp(connshr, ERR_DATA_NOT_FOUND, pquery->get_seqid(), ebuf, esz, pthrpoolarr);
		}

		return false;
	}	
	
	if (qryopt.is_multi_host()) {
		STRING_BUFFER<48 * 1024>		strbuf;
		
		qryopt.get_db_select_multihost_query(strbuf, subsys, clitbl, datetbl.get());

		strbuf.appendconst(";\n reset search_path; ");

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}
	else {
		STRING_BUFFER<48 * 1024>	strbuf;
		char				tablename[128];

		snprintf(tablename, sizeof(tablename), "sch%s.%s%s", qryopt.get_parid_str().get(), clitbl, datetbl.get());

		qryopt.get_db_select_query(strbuf, subsys, tablename);

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}	

	if (bret == false) {
		constexpr const char errbuf[] = "Client Conn Query : Failed to schedule query to Database. Please retry later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	if (!is_extended) {
		writer.KeyConst("clientconn");
	}
	else {
		writer.KeyConst("extclientconn");
	}	
	writer.StartArray();

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_json_cb(conn, std::move(gyres), is_completed, "Client Conn", colarr, ncol, writer, total_rows, noextracolcb);
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
				constexpr const char errbuf[] = "Client Conn Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Client Conn Query : Database Connection Error. Please try later...";

				send_json_error_resp(connshr, ERR_SYSERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}	

			return false;
		}	

		writer.EndArray();
		writer.EndObject();
		
		return false;
	}	

	writer.EndArray();

	if (false == qryopt.is_multi_host()) {
		web_db_set_partha_hostinfo(writer, qryopt);
	}

	writer.EndObject();

	return true;
}	


bool MCONN_HANDLER::web_db_aggr_client_conn(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool, bool is_extended)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Aggregated Client Conns\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Aggregated Client Conns Query : Database Querying Error : Failed to get an idle connection. Please try later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	int				ret;
	bool				bret, updqryopt = false;
	time_t				tcurr = time(nullptr);
	struct timeval			tvstart = qryopt.get_start_timeval(), tvend = qryopt.get_end_timeval(), origtvstart, origtvend;
	char				origstarttime[48], origendtime[48];

	GY_SCOPE_EXIT {
		if (updqryopt == true) {
			qryopt.set_timestamps(origstarttime, origendtime, origtvstart, origtvend, false);
		}
	};	

	if (tvend.tv_sec - tvstart.tv_sec < 25) {
		origtvstart	= tvstart;
		origtvend	= tvend;
		GY_STRNCPY(origstarttime, qryopt.get_starttime(), sizeof(origstarttime));
		GY_STRNCPY(origendtime, qryopt.get_endtime(), sizeof(origendtime));
		updqryopt	= true;
		
		tvstart.tv_sec = tvend.tv_sec - 25;
		qryopt.set_timestamps(gy_localtime_iso8601_sec(tvstart.tv_sec).get(), gy_localtime_iso8601_sec(tvend.tv_sec).get(), tvstart, tvend, false /* pointintime */);
	}	

	if (tcurr - db_storage_days_ * GY_SEC_PER_DAY > (uint64_t)tvend.tv_sec) {
		char			ebuf[256];
		size_t			esz;
		
		esz = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Aggregated Client Conns Query : Time Requested not present in DB : Max Days of DB storage = %u", db_storage_days_);

		if (writer.get_stream()->reset_if_not_sent(ERR_DATA_NOT_FOUND)) {
			send_json_error_resp(connshr, ERR_DATA_NOT_FOUND, pquery->get_seqid(), ebuf, esz, pthrpoolarr);
		}

		return false;
	}	

	auto 				datetbl = get_db_day_partition(tvstart.tv_sec, tvend.tv_sec, 0);

	const JSON_DB_MAPPING		*colarr[QUERY_OPTIONS::MAX_AGGR_COLUMNS];
	JSON_DB_MAPPING			acolarr[QUERY_OPTIONS::MAX_AGGR_COLUMNS];
	uint32_t			ncol;

	if (true) {
		STRING_BUFFER<48 * 1024>	strbuf;

		ncol = get_clientconn_aggr_query(strbuf, qryopt, datetbl.get(), acolarr, gmadhava_id_str_, nullptr, is_extended);

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());

		if (bret == false) {
			constexpr const char errbuf[] = "Aggregated Client Conns Query : Failed to schedule query to Database. Please retry later...";

			if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
				send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}

			return false;
		}	

		for (uint32_t i = 0; i < ncol; ++i) {
			colarr[i] = acolarr + i;
		}	
	}	

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	if (!is_extended) {
		writer.KeyConst("clientconn");
	}
	else {
		writer.KeyConst("extclientconn");
	}	
	writer.StartArray();

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, this, colarr, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_json_cb(conn, std::move(gyres), is_completed, "Aggregated Client Conn", colarr, ncol, writer, total_rows, noextracolcb);
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
				constexpr const char errbuf[] = "Aggregated Client Conns Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Aggregated Client Conns Query : Database Connection Error. Please try later...";

				send_json_error_resp(connshr, ERR_SYSERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}	

			return false;
		}	

		writer.EndArray();
		writer.EndObject();
		
		return false;
	}	

	writer.EndArray();

	if (false == qryopt.is_multi_host()) {
		web_db_set_partha_hostinfo(writer, qryopt);
	}

	set_json_column_list(writer, colarr, ncol);

	writer.EndObject();

	return true;
}


bool MCONN_HANDLER::web_query_client_conn(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool, bool is_extended)
{
	bool				bret, is_aggregated = qryopt.is_aggregated();

	try {
		if (false == qryopt.match_madhava_option(gmadhava_id_str_)) {
			// Skip this query
			writer.StartObject();	
	
			writer.KeyConst("madid");
			writer.String(gmadhava_id_str_, 16);

			writer.EndObject();

			return true;
		}

		if (false == is_aggregated) {
			bret = web_db_detail_client_conn(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool, is_extended);
		}
		else {
			bret = web_db_aggr_client_conn(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool, is_extended);
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


bool MCONN_HANDLER::web_db_listenproc_map(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Listener Process Mapping\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Listener Process Map Query : Database Querying Error : Failed to get an idle connection. Please try later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	int				ret;
	bool				bret, pointintime = qryopt.is_pointintime(), updqryopt = false;
	time_t				tcurr = time(nullptr);
	struct timeval			tvstart, tvend, origtvstart, origtvend;
	char				origstarttime[48], origendtime[48];
	
	GY_SCOPE_EXIT {
		if (updqryopt == true) {
			qryopt.set_timestamps(origstarttime, origendtime, origtvstart, origtvend, pointintime);
		}
	};	

	if (!qryopt.is_historical()) {
		origtvstart 	= {};
		origtvend 	= {};
		*origstarttime 	= 0;
		*origendtime	= 0;
		updqryopt 	= true;

		tvstart.tv_sec 	= tcurr - 10 * 60;
		tvstart.tv_usec = 0;

		tvend.tv_sec	= tcurr + 1;
		tvend.tv_usec	= 0;
		
		qryopt.set_timestamps(gy_localtime_iso8601_sec(tvstart.tv_sec).get(), gy_localtime_iso8601_sec(tvend.tv_sec).get(), tvstart, tvend, true /* pointintime */);
	}	
	else {
		tvstart = qryopt.get_start_timeval(); 
		tvend 	= qryopt.get_end_timeval();

		if (tvend.tv_sec - tvstart.tv_sec < 10 * 60) {
			origtvstart	= tvstart;
			origtvend	= tvend;
			GY_STRNCPY(origstarttime, qryopt.get_starttime(), sizeof(origstarttime));
			GY_STRNCPY(origendtime, qryopt.get_endtime(), sizeof(origendtime));
			updqryopt	= true;
			
			tvstart.tv_sec = tvend.tv_sec - 6 * 60;
			tvend.tv_sec += 4 * 60;

			qryopt.set_timestamps(gy_localtime_iso8601_sec(tvstart.tv_sec).get(), gy_localtime_iso8601_sec(tvend.tv_sec).get(), tvstart, tvend, true /* pointintime */);
		}	
	}

	auto 				datetbl = get_db_day_partition(tvstart.tv_sec, tvend.tv_sec, 0);

	const JSON_DB_MAPPING		*colarr[MAX_MULTI_HOST_COLUMN_LIST];
	
	auto [ncol, colspec] 		= qryopt.get_all_column_list(colarr, GY_ARRAY_SIZE(colarr), SUBSYS_SVCPROCMAP);

	if (tcurr - db_storage_days_ * GY_SEC_PER_DAY > (uint64_t)tvend.tv_sec) {
		char			ebuf[256];
		size_t			esz;
		
		esz = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Listener Process Map Query : Time Requested not present in DB : Max Days of DB storage = %u", db_storage_days_);

		if (writer.get_stream()->reset_if_not_sent(ERR_DATA_NOT_FOUND)) {
			send_json_error_resp(connshr, ERR_DATA_NOT_FOUND, pquery->get_seqid(), ebuf, esz, pthrpoolarr);
		}

		return false;
	}	
	
	if (qryopt.is_multi_host()) {
		STRING_BUFFER<48 * 1024>		strbuf;
		
		qryopt.get_db_select_multihost_query(strbuf, SUBSYS_SVCPROCMAP, "listentaskmaptbl", datetbl.get());

		strbuf.appendconst(";\n reset search_path; ");

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}
	else {
		STRING_BUFFER<48 * 1024>	strbuf;
		char				tablename[128];

		snprintf(tablename, sizeof(tablename), "sch%s.listentaskmaptbl%s", qryopt.get_parid_str().get(), datetbl.get());

		qryopt.get_db_select_query(strbuf, SUBSYS_SVCPROCMAP, tablename);

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}	

	if (bret == false) {
		constexpr const char errbuf[] = "Listener Process Map Query : Failed to schedule query to Database. Please retry later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	writer.KeyConst("svcprocmap");
	writer.StartArray();

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, this, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_json_cb(conn, std::move(gyres), is_completed, "Listener Process Map", colarr, ncol, writer, total_rows, noextracolcb);
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
				constexpr const char errbuf[] = "Listener Process Map Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Listener Process Map Query : Database Connection Error. Please try later...";

				send_json_error_resp(connshr, ERR_SYSERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}	

			return false;
		}	

		writer.EndArray();
		writer.EndObject();
		
		return false;
	}	

	writer.EndArray();

	if (false == qryopt.is_multi_host()) {
		web_db_set_partha_hostinfo(writer, qryopt);
	}

	writer.EndObject();

	return true;
}	

bool MCONN_HANDLER::web_query_listenproc_map(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	bool					bret;

	try {
		if (false == qryopt.match_madhava_option(gmadhava_id_str_)) {
			// Skip this query
			writer.StartObject();	
	
			writer.KeyConst("madid");
			writer.String(gmadhava_id_str_, 16);

			writer.EndObject();

			return true;
		}

		bret = web_db_listenproc_map(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);
		
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


bool MCONN_HANDLER::web_curr_listener_state(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, bool is_extended)
{
	uint64_t			maxrecs = qryopt.get_max_records(), nrecs = 0;
	const auto			& critset = qryopt.get_filter_criteria();
	bool				bret, is_multi_host = qryopt.is_multi_host();
	time_t				tcurr = time(nullptr);
	uint64_t 			min_stats_tusec = GY_USEC_CONVERT(tcurr - 10, 0);
	SUBSYS_CLASS_E			subsys = (false == is_extended ? SUBSYS_SVCSTATE : SUBSYS_EXTSVCSTATE);

	qryopt.comp_criteria_init();

	const JSON_DB_MAPPING		*colarr[MAX_MULTI_HOST_COLUMN_LIST];
	
	auto [ncol, colspec] = qryopt.get_all_column_list(colarr, GY_ARRAY_SIZE(colarr), subsys);

	const auto sendsvc = [&, min_stats_tusec, tcurr, colarr, ncol](const MTCP_LISTENER & listener, bool check_filter = false) -> bool
	{
		const LISTENER_STATE_NOTIFY	& state = listener.state_;

		auto tusec = listener.last_state_tusec_.load(mo_relaxed);

		if (tusec < min_stats_tusec) {
			return false;
		}	

		const auto			prawpartha = listener.parthashr_.get();
		
		if (!prawpartha) {
			return false;
		}	

		std::optional<SvcStateFields>		svcstate;
		std::optional<ExtSvcStateFields>	extsvcstate;
		
		if (!is_extended) {
			svcstate.emplace(*prawpartha, listener, gmadhava_id_str_, tcurr);
		}
		else {
			extsvcstate.emplace(*prawpartha, listener, gmadhava_id_str_, tcurr);
		}	

		if (check_filter && qryopt.has_filter()) {

			CRIT_RET_E 			cret;
			
			if (svcstate) {
				cret = svcstate->filter_match(qryopt.get_filter_criteria());
			}	
			else {
				cret = extsvcstate->filter_match(qryopt.get_filter_criteria());
			}	

			if (cret == CRIT_FAIL) {
				return false;
			}
		}	

		nrecs++;

		if (svcstate) {
			svcstate->print_json(colarr, ncol, writer);
		}	
		else {
			extsvcstate->print_json(colarr, ncol, writer);
		}	

		return CB_OK;
	};

	const auto listl = [&](MSOCKET_HDLR::MTCP_LISTENER_ELEM_TYPE *pdatanode, void *arg)
	{
		const auto			plistener = pdatanode->get_cref().get();

		if (plistener) {
			sendsvc(*plistener, true /* check_filter */);
		}	

		if (nrecs >= maxrecs) {
			return CB_BREAK_LOOP;
		}	

		return CB_OK;
	};	

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	if (!is_extended) {
		writer.KeyConst("svcstate");
	}
	else {
		writer.KeyConst("extsvcstate");
	}	
	writer.StartArray();

	/*
	 * We first search if only svcid filters specified. If no, we check if multihost specified.
	 * If multihost, check if the host fiters are set. If yes, we iterate over the partha_tbl_ first. If multihost and no host filters set,
	 * we iterate over the entire glob_listener_tbl_ :(
	 */
	if (qryopt.has_filter() && critset.is_only_l1() && critset.is_l1_oper_or() && critset.has_subsystem(subsys, true /* match_all */)) {
		const auto 		& l1_grp = critset.l1_grp_;
		uint32_t		neval = 0;

		// First validate
		for (uint32_t i = 0; i < l1_grp.ncrit_; ++i) {
			const auto		pcrit = l1_grp.pcritarr_ + i;
			
			if (subsys != pcrit->get_subsys()) {
				neval = 0;
				break;
			}

			if (FIELD_SVCID != pcrit->get_field_crc()) {
				neval = 0;
				break;
			}	

			if (!((COMP_EQ == pcrit->get_comparator()) || (COMP_IN == pcrit->get_comparator()))) {
				neval = 0;
				break;
			}	

			if (false == pcrit->is_value_string() || true == pcrit->is_value_expression()) {
				neval = 0;
				break;
			}

			neval++;
		}	
	
		if (neval) {
			RCU_LOCK_SLOW			slowlock;

			PARTHA_INFO_ELEM		*pelem = nullptr;
			PARTHA_INFO			*prawpartha = nullptr;

			if (!is_multi_host) {
				pelem = partha_tbl_.lookup_single_elem_locked(qryopt.get_parid(), qryopt.get_parid().get_hash());
				
				if (pelem == nullptr) {
					GY_THROW_EXPR_CODE(ERR_DATA_NOT_FOUND, "Service State Query : Host Partha ID Specified not found or was deleted recently");
				}	
				prawpartha = pelem->get_cref().get();

				if (prawpartha == nullptr) {
					GY_THROW_EXPR_CODE(ERR_DATA_NOT_FOUND, "Service State Query : Partha ID Specified was deleted recently");
				}	
			}
			
			for (uint32_t i = 0; i < l1_grp.ncrit_; ++i) {
				const auto		pcrit = l1_grp.pcritarr_ + i;
				auto [pstrarr, nstr] 	= pcrit->get_str_values();

				if (!pstrarr) {
					continue;
				}	

				for (uint32_t i = 0; i < nstr; i++) {
					uint64_t			glob_id;
					int				ret;
					
					if (pstrarr[i].size() != 16) {
						continue;
					}	

					if (!string_to_number(pstrarr[i].get(), glob_id, nullptr, 16)) {
						continue;
					}	

					const uint32_t			lhash = get_uint64_hash(glob_id);
					MTCP_LISTENER_ELEM_TYPE		*plistelem;
					MTCP_LISTENER			*plistener;
				
					if (prawpartha) {
						plistelem = prawpartha->listen_tbl_.lookup_single_elem_locked(glob_id, lhash);
					}
					else {
						plistelem = glob_listener_tbl_.lookup_single_elem_locked(glob_id, lhash);
					}

					if (gy_unlikely(plistelem == nullptr)) {
						continue;
					}	
					
					plistener = plistelem->get_cref().get();

					if (gy_unlikely(plistener == nullptr)) {
						continue;
					}	

					sendsvc(*plistener, true /* check_filter */);

					if (nrecs >= maxrecs) {
						goto donesvc;
					}	
				}
			}	

donesvc:
			writer.EndArray();

			if (prawpartha) {
					
				writer.KeyConst("hostinfo");
				writer.StartObject();

				writer.KeyConst("parid");
				writer.String(prawpartha->machine_id_str_, sizeof(prawpartha->machine_id_str_) - 1);
				
				writer.KeyConst("host");
				writer.String(prawpartha->hostname_, GY_READ_ONCE(prawpartha->hostname_len_));

				writer.KeyConst("madid");
				writer.String(gmadhava_id_str_, 16);

				writer.KeyConst("cluster");
				writer.String(prawpartha->cluster_name_, GY_READ_ONCE(prawpartha->cluster_len_));

				writer.EndObject();
			}	

			goto done;
		}	
	}

	if (!is_multi_host) {

		const auto parlam = [&](PARTHA_INFO_ELEM *pelem, void *arg1, void *arg2) -> CB_RET_E
		{
			auto				prawpartha = pelem->get_cref().get();

			if (gy_unlikely(prawpartha == nullptr)) {
				return CB_OK;
			}	

			prawpartha->listen_tbl_.walk_hash_table_const(listl);

			writer.EndArray();
			
			writer.KeyConst("hostinfo");
			writer.StartObject();

			writer.KeyConst("parid");
			writer.String(prawpartha->machine_id_str_, sizeof(prawpartha->machine_id_str_) - 1);
			
			writer.KeyConst("host");
			writer.String(prawpartha->hostname_, GY_READ_ONCE(prawpartha->hostname_len_));

			writer.KeyConst("madid");
			writer.String(gmadhava_id_str_, 16);

			writer.KeyConst("cluster");
			writer.String(prawpartha->cluster_name_, GY_READ_ONCE(prawpartha->cluster_len_));

			writer.EndObject();

			return CB_OK;
		};	

		bret = partha_tbl_.lookup_single_elem(qryopt.get_parid(), qryopt.get_parid().get_hash(), parlam);
		
		if (bret == false) {
			GY_THROW_EXPR_CODE(ERR_DATA_NOT_FOUND, "Listener Status Query : Partha ID Specified not found or was deleted recently");
		}	

		goto done;
	}
	else if (critset.has_subsystem(SUBSYS_HOST)) {

		const auto lampar = [&](PARTHA_INFO_ELEM *pelem, void *arg) -> CB_RET_E
		{
			auto				prawpartha = pelem->get_cref().get();

			if (gy_unlikely(prawpartha == nullptr)) {
				return CB_OK;
			}	

			auto 			cret = HostFields(*prawpartha, gmadhava_id_str_).filter_match(qryopt.get_filter_criteria());

			if (cret == CRIT_FAIL) {
				return CB_OK;
			}

			prawpartha->listen_tbl_.walk_hash_table_const(listl);
			
			if (nrecs >= maxrecs) {
				return CB_BREAK_LOOP;
			}	

			return CB_OK;
		};	

		partha_tbl_.walk_hash_table_const(lampar);

		writer.EndArray();
	}	
	else {
		// We need to scan the entire glob_listener_tbl_

		const auto lamsvc = [&](MTCP_LISTENER_ELEM_TYPE *pelem, void *arg) -> CB_RET_E
		{
			auto				plistener = pelem->get_cref().get();

			if (gy_unlikely(plistener == nullptr)) {
				return CB_OK;
			}	

			sendsvc(*plistener, true /* check_filter */);

			if (nrecs >= maxrecs) {
				return CB_BREAK_LOOP;
			}	

			return CB_OK;
		};	

		glob_listener_tbl_.walk_hash_table_const(lamsvc);

		writer.EndArray();
	}	

done :
	writer.EndObject();

	return true;
}

bool MCONN_HANDLER::web_db_detail_listener_state(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool, bool is_extended)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Service State\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Service State Query : Database Querying Error : Failed to get an idle connection. Please try later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	int				ret;
	bool				bret;
	time_t				tcurr = time(nullptr);
	struct timeval			tvstart = qryopt.get_start_timeval(), tvend = qryopt.get_end_timeval();

	if (tcurr - db_storage_days_ * GY_SEC_PER_DAY > (uint64_t)tvend.tv_sec) {
		char			ebuf[256];
		size_t			esz;
		
		esz = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Service State Query : Time Requested not present in DB : Max Days of DB storage = %u", db_storage_days_);

		if (writer.get_stream()->reset_if_not_sent(ERR_DATA_NOT_FOUND)) {
			send_json_error_resp(connshr, ERR_DATA_NOT_FOUND, pquery->get_seqid(), ebuf, esz, pthrpoolarr);
		}

		return false;
	}	

	SUBSYS_CLASS_E			subsys = (false == is_extended ? SUBSYS_SVCSTATE : SUBSYS_EXTSVCSTATE);
	const char			*listentbl = (false == is_extended ? "listenstatetbl" : "extlistenstatetbl");

	auto 				datetbl = get_db_day_partition(tvstart.tv_sec, tvend.tv_sec, is_extended ? 305 : 0);

	const JSON_DB_MAPPING		*colarr[MAX_MULTI_HOST_COLUMN_LIST];
	
	auto [ncol, colspec] 		= qryopt.get_all_column_list(colarr, GY_ARRAY_SIZE(colarr), subsys);


	if (qryopt.is_multi_host()) {
		STRING_BUFFER<48 * 1024>		strbuf;
		
		qryopt.get_db_select_multihost_query(strbuf, subsys, listentbl, datetbl.get());

		strbuf.appendconst(";\n reset search_path; ");

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}
	else {
		STRING_BUFFER<48 * 1024>	strbuf;
		char				tablename[128];

		snprintf(tablename, sizeof(tablename), "sch%s.%s%s", qryopt.get_parid_str().get(), listentbl, datetbl.get());

		qryopt.get_db_select_query(strbuf, subsys, tablename);

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}	

	if (bret == false) {
		constexpr const char errbuf[] = "Service State Query : Failed to schedule query to Database. Please retry later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	if (!is_extended) {
		writer.KeyConst("svcstate");
	}
	else {
		writer.KeyConst("extsvcstate");
	}	
	writer.StartArray();

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, this, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_json_cb(conn, std::move(gyres), is_completed, "Service State", colarr, ncol, writer, total_rows, noextracolcb);
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
				constexpr const char errbuf[] = "Service State Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Service State Query : Database Connection Error. Please try later...";

				send_json_error_resp(connshr, ERR_SYSERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}	

			return false;
		}	

		writer.EndArray();
		writer.EndObject();
		
		return false;
	}	

	writer.EndArray();

	if (false == qryopt.is_multi_host()) {
		web_db_set_partha_hostinfo(writer, qryopt);
	}

	writer.EndObject();

	return true;
}

bool MCONN_HANDLER::web_db_aggr_listener_state(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool, bool is_extended)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Aggregated Service State\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Aggregated Service State Query : Database Querying Error : Failed to get an idle connection. Please try later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	int				ret;
	bool				bret;
	time_t				tcurr = time(nullptr);
	struct timeval			tvstart = qryopt.get_start_timeval(), tvend = qryopt.get_end_timeval();

	if (tcurr - db_storage_days_ * GY_SEC_PER_DAY > (uint64_t)tvend.tv_sec) {
		char			ebuf[256];
		size_t			esz;
		
		esz = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Aggregated Service State Query : Time Requested not present in DB : Max Days of DB storage = %u", db_storage_days_);

		if (writer.get_stream()->reset_if_not_sent(ERR_DATA_NOT_FOUND)) {
			send_json_error_resp(connshr, ERR_DATA_NOT_FOUND, pquery->get_seqid(), ebuf, esz, pthrpoolarr);
		}

		return false;
	}	

	auto 				datetbl = get_db_day_partition(tvstart.tv_sec, tvend.tv_sec, is_extended ? 305 : 0);

	const JSON_DB_MAPPING		*colarr[QUERY_OPTIONS::MAX_AGGR_COLUMNS];
	JSON_DB_MAPPING			acolarr[QUERY_OPTIONS::MAX_AGGR_COLUMNS];
	uint32_t			ncol;

	assert(gy_get_thread_local().get_thread_stack_freespace() >= 256 * 1024);

	if (true) {
		STRING_BUFFER<48 * 1024>		strbuf;

		ncol = get_svcstate_aggr_query(strbuf, qryopt, datetbl.get(), acolarr, nullptr, is_extended);

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());

		if (bret == false) {
			constexpr const char errbuf[] = "Aggregated Service State Query : Failed to schedule query to Database. Please retry later...";

			if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
				send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}

			return false;
		}	

		for (uint32_t i = 0; i < ncol; ++i) {
			colarr[i] = acolarr + i;
		}	
	}

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	if (!is_extended) {
		writer.KeyConst("svcstate");
	}
	else {
		writer.KeyConst("extsvcstate");
	}	
	writer.StartArray();

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, this, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_json_cb(conn, std::move(gyres), is_completed, "Aggregated Service State", colarr, ncol, writer, total_rows, noextracolcb);
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
				constexpr const char errbuf[] = "Aggregated Service State Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Aggregated Service State Query : Database Connection Error. Please try later...";

				send_json_error_resp(connshr, ERR_SYSERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}	

			return false;
		}	

		writer.EndArray();
		writer.EndObject();
		
		return false;
	}	

	writer.EndArray();

	if (false == qryopt.is_multi_host()) {
		web_db_set_partha_hostinfo(writer, qryopt);
	}

	set_json_column_list(writer, colarr, ncol);

	writer.EndObject();

	return true;
}

bool MCONN_HANDLER::web_query_listener_state(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool, bool is_extended)
{
	bool				bret, is_aggregated = qryopt.is_aggregated();

	try {
		if (false == qryopt.match_madhava_option(gmadhava_id_str_)) {
			// Skip this query
			writer.StartObject();	
	
			writer.KeyConst("madid");
			writer.String(gmadhava_id_str_, 16);

			writer.EndObject();

			return true;
		}

		if (!qryopt.is_historical()) {
			bret = web_curr_listener_state(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, is_extended);
		}
		else {
			if (false == is_aggregated) {
				bret = web_db_detail_listener_state(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool, is_extended);
			}
			else {
				bret = web_db_aggr_listener_state(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool, is_extended);
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


CRIT_RET_E MCONN_HANDLER::top_aggr_procs_filter_match(const CRITERIA_SET & criteria, const PARTHA_INFO & rawpartha, bool ignore_other_subsys) const
{
	/*
	 * Currently we only support Host filters for Top Aggr Proc querying
	 */
	auto 			cret = HostFields(rawpartha, gmadhava_id_str_).filter_match(criteria);

	return cret;
}	

bool MCONN_HANDLER::web_curr_top_aggr_procs(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr)
{
	uint64_t			tcurrusec = get_usec_time(), min_tusec = tcurrusec - 15 * GY_USEC_PER_SEC;
	bool				bret, is_multi_host = qryopt.is_multi_host();

	bool				send_topnet = false, send_topcpu = false, send_toprss = false, 
					send_topcpudelay = false, send_topvmdelay = false, send_topiodelay = false, send_topissue = false;

	const auto			*poptions = qryopt.get_options_json();

	qryopt.comp_criteria_init();

	if (poptions) {
		const auto		& optobj = poptions->GetObject();
		auto			miter = optobj.FindMember("send_topnet");
		uint8_t			flag = 0;

		if ((miter != optobj.MemberEnd()) && (miter->value.IsBool())) {
			send_topnet = miter->value.GetBool();
			flag |= send_topnet;	
		}	

		miter = optobj.FindMember("send_topcpu");

		if ((miter != optobj.MemberEnd()) && (miter->value.IsBool())) {
			send_topcpu = miter->value.GetBool();
			flag |= send_topcpu;	
		}	

		miter = optobj.FindMember("send_toprss");

		if ((miter != optobj.MemberEnd()) && (miter->value.IsBool())) {
			send_toprss = miter->value.GetBool();
			flag |= send_toprss;	
		}	

		miter = optobj.FindMember("send_topcpudelay");

		if ((miter != optobj.MemberEnd()) && (miter->value.IsBool())) {
			send_topcpudelay = miter->value.GetBool();
			flag |= send_topcpudelay;	
		}	

		miter = optobj.FindMember("send_topvmdelay");

		if ((miter != optobj.MemberEnd()) && (miter->value.IsBool())) {
			send_topvmdelay = miter->value.GetBool();
			flag |= send_topvmdelay;	
		}	

		miter = optobj.FindMember("send_topiodelay");

		if ((miter != optobj.MemberEnd()) && (miter->value.IsBool())) {
			send_topiodelay = miter->value.GetBool();
			flag |= send_topiodelay;	
		}	

		miter = optobj.FindMember("send_topissue");

		if ((miter != optobj.MemberEnd()) && (miter->value.IsBool())) {
			send_topissue = miter->value.GetBool();
			flag |= send_topissue;	
		}	

		if (flag == 0) {
			constexpr const char errbuf[] = "Top Aggregated Process Query : Query requested with no valid Top criteria ...";

			if (writer.get_stream()->reset_if_not_sent(ERR_INVALID_REQUEST)) {
				send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}

			return false;
		}	
	}
	else {
		send_topissue = true;
	}

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	const auto stream_top = [&](const AGGR_TASK_STATE_NOTIFY & state, uint64_t usec_time, const char *pissue, const char *phostname, uint16_t lenhost, const char *pcluster, uint16_t lencluster, const char *pmachid)
	{
		writer.StartObject();
		
		if (pmachid) {	
			writer.KeyConst("parid");
			writer.String(pmachid, 32);
		}
		
		if (phostname) {	
			writer.KeyConst("host");
			writer.String(phostname, lenhost);

			writer.KeyConst("madid");
			writer.String(gmadhava_id_str_, 16);
		}

		if (pcluster) {	
			writer.KeyConst("cluster");
			writer.String(pcluster, lencluster);
		}

		// svcstate fields follow

		writer.KeyConst("time");
		writer.String(gy_localtime_iso8601(usec_time/GY_USEC_PER_SEC, CHAR_BUF<64>().get(), 64));	

		writer.KeyConst("procid");
		writer.String(number_to_string(state.aggr_task_id_, "%016lx").get(), 16);

		writer.KeyConst("name");
		writer.String(state.onecomm_);

		writer.KeyConst("pid1");
		writer.Int(state.pid_arr_[0]);

		writer.KeyConst("pid2");
		writer.Int(state.pid_arr_[1]);

		writer.KeyConst("netkb");
		writer.Int(state.tcp_kbytes_);

		writer.KeyConst("nconn");
		writer.Int(state.tcp_conns_);
		
		writer.KeyConst("cpu");
		writer.Double(state.total_cpu_pct_);
		
		writer.KeyConst("rss");
		writer.Int(state.rss_mb_);
		
		writer.KeyConst("cpudel");
		writer.Int(state.cpu_delay_msec_);
		
		writer.KeyConst("vmdel");
		writer.Int(state.vm_delay_msec_);
		
		writer.KeyConst("iodel");
		writer.Int(state.blkio_delay_msec_);
		
		writer.KeyConst("nprocs");
		writer.Int(state.ntasks_total_);
		
		writer.KeyConst("nissue");
		writer.Int(state.ntasks_issue_);
		
		writer.KeyConst("state");
		writer.String(state_to_stringlen((OBJ_STATE_E)state.curr_state_));

		writer.KeyConst("issue");
		writer.Int(state.curr_issue_);

		writer.KeyConst("desc");
		if (pissue) {
			writer.String(pissue);
		}
		else {
			writer.String(issue_to_string((TASK_ISSUE_SOURCE)state.curr_issue_));
		}	

		writer.EndObject();
	};	


	if (is_multi_host) {
		using ATASK_MULTI_TOP_VEC		= INLINE_STACK_VECTOR<MULTI_MAGGR_TASK_STATE, sizeof(MULTI_MAGGR_TASK_STATE) * MAX_MULTI_TOPN + 48>;
		using ATASK_MULTI_TOP_ISSUE_VEC		= INLINE_STACK_VECTOR<MULTI_MTASK_ISSUE, sizeof(MULTI_MTASK_ISSUE) * MAX_MULTI_TOPN + 48>;

		using ATASK_MULTI_TOP_NET 		= BOUNDED_PRIO_QUEUE<MULTI_MAGGR_TASK_STATE, MULTI_MAGGR_TASK_STATE::TOP_NET, NULL_MUTEX, ATASK_MULTI_TOP_VEC>;
		using ATASK_MULTI_TOP_CPU 		= BOUNDED_PRIO_QUEUE<MULTI_MAGGR_TASK_STATE, MULTI_MAGGR_TASK_STATE::TOP_CPU, NULL_MUTEX, ATASK_MULTI_TOP_VEC>;
		using ATASK_MULTI_TOP_RSS 		= BOUNDED_PRIO_QUEUE<MULTI_MAGGR_TASK_STATE, MULTI_MAGGR_TASK_STATE::TOP_RSS, NULL_MUTEX, ATASK_MULTI_TOP_VEC>;
		using ATASK_MULTI_TOP_CPU_DELAY 	= BOUNDED_PRIO_QUEUE<MULTI_MAGGR_TASK_STATE, MULTI_MAGGR_TASK_STATE::TOP_CPU_DELAY, NULL_MUTEX, ATASK_MULTI_TOP_VEC>;
		using ATASK_MULTI_TOP_VM_DELAY 		= BOUNDED_PRIO_QUEUE<MULTI_MAGGR_TASK_STATE, MULTI_MAGGR_TASK_STATE::TOP_VM_DELAY, NULL_MUTEX, ATASK_MULTI_TOP_VEC>;
		using ATASK_MULTI_TOP_IO_DELAY 		= BOUNDED_PRIO_QUEUE<MULTI_MAGGR_TASK_STATE, MULTI_MAGGR_TASK_STATE::TOP_IO_DELAY, NULL_MUTEX, ATASK_MULTI_TOP_VEC>;
		using ATASK_MULTI_TOP_ISSUE	 	= BOUNDED_PRIO_QUEUE<MULTI_MTASK_ISSUE, MULTI_MTASK_ISSUE::TOP_ISSUE, NULL_MUTEX, ATASK_MULTI_TOP_ISSUE_VEC>;

		assert(gy_get_thread_local().get_thread_stack_freespace() >= sizeof(ATASK_MULTI_TOP_ISSUE_VEC) + sizeof(ATASK_MULTI_TOP_VEC) * 6 + 64 * 1024);

		ATASK_MULTI_TOP_ISSUE			top_issue_multi		{MAX_MULTI_TOPN};
		ATASK_MULTI_TOP_NET			top_net_multi		{MAX_MULTI_TOPN};	
		ATASK_MULTI_TOP_CPU			top_cpu_multi		{MAX_MULTI_TOPN};	
		ATASK_MULTI_TOP_RSS			top_rss_multi		{MAX_MULTI_TOPN};	
		ATASK_MULTI_TOP_CPU_DELAY		top_cpu_delay_multi	{MAX_MULTI_TOPN};	
		ATASK_MULTI_TOP_VM_DELAY		top_vm_delay_multi	{MAX_MULTI_TOPN};	
		ATASK_MULTI_TOP_IO_DELAY		top_io_delay_multi	{MAX_MULTI_TOPN};	

		const char				*phostname = nullptr, *pcluster_name = nullptr, *pmachine_id_str = nullptr;
		const MAGGR_TASK_STATE			*pone = nullptr;
		const MTASK_ISSUE			*poneissue = nullptr;
		
		const auto compissue = [&](const MULTI_MTASK_ISSUE & elem) noexcept
		{
			return poneissue && MTASK_ISSUE::is_comp_issue(poneissue->task_state_, elem);
		};

		const auto compnet = [&](const MULTI_MAGGR_TASK_STATE & elem) noexcept
		{
			return pone && MAGGR_TASK_STATE::is_comp_net(pone->task_state_, elem);
		};

		const auto compcpu = [&](const MULTI_MAGGR_TASK_STATE & elem) noexcept
		{
			return pone && MAGGR_TASK_STATE::is_comp_cpu(pone->task_state_, elem);
		};

		const auto comprss = [&](const MULTI_MAGGR_TASK_STATE & elem) noexcept
		{
			return pone && MAGGR_TASK_STATE::is_comp_rss(pone->task_state_, elem);
		};

		const auto compcpudelay = [&](const MULTI_MAGGR_TASK_STATE & elem) noexcept
		{
			return pone && MAGGR_TASK_STATE::is_comp_cpu_delay(pone->task_state_, elem);
		};

		const auto compvmdelay = [&](const MULTI_MAGGR_TASK_STATE & elem) noexcept
		{
			return pone && MAGGR_TASK_STATE::is_comp_vm_delay(pone->task_state_, elem);
		};

		const auto compiodelay = [&](const MULTI_MAGGR_TASK_STATE & elem) noexcept
		{
			return pone && MAGGR_TASK_STATE::is_comp_io_delay(pone->task_state_, elem);
		};


		const auto walkissue = [&](const MTASK_ISSUE & elem, void * arg1, void * arg2) -> CB_RET_E
		{
			poneissue = &elem;

			if (phostname) {
				top_issue_multi.try_emplace_locked(compissue, phostname, pcluster_name, pmachine_id_str, elem);
			}

			return CB_OK;
		};	

		const auto walknet = [&](const MAGGR_TASK_STATE & elem, void * arg1, void * arg2) -> CB_RET_E
		{
			pone = &elem;

			if (phostname) {
				top_net_multi.try_emplace_locked(compnet, phostname, pcluster_name, pmachine_id_str, elem);
			}

			return CB_OK;
		};	

		const auto walkcpu = [&](const MAGGR_TASK_STATE & elem, void * arg1, void * arg2) -> CB_RET_E
		{
			pone = &elem;

			if (phostname) {
				top_cpu_multi.try_emplace_locked(compcpu, phostname, pcluster_name, pmachine_id_str, elem);
			}

			return CB_OK;
		};	

		const auto walkrss = [&](const MAGGR_TASK_STATE & elem, void * arg1, void * arg2) -> CB_RET_E
		{
			pone = &elem;

			if (phostname) {
				top_rss_multi.try_emplace_locked(comprss, phostname, pcluster_name, pmachine_id_str, elem);
			}

			return CB_OK;
		};	

		const auto walkcpudelay = [&](const MAGGR_TASK_STATE & elem, void * arg1, void * arg2) -> CB_RET_E
		{
			pone = &elem;

			if (phostname) {
				top_cpu_delay_multi.try_emplace_locked(compcpudelay, phostname, pcluster_name, pmachine_id_str, elem);
			}

			return CB_OK;
		};	

		const auto walkvmdelay = [&](const MAGGR_TASK_STATE & elem, void * arg1, void * arg2) -> CB_RET_E
		{
			pone = &elem;

			if (phostname) {
				top_vm_delay_multi.try_emplace_locked(compvmdelay, phostname, pcluster_name, pmachine_id_str, elem);
			}

			return CB_OK;
		};	

		const auto walkiodelay = [&](const MAGGR_TASK_STATE & elem, void * arg1, void * arg2) -> CB_RET_E
		{
			pone = &elem;

			if (phostname) {
				top_io_delay_multi.try_emplace_locked(compiodelay, phostname, pcluster_name, pmachine_id_str, elem);
			}

			return CB_OK;
		};	


		const auto lampar = [&, send_topissue, send_topcpu, send_toprss, send_topcpudelay, send_topvmdelay, send_topiodelay, min_tusec](PARTHA_INFO_ELEM *pdatanode, void *arg1) -> CB_RET_E
		{
			auto				prawpartha = pdatanode->get_cref().get();
			bool				bret;

			if (gy_unlikely(prawpartha == nullptr)) {
				return CB_OK;
			}	

			if (GY_READ_ONCE(prawpartha->last_aggr_state_tusec_) < min_tusec) {
				return CB_OK;
			}	

			if (qryopt.has_filter()) {
				auto cret = top_aggr_procs_filter_match(qryopt.get_filter_criteria(), *prawpartha, true /* ignore_other_subsys */);

				if (cret == CRIT_FAIL) {
					return CB_OK;
				}
			}	

			// Use the atask_top_issue_ mutex for all top structs
			SCOPE_GY_MUTEX			topmutex(&prawpartha->atask_top_issue_.mutex_);

			phostname 	= prawpartha->hostname_;
			pcluster_name	= prawpartha->cluster_name_;
			pmachine_id_str	= prawpartha->machine_id_str_;

			if (send_topissue) { 
				prawpartha->atask_top_issue_.walk_queue_const(walkissue);
			}

			if (send_topnet) {
				prawpartha->atask_top_net_.walk_queue_const(walknet);
			}

			if (send_topcpu) {
				prawpartha->atask_top_cpu_.walk_queue_const(walkcpu);
			}

			if (send_toprss) {
				prawpartha->atask_top_rss_.walk_queue_const(walkrss);
			}

			if (send_topcpudelay) {
				prawpartha->atask_top_cpu_delay_.walk_queue_const(walkcpudelay);
			}

			if (send_topvmdelay) {
				prawpartha->atask_top_vm_delay_.walk_queue_const(walkvmdelay);
			}

			if (send_topiodelay) {
				prawpartha->atask_top_io_delay_.walk_queue_const(walkiodelay);
			}

			topmutex.unlock();

			return CB_OK;
		};
				
		partha_tbl_.walk_hash_table_const(lampar);

		const auto wstreamissue = [&](const MULTI_MTASK_ISSUE & elem, void * arg1, void * arg2) -> CB_RET_E
		{
			stream_top(elem.task_state_, elem.last_usec_time_, elem.issue_string_, elem.hostname_, elem.lenhost_, elem.cluster_name_, elem.lencluster_, elem.machine_id_str_);
			return CB_OK;
		};	

		const auto wstream = [&](const MULTI_MAGGR_TASK_STATE & elem, void * arg1, void * arg2) -> CB_RET_E
		{
			stream_top(elem.task_state_, elem.last_usec_time_, nullptr, elem.hostname_, elem.lenhost_, elem.cluster_name_, elem.lencluster_, elem.machine_id_str_);
			return CB_OK;
		};	


		if (send_topissue) {
			writer.KeyConst("topissue");
			writer.StartArray();

			top_issue_multi.walk_queue(wstreamissue, nullptr, nullptr, true /* sort_queue */, false /* heap_on_return */);

			writer.EndArray();
		}

		if (send_topnet) {
			writer.KeyConst("topnet");
			writer.StartArray();

			top_net_multi.walk_queue(wstream, nullptr, nullptr, true /* sort_queue */, false /* heap_on_return */);

			writer.EndArray();
		}

		if (send_topcpu) {
			writer.KeyConst("topcpu");
			writer.StartArray();

			top_cpu_multi.walk_queue(wstream, nullptr, nullptr, true /* sort_queue */, false /* heap_on_return */);

			writer.EndArray();
		}

		if (send_toprss) {
			writer.KeyConst("toprss");
			writer.StartArray();

			top_rss_multi.walk_queue(wstream, nullptr, nullptr, true /* sort_queue */, false /* heap_on_return */);

			writer.EndArray();
		}

		if (send_topcpudelay) {
			writer.KeyConst("topcpudelay");
			writer.StartArray();

			top_cpu_delay_multi.walk_queue(wstream, nullptr, nullptr, true /* sort_queue */, false /* heap_on_return */);

			writer.EndArray();
		}

		if (send_topvmdelay) {
			writer.KeyConst("topvmdelay");
			writer.StartArray();

			top_vm_delay_multi.walk_queue(wstream, nullptr, nullptr, true /* sort_queue */, false /* heap_on_return */);

			writer.EndArray();
		}

		if (send_topiodelay) {
			writer.KeyConst("topiodelay");
			writer.StartArray();

			top_io_delay_multi.walk_queue(wstream, nullptr, nullptr, true /* sort_queue */, false /* heap_on_return */);

			writer.EndArray();
		}
	}	
	else {

		const auto wstreamissue = [&](const MTASK_ISSUE & elem, void * arg1, void * arg2) -> CB_RET_E
		{
			stream_top(elem.task_state_, elem.last_usec_time_, elem.issue_string_, nullptr, 0, nullptr, 0, nullptr);
			return CB_OK;
		};	

		const auto wstream = [&](const MAGGR_TASK_STATE & elem, void * arg1, void * arg2) -> CB_RET_E
		{
			stream_top(elem.task_state_, elem.last_usec_time_, nullptr, nullptr, 0, nullptr, 0, nullptr);
			return CB_OK;
		};	

		const auto lampar = [&](PARTHA_INFO_ELEM *pdatanode, void *arg1, void *arg2) -> CB_RET_E
		{
			auto				prawpartha = pdatanode->get_cref().get();
			bool				bret;

			if (gy_unlikely(prawpartha == nullptr)) {
				return CB_OK;
			}	

			auto				tlastusec = GY_READ_ONCE(prawpartha->last_aggr_state_tusec_);

			if (tlastusec < min_tusec) {
				GY_THROW_EXPR_CODE(ERR_DATA_NOT_FOUND, "Top Aggregate Process Query : Partha Host %s has not updated its data recently", prawpartha->hostname_);
			}	

			// Use the atask_top_issue_ mutex for all top structs
			SCOPE_GY_MUTEX			topmutex(&prawpartha->atask_top_issue_.mutex_);

			// Copy locally
			std::optional<AGGR_TASK_TOP_ISSUE>		top_issue;
			std::optional<AGGR_TASK_TOP_NET>		top_net;
			std::optional<AGGR_TASK_TOP_CPU>		top_cpu;
			std::optional<AGGR_TASK_TOP_RSS>		top_rss;
			std::optional<AGGR_TASK_TOP_CPU_DELAY>		top_cpu_delay;
			std::optional<AGGR_TASK_TOP_VM_DELAY>		top_vm_delay;
			std::optional<AGGR_TASK_TOP_IO_DELAY>		top_io_delay;

			if (send_topissue) {
				top_issue.emplace(prawpartha->atask_top_issue_);
			}

			if (send_topnet) {
				top_net.emplace(prawpartha->atask_top_net_);
			}	

			if (send_topcpu) {
				top_cpu.emplace(prawpartha->atask_top_cpu_);
			}	

			if (send_toprss) {
				top_rss.emplace(prawpartha->atask_top_rss_);
			}	

			if (send_topcpudelay) {
				top_cpu_delay.emplace(prawpartha->atask_top_cpu_delay_);
			}	

			if (send_topvmdelay) {
				top_vm_delay.emplace(prawpartha->atask_top_vm_delay_);
			}	

			if (send_topiodelay) {
				top_io_delay.emplace(prawpartha->atask_top_io_delay_);
			}	

			topmutex.unlock();

			if (send_topissue) {
				writer.KeyConst("topissue");
				writer.StartArray();

				top_issue->walk_queue(wstreamissue, nullptr, nullptr, true /* sort_queue */, false /* heap_on_return */);

				writer.EndArray();
			}

			if (send_topnet) {
				writer.KeyConst("topnet");
				writer.StartArray();

				top_net->walk_queue(wstream, nullptr, nullptr, true /* sort_queue */, false /* heap_on_return */);

				writer.EndArray();
			}

			if (send_topcpu) {
				writer.KeyConst("topcpu");
				writer.StartArray();

				top_cpu->walk_queue(wstream, nullptr, nullptr, true /* sort_queue */, false /* heap_on_return */);

				writer.EndArray();
			}

			if (send_toprss) {
				writer.KeyConst("toprss");
				writer.StartArray();

				top_rss->walk_queue(wstream, nullptr, nullptr, true /* sort_queue */, false /* heap_on_return */);

				writer.EndArray();
			}

			if (send_topcpudelay) {
				writer.KeyConst("topcpudelay");
				writer.StartArray();

				top_cpu_delay->walk_queue(wstream, nullptr, nullptr, true /* sort_queue */, false /* heap_on_return */);

				writer.EndArray();
			}

			if (send_topvmdelay) {
				writer.KeyConst("topvmdelay");
				writer.StartArray();

				top_vm_delay->walk_queue(wstream, nullptr, nullptr, true /* sort_queue */, false /* heap_on_return */);

				writer.EndArray();
			}

			if (send_topiodelay) {
				writer.KeyConst("topiodelay");
				writer.StartArray();

				top_io_delay->walk_queue(wstream, nullptr, nullptr, true /* sort_queue */, false /* heap_on_return */);

				writer.EndArray();
			}

			writer.KeyConst("hostinfo");
			writer.StartObject();

			writer.KeyConst("parid");
			writer.String(prawpartha->machine_id_str_, sizeof(prawpartha->machine_id_str_) - 1);
			
			writer.KeyConst("host");
			writer.String(prawpartha->hostname_, GY_READ_ONCE(prawpartha->hostname_len_));

			writer.KeyConst("madid");
			writer.String(gmadhava_id_str_, 16);

			writer.KeyConst("cluster");
			writer.String(prawpartha->cluster_name_, GY_READ_ONCE(prawpartha->cluster_len_));

			writer.EndObject();

			return CB_OK;
		};
				
		bret = partha_tbl_.lookup_single_elem(qryopt.get_parid(), qryopt.get_parid().get_hash(), lampar);
		
		if (bret == false) {
			GY_THROW_EXPR_CODE(ERR_DATA_NOT_FOUND, "Top Aggregated Process Query : Partha ID Specified not found or was deleted recently");
		}	
	}
	
	writer.EndObject();

	return true;
}


bool MCONN_HANDLER::web_db_top_aggr_procs(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Top Aggr Proc query\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Top Aggr Proc Query : Database Querying Error : Failed to get an idle connection. Please try later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	int				ret;
	bool				bret;
	time_t				tcurr = time(nullptr);
	struct timeval			tvstart = qryopt.get_start_timeval(), tvend = qryopt.get_end_timeval();

	if (false == qryopt.is_pointintime() && qryopt.is_multi_host()) {
		constexpr const char errbuf[] = "Top Aggr Proc Query : Query requested for a time range for Multiple hosts instead of a Point in time. Currently not supported...";

		if (writer.get_stream()->reset_if_not_sent(ERR_INVALID_REQUEST)) {
			send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}

	if (tcurr - db_storage_days_ * GY_SEC_PER_DAY > (uint64_t)tvend.tv_sec) {
		char			ebuf[256];
		size_t			esz;
		
		esz = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Top Aggr Proc Query : Time Requested not present in DB : Max Days of DB storage = %u", db_storage_days_);

		if (writer.get_stream()->reset_if_not_sent(ERR_DATA_NOT_FOUND)) {
			send_json_error_resp(connshr, ERR_DATA_NOT_FOUND, pquery->get_seqid(), ebuf, esz, pthrpoolarr);
		}

		return false;
	}	
	
	const JSON_DB_MAPPING		*colarr[GY_ARRAY_SIZE(json_db_procstate_arr) + GY_ARRAY_SIZE(json_db_host_arr) + 4];
	size_t				ncol;

	auto 				datetbl = get_db_day_partition(tvstart.tv_sec, tvend.tv_sec, 0);
	
	bool				send_topnet = false, send_topcpu = false, send_toprss = false, 
					send_topcpudelay = false, send_topvmdelay = false, send_topiodelay = false, send_topissue = false;

	const auto			*poptions = qryopt.get_options_json();

	if (poptions) {
		const auto		& optobj = poptions->GetObject();
		auto			miter = optobj.FindMember("send_topnet");
		uint8_t			flag = 0;

		if ((miter != optobj.MemberEnd()) && (miter->value.IsBool())) {
			send_topnet = miter->value.GetBool();
			flag |= send_topnet;	
		}	

		miter = optobj.FindMember("send_topcpu");

		if ((miter != optobj.MemberEnd()) && (miter->value.IsBool())) {
			send_topcpu = miter->value.GetBool();
			flag |= send_topcpu;	
		}	

		miter = optobj.FindMember("send_toprss");

		if ((miter != optobj.MemberEnd()) && (miter->value.IsBool())) {
			send_toprss = miter->value.GetBool();
			flag |= send_toprss;	
		}	

		miter = optobj.FindMember("send_topcpudelay");

		if ((miter != optobj.MemberEnd()) && (miter->value.IsBool())) {
			send_topcpudelay = miter->value.GetBool();
			flag |= send_topcpudelay;	
		}	

		miter = optobj.FindMember("send_topvmdelay");

		if ((miter != optobj.MemberEnd()) && (miter->value.IsBool())) {
			send_topvmdelay = miter->value.GetBool();
			flag |= send_topvmdelay;	
		}	

		miter = optobj.FindMember("send_topiodelay");

		if ((miter != optobj.MemberEnd()) && (miter->value.IsBool())) {
			send_topiodelay = miter->value.GetBool();
			flag |= send_topiodelay;	
		}	

		miter = optobj.FindMember("send_topissue");

		if ((miter != optobj.MemberEnd()) && (miter->value.IsBool())) {
			send_topissue = miter->value.GetBool();
			flag |= send_topissue;	
		}	

		if (flag == 0) {
			constexpr const char errbuf[] = "Top Aggregated Process Query : Query requested with no valid Top criteria ...";

			if (writer.get_stream()->reset_if_not_sent(ERR_INVALID_REQUEST)) {
				send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}

			return false;
		}	
	}
	else {
		send_topissue = true;
	}

	
	auto 		p = qryopt.get_all_column_list(colarr, GY_ARRAY_SIZE(colarr), SUBSYS_PROCSTATE);
	ncol 		= p.first;

	if (qryopt.is_multi_host()) {
		STRING_BUFFER<48 * 1024>		strbuf;
		
		if (send_topissue) {
			strbuf.appendconst("select \'topissue\'::text as separator_topissue;");
			get_db_multihost_top_aggr_procs_query(strbuf, qryopt, datetbl.get(), TOP_APROC_ISSUE);
			strbuf.appendconst("select \'completed\'::text as separator;");
		}

		if (send_topnet) {
			strbuf.appendconst("\nselect \'topnet\'::text as separator_topnet;");
			get_db_multihost_top_aggr_procs_query(strbuf, qryopt, datetbl.get(), TOP_APROC_NET);
			strbuf.appendconst("select \'completed\'::text as separator;");
		}

		if (send_topcpu) {
			strbuf.appendconst("\nselect \'topcpu\'::text as separator_topcpu;");
			get_db_multihost_top_aggr_procs_query(strbuf, qryopt, datetbl.get(), TOP_APROC_CPU);
			strbuf.appendconst("select \'completed\'::text as separator;");
		}

		if (send_toprss) {
			strbuf.appendconst("\nselect \'toprss\'::text as separator_toprss;");
			get_db_multihost_top_aggr_procs_query(strbuf, qryopt, datetbl.get(), TOP_APROC_RSS);
			strbuf.appendconst("select \'completed\'::text as separator;");
		}

		if (send_topcpudelay) {
			strbuf.appendconst("\nselect \'topcpudelay\'::text as separator_topcpudelay;");
			get_db_multihost_top_aggr_procs_query(strbuf, qryopt, datetbl.get(), TOP_APROC_CPU_DELAY);
			strbuf.appendconst("select \'completed\'::text as separator;");
		}

		if (send_topvmdelay) {
			strbuf.appendconst("\nselect \'topvmdelay\'::text as separator_topvmdelay;");
			get_db_multihost_top_aggr_procs_query(strbuf, qryopt, datetbl.get(), TOP_APROC_VM_DELAY);
			strbuf.appendconst("select \'completed\'::text as separator;");
		}

		if (send_topiodelay) {
			strbuf.appendconst("\nselect \'topiodelay\'::text as separator_topiodelay;");
			get_db_multihost_top_aggr_procs_query(strbuf, qryopt, datetbl.get(), TOP_APROC_IO_DELAY);
			strbuf.appendconst("select \'completed\'::text as separator;");
		}

		strbuf.appendconst("\n reset search_path; \n");

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}
	else {
		STRING_BUFFER<48 * 1024>	strbuf;

		if (send_topissue) {
			strbuf.appendconst("select \'topissue\'::text as separator_topissue;");
			get_db_top_aggr_procs_query(strbuf, qryopt, datetbl.get(), TOP_APROC_ISSUE);
			strbuf.appendconst("select \'completed\'::text as separator;");
		}

		if (send_topnet) {
			strbuf.appendconst("\nselect \'topnet\'::text as separator_topnet;");
			get_db_top_aggr_procs_query(strbuf, qryopt, datetbl.get(), TOP_APROC_NET);
			strbuf.appendconst("select \'completed\'::text as separator;");
		}

		if (send_topcpu) {
			strbuf.appendconst("\nselect \'topcpu\'::text as separator_topcpu;");
			get_db_top_aggr_procs_query(strbuf, qryopt, datetbl.get(), TOP_APROC_CPU);
			strbuf.appendconst("select \'completed\'::text as separator;");
		}

		if (send_toprss) {
			strbuf.appendconst("\nselect \'toprss\'::text as separator_toprss;");
			get_db_top_aggr_procs_query(strbuf, qryopt, datetbl.get(), TOP_APROC_RSS);
			strbuf.appendconst("select \'completed\'::text as separator;");
		}

		if (send_topcpudelay) {
			strbuf.appendconst("\nselect \'topcpudelay\'::text as separator_topcpudelay;");
			get_db_top_aggr_procs_query(strbuf, qryopt, datetbl.get(), TOP_APROC_CPU_DELAY);
			strbuf.appendconst("select \'completed\'::text as separator;");
		}

		if (send_topvmdelay) {
			strbuf.appendconst("\nselect \'topvmdelay\'::text as separator_topvmdelay;");
			get_db_top_aggr_procs_query(strbuf, qryopt, datetbl.get(), TOP_APROC_VM_DELAY);
			strbuf.appendconst("select \'completed\'::text as separator;");
		}

		if (send_topiodelay) {
			strbuf.appendconst("\nselect \'topiodelay\'::text as separator_topiodelay;");
			get_db_top_aggr_procs_query(strbuf, qryopt, datetbl.get(), TOP_APROC_IO_DELAY);
			strbuf.appendconst("select \'completed\'::text as separator;");
		}

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}	

	if (bret == false) {
		constexpr const char errbuf[] = "Top Aggr Proc Query : Failed to schedule query to Database. Please retry later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, total_rows = 0, ncol, ntotcol = 0, pcolarr = (const JSON_DB_MAPPING **)nullptr](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			if (is_completed) {
				conn.make_available();
				return true;
			}	
			
			if (true == gyres.is_error()) {
				DEBUGEXECN(10,
					WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to query Top Aggr Proc from DB due to %s (Total tuples returned so far %d)\n", 
							gyres.get_error_msg(), total_rows);
				);

				if (0 == strcmp(gyres.get_sqlcode(), "42P01")) {
					GY_THROW_EXPR_CODE(ERR_DATA_NOT_FOUND, "Failed to query Top Aggr Proc from DB for the time range specified as no data present");
				}	

				GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "Failed to query Top Aggr Proc from DB due to %s", gyres.get_error_msg());
			}	

			char				tbuf[512];
			const PGresult *		pres = gyres.get();
			const int			nfields = PQnfields(pres);
			const int			ntuples = PQntuples(gyres.get());

			if (nfields == 1 && ntuples == 1) {
				const char	*pfname = PQfname(pres, 0);

				if (!pfname) {
					return false;
				}	
				
				if (0 == strncmp(pfname, "separator_", GY_CONST_STRLEN("separator_"))) {
					const char 		*pkey = pfname + GY_CONST_STRLEN("separator_");

					writer.Key(pkey);

					pcolarr = colarr;
					ntotcol = ncol;
					
					writer.StartArray();
					total_rows = 0;

					return true;
				}	
				else if (0 == strcmp(pfname, "separator")) {
					writer.EndArray();

					pcolarr = nullptr;
					ntotcol = 0;
					return true;
				}	
			}	

			if (ntuples > 0) {
				if (pcolarr == nullptr) {
					GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "Top Aggr Proc DB Response Internal issue : Separator not sent by DB");
				}

				if ((unsigned)nfields > (unsigned)ntotcol) {
					GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "Invalid DB Column count seen for Top Aggr Proc query : %d instead of %d", nfields, ntotcol);
				}	
			}	

			for (int row = 0; row < ntuples; ++row) {
				writer.StartObject();

				for (int col = 0; col < nfields; ++col) {
					const char	*pfname = PQfname(pres, col);

					if (!pfname) {
						break;
					}	

					if (total_rows == 0) {
						// Validate schema
						if (strcmp(pfname, pcolarr[col]->dbcolname)) {
							GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "Invalid DB Column name seen for Top Aggr Proc query : %s instead of %s", 
								pfname, pcolarr[col]->dbcolname);
						}	

						if ((pcolarr[col]->dbstrtype == DB_STR_OCHAR) && (PG_BPCHAROID != PQftype(pres, col))) {
							GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "Invalid DB Column type seen for Top Aggr Proc query : %d instead of %d", 
								PQftype(pres, col), PG_BPCHAROID);
						}	
					}	

					if (pcolarr[col]->szjson == 0) {
						// Ignore this field
						continue;
					}	

					const char 		*pdata;
					int			len = PQgetlength(pres, row, col), rlen;

					if (len == 0) {
						pdata = "";

						if (true == PQgetisnull(pres, row, col)) {
							if (pcolarr[col]->jsontype == JSON_NUMBER) {
								pdata = "0";
								len = 1;
							}	
							else if (pcolarr[col]->jsontype == JSON_BOOL) {
								pdata = "false";
								len = 5;
							}	
						}	
					}
					else {
						pdata = PQgetvalue(pres, row, col);
					}

					if (pcolarr[col]->dbstrtype == DB_STR_OCHAR) {
						rlen = get_rtrim_len(pdata, len);
					}
					else {
						rlen = len;
					}	

					if (pcolarr[col]->dboper) {
						auto p = pcolarr[col]->dboper(pdata, rlen, tbuf, sizeof(tbuf));

						pdata = p.first;
						rlen = p.second;
					}	
					
					writer.Key(pcolarr[col]->jsonfield, pcolarr[col]->szjson);

					if ((pcolarr[col]->jsontype != JSON_STRING) || (pcolarr[col]->dbstrtype == DB_RAW_STRING)) {
						writer.RawValue(pdata, rlen, rapidjson::kNumberType);
					}
					else {
						writer.String(pdata, rlen);
					}	
				}	

				writer.EndObject();

				total_rows++;
			}	

			return true;
		}
	);
	
	auto		expirysec = std::max<int64_t>(30, pquery->get_time_to_expiry(tcurr));

	ret = dbpool.wait_one_response(expirysec * 1000, pconn.getintconn());

	if (ret != 0) {
		if (ret == 2) {
			db_stats_.ndbquery_timeout_.fetch_add_relaxed(1);
		}

		if (writer.get_stream()->reset_if_not_sent(ret == 2 ? ERR_TIMED_OUT : ERR_SYSERROR)) {
			if (ret == 2) {
				constexpr const char errbuf[] = "Top Aggr Proc Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Top Aggr Proc Query : Database Connection Error. Please try later...";

				send_json_error_resp(connshr, ERR_SYSERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}	

			return false;
		}	

		writer.EndObject();

		return false;
	}	

	if (false == qryopt.is_multi_host()) {
		web_db_set_partha_hostinfo(writer, qryopt);
	}

	writer.EndObject();

	return true;
}	

bool MCONN_HANDLER::web_query_top_aggr_procs(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	bool					bret;

	try {
		if (false == qryopt.match_madhava_option(gmadhava_id_str_)) {
			// Skip this query
			writer.StartObject();	
	
			writer.KeyConst("madid");
			writer.String(gmadhava_id_str_, 16);

			writer.EndObject();

			return true;
		}

		if (!qryopt.is_historical()) {
			bret = web_curr_top_aggr_procs(connshr, qryopt, extpool, pquery, writer, pthrpoolarr);
		}
		else {
			bret = web_db_top_aggr_procs(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);

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

bool MCONN_HANDLER::web_curr_top_host_procs(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr)
{
	uint64_t			tcurrusec = get_usec_time(), min_tusec = tcurrusec - 13 * GY_USEC_PER_SEC;
	bool				bret, send_topcpu = false, send_toppgcpu = false, send_toprss = false, send_topfork = false;
	PARTHA_INFO			*prawpartha = nullptr;

	const auto			*poptions = qryopt.get_options_json();

	qryopt.comp_criteria_init();

	if (poptions) {
		const auto	& optobj = poptions->GetObject();
		uint8_t		oset = 0;
		
		if (auto miter = optobj.FindMember("send_topcpu"); (miter != optobj.MemberEnd()) && (miter->value.IsBool())) {
			send_topcpu = miter->value.GetBool();
			oset |= send_topcpu;
		}	
		if (auto miter = optobj.FindMember("send_toppgcpu"); (miter != optobj.MemberEnd()) && (miter->value.IsBool())) {
			send_toppgcpu = miter->value.GetBool();
			oset |= send_toppgcpu;
		}	
		if (auto miter = optobj.FindMember("send_toprss"); (miter != optobj.MemberEnd()) && (miter->value.IsBool())) {
			send_toprss = miter->value.GetBool();
			oset |= send_toprss;
		}	
		if (auto miter = optobj.FindMember("send_topfork"); (miter != optobj.MemberEnd()) && (miter->value.IsBool())) {
			send_topfork = miter->value.GetBool();
			oset |= send_topfork;
		}	

		if (oset == 0) {
			send_topcpu = true;
		}	
	}	
	else {
		send_topcpu = true;
	}	
	
	std::optional<TASK_TOP_PROCS_INFO>	toptasks;

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	const auto lampar = [&](PARTHA_INFO_ELEM *pdatanode, void *arg1, void *arg2) -> CB_RET_E
	{
		bool				bret;

		prawpartha = pdatanode->get_cref().get();

		if (gy_unlikely(prawpartha == nullptr)) {
			GY_THROW_EXPR_CODE(ERR_DATA_NOT_FOUND, "Top Host Procs Query : Partha ID Specified not found or was deleted recently");
		}	

		auto				tlastusec = GY_READ_ONCE(prawpartha->toptasks_.tusec_);

		if (tlastusec < min_tusec) {
			GY_THROW_EXPR_CODE(ERR_DATA_NOT_FOUND, "Top Host Procs Query : Partha Host %s has not updated its data recently", prawpartha->hostname_);
		}	

		toptasks.emplace(prawpartha->toptasks_);

		writer.KeyConst("hostinfo");
		writer.StartObject();

		writer.KeyConst("parid");
		writer.String(prawpartha->machine_id_str_, sizeof(prawpartha->machine_id_str_) - 1);
		
		writer.KeyConst("host");
		writer.String(prawpartha->hostname_, GY_READ_ONCE(prawpartha->hostname_len_));

		writer.KeyConst("madid");
		writer.String(gmadhava_id_str_, 16);

		writer.KeyConst("cluster");
		writer.String(prawpartha->cluster_name_, GY_READ_ONCE(prawpartha->cluster_len_));

		writer.EndObject();

		return CB_OK;
	};
			
	bret = partha_tbl_.lookup_single_elem(qryopt.get_parid(), qryopt.get_parid().get_hash(), lampar);
	
	if (bret == false) {
		GY_THROW_EXPR_CODE(ERR_DATA_NOT_FOUND, "Top Host Procs Query : Partha ID Specified not found or was deleted recently");
	}	
	
	const auto			&topinfo = toptasks->topinfo_;
	const auto			timebuf = gy_localtime_iso8601_sec(toptasks->tusec_/GY_USEC_PER_SEC);

	const JSON_DB_MAPPING		*colarr[MAX_MULTI_HOST_COLUMN_LIST];

	TASK_TOP_PROCS::TOP_TASK	*ptoptask = decltype(ptoptask)(toptasks->topn_data_);

	if (send_topcpu) {
		writer.KeyConst("topcpu");
		writer.StartArray();

		auto [ncol, colspec] 		= qryopt.get_column_list(colarr, GY_ARRAY_SIZE(colarr), SUBSYS_TOPCPU, true /* ign_col_list */);

		for (uint32_t i = 0; i < topinfo.nprocs_; ++i, ++ptoptask) {
			TopCpuRssFields(*prawpartha, *ptoptask, gmadhava_id_str_, i + 1, SUBSYS_TOPCPU).print_json(colarr, ncol, writer, timebuf.get());
		}	
		
		writer.EndArray();
	}
	else {
		ptoptask += topinfo.nprocs_;
	}	

	TASK_TOP_PROCS::TOP_PG_TASK	*ptoppgtask = decltype(ptoppgtask)(ptoptask);
	
	if (send_toppgcpu) {
		writer.KeyConst("toppgcpu");
		writer.StartArray();

		auto [ncol, colspec] 		= qryopt.get_column_list(colarr, GY_ARRAY_SIZE(colarr), SUBSYS_TOPPGCPU, true /* ign_col_list */);

		for (uint32_t i = 0; i < topinfo.npg_procs_; ++i, ++ptoppgtask) {
			TopPgCpuFields(*prawpartha, *ptoppgtask, gmadhava_id_str_, i + 1).print_json(colarr, ncol, writer, timebuf.get());
		}	
		
		writer.EndArray();
	}
	else {
		ptoppgtask += topinfo.npg_procs_;
	}	

	TASK_TOP_PROCS::TOP_TASK	*ptoprsstask = decltype(ptoprsstask)(ptoppgtask);
	
	if (send_toprss) {
		writer.KeyConst("toprss");
		writer.StartArray();

		auto [ncol, colspec] 		= qryopt.get_column_list(colarr, GY_ARRAY_SIZE(colarr), SUBSYS_TOPRSS, true /* ign_col_list */);

		for (uint32_t i = 0; i < topinfo.nrss_procs_; ++i, ++ptoprsstask) {
			TopCpuRssFields(*prawpartha, *ptoprsstask, gmadhava_id_str_, i + 1, SUBSYS_TOPRSS).print_json(colarr, ncol, writer, timebuf.get());
		}	
		
		writer.EndArray();
	}
	else {
		ptoprsstask += topinfo.nrss_procs_;
	}	

	TASK_TOP_PROCS::TOP_FORK_TASK	*ptopforktask = decltype(ptopforktask)(ptoprsstask);

	if (send_topfork) {
		writer.KeyConst("topfork");
		writer.StartArray();

		auto [ncol, colspec] 		= qryopt.get_column_list(colarr, GY_ARRAY_SIZE(colarr), SUBSYS_TOPFORK, true /* ign_col_list */);

		for (uint32_t i = 0; i < topinfo.nfork_procs_; ++i, ++ptopforktask) {
			TopForkFields(*prawpartha, *ptopforktask, gmadhava_id_str_, i + 1).print_json(colarr, ncol, writer, timebuf.get());
		}

		writer.EndArray();
	}
	else {
		ptopforktask += topinfo.nfork_procs_;
	}	

	writer.EndObject();

	return true;
}


bool MCONN_HANDLER::web_db_top_host_procs(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Top Host Procs query\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Top Host Procs Query : Database Querying Error : Failed to get an idle connection. Please try later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	int				ret;
	bool				bret, send_topcpu = false, send_toppgcpu = false, send_toprss = false, send_topfork = false;
	time_t				tcurr = time(nullptr);
	struct timeval			tvstart = qryopt.get_start_timeval(), tvend = qryopt.get_end_timeval();

	if (tcurr - db_storage_days_ * GY_SEC_PER_DAY > (uint64_t)tvend.tv_sec) {
		char			ebuf[256];
		size_t			esz;
		
		esz = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Top Host Procs Query : Time Requested not present in DB : Max Days of DB storage = %u", db_storage_days_);

		if (writer.get_stream()->reset_if_not_sent(ERR_DATA_NOT_FOUND)) {
			send_json_error_resp(connshr, ERR_DATA_NOT_FOUND, pquery->get_seqid(), ebuf, esz, pthrpoolarr);
		}

		return false;
	}	
	
	auto 				datetbl = get_db_day_partition(tvstart.tv_sec, tvend.tv_sec, 0);

	const auto			*poptions = qryopt.get_options_json();

	if (poptions) {
		const auto	& optobj = poptions->GetObject();
		uint8_t		oset = 0;
		
		if (auto miter = optobj.FindMember("send_topcpu"); (miter != optobj.MemberEnd()) && (miter->value.IsBool())) {
			send_topcpu = miter->value.GetBool();
			oset |= send_topcpu;
		}	
		if (auto miter = optobj.FindMember("send_toppgcpu"); (miter != optobj.MemberEnd()) && (miter->value.IsBool())) {
			send_toppgcpu = miter->value.GetBool();
			oset |= send_toppgcpu;
		}	
		if (auto miter = optobj.FindMember("send_toprss"); (miter != optobj.MemberEnd()) && (miter->value.IsBool())) {
			send_toprss = miter->value.GetBool();
			oset |= send_toprss;
		}	

		if (auto miter = optobj.FindMember("send_topfork"); (miter != optobj.MemberEnd()) && (miter->value.IsBool())) {
			send_topfork = miter->value.GetBool();
			oset |= send_topfork;
		}	

		if (oset == 0) {
			send_topcpu = true;
		}	
	}	
	else {
		send_topcpu = true;
	}	
	
	{
		STRING_BUFFER<48 * 1024>	strbuf;
		char				tablename[128];

		if (send_topcpu) {
			strbuf.appendconst("select \'topcpu\'::text as separator_topcpu;");
			snprintf(tablename, sizeof(tablename), "sch%s.topcputbl%s", qryopt.get_parid_str().get(), datetbl.get());

			qryopt.get_db_select_query(strbuf, SUBSYS_TOPCPU, tablename, "", true /* ign_col_list */);

			strbuf.appendconst(";select \'completed\'::text as separator;");
		}

		if (send_toppgcpu) {
			strbuf.appendconst("select \'toppgcpu\'::text as separator_toppgcpu;");
			snprintf(tablename, sizeof(tablename), "sch%s.toppgcputbl%s", qryopt.get_parid_str().get(), datetbl.get());
			qryopt.get_db_select_query(strbuf, SUBSYS_TOPPGCPU, tablename, "", true /* ign_col_list */);
			strbuf.appendconst(";select \'completed\'::text as separator;");
		}

		if (send_toprss) {
			strbuf.appendconst("select \'toprss\'::text as separator_toprss;");
			snprintf(tablename, sizeof(tablename), "sch%s.toprsstbl%s", qryopt.get_parid_str().get(), datetbl.get());

			qryopt.get_db_select_query(strbuf, SUBSYS_TOPRSS, tablename, "", true /* ign_col_list */);

			strbuf.appendconst(";select \'completed\'::text as separator;");
		}

		if (send_topfork) {
			strbuf.appendconst("select \'topfork\'::text as separator_topfork;");
			snprintf(tablename, sizeof(tablename), "sch%s.topforktbl%s", qryopt.get_parid_str().get(), datetbl.get());

			qryopt.get_db_select_query(strbuf, SUBSYS_TOPFORK, tablename, "", true /* ign_col_list */);

			strbuf.appendconst(";select \'completed\'::text as separator;");
		}

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}	

	if (bret == false) {
		constexpr const char errbuf[] = "Top Host Procs Query : Failed to schedule query to Database. Please retry later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, total_rows = 0, ntotcol = 0, pcolarr = (const JSON_DB_MAPPING *)nullptr](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			if (is_completed) {
				conn.make_available();
				return true;
			}	
			
			if (true == gyres.is_error()) {
				DEBUGEXECN(10,
					WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to query Top Host Procs from DB due to %s (Total tuples returned so far %d)\n", 
							gyres.get_error_msg(), total_rows);
				);

				if (0 == strcmp(gyres.get_sqlcode(), "42P01")) {
					GY_THROW_EXPR_CODE(ERR_DATA_NOT_FOUND, "Failed to query Top Host Procs from DB for the time range specified as no data present");
				}	

				GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "Failed to query Top Host Procs from DB due to %s", gyres.get_error_msg());
			}	

			char				tbuf[512];
			const PGresult *		pres = gyres.get();
			const int			nfields = PQnfields(pres);
			const int			ntuples = PQntuples(gyres.get());

			if (nfields == 1 && ntuples == 1) {
				const char	*pfname = PQfname(pres, 0);

				if (!pfname) {
					return false;
				}	
				
				if (0 == strncmp(pfname, "separator_", GY_CONST_STRLEN("separator_"))) {
					const char 		*pkey = pfname + GY_CONST_STRLEN("separator_");

					writer.Key(pkey);

					if (0 == strcmp(pkey, "topcpu")) {
						pcolarr = json_db_topcpu_arr;
						ntotcol = GY_ARRAY_SIZE(json_db_topcpu_arr);

						writer.StartArray();
					}
					else if (0 == strcmp(pkey, "toppgcpu")) {
						pcolarr = json_db_toppgcpu_arr;
						ntotcol = GY_ARRAY_SIZE(json_db_toppgcpu_arr);

						writer.StartArray();
					}
					else if (0 == strcmp(pkey, "toprss")) {
						pcolarr = json_db_toprss_arr;
						ntotcol = GY_ARRAY_SIZE(json_db_toprss_arr);

						writer.StartArray();
					}
					else if (0 == strcmp(pkey, "topfork")) {
						pcolarr = json_db_topfork_arr;
						ntotcol = GY_ARRAY_SIZE(json_db_topfork_arr);

						writer.StartArray();
					}
					else {
						return false;
					}	
					total_rows = 0;

					return true;
				}	
				else if (0 == strcmp(pfname, "separator")) {
					writer.EndArray();

					pcolarr = nullptr;
					ntotcol = 0;
					return true;
				}	
			}	

			if (ntuples > 0) {
				if (pcolarr == nullptr) {
					GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "Top Host Procs DB Response Internal issue : Separator not sent by DB");
				}

				if ((unsigned)nfields > (unsigned)ntotcol) {
					GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "Invalid DB Column count seen for Top Host Procs query : %d instead of %d", nfields, ntotcol);
				}	
			}	

			for (int row = 0; row < ntuples; ++row) {
				writer.StartObject();

				for (int col = 0; col < nfields; ++col) {
					const char	*pfname = PQfname(pres, col);

					if (!pfname) {
						break;
					}	

					if (total_rows == 0) {
						// Validate schema
						if (strcmp(pfname, pcolarr[col].dbcolname)) {
							GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "Invalid DB Column name seen for Top Host Procs query : %s instead of %s", 
								pfname, pcolarr[col].dbcolname);
						}	

						if ((pcolarr[col].dbstrtype == DB_STR_OCHAR) && (PG_BPCHAROID != PQftype(pres, col))) {
							GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "Invalid DB Column type seen for Top Host Procs query : %d instead of %d", 
								PQftype(pres, col), PG_BPCHAROID);
						}	
					}	

					if (pcolarr[col].szjson == 0) {
						// Ignore this field
						continue;
					}	

					const char 		*pdata;
					int			len = PQgetlength(pres, row, col), rlen;

					if (len == 0) {
						pdata = "";

						if (true == PQgetisnull(pres, row, col)) {
							if (pcolarr[col].jsontype == JSON_NUMBER) {
								pdata = "0";
								len = 1;
							}	
							else if (pcolarr[col].jsontype == JSON_BOOL) {
								pdata = "false";
								len = 5;
							}	
						}	
					}
					else {
						pdata = PQgetvalue(pres, row, col);
					}

					if (pcolarr[col].dbstrtype == DB_STR_OCHAR) {
						rlen = get_rtrim_len(pdata, len);
					}
					else {
						rlen = len;
					}	

					if (pcolarr[col].dboper) {
						auto p = pcolarr[col].dboper(pdata, rlen, tbuf, sizeof(tbuf));

						pdata = p.first;
						rlen = p.second;
					}	
					
					writer.Key(pcolarr[col].jsonfield, pcolarr[col].szjson);

					if ((pcolarr[col].jsontype != JSON_STRING) || (pcolarr[col].dbstrtype == DB_RAW_STRING)) {
						writer.RawValue(pdata, rlen, rapidjson::kNumberType);
					}
					else {
						writer.String(pdata, rlen);
					}	
				}	

				writer.EndObject();

				total_rows++;
			}	

			return true;
		}
	);
	
	auto		expirysec = std::max<int64_t>(30, pquery->get_time_to_expiry(tcurr));

	ret = dbpool.wait_one_response(expirysec * 1000, pconn.getintconn());

	if (ret != 0) {
		if (ret == 2) {
			db_stats_.ndbquery_timeout_.fetch_add_relaxed(1);
		}

		if (writer.get_stream()->reset_if_not_sent(ret == 2 ? ERR_TIMED_OUT : ERR_SYSERROR)) {
			if (ret == 2) {
				constexpr const char errbuf[] = "Top Host Procs Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Top Host Procs Query : Database Connection Error. Please try later...";

				send_json_error_resp(connshr, ERR_SYSERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}	

			return false;
		}	

		writer.EndObject();

		return false;
	}	

	web_db_set_partha_hostinfo(writer, qryopt);

	writer.EndObject();

	return true;
}	

bool MCONN_HANDLER::web_query_top_host_procs(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	bool					bret;

	try {
		if (false == qryopt.match_madhava_option(gmadhava_id_str_)) {
			// Skip this query
			writer.StartObject();	
	
			writer.KeyConst("madid");
			writer.String(gmadhava_id_str_, 16);

			writer.EndObject();

			return true;
		}

		if (qryopt.is_multi_host()) {
			constexpr const char errbuf[] = "Top Host Procs Query : Multi Host Querying not currently supported. Please specify the parid Partha ID param";

			if (writer.get_stream()->reset_if_not_sent(ERR_INVALID_REQUEST)) {
				send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}

			return false;
		}

		if (!qryopt.is_historical()) {
			bret = web_curr_top_host_procs(connshr, qryopt, extpool, pquery, writer, pthrpoolarr);
		}
		else {
			bret = web_db_top_host_procs(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);
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

bool MCONN_HANDLER::web_curr_proc_state(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, bool is_extended)
{
	uint64_t			maxrecs = qryopt.get_max_records(), nrecs = 0;
	const auto			& critset = qryopt.get_filter_criteria();
	bool				bret, is_multi_host = qryopt.is_multi_host();
	time_t				tcurr = time(nullptr);
	uint64_t 			min_stats_tusec = GY_USEC_CONVERT(tcurr - 15, 0);
	SUBSYS_CLASS_E			subsys = (false == is_extended ? SUBSYS_PROCSTATE : SUBSYS_EXTPROCSTATE);

	qryopt.comp_criteria_init();

	const JSON_DB_MAPPING		*colarr[MAX_MULTI_HOST_COLUMN_LIST];
	
	auto [ncol, colspec] = qryopt.get_all_column_list(colarr, GY_ARRAY_SIZE(colarr), subsys);

	const auto sendproc = [&, min_stats_tusec, tcurr, colarr, ncol](const MAGGR_TASK & mtask, const PARTHA_INFO & rawpartha, bool check_filter = false) -> bool
	{
		const AGGR_TASK_STATE_NOTIFY 	& state = mtask.task_issue_.task_state_;
		uint64_t			tusec = GY_READ_ONCE(mtask.task_issue_.last_usec_time_);

		if (tusec < min_stats_tusec) {
			return false;
		}	
		
		std::optional<ProcStateFields>		procstate;
		std::optional<ExtProcStateFields>	extprocstate;
		
		if (!is_extended) {
			procstate.emplace(rawpartha, mtask, gmadhava_id_str_, tcurr);
		}
		else {
			extprocstate.emplace(rawpartha, mtask, gmadhava_id_str_, tcurr);
		}	

		if (check_filter && qryopt.has_filter()) {
			CRIT_RET_E 			cret;
			
			if (procstate) {
				cret = procstate->filter_match(qryopt.get_filter_criteria());
			}	
			else {
				cret = extprocstate->filter_match(qryopt.get_filter_criteria());
			}	

			if (cret == CRIT_FAIL) {
				return false;
			}
		}	

		nrecs++;

		if (procstate) {
			procstate->print_json(colarr, ncol, writer);
		}	
		else {
			extprocstate->print_json(colarr, ncol, writer);
		}	

		return true;
	};	


	const auto procl = [&](MSOCKET_HDLR::MAGGR_TASK_ELEM_TYPE *pdatanode, void *arg)
	{
		const auto			ptask = pdatanode->get_cref().get();
		const PARTHA_INFO		*prawpartha = (const PARTHA_INFO *)arg;

		if (!ptask || !prawpartha) {
			return CB_OK;
		}

		sendproc(*ptask, *prawpartha, true /* check_filter */);

		if (nrecs >= maxrecs) {
			return CB_BREAK_LOOP;
		}	

		return CB_OK;
	};	

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	if (!is_multi_host) {
		RCU_LOCK_SLOW			slowlock;

		PARTHA_INFO			*prawpartha;

		const auto pelem = partha_tbl_.lookup_single_elem_locked(qryopt.get_parid(), qryopt.get_parid().get_hash());
			
		if (pelem == nullptr) {
			GY_THROW_EXPR_CODE(ERR_DATA_NOT_FOUND, "Process State Query : Partha ID Specified not found or was deleted recently");
		}	

		prawpartha = pelem->get_cref().get();

		if (prawpartha == nullptr) {
			GY_THROW_EXPR_CODE(ERR_DATA_NOT_FOUND, "Process State Query : Partha ID Specified was deleted recently");
		}	
		
		writer.KeyConst("hostinfo");
		writer.StartObject();

		writer.KeyConst("parid");
		writer.String(prawpartha->machine_id_str_, sizeof(prawpartha->machine_id_str_) - 1);
			
		writer.KeyConst("host");
		writer.String(prawpartha->hostname_, GY_READ_ONCE(prawpartha->hostname_len_));

		writer.KeyConst("madid");
		writer.String(gmadhava_id_str_, 16);

		writer.KeyConst("cluster");
		writer.String(prawpartha->cluster_name_, GY_READ_ONCE(prawpartha->cluster_len_));

		writer.EndObject();

		if (!is_extended) {
			writer.KeyConst("procstate");
		}
		else {
			writer.KeyConst("extprocstate");
		}	
		writer.StartArray();

		/*
		 * We first search if only procid filters specified. 
		 */
		if (qryopt.has_filter() && critset.is_only_l1() && critset.is_l1_oper_or() && critset.has_subsystem(subsys, true /* match_all */)) {
			const auto 		& l1_grp = critset.l1_grp_;
			uint32_t		neval = 0;

			// First validate
			for (uint32_t i = 0; i < l1_grp.ncrit_; ++i) {
				const auto		pcrit = l1_grp.pcritarr_ + i;
				
				if (subsys != pcrit->get_subsys()) {
					neval = 0;
					break;
				}

				if (FIELD_PROCID != pcrit->get_field_crc()) {
					neval = 0;
					break;
				}	

				if (!((COMP_EQ == pcrit->get_comparator()) || (COMP_IN == pcrit->get_comparator()))) {
					neval = 0;
					break;
				}	

				if (false == pcrit->is_value_string() || true == pcrit->is_value_expression()) {
					neval = 0;
					break;
				}

				neval++;
			}
		
			if (neval) {
				for (uint32_t i = 0; i < l1_grp.ncrit_; ++i) {
					const auto		pcrit = l1_grp.pcritarr_ + i;
					auto [pstrarr, nstr] 	= pcrit->get_str_values();

					if (!pstrarr) {
						continue;
					}	

					for (uint32_t i = 0; i < nstr; i++) {
						uint64_t			aggr_task_id;
						int				ret;
						
						if (pstrarr[i].size() != 16) {
							continue;
						}	

						if (!string_to_number(pstrarr[i].get(), aggr_task_id, nullptr, 16)) {
							continue;
						}	

						const uint32_t			lhash = get_uint64_hash(aggr_task_id);
						MAGGR_TASK_ELEM_TYPE		*ptaskelem;
						MAGGR_TASK			*ptask;
					
						ptaskelem = prawpartha->task_aggr_tbl_.lookup_single_elem_locked(aggr_task_id, lhash);

						if (gy_unlikely(ptaskelem == nullptr)) {
							continue;
						}	
						
						ptask = ptaskelem->get_cref().get();

						if (gy_unlikely(ptask == nullptr)) {
							continue;
						}	

						sendproc(*ptask, *prawpartha, true /* check_filter */);

						if (nrecs >= maxrecs) {
							goto doneproc;
						}	
					}
				}	

doneproc:
				writer.EndArray();
				goto done;
			}	
		}

		// Walk through entire list of aggr task procs for this partha
		prawpartha->task_aggr_tbl_.walk_hash_table_const(procl, prawpartha);

		writer.EndArray();
		goto done;
	}
	else  {

		const auto lampar = [&, ishostfil = critset.has_subsystem(SUBSYS_HOST)](PARTHA_INFO_ELEM *pelem, void *arg) -> CB_RET_E
		{
			auto				prawpartha = pelem->get_cref().get();

			if (gy_unlikely(prawpartha == nullptr)) {
				return CB_OK;
			}	

			if (ishostfil) {
				auto 			cret = HostFields(*prawpartha, gmadhava_id_str_).filter_match(critset);

				if (cret == CRIT_FAIL) {
					return CB_OK;
				}
			}

			prawpartha->task_aggr_tbl_.walk_hash_table_const(procl, prawpartha);
			
			if (nrecs >= maxrecs) {
				return CB_BREAK_LOOP;
			}	

			return CB_OK;
		};	

		if (!is_extended) {
			writer.KeyConst("procstate");
		}
		else {
			writer.KeyConst("extprocstate");
		}	
		writer.StartArray();

		partha_tbl_.walk_hash_table_const(lampar);

		writer.EndArray();
	}	

done :
	writer.EndObject();

	return true;
}

bool MCONN_HANDLER::web_db_detail_proc_state(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool, bool is_extended)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Process State\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Process State Query : Database Querying Error : Failed to get an idle connection. Please try later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	int				ret;
	bool				bret;
	time_t				tcurr = time(nullptr);
	struct timeval			tvstart = qryopt.get_start_timeval(), tvend = qryopt.get_end_timeval();

	if (tcurr - db_storage_days_ * GY_SEC_PER_DAY > (uint64_t)tvend.tv_sec) {
		char			ebuf[256];
		size_t			esz;
		
		esz = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Process State Query : Time Requested not present in DB : Max Days of DB storage = %u", db_storage_days_);

		if (writer.get_stream()->reset_if_not_sent(ERR_DATA_NOT_FOUND)) {
			send_json_error_resp(connshr, ERR_DATA_NOT_FOUND, pquery->get_seqid(), ebuf, esz, pthrpoolarr);
		}

		return false;
	}	

	SUBSYS_CLASS_E			subsys = (false == is_extended ? SUBSYS_PROCSTATE : SUBSYS_EXTPROCSTATE);
	const char			*proctbl = (false == is_extended ? "aggrtaskstatetbl" : "extaggrtaskstatetbl");

	auto 				datetbl = get_db_day_partition(tvstart.tv_sec, tvend.tv_sec, is_extended ? 305 : 0);

	const JSON_DB_MAPPING		*colarr[MAX_MULTI_HOST_COLUMN_LIST];
	
	auto [ncol, colspec] 		= qryopt.get_all_column_list(colarr, GY_ARRAY_SIZE(colarr), subsys);

	if (qryopt.is_multi_host()) {
		STRING_BUFFER<48 * 1024>		strbuf;
		
		qryopt.get_db_select_multihost_query(strbuf, subsys, proctbl, datetbl.get());

		strbuf.appendconst(";\n reset search_path; ");

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}
	else {
		STRING_BUFFER<48 * 1024>	strbuf;
		char				tablename[128];

		snprintf(tablename, sizeof(tablename), "sch%s.%s%s", qryopt.get_parid_str().get(), proctbl, datetbl.get());

		qryopt.get_db_select_query(strbuf, subsys, tablename);

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}	

	if (bret == false) {
		constexpr const char errbuf[] = "Process State Query : Failed to schedule query to Database. Please retry later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	if (!is_extended) {
		writer.KeyConst("procstate");
	}
	else {
		writer.KeyConst("extprocstate");
	}	
	writer.StartArray();

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, this, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_json_cb(conn, std::move(gyres), is_completed, "Process State", colarr, ncol, writer, total_rows, noextracolcb);
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
				constexpr const char errbuf[] = "Process State Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Process State Query : Database Connection Error. Please try later...";

				send_json_error_resp(connshr, ERR_SYSERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}	

			return false;
		}	

		writer.EndArray();
		writer.EndObject();
		
		return false;
	}	

	writer.EndArray();

	if (false == qryopt.is_multi_host()) {
		web_db_set_partha_hostinfo(writer, qryopt);
	}

	writer.EndObject();

	return true;
}

bool MCONN_HANDLER::web_db_aggr_proc_state(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool, bool is_extended)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Aggregated Process State\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Aggregated Process State Query : Database Querying Error : Failed to get an idle connection. Please try later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	int				ret;
	bool				bret;
	time_t				tcurr = time(nullptr);
	struct timeval			tvstart = qryopt.get_start_timeval(), tvend = qryopt.get_end_timeval();

	if (tcurr - db_storage_days_ * GY_SEC_PER_DAY > (uint64_t)tvend.tv_sec) {
		char			ebuf[256];
		size_t			esz;
		
		esz = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Aggregated Process State Query : Time Requested not present in DB : Max Days of DB storage = %u", db_storage_days_);

		if (writer.get_stream()->reset_if_not_sent(ERR_DATA_NOT_FOUND)) {
			send_json_error_resp(connshr, ERR_DATA_NOT_FOUND, pquery->get_seqid(), ebuf, esz, pthrpoolarr);
		}

		return false;
	}	

	auto 				datetbl = get_db_day_partition(tvstart.tv_sec, tvend.tv_sec, is_extended ? 305 : 0);

	const JSON_DB_MAPPING		*colarr[QUERY_OPTIONS::MAX_AGGR_COLUMNS];
	JSON_DB_MAPPING			acolarr[QUERY_OPTIONS::MAX_AGGR_COLUMNS];
	uint32_t			ncol;

	assert(gy_get_thread_local().get_thread_stack_freespace() >= 256 * 1024);

	if (true) {
		STRING_BUFFER<48 * 1024>		strbuf;
		
		ncol = get_procstate_aggr_query(strbuf, qryopt, datetbl.get(), acolarr, nullptr, is_extended);
			
		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());

		if (bret == false) {
			constexpr const char errbuf[] = "Aggregated Process State Query : Failed to schedule query to Database. Please retry later...";

			if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
				send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}

			return false;
		}	

		for (uint32_t i = 0; i < ncol; ++i) {
			colarr[i] = acolarr + i;
		}	
	}	

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	if (!is_extended) {
		writer.KeyConst("procstate");
	}
	else {
		writer.KeyConst("extprocstate");
	}	
	writer.StartArray();

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, this, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_json_cb(conn, std::move(gyres), is_completed, "Aggregated Process State", colarr, ncol, writer, total_rows, noextracolcb);
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
				constexpr const char errbuf[] = "Aggregated Process State Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Aggregated Process State Query : Database Connection Error. Please try later...";

				send_json_error_resp(connshr, ERR_SYSERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}	

			return false;
		}	

		writer.EndArray();
		writer.EndObject();
		
		return false;
	}	

	writer.EndArray();

	if (false == qryopt.is_multi_host()) {
		web_db_set_partha_hostinfo(writer, qryopt);
	}

	set_json_column_list(writer, colarr, ncol);

	writer.EndObject();

	return true;
}

bool MCONN_HANDLER::web_query_proc_state(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool, bool is_extended)
{
	bool			bret, is_aggregated = qryopt.is_aggregated();

	try {
		if (false == qryopt.match_madhava_option(gmadhava_id_str_)) {
			// Skip this query
			writer.StartObject();	
	
			writer.KeyConst("madid");
			writer.String(gmadhava_id_str_, 16);

			writer.EndObject();

			return true;
		}

		const auto			& critset = qryopt.get_filter_criteria();
		bool				is_multi_host = qryopt.is_multi_host();

		if (!qryopt.is_historical()) {
			bret = web_curr_proc_state(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, is_extended);
		}
		else {
			if (false == is_aggregated) {
				bret = web_db_detail_proc_state(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool, is_extended);
			}
			else {
				bret = web_db_aggr_proc_state(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool, is_extended);
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


bool MCONN_HANDLER::web_curr_proc_info(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr)
{
	uint64_t			maxrecs = qryopt.get_max_records(), nrecs = 0;
	const auto			& critset = qryopt.get_filter_criteria();
	bool				bret, is_multi_host = qryopt.is_multi_host();
	const auto			timebuf = gy_localtime_iso8601_sec(time(nullptr));

	qryopt.comp_criteria_init();

	const JSON_DB_MAPPING		*colarr[MAX_MULTI_HOST_COLUMN_LIST];
	
	auto [ncol, colspec] = qryopt.get_all_column_list(colarr, GY_ARRAY_SIZE(colarr), SUBSYS_PROCINFO);

	const auto sendproc = [&, colarr, ncol](const MAGGR_TASK & mtask, const PARTHA_INFO & rawpartha, bool check_filter = false) -> bool
	{
		ProcInfoFields			procinfofields(rawpartha, mtask, gmadhava_id_str_);

		if (check_filter && qryopt.has_filter()) {
			auto 			cret = procinfofields.filter_match(qryopt.get_filter_criteria());

			if (cret == CRIT_FAIL) {
				return false;
			}
		}	
		
		nrecs++;

		procinfofields.print_json(colarr, ncol, writer, timebuf.get());

		return true;
	};	
	
	const auto procl = [&](MSOCKET_HDLR::MAGGR_TASK_ELEM_TYPE *pdatanode, void *arg)
	{
		const auto			ptask = pdatanode->get_cref().get();
		const PARTHA_INFO		*prawpartha = (const PARTHA_INFO *)arg;

		if (!ptask || !prawpartha) {
			return CB_OK;
		}

		sendproc(*ptask, *prawpartha, true /* check_filter */);

		if (nrecs >= maxrecs) {
			return CB_BREAK_LOOP;
		}	

		return CB_OK;
	};	

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	if (!is_multi_host) {
		RCU_LOCK_SLOW			slowlock;

		PARTHA_INFO			*prawpartha;

		const auto pelem = partha_tbl_.lookup_single_elem_locked(qryopt.get_parid(), qryopt.get_parid().get_hash());
			
		if (pelem == nullptr) {
			GY_THROW_EXPR_CODE(ERR_DATA_NOT_FOUND, "Process Info Query : Partha ID Specified not found or was deleted recently");
		}	

		prawpartha = pelem->get_cref().get();

		if (prawpartha == nullptr) {
			GY_THROW_EXPR_CODE(ERR_DATA_NOT_FOUND, "Process Info Query : Partha ID Specified was deleted recently");
		}	
		
		writer.KeyConst("hostinfo");
		writer.StartObject();

		writer.KeyConst("parid");
		writer.String(prawpartha->machine_id_str_, sizeof(prawpartha->machine_id_str_) - 1);
			
		writer.KeyConst("host");
		writer.String(prawpartha->hostname_, GY_READ_ONCE(prawpartha->hostname_len_));

		writer.KeyConst("madid");
		writer.String(gmadhava_id_str_, 16);

		writer.KeyConst("cluster");
		writer.String(prawpartha->cluster_name_, GY_READ_ONCE(prawpartha->cluster_len_));

		writer.EndObject();

		writer.KeyConst("procinfo");
		writer.StartArray();

		/*
		 * We first search if only procid filters specified. 
		 */
		if (qryopt.has_filter() && critset.is_only_l1() && critset.is_l1_oper_or() && critset.has_subsystem(SUBSYS_PROCINFO, true /* match_all */)) {
			const auto 		& l1_grp = critset.l1_grp_;
			uint32_t		neval = 0;

			// First validate
			for (uint32_t i = 0; i < l1_grp.ncrit_; ++i) {
				const auto		pcrit = l1_grp.pcritarr_ + i;
				
				if (SUBSYS_PROCINFO != pcrit->get_subsys()) {
					neval = 0;
					break;
				}

				if (FIELD_PROCID != pcrit->get_field_crc()) {
					neval = 0;
					break;
				}	

				if (!((COMP_EQ == pcrit->get_comparator()) || (COMP_IN == pcrit->get_comparator()))) {
					neval = 0;
					break;
				}	

				if (false == pcrit->is_value_string() || true == pcrit->is_value_expression()) {
					neval = 0;
					break;
				}

				neval++;
			}
		
			if (neval) {
				for (uint32_t i = 0; i < l1_grp.ncrit_; ++i) {
					const auto		pcrit = l1_grp.pcritarr_ + i;
					auto [pstrarr, nstr] 	= pcrit->get_str_values();

					if (!pstrarr) {
						continue;
					}	

					for (uint32_t i = 0; i < nstr; i++) {
						uint64_t			aggr_task_id;
						int				ret;
						
						if (pstrarr[i].size() != 16) {
							continue;
						}	

						if (!string_to_number(pstrarr[i].get(), aggr_task_id, nullptr, 16)) {
							continue;
						}	

						const uint32_t			lhash = get_uint64_hash(aggr_task_id);
						MAGGR_TASK_ELEM_TYPE		*ptaskelem;
						MAGGR_TASK			*ptask;
					
						ptaskelem = prawpartha->task_aggr_tbl_.lookup_single_elem_locked(aggr_task_id, lhash);

						if (gy_unlikely(ptaskelem == nullptr)) {
							continue;
						}	
						
						ptask = ptaskelem->get_cref().get();

						if (gy_unlikely(ptask == nullptr)) {
							continue;
						}	

						sendproc(*ptask, *prawpartha, true /* check_filter */);

						if (nrecs >= maxrecs) {
							goto doneproc;
						}	
					}
				}	

doneproc:
				writer.EndArray();
				goto done;
			}	
		}

		// Walk through entire list of aggr task procs for this partha
		prawpartha->task_aggr_tbl_.walk_hash_table_const(procl, prawpartha);

		writer.EndArray();
		goto done;
	}
	else {
		const auto lampar = [&, ishostfil = critset.has_subsystem(SUBSYS_HOST)](PARTHA_INFO_ELEM *pelem, void *arg) -> CB_RET_E
		{
			auto				prawpartha = pelem->get_cref().get();

			if (gy_unlikely(prawpartha == nullptr)) {
				return CB_OK;
			}	

			if (ishostfil) {
				auto 			cret = HostFields(*prawpartha, gmadhava_id_str_).filter_match(critset);

				if (cret == CRIT_FAIL) {
					return CB_OK;
				}
			}

			prawpartha->task_aggr_tbl_.walk_hash_table_const(procl, prawpartha);
			
			if (nrecs >= maxrecs) {
				return CB_BREAK_LOOP;
			}	

			return CB_OK;
		};	

		writer.KeyConst("procinfo");
		writer.StartArray();

		partha_tbl_.walk_hash_table_const(lampar);

		writer.EndArray();
	}	

done :
	writer.EndObject();

	return true;
}

bool MCONN_HANDLER::web_db_proc_info(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Process Info\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Process Info Query : Database Querying Error : Failed to get an idle connection. Please try later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	int				ret;
	bool				bret, origpointintime = qryopt.is_pointintime(), pointintime = origpointintime, multihost = qryopt.is_multi_host(), updqryopt = false;
	time_t				tcurr = time(nullptr);
	struct timeval			tvstart, tvend, origtvstart, origtvend;
	char				origstarttime[48], origendtime[48];
	
	GY_SCOPE_EXIT {
		if (updqryopt == true) {
			qryopt.set_timestamps(origstarttime, origendtime, origtvstart, origtvend, origpointintime);
		}
	};	

	tvstart = qryopt.get_start_timeval(); 
	tvend 	= qryopt.get_end_timeval();

	if (tvend.tv_sec - tvstart.tv_sec < (int64_t)INFO_DB_UPDATE_SEC) {
		origtvstart	= tvstart;
		origtvend	= tvend;
		GY_STRNCPY(origstarttime, qryopt.get_starttime(), sizeof(origstarttime));
		GY_STRNCPY(origendtime, qryopt.get_endtime(), sizeof(origendtime));
		updqryopt	= true;
		
		tvstart.tv_sec = tvend.tv_sec - INFO_DB_UPDATE_SEC;
		tvend.tv_sec += INFO_DB_UPDATE_SEC/3;
		qryopt.set_timestamps(gy_localtime_iso8601_sec(tvstart.tv_sec).get(), gy_localtime_iso8601_sec(tvend.tv_sec).get(), tvstart, tvend, true /* pointintime */);
	
		pointintime 	= true;
	}	

	auto 				datetbl = get_db_day_partition(tvstart.tv_sec, tvend.tv_sec, 0);

	const JSON_DB_MAPPING		*colarr[MAX_MULTI_HOST_COLUMN_LIST];
	
	auto [ncol, colspec] 		= qryopt.get_all_column_list(colarr, GY_ARRAY_SIZE(colarr), SUBSYS_PROCINFO);

	if (tcurr - db_storage_days_ * GY_SEC_PER_DAY > (uint64_t)tvend.tv_sec) {
		char			ebuf[256];
		size_t			esz;
		
		esz = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Process Info Query : Time Requested not present in DB : Max Days of DB storage = %u", db_storage_days_);

		if (writer.get_stream()->reset_if_not_sent(ERR_DATA_NOT_FOUND)) {
			send_json_error_resp(connshr, ERR_DATA_NOT_FOUND, pquery->get_seqid(), ebuf, esz, pthrpoolarr);
		}

		return false;
	}	
	
	if (multihost) {
		STRING_BUFFER<48 * 1024>		strbuf;
		
		qryopt.get_db_select_multihost_query(strbuf, SUBSYS_PROCINFO, "aggrtaskinfotbl", datetbl.get());

		strbuf.appendconst(";\n reset search_path; ");

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}
	else {
		STRING_BUFFER<48 * 1024>	strbuf;
		char				tablename[128];

		snprintf(tablename, sizeof(tablename), "sch%s.aggrtaskinfotbl%s", qryopt.get_parid_str().get(), datetbl.get());

		qryopt.get_db_select_query(strbuf, SUBSYS_PROCINFO, tablename);

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}	

	if (bret == false) {
		constexpr const char errbuf[] = "Process Info Query : Failed to schedule query to Database. Please retry later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	writer.KeyConst("procinfo");
	writer.StartArray();

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_json_cb(conn, std::move(gyres), is_completed, "Process Info", colarr, ncol, writer, total_rows, noextracolcb);
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
				constexpr const char errbuf[] = "Process Info Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Process Info Query : Database Connection Error. Please try later...";

				send_json_error_resp(connshr, ERR_SYSERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}	

			return false;
		}	

		writer.EndArray();
		writer.EndObject();
		
		return false;
	}	

	writer.EndArray();

	if (false == qryopt.is_multi_host()) {
		web_db_set_partha_hostinfo(writer, qryopt);
	}

	writer.EndObject();

	return true;
}

bool MCONN_HANDLER::web_db_aggr_proc_info(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Aggregated Process Info query\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Aggregated Process Info Query : Database Querying Error : Failed to get an idle connection. Please try later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	int				ret;
	bool				bret, updqryopt = false;
	time_t				tcurr = time(nullptr);
	struct timeval			tvstart, tvend, origtvstart, origtvend;
	char				origstarttime[48], origendtime[48];
	
	GY_SCOPE_EXIT {
		if (updqryopt == true) {
			qryopt.set_timestamps(origstarttime, origendtime, origtvstart, origtvend, false);
		}
	};	

	tvstart = qryopt.get_start_timeval(); 
	tvend 	= qryopt.get_end_timeval();

	if (tvend.tv_sec - tvstart.tv_sec < (int64_t)INFO_DB_UPDATE_SEC) {
		origtvstart	= tvstart;
		origtvend	= tvend;
		GY_STRNCPY(origstarttime, qryopt.get_starttime(), sizeof(origstarttime));
		GY_STRNCPY(origendtime, qryopt.get_endtime(), sizeof(origendtime));
		updqryopt	= true;
		
		tvstart.tv_sec = tvend.tv_sec - INFO_DB_UPDATE_SEC;
		tvend.tv_sec += INFO_DB_UPDATE_SEC/3;
		qryopt.set_timestamps(gy_localtime_iso8601_sec(tvstart.tv_sec).get(), gy_localtime_iso8601_sec(tvend.tv_sec).get(), tvstart, tvend, false /* pointintime */);
	}	

	if (tcurr - db_storage_days_ * GY_SEC_PER_DAY > (uint64_t)tvend.tv_sec) {
		char			ebuf[256];
		size_t			esz;
		
		esz = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Aggregated Process Info Query : Time Requested not present in DB : Max Days of DB storage = %u", db_storage_days_);

		if (writer.get_stream()->reset_if_not_sent(ERR_DATA_NOT_FOUND)) {
			send_json_error_resp(connshr, ERR_DATA_NOT_FOUND, pquery->get_seqid(), ebuf, esz, pthrpoolarr);
		}

		return false;
	}	
	
	auto 				datetbl = get_db_day_partition(tvstart.tv_sec, tvend.tv_sec, 0);

	const JSON_DB_MAPPING		*colarr[QUERY_OPTIONS::MAX_AGGR_COLUMNS];
	JSON_DB_MAPPING			acolarr[QUERY_OPTIONS::MAX_AGGR_COLUMNS];
	uint32_t			ncol;

	assert(gy_get_thread_local().get_thread_stack_freespace() >= 256 * 1024);

	if (true) {
		STRING_BUFFER<48 * 1024>		strbuf;
		
		ncol = get_procinfo_aggr_query(strbuf, qryopt, datetbl.get(), acolarr);

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());

		if (bret == false) {
			constexpr const char errbuf[] = "Aggregated Process Info Query : Failed to schedule query to Database. Please retry later...";

			if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
				send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}

			return false;
		}	

		for (uint32_t i = 0; i < ncol; ++i) {
			colarr[i] = acolarr + i;
		}	
	}

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	writer.KeyConst("procinfo");
	writer.StartArray();

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_json_cb(conn, std::move(gyres), is_completed, "Aggregated Process Info", colarr, ncol, writer, total_rows, noextracolcb);
		}
	);
	
	auto		expirysec = std::max<int64_t>(30, pquery->get_time_to_expiry(tcurr));

	ret = dbpool.wait_one_response(expirysec * 1000, pconn.getintconn());

	if (ret != 0) {
		if (ret == 2) {
			db_stats_.ndbquery_timeout_.fetch_add_relaxed(1);
		}

		if (writer.get_stream()->reset_if_not_sent(ret == 2 ? ERR_TIMED_OUT : ERR_SYSERROR)) {
			if (ret == 2) {
				constexpr const char errbuf[] = "Aggregated Process Info Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Aggregated Process Info Query : Database Connection Error. Please try later...";

				send_json_error_resp(connshr, ERR_SYSERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}	

			return false;
		}	

		writer.EndArray();
		writer.EndObject();

		return false;
	}	

	writer.EndArray();

	if (false == qryopt.is_multi_host()) {
		web_db_set_partha_hostinfo(writer, qryopt);
	}

	set_json_column_list(writer, colarr, ncol);

	writer.EndObject();

	return true;
}

bool MCONN_HANDLER::web_query_proc_info(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	bool					bret;

	try {
		if (false == qryopt.match_madhava_option(gmadhava_id_str_)) {
			// Skip this query
			writer.StartObject();	
	
			writer.KeyConst("madid");
			writer.String(gmadhava_id_str_, 16);

			writer.EndObject();

			return true;
		}

		if (!qryopt.is_historical()) {
			bret = web_curr_proc_info(connshr, qryopt, extpool, pquery, writer, pthrpoolarr);
		}
		else {
			if (false == qryopt.is_aggregated()) {
				bret = web_db_proc_info(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);
			}
			else {
				bret = web_db_aggr_proc_info(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);
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


CRIT_RET_E MCONN_HANDLER::notify_msg_filter_match(const CRITERIA_SET & criteria, const NOTIFY_MSG_ONE & msg, bool ignore_other_subsys) const 
{
	const SUBSYS_CLASS_E		subsysarr[] {SUBSYS_NOTIFYMSG};

	auto get_num_field = [&](const JSON_DB_MAPPING *pfield, SUBSYS_CLASS_E subsys) -> NUMBER_CRITERION
	{
		switch (pfield->jsoncrc) {

		default				:	return {};
		}	
	};

	auto get_str_field = [&](const JSON_DB_MAPPING *pfield, char * tbuf, size_t szbuf, SUBSYS_CLASS_E subsys) -> std::pair<const char *, uint32_t>
	{
		switch (pfield->jsoncrc) {

		case FIELD_PARID 		:
			if (tbuf && szbuf > 32) {
				std::pair<const char *, uint32_t>	p;

				p.first		= tbuf;
				p.second 	= snprintf(tbuf, szbuf, "%016lx%016lx", msg.machid_.get_first(), msg.machid_.get_second());

				return p;
			}
			return {};

		case FIELD_TYPE 		: 	
			do {
				const char		*ptype = notify_to_string(msg.type_);

				return { ptype, strlen(ptype) };
			} while (0);
		
		case FIELD_MSG 			:	return { msg.msgbuf_.buffer(), msg.msgbuf_.length() };

		default				:	return {};
		}	
	};	

	auto get_bool_field = [&](const JSON_DB_MAPPING *pfield, SUBSYS_CLASS_E subsys) -> BOOL_CRITERION
	{
		switch (pfield->jsoncrc) {

		default				:	return {};
		}	
	};

	return criteria.match_criteria(get_num_field, get_str_field, get_bool_field, 0, ignore_other_subsys ? subsysarr : nullptr, ignore_other_subsys ? GY_ARRAY_SIZE(subsysarr) : 0);
}

bool MCONN_HANDLER::web_curr_notify_msg(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr)
{
	bool				bret, is_multi_host = qryopt.is_multi_host();
	auto				paridbuf = qryopt.get_parid_str();
	const char			*paridstr = (false == qryopt.is_multi_host() ? paridbuf.get() : nullptr);
	int				limit = qryopt.get_max_records(), nrecs = 0;
	time_t				tstart = qryopt.get_start_timeval().tv_sec, tend = qryopt.get_end_timeval().tv_sec;

	qryopt.comp_criteria_init();

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	writer.KeyConst("notifymsg");
	writer.StartArray();

	const auto walkq = [&, is_multi_host, limit, tstart, tend](const NOTIFY_MSG_ONE & msg, void * arg1, void * arg2) -> CB_RET_E
	{
		if (!(msg.tmsg_ >= tstart && msg.tmsg_ <= tend)) {
			return CB_OK;
		}

		if (false == is_multi_host) {
			if (msg.machid_ != qryopt.get_parid()) {
				return CB_OK;
			}
		}

		if (qryopt.has_filter()) {
			auto cret = notify_msg_filter_match(qryopt.get_filter_criteria(), msg, true /* ignore_other_subsys */);

			if (cret == CRIT_FAIL) {
				return CB_OK;
			}
		}	

		writer.StartObject();

		writer.KeyConst("time");
		writer.String(gy_localtime_iso8601_sec(msg.tmsg_).get());	

		writer.KeyConst("type");
		writer.String(notify_to_string(msg.type_));

		writer.KeyConst("parid");
		writer.String(msg.machid_.get_string().get(), 32);

		writer.KeyConst("msg");
		writer.String(msg.msgbuf_.buffer(), msg.msgbuf_.length());

		writer.EndObject();

		if (++nrecs >= limit) {
			return CB_BREAK_LOOP;
		}

		return CB_OK;
	};	

	if (tlastq_.load(mo_acquire) >= tstart) {
		NOTIFY_MSG_PQ		tnotifyq(notifyq_);

		tnotifyq.walk_queue_const(walkq);
	}

	writer.EndArray();

	if (false == qryopt.is_multi_host()) {
		web_db_set_partha_hostinfo(writer, qryopt);
	}

	writer.EndObject();

	return true;
}

bool MCONN_HANDLER::web_db_notify_msg(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Notify Msg query\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Notify Msg Query : Database Querying Error : Failed to get an idle connection. Please try later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	int				ret;
	bool				bret;
	time_t				tcurr = time(nullptr);
	struct timeval			tvstart = qryopt.get_start_timeval(), tvend = qryopt.get_end_timeval();

	if (tcurr - db_storage_days_ * GY_SEC_PER_DAY > (uint64_t)tvend.tv_sec) {
		char			ebuf[256];
		size_t			esz;
		
		esz = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Notify Msg Query : Time Requested not present in DB : Max Days of DB storage = %u", db_storage_days_);

		if (writer.get_stream()->reset_if_not_sent(ERR_DATA_NOT_FOUND)) {
			send_json_error_resp(connshr, ERR_DATA_NOT_FOUND, pquery->get_seqid(), ebuf, esz, pthrpoolarr);
		}

		return false;
	}	
	
	const JSON_DB_MAPPING		*colarr[MAX_MULTI_HOST_COLUMN_LIST];
	
	auto [ncol, colspec] 		= qryopt.get_column_list(colarr, GY_ARRAY_SIZE(colarr), SUBSYS_NOTIFYMSG, true /* ign_col_list */);

	auto 				datetbl = get_db_day_partition(tvstart.tv_sec, tvend.tv_sec, 0);
	
	{
		STRING_BUFFER<48 * 1024>	strbuf;
		char				tablename[128];

		snprintf(tablename, sizeof(tablename), "public.notificationtbl%s", datetbl.get());

		qryopt.get_db_select_query(strbuf, SUBSYS_NOTIFYMSG, tablename, "", true /* ign_col_list */);

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}	

	if (bret == false) {
		constexpr const char errbuf[] = "Notify Msg Query : Failed to schedule query to Database. Please retry later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	writer.KeyConst("notifymsg");
	writer.StartArray();

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_json_cb(conn, std::move(gyres), is_completed, "Notify Msg", colarr, ncol, writer, total_rows, noextracolcb);
		}
	);
	
	auto		expirysec = std::max<int64_t>(30, pquery->get_time_to_expiry(tcurr));

	ret = dbpool.wait_one_response(expirysec * 1000, pconn.getintconn());

	if (ret != 0) {
		if (ret == 2) {
			db_stats_.ndbquery_timeout_.fetch_add_relaxed(1);
		}

		if (writer.get_stream()->reset_if_not_sent(ret == 2 ? ERR_TIMED_OUT : ERR_SYSERROR)) {
			if (ret == 2) {
				constexpr const char errbuf[] = "Notify Msg Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Notify Msg Query : Database Connection Error. Please try later...";

				send_json_error_resp(connshr, ERR_SYSERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}	

			return false;
		}	

		writer.EndArray();
		writer.EndObject();

		return false;
	}	

	writer.EndArray();

	if (false == qryopt.is_multi_host()) {
		web_db_set_partha_hostinfo(writer, qryopt);
	}

	writer.EndObject();

	return true;
}	

bool MCONN_HANDLER::web_query_notify_msg(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	bool				bret, use_db = qryopt.is_historical();

	try {
		if (false == qryopt.match_madhava_option(gmadhava_id_str_)) {
			// Skip this query
			writer.StartObject();	
	
			writer.KeyConst("madid");
			writer.String(gmadhava_id_str_, 16);

			writer.EndObject();

			return true;
		}

		if (use_db) {
			/* 
			 * Check if the start time is already present in notifyq_
			 */
			time_t			tqrystart = qryopt.get_start_timeval().tv_sec; 
			time_t			tqstart;

			if (false == notifyq_.empty()) {
				tqstart = notifyq_.top().tmsg_;

				if (tqstart <= tqrystart) {
					use_db = false;
				}
			}	
			else if (tqrystart > get_proc_start()) {
				use_db = false;
			}	
		}

		if (false == use_db) {
			bret = web_curr_notify_msg(connshr, qryopt, extpool, pquery, writer, pthrpoolarr);
		}
		else {
			bret = web_db_notify_msg(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);

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

bool MCONN_HANDLER::web_db_host_info(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Host Info query\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Host Info Query : Database Querying Error : Failed to get an idle connection. Please try later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	int				ret;
	bool				bret;
	time_t				tcurr = time(nullptr);

	const JSON_DB_MAPPING		*colarr[MAX_MULTI_HOST_COLUMN_LIST];
	
	auto [ncol, colspec] 		= qryopt.get_column_list(colarr, GY_ARRAY_SIZE(colarr), SUBSYS_HOSTINFO);

	{
		STRING_BUFFER<48 * 1024>	strbuf;

		qryopt.get_db_select_query(strbuf, SUBSYS_HOSTINFO, "public.hostinfoview");

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}	

	if (bret == false) {
		constexpr const char errbuf[] = "Host Info Query : Failed to schedule query to Database. Please retry later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	writer.KeyConst("hostinfo");
	writer.StartArray();

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_json_cb(conn, std::move(gyres), is_completed, "Host Info", colarr, ncol, writer, total_rows, noextracolcb);
		}
	);
	
	auto		expirysec = std::max<int64_t>(30, pquery->get_time_to_expiry(tcurr));

	ret = dbpool.wait_one_response(expirysec * 1000, pconn.getintconn());

	if (ret != 0) {
		if (ret == 2) {
			db_stats_.ndbquery_timeout_.fetch_add_relaxed(1);
		}

		if (writer.get_stream()->reset_if_not_sent(ret == 2 ? ERR_TIMED_OUT : ERR_SYSERROR)) {
			if (ret == 2) {
				constexpr const char errbuf[] = "Host Info Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Host Info Query : Database Connection Error. Please try later...";

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

bool MCONN_HANDLER::web_db_aggr_host_info(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Aggregated Hostinfo\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Aggregated Hostinfo Query : Database Querying Error : Failed to get an idle connection. Please try later...";
		
		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	int				ret;
	bool				bret;
	time_t				tcurr = time(nullptr);

	const JSON_DB_MAPPING		*colarr[QUERY_OPTIONS::MAX_AGGR_COLUMNS];
	JSON_DB_MAPPING			acolarr[QUERY_OPTIONS::MAX_AGGR_COLUMNS];
	uint32_t			ncol;

	assert(gy_get_thread_local().get_thread_stack_freespace() >= 256 * 1024);

	if (true) {
		STRING_BUFFER<48 * 1024>		strbuf;
		
		ncol = get_hostinfo_aggr_query(strbuf, qryopt, acolarr);

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());

		if (bret == false) {
			constexpr const char errbuf[] = "Aggregated Hostinfo Query : Failed to schedule query to Database. Please retry later...";

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

	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	writer.KeyConst("hostinfo");
	writer.StartArray();

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_json_cb(conn, std::move(gyres), is_completed, "Aggregated Hostinfo", colarr, ncol, writer, total_rows, noextracolcb);
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
				constexpr const char errbuf[] = "Aggregated Hostinfo Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Aggregated Hostinfo Query : Database Connection Error. Please try later...";

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

bool MCONN_HANDLER::web_query_host_info(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	bool				bret, is_aggregated = qryopt.is_aggregated();

	try {
		if (false == qryopt.match_madhava_option(gmadhava_id_str_)) {
			// Skip this query
			writer.StartObject();	
	
			writer.KeyConst("madid");
			writer.String(gmadhava_id_str_, 16);

			writer.EndObject();

			return true;
		}

		if (false == is_aggregated) {
			bret = web_db_host_info(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);
		}
		else {
			bret = web_db_aggr_host_info(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);
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

	return true;
}	

bool MCONN_HANDLER::web_query_madhavastatus(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	try {
		const auto			*psettings = get_settings();
		char				verbuf[32];

		// qryopt.comp_criteria_init();		// As no filtering to be done...

		if (false == qryopt.match_madhava_option(gmadhava_id_str_)) {
			// Skip this query
			writer.StartObject();	
	
			writer.KeyConst("madid");
			writer.String(gmadhava_id_str_, 16);

			writer.EndObject();

			return true;
		}

		writer.StartObject();

		writer.KeyConst("madid");
		writer.String(gmadhava_id_str_, 16);

		writer.KeyConst("npartha");
		writer.Int(partha_tbl_.approx_count_fast());

		writer.KeyConst("maxpartha");
		writer.Int(max_partha_allowed_);

		writer.KeyConst("shyamaconn");
		writer.Bool(!!gshyama_.get_num_conns());

		writer.KeyConst("nmadhava");
		writer.Int(last_madhava_cnt_);

		writer.KeyConst("nwebserver");
		writer.Int(last_node_cnt_);

		writer.KeyConst("svchost");
		writer.String(psettings->service_hostname);

		writer.KeyConst("svcport");
		writer.Int(psettings->service_port);

		writer.KeyConst("madhavaname");
		writer.String(madhava_name_);

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

		writer.KeyConst("dbdays");
		writer.Int(db_storage_days_);

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

CRIT_RET_E MCONN_HANDLER::parthalist_filter_match(const CRITERIA_SET & criteria, const PARTHA_INFO * prawpartha, bool ignore_other_subsys) const 
{
	const SUBSYS_CLASS_E		subsysarr[] {SUBSYS_PARTHALIST, SUBSYS_HOST};

	auto get_num_field = [&](const JSON_DB_MAPPING *pfield, SUBSYS_CLASS_E subsys) -> NUMBER_CRITERION
	{
		switch (pfield->jsoncrc) {

		case FIELD_BOOT			: 	return NUMBER_CRITERION((int64_t)(prawpartha->boot_time_sec_));
		case FIELD_LASTSEEN		:	return NUMBER_CRITERION((int64_t)(prawpartha->get_last_host_state_tusec()/GY_USEC_PER_SEC));

		default				:	return {};
		}	
	};

	auto get_str_field = [&](const JSON_DB_MAPPING *pfield, char * tbuf, size_t szbuf, SUBSYS_CLASS_E subsys) -> std::pair<const char *, uint32_t>
	{

		switch (pfield->jsoncrc) {

		case FIELD_PARID 		: 	return { prawpartha->machine_id_str_, 		32 };
		case FIELD_HOST 		: 	return { prawpartha->hostname_, 		GY_READ_ONCE(prawpartha->hostname_len_) };
		case FIELD_MADID		:	return { gmadhava_id_str_,			16 };
		case FIELD_CLUSTER 		: 	return { prawpartha->cluster_name_,		GY_READ_ONCE(prawpartha->cluster_len_) };
		case FIELD_REGION		:	return { prawpartha->region_name_,		GY_READ_ONCE(prawpartha->region_len_) };
		case FIELD_ZONE			:	return { prawpartha->zone_name_,		GY_READ_ONCE(prawpartha->zone_len_) };
		case FIELD_VERSION		:	
						if (tbuf && szbuf > 16) {
							char			verbuf[32];
						
							uint32_t		lenv = GY_STRNCPY_LEN(tbuf, get_string_from_version_num(prawpartha->partha_version_, verbuf, 3), szbuf);

							return { tbuf, lenv };
						}
						return {};
		
		case FIELD_KERNVERSTR		:	
						if (tbuf && szbuf > 16) {
							char			verbuf[32];
						
							uint32_t		lenv = GY_STRNCPY_LEN(tbuf, get_string_from_version_num(prawpartha->kern_version_num_, verbuf, 3), szbuf);

							return { tbuf, lenv };
						}
						return {};
		
		default				:	return {};
		}	
	};	

	auto get_bool_field = [&](const JSON_DB_MAPPING *pfield, SUBSYS_CLASS_E subsys) -> BOOL_CRITERION
	{
		switch (pfield->jsoncrc) {

		case FIELD_ISCONN		:	return BOOL_CRITERION(!!prawpartha->get_num_conns());

		default				:	return {};
		}	
	};

	return criteria.match_criteria(get_num_field, get_str_field, get_bool_field, 0, ignore_other_subsys ? subsysarr : nullptr, ignore_other_subsys ? GY_ARRAY_SIZE(subsysarr) : 0);
}


bool MCONN_HANDLER::web_query_parthalist(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	try {
		int				nhosts = 0;

		qryopt.comp_criteria_init();	

		if (false == qryopt.match_madhava_option(gmadhava_id_str_)) {
			// Skip this query
			writer.StartObject();	
	
			writer.KeyConst("madid");
			writer.String(gmadhava_id_str_, 16);

			writer.EndObject();

			return true;
		}

		writer.StartObject();

		writer.KeyConst("madid");
		writer.String(gmadhava_id_str_, 16);

		writer.KeyConst("region");
		writer.String(region_name_);

		writer.KeyConst("zone");
		writer.String(zone_name_);

		writer.KeyConst("parthalist");
		writer.StartArray();

		auto lampar = [&, maxrecs = qryopt.get_max_records()](PARTHA_INFO_ELEM *pdatanode, void *arg1) -> CB_RET_E
		{
			auto			prawpartha = pdatanode->get_data()->get();
			char			verbuf[32];
			bool			bret;

			if (gy_unlikely(prawpartha == nullptr)) {
				return CB_OK;
			}	

			if (qryopt.has_filter()) {
				auto 			cret = parthalist_filter_match(qryopt.get_filter_criteria(), prawpartha, true /* ignore_other_subsys */);

				if (cret == CRIT_FAIL) {
					return CB_OK;
				}
			}	

			writer.StartObject();

			writer.KeyConst("parid");
			writer.String(prawpartha->machine_id_str_, sizeof(prawpartha->machine_id_str_) - 1);
		
			writer.KeyConst("host");
			writer.String(prawpartha->hostname_, GY_READ_ONCE(prawpartha->hostname_len_));

			writer.KeyConst("cluster");
			writer.String(prawpartha->cluster_name_, GY_READ_ONCE(prawpartha->cluster_len_));

			writer.KeyConst("region");
			writer.String(prawpartha->region_name_, GY_READ_ONCE(prawpartha->region_len_));
			
			writer.KeyConst("zone");
			writer.String(prawpartha->zone_name_, GY_READ_ONCE(prawpartha->zone_len_));

			writer.KeyConst("version");
			writer.String(get_string_from_version_num(prawpartha->partha_version_, verbuf, 3));
			
			writer.KeyConst("boot");
			writer.String(gy_localtime_iso8601_sec(prawpartha->boot_time_sec_).get());

			writer.KeyConst("kernverstr");
			writer.String(get_string_from_version_num(prawpartha->kern_version_num_, verbuf, 3));

			writer.KeyConst("isconn");
			writer.Bool(!!prawpartha->get_num_conns());

			writer.KeyConst("lastseen");
			writer.String(gy_localtime_iso8601_sec(prawpartha->get_last_host_state_tusec()/GY_USEC_PER_SEC).get());

			writer.EndObject();

			nhosts++;

			if ((uint32_t)nhosts >= maxrecs) {
				return CB_BREAK_LOOP;
			}	

			return CB_OK;
		};

		partha_tbl_.walk_hash_table_const(lampar);

		writer.EndArray();

		writer.EndObject();

		return true;
	}
	catch(...) {
		writer.get_stream()->reset_if_not_sent(ERR_SERV_ERROR);
		throw;
	}	
}


bool MCONN_HANDLER::web_db_detail_tracereq(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool, bool is_extended)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Trace Request query\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Trace Request query : Database Querying Error : Failed to get an idle connection. Please try later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	int				ret;
	bool				bret, multihost = qryopt.is_multi_host();
	time_t				tcurr = time(nullptr);
	bool				updqryopt = false;
	struct timeval			tvstart, tvend, origtvstart, origtvend;
	char				origstarttime[48], origendtime[48];
	
	GY_SCOPE_EXIT {
		if (updqryopt == true) {
			qryopt.set_timestamps(origstarttime, origendtime, origtvstart, origtvend, false /* pointintime */);
		}
	};	

	if (!qryopt.is_historical()) {
		origtvstart 	= {};
		origtvend 	= {};
		*origstarttime 	= 0;
		*origendtime	= 0;
		updqryopt 	= true;

		tvstart.tv_sec 	= tcurr - 25;
		tvstart.tv_usec = 0;

		tvend.tv_sec	= tcurr + 1;
		tvend.tv_usec	= 0;
		
		qryopt.set_timestamps(gy_localtime_iso8601_sec(tvstart.tv_sec).get(), gy_localtime_iso8601_sec(tvend.tv_sec).get(), tvstart, tvend, false /* pointintime */);
	}	
	else {
		tvstart = qryopt.get_start_timeval(); 
		tvend 	= qryopt.get_end_timeval();
	}

	SUBSYS_CLASS_E			subsys = (false == is_extended ? SUBSYS_TRACEREQ : SUBSYS_EXTTRACEREQ);
	const char			*acttbl = (false == is_extended ? "tracereqtbl" : "exttracereqtbl");

	auto 				datetbl = get_db_day_partition(tvstart.tv_sec, tvend.tv_sec, 0);

	const JSON_DB_MAPPING		*colarr[MAX_MULTI_HOST_COLUMN_LIST];
	
	auto [ncol, colspec] 		= qryopt.get_all_column_list(colarr, GY_ARRAY_SIZE(colarr), subsys);

	if (tcurr - db_storage_days_ * GY_SEC_PER_DAY > (uint64_t)tvend.tv_sec) {
		char			ebuf[256];
		size_t			esz;
		
		esz = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Trace Request Query : Time Requested not present in DB : Max Days of DB storage = %u", db_storage_days_);

		if (writer.get_stream()->reset_if_not_sent(ERR_DATA_NOT_FOUND)) {
			send_json_error_resp(connshr, ERR_DATA_NOT_FOUND, pquery->get_seqid(), ebuf, esz, pthrpoolarr);
		}

		return false;
	}	
	

	if (multihost) {
		STRING_BUFFER<48 * 1024>		strbuf;
		
		qryopt.get_db_select_multihost_query(strbuf, subsys, acttbl, datetbl.get());

		strbuf.appendconst(";\n reset search_path; ");

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}
	else {
		STRING_BUFFER<48 * 1024>	strbuf;
		char				tablename[128];

		snprintf(tablename, sizeof(tablename), "sch%s.%s%s", qryopt.get_parid_str().get(), acttbl, datetbl.get());

		qryopt.get_db_select_query(strbuf, subsys, tablename);

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}	

	if (bret == false) {
		constexpr const char errbuf[] = "Trace Request Query : Failed to schedule query to Database. Please retry later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	if (!is_extended) {
		writer.KeyConst("tracereq");
	}
	else {
		writer.KeyConst("exttracereq");
	}	
	writer.StartArray();

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_json_cb(conn, std::move(gyres), is_completed, "Trace Request", colarr, ncol, writer, total_rows, noextracolcb);
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
				constexpr const char errbuf[] = "Trace Request Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Trace Request Query : Database Connection Error. Please try later...";

				send_json_error_resp(connshr, ERR_SYSERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}	

			return false;
		}	

		writer.EndArray();
		writer.EndObject();
		
		return false;
	}	

	writer.EndArray();

	if (false == qryopt.is_multi_host()) {
		web_db_set_partha_hostinfo(writer, qryopt);
	}

	writer.EndObject();

	return true;
}	

bool MCONN_HANDLER::web_query_tracereq(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool, bool is_extended)
{
	bool				bret;

	try {
		if (false == qryopt.match_madhava_option(gmadhava_id_str_)) {
			// Skip this query
			writer.StartObject();	
	
			writer.KeyConst("madid");
			writer.String(gmadhava_id_str_, 16);

			writer.EndObject();

			return true;
		}

		bret = web_db_detail_tracereq(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool, is_extended);

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

bool MCONN_HANDLER::web_db_detail_traceconn(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Trace Conn query\n");
		);

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		constexpr const char errbuf[] = "Trace Conn query : Database Querying Error : Failed to get an idle connection. Please try later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	int				ret;
	bool				bret, multihost = qryopt.is_multi_host();
	time_t				tcurr = time(nullptr);
	bool				updqryopt = false;
	struct timeval			tvstart, tvend, origtvstart, origtvend;
	char				origstarttime[48], origendtime[48];
	
	GY_SCOPE_EXIT {
		if (updqryopt == true) {
			qryopt.set_timestamps(origstarttime, origendtime, origtvstart, origtvend, false /* pointintime */);
		}
	};	

	if (!qryopt.is_historical()) {
		origtvstart 	= {};
		origtvend 	= {};
		*origstarttime 	= 0;
		*origendtime	= 0;
		updqryopt 	= true;

		tvstart.tv_sec 	= tcurr - 25;
		tvstart.tv_usec = 0;

		tvend.tv_sec	= tcurr + 1;
		tvend.tv_usec	= 0;
		
		qryopt.set_timestamps(gy_localtime_iso8601_sec(tvstart.tv_sec).get(), gy_localtime_iso8601_sec(tvend.tv_sec).get(), tvstart, tvend, false /* pointintime */);
	}	
	else {
		tvstart = qryopt.get_start_timeval(); 
		tvend 	= qryopt.get_end_timeval();
	}

	const SUBSYS_CLASS_E		subsys = SUBSYS_TRACECONN;
	const char			*acttbl = "traceconntbl";

	auto 				datetbl = get_db_day_partition(tvstart.tv_sec, tvend.tv_sec, 0);

	const JSON_DB_MAPPING		*colarr[MAX_MULTI_HOST_COLUMN_LIST];
	
	auto [ncol, colspec] 		= qryopt.get_all_column_list(colarr, GY_ARRAY_SIZE(colarr), subsys);

	if (tcurr - db_storage_days_ * GY_SEC_PER_DAY > (uint64_t)tvend.tv_sec) {
		char			ebuf[256];
		size_t			esz;
		
		esz = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Trace Conn Query : Time Requested not present in DB : Max Days of DB storage = %u", db_storage_days_);

		if (writer.get_stream()->reset_if_not_sent(ERR_DATA_NOT_FOUND)) {
			send_json_error_resp(connshr, ERR_DATA_NOT_FOUND, pquery->get_seqid(), ebuf, esz, pthrpoolarr);
		}

		return false;
	}	
	

	if (multihost) {
		STRING_BUFFER<48 * 1024>		strbuf;
		
		qryopt.get_db_select_multihost_query(strbuf, subsys, acttbl, datetbl.get());

		strbuf.appendconst(";\n reset search_path; ");

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}
	else {
		STRING_BUFFER<48 * 1024>	strbuf;
		char				tablename[128];

		snprintf(tablename, sizeof(tablename), "sch%s.%s%s", qryopt.get_parid_str().get(), acttbl, datetbl.get());

		qryopt.get_db_select_query(strbuf, subsys, tablename);

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
	}	

	if (bret == false) {
		constexpr const char errbuf[] = "Trace Conn Query : Failed to schedule query to Database. Please retry later...";

		if (writer.get_stream()->reset_if_not_sent(ERR_BLOCKING_ERROR)) {
			send_json_error_resp(connshr, ERR_BLOCKING_ERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
		}

		return false;
	}	

	writer.SetMaxDecimalPlaces(3);

	writer.StartObject();
	
	writer.KeyConst("madid");
	writer.String(gmadhava_id_str_, 16);

	writer.KeyConst("traceconn");

	writer.StartArray();

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_json_cb(conn, std::move(gyres), is_completed, "Trace Conn", colarr, ncol, writer, total_rows, noextracolcb);
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
				constexpr const char errbuf[] = "Trace Conn Query : Database Querying Timeout. Please try later...";

				send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}
			else {
				constexpr const char errbuf[] = "Trace Conn Query : Database Connection Error. Please try later...";

				send_json_error_resp(connshr, ERR_SYSERROR, pquery->get_seqid(), errbuf, sizeof(errbuf) - 1, pthrpoolarr);
			}	

			return false;
		}	

		writer.EndArray();
		writer.EndObject();
		
		return false;
	}	

	writer.EndArray();

	if (false == qryopt.is_multi_host()) {
		web_db_set_partha_hostinfo(writer, qryopt);
	}

	writer.EndObject();

	return true;
}	

bool MCONN_HANDLER::web_query_traceconn(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	bool				bret;

	try {
		if (false == qryopt.match_madhava_option(gmadhava_id_str_)) {
			// Skip this query
			writer.StartObject();	
	
			writer.KeyConst("madid");
			writer.String(gmadhava_id_str_, 16);

			writer.EndObject();

			return true;
		}

		bret = web_db_detail_traceconn(connshr, qryopt, extpool, pquery, writer, pthrpoolarr, dbpool);

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


bool MCONN_HANDLER::web_query_traceuniq(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	bool				bret;

	try {
		if (false == qryopt.match_madhava_option(gmadhava_id_str_)) {
			// Skip this query
			writer.StartObject();	
	
			writer.KeyConst("madid");
			writer.String(gmadhava_id_str_, 16);

			writer.EndObject();

			return true;
		}

		// XXX traceuniqtbl not updated currently...

		writer.StartObject();
		
		writer.KeyConst("madid");
		writer.String(gmadhava_id_str_, 16);

		writer.KeyConst("traceuniq");
		writer.StartArray();
		
		writer.EndArray();
		writer.EndObject();

		return true;
	}
	catch(...) {
		writer.get_stream()->reset_if_not_sent();
		throw;
	}
}

CRIT_RET_E MCONN_HANDLER::tracestatus_filter_match(const CRITERIA_SET & criteria, const REQ_TRACE_SVC & elem, const MREQ_TRACE_SVC & rtrace, const PARTHA_INFO * prawpartha, bool ignore_other_subsys) const 
{
	const SUBSYS_CLASS_E		subsysarr[] {SUBSYS_TRACESTATUS, SUBSYS_HOST};

	auto get_num_field = [&](const JSON_DB_MAPPING *pfield, SUBSYS_CLASS_E subsys) -> NUMBER_CRITERION
	{
		switch (pfield->jsoncrc) {

		case FIELD_PORT			: 	return NUMBER_CRITERION((int)(elem.ns_ip_port_.get_port()));
		case FIELD_TLAST		:	return NUMBER_CRITERION(rtrace.tlaststat_);
		case FIELD_TSTART		:	return NUMBER_CRITERION(rtrace.tstart_);
		case FIELD_TEND			:	return NUMBER_CRITERION(rtrace.tend_);
		case FIELD_NREQ			:	return NUMBER_CRITERION((int64_t)rtrace.nrequests_);
		case FIELD_NERR			:	return NUMBER_CRITERION((int64_t)rtrace.nerrors_);

		default				:	return {};
		}	
	};

	auto get_str_field = [&](const JSON_DB_MAPPING *pfield, char * tbuf, size_t szbuf, SUBSYS_CLASS_E subsys) -> std::pair<const char *, uint32_t>
	{

		switch (pfield->jsoncrc) {

		case FIELD_SVCID		:	
							if (tbuf && szbuf > 16) {
								std::pair<const char *, uint32_t>	p;

								p.first		= tbuf;
								p.second 	= snprintf(tbuf, szbuf, "%016lx", elem.glob_id_);

								return p;
							}
							return {};
						
		case FIELD_NAME 		: 	return { elem.comm_, strlen(elem.comm_) };

		case FIELD_STATE		:	
							if (true) {
								const char		*st = cap_status_to_string(rtrace.api_cap_status_.load(mo_relaxed));

								return { st, strlen(st) };
							}
							
		case FIELD_PROTO		:	
							if (true) {
								const char		*pt = proto_to_string(rtrace.api_proto_.load(mo_relaxed));

								return { pt, strlen(pt) };
							}	

		case FIELD_DEFID		:	
							if (tbuf && szbuf > 8) {
								std::pair<const char *, uint32_t>	p;

								p.first		= tbuf;
								p.second 	= snprintf(tbuf, szbuf, "%08x", rtrace.curr_trace_defid_);

								return p;
							}
							return {};


		case FIELD_PARID 		: 	return { prawpartha->machine_id_str_, 		32 };
		case FIELD_HOST 		: 	return { prawpartha->hostname_, 		GY_READ_ONCE(prawpartha->hostname_len_) };
		case FIELD_MADID		:	return { gmadhava_id_str_,			16 };
		case FIELD_CLUSTER 		: 	return { prawpartha->cluster_name_,		GY_READ_ONCE(prawpartha->cluster_len_) };
		case FIELD_REGION		:	return { prawpartha->region_name_,		GY_READ_ONCE(prawpartha->region_len_) };
		case FIELD_ZONE			:	return { prawpartha->zone_name_,		GY_READ_ONCE(prawpartha->zone_len_) };

		default				:	return {};
		}	
	};	

	auto get_bool_field = [&](const JSON_DB_MAPPING *pfield, SUBSYS_CLASS_E subsys) -> BOOL_CRITERION
	{
		switch (pfield->jsoncrc) {

		case FIELD_ISTLS		:	return BOOL_CRITERION(rtrace.api_is_ssl_.load(mo_relaxed));

		default				:	return {};
		}	
	};

	return criteria.match_criteria(get_num_field, get_str_field, get_bool_field, 0, ignore_other_subsys ? subsysarr : nullptr, ignore_other_subsys ? GY_ARRAY_SIZE(subsysarr) : 0);
}


bool MCONN_HANDLER::web_query_tracestatus(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	try {
		using SVCID_SET			= INLINE_STACK_HASH_SET<uint64_t, 16 * 1024, HASH_SAME_AS_KEY<uint64_t>>;
		
		SVCID_SET			svcset;
		int				nrec = 0;
		bool				bret;

		qryopt.comp_criteria_init();	

		if (false == qryopt.match_madhava_option(gmadhava_id_str_)) {
			// Skip this query
			writer.StartObject();	
	
			writer.KeyConst("madid");
			writer.String(gmadhava_id_str_, 16);

			writer.EndObject();

			return true;
		}

		writer.StartObject();

		writer.KeyConst("madid");
		writer.String(gmadhava_id_str_, 16);

		writer.KeyConst("tracestatus");
		writer.StartArray();

		auto writerec = [&, maxrecs = qryopt.get_max_records()](const REQ_TRACE_SVC & elem, const PARTHA_INFO *prawpartha) -> CB_RET_E
		{
			const auto		*prtraceshr = elem.rtraceshr_.get();
			bool			bret;

			if (!prtraceshr || prtraceshr->tlaststat_ == 0) {
				return CB_OK;
			}	

			auto 			[it, isnew] = svcset.emplace(elem.glob_id_);
			
			if (!isnew) {
				return CB_OK;
			}	

			if (qryopt.has_filter()) {
				auto 			cret = tracestatus_filter_match(qryopt.get_filter_criteria(), elem, *prtraceshr, prawpartha, true /* ignore_other_subsys */);

				if (cret == CRIT_FAIL) {
					return CB_OK;
				}
			}	

			writer.StartObject();

			writer.KeyConst("svcid");
			writer.String(number_to_string(elem.glob_id_, "%016lx").get(), 16);
			
			writer.KeyConst("name");
			writer.String(elem.comm_);
		
			writer.KeyConst("port");
			writer.Int(elem.ns_ip_port_.get_port());

			writer.KeyConst("tlast");
			writer.String(gy_localtime_iso8601(prtraceshr->tlaststat_, CHAR_BUF<64>().get(), 64));	
			
			writer.KeyConst("state");
			writer.String(cap_status_to_string(prtraceshr->api_cap_status_.load(mo_relaxed)));

			writer.KeyConst("proto");
			writer.String(proto_to_string(prtraceshr->api_proto_.load(mo_relaxed)));

			writer.KeyConst("istls");
			writer.Bool(prtraceshr->api_is_ssl_.load(mo_relaxed));

			writer.KeyConst("tstart");
			writer.String(gy_localtime_iso8601(prtraceshr->tstart_, CHAR_BUF<64>().get(), 64));	
			
			writer.KeyConst("tend");
			writer.String(gy_localtime_iso8601(prtraceshr->tend_, CHAR_BUF<64>().get(), 64));	
			
			writer.KeyConst("nreq");
			writer.Uint64(prtraceshr->nrequests_);

			writer.KeyConst("nerr");
			writer.Uint64(prtraceshr->nerrors_);

			writer.KeyConst("defid");
			writer.String(number_to_string(prtraceshr->curr_trace_defid_, "%08x").get(), 8);
			
			writer.KeyConst("parid");
			writer.String(prawpartha->machine_id_str_, sizeof(prawpartha->machine_id_str_) - 1);
		
			writer.KeyConst("host");
			writer.String(prawpartha->hostname_, GY_READ_ONCE(prawpartha->hostname_len_));

			writer.KeyConst("cluster");
			writer.String(prawpartha->cluster_name_, GY_READ_ONCE(prawpartha->cluster_len_));

			writer.KeyConst("region");
			writer.String(prawpartha->region_name_, GY_READ_ONCE(prawpartha->region_len_));
			
			writer.KeyConst("zone");
			writer.String(prawpartha->zone_name_, GY_READ_ONCE(prawpartha->zone_len_));


			writer.EndObject();

			nrec++;

			if ((uint32_t)nrec >= maxrecs) {
				return CB_BREAK_LOOP;
			}	

			return CB_OK;
		};

		SharedMutex::ReadHolder			rscope(trace_elems_.rwmutex_);

		RCU_LOCK_SLOW				slowlock;

		GY_MACHINE_ID				lastparid;
		const PARTHA_INFO			*prawpartha = nullptr;
		
		for (const auto & [defid, smap] : trace_elems_.listmap_) {
			for (const auto & [svcid, elem] : smap) {

				if (lastparid != elem.machid_) {
					
					lastparid 			= elem.machid_;
					prawpartha 			= nullptr;

					const auto 			pelem = partha_tbl_.lookup_single_elem_locked(elem.machid_, elem.machid_.get_hash());
				
					if (pelem == nullptr) {
						// Partha deleted...
						continue;
					}	

					prawpartha = pelem->get_cref().get();
				}	

				if (!prawpartha) {
					continue;
				}	

				auto			cret = writerec(elem, prawpartha);

				if (cret == CB_BREAK_LOOP) {
					goto done;
				}	
			}	
		}	

done :

		slowlock.unlock();
		rscope.unlock();

		writer.EndArray();

		writer.EndObject();

		return true;
	}
	catch(...) {
		writer.get_stream()->reset_if_not_sent(ERR_SERV_ERROR);
		throw;
	}	
}

// prawpartha may be nullptr
CRIT_RET_E MCONN_HANDLER::tracehistory_filter_match(const CRITERIA_SET & criteria, const MREQ_TRACE_STATUS & elem, const PARTHA_INFO * prawpartha, bool ignore_other_subsys) const 
{
	const SUBSYS_CLASS_E		subsysarr[] {SUBSYS_TRACEHISTORY, SUBSYS_HOST};

	auto get_num_field = [&](const JSON_DB_MAPPING *pfield, SUBSYS_CLASS_E subsys) -> NUMBER_CRITERION
	{
		switch (pfield->jsoncrc) {

		case FIELD_TIME			:	return NUMBER_CRITERION(elem.tstatus_);
		case FIELD_PORT			: 	return NUMBER_CRITERION((int)(elem.port_));

		default				:	return {};
		}	
	};

	auto get_str_field = [&](const JSON_DB_MAPPING *pfield, char * tbuf, size_t szbuf, SUBSYS_CLASS_E subsys) -> std::pair<const char *, uint32_t>
	{

		switch (pfield->jsoncrc) {

		case FIELD_SVCID		:	
							if (tbuf && szbuf > 16) {
								std::pair<const char *, uint32_t>	p;

								p.first		= tbuf;
								p.second 	= snprintf(tbuf, szbuf, "%016lx", elem.glob_id_);

								return p;
							}
							return {};
						
		case FIELD_NAME 		: 	return { elem.comm_, strlen(elem.comm_) };

		case FIELD_STATE		:	
							if (true) {
								const char		*st = cap_status_to_string(elem.status_);

								return { st, strlen(st) };
							}
							
		case FIELD_PROTO		:	
							if (true) {
								const char		*pt = proto_to_string(elem.proto_);

								return { pt, strlen(pt) };
							}	

		case FIELD_PARID 		: 	
							if (prawpartha) {
								return { prawpartha->machine_id_str_, 32 };
							}
							return { gunknownparid, 32 };

		case FIELD_HOST 		: 	
							if (prawpartha) {
								return { prawpartha->hostname_, GY_READ_ONCE(prawpartha->hostname_len_) };
							}
							return {};

		case FIELD_MADID		:	
							if (prawpartha) {
								return { gmadhava_id_str_, 16 };
							}
							return { gunknownid, 16 };

		case FIELD_CLUSTER 		: 	
							if (prawpartha) {
								return { prawpartha->cluster_name_, GY_READ_ONCE(prawpartha->cluster_len_) };
							}
							return {};

		case FIELD_REGION		:	
							if (prawpartha) {
								return { prawpartha->region_name_, GY_READ_ONCE(prawpartha->region_len_) };
							}
							return {};

		case FIELD_ZONE			:	
							if (prawpartha) {
								return { prawpartha->zone_name_, GY_READ_ONCE(prawpartha->zone_len_) };
							}
							return {};

		default				:	return {};
		}	
	};	

	auto get_bool_field = [&](const JSON_DB_MAPPING *pfield, SUBSYS_CLASS_E subsys) -> BOOL_CRITERION
	{
		switch (pfield->jsoncrc) {

		case FIELD_ISTLS		:	return BOOL_CRITERION(elem.is_ssl_);

		default				:	return {};
		}	
	};

	return criteria.match_criteria(get_num_field, get_str_field, get_bool_field, 0, ignore_other_subsys ? subsysarr : nullptr, ignore_other_subsys ? GY_ARRAY_SIZE(subsysarr) : 0);
}


bool MCONN_HANDLER::web_query_tracehistory(const std::shared_ptr<MCONNTRACK> & connshr, QUERY_OPTIONS & qryopt, EXT_POOL_ALLOC & extpool, const comm::QUERY_CMD *pquery, SOCK_JSON_WRITER<MSTREAM_JSON_EPOLL> & writer, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	try {
		int				nrec = 0;
		bool				bret;

		qryopt.comp_criteria_init();	

		if (false == qryopt.match_madhava_option(gmadhava_id_str_)) {
			// Skip this query
			writer.StartObject();	
	
			writer.KeyConst("madid");
			writer.String(gmadhava_id_str_, 16);

			writer.EndObject();

			return true;
		}

		writer.StartObject();

		writer.KeyConst("madid");
		writer.String(gmadhava_id_str_, 16);

		writer.KeyConst("tracehistory");
		writer.StartArray();

		auto writerec = [&, maxrecs = qryopt.get_max_records()](const MREQ_TRACE_STATUS & elem, const PARTHA_INFO *prawpartha) -> CB_RET_E
		{
			bool			bret;

			// prawpartha may be nullptr

			if (qryopt.has_filter()) {
				auto 			cret = tracehistory_filter_match(qryopt.get_filter_criteria(), elem, prawpartha, true /* ignore_other_subsys */);

				if (cret == CRIT_FAIL) {
					return CB_OK;
				}
			}	

			writer.StartObject();

			writer.KeyConst("time");
			writer.String(gy_localtime_iso8601(elem.tstatus_, CHAR_BUF<64>().get(), 64));	
			
			writer.KeyConst("svcid");
			writer.String(number_to_string(elem.glob_id_, "%016lx").get(), 16);
			
			writer.KeyConst("name");
			writer.String(elem.comm_);
		
			writer.KeyConst("port");
			writer.Int(elem.port_);

			writer.KeyConst("state");
			writer.String(cap_status_to_string(elem.status_));

			writer.KeyConst("info");
			writer.String(elem.msgstr_);

			writer.KeyConst("proto");
			writer.String(proto_to_string(elem.proto_));

			writer.KeyConst("istls");
			writer.Bool(elem.is_ssl_);

			writer.KeyConst("parid");
			if (prawpartha) {
				writer.String(prawpartha->machine_id_str_, sizeof(prawpartha->machine_id_str_) - 1);
			}
			else {
				writer.String(gunknownparid, 32);
			}	
		
			writer.KeyConst("host");
			if (prawpartha) {
				writer.String(prawpartha->hostname_, GY_READ_ONCE(prawpartha->hostname_len_));
			}
			else {
				writer.String(gunknownid, 16);
			}	

			writer.KeyConst("cluster");
			if (prawpartha) {
				writer.String(prawpartha->cluster_name_, GY_READ_ONCE(prawpartha->cluster_len_));
			}
			else {
				writer.String("");
			}	

			writer.KeyConst("region");
			if (prawpartha) {
				writer.String(prawpartha->region_name_, GY_READ_ONCE(prawpartha->region_len_));
			}	
			else {
				writer.String("");
			}	

			writer.KeyConst("zone");
			if (prawpartha) {
				writer.String(prawpartha->zone_name_, GY_READ_ONCE(prawpartha->zone_len_));
			}	
			else {
				writer.String("");
			}	

			writer.EndObject();

			nrec++;

			if ((uint32_t)nrec >= maxrecs) {
				return CB_BREAK_LOOP;
			}	

			return CB_OK;
		};

		SharedMutex::ReadHolder			rscope(trace_elems_.rwmutex_);

		RCU_LOCK_SLOW				slowlock;

		GY_MACHINE_ID				lastparid;
		const PARTHA_INFO			*prawpartha = nullptr;
		
		for (const auto & elem : trace_elems_.statlist_) {

			if (lastparid != elem.machid_) {
				
				lastparid 			= elem.machid_;
				prawpartha 			= nullptr;

				const auto 			pelem = partha_tbl_.lookup_single_elem_locked(elem.machid_, elem.machid_.get_hash());
			
				if (pelem) {
					prawpartha = pelem->get_cref().get();
				}	
			}	


			// prawpartha may be nullptr

			auto			cret = writerec(elem, prawpartha);

			if (cret == CB_BREAK_LOOP) {
				goto done;
			}	
		}	

done :

		slowlock.unlock();
		rscope.unlock();

		writer.EndArray();

		writer.EndObject();

		return true;
	}
	catch(...) {
		writer.get_stream()->reset_if_not_sent(ERR_SERV_ERROR);
		throw;
	}	
}

} // namespace madhava
} // namespace gyeeta

