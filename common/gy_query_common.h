//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later


#pragma				once

#include			"gy_common_inc.h"
#include			"gy_print_offload.h"
#include			"gy_json_field_maps.h"
#include			"gy_query_criteria.h"
#include			"gy_rapidjson.h"
#include			"gy_stack_pool.h"
#include			"gy_sys_hardware.h"
#include			"gy_web_proto.h"

namespace gyeeta {

enum SORT_DIR_E : uint8_t
{
	SORT_DIR_ASC			= 0,
	SORT_DIR_DESC,
};	

class QUERY_OPTIONS
{
public :
	static constexpr size_t		MAX_CUST_COLUMNS		{24};
	static constexpr size_t		MAX_AGGR_COLUMNS		{std::max(MAX_CUST_COLUMNS * 2, MAX_COLUMN_LIST) + GY_ARRAY_SIZE(host_aggr_info)};
	static constexpr size_t		MAX_SORT_COLUMNS		{4};
	static constexpr size_t		MAX_AGGR_COL_BUFSZ		{6000};

	char				starttime_[48]			{};
	char				endtime_[48]			{};
	struct timeval			tvstart_			{};
	struct timeval			tvend_				{};

	CRITERIA_SET			criteria_;

	const JSON_DB_MAPPING 		**columnarr_			{nullptr};												
	FREE_FPTR			col_free_fp_			{nullptr};
	size_t				ncols_				{0};
	
	uint32_t			nsubsys_			{0};
	SUBSYS_CLASS_E 			pallowed_subsys_arr_[8]		{};
	const SUBSYS_CLASS		*pdefsubsys_			{nullptr};

	size_t				maxrecs_			{0};
	size_t				recoffset_			{0};

	const JSON_DB_MAPPING		*sortcolarr_[MAX_SORT_COLUMNS]	{};
	const SUBSYS_CLASS		*sortsubsys_[MAX_SORT_COLUMNS]	{};
	SORT_DIR_E			sortdir_[MAX_SORT_COLUMNS]	{};
	uint32_t			nsort_				{0};

	GY_MACHINE_ID			parid_;

	char				multiqueryid_[32]		{};

	const GEN_JSON_VALUE		*pjsonobj_			{nullptr};
	const GEN_JSON_VALUE		*pfilterjson_			{nullptr};
	const GEN_JSON_VALUE		*poptjson_			{nullptr};

	char				madid_opt_[17]			{};

	NODE_QUERY_TYPE_E		qtype_				{NQUERY_MIN_TYPE};

	char				*paggrstrbuf_			{nullptr};
	FREE_FPTR			paggrbuf_free_fp_		{nullptr};
	uint32_t			maxstrbufsz_			{0};
	uint32_t			aggr_dur_sec_			{0};
	uint16_t			naggr_column_spec_		{0};
	AGGR_OPER_E			aggr_oper_			{AOPER_UNSPEC};

	uint8_t				nmulti_queries_			{0};
	uint8_t				multiquery_index_		{0};

	bool				is_multihost_			{false};
	bool				point_in_time_			{false};
	bool				is_historical_			{false};
	bool				is_multiquery_			{false};
	bool				is_aggregated_			{false};
	bool				has_aggr_filters_		{false};
	bool				is_madid_opt_			{false};
	bool				is_valid_			{false};

	QUERY_OPTIONS() noexcept	= default;

	QUERY_OPTIONS(const GEN_JSON_VALUE & jdoc, EXT_POOL_ALLOC & extpool, bool is_multiquery = false, uint32_t multiquery_index = 0, bool allocregex = false, const SUBSYS_CLASS_E *pfixedsubsys = nullptr);

	~QUERY_OPTIONS() noexcept
	{
		destroy();
	}	

	QUERY_OPTIONS(const QUERY_OPTIONS &)			= delete;
	QUERY_OPTIONS & operator= (const QUERY_OPTIONS &)	= delete;

	QUERY_OPTIONS(QUERY_OPTIONS && other) 			= delete;
	QUERY_OPTIONS & operator= (QUERY_OPTIONS &&)		= delete;

	void destroy() noexcept
	{
		if (columnarr_) {
			destruct_dealloc_array(columnarr_, ncols_, col_free_fp_);
			columnarr_ = nullptr;
		}
		
		destroy_aggrbuf();
	}

	void destroy_aggrbuf() noexcept
	{
		if (paggrstrbuf_) {
			if (paggrbuf_free_fp_) {
				(*paggrbuf_free_fp_)(paggrstrbuf_);
			}	

			paggrstrbuf_ = nullptr;
		}	
	}	

	void set_aggrbuf(char * paggrstrbuf, uint32_t maxstrbufsz, FREE_FPTR paggrbuf_free_fp) noexcept
	{
		destroy_aggrbuf();

		paggrstrbuf_ 		= paggrstrbuf;
		maxstrbufsz_		= maxstrbufsz;
		paggrbuf_free_fp_	= paggrbuf_free_fp; 
	}	
	
	bool is_valid() const noexcept
	{
		return is_valid_;
	}

	bool is_historical() const noexcept
	{
		return is_historical_;
	}
		
	struct timeval get_start_timeval() const noexcept
	{
		return tvstart_;
	}	

	struct timeval get_end_timeval() const noexcept
	{
		return tvend_;
	}	

	const char * get_starttime() const noexcept
	{
		return starttime_;
	}	

	const char * get_endtime() const noexcept
	{
		return endtime_;
	}	

	bool is_pointintime() const noexcept
	{
		return point_in_time_;
	}

	CRITERIA_SET & get_filter_criteria() noexcept
	{
		return criteria_;
	}	

	const CRITERIA_SET & get_filter_criteria() const noexcept
	{
		return criteria_;
	}	

	bool has_filter() const noexcept
	{
		return criteria_.has_filter_criteria();
	}	

	void comp_criteria_init()
	{
		if (has_filter()) {
			criteria_.init_criteria_regex();
		}	
	}	

	size_t get_max_records() const noexcept
	{
		return maxrecs_;
	}	

	void set_max_records(size_t newmax) noexcept;

	bool is_multi_host() const noexcept
	{
		return is_multihost_;
	}

	bool is_aggregated() const noexcept
	{
		return is_aggregated_;
	}

	std::optional<std::pair<uint32_t, AGGR_OPER_E>> get_aggr_options() const noexcept
	{
		if (is_aggregated_) {
			return std::pair(aggr_dur_sec_, aggr_oper_);
		}

		return {};
	}	

	bool has_aggr_filters() const noexcept
	{
		return is_aggregated_ && has_aggr_filters_;
	}

	const char * get_aggr_oper_str(const char *pdefaultoper, bool ignore_sum = false) const noexcept
	{
		if (is_aggregated_) {
			switch (aggr_oper_) {
			
			case AOPER_SUM		:	return (ignore_sum == false ? "sum" : pdefaultoper);
			case AOPER_AVG		:	return "avg";
			case AOPER_MAX		:	return "max";
			case AOPER_MIN		:	return "min";

			case AOPER_UNSPEC	:	
			default			:
							return pdefaultoper;
			}	
		}

		return "";
	}	

	const char * get_aggr_oper_str(AGGR_OPER_E defaultoper, bool ignore_sum = false) const noexcept
	{
		const char			*pdefaultoper;

		switch (defaultoper) {
		
		case AOPER_AVG			: 	pdefaultoper = "avg"; break;
		case AOPER_MIN			: 	pdefaultoper = "min"; break;
		case AOPER_MAX			: 	pdefaultoper = "max"; break;
		case AOPER_SUM			: 	pdefaultoper = "sum"; break;

		default				: 	pdefaultoper = "avg"; break;

		}

		return get_aggr_oper_str(pdefaultoper, ignore_sum);
	}	

	void reset_aggregated() noexcept
	{
		is_aggregated_ 	= false;
	}

	const GY_MACHINE_ID & get_parid() const noexcept
	{
		return parid_;
	}	

	CHAR_BUF<40> get_parid_str() const noexcept
	{
		return parid_.get_string();
	}	

	bool is_madhava_option() const noexcept
	{
		return is_madid_opt_;
	}	

	bool match_madhava_option(const char *madid) const noexcept
	{
		if (is_madid_opt_) {
			return (0 == memcmp(madid, madid_opt_, 16));
		}

		return true;
	}	

	const char * get_madhava_id() const noexcept
	{
		if (is_madid_opt_) {
			return madid_opt_;
		}	
	
		return nullptr;
	}	

	bool is_multiquery() const noexcept
	{
		return is_multiquery_;
	}	

	const char * get_multiquery_id() const noexcept
	{
		return multiqueryid_;
	}	

	uint8_t get_num_multiqueries() const noexcept
	{
		return nmulti_queries_;
	}	

	uint8_t get_multiquery_index() const noexcept
	{
		return multiquery_index_;
	}	

	NODE_QUERY_TYPE_E get_query_type() const noexcept
	{
		return qtype_;
	}

	// Make sure the original json object still valid
	const GEN_JSON_VALUE * get_json() const noexcept
	{
		return pjsonobj_;
	}

	// Make sure the original json object still valid
	const GEN_JSON_VALUE * get_filter_json() const noexcept
	{
		return pfilterjson_;
	}

	// Make sure the original json object still valid
	const GEN_JSON_VALUE * get_options_json() const noexcept
	{
		return poptjson_;
	}

	bool is_column_list() const noexcept
	{
		return columnarr_ != nullptr && ncols_ > 0;
	}

	// Specify subsys as SUBSYS_MAX to get all subsystem columns
	size_t get_column_list_crc(uint32_t *colarr, size_t maxcol, SUBSYS_CLASS_E subsys) const 
	{
		if (!columnarr_  || ncols_ == 0 || !pdefsubsys_) return 0;

		size_t			n = 0;

		for (size_t i = 0; i < ncols_ && n < maxcol; ++i) {
			if ((subsys == SUBSYS_MAX) || (pdefsubsys_->subsysval == subsys)) {
				colarr[n++] = columnarr_[i]->jsoncrc;
			}
		}

		return n;
	}	

	// Returns {ncol, is_col_spec} for a single subsystem check. The returned columns will be in DB resultset order for easier checks.
	std::pair<size_t, bool> get_column_list(const JSON_DB_MAPPING **colarr, size_t maxcol, SUBSYS_CLASS_E subsys, bool ign_col_list = false) const 
	{
		size_t			n = 0;

		if ((uint32_t)subsys > SUBSYS_MAX || !colarr || !maxcol) {
			return {};
		}

		if (!columnarr_  || ncols_ == 0 || !pdefsubsys_ || ign_col_list) {
			
			if (subsys < SUBSYS_MAX) {
				const auto		*pmap = subsys_class_list[subsys].pjsonmap;
				const size_t		szmap = subsys_class_list[subsys].szjsonmap;

				for (size_t i = 0; i < szmap && n < maxcol; ++i) {
					colarr[n++] = &pmap[i];
				}
			}
			else if (pdefsubsys_) {
				const auto		*pmap = pdefsubsys_->pjsonmap;
				const size_t		szmap = pdefsubsys_->szjsonmap;

				for (size_t i = 0; i < szmap && n < maxcol; ++i) {
					colarr[n++] = &pmap[i];
				}
			}

			return {n, false};
		}	

		const JSON_DB_MAPPING		*nondbcol[MAX_COLUMN_LIST];
		size_t				nnondb = 0;

		for (size_t i = 0; i < ncols_ && n < maxcol; ++i) {
			if (pdefsubsys_->subsysval == subsys || subsys == SUBSYS_MAX) {
				if (columnarr_[i]->dbcolname[0]) {
					colarr[n++] = columnarr_[i];
				}
				else if (nnondb < GY_ARRAY_SIZE(nondbcol)) {
					nondbcol[nnondb++] = columnarr_[i];
				}	
			}
		}

		// Other columns not present in DB schema
		for (size_t i = 0; i < nnondb && n < maxcol; ++i) {
			colarr[n++] = nondbcol[i];
		}

		return {n, true};
	}	

	// Returns {ncol, is_col_spec} for queries spanning multiple subsystems. The returned columns will be in DB resultset order.
	std::pair<size_t, bool> get_all_column_list(const JSON_DB_MAPPING **colarr, size_t maxcol, SUBSYS_CLASS_E subsys, bool ign_col_list = false) const 
	{
		if (((uint32_t)subsys > SUBSYS_MAX) || (maxcol < 5) || !colarr) {
			return {};
		}

		if (false == is_multi_host()) {
			return get_column_list(colarr, maxcol, subsys, ign_col_list);
		}

		static_assert(json_db_host_arr[0].jsoncrc == FIELD_PARID && json_db_host_arr[1].jsoncrc == FIELD_HOST && json_db_host_arr[3].jsoncrc == FIELD_CLUSTER);

		colarr[0] 		= &json_db_host_arr[0];
		colarr[1]		= &json_db_host_arr[1];
		colarr[2]		= &json_db_host_arr[2];
		colarr[3]		= &json_db_host_arr[3];
		
		auto [ncol, is_col_spec] = get_column_list(colarr + 4, maxcol - 4, subsys, ign_col_list);

		return {ncol + 4, is_col_spec};
	}	

	// Get DB query column string. Specify subsys as SUBSYS_MAX to get all subsystem columns
	char * get_db_table_columns(STR_WR_BUF & strbuf, SUBSYS_CLASS_E subsys, const char *table_alias_prefix = "", bool ign_col_list = false) const 
	{
		if (((columnarr_ == nullptr) || (ncols_ == 0)) || (subsys == SUBSYS_MAX) || ign_col_list) {
			strbuf.appendfmt(" %s* ", table_alias_prefix);

			return strbuf.buffer();
		}	

		size_t			n = 0;

		for (size_t i = 0; i < ncols_; ++i) {
			if (pdefsubsys_ && columnarr_ && (pdefsubsys_->subsysval == subsys) && (columnarr_[i]->dbcolname[0])) {
				if (n > 0) {
					strbuf.append(',');
				}	
				strbuf.appendfmt(" %s%s ", table_alias_prefix, columnarr_[i]->dbcolname);

				n++;
			}	
		}	
		
		if (n == 0) {
			strbuf.appendconst(" null ");
		}

		return strbuf.buffer();
	}	

	// Get DB query column definitions for use with plpgsql row type returns. Returns # columns
	size_t get_db_column_definition(STR_WR_BUF & strbuf, SUBSYS_CLASS_E subsys, bool ign_col_list = false) const 
	{
		size_t			n = 0;

		if ((uint32_t)subsys >= SUBSYS_MAX) {
			return 0;
		}

		if ((columnarr_ == nullptr) || (ncols_ == 0) || ign_col_list) {
			auto			jsonmap = subsys_class_list[subsys].pjsonmap;
			auto			szjson 	= subsys_class_list[subsys].szjsonmap;

			for (size_t i = 0; i < szjson; ++i) {
				if (jsonmap[i].dbcolname[0]) {
					if (n > 0) {
						strbuf.append(',');
					}	
					strbuf.appendfmt(" %s %s ", jsonmap[i].dbcolname, jsonmap[i].dbtype);
				
					n++;
				}
			}	
			
			return n;
		}	


		for (size_t i = 0; i < ncols_; ++i) {
			if (pdefsubsys_ && columnarr_ && (pdefsubsys_->subsysval == subsys) && (columnarr_[i]->dbcolname[0])) {
				if (n > 0) {
					strbuf.append(',');
				}	
				strbuf.appendfmt(" %s %s ", columnarr_[i]->dbcolname, columnarr_[i]->dbtype);

				n++;
			}	
		}	
		
		return n;
	}	

	char * get_db_time_param(STR_WR_BUF & strbuf, SUBSYS_CLASS_E subsys, const char *tablename, const char *datetbl = "", const char *table_alias_prefix = "", const char * fallback = "(true)") const 
	{
		if (*starttime_ && (uint32_t)subsys < SUBSYS_MAX && subsys_class_list[subsys].pjsonmap) {
			const auto		*ptimecol = get_jsoncrc_mapping(FIELD_TIME, subsys_class_list[subsys].pjsonmap, subsys_class_list[subsys].szjsonmap);
			
			if (!ptimecol && subsys == SUBSYS_ALERTS) {
				ptimecol = &json_db_alerts_arr[0];
			}	

			if (ptimecol && ptimecol->dbcolname[0]) {
				char			cs = *starttime_, ce = *endtime_;

				if (cs >= '0' && cs <= '9') {
					cs = '\'';
				}	
				else {
					cs = ' ';
				}	
				
				if (ce >= '0' && ce <= '9') {
					ce = '\'';
				}	
				else {
					ce = ' ';
				}	

				if (point_in_time_ == true) {
					if (is_multihost_) {
						// schema already set by gy_multihostselect
						strbuf.appendfmt(" %stime = ( select max(time) from %s%s where time between %c%s%c::timestamptz and %c%s%c::timestamptz ) ", 
							table_alias_prefix, tablename, datetbl, cs, starttime_, cs, ce, endtime_, ce);
					}
					else {
						if (((0 == memcmp(tablename, "sch", 3)) || (0 == memcmp(tablename, "public", 6))) && (strchr(tablename, '.'))) {
							strbuf.appendfmt(" %stime = ( select max(time) from %s%s where time between %c%s%c::timestamptz and %c%s%c::timestamptz ) ", 
								table_alias_prefix, tablename, datetbl, cs, starttime_, cs, ce, endtime_, ce);
						}
						else {
							strbuf.appendfmt(" %stime = ( select max(time) from sch%s.%s%s where time between %c%s%c::timestamptz and %c%s%c::timestamptz ) ", 
								table_alias_prefix, get_parid().get_string().get(), tablename, datetbl, cs, starttime_, cs, ce, endtime_, ce);
						}
					}	
				}
				else {
					strbuf.appendfmt(" %stime between %c%s%c::timestamptz and %c%s%c::timestamptz ", 
							table_alias_prefix, cs, starttime_, cs, ce, endtime_, ce);
				}
				
				return strbuf.buffer();
			}
		}	
		
		strbuf.append(fallback);

		return strbuf.buffer();
	}	
	
	char * get_db_sort_limit(STR_WR_BUF & strbuf, SUBSYS_CLASS_E subsys, const char *table_alias_prefix = "", bool ignorelimit = false, bool ignoresort = false) const 
	{
		if (!ignoresort && nsort_ > 0 && nsort_ <= MAX_SORT_COLUMNS) {
			size_t		n = 0;

			for (size_t i = 0; i < nsort_; ++i) {
				if (sortsubsys_[i] && (is_multihost_ || sortsubsys_[i]->subsysval == subsys)) {
					if (n > 0) {
						strbuf.append(',');
					}	
					else {
						strbuf.appendconst(" order by ");
					}	
					strbuf.appendfmt(" %s%s %s ", table_alias_prefix, sortcolarr_[i]->dbcolname, sortdir_[i] == SORT_DIR_ASC ? "asc" : "desc");
					n++;
				}	
			}	
		}	

		if (!ignorelimit) {
			if (maxrecs_) {
				strbuf.appendfmt(" limit %lu ", maxrecs_);
			}	

			if (recoffset_) {
				strbuf.appendfmt(" offset %lu ", recoffset_);
			}	
		}

		return strbuf.buffer();
	}	

	char * get_db_filters(STR_WR_BUF & strbuf, SUBSYS_CLASS_E subsys, const char *table_alias_prefix = "", const char * fallback = "(true)", bool add_multihost_subsys = false) const
	{
		return criteria_.get_db_filter_criteria(strbuf, subsys, table_alias_prefix, fallback, add_multihost_subsys && (subsys != SUBSYS_HOST), "thost.");
	}	

	char * get_db_where_clause(STR_WR_BUF & strbuf, SUBSYS_CLASS_E subsys, const char *tablename, const char *datetbl = "", const char *table_alias_prefix = "", bool add_multihost_subsys = false) const
	{
		size_t			ntotalcrit = criteria_.get_total_ncriteria();
		bool			is_parid = false;
		const auto		psubsys = get_subsys_info(subsys);

		if (!psubsys) {
			return strbuf.buffer();
		}

		if (ntotalcrit || *starttime_) {

			if (*table_alias_prefix) {
				assert(table_alias_prefix[strlen(table_alias_prefix) - 1] == '.');
			}	

			strbuf.appendconst(" where ");

			if (is_multihost_ == false && psubsys->machidfilstr) {
				is_parid = true;
				strbuf.appendfmt(psubsys->machidfilstr, table_alias_prefix, get_parid_str().get());
			}

			if (*starttime_) {
				if (is_parid) {
					strbuf.appendconst(" and ");
				}
				get_db_time_param(strbuf, subsys, tablename, datetbl, table_alias_prefix);
			}	

			if (ntotalcrit) {
				if (*starttime_ || is_parid) {
					strbuf.appendconst(" and ");
				}


				if (!add_multihost_subsys && force_subsys_multihost(subsys)) {
					get_db_filters(strbuf, SUBSYS_HOST, "", "(true)", true);
					strbuf.appendconst(" and ");
				}	

				get_db_filters(strbuf, subsys, table_alias_prefix, "(true)", add_multihost_subsys);
			}	
		}
		else if (is_multihost_ == false && psubsys->machidfilstr) {
			strbuf.appendconst(" where ");
			strbuf.appendfmt(psubsys->machidfilstr, table_alias_prefix, get_parid_str().get());
		}	

		return strbuf.buffer();
	}

	bool is_db_where_clause() const noexcept
	{
		return (0 != *starttime_ || criteria_.get_total_ncriteria() > 0);
	}	

	// Explicitly set sort column
	void set_sort_column(const char *colname, SORT_DIR_E dir, const JSON_DB_MAPPING *pjsonmap, size_t szjsonmap, const JSON_DB_MAPPING *phostjsonmap, size_t szhostjsonmap, \
					const SUBSYS_CLASS *pmainsubsys, const SUBSYS_CLASS *phostsubsys, bool throw_on_error = false) 
	{
		bool			ishost = false;
		const auto		*pcol = get_jsoncrc_mapping(colname, strlen(colname), pjsonmap, szjsonmap);
			
		if (!pcol) {
			pcol = get_jsoncrc_mapping(colname, strlen(colname), phostjsonmap, szhostjsonmap);

			if (!pcol) {
				if (throw_on_error) {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Options : Invalid Column Name \'%s\' specified for setting sort", colname);
				}
				return;
			}

			ishost = true;
		}	
		else if (pcol->dbcolname[0] == 0) {
			if (throw_on_error) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Options : Column Name \'%s\' specified for setting sort not present in DB schema", colname);
			}
			return;
		}	

		for (size_t i = 0; i < nsort_; ++i) {
			if (sortcolarr_[i] == pcol && (sortsubsys_[i] == pmainsubsys || sortsubsys_[i] == phostsubsys)) {
				return;
			}	
		}	
			
		if (nsort_ >= MAX_SORT_COLUMNS) {
			if (throw_on_error) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Options : Max Sort Columns limit breached for setting new sort column for column \'%s\'", colname);
			}
			return;
		}

		sortcolarr_[nsort_] 	= pcol;
		sortsubsys_[nsort_] 	= ishost == false ? pmainsubsys : phostsubsys;
		sortdir_[nsort_]	= dir;
		nsort_++;
	}	

	// Externally set start/end times
	void set_timestamps(const char * pstarttime, const char * pendtime, struct timeval tvstart, struct timeval tvend, bool pointintime) noexcept
	{
		GY_STRNCPY(starttime_, pstarttime, sizeof(starttime_));
		GY_STRNCPY(endtime_, pendtime, sizeof(endtime_));

		tvstart_ 	= tvstart;
		tvend_		= tvend;
		point_in_time_	= pointintime;
	}

	// Externally set start/end times
	void set_timestamps(time_t tstart, time_t tend, bool pointintime) noexcept
	{
		tvstart_ 	= {tstart, 0};
		tvend_ 		= {tend, 0};
		point_in_time_	= pointintime;
				
		snprintf(starttime_, sizeof(starttime_), "to_timestamp(%ld)", tstart);
		snprintf(endtime_, sizeof(endtime_), "to_timestamp(%ld)", tend);
	}


	char * get_date_trunc_str(STR_WR_BUF & strbuf) noexcept;

	char * get_db_select_query(STR_WR_BUF & strbuf, SUBSYS_CLASS_E subsys, const char *tablename, const char *table_alias_prefix = "", bool ign_col_list = false) const;

	char * get_db_select_multihost_query(STR_WR_BUF & strbuf, SUBSYS_CLASS_E subsys, const char *tablename, const char *datetbl = "", bool ign_col_list = false) const;

	uint32_t get_select_aggr_query(STR_WR_BUF & strbuf, SUBSYS_CLASS_E subsys, JSON_DB_MAPPING (& pcolarr)[MAX_AGGR_COLUMNS], const char *tablename, \
							const char * extra_inner_where = "", EXT_POOL_ALLOC *pstrpool = nullptr);

	uint32_t get_select_aggr_multihost_query(STR_WR_BUF & strbuf, SUBSYS_CLASS_E subsys, JSON_DB_MAPPING (& pcolarr)[MAX_AGGR_COLUMNS], const char *tablename, const char *datetbl = "", \
							const char * extra_inner_where = "", EXT_POOL_ALLOC *pstrpool = nullptr);

	void set_sort_options(const JSON_DB_MAPPING *pjsonmap, size_t szjsonmap, const JSON_DB_MAPPING *phostjsonmap, size_t szhostjsonmap, \
							const SUBSYS_CLASS *pmainsubsys, const SUBSYS_CLASS *phostsubsys);
	
	std::tuple<uint32_t, uint32_t, uint32_t> get_custom_aggr_columns(SUBSYS_CLASS_E subsys, const JSON_DB_MAPPING *pajsonmap, size_t szajsonmap, \
							const JSON_DB_MAPPING *phostjsonmap, size_t szhostjsonmap, \
							const DB_AGGR_INFO *paggrinfo, JSON_DB_MAPPING *pcolarr, DB_AGGR_INFO *dbinnerarr, DB_AGGR_INFO *dbouterarr, DB_AGGR_INFO *dbpostaggrarr, \
							EXT_POOL_ALLOC & strpool);

	void set_aggr_where_clause(STR_WR_BUF & strbuf, const JSON_DB_MAPPING *pjsonmap, size_t szjsonmap);

	void aggr_column_query(STR_WR_BUF & strbuf, const DB_AGGR_INFO *dbarr, uint32_t ncol, uint32_t ninitcol = 0) const;

	uint32_t aggr_groupby_query(STR_WR_BUF & strbuf, const DB_AGGR_INFO *dbarr, uint32_t ncol, uint32_t ninitgroupby = 0) const;

	bool to_enable_multi_madhava_aggr() const;

	static bool has_aggr_oper(const char * colname) noexcept;

private :
	void parse_aggr_col_expr(SUBSYS_CLASS_E subsys, const char *colname, size_t szcol, uint32_t colnum, uint32_t & noutcol, uint32_t & nincol, uint32_t & npostcol, JSON_DB_MAPPING *pcolarr, \
					DB_AGGR_INFO *dbinnerarr, DB_AGGR_INFO *dbouterarr, DB_AGGR_INFO *dbpostaggrarr, EXT_POOL_ALLOC & strpool, \
					const JSON_DB_MAPPING *pjsonmap, size_t szjsonmap) const;

	bool parse_one_aggr_colname(const char *colname, size_t szcol, const char * pfield, uint32_t fieldcrc, uint32_t & noutcol, uint32_t & nincol, \
					DB_AGGR_INFO *dbinnerarr, DB_AGGR_INFO *dbouterarr, EXT_POOL_ALLOC & strpool, \
					const JSON_DB_MAPPING *pjsonmap, size_t szjsonmap, const JSON_DB_MAPPING *pajsonmap, size_t szajsonmap) const;

};	

struct COND_JSON_PARAM
{
	COND_VAR<SCOPE_GY_MUTEX>	cond_;
	std::atomic<int>		nupdated_	{0};
	char				msg_[180]	{};
	JSON_DOCUMENT<4096, 2048>	doc_;

	std::optional<bool> result_status() const noexcept
	{
		int			status = nupdated_.load(mo_acquire);

		if (status == 1) {
			return true;
		}	
		else if (status < 0) {
			return false;
		}	
		else {
			// Pending
			return {};
		}
	}

	GEN_JSON_DOC & get_json_result() noexcept
	{
		return doc_.get_doc();
	}	
};


enum DB_LOGGING_E : uint8_t
{
	DB_LOGGING_NONE		= 0,		// Only unlogged DB tables
	DB_LOGGING_PARTIAL,			// Current day DB tables unlogged, historical (yesterday and older) data logged
	DB_LOGGING_ALWAYS,			// Only logged DB tables	
};	

static DB_LOGGING_E get_db_logging_level(const char *logmode) noexcept
{
	if (!logmode) {
		return DB_LOGGING_PARTIAL;
	}	

	char			c = tolower(*logmode);

	if (c == 'n') {
		return DB_LOGGING_NONE;
	}	
	else if (c == 'a') {
		return DB_LOGGING_ALWAYS;
	}	

	return DB_LOGGING_PARTIAL;
}	

static const char * get_db_logging_level_str(DB_LOGGING_E logmode) noexcept
{
	switch (logmode) {
	
	case DB_LOGGING_PARTIAL		:	return "partial";

	case DB_LOGGING_ALWAYS		:	return "always";

	case DB_LOGGING_NONE		:	return "none";

	default				:	return "unknown";
	}	
}	

static CHAR_BUF<128> get_db_comma_array_split(const char * field) noexcept
{
	CHAR_BUF<128>			cbuf;

	snprintf(cbuf.get(), sizeof(cbuf), "unnest(string_to_array(%s, \',\'))", field);

	return cbuf;
}	

static char * get_db_date_trunc(STR_WR_BUF & strbuf, int trunc_sec, const char *timefield = "time") noexcept
{
	switch (trunc_sec) {
	
	case 3600 		:	return strbuf.appendfmt(" date_trunc('hour', %s) ", timefield);	

	case 3600 * 24		:	return strbuf.appendfmt(" date_trunc('day', %s) ", timefield);

	case 3600 * 24 * 7	:	return strbuf.appendfmt(" date_trunc('week', %s) ", timefield);

	case 3600 * 24 * 30	:	
	case 3600 * 24 * 31	:	
	case GY_SEC_PER_MONTH	:
					return strbuf.appendfmt(" date_trunc('month', %s) ", timefield);

	case 3600 * 24 * 365	:	
	case GY_SEC_PER_YEAR	:
					return strbuf.appendfmt(" date_trunc('year', %s) ", timefield);

	default			:	return strbuf.appendfmt(" public.date_trunc_by_interval('%u sec'::interval, %s) ", trunc_sec, timefield);
	}	
}


/*
 * Will try to avoid the main partitioned table if the start and end times fall within the same 24 hours 
 * wrt Madhava/Shyama timezone. if skipsec > 0, skips the first and last skipsec sec of the day for
 * partition table check
 * 
 * If ptdaystart != nullptr and Day partition is valid, ptdaystart will be updated with time_t of day start, else 0
 */
static CHAR_BUF<16> get_db_day_partition(time_t starttime, time_t endtime, uint32_t skipsec, time_t *ptdaystart = nullptr) noexcept
{
	CHAR_BUF<16>			partbl;
	time_t				td, tdaystart = 0;

	if (starttime >= endtime - 24 * 3600) {
		struct tm 		tm = {};

		assert(skipsec < 3600 * 12);

		localtime_r(&endtime, &tm);
		
		td = tm.tm_hour * 3600 + tm.tm_min * 60 + tm.tm_sec;

		tdaystart = endtime - td;
		
		if (starttime > tdaystart + skipsec && endtime < tdaystart + 24 * 3600 - skipsec) {
			snprintf(partbl.get(), sizeof(partbl), "_%04d%02d%02d", 1900 + tm.tm_year, (int8_t)tm.tm_mon + 1, (int8_t)tm.tm_mday);
		}	
	}
	else {
		*partbl.get() = 0;
	}

	if (ptdaystart) {
		*ptdaystart = tdaystart;
	}	

	return partbl;
}	

static CHAR_BUF<16> get_db_day_partition(time_t tnow, uint32_t skipsec = 0) noexcept
{
	return get_db_day_partition(tnow, tnow, skipsec, nullptr);
}	

// Init Command to set Postgres Connection timezone to local timezone
static CHAR_BUF<128> get_db_init_commands() noexcept
{
	CHAR_BUF<128>			cbuf;
	STR_WR_BUF			strbuf(cbuf.get(), sizeof(cbuf));

	if (auto ptz = GY_TIMEZONE::get_singleton(); ptz) {
		strbuf.appendfmt("set time zone \'%s\';", ptz->get_tz_string());
	}

	strbuf.appendconst("set client_min_messages to warning;");

	return cbuf;
}	

static NODE_MSG_TYPE_E gy_get_json_mtype(const GEN_JSON_VALUE & jdoc)
{
	auto 			it = jdoc.FindMember("mtype");

	if (gy_unlikely(it == jdoc.MemberEnd())) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Message : Required Message Type field mtype not found");
	}

	if (false == it->value.IsInt()) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Message : Required Message Type field mtype not a valid type");
	}	

	int			mtype = it->value.GetInt();

	switch (mtype) {

	case NODE_MSG_QUERY 	:	return NODE_MSG_QUERY;
	case NODE_MSG_ADD	:	return NODE_MSG_ADD;
	case NODE_MSG_UPDATE	:	return NODE_MSG_UPDATE;
	case NODE_MSG_DELETE	:	return NODE_MSG_DELETE;
	case NODE_MSG_PING	:	return NODE_MSG_PING;

	default			:	GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Message Type Field %d seen", mtype); break;
	}	
}	

static NODE_QUERY_TYPE_E gy_get_json_qtype(const GEN_JSON_VALUE & jdoc, const char * perrprefix = "Invalid Message", bool is_noexcept = false)
{
	auto 			it = jdoc.FindMember("qtype");

	if (gy_unlikely(it == jdoc.MemberEnd())) {
		if (is_noexcept) {
			return NQUERY_MAX_TYPE;
		}	
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "%s : Required Query Type qtype field not found", perrprefix);
	}

	if (false == it->value.IsInt()) {
		if (is_noexcept) {
			return NQUERY_MAX_TYPE;
		}	
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "%s : Required Message Type field qtype not a valid type", perrprefix);
	}	

	int			qtype = it->value.GetInt();

	if (qtype > NQUERY_MIN_TYPE && qtype < NQUERY_MAX_TYPE) {
		return (NODE_QUERY_TYPE_E)qtype;
	}

	if (qtype == NQUERY_NM_MULTI_QUERY) {
		return NQUERY_NM_MULTI_QUERY;
	}	

	if (is_noexcept) {
		return NQUERY_MAX_TYPE;
	}	
	GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "%s : Invalid Query Type Field qtype %d seen", perrprefix, qtype); 
}	

template <typename JsonWriter>
void set_json_column_list(JsonWriter & writer, const JSON_DB_MAPPING **colarr, uint32_t ncol)
{
	if (!colarr || !ncol) {
		return;
	}	

	writer.KeyConst("columns");
	writer.StartArray();

	for (uint32_t i = 0; i < ncol; ++i) {
		const auto		*pcol = colarr[i];

		if (pcol->jsonfield[0] == 0) {
			continue;
		}	

		writer.StartObject();

		writer.KeyConst("name");
		writer.String(pcol->jsonfield, pcol->szjson);

		writer.KeyConst("type");
		writer.String(get_json_type_str(pcol->jsontype));

		writer.EndObject();
	}	

	writer.EndArray();
}	


/*
 * Callback that can be used to get DB query output to json writer
 */
template <typename JsonWriter, typename ExtraCB>
bool default_db_json_cb(GyPGConn & conn, GyPGresult && gyres, bool is_completed, const char *name, const JSON_DB_MAPPING **colarr, uint32_t ncol, \
					JsonWriter & writer, int & total_rows, ExtraCB & extracb, bool send_null_columns = true) 
{
	if (is_completed) {
		conn.make_available();
		return true;
	}	
	
	if (true == gyres.is_error()) {
		DEBUGEXECN(1,
			WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "%s : Failed to query from DB due to %s (Total tuples returned so far %d)\n", 
					name, gyres.get_error_msg(), total_rows);
		);

		if (0 == strcmp(gyres.get_sqlcode(), "42P01")) {
			GY_THROW_EXPR_CODE(ERR_DATA_NOT_FOUND, "%s : Failed to query from DB as no such table exists which may be due to data expiry", name);
		}	

		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Failed to query %s from DB due to %s", name, gyres.get_error_msg());
	}	

	char				tbuf[512];
	const PGresult *		pres = gyres.get();
	const int			nfields = PQnfields(pres);
	const int			ntuples = PQntuples(gyres.get());

	if (ntuples > 0 && (unsigned)nfields > ncol) {
		GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "%s : Invalid DB Column count seen : %d instead of %u", name, nfields, ncol);
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
				if (strcmp(pfname, colarr[col]->dbcolname)) {
					GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "Invalid DB Column name seen for %s : %s instead of %s", 
						name, pfname, colarr[col]->dbcolname);
				}	

				if ((colarr[col]->dbstrtype == DB_STR_OCHAR) && (PG_BPCHAROID != PQftype(pres, col))) {
					GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "Invalid DB Column type seen for %s : %d instead of %d", 
						name, PQftype(pres, col), PG_BPCHAROID);
				}	
			}	

			if (colarr[col]->szjson == 0) {
				// Ignore this field
				continue;
			}	

			const char 		*pdata;
			int			len = PQgetlength(pres, row, col), rlen;

			if (len == 0) {
				pdata = "";

				if (true == PQgetisnull(pres, row, col)) {

					if (send_null_columns == false) {
						continue;
					}

					if (colarr[col]->jsontype == JSON_NUMBER) {
						pdata = "0";
						len = 1;
					}	
					else if (colarr[col]->jsontype == JSON_BOOL) {
						pdata = "false";
						len = 5;
					}	
				}	
			}
			else {
				pdata = PQgetvalue(pres, row, col);
			}

			if (len && colarr[col]->dbstrtype == DB_STR_OCHAR) {
				rlen = get_rtrim_len(pdata, len);
			}
			else {
				rlen = len;
			}	

			if (colarr[col]->dboper) {
				auto 		p = colarr[col]->dboper(pdata, rlen, tbuf, sizeof(tbuf));

				pdata = p.first;
				rlen = p.second;
			}	
			
			writer.Key(colarr[col]->jsonfield, colarr[col]->szjson);

			if ((colarr[col]->jsontype != JSON_STRING) || (colarr[col]->dbstrtype == DB_RAW_STRING)) {
				writer.RawValue(pdata, rlen, rapidjson::kNumberType);
			}
			else {
				writer.String(pdata, rlen);
			}
		}	

		/*
		 * Additional fields not present in DB
		 */
		extracb(writer);

		char			rowidbuf[64];
		uint32_t		rowlen = snprintf(rowidbuf, sizeof(rowidbuf), "%d", total_rows + 1);

		writer.KeyConst("rowid");
		writer.String(rowidbuf, rowlen);

		writer.EndObject();
		
		total_rows++;
	}	

	return true;
}


/*
 * Callback that can be used to get DB query output in std::string_view [] format with custom RowCB() called for each row.
 * NULL columns are specified as empty std::string_views
 * 
 * RowCB callback params :  RowCB(int numrow, const JSON_DB_MAPPING **pcolarr, std::string_view colview[], uint32_t ncol)
 * numrow is 0 based
 */
template <typename RowCB>
bool default_db_strview_cb(GyPGConn & conn, GyPGresult && gyres, bool is_completed, const char *name, const JSON_DB_MAPPING **colarr, uint32_t ncol, int & total_rows, RowCB & rowcb)
{
	if (is_completed) {
		conn.make_available();
		return true;
	}	
	
	if (true == gyres.is_error()) {
		DEBUGEXECN(1,
			WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "%s : Failed to query from DB due to %s (Total tuples returned so far %d)\n", 
					name, gyres.get_error_msg(), total_rows);
		);

		if (0 == strcmp(gyres.get_sqlcode(), "42P01")) {
			GY_THROW_EXPR_CODE(ERR_DATA_NOT_FOUND, "%s : Failed to query from DB as no such table exists which may be due to data expiry", name);
		}	

		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Failed to query %s from DB due to %s", name, gyres.get_error_msg());
	}	

	char				tbuf[512];
	const PGresult *		pres = gyres.get();
	const int			nfields = PQnfields(pres);
	const int			ntuples = PQntuples(gyres.get());

	if (ntuples > 0 && (unsigned)nfields > ncol) {
		GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "%s : Invalid DB Column count seen : %d instead of %u", name, nfields, ncol);
	}	

	std::string_view		colstrviews[nfields];

	for (int row = 0; row < ntuples; ++row) {
		for (int col = 0; col < nfields; ++col) {
			const char	*pfname = PQfname(pres, col);

			if (!pfname) {
				for (; col < nfields; ++col) {
					colstrviews[col] = {};
				}	
				break;
			}	

			if (total_rows == 0) {
				// Validate schema
				if (strcmp(pfname, colarr[col]->dbcolname)) {
					GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "Invalid DB Column name seen for %s : %s instead of %s", 
						name, pfname, colarr[col]->dbcolname);
				}	

				if ((colarr[col]->dbstrtype == DB_STR_OCHAR) && (PG_BPCHAROID != PQftype(pres, col))) {
					GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "Invalid DB Column type seen for %s : %d instead of %d", 
						name, PQftype(pres, col), PG_BPCHAROID);
				}	
			}	

			const char 		*pdata;
			int			len = PQgetlength(pres, row, col), rlen;

			if (len == 0) {
				pdata = "";
			}
			else {
				pdata = PQgetvalue(pres, row, col);
			}

			if (len && colarr[col]->dbstrtype == DB_STR_OCHAR) {
				rlen = get_rtrim_len(pdata, len);
			}
			else {
				rlen = len;
			}	

			colstrviews[col] = std::string_view(pdata, rlen);
		}	

		rowcb(total_rows, colarr, colstrviews, nfields);

		total_rows++;
	}	

	return true;
}

// neversec is the sec to return in case of "never" string
extern std::optional<size_t> get_time_modifier_secs(const char *ptimemod, size_t szmod, size_t neversec = ~0u) noexcept;

extern uint32_t	get_hoststate_aggr_query(STR_WR_BUF & strbuf, QUERY_OPTIONS & qryopt, const char *datetbl, JSON_DB_MAPPING (& pcolarr)[QUERY_OPTIONS::MAX_AGGR_COLUMNS], \
							EXT_POOL_ALLOC *pstrpool = nullptr);

extern uint32_t get_cpumem_aggr_query(STR_WR_BUF & strbuf, QUERY_OPTIONS & qryopt, const char *datetbl, JSON_DB_MAPPING (& pcolarr)[QUERY_OPTIONS::MAX_AGGR_COLUMNS], \
							EXT_POOL_ALLOC *pstrpool = nullptr);

extern uint32_t get_svcsumm_aggr_query(STR_WR_BUF & strbuf, QUERY_OPTIONS & qryopt, const char *datetbl, JSON_DB_MAPPING (& pcolarr)[QUERY_OPTIONS::MAX_AGGR_COLUMNS], \
							EXT_POOL_ALLOC *pstrpool = nullptr);

extern uint32_t get_activeconn_aggr_query(STR_WR_BUF & strbuf, QUERY_OPTIONS & qryopt, const char *datetbl, JSON_DB_MAPPING (& pcolarr)[QUERY_OPTIONS::MAX_AGGR_COLUMNS], \
							EXT_POOL_ALLOC *pstrpool = nullptr, bool is_extended = false);

extern uint32_t get_clientconn_aggr_query(STR_WR_BUF & strbuf, QUERY_OPTIONS & qryopt, const char *datetbl, JSON_DB_MAPPING (& pcolarr)[QUERY_OPTIONS::MAX_AGGR_COLUMNS], \
							const char *madhava_id_str, EXT_POOL_ALLOC *pstrpool = nullptr, bool is_extended = false);

extern uint32_t get_svcstate_aggr_query(STR_WR_BUF & strbuf, QUERY_OPTIONS & qryopt, const char *datetbl, JSON_DB_MAPPING (& pcolarr)[QUERY_OPTIONS::MAX_AGGR_COLUMNS], \
							EXT_POOL_ALLOC *pstrpool = nullptr, bool is_extended = false);

extern uint32_t get_svcinfo_aggr_query(STR_WR_BUF & strbuf, QUERY_OPTIONS & qryopt, const char *datetbl, JSON_DB_MAPPING (& pcolarr)[QUERY_OPTIONS::MAX_AGGR_COLUMNS], \
							EXT_POOL_ALLOC *pstrpool = nullptr);

extern uint32_t	get_procstate_aggr_query(STR_WR_BUF & strbuf, QUERY_OPTIONS & qryopt, const char *datetbl, JSON_DB_MAPPING (& pcolarr)[QUERY_OPTIONS::MAX_AGGR_COLUMNS], \
							EXT_POOL_ALLOC *pstrpool = nullptr, bool is_extended = false);

extern uint32_t	get_procinfo_aggr_query(STR_WR_BUF & strbuf, QUERY_OPTIONS & qryopt, const char *datetbl, JSON_DB_MAPPING (& pcolarr)[QUERY_OPTIONS::MAX_AGGR_COLUMNS], \
							EXT_POOL_ALLOC *pstrpool = nullptr);

extern uint32_t get_hostinfo_aggr_query(STR_WR_BUF & strbuf, QUERY_OPTIONS & qryopt, JSON_DB_MAPPING (& pcolarr)[QUERY_OPTIONS::MAX_AGGR_COLUMNS], \
							EXT_POOL_ALLOC *pstrpool = nullptr);

extern uint32_t get_clusterstate_aggr_query(STR_WR_BUF & strbuf, QUERY_OPTIONS & qryopt, const char *datetbl, JSON_DB_MAPPING (& pcolarr)[QUERY_OPTIONS::MAX_AGGR_COLUMNS], \
							EXT_POOL_ALLOC *pstrpool = nullptr);

extern uint32_t get_alerts_aggr_query(STR_WR_BUF & strbuf, QUERY_OPTIONS & qryopt, const char *datetbl, JSON_DB_MAPPING (& pcolarr)[QUERY_OPTIONS::MAX_AGGR_COLUMNS], \
							EXT_POOL_ALLOC *pstrpool = nullptr);

extern void init_subsys_maps();

extern void validate_json_name(const char *pname, size_t namelen, size_t maxlen, const char *ptype = "Field Name", bool firstalphaonly = true, bool emptyok = false, \
							const char * extrainvchars = nullptr);

extern void validate_db_name(const char *pname, size_t namelen, size_t maxlen, const char *ptype = "Field Name");

extern const char * get_common_instancemaster_tbl() noexcept;

extern const char * get_common_instancemaster_proc() noexcept;

extern const char * get_common_pg_procs() noexcept;

} // namespace gyeeta

