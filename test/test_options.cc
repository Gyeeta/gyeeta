
#include			"gy_query_common.h"

using namespace gyeeta;

constexpr const char		*optionarr[] = {
	R"(
		{
			"starttime"		: "2020-09-19T15:20:30+05:30",
			"endtime"		: "2020-09-19T16:20:30+05:30",
			"qtype"			: 1002,
			"options"		: {
				"columns"	: ["parid", "host", "cluster", "nproc", "state"],	
				"sortcolumns"	: ["nproc", "state"],	
				"sortdir"	: ["asc", "desc", "asc"],
				"maxrecs"	: 10000
			},
			"filter" : "{ hoststate.state in 'OK','Bad', 'Severe' } and ( { host.parid =  '97d04b2bfccda84198797c1f260e8edd' } or { host.host like '(?i)host[0-9]*dev\\.local' } ) "
		}
	)",

	R"(
		{
			"starttime"		: "2020-09-19T15:20:30+05:30",
			"endtime"		: "2020-09-19T15:20:40+05:30",
			"parid"			: "97d04b2bfccda84198797c1f260e8edd",
			"qtype"			: 1002
		}	
	)",

	R"(
		{
			"starttime"		: "2020-09-19T15:20:30+05:30",
			"endtime"		: "2020-09-19T15:20:40+05:30",
			"qtype"			: 1002,
			"options"		: {
				"columns"	: ["time", "nlistissue", "nproc", "nprocsevere"],
				"maxrecs"	: 10000000,
				"pointintime"	: true
			},
			"filter" : "{ hoststate.nlistissue > hoststate.nprocsevere } and { host.cluster in  'cluster1','cluster2', 'cluster3' }"
		}	
	)",

	/*
	R"(
		{
			"options"		: {
				"columns"	: ["nproc", "nlistsevere"],	
				"maxrecs"	: 10000000,
				"pointintime"	: true
			}
		}	
	)",
	*/

};	

int main()
{
	try {
		INFOPRINTCOLOR(GY_COLOR_CYAN, "Testing query options ...\n\n");
		
		STACK_POOL_ALLOC_64K	stackpool;
		/*STACK_POOL_ALLOC<64>	stackpool;*/
		QUERY_OPTIONS		optset[GY_ARRAY_SIZE(optionarr)];

		for (size_t i = 0; i < GY_ARRAY_SIZE(optionarr); ++i) {
			JSON_DOCUMENT<2048, 2048>		jdoc;
			auto					& doc = jdoc.get_doc();

			if (doc.Parse(optionarr[i]).HasParseError()) {
				ERRORPRINTCOLOR(GY_COLOR_RED, "Invalid json : Error at offset %lu : Error is \'%s\'\n\n", 
					doc.GetErrorOffset(), rapidjson::GetParseError_En(doc.GetParseError()));
				return -1;
			}	

			optset[i].~QUERY_OPTIONS();
			
			try {
				new (optset + i) QUERY_OPTIONS(doc, stackpool);
			}
			GY_CATCH_EXPRESSION(
				ERRORPRINTCOLOR(GY_COLOR_RED, "Invalid Options specified for \'%s\' : %s\n\n", optionarr[i], GY_GET_EXCEPT_STRING);
				continue;
			);

			STRING_BUFFER<4096>		strbuf;

			INFOPRINT("Option \'%s\' : \n", optionarr[i]);

			optset[i].get_db_select_query(strbuf, SUBSYS_HOST, "parthatbl");

			INFOPRINTCOLOR(GY_COLOR_GREEN, "Query for host subsystem is \'%s\'\n\n", strbuf.buffer());    

			strbuf.reset();

			optset[i].get_db_select_query(strbuf, SUBSYS_HOSTSTATE, "sch97d04b2bfccda84198797c1f260e8edd.hoststatetbl_20200919", "tbl.");

			INFOPRINTCOLOR(GY_COLOR_CYAN, "Query for hoststate subsystem is \'%s\'\n\n", strbuf.buffer());    

			strbuf.reset();

			optset[i].get_db_select_multihost_query(strbuf, SUBSYS_HOSTSTATE, "hoststatetbl", "_20200919");

			INFOPRINTCOLOR(GY_COLOR_BLUE, "Query for multihost hoststate is \'%s\'\n\n", strbuf.buffer());    

			strbuf.reset();

			/*
			if (optset[i].is_multi_host()) {
				get_db_multihost_top_listeners_query(strbuf, optset[i], "_20200919", TOP_LISTEN_ISSUE);
				
				INFOPRINTCOLOR(GY_COLOR_MAGENTA, "Query for multihost Top Listener Issue is \'%s\'\n\n", strbuf.buffer());    
			}	
			else {
				get_db_top_listeners_query(strbuf, optset[i], "_20200919", TOP_LISTEN_QPS);

				INFOPRINTCOLOR(GY_COLOR_MAGENTA, "Query for Host Top Listener QPS is \'%s\'\n\n", strbuf.buffer());    
			}	
			*/
		}
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught while handling query options : %s\n\n", GY_GET_EXCEPT_STRING);
	);

	IRPRINT("\n\n");

}	

