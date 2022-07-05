
#include		"gy_common_inc.h"
#include		"gy_query_criteria.h"

using namespace		gyeeta;

static constexpr const char	*hostcriteria[] = {
	"host.parid =  '97d04b2bfccda84198797c1f260e8edd'",
	"host.host like '(?i)host[0-9]*dev\\.local' ",
	" 	host.cluster in  'cluster1','cluster2', 'cluster3'		 ",
	"host.host substr  'host3'  ",
	"host.host notlike 'Prodhost[0-9]*.local' ",
	"host.cluster != parid ",
	"host.host notsubstr 'host1'",
	"cluster notin  'cluster4','cluster2', 'cluster3' ",
	"host.host substr  'host311111'  ",
	"host.host notsubstr  '1host3'  ",
	"host.host in  'host3'  ",
	"host.host notin  'host3'  ",
};	

// Keep the #hoststatecriteria same as #hostcriteria
static constexpr const char	*hoststatecriteria[GY_ARRAY_SIZE(hostcriteria)] = {
	"hoststate.nlistissue > 1",
	"hoststate.state in 'OK','Bad', 'Severe'",		// translate from number to string with in clause
	"hoststate.severecpu != true",
	" hoststate.nprocsevere in 10, 1, 4, 11 ",
	"hoststate.nlistissue > hoststate.nprocsevere",
	"hoststate.state != 'Idle'",
	"hoststate.nproc bit3 1",
	"hoststate.nlistissue bit2 1",
	"hoststate.nlistissue + hoststate.nprocsevere > 6",
	"          nlistissue / nprocsevere > 1",
	"hoststate.nlistissue * 2.2 >= 6",
	"hoststate.nprocsevere & 1 = 1",
};	

static constexpr const char 	*criteriastr[] = {
	"hoststate.state != 'OK'",
	" { hoststate.nlistissue > hoststate.nprocsevere  } and {host.cluster notin  'cluster1','cluster2', 'cluster3'}",
	"{ state in 'OK','Bad', 'Severe'} and ({host.parid =  '97d04b2bfccda84198797c1f260e8edd'} or { host.host like '(?i)host[0-9]*dev\\.local' } )",
	"( ( { severecpu = true } and { host.host notsubstr 'host1' } ) or ({ hoststate.severecpu = true } and { host.host notlike 'Prodhost[0-9]*.local' } ) or "
		" ( {host notlike 'Prodhost[0-9]*.local'} and {hoststate.nlistissue > 1} ) or ({ host.host notlike 'Prodhost[0-9]*.local' } and { hoststate.nprocsevere > 3 } ) or "
		" ( {host notsubstr 'host1'} and {hoststate.nlistissue > 1}) or ( { host notsubstr 'host1' } and { hoststate.nprocsevere > 3 } ) )",
	/*
	 * Test for invalid field
	 */
	// "{ oom_kill > 0 } and ( { host.host like 'Prodhost[0-9]*.local' } or  { host.host != 'host1' } )",
};

struct host
{
	const char		*parid;
	const char		*hostname;
	const char 		*cluster;

	CHAR_BUF<512> print() const noexcept
	{
		CHAR_BUF<512>		buf;

		snprintf(buf.get(), sizeof(buf), "{ parid : \"%s\", hostname : \"%s\", cluster : \"%s\" }", parid, hostname, cluster); 
		return buf;
	}	
};

static constexpr const host	hostarr[] = {
	  // parid				hostname			cluster
	{ "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaedd", 	"Host1dev.local.dev", 		"devcluster10" },
	{ "97d04b2bfccda84198797c1f260e8edd",	"newhosted1prod.d",		"prodCluster1" },
	{ "97d04b2bfccda84198797c1f260e8eFF",	"newprodhost313.local",		"cluster3" },
};	

struct hoststate
{
	uint32_t		nlistissue;
	uint32_t		nprocsevere;
	OBJ_STATE_E		state;
	bool			isseverecpu;

	CHAR_BUF<512> print() const noexcept
	{
		CHAR_BUF<512>		buf;

		snprintf(buf.get(), sizeof(buf), "{ nlistissue : %u, nprocsevere : %u, state : %d, isseverecpu : %d }", nlistissue, nprocsevere, state, isseverecpu); 
		return buf;
	}	
};

static constexpr const hoststate	hoststatearr[] = {
	// nlistissue	nprocsevere	state		isseverecpu
	{  10,		1,		STATE_BAD,	false },
	{  1,		10,		STATE_OK,	true },
	{  3,		3,		STATE_SEVERE,	true },
	{  0,		0,		STATE_IDLE,	false },
};

int main()
{
	IRPRINT("\n\n");

	try {
		INFOPRINTCOLOR(GY_COLOR_CYAN, "Testing host subsystem criteria...\n\n");
		
		STACK_POOL_ALLOC_64K	stackpool;
		CRITERION_ONE		crithost[GY_ARRAY_SIZE(hostcriteria)];

		SUBSYS_CLASS_E		allowed_subsys_arr[] 	{SUBSYS_HOSTSTATE, SUBSYS_HOST};
		
		const auto		*psubsysinfo = get_subsys_info(SUBSYS_HOSTSTATE);
		const JSON_DB_MAPPING 	*subsys_col_arr[psubsysinfo->szjsonmap + GY_ARRAY_SIZE(json_db_host_arr)];
		uint32_t		ncol_arr = 0;

		for (size_t i = 0; i < GY_ARRAY_SIZE(json_db_host_arr); ++i) {
			subsys_col_arr[ncol_arr++] = json_db_host_arr + i;
		}	

		for (size_t i = 0; i < psubsysinfo->szjsonmap; ++i) {
			subsys_col_arr[ncol_arr++] = psubsysinfo->pjsonmap + i;
		}	


		for (size_t i = 0; i < GY_ARRAY_SIZE(crithost); ++i) {
			crithost[i].~CRITERION_ONE();

			new (crithost + i) CRITERION_ONE(hostcriteria[i], strlen(hostcriteria[i]), i, SUBSYS_HOSTSTATE, "hoststate", subsys_col_arr, ncol_arr, &stackpool);
		}

		for (size_t i = 0; i < GY_ARRAY_SIZE(crithost); ++i) {
			const auto		*pcrit = crithost + i;

			for (size_t n = 0; n < GY_ARRAY_SIZE(hostarr); ++n) {
				const auto		*pelem = hostarr + n;
				bool			bret;

				auto get_num_field = [](const JSON_DB_MAPPING *pfield, SUBSYS_CLASS_E subsys) noexcept -> NUMBER_CRITERION
				{
					return {};
				};

				auto get_str_field = [pelem](const JSON_DB_MAPPING *pfield, char * tbuf, size_t szbuf, SUBSYS_CLASS_E subsys) noexcept -> std::pair<const char *, uint32_t>
				{
					switch (pfield->jsoncrc) {

					case FIELD_PARID 	: 	return { pelem->parid, 		strlen(pelem->parid) };
					case FIELD_HOST 	: 	return { pelem->hostname, 	strlen(pelem->hostname) };
					case FIELD_CLUSTER 	: 	return { pelem->cluster,	strlen(pelem->cluster) };
					
					default			:	return {};
					}	
				};	

				auto get_bool_field = [](const JSON_DB_MAPPING *pfield, SUBSYS_CLASS_E subsys) noexcept -> BOOL_CRITERION
				{
					return {};
				};

				bret = pcrit->match_criterian(get_num_field, get_str_field, get_bool_field);

				INFOPRINTCOLOR(GY_COLOR_CYAN, "Match %s for criteria \"%s\" for %s\n", bret ? "Success" : "Failed", hostcriteria[i], pelem->print().get());

				STRING_BUFFER<512>		strbuf;
				
				bret = pcrit->set_db_filter(strbuf, "", "(true)");
				if (bret) {
					INFOPRINTCOLOR(GY_COLOR_GREEN, "DB Filter for criteria \"%s\" is \"%s\"\n\n", hostcriteria[i], strbuf.buffer());
				}	
			}
		}	

	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught while handling host subsystem criteria : %s\n\n", GY_GET_EXCEPT_STRING);
	);

	IRPRINT("\n\n");

	try {
		INFOPRINTCOLOR(GY_COLOR_GREEN, "Testing hoststate subsystem criteria...\n\n");

		CRITERION_ONE		crithoststate[GY_ARRAY_SIZE(hoststatecriteria)];

		SUBSYS_CLASS_E		allowed_subsys_arr[] 	{SUBSYS_HOSTSTATE, SUBSYS_HOST};
		
		const auto		*psubsysinfo = get_subsys_info(SUBSYS_HOSTSTATE);
		const JSON_DB_MAPPING 	*subsys_col_arr[psubsysinfo->szjsonmap + GY_ARRAY_SIZE(json_db_host_arr)];
		uint32_t		ncol_arr = 0;

		for (size_t i = 0; i < GY_ARRAY_SIZE(json_db_host_arr); ++i) {
			subsys_col_arr[ncol_arr++] = json_db_host_arr + i;
		}	

		for (size_t i = 0; i < psubsysinfo->szjsonmap; ++i) {
			subsys_col_arr[ncol_arr++] = psubsysinfo->pjsonmap + i;
		}	


		for (size_t i = 0; i < GY_ARRAY_SIZE(crithoststate); ++i) {
			crithoststate[i].~CRITERION_ONE();

			new (crithoststate + i) CRITERION_ONE(hoststatecriteria[i], strlen(hoststatecriteria[i]), i, SUBSYS_HOSTSTATE, "hoststate", subsys_col_arr, ncol_arr, nullptr);
		}

		for (size_t i = 0; i < GY_ARRAY_SIZE(crithoststate); ++i) {
			const auto		*pcrit = crithoststate + i;

			for (size_t n = 0; n < GY_ARRAY_SIZE(hoststatearr); ++n) {
				const auto		*pelem = hoststatearr + n;
				bool			bret;

				auto get_num_field = [pelem](const JSON_DB_MAPPING *pfield, SUBSYS_CLASS_E subsys) noexcept -> NUMBER_CRITERION
				{
					switch (pfield->jsoncrc) {

					case FIELD_NLISTISSUE 	: 	return NUMBER_CRITERION((int)pelem->nlistissue);
					case FIELD_NPROCSEVERE 	: 	return NUMBER_CRITERION((int)pelem->nprocsevere);
					
					default			:	return {};
					}	
				};

				auto get_str_field = [pelem](const JSON_DB_MAPPING *pfield, char * tbuf, size_t szbuf, SUBSYS_CLASS_E subsys) noexcept -> std::pair<const char *, uint32_t>
				{
					switch (pfield->jsoncrc) {

					case FIELD_STATE : 	
						do {
							const char		*pstate = state_to_string(pelem->state);

							return { pstate, strlen(pstate) };
						} while (0);

					default		:	return {};

					}	
				};	

				auto get_bool_field = [pelem](const JSON_DB_MAPPING *pfield, SUBSYS_CLASS_E subsys) noexcept -> BOOL_CRITERION
				{
					switch (pfield->jsoncrc) {

					case FIELD_SEVERECPU 	: 	return BOOL_CRITERION(pelem->isseverecpu);
					
					default			:	return {};
					}	
				};

				bret = pcrit->match_criterian(get_num_field, get_str_field, get_bool_field);

				INFOPRINTCOLOR(GY_COLOR_GREEN, "Match %s for criteria \"%s\" for %s\n", bret ? "Success" : "Failed", hoststatecriteria[i], pelem->print().get());

				STRING_BUFFER<512>		strbuf;
				
				bret = pcrit->set_db_filter(strbuf, "", "(true)");
				if (bret) {
					INFOPRINTCOLOR(GY_COLOR_CYAN, "DB Filter for criteria \"%s\" is \"%s\"\n\n", hoststatecriteria[i], strbuf.buffer());
				}	
			}
		}	
		
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught while handling hoststate subsystem criteria : %s\n\n", GY_GET_EXCEPT_STRING);
	);

	IRPRINT("\n\n");

	try {
		INFOPRINTCOLOR(GY_COLOR_CYAN, "Testing complete criteria set...\n\n");
		
		STACK_POOL_ALLOC_64K	stackpool;
		CRITERIA_SET		critset[GY_ARRAY_SIZE(criteriastr)];

		for (size_t i = 0; i < GY_ARRAY_SIZE(critset); ++i) {
			critset[i].~CRITERIA_SET();

			new (critset + i) CRITERIA_SET(criteriastr[i], strlen(criteriastr[i]), SUBSYS_HOSTSTATE);
		}

		for (size_t i = 0; i < GY_ARRAY_SIZE(critset); ++i) {
			const auto		*pcrit = critset + i;

			for (size_t n = 0; n < GY_ARRAY_SIZE(hostarr); ++n) {
				const auto		*phost 		= hostarr + n;
				const auto		*phoststate 	= hoststatearr + n;
				bool			bret;

				auto get_num_field = [phost, phoststate](const JSON_DB_MAPPING *pfield, SUBSYS_CLASS_E subsys) noexcept -> NUMBER_CRITERION
				{
					switch (pfield->jsoncrc) {

					case FIELD_NLISTISSUE 	: 	return NUMBER_CRITERION((int)phoststate->nlistissue);
					case FIELD_NPROCSEVERE 	: 	return NUMBER_CRITERION((int)phoststate->nprocsevere);
					
					default			:	return {};
					}	
				};

				auto get_str_field = [phost, phoststate](const JSON_DB_MAPPING *pfield, char * tbuf, size_t szbuf, SUBSYS_CLASS_E subsys) noexcept -> std::pair<const char *, uint32_t>
				{
					switch (pfield->jsoncrc) {

					case FIELD_PARID 	: 	return { phost->parid, 		strlen(phost->parid) };
					case FIELD_HOST 	: 	return { phost->hostname, 	strlen(phost->hostname) };
					case FIELD_CLUSTER 	: 	return { phost->cluster,	strlen(phost->cluster) };
					case FIELD_STATE : 	
						do {
							const char		*pstate = state_to_string(phoststate->state);

							return { pstate, strlen(pstate) };
						} while (0);

					default			:	return {};
					}	
				};	

				auto get_bool_field = [phost, phoststate](const JSON_DB_MAPPING *pfield, SUBSYS_CLASS_E subsys) noexcept -> BOOL_CRITERION
				{
					switch (pfield->jsoncrc) {

					case FIELD_SEVERECPU 	: 	return BOOL_CRITERION(phoststate->isseverecpu);
					
					default			:	return {};
					}	
				};

				auto cret = pcrit->match_criteria(get_num_field, get_str_field, get_bool_field);

				INFOPRINTCOLOR(GY_COLOR_YELLOW, "Match %s for criteria \'%s\' for host : %s and hoststate : %s\n", 
					cret != CRIT_FAIL ? "Success" : "Failed", criteriastr[i], phost->print().get(), phoststate->print().get());


				STRING_BUFFER<1024>		strbuf;
				
				pcrit->get_db_filter_criteria(strbuf, SUBSYS_HOST);

				INFOPRINTCOLOR(GY_COLOR_GREEN, "DB Filter for Host subsystem is \"%s\"\n\n", strbuf.buffer());

				strbuf.reset();

				pcrit->get_db_filter_criteria(strbuf, SUBSYS_HOSTSTATE, "tbl.");

				INFOPRINTCOLOR(GY_COLOR_CYAN, "DB Filter for Hoststate subsystem is \"%s\"\n\n", strbuf.buffer());
			}
		}	

	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught while testing complete criteria : %s\n\n", GY_GET_EXCEPT_STRING);
	);

	IRPRINT("\n\n");


}	
