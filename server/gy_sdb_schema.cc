//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include		"gy_common_inc.h"
#include		"gy_shconnhdlr.h"
#include		"gy_print_offload.h"
#include		"gy_sdb_schema.h"
#include		"gyshyama.h"

using namespace 	gyeeta::comm;

namespace gyeeta {
namespace shyama {

/*
 * XXX : Any modifications to DB schemas MUST result in incrementing CURR_DB_VERSION
 */
const int		CURR_DB_VERSION	= 1;

void SHCONN_HANDLER::upgrade_db_schemas(int olddbver, int oldprocver, PGConnUniq & pconn)
{
	// Set CURR_DB_VERSION to DB
	auto			gyres = pconn->pqexec_blocking(
					gy_to_charbuf<512>("insert into public.instanceversiontbl(id, dbversion, procvernum, procverstr, tupd) values(1, %d, %d, \'%s\', now()) "
								"on conflict (id) do update set (dbversion, procvernum, procverstr, tupd) = "
								"(excluded.dbversion, excluded.procvernum, excluded.procverstr, excluded.tupd);", 
								CURR_DB_VERSION, gversion_num, gversion).get());

	if (true == gyres.is_error()) {
		GY_THROW_EXCEPTION("Failed to set Postgres Shyama DB Version  : %s", gyres.get_error_no_newline().get());
	}

	if (olddbver == 0 || olddbver >= CURR_DB_VERSION) {
		return;
	}	

	// XXX Add DB Upgrade code here...
}	

const char * SHCONN_HANDLER::get_sglobtables() const noexcept
{
	return R"(
	create table if not exists public.parthatbl (
		machid			char(32) PRIMARY KEY NOT NULL,
		clustername		text,
		region			text,
		zone			text,
		madhavaid		char(16),
		del_after		timestamptz default NULL
	);

	create table if not exists public.madhavatbl (
		madhavaid		char(16) PRIMARY KEY NOT NULL,
		hostname		text,
		port			int,
		region			text,
		zone			text,
		lasttime		timestamptz,
		createtime		timestamptz,
		maxnodes		int,
		lastnodes		int,
		del_after		timestamptz default NULL
	);

	create table if not exists public.alertdeftbl (
		adefid			char(8) PRIMARY KEY NOT NULL,
		alertname		text,
		tcreated		timestamptz,
		disabled		boolean,
		definition		text
	);

	create table if not exists public.inhibitstbl (
		inhid			char(8) PRIMARY KEY NOT NULL,
		inhname			text,
		tcreated		timestamptz,
		disabled		boolean,
		inhibit			text
	);

	create table if not exists public.silencestbl (
		silid			char(8) PRIMARY KEY NOT NULL,
		silname			text,
		tcreated		timestamptz,
		disabled		boolean,
		silence			text
	);

	create table if not exists public.actionstbl (
		actionid		char(8) PRIMARY KEY NOT NULL,
		actname			text,
		acttype			text,
		tcreated		timestamptz,
		action			text
	);

	
)";

}

const char * SHCONN_HANDLER::get_sglob_part_tables() const noexcept
{
	return R"(

create or replace function gy_add_glob_part_tables(isunlogged boolean) returns void as $func1$
declare
	logmode		text;
	tbltoday	text := to_char(now()::date, 'yyyymmdd');
	tbltom		text := to_char(now()::date + '1 day'::interval, 'yyyymmdd');
	timetoday	text := date_trunc('day', now())::text;
	timetomor	text := date_trunc('day', now() + '1 day'::interval)::text;
	timedayafter	text := date_trunc('day', now() + '2 days'::interval)::text;
begin
	if not isunlogged then
		logmode := '';
	else
		logmode := 'unlogged';
	end if;	

	execute format($fmt$
		create %s table if not exists public.clusterstatetbl (
			time 			timestamptz,
			clustername		text,
			nhosts			int,
			ntasks_issue 		int, 
			ntaskissue_hosts	int, 
			ntasks 			int, 
			nsvc_issue 		int, 
			nsvcissue_hosts 	int, 
			nsvc 			int, 
			total_qps		int,
			svc_net_mb		int,
			ncpu_issue		int,
			nmem_issue		int
			) PARTITION BY RANGE (time)
		$fmt$, logmode);
	
	execute format('create index if not exists clusterstatetbl_index_time on public.clusterstatetbl(time)');

	execute format('create %s table if not exists public.clusterstatetbl_%s partition of public.clusterstatetbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)', 
		logmode, tbltoday, timetoday, timetomor);
	execute format('create %s table if not exists public.clusterstatetbl_%s partition of public.clusterstatetbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)',
		logmode, tbltom, timetomor, timedayafter);


	execute format($fmt$
		create %s table if not exists public.svcmeshtbl (
			time 			timestamptz,
			svcclustid 		char(16), 
			comm			char(16),
			clustername		text,
			ntotal_svc		int,
			relidobjs		text
			) PARTITION BY RANGE (time)
		$fmt$, logmode);
	
	execute format('create index if not exists svcmeshtbl_index_time on public.svcmeshtbl(time)');

	execute format('create %s table if not exists public.svcmeshtbl_%s partition of public.svcmeshtbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)', 
		logmode, tbltoday, timetoday, timetomor);
	execute format('create %s table if not exists public.svcmeshtbl_%s partition of public.svcmeshtbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)',
		logmode, tbltom, timetomor, timedayafter);


	execute format($fmt$
		create %s table if not exists public.svcnatiptbl (
			time 			timestamptz,
			svcclustid 		char(16), 
			comm			char(16),
			clustername		text,
			natip			text,
			port			int,
			ntotal_svc		int,
			svcidobjs		text
			) PARTITION BY RANGE (time)
		$fmt$, logmode);
	
	execute format('create index if not exists svcnatiptbl_index_time on public.svcnatiptbl(time)');

	execute format('create %s table if not exists public.svcnatiptbl_%s partition of public.svcnatiptbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)', 
		logmode, tbltoday, timetoday, timetomor);
	execute format('create %s table if not exists public.svcnatiptbl_%s partition of public.svcnatiptbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)',
		logmode, tbltom, timetomor, timedayafter);


	execute format($fmt$
		create %s table if not exists public.alertstbl (
			time 			timestamptz,
			alertid			char(8),
			alertname		text,
			astate			text,
			severity		char(8),
			expiry			timestamptz,
			taction			timestamptz,
			tclose			timestamptz,
			adefid			char(8),
			actions			text,
			annot			text,
			acknotes		text,
			nrepeats		smallint,
			subsys			text,
			labels			text,
			alertdata		text
			) PARTITION BY RANGE (time)
		$fmt$, logmode);
	
	execute format('create index if not exists alertstbl_index_time on public.alertstbl(time)');

	execute format('create %s table if not exists public.alertstbl_%s partition of public.alertstbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)', 
		logmode, tbltoday, timetoday, timetomor);
	execute format('create %s table if not exists public.alertstbl_%s partition of public.alertstbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)',
		logmode, tbltom, timetomor, timedayafter);

	
end;
$func1$ language plpgsql;

)";

}

} // namespace shyama
} // namespace gyeeta

