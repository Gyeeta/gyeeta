//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later


#include		"gy_common_inc.h"
#include		"gy_mconnhdlr.h"
#include		"gy_print_offload.h"
#include		"gy_mdb_schema.h"
#include		"gymadhava.h"

using namespace 	gyeeta::comm;

namespace gyeeta {
namespace madhava {

/*
 * XXX : Any modifications to DB schemas MUST result in incrementing CURR_DB_VERSION
 */
const int			CURR_DB_VERSION	= 2;

void MCONN_HANDLER::upgrade_db_schemas(int olddbver, int oldprocver, PGConnUniq & pconn)
{
	if (olddbver > 0 && olddbver < CURR_DB_VERSION) {
		/*
		 * Add DB Upgrade stuff here...
		 * We limit the upgrade to max 2 prior versions.
		 */

		static constexpr const char		up_1_to_2[] = R"(
do $$
declare
	c               refcursor;
	r               record;
	tbl             text;
begin
	open c for select nspname from pg_catalog.pg_namespace where nspname ~ '^sch[0-9a-f]{32}$';
	loop
		fetch c into r;
		exit when not found;

		execute format($fmt$ alter table if exists %s.hoststatetbl 
					add column if not exists total_cpu_delay int default 0, 
					add column if not exists total_vm_delay int default 0, 
					add column if not exists total_io_delay int default 0; $fmt$ , r.nspname::text);

	end loop;
end;
$$ language plpgsql;
		)";

		if (olddbver == 1) {
			INFOPRINTCOLOR(GY_COLOR_YELLOW, "Altering current DB as Schema Version is lower %d than upgrade Schema version %d...\n", olddbver, CURR_DB_VERSION);

			bool			bret = pconn->check_or_reconnect(false);
			if (!bret) {
				GY_THROW_EXCEPTION("Failed to connect to DB for upgrade to DB Schema");
			}	

			auto			gyres = pconn->pqexec_blocking(up_1_to_2);

			if (true == gyres.is_error()) {
				GY_THROW_EXCEPTION("Failed to Upgrade DB : Alter to hoststatetbl failed : Existing DB Schema Version is lower %d than current %d : %s", 
						olddbver, CURR_DB_VERSION, gyres.get_error_no_newline().get());
			}
		}	
	}

	// Set CURR_DB_VERSION to DB
	auto			gyres = pconn->pqexec_blocking(
					gy_to_charbuf<512>("insert into public.instanceversiontbl(id, dbversion, procvernum, procverstr, tupd) values(1, %d, %d, \'%s\', now()) "
								"on conflict (id) do update set (dbversion, procvernum, procverstr, tupd) = "
								"(excluded.dbversion, excluded.procvernum, excluded.procverstr, excluded.tupd);", 
								CURR_DB_VERSION, gversion_num, gversion).get());

	if (true == gyres.is_error()) {
		GY_THROW_EXCEPTION("Failed to update Postgres Madhava DB Version Info table : %s", gyres.get_error_no_newline().get());
	}
}	


const char * MCONN_HANDLER::get_glob_part_tables() const noexcept
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

	execute format('
		create %s table if not exists public.notificationtbl (
			time 			timestamptz,
			type			char(8),
			machid			char(32),
			msg			text
			) PARTITION BY RANGE (time)
		', logmode);
	
	execute format('create %s table if not exists public.notificationtbl_%s partition of public.notificationtbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)', 
		logmode, tbltoday, timetoday, timetomor);
	execute format('create %s table if not exists public.notificationtbl_%s partition of public.notificationtbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)', 
		logmode, tbltom, timetomor, timedayafter);



	execute format($fmt$
		create %s table if not exists public.tracestatustbl (
			time 			timestamptz,
			glob_id 		char(16), 
			comm			char(16),
			port			int,
			tlast 			timestamptz,
			state			char(16),
			proto			char(16),
			istls			boolean,
			tstart			timestamptz,
			tend			timestamptz,
			nreq			bigint,
			nerr			bigint,
			defid			char(8),
			machid			char(32)
			
			) PARTITION BY RANGE (time)
		$fmt$, logmode);

	execute format('alter table if exists public.tracestatustbl alter column glob_id SET STORAGE plain');
	execute format('alter table if exists public.tracestatustbl alter column comm SET STORAGE plain');
	execute format('alter table if exists public.tracestatustbl alter column state SET STORAGE plain');
	execute format('alter table if exists public.tracestatustbl alter column proto SET STORAGE plain');
	execute format('alter table if exists public.tracestatustbl alter column defid SET STORAGE plain');
	execute format('alter table if exists public.tracestatustbl alter column machid SET STORAGE plain');
	
	execute format('create index if not exists tracestatustbl_index_time on public.tracestatustbl(time)');

	execute format('create %s table if not exists public.tracestatustbl_%s partition of public.tracestatustbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)', 
		logmode, tbltoday, timetoday, timetomor);
	execute format('create %s table if not exists public.tracestatustbl_%s partition of public.tracestatustbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)',
		logmode, tbltom, timetomor, timedayafter);


end;
$func1$ language plpgsql;

/*
 * Function for querying across multiple partha's and a consolidated resultset. e.g. :
 * 
 * select * from gy_multihostselect($a$ where strpos(hostname, 'ubun') != 0 $a$, 'listenstatetbl', '_20200802', 'tbl', 'tbl.time, tbl.comm', 
 	$b$ where time between '2020-08-02T16:30:00+05:30'::timestamptz and '2020-08-02T16:51:00+05:30'::timestamptz limit 10 $b$) as 
 	(machid char(32), hostname text, madhavaid char(16), clustername text, time timestamptz, comm char(16));
 *
 */
create or replace function gy_multihostselect(parthafilter text, tablename text, datetbl text, tablealias text, tablecolumns text, tablefilter text, maxrecs int = 10000000) returns setof record as $$
declare
	ret 		record;
	row 		public.parthatbl%rowtype;
	istbl		boolean;
	nrecs		int := 0;
begin
	for row in execute format($p$ select machid, hostname, madhavaid, clustername from public.parthatbl %s $p$, parthafilter) loop
	declare
		c 	refcursor;
	begin	
		istbl := public.gy_table_exists('sch' || row.machid::char(32), tablename, datetbl);
		if not istbl then 
			continue;
		end if;	

		execute format($f$ set search_path = sch%s $f$, row.machid);

		open c no scroll for execute format($f$ 
			with thost as not materialized (select '%s'::char(32) as machid, '%s'::text as hostname, '%s'::char(16) as madhavaid, '%s'::text as clustername)
				select thost.machid, thost.hostname, thost.madhavaid, thost.clustername, %s from thost cross join %s%s %s %s 
			$f$, row.machid, row.hostname, row.madhavaid, row.clustername, tablecolumns, tablename, datetbl, tablealias, tablefilter);

		fetch first from c into ret;

		while found loop
			nrecs := nrecs + 1;
			EXIT when nrecs > maxrecs;
			
			return next ret;
			fetch next from c into ret;
		end loop;
	
		close c;

		EXIT when nrecs > maxrecs;
	end;	
	end loop;

	reset search_path;
end;
$$ language plpgsql;

)";

}	

/*
  	To sort by table and index disk usage :

	SELECT nspname || '.' || relname AS "relation",   pg_size_pretty(pg_relation_size(C.oid)) AS "size" FROM pg_class C  LEFT JOIN pg_namespace N ON (N.oid = C.relnamespace) 
		WHERE nspname ~ '^sch' ORDER BY pg_relation_size(C.oid) DESC 

 	General Table, Index, Toast size and row info :
	
	SELECT *, pg_size_pretty(total_bytes) AS total , pg_size_pretty(index_bytes) AS INDEX , pg_size_pretty(toast_bytes) AS toast , pg_size_pretty(table_bytes) AS TABLE
		FROM ( SELECT *, total_bytes-index_bytes-COALESCE(toast_bytes,0) AS table_bytes FROM (
			SELECT c.oid,nspname AS table_schema, relname AS TABLE_NAME , c.reltuples AS row_estimate , pg_total_relation_size(c.oid) AS total_bytes
				, pg_indexes_size(c.oid) AS index_bytes , pg_total_relation_size(reltoastrelid) AS toast_bytes
			FROM pg_class c
			LEFT JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE relkind = 'r'
		) a
	) a;		

	To check long running connections :

	select * from pg_stat_activity where backend_start < now() - '10 min'::interval and datname = current_database();

	Lock Monitoring : https://wiki.postgresql.org/wiki/Lock_Monitoring

 */

const char * MCONN_HANDLER::get_globtables() const noexcept
{
	return R"(
	create table if not exists public.parthatbl(
		machid			char(32) PRIMARY KEY NOT NULL,
		hostname		text,
		madhavaid		char(16),
		clustername		text,
		regtime			timestamptz,
		createtime		timestamptz,
		version			int,
		region			text,
		zone			text
	);

	create table if not exists public.parthainfotbl(
		machid			char(32) PRIMARY KEY NOT NULL,
		distribution_name	text,
		kern_version_string	text,
		kern_version_num	bigint,
		processor_model		text,
		cpu_vendor		text,
		cores_online		int,
		cores_offline		int,
		max_cores		int,
		isolated_cores		int,
		ram_mb			int,
		corrupted_ram_mb	int,
		num_numa_nodes		smallint,
		max_cores_per_socket	smallint,
		threads_per_core	smallint,
		l1_dcache_kb		int,
		l2_cache_kb		int,
		l3_cache_kb		int,
		l4_cache_kb		int,
		boot_time		timestamptz,
		updtime			timestamptz,
		is_virtual_cpu		boolean,
		virtualization_type	text,
		instance_id		text,
		cloud_type		text
	);

	create or replace view public.hostinfoview as select t1.hostname, t1.madhavaid, t1.clustername, t1.region, t1.zone, t2.* from 
					public.parthatbl t1 left join public.parthainfotbl t2 on t1.machid = t2.machid;
	
	)";
}	

/*
 * Procedure executed on every new Partha registration
 */
const char * MCONN_HANDLER::get_add_partha() const noexcept
{
	return R"(
create or replace function gy_add_partha(schname text, hostname text, isunlogged boolean) returns void as $func1$
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

	execute format('create schema if not exists %s', schname);
	execute format($fmt$ comment on schema %s is 'Partha Hostname %s' $fmt$, schname, hostname);

	execute format($fmt$
		create %s table if not exists %s.hoststatetbl (
			time 			timestamptz,
			ntasks_issue 		int, 
			ntasks_severe 		int, 
			ntasks 			int, 
			nlisten_issue 		int, 
			nlisten_severe 		int, 
			nlisten 		int, 
			state 			smallint, 
			issue_bit_hist 		smallint,
			cpu_issue		boolean,
			mem_issue		boolean,
			severe_cpu_issue	boolean,
			severe_mem_issue	boolean,
			total_cpu_delay 	int,
			total_vm_delay 		int,
			total_io_delay 		int
			) PARTITION BY RANGE (time)
		$fmt$, logmode, schname);
	
	execute format('create index if not exists hoststatetbl_index_time on %s.hoststatetbl(time)', schname);

	execute format('create %s table if not exists %s.hoststatetbl_%s partition of %s.hoststatetbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)', 
		logmode, schname, tbltoday, schname, timetoday, timetomor);
	execute format('create %s table if not exists %s.hoststatetbl_%s partition of %s.hoststatetbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)',
		logmode, schname, tbltom, schname, timetomor, timedayafter);

	execute format($fmt$
		create %s table if not exists %s.listenstatetbl (
			time 			timestamptz,
			glob_id 		char(16), 
			comm			char(16),

			qps_5s			int,
			nqrys_5s		int,
			avg_5s_resp_ms		int,
			p95_5s_resp_ms		int,
			p95_5m_resp_ms		int,
			nconns			int,
			nconns_active		int,
			ntasks			int,

			curr_kb_inbound		int,
			curr_kb_outbound	int,
			ser_http_errors		int,
			cli_http_errors		int,

			tasks_delay_usec	int,
			tasks_cpudelay_usec	int,
			tasks_blkiodelay_usec	int,
			tasks_vmdelay_usec	int,

			tasks_user_cpu		int,
			tasks_sys_cpu		int,
			tasks_rss_mb		int,

			ntasks_issue		smallint,
			curr_state		smallint,
			curr_issue		smallint,
			issue_bit_hist		smallint,
			
			is_http_svc		boolean,
			issue_string		text

			) PARTITION BY RANGE (time)
		$fmt$, logmode, schname);

	execute format('alter table if exists %s.listenstatetbl alter column glob_id SET STORAGE plain', schname);
	execute format('alter table if exists %s.listenstatetbl alter column comm SET STORAGE plain', schname);
	
	execute format('create index if not exists listenstatetbl_index_time on %s.listenstatetbl(time)', schname);

	execute format('create %s table if not exists %s.listenstatetbl_%s partition of %s.listenstatetbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)', 
		logmode, schname, tbltoday, schname, timetoday, timetomor);
	execute format('create %s table if not exists %s.listenstatetbl_%s partition of %s.listenstatetbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)',
		logmode, schname, tbltom, schname, timetomor, timedayafter);


	execute format($fmt$
		create %s table if not exists %s.cpumemstatetbl (
			time 			timestamptz,
			cpu_pct			real,
			usercpu_pct		real,
			syscpu_pct		real,
			iowait_pct		real,
			cumul_core_cpu_pct	real,
			forks_sec		int,
			procs_running		int,
			cs_sec			int,
			cs_p95_sec		int,
			cpu_p95			int,
			fork_p95_sec		int,
			procs_p95		int,
			cpu_state		smallint,
			cpu_issue		smallint,
			cpu_issue_bit_hist	smallint,
			cpu_severe_issue_hist	smallint,

			rss_pct			real,
			rss_memory_mb		int,
			total_memory_mb		int,
			cached_memory_mb	int,
			locked_memory_mb	int,
			committed_memory_mb	int,
			committed_pct		real,
			swap_free_mb		int,
			swap_total_mb		int,
			pg_inout_sec		int,
			swap_inout_sec		int,
			reclaim_stalls		int,
			pgmajfault		int,
			oom_kill		int,
			rss_pct_p95		int,
			pginout_p95		int,
			swpinout_p95		int,
			allocstall_p95		int,
			mem_state		smallint,
			mem_issue		smallint,
			mem_issue_bit_hist	smallint,
			mem_severe_issue_hist	smallint,
			
			cpu_state_str		text,
			mem_state_str		text
			
			) PARTITION BY RANGE (time)
		$fmt$, logmode, schname);

	execute format('create index if not exists cpumemstatetbl_index_time on %s.cpumemstatetbl(time)', schname);

	execute format('create %s table if not exists %s.cpumemstatetbl_%s partition of %s.cpumemstatetbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)', 
		logmode, schname, tbltoday, schname, timetoday, timetomor);
	execute format('create %s table if not exists %s.cpumemstatetbl_%s partition of %s.cpumemstatetbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)',
		logmode, schname, tbltom, schname, timetomor, timedayafter);


	execute format($fmt$
		create %s table if not exists %s.aggrtaskstatetbl (
			time 			timestamptz,
			aggr_task_id 		char(16), 
			comm			char(16),
			pid1			int,
			pid2			int,
			tcp_kbytes		int,
			tcp_conns		int,
			total_cpu_pct		real,
			rss_mb			int,
			cpu_delay_msec		int,
			vm_delay_msec		int,
			blkio_delay_msec	int,
			ntasks_total		smallint,
			ntasks_issue		smallint,
			curr_state		smallint,
			curr_issue		smallint,
			issue_bit_hist		smallint,
			severe_issue_bit_hist	smallint,
			issue_string		text
			) PARTITION BY RANGE (time)
		$fmt$, logmode, schname);

	execute format('alter table if exists %s.aggrtaskstatetbl alter column aggr_task_id SET STORAGE plain', schname);
	execute format('alter table if exists %s.aggrtaskstatetbl alter column comm SET STORAGE plain', schname);
	
	execute format('create index if not exists aggrtaskstatetbl_index_time on %s.aggrtaskstatetbl(time)', schname);

	execute format('create %s table if not exists %s.aggrtaskstatetbl_%s partition of %s.aggrtaskstatetbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)', 
		logmode, schname, tbltoday, schname, timetoday, timetomor);
	execute format('create %s table if not exists %s.aggrtaskstatetbl_%s partition of %s.aggrtaskstatetbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)', 
		logmode, schname, tbltom, schname, timetomor, timedayafter);


	execute format($fmt$
		create %s table if not exists %s.topcputbl (
			time 			timestamptz,
			aggr_task_id 		char(16), 
			pid			int,
			ppid			int,
			rss_mb			int,
			cpupct			real,
			comm			char(16),
			ranknum			smallint
			) PARTITION BY RANGE (time)
		$fmt$, logmode, schname);

	execute format('alter table if exists %s.topcputbl alter column aggr_task_id SET STORAGE plain', schname);
	execute format('alter table if exists %s.topcputbl alter column comm SET STORAGE plain', schname);

	execute format('create %s table if not exists %s.topcputbl_%s partition of %s.topcputbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)', 
		logmode, schname, tbltoday, schname, timetoday, timetomor);
	execute format('create %s table if not exists %s.topcputbl_%s partition of %s.topcputbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)', 
		logmode, schname, tbltom, schname, timetomor, timedayafter);

	execute format($fmt$
		create %s table if not exists %s.toppgcputbl (
			time 			timestamptz,
			aggr_task_id 		char(16), 
			pg_pid			int,
			cpid			int,
			ntasks			int,
			tot_rss_mb		int,
			tot_cpupct		real,
			pg_comm			char(16),
			child_comm		char(16),
			ranknum			smallint
			) PARTITION BY RANGE (time)
		$fmt$, logmode, schname);

	execute format('alter table if exists %s.toppgcputbl alter column aggr_task_id SET STORAGE plain', schname);
	execute format('alter table if exists %s.toppgcputbl alter column pg_comm SET STORAGE plain', schname);
	execute format('alter table if exists %s.toppgcputbl alter column child_comm SET STORAGE plain', schname);

	execute format('create %s table if not exists %s.toppgcputbl_%s partition of %s.toppgcputbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)', 
		logmode, schname, tbltoday, schname, timetoday, timetomor);
	execute format('create %s table if not exists %s.toppgcputbl_%s partition of %s.toppgcputbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)', 
		logmode, schname, tbltom, schname, timetomor, timedayafter);

	execute format($fmt$
		create %s table if not exists %s.toprsstbl (
			time 			timestamptz,
			aggr_task_id 		char(16), 
			pid			int,
			ppid			int,
			rss_mb			int,
			cpupct			real,
			comm			char(16),
			ranknum			smallint
			) PARTITION BY RANGE (time)
		$fmt$, logmode, schname);

	execute format('alter table if exists %s.toprsstbl alter column aggr_task_id SET STORAGE plain', schname);
	execute format('alter table if exists %s.toprsstbl alter column comm SET STORAGE plain', schname);

	execute format('create index if not exists toprsstbl_index_time on %s.toprsstbl(time)', schname);

	execute format('create %s table if not exists %s.toprsstbl_%s partition of %s.toprsstbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)', 
		logmode, schname, tbltoday, schname, timetoday, timetomor);
	execute format('create %s table if not exists %s.toprsstbl_%s partition of %s.toprsstbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)', 
		logmode, schname, tbltom, schname, timetomor, timedayafter);

	execute format($fmt$
		create %s table if not exists %s.topforktbl (
			time 			timestamptz,
			aggr_task_id 		char(16), 
			pid			int,
			ppid			int,
			nfork_per_sec		int,
			comm			char(16),
			ranknum			smallint
			) PARTITION BY RANGE (time)
		$fmt$, logmode, schname);

	execute format('alter table if exists %s.topforktbl alter column aggr_task_id SET STORAGE plain', schname);
	execute format('alter table if exists %s.topforktbl alter column comm SET STORAGE plain', schname);

	execute format('create %s table if not exists %s.topforktbl_%s partition of %s.topforktbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)', 
		logmode, schname, tbltoday, schname, timetoday, timetomor);
	execute format('create %s table if not exists %s.topforktbl_%s partition of %s.topforktbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)', 
		logmode, schname, tbltom, schname, timetomor, timedayafter);

	execute format($fmt$
		create %s table if not exists %s.activeconntbl (
			time 			timestamptz,
			listen_id 		char(16), 
			listen_comm		char(16),
			cli_aggr_task_id	char(16),
			cli_comm		char(16),
			cli_parthaid		char(32),
			cli_madhavaid		char(16),
			cli_bytes_sent		bigint,
			cli_bytes_received	bigint,
			cli_delay_msec		int,
			ser_delay_msec		int,
			max_rtt_msec		real,
			cli_active_conns	smallint,
			cli_listener_proc	boolean
			) PARTITION BY RANGE (time)
		$fmt$, logmode, schname);

	execute format('alter table if exists %s.activeconntbl alter column listen_id SET STORAGE plain', schname);
	execute format('alter table if exists %s.activeconntbl alter column listen_comm SET STORAGE plain', schname);
	execute format('alter table if exists %s.activeconntbl alter column cli_aggr_task_id SET STORAGE plain', schname);
	execute format('alter table if exists %s.activeconntbl alter column cli_comm SET STORAGE plain', schname);
	execute format('alter table if exists %s.activeconntbl alter column cli_parthaid SET STORAGE plain', schname);
	execute format('alter table if exists %s.activeconntbl alter column cli_madhavaid SET STORAGE plain', schname);

	execute format('create index if not exists activeconntbl_index_time on %s.activeconntbl(time)', schname);

	execute format('create %s table if not exists %s.activeconntbl_%s partition of %s.activeconntbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)', 
		logmode, schname, tbltoday, schname, timetoday, timetomor);
	execute format('create %s table if not exists %s.activeconntbl_%s partition of %s.activeconntbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)',
		logmode, schname, tbltom, schname, timetomor, timedayafter);

	execute format($fmt$
		create %s table if not exists %s.remoteconntbl (
			time 			timestamptz,
			cli_aggr_task_id	char(16),
			cli_comm		char(16),
			listen_id 		char(16), 
			listen_comm		char(16),
			listen_parthaid		char(32),
			listen_madhavaid	char(16),
			cli_bytes_sent		bigint,
			cli_bytes_received	bigint,
			cli_active_conns	smallint,
			cli_listener_proc	boolean
			) PARTITION BY RANGE (time)
		$fmt$, logmode, schname);

	execute format('alter table if exists %s.remoteconntbl alter column cli_aggr_task_id SET STORAGE plain', schname);
	execute format('alter table if exists %s.remoteconntbl alter column cli_comm SET STORAGE plain', schname);
	execute format('alter table if exists %s.remoteconntbl alter column listen_id SET STORAGE plain', schname);
	execute format('alter table if exists %s.remoteconntbl alter column listen_comm SET STORAGE plain', schname);
	execute format('alter table if exists %s.remoteconntbl alter column listen_parthaid SET STORAGE plain', schname);
	execute format('alter table if exists %s.remoteconntbl alter column listen_madhavaid SET STORAGE plain', schname);

	execute format('create index if not exists remoteconntbl_index_time on %s.remoteconntbl(time)', schname);

	execute format('create %s table if not exists %s.remoteconntbl_%s partition of %s.remoteconntbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)', 
		logmode, schname, tbltoday, schname, timetoday, timetomor);
	execute format('create %s table if not exists %s.remoteconntbl_%s partition of %s.remoteconntbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)',
		logmode, schname, tbltom, schname, timetomor, timedayafter);

	execute format($fmt$
		create %s table if not exists %s.aggrtaskinfotbl (
			time 			timestamptz,
			aggr_task_id 		char(16), 
			comm			char(16),
			related_listen_id	text,
			cmdline			text,
			tag			text,
			uid			int,
			gid			int,
			high_cap		boolean,
			cpu_cg_throttled	boolean,
			mem_cg_limited		boolean,
			rt_proc			boolean,
			container_proc		boolean,
			tstart			timestamptz,
			p95cpupct		int,
			p95cpudel		int,
			p95iodel		int,
			nproc			int,
			nthr			int,
			maxcore			smallint,
			cgcpulimpct		smallint,
			cgrsspct		smallint,
			region			text,
			zone			text
			) PARTITION BY RANGE (time)
		$fmt$, logmode, schname);

	execute format('create index if not exists aggrtaskinfotbl_index_time on %s.aggrtaskinfotbl(time)', schname);

	execute format('create %s table if not exists %s.aggrtaskinfotbl_%s partition of %s.aggrtaskinfotbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)', 
		logmode, schname, tbltoday, schname, timetoday, timetomor);
	execute format('create %s table if not exists %s.aggrtaskinfotbl_%s partition of %s.aggrtaskinfotbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)',
		logmode, schname, tbltom, schname, timetomor, timedayafter);
	
	execute format($fmt$
		create %s table if not exists %s.listeninfotbl (
			time 			timestamptz,
			glob_id 		char(16), 
			comm			char(16),
			ns			bigint,
			ip			text,
			port			int,
			related_listen_id	char(16),
			starttime		timestamptz,
			cmdline			text,
			p95resp5d		int,
			avgresp5d		int,
			p95qps			int,
			p95aconn		int,
			svcip1			text,
			svcport1		int,
			svcip2			text,
			svcport2		int,
			svcdns			text,
			svctag			text,
			svcmeshid		text,
			nsvcmesh		int,
			ip1cluid		text,
			nip1svc			int,
			ip2cluid		text,
			nip2svc			int,
			region			text,
			zone			text

			) PARTITION BY RANGE (time)
		$fmt$, logmode, schname);

	execute format('create index if not exists listeninfotbl_index_time on %s.listeninfotbl(time)', schname);

	execute format('create %s table if not exists %s.listeninfotbl_%s partition of %s.listeninfotbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)', 
		logmode, schname, tbltoday, schname, timetoday, timetomor);
	execute format('create %s table if not exists %s.listeninfotbl_%s partition of %s.listeninfotbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)',
		logmode, schname, tbltom, schname, timetomor, timedayafter);


	execute format($fmt$
		create table if not exists %s.listentbl (
			glob_id 		char(16) PRIMARY KEY NOT NULL, 
			comm			char(16),
			ns			bigint,
			ip			text,
			port			int,
			related_listen_id	char(16),
			lastupdtime		timestamptz,
			starttime		timestamptz,
			ser_aggr_task_id	char(16),
			is_any_ip		boolean,
			cmdline			text,
			del_after		timestamptz default NULL
			)
		$fmt$, schname);

	execute format('create index if not exists listentbl_index_del_after on %s.listentbl(del_after) where del_after is not null', schname);

	execute format($fmt$
		create %s table if not exists %s.deplistenissuetbl (
			time 			timestamptz,
			deplisten_id 		char(16), 
			deplisten_comm		char(16),
			srclisten_id		char(16),
			srcmadhava_id		char(16),
			deplisten_state		smallint,
			src_upstream_tier	smallint,
			src_issue		smallint,
			src_is_load_balanced	boolean
			) PARTITION BY RANGE (time)
		$fmt$, logmode, schname);

	execute format('create index if not exists deplistenissuetbl_index_time on %s.deplistenissuetbl(time)', schname);

	execute format('create %s table if not exists %s.deplistenissuetbl_%s partition of %s.deplistenissuetbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)', 
		logmode, schname, tbltoday, schname, timetoday, timetomor);
	execute format('create %s table if not exists %s.deplistenissuetbl_%s partition of %s.deplistenissuetbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)',
		logmode, schname, tbltom, schname, timetomor, timedayafter);

	execute format($fmt$
		create %s table if not exists %s.tasktbl (
			time 			timestamptz,
			task_pid		int,
			task_ppid		int,
			task_pgid		int,
			task_sid		int,
			task_nspid		int,
			task_nspgid		int,
			task_nssid		int,
			task_comm		char(16),
			task_parent_comm	char(16),
			aggr_task_id		char(16),
			task_realuid		int,
			task_effuid		int,
			task_realgid		int,
			task_effgid		int,
			ncpus_allowed		int,
			nmems_allowed		int,
			task_flags		int,
			starttime		timestamptz,
			task_priority		bigint,
			task_nice		bigint,
			task_rt_priority	int,
			task_sched_policy	int,
			ntcp_listeners		int,
			is_tcp_server		boolean,
			is_tcp_client		boolean,
			is_parent_tcp_client	boolean,
			is_high_cap		boolean,
			listen_tbl_inherited	boolean,
			task_exe_path		text,
			task_cmdline		text,
			task_tags		text
			) PARTITION BY RANGE (time)
		$fmt$, logmode, schname);

	execute format('create index if not exists tasktbl_index_time on %s.tasktbl(time)', schname);

	execute format($fmt$ create %s table if not exists %s.tasktbl_%s partition of %s.tasktbl FOR VALUES FROM ('%s'::timestamptz) to ('%s'::timestamptz)$fmt$, 
		logmode, schname, tbltoday, schname, timetoday, timetomor);
	execute format($fmt$ create %s table if not exists %s.tasktbl_%s partition of %s.tasktbl FOR VALUES FROM ('%s'::timestamptz) to ('%s'::timestamptz)$fmt$,
		logmode, schname, tbltom, schname, timetomor, timedayafter);


	execute format($fmt$
		create %s table if not exists %s.listensummtbl (
			time 			timestamptz,
			nidle	 		int, 
			ngood			int,
			nok			int,
			nbad			int,
			nsevere			int,
			ndown			int,
			tot_qps			int,
			tot_act_conn		int,
			tot_kb_inbound		int,
			tot_kb_outbound		int,
			tot_ser_errors		int,
			nlisteners		int,
			nactive			int
			) PARTITION BY RANGE (time)
		$fmt$, logmode, schname);

	execute format('create index if not exists listensummtbl_index_time on %s.listensummtbl(time)', schname);

	execute format('create %s table if not exists %s.listensummtbl_%s partition of %s.listensummtbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)', 
		logmode, schname, tbltoday, schname, timetoday, timetomor);
	execute format('create %s table if not exists %s.listensummtbl_%s partition of %s.listensummtbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)', 
		logmode, schname, tbltom, schname, timetomor, timedayafter);


	execute format($fmt$
		create %s table if not exists %s.listentaskmaptbl (
			time 			timestamptz,
			related_listen_id	char(16),
			ser_comm		text,
			glob_id_arr		text,
			aggr_task_id_arr	text
			) PARTITION BY RANGE (time)
		$fmt$, logmode, schname);

	execute format('create index if not exists listentaskmaptbl_index_time on %s.listentaskmaptbl(time)', schname);

	execute format('create %s table if not exists %s.listentaskmaptbl_%s partition of %s.listentaskmaptbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)', 
		logmode, schname, tbltoday, schname, timetoday, timetomor);
	execute format('create %s table if not exists %s.listentaskmaptbl_%s partition of %s.listentaskmaptbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)', 
		logmode, schname, tbltom, schname, timetomor, timedayafter);


	-- Set as Unlogged Table 
	execute format($fmt$
		create unlogged table if not exists %s.tracereqtbl (
			time 			timestamptz,
			req			text,
			response		bigint,
			bytesin			bigint,
			bytesout		bigint,
			errorcode		int,
			errtxt			text,
			statuscode		int,
			appname			text,
			username		text,
			dbname			text,
			glob_id 		char(16), 
			comm			char(16),
			connid			char(16),
			proto			char(16),
			uniqid			char(16),
			reqnum			bigint,
			conntime		timestamptz,
			cliip			text,
			cliport			int,
			sessid			int,
			prepreqnum		bigint,
			preptime		bigint

			) PARTITION BY RANGE (time)
		$fmt$, schname);

	execute format('alter table if exists %s.tracereqtbl alter column glob_id SET STORAGE plain', schname);
	execute format('alter table if exists %s.tracereqtbl alter column comm SET STORAGE plain', schname);
	execute format('alter table if exists %s.tracereqtbl alter column connid SET STORAGE plain', schname);
	execute format('alter table if exists %s.tracereqtbl alter column proto SET STORAGE plain', schname);
	execute format('alter table if exists %s.tracereqtbl alter column uniqid SET STORAGE plain', schname);
	
	execute format('create index if not exists tracereqtbl_index_time on %s.tracereqtbl(time)', schname);
	execute format('create index if not exists tracereqtbl_index_errorcode on %s.tracereqtbl(errorcode) where errorcode != 0', schname);
	execute format('create index if not exists tracereqtbl_index_response on %s.tracereqtbl(response) where response >= 500000', schname);
	execute format('create index if not exists tracereqtbl_index_bytesout on %s.tracereqtbl(bytesout) where bytesout >= 500000', schname);

	execute format('create unlogged table if not exists %s.tracereqtbl_%s partition of %s.tracereqtbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)', 
		schname, tbltoday, schname, timetoday, timetomor);
	execute format('create unlogged table if not exists %s.tracereqtbl_%s partition of %s.tracereqtbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)',
		schname, tbltom, schname, timetomor, timedayafter);


	-- Set as Unlogged Table 
	execute format($fmt$
		create unlogged table if not exists %s.traceconntbl (
			time 			timestamptz,
			glob_id 		char(16), 
			ser_comm		char(16),
			connid			char(16),
			cli_aggr_task_id	char(16),
			cli_comm		char(16),
			cli_parthaid		char(32),
			cli_madhavaid		char(16),
			cli_listener_proc	boolean

			) PARTITION BY RANGE (time)
		$fmt$, schname);

	execute format('alter table if exists %s.traceconntbl alter column glob_id SET STORAGE plain', schname);
	execute format('alter table if exists %s.traceconntbl alter column ser_comm SET STORAGE plain', schname);
	execute format('alter table if exists %s.traceconntbl alter column connid SET STORAGE plain', schname);
	execute format('alter table if exists %s.traceconntbl alter column cli_aggr_task_id SET STORAGE plain', schname);
	execute format('alter table if exists %s.traceconntbl alter column cli_comm SET STORAGE plain', schname);
	execute format('alter table if exists %s.traceconntbl alter column cli_parthaid SET STORAGE plain', schname);
	execute format('alter table if exists %s.traceconntbl alter column cli_madhavaid SET STORAGE plain', schname);
	
	execute format('create index if not exists traceconntbl_index_time on %s.traceconntbl(time)', schname);

	execute format('create unlogged table if not exists %s.traceconntbl_%s partition of %s.traceconntbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)', 
		schname, tbltoday, schname, timetoday, timetomor);
	execute format('create unlogged table if not exists %s.traceconntbl_%s partition of %s.traceconntbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)',
		schname, tbltom, schname, timetomor, timedayafter);


	execute format($fmt$
		create %s table if not exists %s.traceuniqtbl (
			time 			timestamptz,
			uniqreq			text,
			ncnt			bigint,
			avgresp			bigint,
			maxresp			bigint,
			avgbytesin		bigint,
			avgbytesout		bigint,
			maxbytesout		bigint,
			nerror			bigint,
			glob_id 		char(16), 
			comm			char(16),
			proto			char(16),
			uniqid			char(16)

			) PARTITION BY RANGE (time)
		$fmt$, logmode, schname);

	execute format('alter table if exists %s.traceuniqtbl alter column glob_id SET STORAGE plain', schname);
	execute format('alter table if exists %s.traceuniqtbl alter column comm SET STORAGE plain', schname);
	execute format('alter table if exists %s.traceuniqtbl alter column proto SET STORAGE plain', schname);
	execute format('alter table if exists %s.traceuniqtbl alter column uniqid SET STORAGE plain', schname);
	
	execute format('create index if not exists traceuniqtbl_index_time on %s.traceuniqtbl(time)', schname);

	execute format('create %s table if not exists %s.traceuniqtbl_%s partition of %s.traceuniqtbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)', 
		logmode, schname, tbltoday, schname, timetoday, timetomor);
	execute format('create %s table if not exists %s.traceuniqtbl_%s partition of %s.traceuniqtbl FOR VALUES FROM (''%s''::timestamptz) to (''%s''::timestamptz)',
		logmode, schname, tbltom, schname, timetomor, timedayafter);


	
end;
$func1$ language plpgsql;

	)";

}

const char * MCONN_HANDLER::get_views_cleanup_procs() const noexcept
{
	return R"(
create or replace function gy_add_views(schname text, parthaid text, madhavaid text) returns void as $func1$
declare
	tbltoday	text := to_char(now()::date, 'yyyymmdd');
	tbltom		text := to_char(now()::date + '1 day'::interval, 'yyyymmdd');
	istbl		boolean;
begin
	istbl := public.gy_table_exists(schname, 'listeninfotbl_', tbltoday);
	if not istbl then 
		return;
	end if;	
	
	istbl := public.gy_table_exists(schname, 'listeninfotbl_', tbltom);
	if not istbl then 
		return;
	end if;	

	istbl := public.gy_table_exists(schname, 'aggrtaskinfotbl_', tbltoday);
	if not istbl then 
		return;
	end if;	
	
	istbl := public.gy_table_exists(schname, 'aggrtaskinfotbl_', tbltom);
	if not istbl then 
		return;
	end if;	

	istbl := public.gy_table_exists(schname, 'extlistenstatetbl', '');
	if not istbl then 
		/*
		 * NOTE : Please sync any changes here with set_ext_svcstate_fields() function
		 */
		execute format($fmt$ create or replace view %s.extlistenstatetbl as 
				select tbl.*, l.ip, l.port, l.related_listen_id, l.starttime, l.cmdline,
					l.p95resp5d, l.avgresp5d, l.p95qps, l.p95aconn, l.svcip1, l.svcport1, l.svcdns, l.svctag, l.region, l.zone
					from %s.listenstatetbl tbl left join %s.listeninfotbl l on tbl.glob_id = l.glob_id and 
					l.time = (select max(time) from %s.listeninfotbl where time between tbl.time - '5 min'::interval and tbl.time + '5 min'::interval)
			$fmt$, schname, schname, schname, schname);		
	end if;	
	
	istbl := public.gy_table_exists(schname, 'extlistenstatetbl_', tbltoday);
	if not istbl then 
		execute format($fmt$ create or replace view %s.extlistenstatetbl_%s as 
				select tbl.*, l.ip, l.port, l.related_listen_id, l.starttime, l.cmdline,
					l.p95resp5d, l.avgresp5d, l.p95qps, l.p95aconn, l.svcip1, l.svcport1, l.svcdns, l.svctag, l.region, l.zone
					from %s.listenstatetbl_%s tbl left join %s.listeninfotbl_%s l on tbl.glob_id = l.glob_id and
					l.time = (select max(time) from %s.listeninfotbl_%s where time between tbl.time - '5 min'::interval and tbl.time + '5 min'::interval)
			$fmt$, schname, tbltoday, schname, tbltoday, schname, tbltoday, schname, tbltoday);		
	end if;	

	istbl := public.gy_table_exists(schname, 'extlistenstatetbl_', tbltom);
	if not istbl then 
		execute format($fmt$ create or replace view %s.extlistenstatetbl_%s as 
				select tbl.*, l.ip, l.port, l.related_listen_id, l.starttime, l.cmdline,
					l.p95resp5d, l.avgresp5d, l.p95qps, l.p95aconn, l.svcip1, l.svcport1, l.svcdns, l.svctag, l.region, l.zone
					from %s.listenstatetbl_%s tbl left join %s.listeninfotbl_%s l on tbl.glob_id = l.glob_id and
					l.time = (select max(time) from %s.listeninfotbl_%s where time between tbl.time - '5 min'::interval and tbl.time + '5 min'::interval)
			$fmt$, schname, tbltom, schname, tbltom, schname, tbltom, schname, tbltom);		
	end if;	


	istbl := public.gy_table_exists(schname, 'extaggrtaskstatetbl', '');
	if not istbl then 
		/*
		 * NOTE : Please sync any changes here with set_ext_procstate_fields() function
		 */
		execute format($fmt$ create or replace view %s.extaggrtaskstatetbl as 
				select tbl.*, i.related_listen_id, i.cmdline, i.tag, i.uid, i.gid, i.cpu_cg_throttled, i.mem_cg_limited, 
					i.tstart, i.p95cpupct, i.p95cpudel, i.p95iodel, i.cgcpulimpct, i.cgrsspct, i.region, i.zone 
					from %s.aggrtaskstatetbl tbl left join %s.aggrtaskinfotbl i on tbl.aggr_task_id = i.aggr_task_id and 
					i.time = (select max(time) from %s.aggrtaskinfotbl where time between tbl.time - '5 min'::interval and tbl.time + '5 min'::interval)
			$fmt$, schname, schname, schname, schname);		
	end if;	
	
	istbl := public.gy_table_exists(schname, 'extaggrtaskstatetbl_', tbltoday);
	if not istbl then 
		execute format($fmt$ create or replace view %s.extaggrtaskstatetbl_%s as 
				select tbl.*, i.related_listen_id, i.cmdline, i.tag, i.uid, i.gid, i.cpu_cg_throttled, i.mem_cg_limited, 
					i.tstart, i.p95cpupct, i.p95cpudel, i.p95iodel, i.cgcpulimpct, i.cgrsspct, i.region, i.zone 
					from %s.aggrtaskstatetbl_%s tbl left join %s.aggrtaskinfotbl_%s i on tbl.aggr_task_id = i.aggr_task_id and
					i.time = (select max(time) from %s.aggrtaskinfotbl_%s where time between tbl.time - '5 min'::interval and tbl.time + '5 min'::interval)
			$fmt$, schname, tbltoday, schname, tbltoday, schname, tbltoday, schname, tbltoday);		
	end if;	
	
	istbl := public.gy_table_exists(schname, 'extaggrtaskstatetbl_', tbltom);
	if not istbl then 
		execute format($fmt$ create or replace view %s.extaggrtaskstatetbl_%s as 
				select tbl.*, i.related_listen_id, i.cmdline, i.tag, i.uid, i.gid, i.cpu_cg_throttled, i.mem_cg_limited, 
					i.tstart, i.p95cpupct, i.p95cpudel, i.p95iodel, i.cgcpulimpct, i.cgrsspct, i.region, i.zone 
					from %s.aggrtaskstatetbl_%s tbl left join %s.aggrtaskinfotbl_%s i on tbl.aggr_task_id = i.aggr_task_id and
					i.time = (select max(time) from %s.aggrtaskinfotbl_%s where time between tbl.time - '5 min'::interval and tbl.time + '5 min'::interval)
			$fmt$, schname, tbltom, schname, tbltom, schname, tbltom, schname, tbltom);		
	end if;	
	

	istbl := public.gy_table_exists(schname, 'extactiveconntbl', '');
	if not istbl then 
		/*
		 * NOTE : Please sync any changes here with set_ext_activeconn_fields() function
		 */
		execute format($fmt$ create or replace view %s.extactiveconntbl as 
				select tbl.*, l.ip, l.port, l.related_listen_id, l.starttime, l.cmdline,
					l.p95resp5d, l.avgresp5d, l.p95qps, l.p95aconn, l.svcip1, l.svcport1, l.svcdns, l.svctag, l.region, l.zone
					from %s.activeconntbl tbl left join %s.listeninfotbl l on tbl.listen_id = l.glob_id and
					l.time = (select max(time) from %s.listeninfotbl where time between tbl.time - '5 min'::interval and tbl.time + '5 min'::interval)
			$fmt$, schname, schname, schname, schname);		
	end if;	
	
	istbl := public.gy_table_exists(schname, 'extactiveconntbl_', tbltoday);
	if not istbl then 
		execute format($fmt$ create or replace view %s.extactiveconntbl_%s as 
				select tbl.*, l.ip, l.port, l.related_listen_id, l.starttime, l.cmdline,
					l.p95resp5d, l.avgresp5d, l.p95qps, l.p95aconn, l.svcip1, l.svcport1, l.svcdns, l.svctag, l.region, l.zone
					from %s.activeconntbl_%s tbl left join %s.listeninfotbl_%s l on tbl.listen_id = l.glob_id and
					l.time = (select max(time) from %s.listeninfotbl_%s where time between tbl.time - '5 min'::interval and tbl.time + '5 min'::interval)
			$fmt$, schname, tbltoday, schname, tbltoday, schname, tbltoday, schname, tbltoday);		
	end if;	

	istbl := public.gy_table_exists(schname, 'extactiveconntbl_', tbltom);
	if not istbl then 
		execute format($fmt$ create or replace view %s.extactiveconntbl_%s as 
				select tbl.*, l.ip, l.port, l.related_listen_id, l.starttime, l.cmdline,
					l.p95resp5d, l.avgresp5d, l.p95qps, l.p95aconn, l.svcip1, l.svcport1, l.svcdns, l.svctag, l.region, l.zone
					from %s.activeconntbl_%s tbl left join %s.listeninfotbl_%s l on tbl.listen_id = l.glob_id and
					l.time = (select max(time) from %s.listeninfotbl_%s where time between tbl.time - '5 min'::interval and tbl.time + '5 min'::interval)
			$fmt$, schname, tbltom, schname, tbltom, schname, tbltom, schname, tbltom);		
	end if;	

	istbl := public.gy_table_exists(schname, 'clientconntbl', '');
	if not istbl then 
		execute format($fmt$ create or replace view %s.clientconntbl as 
				select * from %s.remoteconntbl union select time, cli_aggr_task_id, cli_comm, listen_id, listen_comm, 
				'%s'::char(32) as listen_parthaid, '%s'::char(16) as listen_madhavaid, cli_bytes_sent, cli_bytes_received, cli_active_conns, cli_listener_proc 
				from %s.activeconntbl where cli_parthaid = '%s'
			$fmt$, schname, schname, parthaid, madhavaid, schname, parthaid);	
	end if;	

	istbl := public.gy_table_exists(schname, 'clientconntbl_', tbltoday);
	if not istbl then 
		execute format($fmt$ create or replace view %s.clientconntbl_%s as 
				select * from %s.remoteconntbl_%s union select time, cli_aggr_task_id, cli_comm, listen_id, listen_comm, 
				'%s'::char(32) as listen_parthaid, '%s'::char(16) as listen_madhavaid, cli_bytes_sent, cli_bytes_received, cli_active_conns, cli_listener_proc 
				from %s.activeconntbl_%s where cli_parthaid = '%s'
			$fmt$, schname, tbltoday, schname, tbltoday, parthaid, madhavaid, schname, tbltoday, parthaid);	
	end if;	

	istbl := public.gy_table_exists(schname, 'clientconntbl_', tbltom);
	if not istbl then 
		execute format($fmt$ create or replace view %s.clientconntbl_%s as 
				select * from %s.remoteconntbl_%s union select time, cli_aggr_task_id, cli_comm, listen_id, listen_comm, 
				'%s'::char(32) as listen_parthaid, '%s'::char(16) as listen_madhavaid, cli_bytes_sent, cli_bytes_received, cli_active_conns, cli_listener_proc 
				from %s.activeconntbl_%s where cli_parthaid = '%s'
			$fmt$, schname, tbltom, schname, tbltom, parthaid, madhavaid, schname, tbltom, parthaid);	
	end if;	


	istbl := public.gy_table_exists(schname, 'extclientconntbl', '');
	if not istbl then 
		/*
		 * NOTE : Please sync any changes here with set_ext_clientconn_fields() function
		 */
		execute format($fmt$ create or replace view %s.extclientconntbl as 
				select tbl.*, i.cmdline, i.tag, i.uid, i.gid, i.tstart, i.p95cpupct, i.p95cpudel, i.p95iodel, i.nproc, i.region, i.zone
					from %s.clientconntbl tbl left join %s.aggrtaskinfotbl i on tbl.cli_aggr_task_id = i.aggr_task_id and
					i.time = (select max(time) from %s.aggrtaskinfotbl where time between tbl.time - '5 min'::interval and tbl.time + '5 min'::interval)
			$fmt$, schname, schname, schname, schname);		
	end if;	
	
	istbl := public.gy_table_exists(schname, 'extclientconntbl_', tbltoday);
	if not istbl then 
		execute format($fmt$ create or replace view %s.extclientconntbl_%s as 
				select tbl.*, i.cmdline, i.tag, i.uid, i.gid, i.tstart, i.p95cpupct, i.p95cpudel, i.p95iodel, i.nproc, i.region, i.zone
					from %s.clientconntbl_%s tbl left join %s.aggrtaskinfotbl_%s i on tbl.cli_aggr_task_id = i.aggr_task_id and
					i.time = (select max(time) from %s.aggrtaskinfotbl_%s where time between tbl.time - '5 min'::interval and tbl.time + '5 min'::interval)
			$fmt$, schname, tbltoday, schname, tbltoday, schname, tbltoday, schname, tbltoday);		
	end if;	
	
	istbl := public.gy_table_exists(schname, 'extclientconntbl_', tbltom);
	if not istbl then 
		execute format($fmt$ create or replace view %s.extclientconntbl_%s as 
				select tbl.*, i.cmdline, i.tag, i.uid, i.gid, i.tstart, i.p95cpupct, i.p95cpudel, i.p95iodel, i.nproc, i.region, i.zone
					from %s.clientconntbl_%s tbl left join %s.aggrtaskinfotbl_%s i on tbl.cli_aggr_task_id = i.aggr_task_id and
					i.time = (select max(time) from %s.aggrtaskinfotbl_%s where time between tbl.time - '5 min'::interval and tbl.time + '5 min'::interval)
			$fmt$, schname, tbltom, schname, tbltom, schname, tbltom, schname, tbltom);		
	end if;	

	istbl := public.gy_table_exists(schname, 'exttracereqtbl', '');
	if not istbl then 
		/*
		 * NOTE : Please sync any changes here with set_ext_tracereq_fields() function. Need lateral join as duplicate entries possible in traceconntbl...
		 */
		execute format($fmt$ create or replace view %s.exttracereqtbl as 
				select tbl.*, l.cli_aggr_task_id, l.cli_comm, l.cli_parthaid, l.cli_madhavaid, l.cli_listener_proc
					from %s.tracereqtbl tbl left join lateral 
					( select cli_aggr_task_id, cli_comm, cli_parthaid, cli_madhavaid, cli_listener_proc from %s.traceconntbl where 
					tbl.connid = connid and time between tbl.conntime - '10 sec'::interval and tbl.conntime + '10 sec'::interval limit 1 ) l on true
			$fmt$, schname, schname, schname);		
	end if;	
	
	istbl := public.gy_table_exists(schname, 'exttracereqtbl_', tbltoday);
	if not istbl then 
		execute format($fmt$ create or replace view %s.exttracereqtbl_%s as 
				select tbl.*, l.cli_aggr_task_id, l.cli_comm, l.cli_parthaid, l.cli_madhavaid, l.cli_listener_proc
					from %s.tracereqtbl_%s tbl left join lateral
					( select cli_aggr_task_id, cli_comm, cli_parthaid, cli_madhavaid, cli_listener_proc from %s.traceconntbl where 
					tbl.connid = connid and time between tbl.conntime - '10 sec'::interval and tbl.conntime + '10 sec'::interval limit 1 ) l on true
			$fmt$, schname, tbltoday, schname, tbltoday, schname);		
	end if;	


	istbl := public.gy_table_exists(schname, 'exttracereqtbl_', tbltom);
	if not istbl then 
		execute format($fmt$ create or replace view %s.exttracereqtbl_%s as 
				select tbl.*, l.cli_aggr_task_id, l.cli_comm, l.cli_parthaid, l.cli_madhavaid, l.cli_listener_proc
					from %s.tracereqtbl_%s tbl left join lateral
					( select cli_aggr_task_id, cli_comm, cli_parthaid, cli_madhavaid, cli_listener_proc from %s.traceconntbl where 
					tbl.connid = connid and time between tbl.conntime - '10 sec'::interval and tbl.conntime + '10 sec'::interval limit 1 ) l on true
			$fmt$, schname, tbltom, schname, tbltom, schname);		
	end if;	


end;
$func1$ language plpgsql;

create or replace function gy_add_views_for_all(madhavaid text) returns void as $$
declare
	c 		refcursor;
	r 		record;
	tbl		text;
	tbltoday	text := to_char(now()::date, 'yyyymmdd');
	tbltom		text := to_char(now()::date + '1 day'::interval, 'yyyymmdd');
	istbl		boolean;
begin

	-- Add Global Level Views

	istbl := public.gy_table_exists('public', 'tracestatustbl_', tbltoday);
	if not istbl then 
		return;
	end if;	

	istbl := public.gy_table_exists('public', 'tracestatustbl_', tbltom);
	if not istbl then 
		return;
	end if;	

	istbl := public.gy_table_exists('public', 'tracestatus_vtbl', '');
	if not istbl then 
		execute format($fmt$ create or replace view public.tracestatus_vtbl as 
				select tbl.*, t1.hostname, t1.madhavaid, t1.clustername, t1.region, t1.zone 
					from public.tracestatustbl tbl left join public.parthatbl t1 on tbl.machid = t1.machid $fmt$);		
	end if;	

	istbl := public.gy_table_exists('public', 'tracestatus_vtbl_%s', tbltoday);
	if not istbl then 
		execute format($fmt$ create or replace view public.tracestatus_vtbl_%s as 
				select tbl.*, t1.hostname, t1.madhavaid, t1.clustername, t1.region, t1.zone 
					from public.tracestatustbl_%s tbl left join public.parthatbl t1 on tbl.machid = t1.machid 
			$fmt$, tbltoday, tbltoday);		
	end if;	

	istbl := public.gy_table_exists('public', 'tracestatus_vtbl_%s', tbltom);
	if not istbl then 
		execute format($fmt$ create or replace view public.tracestatus_vtbl_%s as 
				select tbl.*, t1.hostname, t1.madhavaid, t1.clustername, t1.region, t1.zone 
					from public.tracestatustbl_%s tbl left join public.parthatbl t1 on tbl.machid = t1.machid 
			$fmt$, tbltom, tbltom);		
	end if;	

	-- Now add Partha Level Views
	open c for select nspname from pg_catalog.pg_namespace where nspname ~ '^sch[0-9a-f]{32}$';
	loop
		fetch c into r;
		exit when not found;
		execute format($fmt$ select public.gy_add_views('%s', '%s', '%s') $fmt$ , r.nspname::text, right(r.nspname, -3)::text, madhavaid);
	end loop;

end;
$$ language plpgsql;

create or replace function gy_cleanup_schema() returns void as $$
declare
	c 		refcursor;
	r 		record;
	cnt		bigint;
	istbl		boolean;
	tbl2		text := to_char(now()::date - '2 days'::interval, 'yyyymmdd');
	tbl3		text := to_char(now()::date - '3 days'::interval, 'yyyymmdd');
begin
	open c for select nspname from pg_catalog.pg_namespace where nspname ~ '^sch[0-9a-f]{32}$';
	loop
		fetch c into r;
		exit when not found;

		istbl := public.gy_table_exists(r.nspname, 'hoststatetbl', '') and public.gy_table_exists(r.nspname, 'hoststatetbl_', tbl2) and public.gy_table_exists(r.nspname, 'hoststatetbl_', tbl3);
		if not istbl then 
			continue;
		end if;	

		execute format($fmt$ select count(time) from %s.hoststatetbl group by time order by time desc limit 1 $fmt$, r.nspname) into cnt;

		if cnt = 0 or cnt is null then
			raise notice '[%]:[INFO]: DB : Deleting Schema %', now()::text, r.nspname;

			execute format($fmt$ drop schema if exists %s cascade $fmt$, r.nspname);
			execute format($fmt$ delete from public.parthainfotbl where machid = '%s' $fmt$, right(r.nspname, -3)::text);
			execute format($fmt$ delete from public.parthatbl where machid = '%s' $fmt$, right(r.nspname, -3)::text);
		end if;	
	end loop;
end;
$$ language plpgsql;


)";

}


} // namespace madhava
} // namespace gyeeta

