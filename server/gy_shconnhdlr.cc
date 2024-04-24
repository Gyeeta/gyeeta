//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include		"gy_common_inc.h"
#include		"gy_shconnhdlr.h"
#include		"gyshyama.h"
#include		"gy_listen_sock.h"
#include		"gy_print_offload.h"
#include 		"gy_scheduler.h"
#include 		"gy_sdb_schema.h"
#include		"gy_alertmgr.h"
#include		"gy_shalerts.h"
#include 		"gy_refcnt.h"
#include 		"gy_cloud_metadata.h"
#include 		"gy_proto_common.h"

#include 		<algorithm>

#include 		"folly/ThreadCachedInt.h"
#include 		"folly/Function.h"

#include 		<sys/epoll.h>
#include 		<sys/eventfd.h>
#include 		<sys/timerfd.h>

using namespace 	gyeeta::comm;

namespace gyeeta {
namespace shyama {

static SHCONN_HANDLER	*pgshconn_handler_;

SHCONN_HANDLER::SHCONN_HANDLER(SHYAMA_C *pshyama)
	: pshyama_(pshyama),
	pdb_scheduler_(GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_LONG_DURATION)),
	pdbmain_scheduler_(GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_MAINTENANCE))
{
	assert(pshyama_);

	if (nullptr == pdb_scheduler_ || nullptr == pdbmain_scheduler_) {
		GY_THROW_EXCEPTION("Scheduler Singleton objects not yet initialized");
	}	

	auto psettings = pshyama_->psettings_;

	if (psettings->listener_ip.size() > MAX_TCP_LISTENERS) {
		GY_THROW_EXCEPTION("Too many Listener IP/Ports specified. Max allowed is %lu", MAX_TCP_LISTENERS);
	}	
	
	if (nullptr == SYS_HARDWARE::get_singleton()) {
		GY_THROW_EXCEPTION("System Hardware Singleton not yet initialized");
	}
	
	if (nullptr == GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_LONG_DURATION)) {
		GY_THROW_EXCEPTION("Scheduler Singleton objects not yet initialized");
	}	

	try {
		GY_STRNCPY(shyama_name_, psettings->shyama_name, sizeof(shyama_name_));
		GY_STRNCPY(shyama_secret_, psettings->shyama_secret, sizeof(shyama_secret_));

		gshyama_id_		= gy_cityhash64(shyama_name_, strlen(shyama_name_));

		snprintf(gshyama_id_str_, sizeof(gshyama_id_str_), "%016lx", gshyama_id_);

		INFOPRINT("Starting Shyama Server Listener Initialization : Shyama Name \'%s\' Shyama Service hostname \'%s\' Service port %hu : ID %016lx...\n", 
			shyama_name_, psettings->service_hostname, psettings->service_port, gshyama_id_);

		listen_host_vec_	= psettings->listener_ip;
		listen_port_vec_	= psettings->listener_port;

		min_madhava_		= psettings->min_madhava;
		db_storage_days_	= psettings->postgres_storage_days;
	
		std::vector<LISTEN_SOCK>	tlistenvec;

		/*
		 * First try to see if the listener IP/Port is already used. We cannot rely on the accept thread as
		 * it will use SO_REUSEPORT and that may succeed if the userid permits even though that IP/Port is already bound.
		 */
		try {
			for (size_t i = 0; i < listen_port_vec_.size(); ++i) {
				tlistenvec.emplace_back(listen_port_vec_[i], listen_host_vec_[i].c_str());
			}	
		}
		GY_CATCH_EXCEPTION(
			ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to start Shyama Listener : %s : Exiting...\n\n", GY_GET_EXCEPT_STRING);
			exit(EXIT_FAILURE);
		);
		
		pgshconn_handler_	= this;

		if (*psettings->cloud_type) {

			try {
				CLOUD_METADATA			meta(psettings->cloud_type);

				auto [pinstance_id, pregion_name, pzone_name, pcloud_type] = meta.get_metadata();
				
				if (*pregion_name) {
					GY_STRNCPY(region_name_, pregion_name, sizeof(region_name_));
				}	

				if (*pzone_name) {
					GY_STRNCPY(zone_name_, pzone_name, sizeof(zone_name_));
				}	

				if (*pcloud_type) {
					GY_STRNCPY(cloud_type_, pcloud_type, sizeof(cloud_type_));
				}	
			}
			GY_CATCH_EXPRESSION(
				ERRORPRINT("Metadata Error : %s\n", GY_GET_EXCEPT_STRING);
			);
		}	

		if (*psettings->region_name) {
			if (*region_name_ && strcmp(psettings->region_name, region_name_)) {
				INFOPRINT_OFFLOAD("Instance Region Name in config \'%s\') different from Metadata retrieved Region Name (\'%s\') : Using Config Value...\n",
					region_name_, psettings->region_name);
			}

			GY_STRNCPY(region_name_, psettings->region_name, sizeof(region_name_));
		}

		if (*psettings->zone_name) {
			if (*zone_name_ && strcmp(psettings->zone_name, zone_name_)) {
				INFOPRINT_OFFLOAD("Instance Zone Name in config \'%s\') different from Metadata retrieved Zone Name (\'%s\') : Using Config Value...\n",
					zone_name_, psettings->zone_name);
			}

			GY_STRNCPY(zone_name_, psettings->zone_name, sizeof(zone_name_));
		}	

		paccept_arr_ 		= new ACC_PARAMS[MAX_ACCEPT_THREADS];
		pl1_arr_		= new L1_PARAMS[MAX_L1_THREADS];

		pl2_db_arr_		= new L2_PARAMS[MAX_L2_DB_THREADS];
		pl2_misc_arr_		= new L2_PARAMS[MAX_L2_MISC_THREADS];
		pl2_alert_arr_		= new L2_PARAMS[MAX_L2_ALERT_THREADS];

		ppmpmc_db_arr_		= new MPMCQ_COMM *[MAX_L2_DB_POOLS];
		ppmpmc_misc_arr_	= new MPMCQ_COMM *[MAX_L2_MISC_POOLS];
		ppmpmc_alert_arr_	= new MPMCQ_COMM *[MAX_L2_ALERT_POOLS];

		for (size_t i = 0; i < MAX_L2_DB_POOLS; ++i) {
			ppmpmc_db_arr_[i]	= new MPMCQ_COMM(MAX_MPMC_ELEMS);
		}	

		for (size_t i = 0; i < MAX_L2_MISC_POOLS; ++i) {
			ppmpmc_misc_arr_[i]	= new MPMCQ_COMM(MAX_MPMC_ELEMS);
		}	

		for (size_t i = 0; i < MAX_L2_ALERT_POOLS; ++i) {
			ppmpmc_alert_arr_[i]	= new MPMCQ_COMM(MAX_MPMC_ELEMS);
		}	

		// Now clear the Temp Listener
		tlistenvec.clear();

		init_db_glob_conns();

		spawn_init_threads();

		auto schedshr = GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_LONG_DURATION);
		schedshr->add_schedule(60'030, 60'000 /* 60 sec */, 0, "Clean up unused Madhava and Node elements and update DB", 
		[this] { 
			sync_partha_madhava_node_stats();
		});

		pdbmain_scheduler_->add_schedule(5000, 5000, 0, "Send Madhava Status Event", 
		[this] { 
			send_madhava_status();
		});

		pdbmain_scheduler_->add_schedule(30 * GY_MSEC_PER_SEC + 100, 100 * GY_MSEC_PER_SEC, 0, "Send All Madhava List Event", 
		[this] { 
			send_all_list_madhava();
		});

		pdb_scheduler_->add_schedule(402'080, 300'000, 0, "Print DB Error Stats", 
		[this] { 
			db_stats_.print_stats();
		});

		auto schedshrhigh = GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_HIGH_PRIO);

		time_t			tcurr = time(nullptr), tnxt = (tcurr / 30) * 30;

		schedshrhigh->add_schedule(60'230 + 4000 + 30'000 - (tcurr - tnxt) * 1000, 30'000, 0, "Cleanup the TCP Conn Table", 
		[this] { 
			cleanup_tcp_conn_table();
		});

		tcurr = time(nullptr);
		tnxt = (tcurr / 5) * 5;

		// Sync with Madhava + 1 sec
		pdbmain_scheduler_->add_schedule(101'400 + 1000 + 5000 - (tcurr - tnxt) * 1000, 5000, 0, "Aggregate Cluster State", 
		[this, nextprint = 5] () mutable { 
			bool			to_print = false;

			if (--nextprint == 0) {
				nextprint = 5;
				to_print = true;
			}	

			aggregate_cluster_state(to_print);
		});

		pdbmain_scheduler_->add_schedule(360'000 + 1000 + 5000 - (tcurr - tnxt) * 1000, 3 * LISTENER_CLUSTER_NOTIFY::INODE_CLUSTER_MSEC /* 300'000 */, 0, "Coalesce Mesh Cluster Listeners", 
		[this] { 
			coalesce_svc_mesh_clusters();
		});

		pdbmain_scheduler_->add_schedule(360'100 + 2000 + 5000 - (tcurr - tnxt) * 1000, 360'000, 0, "NAT IP Cluster Listeners", 
		[this] { 
			check_svc_nat_ip_clusters();
		});

		auto				*pschlong2 = GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_LONG2_DURATION);

		assert(pschlong2);

		pschlong2->add_schedule(101 + 6 * GY_MSEC_PER_HOUR, 12 * GY_MSEC_PER_HOUR, 0, "Cleanup DB Partha Entries",
		[this] {
			cleanup_db_partha_entries();
		});

		pdbmain_scheduler_->add_schedule(303'000, 90'000, 0, "Check expired Req Tracedef Entries",
		[this] {
			check_all_tracedefs(*dbmain_scheduler_pool_.get());
		});

		INFOPRINT("Shyama Listener Initialization Completed successfully...\n");
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Error while starting Shyama Listener Handler Threads : %s\n", GY_GET_EXCEPT_STRING);
		throw;
	);
}	

SHCONN_HANDLER * SHCONN_HANDLER::get_singleton() noexcept
{
	return pgshconn_handler_;
}	

void SHCONN_HANDLER::init_db_glob_conns()
{
	auto 				psettings = pshyama_->psettings_;
	std::optional<GyPGConn>		postconn;
	auto				dbname = get_dbname();
	char				cmd[256];
	
	INFOPRINT("Initiating Postgres Database connection pool and init commands...\n");

	try {
		postconn.emplace(psettings->postgres_hostname, psettings->postgres_port, psettings->postgres_user, psettings->postgres_password,
							"postgres", "shyama", get_db_init_commands().get(), false /* auto_reconnect */, 12, 2);
	}
	GY_CATCH_EXCEPTION(
		INFOPRINT_OFFLOAD("Failed to Login to Postgres database default \'postgres' DB. Will try Shyama DB \'%s\' directly... : Exception message : %s\n",
			dbname.get(), GY_GET_EXCEPT_STRING);
		goto next;
	);
	
	if (bool(postconn)) {
		snprintf(cmd, sizeof(cmd), "select 1 from pg_database where datname = \'%s\'", dbname.get());

		auto			res = postconn->pqexec_blocking(cmd);
		
		if ((res.is_error()) || (0 == PQntuples(res.get())))  {
			INFOPRINT("Postgres Database \'%s\' not found for Shyama. Creating new database...\n", dbname.get());

			snprintf(cmd, sizeof(cmd), "create database %s;", dbname.get());

			auto		cres = postconn->pqexec_blocking(cmd);

			if (cres.is_error()) {
				GY_THROW_EXCEPTION("Postgres Database Host %s Port %s : Failed to create new database %s for Shyama : %s", 
						PQhost(postconn->get()), PQport(postconn->get()), dbname.get(), cres.get_error_no_newline().get());
			}	
		}

		postconn->close_conn();
	}

next :

	db_scheduler_pool_ = std::make_unique<PGConnPool>("DB Scheduler Pool", 3, psettings->postgres_hostname, psettings->postgres_port, psettings->postgres_user, psettings->postgres_password,
						dbname.get(), "shyama_sched", get_db_init_commands().get(), true /* auto_reconnect */, 12, 100, 10);

	if (true) {
		auto			pconn = db_scheduler_pool_->get_conn();
		
		if (!pconn) {
			GY_THROW_EXCEPTION("Failed to get Postgres Database connection from Scheduler connection pool");
		}	
	}

	// Now try to make the instance as master or keep trying till we succeed...
	auto 			[olddbver, oldprocver] = init_set_instance_master(*db_scheduler_pool_.get());

	dbmain_scheduler_pool_ = std::make_unique<PGConnPool>("DB Scheduler Maintenance Pool", 2, psettings->postgres_hostname, psettings->postgres_port, 
					psettings->postgres_user, psettings->postgres_password, dbname.get(), "shyama_schedmain", get_db_init_commands().get(), true /* auto_reconnect */, 12, 10, 10);

	if (true) {
		auto			pconn = dbmain_scheduler_pool_->get_conn();
		
		if (!pconn) {
			GY_THROW_EXCEPTION("Failed to get Postgres Database connection from Scheduler connection pool");
		}	
	}

	auto			pconn = db_scheduler_pool_->get_conn();
	
	if (!pconn) {
		GY_THROW_EXCEPTION("Failed to get Postgres Database connection from connection pool");
	}	

	// Now update global procs
	
	auto 			gyres = pconn->pqexec_blocking(get_common_pg_procs());

	if (true == gyres.is_error()) {
		GY_THROW_EXCEPTION("Failed to execute query on Postgres DB to add global common Postgres procs : %s", gyres.get_error_no_newline().get());
	}

	upgrade_db_schemas(olddbver, oldprocver, pconn);

	gyres = pconn->pqexec_blocking(get_sglobtables());

	if (true == gyres.is_error()) {
		GY_THROW_EXCEPTION("Failed to execute query on Postgres DB to add global tables : %s", gyres.get_error_no_newline().get());
	}
	
	gyres = pconn->pqexec_blocking(get_sglob_part_tables());

	if (true == gyres.is_error()) {
		GY_THROW_EXCEPTION("Failed to execute query on Postgres DB to add global Partition functions : %s", gyres.get_error_no_newline().get());
	}

	gyres = pconn->pqexec_blocking(gy_to_charbuf<256>("select gy_add_glob_part_tables(%s::boolean);", psettings->db_logging != DB_LOGGING_ALWAYS ? "true" : "false").get());

	if (true == gyres.is_error()) {
		GY_THROW_EXCEPTION("Failed to execute query on Postgres DB to add global partition table : %s", gyres.get_error_no_newline().get());
	}

	pconn->make_available();

	db_cleanup_old_partitions(*db_scheduler_pool_.get(), false);

	db_add_partitions();

	db_scheduler_pool_->wait_all_responses();

	pdb_scheduler_->add_schedule(8 * GY_MSEC_PER_HOUR + 502, 8 * GY_MSEC_PER_HOUR, 0, "Add and Delete Postgres DB Partitions", 
	[this] { 
		db_add_partitions();
	});

	pdb_scheduler_->add_schedule(5 * GY_MSEC_PER_HOUR + 701, 12 * GY_MSEC_PER_HOUR, 0, "Set DB Partitions Logged", 
	[this] { 
		db_set_part_logged();
	});

	pdb_scheduler_->add_schedule(0, 60000, 0, "Set DB Disk Space Used", 
	[this] { 
		set_db_disk_space_used();
	});

	pdb_scheduler_->add_schedule(610'120, 60000, 0, "Reset DB Scheduler Idle connections", 
	[this] { 
		db_scheduler_pool_->reset_idle_conns();
	});

	pdbmain_scheduler_->add_schedule(210'320, 60000, 0, "Reset DB Maintenance Idle connections", 
	[this] { 
		dbmain_scheduler_pool_->reset_idle_conns();
	});


	INFOPRINT("Postgres DB Initialization Completed...\n");
}

/*
 * Will not return till instance becomes a master
 * Returns {olddbver, oldprocver}
 */
std::pair<int, int> SHCONN_HANDLER::init_set_instance_master(PGConnPool & dbpool)
{
	int			olddbver = CURR_DB_VERSION, oldprocver = gversion_num;

	if (true) {
		auto			pconn = dbpool.get_conn();

		if (!pconn) {
			GY_THROW_EXPRESSION("Failed to get Postgres Database connection for init master from Scheduler connection pool");
		}	

		auto			res = pconn->pqexec_blocking(get_common_instancemaster_tbl());	
		
		if (res.is_error()) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to execute query to Postgres to create Instance Master table : Error is %s\n", PQerrorMessage(pconn->get()));
		}	

		res = pconn->pqexec_blocking(get_common_instancemaster_proc());

		if (res.is_error()) {
			GY_THROW_EXPRESSION("Failed to execute query on Postgres DB to add Instance Master handling proc : %s", res.get_error_no_newline().get());
		}

		// Now check the dbversion if it is <= CURR_DB_VERSION 		

		res = pconn->pqexec_blocking("select dbversion, procvernum, procverstr from public.instanceversiontbl where id = 1");

		if (res.is_error()) {
			GY_THROW_EXPRESSION("Failed to execute query on Postgres DB to query Instance DB Version : %s", res.get_error_no_newline().get());
		}

		const PGresult *		pres = res.get();
		const int			nfields = PQnfields(pres);
		const int			ntuples = PQntuples(pres);

		if (ntuples > 0 && nfields == 3) {

			const char 		*pdata1, *pdata2, *pdata3;
			int			len1 = PQgetlength(pres, 0, 0);
			int			len2 = PQgetlength(pres, 0, 1);
			int			len3 = PQgetlength(pres, 0, 2);

			if (len1 > 0 && len2 > 0) {

				pdata1 	= PQgetvalue(pres, 0, 0);
				pdata2 	= PQgetvalue(pres, 0, 1);
				pdata3 	= PQgetvalue(pres, 0, 2);

				if (!pdata3) {
					pdata3 = "";
				}	

				DEBUGEXECN(1,
					INFOPRINT_OFFLOAD("Instance Postgres Version Check from DB returned : DB Version %s, Process Version %s (\'%s\')\n", pdata1, pdata2, pdata3);
				);

				olddbver 	= atoi(pdata1);
				oldprocver	= atoi(pdata2);

				if (olddbver > CURR_DB_VERSION && oldprocver > (int)gversion_num) {
					GY_THROW_EXPRESSION("Instance Postgres Current DB Version %d greater than Process handled DB Version %d : "
						"Also last or current Master Instance Version 0x%08x (%s) is greater than Current Process version %08x (%s) : Please update Current Binary first",
						olddbver, CURR_DB_VERSION, oldprocver, pdata3, gversion_num, gversion);
				}	
			}
		}	
	}

	INFOPRINT("Checking if this instance is Shyama Master instance...\n");

	auto 			psettings = pshyama_->psettings_;
	char			qbuf[2048], currhostip[MAX_DOMAINNAME_SIZE] = {};
	time_t			tstart = time(nullptr);
	const char		*name = "Check for Shyama Instance Master";
	int			nerr = 0, ndataerr = 0, port = 0, currport = 0;

	snprintf(qbuf, sizeof(qbuf), "select ismaster, currhostip, currport from gy_try_instance_master(\'%s\', %hu, 0)", psettings->service_hostname, psettings->service_port);

	for (;; (void)gy_nanosleep(30, 0)) {
		auto			pconn = dbpool.get_conn();

		if (!pconn) {
			GY_THROW_EXPRESSION("Failed to get Postgres Database connection for %s from Scheduler connection pool", name);
		}	
		
		auto			gyres = pconn->pqexec_blocking(qbuf);

		if (true == gyres.is_error()) {
			if (++nerr < 10) {
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "%s : Failed to query from DB due to %s\n", name, gyres.get_error_msg());
				continue;
			}

			GY_THROW_EXPRESSION("%s : Too many errors while querying from DB due to %s", name, gyres.get_error_msg());
		}	
		
		nerr = 0;

		const PGresult *		pres = gyres.get();
		const int			nfields = PQnfields(pres);
		const int			ntuples = PQntuples(gyres.get());

		if (ntuples == 0) {

			if (++ndataerr < 10) {
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "%s : Query Result received no rows\n", name);
				continue;
			}

			GY_THROW_EXPRESSION("%s : Too many Errors as Query Result received no rows", name);
		}	

		if ((unsigned)nfields < 3) {
			if (++ndataerr < 10) {
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "%s : Query Result received invalid column count %d instead of 3\n", name, nfields);
				continue;
			}

			GY_THROW_EXPRESSION("%s : Invalid DB Column count seen : %d instead of 3", name, nfields);
		}	


		const char 		*pdata1, *pdata2, *pdata3;
		int			len1 = PQgetlength(pres, 0, 0);
		int			len2 = PQgetlength(pres, 0, 1);
		int			len3 = PQgetlength(pres, 0, 2);

		if (len1 == 0 || len2 == 0 || len3 == 0) {
			if (++ndataerr < 10) {
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "%s : Query Result received null column : %d %d %d\n", name, len1, len2, len3);
				continue;
			}

			GY_THROW_EXPRESSION("%s : Too many Errors as Query Result received null column", name);
		}

		pdata1 	= PQgetvalue(pres, 0, 0);
		pdata2 	= PQgetvalue(pres, 0, 1);
		pdata3 	= PQgetvalue(pres, 0, 2);

		DEBUGEXECN(1,
			INFOPRINT_OFFLOAD("Instance Master Check from DB returned : \'%s\', \'%s\', \'%s\'\n", pdata1, pdata2, pdata3);
		);

		port 	= atoi(pdata3);

		if (*pdata1 == '1') {
			if (strcmp(pdata2, psettings->service_hostname)) {
				if (++ndataerr < 10) {
					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "%s : Query Result received as current Master but service hostname differs : \'%s\' instead of \'%s\'\n", 
						name, pdata2, psettings->service_hostname);
					continue;
				}

				GY_THROW_EXPRESSION("%s : Too many Errors as Query Result received with current as Master but different service hostname \'%s\'", name, pdata2);
			}	
			
			if (port != (int)psettings->service_port) {
				if (++ndataerr < 10) {
					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "%s : Query Result received as current Master but service port differs : %d instead of %hu\n", 
						name, port, psettings->service_port);
					continue;
				}

				GY_THROW_EXPRESSION("%s : Too many Errors as Query Result received with current as Master but different service port %d", name, port);
			}	

			if (!currport) {
				INFOPRINT("Setting current Shyama instance as Master instance...\n");
			}
			else {
				INFOPRINT("Setting current Shyama instance as Master instance from Standby mode as previous master (host %s port %d) is not updating DB...\n",
					currhostip, currport);
			
				INFOPRINT("Time for which instance was a Standby instance was : %s : Now starting the instance in master mode...\n",
					get_time_diff_string(time(nullptr) - tstart).get());
			}	

			is_master_ = true;
			tlast_instance_ = time(nullptr);

			// Now spawn the instance_thr_ to periodically update db
			instance_thr_.emplace("Instance Thread", GET_PTHREAD_WRAPPER(instance_thread), this, nullptr, nullptr, true,
							1024 * 1024 /* 1 MB Stack */, 2000, true, true, true /* thr_func_calls_init_done */, 5000, true);

			return {olddbver, oldprocver};
		}	
		else if (port != currport || (strcmp(pdata2, currhostip))) {

			currport = port;
			GY_STRNCPY(currhostip, pdata2, sizeof(currhostip));
		}	

		INFOPRINT("Shyama instance is in Standby mode : Current Master Instance is host \'%s\' port %d\n", currhostip, currport);
		
		ndataerr = 0;
	}
}	

int SHCONN_HANDLER::instance_thread() noexcept
{
	instance_thr_->set_thread_init_done();

	try {
		char				qbuf[2048];
		const char			*name = "Check for Shyama Instance Master";
		int				nerr = 0, ndataerr = 0, port = 0, currport = 0, nerrormaster = 0;

		auto 				psettings = pshyama_->psettings_;
		auto				dbname = get_dbname();
		PGConnPool			dbpool("DB Instance Pool", 2, psettings->postgres_hostname, psettings->postgres_port, psettings->postgres_user, psettings->postgres_password,
							dbname.get(), "shyama_instance", get_db_init_commands().get(), true /* auto_reconnect */, 12, 10, 10);

		time_t				tcurr = time(nullptr), tlastconn = tcurr;

		/*
		 * NOTE : Only 1 MB stack thread...
		 */
		assert(gy_get_thread_local().get_thread_stack_freespace() >= 300 * 1024);

		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Instance Thread now initiating DB querying as current Master...\n");

		snprintf(qbuf, sizeof(qbuf), "select ismaster, currhostip, currport from gy_try_instance_master(\'%s\', %hu, 1)", psettings->service_hostname, psettings->service_port);
	
		for (;; (void)gy_nanosleep(30, 0)) {

			auto			pconn = dbpool.get_conn();
			time_t			tnow = time(nullptr);

			if (!pconn) {
				if (tnow > tlastconn + 30 * 60) {
					ERRORPRINT("Failed to get Postgres Database connection for %s for more than %ld min. Restarting process to allow other standby servers to take over...\n", 
							name, (tnow - tlastconn)/60);

					pshyama_->send_proc_restart_exit();
					// Will not return...
				}

				ERRORPRINT("Failed to get Postgres Database connection for %s since last %ld min. Will retry later..\n.", name, (tnow - tlastconn)/60);
				continue;
			}	
			
			tlastconn		= tnow;

			auto			gyres = pconn->pqexec_blocking(qbuf);

			if (true == gyres.is_error()) {
				if (++nerr < 10) {
					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "%s : Failed to query from DB due to %s\n", name, gyres.get_error_msg());
					continue;
				}

				ERRORPRINT("%s : Too many errors while querying from DB due to %s. Restarting process to allow other standby servers to take over..\n", name, gyres.get_error_msg());

				pshyama_->send_proc_restart_exit();
			}
			
			nerr = 0;

			const PGresult *		pres = gyres.get();
			const int			nfields = PQnfields(pres);
			const int			ntuples = PQntuples(gyres.get());

			if (ntuples == 0) {

				if (++ndataerr < 10) {
					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "%s : Query Result received no rows\n", name);
					continue;
				}

				ERRORPRINT("%s : Too many Errors as Query Result received no rows. Restarting process to allow other standby servers to take over..\n", name);

				pshyama_->send_proc_restart_exit();
			}	

			if ((unsigned)nfields < 3) {
				if (++ndataerr < 10) {
					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "%s : Query Result received invalid column count %d instead of 3\n", name, nfields);
					continue;
				}

				ERRORPRINT("%s : Invalid DB Column count seen : %d instead of 3. Restarting process to allow other standby servers to take over..\n", name, nfields);
				pshyama_->send_proc_restart_exit();
			}	


			const char 		*pdata1, *pdata2, *pdata3;
			int			len1 = PQgetlength(pres, 0, 0);
			int			len2 = PQgetlength(pres, 0, 1);
			int			len3 = PQgetlength(pres, 0, 2);

			if (len1 == 0 || len2 == 0 || len3 == 0) {
				if (++ndataerr < 10) {
					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "%s : Query Result received null column : %d %d %d\n", name, len1, len2, len3);
					continue;
				}

				ERRORPRINT("%s : Too many Errors as Query Result received null column. Restarting process to allow other standby servers to take over..\n", name);
				pshyama_->send_proc_restart_exit();
			}

			pdata1 	= PQgetvalue(pres, 0, 0);
			pdata2 	= PQgetvalue(pres, 0, 1);
			pdata3 	= PQgetvalue(pres, 0, 2);

			port 	= atoi(pdata3);

			if (*pdata1 == '1') {
				if (strcmp(pdata2, psettings->service_hostname)) {
					if (++ndataerr < 10) {
						ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "%s : Instance is currently a Master but service hostname differs : \'%s\' instead of \'%s\'\n", 
							name, pdata2, psettings->service_hostname);
						continue;
					}

					ERRORPRINT("%s : Too many Errors as Query Result received with current as Master but different service hostname \'%s\' : "
						"Restarting process to allow other standby servers to take over..\n", name, pdata2);

					pshyama_->send_proc_restart_exit();
				}	
				
				if (port != (int)psettings->service_port) {
					if (++ndataerr < 10) {
						ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "%s : Instance is currently a Master but service port differs : %d instead of %hu\n", 
							name, port, psettings->service_port);
						continue;
					}

					ERRORPRINT("%s : Too many Errors as Query Result received with current as Master but different service port %d : "
						"Restarting process to allow other standby servers to take over..\n", name, port);

					pshyama_->send_proc_restart_exit();
				}	
			}	
			else {
				if (++nerrormaster < 4) {
					ERRORPRINT("Instance was the current master but DB query shows different master instance : New Master Instance is host \'%s\' port %d : will wait for a few minutes\n", 
						pdata2, port);
					continue;
				}

				ERRORPRINT("Instance was the current master but DB query shows a different master instance (host \'%s\' port %d). Restarting process in standby mode...\n",
					pdata2, port);

				pshyama_->send_proc_restart_exit();
			}	
			
			ndataerr = 0;
			nerrormaster = 0;

			tlast_instance_ = time(nullptr);
		}
			
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught in Master Instance thread : %s : Restarting process...\n", GY_GET_EXCEPT_STRING);
		pshyama_->send_proc_restart_exit();
	);
	
	return -1;

}	


bool SHCONN_HANDLER::db_cleanup_old_partitions(PGConnPool & dbpool, bool is_non_block) noexcept
{
	try {
		auto			pconn = dbpool.get_conn();

		if (!pconn) {
			db_stats_.nconns_failed_.fetch_add_relaxed(1, mo_relaxed);
			db_stats_.ndel_partition_failed_.fetch_add(1, mo_relaxed);
			return false;
		}	

		STRING_BUFFER<2048>		cleanup_query;
		bool				bret;

		cleanup_query.appendconst("with nsname(ns, name) as "
			"(select nstbl.ns, tbl.name from (select 'public') as nstbl(ns) cross join (values");

		for (size_t i = 0; i < GY_ARRAY_SIZE(db_glob_partition_tbls); ++i) {
			cleanup_query.appendfmt("(\'%s\'),", db_glob_partition_tbls[i]);
		}	

		cleanup_query.set_last_char(' ');

		cleanup_query.appendfmt(") as tbl(name)) select gy_cleanup_partition(nsname.ns::text, nsname.name::text, now()::date - %u) from nsname;\n", 
			db_storage_days_);
			
		if (is_non_block) {
			assert(true == pconn->is_idle());

			bret = PQsendQueryOptim(pconn->get(), cleanup_query.buffer(), cleanup_query.size());
			
			if (bret == false) {
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to schedule query to Postgres to cleanup old DB Partitions : Error is %s\n", PQerrorMessage(pconn->get()));
				db_stats_.ndel_partition_failed_.fetch_add(1, mo_relaxed);
				return false;
			}	

			pconn->set_resp_cb(
				[this](GyPGConn & conn, GyPGresult gyres, bool is_completed) -> bool
				{
					if (is_completed) {
						if (conn.is_within_tran()) {
							conn.pqexec_blocking("Rollback Work;");
						}						
						conn.make_available();
						return true;
					}	
					
					if (true == gyres.is_error()) {
						ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to execute query to cleanup old DB Partitions : %s\n", 
							gyres.get_error_msg());
						db_stats_.ndel_partition_failed_.fetch_add(1, mo_relaxed);
						return false;
					}	

					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Deleted old Postgres DB Partitions successfully...\n");
					return true;
				}
			);

			return true;
		}
		
		auto				res = pconn->pqexec_blocking(cleanup_query.buffer());	
		
		if (res.is_error()) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to execute query to Postgres to cleanup old DB Partitions : Error is %s\n", PQerrorMessage(pconn->get()));
			db_stats_.ndel_partition_failed_.fetch_add(1, mo_relaxed);
			return false;
		}	

		return true;

	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception while cleaning up old Postgres Partitions due to %s\n", GY_GET_EXCEPT_STRING);
		db_stats_.ndel_partition_failed_.fetch_add(1, mo_relaxed);
		return false;
	);
}	

bool SHCONN_HANDLER::db_add_partitions() noexcept
{
	try {
		STRING_BUFFER<2048>		qbuf;
		bool				bret;
		auto 				psettings = pshyama_->psettings_;

		auto				pconn = db_scheduler_pool_->get_conn(true /* wait_response_if_unavail */, 600'000 /* max_msec_wait */, true /* reset_on_timeout */);
		
		if (!pconn) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to schedule query to Postgres to add new DB Partition\n");
			db_stats_.nconns_failed_.fetch_add_relaxed(1, mo_relaxed);
			db_stats_.nadd_partition_failed_.fetch_add(1, mo_relaxed);
			return false;
		}	

		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Sending Add New Partition Command to Postgres...\n");

		qbuf.appendfmt("select gy_add_partition(%u, ARRAY[", db_storage_days_);

		for (size_t i = 0; i < GY_ARRAY_SIZE(db_glob_partition_tbls); ++i) {
			qbuf.appendfmt("\'%s\',", db_glob_partition_tbls[i]);
		}	

		qbuf.set_last_char(' ');

		qbuf.appendfmt("], \'^public$\', %s::boolean);\n", psettings->db_logging != DB_LOGGING_ALWAYS ? "true" : "false");

		bret = PQsendQueryOptim(pconn->get(), qbuf.buffer(), qbuf.size());
		
		if (bret == false) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to schedule query to Postgres to add new DB Partition : Error is %s\n", PQerrorMessage(pconn->get()));
			db_stats_.nadd_partition_failed_.fetch_add(1, mo_relaxed);
			return false;
		}	

		pconn->set_resp_cb(
			[this](GyPGConn & conn, GyPGresult gyres, bool is_completed) -> bool
			{
				if (is_completed) {
					if (conn.is_within_tran()) {
						conn.pqexec_blocking("Rollback Work;");
					}						
					conn.make_available();
					return true;
				}	
				
				if (true == gyres.is_error()) {
					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to execute query to add new DB Partitions : %s\n", 
						gyres.get_error_msg());
					db_stats_.nadd_partition_failed_.fetch_add(1, mo_relaxed);
					return false;
				}	
				else {
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Added new Postgres DB Partitions successfully...\n");
				}	

				return true;
			}
		);

		return true;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while sending query to Postgres DB for adding new DB Partitions : %s\n", GY_GET_EXCEPT_STRING);
		db_stats_.nadd_partition_failed_.fetch_add(1, mo_relaxed);
		return false;
	);
}


bool SHCONN_HANDLER::db_set_part_logged() noexcept
{
	try {
		STRING_BUFFER<4096>		qbuf;
		bool				bret;
		auto 				psettings = pshyama_->psettings_;

		if (psettings->db_logging == DB_LOGGING_NONE) {
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "DB Tables will be kept unlogged as \'db_logging\' option set to \'none\'. "
							"This will cause data loss in case of ungraceful DB shutdown...\n");
			return true;
		}
		else if (psettings->db_logging == DB_LOGGING_ALWAYS) {
			return true;
		}	

		auto				pconn = db_scheduler_pool_->get_conn(true /* wait_response_if_unavail */, 100'000 /* max_msec_wait */, true /* reset_on_timeout */);
		
		if (!pconn) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to schedule query to Postgres to set DB Logged\n");
			db_stats_.nconns_failed_.fetch_add_relaxed(1, mo_relaxed);
			return false;
		}	

		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Sending Partition Logged Command to Postgres...\n");

		qbuf.appendconst("select public.gy_set_tbl_logged(ARRAY[");

		for (size_t i = 0; i < GY_ARRAY_SIZE(db_glob_partition_tbls); ++i) {
			qbuf.appendfmt("\'%s\',", db_glob_partition_tbls[i]);
		}	

		qbuf.set_last_char(' ');

		qbuf.appendconst("], \'^public$\');\n");

		bret = PQsendQueryOptim(pconn->get(), qbuf.buffer(), qbuf.size());
		
		if (bret == false) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to schedule query to Postgres to set DB Partition Logged : Error is %s\n", PQerrorMessage(pconn->get()));
			return false;
		}	

		pconn->set_resp_cb(
			[this](GyPGConn & conn, GyPGresult gyres, bool is_completed) -> bool
			{
				if (is_completed) {
					if (conn.is_within_tran()) {
						conn.pqexec_blocking("Rollback Work;");
					}						
					conn.make_available();
					return true;
				}	
				
				if (true == gyres.is_error()) {
					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to execute query to set DB Partition Logged : %s\n", 
						gyres.get_error_msg());
					return false;
				}	
				else {
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Added new Postgres DB Partitions successfully...\n");
				}	

				return true;
			}
		);

		return true;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while sending query to Postgres DB for setting DB Partition Logged : %s\n", GY_GET_EXCEPT_STRING);
		return false;
	);
}

bool SHCONN_HANDLER::set_db_disk_space_used() noexcept
{
	try {
		bool				bret;

		auto				pconn = db_scheduler_pool_->get_conn(true /* wait_response_if_unavail */, 1000 /* max_msec_wait */, false /* reset_on_timeout */);
		
		if (!pconn) {
			return false;
		}	

		time_t				tcurr = time(nullptr);
		uint64_t			currsz;

		currsz = pconn->get_db_disk_usage();

		if (currsz > 0) {
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Current DB Disk Space Used is %lu MB (%lu GB) : In %ld sec, difference in disk space use is %ld MB\n",
				GY_DOWN_MB(currsz), GY_DOWN_GB(currsz), tcurr - tlast_db_size_, curr_db_size_ ? ((int64_t)currsz - (int64_t)curr_db_size_)/(1024 * 1024) : 0);

			tlast_db_size_ 	= tcurr;
			curr_db_size_ 	= currsz;
		}	

		return true;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while getting Postgres DB Disk Space : %s\n", GY_GET_EXCEPT_STRING);
		return false;
	);
}


void SHCONN_HANDLER::spawn_init_threads()
{
	/*
	 * We first spawn the accept threads (REUSEPORTs)
	 */
	auto acclam = [](void *arg) -> void *
	{
		GY_THREAD	*pthr = (GY_THREAD *)arg;
		SHCONN_HANDLER	*pthis = (SHCONN_HANDLER *)pthr->get_opt_arg1();

		MAKE_PTHREAD_WRAP("handle_accept", pthis->handle_accept(pthr));

		return nullptr;
	};

	for (uint32_t na = 0; na < MAX_ACCEPT_THREADS; ++na) {	
		GY_THREAD		*pthr = nullptr;	
		auto 			psignal = MULTI_COMM_SINGLETON::get_single_512()->get_proc_buf();
		int			nretry = 0, respcode;
		uint8_t			retdata[MULTI_COMM_SINGLETON::SINGLE_PROC_SZ_512::get_max_data_len()];	
		ACC_PARAMS		*pretdata;
		size_t			sz1;
		
		assert(psignal);

		pretdata = (ACC_PARAMS *)psignal->get_data_buf();

		new (pretdata) ACC_PARAMS();

		pretdata->thr_num_ = na;
		pretdata->thr_type_ = TTYPE_ACCEPT;

		do {
			try {
				pthr = new GY_THREAD("accept handler", acclam, nullptr, this, psignal);
			}
			GY_CATCH_EXCEPTION(
				if (++nretry < 4) {
					ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to start accept thread %s : Retrying after 3 sec", GY_GET_EXCEPT_STRING);
					gy_nanosleep(3, 0);
				}
			);
		} 
		while (!pthr && nretry < 4);

		if (!pthr) {
			ERRORPRINTCOLOR(GY_COLOR_RED, "Too many thread spawn failures. Exiting...\n\n");
			exit(EXIT_FAILURE);
		}	

		// Now wait
		psignal->dispatch_wait(retdata, sz1, respcode);

		pretdata = (ACC_PARAMS *)retdata;

		if (respcode != 0) {
			pretdata->descbuf_[sizeof(pretdata->descbuf_) - 1] = '\0';
			ERRORPRINTCOLOR(GY_COLOR_RED, "Accept thread returned error %s (%d). Exiting...\n\n", pretdata->descbuf_, respcode);
			exit(EXIT_FAILURE);
		}	

		assert(pretdata->plisten_ && pretdata->listen_fd_ > 0 && pretdata->epollfd_ > 0 && pretdata->pthread_ == pthr);

		if (!(pretdata->plisten_ && pretdata->listen_fd_ > 0 && pretdata->epollfd_ > 0 && pretdata->pthread_ == pthr)) {
			ERRORPRINTCOLOR(GY_COLOR_RED, "Internal error : Accept thread returned invalid parameters. Exiting...\n\n");
			exit(EXIT_FAILURE);
		}	

		paccept_arr_[na] = *pretdata;
	}	

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "All Accept threads spawned successfully. Now spawning Level 1 Handler threads...\n");

	/*
	 * Now spawn the Level 1 epoll handler threads
	 */
	auto l1lam = [](void *arg) -> void *
	{
		GY_THREAD	*pthr = (GY_THREAD *)arg;
		SHCONN_HANDLER	*pthis = (SHCONN_HANDLER *)pthr->get_opt_arg1();

		MAKE_PTHREAD_WRAP("Level 1 Handler", pthis->handle_l1(pthr));

		return nullptr;
	};

	for (uint32_t n = 0; n < MAX_L1_THREADS; ++n) {	
		GY_THREAD		*pthr = nullptr;	
		auto 			psignal = MULTI_COMM_SINGLETON::get_single_512()->get_proc_buf();
		int			nretry = 0, respcode;
		uint8_t			retdata[MULTI_COMM_SINGLETON::SINGLE_PROC_SZ_512::get_max_data_len()];	
		L1_PARAMS		*pretdata, *parray;
		size_t			sz1;
		
		assert(psignal);

		pretdata = (L1_PARAMS *)psignal->get_data_buf();

		new (pretdata) L1_PARAMS();

		pretdata->thr_num_ 	= n;
		pretdata->thr_type_	= TTYPE_L1;
		parray			= pl1_arr_ + pretdata->thr_num_;

		do {
			try {
				pthr = new GY_THREAD("Level 1 handler", l1lam, nullptr, this, psignal, true, 1024 * 1024);
			}
			GY_CATCH_EXCEPTION(
				if (++nretry < 4) {
					ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to start L1 thread %s : Retrying after 3 sec", GY_GET_EXCEPT_STRING);
					gy_nanosleep(3, 0);
				}
			);
		} 
		while (!pthr && nretry < 4);

		if (!pthr) {
			ERRORPRINTCOLOR(GY_COLOR_RED, "Too many thread spawn failures. Exiting...\n\n");
			exit(EXIT_FAILURE);
		}	

		// Now wait
		psignal->dispatch_wait(retdata, sz1, respcode);

		pretdata = (L1_PARAMS *)retdata;

		if (respcode != 0) {
			pretdata->descbuf_[sizeof(pretdata->descbuf_) - 1] = '\0';
			ERRORPRINTCOLOR(GY_COLOR_RED, "Level 1 thread returned error %s (%d). Exiting...\n\n", pretdata->descbuf_, respcode);
			exit(EXIT_FAILURE);
		}	

		assert(pretdata->epollfd_ > 0);

		if (!(pretdata->epollfd_ > 0 && pretdata->pthread_ == pthr)) {
			ERRORPRINTCOLOR(GY_COLOR_RED, "Internal error : Level 1 thread returned invalid parameters. Exiting...\n\n");
			exit(EXIT_FAILURE);
		}	

		*parray = *pretdata;
	}	

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "All Level 1 threads spawned successfully. Now spawning Level 2 Handler threads...\n");

	/*
	 * Now spawn the Level 2 MPMC handler threads
	 */
	auto l2lam = [](void *arg) -> void *
	{
		GY_THREAD	*pthr = (GY_THREAD *)arg;
		SHCONN_HANDLER	*pthis = (SHCONN_HANDLER *)pthr->get_opt_arg1();

		MAKE_PTHREAD_WRAP("Level 2 Handler", pthis->handle_l2(pthr));

		return nullptr;
	};

	for (uint32_t n = 0; n < MAX_L2_THREADS; ++n) {	
		GY_THREAD		*pthr = nullptr;	
		auto 			psignal = MULTI_COMM_SINGLETON::get_single_512()->get_proc_buf();
		int			nretry = 0, respcode;
		uint8_t			retdata[MULTI_COMM_SINGLETON::SINGLE_PROC_SZ_512::get_max_data_len()];	
		L2_PARAMS		*pretdata, *parray;
		size_t			sz1;
		MPMCQ_COMM		*pmq;
		
		assert(psignal);

		pretdata = (L2_PARAMS *)psignal->get_data_buf();

		new (pretdata) L2_PARAMS();
		
		if (n < MAX_L2_DB_THREADS) {
			pretdata->thr_num_ 	= n;
			pretdata->thr_type_ 	= TTYPE_L2_DB;
			pretdata->pmpmc_	= ppmpmc_db_arr_[pretdata->thr_num_ % MAX_L2_DB_POOLS];

			parray			= pl2_db_arr_ + pretdata->thr_num_;
		}
		else if (n < MAX_L2_DB_THREADS + MAX_L2_MISC_THREADS) {
			pretdata->thr_num_ 	= n - MAX_L2_DB_THREADS;
			pretdata->thr_type_ 	= TTYPE_L2_MISC;
			pretdata->pmpmc_	= ppmpmc_misc_arr_[pretdata->thr_num_ % MAX_L2_MISC_POOLS];

			parray			= pl2_misc_arr_ + pretdata->thr_num_;
		}
		else {
			pretdata->thr_num_ 	= n - MAX_L2_DB_THREADS - MAX_L2_MISC_THREADS;
			pretdata->thr_type_ 	= TTYPE_L2_ALERT;
			pretdata->pmpmc_	= ppmpmc_alert_arr_[pretdata->thr_num_ % MAX_L2_ALERT_POOLS];

			parray			= pl2_alert_arr_ + pretdata->thr_num_;
		}	

		do {
			try {
				pthr = new GY_THREAD("Level 2 handler", l2lam, nullptr, this, psignal, true, 2 * 1024 * 1024 /* 2 MB Stack Size */);
			}
			GY_CATCH_EXCEPTION(
				if (++nretry < 4) {
					ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to start L2 thread %s : Retrying after 3 sec", GY_GET_EXCEPT_STRING);
					gy_nanosleep(3, 0);
				}
			);
		} 
		while (!pthr && nretry < 4);

		if (!pthr) {
			ERRORPRINTCOLOR(GY_COLOR_RED, "Too many thread spawn failures. Exiting...\n\n");
			exit(EXIT_FAILURE);
		}	

		// Now wait
		psignal->dispatch_wait(retdata, sz1, respcode);

		pretdata = (L2_PARAMS *)retdata;

		if (respcode != 0) {
			pretdata->descbuf_[sizeof(pretdata->descbuf_) - 1] = '\0';
			ERRORPRINTCOLOR(GY_COLOR_RED, "Level 2 thread returned error %s (%d). Exiting...\n\n", pretdata->descbuf_, respcode);
			exit(EXIT_FAILURE);
		}	

		if (!(pretdata->pthread_ == pthr)) {
			ERRORPRINTCOLOR(GY_COLOR_RED, "Internal error : Level 2 thread returned invalid parameters. Exiting...\n\n");
			exit(EXIT_FAILURE);
		}	

		*parray = *pretdata;
	}	

	all_spawned_.store(true);
	
	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "All threads spawned successfully. Now signalling the threads to start processing...\n");

	bool		bret;

	// Now check if all threads have received the signal and started
	auto lamchk = [this]() noexcept -> bool
	{
		auto bacc 	= nblocked_acc_.load(mo_relaxed);
		auto bl1 	= nblocked_l1_.load(mo_relaxed);
		auto bl2 	= nblocked_l2_.load(mo_relaxed);

		if (bacc + bl1 + bl2 > 0) {
			return true;
		}	
		return false;
	};	
	
	do {
		gy_msecsleep(100);
		bret = barcond_.cond_broadcast(lamchk);
	} while (bret == true);
	
	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "All threads signalled successfully : Listener is now active. Clients can connect now...\n");
}	

int SHCONN_HANDLER::handle_accept(GY_THREAD *pthr)
{
	LISTEN_SOCK			**pplsock;
	uint32_t			acc_thr_num = 0;
	int				listensockarr[MAX_TCP_LISTENERS], tepollfd, ttimerfd;
	const int			nlsock = listen_host_vec_.size();
	ACC_PARAMS			param;
	const pid_t			tid = gy_gettid();
	
	{
		int				retsig = -1;
		S512_PROC_ELEM			*psignal = (decltype(psignal))pthr->get_opt_arg2();	

		assert(psignal);

		ACC_PARAMS			*psigdata = (ACC_PARAMS *)psignal->get_data_buf();

		acc_thr_num = psigdata->thr_num_;

		snprintf(psigdata->descbuf_, sizeof(psigdata->descbuf_), "Accept Thread %u : TID %d", acc_thr_num, tid);

		GY_SCOPE_EXIT {
			psignal->signal_completion(retsig, sizeof(ACC_PARAMS));
		};	

		try {
			pplsock = new LISTEN_SOCK *[nlsock];

			for (int i = 0; i < nlsock; ++i) {
				pplsock[i] = new LISTEN_SOCK(listen_port_vec_[i], listen_host_vec_[i].c_str(), 128, true /* set_nonblock */, true /* reuseaddr */, true /* reuseport */);
				
				listensockarr[i] = pplsock[i]->get_sock();
			}	
		}
		GY_CATCH_EXCEPTION(
			ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to start Listener for %s : %s\n\n", psigdata->descbuf_, GY_GET_EXCEPT_STRING);
			exit(EXIT_FAILURE);
		);

		tepollfd = epoll_create1(EPOLL_CLOEXEC);
		if (tepollfd == -1) {
			PERRORPRINTCOLOR(GY_COLOR_RED, "Failed to create Accept epoll socket for %s", psigdata->descbuf_);
			exit(EXIT_FAILURE);
		}

		ttimerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
		if (ttimerfd == -1) {
			PERRORPRINTCOLOR(GY_COLOR_RED, "Failed to create Accept timerfd for %s", psigdata->descbuf_);
			exit(EXIT_FAILURE);
		}	

		psigdata->pthread_ 	= pthr;
		psigdata->plisten_	= pplsock[0];
		psigdata->listen_fd_	= listensockarr[0];
		psigdata->epollfd_	= tepollfd;

		param			= *psigdata;

		retsig			= 0;
	}

	const int			epollfd = tepollfd, timerfd = ttimerfd;
	
	/*
	 * Now wait for the main thread to signal all other threads have been initialized...
	 */
	bool 				is_inc = false; 

	auto waitcb = [&, this]() noexcept
	{
		if (is_inc == false) {
			nblocked_acc_.fetch_add(1, mo_relaxed);
			is_inc = true;
		}	
		return !all_spawned_.load(mo_relaxed);
	};

	auto waitsuc = [this]() noexcept 
	{
		nblocked_acc_.fetch_sub(1, mo_relaxed);
	};

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Accept Thread %s now waiting for signal...\n", param.descbuf_);

	barcond_.cond_wait(waitcb, waitsuc);

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Accept Thread %s received signal...Now continuing...\n", param.descbuf_);

	try {

		static constexpr int		max_events = 128;
		struct epoll_event		levent, tevent, *pevarr, *pevcache;
		size_t				nconns = 0;
		int				ret;	
		MAP_CONNTRACK			mconntrack;
		uint64_t			curr_usec_clock, last_usec_clock = 0, niter_checks = 0;
		int64_t				last_tcount = 0, curr_tcount = 0;
		struct itimerspec		tspec;
		STATS_STR_MAP			statsmap;
		
		statsmap.reserve(16);

		statsmap["Exception Occurred"] = 0;

		for (int i = 0; i < nlsock; ++i) {
			levent.data.ptr			= (void *)(uintptr_t)listensockarr[i];
			levent.events 			= EPOLLIN | EPOLLRDHUP | EPOLLET;

			ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, listensockarr[i], &levent);
			if (ret == -1) {
				PERRORPRINTCOLOR(GY_COLOR_RED, "Received error while adding listener socket %s to epoll : Exiting...", param.descbuf_);
				exit(EXIT_FAILURE);
			}	
		}

		tspec.it_interval.tv_sec	= 1;
		tspec.it_interval.tv_nsec	= 0;

		tspec.it_value.tv_sec		= 2;
		tspec.it_value.tv_nsec		= 0;

		ret = timerfd_settime(timerfd, 0, &tspec, nullptr);
		if (ret == -1) {
			PERRORPRINTCOLOR(GY_COLOR_RED, "Received error while setting timerfd interval for %s : Exiting...", param.descbuf_);
			exit(EXIT_FAILURE);
		}	

		tevent.data.ptr			= (void *)(uintptr_t)timerfd;
		tevent.events 			= EPOLLIN;

		ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, timerfd, &tevent);
		if (ret == -1) {
			PERRORPRINTCOLOR(GY_COLOR_RED, "Received error while adding timerfd %s to epoll : Exiting...", param.descbuf_);
			exit(EXIT_FAILURE);
		}	

		pevarr 		= new epoll_event[max_events];
		pevcache	= new epoll_event[max_events];

		auto comp_epoll = [](const epoll_event & ev1, const epoll_event & ev2) noexcept -> bool
		{
			return (uint8_t *)ev2.data.ptr < (uint8_t *)ev1.data.ptr;
		};	

		auto check_conn = [&, this](SHCONNTRACK *pnewconn, const int cfd, decltype(mconntrack.find(0)) cit, const bool is_conn_closed) noexcept
		{
			try {
				ssize_t 		nb;
				alignas(8) uint8_t	tbuf[sizeof(COMM_HEADER)];
				struct epoll_event	ev;
				bool			bret;
				L1_PARAMS		*pl1;	
				int			iret;

				/*
				 * XXX Currently we do not forward connections to L1 which just send some data and immediately close the 
				 * conn or close the reader half without waiting for response back 
				 *
				 * Change the handling below if thats needed
				 */
				if (gy_unlikely(is_conn_closed)) {
					statsmap["Conn Closed at Start"]++;
					mconntrack.erase(cit);
					return;
				}	

				nb = sock_peek_recv_data(cfd, tbuf, sizeof(COMM_HEADER), true);
				if (nb > 0) {
					if (nb == sizeof(COMM_HEADER)) {
						COMM_HEADER		*phdr = reinterpret_cast<COMM_HEADER *>(tbuf);

						if (false == phdr->is_valid_register_req()) {
							statsmap["Dropping Connection for Proto Request"]++;
							mconntrack.erase(cit);
							return;
						}	
						
						if (true == phdr->is_node_action()) {
							static_assert(sizeof(COMM_HEADER) + sizeof(NS_REGISTER_REQ_S) < 1024, 
									"Please change the logic below as it assumes data available at one go");

							alignas(8) uint8_t		actregbuf[1024];
							ssize_t				sret;

							sret = ::recv(cfd, actregbuf, sizeof(actregbuf), MSG_DONTWAIT);
							if (sret == sizeof(COMM_HEADER) + sizeof(NS_REGISTER_REQ_S)) {

								statsmap["Node Action Connection"]++;
								
								// Release the sock as it will be now handled by Alertmgr
								pnewconn->release_sock();

								palertmgr_->add_node_action_sock(cfd, actregbuf, sret);
							}	
							else {
								statsmap["Dropping by Node Action Payload"]++;
							}	

							mconntrack.erase(cit);
							return;
						}	

						if (true == phdr->is_adhoc()) {
							statsmap["Adhoc Connection"]++;
							pnewconn->set_adhoc_conn(true);
						}	
						else {
							statsmap["Persistent Connection"]++;
						}	

						pnewconn->set_comm_magic(phdr->magic_);
					}
					else {
						if (false == COMM_HEADER::is_valid_header_byte(tbuf[0])) {
							statsmap["Invalid Proto Bytes"]++;
							mconntrack.erase(cit);
							return;
						}	
						
						// Wait for further data. If idle timeout occurs will be automatically closed
						return;
					}	

					/*
					 * We need to signal the L1 thread using its epoll and EPOLLOUT. Also 
					 * remove this fd from the accept epoll
					 */
					ACC_NOTIFY_ONE		acc (std::move(mconntrack.extract(cit)), pnewconn->start_clock_usec_, pnewconn->sockfd_);
					int			ntries = 0;

					epoll_ctl(epollfd, EPOLL_CTL_DEL, cfd, nullptr);

					pl1 = pl1_arr_ + (nconns++ % MAX_L1_THREADS);

					/*
					 * Now signal the L1 thread using pl1->psignalq_ and pl1->signal_fd_
					 */
					do { 
						bret = pl1->psignalq_->write(std::move(acc));
					} while (bret == false && ntries++ < 10);

					if (bret == false) {
						statsmap["Connection Drop as L1 Blocked"]++;
						// acc destructor will close the conn
						return;
					}
					
					// ::write() will act as the memory barrier...

					int64_t			n = 1;

					iret = ::write(pl1->signal_fd_, &n, sizeof(int64_t));
					if (iret == sizeof(int64_t)) {
						return;
					}	
					return;
				}	
				else if (nb == 0) {
					return;
				}
				else {
					mconntrack.erase(cit);
				}	
			}
			GY_CATCH_EXCEPTION(
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Caught exception while handling new accept conn : %s\n", GY_GET_EXCEPT_STRING);
				mconntrack.erase(cit);
			);
		};	

		auto fd_listen_data = [&](void *pepdata) noexcept -> int
		{
			for (int i = 0; i < nlsock; ++i) {
				if (pepdata == (void *)(uintptr_t)listensockarr[i]) {
					return listensockarr[i];
				}
			}	

			if (pepdata == (void *)(uintptr_t)timerfd) {
				return timerfd;
			}	

			return -1;
		};

		curr_usec_clock		= get_usec_clock();

		do {
			try {
				int			nevents;
				size_t			nfind;

				// No RCU Offline needed in this thread

				nevents = epoll_wait(epollfd, pevarr, max_events, -1);
				
				if (nevents == -1) {
					if (errno == EINTR) {
						continue;
					}	
					PERRORPRINTCOLOR(GY_COLOR_RED, "poll on %s failed : Exiting...", param.descbuf_);
					exit(EXIT_FAILURE);
				}	

				std::memcpy(pevcache, pevarr, nevents * sizeof(epoll_event));

				std::sort(pevcache,  pevcache + nevents, comp_epoll);

				for (int i = 0; i < nevents; ++i) {
					auto 			pcache = pevcache + i;
					int			cfd, lsock;
					void			*pepdata = pcache->data.ptr;
					uint32_t		cevents = 0;
					SHCONNTRACK		*pconn = nullptr;

					lsock = fd_listen_data(pepdata);

					if (-1 == lsock) {
						cevents = pcache->events;

						while (i + 1 < nevents) {
							if (pevcache[i + 1].data.ptr == pepdata) {
								cevents |= pevcache[i + 1].events;
								++i;
							}	
							else {
								break;
							}	
						}	

						pconn = (SHCONNTRACK *)pepdata;

						cfd = pconn->get_sockfd();

						auto it = mconntrack.find(cfd);
						if (it != mconntrack.end()) {
							// This condition should always be true
							check_conn(pconn, pconn->get_sockfd(), it, (cevents & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)));
						}
					}	
					else if (lsock != timerfd) {
						// From one of the listener sockets

						while (mconntrack.size() < MAX_CONCURRENT_ACCEPT_CONNS) {
							struct sockaddr_storage		saddr;
							socklen_t			slen = sizeof(saddr);
tagain :						
							cfd = ::accept4(lsock, (sockaddr *)&saddr, &slen, SOCK_NONBLOCK | SOCK_CLOEXEC);

							if (cfd == -1) {
								if (errno == EAGAIN) {
									break;
								}	
								else if (errno == EINTR) {
									goto tagain;
								}	
								else if ((errno == ECONNABORTED) || (errno == EAGAIN) || (errno == ENOBUFS) || (errno == ENOMEM) || (errno == EPERM)) {
									DEBUGEXECN(1, PERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Accept failed"); );
									statsmap["Accept Failed"]++;
									continue;
								}	
								else if (errno == EMFILE) {
									PERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Accept failed due to process open files"); 
									continue;
								}	
								else {
									PERRORPRINTCOLOR(GY_COLOR_RED, "accept4 on %s failed : Exiting...", param.descbuf_);
									exit(EXIT_FAILURE);
								}
							}	

							try {
								auto 			[it, success] = mconntrack.try_emplace(cfd, nullptr);
								struct epoll_event	ev;

								if (success == true) {
									try {
										it->second = std::make_shared<SHCONNTRACK>(&saddr, cfd, epollfd, nullptr, 
											0, 0, false /* use_pipeline */, MAX_CONN_DATA_TIMEOUT_USEC, MAX_CONN_DATA_TIMEOUT_USEC);
									}
									GY_CATCH_EXCEPTION(
										ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while creating map element for new connection %s\n", 
											GY_GET_EXCEPT_STRING);

										mconntrack.erase(it);
										::close(cfd);
										statsmap["Exception Occurred"]++;
										continue;
									);

									SHCONNTRACK	*pnewconn = it->second.get();

									pnewconn->set_epoll_data(pnewconn);

									ev.data.ptr	= pnewconn;
									ev.events 	= EPOLLIN | EPOLLET;

									ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, cfd, &ev);
									if (ret == 0) {
										// Set TCP_NODELAY and SO_KEEPALIVE
										set_sock_nodelay(cfd);
										set_sock_keepalive(cfd);

										continue;
									}	
									else {
										PERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Accept epoll add failed");
										mconntrack.erase(it);

										continue;
									}	
								}
								else {
									if (it != mconntrack.end()) {
										mconntrack.erase(it);
									}	
									else {
										close(cfd);
									}
									continue;
								}	
							}
							GY_CATCH_EXCEPTION(
								ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while accepting new connection %s\n", GY_GET_EXCEPT_STRING);
								close(cfd);
								statsmap["Exception Occurred"]++;
								continue;
							);
						} // accept4 loop
					}
					else {
						uint64_t	tt;

						ret = ::read(timerfd, &tt, sizeof(uint64_t));
					}	
				}	
				
				curr_usec_clock = get_usec_clock();

				if (curr_usec_clock - last_usec_clock > MAX_CONN_DATA_TIMEOUT_USEC/2) {
					niter_checks++;

					last_usec_clock	= curr_usec_clock;

					for (auto it = mconntrack.begin(); it != mconntrack.end(); ) {
						auto pconn1 = it->second.get();

						if (pconn1 && ((true == pconn1->is_idle_timedout(curr_usec_clock)))) {

							INFOPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Closing %s due to idle timeout from %s\n",
								pconn1->print_conn(STRING_BUFFER<512>().get_str_buf()), param.descbuf_);

							statsmap["Idle Timeout"]++;
							it = mconntrack.erase(it);
						}	
						else {
							++it;
						}	
					}		

					if (niter_checks == 10) {
						niter_checks = 0;

						STRING_BUFFER<1024>	strbuf;

						for (auto && it : statsmap) {
							strbuf.appendfmt(" {\"%s\" : %ld},", it.first, it.second);
						}	
						strbuf.set_last_char(' ');

						INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "%s : Connections %lu (of Total %lu) : Stats : [ %.*s ]\n", 
								param.descbuf_, mconntrack.size(), gtconncount.load(mo_relaxed), strbuf.sizeint(), strbuf.buffer());
					}
				}	
				
				last_tcount 		= curr_tcount;
				curr_tcount		= mconntrack.size();

				if (curr_tcount - last_tcount != 0) {
					gtconncount.fetch_add(curr_tcount - last_tcount, mo_relaxed);
				}	
			}	
			GY_CATCH_EXCEPTION(
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught in %s : %s\n", param.descbuf_, GY_GET_EXCEPT_STRING);
				statsmap["Exception Occurred"]++;
			);
		} while (true);	

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Fatal Exception caught in %s : %s : Exiting...\n\n", param.descbuf_, GY_GET_EXCEPT_STRING);
		exit(EXIT_FAILURE);
	);
}


int SHCONN_HANDLER::handle_l1(GY_THREAD *pthr)
{
	L1_PARAMS			param;
	L1_PARAMS			*pglobparam = nullptr;
	MPMCQ_COMM			*psignalq = nullptr;
	uint32_t			tl1_thr_num;
	int				tepollfd, tsignalfd, ttimerfd;
	const pid_t			tid = gy_gettid();
	POOL_ALLOC_ARRAY		poolarr;

	{
		int				retsig = -1, spair[2], ret;
		S512_PROC_ELEM			*psignal = (decltype(psignal))pthr->get_opt_arg2();	

		assert(psignal);

		L1_PARAMS			*psigdata = (L1_PARAMS *)psignal->get_data_buf();

		tl1_thr_num = psigdata->thr_num_;

		snprintf(psigdata->descbuf_, sizeof(psigdata->descbuf_), "Level 1 Thread %u TID %d", tl1_thr_num, tid);

		pglobparam = pl1_arr_ + tl1_thr_num;

		GY_SCOPE_EXIT {
			psignal->signal_completion(retsig, sizeof(L1_PARAMS));
		};	

		tepollfd = epoll_create1(EPOLL_CLOEXEC);
		if (tepollfd == -1) {
			PERRORPRINTCOLOR(GY_COLOR_RED, "Failed to create Level 1 epoll socket for %s", psigdata->descbuf_);
			exit(EXIT_FAILURE);
		}

		tsignalfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
		if (tsignalfd == -1) {
			PERRORPRINTCOLOR(GY_COLOR_RED, "Failed to create Level 1 eventfd for %s", psigdata->descbuf_);
			exit(EXIT_FAILURE);
		}	
	
		ttimerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
		if (ttimerfd == -1) {
			PERRORPRINTCOLOR(GY_COLOR_RED, "Failed to create Level 1 timerfd for %s", psigdata->descbuf_);
			exit(EXIT_FAILURE);
		}	

		try {
			psignalq = new MPMCQ_COMM(MAX_MPMC_ELEMS);
		}
		GY_CATCH_EXCEPTION(
			ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to create Level 1 signal queue for %s : %s\n", psigdata->descbuf_, GY_GET_EXCEPT_STRING);
			exit(EXIT_FAILURE);
		);

		try {
			size_t			pool_szarr[8], pool_maxarr[8], npoolarr = 0;
			
			pool_szarr[0] 	= 32767;
			pool_maxarr[0]	= 128;
			
			pool_szarr[1]	= 4096;
			pool_maxarr[1]	= 2048;

			pool_szarr[2] 	= 512;
			pool_maxarr[2]	= 4096;

			pool_szarr[3]	= 256;
			pool_maxarr[3]	= 2048;

			npoolarr 	= 4;

			poolarr.pool_alloc(pool_szarr, pool_maxarr, npoolarr, true);
		}
		GY_CATCH_EXCEPTION(
			ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to create Level 1 memory pool for %s : %s\n", psigdata->descbuf_, GY_GET_EXCEPT_STRING);
			exit(EXIT_FAILURE);
		);
	
		psigdata->pthread_ 	= pthr;
		psigdata->psignalq_	= psignalq;
		psigdata->epollfd_	= tepollfd;
		psigdata->signal_fd_	= tsignalfd;

		param			= *psigdata;

		retsig			= 0;
	}

	/*
	 * Now wait for the main thread to signal all other threads have been initialized...
	 */
	bool 				is_inc = false; 

	auto waitcb = [&, this]() noexcept
	{
		if (is_inc == false) {
			nblocked_l1_.fetch_add(1, mo_relaxed);
			is_inc = true;
		}	
		return !all_spawned_.load(mo_relaxed);
	};

	auto waitsuc = [this]() noexcept 
	{
		nblocked_l1_.fetch_sub(1, mo_relaxed);
	};

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "%s now waiting for signal...\n", param.descbuf_);

	barcond_.cond_wait(waitcb, waitsuc);

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "%s received signal...Now continuing...\n", param.descbuf_);

	try {
		const int			epollfd = tepollfd, signalfd = tsignalfd, timerfd = ttimerfd;
		const uint32_t			l1_thr_num = tl1_thr_num;
		static constexpr int		max_events = 128, max_retry_events = 32, max_signals_no_read = 256;

		struct epoll_event		levent, tevent, *pevarr, *pevcache, *pevretry;
		size_t				nconns = 0;
		int				ret, tpoolcnt = 0;	
		MAP_CONNTRACK			mconntrack;
		uint64_t			curr_usec_clock, last_usec_clock = 0, niter_checks = 0;
		int64_t				last_tcount = 0, curr_tcount = 0, nsignals_seen = 0;
		STATS_STR_MAP			statsmap;

		statsmap.reserve(32);
		statsmap["Exception Occurred"] = 0;

		levent.data.ptr	= (void *)(uintptr_t)signalfd;
		levent.events 	= EPOLLIN | EPOLLET;

		ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, signalfd, &levent);
		if (ret == -1) {
			PERRORPRINTCOLOR(GY_COLOR_RED, "Received error while adding L1 eventfd %s to poll : Exiting...", param.descbuf_);
			exit(EXIT_FAILURE);
		}	

		if (true) {
			struct itimerspec		tspec;

			tspec.it_interval.tv_sec	= 1;
			tspec.it_interval.tv_nsec	= 0;

			tspec.it_value.tv_sec		= 2;
			tspec.it_value.tv_nsec		= 0;

			ret = timerfd_settime(timerfd, 0, &tspec, nullptr);
			if (ret == -1) {
				PERRORPRINTCOLOR(GY_COLOR_RED, "Received error while setting timerfd interval for %s : Exiting...", param.descbuf_);
				exit(EXIT_FAILURE);
			}	
		}

		tevent.data.ptr			= (void *)(uintptr_t)timerfd;
		tevent.events 			= EPOLLIN;

		ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, timerfd, &tevent);
		if (ret == -1) {
			PERRORPRINTCOLOR(GY_COLOR_RED, "Received error while adding timerfd %s to epoll : Exiting...", param.descbuf_);
			exit(EXIT_FAILURE);
		}	

		pevarr 		= new epoll_event[max_events];
		pevcache	= new epoll_event[max_events];

		auto comp_epoll = [](const epoll_event & ev1, const epoll_event & ev2) noexcept -> bool
		{
			// NOTE : Please keep this as a < operation as we need to ensure signalfd is handled first
			return (uint8_t *)ev2.data.ptr < (uint8_t *)ev1.data.ptr;
		};	

		/*
		 * Currently max_syscall is ignored TODO
		 */
		auto handle_recv = [&, this](SHCONNTRACK *pconn1, int sock, const bool is_conn_closed, const bool peer_wr_closed, int max_syscall = INT_MAX - 1) -> ssize_t
		{
			ssize_t				sret, max_bytes, totbytes = 0;
			ssize_t				max_buf_sz, data_sz;
			uint8_t				*prdbuf;
			int				nsyscall = 0, ret;
			auto				&rdstat_ = pconn1->rdstat_;
			bool				is_again = false, bret, bsent, is_pendrecv = (rdstat_.pending_sz_ > 0);
			COMM_HEADER			hdr(COMM_MIN_TYPE, 0, COMM_HEADER::INV_HDR_MAGIC);

			DB_WRITE_ARR			dbarr(pconn1->get_comm_magic());

			GY_SCOPE_EXIT {
				if (dbarr.pbufstart_ && dbarr.free_fp_ && rdstat_.pdirbuf_ == dbarr.pbufstart_) {
					dbarr.reset();
				}	
			};

			auto set_variables = [&]() 
			{
				max_buf_sz 	= rdstat_.max_buf_sz_;
				data_sz		= rdstat_.data_sz_;
				prdbuf		= rdstat_.pdirbuf_;
			};

			auto schedule_db_array = [&](uint8_t *pwrbuf, uint32_t wrlen, COMM_TYPE_E data_type, TTYPE_E dest_thr_type, bool is_json_resp = false) 
			{
				if (gy_unlikely(dbarr.ndbs_ >= GY_ARRAY_SIZE(dbarr.dbonearr_))) {
					statsmap["Internal L1 Error"]++; 
					GY_THROW_EXCEPTION("Internal Error : dbarr stats invalid %u", __LINE__);
				}

				// For TTYPE_L2_DB have a diff thread handle each req
				if (dest_thr_type != dbarr.dest_thr_type_ || dest_thr_type == TTYPE_L2_DB) {
					if (dbarr.ndbs_ > 0) {
						FREE_FPTR		free_fp;
						uint32_t		act_size, maxcopy = std::max<uint32_t>(wrlen, data_sz);
						uint8_t			*palloc = (uint8_t *)poolarr.safe_malloc(std::max<uint32_t>(4096u, maxcopy), free_fp, act_size);

						std::memcpy(palloc, pwrbuf, maxcopy);

						send_db_array(std::move(dbarr), l1_thr_num, statsmap, is_json_resp);
						rdstat_.reset_buf(false);

						rdstat_.set_buf(palloc, free_fp, act_size, maxcopy);
						
						set_variables();
					}	
				}

				dbarr.dbonearr_[dbarr.ndbs_] = {pwrbuf, wrlen, data_type};

				if (dbarr.ndbs_ == 0) {
					dbarr.pl1_src_		= pglobparam;
					dbarr.start_clock_usec_	= get_usec_clock();
					dbarr.shrconn_		= pconn1->shared_from_this();
					dbarr.pbufstart_	= rdstat_.pdirbuf_;
					dbarr.free_fp_		= rdstat_.get_dirbuf_freeptr();
					dbarr.dest_thr_type_	= dest_thr_type;
				}	
				
				dbarr.ndbs_++;
			};	

			if (!rdstat_.pdirbuf_) {
				FREE_FPTR		free_fp;
				uint32_t		act_size;
				void			*palloc = poolarr.safe_malloc(4096u, free_fp, act_size);

				rdstat_.set_buf((uint8_t *)palloc, free_fp, act_size, 0);
			}	

			do {
				set_variables();

				max_bytes = max_buf_sz - data_sz;

				if (gy_unlikely(max_bytes <= 0)) {
					statsmap["Internal L1 Error"]++; 
					GY_THROW_EXCEPTION("Internal Error : max_bytes <= 0");
				}	

				sret = ::recv(sock, prdbuf + data_sz, max_bytes, 0);

				if (sret == -1) {
					if (errno == EINTR) {
						continue;
					}
					else if (errno == EAGAIN) {
						break;
					}	
					else {
						if (dbarr.ndbs_ > 0 && dbarr.dest_thr_type_ != TTYPE_L2_DB) {
							send_db_array(std::move(dbarr), l1_thr_num, statsmap);
						}

						return -1;
					}
				}
				else if (sret == 0) {
					if (dbarr.ndbs_ > 0 && dbarr.dest_thr_type_ != TTYPE_L2_DB) {
						send_db_array(std::move(dbarr), l1_thr_num, statsmap);
					}
					return -1;
				}	

				is_again 			= (sret < max_bytes);

				if (is_pendrecv) {
					is_pendrecv = !pconn1->pending_recv_seen(sret);
				}	

				nsyscall++;

				rdstat_.last_oper_cusec_ 	= get_usec_clock();
				rdstat_.nbytes_seen_ 		+= sret;
				rdstat_.data_sz_		+= sret;
			
				totbytes			+= sret;	
				data_sz				+= sret;

				do {
					if (data_sz >= (ssize_t)sizeof(COMM_HEADER)) {
						std::memcpy(&hdr, prdbuf, sizeof(hdr));

						if (false == hdr.validate(prdbuf, pconn1->get_comm_magic())) {
							statsmap["Invalid Message Error"]++; 
							GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
						}	
					}
					else {
						hdr.total_sz_ = sizeof(COMM_HEADER);
					}

					if ((data_sz < hdr.total_sz_ && dbarr.ndbs_ > 0) || (max_buf_sz < (ssize_t)hdr.total_sz_)) {

						FREE_FPTR		free_fp;
						uint32_t		act_size;
						uint8_t			*palloc = (uint8_t *)poolarr.safe_malloc(std::max(4096u, std::max<uint32_t>(hdr.total_sz_, data_sz)), free_fp, act_size);

						std::memcpy(palloc, prdbuf, data_sz);

						if (dbarr.ndbs_ > 0) {
							send_db_array(std::move(dbarr), l1_thr_num, statsmap);
							rdstat_.reset_buf(false);
						}
						else {
							rdstat_.reset_buf(true);
						}	

						rdstat_.set_buf(palloc, free_fp, act_size, data_sz);
						
						set_variables();
					}
			
					if (data_sz < hdr.total_sz_) {
						if (data_sz != rdstat_.data_sz_) {
							// This implies dbarr.ndbs_ == 0 and we just need to move data to the start

							std::memmove(rdstat_.pdirbuf_, prdbuf, data_sz);
							rdstat_.data_sz_	= data_sz;

							set_variables();
						}	
						break;
					}

					rdstat_.nrequests_++;

					switch (hdr.data_type_) {
				

					case COMM_EVENT_NOTIFY :
						if (true) {
							EVENT_NOTIFY		*pevtnot = (EVENT_NOTIFY *)(prdbuf + sizeof(COMM_HEADER));

							switch (pevtnot->subtype_) {
							
							case NOTIFY_MS_TCP_CONN :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_MADHAVA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									MS_TCP_CONN_NOTIFY	*pconn = (MS_TCP_CONN_NOTIFY *)(pevtnot + 1);

									bret = pconn->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;

							case NOTIFY_MS_TCP_CONN_CLOSE :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_MADHAVA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									MS_TCP_CONN_CLOSE 	*pconn = (MS_TCP_CONN_CLOSE *)(pevtnot + 1);

									bret = pconn->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;

							case NOTIFY_NAT_TCP :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_MADHAVA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									NAT_TCP_NOTIFY	 	*pnat = (NAT_TCP_NOTIFY *)(pevtnot + 1);

									bret = pnat->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;

							case NOTIFY_MS_CLUSTER_STATE :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_MADHAVA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									auto	 	*pconn = (MS_CLUSTER_STATE *)(pevtnot + 1);

									bret = pconn->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;


							case NOTIFY_MS_PARTHA_PING :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_MADHAVA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									auto	 	*pconn = (MS_PARTHA_PING *)(pevtnot + 1);

									bret = pconn->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									// Schedule to DB Thread
									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_DB);
								}

								break;


							case NOTIFY_MS_SVC_CLUSTER_MESH :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_MADHAVA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									auto	 	*pconn = (MS_SVC_CLUSTER_MESH *)(pevtnot + 1);

									bret = pconn->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;


							case NOTIFY_MS_LISTENER_NAT_IP :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_MADHAVA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									auto	 	*pconn = (MS_LISTENER_NAT_IP *)(pevtnot + 1);

									bret = pconn->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;

							case NOTIFY_MS_REG_PARTHA :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_MADHAVA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									auto	 	*pconn = (MS_REG_PARTHA *)(pevtnot + 1);

									bret = pconn->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;


							case NOTIFY_ALERT_STAT_INFO :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_MADHAVA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									auto	 	*pstat = (ALERT_STAT_INFO *)(pevtnot + 1);

									bret = pstat->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_ALERT);
								}

								break;


							case NOTIFY_ALERT_STAT_CLOSE :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_MADHAVA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									auto	 	*pstat = (ALERT_STAT_CLOSE *)(pevtnot + 1);

									bret = pstat->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_ALERT);
								}

								break;



							case NOTIFY_MADHAVA_SHYAMA_STATUS :
								// nevents_ is always 1	
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_MADHAVA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									MADHAVA_SHYAMA_STATUS 	*preq = (MADHAVA_SHYAMA_STATUS *)(pevtnot + 1);

									bret = preq->validate(&hdr);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									auto pmadhava = pconn1->madhava_shr_.get();

									if (pmadhava && preq->madhava_id_ == pmadhava->madhava_id_) {
										pmadhava->last_status_tsec_ 	= get_sec_time();
										pmadhava->last_status_csec_ 	= get_sec_clock();
										pmadhava->npartha_nodes_.store(preq->npartha_nodes_, mo_relaxed);
										pmadhava->approx_partha_conns_	= preq->approx_partha_conns_;
									}	

									// No response needs to be sent
								}

								break;

							case NOTIFY_PING_CONN :

								if (!pconn1->is_registered()) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}

								break;

							default :
								break;
							}
						}
						break;


					case COMM_QUERY_CMD :

						if (false == is_conn_closed && pconn1->cli_type_ != comm::CLI_TYPE_REQ_ONLY) {
							QUERY_CMD		*pquery = (QUERY_CMD *)(prdbuf + sizeof(COMM_HEADER));

							switch (pquery->subtype_) {

							case QUERY_PARTHA_MADHAVA :
								if (true) {
									statsmap["Partha Madhava Lookup Query"]++;

									PARTHA_MADHAVA_REQ 	*preq = (PARTHA_MADHAVA_REQ *)((char *)pquery + sizeof(QUERY_CMD));

									bret = preq->validate(&hdr);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									// XXX Currently not handled
									/*lookup_partha_madhava(pconn1, prdbuf, pquery, preq);*/
								}
								break;
							
	
							case QUERY_WEB_JSON :
							case CRUD_GENERIC_JSON :

								if (!pconn1->is_registered()) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_DB, true /* is_json_resp */);
								}			
								break;

							case CRUD_ALERT_JSON :

								if (!pconn1->is_registered()) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_ALERT, true /* is_json_resp */);
								}			
								break;

							default :
								break;
							}	
						}
						break;

					case PS_REGISTER_REQ :
						if (true) {
							statsmap["Partha Register Req"]++;

							if (pconn1->is_registered()) {
								statsmap["Invalid Message Error"]++; 
								GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
							}	

							PS_REGISTER_REQ_S 		*preg = (PS_REGISTER_REQ_S *)(prdbuf + sizeof(COMM_HEADER));
							char				ebuf[COMM_MAX_ERROR_LEN];
							ERR_CODES_E			errcode;

							bret = preg->validate(&hdr);
							if (bret == false) {
								statsmap["Invalid Message Error"]++; 
								return -1;
							}

							bret = preg->validate_fields(gmin_partha_version, gversion_num, ebuf, errcode);
							if (bret == false) {
								statsmap["Partha Registration Fail"]++;
								send_register_connect_error<PS_REGISTER_RESP_S, PS_REGISTER_RESP>(pconn1, errcode, ebuf, &poolarr);

								ERRORPRINT_OFFLOAD("Partha Registration for Machine ID %016lx%016lx from %s host %s Failed due to %s\n", 
									preg->machine_id_hi_, preg->machine_id_lo_, 
									pconn1->print_peer(STRING_BUFFER<128>().get_str_buf()), preg->hostname_, ebuf);
								return -1;
							}	

							schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
							
							bret = send_db_array(std::move(dbarr), l1_thr_num, statsmap);
							rdstat_.reset_buf(false);

							if (bret == true) {
								break;
							}	
							
							statsmap["Partha Registration Blocking Fail"]++;

							send_register_connect_error<PS_REGISTER_RESP_S, PS_REGISTER_RESP>(pconn1, ERR_BLOCKING_ERROR, 
									"Failed to process Registration due to too many requests", &poolarr);

							ERRORPRINT_OFFLOAD("Partha Registration for Machine ID %016lx%016lx from %s Failed "
								"due to failure to forward registration to handler as too many requests pending\n", 
								preg->machine_id_hi_, preg->machine_id_lo_, pconn1->print_peer(STRING_BUFFER<128>().get_str_buf()));

							return -1;
						}
						break;

					case MS_REGISTER_REQ :
						if (true) {
							statsmap["Madhava Register Req"]++;

							if (pconn1->is_registered()) {
								statsmap["Invalid Message Error"]++; 
								GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
							}	

							MS_REGISTER_REQ_S 		*preg = (MS_REGISTER_REQ_S *)(prdbuf + sizeof(COMM_HEADER));
							char				ebuf[COMM_MAX_ERROR_LEN];
							ERR_CODES_E			errcode;

							bret = preg->validate(&hdr); 
							if (bret == false) {
								statsmap["Invalid Message Error"]++; 
								return -1;
							}
							
							bret = preg->validate_fields(gmin_madhava_version, gversion_num, shyama_secret_, ebuf, errcode);
							if (bret == false) {
								statsmap["Madhava Registration Fail"]++;
								if (errcode == ERR_INVALID_SECRET) {
									statsmap["Invalid Shyama Secret"]++;
								}

								send_register_connect_error<MS_REGISTER_RESP_S, MS_REGISTER_RESP>(pconn1, errcode, ebuf, &poolarr);

								ERRORPRINT_OFFLOAD("Madhava Registration for \'%s\' %s port %hu from %s Failed due to %s\n", 
									preg->madhava_name_, preg->madhava_hostname_, preg->madhava_port_, 
									pconn1->print_peer(STRING_BUFFER<128>().get_str_buf()), ebuf);
								return -1;
							}	

							schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);

							bret = send_db_array(std::move(dbarr), l1_thr_num, statsmap);
							rdstat_.reset_buf(false);

							if (bret == true) {
								break;
							}	
							
							statsmap["Madhava Registration Blocking Fail"]++;

							send_register_connect_error<MS_REGISTER_RESP_S, MS_REGISTER_RESP>(pconn1, ERR_BLOCKING_ERROR, 
									"Failed to process Registration due to too many requests", &poolarr);
						
							ERRORPRINT_OFFLOAD("Madhava Registration for %s port %hu from %s Failed "
								"due to failure to forward registration to handler as too many requests pending\n", 
								preg->madhava_hostname_, preg->madhava_port_, pconn1->print_peer(STRING_BUFFER<128>().get_str_buf()));
							return -1;
						}
						break;

					case NS_REGISTER_REQ :
						if (true) {
							statsmap["Node Web Register Req"]++;

							if (pconn1->is_registered()) {
								statsmap["Invalid Message Error"]++; 
								GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
							}	

							NS_REGISTER_REQ_S 		*preg = (NS_REGISTER_REQ_S *)(prdbuf + sizeof(COMM_HEADER));
							char				ebuf[COMM_MAX_ERROR_LEN];
							ERR_CODES_E			errcode;

							bret = preg->validate(&hdr); 
							if (bret == false) {
								statsmap["Invalid Message Error"]++; 
								return -1;
							}
							
							bret = preg->validate_fields(gmin_node_version, gversion_num, ebuf, errcode);
							if (bret == false) {
								statsmap["Node Registration Fail"]++;
								send_register_connect_error<NS_REGISTER_RESP_S, NS_REGISTER_RESP>(pconn1, errcode, ebuf, &poolarr);

								ERRORPRINT_OFFLOAD("Node Registration for %s port %hu from %s Failed due to %s\n", 
									preg->node_hostname_, preg->node_port_, 
									pconn1->print_peer(STRING_BUFFER<128>().get_str_buf()), ebuf);
								return -1;
							}	

							schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);

							bret = send_db_array(std::move(dbarr), l1_thr_num, statsmap);
							rdstat_.reset_buf(false);

							if (bret == true) {
								break;
							}	
							
							statsmap["Node Registration Blocking Fail"]++;

							send_register_connect_error<NS_REGISTER_RESP_S, NS_REGISTER_RESP>(pconn1, ERR_BLOCKING_ERROR, 
									"Failed to process Registration due to too many requests", &poolarr);
						
							ERRORPRINT_OFFLOAD("Node Registration for %s port %hu from %s Failed "
								"due to failure to forward registration to handler as too many requests pending\n", 
								preg->node_hostname_, preg->node_port_, pconn1->print_peer(STRING_BUFFER<128>().get_str_buf()));
							return -1;
						}
						break;
					
					case COMM_QUERY_RESP :
						
						if (true) {
							if (!pconn1->is_registered()) {
								statsmap["Invalid Message Error"]++; 
								GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
							}

							QUERY_RESPONSE		*presp = (QUERY_RESPONSE *)(prdbuf + sizeof(COMM_HEADER));

							bret = presp->validate(&hdr); 
							if (bret == false) {
								statsmap["Invalid Message Error"]++; 
								return -1;
							}

							switch (presp->subtype_) {

							case RESP_NUM_PARTHA :
								if ((presp->respformat_ == RESP_BINARY) && (presp->seqid_ > 0) && (presp->is_resp_complete_)) {
									statsmap["Num Partha Resp"]++;

									NUM_PARTHA_RESP 	*pnum = (NUM_PARTHA_RESP *)((char *)presp + sizeof(QUERY_RESPONSE));

									bret = pnum->validate(&hdr, presp);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									auto cb = pconn1->extract_recv_cb(presp->seqid_);
									if (cb.has_value()) {
										cb->fcb_(pconn1, (uint8_t *)pnum, presp->resp_len_, (uint8_t *)presp, false /* is_expiry */, false /* is_error */);
										statsmap["Async Callback Handled"]++;
									}
									else {
										statsmap["Async Callback Missed"]++;
									}	
								}
								break;

							case RESP_WEB_JSON :
								if ((presp->respformat_ != RESP_BINARY) && (presp->seqid_ > 0)) {
									statsmap["Web JSON Resp"]++;

									if (presp->is_completed()) {
										auto cb = pconn1->extract_recv_cb(presp->seqid_);
										if (cb.has_value()) {
											cb->fcb_(pconn1, (uint8_t *)(presp + 1), presp->resp_len_, (uint8_t *)prdbuf, 
														false /* is_expiry */, false /* is_error */);
											statsmap["Async Callback Handled"]++;
										}
										else {
											statsmap["Async Callback Missed"]++;
										}
									}
									else {
										auto [it, succ] = pconn1->find_recv_cb(presp->seqid_);

										if (succ && bool(it->second.fcb_)) {
											it->second.fcb_(pconn1, (uint8_t *)(presp + 1), presp->resp_len_, (uint8_t *)prdbuf, false /* is_expiry */,
														false /* is_error */);
										}
									}	
								}
								break;

							default :
								break;
							}	
						}	

						break;

					default :
						statsmap["Invalid Message Error"]++; 
						GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
					}

					if (data_sz != 0) {
						data_sz 	-= hdr.total_sz_;
						max_buf_sz	-= hdr.total_sz_;
						prdbuf 		+= hdr.total_sz_;
					}

					if (gy_unlikely(data_sz < 0 || max_buf_sz < data_sz)) {
						statsmap["Internal L1 recv stats error"]++;
						GY_THROW_EXCEPTION("Internal Error : L1 recv stats invalid");
					}

					if ((dbarr.ndbs_ == GY_ARRAY_SIZE(dbarr.dbonearr_)) || (dbarr.ndbs_ > 0 && (max_buf_sz - data_sz < (ssize_t)sizeof(COMM_HEADER)))) {
						uint32_t		act_size = 0;
						void			*palloc = nullptr;
						FREE_FPTR		free_fp;

						if (!is_again || (data_sz > 0) || ((max_buf_sz - data_sz < (ssize_t)sizeof(COMM_HEADER)) && max_buf_sz > 0)) {
							palloc = poolarr.safe_malloc(data_sz > 4096 ? data_sz + 1024 : 4096, free_fp, act_size);

							if (data_sz > 0) {
								std::memcpy(palloc, prdbuf, data_sz);
							}	
						}

						send_db_array(std::move(dbarr), l1_thr_num, statsmap);
						rdstat_.reset_buf(false);

						if (palloc) {
							rdstat_.set_buf((uint8_t *)palloc, free_fp, act_size, data_sz);
							set_variables();
						}	
					}	
					else if ((data_sz != rdstat_.data_sz_) && (max_buf_sz - data_sz < (ssize_t)sizeof(COMM_HEADER))) {
						// This implies dbarr.ndbs_ == 0 and we just need to move data to the start

						std::memmove(rdstat_.pdirbuf_, prdbuf, data_sz);
						rdstat_.data_sz_	= data_sz;

						set_variables();
					}	

				} while (data_sz > 0);

			} while (is_again == false && nsyscall < max_syscall);

			if (dbarr.ndbs_ > 0) {
				FREE_FPTR		free_fp;
				uint32_t		act_size;
				void			*palloc = nullptr;
				
				if (data_sz > 0) {
					palloc = poolarr.safe_malloc(std::max(4096ul, data_sz + 1024ul), free_fp, act_size);
					std::memcpy(palloc, prdbuf, data_sz);
				}

				send_db_array(std::move(dbarr), l1_thr_num, statsmap);
				rdstat_.reset_buf(false);

				if (palloc) {
					rdstat_.set_buf((uint8_t *)palloc, free_fp, act_size, data_sz);
				}
				else {
					rdstat_.reset_buf(true);
				}	
			}
			else if (data_sz == 0) {
				rdstat_.reset_buf(true);	// Free up the buffer
			}	
			else if (totbytes > 0) {
				// Set rdstat_.pending_sz_ for timeout handling
				rdstat_.pending_sz_		= hdr.total_sz_ - data_sz;
				rdstat_.pending_clock_usec_	= rdstat_.last_oper_cusec_;
			}	

			return totbytes;
		};	

		auto handle_notify = [&, this](EV_NOTIFY_ONE & evn) -> bool
		{
			switch (evn.get_type()) {
			
			case NOTIFY_L1_SEND_DATA :
				statsmap["L1 Data Send Notify"]++;

				if (true == evn.data_.l1_data_.is_cli_active() && evn.data_.l1_data_.pconn_) {
					L1_SEND_DATA		& l1data = evn.data_.l1_data_;
					auto			pconn = l1data.pconn_;
					const int		cfd = pconn->get_sockfd();
					ssize_t			sret;
					size_t			ncbs_deleted;

					if (cfd == -1) {
						// Already closed
						return false;
					}	

					try {
						if (l1data.is_async_cb()) {
							statsmap["Add Async Callback"]++;

							pconn->add_async_callback(std::move(*l1data.async_cb_), &ncbs_deleted);
							if (ncbs_deleted) {
								statsmap["Async Callbacks Timed Out"] += ncbs_deleted;
							}	
						}

						sret = send_immediate(pconn, false /* throw_on_error */);

						if ((sret == -1) || (l1data.to_close_conn())) {
							pconn->signal_conn_close();
							mconntrack.erase(cfd);
							return false;
						}

						return true;
					}
					GY_CATCH_EXCEPTION(
						DEBUGEXECN(1,
							INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, 
								"Caught exception while handling L1 send : %s\n", GY_GET_EXCEPT_STRING);
						);	

						pconn->signal_conn_close();
						mconntrack.erase(cfd);
						return false;
					);
				}	
				break;

			case NOTIFY_L1_MISC_CMD :

				if (true) {
					L1_MISC_NOTIFY & lm = evn.data_.l1_misc_;


					switch (lm.misc_type_) {

					case L1_MISC_CLOSE_CONN :

						statsmap["L1 Close Conn Notify"]++;

						if (true == lm.is_cli_active() && lm.pconn_) {
							auto			pconn = lm.pconn_;
							const int		cfd = pconn->get_sockfd();
							ssize_t			sret;

							if (cfd == -1) {
								// Already closed
								return false;
							}	

							try {
								if (lm.errlen_ > 0) {
									pconn->schedule_ext_send(EPOLL_IOVEC_ARR(lm.errstr_, lm.errlen_, nullptr));
									(void)send_immediate(pconn, false /* throw_on_error */);
								}

								pconn->signal_conn_close();
								mconntrack.erase(cfd);
								return true;
							}
							GY_CATCH_EXCEPTION(
								pconn->signal_conn_close();
								mconntrack.erase(cfd);
								return false;
							);
						}	
						
						break;

					default :
						break;
					}
				}
				break;

			case NOTIFY_ACCEPT :
				if (evn.data_.acc_.connnode_) {
					ACC_NOTIFY_ONE		*pacc = &evn.data_.acc_;

					statsmap["Accept Conn Notify"]++;

					try {
						auto			[it, success, node] = mconntrack.insert(std::move(evn.data_.acc_.connnode_));
						struct epoll_event	ev;

						if (success == true) {
							SHCONNTRACK		*pnewconn = it->second.get();

							ev.data.ptr		= pnewconn;
							ev.events 		= EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLET;

							ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, pacc->sockfd_, &ev);
							if (ret == 0) {
								try { 
									auto 			pconn = it->second.get();
									ssize_t			sret;

									pconn->set_epollfd(epollfd);
									pconn->set_max_idle_usec(MAX_CONN_IDLE_TIMEOUT_USEC);
									pconn->set_wr_pipeline();

									pconn->pl1_ = pglobparam;

									/*
									 * Now read the existing data as we may not receive a new EPOLLIN if all data received.
									 */
									sret = handle_recv(pconn, pacc->sockfd_, false, false);
									if (sret == -1) {
										mconntrack.erase(it);
										return false;
									}	
									 
									return true;
								}
								GY_CATCH_EXCEPTION(
									mconntrack.erase(it);
									return false;
								);
							}	
							else {
								PERRORPRINTCOLOR(GY_COLOR_RED, "Level 1 epoll add failed");
								mconntrack.erase(it);
								return false;
							}	
						}
						else {
							// node destructor will cleanup
						}	
					}
					GY_CATCH_EXCEPTION(
						statsmap["Accept Notify Failure"]++;
						ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while adding connection to Level 1 map : %s\n", GY_GET_EXCEPT_STRING);
						return false;
					);
				}
				else {
					return false;
				}
				break;

			default :
				break;
			}	
			return false;
		};	
	
		curr_usec_clock		= get_usec_clock();

		do {
			try {
				int			nevents, nretry_events = 0;
				size_t			nfind;
				bool			bret;

				gy_thread_rcu().gy_rcu_thread_offline();

				nevents = epoll_wait(epollfd, pevarr, max_events, -1);
				
				if (nevents == -1) {
					if (errno == EINTR) {
						continue;
					}	
					PERRORPRINTCOLOR(GY_COLOR_RED, "poll on %s failed : Exiting...", param.descbuf_);
					exit(EXIT_FAILURE);
				}	

				/*
				 * We sort the event cache to ensure 2 things :
				 * 
				 * 1. The set of operations on a specific socket fd are contiguous such as EPOLLIN/OUT and EPOLLHUP
				 * 
				 * 2. To ensure that the signalfd is handled prior to any remote socket as we can ensure that
				 *    async callbacks will be available for scheduled sends from other threads as otherwise
				 *    a race condition could result in a scheduled send and the corresponding recv already handled
				 *    before the async callback could be added to the SHCONNTRACK cb_tbl_ map.
				 */     

				std::memcpy(pevcache, pevarr, nevents * sizeof(epoll_event));

				std::sort(pevcache,  pevcache + nevents, comp_epoll);

				for (int i = 0; i < nevents; ++i) {
					auto 			pcache = pevcache + i;
					void			*pepdata = pcache->data.ptr;
					uint32_t		cevents = 0;

					if (!(pepdata == (void *)(uintptr_t)signalfd || pepdata == (void *)(uintptr_t)timerfd)) {
						cevents = pcache->events;

						while (i + 1 < nevents) {
							if (pevcache[i + 1].data.ptr == pepdata) {
								cevents |= pevcache[i + 1].events;
								++i;
							}	
							else {
								break;
							}	
						}	

						auto pconn = (SHCONNTRACK *)pepdata;
						
						const int cfd = pconn->get_sockfd();

						try {
							const bool		conn_closed = (cevents & (EPOLLERR | EPOLLHUP));
							const bool		peer_wr_closed = (conn_closed || (cevents & EPOLLRDHUP));
							ssize_t			sret = 0;

							if (cevents & EPOLLIN) {
								sret = handle_recv(pconn, cfd, conn_closed, peer_wr_closed);
							}	
							
							if ((sret >= 0) && (cevents & EPOLLOUT) && (false == conn_closed)) {
								if ((false == pconn->is_outgoing_conn()) || (0 != pconn->get_bytes_sent())) {
									sret = send_immediate(pconn, false /* throw_on_error */);
								}	
								else if (pconn->is_outgoing_conn()) {
									// Init connect notification
									sret = pconn->handle_async_connect();
								}	
							}	

							if (sret < 0 || conn_closed) {
								DEBUGEXECN(10,
									INFOPRINTCOLOR_OFFLOAD(GY_COLOR_LIGHT_RED, "Closing %s\n",
										pconn->print_conn(STRING_BUFFER<512>().get_str_buf()));
								);							

								pconn->signal_conn_close();
								mconntrack.erase(cfd);

								continue;
							}	
						}
						GY_CATCH_EXCEPTION(
							DEBUGEXECN(1,
								WARNPRINTCOLOR_OFFLOAD(GY_COLOR_LIGHT_RED, 
									"Caught exception while handling L1 conn : %s\n", GY_GET_EXCEPT_STRING);
							);	

							pconn->signal_conn_close();
							mconntrack.erase(cfd);
							statsmap["Connection Close due to exception"]++;
							
							continue;
						);
					}	
					else if (pepdata == (void *)(uintptr_t)signalfd) {
						if (gy_unlikely(nsignals_seen++ > max_signals_no_read)) {
							uint64_t		n;

							nsignals_seen = 0;
							
							ret = ::read(signalfd, &n, sizeof(uint64_t));
							if (ret != sizeof(uint64_t)) {
								if (errno != EAGAIN) {
									PERRORPRINTCOLOR(GY_COLOR_RED, "Received error while reading L1 eventfd %s : Exiting...", param.descbuf_);
									exit(EXIT_FAILURE);
								}	
							}	
						}	

						do {
							EV_NOTIFY_ONE		evn;

							bret = psignalq->read(evn);
							if (bret) {
								try {
									handle_notify(evn);
								}
								catch(...) {
								};
							}	
						} while (bret == true);	
					}	
					else {
						uint64_t		n;
							
						ret = ::read(timerfd, &n, sizeof(uint64_t));
						if (ret != sizeof(uint64_t)) {
							if (errno != EAGAIN) {
								PERRORPRINTCOLOR(GY_COLOR_RED, "Received error while reading L1 timerfd %s : Exiting...", param.descbuf_);
								exit(EXIT_FAILURE);
							}
						}	
					}	
				}	
				
				curr_usec_clock = get_usec_clock();

				if (curr_usec_clock - last_usec_clock > MAX_CONN_DATA_TIMEOUT_USEC/2) {
					niter_checks++;

					last_usec_clock = curr_usec_clock;

					ssize_t			npendtimeout = 0, nidletimeout = 0;
					time_t			tcurr1 = time(nullptr);

					for (auto it = mconntrack.begin(); it != mconntrack.end(); ) {
						bool		is_pend = false, is_idle = false;

						auto pconn1 = it->second.get();

						if (!pconn1) {
							it = mconntrack.erase(it);
							continue;
						}

						if (true == pconn1->is_pending_timeout(curr_usec_clock)) {
							is_pend = true;
							npendtimeout++;
						}
						else if (true == pconn1->is_idle_timedout(curr_usec_clock)) {
							is_idle = true;
							nidletimeout++;
						}	

						if (is_pend || is_idle) {
							STRING_BUFFER<512>	strbuf;

							if (is_idle) {
								strbuf.appendconst("Idle Timeout from ");
							}
							else {
								strbuf.appendconst("Pending data Timeout from ");
							}	

							INFOPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Closing connection due to %s : %s\n",
								pconn1->print_conn(strbuf), param.descbuf_);

							pconn1->signal_conn_close();
							it = mconntrack.erase(it);
						}	
						else {
							if (pconn1->get_nrecv_cbs()) {
								auto ncbs_deleted = pconn1->cleanup_async_cbs(tcurr1);
								
								if (ncbs_deleted > 0) {
									statsmap["Async Callbacks Timed Out"] += ncbs_deleted;

									DEBUGEXECN(1,
										INFOPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "%s missed handling %lu async callbacks...\n",
											pconn1->print_conn(STRING_BUFFER<512>().get_str_buf()), ncbs_deleted);
									);
								}
							}

							++it;
						}	
					}		

					if (npendtimeout > 0) {
						statsmap["Pending data Timeout"] += npendtimeout;
					}

					if (nidletimeout > 0) {
						statsmap["Idle Timeout"] += nidletimeout;
					}	

					if (niter_checks == 10) {
						niter_checks = 0;

						STRING_BUFFER<2048>	strbuf;

						for (auto && it : statsmap) {
							strbuf.appendfmt(" {\"%s\" : %ld},", it.first, it.second);
						}	
						strbuf.set_last_char(' ');

						INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "%s : Connections %lu (of Total %lu) : Stats : [ %.*s ] : "
							"Recent Pending Data Timed out conns %ld : Idle Timed out conns %ld\n", 
							param.descbuf_, mconntrack.size(), gtconncount.load(mo_relaxed), strbuf.sizeint(), strbuf.buffer(),
							npendtimeout, nidletimeout);

						tpoolcnt++;
						if (tpoolcnt == 5) {
							tpoolcnt = 0;
							strbuf.reset();

							INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "%s %s\n", param.descbuf_, poolarr.print_stats(strbuf));
						}	

					}
				}	
				
				last_tcount 		= curr_tcount;
				curr_tcount		= mconntrack.size();

				if (curr_tcount - last_tcount != 0) {
					gtconncount.fetch_add(curr_tcount - last_tcount, mo_relaxed);
				}	
			}	
			GY_CATCH_EXCEPTION(
				ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught in %s : %s\n", param.descbuf_, GY_GET_EXCEPT_STRING);
			);
				
		} while (true);	
	
		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught in %s : %s\n\n", param.descbuf_, GY_GET_EXCEPT_STRING);
		return -1;
	);
}

int SHCONN_HANDLER::handle_l2(GY_THREAD *pthr)
{
	uint32_t			l2_thr_num = 0;
	L2_PARAMS			param;
	POOL_ALLOC_ARRAY		*pthrpoolarr = nullptr;
	const pid_t			tid = gy_gettid();
	auto 				psettings = pshyama_->psettings_;
	std::optional<PGConnPool>	dbpool;

	{
		int				retsig = -1;
		S512_PROC_ELEM			*psignal = (decltype(psignal))pthr->get_opt_arg2();	

		assert(psignal);

		L2_PARAMS			*psigdata = (L2_PARAMS *)psignal->get_data_buf();

		l2_thr_num = psigdata->thr_num_;

		GY_SCOPE_EXIT {
			psignal->signal_completion(retsig, sizeof(L2_PARAMS));
		};	

		psigdata->pthread_ 	= pthr;

		const char		*ptype;

		switch (psigdata->thr_type_) {
		
		case TTYPE_L2_DB 	:	ptype = "DB Thread"; break;
		case TTYPE_L2_MISC 	:	ptype = "Misc Thread"; break;
		case TTYPE_L2_ALERT 	:	ptype = "Alert Handler"; break;

		default 		:
			ERRORPRINTCOLOR(GY_COLOR_RED, "Invalid L2 Thread Type specified : %u : Exiting...\n", psigdata->thr_type_);
			exit(EXIT_FAILURE);
		}

		snprintf(psigdata->descbuf_, sizeof(psigdata->descbuf_), "Level 2 %s Thread %u TID %d", ptype, l2_thr_num, tid);
		
		try {
			if (psigdata->thr_type_ == TTYPE_L2_MISC) {
				size_t		pool_szarr[5], pool_maxarr[5];
			
				pool_szarr[0] 	= sizeof(SHTCP_CONN) + 16;
				pool_maxarr[0]	= 18 * 1024;

				pool_szarr[1] 	= 4096;
				pool_maxarr[1]	= 1024;

				pool_szarr[2]	= sizeof(comm::SHYAMA_CLI_TCP_INFO) + 16; 
				pool_maxarr[2]	= 6 * 1024;

				pool_szarr[3]	= sizeof(SHYAMA_SER_TCP_INFO) + 16; 
				pool_maxarr[3]	= 6 * 1024;

				pool_szarr[4]	= 512;
				pool_maxarr[4]	= 1024;

				pthrpoolarr = new POOL_ALLOC_ARRAY(pool_szarr, pool_maxarr, GY_ARRAY_SIZE(pool_szarr), true);
			}	
			else if (psigdata->thr_type_ == TTYPE_L2_DB) {
				size_t		pool_szarr[2], pool_maxarr[2];
			
				pool_szarr[0] 	= 512;
				pool_maxarr[0]	= 2048;

				pool_szarr[1] 	= 4096;
				pool_maxarr[1]	= 1024;

				pthrpoolarr = new POOL_ALLOC_ARRAY(pool_szarr, pool_maxarr, GY_ARRAY_SIZE(pool_szarr), true);

				INFOPRINT("L2 DB Thread %u initiating Postgres Connection...\n", l2_thr_num);

				dbpool.emplace(gy_to_charbuf<128>("DB Pool %u", l2_thr_num).get(), RD_DB_POOL_CONNS,
							psettings->postgres_hostname, psettings->postgres_port, psettings->postgres_user, psettings->postgres_password,
							get_dbname().get(), gy_to_charbuf<64>("shyama_db%u", l2_thr_num).get(), 
							get_db_init_commands().get(), true /* auto_reconnect */, 12, 10, 10);

				if (0 == l2_thr_num) {
					// Init db data...
					read_db_partha_info(*dbpool);

					init_tracedefs(*dbpool);
				}
			}	
			else if (psigdata->thr_type_ == TTYPE_L2_ALERT) {

				static_assert(MAX_L2_ALERT_THREADS == 1, "Require Only 1 Alert Manager thread");

				pshalerthdlr_ = (decltype(pshalerthdlr_))aligned_alloc_or_throw(alignof(decltype(*pshalerthdlr_)), sizeof(*pshalerthdlr_));

				new (pshalerthdlr_) SHALERT_HDLR(this);

				palertmgr_ = (decltype(palertmgr_))aligned_alloc_or_throw(alignof(decltype(*palertmgr_)), sizeof(*palertmgr_));

				new (palertmgr_) ALERTMGR(*psettings, this);

				palertmgr_->read_db_alert_info();
			}
		}
		GY_CATCH_EXCEPTION(
			ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to initialize Shyama for %s : %s\n", psigdata->descbuf_, GY_GET_EXCEPT_STRING);
			exit(EXIT_FAILURE);
		);

		param			= *psigdata;

		retsig			= 0;
	}

	/*
	 * Now wait for the main thread to signal all other threads have been initialized...
	 */
	bool is_inc = false; 

	auto waitcb = [&, this]() noexcept
	{
		if (is_inc == false) {
			nblocked_l2_.fetch_add(1, mo_relaxed);
			is_inc = true;
		}	
		return !all_spawned_.load(mo_relaxed);
	};

	auto waitsuc = [this]() noexcept 
	{
		nblocked_l2_.fetch_sub(1, mo_relaxed);
	};

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "%s now waiting for signal...\n", param.descbuf_);

	barcond_.cond_wait(waitcb, waitsuc);

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "%s received signal...Now continuing...\n", param.descbuf_);

	switch (param.thr_type_) {
	
	case TTYPE_L2_DB 	:	do { handle_l2_db(param, pthrpoolarr, *dbpool); } while (true);

	case TTYPE_L2_MISC 	:	do { handle_l2_misc(param, pthrpoolarr); } while (true);

	case TTYPE_L2_ALERT 	:	do { handle_alert_mgr(param); } while (true);

	default 		: 	break;
	}

	return -1;
}

/*
 * Thread Handling both Node Queries and DB Write events
 */
int SHCONN_HANDLER::handle_l2_db(L2_PARAMS & param, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	try {
		MPMCQ_COMM			* const pl2pool = param.pmpmc_;
		const uint32_t			l2_thr_num = param.thr_num_;
		const pid_t			tid = gy_gettid();
		uint64_t			curr_usec_clock = get_usec_clock() + ((tid * 10) & 0xFFFF), last_usec_clock = curr_usec_clock, last_dbreset_cusec = curr_usec_clock;
		int				tpoolcnt = 0;
		STATS_STR_MAP			statsmap;
		bool				bret;

		statsmap.reserve(64);

		statsmap["Exception Occurred"] = 0;
		statsmap["Idle Timeout"] = 0;

		do {
			gy_thread_rcu().gy_rcu_thread_offline();

			EV_NOTIFY_ONE		ev;

			bret = pl2pool->tryReadUntil(std::chrono::steady_clock::now() + std::chrono::microseconds(MAX_CONN_DATA_TIMEOUT_USEC + ((tid * 100) & 0x7FFFF)), ev);

			try {
				if (bret && NOTIFY_DB_WRITE_ARR != ev.get_type()) {
					statsmap["Invalid DB Notify"]++;
					bret = false;
				}

				if (bret == true) {
					statsmap["Total DB Read Reqs"]++;

					DB_WRITE_ARR		& dbarr = ev.data_.dbwrarr_;

					if (false == dbarr.validate()) {
						statsmap["Internal Error : Invalid dbarr"]++;
						continue;
					}

					if ((1 >= dbarr.shrconn_.use_count()) || (dbarr.shrconn_->is_conn_close_signalled())) {
						statsmap["Connection Disconnect"]++;
						continue;
					}	

					for (size_t i = 0; i < dbarr.ndbs_; ++i) {
						auto 			& dbone 	= dbarr.dbonearr_[i];

						uint8_t			*prdbuf 	= dbone.pwrbuf_;
						COMM_HEADER		*phdr 		= (COMM_HEADER *)prdbuf;
						uint8_t			*pendptr	= prdbuf + phdr->get_act_len();	
						const bool		is_last_elem	= (i + 1 == dbarr.ndbs_);
						QUERY_CMD		*pquery;
						EVENT_NOTIFY		*pevtnot;

						switch (phdr->data_type_) {
					
						case COMM_QUERY_CMD :

							pquery = (QUERY_CMD *)(prdbuf + sizeof(COMM_HEADER));

							switch (pquery->subtype_) {
								
							case QUERY_WEB_JSON :
							case CRUD_GENERIC_JSON :
							/*case CRUD_ALERT_JSON :*/

								do {
									char 			*pjson = (char *)(pquery + 1);

									statsmap["Node Query"]++;
									handle_node_query(dbarr.shrconn_, pquery, pjson, (char *)pendptr, pthrpoolarr, statsmap, dbpool);

								} while (false);

								break;

							default :
								break;
							
							}

							break;


						case COMM_EVENT_NOTIFY :
					
							pevtnot = (EVENT_NOTIFY *)(phdr + 1);

							switch (pevtnot->subtype_) {

							case NOTIFY_MS_PARTHA_PING :
								try {
									auto			*pconn = (MS_PARTHA_PING *)(pevtnot + 1);
									int			nevents = pevtnot->nevents_;

									statsmap["Madhava Partha Ping"]++;

									handle_ms_partha_ping(dbarr.shrconn_->get_madhava_shared(), pconn, nevents, dbpool);
								}
								GY_CATCH_EXCEPTION(
									DEBUGEXECN(1, 
										ERRORPRINT_OFFLOAD("Exception occurred while handling Madhava Partha Ping : %s\n", GY_GET_EXCEPT_STRING);
									);	
									statsmap["Exception Occurred"]++;
								);

								break;

							default :
								break;
							}	

							break;

						default :
							break;
						}	
					}	
				}
				else {
					statsmap["Idle Timeout"]++;
				}	

				curr_usec_clock = get_usec_clock();

				if (curr_usec_clock - last_usec_clock > MAX_CONN_DATA_TIMEOUT_USEC * 5) {
					last_usec_clock = curr_usec_clock;

					STRING_BUFFER<1024>	strbuf;

					for (auto && it : statsmap) {
						strbuf.appendfmt(" {\"%s\" : %ld},", it.first, it.second);
					}	
					strbuf.set_last_char(' ');

					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN_ITALIC, "%s : Stats : [ %.*s ]\n", param.descbuf_, strbuf.sizeint(), strbuf.buffer());

					tpoolcnt++;
					if (tpoolcnt == 5) {
						tpoolcnt = 0;
						strbuf.reset();

						INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN_ITALIC, "%s %s\n", param.descbuf_, pthrpoolarr->print_stats(strbuf));
					}	

					dbpool.check_or_reconnect();
				}

				// Reset the Postgres connection pool to free up backend memory
				if (curr_usec_clock - last_dbreset_cusec > MAX_CONN_DATA_TIMEOUT_USEC) {
					last_dbreset_cusec = curr_usec_clock;
					dbpool.reset_idle_conns();
				}	
			}
			GY_CATCH_EXCEPTION(
				ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught in %s while handling message : %s\n\n", param.descbuf_, GY_GET_EXCEPT_STRING);
				statsmap["Exception Occurred"]++;
			);

		} while (true);	

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught in %s : %s\n\n", param.descbuf_, GY_GET_EXCEPT_STRING);
		return -1;
	);
}

int SHCONN_HANDLER::handle_l2_misc(L2_PARAMS & param, POOL_ALLOC_ARRAY *pthrpoolarr)
{
	try {
		MPMCQ_COMM			* const pl2pool = param.pmpmc_;
		const uint32_t			l2_thr_num = param.thr_num_;
		const pid_t			tid = gy_gettid();
		uint64_t			curr_usec_clock = get_usec_clock() + ((tid * 10) & 0xFFFF), last_usec_clock = curr_usec_clock;
		int				tpoolcnt = 0;
		STATS_STR_MAP			statsmap;
		bool				bret;

		statsmap.reserve(32);

		statsmap["Exception Occurred"] = 0;
		statsmap["Total Misc Notify"] = 0;

		// Need at least 512 KB Stack
		assert(gy_get_thread_local().get_thread_stack_freespace() >= 500 * 1024);

		do {
			gy_thread_rcu().gy_rcu_thread_offline();

			EV_NOTIFY_ONE		ev;

			bret = pl2pool->tryReadUntil(std::chrono::steady_clock::now() + std::chrono::microseconds(MAX_CONN_DATA_TIMEOUT_USEC + ((tid * 100) & 0x7FFFF)), ev);

			try {
				if (bret && NOTIFY_DB_WRITE_ARR != ev.get_type())  {
					statsmap["Invalid Misc Notify"]++;
					bret = false;
				}

				if (bret == true) {
					statsmap["Total Misc Notify"]++;

					DB_WRITE_ARR		& dbarr = ev.data_.dbwrarr_;

					if (false == dbarr.validate()) {
						statsmap["Internal Error : Invalid dbarr"]++;
						continue;
					}

					auto is_disconnected = [&]() noexcept -> bool
					{
						return (1 >= dbarr.shrconn_.use_count());
					};

					for (size_t i = 0; i < dbarr.ndbs_; ++i) {
						auto 			& dbone 	= dbarr.dbonearr_[i];

						uint8_t			*prdbuf 	= dbone.pwrbuf_;
						COMM_HEADER		*phdr 		= (COMM_HEADER *)prdbuf;
						uint8_t			*pendptr	= prdbuf + phdr->get_act_len();	
						const bool		is_last_elem	= (i + 1 == dbarr.ndbs_);
						EVENT_NOTIFY		*pevtnot;

						switch (phdr->data_type_) {

						case COMM_EVENT_NOTIFY :
					
							pevtnot = (EVENT_NOTIFY *)(phdr + 1);

							switch (pevtnot->subtype_) {

							case NOTIFY_MS_TCP_CONN :
								try {
									MS_TCP_CONN_NOTIFY	*pconn = (MS_TCP_CONN_NOTIFY *)(pevtnot + 1);
									int			nevents = pevtnot->nevents_;

									statsmap["TCP Conn Notify"]++;

									madhava_tcp_conn_info(dbarr.shrconn_->get_madhava_shared(), pconn, nevents, pthrpoolarr);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Madhava TCP Conn Notify : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;
												
							case NOTIFY_MS_TCP_CONN_CLOSE :
								try {
									MS_TCP_CONN_CLOSE 	*pconn = (MS_TCP_CONN_CLOSE *)(pevtnot + 1);
									int			nevents = pevtnot->nevents_;

									statsmap["TCP Close Notify"]++;

									madhava_tcp_close(dbarr.shrconn_->get_madhava_shared(), pconn, nevents);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Madhava TCP Close Notify : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;
												
							case NOTIFY_NAT_TCP :
								try {
									statsmap["NAT TCP Notify"]++;

									NAT_TCP_NOTIFY	 	*pnat = (NAT_TCP_NOTIFY *)(pevtnot + 1);
									int			nevents = pevtnot->nevents_;

									handle_madhava_nat_notify(pnat, nevents, pthrpoolarr);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Madhava NAT TCP Notify : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;

							case NOTIFY_MS_CLUSTER_STATE :
								try {
									statsmap["Cluster State Notify"]++;

									auto		 	*pconn = (MS_CLUSTER_STATE *)(pevtnot + 1);
									int			nevents = pevtnot->nevents_;

									handle_cluster_state(dbarr.shrconn_->get_madhava_shared(), pconn, nevents, pendptr, pthrpoolarr);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Madhava Cluster State Notify : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;


							case NOTIFY_MS_SVC_CLUSTER_MESH :
								try {
									statsmap["Svc Cluster Mesh Notify"]++;

									auto		 	*pconn = (MS_SVC_CLUSTER_MESH *)(pevtnot + 1);
									int			nevents = pevtnot->nevents_;

									handle_svc_cluster_mesh(dbarr.shrconn_->get_madhava_shared(), pconn, nevents, pendptr, pthrpoolarr);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Madhava Svc Cluster Mesh Notify : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;


							case NOTIFY_MS_LISTENER_NAT_IP :
								try {
									statsmap["Svc NAT IP Notify"]++;

									auto		 	*pconn = (MS_LISTENER_NAT_IP *)(pevtnot + 1);
									int			nevents = pevtnot->nevents_;

									handle_svc_nat_ip(dbarr.shrconn_->get_madhava_shared(), pconn, nevents, pendptr, pthrpoolarr);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Madhava Svc NAT IP Notify : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;


							case NOTIFY_MS_REG_PARTHA :
								try {
									auto			*preg = (MS_REG_PARTHA *)(pevtnot + 1);
									int			nevents = pevtnot->nevents_;

									statsmap["Reg Partha Notify"]++;

									handle_madhava_reg_partha(dbarr.shrconn_->get_madhava_shared(), preg, nevents);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Madhava Registered Partha Notify : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;
												

							default :
								break;	
							}

							break;

						case MS_REGISTER_REQ :
							try {
								MS_REGISTER_REQ_S 		*pms = (MS_REGISTER_REQ_S *)(phdr + 1);

								statsmap["Madhava Registration Request"]++;

								if (false == is_disconnected()) {
									handle_misc_madhava_reg(pms, dbarr, param, pthrpoolarr, statsmap);
								}
								break;
							}
							GY_CATCH_EXCEPTION(
								ERRORPRINT_OFFLOAD("Exception occurred while handling Madhava Registration request : %s\n", GY_GET_EXCEPT_STRING);
							);

							send_l1_register_connect_error<MS_REGISTER_RESP_S, MS_REGISTER_RESP>(dbarr.pl1_src_, dbarr.shrconn_, dbarr.shrconn_.get(), 
								dbarr.comm_magic_, statsmap, ERR_SERV_ERROR,  "Exception occurred while handling request.", pthrpoolarr);
							statsmap["Madhava Registration Exception"]++;
							
							break;

						case PS_REGISTER_REQ :
							try {
								PS_REGISTER_REQ_S 		*preg = (PS_REGISTER_REQ_S *)(phdr + 1);

								statsmap["Partha Registration Request"]++;

								if (false == is_disconnected()) {
									handle_misc_partha_reg(preg, dbarr, param, pthrpoolarr, statsmap);
								}	
								break;
							}
							GY_CATCH_EXCEPTION(
								ERRORPRINT_OFFLOAD("Exception occurred while handling Partha Registration request : %s\n", GY_GET_EXCEPT_STRING);
							);

							send_l1_register_connect_error<PS_REGISTER_RESP_S, PS_REGISTER_RESP>(dbarr.pl1_src_, dbarr.shrconn_, dbarr.shrconn_.get(), 
								dbarr.comm_magic_, statsmap, ERR_SERV_ERROR,  "Exception occurred while handling request.", pthrpoolarr);
							statsmap["Partha Registration Exception"]++;
							break;

						case NS_REGISTER_REQ :
							try {
								NS_REGISTER_REQ_S		*pns = (NS_REGISTER_REQ_S *)(phdr + 1);

								statsmap["Node Registration Request"]++;

								if (false == is_disconnected()) {
									handle_misc_node_reg(pns, dbarr, param, pthrpoolarr, statsmap);
								}	
								break;
							}
							GY_CATCH_EXCEPTION(
								ERRORPRINT_OFFLOAD("Exception occurred while handling Node Registration request : %s\n", GY_GET_EXCEPT_STRING);
							);

							send_l1_register_connect_error<NS_REGISTER_RESP_S, NS_REGISTER_RESP>(dbarr.pl1_src_, dbarr.shrconn_, dbarr.shrconn_.get(), 
								dbarr.comm_magic_, statsmap, ERR_SERV_ERROR,  "Exception occurred while handling request.", pthrpoolarr);
							statsmap["Node Registration Exception"]++;
							
							break;

						default :
							statsmap["Invalid Misc Cmd Type"]++;
							break;
						}	
					}	
				}

				curr_usec_clock = get_usec_clock();

				if (curr_usec_clock - last_usec_clock > MAX_CONN_DATA_TIMEOUT_USEC * 5) {
					last_usec_clock = curr_usec_clock;

					STRING_BUFFER<1024>	strbuf;

					for (auto && it : statsmap) {
						strbuf.appendfmt(" {\"%s\" : %ld},", it.first, it.second);
					}	
					strbuf.set_last_char(' ');

					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN_ITALIC, "%s : Stats : [ %.*s ]\n", param.descbuf_, strbuf.sizeint(), strbuf.buffer());

					tpoolcnt++;
					if (tpoolcnt == 5) {
						tpoolcnt = 0;
						strbuf.reset();

						INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN_ITALIC, "%s %s\n", param.descbuf_, pthrpoolarr->print_stats(strbuf));
					}	
				}
			}
			GY_CATCH_EXCEPTION(
				ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught in %s while handling message : %s\n\n", param.descbuf_, GY_GET_EXCEPT_STRING);
				statsmap["Exception Occurred"]++;
			);

		} while (true);	

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught in %s : %s\n\n", param.descbuf_, GY_GET_EXCEPT_STRING);
		return -1;
	);
}

// Returns {is_added, is_info}
std::pair<bool, bool> SHCONN_HANDLER::add_tcp_conn_cli(const std::shared_ptr<MADHAVA_INFO> & madhava_shr, const comm::MS_TCP_CONN_NOTIFY * pone, uint64_t tcurrusec, \
				CLI_INFO_VEC_MAP & climap, CLI_INFO_VEC_ARENA & cli_vec_arena, SER_INFO_VEC_MAP & sermap, SER_INFO_VEC_ARENA & ser_vec_arena, POOL_ALLOC_ARRAY *pthrpoolarr)
{
	if (!madhava_shr) {
		return {false, false};
	}

	PAIR_IP_PORT			ctuple(pone->nat_cli_, pone->nat_ser_);
	const uint32_t			chash = ctuple.get_hash();
	bool				bret, binfo = false;
	SHTCP_CONN			*pconn = nullptr;

	RCU_LOCK_FAST			fastlock;

	auto lamtcp = [&](SHTCP_CONN *ptcp, void *arg1, void *arg2) -> CB_RET_E
	{	
		pconn 	= ptcp;

		return CB_OK;
	};	

	bret = !glob_tcp_conn_tbl_.lookup_single_elem(ctuple, chash, lamtcp);

	if (!pconn) {
		SHTCP_CONN				*ptcp;
		FREE_FPTR				free_fp;
		uint32_t				act_size;
		
		ptcp = (SHTCP_CONN *)pthrpoolarr->safe_malloc(sizeof(SHTCP_CONN), free_fp, act_size, false /* try_other_pools */, true /* use_malloc_hdr */);
		new (ptcp) SHTCP_CONN();

		ptcp->cli_				= pone->cli_;
		ptcp->ser_				= pone->ser_;

		ptcp->cli_nat_cli_			= pone->nat_cli_;
		ptcp->cli_nat_ser_			= pone->nat_ser_;

		ptcp->cli_ser_madhava_shr_		= madhava_shr;
		ptcp->cli_madhava_id_			= madhava_shr->madhava_id_;
		ptcp->cli_task_aggr_id_			= pone->cli_task_aggr_id_;
		ptcp->cli_related_listen_id_		= pone->cli_related_listen_id_;
		ptcp->close_cli_bytes_sent_		= pone->close_cli_bytes_sent_;
		ptcp->close_cli_bytes_rcvd_		= pone->close_cli_bytes_rcvd_;
		ptcp->cli_ser_partha_machine_id_	= pone->cli_ser_partha_machine_id_;
		ptcp->cli_ser_cluster_hash_		= pone->cli_ser_cluster_hash_;

		std::memcpy(ptcp->cli_comm_, pone->cli_ser_comm_, sizeof(ptcp->cli_comm_));
		
		if (pone->cli_ser_cmdline_len_ <= sizeof(ptcp->cli_ser_cmdline_trunc_)) {
			ptcp->cli_ser_cmdline_len_ = pone->cli_ser_cmdline_len_;
			std::memcpy(ptcp->cli_ser_cmdline_trunc_, pone->cli_ser_cmdline_trunc_, ptcp->cli_ser_cmdline_len_);
		}	
		else {
			ptcp->cli_ser_cmdline_len_ 	= 0;
		}	

		ptcp->tusec_mstart_			= pone->tusec_mstart_;
		ptcp->tusec_shstart_			= tcurrusec;

		CONDEXEC(
			DEBUGEXECN(10,
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_MAGENTA, "Adding new %sClient side TCP conn : NAT Tuple %s : Original Client %s Server %s from Client Comm \'%s\' and %s\n",
					ptcp->is_conn_closed() ? "Closed " : "",
					ctuple.print_string(STRING_BUFFER<256>().get_str_buf()), ptcp->cli_.print_string(STRING_BUFFER<128>().get_str_buf()),
					ptcp->ser_.print_string(STRING_BUFFER<128>().get_str_buf()), ptcp->cli_comm_, 
					madhava_shr->print_string(STRING_BUFFER<256>().get_str_buf()));
			);
		);

		auto newlam = [&](SHTCP_CONN *poldelem, SHTCP_CONN *pnewelem)
		{
			lamtcp(poldelem, nullptr, nullptr);
		};

		bret = glob_tcp_conn_tbl_.insert_unique(ptcp, ctuple, chash, newlam, true /* delete_after_callback */);
	}

	if (pconn) {

		if (pconn->cli_ser_madhava_shr_ && pconn->ser_glob_id_) {
			auto 		[cit, csuccess] = climap.try_emplace(madhava_shr, cli_vec_arena);
			auto 		& clivec = cit->second;

			clivec.emplace_back(PAIR_IP_PORT(pone->cli_, pone->ser_), pconn->ser_glob_id_, pconn->ser_madhava_id_, pconn->ser_related_listen_id_, pconn->ser_nat_ser_, 
				pone->cli_task_aggr_id_, pone->cli_related_listen_id_, pone->cli_ser_partha_machine_id_, pconn->cli_comm_, pconn->cli_ser_partha_machine_id_, 
				pone->close_cli_bytes_sent_, pone->close_cli_bytes_rcvd_, pone->tusec_mstart_, 
				pone->cli_ser_cluster_hash_ != pconn->cli_ser_cluster_hash_, pconn->ser_comm_, pconn->cli_ser_cmdline_trunc_, pconn->cli_ser_cmdline_len_);

			auto 		[sit, ssuccess] = sermap.try_emplace(std::move(pconn->cli_ser_madhava_shr_), ser_vec_arena);
			auto 		& servec = sit->second;

			servec.emplace_back(pconn->ser_glob_id_, madhava_shr->madhava_id_, pone->cli_task_aggr_id_, pone->cli_related_listen_id_, 
				pone->cli_ser_partha_machine_id_, pconn->ser_comm_, pconn->cli_ser_partha_machine_id_, pone->ser_, 
				pconn->ser_nat_conn_hash_, pconn->ser_conn_hash_, pconn->ser_sock_inode_, 
				pconn->close_cli_bytes_sent_, pconn->close_cli_bytes_rcvd_, pconn->ser_tusec_pstart_, pconn->tusec_mstart_, pone->cli_ser_comm_, 
				pone->cli_ser_cmdline_trunc_, pone->cli_ser_cmdline_len_);

			binfo = true;
		}

		// Now delete this conn as we are already under RCU Lock
		glob_tcp_conn_tbl_.delete_elem_locked(pconn);
	}	

	return {bret, binfo};
}	

// Returns {is_added, is_info}
std::pair<bool, bool> SHCONN_HANDLER::add_tcp_conn_ser(const std::shared_ptr<MADHAVA_INFO> & madhava_shr, const comm::MS_TCP_CONN_NOTIFY * pone, uint64_t tcurrusec, \
						CLI_INFO_VEC_MAP & climap, CLI_INFO_VEC_ARENA & cli_vec_arena, \
						SER_INFO_VEC_MAP & sermap, SER_INFO_VEC_ARENA & ser_vec_arena, POOL_ALLOC_ARRAY *pthrpoolarr)
{
	if (!madhava_shr) {
		return {false, false};
	}

	PAIR_IP_PORT			stuple(pone->cli_, pone->ser_), corigtup;
	const uint32_t			shash = stuple.get_hash();
	bool				bret, binfo = false;
	SHTCP_CONN			*pconn = nullptr;

	RCU_LOCK_FAST			fastlock;

	auto lamtcp = [&](SHTCP_CONN *ptcp, void *arg1, void *arg2) -> CB_RET_E
	{	
		pconn 	= ptcp;

		return CB_OK;
	};	

	bret = !glob_tcp_conn_tbl_.lookup_single_elem(stuple, shash, lamtcp);

	if (!pconn) {
		SHTCP_CONN				*ptcp;
		FREE_FPTR				free_fp;
		uint32_t				act_size;
		
		ptcp = (SHTCP_CONN *)pthrpoolarr->safe_malloc(sizeof(SHTCP_CONN), free_fp, act_size, false /* try_other_pools */, true /* use_malloc_hdr */);
		new (ptcp) SHTCP_CONN();

		ptcp->cli_				= pone->cli_;
		ptcp->ser_				= pone->ser_;

		// Set the cli_nat_cli_ and cli_nat_ser_ as these are the keys of the elem
		ptcp->cli_nat_cli_			= pone->cli_;
		ptcp->cli_nat_ser_			= pone->ser_;

		ptcp->ser_nat_cli_			= pone->nat_cli_;
		ptcp->ser_nat_ser_			= pone->nat_ser_;

		ptcp->cli_ser_madhava_shr_		= madhava_shr;
		ptcp->cli_ser_partha_machine_id_	= pone->cli_ser_partha_machine_id_;
		ptcp->ser_glob_id_			= pone->ser_glob_id_;
		ptcp->ser_madhava_id_			= madhava_shr->madhava_id_;
		ptcp->ser_related_listen_id_		= pone->ser_related_listen_id_;
		ptcp->ser_tusec_pstart_			= pone->ser_tusec_pstart_;
		ptcp->ser_nat_conn_hash_		= pone->ser_nat_conn_hash_;
		ptcp->ser_conn_hash_			= pone->ser_conn_hash_;
		ptcp->ser_sock_inode_			= pone->ser_sock_inode_;
		ptcp->cli_ser_cluster_hash_		= pone->cli_ser_cluster_hash_;

		std::memcpy(ptcp->ser_comm_, pone->cli_ser_comm_, sizeof(ptcp->cli_comm_));
		
		if (pone->cli_ser_cmdline_len_ <= sizeof(ptcp->cli_ser_cmdline_trunc_)) {
			ptcp->cli_ser_cmdline_len_ = pone->cli_ser_cmdline_len_;
			std::memcpy(ptcp->cli_ser_cmdline_trunc_, pone->cli_ser_cmdline_trunc_, ptcp->cli_ser_cmdline_len_);
		}	
		else {
			ptcp->cli_ser_cmdline_len_ 	= 0;
		}	

		ptcp->close_cli_bytes_sent_		= pone->close_cli_bytes_sent_;
		ptcp->close_cli_bytes_rcvd_		= pone->close_cli_bytes_rcvd_;
		ptcp->tusec_mstart_			= pone->tusec_mstart_;
		ptcp->tusec_shstart_			= tcurrusec;

		CONDEXEC(
			DEBUGEXECN(10,
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_MAGENTA, "Adding new %sServer side TCP conn : Tuple %s : NAT Client %s Server %s from Server Comm \'%s\' and %s\n",
					ptcp->is_conn_closed() ? "Closed " : "", 
					stuple.print_string(STRING_BUFFER<256>().get_str_buf()), ptcp->ser_nat_cli_.print_string(STRING_BUFFER<128>().get_str_buf()),
					ptcp->ser_nat_ser_.print_string(STRING_BUFFER<128>().get_str_buf()), ptcp->ser_comm_, 
					madhava_shr->print_string(STRING_BUFFER<256>().get_str_buf()));
			);
		);

		auto newlam = [&](SHTCP_CONN *poldelem, SHTCP_CONN *pnewelem)
		{
			lamtcp(poldelem, nullptr, nullptr);
		};

		bret = glob_tcp_conn_tbl_.insert_unique(ptcp, stuple, shash, newlam, true /* delete_after_callback */);
	}

	if (pconn) {

		if (pconn->cli_ser_madhava_shr_ && pconn->cli_task_aggr_id_) {

			auto		madhava_id = pconn->cli_ser_madhava_shr_->madhava_id_;
			auto 		[cit, csuccess] = climap.try_emplace(std::move(pconn->cli_ser_madhava_shr_), cli_vec_arena);
			auto 		& clivec = cit->second;

			clivec.emplace_back(PAIR_IP_PORT(pconn->cli_, pconn->ser_), pone->ser_glob_id_, madhava_shr->madhava_id_, pone->ser_related_listen_id_, pone->nat_ser_, 
				pconn->cli_task_aggr_id_, pconn->cli_related_listen_id_, pconn->cli_ser_partha_machine_id_, pconn->cli_comm_,
				pone->cli_ser_partha_machine_id_, pconn->close_cli_bytes_sent_, pconn->close_cli_bytes_rcvd_, pconn->tusec_mstart_,
				pone->cli_ser_cluster_hash_ != pconn->cli_ser_cluster_hash_, pone->cli_ser_comm_, pone->cli_ser_cmdline_trunc_, pone->cli_ser_cmdline_len_);

			auto 		[sit, ssuccess] = sermap.try_emplace(madhava_shr, ser_vec_arena);
			auto 		& servec = sit->second;

			servec.emplace_back(pone->ser_glob_id_, madhava_id, pconn->cli_task_aggr_id_, pconn->cli_related_listen_id_, 
				pconn->cli_ser_partha_machine_id_, pone->cli_ser_comm_, pone->cli_ser_partha_machine_id_, pconn->ser_, 
				pone->ser_nat_conn_hash_, pone->ser_conn_hash_, pone->ser_sock_inode_, pone->close_cli_bytes_sent_, pone->close_cli_bytes_rcvd_, 
				pone->ser_tusec_pstart_, pone->tusec_mstart_, pconn->cli_comm_, pconn->cli_ser_cmdline_trunc_, pconn->cli_ser_cmdline_len_);

			binfo = true;
		}

		// Now delete this conn as we are already under RCU Lock
		glob_tcp_conn_tbl_.delete_elem_locked(pconn);
	}	

	return {bret, binfo};
}

bool SHCONN_HANDLER::madhava_tcp_conn_info(const std::shared_ptr<MADHAVA_INFO> & madhava_shr, const comm::MS_TCP_CONN_NOTIFY * ponestart, int nconns, POOL_ALLOC_ARRAY *pthrpoolarr)
{
	MADHAVA_INFO		*pmadhava = madhava_shr.get();

	if (!pmadhava) {
		return false;
	}	
	
	/*
	 * We allocate stack based Vectors/Maps to hold intermediate data with total stack usage of approx : 200 * 1024 + 8192 + 100 * 1024 + 16 * 1024 = 324 KB 
	 */

	SER_INFO_VEC_ARENA		ser_vec_arena;
	CLI_INFO_VEC_ARENA		cli_vec_arena;
	SER_INFO_VEC_MAP_ARENA		ser_map_arena;
	CLI_INFO_VEC_MAP_ARENA		cli_map_arena;
	SER_INFO_VEC_MAP		sermap(ser_map_arena);
	CLI_INFO_VEC_MAP		climap(cli_map_arena);
	
	RCU_DEFER_OFFLINE		deferlock;

	const uint64_t			tusec_start = get_usec_time();
	int				nconnadded = 0, nmadinfo = 0, nmadcli = 0, nmadser = 0;
	auto				pone = ponestart;
	
	for (int i = 0; i < nconns; ++i, ++pone) {
		bool			is_added;

		if (false == pone->is_server_updated()) {
			auto [is_added, is_info] = add_tcp_conn_cli(madhava_shr, pone, tusec_start, climap, cli_vec_arena, sermap, ser_vec_arena, pthrpoolarr);
			
			nconnadded += int(is_added);
			nmadinfo += int(is_info);
		}	
		else {
			auto [is_added, is_info] = add_tcp_conn_ser(madhava_shr, pone, tusec_start, climap, cli_vec_arena, sermap, ser_vec_arena, pthrpoolarr);
			
			nconnadded += int(is_added);
			nmadinfo += int(is_info);
		}	
	}	

	// Now RCU Offline the thread
	deferlock.offline_now();

	for (const auto & epair : climap) {
		const auto & madshr	= epair.first;
		const auto & madvec	= epair.second;

		if (!madshr || madvec.empty()) {
			continue;
		}

		DEBUGEXECN(5,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Sending %lu TCP Conn Client Side Info Messages to Madhava %s\n",
				madvec.size(), madshr->print_string(STRING_BUFFER<256>().get_str_buf()));
		);

		nmadcli += madvec.size();

		send_madhava_cli_conn_info(madshr.get(), madvec.data(), madvec.size(), pthrpoolarr);
	}	

	for (const auto & epair : sermap) {
		const auto & madshr	= epair.first;
		const auto & madvec	= epair.second;

		if (!madshr || madvec.empty()) {
			continue;
		}

		DEBUGEXECN(5,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Sending %lu TCP Conn Server Side Info Messages to Madhava %s\n",
				madvec.size(), madshr->print_string(STRING_BUFFER<256>().get_str_buf()));
		);

		nmadser += madvec.size();

		send_madhava_ser_conn_info(madshr.get(), madvec.data(), madvec.size(), pthrpoolarr);
	}	

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_CYAN, 
		"Madhava %s:%hu TCP Conn Notify : Added %d new TCP Conns, %d Conns Resolved, %d Client Side Madhava Infos, %d Server side Madhava Infos\n",
		pmadhava->listener_port_.get_domain(), pmadhava->listener_port_.get_port(), nconnadded, nmadinfo, nmadcli, nmadser);

	return true;
}

bool SHCONN_HANDLER::send_madhava_cli_conn_info(MADHAVA_INFO *pmadhava, const comm::SHYAMA_CLI_TCP_INFO *pone, size_t nconns, POOL_ALLOC_ARRAY *pthrpoolarr)
{
	auto				connshr = pmadhava->get_last_conn(comm::CLI_TYPE_RESP_REQ);
	if (!connshr) {
		return false;
	}

	size_t				fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + nconns * sizeof(SHYAMA_CLI_TCP_INFO);
	FREE_FPTR			free_fp;
	uint32_t			act_size;

	void				*palloc = pthrpoolarr->safe_malloc(fixed_sz, free_fp, act_size, false /* try_other_pools */);

	COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
	EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1);
	SHYAMA_CLI_TCP_INFO		*pconn = reinterpret_cast<SHYAMA_CLI_TCP_INFO *>(pnot + 1);
	
	new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, fixed_sz, connshr->get_comm_magic());
	new (pnot) EVENT_NOTIFY(comm::NOTIFY_SHYAMA_CLI_TCP_INFO, nconns);

	std::memcpy((void *)pconn, pone, nconns * sizeof(SHYAMA_CLI_TCP_INFO));
	
	return schedule_l1_send_data(connshr, comm::COMM_EVENT_NOTIFY, EPOLL_IOVEC_ARR(2, false, palloc, fixed_sz, free_fp, gpadbuf, phdr->get_pad_len(), nullptr));
}	

bool SHCONN_HANDLER::send_madhava_ser_conn_info(MADHAVA_INFO *pmadhava, const comm::SHYAMA_SER_TCP_INFO *pone, size_t nconns, POOL_ALLOC_ARRAY *pthrpoolarr)
{
	auto				connshr = pmadhava->get_last_conn(comm::CLI_TYPE_RESP_REQ);
	if (!connshr) {
		return false;
	}

	size_t				fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + nconns * sizeof(SHYAMA_SER_TCP_INFO);
	FREE_FPTR			free_fp;
	uint32_t			act_size;

	void				*palloc = pthrpoolarr->safe_malloc(fixed_sz, free_fp, act_size, false /* try_other_pools */);

	COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
	EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1);
	SHYAMA_SER_TCP_INFO		*pconn = reinterpret_cast<SHYAMA_SER_TCP_INFO *>(pnot + 1);
	
	new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, fixed_sz, connshr->get_comm_magic());
	new (pnot) EVENT_NOTIFY(comm::NOTIFY_SHYAMA_SER_TCP_INFO, nconns);

	std::memcpy((void *)pconn, pone, nconns * sizeof(SHYAMA_SER_TCP_INFO));
	
	return schedule_l1_send_data(connshr, comm::COMM_EVENT_NOTIFY, EPOLL_IOVEC_ARR(2, false, palloc, fixed_sz, free_fp, gpadbuf, phdr->get_pad_len(), nullptr));
}	


bool SHCONN_HANDLER::madhava_tcp_close(const std::shared_ptr<MADHAVA_INFO> & madhava_shr, const comm::MS_TCP_CONN_CLOSE * ponestart, int nconns)
{
	MADHAVA_INFO		*pmadhava = madhava_shr.get();

	if (!pmadhava) {
		return false;
	}	
	
	RCU_DEFER_OFFLINE		deferlock;

	int				nconnupd = 0;
	auto				pone = ponestart;
	bool				bret;
	
	auto lamtcpc = [&](SHTCP_CONN *ptcp, void *arg1, void *arg2) -> CB_RET_E
	{	
		auto			*ptmp = (const comm::MS_TCP_CONN_CLOSE *)arg1;

		if (ptmp) {
			ptcp->close_cli_bytes_sent_ = ptmp->close_cli_bytes_sent_;
			ptcp->close_cli_bytes_rcvd_ = ptmp->close_cli_bytes_rcvd_;
		}

		return CB_OK;
	};	

	
	for (int i = 0; i < nconns; ++i, ++pone) {
		uint32_t		chash = pone->tup_.get_hash();

		bret = glob_tcp_conn_tbl_.lookup_single_elem(pone->tup_, chash, lamtcpc, (void *)pone);

		nconnupd += int(bret);
	}	

	deferlock.offline_now();

	if (nconnupd > 0 || gdebugexecn > 0) {
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_CYAN, "Madhava %s:%hu TCP Conn Close Notify : Updated %d conns for closure\n", 
			pmadhava->listener_port_.get_domain(), pmadhava->listener_port_.get_port(), nconnupd);
	}

	return true;
}

bool SHCONN_HANDLER::handle_madhava_nat_notify(comm::NAT_TCP_NOTIFY * pone, int nconns, POOL_ALLOC_ARRAY *pthrpoolarr)
{
	SER_INFO_VEC_ARENA		ser_vec_arena;
	CLI_INFO_VEC_ARENA		cli_vec_arena;
	SER_INFO_VEC_MAP_ARENA		ser_map_arena;
	CLI_INFO_VEC_MAP_ARENA		cli_map_arena;
	SER_INFO_VEC_MAP		sermap(ser_map_arena);
	CLI_INFO_VEC_MAP		climap(cli_map_arena);

	NAT_TCP_NOTIFY			*porigone = pone;

	RCU_DEFER_OFFLINE		deferlock;

	const uint64_t			tusec_start = get_usec_time();
	int				nresolved = 0, nmadcli = 0, nmadser = 0;
	bool				brets, bretc;
	PAIR_IP_PORT			corigtup;

	/*
	 * The NAT Messages are from potential intermediate routers and so we use orig_tup_ and nat_tup_ for 2 separate lookups 
	 * to plumb the client and server side.
	 */
	for (int i = 0; i < nconns; ++i, ++pone) {
		SHTCP_CONN			*pconncli = nullptr, *pconnser = nullptr;
		const uint32_t			chash = pone->orig_tup_.get_hash();

		RCU_LOCK_FAST			fastlock;

		auto lamtcpc = [&](SHTCP_CONN *ptcp, void *arg1, void *arg2) -> CB_RET_E
		{	
			pconncli 	= ptcp;

			return CB_OK;
		};	

		bretc = glob_tcp_conn_tbl_.lookup_single_elem(pone->orig_tup_, chash, lamtcpc);
		
		if (!pconncli) {
			continue;
		}	

		const uint32_t			shash = pone->nat_tup_.get_hash();

		auto lamtcps = [&](SHTCP_CONN *ptcp, void *arg1, void *arg2) -> CB_RET_E
		{	
			pconnser 	= ptcp;

			return CB_OK;
		};	

		brets = glob_tcp_conn_tbl_.lookup_single_elem(pone->nat_tup_, shash, lamtcps);

		if (!pconnser) {
			// By this time the server side conn should already have been updated
			glob_tcp_conn_tbl_.delete_elem_locked(pconncli);
			continue;
		}	

		if (pconncli->cli_ser_madhava_shr_ && pconncli->cli_task_aggr_id_ && pconnser->cli_ser_madhava_shr_ && pconnser->ser_glob_id_) {

			auto		madhava_id_cli = pconncli->cli_ser_madhava_shr_->madhava_id_;
			auto		madhava_id_ser = pconnser->cli_ser_madhava_shr_->madhava_id_;

			auto 		[cit, csuccess] = climap.try_emplace(std::move(pconncli->cli_ser_madhava_shr_), cli_vec_arena);
			auto 		& clivec = cit->second;

			clivec.emplace_back(PAIR_IP_PORT(pconncli->cli_, pconncli->ser_), pconnser->ser_glob_id_, madhava_id_ser, pconnser->ser_related_listen_id_, 
				pconnser->ser_nat_ser_, pconncli->cli_task_aggr_id_, pconncli->cli_related_listen_id_, pconncli->cli_ser_partha_machine_id_, pconncli->cli_comm_,
				pconnser->cli_ser_partha_machine_id_, pconncli->close_cli_bytes_sent_, pconncli->close_cli_bytes_rcvd_, pconncli->tusec_mstart_,
				pconnser->cli_ser_cluster_hash_ != pconncli->cli_ser_cluster_hash_, pconnser->ser_comm_, 
				pconnser->cli_ser_cmdline_trunc_, pconnser->cli_ser_cmdline_len_);

			auto 		[sit, ssuccess] = sermap.try_emplace(std::move(pconnser->cli_ser_madhava_shr_), ser_vec_arena);
			auto 		& servec = sit->second;

			servec.emplace_back(pconnser->ser_glob_id_, madhava_id_cli, pconncli->cli_task_aggr_id_, pconncli->cli_related_listen_id_, 
				pconncli->cli_ser_partha_machine_id_, pconnser->ser_comm_, pconnser->cli_ser_partha_machine_id_, pone->orig_tup_.ser_, 
				pconnser->ser_nat_conn_hash_, pconnser->ser_conn_hash_, pconnser->ser_sock_inode_, pconnser->close_cli_bytes_sent_, 
				pconnser->close_cli_bytes_rcvd_, pconnser->ser_tusec_pstart_, pconnser->tusec_mstart_,
				pconncli->cli_comm_, pconncli->cli_ser_cmdline_trunc_, pconncli->cli_ser_cmdline_len_);

			nresolved++;
		}
		
		glob_tcp_conn_tbl_.delete_elem_locked(pconncli);
		glob_tcp_conn_tbl_.delete_elem_locked(pconnser);
	}

	// Now RCU Offline the thread
	deferlock.offline_now();

	for (const auto & epair : climap) {
		const auto & madshr	= epair.first;
		const auto & madvec	= epair.second;

		if (!madshr || madvec.empty()) {
			continue;
		}

		DEBUGEXECN(5,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Sending %lu TCP Conn Client Side Info Messages to Madhava %s\n",
				madvec.size(), madshr->print_string(STRING_BUFFER<256>().get_str_buf()));
		);

		nmadcli += madvec.size();

		send_madhava_cli_conn_info(madshr.get(), madvec.data(), madvec.size(), pthrpoolarr);
	}	

	for (const auto & epair : sermap) {
		const auto & madshr	= epair.first;
		const auto & madvec	= epair.second;

		if (!madshr || madvec.empty()) {
			continue;
		}

		DEBUGEXECN(5,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Sending %lu TCP Conn Server Side Info Messages to Madhava %s\n",
				madvec.size(), madshr->print_string(STRING_BUFFER<256>().get_str_buf()));
		);

		nmadser += madvec.size();

		send_madhava_ser_conn_info(madshr.get(), madvec.data(), madvec.size(), pthrpoolarr);
	}	

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_CYAN, "Received %d NAT Info : %d Conns Resolved, %d Client Side Madhava Infos, %d Server side Madhava Infos\n",
		nconns, nresolved, nmadcli, nmadser);

	return true;
}	

bool SHCONN_HANDLER::handle_madhava_reg_partha(const std::shared_ptr<MADHAVA_INFO> & madhava_shr, const comm::MS_REG_PARTHA * pone, int nelems)
{
	auto				*pmad = madhava_shr.get();
	
	if (!pmad) {
		return false;
	}	

	CONDDECLARE(
	STRING_BUFFER<2048>		strbuf;
	);

	NOTCONDDECLARE(
	STRING_BUFFER<800>		strbuf;
	);
	
	const auto			*pstart = pone;
	PARTHA_INFO			*prawpartha;
	uint64_t			madid = pmad->madhava_id_;
	time_t				tcurr = time(nullptr);
	int				nadded = 0;
	bool				bret;

	RCU_LOCK_SLOW			slowlock;

	for (int i = 0; i < nelems; ++i, ++pone) {
		prawpartha = partha_tbl_.lookup_single_elem_locked(pone->machine_id_, pone->machine_id_.get_hash());
		
		if (prawpartha) {
			continue;
		}
		else {
			// Delete from pardbmap_ if exists
			SCOPE_GY_MUTEX		scopelock(pardb_mutex_);
			
			pardbmap_.erase(pone->machine_id_);
		}	

		PARTHA_INFO 			*pinfo;
		
		pinfo = new PARTHA_INFO();

		pinfo->comm_version_		= pone->comm_version_;
		pinfo->partha_version_		= pone->partha_version_;
		pinfo->machine_id_		= pone->machine_id_;
		
		GY_STRNCPY(pinfo->hostname_, pone->hostname_, sizeof(pinfo->hostname_));
		GY_STRNCPY(pinfo->cluster_name_, pone->cluster_name_, sizeof(pinfo->cluster_name_));

		GY_STRNCPY(pinfo->region_name_, pone->region_name_, sizeof(pinfo->region_name_));
		GY_STRNCPY(pinfo->zone_name_, pone->zone_name_, sizeof(pinfo->zone_name_));
			
		pinfo->new_registered_		= false;
		pinfo->kern_version_num_	= pone->kern_version_num_;

		pinfo->madhava_weak_		= pmad->weak_from_this();
		pinfo->madhava_id_		= pmad->madhava_id_;

		bret = partha_tbl_.insert_unique(pinfo, pone->machine_id_, pone->machine_id_.get_hash());
		if (bret == true) {
			strbuf.appendfmt("\'%s\',", pone->hostname_);
			nadded++;
		}
	}	

	slowlock.unlock();

	if (nadded > 0) {
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Added %d previously registered Partha Host from %s : \nHosts Added : %s\n", 
			nadded, pmad->print_string().get(), strbuf.data());
	}	

	return true;
}

bool SHCONN_HANDLER::handle_ms_partha_ping(const std::shared_ptr<MADHAVA_INFO> & madhava_shr, const comm::MS_PARTHA_PING * pone, int nelems, PGConnPool & dbpool)
{
	auto				*pmad = madhava_shr.get();
	
	if (!pmad) {
		return false;
	}	

	// Need at least 700 KB Stack
	assert(gy_get_thread_local().get_thread_stack_freespace() >= 700 * 1024);

	STRING_BUFFER<512 * 1024>	qbuf;

	const auto			*pstart = pone;
	PARTHA_INFO			*prawpartha;
	uint64_t			madid = pmad->madhava_id_;
	time_t				tcurr = time(nullptr), tdel = tcurr + 3 * GY_SEC_PER_DAY;
	int				nupd = 0, ndel = 0;
	char				delbuf[128];
	bool				bret;

	// Delete DB entry after 3 days
	snprintf(delbuf, sizeof(delbuf), "to_timestamp(%ld)", tdel);

	SCOPE_GY_MUTEX			scopelock(pardb_mutex_);

	RCU_LOCK_SLOW			slowlock;

	qbuf.appendconst("insert into public.parthatbl values ");

	for (int i = 0; i < nelems; ++i, ++pone) {
		prawpartha = partha_tbl_.lookup_single_elem_locked(pone->machine_id_, pone->machine_id_.get_hash());
		
		if (!prawpartha) {
			// Search in pardbmap_
			auto			it = pardbmap_.find(pone->machine_id_);

			if (it != pardbmap_.end()) {
				auto			& dstat = it->second;
				
				if (pone->is_deleted_) {
					if (dstat.tdel_after_ == 0) {
						dstat.tdel_after_ = tdel;

						ndel++;

						qbuf.appendfmt("(\'%s\', \'%s\', \'%s\', \'%s\', \'%016lx\', %s),", pone->machine_id_.get_string().get(), 
							dstat.cluster_name_, dstat.region_name_, dstat.zone_name_, madid, delbuf);
					}	
				}	
				else {
					dstat.madhava_id_ 	= madid;
					dstat.tping_ 		= tcurr;
				}	
			}	

			continue;
		}	

		if (prawpartha->madhava_id_ != madid) {
			continue;
		}	
		
		prawpartha->tdb_updated_.store(tcurr, mo_relaxed);

		if (pone->is_deleted_) {
			ndel++;

			partha_tbl_.delete_elem_locked(prawpartha);

			auto			[it, succ] = pardbmap_.try_emplace(pone->machine_id_, prawpartha->cluster_name_, 
											prawpartha->region_name_, prawpartha->zone_name_, madid, tdel, tcurr);

			if (!succ) {
				auto			& dstat = it->second;
				
				GY_STRNCPY(dstat.cluster_name_, prawpartha->cluster_name_, sizeof(dstat.cluster_name_));
				GY_STRNCPY(dstat.region_name_, prawpartha->region_name_, sizeof(dstat.region_name_));
				GY_STRNCPY(dstat.zone_name_, prawpartha->zone_name_, sizeof(dstat.zone_name_));

				dstat.madhava_id_ 	= madid;
				dstat.tdel_after_	= tdel;
			}	
		}
		else {
			nupd++;
		}

		qbuf.appendfmt("(\'%s\', \'%s\', \'%s\', \'%s\', \'%016lx\', %s),", prawpartha->get_machid_str().get(), 
			prawpartha->cluster_name_, prawpartha->region_name_, prawpartha->zone_name_, madid, 
			pone->is_deleted_ ? delbuf : "NULL");
	}	

	qbuf.set_last_char(' ');

	qbuf.appendconst("on conflict(machid) do update set (clustername, region, zone, madhavaid, del_after) = "
			"(excluded.clustername, excluded.region, excluded.zone, excluded.madhavaid, excluded.del_after);\n");

	slowlock.unlock();

	scopelock.unlock();

	if (gy_unlikely(true == qbuf.is_overflow())) {
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Internal Error : Insert Buffer Overflow while setting Partha Table entries for Madhava %s\n", pmad->get_hostname());
		return false;
	}

	if (nupd + ndel > 0) {	
		auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 30'000 /* max_msec_wait */, true /* reset_on_timeout */);
		
		if (!pconn) {
			db_stats_.nconns_failed_.fetch_add_relaxed(1);
			db_stats_.npartha_failed_.fetch_add_relaxed(1);
			
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to DB Connection while setting Partha Entries for Madhava %s\n", pmad->get_hostname());
			return false;
		}	

		bret = PQsendQueryOptim(pconn->get(), qbuf.buffer(), qbuf.size());

		if (bret == false) {
			db_stats_.npartha_failed_.fetch_add_relaxed(1);

			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to schedule DB query for Partha Entries for Madhava %s due to %s\n", 
					pmad->get_hostname(), PQerrorMessage(pconn->get()));
			return false;
		}	

		pconn->set_resp_cb(
			[this](GyPGConn & conn, GyPGresult gyres, bool is_completed) -> bool
			{
				if (is_completed) {
					if (conn.is_within_tran()) {
						conn.pqexec_blocking("Rollback Work;");
					}						
					conn.make_available();
					return true;
				}	
				
				if (true == gyres.is_error()) {
					db_stats_.npartha_failed_.fetch_add_relaxed(1);
	
					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to insert Madhava Partha Entries into DB due to %s\n", gyres.get_error_msg());
					return false;
				}	

				return true;
			}
		);

		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_CYAN, "%s : Updated %d Partha entries to DB and deleted %d Partha hosts\n",
			pmad->print_string().get(), nupd, ndel);
	}	
	
	return true;
}	

bool SHCONN_HANDLER::handle_cluster_state(const std::shared_ptr<MADHAVA_INFO> & madhava_shr, comm::MS_CLUSTER_STATE * pone, int nconns, uint8_t *pendptr, POOL_ALLOC_ARRAY *pthrpoolarr)
{
	MADHAVA_INFO			*pmadhava = madhava_shr.get();

	if (!pmadhava) {
		return false;
	}	
	
	auto				*porigone = pone;	
	time_t				tcurr = time(nullptr);
	
	SCOPE_GY_MUTEX			scopelock(&pmadhava->cluststate_mutex_);

	pmadhava->tclustersec_		= tcurr;

	for (int i = 0; i < nconns; ++i, ++pone) {
		auto 			[it, success] = pmadhava->clusterstatemap_.try_emplace(pone->clustname_, pone->state_);

		if (!success) {
			// Aggregation pending. Overwrite
			auto			&state = it->second;
			
			state = pone->state_;
		}	
	}	

	return true;
}	

void SHCONN_HANDLER::aggregate_cluster_state(bool to_print) noexcept
{
	try {
		AggrClusterStateMap		clustermap;
		int				nmadhava = 0;
		
		clustermap.reserve(64);

		auto lammad = [&](MADHAVA_INFO_ELEM *pdatanode, void *arg1) -> CB_RET_E
		{
			auto				pmadhava = pdatanode->get_data()->get();
			
			if (gy_unlikely(pmadhava == nullptr)) {
				return CB_OK;
			}	

			SCOPE_GY_MUTEX			scopelock(&pmadhava->cluststate_mutex_);
			
			/*pmadhava->clusternameset_.clear();*/
			/*pmadhava->clusternameset_.reserve(pmadhava->clusterstatemap_.size());*/

			for (const auto & [cname, cstate] : pmadhava->clusterstatemap_) {
				auto 			[it, success] = clustermap.try_emplace(cname, cstate);

				if (!success) {
					auto			&state = it->second;
					
					state.add_stats(cstate);
				}	

				/*pmadhava->clusternameset_.emplace(cname);*/
			}	
			
			if (pmadhava->clusterstatemap_.size() > 0) {
				nmadhava++;
			}

			pmadhava->clusterstatemap_.clear();

			return CB_OK;
		};

		madhava_tbl_.walk_hash_table(lammad);

		time_t				tcurr = time(nullptr);

		SCOPE_GY_MUTEX			scopelock(&cluststate_mutex_);

		clusterstatemap_		= clustermap;	// Copy

		tclustersec_.store(tcurr, mo_relaxed);

		scopelock.unlock();

		if (clustermap.size() == 0) {
			return;
		}

		auto				pconn = dbmain_scheduler_pool_->get_conn(true /* wait_response_if_unavail */, 3000 /* max_msec_wait */, false /* reset_on_timeout */);
		
		if (!pconn) {
			db_stats_.nconns_failed_.fetch_add_relaxed(1);
			db_stats_.ncluster_state_failed_.fetch_add_relaxed(1);
			
			DEBUGEXECN(5,
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get DB Conn for Cluster State updation\n");
			);
			return;
		}	
		
		assert(gy_get_thread_local().get_thread_stack_freespace() >= 600 * 1024);

		// Max cluster count of 4000-5000 supported...
		STRING_BUFFER<512 * 1024>	qbuf;

		auto				datetbl = get_db_day_partition(tcurr, 15);
		bool				bret;
		uint64_t			nhosts = 0, nsvc = 0, total_qps = 0, svc_net_mb = 0;

		qbuf.appendfmt("insert into public.clusterstatetbl%s values ", datetbl.get());

		for (const auto & [name, state] : clustermap) {
			qbuf.appendfmt("(to_timestamp(%ld),\'%s\',%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d),", 
				tcurr, name.get(), state.nhosts_, state.ntasks_issue_, state.ntaskissue_hosts_, state.ntasks_, state.nsvc_issue_, 
				state.nsvcissue_hosts_, state.nsvc_, state.total_qps_, state.svc_net_mb_, state.ncpu_issue_, state.nmem_issue_);

			nhosts 		+= state.nhosts_;
			nsvc		+= state.nsvc_;
			total_qps	+= state.total_qps_;
			svc_net_mb	+= state.svc_net_mb_;

			if (qbuf.bytes_left() < 200) {
				break;
			}	
		}	

		qbuf.set_last_char(';');

		if (gy_unlikely(true == qbuf.is_overflow())) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Internal Error : Cluster State DB insert buffer overflow occured\n");
			return;
		}

		bret = PQsendQueryOptim(pconn->get(), qbuf.buffer(), qbuf.size());
		
		if (bret == false) {
			db_stats_.ncluster_state_failed_.fetch_add_relaxed(1);

			DEBUGEXECN(5,
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to schedule DB query to update Cluster State due to %s\n", PQerrorMessage(pconn->get()));
			);

			return;
		}	

		pconn->set_resp_cb(
			[this](GyPGConn & conn, GyPGresult gyres, bool is_completed) -> bool
			{
				if (is_completed) {
					if (conn.is_within_tran()) {
						conn.pqexec_blocking("Rollback Work;");
					}						

					conn.make_available();
					return true;
				}	
				
				if (true == gyres.is_error()) {
					db_stats_.ncluster_state_failed_.fetch_add_relaxed(1);

					DEBUGEXECN(5,
						ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to insert Cluster State into DB due to %s\n", gyres.get_error_msg());
					);

					return false;
				}	

				return true;
			}
		);

		if (to_print) {
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Aggregated Cluster State Stats : %lu Clusters, %lu Hosts, %lu Services, %lu Total QPS, %lu MB Service Network Traffic from %d Madhava\'s\n",
				clustermap.size(), nhosts, nsvc, total_qps, svc_net_mb, nmadhava);
		}	
		
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while Aggregating Cluster State Stats : %s\n", GY_GET_EXCEPT_STRING);
	);
}


bool SHCONN_HANDLER::handle_svc_cluster_mesh(const std::shared_ptr<MADHAVA_INFO> & madhava_shr, comm::MS_SVC_CLUSTER_MESH * pone, int nconns, uint8_t *pendptr, POOL_ALLOC_ARRAY *pthrpoolarr)
{
	MADHAVA_INFO			*pmadhava = madhava_shr.get();

	if (!pmadhava) {
		return false;
	}	
	
	auto				*porigone = pone;	
	int				newelem = 0, newclust = 0, newclustid = 0;
	time_t				tcurr = time(nullptr);

	RCU_LOCK_SLOW			slowlock;

	for (int i = 0; i < nconns && (const uint8_t *)pone < pendptr; ++i, pone = (decltype(pone))((uint8_t *)pone + pone->get_elem_size())) {
		
		SvcClusterMapsOne		*pcluster;
		ClusterNameBuf			clustbuf(pone->cluster_name_);
		const uint64_t			clusthash = clustbuf.get_hash();

		pcluster = svcclusters_.lookup_single_elem_locked(clustbuf, clusthash);

		if (gy_unlikely(nullptr == pcluster)) {
			
			pcluster = new SvcClusterMapsOne(clustbuf.get(), tcurr);

			auto clam = [&](SvcClusterMapsOne *poldelem, SvcClusterMapsOne *pnewelem) 
			{
				pcluster 	= poldelem;
			};	

			newclustid += svcclusters_.insert_unique(pcluster, clustbuf, clusthash, clam, true /* delete_after_callback */);
		}	

		pcluster->tlast_upd_.store(tcurr, mo_relaxed);
		
		if (pone->ncluster_elems_ == 0 || pone->svc_cluster_id_ == 0) {
			continue;
		}

		auto			& meshtbl = pcluster->meshtbl_;

		RELSVC_CLUSTER_ONE	*porigrel = (RELSVC_CLUSTER_ONE *)(pone + 1), *prelsvc = porigrel;
		uint64_t		svc_cluster_id = pone->svc_cluster_id_;
		SvcClusterMeshOne	*pmeshone = nullptr;
		uint32_t		nid_found = 0;

		pmeshone = meshtbl.lookup_single_elem_locked(svc_cluster_id, get_uint64_hash(svc_cluster_id));

		if (!pmeshone) {
			pmeshone = new SvcClusterMeshOne(svc_cluster_id, pone->cluster_name_, pone->init_comm_, tcurr);

			auto newlam = [&](SvcClusterMeshOne *poldelem, SvcClusterMeshOne *pnewelem)
			{
				pmeshone = poldelem;
			};
			
			newclustid += meshtbl.insert_unique(pmeshone, svc_cluster_id, get_uint64_hash(svc_cluster_id), newlam, true /* delete_after_callback */);
		}	

		pmeshone->tlast_upd_.store(tcurr, mo_relaxed);

		/*
		 * Now update the elems
		 */
		prelsvc = porigrel;

		SCOPE_GY_MUTEX		scopelock(&pmeshone->elemmutex_);

		for (uint32_t c = 0; c < pone->ncluster_elems_; ++c, ++prelsvc) {
			auto			[it, succ] = pmeshone->elemtbl_.try_emplace(*prelsvc, pone->init_comm_, tcurr);

			newelem 		+= succ;
			it->second.tlast_upd_ 	= tcurr;
		}	

		scopelock.unlock();
	}

	slowlock.unlock();

	if (newelem > 0) {
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "%s : Received %d new Svc Cluster Mesh Elements, %d new Svc Cluster IDs, %d new Clusters\n",
			pmadhava->print_string(STRING_BUFFER<512>().get_str_buf()), newelem, newclustid, newclust);
	}	

	return true;

}	

// Called under RCU Read Lock
CB_RET_E SHCONN_HANDLER::coalesce_svc_mesh_locked(SvcClusterMapsOne *pcluster, MadCacheMap & madcachemap, StringHeapVec & dbstrvec, const char *ptimestr, const char *pdatestr)
{
	using RelMeshMap 		= INLINE_STACK_HASH_MAP<RELSVC_CLUSTER_ONE, SvcClusterMeshOne *, 300 * 1024, RELSVC_CLUSTER_ONE::RHash>;

	EXEC_TIME			exectime;
	RelMeshMap			relmap;
	uint64_t			ntotal;
	int				nmerge = 0;
	const time_t			tcurr = time(nullptr), tcutoff = tcurr - 250;

	assert(gy_get_thread_local().get_thread_stack_freespace() >= 500 * 1024);

	if (true) {
		using RelMeshVec 		= INLINE_STACK_VECTOR<RELSVC_CLUSTER_ONE, 200 * 1024>;

		RelMeshVec			relvec;

		/*
		 * Two pass scans of the pcluster->meshtbl_ :
		 * First scan the mesh elements which had their eff_cluster_id_ updated previously so that we can maintain
		 * continuity of cluster ids.
		 */
		const auto mwalk = [&](SvcClusterMeshOne *pmesh, void *arg) -> CB_RET_E
		{
			if (arg == nullptr) {
				// First pass

				if (pmesh->tlast_upd_.load(mo_relaxed) < tcutoff) {
					return CB_DELETE_ELEM;
				}

				if (pmesh->eff_cluster_id_ == 0) {
					return CB_OK;
				}	
			}
			else {
				if (pmesh->eff_cluster_id_ == 0) {
					pmesh->eff_cluster_id_ = pmesh->svc_cluster_id_;
				}
				else {
					// Already handled
					return CB_OK;
				}	
			}	

			relvec.clear();
			
			SCOPE_GY_MUTEX			scopelock(&pmesh->elemmutex_);

			relvec.reserve(pmesh->elemtbl_.size());

			for (auto rit = pmesh->elemtbl_.begin(); rit != pmesh->elemtbl_.end(); ) {
				auto			& rel = rit->first;
				auto			& elem = rit->second;
				
				if (elem.tlast_upd_ < tcutoff) {
					rit = pmesh->elemtbl_.erase(rit);
					continue;
				}	
				
				relvec.emplace_back(rel);
				++rit;
			}	

			scopelock.unlock();
			
			for (const auto & rel : relvec) {
				auto		[it, succ] = relmap.try_emplace(rel, pmesh);

				if (!succ) {
					// This elem is already part of another cluster. Merge the eff_cluster_id_
					if (it->second->eff_cluster_id_ != pmesh->eff_cluster_id_) {
						pmesh->eff_cluster_id_ = it->second->eff_cluster_id_;
						nmerge++;
					}
				}	
			}
			
			return CB_OK;
		};
		
		pcluster->meshtbl_.walk_hash_table(mwalk, nullptr);

		// Second pass
		ntotal = pcluster->meshtbl_.walk_hash_table(mwalk, pcluster);
	}

	if (ntotal > 0) {
		/*
		 * Now update the madcachemap...
		 */
		struct IdComm
		{
			uint64_t		eff_cluster_id_			{0};
			char			init_comm_[TASK_COMM_LEN];

			IdComm(uint64_t eff_cluster_id, const char *init_comm) noexcept
				: eff_cluster_id_(eff_cluster_id)
			{
				std::memcpy(init_comm_, init_comm, sizeof(init_comm_));
			}	

			IdComm(uint64_t eff_cluster_id) noexcept
				: eff_cluster_id_(eff_cluster_id)
			{
				*init_comm_ = 0;
			}

			struct IHash
			{
				size_t operator()(const IdComm & one) const noexcept
				{
					return get_uint64_hash(one.eff_cluster_id_);
				}	
			};	

			bool operator==(const IdComm & other) const noexcept
			{
				return eff_cluster_id_ == other.eff_cluster_id_;
			}	
		};	

		using MeshIDVec				= GY_STACK_VECTOR<const RELSVC_CLUSTER_ONE *, 180 * 1024>; 
		using MeshIDVecArena			= MeshIDVec::allocator_type::arena_type;
	
		using MeshIDMap 			= INLINE_STACK_HASH_MAP<IdComm, MeshIDVec, 120 * 1024, IdComm::IHash>;
		
		using MadCntMap				= INLINE_STACK_HASH_MAP<uint64_t, size_t, 24 * 1024, GY_JHASHER<uint64_t>>;
		using MadCntSet				= INLINE_STACK_HASH_SET<uint64_t, 16 * 1024, GY_JHASHER<uint64_t>>;
		 
		using MeshStatSet			= INLINE_STACK_HASH_SET<ClusterMeshStat, 50 * 1024, ClusterMeshStat::SHash>; 

		MeshIDVecArena				meshvecarena;
		MeshIDMap				meshidmap; 	
		MadCntMap				madcntmap;
		MeshStatSet				meshstatset;

		CONDDECLARE(
			STRING_BUFFER<4096>		strbuf;
		);

		NOTCONDDECLARE(
			STRING_BUFFER<1024>		strbuf;
		);

		assert(gy_get_thread_local().get_thread_stack_freespace() >= 120 * 1024);

		for (const auto & [clone, pmesh] : relmap) {
			auto			[it, succ] = meshidmap.try_emplace(IdComm(pmesh->eff_cluster_id_, pmesh->init_comm_), meshvecarena);

			it->second.emplace_back(&clone);

			auto			[mit, msucc] = madcntmap.try_emplace(clone.madhava_id_);

			mit->second++;
		}	

		meshstatset.reserve(meshidmap.size());

		STRING_HEAP			*pdbstr = std::addressof(dbstrvec.at(dbstrvec.size() - 1).value());
		size_t				lastdbstrsz = GY_UP_MB(2);
		char				*poutstr;
		uint32_t			nrows = 0;
		bool				retrystr = false, stmtstart = false;

		// DB String Overflow callback
		const auto dbstrovf = [&](const char * pstr, size_t szstr, bool istrunc, bool newupdates) -> bool
		{
			if (istrunc == false) {
				DEBUGEXECN(1,
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Svc Cluster Mesh : Overflow of DB Query Buffer seen. Allocating new element #%lu : \n", 
							dbstrvec.size() + 1);
				);	

				retrystr 	= !newupdates;
			}
			else {
				retrystr 	= true;
				lastdbstrsz 	+= GY_UP_KB(256);

				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Svc Cluster Mesh : Overflow of DB Query Buffer seen as single query too large. "
					"Resetting element #%lu and retrying in a new buffer of size %lu : \n", dbstrvec.size(), lastdbstrsz);

				pdbstr->reset();
				
				GY_CC_BARRIER();

				pdbstr->get_unique_ptr().reset();

				GY_CC_BARRIER();
			}	

			auto			& optelem = dbstrvec.emplace_back(std::in_place, lastdbstrsz); 
			
			pdbstr = std::addressof(optelem.value());
			
			return false;
		};

		for (const auto & [idcomm, idvec] : meshidmap) {
			if (idvec.size() <= 1) {
				continue;
			}

			MadCntMap			onemadcntmap;
			MadCntSet			onemadcntset;
			uint32_t			szmax, num = 0, vecsize = idvec.size();

			retrystr = false;
			lastdbstrsz = GY_UP_MB(2);
			
			if (stmtstart == false) {
				stmtstart = true;
retry0 :
				poutstr = pdbstr->appendcb(dbstrovf, "insert into public.svcmeshtbl values "sv);

				if (!poutstr && retrystr) {
					retrystr = false;
					goto retry0;
				}	
			}	

retry1 :			
			poutstr = pdbstr->appendfmtcb(dbstrovf, "%c(\'%s\',\'%016lx\',\'%s\',\'%s\',%d,\'[", 
						nrows++ == 0 ? ' ' : ',', ptimestr, idcomm.eff_cluster_id_, idcomm.init_comm_, pcluster->cluster_.get(), int(vecsize));
			if (!poutstr && retrystr) {
				retrystr = false;
				goto retry1;
			}	

			for (const auto *pclone : idvec) {
				auto			[it, succ] = onemadcntmap.try_emplace(pclone->madhava_id_);

				it->second++;

retry2 :
				poutstr = pdbstr->appendfmtcb(dbstrovf, "{\"parid\":\"%016lx%016lx\",\"madid\":\"%016lx\",\"relid\":\"%016lx\"}%c", 
					pclone->partha_machine_id_.get_first(), pclone->partha_machine_id_.get_second(), pclone->madhava_id_, pclone->related_listen_id_,
					++num < vecsize ? ',' : ' ');

				if (!poutstr && retrystr) {
					retrystr = false;
					goto retry2;
				}	
			}	

retry3 :
			poutstr = pdbstr->appendcb(dbstrovf, "]\')"sv); 
			
			if (!poutstr && retrystr) {
				retrystr = false;
				goto retry3;
			}	

			meshstatset.emplace(idcomm.eff_cluster_id_, idvec.size(), onemadcntmap.size(), idcomm.init_comm_);

			strbuf.appendfmt("[Svc Cluster for %s #Svcs %lu #Madhava %lu], ", idcomm.init_comm_, idvec.size(), onemadcntmap.size());

			for (const auto *pclone : idvec) {
				auto			[it, succ] = madcachemap.try_emplace(pclone->madhava_id_);

				auto			& streambuf = it->second;

				if (succ) {
					MADHAVA_INFO_ELEM		*pmadelem = madhava_tbl_.lookup_single_elem_locked(pclone->madhava_id_, get_uint64_hash(pclone->madhava_id_));

					if (pmadelem) {
						auto			pmad = pmadelem->get_cref().get();

						if (pmad) {
							auto		madshrconn = pmad->get_last_conn(comm::CLI_TYPE_RESP_REQ);

							if (madshrconn) {
								streambuf.emplace(std::move(madshrconn), *this, NOTIFY_SM_SVC_CLUSTER_MESH, SM_SVC_CLUSTER_MESH::MAX_NUM_CLUSTERS);

								auto		mit = madcntmap.find(pclone->madhava_id_);

								if (mit != madcntmap.end() && mit->second > 0) {
									// Preallocate this cluster elems for this madhava as this is the first allocation
									streambuf->get_buf(mit->second * sizeof(RELSVC_CLUSTER_ONE) + 3 * sizeof(SM_SVC_CLUSTER_MESH), szmax);

									mit->second = 0;
								}	
							}	
						}	
					}
				}

				if (!bool(streambuf)) {
					continue;
				}	

				auto			oit = onemadcntmap.find(pclone->madhava_id_);

				if ((oit == onemadcntmap.end()) || (oit->second == 0) || (oit->second > idvec.size())) {
					continue;
				}	

				auto			[sit, isnew] = onemadcntset.emplace(pclone->madhava_id_);

				if (isnew) {
					uint32_t	minsz = sizeof(SM_SVC_CLUSTER_MESH) + oit->second * sizeof(RELSVC_CLUSTER_ONE);
					auto		*psvcmesh = (SM_SVC_CLUSTER_MESH *)streambuf->get_buf(minsz, szmax);

					new (psvcmesh) SM_SVC_CLUSTER_MESH(idcomm.eff_cluster_id_, idvec.size(), oit->second, pcluster->cluster_.get(), idcomm.init_comm_);
					new (psvcmesh + 1) RELSVC_CLUSTER_ONE(*pclone);

					streambuf->set_buf_sz(sizeof(SM_SVC_CLUSTER_MESH) + sizeof(RELSVC_CLUSTER_ONE), 1 /* nevents */);
				}	
				else {
					auto		*pone = (RELSVC_CLUSTER_ONE *)streambuf->get_buf(sizeof(RELSVC_CLUSTER_ONE), szmax);

					new (pone) RELSVC_CLUSTER_ONE(*pclone);

					streambuf->set_buf_sz(sizeof(RELSVC_CLUSTER_ONE), 0 /* nevents */);
				}	
			}
		}	

		if (stmtstart == true) {
retry4 :
			poutstr = pdbstr->appendcb(dbstrovf, ";\n"sv); 
			
			if (!poutstr && retrystr) {
				retrystr = false;
				goto retry4;
			}	
		}	

		SharedMutex::WriteHolder	scopelock(pcluster->meshrwlock_);

		pcluster->meshstatmap_.clear();
		pcluster->meshstatmap_.reserve(meshidmap.size());

		for (const auto & [idcomm, idvec] : meshidmap) {
			if (idvec.size() <= 1) {
				continue;
			}

			auto			sit = meshstatset.find(idcomm.eff_cluster_id_);

			if (sit == meshstatset.end()) {
				continue;
			}	

			auto			[mit, succ] = pcluster->meshstatmap_.try_emplace(*sit);
			auto			& mvec = mit->second;

			mvec.reserve(idvec.size());

			for (const auto *pclone : idvec) {
				mvec.emplace_back(*pclone);
			}	
		}

		scopelock.unlock();

		auto [cnsec, cmsec, csec] = exectime.get_profile_times();

		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Cluster %s : Cluster Mesh Listeners Total %lu : Time for execution = %lu nsec (%lu msec) : List of Mesh Svcs : %s\n", 
				pcluster->cluster_.get(), meshidmap.size(), cnsec, cmsec, strbuf.buffer());
	}
	else {
		SharedMutex::WriteHolder	scopelock(pcluster->meshrwlock_);

		pcluster->meshstatmap_.clear();
	}	

	return CB_OK;
}	

void SHCONN_HANDLER::coalesce_svc_mesh_clusters() noexcept
{
	try {
		if (svcclusters_.template is_empty<RCU_LOCK_SLOW>()) {
			return;
		}

		uint64_t			ntotal;
		StringHeapVec			dbstrvec;			
		EXEC_TIME			exectime;
		time_t				tcurr = time(nullptr), tmeshcutoff = tcurr - 350, tnatcutoff = tcurr - 650, tdaystart = 0;
		MadCacheMap			madcachemap;
		const auto			timebuf = gy_localtime_iso8601_sec(tcurr);
		const auto			datetbl = get_db_day_partition(tcurr, tcurr, 15, &tdaystart);

		dbstrvec.reserve(std::min(svcclusters_.approx_count_fast() + 1, 16lu));

		dbstrvec.emplace_back(std::in_place, GY_UP_MB(2)); 

		const auto swalk = [&](SvcClusterMapsOne *pcluster, void *arg) noexcept -> CB_RET_E
		{
			try {
				time_t			tlast = pcluster->tlast_upd_.load(mo_relaxed);

				if (tlast < tmeshcutoff) {
					if (tlast > tnatcutoff) {
						if (false == pcluster->natiptbl_.is_empty()) {
							return CB_OK;
						}	
					}	

					return CB_DELETE_ELEM;
				}

				return coalesce_svc_mesh_locked(pcluster, madcachemap, dbstrvec, timebuf.get(), datetbl.get());
			}
			GY_CATCH_EXCEPTION(
				ERRORPRINT_OFFLOAD("Exception caught while coalescing Cluster %s Mesh Listeners : %s\n", pcluster->cluster_.get(), GY_GET_EXCEPT_STRING);
				return CB_OK;
			);

		};	
		
		ntotal = svcclusters_.walk_hash_table(swalk);

		if (ntotal > 0) {
			/*
			 * Now Update the Postgres DB. The query strings are already updated within dbstrvec
			 */
			 
			struct iovec			*piovarr;
			int				j = 1;
			bool				ismalloc, bret;

			SAFE_STACK_ALLOC(piovarr, (dbstrvec.size() + 2) * sizeof(iovec), ismalloc);

			piovarr[0].iov_base		= (void *)"Begin Work;";
			piovarr[0].iov_len		= GY_CONST_STRLEN("Begin Work;");

			for (size_t i = 0; i < dbstrvec.size(); ++i) {
				const auto 		& optstr = dbstrvec[i];
				
				if (bool(optstr) && optstr->buffer() && optstr->length()) {
					piovarr[j].iov_base 	= (void *)optstr->buffer();
					piovarr[j].iov_len	= optstr->length();
					j++;
				}	
			}

			if (j == 1) {
				goto done1;
			}	

			piovarr[j].iov_base		= (void *)"Commit Work;";
			piovarr[j].iov_len		= GY_CONST_STRLEN("Commit Work;");
			j++;

			auto				pconn = dbmain_scheduler_pool_->get_conn(true /* wait_response_if_unavail */, 60'000 /* max_msec_wait */, true /* reset_on_timeout */);
			
			if (!pconn) {
				db_stats_.nconns_failed_.fetch_add_relaxed(1);
				db_stats_.ncluster_mesh_failed_.fetch_add_relaxed(1);
				
				DEBUGEXECN(5,
					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get DB Conn for Cluster Svc Mesh updation\n");
				);
				
				goto done1;
			}	
		
			bret = PQsendIovecQueryOptim(pconn->get(), piovarr, j);
			
			if (bret == false) {
				db_stats_.ncluster_mesh_failed_.fetch_add_relaxed(1);

				DEBUGEXECN(5,
					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to schedule DB query to update Cluster Svc Mesh due to %s\n", 
						PQerrorMessage(pconn->get()));
				);

				goto done1;
			}	

			pconn->set_resp_cb(
				[this](GyPGConn & conn, GyPGresult gyres, bool is_completed) -> bool
				{
					if (is_completed) {
						if (conn.is_within_tran()) {
							conn.pqexec_blocking("Rollback Work;");
						}						

						conn.make_available();
						return true;
					}	
					
					if (true == gyres.is_error()) {
						db_stats_.ncluster_mesh_failed_.fetch_add_relaxed(1);

						DEBUGEXECN(5,
							ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to insert Cluster Svc Mesh into DB due to %s\n", gyres.get_error_msg());
						);

						return false;
					}	

					return true;
				}
			);
		}

done1 :		
		auto [cnsec, cmsec, csec] = exectime.get_profile_times();

		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Clustered Mesh Listeners Coalesecing : Total Clusters seen %lu : Time for execution = %lu nsec (%lu msec)\n",
			ntotal, cnsec, cmsec);

	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT_OFFLOAD("Exception caught while coalescing Clustered Mesh Listeners : %s\n", GY_GET_EXCEPT_STRING);
	);
}	

void SHCONN_HANDLER::handle_svc_nat_ip(const std::shared_ptr<MADHAVA_INFO> & madhava_shr, comm::MS_LISTENER_NAT_IP * pone, int nconns, uint8_t *pendptr, POOL_ALLOC_ARRAY *pthrpoolarr)
{
	MADHAVA_INFO			*pmadhava = madhava_shr.get();

	if (!pmadhava) {
		return;
	}	

	auto				*porigone = pone;	
	int				newelem = 0, delelem = 0, newclustid = 0, newclust = 0;
	time_t				tcurr = time(nullptr);

	RCU_LOCK_SLOW			slowlock;

	for (int i = 0; i < nconns && (const uint8_t *)pone < pendptr; ++i, pone = (decltype(pone))((uint8_t *)pone + pone->get_elem_size())) {
		
		SvcClusterMapsOne		*pcluster;
		ClusterNameBuf			clustbuf(pone->cluster_name_);
		const uint64_t			clusthash = clustbuf.get_hash();

		pcluster = svcclusters_.lookup_single_elem_locked(clustbuf, clusthash);

		if (gy_unlikely(nullptr == pcluster)) {
			
			pcluster = new SvcClusterMapsOne(clustbuf.get(), tcurr);

			auto clam = [&](SvcClusterMapsOne *poldelem, SvcClusterMapsOne *pnewelem) 
			{
				pcluster 	= poldelem;
			};	

			newclust += svcclusters_.insert_unique(pcluster, clustbuf, clusthash, clam, true /* delete_after_callback */);
		}	

		pcluster->tlast_upd_.store(tcurr, mo_relaxed);
		
		auto			& natiptbl = pcluster->natiptbl_;

		/*
		 * First delete the nelems_del_ entries
		 */
		IP_PORT			*pnewip = nullptr, *pdelip = nullptr, *pstartip = (IP_PORT *)(pone + 1);
		SvcNatIPOne		*pnatone;

		if (pone->nelems_del_ > 0) {
			pdelip = pstartip + pone->nelems_new_;
			
			for (uint8_t n = 0; n < pone->nelems_del_; ++n, ++pdelip) {
				NatIPComm		natcomm(*pdelip, pone->comm_, clusthash);	

				pnatone = natiptbl.lookup_single_elem_locked(natcomm, natcomm.get_hash());
				if (!pnatone) {
					continue;
				}	

				pnatone->tlast_upd_.store(tcurr, mo_relaxed);
				
				delelem += pnatone->elemtbl_.delete_single_elem(pone->glob_id_, get_uint64_hash(pone->glob_id_));
			}
		}	

		if (pone->nelems_new_ > 0) {
			pnewip = pstartip;
			
			for (uint8_t n = 0; n < pone->nelems_new_; ++n, ++pnewip) {
				NatIPComm		natcomm(*pnewip, pone->comm_, clusthash);	

				pnatone = natiptbl.lookup_single_elem_locked(natcomm, natcomm.get_hash());
				if (!pnatone) {
					pnatone = new SvcNatIPOne(natcomm, tcurr);

					auto newlam = [&](SvcNatIPOne *poldelem, SvcNatIPOne *pnewelem)
					{
						pnatone = poldelem;
					};

					newclustid += natiptbl.insert_unique(pnatone, natcomm, natcomm.get_hash(), newlam, true /* delete_after_callback */);
				}	

				pnatone->tlast_upd_.store(tcurr, mo_relaxed);

				SvcNatElem		*pelemone;

				pelemone = pnatone->elemtbl_.lookup_single_elem_locked(pone->glob_id_, get_uint64_hash(pone->glob_id_));

				if (!pelemone) {
					pelemone = new SvcNatElem(pone->partha_machine_id_, pone->madhava_id_, pone->glob_id_, tcurr);

					auto newlam = [&](SvcNatElem *poldelem, SvcNatElem *pnewelem)
					{
						pelemone = poldelem;
					};

					newelem += pnatone->elemtbl_.insert_unique(pelemone, pone->glob_id_, get_uint64_hash(pone->glob_id_), newlam, true /* delete_after_callback */);
				}	
				
				pelemone->tlast_upd_.store(tcurr, mo_relaxed);
			}
		}	
	}

	slowlock.unlock();

	if (newelem + delelem > 0) {
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "%s : Received %d new Svc NAT IP Elements, %d new Svc NAT IPs, %d new Clusters and Deleted %d Svc NAT IP Elements\n",
			pmadhava->print_string(STRING_BUFFER<512>().get_str_buf()), newelem, newclustid, newclust, delelem);
	}	
}

// Called under RCU Read Lock
CB_RET_E SHCONN_HANDLER::check_svc_nat_ip_locked(SvcClusterMapsOne *pcluster, MadCacheMap & madcachemap, StringHeapVec & dbstrvec, const char *ptimestr, const char *pdatestr)
{
	using MadCntMap			= INLINE_STACK_HASH_MAP<uint64_t, size_t, 16 * 1024, GY_JHASHER<uint64_t>>;

	MadCntMap			madcntmap;
	EXEC_TIME			exectime;
	uint64_t			ntotal, nclustsvc = 0, nclustelem, ndel;
	const time_t			tcurr = time(nullptr), tcutoff = tcurr - 650;

	CONDDECLARE(
		STRING_BUFFER<4096>		strbuf;
	);

	NOTCONDDECLARE(
		STRING_BUFFER<1024>		strbuf;
	);

	assert(gy_get_thread_local().get_thread_stack_freespace() >= 500 * 1024);

	STRING_HEAP			*pdbstr = std::addressof(dbstrvec.at(dbstrvec.size() - 1).value());
	size_t				lastdbstrsz = GY_UP_MB(2);
	char				*poutstr;
	uint32_t			nrows = 0, ncols = 0;
	bool				retrystr = false, stmtstart = false;

	// DB String Overflow callback
	const auto dbstrovf = [&](const char * pstr, size_t szstr, bool istrunc, bool newupdates) -> bool
	{
		if (istrunc == false) {
			DEBUGEXECN(1,
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Svc Cluster Nat IP : Overflow of DB Query Buffer seen. Allocating new element #%lu : \n", 
						dbstrvec.size() + 1);
			);	

			retrystr 	= !newupdates;
		}
		else {
			retrystr 	= true;
			lastdbstrsz 	+= GY_UP_KB(256);

			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Svc Cluster Nat IP : Overflow of DB Query Buffer seen as single query too large. "
				"Resetting element #%lu and retrying in a new buffer of size %lu : \n", dbstrvec.size(), lastdbstrsz);

			pdbstr->reset();
			
			GY_CC_BARRIER();

			pdbstr->get_unique_ptr().reset();

			GY_CC_BARRIER();
		}	

		auto			& optelem = dbstrvec.emplace_back(std::in_place, lastdbstrsz); 
		
		pdbstr = std::addressof(optelem.value());
		
		return false;
	};

	const auto ewalk = [&, tcutoff](SvcNatElem *pelem, void *arg) -> CB_RET_E
	{
		SvcNatIPOne		*pnat = static_cast<SvcNatIPOne *>(arg);

		if (!pnat) {
			// First pass
			if (pelem->tlast_upd_.load(mo_relaxed) < tcutoff) {
				return CB_DELETE_ELEM;
			}

			auto			[mit, msucc] = madcntmap.try_emplace(pelem->madhava_id_);

			mit->second++;

			return CB_OK;
		}

retry2 :
		poutstr = pdbstr->appendfmtcb(dbstrovf, "%c{\"parid\":\"%016lx%016lx\",\"madid\":\"%016lx\",\"svcid\":\"%016lx\"}", 
			ncols++ == 0 ? ' ' : ',', pelem->partha_machine_id_.get_first(), pelem->partha_machine_id_.get_second(), pelem->madhava_id_, pelem->glob_id_);

		if (!poutstr && retrystr) {
			retrystr = false;
			goto retry2;
		}	
		
		auto				[it, succ] = madcachemap.try_emplace(pelem->madhava_id_);

		auto				& streambuf = it->second;
		uint32_t			szmax;

		if (succ) {
			MADHAVA_INFO_ELEM		*pmadelem = madhava_tbl_.lookup_single_elem_locked(pelem->madhava_id_, get_uint64_hash(pelem->madhava_id_));

			if (pmadelem) {
				auto			pmad = pmadelem->get_cref().get();

				if (pmad) {
					auto		madshrconn = pmad->get_last_conn(comm::CLI_TYPE_RESP_REQ);

					if (madshrconn) {
						streambuf.emplace(std::move(madshrconn), *this, NOTIFY_SM_SVC_NAT_IP_CLUSTER, SM_SVC_NAT_IP_CLUSTER::MAX_NUM_LISTENERS);

						auto		mit = madcntmap.find(pelem->madhava_id_);

						if (mit != madcntmap.end() && mit->second > 0) {
							// Preallocate this cluster elems for this madhava as this is the first allocation
							streambuf->get_buf(mit->second * sizeof(SM_SVC_NAT_IP_CLUSTER), szmax);
						}	
					}	
				}	
			}
		}

		if (!bool(streambuf)) {
			return CB_OK;
		}	

		auto			*psvcnat = (SM_SVC_NAT_IP_CLUSTER *)streambuf->get_buf(sizeof(SM_SVC_NAT_IP_CLUSTER), szmax);

		new (psvcnat) SM_SVC_NAT_IP_CLUSTER(pnat->get_cluster_id(), pelem->glob_id_, pnat->natipcomm_.nat_ip_port_, nclustelem);
		
		streambuf->set_buf_sz(sizeof(SM_SVC_NAT_IP_CLUSTER), 1 /* nevents */);
		
		return CB_OK;
	};	

	const auto mwalk = [&, tcutoff](SvcNatIPOne *pnat, void *arg) -> CB_RET_E
	{
		if (pnat->tlast_upd_.load(mo_relaxed) < tcutoff) {
			return CB_DELETE_ELEM;
		}

		/*
		 * 2 pass walk. First to remove any non updated elems and second to update madcachemap if #elems > 1
		 */
		madcntmap.clear(); 
		ndel = 0;

		size_t			nelem = pnat->elemtbl_.walk_hash_table(ewalk, nullptr);
		
		if (nelem <= ndel) {
			if (pnat->elemtbl_.is_empty()) {
				return CB_DELETE_ELEM;
			}	
			else {
				return CB_OK;
			}	
		}	
		
		nelem -= ndel;

		if (nelem <= 1) {
			return CB_OK;
		}	

		auto			natipstr = pnat->natipcomm_.nat_ip_port_.ipaddr_.printaddr();
		uint16_t		natport = pnat->natipcomm_.nat_ip_port_.port_;

		strbuf.appendfmt("[NAT IP Cluster for Svc %s NAT IP %s Port %hu #Svcs %lu #Madhava %lu], ", 
			pnat->natipcomm_.comm_, natipstr.get(), natport, nelem, madcntmap.size());

		nclustsvc++;
		nclustelem = nelem;
		
		GY_CC_BARRIER();

		if (stmtstart == false) {
			stmtstart = true;
retry0 :
			poutstr = pdbstr->appendcb(dbstrovf, "insert into public.svcnatiptbl values "sv);

			if (!poutstr && retrystr) {
				retrystr = false;
				goto retry0;
			}	
		}	

retry1 :			
		poutstr = pdbstr->appendfmtcb(dbstrovf, "%c(\'%s\',\'%016lx\',\'%s\',\'%s\',\'%s\',%d,%d,\'[", 
					nrows++ == 0 ? ' ' : ',', ptimestr, pnat->get_cluster_id(), pnat->natipcomm_.comm_, pcluster->cluster_.get(), 
					natipstr.get(), natport, int(nelem));
		if (!poutstr && retrystr) {
			retrystr = false;
			goto retry1;
		}	

		ncols = 0;

		// 2nd pass
		pnat->elemtbl_.walk_hash_table(ewalk, pnat);
		
retry2 :
		poutstr = pdbstr->appendcb(dbstrovf, "]\')"sv); 
		
		if (!poutstr && retrystr) {
			retrystr = false;
			goto retry2;
		}	

		return CB_OK;
	};
	
	ntotal = pcluster->natiptbl_.walk_hash_table(mwalk);
	
	if (stmtstart == true) {
retry4 :
		poutstr = pdbstr->appendcb(dbstrovf, ";\n"sv); 
		
		if (!poutstr && retrystr) {
			retrystr = false;
			goto retry4;
		}	
	}	
	
	if (ntotal > 0) {	
		auto [cnsec, cmsec, csec] = exectime.get_profile_times();

		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Cluster %s : NAT IP Cluster Check : Total NAT IPs %lu : Total Clustered IPs %lu : "
				"Time for execution = %lu nsec (%lu msec) : List of NAT IP Cluster Svcs : %s\n", 
				pcluster->cluster_.get(), ntotal, nclustsvc, cnsec, cmsec, strbuf.buffer());
	}

	return CB_OK;
}

void SHCONN_HANDLER::check_svc_nat_ip_clusters() noexcept
{
	try {
		if (svcclusters_.template is_empty<RCU_LOCK_SLOW>()) {
			return;
		}

		uint64_t			ntotal;
		StringHeapVec			dbstrvec;			
		EXEC_TIME			exectime;
		time_t				tcurr = time(nullptr), tnatcutoff = tcurr - 650, tdaystart = 0;
		MadCacheMap			madcachemap;
		const auto			timebuf = gy_localtime_iso8601_sec(tcurr);
		const auto			datetbl = get_db_day_partition(tcurr, tcurr, 15, &tdaystart);

		dbstrvec.reserve(std::min(svcclusters_.approx_count_fast() + 1, 16lu));

		dbstrvec.emplace_back(std::in_place, GY_UP_MB(2)); 

		const auto swalk = [&](SvcClusterMapsOne *pcluster, void *arg) noexcept -> CB_RET_E
		{
			try {
				time_t			tlast = pcluster->tlast_upd_.load(mo_relaxed);

				if (tlast < tnatcutoff) {
					return CB_DELETE_ELEM;
				}

				return check_svc_nat_ip_locked(pcluster, madcachemap, dbstrvec, timebuf.get(), datetbl.get());
			}
			GY_CATCH_EXCEPTION(
				ERRORPRINT_OFFLOAD("Exception caught while checking Cluster %s NAT IP Listeners : %s\n", pcluster->cluster_.get(), GY_GET_EXCEPT_STRING);
				return CB_OK;
			);

		};	
		
		ntotal = svcclusters_.walk_hash_table(swalk);

		if (ntotal > 0) {
			/*
			 * Now Update the Postgres DB. The query strings are already updated within dbstrvec
			 */
			 
			struct iovec			*piovarr;
			int				j = 1;
			bool				ismalloc, bret;

			SAFE_STACK_ALLOC(piovarr, (dbstrvec.size() + 2) * sizeof(iovec), ismalloc);

			piovarr[0].iov_base		= (void *)"Begin Work;";
			piovarr[0].iov_len		= GY_CONST_STRLEN("Begin Work;");

			for (size_t i = 0; i < dbstrvec.size(); ++i) {
				const auto 		& optstr = dbstrvec[i];
				
				if (bool(optstr) && optstr->buffer() && optstr->length()) {
					piovarr[j].iov_base 	= (void *)optstr->buffer();
					piovarr[j].iov_len	= optstr->length();
					j++;
				}	
			}

			if (j == 1) {
				goto done1;
			}	

			piovarr[j].iov_base		= (void *)"Commit Work;";
			piovarr[j].iov_len		= GY_CONST_STRLEN("Commit Work;");
			j++;

			auto				pconn = dbmain_scheduler_pool_->get_conn(true /* wait_response_if_unavail */, 60'000 /* max_msec_wait */, true /* reset_on_timeout */);
			
			if (!pconn) {
				db_stats_.nconns_failed_.fetch_add_relaxed(1);
				db_stats_.ncluster_natip_failed_.fetch_add_relaxed(1);
				
				DEBUGEXECN(5,
					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get DB Conn for Cluster Svc Nat IP updation\n");
				);
				
				goto done1;
			}	
		
			bret = PQsendIovecQueryOptim(pconn->get(), piovarr, j);
			
			if (bret == false) {
				db_stats_.ncluster_natip_failed_.fetch_add_relaxed(1);

				DEBUGEXECN(5,
					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to schedule DB query to update Cluster Svc Nat IP due to %s\n", 
						PQerrorMessage(pconn->get()));
				);

				goto done1;
			}	

			pconn->set_resp_cb(
				[this](GyPGConn & conn, GyPGresult gyres, bool is_completed) -> bool
				{
					if (is_completed) {
						if (conn.is_within_tran()) {
							conn.pqexec_blocking("Rollback Work;");
						}						

						conn.make_available();
						return true;
					}	
					
					if (true == gyres.is_error()) {
						db_stats_.ncluster_natip_failed_.fetch_add_relaxed(1);

						DEBUGEXECN(5,
							ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to insert Cluster Svc NAT IP into DB due to %s\n", gyres.get_error_msg());
						);

						return false;
					}	

					return true;
				}
			);
		}

done1 :
		auto [cnsec, cmsec, csec] = exectime.get_profile_times();

		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Clustered Nat IP Listeners check : Total Clusters seen %lu : Time for execution = %lu nsec (%lu msec)\n",
			ntotal, cnsec, cmsec);

	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT_OFFLOAD("Exception caught while checking Clustered NAT IP Listeners : %s\n", GY_GET_EXCEPT_STRING);
	);
}	

void SHCONN_HANDLER::cleanup_tcp_conn_table() noexcept
{
	try {
		int				ndel = 0;
		ssize_t				ntotal;
		const uint64_t			tcutoffusec = get_usec_time() - 30 * GY_USEC_PER_SEC;
		
		auto twalk = [&, tcutoffusec](SHTCP_CONN *ptcp, void *arg) -> CB_RET_E
		{
			if (ptcp->tusec_shstart_ < tcutoffusec) {
				ndel++;
				return CB_DELETE_ELEM;
			}
			else {
				return CB_OK;
			}	
		};	
		
		ntotal = glob_tcp_conn_tbl_.walk_hash_table(twalk);

		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN_ITALIC, "Global Unresolved TCP Connections Deleted = %d : Total Remaining count = %ld\n", ndel, ntotal - ndel);
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while cleaning the Global TCP conn table : %s\n", GY_GET_EXCEPT_STRING);
		);	
	);
}	

ssize_t SHCONN_HANDLER::send_immediate(SHCONNTRACK *pconn1, bool throw_on_error)
{
	bool			is_closed = false, is_blocked = false;
	ssize_t			sret;

	auto wr_cb = [](EPOLL_CONNTRACK * ptconn, ssize_t total_bytes) noexcept
	{};	
	
	auto again_cb = [](EPOLL_CONNTRACK * ptconn, ssize_t total_bytes) noexcept
	{
		ptconn->wrstat_.pending_clock_usec_ 	= get_usec_clock();
		ptconn->wrstat_.pending_sz_		= total_bytes;
	};	

	auto close_cb = [&](EPOLL_CONNTRACK *ptconn, int tsock) noexcept
	{
		is_closed = true;
	};

	sret = pconn1->send_data(wr_cb, again_cb, close_cb, is_blocked);

	if (is_closed) {
		if (throw_on_error) {
			const char * const excstr = (sret <= 0 ? "Failed to send message" : "Connection closed gracefully");

			GY_THROW_EXCEPTION("%s", excstr);
		}
		else {
			return -1;
		}	
	}	

	return sret;
};


std::shared_ptr<SHCONN_HANDLER::MADHAVA_INFO> SHCONN_HANDLER::assign_partha_madhava(const char *hostname, const GY_MACHINE_ID & machid, const char *region, const char *zone, 
												uint64_t last_madhava_id, const char *cluster, uint64_t ign_madid) 
{
	/*
	 * Try to get a madhava in the same region and zone. Currently we do not try to match cluster...
	 */

	std::shared_ptr<MADHAVA_INFO>	madshr, mtmpshr;
	uint64_t			min_csec = std::max<int64_t>(int64_t(get_sec_clock()) - 600L, 60L);
	int				regionerr = 0, zoneerr = 0;
	bool				ign_zone = false, ign_region = false;

	std::optional<RCU_LOCK_SLOW>	slowlock;

	/*
	 * First try with the last used madhava if entry for this machid present in pardbmap_. If not found,
	 * then try the last used madhava.
	 * Currently we ignore the last_madhava_id sent in registration req and rely on pardbmap_ instead...
	 */

	const auto check_madhava = [&](MADHAVA_INFO *pmad) 
	{
		if (pmad->madhava_id_ != ign_madid && pmad->last_status_csec_ > min_csec) {

			if (*region && *zone && !ign_region) {
				if (strcmp(region, pmad->region_name_)) {
					regionerr++;

					return false;
				}	
				else if (!ign_zone && strcmp(zone, pmad->zone_name_)) {
					zoneerr++;

					return false;
				}	
			}
			
			uint32_t			npar = pmad->npartha_nodes_.load(mo_relaxed);

			if (npar + 1 < pmad->max_partha_nodes_) {
				// Check last 2 min added partha as Partha registration may have taken longer and npartha_nodes_ will not reflect that

				uint32_t			nc = pmad->curr_par_adds_.fetch_add(1, mo_relaxed) + 1; 
				uint32_t			nl = pmad->last_par_adds_.load(mo_acquire);

				if (npar + nc + nl < pmad->max_partha_nodes_) {
					if (npar == 0) {
						nmadhava_partha_.fetch_add(1, mo_acq_rel);
					}	

					return true;
				}
			}	
		}	

		return false;
	};	
	
	if (true) {
		SCOPE_GY_MUTEX		scopelock(pardb_mutex_);

		auto			it = pardbmap_.find(machid);

		if (it != pardbmap_.end()) {
			auto			dbstat = it->second;	// Copy

			pardbmap_.erase(it);
			
			scopelock.unlock();

			if (dbstat.madhava_id_ == ign_madid) {
				goto next1;
			}	

			if (strcmp(region, dbstat.region_name_) || strcmp(zone, dbstat.zone_name_)) {
				WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Partha Host %s : Reassigning a new Madhava as change in Region or Zone detected\n", hostname);
				goto next1;
			}	

			slowlock.emplace();	
			
			MADHAVA_INFO_ELEM		*pmadelem = madhava_tbl_.lookup_single_elem_locked(dbstat.madhava_id_, get_uint64_hash(dbstat.madhava_id_));

			if (pmadelem) {
				auto			pmad = pmadelem->get_cref().get();

				if (pmad && true == check_madhava(pmad)) {
					madshr = pmad->shared_from_this();

					return madshr;
				}
			}	
		}	
	}	
	 
next1 :	
	
	if (!slowlock) {
		slowlock.emplace();
	}	

	mtmpshr = curr_madhava_.load(mo_acquire);

	if (auto pmad = mtmpshr.get(); pmad) {
		if (true == check_madhava(pmad)) {
			return mtmpshr;
		}	
	}

next2 :	
	auto lammad = [&](MADHAVA_INFO_ELEM *pdatanode, void *arg1) -> CB_RET_E
	{
		auto			pmad = pdatanode->get_data()->get();
		
		if (pmad == nullptr || false == check_madhava(pmad)) {
			return CB_OK;
		}	

		madshr = pmad->shared_from_this();
		return CB_BREAK_LOOP;
	};

	madhava_tbl_.walk_hash_table_const(lammad);

	if (!madshr) {
		if (zoneerr > 0) {
			WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to find a Madhava server with same Zone as Partha : Assigning a Madhava from a different Zone for Partha %s with Region %s Zone %s\n",
				hostname, region, zone);

			ign_zone = true;

			madhava_tbl_.walk_hash_table_const(lammad);
		}	

		if (!madshr && regionerr > 0) {
			WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to find a Madhava server with same Region as Partha : Assigning a Madhava from a different Region for Partha %s with Region %s Zone %s\n",
				hostname, region, zone);

			ign_region = true;

			madhava_tbl_.walk_hash_table_const(lammad);
		}	

		if (!madshr && ign_madid) {
			ign_madid = 0;

			WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to find a new Madhava server for Partha : "
				"Assigning the same previous Madhava for Partha %s with Region %s Zone %s till another Madhava becomes available\n",
				hostname, region, zone);

			madhava_tbl_.walk_hash_table_const(lammad);
		}	
	}	

	if (madshr) {
		curr_madhava_.store(madshr, mo_release);
		curr_madhava_id_.store(madshr->madhava_id_, mo_relaxed);
	}	

	return madshr;
}	

void SHCONN_HANDLER::read_db_partha_info(PGConnPool & dbpool) noexcept
{
	try {
		auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 5000 /* max_msec_wait */, true /* reset_on_timeout */);

		if (!pconn) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Partha to Madhava info\n");
			return;
		}	

		int				ret, ncols;
		bool				bret;
		STRING_BUFFER<1024>		strbuf;

		// If sql changed, update ncols below
		ncols = 6;
		strbuf.appendconst( "select machid, clustername, region, zone, madhavaid, extract(epoch from del_after) as del_after from public.parthatbl limit 500000;");

		bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());

		if (bret == false) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to schedule query Postgres for Partha to Madhava info\n");
			return;
		}	

		pconn->set_single_row_mode();

		pconn->set_resp_cb(
			[&, total_rows = 0, is_error = false, ncols, tcurr = time(nullptr)](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
			{
				if (is_completed) {
					conn.make_available();
					return true;
				}	
				
				if (is_error) {
					return false;
				}

				if (true == gyres.is_error()) {
					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to query DB for Partha to Madhava mapping due to %s (Total tuples returned so far %d)\n", 
							gyres.get_error_msg(), total_rows);

					return false;
				}	

				char				tbuf[512];
				const PGresult *		pres = gyres.get();
				const int			nfields = PQnfields(pres);
				const int			ntuples = PQntuples(gyres.get());

				if (nfields != ncols) {
					is_error = true;
					return false;
				}	

				for (int row = 0; row < ntuples; ++row) {
					int				len;
					bool				bret;
					
					len = PQgetlength(pres, row, 0);

					if (len == 0) {
						continue;
					}

					try {
						GY_MACHINE_ID			machid(PQgetvalue(pres, row, 0), len);
						ParthaDbStat			parstat;

						len = PQgetlength(pres, row, 1);
						
						if (len > 0) {
							GY_STRNCPY(parstat.cluster_name_, PQgetvalue(pres, row, 1), sizeof(parstat.cluster_name_));
						}	

						len = PQgetlength(pres, row, 2);
						
						if (len > 0) {
							GY_STRNCPY(parstat.region_name_, PQgetvalue(pres, row, 2), sizeof(parstat.region_name_));
						}	

						len = PQgetlength(pres, row, 3);
						
						if (len > 0) {
							GY_STRNCPY(parstat.zone_name_, PQgetvalue(pres, row, 3), sizeof(parstat.zone_name_));
						}	

						len = PQgetlength(pres, row, 4);
						
						if (len == 0) {
							continue;
						}

						bret = string_to_number(PQgetvalue(pres, row, 4), parstat.madhava_id_, nullptr, 16);
						if (!bret) {
							continue;
						}	
						
						len = PQgetlength(pres, row, 5);
						
						if (len != 0) {
							double			tdel = 0;

							string_to_number(PQgetvalue(pres, row, 5), tdel);

							parstat.tdel_after_ = time_t(tdel);

							if (parstat.tdel_after_ > 0 && parstat.tdel_after_ < tcurr) {
								continue;
							}	
						}

						parstat.tping_ = tcurr;

						// No mutex as init 
						pardbmap_.try_emplace(machid, parstat);

						total_rows++;

					}
					catch(...) {
						return false;
					}	
				}	

				return true;
			}
		);
		
		// Wait max 30 sec
		ret = dbpool.wait_one_response(30 * 1000, pconn.getintconn());

		if (ret != 0) {
			if (ret == 2) {
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "DB Query to get Partha to Madhava mapping Timed Out\n");
			}
			else {
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "DB Query to get Partha to Madhava mapping Errored Out\n");
			}	
		}	
		else {
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Read %lu Partha hosts info from DB\n", pardbmap_.size());
		}	
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while reading Partha to Madhava Mapping from DB : %s\n", GY_GET_EXCEPT_STRING);
	);
}	

void SHCONN_HANDLER::cleanup_db_partha_entries() noexcept
{
	try {
		/*
		 * First iterate over pardbmap_
		 */
		time_t				tcurr = time(nullptr), tmin_ping = tcurr - 30 * 3600, tprocstart = get_proc_start();

		if (tmin_ping < tprocstart and tprocstart > 0) {
			// Process started recently. Lets wait for another 30 hours
			tmin_ping = 0;
		}	
		
		assert(gy_get_thread_local().get_thread_stack_freespace() > 1024 * 1024 + 100 * 1024);

		STRING_BUFFER<1024 * 1024>	qbuf;
		int				ndel = 0, nact = 0, maxdel = 25000;

		qbuf << "delete from public.parthatbl where machid in ("sv;

		SCOPE_GY_MUTEX			scopelock(pardb_mutex_);

		for (auto it = pardbmap_.begin(); it != pardbmap_.end() && ndel < maxdel; ) {
			auto			& dstat = it->second;
			
			if (dstat.tdel_after_ > 0 and dstat.tdel_after_ < tcurr) {
				ndel++;
				qbuf.appendfmt("\'%s\',", it->first.get_string().get());

				it = pardbmap_.erase(it);

				continue;
			}	

			if (dstat.tping_ < tmin_ping and dstat.tping_ > 0) {
				ndel++;
				qbuf.appendfmt("\'%s\', ", it->first.get_string().get());

				it = pardbmap_.erase(it);
				continue;
			}	

			++it;
		}	
		 
		scopelock.unlock();

		auto lampar = [&, this, tmin_ping](PARTHA_INFO *pinfo, void *arg1) -> CB_RET_E
		{
			if (pinfo->tdb_updated_.load(mo_relaxed) < tmin_ping && pinfo->tinit_ < tmin_ping) {
				ndel++;
				qbuf.appendfmt("\'%s\', ", pinfo->get_machid_str().get());

				return ndel < maxdel ? CB_DELETE_ELEM : CB_DELETE_BREAK;
			}	
				
			nact++;

			return CB_OK;
		};

		partha_tbl_.walk_hash_table(lampar);

		qbuf << "NULL);\n"sv;
		qbuf << "delete from public.parthatbl where del_after is not null and now() > del_after;\n"sv;

		auto				res = get_new_db_conn().pqexec_blocking(qbuf.buffer());

		if (res.is_error())  {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to delete Partha entries from DB during cleanup due to %s\n", res.get_error_no_newline().get());  
		}

		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Partha Stats after Cleanup : # Partha Hosts active %d : # Hosts inacive or connected before proc start %lu : Deleted %d hosts\n",
			nact, pardbmap_.size(), ndel);

	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while cleaning up Partha entries in DB : %s\n", GY_GET_EXCEPT_STRING);
	);
}

void SHCONN_HANDLER::init_tracedefs(PGConnPool & dbpool)
{
	const char			*penv = getenv("CFG_TRACEDEFS_JSON");
	std::string			jsonstr;

	if (penv && *penv) {
		jsonstr = read_file_to_string(penv, GY_UP_MB(32), 0, "Trace Definitions CFG_TRACEDEFS_JSON config file ");
	}	

	if (jsonstr.empty()) {
		try {
			read_db_tracedef_info(dbpool);
		}
		GY_CATCH_EXCEPTION(
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while trying to read Req Trace Definitions Info from DB : %s\n", GY_GET_EXCEPT_STRING); 
		);
	}
	else {
		// Set all tracedefs from config file ignoring existing tracedefs in db
		set_cfg_tracedefs(penv, jsonstr.data(), jsonstr.size(), dbpool);
	}	
}	

void SHCONN_HANDLER::set_cfg_tracedefs(const char *pfilename, const char *pcfg, size_t lencfg, PGConnPool & dbpool)
{
	JSON_DOCUMENT<32 * 1024, 8192>	doc;
	auto				& jdoc = doc.get_doc();
	JSON_ALLOCATOR			& allocator = jdoc.GetAllocator();

	jdoc.Parse(pcfg, lencfg);

	if (jdoc.HasParseError()) {
		char			ebuf[256];
		const char		*perrorstr = rapidjson::GetParseError_En(jdoc.GetParseError());

		ERRORPRINTCOLOR(GY_COLOR_RED, "Invalid Request Trace Definitions Config CFG_TRACEDEFS_JSON : Error at offset %lu : Error is \'%s\'\n\n", 
			jdoc.GetErrorOffset(), perrorstr);

		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid JSON for Trace Definitions Config CFG_TRACEDEFS_JSON file %s", pfilename);
	}	

	if (false == jdoc.IsArray()) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Trace Definitions Config CFG_TRACEDEFS_JSON file %s : Needs to be a JSON Array type", pfilename);
	}	

	time_t				tcurr = time(nullptr);
	int				nadded = 0;
	bool				bret;

	// First truncate existing Tracedefs...
	if (true) {
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Request Trace Definitions Config CFG_TRACEDEFS_JSON file %s seen : Deleting existing DB Tracedefs first...\n", pfilename);

		auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 30'000 /* max_msec_wait */, true /* reset_on_timeout */);
		
		if (!pconn) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to Postgres for Trace Definitions truncation\n");

			db_stats_.nconns_failed_.fetch_add_relaxed(1);
			db_stats_.ndbquery_failed_.fetch_add_relaxed(1);
		}
		else {
			pconn->pqexec_blocking("truncate table public.tracedeftbl;");
		}
	}	
	
	for (uint32_t i = 0; i < jdoc.Size(); i++) {
		STRING_BUFFER<512>		errbuf;
		auto 				[errcode, defid] = new_tracedef_json(jdoc[i], errbuf, dbpool);

		if (defid) {
			nadded++;
		}	
		else {
			GY_THROW_EXPR_CODE(errcode, "Failed to add new Req Trace Definition from Config file : %s", errbuf.buffer()); 
		}
	}
		
	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Added %u Req Trace Definitions from Tracedef Config file %s\n", nadded, pfilename);
}


void SHCONN_HANDLER::read_db_tracedef_info(PGConnPool & dbpool)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 30000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Req Trace Definitions info from db\n");

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		return;
	}	

	int				ret, nadded = 0;
	bool				bret;
	time_t				tcurr = time(nullptr);

	const JSON_DB_MAPPING		*colarr[GY_ARRAY_SIZE(json_db_tracedef_arr)] {};
	size_t				ncol;
	STRING_BUFFER<1024>		strbuf;

	strbuf << "select defid, name, tstart, tend, filter from public.tracedeftbl limit "sv << MAX_REQ_TRACE_DEFS << "\n;";

	bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.length());

	if (bret == false) {
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to schedule query Postgres for Req Trace Definitions info from db\n");

		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);
		return;
	}

	ncol 				= GY_ARRAY_SIZE(json_db_tracedef_arr);

	colarr[0]			= &json_db_tracedef_arr[0];
	colarr[1]		 	= &json_db_tracedef_arr[1];
	colarr[2]			= &json_db_tracedef_arr[2];
	colarr[3]			= &json_db_tracedef_arr[3];
	colarr[4]			= &json_db_tracedef_arr[4];

	static_assert(json_db_tracedef_arr[0].jsoncrc == FIELD_DEFID);
	static_assert(json_db_tracedef_arr[1].jsoncrc == FIELD_NAME);
	static_assert(json_db_tracedef_arr[2].jsoncrc == FIELD_TSTART);
	static_assert(json_db_tracedef_arr[3].jsoncrc == FIELD_TEND);
	static_assert(json_db_tracedef_arr[4].jsoncrc == FIELD_FILTER);

	const auto rowcb = [&](int numrow, const JSON_DB_MAPPING **pcolarr, std::string_view colview[], uint32_t ncol)
	{
		uint32_t			defid;
		time_t				tstart, tend = 0;
		STRING_BUFFER<256>		strbuf;
		std::string_view		& name = colview[1], & filter = colview[4];
		
		if (colview[0].size() == 0) {
			return;
		}	

		defid = string_to_number<uint32_t>(colview[0].data(), 16);
		if (defid == 0) {
			return;
		}	

		if (name.size() == 0 || filter.size() == 0) {
			return;
		}	

		if (colview[2].size() > 0) {
			tstart = gy_iso8601_to_time_t(CHAR_BUF<64>(colview[2].data(), colview[2].size()).get());
		}
		else {
			tstart = tcurr;
		}

		if (colview[3].size() > 0) {
			tend = gy_iso8601_to_time_t(CHAR_BUF<64>(colview[3].data(), colview[3].size()).get());
		}

		if (tend == 0) {
			tend = tcurr + 10 * GY_SEC_PER_YEAR;
		}	

		auto 			[errcode, id] = add_tracedef(defid, name, filter, tstart, tend, strbuf);
		
		if (id) {
			nadded++;

			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Added Req Trace Definition from DB : \'%s\'\n", name.data());
		}	
		else {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to add new Req Trace Definition from DB : %s\n", strbuf.buffer()); 
		}
	};	

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_strview_cb(conn, std::move(gyres), is_completed, "Trace Definition", colarr, ncol, total_rows, rowcb);
		}
	);
	
	ret = dbpool.wait_one_response(30'000, pconn.getintconn());

	if (ret != 0) {
		if (ret == 2) {
			db_stats_.ndbquery_timeout_.fetch_add_relaxed(1);
		}

		if (ret == 2) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Trace Definition Query : Database Querying Timeout... Skipping...\n");
		}
		else {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Trace Definition Query : Database Connection Error... Skipping...\n");
		}	

		return;
	}	

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Added %u Request Trace Definitions from DB\n", nadded);
}

std::tuple<ERR_CODES_E, uint32_t> SHCONN_HANDLER::add_tracedef(uint32_t defid, std::string_view name, std::string_view filter, time_t tstart, time_t tend, STR_WR_BUF & errbuf) noexcept
{
	try {
		time_t				tcurr = time(nullptr);

		if (name.size() == 0) {
			errbuf << "Invalid Trace Add Definition : Require a valid name"sv;
			return {ERR_INVALID_REQUEST, 0};
		}	
		else if (name.size() >= REQ_TRACE_DEF::MAX_NAMELEN) {
			errbuf << "Trace Add Definition failed as Max name length "sv << REQ_TRACE_DEF::MAX_NAMELEN << " exceeded : "sv << name.size();
			return {ERR_INVALID_REQUEST, 0};
		}	

		if (filter.size() == 0) {
			errbuf << "Invalid Trace Add Definition : Require a valid filter"sv;
			return {ERR_INVALID_REQUEST, 0};
		}	
		else if (filter.size() >= MAX_QUERY_STRLEN) {
			errbuf << "Trace Add Definition failed as Max filter length "sv << MAX_QUERY_STRLEN << " exceeded : "sv << filter.size();
			return {ERR_INVALID_REQUEST, 0};
		}	

		if (defid == 0) {
			defid = REQ_TRACE_DEF::get_def_id(name.data(), name.size());
		}

		if (tstart == 0) {
			tstart = tcurr;
		}

		CRITERIA_SET			tcrit(filter.data(), filter.size(), SUBSYS_SVCINFO);

		SCOPE_GY_MUTEX			scope(tracemutex_);

		if (tracedefmap_.size() >= MAX_REQ_TRACE_DEFS) {
			errbuf.appendfmt("Request Trace Definition Add received but Max Trace Definition Count is already reached %lu : "
						"Cannot add new Trace Definitions : Please delete any unused ones first", tracedefmap_.size());
			return {ERR_INVALID_REQUEST, 0};
		}

		auto 				[it, success] = tracedefmap_.try_emplace(defid, defid, name.data(), filter, std::move(tcrit), tend, tstart);

		if (!success) {
			errbuf << "Trace Definition name \'"sv << name << "\' already exists : Please use a different name or delete the existing one first"sv;
			return {ERR_CONFLICTS, 0};
		}	

		// Reset criteria as its no longer needed
		it->second.reset_criteria();
		
		errbuf << "Added new Request Trace Definition name \'"sv << name << "\' successfully : Definition ID is "sv;
		errbuf.appendfmt("\'%08x\'", defid);

		return {ERR_STATUS_OK, defid};
	}
	GY_CATCH_EXPRESSION(
		int			ecode = GY_GET_EXCEPT_CODE();

		if (ecode == 0) ecode = ERR_SERV_ERROR;
	
		errbuf << "New Request Trace Definition failed due to : "sv << GY_GET_EXCEPT_STRING;
		return {ERR_CODES_E(ecode), 0};
	);
}	

std::tuple<ERR_CODES_E, uint32_t> SHCONN_HANDLER::new_tracedef_json(GEN_JSON_VALUE & value, STR_WR_BUF & errbuf, PGConnPool & dbpool, 
									const std::shared_ptr<SHCONN_HANDLER::SHCONNTRACK> * pconnshr, const comm::QUERY_CMD *pquery)
{
	std::string_view			name, filter;
	time_t					tstart = time(nullptr), tend = 0;
	ERR_CODES_E				errcode = ERR_STATUS_OK;
	uint32_t				defid = 0;
	STACK_JSON_WRITER<12 * 1024, 4096>	writer;
	bool					bret;

	writer.StartObject();

	if (!value.IsObject()) {
		errbuf << "Failed to add new Request Trace Definition as JSON not of object type"sv;
		errcode = ERR_INVALID_REQUEST;
		goto done1;
	}	

	if (auto aiter = value.FindMember("name"); ((aiter != value.MemberEnd()) && (aiter->value.IsString()))) {
		name = { aiter->value.GetString(), (size_t)aiter->value.GetStringLength() };
	}
	else {
		errbuf << "Failed to add new Request Trace Definition as required field : name : of string data type not found"sv;
		errcode = ERR_INVALID_REQUEST;
		goto done1;
	}	

	if (auto aiter = value.FindMember("filter"); ((aiter != value.MemberEnd()) && (aiter->value.IsString()))) {
		filter = { aiter->value.GetString(), (size_t)aiter->value.GetStringLength() };
	}
	else {
		errbuf << "Failed to add new Request Trace Definition as required field : filter : of string data type not found"sv;
		errcode = ERR_INVALID_REQUEST;
		goto done1;
	}	
	
	if (auto aiter = value.FindMember("tend"); ((aiter != value.MemberEnd()) && (aiter->value.IsString()))) {
		tend = gy_iso8601_to_time_t(aiter->value.GetString());
	}	

	if (tend == 0) {
		tend = tstart + 10 * GY_SEC_PER_YEAR;
	}	

	if (true) {
		auto tup =  add_tracedef(0, name, filter, tstart, tend, errbuf);
		
		errcode = std::get<0>(tup);
		defid 	= std::get<1>(tup);
	}

	if (defid) {
		bret = db_insert_tracedef(defid, name.data(), filter.data(), tstart, tend, errbuf, dbpool);

		if (!bret) {
			SCOPE_GY_MUTEX			scope(tracemutex_);

			tracedefmap_.erase(defid);

			defid 	= 0;
			errcode = ERR_SERV_ERROR;
		}	
		else {
			if (pconnshr) {
				writer.KeyConst("status");
				writer.StringConst("ok");

				writer.KeyConst("msg");
				writer.String(errbuf.data(), errbuf.size());
			}
		}	
	}

done1 :
	if (!defid && pconnshr) {

		writer.KeyConst("status");
		writer.StringConst("failed");
		
		writer.KeyConst("error");
		writer.Uint(errcode);

		writer.KeyConst("errmsg");
		writer.String(errbuf.data(), errbuf.size());
	}	

	writer.EndObject();

	if (pconnshr && pquery) {
		// Send the status
		const char			*pstr = writer.get_string();
		uint32_t			lenstr = writer.get_size();
		bool				bret;

		send_query_response(*pconnshr, pquery->get_seqid(), RESP_WEB_JSON, errcode, RESP_JSON_WITH_HEADER, pstr, lenstr);
	}

	if (defid == 0) {
		WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to add new Req Trace Definition from Node : %s\n", errbuf.buffer());
	}	
	else if (pconnshr) {
		/*
		 * Send Trace Def Add event to all Madhava's
		 */
	
		constexpr size_t		fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY);

		auto				puniq = make_refcnt_uniq(fixed_sz + sizeof(SM_REQ_TRACE_DEF_NEW) + filter.size() + 1 + 7);
		void				*palloc = puniq.get();

		COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
		EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1); 
		auto				*pstat = reinterpret_cast<SM_REQ_TRACE_DEF_NEW *>(pnot + 1);

		new (pstat) SM_REQ_TRACE_DEF_NEW(defid, name.data(), tend, filter.size() + 1);

		new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, fixed_sz + pstat->get_elem_size(), COMM_HEADER::MS_HDR_MAGIC);
		
		new (pnot) EVENT_NOTIFY(NOTIFY_SM_REQ_TRACE_DEF_NEW, 1);

		std::memcpy((uint8_t *)(pstat + 1), filter.data(), filter.size());
		((uint8_t *)(pstat + 1))[filter.size()] = 0;
		 
		send_all_madhava_event(std::move(puniq), phdr->get_act_len(), phdr->get_pad_len());
	}

	if (defid) {
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Added new Request Trace Definition : %s\n", name.data());
	}	

	return {errcode, defid};
}	

bool SHCONN_HANDLER::db_insert_tracedef(uint32_t defid, const char *name, const char *filter, time_t tstart, time_t tend, STR_WR_BUF & errbuf, PGConnPool & dbpool)
{
	auto				tstartbuf = gy_localtime_iso8601_sec(tstart), tendbuf = gy_localtime_iso8601_sec(tend);
	bool				bret;
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 30'000 /* max_msec_wait */, true /* reset_on_timeout */);
	
	if (!pconn) {
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to insert new Request Trace Definition to DB\n");

		errbuf.reset();
		errbuf << "Request Trace Definition add failed due to unavailable DB connection issue";

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		return false;
	}	

	char				idbuf[20];
	const char			*params[5] { idbuf, name, tstartbuf.get(), tendbuf.get(), filter };
	
	snprintf(idbuf, sizeof(idbuf), "%08x", defid);

	const char			qcmd[] = "insert into public.tracedeftbl values ($1::char(8), $2::text, $3::timestamptz, $4::timestamptz, $5::text) "
							"on conflict(defid) do update set (tstart, tend, filter) = (excluded.tstart, excluded.tend, excluded.filter);\n";

	bret = PQsendQueryParams(pconn->get(), qcmd, GY_ARRAY_SIZE(params), nullptr, params, nullptr, nullptr, 0);

	if (bret == false) {
		db_stats_.ntracedef_failed_.fetch_add_relaxed(1);

		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to update DB with New Request Trace Definition due to %s\n", PQerrorMessage(pconn->get()));
		return false;
	}	

	pconn->set_resp_cb(
		[this](GyPGConn & conn, GyPGresult gyres, bool is_completed) -> bool
		{
			if (is_completed) {
				if (conn.is_within_tran()) {
					conn.pqexec_blocking("Rollback Work;");
				}						
				conn.make_available();
				return true;
			}	
			
			if (true == gyres.is_error()) {
				db_stats_.nalertdef_failed_.fetch_add_relaxed(1);

				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to update DB with New Request Trace Definition due to %s\n", gyres.get_error_msg());
				return false;
			}	

			return true;
		}
	);

	return true;
}

void SHCONN_HANDLER::handle_node_tracedef_add(const std::shared_ptr<SHCONN_HANDLER::SHCONNTRACK> & connshr, GEN_JSON_VALUE & jdoc, const comm::QUERY_CMD *pquery, PGConnPool & dbpool)
{
	STRING_BUFFER<1024>		strbuf;
	auto				it = jdoc.FindMember("data");
	
	if (it == jdoc.MemberEnd()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Request Trace Definition Add Command received with missing data payload");

		send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}
	else if (false == it->value.IsObject()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Request Trace Definition Add Command received with invalid data : data member not of JSON Object type");

		send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}

	new_tracedef_json(it->value, strbuf, dbpool, &connshr, pquery);
}

void SHCONN_HANDLER::handle_node_tracedef_delete(const std::shared_ptr<SHCONN_HANDLER::SHCONNTRACK> & connshr, GEN_JSON_VALUE & jdoc, const comm::QUERY_CMD *pquery, PGConnPool & dbpool)
{
	STRING_BUFFER<1024>		strbuf;
	auto				it = jdoc.FindMember("data");
	
	if (it == jdoc.MemberEnd()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Request Trace Definition Delete Command received with missing data payload");

		send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}
	else if (false == it->value.IsObject()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Request Trace Definition Delete Command received with invalid data : data member not of JSON Object type");

		send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}

	STACK_JSON_WRITER<2048>		writer;
	ERR_CODES_E			errcode = ERR_STATUS_OK;
	size_t				len;

	writer.StartObject();

	writer.KeyConst("status");

	const char			*pdefid = nullptr, *pname = nullptr;
	char				ebuf[255];
	uint32_t			defid = 0;
	bool				bret, delok = false;
	const auto			& obj = it->value.GetObject();
	
	it = obj.FindMember("defid");

	if (it == obj.MemberEnd()) {
		it = obj.FindMember("name");
		
		if (it == obj.MemberEnd() || (false == it->value.IsString())) {
			auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Trace Definition Delete Command received with missing mandatory fields \'defid\' or \'name\'");

			send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
			return;
		}

		pname = it->value.GetString();

		defid = REQ_TRACE_DEF::get_def_id(pname, it->value.GetStringLength());
	}	
	else if (false == it->value.IsString()) {
		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Trace Definition Delete Command received with invalid data : \'defid\' member not of JSON string type");

		send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}	
	else {
		pdefid = it->value.GetString();

		bret = string_to_number(pdefid, defid, nullptr, 16);
		if (!bret) {
			auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Trace Definition Delete Command received with invalid data : \'defid\' specified is invalid : not in ID string format");

			send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
			return;
		}
	}	

	SCOPE_GY_MUTEX			scope(tracemutex_);

	auto				mit = tracedefmap_.find(defid);

	if (mit == tracedefmap_.end()) {
		errcode	= ERR_DATA_NOT_FOUND;
		len 	= GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Trace Definition %s \'%s\' not found", pdefid ? "ID" : "Name", pdefid ? pdefid : pname);

		writer.StringConst("failed");
	
		writer.KeyConst("error");
		writer.Uint(errcode);

		writer.KeyConst("errmsg");
		writer.String(ebuf, len);
	}	
	else {
		tracedefmap_.erase(mit);

		delok = true;

		writer.StringConst("ok");

		writer.KeyConst("msg");
		writer.StringConst("Deleted Trace Definition");
	}	

	scope.unlock();

	writer.EndObject();

	// Send the status
	const char			*pstr = writer.get_string();
	uint32_t			lenstr = writer.get_size();
	time_t				tend = time(nullptr) - 60;

	bret = send_query_response(connshr, pquery->get_seqid(), RESP_WEB_JSON, errcode, RESP_JSON_WITH_HEADER, pstr, lenstr);
	
	if (!delok) {
		return;
	}	
	
	/*
	 * Send Trace Def Delete event to all Madhava's
	 */
	size_t				fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + sizeof(SM_REQ_TRACE_DEF_DISABLE);

	auto				puniq = make_refcnt_uniq(fixed_sz);
	void				*palloc = puniq.get();

	COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
	EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1); 
	auto				*pstat = reinterpret_cast<SM_REQ_TRACE_DEF_DISABLE *>(pnot + 1);

	new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, fixed_sz, COMM_HEADER::MS_HDR_MAGIC);
	
	new (pnot) EVENT_NOTIFY(NOTIFY_SM_REQ_TRACE_DEF_DISABLE, 1);
	
	new (pstat) SM_REQ_TRACE_DEF_DISABLE(defid, tend);

	send_all_madhava_event(std::move(puniq), fixed_sz, phdr->get_pad_len());

	/*
	 * Now update the DB 
	 */
	db_update_tracedef(&defid, 1, true, tend, dbpool);
}

void SHCONN_HANDLER::handle_node_tracedef_update(const std::shared_ptr<SHCONN_HANDLER::SHCONNTRACK> & connshr, GEN_JSON_VALUE & jdoc, const comm::QUERY_CMD *pquery, PGConnPool & dbpool)
{
	STRING_BUFFER<1024>		strbuf;
	auto				it = jdoc.FindMember("data");
	
	if (it == jdoc.MemberEnd()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Request Trace Definition Update Command received with missing data payload");

		send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}
	else if (false == it->value.IsObject()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Request Trace Definition Update Command received with invalid data : data member not of JSON Object type");

		send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}

	STACK_JSON_WRITER<2048>		writer;
	ERR_CODES_E			errcode = ERR_STATUS_OK;
	size_t				len;

	writer.StartObject();

	writer.KeyConst("status");

	const char			*pdefid = nullptr, *pname = nullptr;
	char				ebuf[255];
	time_t				tend = 0;
	uint32_t			defid = 0;
	bool				bret;
	const auto			& obj = it->value.GetObject();
	
	it = obj.FindMember("defid");

	if (it == obj.MemberEnd()) {
		it = obj.FindMember("name");
		
		if (it == obj.MemberEnd() || (false == it->value.IsString())) {
			auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Trace Definition Update Command received with missing mandatory fields \'defid\' or \'name\'");

			send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
			return;
		}

		pname = it->value.GetString();

		defid = REQ_TRACE_DEF::get_def_id(pname, it->value.GetStringLength());
	}	
	else if (false == it->value.IsString()) {
		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Trace Definition Update Command received with invalid data : \'defid\' member not of JSON string type");

		send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}	
	else {
		pdefid = it->value.GetString();

		bret = string_to_number(pdefid, defid, nullptr, 16);
		if (!bret) {
			auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Trace Definition Update Command received with invalid data : \'defid\' specified is invalid : not in ID string format");

			send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
			return;
		}
	}	

	SCOPE_GY_MUTEX			scope(tracemutex_);

	auto				mit = tracedefmap_.find(defid);

	if (mit == tracedefmap_.end()) {
		errcode	= ERR_DATA_NOT_FOUND;
		len 	= GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Trace Definition %s \'%s\' not found", pdefid ? "ID" : "Name", pdefid ? pdefid : pname);

		writer.StringConst("failed");
	
		writer.KeyConst("error");
		writer.Uint(errcode);

		writer.KeyConst("errmsg");
		writer.String(ebuf, len);
	}	
	else {
		it = obj.FindMember("filter");

		if (it != obj.MemberEnd()) {
			auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Trace Definition Update Command received with invalid data : \'filter\' specified but update can only change tend field");

			send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
			return;
		}	

		it = obj.FindMember("tend");

		if (it == obj.MemberEnd()) {
			auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Trace Definition Update Command received with invalid data : \'tend\' field missing : update can only change tend field");

			send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
			return;
		}	
		else if (false == it->value.IsString()) {
			auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Trace Definition Update Command received with invalid data : \'tend\' field not of string type");

			send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
			return;
		}	
		else {
			tend = gy_iso8601_to_time_t(it->value.GetString());

			if (tend == 0) {
				auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Trace Definition Update Command received with invalid data : \'tend\' field is invalid ");

				send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
				return;
			}	

			if (mit->second.tend_ != tend) {
				mit->second.tend_ = tend;
			}
			else {
				tend = 0;
			}	

			writer.StringConst("ok");

			writer.KeyConst("msg");
			writer.StringConst("Updated Trace Definition");
		}
	}	

	scope.unlock();

	writer.EndObject();

	// Send the status
	const char			*pstr = writer.get_string();
	uint32_t			lenstr = writer.get_size();

	bret = send_query_response(connshr, pquery->get_seqid(), RESP_WEB_JSON, errcode, RESP_JSON_WITH_HEADER, pstr, lenstr);
	
	if (0 == tend) {
		return;
	}	
	
	/*
	 * Send Trace Def Update event to all Madhava's
	 */
	size_t				fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + sizeof(SM_REQ_TRACE_DEF_DISABLE);

	auto				puniq = make_refcnt_uniq(fixed_sz);
	void				*palloc = puniq.get();

	COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
	EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1); 
	auto				*pstat = reinterpret_cast<SM_REQ_TRACE_DEF_DISABLE *>(pnot + 1);

	new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, fixed_sz, COMM_HEADER::MS_HDR_MAGIC);
	
	new (pnot) EVENT_NOTIFY(NOTIFY_SM_REQ_TRACE_DEF_DISABLE, 1);
	
	new (pstat) SM_REQ_TRACE_DEF_DISABLE(defid, tend);

	send_all_madhava_event(std::move(puniq), fixed_sz, phdr->get_pad_len());

	/*
	 * Now update the DB 
	 */
	db_update_tracedef(&defid, 1, false, tend, dbpool);
}

bool SHCONN_HANDLER::db_update_tracedef(uint32_t *pdefidarr, uint32_t ndefs, bool isdelete, time_t tend, PGConnPool & dbpool)
{
	if (!pdefidarr || !ndefs) {
		return false;
	}

	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 30'000 /* max_msec_wait */, false /* reset_on_timeout */);
	bool				bret;
	
	if (!pconn) {
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection for Trace Definition Update to DB\n");

		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		return false;
	}	

	STRING_BUFFER<32 * 1024>	strbuf;

	if (!isdelete) {
		auto				tendbuf = gy_localtime_iso8601_sec(tend);
		
		strbuf.appendfmt("update public.tracedeftbl set tend = \'%s\'::timestamptz where defid in (", tendbuf.get());
	}
	else {
		strbuf.appendfmt("delete from public.tracedeftbl where defid in (");
	}	

	for (uint32_t i = 0; i < ndefs; ++i) {
		strbuf.appendfmt("\'%08x\',", pdefidarr[i]);
	}	

	strbuf--;

	strbuf << ");";

	bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.length());

	if (bret == false) {
		db_stats_.nalertdef_failed_.fetch_add_relaxed(1);

		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to set Trace Definition Update to DB due to %s\n", PQerrorMessage(pconn->get()));
		return false;
	}	

	pconn->set_resp_cb(
		[this](GyPGConn & conn, GyPGresult gyres, bool is_completed) -> bool
		{
			if (is_completed) {
				if (conn.is_within_tran()) {
					conn.pqexec_blocking("Rollback Work;");
				}						
				conn.make_available();
				return true;
			}	
			
			if (true == gyres.is_error()) {
				db_stats_.nalertdef_failed_.fetch_add_relaxed(1);

				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to set Trace Definition Update to DB due to %s\n", gyres.get_error_msg());
				return false;
			}	

			return true;
		}
	);

	return true;
}

bool SHCONN_HANDLER::send_madhava_all_tracedefs(MADHAVA_INFO *pmad, const std::shared_ptr<SHCONNTRACK> & connshr) noexcept
{
	try {
		SHSTREAM_EVENT_BUF		streambuf(connshr, *this, NOTIFY_SM_REQ_TRACE_DEF_NEW, SM_REQ_TRACE_DEF_NEW::MAX_NUM_DEFS);

		// Preallocate memory
		streambuf.get_buf(64 * 1024);

		SCOPE_GY_MUTEX			scope(tracemutex_);
		
		for (const auto & [defid, def] : tracedefmap_) {
			uint32_t		szext = def.get_ext_sz(), minsz = sizeof(SM_REQ_TRACE_DEF_NEW) + szext + 1 + 7;
			auto			*pstat = (SM_REQ_TRACE_DEF_NEW *)streambuf.get_buf(minsz);
			
			if (def.is_fixed_svcs()) {
				new (pstat) SM_REQ_TRACE_DEF_NEW(def.reqdefid_, def.cap_glob_id_vec_.size(), def.name_, def.tend_);

				std::memcpy((uint8_t *)(pstat + 1), def.cap_glob_id_vec_.data(), def.cap_glob_id_vec_.size() * sizeof(uint64_t));
			}
			else {
				new (pstat) SM_REQ_TRACE_DEF_NEW(def.reqdefid_, def.name_, def.tend_, def.filterstr_.size() + 1);

				std::memcpy((uint8_t *)(pstat + 1), def.filterstr_.data(), def.filterstr_.size() + 1);
			}	
			 
			streambuf.set_buf_sz(pstat->get_elem_size(), 1);
		}

		return true;
	}
	GY_CATCH_EXPRESSION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to send Madhava %s Request Trace Definitions due to exception : %s\n", 
				pmad->print_string(STRING_BUFFER<512>().get_str_buf()), GY_GET_EXCEPT_STRING);
		return false;
	)
}	

void SHCONN_HANDLER::check_all_tracedefs(PGConnPool & dbpool) noexcept
{
	try {
		uint32_t			defidarr[MAX_REQ_TRACE_DEFS + 64], ndefs = 0;

		SCOPE_GY_MUTEX			scope(tracemutex_);
		time_t				tmin = time(nullptr) + 30;
	
		for (auto it = tracedefmap_.begin(); it != tracedefmap_.end();) {
			if (it->second.tend_ < tmin) {

				if (ndefs + 1 < GY_ARRAY_SIZE(defidarr)) {
					defidarr[ndefs++] = it->second.reqdefid_;
				}	

				it = tracedefmap_.erase(it);
				continue;
			}	

			++it;
		}	

		scope.unlock();

		if (ndefs > 0) {
			db_update_tracedef(defidarr, ndefs, true /* isdelete */, tmin, dbpool);
		}	
	}
	GY_CATCH_EXPRESSION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception occured while cleaning Request Trace Defs : %s\n", GY_GET_EXCEPT_STRING);
	);

}	

GyPGConn SHCONN_HANDLER::get_new_db_conn(bool auto_reconnect)
{
	auto 				psettings = pshyama_->psettings_;
	auto				dbname = get_dbname();

	return GyPGConn(psettings->postgres_hostname, psettings->postgres_port, psettings->postgres_user, psettings->postgres_password,
						dbname.get(), "shyama_adhoc", get_db_init_commands().get(), auto_reconnect, 12, 2, 2);
}	

int SHCONN_HANDLER::handle_misc_madhava_reg(MS_REGISTER_REQ_S *pms, const DB_WRITE_ARR & dbarr, L2_PARAMS & param, POOL_ALLOC_ARRAY *pthrpoolarr, STATS_STR_MAP & statsmap)
{
	auto				pconn1 = dbarr.shrconn_.get();

	if (nullptr == pconn1) {
		statsmap["Madhava Disconnected"]++;

		return 1;
	}

	MADHAVA_INFO_ELEM		mstatshr;
	MADHAVA_INFO			*pminfo = nullptr;
	uint64_t			madhava_id = pms->madhava_id_;
	uint64_t			curr_nmadhava = 0;
	uint64_t			tcurrusec = get_usec_time();
	bool				bret, is_new = false;

	/*
	 * Need to securely verify the remote madhava registration TODO
	 */

	bret = madhava_tbl_.template lookup_single_elem<RCU_LOCK_FAST>(madhava_id, get_uint64_hash(madhava_id), mstatshr);
	if (bret == true) {
		pminfo = mstatshr.get_cref().get();
	}	
	
	curr_nmadhava = madhava_tbl_.template count_slow<RCU_LOCK_SLOW>();

	if (!pminfo) {
		/*
		 * Check if the number of registered madhava's is too large
		 */
		if (curr_nmadhava >= MAX_MADHAVA_PER_SHYAMA) {
			send_l1_register_connect_error<MS_REGISTER_RESP_S, MS_REGISTER_RESP>(dbarr.pl1_src_, dbarr.shrconn_, dbarr.shrconn_.get(), 
				dbarr.comm_magic_, statsmap, ERR_MAX_LIMIT,  "Maximum Number of Allowed Madhava Servers Limit Breached", pthrpoolarr);

			ERRORPRINT_OFFLOAD("Madhava Registration Request for \'%s\' Domain %s Port %hu rejected as Max number of Madhava servers allowed already reached %lu\n", 
				pms->madhava_name_, pms->madhava_hostname_, pms->madhava_port_, curr_nmadhava);

			statsmap["Max Madhava Limit Reached"]++;
			return -1;
		}	

		pminfo = new MADHAVA_INFO(pms->madhava_hostname_, pms->madhava_port_, madhava_id);
		
		MADHAVA_INFO_ELEM		*pelem; 
		
		try {
			pelem = new MADHAVA_INFO_ELEM(pminfo);
		}
		catch(...) {
			delete pminfo;
			throw;
		}	

		mstatshr = *pelem;

		auto milam = [&](MADHAVA_INFO_ELEM *poldelem, MADHAVA_INFO_ELEM *pnewelem) noexcept
		{
			mstatshr = *poldelem;
		};	

		auto bret = madhava_tbl_.insert_unique(pelem, madhava_id, get_uint64_hash(madhava_id), milam, true /* delete_after_callback */);

		if (bret == true) {
			curr_nmadhava++;
			is_new = true;

			last_madhava_chg_tusec_.store(get_usec_time(), mo_release);
		}
		else {
			pminfo = mstatshr.get_cref().get();

			if (!pminfo) {
				GY_THROW_EXCEPTION("[Internal Error]: Null Madhava element seen in Madhava Map");
			}	
		}	
	}	
	
	SCOPE_GY_MUTEX			scopelock(pminfo->mutex_);

	if (!is_new) {
		/*
		 * Check if the Madhava instance has same Service Host/port. If not, it could be a standby Madhava
		 * taking over in which case we need to close all conns to previous madhava if still connected...
		 */
		if (pminfo->get_port() != pms->madhava_port_ || strcmp(pminfo->get_hostname(), pms->madhava_hostname_)) {

			if (pminfo->prev_instance_.get_port() == pms->madhava_port_ && (!strcmp(pminfo->prev_instance_.get_domain(), pms->madhava_hostname_))) {

				if (tcurrusec/GY_USEC_PER_SEC < (uint64_t)pminfo->tignore_till_) {
					scopelock.unlock();
					
					send_l1_register_connect_error<MS_REGISTER_RESP_S, MS_REGISTER_RESP>(dbarr.pl1_src_, dbarr.shrconn_, dbarr.shrconn_.get(), 
						dbarr.comm_magic_, statsmap, ERR_ID_REUSED,  
						"Another Madhava Instance has registered as the Master instance for the Madhava ID specified", pthrpoolarr);

					ERRORPRINT_OFFLOAD("Madhava Registration Request for \'%s\' from Domain %s Port %hu with ID %016lx rejected "
						"as another Madhava Instance has already registered for same Madhava ID...\n", 
						pms->madhava_name_, pms->madhava_hostname_, pms->madhava_port_, pminfo->madhava_id_);

					return -1;
				}	
			}

			INFOPRINT_OFFLOAD("Registered Connection from a Standby Madhava Server which has now become master for \'%s\' from Host %s Port %hu with ID %016lx : "
				"Closing connections to older Madhava host %s port %hu if any...\n", 
				pms->madhava_name_, pms->madhava_hostname_, pms->madhava_port_, pminfo->madhava_id_, pminfo->get_hostname(), pminfo->get_port());
			
			// Save the current Host/Port as previous to reject any new conns from the older instance for next 2 min
			pminfo->prev_instance_ = pminfo->listener_port_;
			pminfo->tignore_till_ = time(nullptr) + 120;

			pminfo->listener_port_.set(pms->madhava_hostname_, pms->madhava_port_);

			scopelock.unlock();

			close_all_conns(*pminfo);

			statsmap["Standby Madhava Registered"]++;

			scopelock.setlock(&pminfo->mutex_);
		}	
	}	

	pminfo->last_reg_tusec_		= tcurrusec;
	pminfo->npartha_nodes_.store(pms->last_partha_nodes_, mo_relaxed);
	pminfo->max_partha_nodes_ 	= pms->max_partha_nodes_;
	
	pminfo->diff_sys_sec_ 		= tcurrusec/GY_USEC_PER_SEC - pms->curr_sec_;

	pconn1->get_peer_ip(pminfo->remote_ip_);
	
	pminfo->comm_version_		= pms->comm_version_;
	pminfo->madhava_version_	= pms->madhava_version_;
	pminfo->kern_version_num_	= pms->kern_version_num_;

	GY_STRNCPY(pminfo->region_name_, pms->region_name_, sizeof(pminfo->region_name_));
	GY_STRNCPY(pminfo->zone_name_, pms->zone_name_, sizeof(pminfo->zone_name_));
	GY_STRNCPY(pminfo->madhava_name_, pms->madhava_name_, sizeof(pminfo->madhava_name_));

	/*GY_SAFE_MEMCPY(pminfo->host_tagname_, sizeof(pminfo->host_tagname_) - 1, pms->node_tagname_, pms->taglen_, pminfo->host_taglen_);*/
	/*pminfo->host_tagname_[pminfo->host_taglen_] = '\0';*/

	scopelock.unlock();

	pminfo->add_conn(dbarr.pl1_src_, dbarr.shrconn_, dbarr.shrconn_.get(), HOST_MADHAVA, pms->cli_type_);
	
	// Now update the conn table params
	pconn1->host_type_		= HOST_MADHAVA;
	pconn1->cli_type_		= pms->cli_type_;
	pconn1->madhava_shr_		= pminfo->shared_from_this();
	pconn1->set_registered();

	// Now schedule the response

	uint8_t				*palloc;
	FREE_FPTR			free_fp_hdr;
	static constexpr size_t		fixed_sz = sizeof(comm::COMM_HEADER) + sizeof(MS_REGISTER_RESP_S);
	uint32_t			act_size;

	palloc = (uint8_t *)pthrpoolarr->safe_malloc(fixed_sz, free_fp_hdr, act_size);

	comm::COMM_HEADER		*phdr = reinterpret_cast<comm::COMM_HEADER *>(palloc);
	MS_REGISTER_RESP_S		*presp = reinterpret_cast<MS_REGISTER_RESP_S *>((uint8_t *)phdr + sizeof(comm::COMM_HEADER)); 
	
	new (phdr) comm::COMM_HEADER(MS_REGISTER_RESP, fixed_sz, dbarr.comm_magic_);

	std::memset((void *)presp, 0, sizeof(*presp));

	presp->error_code_		= ERR_SUCCESS;
	GY_STRNCPY(presp->error_string_, "Successfully Registered", sizeof(presp->error_string_));

	presp->comm_version_		= pms->comm_version_;
	presp->shyama_version_		= gversion_num;
	presp->shyama_id_		= gshyama_id_;
	presp->madhava_id_		= pminfo->madhava_id_;
	presp->nmadhava_reg_		= curr_nmadhava;
	presp->nmadhava_partha_		= nmadhava_partha_.load(mo_acquire);

	GY_STRNCPY(presp->region_name_, region_name_, sizeof(presp->region_name_));
	GY_STRNCPY(presp->zone_name_, zone_name_, sizeof(presp->zone_name_));
	GY_STRNCPY(presp->shyama_name_, shyama_name_, sizeof(presp->shyama_name_));

	presp->curr_sec_		= time(nullptr);
	presp->clock_sec_		= get_sec_clock();

	if (is_new && pms->last_partha_nodes_ > 0) {
		presp->flags_		= comm::MS_REGISTER_RESP_S::CONN_FLAGS_RESET_STATS | comm::MS_REGISTER_RESP_S::CONN_FLAGS_SEND_PARTHAS;
	}	
	else {
		presp->flags_		= 0;
	}	

	struct iovec			iov[3] {{phdr, sizeof(*phdr)}, {presp, sizeof(*presp)}, {(void *)gpadbuf, phdr->get_pad_len()}};	
	FREE_FPTR			free_fp_arr[3] {free_fp_hdr, nullptr, nullptr};

	pconn1->schedule_ext_send(EPOLL_IOVEC_ARR(iov, GY_ARRAY_SIZE(iov), free_fp_arr, false));
	
	L1_SEND_DATA			l1data(dbarr.pl1_src_, dbarr.shrconn_, dbarr.shrconn_.get(), dbarr.comm_magic_, MS_REGISTER_RESP, false /* close_conn_on_send */);
	int				ntries = 0;

	do { 
		bret = dbarr.pl1_src_->psignalq_->write(std::move(l1data));
	} while (bret == false && ntries++ < 10);

	if (bret == false) {
		statsmap["L1 Notify Blocked"]++;
		ERRORPRINT_OFFLOAD("Failed to signal Madhava Register response for %s port %hu as L1 is blocked...\n", pms->madhava_hostname_, pms->madhava_port_);
		return 1;
	}

	int64_t			n = 1;

	(void)::write(dbarr.pl1_src_->signal_fd_, &n, sizeof(int64_t));
	
	if (is_new) {
		statsmap["New Madhava Registered"]++;
		
		INFOPRINT_OFFLOAD("Registered New Madhava Server \'%s\' from Host %s Port %hu with ID %016lx from Region %s Zone %s and Remote IP %s "
					"with max Partha Nodes %u and current Partha Nodes %u.\n", 
			pms->madhava_name_, pms->madhava_hostname_, pms->madhava_port_, pminfo->madhava_id_, pminfo->region_name_, pminfo->zone_name_, 
			pminfo->remote_ip_.printaddr(STRING_BUFFER<128>().get_str_buf()), pminfo->max_partha_nodes_, pms->last_partha_nodes_);
	}
	else {
		statsmap["Existing Madhava Registered"]++;
		
		INFOPRINT_OFFLOAD("Registered Connection from existing Madhava Server \'%s\' "
			"from Host %s Port %hu with ID %016lx from Remote IP %s with max Partha Nodes %u and current Partha Nodes %u.  "
			"Current # connections from this Madhava instance is %lu\n", pms->madhava_name_,
			pms->madhava_hostname_, pms->madhava_port_, pminfo->madhava_id_, pminfo->remote_ip_.printaddr(STRING_BUFFER<128>().get_str_buf()), 
			pminfo->max_partha_nodes_, pms->last_partha_nodes_, pminfo->get_num_conns());
	}	

	if (pms->cli_type_ == CLI_TYPE_RESP_REQ) {
		send_madhava_all_info(pminfo, dbarr.shrconn_);
	}	

	return 0;
}	

int SHCONN_HANDLER::handle_misc_partha_reg(PS_REGISTER_REQ_S *preg, const DB_WRITE_ARR & dbarr, L2_PARAMS & param, POOL_ALLOC_ARRAY *pthrpoolarr, STATS_STR_MAP & statsmap)
{
	auto				pconn1 = dbarr.shrconn_.get();

	if (nullptr == pconn1) {
		statsmap["Partha Disconnected"]++;

		return 1;
	}

	uint64_t			ign_madid = 0;
	bool				bret, found = false, is_new = false, is_success = true, errbyreassign = false;
	int				ret;
	std::shared_ptr <MADHAVA_INFO>	shrmadhav;
	GY_MACHINE_ID			machid (preg->machine_id_hi_, preg->machine_id_lo_);
	const uint32_t			mhash = machid.get_hash();
	
	// TODO Validate partha write_access_key_ from DB in case partha registration is to be secured

	uint8_t				*palloc;
	FREE_FPTR			free_fp_hdr;
	static constexpr size_t		fixed_sz = sizeof(comm::COMM_HEADER) + sizeof(PS_REGISTER_RESP_S);
	uint32_t			act_size;

	palloc = (uint8_t *)pthrpoolarr->safe_malloc(fixed_sz, free_fp_hdr, act_size);

	GY_SCOPE_EXIT {
		if (palloc && free_fp_hdr) {
			(*free_fp_hdr)(palloc);
		}	
	};

	comm::COMM_HEADER		*phdr = reinterpret_cast<comm::COMM_HEADER *>(palloc);
	PS_REGISTER_RESP_S		*presp = reinterpret_cast<PS_REGISTER_RESP_S *>((uint8_t *)phdr + sizeof(comm::COMM_HEADER)); 
	
	new (phdr) comm::COMM_HEADER(PS_REGISTER_RESP, fixed_sz, dbarr.comm_magic_);

	std::memset((void *)presp, 0, sizeof(*presp));

	presp->comm_version_		= preg->comm_version_;
	presp->shyama_version_		= gversion_num;
	presp->shyama_id_		= gshyama_id_;
	
	pconn1->host_type_		= HOST_PARTHA;

	uint64_t			tcurr_usec = get_usec_time();

	/*
	 * First check if this partha is previously registered
	 * If found, we first check if corresponding madhava is still available. If not, we need to assign a new madhava
	 * Else check if madhava is currently connected.
	 * If connected, then return success.
	 * If not, then return ERR_MADHAVA_UNAVAIL as madhava host/procs may be restarting
	 * in which case the Partha host will need to recheck till a new Madhava is assigned
	 */

	auto upd_pinfo = [&](PARTHA_INFO *pinfo) 
	{
		pinfo->comm_version_		= preg->comm_version_;
		pinfo->partha_version_		= preg->partha_version_;
		pinfo->machine_id_		= {preg->machine_id_hi_, preg->machine_id_lo_};
		
		GY_STRNCPY(pinfo->hostname_, preg->hostname_, sizeof(pinfo->hostname_));
		/*GY_STRNCPY(pinfo->write_access_key_, preg->write_access_key_, sizeof(pinfo->write_access_key_));*/
		GY_STRNCPY(pinfo->cluster_name_, preg->cluster_name_, sizeof(pinfo->cluster_name_));

		GY_STRNCPY(pinfo->region_name_, preg->region_name_, sizeof(pinfo->region_name_));
		GY_STRNCPY(pinfo->zone_name_, preg->zone_name_, sizeof(pinfo->zone_name_));
			
		pinfo->kern_version_num_	= preg->kern_version_num_;
		
		/*GY_SAFE_MEMCPY(pinfo->node_tagname_, sizeof(pinfo->node_tagname_) - 1, preg->node_tagname_, preg->taglen_, pinfo->node_taglen_);*/
		
		pconn1->get_peer_ip(pinfo->remote_ip_);
	};

	auto parlam = [&, this](PARTHA_INFO *pinfo, void *arg1, void *arg2) -> CB_RET_E
	{
		shrmadhav 		= pinfo->madhava_weak_.lock();
		auto			pmad = shrmadhav.get();

		if (!pmad) {
			// Madhava was deleted. We need to assign a new Madhava instance
			ERRORPRINT_OFFLOAD("Partha Registration Request for Machine ID %016lx%016lx from %s and hostname %s : Previous Madhava is no longer available (id %016lx). "
				"Will assign a new Madhava. All previous data may be lost...\n", 
				preg->machine_id_hi_, preg->machine_id_lo_, pconn1->print_peer(STRING_BUFFER<128>().get_str_buf()), preg->hostname_, pinfo->madhava_id_);

			statsmap["Partha Madhava Reassignment"]++;

			ign_madid = preg->last_madhava_id_;
			
			errbyreassign = true;

			return CB_DELETE_ELEM;
		}
		
		if (preg->last_mdisconn_sec_ > 0 && preg->curr_sec_ > preg->last_mdisconn_sec_ + 1800 && pmad->madhava_id_ == preg->last_madhava_id_ && 
			pinfo->last_register_tusec_ < get_usec_time() - 5 * GY_USEC_PER_MINUTE && pinfo->last_register_tusec_ > 0) {

			/*
			 * Its more than 30 min since we assigned a Madhava to this Partha and its still not registered.
			 * We need to reassign a new Madhava as seems the assigned Madhava is rejecting registration or 
			 * Partha cannot connect to that Madhava...
			 */
			ERRORPRINT_OFFLOAD("Partha Registration Request for Machine ID %016lx%016lx from %s and hostname %s : Assigned Madhava is not accepting registration since %ld min (Host %s). "
				"Will assign a new Madhava. All previous data may be lost...\n", 
				preg->machine_id_hi_, preg->machine_id_lo_, pconn1->print_peer(STRING_BUFFER<128>().get_str_buf()), 
				preg->hostname_, (preg->curr_sec_ - preg->last_mdisconn_sec_)/60, pmad->get_hostname());

			statsmap["Partha Madhava Reassignment"]++;

			ign_madid = preg->last_madhava_id_;

			errbyreassign = true;

			return CB_DELETE_ELEM;
		}

		found = true;

		upd_pinfo(pinfo);

		presp->error_code_ 		= ERR_SUCCESS;

		GY_CC_BARRIER();

		presp->partha_ident_key_	= pinfo->set_ident_key(tcurr_usec);

		presp->madhava_expiry_sec_	= time(nullptr) + 300 - 5;
		presp->madhava_id_		= pmad->madhava_id_;
		presp->madhava_port_		= pmad->listener_port_.get_port();

		GY_STRNCPY(presp->madhava_hostname_, pmad->listener_port_.get_domain(), sizeof(presp->madhava_hostname_));
		GY_STRNCPY(presp->madhava_name_, pmad->madhava_name_, sizeof(presp->madhava_name_));

		return CB_OK;
	};	

	auto send_madhava_key = [&, this]() -> bool
	{
		auto				pmad = shrmadhav.get();

		assert(pmad);
		if (!pmad) {
			return false;
		}	

		auto				madshrconn = pmad->get_last_conn(comm::CLI_TYPE_RESP_REQ);
		auto 				pmadconn = madshrconn.get();

		if (!pmadconn) {
			presp->error_code_	= ERR_MADHAVA_UNAVAIL;
			snprintf(presp->error_string_, sizeof(presp->error_string_), "Madhava Server is currently not connected. "
				"Please retry after some time. Time of last Madhava interaction was %s",
				gy_localtime_iso8601(pmad->get_last_oper_time()/GY_USEC_PER_SEC, CHAR_BUF<128>().get(), 128));

			ERRORPRINT_OFFLOAD("Partha Registration Request for Machine ID %016lx%016lx from %s and hostname %s "
					"with previous Madhava %s ID %016lx failed as %s\n",
					preg->machine_id_hi_, preg->machine_id_lo_, pconn1->print_peer(STRING_BUFFER<128>().get_str_buf()), 
					preg->hostname_, pmad->madhava_name_, pmad->madhava_id_, presp->error_string_);

			statsmap["Partha related Madhava unavailable"]++;
			
			is_success = false;

			return false;
		}	

		pmad->last_par_assign_tusec_	= get_usec_time();
		last_madhava_chg_tusec_.store(get_usec_time(), mo_release);

		uint8_t				*palloc2;
		FREE_FPTR			free_fp_hdr2;
		static constexpr size_t		fixed_sz2 = sizeof(comm::COMM_HEADER) + sizeof(comm::EVENT_NOTIFY) + sizeof(comm::SM_PARTHA_IDENT_NOTIFY);
		uint32_t			act_size2;

		palloc2 = (uint8_t *)pthrpoolarr->safe_malloc(fixed_sz2, free_fp_hdr2, act_size2);

		comm::COMM_HEADER		*phdr2 = reinterpret_cast<comm::COMM_HEADER *>(palloc2);
		EVENT_NOTIFY			*pevt2 = reinterpret_cast<EVENT_NOTIFY *>((uint8_t *)phdr2 + sizeof(comm::COMM_HEADER)); 
		SM_PARTHA_IDENT_NOTIFY		*pident2 = reinterpret_cast<SM_PARTHA_IDENT_NOTIFY *>((uint8_t *)pevt2 + sizeof(*pevt2));
		
		std::memset(palloc2, 0, fixed_sz2);

		new (phdr2) comm::COMM_HEADER(COMM_EVENT_NOTIFY, fixed_sz2, pmadconn->get_comm_magic());
		
		pevt2->subtype_			= NOTIFY_SM_PARTHA_IDENT;
		pevt2->nevents_			= 1;

		pident2->machine_id_hi_		= preg->machine_id_hi_;
		pident2->machine_id_lo_		= preg->machine_id_lo_;
		pident2->partha_ident_key_	= presp->partha_ident_key_;
		pident2->texpiry_sec_		= time(nullptr) + 300;
		pident2->is_new_host_		= is_new;
		GY_STRNCPY(pident2->hostname_, preg->hostname_, sizeof(pident2->hostname_));

		struct iovec			iov2[2] {{phdr2, fixed_sz2}, {(void *)gpadbuf, phdr2->get_pad_len()}};	
		FREE_FPTR			free_fp_arr2[2] {free_fp_hdr2, nullptr};
		
		pmadconn->schedule_ext_send(EPOLL_IOVEC_ARR(iov2, GY_ARRAY_SIZE(iov2), free_fp_arr2, false));

		L1_SEND_DATA			l1data(pmadconn->pl1_, pmadconn->weak_from_this(), pmadconn, pmadconn->get_comm_magic(), 
							COMM_EVENT_NOTIFY, false /* close_conn_on_send */);
		int				ntries = 0;
		bool				bret2;

		do { 
			bret2 = pmadconn->pl1_->psignalq_->write(std::move(l1data));
		} while (bret2 == false && ntries++ < 10);

		if (bret2 == false) {
			statsmap["L1 Notify Blocked"]++;
			statsmap["Partha Ident Notify Blocked"]++;
			ERRORPRINT_OFFLOAD("Failed to signal Madhava Notify for Partha Ident %016lx%016lx as L1 is blocked...\n", preg->machine_id_hi_, preg->machine_id_lo_);

			presp->error_code_	= ERR_BLOCKING_ERROR;
			snprintf(presp->error_string_, sizeof(presp->error_string_), "Shyama Server is handling too many requests. Please retry after some time.");

			is_success = false;

			return false;
		}

		int64_t			n = 1;

		(void)::write(pmadconn->pl1_->signal_fd_, &n, sizeof(int64_t));

		GY_STRNCPY(presp->error_string_, "Successfully Registered with Shyama. Please connect to Madhava after a few seconds...", sizeof(presp->error_string_));

		return true;
	};	

	auto send_par = [&, this]() -> int
	{
		struct iovec			iov[2] {{phdr, fixed_sz}, {(void *)gpadbuf, phdr->get_pad_len()}};	
		FREE_FPTR			free_fp_arr[2] {free_fp_hdr, nullptr};
		
		palloc = nullptr;

		pconn1->schedule_ext_send(EPOLL_IOVEC_ARR(iov, GY_ARRAY_SIZE(iov), free_fp_arr, false));

		L1_SEND_DATA			l1data(dbarr.pl1_src_, dbarr.shrconn_, dbarr.shrconn_.get(), 
							dbarr.comm_magic_, PS_REGISTER_RESP, false /* close_conn_on_send */);
		int				ntries = 0;
		bool				bret2;

		do { 
			bret2 = dbarr.pl1_src_->psignalq_->write(std::move(l1data));
		} while (bret2 == false && ntries++ < 10);

		if (bret2 == false) {
			statsmap["L1 Notify Blocked"]++;
			statsmap["Partha Register Resp Blocked"]++;

			ERRORPRINT_OFFLOAD("Failed to schedule Partha Register Response for ID %016lx%016lx as L1 is blocked...\n", preg->machine_id_hi_, preg->machine_id_lo_);

			is_success = false;

			return -1;
		}

		int64_t			n = 1;

		(void)::write(dbarr.pl1_src_->signal_fd_, &n, sizeof(int64_t));
		
		return 0;
	};
	
	bret = partha_tbl_.lookup_single_elem(machid, mhash, parlam);

	if (gy_unlikely(found == false)) {
		// New partha host or reassignment to another madhava

		if (false == madhava_tbl_.has_at_least(min_madhava_)) {
			presp->error_code_	= ERR_MADHAVA_UNAVAIL;
			
			size_t			nmad = madhava_tbl_.count_slow();

			snprintf(presp->error_string_, sizeof(presp->error_string_), 
					"Minimum number of Madhava Servers Required (%u) are not connected to Shyama server. "
						"Please try after starting at least %ld new Madhava Servers. Current number of Madhava servers is %lu",
						min_madhava_, min_madhava_ - nmad, nmad);

			ERRORPRINT_OFFLOAD("Failed to register new Partha Host for ID %016lx%016lx from Remote IP %s and Hostname %s as %s\n",
					preg->machine_id_hi_, preg->machine_id_lo_, pconn1->print_peer(STRING_BUFFER<128>().get_str_buf()), 
					preg->hostname_, presp->error_string_);

			send_par();

			return -1;
		}

		if (errbyreassign) {
			presp->error_code_	= ERR_MADHAVA_UNAVAIL;
			
			size_t			nmad = madhava_tbl_.count_slow();

			snprintf(presp->error_string_, sizeof(presp->error_string_), 
					"Madhava server assigned is no longer available or curently not accepting new hosts. Please try connecting after some time");
						
			send_par();

			return -1;
		}	

		shrmadhav = assign_partha_madhava(preg->hostname_, machid, preg->region_name_, preg->zone_name_, preg->last_madhava_id_, preg->cluster_name_, ign_madid);
		
		auto			pmad = shrmadhav.get();

		if (!pmad) {
			presp->error_code_	= ERR_MADHAVA_UNAVAIL;

			if (!pmad) {
				snprintf(presp->error_string_, sizeof(presp->error_string_), 
					"No Madhava Server currently connected or all connected Madhava Servers currently have no idle capacity. Please try after starting a new Madhava Server");
			}

			ERRORPRINT_OFFLOAD("Failed to register new Partha Host for ID %016lx%016lx from Remote IP %s and Hostname %s as %s\n",
					preg->machine_id_hi_, preg->machine_id_lo_, pconn1->print_peer(STRING_BUFFER<128>().get_str_buf()), 
					preg->hostname_, presp->error_string_);

			send_par();

			return -1;
		}	

		is_new = true;
		
		PARTHA_INFO 			*pinfo;
		
		pinfo = new PARTHA_INFO();

		upd_pinfo(pinfo);

		pinfo->madhava_weak_		= pmad->weak_from_this();
		pinfo->madhava_id_		= pmad->madhava_id_;

		presp->error_code_ 		= ERR_SUCCESS;
		presp->partha_ident_key_	= pinfo->set_ident_key(tcurr_usec);

		presp->madhava_id_		= pmad->madhava_id_;
		presp->madhava_port_		= pmad->listener_port_.get_port();

		GY_STRNCPY(presp->madhava_hostname_, pmad->listener_port_.get_domain(), sizeof(presp->madhava_hostname_));

		bret = partha_tbl_.insert_unique(pinfo, machid, mhash);
		if (bret == false) {
			GY_THROW_EXCEPTION("Partha Registration race condition seen : Please retry later : "
				"Will close current partha connection for Partha Host for ID %016lx%016lx from Remote IP %s and Hostname %s",
				preg->machine_id_hi_, preg->machine_id_lo_, pconn1->print_peer(STRING_BUFFER<128>().get_str_buf()), preg->hostname_);
		}	
	}	

	std::atomic_thread_fence(mo_acq_rel);

	// We first need to send the partha_ident_key_ to Madhava
	bret = send_madhava_key();
	
	std::atomic_thread_fence(mo_acq_rel);

	// Now send the partha Register response
	ret = send_par();

	if (ret == 0 && shrmadhav && is_success) {
		INFOPRINT_OFFLOAD("Registered %s Partha Host with ID %016lx%016lx Hostname %s Region %s Zone %s with Madhava Server %s Host %s Port %hu Region %s Zone %s\n", 
			is_new ? "New" : "Existing", preg->machine_id_hi_, preg->machine_id_lo_, preg->hostname_, preg->region_name_, preg->zone_name_, shrmadhav->madhava_name_,
			shrmadhav->listener_port_.get_domain(), shrmadhav->listener_port_.get_port(), shrmadhav->region_name_, shrmadhav->zone_name_);
		
		if (is_new) {
			statsmap["New Partha Registered"]++;
		}
		else {
			statsmap["Existing Partha Registered"]++;
		}	

		// The DB will be updated later by sync_partha_madhava_node_stats()
	}	

	return ret;
}

int SHCONN_HANDLER::handle_misc_node_reg(NS_REGISTER_REQ_S *pns, const DB_WRITE_ARR & dbarr, L2_PARAMS & param, POOL_ALLOC_ARRAY *pthrpoolarr, STATS_STR_MAP & statsmap)
{
	auto				pconn1 = dbarr.shrconn_.get();

	if (nullptr == pconn1) {
		statsmap["Node Disconnected"]++;

		return 1;
	}

	bool				bret, is_new = false;
	NODE_INFO			*pninfo = nullptr;
	std::shared_ptr<NODE_INFO>	nodeshr;	
	DOMAIN_PORT			domain_port(pns->node_hostname_, pns->node_port_);
	
	SCOPE_GY_MUTEX			scopelock(&node_mutex_);

	auto it = node_tbl_.find(domain_port);
	
	if (it != node_tbl_.end()) {
		nodeshr = it->second;
		pninfo = it->second.get();

		if (pninfo && ((pninfo->listener_port_.get_port() != pns->node_port_) || (0 != strcmp(pninfo->listener_port_.get_domain(), pns->node_hostname_)))) {
			send_l1_register_connect_error<NS_REGISTER_RESP_S, NS_REGISTER_RESP>(dbarr.pl1_src_, dbarr.shrconn_, dbarr.shrconn_.get(), 
				dbarr.comm_magic_, statsmap, ERR_MISMATCH_ID,  "Invalid Node domain or port as Node ID does not match", pthrpoolarr);

			ERRORPRINT_OFFLOAD("Invalid Node Registration request : "
				"Node ID is mapped to a different Domain %s or Port %hu compared to request domain %s port %hu\n", 
				pninfo->listener_port_.get_domain(), pninfo->listener_port_.get_port(), pns->node_hostname_, pns->node_port_);

			statsmap["Invalid Node Register Field"]++;
			return -1;
		}
	}

	if (!pninfo) {
		/*
		 * Check if the number of registered node's is too large
		 */
		if (gy_unlikely(node_tbl_.size() >= MAX_NODE_INSTANCES)) {
			send_l1_register_connect_error<NS_REGISTER_RESP_S, NS_REGISTER_RESP>(dbarr.pl1_src_, dbarr.shrconn_, dbarr.shrconn_.get(), 
				dbarr.comm_magic_, statsmap, ERR_MAX_LIMIT,  "Maximum Number of Allowed Node Servers Limit Breached", pthrpoolarr);

			ERRORPRINT_OFFLOAD("Node Registration Request for Domain %s Port %hu rejected as Max number of Node servers allowed already reached %lu\n", 
				pns->node_hostname_, pns->node_port_, node_tbl_.size());

			statsmap["Max Node Limit Reached"]++;
			return -1;
		}
		
		auto [nit, success] = node_tbl_.try_emplace(domain_port, nullptr);
		
		if (success == false) {
			return 1;
		}

		try {
			nit->second = std::make_shared<NODE_INFO>(domain_port);
		}
		GY_CATCH_EXCEPTION(
			ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught while creating new Node entry %s\n", GY_GET_EXCEPT_STRING);
			node_tbl_.erase(nit);

			send_l1_register_connect_error<NS_REGISTER_RESP_S, NS_REGISTER_RESP>(dbarr.pl1_src_, dbarr.shrconn_, dbarr.shrconn_.get(), 
				dbarr.comm_magic_, statsmap, ERR_SERV_ERROR,  "Exception occurred while adding entry", pthrpoolarr);

			return -1;
		);

		nodeshr = nit->second;
		pninfo = nit->second.get();

		is_new = true;
	}	
	
	scopelock.unlock();

	pninfo->diff_sys_sec_ 		= time(nullptr) - pns->curr_sec_;
	pconn1->get_peer_ip(pninfo->remote_ip_);
	
	pninfo->comm_version_		= pns->comm_version_;
	pninfo->node_version_		= pns->node_version_;

	pninfo->add_conn(dbarr.pl1_src_, dbarr.shrconn_, dbarr.shrconn_.get(), HOST_NODE_WEB, pns->cli_type_);

	// Now update the conn table params
	pconn1->host_type_		= HOST_NODE_WEB;
	pconn1->cli_type_		= pns->cli_type_;
	pconn1->node_shr_		= pninfo->shared_from_this();
	pconn1->set_registered();
	
	// Now schedule the response

	uint8_t				*palloc;
	FREE_FPTR			free_fp_hdr;
	static constexpr size_t		fixed_sz = sizeof(comm::COMM_HEADER) + sizeof(NS_REGISTER_RESP_S);
	uint32_t			act_size;

	palloc = (uint8_t *)pthrpoolarr->safe_malloc(fixed_sz, free_fp_hdr, act_size);

	comm::COMM_HEADER		*phdr = reinterpret_cast<comm::COMM_HEADER *>(palloc);
	NS_REGISTER_RESP_S		*presp = reinterpret_cast<NS_REGISTER_RESP_S *>((uint8_t *)phdr + sizeof(comm::COMM_HEADER)); 
	
	new (phdr) comm::COMM_HEADER(NS_REGISTER_RESP, fixed_sz, dbarr.comm_magic_);

	std::memset((void *)presp, 0, sizeof(*presp));

	presp->error_code_		= ERR_SUCCESS;
	GY_STRNCPY(presp->error_string_, "Successfully Registered", sizeof(presp->error_string_));
	presp->shyama_version_		= gversion_num;
	snprintf(presp->shyama_id_, sizeof(presp->shyama_id_), "%016lx", gshyama_id_);

	struct iovec			iov[3] {{phdr, sizeof(*phdr)}, {presp, sizeof(*presp)}, {(void *)gpadbuf, phdr->get_pad_len()}};	
	FREE_FPTR			free_fp_arr[3] {free_fp_hdr, nullptr, nullptr};

	pconn1->schedule_ext_send(EPOLL_IOVEC_ARR(iov, GY_ARRAY_SIZE(iov), free_fp_arr, false));
	
	L1_SEND_DATA			l1data(dbarr.pl1_src_, dbarr.shrconn_, dbarr.shrconn_.get(), dbarr.comm_magic_, NS_REGISTER_RESP, false /* close_conn_on_send */);
	int				ntries = 0;

	do { 
		bret = dbarr.pl1_src_->psignalq_->write(std::move(l1data));
	} while (bret == false && ntries++ < 3);

	if (bret == false) {
		statsmap["L1 Notify Blocked"]++;
		ERRORPRINT_OFFLOAD("Failed to signal Node Register response for %s port %hu as L1 is blocked...\n", pns->node_hostname_, pns->node_port_);
		return 1;
	}

	int64_t			n = 1;

	(void)::write(dbarr.pl1_src_->signal_fd_, &n, sizeof(int64_t));
	

	STRING_BUFFER<128>		strbuf;

	if (is_new) {
		INFOPRINT_OFFLOAD("Registered New Node Server for Host %s Port %hu from Remote IP %s\n", 
			pns->node_hostname_, pns->node_port_, pninfo->remote_ip_.printaddr(strbuf));
	}
	else {
		INFOPRINT_OFFLOAD("Registered Connection from existing Node Server"
			" for Host %s Port %hu from Remote IP %s Current # connections from this Node instance is %lu\n", 
			pns->node_hostname_, pns->node_port_, pninfo->remote_ip_.printaddr(strbuf), pninfo->get_num_conns());
	}	

	return 0;
}


bool SHCONN_HANDLER::send_l1_close_conn(const L1_PARAMS *pl1_src, std::weak_ptr <SHCONNTRACK> && weakconn, SHCONNTRACK *pconn, const char *errstr, uint32_t errlen) noexcept
{
	L1_MISC_NOTIFY		l1close(pl1_src, std::move(weakconn), pconn, errstr, errlen);

	bool			bret;
	int			ntries = 0;

	do { 
		bret = pl1_src->psignalq_->write(std::move(l1close));
	} while (bret == false && ntries++ < 10);

	if (bret == false) {
		return false;
	}

	int64_t			n = 1;

	(void)::write(pl1_src->signal_fd_, &n, sizeof(int64_t));
	
	return true;
}	


/*
 * Blocking Query to be sent to remote Node server (unless waitms == 0 in which case the caller is responsible for waiting).
 * 
 * The raw query data in a raw JSON Object format (must be JSON escaped using gy_escape_json() if needed):
 *	[ 
 *		{type : "parsefilter", id : "f1", data : "( ({ percentile(0.95, resp5s) > 100 }) or ({ percentile(0.95, qps5s) > 50 }) )" }, 
 *		{type : "currtime", id : "c1" }
 *	]
 */			
bool SHCONN_HANDLER::get_node_response_blocking(const char *rawqueryarr[], uint32_t lenarr[], uint32_t narr, const std::shared_ptr<COND_JSON_PARAM> & condshr, int waitms) 
{
	assert(false == gy_thread_rcu().is_rcu_in_read_lock());

	// Need at least 128 KB Stack
	assert(gy_get_thread_local().get_thread_stack_freespace() >= 128 * 1024);

	if (!narr || !rawqueryarr || !lenarr) {
		return false;
	}	

	auto				shrconn = get_any_node_conn();

	if (!shrconn) {
		return false;
	}	
	
	
	STACK_JSON_WRITER<32 * 1024, 8 * 1024>	writer;

	writer.StartArray();

	for (uint32_t i = 0; i < narr; ++i) {
		if (!rawqueryarr[i] || !lenarr[i]) {
			continue;
		}

		writer.RawStreamStart(rapidjson::kObjectType);
		writer.RawStream(rawqueryarr[i], lenarr[i]);
		writer.RawStreamEnd();
	}	
	
	writer.EndArray();

	const char			*pstr = writer.get_string();
	uint32_t			lenstr = writer.get_size();

	if (lenstr > comm::MAX_COMM_DATA_SZ >> 1) {
		GY_THROW_EXPRESSION("Remote Node Query : The total raw query size too large %u : Please reduce the number of queries or size", lenstr); 
	}	

	size_t				totallen = sizeof(COMM_HEADER) + sizeof(QUERY_CMD) + lenstr, nl = 0;

	void				*palloc = ::malloc(totallen);
	if (!palloc) {
		return false;
	}	

	GY_SCOPE_EXIT {
		if (palloc) {
			::free(palloc);
		}	
	};	

	COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
	QUERY_CMD			*pqry = reinterpret_cast<QUERY_CMD *>(phdr + 1); 
	bool				bret;

	new (phdr) COMM_HEADER(COMM_QUERY_CMD, totallen, comm::COMM_HEADER::NS_HDR_MAGIC);

	new (pqry) QUERY_CMD(get_usec_clock(), time(nullptr) + waitms >= 1000 ? waitms : 100 /* timeout */, QUERY_WEB_JSON, RESP_JSON_WITH_HEADER);

	std::memcpy((char *)(pqry + 1), pstr, lenstr);

	bret = schedule_l1_query(
	ASYNC_SOCK_CB(
		[this, condshr = condshr, ninput = narr](EPOLL_CONNTRACK *pconn, void * pact_resp, size_t nact_resp, void * presphdr, bool is_expiry, bool is_error) noexcept
		{
			auto errchk = [&]() noexcept
			{ 
				if (condshr->nupdated_.load(mo_relaxed) != 0) {
					return false;
				}	

				condshr->nupdated_.store(-1, mo_relaxed);
				return true;
			};

			auto lsuccess = [&]() noexcept
			{ 
				if (condshr->nupdated_.load(mo_relaxed) != 0) {
					return false;
				}	

				condshr->nupdated_.store(1, mo_relaxed);
				return true;
			};

			try {
				if (is_expiry || is_error || !pact_resp || !nact_resp) {
					snprintf(condshr->msg_, sizeof(condshr->msg_), "Remote Node Query Failed due to : %s", is_expiry ? "timeout expired" : "errored out");

					condshr->cond_.cond_signal(errchk);
					return false;
				}	

				char					*pjson = (char *)pact_resp, *pendptr = pjson + nact_resp;
				auto					& jdoc = condshr->doc_.get_doc();

				// Cannot use ParseInsitu
				jdoc.Parse(pjson, pendptr - pjson);

				if (jdoc.HasParseError()) {
					char			ebuf[256];
					const char		*perrorstr = rapidjson::GetParseError_En(jdoc.GetParseError());

					snprintf(condshr->msg_, sizeof(condshr->msg_), "Remote Node Query Failed due to JSON Error : %s", perrorstr);
					
					condshr->cond_.cond_signal(errchk);
					return false;
				}	

				condshr->cond_.cond_signal(lsuccess);
				return true;

			}
			GY_CATCH_EXPRESSION(
				snprintf(condshr->msg_, sizeof(condshr->msg_), "Remote Node Query Failed due to Exception : %s", GY_GET_EXCEPT_STRING);
					
				condshr->cond_.cond_signal(errchk);
				return false;
			);
		},
		pqry->get_seqid(), pqry->get_expiry_sec()
	), shrconn, EPOLL_IOVEC_ARR(2, false, phdr, phdr->get_act_len(), ::free, gpadbuf, phdr->get_pad_len(), nullptr));

	palloc = nullptr;	// So as to prevent ::free()

	if (waitms != 0) {
		auto waitchk = [&]() noexcept
		{ 
			return condshr->nupdated_.load(mo_relaxed) == 0;
		};

		auto ltimeout = [&]() noexcept 
		{
			condshr->nupdated_.store(-2, mo_relaxed);

			snprintf(condshr->msg_, sizeof(condshr->msg_), "Remote Node Query timed out waiting for result.");
		};	

		auto lamsuccess = []() noexcept {};

		int ret = condshr->cond_.cond_timed_wait(waitchk, ltimeout, lamsuccess, waitms);
		
		if (ret || condshr->nupdated_.load(mo_relaxed) != 1) {
			if (condshr->msg_[0]) {
				condshr->msg_[sizeof(condshr->msg_) - 1] = 0;

				WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "%s\n", condshr->msg_);
			}
			else {
				WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Remote Node Query failed due to an unknown reason...\n");
			}	

			return false;
		}
	}

	return true;
	
}	

void SHCONN_HANDLER::send_json_block_error(const DB_WRITE_ARR & dbarr) noexcept
{
	try {
		if (false == dbarr.validate()) {
			return;
		}

		if ((1 >= dbarr.shrconn_.use_count()) || (dbarr.shrconn_->is_conn_close_signalled())) {
			return;
		}	

		for (size_t i = 0; i < dbarr.ndbs_; ++i) {
			auto 			& dbone 	= dbarr.dbonearr_[i];

			uint8_t			*prdbuf 	= dbone.pwrbuf_;
			COMM_HEADER		*phdr 		= (COMM_HEADER *)prdbuf;
			QUERY_CMD		*pquery;

			switch (phdr->data_type_) {
		
			case COMM_QUERY_CMD :

				pquery = (QUERY_CMD *)(prdbuf + sizeof(COMM_HEADER));

				switch (pquery->subtype_) {
					
				case QUERY_WEB_JSON :
				case CRUD_GENERIC_JSON :
				case CRUD_ALERT_JSON :

					send_json_error_resp(dbarr.shrconn_, ERR_BLOCKING_ERROR, pquery->get_seqid(), "Query Blocked due to Large Request count",
							GY_CONST_STRLEN("Query Blocked due to Large Request count"));
					break;

				default :
					break;
				
				}

				break;

			default :
				break;
			}	
		}	
	}
	catch(...) {
	}	
}	

bool SHCONN_HANDLER::send_db_array(DB_WRITE_ARR && dbarr, uint32_t caller_thr_num, STATS_STR_MAP & statsmap, bool is_json_resp)
{
	L2_PARAMS		*parr;
	size_t			maxthr;

	switch (dbarr.dest_thr_type_) {
	
	case TTYPE_L2_MISC :
	default :
		parr = pl2_misc_arr_;
		maxthr = MAX_L2_MISC_THREADS;
		break;

	case TTYPE_L2_DB :
		parr 	= pl2_db_arr_;
		maxthr 	= MAX_L2_DB_THREADS;
		break;

	case TTYPE_L2_ALERT :	
		parr 	= pl2_alert_arr_;
		maxthr 	= MAX_L2_ALERT_THREADS;
		break;
	}

	L2_PARAMS		*pdbwr 	= parr + caller_thr_num % maxthr;
	bool			bret;
	int			ntries = 0;

	do { 
		bret = pdbwr->pmpmc_->write(std::move(dbarr));
	} while (bret == false && ntries++ < 2);

	if (bret == false) {
		// Try the next db thread once
		pdbwr = parr + (caller_thr_num + 1) % maxthr;

		bret = pdbwr->pmpmc_->write(std::move(dbarr));

		if (bret == false) {
			if (is_json_resp) {
				send_json_block_error(dbarr); 
			}	

			dbarr.dealloc();
			statsmap["Write Array Thread Blocked"]++;
		}	
	}

	return bret;
}

	

std::shared_ptr<SHCONN_HANDLER::SHCONNTRACK> SHCONN_HANDLER::get_any_node_conn() noexcept
{
	std::shared_ptr<SHCONNTRACK>	shrconn;
	SCOPE_GY_MUTEX			scopelock(node_mutex_);
		
	for (auto it = node_tbl_.begin(); it != node_tbl_.end(); ++it) {

		auto			pnod = it->second.get();

		if (!pnod) {
			continue;
		}
		
		shrconn = pnod->get_last_conn(comm::CLI_TYPE_REQ_RESP);

		if (shrconn) {
			break;
		}	
	}	

	return shrconn;
}	

int SHCONN_HANDLER::sync_partha_madhava_node_stats() noexcept
{
	RCU_DEFER_OFFLINE		deferlock;

	try {
		int64_t			npartha, nmadhav, nmaddel = 0, nmaddel_with_par = 0, nmadconn = 0, nmadnodes = 0;
		int64_t			nnode = 0, nnodedel = 0, nnodeconn = 0;
		uint64_t		cmin_statsec = get_sec_clock() - 10;
		uint64_t		curr_clock = get_usec_clock(), nmad = 0, last_mad = nmadhava_partha_.load(mo_relaxed);

		STRING_BUFFER<8000>	strbuf;

		auto lammad = [&, this, tlast = last_mn_db_upd_tusec_, cmin_statsec, curr_clock](MADHAVA_INFO_ELEM *pdatanode, void *arg1) -> CB_RET_E
		{
			auto			pmad = pdatanode->get_data()->get();
			uint64_t		last_oper;
			size_t			nconn;
			
			if (gy_unlikely(pmad == nullptr)) {
				nmaddel++;
				return CB_DELETE_ELEM;
			}	

			last_oper = pmad->get_last_oper_time();

			nconn = pmad->get_num_conns();
			nmadconn += nconn;

			if (nconn > 0) {
				nmadnodes++;
			}

			pmad->last_par_adds_.store(pmad->curr_par_adds_.exchange(0, mo_relaxed), mo_release);

			strbuf.appendfmt("\t\t\tMadhava %s Host %s port %hu Region %s Zone %s has %d Partha Hosts registered : Max allowed %u : # conns active %lu : Partha conns %u\n", 
					pmad->madhava_name_, pmad->listener_port_.get_domain(), pmad->listener_port_.get_port(), pmad->region_name_, pmad->zone_name_, 
					pmad->npartha_nodes_.load(mo_relaxed), pmad->max_partha_nodes_, nconn, pmad->approx_partha_conns_);

			if ((nconn > 0) && (pmad->last_status_csec_ > cmin_statsec)) {
				nmad += !!pmad->npartha_nodes_.load(mo_relaxed);
			}

			if (last_oper > tlast) {
			}	
			else {
				if ((nconn == 0) && (tlast - last_oper > MAX_HOST_DISCONNECT_RAM_USEC)) {
					// We need to delete this element
					nmaddel++;
					if (pmad->npartha_nodes_.load(mo_relaxed)) {
						nmaddel_with_par++;
					}	


					NOTEPRINT_OFFLOAD("Deleting Madhava %s Host %s port %hu Madhava ID %016lx from registered list as host has not connected since last %ld hours..."
						"%d Partha hosts were last handled by this Madhava...\n", 
						pmad->madhava_name_, pmad->listener_port_.get_domain(), pmad->listener_port_.get_port(), pmad->madhava_id_, 
						(tlast - last_oper)/GY_USEC_PER_HOUR, pmad->npartha_nodes_.load(mo_relaxed));

					auto 			shrmadhav = curr_madhava_.load(mo_acquire);
					decltype(shrmadhav)	nullshr;

					if (pmad == shrmadhav.get()) {
						curr_madhava_.compare_exchange_strong(shrmadhav, std::move(nullshr));
					}

					return CB_DELETE_ELEM;
				}	
			}
				
			return CB_OK;
		};

		nmadhav = madhava_tbl_.walk_hash_table(lammad);

		last_mad -= nmaddel_with_par;

		if (nmad > last_mad) {
			nmadhava_partha_.compare_exchange_strong(last_mad, nmad);
		}	
		if (nmaddel_with_par) {
			last_madhava_chg_tusec_.store(get_usec_time(), mo_release);
		}	

		last_mn_db_upd_tusec_	= get_usec_time();
		last_madhava_cnt_	= nmadnodes;
		npartha 		= partha_tbl_.count_slow();
			
		deferlock.offline_now();

		if (strbuf.length()) {
			INFOPRINT_OFFLOAD("List of Madhava servers : \n%s\n", strbuf.buffer());
		}

		INFOPRINT_OFFLOAD("Total Number of Madhava Hosts registered is %ld, # Madhava currently Connected is %ld, # Madhava recently Deleted is %ld, "
				"Total # of Connections from all Madhava hosts is %ld, # Madhava hosts with Partha registered = %lu\n"
				"\t\t\tNumber of Partha Hosts Registered is %lu\n", 
				nmadhav - nmaddel, nmadnodes, nmaddel, nmadconn, nmadhava_partha_.load(mo_relaxed), npartha);


		SCOPE_GY_MUTEX		scopelock(&node_mutex_);
			
		for (auto it = node_tbl_.begin(); it != node_tbl_.end(); ) {

			auto			pnod = it->second.get();

			if (!pnod) {
				it = node_tbl_.erase(it);
				nnodedel++;
				continue;
			}
			
			size_t			nconn = pnod->get_num_conns();

			if (nconn == 0) {
				it = node_tbl_.erase(it);

				nnodedel++;
				continue;
			}	
			
			nnodeconn += nconn;
			nnode++;

			last_node_version_ = pnod->node_version_;

			++it;
		}	

		last_node_cnt_ = nnode;

		scopelock.unlock();

		INFOPRINT_OFFLOAD("Total Number of Node Web servers registered is %ld, # Nodes recently Disconnected is %ld, Total # of Connections from all Node servers is %ld\n",
			nnode, nnodedel, nnodeconn);

		if (0 == nmadnodes) {
			WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Shyama Current status : No Madhava Servers currently connected to Shyama...\n");
		}	

		if (nnode == 0) {
			WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Shyama Current status : No Web Servers currently connected to Shyama...\n");
		}	

		if (palertmgr_ && 0 == palertmgr_->get_action_conn_count()) {
			WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Shyama Current status : No Action Handlers currently connected to Shyama...\n");
		}

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught while updating partha, madhava and node statistics to DB  : %s\n\n", GY_GET_EXCEPT_STRING);
		return -1;
	);
}	

void SHCONN_HANDLER::send_madhava_status() noexcept
{
	try {
		static constexpr size_t		fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + sizeof(SHYAMA_MADHAVA_STATUS);
		void				*palloc = GY_REFCNT::allocate_refbuf(fixed_sz);

		GY_SCOPE_EXIT {
			GY_REFCNT::sub_refcount_free(palloc);
		};	

		COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
		EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>((uint8_t *)phdr + sizeof(COMM_HEADER)); 
		SHYAMA_MADHAVA_STATUS		*pstat = reinterpret_cast<SHYAMA_MADHAVA_STATUS *>((uint8_t *)pnot + sizeof(*pnot));
		
		new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, fixed_sz, comm::COMM_HEADER::MS_HDR_MAGIC);
		
		pnot->subtype_			= comm::NOTIFY_SHYAMA_MADHAVA_STATUS;
		pnot->nevents_			= 1;

		pstat->nmadhava_reg_		= madhava_tbl_.count_slow();
		pstat->nmadhava_partha_		= nmadhava_partha_.load(mo_acquire);
		pstat->active_madhava_id_	= curr_madhava_id_.load(mo_relaxed);

		auto lammad = [&, this, palloc](MADHAVA_INFO_ELEM *pdatanode, void *arg1) -> CB_RET_E
		{
			auto		pmad = pdatanode->get_data()->get();
			
			if (gy_unlikely(pmad == nullptr)) {
				return CB_DELETE_ELEM;
			}	

			auto				madshrconn = pmad->get_last_conn(comm::CLI_TYPE_RESP_REQ);
			auto 				pconn1 = madshrconn.get();

			if (pconn1) {

				GY_REFCNT::add_refcount(palloc);

				schedule_l1_send_data(madshrconn, comm::COMM_EVENT_NOTIFY, 
					EPOLL_IOVEC_ARR(2, false, palloc, fixed_sz, GY_REFCNT::sub_refcount_free, gpadbuf, phdr->get_pad_len(), nullptr));
			}
			return CB_OK;
		};

		madhava_tbl_.walk_hash_table(lammad);

	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught while sending Madhava Status  : %s\n\n", GY_GET_EXCEPT_STRING);
	);
}	

std::tuple<void *, size_t, size_t> SHCONN_HANDLER::populate_madhava_list() const noexcept
{
	try {
		size_t				maxmad = madhava_tbl_.count_slow(), nmad = 0;
		size_t				fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + maxmad * sizeof(comm::MADHAVA_LIST);

		void				*palloc = GY_REFCNT::allocate_refbuf(fixed_sz);

		COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
		EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>((uint8_t *)phdr + sizeof(COMM_HEADER)); 
		MADHAVA_LIST			*pstat = reinterpret_cast<MADHAVA_LIST *>((uint8_t *)pnot + sizeof(*pnot));
			
		auto lammad = [&, this, pstat, maxmad](MADHAVA_INFO_ELEM *pdatanode, void *arg1) mutable
		{
			auto		pmad = pdatanode->get_cref().get();
			
			if (gy_unlikely(pmad == nullptr)) {
				return CB_OK;
			}	

			if (false == pmad->is_conn_available()) {
				return CB_OK;
			}

			pstat->madhava_id_		= pmad->madhava_id_;
			pstat->npartha_nodes_		= pmad->npartha_nodes_.load(mo_relaxed);
			pstat->madhava_version_		= pmad->madhava_version_;

			GY_STRNCPY(pstat->madhava_svc_hostname_, pmad->listener_port_.get_domain(), sizeof(pstat->madhava_svc_hostname_));
			pstat->madhava_svc_port_	= pmad->listener_port_.get_port();

			pstat++;
			nmad++;

			if (nmad == maxmad) {
				return CB_BREAK_LOOP;
			}	

			return CB_OK;
		};

		madhava_tbl_.walk_hash_table(lammad);
		
		if (nmad == 0) {
			// No Madhava active
			GY_REFCNT::sub_refcount_free(palloc);
			return {};
		}

		fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + nmad * sizeof(comm::MADHAVA_LIST);

		new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, fixed_sz, comm::COMM_HEADER::MS_HDR_MAGIC);
		new (pnot) EVENT_NOTIFY(comm::NOTIFY_MADHAVA_LIST, nmad);

		return {palloc, fixed_sz, phdr->get_pad_len()};
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while populating Madhava List for sending info : %s\n", GY_GET_EXCEPT_STRING);

		return {};
	);
}	

SA_SETTINGS_C * SHCONN_HANDLER::get_settings() const noexcept
{
	return pshyama_->psettings_;
}	

void SHCONN_HANDLER::send_all_list_madhava() noexcept
{
	try {
		const auto filtercb = [this, tcurrusec = get_usec_time()](MADHAVA_INFO *pmad) -> bool
		{
			// Ignore recently registered madhava's
			if (tcurrusec < pmad->last_reg_tusec_ + GY_USEC_PER_MINUTE) {
				return false;
			}

			return true;
		};	

		auto [palloc, fixed_sz, padlen] = populate_madhava_list();

		send_all_madhava_event(UNIQ_REFCNT(palloc), fixed_sz, padlen, &filtercb);
	}
	catch(...) {
	}	
}	


void SHCONN_HANDLER::send_madhava_all_info(MADHAVA_INFO *pminfo, const std::shared_ptr<SHCONNTRACK> & connshr) noexcept
{
	try {
		auto 			[palloc, fixed_sz, padlen] = populate_madhava_list();
		bool			bret;

		if (palloc) {
			bret = schedule_l1_send_data(connshr, comm::COMM_EVENT_NOTIFY, EPOLL_IOVEC_ARR(2, false, palloc, fixed_sz, GY_REFCNT::sub_refcount_free, gpadbuf, padlen, nullptr));
		}

		// Send all Alert definitions. This will result in all ongoing alerts within this Madhava to be cancelled
		send_madhava_all_alertdefs(pminfo, connshr);

		send_madhava_all_tracedefs(pminfo, connshr);
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to send Madhava %s info such as Madhava List and alert, trace definitions due to exception : %s\n", 
					pminfo->print_string(STRING_BUFFER<512>().get_str_buf()), GY_GET_EXCEPT_STRING);
	);	
}	

bool SHCONN_HANDLER::schedule_l1_send_data(const std::shared_ptr<SHCONNTRACK> & connshr, comm::COMM_TYPE_E data_type, EPOLL_IOVEC_ARR && data_arr, bool close_conn_on_send) noexcept
{
	auto 				pconn1 = connshr.get();
	bool				bret;

	if (pconn1) {
		bret = pconn1->schedule_ext_send(std::move(data_arr), false /* throw_on_error */);
		if (bret == false) {
			return false;
		}	

		L1_SEND_DATA		l1data(pconn1->pl1_, pconn1->weak_from_this(), pconn1, pconn1->get_comm_magic(), data_type, close_conn_on_send);

		bret = pconn1->pl1_->psignalq_->write(std::move(l1data));
		if (bret == true) {
			int64_t		n = 1;

			(void)::write(pconn1->pl1_->signal_fd_, &n, sizeof(int64_t));

			return true;
		}
	}

	return false;
}	

bool SHCONN_HANDLER::schedule_l1_query(ASYNC_SOCK_CB && async_cb, const std::shared_ptr<SHCONNTRACK> & connshr, EPOLL_IOVEC_ARR && data_arr) noexcept
{
	auto 				pconn1 = connshr.get();
	bool				bret;

	if (pconn1) {
		bret = pconn1->schedule_ext_send(std::move(data_arr), false /* throw_on_error */);
		if (bret == false) {
			goto err1;
		}	

		L1_SEND_DATA		l1data(std::move(async_cb), pconn1->pl1_, pconn1->weak_from_this(), pconn1, pconn1->get_comm_magic());

		bret = pconn1->pl1_->psignalq_->write(std::move(l1data));
		if (bret == true) {
			int64_t		n = 1;

			(void)::write(pconn1->pl1_->signal_fd_, &n, sizeof(int64_t));

			return true;
		}

		return false;
	}

err1 :	
	if (async_cb.is_valid()) {
		try {
			async_cb.fcb_(pconn1, nullptr, 0, nullptr, false /* is_expiry */, true /* is_error */);
		}
		catch(...) {
		}	
	}	

	return false;
}	

} // namespace shyama
} // namespace gyeeta

