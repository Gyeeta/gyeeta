//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include		"gy_common_inc.h"
#include		"gy_mconnhdlr.h"
#include		"gymadhava.h"
#include		"gy_listen_sock.h"
#include		"gy_print_offload.h"
#include 		"gy_scheduler.h"
#include		"gy_socket_stat.h"
#include		"gy_mdb_schema.h"
#include		"gy_malerts.h"
#include 		"gy_refcnt.h"
#include 		"gy_cloud_metadata.h"

#include 		<algorithm>

#include 		"folly/ThreadCachedInt.h"
#include 		"folly/Function.h"

#include 		<sys/epoll.h>
#include 		<sys/eventfd.h>
#include 		<sys/timerfd.h>

using namespace 	gyeeta::comm;

namespace gyeeta {
namespace madhava {

MCONN_HANDLER		*pgmconn_handler_ = nullptr;

MCONN_HANDLER::MCONN_HANDLER(MADHAVA_C *pmadhava)
	: pmadhava_(pmadhava), 
	pdb_scheduler_(GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_LONG_DURATION)),
	pdbmain_scheduler_(GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_MAINTENANCE)),
	listen_host_vec_(pmadhava->psettings_->listener_ip), listen_port_vec_(pmadhava->psettings_->listener_port)
{
	if (nullptr == pdb_scheduler_ || nullptr == pdbmain_scheduler_) {
		GY_THROW_EXCEPTION("Scheduler Singleton objects not yet initialized");
	}	

	auto 			psettings = pmadhava_->psettings_;
	time_t			tcurr, tnxt;

	if (psettings->listener_ip.size() > MAX_TCP_LISTENERS) {
		GY_THROW_EXCEPTION("Too many Listener IP/Ports specified. Max allowed is %lu", MAX_TCP_LISTENERS);
	}	
	
	if (nullptr == SYS_HARDWARE::get_singleton()) {
		GY_THROW_EXCEPTION("System Hardware Singleton not yet initialized");
	}
	
	try {
		GY_STRNCPY(service_hostname_, psettings->service_hostname, sizeof(service_hostname_));
		service_port_			= psettings->service_port;

		GY_STRNCPY(madhava_name_, psettings->madhava_name, sizeof(madhava_name_));

		gmadhava_id_			= gy_cityhash64(madhava_name_, strlen(madhava_name_));

		gshyama_.shyama_host_vec_	= psettings->shyama_hosts;
		gshyama_.shyama_port_vec_	= psettings->shyama_ports;

		GY_STRNCPY(gshyama_.curr_shyama_host_, psettings->shyama_hosts[0].data(), sizeof(gshyama_.curr_shyama_host_));
		gshyama_.curr_shyama_port_	= psettings->shyama_ports[0];

		GY_STRNCPY(gshyama_.shyama_secret_, psettings->shyama_secret, sizeof(gshyama_.shyama_secret_));

		INFOPRINT("Starting Madhava Server Listener Initialization : Madhava Name \'%s\' Service Domain \'%s\' Port %hu : ID %016lx...\n", 
			madhava_name_, psettings->service_hostname, psettings->service_port, gmadhava_id_);

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
			ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to start Madhava Listener : %s : Exiting...\n\n", GY_GET_EXCEPT_STRING);
			exit(EXIT_FAILURE);
		);
		
		pgmconn_handler_	= this;

		gmadhava_shr_ 		= std::make_shared<MADHAVA_INFO>(service_hostname_, service_port_, gmadhava_id_);
		gmadhava_weak_		= gmadhava_shr_;
		snprintf(gmadhava_id_str_, sizeof(gmadhava_id_str_), "%016lx", gmadhava_id_);

		db_storage_days_	= psettings->postgres_storage_days;

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

		set_max_partha_allowed();

		paccept_arr_ 		= new ACC_PARAMS[MAX_ACCEPT_THREADS];

		pl1_cli_arr_		= new L1_PARAMS[MAX_L1_CLI_THREADS];
		pl1_shyama_		= new L1_PARAMS[MAX_L1_SHYAMA_THREADS];

		pl2_db_rd_arr_		= new L2_PARAMS[MAX_L2_DB_READERS];
		pl2_misc_arr_		= new L2_PARAMS[MAX_L2_MISC_THREADS];
		pl2_alert_arr_		= new L2_PARAMS[MAX_L2_ALERT_THREADS];

		ppmpmc_db_rd_arr_	= new MPMCQ_COMM *[MAX_L2_DB_RD_POOLS];
		ppmpmc_misc_arr_	= new MPMCQ_COMM *[MAX_L2_MISC_POOLS];
		ppmpmc_alert_arr_	= new MPMCQ_COMM *[MAX_L2_ALERT_POOLS];

		for (size_t i = 0; i < MAX_L2_DB_RD_POOLS; ++i) {
			ppmpmc_db_rd_arr_[i]	= new MPMCQ_COMM(MAX_MPMC_ELEMS);
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

		pdbmain_scheduler_->add_schedule(501'080, 300'000, 0, "Send Shyama Partha Pings and check Node stats", 
		[this] { 
			sync_partha_node_stats();
		});

		pdbmain_scheduler_->add_schedule(702'080, 300'000, 0, "Print DB Error Stats", 
		[this] { 
			db_stats_.print_stats();
		});

		pdbmain_scheduler_->add_schedule(5000, 5000, 0, "Send Shyama Status Event", 
		[this] { 
			send_shyama_status();
		});

		pdbmain_scheduler_->add_schedule(55'300, 56'000, 0, "Send Partha Status Event", 
		[this] { 
			send_partha_status();
		});

		pdbmain_scheduler_->add_schedule(300'200, 300'000, 0, "Send Remote Madhava Status Event", 
		[this] { 
			send_remote_madhava_status();
		});

		tcurr = time(nullptr);
		tnxt = (tcurr / 5) * 5;

		pdbmain_scheduler_->add_schedule(101'400 + 5000 - (tcurr - tnxt) * 1000, 5000, 0, "Send Cluster State to Shyama", 
		[this] { 
			send_cluster_state();
		});

		auto 			schedshrhigh = GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_HIGH_PRIO);
	
		tcurr = time(nullptr); 
		tnxt = (tcurr / 30) * 30;

		schedshrhigh->add_schedule(60'230 + 3000 + 30'000 - (tcurr - tnxt) * 1000, 30'000, 0, "Cleanup the TCP Conn Table", 
		[this] { 
			cleanup_tcp_conn_table();
		});

		INFOPRINT("Madhava Listener Initialization Completed successfully...\n");
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception while starting Madhava Listener Handler : %s\n", GY_GET_EXCEPT_STRING);
		throw;
	);
}	

MCONN_HANDLER * MCONN_HANDLER::get_singleton() noexcept
{
	return pgmconn_handler_;
}	

void MCONN_HANDLER::init_db_glob_conns()
{
	auto 				psettings = pmadhava_->psettings_;
	std::optional<GyPGConn>		postconn;
	auto				dbname = get_dbname();
	char				cmd[256];
	
	INFOPRINT("Initiating Postgres Database connection pool and init commands...\n");

	try {
		postconn.emplace(psettings->postgres_hostname, psettings->postgres_port, psettings->postgres_user, psettings->postgres_password,
							"postgres", "madhava", get_db_init_commands().get(), false /* auto_reconnect */, 12, 2);
	}
	GY_CATCH_EXPRESSION(
		INFOPRINT_OFFLOAD("Failed to Login to Postgres default \'postgres' DB. Will try Madhava DB \'%s\' directly... : Exception message : %s\n",
			dbname.get(), GY_GET_EXCEPT_STRING);
		goto next;
	);
	
	if (bool(postconn)) {
		snprintf(cmd, sizeof(cmd), "select 1 from pg_database where datname = \'%s\'", dbname.get());

		auto			res = postconn->pqexec_blocking(cmd);
		
		if ((res.is_error()) || (0 == PQntuples(res.get())))  {
			INFOPRINT("Postgres Database \'%s\' not found for Madhava. Creating new database...\n", dbname.get());

			snprintf(cmd, sizeof(cmd), "create database %s;", dbname.get());

			auto		cres = postconn->pqexec_blocking(cmd);

			if (cres.is_error()) {
				GY_THROW_EXCEPTION("Postgres Database Host %s Port %s : Failed to create new database %s for Madhava : %s", 
						PQhost(postconn->get()), PQport(postconn->get()), dbname.get(), cres.get_error_no_newline().get());
			}	
		}

		postconn->close_conn();
	}

next :

	db_scheduler_pool_ = std::make_unique<PGConnPool>("DB Scheduler Pool", 3, psettings->postgres_hostname, psettings->postgres_port, psettings->postgres_user, psettings->postgres_password,
						dbname.get(), "madhava_sched", get_db_init_commands().get(), true /* auto_reconnect */, 12, 100, 10);

	if (true) {
		auto			pconn = db_scheduler_pool_->get_conn();
		
		if (!pconn) {
			GY_THROW_EXCEPTION("Failed to get Postgres Database connection from Scheduler connection pool");
		}	
	}
	
	// Now try to make the instance as master or keep trying till we succeed...
	auto 			[olddbver, oldprocver] = init_set_instance_master(*db_scheduler_pool_.get());

	// Now update global procs
	auto			pconn = db_scheduler_pool_->get_conn();
	
	if (!pconn) {
		GY_THROW_EXCEPTION("Failed to get Postgres Database connection from connection pool");
	}	
	
	auto 			gyres = pconn->pqexec_blocking(get_common_pg_procs());

	if (true == gyres.is_error()) {
		GY_THROW_EXCEPTION("Failed to execute query on Postgres DB to add global common Postgres procs : %s", gyres.get_error_no_newline().get());
	}

	upgrade_db_schemas(olddbver, oldprocver, pconn);

	gyres = pconn->pqexec_blocking(get_globtables());

	if (true == gyres.is_error()) {
		GY_THROW_EXCEPTION("Failed to execute query on Postgres DB to add global tables : %s", gyres.get_error_no_newline().get());
	}
	
	gyres = pconn->pqexec_blocking(get_glob_part_tables());

	if (true == gyres.is_error()) {
		GY_THROW_EXCEPTION("Failed to execute query on Postgres DB to add global partition functions : %s", gyres.get_error_no_newline().get());
	}

	gyres = pconn->pqexec_blocking(gy_to_charbuf<256>("select gy_add_glob_part_tables(%s::boolean);", psettings->db_logging != DB_LOGGING_ALWAYS ? "true" : "false").get());

	if (true == gyres.is_error()) {
		GY_THROW_EXCEPTION("Failed to execute query on Postgres DB to add global partition table : %s", gyres.get_error_no_newline().get());
	}

	gyres = pconn->pqexec_blocking(get_add_partha());

	if (true == gyres.is_error()) {
		GY_THROW_EXCEPTION("Failed to execute query on Postgres DB to add Partha Partition tables : %s", gyres.get_error_no_newline().get());
	}

	gyres = pconn->pqexec_blocking(get_views_cleanup_procs());

	if (true == gyres.is_error()) {
		GY_THROW_EXCEPTION("Failed to execute query on Postgres DB to add Partha Views and Cleanup proc : %s", gyres.get_error_no_newline().get());
	}

	pconn->make_available();

	db_cleanup_old_partitions(*db_scheduler_pool_.get(), false);

	db_add_init_partitions();

	db_trunc_init_entries("ARRAY[\'listentbl\']", "\'^sch[0-9a-f]{32}$\'");

	db_scheduler_pool_->wait_all_responses();

	// Run on dedicated scheduler thread as each iteration may last for an hour or more
	db_part_scheduler_.add_schedule(10 * GY_MSEC_PER_HOUR + 102, 10 * GY_MSEC_PER_HOUR, 0, "Add and Delete Postgres DB Partitions", 
	[this] { 
		db_add_partitions();
	});

	db_part_scheduler_.add_schedule(5 * GY_MSEC_PER_HOUR + 901, 12 * GY_MSEC_PER_HOUR, 0, "Set DB Partitions Logged", 
	[this] { 
		db_set_part_logged();
	});


	pdb_scheduler_->add_schedule(GY_MSEC_PER_DAY + 11301, GY_MSEC_PER_DAY, 0, "Delete entries expired from DB", 
	[this] { 
		db_del_entries(false /* is_check */);
	});

	pdb_scheduler_->add_schedule(GY_MSEC_PER_HOUR * 6 + 102, GY_MSEC_PER_HOUR * 6, 0, "Check if too many deleted entries in DB", 
	[this] { 
		db_del_entries(true /* is_check */);
	});

	pdb_scheduler_->add_schedule(GY_MSEC_PER_MINUTE * 20 + 132, GY_MSEC_PER_MINUTE * 20, 0, "Cleanup Partha non updated structs", 
	[this] { 
		cleanup_partha_unused_structs();
	});

	pdb_scheduler_->add_schedule(GY_MSEC_PER_MINUTE * 45 + 432, GY_MSEC_PER_MINUTE * 45, 0, "Cleanup remote Madhava non updated structs", 
	[this] { 
		cleanup_rem_madhava_unused_structs();
	});

	pdb_scheduler_->add_schedule(0, 60000, 0, "Set DB Disk Space Used", 
	[this] { 
		set_db_disk_space_used();
	});

	pdb_scheduler_->add_schedule(610'120, 60000, 0, "Reset DB Scheduler Idle connections", 
	[this] { 
		db_scheduler_pool_->reset_idle_conns();
	});

	INFOPRINT("Postgres DB Initialization Completed...\n");
}	

/*
 * Will not return till instance becomes a master
 * Returns {olddbver, oldprocver}
 */
std::pair<int, int> MCONN_HANDLER::init_set_instance_master(PGConnPool & dbpool)
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

	INFOPRINT("Checking if this instance is Madhava Master instance...\n");

	auto 			psettings = pmadhava_->psettings_;
	char			qbuf[2048], currhostip[MAX_DOMAINNAME_SIZE] = {};
	time_t			tstart = time(nullptr);
	const char		*name = "Check for Madhava Instance Master";
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
				INFOPRINT("Setting current Madhava instance as Master instance...\n");
			}
			else {
				INFOPRINT("Setting current Madhava instance as Master instance from Standby mode as previous master (host %s port %d) is not updating DB...\n",
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

		INFOPRINT("Madhava instance is in Standby mode : Current Master Instance is host \'%s\' port %d\n", currhostip, currport);
		
		ndataerr = 0;
	}
}	

int MCONN_HANDLER::instance_thread() noexcept
{
	instance_thr_->set_thread_init_done();

	try {
		char				qbuf[2048];
		const char			*name = "Check for Madhava Instance Master";
		int				nerr = 0, ndataerr = 0, port = 0, currport = 0, nerrormaster = 0;

		auto 				psettings = pmadhava_->psettings_;
		auto				dbname = get_dbname();
		PGConnPool			dbpool("DB Instance Pool", 2, psettings->postgres_hostname, psettings->postgres_port, psettings->postgres_user, psettings->postgres_password,
							dbname.get(), "madhava_instance", get_db_init_commands().get(), true /* auto_reconnect */, 12, 10, 10);

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

					pmadhava_->send_proc_restart_exit();
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

				pmadhava_->send_proc_restart_exit();
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

				pmadhava_->send_proc_restart_exit();
			}	

			if ((unsigned)nfields < 3) {
				if (++ndataerr < 10) {
					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "%s : Query Result received invalid column count %d instead of 3\n", name, nfields);
					continue;
				}

				ERRORPRINT("%s : Invalid DB Column count seen : %d instead of 3. Restarting process to allow other standby servers to take over..\n", name, nfields);
				pmadhava_->send_proc_restart_exit();
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
				pmadhava_->send_proc_restart_exit();
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

					pmadhava_->send_proc_restart_exit();
				}	
				
				if (port != (int)psettings->service_port) {
					if (++ndataerr < 10) {
						ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "%s : Instance is currently a Master but service port differs : %d instead of %hu\n", 
							name, port, psettings->service_port);
						continue;
					}

					ERRORPRINT("%s : Too many Errors as Query Result received with current as Master but different service port %d : "
						"Restarting process to allow other standby servers to take over..\n", name, port);

					pmadhava_->send_proc_restart_exit();
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

				pmadhava_->send_proc_restart_exit();
			}	
			
			ndataerr = 0;
			nerrormaster = 0;

			tlast_instance_ = time(nullptr);
		}
			
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught in Master Instance thread : %s : Restarting process...\n", GY_GET_EXCEPT_STRING);
		pmadhava_->send_proc_restart_exit();
	);
	
	return -1;

}	

bool MCONN_HANDLER::db_cleanup_old_partitions(PGConnPool & dbpool, bool is_non_block) noexcept
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

		for (size_t i = 0; i < GY_ARRAY_SIZE(db_glob_partition_tbls_); ++i) {
			cleanup_query.appendfmt("(\'%s\'),", db_glob_partition_tbls_[i]);
		}	

		cleanup_query.set_last_char(' ');

		cleanup_query.appendfmt(") as tbl(name)) select gy_cleanup_partition(nsname.ns::text, nsname.name::text, now()::date - %u) from nsname;\n", 
			db_storage_days_);
			
		cleanup_query.appendconst("with nsname(ns, name) as "
			"(select nstbl.ns, tbl.name from (select nspname from pg_catalog.pg_namespace where nspname ~ '^sch[0-9a-f]{32}$') as nstbl(ns) cross join (values");

		for (size_t i = 0; i < GY_ARRAY_SIZE(db_partha_partition_tbls_); ++i) {
			cleanup_query.appendfmt("(\'%s\'),", db_partha_partition_tbls_[i]);
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

bool MCONN_HANDLER::db_add_init_partitions() noexcept
{
	try {
		STRING_BUFFER<4096>		qbuf;
		bool				bret;
		auto 				psettings = pmadhava_->psettings_;

		auto				pconn = db_scheduler_pool_->get_conn(true /* wait_response_if_unavail */, 600'000 /* max_msec_wait */, true /* reset_on_timeout */);
		
		if (!pconn) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to schedule query to Postgres to add new DB Partition\n");
			db_stats_.nconns_failed_.fetch_add_relaxed(1, mo_relaxed);
			db_stats_.nadd_partition_failed_.fetch_add(1, mo_relaxed);
			return false;
		}	

		INFOPRINT_OFFLOAD("Sending Add New Partition Init Command to Postgres...\n");

		qbuf.appendfmt("select public.gy_add_partition(%u, ARRAY[", db_storage_days_);

		for (size_t i = 0; i < GY_ARRAY_SIZE(db_glob_partition_tbls_); ++i) {
			qbuf.appendfmt("\'%s\',", db_glob_partition_tbls_[i]);
		}	

		qbuf.set_last_char(' ');

		qbuf.appendfmt("], \'^public$\', %s::boolean);\n", psettings->db_logging != DB_LOGGING_ALWAYS ? "true" : "false");

		/*
		 * XXX We defer to Partha register and subsequent gy_add_partha() instead of init partition as 
		 * this takes a long time to complete
		
		qbuf.appendfmt("select public.gy_add_partition(%u, ARRAY[", db_storage_days_);

		for (size_t i = 0; i < GY_ARRAY_SIZE(db_partha_partition_tbls_); ++i) {
			qbuf.appendfmt("\'%s\',", db_partha_partition_tbls_[i]);
		}	

		qbuf.set_last_char(' ');

		qbuf.appendfmt("], \'^sch[0-9a-f]{32}$\', %s::boolean);\n", psettings->db_logging != DB_LOGGING_ALWAYS ? "true" : "false");

		*/

		qbuf.appendfmt("select public.gy_add_views_for_all(\'%s\');\n", gmadhava_id_str_);

		qbuf.appendconst("select public.gy_cleanup_schema();\n");

		bret = PQsendQueryOptim(pconn->get(), qbuf.buffer(), qbuf.size());
		
		if (bret == false) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to schedule query to Postgres to add new DB Partition : Error is %s\n", PQerrorMessage(pconn->get()));
			db_stats_.nadd_partition_failed_.fetch_add(1, mo_relaxed);
			return false;
		}	

		pconn->set_resp_cb(
			[this, iserr = false](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
			{
				if (is_completed) {
					if (conn.is_within_tran()) {
						conn.pqexec_blocking("Rollback Work;");
					}						
					conn.make_available();

					if (!iserr) {
						INFOPRINT_OFFLOAD("Added new Postgres DB Partitions successfully...\n");
					}	
					
					return true;
				}	
				
				if (true == gyres.is_error()) {
					iserr = true;

					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to execute query to add new DB Partitions : %s\n", 
						gyres.get_error_msg());
					db_stats_.nadd_partition_failed_.fetch_add(1, mo_relaxed);
					return false;
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

bool MCONN_HANDLER::db_add_partitions() noexcept
{
	try {
		using ParSet			= INLINE_STACK_HASH_SET<GY_MACHINE_ID, 64 * 1024, GY_MACHINE_ID::MAC_HASH>;

		ParSet				parset;
		STRING_BUFFER<4096>		qbuf;
		bool				bret;
		auto 				psettings = pmadhava_->psettings_;

		PGConnPool			dbpool("DB Partition Pool", 2, psettings->postgres_hostname, psettings->postgres_port, psettings->postgres_user, psettings->postgres_password,
							get_dbname().get(), "madhava_partition", get_db_init_commands().get(), true /* auto_reconnect */, 12, 10);


		auto lampar = [&](PARTHA_INFO_ELEM *pdatanode, void *arg1) -> CB_RET_E
		{
			auto			prawpartha = pdatanode->get_cref().get();
			
			if (gy_unlikely(prawpartha == nullptr)) {
				return CB_DELETE_ELEM;
			}	

			parset.emplace(prawpartha->machine_id_);

			return CB_OK;
		};

		partha_tbl_.walk_hash_table(lampar);

		EXEC_TIME			exectime("DB Partitions Add Command");

		INFOPRINT_OFFLOAD("Adding New Partitions to Postgres...\n");
		
		for (const auto & machid : parset) {

			auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 100'000 /* max_msec_wait */, true /* reset_on_timeout */);
			
			if (!pconn) {
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to schedule query to Postgres to add new DB Partition\n");
				db_stats_.nconns_failed_.fetch_add_relaxed(1, mo_relaxed);
				db_stats_.nadd_partition_failed_.fetch_add(1, mo_relaxed);
				return false;
			}	

			qbuf.reset();

			qbuf.appendfmt("select public.gy_add_partition(%u, ARRAY[", db_storage_days_);

			for (size_t i = 0; i < GY_ARRAY_SIZE(db_partha_partition_tbls_); ++i) {
				qbuf.appendfmt("\'%s\',", db_partha_partition_tbls_[i]);
			}	

			qbuf.set_last_char(' ');

			qbuf.appendfmt("], \'%s\', %s::boolean);\n", machid.get_string().get(), psettings->db_logging != DB_LOGGING_ALWAYS ? "true" : "false");

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
						ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to execute query to add new DB Partition : %s\n", gyres.get_error_msg());
						db_stats_.nadd_partition_failed_.fetch_add(1, mo_relaxed);
						return false;
					}	

					return true;
				}
			);

		}

		auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 100'000 /* max_msec_wait */, true /* reset_on_timeout */);

		if (!pconn) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to schedule query to Postgres to add new Global DB Partition and Cleanup unused ones\n");
			db_stats_.nconns_failed_.fetch_add_relaxed(1, mo_relaxed);
			db_stats_.nadd_partition_failed_.fetch_add(1, mo_relaxed);
			return false;
		}	

		qbuf.reset();

		qbuf.appendfmt("select public.gy_add_partition(%u, ARRAY[", db_storage_days_);

		for (size_t i = 0; i < GY_ARRAY_SIZE(db_glob_partition_tbls_); ++i) {
			qbuf.appendfmt("\'%s\',", db_glob_partition_tbls_[i]);
		}	

		qbuf.set_last_char(' ');

		qbuf.appendfmt("], \'^public$\', %s::boolean);\n", psettings->db_logging != DB_LOGGING_ALWAYS ? "true" : "false");

		qbuf.appendfmt("select public.gy_add_views_for_all(\'%s\');\n", gmadhava_id_str_);

		qbuf.appendconst("select public.gy_cleanup_schema();\n");

		auto			cres = pconn->pqexec_blocking(qbuf.buffer());
		
		if (cres.is_error()) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to execute query to Postgres to create Global DB Partitions and Cleanup unused ones : Error is %s\n", 
				cres.get_error_no_newline().get());
			return false;
		}	

		return true;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while updating Postgres DB for adding Table Partitions : %s\n", GY_GET_EXCEPT_STRING);
		return false;
	);
}


bool MCONN_HANDLER::db_set_part_logged() noexcept
{
	try {
		STRING_BUFFER<4096>		qbuf;
		bool				bret;
		auto 				psettings = pmadhava_->psettings_;

		if (psettings->db_logging == DB_LOGGING_NONE) {
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "DB Tables will be kept unlogged as \'db_logging\' option set to \'none\'. "
							"This will cause data loss in case of ungraceful DB shutdown...\n");
			return true;
		}
		else if (psettings->db_logging == DB_LOGGING_ALWAYS) {
			return true;
		}	

		GyPGConn			postconn(psettings->postgres_hostname, psettings->postgres_port, psettings->postgres_user, psettings->postgres_password,
									get_dbname().get(), "madhava_tbl_log", get_db_init_commands().get(), false /* auto_reconnect */, 12, 2);

		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Sending DB Table Logged Command to Postgres...\n");

		EXEC_TIME			exectime("DB Table Log Command");

		qbuf.appendconst("select public.gy_set_tbl_logged(ARRAY[");

		for (size_t i = 0; i < GY_ARRAY_SIZE(db_glob_partition_tbls_); ++i) {
			qbuf.appendfmt("\'%s\',", db_glob_partition_tbls_[i]);
		}	

		qbuf.set_last_char(' ');

		qbuf.appendconst("], \'^public$\');\n");

		qbuf.appendconst("select public.gy_set_tbl_logged(ARRAY[");

		for (size_t i = 0; i < GY_ARRAY_SIZE(db_partha_partition_tbls_); ++i) {
			qbuf.appendfmt("\'%s\',", db_partha_partition_tbls_[i]);
		}	

		qbuf.set_last_char(' ');

		qbuf.appendconst("], \'^sch[0-9a-f]{32}$\');\n");

		auto			cres = postconn.pqexec_blocking(qbuf.buffer());
		
		if (cres.is_error()) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to execute query to Postgres to set DB Partition Logged : Error is %s\n", cres.get_error_no_newline().get());
			return false;
		}	

		return true;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while updating Postgres DB for setting Tables Logged : %s\n", GY_GET_EXCEPT_STRING);
		return false;
	);
}

bool MCONN_HANDLER::db_del_entries(bool is_check) noexcept
{
	try {
		STRING_BUFFER<2048>		qbuf;
		bool				bret;

		auto				pconn = db_scheduler_pool_->get_conn(true /* wait_response_if_unavail */, 60'000 /* max_msec_wait */, false /* reset_on_timeout */);
		if (!pconn) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to schedule query to Postgres to %s old entries\n", is_check ? "check" : "delete");
			db_stats_.nconns_failed_.fetch_add_relaxed(1, mo_relaxed);
			return false;
		}	

		qbuf.appendfmt("select %s(ARRAY[\'listentbl\'], \'^sch[0-9a-f]{32}$\');", is_check ? "gy_del_if_many" : "gy_del_entries");

		bret = PQsendQueryOptim(pconn->get(), qbuf.buffer(), qbuf.size());
		
		if (bret == false) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to schedule query to Postgres to %s old entries : Error is %s\n", 
				is_check ? "check" : "delete", PQerrorMessage(pconn->get()));
			return false;
		}	

		pconn->set_resp_cb(
			[this, is_check](GyPGConn & conn, GyPGresult gyres, bool is_completed) -> bool
			{
				if (is_completed) {
					if (conn.is_within_tran()) {
						conn.pqexec_blocking("Rollback Work;");
					}						
					conn.make_available();
					return true;
				}	
				
				if (true == gyres.is_error()) {
					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to execute query to %s old entries : %s\n", 
						is_check ? "check" : "delete", gyres.get_error_msg());
					return false;
				}	

				return true;
			}
		);

		return true;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while sending query to Postgres DB to %s old entries : %s\n", is_check ? "check" : "delete", GY_GET_EXCEPT_STRING);
		return false;
	);
}	

bool MCONN_HANDLER::db_trunc_init_entries(const char * tblarrstr, const char *ns_regex) noexcept
{
	try {
		STRING_BUFFER<2048>		qbuf;
		bool				bret;

		auto				pconn = db_scheduler_pool_->get_conn(true /* wait_response_if_unavail */, 60'000 /* max_msec_wait */, false /* reset_on_timeout */);
		
		if (!pconn) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to schedule query to Postgres to init truncate old entries\n");
			db_stats_.nconns_failed_.fetch_add_relaxed(1, mo_relaxed);
			return false;
		}	

		qbuf.appendfmt("select gy_trunc_init_entries(%s, %s);", tblarrstr, ns_regex);

		bret = PQsendQueryOptim(pconn->get(), qbuf.buffer(), qbuf.size());
		
		if (bret == false) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to schedule query to Postgres to init truncate old entries : Error is %s\n", PQerrorMessage(pconn->get()));
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
					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to execute query to delete init old entries : %s\n", 
						gyres.get_error_msg());
					return false;
				}	

				return true;
			}
		);

		return true;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while sending query to Postgres DB for init truncate old entries : %s\n", GY_GET_EXCEPT_STRING);
		return false;
	);
}	

bool MCONN_HANDLER::set_db_disk_space_used() noexcept
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

void MCONN_HANDLER::set_max_partha_allowed() noexcept
{
	size_t 				maxcore		= gy_get_proc_cpus_allowed(getpid());
	size_t 				maxmem		= CPU_MEM_INFO::get_singleton()->get_total_memory();	// No need to check mems_allowed as this is advisory
	auto 				psettings 	= pmadhava_->psettings_;

	static_assert(comm::MAX_PARTHA_PER_MADHAVA > 1000);

	if (psettings->set_max_hosts > 5 && psettings->set_max_hosts <= comm::MAX_PARTHA_PER_MADHAVA) {
		if (psettings->set_max_hosts > 80 && (maxcore < 2 || maxmem <= GY_UP_GB(4 - 1))) {
			WARNPRINT_OFFLOAD("Maximum Partha Hosts Config option ignored due to low CPU count or Memory availability\n");
		}
		else {
			max_partha_allowed_ = psettings->set_max_hosts;

			INFOPRINT_OFFLOAD("Setting Maximum Partha Hosts Handled count to %u as per Config option\n", max_partha_allowed_);
			return;
		}
	}

	/*
	 * NOTE : We limit the max Partha Hosts Count to a low value as otherwise multi host querying will
	 * take more time. This does have a side-effect that we may miss some short lived TCP connection
	 * flow evaluations (> 15 sec and < 30 sec) durations...
	 */

	if (maxcore >= 16 && maxmem >= GY_UP_GB(32 - 1)) {
		max_partha_allowed_	= 400;
	}	
	else if (maxcore >= 8 && maxmem >= GY_UP_GB(16 - 1)) {
		max_partha_allowed_	= 200;
	}	
	else if (maxcore >= 4 && maxmem >= GY_UP_GB(16 - 1)) {
		max_partha_allowed_	= 150;
	}	
	else if (maxcore >= 4 && maxmem >= GY_UP_GB(8 - 1)) {
		max_partha_allowed_	= 100;
	}	
	else {
		WARNPRINT_OFFLOAD("Max Processor cores allowed (%lu) and Memory (%lu GB) is too low : Postgres/Madhava Response times may be affected...\n",
			maxcore, GY_DOWN_GB(maxmem));
		max_partha_allowed_	= 40;
	}	

	INFOPRINT_OFFLOAD("Setting Maximum Partha Hosts Handled count to %u\n", max_partha_allowed_);
}

void MCONN_HANDLER::spawn_init_threads()
{
	/*
	 * We first spawn the accept threads (REUSEPORTs)
	 */
	auto acclam = [](void *arg) -> void *
	{
		GY_THREAD	*pthr = (GY_THREAD *)arg;
		MCONN_HANDLER	*pthis = (MCONN_HANDLER *)pthr->get_opt_arg1();

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
		MCONN_HANDLER	*pthis = (MCONN_HANDLER *)pthr->get_opt_arg1();

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

		if (n < MAX_L1_CLI_THREADS) {	
			pretdata->thr_num_ 	= n;
			pretdata->thr_type_	= TTYPE_L1_CLI;
			parray			= pl1_cli_arr_ + pretdata->thr_num_;
		}
		else {
			pretdata->thr_num_ 	= n - MAX_L1_CLI_THREADS;
			pretdata->thr_type_	= TTYPE_L1_SHYAMA;
			parray			= pl1_shyama_ + pretdata->thr_num_;
		}	

		do {
			try {
				pthr = new GY_THREAD("Level 1 handler", l1lam, nullptr, this, psignal, true /* start_immed */, 1024 * 1024 /* 1 MB Stack size */);
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
		MCONN_HANDLER	*pthis = (MCONN_HANDLER *)pthr->get_opt_arg1();

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
		
		if (n < MAX_L2_DB_READERS) {
			pretdata->thr_num_ 	= n;
			pretdata->thr_type_ 	= TTYPE_L2_DB_RD;
			pretdata->pmpmc_	= ppmpmc_db_rd_arr_[pretdata->thr_num_ % MAX_L2_DB_RD_POOLS];

			parray			= pl2_db_rd_arr_ + pretdata->thr_num_;
		}
		else if (n < MAX_L2_DB_READERS + MAX_L2_MISC_THREADS) {
			pretdata->thr_num_ 	= n - MAX_L2_DB_READERS;
			pretdata->thr_type_ 	= TTYPE_L2_MISC;
			pretdata->pmpmc_	= ppmpmc_misc_arr_[pretdata->thr_num_ % MAX_L2_MISC_POOLS];

			parray			= pl2_misc_arr_ + pretdata->thr_num_;
		}
		else {
			pretdata->thr_num_ 	= n - MAX_L2_DB_READERS - MAX_L2_MISC_THREADS;
			pretdata->thr_type_ 	= TTYPE_L2_ALERT;
			pretdata->pmpmc_	= ppmpmc_alert_arr_[pretdata->thr_num_ % MAX_L2_ALERT_POOLS];

			parray			= pl2_alert_arr_ + pretdata->thr_num_;
		}	

		do {
			try {
				pthr = new GY_THREAD("Level 2 handler", l2lam, nullptr, this, psignal, true /* start_immed */, 2 * 1024 * 1024 /* 2 MB Stack size */);
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
			ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to spawn threads multiple times. Exiting...\n\n");
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

int MCONN_HANDLER::handle_accept(GY_THREAD *pthr)
{
	LISTEN_SOCK			**pplsock = nullptr;
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

		auto check_conn = [&, this](MCONNTRACK *pnewconn, const int cfd, decltype(mconntrack.find(0)) cit, const bool is_conn_closed) noexcept
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

				nb = sock_peek_recv_data(cfd, tbuf, sizeof(tbuf), true);
				if (nb > 0) {
					if (nb == sizeof(tbuf)) {
						COMM_HEADER		*phdr = reinterpret_cast<COMM_HEADER *>(tbuf);

						if (false == phdr->is_valid_register_req()) {
							statsmap["Dropping Connection for Proto Request"]++;
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

					pl1 = pl1_cli_arr_ + (nconns++ % MAX_L1_CLI_THREADS);

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
					MCONNTRACK		*pconn = nullptr;

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

						pconn = (MCONNTRACK *)pepdata;

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
									DEBUGEXECN(1, PERRORPRINTCOLOR(GY_COLOR_RED, "Accept failed"); );
									statsmap["Accept Failed"]++;
									continue;
								}	
								else if (errno == EMFILE) {
									PERRORPRINTCOLOR(GY_COLOR_RED, "Accept failed due to process open files"); 
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
										it->second = std::make_shared<MCONNTRACK>(&saddr, cfd, epollfd, nullptr, 
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

									MCONNTRACK	*pnewconn = it->second.get();

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
										PERRORPRINTCOLOR(GY_COLOR_RED, "Accept epoll add failed");
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


int MCONN_HANDLER::handle_l1(GY_THREAD *pthr)
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

		snprintf(psigdata->descbuf_, sizeof(psigdata->descbuf_), "Level 1 %s Thread %u TID %d", 
			psigdata->thr_type_ == TTYPE_L1_CLI ? "Client" : "Shyama", tl1_thr_num, tid);

		if (psigdata->thr_type_ == TTYPE_L1_CLI) {
			pglobparam = pl1_cli_arr_ + tl1_thr_num;
		}
		else {
			pglobparam = pl1_shyama_ + tl1_thr_num;
		}	

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
			
			if (psigdata->thr_type_ == TTYPE_L1_CLI) {
				pool_szarr[0] 	= 32767;
				pool_maxarr[0]	= 256;
				
				pool_szarr[1]	= 4096;
				pool_maxarr[1]	= 2048;

				pool_szarr[2] 	= 512;
				pool_maxarr[2]	= 128;

				npoolarr 	= 3;
			}
			else {
				pool_szarr[0]	= 4096;
				pool_maxarr[0]	= 256;

				pool_szarr[1] 	= 512;
				pool_maxarr[1]	= 512;

				npoolarr 	= 2;
			}	

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
		const bool			is_shyama_l1 = (param.thr_type_ == TTYPE_L1_SHYAMA);
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
		 * Currently max_syscall is ignored 
		 */
		auto handle_recv = [&, this](MCONNTRACK *pconn1, int sock, const bool is_conn_closed, const bool peer_rd_closed, int max_syscall = INT_MAX - 1) -> ssize_t
		{
			ssize_t				sret, max_bytes, totbytes = 0;
			ssize_t				max_buf_sz, data_sz;
			uint8_t				*prdbuf;
			int				nsyscall = 0, ret;
			auto				&rdstat_ = pconn1->rdstat_;
			COMM_HEADER			hdr(COMM_MIN_TYPE, 0, COMM_HEADER::INV_HDR_MAGIC);
			bool				is_again = false, bret, bsent, is_pendrecv = (rdstat_.pending_sz_ > 0);

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

				// For TTYPE_L2_DB_RD have a diff thread handle each req
				if (dest_thr_type != dbarr.dest_thr_type_ || dest_thr_type == TTYPE_L2_DB_RD) {
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
					GY_THROW_EXCEPTION("Internal Error : max_bytes <= 0 #%u", __LINE__);
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
						if (dbarr.ndbs_ > 0 && dbarr.dest_thr_type_ != TTYPE_L2_DB_RD) {
							send_db_array(std::move(dbarr), l1_thr_num, statsmap);
						}

						return -1;
					}
				}
				else if (sret == 0) {
					if (dbarr.ndbs_ > 0 && dbarr.dest_thr_type_ != TTYPE_L2_DB_RD) {
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
							
							case NOTIFY_TCP_CONN :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_PARTHA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									TCP_CONN_NOTIFY	 	*ptcp = (TCP_CONN_NOTIFY *)(pevtnot + 1);

									bret = ptcp->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;

							case NOTIFY_LISTENER_STATE :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_PARTHA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									LISTENER_STATE_NOTIFY	 *plist = (LISTENER_STATE_NOTIFY *)(pevtnot + 1);

									bret = plist->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;


							case NOTIFY_AGGR_TASK_STATE :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_PARTHA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									AGGR_TASK_STATE_NOTIFY	 *ptask = (AGGR_TASK_STATE_NOTIFY *)(pevtnot + 1);

									bret = ptask->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;

							case NOTIFY_ACTIVE_CONN_STATS :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_PARTHA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									auto		 *pconn = (ACTIVE_CONN_STATS *)(pevtnot + 1);

									bret = pconn->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}
								break;

							case NOTIFY_MM_ACTIVE_CONN_STATS :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_MADHAVA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									auto		 *pconn = (ACTIVE_CONN_STATS *)(pevtnot + 1);

									bret = pconn->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}
								break;


							case NOTIFY_LISTEN_TASKMAP_EVENT :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_PARTHA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									auto		 *plist = (LISTEN_TASKMAP_NOTIFY *)(pevtnot + 1);

									bret = plist->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}
								break;


							case NOTIFY_TASK_MINI_ADD :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_PARTHA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									bret = TASK_MINI_ADD::validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}
								break;

							case NOTIFY_TASK_FULL_ADD :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_PARTHA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									bret = TASK_FULL_ADD::validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;

							case NOTIFY_TASK_TOP_PROCS :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_PARTHA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									TASK_TOP_PROCS	 	*ptask = (TASK_TOP_PROCS *)(pevtnot + 1);

									bret = ptask->validate(&hdr);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;

							case NOTIFY_TASK_HISTOGRAM :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_PARTHA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									TASK_HISTOGRAM	 	*ptask = (TASK_HISTOGRAM *)(pevtnot + 1);

									bret = ptask->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;

							case NOTIFY_NEW_LISTENER :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_PARTHA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									NEW_LISTENER	 	*plist = (NEW_LISTENER *)(pevtnot + 1);

									bret = plist->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;

							case NOTIFY_LISTENER_DEPENDENCY :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_PARTHA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									auto		 *plist = (LISTENER_DEPENDENCY_NOTIFY *)(pevtnot + 1);

									bret = plist->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;


							case NOTIFY_LISTENER_NAT_IP_EVENT :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_PARTHA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									auto	 		*pnat = (LISTENER_NAT_IP_EVENT *)(pevtnot + 1);

									bret = pnat->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;

							case NOTIFY_LISTENER_DOMAIN_EVENT :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_PARTHA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									auto	 		*pnot = (LISTENER_DOMAIN_NOTIFY *)(pevtnot + 1);

									bret = pnot->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;


							case NOTIFY_LISTEN_CLUSTER_INFO :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_PARTHA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									auto	 		*pnot = (LISTENER_CLUSTER_NOTIFY *)(pevtnot + 1);

									bret = pnot->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;


							case NOTIFY_SM_ALERT_ADEF_NEW :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_SHYAMA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									auto	 		*pnot = (SM_ALERT_ADEF_NEW *)(pevtnot + 1);

									bret = pnot->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_ALERT);
								}

								break;

							case NOTIFY_SM_ALERT_ADEF_UPD :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_SHYAMA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									auto	 		*pnot = (SM_ALERT_ADEF_UPD *)(pevtnot + 1);

									bret = pnot->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_ALERT);
								}

								break;


							case NOTIFY_SM_ALERT_STAT_DISABLE :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_SHYAMA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									auto	 		*pnot = (SM_ALERT_STAT_DISABLE *)(pevtnot + 1);

									bret = pnot->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_ALERT);
								}

								break;


							case NOTIFY_LISTENER_DAY_STATS :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_PARTHA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									auto	 		*pnot = (LISTENER_DAY_STATS *)(pevtnot + 1);

									bret = pnot->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;


							case NOTIFY_NAT_TCP :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_PARTHA)) {
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

							case NOTIFY_SHYAMA_CLI_TCP_INFO :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_SHYAMA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									SHYAMA_CLI_TCP_INFO	 	*ptcp = (SHYAMA_CLI_TCP_INFO *)(pevtnot + 1);

									bret = ptcp->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;


							case NOTIFY_SHYAMA_SER_TCP_INFO :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_SHYAMA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									SHYAMA_SER_TCP_INFO	 	*ptcp = (SHYAMA_SER_TCP_INFO *)(pevtnot + 1);

									bret = ptcp->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;


							case NOTIFY_SM_SVC_CLUSTER_MESH :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_SHYAMA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									auto		 	*psvc = (SM_SVC_CLUSTER_MESH *)(pevtnot + 1);

									bret = psvc->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;

							case NOTIFY_SM_SVC_NAT_IP_CLUSTER :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_SHYAMA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									auto		 	*psvc = (SM_SVC_NAT_IP_CLUSTER *)(pevtnot + 1);

									bret = psvc->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;


							case NOTIFY_MM_LISTENER_ISSUE_RESOL :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_MADHAVA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									MM_LISTENER_ISSUE_RESOL	 *plist = (MM_LISTENER_ISSUE_RESOL *)(pevtnot + 1);

									bret = plist->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;


							case NOTIFY_MM_LISTENER_DEPENDS :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_MADHAVA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									MM_LISTENER_DEPENDS	 *plist = (MM_LISTENER_DEPENDS *)(pevtnot + 1);

									bret = plist->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;

							case NOTIFY_MM_LISTENER_PING :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_MADHAVA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									MM_LISTENER_PING	 *plist = (MM_LISTENER_PING *)(pevtnot + 1);

									bret = plist->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;


							case NOTIFY_MM_LISTENER_DELETE :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_MADHAVA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									MM_LISTENER_DELETE	 *plist = (MM_LISTENER_DELETE *)(pevtnot + 1);

									bret = plist->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;


							case NOTIFY_TASK_AGGR :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_PARTHA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									TASK_AGGR_NOTIFY	 	*ptask = (TASK_AGGR_NOTIFY *)(pevtnot + 1);

									bret = ptask->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;
							

							case NOTIFY_AGGR_TASK_HIST_STATS :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_PARTHA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									auto	 	*ptask = (const AGGR_TASK_HIST_STATS *)(pevtnot + 1);

									bret = ptask->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;


							case NOTIFY_PING_TASK_AGGR :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_PARTHA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									PING_TASK_AGGR	 	*ptask = (PING_TASK_AGGR *)(pevtnot + 1);

									bret = ptask->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;

							case NOTIFY_MM_TASK_AGGR_PING :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_MADHAVA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									MM_TASK_AGGR_PING	 	*ptask = (MM_TASK_AGGR_PING *)(pevtnot + 1);

									bret = ptask->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;

							case NOTIFY_MM_TASK_AGGR_DEL :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_MADHAVA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									MM_TASK_AGGR_DEL	 	*ptask = (MM_TASK_AGGR_DEL *)(pevtnot + 1);

									bret = ptask->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;

							case NOTIFY_MM_AGGR_TASK_STATE :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_MADHAVA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									AGGR_TASK_STATE_NOTIFY	 *ptask = (AGGR_TASK_STATE_NOTIFY *)(pevtnot + 1);

									bret = ptask->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;


							case NOTIFY_CPU_MEM_STATE :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_PARTHA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									CPU_MEM_STATE_NOTIFY	 	*pcpumem = (CPU_MEM_STATE_NOTIFY *)(pevtnot + 1);

									bret = pcpumem->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;
														
							case NOTIFY_HOST_STATE :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_PARTHA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									auto	 	*phost = (HOST_STATE_NOTIFY *)(pevtnot + 1);

									bret = phost->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;

							// Older Partha
							case NOTIFY_HOST_STATE__V000100 :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_PARTHA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									auto	 	*phost = (HOST_STATE_NOTIFY__V000100 *)(pevtnot + 1);

									bret = phost->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;

							case NOTIFY_HOST_INFO :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_PARTHA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									auto	 	*phost = (HOST_INFO_NOTIFY *)(pevtnot + 1);

									bret = phost->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;

							case NOTIFY_HOST_CPU_MEM_CHANGE :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_PARTHA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									auto	 	*phost = (HOST_CPU_MEM_CHANGE *)(pevtnot + 1);

									bret = phost->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;


							case NOTIFY_NOTIFICATION_MSG :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_PARTHA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									auto	 	*pmsg = (NOTIFICATION_MSG *)(pevtnot + 1);

									bret = pmsg->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;


							case NOTIFY_MADHAVA_LIST :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_SHYAMA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									MADHAVA_LIST	 	*pnew = (MADHAVA_LIST *)(pevtnot + 1);

									bret = pnew->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
								}

								break;


							case NOTIFY_SM_PARTHA_IDENT :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_SHYAMA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									SM_PARTHA_IDENT_NOTIFY 	*preq = (SM_PARTHA_IDENT_NOTIFY *)(pevtnot + 1);
									int			nevents = pevtnot->nevents_;

									statsmap["Shyama Partha Ident Notify"] += nevents;

									comm::COMM_HEADER	thdr = hdr;

									bret = preq->validate(&thdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									while (nevents-- > 0) {
										set_partha_ident(pconn1, preq++, statsmap);
									}
								}

								break;
							
							case NOTIFY_SHYAMA_MADHAVA_STATUS :
								// nevents_ is always 1 here

								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_SHYAMA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									statsmap["Shyama Status"]++;

									SHYAMA_MADHAVA_STATUS 	*preq = (SHYAMA_MADHAVA_STATUS *)(pevtnot + 1);

									bret = preq->validate(&hdr);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									gshyama_.last_status_ = *preq;

									// No response needs to be sent
								}

								break;


							case NOTIFY_PARTHA_STATUS :

								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_PARTHA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									PARTHA_STATUS 	*preq = (PARTHA_STATUS *)(pevtnot + 1);

									bret = preq->validate(&hdr);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									// No response needs to be sent
								}

								break;

							case NOTIFY_MADHAVA_MADHAVA_STATUS :

								if (!pconn1->is_registered()) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									MADHAVA_MADHAVA_STATUS 	*preq = (MADHAVA_MADHAVA_STATUS *)(pevtnot + 1);

									bret = preq->validate(&hdr);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
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

						if (false == peer_rd_closed && pconn1->cli_type_ != comm::CLI_TYPE_REQ_ONLY) {
							QUERY_CMD		*pquery = (QUERY_CMD *)(prdbuf + sizeof(COMM_HEADER));

							switch (pquery->subtype_) {
							
							case QUERY_LISTENER_INFO_STATS :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_PARTHA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									LISTENER_INFO_REQ	 	*plist = (LISTENER_INFO_REQ *)(pquery + 1);

									bret = plist->validate(&hdr);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_DB_RD);
								}			
								break;

							case QUERY_WEB_JSON :
							case CRUD_GENERIC_JSON :
							case CRUD_ALERT_JSON :

								if (!pconn1->is_registered()) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_DB_RD, true /* is_json_resp */);
								}			
								break;


							default :
								break;
							}
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

							case RESP_WEB_JSON :
								if ((presp->respformat_ != RESP_BINARY) && (presp->seqid_ > 0)) {
									statsmap["Web JSON Resp"]++;

									if (presp->is_completed()) {
										auto cb = pconn1->extract_recv_cb(presp->seqid_);
										if (cb.has_value()) {
											cb->fcb_(pconn1, (uint8_t *)(presp + 1), presp->resp_len_, (uint8_t *)prdbuf, false /* is_expiry */, 
													false /* is_error */);
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


					case MS_REGISTER_RESP :
						if (true) {
							statsmap["Shyama Register Response"]++;

							if ((pconn1->is_registered()) || (pconn1->host_type_ != HOST_SHYAMA)) {
								statsmap["Invalid Message Error"]++; 
								GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
							}	

							MS_REGISTER_RESP_S 		*preg = (MS_REGISTER_RESP_S *)(prdbuf + sizeof(COMM_HEADER));

							bret = preg->validate(&hdr); 
							if (bret == false) {
								statsmap["Invalid Message Error"]++; 
								return -1;
							}
							
							bret = handle_shyama_reg_resp(pconn1, preg, statsmap);
							if (bret == false) {
								return -1;
							}	
						}
						break;

					case MM_CONNECT_CMD :
						if (true) {
							statsmap["Remote Madhava Register Req"]++;

							if (pconn1->is_registered()) {
								statsmap["Invalid Message Error"]++; 
								GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
							}	

							MM_CONNECT_CMD_S 		*preg = (MM_CONNECT_CMD_S *)(prdbuf + sizeof(COMM_HEADER));
							char				ebuf[COMM_MAX_ERROR_LEN];
							ERR_CODES_E			errcode;

							bret = preg->validate(&hdr);
							if (bret == false) {
								statsmap["Invalid Message Error"]++; 
								return -1;
							}

							bret = preg->validate_fields(gmadhava_id_, gversion_num, gversion_num, ebuf, errcode);
							if (bret == false) {
								statsmap["Remote Madhava Registration Fail"]++;
								send_register_connect_error<MM_CONNECT_RESP_S, MM_CONNECT_RESP>(pconn1, errcode, ebuf, &poolarr);

								ERRORPRINT_OFFLOAD("Remote Madhava Registration from Madhava ID %016lx %s Host %s Port %hu Failed due to %s\n", 
									preg->local_madhava_id_, 
									pconn1->print_peer(STRING_BUFFER<128>().get_str_buf()), preg->madhava_hostname_, 
									preg->madhava_port_, ebuf);
								return -1;
							}	

							schedule_db_array(prdbuf, hdr.total_sz_, hdr.data_type_, TTYPE_L2_MISC);
							
							bret = send_db_array(std::move(dbarr), l1_thr_num, statsmap);
							rdstat_.reset_buf(false);

							if (bret == false) {
								statsmap["Remote Madhava Register Blocking Fail"]++;

								send_register_connect_error<MM_CONNECT_RESP_S, MM_CONNECT_RESP>(pconn1, ERR_BLOCKING_ERROR, 
										"Failed to process Registration due to too many requests", &poolarr);

								ERRORPRINT_OFFLOAD("Remote Madhava Registration from Madhava ID %016lx %s Host %s Port %hu Failed "
									"due to failure to forward registration to handler as too many requests pending\n", 
										preg->local_madhava_id_, 
										pconn1->print_peer(STRING_BUFFER<128>().get_str_buf()), preg->madhava_hostname_, 
										preg->madhava_port_);

								return -1;
							}
						}
						break;


					case MM_CONNECT_RESP :
						if (true) {
							statsmap["Madhava Register Response"]++;

							if ((pconn1->is_registered()) || (pconn1->host_type_ != HOST_MADHAVA)) {
								statsmap["Invalid Message Error"]++; 
								GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
							}	

							MM_CONNECT_RESP_S 		*preg = (MM_CONNECT_RESP_S *)(prdbuf + sizeof(COMM_HEADER));

							bret = preg->validate(&hdr); 
							if (bret == false) {
								statsmap["Invalid Message Error"]++; 
								return -1;
							}
							
							bret = handle_madhava_reg_resp(pconn1, preg, statsmap);
							if (bret == false) {
								return -1;
							}	
						}
						break;

					case PM_CONNECT_CMD :
						if (true) {
							statsmap["Partha Register Req"]++;

							if (pconn1->is_registered()) {
								statsmap["Invalid Message Error"]++; 
								GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
							}	

							PM_CONNECT_CMD_S 		*preg = (PM_CONNECT_CMD_S *)(prdbuf + sizeof(COMM_HEADER));
							char				ebuf[COMM_MAX_ERROR_LEN];
							ERR_CODES_E			errcode;

							bret = preg->validate(&hdr);
							if (bret == false) {
								statsmap["Invalid Message Error"]++; 
								return -1;
							}

							bret = preg->validate_fields(gmadhava_id_, gmin_partha_version, gversion_num, ebuf, errcode);
							if (bret == false) {
								statsmap["Partha Registration Fail"]++;
								send_register_connect_error<PM_CONNECT_RESP_S, PM_CONNECT_RESP>(pconn1, errcode, ebuf, &poolarr);

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

							send_register_connect_error<PM_CONNECT_RESP_S, PM_CONNECT_RESP>(pconn1, ERR_BLOCKING_ERROR, 
									"Failed to process Registration due to too many requests", &poolarr);

							ERRORPRINT_OFFLOAD("Partha Registration for Machine ID %016lx%016lx from %s Failed "
								"due to failure to forward registration to handler as too many requests pending\n", 
								preg->machine_id_hi_, preg->machine_id_lo_, pconn1->print_peer(STRING_BUFFER<128>().get_str_buf()));

							return -1;
						}
						break;

					case NM_CONNECT_CMD :
						if (true) {
							statsmap["Node Web Register Req"]++;

							if (pconn1->is_registered()) {
								statsmap["Invalid Message Error"]++; 
								GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
							}	

							NM_CONNECT_CMD_S 		*preg = (NM_CONNECT_CMD_S *)(prdbuf + sizeof(COMM_HEADER));
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
								send_register_connect_error<NM_CONNECT_RESP_S, NM_CONNECT_RESP>(pconn1, errcode, ebuf, &poolarr);

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

							send_register_connect_error<NM_CONNECT_RESP_S, NM_CONNECT_RESP>(pconn1, ERR_BLOCKING_ERROR, 
									"Failed to process Registration due to too many requests", &poolarr);
						
							ERRORPRINT_OFFLOAD("Node Registration for %s port %hu from %s Failed "
								"due to failure to forward registration to handler as too many requests pending\n", 
								preg->node_hostname_, preg->node_port_, pconn1->print_peer(STRING_BUFFER<128>().get_str_buf()));
							return -1;
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
						GY_THROW_EXCEPTION("Internal Error : L1 recv stats invalid #%u", __LINE__);
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

					case L1_MISC_SHYAMA_RECONNECT :	
						
						return !connect_shyama_blocking(lm.cli_type_, mconntrack, epollfd, pglobparam, statsmap, &poolarr);
					
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
							MCONNTRACK		*pnewconn = it->second.get();

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
										pconn->signal_conn_close();
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
			
			case NOTIFY_CONNECT :
				if (evn.data_.conn_.sockfd_.get() > 0) {
					CONN_NOTIFY_ONE		& conn = evn.data_.conn_;

					statsmap["Connect Conn Notify"]++;

					try {
						int			sockfd = conn.sockfd_.get();

						auto 			[it, success] = mconntrack.try_emplace(sockfd, nullptr);
						struct epoll_event	ev;

						if (success == true) {
							try {
								it->second = std::make_shared<MCONNTRACK>(conn.pconnect_sockaddr_.get(), sockfd, epollfd, nullptr, 
									0, 0, true /* use_pipeline */, MAX_CONN_DATA_TIMEOUT_USEC, MAX_CONN_DATA_TIMEOUT_USEC, 
									false /* close_conn_on_wr_complete */, true /* is_outgoing */);

								conn.sockfd_.reset();

								MCONNTRACK	*pnewconn = it->second.get();

								pnewconn->set_epoll_data(pnewconn);

								pnewconn->set_comm_magic(conn.comm_magic_);

								pnewconn->pl1_ 		= pglobparam;
								pnewconn->host_type_ 	= conn.host_type_;
								pnewconn->cli_type_ 	= conn.cli_type_;

								ev.data.ptr		= pnewconn;
								ev.events 		= EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLET;

								ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, sockfd, &ev);
								if (ret != 0) {
									PERRORPRINTCOLOR(GY_COLOR_RED, "Connect Conn epoll add failed");
									mconntrack.erase(it);

									return false;
								}	

								// We need to add the async callbacks for registration once the connect completes
								if (conn.cb_success_.is_valid()) {
									statsmap["Add Async Connect Callback"]++;

									pnewconn->add_connect_cb(std::move(conn.cb_success_));
								}
							}
							GY_CATCH_EXCEPTION(
								ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while initializing new %s connection %s\n", 
									comm::host_type_string(conn.host_type_), GY_GET_EXCEPT_STRING);

								mconntrack.erase(it);
								statsmap["Exception Occurred"]++;
								return false;
							);
						}	
					}
					GY_CATCH_EXCEPTION(
						statsmap["Connect Conn Notify Exception"]++;
						ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while adding connect connection to Level 1 map : %s\n", GY_GET_EXCEPT_STRING);
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

		if (is_shyama_l1) {
			/*
			 * Now connect to shyama. We do not start conns earlier so as to allow Shyama to be started later than Madhava
			 */
			SHYAMA_INFO::start_connect_scheduler(&param, CLI_TYPE_REQ_RESP);
			SHYAMA_INFO::start_connect_scheduler(&param, CLI_TYPE_RESP_REQ);
		}	

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
				 *    before the async callback could be added to the MCONNTRACK cb_tbl_ map.
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

						auto pconn = (MCONNTRACK *)pepdata;
						
						const int cfd = pconn->get_sockfd();

						try {
							const bool		conn_closed = (cevents & (EPOLLERR | EPOLLHUP));
							const bool		peer_rd_closed = (conn_closed || (cevents & EPOLLRDHUP));
							ssize_t			sret = 0;

							if (cevents & EPOLLIN) {
								sret = handle_recv(pconn, cfd, conn_closed, peer_rd_closed);
							}	
							
							if ((sret >= 0) && (cevents & EPOLLOUT) && (false == peer_rd_closed)) {
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
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught in %s : %s\n", param.descbuf_, GY_GET_EXCEPT_STRING);
			);
				
		} while (true);	
	
		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught in %s : %s\n\n", param.descbuf_, GY_GET_EXCEPT_STRING);
		return -1;
	);
}


int MCONN_HANDLER::handle_l2(GY_THREAD *pthr)
{
	uint32_t			l2_thr_num = 0;
	L2_PARAMS			param;
	POOL_ALLOC_ARRAY		*pthrpoolarr = nullptr;
	const pid_t			tid = gy_gettid();
	auto 				psettings = pmadhava_->psettings_;
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

		case TTYPE_L2_DB_RD 	:	ptype = "DB Reader"; break;
		case TTYPE_L2_MISC 	:	ptype = "Misc Thread"; break;
		case TTYPE_L2_ALERT 	:	ptype = "Alert Handler"; break;

		default 		:
			ERRORPRINTCOLOR(GY_COLOR_RED, "Invalid L2 Thread Type specified : %u : Exiting...\n", psigdata->thr_type_);
			exit(EXIT_FAILURE);
		}

		snprintf(psigdata->descbuf_, sizeof(psigdata->descbuf_), "Level 2 %s Thread %u TID %d", ptype, l2_thr_num, tid);
		
		try {
			if (psigdata->thr_type_ == TTYPE_L2_DB_RD) {
				size_t		pool_szarr[2], pool_maxarr[2];
			
				pool_szarr[0] 	= 512;
				pool_maxarr[0]	= 2048;

				pool_szarr[1] 	= 4096;
				pool_maxarr[1]	= 1024;

				pthrpoolarr = new POOL_ALLOC_ARRAY(pool_szarr, pool_maxarr, GY_ARRAY_SIZE(pool_szarr), true);

				INFOPRINT("L2 DB Reader Thread %u initiating Postgres Connection...\n", l2_thr_num);

				dbpool.emplace(gy_to_charbuf<128>("DB Reader Pool %u", l2_thr_num).get(), RD_DB_POOL_CONNS,
							psettings->postgres_hostname, psettings->postgres_port, psettings->postgres_user, psettings->postgres_password,
							get_dbname().get(), gy_to_charbuf<64>("madhava_rd%u", l2_thr_num).get(), 
							get_db_init_commands().get(), true /* auto_reconnect */, 12, 10, 10);

			}	
			else if (psigdata->thr_type_ == TTYPE_L2_MISC) {
				size_t		pool_szarr[5], pool_maxarr[5];
			
				pool_szarr[0] 	= std::max(sizeof(MTCP_CONN), sizeof(MAGGR_TASK)) + 16;
				pool_maxarr[0]	= 20 * 1024;

				pool_szarr[1] 	= 4096;
				pool_maxarr[1]	= 1024;

				pool_szarr[2]	= 256;
				pool_maxarr[2]	= 2048;

				pool_szarr[3]	= std::max(sizeof(MAGGR_TASK_ELEM_TYPE), sizeof(MAGGR_TASK_WEAK)) + 16; 
				pool_maxarr[3]	= 20 * 1024;

				pool_szarr[4]	= 750;
				pool_maxarr[4]	= 1024;

				pthrpoolarr = new POOL_ALLOC_ARRAY(pool_szarr, pool_maxarr, GY_ARRAY_SIZE(pool_szarr), true);
				
				INFOPRINT("L2 Misc Thread %u initiating Postgres Connection Pool...\n", l2_thr_num);

				dbpool.emplace(gy_to_charbuf<128>("DB Misc Pool %u", l2_thr_num).get(), MISC_DB_POOL_CONNS,
							psettings->postgres_hostname, psettings->postgres_port, psettings->postgres_user, psettings->postgres_password,
							get_dbname().get(), gy_to_charbuf<64>("madhava_misc%u", l2_thr_num).get(), 
							get_db_init_commands().get(), true /* auto_reconnect */, 12, 10, 10);
			}	
			else if (psigdata->thr_type_ == TTYPE_L2_ALERT) {

				static_assert(MAX_L2_ALERT_THREADS == 1, "Require Only 1 Alert Handler thread");

				// We use placement new as palerthdlr_ is internally referenced by the MALERT_HDLR constructor...
				palerthdlr_ = (decltype(palerthdlr_))aligned_alloc_or_throw(alignof(decltype(*palerthdlr_)), sizeof(*palerthdlr_));

				new (palerthdlr_) MALERT_HDLR(this);
			}
		}
		GY_CATCH_EXCEPTION(
			ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to create Level 2 Pool objects for %s : %s\n", psigdata->descbuf_, GY_GET_EXCEPT_STRING);
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
	
	case TTYPE_L2_DB_RD 	:	do { handle_l2_db(param, pthrpoolarr, *dbpool); } while (true);

	case TTYPE_L2_MISC 	:	do { handle_l2_misc(param, pthrpoolarr, *dbpool); } while (true);

	case TTYPE_L2_ALERT 	:	do { handle_alert_mgr(param); } while (true);

	default 		: 	break;
	}

	return -1;
}

int MCONN_HANDLER::handle_l2_db(L2_PARAMS & param, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	try {
		MPMCQ_COMM			* const pl2pool = param.pmpmc_;
		const uint32_t			l2_thr_num = param.thr_num_;
		const pid_t			tid = gy_gettid();
		uint64_t			curr_usec_clock = get_usec_clock() + ((tid * 10) & 0xFFFF), last_usec_clock = curr_usec_clock, last_dbreset_cusec = curr_usec_clock;
		int				tpoolcnt = 0;
		STATS_STR_MAP			statsmap;
		bool				bret;

		statsmap.reserve(128);

		statsmap["Exception Occurred"] = 0;
		statsmap["Idle Timeout"] = 0;

		do {
			gy_thread_rcu().gy_rcu_thread_offline();

			EV_NOTIFY_ONE		ev;

			bret = pl2pool->tryReadUntil(std::chrono::steady_clock::now() + std::chrono::microseconds(MAX_CONN_DATA_TIMEOUT_USEC + ((tid * 100) & 0x7FFFF)), ev);

			try {
				if (bret && NOTIFY_DB_WRITE_ARR != ev.get_type()) {
					statsmap["Invalid DB Notify"]++;

					DEBUGEXECN(11, WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Invalid DB Notify seen for %s\n", param.descbuf_););
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
						auto & dbone 		= dbarr.dbonearr_[i];

						uint8_t			*prdbuf 	= dbone.pwrbuf_;
						COMM_HEADER		*phdr 		= (COMM_HEADER *)prdbuf;
						uint8_t			*pendptr	= prdbuf + phdr->get_act_len();	
						const bool		is_last_elem	= (i + 1 == dbarr.ndbs_);
						QUERY_CMD		*pquery;

						switch (phdr->data_type_) {
					
						case COMM_QUERY_CMD :

							pquery = (QUERY_CMD *)(prdbuf + sizeof(COMM_HEADER));

							switch (pquery->subtype_) {
								
							case QUERY_LISTENER_INFO_STATS :

								if (true) {
									LISTENER_INFO_REQ 	*plist = (LISTENER_INFO_REQ *)(pquery + 1);

									statsmap["Partha Listener Info Req"]++;
									handle_listener_req(dbarr.shrconn_, dbarr.shrconn_->get_partha_shared(), pquery, plist, prdbuf + phdr->get_act_len(), 
												pthrpoolarr, statsmap, dbpool);
								}	
								break;

							case QUERY_WEB_JSON :
							case CRUD_GENERIC_JSON :
							case CRUD_ALERT_JSON :

								do {
									char 			*pjson = (char *)(pquery + 1);

									statsmap["Node Query"]++;
									handle_node_query(dbarr.shrconn_, pquery, pjson, (char *)pendptr, pthrpoolarr, statsmap, dbpool);

								} while (false);

								break;

							default :
								statsmap["Invalid DB Query Type"]++;
								break;
							
							}

							break;

						default :
							statsmap["Invalid DB Cmd Type"]++;
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
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught in %s while handling message : %s\n\n", param.descbuf_, GY_GET_EXCEPT_STRING);
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

int MCONN_HANDLER::handle_l2_misc(L2_PARAMS & param, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	try {
		MPMCQ_COMM			* const pl2pool = param.pmpmc_;
		const uint32_t			l2_thr_num = param.thr_num_;
		const pid_t			tid = gy_gettid();
		uint64_t			curr_usec_clock = get_usec_clock() + ((tid * 10) & 0xFFFF), last_usec_clock = curr_usec_clock, last_dbreset_cusec = curr_usec_clock;
		int				tpoolcnt = 0;
		STATS_STR_MAP			statsmap;
		bool				bret;

		statsmap.reserve(32);

		statsmap["Exception Occurred"] = 0;
		statsmap["Total Misc Notify"] = 0;
		statsmap["Idle Timeout"] = 0;

		do {
			gy_thread_rcu().gy_rcu_thread_offline();

			EV_NOTIFY_ONE		ev;

			bret = pl2pool->tryReadUntil(std::chrono::steady_clock::now() + 
					std::chrono::seconds(MAX_CONN_DATA_TIMEOUT_USEC/GY_USEC_PER_SEC) + std::chrono::microseconds((tid * 100) & 0x7FFFF), ev);

			try {
				if (bret && NOTIFY_DB_WRITE_ARR != ev.get_type())  {
					statsmap["Invalid Misc Notify"]++;
					DEBUGEXECN(11, WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Invalid Misc Notify seen for %s\n", param.descbuf_););
					bret = false;
				}

				if (bret == true) {
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
						auto & dbone 		= dbarr.dbonearr_[i];

						uint8_t			*prdbuf 	= dbone.pwrbuf_;
						COMM_HEADER		*phdr 		= (COMM_HEADER *)prdbuf;
						uint8_t			*pendptr	= prdbuf + phdr->get_act_len();	
						const bool		is_last_elem	= (i + 1 == dbarr.ndbs_);
						EVENT_NOTIFY		*pevtnot;

						switch (phdr->data_type_) {

						case COMM_EVENT_NOTIFY :
					
							pevtnot = (EVENT_NOTIFY *)(phdr + 1);

							switch (pevtnot->subtype_) {

							case NOTIFY_TCP_CONN :
								try {
									TCP_CONN_NOTIFY	 	*ptcp = (TCP_CONN_NOTIFY *)(pevtnot + 1);
									int			nevents = pevtnot->nevents_;

									statsmap["Partha TCP Conn Notify"]++;

									partha_tcp_conn_info(dbarr.shrconn_->get_partha_shared(), ptcp, nevents, pendptr, pthrpoolarr);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Partha TCP Conn Notify : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;
												
							case NOTIFY_LISTENER_STATE :
								try {
									LISTENER_STATE_NOTIFY	*plist = (LISTENER_STATE_NOTIFY *)(pevtnot + 1);
									int			nevents = pevtnot->nevents_;

									statsmap["Partha Listener State"]++;

									partha_listener_state(dbarr.shrconn_->get_partha_shared(), plist, nevents, pendptr, pthrpoolarr, dbpool);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Partha Listener State Notify : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;
												

							case NOTIFY_AGGR_TASK_STATE :
								try {
									AGGR_TASK_STATE_NOTIFY 	*ptask = (AGGR_TASK_STATE_NOTIFY *)(pevtnot + 1);
									int			nevents = pevtnot->nevents_;

									statsmap["Partha Aggr Task State"]++;

									partha_aggr_task_state(dbarr.shrconn_->get_partha_shared(), ptask, nevents, pendptr, pthrpoolarr, dbpool);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Partha Aggr Task State Notify : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;

							case NOTIFY_TASK_AGGR :
								try {
									statsmap["Add Aggr Task"]++;

									TASK_AGGR_NOTIFY	*ptask = (TASK_AGGR_NOTIFY *)(pevtnot + 1);

									handle_add_aggr_task(dbarr.shrconn_, ptask, pevtnot->nevents_, pendptr, statsmap, pthrpoolarr, dbpool);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Partha Add Aggr Task : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;		

							case NOTIFY_LISTENER_NAT_IP_EVENT :
								try {
									statsmap["Listener NAT IP Notify"]++;

									auto	 		*pnat = (LISTENER_NAT_IP_EVENT *)(pevtnot + 1);
									int			nevents = pevtnot->nevents_;

									handle_listener_natip_notify(dbarr.shrconn_->get_partha_shared(), pnat, nevents, pthrpoolarr);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Partha Listener NAT IP Notify : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;

							case NOTIFY_LISTENER_DOMAIN_EVENT :
								try {
									statsmap["Listener Domain Notify"]++;

									auto	 		*pnot = (LISTENER_DOMAIN_NOTIFY *)(pevtnot + 1);
									int			nevents = pevtnot->nevents_;

									handle_listener_domain_notify(dbarr.shrconn_->get_partha_shared(), pnot, nevents);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Partha Listener Domain Notify : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;

							case NOTIFY_LISTEN_CLUSTER_INFO :
								try {
									statsmap["Clustered Listener Notify"]++;

									auto	 		*pnot = (LISTENER_CLUSTER_NOTIFY *)(pevtnot + 1);
									int			nevents = pevtnot->nevents_;

									handle_listener_cluster_info(dbarr.shrconn_->get_partha_shared(), pnot, nevents, pendptr, pthrpoolarr);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Partha Listener Cluster Notify : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;

							case NOTIFY_LISTENER_DAY_STATS :
								try {
									statsmap["Listener Day Stats Notify"]++;

									auto	 		*pnot = (LISTENER_DAY_STATS *)(pevtnot + 1);
									int			nevents = pevtnot->nevents_;

									handle_listener_day_stats(dbarr.shrconn_->get_partha_shared(), pnot, nevents);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Partha Listener Day Stats Notify : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;


							case NOTIFY_NAT_TCP :
								try {
									statsmap["NAT TCP Notify"]++;

									NAT_TCP_NOTIFY	 	*pnat = (NAT_TCP_NOTIFY *)(pevtnot + 1);
									int			nevents = pevtnot->nevents_;

									handle_partha_nat_notify(pnat, nevents, pendptr, pthrpoolarr, is_last_elem, std::move(dbarr));
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Partha NAT TCP Notify : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;


							case NOTIFY_SHYAMA_CLI_TCP_INFO :
								try {
									statsmap["Shyama TCP Client Notify"]++;

									SHYAMA_CLI_TCP_INFO	*ptcp = (SHYAMA_CLI_TCP_INFO *)(pevtnot + 1);
									int			nevents = pevtnot->nevents_;

									handle_shyama_tcp_cli(ptcp, nevents, pendptr, pthrpoolarr);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Shyama TCP Client Notify : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;

							case NOTIFY_SHYAMA_SER_TCP_INFO :
								try {
									statsmap["Shyama TCP Server Notify"]++;

									SHYAMA_SER_TCP_INFO	*ptcp = (SHYAMA_SER_TCP_INFO *)(pevtnot + 1);
									int			nevents = pevtnot->nevents_;

									handle_shyama_tcp_ser(ptcp, nevents, pendptr, pthrpoolarr);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Shyama TCP Server Notify : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;


							case NOTIFY_SM_SVC_CLUSTER_MESH :
								try {
									statsmap["Shyama Svc Mesh Cluster Notify"]++;

									auto		 	*psvc = (SM_SVC_CLUSTER_MESH *)(pevtnot + 1);
									int			nevents = pevtnot->nevents_;

									handle_shyama_svc_mesh(psvc, nevents, pendptr, pthrpoolarr);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Shyama Svc Mesh Notify : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;


							case NOTIFY_SM_SVC_NAT_IP_CLUSTER :
								try {
									statsmap["Shyama Svc Nat IP Cluster Notify"]++;

									auto		 	*psvc = (SM_SVC_NAT_IP_CLUSTER *)(pevtnot + 1);
									int			nevents = pevtnot->nevents_;

									handle_shyama_svc_natip_clust(psvc, nevents, pendptr, pthrpoolarr);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Shyama Svc NAT IP Cluster Notify : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;


							case NOTIFY_MM_LISTENER_ISSUE_RESOL :
								try {
									statsmap["Remote Madhava Listener Issue Resolve"]++;

									auto			*plist = (MM_LISTENER_ISSUE_RESOL *)(pevtnot + 1);

									handle_mm_listener_issue(dbarr.shrconn_->get_madhava_shared(), plist, pevtnot->nevents_, pendptr, pthrpoolarr);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Remote Madhava Issue Resolve : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;		

							case NOTIFY_NEW_LISTENER :
								try {
									NEW_LISTENER	 	*plist = (NEW_LISTENER *)(pevtnot + 1);
									int			nevents = pevtnot->nevents_;
									uint32_t		nresplisten, szresp;

									statsmap["New Listener Notify"]++;

									partha_listener_info(dbarr.shrconn_->get_partha_shared(), plist, nevents, pendptr, nullptr,
										0, nresplisten, szresp, pthrpoolarr, dbpool);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Partha New Listener Notify : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;

							case NOTIFY_LISTENER_DEPENDENCY :
								try {
									auto			*plist = (LISTENER_DEPENDENCY_NOTIFY *)(pevtnot + 1);
									int			nevents = pevtnot->nevents_;

									statsmap["Partha Listener Dependency"]++;

									partha_listener_dependency(dbarr.shrconn_->get_partha_shared(), plist, nevents, pendptr, statsmap, pthrpoolarr);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Partha Listener Dependency Notify : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;
												
							case NOTIFY_MM_LISTENER_DEPENDS :
								try {
									statsmap["Remote Madhava Listener Dependency"]++;

									auto			*plist = (MM_LISTENER_DEPENDS *)(pevtnot + 1);

									handle_mm_listener_depends(dbarr.shrconn_->get_madhava_shared(), plist, pevtnot->nevents_, pthrpoolarr);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Remote Madhava Listener Dependency : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;		


							case NOTIFY_MM_LISTENER_PING :
								try {
									statsmap["Remote Madhava Listener Ping"]++;

									auto			*plist = (MM_LISTENER_PING *)(pevtnot + 1);

									handle_mm_listener_ping(dbarr.shrconn_, plist, pevtnot->nevents_);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Remote Madhava Listener Deletion : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;		


							case NOTIFY_MM_LISTENER_DELETE :
								try {
									statsmap["Remote Madhava Listener Deletion"]++;

									auto			*plist = (MM_LISTENER_DELETE *)(pevtnot + 1);

									handle_mm_listener_delete(dbarr.shrconn_->get_madhava_shared(), plist, pevtnot->nevents_);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Remote Madhava Listener Deletion : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;		


							case NOTIFY_AGGR_TASK_HIST_STATS :
								try {
									statsmap["Aggr Task Hist Stats"]++;

									auto 		*ptask = (AGGR_TASK_HIST_STATS *)(pevtnot + 1);

									handle_aggr_task_hist_stats(dbarr.shrconn_, ptask, pevtnot->nevents_, pthrpoolarr, dbpool);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Aggr Task Hist Stats : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;		

							case NOTIFY_PING_TASK_AGGR :
								try {
									statsmap["Ping Aggr Task"]++;

									PING_TASK_AGGR 		*ptask = (PING_TASK_AGGR *)(pevtnot + 1);

									handle_ping_aggr_task(dbarr.shrconn_->get_partha_shared(), ptask, pevtnot->nevents_, pthrpoolarr, dbpool);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Partha Ping Aggr Task : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;		


							case NOTIFY_MM_TASK_AGGR_PING :
								try {
									statsmap["Remote Madhava Ping Aggr Task"]++;

									MM_TASK_AGGR_PING 	*ptask = (MM_TASK_AGGR_PING *)(pevtnot + 1);

									handle_mm_ping_aggr_task(dbarr.shrconn_->get_madhava_shared(), ptask, pevtnot->nevents_);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling remote Madhava Ping Aggr Task : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;		

							case NOTIFY_MM_TASK_AGGR_DEL :
								try {
									statsmap["Remote Madhava Delete Aggr Task"]++;

									MM_TASK_AGGR_DEL 	*ptask = (MM_TASK_AGGR_DEL *)(pevtnot + 1);

									handle_mm_del_aggr_task(dbarr.shrconn_->get_madhava_shared(), ptask, pevtnot->nevents_);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Remote Madhava Delete Aggr Task : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;		

							case NOTIFY_MM_AGGR_TASK_STATE :
								try {
									AGGR_TASK_STATE_NOTIFY 	*ptask = (AGGR_TASK_STATE_NOTIFY *)(pevtnot + 1);
									int			nevents = pevtnot->nevents_;

									statsmap["Remote Madhava Aggr Task State Notify"]++;

									handle_mm_aggr_task_state(dbarr.shrconn_->get_madhava_shared(), ptask, nevents, pendptr);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Remote Madhava Aggr Task State Notify : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;


							case NOTIFY_CPU_MEM_STATE :
								try {
									statsmap["Partha CPU Mem State"]++;

									CPU_MEM_STATE_NOTIFY 	*pcpumem = (CPU_MEM_STATE_NOTIFY *)(pevtnot + 1);

									handle_cpu_mem_state(dbarr.shrconn_->get_partha_shared(), pcpumem, pthrpoolarr, dbpool);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Partha CPU Memory State : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;		
							
							case NOTIFY_HOST_STATE :
								try {
									statsmap["Partha Host State"]++;

									auto		 	*phost = (HOST_STATE_NOTIFY *)(pevtnot + 1);

									handle_host_state(dbarr.shrconn_->get_partha_shared(), phost, dbpool);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Partha Host State : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;		

							case NOTIFY_HOST_STATE__V000100 :
								try {
									statsmap["Partha v0.1.0 Host State"]++;

									auto		 	*phost = (HOST_STATE_NOTIFY__V000100 *)(pevtnot + 1);

									HOST_STATE_NOTIFY	hstate(*phost);	

									handle_host_state(dbarr.shrconn_->get_partha_shared(), &hstate, dbpool);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Partha v0.1.0 Host State : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;		


							case NOTIFY_HOST_INFO :
								try {
									statsmap["Partha Host Info"]++;

									auto		 	*phost = (HOST_INFO_NOTIFY *)(pevtnot + 1);

									handle_host_info(dbarr.shrconn_->get_partha_shared(), phost, dbpool);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Partha Host Info : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;		

							case NOTIFY_HOST_CPU_MEM_CHANGE :
								try {
									statsmap["Partha Host CPU Mem Change"]++;

									auto		 	*phost = (HOST_CPU_MEM_CHANGE *)(pevtnot + 1);

									handle_host_cpu_mem_change(dbarr.shrconn_->get_partha_shared(), phost, dbpool);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Partha CPU Mem Change : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;		

							case NOTIFY_NOTIFICATION_MSG :
								try {
									statsmap["Notification Msg"]++;

									auto	 		*pmsg = (NOTIFICATION_MSG *)(pevtnot + 1);
									int			nevents = pevtnot->nevents_;

									handle_notification_msg(dbarr.shrconn_->get_partha_shared(), pmsg, nevents, pendptr, dbpool);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Notification Msg : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;		

							case NOTIFY_ACTIVE_CONN_STATS :
								try {
									auto		 	*pconn = (ACTIVE_CONN_STATS *)(pevtnot + 1);
									int			nevents = pevtnot->nevents_;

									statsmap["Partha Active Conn Stats"]++;
									handle_partha_active_conns(dbarr.shrconn_->get_partha_shared(), pconn, nevents, pendptr, pthrpoolarr, dbpool);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Partha Active Conn Stats : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;


							case NOTIFY_LISTEN_TASKMAP_EVENT :
								try {
									auto		 	*plist = (LISTEN_TASKMAP_NOTIFY *)(pevtnot + 1);
									int			nevents = pevtnot->nevents_;

									statsmap["Partha Listen Taskmap Stats"]++;
									handle_listen_taskmap(dbarr.shrconn_->get_partha_shared(), plist, nevents, pendptr, pthrpoolarr, dbpool);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Partha Listen Taskmap Stats : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;


							case NOTIFY_TASK_MINI_ADD :
								try {
									TASK_MINI_ADD	 	*ptask = (TASK_MINI_ADD *)(pevtnot + 1);
									int			nevents = pevtnot->nevents_;

									statsmap["Task Mini Add"]++;
									insert_db_mini_task(dbarr.shrconn_->get_partha_shared(), ptask, nevents, pendptr);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Task Mini Add events : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;
							
							case NOTIFY_TASK_FULL_ADD :
								try {
									TASK_FULL_ADD	 	*ptask = (TASK_FULL_ADD *)(pevtnot + 1);
									int			nevents = pevtnot->nevents_;

									statsmap["Task Full Add"]++;
									insert_db_full_task(dbarr.shrconn_->get_partha_shared(), ptask, nevents, pendptr, dbpool);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Task Full Add Events : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;

							case NOTIFY_TASK_TOP_PROCS :
								try {
									TASK_TOP_PROCS	 	*ptask = (TASK_TOP_PROCS *)(pevtnot + 1);

									statsmap["Task Top Procs"]++;
									insert_db_top_procs(dbarr.shrconn_->get_partha_shared(), ptask, pendptr, dbpool);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Task Top Procs Event : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;

							case NOTIFY_TASK_HISTOGRAM :
								try {
									TASK_HISTOGRAM	 	*ptask = (TASK_HISTOGRAM *)(pevtnot + 1);
									int			nevents = pevtnot->nevents_;

									statsmap["Task Histogram Stats"]++;
									insert_db_task_stats(dbarr.shrconn_->get_partha_shared(), ptask, nevents, pendptr);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Task Histogram Stats : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;

								
							case NOTIFY_MADHAVA_LIST :
								try {
									MADHAVA_LIST 		*pmad = (MADHAVA_LIST *)((char *)pevtnot + sizeof(*pevtnot));
									int			nevents = pevtnot->nevents_;

									statsmap["Madhava List Notify"]++;
									
									handle_madhava_list(pmad, nevents, pendptr, statsmap);
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Madhava List Notify : %s\n", GY_GET_EXCEPT_STRING);
									statsmap["Exception Occurred"]++;
								);

								break;

							default :
								break;	
							}

							break;

						case PM_CONNECT_CMD :
							try {
								PM_CONNECT_CMD_S 		*preg = (PM_CONNECT_CMD_S *)(phdr + 1);

								statsmap["Partha Registration Request"]++;

								if (false == is_disconnected()) {
									handle_misc_partha_reg(preg, dbarr, param, pthrpoolarr, statsmap, dbpool);
								}
								else {
									DEBUGEXECN(11, INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Partha Registration Request seen but socket disconnected\n"););
								}	
								break;
							}
							GY_CATCH_EXCEPTION(
								ERRORPRINT_OFFLOAD("Exception occurred while handling Partha Registration request : %s\n", GY_GET_EXCEPT_STRING);
							);

							send_l1_register_connect_error<PM_CONNECT_RESP_S, PM_CONNECT_RESP>(dbarr.pl1_src_, dbarr.shrconn_, dbarr.shrconn_.get(), 
								dbarr.comm_magic_, statsmap, ERR_SERV_ERROR,  "Exception occurred while handling request.", pthrpoolarr);
							statsmap["Partha Registration Exception"]++;
							break;


						case MM_CONNECT_CMD :
							try {
								MM_CONNECT_CMD_S 		*preg = (MM_CONNECT_CMD_S *)(phdr + 1);

								statsmap["Remote Madhava Registration Request"]++;

								if (false == is_disconnected()) {
									handle_misc_madhava_reg(preg, dbarr, param, pthrpoolarr, statsmap);
								}	
								break;
							}
							GY_CATCH_EXCEPTION(
								ERRORPRINT_OFFLOAD("Exception occurred while handling Remote Madhava Registration request : %s\n", GY_GET_EXCEPT_STRING);
							);

							send_l1_register_connect_error<MM_CONNECT_RESP_S, MM_CONNECT_RESP>(dbarr.pl1_src_, dbarr.shrconn_, dbarr.shrconn_.get(), 
								dbarr.comm_magic_, statsmap, ERR_SERV_ERROR,  "Exception occurred while handling request.", pthrpoolarr);
							statsmap["Remote Madhava Register Exception"]++;
							break;


						case NM_CONNECT_CMD :
							try {
								NM_CONNECT_CMD_S		*pnm = (NM_CONNECT_CMD_S *)(phdr + 1);

								statsmap["Node Registration Request"]++;

								if (false == is_disconnected()) {
									handle_misc_node_reg(pnm, dbarr, param, pthrpoolarr, statsmap);
								}	
								break;
							}
							GY_CATCH_EXCEPTION(
								ERRORPRINT_OFFLOAD("Exception occurred while handling Node Registration request : %s\n", GY_GET_EXCEPT_STRING);
							);

							send_l1_register_connect_error<NM_CONNECT_RESP_S, NM_CONNECT_RESP>(dbarr.pl1_src_, dbarr.shrconn_, dbarr.shrconn_.get(), 
								dbarr.comm_magic_, statsmap, ERR_SERV_ERROR,  "Exception occurred while handling request.", pthrpoolarr);
							statsmap["Node Registration Exception"]++;
							
							break;


						default :
							statsmap["Invalid Misc Cmd Type"]++;
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
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught in %s while handling message : %s\n\n", param.descbuf_, GY_GET_EXCEPT_STRING);
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

MA_SETTINGS_C * MCONN_HANDLER::get_settings() const noexcept
{
	return pmadhava_->psettings_;
}	

void MCONN_HANDLER::send_madhava_registration(MCONNTRACK *pconn, uint64_t remote_madhava_id)
{
	auto			madshr = pconn->get_madhava_shared();
	if (!madshr) {
		GY_THROW_EXCEPTION("Invalid Madhava Connection as shared pointer invalid");
	}	

	const size_t		fixed_sz = sizeof(COMM_HEADER) + sizeof(MM_CONNECT_CMD_S);
	FREE_FPTR		free_fp;
	uint32_t		act_size;
	void			*palloc = malloc_or_throw(fixed_sz);

	COMM_HEADER		*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
	MM_CONNECT_CMD_S	*preq = reinterpret_cast<MM_CONNECT_CMD_S *>((uint8_t *)phdr + sizeof(COMM_HEADER)); 
	
	new (phdr) COMM_HEADER(MM_CONNECT_CMD, fixed_sz, pconn->get_comm_magic());

	new (preq) MM_CONNECT_CMD_S();
	
	std::memset(preq, 0, sizeof(*preq));

	preq->comm_version_		= comm::COMM_VERSION_NUM;
	preq->local_version_		= gversion_num;
	preq->min_remote_version_	= gversion_num;	// We need to have all Madhava peers of the same version

	GY_STRNCPY(preq->madhava_hostname_, service_hostname_, sizeof(preq->madhava_hostname_));
	preq->madhava_port_		= service_port_;
	
	GY_STRNCPY(preq->region_name_, region_name_, sizeof(preq->region_name_));
	GY_STRNCPY(preq->zone_name_, zone_name_, sizeof(preq->zone_name_));
	GY_STRNCPY(preq->madhava_name_, madhava_name_, sizeof(preq->madhava_name_));

	preq->local_madhava_id_		= gmadhava_id_;
	preq->remote_madhava_id_	= remote_madhava_id;
	preq->cli_type_			= pconn->cli_type_;
	preq->kern_version_num_		= OS_INFO::get_singleton()->get_kernel_version();
	preq->curr_sec_			= time(nullptr);
	preq->clock_sec_		= get_sec_clock();
	preq->curr_partha_nodes_	= partha_tbl_.approx_count_fast();

	struct iovec			iov[2] {{phdr, fixed_sz}, {(void *)gpadbuf, phdr->get_pad_len()}};	
	FREE_FPTR			free_fp_arr[2] {::free, nullptr};
	
	pconn->schedule_ext_send(EPOLL_IOVEC_ARR(iov, GY_ARRAY_SIZE(iov), free_fp_arr, false));
	 
	send_immediate(pconn);

	madshr->add_conn(pconn->pl1_, pconn->weak_from_this(), pconn, HOST_MADHAVA, pconn->cli_type_);
}	

bool MCONN_HANDLER::handle_madhava_reg_resp(MCONNTRACK *pconn1, comm::MM_CONNECT_RESP_S *preg, STATS_STR_MAP & statsmap)
{
	auto			madshr = pconn1->get_madhava_shared();
	auto			pmad = madshr.get();

	if (!pmad) {
		return false;
	}	

	if (preg->error_code_ != ERR_SUCCESS) {
		preg->error_string_[sizeof(preg->error_string_) - 1] = 0;

		ERRORPRINT_OFFLOAD("Remote Madhava server %s port %hu Registration Failed due to %s...\n", 
			pmad->get_domain(), pmad->get_port(), preg->error_string_);

		return false;
	}	
	
	pconn1->set_registered();
	pconn1->set_max_idle_usec(MAX_CONN_IDLE_TIMEOUT_USEC);

	pmad->last_reg_tsec_		= time(nullptr);
	pmad->comm_version_		= preg->comm_version_;

	GY_STRNCPY(pmad->region_name_, preg->region_name_, sizeof(pmad->region_name_));
	GY_STRNCPY(pmad->zone_name_, preg->zone_name_, sizeof(pmad->zone_name_));
	GY_STRNCPY(pmad->madhava_name_, preg->madhava_name_, sizeof(pmad->madhava_name_));

	statsmap["Registered with Remote Madhava"]++;

	INFOPRINT_OFFLOAD("Registered successfully with remote Madhava peer %s %s\n", 
		pmad->print_string(STRING_BUFFER<512>().get_str_buf()), pconn1->print_peer(STRING_BUFFER<128>().get_str_buf())); 
		
	
	return true;
};	

void MCONN_HANDLER::send_shyama_registration(MCONNTRACK *pconn)
{
	const size_t		fixed_sz = sizeof(COMM_HEADER) + sizeof(MS_REGISTER_REQ_S);
	FREE_FPTR		free_fp;
	uint32_t		act_size;
	void			*palloc = malloc_or_throw(fixed_sz);
	COMM_HEADER		*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
	MS_REGISTER_REQ_S	*preq = reinterpret_cast<MS_REGISTER_REQ_S *>((uint8_t *)phdr + sizeof(COMM_HEADER)); 
	
	new (phdr) COMM_HEADER(MS_REGISTER_REQ, fixed_sz, pconn->get_comm_magic());

	new (preq) MS_REGISTER_REQ_S();
	
	std::memset(preq, 0, sizeof(*preq));

	preq->comm_version_		= comm::COMM_VERSION_NUM;
	preq->madhava_version_		= gversion_num;
	preq->min_shyama_version_	= gmin_shyama_version;

	preq->madhava_id_		= gmadhava_id_;

	GY_STRNCPY(preq->madhava_hostname_, service_hostname_, sizeof(preq->madhava_hostname_));
	preq->madhava_port_		= service_port_;

	GY_STRNCPY(preq->region_name_, region_name_, sizeof(preq->region_name_));
	GY_STRNCPY(preq->zone_name_, zone_name_, sizeof(preq->zone_name_));
	GY_STRNCPY(preq->madhava_name_, madhava_name_, sizeof(preq->madhava_name_));
	GY_STRNCPY(preq->shyama_secret_, gshyama_.shyama_secret_, sizeof(preq->shyama_secret_));
	
	preq->cli_type_			= pconn->cli_type_;
	preq->kern_version_num_		= OS_INFO::get_singleton()->get_kernel_version();
	preq->curr_sec_			= time(nullptr);
	preq->clock_sec_		= get_sec_clock();
	preq->max_partha_nodes_		= max_partha_allowed_;
	preq->last_partha_nodes_	= partha_tbl_.count_slow();

	struct iovec			iov[2] {{phdr, fixed_sz}, {(void *)gpadbuf, phdr->get_pad_len()}};	
	FREE_FPTR			free_fp_arr[2] {::free, nullptr};
	
	pconn->schedule_ext_send(EPOLL_IOVEC_ARR(iov, GY_ARRAY_SIZE(iov), free_fp_arr, false));
	 
	send_immediate(pconn);

	gshyama_.add_conn(pconn->pl1_, pconn->weak_from_this(), pconn, HOST_SHYAMA, pconn->cli_type_);
}	

/*
 * Currently we have only 1 connection per cli type to shyama from Madhava...
 * Shyama connect's are done synchronously
 */
int MCONN_HANDLER::connect_shyama_blocking(comm::CLI_TYPE_E clitype, MAP_CONNTRACK & mconntrack, int epollfd, const L1_PARAMS *pl1, STATS_STR_MAP & statsmap, POOL_ALLOC_ARRAY * pthrpoolarr)
{
	if (true == gshyama_.is_cli_type_avail(clitype)) {
		// This can occur if Shyama register resp not yet recv and next scheduler event fires
		return 1;
	}	

	int			ret;
	sockaddr_storage	sockaddr;
	socklen_t		socklen;

	auto [sfd, conn_success] = gy_tcp_connect(gshyama_.curr_shyama_host_, gshyama_.curr_shyama_port_, gshyama_.last_error_buf_, "Shyama Server", true /* set_nodelay */, 
		false /* always_resolve_dns */, &sockaddr, &socklen, false /* use_ipv4_only */, true /* cloexec */, false /* set_nonblock */);

	if (sfd < 0) {
		uint64_t		csec = get_sec_clock(), lastcsec = GY_READ_ONCE(gshyama_.last_reg_csec_);

		gshyama_.nfails_++;

		if (gshyama_.nfails_ >= 4 && gshyama_.shyama_host_vec_.size() > 1 && (csec - lastcsec >= 270 || (csec - lastcsec >= 90 && !gshyama_.last_reg_tsec_))) {
		
			gshyama_.curr_shyama_index_++;
			if (gshyama_.curr_shyama_index_ >= gshyama_.shyama_host_vec_.size()) {
				gshyama_.curr_shyama_index_ = 0;
			}	
			
			const auto			*pnewhost = gshyama_.shyama_host_vec_[gshyama_.curr_shyama_index_].data();
			uint16_t			newport = gshyama_.shyama_port_vec_[gshyama_.curr_shyama_index_];

			INFOPRINT_OFFLOAD("Checking for Shyama Failover as current Shyama Host %s Port %hu not connected since last %ld seconds (last error %s) : "
					"Will try with next Shyama Host %s Port %hu after a few seconds\n", 
					gshyama_.curr_shyama_host_, gshyama_.curr_shyama_port_, csec - lastcsec, gshyama_.last_error_buf_, pnewhost, newport);

			GY_STRNCPY(gshyama_.curr_shyama_host_, pnewhost, sizeof(gshyama_.curr_shyama_host_));
			gshyama_.curr_shyama_port_	= newport;

			gshyama_.nfails_		= 0;

			close_all_conns(gshyama_);
		}	
		else {
			ERRORPRINT_OFFLOAD("Failed to connect to Shyama Server %s port %hu due to %s : Will retry later. Time since last connect to Shyama : %ld minutes\n", 
				gshyama_.curr_shyama_host_, gshyama_.curr_shyama_port_, gshyama_.last_error_buf_, (csec - lastcsec)/60);
		}	
		
		// return as we will retry at the next scheduler signal
		statsmap["Shyama Connect Failed"]++;
		return -1;
	}	

	statsmap["Shyama Connect"]++;

	set_sock_nonblocking(sfd, 1);
	set_sock_keepalive(sfd);

	try {

		auto 			[it, success] = mconntrack.try_emplace(sfd, nullptr);
		struct epoll_event	ev;

		if (success == true) {
			try {
				it->second = std::make_shared<MCONNTRACK>(&sockaddr, sfd, epollfd, nullptr, 
					0, 0, true /* use_pipeline */, MAX_CONN_DATA_TIMEOUT_USEC, MAX_CONN_DATA_TIMEOUT_USEC, false /* close_conn_on_wr_complete */,
					true /* is_outgoing */);
			}
			GY_CATCH_EXCEPTION(
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while creating map element for new Shyama connection %s\n", 
					GY_GET_EXCEPT_STRING);

				mconntrack.erase(it);
				::close(sfd);
				statsmap["Exception Occurred"]++;
				return -1;
			);

			MCONNTRACK		*pnewconn = it->second.get();

			pnewconn->set_epoll_data(pnewconn);
			pnewconn->set_comm_magic(comm::COMM_HEADER::MS_HDR_MAGIC);

			pnewconn->pl1_ 		= pl1;
			pnewconn->host_type_ 	= HOST_SHYAMA;
			pnewconn->cli_type_ 	= clitype;

			ev.data.ptr		= pnewconn;
			ev.events 		= EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLET;

			ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, sfd, &ev);
			if (ret != 0) {
				PERRORPRINTCOLOR(GY_COLOR_RED, "Shyama Conn epoll add failed");
				mconntrack.erase(it);

				return -1;
			}	

			try {
				send_shyama_registration(pnewconn);
			}
			GY_CATCH_EXCEPTION(
				ERRORPRINT_OFFLOAD("Shyama Conn Registration send / add conn failed : %s\n", GY_GET_EXCEPT_STRING);
				mconntrack.erase(it);

				return -1;
			);

			return 0;
		}
		else {
			if (it != mconntrack.end()) {
				mconntrack.erase(it);
			}	
			else {
				close(sfd);
			}
			return -1;
		}	
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while handling new Shyama connection %s\n", GY_GET_EXCEPT_STRING);
		close(sfd);
		statsmap["Exception Occurred"]++;
		return -1;
	);
};	

bool MCONN_HANDLER::handle_shyama_reg_resp(MCONNTRACK *pconn1, comm::MS_REGISTER_RESP_S *preg, STATS_STR_MAP & statsmap)
{
	if (preg->error_code_ != ERR_SUCCESS) {

		if (preg->error_code_ == ERR_ID_REUSED) {
			if (GY_READ_ONCE(tlast_instance_) <= time(nullptr) + 60) {
				ERRORPRINT("Shyama server %s port %hu Registration Failed due to %s : Postgres DB Instance update has also failed since over a minute : Restarting process...\n",
					gshyama_.curr_shyama_host_, gshyama_.curr_shyama_port_, preg->error_string_);

				pmadhava_->send_proc_restart_exit();
			}	
		}	

		ERRORPRINT_OFFLOAD("Shyama server %s port %hu Registration Failed due to %s : will retry later...\n", 
			gshyama_.curr_shyama_host_, gshyama_.curr_shyama_port_, preg->error_string_);

		GY_STRNCPY(gshyama_.last_error_buf_, preg->error_string_, sizeof(gshyama_.last_error_buf_));
		return false;
	}	
	
	if (gmadhava_id_ != preg->madhava_id_) {
		ERRORPRINT_OFFLOAD("Shyama Registration Error as Madhava ID returned is different. Shyama returned Madhava ID is %016lx instead of current ID %016lx. Closing connection...\n",
			preg->madhava_id_, gmadhava_id_);
		return false;
	}

	pconn1->set_registered();
	pconn1->set_max_idle_usec(MAX_CONN_IDLE_TIMEOUT_USEC);

	gshyama_.last_reg_csec_			= get_sec_clock();
	gshyama_.last_reg_tsec_			= time(nullptr);
	gshyama_.last_error_buf_[0]		= 0;
	gshyama_.shyama_id_			= preg->shyama_id_;
	gshyama_.comm_version_			= preg->comm_version_;
	gshyama_.shyama_version_		= preg->shyama_version_;
	
	GY_STRNCPY(gshyama_.region_name_, preg->region_name_, sizeof(gshyama_.region_name_));
	GY_STRNCPY(gshyama_.zone_name_, preg->zone_name_, sizeof(gshyama_.zone_name_));
	GY_STRNCPY(gshyama_.shyama_name_, preg->shyama_name_, sizeof(gshyama_.shyama_name_));

	gshyama_.nfails_ 			= 0;

	gshyama_.last_status_.nmadhava_reg_	= preg->nmadhava_reg_;
	gshyama_.last_status_.nmadhava_partha_	= preg->nmadhava_partha_;

	if (preg->flags_ & comm::MS_REGISTER_RESP_S::CONN_FLAGS_RESET_STATS) {
		shyama_reset_stats_		= true;		// Currently a NOP
	}	

	if (preg->flags_ & comm::MS_REGISTER_RESP_S::CONN_FLAGS_SEND_PARTHAS) {
		shyama_send_parthas_		= true;
	}	

	SHYAMA_INFO::stop_shyama_scheduler(pconn1->cli_type_);

	statsmap["Registered with Shyama"]++;

	INFOPRINT_OFFLOAD("Registered successfully with Shyama Server %s from Remote %s Region %s Zone %s : Current # connections to Shyama is %lu\n", 
		gshyama_.print_string(STRING_BUFFER<512>().get_str_buf()), pconn1->print_peer(STRING_BUFFER<128>().get_str_buf()), 
		gshyama_.region_name_, gshyama_.zone_name_, gshyama_.get_num_conns());
	
	return true;
};	

bool MCONN_HANDLER::set_partha_ident(MCONNTRACK *pconn1, SM_PARTHA_IDENT_NOTIFY *preq, STATS_STR_MAP & statsmap) noexcept
{
	try {
		/*
		 * First check the partha_tbl_ itslef. If not found, then add an entry to partha_id_tbl_
		 */
		if ((preq->machine_id_hi_ == 0) && (preq->machine_id_lo_ == 0)) {
			statsmap["Invalid Partha Ident from Shyama"]++;
			return false;
		}
		
		GY_MACHINE_ID			machid (preq->machine_id_hi_, preq->machine_id_lo_);
		const uint32_t			mhash = machid.get_hash();
		bool				bret = false;

		auto lamp = [&](PARTHA_INFO_ELEM *pelem, void *arg1, void *arg2) -> CB_RET_E
		{
			PARTHA_INFO			*pinfo = pelem->get_data()->get();
	
			if (gy_unlikely(nullptr == pinfo)) {
				return CB_DELETE_ELEM;
			}

			pinfo->partha_ident_key_	= preq->partha_ident_key_;
			pinfo->ident_key_expiry_tsec_	= preq->texpiry_sec_;
	
			bret = true;

			return CB_OK;
		};

		partha_tbl_.lookup_single_elem(machid, mhash, lamp);

		if (bret == true) {
			return true;
		}	
		
		time_t			tcur = time(nullptr);

		SCOPE_GY_MUTEX		scopelock(&node_partha_mutex_);

		if (partha_id_tbl_.size() > 10 * max_partha_allowed_) {
			preq->hostname_[sizeof(preq->hostname_) - 1] = 0;
			statsmap["Partha Ident Ignored as Max Reached"]++;

			ERRORPRINT_OFFLOAD("Too many Partha Ident entries seen from Shyama : %lu. Ignoring Partha ident for Machine ID %016lx%016lx host %s\n",
				partha_id_tbl_.size(), preq->machine_id_hi_, preq->machine_id_lo_, preq->hostname_);
			return false;
		}

		partha_id_tbl_.insert_or_assign(machid, std::move(*preq));

		if (partha_id_tbl_.size() > 2 * max_partha_allowed_) {
			// Cleanup unused elements
			for (auto it = partha_id_tbl_.begin(); it != partha_id_tbl_.end();) {

				if (tcur > it->second.texpiry_sec_) {
					it = partha_id_tbl_.erase(it);
				}	
				else {
					++it;
				}
			}
		}	
		
		return true;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT_OFFLOAD("Exception caught while setting Partha Ident Key : %s\n", GY_GET_EXCEPT_STRING);
		return false;
	);
}	



void MCONN_HANDLER::insert_db_mini_task(const std::shared_ptr<PARTHA_INFO> & partha_shr, const comm::TASK_MINI_ADD * ptask, int ntasks, uint8_t *pendptr) 
{
	// Currently not handled...
}	

void MCONN_HANDLER::insert_db_full_task(const std::shared_ptr<PARTHA_INFO> & partha_shr, const comm::TASK_FULL_ADD *ptask, int ntasks, uint8_t *pendptr, PGConnPool & dbpool) 
{
	PARTHA_INFO			*prawpartha = partha_shr.get();

	if (!prawpartha) {
		return;
	}	

	/*
	 * Currently we do not store individual processes to DB. Uncomment this and enable partha TASK_FULL_ADD sends if this is needed.
	 */
#if 0

	const uint64_t			currtsec = get_sec_time();
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 10'000 /* max_msec_wait */, false /* reset_on_timeout */);
	
	if (!pconn) {
		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ntaskadd_failed_.fetch_add_relaxed(1);
		
		DEBUGEXECN(5,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get DB Conn for Partha %s Task Adds\n", prawpartha->hostname_);
		);
		return;
	}	
	
	STRING_BUFFER<256 * 1028>	qbuf;
	auto				timebuf = gy_localtime_iso8601_sec(currtsec);
	const auto			datetbl = get_db_day_partition(currtsec, 30);
	auto				schemabuf = prawpartha->get_db_schema();
	auto				pone = ptask;
	bool				bret;

	qbuf.appendfmt("insert into %s.tasktbl%s values ", schemabuf.get(), datetbl.get());

	for (int i = 0; i < ntasks && (uint8_t *)pone < pendptr; ++i, pone = decltype(pone)((uint8_t *)pone + pone->get_elem_size())) {
		qbuf.appendfmt("(\'%s\', %d, %d, %d, %d, %d, %d, %d, \'%s\', \'%s\', \'%016lx\', %d, %d, %d, %d, %d, %d, %d, to_timestamp(%ld), " 
			"%ld, %ld, %d, %d, %d, \'%d\', \'%d\', \'%d\', \'%d\', \'%d\', \'",
			timebuf.get(), pone->task_pid_, pone->task_ppid_, pone->task_pgid_, pone->task_sid_, pone->task_nspid_,
			pone->task_nspgid_, pone->task_nssid_, pone->task_comm_, pone->task_parent_comm_, pone->aggr_task_id_,
			pone->task_realuid_, pone->task_effuid_, pone->task_realgid_, pone->task_effgid_, pone->ncpus_allowed_,
			pone->nmems_allowed_, pone->task_flags_, pone->start_tusec_/GY_USEC_PER_SEC, pone->task_priority_,
			pone->task_nice_, pone->task_rt_priority_, pone->task_sched_policy_, pone->ntcp_listeners_,
			pone->is_tcp_server_, pone->is_tcp_client_, pone->is_parent_tcp_client_, pone->is_high_cap_,
			pone->listen_tbl_inherited_);

		if (pone->task_exe_path_len_ > 1) {
			qbuf.append((const char *)(pone + 1), pone->task_exe_path_len_ - 1);
		}	

		qbuf.appendconst("\', \'");

		if (pone->task_cmdline_len_ > 1) {
			auto		cmdline = pconn->escape_string<512>((const char *)((uint8_t *)pone + sizeof(*pone) + pone->task_exe_path_len_), 
						pone->task_cmdline_len_ - 1);

			qbuf.append(cmdline.get(), cmdline.size());
		}

		qbuf.appendconst("\', \'");

		if (pone->task_tags_len_ > 1) {
			auto		tagbuf = pconn->escape_string<2048>((const char *)((uint8_t *)pone + sizeof(*pone) + pone->task_exe_path_len_ + pone->task_cmdline_len_), 
						pone->task_tags_len_ - 1);

			qbuf.append(tagbuf.get(), tagbuf.size());
		}

		qbuf.appendconst("\'),");
	}	

	qbuf.set_last_char(';');
	
	bret = PQsendQueryOptim(pconn->get(), qbuf.buffer(), qbuf.size());
	
	if (bret == false) {
		db_stats_.ntaskadd_failed_.fetch_add_relaxed(1);

		DEBUGEXECN(5,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to schedule DB query to add Partha %s Tasks due to %s\n", prawpartha->hostname_, PQerrorMessage(pconn->get()));
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
				db_stats_.ntaskadd_failed_.fetch_add_relaxed(1);

				DEBUGEXECN(5,
					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to insert Partha Tasks into DB due to %s\n", gyres.get_error_msg());
				);

				return false;
			}	

			return true;
		}
	);
#endif	
}	

void MCONN_HANDLER::insert_db_top_procs(const std::shared_ptr<PARTHA_INFO> & partha_shr, const comm::TASK_TOP_PROCS *ptask, uint8_t *pendptr, PGConnPool & dbpool) 
{
	PARTHA_INFO			*prawpartha = partha_shr.get();

	if (!prawpartha) {
		return;
	}	

	const uint64_t			currtusec = get_usec_time();
	const time_t			currt = currtusec/GY_USEC_PER_SEC;

	prawpartha->toptasks_.update_stats(ptask, pendptr, currtusec);

	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 10'000 /* max_msec_wait */, false /* reset_on_timeout */);
	
	if (!pconn) {
		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ntop_tasks_failed_.fetch_add_relaxed(1);
		
		DEBUGEXECN(5,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get DB Conn for Partha %s Top Tasks updation\n", prawpartha->hostname_);
		);
		return;
	}	
	
	STRING_BUFFER<256 * 1028>	qbuf;
	auto				timebuf = gy_localtime_iso8601_sec(currt);
	auto				schemabuf = prawpartha->get_db_schema();
	auto				datetbl = get_db_day_partition(currt, 15);
	bool				bret;

	auto				toptasks = prawpartha->toptasks_;
	const auto			&topinfo = toptasks.topinfo_;
	TASK_TOP_PROCS::TOP_TASK	*ptoptask = decltype(ptoptask)(toptasks.topn_data_);

	SharedMutex::ReadHolder		rtscope(prawpartha->rtalerts_.adef_rwmutex_);
	bool				isrtadef = !!(prawpartha->rtalerts_.adef_topcpu_.size() + prawpartha->rtalerts_.adef_toppgcpu_.size() + 
							prawpartha->rtalerts_.adef_toprss_.size() + prawpartha->rtalerts_.adef_topfork_.size());

	if (!isrtadef) {
		rtscope.unlock();
	}	

	qbuf.appendconst("Begin Work;");

	if (topinfo.nprocs_) {
		qbuf.appendfmt("\ninsert into %s.topcputbl%s values ", schemabuf.get(), datetbl.get());

		for (uint32_t i = 0; i < topinfo.nprocs_; ++i, ++ptoptask) {
			if (isrtadef) {
				topcpurss_rtalert_rwlocked(*prawpartha, *ptoptask, i + 1, SUBSYS_TOPCPU, currt, timebuf.get()); 
			}

			qbuf.appendfmt("(\'%s\', \'%016lx\', %d, %d, %d, %.3f, \'%s\', %d),", 
				timebuf.get(), ptoptask->aggr_task_id_, ptoptask->pid_, ptoptask->ppid_, ptoptask->rss_mb_,
				ptoptask->cpupct_, ptoptask->comm_, i + 1);
		}	

		qbuf.set_last_char(';');
	}

	TASK_TOP_PROCS::TOP_PG_TASK	*ptoppgtask = decltype(ptoppgtask)(ptoptask);

	if (topinfo.npg_procs_) {
		qbuf.appendfmt("\ninsert into %s.toppgcputbl%s values ", schemabuf.get(), datetbl.get());

		for (uint32_t i = 0; i < topinfo.npg_procs_; ++i, ++ptoppgtask) {
			if (isrtadef) {
				toppgcpu_rtalert_rwlocked(*prawpartha, *ptoppgtask, i + 1, currt, timebuf.get()); 
			}

			qbuf.appendfmt("(\'%s\', \'%016lx\', %d, %d, %d, %d, %.3f, \'%s\', \'%s\', %d),", 
				timebuf.get(), ptoppgtask->aggr_task_id_, ptoppgtask->pg_pid_, ptoppgtask->cpid_, ptoppgtask->ntasks_,
				ptoppgtask->tot_rss_mb_, ptoppgtask->tot_cpupct_, ptoppgtask->pg_comm_, ptoppgtask->child_comm_, i + 1);
		}	

		qbuf.set_last_char(';');
	}

	TASK_TOP_PROCS::TOP_TASK	*ptoprsstask = decltype(ptoprsstask)(ptoppgtask);

	if (topinfo.nrss_procs_) {
		qbuf.appendfmt("\ninsert into %s.toprsstbl%s values ", schemabuf.get(), datetbl.get());

		for (uint32_t i = 0; i < topinfo.nrss_procs_; ++i, ++ptoprsstask) {
			if (isrtadef) {
				topcpurss_rtalert_rwlocked(*prawpartha, *ptoprsstask, i + 1, SUBSYS_TOPRSS, currt, timebuf.get()); 
			}

			qbuf.appendfmt("(\'%s\', \'%016lx\', %d, %d, %d, %.3f, \'%s\', %d),", 
				timebuf.get(), ptoprsstask->aggr_task_id_, ptoprsstask->pid_, ptoprsstask->ppid_,
				ptoprsstask->rss_mb_, ptoprsstask->cpupct_, ptoprsstask->comm_, i + 1);
		}	

		qbuf.set_last_char(';');

	}

	TASK_TOP_PROCS::TOP_FORK_TASK	*ptopforktask = decltype(ptopforktask)(ptoprsstask);

	if (topinfo.nfork_procs_) {
		qbuf.appendfmt("\ninsert into %s.topforktbl%s values ", schemabuf.get(), datetbl.get());

		for (uint32_t i = 0; i < topinfo.nfork_procs_; ++i, ++ptopforktask) {
			if (isrtadef) {
				topfork_rtalert_rwlocked(*prawpartha, *ptopforktask, i + 1, currt, timebuf.get()); 
			}

			qbuf.appendfmt("(\'%s\', \'%016lx\', %d, %d, %d, \'%s\', %d),", 
				timebuf.get(), ptopforktask->aggr_task_id_, ptopforktask->pid_, ptopforktask->ppid_,
				ptopforktask->nfork_per_sec_, ptopforktask->comm_, i + 1);
		}	

		qbuf.set_last_char(';');
	}

	qbuf.appendconst("Commit Work;");

	if (isrtadef) {
		rtscope.unlock();
	}	

	bret = PQsendQueryOptim(pconn->get(), qbuf.buffer(), qbuf.size());
	
	if (bret == false) {
		db_stats_.ntop_tasks_failed_.fetch_add_relaxed(1);

		DEBUGEXECN(5,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to schedule DB query to update Partha %s Top Tasks due to %s\n", prawpartha->hostname_, PQerrorMessage(pconn->get()));
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
				db_stats_.ntop_tasks_failed_.fetch_add_relaxed(1);

				DEBUGEXECN(5,
					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to insert Partha Top Tasks into DB due to %s\n", gyres.get_error_msg());
				);

				return false;
			}	

			return true;
		}
	);
}	

void MCONN_HANDLER::insert_db_task_stats(const std::shared_ptr<PARTHA_INFO> & partha_shr, const comm::TASK_HISTOGRAM * ptask, int ntasks, uint8_t *pendptr)
{
	// Currently not used...
}

bool MCONN_HANDLER::handle_partha_active_conns(const std::shared_ptr<PARTHA_INFO> & partha_shr, const comm::ACTIVE_CONN_STATS * pconn, int nitems, uint8_t *pendptr, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool) 
{
	PARTHA_INFO			*prawpartha = partha_shr.get();

	if (!prawpartha) {
		return false;
	}	

	time_t				tnewcur = time(nullptr), tcur = tnewcur, tlastsumm = prawpartha->tlast_active_insert_;
	const bool			is_continue_batch = (labs(tcur - tlastsumm) <= 4);	// Partha sends every 15 sec
	int				ncloselist = 0, nclosecli = 0;

	if (is_continue_batch) {
		// Set all time consistent for pointintime queries
		tcur = tlastsumm;
	}

	auto [nactlist, nactcli] = insert_active_conns(prawpartha, tcur, pconn, nitems, pendptr, dbpool);

	// Add records from previously closed conns
	if ((tnewcur >= prawpartha->tdbconnlistensec_ + 10) && (GY_READ_ONCE(prawpartha->tconnlistensec_) >= prawpartha->tdbconnlistensec_) && 
		(!prawpartha->connlistenmap_.empty() || !prawpartha->connclientmap_.empty())) {
		
		auto p = insert_close_conn_records(prawpartha, tcur, pthrpoolarr, dbpool);

		ncloselist 	= p.first;
		nclosecli 	= p.second;
	}	

	prawpartha->tlast_active_insert_ = tcur;

	DEBUGEXECN(12,
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "%s : Received Active Conn Stats for %d Listeners and %d Client Records : Updated %d Close Listener and %d Close Client connections to DB\n",
			prawpartha->print_string(STRING_BUFFER<128>().get_str_buf()), nactlist, nactcli, ncloselist, nclosecli);
	);

	return true;
}	

std::pair<int, int> MCONN_HANDLER::insert_active_conns(PARTHA_INFO *prawpartha, time_t tcur, const comm::ACTIVE_CONN_STATS * pactive, int nconn, uint8_t *pendptr, PGConnPool & dbpool) 
{
	if (nconn <= 0) {
		return {};
	}

	assert(gy_get_thread_local().get_thread_stack_freespace() >= 900 * 1024);
	
	using ExtActMap			= INLINE_STACK_HASH_MAP<uint64_t, const MTCP_LISTENER *, 48 * 1024, GY_JHASHER<uint64_t>>;
	using ExtCliMap			= INLINE_STACK_HASH_MAP<uint64_t, const MAGGR_TASK *, 48 * 1024, GY_JHASHER<uint64_t>>;

	std::optional<ExtActMap>	actmap;
	std::optional<ExtCliMap>	climap;

	STRING_BUFFER<700 * 1024>	qbuf;

	auto				timebuf = gy_localtime_iso8601_sec(tcur);
	auto				datetbl = get_db_day_partition(tcur, 30);
	auto				schemabuf = prawpartha->get_db_schema();
	const auto			*pone = pactive;

	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 10'000 /* max_msec_wait */, false /* reset_on_timeout */);
	int				nlisten = 0, ncli = 0;
	bool				bret, extact = false, extcli = false;
	
	if (!pconn) {
		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.nactive_conns_failed_.fetch_add_relaxed(1);
		
		DEBUGEXECN(5,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get DB Conn for Listener Active Conns updation\n");
		);
		
		return {};
	}	

	SharedMutex::ReadHolder			rtscope(prawpartha->rtalerts_.adef_rwmutex_);

	/*
	 * We do not look up the Listener or Task structs as we directly write to DB. 
	 * But if Extended Active Conn or Client Conn Alerts are active, we need to pass the
	 * corresponding structs. Hence the following...
	 */
	std::optional<RCU_LOCK_SLOW>		slowlock;

	extact 	= !!prawpartha->rtalerts_.nextact_;
	extcli	= !!prawpartha->rtalerts_.nextcli_;

	if (extact) {
		actmap.emplace();
	}	

	if (extcli) {
		climap.emplace();
	}	
	
	if (extact || extcli) {
		slowlock.emplace();
	}	

	qbuf.appendfmt("\ninsert into %s.activeconntbl%s values ", schemabuf.get(), datetbl.get());

	for (int i = 0; i < nconn; ++i, ++pone) {
		if (pone->is_remote_listen_ == false) {
			const MTCP_LISTENER		*plistener = nullptr;

			if (extact) {
				const uint64_t			glob_id = pone->listener_glob_id_;
				auto				it = actmap->find(glob_id);

				if (it != actmap->end()) {
					plistener = it->second;
				}	
				else {
					uint32_t		lhash = get_uint64_hash(glob_id);
					auto			pdatanode = prawpartha->listen_tbl_.lookup_single_elem_locked(glob_id, lhash);

					if (pdatanode) {
						plistener = pdatanode->get_cref().get();

						if (plistener && actmap->size() < 512) {
							actmap->try_emplace(glob_id, plistener);
						}	
					}	
				}	
			}	

			activeconn_rtalert_rwlocked(*prawpartha, *pone, tcur, timebuf.get(), plistener);
	
			qbuf.appendfmt("(\'%s\',\'%016lx\',\'%s\',\'%016lx\',\'%s\',\'%016lx%016lx\',\'%016lx\',%ld,%ld,%d,%d,%.3f,%hd,%hhd::boolean),", 
				timebuf.get(), pone->listener_glob_id_, pone->ser_comm_, pone->cli_aggr_task_id_,
				pone->cli_comm_, pone->remote_machine_id_.get_first(), pone->remote_machine_id_.get_second(), pone->remote_madhava_id_, 
				pone->bytes_sent_, pone->bytes_received_, pone->cli_delay_msec_, pone->ser_delay_msec_, pone->max_rtt_msec_, pone->active_conns_, 
				pone->cli_listener_proc_);

			nlisten++;
		}
		else {
			ncli++;
		}	
	}

	if (nlisten > 0) {
		qbuf.set_last_char(';');
	}
	else {
		qbuf.reset();
	}	

	if (ncli > 0) {

		qbuf.appendfmt("\ninsert into %s.remoteconntbl%s values ", schemabuf.get(), datetbl.get());

		pone = pactive;
		for (int i = 0; i < nconn; ++i, ++pone) {
			if (pone->is_remote_listen_ == true) {
				const MAGGR_TASK		*ptask = nullptr;
				
				if (extcli) {
					auto			it = climap->find(pone->cli_aggr_task_id_);

					if (it != climap->end()) {
						ptask = it->second;
					}
					else {
						auto			pdatanode = prawpartha->task_aggr_tbl_.lookup_single_elem_locked(pone->cli_aggr_task_id_, 
															get_uint64_hash(pone->cli_aggr_task_id_));

						if (pdatanode) {
							ptask = pdatanode->get_cref().get();

							if (ptask && climap->size() < 512) {
								climap->try_emplace(pone->cli_aggr_task_id_, ptask);
							}	
						}
					}
				}	
			
				clientconn_rtalert_rwlocked(*prawpartha, *pone, tcur, timebuf.get(), ptask);

				qbuf.appendfmt("(\'%s\',\'%016lx\',\'%s\',\'%016lx\',\'%s\',\'%016lx%016lx\',\'%016lx\',%ld,%ld,%hd,%hhd::boolean),", 
					timebuf.get(), pone->cli_aggr_task_id_, pone->cli_comm_, pone->listener_glob_id_, pone->ser_comm_, 
					pone->remote_machine_id_.get_first(), pone->remote_machine_id_.get_second(), pone->remote_madhava_id_, 
					pone->bytes_sent_, pone->bytes_received_, pone->active_conns_, pone->cli_listener_proc_);
			}
		}

		qbuf.set_last_char(';');
	}	
	
	if (bool(slowlock)) {
		slowlock->unlock();
	}

	rtscope.unlock();

	if (gy_unlikely(true == qbuf.is_overflow())) {
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Internal Error : Active Connections insert buffer overflow occured for %d listen and %d cli recs\n", nlisten, ncli);
		return {};
	}

	bret = PQsendQueryOptim(pconn->get(), qbuf.buffer(), qbuf.size());
	
	if (bret == false) {
		db_stats_.nactive_conns_failed_.fetch_add_relaxed(1);

		DEBUGEXECN(5,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to schedule DB query for Listener Active Conns updation due to %s\n", PQerrorMessage(pconn->get()));
		);

		return {};
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
				db_stats_.nactive_conns_failed_.fetch_add_relaxed(1);

				DEBUGEXECN(5,
					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to insert Active Conns into DB due to %s\n", gyres.get_error_msg());
				);

				return false;
			}	

			return true;
		}
	);

done1 :
	return {nlisten, ncli};
}	

std::pair<int, int> MCONN_HANDLER::insert_close_conn_records(PARTHA_INFO *prawpartha, time_t currtsec, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 10'000 /* max_msec_wait */, false /* reset_on_timeout */);
	
	if (!pconn) {
		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ncloseconn_failed_.fetch_add_relaxed(1);
		
		DEBUGEXECN(5,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get DB Conn for Partha %s Close Connection Records\n", prawpartha->hostname_);
		);
		return {};
	}	
	
	assert(gy_get_thread_local().get_thread_stack_freespace() > 850 * 1024);

	STRING_BUFFER<700 * 1028>	qbuf;
	auto				timebuf = gy_localtime_iso8601_sec(currtsec);
	const auto			datetbl = get_db_day_partition(currtsec, 30);
	auto				schemabuf = prawpartha->get_db_schema();
	int				nl = 0, nc = 0, nactdef = 0, nclidef = 0; 
	bool				bret, rtdefs, extact = false, extcli = false;
	
	SCOPE_GY_MUTEX			scopelock(&prawpartha->connlistenmutex_);

	SharedMutex::ReadHolder		rtscope(prawpartha->rtalerts_.adef_rwmutex_);

	nactdef = (int)prawpartha->rtalerts_.adef_activeconn_.size();
	nclidef = (int)prawpartha->rtalerts_.adef_clientconn_.size();

	/*
	 * We do not look up the Listener or Task structs as we directly write to DB. 
	 * But if Extended Active Conn or Client Conn Alerts are active, we need to pass the
	 * corresponding structs. Hence the following...
	 */
	std::optional<RCU_LOCK_SLOW>		slowlock;

	extact 	= !!prawpartha->rtalerts_.nextact_;
	extcli	= !!prawpartha->rtalerts_.nextcli_;

	if (extact || extcli) {
		slowlock.emplace();
	}	

	rtdefs = bool(nactdef + nclidef);

	if (prawpartha->connlistenmap_.size()) {	
	
		using ExtActMap			= INLINE_STACK_HASH_MAP<uint64_t, const MTCP_LISTENER *, 48 * 1024, GY_JHASHER<uint64_t>>;
		
		std::optional<ExtActMap>	actmap;
		size_t				currsz = qbuf.size();

		if (extact) {
			actmap.emplace();
		}	

		/*
		 * Records where no Client info available will have their partha id set as "00000000000000000000000000000000" and madhava id as "0000000000000000"
		 */
		qbuf.appendfmt("insert into %s.activeconntbl%s values ", schemabuf.get(), datetbl.get());

		for (const auto & elem : prawpartha->connlistenmap_) {
			const CONN_LISTEN_ONE 		& one = elem.second;

			for (const auto & celem : one.climap_) {
				const CONN_PEER_ONE		& cli = celem.second;
				
				if (rtdefs) {
					const MTCP_LISTENER		*plistener = nullptr;

					if (extact) {
						const uint64_t			glob_id = elem.first;
						auto				it = actmap->find(glob_id);

						if (it != actmap->end()) {
							plistener = it->second;
						}	
						else {
							uint32_t		lhash = get_uint64_hash(glob_id);
							auto			pdatanode = prawpartha->listen_tbl_.lookup_single_elem_locked(glob_id, lhash);

							if (pdatanode) {
								plistener = pdatanode->get_cref().get();

								if (plistener && actmap->size() < 512) {
									actmap->try_emplace(glob_id, plistener);
								}	
							}	
						}	
					}	

					const auto		& conn = cli.get_active_conn(elem.first, celem.first, one.ser_comm_, prawpartha->machine_id_);

					activeconn_rtalert_rwlocked(*prawpartha, conn, currtsec, timebuf.get(), plistener);
				}

				qbuf.appendfmt("(\'%s\',\'%016lx\',\'%s\',\'%016lx\',\'%s\',\'%016lx%016lx\',\'%016lx\',%ld,%ld,%d,%d,%.3f,%hd,%hhd::boolean),", 
					timebuf.get(), elem.first, one.ser_comm_, celem.first,
					cli.comm_, cli.remote_machine_id_.get_first(), cli.remote_machine_id_.get_second(), 
					cli.remote_madhava_id_, cli.bytes_sent_, cli.bytes_received_, 0, 0, 0.0, cli.nconns_, cli.cli_listener_proc_);
				nl++;
			}
		}


		if (nl > 0) {
			qbuf.set_last_char(';');
		}
		else {
			qbuf.truncate_to(currsz);
		}	
	}

	if (prawpartha->connclientmap_.size()) {
		using ExtCliMap			= INLINE_STACK_HASH_MAP<uint64_t, const MAGGR_TASK *, 48 * 1024, GY_JHASHER<uint64_t>>;

		std::optional<ExtCliMap>	climap;
		size_t				currsz = qbuf.size();

		if (extcli) {
			climap.emplace();
		}	

		/*
		 * Records where no Listener info available will have their partha id set as "00000000000000000000000000000000" and madhava id as "0000000000000000"
		 */
		qbuf.appendfmt("insert into %s.remoteconntbl%s values ", schemabuf.get(), datetbl.get());

		for (const auto & elem : prawpartha->connclientmap_) {
			const CONN_CLIENT_ONE 		& cli = elem.second;

			for (const auto & lelem : cli.listmap_) {
				const CONN_PEER_ONE 		& list = lelem.second;

				if (rtdefs) {
					const MAGGR_TASK		*ptask = nullptr;
					
					if (extcli) {
						auto			it = climap->find(elem.first);

						if (it != climap->end()) {
							ptask = it->second;
						}
						else {
							auto			pdatanode = prawpartha->task_aggr_tbl_.lookup_single_elem_locked(elem.first, 
																get_uint64_hash(elem.first));

							if (pdatanode) {
								ptask = pdatanode->get_cref().get();

								if (ptask && climap->size() < 512) {
									climap->try_emplace(elem.first, ptask);
								}	
							}
						}
					}	
			
					const auto		& conn = list.get_remote_conn(lelem.first, elem.first, cli.cli_comm_, cli.cli_listener_proc_);

					clientconn_rtalert_rwlocked(*prawpartha, conn, currtsec, timebuf.get(), ptask);
				}

				qbuf.appendfmt("(\'%s\',\'%016lx\',\'%s\',\'%016lx\',\'%s\',\'%016lx%016lx\',\'%016lx\',%ld,%ld,%hd,%hhd::boolean),", 
					timebuf.get(), elem.first, cli.cli_comm_, lelem.first, list.comm_, list.remote_machine_id_.get_first(), list.remote_machine_id_.get_second(),
					list.remote_madhava_id_, list.bytes_sent_, list.bytes_received_, list.nconns_, cli.cli_listener_proc_);
				nc++;
			}
		}

		if (nc > 0) {
			qbuf.set_last_char(';');
		}
		else {
			qbuf.truncate_to(currsz);
		}	
	}	
		
	if (bool(slowlock)) {
		slowlock->unlock();
	}

	rtscope.unlock();

	prawpartha->connlistenmap_.clear();
	prawpartha->connclientmap_.clear();
	prawpartha->connpeerarena_.reset();
	prawpartha->tdbconnlistensec_ = time(nullptr);

	scopelock.unlock();

	if (gy_unlikely(true == qbuf.is_overflow())) {
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Internal Error : Close Conn Records insert buffer overflow occured\n");
		return {};
	}

	bret = PQsendQueryOptim(pconn->get(), qbuf.buffer(), qbuf.size());
	
	if (bret == false) {
		db_stats_.ncloseconn_failed_.fetch_add_relaxed(1);

		DEBUGEXECN(5,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to schedule DB query to add Partha %s Close Conn Records due to %s\n", 
						prawpartha->hostname_, PQerrorMessage(pconn->get()));
		);

		return {};
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
				db_stats_.ncloseconn_failed_.fetch_add_relaxed(1);

				DEBUGEXECN(5,
					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to insert Partha Close Conn Records into DB due to %s\n", gyres.get_error_msg());
				);

				return false;
			}	

			return true;
		}
	);

	return {nl, nc};
}

bool MCONN_HANDLER::cleanup_remote_cli_tcp_conn(MADHAVA_INFO *pcli_madhava, uint64_t cli_task_aggr_id, uint64_t ser_glob_id, int nconns_closed) 
{
	assert(pcli_madhava);

	if (!cli_task_aggr_id || !ser_glob_id) {
		return false;
	}	
	
	const uint32_t			taskhash = get_uint64_hash(cli_task_aggr_id);
	const uint32_t			lhash = get_uint64_hash(ser_glob_id);
	
	auto lamtask = [=](MAGGR_TASK_ELEM_TYPE *pelem, void *arg1, void *arg2) -> CB_RET_E
	{	
		auto			pclitask = pelem->get_cref().get();
		bool			bret;

		if (gy_unlikely(nullptr == pclitask)) {
			return CB_DELETE_ELEM;
		}	

		pclitask->tcp_cli_in_use_.fetch_sub_relaxed_0(nconns_closed);

		auto lweak = [=](MWEAK_LISTEN_ID *pweaklisten, void *arg1, void *arg2) -> CB_RET_E
		{
			auto listenshr = pweaklisten->weaklisten_.lock();
			auto plistener = listenshr.get();

			if (plistener && plistener->is_remote_madhava_ == false) {
				auto tlam = [=](MAGGR_TASK_WEAK *pweaktask, void *arg1, void *arg2) -> CB_RET_E
				{
					int ntimes = pweaktask->ntimes_.fetch_sub_relaxed_0(nconns_closed);

					if (ntimes != 1) {
						return CB_OK;
					}
					else {
						return CB_DELETE_ELEM;
					}	
				};	

				plistener->cli_aggr_task_tbl_->lookup_single_elem(cli_task_aggr_id, taskhash, tlam);
			}
			else {
				return CB_DELETE_ELEM;
			}	

			int nold = pweaklisten->ntimes_.fetch_sub_relaxed_0(nconns_closed);

			if (nold != 1) {
				return CB_OK;
			}
			else {
				return CB_DELETE_ELEM;
			}	
		};	
		
		if (pclitask->remote_listener_tbl_) {
			bret = pclitask->remote_listener_tbl_->lookup_single_elem(ser_glob_id, lhash, lweak);
		}

		return CB_OK;
	};

	return pcli_madhava->task_aggr_tbl_.lookup_single_elem(cli_task_aggr_id, taskhash, lamtask);
}

bool MCONN_HANDLER::cleanup_local_cli_tcp_conn(PARTHA_INFO *prawpartha, uint64_t cli_task_aggr_id, uint64_t ser_glob_id, uint64_t ser_madhava_id, int nconns_closed) 
{
	if (!cli_task_aggr_id) {
		return false;
	}	
	
	const uint32_t			taskhash = get_uint64_hash(cli_task_aggr_id);
	uint32_t			lhash = get_uint64_hash(ser_glob_id);
	const bool			is_ser_remote_madhava = (ser_madhava_id != gmadhava_id_ && ser_madhava_id);
	
	auto lamtask = [=](MAGGR_TASK_ELEM_TYPE *pelem, void *arg1, void *arg2) -> CB_RET_E
	{	
		auto			pclitask = pelem->get_cref().get();
		bool			bret;

		if (gy_unlikely(nullptr == pclitask)) {
			return CB_DELETE_ELEM;
		}	

		pclitask->tcp_cli_in_use_.fetch_sub_relaxed_0(nconns_closed);

		if (ser_glob_id == 0) {
			return CB_OK;
		}	

		auto lweak = [=](MWEAK_LISTEN_ID *pweaklisten, void *arg1, void *arg2) -> CB_RET_E
		{
			if (is_ser_remote_madhava == false) {
				auto listenshr = pweaklisten->weaklisten_.lock();
				auto plistener = listenshr.get();

				if (plistener) {
					auto tlam = [=](MAGGR_TASK_WEAK *pweaktask, void *arg1, void *arg2) -> CB_RET_E
					{
						int ntimes = pweaktask->ntimes_.fetch_sub_relaxed_0(nconns_closed);

						if (ntimes != 1) {
							return CB_OK;
						}
						else {
							return CB_DELETE_ELEM;
						}	
					};	

					plistener->cli_aggr_task_tbl_->lookup_single_elem(cli_task_aggr_id, taskhash, tlam);
				}
				else {
					return CB_DELETE_ELEM;
				}	
			}

			int nold = pweaklisten->ntimes_.fetch_sub_relaxed_0(nconns_closed);

			if (nold != 1) {
				return CB_OK;
			}
			else {
				return CB_DELETE_ELEM;
			}	
		};	
		
		if (is_ser_remote_madhava == false) {
			if (pclitask->cli_listener_tbl_) {
				bret = pclitask->cli_listener_tbl_->lookup_single_elem(ser_glob_id, lhash, lweak);
			}	
		}
		else {
			if (pclitask->remote_listener_tbl_) {
				bret = pclitask->remote_listener_tbl_->lookup_single_elem(ser_glob_id, lhash, lweak);
			}
		}	

		return CB_OK;
	};

	return prawpartha->task_aggr_tbl_.lookup_single_elem(cli_task_aggr_id, taskhash, lamtask);
}	

// Returns true if a new task elem is added
bool MCONN_HANDLER::add_remote_conn_task_ref(MADHAVA_INFO *pcli_madhava, uint64_t aggr_task_id, GY_MACHINE_ID remote_machine_id, MTCP_LISTENER *plistener, const char *pcli_comm, uint32_t cli_cmdline_len, const char *pcli_cmdline, POOL_ALLOC_ARRAY *pthrpoolarr, uint64_t tusec_start)
{
	if (!aggr_task_id || !plistener || plistener->is_remote_madhava_) {
		return false;
	}	
	
	assert(pcli_madhava);

	RCU_DEFER_OFFLINE		deferlock;

	MAGGR_TASK_ELEM_TYPE		cli_task_elem;
	MAGGR_TASK			*pclitask = nullptr;
	MWEAK_LISTEN_TABLE		*plistentbl = nullptr;
	const uint32_t			taskhash = get_uint64_hash(aggr_task_id), madhash = get_uint64_hash(pcli_madhava->madhava_id_);
	bool				bret, newadd = false;
	FREE_FPTR			free_fp;
	uint32_t			act_size;
	
	auto lamtask = [&](MAGGR_TASK_ELEM_TYPE *pdatanode, void *arg1, void *arg2) -> CB_RET_E
	{
		// No need to increment Shared pointer as we will not be offlined
		pclitask = pdatanode->get_cref().get();
		return CB_OK;
	};	

	bret = pcli_madhava->task_aggr_tbl_.lookup_single_elem(aggr_task_id, taskhash, lamtask);

	if (nullptr == pclitask) {
		if (cli_cmdline_len && pcli_cmdline && pcli_comm) {

			pclitask = (MAGGR_TASK *)pthrpoolarr->safe_malloc(sizeof(MAGGR_TASK), free_fp, act_size, false /* try_other_pools */, true /* use_malloc_hdr */);

			// New Remote Task
			new (pclitask) MAGGR_TASK(aggr_task_id, pcli_comm, pcli_cmdline, remote_machine_id, pcli_madhava->weak_from_this(), 
							pcli_madhava->madhava_id_, cli_cmdline_len, tusec_start);

			MAGGR_TASK_ELEM_TYPE  *pmtaskelem = (MAGGR_TASK_ELEM_TYPE *)pthrpoolarr->safe_malloc(sizeof(MAGGR_TASK_ELEM_TYPE), free_fp, act_size, false, true);
			
			new (pmtaskelem) MAGGR_TASK_ELEM_TYPE(pclitask, TPOOL_DEALLOC<MAGGR_TASK>());

			auto palam = [&](MAGGR_TASK_ELEM_TYPE *poldelem, MAGGR_TASK_ELEM_TYPE *pnewelem)
			{
				pclitask	= poldelem->get_cref().get();
			};	
			
			bret = pcli_madhava->task_aggr_tbl_.insert_unique(pmtaskelem, aggr_task_id, taskhash, palam, true);

			if (bret == true) {	
				newadd = true;

				DEBUGEXECN(11,
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Adding new Remote Madhava Handled Task Aggr from TCP Conn"
						": Comm \'%s\' : from Remote Madhava %s for local Listener \'%s\'\n", 
						pcli_comm, pcli_madhava->get_domain(), plistener->comm_);
				);	
			}	
		}
		else {
			return false;
		}	
	}	

	pclitask->tcp_cli_in_use_.fetch_add_relaxed(1);

	const uint32_t			lhash = get_uint64_hash(plistener->glob_id_);

	auto lweak = [](MWEAK_LISTEN_ID *pweaklisten, void *arg1, void *arg2) -> CB_RET_E
	{
		pweaklisten->ntimes_.fetch_add_relaxed(1);

		return CB_OK;
	};	
	
	plistentbl = pclitask->get_remote_listener_table();

	bret = plistentbl->lookup_single_elem(plistener->glob_id_, lhash, lweak);
	if (bret == false) {
		MWEAK_LISTEN_ID		*pweaklisten;

		pweaklisten = new MWEAK_LISTEN_ID(plistener->weak_from_this(), plistener->glob_id_);

		auto newlam = [](MWEAK_LISTEN_ID *poldelem, MWEAK_LISTEN_ID *pnewelem)
		{
			poldelem->ntimes_.fetch_add_relaxed(1);
		};

		plistentbl->insert_unique(pweaklisten, plistener->glob_id_, lhash, newlam, true /* delete_after_callback */);
	}	

	auto tlam = [](MAGGR_TASK_WEAK *pweaktask, void *arg1, void *arg2) -> CB_RET_E
	{
		pweaktask->ntimes_.fetch_add_relaxed(1);

		return CB_OK;
	};	

	bret = plistener->cli_aggr_task_tbl_->lookup_single_elem(aggr_task_id, taskhash, tlam);

	if (bret == false) {
		MAGGR_TASK_WEAK		*pweaktask;

		pweaktask = (MAGGR_TASK_WEAK *)pthrpoolarr->safe_malloc(sizeof(MAGGR_TASK_WEAK), free_fp, act_size, false /* try_other_pools */, true /* use_malloc_hdr */);

		new (pweaktask) MAGGR_TASK_WEAK(pclitask->weak_from_this(), aggr_task_id);

		auto newlam = [](MAGGR_TASK_WEAK *poldelem, MAGGR_TASK_WEAK *pnewelem)
		{
			poldelem->ntimes_.fetch_add_relaxed(1);
		};

		plistener->cli_aggr_task_tbl_->insert_unique(pweaktask, aggr_task_id, taskhash, newlam, true /* delete_after_callback */);
	}	

	/*
	 * Add the remote Madhava reference within the listener
	 */
	auto tmad = [tusec_start](WEAK_REMOTE_MADHAVA *pweakmad, void *arg1, void *arg2) -> CB_RET_E
	{
		pweakmad->ntimes_.fetch_add_relaxed(1);
		pweakmad->tlast_usec_ = tusec_start;

		return CB_OK;
	};	

	bret = plistener->remote_madhava_tbl_->lookup_single_elem(pcli_madhava->madhava_id_, madhash, tmad);

	if (bret == false) {
		WEAK_REMOTE_MADHAVA		*pweakmad;

		pweakmad = (WEAK_REMOTE_MADHAVA *)pthrpoolarr->safe_malloc(sizeof(WEAK_REMOTE_MADHAVA), free_fp, act_size, false /* try_other_pools */, true /* use_malloc_hdr */);

		new (pweakmad) WEAK_REMOTE_MADHAVA(pcli_madhava->weak_from_this(), pcli_madhava->madhava_id_, tusec_start);

		auto newmad = [](WEAK_REMOTE_MADHAVA *poldelem, WEAK_REMOTE_MADHAVA *pnewelem)
		{
			poldelem->ntimes_.fetch_add_relaxed(1);
		};

		plistener->remote_madhava_tbl_->insert_unique(pweakmad, pcli_madhava->madhava_id_, madhash, newmad, true /* delete_after_callback */);
	}	

	return newadd;
}

// Returns true if a new task elem is added
bool MCONN_HANDLER::add_local_conn_task_ref(PARTHA_INFO *pcli_partha, uint64_t aggr_task_id, MTCP_LISTENER *plistener, const char *pcli_comm, uint32_t cli_cmdline_len, const char *pcli_cmdline, POOL_ALLOC_ARRAY *pthrpoolarr, uint64_t tusec_start)
{
	if (!aggr_task_id) {
		return false;
	}	
	
	assert(pcli_partha);

	RCU_DEFER_OFFLINE		deferlock;

	MAGGR_TASK			*pclitask = nullptr;
	MWEAK_LISTEN_TABLE		*plistentbl = nullptr;
	const uint32_t			taskhash = get_uint64_hash(aggr_task_id);
	bool				bret, newadd = false;
	FREE_FPTR			free_fp;
	uint32_t			act_size;
	
	auto lamtask = [&](MAGGR_TASK_ELEM_TYPE *pdatanode, void *arg1, void *arg2) -> CB_RET_E
	{
		// No need to increment Shared pointer as we will not be offlined
		pclitask = pdatanode->get_cref().get();
		return CB_OK;
	};	

	bret = pcli_partha->task_aggr_tbl_.lookup_single_elem(aggr_task_id, taskhash, lamtask);

	if (nullptr == pclitask) {
		if (cli_cmdline_len && pcli_cmdline && pcli_comm) {

			pclitask = (MAGGR_TASK *)pthrpoolarr->safe_malloc(sizeof(MAGGR_TASK), free_fp, act_size, false /* try_other_pools */, true /* use_malloc_hdr */);
			
			new (pclitask) MAGGR_TASK(aggr_task_id, pcli_comm, pcli_cmdline, pcli_partha->weak_from_this(), pcli_partha->machine_id_,
							gmadhava_weak_, gmadhava_id_, cli_cmdline_len, 0, "", 0, tusec_start);

			MAGGR_TASK_ELEM_TYPE *pmtaskelem = (MAGGR_TASK_ELEM_TYPE *)pthrpoolarr->safe_malloc(sizeof(MAGGR_TASK_ELEM_TYPE), free_fp, act_size, false, true);

			new (pmtaskelem) MAGGR_TASK_ELEM_TYPE(pclitask, TPOOL_DEALLOC<MAGGR_TASK>());

			auto palam = [&](MAGGR_TASK_ELEM_TYPE *poldelem, MAGGR_TASK_ELEM_TYPE *pnewelem)
			{
				pclitask	= poldelem->get_cref().get();
			};	
			
			bret = pcli_partha->task_aggr_tbl_.insert_unique(pmtaskelem, aggr_task_id, taskhash, palam, true);

			if (bret == true) {	
				DEBUGEXECN(10,
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Adding new Task Aggr from TCP Conn : Comm \'%s\' : from Partha : %s\n",
						pcli_comm, pcli_partha->print_string(STRING_BUFFER<256>().get_str_buf()));
				);	

				newadd = true;
			}	
		}
		else {
			DEBUGEXECN(5,
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_LIGHT_RED, 
					"Missed Adding TCP conn Task Reference as Task with comm \'%s\' from %s not present and inadequate data seen\n",
					pcli_comm, pcli_partha->print_string(STRING_BUFFER<256>().get_str_buf()));
			);	

			pcli_partha->cli_task_missed_++;
			return false;
		}	
	}	

	if (!plistener || !plistener->is_remote_madhava_)  {
		pclitask->tcp_cli_in_use_.fetch_add_relaxed(1);
	}

	if (!plistener) {
		return newadd;
	}	

	const uint32_t			lhash = get_uint64_hash(plistener->glob_id_);

	auto lweak = [](MWEAK_LISTEN_ID *pweaklisten, void *arg1, void *arg2) -> CB_RET_E
	{
		pweaklisten->ntimes_.fetch_add_relaxed(1);

		return CB_OK;
	};	
	
	if (plistener->is_remote_madhava_ == false) {
		plistentbl = pclitask->get_cli_listener_table();
	}
	else {
		plistentbl = pclitask->get_remote_listener_table();
	}	

	bret = plistentbl->lookup_single_elem(plistener->glob_id_, lhash, lweak);
	if (bret == false) {
		MWEAK_LISTEN_ID		*pweaklisten;

		pweaklisten = new MWEAK_LISTEN_ID(plistener->weak_from_this(), plistener->glob_id_);

		auto newlam = [](MWEAK_LISTEN_ID *poldelem, MWEAK_LISTEN_ID *pnewelem)
		{
			poldelem->ntimes_.fetch_add_relaxed(1);
		};

		plistentbl->insert_unique(pweaklisten, plistener->glob_id_, lhash, newlam, true /* delete_after_callback */);
	}	

	if (plistener->is_remote_madhava_ == false) {
		auto tlam = [](MAGGR_TASK_WEAK *pweaktask, void *arg1, void *arg2) -> CB_RET_E
		{
			pweaktask->ntimes_.fetch_add_relaxed(1);

			return CB_OK;
		};	

		bret = plistener->cli_aggr_task_tbl_->lookup_single_elem(aggr_task_id, taskhash, tlam);

		if (bret == false) {
			MAGGR_TASK_WEAK		*pweaktask;

			pweaktask = (MAGGR_TASK_WEAK *)pthrpoolarr->safe_malloc(sizeof(MAGGR_TASK_WEAK), free_fp, act_size, false /* try_other_pools */, true /* use_malloc_hdr */);

			new (pweaktask) MAGGR_TASK_WEAK(pclitask->weak_from_this(), aggr_task_id);

			auto newlam = [](MAGGR_TASK_WEAK *poldelem, MAGGR_TASK_WEAK *pnewelem)
			{
				poldelem->ntimes_.fetch_add_relaxed(1);
			};

			plistener->cli_aggr_task_tbl_->insert_unique(pweaktask, aggr_task_id, taskhash, newlam, true /* delete_after_callback */);
		}	
	}

	return newadd;
}	

// Returns {is_resolved, newconn, newtask}
std::tuple<bool, bool, bool> MCONN_HANDLER::add_tcp_conn_cli(const std::shared_ptr<PARTHA_INFO> & partha_shr, comm::TCP_CONN_NOTIFY *pone, uint64_t tcurrusec, MP_CLI_TCP_INFO_MAP & parclimap, MP_CLI_TCP_INFO_VEC_ARENA & parclivecarena, MP_SER_TCP_INFO_MAP & parsermap, MP_SER_TCP_INFO_VEC_ARENA & parservecarena, SER_UN_CLI_INFO_MAP & serunmap, SER_UN_CLI_INFO_VEC_ARENA & serunvecarena, POOL_ALLOC_ARRAY *pthrpoolarr) 
{
	/*
	 * We first check if the Server corresponding half connection is already present in the glob_tcp_conn_tbl_.
	 * We use the NAT Client/Server IP for lookup. We also update the partha_shr->task_aggr_tbl_ and 
	 * listener partha listen_tbl_ with the MAGGR_TASK_WEAK
	 */
	PARTHA_INFO			*prawpartha = partha_shr.get();

	if (!prawpartha) {
		return {};
	}	

	std::shared_ptr<MTCP_LISTENER>	listenshr;
	uint64_t			ser_cluster_hash = 0, ser_tusec_start = 0;
	uint32_t			ser_conn_hash = 0, ser_sock_inode = 0;
	bool				bret, conn_closed, updunmap = false;

	conn_closed = !!pone->tusec_close_;

	if (pone->is_loopback_conn_ || pone->is_pre_existing_) {

		if (!pone->cli_task_aggr_id_ || conn_closed) {
			return {};
		}	

		MTCP_LISTENER_ELEM_TYPE		*plistenelem = nullptr;

		if (pone->is_loopback_conn_ && pone->ser_glob_id_) {
			plistenelem = prawpartha->listen_tbl_.lookup_single_elem_locked(pone->ser_glob_id_, get_uint64_hash(pone->ser_glob_id_));
		}

		bret = add_local_conn_task_ref(prawpartha, pone->cli_task_aggr_id_, plistenelem ? plistenelem->get_cref().get() : nullptr,
						pone->cli_comm_, pone->cli_cmdline_len_, (const char *)(pone + 1), pthrpoolarr, tcurrusec);

		return {false, false, bret};
	}

	PAIR_IP_PORT			ctuple(pone->nat_cli_, pone->nat_ser_);
	const uint32_t			chash = ctuple.get_hash();

	auto lamtcp = [&](MTCP_CONN *ptcp, void *arg1, void *arg2) -> CB_RET_E
	{	
		/*
		 * Server half conn already updated. Just plumb the server global id and then add task refs
		 * and delete this conn. Its safe to move the ser_listen_shr_ as this conn will be updated only
		 * once and then deleted.
		 */
		listenshr		= std::move(ptcp->ser_listen_shr_);
		ser_tusec_start		= ptcp->tusec_start_;
		ser_conn_hash		= ptcp->ser_conn_hash_;
		ser_sock_inode		= ptcp->ser_sock_inode_;
		ser_cluster_hash	= ptcp->cli_ser_cluster_hash_;

		updunmap = ptcp->is_conn_closed();

		return CB_DELETE_ELEM;
	};	

	bret = glob_tcp_conn_tbl_.lookup_single_elem(ctuple, chash, lamtcp);

	if (!listenshr) {
		if (conn_closed) {
			if (glob_tcp_conn_tbl_.approx_count_fast() > MAX_UNRESOLVED_TCP_CONNS) {
				return {};
			}	
		}

		MTCP_CONN		*ptcp;
		FREE_FPTR		free_fp;
		uint32_t		act_size;
		
		ptcp = (MTCP_CONN *)pthrpoolarr->safe_malloc(sizeof(MTCP_CONN), free_fp, act_size, false /* try_other_pools */, true /* use_malloc_hdr */);
		new (ptcp) MTCP_CONN();

		ptcp->cli_			= pone->cli_;
		ptcp->ser_			= pone->ser_;

		ptcp->cli_nat_cli_		= pone->nat_cli_;
		ptcp->cli_nat_ser_		= pone->nat_ser_;

		ptcp->cli_shr_host_		= partha_shr;
		ptcp->cli_task_aggr_id_		= pone->cli_task_aggr_id_;
		ptcp->cli_related_listen_id_	= pone->cli_related_listen_id_;
		ptcp->cli_pid_			= pone->cli_pid_;

		ptcp->cli_ser_cluster_hash_	= prawpartha->cluster_hash_;
		
		GY_STRNCPY(ptcp->cli_comm_, pone->cli_comm_, sizeof(ptcp->cli_comm_));
		
		if (pone->cli_cmdline_len_ > 1) {
			ptcp->cli_cmdline_.assign((const char *)(pone + 1), pone->cli_cmdline_len_ - 1);
		}	

		if (conn_closed) {
			ptcp->close_cli_bytes_sent_	= pone->bytes_sent_;
			ptcp->close_cli_bytes_rcvd_	= pone->bytes_rcvd_;
		}

		ptcp->tusec_start_		= tcurrusec;

		CONDEXEC(
			DEBUGEXECN(10,
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_MAGENTA, "Adding %s Client side TCP conn : NAT Tuple %s : Original Client %s Server %s from Client Comm \'%s\' and %s\n",
					conn_closed ? "closed" : "new", ctuple.print_string(STRING_BUFFER<256>().get_str_buf()), ptcp->cli_.print_string(STRING_BUFFER<128>().get_str_buf()),
					ptcp->ser_.print_string(STRING_BUFFER<128>().get_str_buf()), ptcp->cli_comm_, 
					prawpartha->print_string(STRING_BUFFER<128>().get_str_buf()));
			);
		);

		auto newlam = [&](MTCP_CONN *poldelem, MTCP_CONN *pnewelem)
		{
			lamtcp(poldelem, nullptr, nullptr);
		};

		bret = glob_tcp_conn_tbl_.insert_unique(ptcp, ctuple, chash, newlam, true /* delete_after_callback */);
		if (bret == false) {
			glob_tcp_conn_tbl_.delete_single_elem(ctuple, chash);
		}	
	}

	if (listenshr) {
		auto				plistener = listenshr.get();

		bret = false;

		// Update pone with the resolved entries
		pone->ser_glob_id_ = plistener->glob_id_;
		pone->cli_ser_machine_id_ = plistener->partha_machine_id_;
		pone->ser_related_listen_id_ = plistener->related_listen_id_;
		pone->ser_madhava_id_ = gmadhava_id_;

		if (!conn_closed) {

			PAIR_IP_PORT		corigtup(pone->cli_, pone->ser_);

			auto 			[it, success] = parclimap.try_emplace(partha_shr, parclivecarena);
			auto 			& parclivec = it->second;

			parclivec.emplace_back(corigtup, plistener->partha_machine_id_, plistener->glob_id_, gmadhava_id_, plistener->related_listen_id_, ser_cluster_hash != prawpartha->cluster_hash_,
						plistener->comm_);

			bret = add_local_conn_task_ref(prawpartha, pone->cli_task_aggr_id_, plistener, pone->cli_comm_, pone->cli_cmdline_len_, (const char *)(pone + 1), pthrpoolarr, tcurrusec);

			if (plistener->parthashr_) {
				auto 			[sit, ssuccess] = parsermap.try_emplace(plistener->parthashr_, parservecarena);
				auto 			& parservec = sit->second;

				parservec.emplace_back(prawpartha->machine_id_, pone->cli_task_aggr_id_, gmadhava_id_, pone->cli_related_listen_id_, 
							pone->cli_comm_, corigtup.ser_, ser_conn_hash, ser_sock_inode);
			}
		}
		else if (updunmap && plistener->parthashr_) {
			auto 			[sit, ssuccess] = serunmap.try_emplace(plistener->parthashr_, serunvecarena);
			auto 			& serunvec = sit->second;

			serunvec.emplace_back(ser_tusec_start/GY_USEC_PER_SEC, plistener->glob_id_, plistener->comm_, pone->cli_task_aggr_id_, pone->cli_related_listen_id_,
						pone->cli_comm_, prawpartha->machine_id_, pone->bytes_sent_, pone->bytes_rcvd_, gmadhava_id_);
		}	

		return {true, false, bret};
	}	
	else {
		if (conn_closed) {
			return {};
		}

		// Add the entry to the local task list
		bret = add_local_conn_task_ref(prawpartha, pone->cli_task_aggr_id_, nullptr, pone->cli_comm_, pone->cli_cmdline_len_, (const char *)(pone + 1), pthrpoolarr, tcurrusec);

		return {false, true, bret};
	}	
}	

std::tuple<bool, bool, bool> MCONN_HANDLER::add_tcp_conn_ser(const std::shared_ptr<PARTHA_INFO> & partha_shr, comm::TCP_CONN_NOTIFY *pone, uint64_t tcurrusec, MP_CLI_TCP_INFO_MAP & parclimap, MP_CLI_TCP_INFO_VEC_ARENA & parclivecarena, MP_SER_TCP_INFO_MAP & parsermap, MP_SER_TCP_INFO_VEC_ARENA & parservecarena, CLI_UN_SERV_INFO_MAP & cliunmap, CLI_UN_SERV_INFO_VEC_ARENA & cliunvecarena, POOL_ALLOC_ARRAY *pthrpoolarr) 
{
	PARTHA_INFO			*prawpartha = partha_shr.get();

	if (gy_unlikely(!prawpartha || pone->is_loopback_conn_ || !pone->ser_glob_id_ || pone->cli_task_aggr_id_ || pone->is_pre_existing_)) {
		return {};
	}	

	/*
	 * We first check if the Client corresponding half connection is already present in the glob_tcp_conn_tbl_.
	 * We use the Original Client/Server IP for lookup.
	 */
	 
	bool				bret, conn_closed = !!pone->tusec_close_, updunmap = false;
	MTCP_LISTENER_ELEM_TYPE		*plistenelem;

	plistenelem = prawpartha->listen_tbl_.lookup_single_elem_locked(pone->ser_glob_id_, get_uint64_hash(pone->ser_glob_id_));
	
	if (!plistenelem) {
		return {};
	}


	auto				plistener = plistenelem->get_cref().get();
	PAIR_IP_PORT			stuple(pone->cli_, pone->ser_), corigtup;
	const uint32_t			shash = stuple.get_hash();

	uint64_t			cli_task_aggr_id = 0, cli_related_listen_id = 0, cli_cluster_hash = 0, cli_tusec_start = 0;
	std::shared_ptr <PARTHA_INFO>	cli_shr_host;
	char				cli_comm[TASK_COMM_LEN], cli_cmdline[comm::MAX_PROC_CMDLINE_LEN];
	uint32_t			cli_cmdline_len = 0;

	*cli_comm 	= 0;
	*cli_cmdline	= 0;

	auto lamtcp = [&](MTCP_CONN *ptcp, void *arg1, void *arg2) -> CB_RET_E
	{	
		/*
		 * Client half conn already updated. Just plumb the task id and then add task refs
		 * and delete this conn
		 */
		corigtup		= {ptcp->cli_, ptcp->ser_}; 
		cli_tusec_start		= ptcp->tusec_start_;
		cli_shr_host		= std::move(ptcp->cli_shr_host_);
		cli_task_aggr_id 	= ptcp->cli_task_aggr_id_;
		cli_related_listen_id	= ptcp->cli_related_listen_id_;
		cli_cluster_hash	= ptcp->cli_ser_cluster_hash_;
		
		GY_STRNCPY(cli_comm, ptcp->cli_comm_, sizeof(cli_comm));

		auto			sz = ptcp->cli_cmdline_.size();

		if (sz) {
			GY_STRNCPY(cli_cmdline, ptcp->cli_cmdline_.data(), sizeof(cli_cmdline));
			cli_cmdline_len = sz;
		}
		else {
			*cli_cmdline 	= 0;
			cli_cmdline_len = 0;
		}	

		updunmap = ptcp->is_conn_closed();

		return CB_DELETE_ELEM;
	};	

	bret = glob_tcp_conn_tbl_.lookup_single_elem(stuple, shash, lamtcp);

	if (!cli_shr_host) {
		if (conn_closed) {
			if (glob_tcp_conn_tbl_.approx_count_fast() > MAX_UNRESOLVED_TCP_CONNS) {
				return {};
			}	
		}
		
		MTCP_CONN		*ptcp;
		FREE_FPTR		free_fp;
		uint32_t		act_size;
		
		ptcp = (MTCP_CONN *)pthrpoolarr->safe_malloc(sizeof(MTCP_CONN), free_fp, act_size, false /* try_other_pools */, true /* use_malloc_hdr */);
		new (ptcp) MTCP_CONN();

		ptcp->cli_		= pone->cli_;
		ptcp->ser_		= pone->ser_;

		// Set the cli_nat_cli_ and cli_nat_ser_ as these are the keys of the elem
		ptcp->cli_nat_cli_	= pone->cli_;
		ptcp->cli_nat_ser_	= pone->ser_;

		ptcp->ser_nat_cli_	= pone->nat_cli_;
		ptcp->ser_nat_ser_	= pone->nat_ser_;

		ptcp->ser_glob_id_	= pone->ser_glob_id_;
		ptcp->ser_listen_shr_	= plistenelem->get_cref();
		ptcp->ser_pid_		= pone->ser_pid_;
		ptcp->ser_conn_hash_	= pone->ser_conn_hash_;
		ptcp->ser_sock_inode_	= pone->ser_sock_inode_;
		
		GY_STRNCPY(ptcp->ser_comm_, pone->ser_comm_, sizeof(ptcp->ser_comm_));

		ptcp->cli_ser_cluster_hash_	= prawpartha->cluster_hash_;

		if (conn_closed) {
			ptcp->close_cli_bytes_sent_	= pone->bytes_sent_;
			ptcp->close_cli_bytes_rcvd_	= pone->bytes_rcvd_;
		}

		ptcp->tusec_start_		= tcurrusec;

		CONDEXEC(
			DEBUGEXECN(10,
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_MAGENTA, "Adding %s Server side TCP conn : Tuple %s : NAT Client %s Server %s from Server comm \'%s\' and %s\n",
					conn_closed ? "closed" : "new", stuple.print_string(STRING_BUFFER<256>().get_str_buf()), 
					ptcp->ser_nat_cli_.print_string(STRING_BUFFER<128>().get_str_buf()), ptcp->ser_nat_ser_.print_string(STRING_BUFFER<128>().get_str_buf()), 
					ptcp->ser_comm_, prawpartha->print_string(STRING_BUFFER<128>().get_str_buf()));
			);
		);

		auto newlam = [&](MTCP_CONN *poldelem, MTCP_CONN *pnewelem)
		{
			lamtcp(poldelem, nullptr, nullptr);
		};

		bret = glob_tcp_conn_tbl_.insert_unique(ptcp, stuple, shash, newlam, true /* delete_after_callback */);
		if (bret == false) {
			glob_tcp_conn_tbl_.delete_single_elem(stuple, shash);
		}	
	}

	if (cli_shr_host && cli_task_aggr_id && plistener) {
		auto			pclihost = cli_shr_host.get();	

		bret = false;

		// Update pone with the resolved entries
		pone->cli_task_aggr_id_ = cli_task_aggr_id;
		pone->cli_ser_machine_id_ = pclihost->machine_id_;
		pone->cli_related_listen_id_ = cli_related_listen_id;
		pone->cli_madhava_id_ = gmadhava_id_;


		if (!conn_closed) {
			auto 			[it, success] = parclimap.try_emplace(std::move(cli_shr_host), parclivecarena);
			auto 			& parclivec = it->second;

			parclivec.emplace_back(corigtup, plistener->partha_machine_id_, plistener->glob_id_, gmadhava_id_, plistener->related_listen_id_, prawpartha->cluster_hash_ != cli_cluster_hash,
				plistener->comm_);

			bret = add_local_conn_task_ref(pclihost, cli_task_aggr_id, plistener, cli_comm, cli_cmdline_len, cli_cmdline, pthrpoolarr, tcurrusec);

			auto 			[sit, ssuccess] = parsermap.try_emplace(partha_shr, parservecarena);
			auto 			& parservec = sit->second;

			parservec.emplace_back(pclihost->machine_id_, cli_task_aggr_id, gmadhava_id_, cli_related_listen_id, cli_comm, corigtup.ser_, pone->ser_conn_hash_, pone->ser_sock_inode_);
		}
		else if (updunmap) {
			auto 			[sit, ssuccess] = cliunmap.try_emplace(std::move(cli_shr_host), cliunvecarena);
			auto 			& cliunvec = sit->second;

			cliunvec.emplace_back(cli_tusec_start/GY_USEC_PER_SEC, cli_task_aggr_id, cli_comm, cli_related_listen_id, 
						plistener->glob_id_, plistener->related_listen_id_, plistener->comm_, plistener->partha_machine_id_, pone->bytes_sent_, pone->bytes_rcvd_,
						gmadhava_id_);
		}	

		return {true, false, bret};
	}	

	return {false, true, false};
}	

bool MCONN_HANDLER::partha_tcp_conn_info(const std::shared_ptr<PARTHA_INFO> & partha_shr, comm::TCP_CONN_NOTIFY *pone, int nconns, uint8_t *pendptr, POOL_ALLOC_ARRAY *pthrpoolarr)
{
	PARTHA_INFO 			*prawpartha = partha_shr.get(); 

	if (!prawpartha) {
		return false;
	}

	/*
	 * We create entries in glob_tcp_conn_tbl_ till we can plumb the client and server side. Once the end to end connection is in place,
	 * we send the Listener ID to the client side and create references to client task in Listener object. No info is sent to the 
	 * Listener side partha.
	 *
	 * Stack based Maps/Vectors used as intermediate stores
	 */

	using Cleanupmap 		= INLINE_STACK_HASH_MAP<std::tuple<uint64_t, uint64_t, uint64_t>, int, 24 * 1024, GY_JHASHER<std::tuple<uint64_t, uint64_t, uint64_t>, true>>;

	using RemCliMap			= GY_STACK_HASH_MAP<std::pair<uint64_t, uint64_t>, int, 16 * 1024, GY_JHASHER<std::pair<uint64_t, uint64_t>, true>>;
	using RemCliMapArena		= RemCliMap::allocator_type::arena_type;
	using RemCliCloseMap		= INLINE_STACK_HASH_MAP<uint64_t, RemCliMap, 4096, GY_JHASHER<uint64_t>>;

	using MSVec			= GY_STACK_VECTOR<comm::MS_TCP_CONN_CLOSE, 16 * 1024>;
	using MSVecArena		= MSVec::allocator_type::arena_type;

	Cleanupmap			cleanupmap;
	RemCliMapArena			remclimaparena;	
	RemCliCloseMap			remcliclosemap;

	MP_CLI_TCP_INFO_VEC_ARENA	parclivecarena;
	MP_CLI_TCP_INFO_MAP_ARENA	parclimaparena;
	MP_CLI_TCP_INFO_MAP		parclimap(parclimaparena);
	MP_SER_TCP_INFO_VEC_ARENA	parservecarena;
	MP_SER_TCP_INFO_MAP_ARENA	parsermaparena;
	MP_SER_TCP_INFO_MAP		parsermap(parsermaparena);

	CLI_UN_SERV_INFO_VEC_ARENA	cliunvecarena;
	CLI_UN_SERV_INFO_MAP_ARENA	cliunmaparena;
	CLI_UN_SERV_INFO_MAP		cliunmap(cliunmaparena);
	SER_UN_CLI_INFO_VEC_ARENA	serunvecarena;
	SER_UN_CLI_INFO_MAP_ARENA	serunmaparena;
	SER_UN_CLI_INFO_MAP		serunmap(serunmaparena);

	MSVecArena			msveccleanuparena;
	MSVec				msveccleanup(msveccleanuparena);

	assert(gy_get_thread_local().get_thread_stack_freespace() > 100 * 1024);

	SCOPE_GY_MUTEX			scopelock(&prawpartha->connlistenmutex_);

	RCU_LOCK_SLOW			slowlock;

	const uint64_t			tusec_start = get_usec_time(), tsec_start = tusec_start/GY_USEC_PER_SEC, local_madid = gmadhava_id_;
	int				nnew = 0, nclosed = 0, nclosed_no_not = 0, ncloseadded = 0, nconnadded = 0, ntaskadded = 0, nremmadhav = 0, nparcliinfo = 0, nparserinfo = 0;
	int				ncliuninfo = 0, nseruninfo = 0;
	const bool			multi_madhava = multiple_madhava_active();
	bool				conn_closed, tcupdated = false;
	auto				& cunknown = prawpartha->get_curr_unknown_locked(tsec_start, true /* reset_old */);
	
	if (prawpartha->tconnlistensec_ < (int64_t)tsec_start - 60) {
		prawpartha->connlistenmap_.clear();
		prawpartha->connclientmap_.clear();
		prawpartha->connpeerarena_.reset();
	}

	auto lamtcpc = [](MTCP_CONN *ptcp, void *arg1, void *arg2) -> CB_RET_E
	{	
		auto			*ptmp = (const comm::TCP_CONN_NOTIFY *)arg1;

		if (ptcp && ptmp) {
			ptcp->close_cli_bytes_sent_ = ptmp->bytes_sent_;
			ptcp->close_cli_bytes_rcvd_ = ptmp->bytes_rcvd_;
		}

		return CB_OK;
	};	


	for (int i = 0; i < nconns && (uint8_t *)pone < pendptr; ++i, pone = (decltype(pone))((uint8_t *)pone + pone->get_elem_size())) {
		conn_closed = !!pone->tusec_close_;

		if (conn_closed) {
			nclosed++;

			if (false == pone->notified_before_) {
				nclosed_no_not++;
			}	
			else {
				if (pone->cli_task_aggr_id_ && pone->ser_glob_id_) {
					if (pone->is_tcp_connect_event_) {
						cleanupmap[std::make_tuple(pone->cli_task_aggr_id_, pone->ser_glob_id_, pone->ser_madhava_id_)]++;
					}
					else if (pone->cli_madhava_id_ != local_madid && pone->cli_madhava_id_) {
						auto 		[it, success] = remcliclosemap.try_emplace(pone->cli_madhava_id_, remclimaparena);
						auto 		& rmap = it->second;

						rmap[std::make_pair(pone->cli_task_aggr_id_, pone->ser_glob_id_)]++;
					}	
					else {
						// We wait for the Client partha to send in its data to update in memory structs
					}	
				}
				else if (!pone->is_loopback_conn_ && !pone->is_pre_existing_) {
					// We check only for recently started connections
					bool			bret = true;

					if (pone->cli_task_aggr_id_) {
						cleanupmap[std::make_tuple(pone->cli_task_aggr_id_, 0ul, 0ul)]++;
					}	

					if (pone->tusec_start_ > tusec_start - 50 * GY_USEC_PER_SEC) {
						if (pone->is_tcp_connect_event_) {
							PAIR_IP_PORT		ctuple(pone->nat_cli_, pone->nat_ser_);
							uint32_t		chash = ctuple.get_hash();

							bret = glob_tcp_conn_tbl_.lookup_single_elem(ctuple, chash, lamtcpc, pone);
							// Only send shyama conn close msg for listener conns
						}	
						else {
							PAIR_IP_PORT		stuple(pone->cli_, pone->ser_);
							uint32_t		shash = stuple.get_hash();

							bret = glob_tcp_conn_tbl_.lookup_single_elem(stuple, shash, lamtcpc, pone);
							if (bret == false && multi_madhava) {
								msveccleanup.emplace_back(stuple, pone->bytes_sent_, pone->bytes_rcvd_);
							}	
						}
					}
				}	
			}	

			if (pone->bytes_sent_ + pone->bytes_rcvd_ > 0) {
				bool			connpeer = true;

				if ( !(pone->notified_before_ || (pone->cli_task_aggr_id_ && pone->ser_glob_id_) || pone->is_loopback_conn_ || pone->is_pre_existing_) ) {
					if (pone->is_tcp_connect_event_) {
						if (cunknown.cliunsermap_.bytes_left() > 2 * sizeof(CONN_PEER_UNKNOWN)) {

							auto [is_resolved, newconn, newtask] = add_tcp_conn_cli(partha_shr, pone, tusec_start, 
											parclimap, parclivecarena, parsermap, parservecarena, serunmap, serunvecarena, pthrpoolarr);
							
							connpeer = (is_resolved || !newconn);

							if (newconn) {
								auto 			[cit, cret] = cunknown.cliunsermap_.try_emplace(pone->cli_task_aggr_id_);
								auto 			& clione = cit->second;

								clione.bytes_sent_ 	+= pone->bytes_sent_;
								clione.bytes_received_	+= pone->bytes_rcvd_;
								clione.nconns_++;
							
								nconnadded++;
								ncloseadded++;

								if (!tcupdated) {
									tcupdated = true;
									prawpartha->tconnlistensec_ = tsec_start;
								}
							}	
						}
					}	
					else {
						if (cunknown.serunclimap_.bytes_left() > 2 * sizeof(CONN_PEER_UNKNOWN)) {
							auto [is_resolved, newconn, newtask] = add_tcp_conn_ser(partha_shr, pone, tusec_start, 
											parclimap, parclivecarena, parsermap, parservecarena, cliunmap, cliunvecarena, pthrpoolarr);

							connpeer = (is_resolved || !newconn);

							if (newconn) {
								auto 			[cit, cret] = cunknown.serunclimap_.try_emplace(pone->ser_glob_id_);
								auto 			& clione = cit->second;

								clione.bytes_sent_ 	+= pone->bytes_sent_;
								clione.bytes_received_	+= pone->bytes_rcvd_;
								clione.nconns_++;
							
								nconnadded++;
								ncloseadded++;

								if (!tcupdated) {
									tcupdated = true;
									prawpartha->tconnlistensec_ = tsec_start;
								}
							}
						}
					}	
				}

				if (connpeer) {
					if (pone->ser_glob_id_ && pone->is_tcp_accept_event_) {
						if (prawpartha->connpeerarena_.bytes_left() > 2 * sizeof(CONN_PEER_ONE) && prawpartha->connlistenmap_.size() < MAX_CLOSE_CONN_ELEM - 1) {
							auto [sit, sret] = prawpartha->connlistenmap_.try_emplace(pone->ser_glob_id_, pone->ser_comm_, prawpartha->connpeerarena_);
							auto & climap = sit->second.climap_;

							auto [cit, cret] = climap.try_emplace(pone->cli_task_aggr_id_, pone->cli_comm_, pone->cli_ser_machine_id_, pone->cli_madhava_id_);
							auto & clione = cit->second;

							clione.bytes_sent_ 	+= pone->bytes_sent_;
							clione.bytes_received_	+= pone->bytes_rcvd_;

							clione.nconns_++;
							clione.cli_listener_proc_ |= (!!pone->cli_related_listen_id_);

							if (!tcupdated) {
								tcupdated = true;
								prawpartha->tconnlistensec_ = tsec_start;
							}
						}
					}	
					else if (false == pone->is_tcp_accept_event_ && pone->is_tcp_connect_event_ && pone->cli_task_aggr_id_) {
						if (prawpartha->connpeerarena_.bytes_left() > 2 * sizeof(CONN_PEER_ONE) && prawpartha->connclientmap_.size() < MAX_CLOSE_CONN_ELEM - 1) {

							auto [sit, sret] = prawpartha->connclientmap_.try_emplace(pone->cli_task_aggr_id_, 
												pone->cli_comm_, !!pone->cli_related_listen_id_, prawpartha->connpeerarena_);
							auto & listmap = sit->second.listmap_;

							auto [cit, cret] = listmap.try_emplace(pone->ser_glob_id_, pone->ser_comm_, pone->cli_ser_machine_id_, pone->ser_madhava_id_);
							auto & listone = cit->second;

							listone.bytes_sent_ 	+= pone->bytes_sent_;
							listone.bytes_received_	+= pone->bytes_rcvd_;

							listone.nconns_++;

							if (!tcupdated) {
								tcupdated = true;
								prawpartha->tconnlistensec_ = tsec_start;
							}
						}	
					}	
				}
			}
		}
		else {
			nnew++;

			if (pone->is_tcp_connect_event_) {
				auto [is_resolved, newconn, newtask] = add_tcp_conn_cli(partha_shr, pone, tusec_start, parclimap, parclivecarena, 
										parsermap, parservecarena, serunmap, serunvecarena, pthrpoolarr);

				nconnadded += int(newconn);
				ntaskadded += int(newtask);
			}	
			else {
				auto [is_resolved, newconn, newtask] = add_tcp_conn_ser(partha_shr, pone, tusec_start, parclimap, parclivecarena, 
										parsermap, parservecarena, cliunmap, cliunvecarena, pthrpoolarr);

				nconnadded += int(newconn);
				ntaskadded += int(newtask);
			}	
		}	
	}	

	scopelock.unlock();

	if (cleanupmap.size()) {
		uint64_t		cli_task_aggr_id, ser_glob_id, madhava_id;
		int			nconns_closed;

		for (const auto & elem : cleanupmap) {

			cli_task_aggr_id 	= std::get<0>(elem.first);
			ser_glob_id		= std::get<1>(elem.first);
			madhava_id 		= std::get<2>(elem.first);
			nconns_closed		= elem.second;

			cleanup_local_cli_tcp_conn(prawpartha, cli_task_aggr_id, ser_glob_id, madhava_id, nconns_closed);
		}
	}	

	if (remcliclosemap.size()) {
		uint64_t		cli_task_aggr_id, ser_glob_id, madhava_id;
		int			nconns_closed;
		bool			is_valid;

		for (const auto & relem : remcliclosemap) {
			uint64_t		madhava_id = relem.first;

			const auto 		pnode = madhava_tbl_.lookup_single_elem_locked(madhava_id, get_uint64_hash(madhava_id));

			if (gy_unlikely(nullptr == pnode)) {
				continue;
			}	

			auto			pmad = pnode->get_cref().get();
			if (!pmad) {
				continue;
			}	

			const auto		& cmap = relem.second;
			
			for (const auto & elem : cmap) {	
				cli_task_aggr_id 	= elem.first.first;
				ser_glob_id		= elem.first.second;
				nconns_closed		= elem.second;

				cleanup_remote_cli_tcp_conn(pmad, cli_task_aggr_id, ser_glob_id, nconns_closed);
			}
		}
	}	

	// Now RCU Offline the thread
	slowlock.unlock();

	ncliuninfo = upd_cli_ser_unknown_conns(cliunmap);
	nseruninfo = upd_ser_cli_unknown_conns(serunmap);

	for (const auto & epair : parclimap) {
		const auto & parshr	= epair.first;
		const auto & parclivec	= epair.second;

		if (!parshr || parclivec.empty()) {
			continue;
		}

		DEBUGEXECN(5,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Sending %lu TCP Conn Listener Info Messages to Client Partha %s\n",
				parclivec.size(), parshr->print_string(STRING_BUFFER<256>().get_str_buf()));
		);

		nparcliinfo += parclivec.size();

		send_mp_cli_tcp_info(parshr.get(), parclivec.data(), parclivec.size(), pthrpoolarr);
	}	

	for (const auto & epair : parsermap) {
		const auto & parshr	= epair.first;
		const auto & parservec	= epair.second;

		if (!parshr || parservec.empty()) {
			continue;
		}

		DEBUGEXECN(5,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Sending %lu TCP Conn Remote Client Info Messages to Server Partha %s\n",
				parservec.size(), parshr->print_string(STRING_BUFFER<256>().get_str_buf()));
		);

		nparserinfo += parservec.size();

		send_mp_ser_tcp_info(parshr.get(), parservec.data(), parservec.size(), pthrpoolarr);
	}	

	DEBUGEXECN(1, 
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_CYAN, "Partha Host \'%s\' has seen %d new TCP Conns, %d closed, %d closed without notify, %d closed conns added, "
			"%d half conns added, %d tasks added, %d Client close conns updated, %d Server close conns updated, %d remote madhava informs, "
			"%d Partha Cli Conn Infos sent, %d Partha Ser Conn Infos sent, %lu Shyama conn close sent\n", 
			prawpartha->hostname_, nnew, nclosed, nclosed_no_not, ncloseadded, nconnadded, ntaskadded, ncliuninfo, nseruninfo,
			nremmadhav, nparcliinfo, nparserinfo, msveccleanup.size());
	);

	return true;
}

int MCONN_HANDLER::upd_cli_ser_unknown_conns(CLI_UN_SERV_INFO_MAP & cliunmap)
{
	int			nupd = 0;

	for (const auto & epair : cliunmap) {
		const auto & clishr	= epair.first;
		const auto & clivec	= epair.second;

		if (!clishr || clivec.empty()) {
			continue;
		}

		DEBUGEXECN(10,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Signalling %lu Closed TCP Conn Resolve for unknown listeners to Partha %s\n",
				clivec.size(), clishr->print_string(STRING_BUFFER<256>().get_str_buf()));
		);

		SCOPE_GY_MUTEX			scopelock(clishr->connlistenmutex_);
		int				n = 0;
		
		for (const auto & obj : clivec) {
			auto			*pcunknown = clishr->get_curr_unknown_locked(obj.tstart_);
			
			if (!pcunknown) {
				continue;
			}

			if (clishr->connpeerarena_.bytes_left() > 2 * sizeof(CONN_PEER_ONE) && clishr->connclientmap_.size() < MAX_CLOSE_CONN_ELEM - 1) {

				if (auto sit = pcunknown->cliunsermap_.find(obj.cli_task_aggr_id_); sit != pcunknown->cliunsermap_.end()) {
					auto 			& clione = sit->second;
					auto 			[it, sret] = clishr->connclientmap_.try_emplace(obj.cli_task_aggr_id_, 
											obj.cli_comm_, !!obj.cli_related_listen_id_, clishr->connpeerarena_);
					auto 			& listmap = it->second.listmap_;

					auto 			[cit, cret] = listmap.try_emplace(obj.ser_glob_id_, obj.ser_comm_, obj.ser_partha_machine_id_, obj.ser_madhava_id_);
					auto 			& listone = cit->second;

					if (clione.bytes_sent_ >= obj.close_cli_bytes_sent_) 		clione.bytes_sent_	-= obj.close_cli_bytes_sent_;
					if (clione.bytes_received_ >= obj.close_cli_bytes_rcvd_) 	clione.bytes_received_	-= obj.close_cli_bytes_rcvd_;
					if (clione.nconns_ > 0) 					clione.nconns_--;

					listone.bytes_sent_ 	+= obj.close_cli_bytes_sent_;
					listone.bytes_received_	+= obj.close_cli_bytes_rcvd_;
					listone.nconns_++;

					n++;
				}

			}	
			else {
				break;
			}	
		}	

		if (n > 0) {
			clishr->tconnlistensec_ = time(nullptr);
			nupd += n;
		}
	}	

	return nupd;
}	

int MCONN_HANDLER::upd_ser_cli_unknown_conns(SER_UN_CLI_INFO_MAP & serunmap)
{
	int			nupd = 0;

	for (const auto & epair : serunmap) {
		const auto & sershr	= epair.first;
		const auto & servec	= epair.second;

		if (!sershr || servec.empty()) {
			continue;
		}

		DEBUGEXECN(10,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Signalling %lu Closed TCP Conn Resolve for unknown client to Partha %s\n",
				servec.size(), sershr->print_string(STRING_BUFFER<256>().get_str_buf()));
		);

		SCOPE_GY_MUTEX			scopelock(sershr->connlistenmutex_);
		int				n = 0;
		
		for (const auto & obj : servec) {
			auto			*pcunknown = sershr->get_curr_unknown_locked(obj.tstart_);
			
			if (!pcunknown) {
				continue;
			}

			if (sershr->connpeerarena_.bytes_left() > 2 * sizeof(CONN_PEER_ONE) && sershr->connlistenmap_.size() < MAX_CLOSE_CONN_ELEM - 1) {

				if (auto sit = pcunknown->serunclimap_.find(obj.ser_glob_id_); sit != pcunknown->serunclimap_.end()) {
					auto 			& serone = sit->second;

					auto 			[it, sret] = sershr->connlistenmap_.try_emplace(obj.ser_glob_id_, obj.ser_comm_, sershr->connpeerarena_);
					auto 			& climap = it->second.climap_;

					auto 			[cit, cret] = climap.try_emplace(obj.cli_task_aggr_id_, obj.cli_comm_, obj.cli_partha_machine_id_, obj.cli_madhava_id_);
					auto 			& clione = cit->second;

					if (serone.bytes_sent_ >= obj.close_cli_bytes_sent_) 		serone.bytes_sent_	-= obj.close_cli_bytes_sent_;
					if (serone.bytes_received_ >= obj.close_cli_bytes_rcvd_) 	serone.bytes_received_	-= obj.close_cli_bytes_rcvd_;
					if (serone.nconns_ > 0) 					serone.nconns_--;

					clione.bytes_sent_ 	+= obj.close_cli_bytes_sent_;
					clione.bytes_received_	+= obj.close_cli_bytes_rcvd_;
					clione.nconns_++;
					clione.cli_listener_proc_ |= (!!obj.cli_related_listen_id_);

					n++;
				}

			}	
			else {
				break;
			}	
		}	

		if (n > 0) {
			sershr->tconnlistensec_ = time(nullptr);
			nupd += n;
		}
	}	

	return nupd;
}

bool MCONN_HANDLER::send_mp_cli_tcp_info(PARTHA_INFO *prawpartha, const comm::MP_CLI_TCP_INFO *pone, size_t nconns, POOL_ALLOC_ARRAY *pthrpoolarr)
{
	auto				connshr = prawpartha->get_last_conn(comm::CLI_TYPE_RESP_REQ);
	if (!connshr) {
		return false;
	}

	size_t				fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + nconns * sizeof(MP_CLI_TCP_INFO);
	FREE_FPTR			free_fp;
	uint32_t			act_size;

	void				*palloc = pthrpoolarr->safe_malloc(fixed_sz, free_fp, act_size, false /* try_other_pools */);

	COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
	EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1);
	MP_CLI_TCP_INFO			*pconn = reinterpret_cast<MP_CLI_TCP_INFO *>(pnot + 1);
	
	new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, fixed_sz, connshr->get_comm_magic());
	new (pnot) EVENT_NOTIFY(comm::NOTIFY_MP_CLI_TCP_INFO, nconns);

	std::memcpy((void *)pconn, pone, nconns * sizeof(MP_CLI_TCP_INFO));
	
	return schedule_l1_send_data(connshr, comm::COMM_EVENT_NOTIFY, EPOLL_IOVEC_ARR(2, false, palloc, fixed_sz, free_fp, gpadbuf, phdr->get_pad_len(), nullptr));
}	

bool MCONN_HANDLER::send_mp_ser_tcp_info(PARTHA_INFO *prawpartha, const comm::MP_SER_TCP_INFO *pone, size_t nconns, POOL_ALLOC_ARRAY *pthrpoolarr)
{
	auto				connshr = prawpartha->get_last_conn(comm::CLI_TYPE_RESP_REQ);
	if (!connshr) {
		return false;
	}

	size_t				fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + nconns * sizeof(MP_SER_TCP_INFO);
	FREE_FPTR			free_fp;
	uint32_t			act_size;

	void				*palloc = pthrpoolarr->safe_malloc(fixed_sz, free_fp, act_size, false /* try_other_pools */);

	COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
	EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1);
	MP_SER_TCP_INFO			*pconn = reinterpret_cast<MP_SER_TCP_INFO *>(pnot + 1);
	
	new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, fixed_sz, connshr->get_comm_magic());
	new (pnot) EVENT_NOTIFY(comm::NOTIFY_MP_SER_TCP_INFO, nconns);

	std::memcpy((void *)pconn, pone, nconns * sizeof(MP_SER_TCP_INFO));
	
	return schedule_l1_send_data(connshr, comm::COMM_EVENT_NOTIFY, EPOLL_IOVEC_ARR(2, false, palloc, fixed_sz, free_fp, gpadbuf, phdr->get_pad_len(), nullptr));
}	


bool MCONN_HANDLER::send_shyama_conn_close(const comm::MS_TCP_CONN_CLOSE *pone, size_t nconns, POOL_ALLOC_ARRAY *pthrpoolarr)
{
	auto				shrconn = gshyama_.get_last_conn(comm::CLI_TYPE_REQ_RESP);

	if (!shrconn) {
		return false;
	}
				
	size_t				fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + nconns * sizeof(MS_TCP_CONN_CLOSE);
	FREE_FPTR			free_fp;
	uint32_t			act_size;
	void				*palloc = pthrpoolarr->opt_safe_malloc(pthrpoolarr, fixed_sz, free_fp, act_size, false /* try_other_pools */);

	COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
	EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1);
	MS_TCP_CONN_CLOSE		*pconn = reinterpret_cast<MS_TCP_CONN_CLOSE *>(pnot + 1);
	
	new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, fixed_sz, shrconn->get_comm_magic());
	new (pnot) EVENT_NOTIFY(comm::NOTIFY_MS_TCP_CONN_CLOSE, nconns);

	std::memcpy(pconn, pone, nconns * sizeof(MS_TCP_CONN_CLOSE));
	
	return schedule_l1_send_data(shrconn, comm::COMM_EVENT_NOTIFY, EPOLL_IOVEC_ARR(2, false, palloc, fixed_sz, free_fp, gpadbuf, phdr->get_pad_len(), nullptr));
}	


bool MCONN_HANDLER::handle_partha_nat_notify(comm::NAT_TCP_NOTIFY * pone, int nconns, uint8_t *pendptr, POOL_ALLOC_ARRAY *pthrpoolarr, bool is_last_elem, DB_WRITE_ARR && dbarr)
{
	MP_CLI_TCP_INFO_VEC_ARENA	parclivecarena;
	MP_CLI_TCP_INFO_MAP_ARENA	parclimaparena;
	MP_CLI_TCP_INFO_MAP		parclimap(parclimaparena);
	MP_SER_TCP_INFO_VEC_ARENA	parservecarena;
	MP_SER_TCP_INFO_MAP_ARENA	parsermaparena;
	MP_SER_TCP_INFO_MAP		parsermap(parsermaparena);

	CLI_UN_SERV_INFO_VEC_ARENA	cliunvecarena;
	CLI_UN_SERV_INFO_MAP_ARENA	cliunmaparena;
	CLI_UN_SERV_INFO_MAP		cliunmap(cliunmaparena);
	SER_UN_CLI_INFO_VEC_ARENA	serunvecarena;
	SER_UN_CLI_INFO_MAP_ARENA	serunmaparena;
	SER_UN_CLI_INFO_MAP		serunmap(serunmaparena);

	NAT_TCP_NOTIFY			*porigone = pone;

	const uint64_t			tusec_start = get_usec_time();
	uint32_t			nshyama = 0, nparcliconn = 0, nparserconn = 0, ncliuninfo = 0, nseruninfo = 0;
	bool				brets, bretc;
	std::shared_ptr <PARTHA_INFO>	cli_shr_host;
	std::shared_ptr<MTCP_LISTENER>	listenshr;
	PAIR_IP_PORT			corigtup;

	assert(gy_get_thread_local().get_thread_stack_freespace() > 100 * 1024);

	RCU_LOCK_SLOW			slowlock;

	/*
	 * The NAT Messages are from potential intermediate routers and so we use orig_tup_ and nat_tup_ for 2 separate lookups 
	 * to plumb the client and server side. This implies we support a max of 2 intermediate hops.
	 */
	for (int i = 0; i < nconns; ++i, ++pone) {
		const uint32_t			chash = pone->orig_tup_.get_hash(), shash = pone->nat_tup_.get_hash();

		uint64_t			cli_task_aggr_id = 0, cli_related_listen_id = 0, cli_cluster_hash = 0, ser_cluster_hash = 0;
		uint32_t			cli_cmdline_len = 0;
		uint32_t			ser_conn_hash = 0, ser_sock_inode = 0;
		MTCP_CONN			*pcliconn = nullptr;
		uint64_t			tstart_usec_cli = 0, tstart_usec_ser = 0, cli_bytes_sent = 0, cli_bytes_rcvd = 0, ser_bytes_sent = 0, ser_bytes_rcvd = 0;
		char				cli_comm[TASK_COMM_LEN], cli_cmdline[comm::MAX_PROC_CMDLINE_LEN];
		bool				cli_closed = false, ser_closed = false, conn_closed;

		*cli_comm 	= 0;
		*cli_cmdline	= 0;

		auto lamtcpc = [&](MTCP_CONN *ptcp, void *arg1, void *arg2) -> CB_RET_E
		{	
			corigtup		= {ptcp->cli_, ptcp->ser_}; 
			cli_shr_host		= std::move(ptcp->cli_shr_host_);
			cli_task_aggr_id 	= ptcp->cli_task_aggr_id_;
			cli_related_listen_id	= ptcp->cli_related_listen_id_;
			cli_cluster_hash	= ptcp->cli_ser_cluster_hash_;
			
			GY_STRNCPY(cli_comm, ptcp->cli_comm_, sizeof(cli_comm));

			auto			sz = ptcp->cli_cmdline_.size();

			if (sz) {
				GY_STRNCPY(cli_cmdline, ptcp->cli_cmdline_.data(), sizeof(cli_cmdline));
				cli_cmdline_len = sz;
			}
			else {
				*cli_cmdline 	= 0;
				cli_cmdline_len = 0;
			}	

			pcliconn 		= ptcp;

			cli_closed 		= ptcp->is_conn_closed();
			tstart_usec_cli		= ptcp->tusec_start_;
			cli_bytes_sent		= ptcp->close_cli_bytes_sent_;
			cli_bytes_rcvd		= ptcp->close_cli_bytes_rcvd_;

			return CB_OK;
		};	

		bretc = glob_tcp_conn_tbl_.lookup_single_elem(pone->orig_tup_, chash, lamtcpc);
		
		if (bretc == false) {
			// Keep the pone to be sent to Shyama
			CONDEXEC(
				DEBUGEXECN(11,
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_LIGHT_CYAN, "Received unclaimed NAT info Client : Orig Tuple %s : NAT Tuple %s\n",
						pone->orig_tup_.print_string(STRING_BUFFER<128>().get_str_buf()), 
						pone->nat_tup_.print_string(STRING_BUFFER<128>().get_str_buf()));
				);
			);

			nshyama++;
			continue;
		}	

		auto lamtcps = [&](MTCP_CONN *ptcp, void *arg1, void *arg2) -> CB_RET_E
		{	
			listenshr		= std::move(ptcp->ser_listen_shr_);
			ser_conn_hash		= ptcp->ser_conn_hash_;
			ser_sock_inode		= ptcp->ser_sock_inode_;
			ser_cluster_hash	= ptcp->cli_ser_cluster_hash_;

			ser_closed 		= ptcp->is_conn_closed();
			tstart_usec_ser		= ptcp->tusec_start_;
			ser_bytes_sent		= ptcp->close_cli_bytes_sent_;
			ser_bytes_rcvd		= ptcp->close_cli_bytes_rcvd_;

			return CB_DELETE_ELEM;
		};	

		brets = glob_tcp_conn_tbl_.lookup_single_elem(pone->nat_tup_, shash, lamtcps);

		if (brets && cli_shr_host && cli_task_aggr_id && listenshr && listenshr->parthashr_) {
			if (pcliconn) {
				glob_tcp_conn_tbl_.delete_elem_locked(pcliconn);
			}

			conn_closed = cli_closed || ser_closed;

			auto			plistener = listenshr.get();
			auto			pclihost = cli_shr_host.get();

			if (!conn_closed) {
				auto 			[it, success] = parclimap.try_emplace(std::move(cli_shr_host), parclivecarena);
				auto 			& parclivec = it->second;

				parclivec.emplace_back(corigtup, plistener->partha_machine_id_, plistener->glob_id_, gmadhava_id_, plistener->related_listen_id_, 
							ser_cluster_hash != cli_cluster_hash, plistener->comm_);

				auto 			[sit, ssuccess] = parsermap.try_emplace(plistener->parthashr_, parservecarena);
				auto 			& parservec = sit->second;

				parservec.emplace_back(pclihost->machine_id_, cli_task_aggr_id, gmadhava_id_, cli_related_listen_id, cli_comm, pone->orig_tup_.ser_, ser_conn_hash, ser_sock_inode);
			
				add_local_conn_task_ref(pclihost, cli_task_aggr_id, plistener, cli_comm, cli_cmdline_len, cli_cmdline, pthrpoolarr, tusec_start);
			}
			else {
				if (cli_closed) {
					auto 			[sit, ssuccess] = cliunmap.try_emplace(std::move(cli_shr_host), cliunvecarena);
					auto 			& cliunvec = sit->second;

					cliunvec.emplace_back(tstart_usec_cli/GY_USEC_PER_SEC, cli_task_aggr_id, cli_comm, cli_related_listen_id, 
								plistener->glob_id_, plistener->related_listen_id_, plistener->comm_, plistener->partha_machine_id_, 
								cli_bytes_sent, cli_bytes_rcvd, gmadhava_id_);
				}

				if (ser_closed) {
					auto 			[sit, ssuccess] = serunmap.try_emplace(plistener->parthashr_, serunvecarena);
					auto 			& serunvec = sit->second;

					serunvec.emplace_back(tstart_usec_ser/GY_USEC_PER_SEC, plistener->glob_id_, plistener->comm_, cli_task_aggr_id, cli_related_listen_id,
								cli_comm, cli_shr_host->machine_id_, ser_bytes_sent, ser_bytes_rcvd, gmadhava_id_);
				}	
			}	

			CONDEXEC(
				DEBUGEXECN(11,
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_LIGHT_CYAN, "Updated %sTCP Conn using NAT info : Orig Tuple %s : NAT Tuple %s\n",
						conn_closed ? "Closed " : "", pone->orig_tup_.print_string(STRING_BUFFER<128>().get_str_buf()), 
						pone->nat_tup_.print_string(STRING_BUFFER<128>().get_str_buf()));
				);
			);

		}	
		else if (!brets) {
			CONDEXEC(
				DEBUGEXECN(11,
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_LIGHT_CYAN, "Received unclaimed NAT info Server Updated Orig Tuple : Orig Tuple %s : NAT Tuple %s\n",
						pone->orig_tup_.print_string(STRING_BUFFER<128>().get_str_buf()), 
						pone->nat_tup_.print_string(STRING_BUFFER<128>().get_str_buf()));
				);
			);
		}	
		
		pone->orig_tup_.cli_.port_ = 0;		// Reset this elem
	}

	// Now RCU Offline the thread
	slowlock.unlock();

	ncliuninfo = upd_cli_ser_unknown_conns(cliunmap);
	nseruninfo = upd_ser_cli_unknown_conns(serunmap);

	for (const auto & epair : parclimap) {
		const auto & parshr	= epair.first;
		const auto & parclivec	= epair.second;

		if (!parshr || parclivec.empty()) {
			continue;
		}

		DEBUGEXECN(5,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Sending %lu TCP Conn Listener Info Messages using NAT info to Client Partha %s\n",
				parclivec.size(), parshr->print_string(STRING_BUFFER<256>().get_str_buf()));
		);

		nparcliconn += parclivec.size();

		send_mp_cli_tcp_info(parshr.get(), parclivec.data(), parclivec.size(), pthrpoolarr);
	}	

	for (const auto & epair : parsermap) {
		const auto & parshr	= epair.first;
		const auto & parservec	= epair.second;

		if (!parshr || parservec.empty()) {
			continue;
		}

		DEBUGEXECN(5,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Sending %lu TCP Conn Remote Client Info Messages using NAT info to Server Partha %s\n",
				parservec.size(), parshr->print_string(STRING_BUFFER<256>().get_str_buf()));
		);

		nparserconn += parservec.size();

		send_mp_ser_tcp_info(parshr.get(), parservec.data(), parservec.size(), pthrpoolarr);
	}	

	if (nshyama > 0 && multiple_madhava_active()) {
		auto				shrconn = gshyama_.get_last_conn(comm::CLI_TYPE_REQ_RESP);
		auto 				pconn1 = shrconn.get();

		if (pconn1) {
			bool				is_malloc;
			NAT_TCP_NOTIFY			*ptmpstart, *ptmp;
			uint32_t			nsconn = 0;

			SAFE_STACK_ALLOC(ptmpstart, nshyama * sizeof(*pone), is_malloc);

			ptmp = ptmpstart;

			for (pone = porigone; (uint8_t *)pone < pendptr && nsconn < nshyama; ++pone) {
				if (pone->orig_tup_.cli_.port_ != 0) {
					*ptmp++ = *pone;
					nsconn++;
				}	
			}

			size_t				fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + nsconn * sizeof(NAT_TCP_NOTIFY);
			void				*palloc;
			FREE_FPTR			free_fp;
			uint32_t			act_size;
			
			if (is_last_elem) {
				// Reuse the request buffer to send to Shyama
				palloc 		= dbarr.pbufstart_;
				free_fp		= dbarr.free_fp_;	
				act_size	= fixed_sz;

				dbarr.reset();
			}	
			else {
				palloc = pthrpoolarr->safe_malloc(fixed_sz, free_fp, act_size, false /* try_other_pools */);
			}	

			COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
			EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1);
			NAT_TCP_NOTIFY			*porigone = reinterpret_cast<NAT_TCP_NOTIFY *>(pnot + 1);
			
			new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, fixed_sz, shrconn->get_comm_magic());
			new (pnot) EVENT_NOTIFY(comm::NOTIFY_NAT_TCP, nsconn);

			std::memcpy(porigone, ptmpstart, nsconn * sizeof(*porigone));
			
			schedule_l1_send_data(shrconn, comm::COMM_EVENT_NOTIFY, EPOLL_IOVEC_ARR(2, false, palloc, fixed_sz, free_fp, gpadbuf, phdr->get_pad_len(), nullptr));
		}
	}	
	else {
		nshyama = 0;
	}	

	bool		print1 = false;

	CONDEXEC(
		DEBUGEXECN(5,
			print1 = true;
		);
	);

	if ((nparcliconn + nparserconn + ncliuninfo + nseruninfo) || print1) {
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Received %d NAT Info from %s :  %d Client close conns updated, %d Server close conns updated, "
			"Sent %u Partha TCP Cli Conn Info and %u TCP Ser Conn Info messages and remaining %u NAT Info to Shyama\n",
			nconns, dbarr.shrconn_ ? dbarr.shrconn_->print_peer(STRING_BUFFER<128>().get_str_buf()) : "", ncliuninfo, nseruninfo, nparcliconn, nparserconn, nshyama);
	}	

	return true;
}	

bool MCONN_HANDLER::partha_aggr_task_state(const std::shared_ptr<PARTHA_INFO> & partha_shr, const comm::AGGR_TASK_STATE_NOTIFY * porigone, int ntasks, uint8_t *pendptr, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	if (!partha_shr) {
		return false;
	}

	PARTHA_INFO 			*prawpartha = partha_shr.get(); 
	const uint64_t			curr_tusec = get_usec_time();
	const auto			tvsec = curr_tusec/GY_USEC_PER_SEC;
	auto				timebuf = gy_localtime_iso8601_sec(tvsec);
	int				nremmadhav = 0, nissues = 0, ndbarr = 0;
	const uint64_t			curr_madid = gmadhava_id_;
	auto				pone = porigone;
	bool				bret;
	
	if (true) {
		using MMSet			= GY_STACK_HASH_SET<const comm::AGGR_TASK_STATE_NOTIFY *, 32 * 1024, GY_JHASHER<const comm::AGGR_TASK_STATE_NOTIFY *>>;
		using MMSetArena		= MMSet::allocator_type::arena_type;

		using MMStateMap		= GY_STACK_HASH_MAP<uint64_t, std::pair<std::weak_ptr<MADHAVA_INFO>, MMSet>, 48 * 1024, GY_JHASHER<uint64_t>>;
		using MMStateArena		= MMStateMap::allocator_type::arena_type;

		MMSetArena			mmsetarena;
		MMStateArena			mmarena;
		MMStateMap			mmstatemap(mmarena);

		assert(gy_get_thread_local().get_thread_stack_freespace() >= 400 * 1024 + 64 * 1024);

		// Use the atask_top_issue_ mutex for all top structs
		SCOPE_GY_MUTEX			topmutex(&prawpartha->atask_top_issue_.mutex_);

		prawpartha->atask_top_issue_.clear_locked();
		prawpartha->atask_top_net_.clear_locked();
		prawpartha->atask_top_cpu_.clear_locked();
		prawpartha->atask_top_rss_.clear_locked();
		prawpartha->atask_top_cpu_delay_.clear_locked();
		prawpartha->atask_top_vm_delay_.clear_locked();
		prawpartha->atask_top_io_delay_.clear_locked();
		
		SharedMutex::ReadHolder		rtscope(prawpartha->rtalerts_.adef_rwmutex_);
		bool				isrtadef = !!prawpartha->rtalerts_.adef_procstate_.size();

		if (!isrtadef) {
			rtscope.unlock();
		}	

		RCU_LOCK_SLOW			slowlock;

		for (int i = 0; i < ntasks; ++i, pone = (decltype(pone))((uint8_t *)pone + pone->get_elem_size())) {
			MAGGR_TASK		*ptask;
			MAGGR_TASK_ELEM_TYPE 	*pdatanode;
			MWEAK_LISTEN_TABLE	*premotelisttbl;

			if (pone->tcp_kbytes_ > 0) {

				const auto compnet = [pone](const MAGGR_TASK_STATE & elem) noexcept
				{
					return MAGGR_TASK_STATE::is_comp_net(*pone, elem);
				};

				prawpartha->atask_top_net_.try_emplace_locked(compnet, *pone, curr_tusec);
			}	

			if (pone->total_cpu_pct_ >= 0.1f) {

				const auto compcpu = [pone](const MAGGR_TASK_STATE & elem) noexcept
				{
					return MAGGR_TASK_STATE::is_comp_cpu(*pone, elem);
				};

				prawpartha->atask_top_cpu_.try_emplace_locked(compcpu, *pone, curr_tusec);
			}	

			if (pone->rss_mb_ >= 5) {

				const auto comprss = [pone](const MAGGR_TASK_STATE & elem) noexcept
				{
					return MAGGR_TASK_STATE::is_comp_rss(*pone, elem);
				};

				prawpartha->atask_top_rss_.try_emplace_locked(comprss, *pone, curr_tusec);
			}	

			if (pone->cpu_delay_msec_ > 0) {

				const auto compdelay = [pone](const MAGGR_TASK_STATE & elem) noexcept
				{
					return MAGGR_TASK_STATE::is_comp_cpu_delay(*pone, elem);
				};

				prawpartha->atask_top_cpu_delay_.try_emplace_locked(compdelay, *pone, curr_tusec);
			}	

			if (pone->vm_delay_msec_ > 0) {

				const auto compdelay = [pone](const MAGGR_TASK_STATE & elem) noexcept
				{
					return MAGGR_TASK_STATE::is_comp_vm_delay(*pone, elem);
				};

				prawpartha->atask_top_vm_delay_.try_emplace_locked(compdelay, *pone, curr_tusec);
			}	

			if (pone->blkio_delay_msec_ > 0) {

				const auto compdelay = [pone](const MAGGR_TASK_STATE & elem) noexcept
				{
					return MAGGR_TASK_STATE::is_comp_io_delay(*pone, elem);
				};

				prawpartha->atask_top_io_delay_.try_emplace_locked(compdelay, *pone, curr_tusec);
			}	

			if (pone->curr_state_ > STATE_OK) {
				const auto compissue = [pone](const MTASK_ISSUE & elem) noexcept
				{
					return MTASK_ISSUE::is_comp_issue(*pone, elem);
				};

				prawpartha->atask_top_issue_.try_emplace_locked(compissue, *pone, curr_tusec);
			}

			pdatanode = prawpartha->task_aggr_tbl_.lookup_single_elem_locked(pone->aggr_task_id_, get_uint64_hash(pone->aggr_task_id_));

			if (gy_unlikely(nullptr == pdatanode)) {
				continue;
			}	

			ptask = pdatanode->get_cref().get();
			if (gy_unlikely(nullptr == ptask)) {
				continue;
			}	
			
			// Update the local state and Historgrams if needed
			ptask->set_local_task_state(pone, curr_tusec);

			if (isrtadef) {
				procstate_rtalert_rwlocked(*prawpartha, *ptask, tvsec, timebuf.get()); 
			}

			if (pone->curr_state_ <= STATE_OK) {
				continue;
			}	

			nissues++;

			premotelisttbl = ptask->remote_listener_tbl_.get();

			if (premotelisttbl) {
				auto rwalk = [&](MWEAK_LISTEN_ID *pdatanode, void *arg) -> CB_RET_E
				{
					auto		listenshr = pdatanode->weaklisten_.lock();
					auto		plistener = listenshr.get();

					if (!plistener) {
						return CB_DELETE_ELEM;
					}	

					if (gy_likely(plistener->madhava_id_ != curr_madid)) {
						auto [mit, present] = mmstatemap.try_emplace(plistener->madhava_id_, plistener->madhava_weak_, mmsetarena);

						mit->second.second.emplace(pone);
					}	
					return CB_OK;
				};	

				premotelisttbl->walk_hash_table(rwalk);
			}	
		}	

		prawpartha->last_aggr_state_tusec_	= curr_tusec;

		if (isrtadef) {
			rtscope.unlock();
		}	

		topmutex.unlock();

		// Now RCU Offline the thread
		slowlock.unlock();

		for (const auto & it : mmstatemap) {
			auto madshr			= it.second.first.lock();
			auto pmad			= madshr.get();
			
			if (!pmad) {
				continue;
			}

			auto 				& commset = it.second.second;
			auto				shrconn = pmad->get_last_conn(comm::CLI_TYPE_REQ_RESP);
			auto 				pconn1 = shrconn.get();

			if (pconn1 && commset.size()) {

				size_t				maxsz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + commset.size() * AGGR_TASK_STATE_NOTIFY::get_max_elem_size(), 
								totalsz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY);
				FREE_FPTR			free_fp;
				uint32_t			act_size;
				void				*palloc = pthrpoolarr->safe_malloc(maxsz, free_fp, act_size, false /* try_other_pools */);

				COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
				EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1);
				AGGR_TASK_STATE_NOTIFY		*ptask = reinterpret_cast<AGGR_TASK_STATE_NOTIFY *>(pnot + 1);
				
				for (const comm::AGGR_TASK_STATE_NOTIFY * psrctask : commset) {
					auto 			tsz = psrctask->get_elem_size();

					std::memcpy(ptask, psrctask, tsz);

					totalsz += tsz;

					ptask = (decltype(ptask))((char *)ptask + tsz);
				}	

				new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, totalsz, pconn1->get_comm_magic());

				new (pnot) EVENT_NOTIFY(comm::NOTIFY_MM_AGGR_TASK_STATE, commset.size());

				schedule_l1_send_data(shrconn, comm::COMM_EVENT_NOTIFY, EPOLL_IOVEC_ARR(2, false, palloc, totalsz, free_fp, gpadbuf, phdr->get_pad_len(), nullptr));

				DEBUGEXECN(5,
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Sending %lu Aggr Task States to Remote Madhava %s\n",
						commset.size(), pmad->print_string(STRING_BUFFER<256>().get_str_buf()));
				);

				nremmadhav++;
			}
		}	
	}

	if (true) {
		// Update the DB
		static constexpr size_t		max_db_query_sz = 350 * 1024;

		assert(gy_get_thread_local().get_thread_stack_freespace() >= max_db_query_sz + 64 * 1024);

		STRING_BUFFER<max_db_query_sz>	qbuf;
		auto				datetbl = get_db_day_partition(tvsec, 30);
		auto				schemabuf = prawpartha->get_db_schema();

		auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 10'000 /* max_msec_wait */, false /* reset_on_timeout */);
		
		if (!pconn) {
			db_stats_.nconns_failed_.fetch_add_relaxed(1);
			db_stats_.naggrtask_state_failed_.fetch_add_relaxed(1);
			
			DEBUGEXECN(5,
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get DB Conn for Partha %s Aggr Task State updation\n", prawpartha->hostname_);
			);
			
			goto done2;
		}	
		
		qbuf.appendfmt("insert into %s.aggrtaskstatetbl%s values ", schemabuf.get(), datetbl.get());

		pone = porigone;
		
		auto				maxtasks = std::min(ntasks, (int)AGGR_TASK_STATE_NOTIFY::MAX_NUM_TASKS);

		for (int i = 0; i < maxtasks && (const uint8_t *)pone < pendptr; ++i, pone = (decltype(pone))((uint8_t *)pone + pone->get_elem_size())) {

			qbuf.appendfmt("(\'%s\',\'%016lx\',\'%s\',%d,%d,%d,%d,%.3f,%d,%d,%d,%d,%hd,%hd,%hd,%hd,%hd,%hd,\'", 
				timebuf.get(), pone->aggr_task_id_, pone->onecomm_, pone->pid_arr_[0], pone->pid_arr_[1], 
				pone->tcp_kbytes_, pone->tcp_conns_, pone->total_cpu_pct_, pone->rss_mb_, 
				pone->cpu_delay_msec_, pone->vm_delay_msec_, pone->blkio_delay_msec_, pone->ntasks_total_, pone->ntasks_issue_, 
				pone->curr_state_, pone->curr_issue_, pone->issue_bit_hist_, pone->severe_issue_bit_hist_);

			if (pone->issue_string_len_ > 1) {
				qbuf.append((const char *)(pone + 1), pone->issue_string_len_ - 1);
			}
			qbuf.appendconst("\'),");
		}	

		qbuf.set_last_char(';');

		if (gy_unlikely(true == qbuf.is_overflow())) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Internal Error : Aggr Task State DB insert buffer overflow occured for Partha %s\n",
				prawpartha->hostname_);
			goto done2;
		}

		bret = PQsendQueryOptim(pconn->get(), qbuf.buffer(), qbuf.size());
		
		if (bret == false) {
			db_stats_.naggrtask_state_failed_.fetch_add_relaxed(1);

			DEBUGEXECN(5,
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to schedule DB query to update Partha %s Aggr Task State due to %s\n", 
						prawpartha->hostname_, PQerrorMessage(pconn->get()));
			);

			goto done2;
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
					db_stats_.naggrtask_state_failed_.fetch_add_relaxed(1);

					DEBUGEXECN(5,
						ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to insert Partha Aggr Task State into DB due to %s\n", gyres.get_error_msg());
					);

					return false;
				}	

				return true;
			}
		);
	}

done2 :
	DEBUGEXECN(12,
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Partha %s : Received %d Aggr Task States : #PIDs with issues = %d : #Remote Madhava's intimated = %d\n",
			prawpartha->hostname_, ntasks, nissues, nremmadhav);
	);

	return true;
}

bool MCONN_HANDLER::handle_mm_aggr_task_state(const std::shared_ptr<MADHAVA_INFO> & madhava_shr, const comm::AGGR_TASK_STATE_NOTIFY * pone, int ntasks, uint8_t *pendptr)
{
	if (!madhava_shr) {
		return false;
	}

	MADHAVA_INFO 			*premmadhava = madhava_shr.get(); 

	RCU_LOCK_SLOW			slowlock;

	const uint64_t			curr_tusec = get_usec_time();
	int				nfound = 0, nissues = 0;
	bool				bret;
	
	for (int i = 0; i < ntasks && (const uint8_t *)pone < pendptr; ++i) {
		size_t			elem_sz = pone->get_elem_size();
		MAGGR_TASK		*ptask;
		MAGGR_TASK_ELEM_TYPE 	*pdatanode;
		MWEAK_LISTEN_TABLE	*premotelisttbl;

		pdatanode = premmadhava->task_aggr_tbl_.lookup_single_elem_locked(pone->aggr_task_id_, get_uint64_hash(pone->aggr_task_id_));

		if (gy_unlikely(nullptr == pdatanode)) {
			goto next1;
		}	

		ptask = pdatanode->get_cref().get();
		if (gy_unlikely(nullptr == ptask)) {
			goto next1;
		}	
		
		ptask->task_issue_.set_task_state(pone, curr_tusec);

		nfound++;
		nissues += pone->ntasks_issue_;

next1 :
		pone = (decltype(pone))((uint8_t *)pone + elem_sz);
	}	

	slowlock.unlock();

	DEBUGEXECN(1,
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Remote %s : Received %d Aggr Task States : Valid Tasks %d : #PIDs with issues = %d\n",
			premmadhava->print_string(STRING_BUFFER<256>().get_str_buf()), ntasks, nfound, nissues);
	);

	return true;
}

MCONN_HANDLER::MTCP_LISTENER * MCONN_HANDLER::upd_remote_listener(MADHAVA_INFO *premotemad, const comm::SHYAMA_CLI_TCP_INFO *pone, bool & is_new, uint64_t tusec)
{
	MTCP_LISTENER			*plistener = nullptr;
	uint64_t			glob_id = pone->ser_glob_id_;
	uint32_t			ghash = get_uint64_hash(glob_id);	
	bool				bret;

	auto listl = [&](MTCP_LISTENER_ELEM_TYPE *pdatanode, void *arg1, void *arg2)
	{
		plistener = pdatanode->get_cref().get();
		plistener->rem_madhava_ping_tusec_ = tusec;

		return CB_OK;
	};	

	bret = premotemad->listen_tbl_.lookup_single_elem(glob_id, ghash, listl);
	if (plistener == nullptr) {
		plistener = new MTCP_LISTENER(pone->ser_ip_port_, pone->ser_glob_id_, pone->ser_partha_machine_id_, premotemad->madhava_id_,
				premotemad->weak_from_this(), pone->ser_comm_, pone->ser_cmdline_trunc_, pone->ser_cmdline_len_);
		
		auto listelem = new MTCP_LISTENER_ELEM_TYPE(plistener);

		premotemad->listen_tbl_.insert_or_replace(listelem, glob_id, ghash);

		// We do not update glob_listener_tbl_ for remote listeners

		is_new = true;
	}

	return plistener;
}	

void MCONN_HANDLER::handle_shyama_tcp_cli(comm::SHYAMA_CLI_TCP_INFO * pone, int nconns, uint8_t *pendptr, POOL_ALLOC_ARRAY *pthrpoolarr)
{
	/*
	 * We create entries in remote madhava listen_tbl_ for the remote Madhava Handled Listeners and create the Task References
	 * We also send the Listener Info to the respective Partha.
	 */

	using ParCliVec			= GY_STACK_VECTOR<comm::MP_CLI_TCP_INFO, 128 * 1024>;
	using ParCliVecArena		= ParCliVec::allocator_type::arena_type;
	using ParCliMap			= GY_STACK_HASH_MAP<std::shared_ptr<PARTHA_INFO>, ParCliVec, 24 * 1024>;
	using ParCliMapArena		= ParCliMap::allocator_type::arena_type;
	
	ParCliVecArena			parclivecarena;
	ParCliMapArena			parclimaparena;
	ParCliMap			parclimap(parclimaparena);

	CLI_UN_SERV_INFO_VEC_ARENA	cliunvecarena;
	CLI_UN_SERV_INFO_MAP_ARENA	cliunmaparena;
	CLI_UN_SERV_INFO_MAP		cliunmap(cliunmaparena);

	auto				*porigone = pone;

	const uint64_t			tusec_start = get_usec_time();
	bool				bret, is_new;
	int				nmadmissed = 0, ninvpartha = 0, ninfo = 0, ncliuninfo = 0;
	uint64_t			last_madid = 0;
	MTCP_LISTENER			*plistener;
	MADHAVA_INFO			*premotemad = nullptr;	
	PARTHA_INFO			*pclihost = nullptr;

	RCU_LOCK_SLOW			slowlock;

	auto madlam = [&](MADHAVA_INFO_ELEM *pelem, void *arg1, void *arg2) -> CB_RET_E
	{
		premotemad = pelem->get_cref().get();

		if (premotemad) {
			last_madid = premotemad->madhava_id_;
		}	

		return CB_OK;
	};	

	auto parlam = [&](PARTHA_INFO_ELEM *pelem, void *arg1, void *arg2) -> CB_RET_E
	{
		pclihost = pelem->get_cref().get();
		return CB_OK;
	};	

	for (int i = 0; i < nconns; ++i, ++pone) {
		
		bool			conn_closed = pone->is_conn_closed();

		if (!premotemad || last_madid != pone->ser_madhava_id_) {
			bret = madhava_tbl_.lookup_single_elem(pone->ser_madhava_id_, get_uint64_hash(pone->ser_madhava_id_), madlam);
		}
		else {
			bret = true;
		}	

		if (!bret || !premotemad) {
			nmadmissed++;

			DEBUGEXECN(1, WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Shyama Server sent an invalid TCP Conn Cli Info as Server Madhava ID %016lx not found...\n",
				pone->ser_madhava_id_););
			continue;
		}	
	
		if (!conn_closed) {
			plistener = upd_remote_listener(premotemad, pone, is_new, tusec_start);

			if (!plistener) {
				ninvpartha++;
				continue;
			}	
		}
		else {
			plistener = nullptr;
		}
	

		bret = partha_tbl_.lookup_single_elem(pone->cli_partha_machine_id_, pone->cli_partha_machine_id_.get_hash(), parlam);

		if (!bret || !pclihost) {
			ninvpartha++;
			continue;
		}	
	
		if (!conn_closed) {	
			auto 			[it, success] = parclimap.try_emplace(pclihost->shared_from_this(), parclivecarena);
			auto 			& parclivec = it->second;

			parclivec.emplace_back(pone->tup_, pone->ser_partha_machine_id_, plistener->glob_id_, pone->ser_madhava_id_, pone->ser_related_listen_id_, 
						pone->cli_ser_diff_clusters_, plistener->comm_);

			add_local_conn_task_ref(pclihost, pone->cli_task_aggr_id_, plistener, "", 0, "", pthrpoolarr, tusec_start);
		}
		else {
			// plistener is nullptr here
			auto 			[it, success] = cliunmap.try_emplace(pclihost->shared_from_this(), cliunvecarena);
			auto 			& cliunvec = it->second;

			cliunvec.emplace_back(*pone);
		}	

		DEBUGEXECN(5,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_LIGHT_CYAN, "Updated %sTCP Client Conn using Shyama info : Orig Tuple %s : Remote Madhava Listener is \'%s\'\n",
				conn_closed ? "Closed " : "", pone->tup_.print_string(STRING_BUFFER<128>().get_str_buf()), pone->ser_comm_);
		);

		ninfo++;
	}

	slowlock.unlock();

	ncliuninfo = upd_cli_ser_unknown_conns(cliunmap);

	for (const auto & epair : parclimap) {
		const auto & parshr	= epair.first;
		const auto & parclivec	= epair.second;

		if (!parshr || parclivec.empty()) {
			continue;
		}

		DEBUGEXECN(5,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Sending %lu TCP Conn Listener Info Messages using Shyama Client info to Client Partha %s\n",
				parclivec.size(), parshr->print_string(STRING_BUFFER<256>().get_str_buf()));
		);

		send_mp_cli_tcp_info(parshr.get(), parclivec.data(), parclivec.size(), pthrpoolarr);
	}	

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_GREEN, "Shyama Client TCP Info : #Conn Info sent %d, #Closed Conns %d, #Valid Conn Info %d, #Madhava Errors %d, #Partha Errors %d\n",
		nconns, ncliuninfo, ninfo, nmadmissed, ninvpartha);
}

void MCONN_HANDLER::handle_shyama_tcp_ser(comm::SHYAMA_SER_TCP_INFO * pone, int nconns, uint8_t *pendptr, POOL_ALLOC_ARRAY *pthrpoolarr)
{
	/*
	 * We create remote Client Task entries in listen_tbl_ for the remote Madhava
	 * We also create Weak Madhava References within the listener.
	 */

	using ParSerVec			= GY_STACK_VECTOR<comm::MP_SER_TCP_INFO, 128 * 1024>;
	using ParSerVecArena		= ParSerVec::allocator_type::arena_type;
	using ParSerMap			= GY_STACK_HASH_MAP<std::shared_ptr<PARTHA_INFO>, ParSerVec, 24 * 1024>;
	using ParSerMapArena		= ParSerMap::allocator_type::arena_type;

	ParSerVecArena			parservecarena;
	ParSerMapArena			parsermaparena;
	ParSerMap			parsermap(parsermaparena);

	SER_UN_CLI_INFO_VEC_ARENA	serunvecarena;
	SER_UN_CLI_INFO_MAP_ARENA	serunmaparena;
	SER_UN_CLI_INFO_MAP		serunmap(serunmaparena);

	auto				*porigone = pone;

	const uint64_t			tusec_start = get_usec_time();
	bool				bret, is_new;
	int				nmadmissed = 0, ninvpartha = 0, ninvlisten = 0, ninfo = 0, nseruninfo = 0;
	uint64_t			last_madid = 0;
	MTCP_LISTENER			*plistener;
	MADHAVA_INFO			*premotemad = nullptr;	
	PARTHA_INFO			*pserhost = nullptr;

	RCU_LOCK_SLOW			slowlock;

	auto madlam = [&](MADHAVA_INFO_ELEM *pelem, void *arg1, void *arg2) -> CB_RET_E
	{
		premotemad = pelem->get_cref().get();

		if (premotemad) {
			last_madid = premotemad->madhava_id_;
		}	

		return CB_OK;
	};	

	auto parlam = [&](PARTHA_INFO_ELEM *pelem, void *arg1, void *arg2) -> CB_RET_E
	{
		pserhost = pelem->get_cref().get();
		return CB_OK;
	};	

	auto listl = [&](MTCP_LISTENER_ELEM_TYPE *pdatanode, void *arg1, void *arg2)
	{
		plistener = pdatanode->get_cref().get();
		return CB_OK;
	};	


	for (int i = 0; i < nconns; ++i, ++pone) {
		
		bool			conn_closed = pone->is_conn_closed();

		if (!premotemad || last_madid != pone->cli_madhava_id_) {
			bret = madhava_tbl_.lookup_single_elem(pone->cli_madhava_id_, get_uint64_hash(pone->cli_madhava_id_), madlam);
		}
		else {
			bret = true;
		}	

		if (!bret || !premotemad) {
			nmadmissed++;

			DEBUGEXECN(1, WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Shyama Server sent an invalid TCP Conn Ser Info as Client Madhava ID %016lx not found...\n",
				pone->cli_madhava_id_););
			continue;
		}	
	
		bret = partha_tbl_.lookup_single_elem(pone->ser_partha_machine_id_, pone->ser_partha_machine_id_.get_hash(), parlam);

		if (!bret || !pserhost) {
			ninvpartha++;
			continue;
		}	
	
		plistener = nullptr;

		bret = pserhost->listen_tbl_.lookup_single_elem(pone->ser_glob_id_, get_uint64_hash(pone->ser_glob_id_), listl);

		if (!plistener) {
			ninvlisten++;
			continue;
		}	

		if (!conn_closed) {	
			auto 			[it, success] = parsermap.try_emplace(pserhost->shared_from_this(), parservecarena);
			auto 			& parservec = it->second;

			parservec.emplace_back(pone->cli_partha_machine_id_, pone->cli_task_aggr_id_, pone->cli_madhava_id_, pone->cli_related_listen_id_, pone->cli_comm_, 
						pone->ser_nat_ip_port_, pone->ser_conn_hash_, pone->ser_sock_inode_);

			add_remote_conn_task_ref(premotemad, pone->cli_task_aggr_id_, pone->cli_partha_machine_id_, plistener, pone->cli_comm_, 
						pone->cli_cmdline_len_, pone->cli_cmdline_trunc_, pthrpoolarr, tusec_start);

		}
		else {
			auto 			[it, success] = serunmap.try_emplace(pserhost->shared_from_this(), serunvecarena);
			auto 			& serunvec = it->second;

			serunvec.emplace_back(*pone);

		}	
	
		DEBUGEXECN(11,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_LIGHT_CYAN, 
				"Updated %sTCP Server Conn using Shyama info for listener \'%s\' : : Remote Client is \'%s\' : Remote Madhava from \'%s\'\n",
				conn_closed ? "Closed " : "", pone->ser_comm_, pone->cli_comm_, premotemad->get_domain());
		);

		ninfo++;
	}

	slowlock.unlock();

	nseruninfo = upd_ser_cli_unknown_conns(serunmap);

	for (const auto & epair : parsermap) {
		const auto & parshr	= epair.first;
		const auto & parservec	= epair.second;

		if (!parshr || parservec.empty()) {
			continue;
		}

		DEBUGEXECN(5,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Sending %lu TCP Conn Listener Info Messages using Shyama Server info to Server Partha %s\n",
				parservec.size(), parshr->print_string(STRING_BUFFER<256>().get_str_buf()));
		);

		send_mp_ser_tcp_info(parshr.get(), parservec.data(), parservec.size(), pthrpoolarr);
	}	

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_GREEN, "Shyama Server TCP Info : #Conn Info sent %d, #Closed Conns %d, #Valid Conn Info %d, #Madhava Errors %d, #Partha Errors %d\n",
		nconns, nseruninfo, ninfo, nmadmissed, ninvpartha);
}


void MCONN_HANDLER::cleanup_tcp_conn_table() noexcept
{
	try {
		auto				shrconn = gshyama_.get_last_conn(comm::CLI_TYPE_REQ_RESP);
		auto 				pconn1 = shrconn.get();

		if (pconn1 && false == multiple_madhava_active()) {
			// No need to send to Shyama
			shrconn.reset();
			pconn1 = nullptr;
		}	

		DATA_BUFFER			scache(sizeof(comm::MS_TCP_CONN_NOTIFY), std::min(1000ul, glob_tcp_conn_tbl_.approx_count_fast() + 8), 1000, 
							sizeof(comm::COMM_HEADER) + sizeof(comm::EVENT_NOTIFY));
		const uint64_t			tcutoffusec = get_usec_time() - 30 * GY_USEC_PER_SEC;
		size_t				ntotal, nsent = 0;
		int				nclosed = 0, nclosesent = 0;

		auto sendcb = [&](void *palloc, size_t sz, FREE_FPTR free_fp, size_t nelems) -> bool
		{
			COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
			EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1); 

			new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, sz, shrconn->get_comm_magic());
			new (pnot) EVENT_NOTIFY(comm::NOTIFY_MS_TCP_CONN, nelems);

			return schedule_l1_send_data(shrconn, comm::COMM_EVENT_NOTIFY, EPOLL_IOVEC_ARR(2, false, palloc, sz, free_fp, gpadbuf, phdr->get_pad_len(), nullptr));
		};	

		auto twalk = [&, tcutoffusec](MTCP_CONN *ptcp, void *arg) -> CB_RET_E
		{
			if (ptcp->tusec_start_ < tcutoffusec) {

				try {
					if (pconn1) {
						MS_TCP_CONN_NOTIFY		*pone = (comm::MS_TCP_CONN_NOTIFY *)scache.get_next_buffer();

						new (pone) MS_TCP_CONN_NOTIFY();

						ptcp->set_notify_elem(pone);
						
						if (ptcp->is_conn_closed()) {
							nclosesent++;
						}

						scache.set_buffer_sz(sendcb, sizeof(MS_TCP_CONN_NOTIFY), false /* force_flush */);
					}
				}
				GY_CATCH_EXCEPTION(
					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while updating the Shyama TCP conn notify : %s\n", GY_GET_EXCEPT_STRING);
					pconn1 = nullptr;
				);

				nsent++;

				return CB_DELETE_ELEM;
			}
			else {
				if (ptcp->is_conn_closed()) {
					nclosed++;
				}

				return CB_OK;
			}	
		};	
		
		ntotal = glob_tcp_conn_tbl_.walk_hash_table(twalk);

		if (pconn1) {
			scache.flush_cache(sendcb);
		}

		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN_ITALIC, "Global Unresolved TCP Connections %s = %lu : Total Remaining count = %lu : Closed Conns sent %d : Closed Conns remaining %d\n",
			pconn1 ? "sent to Shyama" : "Deleted", nsent, ntotal - nsent, nclosesent, nclosed);
		
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while cleaning the Global TCP conn table : %s\n", GY_GET_EXCEPT_STRING);
		);	
	);
}	

bool MCONN_HANDLER::send_partha_reset_stats(PARTHA_INFO *prawpartha)
{
	auto				connshr = prawpartha->get_last_conn(comm::CLI_TYPE_RESP_REQ);
	if (!connshr) {
		return false;
	}

	size_t				fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + sizeof(MP_RESET_STATS);

	void				*palloc = ::malloc(fixed_sz);
	if (!palloc) {
		return false;
	}	

	COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
	EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1);
	MP_RESET_STATS			*pres = reinterpret_cast<MP_RESET_STATS *>(pnot + 1);
	
	new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, fixed_sz, connshr->get_comm_magic());
	new (pnot) EVENT_NOTIFY(comm::NOTIFY_MP_RESET_STATS, 1);
	new (pres) MP_RESET_STATS(true);

	return schedule_l1_send_data(connshr, comm::COMM_EVENT_NOTIFY, EPOLL_IOVEC_ARR(2, false, palloc, fixed_sz, ::free, gpadbuf, phdr->get_pad_len(), nullptr));
}	


size_t MCONN_HANDLER::handle_dependency_issue(MTCP_LISTENER *plistener, const comm::MM_LISTENER_ISSUE_RESOL & resol, uint8_t src_upstream_tier, MM_LISTENER_ISSUE_MAP & mmissue_map, RESOL_MM_MAP_ARENA & resol_arena, DOWNSTREAM_VEC_ARENA & downvec_arena)
{
	if (gy_unlikely(src_upstream_tier > MM_LISTENER_ISSUE_RESOL::MAX_DOWNSTREAM_TIERS)) {
		return 0;
	}

	static_assert(MM_LISTENER_ISSUE_RESOL::MAX_DOWNSTREAM_TIERS <= 8, "Limit Max Dependency Resolution tiers to 8");

	/*
	 * We walk the depending_related_tbl_ and check the individual listeners within each related listener for remote Madhavas and then update the
	 * mmissue_map. We recursively call upto MAX_DOWNSTREAM_TIERS if any depending listener state was Bad.
	 */

	const uint64_t 		issue_src_time_usec = resol.issue_src_time_usec_; 
	size_t			nlisten_resolved = 0;
	const bool		is_remote_listener = plistener->is_remote_madhava_;

	auto madlist = [&, src_upstream_tier](WEAK_REMOTE_MADHAVA *pweakmad, void *arg) -> CB_RET_E
	{
		if (false == GY_READ_ONCE(pweakmad->listen_depends_)) {
			return CB_OK;
		}	

		MTCP_LISTENER	*pdeplistener = (MTCP_LISTENER *)arg;
		auto 		[it, success] = mmissue_map.try_emplace(pweakmad->madhava_id_, resol_arena);

		if (success == true) {
			auto	madshr = pweakmad->weakmad_.lock();

			if (madshr) {
				it->second.shrconn_ = madshr->get_last_conn(comm::CLI_TYPE_REQ_RESP);
			}	
		}

		if (it->second.shrconn_) {
			auto 	[mit, mnew] = it->second.resmap_.try_emplace(resol.issue_src_glob_id_, resol, downvec_arena);

			it->second.totaldownvec_count_++;

			mit->second.downvec_.emplace_back(pdeplistener->glob_id_, pdeplistener->state_.curr_state_, pdeplistener->state_.curr_issue_,
				pdeplistener->state_.issue_bit_hist_, src_upstream_tier + uint8_t(pdeplistener != plistener));
		}	

		return CB_OK;
	};	

	auto relam = [&, issue_src_time_usec, glob_id = plistener->glob_id_, this, is_remote_listener](MRELATED_LISTENER_ELEM_TYPE *pdatanode, void *arg) -> CB_RET_E
	{
		auto ptrel = pdatanode->get_cref().get();

		if (!ptrel) {
			return CB_DELETE_ELEM;
		}

		auto lastt = ptrel->updated_tusec_.load(mo_relaxed);

		if (lastt >= issue_src_time_usec - 2 * GY_USEC_PER_SEC) {
			if ((ptrel->any_state_ok_bad_ == false) || (issue_src_time_usec <= ptrel->issue_resol_.upd_tusec_.load(mo_relaxed))) {
				return CB_OK;
			}	
		}

		ptrel->issue_resol_.resol_			= resol;
		ptrel->issue_resol_.downstream_glob_id_		= glob_id;
		ptrel->issue_resol_.src_upstream_tier_		= src_upstream_tier;
		ptrel->issue_resol_.upd_tusec_.store(issue_src_time_usec, mo_release);

		if (lastt < issue_src_time_usec - 2 * GY_USEC_PER_SEC) {
			// Listener State not yet updated...
			return CB_OK;
		}

		auto llam = [&, issue_src_time_usec, this, is_remote_listener](MTCP_LISTENER_ELEM_TYPE *pdatanode, void *arg)
		{
			auto pdeplistener = pdatanode->get_cref().get();
		
			if (!pdeplistener) {
				return CB_DELETE_ELEM;
			}	

			if (((pdeplistener->state_.curr_state_ > STATE_OK) && (pdeplistener->state_.curr_issue_ == ISSUE_DEPENDENT_SERVER_LISTENER)) || 
				(pdeplistener->state_.curr_state_ == STATE_OK)) {
				
				++nlisten_resolved;

				DEBUGEXECN(5,
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_GREEN, "Listener Issue Resolved : %s state %d : "
						"Source of issue is%s Listener \'%s\' ID %016lx located %d Tiers upstream : Neighbor upstream Listener \'%s\'\n",
						pdeplistener->print_string(STRING_BUFFER<512>().get_str_buf()), pdeplistener->state_.curr_state_,
						is_remote_listener ? " Remote Madhava" : "", resol.issue_src_comm_, resol.issue_src_glob_id_, src_upstream_tier,
						plistener->comm_);
				);

				/*
				 * Check whether remote Madhava's need to be communicated to.
				 */
				if (src_upstream_tier < MM_LISTENER_ISSUE_RESOL::MAX_DOWNSTREAM_TIERS) {

					if (0 != pdeplistener->remote_madhava_tbl_->approx_count_fast()) {
						pdeplistener->remote_madhava_tbl_->walk_hash_table(madlist, pdeplistener);
					}	

					// Recursively called till MAX_DOWNSTREAM_TIERS
					nlisten_resolved += handle_dependency_issue(pdeplistener, resol, src_upstream_tier + 1, mmissue_map, resol_arena, downvec_arena);
				}	
			}	

			return CB_OK;
		};	
	
		ptrel->listener_table_.walk_hash_table(llam);

		return CB_OK;
	};

	if (0 != plistener->depending_related_tbl_.approx_count_fast()) {
		plistener->depending_related_tbl_.walk_hash_table(relam);
	}	

	if ((false == is_remote_listener) && (0 != plistener->remote_madhava_tbl_->approx_count_fast())) {
		plistener->remote_madhava_tbl_->walk_hash_table(madlist, plistener);
	}	

	return nlisten_resolved;
}	


bool MCONN_HANDLER::partha_listener_state(const std::shared_ptr<PARTHA_INFO> & partha_shr, const comm::LISTENER_STATE_NOTIFY * porigone, int nconns, uint8_t *pendptr, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool, bool isdummycall)
{
	if (!partha_shr) {
		return false;
	}

	using MMDelVec			= GY_STACK_VECTOR<MM_LISTENER_DELETE, 32 * 1024>;
	using MMDelVecArena		= MMDelVec::allocator_type::arena_type;

	struct MMDelVecSize
	{
		MMDelVec			vec_;
		std::shared_ptr<MCONNTRACK>	shrconn_;

		MMDelVecSize(MMDelVecArena & arena) : vec_(arena)
		{}
	};

	using MMDelMap			= GY_STACK_HASH_MAP<uint64_t, MMDelVecSize, 80 * 1024, GY_JHASHER<uint64_t>>;
	using MMDelMapArena		= MMDelMap::allocator_type::arena_type;

	MMDelVecArena			delvecarena;
	MMDelMapArena			delmaparena;
	MMDelMap			delmap(delmaparena);

	struct DB_NOTIFY
	{
		const LISTENER_STATE_NOTIFY	*pone_;
		char				comm_[TASK_COMM_LEN];

		DB_NOTIFY() noexcept 		= default;

		DB_NOTIFY(const LISTENER_STATE_NOTIFY *pone, const char *comm) noexcept
			: pone_(pone)
		{
			std::memcpy(comm_, comm, sizeof(comm_));
		}	
	};	

	struct DB_DEL
	{
		const LISTENER_STATE_NOTIFY	*pone_;

		DB_DEL() noexcept 		= default;

		DB_DEL(const LISTENER_STATE_NOTIFY *pone) noexcept
			: pone_(pone)
		{}	
	};	

	struct NAT_DEL
	{
		uint64_t			glob_id_;
		char				comm_[TASK_COMM_LEN];
		IP_PORT				ip_ports_[2];
		uint8_t				nelem_new_;
		uint8_t				nelem_del_;

		NAT_DEL() noexcept 		= default;

		NAT_DEL(uint64_t glob_id, const char * comm, const IP_PORT (&ip_ports)[GY_ARRAY_SIZE(ip_ports_)], bool is_del) noexcept
			: glob_id_(glob_id), nelem_new_(0), nelem_del_(0)
		{
			for (size_t i = 0; i < GY_ARRAY_SIZE(ip_ports_); ++i) {
				if (ip_ports[i].port_) {
					ip_ports_[i] = ip_ports[i];

					if (is_del) {
						nelem_del_++;
					}
					else {
						nelem_new_++;
					}	
				}	
			}

			GY_STRNCPY(comm_, comm, sizeof(comm_));
		}	
	};	

	using NatVec			= INLINE_STACK_VECTOR<NAT_DEL, 16 * 1024>;

	static constexpr size_t		max_db_query_sz = 512 * 1024;
	DB_NOTIFY			dbarr[LISTENER_STATE_NOTIFY::MAX_NUM_LISTENERS + 1];
	DB_NOTIFY			dbdelarr[LISTENER_STATE_NOTIFY::MAX_NUM_LISTENERS + 1];
	std::optional<NatVec>		natvec;

	PARTHA_INFO 			*prawpartha = partha_shr.get(); 

	uint32_t			min_db_nqry;
	auto				pone = porigone;
	auto				ptopissue = &prawpartha->top_issue_listen_;
	auto				ptopqps = &prawpartha->top_qps_listen_;
	auto				ptopactivecon = &prawpartha->top_active_conn_listen_;
	auto				ptopnet = &prawpartha->top_net_listen_;
	auto				& rtalerts = prawpartha->rtalerts_; 
	int				nissues = 0, nmissed = 0, ndeleted = 0, nexcept = 0, nerrors = 0, nremmad = 0, nremmaddel = 0, nlisten_resolved = 0, ndbarr = 0, ndbdel = 0, nnatip = 0;
	LISTEN_SUMM_STATS<int>		summstats, lastsummstats;
	bool				bret;

	uint64_t			curr_tusec = get_usec_time(), tlastsumm = prawpartha->last_listen_state_tusec_;
	time_t				tvsec = curr_tusec/GY_USEC_PER_SEC, tdaystart = 0;
	auto				timebuf = gy_localtime_iso8601_sec(tvsec);

	const bool			is_continue_batch = (labs(curr_tusec - prawpartha->last_listen_state_tusec_) < 2 * GY_USEC_PER_SEC); // Partha sends every 5 sec
	
	if (is_continue_batch) {
		// Set all listen time consistent for pointintime queries
		curr_tusec = prawpartha->last_listen_state_tusec_;
		summstats = prawpartha->summstats_;
	}	

	const bool			shyama_nat_send = ((curr_tusec > prawpartha->last_shyama_nat_ping_tusec_ + 5 * GY_USEC_PER_MINUTE) ||
											(curr_tusec == prawpartha->last_shyama_nat_ping_tusec_));

	if (isdummycall) {
		min_db_nqry = 0;
	}	
	else if ((curr_tusec - prawpartha->last_all_listen_state_tusec_ < 30 * GY_USEC_PER_SEC) && (curr_tusec != prawpartha->last_all_listen_state_tusec_)) {
		min_db_nqry = ((is_continue_batch || nconns >= 255) ? 5 : 1);	
	}	
	else {
		// Save all Listener States to DB
		min_db_nqry = 0;
		prawpartha->last_all_listen_state_tusec_ = curr_tusec;
	}	

	if (shyama_nat_send) {
		prawpartha->last_shyama_nat_ping_tusec_ = curr_tusec;
		natvec.emplace();
	}	

	// Use the ptopissue mutex for all top structs
	SCOPE_GY_MUTEX			topmutex(&ptopissue->mutex_);

	if (!isdummycall && is_continue_batch == false) {
		ptopissue->clear_locked();
		ptopqps->clear_locked();
		ptopactivecon->clear_locked();
		ptopnet->clear_locked();
	}	

	if (true) {
		assert(gy_get_thread_local().get_thread_stack_freespace() >= 100 * 1024 + sizeof(DOWNSTREAM_VEC_ARENA) + sizeof(RESOL_MM_MAP_ARENA) + sizeof(MM_LISTENER_ISSUE_MAP_ARENA));

		DOWNSTREAM_VEC_ARENA		downvec_arena;
		RESOL_MM_MAP_ARENA		resol_arena;
		MM_LISTENER_ISSUE_MAP_ARENA	mmissue_map_arena;
		MM_LISTENER_ISSUE_MAP		mmissue_map(mmissue_map_arena);

		SharedMutex::ReadHolder		rtscope(rtalerts.adef_rwmutex_);
		bool				isrtadef = !!(prawpartha->rtalerts_.adef_svcstate_.size() + prawpartha->rtalerts_.adef_svcsumm_.size());

		if (!isrtadef) {
			rtscope.unlock();
		}	

		RCU_LOCK_SLOW			slowlock;

		assert((unsigned)nconns <= LISTENER_STATE_NOTIFY::MAX_NUM_LISTENERS);

		auto dellist = [&](WEAK_REMOTE_MADHAVA *pweakmad, void *arg) -> CB_RET_E
		{
			uint64_t	glob_id = (uint64_t)(uintptr_t)arg;

			auto 		[it, success] = delmap.try_emplace(pweakmad->madhava_id_, delvecarena);

			if (success == true) {
				auto	madshr = pweakmad->weakmad_.lock();

				if (madshr) {
					it->second.shrconn_ = madshr->get_last_conn(comm::CLI_TYPE_REQ_RESP);
				}	
			}

			if (it->second.shrconn_) {
				it->second.vec_.emplace_back(glob_id);
			}	

			return CB_OK;
		};	
		
		for (int i = 0; i < nconns && (const uint8_t *)pone < pendptr; ++i, pone = (decltype(pone))((uint8_t *)pone + pone->get_elem_size())) {
			MTCP_LISTENER			*plistener;
			MTCP_LISTENER_ELEM_TYPE 	*pdatanode;

			const uint64_t			glob_id = pone->glob_id_;
			const uint32_t			lhash = get_uint64_hash(glob_id);
			bool				is_issue;

			pdatanode = prawpartha->listen_tbl_.lookup_single_elem_locked(glob_id, lhash);

			if (gy_unlikely(nullptr == pdatanode)) {
				nmissed++;
				continue;
			}	

			plistener = pdatanode->get_cref().get();
			if (gy_unlikely(nullptr == plistener)) {
				continue;
			}	
			
			if (gy_unlikely(pone->query_flags_ == LISTEN_FLAG_DELETE)) {
				ndeleted++;

				dbdelarr[ndbdel].~DB_NOTIFY();
				new (dbdelarr + ndbdel) DB_NOTIFY(pone, plistener->comm_);
				ndbdel++;

				if ((plistener->nat_ip_port_arr_[0].port_ > 0) || (plistener->nat_ip_port_arr_[1].port_ > 0)) {
					if (!natvec.has_value()) {
						natvec.emplace();
					}	

					auto 		& nelem = natvec->emplace_back(glob_id, plistener->comm_, plistener->nat_ip_port_arr_, true /* is_del */);

					nnatip += nelem.nelem_del_;
				}	
	
				plistener->remote_madhava_tbl_->walk_hash_table(dellist, (void *)(uintptr_t)glob_id);

				auto relam = [id = plistener->glob_id_, lhash](MRELATED_LISTENER_ELEM_TYPE *pdatanode, void *arg) -> CB_RET_E
				{
					auto ptrel = pdatanode->get_ref().get();

					if (ptrel) {
						ptrel->depended_id_tbl_.delete_single_elem(id, lhash);
					}	

					return CB_DELETE_ELEM;
				};

				plistener->depending_related_tbl_.walk_hash_table(relam);

				auto relshr = plistener->related_listen_shr_.load(mo_acquire);

				if (relshr) {
					relshr->listener_table_.delete_single_elem(glob_id, lhash);

					if (true == relshr->listener_table_.is_empty()) {
						prawpartha->related_listen_tbl_.delete_single_elem(plistener->related_listen_id_, get_uint64_hash(plistener->related_listen_id_));

						auto taskshr = plistener->ser_task_weak_.lock();

						if (taskshr && taskshr->related_listen_id_ == plistener->related_listen_id_) {
							taskshr->related_listen_id_ = 0;
						}	
					}	
				}	

				glob_listener_tbl_.delete_single_elem(glob_id, lhash);

				prawpartha->listen_tbl_.delete_elem_locked(pdatanode);

				continue;
			}

			if (pone->curr_state_ <= OBJ_STATE_E::STATE_DOWN) {
				summstats.update(*pone);
			}
			else {
				nerrors++;
				continue;
			}	

			plistener->set_state(pone, curr_tusec);

			is_issue = (pone->curr_state_ > STATE_OK);

			if (is_issue) {

				const auto compissue = [pone](const LISTEN_TOPN & elem) noexcept
				{
					return LISTEN_TOPN::is_comp_issue(*pone, elem);
				};

				ptopissue->try_emplace_locked(compissue, *pone, plistener->comm_, plistener->ns_ip_port_, curr_tusec, 
						plistener->tusec_start_, plistener->is_load_balanced_);
			}

			if (pone->nqrys_5s_ >= 5) {

				const auto compqps = [pone](const LISTEN_TOPN & elem) noexcept
				{
					return LISTEN_TOPN::is_comp_qps(*pone, elem);
				};

				ptopqps->try_emplace_locked(compqps, *pone, plistener->comm_, plistener->ns_ip_port_, curr_tusec,
						plistener->tusec_start_, plistener->is_load_balanced_);
			}	

			if (pone->nconns_active_ >= 1) {

				const auto compactiveconn = [pone](const LISTEN_TOPN & elem) noexcept
				{
					return LISTEN_TOPN::is_comp_active_conn(*pone, elem);
				};

				ptopactivecon->try_emplace_locked(compactiveconn, *pone, plistener->comm_, plistener->ns_ip_port_, curr_tusec,
						plistener->tusec_start_, plistener->is_load_balanced_);
			}	

			if (pone->curr_kbytes_inbound_ + pone->curr_kbytes_outbound_ > 0) {

				const auto compnet = [pone](const LISTEN_TOPN & elem) noexcept
				{
					return LISTEN_TOPN::is_comp_net(*pone, elem);
				};

				ptopnet->try_emplace_locked(compnet, *pone, plistener->comm_, plistener->ns_ip_port_, curr_tusec,
						plistener->tusec_start_, plistener->is_load_balanced_);
			}	

			if (gy_unlikely(shyama_nat_send)) {
				if ((plistener->nat_ip_port_arr_[0].port_ > 0) || (plistener->nat_ip_port_arr_[1].port_ > 0)) {

					auto 		& nelem = natvec->emplace_back(glob_id, plistener->comm_, plistener->nat_ip_port_arr_, false /* is_del */);

					nnatip += nelem.nelem_new_;
				}	
			}	

			if (isrtadef) {
				svcstate_rtalert_rwlocked(*prawpartha, *plistener, tvsec, timebuf.get()); 
			}

			if (is_issue || pone->nqrys_5s_ >= min_db_nqry || (pone->curr_kbytes_inbound_ + pone->curr_kbytes_outbound_ > 0)) {
				dbarr[ndbarr].~DB_NOTIFY();
				new (dbarr + ndbarr) DB_NOTIFY(pone, plistener->comm_);
				ndbarr++;
			}	

			if (is_issue || pone->curr_state_ == STATE_OK) {

				if (is_issue) {
					nissues++;
				}

				if (is_issue && (pone->curr_issue_ != ISSUE_DEPENDENT_SERVER_LISTENER)) {

					MM_LISTENER_ISSUE_RESOL		resol;
					const uint8_t			src_upstream_tier = 1;

					resol.issue_src_glob_id_	= plistener->glob_id_;
					resol.issue_src_madhava_id_	= gmadhava_id_;
					resol.issue_src_time_usec_	= curr_tusec;

					std::memcpy(resol.issue_src_comm_, plistener->comm_, sizeof(resol.issue_src_comm_));
					resol.issue_src_comm_[sizeof(resol.issue_src_comm_) - 1] = 0;

					resol.src_is_load_balanced_	= plistener->is_load_balanced_;
					resol.src_state_		= pone->curr_state_;
					resol.src_issue_		= pone->curr_issue_;
					resol.issue_bit_hist_		= pone->issue_bit_hist_;

					nlisten_resolved += (int)handle_dependency_issue(plistener, resol, src_upstream_tier, mmissue_map, resol_arena, downvec_arena);
				}
				else {

					auto relshr = plistener->related_listen_shr_.load(mo_relaxed);
					
					if (relshr) {
						if (relshr->issue_resol_.upd_tusec_.load(mo_acquire) > curr_tusec - 2 * GY_USEC_PER_SEC) {

							auto			& resol = relshr->issue_resol_.resol_;

							++nlisten_resolved;

							DEBUGEXECN(5,
								INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_GREEN, "Listener Issue Resolved by prior state : %s state %d : "
									"Source of issue is Listener \'%s\' ID %016lx located %d Tiers upstream\n",
									plistener->print_string(STRING_BUFFER<512>().get_str_buf()), plistener->state_.curr_state_,
									resol.issue_src_comm_, resol.issue_src_glob_id_, relshr->issue_resol_.src_upstream_tier_);
							);

							nlisten_resolved += (int)handle_dependency_issue(plistener, resol, 
								relshr->issue_resol_.src_upstream_tier_ + 1, mmissue_map, resol_arena, downvec_arena);
						}
					}	
				}	
			}	
		}	

		if (tlastsumm) {
			if (tlastsumm != curr_tusec) {
				if (!isdummycall || curr_tusec > tlastsumm + GY_USEC_PER_MINUTE) {
					lastsummstats = prawpartha->summstats_;
				}
				else {
					tlastsumm = 0;
				}	
			}
			else {
				tlastsumm = 0;
			}	
		}

		if (!isdummycall) {
			prawpartha->last_listen_state_tusec_ = curr_tusec;
			prawpartha->summstats_ = summstats;

			if (isrtadef && tlastsumm && curr_tusec < tlastsumm + GY_USEC_PER_MINUTE) {
				svcsumm_rtalert_rwlocked(*prawpartha, lastsummstats, tvsec, timebuf.get()); 
			}
		}
	
		// Offline the thread now
		slowlock.unlock();

		if (isrtadef) {
			rtscope.unlock();
		}

		topmutex.unlock();

		nremmad = send_mm_listener_issue(mmissue_map, false /* is_remote */, pthrpoolarr);

		for (const auto & epair : delmap) {
			uint64_t	 	madid = epair.first;
			const auto 		& madvec = epair.second.vec_;
			const auto		& shrconn = epair.second.shrconn_;

			if (!shrconn || (madvec.empty())) {
				continue;
			}

			nremmaddel++;

			DEBUGEXECN(5,
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Sending %lu Listener Delete Messages to Remote Madhava %s\n",
					madvec.size(), shrconn->print_peer(STRING_BUFFER<256>().get_str_buf()));
			);

			size_t			fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + madvec.size() * sizeof(MM_LISTENER_DELETE);
			FREE_FPTR		free_fp;
			uint32_t		act_size;
			void			*palloc = pthrpoolarr->safe_malloc(fixed_sz, free_fp, act_size);

			COMM_HEADER		*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
			EVENT_NOTIFY		*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1);
			MM_LISTENER_DELETE	*plist = reinterpret_cast<MM_LISTENER_DELETE *>(pnot + 1);

			new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, fixed_sz, shrconn->get_comm_magic());
			new (pnot) EVENT_NOTIFY(comm::NOTIFY_MM_LISTENER_DELETE, madvec.size());
			
			std::memcpy(plist, madvec.data(), madvec.size() * sizeof(MM_LISTENER_DELETE));

			schedule_l1_send_data(shrconn, comm::COMM_EVENT_NOTIFY, EPOLL_IOVEC_ARR(2, false, palloc, fixed_sz, free_fp, gpadbuf, phdr->get_pad_len(), nullptr));
		}	

	}

	if (ndbarr > 0 || tlastsumm) {

		// Update the DB
		assert(gy_get_thread_local().get_thread_stack_freespace() >= max_db_query_sz /* 512 KB */ + 64 * 1024);

		STRING_BUFFER<max_db_query_sz>	qbuf;

		auto				datetbl = get_db_day_partition(tvsec, tvsec, 15, &tdaystart);

		auto				schemabuf = prawpartha->get_db_schema();

		auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 10'000 /* max_msec_wait */, false /* reset_on_timeout */);
		
		if (!pconn) {
			db_stats_.nconns_failed_.fetch_add_relaxed(1);
			db_stats_.nlisten_state_failed_.fetch_add_relaxed(1);
			
			DEBUGEXECN(5,
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get DB Conn for Partha %s Listener State updation\n", prawpartha->hostname_);
			);
			
			goto done1;
		}	
		
		qbuf.appendconst("Begin Work;");

		if (ndbarr > 0) {
			qbuf.appendfmt("insert into %s.listenstatetbl%s values ", schemabuf.get(), datetbl.get());

			for (int i = 0; i < ndbarr; ++i) {
				const LISTENER_STATE_NOTIFY	*pone = dbarr[i].pone_;
				
				qbuf.appendfmt("(\'%s\',\'%016lx\',\'%s\',"
						"%d,%d,%d,%d,%d,%d,%d,%d,"
						"%d,%d,%d,%d,"
						"%d,%d,%d,%d,"
						"%d,%d,%d,"
						"%hd,%hd,%hd,%hd,\'%c\',\'", 
					timebuf.get(), pone->glob_id_, dbarr[i].comm_, 
					
					pone->nqrys_5s_/5, pone->nqrys_5s_, pone->total_resp_5sec_/(pone->nqrys_5s_ > 0 ? pone->nqrys_5s_ : 1),
					pone->p95_5s_resp_ms_, pone->p95_5min_resp_ms_, pone->nconns_, pone->nconns_active_, pone->ntasks_, 
					
					pone->curr_kbytes_inbound_, pone->curr_kbytes_outbound_, pone->ser_http_errors_, pone->cli_http_errors_,
					
					pone->tasks_delay_usec_, pone->tasks_cpudelay_usec_, pone->tasks_blkiodelay_usec_, 
					pone->tasks_delay_usec_ - pone->tasks_cpudelay_usec_ - pone->tasks_blkiodelay_usec_,
					
					pone->tasks_user_cpu_, pone->tasks_sys_cpu_, pone->tasks_rss_mb_,

					pone->ntasks_issue_, pone->curr_state_, pone->curr_issue_, pone->issue_bit_hist_, pgintbool[pone->is_http_svc_ & 0x1]);

				// Only save issue strings for states Bad and higher
				if (pone->curr_state_ >= STATE_BAD && pone->issue_string_len_ > 0) {
					qbuf.append((const char *)(pone + 1), pone->issue_string_len_ - 1);
				}
				qbuf.appendconst("\'),");
			}	

			qbuf.set_last_char(';');
		}

		if (tlastsumm) {
			time_t				lastsum = tlastsumm/GY_USEC_PER_SEC;
			auto				lasttimebuf = gy_localtime_iso8601_sec(lastsum);

			qbuf.appendfmt("\n insert into %s.listensummtbl%s values (\'%s\', %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d);", 
				schemabuf.get(), lastsum > tdaystart ? datetbl.get() : "", 
				lasttimebuf.get(), lastsummstats.nstates_[STATE_IDLE], lastsummstats.nstates_[STATE_GOOD], lastsummstats.nstates_[STATE_OK],
				lastsummstats.nstates_[STATE_BAD], lastsummstats.nstates_[STATE_SEVERE], lastsummstats.nstates_[STATE_DOWN], lastsummstats.tot_qps_, lastsummstats.tot_act_conn_,
				lastsummstats.tot_kb_inbound_, lastsummstats.tot_kb_outbound_, lastsummstats.tot_ser_errors_, lastsummstats.nlisteners_, lastsummstats.nactive_);
		}
	
		qbuf.appendconst("Commit Work;");

		if (gy_unlikely(true == qbuf.is_overflow())) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Internal Error : Listener State DB insert buffer overflow occured for Partha %s\n",
				prawpartha->hostname_);
			goto done1;
		}

		bret = PQsendQueryOptim(pconn->get(), qbuf.buffer(), qbuf.size());
		
		if (bret == false) {
			db_stats_.nlisten_state_failed_.fetch_add_relaxed(1);

			DEBUGEXECN(5,
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to schedule DB query to update Partha %s Listener State due to %s\n", 
					prawpartha->hostname_, PQerrorMessage(pconn->get()));
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
					db_stats_.nlisten_state_failed_.fetch_add_relaxed(1);

					DEBUGEXECN(5,
						ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to insert Partha Listener State into DB due to %s\n", gyres.get_error_msg());
					);

					return false;
				}	

				return true;
			}
		);
	}

	if (ndbdel > 0) {
		// Update the DB
		assert(gy_get_thread_local().get_thread_stack_freespace() >= 128 * 1024 + 64 * 1024);

		STRING_BUFFER<128 * 1024>	qbuf;
		auto				timebuf = gy_localtime_iso8601_sec(time(nullptr) + LISTENER_DB_STORE_SEC);
		auto				schemabuf = prawpartha->get_db_schema();
		auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 10'000 /* max_msec_wait */, false /* reset_on_timeout */);
		
		if (!pconn) {
			db_stats_.nconns_failed_.fetch_add_relaxed(1);
			db_stats_.nlisten_del_failed_.fetch_add_relaxed(1);
			
			DEBUGEXECN(5,
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get DB Conn for Delete Listeners for Partha %s\n", prawpartha->hostname_);
			);
			
			goto done1;
		}	

		qbuf.appendfmt("update %s.listentbl set del_after = \'%s\' where glob_id in ( \'0000000000000000\',", schemabuf.get(), timebuf.get());

		for (int i = 0; i < ndbdel; ++i) {
			const LISTENER_STATE_NOTIFY	*pone = dbdelarr[i].pone_;

			qbuf.appendfmt("\'%016lx\',", pone->glob_id_);
		}	

		qbuf.set_last_char(' ');

		qbuf.appendconst(");");

		if (gy_unlikely(true == qbuf.is_overflow())) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Internal Error : Delete Listener buffer overflow occured for Partha %s\n", prawpartha->hostname_);
			goto done1;
		}

		bret = PQsendQueryOptim(pconn->get(), qbuf.buffer(), qbuf.size());
		
		if (bret == false) {
			db_stats_.nlisten_del_failed_.fetch_add_relaxed(1);

			DEBUGEXECN(5,
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to schedule DB query for Delete Listener updation for Partha %s due to %s\n", 
					prawpartha->hostname_, PQerrorMessage(pconn->get()));
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
					db_stats_.nlisten_del_failed_.fetch_add_relaxed(1);
	
					DEBUGEXECN(5,
						ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to set Delete Listener in DB due to %s\n", gyres.get_error_msg());
					);

					return false;
				}	

				return true;
			}
		);

	}	

	if (nnatip > 0 && natvec.has_value() && natvec->size() > 0) {
		
		auto				shrconn = gshyama_.get_last_conn(comm::CLI_TYPE_REQ_RESP);

		if (shrconn) {

			size_t			fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + natvec->size() * sizeof(MS_LISTENER_NAT_IP) + nnatip * sizeof(IP_PORT); 
			FREE_FPTR		free_fp;
			uint32_t		act_size;
			void			*palloc = pthrpoolarr->opt_safe_malloc(pthrpoolarr, fixed_sz + 64, free_fp, act_size, false /* try_other_pools */);

			COMM_HEADER		*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
			EVENT_NOTIFY		*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1);
			MS_LISTENER_NAT_IP	*pconn = reinterpret_cast<MS_LISTENER_NAT_IP *>(pnot + 1);

			uint64_t		madhava_id = gmadhava_id_;

			new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, fixed_sz, shrconn->get_comm_magic());
			new (pnot) EVENT_NOTIFY(comm::NOTIFY_MS_LISTENER_NAT_IP, natvec->size());

			for (const auto & nelem : *natvec) {
				new (pconn) MS_LISTENER_NAT_IP(prawpartha->machine_id_, madhava_id, nelem.glob_id_, prawpartha->cluster_name_, nelem.comm_, nelem.nelem_new_, nelem.nelem_del_);

				IP_PORT			*pip = (IP_PORT *)(pconn + 1);
				auto			n = std::max(nelem.nelem_del_, nelem.nelem_new_);	// Either Ping or Delete not both

				for (uint8_t i = 0; i < n && i < GY_ARRAY_SIZE(nelem.ip_ports_); ++i) {
					new (pip++) IP_PORT(nelem.ip_ports_[i]);
				}	

				pconn = (decltype(pconn))((uint8_t *)pconn + pconn->get_elem_size());
			}

			schedule_l1_send_data(shrconn, comm::COMM_EVENT_NOTIFY, EPOLL_IOVEC_ARR(2, false, palloc, fixed_sz, free_fp, gpadbuf, phdr->get_pad_len(), nullptr));
		}
	}

	// TODO Update DB deplistenissuetbl for any listener issue resolutions

done1 :
	if ((nissues + ndeleted + nmissed + nerrors + nlisten_resolved > 0) || gdebugexecn >= 12) {
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "%s : Received %d Listener States : "
			"%d Listeners are good : %d have issues : Missed %d : %d Deleted : %d Errors seen : "
			"%d Listener Issues Resolved : %d Remote Madhavas Updated for Issue : %d Remote Madhavas sent Listener Deletion : %d Shyama NAT Pings/Deletes : %d DB States Updated\n", 
			prawpartha->print_string(STRING_BUFFER<256>().get_str_buf()), nconns, prawpartha->summstats_.nstates_[STATE_IDLE] + prawpartha->summstats_.nstates_[STATE_GOOD], 
			nissues, nmissed, ndeleted, nerrors, nlisten_resolved, nremmad, nremmaddel, nnatip, ndbarr);
	}

	if (nerrors > 0) {
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "%s : Received %d Errored Listener States which were ignored.\n",
			prawpartha->print_string(STRING_BUFFER<256>().get_str_buf()), nerrors);
	}	

	return true;
}	

bool MCONN_HANDLER::handle_mm_listener_issue(const std::shared_ptr<MADHAVA_INFO> & madshr, const comm::MM_LISTENER_ISSUE_RESOL * pone, int nevents, uint8_t *pendptr, POOL_ALLOC_ARRAY *pthrpoolarr)
{
	MADHAVA_INFO	 		*pmadhava = madshr.get(); 
	
	if (!pmadhava) {
		return false;
	}	

	DOWNSTREAM_VEC_ARENA		downvec_arena;
	RESOL_MM_MAP_ARENA		resol_arena;
	MM_LISTENER_ISSUE_MAP_ARENA	mmissue_map_arena;
	MM_LISTENER_ISSUE_MAP		mmissue_map(mmissue_map_arena);

	RCU_LOCK_SLOW			slowlock;

	const uint64_t			curr_tusec = get_usec_time(), cutoff_usec = curr_tusec - 2 * GY_USEC_PER_SEC;
	int				nlisten_resolved = 0, nmissed = 0, nremmad = 0, nold = 0;
	bool				bret;
	
	for (int i = 0; i < nevents && (const uint8_t *)pone < pendptr; ++i) {
		const size_t				elem_sz = pone->get_elem_size();
		MM_LISTENER_ISSUE_RESOL::DOWNSTREAM_ONE	*pdown;
		MM_LISTENER_ISSUE_RESOL			resol = *pone;
		
		if (pone->issue_src_time_usec_ < cutoff_usec) {
			nold++;
			goto next1;
		}
		
		pdown = (decltype(pdown))(pone + 1);

		for (int d = 0; d < pone->ndownstreams_; ++d, pdown++) {
			auto [glob_id, downstream_state, downstream_issue, downstream_issue_bit_hist, src_upstream_tier] = pdown->get_data();

			const uint32_t			lhash = get_uint64_hash(glob_id);
			bool				is_issue;
			MTCP_LISTENER			*plistener;
			MTCP_LISTENER_ELEM_TYPE 	*pdatanode;
			LISTENER_STATE_NOTIFY		state;

			pdatanode = pmadhava->listen_tbl_.lookup_single_elem_locked(glob_id, lhash);

			if (gy_unlikely(nullptr == pdatanode)) {
				nmissed++;
				continue;
			}	

			plistener = pdatanode->get_cref().get();
			if (gy_unlikely(nullptr == plistener)) {
				goto next1;
			}	
			
			state.glob_id_			= glob_id;
			state.curr_state_		= downstream_state;
			state.curr_issue_		= downstream_issue;
			state.issue_bit_hist_		= downstream_issue_bit_hist;

			plistener->set_state(&state, curr_tusec);

			nlisten_resolved += (int)handle_dependency_issue(plistener, resol, src_upstream_tier, mmissue_map, resol_arena, downvec_arena);
		}

next1 :
		pone = (decltype(pone))((uint8_t *)pone + elem_sz);
	}	

	// Offline the thread now
	slowlock.unlock();

	nremmad = send_mm_listener_issue(mmissue_map, true /* is_remote */, pthrpoolarr);

	if ((nlisten_resolved + nremmad + nold > 0) || gdebugexecn >= 5) {
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Received %d Listener Issue Resolutions from Remote Madhava %s : "
			"%d Missed : %d Too Old : %d Listener Issues Resolved : %d Remote Madhavas Updated\n", 
			nevents, pmadhava->get_domain(), nmissed, nold, nlisten_resolved, nremmad);
	}

	return true;
}

bool MCONN_HANDLER::handle_mm_listener_depends(const std::shared_ptr<MADHAVA_INFO> & madshr, const comm::MM_LISTENER_DEPENDS * pone, int nevents, POOL_ALLOC_ARRAY *pthrpoolarr)
{
	MADHAVA_INFO	 		*pmadhava = madshr.get(); 
	
	if (!pmadhava) {
		return false;
	}	

	RCU_LOCK_SLOW			slowlock;

	const uint64_t			curr_tusec = get_usec_time();
	const uint64_t			madid = pmadhava->madhava_id_;
	const uint32_t			madhash = get_uint64_hash(madid);
	int				nmissed = 0, nadded = 0, ndel = 0;
	bool				bret;
	
	for (int i = 0; i < nevents; ++i, pone++) {
		const uint64_t			glob_id = pone->glob_id_;
		const uint32_t			lhash = get_uint64_hash(glob_id);
		MTCP_LISTENER_ELEM_TYPE		*plistelem;
		MTCP_LISTENER			*pdeplistener;
		WEAK_REMOTE_MADHAVA		*pweakmad;
	
		plistelem = glob_listener_tbl_.lookup_single_elem_locked(glob_id, lhash);

		if (gy_unlikely(plistelem == nullptr)) {
			nmissed++;
			continue;
		}	
		
		pdeplistener = plistelem->get_cref().get();

		if (gy_unlikely(pdeplistener == nullptr)) {
			continue;
		}	

		pweakmad = pdeplistener->remote_madhava_tbl_->lookup_single_elem_locked(madid, madhash);

		if (pone->delete_depends_) {
			if (pweakmad) {
				pdeplistener->remote_madhava_tbl_->delete_elem_locked(pweakmad);
				ndel++;
			}	

			continue;
		}

		pdeplistener->is_load_balanced_ |= pone->is_load_balanced_;
		
		if (gy_unlikely(pweakmad == nullptr)) {
			FREE_FPTR			free_fp;
			uint32_t			act_size;

			pweakmad = (WEAK_REMOTE_MADHAVA *)pthrpoolarr->safe_malloc(sizeof(WEAK_REMOTE_MADHAVA), free_fp, act_size, false /* try_other_pools */, true /* use_malloc_hdr */);

			new (pweakmad) WEAK_REMOTE_MADHAVA(pmadhava->weak_from_this(), pmadhava->madhava_id_, curr_tusec);

			auto newmad = [](WEAK_REMOTE_MADHAVA *poldelem, WEAK_REMOTE_MADHAVA *pnewelem)
			{
				poldelem->listen_depends_ = true;
			};

			pdeplistener->remote_madhava_tbl_->insert_unique(pweakmad, madid, madhash, newmad, true /* delete_after_callback */);

			nadded++;
		}	
		else {
			pweakmad->listen_depends_ = true;
		}	
	}	

	slowlock.unlock();

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN_ITALIC, "Remote %s Listener Dependency : Total Events %d : Missed %d : Deleted %d : Newly Added %d\n",
		pmadhava->print_string(STRING_BUFFER<256>().get_str_buf()), nevents, nmissed, ndel, nadded);

	return true;
}


size_t MCONN_HANDLER::send_mm_listener_issue(MM_LISTENER_ISSUE_MAP & mmissue_map, bool is_remote, POOL_ALLOC_ARRAY *pthrpoolarr)
{
	size_t			nremmad = 0;

	for (auto && mpair : mmissue_map) {
		uint64_t	 	madid = mpair.first, totaldownvec_count = mpair.second.totaldownvec_count_;
		auto			& resmap = mpair.second.resmap_;
		const auto		& shrconn = mpair.second.shrconn_;

		if (!shrconn || (resmap.empty())) {
			continue;
		}

		nremmad++;

		DEBUGEXECN(5,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Sending %lu%s Listener Issue Resolve Messages to Remote Madhava %s : Total Downstream Listeners referenced %lu\n",
				resmap.size(), is_remote ? " Remote" : "", shrconn->print_peer(STRING_BUFFER<256>().get_str_buf()), totaldownvec_count);
		);

		size_t			fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + resmap.size() * sizeof(MM_LISTENER_ISSUE_RESOL) + 
						totaldownvec_count * sizeof(MM_LISTENER_ISSUE_RESOL::DOWNSTREAM_ONE) + resmap.size() * 8 /* alignment */ + 64;
		size_t			nmsg = 0, totsz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY);				
		FREE_FPTR		free_fp;
		uint32_t		act_size;
		void			*palloc = pthrpoolarr->safe_malloc(fixed_sz, free_fp, act_size), *pendbuf = (uint8_t *)palloc + fixed_sz;

		COMM_HEADER		*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
		EVENT_NOTIFY		*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1);
		MM_LISTENER_ISSUE_RESOL	*plist = reinterpret_cast<MM_LISTENER_ISSUE_RESOL *>(pnot + 1);

		for (auto && epair : resmap) {
			auto			& resol = epair.second.resol_;
			auto 			& downvec = epair.second.downvec_;
			size_t			elemsz;

			if (downvec.empty()) {
				continue;
			}

			resol.ndownstreams_ = downvec.size();
			resol.set_padding_len();

			elemsz = resol.get_elem_size();

			if ((uint8_t *)plist + elemsz < pendbuf) {
				std::memcpy(plist, &resol, sizeof(resol));
				std::memcpy((uint8_t *)plist + sizeof(resol), downvec.data(), downvec.size() * sizeof(MM_LISTENER_ISSUE_RESOL::DOWNSTREAM_ONE));

				plist = (decltype(plist))((uint8_t *)plist + elemsz);

				nmsg++;
				totsz += elemsz;
			}	
			else {
				break;
			}	
		}
		
		if (nmsg == 0) {
			continue;
		}	

		new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, totsz, shrconn->get_comm_magic());
		new (pnot) EVENT_NOTIFY(comm::NOTIFY_MM_LISTENER_ISSUE_RESOL, nmsg);
		
		schedule_l1_send_data(shrconn, comm::COMM_EVENT_NOTIFY, EPOLL_IOVEC_ARR(2, false, palloc, phdr->get_act_len(), free_fp, gpadbuf, phdr->get_pad_len(), nullptr));
	}	

	return nremmad;
}	

bool MCONN_HANDLER::handle_mm_listener_ping(const std::shared_ptr<MCONNTRACK> &connshr, const comm::MM_LISTENER_PING *pone, int nevents)
{
	auto				madshr = connshr->get_madhava_shared();
	MADHAVA_INFO	 		*pmadhava = madshr.get(); 
	
	if (!pmadhava) {
		return false;
	}	

	uint64_t			tusec = get_usec_time();
	int				npings = 0;
	bool				bret;
	RCU_LOCK_SLOW			slowlock;
	
	for (int i = 0; i < nevents; ++i, ++pone) {
		MTCP_LISTENER			*plistener;
		MTCP_LISTENER_ELEM_TYPE 	*pdatanode;
		const uint64_t			glob_id = pone->glob_id_;
		const uint32_t			lhash = get_uint64_hash(glob_id);

		pdatanode = pmadhava->listen_tbl_.lookup_single_elem_locked(glob_id, lhash);
		if (gy_unlikely(nullptr == pdatanode)) {
			continue;
		}	

		plistener = pdatanode->get_cref().get();
		if (gy_unlikely(nullptr == plistener)) {
			continue;
		}	
		
		npings++;

		plistener->rem_madhava_ping_tusec_ = tusec;
	}	

	slowlock.unlock();

	DEBUGEXECN(10, 
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Remote Listener Ping : Pings for %d listeners of total %d from Remote %s\n",
			npings, nevents, pmadhava->print_string(STRING_BUFFER<256>().get_str_buf()));
	);

	return true;
}	


bool MCONN_HANDLER::handle_mm_listener_delete(const std::shared_ptr<MADHAVA_INFO> &madshr, const comm::MM_LISTENER_DELETE *pone, int nevents, bool isdummycall)
{
	MADHAVA_INFO	 		*pmadhava = madshr.get(); 
	
	if (!pmadhava) {
		return false;
	}	

	RCU_LOCK_SLOW			slowlock;
	int				ndeleted = 0;
	bool				bret;
	
	for (int i = 0; i < nevents; ++i, ++pone) {
		MTCP_LISTENER			*plistener;
		MTCP_LISTENER_ELEM_TYPE 	*pdatanode;
		const uint64_t			glob_id = pone->glob_id_;
		const uint32_t			lhash = get_uint64_hash(glob_id);

		pdatanode = pmadhava->listen_tbl_.lookup_single_elem_locked(glob_id, lhash);
		if (gy_unlikely(nullptr == pdatanode)) {
			continue;
		}	

		plistener = pdatanode->get_cref().get();
		if (gy_unlikely(nullptr == plistener)) {
			continue;
		}	
		
		ndeleted++;

		auto relam = [glob_id, lhash](MRELATED_LISTENER_ELEM_TYPE *pdatanode, void *arg) -> CB_RET_E
		{
			auto ptrel = pdatanode->get_ref().get();

			if (ptrel) {
				ptrel->depended_id_tbl_.delete_single_elem(glob_id, lhash);
			}	

			return CB_DELETE_ELEM;
		};

		plistener->depending_related_tbl_.walk_hash_table(relam);

		pmadhava->listen_tbl_.delete_elem_locked(pdatanode);
	}	

	slowlock.unlock();

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Remote Listener Delete : Deleted %d of total %d from Remote %s\n",
			ndeleted, nevents, pmadhava->print_string(STRING_BUFFER<256>().get_str_buf()));

	return true;
}	

bool MCONN_HANDLER::partha_listener_dependency(const std::shared_ptr<PARTHA_INFO> & partha_shr, const comm::LISTENER_DEPENDENCY_NOTIFY * ponelisten, int nelems, uint8_t *pendptr, STATS_STR_MAP & statsmap, POOL_ALLOC_ARRAY *pthrpoolarr)
{
	if (!partha_shr) {
		return false;
	}

	using MMDepListMap		= GY_STACK_HASH_MAP<uint64_t, MM_LISTENER_DEPENDS, 50 * 1024, GY_JHASHER<uint64_t>>;
	using MMDepListMapArena		= MMDepListMap::allocator_type::arena_type;

	struct MMDepListMapSize
	{
		MMDepListMap			listmap_;
		std::shared_ptr<MCONNTRACK>	shrconn_;

		MMDepListMapSize(MMDepListMapArena & arena) : listmap_(arena)
		{}
	};

	using MMDepMap			= GY_STACK_HASH_MAP<uint64_t, MMDepListMapSize, 80 * 1024, GY_JHASHER<uint64_t>>;
	using MMDepMapArena		= MMDepMap::allocator_type::arena_type;

	MMDepListMapArena		deplistmaparena;
	MMDepMapArena			depmaparena;
	MMDepMap			depmap(depmaparena);

	PARTHA_INFO 			*prawpartha = partha_shr.get(); 
	const uint64_t			curr_tusec = get_usec_time();
	int				nmissed = 0, nlistmissed = 0, ndeleted = 0, nadded = 0, nremmad = 0, nmadmissed = 0, nipport = 0, nexcept = 0;
	const uint64_t			curr_madhava_id = gmadhava_id_;
	bool				bret;
	
	RCU_LOCK_SLOW			slowlock;

	auto depremote = [&](const std::weak_ptr <MADHAVA_INFO> & weakmad, uint64_t madhava_id, uint64_t glob_id, bool delete_depends, bool is_load_balanced = false)
	{
		auto 		[it, success] = depmap.try_emplace(madhava_id, deplistmaparena);

		if (success == true) {
			auto	madshr = weakmad.lock();

			if (madshr) {
				it->second.shrconn_ = madshr->get_last_conn(comm::CLI_TYPE_REQ_RESP);
			}	
		}

		if (it->second.shrconn_) {
			auto 	[mit, isnew] = it->second.listmap_.try_emplace(glob_id, glob_id, delete_depends, is_load_balanced);

			if (false == isnew) {
				mit->second.is_load_balanced_	|= is_load_balanced;

				if (mit->second.delete_depends_ != delete_depends && false == delete_depends) {
					mit->second.delete_depends_ = false;
				}	
			}	
		}	
	};	


	for (int i = 0; i < nelems && (const uint8_t *)ponelisten < pendptr; ++i) {
		const size_t			elem_sz = ponelisten->get_elem_size();
		const int			ndepends = ponelisten->ndepends_;
		MRELATED_LISTENER_ELEM_TYPE	*prelnode;
		MRELATED_LISTENER		*prelated;
		const uint64_t			relid = ponelisten->related_listen_id_;
		const uint32_t			rhash = get_uint64_hash(relid);
		auto				pdepone = (LISTENER_DEPENDENCY_NOTIFY::DEPENDS_ONE *)(ponelisten + 1);
		
		prelnode = prawpartha->related_listen_tbl_.lookup_single_elem_locked(relid, rhash);

		if (gy_unlikely(nullptr == prelnode)) {
			nmissed++;
			goto next1;
		}	

		prelated = prelnode->get_cref().get();

		if (gy_unlikely(nullptr == prelated)) {
			goto next1;
		}	

		for (int d = 0; d < ndepends; ++d, ++pdepone) {

			try {
				if (pdepone->glob_id_) {

					MTCP_LISTENER_ELEM_TYPE 	*pdatanode = nullptr, *pnewdatanode = nullptr;
					MTCP_LISTENER			*pdeplistener = nullptr;
					MRELATED_LISTENER_ELEM_TYPE	*pnewrelnode = nullptr;
					const uint64_t			glob_id = pdepone->glob_id_;
					const uint32_t			lhash = get_uint64_hash(glob_id);
					
					pdatanode = prelated->depended_id_tbl_.lookup_single_elem_locked(glob_id, lhash);
					
					if (pdatanode) {
						pdeplistener = pdatanode->get_cref().get();

						if (pdeplistener == nullptr) {
							prelated->depended_id_tbl_.delete_elem_locked(pdatanode);
						}	
						else {
							const bool		is_rem = pdeplistener->is_remote_madhava_;

							nremmad += int(is_rem);

							if (pdepone->delete_depends_ == true) {
								pdeplistener->depending_related_tbl_.delete_single_elem(relid, rhash);

								if (is_rem && true == pdeplistener->depending_related_tbl_.is_empty()) {
									depremote(pdeplistener->madhava_weak_, pdeplistener->madhava_id_, glob_id, true /* delete_depends */);
								}	

								prelated->depended_id_tbl_.delete_elem_locked(pdatanode);

								ndeleted++;
							}	
							else {
								pdeplistener->is_load_balanced_ |= pdepone->is_load_balanced_;
		
								if (is_rem) {
									depremote(pdeplistener->madhava_weak_, pdeplistener->madhava_id_, glob_id, 
											false /* delete_depends */, pdeplistener->is_load_balanced_);
								}
							}	

							continue;
						}	
					}	

					if (pdepone->delete_depends_ == true) {
						continue;
					}	

					// Need to add a new dependency

					if (pdepone->is_localhost_) {
						pdatanode = prawpartha->listen_tbl_.lookup_single_elem_locked(glob_id, lhash);

						if (gy_unlikely(nullptr == pdatanode)) {
							nlistmissed++;
							continue;
						}	

						pdeplistener = pdatanode->get_cref().get();
				
						if (gy_unlikely(nullptr == pdeplistener)) {
							nlistmissed++;
							continue;
						}

						pnewdatanode = new MTCP_LISTENER_ELEM_TYPE(pdatanode->get_cref());
						prelated->depended_id_tbl_.insert_or_replace(pnewdatanode, glob_id, lhash);

						pnewrelnode = new MRELATED_LISTENER_ELEM_TYPE(prelnode->get_cref());
						pdeplistener->depending_related_tbl_.insert_or_replace(pnewrelnode, relid, rhash);

						pdeplistener->is_load_balanced_ |= pdepone->is_load_balanced_;

						nadded++;

						continue;
					}	
					else if (pdepone->madhava_id_ == curr_madhava_id) {
		
						pdatanode = glob_listener_tbl_.lookup_single_elem_locked(pdepone->glob_id_, get_uint64_hash(pdepone->glob_id_));

						if (gy_unlikely(pdatanode == nullptr)) {
							nlistmissed++;
							continue;
						}	
						
						pdeplistener = pdatanode->get_cref().get();

						if (gy_unlikely(pdeplistener == nullptr)) {
							nlistmissed++;
							continue;
						}	

						pnewdatanode = new MTCP_LISTENER_ELEM_TYPE(std::move(pdeplistener->shared_from_this()));
						prelated->depended_id_tbl_.insert_or_replace(pnewdatanode, glob_id, lhash);

						pnewrelnode = new MRELATED_LISTENER_ELEM_TYPE(prelnode->get_cref());
						pdeplistener->depending_related_tbl_.insert_or_replace(pnewrelnode, relid, rhash);

						pdeplistener->is_load_balanced_ |= pdepone->is_load_balanced_;

						nadded++;

						continue;
					}	
					else {
						MADHAVA_INFO_ELEM 	*pelem;

						pelem = madhava_tbl_.lookup_single_elem_locked(pdepone->madhava_id_, get_uint64_hash(pdepone->madhava_id_));

						if (gy_unlikely(nullptr == pelem)) {
							nmadmissed++;
							continue;
						}	

						auto			pmad = pelem->get_cref().get();

						pdatanode = pmad->listen_tbl_.lookup_single_elem_locked(glob_id, lhash);

						if (gy_unlikely(nullptr == pdatanode)) {
							nlistmissed++;
							continue;
						}	

						pdeplistener = pdatanode->get_cref().get();
				
						if (gy_unlikely(nullptr == pdeplistener)) {
							nlistmissed++;
							continue;
						}

						pnewdatanode = new MTCP_LISTENER_ELEM_TYPE(pdatanode->get_cref());
						prelated->depended_id_tbl_.insert_or_replace(pnewdatanode, glob_id, lhash);

						pnewrelnode = new MRELATED_LISTENER_ELEM_TYPE(prelnode->get_cref());
						pdeplistener->depending_related_tbl_.insert_or_replace(pnewrelnode, relid, rhash);

						pdeplistener->is_load_balanced_ |= pdepone->is_load_balanced_;

						depremote(pdeplistener->madhava_weak_, pdeplistener->madhava_id_, glob_id, false /* delete_depends */, pdeplistener->is_load_balanced_);
						
						nadded++;
						nremmad++;

						continue;
					}
				}	
				else {
					/*
					 * We currently do not use the depended_ipport_tbl_ . Uncomment this if needed
					 */
					/*			
					MIP_PORT		*pipport;
					const IP_PORT		& ipport = pdepone->ns_ip_port_.ip_port_;
					const uint32_t		iphash = ipport.get_hash();

					nipport++;

					pipport = prelated->depended_ipport_tbl_.lookup_single_elem_locked(ipport, iphash);

					if (pipport) {
						if (pdepone->delete_depends_ == true) {
							prelated->depended_ipport_tbl_.delete_elem_locked(pipport);
							ndeleted++;
						}	
					}
					else {
						pipport = new MIP_PORT(ipport, curr_tusec);

						prelated->depended_ipport_tbl_.insert_or_replace(pipport, ipport, iphash);
						nadded++;
					}	
					*/
				}	
			}
			catch(...) {
				nexcept++;
			}	
		}

next1 :
		ponelisten = (decltype(ponelisten))((uint8_t *)ponelisten + elem_sz);
	}	

	slowlock.unlock();

	for (const auto & epair : depmap) {
		uint64_t	 	madid = epair.first;
		const auto 		& madlistmap = epair.second.listmap_;
		const auto		& shrconn = epair.second.shrconn_;

		if (!shrconn || (madlistmap.empty())) {
			continue;
		}

		DEBUGEXECN(5,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Sending %lu Listener Dependency Messages to Remote Madhava %s\n",
				madlistmap.size(), shrconn->print_peer(STRING_BUFFER<256>().get_str_buf()));
		);

		size_t			fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + madlistmap.size() * sizeof(MM_LISTENER_DEPENDS);
		FREE_FPTR		free_fp;
		uint32_t		act_size;
		void			*palloc = pthrpoolarr->safe_malloc(fixed_sz, free_fp, act_size);

		COMM_HEADER		*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
		EVENT_NOTIFY		*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1);
		MM_LISTENER_DEPENDS	*plist = reinterpret_cast<MM_LISTENER_DEPENDS *>(pnot + 1);

		new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, fixed_sz, shrconn->get_comm_magic());
		new (pnot) EVENT_NOTIFY(comm::NOTIFY_MM_LISTENER_DEPENDS, madlistmap.size());
		
		for (const auto & mpair : madlistmap) {
			*plist++ = mpair.second;
		}

		schedule_l1_send_data(shrconn, comm::COMM_EVENT_NOTIFY, EPOLL_IOVEC_ARR(2, false, palloc, fixed_sz, free_fp, gpadbuf, phdr->get_pad_len(), nullptr));
	}	

	if (nexcept > 0) {
		statsmap["Exception Occurred"] += nexcept;

		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "%d Exceptions encountered while handling Listener Dependency Updates from %s\n",
				nexcept, prawpartha->print_string(STRING_BUFFER<256>().get_str_buf()));
		);
	}	

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Listener Dependency Updates from %s and total count of %d : New Listener Dependencies %d, %d Deleted, %d unresolved external, "
		"%d Remote Madhava listeners, %d Related missed, %d listeners missed, %d exceptions\n",
		prawpartha->print_string(STRING_BUFFER<256>().get_str_buf()), nelems, nadded, ndeleted, nipport, nremmad, nmissed, nlistmissed, nexcept);
	
	return true;
}


bool MCONN_HANDLER::handle_listener_natip_notify(const std::shared_ptr<PARTHA_INFO> & partha_shr, const comm::LISTENER_NAT_IP_EVENT * porigone, int nevents, POOL_ALLOC_ARRAY *pthrpoolarr)
{
	if (!partha_shr) {
		return false;
	}

	struct NatList : public MS_LISTENER_NAT_IP
	{
		IP_PORT			nat_ip_ports_[2];
		IP_PORT			del_ip_ports_[2];
		
		using MS_LISTENER_NAT_IP::MS_LISTENER_NAT_IP;
	};	

	using NatVec			= INLINE_STACK_VECTOR<NatList, 80 * 1024>;

	NatVec				natvec;

	PARTHA_INFO 			*prawpartha = partha_shr.get(); 
	const uint64_t			curr_tusec = get_usec_time();
	auto				pone = porigone;
	uint64_t			madhava_id = gmadhava_id_;
	int				nmissed = 0, nnew = 0, ndel = 0;
		
	RCU_LOCK_SLOW			slowlock;

	for (int i = 0; i < nevents; ++i, ++pone) {
		MTCP_LISTENER			*plistener;
		MTCP_LISTENER_ELEM_TYPE 	*pdatanode;
		const uint64_t			glob_id = pone->glob_id_;
		const uint32_t			lhash = get_uint64_hash(glob_id);

		pdatanode = prawpartha->listen_tbl_.lookup_single_elem_locked(glob_id, lhash);

		if (gy_unlikely(nullptr == pdatanode)) {
			nmissed++;
			continue;
		}	

		plistener = pdatanode->get_cref().get();
		if (gy_unlikely(nullptr == plistener)) {
			continue;
		}	

		auto 			& nelem = natvec.emplace_back(prawpartha->machine_id_, madhava_id, glob_id, prawpartha->cluster_name_, plistener->comm_, 0, 0);
			
		if (plistener->nat_ip_port_arr_[0].port_ > 0) {
			if (plistener->nat_ip_port_arr_[0] != pone->nat_ip_port_arr_[0]) {
				ndel++;
				nelem.nelems_del_++;
				nelem.del_ip_ports_[0] = plistener->nat_ip_port_arr_[0];
			}	
		}	

		if (pone->nat_ip_port_arr_[0].port_) {
			nnew++;
			
			nelem.nelems_new_++;
			nelem.nat_ip_ports_[0] = pone->nat_ip_port_arr_[0];
			
			plistener->nat_ip_port_arr_[0] = pone->nat_ip_port_arr_[0];
		}	
		else {
			plistener->nat_ip_port_arr_[0] = {};
		}	

		if (plistener->nat_ip_port_arr_[1].port_ > 0) {
			if (plistener->nat_ip_port_arr_[1] != pone->nat_ip_port_arr_[1]) {
				ndel++;
				nelem.nelems_del_++;
				nelem.del_ip_ports_[1] = plistener->nat_ip_port_arr_[1];
			}	
		}	

		if (pone->nat_ip_port_arr_[1].port_) {
			nnew++;
			
			nelem.nelems_new_++;
			nelem.nat_ip_ports_[1] = pone->nat_ip_port_arr_[1];
			
			plistener->nat_ip_port_arr_[1] = pone->nat_ip_port_arr_[1];
		}	
		else {
			plistener->nat_ip_port_arr_[1] = {};
		}	

		plistener->last_nat_chg_ip_tsec_ = curr_tusec;

		auto 				relshr = plistener->related_listen_shr_.load(mo_relaxed);

		if (relshr && relshr->has_service_ip_ == false) {
			relshr->has_service_ip_	= true;
		}
	}	

	slowlock.unlock();


	if (!natvec.size()) {
		return false;
	}

	auto				shrconn = gshyama_.get_last_conn(comm::CLI_TYPE_REQ_RESP);

	if (!shrconn) {
		return false;
	}

	size_t				fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + natvec.size() * sizeof(MS_LISTENER_NAT_IP) + (nnew + ndel) * sizeof(IP_PORT); 
	FREE_FPTR			free_fp;
	uint32_t			act_size;
	void				*palloc = pthrpoolarr->opt_safe_malloc(pthrpoolarr, fixed_sz + 64, free_fp, act_size, false /* try_other_pools */);

	COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
	EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1);
	MS_LISTENER_NAT_IP		*pconn = reinterpret_cast<MS_LISTENER_NAT_IP *>(pnot + 1);

	new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, fixed_sz, shrconn->get_comm_magic());
	new (pnot) EVENT_NOTIFY(comm::NOTIFY_MS_LISTENER_NAT_IP, natvec.size());

	for (const auto & nelem : natvec) {
		new (pconn) MS_LISTENER_NAT_IP(nelem);

		IP_PORT			*pip = (IP_PORT *)(pconn + 1);

		for (uint8_t i = 0; i < nelem.nelems_new_ && i < GY_ARRAY_SIZE(NatList::nat_ip_ports_); ++i) {
			new (pip++) IP_PORT(nelem.nat_ip_ports_[i]);
		}	

		for (uint8_t i = 0; i < nelem.nelems_del_ && i < GY_ARRAY_SIZE(NatList::del_ip_ports_); ++i) {
			new (pip++) IP_PORT(nelem.del_ip_ports_[i]);
		}	

		pconn = (decltype(pconn))((uint8_t *)pconn + pconn->get_elem_size());
	}

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Partha %s : Received %d Listener NAT IP events of which %d were missed. Sending %lu bytes to Shyama Server\n",
		prawpartha->hostname_, nevents, nmissed, fixed_sz);

	return schedule_l1_send_data(shrconn, comm::COMM_EVENT_NOTIFY, EPOLL_IOVEC_ARR(2, false, palloc, fixed_sz, free_fp, gpadbuf, phdr->get_pad_len(), nullptr));
}	


bool MCONN_HANDLER::handle_listener_domain_notify(const std::shared_ptr<PARTHA_INFO> & partha_shr, const comm::LISTENER_DOMAIN_NOTIFY * porigone, int nevents)
{
	if (!partha_shr) {
		return false;
	}

	PARTHA_INFO 			*prawpartha = partha_shr.get(); 
	const uint64_t			curr_tusec = get_usec_time();
	auto				pone = porigone;
	int				nmissed = 0;

	RCU_LOCK_SLOW			slowlock;
		
	for (int i = 0; i < nevents; ++i, pone = (decltype(pone))((char *)pone + pone->get_elem_size())) {
		MTCP_LISTENER			*plistener;
		MTCP_LISTENER_ELEM_TYPE 	*pdatanode;
		const uint64_t			glob_id = pone->glob_id_;
		const uint32_t			lhash = get_uint64_hash(glob_id);

		pdatanode = prawpartha->listen_tbl_.lookup_single_elem_locked(glob_id, lhash);

		if (gy_unlikely(nullptr == pdatanode)) {
			nmissed++;
			continue;
		}	

		plistener = pdatanode->get_cref().get();
		if (gy_unlikely(nullptr == plistener)) {
			continue;
		}	

		if (pone->domain_string_len_ > 1 && pone->domain_string_len_ <= sizeof(plistener->server_domain_)) {
			std::memcpy(plistener->server_domain_, (const char *)(pone + 1), pone->domain_string_len_ - 1);
			plistener->server_domain_[pone->domain_string_len_ - 1] = 0;

			plistener->domain_string_len_ 	= pone->domain_string_len_ - 1;
		}

		if (pone->tag_len_ > 1) {
			auto relshr = plistener->related_listen_shr_.load(mo_relaxed);

			if (relshr && pone->tag_len_ <= sizeof(relshr->tagbuf_)) {
				std::memcpy(relshr->tagbuf_, (const char *)(pone + 1) + pone->domain_string_len_, pone->tag_len_ - 1);
				relshr->tagbuf_[pone->tag_len_ - 1] = 0;

				relshr->tag_len_ 	= pone->tag_len_ - 1;
			}
		}	
	}	

	slowlock.unlock();

	DEBUGEXECN(5, 
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "%s : Received %d Listener Domain updates of which %d were missed.\n",
			prawpartha->print_string(STRING_BUFFER<256>().get_str_buf()), nevents, nmissed);
	);

	return true;
}	

bool MCONN_HANDLER::handle_listener_cluster_info(const std::shared_ptr<PARTHA_INFO> & partha_shr, const comm::LISTENER_CLUSTER_NOTIFY * porigone, int nevents, uint8_t *pendptr, POOL_ALLOC_ARRAY *pthrpoolarr)
{
	if (!partha_shr) {
		return false;
	}

	PARTHA_INFO 			*prawpartha = partha_shr.get(); 
	const uint64_t			curr_tusec = get_usec_time(), local_madhava_id = gmadhava_id_;
	int				nmissed = 0, nclustelems = 0;

	MRELATED_LISTENER_ELEM_TYPE	*prelnode;
	MRELATED_LISTENER		*prelated;
	MTCP_LISTENER			*plistener;
	MTCP_LISTENER_ELEM_TYPE 	*pdatanode;

	auto				shrconn = gshyama_.get_last_conn(comm::CLI_TYPE_REQ_RESP);

	if (!shrconn) {
		return false;
	}

	auto				pone = porigone;

	for (int i = 0; i < nevents; ++i, pone = (decltype(pone))((char *)pone + pone->get_elem_size())) {
		nclustelems += pone->ncluster_elems_ + 1;
	}	
	
				
	size_t				fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + nevents * sizeof(MS_SVC_CLUSTER_MESH) + nclustelems * sizeof(RELSVC_CLUSTER_ONE),
					used_sz  = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY);
	FREE_FPTR			free_fp;
	uint32_t			act_size;
	void				*palloc = pthrpoolarr->opt_safe_malloc(pthrpoolarr, fixed_sz, free_fp, act_size, false /* try_other_pools */);

	COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
	EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1);
	MS_SVC_CLUSTER_MESH		*pconn = reinterpret_cast<MS_SVC_CLUSTER_MESH *>(pnot + 1);

	int				nconns = 0;
	
	RCU_LOCK_SLOW			slowlock;
		
	pone = porigone;

	for (int i = 0; i < nevents && used_sz + pone->get_elem_size() <= fixed_sz; ++i, pone = (decltype(pone))((char *)pone + pone->get_elem_size())) {

		const uint64_t			relid = pone->related_listen_id_;
		const uint32_t			rhash = get_uint64_hash(relid);

		prelnode = prawpartha->related_listen_tbl_.lookup_single_elem_locked(relid, rhash);

		if (gy_unlikely(nullptr == prelnode)) {
			nmissed++;
			continue;
		}	

		prelated = prelnode->get_cref().get();

		if (gy_unlikely(nullptr == prelated)) {
			continue;
		}	

		if (prelated->is_cluster_mesh_ == false) {
			prelated->is_cluster_mesh_ = true;
		}	

		if (prelated->svc_mesh_cluster_id_ == 0) {
			prelated->svc_mesh_cluster_id_ = prelated->new_cluster_id(gmadhava_id_);
		}	

		new (pconn) MS_SVC_CLUSTER_MESH(prelated->svc_mesh_cluster_id_, pone->ncluster_elems_ + 1, prawpartha->cluster_name_, prelated->init_comm_);
		
		RELSVC_CLUSTER_ONE		*pclout	= (RELSVC_CLUSTER_ONE *)(pconn + 1);
		const RELSVC_CLUSTER_ONE	*pclin 	= (const RELSVC_CLUSTER_ONE *)(pone + 1);

		new (pclout) RELSVC_CLUSTER_ONE(prawpartha->machine_id_, gmadhava_id_, pone->related_listen_id_);

		pclout++;

		for (uint32_t c = 0; c < pone->ncluster_elems_; ++c, ++pclout, ++pclin) {
			new (pclout) RELSVC_CLUSTER_ONE(*pclin);
		}

		used_sz += pconn->get_elem_size();
		pconn = decltype(pconn)((char *)pconn + pconn->get_elem_size());
		++nconns;
	}	

	slowlock.unlock();

	new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, used_sz, shrconn->get_comm_magic());
	new (pnot) EVENT_NOTIFY(comm::NOTIFY_MS_SVC_CLUSTER_MESH, nconns);

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Partha %s : Received %d Listener Cluster events of which %d were missed. Sending %lu bytes to Shyama Server\n",
		prawpartha->hostname_, nevents, nmissed, used_sz);

	return schedule_l1_send_data(shrconn, comm::COMM_EVENT_NOTIFY, EPOLL_IOVEC_ARR(2, false, palloc, used_sz, free_fp, gpadbuf, phdr->get_pad_len(), nullptr));
}	

void MCONN_HANDLER::handle_shyama_svc_mesh(const comm::SM_SVC_CLUSTER_MESH * porigone, int nevents, uint8_t *pendptr, POOL_ALLOC_ARRAY *pthrpoolarr)
{
	uint64_t			svc_cluster_id = 0, ntotal_cluster_svc = 0;
	time_t				tcurr = time(nullptr);

	CONDDECLARE(
		STRING_BUFFER<4096>		strbuf;
	);

	NOTCONDDECLARE(
		STRING_BUFFER<1024>		strbuf;
	);

	auto llam = [&](MTCP_LISTENER_ELEM_TYPE *pdatanode, void *arg)
	{
		auto 			plistener = pdatanode->get_cref().get();
	
		if (!plistener) {
			return CB_OK;
		}	

		plistener->eff_mesh_cluster_id_.store(svc_cluster_id, mo_relaxed);
		plistener->tlast_mesh_upd_ 	= tcurr;
		plistener->ntotal_mesh_svc_ 	= ntotal_cluster_svc;

		if (plistener->is_cluster_mesh_ == false) {
			plistener->is_cluster_mesh_ = true;
		}	

		return CB_OK;
	};	
	

	RCU_LOCK_SLOW			slowlock;

	auto				pone = porigone;

	for (int i = 0; i < nevents; ++i, pone = (decltype(pone))((char *)pone + pone->get_elem_size())) {
		
		svc_cluster_id 			= pone->svc_cluster_id_;
		ntotal_cluster_svc 		= pone->ntotal_cluster_svc_;

		strbuf.appendfmt("[Svc Mesh for Cluster %s Svc Comm %s #Total Svcs %u], ", pone->cluster_name_, pone->init_comm_, pone->ntotal_cluster_svc_);

		RELSVC_CLUSTER_ONE		*prel = (RELSVC_CLUSTER_ONE *)(pone + 1);

		for (int c = 0; c < (int)pone->nmadhava_elems_; c++, prel++) {
			auto				parelem = partha_tbl_.lookup_single_elem_locked(prel->partha_machine_id_, prel->partha_machine_id_.get_hash());
			
			if (!parelem) {
				continue;
			}	

			auto				prawpartha = parelem->get_cref().get();

			if (!prawpartha) {
				continue;
			}	

			const uint64_t			relid = prel->related_listen_id_;
			const uint32_t			rhash = get_uint64_hash(relid);

			auto				prelnode = prawpartha->related_listen_tbl_.lookup_single_elem_locked(relid, rhash);

			if (gy_unlikely(nullptr == prelnode)) {
				continue;
			}	

			auto				prelated = prelnode->get_cref().get();

			if (gy_unlikely(nullptr == prelated)) {
				continue;
			}	

			prelated->listener_table_.walk_hash_table(llam);
		}
	}	

	slowlock.unlock();

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Received %d Shyama Svc Mesh Cluster events : %s\n", nevents, strbuf.buffer());
}

void MCONN_HANDLER::handle_shyama_svc_natip_clust(const comm::SM_SVC_NAT_IP_CLUSTER * porigone, int nevents, uint8_t *pendptr, POOL_ALLOC_ARRAY *pthrpoolarr)
{
	CONDDECLARE(
		STRING_BUFFER<4096>		strbuf;
	);

	NOTCONDDECLARE(
		STRING_BUFFER<1024>		strbuf;
	);

	const auto			*pone = porigone;
	int				nprints = 0, nmissed = 0;

	RCU_LOCK_SLOW			slowlock;

	for (int i = 0; i < nevents; ++i, ++pone) {
		const uint64_t			glob_id = pone->glob_id_;
		const uint32_t			lhash = get_uint64_hash(glob_id);
		MTCP_LISTENER_ELEM_TYPE		*plistelem;
	
		plistelem = glob_listener_tbl_.lookup_single_elem_locked(glob_id, lhash);

		if (gy_unlikely(plistelem == nullptr)) {
			nmissed++;
			continue;
		}	
	
		auto 				plistener = plistelem->get_cref().get();
	
		if (!plistener) {
			continue;
		}	

		for (int j = 0; (uint32_t)j < GY_ARRAY_SIZE(plistener->nat_ip_port_arr_); ++j) {
			if (plistener->nat_ip_port_arr_[j] == pone->nat_ip_port_) {

				plistener->nat_ip_cluster_id_[j] 	= pone->nat_ip_cluster_id_;
				plistener->ntotal_nat_ip_svc_[j]	= pone->ntotal_cluster_svc_;

				GY_CC_BARRIER();

				plistener->is_cluster_nat_ip_[j]	= pone->ntotal_cluster_svc_ > 1;

				strbuf.appendfmt("[Svc NAT IP Cluster for Svc %s #Total Svcs %u], ", plistener->comm_, pone->ntotal_cluster_svc_);
				
				if (nprints++ == 3) {
					nprints = 0;
					strbuf << "\n\t";
				}	
				break;
			}
		}
	}	

	slowlock.unlock();

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Received %d Shyama Svc NAT IP Cluster events : Missed %d : \n\t%s\n", nevents, nmissed, strbuf.buffer());
}


bool MCONN_HANDLER::handle_listener_day_stats(const std::shared_ptr<PARTHA_INFO> & partha_shr, const comm::LISTENER_DAY_STATS * porigone, int nevents)
{
	if (!partha_shr) {
		return false;
	}

	RCU_LOCK_SLOW			slowlock;
	PARTHA_INFO 			*prawpartha = partha_shr.get(); 
	const uint64_t			curr_tusec = get_usec_time();
	auto				pone = porigone;
	int				nmissed = 0;
		
	for (int i = 0; i < nevents; ++i, pone = (decltype(pone))((char *)pone + pone->get_elem_size())) {
		MTCP_LISTENER			*plistener;
		MTCP_LISTENER_ELEM_TYPE 	*pdatanode;
		const uint64_t			glob_id = pone->glob_id_;
		const uint32_t			lhash = get_uint64_hash(glob_id);

		pdatanode = prawpartha->listen_tbl_.lookup_single_elem_locked(glob_id, lhash);

		if (gy_unlikely(nullptr == pdatanode)) {
			nmissed++;
			continue;
		}	

		plistener = pdatanode->get_cref().get();
		if (gy_unlikely(nullptr == plistener)) {
			continue;
		}	

		plistener->last_day_stats_tusec_	= curr_tusec;
		plistener->day_stats_ 			= *pone;
	}	

	slowlock.unlock();

	DEBUGEXECN(5, 
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "%s : Received %d Listener Day Stats of which %d were missed.\n",
			prawpartha->print_string(STRING_BUFFER<256>().get_str_buf()), nevents, nmissed);
	);

	return true;
}	

void MCONN_HANDLER::handle_cpu_mem_state(const std::shared_ptr<PARTHA_INFO> & partha_shr, const comm::CPU_MEM_STATE_NOTIFY * pcpumem, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	auto			prawpartha = partha_shr.get();

	if (!prawpartha) {
		return;
	}	

	auto			& cpu_mem_state = prawpartha->cpu_mem_state_;
	const uint64_t		currtusec = get_usec_time();
	const time_t		currt = currtusec/GY_USEC_PER_SEC;	

	cpu_mem_state.set_new_state(pcpumem, currtusec);

	CONDEXEC(
		DEBUGEXECN(11,
			if (cpu_mem_state.is_state_bad(currtusec)) {
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_LIGHT_BLUE, "%s : CPU State : %s : Memory State : %s\n",
					prawpartha->print_string(STRING_BUFFER<256>().get_str_buf()), cpu_mem_state.cpu_state_str_, cpu_mem_state.mem_state_str_);
			}
		);	
	);

	auto			pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 10'000 /* max_msec_wait */, false /* reset_on_timeout */);
	
	if (!pconn) {
		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ncpumem_state_failed_.fetch_add_relaxed(1);
		
		DEBUGEXECN(5,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get DB Conn for Partha %s CPU Memory State updation\n", prawpartha->hostname_);
		);
		return;
	}	
	
	const auto			& state = cpu_mem_state.cpu_mem_;
	const auto			timebuf = gy_localtime_iso8601_sec(cpu_mem_state.tusec_/GY_USEC_PER_SEC);
	STRING_BUFFER<8 * 1024>		qbuf;
	auto				datetbl = get_db_day_partition(currt, 15);
	auto				schemabuf = prawpartha->get_db_schema();
	bool				bret;

	SharedMutex::ReadHolder		rtscope(prawpartha->rtalerts_.adef_rwmutex_);

	cpumem_rtalert_rwlocked(*prawpartha, cpu_mem_state, cpu_mem_state.tusec_/GY_USEC_PER_SEC, timebuf.get()); 

	rtscope.unlock();
		
	qbuf.appendfmt("insert into %s.cpumemstatetbl%s values (\'%s\', %.3f, %.3f, %.3f, %.3f, %.3f, %d, %d, %u, %u, %d, %d, %d, %hd, %hd, %hd, %hd, %.3f, "
			"%d, %d, %d, %d, %d, %.3f, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %hd, %hd, %hd, %hd, \'",
		schemabuf.get(), datetbl.get(),
		timebuf.get(), state.cpu_pct_, state.usercpu_pct_,
		state.syscpu_pct_, state.iowait_pct_, state.cumul_core_cpu_pct_, state.forks_sec_, state.procs_running_, state.cs_sec_,
		state.cs_p95_sec_, state.cpu_p95_, state.fork_p95_sec_, state.procs_p95_, state.cpu_state_, state.cpu_issue_, state.cpu_issue_bit_hist_,
		state.cpu_severe_issue_hist_, state.rss_pct_, (int)state.rss_memory_mb_, (int)state.total_memory_mb_, (int)state.cached_memory_mb_, (int)state.locked_memory_mb_,
		(int)state.committed_memory_mb_, state.committed_pct_, (int)state.swap_free_mb_, (int)state.swap_total_mb_, state.pg_inout_sec_, state.swap_inout_sec_,
		state.reclaim_stalls_, state.pgmajfault_, state.oom_kill_, state.rss_pct_p95_, (int)state.pginout_p95_, (int)state.swpinout_p95_, (int)state.allocstall_p95_,
		state.mem_state_, state.mem_issue_, state.mem_issue_bit_hist_, state.mem_severe_issue_hist_);

	if (state.cpu_state_ >= STATE_BAD && state.cpu_state_string_len_ > 1) { 
		qbuf.append(cpu_mem_state.cpu_state_str_, state.cpu_state_string_len_ - 1);
	}
	qbuf.appendconst("\', \'");

	if (state.mem_state_ >= STATE_BAD && state.mem_state_string_len_ > 1) { 
		qbuf.append(cpu_mem_state.mem_state_str_, state.mem_state_string_len_ - 1);
	}
	qbuf.appendconst("\');");

	if (state.oom_kill_) {
		STRING_BUFFER<512>		sbuf;

		sbuf.appendfmt("Host %s : Out of Memory OOM %d Process Kills encountered", prawpartha->hostname_, state.oom_kill_);
		
		// Update notificationtbl
		qbuf.appendfmt("\ninsert into notificationtbl%s values (now(), \'%s\', \'%s\', \'", datetbl.get(), notify_to_string(NOTIFY_WARN), prawpartha->machine_id_str_);
		qbuf.append(sbuf.buffer(), sbuf.size());
		qbuf.appendconst("\');");

		add_notificationq(NOTIFY_WARN, cpu_mem_state.tusec_/GY_USEC_PER_SEC, sbuf.buffer(), sbuf.size(), prawpartha->machine_id_);
	}	

	bret = PQsendQueryOptim(pconn->get(), qbuf.buffer(), qbuf.size());
	
	if (bret == false) {
		db_stats_.ncpumem_state_failed_.fetch_add_relaxed(1);

		DEBUGEXECN(5,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to schedule DB query to update Partha %s CPU Memory State due to %s\n", 
				prawpartha->hostname_, PQerrorMessage(pconn->get()));
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
				db_stats_.ncpumem_state_failed_.fetch_add_relaxed(1);

				DEBUGEXECN(5,
					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to insert Partha CPU Memory State into DB due to %s\n", gyres.get_error_msg());
				);

				return false;
			}	

			return true;
		}
	);
}

void MCONN_HANDLER::handle_host_state(const std::shared_ptr<PARTHA_INFO> & partha_shr, const comm::HOST_STATE_NOTIFY * phost, PGConnPool & dbpool)
{
	auto			prawpartha = partha_shr.get();

	if (!prawpartha) {
		return;
	}	

	prawpartha->host_state_	= *phost;

	const auto &		state = prawpartha->host_state_;

	CONDEXEC(
		DEBUGEXECN(11,
			if (state.curr_state_ >= STATE_BAD) {
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_LIGHT_BLUE, "%s : Host State %s : #Tasks with issues %d, #Total Tasks %d : "
					"#Listeners with issue %d, #Total Listeners %d : Host CPU Delays %u msec, VM Delays %u msec, IO Delays %u msec : CPU Issue %s : Memory Issue %s\n",
					prawpartha->print_string(STRING_BUFFER<256>().get_str_buf()), 
					state_to_string((OBJ_STATE_E)state.curr_state_), state.ntasks_issue_, state.ntasks_, state.nlisten_issue_, state.nlisten_, 
					state.total_cpu_delayms_, state.total_vm_delayms_, state.total_io_delayms_,
					state.severe_cpu_issue_ ? "Severe" : state.cpu_issue_ ? "Yes" : "No", 
					state.severe_mem_issue_ ? "Severe" : state.mem_issue_ ? "Yes" : "No");
			}
		);	
	);

	auto			pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 10'000 /* max_msec_wait */, false /* reset_on_timeout */);
	
	if (!pconn) {
		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.nhost_state_failed_.fetch_add_relaxed(1);
		
		DEBUGEXECN(5,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get DB Conn for Partha %s Host State updation\n", prawpartha->hostname_);
		);
		return;
	}	
	
	STRING_BUFFER<2048>		qbuf;
	const auto			tvbuf = GY_USEC_TO_TIMEVAL(state.curr_time_usec_);
	const auto			timebuf = gy_localtime_iso8601_usec(tvbuf);
	const auto			datetbl = get_db_day_partition(tvbuf.tv_sec, 15);
	auto				schemabuf = prawpartha->get_db_schema();
	bool				bret;

	SharedMutex::ReadHolder		rtscope(prawpartha->rtalerts_.adef_rwmutex_);

	hoststate_rtalert_rwlocked(*prawpartha, state, state.curr_time_usec_/GY_USEC_PER_SEC, timebuf.get()); 

	rtscope.unlock();

	qbuf.appendfmt("insert into %s.hoststatetbl%s(time, ntasks_issue, ntasks_severe, ntasks, nlisten_issue, nlisten_severe, nlisten, "
			"state, issue_bit_hist, cpu_issue, mem_issue, severe_cpu_issue, severe_mem_issue, total_cpu_delay, total_vm_delay, total_io_delay) "
			"values(\'%s\'::timestamptz, %d, %d, %d, %d, %d, %d, %hd, %hd, %hhd::boolean, %hhd::boolean, %hhd::boolean, %hhd::boolean, %d, %d, %d);",
		schemabuf.get(), datetbl.get(), timebuf.get(), state.ntasks_issue_, state.ntasks_severe_,
		state.ntasks_, state.nlisten_issue_, state.nlisten_severe_, state.nlisten_, state.curr_state_, state.issue_bit_hist_,
		state.cpu_issue_, state.mem_issue_, state.severe_cpu_issue_, state.severe_mem_issue_,
		state.total_cpu_delayms_, state.total_vm_delayms_, state.total_io_delayms_);

	bret = PQsendQueryOptim(pconn->get(), qbuf.buffer(), qbuf.size());
	
	if (bret == false) {
		db_stats_.nhost_state_failed_.fetch_add_relaxed(1);

		DEBUGEXECN(5,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to schedule DB query to update Partha %s Host State due to %s\n", prawpartha->hostname_, PQerrorMessage(pconn->get()));
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
				db_stats_.nhost_state_failed_.fetch_add_relaxed(1);

				DEBUGEXECN(5,
					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to insert Partha Host State into DB due to %s\n", gyres.get_error_msg());
				);

				return false;
			}	

			return true;
		}
	);
}

void MCONN_HANDLER::handle_host_info(const std::shared_ptr<PARTHA_INFO> & partha_shr, const comm::HOST_INFO_NOTIFY * phost, PGConnPool & dbpool)
{
	auto			prawpartha = partha_shr.get();

	if (!prawpartha) {
		return;
	}	

	prawpartha->boot_time_sec_	= phost->boot_time_sec_;
	prawpartha->cores_online_	= phost->cores_online_;
	prawpartha->cores_offline_	= phost->cores_offline_;
	prawpartha->ram_mb_		= phost->ram_mb_;
	prawpartha->is_virtual_cpu_	= phost->is_virtual_cpu_;

	auto			pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 10'000 /* max_msec_wait */, false /* reset_on_timeout */);
	
	if (!pconn) {
		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.nhostinfo_failed_.fetch_add_relaxed(1);
		
		DEBUGEXECN(5,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get DB Conn for Partha %s Host Info updation\n", prawpartha->hostname_);
		);
		return;
	}	
	
	STRING_BUFFER<4096>		qbuf;
	auto				schemabuf = prawpartha->get_db_schema();
	bool				bret;

	qbuf.appendfmt("insert into parthainfotbl values(\'%s\', \'%s\', \'%s\', %u, \'%s\', \'%s\', %hu, %hu, %hu, %hu, %u, %u, %hu, %hu, %hu, %u, %u, %u, %u, "
			"to_timestamp(%ld), now(), %hhd::boolean, \'%s\', \'%s\', \'%s\') "
			"on conflict (machid) do update set "
			"(distribution_name, kern_version_string, kern_version_num, processor_model, cpu_vendor, cores_online, cores_offline, max_cores, isolated_cores, "
			"ram_mb, corrupted_ram_mb, num_numa_nodes, max_cores_per_socket, threads_per_core, l1_dcache_kb, l2_cache_kb, l3_cache_kb, l4_cache_kb, boot_time, "
			"updtime, is_virtual_cpu, virtualization_type, instance_id, cloud_type) = "
			"(excluded.distribution_name, excluded.kern_version_string, excluded.kern_version_num, excluded.processor_model, excluded.cpu_vendor, "
			"excluded.cores_online, excluded.cores_offline, excluded.max_cores, excluded.isolated_cores, excluded.ram_mb, excluded.corrupted_ram_mb, "
			"excluded.num_numa_nodes, excluded.max_cores_per_socket, excluded.threads_per_core, excluded.l1_dcache_kb, excluded.l2_cache_kb, "
			"excluded.l3_cache_kb, excluded.l4_cache_kb, excluded.boot_time, excluded.updtime, excluded.is_virtual_cpu, excluded.virtualization_type, "
			"excluded.instance_id, excluded.cloud_type);",
			prawpartha->machine_id_str_, phost->distribution_name_, phost->kern_version_string_, phost->kern_version_num_, phost->processor_model_, 
			phost->cpu_vendor_, phost->cores_online_, phost->cores_offline_, phost->max_cores_, phost->isolated_cores_, phost->ram_mb_, phost->corrupted_ram_mb_,
			phost->num_numa_nodes_, phost->max_cores_per_socket_, phost->threads_per_core_, phost->l1_dcache_kb_, phost->l2_cache_kb_, phost->l3_cache_kb_, 
			phost->l4_cache_kb_, phost->boot_time_sec_, phost->is_virtual_cpu_, phost->is_virtual_cpu_ ? phost->virtualization_type_ : "Bare Metal",
			phost->instance_id_, phost->cloud_type_);

	bret = PQsendQueryOptim(pconn->get(), qbuf.buffer(), qbuf.size());
	
	if (bret == false) {
		db_stats_.nhostinfo_failed_.fetch_add_relaxed(1);

		DEBUGEXECN(5,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to schedule DB query to update Partha %s Host Info due to %s\n", prawpartha->hostname_, PQerrorMessage(pconn->get()));
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
				db_stats_.nhostinfo_failed_.fetch_add_relaxed(1);

				DEBUGEXECN(5,
					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to insert Partha Host Info into DB due to %s\n", gyres.get_error_msg());
				);

				return false;
			}	

			return true;
		}
	);
}

void MCONN_HANDLER::handle_host_cpu_mem_change(const std::shared_ptr<PARTHA_INFO> & partha_shr, const comm::HOST_CPU_MEM_CHANGE * phost, PGConnPool & dbpool)
{
	auto			prawpartha = partha_shr.get();

	if (!prawpartha) {
		return;
	}	

	if (phost->cpu_changed_) {
		prawpartha->cores_online_	= phost->new_cores_online_;
		prawpartha->cores_offline_	= phost->new_cores_offline_;
	}

	if (phost->mem_changed_) {
		prawpartha->ram_mb_		= phost->new_ram_mb_;
	}

	auto			pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 10'000 /* max_msec_wait */, false /* reset_on_timeout */);
	
	if (!pconn) {
		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.ncpumemchange_failed_.fetch_add_relaxed(1);
		
		DEBUGEXECN(5,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get DB Conn for Partha %s CPU Mem Change updation\n", prawpartha->hostname_);
		);
		return;
	}	
	
	STRING_BUFFER<2048>		qbuf;
	STRING_BUFFER<512>		qmsg;
	auto				schemabuf = prawpartha->get_db_schema();
	const uint64_t			currtsec = get_sec_time();
	const auto			datetbl = get_db_day_partition(currtsec, 30);
	bool				bret;
	NOTIFY_MSGTYPE_E		ntype = (phost->mem_corrupt_changed_ ? NOTIFY_WARN : NOTIFY_INFO);

	qmsg.appendfmt("Host %s : ", prawpartha->hostname_);

	qbuf.appendconst("update parthainfotbl set ");
	if (phost->cpu_changed_) {
		qbuf.appendfmt("cores_online = %hu, cores_offline = %hu,", phost->new_cores_online_, phost->new_cores_offline_);

		qmsg.appendfmt("CPU Count Changed : New cores online = %hu (Older %hu) New cores offline = %hu (Older %hu) ", 
				phost->new_cores_online_, phost->old_cores_online_, phost->new_cores_offline_, phost->old_cores_offline_);
	}	

	if (phost->mem_changed_) {
		qbuf.appendfmt("ram_mb = %u,", phost->new_ram_mb_);

		qmsg.appendfmt("Memory Size Change : New RAM size = %u MB (Older %u MB) ", phost->new_ram_mb_, phost->old_ram_mb_);
	}	

	if (phost->mem_corrupt_changed_) {
		qbuf.appendfmt("corrupted_ram_mb = %u,", phost->new_corrupted_ram_mb_);

		qmsg.appendfmt("Corrupt Memory Size Change : New Corrupted RAM size = %u MB (Older %u MB) ", phost->new_corrupted_ram_mb_, phost->old_corrupted_ram_mb_);
	}	
	
	qbuf.appendfmt("updtime = now() where machid = \'%s\';", prawpartha->machine_id_str_);

	// Update notificationtbl
	qbuf.appendfmt("\n insert into notificationtbl%s values (now(), \'%s\', \'%s\', \'", datetbl.get(), notify_to_string(ntype), prawpartha->machine_id_str_);
	
	qbuf.append(qmsg.buffer(), qmsg.size());

	qbuf.appendconst("\');");

	bret = PQsendQueryOptim(pconn->get(), qbuf.buffer(), qbuf.size());
	
	if (bret == false) {
		db_stats_.ncpumemchange_failed_.fetch_add_relaxed(1);

		DEBUGEXECN(5,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to schedule DB query to update Partha %s CPU Mem Change due to %s\n", prawpartha->hostname_, PQerrorMessage(pconn->get()));
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
				db_stats_.ncpumemchange_failed_.fetch_add_relaxed(1);

				DEBUGEXECN(5,
					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to insert Partha CPU Mem Change into DB due to %s\n", gyres.get_error_msg());
				);

				return false;
			}	

			return true;
		}
	);

	// Now add the notification msg to queue
	add_notificationq(ntype, currtsec, qmsg.buffer(), qmsg.size(), prawpartha->machine_id_);

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "%s\n", qmsg.buffer());
}

void MCONN_HANDLER::handle_notification_msg(const std::shared_ptr<PARTHA_INFO> & partha_shr, const comm::NOTIFICATION_MSG * pmsg, int nevents, const uint8_t *pendptr, PGConnPool & dbpool)
{
	auto			prawpartha = partha_shr.get();

	if (!prawpartha) {
		return;
	}	

	auto			pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 10'000 /* max_msec_wait */, false /* reset_on_timeout */);
	
	if (!pconn) {
		db_stats_.nconns_failed_.fetch_add_relaxed(1);
		db_stats_.nnotify_failed_.fetch_add_relaxed(1);
		
		return;
	}	
	
	STRING_BUFFER<200 * 1024>	qbuf;
	auto				schemabuf = prawpartha->get_db_schema();
	const uint64_t			currtsec = get_sec_time();
	auto				timebuf = gy_localtime_iso8601_sec(currtsec);
	const auto			datetbl = get_db_day_partition(currtsec, 30);
	const auto			*pone = pmsg;
	bool				bret;

	qbuf.appendfmt("insert into notificationtbl%s values ", datetbl.get());
	
	for (int i = 0; i < nevents; ++i, pone = (decltype(pone))((uint8_t *)pone + pone->get_elem_size())) {
		qbuf.appendfmt("(\'%s\', \'%s\', \'%s\', \'", timebuf.get(), notify_to_string(pone->type_), prawpartha->machine_id_str_);
		
		if (pone->msglen_ > 1) {
			qbuf.append((const char *)(pone + 1), pone->msglen_ - 1);

			// Now add the notification msg to queue
			add_notificationq(pone->type_, currtsec, (const char *)(pone + 1), pone->msglen_ - 1, prawpartha->machine_id_);

			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Received Notification Message : %s\n", (const char *)(pone + 1));
		}
		
		qbuf.appendconst("\'),");
	}

	qbuf.set_last_char(';');

	bret = PQsendQueryOptim(pconn->get(), qbuf.buffer(), qbuf.size());
	
	if (bret == false) {
		db_stats_.nnotify_failed_.fetch_add_relaxed(1);

		DEBUGEXECN(5,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to schedule DB query to update Notification Message Table due to %s\n", PQerrorMessage(pconn->get()));
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
				db_stats_.nnotify_failed_.fetch_add_relaxed(1);

				DEBUGEXECN(5,
					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to insert Notification Msg into DB due to %s\n", gyres.get_error_msg());
				);

				return false;
			}	

			return true;
		}
	);
}

void MCONN_HANDLER::handle_listen_taskmap(const std::shared_ptr<PARTHA_INFO> & partha_shr, comm::LISTEN_TASKMAP_NOTIFY * prel, int nitems, uint8_t *pendptr, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool) 
{
	PARTHA_INFO			*prawpartha = partha_shr.get();

	if (!prawpartha) {
		return;
	}	

	uint64_t			tsec = get_sec_time(), ninfo = 0, ntaskmap = 0;


	if (true) {
		/*
		 * Currently we do not update the in memory related listener structs...
		 */

		const uint64_t			currtsec = tsec;
		auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 10'000 /* max_msec_wait */, false /* reset_on_timeout */);
		
		if (!pconn) {
			db_stats_.nconns_failed_.fetch_add_relaxed(1);
			db_stats_.nlistentask_failed_.fetch_add_relaxed(1);
			
			DEBUGEXECN(5,
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get DB Conn for Partha %s Listen Taskmap Adds\n", prawpartha->hostname_);
			);
			return;
		}	
		
		STRING_BUFFER<512 * 1028>	qbuf;
		auto				timebuf = gy_localtime_iso8601_sec(currtsec);
		const auto			datetbl = get_db_day_partition(currtsec, 30);
		auto				schemabuf = prawpartha->get_db_schema();
		auto				pone = prel;
		bool				bret;

		qbuf.appendfmt("insert into %s.listentaskmaptbl%s values ", schemabuf.get(), datetbl.get());

		for (int i = 0; i < nitems && (uint8_t *)pone < pendptr; ++i, ++ntaskmap, pone = decltype(pone)((uint8_t *)pone + pone->get_elem_size())) {
			uint64_t		*parr = (uint64_t *)(pone + 1);

			qbuf.appendfmt("(\'%s\', \'%016lx\', \'%s\', \'", timebuf.get(), pone->related_listen_id_, pone->ser_comm_);

			for (uint32_t l = 0; l < pone->nlisten_; ++l) {
				qbuf.appendfmt("%016lx,", *parr++);
			}

			if (pone->nlisten_) {
				qbuf.set_last_char('\'');
			}
			else {
				qbuf.append('\'');
			}	
			
			qbuf.appendconst(", \'");

			for (uint32_t l = 0; l < pone->naggr_taskid_; ++l) {
				qbuf.appendfmt("%016lx,", *parr++);
			}

			if (pone->naggr_taskid_) {
				qbuf.set_last_char('\'');
			}
			else {
				qbuf.append('\'');
			}	
			
			qbuf.appendconst("),");
		}	

		qbuf.set_last_char(';');
		
		bret = PQsendQueryOptim(pconn->get(), qbuf.buffer(), qbuf.size());
		
		if (bret == false) {
			db_stats_.nlistentask_failed_.fetch_add_relaxed(1);

			DEBUGEXECN(5,
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to schedule DB query to add Partha %s Listener Taskmap due to %s\n", prawpartha->hostname_, PQerrorMessage(pconn->get()));
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
					db_stats_.nlistentask_failed_.fetch_add_relaxed(1);

					DEBUGEXECN(5,
						ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to insert Partha Listener Taskmap into DB due to %s\n", gyres.get_error_msg());
					);

					return false;
				}	

				return true;
			}
		);
	}

	if (tsec > prawpartha->last_svcinfo_tsec_ + INFO_DB_UPDATE_SEC - INFO_DB_UPDATE_SEC/4) {
		
		static constexpr size_t		max_db_query_sz = 400 * 1024;

		assert(gy_get_thread_local().get_thread_stack_freespace() >= max_db_query_sz + 64 * 1024);

		STRING_BUFFER<max_db_query_sz>	qbuf;

		auto				datetbl = get_db_day_partition(tsec, 30);
		const auto			timebuf = gy_localtime_iso8601_sec(tsec);
		auto				schemabuf = prawpartha->get_db_schema();
		bool				bret, isrtadef;

		auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 10'000 /* max_msec_wait */, false /* reset_on_timeout */);
		
		if (!pconn) {
			db_stats_.nconns_failed_.fetch_add_relaxed(1);
			db_stats_.nsvcinfo_failed_.fetch_add_relaxed(1);
			
			DEBUGEXECN(5,
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get DB Conn for Partha %s Listener Info updation\n", prawpartha->hostname_);
			);
			
			goto done1;
		}	
		
		SharedMutex::ReadHolder		rtscope(prawpartha->rtalerts_.adef_rwmutex_);
		
		isrtadef = !!prawpartha->rtalerts_.adef_svcinfo_.size();

		if (!isrtadef) {
			rtscope.unlock();
		}	

		const auto svcl = [&, prawpartha, isrtadef](MTCP_LISTENER_ELEM_TYPE *pdatanode, void *arg)
		{
			const auto			plistener = pdatanode->get_cref().get();

			if (!plistener) {
				return CB_OK;
			}
			
			const auto			& listener = *plistener;

			if (isrtadef) {
				svcinfo_rtalert_rwlocked(*prawpartha, listener, tsec, timebuf.get()); 
			}	

			qbuf.appendfmt("(to_timestamp(%ld),\'%016lx\',\'%s\',%ld,\'%s\',%d,\'%016lx\',to_timestamp(%ld),\'", 
				tsec, listener.glob_id_, listener.comm_, listener.ns_ip_port_.inode_, listener.ns_ip_port_.ip_port_.ipaddr_.printaddr().get(), 
				listener.ns_ip_port_.ip_port_.port_, listener.related_listen_id_, listener.tusec_start_/GY_USEC_PER_SEC);

			uint32_t			clen = GY_READ_ONCE(listener.cmdline_len_);

			if (clen > 0) {
				auto		cmdline = pconn->escape_string<512>(listener.cmdline_, clen);

				qbuf.append(cmdline.get(), cmdline.size());
			}

			qbuf.appendfmt("\',%d,%d,%d,%d,\'", listener.day_stats_.p95_5d_respms_, int(listener.day_stats_.tsum_5d_/NUM_OR_1(listener.day_stats_.tcount_5d_)), 
				listener.day_stats_.p95_qps_, listener.day_stats_.p95_nactive_);

			if (listener.nat_ip_port_arr_[0].port_ > 0) {
				qbuf << listener.nat_ip_port_arr_[0].ipaddr_.printaddr().get();
			}

			qbuf << "\'," << listener.nat_ip_port_arr_[0].port_ << ",\'"; 

			if (listener.nat_ip_port_arr_[1].port_ > 0) {
				qbuf << listener.nat_ip_port_arr_[1].ipaddr_.printaddr().get();
			}

			qbuf << "\'," << listener.nat_ip_port_arr_[1].port_ << ",\'";

			qbuf.append(listener.server_domain_, GY_READ_ONCE(listener.domain_string_len_));

			qbuf << "\',\'";

			auto relshr = listener.related_listen_shr_.load(mo_relaxed);

			if (relshr) {
				clen = GY_READ_ONCE(relshr->tag_len_);

				if (clen > 0) {
					auto		tag = pconn->escape_string<512>(relshr->tagbuf_, clen);

					qbuf.append(tag.get(), tag.size());
				}
			}	
			
			qbuf << "\',\'";

			if (listener.is_cluster_mesh_) {
				qbuf.appendfmt("%016lx", listener.eff_mesh_cluster_id_.load(mo_relaxed));
			}

			qbuf << "\'," << listener.ntotal_mesh_svc_ << ",\'";

			if (listener.is_cluster_nat_ip_[0]) {
				qbuf.appendfmt("%016lx", listener.nat_ip_cluster_id_[0].load(mo_relaxed));
			}

			qbuf << "\'," << listener.ntotal_nat_ip_svc_[0] << ",\'";

			if (listener.is_cluster_nat_ip_[1]) {
				qbuf.appendfmt("%016lx", listener.nat_ip_cluster_id_[1].load(mo_relaxed));
			}

			qbuf << "\'," << listener.ntotal_nat_ip_svc_[1];

			qbuf.appendfmt(",\'%s\',\'%s\'),", prawpartha->region_name_, prawpartha->zone_name_);

			if (qbuf.bytes_left() < 2048) {
				return CB_BREAK_LOOP;
			}	

			return CB_OK;
		};	
		
		qbuf.appendfmt("insert into %s.listeninfotbl%s values ", schemabuf.get(), datetbl.get());

		ninfo = prawpartha->listen_tbl_.walk_hash_table(svcl);

		if (isrtadef) {
			rtscope.unlock();
		}

		qbuf.set_last_char(';');

		if (ninfo == 0) {
			goto done1;
		}	

		if (gy_unlikely(true == qbuf.is_overflow())) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Internal Error : Listener Info DB insert buffer overflow occured for Partha %s\n",
				prawpartha->hostname_);
			goto done1;
		}

		bret = PQsendQueryOptim(pconn->get(), qbuf.buffer(), qbuf.size());
		
		if (bret == false) {
			db_stats_.nsvcinfo_failed_.fetch_add_relaxed(1);

			DEBUGEXECN(5,
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to schedule DB query to update Partha %s Listener Info due to %s\n", 
						prawpartha->hostname_, PQerrorMessage(pconn->get()));
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
					db_stats_.nsvcinfo_failed_.fetch_add_relaxed(1);

					DEBUGEXECN(5,
						ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to insert Partha Listener Info into DB due to %s\n", gyres.get_error_msg());
					);

					return false;
				}	

				return true;
			}
		);
			
		prawpartha->last_svcinfo_tsec_ = tsec;
	}	

done1 :
	if (ninfo) {
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Partha %s : Updated %lu Listen Taskmap entries and %lu Listener Infos to DB\n", prawpartha->hostname_, ntaskmap, ninfo);
	}	
}

bool MCONN_HANDLER::schedule_remote_madhava_conn(const char *madhava_hostname, uint16_t madhava_port, uint64_t madhava_id, uint64_t sched_after_msec, int l1_id, std::weak_ptr<MADHAVA_INFO> weak_info) noexcept
{
	try {
		char			buf1[128];

		snprintf(buf1, sizeof(buf1), "Connect to remote Madhava ID %016lx", madhava_id);

		/*
		 * The callback which will be invoked once the connect completion is signalled...
		 */
		ASYNC_SOCK_CB 		cb_succ(
			[this, madweak = std::move(weak_info), madhava_id](MCONNTRACK *pconn, void * pact_resp, size_t nact_resp, void * presphdr, bool is_expiry, bool is_error) -> bool
			{
				if (is_expiry || is_error) {
					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Remote Madhava ID %016lx connection callback error\n", madhava_id);
					return false;
				}	

				auto			madshr = madweak.lock();

				if (!madshr) {
					GY_THROW_EXCEPTION("Remote Madhava ID %016lx expired. Closing Connection", madhava_id);
				}	

				pconn->host_shr_ = std::move(madshr);

				set_sock_nodelay(pconn->get_sockfd());
				set_sock_keepalive(pconn->get_sockfd());

				send_madhava_registration(pconn, madhava_id);

				return true;
			}, 0
		);

		// Async schedule for tcp connection to remote madhava

		return GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_LONG2_DURATION)->add_oneshot_schedule(sched_after_msec, buf1,
			[this, hoststr = SSO_STRING<64>(madhava_hostname), hostport = madhava_port, l1_id, cb_succ = std::move(cb_succ)]() mutable
			{ 
				try {
					char			ebuf[128];
					auto			psockaddr = std::make_unique<sockaddr_storage>();
					socklen_t		socklen;

					auto [sockfd, is_conn] = gy_tcp_connect(hoststr.data(), hostport, ebuf, "Remote Madhava", true /* set_nodelay */, false /* always_resolve_dns */,
									psockaddr.get(), &socklen, false, true, true /* set_nonblock */);

					if (sockfd < 0) {
						DEBUGEXECN(1,
							ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to connect to remote Madhava %s\n", ebuf);
						);	

						return;
					}	

					CONN_NOTIFY_ONE		conn(std::move(psockaddr), sockfd, std::move(cb_succ), HOST_MADHAVA, COMM_HEADER::MM_HDR_MAGIC, CLI_TYPE_REQ_RESP, is_conn);
					int			ntries = 0;

					auto			pl1 = pl1_cli_arr_ + (l1_id % MAX_L1_CLI_THREADS);
					bool			bret;

					do { 
						bret = pl1->psignalq_->write(std::move(conn));
					} while (bret == false && ntries++ < 3);

					if (bret == false) {
						// conn destructor will close the conn
						return;
					}
					
					// ::write() will act as the memory barrier...

					int64_t			n = 1;

					int iret = ::write(pl1->signal_fd_, &n, sizeof(int64_t));
					if (iret == sizeof(int64_t)) {
						return;
					}	
				}
				catch(...) {
				}	

			}, false);
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while scheduling remote madhava conn : %s\n", GY_GET_EXCEPT_STRING);
		);	

		return false;
	);
}

bool MCONN_HANDLER::handle_madhava_list(comm::MADHAVA_LIST * pone, int nelems, uint8_t *pendptr, STATS_STR_MAP & statsmap)
{
	const uint64_t		currtusec = get_usec_time();
	size_t			nmadhava = 0;
	int			nnew = 0, nconn = 0, nskip = 0;
	bool			bret;
	
	GY_SCOPE_EXIT {
		gy_thread_rcu().gy_rcu_thread_offline();
	};	
	
	if (true == partha_tbl_.is_empty()) {
		// No partha being handled currently. Lets skip this till we handle one
		return true;
	}

	auto schedmad = [&, this, startmsec = 100](const MADHAVA_LIST *plist, MADHAVA_INFO *pmad) mutable
	{
		if (plist->madhava_id_ == gmadhava_id_) {
			return;
		}

		nconn++;

		schedule_remote_madhava_conn(plist->madhava_svc_hostname_, plist->madhava_svc_port_, plist->madhava_id_, startmsec, nconn, pmad->weak_from_this());

		startmsec += 50;
	};	
	

	auto madlam = [&, this, currtusec](MADHAVA_INFO_ELEM *pelem, void *arg1, void *arg2) -> CB_RET_E
	{
		auto				pmad = pelem->get_cref().get();
		const MADHAVA_LIST		*plist = (const MADHAVA_LIST *)arg1;

		if (!pmad) {
			return CB_OK;
		}	

		if (pmad->get_port() != plist->madhava_svc_port_ || strcmp(pmad->get_domain(), plist->madhava_svc_hostname_)) {
			INFOPRINT_OFFLOAD("New Master Madhava seen for Remote Madhava Host %s Port %hu with ID %016lx : "
				"Closing connections to older Madhava host %s port %hu if any...\n", 
				plist->madhava_svc_hostname_, plist->madhava_svc_port_, pmad->madhava_id_, pmad->get_domain(), pmad->get_port());
			
			close_all_conns(*pmad);

			pmad->listener_port_.set(plist->madhava_svc_hostname_, plist->madhava_svc_port_);
		}	

		pmad->last_upd_tusec_ = currtusec;
		pmad->npartha_nodes_.store(plist->npartha_nodes_, mo_relaxed);

		if ((plist->npartha_nodes_ > 0) && (false == pmad->is_cli_type_avail(CLI_TYPE_REQ_RESP))) {
			// We need to schedule a connect
			schedmad(plist, pmad);
		}	

		return CB_OK;
	};	


	for (int i = 0; i < nelems; ++i, ++pone) {
		const uint64_t			madhava_id = pone->madhava_id_;
		const uint32_t			madhash = get_uint64_hash(madhava_id);

		bret = madhava_tbl_.template lookup_single_elem<decltype(madlam), RCU_LOCK_FAST>(madhava_id, madhash, madlam, pone);

		if (bret == false) {
			if (nmadhava == 0) {
				nmadhava = madhava_tbl_.count_slow();	
			}
			else if (nmadhava + 1 >= comm::MAX_MADHAVA_PER_SHYAMA) {
				// Ignore adding new Madhava at this moment
				nskip++;
				continue;
			}	
			nmadhava++;

			gy_thread_rcu().gy_rcu_thread_offline();
			
			auto pminfo = new MADHAVA_INFO(pone->madhava_svc_hostname_, pone->madhava_svc_port_, pone->madhava_id_);
			
			MADHAVA_INFO_ELEM		*pelem; 
			
			try {
				pelem = new MADHAVA_INFO_ELEM(pminfo);
			}
			catch(...) {
				delete pminfo;
				throw;
			}	

			auto newlam = [&](MADHAVA_INFO_ELEM *poldelem, MADHAVA_INFO_ELEM *pnewelem)
			{
				madlam(poldelem, pone, nullptr);
			};

			bret = madhava_tbl_.insert_unique(pelem, pminfo->madhava_id_, get_uint64_hash(pminfo->madhava_id_), newlam, true /* delete_after_callback */);

			if (bret == true) {
				nnew++;
				if (pone->npartha_nodes_ > 0) {
					// We need to schedule a connect
					schedmad(pone, pminfo);
				}	
			}
		}	
	}	

	if (nnew + nconn) {
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Added %d new Madhava instances and scheduled new connections to %d Madhava instances\n", nnew, nconn);
	}	

	if (nskip) {
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Skipped adding %d Madhava instances as Max Madhava limit %lu breached.\n", nskip, comm::MAX_MADHAVA_PER_SHYAMA);
	}	

	return true;
}

/*
 * This function can be called concurrently from multiple threads for the same partha node although not likely for the same MTCP_LISTENER
 */
bool MCONN_HANDLER::partha_listener_info(const std::shared_ptr<PARTHA_INFO> & partha_shr, comm::NEW_LISTENER *porigone, int nlisteners, uint8_t *pendptr, comm::LISTENER_DAY_STATS *prespone, uint32_t nrespelem, uint32_t & nresplisten, uint32_t & szresp, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool) noexcept
{
	try {	
		PARTHA_INFO	 		*prawpartha = partha_shr.get(); 

		if (gy_unlikely(prawpartha == nullptr)) {
			return false;
		}	

		RCU_LOCK_SLOW			slowlock;
		uint64_t			tusec_start = get_usec_time(), cusec_start = get_usec_clock();
		uint32_t			nadded = 0;
		int				ndbupd = 0;
		NEW_LISTENER			*ponelisten = porigone;

		auto handlelisten = [&, this, tusec_start, cusec_start, prawpartha](MTCP_LISTENER *plistener, comm::NEW_LISTENER *pone, bool is_new)
		{
			std::shared_ptr<MAGGR_LISTENER>		aggrshr;
			uint64_t				ser_aggr_task_id;
			MAGGR_TASK				*pmtask = nullptr;
			bool					bret;

			if (!is_new) {
				plistener->ns_ip_port_		= pone->ns_ip_port_;
				plistener->is_any_ip_		= pone->is_any_ip_;
				plistener->tusec_start_		= tusec_start;
				plistener->cusec_start_		= get_usec_clock_from_usec_diff(cusec_start, (int64_t)tusec_start - (int64_t)pone->tstart_usec_);

				if (pone->aggr_glob_id_) {
					plistener->aggr_glob_id_ = pone->aggr_glob_id_;
				}	

				plistener->comm_len_ = GY_STRNCPY_LEN(plistener->comm_, pone->comm_, sizeof(plistener->comm_));

				if (pone->cmdline_len_ > 1 && pone->cmdline_len_ <= sizeof(plistener->cmdline_)) {
					auto			clen = pone->cmdline_len_ - 1;

					std::memcpy(plistener->cmdline_, (const char *)(pone + 1), clen);
					plistener->cmdline_[clen] = 0; 

					GY_CC_BARRIER();
					plistener->cmdline_len_ = clen;
				}
			}

			ser_aggr_task_id = plistener->ser_aggr_task_id_.load(mo_relaxed);

			if (ser_aggr_task_id != pone->ser_aggr_task_id_ && pone->ser_aggr_task_id_) {

				const uint32_t		lhash = get_uint64_hash(plistener->glob_id_);

				// No need for a cmpxchg as simulataneous writes is extremely unlikely
				if (plistener->ser_aggr_task_id_.load(mo_acquire)) {
					plistener->ser_aggr_task_id_.store(0, mo_release);
				}	

				MAGGR_TASK_ELEM_TYPE		mtaskelem;
				const uint32_t			mahash = get_uint64_hash(pone->ser_aggr_task_id_);
				FREE_FPTR			free_fp;
				uint32_t			act_size;

				bret = prawpartha->task_aggr_tbl_.lookup_single_elem(pone->ser_aggr_task_id_, mahash, mtaskelem);

				pmtask = mtaskelem.get_cref().get();

				if (!pmtask) {
					size_t			slen = std::min<uint32_t>(pone->cmdline_len_, sizeof(plistener->cmdline_));

					plistener->cmdline_len_ = slen ? slen - 1 : 0;

					std::memcpy(plistener->cmdline_, (const char *)(pone + 1), plistener->cmdline_len_);
					plistener->cmdline_[plistener->cmdline_len_] = 0;

					pmtask = (MAGGR_TASK *)pthrpoolarr->safe_malloc(sizeof(MAGGR_TASK), free_fp, act_size, false /* try_other_pools */, true /* use_malloc_hdr */);

					new (pmtask) MAGGR_TASK(pone->ser_aggr_task_id_, plistener->comm_, plistener->cmdline_, prawpartha->weak_from_this(),
								prawpartha->machine_id_, gmadhava_weak_, gmadhava_id_, slen, plistener->related_listen_id_, "", 0 , tusec_start);

					MAGGR_TASK_ELEM_TYPE *pmtaskelem = (MAGGR_TASK_ELEM_TYPE *)pthrpoolarr->safe_malloc(sizeof(MAGGR_TASK_ELEM_TYPE), free_fp, act_size,
																false, true);
					new (pmtaskelem) MAGGR_TASK_ELEM_TYPE(pmtask, TPOOL_DEALLOC<MAGGR_TASK>());

					auto ulam = [&](MAGGR_TASK_ELEM_TYPE *poldelem, MAGGR_TASK_ELEM_TYPE *pnewelem)
					{
						mtaskelem = *poldelem;
					};	

					bret = prawpartha->task_aggr_tbl_.insert_unique(pmtaskelem, pone->ser_aggr_task_id_, mahash, ulam, true /* delete_after_callback */);
					if (bret == false) {
						pmtask = mtaskelem.get_cref().get();
						
						GY_STRNCPY(pmtask->comm_, plistener->comm_, sizeof(pmtask->comm_));
					}	
				}
				
				plistener->ser_task_weak_ = pmtask->weak_from_this();

				plistener->ser_aggr_task_id_.store(pone->ser_aggr_task_id_, mo_release);

				ser_aggr_task_id = pone->ser_aggr_task_id_;
			}	

			if (plistener->related_listen_id_ != pone->related_listen_id_) {
				auto relshr = plistener->related_listen_shr_.load(mo_acquire);

				uint64_t				relid = pone->related_listen_id_;
				uint64_t				relhash = get_uint64_hash(relid);
				MRELATED_LISTENER_ELEM_TYPE		mrelshrelem;
				std::shared_ptr<MRELATED_LISTENER>	mrelshr;
				bool					bret;
				const uint32_t				lhash = get_uint64_hash(plistener->glob_id_);

				if (relshr) {
					relshr->listener_table_.delete_single_elem(plistener->glob_id_, lhash);

					if (true == relshr->listener_table_.is_empty()) {
						prawpartha->related_listen_tbl_.delete_single_elem(plistener->related_listen_id_, get_uint64_hash(plistener->related_listen_id_));

						if (pmtask) {
							pmtask->related_listen_id_ = 0;
						}	
					}	

					relshr.reset();
				}	

				// Now find if the new related_listen_id_ already available
				bret = prawpartha->related_listen_tbl_.lookup_single_elem(relid, relhash, mrelshrelem);
				if (bret == true) {
					mrelshr = std::move(mrelshrelem.get_ref());
				}

				if ((false == bret) || (nullptr == mrelshr.get())) {
					auto prel = new MRELATED_LISTENER(relid, plistener->comm_);
					
					try {
						auto pelem = new MRELATED_LISTENER_ELEM_TYPE(prel);
						
						prawpartha->related_listen_tbl_.insert_or_replace(pelem, relid, relhash);
					}
					catch(...) {
						plistener->related_listen_shr_.store(mrelshr, mo_release);

						delete prel;
						throw;
					}	

					mrelshr = prel->shared_from_this();
				}	

				plistener->related_listen_shr_.store(mrelshr, mo_release);
				plistener->related_listen_id_	= pone->related_listen_id_;

				mrelshr->last_aggr_task_id_	= ser_aggr_task_id;

				auto 			prel2 = new MTCP_LISTENER_ELEM_TYPE(plistener->shared_from_this());

				mrelshr->listener_table_.insert_or_replace(prel2, plistener->glob_id_, lhash);

				if (!pmtask) {
					auto taskshr = plistener->ser_task_weak_.lock();
					pmtask = taskshr.get();

					if (pmtask) {
						pmtask->related_listen_id_ = plistener->related_listen_id_;
					}	
				}	
				else {
					pmtask->related_listen_id_ = plistener->related_listen_id_;
				}	
			}

			if (pone->no_aggr_stats_ == false && pone->aggr_glob_id_) {

				/*
				 * XXX : Currently no_aggr_stats_ is always set as true in partha as MAGGR_LISTENER handling is disabled...
				 */
				if ((is_new) || (true == plistener->aggr_weak_.expired())) {

					// Set plistener aggr weak
					bool				bret;
					uint64_t			aggid = pone->aggr_glob_id_;
					uint32_t			agghash = get_uint64_hash(aggid);
					MAGGR_LISTENER_ELEM_TYPE	aggrshrelem;	

					bret = prawpartha->aggr_listen_tbl_.lookup_single_elem(aggid, agghash, aggrshrelem);
					if (bret == true) {
						aggrshr = std::move(aggrshrelem.get_ref());
					}	

					if (aggrshr) {
						plistener->aggr_weak_ = aggrshr;
					}	
					else {
						auto pmaggr = new MAGGR_LISTENER(plistener->ns_ip_port_.ip_port_, aggid, plistener->is_any_ip_, pone->comm_, 
									(const char *)(pone + 1), pone->cmdline_len_);

						auto pmaggrshr = new MAGGR_LISTENER_ELEM_TYPE(pmaggr);

						prawpartha->aggr_listen_tbl_.insert_or_replace(pmaggrshr, aggid, agghash);

						aggrshr = pmaggrshr->get_cref();
						plistener->aggr_weak_ = pmaggr->weak_from_this();
					}	
				}
			}

			if (nrespelem && prespone && !pone->no_resp_stats_ && nresplisten < nrespelem) {
				LISTENER_DAY_STATS		*pinputone = nullptr;

				if (!is_new) {
					if (plistener->last_day_stats_tusec_ > tusec_start - 3 * GY_USEC_PER_HOUR) {
						pinputone = &plistener->day_stats_;
					}	
				}
				/*
					// Currently no_aggr_stats_ is always true

				else if (!pone->no_aggr_stats_ && bool(aggrshr) && aggrshr->last_day_stats_tusec_) {
					pinputone = &aggrshr->day_stats_;
				}
				*/

				if (pinputone) {
					*prespone 		= *pinputone;

					nresplisten++;
					szresp += prespone->get_elem_size();
				}
			}
		};	

		auto listl = [&](MSOCKET_HDLR::MTCP_LISTENER_ELEM_TYPE *pdatanode, void *arg1, void *arg2)
		{
			comm::NEW_LISTENER			*pone = (decltype(pone))arg1;
			auto					plistener = pdatanode->get_cref().get();

			if (plistener) {
				handlelisten(plistener, pone, false);
			}	

			return CB_OK;
		};	

		for (int i = 0; i < nlisteners && (uint8_t *)ponelisten < pendptr; ++i) {
			size_t				elem_sz = ponelisten->get_elem_size();

			uint64_t			glob_id = ponelisten->glob_id_;
			uint32_t			ghash = get_uint64_hash(glob_id);	
			bool				bret;

			if (ponelisten->cmdline_len_ > 1) {
				ndbupd++;
			}	

			bret = prawpartha->listen_tbl_.template lookup_single_elem<decltype(listl), RCU_LOCK_FAST>(glob_id, ghash, listl, ponelisten);
			if (bret == false) {
				auto plistener = new MTCP_LISTENER(ponelisten->ns_ip_port_, ponelisten->is_any_ip_, ponelisten->glob_id_, ponelisten->aggr_glob_id_, partha_shr, prawpartha->machine_id_,
						gmadhava_id_, gmadhava_weak_, ponelisten->comm_, (const char *)(ponelisten + 1), ponelisten->cmdline_len_);
				
				auto listelem = new MTCP_LISTENER_ELEM_TYPE(plistener);

				prawpartha->listen_tbl_.insert_or_replace(listelem, glob_id, ghash);

				nadded++;

				handlelisten(plistener, ponelisten, true);

				auto plistelem2 = new MTCP_LISTENER_ELEM_TYPE(listelem->get_cref());

				glob_listener_tbl_.insert_or_replace(plistelem2, glob_id, ghash);
			}	

			ponelisten = (decltype(ponelisten))((uint8_t *)ponelisten + elem_sz);
		}	

		slowlock.unlock();

		if (ndbupd > 0) {

			// Update the DB
			assert(gy_get_thread_local().get_thread_stack_freespace() >= 512 * 1024 + 64 * 1024);

			STRING_BUFFER<512 * 1024>	qbuf;
			auto				timebuf = gy_localtime_iso8601_sec(tusec_start/GY_USEC_PER_SEC);
			auto				schemabuf = prawpartha->get_db_schema();
			bool				bret;
			auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 10'000 /* max_msec_wait */, false /* reset_on_timeout */);
			
			if (!pconn) {
				db_stats_.nconns_failed_.fetch_add_relaxed(1);
				db_stats_.nnewlisten_failed_.fetch_add_relaxed(1);
				
				DEBUGEXECN(5,
					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get DB Conn for new Listener inserts for Partha %s\n", prawpartha->hostname_);
				);
				
				goto done1;
			}	

			qbuf.appendfmt("insert into %s.listentbl values ", schemabuf.get());

			auto			pone = porigone;

			for (int i = 0; i < nlisteners && (uint8_t *)pone < pendptr; ++i, pone = (decltype(pone))((uint8_t *)pone + pone->get_elem_size())) {
				
				qbuf.appendfmt("(\'%016lx\', \'%s\', %ld, \'%s\', %d, \'%016lx\', \'%s\', \'%s\', \'%016lx\', \'%d\', \'",
					pone->glob_id_, pone->comm_, pone->ns_ip_port_.inode_, pone->ns_ip_port_.ip_port_.ipaddr_.printaddr().get(), 
					pone->ns_ip_port_.ip_port_.port_, pone->related_listen_id_, timebuf.get(), timebuf.get(),
					pone->ser_aggr_task_id_, pone->is_any_ip_);

				if (pone->cmdline_len_ > 1) {
					auto		cmdline = pconn->escape_string<512>((const char *)(pone + 1), pone->cmdline_len_ - 1);

					qbuf.append(cmdline.get(), cmdline.size());
				}

				qbuf.appendconst("\'),");
			}	

			qbuf.set_last_char(' ');

			qbuf.appendconst("on conflict(glob_id) do update set (comm, related_listen_id, lastupdtime, starttime,"
					"ser_aggr_task_id, is_any_ip, cmdline, del_after) = "
					"(excluded.comm, excluded.related_listen_id, excluded.lastupdtime, excluded.starttime,"
					"excluded.ser_aggr_task_id, excluded.is_any_ip, excluded.cmdline, NULL);\n");

			if (gy_unlikely(true == qbuf.is_overflow())) {
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Internal Error : New Listener insert buffer overflow occured for Partha %s\n", prawpartha->hostname_);
				goto done1;
			}

			bret = PQsendQueryOptim(pconn->get(), qbuf.buffer(), qbuf.size());
			
			if (bret == false) {
				db_stats_.nnewlisten_failed_.fetch_add_relaxed(1);

				DEBUGEXECN(5,
					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to schedule DB query for New Listener updation for Partha %s due to %s\n", 
						prawpartha->hostname_, PQerrorMessage(pconn->get()));
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
						db_stats_.nnewlisten_failed_.fetch_add_relaxed(1);
		
						DEBUGEXECN(5,
							ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to insert new Listener updation into DB due to %s\n", gyres.get_error_msg());
						);

						return false;
					}	

					return true;
				}
			);
		}

done1 :

		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_GREEN, "%s started %u listeners of which %u are newly seen\n",
			prawpartha->print_string(STRING_BUFFER<256>().get_str_buf()), nlisteners, nadded);

		return true;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, 
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while handling Listener Info Request : %s\n\n", GY_GET_EXCEPT_STRING);
		);	
		return false;
	);
}	

bool MCONN_HANDLER::handle_listener_req(const std::shared_ptr<MCONNTRACK> & connshr, const std::shared_ptr<PARTHA_INFO> & partha_shr, comm::QUERY_CMD *pquery, comm::LISTENER_INFO_REQ * plist, uint8_t *pendptr, POOL_ALLOC_ARRAY *pthrpoolarr, STATS_STR_MAP & statsmap, PGConnPool & dbpool) noexcept
{
	try {
		PARTHA_INFO			*prawpartha = partha_shr.get();

		if (gy_unlikely(prawpartha == nullptr)) {
			statsmap["Null Partha"]++;
			return false;
		}	

		RCU_LOCK_FAST			fastlock;
		const int			nlisteners = plist->ntcp_listeners_;
		comm::NEW_LISTENER		*pone = (comm::NEW_LISTENER *)(plist + 1), *porigone = pone;
		uint32_t			nadded = 0, nrespelem = 0;
		bool				bret; 

		/*
		 * First check the pone's to get a count of LISTENER_DAY_STATS's that need to be sent
		 */
		for (int i = 0; i < nlisteners && (uint8_t *)pone < pendptr; ++i) {
			size_t			elem_sz = pone->get_elem_size();

			if (pone->no_aggr_stats_ && pone->aggr_glob_id_) {
				uint64_t		aggr_id = pone->aggr_glob_id_;
				uint32_t		ahash = get_uint64_hash(aggr_id);	

				prawpartha->aggr_listen_tbl_.delete_single_elem(aggr_id, ahash);
			}

			if (pone->no_resp_stats_ == false) {
				nrespelem++;
			}	

			pone = (decltype(pone))((uint8_t *)pone + elem_sz);
		}	

		fastlock.unlock();

		pone = porigone;

		uint8_t				*palloc, *pallocend;
		FREE_FPTR			free_fp_hdr;
		constexpr size_t		fixed_sz = sizeof(comm::COMM_HEADER) + sizeof(QUERY_RESPONSE) + sizeof(LISTENERS_INFO_STATS_RESP);	
		size_t				reqsz = fixed_sz + nrespelem * (sizeof(LISTENER_DAY_STATS) + 0 /* 0 domain len */);
		uint32_t			act_size, szresp = fixed_sz, nresplisten = 0;

		palloc	 			= (uint8_t *)pthrpoolarr->safe_malloc(reqsz, free_fp_hdr, act_size);
		pallocend 			= (uint8_t *)palloc + act_size;

		LISTENER_DAY_STATS		*prespone = (LISTENER_DAY_STATS *)(palloc + fixed_sz);

		bret = partha_listener_info(partha_shr, pone, nlisteners, pendptr, prespone, nrespelem, nresplisten, szresp, pthrpoolarr, dbpool);

		time_t				tcur = time(nullptr);

		if ((szresp < act_size) && (tcur <= pquery->timeoutsec_)) {

			COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
			QUERY_RESPONSE			*presp = reinterpret_cast<QUERY_RESPONSE *>(phdr + 1);
			LISTENERS_INFO_STATS_RESP	*plist = reinterpret_cast<LISTENERS_INFO_STATS_RESP *>(presp + 1);

			new (phdr) COMM_HEADER(COMM_QUERY_RESP, szresp, connshr->get_comm_magic());

			new (presp) QUERY_RESPONSE(pquery->seqid_, RESP_LISTENER_INFO_STATS, ERR_SUCCESS, RESP_BINARY, *phdr);
			
			plist->ntcp_listeners_		= nresplisten;

			bret = schedule_l1_send_data(connshr, COMM_QUERY_RESP, IOVEC_ARRAY(2, false, phdr, szresp, free_fp_hdr, gpadbuf, phdr->get_pad_len(), nullptr));

			return bret;
		}	
		else if (tcur > pquery->timeoutsec_) {
			statsmap["Response Timed Out"]++;
			WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Listener Info Request timed out for %s\n", prawpartha->print_string(STRING_BUFFER<256>().get_str_buf()));
		}	
		else {
			statsmap["Internal Error"]++;
		}	

		return false;

	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, 
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while handling Listener Info Request : %s\n\n", GY_GET_EXCEPT_STRING);
		);	
		return false;
	);
}


/*
 * We need to delete this aggr task from remote listener tables if it was a TCP client.
 * The remote Listener may be on a different madhava host and we need to send the 
 * delete msg to the remote Madhava instance
 */
void MCONN_HANDLER::handle_aggr_task_deletion(MAGGR_TASK *pmtask, PARTHA_INFO *prawpartha, REMOTE_PING_MAP & remote_map, STACK_ID_SET_ARENA & stacksetarena)
{
	auto		pclilistentbl = pmtask->cli_listener_tbl_.get();
	auto		premotelisttbl = pmtask->remote_listener_tbl_.get();
	
	if (!pclilistentbl && !premotelisttbl) {
		return;
	}	

	if (pclilistentbl) {
		auto lwalk = [pmtask, hashid = get_uint64_hash(pmtask->aggr_task_id_)](MWEAK_LISTEN_ID *pdatanode, void *arg) -> CB_RET_E
		{
			auto		listenshr = pdatanode->weaklisten_.lock();
			auto		plistener = listenshr.get();

			if (!plistener) {
				return CB_DELETE_ELEM;
			}	

			plistener->cli_aggr_task_tbl_->delete_single_elem(pmtask->aggr_task_id_, hashid);

			return CB_OK;
		};	
		
		pclilistentbl->walk_hash_table(lwalk);
	}

	if (premotelisttbl) {
		auto rwalk = [&](MWEAK_LISTEN_ID *pdatanode, void *arg) -> CB_RET_E
		{
			auto		listenshr = pdatanode->weaklisten_.lock();
			auto		plistener = listenshr.get();

			if (!plistener) {
				return CB_DELETE_ELEM;
			}	

			if (gy_likely(plistener->madhava_id_ != gmadhava_id_)) {
				// Remote Listener

				auto [mit, present] = remote_map.try_emplace(plistener->madhava_id_, plistener->madhava_weak_, stacksetarena);

				mit->second.second.emplace(pmtask->aggr_task_id_);
				
				return CB_OK;
			}	
			else {
				return CB_DELETE_ELEM;
			}	
		};	

		premotelisttbl->walk_hash_table(rwalk);
	}
}	

void MCONN_HANDLER::ping_remote_aggr_task(MAGGR_TASK *pmtask, MWEAK_LISTEN_TABLE *plistentbl, REMOTE_PING_MAP & remote_map, STACK_ID_SET_ARENA & stacksetarena)
{
	auto lwalk = [&](MWEAK_LISTEN_ID *pdatanode, void *arg) -> CB_RET_E
	{
		auto		listenshr = pdatanode->weaklisten_.lock();
		auto		plistener = listenshr.get();

		if (!plistener) {
			return CB_DELETE_ELEM;
		}	

		if (gy_likely(plistener->madhava_id_ != gmadhava_id_)) {
			// Remote Listener

			auto [mit, present] = remote_map.try_emplace(plistener->madhava_id_, plistener->madhava_weak_, stacksetarena);

			mit->second.second.emplace(pmtask->aggr_task_id_);

			return CB_OK;
		}	
		else {
			return CB_DELETE_ELEM;
		}	
	};	
	
	plistentbl->walk_hash_table(lwalk);
}	


uint64_t MCONN_HANDLER::send_remote_aggr_task_deletion(REMOTE_PING_MAP & remote_map, POOL_ALLOC_ARRAY *pthrpoolarr)
{
	uint64_t			nmadhava = 0;

	for (const auto & it : remote_map) {
		auto madshr			= it.second.first.lock();
		auto pmad			= madshr.get();
		
		if (!pmad) {
			continue;
		}

		auto 				& idset = it.second.second;
		auto				shrconn = pmad->get_last_conn(comm::CLI_TYPE_REQ_RESP);
		auto 				pconn1 = shrconn.get();

		FREE_FPTR			free_fp;
		uint32_t			act_size;

		if (pconn1 && idset.size()) {

			size_t				fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + idset.size() * sizeof(MM_TASK_AGGR_DEL);

			void				*palloc = pthrpoolarr->opt_safe_malloc(pthrpoolarr, fixed_sz, free_fp, act_size);

			COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
			EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>((uint8_t *)phdr + sizeof(COMM_HEADER)); 
			MM_TASK_AGGR_DEL		*ptask = reinterpret_cast<MM_TASK_AGGR_DEL *>((uint8_t *)pnot + sizeof(*pnot));
			
			new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, fixed_sz, pconn1->get_comm_magic());
			
			new (pnot) EVENT_NOTIFY(NOTIFY_MM_TASK_AGGR_DEL, idset.size());

			for (uint64_t id : idset) {
				ptask->aggr_task_id_	= id;
				ptask++;
			}	

			schedule_l1_send_data(shrconn, comm::COMM_EVENT_NOTIFY, EPOLL_IOVEC_ARR(2, false, palloc, fixed_sz, free_fp, gpadbuf, phdr->get_pad_len(), nullptr));

			nmadhava++;
		}
	}	

	return nmadhava;
}	

uint64_t MCONN_HANDLER::send_remote_aggr_task_ping(REMOTE_PING_MAP & remote_map, POOL_ALLOC_ARRAY *pthrpoolarr)
{
	uint64_t  		nmadhava = 0;

	for (const auto & it : remote_map) {
		auto madshr			= it.second.first.lock();
		auto pmad			= madshr.get();
		
		if (!pmad) {
			continue;
		}

		auto 				& idset = it.second.second;
		auto				shrconn = pmad->get_last_conn(comm::CLI_TYPE_REQ_RESP);
		auto 				pconn1 = shrconn.get();

		FREE_FPTR			free_fp;
		uint32_t			act_size;

		if (pconn1 && idset.size()) {

			size_t				fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + idset.size() * sizeof(MM_TASK_AGGR_PING);

			void				*palloc = pthrpoolarr->safe_malloc(fixed_sz, free_fp, act_size);
			COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
			EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>((uint8_t *)phdr + sizeof(COMM_HEADER)); 
			MM_TASK_AGGR_PING		*ptask = reinterpret_cast<MM_TASK_AGGR_PING *>((uint8_t *)pnot + sizeof(*pnot));
			
			new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, fixed_sz, pconn1->get_comm_magic());
			
			new (pnot) EVENT_NOTIFY(NOTIFY_MM_TASK_AGGR_PING, idset.size());

			for (uint64_t id : idset) {
				ptask->aggr_task_id_	= id;
				ptask++;
			}	

			schedule_l1_send_data(shrconn, comm::COMM_EVENT_NOTIFY, EPOLL_IOVEC_ARR(2, false, palloc, fixed_sz, free_fp, gpadbuf, phdr->get_pad_len(), nullptr));

			nmadhava++;
		}
	}	

	return nmadhava;
}	


bool MCONN_HANDLER::handle_add_aggr_task(const std::shared_ptr<MCONNTRACK> &connshr, comm::TASK_AGGR_NOTIFY *ptask, int nevents, uint8_t *pendptr, STATS_STR_MAP & statsmap, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	auto				pconn1 = connshr.get();
	auto				partha_shr = pconn1->get_partha_shared();
	PARTHA_INFO	 		*prawpartha = partha_shr.get(); 
	
	if (!prawpartha) {
		statsmap["Null Partha"]++;
		return false;
	}	

	const uint64_t			tcurrusec = get_usec_time();
	TASK_AGGR_NOTIFY		*pone = ptask;
	int				nnew = 0;
	uint64_t			aggr_task_id = 0;
	uint32_t			ahash = 0;
	bool				bret;
	FREE_FPTR			free_fp;
	uint32_t			act_size;
	
	RCU_LOCK_SLOW			slowlock;

	auto listt = [tcurrusec](MAGGR_TASK_ELEM_TYPE *pdatanode, void *arg1, void *arg2)
	{
		MAGGR_TASK			*pmtask = pdatanode->get_cref().get();
		TASK_AGGR_NOTIFY		*ptone = (TASK_AGGR_NOTIFY *)arg1;
		
		if (gy_unlikely(nullptr == pmtask)) {
			return CB_DELETE_ELEM;
		}

		if (ptone) {
			pmtask->related_listen_id_ = ptone->related_listen_id_;

			std::memcpy(pmtask->comm_, ptone->comm_, sizeof(pmtask->comm_) - 1);
			pmtask->comm_[sizeof(pmtask->comm_) - 1] = 0;

			if (pmtask->cmdline_len_.load(mo_relaxed) == 0 && ptone->cmdline_len_ > 1) {
				/*
				 * This indicates that the In Memory Aggregation task was populated as a result of a TCP conn/Listener but 
				 * where no cmdline was available. We will have to limit the cmdline to 77 bytes to avoid a heap alloc.
				 */
				uint16_t		cmdlen = std::min<uint16_t>(pmtask->cmdline_.MAX_SSO_SZ - 1, ptone->cmdline_len_ - 1);

				pmtask->cmdline_.assign((const char *)(ptone + 1), cmdlen);
				pmtask->cmdline_len_.store(cmdlen, mo_seq_cst);
			}	

			if (ptone->tag_len_ > 1 && ptone->tag_len_ <= sizeof(pmtask->tagbuf_)) {
				pmtask->tag_len_ = ptone->tag_len_ - 1;

				std::memcpy(pmtask->tagbuf_, (const char *)ptone + sizeof(*ptone) + ptone->cmdline_len_ , pmtask->tag_len_);
				pmtask->tagbuf_[pmtask->tag_len_] = 0;

				if (pmtask->tagbuf_[pmtask->tag_len_ - 1] == 0) {
					pmtask->tag_len_--;
				}	
			}

			pmtask->uid_ 				= ptone->uid_;
			pmtask->gid_				= ptone->gid_;
			pmtask->is_high_cap_			= ptone->is_high_cap_;
			pmtask->is_cpu_cgroup_throttled_	= ptone->is_cpu_cgroup_throttled_;
			pmtask->is_mem_cgroup_limited_		= ptone->is_mem_cgroup_limited_;
			pmtask->is_rt_proc_			= ptone->is_rt_proc_;
			pmtask->is_container_proc_		= ptone->is_container_proc_;
		}

		pmtask->last_tusec_	= tcurrusec;
		pmtask->ntasks_.store(1, mo_relaxed);	// Wait for next ping to update this

		return CB_OK;
	};	
		
	for (int i = 0; i < nevents && (uint8_t *)pone < pendptr; ++i) {
		size_t			elem_sz = pone->get_elem_size();

		aggr_task_id		= pone->aggr_task_id_;
		ahash			= get_uint64_hash(pone->aggr_task_id_);

		bret = prawpartha->task_aggr_tbl_.lookup_single_elem(aggr_task_id, ahash, listt, pone);
		if (bret == false) {

			MAGGR_TASK			*pmtask;
			
			pmtask = (MAGGR_TASK *)pthrpoolarr->safe_malloc(sizeof(MAGGR_TASK), free_fp, act_size, false /* try_other_pools */, true /* use_malloc_hdr */);

			new (pmtask) MAGGR_TASK(pone->aggr_task_id_, pone->comm_, (const char *)(pone + 1), prawpartha->weak_from_this(), prawpartha->machine_id_,
							gmadhava_weak_, gmadhava_id_, pone->cmdline_len_, pone->related_listen_id_, 
							(const char *)pone + sizeof(*pone) + pone->cmdline_len_, pone->tag_len_, tcurrusec);

			MAGGR_TASK_ELEM_TYPE *pmtaskelem = (MAGGR_TASK_ELEM_TYPE *)pthrpoolarr->safe_malloc(sizeof(MAGGR_TASK_ELEM_TYPE), free_fp, act_size, false, true);
			
			new (pmtaskelem) MAGGR_TASK_ELEM_TYPE(pmtask, TPOOL_DEALLOC<MAGGR_TASK>());

			listt(pmtaskelem, pone, nullptr);

			prawpartha->task_aggr_tbl_.insert_unique(pmtaskelem, aggr_task_id, ahash);
			nnew++;
		}	

		pone = (decltype(pone))((uint8_t *)pone + elem_sz);
	}	

	slowlock.unlock();


done1 :

	if (nnew > 0) {
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Partha %s : Added %d new Aggregate Tasks and updated %d existing Tasks\n",
				prawpartha->print_string(STRING_BUFFER<256>().get_str_buf()), nnew, nevents - nnew);
	}	

	return true;
}	

bool MCONN_HANDLER::handle_aggr_task_hist_stats(const std::shared_ptr<MCONNTRACK> &connshr, AGGR_TASK_HIST_STATS *ptask, int nevents, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool)
{
	auto				pconn1 = connshr.get();
	auto				partha_shr = pconn1->get_partha_shared();
	PARTHA_INFO	 		*prawpartha = partha_shr.get(); 
	
	if (!prawpartha) {
		return false;
	}	

	HIST_DATA 			hist_data[] {95};
	size_t				total_val;
	int				max_val;

	auto				*pcurr = ptask;
	int				nupd = 0;

	RCU_LOCK_SLOW			slowlock;

	auto listt = [&](MAGGR_TASK_ELEM_TYPE *pdatanode, void *arg1, void *arg2)
	{
		MAGGR_TASK		*pmtask = pdatanode->get_cref().get();
		auto			*pone = (AGGR_TASK_HIST_STATS *)arg1;

		if (gy_unlikely(nullptr == pmtask)) {
			return CB_DELETE_ELEM;
		}

		if (pmtask->task_hist_) {
			pmtask->task_hist_->cpu_pct_histogram_.get_percentiles(hist_data, GY_ARRAY_SIZE(hist_data), total_val, max_val);
			pone->p95_cpu_pct_ = hist_data[0].data_value;

			pmtask->task_hist_->cpu_delay_histogram_.get_percentiles(hist_data, GY_ARRAY_SIZE(hist_data), total_val, max_val);
			pone->p95_cpu_delay_ms_ = hist_data[0].data_value;

			pmtask->task_hist_->blkio_delay_histogram_.get_percentiles(hist_data, GY_ARRAY_SIZE(hist_data), total_val, max_val);
			pone->p95_blkio_delay_ms_ = hist_data[0].data_value;
		}

		pmtask->histstats_	= *pone;

		return CB_OK;
	};	
		
	for (int i = 0; i < nevents; ++i, pcurr++) {
		nupd += (int)prawpartha->task_aggr_tbl_.lookup_single_elem(pcurr->aggr_task_id_, get_uint64_hash(pcurr->aggr_task_id_), listt, pcurr);
	}	

	slowlock.unlock();

	CONDEXEC(
		DEBUGEXECN(1,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Partha Host %s : Updated %d Aggr Task Histogram Stats out of total %d\n", 
				prawpartha->hostname_, nupd, nevents);
		);
	);

	return true;
}

bool MCONN_HANDLER::handle_ping_aggr_task(const std::shared_ptr<PARTHA_INFO> &partha_shr, PING_TASK_AGGR *ptask, int nevents, POOL_ALLOC_ARRAY *pthrpoolarr, PGConnPool & dbpool, bool isdummycall)
{
	STACK_ID_SET_ARENA		stack_id_set_arena;
	REMOTE_PING_MAP_ARENA		remote_ping_arena;
	REMOTE_PING_MAP			remote_ping_map(remote_ping_arena), remote_del_map(remote_ping_arena);

	PARTHA_INFO	 		*prawpartha = partha_shr.get(); 
	
	if (!prawpartha) {
		return false;
	}	

	const uint64_t			tcurr = get_usec_time();
	PING_TASK_AGGR			*pcurr = ptask;
	int				nupd = 0, ndel = 0, norigdel = 0;
	uint64_t			tsec, ninfo = 0;
	size_t				nmadhava_ping = 0, nmadhava_del = 0;

	CONDDECLARE(
		STRING_BUFFER<8000>	strbuf;
	);
	
	RCU_LOCK_SLOW			slowlock;

	auto listt = [&, tcurr](MAGGR_TASK_ELEM_TYPE *pdatanode, void *arg1, void *arg2)
	{
		MAGGR_TASK			*pmtask = pdatanode->get_cref().get();
		PING_TASK_AGGR			*pone = (PING_TASK_AGGR *)arg1;

		if (gy_unlikely(nullptr == pmtask)) {
			return CB_DELETE_ELEM;
		}

		if (pone->keep_task_) {
			pmtask->last_tusec_	= tcurr;
			pmtask->ntasks_.store(pone->ntasks_, mo_relaxed);	
		
			if (pone->ntasks_ > 1) {
				pmtask->init_task_hist(tcurr);
			}

			if (pone->related_listen_id_ && pmtask->related_listen_id_ != pone->related_listen_id_) {
				pmtask->related_listen_id_ = pone->related_listen_id_;
			}

			nupd++;
			
			auto			plistentbl = pmtask->remote_listener_tbl_.get();
			
			if (plistentbl) {
				ping_remote_aggr_task(pmtask, plistentbl, remote_ping_map, stack_id_set_arena);
			}

			CONDEXEC(
				DEBUGEXECN(11,
					strbuf.appendfmt("\n\t\tAggr Task \'%s\' : # Tasks %d : %s : # TCP Conns %d : Listener %s : # Local Listeners connected %lu : # Remote Listeners %lu",
						pmtask->comm_, pmtask->ntasks_.load(mo_relaxed), pmtask->is_remote_task_ ? "Remote Task" : "Local Task",
						pmtask->tcp_cli_in_use_.load(mo_relaxed), pmtask->related_listen_id_ ? "true" : "false",
						pmtask->cli_listener_tbl_ ? pmtask->cli_listener_tbl_->approx_count_fast() : 0ul,
						pmtask->remote_listener_tbl_ ? pmtask->remote_listener_tbl_->approx_count_fast() : 0ul);

				);
			);

			return CB_OK;
		}
		else {
			ndel++;
			
			CONDEXEC(
				DEBUGEXECN(11,
					strbuf.appendfmt("\n\t\tDeleting Aggr Task \'%s\' : # Tasks %d : %s : # TCP Conns %d : Listener %s : "
						"# Local Listeners connected %lu : # Remote Listeners %lu",
						pmtask->comm_, pmtask->ntasks_.load(mo_relaxed), pmtask->is_remote_task_ ? "Remote Task" : "Local Task",
						pmtask->tcp_cli_in_use_.load(mo_relaxed), pmtask->related_listen_id_ ? "true" : "false",
						pmtask->cli_listener_tbl_ ? pmtask->cli_listener_tbl_->approx_count_fast() : 0ul,
						pmtask->remote_listener_tbl_ ? pmtask->remote_listener_tbl_->approx_count_fast() : 0ul);

				);
			);

			handle_aggr_task_deletion(pmtask, prawpartha, remote_del_map, stack_id_set_arena);

			return CB_DELETE_ELEM;
		}	
	};	
		
	for (int i = 0; i < nevents; ++i, pcurr++) {
		norigdel += int(!pcurr->keep_task_);
		prawpartha->task_aggr_tbl_.lookup_single_elem(pcurr->aggr_task_id_, get_uint64_hash(pcurr->aggr_task_id_), listt, pcurr);
	}	

	slowlock.unlock();

	if (remote_ping_map.size() + remote_del_map.size()) {

		nmadhava_ping = send_remote_aggr_task_ping(remote_ping_map, pthrpoolarr);
		nmadhava_del = send_remote_aggr_task_deletion(remote_del_map, pthrpoolarr);
	}	

	tsec = get_sec_time();

	if (!isdummycall && (tsec > prawpartha->last_aggrinfo_tsec_ + INFO_DB_UPDATE_SEC - INFO_DB_UPDATE_SEC/4)) {
		
		static constexpr size_t		max_db_query_sz = 400 * 1024;

		assert(gy_get_thread_local().get_thread_stack_freespace() >= max_db_query_sz + 64 * 1024);

		STRING_BUFFER<max_db_query_sz>	qbuf;
		auto				timebuf = gy_localtime_iso8601_sec(tsec);
		auto				datetbl = get_db_day_partition(tsec, 30);
		auto				schemabuf = prawpartha->get_db_schema();
		bool				bret;

		auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 10'000 /* max_msec_wait */, false /* reset_on_timeout */);
		
		if (!pconn) {
			db_stats_.nconns_failed_.fetch_add_relaxed(1);
			db_stats_.naggrtaskinfo_failed_.fetch_add_relaxed(1);
			
			DEBUGEXECN(5,
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get DB Conn for Partha %s Aggr Task Info updation\n", prawpartha->hostname_);
			);
			
			goto done1;
		}	

		SharedMutex::ReadHolder		rtscope(prawpartha->rtalerts_.adef_rwmutex_);
		bool				isrtadef = !!prawpartha->rtalerts_.adef_procinfo_.size();

		if (!isrtadef) {
			rtscope.unlock();
		}	
	
		const auto procl = [&, prawpartha, isrtadef, min_upd_tsec = tsec - INFO_DB_UPDATE_SEC - 5](MAGGR_TASK_ELEM_TYPE *pdatanode, void *arg)
		{
			const auto			ptask = pdatanode->get_cref().get();

			if (!ptask) {
				return CB_OK;
			}
			
			if (GY_READ_ONCE(ptask->last_tusec_) < min_upd_tsec) {
				return CB_OK;
			}	

			if (isrtadef) {
				procinfo_rtalert_rwlocked(*prawpartha, *ptask, tsec, timebuf.get()); 
			}

			qbuf.appendfmt("(to_timestamp(%ld),\'%016lx\',\'%s\',\'%016lx\',\'", tsec, ptask->aggr_task_id_, ptask->comm_, ptask->related_listen_id_);

			uint32_t			clen = ptask->cmdline_len_.load(mo_relaxed);

			if (clen > 0) {
				auto		cmdline = pconn->escape_string<512>(ptask->cmdline_.data(), clen);

				qbuf.append(cmdline.get(), cmdline.size());
			}

			qbuf.appendconst("\', \'");

			clen = GY_READ_ONCE(ptask->tag_len_);

			if (clen > 0) {
				auto		tag = pconn->escape_string<512>(ptask->tagbuf_, clen);

				qbuf.append(tag.get(), tag.size());
			}
	
			auto			& hist = ptask->histstats_;

			qbuf.appendfmt("\',%d,%d,\'%c\',\'%c\',\'%c\',\'%c\',\'%c\',to_timestamp(%ld),%d,%d,%d,%d,%d,%hd,%hd,%hd,\'%s\',\'%s\'),", ptask->uid_, ptask->gid_, 
				pgintbool[ptask->is_high_cap_ & 0x1], pgintbool[ptask->is_cpu_cgroup_throttled_ & 0x1], pgintbool[ptask->is_mem_cgroup_limited_ & 0x1], 
				pgintbool[ptask->is_rt_proc_ & 0x1], pgintbool[ptask->is_container_proc_ & 0x1], hist.starttimeusec_/GY_USEC_PER_SEC,
				hist.p95_cpu_pct_, hist.p95_cpu_delay_ms_, hist.p95_blkio_delay_ms_, hist.nprocs_, hist.nthreads_, int16_t(hist.max_cores_allowed_), 
				int16_t(hist.cpu_cg_pct_limit_), int16_t(hist.max_mem_cg_pct_rss_), prawpartha->region_name_, prawpartha->zone_name_);

			ninfo++;

			if (qbuf.bytes_left() < 2048) {
				return CB_BREAK_LOOP;
			}	

			return CB_OK;
		};	
		
		qbuf.appendfmt("insert into %s.aggrtaskinfotbl%s values ", schemabuf.get(), datetbl.get());

		prawpartha->task_aggr_tbl_.walk_hash_table(procl);

		if (isrtadef) {
			rtscope.unlock();
		}

		qbuf.set_last_char(';');

		if (ninfo == 0) {
			goto done1;
		}	

		if (gy_unlikely(true == qbuf.is_overflow())) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Internal Error : Aggr Task Info DB insert buffer overflow occured for Partha %s\n",
				prawpartha->hostname_);
			goto done1;
		}

		bret = PQsendQueryOptim(pconn->get(), qbuf.buffer(), qbuf.size());
		
		if (bret == false) {
			db_stats_.naggrtaskinfo_failed_.fetch_add_relaxed(1);

			DEBUGEXECN(5,
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to schedule DB query to update Partha %s Aggr Task Info due to %s\n", 
						prawpartha->hostname_, PQerrorMessage(pconn->get()));
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
					db_stats_.naggrtaskinfo_failed_.fetch_add_relaxed(1);

					DEBUGEXECN(5,
						ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to insert Partha Aggr Task Info into DB due to %s\n", gyres.get_error_msg());
					);

					return false;
				}	

				return true;
			}
		);
			
		prawpartha->last_aggrinfo_tsec_ = tsec;
	}	

done1 :
	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "%s : Updated %d Aggregate Task Pings and Deleted %d Aggregated Tasks : "
			"# Remote Madhavas pinged = %lu # Remote Madhavas with deletion = %lu : %lu DB Info Updates\n", 
			prawpartha->print_string(STRING_BUFFER<256>().get_str_buf()), nupd, ndel, nmadhava_ping, nmadhava_del, ninfo);

	CONDEXEC(
		DEBUGEXECN(11,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "%s\n", strbuf.buffer());
		);
	);

	return true;
}	

bool MCONN_HANDLER::handle_mm_ping_aggr_task(const std::shared_ptr<MADHAVA_INFO> &madshr, MM_TASK_AGGR_PING *ptask, int nevents)
{
	MADHAVA_INFO	 		*pmadhava = madshr.get(); 
	
	if (!pmadhava) {
		return false;
	}	

	CONDDECLARE(
		STRING_BUFFER<8000>	strbuf;
	);

	const uint64_t			tcurr = get_usec_time();

	RCU_LOCK_SLOW			slowlock;
	MM_TASK_AGGR_PING		*pcurr = ptask;
	int				nupd = 0;
	bool				bret;
	
	auto listt = [&, tcurr](MAGGR_TASK_ELEM_TYPE *pdatanode, void *arg1, void *arg2)
	{
		MAGGR_TASK			*pmtask = pdatanode->get_cref().get();
		MM_TASK_AGGR_PING		*pone = (MM_TASK_AGGR_PING *)arg1;

		if (gy_unlikely(nullptr == pmtask)) {
			return CB_DELETE_ELEM;
		}

		pmtask->last_tusec_ = tcurr;
	
		CONDEXEC(
			DEBUGEXECN(11,
				strbuf.appendfmt("\n\t\tAggr Task \'%s\' : # Tasks %d : %s : # TCP Conns %d : Listener %s : # Local Listeners connected %lu : # Remote Listeners %lu",
					pmtask->comm_, pmtask->ntasks_.load(mo_relaxed), pmtask->is_remote_task_ ? "Remote Task" : "Local Task",
					pmtask->tcp_cli_in_use_.load(mo_relaxed), pmtask->related_listen_id_ ? "true" : "false",
					pmtask->cli_listener_tbl_ ? pmtask->cli_listener_tbl_->approx_count_fast() : 0ul,
					pmtask->remote_listener_tbl_ ? pmtask->remote_listener_tbl_->approx_count_fast() : 0ul);

			);
		);
	
		return CB_OK;
	};	
		
	for (int i = 0; i < nevents; ++i, pcurr++) {
		bret = pmadhava->task_aggr_tbl_.lookup_single_elem(pcurr->aggr_task_id_, get_uint64_hash(pcurr->aggr_task_id_), listt, pcurr);
		nupd += int(bret);
	}	

	slowlock.unlock();

	if (nupd > 0 || gdebugexecn > 0) {
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Madhava %s : Updated %d Remote Aggregate Task Pings\n",
				pmadhava->print_string(STRING_BUFFER<256>().get_str_buf()), nupd);
		CONDEXEC(
			DEBUGEXECN(11,
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "%s\n", strbuf.buffer());
			);
		);
	}	

	return true;
}	

bool MCONN_HANDLER::handle_mm_del_aggr_task(const std::shared_ptr<MADHAVA_INFO> &madshr, MM_TASK_AGGR_DEL *ptask, int nevents, bool isdummycall)
{
	MADHAVA_INFO	 		*pmadhava = madshr.get(); 
	
	if (!pmadhava) {
		return false;
	}	

	CONDDECLARE(
		STRING_BUFFER<8000>	strbuf;
	);

	RCU_LOCK_SLOW			slowlock;
	MM_TASK_AGGR_DEL		*pcurr = ptask;
	int				ndel = 0;
	
	auto listt = [&](MAGGR_TASK_ELEM_TYPE *pdatanode, void *arg1, void *arg2)
	{
		MAGGR_TASK			*pmtask = pdatanode->get_cref().get();
		MM_TASK_AGGR_DEL		*pone = (MM_TASK_AGGR_DEL *)arg1;

		if (gy_unlikely(nullptr == pmtask)) {
			return CB_DELETE_ELEM;
		}

		CONDEXEC(
			DEBUGEXECN(11,
				strbuf.appendfmt("\n\t\tDeleting Aggr Task \'%s\' : # Tasks %d : %s : # TCP Conns %d : Listener %s : "
					"# Local Listeners connected %lu : # Remote Listeners %lu",
					pmtask->comm_, pmtask->ntasks_.load(mo_relaxed), pmtask->is_remote_task_ ? "Remote Task" : "Local Task",
					pmtask->tcp_cli_in_use_.load(mo_relaxed), pmtask->related_listen_id_ ? "true" : "false",
					pmtask->cli_listener_tbl_ ? pmtask->cli_listener_tbl_->approx_count_fast() : 0ul,
					pmtask->remote_listener_tbl_ ? pmtask->remote_listener_tbl_->approx_count_fast() : 0ul);

			);
		);

		auto				plistentbl = pmtask->remote_listener_tbl_.get();
		
		if (plistentbl) {
			auto lwalk = [pmtask, hashid = get_uint64_hash(pmtask->aggr_task_id_)](MWEAK_LISTEN_ID *pdatanode, void *arg) -> CB_RET_E
			{
				auto		listenshr = pdatanode->weaklisten_.lock();
				auto		plistener = listenshr.get();

				if (!plistener) {
					return CB_DELETE_ELEM;
				}	

				plistener->cli_aggr_task_tbl_->delete_single_elem(pmtask->aggr_task_id_, hashid);

				return CB_OK;
			};	
			
			plistentbl->walk_hash_table(lwalk);
		}
		
		return CB_DELETE_ELEM;
	};	
		
	for (int i = 0; i < nevents; ++i, pcurr++) {
		ndel += (int)pmadhava->task_aggr_tbl_.lookup_single_elem(pcurr->aggr_task_id_, get_uint64_hash(pcurr->aggr_task_id_), listt, pcurr);
	}	

	slowlock.unlock();

	if (ndel > 0 || gdebugexecn > 0) {
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Madhava %s : Deleted %d Remote Aggregate Task\n",
				pmadhava->print_string(STRING_BUFFER<256>().get_str_buf()), ndel);
		CONDEXEC(
			DEBUGEXECN(11,
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "%.*s\n", strbuf.sizeint(), strbuf.buffer());
			);
		);
	}	

	return true;
}	



int MCONN_HANDLER::handle_misc_partha_reg(PM_CONNECT_CMD_S *preg, const DB_WRITE_ARR & dbarr, L2_PARAMS & param, POOL_ALLOC_ARRAY *pthrpoolarr, STATS_STR_MAP & statsmap, PGConnPool & dbpool)
{
	auto				pconn1 = dbarr.shrconn_.get();
	
	if (!pconn1) {
		statsmap["Partha Disconnected during Register"]++;
		return -1;
	}	

	bool				bret, is_new = false, info_chg = false;
	char				info_chg_buf[600];
	PARTHA_INFO_ELEM		pstatshr;
	PARTHA_INFO			*pinfo = nullptr;
	GY_MACHINE_ID			machid (preg->machine_id_hi_, preg->machine_id_lo_);
	const uint32_t			mhash = machid.get_hash();
	time_t				tcurr = time(nullptr);
	SM_PARTHA_IDENT_NOTIFY		parnotify;
	size_t				curr_partha_nodes = 0;

	*info_chg_buf = 0;

	/*
	 * Need to securely verify the remote partha registration TODO
	 */

	bret = partha_tbl_.lookup_single_elem(machid, mhash, pstatshr);
	if (bret == true) {
		pinfo = pstatshr.get_cref().get();

		if (!(pinfo && pinfo->partha_ident_key_ != 0 && pinfo->ident_key_expiry_tsec_ >= tcurr)) {
			send_l1_register_connect_error<PM_CONNECT_RESP_S, PM_CONNECT_RESP>(dbarr.pl1_src_, dbarr.shrconn_, dbarr.shrconn_.get(), 
				dbarr.comm_magic_, statsmap, ERR_NOT_VALIDATED,  "Partha Registration not validated by Shyama", pthrpoolarr);

			ERRORPRINT_OFFLOAD("Invalid Partha Registration request : Ident Key could not be validated for partha Machine ID %016lx%016lx from %s and hostname %s\n",
				preg->machine_id_hi_, preg->machine_id_lo_, pconn1->print_peer(STRING_BUFFER<128>().get_str_buf()), preg->hostname_);

			statsmap["Partha Validation Failed"]++;
			return -1;
		}	

		if (pinfo->madhava_id_ != gmadhava_id_ && pinfo->madhava_id_) {
			WARNPRINTCOLOR_OFFLOAD(GY_COLOR_LIGHT_RED, "Partha Registration Madhava Reassignment detected for partha Machine ID %016lx%016lx from %s and hostname %s : "
				"Older Madhava ID was %016lx. Resetting older Partha info...Sending Registration Failure to allow later retry...\n",
				preg->machine_id_hi_, preg->machine_id_lo_, pconn1->print_peer(STRING_BUFFER<128>().get_str_buf()), preg->hostname_, pinfo->madhava_id_); 

			partha_tbl_.delete_single_elem(machid, mhash);

			send_l1_register_connect_error<PM_CONNECT_RESP_S, PM_CONNECT_RESP>(dbarr.pl1_src_, dbarr.shrconn_, dbarr.shrconn_.get(), 
				dbarr.comm_magic_, statsmap, ERR_NOT_VALIDATED,  "Partha Registration failed as different Madhava assigned. Please retry after some time", 
				pthrpoolarr);
			statsmap["Partha Madhava Reassigned"]++;

			return -1;
		}	
	}	
	else {
		/*
		 * Check the partha_id_tbl_
		 */
		SCOPE_GY_MUTEX		scopelock(&node_partha_mutex_);

		auto it = partha_id_tbl_.find(machid); 

		if ((it == partha_id_tbl_.end()) || (it->second.texpiry_sec_ < tcurr)) {
			if (it != partha_id_tbl_.end()) {
				partha_id_tbl_.erase(it);
			}

			scopelock.unlock();

			send_l1_register_connect_error<PM_CONNECT_RESP_S, PM_CONNECT_RESP>(dbarr.pl1_src_, dbarr.shrconn_, dbarr.shrconn_.get(), 
				dbarr.comm_magic_, statsmap, ERR_NOT_VALIDATED,  "Partha Registration not validated by Shyama", pthrpoolarr);

			ERRORPRINT_OFFLOAD("Invalid Partha Registration request : Ident Key could not be validated for partha Machine ID %016lx%016lx from %s and hostname %s\n",
				preg->machine_id_hi_, preg->machine_id_lo_, pconn1->print_peer(STRING_BUFFER<128>().get_str_buf()), preg->hostname_);

			statsmap["Partha Validation Failed"]++;
			return -1;
		}

		parnotify = std::move(it->second);
		partha_id_tbl_.erase(it);

		scopelock.unlock();

		/*
		 * We need to create a new partha node. First check if the max partha limit reached.
		 */
		curr_partha_nodes = partha_tbl_.count_slow();

		// Allow upto 20 hosts over max limit
		if ((curr_partha_nodes + 1 > max_partha_allowed_ + std::min<uint32_t>(20, max_partha_allowed_ * 0.2)) || (curr_partha_nodes >= MAX_PARTHA_PER_MADHAVA - 16)) {

			send_l1_register_connect_error<PM_CONNECT_RESP_S, PM_CONNECT_RESP>(dbarr.pl1_src_, dbarr.shrconn_, dbarr.shrconn_.get(), 
				dbarr.comm_magic_, statsmap, ERR_MAX_LIMIT,  "Max Partha Nodes Limit Reached", pthrpoolarr);

			ERRORPRINT_OFFLOAD("Partha Registration failed for partha Machine ID %016lx%016lx from %s and hostname %s as Max Partha Hosts Allowed limit %lu reached...\n",
				preg->machine_id_hi_, preg->machine_id_lo_, pconn1->print_peer(STRING_BUFFER<128>().get_str_buf()), preg->hostname_, curr_partha_nodes);

			statsmap["Partha Register Fail as Max Limit"]++;
			return -1;
		}

		/*
		 * Create a new partha node
		 */
		pinfo = new PARTHA_INFO();
		
		PARTHA_INFO_ELEM		*pelem; 
		
		try {
			pelem = new PARTHA_INFO_ELEM(pinfo);
		}
		catch(...) {
			delete pinfo;
			throw;
		}	

		is_new = true;
		
		pinfo->machine_id_		= {preg->machine_id_hi_, preg->machine_id_lo_};
		pinfo->ident_key_expiry_tsec_	= parnotify.texpiry_sec_;
		pinfo->partha_ident_key_	= parnotify.partha_ident_key_;
		snprintf(pinfo->machine_id_str_, sizeof(pinfo->machine_id_str_), "%016lx%016lx", pinfo->machine_id_.machid_.first, pinfo->machine_id_.machid_.second);

		pstatshr			= *pelem;

		auto palam = [&](PARTHA_INFO_ELEM *poldelem, PARTHA_INFO_ELEM *pnewelem) noexcept
		{
			pstatshr 			= *poldelem;
			pinfo				= poldelem->get_cref().get();

			pinfo->ident_key_expiry_tsec_	= parnotify.texpiry_sec_;
			pinfo->partha_ident_key_	= parnotify.partha_ident_key_;
			is_new 				= false;
		};	

		partha_tbl_.insert_unique(pelem, pinfo->machine_id_, mhash, palam, true /* delete_after_callback */);
	}
	
	SCOPE_GY_MUTEX			scopelock(&pinfo->mutex_);
	size_t				nconns;
	int64_t				tcurrusec = get_usec_time();

	if (!is_new && pinfo->last_register_tusec_ > 0 && (tcurrusec - int64_t(pinfo->last_register_tusec_/GY_USEC_PER_SEC)) > preg->process_uptime_sec_ && preg->process_uptime_sec_) {
		// Partha was restarted since last registration. We need to clear out in memory stuff such as related_listen_tbl_ etc..
		// XXX Currently we just wait for cleanup_partha_unused_structs()
	}

	pinfo->madhava_id_		= gmadhava_id_;
	pinfo->madhava_weak_		= gmadhava_shr_;

	pinfo->comm_version_		= preg->comm_version_;
	pinfo->partha_version_		= preg->partha_version_;
	pinfo->last_register_tusec_	= tcurrusec;
	pinfo->last_register_cusec_	= get_usec_clock();

	last_partha_chg_tusec_.store(tcurrusec, mo_release);
	
	if (!is_new) {
		if (strcmp(pinfo->hostname_, preg->hostname_)) {
			info_chg 	= true;

			snprintf(info_chg_buf, sizeof(info_chg_buf), "Partha Host Info Change Detected for Machine ID %016lx%016lx : Old Hostname %s : New Hostname %s",
				preg->machine_id_hi_, preg->machine_id_lo_, pinfo->hostname_, preg->hostname_);

		}	
		else if (strcmp(pinfo->cluster_name_, preg->cluster_name_)) {
			info_chg	= true;

			snprintf(info_chg_buf, sizeof(info_chg_buf), "Partha Host Info Change Detected for Machine ID %016lx%016lx : Old Cluster %s : New Cluster %s",
				preg->machine_id_hi_, preg->machine_id_lo_, pinfo->cluster_name_, preg->cluster_name_);
		}	
		else if (strcmp(pinfo->region_name_, preg->region_name_)) {
			info_chg	= true;

			snprintf(info_chg_buf, sizeof(info_chg_buf), "Partha Host Info Change Detected for Machine ID %016lx%016lx : Old Region %s : New Region %s",
				preg->machine_id_hi_, preg->machine_id_lo_, pinfo->region_name_, preg->region_name_);
		}	
		else if (strcmp(pinfo->zone_name_, preg->zone_name_)) {
			info_chg	= true;

			snprintf(info_chg_buf, sizeof(info_chg_buf), "Partha Host Info Change Detected for Machine ID %016lx%016lx : Old Zone %s : New Zone %s",
				preg->machine_id_hi_, preg->machine_id_lo_, pinfo->zone_name_, preg->zone_name_);
		}	

		if (info_chg) {
			// Reset RT Alerts checks
			pinfo->rtalerts_.last_upd_cusec_.store(0, mo_relaxed);
		}
	}

	pinfo->hostname_len_ 		= GY_STRNCPY_LEN(pinfo->hostname_, preg->hostname_, sizeof(pinfo->hostname_));
	pinfo->cluster_len_ 		= GY_STRNCPY_LEN(pinfo->cluster_name_, preg->cluster_name_, sizeof(pinfo->cluster_name_));
	pinfo->cluster_hash_		= gy_cityhash64(pinfo->cluster_name_, pinfo->cluster_len_);
	pinfo->region_len_		= GY_STRNCPY_LEN(pinfo->region_name_, preg->region_name_, sizeof(pinfo->region_name_));
	pinfo->zone_len_		= GY_STRNCPY_LEN(pinfo->zone_name_, preg->zone_name_, sizeof(pinfo->zone_name_));

	/*std::memcpy(pinfo->write_access_key_, preg->write_access_key_, sizeof(pinfo->write_access_key_));*/

	pinfo->kern_version_num_	= preg->kern_version_num_;

	scopelock.unlock();

	/*
	if (preg->taglen_ > 0) {
		pinfo->node_tagname_.lock()->assign(preg->node_tagname_, preg->taglen_);
	}
	*/

	pconn1->get_peer_ip(pinfo->remote_ip_);

	nconns = pinfo->add_conn(dbarr.pl1_src_, dbarr.shrconn_, dbarr.shrconn_.get(), HOST_PARTHA, preg->cli_type_);

	// Now update the conn table params
	pconn1->cli_type_		= preg->cli_type_;
	pconn1->host_type_	 	= HOST_PARTHA;
	pconn1->host_shr_		= pinfo->shared_from_this();
	pconn1->partha_machine_id_	= machid;

	GY_CC_BARRIER();

	if (is_new || info_chg) {
		// Update DB : RCU offlined already
		db_add_partha(pinfo, dbpool);
	}
	else if (1 == nconns) {
	}	

	pconn1->set_registered();

	// Now schedule the response

	uint8_t				*palloc;
	FREE_FPTR			free_fp_hdr;
	static constexpr size_t		fixed_sz = sizeof(comm::COMM_HEADER) + sizeof(PM_CONNECT_RESP_S);
	uint32_t			act_size;
	bool				sent_reset_stats = false;

	palloc = (uint8_t *)pthrpoolarr->safe_malloc(fixed_sz, free_fp_hdr, act_size);

	comm::COMM_HEADER		*phdr = reinterpret_cast<comm::COMM_HEADER *>(palloc);
	PM_CONNECT_RESP_S		*presp = reinterpret_cast<PM_CONNECT_RESP_S *>((uint8_t *)phdr + sizeof(comm::COMM_HEADER)); 
	
	phdr->~COMM_HEADER();

	new (phdr) comm::COMM_HEADER(PM_CONNECT_RESP, fixed_sz, dbarr.comm_magic_);

	std::memset((void *)presp, 0, sizeof(*presp));

	presp->error_code_		= ERR_SUCCESS;
	GY_STRNCPY(presp->error_string_, "Successfully Registered", sizeof(presp->error_string_));

	presp->madhava_id_		= gmadhava_id_;
	presp->comm_version_		= preg->comm_version_;
	presp->madhava_version_		= gversion_num;

	GY_STRNCPY(presp->region_name_, region_name_, sizeof(presp->region_name_));
	GY_STRNCPY(presp->zone_name_, zone_name_, sizeof(presp->zone_name_));
	GY_STRNCPY(presp->madhava_name_, madhava_name_, sizeof(presp->madhava_name_));
	
	presp->curr_sec_		= time(nullptr);
	presp->clock_sec_		= get_sec_clock();
	
	// No need to check for multi reset as synchronous connect from partha
	if (preg->last_connect_sec_ > 0 && preg->last_connect_sec_ < get_proc_start()) {
		presp->flags_		= comm::PM_CONNECT_RESP_S::CONN_FLAGS_RESET_STATS;
		sent_reset_stats	= true;
	}

	struct iovec			iov[2] {{phdr, fixed_sz}, {(void *)gpadbuf, phdr->get_pad_len()}};	
	FREE_FPTR			free_fp_arr[2] {free_fp_hdr, nullptr};

	pconn1->schedule_ext_send(EPOLL_IOVEC_ARR(iov, GY_ARRAY_SIZE(iov), free_fp_arr, false));
	
	L1_SEND_DATA			l1data(dbarr.pl1_src_, dbarr.shrconn_, dbarr.shrconn_.get(), dbarr.comm_magic_, PM_CONNECT_RESP, false /* close_conn_on_send */);
	int				ntries = 0;

	do { 
		bret = dbarr.pl1_src_->psignalq_->write(std::move(l1data));
	} while (bret == false && ntries++ < 10);

	if (bret == false) {
		statsmap["L1 Notify Blocked"]++;
		ERRORPRINT_OFFLOAD("Failed to signal Partha Register response for partha Machine ID %016lx%016lx from %s and hostname %s as L1 is blocked...\n", 
			preg->machine_id_hi_, preg->machine_id_lo_, pconn1->print_peer(STRING_BUFFER<128>().get_str_buf()), preg->hostname_);
		return 1;
	}

	int64_t			n = 1;

	(void)::write(dbarr.pl1_src_->signal_fd_, &n, sizeof(int64_t));
	
	if (is_new) {
		statsmap["New Partha Registered"]++;

		STRING_BUFFER<512>		sbuf;

		sbuf.appendfmt("Madhava \'%s\' (%s:%hu) : Registered New Partha Host %s with Machine ID %016lx%016lx from Remote IP %s : Total Partha Hosts being handled = %lu", 
			madhava_name_, service_hostname_, service_port_, preg->hostname_, preg->machine_id_hi_, preg->machine_id_lo_, 
			pconn1->print_peer(STRING_BUFFER<128>().get_str_buf()), curr_partha_nodes + 1);

		INFOPRINT_OFFLOAD("%s\n", sbuf.buffer());

		add_notificationq(NOTIFY_INFO, tcurr, sbuf.buffer(), sbuf.size(), machid);
	}
	else if (info_chg) {
		statsmap["Existing Partha with Info Change Registered"]++;

		NOTEPRINT_OFFLOAD("%s\n", info_chg_buf);

		INFOPRINT_OFFLOAD("Registered Connection from existing Partha Host %s with Machine ID %016lx%016lx from Remote IP %s : "
			"Current # connections from this Partha host is %lu\n", 
			preg->hostname_, preg->machine_id_hi_, preg->machine_id_lo_, pconn1->print_peer(STRING_BUFFER<128>().get_str_buf()), 
			pinfo->get_num_conns());

		add_notificationq(NOTIFY_INFO, tcurr, info_chg_buf, strlen(info_chg_buf), machid);
	}	
	else {
		statsmap["Existing Partha Registered"]++;

		INFOPRINT_OFFLOAD("Registered Connection from existing Partha Host %s with Machine ID %016lx%016lx from Remote IP %s : "
			"Current # connections from this Partha host is %lu\n", 
			preg->hostname_, preg->machine_id_hi_, preg->machine_id_lo_, pconn1->print_peer(STRING_BUFFER<128>().get_str_buf()), 
			pinfo->get_num_conns());
	}	

	DEBUGEXECN(1, 
		if (sent_reset_stats) {
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_GREEN, "Sent Reset Stats to Partha Host %s as it was already previously registered before process started...\n",
				preg->hostname_);
		}	
	);	

	return 0;
}	

int MCONN_HANDLER::handle_misc_madhava_reg(MM_CONNECT_CMD_S *preg, const DB_WRITE_ARR & dbarr, L2_PARAMS & param, POOL_ALLOC_ARRAY *pthrpoolarr, STATS_STR_MAP & statsmap)
{
	auto				pconn1 = dbarr.shrconn_.get();

	if (!pconn1) {
		statsmap["Remote Madhava Disconnected during Register"]++;
		return -1;
	}	

	MADHAVA_INFO_ELEM		mstatshr;
	MADHAVA_INFO			*pinfo = nullptr;
	time_t				tcurr = time(nullptr);
	uint64_t			madhava_id = preg->local_madhava_id_;
	uint32_t			mhash = get_uint64_hash(madhava_id);
	bool				bret, is_new = false;

	/*
	 * Need to securely verify the remote madhava registration TODO
	 */

	bret = madhava_tbl_.lookup_single_elem(madhava_id, mhash, mstatshr);
	if ((bret == true) && mstatshr.get_cref()) {
		pinfo = mstatshr.get_cref().get();
	}	
	else {
		/*
		 * We need to create a new madhava node. First check if the max madhava limit reached.
		 */
		size_t madcnt = madhava_tbl_.count_slow();

		if (madcnt + 1 >= comm::MAX_MADHAVA_PER_SHYAMA) {
			send_l1_register_connect_error<MM_CONNECT_RESP_S, MM_CONNECT_RESP>(dbarr.pl1_src_, dbarr.shrconn_, dbarr.shrconn_.get(), 
				dbarr.comm_magic_, statsmap, ERR_MAX_LIMIT,  "Max Madhava Limit Reached", pthrpoolarr);

			ERRORPRINT_OFFLOAD("Remote Madhava Registration failed for Madhava ID %016lx from %s and Hostname %s port %hu as Max Madhava Allowed limit reached...\n",
				madhava_id, pconn1->print_peer(STRING_BUFFER<128>().get_str_buf()), preg->madhava_hostname_, preg->madhava_port_);

			statsmap["Remote Madhava Register Fail as Max Limit"]++;
			return -1;
		}

		/*
		 * Create a new Madhava node
		 */
		pinfo = new MADHAVA_INFO(preg->madhava_hostname_, preg->madhava_port_, preg->local_madhava_id_);
		
		MADHAVA_INFO_ELEM		*pelem; 
		
		try {
			pelem = new MADHAVA_INFO_ELEM(pinfo);
		}
		catch(...) {
			delete pinfo;
			throw;
		}	

		mstatshr = *pelem;

		auto milam = [&](MADHAVA_INFO_ELEM *poldelem, MADHAVA_INFO_ELEM *pnewelem)
		{
			mstatshr = *poldelem;
		};	

		bret = madhava_tbl_.insert_unique(pelem, madhava_id, mhash, milam, true /* delete_after_callback */);

		if (bret == false) {
			pinfo = mstatshr.get_cref().get();

			if (!pinfo) {
				GY_THROW_EXCEPTION("[Internal Error]: Null Madhava element seen in Madhava Map");
			}	
		}	
	}
	
	int64_t				tcurrusec = get_usec_time();

	pinfo->comm_version_		= preg->comm_version_;
	pinfo->madhava_version_		= preg->local_version_;

	GY_STRNCPY(pinfo->region_name_, preg->region_name_, sizeof(pinfo->region_name_));
	GY_STRNCPY(pinfo->zone_name_, preg->zone_name_, sizeof(pinfo->zone_name_));
	GY_STRNCPY(pinfo->madhava_name_, preg->madhava_name_, sizeof(pinfo->madhava_name_));

	pinfo->last_reg_tsec_		= tcurr;
	pinfo->npartha_nodes_.store(preg->curr_partha_nodes_, mo_relaxed);

	/*
	if (preg->taglen_ > 0) {
		pinfo->node_tagname_.lock()->assign(preg->node_tagname_, preg->taglen_);
	}	
	*/

	pconn1->get_peer_ip(pinfo->remote_ip_);

	// Set this conn as a CLI_TYPE_RESP_REQ as its only being used by remote peer and not us
	pinfo->add_conn(dbarr.pl1_src_, dbarr.shrconn_, dbarr.shrconn_.get(), HOST_MADHAVA, CLI_TYPE_RESP_REQ);

	// Now update the conn table params
	pconn1->cli_type_		= CLI_TYPE_RESP_REQ;
	pconn1->host_type_	 	= HOST_MADHAVA;
	pconn1->host_shr_		= pinfo->shared_from_this();

	GY_CC_BARRIER();

	pconn1->set_registered();

	// Now schedule the response

	uint8_t				*palloc;
	FREE_FPTR			free_fp_hdr;
	static constexpr size_t		fixed_sz = sizeof(comm::COMM_HEADER) + sizeof(MM_CONNECT_RESP_S);
	uint32_t			act_size;
	bool				sent_reset_stats = false;

	palloc = (uint8_t *)pthrpoolarr->safe_malloc(fixed_sz, free_fp_hdr, act_size);

	comm::COMM_HEADER		*phdr = reinterpret_cast<comm::COMM_HEADER *>(palloc);
	MM_CONNECT_RESP_S		*presp = reinterpret_cast<MM_CONNECT_RESP_S *>((uint8_t *)phdr + sizeof(comm::COMM_HEADER)); 
	
	phdr->~COMM_HEADER();

	new (phdr) comm::COMM_HEADER(MM_CONNECT_RESP, fixed_sz, dbarr.comm_magic_);

	std::memset((void *)presp, 0, sizeof(*presp));

	presp->error_code_		= ERR_SUCCESS;
	GY_STRNCPY(presp->error_string_, "Successfully Registered", sizeof(presp->error_string_));

	presp->comm_version_		= preg->comm_version_;

	GY_STRNCPY(presp->region_name_, region_name_, sizeof(presp->region_name_));
	GY_STRNCPY(presp->zone_name_, zone_name_, sizeof(presp->zone_name_));
	GY_STRNCPY(presp->madhava_name_, madhava_name_, sizeof(presp->madhava_name_));

	presp->curr_sec_		= time(nullptr);
	presp->clock_sec_		= get_sec_clock();
	
	struct iovec			iov[2] {{phdr, fixed_sz}, {(void *)gpadbuf, phdr->get_pad_len()}};	
	FREE_FPTR			free_fp_arr[2] {free_fp_hdr, nullptr};

	pconn1->schedule_ext_send(EPOLL_IOVEC_ARR(iov, GY_ARRAY_SIZE(iov), free_fp_arr, false));
	
	L1_SEND_DATA			l1data(dbarr.pl1_src_, dbarr.shrconn_, dbarr.shrconn_.get(), dbarr.comm_magic_, MM_CONNECT_RESP, false /* close_conn_on_send */);
	int				ntries = 0;

	do { 
		bret = dbarr.pl1_src_->psignalq_->write(std::move(l1data));
	} while (bret == false && ntries++ < 3);

	if (bret == false) {
		statsmap["L1 Notify Blocked"]++;
		ERRORPRINT_OFFLOAD("Failed to signal Remote Madhava Registration response for Madhava ID %016lx from %s and Hostname %s port %hu as L1 is blocked...\n",
			madhava_id, pconn1->print_peer(STRING_BUFFER<128>().get_str_buf()), preg->madhava_hostname_, preg->madhava_port_);
		return 1;
	}

	int64_t			n = 1;

	(void)::write(dbarr.pl1_src_->signal_fd_, &n, sizeof(int64_t));
	
	INFOPRINT_OFFLOAD("Registered Connection from Remote Madhava Host %s port %hu with Madhava ID %016lx from Remote IP %s : "
		"Current # connections from this host is %lu\n", 
		preg->madhava_hostname_, preg->madhava_port_, madhava_id, pconn1->print_peer(STRING_BUFFER<128>().get_str_buf()), 
		pinfo->get_num_conns());

	return 0;
}

int MCONN_HANDLER::handle_misc_node_reg(NM_CONNECT_CMD_S *pnm, const DB_WRITE_ARR & dbarr, L2_PARAMS & param, POOL_ALLOC_ARRAY *pthrpoolarr, STATS_STR_MAP & statsmap)
{
	auto				pconn1 = dbarr.shrconn_.get();

	if (nullptr == pconn1) {
		statsmap["Node Disconnected"]++;

		return 1;
	}

	bool				bret, is_new = false;
	NODE_INFO			*pninfo = nullptr;
	std::shared_ptr<NODE_INFO>	nodeshr;	
	DOMAIN_PORT			domain_port(pnm->node_hostname_, pnm->node_port_);
	
	SCOPE_GY_MUTEX			scopelock(&node_partha_mutex_);

	auto it = node_tbl_.find(domain_port);
	
	if (it != node_tbl_.end()) {
		nodeshr = it->second;
		pninfo = it->second.get();

		if (pninfo && ((pninfo->listener_port_.get_port() != pnm->node_port_) || (0 != strcmp(pninfo->listener_port_.get_domain(), pnm->node_hostname_)))) {
			send_l1_register_connect_error<NM_CONNECT_RESP_S, NM_CONNECT_RESP>(dbarr.pl1_src_, dbarr.shrconn_, dbarr.shrconn_.get(), 
				dbarr.comm_magic_, statsmap, ERR_MISMATCH_ID,  "Invalid Node domain or port as Node ID does not match", pthrpoolarr);

			ERRORPRINT_OFFLOAD("Invalid Node Registration request : "
				"Node ID is mapped to a different Domain %s or Port %hu compared to request domain %s port %hu\n", 
				pninfo->listener_port_.get_domain(), pninfo->listener_port_.get_port(), pnm->node_hostname_, pnm->node_port_);

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
				pnm->node_hostname_, pnm->node_port_, node_tbl_.size());

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
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while creating new Node entry %s\n", GY_GET_EXCEPT_STRING);
			node_tbl_.erase(nit);

			send_l1_register_connect_error<NM_CONNECT_RESP_S, NM_CONNECT_RESP>(dbarr.pl1_src_, dbarr.shrconn_, dbarr.shrconn_.get(), 
				dbarr.comm_magic_, statsmap, ERR_SERV_ERROR,  "Exception occurred while adding entry", pthrpoolarr);

			return -1;
		);

		nodeshr = nit->second;
		pninfo = nit->second.get();

		is_new = true;
	}	
	
	scopelock.unlock();

	pninfo->diff_sys_sec_ 		= time(nullptr) - pnm->curr_sec_;
	pconn1->get_peer_ip(pninfo->remote_ip_);
	
	pninfo->comm_version_		= pnm->comm_version_;
	pninfo->node_version_		= pnm->node_version_;

	pninfo->add_conn(dbarr.pl1_src_, dbarr.shrconn_, dbarr.shrconn_.get(), HOST_NODE_WEB, pnm->cli_type_);

	// Now update the conn table params
	pconn1->host_type_		= HOST_NODE_WEB;
	pconn1->cli_type_		= pnm->cli_type_;
	pconn1->host_shr_		= pninfo->shared_from_this();
	pconn1->set_registered();
	
	// Now schedule the response

	uint8_t				*palloc;
	FREE_FPTR			free_fp_hdr;
	static constexpr size_t		fixed_sz = sizeof(comm::COMM_HEADER) + sizeof(NM_CONNECT_RESP_S);
	uint32_t			act_size;

	palloc = (uint8_t *)pthrpoolarr->safe_malloc(fixed_sz, free_fp_hdr, act_size);

	comm::COMM_HEADER		*phdr = reinterpret_cast<comm::COMM_HEADER *>(palloc);
	NM_CONNECT_RESP_S		*presp = reinterpret_cast<NM_CONNECT_RESP_S *>((uint8_t *)phdr + sizeof(comm::COMM_HEADER)); 
	
	new (phdr) comm::COMM_HEADER(NM_CONNECT_RESP, fixed_sz, dbarr.comm_magic_);

	std::memset((void *)presp, 0, sizeof(*presp));

	presp->error_code_		= ERR_SUCCESS;
	GY_STRNCPY(presp->error_string_, "Successfully Registered", sizeof(presp->error_string_));
	presp->madhava_version_		= gversion_num;
	snprintf(presp->madhava_id_, sizeof(presp->madhava_id_), "%016lx", gmadhava_id_);

	struct iovec			iov[3] {{phdr, sizeof(*phdr)}, {presp, sizeof(*presp)}, {(void *)gpadbuf, phdr->get_pad_len()}};	
	FREE_FPTR			free_fp_arr[3] {free_fp_hdr, nullptr, nullptr};

	pconn1->schedule_ext_send(EPOLL_IOVEC_ARR(iov, GY_ARRAY_SIZE(iov), free_fp_arr, false));
	
	L1_SEND_DATA			l1data(dbarr.pl1_src_, dbarr.shrconn_, dbarr.shrconn_.get(), dbarr.comm_magic_, NM_CONNECT_RESP, false /* close_conn_on_send */);
	int				ntries = 0;

	do { 
		bret = dbarr.pl1_src_->psignalq_->write(std::move(l1data));
	} while (bret == false && ntries++ < 3);

	if (bret == false) {
		statsmap["L1 Notify Blocked"]++;
		ERRORPRINT_OFFLOAD("Failed to signal Node Register response for %s port %hu as L1 is blocked...\n", pnm->node_hostname_, pnm->node_port_);
		return 1;
	}

	int64_t			n = 1;

	(void)::write(dbarr.pl1_src_->signal_fd_, &n, sizeof(int64_t));
	

	STRING_BUFFER<128>		strbuf;

	if (is_new) {
		INFOPRINT_OFFLOAD("Registered New Node Server for Host %s Port %hu from Remote IP %s\n", 
			pnm->node_hostname_, pnm->node_port_, pninfo->remote_ip_.printaddr(strbuf));
	}
	else {
		INFOPRINT_OFFLOAD("Registered Connection from existing Node Server"
			" for Host %s Port %hu from Remote IP %s Current # connections from this Node instance is %lu\n", 
			pnm->node_hostname_, pnm->node_port_, pninfo->remote_ip_.printaddr(strbuf), pninfo->get_num_conns());
	}	

	return 0;
}


ssize_t MCONN_HANDLER::send_immediate(MCONNTRACK *pconn1, bool throw_on_error)
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


bool MCONN_HANDLER::send_l1_close_conn(const L1_PARAMS *pl1_src, std::weak_ptr <MCONNTRACK> && weakconn, MCONNTRACK *pconn, const char *errstr, uint32_t errlen) noexcept
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



bool MCONN_HANDLER::db_add_partha(PARTHA_INFO *pinfo, PGConnPool & dbpool)
{
	STRING_BUFFER<2048>		addbuf;
	uint64_t			currtusec = get_usec_time();

	assert(true == gy_thread_rcu().is_rcu_thread_offline());

	// Set last_db_register_tusec_ as 1 so that sync_partha_node_stats() will not send a new db query to add
	pinfo->last_db_register_tusec_.store(1, mo_release);
	pinfo->last_db_upd_tusec_.store(currtusec, mo_relaxed);

	auto				pconn = dbpool.get_conn(true /* wait_response_if_unavail */, 100'000 /* max_msec_wait */, true /* reset_on_timeout */);
		
	if (!pconn) {
		db_stats_.nconns_failed_.fetch_add_relaxed(1, mo_relaxed);
		db_stats_.nadd_partha_failed_.fetch_add(1, mo_relaxed);

		GY_THROW_EXCEPTION("Failed to get a DB connection to schedule query to add new Partha %s. Please retry later",
			pinfo->print_string(STRING_BUFFER<256>().get_str_buf()));
	}	

	auto 				psettings = pmadhava_->psettings_;
	auto				schemabuf = pinfo->get_db_schema();
	bool				bret;

	assert(35 == strlen(schemabuf.get()));

	addbuf.appendfmt("insert into public.parthatbl(machid, hostname, madhavaid, clustername, regtime, createtime, version, region, zone) "
			"values(\'%s\', \'%s\', \'%016lx\', \'%s\', now(), now(), %u, \'%s\', \'%s\') on conflict (machid) do update set "
			"(hostname, clustername, regtime, version, region, zone) = (excluded.hostname, excluded.clustername, excluded.regtime, excluded.version, excluded.region, excluded.zone);",
			pinfo->machine_id_str_, pinfo->hostname_, gmadhava_id_, pinfo->cluster_name_, pinfo->partha_version_, pinfo->region_name_, pinfo->zone_name_);

	auto				res = pconn->pqexec_blocking(addbuf.buffer());

	if (res.is_error()) {
		db_stats_.nadd_partha_failed_.fetch_add(1, mo_relaxed);

		pinfo->last_db_register_tusec_.store(0, mo_release);
		pinfo->last_db_upd_tusec_.store(0, mo_relaxed);
		
		GY_THROW_EXCEPTION("Failed to insert new Partha entry into Postgres DB due to %s", res.get_error_msg());
	}

	addbuf.reset();

	addbuf.appendfmt("select public.gy_add_partha(\'%s\', \'%s\', %s::boolean);\n", schemabuf.get(), pinfo->hostname_, psettings->db_logging != DB_LOGGING_ALWAYS ? "true" : "false");
	addbuf.appendfmt("select public.gy_add_views(\'%s\', \'%s\', \'%s\');\n", schemabuf.get(), pinfo->machine_id_str_, gmadhava_id_str_);
	
	bret = PQsendQueryOptim(pconn->get(), addbuf.buffer(), addbuf.size());
	
	if (bret == false) {
		db_stats_.nadd_partha_failed_.fetch_add(1, mo_relaxed);

		pinfo->last_db_register_tusec_.store(0, mo_release);
		pinfo->last_db_upd_tusec_.store(0, mo_relaxed);

		GY_THROW_EXCEPTION("Failed to schedule query to Postgres to add new Partha due to %s", PQerrorMessage(pconn->get()));
	}	

	pconn->set_resp_cb(
		[parthashr = pinfo->shared_from_this(), this](GyPGConn & conn, GyPGresult gyres, bool is_completed) -> bool
		{
			if (is_completed) {
				if (conn.is_within_tran()) {
					conn.pqexec_blocking("Rollback Work;");
				}						

				conn.make_available();
				return true;
			}	
			
			if (true == gyres.is_error()) {
				db_stats_.nadd_partha_failed_.fetch_add(1, mo_relaxed);
				
				if (parthashr) {
					parthashr->last_db_register_tusec_.store(0, mo_release);
					parthashr->last_db_upd_tusec_.store(0, mo_relaxed);

					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to execute DB query to add new Partha %s due to %s\n", 
						parthashr->print_string(STRING_BUFFER<256>().get_str_buf()), gyres.get_error_msg());
				}
				return false;
			}	

			if (parthashr) {
				auto			tusec = get_usec_time();

				parthashr->last_db_register_tusec_.store(tusec, mo_release);
				parthashr->last_db_upd_tusec_.store(tusec, mo_relaxed);

				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Updated DB with newly Added Partha %s successfully : Current TID = %d...\n",
					parthashr->print_string(STRING_BUFFER<256>().get_str_buf()), gy_gettid());
			}

			return true;
		}
	);

	pdb_scheduler_->add_oneshot_schedule(600 * 1000, gy_to_charbuf<128>("New Partha %s reset stats", pinfo->machine_id_str_).get(),
	[this, parthashr = pinfo->shared_from_this()] {
		send_partha_reset_stats(parthashr.get());
	}, false);	

	return true;
}	

struct CLUSTER_STATE_ONE : public comm::MS_CLUSTER_STATE::STATE_ONE
{
	void update_from_state(const comm::HOST_STATE_NOTIFY & state, const LISTEN_SUMM_STATS<int> & summstats) noexcept
	{
		nhosts_++;
		ntasks_issue_		+= state.ntasks_issue_;
		ntaskissue_hosts_	+= !!state.ntasks_issue_;
		ntasks_			+= state.ntasks_;

		nsvc_issue_		+= state.nlisten_issue_;
		nsvcissue_hosts_	+= !!state.nlisten_issue_;
		nsvc_			+= state.nlisten_;
		total_qps_		+= summstats.tot_qps_;
		svc_net_mb_		+= (summstats.tot_kb_inbound_ + summstats.tot_kb_outbound_)/1024;

		ncpu_issue_		+= state.cpu_issue_;
		nmem_issue_		+= state.mem_issue_;
	}	
};

void MCONN_HANDLER::send_cluster_state() noexcept
{
	try {
		using ClusterStateMap		= INLINE_STACK_HASH_MAP<CHAR_BUF<comm::MAX_CLUSTER_NAME_LEN>, CLUSTER_STATE_ONE, 40 * 1024, CHAR_BUF<comm::MAX_CLUSTER_NAME_LEN>::CHAR_BUF_HASH>;
		
		ClusterStateMap			clustermap;

		auto lampar = [&, tminusec = get_usec_time() - 6 * GY_USEC_PER_SEC](PARTHA_INFO_ELEM *pdatanode, void *arg1) -> CB_RET_E
		{
			auto			prawpartha = pdatanode->get_cref().get();
			
			if (gy_unlikely(prawpartha == nullptr)) {
				return CB_DELETE_ELEM;
			}	

			const auto 		& state = prawpartha->host_state_;
			const auto 		& summstats = prawpartha->summstats_;
			
			if (GY_READ_ONCE(state.curr_time_usec_) < tminusec) {
				return CB_OK;
			}	

			auto 			[it, success] = clustermap.try_emplace(prawpartha->cluster_name_);

			it->second.update_from_state(state, summstats);

			return CB_OK;
		};

		partha_tbl_.walk_hash_table(lampar);

		if (clustermap.size() == 0) {
			return;
		}

		auto				shrconn = gshyama_.get_last_conn(comm::CLI_TYPE_REQ_RESP);

		if (!shrconn) {
			return;
		}

		size_t				maxelem = std::min<size_t>(clustermap.size(), MS_CLUSTER_STATE::MAX_NUM_CLUSTERS), nelem = 0;
		size_t				fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + maxelem * sizeof(MS_CLUSTER_STATE); 
		void				*palloc = malloc_or_throw(fixed_sz);

		COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
		EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1);
		MS_CLUSTER_STATE		*pstate = reinterpret_cast<MS_CLUSTER_STATE *>(pnot + 1);

		new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, fixed_sz, shrconn->get_comm_magic());
		new (pnot) EVENT_NOTIFY(comm::NOTIFY_MS_CLUSTER_STATE, maxelem);

		for (const auto & [cname, cstate] : clustermap) {
			
			new (pstate++) MS_CLUSTER_STATE(cstate, cname.get());

			if (++nelem == maxelem) {
				break;
			}	
		}	

		schedule_l1_send_data(shrconn, comm::COMM_EVENT_NOTIFY, EPOLL_IOVEC_ARR(2, false, palloc, fixed_sz, ::free, gpadbuf, phdr->get_pad_len(), nullptr));
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while sending Cluster State to Shyama : %s\n", GY_GET_EXCEPT_STRING);
	);
}	

MCONN_HANDLER::RT_ADEF_VEC * MCONN_HANDLER::RT_ALERT_VECS::get_subsys_vec(SUBSYS_CLASS_E csubsys) noexcept
{
	switch (csubsys) {
	
	case SUBSYS_HOSTSTATE		:	return &adef_hoststate_;
	
	case SUBSYS_CPUMEM		:	return &adef_cpumem_;

	case SUBSYS_SVCSUMM		:	return &adef_svcsumm_;
	
	case SUBSYS_SVCSTATE		:	
	case SUBSYS_EXTSVCSTATE		:	
						return &adef_svcstate_;

	case SUBSYS_SVCINFO		:	return &adef_svcinfo_;

	case SUBSYS_ACTIVECONN		:	
	case SUBSYS_EXTACTIVECONN	:	
						return &adef_activeconn_;

	case SUBSYS_CLIENTCONN		:	
	case SUBSYS_EXTCLIENTCONN	:	
						return &adef_clientconn_;

	case SUBSYS_PROCSTATE		:	
	case SUBSYS_EXTPROCSTATE	:	
						return &adef_procstate_;

	case SUBSYS_PROCINFO		:	return &adef_procinfo_;

	case SUBSYS_TOPCPU		:	return &adef_topcpu_;
	case SUBSYS_TOPPGCPU		:	return &adef_toppgcpu_;
	case SUBSYS_TOPRSS		:	return &adef_toprss_;
	case SUBSYS_TOPFORK		:	return &adef_topfork_;
	
	default 			:	return nullptr;
	}
}	

void MCONN_HANDLER::RT_ALERT_VECS::reset_locked() 
{
	adef_hoststate_.clear();
	adef_cpumem_.clear();
	adef_svcsumm_.clear();
	adef_svcstate_.clear();
	adef_svcinfo_.clear();
	adef_activeconn_.clear();
	adef_clientconn_.clear();
	adef_procstate_.clear();
	adef_procinfo_.clear();
	adef_topcpu_.clear();
	adef_toppgcpu_.clear();
	adef_toprss_.clear();
	adef_topfork_.clear();

	last_upd_cusec_.store(0, mo_relaxed);
}	

void MCONN_HANDLER::send_json_block_error(const DB_WRITE_ARR & dbarr) noexcept
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

bool MCONN_HANDLER::send_db_array(DB_WRITE_ARR && dbarr, uint32_t caller_thr_num, STATS_STR_MAP & statsmap, bool is_json_resp)
{
	L2_PARAMS		*parr;
	size_t			maxthr;

	switch (dbarr.dest_thr_type_) {
	
	case TTYPE_L2_MISC :
	default :
		parr = pl2_misc_arr_;
		maxthr = MAX_L2_MISC_THREADS;
		break;

	case TTYPE_L2_DB_RD :
		parr 	= pl2_db_rd_arr_;
		maxthr 	= MAX_L2_DB_READERS;
		break;

	case TTYPE_L2_ALERT :	
		parr 	= pl2_alert_arr_;
		maxthr 	= MAX_L2_ALERT_THREADS;
		break;
	}

	L2_PARAMS		*pdbwr 	= parr + (caller_thr_num % maxthr);
	bool			bret;
	int			ntries = 0;

	do { 
		bret = pdbwr->pmpmc_->write(std::move(dbarr));
	} while (bret == false && ntries++ < 2);

	if (bret == false) {
		// Try the next db thread once
		pdbwr = parr + ((caller_thr_num + 1) % maxthr);

		bret = pdbwr->pmpmc_->write(std::move(dbarr));

		if (bret == false) {
			if (is_json_resp) {
				send_json_block_error(dbarr); 
			}	

			dbarr.dealloc();
			statsmap["Write Array Thread Blocked"]++;

			return false;
		}	
	}

	/*DEBUGEXECN(11, INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Sent Message to %s\n", pdbwr->descbuf_););*/

	return bret;
}


void MCONN_HANDLER::cleanup_partha_unused_listeners(const std::shared_ptr<PARTHA_INFO> & parshr, POOL_ALLOC_ARRAY & thrpool, PGConnPool & dbpool)
{
	PARTHA_INFO	 		*prawpartha = parshr.get(); 
	int				ndels = 0, nremmad = 0;

	if (!prawpartha) {
		return;
	}	

	if (true) {
		// Don't use too much Stack space as partha_listener_state() will allocate over 800KB stack itself

		alignas(8) uint8_t		delarr[LISTENER_STATE_NOTIFY::MAX_NUM_LISTENERS * sizeof(LISTENER_STATE_NOTIFY)];
		uint64_t			tcurr = time(nullptr), min_upd_tusec = get_usec_time() - 30 * GY_USEC_PER_MINUTE;

		/*
		 * We walk the listen_tbl_ searching for listeners not updated for last 30 min and simulate a delete listener using LISTENER_STATE_NOTIFY delete
		 */
		auto awalk = [&, min_upd_tusec, min_mesh_tsec = time_t(tcurr - 10 * 60)](MTCP_LISTENER_ELEM_TYPE *pdatanode, void *arg1) -> CB_RET_E
		{
			MTCP_LISTENER			*plistener = pdatanode->get_cref().get();

			if (gy_unlikely(nullptr == plistener)) {
				return CB_DELETE_ELEM;
			}

			if (plistener->last_state_tusec_.load(mo_acquire) < min_upd_tusec) {
				LISTENER_STATE_NOTIFY		*pdel = (LISTENER_STATE_NOTIFY *)(delarr + ndels * sizeof(LISTENER_STATE_NOTIFY));

				new (pdel) LISTENER_STATE_NOTIFY();

				pdel->glob_id_ 		= plistener->glob_id_;
				pdel->query_flags_	= LISTEN_FLAG_DELETE;

				pdel->set_padding_len();
			
				ndels++;

				if ((unsigned)ndels >= LISTENER_STATE_NOTIFY::MAX_NUM_LISTENERS - 1) {
					return CB_BREAK_LOOP;
				}	
			}	

			if ((plistener->eff_mesh_cluster_id_.load(mo_relaxed) > 0) && (plistener->tlast_mesh_upd_ < min_mesh_tsec)) {
				plistener->eff_mesh_cluster_id_.store(0, mo_relaxed);

				plistener->is_cluster_mesh_ 	= false;
				plistener->ntotal_mesh_svc_ 	= 0;
			}	

			return CB_OK;
		};	

		prawpartha->listen_tbl_.walk_hash_table(awalk);

		if (ndels > 0) {
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Partha host %s : Deleting %d listeners due to inactivity\n", prawpartha->hostname_, ndels);

			partha_listener_state(parshr, (LISTENER_STATE_NOTIFY *)delarr, ndels, delarr + ndels * sizeof(LISTENER_STATE_NOTIFY), &thrpool, dbpool, true /* isdummycall */);
		}
	}

	if (true) {
		using MMPingVec			= GY_STACK_VECTOR<MM_LISTENER_PING, 32 * 1024>;
		using MMPingVecArena		= MMPingVec::allocator_type::arena_type;

		struct MMPingVecSize
		{
			MMPingVec			vec_;
			std::shared_ptr<MCONNTRACK>	shrconn_;

			MMPingVecSize(MMPingVecArena & arena) : vec_(arena)
			{}
		};

		using MMPingMap			= GY_STACK_HASH_MAP<uint64_t, MMPingVecSize, 80 * 1024, GY_JHASHER<uint64_t>>;
		using MMPingMapArena		= MMPingMap::allocator_type::arena_type;

		MMPingVecArena			pingvecarena;
		MMPingMapArena			pingmaparena;
		MMPingMap			pingmap(pingmaparena);

		uint64_t			min_upd_tusec = get_usec_time() - 5 * GY_USEC_PER_MINUTE;

		auto pinglist = [&](WEAK_REMOTE_MADHAVA *pweakmad, void *arg) -> CB_RET_E
		{
			uint64_t	glob_id = (uint64_t)(uintptr_t)arg;

			auto 		[it, success] = pingmap.try_emplace(pweakmad->madhava_id_, pingvecarena);

			if (success == true) {
				auto	madshr = pweakmad->weakmad_.lock();

				if (madshr) {
					it->second.shrconn_ = madshr->get_last_conn(comm::CLI_TYPE_REQ_RESP);
				}	
			}

			if (it->second.shrconn_) {
				it->second.vec_.emplace_back(glob_id);
			}	

			return CB_OK;
		};	

		/*
		 * We walk the listen_tbl_ searching for listeners updated in last 5 min and having remote_madhava_tbl_ entries
		 */
		auto awalk = [&, min_upd_tusec](MTCP_LISTENER_ELEM_TYPE *pdatanode, void *arg1) -> CB_RET_E
		{
			MTCP_LISTENER			*plistener = pdatanode->get_cref().get();

			if (gy_unlikely(nullptr == plistener)) {
				return CB_DELETE_ELEM;
			}

			if (plistener->last_state_tusec_.load(mo_acquire) > min_upd_tusec) {
				plistener->remote_madhava_tbl_->walk_hash_table(pinglist, (void *)(uintptr_t)plistener->glob_id_);
			}	

			return CB_OK;
		};	

		prawpartha->listen_tbl_.walk_hash_table(awalk);

		for (const auto & epair : pingmap) {
			uint64_t	 	madid = epair.first;
			const auto 		& madvec = epair.second.vec_;
			const auto		& shrconn = epair.second.shrconn_;

			if (!shrconn || (madvec.empty())) {
				continue;
			}

			nremmad++;

			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Partha host %s : Sending %lu Listener Ping Messages to Remote Madhava %s\n",
				prawpartha->hostname_, madvec.size(), shrconn->print_peer(STRING_BUFFER<256>().get_str_buf()));

			size_t			fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + madvec.size() * sizeof(MM_LISTENER_PING);
			FREE_FPTR		free_fp;
			uint32_t		act_size;
			void			*palloc = thrpool.safe_malloc(fixed_sz, free_fp, act_size);

			COMM_HEADER		*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
			EVENT_NOTIFY		*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1);
			MM_LISTENER_PING	*plist = reinterpret_cast<MM_LISTENER_PING *>(pnot + 1);

			new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, fixed_sz, shrconn->get_comm_magic());
			new (pnot) EVENT_NOTIFY(comm::NOTIFY_MM_LISTENER_PING, madvec.size());
			
			std::memcpy(plist, madvec.data(), madvec.size() * sizeof(MM_LISTENER_PING));

			schedule_l1_send_data(shrconn, comm::COMM_EVENT_NOTIFY, EPOLL_IOVEC_ARR(2, false, palloc, fixed_sz, free_fp, gpadbuf, phdr->get_pad_len(), nullptr));
		}	
	}	
}	


void MCONN_HANDLER::cleanup_mm_unused_listeners(const std::shared_ptr<MADHAVA_INFO> & madshr)
{
	MADHAVA_INFO	 		*pmadhava = madshr.get(); 

	if (!pmadhava) {
		return;
	}	

	constexpr int			max_del_pings = 2048;
	alignas(8) uint8_t		delarr[max_del_pings * sizeof(MM_LISTENER_DELETE)];
	uint64_t			min_upd_tusec = get_usec_time() - 30 * GY_USEC_PER_MINUTE;
	int				ndels = 0;

	/*
	 * We walk the listen_tbl_ searching for listeners not updated for last 30 min and simulate a delete listener using MM_LISTENER_DELETE 
	 */
	auto awalk = [&, min_upd_tusec](MTCP_LISTENER_ELEM_TYPE *pdatanode, void *arg1) -> CB_RET_E
	{
		MTCP_LISTENER			*plistener = pdatanode->get_cref().get();

		if (gy_unlikely(nullptr == plistener)) {
			return CB_DELETE_ELEM;
		}

		if (GY_READ_ONCE(plistener->rem_madhava_ping_tusec_) < min_upd_tusec) {
			MM_LISTENER_DELETE		*pdel = (MM_LISTENER_DELETE *)(delarr + ndels * sizeof(MM_LISTENER_DELETE));

			new (pdel) MM_LISTENER_DELETE(plistener->glob_id_);

			ndels++;

			if (ndels >= max_del_pings) {
				return CB_BREAK_LOOP;
			}	
		}	

		return CB_OK;
	};	

	pmadhava->listen_tbl_.walk_hash_table(awalk);

	if (ndels > 0) {
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Remote Madhava %s : Deleting %d Remote Listeners due to inactivity\n",
				pmadhava->print_string(STRING_BUFFER<256>().get_str_buf()), ndels);

		handle_mm_listener_delete(madshr, (MM_LISTENER_DELETE *)delarr, ndels, true /* isdummycall */);
	}
}

void MCONN_HANDLER::cleanup_partha_unused_aggr_tasks(const std::shared_ptr<PARTHA_INFO> & parshr, POOL_ALLOC_ARRAY & thrpool, PGConnPool & dbpool)
{
	constexpr int			max_del_pings = 2048;

	PARTHA_INFO	 		*prawpartha = parshr.get(); 
	alignas(8) uint8_t		pingarr[max_del_pings * sizeof(PING_TASK_AGGR)];
	uint64_t			min_upd_tusec = get_usec_time() - 30 * GY_USEC_PER_MINUTE;
	int				npings = 0;

	if (!prawpartha) {
		return;
	}	

	/*
	 * We walk the task_aggr_tbl_ searching for tasks not updated for last 30 min and simulate a delete task comm msg using PING_TASK_AGGR
	 */
	auto awalk = [&, min_upd_tusec](MAGGR_TASK_ELEM_TYPE *pdatanode, void *arg1) -> CB_RET_E
	{
		MAGGR_TASK			*pmtask = pdatanode->get_cref().get();

		if (gy_unlikely(nullptr == pmtask)) {
			return CB_DELETE_ELEM;
		}

		if (GY_READ_ONCE(pmtask->last_tusec_) < min_upd_tusec) {
			PING_TASK_AGGR		*pping = (PING_TASK_AGGR *)(pingarr + npings * sizeof(PING_TASK_AGGR));

			new (pping) PING_TASK_AGGR(pmtask->aggr_task_id_);
			pping->keep_task_ = false;
		
			npings++;

			if (npings >= max_del_pings) {
				return CB_BREAK_LOOP;
			}	
		}	

		return CB_OK;
	};	

	prawpartha->task_aggr_tbl_.walk_hash_table(awalk);

	if (npings == 0) {
		return;
	}	

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Partha host %s : Deleting %d Aggr Tasks due to inactivity\n", prawpartha->hostname_, npings);

	handle_ping_aggr_task(parshr, (PING_TASK_AGGR *)pingarr, npings, &thrpool, dbpool, true /* isdummycall */);
}	

void MCONN_HANDLER::cleanup_mm_unused_aggr_tasks(const std::shared_ptr<MADHAVA_INFO> & madshr)
{
	constexpr int			max_del_pings = 1024;

	MADHAVA_INFO	 		*pmadhava = madshr.get(); 

	if (!pmadhava) {
		return;
	}	

	alignas(8) uint8_t		pingarr[max_del_pings * sizeof(MM_TASK_AGGR_DEL)];
	uint64_t			min_upd_tusec = get_usec_time() - 30 * GY_USEC_PER_MINUTE;
	int				npings = 0;

	/*
	 * We walk the task_aggr_tbl_ searching for tasks not updated for last 30 min and simulate a delete task comm msg using MM_TASK_AGGR_DEL
	 */
	auto awalk = [&, min_upd_tusec](MAGGR_TASK_ELEM_TYPE *pdatanode, void *arg1) -> CB_RET_E
	{
		MAGGR_TASK			*pmtask = pdatanode->get_cref().get();

		if (gy_unlikely(nullptr == pmtask)) {
			return CB_DELETE_ELEM;
		}

		if (GY_READ_ONCE(pmtask->last_tusec_) < min_upd_tusec) {
			MM_TASK_AGGR_DEL	*pping = (MM_TASK_AGGR_DEL *)(pingarr + npings * sizeof(MM_TASK_AGGR_DEL));

			pping->aggr_task_id_ 	= pmtask->aggr_task_id_;
		
			npings++;

			if (npings >= max_del_pings) {
				return CB_BREAK_LOOP;
			}	
		}	

		return CB_OK;
	};	

	pmadhava->task_aggr_tbl_.walk_hash_table(awalk);

	if (npings == 0) {
		return;
	}	

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Remote Madhava %s : Deleting %d Remote Aggregate Tasks due to inactivity\n",
				pmadhava->print_string(STRING_BUFFER<256>().get_str_buf()), npings);

	handle_mm_del_aggr_task(madshr, (MM_TASK_AGGR_DEL *)pingarr, npings, true /* isdummycall */);
}	

void MCONN_HANDLER::cleanup_rem_madhava_unused_structs() noexcept
{
	try {
		POOL_ALLOC_ARRAY		emptypool;

		auto lammad = [&](MADHAVA_INFO_ELEM *pdatanode, void *arg1) -> CB_RET_E
		{
			auto		& madshr = pdatanode->get_cref();

			if (madshr && madshr->madhava_id_ == gmadhava_id_) {
				return CB_OK;
			}	

			try {
				cleanup_mm_unused_aggr_tasks(madshr);
				cleanup_mm_unused_listeners(madshr);
			}
			GY_CATCH_EXCEPTION(
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while cleaning up remote Madhava %s unused structs : %s\n\n", 
					madshr->print_string(STRING_BUFFER<512>().get_str_buf()), GY_GET_EXCEPT_STRING);
			);

			return CB_OK;
		};

		madhava_tbl_.walk_hash_table(lammad);
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while cleaning up remote Madhava unused structs : %s\n\n", GY_GET_EXCEPT_STRING);
	);
}	


void MCONN_HANDLER::cleanup_partha_unused_structs() noexcept
{
	try {
		POOL_ALLOC_ARRAY		emptypool;

		auto lampar = [&](PARTHA_INFO_ELEM *pdatanode, void *arg1) -> CB_RET_E
		{
			const auto		& parshr = pdatanode->get_cref();
			auto			prawpartha = parshr.get();
			
			if (gy_unlikely(prawpartha == nullptr)) {
				return CB_DELETE_ELEM;
			}	

			try {
				// Check if no host status seen recenly as the host status, listener status and aggr task status sent on the same thread by partha
				if (prawpartha->last_register_tusec_ && prawpartha->get_last_host_state_tusec() < get_usec_time() - 10 * GY_USEC_PER_MINUTE && prawpartha->get_num_conns()) {
					WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Partha %s : Connected to Madhava but no Host States seen for over 10 min. Sending Reset Stats msg...\n",
						prawpartha->hostname_);
					
					send_partha_reset_stats(prawpartha);
				}	

				cleanup_partha_unused_aggr_tasks(parshr, emptypool, *db_scheduler_pool_.get());
				cleanup_partha_unused_listeners(parshr, emptypool, *db_scheduler_pool_.get());
			}
			GY_CATCH_EXCEPTION(
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while cleaning up partha host %s unused structs : %s\n\n", 
					prawpartha->hostname_, GY_GET_EXCEPT_STRING);
			);

			return CB_OK;
		};

		partha_tbl_.walk_hash_table(lampar);
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while cleaning up partha unused structs : %s\n\n", GY_GET_EXCEPT_STRING);
	);
}	

std::shared_ptr<MCONN_HANDLER::MCONNTRACK> MCONN_HANDLER::get_any_node_conn() noexcept
{
	std::shared_ptr<MCONNTRACK>	shrconn;
	SCOPE_GY_MUTEX			scopelock(node_partha_mutex_);
		
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

GyPGConn MCONN_HANDLER::get_new_db_conn(bool auto_reconnect)
{
	auto 				psettings = pmadhava_->psettings_;
	auto				dbname = get_dbname();

	return GyPGConn(psettings->postgres_hostname, psettings->postgres_port, psettings->postgres_user, psettings->postgres_password,
						dbname.get(), "madhava_adhoc", get_db_init_commands().get(), auto_reconnect, 12, 2, 2);
}	


int MCONN_HANDLER::sync_partha_node_stats() noexcept
{
	try {
		MS_PARTHA_PING			msping[comm::MS_PARTHA_PING::MAX_PARTHA_PING];	
		size_t				nmsping = 0;
		auto				nshconn = gshyama_.get_num_conns();
		int64_t				npartha, nparthadel = 0, nparthaconn = 0, nparnodes = 0;
		int64_t				nnode = 0, nnodedel = 0, nnodeconn = 0;
		int				nmaxpar = 0, nregpar =  0;
		uint64_t			tprocstart = get_proc_start_tusec(), tlast = std::max(last_par_db_upd_tusec_, tprocstart),
						tminregusec = get_usec_time() - 12 * GY_USEC_PER_MINUTE;
		time_t				tcurr = time(nullptr);
		void				*psend_all = nullptr;
		bool				send_all = false;
		STRING_BUFFER<4096>		strbuf;

		GY_SCOPE_EXIT {
			if (psend_all) {
				::free(psend_all);
			}	
		};	

		if (shyama_reset_stats_) {
			// XXX Need to analyze
			shyama_reset_stats_ = false;
		}	

		if (nshconn) {
			if (shyama_send_parthas_) {
				shyama_send_parthas_ = false;

				send_all = true;

				nmaxpar = (int)partha_tbl_.count_slow();

				if (nmaxpar > 0 && nmaxpar + 8 < (int)MS_REG_PARTHA::MAX_REG_PARTHA) {
					nmaxpar += 8;
				}	

				if (nmaxpar > 0) {
					psend_all = malloc_or_throw(sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + nmaxpar * sizeof(MS_REG_PARTHA));
				}
			}	

			if (tcurr > tpartha_pingall_) {
				tminregusec = tprocstart;

				tpartha_pingall_ = tcurr + 5 * 3600;
			}	
		}

		/*
		 * XXX Do we need to resend gy_add_partha() if partha last_db_upd_tusec_ is not set...?
		 */

		auto			ptmpreg = (psend_all ? (MS_REG_PARTHA *)((char *)psend_all + sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY)) : nullptr);

		auto lampar = [&, tprocstart, tlast, tcurr, tminregusec, tminhostateusec = get_usec_time() - 2 * GY_USEC_PER_MINUTE, nshconn](PARTHA_INFO_ELEM *pdatanode, void *arg1) -> CB_RET_E
		{
			const auto		& parshr = pdatanode->get_cref();
			auto			prawpartha = parshr.get();
			uint64_t		last_oper; 
			time_t			tdisconn = prawpartha->last_disconnect_tsec_.load(mo_acquire);
			size_t			nconn;
			
			if (gy_unlikely(prawpartha == nullptr)) {
				nparthadel++;
				return CB_DELETE_ELEM;
			}	

			last_oper = std::max(prawpartha->get_last_oper_time(), tprocstart);

			nconn = prawpartha->get_num_conns();
			nparthaconn += nconn;

			strbuf.appendfmt("\t\t\tPartha Host %s Region %s Zone %s : # conns %lu\n", prawpartha->hostname_, prawpartha->region_name_, prawpartha->zone_name_, nconn);

			if (nconn > 0) {
				nparnodes++;

				if (ptmpreg && nregpar < nmaxpar && prawpartha->get_last_host_state_tusec() > tminhostateusec) {

					ptmpreg->machine_id_		= prawpartha->machine_id_;
					ptmpreg->comm_version_		= prawpartha->comm_version_;
					ptmpreg->partha_version_	= prawpartha->partha_version_;

					GY_SAFE_STR_MEMCPY(ptmpreg->hostname_, sizeof(ptmpreg->hostname_), prawpartha->hostname_, prawpartha->hostname_len_);
					GY_SAFE_STR_MEMCPY(ptmpreg->cluster_name_, sizeof(ptmpreg->cluster_name_), prawpartha->cluster_name_, prawpartha->cluster_len_);
					GY_SAFE_STR_MEMCPY(ptmpreg->region_name_, sizeof(ptmpreg->region_name_), prawpartha->region_name_, prawpartha->region_len_);
					GY_SAFE_STR_MEMCPY(ptmpreg->zone_name_, sizeof(ptmpreg->zone_name_), prawpartha->zone_name_, prawpartha->zone_len_);

					ptmpreg->kern_version_num_	= prawpartha->kern_version_num_;

					nregpar++;
					ptmpreg++;
				}

				if ((prawpartha->last_register_tusec_ > tminregusec) || (!prawpartha->is_shyama_pinged_)) {
					if (nmsping < GY_ARRAY_SIZE(msping)) {
						msping[nmsping++] = MS_PARTHA_PING(prawpartha->machine_id_, false);

						if (nshconn > 0) {
							prawpartha->is_shyama_pinged_ = true;
						}
					}	
				}	
			}

			if (last_oper > tlast) {
				// Do we need to update DB... ?
			}	
			else {
				if ((nconn == 0) && (tlast - last_oper > MAX_PARTHA_CONN_DELETE_USEC)) {
					if (++prawpartha->ndel_times_ > 2) {
						// We need to delete this element
						nparthadel++;

						NOTEPRINT_OFFLOAD("Deleting %s data as host has not connected since last %ld hours...\n",
							prawpartha->print_string(STRING_BUFFER<256>().get_str_buf()), (tlast - last_oper)/GY_USEC_PER_HOUR);

						return CB_DELETE_ELEM;
					}
					else {
						if (nmsping < GY_ARRAY_SIZE(msping)) {
							msping[nmsping++] = MS_PARTHA_PING(prawpartha->machine_id_, true);
						}	
					}	
				}	
			}
				
			return CB_OK;
		};

		npartha = partha_tbl_.walk_hash_table(lampar);

		last_partha_conns_	= nparthaconn;

		if (strbuf.length()) {
			INFOPRINT_OFFLOAD("List of Partha Hosts : \n%s\n", strbuf.buffer());
		}

		INFOPRINT_OFFLOAD("Total Number of Partha Hosts handled is %ld, # Partha currently Connected is %ld, # Partha Deleted is %ld, "
				"Total # of Partha Connections is %ld, # Pings to Shyama %lu\n",
				npartha - nparthadel, nparnodes, nparthadel, nparthaconn, nmsping);

		last_par_db_upd_tusec_	= get_usec_time();
			
		if (nmsping > 0 || nregpar > 0) {
			try {
				auto				shrconn = gshyama_.get_last_conn(comm::CLI_TYPE_REQ_RESP);
				auto 				pconn1 = shrconn.get();

				if (pconn1) {

					if (nregpar > 0 && psend_all) {
						void 				*palloc = std::exchange(psend_all, nullptr);

						size_t				fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + nregpar * sizeof(MS_REG_PARTHA);

						COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
						EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1); 
						
						new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, fixed_sz, pconn1->get_comm_magic());
						new (pnot) EVENT_NOTIFY(comm::NOTIFY_MS_REG_PARTHA, nregpar);

						schedule_l1_send_data(shrconn, comm::COMM_EVENT_NOTIFY, EPOLL_IOVEC_ARR(2, false, palloc, fixed_sz, ::free, gpadbuf, phdr->get_pad_len(), nullptr));

						INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Sent %d Parthas Registered to Shyama as per Shyama started recently...\n", nregpar);
					}

					if (nmsping > 0) {

						size_t				fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + nmsping * sizeof(MS_PARTHA_PING);

						void				*palloc = malloc(fixed_sz);
						if (!palloc) {
							goto next1;
						}	

						COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
						EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1); 
						MS_PARTHA_PING			*pstat = reinterpret_cast<MS_PARTHA_PING *>(pnot + 1);
						
						new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, fixed_sz, pconn1->get_comm_magic());
						new (pnot) EVENT_NOTIFY(comm::NOTIFY_MS_PARTHA_PING, nmsping);

						std::memcpy((void *)pstat, msping, nmsping * sizeof(*pstat));

						schedule_l1_send_data(shrconn, comm::COMM_EVENT_NOTIFY, EPOLL_IOVEC_ARR(2, false, palloc, fixed_sz, ::free, gpadbuf, phdr->get_pad_len(), nullptr));
					}
				}
			}
			GY_CATCH_EXCEPTION(
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while sending Shyama Partha Pings / Registered Parthas  : %s\n\n", GY_GET_EXCEPT_STRING);
			);
		}	
			
next1 :			
		SCOPE_GY_MUTEX		scopelock(node_partha_mutex_);
			
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

			++it;
		}	

		last_node_cnt_ = nnode;

		scopelock.unlock();

		INFOPRINT_OFFLOAD("Total Number of Node Web servers registered is %ld, # Nodes recently Disconnected is %ld, Total # of Connections from all Node servers is %ld\n",
			nnode, nnodedel, nnodeconn);

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while updating partha pings and node statistics : %s\n\n", GY_GET_EXCEPT_STRING);
		return -1;
	);
}	

void MCONN_HANDLER::send_shyama_status() noexcept
{
	try {
		auto				shrconn = gshyama_.get_last_conn(comm::CLI_TYPE_REQ_RESP);
		auto 				pconn1 = shrconn.get();

		if (pconn1) {

			static constexpr size_t		fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + sizeof(MADHAVA_SHYAMA_STATUS);

			void				*palloc = malloc(fixed_sz);
			if (!palloc) {
				return;
			}	

			COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
			EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>((uint8_t *)phdr + sizeof(COMM_HEADER)); 
			MADHAVA_SHYAMA_STATUS		*pstat = reinterpret_cast<MADHAVA_SHYAMA_STATUS *>((uint8_t *)pnot + sizeof(*pnot));
			
			new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, fixed_sz, pconn1->get_comm_magic());
			
			pnot->subtype_			= comm::NOTIFY_MADHAVA_SHYAMA_STATUS;
			pnot->nevents_			= 1;

			pstat->madhava_id_		= gmadhava_id_;
			pstat->npartha_nodes_		= partha_tbl_.approx_count_fast();
			pstat->approx_partha_conns_	= GY_READ_ONCE(last_partha_conns_);

			schedule_l1_send_data(shrconn, comm::COMM_EVENT_NOTIFY, EPOLL_IOVEC_ARR(2, false, palloc, fixed_sz, ::free, gpadbuf, phdr->get_pad_len(), nullptr));
		}
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while sending Shyama Status  : %s\n\n", GY_GET_EXCEPT_STRING);
	);
}	

void MCONN_HANDLER::send_partha_status() noexcept
{
	try {
		static constexpr size_t		fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + sizeof(MADHAVA_PARTHA_STATUS);
		void				*palloc = GY_REFCNT::allocate_refbuf(fixed_sz);

		GY_SCOPE_EXIT {
			GY_REFCNT::sub_refcount_free(palloc);
		};	

		COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
		EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>((uint8_t *)phdr + sizeof(COMM_HEADER)); 
		MADHAVA_PARTHA_STATUS		*pstat = reinterpret_cast<MADHAVA_PARTHA_STATUS *>((uint8_t *)pnot + sizeof(*pnot));
		
		new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, fixed_sz, comm::COMM_HEADER::PM_HDR_MAGIC);
		
		pnot->subtype_			= comm::NOTIFY_MADHAVA_PARTHA_STATUS;
		pnot->nevents_			= 1;

		pstat->madhava_id_		= gmadhava_id_;
		pstat->npartha_nodes_		= partha_tbl_.approx_count_fast();
		pstat->is_active_madhava_id_	= (GY_READ_ONCE(gshyama_.last_status_.active_madhava_id_) == gmadhava_id_);

		auto lampar = [&, this, palloc](PARTHA_INFO_ELEM *pdatanode, void *arg1) -> CB_RET_E
		{
			auto		ppar = pdatanode->get_data()->get();
			
			if (gy_unlikely(ppar == nullptr)) {
				return CB_DELETE_ELEM;
			}	

			auto				parshrconn = ppar->get_last_conn(comm::CLI_TYPE_RESP_REQ);
			auto 				pconn1 = parshrconn.get();

			if (pconn1) {

				GY_REFCNT::add_refcount(palloc);
				
				schedule_l1_send_data(parshrconn, comm::COMM_EVENT_NOTIFY, 
					EPOLL_IOVEC_ARR(2, false, palloc, fixed_sz, GY_REFCNT::sub_refcount_free, gpadbuf, phdr->get_pad_len(), nullptr));
			}
			return CB_OK;
		};

		partha_tbl_.walk_hash_table(lampar);
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while sending Partha Status  : %s\n\n", GY_GET_EXCEPT_STRING);
	);
}	

void MCONN_HANDLER::send_remote_madhava_status() noexcept
{
	try {
		size_t				nmad, nmadconn = 0, nmaddel = 0, nconns = 0;
		static constexpr size_t		fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + sizeof(MADHAVA_MADHAVA_STATUS);
		void				*palloc = GY_REFCNT::allocate_refbuf(fixed_sz);

		GY_SCOPE_EXIT {
			GY_REFCNT::sub_refcount_free(palloc);
		};	

		COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
		EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>((uint8_t *)phdr + sizeof(COMM_HEADER)); 
		MADHAVA_MADHAVA_STATUS		*pstat = reinterpret_cast<MADHAVA_MADHAVA_STATUS *>((uint8_t *)pnot + sizeof(*pnot));
		
		new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, fixed_sz, comm::COMM_HEADER::MM_HDR_MAGIC);
		
		pnot->subtype_			= comm::NOTIFY_MADHAVA_MADHAVA_STATUS;
		pnot->nevents_			= 1;

		pstat->madhava_id_		= gmadhava_id_;
		pstat->npartha_nodes_		= partha_tbl_.approx_count_fast();

		auto lammad = [&, this, palloc, currtusec = get_usec_time()](MADHAVA_INFO_ELEM *pdatanode, void *arg1) -> CB_RET_E
		{
			auto		pmad = pdatanode->get_cref().get();
			
			if (gy_unlikely(pmad == nullptr)) {
				return CB_DELETE_ELEM;
			}	

			if (pmad->madhava_id_ == gmadhava_id_) {
				return CB_OK;
			}	

			size_t				nc = pmad->get_num_conns();	

			nconns += nc;	
				
			auto				madshrconn = pmad->get_last_conn(comm::CLI_TYPE_REQ_RESP);
			auto 				pconn1 = madshrconn.get();

			if (pconn1) {
				nmadconn++;

				GY_REFCNT::add_refcount(palloc);
				
				schedule_l1_send_data(madshrconn, comm::COMM_EVENT_NOTIFY, 
					EPOLL_IOVEC_ARR(2, false, palloc, fixed_sz, GY_REFCNT::sub_refcount_free, gpadbuf, phdr->get_pad_len(), nullptr));
			}
			else if (nc == 0 && pmad->last_upd_tusec_ < currtusec - MAX_MADHAVA_CONN_DELETE_USEC) {
				nmaddel++;

				NOTEPRINT_OFFLOAD("Deleting Remote Madhava %s as host has not connected since last %ld minutes...\n",
					pmad->print_string(STRING_BUFFER<512>().get_str_buf()), (currtusec - pmad->last_upd_tusec_)/GY_USEC_PER_MINUTE);
				return CB_DELETE_ELEM;
			}

			return CB_OK;
		};

		nmad = madhava_tbl_.walk_hash_table(lammad);

		last_madhava_cnt_ = nmadconn;

		INFOPRINT_OFFLOAD("Number of Madhava instances %lu : # instances connected %lu :  Total # of Connections from all Madhava servers %lu\n", 
			nmad - nmaddel, nmadconn, nconns);

	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while sending Remote Madhava Status  : %s\n\n", GY_GET_EXCEPT_STRING);
	);
}

bool MCONN_HANDLER::schedule_l1_send_data(const std::shared_ptr<MCONNTRACK> & connshr, comm::COMM_TYPE_E data_type, EPOLL_IOVEC_ARR && data_arr, bool close_conn_on_send) noexcept
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

bool MCONN_HANDLER::schedule_l1_query(ASYNC_SOCK_CB && async_cb, const std::shared_ptr<MCONNTRACK> & connshr, EPOLL_IOVEC_ARR && data_arr) noexcept
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

} // namespace madhava
} // namespace gyeeta

