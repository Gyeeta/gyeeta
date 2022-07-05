
#include		"gy_common_inc.h"

// Comment the below line to enable the malloc stats
#define			GY_DISABLE_MALLOC_HOOK

#include		"gy_malloc_hook.h"
#include 		"gy_postgres.h"

using namespace 	gyeeta;

int main(int argc, char **argv)
{
	gdebugexecn = 20;

	if (argc < 7) {
		IRPRINT("\nUsage : %s <dbhost> <dbport> <user> <password> <dbname> <number of conns> <number of iterations (Optional)> <Option select query to be executed>\n\n", argv[0]);
		return 1;
	}	

	PRINT_OFFLOAD::init_singleton();

	PROC_CPU_IO_STATS::init_singleton(30);

	GY_MALLOC_HOOK::gy_malloc_init("Postgres Connection Pool tests", false /* print_individual */);

	GY_MALLOC_HOOK::gy_print_memuse("Starting Connection Pool now...", true);

	size_t			totalconns = atoi(argv[6]), niter = (argc >= 8 ? atoi(argv[7]) : 5);
	const char		*pquery; 

	if (argc >= 9) {
		pquery = argv[8];
	}
	else {
		pquery = "select * from pg_catalog.pg_class, pg_aggregate limit 5;select pg_sleep(1);select count(*) from pg_aggregate;";
	}	
	
	try {
		PGConnPool		pgpool("Test Pool", totalconns, argv[1], atoi(argv[2]), argv[3], argv[4], argv[5], "test_pg"/* , "select * from pg_authid;select * from pg_aggregate;" */);

		for (size_t k = 0; k < totalconns * niter; ++k) {
			auto			pconn = pgpool.get_conn(true /* wait_response_if_unavail */, 100'000 /* max_msec_wait */, true /* reset_on_timeout */);
			bool			bret;
			size_t			nconn;

			if (!pconn) {
				nconn = pgpool.num_connected();

				if (nconn == 0) {
					gy_nanosleep(10, 0);
					continue;
				}	
				else {
					assert(pconn);
				}	
			}	

			GY_MALLOC_HOOK::gy_print_memuse("Before Begin Work", true);

			pconn->pqexec_blocking("Begin Work;");

			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Sending Query from conn %p\n", &(*pconn));

			GY_MALLOC_HOOK::gy_print_memuse("Before Sending Query", true);

			bret = PQsendQueryOptim(pconn->get(), pquery, strlen(pquery));

			GY_MALLOC_HOOK::gy_print_memuse("After Sending Query", true);

			if (bret == false) {
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to schedule command to Postgres connection due to %s\n", PQerrorMessage(pconn->get()));

				pconn->pqexec_blocking("Rollback Work");
				continue;
			}	

			pconn->set_single_row_mode();

			pconn->set_resp_cb(
				[total_tuples = 0](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
				{
					if (is_completed) {
						conn.pqexec_blocking("Commit Work");

						INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Response completed for conn %p : Total tuples returned is %d\n", &conn, total_tuples);
						conn.make_available();
						return true;
					}	
					
					int			ntuples = PQntuples(gyres.get());

					if (true == gyres.is_error()) {
						ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to execute query (Total tuples returned so far %d) : %s\n", 
							total_tuples, gyres.get_error_msg());
						return false;
					}	

					// Handle resultset here...

					total_tuples += ntuples;

					GY_MALLOC_HOOK::gy_print_memuse("Within Response Callback", true);

					return true;
				}
			);

		}	

		pgpool.wait_all_responses();

		assert(true == pgpool.check_or_reconnect());

		GY_MALLOC_HOOK::gy_print_memuse("Before starting insert test...", true);

		do {
			auto				pconn = pgpool.get_conn(true /* wait_response_if_unavail */, 100'000 /* max_msec_wait */, true /* reset_on_timeout */);
			STRING_BUFFER<GY_UP_KB(512)>	qbuf;
			char				descbuf[128];
			bool				bret;
			
			if (!pconn) {
				throw std::runtime_error("Failed to get a connection to DB...\n");
			}

			std::memset(descbuf, '\'', sizeof(descbuf) - 1);
			descbuf[sizeof(descbuf) - 1] = 0;

			pconn->pqexec_blocking("create table test_pg1234512345 (id int, descr text);");

			qbuf.appendconst("Begin work; insert into test_pg1234512345(id, descr) values ");

			for (int i = 0; i < 1024; ++i) {
				qbuf.appendfmt("(%d, \'%s\'),", i, pconn->escape_string<272>(descbuf).get());
			}	
			qbuf.set_last_char(';');

			assert(false == qbuf.is_overflow());

			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Sending Insert Query from conn %p of length %lu\n", &(*pconn), qbuf.size());

			GY_MALLOC_HOOK::gy_print_memuse("Before Sending Insert Query", true);

			bret = PQsendQueryOptim(pconn->get(), qbuf.buffer(), qbuf.size());

			assert(bret != false);

			GY_MALLOC_HOOK::gy_print_memuse("After Sending Insert Query", true);

			pconn->set_resp_cb(
				[](GyPGConn & conn, GyPGresult gyres, bool is_completed) -> bool
				{
					if (is_completed) {
						if (conn.is_within_tran()) {
							conn.pqexec_blocking("Commit Work;");
						}

						INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Insert Response completed for conn %p\n", &conn);
						conn.make_available();
						return true;
					}	
					
					if (true == gyres.is_error()) {
						ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to execute insert query : %s\n", 
							gyres.get_error_msg());
						conn.pqexec_blocking("Rollback Work;");
						return false;
					}	

					// Handle resultset here...
					GY_MALLOC_HOOK::gy_print_memuse("Within Insert Response Callback", true);

					return true;
				}
			);

			pgpool.wait_all_responses();

			pconn = pgpool.get_conn(true /* wait_response_if_unavail */, 100'000 /* max_msec_wait */, true /* reset_on_timeout */);

			assert(pconn);

			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Sending Second Insert Query from conn %p of length %lu\n", &(*pconn), qbuf.size());

			GY_MALLOC_HOOK::gy_print_memuse("Before Sending Second Insert Query", true);

			bret = PQsendQueryOptim(pconn->get(), qbuf.buffer(), qbuf.size());

			assert(bret != false);

			GY_MALLOC_HOOK::gy_print_memuse("After Sending Second Insert Query", true);

			pconn->set_resp_cb(
				[](GyPGConn & conn, GyPGresult gyres, bool is_completed) -> bool
				{
					if (is_completed) {
						if (conn.is_within_tran()) {
							conn.pqexec_blocking("Commit Work;");
						}	
						conn.pqexec_blocking("drop table test_pg1234512345;");

						INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Second Insert Response completed for conn %p\n", &conn);
						conn.make_available();
						return true;
					}	
					
					if (true == gyres.is_error()) {
						ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to execute insert query : %s\n", 
							gyres.get_error_msg());
						conn.pqexec_blocking("Rollback Work;");
						return false;
					}	

					// Handle resultset here...
					GY_MALLOC_HOOK::gy_print_memuse("Within Insert Response Callback", true);

					return true;
				}
			);

			pgpool.wait_all_responses();


		} while (0);

		GY_MALLOC_HOOK::gy_print_memuse("Before exiting...", true);
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught while handling Postgres Connection Pool : %s : Exiting...\n\n", GY_GET_EXCEPT_STRING);
	);
}	
