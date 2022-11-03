//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include		"gy_common_inc.h"
#include 		"gy_postgres.h"

using namespace 	gyeeta;

int main(int argc, char **argv)
{
	gdebugexecn = 20;

	if (argc < 6) {
		IRPRINT("\nUsage : %s <dbhost> <dbport> <user> <password> <dbname>\n\n", argv[0]);
		IRPRINT("\t\t e.g. : %s localhost 10040 krishna gyeeta dbff269abf0e89f643\n\n", argv[0]);
		return 1;
	}	

	PROC_CPU_IO_STATS::init_singleton(30);

	try {
		PGConnPool			pgpool("Test Pool", 3, argv[1], atoi(argv[2]), argv[3], argv[4], argv[5], "test_postgres_insert", 
							"create table IF NOT EXISTS testinsert (fint int, fchar8 char(8), ftext text); \n"
							"prepare insprep (int, char(8), text) as insert into testinsert values ($1, $2, $3);");
	
		GY_SCOPE_EXIT {
			try {
				auto			pconn = pgpool.get_conn(true /* wait_response_if_unavail */, 10'000 /* max_msec_wait */, true /* reset_on_timeout */);
			
				if (pconn) {
					INFOPRINTCOLOR(GY_COLOR_YELLOW, "Dropping Table testinsert...\n\n");
					pconn->pqexec_blocking("drop table testinsert");
				}	
			}
			catch(...) {
			}	
		};

		size_t				nconn;
		int				ret;
		bool				bret;

		for (int i = 0; i < 3; ++i) {
			
			auto				pconn = pgpool.get_conn(true /* wait_response_if_unavail */, 10'000 /* max_msec_wait */, true /* reset_on_timeout */);

			if (!pconn) {
				throw std::runtime_error("Failed to get a connection to DB...\n");
			}

			const char 			*params1[] {"1", "00000001", "This is 1 \'text\' string with \"quotes\" and \\ and \t;" };

			// Using PQsendQueryPrepared
			bret = PQsendQueryPrepared(pconn->get(), "insprep", 3, params1, nullptr, nullptr, 0);

			if (bret == false) {
				ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to schedule prepared query to Postgres : Error is %s\n", PQerrorMessage(pconn->get()));
				throw std::runtime_error("Failed to schedule a query to DB");
			}	

			pconn->set_resp_cb(
				[](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
				{
					if (is_completed) {
						INFOPRINTCOLOR(GY_COLOR_GREEN, "Insert 1 completed...\n");
						conn.make_available();
						return true;
					}	
					
					if (true == gyres.is_error()) {
						ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to execute insert 1 : SQLCODE \'%s\' : Message : \'%s\'\n", 
							gyres.get_sqlcode(), gyres.get_error_msg());
						return false;
					}	

					return true;
				}
			);
			
			pconn = pgpool.get_conn(true /* wait_response_if_unavail */, 10'000 /* max_msec_wait */, true /* reset_on_timeout */);

			if (!pconn) {
				throw std::runtime_error("Failed to get a connection to DB...\n");
			}

			const char 			*params2[] {"2", "00000002", "This is 2 \'text\' string with \"quotes\" and \\ and \t;" };

			// Using PQsendQueryParams
			bret = PQsendQueryParams(pconn->get(), "insert into testinsert values ($1::int, $2::char(8), $3::text)", 
									3, nullptr, params2, nullptr, nullptr, 0);

			if (bret == false) {
				ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to schedule query params to Postgres : Error is %s\n", PQerrorMessage(pconn->get()));
				throw std::runtime_error("Failed to schedule a query to DB");
			}	

			pconn->set_resp_cb(
				[](GyPGConn &conn, GyPGresult gyres, bool is_completed) mutable -> bool
				{
					if (is_completed) {
						INFOPRINTCOLOR(GY_COLOR_GREEN, "Insert 2 completed...\n");
						conn.make_available();
						return true;
					}	
					
					if (true == gyres.is_error()) {
						ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to execute insert 2 : SQLCODE \'%s\' : Message : \'%s\'\n", 
							gyres.get_sqlcode(), gyres.get_error_msg());
						return false;
					}	

					return true;
				}
			);

			pconn = pgpool.get_conn(true /* wait_response_if_unavail */, 10'000 /* max_msec_wait */, true /* reset_on_timeout */);

			if (!pconn) {
				throw std::runtime_error("Failed to get a connection to DB...\n");
			}

			STRING_BUFFER<512>		strbuf;
			
			strbuf << "insert into testinsert values (" 
					<< 3 << ", \'00000003\', \'" << pconn->escape_string<256>("This is 3 \'text\' string with \"quotes\" and \\ and \t;").get_view() << "\');";

			// Using PQsendQueryOptim
			bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.size());
		
			if (bret == false) {
				ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to schedule query string to Postgres : Error is %s\n", PQerrorMessage(pconn->get()));
				throw std::runtime_error("Failed to schedule a query to DB");
			}	

			pconn->set_resp_cb(GyPGConn::ignore_response_till_end);
		}

		pgpool.wait_all_responses();

		const char		pquery[] {"select * from testinsert"};

		auto			pconn = pgpool.get_conn(true /* wait_response_if_unavail */, 10'000 /* max_msec_wait */, true /* reset_on_timeout */);

		if (nullptr == pconn) {
			throw std::runtime_error("Failed to get a connection to DB...\n");
		}

		ret = PQsendQueryOptim(pconn->get(), pquery, sizeof(pquery) - 1);

		if (ret == 0) {
			ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to schedule select query to Postgres connection due to %s\n", PQerrorMessage(pconn->get()));
			return -1;
		}	

		pconn->set_single_row_mode();

		pconn->set_resp_cb(
			[total_tuples = 0](GyPGConn &conn, GyPGresult gyres, bool is_completed) mutable -> bool
			{
				if (is_completed) {
					INFOPRINTCOLOR(GY_COLOR_YELLOW, "Response completed for query : Total tuples returned is %d\n", total_tuples);
					conn.make_available();
					return true;
				}	
				
				if (true == gyres.is_error()) {
					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to execute query (Total tuples returned so far %d) : SQLCODE \'%s\' : Message : \'%s\'\n", 
						total_tuples, gyres.get_sqlcode(), gyres.get_error_msg());
					return false;
				}	

				// Handle resultset here...

				int				ntuples = PQntuples(gyres.get());
				
				const PGresult *		pres = gyres.get();
				const int			nfields = PQnfields(pres);

				for (int row = 0; row < ntuples; ++row) {
					INFOPRINTCOLOR(GY_COLOR_YELLOW, "Response Row #%d follows : \n", total_tuples + row + 1);
					
					for (int col = 0; col < nfields; ++col) {
						const char	*pfname = PQfname(pres, col);

						if (!pfname) {
							break;
						}	

						int		len = PQgetlength(pres, row, col), rlen;

						if (len == 0) {
							if (true == PQgetisnull(pres, row, col)) {
								IRPRINT("\tRow #%5d Column #%3d %20s : NULL\n", total_tuples + row + 1, col + 1, pfname);
							}	
							else {
								IRPRINT("\tRow #%5d Column #%3d %20s : \'\' : length 0\n", total_tuples + row + 1, col + 1, pfname);
							}	

							continue;
						}

						const char 		*pdata = PQgetvalue(pres, row, col);

						if (PG_BPCHAROID == PQftype(pres, col)) {
							rlen = get_rtrim_len(pdata, len);
						}
						else {
							rlen = len;
						}	

						IRPRINT("\tRow #%5d Column #%3d %20s : \'%s\' : length %d (trim len %d) : OID of column = %d\n", 
								total_tuples + row + 1, col + 1, pfname, pdata, len, rlen, PQftype(pres, col));
					}	
				}	

				total_tuples += ntuples;
	
				return true;
			}
		);

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Query result for \'%s\' follows...\n\n", pquery);

		pgpool.wait_all_responses();

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Query completed...\n\n");

		assert(3 == pgpool.num_available());
	}
	GY_CATCH_EXPRESSION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught while handling Postgres Query : %s : Exiting...\n\n", GY_GET_EXCEPT_STRING);
	);
}

