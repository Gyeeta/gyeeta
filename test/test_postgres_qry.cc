//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include		"gy_common_inc.h"
#include 		"gy_postgres.h"

using namespace 	gyeeta;

int main(int argc, char **argv)
{
	gdebugexecn = 20;

	if (argc < 7) {
		IRPRINT("\nUsage : %s <dbhost> <dbport> <user> <password> <dbname> <query> <Optional Timeout in msec>\n\n", argv[0]);
		IRPRINT("\t\t e.g. : %s localhost 10040 krishna gyeeta dbff269abf0e89f643 "
			"\"select * from sch97d04b2bfccda84198797c1f260e8edd.activeconntbl where time between now() - \'1 hour\'::interval and now() limit 100\"\n\n", argv[0]);
		return 1;
	}	

	PROC_CPU_IO_STATS::init_singleton(30);

	try {
		PGConnPool		pgpool("Test Pool", 2, argv[1], atoi(argv[2]), argv[3], argv[4], argv[5], "test_postgres_qry");

		auto			pconn = pgpool.get_conn();
		int			ret;
		size_t			nconn;
		const char		*pquery = argv[6];
		int			timeoutmsec = -1;

		if (argc > 7) {
			timeoutmsec = atoi(argv[7]);
			if (timeoutmsec == 0) timeoutmsec = -1;
		}	

		ret = PQsendQueryOptim(pconn->get(), pquery, strlen(pquery));

		if (ret == 0) {
			ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to schedule query to Postgres connection due to %s\n", PQerrorMessage(pconn->get()));
			return -1;
		}	

		pconn->set_single_row_mode();

		pconn->set_resp_cb(
			[total_tuples = 0](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
			{
				if (is_completed) {
					INFOPRINTCOLOR(GY_COLOR_YELLOW, "Response completed for : Total tuples returned is %d\n", total_tuples);
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

				/*GY_THROW_EXCEPTION("testing exception at time %lu", get_usec_time());*/

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

		pgpool.wait_one_response(timeoutmsec);

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Query completed...\n\n");

		if (timeoutmsec == -1) {
			assert(2 == pgpool.num_available());
		}
	}
	GY_CATCH_EXPRESSION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught while handling Postgres Query : %s : Exiting...\n\n", GY_GET_EXCEPT_STRING);
	);
}

