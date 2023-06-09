#include "gy_common_inc.h"
#include "gy_postgres.h"

using namespace gyeeta;

#include <libpq-fe.h>
#include <arpa/inet.h>

void send_float8_binary(PGconn *conn, double value) 
{
	PGresult *res;

	// Prepare the SQL statement with the binary placeholder
	const char *sql = "INSERT INTO test_table (float8_col) VALUES ($1::double precision)";
	Oid paramTypes[1] = { 701 /* FLOAT8OID */ };

	// Convert the float value to its binary representation
	int64_t binary_value;
	memcpy(&binary_value, &value, sizeof(binary_value));
	int64_t network_byte_order_value = GY_SWAP_64(binary_value);

	// Prepare the parameter values
	const void *paramValues[1] = { &network_byte_order_value };
	const int paramLengths[1] = { sizeof(int64_t) };
	const int paramFormats[1] = { 1 };

	// Execute the prepared statement with binary parameters
	res = PQexecParams(conn, sql, 1, paramTypes, (const char* const*)paramValues, paramLengths, paramFormats, 0);

	// Check for errors
	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to insert float8 value: %s\n", PQerrorMessage(conn));
	}

	PQclear(res);
}
	
void send_timestamp_binary(PGconn *conn, time_t value) 
{
	PGresult *res;

	// Prepare the SQL statement with the binary placeholder
	const char *sql = "INSERT INTO test_table (timestamp_col) VALUES ($1::timestamptz)";
	Oid paramTypes[1] = { 1114 };

	const time_t postgresEpochToUnixEpoch = 946684800;

	// Convert the time_t value to its binary representation
	int64_t binary_value = (value - 946684800);
	int64_t network_byte_order_value;

	unaligned_write_64(&network_byte_order_value, binary_value, BO_BIG_ENDIAN);

	const uint8_t rawbytes[] = "\x02\x9f\x47\x1d\xce\x40"; // 0x29f471dceae40

	// Prepare the parameter values
	const void *paramValues[1] = { rawbytes };
	const int paramLengths[1] = { sizeof(int64_t) };
	const int paramFormats[1] = { 1 };

	// Execute the prepared statement with binary parameters
	res = PQexecParams(conn, sql, 1, paramTypes, (const char* const*)paramValues, paramLengths, paramFormats, 0);

	// Check for errors
	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to insert timestamp value: %s\n", PQerrorMessage(conn));
	}

	PQclear(res);
}

void insertDataUsingCopyCommand(PGconn *conn, const char *tableName, const char *dataFilePath) 
{
	PGresult *res;

	// Construct the COPY command
	const char *copyCommand = "COPY %s FROM STDIN";

	// Create the SQL statement with the table name
	int bufferSize = snprintf(NULL, 0, copyCommand, tableName) + 1;
	char *sql = (char *)malloc(bufferSize);
	sprintf(sql, copyCommand, tableName);

	// Open the data file
	FILE *dataFile = fopen(dataFilePath, "r");
	if (!dataFile) {
		fprintf(stderr, "Failed to open data file: %s\n", dataFilePath);
		free(sql);
		return;
	}

	// Execute the COPY command
	res = PQexecParams(conn, sql, 0, NULL, NULL, NULL, NULL, 1);

	if (PQresultStatus(res) != PGRES_COPY_IN) {
		fprintf(stderr, "COPY command failed: %s\n", PQerrorMessage(conn));
		free(sql);
		PQclear(res);
		fclose(dataFile);
		return;
	}

	// Read and send the data from the file
	char buffer[1024];
	size_t bytesRead;
	while ((bytesRead = fread(buffer, 1, sizeof(buffer), dataFile)) > 0) {
		int result = PQputCopyData(conn, buffer, bytesRead);
		if (result != 1) {
			fprintf(stderr, "Failed to send data: %s\n", PQerrorMessage(conn));
			break;
		}
	}

	// Signal the end of data
	int result = PQputCopyEnd(conn, NULL);
	if (result != 1) {
		fprintf(stderr, "Failed to signal end of data: %s\n", PQerrorMessage(conn));
	}

	// Check for errors during data transmission
	res = PQgetResult(conn);
	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		fprintf(stderr, "Data transmission failed: %s\n", PQerrorMessage(conn));
	}

	// Cleanup
	fclose(dataFile);
	free(sql);
	PQclear(res);
}

void exportDataUsingCopyCommand(PGconn *conn, const char *tableName, const char *outputFilePath) 
{
	PGresult *res;

	// Construct the COPY command
	const char *copyCommand = "COPY %s TO STDOUT";

	// Create the SQL statement with the table name
	int bufferSize = snprintf(NULL, 0, copyCommand, tableName) + 1;
	char *sql = (char *)malloc(bufferSize);
	sprintf(sql, copyCommand, tableName);

	// Execute the COPY command
	res = PQexecParams(conn, sql, 0, NULL, NULL, NULL, NULL, 1);

	if (PQresultStatus(res) != PGRES_COPY_OUT) {
		fprintf(stderr, "COPY command failed: %s\n", PQerrorMessage(conn));
		free(sql);
		PQclear(res);
		return;
	}

	// Open the output file
	FILE *outputFile = fopen(outputFilePath, "w");
	if (!outputFile) {
		fprintf(stderr, "Failed to open output file: %s\n", outputFilePath);
		free(sql);
		PQclear(res);
		return;
	}

	// Read and write the data from the server
	char *buffer;
	int bytesRead;
	while ((bytesRead = PQgetCopyData(conn, &buffer, 0)) > 0) {
		fwrite(buffer, 1, bytesRead, outputFile);
		PQfreemem(buffer);
	}

	if (bytesRead < 0) {
		fprintf(stderr, "Failed to read COPY data: %s\n", PQerrorMessage(conn));
	}

	// Close the output file
	fclose(outputFile);

	// Check for errors during data retrieval
	res = PQgetResult(conn);
	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		fprintf(stderr, "Data retrieval failed: %s\n", PQerrorMessage(conn));
	}

	// Cleanup
	free(sql);
	PQclear(res);
}

int main(int argc, char **argv)
{
	gdebugexecn = 20;

	if (argc < 5) {
		IRPRINT("\nUsage : %s <dbhost> <dbport> <user> <password> <dbname>\n\n", argv[0]);
		IRPRINT("\t\t e.g. : %s localhost 10040 postgres gyeeta shyama1", argv[0]);
		return 1;
	}	

	try {
		PGConnPool		pgpool("Test Pool", 2, argv[1], atoi(argv[2]), argv[3], argv[4], argv[5], "test_postgres_param");

		auto			pconn = pgpool.get_conn();
		int			ret;
		size_t			nconn;

		pconn->pqexec_blocking("drop table if exists test_table; ");
		pconn->pqexec_blocking("create table test_table(float8_col double precision);");

		send_float8_binary(pconn->pconn_, 11.123);

		pconn->pqexec_blocking("select * from test_table; drop table test_table;");

		/*
		gy_msecsleep(1000);

		pconn->pqexec_blocking("drop table if exists test_table; ");
		pconn->pqexec_blocking("create table test_table(timestamp_col timestamptz);");

		send_timestamp_binary(pconn->pconn_, time(nullptr));

		pconn->pqexec_blocking("select * from test_table; drop table test_table;");
		*/

		gy_msecsleep(1000);

		const char 		*dataFilePath = "/tmp/datafile__.csv", *outFilePath = "/tmp/datafile__2.csv";
		const char		pcsv[] = R"(Jane Doe
Joe Doe
Jack Doe)";

		bool			bret = write_string_to_file(pcsv, sizeof(pcsv) - 1, dataFilePath, O_CREAT | O_TRUNC);

		pconn->pqexec_blocking("drop table if exists test_table; ");
		pconn->pqexec_blocking("create table test_table(name text);");

		insertDataUsingCopyCommand(pconn->pconn_, "test_table", dataFilePath);

		exportDataUsingCopyCommand(pconn->pconn_, "test_table", outFilePath);

		pconn->pqexec_blocking("drop table test_table;");

	}
	GY_CATCH_EXPRESSION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught while handling Postgres Query : %s : Exiting...\n\n", GY_GET_EXCEPT_STRING);
	);
}
	
