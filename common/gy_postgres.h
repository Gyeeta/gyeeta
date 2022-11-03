//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma			once

#include		"gy_common_inc.h"
#include		"gy_print_offload.h"
#include		"gy_atomic.h"

#include		"libpq-fe.h"

#pragma 		GCC diagnostic push
#pragma 		GCC diagnostic ignored "-Wsign-compare"

#include 		"folly/Function.h"

#pragma 		GCC diagnostic pop
		

/*
 * Postgres 11+ Client Wrapper. 
 */

namespace gyeeta {

class GyPGConn;

class GyPGresult
{
public :
	PGresult		*presult_;

	GyPGresult(PGresult *presult) noexcept
		: presult_(presult)
	{}

	~GyPGresult() noexcept
	{
		if (presult_) {
			PQclear(presult_);
			presult_ = nullptr;
		}
	}	

	GyPGresult(const GyPGresult &) 			= delete;
	GyPGresult & operator=(const GyPGresult &)	= delete;

	GyPGresult(GyPGresult && other) noexcept
		: presult_(std::exchange(other.presult_, nullptr))
	{}

	GyPGresult & operator=(GyPGresult && other) noexcept
	{
		if (this != &other) {
			if (presult_ != other.presult_) {
				PQclear(presult_);
				presult_ = std::exchange(other.presult_, nullptr);
			}
			else {
				other.presult_ = nullptr;
			}	
		}	

		return *this;
	}	

	PGresult * get() const noexcept
	{
		return presult_;
	}	

	bool is_error() const noexcept
	{
		return is_error(presult_);
	}	

	// Error msg will have a terminating newline \n
	const char * get_error_msg() const noexcept
	{
		return PQresultErrorMessage(presult_);
	}

	CHAR_BUF<512> get_error_no_newline() const noexcept
	{
		return copy_str_buf<512>(PQresultErrorMessage(presult_), true);
	}	

	const char * get_sqlcode() const noexcept
	{
		return PQresultErrorField(presult_, PG_DIAG_SQLSTATE);
	}	

	static bool is_error(PGresult * pres) noexcept
	{
		if (pres) {

			switch (PQresultStatus(pres)) {
			
			case PGRES_BAD_RESPONSE :
			case PGRES_NONFATAL_ERROR :
			case PGRES_FATAL_ERROR :
				return true;

			default :
				return false;
			}	
		}

		return false;
	}	
};

using PG_RESP_CB 			= folly::Function<bool(GyPGConn &, GyPGresult, bool /* is_completed  */)>;


/*
 * Not thread-safe.
 */
class GyPGConn
{
public :
	PGconn				*pconn_				{nullptr};
	gy_atomic<bool>			is_avail_			{false};
	uint64_t			last_avail_cusec_		{0};
	uint64_t			connect_tusec_			{0};
	std::string			init_commands_;
	PG_RESP_CB			resp_cb_;
	int				max_reconnect_retries_		{-1};
	bool				auto_reconnect_			{true};
	bool				force_reconnect_next_		{false};

	GyPGConn(const char *dbhost, uint16_t dbport, const char *user, const char *passwd, const char *dbname, const char *appname, \
			const char *init_commands = "", bool auto_reconnect = true, int min_db_major_version = 11, int max_init_retries = 100, int max_reconnect_retries = -1)
		
		: init_commands_(init_commands ? init_commands : ""), max_reconnect_retries_(max_reconnect_retries), auto_reconnect_(auto_reconnect)
	{

		PGconn			*pconn = nullptr;
		const char 		*keywords[10] {};
		const char 		*values[10] {};
		int			max_retry = ((uint32_t)max_init_retries & 0x7FFFFFFFu);
		auto			portstr = number_to_string(dbport);

		keywords[0] 		= "host";
		values[0] 		= dbhost;

		keywords[1] 		= "port";
		values[1] 		= portstr.get();

		keywords[2] 		= "user";
		values[2] 		= user;

		keywords[3] 		= "password";
		values[3] 		= (passwd && *passwd) ? passwd : nullptr;

		keywords[4] 		= "dbname";
		values[4] 		= dbname;

		keywords[5] 		= "application_name";
		values[5] 		= appname;
		
		keywords[6]	 	= "connect_timeout";
		values[6] 		= "10";			// Fixed 10 sec timeout

		keywords[7] 		= nullptr;
		values[7] 		= nullptr;

		do {
			pconn = PQconnectdbParams(keywords, values, 0);

			GY_SCOPE_EXIT {
				if (pconn) PQfinish(pconn);
			};

			if (PQstatus(pconn) != CONNECTION_OK) {
				if (--max_retry > 0) {
					ERRORPRINT("Failed to connect to Postgres Database (Will retry after a few secs) : Error Message is %s\n", PQerrorMessage(pconn));

					gy_nanosleep(10, 0);
					continue;
				}	
				else {
					GY_THROW_EXPR_CODE(500, "Failed to connect to Postgres Database due to %s", copy_str_buf(PQerrorMessage(pconn), true).get());
				}	
			}	
			else {

				int			ver = PQserverVersion(pconn);

				if (ver/10000 < min_db_major_version) {
					GY_THROW_EXPR_CODE(500, "Postgres Database Host %s Port %s Version %d less than minimum version needed %d", 
						PQhost(pconn), PQport(pconn), ver/10000, min_db_major_version);
				}

				connect_tusec_	= get_usec_time();

				if (init_commands_.size()) {
					PGresult 		*res;
					
					res = PQexec(pconn, init_commands_.c_str());

					GY_SCOPE_EXIT {
						if (res) PQclear(res);
					};

					if (!res || (!((PQresultStatus(res) == PGRES_TUPLES_OK) || (PQresultStatus(res) == PGRES_COMMAND_OK)))) {
						GY_THROW_EXPR_CODE(500, "Postgres Database Host %s Port %s : Failed to execute init commands : %s", 
							PQhost(pconn), PQport(pconn), copy_str_buf(PQerrorMessage(pconn), true).get());
					}	
				}

				pconn_		= std::exchange(pconn, nullptr);

				is_avail_.store(true, std::memory_order_relaxed);
				last_avail_cusec_ = get_usec_clock();

				DEBUGEXECN(1,
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Connected to %s successfully\n", print_db_conn().get());
				);	
				return;
			}

		} while (true);	
	}	

	GyPGConn(const GyPGConn &)			= delete;
	GyPGConn & operator=(const GyPGConn &)		= delete;

	GyPGConn(GyPGConn && other) noexcept
		: pconn_(std::exchange(other.pconn_, nullptr)), is_avail_(other.is_avail_.exchange(false)), last_avail_cusec_(other.last_avail_cusec_),
		connect_tusec_(other.connect_tusec_), init_commands_(std::move(other.init_commands_)), resp_cb_(std::move(other.resp_cb_)),
		max_reconnect_retries_(other.max_reconnect_retries_), auto_reconnect_(other.auto_reconnect_), force_reconnect_next_(other.force_reconnect_next_)
	{}	
	
	GyPGConn & operator= (GyPGConn && other) noexcept
	{
		if (this != &other) {
			close_conn();

			pconn_			= std::exchange(other.pconn_, nullptr);
			is_avail_		= other.is_avail_.exchange(false);
			last_avail_cusec_	= other.last_avail_cusec_;
			connect_tusec_		= other.connect_tusec_;
			init_commands_		= std::move(other.init_commands_);
			resp_cb_		= std::move(other.resp_cb_);
			max_reconnect_retries_	= other.max_reconnect_retries_;
			auto_reconnect_		= other.auto_reconnect_;
			force_reconnect_next_	= other.force_reconnect_next_;
		}

		return *this;
	}	

	/*
	 * Will not check if resp_cb_ is active. This needs to be externally co-ordinated...
	 */
	~GyPGConn() noexcept
	{
		close_conn();
	}	

	bool is_available(std::memory_order order = std::memory_order_acquire) const noexcept
	{
		return is_avail_.load(order);
	}	

	bool is_connected() const noexcept
	{
		if (pconn_) {
			return (CONNECTION_OK == PQstatus(pconn_));
		}

		return false;
	}	

	bool claim_if_avail(bool is_nonblock = false)
	{
		if (pconn_ && true == is_avail_.load(std::memory_order_relaxed)) {
			bool		avail = true, bret;

			bret = is_avail_.compare_exchange_relaxed(avail, false);

			if (true == bret) {
				if (true == is_connected()) {
					assert(true == is_idle());
					return true;
				}	
				
				return check_or_reconnect(is_nonblock);
			}	
		}	

		return false;
	}	

	/*
	 * Response Callbacks calling this should not reference any resp_cb_ lambda capture variables after this is called,
	 * if this is invoked from within the Response Callback.
	 */
	[[gnu::noinline]] void make_available(bool ignore_reconnect = false) noexcept
	{
		if (pconn_) {
			if (!force_reconnect_next_ || ignore_reconnect) {
				resp_cb_ = {};

				is_avail_.store(true, std::memory_order_relaxed);
				last_avail_cusec_ = get_usec_clock();
			}
			else {
				try {
					reset_conn(false);
				}
				catch(...) {
				}	
			}	
		}	
	}
	
	// Returns -1 on errors (if reset will return 2), 1 on timeout, 0 if response available
	int poll_response(int max_msec_wait, bool reset_on_error)
	{
		int			ret, revents = 0;

		if (gy_unlikely(pconn_ == nullptr)) {
			return -1;
		}

		ret = poll_socket(get_socket(), max_msec_wait, revents, POLLIN, false /* close_on_errors */);

		if (ret > 0) {
			return 0;
		}
		else if (ret == 0) {
			return 1;
		}	

		if (reset_on_error) {
			if (revents & (POLLHUP | POLLERR | POLLNVAL)) {
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Connection disconnection occurred while waiting for response for %s after %lu min of last connect. Attempting a reconnect...\n", 
					print_db_conn().get(), (get_usec_time() - connect_tusec_)/GY_USEC_PER_MINUTE);

				if (true == reset_conn()) {
					return 2;
				}	
			}	
		}

		return -1;
	}

	/*
	 *
	 * Set Async Response Response Handler.
	 * This will be called repeatedly in case multiple rows are returned. The response will be considered complete when
	 * is_completed is set. The callback must not initiate a new async query within itself...
	 *
	 * Sample :
		pconn->set_resp_cb(
			[&](GyPGConn & conn, GyPGresult gyres, bool is_completed) -> bool
			{
				if (is_completed) {
					if (conn.is_within_tran()) {
						conn.pqexec_blocking("Rollback Work;");
					}			
					conn.make_available();	// Not mandatory if using PGConnPool as the caller will make it available if not done	
					return true;
				}	
				
				if (true == gyres.is_error()) {
					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to execute query : SQLCODE \'%s\' : Message : \'%s\'\n", 
						gyres.get_sqlcode(), gyres.get_error_msg());
					return false;
				}	

				// Handle row...

				return true;
			}
		);
	 *
	 */
	void set_resp_cb(PG_RESP_CB && resp_cb) noexcept
	{
		resp_cb_ = std::move(resp_cb);
	}	

	bool has_resp_cb() const noexcept
	{
		return bool(resp_cb_);
	}	

	// Set the init commands to run on the next reconnect
	void set_init_commands(const char *pcmd)
	{
		if (!pcmd) {
			pcmd = "";
		}	

		init_commands_.assign(pcmd);
	}

	// Valid only once per query
	bool set_single_row_mode() const noexcept
	{
		if (gy_unlikely(pconn_ == nullptr)) {
			return false;
		}

		return PQsetSingleRowMode(pconn_);
	}	

	void set_reconnect_on_next_avail() noexcept
	{
		if (pconn_) {
			force_reconnect_next_ = true;
		}
	}

	bool reset_conn(bool print_log = true)
	{
		if (pconn_) {
			is_avail_.store(false, std::memory_order_release);

			resp_cb_ 		= {};
			force_reconnect_next_ 	= false;

			PQreset(pconn_);
			
			if (true == is_connected()) {
				connect_tusec_	= get_usec_time();

				is_avail_.store(true, std::memory_order_release);
				last_avail_cusec_ = get_usec_clock();
				
				if (init_commands_.size()) {
					PGresult 		*res;
					
					res = PQexec(pconn_, init_commands_.c_str());

					if (!res || (!((PQresultStatus(res) == PGRES_TUPLES_OK) || (PQresultStatus(res) == PGRES_COMMAND_OK)))) {
						ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Postgres Database Host %s Port %s : Failed to execute init commands on reconnect : %s", 
							PQhost(pconn_), PQport(pconn_), PQerrorMessage(pconn_));
					}	

					if (res) PQclear(res);
				}

				if (print_log) {
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Reconnected to %s successfully...\n", print_db_conn().get());
				}

				return true;
			}
			else {
				// Set as available so that on the next claim, a reconnect may be attempted
				is_avail_.store(true, std::memory_order_release);
			}	
		}	

		return false;
	}	

	bool check_or_reconnect(bool is_nonblock = false) 
	{
		if (false == is_socket_still_connected(get_socket(), true /* is_peer_writeable */)) {

			int			max_retry = ((uint32_t)max_reconnect_retries_ & 0x7FFFFFFFu);

			if ((is_nonblock == true) || (auto_reconnect_ == false) || (max_retry <= 0)) {
				is_avail_.store(true, std::memory_order_release);

				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Connection disconnection occurred for %s. No Reconnect will be attempted...\n", print_db_conn().get());
				return false;
			}	

			WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Connection disconnection occurred for %s after %lu min of last connect. Attempting a reconnect...\n", 
				print_db_conn().get(), (get_usec_time() - connect_tusec_)/GY_USEC_PER_MINUTE);
			
			while (max_retry-- > 0) {
				
				if (true == reset_conn()) {
					is_avail_.store(false, std::memory_order_release);

					return true;
				}	

				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to reconnect to Postgres Database (Will retry after a few secs) : Error Message is %s\n", 
					PQerrorMessage(pconn_));


				gy_nanosleep(10, 0);
			}	

			is_avail_.store(true, std::memory_order_release);

			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to reconnect to Postgres. No more reconnects will be attempted currently...\n");
			return false;
		}	
		
		return true;
	}	
	
	void close_conn() noexcept
	{
		if (pconn_) {
			PQfinish(pconn_);

			resp_cb_ 		= {};
			pconn_ 			= nullptr;
			force_reconnect_next_	= false;
		}	
		
		is_avail_.store(false, std::memory_order_release);
	}	

	bool cancel_query() noexcept
	{
		char			ebuf[256];
		bool			bret;

		if (!pconn_) return false;

		auto		pcan = PQgetCancel(pconn_);

		if (!pcan) return false;
		
		bret = PQcancel(pcan, ebuf, sizeof(ebuf));
		
		PQfreeCancel(pcan);

		return bret;
	}	

	int get_socket() const noexcept
	{
		if (gy_unlikely(pconn_ == nullptr)) {
			return -1;
		}

		return PQsocket(pconn_);
	}	

	const char * get_db_host() const noexcept
	{
		if (pconn_) {
			return PQhost(pconn_);
		}	
		
		return "";
	}	

	const char * get_db_port() const noexcept
	{
		if (pconn_) {
			return PQport(pconn_);
		}

		return "";
	}	

	const char * get_user() const noexcept
	{
		if (pconn_) {
			return PQuser(pconn_);
		}	

		return "";
	}	

	const char * get_db() const noexcept
	{
		if (pconn_) {
			return PQdb(pconn_);
		}	

		return "";
	}	

	int db_version() const noexcept
	{
		if (gy_unlikely(pconn_ == nullptr)) {
			return 0;
		}

		return PQserverVersion(pconn_);
	}	

	char * db_version_string(char *verbuf, size_t szbuf) const noexcept
	{
		if (gy_unlikely(pconn_ == nullptr)) {
			*verbuf = 0;
			return verbuf;
		}

		int		ver = PQserverVersion(pconn_);

		snprintf(verbuf, szbuf, "%d.%d", ver/10000, ver % 100);

		return verbuf;
	}	

	CHAR_BUF<32> db_version_string() const noexcept
	{
		CHAR_BUF<32>		cbuf;

		db_version_string(cbuf.get(), sizeof(cbuf));

		return cbuf;
	}	

	const char * get_app_name() const noexcept
	{
		if (pconn_) {
			return PQparameterStatus(pconn_, "application_name");
		}	

		return "";
	}	

	const char * get_server_encoding() const noexcept
	{
		if (pconn_) {
			return PQparameterStatus(pconn_, "server_encoding");
		}	

		return "";
	}	

	bool is_superuser() const noexcept
	{
		if (pconn_) {
			const char	*res = PQparameterStatus(pconn_, "is_superuser");

			return res && ('t' == tolower(*res)); 
		}	

		return false;
	}	

	PGTransactionStatusType get_tran_status() const noexcept
	{
		if (pconn_) {
			return PQtransactionStatus(pconn_);
		}

		return {};
	}	

	bool is_response_expected() const noexcept
	{
		return PQTRANS_ACTIVE == get_tran_status();
	}	

	bool is_idle() const noexcept
	{
		return PQTRANS_IDLE == get_tran_status();
	}	

	bool is_within_tran() const noexcept
	{
		auto		tstatus = get_tran_status();

		switch (tstatus) {
		
		case PQTRANS_ACTIVE :
		case PQTRANS_INTRANS :
		case PQTRANS_INERROR :
			return true;

		default :
			return false;
		}	
	}	

	pid_t get_db_pid() const noexcept
	{
		if (pconn_) {
			return PQbackendPID(pconn_);
		}

		return 0;
	}	

	uint64_t get_connect_time() const noexcept
	{
		return connect_tusec_;
	}

	PGconn * get() const noexcept
	{
		return pconn_;
	}	

	GyPGresult pqexec_blocking(const char *query) const noexcept
	{
		if (pconn_) {
			return GyPGresult(PQexec(pconn_, query));
		}

		return GyPGresult(nullptr);
	}	

	uint64_t get_db_disk_usage(bool printerr = true) const noexcept
	{
		if (!pconn_) {
			return 0;
		}

		auto				gyres = pqexec_blocking("select pg_database_size(datname) from pg_database where datname = current_database();");
		const auto			*pres = gyres.get();
		const char			*pdata = nullptr;
	
		if (true == gyres.is_error() || (1 != PQnfields(pres)) || (!(pdata = PQgetvalue(pres, 0, 0)))) {
			if (printerr) {
				WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get Disk Usage of current Database...\n");
			}
			return 0;
		}	
		
		return string_to_number<uint64_t>(pdata);
	}	

	template <size_t outbufsz = 256>
	STR_ARRAY<outbufsz> escape_string(const char *inputstr, uint32_t szinput = 0) const noexcept
	{
		static_assert(outbufsz >= 16, "At least 16 bytes outbufsz needed");
		static_assert(outbufsz < 700 * 1024, "Max 700 KB outbufsz");

		static constexpr size_t		maxinputsz = (outbufsz >> 1) - 1;

		STR_ARRAY<outbufsz>		outbuf;
		size_t				outlen;

		if (szinput == 0) {
			szinput = gy_strnlen(inputstr, maxinputsz);
		}	
		else if (szinput > maxinputsz) {
			szinput = maxinputsz;
		}	
		
		if (pconn_) {
			outlen = PQescapeStringConn(pconn_, outbuf.get(), inputstr, szinput, nullptr);	
			outbuf.set_len(outlen);
		}

		return outbuf;
	}	

	// Returns std::pair of outbuf strlen and whether inputstr was truncated due to inadequate outlen
	std::pair<uint32_t, bool> escape_string(const char *inputstr, char *outbuf, uint32_t outlen, uint32_t szinput = 0) const noexcept
	{
		assert(outlen >= 8);

		uint32_t		outstrlen, maxinputsz = (outlen >> 1) - 1;
		bool			is_trunc = false;

		if (szinput == 0) {
			szinput = gy_strnlen(inputstr, maxinputsz);
		}	
		else if (szinput > maxinputsz) {
			is_trunc = true;
			szinput = maxinputsz;
		}	
		
		if (pconn_) {
			outstrlen = PQescapeStringConn(pconn_, outbuf, inputstr, szinput, nullptr);	
			return {outstrlen, is_trunc};
		}

		return {};
	}	

	// Returns unique_ptr of escaped string with escaped strlen updated in szoutput
	std::unique_ptr<char []> escape_string_alloced(const char *inputstr, uint32_t szinput, uint32_t & szoutput) const
	{
		auto			pout = std::make_unique<char []>(szinput * 2 + 1 + 1);

		if (pconn_) {
			szoutput = PQescapeStringConn(pconn_, pout.get(), inputstr, szinput, nullptr);	
		}
		else {
			pout.get()[0] = 0;
		}	

		return pout;
	}	

	CHAR_BUF<512> print_db_conn() const noexcept
	{
		CHAR_BUF<512>		buf;

		if (pconn_) {
			int			ver = PQserverVersion(pconn_);

			snprintf(buf.get(), buf.maxsz(), "Postgres Database Host \'%s\' Port %s User \'%s\' DB \'%s\' DB Version %d.%d App Name \'%s\' Backend PID %d", 
				get_db_host(), get_db_port(), get_user(), get_db(), ver/10000, ver % 100, get_app_name(), get_db_pid());
		}

		return buf;
	}	

	static bool ignore_response_till_end(GyPGConn & conn, GyPGresult gyres, bool is_completed) noexcept
	{
		if (is_completed) {
			if (conn.is_within_tran()) {
				conn.pqexec_blocking("Rollback Work;");
			}						
			conn.make_available();
			return true;
		}	
		
		return !gyres.is_error();
	}	

};	

/*
 * Will release the conn to pool on destruction if active query not ongoing (i.e. conn is idle)
 */
class PGConnUniq final
{
public :
	GyPGConn			*pconn_;

	explicit PGConnUniq(GyPGConn *pconn) noexcept
		: pconn_(pconn)
	{}

	~PGConnUniq() noexcept
	{
		if (pconn_) {
			if ((true == pconn_->is_available()) || (true == pconn_->has_resp_cb())) {
				return;
			}	

			pconn_->make_available();
			pconn_ = nullptr;
		}
	}	

	PGConnUniq(const PGConnUniq &)			= delete;
	PGConnUniq & operator=(const PGConnUniq &)	= delete;

	PGConnUniq(PGConnUniq && other) noexcept
		: pconn_(std::exchange(other.pconn_, nullptr))
	{}

	PGConnUniq & operator=(PGConnUniq && other) noexcept
	{
		if (this != &other) {
			if (this->pconn_ != other.pconn_) {
				this->~PGConnUniq();
				new (this) PGConnUniq(std::move(other));
			}
			else {	
				other.reset();
			}	
		}	

		return *this;
	}	

	GyPGConn & operator*() const noexcept
	{
		return *pconn_;
	}	

	GyPGConn * operator->() const noexcept
	{
		return pconn_;
	}	

	GyPGConn * getintconn() const noexcept
	{
		return pconn_;
	}	

	explicit operator bool() const noexcept
	{
		return !!pconn_;
	}	

	void reset() noexcept
	{
		pconn_ = nullptr;
	}	

	friend bool operator==(const PGConnUniq & left, const PGConnUniq & right) noexcept
	{
		return left.pconn_ == right.pconn_;
	}	

	friend bool operator==(const PGConnUniq & left, const GyPGConn * pconn) noexcept
	{
		return left.pconn_ == pconn;
	}	

	friend bool operator==(const GyPGConn * pconn, const PGConnUniq & right) noexcept
	{
		return right.pconn_ == pconn;
	}	
};	

class PGConnPool
{
public :
	std::vector<GyPGConn>		connvec_;
	size_t				consecutive_no_conns_	{0};
	std::string			name_;
	uint64_t			last_reset_cusec_	{0};

	static constexpr size_t		MAX_CONNS 		{128};
	
	PGConnPool(const char *ident, size_t nconns, const char *dbhost, uint16_t dbport, const char *user, const char *passwd, const char *dbname, const char *appname, \
			const char *init_commands = "", bool auto_reconnect = true, int min_db_major_version = 11, int max_init_retries = 100, int max_reconnect_retries = -1)
		
		: name_(ident)
	{
		if ((nconns == 0) || (nconns > MAX_CONNS)) {
			GY_THROW_EXCEPTION("Invalid Postgres Connection Pool number of connections specified %lu : Max Possible is %lu", nconns, MAX_CONNS);
		}

		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Starting Postgres Connection Pool \'%s\' of %lu conns for DB Host \'%s\' Port %hu User \'%s\' DB \'%s\'\n",
			ident, nconns, dbhost, dbport, user, dbname);

		for (size_t i = 0; i < nconns; ++i) {
			connvec_.emplace_back(dbhost, dbport, user, passwd, dbname, appname, init_commands, auto_reconnect, min_db_major_version, 
									i == 0 ? max_init_retries : 1, max_reconnect_retries);
		}

		last_reset_cusec_ = get_usec_clock();

		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Postgres Connection Pool \'%s\' completed : Sample connection Info is : %s\n", ident, connvec_[0].print_db_conn().get());
	}	

	~PGConnPool() noexcept			= default;

	/*
	 * Get a connection from pool.
	 * wait_response_if_unavail => If no idle conns, will wait for at least 1 conn to complete response. This requires the resp_cb_ to be set to be effective
	 * max_msec_wait => Max msec to wait for response
	 * reset_on_timeout => On timeout, should the pool be reset and new connections created
	 * max_no_conn_errors => If reset_on_timeout is false and no conns available and consecutive this many no conn errors seen after at least 5 min, reset the pool.
	 */
	PGConnUniq get_conn(bool wait_response_if_unavail = true, int max_msec_wait = 120'000, bool reset_on_timeout = true, size_t max_no_conn_errors = 100)
	{
		int			ret;
		bool			bret;

		do {
			for (size_t i = 0; i < connvec_.size(); ++i) {
				auto		pconn = &connvec_[i];

				bret = pconn->claim_if_avail(!wait_response_if_unavail);	
				
				if (bret) {
					consecutive_no_conns_ = 0;
					return PGConnUniq(pconn);
				}	
			}	

			if (wait_response_if_unavail) {
				DEBUGEXECN(20,
					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "No idle Postgres Pool connections exist for %s. Now waiting for any result...\n", name_.c_str());
				);	

				ret = wait_one_response(max_msec_wait, nullptr, true /* ignore_cb_except */, false /* timeout_replace_cb */, false /* cancel_on_timeout */);

				if (ret != 0) {
					consecutive_no_conns_++;

					if (ret == 2 && reset_on_timeout && (num_connected() > 0)) {
						ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Postgres Pool %s : Timed Out waiting for response (%d msec). Resetting Pool...\n", 
								name_.c_str(), max_msec_wait);
						
						size_t 		nconn = this->reset();

						if (nconn > 0) {
							continue;
						}	
					}	

					if (consecutive_no_conns_ > max_no_conn_errors && max_no_conn_errors > 10 && num_connected() > 0) {
						uint64_t		cusec = get_usec_clock();

						if (cusec - last_reset_cusec_ > 300 * GY_USEC_PER_SEC) {
							ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Postgres Pool %s : Too Many No Idle Connection errors seen %lu. Resetting Pool...\n", 
									name_.c_str(), consecutive_no_conns_);
							
							size_t 		nconn = this->reset();

							if (nconn > 0) {
								continue;
							}	
						}	
					}	

					break;
				}	
			}	
			else {
				break;
			}	
		} while (true);	

		return PGConnUniq(nullptr);
	}	

	/*
	 * Waits for the first complete response completion of one or more connections (only for connections which have a response callback set).
	 * Returns 0 if 1 or more conns responded (success), 1 in case no response waits possible as no conns exist or no response callbacks set, 
	 * 2 on Response Timeout, -1 on poll errors.
	 *
	 * Specify pconnone as non nullptr to wait for a specific conn response.
	 * 
	 * If the callback throws an exception, then will wait for only that conn to complete the response or timeout.
	 * Specify ignore_cb_except as false if you want to ignore the exception and just complete the response without calling
	 * the callback after an exception. NOTE : specify ignore_cb_except only if you can handle the exception later as well within the callback.
	 *
	 * On timeout, if timeout_replace_cb is true, the original resp_cb will be replaced by an empty callback which implies any further responses
	 * will be silently dropped till the end of response. Set timeout_replace_cb as false only if you are polling for responses. 
	 *
	 * If cancel_on_timeout is true, the query will be attempted to be cancelled on a timeout.
	 */
	int wait_one_response(int max_msec_wait, GyPGConn *pconnone = nullptr, bool ignore_cb_except = false, bool timeout_replace_cb = true, bool cancel_on_timeout = true)
	{
		struct pollfd 			pfds[MAX_CONNS];
		GyPGConn			*pconntbl[MAX_CONNS], *pavail = nullptr;
		size_t				nset;
		int				ret, nret;
		int64_t				curr_clock_msec, timeout_clock_msec = (max_msec_wait >= 0 ? get_msec_clock() + max_msec_wait : -1);
		int				diff_clock_msec = -1;
		std::optional<GY_EXCEPTION>	except;

		do {
			nset	= 0;

			for (size_t i = 0; i < connvec_.size(); ++i) {
				auto		pconn = &connvec_[i];

				if (pconnone) {
					i = connvec_.size();

					pconn = pconnone;
				}

				if ((true == pconn->is_available()) || (false == pconn->is_connected()) || (false == pconn->has_resp_cb())) {
					continue;
				}

				int 			sock = pconn->get_socket();

				pfds[nset].fd 		= sock;
				pfds[nset].events 	= POLLIN;
				pfds[nset].revents 	= 0;

				pconntbl[nset]		= pconn;

				nset++;
			}	
			
			if (nset == 0) {
				return 1;
			}

			if (timeout_clock_msec >= 0) {
				curr_clock_msec = get_msec_clock();

				if (timeout_clock_msec < curr_clock_msec && timeout_clock_msec != 0) {

					if (timeout_clock_msec > 10) {
						DEBUGEXECN(10,
							WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "poll for Postgres response for pool %s timed out %s...\n", 
								name_.c_str(), bool(except) ? "after an exception" : "");
						);
					}

					if (timeout_replace_cb) {
						for (size_t i = 0; i < nset; ++i) {
							auto		pconn = pconntbl[i];
					
							pconn->set_resp_cb(
									[](GyPGConn & conn, GyPGresult gyres, bool is_completed) 
									{ 
										return GyPGConn::ignore_response_till_end(conn, std::move(gyres), is_completed); 
									});
						}	
					}	
					
					if (cancel_on_timeout) {
						for (size_t i = 0; i < nset; ++i) {
							auto		pconn = pconntbl[i];
					
							pconn->cancel_query();
						}	
					}	
					
					if (!ignore_cb_except && bool(except)) {
						throw *except;
					}	

					// timeout
					return 2;
				}	

				if (timeout_clock_msec > 0) {
					diff_clock_msec = timeout_clock_msec - curr_clock_msec;
				}
				else {
					diff_clock_msec = 0;
				}	
			}	

			do {
				nret = ::poll(pfds, nset, diff_clock_msec);

				if (nret < 0) {
					if (errno == EINTR) {
						continue;
					}
					else {
						PERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "poll for Postgres Response for pool %s failed", name_.c_str());
						return -1;
					}	
				}	
				else if (nret == 0) {
					if (timeout_clock_msec > 10) {
						DEBUGEXECN(10,
							WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "poll for Postgres Response for pool %s timed out %s...\n", 
								name_.c_str(), bool(except) ? "after an exception" : "");
						);
					}	

					if (timeout_replace_cb) {
						for (size_t i = 0; i < nset; ++i) {
							auto		pconn = pconntbl[i];
					
							pconn->set_resp_cb(
									[](GyPGConn & conn, GyPGresult gyres, bool is_completed) 
									{ 
										return GyPGConn::ignore_response_till_end(conn, std::move(gyres), is_completed); 
									});
						}	
					}	
					
					if (cancel_on_timeout) {
						for (size_t i = 0; i < nset; ++i) {
							auto		pconn = pconntbl[i];
					
							pconn->cancel_query();
						}	
					}	

					if (!ignore_cb_except && bool(except)) {
						throw *except;
					}	

					// timeout
					return 2;
				}	
			
				break;

			} while (true);	

			for (size_t i = 0, k = 0; i < nset && (signed)k < nret; ++i) {
				auto		pconn = pconntbl[i];

				if (pfds[i].revents & (POLLHUP | POLLERR | POLLNVAL)) {
					k++;

					DEBUGEXECN(1, 
						ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Connection disconnection occurred for %s while waiting for response\n", 
							pconn->print_db_conn().get());
					);	
					
					if (pconn->auto_reconnect_) {
						if (max_msec_wait != 0) {
							if (true == pconn->reset_conn()) {
								pavail = pconn;
							}	
						}
					}	
					else {
						pconn->close_conn();
					}	

					continue;
				}
				else if (0 == (pfds[i].revents & POLLIN)) {
					continue;
				}	
				
				k++;

				ret = PQconsumeInput(pconn->get());

				if (ret == 0) {
					// Some error
					continue;
				}	

				if (gy_unlikely(bool(except))) {

					while (false == PQisBusy(pconn->get())) {
						PGresult	*presult = PQgetResult(pconn->get());

						if (!presult) {
							if (pconn->is_within_tran()) {
								pconn->pqexec_blocking("Rollback Work;");
							}

							pconn->make_available(true /* ignore_reconnect */);
							
							if (ignore_cb_except == false) {
								throw *except;
							}

							return 0;
						}	
					}	
					
					goto startagain;
				}	

				try {
					while (false == PQisBusy(pconn->get())) {
						PGresult	*presult = PQgetResult(pconn->get());

						if (presult) {
							(void)pconn->resp_cb_(*pconn, GyPGresult(presult), false);
						}	
						else {
							(void)pconn->resp_cb_(*pconn, GyPGresult(nullptr), true);

							// NOTE : We do not allow the callback to initiate a new async query after completion
							if (false == pconn->is_available(std::memory_order_relaxed)) {
								pconn->make_available();
							}

							pavail = pconn;

							break;
						}	
					}	
				}
				GY_CATCH_EXPRESSION(

					// Ignore all further responses and cleanup
					while (false == PQisBusy(pconn->get())) {
						PGresult	*presult = PQgetResult(pconn->get());

						if (!presult) {
							if (pconn->is_within_tran()) {
								pconn->pqexec_blocking("Rollback Work;");
							}

							pconn->make_available(true /* ignore_reconnect */);
							
							if (ignore_cb_except == false) {
								throw;
							}

							return 0;
						}	
					}	

					int			ecode = GY_GET_EXCEPT_CODE();

					if (ecode == 0) ecode = 500;

					except.emplace(GY_GET_EXCEPT_STRING, ecode);

					// Ensure we stick to this conn only as resp not yet completed
					pconnone = pconn;
					goto startagain;
				);
			}
startagain :

			;
		} while (pavail == nullptr);

		return 0;
	}	

	/*
	 * Waits for all connections response completion (only for connections which have a response callback set).
	 * If any Callback throws an exception, only the first exception is caught and others are ignored although
	 * all connections are waited for...
	 */
	void wait_all_responses(int max_msec_one_conn_wait = -1, int max_total_msec_wait = -1, bool ignore_cb_except = false)
	{
		if (max_total_msec_wait != -1 && max_msec_one_conn_wait == -1) {
			max_total_msec_wait = -1;
		}

		if (max_total_msec_wait != -1 && max_total_msec_wait < max_msec_one_conn_wait) {
			max_total_msec_wait = max_msec_one_conn_wait;
		}	

		uint64_t			total_timeout_clock_msec = (max_total_msec_wait >= 0 ? get_msec_clock() + max_total_msec_wait : ULONG_MAX - 100);
		int				ret;

		do {
			try {
				ret = wait_one_response(get_msec_clock() < total_timeout_clock_msec ? max_msec_one_conn_wait : 10);
			}
			catch (...) {
				do {
					ret = wait_one_response(get_msec_clock() < total_timeout_clock_msec ? max_msec_one_conn_wait : 10, nullptr, true /* ignore_cb_except */);

				} while (ret == 0);	

				if (!ignore_cb_except) {
					throw;
				}

				return;
			}	
				
		} while (ret == 0);	
	}	

	/*
	 * Resets all conns forcefully without checking pending responses and return number of conns connected
	 */
	size_t reset()
	{
		size_t			nconns = 0;

		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Resetting Postgres Connection Pool %s ...\n", name_.c_str());

		for (size_t i = 0; i < connvec_.size(); ++i) {
			auto		pconn = &connvec_[i];
			
			nconns += (size_t)pconn->reset_conn();
		}	

		last_reset_cusec_ = get_usec_clock();

		return nconns;
	}	


	/*
	 * Reset all idle conns and return number of conns reconnected. This is recommended to be run periodically
	 * to free up Postgres Backend Process Memory. Recommendation is for the check to be run every 300 sec.
	 * 
	 * force_reset_if_busy_over_sec : Force reset of connection if the connection is busy for over these many secs
	 */
	int reset_idle_conns(uint64_t min_conn_age_sec = 300, uint64_t force_reset_if_busy_over_sec = 3600) noexcept
	{
		try {
			int			nconns = 0, ret;
			uint64_t		tcurrusec = get_usec_time(), min_avail_cusec, cusec = get_usec_clock(), poll_cusec;
			
			if (gy_unlikely(cusec <= force_reset_if_busy_over_sec * GY_USEC_PER_SEC)) {
				return 0;
			}

			min_avail_cusec = cusec - force_reset_if_busy_over_sec * GY_USEC_PER_SEC;
			poll_cusec	= std::max<uint64_t>(cusec - min_conn_age_sec * 2 * GY_USEC_PER_SEC, min_avail_cusec);

			for (size_t i = 0; i < connvec_.size(); ++i) {
				auto		pconn = &connvec_[i];
				
				if (tcurrusec > pconn->get_connect_time() + min_conn_age_sec * GY_USEC_PER_SEC) {
					if (true == pconn->is_available()) {
						nconns += (int)pconn->reset_conn(false /* print_log */);
						continue;
					}

					pconn->set_reconnect_on_next_avail();

					if (pconn->last_avail_cusec_) {
						if (pconn->last_avail_cusec_ <= poll_cusec) {

							// poll if response completed
							wait_one_response(0, pconn, true /* ignore_cb_except */, false /* timeout_replace_cb */, false /* cancel_on_timeout */);

							if (true == pconn->is_available()) {
								nconns += (int)pconn->reset_conn(false /* print_log */);
								continue;
							}
						}	

						if (pconn->last_avail_cusec_ <= min_avail_cusec) {

							NOTEPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Postgres Connection Pool %s : Forced Reconnect as connection busy since last %lu minutes\n",
								name_.c_str(), (cusec - pconn->last_avail_cusec_)/GY_USEC_PER_MINUTE);

							nconns += (int)pconn->reset_conn(false /* print_log */);
						}	
					}
				}
			}	

			if (nconns) {
				DEBUGEXECN(1, INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Postgres Connection Pool %s : Reconnected %d connections ...\n", name_.c_str(), nconns););
			}

			return nconns;
		}
		GY_CATCH_EXPRESSION(
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught for Postgres Connection Pool %s while idle Reconnection : %s ...\n", 
				name_.c_str(), GY_GET_EXCEPT_STRING);
			return -1;
		);
	}	

	// Set the init commands to run on the next reconnect
	void set_init_commands(const char *pcmd)
	{
		for (size_t i = 0; i < connvec_.size(); ++i) {
			auto		pconn = &connvec_[i];

			pconn->set_init_commands(pcmd);
		}
	}

	bool check_or_reconnect(bool is_nonblock = false) 
	{
		bool			is_connected = true;

		for (size_t i = 0; i < connvec_.size(); ++i) {
			auto		pconn = &connvec_[i];

			is_connected = is_connected && pconn->check_or_reconnect(is_nonblock);
		}	
		
		return is_connected;
	}	

	size_t num_connected() const noexcept
	{
		size_t			nconns = 0;

		for (size_t i = 0; i < connvec_.size(); ++i) {
			auto		pconn = &connvec_[i];

			nconns += (size_t)pconn->is_connected();
		}	
		
		return nconns;
	}	

	size_t num_available() const noexcept
	{
		size_t			nconns = 0;

		for (size_t i = 0; i < connvec_.size(); ++i) {
			auto		pconn = &connvec_[i];

			nconns += (pconn->is_connected() && pconn->is_available());
		}	
		
		return nconns;
	}	

	CHAR_BUF<32> db_version_string() const noexcept
	{
		CHAR_BUF<32>		cbuf;

		connvec_[0].db_version_string(cbuf.get(), sizeof(cbuf));
		
		return cbuf;
	}	
	
	const char * get_app_name() const noexcept
	{
		return connvec_[0].get_app_name();
	}	

	const char * get_server_encoding() const noexcept
	{
		return connvec_[0].get_server_encoding();
	}	

	bool is_superuser() const noexcept
	{
		return connvec_[0].is_superuser();
	}	

	size_t size() const noexcept
	{
		return connvec_.size();
	}	
};	

static constexpr int		PG_BPCHAROID		= 1042;
static constexpr char		pgintbool[2]		= {'f', 't'};

} // namespace gyeeta

