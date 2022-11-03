//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"
#include			"gy_misc.h"
#include			"gy_epoll_conntrack.h"
#include			"gy_comm_proto.h"
#include			"gy_rapidjson.h"

namespace gyeeta {

using EPOLL_NODE_CACHE		= IOVEC_BUFFER_CACHE<MAX_IOVEC_ARR, MAX_IOVEC_ARR>;		// No padding needed for Node Responses
using EPOLL_BUFFER_CACHE	= IOVEC_BUFFER_CACHE<MAX_IOVEC_ARR, MAX_IOVEC_ARR - 1>;		// 1 Buffer less for Padding

/*
 * Streaming Network Multi Message JSON writer based on the gy_rapidjson APIs.
 * 
 * To be used ONLY for gyeeta::comm::QUERY_RESPONSE RESP_WEB_JSON type messages.
 * 
 * If the JSON is too large, multiple Comm messages will be sent to the remote peer.
 * Max total JSON size which may be across multiple messages is comm::MAX_COMM_DATA_SZ (4 GB)
 *
 * Check gy_mnodehandle.cc for example usage.
 *
 * Not Thread Safe
 */
template <typename ConnTrack, typename ConnHdlr, typename CacheType = EPOLL_NODE_CACHE> 
class STREAM_RESP_BUF
{
public :
	CacheType				cache_;
	std::shared_ptr<ConnTrack>		tmpshr_;
	const std::shared_ptr<ConnTrack>	& connshr_;
	ConnHdlr				& connhdlr_;
	uint64_t				resp_seqid_		{0};
	size_t					total_sched_bytes_	{0};
	size_t					max_total_bytes_	{0};
	size_t					total_sent_bytes_	{0};
	comm::RESP_TYPE_E			resp_type_		{comm::RESP_MIN_TYPE};
	ERR_CODES_E				errcode_		{ERR_SUCCESS};
	comm::RESP_FORMAT_E			respfmt_		{comm::RESP_JSON_WITH_HEADER};
	uint32_t				nbatches_sent_		{0};
	uint32_t				max_batches_		{0};
	uint32_t				orig_max_batches_	{0};
	bool					incr_max_sched_		{false};
	bool					close_conn_on_end_	{false};
	bool					is_completed_		{false};

	// For const ref connshr
	STREAM_RESP_BUF(const std::shared_ptr<ConnTrack> & connshr, ConnHdlr & connhdlr, comm::RESP_TYPE_E resp_type, ERR_CODES_E errcode, comm::RESP_FORMAT_E respfmt, \
		uint64_t resp_seqid, uint64_t max_total_bytes = 0, POOL_ALLOC_ARRAY *parrpool = nullptr, bool incr_max_sched = true)

		: cache_(comm::MAX_COMM_DATA_SZ, parrpool), connshr_(connshr), connhdlr_(connhdlr), resp_seqid_(resp_seqid), 
		resp_type_(resp_type), errcode_(errcode), respfmt_(respfmt), incr_max_sched_(incr_max_sched)
	{
		if (!connshr_) {
			GY_THROW_EXCEPTION("No connection object available for Streaming Response");
		}	

		max_batches_ = connshr_->num_sends_possible();
		if (!max_batches_) max_batches_++;

		if ((max_total_bytes == 0) || (max_total_bytes > comm::MAX_COMM_DATA_SZ)) {
			if (resp_type == comm::RESP_WEB_JSON) {
				if ((max_total_bytes == 0) || (max_total_bytes > comm::MAX_COMM_JSON_DATA_SZ)) {
					max_total_bytes = comm::MAX_COMM_JSON_DATA_SZ;
				}	
			}
			else if (max_total_bytes) {
				max_total_bytes = comm::MAX_COMM_DATA_SZ;
			}	
		}	

		max_total_bytes_ = max_total_bytes;

		orig_max_batches_ = max_batches_;
		
		if (connshr_->close_conn_on_wr_complete_) {
			close_conn_on_end_ = true;
			connshr_->close_conn_on_wr_complete_ = false;
		}	
	}

	// For rvalue ref connshr as the connshr_ cannot extend lifetime of a temporary as it is a class member
	STREAM_RESP_BUF(std::shared_ptr<ConnTrack> && connshr, ConnHdlr & connhdlr, comm::RESP_TYPE_E resp_type, ERR_CODES_E errcode, comm::RESP_FORMAT_E respfmt, \
		uint64_t resp_seqid, uint64_t max_total_bytes = 0, POOL_ALLOC_ARRAY *parrpool = nullptr, bool incr_max_sched = true)
		
		: cache_(comm::MAX_COMM_DATA_SZ, parrpool), tmpshr_(std::move(connshr)), connshr_(tmpshr_), connhdlr_(connhdlr), resp_seqid_(resp_seqid), 
		resp_type_(resp_type), errcode_(errcode), respfmt_(respfmt), incr_max_sched_(incr_max_sched)
	{
		if (!connshr_) {
			GY_THROW_EXCEPTION("No connection object available for Streaming Response");
		}	

		max_batches_ = connshr_->num_sends_possible();
		if (!max_batches_) max_batches_++;

		if ((max_total_bytes == 0) || (max_total_bytes > comm::MAX_COMM_DATA_SZ)) {
			if (resp_type == comm::RESP_WEB_JSON) {
				if ((max_total_bytes == 0) || (max_total_bytes > comm::MAX_COMM_JSON_DATA_SZ)) {
					max_total_bytes = comm::MAX_COMM_JSON_DATA_SZ;
				}	
			}
			else if (max_total_bytes) {
				max_total_bytes = comm::MAX_COMM_DATA_SZ;
			}	
		}	

		max_total_bytes_ = max_total_bytes;

		orig_max_batches_ = max_batches_;
		
		if (connshr_->close_conn_on_wr_complete_) {
			close_conn_on_end_ = true;
			connshr_->close_conn_on_wr_complete_ = false;
		}	
	}

	~STREAM_RESP_BUF() noexcept
	{
		set_resp_completed();
	}	

	// Will always return non-nullptr buf except when min_sz == 0 && force_flush
	void * get_buf(uint32_t min_sz, uint32_t & szmax, uint32_t recomm_sz = 0, bool force_flush = false)
	{
		using namespace		comm;

		uint8_t			*pbuf;
		bool			set_hdr = false;

		if (min_sz && false == force_flush) {
			pbuf = (uint8_t *)cache_.get_buf_if_avail(min_sz, szmax);

			if (pbuf) {
				return pbuf;
			}
		}
		else if (false == force_flush) {
			szmax = 0;
			return nullptr;
		}	
		else if (min_sz > max_total_bytes_) {
			uint32_t 		total_sz, nmsg_set;
			auto			iovarr = cache_.get_iovec_array(total_sz, nmsg_set);

			GY_THROW_EXPR_CODE(ERR_MAX_SZ_BREACHED, "Stream Event : Requested Memory %u bytes > Max Allowed %lu", min_sz, max_total_bytes_);
		}	

		auto fcb = [this](EPOLL_IOVEC_ARR && iovarr, uint32_t total_sz, uint32_t nmsg_set)
		{
			const bool		is_comp = is_completed_;
				
			uint8_t			*palloc = (uint8_t *)iovarr.iovarr_[0].iov_base;	
			uint32_t		tsz = iovarr.iovarr_[0].iov_len, niov_set = iovarr.get_num_iovec();

			assert(niov_set > 0 && niov_set <= MAX_IOVEC_ARR);

			if (gy_unlikely(tsz < sizeof(comm::COMM_HEADER) + sizeof(comm::QUERY_RESPONSE))) {
				GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "Internal Error : Total size of Flushed Stream Response first message less than min required");
			}	

			if (gy_unlikely(connshr_->is_conn_close_signalled())) {
				GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "Connection closed while scheduling Response");
			}	

			COMM_HEADER		*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
			QUERY_RESPONSE		*presp = reinterpret_cast<QUERY_RESPONSE *>(phdr + 1);
				
			new (phdr) COMM_HEADER(COMM_QUERY_RESP, total_sz, connshr_->get_comm_magic());
			new (presp) QUERY_RESPONSE(resp_seqid_, resp_type_, errcode_, respfmt_, *phdr, is_comp);

			if (CacheType::is_padding_enabled_) {
				iovarr.push_iovec((void *)connhdlr_.gpadbuf, phdr->get_pad_len(), nullptr);
			}
				
			auto bret = connhdlr_.schedule_l1_send_data(connshr_, COMM_QUERY_RESP, std::move(iovarr), is_comp && close_conn_on_end_);	

			if (bret == false) {
				GY_THROW_EXPR_CODE(ERR_BLOCKING_ERROR, "Failed to schedule Streaming Response");
			}	
		
			nbatches_sent_++;
			total_sent_bytes_ += total_sz;
		};	
		
		if (force_flush == true) {
			uint32_t 		total_sz, nmsg_set;
			auto			iovarr = cache_.get_iovec_array(total_sz, nmsg_set);

			if (iovarr.get_num_iovec() > 0 && total_sz) {
				fcb(std::move(iovarr), total_sz, nmsg_set);
			}
			else if (min_sz == 0 && total_sent_bytes_ > 0 && is_completed_) {
				/*
				 * We have hit a case where the force_flush was called with min_sz == 0, followed directly with the end of msg
				 * We need to send an empty resp payload to indicate eom
				 */
				total_sz	= sizeof(comm::COMM_HEADER) + sizeof(comm::QUERY_RESPONSE);

				fcb(EPOLL_IOVEC_ARR(malloc_or_throw(total_sz), total_sz, ::free), total_sz, nmsg_set);
			}

			if (min_sz == 0) {
				szmax = 0;
				return nullptr;
			}	

			set_hdr = true;
		}

		auto [tsz, nmsg, niov] = cache_.get_stats();
		
		if (force_flush == false) {
			set_hdr = !tsz;
		}

		if (recomm_sz < min_sz) {
			recomm_sz = min_sz;
		}

		if (niov + 2 >= MAX_IOVEC_ARR) {
			if (recomm_sz < 16 * 1024) {
				recomm_sz = 16 * 1024;
			}	
		}	

		if (recomm_sz < 4096) {
			recomm_sz = 4096;
		}	

		if (nbatches_sent_ > 0) {
			if (set_hdr && nbatches_sent_ + 3 > max_batches_) {
				nbatches_sent_ = connshr_->num_sends_scheduled();

				if (nbatches_sent_ >= max_batches_ - 1) {
					if (!incr_max_sched_ || max_batches_ >= connshr_->MAX_PIPELINE_SCHED) {
						uint32_t 		total_sz, nmsg_set;
						auto			iovarr = cache_.get_iovec_array(total_sz, nmsg_set);

						GY_THROW_EXPR_CODE(ERR_MAX_SZ_BREACHED, "Max Scheduled Streaming Response Message count reached");
					}
					else {
						size_t			newsz = connshr_->get_max_pipeline_sz() + 128;

						INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Increasing Pipeline Size to %lu for JSON Web Streaming Response for remote connection %s\n",
							newsz, connshr_->print_conn(STRING_BUFFER<256>().get_str_buf()));

						connshr_->set_max_pipeline_sz(newsz);

						max_batches_ = newsz;
					}	
				}	
			}

			if (nbatches_sent_ > 10) {
				if (recomm_sz < 256 * 1024) {
					recomm_sz = 256 * 1024;
				}
			}
			else {
				if (recomm_sz < 32 * 1024) {
					recomm_sz = 32 * 1024;
				}
			}
		}	

		if (set_hdr) {
			min_sz += sizeof(comm::COMM_HEADER) + sizeof(comm::QUERY_RESPONSE);
		}	

		pbuf = (uint8_t *)cache_.get_buf(fcb, min_sz, recomm_sz, szmax);

		if (pbuf == nullptr) {
			// Flush occured
			min_sz += sizeof(comm::COMM_HEADER) + sizeof(comm::QUERY_RESPONSE);

			pbuf = (uint8_t *)cache_.get_buf(fcb, min_sz, recomm_sz, szmax);
			assert(pbuf);

			set_hdr = true;
		}	
		
		if (set_hdr) {
			set_buf_sz(sizeof(comm::COMM_HEADER) + sizeof(comm::QUERY_RESPONSE));

			return pbuf + sizeof(comm::COMM_HEADER) + sizeof(comm::QUERY_RESPONSE);
		}	

		return pbuf;
	}	

	// Will always return non-nullptr buf except when min_sz == 0 && force_flush
	void * get_buf(uint32_t min_sz, bool force_flush = false, uint32_t recomm_sz = 0)
	{
		uint32_t		szmax;

		return get_buf(min_sz, szmax, recomm_sz, force_flush);
	}

	void set_buf_sz(uint32_t sz, bool is_resp_complete = false)
	{
		cache_.set_buf_sz(sz);

		total_sched_bytes_ += sz;

		if (total_sched_bytes_ > max_total_bytes_) {
			uint32_t 		total_sz, nmsg_set;
			auto			iovarr = cache_.get_iovec_array(total_sz, nmsg_set);

			GY_THROW_EXPR_CODE(ERR_MAX_SZ_BREACHED, "Max Streaming Response Limit breached : %lu", max_total_bytes_);
		}	

		if (is_resp_complete) {
			set_resp_completed();
		}	
	}

	ERR_CODES_E get_errorcode() const noexcept
	{
		return errcode_;
	}

	void set_errorcode(ERR_CODES_E errcode) noexcept
	{
		errcode_ = errcode;
	}

	bool set_resp_completed() noexcept
	{
		try {
			bool			bret = true;

			if (is_completed_ == true) {
				return true;
			}	

			is_completed_		= true;
			
			GY_CC_BARRIER();

			try {
				uint32_t		szmax;

				get_buf(0, szmax, 0, true /* force_flush */);
			}
			GY_CATCH_EXCEPTION(
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while Stream Response Buffer was being flushed for remote %s...%s\n", 
					connshr_->print_conn(STRING_BUFFER<256>().get_str_buf()), GY_GET_EXCEPT_STRING);
				bret = false;
			);

			if (!close_conn_on_end_ && incr_max_sched_ && max_batches_ > orig_max_batches_) {
				connshr_->set_max_pipeline_sz(orig_max_batches_);
			}	

			return bret;
		}
		catch(...) {
			return false;
		}	
	}	

	size_t get_bytes_sent() const noexcept
	{
		return total_sent_bytes_;
	}	

	size_t get_bytes_scheduled() const noexcept
	{
		return total_sched_bytes_;
	}	

	/*
	 * Returns true if reset success (no bytes sent). If reset failed, set the new error code if passed
	 */
	bool reset_if_not_sent(std::optional<ERR_CODES_E> err_on_reset_fail = {}) noexcept
	{
		if (bool(err_on_reset_fail)) {
			// This new errorcode will be sent on object destruction or on set_resp_completed()
			set_errorcode(*err_on_reset_fail);
		}	

		if (total_sent_bytes_ == 0) {
			cache_.reset(true);

			total_sched_bytes_ = 0;
			return true;
		}	

		return false;
	}	
};

/*
 * Streaming Network Event Notification.
 * 
 * To be used ONLY for gyeeta::comm::EVENT_NOTIFY type messages.
 *
 * Check gy_malerts.cc for example usage.
 *
 * Not Thread Safe
 */
template <typename ConnTrack, typename ConnHdlr> 
class STREAM_EVENT_BUF
{
public :
	EPOLL_BUFFER_CACHE			cache_;
	std::shared_ptr<ConnTrack>		tmpshr_;
	const std::shared_ptr<ConnTrack>	& connshr_;
	ConnHdlr				& connhdlr_;
	size_t					total_sched_bytes_	{0};
	size_t					max_total_bytes_	{0};
	size_t					total_sent_bytes_	{0};
	comm::NOTIFY_TYPE_E			event_type_		{comm::NOTIFY_MIN_TYPE};
	uint32_t				max_nevents_		{0};
	uint32_t				nevents_		{0};
	uint32_t				nbatches_sent_		{0};
	bool					is_completed_		{false};

	// For const ref connshr
	STREAM_EVENT_BUF(const std::shared_ptr<ConnTrack> & connshr, ConnHdlr & connhdlr, comm::NOTIFY_TYPE_E event_type, uint32_t max_nevents, \
					uint64_t max_total_bytes = comm::MAX_COMM_DATA_SZ, POOL_ALLOC_ARRAY *parrpool = nullptr) 

		: cache_(comm::MAX_COMM_DATA_SZ, parrpool), connshr_(connshr), connhdlr_(connhdlr), 
		max_total_bytes_(((max_total_bytes == 0) || (max_total_bytes > comm::MAX_COMM_DATA_SZ)) ? comm::MAX_COMM_DATA_SZ : max_total_bytes),
		event_type_(event_type), max_nevents_(max_nevents > 0 ? max_nevents : 1)
	{
		if (!connshr_) {
			GY_THROW_EXCEPTION("No connection object available for Streaming Event");
		}	
	}

	// For rvalue ref connshr as the connshr_ cannot extend lifetime of a temporary as it is a class member
	STREAM_EVENT_BUF(std::shared_ptr<ConnTrack> && connshr, ConnHdlr & connhdlr, comm::NOTIFY_TYPE_E event_type, uint32_t max_nevents, \
					uint64_t max_total_bytes = comm::MAX_COMM_DATA_SZ, POOL_ALLOC_ARRAY *parrpool = nullptr)

		: cache_(comm::MAX_COMM_DATA_SZ, parrpool), tmpshr_(std::move(connshr)), connshr_(tmpshr_), connhdlr_(connhdlr), 
		max_total_bytes_(((max_total_bytes == 0) || (max_total_bytes > comm::MAX_COMM_DATA_SZ)) ? comm::MAX_COMM_DATA_SZ : max_total_bytes),
		event_type_(event_type), max_nevents_(max_nevents > 0 ? max_nevents : 1)
	{
		if (!connshr_) {
			GY_THROW_EXCEPTION("No connection object available for Streaming Event");
		}	
	}

	~STREAM_EVENT_BUF() noexcept
	{
		set_completed();
	}	

	// Will always return non-nullptr buf except when min_sz == 0 && force_flush
	void * get_buf(uint32_t min_sz, uint32_t & szmax, uint32_t recomm_sz = 0, bool force_flush = false)
	{
		using namespace		comm;

		uint8_t			*pbuf;
		bool			set_hdr = false;

		if (min_sz && false == force_flush) {
			pbuf = (uint8_t *)cache_.get_buf_if_avail(min_sz, szmax);

			if (pbuf) {
				return pbuf;
			}
		}
		else if (false == force_flush) {
			szmax = 0;
			return nullptr;
		}	
		else if (min_sz > max_total_bytes_) {
			uint32_t 		total_sz, nmsg_set;
			auto			iovarr = cache_.get_iovec_array(total_sz, nmsg_set);

			GY_THROW_EXCEPTION("Stream Event : Requested Memory %u bytes > Max Allowed %lu", min_sz, max_total_bytes_);
		}	

		auto fcb = [this](EPOLL_IOVEC_ARR && iovarr, uint32_t total_sz, uint32_t nmsg_set)
		{
			uint8_t			*palloc = (uint8_t *)iovarr.iovarr_[0].iov_base;	
			uint32_t		tsz = iovarr.iovarr_[0].iov_len, niov_set = iovarr.get_num_iovec();

			assert(niov_set > 0 && niov_set < MAX_IOVEC_ARR);

			if (gy_unlikely(tsz < sizeof(comm::COMM_HEADER) + sizeof(comm::EVENT_NOTIFY))) {
				GY_THROW_EXCEPTION("Internal Error : Total size of Flushed Stream Event first message less than min required");
			}	

			if (gy_unlikely(connshr_->is_conn_close_signalled())) {
				GY_THROW_EXCEPTION("Connection closed while scheduling Event Stream");
			}	

			COMM_HEADER		*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
			EVENT_NOTIFY		*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1);
				
			new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, total_sz, connshr_->get_comm_magic());
			new (pnot) EVENT_NOTIFY(event_type_, nevents_);

			iovarr.push_iovec((void *)connhdlr_.gpadbuf, phdr->get_pad_len(), nullptr);
				
			auto bret = connhdlr_.schedule_l1_send_data(connshr_, COMM_EVENT_NOTIFY, std::move(iovarr), false);	

			if (bret == false) {
				GY_THROW_EXCEPTION("Failed to schedule Streaming Event Notify");
			}	
		
			nevents_ = 0;
			nbatches_sent_++;
			total_sent_bytes_ += total_sz;
		};	
		
		if (force_flush == true) {
			uint32_t 		total_sz, nmsg_set;
			auto			iovarr = cache_.get_iovec_array(total_sz, nmsg_set);

			if (iovarr.get_num_iovec() > 0 && total_sz) {
				fcb(std::move(iovarr), total_sz, nmsg_set);
			}

			if (min_sz == 0) {
				szmax = 0;
				return nullptr;
			}	

			set_hdr = true;
		}

		auto [tsz, nmsg, niov] = cache_.get_stats();
		
		if (force_flush == false) {
			set_hdr = !tsz;
		}

		if (recomm_sz < min_sz) {
			recomm_sz = min_sz;
		}

		if (niov + 2 >= MAX_IOVEC_ARR) {
			if (recomm_sz < 16 * 1024) {
				recomm_sz = 16 * 1024;
			}	
		}	

		if (recomm_sz < 4096) {
			recomm_sz = 4096;
		}	

		if (nbatches_sent_ > 0) {
			if (nbatches_sent_ > 10) {
				if (recomm_sz < 256 * 1024) {
					recomm_sz = 256 * 1024;
				}
			}
			else {
				if (recomm_sz < 32 * 1024) {
					recomm_sz = 32 * 1024;
				}
			}
		}	

		if (set_hdr) {
			min_sz += sizeof(comm::COMM_HEADER) + sizeof(comm::EVENT_NOTIFY);
		}	

		pbuf = (uint8_t *)cache_.get_buf(fcb, min_sz, recomm_sz, szmax);

		if (pbuf == nullptr) {
			// Flush occured
			min_sz += sizeof(comm::COMM_HEADER) + sizeof(comm::EVENT_NOTIFY);

			pbuf = (uint8_t *)cache_.get_buf(fcb, min_sz, recomm_sz, szmax);
			assert(pbuf);

			set_hdr = true;
		}	
		
		if (set_hdr) {
			this->set_buf_sz(sizeof(comm::COMM_HEADER) + sizeof(comm::EVENT_NOTIFY), 0);

			return pbuf + sizeof(comm::COMM_HEADER) + sizeof(comm::EVENT_NOTIFY);
		}	

		return pbuf;
	}	
	
	// Will always return non-nullptr buf except when min_sz == 0 && force_flush
	void * get_buf(uint32_t min_sz, bool force_flush = false, uint32_t recomm_sz = 0)
	{
		uint32_t		szmax;

		return get_buf(min_sz, szmax, recomm_sz, force_flush);
	}

	void set_buf_sz(uint32_t sz, uint32_t nevents, bool is_complete = false)
	{
		cache_.set_buf_sz(sz);

		total_sched_bytes_ 	+= sz;
		nevents_ 		+= nevents;

		if (total_sched_bytes_ > max_total_bytes_) {
			uint32_t 		total_sz, nmsg_set;
			auto			iovarr = cache_.get_iovec_array(total_sz, nmsg_set);

			GY_THROW_EXCEPTION("Max Streaming Event Notify Message Size Limit breached : %lu", max_total_bytes_);
		}	

		if (is_complete) {
			set_completed();
		}	
		else {
			if (nevents_ + 1 >= max_nevents_) {
				force_flush(true /* throw_on_error */);
			}
			else if (max_nevents_ > 50 && nevents_ > max_nevents_ * 0.95) {
				force_flush(true /* throw_on_error */);
			}	
		}	
	}

	void set_completed() noexcept
	{
		try {
			if (is_completed_ == true) {
				return;
			}	

			is_completed_		= true;
			
			GY_CC_BARRIER();

			force_flush(false /* throw_on_error */);
		}
		catch(...) {
		}	
	}	

	bool force_flush(bool throw_on_error = false)
	{
		try {
			uint32_t		szmax;

			get_buf(0, szmax, 0, true /* force_flush */);

			return true;
		}
		GY_CATCH_EXCEPTION(
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while Stream Event Notify Buffer was being flushed for remote %s...%s\n", 
				connshr_->print_conn(STRING_BUFFER<256>().get_str_buf()), GY_GET_EXCEPT_STRING);

			if (throw_on_error) {
				throw;
			}

			return false;
		);
	}	

	size_t get_bytes_sent() const noexcept
	{
		return total_sent_bytes_;
	}	

	size_t get_bytes_scheduled() const noexcept
	{
		return total_sched_bytes_;
	}	

	uint32_t get_num_events() const noexcept
	{
		return nevents_;
	}	

	// Returns true if reset success
	bool reset_if_not_sent() noexcept
	{
		if (total_sent_bytes_ == 0) {
			cache_.reset(true);

			nevents_ = 0;
			total_sched_bytes_ = 0;
			return true;
		}	

		return false;
	}	
};


/*
 * For Node Servers, use CacheType as EPOLL_NODE_CACHE. For others where Padding is needed use EPOLL_BUFFER_CACHE
 */
template <typename ConnTrack, typename ConnHdlr, typename CacheType = EPOLL_NODE_CACHE>
class STREAM_JSON_EPOLL : public STREAM_RESP_BUF<ConnTrack, ConnHdlr, CacheType>
{
public :
	using StreamBuf			= STREAM_RESP_BUF<ConnTrack, ConnHdlr, CacheType>;

	typedef char Ch; 		// Character type. Only support char.

	static constexpr uint32_t	MAX_RESERVE_LEN	= 4096;	

	STREAM_JSON_EPOLL(const std::shared_ptr<ConnTrack> & connshr, ConnHdlr & connhdlr, comm::RESP_TYPE_E resp_type, \
		uint64_t resp_seqid, POOL_ALLOC_ARRAY *parrpool = nullptr, ERR_CODES_E errcode = ERR_SUCCESS, \
		uint64_t max_total_bytes = ~0lu - 1, bool incr_max_sched = false)
		
		: StreamBuf(connshr, connhdlr, resp_type, errcode, comm::RESP_JSON_WITH_HEADER, resp_seqid, max_total_bytes, parrpool, incr_max_sched)
	{}	

	~STREAM_JSON_EPOLL() noexcept		= default;


	void Put(char c)
	{
		uint32_t		bufsz;
		char			*pbuf = (char *)StreamBuf::get_buf(1, bufsz);

		*pbuf = c;

		StreamBuf::set_buf_sz(1);
	}	

	void PutN(char c, size_t n)
	{
		if (n == 0) return;

		uint32_t		bufsz;
		char			*pbuf = (char *)StreamBuf::get_buf(n, bufsz);

		std::memset(pbuf, c, n);

		StreamBuf::set_buf_sz(n);
	}	

	/*
	 * Should be called at the start or else memory fragmentation/wastage can occur at boundaries
	 */
	void reserve(size_t sz) 
	{
		uint32_t		bufsz;
		
		(void)StreamBuf::get_buf(sz, bufsz);
	}

	// Not implemented methods

	void Flush()
	{}	

	char Peek() const 
	{ 
		return 0; 
	}

	char Take() 
	{ 
		return 0; 
	}

	size_t Tell() const 
	{ 
		return 0; 
	}

	char * PutBegin() 
	{ 
		return 0; 
	}

	size_t PutEnd(char *) 
	{ 
		return 0; 
	}

	static void stream_reserve(void *arg, uint32_t len)
	{
		STREAM_JSON_EPOLL	*pstream = static_cast<STREAM_JSON_EPOLL *>(arg);

		if (pstream && len < MAX_RESERVE_LEN && len) {
			pstream->reserve(std::max(len * 2, 4u));
		}	
	}	
};	

template <typename OutputStream, typename Allocator = rapidjson::CrtAllocator>
class SOCK_JSON_WRITER : public JSON_WRITER_BASE<OutputStream, Allocator, rapidjson::Writer<OutputStream, rapidjson::UTF8<>, rapidjson::UTF8<>, Allocator>>
{
public :
	SOCK_JSON_WRITER(OutputStream & os)
		: JSON_WRITER_BASE<OutputStream, Allocator, rapidjson::Writer<OutputStream, rapidjson::UTF8<>, rapidjson::UTF8<>, Allocator>>(os, nullptr, OutputStream::stream_reserve, &os)
	{}	
};	

 
} // namespace gyeeta	

