//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include		"gy_common_inc.h"
#include		"gy_paconnhdlr.h"
#include		"gypartha.h"
#include		"gy_print_offload.h"
#include 		"gy_scheduler.h"
#include 		"gy_task_handler.h"
#include 		"gy_socket_stat.h"
#include 		"gy_sys_hardware.h"
#include 		"gy_refcnt.h"
#include 		"gy_cloud_metadata.h"

#include 		<algorithm>

#include 		<sys/epoll.h>
#include 		<sys/eventfd.h>
#include 		<sys/timerfd.h>

using namespace 	gyeeta::comm;

namespace gyeeta {
namespace partha {

static PACONN_HANDLER	*pgconn_handler_;

PACONN_HANDLER::PACONN_HANDLER(PARTHA_C *ppartha)
	: SERVER_COMM(comm::COMM_HEADER::PM_HDR_MAGIC), ppartha_(ppartha), gshyama_(ppartha_->psettings_->shyama_hosts, ppartha_->psettings_->shyama_ports)
{
	assert(ppartha_);

	if (nullptr == SYS_HARDWARE::get_singleton()) {
		GY_THROW_EXCEPTION("System Hardware Singleton not yet initialized");
	}

	pgconn_handler_		= this;

	auto psettings = ppartha_->psettings_;
	
	GY_STRNCPY(cluster_name_, psettings->cluster_name, sizeof(cluster_name_));

	// Get Instance Metadata	

	if (*psettings->cloud_type) {

		try {
			CLOUD_METADATA			meta(psettings->cloud_type);

			auto [pinstance_id, pregion_name, pzone_name, pcloud_type] = meta.get_metadata();
			
			if (*pinstance_id) {
				GY_STRNCPY(instance_id_, pinstance_id, sizeof(instance_id_));
			}	

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

	auto lam = [](void *arg) -> void *
	{
		GY_THREAD	*pthr 	= (GY_THREAD *)arg;
		PACONN_HANDLER	*pthis 	= (PACONN_HANDLER *)pthr->get_opt_arg1();
		int64_t	is_req_rsp 	= (int64_t)(intptr_t)pthr->get_opt_arg2();	

		if (is_req_rsp) {
			MAKE_PTHREAD_WRAP("Req_Response_handler", pthis->handle_l1(pthr, true));
		}
		else {
			MAKE_PTHREAD_WRAP("Event_Notifier", pthis->handle_l1(pthr, false));
		}	

		return nullptr;
	};

	GY_THREAD		*pthr = nullptr;
	int			nretry = 0;

	do {
		try {
			evt_hdlr_.pthread_ = pthr = new GY_THREAD("Madhava Event Notifier", lam, nullptr, this, (void *)(intptr_t)0ul);
		}
		GY_CATCH_EXCEPTION(
			if (++nretry < 4) {
				ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to start event notifier thread %s : Retrying after 3 sec", GY_GET_EXCEPT_STRING);
				gy_nanosleep(3, 0);
			}
		);
	} 
	while (!pthr && nretry < 4);

	if (!pthr) {
		GY_THROW_EXCEPTION("Failed to start threads for connection handler");
	}	

	pthr 		= nullptr;
	nretry 		= 0;

	do {
		try {
			req_rsp_hdlr_.pthread_ = pthr = new GY_THREAD("Madhava Request Response", lam, nullptr, this, (void *)(intptr_t)1ul);
		}
		GY_CATCH_EXCEPTION(
			if (++nretry < 4) {
				ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to start Madhava Req Handler thread %s : Retrying after 3 sec", GY_GET_EXCEPT_STRING);
				gy_nanosleep(3, 0);
			}
		);
	} 
	while (!pthr && nretry < 4);

	if (!pthr) {
		GY_THROW_EXCEPTION("Failed to start threads for connection handler");
	}	

}	

static void handle_reset_stats() noexcept
{
	try {
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_GREEN, "Madhava Server signalled a Reset Stats required... Will resend all data.\n");

		if (TASK_HANDLER::get_singleton()) {
			TASK_HANDLER::get_singleton()->reset_server_stats();
		}

		if (TCP_SOCK_HANDLER::get_singleton()) {
			TCP_SOCK_HANDLER::get_singleton()->reset_server_stats();
		}	
	}
	catch(...) {
	}	
}	

int PACONN_HANDLER::handle_l1(GY_THREAD *pthr, bool is_req_rsp)
{
	SERVER_SIGNAL			*pglobparam = (is_req_rsp ? &req_rsp_hdlr_ : &evt_hdlr_);
	SERVER_SIGNAL			& param = *pglobparam;
	MPMCQ_COMM			*psignalq = &pglobparam->signalq_;
	const pid_t			tid = gy_gettid();
	POOL_ALLOC_ARRAY		poolarr;

	if (is_req_rsp) {
		snprintf(pglobparam->descbuf_, sizeof(pglobparam->descbuf_), "Socket Handling Req and Response Thread TID %d", tid);
	}
	else {
		snprintf(pglobparam->descbuf_, sizeof(pglobparam->descbuf_), "Socket Handling Event Notifier Thread TID %d", tid);
	}	

	pglobparam->epollfd_ = epoll_create1(EPOLL_CLOEXEC);
	if (pglobparam->epollfd_ == -1) {
		PERRORPRINTCOLOR(GY_COLOR_RED, "Failed to create epoll socket for %s : Exiting", pglobparam->descbuf_);
		exit(EXIT_FAILURE);
	}

	pglobparam->signalfd_ = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (pglobparam->signalfd_ == -1) {
		PERRORPRINTCOLOR(GY_COLOR_RED, "Failed to create eventfd for %s : Exiting", pglobparam->descbuf_);
		exit(EXIT_FAILURE);
	}	

	pglobparam->timerfd_ = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (pglobparam->timerfd_ == -1) {
		PERRORPRINTCOLOR(GY_COLOR_RED, "Failed to create timerfd for %s : Exiting", pglobparam->descbuf_);
		exit(EXIT_FAILURE);
	}	

	try {
		size_t			pool_szarr[4], pool_maxarr[4], npoolarr = 0;
		
		if (is_req_rsp) {
			pool_szarr[0] 	= 32767;
			pool_maxarr[0]	= 128;
			
			pool_szarr[1]	= 4096;
			pool_maxarr[1]	= 1024;

			pool_szarr[2] 	= 512;
			pool_maxarr[2]	= 1024;

			npoolarr 	= 3;
		}
		else {
			pool_szarr[0]	= 4096;
			pool_maxarr[0]	= 256;

			npoolarr 	= 1;
		}	

		poolarr.pool_alloc(pool_szarr, pool_maxarr, npoolarr, true);
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to create memory pool for %s : %s : Exiting...\n", pglobparam->descbuf_, GY_GET_EXCEPT_STRING);
		exit(EXIT_FAILURE);
	);
	
	try {
		const int			epollfd = param.epollfd_, signalfd = param.signalfd_, timerfd = param.timerfd_;
		static constexpr int		max_events = 128, max_retry_events = 32, max_signals_no_read = 256;

		struct epoll_event		levent, tevent, *pevarr, *pevcache, *pevretry;
		size_t				nconns = 0;
		int				ret;	
		MAP_CONNTRACK			mconntrack;
		uint64_t			curr_usec_clock, last_usec_clock = 0, niter_checks = 0;
		int64_t				last_tcount = 0, curr_tcount = 0, nsignals_seen = 0;
		bool				lastdbwr = false;
		STATS_STR_MAP			statsmap;

		statsmap.reserve(16);

		levent.data.ptr	= (void *)(uintptr_t)signalfd;
		levent.events 	= EPOLLIN | EPOLLET;

		ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, signalfd, &levent);
		if (ret == -1) {
			PERRORPRINTCOLOR(GY_COLOR_RED, "Received error while adding eventfd %s to poll : Exiting...", param.descbuf_);
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

		if (is_req_rsp) {
			// Now start the Shyama Registration
			schedule_shyama_register();

			scheduler_.add_schedule(121'000, 120'000, 0, "Send Madhava Status Event",
					[this] {
						send_madhava_status();
					}, false);
		}

		pevarr 		= new epoll_event[max_events];
		pevcache	= new epoll_event[max_events];

		auto comp_epoll = [](const epoll_event & ev1, const epoll_event & ev2) noexcept -> bool
		{
			// NOTE : Please keep this as a < operation as we need to ensure signalfd is handled first
			return (uint8_t *)ev2.data.ptr < (uint8_t *)ev1.data.ptr;
		};	

		auto send_error_response = [&, this](PACONNTRACK *pconn1, uint64_t seqid, ERR_CODES_E errcode, const char *errstr = nullptr) -> ssize_t
		{
			size_t			fixed_sz = sizeof(COMM_HEADER) + sizeof(QUERY_RESPONSE) + errstr ? sizeof(ERROR_STRING_RESP) : 0;
			FREE_FPTR		free_fp;
			uint32_t		act_size;
			void			*palloc = poolarr.safe_malloc(fixed_sz, free_fp, act_size);

			COMM_HEADER		*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
			QUERY_RESPONSE		*presp = reinterpret_cast<QUERY_RESPONSE *>((uint8_t *)phdr + sizeof(COMM_HEADER)); 
			
			new (phdr) COMM_HEADER(COMM_QUERY_RESP, fixed_sz, pconn1->get_comm_magic());

			new (presp) QUERY_RESPONSE(seqid, errstr ? RESP_NULL_PAYLOAD : RESP_ERROR_STRING, errcode, RESP_BINARY, errstr ? sizeof(ERROR_STRING_RESP) : 0);
			
			if (errstr) {
			
				ERROR_STRING_RESP	*perrstr = reinterpret_cast<ERROR_STRING_RESP *>((uint8_t *)presp + sizeof(*presp));
				
				std::memset(perrstr, 0, sizeof(*perrstr));
				GY_STRNCPY(perrstr->error_string_, errstr, sizeof(perrstr->error_string_));
			}

			struct iovec		iov[2] {{phdr, fixed_sz}, {(void *)gpadbuf, phdr->get_pad_len()}};	
			FREE_FPTR		free_fp_arr[2] {free_fp, nullptr};
			
			pconn1->schedule_ext_send(EPOLL_IOVEC_ARR(iov, GY_ARRAY_SIZE(iov), free_fp_arr, false));

			if (errcode != ERR_SUCCESS) {
				statsmap["Errored Response"]++; 
			}	

			/*
			 * Extra safe checks ..
			 * We need to check if other sends are already scheduled. If yes, then 
			 * don't invoke l1_handle_send() directly. Rather signal using pl1_ as we need to ensure
			 * other threads which have scheduled sends have their async cb handled in case the response
			 * comes in before the Notify handling happens. This is because l1_handle_send() will send all 
			 * previously scheduled sends as well if possible.
			 */
			if (pconn1->num_sends_scheduled() > 1) {
				SOCK_SEND_DATA		ldata(pconn1->pl1_, pconn1->weak_from_this(), pconn1, pconn1->get_comm_magic(), 
								COMM_QUERY_RESP, false /* close_conn_on_send */);
				int			ntries = 0;
				bool			bret;

				do { 
					bret = pconn1->pl1_->signalq_.write(std::move(ldata));
				} while (bret == false && ntries++ < 10);

				if (bret == true) {
					int64_t		n = 1;

					(void)::write(pconn1->pl1_->signalfd_, &n, sizeof(int64_t));
					
					return 0;
				}
			}	

			return l1_handle_send(pconn1);
		};

		/*
		 * Currently max_syscall is ignored TODO
		 * Called only if is_req_rsp true
		 */
		auto handle_recv = [&, this](PACONNTRACK *pconn1, int sock, const bool is_conn_closed, const bool peer_rd_closed, int max_syscall = INT_MAX - 1) -> ssize_t
		{
			ssize_t				sret, max_bytes, totbytes = 0;
			ssize_t				max_buf_sz, data_sz;
			uint8_t				*prdbuf;
			int				nsyscall = 0, ret;
			auto				&rdstat_ = pconn1->rdstat_;
			bool				is_again = false, bret, bsent, is_pendrecv = (rdstat_.pending_sz_ > 0);
			COMM_HEADER			hdr(COMM_MIN_TYPE, 0, COMM_HEADER::INV_HDR_MAGIC);

			auto set_variables = [&]() 
			{
				max_buf_sz 	= rdstat_.max_buf_sz_;
				data_sz		= rdstat_.data_sz_;
				prdbuf		= rdstat_.pdirbuf_;
			};

			if (!rdstat_.pdirbuf_) {
				FREE_FPTR		free_fp;
				uint32_t		act_size;
				void			*palloc = poolarr.safe_malloc(4096, free_fp, act_size);

				rdstat_.set_buf((uint8_t *)palloc, free_fp, act_size, 0);
			}	

			do {
				set_variables();

				max_bytes = max_buf_sz - data_sz;

				if (gy_unlikely(max_bytes <= 0)) {
					statsmap["Internal Error"]++; 
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
						return -1;
					}
				}
				else if (sret == 0) {
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
					if ((size_t)data_sz >= sizeof(COMM_HEADER)) {
						std::memcpy(&hdr, prdbuf, sizeof(hdr));

						if (false == hdr.validate(prdbuf, pconn1->get_comm_magic())) {
							statsmap["Invalid Message Error"]++; 
							GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
						}	
					}
					else {
						hdr.total_sz_ = sizeof(COMM_HEADER);
					}

					if (max_buf_sz < (ssize_t)hdr.total_sz_) {

						FREE_FPTR		free_fp;
						uint32_t		act_size;
						uint8_t			*palloc = (uint8_t *)poolarr.safe_malloc(std::max(4096u, hdr.total_sz_), free_fp, act_size);

						std::memcpy(palloc, prdbuf, std::min<uint32_t>(data_sz, act_size));

						rdstat_.reset_buf(true);

						rdstat_.set_buf(palloc, free_fp, act_size, data_sz);
						
						set_variables();
					}
			
					if (data_sz < hdr.total_sz_) {
						if (data_sz != rdstat_.data_sz_) {
							// This implies we just need to move data to the start

							std::memmove(rdstat_.pdirbuf_, prdbuf, data_sz);
							rdstat_.data_sz_	= data_sz;

							set_variables();
						}	
						break;
					}

					rdstat_.nrequests_++;

					switch (hdr.data_type_) {
				
					case COMM_QUERY_CMD :

						if (false == peer_rd_closed) {
							QUERY_CMD		*pquery = (QUERY_CMD *)(prdbuf + sizeof(COMM_HEADER));
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

							case RESP_LISTENER_INFO_STATS :
								if ((presp->respformat_ == RESP_BINARY) && (presp->seqid_ > 0)) {
									statsmap["Listener Stats Resp"]++;

									LISTENERS_INFO_STATS_RESP 	*plist = (LISTENERS_INFO_STATS_RESP *)((char *)presp + sizeof(QUERY_RESPONSE));

									bret = plist->validate(&hdr, presp);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									auto cb = pconn1->extract_recv_cb(presp->seqid_);
									if (cb.has_value()) {
										cb->fcb_(pconn1, (uint8_t *)plist, presp->resp_len_, (uint8_t *)presp, false /* is_expiry */, false /* is_error */);
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
											cb->fcb_(pconn1, (uint8_t *)(presp + 1), presp->resp_len_, (uint8_t *)prdbuf, false /* is_expiry */, false /* is_error */);
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

					case COMM_EVENT_NOTIFY :
						if (true) {
							EVENT_NOTIFY		*pevtnot = (EVENT_NOTIFY *)(prdbuf + sizeof(COMM_HEADER));
							uint8_t			*pendptr = prdbuf + hdr.get_act_len();	

							switch (pevtnot->subtype_) {
							
							case NOTIFY_MP_CLI_TCP_INFO :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_MADHAVA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									MP_CLI_TCP_INFO 	*pinfo = (MP_CLI_TCP_INFO *)(pevtnot + 1);
									int			nevents = pevtnot->nevents_;

									statsmap["Madhava TCP Cli Conn Info"] += nevents;

									bret = pinfo->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									auto			psock = TCP_SOCK_HANDLER::get_singleton();

									if (psock) {
										psock->update_cli_conn_info_madhava(pinfo, nevents, pendptr);
									}

									// No response needs to be sent
								}

								break;

							case NOTIFY_MP_SER_TCP_INFO :
								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_MADHAVA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									MP_SER_TCP_INFO 	*pinfo = (MP_SER_TCP_INFO *)(pevtnot + 1);
									int			nevents = pevtnot->nevents_;

									statsmap["Madhava TCP Ser Conn Info"] += nevents;

									bret = pinfo->validate(&hdr, pevtnot);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									auto			psock = TCP_SOCK_HANDLER::get_singleton();

									if (psock) {
										psock->update_ser_conn_info_madhava(pinfo, nevents, pendptr);
									}

									// No response needs to be sent
								}

								break;

							case NOTIFY_MP_RESET_STATS :
								// nevents_ is always 1 here

								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_MADHAVA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									statsmap["Madhava Reset Stats"]++;

									auto 		*preset = (MP_RESET_STATS *)(pevtnot + 1);

									bret = preset->validate(&hdr);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									if (preset->reset_stats_) {
										handle_reset_stats();
									}	

									// No response needs to be sent
								}

								break;

							case NOTIFY_MADHAVA_PARTHA_STATUS :
								// nevents_ is always 1 here

								if ((!pconn1->is_registered()) || (pconn1->host_type_ != HOST_MADHAVA)) {
									statsmap["Invalid Message Error"]++; 
									GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
								}
								else {
									statsmap["Madhava Status"]++;

									MADHAVA_PARTHA_STATUS 	*preq = (MADHAVA_PARTHA_STATUS *)(pevtnot + 1);

									bret = preq->validate(&hdr);
									if (bret == false) {
										statsmap["Invalid Message Error"]++; 
										GY_THROW_EXCEPTION("Invalid Message received #%u. Closing connection", __LINE__);
									}

									gmadhava_.last_status_ = *preq;

									// No response needs to be sent
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

					data_sz 	-= hdr.total_sz_;
					max_buf_sz	-= hdr.total_sz_;
					prdbuf 		+= hdr.total_sz_;

					if (gy_unlikely(data_sz < 0 || max_buf_sz < data_sz)) {
						statsmap["Internal L1 recv stats error"]++;
						GY_THROW_EXCEPTION("Internal Error : L1 recv stats invalid");
					}

					if ((data_sz != rdstat_.data_sz_) && (max_buf_sz - data_sz < (ssize_t)sizeof(COMM_HEADER))) {
						// This implies we just need to move data to the start

						std::memmove(rdstat_.pdirbuf_, prdbuf, data_sz);
						rdstat_.data_sz_	= data_sz;

						set_variables();
					}	

				} while (data_sz > 0);

			} while (is_again == false && nsyscall < max_syscall);

			if (data_sz == 0) {
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
			
			case NOTIFY_SEND_DATA :
				statsmap["L1 Data Send Notify"]++;

				if (true == evn.data_.sock_data_.is_cli_active() && evn.data_.sock_data_.pconn_) {
					SOCK_SEND_DATA		& ldata = evn.data_.sock_data_;
					auto			pconn = ldata.pconn_;
					const int		cfd = pconn->get_sockfd();
					ssize_t			sret;
					size_t			ncbs_deleted;

					if (cfd == -1) {
						// Already closed
						return false;
					}	

					try {
						if (is_req_rsp && ldata.is_async_cb()) {
							statsmap["Add Async Callback"]++;

							pconn->add_async_callback(std::move(*ldata.async_cb_), &ncbs_deleted);
							if (ncbs_deleted) {
								statsmap["Async Callbacks Timed Out"] += ncbs_deleted;
							}	
						}

						sret = l1_handle_send(pconn, false /* throw_on_error */);

						if ((sret == -1) || (ldata.to_close_conn())) {
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
									(void)l1_handle_send(pconn, false /* throw_on_error */);
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

					case L1_MISC_MADHAVA_NEW_CONN :	
						
						statsmap["New Madhava Conn Notify"]++;

						if (lm.newsockfd_ >= 0) {
							/*
							 * First check if cli_type_ is already present as there is a race between connect_madhava() and this
							 * point. So any extra connections need to be closed.
							 */
							if (gy_unlikely(true == gmadhava_.is_cli_type_avail(lm.cli_type_))) {
								statsmap["Extra Madhava Conn"]++;
								close(lm.newsockfd_);
								return false;
							}	
							 
							set_sock_nonblocking(lm.newsockfd_, 1);

							try {
								auto 			[it, success] = mconntrack.try_emplace(lm.newsockfd_, nullptr);
								struct epoll_event	ev;

								if (success == true) {
									try {
										it->second = std::make_shared<PACONNTRACK>(&lm.saddr_, lm.newsockfd_, epollfd, nullptr, 
											0, 0, true /* use_pipeline */, MAX_CONN_IDLE_TIMEOUT_USEC, MAX_CONN_DATA_TIMEOUT_USEC,
											false /* close_conn_on_wr_complete */, true /* is_outgoing */);
									}
									GY_CATCH_EXCEPTION(
										ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught while creating map element for new connection %s\n", 
											GY_GET_EXCEPT_STRING);

										mconntrack.erase(it);
										::close(lm.newsockfd_);
										statsmap["Exception Occurred"]++;
										return false;
									);

									PACONNTRACK	*pnewconn = it->second.get();

									pnewconn->set_comm_magic(comm::COMM_HEADER::PM_HDR_MAGIC);
									pnewconn->set_epoll_data(pnewconn);

									pnewconn->set_registered();	
									
									pnewconn->pl1_ 		= &param;
									pnewconn->host_type_ 	= HOST_MADHAVA;
									pnewconn->cli_type_ 	= lm.cli_type_;

									if (lm.cli_type_ == CLI_TYPE_REQ_ONLY) {
										pnewconn->set_max_pipeline_sz(8192);
									}

									ev.data.ptr		= pnewconn;
									ev.events 		= (is_req_rsp ? EPOLLIN : 0) | EPOLLOUT | EPOLLHUP | EPOLLET;	// No EPOLLIN for CLI_TYPE_REQ_ONLY

									ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, lm.newsockfd_, &ev);
									if (ret == 0) {
										set_sock_keepalive(lm.newsockfd_);
									}	
									else {
										PERRORPRINTCOLOR(GY_COLOR_RED, "Madhava connection epoll add failed");
										mconntrack.erase(it);

										return false;
									}	
						
									try {
										gmadhava_.add_conn(const_cast<const SERVER_SIGNAL *>(lm.pl1_), pnewconn->weak_from_this(), 
													pnewconn, HOST_MADHAVA, pnewconn->cli_type_);
									}
									GY_CATCH_EXCEPTION(
										ERRORPRINT_OFFLOAD("Madhava Conn list add failed : %s\n", GY_GET_EXCEPT_STRING);
										mconntrack.erase(it);

										return false;
									);
								}
								else {
									if (it != mconntrack.end()) {
										mconntrack.erase(it);
									}	
									else {
										close(lm.newsockfd_);
									}
									return false;
								}	
							}
							GY_CATCH_EXCEPTION(
								ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught while adding new Madhava connection %s\n", GY_GET_EXCEPT_STRING);
								close(lm.newsockfd_);
								statsmap["Exception Occurred"]++;
								return false;
							);
						}	
						
						break;

					default :
						break;
					}
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
				 *    before the async callback could be added to the PACONNTRACK cb_tbl_ map.
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

						auto pconn = (PACONNTRACK *)pepdata;
						
						const int cfd = pconn->get_sockfd();

						try {
							const bool		conn_closed = (cevents & (EPOLLERR | EPOLLHUP));
							const bool		peer_rd_closed = (conn_closed || (cevents & EPOLLRDHUP));
							ssize_t			sret = 0;

							/* 
							 * No recv's allowed for Event Notify CLI_TYPE_REQ_ONLY conns
							 */
							
							if (is_req_rsp && cevents & EPOLLIN) {
								sret = handle_recv(pconn, cfd, conn_closed, peer_rd_closed);

								if (sret == -1) {
									pconn->signal_conn_close();
									mconntrack.erase(cfd);
									continue;
								}	
							}	
							
							if (cevents & EPOLLOUT) {
								if (false == peer_rd_closed) {
									if (!is_req_rsp || (0 != pconn->get_bytes_sent())) {
										sret = l1_handle_send(pconn, false /* throw_on_error */);
									}	
									else {
										// Init connect notification
										sret = pconn->handle_async_connect();
									}	
								}	
							}	

							if (sret == -1 || conn_closed) {
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

					if (0 == (niter_checks & 1)) {

						STRING_BUFFER<2048>	strbuf;

						for (auto && it : statsmap) {
							strbuf.appendfmt(" {\"%s\" : %ld},", it.first, it.second);
						}	
						strbuf.set_last_char(' ');

						INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "%s : Connections %lu (of Total %lu) : Stats : [ %.*s ] : "
							"Recent Pending Data Timed out conns %ld : Idle Timed out conns %ld\n", 
							param.descbuf_, mconntrack.size(), gtconncount.load(std::memory_order_relaxed), strbuf.sizeint(), strbuf.buffer(),
							npendtimeout, nidletimeout);
					}
				}	
				
				last_tcount 		= curr_tcount;
				curr_tcount		= mconntrack.size();

				gtconncount.fetch_add(curr_tcount - last_tcount, std::memory_order_relaxed);
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


int PACONN_HANDLER::blocking_shyama_register() noexcept
{
	try {
		if (time(nullptr) - gshyama_.last_reg_tsec_ < 10) {
			// Try at next iter as we need to give time to concurrent blocking_madhava_register() to complete and cancel this schedule
			return 1;
		}

		bool			is_registered = false;
		char			ebuf[128];

		auto [sfd, conn_success] = gy_tcp_connect(gshyama_.curr_shyama_host_, gshyama_.curr_shyama_port_, ebuf, "Shyama Server", true /* set_nodelay */, 
			false /* always_resolve_dns */, nullptr, nullptr, false /* use_ipv4_only */, true /* cloexec */, false /* set_nonblock */);

		if (sfd < 0) {

			GY_STRNCPY(gshyama_.last_error_buf_, ebuf, sizeof(gshyama_.last_error_buf_));
			GY_STRNCPY(last_error_buf_, ebuf, sizeof(last_error_buf_));
			
			uint64_t		csec = get_sec_clock(), lastcsec = GY_READ_ONCE(gshyama_.first_fail_csec_);

			if (!lastcsec) {
				lastcsec			= csec;
				gshyama_.first_fail_csec_ 	= csec;
			}

			gshyama_.nfails_++;

			if (gshyama_.nfails_ >= 3 && gshyama_.shyama_host_vec_.size() > 1 && (csec - lastcsec >= 270 || (csec - lastcsec >= 90 && !gshyama_.last_reg_tsec_))) {
			
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
				gshyama_.first_fail_csec_	= 0;

			}
			else {
				ERRORPRINT_OFFLOAD("Failed to connect to Shyama Server %s port %hu due to %s : Will retry later. "
					"Time since last connect to Shyama is %ld minutes : Time since Shyama cannot be connected is %ld seconds\n", 
					gshyama_.curr_shyama_host_, gshyama_.curr_shyama_port_, gshyama_.last_error_buf_, 
					gshyama_.last_success_tsec_ ? (get_sec_time() - gshyama_.last_success_tsec_)/60 : get_process_uptime_sec()/60, csec - lastcsec);
			}

			ppartha_->update_server_status(last_error_buf_);

			// We will retry at the next scheduler signal
			return -1;
		}	
	
		GY_SCOPE_EXIT {
			::close(sfd);

			gshyama_.last_reg_tsec_		= time(nullptr);

			if (is_registered) {
				gshyama_.last_success_tsec_ = get_sec_time();
			}
		};

		gshyama_.nfails_		= 0;
		gshyama_.first_fail_csec_	= 0;

		/*
		 * Now send the PS_REGISTER_REQ
		 */
		constexpr size_t	fixed_sz_ps = sizeof(COMM_HEADER) + sizeof(PS_REGISTER_REQ_S), fixed_sz_psr = sizeof(COMM_HEADER) + sizeof(PS_REGISTER_RESP_S);
		constexpr size_t	act_size = std::max(fixed_sz_ps, fixed_sz_psr) + 8;
		ssize_t			sret;
		int			ret, revents;
		uint8_t			*palloc;
		bool			is_malloc;
		char			tbuf[64];
		
		SAFE_STACK_ALLOC(palloc, act_size, is_malloc);

		COMM_HEADER		*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
		PS_REGISTER_REQ_S	*preq = reinterpret_cast<PS_REGISTER_REQ_S *>((uint8_t *)phdr + sizeof(COMM_HEADER)); 
		
		new (phdr) COMM_HEADER(PS_REGISTER_REQ, fixed_sz_ps, comm::COMM_HEADER::PS_ADHOC_MAGIC);

		new (preq) PS_REGISTER_REQ_S();
		
		std::memset(preq, 0, sizeof(*preq));

		preq->comm_version_		= comm::COMM_VERSION_NUM;
		preq->partha_version_		= gversion_num;
		preq->min_shyama_version_	= gmin_shyama_version;

		SYS_HARDWARE::get_singleton()->get_machine_id_num(preq->machine_id_hi_, preq->machine_id_lo_);

		GY_STRNCPY(preq->hostname_, OS_INFO::get_singleton()->get_node_hostname(), sizeof(preq->hostname_));
		GY_STRNCPY(preq->cluster_name_, cluster_name_, sizeof(preq->cluster_name_));
		GY_STRNCPY(preq->region_name_, region_name_, sizeof(preq->region_name_));
		GY_STRNCPY(preq->zone_name_, zone_name_, sizeof(preq->zone_name_));
		
		preq->kern_version_num_		= OS_INFO::get_singleton()->get_kernel_version();
		preq->curr_sec_			= time(nullptr);
		preq->last_mdisconn_sec_	= gmadhava_.last_disconn_tsec_ ? gmadhava_.last_disconn_tsec_ : preq->curr_sec_ - get_process_uptime_sec();
		preq->last_madhava_id_		= gmadhava_.madhava_id_;

		struct iovec			iov[2] {{phdr, fixed_sz_ps}, {(void *)gpadbuf, phdr->get_pad_len()}};	
		
		sret = gy_writev(sfd, iov, GY_ARRAY_SIZE(iov));
		if (sret < 0) {
			snprintf(gshyama_.last_error_buf_, sizeof(gshyama_.last_error_buf_), "Failed to send registration to Shyama server %s port %hu : %s", 
				gshyama_.curr_shyama_host_, gshyama_.curr_shyama_port_, strerror_r(errno, tbuf, sizeof(tbuf)));
			GY_STRNCPY(last_error_buf_, gshyama_.last_error_buf_, sizeof(last_error_buf_));

			ppartha_->update_server_status(last_error_buf_);

			ERRORPRINT_OFFLOAD("Failed to send registration to Shyama Server %s port %hu due to %s : Will retry later. Time since last connect to Shyama : %ld minutes\n", 
				gshyama_.curr_shyama_host_, gshyama_.curr_shyama_port_, gshyama_.last_error_buf_, 
				gshyama_.last_success_tsec_ ? (get_sec_time() - gshyama_.last_success_tsec_)/60 : get_process_uptime_sec()/60);
			return -1;
		}	
		
		// Now wait for the response : We wait for max 30 sec
		ret = poll_socket(sfd, 30'000, revents, POLLIN, false /* close_on_errors */);
		if (ret <= 0) {
			if (ret == 0) {
				snprintf(gshyama_.last_error_buf_, sizeof(gshyama_.last_error_buf_), "Registration Timed Out for connection to Shyama server %s port %hu", 
					gshyama_.curr_shyama_host_, gshyama_.curr_shyama_port_);
			}
			else {
				snprintf(gshyama_.last_error_buf_, sizeof(gshyama_.last_error_buf_), "Registration failed for connection to Shyama server %s port %hu : %s", 
					gshyama_.curr_shyama_host_, gshyama_.curr_shyama_port_, strerror_r(errno, tbuf, sizeof(tbuf)));
			}	
			GY_STRNCPY(last_error_buf_, gshyama_.last_error_buf_, sizeof(last_error_buf_));

			ppartha_->update_server_status(last_error_buf_);

			ERRORPRINT_OFFLOAD("Shyama Registration failed : %s : Will retry later. Time since last connect to Shyama : %ld minutes\n", 
				gshyama_.last_error_buf_, 
				gshyama_.last_success_tsec_ ? (get_sec_time() - gshyama_.last_success_tsec_)/60 : get_process_uptime_sec()/60);
			return -1;
		}
		
		sret = gy_recvbuffer(sfd, palloc, gy_align_up_2(fixed_sz_psr, 8), 0, true /* no_block_after_first_recv */);
		if (sret < (ssize_t)fixed_sz_psr) {
			snprintf(gshyama_.last_error_buf_, sizeof(gshyama_.last_error_buf_), "Registration failed for connection to Shyama server %s port %hu : %s", 
				gshyama_.curr_shyama_host_, gshyama_.curr_shyama_port_, strerror_r(errno, tbuf, sizeof(tbuf)));
			GY_STRNCPY(last_error_buf_, gshyama_.last_error_buf_, sizeof(last_error_buf_));

			ppartha_->update_server_status(last_error_buf_);

			ERRORPRINT_OFFLOAD("Failed to recv registration response from Shyama Server %s port %hu due to %s : Will retry later. Time since last connect to Shyama : %ld minutes\n", 
				gshyama_.curr_shyama_host_, gshyama_.curr_shyama_port_, gshyama_.last_error_buf_, 
				gshyama_.last_success_tsec_ ? (get_sec_time() - gshyama_.last_success_tsec_)/60 : get_process_uptime_sec()/60);

			return -1;
		}
	
		phdr = (COMM_HEADER *)palloc;
		PS_REGISTER_RESP_S		*presp = (PS_REGISTER_RESP_S *)((uint8_t *)phdr + sizeof(*phdr));

		if ((false == phdr->validate(palloc, comm::COMM_HEADER::PS_ADHOC_MAGIC)) || (false == presp->validate(phdr))) {
			snprintf(gshyama_.last_error_buf_, sizeof(gshyama_.last_error_buf_), "Registration failed as invalid response from Shyama server %s port %hu", 
				gshyama_.curr_shyama_host_, gshyama_.curr_shyama_port_);
			GY_STRNCPY(last_error_buf_, gshyama_.last_error_buf_, sizeof(last_error_buf_));

			ppartha_->update_server_status(last_error_buf_);

			ERRORPRINT_OFFLOAD("Invalid Registration response from Shyama Server %s port %hu : Will retry later. Time since last connect to Shyama : %ld minutes\n", 
				gshyama_.curr_shyama_host_, gshyama_.curr_shyama_port_, 
				gshyama_.last_success_tsec_ ? (get_sec_time() - gshyama_.last_success_tsec_)/60 : get_process_uptime_sec()/60);

			return -1;
		}

		if (presp->error_code_ != ERR_SUCCESS) {
			presp->error_string_[sizeof(presp->error_string_) - 1] = 0;

			snprintf(gshyama_.last_error_buf_, sizeof(gshyama_.last_error_buf_), "Registration failed as error response from Shyama server %s : Server %s port %hu", 
				presp->error_string_, gshyama_.curr_shyama_host_, gshyama_.curr_shyama_port_);
			GY_STRNCPY(last_error_buf_, gshyama_.last_error_buf_, sizeof(last_error_buf_));

			ppartha_->update_server_status(last_error_buf_);

			ERRORPRINT_OFFLOAD("Registration failed as Error response from Shyama Server %s : Server %s port %hu : Will retry later. Time since last connect to Shyama : %ld minutes\n", 
				presp->error_string_, gshyama_.curr_shyama_host_, gshyama_.curr_shyama_port_, 
				gshyama_.last_success_tsec_ ? (get_sec_time() - gshyama_.last_success_tsec_)/60 : get_process_uptime_sec()/60);

			return -1;
		}	
		
		bool			madhava_changed = false;

		if ((gmadhava_.madhava_id_ != presp->madhava_id_ && gmadhava_.madhava_id_ != 0) || 
			(gmadhava_.madhava_id_ != 0 && (strcmp(gmadhava_.madhava_hostname_, presp->madhava_hostname_) || gmadhava_.madhava_port_ != presp->madhava_port_))) {

			gmadhava_.last_madhava_id_ 	= gmadhava_.madhava_id_;
			std::memcpy(gmadhava_.last_madhava_hostname_, gmadhava_.madhava_hostname_, sizeof(gmadhava_.last_madhava_hostname_));
			gmadhava_.last_madhava_port_	= gmadhava_.madhava_port_;

			madhava_changed 		= true;
		}

		gmadhava_.madhava_id_		= presp->madhava_id_;
		GY_STRNCPY(gmadhava_.madhava_hostname_, presp->madhava_hostname_, sizeof(gmadhava_.madhava_hostname_));
		GY_STRNCPY(gmadhava_.madhava_name_, presp->madhava_name_, sizeof(gmadhava_.madhava_name_));
		gmadhava_.madhava_port_		= presp->madhava_port_;
		gmadhava_.partha_ident_key_	= presp->partha_ident_key_;
		gmadhava_.madhava_expiry_sec_	= presp->madhava_expiry_sec_;

		is_registered = true;

		stop_shyama_scheduler();

		snprintf(gshyama_.last_error_buf_, sizeof(gshyama_.last_error_buf_), "Registration success for Shyama server %s port %hu", 
			gshyama_.curr_shyama_host_, gshyama_.curr_shyama_port_);

		snprintf(last_error_buf_, sizeof(last_error_buf_), "Registered successfully with Shyama : Register with Madhava Server \'%s\' Host %s port %hu in progress", 
			gmadhava_.madhava_name_, gmadhava_.madhava_hostname_, gmadhava_.madhava_port_);

		INFOPRINT_OFFLOAD("%s\n\n", last_error_buf_);

		ppartha_->update_server_status(last_error_buf_);

		if (madhava_changed) {
			WARNPRINT_OFFLOAD("New Madhava Server \'%s\' assigned by Shyama : Older Madhava Server data may be lost if new Madhava has a different DB : Older Madhava server was %s port %hu\n\n",
				gmadhava_.madhava_name_, gmadhava_.last_madhava_hostname_, gmadhava_.last_madhava_port_);

			// Now delete each existing Madhava conn from HOST_CONN_LIST and signal the L1 thread to close conn
			close_all_conns(gmadhava_);
		}	

		schedule_madhava_register(100);

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught while registering with Shyama : %s\n\n", GY_GET_EXCEPT_STRING);
		return -1;
	);
}	

int PACONN_HANDLER::blocking_madhava_register() noexcept
{
	try {
		/*
		 * First check if the partha_ident_key_ is still valid. Then check if
		 * any existing Madhava connections already exist.
		 */
		time_t				tcurr = time(nullptr);

		if ((gmadhava_.partha_ident_key_ == 0) || (gmadhava_.madhava_expiry_sec_ < tcurr)) {
			/*
			 * Invalid Partha Ident key. We need to register with Shyama again to get the fresh keys...
			 * First we need to check if all Madhava connections already active and this was a false 
			 * alarm...
			 */
			if ((false == gmadhava_.is_cli_type_avail(CLI_TYPE_REQ_ONLY)) || (false == gmadhava_.is_cli_type_avail(CLI_TYPE_REQ_RESP))
				|| (false == gmadhava_.is_cli_type_avail(CLI_TYPE_RESP_REQ)) || (false == gmadhava_.trace_req_sock_.isvalid())) {

				stop_madhava_scheduler();
				schedule_shyama_register();
				return 1;
			}
			else {
				stop_madhava_scheduler();
				return 0;
			}	
		}	

		/*
		 * We register 4 connections to Madhava : 1 of type CLI_TYPE_REQ_ONLY, 1 of CLI_TYPE_REQ_RESP, 1 of CLI_TYPE_RESP_REQ and 
		 * 						1 Trace Request Socket also of CLI_TYPE_REQ_ONLY
		 */						

		bool				bret, reqonly = false;
		int				ret, nconnects = 0;
		int				sock_req_only = -1, sock_req_resp = -1, sock_resp_req = -1;
		struct sockaddr_storage		saddr_req_only {}, saddr_req_resp {}, saddr_resp_req {};
		socklen_t			slen_req_only = 0, slen_req_resp = 0, slen_resp_req = 0;
		struct sockaddr_storage		tsaddr {};
		socklen_t			tslen = 0;
		int				tsock = -1;

		GY_SCOPE_EXIT {
			if (sock_req_only >= 0) {
				::close(sock_req_only);
			}	
			if (sock_req_resp >= 0) {
				::close(sock_req_resp);
			}	
			if (sock_resp_req >= 0) {
				::close(sock_resp_req);
			}	
			if (tsock >= 0) {
				::close(tsock);
			}	
		};

		bret = gmadhava_.is_cli_type_avail(CLI_TYPE_REQ_ONLY);
		if (bret == false) {
			sock_req_only = connect_madhava(CLI_TYPE_REQ_ONLY, saddr_req_only, slen_req_only);
			if (sock_req_only < 0) {
				tcurr = time(nullptr);

				if (gmadhava_.madhava_expiry_sec_ < tcurr) {
					stop_madhava_scheduler();
					schedule_shyama_register();
				}	
				return -1;
			}	

			bret = notify_new_conn(&evt_hdlr_, CLI_TYPE_REQ_ONLY, saddr_req_only, sock_req_only);
			if (bret != true) {
				ERRORPRINT_OFFLOAD("Failed to notify L1 thread for new Madhava connection. Will retry later...\n");
				return -1;
			}	

			// Reset sock to avoid closing
			sock_req_only = -1;

			nconnects++;

			reqonly = true;
		}	

		bret = gmadhava_.is_cli_type_avail(CLI_TYPE_REQ_RESP);
		if (bret == false) {
			sock_req_resp = connect_madhava(CLI_TYPE_REQ_RESP, saddr_req_resp, slen_req_resp);
			if (sock_req_resp < 0) {
				tcurr = time(nullptr);

				if (gmadhava_.madhava_expiry_sec_ < tcurr) {
					stop_madhava_scheduler();
					schedule_shyama_register();
				}	
				return -1;
			}	

			bret = notify_new_conn(&req_rsp_hdlr_, CLI_TYPE_REQ_RESP, saddr_req_resp, sock_req_resp);
			if (bret != true) {
				ERRORPRINT_OFFLOAD("Failed to notify L1 thread for new Madhava connection. Will retry later...\n");
				return -1;
			}	

			// Reset sock to avoid closing
			sock_req_resp = -1;

			nconnects++;
		}	

		bret = gmadhava_.is_cli_type_avail(CLI_TYPE_RESP_REQ);
		if (bret == false) {
			sock_resp_req = connect_madhava(CLI_TYPE_RESP_REQ, saddr_resp_req, slen_resp_req);
			if (sock_resp_req < 0) {
				tcurr = time(nullptr);

				if (gmadhava_.madhava_expiry_sec_ < tcurr) {
					stop_madhava_scheduler();
					schedule_shyama_register();
				}	
				return -1;
			}	

			bret = notify_new_conn(&req_rsp_hdlr_, CLI_TYPE_RESP_REQ, saddr_resp_req, sock_resp_req);
			if (bret != true) {
				ERRORPRINT_OFFLOAD("Failed to notify L1 thread for new Madhava connection. Will retry later...\n");
				return -1;
			}	

			// Reset sock to avoid closing
			sock_resp_req = -1;

			nconnects++;
		}	

		if (false == gmadhava_.trace_req_sock_.isvalid() && true == gmadhava_.is_cli_type_avail(CLI_TYPE_REQ_ONLY)) {

			tsock = connect_madhava(CLI_TYPE_REQ_ONLY, tsaddr, tslen, comm::PM_CONNECT_CMD_S::CONN_FLAGS_REQ_TRACING, false /* upd_madhava_stats */);
			if (tsock < 0) {
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to connect to Madhava Server for Request Tracing. Will retry later...\n");
				return -1;
			}	
			else {
				// Set blocking
				set_sock_nonblocking(tsock, 0);
				set_sock_keepalive(tsock);
				
				gmadhava_.trace_req_sock_.set_fd(tsock);
				gmadhava_.trace_sched_sec_ = time(nullptr);

				tsock = -1;

				nconnects++;
			}	
		}	

		// Again check if all connections still connected and if so, then cancel the schedule
		if (gmadhava_.is_cli_type_avail(CLI_TYPE_REQ_ONLY) && gmadhava_.is_cli_type_avail(CLI_TYPE_REQ_RESP) && gmadhava_.is_cli_type_avail(CLI_TYPE_RESP_REQ)
			&& gmadhava_.trace_req_sock_.isvalid()) {

			stop_madhava_scheduler();
		}	

		if (nconnects > 0) {
			snprintf(last_error_buf_, sizeof(last_error_buf_), "Successfully Registered with Madhava Server \'%s\' Host %s port %hu with %lu connections\n",
				gmadhava_.madhava_name_, gmadhava_.madhava_hostname_, gmadhava_.madhava_port_, gmadhava_.get_num_conns() + gmadhava_.trace_req_sock_.isvalid());

			char				zbuf[512];

			if (*region_name_ && *zone_name_) {
				if ((0 == strcmp(gmadhava_.region_name_, region_name_)) && 0 == strcmp(gmadhava_.zone_name_, zone_name_)) {
					snprintf(zbuf, sizeof(zbuf), "Madhava server is in the same region %s and same zone %s", gmadhava_.region_name_, gmadhava_.zone_name_);
				}
				else if (0 == strcmp(gmadhava_.region_name_, region_name_)) {
					snprintf(zbuf, sizeof(zbuf), "Madhava server is in the same region %s but different zone %s", gmadhava_.region_name_, gmadhava_.zone_name_);
				}
				else {
					snprintf(zbuf, sizeof(zbuf), "Madhava server is in a different region %s zone %s", gmadhava_.region_name_, gmadhava_.zone_name_);
				}
			}
			else {
				snprintf(zbuf, sizeof(zbuf), "Madhava server is in region %s zone %s", gmadhava_.region_name_, gmadhava_.zone_name_);
			}	

			INFOPRINT_OFFLOAD("Successfully Registered with Madhava Server \'%s\' Host %s port %hu : %s\n", 
					gmadhava_.madhava_name_, gmadhava_.madhava_hostname_, gmadhava_.madhava_port_, zbuf);

			ppartha_->update_server_status(last_error_buf_);

			if (reqonly) {
				PACONN_HANDLER::get_singleton()->scheduler_.add_schedule(90'000, 60'000, 0, "Schedule Host Extended Info send",
				[] {
					auto			psys = SYS_HARDWARE::get_singleton();
					bool			bret;

					if (psys) {
						bret = psys->send_host_info();
						if (bret) {
							if (!PACONN_HANDLER::get_singleton()) {
								return;
							}
							
							PACONN_HANDLER::get_singleton()->scheduler_.cancel_schedule("Schedule Host Extended Info send");
						}	
					}
				}, false);	
			}	
		}

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught while registering with Madhava : %s\n\n", GY_GET_EXCEPT_STRING);
		return -1;
	);
}

int PACONN_HANDLER::connect_madhava(comm::CLI_TYPE_E cli_type, struct sockaddr_storage & saddr, socklen_t & socklen, uint64_t conn_flags, bool upd_madhava_stats) 
{
	bool				is_registered = false;
	struct sockaddr_storage		saddr_store;
	char				ebuf[128];

	if (upd_madhava_stats && gmadhava_.last_disconn_tsec_ == 0) {
		gmadhava_.last_disconn_tsec_ = time(nullptr);
	}

	auto [sfd, conn_success] = gy_tcp_connect(gmadhava_.madhava_hostname_, gmadhava_.madhava_port_, ebuf, "Madhava Server", true /* set_nodelay */, 
		false /* always_resolve_dns */, &saddr_store, &socklen, false /* use_ipv4_only */, true /* cloexec */, false /* set_nonblock */);

	if (sfd < 0) {

		GY_STRNCPY(gmadhava_.last_error_buf_, ebuf, sizeof(gmadhava_.last_error_buf_));
		GY_STRNCPY(last_error_buf_, ebuf, sizeof(last_error_buf_));

		ERRORPRINT_OFFLOAD("Failed to connect to Madhava Server \'%s\' Host %s port %hu due to %s : Will retry later. Time since last disconnect to Madhava : %ld minutes\n", 
			gmadhava_.madhava_name_, gmadhava_.madhava_hostname_, gmadhava_.madhava_port_, gmadhava_.last_error_buf_, 
			gmadhava_.last_disconn_tsec_ ? (get_sec_time() - gmadhava_.last_disconn_tsec_)/60 : get_process_uptime_sec()/60);
		
		if (upd_madhava_stats) {
			ppartha_->update_server_status(last_error_buf_);
		}

		// We will retry at the next scheduler signal
		return -1;
	}	

	std::memcpy(&saddr, &saddr_store, sizeof(saddr));

	GY_SCOPE_EXIT {

		gmadhava_.last_reg_tsec_		= time(nullptr);

		if (false == is_registered) {
			::close(sfd);
		}
	};

	/*
	 * Now send the PM_CONNECT_CMD_S
	 */
	constexpr size_t	fixed_sz_pm = sizeof(COMM_HEADER) + sizeof(PM_CONNECT_CMD_S), fixed_sz_pmr = sizeof(COMM_HEADER) + sizeof(PM_CONNECT_RESP_S);
	constexpr size_t	act_size = std::max(fixed_sz_pm, fixed_sz_pmr) + 8;
	ssize_t			sret;
	int			ret, revents;
	uint8_t			*palloc;
	bool			is_malloc;
	char			tbuf[64];
	
	SAFE_STACK_ALLOC(palloc, act_size, is_malloc);

	COMM_HEADER		*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
	PM_CONNECT_CMD_S	*preq = reinterpret_cast<PM_CONNECT_CMD_S *>((uint8_t *)phdr + sizeof(COMM_HEADER)); 
	
	new (phdr) COMM_HEADER(PM_CONNECT_CMD, fixed_sz_pm, comm::COMM_HEADER::PM_HDR_MAGIC);

	new (preq) PM_CONNECT_CMD_S();
	
	std::memset(preq, 0, sizeof(*preq));

	preq->comm_version_		= comm::COMM_VERSION_NUM;
	preq->partha_version_		= gversion_num;
	preq->min_madhava_version_	= gmin_madhava_version;

	SYS_HARDWARE::get_singleton()->get_machine_id_num(preq->machine_id_hi_, preq->machine_id_lo_);
	preq->partha_ident_key_		= gmadhava_.partha_ident_key_;

	GY_STRNCPY(preq->hostname_, OS_INFO::get_singleton()->get_node_hostname(), sizeof(preq->hostname_));
	GY_STRNCPY(preq->cluster_name_, cluster_name_, sizeof(preq->cluster_name_));
	GY_STRNCPY(preq->region_name_, region_name_, sizeof(preq->region_name_));
	GY_STRNCPY(preq->zone_name_, zone_name_, sizeof(preq->zone_name_));
	
	preq->madhava_id_		= gmadhava_.madhava_id_;
	preq->cli_type_			= cli_type;
	preq->kern_version_num_		= OS_INFO::get_singleton()->get_kernel_version();
	preq->curr_sec_			= time(nullptr);
	preq->clock_sec_		= get_sec_clock();
	preq->process_uptime_sec_	= get_process_uptime_sec();
	preq->last_connect_sec_		= gmadhava_.last_success_tsec_;
	preq->flags_			= conn_flags;

	struct iovec			iov[2] {{phdr, fixed_sz_pm}, {(void *)gpadbuf, phdr->get_pad_len()}};	
	
	sret = gy_writev(sfd, iov, GY_ARRAY_SIZE(iov));
	if (sret < 0) {
		snprintf(gmadhava_.last_error_buf_, sizeof(gmadhava_.last_error_buf_), "Failed to send registration to Madhava server %s port %hu : %s", 
			gmadhava_.madhava_hostname_, gmadhava_.madhava_port_, strerror_r(errno, tbuf, sizeof(tbuf)));
		GY_STRNCPY(last_error_buf_, gmadhava_.last_error_buf_, sizeof(last_error_buf_));

		ERRORPRINT_OFFLOAD("Failed to send registration to Madhava Server %s port %hu due to %s : Will retry later. Time since last disconnect to Madhava : %ld minutes\n", 
			gmadhava_.madhava_hostname_, gmadhava_.madhava_port_, gmadhava_.last_error_buf_, 
			gmadhava_.last_disconn_tsec_ ? (get_sec_time() - gmadhava_.last_disconn_tsec_)/60 : get_process_uptime_sec()/60);

		if (upd_madhava_stats) {
			ppartha_->update_server_status(last_error_buf_);
		}

		return -1;
	}	
	
	// Now wait for the response : We wait for max 30 sec
	ret = poll_socket(sfd, 30'000, revents, POLLIN, false /* close_on_errors */);
	if (ret <= 0) {
		if (ret == 0) {
			snprintf(gmadhava_.last_error_buf_, sizeof(gmadhava_.last_error_buf_), "Registration Timed Out for connection to Madhava server %s port %hu", 
				gmadhava_.madhava_hostname_, gmadhava_.madhava_port_);
		}
		else {
			snprintf(gmadhava_.last_error_buf_, sizeof(gmadhava_.last_error_buf_), "Registration failed for connection to Madhava server %s port %hu : %s", 
				gmadhava_.madhava_hostname_, gmadhava_.madhava_port_, strerror_r(errno, tbuf, sizeof(tbuf)));
		}	
		GY_STRNCPY(last_error_buf_, gmadhava_.last_error_buf_, sizeof(last_error_buf_));

		if (upd_madhava_stats) {
			ppartha_->update_server_status(last_error_buf_);
		}

		ERRORPRINT_OFFLOAD("Madhava Registration failed : %s : Will retry later. Time since last disconnect to Madhava : %ld minutes\n", 
			gmadhava_.last_error_buf_, 
			gmadhava_.last_disconn_tsec_ ? (get_sec_time() - gmadhava_.last_disconn_tsec_)/60 : get_process_uptime_sec()/60);

		return -1;
	}
	
	sret = gy_recvbuffer(sfd, palloc, gy_align_up_2(fixed_sz_pmr, 8), 0, true /* no_block_after_first_recv */);
	if (sret < (ssize_t)fixed_sz_pmr) {
		snprintf(gmadhava_.last_error_buf_, sizeof(gmadhava_.last_error_buf_), "Registration failed for connection to Madhava server %s port %hu : %s", 
			gmadhava_.madhava_hostname_, gmadhava_.madhava_port_, strerror_r(errno, tbuf, sizeof(tbuf)));
		GY_STRNCPY(last_error_buf_, gmadhava_.last_error_buf_, sizeof(last_error_buf_));

		if (upd_madhava_stats) {
			ppartha_->update_server_status(last_error_buf_);
		}

		ERRORPRINT_OFFLOAD("Failed to recv registration response from Madhava Server %s port %hu due to %s : Will retry later. Time since last disconnect to Madhava : %ld minutes\n", 
			gmadhava_.madhava_hostname_, gmadhava_.madhava_port_, gmadhava_.last_error_buf_, 
			gmadhava_.last_disconn_tsec_ ? (get_sec_time() - gmadhava_.last_disconn_tsec_)/60 : get_process_uptime_sec()/60);

		return -1;
	}

	phdr 			= (COMM_HEADER *)palloc;
	PM_CONNECT_RESP_S	*presp = (PM_CONNECT_RESP_S *)((uint8_t *)phdr + sizeof(*phdr));

	if ((false == phdr->validate(palloc, comm::COMM_HEADER::PM_HDR_MAGIC)) || (false == presp->validate(phdr))) {
		snprintf(gmadhava_.last_error_buf_, sizeof(gmadhava_.last_error_buf_), "Registration failed as invalid response from Madhava server %s port %hu", 
			gmadhava_.madhava_hostname_, gmadhava_.madhava_port_);
		GY_STRNCPY(last_error_buf_, gmadhava_.last_error_buf_, sizeof(last_error_buf_));

		if (upd_madhava_stats) {
			ppartha_->update_server_status(last_error_buf_);
		}

		ERRORPRINT_OFFLOAD("Invalid Registration response from Madhava Server %s port %hu : Will retry later. Time since last disconnect to Madhava : %ld minutes\n", 
			gmadhava_.madhava_hostname_, gmadhava_.madhava_port_, 
			gmadhava_.last_disconn_tsec_ ? (get_sec_time() - gmadhava_.last_disconn_tsec_)/60 : get_process_uptime_sec()/60);

		return -1;
	}

	if (presp->error_code_ != ERR_SUCCESS) {
		snprintf(gmadhava_.last_error_buf_, sizeof(gmadhava_.last_error_buf_), "Registration failed as error response from Madhava server \'%s\' : Server %s port %hu", 
			presp->error_string_, gmadhava_.madhava_hostname_, gmadhava_.madhava_port_);
		GY_STRNCPY(last_error_buf_, gmadhava_.last_error_buf_, sizeof(last_error_buf_));

		if (upd_madhava_stats) {
			ppartha_->update_server_status(last_error_buf_);
		}

		ERRORPRINT_OFFLOAD("Registration failed as Error response from Madhava Server %s : Server %s port %hu : Will retry later. Time since last disconnect to Madhava : %ld minutes\n", 
			presp->error_string_, gmadhava_.madhava_hostname_, gmadhava_.madhava_port_, 
			gmadhava_.last_disconn_tsec_ ? (get_sec_time() - gmadhava_.last_disconn_tsec_)/60 : get_process_uptime_sec()/60);

		/*
		 * Check for specific Error codes
		 */
		if (upd_madhava_stats && presp->error_code_ == ERR_NOT_VALIDATED) {
			// Check if Shyama was last connected over 30 sec back. If so, we need to send a new Shyama register
			if (get_sec_time() - GY_READ_ONCE(gshyama_.last_success_tsec_) > 30) {
				gmadhava_.madhava_expiry_sec_ = 1;
			}	
		}

		return -1;
	}	
	
	if (upd_madhava_stats) {
		gmadhava_.comm_version_		= presp->comm_version_;
		gmadhava_.madhava_version_	= presp->madhava_version_;
		gmadhava_.last_success_tsec_ 	= get_sec_time();
		gmadhava_.last_disconn_tsec_ 	= 0;

		GY_STRNCPY(gmadhava_.region_name_, presp->region_name_, sizeof(gmadhava_.region_name_));
		GY_STRNCPY(gmadhava_.zone_name_, presp->zone_name_, sizeof(gmadhava_.zone_name_));
		GY_STRNCPY(gmadhava_.madhava_name_, presp->madhava_name_, sizeof(gmadhava_.madhava_name_));
	}

	is_registered = true;

	/*
	 * Now check the response presp->flags_
	 */
	if (upd_madhava_stats && presp->flags_ & comm::PM_CONNECT_RESP_S::CONN_FLAGS_RESET_STATS) {
		handle_reset_stats();
	}	

	return sfd;
}	

bool PACONN_HANDLER::notify_close_conn(const SERVER_SIGNAL *pl1const, std::weak_ptr <PACONNTRACK> weakconn, PACONNTRACK *pconn) noexcept
{
	SERVER_SIGNAL			*pl1 = const_cast<SERVER_SIGNAL *>(pl1const);
	L1_MISC_NOTIFY			l1(pl1, std::move(weakconn), pconn);

	bool				bret;
	int				ntries = 0;

	do { 
		bret = pl1->signalq_.write(std::move(l1));
	} while (bret == false && ntries++ < 10);

	if (bret == false) {
		return false;
	}

	int64_t			n = 1;

	(void)::write(pl1->signalfd_, &n, sizeof(int64_t));

	return true;
}	

void PACONN_HANDLER::close_all_conns(MADHAVA_INFO & madhava) noexcept
{
	auto lwalk = [&, this](HOST_CONN_LIST::HOST_CONN_L1 & lconn) noexcept
	{
		if (lconn.is_cli_active()) {
			// This is executed under mutex lock. But OK as we need to clear all conns
			notify_close_conn(lconn.pl1_, lconn.weakconn_, lconn.pconn_);
		}
		return CB_DELETE_ELEM;
	};	

	madhava.walk_conn_list(lwalk);

	if (madhava.trace_req_sock_.isvalid()) {
		madhava.trace_req_sock_.close();
	}	
}	

bool PACONN_HANDLER::notify_new_conn(SERVER_SIGNAL *pl1, comm::CLI_TYPE_E cli_type, struct sockaddr_storage & saddr, int newsockfd) noexcept
{
	L1_MISC_NOTIFY			l1(pl1, cli_type, saddr, newsockfd);

	bool				bret;
	int				ntries = 0;

	do { 
		bret = pl1->signalq_.write(std::move(l1));
	} while (bret == false && ntries++ < 10);

	if (bret == false) {
		return false;
	}

	int64_t			n = 1;

	(void)::write(pl1->signalfd_, &n, sizeof(int64_t));

	return true;
}	

ssize_t PACONN_HANDLER::l1_handle_send(PACONNTRACK *pconn1, bool throw_on_error)
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

int PACONN_HANDLER::schedule_shyama_register() noexcept
{
	auto phdlr = PACONN_HANDLER::get_singleton(); 
	if (!phdlr) {
		return false;
	}

	bool bret = phdlr->scheduler_.add_schedule(0, 30'000, 0, SHYAMA_INFO::shyama_schedule_name_, 
		[phdlr] {
			phdlr->blocking_shyama_register();
		}, false);	

	return !bret;
}	

int PACONN_HANDLER::schedule_madhava_register(uint64_t startaftermsec) noexcept
{
	auto phdlr = PACONN_HANDLER::get_singleton(); 
	if (!phdlr) {
		return false;
	}

	bool bret = phdlr->scheduler_.add_schedule(startaftermsec, 30'000, 0, MADHAVA_INFO::madhava_schedule_name_, 
		[phdlr] {
			phdlr->blocking_madhava_register();
		}, false);	

	return !bret;
}	

void PACONN_HANDLER::send_madhava_status() noexcept
{
	try {

		static constexpr size_t		fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + sizeof(PARTHA_STATUS);
		void				*palloc = GY_REFCNT::allocate_refbuf(fixed_sz);

		GY_SCOPE_EXIT {
			GY_REFCNT::sub_refcount_free(palloc);
		};	

		COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
		EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>((uint8_t *)phdr + sizeof(COMM_HEADER)); 
		PARTHA_STATUS			*pstat = reinterpret_cast<PARTHA_STATUS *>((uint8_t *)pnot + sizeof(*pnot));
		
		new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, fixed_sz, COMM_HEADER::PM_HDR_MAGIC);

		pnot->subtype_			= comm::NOTIFY_PARTHA_STATUS;
		pnot->nevents_			= 1;
		
		pstat->is_ok_			= true;

		auto				shrconn1 = gmadhava_.get_last_conn(comm::CLI_TYPE_REQ_ONLY);
		auto 				pconn = shrconn1.get();
		bool				bret;

		if (pconn) {
			GY_REFCNT::add_refcount(palloc);
			
			bret = send_server_data(EPOLL_IOVEC_ARR(2, false, palloc, fixed_sz, GY_REFCNT::sub_refcount_free, gpadbuf, phdr->get_pad_len(), nullptr), 
				pconn->cli_type_, comm::COMM_EVENT_NOTIFY, shrconn1);
			
			if (bret == true) {
				shrconn1 = gmadhava_.get_last_conn(comm::CLI_TYPE_REQ_RESP);
				pconn = shrconn1.get();

				if (pconn) {
					GY_REFCNT::add_refcount(palloc);

					bret = send_server_data(EPOLL_IOVEC_ARR(2, false, palloc, fixed_sz, GY_REFCNT::sub_refcount_free, gpadbuf, phdr->get_pad_len(), nullptr), 
							pconn->cli_type_, comm::COMM_EVENT_NOTIFY, shrconn1);
				}	

			}
		}
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught while sending Madhava Status  : %s\n\n", GY_GET_EXCEPT_STRING);
	);
}	

PACONN_HANDLER * PACONN_HANDLER::get_singleton() noexcept
{
	return pgconn_handler_;
}	

} // namespace partha
} // namespace gyeeta

