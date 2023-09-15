//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include 			"gy_network_capture.h"
#include 			"gy_print_offload.h"
#include			"gy_netif.h"
#include			"gy_rcu_inc.h"

#include 			"pcap.h"
#include 			"pcap/dlt.h"

namespace gyeeta {

PCAP_NET_CAP::PCAP_NET_CAP(const char *devname, const char * filterstr, uint32_t filterlen,
			folly::Function<void(const uint8_t * pframe, uint32_t caplen, uint32_t origlen, int linktype, struct timeval tv_cap)> && callback, 
			uint32_t buffersize, uint32_t snaplen, bool use_promiscuous, size_t thr_stacksz,
			int timeout_sec, folly::Function<void(const PCAP_NET_CAP *)> && timeout_cb, int ring_max_pkts, bool rcu_offline_after_read)
	: callback_(std::move(callback)), timeout_cb_(std::move(timeout_cb)), timeout_sec_(timeout_sec), ring_max_pkts_(ring_max_pkts), use_promiscuous_(use_promiscuous), 
	rcu_offline_after_read_(rcu_offline_after_read), timeoutcb_defined_(timeout_sec > 0 && bool(timeout_cb_)), 
	pfilter_code_((bpf_program *)malloc_or_throw(sizeof(*pfilter_code_))), filter_string_(filterstr, filterlen)
{
	int			ret;

	if (!devname) {
		devname = "any";
	}	

	GY_STRNCPY(ifname_, devname, sizeof(ifname_));
	
	if (use_promiscuous_ && 0 == strcmp(ifname_, "any")) {
		use_promiscuous_ = false;
	}

	if (buffersize > 100 * 1024 && buffersize < 2 * 1024 * 1024 * 1024u) {
		cap_bufsize_ = buffersize;
	}

	if (snaplen < 256 * 1024) {
		if (snaplen < 60) {
			snaplen = 60;
		}	
		cap_snaplen_ = snaplen;
	}

	try {
		set_capture_params();
	}
	catch(...) {
		free(pfilter_code_);
		throw;
	}	

	ret = gy_create_thread(&loop_tid_, PCAP_NET_CAP::GET_PTHREAD_WRAPPER(loop_thread), this, thr_stacksz);
	if (ret) {
		int		olderr = errno;

		loop_tid_ = 0;
		this->~PCAP_NET_CAP();

		errno = olderr;

		GY_THROW_SYS_EXCEPTION("Could not spawn pcap capture loop thread for device %s", ifname_); 
	}	
}	

PCAP_NET_CAP::~PCAP_NET_CAP()
{
	if (loop_tid_ > 0) {
		cap_cmd_.store(CAP_CMD_STOP);

		if (pd_) {
			pcap_breakloop(pd_);
		}	

		SCOPE_GY_MUTEX			scope(filtmutex_);

		INFOPRINT_OFFLOAD("pcap Capture for \'%s\' on device %s destructor called. Waiting for thread exit...\n", filter_string_.c_str(), ifname_);

		scope.unlock();

		gy_pthread_join(loop_tid_, nullptr, 200 /* max_millsecs_to_wait_at_start */, true); 
		
		loop_tid_ = 0;
	}	
	
	if (pd_) {
		pcap_close(pd_);
		pd_ = nullptr;
	}
		
	if (pfilter_code_) {
		pcap_freecode(pfilter_code_);
		free(pfilter_code_);
		pfilter_code_ = nullptr;
	}
}	

void PCAP_NET_CAP::set_capture_params()
{
	char 			ebuf[PCAP_ERRBUF_SIZE];
	int			ret;
	pcap_t			*pd_backup;

	if (!pfilter_code_) {
		GY_THROW_EXCEPTION("Internal Error : Filter struct not yet allocated for pcap capture");
	}

	pd_ = pcap_create(ifname_, ebuf);
	if (pd_ == nullptr) {
		cap_cmd_.store(CAP_CMD_NONE);
		GY_THROW_EXCEPTION("Failed to start capture on devive %s : %s", ifname_, ebuf);
	}		

	pd_backup = pd_;

	GY_SCOPE_EXIT {
		if (pd_backup) {
			pcap_close(pd_backup);
			pd_ = nullptr;
			
			cap_cmd_.store(CAP_CMD_NONE);
		}	
	};
		
	ret = pcap_set_snaplen(pd_, cap_snaplen_);
	if (ret != 0) {
		GY_THROW_EXCEPTION("pcap capture on %s: pcap_set_snaplen failed: %s", ifname_, pcap_statustostr(ret));
	}

	pcap_set_promisc(pd_, use_promiscuous_);

	ret = pcap_set_timeout(pd_, timeout_sec_ > 0 ? timeout_sec_ * 1000 : timeout_sec_ < 0 ? timeout_sec_ : 1000);
	if (ret != 0) {
		GY_THROW_EXCEPTION("pcap capture on %s: pcap_set_timeout failed: %s", ifname_, pcap_statustostr(ret));
	}

	ret = pcap_set_buffer_size(pd_, cap_bufsize_);
	if (ret != 0) {
		ERRORPRINT("pcap capture on %s : pcap_set_buffer_size failed: %s\n", ifname_, pcap_statustostr(ret));
	}
	
	ret = pcap_activate(pd_);
	if (ret < 0) {
		/*
		 * pcap_activate() failed.
		 */
		GY_THROW_EXCEPTION("pcap capture on %s failed : %s : (%s)", ifname_, pcap_statustostr(ret), pcap_geterr(pd_));
	} 
	else if (ret > 0) {
		/*
		 * pcap_activate() succeeded, but it's warning us
		 * of a problem it had.
		 */
		WARNPRINT_OFFLOAD("pcap capture on %s : %s : (%s)\n", ifname_, pcap_statustostr(ret), pcap_geterr(pd_));
	}

	SCOPE_GY_MUTEX			scopemutex(filtmutex_);

	if (pcap_compile(pd_, pfilter_code_, filter_string_.c_str(), 1 /* Optimize filter */, 0xFFFFFFFF) < 0) {
		GY_THROW_EXCEPTION("Error in setting pcap filter for capturing on device %s : %s", ifname_, pcap_geterr(pd_));
	}	
	
	if (pcap_setfilter(pd_, pfilter_code_) < 0) {
		GY_THROW_EXCEPTION("Error in setting pcap filter for capturing on device %s : %s", ifname_, pcap_geterr(pd_));
	}	

	linktype_ = pcap_datalink(pd_);

	switch (linktype_) {
	
	case DLT_EN10MB :
	case DLT_IEEE802 :
	case DLT_NULL :
	case DLT_LOOP :
	case DLT_RAW :
	case DLT_LINUX_SLL :
	case DLT_IPNET :
		break;

	default :
		pcap_freecode(pfilter_code_);
		GY_THROW_EXCEPTION("pcap capture on device %s not currently supported as linktype is %d", ifname_, linktype_);
	}	
	
	INFOPRINT_OFFLOAD("Started Network pcap capture on device %s for filter \'%s\'\n", ifname_, filter_string_.c_str());

	scopemutex.unlock();

	tstart_ = time(nullptr);

	auto			cap = cap_cmd_.exchange(CAP_CMD_START);
	
	if (cap == CAP_CMD_STOP) {
		GY_THROW_EXCEPTION("pcap capture on device %s started but stop capture was signalled...", ifname_);
	}	

	pd_backup = nullptr;
}	

// Not thread safe
void PCAP_NET_CAP::restart_capture_signal(const char *newfilter, size_t lenfilter, uint32_t buffersize, uint32_t snaplen)
{
	if (!pd_ || loop_tid_ == 0 || cap_cmd_.load(std::memory_order_acquire) > CAP_CMD_START) {
		GY_THROW_EXCEPTION("pcap Capture restart called while capture not active");
	}	
	
	SCOPE_GY_MUTEX			scopemutex(filtmutex_);

	filter_string_.assign(newfilter, lenfilter);

	scopemutex.unlock();

	if (buffersize) {
		cap_bufsize_ = buffersize;
	}
	if (snaplen) {
		cap_snaplen_ = snaplen;
	}

	auto			cap = cap_cmd_.exchange(CAP_CMD_RESTART);
	
	if (cap == CAP_CMD_STOP) {
		pcap_breakloop(pd_);

		GY_THROW_EXCEPTION("pcap capture on device %s restart signalled but stop capture was signalled from capture thread...", ifname_);
	}	

	pcap_breakloop(pd_);
}

std::pair<uint32_t, uint32_t> PCAP_NET_CAP::update_pcap_stats() const noexcept
{
	uint32_t 		npkts_received = 0, npkts_kernel_drops = 0;

	if (pd_) {
		int 			ret;
		struct pcap_stat 	stat1;

		ret = pcap_stats(pd_, &stat1);
		if (ret < 0) {
			return {};
		}	
		
		if (stat1.ps_recv > last_npkts_rcvd_) {
			npkts_received 		= stat1.ps_recv - last_npkts_rcvd_;
			npkts_kernel_drops	= stat1.ps_drop - last_npkts_drops_;
		}	

		last_npkts_rcvd_ 	= stat1.ps_recv;
		last_npkts_drops_	= stat1.ps_drop;
	}	

	return {npkts_received, npkts_kernel_drops};
}	

int PCAP_NET_CAP::loop_thread() noexcept
{
	int			ret;

	// Initialization : Call the Timeout handler
	try {
		if (timeoutcb_defined_) {
			next_timeout_sec_ = time(nullptr) + timeout_sec_;
			timeout_cb_(this);
		}
	}
	catch(...) {
	}	

	const auto pcapcb = [](uint8_t *parg, const struct pcap_pkthdr *phdr, const uint8_t *pframe) noexcept
	{
		PCAP_NET_CAP		*pthis = (PCAP_NET_CAP *)parg;
		struct timeval		tv_cap {phdr->ts.tv_sec, phdr->ts.tv_usec};

		try {
			pthis->callback_(pframe, phdr->caplen, phdr->len, pthis->linktype_, tv_cap);

			// Call timeout_cb_ if no timeouts seen due to continuous traffic
			if (pthis->next_timeout_sec_ > 0 && pthis->next_timeout_sec_ <= tv_cap.tv_sec) {

				pthis->next_timeout_sec_ = tv_cap.tv_sec + pthis->timeout_sec_;
				pthis->timeout_cb_(pthis);
			}	
		}
		catch(...) {
		}	
	};
		
	do {	
		ret = pcap_dispatch(pd_, ring_max_pkts_, pcapcb, (uint8_t *)this);
		
		if (ret == 0) {
			// Timeout
			if (next_timeout_sec_ > 0) { 
				time_t			tcur = time(nullptr);

				if (tcur >= next_timeout_sec_) {
					next_timeout_sec_ = tcur + timeout_sec_;

					try {
						timeout_cb_(this);
					}
					catch(...) {
					}	
				}	
			}
		}	
		else if (ret == PCAP_ERROR_BREAK) {
			// pcap_breakloop was called

			CAP_CMD_E		cmd = cap_cmd_.load(std::memory_order_acquire);
			bool			bret;

			if (cmd == CAP_CMD_RESTART) {
				INFOPRINT_OFFLOAD("pcap capture restart signalled for device %s...\n", ifname_);

				if (pd_) {
					pcap_close(pd_);
				}
				
				if (pfilter_code_) {
					pcap_freecode(pfilter_code_);
				}
				
				try {
					set_capture_params();
				}
				GY_CATCH_EXCEPTION(
					ERRORPRINT_OFFLOAD("pcap capture restart on device %s failed with an exception : %s : Exiting capture thread...\n", ifname_, GY_GET_EXCEPT_STRING);
					
					cap_cmd_.store(CAP_CMD_STOP);
					return -1;
				);

				ret = 0;
				continue;
			}	
			else if (cmd != CAP_CMD_STOP) {
				// Ignore 
				ret = 0;
				continue;
			}	
			else {
				return 0;
			}	
		}
		else if (ret < 0) {
			WARNPRINT_OFFLOAD("pcap capture on device %s failed : pcap read loop failed : %s\n", ifname_, pcap_geterr(pd_));

			cap_cmd_.store(CAP_CMD_STOP);
			return -1;
		}	
		else if (rcu_offline_after_read_) {
			gy_rcu_offline();
		}	
	} while (ret >= 0);

	return 0;
}	

} // namespace gyeeta
	
