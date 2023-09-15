//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma 			once

#include			"gy_common_inc.h"

#include 			"folly/Function.h"

struct pcap;
struct bpf_program;

namespace gyeeta {

class PCAP_NET_CAP
{
public :	
	enum CAP_CMD_E : uint8_t
	{
		CAP_CMD_NONE		= 0,
		CAP_CMD_START,
		CAP_CMD_STOP,
		CAP_CMD_RESTART,
	};

	using CBType			= folly::Function<void(const uint8_t * pframe, uint32_t caplen, uint32_t origlen, int linktype, struct timeval tv_cap)>;
	using TimeoutType		= folly::Function<void(const PCAP_NET_CAP *)>;

	pcap				*pd_ 			{nullptr};
	pthread_t			loop_tid_ 		{0};

	CBType		 		callback_;
	TimeoutType			timeout_cb_;
	time_t				next_timeout_sec_	{0};

	mutable uint32_t 		last_npkts_rcvd_	{0};
	mutable uint32_t		last_npkts_drops_ 	{0};

	int				linktype_ 		{0};
	char				ifname_[32] 		{};

	int				timeout_sec_		{1};
	int				ring_max_pkts_ 		{-1};
	uint32_t			cap_bufsize_		{4 * 1024 * 1024};
	uint32_t			cap_snaplen_		{8192};	
	bool				use_promiscuous_;
	bool				rcu_offline_after_read_	{false};
	bool				timeoutcb_defined_	{false};

private :	
	bpf_program			*pfilter_code_		{nullptr};
	GY_MUTEX			filtmutex_;
	std::string			filter_string_;
		
	time_t				tstart_ 		{0}; 
	std::atomic<CAP_CMD_E>		cap_cmd_ 		{CAP_CMD_NONE};

public :
	/*
	 * The callback func is called for each packet.
	 * The timeout_cb is called at start of Capture thread run and then at every timeout_msec.
	 */
	PCAP_NET_CAP(const char *devname, const char * filterstr, uint32_t filterlen,
			folly::Function<void(const uint8_t * pframe, uint32_t caplen, uint32_t origlen, int linktype, struct timeval tv_cap)> && callback, 
			uint32_t buffersize = 4 * 1024 * 1024, uint32_t snaplen = 8192, bool use_promiscuous = true, size_t thr_stacksz = 128 * 1024, \
			int timeout_sec = 1, folly::Function<void(const PCAP_NET_CAP *)> && timeout_cb = {}, int ring_max_pkts = -1, bool rcu_offline_after_read = false);

	PCAP_NET_CAP(const PCAP_NET_CAP &)			= delete;
	PCAP_NET_CAP(PCAP_NET_CAP &&)				= delete;

	~PCAP_NET_CAP();
	
	bool is_capture_active() const noexcept
	{
		return (cap_cmd_.load(std::memory_order_relaxed) == CAP_CMD_START);
	}	

	// Not thread safe. If multiple writers please use an external mutex
	void restart_capture_signal(const char *newfilter, size_t lenfilter, uint32_t buffersize = 0, uint32_t snaplen = 0);

	// Returns difference between last and current stats. Needs to be called periodically externally if stats needed
	std::pair<uint32_t, uint32_t> update_pcap_stats() const noexcept;

	int loop_thread() noexcept;

	MAKE_CLASS_FUNC_WRAPPER_NO_ARG(PCAP_NET_CAP, loop_thread);

private :
	void set_capture_params();	
};	 


} // namespace gyeeta

