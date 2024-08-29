//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"
#include			"gy_pcap_read.h"

namespace gyeeta {

class API_PARSE_HDLR;

class PSEUDO_PCAP_CAP
{
public :
	using IPPortMap			= std::unordered_map<IP_PORT, uint16_t, IP_PORT::ONLY_PORT, IP_PORT::ONLY_PORT>;
	
	char				filepath_[GY_PATH_MAX];
	uint64_t			netns_				{0};
	int				nrepeats_			{0};
	float				comp_rate_			{0};
	bool				del_on_end_			{false};

	API_PARSE_HDLR			& apihdlr_;
	uint64_t			tactstartus_			{0};
	uint64_t			tpcapstartus_			{0};
	float				delay_multiplier_		{0};
	IPPortMap			ipportmap_;
	PCAP_READER			rdpcap_;
	std::unique_ptr<GY_THREAD>	pthr_;

	struct Stats
	{
		uint64_t		npkts_				{0};
		uint64_t		nskipped_			{0};
		uint64_t		nother_server_			{0};
		uint64_t		npool_skip_			{0};

		void reset() noexcept
		{
			std::memset(this, 0, sizeof(*this));
		}	
	};

	Stats				stats_;
	
	PSEUDO_PCAP_CAP(const char *filepath, const IP_PORT *pcap_ip_port_arr, const uint16_t *pact_port_arr, uint32_t narrelem, uint64_t netns, API_PARSE_HDLR & apihdlr, \
					int nrepeats, float comp_rate, bool delete_object_on_end);
	
	MAKE_CLASS_FUNC_WRAPPER_NO_ARG(PSEUDO_PCAP_CAP, pcap_rd_thread);

	int pcap_rd_thread() noexcept;

	int send_pkt(const uint8_t *pframe, uint32_t caplen, uint32_t origlen, int linktype, struct timeval tv_pkt) noexcept;
	
	void sleep_per_pkt(const struct timeval & pcap_tv) noexcept;
};	

} // namespace gyeeta

