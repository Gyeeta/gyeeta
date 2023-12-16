//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma 			once

#include			"gy_common_inc.h"
#include 			"gy_net_parse.h"

namespace gyeeta {

/*
 * Class to create a pcap using data obtained from diverse sources e.g. from ebpf captures. 
 * The outout pcap will be of Raw IP format with no Ethernet headers,
 */
class GY_PCAP_WRITER
{
public :
	// maxsize checks are not atomic...
	explicit GY_PCAP_WRITER(const char *outputfile, bool use_unlocked_io = true, bool throw_if_exists = true, size_t maxsize = ~0ul);
	
	bool write_tcp_pkt(struct timeval tv, const GY_IP_ADDR & cip, const GY_IP_ADDR &dip, uint16_t cport, uint16_t dport, uint32_t seq, uint32_t ack, 
				uint8_t tcpflags, const void *pdata, uint16_t datalen) noexcept;

	bool write_udp_pkt(struct timeval tv, const GY_IP_ADDR & cip, const GY_IP_ADDR &dip, uint16_t cport, uint16_t dport, const void *pdata, uint16_t datalen) noexcept;

	// Returns { npkts, nbytes, start time of pcap }
	std::tuple<size_t, size_t, time_t> get_stats() const noexcept
	{
		return {npkts_, nwritten_, tstart_};
	}	

	const char * get_filename() const noexcept
	{
		return filename_.data();
	}	

	int flush_file() noexcept
	{
		return fflush(sfile_.get());
	}	

protected :

	SCOPE_FILE			sfile_;

	size_t				nwritten_		{0};
	size_t				npkts_			{0};
	const size_t			maxsize_;
	const time_t			tstart_			{time(nullptr)};
	
	const std::string		filename_;
};	

} // namespace gyeeta

