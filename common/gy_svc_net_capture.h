//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"
#include			"gy_scheduler.h"
#include			"gy_rcu_inc.h"
#include			"gy_network_capture.h"
#include			"gy_net_parse.h"
#include			"gy_stack_container.h"
#include			"gy_misc.h"

namespace gyeeta {

class TCP_LISTENER;

using SvcInodeMap			= std::unordered_map<ino_t, std::vector<std::shared_ptr<TCP_LISTENER>>, GY_JHASHER<ino_t>>;
using GlobIDInodeMap			= std::unordered_map<ino_t, std::vector<std::pair<uint64_t, uint16_t>>, GY_JHASHER<ino_t>>;

enum class DirPacket : uint8_t
{
	DIR_UNKNOWN		= 0,

	DIR_INBOUND		= 1,	/* Inbound to a Service i.e. From Client to Server */
	DIR_OUTBOUND		= 2,	/* Outbound : From Server to Client */
};	


class SVC_CAP_ONE
{
public :
	struct SessInfo
	{
		uint32_t			exp_cli_seq_;
		uint32_t			exp_ser_seq_;
		uint16_t			cli_ip_hash2_;	
		uint16_t			cli_port_;
		uint16_t			last_pkt_sec_;
		bool				is_syn_sess_ : 1;
		bool				last_tcp_syn_ : 1;
		bool				init_http1_req_ : 1;
		bool				init_http2_req_ : 1;
		bool				last_http1_req_ : 1;
		bool				last_http1_req_maybe_ : 1;
		bool				last_http2_req_ : 1;
		bool				init_other_req_ : 1;
		bool				last_other_req_ : 1;
		bool				init_resp_pend_ : 1;
		bool				last_pkt_resp_ : 1;
		bool				req_seen_ : 1;
		bool				http2_seen_ : 1;
	};	

	static constexpr size_t			MaxCliHash			{0xF};

	RCU_HASH_CLASS_MEMBERS(uint16_t, SVC_CAP_ONE);

	std::shared_ptr<TCP_LISTENER> 		listenshr_;
	time_t					tstart_				{0};
	time_t					tfirstreq_			{0};
	time_t					tfirstresp_			{0};
	SessInfo				sesscache_[MaxCliHash + 1]	{};
	uint32_t				nconfirm_web_			{0};
	uint32_t				nconfirm_noweb_			{0};		
	uint32_t				nmaybe_noweb_			{0};		
	uint32_t				npkts_data_			{0};		// Only updated if nconfirm_web_ == 0
	uint16_t				serport_			{0};
	uint8_t					nsess_chks_			{0};
	tribool					is_http2_			{indeterminate};
	bool					web_confirm_			{false};
	bool					parse_api_calls_		{false};
	bool					is_rootns_			{false};
	
	SVC_CAP_ONE(std::shared_ptr<TCP_LISTENER> && listenshr, bool parse_api_calls, bool is_rootns, time_t tstart = time(nullptr)) noexcept; 

	SVC_CAP_ONE(const SVC_CAP_ONE &)		= delete;
	SVC_CAP_ONE(SVC_CAP_ONE &&) noexcept		= default;
	
	SVC_CAP_ONE & operator=(const SVC_CAP_ONE &)	= delete;
	SVC_CAP_ONE & operator=(SVC_CAP_ONE &&)		= default;
	
	~SVC_CAP_ONE() noexcept				= default;

	SessInfo * get_session_inbound(const GY_IP_ADDR & cliip, uint16_t cliport, const GY_TCP_HDR & tcp, time_t tpkt) noexcept;

	SessInfo * get_session_outbound(const GY_IP_ADDR & cliip, uint16_t cliport, const GY_TCP_HDR & tcp, time_t tpkt) noexcept;
	
	static inline uint16_t get_port_hash(uint16_t cliport) noexcept
	{
		return (cliport >> 1) & MaxCliHash;
	}

	static inline uint16_t get_ip_hash(const GY_IP_ADDR & ip) noexcept
	{
		uint8_t			abuf[32];
		ssize_t			sz = ip.get_as_inaddr(abuf);

		return (abuf[sz - 2] << 8) | abuf[sz - 1];
	}	

	void reset_stats(time_t tcurr) noexcept;

	bool operator== (uint16_t sport) const noexcept;
};	

/*
 * Check for retransmits to skip multiple errors due to retransmits on 'any' interface captures.
 * Currently we enable this check only on root Network Namespace. 
 * XXX Revisit this logic if needed on other NetNs...
 */
class SEQ_ERR_RETRAN
{
public :
	struct SeqErrOne
	{
		uint32_t		ser_seq_		{0};
		uint16_t		cli_seq_		{0};
		uint16_t		cli_port_		{0};

		SeqErrOne(uint32_t ser_seq, uint32_t cli_seq, uint16_t cli_port) noexcept
			: ser_seq_(ser_seq), cli_seq_(cli_seq), cli_port_(cli_port)
		{}	

		bool operator== (SeqErrOne other) const noexcept
		{
			return std::memcmp(this, &other, sizeof(*this));
		}	

		struct HashOne
		{
			uint64_t operator()(SeqErrOne key) const noexcept
			{
				uint64_t		lkey;

				std::memcpy(&lkey, &key, sizeof(lkey));

				return get_uint64_hash(lkey);
			}
		};	
	};	
	
	static constexpr size_t		MaxSetEntries		{1024};

	using SeqErrHashSet		= INLINE_STACK_HASH_SET<SeqErrOne, MaxSetEntries * sizeof(SeqErrOne) * 3 + 512, SeqErrOne::HashOne>;

	SeqErrHashSet			set0_			{MaxSetEntries};
	SeqErrHashSet			set1_			{MaxSetEntries};
	uint64_t			nretrans_		{0};
	uint64_t			last_nretrans_		{0};
	bool				curr0_			{true};

	bool is_retranmit(uint32_t ser_seq, uint32_t cli_seq, uint16_t cli_port) noexcept;
};	

class NETNS_CAP_ONE
{
public :
	using PortListenHashTbl		= RCU_HASH_TABLE <uint16_t, SVC_CAP_ONE>;

	PortListenHashTbl		port_listen_tbl_	{32, 32, 0, false, false};
	ino_t				netinode_		{0};
	std::unique_ptr<PCAP_NET_CAP>	netcap_;
	std::unique_ptr<SEQ_ERR_RETRAN>	retranchk_;
	time_t				tstart_ 		{0};
	time_t				tlast_check_ 		{0};
	int				nerror_retries_		{0};
	uint32_t 			last_npkts_rcvd_	{0};
	uint32_t			last_npkts_drops_ 	{0};
	gy_atomic<uint16_t>		max_listen_port_	{0};
	gy_atomic<uint16_t>		min_listen_port_	{0};
	bool				parse_api_calls_	{false};
	bool				is_rootns_		{false};
	bool				forcerestart_		{false};

	NETNS_CAP_ONE(ino_t netinode, std::vector<std::shared_ptr<TCP_LISTENER>> & veclist, bool parse_api_calls, bool is_rootns = false);

	uint32_t get_filter_string(STR_WR_BUF & strbuf); 

	void restart_capture();

	SVC_CAP_ONE * find_svc_by_globid_locked(uint64_t globid, uint16_t port, bool & portused) const noexcept;

	std::pair<SVC_CAP_ONE *, DirPacket> get_svc_from_tuple_locked(const GY_IP_ADDR & srcip, uint16_t srcport, const GY_IP_ADDR & dstip, uint16_t dstport) const noexcept;

	int process_pkt(const uint8_t *pframe, uint32_t caplen, uint32_t origlen, int linktype, struct timeval tv_pkt) const noexcept;
	
	bool handle_req_err_locked(SVC_CAP_ONE & svc, const GY_IP_ADDR & cliip, uint16_t cliport, const GY_TCP_HDR & tcp, const uint8_t *pdata, \
					uint32_t datalen, uint32_t caplen, struct timeval tv_pkt) const;

	bool handle_resp_err_locked(SVC_CAP_ONE & svc, const GY_IP_ADDR & cliip, uint16_t cliport, const GY_TCP_HDR & tcp, const uint8_t *pdata, \
					uint32_t datalen, uint32_t caplen, struct timeval tv_pkt) const;

	static tribool check_http1_req(const uint8_t *pdata, uint32_t caplen, uint32_t datalen) noexcept;

	static bool get_http1_status_resp(const uint8_t *pdata, uint32_t caplen, bool & is_cli_err, bool & is_ser_err) noexcept;

};

class SVC_NET_CAPTURE
{
public :
	using NetNSMap			= std::unordered_map<ino_t, NETNS_CAP_ONE, GY_JHASHER<ino_t>>;

	static constexpr uint32_t	MAX_NETNS_CAP 		{128};
	static constexpr uint32_t	MAX_NETNS_PORTS		{64};

private :
	NetNSMap			errcodemap_;		// Map of captures for only http errors : To be accessed only from the schedthr_
	NetNSMap			apicallmap_;		// Map of captures for API calls & errors : To be accessed only from the schedthr_
	ino_t				rootnsid_		{0};		
	GY_SCHEDULER			schedthr_		{true /* allow_catchup */};

public :
	SVC_NET_CAPTURE(ino_t rootnsid);

	bool listen_cap_allowed(bool isapicall = false) const noexcept
	{
		if (isapicall == false) return errcodemap_.size() < MAX_NETNS_CAP;
		return apicallmap_.size() < MAX_NETNS_CAP;
	}

	bool sched_add_listeners(uint64_t start_after_msec, const char *name, SvcInodeMap && nslistmap, bool isapicallmap);

	bool sched_del_listeners(uint64_t start_after_msec, const char *name, GlobIDInodeMap && nslistmap);

private :

	void add_listeners(SvcInodeMap & nslistmap, bool isapicallmap) noexcept;

	void del_listeners(const GlobIDInodeMap & nslistmap) noexcept;

	void check_netns_listeners() noexcept;

	void print_netns_stats(NetNSMap & cmap, const char * prefix) const noexcept;
};	


} // namespace gyeeta

