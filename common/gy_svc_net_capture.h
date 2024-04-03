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
#include			"gy_proto_parser.h"
#include			"gy_comm_proto.h"

namespace gyeeta {

class TCP_LISTENER;

using SvcInodeMap			= std::unordered_map<ino_t, std::vector<std::shared_ptr<TCP_LISTENER>>, GY_JHASHER<ino_t>>;
using GlobIDInodeMap			= std::unordered_map<ino_t, std::vector<std::pair<uint64_t, uint16_t>>, GY_JHASHER<ino_t>>;

class SVC_ERR_HTTP
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

	RCU_HASH_CLASS_MEMBERS(uint16_t, SVC_ERR_HTTP);

	std::shared_ptr<TCP_LISTENER> 		listenshr_;
	uint64_t				glob_id_			{0};
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
	bool					is_rootns_			{false};
	
	static constexpr bool			parse_api_calls_		{false};

	SVC_ERR_HTTP(std::shared_ptr<TCP_LISTENER> && listenshr, bool is_rootns, time_t tstart = time(nullptr)); 

	SVC_ERR_HTTP(const SVC_ERR_HTTP &)		= delete;
	SVC_ERR_HTTP(SVC_ERR_HTTP &&) noexcept		= default;
	
	SVC_ERR_HTTP & operator=(const SVC_ERR_HTTP &)	= delete;
	SVC_ERR_HTTP & operator=(SVC_ERR_HTTP &&)	= default;
	
	~SVC_ERR_HTTP() noexcept			= default;

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

class SVC_NET_CAPTURE;

class NETNS_HTTP_CAP1
{
public :
	using PortListenHashTbl		= RCU_HASH_TABLE <uint16_t, SVC_ERR_HTTP>;

	PortListenHashTbl		port_listen_tbl_	{32, 32, 0, false, false};
	ino_t				netinode_		{0};
	SVC_NET_CAPTURE			&svccap_;
	std::unique_ptr<SEQ_ERR_RETRAN>	retranchk_;
	time_t				tstart_ 		{0};
	time_t				tlast_check_ 		{0};
	int				nerror_retries_		{0};
	gy_atomic<uint16_t>		max_listen_port_	{0};
	gy_atomic<uint16_t>		min_listen_port_	{0};
	bool				is_rootns_		{false};
	bool				forcerestart_		{false};

	// Keep this field last
	std::unique_ptr<PCAP_NET_CAP>	netcap_;

	static constexpr bool		parse_api_calls_	{false};

	NETNS_HTTP_CAP1(ino_t netinode, SVC_NET_CAPTURE & svccap, bool is_rootns = false);

	uint32_t get_filter_string(STR_WR_BUF & strbuf); 

	void restart_capture();

	SVC_ERR_HTTP * find_svc_by_globid_locked(uint64_t globid, uint16_t port, bool & portused) const noexcept;

	std::pair<SVC_ERR_HTTP *, DirPacket> get_svc_from_tuple_locked(const GY_IP_ADDR & srcip, uint16_t srcport, const GY_IP_ADDR & dstip, uint16_t dstport) const noexcept;

	bool handle_req_err_locked(SVC_ERR_HTTP & svc, const GY_IP_ADDR & cliip, uint16_t cliport, const GY_TCP_HDR & tcp, const uint8_t *pdata, \
					uint32_t datalen, uint32_t caplen, struct timeval tv_pkt) const;

	bool handle_resp_err_locked(SVC_ERR_HTTP & svc, const GY_IP_ADDR & cliip, uint16_t cliport, const GY_TCP_HDR & tcp, const uint8_t *pdata, \
					uint32_t datalen, uint32_t caplen, struct timeval tv_pkt) const;

	void print_stats(uint32_t npkts_received, uint32_t npkts_kernel_drops) const noexcept
	{
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Service Error Capture Network Stats for Namespace %lu in last few minutes : "
					"%u packets %u drops #Listeners %lu Retransitted Errors %lu\n", 
					netinode_, npkts_received, npkts_kernel_drops, port_listen_tbl_.approx_count_fast(), 
					retranchk_ ? gy_diff_counter(retranchk_->nretrans_, retranchk_->last_nretrans_) : 0);
	}	
};

class SVC_API_PARSER
{
public :
	RCU_HASH_CLASS_MEMBERS(uint16_t, SVC_API_PARSER);

	std::shared_ptr<TCP_LISTENER> 		listenshr_;
	uint64_t				glob_id_		{0};
	time_t					tstart_			{0};
	time_t					tfirstreq_		{0};
	time_t					tfirstresp_		{0};
	std::shared_ptr<SVC_INFO_CAP>		svcinfocap_;
	uint16_t				serport_		{0};
	bool					is_rootns_		{false};
	
	static constexpr bool			parse_api_calls_	{true};

	SVC_API_PARSER(std::shared_ptr<TCP_LISTENER> && listenshr, bool is_rootns, time_t tstart = time(nullptr)); 

	SVC_API_PARSER(const SVC_API_PARSER &)			= delete;
	SVC_API_PARSER(SVC_API_PARSER &&) noexcept		= default;
	
	SVC_API_PARSER & operator=(const SVC_API_PARSER &)	= delete;
	SVC_API_PARSER & operator=(SVC_API_PARSER &&)		= default;
	
	~SVC_API_PARSER() noexcept				= default;

	void reset_stats(time_t tcurr) noexcept;

	bool operator== (uint16_t sport) const noexcept;

};	

class NETNS_API_CAP1
{
public :
	using PortListenHashTbl		= RCU_HASH_TABLE <uint16_t, SVC_API_PARSER>;

	PortListenHashTbl		port_listen_tbl_	{32, 32, 0, false, false};
	ino_t				netinode_		{0};
	SVC_NET_CAPTURE			&svccap_;
	time_t				tstart_ 		{0};
	time_t				tlast_check_ 		{0};

	STRING_BUFFER<128>		printbuf_;
	uint64_t			nmissed_total_		{0};
	mutable uint64_t		nlast_missed_		{0};
	int				nerror_retries_		{0};
	
	gy_atomic<uint16_t>		max_listen_port_	{0};
	gy_atomic<uint16_t>		min_listen_port_	{0};
	bool				is_rootns_		{false};
	bool				forcerestart_		{false};

	// Keep this field last
	std::unique_ptr<PCAP_NET_CAP>	netcap_;

	static constexpr bool		parse_api_calls_	{true};

	NETNS_API_CAP1(ino_t netinode, SVC_NET_CAPTURE & svccap, bool is_rootns = false);

	uint32_t get_filter_string(STR_WR_BUF & strbuf); 

	void restart_capture();

	SVC_API_PARSER * find_svc_by_globid_locked(uint64_t globid, uint16_t port, bool & portused) const noexcept;

	std::pair<SVC_API_PARSER *, DirPacket> get_svc_from_tuple_locked(const GY_IP_ADDR & srcip, uint16_t srcport, const GY_IP_ADDR & dstip, uint16_t dstport) const noexcept;

	inline void set_api_msghdr(std::optional<PARSE_PKT_HDR> & msghdr, const GY_IP_ADDR & cliip, const GY_IP_ADDR & serip, uint16_t cliport, uint16_t serport, \
					const GY_TCP_HDR & tcp, const uint8_t *pdata, uint32_t wirelen, uint32_t caplen, struct timeval tv_pkt, DirPacket dir) const noexcept;

	void print_stats(uint32_t npkts_received, uint32_t npkts_kernel_drops) const noexcept
	{
		char			buf1[128];

		std::memcpy(buf1, printbuf_.get(), sizeof(buf1) - 1);
		buf1[sizeof(buf1) - 1] = 0;

		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Service API Capture Network Stats for Namespace %lu and API Capture Services such as %s in last few minutes : "
					"%u packets, %u drops, %lu missed, %lu #Listeners (%lu Total missed)\n", 
					netinode_, buf1, npkts_received, npkts_kernel_drops, nmissed_total_ - nlast_missed_, port_listen_tbl_.approx_count_fast(), nmissed_total_);
		nlast_missed_ = nmissed_total_;
	}	
};


class SVC_NET_CAPTURE
{
public :
	using ErrNSMap				= std::unordered_map<ino_t, NETNS_HTTP_CAP1, GY_JHASHER<ino_t>>;
	using ApiNSMap				= std::unordered_map<ino_t, NETNS_API_CAP1, GY_JHASHER<ino_t>>;
	
	static constexpr uint32_t		MAX_NETNS_CAP_ERR 	{128};
	static constexpr uint32_t		MAX_NETNS_CAP_API 	{24};

	static constexpr uint32_t		MAX_NETNS_PORTS_ERR	{64};
	static constexpr uint32_t		MAX_NETNS_PORTS_API	{16};

	static constexpr uint32_t		MAX_SVC_API_CAP		{64};

private :
	ErrNSMap				errcodemap_;		// Map of captures for only http errors : To be accessed only from the errschedthr_
	ApiNSMap				apicallmap_;		// Map of captures for API calls : To be accessed only from the apischedthr_
	ino_t					rootnsid_		{0};		
	GY_SCHEDULER				errschedthr_		{true /* allow_catchup */};
	GY_SCHEDULER				apischedthr_		{true /* allow_catchup */};
	std::atomic<size_t>			last_errmapsize_	{0};
	std::atomic<size_t>			last_apimapsize_	{0};

public :
	COND_VAR<SCOPE_GY_MUTEX>		api_cond_;
	GY_THREAD				api_thr_;		

	/*
	 * For now, only a single API Parser thread. Change to array if increased to over 1...
	 */
	std::unique_ptr<API_PARSE_HDLR>		apihdlr_;		// Updated lazily on API capture start
	gy_atomic<uint32_t>			ncap_api_svc_		{0};
	uint32_t				api_max_len_		{0};
	gy_atomic<bool>				allow_api_cap_		{true};

	SVC_NET_CAPTURE(ino_t rootnsid, bool disable_api_capture = false, uint32_t api_max_len = 0);

	bool is_svc_cap_allowed(bool isapicall) const noexcept
	{
		if (isapicall == false) return last_errmapsize_.load(mo_acquire) < MAX_NETNS_CAP_ERR;

		return ncap_api_svc_.load(mo_acquire) < MAX_SVC_API_CAP && last_apimapsize_.load(mo_acquire) < MAX_NETNS_CAP_API;
	}

	bool sched_add_listeners(uint64_t start_after_msec, const char *name, SvcInodeMap && nslistmap, bool isapicall);
	
	bool sched_add_listener(uint64_t start_after_msec, const char *name, ino_t inode, std::shared_ptr<TCP_LISTENER> svcshr, bool isapicall);

	bool sched_del_listeners(uint64_t start_after_msec, const char *name, GlobIDInodeMap && nslistmap, bool onlyapi = false);

	bool sched_del_one_listener(uint64_t start_after_msec, uint64_t glob_id, ino_t inode, uint16_t port, bool onlyapi) noexcept;

	bool sched_svc_ssl_probe(const char *name, std::weak_ptr<TCP_LISTENER> svcweak);

	bool sched_svc_ssl_stop(const char *name, uint64_t glob_id) noexcept;

	bool send_api_cap_status(comm::REQ_TRACE_STATUS *preq, size_t nreq);

	MAKE_CLASS_FUNC_WRAPPER_NO_ARG(SVC_NET_CAPTURE, api_parse_thread);

	int api_parse_thread() noexcept;

	void init_api_cap_handler();

	void handle_uprobe_cb(void *pdata, int data_size);

	GY_SCHEDULER & get_api_scheduler() noexcept
	{
		return apischedthr_;
	}	

	GY_SCHEDULER & get_err_scheduler() noexcept
	{
		return errschedthr_;
	}	

	API_PARSE_HDLR * get_api_handler(size_t parseridx) noexcept
	{
		/*
		 * For now, only a single API Handler...
		 */
		if (parseridx == 0) {
			return apihdlr_.get();
		}	

		return nullptr;
	}	
	
	static void svc_ssl_probe_cb(void *pcb_cookie, void *pdata, int data_size) noexcept;

	static SVC_NET_CAPTURE *		get_singleton() noexcept;

private :

	void add_err_listeners(SvcInodeMap & nslistmap) noexcept;
	void del_err_listeners(const GlobIDInodeMap & nslistmap) noexcept;

	void add_api_listeners(SvcInodeMap & nslistmap) noexcept;
	void del_api_listeners(const GlobIDInodeMap & nslistmap) noexcept;

	void check_netns_err_listeners() noexcept;
	void check_netns_api_listeners(const bool sendstatus) noexcept;
};	


} // namespace gyeeta

