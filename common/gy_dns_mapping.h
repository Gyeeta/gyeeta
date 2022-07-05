
#pragma 			once

#include			"gy_common_inc.h"
#include			"gy_netif.h"

#include 			<list>

namespace gyeeta {

class PCAP_NET_CAP;

class DNS_ENTRY
{
public :	
	RCU_HASH_CLASS_MEMBERS(GY_IP_ADDR, DNS_ENTRY);

	char			domain[MAX_DOMAINNAME_SIZE];
	GY_IP_ADDR		dstaddr;
	uint64_t		tusec_added {0};
	uint64_t		tusec_access {0};

	DNS_ENTRY(const char *pdns, const GY_IP_ADDR & ip, uint64_t tusec_add = get_usec_time()) noexcept 
		: dstaddr(ip), tusec_added(tusec_add), tusec_access(tusec_add)
	{
		GY_STRNCPY_0(domain, pdns, sizeof(domain));
	}	

	DNS_ENTRY() noexcept						= default;

	DNS_ENTRY(const DNS_ENTRY & other) noexcept			= default;
	DNS_ENTRY(DNS_ENTRY && other) noexcept				= default;
	DNS_ENTRY & operator= (const DNS_ENTRY & other) noexcept	= default;	
	DNS_ENTRY & operator= (DNS_ENTRY && other) noexcept		= default;
	
	~DNS_ENTRY()							= default;

	friend bool operator== (const DNS_ENTRY & lhs, const GY_IP_ADDR & rhs) noexcept
	{
		return lhs.dstaddr == rhs;
	}
};	

class DNS_MAPPING
{
public :	
	using DNS_MAPPING_HASH_TABLE 	= RCU_HASH_TABLE <GY_IP_ADDR, DNS_ENTRY>;

	static constexpr size_t		MAX_DNS_ENTRIES = 8192;
	static constexpr int		MAX_CAPTURE_INTERFACES = 16;
	static constexpr int		MAX_SAVED_DNS_ENTRIES = 512;

	static constexpr const char *	CAP_FILTER_STRING = "src port 53";

	DNS_MAPPING_HASH_TABLE		dnstable;

	std::list <std::unique_ptr<PCAP_NET_CAP>>	pcapture_list;

	uint64_t			tlast_added {0};
	time_t				tlast_check {0};

	char				save_entry_path[GY_PATH_MAX]	{};
	SCOPE_FD			fd_save_file;
	
	DNS_MAPPING(const char * save_entry_pathin = nullptr);

	~DNS_MAPPING()			= default;

	// Returns 0 if newly added, 1 if already present
	int add_dns_entry(const char *pdomain, const GY_IP_ADDR & addr) noexcept;

	// Returns 0 on success with pdomain updated
	template <typename LockType = RCU_LOCK_SLOW>
	bool get_domain_from_ip(const GY_IP_ADDR & addr, char *pdomain, size_t maxsz, uint64_t tusec = 0) noexcept
	{
		const uint32_t		hash = addr.get_hash();
		bool			bret;

		assert(pdomain);

		auto lambda_look = [pdomain, maxsz, tusec](DNS_ENTRY *pdatanode, void *arg1, void *arg2) noexcept -> CB_RET_E
		{
			GY_STRNCPY(pdomain, pdatanode->domain, maxsz);
			pdatanode->tusec_access = tusec ? tusec : get_usec_time();

			return CB_OK;
		};	

		bret = dnstable.template lookup_single_elem<decltype(lambda_look), LockType>(addr, hash, lambda_look);
		
		if (bret == true) {
			return true;
		}	
		
		*pdomain = '\0';

		return false;
	}	

	int process_dns_response(const uint8_t *pframe, uint32_t caplen, uint32_t origlen, int linktype, struct timeval tv_pkt) noexcept;

	int parse_dns_response(const uint8_t *pdata, uint32_t len, struct timeval tv_pkt) noexcept;	

	int check_for_deletion() noexcept;

	int check_new_bridge_masters() noexcept;

	int save_dns_to_file() noexcept;

	static int			init_singleton(const char * save_entry_pathin = nullptr);

	static DNS_MAPPING *		get_singleton() noexcept;
};
	
} // namespace gyeeta
	
