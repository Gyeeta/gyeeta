
#pragma			once

#include		"gy_common_inc.h"
#include		<vector>
#include		<map>

#include		"gy_file_api.h"
#include		"gy_misc.h"
#include		"gy_rcu_inc.h"
#include		"gy_inet_inc.h"

#include		"folly/memory/EnableSharedFromThis.h"

#include		<arpa/inet.h>
#include 		<libmnl/libmnl.h>
#include 		<linux/if.h>

#include 		"if_link_gy.h"

#include 		<linux/rtnetlink.h>
#include 		<netinet/in.h>

namespace gyeeta {

static constexpr int			IF_MAX_LEN_64 = 64;

enum GY_IF_INFO_E
{
	IF_INFO_NONE			= 0,
	IF_INFO_LOOPBACK		= 1 << 0,
	IF_INFO_ETHERNET		= 1 << 1,
	IF_INFO_TUNNEL			= 1 << 2,		// Valid for IPIP, GRE, GRE6, SIT
	IF_INFO_INFINIBAND		= 1 << 3,
	IF_INFO_FC			= 1 << 4,
	IF_INFO_VSOCK			= 1 << 5,

	IF_INFO_MASTER			= 1 << 8,
	IF_INFO_SLAVE			= 1 << 9,

	IF_INFO_BONDING			= 1 << 10,
	IF_INFO_BRIDGE			= 1 << 11,
	IF_INFO_VLAN_BRIDGE		= 1 << 12,		// MacVLAN / IPVLan
	IF_INFO_VRF_DEV			= 1 << 13,

	IF_INFO_PHY_LINK		= 1 << 14,
	IF_INFO_VF_SRIOV		= 1 << 15,

	IF_INFO_TUNNEL_IPIP		= 1 << 16,
	IF_INFO_TUNNEL_GRE		= 1 << 17,
	IF_INFO_TUNNEL_SIT		= 1 << 18,
	IF_INFO_TUNNEL_VXLAN		= 1 << 19,
	IF_INFO_TUNNEL_GENEVE		= 1 << 20,

	IF_INFO_XDP			= 1 << 21,

	IF_INFO_DUMMY			= 1 << 31,
};

enum IF_KIND_TYPE_E 
{
	IF_KIND_NONE			= 0,
	IF_KIND_IPVLAN,
	IF_KIND_VTI,
	IF_KINF_VTI6,
	IF_KIND_IP6GRE,
	IF_KIND_MACSEC,
	IF_KIND_IPIP,
	IF_KIND_IP6TNL,
	IF_KIND_IFB,
	IF_KIND_VETH,
	IF_KIND_SIT,
	IF_KIND_MACVTAP,
	IF_KIND_MACVLAN,
	IF_KIND_BRIDGE_MASTER,
	IF_KIND_BRIDGE_SLAVE,
	IF_KIND_VXCAN,
	IF_KIND_BOND_MASTER,
	IF_KIND_BOND_SLAVE,
	IF_KIND_HSR,
	IF_KIND_VCAN,
	IF_KIND_VXLAN,
	IF_KIND_TEAM_MASTER,
	IF_KIND_IPOIB,
	IF_KIND_GENEVE,
	IF_KIND_IP6GRETAP,
	IF_KIND_VRF_MASTER,
	IF_KIND_VRF_SLAVE,
	IF_KIND_TEAM_SLAVE,
};	

enum IF_XDP_TYPE_E 
{
	IF_XDP_NONE			= 0,
	IF_XDP_DRV,
	IF_XDP_SKB,
	IF_XDP_HW,
};

int get_if_info_from_type(uint16_t ifi_type, char *pbuf, size_t szbuf, uint32_t & infomask) noexcept;
int get_bond_slave_ids(int sysfs_dir_fd, const char *pbond, std::vector<int> & vec) noexcept;

class IF_LINK;

class IF_LINK_BOND_MASTER
{
public :	
	enum IF_BOND_MODE_E 
	{
		BOND_BALANCE_RR		= 0,
		BOND_ACTIVE_BACKUP,
		BOND_BALANCE_XOR,
		BOND_BROADCAST,
		BOND_LINK_AGGR_802,
		BOND_BALANCE_TLB,
		BOND_BALANCE_ALB,
	};	

	uint8_t					mode { BOND_BALANCE_RR };

	int					active_slave_ifi_index {0};
	std::weak_ptr <IF_LINK>			active_slave_shr;

	int					primary_ifi_index {0};
	std::weak_ptr <IF_LINK>			primary_ifi_shr;

	uint32_t				all_slaves_active {0};
	uint32_t				min_links {0};
	uint32_t				rr_packets_per_slave {0};

	std::vector <int>			slaves_index_vec;
	std::vector <std::weak_ptr<IF_LINK>>	slaves_shr_vec;

	IF_LINK_BOND_MASTER()	noexcept	= default;

	IF_LINK_BOND_MASTER(const IF_LINK_BOND_MASTER & other)
		: mode(other.mode), 
		active_slave_ifi_index(other.active_slave_ifi_index), active_slave_shr(other.active_slave_shr),
		primary_ifi_index(other.primary_ifi_index), primary_ifi_shr(other.primary_ifi_shr),
		all_slaves_active(other.all_slaves_active), min_links(other.min_links), rr_packets_per_slave(other.rr_packets_per_slave),
		slaves_index_vec(other.slaves_index_vec), slaves_shr_vec(other.slaves_shr_vec)
	{ }	

	int update_on_change(IF_LINK_BOND_MASTER && other) noexcept
	{
		int				nupd = 0;
	
		if (mode != other.mode) {
			mode = other.mode;
			nupd++;	
		}	 	

		if (active_slave_ifi_index != other.active_slave_ifi_index) {
			active_slave_ifi_index = other.active_slave_ifi_index;
			active_slave_shr = std::move(other.active_slave_shr);
			nupd++;
		}	

		if (primary_ifi_index != other.primary_ifi_index) {
			primary_ifi_index = other.primary_ifi_index;
			primary_ifi_shr = std::move(other.primary_ifi_shr);
			nupd++;
		}	

		if (all_slaves_active != other.all_slaves_active) {
			all_slaves_active = other.all_slaves_active;
			nupd++;
		}	

		if (min_links != other.min_links) {
			min_links = other.min_links;
			nupd++;
		}	

		if (rr_packets_per_slave != other.rr_packets_per_slave) {
			rr_packets_per_slave = other.rr_packets_per_slave;
			nupd++;
		}	
		
		if (slaves_index_vec != other.slaves_index_vec) {
			slaves_index_vec = std::move(other.slaves_index_vec);
			slaves_shr_vec = std::move(other.slaves_shr_vec);

			nupd++;
		}	

		return nupd;
	}	
};	

class IF_LINK_BOND_SLAVE
{
public :	
	enum BOND_SLAVE_STATE_E {
		BOND_SLAVE_STATE_ACTIVE	= 0,
		BOND_SLAVE_STATE_BACKUP,
	};	

	uint8_t				state { BOND_SLAVE_STATE_BACKUP };
	bool				mii_status_up { false };
	
	/*
	 * master_ifi_shr will contain the shared_ptr to bonding_master
	 */
	int update_on_change(IF_LINK_BOND_SLAVE && other) noexcept
	{
		int			nupd = 0;
	
		if (state != other.state) {
			state = other.state;
			nupd++;	
		}	 	

		if (mii_status_up != other.mii_status_up) {
			mii_status_up = other.mii_status_up;
			nupd++;	
		}	 	
		return nupd;
	}	
};	

class IF_LINK_GENEVE
{
public :	
	GY_IP_ADDR			remote_addr;
	GY_IP_ADDR			remote_addr_6;
	uint16_t			dstport {0};

	int update_on_change(IF_LINK_GENEVE && other) noexcept
	{
		int			nupd = 0;
	
		if (!(remote_addr == other.remote_addr)) {
			remote_addr = other.remote_addr;
			nupd++;	
		}	 	

		if (!(remote_addr_6 == other.remote_addr_6)) {
			remote_addr_6 = other.remote_addr_6;
			nupd++;	
		}	 	

		if (dstport != other.dstport) {
			dstport = other.dstport;
			nupd++;
		}	

		return nupd;
	}	
};

class IF_LINK_IPVLAN
{
public :	
	enum IPVLAN_FLAGS_E 
	{
		IF_IPVLAN_PRIVATE	= 1,
		IF_IPVLAN_VEPA,
		IF_IPVLAN_BRIDGE,
	};

	uint16_t			mode { IPVLAN_MODE_L2 };
	uint16_t			ipvflags { IF_IPVLAN_VEPA };

	int update_on_change(IF_LINK_IPVLAN && other) noexcept
	{
		int			nupd = 0;
	
		if (mode != other.mode) {
			mode = other.mode;
			nupd++;	
		}	 	

		if (ipvflags != other.ipvflags) {
			ipvflags = other.ipvflags;
			nupd++;	
		}	 	

		return nupd;
	}	
};	

class IF_LINK_MACVLAN_TAP
{
public :	
	uint32_t			mode { MACVLAN_MODE_BRIDGE };

	int update_on_change(IF_LINK_MACVLAN_TAP && other) noexcept
	{
		int			nupd = 0;
	
		if (mode != other.mode) {
			mode = other.mode;
			nupd++;	
		}	 	
		return nupd;
	}	
};	

class IF_LINK_VRF
{
public :	
	uint32_t			vrf_table {0};

	int update_on_change(IF_LINK_VRF && other) noexcept
	{
		int			nupd = 0;
	
		if (vrf_table != other.vrf_table) {
			vrf_table = other.vrf_table;
			nupd++;	
		}	 	
		return nupd;
	}	
};	

class IF_LINK_BRIDGE
{
public :	
	uint16_t			priority {0};

	int update_on_change(IF_LINK_BRIDGE && other) noexcept
	{
		int			nupd = 0;
	
		if (priority != other.priority) {
			priority = other.priority;
			nupd++;	
		}	 	
		return nupd;
	}	
};	

class IF_LINK_VXLAN
{
public :	
	GY_IP_ADDR			remote_addr;
	GY_IP_ADDR			remote_addr_6;

	GY_IP_ADDR			local_addr;
	GY_IP_ADDR			local_addr_6;

	std::weak_ptr<IF_LINK>		device_shr;
	int				device_id {0};

	uint16_t			dstport {0};

	int update_on_change(IF_LINK_VXLAN && other) noexcept
	{
		int			nupd = 0;
	
		if (!(remote_addr == other.remote_addr)) {
			remote_addr = other.remote_addr;
			nupd++;	
		}	 	

		if (!(remote_addr_6 == other.remote_addr_6)) {
			remote_addr_6 = other.remote_addr_6;
			nupd++;	
		}	 	

		if (!(local_addr == other.local_addr)) {
			local_addr = other.local_addr;
			nupd++;	
		}	 	

		if (!(local_addr_6 == other.local_addr_6)) {
			local_addr_6 = other.local_addr_6;
			nupd++;	
		}	 	

		if (device_id != other.device_id) {
			device_id = other.device_id;
			device_shr = std::move(other.device_shr);
			nupd++;
		}
			
		if (dstport != other.dstport) {
			dstport = other.dstport;
			nupd++;
		}	

		return nupd;
	}	
};	

enum IF_SCOPE_E
{
	IF_SCOPE_UNIVERSAL		= 0,
	IF_SCOPE_LINK,
	IF_SCOPE_HOST,
	IF_SCOPE_SITE,

	IF_SCOPE_ANY			= 100,
};
	
class IF_LINK;

using 	NET_IF_ELEM_TYPE 		= RCU_HASH_WRAPPER <int, std::shared_ptr<IF_LINK>>;
using 	NET_IF_HASH_TABLE 		= RCU_HASH_TABLE <int, NET_IF_ELEM_TYPE>;
	
class IF_LINK : public folly::enable_shared_from_this <IF_LINK>
{
public :	
	int				ifi_index {0};
	uint16_t			ifi_type {0};
	char				ifname[IFNAMSIZ] {};
	uint32_t			ifi_flags {0};

	char				iftype_str[IF_MAX_LEN_64] {};
	uint32_t			infomask {0};
	
	int				master_ifi_index {0};
	std::weak_ptr<IF_LINK>		master_ifi_shr;			// Access only after kind_mutex locked

	int				link_ifi_index {0};
	std::weak_ptr<IF_LINK>		link_ifi_shr;			// Access only after kind_mutex locked

	uint8_t				hw_addr[IF_MAX_LEN_64] {};
	uint8_t				hw_addr_len {0};
	uint32_t			mtu {0};

	uint8_t				broadcast_addr[IF_MAX_LEN_64] {};
	uint8_t				broadcast_len {0};

	mutable GY_MUTEX		kind_mutex;

	char				if_kind_str[IF_MAX_LEN_64] {};
	IF_KIND_TYPE_E			if_kind { IF_KIND_NONE };

	union {
		IF_LINK_BOND_MASTER	*pbond_master		{nullptr};
		IF_LINK_BOND_SLAVE	*pbond_slave;
		IF_LINK_BRIDGE		*pbridge_master;
		IF_LINK_BRIDGE		*pbridge_slave;
		IF_LINK_GENEVE		*pgeneve;	
		IF_LINK_IPVLAN		*pipvlan;
		IF_LINK_MACVLAN_TAP	*pmacvlan;
		IF_LINK_VRF		*pvrf_master;
		IF_LINK_VRF		*pvrf_slave;
		IF_LINK_VXLAN		*pvxlan;
	}; 

	char				qdisc[IF_MAX_LEN_64] {};
	
	uint8_t				xdp_type {IF_XDP_NONE};

	uint32_t			ntx_queues {0};	
	uint32_t			nrx_queues {0};

	uint32_t			gso_max_size {0};
	uint32_t			gso_max_segs {0};

	uint32_t			num_vf_sriov {0};

	int				speed_mbps {0};
	std::atomic<int>		observed_speed_mbps {0};

	uint64_t			if_add_usec_time	{get_usec_time()};

	std::atomic <uint64_t>		last_chk_usec_time	{if_add_usec_time};

	ino_t				netns_inode {0};

	union {
		uint64_t		flags 	{0};
			
		struct {
			bool			is_if_up : 1;
			bool			is_carrier : 1;
			bool			is_lower_up : 1;
			bool			is_operstate_up : 1;
			bool			is_if_broadcast : 1;
			bool			is_if_loopback : 1;
			bool			is_point_to_point : 1;
			bool			is_promiscuous : 1;
			bool			is_master : 1;
			bool			is_slave : 1;

			bool			is_ethernet : 1;
			bool			is_infiniband : 1;
			bool			is_tunnel : 1;
			bool			is_ipip_tunnel : 1;
			bool			is_gre_tunnel : 1;
			bool			is_sit_tunnel : 1;
			bool			is_geneve_tunnel : 1;
			bool			is_vxlan_tunnel : 1;
			bool			is_fiberchannel : 1;
			bool			is_vsock : 1;
			bool			is_bridge : 1;
			bool			is_bonding : 1;
			bool			is_xdp : 1;
			bool			is_vlan : 1;
			bool			is_sriov : 1;

			bool			is_hw_addr_ipv4 : 1;	
			bool			is_hw_addr_ipv6 : 1;
		};
	};	

	struct {
		GY_IP_ADDR		univeral_ipv6;
		GY_IP_ADDR		site_ipv6;
		GY_IP_ADDR		link_ipv6;
		GY_IP_ADDR		host_ipv6;

		GY_IP_ADDR		univeral_ipv4;
		GY_IP_ADDR		link_ipv4;
		GY_IP_ADDR		host_ipv4;

		char * print_info_str(STR_WR_BUF & strbuf) const noexcept
		{
			char			tbuf[256];

			if (univeral_ipv6.is_valid_ip()) {
				strbuf.appendfmt("Universal IPv6 Address %s, ", univeral_ipv6.printaddr(tbuf, sizeof(tbuf) - 1));
			}	

			if (link_ipv6.is_valid_ip()) {
				strbuf.appendfmt("Link Level IPv6 Address %s, ", link_ipv6.printaddr(tbuf, sizeof(tbuf) - 1));
			}	

			if (host_ipv6.is_valid_ip()) {
				strbuf.appendfmt("Host Scope IPv6 Address %s, ", host_ipv6.printaddr(tbuf, sizeof(tbuf) - 1));
			}	

			if (site_ipv6.is_valid_ip()) {
				strbuf.appendfmt("Site Scope IPv6 Address %s, ", site_ipv6.printaddr(tbuf, sizeof(tbuf) - 1));
			}	

			if (univeral_ipv4.is_valid_ip()) {
				strbuf.appendfmt("Universal IPv4 Address %s, ", univeral_ipv4.printaddr(tbuf, sizeof(tbuf) - 1));
			}	

			if (link_ipv4.is_valid_ip()) {
				strbuf.appendfmt("Link Level IPv4 Address %s, ", link_ipv4.printaddr(tbuf, sizeof(tbuf) - 1));
			}	

			if (host_ipv4.is_valid_ip()) {
				strbuf.appendfmt("Host Scope IPv4 Address %s, ", host_ipv4.printaddr(tbuf, sizeof(tbuf) - 1));
			}	

			return strbuf.buffer();
		}			
	} addr;	
	
	struct {
		uint64_t		tstats_usec {0};
		uint64_t		rx_packets {0};
		uint64_t		tx_packets {0};
		uint64_t		rx_bytes {0};
		uint64_t		tx_bytes {0};
	} stats;
		
	IF_LINK() noexcept 		= default;

	IF_LINK(IF_LINK && other) noexcept;

	IF_LINK(const IF_LINK & other);

	~IF_LINK() noexcept
	{
		try {
			SCOPE_GY_MUTEX	sclock(&kind_mutex);
				
			reset_kind_locked();
		}
		catch(...) {
		}
	}	

	int update_on_change(IF_LINK && other) noexcept;

	int update_weak_ptrs(NET_IF_HASH_TABLE & iftable);

	bool is_if_active() const noexcept
	{
		return (is_if_up && is_carrier);
	}	

	const char * print_info_str(char *pbuf, size_t szbuf) const;

	friend bool operator== (const std::shared_ptr<IF_LINK> &lhs, const int ifid) noexcept
	{
		return (lhs && (lhs->ifi_index == ifid));
	}

private :
	
	void reset_kind_locked()
	{
		if (pbond_master) {
			switch (if_kind) {
			
			case IF_KIND_BOND_MASTER :
				delete pbond_master;
				break;
	
			case IF_KIND_BOND_SLAVE :
				delete pbond_slave;
				break;
	
			case IF_KIND_BRIDGE_MASTER :
				delete pbridge_master;
				break;

			case IF_KIND_BRIDGE_SLAVE :
				delete pbridge_slave;
				break;

			case IF_KIND_GENEVE :
				delete pgeneve;
				break;
	
			case IF_KIND_IPVLAN :
				delete pipvlan;
				break;
	
			case IF_KIND_MACVLAN :
			case IF_KIND_MACVTAP :
				delete pmacvlan;
				break;
	
			case IF_KIND_VRF_MASTER :
				delete pvrf_master;
				break;
				
			case IF_KIND_VRF_SLAVE :
				delete pvrf_slave;
				break;

			case IF_KIND_VXLAN :
				delete pvxlan;
				break;

			default :
				break;	
			}	
		}	

		pbond_master = nullptr;

		if_kind = IF_KIND_NONE;
		if_kind_str[0] = '\0';
	}		

	char * print_hwaddr_str(STR_WR_BUF & strbuf) const noexcept
	{
		if (hw_addr_len) {
			strbuf.appendconst("Hardware Address : ");

			if (hw_addr_len != 4) {
				for (uint32_t i = 0; i < hw_addr_len; i++) {
					strbuf.appendfmt("%02X:", hw_addr[i]);	
				}	 

				strbuf.set_last_char(',');
			}	
			else {
				// This is an IP Address
				uint32_t		ip1;
				char			tbuf[256];

				std::memcpy(&ip1, hw_addr, sizeof(ip1)); 
				
				GY_IP_ADDR		ipa {ip1};
				strbuf.append(ipa.printaddr(tbuf, sizeof(tbuf) - 1)); 
				strbuf.append(',');
			}	
		}	

		return strbuf.buffer();
	}
};	

class NET_ROUTE
{
public :	
	RCU_HASH_CLASS_MEMBERS(GY_IP_ADDR, NET_ROUTE);

	GY_IP_ADDR			dstaddr;
	GY_IP_ADDR			srcaddr;
	std::weak_ptr<IF_LINK>		iflink;	
	uint64_t			tclock_usec_added {0};

	NET_ROUTE() noexcept					= default;

	NET_ROUTE(GY_IP_ADDR &dstaddr_in, GY_IP_ADDR &srcaddr_in, const std::weak_ptr<IF_LINK> &iflink_weak) noexcept 
		: dstaddr(dstaddr_in), srcaddr(srcaddr_in), iflink(iflink_weak), tclock_usec_added(get_usec_time())
	{}	

	NET_ROUTE(const NET_ROUTE &other) 			= default;
	NET_ROUTE(NET_ROUTE && other) 				= default;
	NET_ROUTE & operator= (const NET_ROUTE &other) 		= default;
	NET_ROUTE & operator= (NET_ROUTE && other) 		= default;
	
	~NET_ROUTE() noexcept					= default;

	friend bool operator== (const NET_ROUTE & lhs, const GY_IP_ADDR & rhs) noexcept
	{
		return lhs.dstaddr == rhs;
	}
};	

class NET_IF_HDLR
{
public :	
	using 	CLI_IP_HASH_TABLE	= RCU_HASH_TABLE <GY_IP_ADDR, CLI_IP>;
	using 	NET_ROUTE_HASH_TABLE 	= RCU_HASH_TABLE <GY_IP_ADDR, NET_ROUTE>;

	NET_IF_HASH_TABLE		iftable			{1};
	CLI_IP_HASH_TABLE		iptable			{1};
	NET_ROUTE_HASH_TABLE		route_table		{1, 1, 1024, true, false};

	std::atomic<uint32_t>		if_info_errors		{0};			
	int				proc_dir_fd;
	int				sysfs_dir_fd;
	ino_t				netns_inode;
	bool				is_root_ns;

	NET_IF_HDLR(int proc_dir_fd, int sysfs_dir_fd, ino_t nsinode, bool is_root_ns);

	int				check_for_changes() noexcept;

	size_t				get_approx_interface_count() const noexcept
	{
		return iftable.approx_count_fast();
	}	

	void 				print_net_iflink_info(void) const;

	std::weak_ptr<IF_LINK>		get_link_from_ip(const GY_IP_ADDR & addr, IF_SCOPE_E scope = IF_SCOPE_ANY) const noexcept;

	// Checks if the addr is not present as a Universal IP of any of the interfaces. Updated periodically every 90 sec
	bool is_remote_universal_ip(const GY_IP_ADDR & addr) const noexcept
	{
		if ((!addr.is_valid_ip()) || (addr.is_loopback()) || (addr.is_link_local_addr()) || (addr.is_any_address())) {
			return false;
		}
		
		return !iptable.lookup_single_elem(addr, addr.get_hash());
	}

	static NET_IF_HDLR *		get_singleton() noexcept;
	
private :

	int 				populate_iflist();
	mnl_socket * 			send_netlink_req(char *pmnlbuf, uint32_t & seqout, uint32_t & portidout, bool get_link_info) noexcept;
	int 				add_if_from_cb(const struct nlmsghdr *pnlh) noexcept;
	int 				add_addr_from_cb(const struct nlmsghdr *pnlh) noexcept;
	int 				update_if_from_cb(const struct nlmsghdr *pnlh) noexcept;
	int 				update_addr_from_cb(const struct nlmsghdr *pnlh) noexcept;
	int 				get_if_from_nlm(IF_LINK *pif, const struct nlmsghdr *pnlh, bool ignore_del);
};	


} // namespace gyeeta

