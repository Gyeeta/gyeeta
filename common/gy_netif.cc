
#include		"gy_netif.h"
#include		"gy_print_offload.h"

namespace gyeeta {

int get_if_info_from_type(uint16_t ifi_type, char *pbuf, size_t szbuf, uint32_t & infomask) noexcept
{
	static constexpr struct {
		uint16_t		type;
		const char 		*name;
		uint32_t		infomask;
	} aiftypes[] = {	
		{ 0,			"generic",		IF_INFO_NONE },
		{ ARPHRD_ETHER,		"ether",	 	IF_INFO_ETHERNET },
		{ ARPHRD_LOOPBACK,	"loopback",		IF_INFO_LOOPBACK },
		{ ARPHRD_INFINIBAND,	"infiniband", 		IF_INFO_INFINIBAND },
		{ ARPHRD_TUNNEL,	"ipip",			IF_INFO_TUNNEL | IF_INFO_TUNNEL_IPIP },
		{ ARPHRD_IPGRE,		"gre",			IF_INFO_TUNNEL | IF_INFO_TUNNEL_GRE },
		{ ARPHRD_IP6GRE, 	"gre6", 		IF_INFO_TUNNEL | IF_INFO_TUNNEL_GRE },
		{ ARPHRD_SIT,		"sit",			IF_INFO_TUNNEL | IF_INFO_TUNNEL_SIT },
		{ ARPHRD_TUNNEL6,	"tunnel6",		IF_INFO_TUNNEL | IF_INFO_TUNNEL_IPIP },
		{ ARPHRD_FCPP,		"fcpp",			IF_INFO_FC },
		{ ARPHRD_FCAL,		"fcal",			IF_INFO_FC },
		{ ARPHRD_FCPL,		"fcpl",			IF_INFO_FC },
		{ ARPHRD_FCFABRIC,	"fcfb0",		IF_INFO_FC },
		{ ARPHRD_FCFABRIC + 1,	"fcfb1",		IF_INFO_FC },
		{ ARPHRD_FCFABRIC + 2,	"fcfb2",		IF_INFO_FC },
		{ ARPHRD_FCFABRIC + 3,	"fcfb3",		IF_INFO_FC },
		{ ARPHRD_FCFABRIC + 4,	"fcfb4",		IF_INFO_FC },
		{ ARPHRD_FCFABRIC + 5,	"fcfb5",		IF_INFO_FC },
		{ ARPHRD_FCFABRIC + 6,	"fcfb6",		IF_INFO_FC },
		{ ARPHRD_FCFABRIC + 7,	"fcfb7",		IF_INFO_FC },
		{ ARPHRD_FCFABRIC + 8,	"fcfb8",		IF_INFO_FC },
		{ ARPHRD_FCFABRIC + 9,	"fcfb9",		IF_INFO_FC },
		{ ARPHRD_FCFABRIC + 10,	"fcfb10",		IF_INFO_FC },
		{ ARPHRD_FCFABRIC + 11,	"fcfb11",		IF_INFO_FC },
		{ ARPHRD_FCFABRIC + 12,	"fcfb12",		IF_INFO_FC },
		{ ARPHRD_VSOCKMON, 	"vsockmon",		IF_INFO_VSOCK },

		{ ARPHRD_EETHER,	"eether",		IF_INFO_NONE },
		{ ARPHRD_AX25,		"ax25",			IF_INFO_NONE },
		{ ARPHRD_PRONET,	"pronet",		IF_INFO_NONE },
		{ ARPHRD_CHAOS,		"chaos",		IF_INFO_NONE },
		{ ARPHRD_IEEE802,	"ieee802",		IF_INFO_NONE },
		{ ARPHRD_ARCNET,	"arcnet",		IF_INFO_NONE },
		{ ARPHRD_APPLETLK,	"atalk",		IF_INFO_NONE },
		{ ARPHRD_DLCI,		"dlci",			IF_INFO_NONE },
		{ ARPHRD_ATM,		"atm",			IF_INFO_NONE },
		{ ARPHRD_METRICOM,	"metricom",		IF_INFO_NONE },
		{ ARPHRD_IEEE1394,	"ieee1394",		IF_INFO_NONE },
		{ ARPHRD_SLIP,		"slip",			IF_INFO_NONE },
		{ ARPHRD_CSLIP,		"cslip",		IF_INFO_NONE },
		{ ARPHRD_SLIP6,		"slip6",		IF_INFO_NONE },
		{ ARPHRD_CSLIP6,	"cslip6",		IF_INFO_NONE },
		{ ARPHRD_RSRVD,		"rsrvd",		IF_INFO_NONE },
		{ ARPHRD_ADAPT,		"adapt",		IF_INFO_NONE },
		{ ARPHRD_ROSE,		"rose",			IF_INFO_NONE },
		{ ARPHRD_X25,		"x25",			IF_INFO_NONE },
		{ ARPHRD_HWX25,		"hwx25",		IF_INFO_NONE },
		{ ARPHRD_CAN,		"can",			IF_INFO_NONE },
		{ ARPHRD_PPP,		"ppp",			IF_INFO_NONE },
		{ ARPHRD_HDLC,		"hdlc",			IF_INFO_NONE },
		{ ARPHRD_LAPB,		"lapb",			IF_INFO_NONE },
		{ ARPHRD_DDCMP,		"ddcmp",		IF_INFO_NONE },
		{ ARPHRD_RAWHDLC,	"rawhdlc",		IF_INFO_NONE },
		{ ARPHRD_FRAD,		"frad",			IF_INFO_NONE },
		{ ARPHRD_SKIP,		"skip",			IF_INFO_NONE },
		{ ARPHRD_LOCALTLK,	"ltalk",		IF_INFO_NONE },
		{ ARPHRD_FDDI,		"fddi",			IF_INFO_NONE },
		{ ARPHRD_BIF,		"bif",			IF_INFO_NONE },
		{ ARPHRD_IPDDP,		"ip/ddp",		IF_INFO_NONE },
		{ ARPHRD_PIMREG,	"pimreg",		IF_INFO_NONE },
		{ ARPHRD_HIPPI,		"hippi",		IF_INFO_NONE },
		{ ARPHRD_ASH,		"ash",			IF_INFO_NONE },
		{ ARPHRD_ECONET,	"econet",		IF_INFO_NONE },
		{ ARPHRD_IRDA,		"irda",			IF_INFO_NONE },
		{ ARPHRD_IEEE802_TR,	"tr",			IF_INFO_NONE },
		{ ARPHRD_IEEE80211,	"ieee802.11",		IF_INFO_NONE },
		{ ARPHRD_IEEE80211_PRISM,	"ieee802.11/prism",		IF_INFO_NONE },
		{ ARPHRD_IEEE80211_RADIOTAP,	"ieee802.11/radiotap",		IF_INFO_NONE },
		{ ARPHRD_IEEE802154, 		"ieee802.15.4",			IF_INFO_NONE },
		{ ARPHRD_IEEE802154_MONITOR, 	"ieee802.15.4/monitor",		IF_INFO_NONE },
		{ ARPHRD_PHONET, 	"phonet",		IF_INFO_NONE },
		{ ARPHRD_PHONET_PIPE, 	"phonet_pipe",		IF_INFO_NONE },
		{ ARPHRD_CAIF, 		"caif",			IF_INFO_NONE },
		{ ARPHRD_NETLINK, 	"netlink",		IF_INFO_NONE },
		{ ARPHRD_6LOWPAN, 	"6lowpan",		IF_INFO_NONE },
	};

	for (size_t i = 0; i < GY_ARRAY_SIZE(aiftypes); i++) {
		if (aiftypes[i].type == ifi_type) {
			if (pbuf && szbuf) {
				GY_STRNCPY(pbuf, aiftypes[i].name, szbuf);
			}	
			infomask = aiftypes[i].infomask;

			return 0;
		}	
	}	

	DEBUGEXECN(1, WARNPRINTCOLOR(GY_COLOR_BOLD_YELLOW, "Unhandled Interface Type %d seen...\n", ifi_type););

	if (pbuf && szbuf) {
		snprintf(pbuf, szbuf, "Unknown_Type_%d", ifi_type);
	}
	infomask = IF_INFO_NONE;
	return 1;
}

int get_bond_slave_ids(int sysfs_dir_fd, const char *pbond, std::vector<int> & vec) noexcept
{
	int				ret, fd;
	char				buf[256], path[256], readbuf[512];
	const char			*ptmp;
	ssize_t				szread;
	size_t				nbytes, lencopy;
	
	snprintf(buf, sizeof(buf), "./class/net/%s/bonding/slaves", pbond);

	SCOPE_FD			scopefd(sysfs_dir_fd, buf, O_RDONLY, 0640);
	
	fd = scopefd.get();
	if (fd < 0) {
		return -1;
	}	

	szread = gy_readbuffer(fd, readbuf, sizeof(readbuf) - 1);
	if (szread <= 0) {
		return -1;
	}

	readbuf[szread] = '\0';

	scopefd.close();

	vec.clear();

	STR_RD_BUF			strbuf(readbuf, szread);

	do {
		ptmp = strbuf.get_next_word(nbytes);
		if (!ptmp) {
			break;
		}	

		GY_SAFE_MEMCPY(buf, sizeof(buf) - 1, ptmp, nbytes, lencopy);
		buf[lencopy] = '\0';

		snprintf(path, sizeof(path), "./class/net/%s/ifindex", buf);

		SCOPE_FD			ifscopefd(sysfs_dir_fd, path, O_RDONLY, 0640);
		int				ifd, ifindex;
		bool				bret;
		
		ifd = ifscopefd.get();
		if (ifd < 0) {
			continue;
		}	

		szread = gy_readbuffer(ifd, buf, sizeof(buf) - 1);
		if (szread <= 0) {
			continue;
		}

		buf[szread] = '\0';
		
		bret = string_to_number(buf, ifindex);
		if (bret) {
			try {
				vec.push_back(ifindex);
			}
			GY_CATCH_EXCEPTION(return -1;);	
		}		
	
	} while (true);

	return 0;	
}	


IF_LINK::IF_LINK(IF_LINK && other) noexcept
	: 
	ifi_index(other.ifi_index), ifi_type(other.ifi_type), ifi_flags(other.ifi_flags),
	infomask(other.infomask),
	master_ifi_index(other.master_ifi_index), master_ifi_shr(std::move(other.master_ifi_shr)),
	link_ifi_index(other.link_ifi_index), link_ifi_shr(std::move(other.link_ifi_shr)),
	hw_addr_len(other.hw_addr_len), mtu(other.mtu), broadcast_len(other.broadcast_len),
	if_kind(other.if_kind), 
	xdp_type(other.xdp_type), ntx_queues(other.ntx_queues), nrx_queues(other.nrx_queues),
	gso_max_size(other.gso_max_size), gso_max_segs(other.gso_max_segs),
	num_vf_sriov(other.num_vf_sriov), 
	speed_mbps(other.speed_mbps), observed_speed_mbps(other.observed_speed_mbps.load(std::memory_order_relaxed)),
	if_add_usec_time(other.if_add_usec_time), last_chk_usec_time(other.last_chk_usec_time.load(std::memory_order_relaxed)), netns_inode(other.netns_inode), 
	flags(other.flags), addr(other.addr), stats(other.stats)
{
	GY_STRNCPY(ifname, other.ifname, sizeof(ifname));
	GY_STRNCPY(iftype_str, other.iftype_str, sizeof(iftype_str));
	std::memcpy(hw_addr, other.hw_addr, sizeof(hw_addr));
	std::memcpy(broadcast_addr, other.broadcast_addr, sizeof(broadcast_addr));
	GY_STRNCPY(if_kind_str, other.if_kind_str, sizeof(if_kind_str));

	if (other.pbond_master) {
		pbond_master = other.pbond_master;
		other.pbond_master = nullptr;
		other.if_kind = IF_KIND_NONE;
	}	

	GY_STRNCPY(qdisc, other.qdisc, sizeof(qdisc));
}	

IF_LINK::IF_LINK(const IF_LINK & other)
	: 
	ifi_index(other.ifi_index), ifi_type(other.ifi_type), ifi_flags(other.ifi_flags),
	infomask(other.infomask),
	master_ifi_index(other.master_ifi_index), master_ifi_shr(other.master_ifi_shr),
	link_ifi_index(other.link_ifi_index), link_ifi_shr(other.link_ifi_shr),
	hw_addr_len(other.hw_addr_len), mtu(other.mtu), broadcast_len(other.broadcast_len),
	if_kind(other.if_kind), 
	xdp_type(other.xdp_type), ntx_queues(other.ntx_queues), nrx_queues(other.nrx_queues),
	gso_max_size(other.gso_max_size), gso_max_segs(other.gso_max_segs),
	num_vf_sriov(other.num_vf_sriov), 
	speed_mbps(other.speed_mbps), observed_speed_mbps(other.observed_speed_mbps.load(std::memory_order_relaxed)),
	if_add_usec_time(other.if_add_usec_time), last_chk_usec_time(other.last_chk_usec_time.load(std::memory_order_relaxed)), netns_inode(other.netns_inode), 
	flags(other.flags), addr(other.addr), stats(other.stats)
{
	GY_STRNCPY(ifname, other.ifname, sizeof(ifname));
	GY_STRNCPY(iftype_str, other.iftype_str, sizeof(iftype_str));
	std::memcpy(hw_addr, other.hw_addr, sizeof(hw_addr));
	std::memcpy(broadcast_addr, other.broadcast_addr, sizeof(broadcast_addr));
	GY_STRNCPY(if_kind_str, other.if_kind_str, sizeof(if_kind_str));

	pbond_master = nullptr;

	if (other.pbond_master) {
		switch (other.if_kind) {

		case IF_KIND_BOND_MASTER :
			pbond_master = new std::decay_t<decltype(*pbond_master)>(*other.pbond_master);
			break;

		case IF_KIND_BOND_SLAVE :
			pbond_slave = new std::decay_t<decltype(*pbond_slave)>(*other.pbond_slave);
			break;

		case IF_KIND_BRIDGE_MASTER :
			pbridge_master = new std::decay_t<decltype(*pbridge_master)>(*other.pbridge_master);
			break;

		case IF_KIND_BRIDGE_SLAVE :
			pbridge_slave = new std::decay_t<decltype(*pbridge_slave)>(*other.pbridge_slave);
			break;

		case IF_KIND_GENEVE :
			pgeneve = new std::decay_t<decltype(*pgeneve)>(*other.pgeneve);
			break;

		case IF_KIND_IPVLAN :
			pipvlan = new std::decay_t<decltype(*pipvlan)>(*other.pipvlan);
			break;

		case IF_KIND_MACVLAN :
		case IF_KIND_MACVTAP :
			pmacvlan = new std::decay_t<decltype(*pmacvlan)>(*other.pmacvlan);
			break;

		case IF_KIND_VRF_MASTER :
			pvrf_master = new std::decay_t<decltype(*pvrf_master)>(*other.pvrf_master);
			break;
			
		case IF_KIND_VRF_SLAVE :
			pvrf_slave = new std::decay_t<decltype(*pvrf_slave)>(*other.pvrf_slave);
			break;

		case IF_KIND_VXLAN :
			pvxlan = new std::decay_t<decltype(*pvxlan)>(*other.pvxlan);
			break;

		default :
			break;	
		}	
	}	

	GY_STRNCPY(qdisc, other.qdisc, sizeof(qdisc));
}	

/*
 * Returns > 0 if changed and updated, 0 if no updates, < 0 on all errors
 */
int IF_LINK::update_on_change(IF_LINK && other) noexcept
{
	int			nupd = 0;

	try {

		if (ifi_index != other.ifi_index) {
			return 0;
		}	
		if (ifi_type != other.ifi_type) {
			return 0;
		}	
		
		if (ifi_flags != other.ifi_flags) {
			ifi_flags 	= other.ifi_flags;
			flags 		= other.flags;

			nupd = 2;
		}	

		if (mtu != other.mtu) {
			mtu = other.mtu;
			nupd++;
		}	
		
		if (strcmp(ifname, other.ifname)) {
			strcpy(ifname, other.ifname);
			nupd++;
		}	

		if (link_ifi_index != other.link_ifi_index) {
			SCOPE_GY_MUTEX			scopelock(&kind_mutex);

			if (link_ifi_index != other.link_ifi_index) {
				link_ifi_shr 		= std::move(other.link_ifi_shr);

				link_ifi_index		= other.link_ifi_index;
				nupd++;
			}	
		}	

		if (xdp_type != other.xdp_type) {
			xdp_type = other.xdp_type;
			nupd++;
		}	

		if (strcmp(qdisc, other.qdisc)) {
			GY_STRNCPY(qdisc, other.qdisc, sizeof(qdisc));
			nupd++;
		}	

		if (master_ifi_index != other.master_ifi_index) {
			SCOPE_GY_MUTEX			scopelock(&kind_mutex);

			if (master_ifi_index != other.master_ifi_index) {
				master_ifi_shr 			= std::move(other.master_ifi_shr);

				master_ifi_index		= other.master_ifi_index;
				nupd++;
			}	
		}	

		if (memcmp(hw_addr, other.hw_addr, hw_addr_len)) {
			std::memcpy(hw_addr, other.hw_addr, other.hw_addr_len);
			hw_addr_len = other.hw_addr_len;
			nupd++;
		}	

		if (memcmp(broadcast_addr, other.broadcast_addr, broadcast_len)) {
			std::memcpy(broadcast_addr, other.broadcast_addr, other.broadcast_len);
			broadcast_len = other.broadcast_len;
			nupd++;
		}	

		if (ntx_queues != other.ntx_queues) {
			ntx_queues = other.ntx_queues;
			nupd++;
		}	

		if (nrx_queues != other.nrx_queues) {
			nrx_queues = other.nrx_queues;
			nupd++;
		}	

		if (gso_max_size != other.gso_max_size) {
			gso_max_size = other.gso_max_size;
			nupd++;
		}	

		if (gso_max_segs != other.gso_max_segs) {
			gso_max_segs = other.gso_max_segs;
			nupd++;
		}	

		if (num_vf_sriov != other.num_vf_sriov) {
			num_vf_sriov = other.num_vf_sriov;
			nupd++;
		}	

		stats = other.stats;
		last_chk_usec_time.store(other.last_chk_usec_time, std::memory_order_release);

		{
			SCOPE_GY_MUTEX			scopelock(&kind_mutex);

			if (if_kind != other.if_kind) {
				nupd++;

				reset_kind_locked();

				GY_STRNCPY(if_kind_str, other.if_kind_str, sizeof(if_kind_str));

				if_kind = other.if_kind;
				pbond_master = other.pbond_master;
				
				other.pbond_master = nullptr;
				other.if_kind = IF_KIND_NONE;	
				other.if_kind_str[0] = '\0';
			}	
			else if (pbond_master && other.pbond_master) {

				switch (if_kind) {
				
				case IF_KIND_BOND_MASTER :
					nupd += pbond_master->update_on_change(std::move(*other.pbond_master));
					break;
					
				case IF_KIND_BOND_SLAVE :
					nupd += pbond_slave->update_on_change(std::move(*other.pbond_slave));
					break;
					
				case IF_KIND_BRIDGE_MASTER :
					nupd += pbridge_master->update_on_change(std::move(*other.pbridge_master));
					break;
					
				case IF_KIND_BRIDGE_SLAVE :
					nupd += pbridge_slave->update_on_change(std::move(*other.pbridge_slave));
					break;
					
				case IF_KIND_GENEVE :
					nupd += pgeneve->update_on_change(std::move(*other.pgeneve));
					break;
					
				case IF_KIND_IPVLAN :
					nupd += pipvlan->update_on_change(std::move(*other.pipvlan));
					break;
					
				case IF_KIND_MACVLAN :
				case IF_KIND_MACVTAP :
					nupd += pmacvlan->update_on_change(std::move(*other.pmacvlan));
					break;
					
				case IF_KIND_VRF_MASTER :
					nupd += pvrf_master->update_on_change(std::move(*other.pvrf_master));
					break;
					
				case IF_KIND_VRF_SLAVE :
					nupd += pvrf_slave->update_on_change(std::move(*other.pvrf_slave));
					break;
					
				case IF_KIND_VXLAN :
					nupd += pvxlan->update_on_change(std::move(*other.pvxlan));
					break;
					
				default :
					break;
				}
			}	
		}
	
		if (nupd) {
			DEBUGEXECN(1,
				char		ibuf[1024];

				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Interface # %d has changed : Number of changes %d : New Info : %s\n", ifi_index, nupd,
					print_info_str(ibuf, sizeof(ibuf) - 1));
			);		

			if_add_usec_time = get_usec_time();
		}

		return nupd;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT("Exception caught while updating Interface %s info : %s\n", ifname, GY_GET_EXCEPT_STRING);
		return -1;
	);
}	

int IF_LINK::update_weak_ptrs(NET_IF_HASH_TABLE & iftable)
{
	auto 		lfindif = [](NET_IF_ELEM_TYPE *pdatanode, void *arg1, void *arg2) -> CB_RET_E
	{
		auto				pif = pdatanode->get_data()->get();
		std::weak_ptr<IF_LINK>	*pweak = static_cast<std::weak_ptr<IF_LINK> *>(arg1);

		if (pif == nullptr) {
			return CB_DELETE_ELEM;
		}

		*pweak = pif->weak_from_this();

		return CB_OK;
	};	

	int			ret, id;

	SCOPE_GY_MUTEX		scopelock(&kind_mutex);

	RCU_DEFER_OFFLINE	slowlock;

	id = link_ifi_index;	
	if (id > 0) {
		iftable.lookup_single_elem(id, get_int_hash(id), lfindif, &link_ifi_shr, nullptr);
	}

	id = master_ifi_index;
	if (id > 0) {
		iftable.lookup_single_elem(id, get_int_hash(id), lfindif, &master_ifi_shr, nullptr);
	}

	if (if_kind == IF_KIND_BOND_MASTER && pbond_master) {
		auto pkind = pbond_master;

		if (pkind->active_slave_ifi_index > 0) {
			iftable.lookup_single_elem(pkind->active_slave_ifi_index, get_int_hash(pkind->active_slave_ifi_index), lfindif, &pkind->active_slave_shr, nullptr);
		}	

		if (pkind->primary_ifi_index > 0) {
			iftable.lookup_single_elem(pkind->primary_ifi_index, get_int_hash(pkind->primary_ifi_index), lfindif, &pkind->primary_ifi_shr, nullptr);
		}	

		// Populate slaves_shr_vec
		for (int ifid : pkind->slaves_index_vec) {

			std::weak_ptr<IF_LINK>	weakp;
			
			iftable.lookup_single_elem(ifid, get_int_hash(ifid), lfindif, &weakp, nullptr);

			pkind->slaves_shr_vec.push_back(std::move(weakp));	
		}		
	}	
	else if (if_kind == IF_KIND_VXLAN && pvxlan) {
		auto pkind = pvxlan;
	
		if (pkind->device_id > 0) {
			iftable.lookup_single_elem(pkind->device_id, get_int_hash(pkind->device_id), lfindif, &pkind->device_shr, nullptr);
		}	
	}	
	
	return 0;
}	

const char * IF_LINK::print_info_str(char *pbuf, size_t szbuf) const 
{
	if (!pbuf) {
		return nullptr;
	}

	STR_WR_BUF		strbuf(pbuf, szbuf);
	char			tbuf[256];
	int			id;

	strbuf.appendfmt("Interface \'%s\' : Index %d Type %s, ", ifname, ifi_index, iftype_str);

	if ((id = master_ifi_index)) strbuf.appendfmt("Master Interface %d, ", id);
	if ((id = link_ifi_index)) strbuf.appendfmt("Linked Interface %d, ", id);

	strbuf.appendfmt("MTU %u, qdisc %s, Speed %d Mbps, Observed Max Speed %d Mbps, Flags : ", mtu, qdisc, speed_mbps, observed_speed_mbps.load(std::memory_order_relaxed));
	
	if (is_if_active()) strbuf.appendconst("Interface Active | ");
	else strbuf.appendconst("Interface inactive | ");

	if (is_if_up) strbuf.appendconst("Up | "); 
	else strbuf.appendconst("Down | ");
	
	if (is_carrier) strbuf.appendconst("Carrier Up | ");
	else strbuf.appendconst("Carrier Down | ");		

	if (is_if_loopback) strbuf.appendconst("Loopback | ");
	if (is_ethernet) strbuf.appendconst("Ethernet | ");
	if (is_infiniband) strbuf.appendconst("Infiniband | ");
	if (is_tunnel) strbuf.appendconst("Tunnel | ");
	if (is_ipip_tunnel) strbuf.appendconst("IPIP | ");
	if (is_gre_tunnel) strbuf.appendconst("GRE | ");
	if (is_sit_tunnel) strbuf.appendconst("SIT | ");
	if (is_geneve_tunnel) strbuf.appendconst("Geneve | ");
	if (is_vxlan_tunnel) strbuf.appendconst("VxLAN | ");
	if (is_fiberchannel) strbuf.appendconst("FiberChannel | ");
	if (is_vsock) strbuf.appendconst("vsock | ");

	if (is_master) strbuf.appendconst("Master | ");
	if (is_slave) strbuf.appendconst("Slave | ");
	if (is_bridge) strbuf.appendconst("Bridge | ");
	if (is_bonding) strbuf.appendconst("Bonding | ");
	if (is_xdp) strbuf.appendconst("XDP | ");
	if (is_vlan) strbuf.appendconst("VLAN | ");
	if (is_sriov) strbuf.appendconst("SR-IOV, ");

	if (is_sriov && num_vf_sriov) strbuf.appendfmt("# SR-IOV Interfaces %u, ", num_vf_sriov);

	if (if_kind != IF_KIND_NONE) strbuf.appendfmt("Interface Type %s%s, ", if_kind_str, is_slave ? "_slave" : ""); 
		
	if (if_kind != IF_KIND_NONE) {

		SCOPE_GY_MUTEX			scopelock(&kind_mutex);

		switch (if_kind) {
		
		case IF_KIND_BOND_MASTER :
			strbuf.appendconst("Bond Master Info : Mode ");

			switch (pbond_master->mode) {

			case IF_LINK_BOND_MASTER::BOND_BALANCE_RR 		: strbuf.appendconst("Balance RR"); break;	
			case IF_LINK_BOND_MASTER::BOND_ACTIVE_BACKUP		: strbuf.appendconst("Active Backup"); break;	
			case IF_LINK_BOND_MASTER::BOND_BALANCE_XOR		: strbuf.appendconst("Balance XOR"); break;	
			case IF_LINK_BOND_MASTER::BOND_BROADCAST		: strbuf.appendconst("Broadcast"); break;	
			case IF_LINK_BOND_MASTER::BOND_LINK_AGGR_802		: strbuf.appendconst("Link Aggregation 802.3ad"); break;
			case IF_LINK_BOND_MASTER::BOND_BALANCE_TLB		: strbuf.appendconst("Balance TLB"); break;
			case IF_LINK_BOND_MASTER::BOND_BALANCE_ALB		: strbuf.appendconst("Balance ALB"); break;
			default 						: strbuf.appendconst("Unknown Node"); break;

			}	

			strbuf.appendconst(" ");

			if (pbond_master->active_slave_ifi_index > 0) strbuf.appendfmt("Active Slave Index %d ", pbond_master->active_slave_ifi_index);
			if (pbond_master->primary_ifi_index > 0) strbuf.appendfmt("Primary Slave Index %d ", pbond_master->primary_ifi_index);
			strbuf.appendfmt("All Slaves Active - %d ", pbond_master->all_slaves_active);
			if (pbond_master->min_links) strbuf.appendfmt("Minimum Slave Links %u ", pbond_master->min_links);
			if (pbond_master->rr_packets_per_slave) strbuf.appendfmt("RR Packets per slave %u ", pbond_master->rr_packets_per_slave);
			
			strbuf.appendconst("Bond Slaves Indexes : ");
	
			for (int ifnum : pbond_master->slaves_index_vec) {
				strbuf.appendfmt("%d, ", ifnum);
			}

			break;

		case IF_KIND_BOND_SLAVE :
			strbuf.appendconst("Bond Slave Info : ");
			if (pbond_slave->state == IF_LINK_BOND_SLAVE::BOND_SLAVE_STATE_BACKUP) strbuf.appendconst("State : Backup ");
			else strbuf.appendconst("State : Active ");

			if (pbond_slave->mii_status_up) strbuf.appendconst("MII Status : Up ");
			else strbuf.appendconst("MII Status : Down ");
			break;

		case IF_KIND_BRIDGE_MASTER :
			strbuf.appendfmt("Bridge Master Info : priority %hu ", pbridge_master->priority);
			break;

		case IF_KIND_BRIDGE_SLAVE :
			strbuf.appendfmt("Bridge Slave Info : priority %hu ", pbridge_slave->priority);
			break;

		case IF_KIND_GENEVE :
			strbuf.appendfmt("Geneve Info : ");
			strbuf.appendfmt("Remote Address %s ", pgeneve->remote_addr.printaddr(tbuf, sizeof(tbuf) - 1));
			if (pgeneve->remote_addr_6.is_valid_ip()) {
				strbuf.appendfmt("Remote Address %s ", pgeneve->remote_addr_6.printaddr(tbuf, sizeof(tbuf) - 1));
			}	
			strbuf.appendfmt("Tunnel UDP Port %hu ", pgeneve->dstport);

			break;

		case IF_KIND_IPVLAN :
			strbuf.appendfmt("IPVLAN Info : ");

			switch (pipvlan->mode) {
			
			case IPVLAN_MODE_L2 	: strbuf.appendconst("Mode L2 "); break;
			case IPVLAN_MODE_L3 	: strbuf.appendconst("Mode L3 "); break;
			case IPVLAN_MODE_L3S 	: strbuf.appendconst("Mode L3S "); break;
			
			default			: strbuf.appendconst("Mode Unknown "); break;

			}	

			switch (pipvlan->ipvflags) {
	
			case IF_LINK_IPVLAN::IF_IPVLAN_PRIVATE		: strbuf.appendconst("Type Private "); break;
			case IF_LINK_IPVLAN::IF_IPVLAN_VEPA		: strbuf.appendconst("Type VEPA "); break;
			case IF_LINK_IPVLAN::IF_IPVLAN_BRIDGE		: strbuf.appendconst("Type Bridge "); break;

			default						: strbuf.appendconst("Type Unknown "); break;

			}	
			break;

		case IF_KIND_MACVLAN :
		case IF_KIND_MACVTAP :
			if (if_kind == IF_KIND_MACVLAN) {
				strbuf.appendfmt("MACVLAN Info : ");
			}
			else {
				strbuf.appendfmt("MACVTAP Info : ");
			}		

			switch (pmacvlan->mode) {
			
			case MACVLAN_MODE_PRIVATE 	: strbuf.appendconst("Mode Private "); break;
			case MACVLAN_MODE_VEPA 		: strbuf.appendconst("Mode VEPA "); break;
			case MACVLAN_MODE_BRIDGE	: strbuf.appendconst("Mode Bridge "); break;
			case MACVLAN_MODE_PASSTHRU	: strbuf.appendconst("Mode Passthrough "); break;
			case MACVLAN_MODE_SOURCE	: strbuf.appendconst("Mode Source MAC "); break;
			
			default				: strbuf.appendconst("Mode Unknown "); break;

			}	

			break;

		case IF_KIND_VRF_MASTER :
			strbuf.appendfmt("VRF Master Info : VRF Table %u ", pvrf_master->vrf_table);
			break;
			
		case IF_KIND_VRF_SLAVE :
			strbuf.appendfmt("VRF Slave Info : VRF Table %u ", pvrf_slave->vrf_table);
			break;

		case IF_KIND_VXLAN :
			strbuf.appendfmt("VXLAN Info : ");
			strbuf.appendfmt("Remote Address %s ", pvxlan->remote_addr.printaddr(tbuf, sizeof(tbuf) - 1));
			if (pvxlan->remote_addr_6.is_valid_ip()) {
				strbuf.appendfmt("Remote Address %s ", pvxlan->remote_addr_6.printaddr(tbuf, sizeof(tbuf) - 1));
			}	

			strbuf.appendfmt("Local Address %s ", pvxlan->local_addr.printaddr(tbuf, sizeof(tbuf) - 1));
			if (pvxlan->local_addr_6.is_valid_ip()) {
				strbuf.appendfmt("Local Address %s ", pvxlan->local_addr_6.printaddr(tbuf, sizeof(tbuf) - 1));
			}	

			strbuf.appendfmt("Device Interface %d Tunnel UDP Port %hu ", pvxlan->device_id, pvxlan->dstport);

			break;

		case IF_KIND_IPOIB :
			strbuf.appendfmt("IPoIB ");
			break;

		case IF_KIND_TEAM_MASTER :
			strbuf.appendfmt("Teaming Master ");
			break;

		case IF_KIND_TEAM_SLAVE :
			strbuf.appendfmt("Teaming Slave ");
			break;

		default :
			break;	
		}	
	}	
	
	strbuf.appendconst(", ");

	if (xdp_type != IF_XDP_NONE) {
		switch (xdp_type) {
		
		case IF_XDP_DRV 	: strbuf.appendfmt("XDP Type : XDP "); break;
		case IF_XDP_SKB 	: strbuf.appendfmt("XDP Type : XDP Generic "); break;
		case IF_XDP_HW 		: strbuf.appendfmt("XDP Type : XDP Offload "); break;
		
		default			: strbuf.appendfmt("XDP Type : Unknown %hhu ", xdp_type); break;
		}	
	}	

	strbuf.appendfmt("Num Tx Queues %u Num Rx Queues %u, ", ntx_queues, nrx_queues);
	strbuf.appendfmt("GSO Max Size %u GSO Max Segments %u, ", gso_max_size, gso_max_segs);
	
	addr.print_info_str(strbuf);
	print_hwaddr_str(strbuf);

	strbuf.appendfmt(" Last Stats : RxPackets %lu TxPackets %lu RxBytes %lu MB TxBytes %lu MB ", 
		stats.rx_packets, stats.tx_packets, GY_DOWN_MB(stats.rx_bytes), GY_DOWN_MB(stats.tx_bytes));

	return pbuf;
}	

int NET_IF_HDLR::populate_iflist()
{
	int			ret;
	struct mnl_socket 	*pnl, *pnl_addr;
	uint32_t 		seq, portid = 0;
	char 			*pmnlbuf;
	bool 			is_malloc;

	SAFE_STACK_ALLOC(pmnlbuf, GY_MNL_SOCKET_BUFFER_SIZE, is_malloc);

	INFOPRINT_OFFLOAD("Adding Network Interfaces to list...\n");

	pnl = send_netlink_req(pmnlbuf, seq, portid, true /* get_link_info */);
	if (!pnl) {
		GY_THROW_EXCEPTION("Failed to get Netlink socket / data for Interface Info");	
	}		
		
	GY_SCOPE_EXIT {
		if (pnl) {
			mnl_socket_close(pnl);
		}	
	};

	auto mnlcb = [](const struct nlmsghdr *pnlh, void *arg) -> int
	{
		NET_IF_HDLR 		*pthis = static_cast<NET_IF_HDLR *>(arg);

		return 	pthis->add_if_from_cb(pnlh);
	};
		 
	ret = mnl_socket_recvfrom(pnl, pmnlbuf, GY_MNL_SOCKET_BUFFER_SIZE);
	while (ret > 0) {
		ret = mnl_cb_run(pmnlbuf, ret, seq, portid, mnlcb, (void *)this);
		if (ret <= MNL_CB_STOP) {
			break;
		}	
		ret = mnl_socket_recvfrom(pnl, pmnlbuf, GY_MNL_SOCKET_BUFFER_SIZE);
	}
	if (ret == -1) {
		GY_THROW_SYS_EXCEPTION("Error while receiving Netlink data for getting interface list");
	}

	/*
	 * Now run a scan on the iftable and populate the weak_ptrs...
	 */
	auto 		lambda_upd_if = [this](NET_IF_ELEM_TYPE *pdatanode, void *arg1) -> CB_RET_E
	{
		try {
			auto			pif = pdatanode->get_data()->get();
			int			ret, id;

			if (pif == nullptr) {
				return CB_DELETE_ELEM;
			}
			
			pif->update_weak_ptrs(iftable);

			return CB_OK;

		}
		GY_CATCH_EXCEPTION(ERRORPRINT("Exception occured while populating interface table shared links : %s\n", GY_GET_EXCEPT_STRING); return CB_BREAK_LOOP;);
	};	

	iftable.walk_hash_table(lambda_upd_if, nullptr); 	

	/*
	 * Now populate the IP Addresses for all interfaces
	 */

	pnl_addr = send_netlink_req(pmnlbuf, seq, portid, false /* get_link_info */);
	if (!pnl_addr) {
		GY_THROW_EXCEPTION("Failed to get Netlink socket / data for Interface Addresses");	
	}		
		
	GY_SCOPE_EXIT {
		if (pnl_addr) {
			mnl_socket_close(pnl_addr);
		}	
	};

	auto mnlcb_addr = [](const struct nlmsghdr *pnlh, void *arg) -> int
	{
		NET_IF_HDLR 		*pthis = static_cast<NET_IF_HDLR *>(arg);

		return 	pthis->add_addr_from_cb(pnlh);
	};
		 
	ret = mnl_socket_recvfrom(pnl_addr, pmnlbuf, GY_MNL_SOCKET_BUFFER_SIZE);
	while (ret > 0) {
		ret = mnl_cb_run(pmnlbuf, ret, seq, portid, mnlcb_addr, (void *)this);
		if (ret <= MNL_CB_STOP) {
			break;
		}	
		ret = mnl_socket_recvfrom(pnl_addr, pmnlbuf, GY_MNL_SOCKET_BUFFER_SIZE);
	}

	// Now populate the Universal IP iptable
	auto l1 = [&, currt = (uint32_t)get_sec_time()](NET_IF_ELEM_TYPE *pdatanode, void *arg1) -> CB_RET_E
	{
		auto			pif = pdatanode->get_data()->get();

		if (pif) {
			if (pif->addr.univeral_ipv4.is_valid_ip()) {
				const auto 		& cip 	= pif->addr.univeral_ipv4;
				auto 			nchash 	= cip.get_hash();
				auto 			pcli = new CLI_IP(cip, currt);

				iptable.insert_or_replace(pcli, cip, nchash);
			}	

			if (pif->addr.univeral_ipv6.is_valid_ip()) {
				const auto 		& cip 	= pif->addr.univeral_ipv6;
				auto 			nchash 	= cip.get_hash();
				auto 			pcli = new CLI_IP(cip, currt);

				iptable.insert_or_replace(pcli, cip, nchash);
			}
		}
			 
		return CB_OK;
	};	

	iftable.walk_hash_table_const(l1); 	

	CONDEXEC( 

		/*
		 * Now print all Interface Addresses
		 */
		auto 		lambda_print_if = [](NET_IF_ELEM_TYPE *pdatanode, void *arg1) -> CB_RET_E
		{
			auto			pif = pdatanode->get_data()->get();

			char			tbuf[700];
			STR_WR_BUF		strbuf(tbuf, sizeof(tbuf));

			if (pif == nullptr) {
				return CB_DELETE_ELEM;
			}
			
			pif->addr.print_info_str(strbuf);

			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Interface %s (%d) IP Address Info : %.*s\n", pif->ifname, pif->ifi_index, strbuf.sizeint(), strbuf.buffer());

			return CB_OK;
		};	

		iftable.walk_hash_table(lambda_print_if, nullptr); 	
	);

	return 0;
}	

int NET_IF_HDLR::check_for_changes() noexcept
{
	/*
	 * XXX TODO : Current implementation is too expensive. We need a lightweight method for checking changes...
	 */
	GY_NOMT_COLLECT_PROFILE(20, "Check Network Interface Changes");

	try {
		int			ret;
		struct mnl_socket 	*pnl, *pnl_addr;
		uint32_t 		seq, portid = 0;
		char 			*pmnlbuf;
		bool 			is_malloc;

		SAFE_STACK_ALLOC(pmnlbuf, GY_MNL_SOCKET_BUFFER_SIZE, is_malloc);

		pnl = send_netlink_req(pmnlbuf, seq, portid, true /* get_link_info */);
		if (!pnl) {
			ERRORPRINT("Failed to get Netlink socket / data for Interface Info Changes\n");	
			return -1;
		}		
			
		GY_SCOPE_EXIT {
			if (pnl) {
				mnl_socket_close(pnl);
			}	
		};

		auto mnlcb = [](const struct nlmsghdr *pnlh, void *arg) -> int
		{
			NET_IF_HDLR 		*pthis = static_cast<NET_IF_HDLR *>(arg);

			return 	pthis->update_if_from_cb(pnlh);
		};
			 
		ret = mnl_socket_recvfrom(pnl, pmnlbuf, GY_MNL_SOCKET_BUFFER_SIZE);
		while (ret > 0) {
			ret = mnl_cb_run(pmnlbuf, ret, seq, portid, mnlcb, (void *)this);
			if (ret <= MNL_CB_STOP) {
				break;
			}	
			ret = mnl_socket_recvfrom(pnl, pmnlbuf, GY_MNL_SOCKET_BUFFER_SIZE);
		}
		if (ret == -1) {
			ERRORPRINT("Error while receiving Netlink data for checking interface list changes\n");
			return -1;
		}

		/*
		 * Now check for IP Address changes for all interfaces
		 */

		pnl_addr = send_netlink_req(pmnlbuf, seq, portid, false /* get_link_info */);
		if (!pnl_addr) {
			ERRORPRINT("Failed to get Netlink socket / data for Interface Addresses\n");	
			return -1;
		}		
			
		GY_SCOPE_EXIT {
			if (pnl_addr) {
				mnl_socket_close(pnl_addr);
			}	
		};

		auto mnlcb_addr = [](const struct nlmsghdr *pnlh, void *arg) -> int
		{
			NET_IF_HDLR 		*pthis = static_cast<NET_IF_HDLR *>(arg);

			return 	pthis->update_addr_from_cb(pnlh);
		};
			 
		ret = mnl_socket_recvfrom(pnl_addr, pmnlbuf, GY_MNL_SOCKET_BUFFER_SIZE);
		while (ret > 0) {
			ret = mnl_cb_run(pmnlbuf, ret, seq, portid, mnlcb_addr, (void *)this);
			if (ret <= MNL_CB_STOP) {
				break;
			}	
			ret = mnl_socket_recvfrom(pnl_addr, pmnlbuf, GY_MNL_SOCKET_BUFFER_SIZE);
		}

		uint64_t	tcurusec = get_usec_time();
			
		/*
		 * Now run a scan on the iftable and remove the interfaces which have not been updated since last 300 sec
		 */
		auto lambda_del_if = [&, tcurusec, currt = (uint32_t)(tcurusec/GY_USEC_PER_SEC)](NET_IF_ELEM_TYPE *pdatanode, void *arg1) -> CB_RET_E
		{
			auto			pif = pdatanode->get_data()->get();
			int			ret, id;

			if (pif == nullptr) {
				return CB_DELETE_ELEM;
			}
			
			uint64_t		tcheck = pif->last_chk_usec_time.load(std::memory_order_relaxed);

			if (tcurusec - tcheck > 300 * GY_USEC_PER_SEC && tcheck) {

				if (tcheck == pif->last_chk_usec_time.load(std::memory_order_acquire)) {

					DEBUGEXECN(1, INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Deleting Interface %s (%d) since no info since last 300 sec\n",
						pif->ifname, pif->ifi_index););

					return CB_DELETE_ELEM;
				}
			}	
			else {
				const auto 		& cip 	= pif->addr.univeral_ipv4;
				const auto 		& cip6 	= pif->addr.univeral_ipv6;

				if (cip.is_valid_ip()) {
					auto 			nchash 	= cip.get_hash();
					CLI_IP			*pcli;

					pcli = iptable.lookup_single_elem_locked(cip, nchash);

					if (pcli) {
						pcli->last_tsec_ = currt;
					}
					else {
						auto 			pcli = new CLI_IP(cip, currt);

						iptable.insert_or_replace(pcli, cip, nchash);
					}
				}	

				if (cip6.is_valid_ip()) {
					auto 			nchash 	= cip6.get_hash();
					CLI_IP			*pcli;

					pcli = iptable.lookup_single_elem_locked(cip6, nchash);

					if (pcli) {
						pcli->last_tsec_ = currt;
					}
					else {
						auto 			pcli = new CLI_IP(cip6, currt);

						iptable.insert_or_replace(pcli, cip6, nchash);
					}
				}	
			}	

			return CB_OK;
		};	

		size_t nifs_cur = iftable.walk_hash_table(lambda_del_if, nullptr); 	

		/*
		 * Now run a scan on the iptable and remove the IPs which have not been updated since last 300 sec
		 */
		auto ldelip = [cutoffsec = (uint32_t)get_sec_time() - 300](CLI_IP *pcli, void *arg1) -> CB_RET_E
		{
			if (pcli->last_tsec_ < cutoffsec) {
				return CB_DELETE_ELEM;
			}	
			return CB_OK;
		};
			
		size_t nips_cur = iptable.walk_hash_table(ldelip);

		INFOPRINT_OFFLOAD("Current # of network interfaces active is %lu : Current Universal IPs used = %lu\n", nifs_cur, nips_cur);

		return 0;

	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT("Exception caught while checking for interface changes : %s\n", GY_GET_EXCEPT_STRING);
		return -1;
	);	
}	


/*
 * Returns 0 if new interface successfully filled in or deleted interface data added
 * Returns > 0 for ignoring this callback
 * Returns < 0 to signal main callback loop to terminate due to unrecoverable errors
 */
int NET_IF_HDLR::get_if_from_nlm(IF_LINK *pif, const struct nlmsghdr *pnlh, bool ignore_del)
{
	struct ifinfomsg	 	*pdata = static_cast<ifinfomsg *>(mnl_nlmsg_get_payload(pnlh));
	struct nlattr 			*pattr;
	uint16_t 			attr_len;

	if (pnlh->nlmsg_type != RTM_NEWLINK && pnlh->nlmsg_type != RTM_DELLINK) {
		return 1;
	}	

	if ((pnlh->nlmsg_type == RTM_DELLINK) && ignore_del) {
		return 1;
	}	

	if (mnl_nlmsg_get_payload_len(pnlh) < sizeof(*pdata)) {
		DEBUGEXECN(1, ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Invalid Netlink message length seen %lu while populating interfaces\n", 
			mnl_nlmsg_get_payload_len(pnlh)););
		return -1;
	}	

	if (pdata->ifi_family != AF_UNSPEC) {
		return 1;
	}	
	
	pif->ifi_index 	= pdata->ifi_index;
	pif->ifi_type	= pdata->ifi_type;
	pif->ifi_flags	= pdata->ifi_flags;

	get_if_info_from_type(pif->ifi_type, pif->iftype_str, sizeof(pif->iftype_str), pif->infomask);

	if (pif->ifi_flags & IFF_UP) {
		pif->is_if_up = true;

		if (pif->ifi_flags & IFF_RUNNING) {
			pif->is_carrier = true;
			pif->is_operstate_up = true;		// Preset this
		}	
		else {
			pif->is_carrier = false;
		}	
	}
	else {
		pif->is_if_up = false;
		pif->is_carrier = false;
	}		

	pif->is_lower_up	= (pif->ifi_flags & IFF_LOWER_UP);
	pif->is_if_broadcast 	= (pif->ifi_flags & IFF_BROADCAST);
	pif->is_if_loopback 	= (pif->ifi_flags & IFF_LOOPBACK);
	pif->is_point_to_point	= (pif->ifi_flags & IFF_POINTOPOINT);
	pif->is_promiscuous	= (pif->ifi_flags & IFF_PROMISC);
	pif->is_master		= (pif->ifi_flags & IFF_MASTER);
	pif->is_slave		= (pif->ifi_flags & IFF_SLAVE);

	pif->is_ethernet	= pif->infomask & IF_INFO_ETHERNET;
	pif->is_infiniband	= pif->infomask & IF_INFO_INFINIBAND;
	pif->is_tunnel		= pif->infomask & IF_INFO_TUNNEL;
	pif->is_ipip_tunnel	= pif->infomask & IF_INFO_TUNNEL_IPIP;
	pif->is_gre_tunnel	= pif->infomask & IF_INFO_TUNNEL_GRE;
	pif->is_sit_tunnel	= pif->infomask & IF_INFO_TUNNEL_SIT;

	switch (pif->ifi_type) {

	case ARPHRD_TUNNEL :
	case ARPHRD_SIT :
	case ARPHRD_IPGRE :
		pif->is_hw_addr_ipv4 	= true;
		break;

	case ARPHRD_TUNNEL6 :
	case ARPHRD_IP6GRE :
		pif->is_hw_addr_ipv6 	= true;
		break;
		
	default :
		break;	
	}	
		
	/*
	 * Now iterate over the NLMsg
	 */
	gy_mnl_attr_for_each(pattr, pnlh, sizeof(*pdata)) {
		int type = mnl_attr_get_type(pattr);

		/* skip unsupported attribute in user-space */
		if (mnl_attr_type_valid(pattr, IFLA_MAX) < 0) {
			continue;
		}	

		switch (type) {

		case IFLA_MTU :
			if (mnl_attr_validate(pattr, MNL_TYPE_U32) >= 0) {
				pif->mtu = mnl_attr_get_u32(pattr);
			}	
			break;

		case IFLA_IFNAME :
			if (mnl_attr_validate(pattr, MNL_TYPE_STRING) < 0) {
				return 1;
			}
			
			GY_STRNCPY(pif->ifname, mnl_attr_get_str(pattr), sizeof(pif->ifname));
			break;

		case IFLA_LINK :
			if (mnl_attr_validate(pattr, MNL_TYPE_U32) >= 0) {
				pif->link_ifi_index = mnl_attr_get_u32(pattr);

				// The link_ifi_shr will be populated in the second pass
			}	

			break;	
			
		case IFLA_XDP :
			{
				const struct nlattr 		*pattr_nest;
				uint8_t				mode;

				gy_mnl_attr_for_each_nested(pattr_nest, pattr) {
					int type_nest = mnl_attr_get_type(pattr_nest);

					if (type_nest == IFLA_XDP_ATTACHED) {
						mode = mnl_attr_get_u8(pattr_nest);
						
						if (mode == IF_XDP_NONE) {
							pif->is_xdp = false;
							pif->xdp_type = IF_XDP_NONE;
						}	
						else {
							pif->is_xdp = true;
							pif->xdp_type = mode;
						}	
						
						goto done1;
					}	
				}	

done1 :	
				break;		
			}
			break;
			
		case IFLA_QDISC :
			if (mnl_attr_validate(pattr, MNL_TYPE_STRING) >= 0) {
				GY_STRNCPY(pif->qdisc, mnl_attr_get_str(pattr), sizeof(pif->qdisc));
			}
			break;

		case IFLA_MASTER :
			if (mnl_attr_validate(pattr, MNL_TYPE_U32) >= 0) {
				pif->master_ifi_index = mnl_attr_get_u32(pattr);
				// The master_ifi_shr will be populated in the second pass
			}	
			break;

		case IFLA_OPERSTATE :
			pif->is_operstate_up = (mnl_attr_get_u8(pattr) == 6);
			break;	

		case IFLA_ADDRESS :
			if (mnl_attr_validate(pattr, MNL_TYPE_BINARY) >= 0) {
				uint8_t 		*phwaddr = (uint8_t *)mnl_attr_get_payload(pattr);
				size_t 			hwlen = mnl_attr_get_payload_len(pattr);

				if (hwlen >= sizeof(pif->hw_addr)) {
					hwlen = sizeof(pif->hw_addr);
				}	 

				pif->hw_addr_len = hwlen;

				std::memcpy(pif->hw_addr, phwaddr, hwlen);
			}
			
			break;

		case IFLA_BROADCAST :
			if (mnl_attr_validate(pattr, MNL_TYPE_BINARY) >= 0) {
				uint8_t 		*phwaddr = (uint8_t *)mnl_attr_get_payload(pattr);
				size_t 			hwlen = mnl_attr_get_payload_len(pattr);

				if (hwlen >= sizeof(pif->broadcast_addr)) {
					hwlen = sizeof(pif->broadcast_addr);
				}	 

				pif->broadcast_len = hwlen;

				std::memcpy(pif->broadcast_addr, phwaddr, hwlen);
			}
			
			break;

		case IFLA_NUM_TX_QUEUES :
			if (mnl_attr_validate(pattr, MNL_TYPE_U32) >= 0) {
				pif->ntx_queues = mnl_attr_get_u32(pattr);
			}	
			break;

		case IFLA_NUM_RX_QUEUES :
			if (mnl_attr_validate(pattr, MNL_TYPE_U32) >= 0) {
				pif->nrx_queues = mnl_attr_get_u32(pattr);
			}	
			break;

		case IFLA_GSO_MAX_SIZE :
			if (mnl_attr_validate(pattr, MNL_TYPE_U32) >= 0) {
				pif->gso_max_size = mnl_attr_get_u32(pattr);
			}	
			break;

		case IFLA_GSO_MAX_SEGS :
			if (mnl_attr_validate(pattr, MNL_TYPE_U32) >= 0) {
				pif->gso_max_segs = mnl_attr_get_u32(pattr);
			}	
			break;

		case IFLA_NUM_VF :
			if (mnl_attr_validate(pattr, MNL_TYPE_U32) >= 0) {
				pif->num_vf_sriov = mnl_attr_get_u32(pattr);
			}	
			break;

		case IFLA_STATS64 :
			attr_len = mnl_attr_get_payload_len(pattr);

			if (attr_len >= (uint16_t)sizeof(rtnl_link_stats64)) {

				struct rtnl_link_stats64	stats64;

				memcpy(&stats64, mnl_attr_get_payload(pattr), sizeof(stats64));

				pif->stats.tstats_usec	= get_usec_time();

				pif->stats.rx_packets 	= stats64.rx_packets;
				pif->stats.tx_packets	= stats64.tx_packets;
				 
				pif->stats.rx_bytes 	= stats64.rx_bytes;
				pif->stats.tx_bytes	= stats64.tx_bytes;
			}
			break;

		case IFLA_LINKINFO :
			{

				/*
				 * We cache both the IFLA_INFO_KIND && IFLA_INFO_SLAVE_KIND attr if present.
				 * Then if IFLA_INFO_SLAVE_KIND is present, we ignore the IFLA_INFO_KIND and create the
				 * corresponding if_kind struct
				 */
				const struct nlattr 		*pattr_kind = nullptr, *pattr_slave = nullptr, *pattr_kind_data = nullptr, 
								*pattr_slave_data = nullptr, *pattr_nest;

				gy_mnl_attr_for_each_nested(pattr_nest, pattr) {
					int type_nest = mnl_attr_get_type(pattr_nest);

					if (type_nest == IFLA_INFO_KIND) {
						pattr_kind = pattr_nest;
					}	
					else if (type_nest == IFLA_INFO_SLAVE_KIND) {
						pattr_slave = pattr_nest;
					}	
					else if (type_nest == IFLA_INFO_DATA) {
						pattr_kind_data = pattr_nest;
					}	
					else if (type_nest == IFLA_INFO_SLAVE_DATA) {
						pattr_slave_data = pattr_nest;
					}	
				}	

				if (pattr_slave && pattr_slave_data) {
					
					if (mnl_attr_validate(pattr_slave, MNL_TYPE_STRING) < 0) {
						break;
					}
					GY_STRNCPY(pif->if_kind_str, mnl_attr_get_str(pattr_slave), sizeof(pif->if_kind_str));

					if (0 == strcmp(pif->if_kind_str, "bond")) {
						pif->if_kind = IF_KIND_BOND_SLAVE;

						pif->is_bonding = true;

						pif->pbond_slave = new IF_LINK_BOND_SLAVE();

						gy_mnl_attr_for_each_nested(pattr_nest, pattr_slave_data) {
							int type_nest = mnl_attr_get_type(pattr_nest);

							switch (type_nest) {

							case IFLA_BOND_SLAVE_STATE :
								pif->pbond_slave->state = mnl_attr_get_u8(pattr_nest);
								break;
								
							case IFLA_BOND_SLAVE_MII_STATUS :
								pif->pbond_slave->mii_status_up = (mnl_attr_get_u8(pattr_nest) == 0);
								break;
								
							default :
								break;	

							}	
						}
					}	
					else if (0 == strcmp(pif->if_kind_str, "bridge")) {
						pif->if_kind = IF_KIND_BRIDGE_SLAVE;

						pif->is_bridge = true;

						pif->pbridge_slave = new IF_LINK_BRIDGE();

						gy_mnl_attr_for_each_nested(pattr_nest, pattr_slave_data) {
							int type_nest = mnl_attr_get_type(pattr_nest);

							switch (type_nest) {

							case IFLA_BRPORT_PRIORITY :
								pif->pbridge_slave->priority = mnl_attr_get_u16(pattr_nest);
								break;
								
							default :
								break;	
							}	
						}
					}
					else if (0 == strcmp(pif->if_kind_str, "vrf")) {
						pif->if_kind = IF_KIND_VRF_SLAVE;

						pif->pvrf_slave = new IF_LINK_VRF();

						gy_mnl_attr_for_each_nested(pattr_nest, pattr_slave_data) {
							int type_nest = mnl_attr_get_type(pattr_nest);

							switch (type_nest) {

							case IFLA_VRF_TABLE :
								pif->pvrf_slave->vrf_table = mnl_attr_get_u32(pattr_nest);
								break;
								
							default :
								break;	
							}	
						}
					}
					else if (0 == strcmp(pif->if_kind_str, "team")) {
						pif->if_kind = IF_KIND_TEAM_SLAVE;
					}
				}	
				else if (pattr_kind && pattr_kind_data) {

					if (mnl_attr_validate(pattr_kind, MNL_TYPE_STRING) < 0) {
						break;
					}
					GY_STRNCPY(pif->if_kind_str, mnl_attr_get_str(pattr_kind), sizeof(pif->if_kind_str));

					if (0 == strcmp(pif->if_kind_str, "bond")) {

						pif->if_kind = IF_KIND_BOND_MASTER;

						pif->is_bonding = true;

						pif->pbond_master = new IF_LINK_BOND_MASTER();

						auto pbond_master = pif->pbond_master;

						gy_mnl_attr_for_each_nested(pattr_nest, pattr_kind_data) {
							int type_nest = mnl_attr_get_type(pattr_nest);

							switch (type_nest) {

							case IFLA_BOND_MODE :
								pbond_master->mode = mnl_attr_get_u8(pattr_nest);
								break;
								
							case IFLA_BOND_ACTIVE_SLAVE :
								pbond_master->active_slave_ifi_index = mnl_attr_get_u32(pattr_nest);
								// active_slave_shr will be updated in second pass
								break;
								
							case IFLA_BOND_PRIMARY :
								pbond_master->primary_ifi_index = mnl_attr_get_u32(pattr_nest);
								// primary_ifi_shr will be updated in second pass
								break;
								
							case IFLA_BOND_ALL_SLAVES_ACTIVE :
								pbond_master->all_slaves_active = mnl_attr_get_u8(pattr_nest);
								break;
								
							case IFLA_BOND_MIN_LINKS :
								pbond_master->min_links = mnl_attr_get_u32(pattr_nest);
								break;
								
							case IFLA_BOND_PACKETS_PER_SLAVE :
								pbond_master->rr_packets_per_slave = mnl_attr_get_u32(pattr_nest);
								break;
								
							default :
								break;	

							}	
						}
						
						// pbond_master->slaves_shr_vec will be updated in second pass. Populate the slave ifids
						get_bond_slave_ids(sysfs_dir_fd, pif->ifname, pbond_master->slaves_index_vec);
					}
					else if (0 == strcmp(pif->if_kind_str, "bridge")) {
						pif->if_kind = IF_KIND_BRIDGE_MASTER;

						pif->is_bridge = true;

						pif->pbridge_master = new IF_LINK_BRIDGE();

						gy_mnl_attr_for_each_nested(pattr_nest, pattr_kind_data) {
							int type_nest = mnl_attr_get_type(pattr_nest);

							switch (type_nest) {

							case IFLA_BR_PRIORITY :
								pif->pbridge_master->priority = mnl_attr_get_u16(pattr_nest);
								break;
								
							default :
								break;	
							}	
						}
					}	
					else if (0 == strcmp(pif->if_kind_str, "vrf")) {
						pif->if_kind = IF_KIND_VRF_MASTER;

						pif->pvrf_master = new IF_LINK_VRF();

						gy_mnl_attr_for_each_nested(pattr_nest, pattr_kind_data) {
							int type_nest = mnl_attr_get_type(pattr_nest);

							switch (type_nest) {

							case IFLA_VRF_TABLE :
								pif->pvrf_master->vrf_table = mnl_attr_get_u32(pattr_nest);
								break;
								
							default :
								break;	
							}	
						}
					}	
					else if (0 == strcmp(pif->if_kind_str, "geneve")) {
						pif->if_kind = IF_KIND_GENEVE;

						pif->is_geneve_tunnel = true;

						pif->pgeneve = new IF_LINK_GENEVE();

						gy_mnl_attr_for_each_nested(pattr_nest, pattr_kind_data) {
							int type_nest = mnl_attr_get_type(pattr_nest);

							switch (type_nest) {

							case IFLA_GENEVE_REMOTE :
								pif->pgeneve->remote_addr.set_ip(mnl_attr_get_u32(pattr_nest));
								break;
								
							case IFLA_GENEVE_REMOTE6 :

								attr_len = mnl_attr_get_payload_len(pattr_nest);
								if (attr_len == sizeof(__int128)) {
									unsigned __int128		ip;
									uint8_t 			*paddr = (uint8_t *)mnl_attr_get_payload(pattr_nest);

									std::memcpy(&ip, paddr, sizeof(ip));
									
									pif->pgeneve->remote_addr.set_ip(ip);
								}	
								break;
								
							case IFLA_GENEVE_PORT :
								attr_len = mnl_attr_get_payload_len(pattr_nest);
								if (attr_len == sizeof(uint16_t)) {
									pif->pvxlan->dstport = ntohs(mnl_attr_get_u16(pattr_nest));
								}	
								break;

							default :
								break;	
							}	
						}
					}	
					else if (0 == strcmp(pif->if_kind_str, "ipvlan")) {
						pif->if_kind = IF_KIND_IPVLAN;

						pif->pipvlan = new IF_LINK_IPVLAN();

						gy_mnl_attr_for_each_nested(pattr_nest, pattr_kind_data) {
							int type_nest = mnl_attr_get_type(pattr_nest);

							switch (type_nest) {

							case IFLA_IPVLAN_MODE :
								attr_len = mnl_attr_get_payload_len(pattr_nest);
								if (attr_len == sizeof(uint16_t)) {
									pif->pipvlan->mode = mnl_attr_get_u16(pattr_nest);
								}	
								break;
								
							case IFLA_IPVLAN_FLAGS :
								attr_len = mnl_attr_get_payload_len(pattr_nest);
								if (attr_len == sizeof(uint16_t)) {
									pif->pipvlan->ipvflags = mnl_attr_get_u16(pattr_nest);
								}	
								break;

							default :
								break;	
							}	
						}

					}	
					else if ((0 == strcmp(pif->if_kind_str, "macvlan")) || (0 == strcmp(pif->if_kind_str, "macvtap"))) {
						if (0 == strcmp(pif->if_kind_str, "macvlan")) {
							pif->if_kind = IF_KIND_MACVLAN;
						}
						else {
							pif->if_kind = IF_KIND_MACVTAP;
						}	

						pif->pmacvlan = new IF_LINK_MACVLAN_TAP();

						gy_mnl_attr_for_each_nested(pattr_nest, pattr_kind_data) {
							int type_nest = mnl_attr_get_type(pattr_nest);

							switch (type_nest) {

							case IFLA_MACVLAN_MODE :
								attr_len = mnl_attr_get_payload_len(pattr_nest);
								if (attr_len == sizeof(uint32_t)) {
									pif->pmacvlan->mode = mnl_attr_get_u32(pattr_nest);
								}	
								break;

							default :
								break;	
							}	
						}
					}	
					else if (0 == strcmp(pif->if_kind_str, "vxlan")) {
						pif->if_kind = IF_KIND_VXLAN;

						pif->is_vxlan_tunnel = true;

						pif->pvxlan = new IF_LINK_VXLAN();

						gy_mnl_attr_for_each_nested(pattr_nest, pattr_kind_data) {
							int type_nest = mnl_attr_get_type(pattr_nest);

							switch (type_nest) {

							case IFLA_VXLAN_GROUP :
								attr_len = mnl_attr_get_payload_len(pattr_nest);
								if (attr_len == sizeof(uint32_t)) {
									pif->pvxlan->remote_addr.set_ip(mnl_attr_get_u32(pattr_nest));
								}	
								break;
								
							case IFLA_VXLAN_GROUP6 :
								attr_len = mnl_attr_get_payload_len(pattr_nest);
								if (attr_len == sizeof(__int128)) {
									unsigned __int128		ip;
									uint8_t 			*paddr = (uint8_t *)mnl_attr_get_payload(pattr_nest);

									std::memcpy(&ip, paddr, sizeof(ip));
									
									pif->pvxlan->remote_addr_6.set_ip(ip);
								}	
								break;

							case IFLA_VXLAN_LOCAL :
								attr_len = mnl_attr_get_payload_len(pattr_nest);
								if (attr_len == sizeof(uint32_t)) {
									pif->pvxlan->local_addr.set_ip(mnl_attr_get_u32(pattr_nest));
								}	
								break;
								
							case IFLA_VXLAN_LOCAL6 :
								attr_len = mnl_attr_get_payload_len(pattr_nest);
								if (attr_len == sizeof(__int128)) {
									unsigned __int128		ip;
									uint8_t 			*paddr = (uint8_t *)mnl_attr_get_payload(pattr_nest);

									std::memcpy(&ip, paddr, sizeof(ip));
									
									pif->pvxlan->local_addr_6.set_ip(ip);
								}	
								break;

							case IFLA_VXLAN_LINK :
								attr_len = mnl_attr_get_payload_len(pattr_nest);
								if (attr_len == sizeof(uint32_t)) {
									pif->pvxlan->device_id = mnl_attr_get_u32(pattr_nest);

									// device_shr will be updated in second pass
								}	
								break;

							case IFLA_VXLAN_PORT :
								attr_len = mnl_attr_get_payload_len(pattr_nest);
								if (attr_len == sizeof(uint16_t)) {
									pif->pvxlan->dstport = ntohs(mnl_attr_get_u16(pattr_nest));
								}	
								break;

							default :
								break;	
							}	
						}
					}	
					else if (0 == strcmp(pif->if_kind_str, "ipoib")) {
						pif->if_kind = IF_KIND_IPOIB;

						pif->is_infiniband = true;
					}	
					else if (0 == strcmp(pif->if_kind_str, "team")) {
						pif->if_kind = IF_KIND_TEAM_MASTER;

						// Currently we do not save any team slaves as the netlink message does not provide any data.
					}	
					else if (0 == strcmp(pif->if_kind_str, "vlan")) {
						pif->is_vlan = true;
					}
				}	
			}
			break;	

		default :
			break;

		}
	}

	// Update speed as Netlink does not provide this

	char				buf[256];

	snprintf(buf, sizeof(buf), "./class/net/%s/speed", pif->ifname);

	SCOPE_FD			ifscopefd(sysfs_dir_fd, buf, O_RDONLY, 0640);
	int				ret, ifd, speed;
	bool				bret;
	
	ifd = ifscopefd.get();
	if (ifd > 0) {
		ret = read(ifd, buf, sizeof(buf) - 1);
		if (ret > 0) {
			buf[ret] = '\0';
			
			bret = string_to_number(buf, speed);
			if (bret && speed != -1) {
				pif->speed_mbps = speed;
			}	
		}
	}

	pif->last_chk_usec_time.store(get_usec_time(), std::memory_order_release);

	return 0;
}

int NET_IF_HDLR::add_if_from_cb(const struct nlmsghdr *pnlh) noexcept
{
	try {
		int			ret;
		IF_LINK			*pif;
		
		pif = new IF_LINK();

		GY_SCOPE_EXIT {
			if (pif) delete pif;
		};	
		
		ret = get_if_from_nlm(pif, pnlh, true /* ignore_del */);
		
		if (ret == 0) {
			/*
			 * Now add the pif to the iftable. The pending weak_ptrs will be updated once the NL msg is over.
			 */
			DEBUGEXECN(1, 
				
				char		ibuf[1024];

				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Adding new interface to iftable : %s\n", pif->print_info_str(ibuf, sizeof(ibuf) - 1));
			);	

			NET_IF_ELEM_TYPE		*pelem;

			pelem = new NET_IF_ELEM_TYPE(pif);

			iftable.template insert_or_replace<RCU_LOCK_SLOW>(pelem, pif->ifi_index, get_int_hash(pif->ifi_index));

			pif = nullptr;
		}	 

		return MNL_CB_OK;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT("Exception caught while populating interface from netlink : %s\n", GY_GET_EXCEPT_STRING);
		return MNL_CB_STOP;
	);
}	

int NET_IF_HDLR::add_addr_from_cb(const struct nlmsghdr *pnlh) noexcept
{
	try {
		struct ifaddrmsg 		*pifa = static_cast<ifaddrmsg *>(mnl_nlmsg_get_payload(pnlh));
		struct nlattr 			*pattr;
		uint16_t 			attr_len;

		if (pnlh->nlmsg_type != RTM_NEWADDR) {
			return MNL_CB_OK;
		}	

		if (mnl_nlmsg_get_payload_len(pnlh) < sizeof(*pifa)) {
			DEBUGEXECN(1, ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Invalid Netlink message length seen %lu while populating interface addresses\n", 
				mnl_nlmsg_get_payload_len(pnlh)););
			return MNL_CB_STOP;
		}	

		RCU_DEFER_OFFLINE		slowlock;

		/*
		 * Now iterate over the NLMsg
		 */
		gy_mnl_attr_for_each(pattr, pnlh, sizeof(*pifa)) {
			int 			id, type = mnl_attr_get_type(pattr);

			/* skip unsupported attribute in user-space */
			if (mnl_attr_type_valid(pattr, IFA_MAX) < 0) {
				continue;
			}	

			switch (type) {

			case IFA_ADDRESS :
				if (mnl_attr_validate(pattr, MNL_TYPE_BINARY) < 0) {
					return MNL_CB_ERROR;
				}
				else {
					uint8_t 		*paddr = (uint8_t *)mnl_attr_get_payload(pattr);
					uint32_t		addr32 = 0;
					unsigned __int128	addr128 = 0;	

					if (pifa->ifa_family == AF_INET) {
						std::memcpy(&addr32, paddr, sizeof(addr32));
					}	
					else if (pifa->ifa_family == AF_INET6) {
						std::memcpy(&addr128, paddr, sizeof(addr128));
					}	
					else {
						return MNL_CB_OK;
					}	
					
					auto 		lupdate = [&, pifa](NET_IF_ELEM_TYPE *pdatanode, void *arg1, void *arg2) -> CB_RET_E
					{
						auto		pif = pdatanode->get_data()->get();

						if (pif == nullptr) {
							return CB_OK;
						}
						
						if (pifa->ifa_family == AF_INET) {
							if (pifa->ifa_scope == RT_SCOPE_UNIVERSE) {
								pif->addr.univeral_ipv4.set_ip(addr32);
							}
							else if (pifa->ifa_scope == RT_SCOPE_HOST) {
								pif->addr.host_ipv4.set_ip(addr32);		
							}		
							else if (pifa->ifa_scope == RT_SCOPE_LINK) {
								pif->addr.link_ipv4.set_ip(addr32);
							}	
						}	
						else {
							if (pifa->ifa_scope == RT_SCOPE_UNIVERSE) {
								pif->addr.univeral_ipv6.set_ip(addr128);
							}
							else if (pifa->ifa_scope == RT_SCOPE_LINK) {
								pif->addr.link_ipv6.set_ip(addr128);
							}	
							else if (pifa->ifa_scope == RT_SCOPE_HOST) {
								pif->addr.host_ipv6.set_ip(addr128);		
							}		
							else if (pifa->ifa_scope == RT_SCOPE_SITE) {
								pif->addr.site_ipv6.set_ip(addr128);		
							}		
						}	

						return CB_OK;
					};	

					id = pifa->ifa_index;

					iftable.lookup_single_elem(id, get_int_hash(id), lupdate);
				}
				break;

			default :
				break;
			}
		}

		return MNL_CB_OK;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT("Exception caught while populating interface addresses from netlink : %s\n", GY_GET_EXCEPT_STRING);
		return MNL_CB_STOP;
	);

}	


int NET_IF_HDLR::update_if_from_cb(const struct nlmsghdr *pnlh) noexcept
{
	try {
		int			ret, id;
		bool			bret;
		IF_LINK			*pif;
		
		pif = new IF_LINK();

		GY_SCOPE_EXIT {
			if (pif) delete pif;
		};	
		
		ret = get_if_from_nlm(pif, pnlh, true /* ignore_del */);
		
		if (ret == 0) {
			/*
			 * Now update the weak_ptrs and then run the comparison with the iftable struct. If iftable
			 * struct not present then add to iftable
			 */
			pif->update_weak_ptrs(iftable);

			RCU_DEFER_OFFLINE	slowlock;

			auto 		lcompare = [](NET_IF_ELEM_TYPE *pdatanode, void *arg1, void *arg2) -> CB_RET_E
			{
				auto				pif = pdatanode->get_data()->get();
				decltype(pif)			pnew = (decltype(pif))arg1;

				if (pif == nullptr) {
					return CB_DELETE_ELEM;
				}
				
				pif->update_on_change(std::move(*pnew));

				return CB_OK;
			};	

			id = pif->ifi_index;

			bret = iftable.lookup_single_elem(id, get_int_hash(id), lcompare, pif, nullptr);
			if (bret == false) {
				DEBUGEXECN(1, 
					
					char		ibuf[1024];

					INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Adding newly added interface to iftable : %s\n", pif->print_info_str(ibuf, sizeof(ibuf) - 1));
				);	

				NET_IF_ELEM_TYPE		*pelem;

				pelem = new NET_IF_ELEM_TYPE(pif);

				iftable.insert_or_replace(pelem, pif->ifi_index, get_int_hash(pif->ifi_index));

				pif = nullptr;
			}
		}	 

		return MNL_CB_OK;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT("Exception caught while checking interface for changes from netlink : %s\n", GY_GET_EXCEPT_STRING);
		return MNL_CB_STOP;
	);
}	

int NET_IF_HDLR::update_addr_from_cb(const struct nlmsghdr *pnlh) noexcept
{
	try {
		struct ifaddrmsg 		*pifa = static_cast<ifaddrmsg *>(mnl_nlmsg_get_payload(pnlh));
		struct nlattr 			*pattr;
		uint16_t 			attr_len;

		if (pnlh->nlmsg_type != RTM_NEWADDR) {
			return MNL_CB_OK;
		}	

		if (mnl_nlmsg_get_payload_len(pnlh) < sizeof(*pifa)) {
			DEBUGEXECN(1, ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Invalid Netlink message length seen %lu while getting interface addresses\n", 
				mnl_nlmsg_get_payload_len(pnlh)););
			return MNL_CB_STOP;
		}	

		RCU_DEFER_OFFLINE		slowlock;

		/*
		 * Now iterate over the NLMsg
		 */
		gy_mnl_attr_for_each(pattr, pnlh, sizeof(*pifa)) {
			int 			id, type = mnl_attr_get_type(pattr);

			/* skip unsupported attribute in user-space */
			if (mnl_attr_type_valid(pattr, IFA_MAX) < 0) {
				continue;
			}	

			switch (type) {

			case IFA_ADDRESS :
				if (mnl_attr_validate(pattr, MNL_TYPE_BINARY) < 0) {
					return MNL_CB_ERROR;
				}
				else {
					uint8_t 		*paddr = (uint8_t *)mnl_attr_get_payload(pattr);
					uint32_t		addr32 = 0;
					unsigned __int128	addr128 = 0;	
					GY_IP_ADDR		addr;	

					if (pifa->ifa_family == AF_INET) {
						std::memcpy(&addr32, paddr, sizeof(addr32));
						addr.set_ip(addr32);
					}	
					else if (pifa->ifa_family == AF_INET6) {
						std::memcpy(&addr128, paddr, sizeof(addr128));
						addr.set_ip(addr128);
					}	
					else {
						return MNL_CB_OK;
					}	
					
					auto lchkupdate = [&, pifa](NET_IF_ELEM_TYPE *pdatanode, void *arg1, void *arg2) -> CB_RET_E
					{
						auto		pif = pdatanode->get_data()->get();

						if (pif == nullptr) {
							return CB_OK;
						}
						
						if (pifa->ifa_family == AF_INET) {
							if (pifa->ifa_scope == RT_SCOPE_UNIVERSE) {
								if (!(pif->addr.univeral_ipv4 == addr)) {
				
									pif->addr.univeral_ipv4 = addr;

									DEBUGEXECN(1, 
									char		tbuf[256];
									INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Interface %s (%d) Universal IPv4 Address changed to %s\n",
										pif->ifname, pif->ifi_index, pif->addr.univeral_ipv4.printaddr(tbuf, sizeof(tbuf) - 1));	
									);	
								}	
							}
							else if (pifa->ifa_scope == RT_SCOPE_HOST) {
								if (!(pif->addr.host_ipv4 == addr)) {
				
									pif->addr.host_ipv4 = addr;

									DEBUGEXECN(1, 
									char		tbuf[256];
									INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Interface %s (%d) Host Scope IPv4 Address changed to %s\n",
										pif->ifname, pif->ifi_index, pif->addr.host_ipv4.printaddr(tbuf, sizeof(tbuf) - 1));	
									);
								}	

							}		
							else if (pifa->ifa_scope == RT_SCOPE_LINK) {
								if (!(pif->addr.link_ipv4 == addr)) {
				
									pif->addr.link_ipv4 = addr;

									DEBUGEXECN(1, 
									char		tbuf[256];
									INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Interface %s (%d) Link Scope IPv4 Address changed to %s\n",
										pif->ifname, pif->ifi_index, pif->addr.link_ipv4.printaddr(tbuf, sizeof(tbuf) - 1));	
									);
								}	
							}	
						}	
						else {
							if (pifa->ifa_scope == RT_SCOPE_UNIVERSE) {
								if (!(pif->addr.univeral_ipv6 == addr)) {
				
									pif->addr.univeral_ipv6 = addr;

									DEBUGEXECN(1, 
									char		tbuf[256];
									INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Interface %s (%d) Universal IPv6 Address changed to %s\n",
										pif->ifname, pif->ifi_index, pif->addr.univeral_ipv6.printaddr(tbuf, sizeof(tbuf) - 1));	
									);
								}	
							}
							else if (pifa->ifa_scope == RT_SCOPE_HOST) {
								if (!(pif->addr.host_ipv6 == addr)) {
				
									pif->addr.host_ipv6 = addr;

									DEBUGEXECN(1, 
									char		tbuf[256];
									INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Interface %s (%d) Host Scope IPv6 Address changed to %s\n",
										pif->ifname, pif->ifi_index, pif->addr.host_ipv6.printaddr(tbuf, sizeof(tbuf) - 1));	
									);
								}	

							}		
							else if (pifa->ifa_scope == RT_SCOPE_LINK) {
								if (!(pif->addr.link_ipv6 == addr)) {
				
									pif->addr.link_ipv6 = addr;

									DEBUGEXECN(1, 
									char		tbuf[256];
									INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Interface %s (%d) Link Scope IPv6 Address changed to %s\n",
										pif->ifname, pif->ifi_index, pif->addr.link_ipv6.printaddr(tbuf, sizeof(tbuf) - 1));	
									);
								}	
							}	
							else if (pifa->ifa_scope == RT_SCOPE_SITE) {
								if (!(pif->addr.site_ipv6 == addr)) {
				
									pif->addr.site_ipv6 = addr;

									DEBUGEXECN(1, 
									char		tbuf[256];
									INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Interface %s (%d) Site Scope IPv6 Address changed to %s\n",
										pif->ifname, pif->ifi_index, pif->addr.site_ipv6.printaddr(tbuf, sizeof(tbuf) - 1));	
									);
								}	
							}	
						}	

						return CB_OK;
					};	

					id = pifa->ifa_index;

					iftable.lookup_single_elem(id, get_int_hash(id), lchkupdate);
				}
				break;

			default :
				break;
			}
		}

		return MNL_CB_OK;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT("Exception caught while checking getting interface addresses : %s\n", GY_GET_EXCEPT_STRING);
		return MNL_CB_STOP;
	);
}	


mnl_socket * NET_IF_HDLR::send_netlink_req(char *pmnlbuf, uint32_t & seqout, uint32_t & portidout, bool get_link_info) noexcept
{
	int			ret;
	struct mnl_socket 	*pnl, *pnlret = nullptr;
	struct nlmsghdr 	*nlh;
	struct rtgenmsg 	*rt;
	uint32_t 		seq, portid;

	pnl = mnl_socket_open(NETLINK_ROUTE);
	if (pnl == nullptr) {
		PERRORPRINT("Netlink socket open failed");
		return nullptr;
	}
	pnlret = pnl;

	GY_SCOPE_EXIT {
		if (pnl) {
			mnl_socket_close(pnl);
		}	
	};

	if (mnl_socket_bind(pnl, 0, MNL_SOCKET_AUTOPID) < 0) {
		PERRORPRINT("Netlink socket bind failed");
		return nullptr;
	}

	portid = mnl_socket_get_portid(pnl);
	portidout = portid;

	nlh = mnl_nlmsg_put_header(pmnlbuf);

	if (get_link_info) {
		nlh->nlmsg_type	= RTM_GETLINK;
	}
	else {
		nlh->nlmsg_type	= RTM_GETADDR;
	}		

	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = seq = time(nullptr);
	seqout = seq;

	rt = (decltype(rt))mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtgenmsg));

	if (get_link_info) {
		rt->rtgen_family = AF_PACKET;
	}
	else {
		rt->rtgen_family = AF_UNSPEC;
	}		

	if (mnl_socket_sendto(pnl, nlh, nlh->nlmsg_len) < 0) {
		PERRORPRINT("Netlink socket sendto failed");
		return nullptr;
	}
	
	pnl = nullptr;

	return pnlret;
}	

std::weak_ptr<IF_LINK>	NET_IF_HDLR::get_link_from_ip(const GY_IP_ADDR & addr, IF_SCOPE_E scope) const noexcept
{
	std::weak_ptr<IF_LINK>		weakif;
	bool				is_ipv4;

	is_ipv4 = addr.is_ipv4_addr();

	if (scope == IF_SCOPE_ANY) {
		// Get the scope from the IP

		if (addr.is_link_local_addr()) {
			scope = IF_SCOPE_LINK;
		}
		else if (addr.is_loopback()) {
			scope = IF_SCOPE_HOST;	
		}
		else scope = IF_SCOPE_UNIVERSAL;	// Ignore IF_SCOPE_SITE		
	}
	

	auto 				lambda1 = [&](NET_IF_ELEM_TYPE *pdatanode, void *arg1) -> CB_RET_E
	{
		auto			pif = pdatanode->get_data()->get();

		if (pif) {
			switch (scope) {
			
			case IF_SCOPE_UNIVERSAL :
				if (is_ipv4) {
					if (pif->addr.univeral_ipv4 == addr) {
						weakif = pif->weak_from_this();
						return CB_BREAK_LOOP;
					}	
				}	
				else {
					if (pif->addr.univeral_ipv6 == addr) {
						weakif = pif->weak_from_this();
						return CB_BREAK_LOOP;
					}
				}	
				break;

			case IF_SCOPE_LINK :
				if (is_ipv4) {
					if (pif->addr.link_ipv4 == addr) {
						weakif = pif->weak_from_this();
						return CB_BREAK_LOOP;
					}	
				}	
				else {
					if (pif->addr.link_ipv6 == addr) {
						weakif = pif->weak_from_this();
						return CB_BREAK_LOOP;
					}
				}	
				break;
			
			case IF_SCOPE_HOST :
				if (is_ipv4) {
					if (pif->addr.host_ipv4 == addr) {
						weakif = pif->weak_from_this();
						return CB_BREAK_LOOP;
					}	
				}	
				else {
					if (pif->addr.host_ipv6 == addr) {
						weakif = pif->weak_from_this();
						return CB_BREAK_LOOP;
					}
				}	
				break;
			
			case IF_SCOPE_SITE :
				if (pif->addr.site_ipv6 == addr) {
					weakif = pif->weak_from_this();
					return CB_BREAK_LOOP;
				}	
				break;

			default :
				break;	
			}	
		}
			 
		return CB_OK;
	};	

	iftable.walk_hash_table_const(lambda1, nullptr); 	

	return weakif;
}	

void NET_IF_HDLR::print_net_iflink_info(void) const
{
	int			n = 1;

	auto 			lambda1 = [&](NET_IF_ELEM_TYPE *pdatanode, void *arg1) -> CB_RET_E
	{
		auto		pif = pdatanode->get_data()->get();

		if (pif) {
			char		tbuf[4096];

			IRPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "[#%d] : %s\n", n++, pif->print_info_str(tbuf, sizeof(tbuf) - 1));
		}	
		return CB_OK;
	};	

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Network Interface Information follows : \n\n");

	iftable.walk_hash_table_const(lambda1, nullptr); 	
}
	
NET_IF_HDLR::NET_IF_HDLR(int proc_dir_fd, int sysfs_dir_fd, ino_t nsinode, bool is_root_ns)
	: proc_dir_fd(proc_dir_fd), sysfs_dir_fd(sysfs_dir_fd), netns_inode(nsinode), is_root_ns(is_root_ns)
{
	populate_iflist();
}	



} // namespace gyeeta	

