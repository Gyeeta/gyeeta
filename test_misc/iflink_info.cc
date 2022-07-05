
#include		"gy_common_inc.h"
#include 		"gy_netif.h"
#include 		"gy_inet_inc.h"
#include		"gy_file_api.h"

#include		<dirent.h>

using namespace 	gyeeta;

static int if_data_cb(const struct nlmsghdr *nlh, void *arg)
{
	STR_WR_BUF 			*pstrbuf = (decltype(pstrbuf))(arg);	
	struct ifinfomsg	 	*ifm = (ifinfomsg *)mnl_nlmsg_get_payload(nlh);
	struct nlattr 			*attr;
	uint16_t 			attr_len;

	pstrbuf->appendfmt("ifindex = %d Type = %hd Flags = 0x%08X Family = %d ", 
		ifm->ifi_index, ifm->ifi_type, ifm->ifi_flags, ifm->ifi_family);

	if (ifm->ifi_flags & IFF_RUNNING) {
		pstrbuf->append("[RUNNING] ");
	}	
	else {
		pstrbuf->append("[NOT RUNNING] ");
	}	

	gy_mnl_attr_for_each(attr, nlh, sizeof(*ifm)) {
		int type = mnl_attr_get_type(attr);

		/* skip unsupported attribute in user-space */
		if (mnl_attr_type_valid(attr, IFLA_MAX) < 0) {
			continue;
		}	

		switch (type) {

		case IFLA_MTU :
			if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
				pstrbuf->append("MTU : -1 ");
			}
			else {
				pstrbuf->appendfmt("MTU : %u ", mnl_attr_get_u32(attr));
			}	
			break;

		case IFLA_IFNAME :
			if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
				PERRORPRINT("mnl_attr_validate for ifname failed");
				return MNL_CB_ERROR;
			}
			pstrbuf->appendfmt("Name = %s ", mnl_attr_get_str(attr));
			break;

		case IFLA_ADDRESS :
			if (mnl_attr_validate(attr, MNL_TYPE_BINARY) < 0) {
				PERRORPRINT("mnl_attr_validate for if address failed");
				return MNL_CB_ERROR;
			}
			else {
				uint8_t *hwaddr = (uint8_t *)mnl_attr_get_payload(attr);

				pstrbuf->append("HWAddr = ");

				for (int i = 0; i < mnl_attr_get_payload_len(attr); i++) {
					pstrbuf->appendfmt("%.2x:", hwaddr[i] & 0xff);
				}
				pstrbuf->set_last_char(' ');	// Reset the last ':'
			}
			
			break;
	
		case IFLA_STATS64 :
			attr_len = mnl_attr_get_payload_len(attr);

			if (attr_len >= (uint16_t)sizeof(rtnl_link_stats64)) {

				struct rtnl_link_stats64	*pstats64;

				pstats64 = (decltype(pstats64))mnl_attr_get_payload(attr);

				pstrbuf->appendfmt(": Stats - rx_packets %llu rx_bytes %llu tx_packets %llu tx_bytes %llu\n", 
					pstats64->rx_packets, pstats64->rx_bytes, pstats64->tx_packets, pstats64->tx_bytes);

			}

			break;
		}
	}

	return MNL_CB_OK;
}

static int inet_info_ns(ino_t nsinode, int netns_fd)
{
	int			ret;
	char			buf1[GY_MNL_SOCKET_BUFFER_SIZE];
	STR_WR_BUF		strbuf(buf1, sizeof(buf1));

	INFOPRINT("Inet Interface info for NetNS %lu follows...\n", nsinode);

	ret = setns(netns_fd, CLONE_NEWNET);
	if (ret == -1) {
		PERRORPRINT("Failed to setns for inode %lu", nsinode);
		return -1;
	}	

	struct mnl_socket 	*nl;
	char 			buf[GY_MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr 	*nlh;
	struct rtgenmsg 	*rt;
	uint32_t 		seq, portid;

	nl = mnl_socket_open(NETLINK_ROUTE);
	if (nl == NULL) {
		PERRORPRINT("mnl_socket_open failed");
		return -1;
	}

	GY_SCOPE_EXIT {
		mnl_socket_close(nl);
	};

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		PERRORPRINT("mnl_socket_bind failed");
		return -1;
	}

	portid = mnl_socket_get_portid(nl);

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= RTM_GETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = seq = time(NULL);

	rt = (decltype(rt))mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtgenmsg));
	rt->rtgen_family = AF_PACKET;

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		PERRORPRINT("mnl_socket_sendto failed");
		return -1;
	}

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, seq, portid, if_data_cb, (void *)&strbuf);
		if (ret <= MNL_CB_STOP)
			break;
		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	}
	if (ret == -1) {
		PERRORPRINT("Error while receiving Netlink data");
		return -1;
	}

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Inet Info : \n%s\n\n", buf1);

	return 0;
}	

int inet_iflist(int niter)
{
	using ns_net_map_u 		= std::map<uint64_t, int>;
	
	EXEC_TIME			prof1(__FUNCTION__, __LINE__);

	DIR				*pdir = nullptr, *ptaskdir = nullptr;

	try {
		ns_net_map_u			nsmap;
		int				fd, ret;
		bool				bret;

		/*
		 * First scan all tasks in system to get the list of unique Network Namespaces
		 */
		struct dirent			*pdent, *ptaskdent;
		char				*pfile, path[256], readstr[64], *pstr1, *ptaskfile;
		struct stat			stat1;
		uint64_t			ulval, ultaskval, inoval, pidnsval;

		pdir = opendir("/proc");
		if (!pdir) {
			PERRORPRINT("Could not open proc filesystem");
			return -1;
		}

		while ((pdent = readdir(pdir)) != NULL) {

			pfile = pdent->d_name;	
			
			pstr1 = nullptr;

			ret = string_to_number(pfile, ulval, &pstr1, 10);
			if (ret == 0) {
				if (pstr1 && *pstr1) {
					continue;
				}	
			}	
			else {
				continue;
			}	

			pidnsval = 0;

			snprintf(path, sizeof(path), "/proc/%lu/task", ulval);

			ptaskdir = opendir(path);
			if (!ptaskdir) {
				continue;
			}	

			while ((ptaskdent = readdir(ptaskdir)) != NULL) {

				ptaskfile = ptaskdent->d_name;	
				
				pstr1 = nullptr;

				bret = string_to_number(ptaskfile, ultaskval, &pstr1, 10);
				if (bret) {
					if (pstr1 && *pstr1) {
						continue;
					}	
				}	
				else {
					continue;
				}	

				snprintf(path, sizeof(path), "/proc/%lu/task/%lu/ns/net", ulval, ultaskval);

				ret = readlink(path, readstr, sizeof(readstr) - 1);
				if (ret > 5) {
					readstr[ret] = '\0';

					inoval = strtoul(readstr + 5, nullptr, 10);

					if (!((inoval > 0) && (ultaskval < ULONG_MAX))) {
						continue;
					}

					if (pidnsval == inoval) {
						continue;
					}	

					pidnsval = inoval;

					auto it = nsmap.find(inoval);
					if (it == nsmap.end()) {
						INFOPRINT("New Network Namespace %lu seen for PID %lu Thread %lu\n", inoval, ulval, ultaskval);

						fd = open(path, O_RDONLY);
						if (fd == -1) {
							PERRORPRINT("Could not open Namespace file for PID %lu Thread %lu", ulval, ultaskval);
							break;
						}	

						nsmap[inoval] = fd;
					}	
				}	
			}

			closedir(ptaskdir);

			ptaskdir = nullptr;
		}

		closedir(pdir);

		pdir = nullptr;

		prof1.print_current_exec_time();

	 	INFOPRINT("Total number of Network Namespaces is %lu\n", nsmap.size());
	 	
		for (int i = 0; i < niter; ++i) {	
			for (auto && it : nsmap) {
				inet_info_ns(it.first, it.second);
			}	

			if (i + 1 < niter) {
				gy_nanosleep(1, 0);
			}
		}
	 
		for (auto && it : nsmap) {
			if (it.second > 0) close(it.second);
		}	

		INFOPRINT("Now exiting from process since all NS net if info completed...\n\n");

	 	return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT("Caught Exception while getting list of Namespaces : %s\n", GY_GET_EXCEPT_STRING);
		if (ptaskdir) closedir(ptaskdir);
		if (pdir) closedir(pdir);
		return -1;
	);
}	


int main(int argc, char **argv)
{
	int			niter = 1;

	gdebugexecn = 1;

	if (argc > 1) {
		niter = atoi(argv[1]);
	}	

	return inet_iflist(niter);
}	

