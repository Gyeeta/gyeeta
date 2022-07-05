
#include 		"tcptracer_user.h"
#include 		"gy_inet_inc.h"

#include 		<poll.h>

#include		"libmnl/libmnl.h"
#include 		"linux/netfilter/nfnetlink.h"
#include 		"linux/netfilter/nfnetlink_conntrack.h"

#include 		<linux/netlink.h>
#include 		<linux/rtnetlink.h>
#include 		<netinet/in.h>
/* #include 		<linux/tcp.h> */
#include 		<linux/sock_diag.h>
#include 		<linux/inet_diag.h>
#include 		<pwd.h>

using namespace		gyeeta;


#define GY_TCP_ALL_FLAGS 		((1 << GY_TCP_MAX_STATES) - 1)
#define GY_SOCK_DIAG_FLAGS 		(GY_TCP_ALL_FLAGS & ~((1 << GY_TCP_LISTEN) | (1 << GY_TCP_CLOSE) | (1 << GY_TCP_TIME_WAIT) | (1 << GY_TCP_SYN_RECV) | (1 << GY_TCP_NEW_SYN_RECV)))

#define GY_TCP_MAGIC_SEQ 		123456
#define GY_INET_BUFFER_SIZE 		(16 * 1024)

static int sockdiag_send(int sockfd)
{
	struct sockaddr_nl 		nladdr = { .nl_family = AF_NETLINK };
	struct {
		struct nlmsghdr 	nlh;
		struct inet_diag_req 	r;
	} req = {};
	struct msghdr 			msg;
	struct iovec 			iov[3];
	int 				iovlen = 1;

	req.nlh.nlmsg_len 		= sizeof(req),
	req.nlh.nlmsg_flags 		= NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST,
	req.nlh.nlmsg_seq 		= GY_TCP_MAGIC_SEQ,
	req.nlh.nlmsg_type 		= TCPDIAG_GETSOCK;
	req.r.idiag_family 		= AF_INET,
	req.r.idiag_states 		= GY_SOCK_DIAG_FLAGS,

	req.r.idiag_ext 		|= (1 << (INET_DIAG_INFO - 1));

	iov[0] = (struct iovec) {
		.iov_base 		= &req,
		.iov_len 		= sizeof(req)
	};

	msg = (struct msghdr) {
		.msg_name 		= (void *)&nladdr,
		.msg_namelen 		= sizeof(nladdr),
		.msg_iov 		= iov,
		.msg_iovlen 		= (size_t)iovlen,
	};

	if (sendmsg(sockfd, &msg, 0) < 0) {
		PERRORPRINT("Could not send nl inet diag message");
		return -1;
	}

	return 0;
}

static int parse_diag_msg(struct inet_diag_msg *pdiag_msg, uint32_t rta_len)
{
	struct rtattr 			*attr;
	GY_TCP_CONN			connstat = {};

	uint8_t				idiag_family = pdiag_msg->idiag_family;
	uint32_t			addr32_be;
	unsigned __int128		addr128_be;
	uid_t				uid;
	GY_TCP_INFO	 		*info;
	TCP_INFO_STATS			tcpi;
	char				infobuf[512], tcpstatbuf[512];
	STR_WR_BUF	 		tcpss {tcpstatbuf, sizeof(tcpstatbuf)};

	connstat.conn_state = (GY_TCP_STATE_E)pdiag_msg->idiag_state;

	if (idiag_family == AF_INET) {
		memcpy(&addr32_be, pdiag_msg->id.idiag_src, sizeof(addr32_be));
		connstat.client_conn.ipaddr.set_ip(addr32_be);

		memcpy(&addr32_be, pdiag_msg->id.idiag_dst, sizeof(addr32_be));
		connstat.server_conn.ipaddr.set_ip(addr32_be);

	}	
	else {
		memcpy(&addr128_be, pdiag_msg->id.idiag_src, sizeof(addr128_be));
		connstat.client_conn.ipaddr.set_ip(addr128_be);

		memcpy(&addr128_be, pdiag_msg->id.idiag_dst, sizeof(addr128_be));
		connstat.server_conn.ipaddr.set_ip(addr128_be);
	}	

	connstat.client_conn.port = ntohs(pdiag_msg->id.idiag_sport);
	connstat.server_conn.port = ntohs(pdiag_msg->id.idiag_dport);

	uid = pdiag_msg->idiag_uid;

	connstat.client_conn.interface_num = pdiag_msg->id.idiag_if;

	*infobuf = '\0';
	*tcpstatbuf = '\0';

	connstat.get_conn_info_str(infobuf, sizeof(infobuf));

	for (attr = (struct rtattr *) (pdiag_msg + 1); RTA_OK(attr, rta_len); attr = RTA_NEXT(attr, rta_len)) {
		if (attr->rta_type == INET_DIAG_INFO) {

			int len = RTA_PAYLOAD(attr);

			/* workaround for older kernels with less fields */
			if ((uint32_t)len < sizeof(*info)) {
				info = (decltype(info))alloca(sizeof(*info));
				memcpy(info, RTA_DATA(attr), len);
				memset((char *)info + len, 0, sizeof(*info) - len);
			} else
				info = (decltype(info))RTA_DATA(attr);

			tcpi.populate_tcp_info(info);
			
			if (tcpi.is_recent_activity(1000)) {
				tcpi.print_tcpinfo_str(tcpss);
			}	
			
			break;
		}
	}

	if (*tcpstatbuf) {	
		INFOPRINT("TCP Connection : %s : Stats %s\n\n", infobuf, tcpstatbuf);
	}	

	return 0;
}	

static int do_inet_diag_info(void)
{
	static constexpr int		GY_NL_BUFFER_SIZE = 16 * 1024;
	int 				nl_sock = 0, numbytes = 0, rtalen = 0, inet_ret = -1, ret;
	struct nlmsghdr 		*nlh;
	uint8_t 			*pbuf;
	struct inet_diag_msg 		*pdiag_msg;
	struct sockaddr_nl 		addr;

	pbuf = new (std::nothrow) uint8_t[GY_NL_BUFFER_SIZE];
	if (!pbuf) {
		PERRORPRINT("Failed to allocate memory for task nl handler");
		return -1;
	}	

	GY_SCOPE_EXIT { delete [] pbuf; };

	struct iovec iov = {
		.iov_base	= pbuf,
		.iov_len	= GY_INET_BUFFER_SIZE,
	};

	struct msghdr msg = {
		.msg_name	= &addr,
		.msg_namelen	= sizeof(struct sockaddr_nl),
		.msg_iov	= &iov,
		.msg_iovlen	= 1,
		.msg_control	= NULL,
		.msg_controllen	= 0,
		.msg_flags	= 0,
	};

	if ((nl_sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG)) == -1) {
		PERRORPRINT("inet diag socket failed");
		goto done_ret;
	}

	try {
		if (sockdiag_send(nl_sock) < 0) {
			goto done_ret;
		}

		while (1) {
			int			msglen = 0;
			struct nlmsghdr 	*h;
			bool			found_done = false, dump_intr = false;

			ret = recvmsg(nl_sock, &msg, 0);
			if (ret == -1) {
				if (errno == EINTR || errno == EAGAIN) {
					if (gsig_rcvd.load()) {
						break;
					}	
					continue;
				}	

				PERRORPRINT("recv of inet diag failed");
				break;
			}	
			else if (ret == 0) {
				break;
			}	

			if (msg.msg_namelen != sizeof(struct sockaddr_nl)) {
				errno = EINVAL;
				PERRORPRINT("recv of inet diag failed due to invalid data len");
				break;
			}

			h = (struct nlmsghdr *)pbuf;

			msglen = ret;

			while (NLMSG_OK(h, (unsigned)msglen)) {
				if (h->nlmsg_flags & NLM_F_DUMP_INTR) {
					dump_intr = true;
				}	

				if (h->nlmsg_type == NLMSG_DONE) {
					found_done = true;
					break; 
				}

				if (h->nlmsg_type == NLMSG_ERROR) {
					ERRORPRINT("recv of inet diag failed due to invalid data\n");
					goto done_ret;
				}

				pdiag_msg = (struct inet_diag_msg *) NLMSG_DATA(h);

				rtalen = h->nlmsg_len - NLMSG_LENGTH(sizeof(*pdiag_msg));

				parse_diag_msg(pdiag_msg, rtalen);

				h = NLMSG_NEXT(h, msglen);
			}

			if (found_done) {
				if (dump_intr) {
					DEBUGEXECN(1, INFOPRINT("inet diag dump was interrupted and may be inconsistent.\n"));
				}	
				break;
			}

			if (msg.msg_flags & MSG_TRUNC) {
				DEBUGEXECN(1, INFOPRINT("inet Message truncated\n"));
				continue;
			}
			if (msglen) {
				ERRORPRINT("inet diag messgae still remains of size %d\n", msglen);
				goto done_ret;
			}
		}	
		
		inet_ret = 0;
		
	}
	GY_CATCH_EXCEPTION(ERRORPRINT("Exception caught while query inet info : %s\n", GY_GET_EXCEPT_STRING));

done_ret :
	if (nl_sock > 0) {
		close(nl_sock);
	}	

	return inet_ret;
}	

void * inet_diag_thr(void *arg)
{
	int			ret;
	struct timespec 	tsleep;
	constexpr int		inet_sleep_interval = 5;

	do {
		clock_gettime(CLOCK_MONOTONIC, &tsleep);
		tsleep.tv_sec += inet_sleep_interval;

		ret = do_inet_diag_info();

		if (gsig_rcvd.load()) {
			INFOPRINT("Thread %s returning as signal %s received...\n", __FUNCTION__, gy_signal_str(gsig_rcvd.load()));
			break;
		}

		clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &tsleep, nullptr);

	} while (1);

	return (void *)0;
}	


int ct_data_cb(const struct nlmsghdr *pnlh, void *) noexcept
{
	try {
		struct nfgenmsg		 	*pdata = (nfgenmsg *)mnl_nlmsg_get_payload(pnlh);
		struct nlattr 			*pattr;
		uint16_t 			attr_len;
		bool				is_new_conn;
		GY_IP_ADDR 			cli_addr, ser_addr, cli_nat_addr, ser_nat_addr, dflt_addr;
		uint16_t			cli_port = 0, ser_port = 0, cli_nat_port = 0, ser_nat_port = 0;

		switch (pnlh->nlmsg_type & 0xFF) {
			case IPCTNL_MSG_CT_NEW:
				if (pnlh->nlmsg_flags & (NLM_F_CREATE|NLM_F_EXCL)) {
					is_new_conn = true;
				}	
				else {
					return MNL_CB_OK;
				}
				break;

			case IPCTNL_MSG_CT_DELETE:
				is_new_conn = false;
				break;

			default :
				return MNL_CB_OK;	
		}

		gy_mnl_attr_for_each(pattr, pnlh, sizeof(*pdata)) {
			int type = mnl_attr_get_type(pattr);

			/* skip unsupported attribute in user-space */
			if (mnl_attr_type_valid(pattr, CTA_MAX) < 0) {
				continue;
			}	

			switch (type) {
			
			case CTA_TUPLE_ORIG : {
				const struct nlattr 		*pattr_nest;

				gy_mnl_attr_for_each_nested(pattr_nest, pattr) {
					int type_nest = mnl_attr_get_type(pattr_nest);

					if (type_nest == CTA_TUPLE_PROTO) {
						const struct nlattr 		*pattr_nest2;

						gy_mnl_attr_for_each_nested(pattr_nest2, pattr_nest) {
							int type_nest2 = mnl_attr_get_type(pattr_nest2);
								
							if (type_nest2 == CTA_PROTO_NUM) {
								int proto = mnl_attr_get_u8(pattr_nest2);
								
								if (proto != IP_PROTO_TCP) {
									// XXX We currently ignore UDP Connections
									return MNL_CB_OK;
								}	
							}		
							else if (type_nest2 == CTA_PROTO_SRC_PORT) {
								if (mnl_attr_validate(pattr_nest2, MNL_TYPE_U16) >= 0) {
									cli_port = ntohs(mnl_attr_get_u16(pattr_nest2));
								}		
							}
							else if (type_nest2 == CTA_PROTO_DST_PORT) {
								if (mnl_attr_validate(pattr_nest2, MNL_TYPE_U16) >= 0) {
									ser_port = ntohs(mnl_attr_get_u16(pattr_nest2));
								}		
							}		
						}
					}
					else if (type_nest == CTA_TUPLE_IP) {
						const struct nlattr 		*pattr_nest2;

						gy_mnl_attr_for_each_nested(pattr_nest2, pattr_nest) {
							int type_nest2 = mnl_attr_get_type(pattr_nest2);
						
							if (type_nest2 == CTA_IP_V4_SRC) {

								if (mnl_attr_validate(pattr_nest2, MNL_TYPE_U32) >= 0) {
									cli_addr.set_ip(mnl_attr_get_u32(pattr_nest2));
								}
							}
							else if (type_nest2 == CTA_IP_V6_SRC) {

								attr_len = mnl_attr_get_payload_len(pattr_nest2);

								if (attr_len == sizeof(__int128)) {
									unsigned __int128	ip;
									uint8_t 		*paddr = (uint8_t *)mnl_attr_get_payload(pattr_nest2);

									std::memcpy(&ip, paddr, sizeof(ip));
									cli_addr.set_ip(ip);
								}	
							}
							else if (type_nest2 == CTA_IP_V4_DST) {

								if (mnl_attr_validate(pattr_nest2, MNL_TYPE_U32) >= 0) {
									ser_addr.set_ip(mnl_attr_get_u32(pattr_nest2));
								}
							}
							else if (type_nest2 == CTA_IP_V6_DST) {

								attr_len = mnl_attr_get_payload_len(pattr_nest2);

								if (attr_len == sizeof(__int128)) {
									unsigned __int128		ip;
									uint8_t 			*paddr = (uint8_t *)mnl_attr_get_payload(pattr_nest2);

									std::memcpy(&ip, paddr, sizeof(ip));
									ser_addr.set_ip(ip);
								}	
							}
						}
					}	
				}	

				break;
			}

			case CTA_TUPLE_REPLY : {
				const struct nlattr 		*pattr_nest;

				gy_mnl_attr_for_each_nested(pattr_nest, pattr) {
					int type_nest = mnl_attr_get_type(pattr_nest);

					if (type_nest == CTA_TUPLE_PROTO) {
						const struct nlattr 		*pattr_nest2;

						gy_mnl_attr_for_each_nested(pattr_nest2, pattr_nest) {
							int type_nest2 = mnl_attr_get_type(pattr_nest2);
								
							if (type_nest2 == CTA_PROTO_NUM) {
								int proto = mnl_attr_get_u8(pattr_nest2);
								
								if (proto != IP_PROTO_TCP) {
									// XXX We currently ignore UDP Connections
									return MNL_CB_OK;
								}	
							}		
							else if (type_nest2 == CTA_PROTO_SRC_PORT) {
								if (mnl_attr_validate(pattr_nest2, MNL_TYPE_U16) >= 0) {
									ser_nat_port = ntohs(mnl_attr_get_u16(pattr_nest2));
								}		
							}
							else if (type_nest2 == CTA_PROTO_DST_PORT) {
								if (mnl_attr_validate(pattr_nest2, MNL_TYPE_U16) >= 0) {
									cli_nat_port = ntohs(mnl_attr_get_u16(pattr_nest2));
								}		
							}		
						}
					}
					else if (type_nest == CTA_TUPLE_IP) {
						const struct nlattr 		*pattr_nest2;

						gy_mnl_attr_for_each_nested(pattr_nest2, pattr_nest) {
							int type_nest2 = mnl_attr_get_type(pattr_nest2);
						
							if (type_nest2 == CTA_IP_V4_SRC) {

								if (mnl_attr_validate(pattr_nest2, MNL_TYPE_U32) >= 0) {
									ser_nat_addr.set_ip(mnl_attr_get_u32(pattr_nest2));
								}
							}
							else if (type_nest2 == CTA_IP_V6_SRC) {

								attr_len = mnl_attr_get_payload_len(pattr_nest2);

								if (attr_len == sizeof(__int128)) {
									unsigned __int128	ip;
									uint8_t 		*paddr = (uint8_t *)mnl_attr_get_payload(pattr_nest2);

									std::memcpy(&ip, paddr, sizeof(ip));
									ser_nat_addr.set_ip(ip);
								}	
							}
							else if (type_nest2 == CTA_IP_V4_DST) {

								if (mnl_attr_validate(pattr_nest2, MNL_TYPE_U32) >= 0) {
									cli_nat_addr.set_ip(mnl_attr_get_u32(pattr_nest2));
								}
							}
							else if (type_nest2 == CTA_IP_V6_DST) {

								attr_len = mnl_attr_get_payload_len(pattr_nest2);

								if (attr_len == sizeof(__int128)) {
									unsigned __int128		ip;
									uint8_t 			*paddr = (uint8_t *)mnl_attr_get_payload(pattr_nest2);

									std::memcpy(&ip, paddr, sizeof(ip));
									cli_nat_addr.set_ip(ip);
								}	
							}
						}
					}	
				}	

				break;
			}
			
			default :
				break;
			}		
		}	

		/*
		 * Now validate and check if NAT active.
		 */
		if ((cli_port == 0) || (ser_port == 0) || (cli_nat_port == 0) || (ser_nat_port == 0)) {
			return MNL_CB_OK;
		}	

		if ((cli_addr == dflt_addr) || (ser_addr == dflt_addr) || (cli_nat_addr == dflt_addr) || (ser_nat_addr == dflt_addr)) {
			return MNL_CB_OK;
		}	

		bool					is_snat {(cli_addr != cli_nat_addr) || (cli_port != cli_nat_port)}; 
		bool					is_dnat {(ser_addr != ser_nat_addr) || (ser_port != ser_nat_port)}; 
		char					cli_addr_buf[48], ser_addr_buf[48], cli_nat_addr_buf[48], ser_nat_addr_buf[48];

		INFOPRINTCOLOR(GY_COLOR_CYAN, "[ %s %s %s ] : Client %s Port %hu - Server %s Port %hu : NAT Client %s Port %hu - NAT Server %s Port %hu\n",
				is_snat ? "SNAT" : "", is_dnat ? "DNAT" : "", is_new_conn ? "New CT" : "Close CT",
				cli_addr.printaddr(cli_addr_buf, sizeof(cli_addr_buf)), cli_port, 
				ser_addr.printaddr(ser_addr_buf, sizeof(ser_addr_buf)), ser_port, 
				cli_nat_addr.printaddr(cli_nat_addr_buf, sizeof(cli_nat_addr_buf)), cli_nat_port, 
				ser_nat_addr.printaddr(ser_nat_addr_buf, sizeof(ser_nat_addr_buf)), ser_nat_port); 


		return MNL_CB_OK;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT("Exception caught while populating NAT Conntrack from netlink : %s\n", GY_GET_EXCEPT_STRING);
		return MNL_CB_STOP;
	);
}	

void * nlct_thread(void *arg)
{
	struct mnl_socket 		*nl;
	uint8_t				buf[GY_MNL_SOCKET_BUFFER_SIZE];
	int 				ret;
	struct pollfd 			pfds[1] = {};

	nl = mnl_socket_open(NETLINK_NETFILTER);
	if (nl == nullptr) {
		PERRORPRINT("mnl socket open failed");
		goto done_ret;
	}

	if (mnl_socket_bind(nl, NF_NETLINK_CONNTRACK_NEW |
/* 				NF_NETLINK_CONNTRACK_UPDATE | */
				NF_NETLINK_CONNTRACK_DESTROY,
				MNL_SOCKET_AUTOPID) < 0) {
		PERRORPRINT("mnl socket bind failed");
		goto done_ret;
	}

	pfds[0].fd 	= mnl_socket_get_fd(nl);
	pfds[0].events 	= POLLIN | POLLRDHUP;
	pfds[0].revents = 0;


	while (gsig_rcvd.load() == 0) {

		ret = poll(pfds, 1, 1000);
		if (ret < 0) {
			if (errno == EINTR) {
				continue;
			}
			PERRORPRINT("poll for mnl socket recv failed");
			goto done_ret;
		}
		else if (ret == 0) {
			continue;
		}

		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
		if (ret == -1) {
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			}	
			PERRORPRINT("mnl socket recv failed");
			goto done_ret;
		}

		ret = mnl_cb_run(buf, ret, 0, 0, ct_data_cb, NULL);
		if (ret == -1) {
			PERRORPRINT("mnl callback failed");
			goto done_ret;
		}
	}

done_ret :	
	if (nl) {
		mnl_socket_close(nl);
	}	

	if (gsig_rcvd.load()) {
		INFOPRINT("Thread %s returning as signal %s received...\n", __FUNCTION__, gy_signal_str(gsig_rcvd.load()));
	}
	else {
		INFOPRINT("Thread %s returning as error received...\n", __FUNCTION__);
	}	
	
	return (void *)0;

}



