//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_listen_sock.h"

#include 			<sys/socket.h>
#include 			<netdb.h>
#include 			<netinet/tcp.h>
#include 			<sys/un.h>

#include			"gy_inet_inc.h"
#include 			"gy_file_api.h"
#include 			"gy_print_offload.h"

namespace gyeeta {

LISTEN_SOCK::LISTEN_SOCK(uint16_t port, const char * ipaddr_str, int backlog, bool set_nonblock, bool reuseaddr, bool reuseport, bool ipv6_only, bool freebind, int type, LISTEN_DEL_CB delcb, void *delcb_arg1, void *delcb_arg2, bool cloexec, bool no_delay) :
	port_(port), backlog_(backlog), del_cb_(delcb), delcb_arg1_(delcb_arg1), delcb_arg2_(delcb_arg2), socktype_(type),
	is_nonblock_(set_nonblock), is_reuseaddr_(reuseaddr), is_reuseport_(reuseport), is_ipv6_(false), ipv6_only_(ipv6_only), is_freebind_(freebind), 
	is_unix_domain_(false), is_cloexec_(cloexec), is_no_delay_(no_delay)
{
	int			sfd = -1, ret;
	char			addrbuf[128];

	*addrbuf = '\0';

	GY_SCOPE_EXIT {
		if (sfd != -1) {
			close(sfd);
		}	
	};


	/*
	 * We first check if the ipaddr_str non-digit char. If so, we invoke the getaddrinfo(). 
	 * If ipaddr_str == nullptr assume 0.0.0.0
	 */ 
	if ((ipaddr_str == nullptr) || (0 != isxdigit(*ipaddr_str)) || (':' == *ipaddr_str)) {
		if (ipaddr_str) {
			bool			is_valid = false;
			GY_IP_ADDR		ip(ipaddr_str, is_valid);	
			
			if (is_valid == false) {
				goto get1;
			}	

			ipaddr_		= ip;
		}
		else {
			ipaddr_str = "";
		}	

		ipaddr_.printaddr(addrbuf, sizeof(addrbuf));

		is_ipv6_ 	= ipaddr_.is_pure_ipv6();
		is_link_local_	= ipaddr_.is_link_local_addr();

		if (is_ipv6_ && is_link_local_) {
			GY_THROW_EXCEPTION("IPv6 Link Local Address specified without Network Interface scope ID. Specify address as \'%s%%<Interface>\' e.g. %s%%eth0", addrbuf, addrbuf);
		}	

		if (false == is_ipv6_) {
			struct sockaddr_in 	*paddr = (sockaddr_in *)&sockaddr_;

			std::memset(paddr, 0, sizeof(*paddr));

			paddr->sin_family 	= AF_INET;
			paddr->sin_port 	= htons(port_);
			
			ipaddr_.get_as_inaddr(&paddr->sin_addr.s_addr);
			
			socklen_		= sizeof(sockaddr_in);
			sockfamily_		= AF_INET;
		}	
		else {
			struct sockaddr_in6 	*paddr = (sockaddr_in6 *)&sockaddr_;

			std::memset(paddr, 0, sizeof(*paddr));

			paddr->sin6_family 	= AF_INET6;
			paddr->sin6_port 	= htons(port_);
			
			ipaddr_.get_as_inaddr(&paddr->sin6_addr);

			socklen_		= sizeof(sockaddr_in6);
			sockfamily_		= AF_INET6;
		}	

		if (socktype_ != SOCK_SEQPACKET) {
			sockprotocol_ = 0;
		}
		else {
			sockprotocol_ = IPPROTO_SCTP;
		}	

		if ((sfd = socket(sockfamily_, socktype_ | (cloexec ? SOCK_CLOEXEC : 0) | (is_nonblock_ ? SOCK_NONBLOCK : 0), sockprotocol_)) < 0) {
			GY_THROW_SYS_EXCEPTION("Could not create listener socket for IP %s Port %hu Type %s", addrbuf, port_, get_socket_type_string(socktype_));
		}

		lsock_ = sfd;

		set_listen_options(addrbuf);	
			
		if (bind(sfd, (struct sockaddr *)&sockaddr_, socklen_) == -1) {
			GY_THROW_SYS_EXCEPTION("Unable to bind to IP %s port %hu Type %s", addrbuf, port_, get_socket_type_string(socktype_));
		}
	}
	else {
get1 :

		struct addrinfo		*res, hints;
		char			buf[64];

		sprintf(buf, "%hu", port_);

		memset(&hints, 0, sizeof(hints));

		hints.ai_family 	= ipv6_only_ ? AF_INET6 : AF_UNSPEC;
		hints.ai_socktype 	= socktype_;
		hints.ai_flags 		= AI_PASSIVE;    /* For wildcard IP address */
		hints.ai_protocol 	= 0; 
		hints.ai_canonname 	= nullptr;
		hints.ai_addr 		= nullptr;
		hints.ai_next 		= nullptr;

		ret = getaddrinfo(ipaddr_str, buf, &hints, &res);
		if (ret != 0) {
			GY_THROW_EXCEPTION("Could not resolve IP/port for Listener getaddrinfo %s (%s_%hu) Type %s", 
				gai_strerror(ret), ipaddr_str ? ipaddr_str : "", port_, get_socket_type_string(socktype_));
		}

		GY_SCOPE_EXIT {
			freeaddrinfo(res);
		};	

		const struct addrinfo 		*r;

		for (r = res; r != nullptr; r = r->ai_next) {

			if (r->ai_family == AF_INET) {
				struct sockaddr_in 	*paddr = (sockaddr_in *)r->ai_addr;

				ipaddr_ 	= paddr->sin_addr.s_addr;
				port_		= ntohs(paddr->sin_port);
				socklen_	= sizeof(*paddr);	
				sockfamily_ 	= AF_INET;
			}
			else if (r->ai_family == AF_INET6) {
				struct sockaddr_in6 	*paddr = (sockaddr_in6 *)r->ai_addr;
				
				ipaddr_ 	= paddr->sin6_addr;
				port_		= ntohs(paddr->sin6_port);
				socklen_	= sizeof(*paddr);	
				sockfamily_ 	= AF_INET6;
			}	
			else {
				continue;
			}	

			sockprotocol_		= r->ai_protocol;
				
			sfd = socket(r->ai_family, r->ai_socktype | (cloexec ? SOCK_CLOEXEC : 0) | (is_nonblock_ ? SOCK_NONBLOCK : 0), r->ai_protocol);
			if (sfd < 0) {
				continue;
			}

			GY_SCOPE_EXIT {
				if (sfd != -1) {
					close(sfd);
				}	
			};

			lsock_ = sfd;
			ipaddr_.printaddr(addrbuf, sizeof(addrbuf));

			set_listen_options(addrbuf);

			ret = bind(sfd, r->ai_addr, r->ai_addrlen);
			if (ret == 0) {
				if (r->ai_addrlen <= sizeof(sockaddr_)) {
					socklen_		= r->ai_addrlen;
					sockfamily_		= r->ai_family;

					std::memcpy(&sockaddr_, r->ai_addr, r->ai_addrlen);
				}
				sfd = -1;
				break;
			}
		}	

		if (r == nullptr) {
			GY_THROW_EXCEPTION("Could not listen to IP %s port %hu Type %s", 
				*addrbuf ? addrbuf : (ipaddr_str ? ipaddr_str : ""), port_, get_socket_type_string(socktype_));
		}
	}		

	if (socktype_ == SOCK_STREAM || socktype_ == SOCK_SEQPACKET) {
		if (0 != listen(lsock_, backlog_)) {
			GY_THROW_SYS_EXCEPTION("Could not listen on bound socket for IP %s port %hu Type %s", addrbuf, port_, get_socket_type_string(socktype_));
		}	
		
		sfd = -1;
	}	
	else {
		sfd = -1;
	}	

	INFOPRINT_OFFLOAD("%s Server Listening on IP %s port %hu\n", get_socket_type_string(socktype_), addrbuf, port_);
}		

LISTEN_SOCK::LISTEN_SOCK(const char * path_str, int backlog, bool set_nonblock, bool unlink_first, bool reuseaddr, mode_t mode, int type, LISTEN_DEL_CB delcb, void *delcb_arg1, void *delcb_arg2, bool cloexec)
	: backlog_(backlog), del_cb_(delcb), delcb_arg1_(delcb_arg1), delcb_arg2_(delcb_arg2), sockfamily_(AF_UNIX), socktype_(type),
	is_nonblock_(set_nonblock), is_reuseaddr_(reuseaddr), is_unix_domain_(true), is_cloexec_(cloexec)
{
	int			sfd, ret;
	struct sockaddr_un 	*paddr = (sockaddr_un *)&sockaddr_;

	assert(path_str);

	if ((sfd = socket(AF_UNIX, socktype_ | (cloexec ? SOCK_CLOEXEC : 0) | (is_nonblock_ ? SOCK_NONBLOCK : 0), 0)) < 0) {
		GY_THROW_SYS_EXCEPTION("Could not create Unix Domain listener socket for path %s Type %s", path_str, get_socket_type_string(socktype_));
	}

	GY_SCOPE_EXIT {
		if (sfd != -1) {
			close(sfd);
		}	
	};
	
	std::memset(paddr, 0, sizeof(*paddr));

	lsock_ 			= sfd;
	paddr->sun_family 	= AF_UNIX;
	socklen_		= sizeof(*paddr);	

	GY_STRNCPY(paddr->sun_path, path_str, sizeof(paddr->sun_path) - 1);
	
	if (unlink_first) {
		unlink(paddr->sun_path);
	}	

	set_listen_options(path_str);	
		
	if (bind(sfd, (struct sockaddr *)paddr, socklen_) == -1) {
		GY_THROW_SYS_EXCEPTION("Unable to bind to Unix Domain path %s Type %s", path_str, get_socket_type_string(socktype_));
	}

	(void)chmod(paddr->sun_path, mode);

	if (socktype_ == SOCK_STREAM || socktype_ == SOCK_SEQPACKET) {
		if (0 != listen(lsock_, backlog_)) {
			GY_THROW_SYS_EXCEPTION("Could not listen on bound socket for Unix Domain path %s Type %s", path_str, get_socket_type_string(socktype_));
		}	
		
		sfd 	= -1;
	}	
	else {
		sfd	= -1;
	}	

	INFOPRINT_OFFLOAD("Unix Domain %s Server Listening on path %s\n", get_socket_type_string(socktype_), path_str);
}
	
void LISTEN_SOCK::set_listen_options(const char * paddrbuf) 
{
	int			sopt, ret;
	char			addrbuf[256];

	if (false == is_unix_domain_) {

		snprintf(addrbuf, sizeof(addrbuf), "IP %s port %hu Type %s", paddrbuf, port_, get_socket_type_string(socktype_));

		if (is_reuseport_ && socktype_ == SOCK_STREAM) {
			sopt = 1;

			if (setsockopt(lsock_, SOL_SOCKET, SO_REUSEPORT, (void *)&sopt, sizeof(sopt)) == -1) {
				GY_THROW_SYS_EXCEPTION("Socket option SO_REUSEPORT failed for %s during listener initialization", addrbuf);
			}
		}	

		if (is_ipv6_ && ipv6_only_) {
			sopt = 1;

			if (setsockopt(lsock_, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&sopt, sizeof(sopt)) == -1) {
				GY_THROW_SYS_EXCEPTION("Socket option IPV6_V6ONLY failed for %s during listener initialization", addrbuf);
			}
		}	

		if (is_freebind_) {
			sopt = 1;

			if (setsockopt(lsock_, IPPROTO_IP, IP_FREEBIND, (void *)&sopt, sizeof(sopt)) == -1) {
				DEBUGEXECN(1, 
					PERRORPRINTCOLOR(GY_COLOR_RED, "Socket option IP_FREEBIND failed for %s during listener initialization", addrbuf);
				);	
			}
		}					

		if (is_no_delay_) {
			sopt = 1;
			(void)setsockopt(lsock_, IPPROTO_TCP, TCP_NODELAY, &sopt, sizeof(sopt));
		}
	}
	else {
		GY_STRNCPY(addrbuf, paddrbuf, sizeof(addrbuf));
	}

	if (is_reuseaddr_) {
		sopt = 1;

		if (setsockopt(lsock_, SOL_SOCKET, SO_REUSEADDR, (void *)&sopt, sizeof(sopt)) == -1) {
			DEBUGEXECN(1, PERRORPRINTCOLOR(GY_COLOR_RED, "Socket option SO_REUSEADDR failed for %s during listener initialization", addrbuf););
		}
	}

}	

char * LISTEN_SOCK::print_sockaddr(STR_WR_BUF & strbuf) const noexcept
{
	if (lsock_ > 0) {
		if (false == is_unix_domain_) {
			strbuf.appendfmt("%sSocket Listener for IP ", 
				socktype_ == SOCK_STREAM ? "TCP " : socktype_ == SOCK_DGRAM ? "UDP " : socktype_ == SOCK_SEQPACKET ? "SCTP " : "");

			ipaddr_.printaddr(strbuf);
			strbuf.appendfmt(" Port %hu", port_);
		}	
		else {
			struct sockaddr_un 	*paddr = (sockaddr_un *)&sockaddr_;

			strbuf.appendfmt("Unix Domain socket Listener for path %s Type %s", paddr->sun_path, get_socket_type_string(socktype_));
		}	
	}

	return strbuf.buffer();
}

LISTEN_SOCK::~LISTEN_SOCK() noexcept
{
	int			ret;
	auto			pdelcb = GY_READ_ONCE(del_cb_);
	
	if (lsock_ > 0 && pdelcb) {
		try {
			(*pdelcb)(lsock_, GY_READ_ONCE(delcb_arg1_), GY_READ_ONCE(delcb_arg2_));
		}
		catch(...) {
		}
	}

	if (lsock_ > 0) {
		ret = ::close(lsock_);
		if (ret != 0) {
			PERRORPRINTCOLOR(GY_COLOR_RED, "Failed to close listener socket");
		}
		else if (is_unix_domain_) {
			// Delete the sock path
			struct ::sockaddr_un 	*paddr = (sockaddr_un *)&sockaddr_;
			
			paddr->sun_path[sizeof(paddr->sun_path) - 1] = '\0';

			if (0 != *paddr->sun_path) {
				::unlink(paddr->sun_path);	
			}	 	
		}	

		lsock_ = -1;
	}
}			



} // namespace gyeeta
	
