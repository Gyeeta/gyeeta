
#pragma			once

#include		"gy_common_inc.h"

namespace gyeeta {

#ifndef	SO_REUSEPORT
#define SO_REUSEPORT			15
#endif

typedef void 				(*LISTEN_DEL_CB)(const int lsock, void *arg1, void *arg2);

class LISTEN_SOCK final
{
public :
	/*
	 * IPv4/IPv6 TCP, UDP, SEQPACKET (SCTP) type listener
	 * Does not support SCTP Streaming protocol listener
	 */ 
	LISTEN_SOCK(uint16_t port, const char * ipaddr_str = nullptr, int backlog = 128, bool set_nonblock = false, bool reuseaddr = true, bool reuseport = false, bool ipv6_only = false, bool freebind = false, int type = SOCK_STREAM, LISTEN_DEL_CB delcb = nullptr, void *delcb_arg1 = nullptr, void *delcb_arg2 = nullptr, bool cloexec = true, bool no_delay = true);
	
	/*
	 * Unix Domain Listener
	 */ 
	LISTEN_SOCK(const char * path_str, int backlog = 128, bool set_nonblock = false, bool unlink_first = true, bool reuseaddr = true, mode_t mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP, int type = SOCK_STREAM, LISTEN_DEL_CB delcb = nullptr, void *delcb_arg1 = nullptr, void *delcb_arg2 = nullptr, bool cloexec = true);

	LISTEN_SOCK(const LISTEN_SOCK &)			= delete;

	LISTEN_SOCK & operator=(const LISTEN_SOCK &)		= delete;

	LISTEN_SOCK(LISTEN_SOCK && other) noexcept
	{
		std::memcpy(this, &other, sizeof(*this));

		other.lsock_		= -1;
		other.del_cb_		= nullptr;
	}	

	LISTEN_SOCK & operator=(LISTEN_SOCK && other) noexcept
	{
		if (this != &other) {
			this->~LISTEN_SOCK();

			new (this) LISTEN_SOCK(std::move(other));
		}

		return *this;
	}	

	~LISTEN_SOCK() noexcept;

	void set_delete_cb(LISTEN_DEL_CB delcb, void *delcb_arg1 = nullptr, void *delcb_arg2 = nullptr) noexcept
	{
		GY_WRITE_ONCE(del_cb_, delcb);
		GY_WRITE_ONCE(delcb_arg1_, delcb_arg1);
		GY_WRITE_ONCE(delcb_arg2_, delcb_arg2);
	}	

	int get_sock() const noexcept
	{
		return lsock_;
	}	

	bool get_ip_port(GY_IP_ADDR & ip, uint16_t & port) const noexcept
	{
		if (is_unix_domain_ == false) {
			ip 	= ipaddr_;
			port	= port_;

			return true;
		}	

		return false;
	}	

	bool get_ipv6_link_scopeid(uint32_t & scope_id) const noexcept
	{
		if (sockfamily_ == AF_INET6) {
			sockaddr_in6	*pin6 = (sockaddr_in6 *)&sockaddr_;
			
			scope_id = pin6->sin6_scope_id;	
			return true;
		}	
		return false;
	}	

	void get_sockaddr(struct sockaddr_storage & sockaddr, socklen_t & socklen, int & sockfamily, int & socktype, int & sockprotocol) const noexcept
	{
		sockaddr 	= sockaddr_;
		socklen		= socklen_;
		sockfamily	= sockfamily_;
		socktype	= socktype_;
		sockprotocol	= sockprotocol_;
	}	

	char * print_sockaddr(char *pbuf, size_t szbuf) const noexcept
	{
		if (!pbuf) {
			return nullptr;
		}

		STR_WR_BUF	strbuf(pbuf, szbuf);

		return print_sockaddr(strbuf);
	}

	char * print_sockaddr(STR_WR_BUF & strbuf) const noexcept;

private :
	
	void set_listen_options(const char *);

	int				lsock_			{-1};
	GY_IP_ADDR			ipaddr_;
	uint16_t			port_			{0};
	int				backlog_		{0};

	LISTEN_DEL_CB			del_cb_			{nullptr};
	void				*delcb_arg1_		{nullptr};
	void				*delcb_arg2_		{nullptr};

	struct sockaddr_storage		sockaddr_		{};
	socklen_t			socklen_		{0};
	int				sockfamily_		{AF_INET};
	int				socktype_		{SOCK_STREAM};
	int				sockprotocol_		{0};

	bool				is_nonblock_		{false};
	bool				is_reuseaddr_		{false};
	bool				is_reuseport_		{false};
	bool				is_ipv6_		{false};
	bool				ipv6_only_		{false};
	bool				is_freebind_		{false};	
	bool				is_link_local_		{false};
	bool				is_unix_domain_		{false};
	bool				is_cloexec_		{false};
	bool				is_no_delay_		{false};
};	

} // namespace gyeeta	

