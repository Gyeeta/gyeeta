//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include 			"gy_ssl_cap_common.h"
#include			"gy_svc_net_capture.h"

namespace gyeeta {

class GY_SSLCAP
{
public :

};	

SSL_CAP_SVC::SSL_CAP_SVC() noexcept
{

}

SSL_CAP_SVC::SSL_CAP_SVC(SVC_NET_CAPTURE & svcnet)
{

}

SSL_CAP_SVC::~SSL_CAP_SVC() noexcept
{

}

size_t SSL_CAP_SVC::start_svc_cap(const char * comm, uint64_t glob_id, uint16_t port, pid_t *pidarr, size_t npids) noexcept
{
	return 0;
}

void SSL_CAP_SVC::stop_svc_cap(uint64_t glob_id) noexcept
{
}


bool SSL_CAP_SVC::ssl_uprobes_allowed() noexcept
{
	return false;
}	

void SVC_NET_CAPTURE::handle_uprobe_cb(void *pdata, int data_size)
{
	
}


} // namespace gyeeta

