//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"

namespace gyeeta {

static constexpr size_t				MAX_SVC_SSL_PROCS		{8};	// Does not include forked child processes

enum class SSL_SVC_E : uint8_t
{
	SSL_UNINIT				= 0,

	SSL_NO,
	SSL_YES,
	SSL_MULTIPLEXED,			// TLS and non-TLS on a single listener 
};	

enum class SSL_REQ_E : uint8_t
{
	SSL_NO_REQ				= 0,

	SSL_REQUEST_SCHED,			
	SSL_REJECTED,
	SSL_ACTIVE,
};	

class GY_SSLCAP;
class SVC_NET_CAPTURE;

class SSL_CAP_SVC 
{
public :
	static std::optional<GY_SSLCAP>		gsslcap_;

	static GY_CLOCK_TO_TIME			gclktime_;
	
	SSL_CAP_SVC() noexcept;

	// Use this constructor to load the ebpf probes at construct time itself
	SSL_CAP_SVC(SVC_NET_CAPTURE & svcnet);

	~SSL_CAP_SVC() noexcept;

	// Will update pidarr and set skipped pids to 0
	size_t start_svc_cap(const char * comm, uint64_t glob_id, uint16_t port, pid_t *pidarr, size_t npids) noexcept;

	void stop_svc_cap(uint64_t glob_id) noexcept;

	static bool ssl_uprobes_allowed() noexcept;

protected :

	using 					SvcPidMap = std::unordered_map<uint64_t, std::vector<pid_t>, GY_JHASHER<pid_t>>;
	
	GY_MUTEX				mapmutex_;
	SvcPidMap				svcmap_;
};


} // namespace gyeeta

