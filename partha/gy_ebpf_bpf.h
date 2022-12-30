//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"
#include			"gy_ebpf.h"
#include			"gy_libbpf.h"

#include			"gy_ebpf_kernel.h"
#include			"gy_ebpf_common.h"

#include			"gy_ebpf_kernel.skel.h"

namespace gyeeta {

class GY_EBPF_BASE
{
public :
	using GY_BPF_OBJ		= GY_LIBBPF_OBJ<gy_ebpf_kernel_bpf>;

	GY_EBPF_BASE();

	void start_probes();


	GY_BTF_INIT				btf_;
	GY_BPF_OBJ				obj_				{"partha BPF"};

	std::optional<GY_PERF_BUFPOOL>		tcp_ipv4_event_pool_;
	std::optional<GY_PERF_BUFPOOL>		tcp_ipv6_event_pool_;
	std::optional<GY_PERF_BUFPOOL>		tcp_listener_event_pool_;
	std::optional<GY_PERF_BUFPOOL>		ipv4_xmit_perf_pool_;
	std::optional<GY_PERF_BUFPOOL>		ipv6_xmit_perf_pool_;
	std::optional<GY_PERF_BUFPOOL>		create_ns_event_pool_;
	std::optional<GY_PERF_BUFPOOL>		cgroup_migrate_event_pool_;
	std::optional<GY_PERF_BUFPOOL>		ip_vs_new_conn_event_pool_;

	uint32_t				max_possible_cpus_		{(uint32_t)libbpf_num_possible_cpus()};
	bool					is_fentry_			{false};
};	



} // namespace gyeeta

