//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include		"gy_sys_hardware.h"
#include		"gy_paconnhdlr.h"

namespace gyeeta {

bool SYS_HARDWARE::send_host_info() const noexcept
{
	using namespace			comm;

	try {
		auto					pser = SERVER_COMM::get_singleton();
		std::shared_ptr<SERVER_CONNTRACK>	shrp;
		SERVER_CONNTRACK			*pconn1;

		shrp = pser->get_server_conn(comm::CLI_TYPE_REQ_ONLY);
		pconn1 = shrp.get();

		if (!pconn1) {
			return false;
		}	

		auto				pconnhdlr = partha::PACONN_HANDLER::get_singleton();
		const size_t			max_buf_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + sizeof(HOST_INFO_NOTIFY);

		void				*palloc = ::malloc(max_buf_sz);
		if (!palloc) {
			return false;
		}	

		COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
		EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1); 
		HOST_INFO_NOTIFY		*phost = reinterpret_cast<HOST_INFO_NOTIFY *>(pnot + 1);
		bool				bret;

		new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, max_buf_sz, pser->get_conn_magic());
		new (pnot) EVENT_NOTIFY(comm::NOTIFY_HOST_INFO, 1);	
		new (phost) HOST_INFO_NOTIFY();
		
		if (os_info) {
			GY_STRNCPY(phost->distribution_name_, os_info->get_node_distribution_str(), sizeof(phost->distribution_name_));
			GY_STRNCPY(phost->kern_version_string_, os_info->get_kernel_version_str(), sizeof(phost->kern_version_string_));

			phost->kern_version_num_ = os_info->get_kernel_version();
		}

		if (pconnhdlr) {
			GY_STRNCPY(phost->instance_id_, pconnhdlr->instance_id_, sizeof(phost->instance_id_));
			GY_STRNCPY(phost->cloud_type_, pconnhdlr->cloud_type_, sizeof(phost->cloud_type_));
		}	

		if (cpumem_info) {
			GY_STRNCPY(phost->processor_model_, cpumem_info->cpu_model_name, sizeof(phost->processor_model_));
			GY_STRNCPY(phost->cpu_vendor_, cpumem_info->cpu_vendor_name, sizeof(phost->cpu_vendor_));

			phost->cores_online_		= cpumem_info->num_online;
			phost->cores_offline_		= cpumem_info->num_offline;
			phost->max_cores_		= cpumem_info->num_possible;
			phost->isolated_cores_		= cpumem_info->num_isolated;
			phost->ram_mb_			= GY_DOWN_MB(cpumem_info->total_memory);
			phost->corrupted_ram_mb_	= GY_DOWN_MB(cpumem_info->corrupted_memory);
			phost->num_numa_nodes_		= cpumem_info->num_numa_nodes;
			phost->max_cores_per_socket_	= cpumem_info->cores_per_socket;
			phost->threads_per_core_	= cpumem_info->threads_per_core;

			phost->boot_time_sec_ 		= time(nullptr) - int64_t(get_usec_bootclock()/GY_USEC_PER_SEC);

			phost->l1_dcache_kb_		= GY_DOWN_KB(cpumem_info->level1_dcache_sz);
			phost->l2_cache_kb_		= GY_DOWN_KB(cpumem_info->level2_cache_sz);
			phost->l3_cache_kb_		= GY_DOWN_KB(cpumem_info->level3_cache_sz);
			phost->l4_cache_kb_		= GY_DOWN_KB(cpumem_info->level4_cache_sz);

			phost->is_virtual_cpu_		= cpumem_info->is_virtual_cpu();
			if (phost->is_virtual_cpu_) {
				GY_STRNCPY(phost->virtualization_type_, get_virtualization_type(cpumem_info->virtualization_type), sizeof(phost->virtualization_type_));
			}	

		}	

		bret = pser->send_server_data(EPOLL_IOVEC_ARR(2, false, phdr, phdr->get_act_len(), ::free, pser->gpadbuf, phdr->get_pad_len(), nullptr), 
						comm::CLI_TYPE_REQ_ONLY, COMM_EVENT_NOTIFY, shrp);

		if (bret) {
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Sent Host Info to Madhava server\n");
		}	

		return bret;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT_OFFLOAD("Exception caught while sending Host Info to Madhava : %s\n", GY_GET_EXCEPT_STRING);
		return false;
	);
}	

} // namespace gyeeta

