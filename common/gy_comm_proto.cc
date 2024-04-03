//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include 			"gy_comm_proto.h"
#include			"gy_proto_common.h"

namespace gyeeta {
namespace comm {

bool COMM_HEADER::validate(const uint8_t *pdata, HDR_MAGIC_E req_magic) const noexcept
{
	if (!((magic_ == req_magic) && 
		total_sz_ < MAX_COMM_DATA_SZ && total_sz_ >= sizeof(COMM_HEADER) && padding_sz_ < 8 &&
		data_type_ > COMM_MIN_TYPE && data_type_ < COMM_MAX_TYPE)) {

		return false;
	}	

	if (total_sz_ & (8 - 1)) {
		return false;
	}	

	// Check if pdata is 8 bytes aligned : We will terminate connections resulting in unaligned accesses
	if (0 != (((uint64_t)pdata) & (8 - 1))) {
		return false;
	}	

	const uint32_t		act_total_sz = total_sz_ - padding_sz_;

	switch (data_type_) {
	
	case COMM_EVENT_NOTIFY 	: return (act_total_sz >= sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY));

	case COMM_QUERY_CMD	: return (act_total_sz >= sizeof(COMM_HEADER) + sizeof(QUERY_CMD));
	case COMM_QUERY_RESP	: return (act_total_sz >= sizeof(COMM_HEADER) + sizeof(QUERY_RESPONSE));

	case PS_REGISTER_REQ	: return (act_total_sz >= sizeof(COMM_HEADER) + sizeof(PS_REGISTER_REQ_S));
	case PM_CONNECT_CMD	: return (act_total_sz >= sizeof(COMM_HEADER) + sizeof(PM_CONNECT_CMD_S));
	case MS_REGISTER_REQ	: return (act_total_sz >= sizeof(COMM_HEADER) + sizeof(MS_REGISTER_REQ_S));
	case MM_CONNECT_CMD	: return (act_total_sz >= sizeof(COMM_HEADER) + sizeof(MM_CONNECT_CMD_S));

	case NS_REGISTER_REQ	: 
	case NS_ALERT_REGISTER	: return (act_total_sz >= sizeof(COMM_HEADER) + sizeof(NS_REGISTER_REQ_S));
	
	case NM_CONNECT_CMD	: return (act_total_sz >= sizeof(COMM_HEADER) + sizeof(NM_CONNECT_CMD_S));

	case PS_REGISTER_RESP	: return (act_total_sz >= sizeof(COMM_HEADER) + sizeof(PS_REGISTER_RESP_S));
	case PM_CONNECT_RESP	: return (act_total_sz >= sizeof(COMM_HEADER) + sizeof(PM_CONNECT_RESP_S));
	case MS_REGISTER_RESP	: return (act_total_sz >= sizeof(COMM_HEADER) + sizeof(MS_REGISTER_RESP_S));
	case MM_CONNECT_RESP	: return (act_total_sz >= sizeof(COMM_HEADER) + sizeof(MM_CONNECT_RESP_S));
	case NS_REGISTER_RESP	: return (act_total_sz >= sizeof(COMM_HEADER) + sizeof(NS_REGISTER_RESP_S));
	case NM_CONNECT_RESP	: return (act_total_sz >= sizeof(COMM_HEADER) + sizeof(NM_CONNECT_RESP_S));

	default 		: return false;
	}	
}

bool ERROR_NOTIFY::validate(const COMM_HEADER *phdr) const noexcept
{
	static constexpr size_t fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + sizeof(ERROR_NOTIFY);

	if (phdr->get_act_len() < fixed_sz) {
		return false;
	}	
	
	GY_CC_BARRIER();

	if (phdr->get_act_len() < fixed_sz + error_string_len_) {
		return false;
	}	

	return true;
}	

bool QUERY_RESPONSE::validate(const COMM_HEADER *phdr) const noexcept
{
	static constexpr size_t fixed_sz = sizeof(COMM_HEADER) + sizeof(QUERY_RESPONSE);

	if (phdr->get_act_len() < fixed_sz) {
		return false;
	}	
	
	GY_CC_BARRIER();

	if (phdr->get_act_len() != fixed_sz + resp_len_) {
		return false;
	}	

	return true;
}	

bool PARTHA_MADHAVA_REQ::validate(const COMM_HEADER *phdr) const noexcept
{
	static constexpr size_t fixed_sz = sizeof(COMM_HEADER) + sizeof(QUERY_CMD) + sizeof(PARTHA_MADHAVA_REQ);

	if (phdr->get_act_len() < fixed_sz) {
		return false;
	}	
	
	GY_CC_BARRIER();

	if (phdr->get_act_len() < fixed_sz + partha_hostname_len_ + extra_tags_len_) {
		return false;
	}	

	if (partha_machine_id_hi_ > 0 && partha_machine_id_lo_ > 0) {
		return true;
	}

	if ((partha_hostname_len_ > MAX_DOMAINNAME_SIZE) || (extra_tags_len_ > MAX_TOTAL_TAG_LEN)) {
		return false;
	}	

	return true;
}	

bool PARTHA_MADHAVA_RESP::validate(const COMM_HEADER *phdr, const QUERY_RESPONSE *presp) const noexcept
{
	static constexpr size_t fixed_sz = sizeof(COMM_HEADER) + sizeof(QUERY_RESPONSE) + sizeof(*this);

	if ((phdr->get_act_len() != fixed_sz) || (presp->resp_len_ != sizeof(*this))) {
		return false;
	}	
	
	GY_CC_BARRIER();

	if ((madhava_id_ == 0) || (madhava_svc_port_ == 0)) {
		return false;
	}

	return true;
}	

bool PS_REGISTER_REQ_S::validate_fields(uint32_t min_partha_version, uint32_t shyama_version, char (&ebuf)[COMM_MAX_ERROR_LEN], ERR_CODES_E & errcode) noexcept
{
	*ebuf = 0;
	hostname_[sizeof(hostname_) - 1] = 0;
	write_access_key_[sizeof(write_access_key_) - 1] = 0;
	cluster_name_[sizeof(cluster_name_) - 1] = 0;
	region_name_[sizeof(region_name_) - 1] = 0;
	zone_name_[sizeof(zone_name_) - 1] = 0;

	if (comm_version_ > COMM_VERSION_NUM) {
		comm_version_ = COMM_VERSION_NUM;
	}
	else if (comm_version_ < MIN_COMM_VERSION_NUM) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Protocol Version %u not supported : Please upgrade the Partha install", comm_version_);
		errcode = ERR_PROTOCOL_VERSION;

		return false;
	}	

	if (partha_version_ < min_partha_version) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Partha Version %s (0x%08X) not supported : Please upgrade the Partha install", 
					get_string_from_version_num(partha_version_).get(), partha_version_);
		errcode = ERR_PARTHA_VERSION;

		return false;
	}	

	if (min_shyama_version_ > shyama_version) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Shyama Version %s (0x%08X) not supported by Partha : Please upgrade Shyama install", 
					get_string_from_version_num(shyama_version).get(), shyama_version);
		errcode = ERR_SHYAMA_VERSION;

		return false;
	}	

	if (machine_id_hi_ == 0ul && machine_id_lo_ == 0ul) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Invalid MachineID sent by Partha");
		errcode = ERR_INVALID_MACHINE_ID;

		return false;
	}	

	int64_t				diff_sys_sec = time(nullptr) - curr_sec_;

	if (gy_unlikely(labs(diff_sys_sec) >= 60)) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Partha Register failed as Partha Host system time differs from Shyama by %ld seconds. Please sync the system times first",
			diff_sys_sec);
		errcode = ERR_SYSTEM_TIME_MISMATCH;
		return false;
	}	

	return true;
}

bool MM_CONNECT_CMD_S::validate_fields(uint64_t madhava_id, uint32_t min_madhava_version, uint32_t curr_madhava_version, char (&ebuf)[COMM_MAX_ERROR_LEN], ERR_CODES_E & errcode) noexcept
{
	*ebuf = 0;
	madhava_hostname_[sizeof(madhava_hostname_) - 1] = 0;
	region_name_[sizeof(region_name_) - 1] = 0;
	zone_name_[sizeof(zone_name_) - 1] = 0;
	madhava_name_[sizeof(madhava_name_) - 1] = 0;

	if (remote_madhava_id_ != madhava_id) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Requested Madhava ID %016lx not valid", remote_madhava_id_);
		errcode = ERR_MISMATCH_ID;

		return false;		
	}

	if (comm_version_ > COMM_VERSION_NUM) {
		comm_version_ = COMM_VERSION_NUM;
	}
	else if (comm_version_ < MIN_COMM_VERSION_NUM) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Protocol Version %u not supported : Please upgrade the Madhava install", comm_version_);
		errcode = ERR_PROTOCOL_VERSION;

		return false;
	}	

	if (local_version_ < min_madhava_version) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Madhava Version %s (0x%08X) not supported : Please upgrade the Madhava install", 
					get_string_from_version_num(local_version_).get(), local_version_);
		errcode = ERR_MADHAVA_VERSION;

		return false;
	}	

	if (min_remote_version_ > curr_madhava_version) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Madhava Version %s (0x%08X) not supported by Remote madhava : Please upgrade the Madhava install", 
					get_string_from_version_num(curr_madhava_version).get(), curr_madhava_version);
		errcode = ERR_MADHAVA_VERSION;

		return false;
	}	

	if (local_madhava_id_ == 0) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Invalid Madhava ID sent by remote Madhava");
		errcode = ERR_INVALID_ID;

		return false;
	}	

	int64_t				diff_sys_sec = time(nullptr) - curr_sec_;

	if (gy_unlikely(labs(diff_sys_sec) >= 60)) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Madhava Register failed as remote Madhava Host system time differs by %ld seconds. Please sync the system times first",
			diff_sys_sec);
		errcode = ERR_SYSTEM_TIME_MISMATCH;
		return false;
	}	

	return true;
}

bool PM_CONNECT_CMD_S::validate_fields(uint64_t madhava_id, uint32_t min_partha_version, uint32_t madhava_version, char (&ebuf)[COMM_MAX_ERROR_LEN], ERR_CODES_E & errcode) noexcept
{
	*ebuf = 0;
	hostname_[sizeof(hostname_) - 1] = 0;
	write_access_key_[sizeof(write_access_key_) - 1] = 0;
	cluster_name_[sizeof(cluster_name_) - 1] = 0;
	region_name_[sizeof(region_name_) - 1] = 0;
	zone_name_[sizeof(zone_name_) - 1] = 0;

	if (comm_version_ > COMM_VERSION_NUM) {
		comm_version_ = COMM_VERSION_NUM;
	}
	else if (comm_version_ < MIN_COMM_VERSION_NUM) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Protocol Version %u not supported : Please upgrade the Partha install", comm_version_);
		errcode = ERR_PROTOCOL_VERSION;

		return false;
	}	

	if (partha_version_ < min_partha_version) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Partha Version %s (0x%08X) not supported : Please upgrade the Partha install", 
					get_string_from_version_num(partha_version_).get(), partha_version_);
		errcode = ERR_PARTHA_VERSION;

		return false;
	}	

	if (min_madhava_version_ > madhava_version) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Madhava Version %s (0x%08X) not supported by Partha : Please upgrade the Madhava install", 
					get_string_from_version_num(madhava_version).get(), madhava_version);
		errcode = ERR_MADHAVA_VERSION;

		return false;
	}	

	if (machine_id_hi_ == 0ul && machine_id_lo_ == 0ul) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Invalid MachineID sent by partha");
		errcode = ERR_INVALID_MACHINE_ID;

		return false;
	}	

	if (madhava_id_ != madhava_id) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Madhava ID sent %016lx not valid", madhava_id_);
		errcode = ERR_MISMATCH_ID;

		return false;
	}

	int64_t				diff_sys_sec = time(nullptr) - curr_sec_;

	if (gy_unlikely(labs(diff_sys_sec) >= 60)) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Partha Register failed as Partha Host system time differs from Madhava by %ld seconds. Please sync the system times first.",
			diff_sys_sec);
		errcode = ERR_SYSTEM_TIME_MISMATCH;
		return false;
	}	

	return true;
}

bool MS_REGISTER_REQ_S::validate_fields(uint32_t min_madhava_version, uint32_t shyama_version, const char * shyama_secret, char (&ebuf)[COMM_MAX_ERROR_LEN], ERR_CODES_E & errcode) noexcept
{
	*ebuf = 0;
	madhava_hostname_[sizeof(madhava_hostname_) - 1] = 0;
	region_name_[sizeof(region_name_) - 1] = 0;
	zone_name_[sizeof(zone_name_) - 1] = 0;
	madhava_name_[sizeof(madhava_name_) - 1] = 0;
	shyama_secret_[sizeof(shyama_secret_) - 1] = 0;

	if (comm_version_ > COMM_VERSION_NUM) {
		comm_version_ = COMM_VERSION_NUM;
	}
	else if (comm_version_ < MIN_COMM_VERSION_NUM) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Protocol Version %u not supported : Please upgrade the Madhava install", comm_version_);
		errcode = ERR_PROTOCOL_VERSION;

		return false;
	}	

	if (madhava_version_ < min_madhava_version) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Madhava Version %s (0x%08X) not supported : Please upgrade the Madhava install", 
						get_string_from_version_num(madhava_version_).get(), madhava_version_);
		errcode = ERR_MADHAVA_VERSION;

		return false;
	}	

	if (min_shyama_version_ > shyama_version) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Shyama Version %s (0x%08X) not supported by Madhava : Please upgrade the Shyama install", 
						get_string_from_version_num(shyama_version).get(), shyama_version);
		errcode = ERR_SHYAMA_VERSION;

		return false;
	}	

	if (strcmp(shyama_secret_, shyama_secret)) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Invalid Shyama Secret sent");
		errcode = ERR_INVALID_SECRET;

		return false;
	}	

	if (madhava_port_ == 0) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Madhava port cannot be 0");
		errcode = ERR_INVALID_REQUEST;

		return false;
	}	

	if ((uint32_t)cli_type_ >= (uint32_t)CLI_TYPE_MAX) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Invalid cli_type_ %u", cli_type_);
		errcode = ERR_INVALID_REQUEST;

		return false;
	}	

	int64_t				diff_sys_sec = time(nullptr) - curr_sec_;

	if (gy_unlikely(labs(diff_sys_sec) >= 60)) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Madhava Register failed as Madhava Host system time differs from Shyama by %ld seconds. Please sync the system times first.",
			diff_sys_sec);
		errcode = ERR_SYSTEM_TIME_MISMATCH;
		return false;
	}	

	if ((max_partha_nodes_ == 0) || (max_partha_nodes_ > MAX_PARTHA_PER_MADHAVA)) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Invalid Max Partha Nodes Allowed %u", max_partha_nodes_);
		errcode = ERR_INVALID_REQUEST;
		return false;
	}	

	return true;
}

bool NS_REGISTER_REQ_S::validate_fields(uint32_t min_node_version, uint32_t shyama_version, char (&ebuf)[COMM_MAX_ERROR_LEN], ERR_CODES_E & errcode) noexcept
{
	*ebuf = 0;
	node_hostname_[sizeof(node_hostname_) - 1] = 0;

	if (comm_version_ > COMM_VERSION_NUM) {
		comm_version_ = COMM_VERSION_NUM;
	}
	else if (comm_version_ < MIN_COMM_VERSION_NUM) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Protocol Version %u not supported : Please upgrade the Node install", comm_version_);
		errcode = ERR_PROTOCOL_VERSION;

		return false;
	}	

	if (node_version_ < min_node_version) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Node Version %s (0x%08X) not supported : Please upgrade the Node install", 
						get_string_from_version_num(node_version_).get(), node_version_);
		errcode = ERR_NODE_VERSION;

		return false;
	}	

	if (min_shyama_version_ > shyama_version) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Shyama Version %s (0x%08X) not supported by Node", 
						get_string_from_version_num(shyama_version).get(), shyama_version);
		errcode = ERR_SHYAMA_VERSION;

		return false;
	}	

	if (node_port_ == 0) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Node port cannot be 0");
		errcode = ERR_INVALID_REQUEST;

		return false;
	}	

	if ((uint32_t)cli_type_ >= (uint32_t)CLI_TYPE_MAX) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Invalid cli_type_ %u", cli_type_);
		errcode = ERR_INVALID_REQUEST;

		return false;
	}	

	int64_t				diff_sys_sec = time(nullptr) - curr_sec_;

	if (gy_unlikely(labs(diff_sys_sec) >= 60)) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Node Register failed as Node Host system time differs from Shyama by %ld seconds. Please sync the system times first.",
			diff_sys_sec);
		errcode = ERR_SYSTEM_TIME_MISMATCH;
		return false;
	}	

	return true;
}

bool NM_CONNECT_CMD_S::validate_fields(uint32_t min_node_version, uint32_t madhava_version, char (&ebuf)[COMM_MAX_ERROR_LEN], ERR_CODES_E & errcode) noexcept
{
	*ebuf = 0;
	node_hostname_[sizeof(node_hostname_) - 1] = 0;

	if (comm_version_ > COMM_VERSION_NUM) {
		comm_version_ = COMM_VERSION_NUM;
	}
	else if (comm_version_ < MIN_COMM_VERSION_NUM) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Protocol Version %u not supported : Please upgrade the Node install", comm_version_);
		errcode = ERR_PROTOCOL_VERSION;

		return false;
	}	

	if (node_version_ < min_node_version) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Node Version %s (0x%08X) not supported : Please upgrade the Node install", 
						get_string_from_version_num(node_version_).get(), node_version_);
		errcode = ERR_NODE_VERSION;

		return false;
	}	

	if (min_madhava_version_ > madhava_version) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Madhava Version %s (0x%08X) not supported by node", 
						get_string_from_version_num(madhava_version).get(), madhava_version);
		errcode = ERR_SHYAMA_VERSION;

		return false;
	}	

	if (node_port_ == 0) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Node port cannot be 0");
		errcode = ERR_INVALID_REQUEST;

		return false;
	}	

	if ((uint32_t)cli_type_ >= (uint32_t)CLI_TYPE_MAX) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Invalid cli_type_ %u", cli_type_);
		errcode = ERR_INVALID_REQUEST;

		return false;
	}	

	int64_t				diff_sys_sec = time(nullptr) - curr_sec_;

	if (gy_unlikely(labs(diff_sys_sec) >= 60)) {
		snprintf(ebuf, COMM_MAX_ERROR_LEN, "Node Register failed as Node Host system time differs from Madhava by %ld seconds. Please sync the system times first.",
			diff_sys_sec);
		errcode = ERR_SYSTEM_TIME_MISMATCH;
		return false;
	}	

	return true;
}

bool TASK_MINI_ADD::validate(const COMM_HEADER *phdr, size_t & elem_sz) noexcept
{
	static constexpr size_t fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + sizeof(*this);

	if (phdr->get_act_len() < fixed_sz) {
		return false;
	}	
	
	GY_CC_BARRIER();

	if (phdr->get_act_len() < fixed_sz + task_cmdline_len_ + padding_len_) {
		return false;
	}	

	if (task_pid_ == 0) {
		return false;
	}

	elem_sz = fixed_sz + task_cmdline_len_ + padding_len_;

	if (elem_sz & (8 - 1)) {
		// Padding issue
		return false;
	}	

	task_comm_[sizeof(task_comm_) - 1] = 0;
	task_parent_comm_[sizeof(task_parent_comm_) - 1] = 0;

	if (task_cmdline_len_) {
		*((uint8_t *)this + sizeof(*this) + task_cmdline_len_ - 1) = '\0';
	}

	return true;
}	

bool TASK_MINI_ADD::validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
{
	COMM_HEADER			hdr = *phdr;
	const uint32_t			nevents = pnotify->nevents_;
	bool				bret;
	TASK_MINI_ADD			*ptmptask = (TASK_MINI_ADD *)(pnotify + 1);
	size_t				elem_sz;
	uint32_t			i;

	for (i = 0; i < nevents && (int)hdr.total_sz_ > (ssize_t)sizeof(COMM_HEADER); ++i) {
		bret = ptmptask->validate(&hdr, elem_sz);
		if (bret == false) {
			return false;
		}

		hdr.total_sz_ -= elem_sz;
		ptmptask = (TASK_MINI_ADD *)((uint8_t *)ptmptask + elem_sz);
	}
	
	return (i == nevents);
}	

bool TASK_FULL_ADD::validate(const COMM_HEADER *phdr, size_t & elem_sz) noexcept
{
	static constexpr size_t fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + sizeof(*this);

	if (phdr->get_act_len() < fixed_sz) {
		return false;
	}	
	
	GY_CC_BARRIER();

	if (phdr->get_act_len() < fixed_sz + task_exe_path_len_ + task_cmdline_len_ + task_tags_len_ + padding_len_) {
		return false;
	}	

	elem_sz = fixed_sz + task_exe_path_len_ + task_cmdline_len_ + task_tags_len_ + padding_len_;

	if (elem_sz & (8 - 1)) {
		// Padding issue
		return false;
	}	

	task_comm_[sizeof(task_comm_) - 1] = 0;
	task_parent_comm_[sizeof(task_parent_comm_) - 1] = 0;

	if (task_exe_path_len_) {
		*((uint8_t *)this + sizeof(*this) + task_exe_path_len_  - 1) = '\0';
	}	

	if (task_cmdline_len_) {
		*((uint8_t *)this + sizeof(*this) + task_exe_path_len_ + task_cmdline_len_ - 1) = '\0';
	}

	if (task_tags_len_) {
		*((uint8_t *)this + sizeof(*this) + task_exe_path_len_ + task_cmdline_len_ + task_tags_len_ - 1) = '\0';
	}	

	return true;
}	

bool TASK_FULL_ADD::validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
{
	COMM_HEADER			hdr = *phdr;
	const uint32_t			nevents = pnotify->nevents_;
	bool				bret;
	TASK_FULL_ADD			*ptmptask = (TASK_FULL_ADD *)(pnotify + 1);
	size_t				elem_sz;
	uint32_t			i;
	static constexpr size_t 	fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY);

	for (i = 0; i < nevents && (int)hdr.total_sz_ > (ssize_t)sizeof(COMM_HEADER); ++i) {
		bret = ptmptask->validate(&hdr, elem_sz);
		if (bret == false) {
			return false;
		}

		elem_sz -= fixed_sz;

		hdr.total_sz_ -= elem_sz;
		ptmptask = (TASK_FULL_ADD *)((uint8_t *)ptmptask + elem_sz);
	}
	
	return (i == nevents);
}	

bool TASK_AGGR_NOTIFY::validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
{
	static constexpr size_t 	fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY);

	if (phdr->get_act_len() < fixed_sz) {
		return false;
	}	
	
	ssize_t				totallen = phdr->get_act_len();
	const uint32_t			nelems = pnotify->nevents_;
	TASK_AGGR_NOTIFY		*pone = (TASK_AGGR_NOTIFY *)(pnotify + 1);
	uint32_t			i;

	if (nelems > MAX_NUM_AGGR_TASK) {
		return false;
	}

	totallen -= fixed_sz;

	for (i = 0; i < nelems && totallen >= (ssize_t)sizeof(TASK_AGGR_NOTIFY); ++i) {
		ssize_t elem_sz = pone->get_elem_size();

		if (totallen < elem_sz) {
			return false;
		}

		if (elem_sz & (8 - 1)) {
			// Padding issue
			return false;
		}	

		if (pone->cmdline_len_) {
			*((uint8_t *)pone + sizeof(*pone) + pone->cmdline_len_  - 1) = '\0';
		}

		if (pone->tag_len_) {
			*((uint8_t *)pone + sizeof(*pone) + pone->cmdline_len_ + pone->tag_len_ - 1) = '\0';
		}

		totallen -= elem_sz;

		pone = (TASK_AGGR_NOTIFY *)((uint8_t *)pone + elem_sz);
	}
	
	return (i == nelems);
}	


bool TASK_TOP_PROCS::validate(const COMM_HEADER *phdr) noexcept
{
	static constexpr size_t fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + sizeof(*this);

	if (phdr->get_act_len() < fixed_sz) {
		return false;
	}	
	
	GY_CC_BARRIER();

	if (phdr->get_act_len() - fixed_sz != ext_data_len_) {
		return false;
	}	

	if ((nprocs_ > TASK_MAX_TOP_N) || (npg_procs_ > TASK_MAX_TOP_N) || (nrss_procs_ > TASK_MAX_RSS_TOP_N) || (nfork_procs_ > TASK_MAX_FORKS_TOP_N)) {
		return false;
	}

	return (phdr->get_act_len() == fixed_sz - sizeof(*this) + get_elem_size());
}	

bool NEW_LISTENER::validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) const noexcept
{
	static constexpr size_t 	fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY);

	if (phdr->get_act_len() < fixed_sz) {
		return false;
	}	
	
	ssize_t				totallen = phdr->get_act_len();
	const uint32_t			nelems = pnotify->nevents_;
	NEW_LISTENER			*pone = (NEW_LISTENER *)(pnotify + 1);
	uint32_t				i;

	if (nelems > MAX_NUM_LISTENERS) {
		return false;
	}

	totallen -= fixed_sz;

	for (i = 0; i < nelems && totallen >= (ssize_t)sizeof(NEW_LISTENER); ++i) {
		ssize_t elem_sz = pone->get_elem_size();

		if (totallen < elem_sz) {
			return false;
		}

		if (elem_sz & (8 - 1)) {
			// Padding issue
			return false;
		}	

		if (pone->cmdline_len_) {
			*((uint8_t *)pone + sizeof(*pone) + pone->cmdline_len_  - 1) = '\0';
		}

		totallen -= elem_sz;

		pone = (NEW_LISTENER *)((uint8_t *)pone + elem_sz);
	}
	
	return (i == nelems);
}	



bool LISTENER_INFO_REQ::validate(const COMM_HEADER *phdr) const noexcept
{
	static constexpr size_t 	fixed_sz = sizeof(COMM_HEADER) + sizeof(QUERY_CMD) + sizeof(*this);

	if (phdr->get_act_len() < fixed_sz) {
		return false;
	}	

	if (ntcp_listeners_ > NEW_LISTENER::MAX_NUM_LISTENERS) {
		return false;
	}	
	
	GY_CC_BARRIER();

	const uint32_t			nelems = ntcp_listeners_;
	NEW_LISTENER			*pone = (NEW_LISTENER *)(this + 1);
	ssize_t				elem_sz;
	uint32_t			i;
	ssize_t				totallen = phdr->get_act_len();

	totallen -= fixed_sz;

	for (i = 0; i < nelems && totallen >= (ssize_t)sizeof(NEW_LISTENER); ++i) {
		elem_sz = pone->get_elem_size();

		if (totallen < elem_sz) {
			return false;
		}

		if (elem_sz & (8 - 1)) {
			// Padding issue
			return false;
		}	

		if (pone->cmdline_len_) {
			*((uint8_t *)pone + sizeof(*pone) + pone->cmdline_len_  - 1) = '\0';
		}

		totallen -= elem_sz;

		pone = (NEW_LISTENER *)((uint8_t *)pone + elem_sz);
	}
	
	return (i == nelems);
}	

uint32_t LISTENER_INFO_REQ::get_elem_size() const noexcept
{
	const uint32_t			nelems = ntcp_listeners_;
	NEW_LISTENER			*pone = (NEW_LISTENER *)(this + 1);
	ssize_t				elem_sz;
	uint32_t			i, totallen = sizeof(*this);

	for (i = 0; i < nelems; ++i) {
		elem_sz = pone->get_elem_size();

		totallen += elem_sz;

		pone = (NEW_LISTENER *)((uint8_t *)pone + elem_sz);
	}
	
	return totallen;
}	

bool LISTENER_DAY_STATS::validate(LISTENER_DAY_STATS *pone, uint32_t nelems, ssize_t totallen) noexcept
{
	return ((unsigned)nelems <= MAX_NUM_LISTENERS && (size_t)totallen >= nelems * sizeof(LISTENER_DAY_STATS));
}	

bool LISTENER_DAY_STATS::validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
{
	static constexpr size_t 	fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY);

	if (phdr->get_act_len() < fixed_sz) {
		return false;
	}	
	
	ssize_t				totallen = phdr->get_act_len();
	const uint32_t			nelems = pnotify->nevents_;
	LISTENER_DAY_STATS		*pone = (LISTENER_DAY_STATS *)(pnotify + 1);

	totallen -= fixed_sz;

	return LISTENER_DAY_STATS::validate(pone, nelems, totallen);
}	

bool LISTENERS_INFO_STATS_RESP::validate(const COMM_HEADER *phdr, const QUERY_RESPONSE *presp) const noexcept
{
	static constexpr size_t fixed_sz = sizeof(COMM_HEADER) + sizeof(QUERY_RESPONSE) + sizeof(*this);

	if ((phdr->get_act_len() < fixed_sz) || (presp->resp_len_ < sizeof(*this))) {
		return false;
	}	
	
	const uint32_t			nelems = ntcp_listeners_;
	LISTENER_DAY_STATS		*pone = (LISTENER_DAY_STATS *)(this + 1);
	ssize_t				resplen = presp->resp_len_ - sizeof(*this);

	return LISTENER_DAY_STATS::validate(pone, nelems, resplen);
}	


uint32_t LISTENERS_INFO_STATS_RESP::get_elem_size() const noexcept
{
	return sizeof(*this) + ntcp_listeners_ * sizeof(LISTENER_DAY_STATS);
}

bool TCP_CONN_NOTIFY::validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
{
	static constexpr size_t 	fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY);

	if (phdr->get_act_len() < fixed_sz) {
		return false;
	}	
	
	ssize_t				totallen = phdr->get_act_len();
	const int			nelems = pnotify->nevents_;
	TCP_CONN_NOTIFY			*pone = (TCP_CONN_NOTIFY *)(pnotify + 1);
	int				i;

	if ((unsigned)nelems > MAX_NUM_CONNS) {
		return false;
	}	

	totallen -= fixed_sz;

	for (i = 0; i < nelems && totallen >= (ssize_t)sizeof(TCP_CONN_NOTIFY); ++i) {
		ssize_t elem_sz = pone->get_elem_size();

		if (totallen < elem_sz) {
			return false;
		}

		if (elem_sz & (8 - 1)) {
			// Padding issue
			return false;
		}	

		if (pone->cli_cmdline_len_) {
			*((uint8_t *)pone + sizeof(*pone) + pone->cli_cmdline_len_  - 1) = '\0';
		}

		totallen -= elem_sz;

		pone = (TCP_CONN_NOTIFY *)((uint8_t *)pone + elem_sz);
	}
	
	return (i == nelems);
}	

bool CPU_MEM_STATE_NOTIFY::validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
{
	static constexpr size_t 	fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY);

	if (phdr->get_act_len() < fixed_sz) {
		return false;
	}	

	if (pnotify->nevents_ != 1) {
		return false;
	}	

	GY_CC_BARRIER();

	if (phdr->get_act_len() != fixed_sz + get_elem_size()) {
		return false;
	}	

	if (cpu_state_string_len_) {
		*((uint8_t *)this + sizeof(*this) + cpu_state_string_len_  - 1) = '\0';
	}
	
	if (mem_state_string_len_) {
		*((uint8_t *)this + sizeof(*this) + cpu_state_string_len_ + mem_state_string_len_ - 1) = '\0';
	}

	return true;
}	

bool AGGR_TASK_STATE_NOTIFY::validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
{
	static constexpr size_t 	fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY);

	if (phdr->get_act_len() < fixed_sz) {
		return false;
	}	
	
	ssize_t				totallen = phdr->get_act_len();
	const int			nelems = pnotify->nevents_;
	AGGR_TASK_STATE_NOTIFY		*pone = (AGGR_TASK_STATE_NOTIFY *)(pnotify + 1);
	int				i;

	if ((unsigned)nelems > MAX_NUM_TASKS) {
		return false;
	}	

	totallen -= fixed_sz;

	for (i = 0; i < nelems && totallen >= (ssize_t)sizeof(AGGR_TASK_STATE_NOTIFY); ++i) {
		ssize_t elem_sz = pone->get_elem_size();

		if (totallen < elem_sz) {
			return false;
		}

		if (elem_sz & (8 - 1)) {
			// Padding issue
			return false;
		}	

		if (pone->issue_string_len_) {
			*((uint8_t *)pone + sizeof(*pone) + pone->issue_string_len_  - 1) = '\0';
		}

		totallen -= elem_sz;

		pone = (AGGR_TASK_STATE_NOTIFY *)((uint8_t *)pone + elem_sz);
	}
	
	return (i == nelems);
}	

bool LISTENER_STATE_NOTIFY::validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
{
	static constexpr size_t 	fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY);

	if (phdr->get_act_len() < fixed_sz) {
		return false;
	}	
	
	ssize_t				totallen = phdr->get_act_len();
	const int			nelems = pnotify->nevents_;
	LISTENER_STATE_NOTIFY		*pone = (LISTENER_STATE_NOTIFY *)(pnotify + 1);
	int				i;

	if ((unsigned)nelems > MAX_NUM_LISTENERS) {
		return false;
	}	

	totallen -= fixed_sz;

	for (i = 0; i < nelems && totallen >= (ssize_t)sizeof(LISTENER_STATE_NOTIFY); ++i) {
		ssize_t elem_sz = pone->get_elem_size();

		if (totallen < elem_sz) {
			return false;
		}

		if (elem_sz & (8 - 1)) {
			// Padding issue
			return false;
		}	

		if (pone->issue_string_len_) {
			*((uint8_t *)pone + sizeof(*pone) + pone->issue_string_len_  - 1) = '\0';
		}

		totallen -= elem_sz;

		pone = (LISTENER_STATE_NOTIFY *)((uint8_t *)pone + elem_sz);
	}
	
	return (i == nelems);
}

bool LISTENER_DEPENDENCY_NOTIFY::validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
{
	static_assert(LISTENER_DEPENDENCY_NOTIFY::get_max_elem_size() * MAX_NUM_LISTENERS < MAX_COMM_DATA_SZ, "Max Network Payload size limit breached");

	static_assert(LISTENER_DEPENDENCY_NOTIFY::get_max_elem_size() < 512 * 1024);

	static constexpr size_t 	fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY);

	if (phdr->get_act_len() < fixed_sz) {
		return false;
	}	
	
	ssize_t				totallen = phdr->get_act_len();
	const int			nelems = pnotify->nevents_;
	LISTENER_DEPENDENCY_NOTIFY	*pone = (LISTENER_DEPENDENCY_NOTIFY *)(pnotify + 1);
	int				i;

	if ((unsigned)nelems > MAX_NUM_LISTENERS) {
		return false;
	}	

	totallen -= fixed_sz;

	for (i = 0; i < nelems && totallen >= (ssize_t)sizeof(LISTENER_DEPENDENCY_NOTIFY); ++i) {
		ssize_t elem_sz = pone->get_elem_size();

		if (totallen < elem_sz) {
			return false;
		}

		if (pone->ndepends_ > MAX_DEPENDS_PER_LISTEN) {
			return false;
		}	

		totallen -= elem_sz;

		pone = (LISTENER_DEPENDENCY_NOTIFY *)((uint8_t *)pone + elem_sz);
	}
	
	return (i == nelems);
}

bool LISTENER_CLUSTER_NOTIFY::validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
{
	static_assert(LISTENER_CLUSTER_NOTIFY::get_max_elem_size() * MAX_NUM_LISTENERS < MAX_COMM_DATA_SZ, "Max Network Payload size limit breached");

	static_assert(LISTENER_CLUSTER_NOTIFY::get_max_elem_size() < 512 * 1024);

	static constexpr size_t 	fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY);

	if (phdr->get_act_len() < fixed_sz) {
		return false;
	}	
	
	ssize_t				totallen = phdr->get_act_len();
	const int			nelems = pnotify->nevents_;
	auto				*pone = (LISTENER_CLUSTER_NOTIFY *)(pnotify + 1);
	int				i;

	if ((unsigned)nelems > MAX_NUM_LISTENERS) {
		return false;
	}	

	totallen -= fixed_sz;

	for (i = 0; i < nelems && totallen >= (ssize_t)sizeof(LISTENER_CLUSTER_NOTIFY); ++i) {
		ssize_t elem_sz = pone->get_elem_size();

		if (totallen < elem_sz) {
			return false;
		}

		if (pone->ncluster_elems_ > MAX_CLUSTER_ELEMS) {
			return false;
		}	

		totallen -= elem_sz;

		pone = (LISTENER_CLUSTER_NOTIFY *)((uint8_t *)pone + elem_sz);
	}
	
	return (i == nelems);
}

bool MS_SVC_CLUSTER_MESH::validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
{
	static_assert(MS_SVC_CLUSTER_MESH::get_max_elem_size() * MAX_NUM_CLUSTERS < MAX_COMM_DATA_SZ, "Max Network Payload size limit breached");

	static_assert(MS_SVC_CLUSTER_MESH::get_max_elem_size() < 512 * 1024);

	static constexpr size_t 	fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY);

	if (phdr->get_act_len() < fixed_sz) {
		return false;
	}	
	
	ssize_t				totallen = phdr->get_act_len();
	const int			nelems = pnotify->nevents_;
	auto				*pone = (MS_SVC_CLUSTER_MESH *)(pnotify + 1);
	int				i;

	if ((unsigned)nelems > MAX_NUM_CLUSTERS) {
		return false;
	}	

	totallen -= fixed_sz;

	for (i = 0; i < nelems && totallen >= (ssize_t)sizeof(MS_SVC_CLUSTER_MESH); ++i) {
		ssize_t elem_sz = pone->get_elem_size();

		if (totallen < elem_sz) {
			return false;
		}

		if (pone->ncluster_elems_ > MAX_CLUSTER_ELEMS) {
			return false;
		}	

		totallen -= elem_sz;

		pone = (MS_SVC_CLUSTER_MESH *)((uint8_t *)pone + elem_sz);
	}
	
	return (i == nelems);
}

bool SM_SVC_CLUSTER_MESH::validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
{
	static constexpr size_t 	fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY);

	if (phdr->get_act_len() < fixed_sz) {
		return false;
	}	
	
	ssize_t				totallen = phdr->get_act_len();
	const int			nelems = pnotify->nevents_;
	auto				*pone = (SM_SVC_CLUSTER_MESH *)(pnotify + 1);
	int				i;

	if ((unsigned)nelems > MAX_NUM_CLUSTERS) {
		return false;
	}	

	totallen -= fixed_sz;

	for (i = 0; i < nelems && totallen >= (ssize_t)sizeof(SM_SVC_CLUSTER_MESH); ++i) {
		ssize_t elem_sz = pone->get_elem_size();

		if (totallen < elem_sz) {
			return false;
		}

		if (pone->nmadhava_elems_ > MAX_CLUSTER_ELEMS) {
			return false;
		}	

		totallen -= elem_sz;

		pone = (SM_SVC_CLUSTER_MESH *)((uint8_t *)pone + elem_sz);
	}
	
	return (i == nelems);
}


bool MS_LISTENER_NAT_IP::validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
{
	static_assert(MS_LISTENER_NAT_IP::get_max_elem_size() * MAX_NUM_LISTENERS < MAX_COMM_DATA_SZ, "Max Network Payload size limit breached");

	static_assert(MS_LISTENER_NAT_IP::get_max_elem_size() < 512 * 1024);

	static constexpr size_t 	fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY);

	if (phdr->get_act_len() < fixed_sz) {
		return false;
	}	
	
	ssize_t				totallen = phdr->get_act_len();
	const int			nelems = pnotify->nevents_;
	auto				*pone = (MS_LISTENER_NAT_IP *)(pnotify + 1);
	int				i;

	if ((unsigned)nelems > MAX_NUM_LISTENERS) {
		return false;
	}	

	totallen -= fixed_sz;

	for (i = 0; i < nelems && totallen >= (ssize_t)sizeof(MS_LISTENER_NAT_IP); ++i) {
		ssize_t elem_sz = pone->get_elem_size();

		if (totallen < elem_sz) {
			return false;
		}

		if (pone->nelems_new_ + pone->nelems_del_ > MAX_ELEMS) {
			return false;
		}	

		totallen -= elem_sz;

		pone = (MS_LISTENER_NAT_IP *)((uint8_t *)pone + elem_sz);
	}
	
	return (i == nelems);
}


bool MM_LISTENER_ISSUE_RESOL::validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
{
	static constexpr size_t 	fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY);

	if (phdr->get_act_len() < fixed_sz) {
		return false;
	}	
	
	ssize_t				totallen = phdr->get_act_len();
	const int			nelems = pnotify->nevents_;
	MM_LISTENER_ISSUE_RESOL		*pone = (MM_LISTENER_ISSUE_RESOL *)(pnotify + 1);
	int				i;

	if ((unsigned)nelems > MAX_NUM_LISTENERS) {
		return false;
	}	

	totallen -= fixed_sz;

	for (i = 0; i < nelems && totallen >= (ssize_t)sizeof(MM_LISTENER_ISSUE_RESOL); ++i) {
		ssize_t elem_sz = pone->get_elem_size();

		if (totallen < elem_sz) {
			return false;
		}

		if (pone->ndownstreams_ > MAX_DOWNSTREAM_IDS) {
			return false;
		}	

		if (elem_sz & (8 - 1)) {
			// Padding issue
			return false;
		}	

		totallen -= elem_sz;

		pone = (MM_LISTENER_ISSUE_RESOL *)((uint8_t *)pone + elem_sz);
	}
	
	return (i == nelems);
}

bool LISTENER_DOMAIN_NOTIFY::validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
{
	static constexpr size_t 	fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY);

	if (phdr->get_act_len() < fixed_sz) {
		return false;
	}	
	
	ssize_t				totallen = phdr->get_act_len();
	const int			nelems = pnotify->nevents_;
	LISTENER_DOMAIN_NOTIFY		*pone = (LISTENER_DOMAIN_NOTIFY *)(pnotify + 1);
	int				i;

	if ((unsigned)nelems > MAX_NUM_LISTENERS) {
		return false;
	}	

	totallen -= fixed_sz;

	for (i = 0; i < nelems && totallen >= (ssize_t)sizeof(LISTENER_DOMAIN_NOTIFY); ++i) {
		ssize_t elem_sz = pone->get_elem_size();

		if (totallen < elem_sz) {
			return false;
		}

		if (elem_sz & (8 - 1)) {
			// Padding issue
			return false;
		}	

		if (pone->domain_string_len_) {
			*((uint8_t *)pone + sizeof(*pone) + pone->domain_string_len_  - 1) = '\0';
		}

		if (pone->tag_len_) {
			*((uint8_t *)pone + sizeof(*pone) + pone->domain_string_len_ + pone->tag_len_ - 1) = '\0';
		}

		totallen -= elem_sz;

		pone = (LISTENER_DOMAIN_NOTIFY *)((uint8_t *)pone + elem_sz);
	}
	
	return (i == nelems);
}


bool LISTEN_TASKMAP_NOTIFY::validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) const noexcept
{
	static constexpr size_t 	fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY);

	if (phdr->get_act_len() < fixed_sz) {
		return false;
	}	
	
	ssize_t				totallen = phdr->get_act_len();
	const int			nelems = pnotify->nevents_;
	LISTEN_TASKMAP_NOTIFY		*pone = (LISTEN_TASKMAP_NOTIFY *)(pnotify + 1);
	int				i;

	totallen -= fixed_sz;

	if ((size_t)nelems > MAX_NUM_LISTENERS) {
		return false;
	}	

	for (i = 0; i < nelems && totallen >= (ssize_t)sizeof(LISTEN_TASKMAP_NOTIFY); ++i) {
		ssize_t elem_sz = pone->get_elem_size();

		if (totallen < elem_sz) {
			return false;
		}

		if (pone->nlisten_ > MAX_NUM_LISTENERS) {
			return false;
		}	
		else if (pone->naggr_taskid_ > MAX_NUM_TASKS) {
			return false;
		}	

		totallen -= elem_sz;

		pone = (LISTEN_TASKMAP_NOTIFY *)((uint8_t *)pone + elem_sz);
	}
	
	return (i == nelems);
}

bool NOTIFICATION_MSG::validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
{
	static constexpr size_t 	fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY);

	if (phdr->get_act_len() < fixed_sz) {
		return false;
	}	
	
	ssize_t				totallen = phdr->get_act_len();
	const int			nelems = pnotify->nevents_;
	NOTIFICATION_MSG		*pone = (NOTIFICATION_MSG *)(pnotify + 1);
	int				i;

	if ((unsigned)nelems > MAX_NUM_MSG) {
		return false;
	}	

	totallen -= fixed_sz;

	for (i = 0; i < nelems && totallen >= (ssize_t)sizeof(NOTIFICATION_MSG); ++i) {
		ssize_t elem_sz = pone->get_elem_size();

		if (totallen < elem_sz) {
			return false;
		}

		if (elem_sz & (8 - 1)) {
			// Padding issue
			return false;
		}	

		if (pone->msglen_) {
			*((uint8_t *)pone + sizeof(*pone) + pone->msglen_  - 1) = '\0';
		}

		totallen -= elem_sz;

		pone = (NOTIFICATION_MSG *)((uint8_t *)pone + elem_sz);
	}
	
	return (i == nelems);
}	

bool SM_ALERT_ADEF_NEW::validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) const noexcept
{
	static constexpr size_t 	fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY);

	if (phdr->get_act_len() < fixed_sz) {
		return false;
	}	
	
	ssize_t				totallen = phdr->get_act_len();
	const uint32_t			nelems = pnotify->nevents_;
	SM_ALERT_ADEF_NEW		*pone = (SM_ALERT_ADEF_NEW *)(pnotify + 1);
	uint32_t			i;

	if (nelems > MAX_NUM_DEFS) {
		return false;
	}

	totallen -= fixed_sz;

	for (i = 0; i < nelems && totallen >= (ssize_t)sizeof(SM_ALERT_ADEF_NEW); ++i) {
		ssize_t elem_sz = pone->get_elem_size();

		if (totallen < elem_sz) {
			return false;
		}

		if (elem_sz & (8 - 1)) {
			// Padding issue
			return false;
		}	

		if (pone->lenjson_ == 0) {
			return false;
		}

		*((uint8_t *)pone + sizeof(*pone) + pone->lenjson_  - 1) = '\0';

		totallen -= elem_sz;

		pone = (SM_ALERT_ADEF_NEW *)((uint8_t *)pone + elem_sz);
	}
	
	return (i == nelems);
}	


bool ALERT_STAT_INFO::validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) const noexcept
{
	static constexpr size_t 	fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY);

	if (phdr->get_act_len() < fixed_sz) {
		return false;
	}	
	
	ssize_t				totallen = phdr->get_act_len();
	const uint32_t			nelems = pnotify->nevents_;
	ALERT_STAT_INFO			*pone = (ALERT_STAT_INFO *)(pnotify + 1);
	uint32_t			i;

	if (nelems > MAX_NUM_STATS) {
		return false;
	}

	totallen -= fixed_sz;

	for (i = 0; i < nelems && totallen >= (ssize_t)sizeof(ALERT_STAT_INFO); ++i) {
		ssize_t elem_sz = pone->get_elem_size();

		if (totallen < elem_sz) {
			return false;
		}

		if (elem_sz & (8 - 1)) {
			// Padding issue
			return false;
		}	

		if (pone->lenjson_ == 0) {
			return false;
		}

		*((uint8_t *)pone + sizeof(*pone) + pone->lenjson_  - 1) = '\0';

		totallen -= elem_sz;

		pone = (ALERT_STAT_INFO *)((uint8_t *)pone + elem_sz);
	}
	
	return (i == nelems);
}	

bool MS_REG_PARTHA::validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
{
	static constexpr size_t 	fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY);

	if (phdr->get_act_len() < fixed_sz) {
		return false;
	}	

	if (pnotify->nevents_ > MAX_REG_PARTHA) {
		return false;
	}	

	GY_CC_BARRIER();

	if (phdr->get_act_len() != fixed_sz + pnotify->nevents_ * sizeof(MS_REG_PARTHA)) {
		return false;
	}	

	MS_REG_PARTHA			*pone = (MS_REG_PARTHA *)(pnotify + 1);
	auto				nelems = pnotify->nevents_, i = 0u;

	for (i = 0; i < nelems; ++i, ++pone) {
		pone->hostname_[sizeof(pone->hostname_) - 1] 		= 0;
		pone->cluster_name_[sizeof(pone->cluster_name_) - 1] 	= 0;
		pone->region_name_[sizeof(pone->region_name_) - 1]	= 0;
		pone->zone_name_[sizeof(pone->zone_name_) - 1]		= 0;
	}

	return true;
}	

bool REQ_TRACE_TRAN::validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) noexcept
{
	static constexpr size_t 	fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY);

	static_assert(sizeof(REQ_TRACE_TRAN) == sizeof(API_TRAN), "Please change code directly referencing API_TRAN");

	if (phdr->get_act_len() < fixed_sz) {
		return false;
	}	
	
	ssize_t				totallen = phdr->get_act_len();
	const uint32_t			nelems = pnotify->nevents_;
	REQ_TRACE_TRAN			*pone = (REQ_TRACE_TRAN *)(pnotify + 1);
	uint32_t			i;

	if (nelems > MAX_NUM_REQS) {
		return false;
	}

	if (phdr->get_total_len() >= get_max_actual_send_size()) {
		return false;
	}

	totallen -= fixed_sz;

	for (i = 0; i < nelems && totallen >= (ssize_t)sizeof(REQ_TRACE_TRAN); ++i) {
		ssize_t elem_sz = pone->get_elem_size();

		if (totallen < elem_sz) {
			return false;
		}

		if (elem_sz & (8 - 1)) {
			// Padding issue
			return false;
		}	

		if (pone->request_len_ == 0 || pone->request_len_ > MAX_PARSE_API_LEN) {
			return false;
		}
		
		if (pone->lenext_ > MAX_PARSE_EXT_LEN) {
			return false;
		}	

		*((uint8_t *)pone + sizeof(*pone) + pone->request_len_  - 1) = '\0';

		totallen -= elem_sz;

		pone = (REQ_TRACE_TRAN *)((uint8_t *)pone + elem_sz);
	}
	
	return (i == nelems);
}	


bool SM_REQ_TRACE_DEF_NEW::validate(const COMM_HEADER *phdr, const EVENT_NOTIFY *pnotify) const noexcept
{
	static constexpr size_t 	fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY);

	if (phdr->get_act_len() < fixed_sz) {
		return false;
	}	
	
	ssize_t				totallen = phdr->get_act_len();
	const uint32_t			nelems = pnotify->nevents_;
	SM_REQ_TRACE_DEF_NEW		*pone = (SM_REQ_TRACE_DEF_NEW *)(pnotify + 1);
	uint32_t			i;

	if (nelems > MAX_NUM_DEFS) {
		return false;
	}

	totallen -= fixed_sz;

	for (i = 0; i < nelems && totallen >= (ssize_t)sizeof(SM_REQ_TRACE_DEF_NEW); ++i) {
		ssize_t elem_sz = pone->get_elem_size();

		if (totallen < elem_sz) {
			return false;
		}

		if (elem_sz & (8 - 1)) {
			// Padding issue
			return false;
		}	

		if (pone->ncap_glob_id_arr_ == 0 && pone->lencrit_ == 0) {
			return false;
		}
		else if (pone->ncap_glob_id_arr_ && pone->lencrit_) {
			// Either ncap_glob_id_arr_ or lencrit_ can be specified
			return false;
		}	

		if (pone->ncap_glob_id_arr_ > MAX_GLOB_ID_ARR) {
			return false;
		}	
		
		pone->name_[sizeof(pone->name_) - 1] = 0;

		if (pone->lencrit_) {
			*((uint8_t *)pone + sizeof(*pone) + pone->lencrit_  - 1) = '\0';
		}	

		totallen -= elem_sz;

		pone = (SM_REQ_TRACE_DEF_NEW *)((uint8_t *)pone + elem_sz);
	}
	
	return (i == nelems);
}	


} // namespace comm

} // namespace gyeeta

