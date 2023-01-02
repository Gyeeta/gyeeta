//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include		"gy_ebpf.h"
#include		"gy_rcu_inc.h"
#include		"gy_ebpf_common.h"

#include		<dirent.h>

namespace gyeeta {


/*
 * Each interval as specified by RESPONSE_BPF_TIME_MSEC is divided into MAX_RESP_SAMPLING_SLOTS slots and based on the sampling rate
 * we try to schedule the response collection
 */
void RESP_SAMPLING::set_resp_sampling_pct(uint8_t resp_sampling_pct) noexcept
{
	if (resp_sampling_pct > 0 && resp_sampling_pct < 100) {
		resp_sampling_pct = gy_align_up(resp_sampling_pct - 1, 10);
	}	
	else if (resp_sampling_pct > 100) {
		resp_sampling_pct = 100;
	}	

	static_assert(MAX_RESP_SAMPLING_SLOTS == 10, "Max Resp Sampling Slots needs to be set as 10");

	INFOPRINT_OFFLOAD("Setting Response Sampling Percent to %hhu%% : Older Sampling Percent was %hhu%%\n", resp_sampling_pct, curr_sampling_pct_);

	curr_sampling_pct_ 		= resp_sampling_pct;

	switch (curr_sampling_pct_) {
	
	case 100 :
	default :
		std::memset(sample_state_arr_, true, sizeof(sample_state_arr_));
		break;
	
	case 90 :
		std::memset(sample_state_arr_, true, sizeof(sample_state_arr_));
		sample_state_arr_[4] 	= false;
		break;
	
	case 80 :
		std::memset(sample_state_arr_, true, sizeof(sample_state_arr_));
		sample_state_arr_[3] 	= false;
		sample_state_arr_[7]	= false;
		break;
				
	case 70 :
		std::memset(sample_state_arr_, true, sizeof(sample_state_arr_));
		sample_state_arr_[2] 	= false;
		sample_state_arr_[5]	= false;
		sample_state_arr_[8]	= false;
		break;
				
	case 60 :
		std::memset(sample_state_arr_, true, sizeof(sample_state_arr_));
		sample_state_arr_[2] 	= false;
		sample_state_arr_[4]	= false;
		sample_state_arr_[7]	= false;
		sample_state_arr_[9]	= false;
		break;
	
	case 50 :
		for (uint8_t i = 0; i < 10; i += 2) {
		 	sample_state_arr_[i] 	= true;
		}				

		for (uint8_t i = 1; i < 10; i += 2) {
		 	sample_state_arr_[i] 	= false;
		}				
		break;

	case 40 :
		std::memset(sample_state_arr_, false, sizeof(sample_state_arr_));
		sample_state_arr_[2] 	= true;
		sample_state_arr_[4]	= true;
		sample_state_arr_[7]	= true;
		sample_state_arr_[9]	= true;
		break;
		
	case 30 :
		std::memset(sample_state_arr_, false, sizeof(sample_state_arr_));
		sample_state_arr_[2] 	= true;
		sample_state_arr_[5]	= true;
		sample_state_arr_[8]	= true;
		break;
				
	case 20 :
		std::memset(sample_state_arr_, false, sizeof(sample_state_arr_));
		sample_state_arr_[3] 	= true;
		sample_state_arr_[7]	= true;
		break;
				
	case 10 :
		std::memset(sample_state_arr_, false, sizeof(sample_state_arr_));
		sample_state_arr_[4] 	= true;
		break;

	case 0 :
		std::memset(sample_state_arr_, false, sizeof(sample_state_arr_));
		break;
	}	
}	


bool host_btf_enabled(bool check_module) noexcept
{
	DIR				*pdir;
	struct dirent			*pdent;
	char				*pfile;
	bool				is_vmlinux = false, is_mod = false;

	if (!check_module) {
		return !access("/sys/kernel/btf/vmlinux", R_OK);
	}

	pdir = opendir("/sys/kernel/btf");
	if (!pdir) {
		return false;
	}

	while ((pdent = readdir(pdir)) != nullptr) {

		pfile = pdent->d_name;	
		
		if (!gy_isdigit_ascii(*pfile)) {
			continue;
		}

		if (0 == strcmp(pfile, "vmlinux")) {
			is_vmlinux = true;
		}	
		else {
			is_mod = true;
		}	
	}

	closedir(pdir);

	return (is_vmlinux && is_mod);
}	

	
} // namespace gyeeta

