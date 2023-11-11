//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"

namespace gyeeta {

enum class DROP_TYPES : uint8_t 
{
	NO_DROP 		= 0,
	RETRANSMIT		= 1 << 0,
	DROP_SEEN		= 1 << 1,
	DROP_NEW_SESS		= 1 << 2,		// Very Large drop, maybe a new sess
};


static DROP_TYPES is_tcp_drop(uint32_t exp_seq, uint32_t act_seq, bool is_syn = false, uint32_t exp_other_seq = 0, uint32_t act_other_seq = 0) noexcept
{
	int			diff;

	diff = exp_seq - act_seq;

	if (diff == 0) {
		return DROP_TYPES::NO_DROP;
	}

	if (diff > 0) {	
		if (diff < 1024 * 1024) {
			return DROP_TYPES::RETRANSMIT;
		}
		else {
			if (is_syn || abs(int(exp_other_seq - act_other_seq)) > 1024 * 1024) {
				return DROP_TYPES::DROP_NEW_SESS;
			}
			else {
				return DROP_TYPES::RETRANSMIT;
			}
		}
	}

	if ((diff < -100 * 1024 * 1024) || ((diff < -1024 * 1024) && (is_syn || abs(int(exp_other_seq - act_other_seq)) > 1024 * 1024))) {
		return DROP_TYPES::DROP_NEW_SESS;
	}

	return DROP_TYPES::DROP_SEEN;
}	

static uint32_t tcp_drop_bytes(uint32_t exp_seq, uint32_t act_seq, bool is_syn = false, uint32_t exp_other_seq = 0, uint32_t act_other_seq = 0) noexcept
{

	auto			droptype = is_tcp_drop(exp_seq, act_seq, is_syn, exp_other_seq, act_other_seq);	

	if (droptype == DROP_TYPES::NO_DROP || droptype == DROP_TYPES::RETRANSMIT) {
		return 0;
	}	
	else if (droptype == DROP_TYPES::DROP_NEW_SESS) {
		return 1024;	// We do not know the extent of the drop. Set a small drop byte count
	}	

	return abs(int(act_seq - exp_seq));
}	



} // namespace gyeeta

