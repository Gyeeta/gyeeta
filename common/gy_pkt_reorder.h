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

	if ((diff < -1024 * 1024) && (is_syn || abs(int(exp_other_seq - act_other_seq)) > 1024 * 1024)) {
		return DROP_TYPES::DROP_NEW_SESS;
	}

	return DROP_TYPES::DROP_SEEN;
}	



} // namespace gyeeta

