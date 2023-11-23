//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"

namespace gyeeta {

enum DROP_TYPES : uint8_t 
{
	DT_NO_DROP 		= 0,
	DT_RETRANSMIT		= 1 << 0,
	DT_DROP_SEEN		= 1 << 1,
	DT_DROP_NEW_SESS	= 1 << 2,		// Very Large drop, maybe a new sess
};


// Returns drop status for both dirs (current and other)
static std::pair<DROP_TYPES, DROP_TYPES> is_tcp_drop(uint32_t exp_seq, uint32_t act_seq, uint32_t exp_ack, uint32_t act_ack, bool is_syn = false) noexcept
{
	int			diff = exp_seq - act_seq, diffack = exp_ack - act_ack;

	if (diff == 0) {
		if (diffack >= 0) {
			return {DT_NO_DROP, DT_NO_DROP};
		}

		return {DT_NO_DROP, DT_DROP_SEEN};
	}

	if (diff > 0) {	
		if (diff < 1024 * 1024) {
			return {DT_RETRANSMIT, DT_RETRANSMIT};
		}
		else {
			if (is_syn || abs(diffack) > 1024 * 1024) {
				return {DT_DROP_NEW_SESS, DT_DROP_NEW_SESS};
			}
			else {
				return {DT_RETRANSMIT, DT_RETRANSMIT};
			}
		}
	}

	if ((diff < -100 * 1024 * 1024) || ((diff < -1024 * 1024) && (is_syn || abs(diffack) > 1024 * 1024))) {
		return {DT_DROP_NEW_SESS, DT_DROP_NEW_SESS};
	}

	if (diffack >= 0) {
		return {DT_DROP_SEEN, DT_NO_DROP};
	}

	return {DT_DROP_SEEN, DT_DROP_SEEN};
}	

static uint64_t tcp_drop_bytes(uint32_t exp_seq, uint32_t act_seq, uint32_t exp_ack, uint32_t act_ack, bool is_syn = false) noexcept
{
	uint64_t			dbytes = 0;
	auto				[type, typea] = is_tcp_drop(exp_seq, act_seq, exp_ack, act_ack, is_syn);	

	if ((type == DT_NO_DROP || type == DT_RETRANSMIT) && (typea == DT_NO_DROP || typea == DT_RETRANSMIT)) {
		return 0;
	}	
	else if (type == DT_DROP_NEW_SESS) {
		return 1024;	// We do not know the extent of the drop. Set a small drop byte count
	}	

	if (type == DT_DROP_SEEN) {
		dbytes = abs(int(act_seq - exp_seq));
	}	

	if (typea == DT_DROP_SEEN) {
		dbytes += abs(int(act_ack - exp_ack));
	}	

	return dbytes;
}	



} // namespace gyeeta

