//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma once 

#include		"gy_common_inc.h"
#include		"gy_file_api.h"
#include		"gy_pkt_pool.h"

#include 		<unistd.h>
#include 		<cstdlib>
#include 		<string>
#include		<cstdint>
#include		<arpa/inet.h>
#include		<linux/sched.h>


#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP		0x02000000	/* New cgroup namespace */
#endif

extern std::atomic<int>	gsig_rcvd;
extern void * 		nlct_thread(void *arg);
extern void * 		inet_diag_thr(void *arg);


