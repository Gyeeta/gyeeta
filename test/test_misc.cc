//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include 		"gy_common_inc.h"
#include 		"gy_file_api.h"
#include 		"gy_task_stat.h"
#include 		"gy_scheduler.h"
#include 		"gy_async_func.h"
#include 		"gy_mount_disk.h"

using namespace gyeeta;


namespace TEST_SPACE {

#include		"./testdata/test_proc_status1.cc"
#include		"./testdata/test_proc_cgroup.cc"
	
int test_string_rd_buf()
{
	INFOPRINTCOLOR(GY_COLOR_YELLOW, "Testing /proc/pid/status of gstatus_k8s_nginx...\n\n");

	STR_RD_BUF				nginx1(gstatus_k8s_nginx, sizeof(gstatus_k8s_nginx) - 1);
	const char				*ptmp;
	size_t					nbytes, tsz;

	ptmp = nginx1.get_next_word(nbytes);

	tsz = GY_CONST_STRLEN("Name:");
	if (nbytes >= tsz && (0 == memcmp(ptmp, "Name:", tsz))) {
		ptmp = nginx1.get_next_word(nbytes);

		IRPRINT("Name (comm) of process is \'%.*s\'\n", (int)nbytes, ptmp);
	}	
	
	ptmp = nginx1.get_next_line(nbytes);
	if (ptmp) IRPRINT("Next line is \'%.*s\'\n", (int)nbytes, ptmp);

	ptmp = nginx1.get_next_line(nbytes);
	if (ptmp) IRPRINT("Next line is \'%.*s\'\n", (int)nbytes, ptmp);

	ptmp = nginx1.get_next_word(nbytes);

	tsz = GY_CONST_STRLEN("Tgid:");
	if (nbytes >= tsz && 0 == memcmp(ptmp, "Tgid:", tsz)) {
		ptmp = nginx1.get_next_word(nbytes);

		if (ptmp) IRPRINT("Tgid (PID) of process is \'%.*s\' (%d)\n", (int)nbytes, ptmp, atoi(ptmp));
	}	
	
	ptmp = nginx1.skip_till_substring_const("Groups:");
	assert(ptmp != nullptr);

	ptmp = nginx1.skip_till_next_delim('\n');

	ptmp = nginx1.get_next_word(nbytes);

	tsz = GY_CONST_STRLEN("NStgid:");
	if (nbytes >= tsz && 0 == memcmp(ptmp, "NStgid:", tsz)) {
		ptmp = nginx1.get_next_word(nbytes);

		if (ptmp) IRPRINT("NSTgid (PID) of process in root NS is %d\n", atoi(ptmp));

		ptmp = nginx1.get_next_word(nbytes);
		if (ptmp && isdigit(*ptmp)) {
			IRPRINT("NSTgid (PID) of process in PID namespace is %d\n", atoi(ptmp));

			char		test1[16];

			nbytes = nginx1.peek_next_nchars(test1, sizeof(test1) - 1);
			if (nbytes && isalpha(*test1)) {
				ptmp = nginx1.get_next_word(nbytes);

				if (ptmp) IRPRINT("Next word is \'%.*s\'\n", (int)nbytes, ptmp);
			}	
		}	
	}	
	
	return 0;
}	
	
struct TASK_INFO
{
	pid_t					pid;		// In root PID namespace
	pid_t					ppid;		// In root PID namespace
	pid_t					pgid;		// In root PID namespace
	pid_t					sid;		// In root PID namespace
	
	pid_t					nspid;		// 1st level PID namespace
	pid_t					nspgid;		// 1st level PID namespace
	pid_t					nssid;		// 1st level PID namespace

	char					comm[TASK_COMM_LEN];

	uid_t					realuid;
	uid_t					effuid;
	uid_t					saveduid;
	uid_t					fsuid;

	gid_t					realgid;
	gid_t					effgid;
	gid_t					savedgid;
	gid_t					fsgid;
	
	uint32_t				nthreads;
	
	GY_CAPABILITIES				taskcap;

	std::bitset<32>				cpus_allowed;
	std::bitset<32>				mems_allowed;	

	char * get_task_info_str(char *pbuf, size_t bufsz)
	{
		STR_WR_BUF			strbuf(pbuf, bufsz);
		
		try {
			strbuf.appendfmt("Task info for PID %d Comm %s : PPID %d PGID %d SID %d 1st level PID namespace NSPID %d NSPGID %d NSSID %d : realuid %u effuid %u saveduid %u fsuid %u : realgid %u effgid %u savedgid %u fsgid %u : Number of Threads %u : ", pid, comm, ppid, pgid, sid, nspid, nspgid, nssid, realuid, effuid, saveduid, fsuid, realgid, effgid, savedgid, fsgid, nthreads);
			
			char 				*pcap = cap_to_text(taskcap.get(), nullptr);
			
			GY_SCOPE_EXIT {
				if (pcap) cap_free(pcap);
			};
				
			std::string			cpustr = cpus_allowed.to_string();
			std::string			memstr = mems_allowed.to_string();

			strbuf.appendfmt("Capabilities : %s : CPU Bitset %s : Memory Bitset %s", pcap ? pcap : "", cpustr.c_str(), memstr.c_str());

			return pbuf;
		}
		GY_CATCH_EXCEPTION(ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught while printing Task info : %s\n", GY_GET_EXCEPT_STRING); return pbuf;);
	}	
};
		
int test_proc_status()
{	
	for (size_t i = 0; i < sizeof(gtest_status_arr)/sizeof(*gtest_status_arr); i++) {

		INFOPRINTCOLOR(GY_COLOR_CYAN, "Populating from  test sample : /proc/pid/status of %s...\n\n", gtest_status_info_arr[i]);

		STR_RD_BUF				taskstr(gtest_status_arr[i], strlen(gtest_status_arr[i]));
		const char				*ptmp;
		size_t					nbytes;
		TASK_INFO				info = {};
		int					ret, tint1, tint2, tint3, tint4;

		// First Name (comm)
		ptmp = taskstr.skip_till_substring_const("Name:");
		if (!ptmp) {
			goto errexit;
		}	
		ptmp = taskstr.get_next_word(nbytes);
		if (nbytes >= TASK_COMM_LEN) {
			nbytes = TASK_COMM_LEN - 1;
		}
		memcpy(info.comm, ptmp, nbytes);
		info.comm[nbytes] = '\0';	

		ptmp = taskstr.skip_till_substring_const("Uid:");
		if (!ptmp) {
			goto errexit;
		}	
		
		ptmp = taskstr.get_next_line(nbytes);
		if (!ptmp) {
			goto errexit;
		}	

		ret = sscanf(ptmp, "%u %u %u %u", &info.realuid, &info.effuid, &info.saveduid, &info.fsuid);
		if (ret != 4) {
			goto errexit;
		}	
		
		ptmp = taskstr.skip_till_substring_const("Gid:");
		if (!ptmp) {
			goto errexit;
		}	
		
		ptmp = taskstr.get_next_line(nbytes);
		if (!ptmp) {
			goto errexit;
		}	

		ret = sscanf(ptmp, "%u %u %u %u", &info.realgid, &info.effgid, &info.savedgid, &info.fsgid);
		if (ret != 4) {
			goto errexit;
		}	

		ptmp = taskstr.skip_till_substring_const("PPid:");
		if (!ptmp) {
			goto errexit;
		}	
		
		ptmp = taskstr.get_next_word(nbytes);
		if (!ptmp) {
			goto errexit;
		}	
		info.ppid = atoi(ptmp);

		ptmp = taskstr.skip_till_substring_const("NStgid:");
		if (!ptmp) {
			goto errexit;
		}	
		
		ptmp = taskstr.get_next_line(nbytes);
		if (!ptmp) {
			goto errexit;
		}	

		ret = sscanf(ptmp, "%d %d", &info.pid, &info.nspid);
		if (ret < 1) {
			goto errexit;
		}	

		ptmp = taskstr.skip_till_substring_const("NSpgid:");
		if (!ptmp) {
			goto errexit;
		}	
		
		ptmp = taskstr.get_next_line(nbytes);
		if (!ptmp) {
			goto errexit;
		}	

		ret = sscanf(ptmp, "%d %d", &info.pgid, &info.nspgid);
		if (ret < 1) {
			goto errexit;
		}	

		ptmp = taskstr.skip_till_substring_const("NSsid:");
		if (!ptmp) {
			goto errexit;
		}	
		
		ptmp = taskstr.get_next_line(nbytes);
		if (!ptmp) {
			goto errexit;
		}	

		ret = sscanf(ptmp, "%d %d", &info.sid, &info.nssid);
		if (ret < 1) {
			goto errexit;
		}	

		ptmp = taskstr.skip_till_substring_const("Threads:");
		if (!ptmp) {
			goto errexit;
		}	
		
		ptmp = taskstr.get_next_word(nbytes);
		if (!ptmp) {
			goto errexit;
		}	

		info.nthreads = atoi(ptmp);		
		
		info.taskcap.setpid(info.pid);

		ptmp = taskstr.skip_till_substring_const("Cpus_allowed_list:");
		if (!ptmp) {
			goto errexit;
		}	
		
		ptmp = taskstr.get_next_line(nbytes);
		if (!ptmp) {
			goto errexit;
		}	

		ret = set_bitset_from_buffer(info.cpus_allowed, ptmp, nbytes);

		ptmp = taskstr.skip_till_substring_const("Mems_allowed_list:");
		if (!ptmp) {
			goto errexit;
		}	
		
		ptmp = taskstr.get_next_line(nbytes);
		if (!ptmp) {
			goto errexit;
		}	

		ret = set_bitset_from_buffer(info.mems_allowed, ptmp, nbytes);

		char			bufprint[1024];

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Task Info for Sample task %s : %s\n\n", gtest_status_info_arr[i], info.get_task_info_str(bufprint, sizeof(bufprint) - 1));
	}


	return 0;

errexit :
	ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to parse the /proc/pid/status...\n");
	return -1;	
}	

int test_get_proc_cgroups(const char *pbuf, size_t szread, const char *ptypecg1[], char *pdircg1[], size_t maxcg1sz[], int maxcg1types, char *pdircg2, size_t maxcg2sz)
{
	int				fd, ret, nupd = 0, len1;
	const char			*pdata, *path;
	bool				is_malloc, is_word;	
	size_t				lenword, lenpath, lencopy;
	char				cgname[128];
	
	for (int i = 0; i < maxcg1types; i++) {
		if (ptypecg1[i] && pdircg1[i]) {
			pdircg1[i][0] = '\0';
		}
	}		
	if (pdircg2) *pdircg2 = '\0';

	if (szread < 2) {
		return 0;
	}	

	STR_RD_BUF			taskstr(pbuf, szread);

	while (maxcg1types) {
		pdata = taskstr.get_next_word(lenword, true, ":");
		if (!pdata) {
			break;
		}	

		pdata = taskstr.get_next_word(lenword, true, ":");
		if (!pdata) {
			break;
		}	

		GY_SAFE_MEMCPY(cgname, sizeof(cgname) - 1, pdata, lenword, lencopy);
		cgname[lencopy] = '\0';

		path = taskstr.get_next_word(lenpath);
		if (!path) {
			break;
		}
			
		for (int i = 0; i < maxcg1types; i++) {
			if (ptypecg1[i] && pdircg1[i]) {
				is_word = is_whole_word_in_str(cgname, ptypecg1[i], nullptr, false, lencopy, strlen(ptypecg1[i]));
				
				if (is_word) {
					GY_SAFE_MEMCPY(pdircg1[i], maxcg1sz[i] - 1, path, lenpath, lencopy);

					pdircg1[i][lencopy] = '\0';	
					nupd++;
				}
			}	
		}
	} 

	if (pdircg2 && maxcg2sz) {
		path = taskstr.skip_till_substring_const("0::", true);
		if (!path) {
			*pdircg2 = '\0';
			return nupd;
		}	

		path = taskstr.get_next_word(lenpath);
		if (path) {
			GY_SAFE_MEMCPY(pdircg2, maxcg2sz - 1, path, lenpath, lencopy);

			pdircg2[lencopy] = '\0';
			nupd++;
		}
	}	

	return nupd;	
}

int test_proc_cgroup()
{
	int				ret;
	const char 			*pcglist[] = {"cpu", "cpuacct", "cpuset", "memory", "blkio", "hugetlb", "net_cls", "net_prio"};
	char				*pdirbuf;
	bool				is_malloc;

	SAFE_STACK_ALLOC(pdirbuf, GY_ARRAY_SIZE(pcglist) * GY_PATH_MAX + 512, is_malloc);

	char				*pdircg1[ GY_ARRAY_SIZE(pcglist) ];
	size_t				maxcg1sz[ GY_ARRAY_SIZE(pcglist) ];
	char				pdircg2[ GY_PATH_MAX + 1 ];

	for (size_t i = 0; i < GY_ARRAY_SIZE(pcglist); i++) {
		pdircg1[i]	= pdirbuf + i * GY_PATH_MAX + 1;
		maxcg1sz[i]	= GY_PATH_MAX;
	}	

	for (size_t i = 0; i < sizeof(gtest_proc_cgroup_arr)/sizeof(*gtest_proc_cgroup_arr); i++) {
		ret = test_get_proc_cgroups(gtest_proc_cgroup_arr[i], strlen(gtest_proc_cgroup_arr[i]), pcglist, pdircg1, maxcg1sz, GY_ARRAY_SIZE(pcglist),
				pdircg2, sizeof(pdircg2) - 1);
		if (ret <= 0) {
			ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to get cgroup paths for %s...\n\n", gtest_proc_cgroup_info_arr[i]);
			continue;
		}	

		INFOPRINTCOLOR(GY_COLOR_BLACK, "cgroup directory list for %s : \n\n", gtest_proc_cgroup_info_arr[i]);

		for (size_t j = 0; j < GY_ARRAY_SIZE(pcglist); j++) {
			INFOPRINTCOLOR(GY_COLOR_BLACK, "cgroup type %s : directory : \'%s\'\n", pcglist[j], pdircg1[j]);
		}	

		INFOPRINTCOLOR(GY_COLOR_BLACK, "cgroupv2 : directory : \'%s\'\n", pdircg2);
	}	

	return 0;

}	

int test_cgroup_path()
{
	char				testpath[GY_PATH_MAX];

	GY_STRNCPY(testpath, "//kubepods/./besteffort/podd0544205-72df-11e8-b691-080027c5d95e\\/84ad0790d137467a41a21d7fb29b4973f68d4d00e67390454d587da8e5cc292", sizeof(testpath) - 1);

	INFOPRINT("Path cleanup of testpath : %s is : ", testpath);
	
	gy_path_cleanup(testpath);
	
	IRPRINT("%s\n\n", testpath);
	
	STR_RD_BUF			pathstr(testpath, strlen(testpath));
	char				dir1[GY_PATH_MAX];
	const char			*pdata;
	size_t				lenword, lencopy;
	
	INFOPRINT("Now splitting the path into directories : ");

	while (1) {
		pdata = pathstr.get_next_word(lenword, true, "/", true, false /* ignore_escape */);
		if (!pdata) {
			break;
		}	
		
		GY_SAFE_MEMCPY(dir1, sizeof(dir1) - 1, pdata, lenword, lencopy);

		dir1[lencopy] = '\0';

		IRPRINT("\'%s\'	", dir1);
	} 	
	
	IRPRINT("\n\n");

	return 0;
}

int test_proc_stat(pid_t pidin)
{
	int				ret, fd;
	char				buf[64], databuf[1024], *ptmp;
	ssize_t				szread;
	size_t				nbytes;
	
	char				c;
	uint32_t			flags, rt_priority, policy;	
	int64_t				priority, nice;	
	uint64_t			startclock, starttimeusec, currtime, currclock;
		
	gy_nanosleep(1, 0);

	snprintf(buf, sizeof(buf), "/proc/%u/stat", pidin);

	SCOPE_FD			scopefd(buf, O_RDONLY, 0640);
	
	fd = scopefd.get();
	if (fd < 0) {
		DEBUGEXECN(1, PERRORPRINT("Failed to open proc/status of PID %d", pidin););
		return -1;
	}	

	szread = gy_readbuffer(fd, databuf, sizeof(databuf) - 1);
	if (szread <= 5) {
		DEBUGEXECN(1, PERRORPRINT("Failed to read proc/status of PID %d", pidin););
		return -1;
	}

	databuf[szread] = '\0';

	currtime = get_usec_time();
	currclock = get_usec_clock();

	ptmp = strchr(databuf, ')');
	if (!ptmp) {
		DEBUGEXECN(1, ERRORPRINTCOLOR(GY_COLOR_RED, "Invalid proc/status of PID %d\n", pidin););
		return -1;
	}	

	ptmp++;

	while ((c = *ptmp) && (c == ' ')) {
		ptmp++;
	}	
	
	ret = sscanf(ptmp, "%c %*d %*d %*d %*d %*d %u %*u %*u %*u %*u %*u %*u %*d %*d %ld %ld %*d %*d %lu %*u %*d %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*d %*d %u %u", &c, &flags, &priority, &nice, &startclock, &rt_priority, &policy);
	
	if (ret != 7) {
		DEBUGEXECN(1, ERRORPRINTCOLOR(GY_COLOR_RED, "Invalid proc/status of PID %d\n", pidin););
		return -1;
	}	

	startclock *= (GY_USEC_PER_SEC / gy_clk_tck());

	if (startclock > currclock) startclock = currclock;

	starttimeusec = currtime - (currclock - startclock);

	struct timeval		tv = GY_USEC_TO_TIMEVAL(starttimeusec);
	
	INFOPRINTCOLOR(GY_COLOR_CYAN, "PID %d : flags %u priority %ld nice %ld rt_priority %u policy %u process start time %s\n",
			pidin, flags, priority, nice, rt_priority, policy, gy_localtime_iso8601(tv, buf, sizeof(buf)));
	 
	return 0;
}	

int test_scheduler()
{
	try {
		MOUNT_HDLR		mountinfo;
		GY_SCHEDULER		schedule(true);

		schedule.add_schedule(0, 100, 12, "mount update_mount_info", [&] { mountinfo.update_mount_info();});
		
		schedule.add_schedule(100, 1000, 5, "mount add_mount_errors", 
			[&] 
			{ 
				DEBUGEXECN(1, INFOPRINTCOLOR(GY_COLOR_BLACK, "Adding Mount error..\n");); mountinfo.add_mount_errors();
			});

		schedule.add_schedule_uniform_dist(300, 2000, 6000, "mount print", [&] { mountinfo.print_mount_info(); });

		// test error
		schedule.add_schedule_uniform_dist(0, 1000, 6000, "mount print", [&] { mountinfo.print_mount_info(); });

		schedule.add_schedule_poisson_dist(10, 3000.0, "mount get_tracefs_mount", 
			[&] {
				char			tracemount[GY_PATH_MAX];
				int			ret;	

				ret = mountinfo.get_tracefs_mount(tracemount, sizeof(tracemount) - 1);
				if (ret != 0) {
					ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Failed to get trace mount\n");
					return -1;
				}
				INFOPRINTCOLOR(GY_COLOR_BOLD_YELLOW, "Tracefs mount point is %s\n", tracemount);
				return 0;
			});	

		schedule.add_schedule(0, 1000, 0, "Check for mutable captured variable",
			[startnum = int(0)] () mutable noexcept {
				INFOPRINTCOLOR(GY_COLOR_GREEN, "startnum = %d...\n", startnum++);
			});	

		schedule.add_schedule(0, 1000, 5, "Check for schedule function from a function callback",
			[&, nchk = 1] () mutable {	
				INFOPRINTCOLOR(GY_COLOR_GREEN, "Adding Schedule function %d from within a callback...\n", nchk++);

				schedule.add_oneshot_schedule(500, "schedule from within func",
					[] {
						INFOPRINTCOLOR(GY_COLOR_BOLD_GREEN, "Testing Schedule within schedule...\n"); 
					});	

			});	


		schedule.add_oneshot_schedule(4000, "test exception print", 
			[] { 
				INFOPRINTCOLOR(GY_COLOR_BOLD_RED, "Testing Exception within schedule...\n"); 
				GY_THROW_EXCEPTION("Test exception");
			});

		gy_nanosleep(10, 0);

		schedule.cancel_schedule("mount update_mount_info");
		schedule.cancel_schedule("No such schedule");
		schedule.cancel_all_schedules(true);

		INFOPRINTCOLOR(GY_COLOR_CYAN, "Scheduler handling completed...\n");

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Exception caught while scheduling... : %s\n", GY_GET_EXCEPT_STRING);
		return -1;
	);	
}	

int test_async_func()
{
	try {
		static pthread_mutex_t		mutex = PTHREAD_MUTEX_INITIALIZER;
		static pthread_cond_t 		cond = PTHREAD_COND_INITIALIZER; 

		uint8_t				*pbufpool[1001] = {}, *pbufpool1[1001] = {};
		int				ret;

		ASYNC_FUNC_HDLR			asyncfunc("test async func", 500, true);

		{
			EXEC_TIME			prof1("Profile for async malloc", __LINE__);

			for (int i = 0; i < 1000; i++) {
				uint8_t			*pbuf;

				GY_NOMT_COLLECT_PROFILE(1000, "async func exec");

				COMM_MSG_C		elem;
				
				pbuf = nullptr;

				elem.func_ = [](uint64_t arg1, uint64_t arg2, uint64_t arg3, const uint8_t *poptbuf, size_t opt_bufsize) -> int
				{
					size_t			sz = static_cast<size_t>(arg1);
					uint8_t			**ppbuf = (uint8_t **)(uintptr_t)arg2;

					uint8_t			*pbuf = (uint8_t *)malloc(sz);

					if (ppbuf) *ppbuf = pbuf;

					return 0;
				};

				elem.arg1_	= 1024;
				elem.arg2_	= (uintptr_t)(pbufpool + i);

				asyncfunc.send_async_func(elem);
			}

			// Do some work and then wait
			
			COMM_MSG_C		elem;
			void			*paddr = &cond;

			elem.func_ = [](uint64_t arg1, uint64_t arg2, uint64_t arg3, const uint8_t *poptbuf, size_t opt_bufsize) -> int
			{
				size_t			sz = static_cast<size_t>(arg1);

				uint8_t			**ppbuf = (uint8_t **)arg2;
				pthread_mutex_t		*pmutex = (pthread_mutex_t *)arg3;
			
				void			**paddr = (void **)poptbuf;
				
				pthread_cond_t		*pcond= (pthread_cond_t *)*paddr;

				uint8_t			*pbuf = (uint8_t *)malloc(sz);

				if (ppbuf) *ppbuf = pbuf;

				if (pmutex &&pcond) {
					pthread_mutex_lock(pmutex);
					pthread_cond_signal(pcond);
					pthread_mutex_unlock(pmutex);
				}	
				return (uintptr_t)pbuf;
			};

			elem.arg1_		= 1024;
			elem.arg2_		= (uintptr_t)(pbufpool + 1000);
			elem.arg3_		= (uintptr_t)&mutex;
			elem.opt_bufsize_	= sizeof(&cond);

			INFOPRINTCOLOR(GY_COLOR_GREEN, "Sent all async malloc requests. Now waiting for the completion...\n");

			pthread_mutex_lock(&mutex);

			ret = asyncfunc.send_async_func(elem, (const uint8_t *) (uintptr_t)&paddr, false /* exec_inline_if_async_failed */, 200, true /* async_safe_write */, false /* is_writer_rcu */);

			if (ret == 0) {
				pthread_cond_wait(&cond, &mutex);
				pthread_mutex_unlock(&mutex);

				INFOPRINTCOLOR(GY_COLOR_GREEN, "Completion signalled from async exec...\n");
			}
			else {
				pthread_mutex_unlock(&mutex);
				WARNPRINTCOLOR(GY_COLOR_GREEN, "Completion could not be sent to async reader...\n");
			}
		}

		{

			EXEC_TIME			prof1("Profile for direct non async malloc", __LINE__);

			for (int i = 0; i < 1001; i++) {
				pbufpool1[i] = (uint8_t *)malloc(1024);
			}
		}

		for (int i = 0; i < 1001; i++) {
			if (!pbufpool[i]) {
				ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Failed to allocate memory from async function for iteration %d\n", i);
			}	
			else {
				free(pbufpool[i]);
			}	
			if (pbufpool1[i]) {
				free(pbufpool1[i]);
			}
		}
					
		return 0;			
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Exception caught while running async func test... : %s\n", GY_GET_EXCEPT_STRING);
		return -1;
	);	
}	

void *debug_thread(void *arg)
{
	std::pair<pid_t, uint32_t>	*p = reinterpret_cast<decltype(p)>(arg);

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Monitoring CPU/IO stats of process PID %d for %u iterations...\n", p->first, p->second);

	PROC_CPU_IO_STATS			procstats(p->first, p->first, true);

	for (uint32_t i = 0; i < p->second; ++i) {
		procstats.get_current_stats(true);

		gy_nanosleep(5, 0);
	}

	return nullptr;
}
MAKE_PTHREAD_FUNC_WRAPPER(debug_thread);

}	

int main(int argc, char **argv)
{
	if (argc < 3) {
		IRPRINT("Usage : %s <PID of process to monitor> <#Iterations to keep monitoring in seconds>\n\n", argv[0]);
		return -1;
	}

	GY_SIGNAL_HANDLER::init_singleton(argv[0]);
	
	pid_t		pid = atoi(argv[1]);
	uint32_t	niter = atoi(argv[2]);

	using namespace TEST_SPACE;

	gdebugexecn = 25;

/* 	test_string_rd_buf(); */

	test_proc_status();

	test_proc_stat(getpid());

	test_proc_cgroup();

	test_cgroup_path();

	std::pair<pid_t, uint32_t>	tpair {pid, niter};
	pthread_t 			dbgtid;

	gy_create_thread(&dbgtid, GET_PTHREAD_WRAPPER(debug_thread), &tpair);

	test_scheduler();

	test_async_func();

	pthread_join(dbgtid, nullptr);

	return 0;
}	



