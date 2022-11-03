//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

/* #undef 			DO_PROFILE   */

#include		"gy_common_inc.h"
#include		"gy_file_api.h"
#include		"gy_inet_inc.h"
#include		"gy_statistics.h"
#include		"gy_async_func.h"
#include		"gy_rcu_inc.h"

#include		<sched.h>

using 			namespace gyeeta;

struct GY_INET_IP_PORT
{
	GY_IP_ADDR			ipaddr;
	uint16_t			port;

	uint32_t get_ip_port_hash() 
	{
		alignas(4) uint8_t	buf1[32];
		int			len;

		len = ipaddr.get_as_inaddr(buf1);

		memcpy(buf1 + len, &port, sizeof(port));
		len += sizeof(port);
		
		buf1[len++] = '\0';	// Align to 4 bytes
		buf1[len++] = '\0';

		return jhash2((uint32_t *)buf1, len / sizeof(uint32_t), 0xceedfead);
	}

	GY_INET_IP_PORT()
	{
		GY_MT_COLLECT_PROFILE(1000'000, "constructor");

		ipaddr = 0u;
		port = 0;
	}	

	~GY_INET_IP_PORT()
	{
		GY_MT_COLLECT_PROFILE(1000'000, "destructor");
	}	
};

bool operator== (const GY_INET_SOCK &lhs, const GY_INET_IP_PORT &rhs) noexcept
{
	return ((lhs.port == rhs.port) && (lhs.ipaddr == rhs.ipaddr));	
}

struct TASK_MINI_ELEM
{
	RCU_HASH_CLASS_MEMBERS(pid_t, TASK_MINI_ELEM);

	pid_t					pid;
	pid_t					ppid;
	uid_t					uid;
	gid_t					gid;
	uint64_t				tstartusec_approx;
	char					exe_path[GY_PATH_MAX];
	char					cmdline[256];

	TASK_MINI_ELEM() noexcept : pid(0) 
	{
		*cmdline = '\0';
	}	

	TASK_MINI_ELEM(int proc_dir_fd, pid_t pidin, pid_t ppidin) noexcept
		: pid(pidin), ppid(ppidin), tstartusec_approx(get_usec_time())
	{
		struct stat		stat1;
		int			ret;
		char			buf[128];
		
		uid = -1;
		gid = -1;

		*exe_path = '\0';
		*cmdline = '\0';

		snprintf(buf, sizeof(buf), "./%d", pidin);

		ret = fstatat(proc_dir_fd, buf, &stat1, AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW);
		if (ret == -1) {
			DEBUGEXECN(1, PERRORPRINTCOLOR(GY_COLOR_RED, "Failed to get PID %d init info", pidin););
			return;
		}	

		uid = stat1.st_uid;
		gid = stat1.st_gid;

		ret = get_task_exe_path(pidin, exe_path, sizeof(exe_path), proc_dir_fd); 
		if (ret < 0) {
			DEBUGEXECN(1, PERRORPRINTCOLOR(GY_COLOR_RED, "Failed to get PID %d exe path", pidin););
			return;
		}	

		ret = get_task_cmdline(pidin, cmdline, sizeof(cmdline), proc_dir_fd); 
		if (ret < 0) {
			DEBUGEXECN(1, PERRORPRINTCOLOR(GY_COLOR_RED, "Failed to get PID %d cmdline", pidin););
			return;
		}	
	}		

	TASK_MINI_ELEM(pid_t pidin, pid_t ppidin, const char *pexe_path, const char *pcmdline, uid_t uid, gid_t gid) noexcept	
		: pid(pidin), ppid(ppidin), uid(uid), gid(gid), tstartusec_approx(get_usec_time())
	{
		GY_STRNCPY(exe_path, pexe_path, sizeof(exe_path));	
		GY_STRNCPY(cmdline, pcmdline, sizeof(cmdline));	
	}		

	TASK_MINI_ELEM(const TASK_MINI_ELEM &other) noexcept
	{
		std::memcpy(this, &other, sizeof(*this));
	}
		
	TASK_MINI_ELEM & operator= (const TASK_MINI_ELEM &other) noexcept
	{
		if (&other != this) {
			std::memcpy(this, &other, sizeof(*this));
		}
		
		return *this;	
	}
		
	TASK_MINI_ELEM & operator= (TASK_MINI_ELEM && other) 	= default;

	char *		get_task_print_str(char *pbuf, size_t maxsz) const noexcept
	{
		snprintf(pbuf, maxsz, "PID %d PPID %d UID %d GID %d exe path : %s cmdline : %s",
			pid, ppid, uid, gid, exe_path, cmdline);

		return pbuf;
	}	

	bool is_valid() const noexcept
	{
		return (*cmdline != '\0');
	}
		
	friend bool operator== (const TASK_MINI_ELEM &lhs, const pid_t pid) noexcept
	{
		return lhs.pid == pid;
	}
};	


namespace TEST_SPACE {

using 		GY_TEST_ELEM_TYPE 	= RCU_HASH_WRAP_PTR<GY_INET_IP_PORT, GY_INET_SOCK>;
using 		GY_TEST_HASH_TABLE 	= RCU_HASH_TABLE<GY_INET_IP_PORT, GY_TEST_ELEM_TYPE>;

using		GY_MINI_TASK_TABLE	= RCU_HASH_TABLE<pid_t, TASK_MINI_ELEM>;

GY_MUTEX	grcumutex;

auto glambda_walker = [](GY_TEST_ELEM_TYPE *pdatanode, void *arg) noexcept -> CB_RET_E
{
	char		buf[256];
	auto		psock = pdatanode->get_data();
	size_t		maxsz = (size_t)arg;

	if (psock == nullptr) {
		return CB_OK;
	}

	psock->get_sock_info_str(buf, sizeof(buf), "Info");

	if (psock->port <= 1025) {
		return CB_DELETE_ELEM;
	}	
	return CB_OK;
};	

auto glambda_lookup = [](GY_TEST_ELEM_TYPE *pdatanode, void *arg1, void *arg2) noexcept -> CB_RET_E
{
	char		buf[256];
	auto		psock = pdatanode->get_data();

	if (psock == nullptr) {
		return CB_OK;
	}
	psock->get_sock_info_str(buf, sizeof(buf), "Found");

	return CB_OK;
};	


auto glambda_lookup_with_inline_rcu_read_lock = [](GY_TEST_ELEM_TYPE *pdatanode, void *arg1, void *arg2) noexcept -> CB_RET_E
{
	char		buf[256];
	auto		psock = pdatanode->get_data();

	RCU_LOCK_TIMED		fastlock;

	if (psock == nullptr) {
		return CB_OK;
	}
	psock->get_sock_info_str(buf, sizeof(buf), "Found");

	if (psock->port == 1026) {
		return CB_DELETE_ELEM;
	}

	return CB_OK;
};	

/*
 * Example usage of a different key lookup match callback
 */
static int match_different_key(struct cds_lfht_node *pht_node, const void *pkey)
{
	GY_TEST_ELEM_TYPE					*pwrap = GY_CONTAINER_OF(pht_node, GY_TEST_ELEM_TYPE, cds_node_);
	const GY_INET_SOCK					*pactdata = pwrap->get_data();
	const GY_INET_IP_PORT					*pkeydata = static_cast<decltype(pkeydata)>(pkey);

	return (pactdata && (pactdata->port == pkeydata->port));
}

static int to_exit = 0;

void * writer_thread(void *arg)
{
	GY_TEST_HASH_TABLE 		*pgrcuhash = static_cast<GY_TEST_HASH_TABLE *>(arg);

	try {
		for (int j = 0; j < 10; j++) {
			for (int i = 0; i < 10000; i++) {
				bool				bret;
				GY_TEST_ELEM_TYPE		*pelem, *pelem2, *pdupelem[3];
				GY_INET_IP_PORT		key;

				pelem = new GY_TEST_ELEM_TYPE(new GY_INET_SOCK((uint32_t)0x7f00a8c0, 1024 + i, 1, 1));
				pelem2 = new GY_TEST_ELEM_TYPE(new GY_INET_SOCK((uint32_t)0x7f00a8c0, 1024 + i, 1, 1));

				// Use below if type of RCU_HASH_WRAPPER
				// pelem = new GY_TEST_ELEM_TYPE((uint32_t)0x7f00a8c0, 1024 + i, 1, 1);
				// pelem2 = new GY_TEST_ELEM_TYPE((uint32_t)0x7f00a8c0, 1024 + i, 1, 1);

				key.ipaddr = (uint32_t)0x7f00a8c0; 
				key.port = 1024 + i;
				
				for (uint32_t k = 0; k < sizeof(pdupelem)/sizeof(*pdupelem); k++) {
					pdupelem[k] = new GY_TEST_ELEM_TYPE(*pelem);
				}	

				bret = pgrcuhash->template insert_unique<RCU_LOCK_FAST>(pelem, key, gy_get_sock_hash(*pelem->get_data()), true);

				pgrcuhash->template insert_duplicate_elem<RCU_LOCK_FAST>(pelem2, gy_get_sock_hash(*pelem2->get_data()));

				for (uint32_t k = 0; k < sizeof(pdupelem)/sizeof(*pdupelem); k++) {
					pgrcuhash->template insert_duplicate_elem<RCU_LOCK_FAST>(pdupelem[k], gy_get_sock_hash(*pdupelem[k]->get_data()));
				}	
			}	

/* 			gy_nanosleep(1, 0); */
			
			{

			RCU_DEFER_OFFLINE		slowlock;	

			for (int i = 9000; i < 10000; i++) {
				GY_INET_IP_PORT		key;
				GY_TEST_ELEM_TYPE		elem;

				key.ipaddr = (uint32_t)0x7f00a8c0; 
				key.port = 1024 + i;
				
				pgrcuhash->delete_single_elem(key, key.get_ip_port_hash());
				pgrcuhash->delete_duplicate_elems(key, key.get_ip_port_hash());
			}	
			}
			
			{
				struct timeval			tv;

				SCOPE_GY_MUTEX			smutex(&grcumutex);

				for (int i = 0; i < 100; i++) {
					gettimeofday(&tv, nullptr);
				}
			}	

			gy_thread_rcu().gy_rcu_thread_offline();

			{
				struct timeval			tv;

				SCOPE_GY_MUTEX			smutex(&grcumutex);

				for (int i = 0; i < 100; i++) {
					gettimeofday(&tv, nullptr);
				}
			}	
		}
	}
	GY_CATCH_EXCEPTION(ERRORPRINT("Exception occured while inserting elements : %s\n", GY_GET_EXCEPT_STRING));

	return nullptr;
}	

void * reader_thread(void *arg)
{
	GY_TEST_HASH_TABLE 		*pgrcuhash = static_cast<GY_TEST_HASH_TABLE *>(arg);

	try {
		auto thrid = gy_thread_rcu().thrid_;

		for (int j = 0; j < 10; j++) {
			size_t		currsize = pgrcuhash->count_slow(), approxcount;

			auto sret = pgrcuhash->walk_hash_table(glambda_walker, (void *)currsize); 	

			for (int i = 0; i < 20000; i++) {
				bool				bret;
				GY_INET_IP_PORT			key;
				GY_TEST_ELEM_TYPE		elem;

				key.ipaddr = (uint32_t)0x7f00a8c0; 
				key.port = 1024 + i;
				
				bret = pgrcuhash->template lookup_single_elem<RCU_LOCK_FAST>(key, key.get_ip_port_hash(), elem);

				if (0 == (thrid % 4)) {
					bret = pgrcuhash->lookup_duplicate_elems(key, key.get_ip_port_hash(), glambda_lookup_with_inline_rcu_read_lock, nullptr, nullptr);
				}
				else {
					bret = pgrcuhash->template lookup_duplicate_elems<decltype(glambda_lookup), RCU_LOCK_SLOW>(key, key.get_ip_port_hash(), glambda_lookup, nullptr, nullptr);
				}	

				if (i < 2000) {
					pgrcuhash->delete_duplicate_elems(key, key.get_ip_port_hash()); 
				}	
			}	
		
			{
				struct timeval			tv;

				SCOPE_GY_MUTEX			smutex(&grcumutex);

				for (int i = 0; i < 100; i++) {
					gettimeofday(&tv, nullptr);
				}
			}	

			approxcount = pgrcuhash->approx_count_fast();

			GY_CC_BARRIER();
			
			currsize = pgrcuhash->count_slow();
			
			INFOPRINTCOLOR(GY_COLOR_GREEN, "Current count of Hash Table elements is %lu : Approx count = %lu\n\n", currsize, approxcount);

			gy_thread_rcu().gy_rcu_thread_offline();
		}

		auto memutil = gy_get_proc_vmsize(0);
		INFOPRINTCOLOR(GY_COLOR_GREEN, "Current PID %d Memory Util is %lu (%lu MB)\n", getpid(), memutil, memutil >> 20);
	}
	GY_CATCH_EXCEPTION(ERRORPRINT("Exception occured while reading elements : %s\n", GY_GET_EXCEPT_STRING));

	return nullptr;
}	


void *debug_thread(void *arg)
{
	PROC_CPU_IO_STATS		procstats(getpid(), getpid(), true);

	while (to_exit == 0) {
		for (int i = 0; i < 10 && to_exit == 0; ++i) {
			gy_nanosleep(1, 0);
		}
		procstats.get_current_stats(true);
	}

	return nullptr;
}	

void * init_hash_test(void *arg)
{
	GY_TEST_HASH_TABLE *pgrcuhash = static_cast<GY_TEST_HASH_TABLE *>(arg);

	try {
		gy_get_thread_local().set_name("main thread");

		RCU_DEFER_OFFLINE		slowlock;

		for (int i = 0; i < 128; i++) {
			bool				bret;
			GY_TEST_ELEM_TYPE		*pelem, *pelem2;
			GY_INET_IP_PORT		key;

			pelem = new GY_TEST_ELEM_TYPE(new GY_INET_SOCK((uint32_t)0x7f00a8c0, 1024 + i, 1, 1));
			pelem2 = new GY_TEST_ELEM_TYPE(new GY_INET_SOCK((uint32_t)0x7f00a8c0, 1024 + i, 1, 1));

			// Use below if type of RCU_HASH_WRAPPER
			// pelem = new GY_TEST_ELEM_TYPE((uint32_t)0x7f00a8c0, 1024 + i, 1, 1);
			// pelem2 = new GY_TEST_ELEM_TYPE((uint32_t)0x7f00a8c0, 1024 + i, 1, 1);

			key.ipaddr = (uint32_t)0x7f00a8c0; 
			key.port = 1024 + i;
			
			bret = pgrcuhash->template insert_unique<RCU_LOCK_FAST>(pelem, key, gy_get_sock_hash(*pelem->get_data()), true);
			assert(bret == true);

			size_t		currsize = pgrcuhash->count_slow(); 

			assert(currsize >= ((size_t)i + 1));

			if (i >= 64) {
				bret = pgrcuhash->template insert_unique<RCU_LOCK_FAST>(pelem2, key, gy_get_sock_hash(*pelem2->get_data()), i >= 100);
				assert(bret == false);

				if (i < 100) {
					bret = pgrcuhash->template insert_or_replace<RCU_LOCK_FAST>(pelem2, key, gy_get_sock_hash(*pelem2->get_data()));
					assert(bret == false);
				}	
			}	
			else {
				pgrcuhash->template insert_duplicate_elem<RCU_LOCK_FAST>(pelem2, gy_get_sock_hash(*pelem2->get_data()));
			}	
		}	
		
		size_t		approxcount = pgrcuhash->approx_count_fast();

		GY_CC_BARRIER();

		size_t		currsize = pgrcuhash->count_slow(); 

		assert(currsize > 128);

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Current actual count = %lu, approx count = %lu\n", currsize, approxcount);

		auto sret = pgrcuhash->walk_hash_table(glambda_walker, (void *)currsize); 	

		currsize = pgrcuhash->count_slow(); 

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Current actual count = %lu, count with duplicates = %lu\n", currsize, sret);

		for (int i = 0; i < 64; i++) {
			bool				bret;
			GY_INET_IP_PORT			key;
			GY_TEST_ELEM_TYPE		elem;

			key.ipaddr = (uint32_t)0x7f00a8c0; 
			key.port = 1024 + i;
			
			bret = pgrcuhash->template lookup_single_elem<RCU_LOCK_FAST>(key, key.get_ip_port_hash(), elem);

			if (key.port > 1025) {
				// The walk has deleted ports <= 1025
				assert(bret == true);
				assert(elem.get_data()->port == key.port  && (elem.get_data()->ipaddr == key.ipaddr));
			}
			else {
				assert(bret == false);
				continue;
			}

			bret = pgrcuhash->lookup_duplicate_elems(key, key.get_ip_port_hash(), glambda_lookup_with_inline_rcu_read_lock, nullptr, nullptr);
			assert(bret == true);


			{
				// Test delete and copy 

				GY_TEST_ELEM_TYPE		elem2;
				
				bret = pgrcuhash->template delete_single_elem_and_copy<RCU_LOCK_FAST>(key, key.get_ip_port_hash(), elem2);

				if (key.port == 1026) {
					assert(bret == false);

					// deleted
					continue;
				}	

				assert(bret == true);
			}
			
			bret = pgrcuhash->template lookup_duplicate_elems<decltype(glambda_lookup), RCU_LOCK_FAST>(key, key.get_ip_port_hash(), glambda_lookup, nullptr, nullptr);
			assert(bret == true);

			{
				struct timeval			tv;

				SCOPE_GY_MUTEX			smutex(&grcumutex);

				for (int i = 0; i < 100; i++) {
					gettimeofday(&tv, nullptr);
				}
			}	

			pgrcuhash->delete_duplicate_elems(key, key.get_ip_port_hash());
		}	
	
		assert(pgrcuhash->is_empty() == false);

		gy_thread_rcu().gy_rcu_thread_offline();
	}
	GY_CATCH_EXCEPTION(ERRORPRINT("Exception occured while inserting elements : %s\n", GY_GET_EXCEPT_STRING));

	auto memutil = gy_get_proc_vmsize(0);
	INFOPRINTCOLOR(GY_COLOR_GREEN, "Current PID %d Memory Util is %lu (%lu MB)\n", getpid(), memutil, memutil >> 20);

	return nullptr;
}	

int init_test_second(GY_TEST_HASH_TABLE &grcuhash, GY_TEST_HASH_TABLE &grcuhash_temp)
{
	{
		{
			RCU_LOCK_TIMED	timedfastlock;

			/*
			 * This should not be called within rcu read lock. Test if we handle properly
			 */

			grcuhash = std::move(grcuhash_temp);
		}

		GY_TEST_HASH_TABLE			ttbl(grcuhash), tt2(1);

		for (int i = 64; i < 128; i++) {
			bool				bret;
			GY_INET_IP_PORT			key;
			GY_TEST_ELEM_TYPE		elem;
			uint32_t			hash;

			key.ipaddr = (uint32_t)0x7f00a8c0; 
			key.port = 1024 + i;
			
			hash = key.get_ip_port_hash();

			bret = ttbl.template lookup_single_elem<RCU_LOCK_FAST>(key, hash, elem);

			assert(bret == true);
			assert(elem.get_data()->port == key.port  && (elem.get_data()->ipaddr == key.ipaddr));

			// Test lookup with a different match callback
			key.ipaddr = 0u;
			bret = ttbl.template lookup_single_elem<RCU_LOCK_FAST, match_different_key>(key, hash, elem);

			assert(bret == true);
			assert(elem.get_data()->port == key.port);
		}	

		auto rcucopylambda = [](GY_TEST_ELEM_TYPE *pdatanode, void *arg) -> CB_RET_E
		{
			GY_TEST_HASH_TABLE	*phtable = static_cast<decltype(phtable)>(arg);
			
			if (pdatanode->get_data()->port < 1024 + 100) {
				return CB_OK;
			}	

			GY_TEST_ELEM_TYPE	*pnewdatanode = new GY_TEST_ELEM_TYPE(*pdatanode);

			phtable->template insert_duplicate_elem(pnewdatanode, pdatanode->rcu_get_hash(pdatanode));

			return CB_OK;
		};	

		tt2.copy_table<decltype(rcucopylambda)>(ttbl, rcucopylambda);
		
		for (int i = 64; i < 128; i++) {
			bool				bret;
			GY_INET_IP_PORT			key;
			GY_TEST_ELEM_TYPE		elem;
			uint32_t			hash;

			key.ipaddr = (uint32_t)0x7f00a8c0; 
			key.port = 1024 + i;
			
			hash = key.get_ip_port_hash();

			bret = tt2.template lookup_single_elem<RCU_LOCK_FAST>(key, hash, elem);

			if (i >= 100) {
				assert(bret == true);
			}
			else {
				assert(bret == false);
			}
		}	

		gy_nanosleep(0, GY_NSEC_PER_MSEC * 100);
	}	

	GY_MINI_TASK_TABLE		gtaskhash(32);
	TASK_MINI_ELEM			*pelem, *pelem2, elem;
	bool				bret;
	pid_t				pid;

	if (true) {
		pid = 1000;
		pelem = new TASK_MINI_ELEM(pid, pid - 1, "/tmp/test_rcu_hashtable", "/tmp/test_rcu_hashtable --test", getuid(), getgid());

		RCU_LOCK_FAST		fastlock;

		assert(true == gtaskhash.insert_unique(pelem, pid, get_int_hash(pid), true));

		auto ptmp1 = gtaskhash.lookup_single_elem_locked(pid, get_int_hash(pid));

		assert(ptmp1 != nullptr);
		
		GY_CC_BARRIER();

		gtaskhash.delete_elem_locked(ptmp1);

		assert(true == gtaskhash.is_empty());
	}	

	for (int i = 0; i < 1000; i++) {
		pid = 1000 + i;

		pelem = new TASK_MINI_ELEM(pid, pid - 1, "/tmp/test_rcu_hashtable", "/tmp/test_rcu_hashtable --test", getuid(), getgid());

		pelem2 = new TASK_MINI_ELEM(*pelem);

		bret = gtaskhash.template insert_unique<RCU_LOCK_TIMED>(pelem, pid, get_int_hash(pid), true);
		assert(bret == true);

		size_t		currsize = gtaskhash.count_slow(); 

		assert(currsize == ((size_t)i + 1));

		bret = gtaskhash.template insert_unique<RCU_LOCK_TIMED>(pelem2, pid, get_int_hash(pid), false  /* delete_after_callback */);
		assert(bret == false);

		RCU_LOCK_FAST		fastlock;

		auto ptmp1 = gtaskhash.lookup_single_elem_locked(pid, get_int_hash(pid));

		assert(ptmp1 != nullptr);
		
		GY_CC_BARRIER();

		gtaskhash.delete_elem_locked(ptmp1);

		assert(true == gtaskhash.insert_unique(pelem2, pid, get_int_hash(pid), true));
	}	

	pid = 99;

	bret = gtaskhash.template lookup_single_elem<RCU_LOCK_TIMED>(99, get_int_hash(99), elem);
	assert(bret == false);

	{
	RCU_DEFER_OFFLINE	slowlock;

	for (int i = 1000; i < 1064; i++) {
		pid = i;

		bret = gtaskhash.template lookup_single_elem<RCU_LOCK_FAST>(pid, get_int_hash(pid), elem);
		assert(bret == true);
		assert(elem.ppid == pid - 1);

		gtaskhash.delete_duplicate_elems(pid, get_int_hash(pid));

		bret = gtaskhash.template lookup_single_elem<RCU_LOCK_FAST>(pid, get_int_hash(pid), elem);
		assert(bret == false);
	}	
	}

	auto ttask = gtaskhash;

	IRPRINT("\n\n");

	INFOPRINTCOLOR(GY_COLOR_YELLOW, "Now benchmarking single threaded Hash Table Inserts, Lookups, Deletes for a range of table counts...\n\n");
	
	size_t			szarr[] {100, 500, 2000, 10000, 50000, 500'000, 2'000'000};
	BENCH_HISTOGRAM		bench;

	for (size_t s = 0; s < GY_ARRAY_SIZE(szarr); ++s) {
		uint64_t		tstartns = get_nsec_clock(), tmp1, tmp2, tmpu, totaltime = 0, mintime = ~0ul, maxtime = 0, nsec = 0, nrej = 0;
		uint64_t		niter = 0;

		niter = std::max(szarr[s], 100'000ul);

		gtaskhash.clear_table();

		RCU_LOCK_SLOW		slowlock;

		for (size_t iter = 0; iter < niter/szarr[s]; ++iter) {
			for (size_t i = 0; i < szarr[s]; i++) {
				pid = 1000 + i;

				pelem = new TASK_MINI_ELEM(pid, pid - 1, "/tmp/test_rcu_hashtable", "/tmp/test_rcu_hashtable --test", getuid(), getgid());

				tmp2 = get_nsec_clock();
				
				GY_CC_BARRIER();

				gtaskhash.insert_duplicate_elem(pelem, get_int_hash(pid));

				GY_CC_BARRIER();

				tmpu = get_nsec_clock();

				tmp1 = tmpu - tmp2;

				if (tmp1 < mintime) {
					mintime = tmp1;
				}	

				if (tmp1 > maxtime) {
					maxtime = tmp1;
				}

				bench.add_data(tmp1);

				totaltime += tmp1;
			}	
		
			gtaskhash.clear_table();
			wait_for_all_call_rcu_free();
		}	

		slowlock.~RCU_LOCK_SLOW();

		INFOPRINTCOLOR(GY_COLOR_CYAN, "Benchmarking Potential Duplicate Inserts for %lu entries across %lu iter : Avg time is %lu nsec (%lu usec) : Min time is %lu nsec : Max time is %lu nsec : Histogram Stats : %s\n\n", szarr[s], niter, totaltime/niter, totaltime/1000/niter, mintime, maxtime, bench.print_stats(STRING_BUFFER<1024>().get_str_buf()));

		bench.clear();

		totaltime = 0; mintime = ~0ul; maxtime = 0; nsec = 0;

		new (&slowlock) RCU_LOCK_SLOW();

		for (size_t iter = 0; iter < niter/szarr[s]; ++iter) {

			gtaskhash.clear_table();

			for (size_t i = 0; i < szarr[s]; i++) {
				pid = 1000 + i;

				pelem = new TASK_MINI_ELEM(pid, pid - 1, "/tmp/test_rcu_hashtable", "/tmp/test_rcu_hashtable --test", getuid(), getgid());

				tmp2 = get_nsec_clock();

				GY_CC_BARRIER();

				bret = gtaskhash.insert_unique(pelem, pid, get_int_hash(pid), true);

				GY_CC_BARRIER();

				tmpu = get_nsec_clock();

				assert(bret == true);

				tmp1 = tmpu - tmp2;

				if (tmp1 < mintime) {
					mintime = tmp1;
				}	

				if (tmp1 > maxtime) {
					maxtime = tmp1;
				}

				bench.add_data(tmp1);

				totaltime += tmp1;
			}	

			wait_for_all_call_rcu_free();
		}

		slowlock.~RCU_LOCK_SLOW();

		INFOPRINTCOLOR(GY_COLOR_BLUE, "Benchmarking Unique Inserts for %lu entries across %lu iter : Avg time is %lu nsec (%lu usec) : Min time is %lu nsec : Max time is %lu nsec : Histogram Stats : %s\n\n",
			szarr[s], niter, totaltime/niter, totaltime/1000/niter, mintime, maxtime, bench.print_stats(STRING_BUFFER<1024>().get_str_buf()));

		bench.clear();
		totaltime = 0; mintime = ~0ul; maxtime = 0; nsec = 0, nrej = 0;

		new (&slowlock) RCU_LOCK_SLOW();

		for (size_t iter = 0; iter < niter/szarr[s]; ++iter) {
			for (size_t i = 0; i < szarr[s]; i++) {
				pid = 1000 + i + get_nsec_clock() % szarr[s];

				tmp2 = get_nsec_clock();
				GY_CC_BARRIER();

				pelem = gtaskhash.lookup_single_elem_locked(pid, get_int_hash(pid));
				GY_CC_BARRIER();

				tmpu = get_nsec_clock();

				if (pelem) nsec++;

				tmp1 = tmpu - tmp2;

				if (tmp1 < mintime) {
					mintime = tmp1;
				}	

				if (tmp1 > maxtime) {
					maxtime = tmp1;
				}

				bench.add_data(tmp1);

				totaltime += tmp1;
			}	
		}

		slowlock.~RCU_LOCK_SLOW();

		INFOPRINTCOLOR(GY_COLOR_YELLOW, "Benchmarking Lookups for %lu entries across %lu iter (successful %lu) : Avg time is %lu nsec (%lu usec) : Min time is %lu nsec : Max time is %lu nsec : Histogram Stats : %s\n\n",
			szarr[s], niter, nsec, totaltime/niter, totaltime/1000/niter, mintime, maxtime, bench.print_stats(STRING_BUFFER<1024>().get_str_buf()));

		bench.clear();
		totaltime = 0; mintime = ~0ul; maxtime = 0; nsec = 0;

		wait_for_all_call_rcu_free();

		new (&slowlock) RCU_LOCK_SLOW();

		auto lam1 = [](TASK_MINI_ELEM *  pelem, void *, void *) noexcept
		{
			GY_CC_BARRIER();

			return CB_OK;
		};

		for (size_t iter = 0; iter < niter/szarr[s]; ++iter) {
			for (size_t i = 0; i < szarr[s]; i++) {
				pid = 1000 + i + get_nsec_clock() % szarr[s];

				tmp2 = get_nsec_clock();
				GY_CC_BARRIER();

				bret = gtaskhash.lookup_single_elem(pid, get_int_hash(pid), lam1);

				GY_CC_BARRIER();

				tmpu = get_nsec_clock();

				if (bret) nsec++;

				tmp1 = tmpu - tmp2;

				if (tmp1 < mintime) {
					mintime = tmp1;
				}	

				if (tmp1 > maxtime) {
					maxtime = tmp1;
				}

				bench.add_data(tmp1);

				totaltime += tmp1;
			}	
		}

		slowlock.~RCU_LOCK_SLOW();

		INFOPRINTCOLOR(GY_COLOR_CYAN, "Benchmarking Lookups with callback for %lu entries across %lu iter (successful %lu) : Avg time is %lu nsec (%lu usec) : Min time is %lu nsec : Max time is %lu nsec : Histogram Stats : %s\n\n",
			szarr[s], niter, nsec, totaltime/niter, totaltime/1000/niter, mintime, maxtime, bench.print_stats(STRING_BUFFER<1024>().get_str_buf()));

		bench.clear();
		totaltime = 0; mintime = ~0ul; maxtime = 0; nsec = 0;

		wait_for_all_call_rcu_free();

		for (size_t iter = 0; iter < niter/szarr[s]; ++iter) {
			for (size_t i = 0; i < szarr[s]; i++) {
				pid = 1000 + i + get_nsec_clock() % szarr[s];

				tmp2 = get_nsec_clock();
				GY_CC_BARRIER();

				bret = gtaskhash.lookup_single_elem(pid, get_int_hash(pid));
				GY_CC_BARRIER();

				tmpu = get_nsec_clock();

				if (bret) nsec++;

				tmp1 = tmpu - tmp2;

				if (tmp1 < mintime) {
					mintime = tmp1;
				}	

				if (tmp1 > maxtime) {
					maxtime = tmp1;
				}

				bench.add_data(tmp1);

				totaltime += tmp1;
			}	
		}	

		INFOPRINTCOLOR(GY_COLOR_BLUE, "Benchmarking Lookups with Offlining at each lookup for %lu entries across %lu iter (successful %lu) : Avg time is %lu nsec (%lu usec) : Min time is %lu nsec : Max time is %lu nsec : Histogram Stats : %s\n\n",
			szarr[s], niter, nsec, totaltime/niter, totaltime/1000/niter, mintime, maxtime, bench.print_stats(STRING_BUFFER<1024>().get_str_buf()));


		bench.clear();
		totaltime = 0; mintime = ~0ul; maxtime = 0; nsec = 0;

		new (&slowlock) RCU_LOCK_SLOW();

		for (size_t i = 0; i < szarr[s]; i++) {
			pid = 1000 + i + get_nsec_clock() % szarr[s];

			tmp2 = get_nsec_clock();
			GY_CC_BARRIER();

			bret = gtaskhash.template delete_single_elem<RCU_LOCK_FAST>(pid, get_int_hash(pid));
			GY_CC_BARRIER();

			tmpu = get_nsec_clock();

			if (bret) nsec++;

			tmp1 = tmpu - tmp2;

			if (tmp1 < mintime) {
				mintime = tmp1;
			}	

			if (tmp1 > maxtime) {
				maxtime = tmp1;
			}

			bench.add_data(tmp1);

			totaltime += tmp1;
		}	

		slowlock.~RCU_LOCK_SLOW();

		INFOPRINTCOLOR(GY_COLOR_YELLOW, "Benchmarking Deletes for %lu entries (successful %lu) : Avg time is %lu nsec (%lu usec) : Min time is %lu nsec : Max time is %lu nsec : Histogram Stats : %s\n\n",
			szarr[s], nsec, totaltime/szarr[s], totaltime/1000/szarr[s], mintime, maxtime, bench.print_stats(STRING_BUFFER<1024>().get_str_buf()));

		wait_for_all_call_rcu_free();
	}
	
	return 0;
}

MAKE_PTHREAD_FUNC_WRAPPER(writer_thread);
MAKE_PTHREAD_FUNC_WRAPPER(reader_thread);
MAKE_PTHREAD_FUNC_WRAPPER(debug_thread);

}

int main(int argc, char **argv)
{
	using namespace TEST_SPACE;

	gdebugexecn = 10;
	
	INFOPRINTCOLOR(GY_COLOR_CLEAR_SCREEN, "\t\tStarting the RCU Hashtable test cases...\n\n\n");

	CPU_IO_STATS			procstats(GY_COLOR_YELLOW_UNDERLINE "Process summary stats" GY_COLOR_RESET, getpid(), true);

	auto 				& thrdata = gy_thread_rcu();

	GY_SIGNAL_HANDLER::init_singleton(argv[0]);

	int				ret;
	pthread_t			dbgtid;
	
	gy_create_thread(&dbgtid, GET_PTHREAD_WRAPPER(debug_thread), nullptr);

	try {
		ASYNC_FUNC_HDLR::init_singleton();

		GY_TEST_HASH_TABLE	grcuhash(1), grcuhash_temp(400);

		init_hash_test(&grcuhash_temp);

		init_test_second(grcuhash, grcuhash_temp);

		INFOPRINT("Inital tests succeeded : Now spawning threads...\n");

		gy_nanosleep(1, 0);
		
		pthread_t		rdtid[10];
		int			ret;

		//gdebugexecn = 0;

		for (size_t i = 0; i < sizeof(rdtid)/sizeof(*rdtid); i++) {
			gy_create_thread(rdtid + i, i < 4 ? GET_PTHREAD_WRAPPER(writer_thread) : GET_PTHREAD_WRAPPER(reader_thread), &grcuhash);
		}	

		for (size_t i = 0; i < sizeof(rdtid)/sizeof(*rdtid); i++) {
			pthread_join(rdtid[i], nullptr);
		}	

		INFOPRINT("Final count of Hash Table elements is %lu\n\n", grcuhash.count_slow());
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT("Exception caught while handling grcuhash : %s\n", GY_GET_EXCEPT_STRING);
	);

	to_exit = 1; 
/* 	pthread_cancel(dbgtid); */

	pthread_join(dbgtid, nullptr);

	INFOPRINTCOLOR(GY_COLOR_BOLD_GREEN, "All threads exited. Waiting for RCU thread exit...\n");

	wait_for_all_call_rcu_free();

	return 0;
}

