
#if defined(__i386__) || defined(__x86_64__)
#include 		<cpuid.h>
#endif

#include		"gy_server_int.h"
#include		"gy_sys_hardware.h"
#include		"gy_mount_disk.h"
#include		"gy_scheduler.h"
#include		"gy_task_stat.h"
#include		"gy_child_proc.h"
#include		"gy_multi_proc_comm.h"

#include 		<dirent.h>
#include 		<sys/utsname.h>

namespace gyeeta {

/*
 * Inspired liberally from systemd src.
 */ 
static int detect_vm_dmi(VIRT_TYPE_E & type, int sysfs_dir_fd, int procfs_dir_fd) noexcept
{
	int				fd, ret;
	char				buf[512];
	
	static constexpr const char * dmi_vendors[] = 
	{
		/*	"/sys" */ "/class/dmi/id/product_name", 
		/*	"/sys" */ "/class/dmi/id/sys_vendor",
		/*	"/sys" */ "/class/dmi/id/board_vendor",
		/*	"/sys" */ "/class/dmi/id/bios_vendor"
	};

	static constexpr const struct 
	{
		const char 		*pvendor;
		size_t			len;
		VIRT_TYPE_E		type;
	} dmi_vendor_table[] = {

		{ "KVM", 		GY_CONST_STRLEN("KVM"), 		VIRT_TYPE_KVM },
		{ "QEMU",		GY_CONST_STRLEN("QEMU"), 		VIRT_TYPE_QEMU },
		{ "VMware", 		GY_CONST_STRLEN("VMware"),		VIRT_TYPE_VMWARE },
		{ "VMW", 		GY_CONST_STRLEN("VMW"),			VIRT_TYPE_VMWARE },
		{ "innotek GmbH", 	GY_CONST_STRLEN("innotek GmbH"),	VIRT_TYPE_ORACLE },
                { "Oracle Corporation", GY_CONST_STRLEN("Oracle Corporation"),	VIRT_TYPE_ORACLE },
		{ "Xen",		GY_CONST_STRLEN("Xen"),			VIRT_TYPE_XEN },
		{ "Bochs", 		GY_CONST_STRLEN("Bochs"),		VIRT_TYPE_BOCHS },
		{ "Parallels",		GY_CONST_STRLEN("Parallels"),		VIRT_TYPE_PARALLELS },
		{ "BHYVE",		GY_CONST_STRLEN("BHYVE"),		VIRT_TYPE_BHYVE },
	};
	

	for (size_t i = 0; i < GY_ARRAY_SIZE(dmi_vendors); i++) {
		snprintf(buf, sizeof(buf), "./%s", dmi_vendors[i]);

		SCOPE_FD		scopefd(sysfs_dir_fd, buf, O_RDONLY, 0600);

		fd = scopefd.get();
		if (fd >= 0) {
			
			ret = read(fd, buf, sizeof(buf) - 1);
			if (ret > 0) {
				buf[ret] = '\0';

				for (size_t j = 0; j < GY_ARRAY_SIZE(dmi_vendor_table); j++) {
					if (0 == strncmp(buf, dmi_vendor_table[j].pvendor, dmi_vendor_table[j].len)) {

						DEBUGEXECN(1, INFOPRINTCOLOR(GY_COLOR_BLUE, "Virtualization detected from DMI : %s is seen...\n", dmi_vendor_table[j].pvendor););
						type = dmi_vendor_table[j].type;
						return 0;
					}
				}	
			}	
		}
	}	

	return 1;

}	

static VIRT_TYPE_E detect_vm_cpuid(void) noexcept
{
#if defined(__i386__) || defined(__x86_64__)
	/* CPUID is an x86 specific interface. */

	static const struct {
		const char 			*cpuid;
		VIRT_TYPE_E 			id;
	} cpuid_vendor_table[] = 
	{
		{ "XenVMMXenVMM", 		VIRT_TYPE_XEN       },
		{ "KVMKVMKVM",    		VIRT_TYPE_KVM       },
		{ "TCGTCGTCGTCG", 		VIRT_TYPE_QEMU      },
		{ "VMwareVMware", 		VIRT_TYPE_VMWARE    },
		{ "Microsoft Hv", 		VIRT_TYPE_MICROSOFT },
		{ "bhyve bhyve ", 		VIRT_TYPE_BHYVE     },
		{ "QNXQVMBSQG",   		VIRT_TYPE_QNX       },
		{ "ACRNACRNACRN",   		VIRT_TYPE_ACRN      },
	};

	uint32_t 				eax, ebx, ecx, edx;
	bool 					hypervisor;

	/* http://lwn.net/Articles/301888/ */

	/* First detect whether there is a hypervisor */
	if (__get_cpuid(1, &eax, &ebx, &ecx, &edx) == 0) {
		return VIRT_TYPE_NONE;
	}	

	hypervisor = ecx & 0x80000000U;

	if (hypervisor) {
		union {
			uint32_t 		sig32[3];
			char 			text[13];
		} sig = {};

		size_t 				j;

		/* There is a hypervisor, see what it is */
		__cpuid(0x40000000U, eax, ebx, ecx, edx);

		sig.sig32[0] = ebx;
		sig.sig32[1] = ecx;
		sig.sig32[2] = edx;


		for (j = 0; j < GY_ARRAY_SIZE(cpuid_vendor_table); j++) {
			if (0 == strcmp(sig.text, cpuid_vendor_table[j].cpuid)) {

				DEBUGEXECN(1, INFOPRINTCOLOR(GY_COLOR_BLUE, "Virtualization found : using cpuid is %s\n", cpuid_vendor_table[j].cpuid););
				return cpuid_vendor_table[j].id;
			}	
		}		

		DEBUGEXECN(1, INFOPRINTCOLOR(GY_COLOR_BLUE, "Virtualization found from cpuid %s is not yet handled...\n", sig.text););

		return VIRT_TYPE_OTHER;
	}
#endif
	// No virtualization found in CPUID

	return VIRT_TYPE_NONE;
}


/*
 * Returns 1 if virtualization detected and 0 otherwise.
 */ 
int gy_detect_virtualization(VIRT_TYPE_E & type, int sysfs_dir_fd, int procfs_dir_fd) noexcept
{
	int				fd, ret;
	char				buf[512];
	VIRT_TYPE_E			dmitype = VIRT_TYPE_NONE, cpuidtype = VIRT_TYPE_NONE;

	type = VIRT_TYPE_NONE;

	GY_SCOPE_EXIT {
		DEBUGEXECN(1, 
			if (type != VIRT_TYPE_NONE) {
				INFOPRINTCOLOR(GY_COLOR_BLUE, "Virtualization detected : Type %s is seen...\n", get_virtualization_type(type));
			}	
		);
	};
		
	{
		/*
		 * First try to detect if running under Microsoft WSL
		 */
		 
		snprintf(buf, sizeof(buf), "./sys/kernel/osrelease");	

		SCOPE_FD		scopefd(procfs_dir_fd, buf, O_RDONLY, 0600);

		fd = scopefd.get();
		if (fd >= 0) {
			
			ret = read(fd, buf, sizeof(buf) - 1);
			if (ret > 0) {
				buf[ret] = '\0';

				if ((strstr(buf, "Microsoft")) || (strstr(buf, "WSL"))) {
					type = VIRT_TYPE_HYPER_WSL;
					return 1;
				}	
			}	
		}
	}

	/*
	 * First, try to detect Oracle Virtualbox, even if it uses KVM, as well as Xen even if it cloaks as Microsoft hyper-V
	 *
	 * Second, try to detect from CPUID, this will report KVM for whatever software is used even if info in DMI is overwritten.
	 */
	ret = detect_vm_dmi(dmitype, sysfs_dir_fd, procfs_dir_fd); 
	if (ret == 0) {
		if ((dmitype == VIRT_TYPE_ORACLE) || (dmitype == VIRT_TYPE_XEN)) {
			type = dmitype;
			return 1;
		}	
	}	

	cpuidtype = detect_vm_cpuid(); 

	if (cpuidtype != VIRT_TYPE_NONE) {

		if (cpuidtype != VIRT_TYPE_OTHER) {
			type = cpuidtype;
			return 1;
		}	

		if ((dmitype != VIRT_TYPE_OTHER) && (dmitype != VIRT_TYPE_NONE)) {
			type = dmitype;
			return 1;
		}	
		
		// Last try for xen
		
		snprintf(buf, sizeof(buf), "./hypervisor/type");	
		
		SCOPE_FD		scopefd(sysfs_dir_fd, buf, O_RDONLY, 0600);

		fd = scopefd.get();
		if (fd >= 0) {
			
			ret = read(fd, buf, sizeof(buf) - 1);
			if (ret > 0) {
				buf[ret] = '\0';

				if (0 == strncmp(buf, "xen", 3)) {
					type = VIRT_TYPE_XEN;
					return 1;
				}	
			}	
		}
		
		type = VIRT_TYPE_OTHER;
		return 1;
	}	

	type = VIRT_TYPE_NONE;
	return 0;
}	

int detect_container(bool & is_pid_namespace, bool & is_net_namespace, bool & is_mount_namespace, bool & is_uts_namespace, bool & is_cgroup_namespace) noexcept
{
	/*
	 * First check if we are running in root PID Namesapce. Also check if /proc/<PIDs> are valid entries for root NS.
	 * We check the /proc/1/stat for starttime and if starttime is over 100 ticks we assume in a non root PID NS. We confirm
	 * it by checking all PIDs comm for ksoftirqd or kworker
	 *
	 * XXX TODO Revisit 100 ticks logic once Kernel Time Namespace mechanism is integrated
	 */

	int				ret, fd;
	char				buf[64], databuf[1024], *ptmp;
	ssize_t				szread;
	size_t				nbytes;
	char				c, task_state;
	uint64_t			startclock;
	pid_t				task_ppid;
	uint32_t 			task_flags, task_rt_priority, task_sched_policy;
	uint64_t			starttimeusec;
	int64_t 			task_priority, task_nice;

	try {
		TASK_NS_INODES		taskns(getpid(), SYS_HARDWARE::get_root_ns_inodes());	

		is_pid_namespace 	= !taskns.is_in_root_ns(NS_TYPE_PID);
		is_net_namespace	= !taskns.is_in_root_ns(NS_TYPE_NET);
		is_mount_namespace	= !taskns.is_in_root_ns(NS_TYPE_MNT);
		is_uts_namespace	= !taskns.is_in_root_ns(NS_TYPE_UTS);
		is_cgroup_namespace 	= !taskns.is_in_root_ns(NS_TYPE_CGROUP);

		if (is_pid_namespace) {
			// All bets are off as we cannot figure whether ns is in root ns
			is_net_namespace 	= true;
			is_mount_namespace	= true;
			is_uts_namespace	= true;
			is_cgroup_namespace	= true;
	
			DEBUGEXECN(1, INFOPRINTCOLOR(GY_COLOR_BOLD_RED, "Running in a PID Namespace container...\n"););
			return 0; 
		}

		// We need to confirm root PID namespace using other methods...
	}
	GY_CATCH_EXCEPTION(
		PERRORPRINT("Exception caught while getting Namespace info for current process : %s", GY_GET_EXCEPT_STRING);
		return -1;
	);
	
	SCOPE_FD			scopefd("/proc/1/stat", O_RDONLY);
	
	fd = scopefd.get();
	if (fd < 0) {
		PERRORPRINT("Failed to open /proc/1/stat");
		return -1;
	}	

	szread = gy_readbuffer(fd, databuf, sizeof(databuf) - 1);
	if (szread <= 5) {
		PERRORPRINT("Failed to read /proc/1/stat");
		return -1;
	}

	databuf[szread] = '\0';

	ptmp = strchr(databuf, ')');
	if (!ptmp) {
		ERRORPRINT("Invalid format of /proc/1/stat\n");
		return -1;
	}	

	ptmp++;

	while ((c = *ptmp) && (c != ' ')) {
		ptmp++;
	}

	while ((c = *ptmp) && (c == ' ')) {
		ptmp++;
	}	
	
	ret = sscanf(ptmp, "%c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %*u %*u %*d %*d %*d %*d %*d %*d %lu", &c, &startclock);
	
	if (ret != 2) {
		ERRORPRINT("Invalid format of /proc/1/stat file\n");
		return -1;
	}	
	
	if (startclock < 100) {
		// Seems to be running in root NS
		return 0;
	}	

	// Seems to be running in a PID NS container as starttime over 100 ticks : Confirm from process comms

	DIR				*pdir;
	struct dirent			*pdent;
	char				*pfile, path[256], *pstr1;
	uint64_t			ulval;

	pdir = opendir("/proc");
	if (!pdir) {
		PERRORPRINT("Could not open /proc filesystem");
		return -1;
	}

	GY_SCOPE_EXIT {
		closedir(pdir);
	};	

	while ((pdent = readdir(pdir)) != nullptr) {

		pfile = pdent->d_name;	
		
		pstr1 = nullptr;

		if (string_to_number(pfile, ulval, &pstr1, 10)) {
			if (pstr1 && *pstr1) {
				continue;
			}	
		}	
		else {
			continue;
		}	

		snprintf(path, sizeof(path), "/proc/%lu/comm", ulval);

		SCOPE_FD			pidfd(path, O_RDONLY);
		
		fd = pidfd.get();
		if (fd < 0) {
			continue;
		}	

		szread = gy_readbuffer(fd, databuf, sizeof(databuf) - 1);
		if (szread <= 5) {
			continue;
		}

		databuf[szread] = '\0';

		ptmp = strstr(databuf, "ksoftirqd");
		if (!ptmp) {
			ptmp = strstr(databuf, "kworker");
		}

		if (ptmp) {
			ret = get_proc_stat((pid_t)ulval, task_ppid, task_state, task_flags, starttimeusec, task_priority, task_nice, task_rt_priority, task_sched_policy);

			if ((ret == 0) && (true == is_task_kthread(task_flags))) {
				DEBUGEXECN(1, INFOPRINTCOLOR(GY_COLOR_BLUE, "Kernel Worker process detected for PID %lu. So assuming running in root PID NS...\n", ulval););
				return 0;
			}
		}	
	}

	is_pid_namespace 	= true;
	is_net_namespace 	= true;
	is_mount_namespace	= true;
	is_uts_namespace	= true;
	is_cgroup_namespace	= true;

	DEBUGEXECN(1, INFOPRINTCOLOR(GY_COLOR_BOLD_RED, "Running in a PID Namespace container confirmed...\n"););
	return 0; 
}	

int get_host_id(int sysfs_dir_fd_in, char *pbuffer, size_t maxsz) noexcept
{
	int				fd, ret;
	SCOPE_FD			scopefd(sysfs_dir_fd_in, sysfs_dir_fd_in >= 0 ? "./class/dmi/id/product_uuid" : "/sys/class/dmi/id/product_uuid", O_RDONLY);
	
	fd = scopefd.get();
	if (fd < 0) {
		PERRORPRINT("Failed to open /sys/class/dmi/id/product_uuid for getting machine id");
		return -1;
	}	

	ret = read(fd, pbuffer, maxsz > 1 ? maxsz - 1 : 0);
	if (ret < 8) {
		PERRORPRINT("Failed to read /sys/class/dmi/id/product_uuid or format error");
		return -1;
	}

	if (pbuffer[ret - 1] == '\n') {
		ret--;
	}
	pbuffer[ret] = '\0';

	for (int i = 0; i < ret; ++i) {
		pbuffer[i] = std::toupper(pbuffer[i]);
	}

	// Delete all '-' within the id
	string_delete_char(pbuffer, ret, '-');


	return 0;
}	


int CPU_MEM_INFO::get_processor_topology(char *pbuf, const size_t bufsz)
{
	int				fd, tfd, ret;
	char				tbuf[128];
	const char 			*ptmp; 
	size_t				tlen, lencopy;
	struct stat			stat1;
	MEM_NODE_BITSET			numaset;
	CPU_CORES_BITSET		cpuset;

	/*
	 * First get the NUMA config and then the processor core/threads and caches.
	 */
	{ 
		snprintf(tbuf, sizeof(tbuf), "./devices/system/node/online");
		
		SCOPE_FD			scopefd(sysfs_dir_fd, tbuf, O_RDONLY, 0600);

		fd = scopefd.get();
		if (fd >= 0) {
			
			ret = read(fd, pbuf, bufsz > 1 ? bufsz - 1 : 0);
			if (ret <= 0) {
				GY_THROW_SYS_EXCEPTION("Failed to read /sys/devices/system/node/online");
			}	
			pbuf[ret] = '\0';

			ret = set_bitset_from_buffer(numaset, pbuf, ret);

			num_numa_nodes = numaset.count();
			
			if (num_numa_nodes == 0) {
				GY_THROW_EXCEPTION("Number of NUMA nodes from /sys/devices/system/node/online is 0");
			}	
			else if (num_numa_nodes >= MAX_PROCESSOR_SOCKETS) {
				GY_THROW_EXCEPTION("Number of processor NUMA nodes is higher than max that can be handled %u", MAX_PROCESSOR_SOCKETS - 1);
			}	
			
			pnodelist = new NUMA_NODE_ONE[num_numa_nodes];

			for (int i = 0; i < num_numa_nodes; i++) {

				pnodelist[i].nodenum = i;
				pnodelist[i].num_numa_nodes = num_numa_nodes;
				pnodelist[i].pnode_distance_hops = (int *)calloc_or_throw(num_numa_nodes + 1, sizeof(int));

				{
					snprintf(tbuf, sizeof(tbuf), "./devices/system/node/node%d/cpulist", i);
					
					SCOPE_FD			scfd(sysfs_dir_fd, tbuf, O_RDONLY, 0600);

					tfd = scfd.get();
					if (tfd >= 0) {
						
						ret = read(tfd, pbuf, bufsz - 1);
						if (ret <= 0) {
							GY_THROW_SYS_EXCEPTION("Failed to read sysfs %s", tbuf);
						}	
						pbuf[ret] = '\0';
				
						ret = set_bitset_from_buffer(pnodelist[i].cpuset, pbuf, ret);

						pnodelist[i].ncpu = pnodelist[i].cpuset.count();
					}	
				}

				{
					snprintf(tbuf, sizeof(tbuf), "./devices/system/node/node%d/distance", i);
					
					SCOPE_FD			scfd(sysfs_dir_fd, tbuf, O_RDONLY, 0600);

					tfd = scfd.get();
					if (tfd >= 0) {
						
						ret = read(tfd, pbuf, bufsz - 1);
						if (ret <= 0) {
							GY_THROW_SYS_EXCEPTION("Failed to read sysfs %s", tbuf);
						}	
						pbuf[ret] = '\0';
				
						STR_RD_BUF		nodestr(pbuf, ret);
						
						for (int j = 0; j < num_numa_nodes; j++) {
							ptmp = nodestr.get_next_word(tlen);
							if (ptmp) {
								int		dist = atoi(ptmp);

								pnodelist[i].pnode_distance_hops[j] = dist/10 - (dist >= 10 ? 1 : 0);
							}	
						}	
					}	
				}

				{
					snprintf(tbuf, sizeof(tbuf), "./devices/system/node/node%d/meminfo", i);
					
					SCOPE_FD			scfd(sysfs_dir_fd, tbuf, O_RDONLY, 0600);

					tfd = scfd.get();
					if (tfd >= 0) {
						
						ret = read(tfd, pbuf, bufsz - 1);
						if (ret <= 0) {
							GY_THROW_SYS_EXCEPTION("Failed to read sysfs %s", tbuf);
						}	
						pbuf[ret] = '\0';
				
						STR_RD_BUF		memstr(pbuf, ret);
								
						ptmp = memstr.skip_till_substring_const("MemTotal");
						if (ptmp) {
							memstr.skip_till_next_delim(':');

							ptmp = memstr.get_next_word(tlen);
							if (ptmp) {
								if (string_to_number(ptmp, pnodelist[i].memtotal)) {
									pnodelist[i].memtotal <<= 10;
								}	
							}	
						}	
					}	
				}

			}	
		}
		else {
			// Check if NUMA present
			snprintf(tbuf, sizeof(tbuf), "./devices/system/node");

			ret = fstatat(sysfs_dir_fd, tbuf, &stat1, 0);
			if (ret != 0) {
				// No NUMA
				num_numa_nodes = 0;
				pnodelist = nullptr;
			}	
			else {
				GY_THROW_EXCEPTION("Failed to get the number of NUMA nodes from /sys/devices/system/node/online");
			}	
		}	
	}

	/*
	 * Now we get the processor threads_per_core and if hyperthreading is enabled, populate thread_siblings_list
	 * We only check cpu0 to check if hyperthreading active. TODO handle if heterogenious CPU config (Big.little) is present. 
	 */
	
	{
		if (pnodelist) {
			cores_per_socket = pnodelist[0].ncpu;
		}	
		else {
			cores_per_socket = num_online;
		}
			
		snprintf(tbuf, sizeof(tbuf), "./devices/system/cpu/cpu0/topology/thread_siblings_list");

		SCOPE_FD			scopefd(sysfs_dir_fd, tbuf, O_RDONLY, 0600);

		fd = scopefd.get();
		if (fd >= 0) {
			
			ret = read(fd, pbuf, bufsz - 1);
			if (ret <= 0) {
				GY_THROW_SYS_EXCEPTION("Failed to read sysfs %s", tbuf);
			}	
			pbuf[ret] = '\0';

			ret = set_bitset_from_buffer(cpuset, pbuf, ret);

			threads_per_core = cpuset.count();

			if (threads_per_core > 1) {
				thread_siblings_list.reserve(num_online);
			
				thread_siblings_list.push_back(cpuset);

				for (int i = 1; i < num_online; i++) {

					snprintf(tbuf, sizeof(tbuf), "./devices/system/cpu/cpu%d/topology/thread_siblings_list", i);

					SCOPE_FD			scfd(sysfs_dir_fd, tbuf, O_RDONLY, 0600);

					tfd = scfd.get();
					if (tfd >= 0) {
						
						ret = read(tfd, pbuf, bufsz - 1);
						if (ret <= 0) {
							GY_THROW_SYS_EXCEPTION("Failed to read sysfs %s", tbuf);
						}	
						pbuf[ret] = '\0';

						ret = set_bitset_from_buffer(cpuset, pbuf, ret);
						
						thread_siblings_list.push_back(cpuset);
					}	
					else {
						GY_THROW_SYS_EXCEPTION("Failed to open sysfs %s", pbuf);
					}	
				}		
			}
		}	
		else {
			threads_per_core = 1;
		}	
	}

	{
		/*
		 * Now get the processor cache sizes. Only cpu0 is considered
		 */
		uint32_t			cachesize[5] {};  

		for (size_t i = 0; i < GY_ARRAY_SIZE(cachesize); i++) {

			snprintf(tbuf, sizeof(tbuf), "./devices/system/cpu/cpu0/cache/index%lu/size", i);

			SCOPE_FD			scfd(sysfs_dir_fd, tbuf, O_RDONLY, 0600);

			tfd = scfd.get();
			if (tfd >= 0) {
				
				ret = read(tfd, pbuf, bufsz - 1);
				if (ret > 0) {
					pbuf[ret] = '\0';
				}	
				else {
					*pbuf = '\0';
				}	

				cachesize[i] = atoi(pbuf) * 1024;
			}	
		}

		level1_dcache_sz 	= cachesize[0];
		level1_icache_sz	= cachesize[1];
		level2_cache_sz 	= cachesize[2];
		level3_cache_sz 	= cachesize[3];
		level4_cache_sz 	= cachesize[4];
	}

	{
		snprintf(tbuf, sizeof(tbuf), "./devices/system/clocksource/clocksource0/current_clocksource");

		SCOPE_FD			scfd(sysfs_dir_fd, tbuf, O_RDONLY, 0600);

		tfd = scfd.get();
		if (tfd >= 0) {
			
			ret = read(tfd, current_clocksource, sizeof(current_clocksource) - 1);
			if (ret > 0) {
				if (current_clocksource[ret - 1] == '\n') ret--;

				current_clocksource[ret] = '\0';
			}	
			else {
				*current_clocksource = '\0';
			}	
		}	
	}	

	return 0;
}	

/*
 * We could also have used /proc/1/root/ as prefix path... XXX
 */
int get_root_mount_ns_info(OS_INFO *posinfo, CHILD_PROC *pcmd_child, bool is_uts_namespace) noexcept
{
	try {
		int			scoperet = -1;

		GY_SCOPE_EXIT {
			if (scoperet == -1) {
				WARNPRINT("Failed to get Root Mount Namespace Hostname and OS Distribution. Hostname and Distribution used will be as per container...\n");
			}
		};

		if (!(pcmd_child && pcmd_child->get_shared_pool())) {
			return -1;
		}	

		auto phdlr = MULTI_COMM_SINGLETON::get_multi_4096();
		if (!phdlr) {
			ERRORPRINT("Multi Proc comm singleton not yet initialized...\n");
			return -1;
		}	

		auto pmulti = phdlr->get_proc_buf(true /* is_non_block */);
		if (!pmulti) {
			return -1;
		}	

		static_assert(sizeof(OS_INFO) < MULTI_COMM_SINGLETON::MULTI_PROC_SZ_4096::get_max_data_len());

		COMM_MSG_C			tmsg;

		tmsg.arg1_ = (uint64_t)(uintptr_t)pmulti;
		tmsg.arg2_ = (uint64_t)(uintptr_t)phdlr;
		tmsg.arg3_ = (uint64_t)(uintptr_t)is_uts_namespace;
		
		tmsg.func_ = [](uint64_t arg1, uint64_t arg2, uint64_t arg3, const uint8_t *poptbuf, size_t opt_bufsize)
		{
			MULTI_COMM_SINGLETON::MULTI_PROC_SZ_4096::MULTI_PROC_ELEM	*pelem;
			MULTI_COMM_SINGLETON::MULTI_PROC_SZ_4096			*phdlr;
			OS_INFO								*posinfo;
			size_t								szmax;
			int								ret, respcode = 0;
			bool								is_uts_namespace;

			pelem = decltype(pelem)((uintptr_t)arg1);
			phdlr = decltype(phdlr)((uintptr_t)arg2);
			is_uts_namespace = decltype(is_uts_namespace)((uintptr_t)arg3);

			assert(pelem && phdlr);
			
			ret = open("/proc/1/task/1/ns/mnt", O_RDONLY | O_CLOEXEC);	
			if (ret == -1) {
				PERRORPRINT("Could not open /proc/1 Mount Namespace file ");
				respcode = -1;
			}	
			else {

				ret = setns(ret, 0);
				if ((ret == -1) && (errno != ENOSYS)) {
					if (errno != ENOMEM) {
						PERRORPRINT("Failed to setns for /proc/1 Mount Namespace");
						respcode = -1;
						goto done1;
					}
				}	
				
				posinfo = (OS_INFO *)pelem->get_data_buf();

				try {
					new (posinfo) OS_INFO(false /* ignore_min_kern */, false /* is_mount_namespace */, is_uts_namespace);
				}
				GY_CATCH_EXCEPTION(
					ERRORPRINT_OFFLOAD("Exception caught while getting host os info : %s\n", GY_GET_EXCEPT_STRING);
					respcode = -1;
				);
			}

done1 :
			pelem->signal_completion(respcode, sizeof(*posinfo));

			return 0;
		};	

		struct iovec		iov[1] = {{&tmsg, sizeof(tmsg)}};
		uint32_t		count;	
		PKT_RET_E		retp;

		retp = pcmd_child->get_shared_pool()->pool_write_buffer(iov, 1, &count, false /* is_nonblock */); 
		if (retp != PKT_RET_SUCCESS) {
			return -1;
		}	

		// Now wait upto 10 sec for response

		bool			bret;
		size_t			reslen;
		int			ret, respcode;
		alignas(8) uint8_t	resbuf[sizeof(OS_INFO)];

		bret = pmulti->dispatch_timed_wait(10'000, resbuf, reslen, respcode);
		if ((bret == false) || (respcode != 0)) {
			return -1;
		}

		OS_INFO			*pos = (OS_INFO *)resbuf;	

		if (pos->distrib != DIST_DUMMY_START) {
			INFOPRINT("Root Mount NS Hostname = %s : Distribution = %s\n", pos->hostname_str, pos->distrib_string);

			GY_STRNCPY(posinfo->node_hostname_str, pos->hostname_str, sizeof(posinfo->node_hostname_str));
			GY_STRNCPY(posinfo->node_distrib_string, pos->distrib_string, sizeof(posinfo->node_distrib_string));
			posinfo->node_distrib = pos->distrib;

			scoperet = 0;

			return 0;
		}	

		return 1;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT("Exception caught while getting root mount NS info : %s\n", GY_GET_EXCEPT_STRING);
		return -1;
	);
}

char * CPU_MEM_INFO::get_cpu_mem_print_str(char *pbuf, size_t maxsz) noexcept
{
	if (!pbuf) {
		return nullptr;
	}

	STR_WR_BUF		strbuf(pbuf, maxsz);

	strbuf.appendfmt("Processor Model %s CPU Vendor %s : Number of cores online %d, offline %d, possible %d, isolated %d, with nohz_full %d : "
			"Total Memory %lu (%lu GB),  Corrupted Memory %lu (%lu GB), Number of NUMA Nodes %d, Cores per socket %d, Threads per core %d : ",
			cpu_model_name, cpu_vendor_name, num_online, num_offline, num_possible, num_isolated, num_nohz, total_memory, GY_DOWN_GB(total_memory),
			corrupted_memory, GY_DOWN_GB(corrupted_memory), num_numa_nodes, cores_per_socket, threads_per_core); 

	for (int i = 0; i < num_numa_nodes; i++) {
		strbuf.appendfmt("Numa Node %d : Number of cores %d, Memory %lu (%lu GB), Hop Count to Numa Nodes ", 
			i, pnodelist[i].ncpu, pnodelist[i].memtotal, GY_DOWN_GB(pnodelist[i].memtotal));
		
		for (int j = 0; j < num_numa_nodes; j++) {
			strbuf.appendfmt("Node %d - %d hops, ", j, pnodelist[i].pnode_distance_hops[j]);		
		}
	}	

	strbuf.appendfmt(" : Level 1 Data Cache %u KB, Instruction Cache %u KB, Level 2 Cache %u KB, Level 3 Cache %u KB, Level 4 Cache %u KB : ",
		GY_DOWN_KB(level1_dcache_sz), GY_DOWN_KB(level1_icache_sz), GY_DOWN_KB(level2_cache_sz), GY_DOWN_KB(level3_cache_sz), GY_DOWN_KB(level4_cache_sz)); 

	strbuf.appendfmt("Current clocksource %s : CPU Virtualization type - %s", current_clocksource, get_virtualization_type(virtualization_type));

	return pbuf;
}	

CPU_MEM_INFO::CPU_MEM_INFO(int sysfs_dir_fd_in, int procfs_dir_fd_in) 
	: sysfs_dir_fd(sysfs_dir_fd_in), procfs_dir_fd(procfs_dir_fd_in)
{
	try {
		constexpr size_t		bufsz = 4096;
		int				fd, ret;
		char				pbuf[bufsz], tbuf[128];
		const char 			*ptmp; 
		size_t				tlen, lencopy;
		
		*cpu_model_name = '\0';
		*cpu_vendor_name = '\0';
		*current_clocksource = '\0';

		{
			strcpy(pbuf, "./cpuinfo");

			SCOPE_FD			scopefd(procfs_dir_fd, pbuf, O_RDONLY, 0600);

			fd = scopefd.get();
			if (fd >= 0) {
				
				ret = read(fd, pbuf, bufsz - 1);
				if (ret <= 0) {
					GY_THROW_SYS_EXCEPTION("Failed to read /proc/cpuinfo");
				}	
				pbuf[ret] = '\0';

				STR_RD_BUF		cpustr(pbuf, ret);

				ptmp = cpustr.skip_till_substring_const("vendor_id");
				if (ptmp) {
					cpustr.skip_till_next_delim(':');

					ptmp = cpustr.get_next_word(tlen, true, "\n");
					if (ptmp) {
						GY_SAFE_MEMCPY(cpu_vendor_name, sizeof(cpu_vendor_name) - 1, ptmp, tlen, lencopy);
						cpu_vendor_name[lencopy] = '\0';
					}	
				}	
				
				ptmp = cpustr.skip_till_substring_const("model name");
				if (ptmp) {
					cpustr.skip_till_next_delim(':');

					ptmp = cpustr.get_next_word(tlen, true, "\n");
					if (ptmp) {
						GY_SAFE_MEMCPY(cpu_model_name, sizeof(cpu_model_name) - 1, ptmp, tlen, lencopy);
						cpu_model_name[lencopy] = '\0';
					}	
				}	

				ptmp = cpustr.skip_till_whole_word_const("flags");
				if (ptmp) {
					cpustr.skip_till_next_delim(':');

					ptmp = cpustr.get_next_word(tlen, true, "\n");
					if (ptmp) {
						pcpu_flags = new char[tlen + 1];

						std::memcpy(pcpu_flags, ptmp, tlen);
						pcpu_flags[tlen] = '\0';
					}	
				}	

				ptmp = cpustr.skip_till_whole_word_const("bugs");
				if (ptmp) {
					cpustr.skip_till_next_delim(':');

					ptmp = cpustr.get_next_word(tlen, true, "\n");
					if (ptmp) {
						pcpu_bugs = new char[tlen + 1];

						std::memcpy(pcpu_bugs, ptmp, tlen);
						pcpu_bugs[tlen] = '\0';
					}	
				}	
			}	
			else {
				GY_THROW_SYS_EXCEPTION("Could not open /proc/cpuinfo");
			}
		}	

		{
			strcpy(pbuf, "./devices/system/cpu/online");

			SCOPE_FD			scopefd(sysfs_dir_fd, pbuf, O_RDONLY, 0600);

			fd = scopefd.get();
			if (fd >= 0) {
				
				ret = read(fd, pbuf, bufsz - 1);
				if (ret <= 0) {
					GY_THROW_SYS_EXCEPTION("Failed to read /sys/devices/system/cpu/online");
				}	
				pbuf[ret] = '\0';

				ret = set_bitset_from_buffer(online_cpu, pbuf, ret);

				num_online = online_cpu.count();

				if (num_online >= MAX_PROCESSOR_CORES) {
					GY_THROW_EXCEPTION("Number of processor cores is higher than max that can be handled %u", MAX_PROCESSOR_CORES - 1);
				}	
				else if (num_online == 0) {
					num_online = 1;
				}
			}
			else {
				GY_THROW_SYS_EXCEPTION("Could not open /sys/devices/system/cpu/online");
			}
		}
		
		{
			strcpy(pbuf, "./devices/system/cpu/offline");

			SCOPE_FD			scopefd(sysfs_dir_fd, pbuf, O_RDONLY, 0600);

			fd = scopefd.get();
			if (fd >= 0) {
				
				ret = read(fd, pbuf, bufsz - 1);
				if (ret > 0) {
					pbuf[ret] = '\0';

					ret = set_bitset_from_buffer(offline_cpu, pbuf, ret);
					num_offline = offline_cpu.count();
				}	
				
			}
		}

		{
			strcpy(pbuf, "./devices/system/cpu/possible");

			SCOPE_FD			scopefd(sysfs_dir_fd, pbuf, O_RDONLY, 0600);

			fd = scopefd.get();
			if (fd >= 0) {
				
				ret = read(fd, pbuf, bufsz - 1);
				if (ret > 0) {
					pbuf[ret] = '\0';

					ret = set_bitset_from_buffer(possible_cpu, pbuf, ret);
					num_possible = possible_cpu.count();

					if (num_possible >= MAX_PROCESSOR_CORES) {
						GY_THROW_EXCEPTION("Number of processor cores possible is higher than max that can be handled %u", MAX_PROCESSOR_CORES - 1);
					}	
				}	
			}
		}

		{
			strcpy(pbuf, "./devices/system/cpu/isolated");

			SCOPE_FD			scopefd(sysfs_dir_fd, pbuf, O_RDONLY, 0600);

			fd = scopefd.get();
			if (fd >= 0) {
				
				ret = read(fd, pbuf, bufsz - 1);
				if (ret > 0) {
					pbuf[ret] = '\0';

					ret = set_bitset_from_buffer(isolated_cpu, pbuf, ret);
					num_isolated = isolated_cpu.count();
				}	
			}
		}
		{
			strcpy(pbuf, "./devices/system/cpu/nohz_full");

			SCOPE_FD			scopefd(sysfs_dir_fd, pbuf, O_RDONLY, 0600);

			fd = scopefd.get();
			if (fd >= 0) {
				
				ret = read(fd, pbuf, bufsz - 1);
				if (ret > 0) {
					pbuf[ret] = '\0';

					ret = set_bitset_from_buffer(nohz_full_cpu, pbuf, ret);
					num_nohz = nohz_full_cpu.count();
				}	
			}
		}

		gy_detect_virtualization(virtualization_type, sysfs_dir_fd, procfs_dir_fd);

		{
			strcpy(pbuf, "./meminfo");

			SCOPE_FD			scopefd(procfs_dir_fd, pbuf, O_RDONLY, 0600);

			fd = scopefd.get();
			if (fd >= 0) {
				
				ret = read(fd, pbuf, bufsz - 1);
				if (ret <= 0) {
					GY_THROW_SYS_EXCEPTION("Failed to read /proc/meminfo");
				}	
				pbuf[ret] = '\0';

				STR_RD_BUF		memstr(pbuf, ret);

				ptmp = memstr.skip_till_substring_const("MemTotal");
				if (ptmp) {
					memstr.skip_till_next_delim(':');

					ptmp = memstr.get_next_word(tlen);
					if (ptmp) {
						if (string_to_number(ptmp, total_memory)) {
							total_memory <<= 10;
						}	
					}	
				}	

				if (total_memory < 1024) {
					GY_THROW_EXCEPTION("Failed to parse total memory from /proc/meminfo");
				}	
				
				ptmp = memstr.skip_till_substring_const("HardwareCorrupted");
				if (ptmp) {
					memstr.skip_till_next_delim(':');

					ptmp = memstr.get_next_word(tlen);
					if (ptmp) {
						if (string_to_number(ptmp, corrupted_memory)) {
							corrupted_memory <<= 10;
						}	
					}	
				}	
			}	
			else {
				GY_THROW_SYS_EXCEPTION("Could not open /proc/meminfo");
			}
		}	

		get_processor_topology(pbuf, bufsz);
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT("Exception caught while getting the system CPU/Memory configuration : %s\n", GY_GET_EXCEPT_STRING);

		throw;
	);
}	

int CPU_MEM_INFO::check_for_changes() noexcept
{
	using namespace			comm;

	try {
		constexpr size_t		bufsz = 4096;
		int				fd, ret;
		char				pbuf[bufsz], tbuf[128];
		const char 			*ptmp; 
		size_t				tlen, lencopy;
		HOST_CPU_MEM_CHANGE		cpumemchg;

		/*
		 * We check for changes to cpu online and memory online, corrupted
		 */
		{
			CPU_CORES_BITSET		newonline;

			strcpy(pbuf, "./devices/system/cpu/online");

			SCOPE_FD			scopefd(sysfs_dir_fd, pbuf, O_RDONLY, 0600);

			fd = scopefd.get();
			if (fd >= 0) {
				
				ret = read(fd, pbuf, bufsz - 1);
				if (ret <= 0) {
					DEBUGEXECN(1, PERRORPRINT("Failed to read /sys/devices/system/cpu/online for cpu info check"););
					return -1;
				}	
				pbuf[ret] = '\0';

				ret = set_bitset_from_buffer(newonline, pbuf, ret);

				if (newonline != online_cpu) {
					int		oldcount = num_online;
					
					online_cpu = newonline;
					num_online = online_cpu.count();
					
					if (num_online == 0) {
						num_online = 1;
					}

					INFOPRINT("CPU online count changed. New number of cores online = %d. Older number = %d\n",
						num_online, oldcount); 

					cpumemchg.cpu_changed_ 		= true;
					cpumemchg.new_cores_online_	= num_online;
					cpumemchg.old_cores_online_	= oldcount;

					num_cpu_core_changes++;
					last_cpu_change_clock_nsec = get_nsec_clock();
				}	
			}
			else {
				DEBUGEXECN(1, PERRORPRINT("Failed to open /sys/devices/system/cpu/online for cpu info check"););
				return -1;
			}
		}

		if (cpumemchg.cpu_changed_) {

			CPU_CORES_BITSET		newoffline;

			strcpy(pbuf, "./devices/system/cpu/offline");

			SCOPE_FD			scopefd(sysfs_dir_fd, pbuf, O_RDONLY, 0600);

			fd = scopefd.get();
			if (fd >= 0) {
				
				ret = read(fd, pbuf, bufsz - 1);
				if (ret <= 0) {
					DEBUGEXECN(1, PERRORPRINT("Failed to read /sys/devices/system/cpu/offline for cpu info check"););
					return -1;
				}	
				pbuf[ret] = '\0';

				ret = set_bitset_from_buffer(newoffline, pbuf, ret);

				int		oldcount = num_offline;

				offline_cpu = newoffline;
				num_offline = offline_cpu.count();

				cpumemchg.new_cores_offline_	= num_offline;
				cpumemchg.old_cores_offline_	= oldcount;
			}
			else {
				DEBUGEXECN(1, PERRORPRINT("Failed to open /sys/devices/system/cpu/online for cpu info check"););
				return -1;
			}
		}

		{
			strcpy(pbuf, "./meminfo");

			SCOPE_FD			scopefd(procfs_dir_fd, pbuf, O_RDONLY, 0600);

			fd = scopefd.get();
			if (fd >= 0) {
				
				ret = read(fd, pbuf, bufsz - 1);
				if (ret <= 0) {
					DEBUGEXECN(1, PERRORPRINT("Failed to read /proc/meminfo for memory info check"););
					return -1;
				}	
				pbuf[ret] = '\0';

				uint64_t			new_total_memory;
				uint64_t			new_corrupted_memory;

				STR_RD_BUF			memstr(pbuf, ret);

				ptmp = memstr.skip_till_substring_const("MemTotal:");
				if (ptmp) {
					ptmp = memstr.get_next_word(tlen);
					if (ptmp) {
						if (string_to_number(ptmp, new_total_memory)) {
							new_total_memory <<= 10;

							if (new_total_memory != this->total_memory) {
								INFOPRINT("Total memory size changed. New Total memory = %lu (%lu GB). Older number = %lu (%lu GB)\n",
									new_total_memory, GY_DOWN_GB(new_total_memory), total_memory, GY_DOWN_GB(total_memory)); 
	
								if (new_total_memory < 1024) {
									ERRORPRINT("Invalid MemTotal %lu Too low : from /proc/meminfo : Assuming 1024\n", new_total_memory);
									new_total_memory = 1024;
								}	

								cpumemchg.mem_changed_		= true;
								cpumemchg.new_ram_mb_		= GY_DOWN_MB(new_total_memory);
								cpumemchg.old_ram_mb_		= GY_DOWN_MB(total_memory);

								total_memory 			= new_total_memory;

								last_mem_change_clock_nsec 	= get_nsec_clock();
								num_memory_changes++;
							}	
						}	
					}	
				}	

				ptmp = memstr.skip_till_substring_const("HardwareCorrupted:");
				if (ptmp) {
					ptmp = memstr.get_next_word(tlen);
					if (ptmp) {
						if (string_to_number(ptmp, new_corrupted_memory)) {
							new_corrupted_memory <<= 10;

							if (new_corrupted_memory != this->corrupted_memory) {
								INFOPRINT("Corrupted memory size changed. New Corrupted memory = %lu (%lu GB). Older number = %lu (%lu GB)\n",
									new_corrupted_memory, GY_DOWN_GB(new_corrupted_memory), corrupted_memory, GY_DOWN_GB(corrupted_memory)); 
	
								cpumemchg.mem_corrupt_changed_	= true;
								cpumemchg.new_corrupted_ram_mb_	= GY_DOWN_MB(new_corrupted_memory);
								cpumemchg.old_corrupted_ram_mb_	= GY_DOWN_MB(corrupted_memory);

								corrupted_memory 		= new_corrupted_memory;
							}	
						}	
					}	
				}	
			}	
			else {
				DEBUGEXECN(1, PERRORPRINT("Failed to open /proc/meminfo for memory info check"););
				return -1;
			}
		}	

		if (cpumemchg.cpu_changed_ || cpumemchg.mem_changed_ || cpumemchg.mem_corrupt_changed_) {

			auto					pser = SERVER_COMM::get_singleton();
			std::shared_ptr<SERVER_CONNTRACK>	shrp;
			SERVER_CONNTRACK			*pconn1;

			shrp = pser->get_server_conn(comm::CLI_TYPE_REQ_ONLY);
			pconn1 = shrp.get();

			if (!pconn1) {
				return 0;
			}	

			const size_t			max_buf_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + sizeof(HOST_CPU_MEM_CHANGE);

			void				*palloc = ::malloc(max_buf_sz);
			if (!palloc) {
				return -1;
			}	

			COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
			EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1); 
			HOST_CPU_MEM_CHANGE		*pchange = reinterpret_cast<HOST_CPU_MEM_CHANGE *>(pnot + 1);
			bool				bret;

			new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, max_buf_sz, pser->get_conn_magic());
			new (pnot) EVENT_NOTIFY(comm::NOTIFY_HOST_CPU_MEM_CHANGE, 1);	
			new (pchange) HOST_CPU_MEM_CHANGE(cpumemchg);

			bret = pser->send_server_data(EPOLL_IOVEC_ARR(2, false, phdr, phdr->get_act_len(), ::free, pser->gpadbuf, phdr->get_pad_len(), nullptr), 
							comm::CLI_TYPE_REQ_ONLY, COMM_EVENT_NOTIFY, shrp);

			if (bret) {
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Sent CPU Change info to Madhava server\n");
			}	
		}	
	
		return 0;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINT("Exception caught while checking for CPU Memory changes %s\n", GY_GET_EXCEPT_STRING););
		return -1;
	);
}
	

OS_INFO::OS_INFO(bool ignore_min_kern, bool is_mount_namespace, bool is_uts_namespace)
{
	int				ret;
	struct utsname			uts;

	ret = uname(&uts);
	if (ret != 0) {
		GY_THROW_SYS_EXCEPTION("uname syscall failed");
	}	
	
	GY_STRNCPY(kern_version_string, uts.release, sizeof(kern_version_string));

	if ((is_uts_namespace == false) || (is_mount_namespace == true)) {
		GY_STRNCPY(hostname_str, uts.nodename, sizeof(hostname_str));
	}
	else {
		DEBUGEXECN(1, 
			INFOPRINTCOLOR(GY_COLOR_BLUE, "Process is in non root UTS Namespace but in root Mount Namespace. Using /etc/hostname for hostname...\n\n");
		);

		// We need to get the hostname from /etc/hostname
		SCOPE_FD		scopefd("/etc/hostname", O_RDONLY);
		int			fd;

		fd = scopefd.get();
		if (fd == -1) {
			// No option but to copy uts.nodename
			GY_STRNCPY(hostname_str, uts.nodename, sizeof(hostname_str));
		}	
		else {
			ret = read(fd, hostname_str, sizeof(hostname_str) - 1);
			if (ret > 0) {
				if (hostname_str[ret - 1] == '\n') ret--;
				hostname_str[ret] = 0;
			}	
			else {
				GY_STRNCPY(hostname_str, uts.nodename, sizeof(hostname_str));
			}	
		}	
	}	
	
	ret = sscanf(kern_version_string, "%hhu.%hhu.%hhu", &kern_base_version, &kern_abi_num, &kern_upload_num);
	if (ret != 3) {
		GY_THROW_EXCEPTION("uname syscall release string %s parsing failed", kern_version_string);
	}	
		
	kern_version_num = (((uint32_t)kern_base_version << 16) | ((uint32_t)kern_abi_num << 8) | kern_upload_num);	

	if (kern_version_num < MIN_SUPPORTED_KERN_VERSION) {
		char		minstr[64];

		snprintf(minstr, sizeof(minstr), "%u.%u.%u", (MIN_SUPPORTED_KERN_VERSION & 0xFF0000) >> 16, 
			(MIN_SUPPORTED_KERN_VERSION & 0xFF00) >> 8, MIN_SUPPORTED_KERN_VERSION & 0xFF);

		if (ignore_min_kern == false) {
			GY_THROW_EXCEPTION("Kernel version of host %s (0x%06X) is less than minimum needed %s", 
				kern_version_string, kern_version_num, minstr);
		}
			
		ERRORPRINT("Kernel version of host %s (0x%06X) is less than minimum needed %s\n",
			kern_version_string, kern_version_num, minstr);
	}	

	ret = get_host_distribution(distrib, distrib_string, sizeof(distrib_string));
	if (ret < 0) {
		errno = -ret;
		PERRORPRINT("Failed to get OS Distribution from /etc/os-release");

		distrib = DIST_UNKNOWN;
		strcpy(distrib_string, "\"Unknown Distribution\"");
	}
	else if (distrib == DIST_UNKNOWN) {
		INFOPRINT("Unknown OS Distribution : %s : seen\n", distrib_string);
	}	

	std::memcpy(node_hostname_str, hostname_str, sizeof(node_hostname_str));
	std::memcpy(node_distrib_string, distrib_string, sizeof(node_distrib_string));
	node_distrib = distrib;

	DEBUGEXECN(1,
		char			buf1[512];

		INFOPRINTCOLOR(GY_COLOR_GREEN, "%s\n", print_osinfo(buf1, sizeof(buf1) - 1));
	);	
}

int get_host_distribution(OS_DISTRIB_E & distrib, char distrib_string[], size_t szstr) noexcept
{
	char				osbuf[1024];
	ssize_t				szread;
	SCOPE_FD			scopefd("/etc/os-release", O_RDONLY);
	int				fd;
	
	*distrib_string = '\0';

	fd = scopefd.get();
	if (fd < 0) {
		return -errno;
	}	
	else {
		szread = gy_readbuffer(fd, osbuf, sizeof(osbuf) - 1);

		if (gy_unlikely(szread < 0)) {
			return -errno;
		}

		osbuf[szread] = '\0';
		
		STR_RD_BUF			relbuf(osbuf, szread);
		const char			*pdata;
		size_t				lenword, lencopy;

		pdata = relbuf.skip_till_substring_const("PRETTY_NAME=", true);
		if (!pdata) {
			pdata = relbuf.skip_till_substring_const("NAME=", true);
		}	

		if (pdata) {
			pdata = relbuf.get_next_line(lenword);
			if (pdata) {
				if (*pdata == '\"') {
					pdata++;
					lenword--;
				}	
				if (lenword && pdata[lenword - 1] == '\"') {
					lenword--;
				}	
				GY_SAFE_MEMCPY(distrib_string, szstr - 1, pdata, lenword, lencopy);

				distrib_string[lencopy] = '\0';

				if (strstr(distrib_string, "Ubuntu")) {
					distrib = DIST_UBUNTU;
				}
				else if (strstr(distrib_string, "Amazon")) {
					distrib = DIST_AMAZON_AMI;
				}
				else if (strstr(distrib_string, "CentOS")) {
					distrib = DIST_CENTOS;	
				}		
				else if (strstr(distrib_string, "Red Hat Enterprise")) {
					distrib = DIST_RHEL;	
				}
				else if (strstr(distrib_string, "Fedora")) {
					distrib = DIST_FEDORA;	
				}
				else if (strstr(distrib_string, "openSUSE")) {
					distrib = DIST_OPENSUSE;	
				}
				else if (strstr(distrib_string, "SUSE")) {
					distrib = DIST_SLES;	
				}
				else if (strstr(distrib_string, "Debian")) {
					distrib = DIST_DEBIAN;	
				}
				else if (strstr(distrib_string, "CoreOS")) {
					distrib = DIST_COREOS;	
				}
				else if (strstr(distrib_string, "Buildroot")) {
					distrib = DIST_BUILDROOT;	
				}
				else if (strstr(distrib_string, "Container-Optimized OS")) {
					distrib = DIST_CONTAINER_GOOGLE;	
				}
				else if (strstr(distrib_string, "Arch Linux")) {
					distrib = DIST_ARCH_LINUX;	
				}
				else if (strstr(distrib_string, "Gentoo")) {
					distrib = DIST_GENTOO;	
				}
				else if (strstr(distrib_string, "Slackware")) {
					distrib = DIST_SLACKWARE;	
				}
				else if (strstr(distrib_string, "Scientific Linux")) {
					distrib = DIST_SCIENTIFIC_LINUX;	
				}
				else {
					distrib = DIST_UNKNOWN;
				}	
			}
		}
	}

	return 0;
}	
			
void SYS_HARDWARE::print_system_info() noexcept
{
	auto 			pmshr = MOUNT_HDLR::get_singleton();
	char			tbuf[4096];
	
	IRPRINTCOLOR(GY_COLOR_GREEN, "\n\n--------------------------------    Host System Information   ---------------------------------\n\n");

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Host CPU Memory info : %s\n\n", cpumem_info->get_cpu_mem_print_str(tbuf, sizeof(tbuf) - 1));
	
	net_info->print_net_iflink_info();

	if (pmshr) {
		pmshr->print_mount_info(false /* print_all */);
	}			
	
	STR_WR_BUF		strbuf(tbuf, sizeof(tbuf));

	os_info->print_osinfo(strbuf);
	
	strbuf.append('\n');
	
	if (is_pid_namespace) { 
		strbuf.appendconst("Current process is running in a PID Namespace Container\n\n");
	}	

	if (is_net_namespace) { 
		strbuf.appendconst("Current process is running in a Net Namespace Container\n\n");
	}	

	if (is_mount_namespace) { 
		strbuf.appendconst("Current process is running in a Mount Namespace Container\n\n");
	}	

	if (is_uts_namespace) { 
		strbuf.appendconst("Current process is running in a UTS Namespace Container\n\n");
	}	

	machine_id_128.print_string(strbuf);

	IRPRINTCOLOR(GY_COLOR_CYAN, "\n\n");

	INFOPRINTCOLOR(GY_COLOR_CYAN, "%s\n\n", strbuf.buffer());

	IRPRINTCOLOR(GY_COLOR_GREEN, "--------------------------------------------------------------------------------------------------------\n\n");
}

			
static SYS_HARDWARE			*pgsys_hardware = nullptr;

CPU_MEM_INFO * CPU_MEM_INFO::get_singleton() noexcept
{
	if (pgsys_hardware) {
		return pgsys_hardware->cpumem_info.get();
	}	

	return nullptr;
}	

OS_INFO * OS_INFO::get_singleton() noexcept
{
	if (pgsys_hardware) {
		return pgsys_hardware->os_info.get();
	}	

	return nullptr;
}	

NET_IF_HDLR * NET_IF_HDLR::get_singleton() noexcept
{
	if (pgsys_hardware) {
		return pgsys_hardware->net_info.get();
	}	

	return nullptr;
}	

SYS_HARDWARE * SYS_HARDWARE::get_singleton() noexcept
{
	return pgsys_hardware;
}
	
int SYS_HARDWARE::init_singleton(bool ignore_min_kern, bool need_root_priv, bool error_on_no_host_ns)
{
	int				texp = 0, tdes = 1;
	static std::atomic<int>		is_init_done(0);

	if (false == is_init_done.compare_exchange_strong(texp, tdes)) {
		return 0;
	}

	/*
	 * Initialize all singletons we need, if not already done
	 */
	GY_SCHEDULER::init_singletons();

	auto schedshrlong2 = GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_LONG2_DURATION);

	if (!schedshrlong2) {
		GY_THROW_EXCEPTION("Global Scheduler Shared object not yet initialized");
	}	
	 
	MOUNT_HDLR::init_singleton();

	auto pmountshr = MOUNT_HDLR::get_singleton();
	if (!pmountshr) {
		GY_THROW_EXCEPTION("Global Mount Shared object is not yet initialized");
	}	

	try {
		pgsys_hardware = new SYS_HARDWARE(ignore_min_kern, pmountshr->get_sysfs_dir_fd(), pmountshr->get_proc_dir_fd(), error_on_no_host_ns, need_root_priv);

		/*
		 * Schedule a periodic 30 sec check for CPU/Memory changes
		 */
		schedshrlong2->add_schedule(3300, 30'000, 0, "check for new CPU / Memory changes", 
		[] { 
			auto pcpu = CPU_MEM_INFO::get_singleton();
			if (pcpu) {
				pcpu->check_for_changes();
			}	
		});
		
		/*
		 * Schedule a periodic 90 sec check for Interface changes. Keep the interval
		 * less than 150 sec as the function will delete intrefaces not recently updated
		 */
		schedshrlong2->add_schedule(60'120, 90'000, 0, "check for Interface changes", 
		[] { 
			auto pnet = NET_IF_HDLR::get_singleton();
			if (pnet) {
				pnet->check_for_changes();
			}	
		});

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT("Exception caught while creating global CPU / Memory config object ... : %s\n", GY_GET_EXCEPT_STRING);
		throw;
	);	
}	


} // namespace gyeeta	
