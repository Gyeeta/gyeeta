//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

/*
 * System Hardware configuration stuff
 */
 
#pragma					once

#include				"gy_common_inc.h"
#include				"gy_file_api.h"
#include				"gy_misc.h"
#include				"gy_netif.h"

namespace gyeeta {


int get_host_id(int sysfs_dir_fd_in, char *pbuffer, size_t maxsz) noexcept;

class GY_MACHINE_ID
{
public :	
	std::pair<uint64_t, uint64_t> 		machid_		{};

	static constexpr size_t			MACHID_STRLEN	{32};

	GY_MACHINE_ID() noexcept 		= default;

	GY_MACHINE_ID(std::pair<uint64_t, uint64_t> machid) noexcept
		: machid_(machid)
	{}

	GY_MACHINE_ID(uint64_t hi, uint64_t lo) noexcept
		: machid_(hi, lo)
	{}

	GY_MACHINE_ID(const char *machid_str, size_t szstr = 0)
	{
		set_from_string(machid_str, szstr ? szstr : strlen(machid_str));
	}	

	~GY_MACHINE_ID() noexcept		= default;

	GY_MACHINE_ID(const GY_MACHINE_ID & other) noexcept
		: machid_(other.machid_)
	{}	
	
	GY_MACHINE_ID(GY_MACHINE_ID && other) noexcept
		: machid_(other.machid_)
	{}	
	
	GY_MACHINE_ID & operator=(const GY_MACHINE_ID & other) noexcept
	{
		machid_ = other.machid_;
		return *this;
	}	

	GY_MACHINE_ID & operator=(GY_MACHINE_ID && other) noexcept
	{
		machid_ = other.machid_;
		return *this;
	}	

	void set_machineid(std::pair<uint64_t, uint64_t> mach) noexcept
	{
		machid_ = mach;
	}	

	uint64_t get_first() const noexcept
	{
		return machid_.first;
	}

	uint64_t get_second() const noexcept
	{
		return machid_.second;
	}

	uint32_t get_hash() const noexcept
	{
		return jhash2((uint32_t *)(&machid_), sizeof(machid_)/sizeof(uint32_t), 0xceedfead);
	}

	class MAC_HASH 
	{
	public :
		size_t operator()(GY_MACHINE_ID k) const noexcept
		{
			return k.get_hash();
		}
	};

	bool operator==(const GY_MACHINE_ID other) const noexcept
	{
		return ((machid_.first == other.machid_.first) && (machid_.second == other.machid_.second));
	}

	bool operator!=(const GY_MACHINE_ID other) const noexcept
	{
		return machid_ != other.machid_;
	}

	void populate_machineid(int sysfs_dir_fd = -1) 
	{
		constexpr size_t	MACHINE_ID_LEN = 32 * 2;

		int			ret;
		char			machine_id_str[MACHINE_ID_LEN]	{};

		ret = get_host_id(sysfs_dir_fd, machine_id_str, sizeof(machine_id_str));
		if (ret != 0) {
			GY_THROW_EXCEPTION("Could not get machine ID from DMI info");
		}	

		set_from_string(machine_id_str, strlen(machine_id_str));

		INFOPRINT("Current Host %s\n", print_string(STRING_BUFFER<128>().get_str_buf()));
	}

	bool set_from_string(const char * machine_id_str, size_t szstr, bool throw_on_error = true)
	{
		bool			bret;
		char			tstr[33], c;
		uint64_t		tnumhi, tnumlo;

		if (szstr < 17 || szstr > 32) {
			if (false == throw_on_error) {
				return false;
			}	
			GY_THROW_EXCEPTION("Machine ID Length invalid %lu : Invalid ID", szstr);
		}

		std::memcpy(tstr, machine_id_str, szstr);
		tstr[szstr] = 0;

		c = std::exchange(tstr[16], 0);

		bret = string_to_number(tstr, tnumhi, nullptr, 16);
		if (!bret) {
			if (false == throw_on_error) {
				return false;
			}	
			GY_THROW_SYS_EXCEPTION("Invalid Machineid (1) %s", machine_id_str);
		}	

		tstr[16] = c;

		bret = string_to_number(tstr + 16, tnumlo, nullptr, 16);
		if (!bret) {
			if (false == throw_on_error) {
				return false;
			}	
			GY_THROW_SYS_EXCEPTION("Invalid Machineid (2) %s", machine_id_str);
		}	

		set_machineid({tnumhi, tnumlo});

		return true;
	}	

	CHAR_BUF<MACHID_STRLEN + 1> get_string() const noexcept
	{
		return gy_to_charbuf<MACHID_STRLEN + 1>("%016lx%016lx", machid_.first, machid_.second);
	}	

	char * print_string(STR_WR_BUF & strbuf) const noexcept
	{
		if (machid_.first || machid_.second) {
			strbuf.appendfmt("MachineID %016lx%016lx ", machid_.first, machid_.second);
		}
		return strbuf.buffer();
	}
};

class NUMA_NODE_ONE
{
public :	
	int				nodenum {0};
	CPU_CORES_BITSET		cpuset;
	int				ncpu {0};
	uint64_t			memtotal {0};

	int				num_numa_nodes {0};
	int				*pnode_distance_hops {nullptr};

	~NUMA_NODE_ONE() noexcept
	{
		if (pnode_distance_hops) {
			free(pnode_distance_hops);
			pnode_distance_hops = nullptr;
		}	
	}		
};	

enum VIRT_TYPE_E 
{
	VIRT_TYPE_NONE			= 0,

	VIRT_TYPE_KVM,
	VIRT_TYPE_QEMU,
	VIRT_TYPE_BOCHS,
	VIRT_TYPE_XEN,
	VIRT_TYPE_UML,
	VIRT_TYPE_VMWARE,
	VIRT_TYPE_ORACLE,		// VirtualBox
	VIRT_TYPE_MICROSOFT,
	VIRT_TYPE_ZVM,
	VIRT_TYPE_QNX,
	VIRT_TYPE_PARALLELS,
	VIRT_TYPE_BHYVE,		// https://wiki.freebsd.org/bhyve 
	VIRT_TYPE_HYPER_WSL,		// Windows WSL
	VIRT_TYPE_ACRN,	

	VIRT_TYPE_OTHER			// Keep this last
};

static const char *		get_virtualization_type(VIRT_TYPE_E v)
{
	static constexpr const char * 	virtnametable[] = { 
			"No virtualization", "KVM", "QEMU", "Bochs", "Xen", "User Mode Linux", "VmWare", "Oracle VirtualBox",
			"Microsoft HyperV", "z/VM", "QNX", "Parellels", "FreeBSD Bhyve", "Microsoft Windows WSL", "ACRN",
			"Unknown type"
	};

	if (gy_unlikely(v >= VIRT_TYPE_OTHER)) {
		return virtnametable[VIRT_TYPE_OTHER];
	}
		
	return virtnametable[v];	
}	


class CPU_MEM_INFO
{
public :	
	int				num_online = 0;
	int				num_offline = 0;
	int				num_possible = 0;
	int				num_isolated = 0;
	int				num_nohz = 0;

	CPU_CORES_BITSET		online_cpu;
	CPU_CORES_BITSET		offline_cpu;
	CPU_CORES_BITSET		possible_cpu;
	CPU_CORES_BITSET		isolated_cpu;
	CPU_CORES_BITSET		nohz_full_cpu;

	uint64_t			total_memory = 0;
	uint64_t			corrupted_memory = 0;

	NUMA_NODE_ONE			*pnodelist = nullptr;
	int				num_numa_nodes = 0;

	int				cores_per_socket = 0;
	int				threads_per_core = 0;				// Hyperthreading
	std::vector<CPU_CORES_BITSET>	thread_siblings_list;		

	uint32_t			level1_dcache_sz = 0;
	uint32_t			level1_icache_sz = 0;
	uint32_t			level2_cache_sz = 0;
	uint32_t			level3_cache_sz = 0;
	uint32_t			level4_cache_sz = 0;

	char				cpu_model_name[128] {};
	char				cpu_vendor_name[64] {};

	char				*pcpu_flags = nullptr;
	char				*pcpu_bugs = nullptr;

	char				current_clocksource[64] {};

	VIRT_TYPE_E			virtualization_type = VIRT_TYPE_NONE;

	uint64_t			last_cpu_change_clock_nsec = 0;	
	uint64_t			last_mem_change_clock_nsec = 0;	

	int				num_cpu_core_changes = 0;
	int				num_memory_changes = 0;

	int				sysfs_dir_fd = -1;
	int				procfs_dir_fd = -1;

	bool				is_hetero_cpu_config		{false};	// XXX  TODO : e.g. Big.Little

	CPU_MEM_INFO(int sysfs_dir_fd_in, int procfs_dir_fd_in);

	~CPU_MEM_INFO() noexcept
	{
		if (pcpu_flags)	{
			delete [] pcpu_flags;
			pcpu_flags = nullptr;
		}

		if (pcpu_bugs) {
			delete [] pcpu_bugs;
			pcpu_bugs = nullptr;
		}

		if (pnodelist) {
			delete [] pnodelist;
			pnodelist = nullptr;
		}
	}

	bool				is_virtual_cpu() const noexcept
	{
		return (virtualization_type > VIRT_TYPE_NONE);
	}

	char *				get_cpu_mem_print_str(char *pbuf, size_t maxsz) noexcept;

	uint32_t			get_number_of_cores() const noexcept
	{
		return GY_READ_ONCE(num_online);
	}
	
	uint32_t			get_max_possible_cores() const noexcept
	{
		return num_possible;
	}

	uint32_t			get_numa_node_count() const noexcept
	{
		return GY_READ_ONCE(num_numa_nodes);
	}
	
	uint64_t			get_total_memory() const noexcept
	{
		return GY_READ_ONCE(total_memory);
	}		

	bool				is_cpu_hyperthreaded() const noexcept
	{
		return threads_per_core > 1;
	}	

	/*
	 *  Populate the CPU thread siblings core number for a specific cpu core
	 *  Returns number of siblings populated or 0 in case no hyperthreading 
	 */
	int				get_cpu_thread_siblings(int core_num, int *psiblings, size_t maxsiblings) noexcept
	{
		size_t			nupd = 0;

		assert(psiblings);

		if ((false == is_cpu_hyperthreaded()) || (core_num >= MAX_PROCESSOR_CORES)) {
			return 0;
		}	

		auto && bset = thread_siblings_list[core_num];

		for (size_t i = 0; i < bset.size() && nupd < maxsiblings; ++i) {
			if ((int)i != core_num && (bset[i] != false)) {
				psiblings[nupd++] = i;
			}	
		}	

		return nupd;
	}	

	const char *			get_cpu_flags() const noexcept
	{
		return (pcpu_flags ? pcpu_flags : "");
	}
		
	const char *			get_cpu_bugs() const noexcept
	{
		return (pcpu_bugs ? pcpu_bugs : "");
	}

	uint64_t			get_cpu_change_clock_nsec() const noexcept
	{
		return last_cpu_change_clock_nsec;
	}
		
	uint64_t			get_memory_change_clock_nsec() const noexcept
	{
		return last_mem_change_clock_nsec;
	}

	int				check_for_changes() noexcept;

	static CPU_MEM_INFO *		get_singleton() noexcept;

private :

	int				get_processor_topology(char *pbuf, const size_t bufsz);
	
};	

enum OS_DISTRIB_E : int
{
	DIST_DUMMY_START		= 0,

	DIST_UBUNTU			= 1,
	DIST_AMAZON_AMI			= 2,			
	DIST_CENTOS			= 3,
	DIST_RHEL			= 4,
	DIST_FEDORA			= 5,
	DIST_OPENSUSE			= 6,
	DIST_SLES			= 7,
	DIST_DEBIAN			= 8,
	DIST_COREOS			= 9,
	DIST_BUILDROOT			= 10,			// For minikube		
	DIST_CONTAINER_GOOGLE		= 11,
	DIST_ARCH_LINUX			= 12,
	DIST_GENTOO			= 13,
	DIST_SLACKWARE			= 14,
	DIST_SCIENTIFIC_LINUX		= 15,
	DIST_ORACLE_LINUX		= 16,
	DIST_ROCKY_LINUX		= 17,

	DIST_UNKNOWN			= 100,

	DIST_DUMMY_END			= ~0
};	

class OS_INFO
{
public :	
	char				kern_version_string[64]		{};
	char				hostname_str[256]		{};
	char				distrib_string[256]		{};
	char				node_hostname_str[256]		{};	// The node based stuff is applicable if this proc is being run from a non-root Mount namespace
	char				node_distrib_string[256]	{};

	uint32_t			kern_version_num		= 0;	// e.g. for 4.15.0-32-generic returns 0x040F00
	uint8_t				kern_base_version		= 0;	// e.g. for 4.15.0-32-generic returns 4 
	uint8_t				kern_abi_num			= 0;	// e.g. for 4.15.0-32-generic returns 15
	uint8_t				kern_upload_num			= 0;	// e.g. for 4.15.0-32-generic returns 0	

	OS_DISTRIB_E			distrib				= DIST_DUMMY_START;
	OS_DISTRIB_E			node_distrib			= DIST_DUMMY_START;

	static constexpr uint32_t	MIN_SUPPORTED_KERN_VERSION = 0x040400;		// Minimum supported is 4.4.0

	OS_INFO(bool ignore_min_kern = false, bool is_mount_namespace = false, bool is_uts_namespace = false);

	char *				print_osinfo(char *pbuf, size_t szbuf) const noexcept
	{
		if (!pbuf) {
			return nullptr;
		}

		STR_WR_BUF		strbuf(pbuf, szbuf);

		return print_osinfo(strbuf);
	}	

	char *				print_osinfo(STR_WR_BUF & strbuf) const noexcept
	{
		strbuf.appendfmt("OS Info : Kernel Version %s (0x%06X) : Mount based Hostname %s : Distribution %s (%u) ", 
			kern_version_string, kern_version_num, hostname_str, distrib_string, distrib);

		if (*node_hostname_str && strcmp(node_hostname_str, hostname_str)) {
			strbuf.appendfmt("Node Hostname %s ", node_hostname_str);
		}	

		if (*node_distrib_string && strcmp(node_distrib_string, distrib_string)) {
			strbuf.appendfmt(": Node Distribution %s (%u) ", node_distrib_string, node_distrib);
		}

		strbuf.append('\n');

		return strbuf.buffer();
	}

	uint32_t			get_kernel_version() const noexcept
	{
		return kern_version_num;
	}
		
	const char *			get_kernel_version_str() const noexcept
	{
		return kern_version_string;
	}
		
	const char *			get_node_distribution_str() const noexcept
	{
		return node_distrib_string;
	}

	const char *			get_node_hostname() const noexcept
	{
		return node_hostname_str;
	}

	static OS_INFO *		get_singleton() noexcept;
};	

class CHILD_PROC;

int gy_detect_virtualization(VIRT_TYPE_E & type, int sysfs_dir_fd, int procfs_dir_fd) noexcept;
int detect_container(bool & is_pid_namespace, bool & is_net_namespace, bool & is_mount_namespace, bool & is_uts_namespace, bool & is_cgroup_namespace) noexcept;
int get_host_distribution(OS_DISTRIB_E & distrib, char distrib_string[], size_t szstr) noexcept;
int get_root_mount_ns_info(OS_INFO *posinfo, CHILD_PROC *pcmd_child, bool is_uts_namespace = true) noexcept;

class SYS_HARDWARE
{
public :	
	std::unique_ptr <CPU_MEM_INFO>		cpumem_info;
	std::unique_ptr <OS_INFO>		os_info;
	std::unique_ptr <NET_IF_HDLR>		net_info;

	static TASK_NS_INODES			rootns_inodes;
	
	GY_MACHINE_ID				machine_id_128;

	int					sysfs_dir_fd		{-1};
	int					procfs_dir_fd		{-1};

	bool					close_sysfs_fd		{false};
	bool					close_procfs_fd		{false};
	bool					is_pid_namespace	{false};
	bool					is_net_namespace	{false};
	bool					is_mount_namespace	{false};
	bool					is_uts_namespace	{false};
	bool					is_cgroup_namespace	{false};

	SYS_HARDWARE(bool ignore_min_kern = false, int sysfs_dir_fd_in = -1, int procfs_dir_fd_in = -1, bool error_on_no_host_ns = true, bool need_root_priv = false)
		: sysfs_dir_fd(sysfs_dir_fd_in), procfs_dir_fd(procfs_dir_fd_in), close_sysfs_fd(false), close_procfs_fd(false)
	{
		int			ret;
		bool			is_perm_issue = false;
		
		if (procfs_dir_fd_in == -1) {
			procfs_dir_fd_in = open("/proc", O_PATH | O_CLOEXEC);

			if (procfs_dir_fd_in == -1) {
				GY_THROW_SYS_EXCEPTION("Could not open /proc dir");
			}	

			procfs_dir_fd = procfs_dir_fd_in;
			close_procfs_fd = true;	
		}	

		if (sysfs_dir_fd_in == -1) {
			sysfs_dir_fd_in = open("/sys", O_PATH | O_CLOEXEC);

			if (sysfs_dir_fd_in == -1) {
				GY_THROW_SYS_EXCEPTION("Could not open /sys sysfs dir");
			}	

			sysfs_dir_fd = sysfs_dir_fd_in;
			close_sysfs_fd = true;	
		}	

		if (false == rootns_inodes.is_initialized()) {	
			ret = rootns_inodes.populate_ns_inodes(procfs_dir_fd_in, 1, &rootns_inodes);
			if (ret != 0) {
				if (need_root_priv) {
					GY_THROW_SYS_EXCEPTION("Could not get Namespace inodes for init process");
				}
				else {
					is_perm_issue = true;
					WARNPRINT("Could not get Namespace inodes for init process : System info may be incorrect : %s\n", ::strerror(errno));	
				}		
			}	
		}

		if (is_perm_issue == false) {
			ret = detect_container(is_pid_namespace, is_net_namespace, is_mount_namespace, is_uts_namespace, is_cgroup_namespace);

			if ((ret == 0) && (is_pid_namespace || is_net_namespace || is_cgroup_namespace)) {
				if (error_on_no_host_ns) {
					GY_THROW_EXCEPTION("This process seems to be running under a non Host PID/Net/Cgroup Namespace Container. Please run from the Host Namespace");
				}	

				INFOPRINT("We seem to be running under a container with non Host PID/Net/cgroup Namespace. This is errorprone...\n");
			}	
		}

		cpumem_info 	= std::make_unique <CPU_MEM_INFO> (sysfs_dir_fd, procfs_dir_fd);
		os_info	 	= std::make_unique <OS_INFO> (ignore_min_kern, is_mount_namespace, is_uts_namespace);
		net_info 	= std::make_unique <NET_IF_HDLR> (procfs_dir_fd, sysfs_dir_fd, rootns_inodes.get_ns_inode(NS_TYPE_NET), true /* is_root_ns */);

		if (is_perm_issue == false && need_root_priv) {
			machine_id_128.populate_machineid(sysfs_dir_fd);
		}
	}

	~SYS_HARDWARE() noexcept
	{
		if (close_sysfs_fd && sysfs_dir_fd > 0) close(sysfs_dir_fd);
		if (close_procfs_fd && procfs_dir_fd > 0) close(procfs_dir_fd);
	}	

	void				get_machine_id_num(uint64_t & id_hi, uint64_t & id_lo) const noexcept
	{
		id_hi = machine_id_128.machid_.first;
		id_lo = machine_id_128.machid_.second;
	}

	uint32_t			get_machine_id_hash() const noexcept
	{
		return machine_id_128.get_hash();
	}	

	GY_MACHINE_ID 			get_machineid() noexcept
	{
		return machine_id_128;
	}

	bool 				is_pid_ns_container() const noexcept
	{
		return is_pid_namespace;
	}

	bool 				is_net_ns_container() const noexcept
	{
		return is_net_namespace;
	}

	bool 				is_mount_ns_container() const noexcept
	{
		return is_mount_namespace;
	}

	bool 				is_uts_ns_container() const noexcept
	{
		return is_uts_namespace;
	}

	bool 				is_cgroup_ns_container() const noexcept
	{
		return is_cgroup_namespace;
	}

	// Only valid for partha : Defined in sys_hardware_partha.cc
	bool send_host_info() const noexcept;

	static const TASK_NS_INODES * get_root_ns_inodes() noexcept
	{
		return &rootns_inodes;
	}	
		
	void print_system_info() noexcept;
			
	static int			init_singleton(bool ignore_min_kern = false, bool need_root_priv = false, bool error_on_no_host_ns = true);

	static SYS_HARDWARE *		get_singleton() noexcept;
};	

} // namespace gyeeta	

