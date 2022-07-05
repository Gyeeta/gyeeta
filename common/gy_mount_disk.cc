
#include			"gy_server_int.h"
#include			"gy_mount_disk.h"
#include			"gy_task_stat.h"
#include			"gy_scheduler.h"
#include			"gy_print_offload.h"
#include			"gy_sys_hardware.h"

#include 			<sys/statfs.h>
#include 			<sys/vfs.h>
#include 			<sys/statvfs.h>

namespace gyeeta {

static const MOUNT_STRING_FLAGS 	gmount_option_flags[] = {
		{ "ro",  		GY_MS_RDONLY },
		{ "nosuid", 		GY_MS_NOSUID },
		{ "nodev", 		GY_MS_NODEV },
		{ "noexec", 		GY_MS_NOEXEC },
		{ "noatime", 		GY_MS_NOATIME },
		{ "nodiratime", 	GY_MS_NODIRATIME },
		{ "relatime", 		GY_MS_RELATIME },
		{ "shared", 		GY_MS_SHARED },
		{ "slave", 		GY_MS_SLAVE },
		{ "sync", 		GY_MS_SYNCHRONOUS },
		{ nullptr, 		0 }
};

static const MOUNT_STRING_FLAGS 	gmount_fs_flags[] = {
		{ "ext4",		FS_EXT4 },
		{ "xfs",		FS_XFS },
		{ "btrfs",		FS_BTRFS },
		{ "proc",		FS_PROC },
		{ "sysfs",		FS_SYSFS },
		{ "cgroup",		FS_CGROUP },
		{ "cgroup2",		FS_CGROUP2 },
		{ "tmpfs",		FS_TMPFS },
		{ "debugfs",		FS_DEBUGFS },
		{ "tracefs",		FS_TRACEFS },
		{ "fuse",		FS_FUSE },
		{ "aufs",		FS_AUFS },
		{ "overlay",		FS_OVERLAY },
		{ nullptr, 		0 }
};

/*
 * We currently use options2 only for cgroups...
 */
static const MOUNT_STRING_FLAGS 	gmount_option2_flags[] = {
		{ "cpu",		MTYPE_CPU },
		{ "cpuacct",		MTYPE_CPUACCT },
		{ "cpuset",		MTYPE_CPUSET },
		{ "net_cls",		MTYPE_NET_CLS },
		{ "net_prio",		MTYPE_NET_PRIO },
		{ "blkio",		MTYPE_BLKIO },
		{ "memory",		MTYPE_MEMORY },
		{ "pids",		MTYPE_PIDS },
		{ "rdma",		MTYPE_RDMA },
		{ "hugetlb",		MTYPE_HUGETLB },
		{ "perf_event",		MTYPE_PERFEVENT },
		{ "freezer",		MTYPE_FREEZER },
		{ "devices",		MTYPE_DEVICES },
		{ "systemd",		MTYPE_SYSTEMD },
		{ nullptr, 		0 }
};

bool gy_are_files_same(const char *path1, const char *path2, int flags) noexcept
{
	struct stat 		stat1, stat2;

	if (fstatat(AT_FDCWD, path1, &stat1, flags) < 0) {
		return -1;
	}	

	if (fstatat(AT_FDCWD, path2, &stat2, flags) < 0) {
		return -1;
	}	

	return stat1.st_dev == stat2.st_dev && stat1.st_ino == stat2.st_ino;
}


bool is_fs_networkfs(const char *fstype) noexcept
{
	static constexpr uint32_t 	fshash[] = {
						fnv1_consthash("afs"), fnv1_consthash("cifs"), fnv1_consthash("smbfs"),
						fnv1_consthash("sshfs"), fnv1_consthash("ncpfs"), fnv1_consthash("ncp"),
						fnv1_consthash("nfs"), fnv1_consthash("nfs4"), fnv1_consthash("gfs"),
						fnv1_consthash("gfs2"), fnv1_consthash("glusterfs"), fnv1_consthash("pvfs2") /* OrangeFS */,
						fnv1_consthash("ocfs2"), fnv1_consthash("lustre"), fnv1_consthash("9p"),
						fnv1_consthash("ceph"), fnv1_consthash("hdfs"), fnv1_consthash("ipfs"),
						fnv1_consthash("moosefs")
						};

	uint32_t			rhash = fnv1_hash(fstype, strlen(fstype));							 	

	for (uint32_t i = 0; i < sizeof(fshash)/sizeof(*fshash); i++) {
		if (rhash == fshash[i]) return true;
	}	

	return false;
}	


bool is_fs_clusterfs(const char *fstype) noexcept
{
	static constexpr uint32_t 	fshash[] = {
						fnv1_consthash("gfs"), fnv1_consthash("gfs2"), 
						fnv1_consthash("glusterfs"), fnv1_consthash("pvfs2") /* OrangeFS */,
						fnv1_consthash("ocfs2"), fnv1_consthash("lustre"), fnv1_consthash("vmfs6"),
						fnv1_consthash("ceph"), fnv1_consthash("hdfs"), fnv1_consthash("ipfs"),
						fnv1_consthash("moosefs")
						};

	uint32_t			rhash = fnv1_hash(fstype, strlen(fstype));							 	

	for (uint32_t i = 0; i < sizeof(fshash)/sizeof(*fshash); i++) {
		if (rhash == fshash[i]) return true;
	}	

	return false;
}	


bool is_fs_virtual_api_fs(const char *fstype) noexcept
{
	static constexpr uint32_t 	fshash[] = {
						fnv1_consthash("autofs"), fnv1_consthash("bpf"), fnv1_consthash("cgroup"),
						fnv1_consthash("cgroup2"), fnv1_consthash("configfs"), fnv1_consthash("cpuset"),
						fnv1_consthash("debugfs"), fnv1_consthash("devpts"), fnv1_consthash("devtmpfs"),
						fnv1_consthash("efivarfs"), fnv1_consthash("fusectl"), fnv1_consthash("hugetlbfs"),
						fnv1_consthash("mqueue"), fnv1_consthash("proc"), fnv1_consthash("pstore"),
						fnv1_consthash("ramfs"), fnv1_consthash("securityfs"), fnv1_consthash("sysfs"),
						fnv1_consthash("tmpfs"), fnv1_consthash("tracefs"), fnv1_consthash("binfmt_misc"),
						fnv1_consthash("lxcfs"), fnv1_consthash("nsfs"), fnv1_consthash("selinuxfs"),
						fnv1_consthash("nfsd"), fnv1_consthash("rpc_pipefs"), fnv1_consthash("rootfs"),
						};

	uint32_t			rhash = fnv1_hash(fstype, strlen(fstype));							 	

	for (uint32_t i = 0; i < sizeof(fshash)/sizeof(*fshash); i++) {
		if (rhash == fshash[i]) return true;
	}	

	return false;
}	

bool is_fs_union(const char *fstype) noexcept
{
	static constexpr uint32_t 	fshash[] = {
						fnv1_consthash("aufs"), fnv1_consthash("overlay"), 
						};

	uint32_t			rhash = fnv1_hash(fstype, strlen(fstype));							 	

	for (uint32_t i = 0; i < sizeof(fshash)/sizeof(*fshash); i++) {
		if (rhash == fshash[i]) return true;
	}	

	return false;
}	


bool is_fs_local_fs(const char *fstype) noexcept
{
	static constexpr uint32_t 	fshash[] = {
						fnv1_consthash("btrfs"), fnv1_consthash("ext2"), fnv1_consthash("ext3"),
						fnv1_consthash("ext4"), fnv1_consthash("vfat"), fnv1_consthash("ntfs"), 
						fnv1_consthash("zfs"), fnv1_consthash("reiser4"), fnv1_consthash("squashfs"),
						fnv1_consthash("xfs"), fnv1_consthash("jfs"), fnv1_consthash("jffs2"),
						fnv1_consthash("dax"),
						};

	uint32_t			rhash = fnv1_hash(fstype, strlen(fstype));							 	

	for (uint32_t i = 0; i < sizeof(fshash)/sizeof(*fshash); i++) {
		if (rhash == fshash[i]) return true;
	}	

	return false;
}	

uint32_t get_fs_category(const char *pfstype) noexcept
{
	uint32_t		fscategory = FS_CAT_NONE;

	if (true == is_fs_networkfs(pfstype)) {
		fscategory |= FS_NETWORK_FS;
	}	
	else if (true == is_fs_local_fs(pfstype)) {
		fscategory |= FS_LOCAL;
	}	
	else if (true == is_fs_virtual_api_fs(pfstype)) {
		fscategory |= FS_VIRTUAL_API;
	}	
	else if (true == is_fs_union(pfstype)) {
		fscategory |= FS_UNION;
	}	

	if (true == is_fs_clusterfs(pfstype)) {
		fscategory |= FS_CLUSTERED;
	}	

	return fscategory;
}	

int gy_mount_virtual_fs(const char *fstype, const char *dest_dir, mode_t mode, bool mount_on_existing_dir, bool print_error) noexcept
{
	int			ret, olderrno;
	bool			dir_created;

	ret = mkdir(dest_dir, mode);
	if (ret) {
		if ((errno != EEXIST) || (mount_on_existing_dir == false)) {
			if (print_error) {
				olderrno = errno;
				PERRORPRINT("Failed to create Mount point %s dir for mounting filesystem %s", dest_dir, fstype);
				errno = olderrno;
			}	
			return -1;
		}	
		dir_created = false;
	}
	else {
		dir_created = true;
	}	

	INFOPRINT("Creating a new %s mounted partition on %s path\n", fstype, dest_dir);

	ret = mount(fstype, dest_dir, fstype, MS_MGC_VAL, nullptr);
	if (ret) {
		olderrno = errno;

		if (print_error) {
			PERRORPRINT("Failed to mount %s to destination dir %s", fstype, dest_dir);
		}	

		if (dir_created) {
			rmdir(dest_dir);
		}	

		errno = olderrno;
		return -1;
	}

	return 0;	
}

MOUNT_HDLR::MOUNT_HDLR(bool mount_proc_if_not, bool mount_sys_if_not, bool mount_tracefs_if_not)
	:
	mntid_sysfs(0), mntid_cg_cpu(0), mntid_cg_cpuacct(0), mntid_cg_cpuset(0), mntid_tracefs(0), 
	mntid_cg_net_cls(0), mntid_cg_net_prio(0), mntid_cg_blkio(0), mntid_cg_memory(0),
	proc_dir_fd(-1), sysfs_dir_fd(-1),
	mount_proc_if_not(mount_proc_if_not), mount_sys_if_not(mount_sys_if_not), 
	mount_tracefs_if_not(mount_tracefs_if_not), is_init(false), mount_info_errors(0)
	
{
	SCOPE_FILE		fpscope("/proc/self/mountinfo", "re");
	FILE			*pfp = fpscope.get();
	int			ret, nmounts = 0;
	struct stat		stat1;

	if (gy_unlikely(!pfp)) {
		PERRORPRINT("Failed to open /proc/self/mountinfo");

		if (mount_proc_if_not && (0 != stat("/proc", &stat1))) {
			ret = gy_mount_virtual_fs("proc", "/proc", 0555, true);
			if (ret < 0) {
				GY_THROW_SYS_EXCEPTION("Could not access or mount /proc");
			}	
			else {
				pfp = fopen("/proc/self/mountinfo", "re");
				if (!pfp) {
					GY_THROW_SYS_EXCEPTION("Could not access /proc/self/mountinfo");
				}	

				fpscope.set_file(pfp);
			}
		}
		else {
			GY_THROW_SYS_EXCEPTION("Could not access /proc/self/mountinfo");
		}	
	}

	proc_dir_fd = open("/proc",  O_PATH | O_CLOEXEC);
	if (proc_dir_fd < 0) {
		GY_THROW_SYS_EXCEPTION("Failed to get /proc dir fd");
	}

	nmounts = populate_mount_map_locked(pfp, false);

	if (mntid_sysfs == 0) {
		if (mount_sys_if_not) {
			ret = gy_mount_virtual_fs("sysfs", "/sys", 0555, false /* mount_on_existing_dir */);
			if (ret < 0) {
				GY_THROW_SYS_EXCEPTION("Could not access or mount sysfs at /sys mount point");
			}

			// Add to mount errors so that the periodic mount error checking thread will update the mountmap again
			mount_info_errors.fetch_add_relaxed(1, std::memory_order_relaxed);

			sysfs_dir_fd = open("/sys", O_PATH | O_CLOEXEC);
			if (sysfs_dir_fd < 0) {
				GY_THROW_SYS_EXCEPTION("Failed to get sysfs dir fd");
			}
		}	
	}	
	else {
		auto it = mountmap.find(mntid_sysfs);
		if (it != mountmap.end()) {
			sysfs_dir_fd = open(it->second.pmount_point, O_PATH | O_CLOEXEC);
			if (sysfs_dir_fd < 0) {
				GY_THROW_SYS_EXCEPTION("Failed to get sysfs dir fd");
			}
		}	
		else {
			GY_THROW_EXCEPTION("Failed to get sysfs dir mount point in mount map");
		}	
	}	

	if (mntid_tracefs == 0) {
		if (mount_tracefs_if_not) {
			ret = mount_tracefs();
			if (ret != 0) {
				ERRORPRINT("Failed to mount tracefs mount.\n"); 
			}	
		}	
	}	

	is_init = true;
}		
	
int MOUNT_HDLR::mount_tracefs(void) noexcept
{
	/*
	 * TODO Curently bcc expects tracefs at /sys/kernel/debug/tracing : Need to update this
	 * if code is patched...
	 */
	int		ret;

	// First mount debugfs and then tracefs 
	gy_mount_virtual_fs("debugfs", "/sys/kernel/debug", 0700, true /* mount_on_existing_dir */, false /* print_error */);

	ret = gy_mount_virtual_fs("tracefs", "/sys/kernel/debug/tracing", 0700, true);
	if (ret < 0) {
		PERRORPRINT("Failed to mount tracefs at /sys/kernel/debug/tracing");
		return ret;
	}	

	// Add to mount errors so that the periodic mount error checking thread will update the mountmap again
	mount_info_errors.fetch_add_relaxed(1, std::memory_order_relaxed);

	return 0;
}		

int MOUNT_HDLR::update_mount_info(void) noexcept
{
	if (0 == mount_info_errors.load(std::memory_order_relaxed)) {
		return 0;
	}	

	SCOPE_FILE		fpscope("/proc/self/mountinfo", "re");
	FILE			*pfp = fpscope.get();
	int			ret, nmounts = 0, nnewmounts = 0;
	struct stat		stat1;

	if (gy_unlikely(!pfp)) {
		PERRORPRINT("Failed to open /proc/self/mountinfo");
		return -1;
	}

	try {
		INFOPRINT("Updating Mount info as mount errors or new mounts seen...\n");

		SCOPE_GY_MUTEX			rlock(&mountmutex);

		mountmap.clear();
		nmounts = populate_mount_map_locked(pfp, true);

		if (nmounts > 0) {
			mount_info_errors.store(0, std::memory_order_relaxed);
		}	

		return 0;
	}
	GY_CATCH_EXCEPTION(ERRORPRINT("Failed to load mount map. Will try later... : %s\n\n", GY_GET_EXCEPT_STRING); return -1;);
}	

void MOUNT_HDLR::print_mount_info(bool print_all) noexcept
{
	SCOPE_GY_MUTEX			rlock(&mountmutex);

	IRPRINT("\n\n");

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Current Mount Info : (%lu mounts) : \n\n", mountmap.size());

	try {
		struct statvfs			vfs;
		int				i = 1, ret;
		uint64_t			freespace;

		for (auto && it : mountmap) {
			auto && one = it.second;

			if (one.pmount_point && is_mount_diskspace_valid(one.fscategory) && !one.freespace_init) {

				ret = statvfs(one.pmount_point, &vfs);
				if (ret == 0) {
					freespace = vfs.f_bavail * vfs.f_frsize;

					if (one.freespace_init == 0) {
						one.freespace_init = freespace;
					}	
				}	
			}
				
			if (!print_all) {	
				IRPRINTCOLOR(GY_COLOR_GREEN, "[#%d] : %u:%u Mount at %s : Filesystem %s : Subtype %s : Free Space %lu GB\n",
					i++, one.dev_major_num, one.dev_minor_num, one.pmount_point,  one.fsname, one.fs_subname, GY_DOWN_GB(one.freespace));
			}
			else {
				IRPRINTCOLOR(GY_COLOR_GREEN, "[#%d] : %d:%d %u:%u Mount at %s : Filesystem %s : Subtype %s : "
					"Free Space %lu GB : Mount Options : 0x%08x : fstype 0x%08x : fscategory 0x%08x : mount_options2 0x%08x\n",
					i++, one.mnt_id, one.parent_mnt_id, one.dev_major_num, one.dev_minor_num, one.pmount_point,  
					one.fsname, one.fs_subname, GY_DOWN_GB(one.freespace), one.mount_options, one.fstype, one.fscategory, one.mount_options2);
			}	
		}

		IRPRINT("\n\n");
	}
	GY_CATCH_EXCEPTION(ERRORPRINT("Error while walking the mount map : %s\n", GY_GET_EXCEPT_STRING););
}	

int MOUNT_HDLR::update_mount_freespace(void) noexcept
{
	using namespace			comm;

	struct statvfs			vfs;
	int				ret;
	uint64_t			freespace;
	char				buf[NOTIFICATION_MSG::MAX_NOTIFY_LEN];
	size_t				szbuf;
	NOTIFICATION_MSG_BUF		msgarr[5];
	size_t				nmsg = 0, totlen = 0;

	OS_INFO				*pos = OS_INFO::get_singleton();
	const char			*phostname = pos ? pos->get_node_hostname() : "";

	time_t				tcurr = time(nullptr);

	SCOPE_GY_MUTEX			rlock(&mountmutex);

	try {
		for (auto && it : mountmap) {
			auto && one = it.second;

			if (one.pmount_point && is_mount_diskspace_valid(one.fscategory)) {
				bool			is_warn = false;

				freespace = 0;

				ret = statvfs(one.pmount_point, &vfs);
				if (ret == 0) {
					freespace = vfs.f_bavail * vfs.f_frsize;

					if (one.freespace_init == 0) {
						one.freespace_init = freespace;
					}	
				}	
				
				if (freespace > GY_UP_MB(500) && (freespace < (one.freespace >> 1))) { 
					is_warn = true;

					szbuf = GY_SAFE_SNPRINTF(buf, sizeof(buf), "Host %s : Mount point %s free disk space reduced by over 50%% in last few minutes : "
						"Current Free Space %lu GB : Previous Free Space %lu GB : Initial Free Space %lu", 
						phostname, one.pmount_point, GY_DOWN_GB(freespace), GY_DOWN_GB(one.freespace), GY_DOWN_GB(one.freespace_init));

					WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "%s\n", buf);
				}	
				else if (freespace < GY_UP_MB(100) && one.last_warn_tusec_ < tcurr - 24 * 3600 && one.freespace_init > freespace * 2 && one.freespace > freespace) {

					one.last_warn_tusec_ 	= tcurr;
					is_warn 		= true;
		
					szbuf = GY_SAFE_SNPRINTF(buf, sizeof(buf), "Host %s : Mount point %s free disk space is too low : "
						"Current Free Space %lu MB : Previous Free Space %lu MB : Initial Free Space %lu MB\n", 
						phostname, one.pmount_point, GY_DOWN_MB(freespace), GY_DOWN_MB(one.freespace), GY_DOWN_MB(one.freespace_init));

					WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "%s\n", buf);
				}	

				if (is_warn && (nmsg < GY_ARRAY_SIZE(msgarr))) {
					auto			pmsg = msgarr + nmsg++;
					NOTIFICATION_MSG	*pnot = (NOTIFICATION_MSG *)pmsg;

					new (pnot) NOTIFICATION_MSG(NOTIFY_WARN, szbuf + 1);
					pmsg->setbuf(buf, szbuf);

					totlen += pmsg->get_elem_size() - sizeof(NOTIFICATION_MSG);
				}

				one.freespace = freespace;
			}	
		}

		if (nmsg > 0) {
			auto					pser = SERVER_COMM::get_singleton();
			std::shared_ptr<SERVER_CONNTRACK>	shrp;
			SERVER_CONNTRACK			*pconn1;

			shrp = pser->get_server_conn(comm::CLI_TYPE_REQ_ONLY);
			pconn1 = shrp.get();

			if (!pconn1) {
				return 0;
			}	

			const size_t			max_buf_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + nmsg * sizeof(NOTIFICATION_MSG) + totlen;

			void				*palloc = ::malloc(max_buf_sz);
			if (!palloc) {
				return 0;
			}	

			COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
			EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1); 
			NOTIFICATION_MSG		*pone = reinterpret_cast<NOTIFICATION_MSG *>(pnot + 1);
			bool				bret;

			new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, max_buf_sz, pser->get_conn_magic());
			new (pnot) EVENT_NOTIFY(comm::NOTIFY_NOTIFICATION_MSG, nmsg);	

			for (size_t i = 0; i < nmsg; ++i, pone = (decltype(pone)((uint8_t *)pone + pone->get_elem_size()))) {
				auto			pmsg = msgarr + i;

				new (pone) NOTIFICATION_MSG((const NOTIFICATION_MSG &)(*pmsg));

				std::memcpy((void *)(pone + 1), pmsg->get(), pmsg->msglen_);
			}	

			bret = pser->send_server_data(EPOLL_IOVEC_ARR(2, false, phdr, phdr->get_act_len(), ::free, pser->gpadbuf, phdr->get_pad_len(), nullptr), 
							comm::CLI_TYPE_REQ_ONLY, COMM_EVENT_NOTIFY, shrp);

			if (bret) {
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Sent %lu warning notifications to Madhava server\n", nmsg);
			}	
		}

		return 0;
	}
	GY_CATCH_EXCEPTION(ERRORPRINT("Error while updating the mount map freespace : %s\n", GY_GET_EXCEPT_STRING); return -1;);
}	


uint32_t MOUNT_HDLR::populate_mount_map_locked(FILE *pfp, bool is_update)
{
	uint32_t			nmounts = 0;
	struct statvfs			vfs;
	int				ret;

	while (true) {
		char			*pmount_point = nullptr, *pmount_options = nullptr, *pfstype = nullptr, 
					*pmount_source = nullptr, *pmount_other_options = nullptr, pfs_subname[MAX_FS_NAME_LEN];
		int			mnt_id = 0, parent_mnt_id = 0, mount_options = 0;
		uint32_t		dev_major_num = 0, dev_minor_num = 0;
		uint32_t		fstype = FS_NONE;
		uint32_t		fscategory = FS_CAT_NONE;
		uint32_t 		mount_options2 = MTYPE_NONE;
		uint64_t		freespace = 0;
		int			n; 

		*pfs_subname = '\0';

		GY_SCOPE_EXIT {
			if (pmount_point) 		free(pmount_point);
			if (pmount_options) 		free(pmount_options);
			if (pfstype) 			free(pfstype);
			if (pmount_source) 		free(pmount_source);
			if (pmount_other_options) 	free(pmount_other_options);
		};

		n = fscanf(pfp,
				"%d "       	/* (1) mount id */
				"%d "       	/* (2) parent id */
				"%u:%u "    	/* (3) major:minor */
				"%*s "       	/* (4) root */
				"%ms "       	/* (5) mount point */
				"%ms"        	/* (6) mount options */
				"%*[^-]"     	/* (7) optional fields */
				"- "         	/* (8) separator */
				"%ms "       	/* (9) file system type */
				"%ms"        	/* (10) mount source */
				"%ms"        	/* (11) mount options 2 */
				"%*[^\n]",   	/* Ignore stuff */
				&mnt_id, &parent_mnt_id, &dev_major_num, &dev_minor_num, 
				&pmount_point, &pmount_options, &pfstype, &pmount_source, &pmount_other_options);

		if ((n < 7) || (!pmount_point)) {
			if (n == EOF) break;
			continue;
		}

		nmounts++;

		// Parse pmount_options
		if (pmount_options) {
			for (int i = 0; gmount_option_flags[i].pstr != nullptr; i++) {
				if (true == is_whole_word_in_str(pmount_options, gmount_option_flags[i].pstr)) {
					mount_options |= gmount_option_flags[i].flag;
				}	
			}
		}	

		if (pfstype) {
			char		*ptmp;

			ptmp = strchr(pfstype, '.');
			if (ptmp) {
				GY_STRNCPY(pfs_subname, ptmp + 1, sizeof(pfs_subname));
				*ptmp = '\0';
			}	

			// Now parse pfstype && fscategory
			for (int i = 0; gmount_fs_flags[i].pstr != nullptr; i++) {
				if (true == is_whole_word_in_str(pfstype, gmount_fs_flags[i].pstr)) {
					fstype = gmount_fs_flags[i].flag;
					break;
				}	
			}

			fscategory = get_fs_category(pfstype);

			if (*pfs_subname) {
				fscategory |= get_fs_category(pfs_subname);
			}	

			if (pmount_options) {
				/*
				 * Handle mount option _netdev separately
				 */
				if (true == is_whole_word_in_str(pmount_options, "_netdev")) {
					fscategory |= FS_NETWORK_FS;
				}	
			}	
		}

		/*
		 * Currently we do not parse pmount_source
		 */

		if (pmount_other_options) {
			// Parse for cgroup type 
			if (fstype & FS_CGROUP) {

				for (int i = 0; gmount_option2_flags[i].pstr != nullptr; i++) {
					if (true == is_whole_word_in_str(pmount_other_options, gmount_option2_flags[i].pstr)) {
						mount_options2 |= gmount_option2_flags[i].flag;
					}	
				}
			}	
		}	

		if (fstype & FS_SYSFS) {
			mntid_sysfs = mnt_id;
		}	
		else if (fstype & FS_CGROUP) {
			if (mount_options2 & MTYPE_CPU) {
				mntid_cg_cpu = mnt_id;
			}	
			if (mount_options2 & MTYPE_CPUACCT) {
				mntid_cg_cpuacct = mnt_id;
			}	
			if (mount_options2 & MTYPE_CPUSET) {
				mntid_cg_cpuset = mnt_id;
			}	
			if (mount_options2 & MTYPE_NET_CLS) {
				mntid_cg_net_cls = mnt_id;
			}	
			if (mount_options2 & MTYPE_NET_PRIO) {
				mntid_cg_net_prio = mnt_id;
			}	
			if (mount_options2 & MTYPE_BLKIO) {
				mntid_cg_blkio = mnt_id;
			}	
			if (mount_options2 & MTYPE_MEMORY) {
				mntid_cg_memory = mnt_id;
			}	
		}	
		else if (fstype & FS_TRACEFS) {
			mntid_tracefs = mnt_id;
		}	

		if (is_mount_diskspace_valid(fscategory)) {
			ret = statvfs(pmount_point, &vfs);
			if (ret == 0) {
				freespace = vfs.f_bavail * vfs.f_frsize;
			}	
		}

		auto mret = mountmap.emplace(std::piecewise_construct, std::forward_as_tuple(mnt_id), 
			std::forward_as_tuple(mnt_id, parent_mnt_id, dev_major_num, dev_minor_num, pmount_point, mount_options, 
						pfstype, pfs_subname, fstype, fscategory, mount_options2, freespace));
		
		if (mret.second == true) {
			pmount_point = nullptr;
		}	
		else {
			ERRORPRINT("Failed to insert mountid %d for %s mount point into mount map...\n", mnt_id, pmount_point);
		}	

	} // while (true)

	return nmounts;
}	

static std::shared_ptr<MOUNT_HDLR>		gmount_shr_, *pgmount_shr_;

std::shared_ptr<MOUNT_HDLR> MOUNT_HDLR::get_singleton() noexcept
{
	return gmount_shr_;
}	

int MOUNT_HDLR::init_singleton(bool mount_proc_if_not, bool mount_sys_if_not, bool mount_tracefs_if_not)
{
	int				texp = 0, tdes = 1;
	static std::atomic<int>		is_init_done(0);

	if (false == is_init_done.compare_exchange_strong(texp, tdes)) {
		return 0;
	}

	try {
		gmount_shr_.reset(new MOUNT_HDLR(mount_proc_if_not, mount_sys_if_not, mount_tracefs_if_not), [](MOUNT_HDLR *) {});

		pgmount_shr_ = new std::decay_t<decltype(*pgmount_shr_)>(gmount_shr_);

		int		ret;

		PRINT_OFFLOAD::init_singleton();

		GY_SCHEDULER::init_singletons();

		/*
		 * Schedule a periodic 5 sec mount change check
		 */
		auto schedshr = GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_LONG_DURATION);
		if (schedshr) {
			schedshr->add_schedule(100, 5000, 0, "update mountinfo mounts", 
			[] { 
				auto mountshr = MOUNT_HDLR::get_singleton();
				if (mountshr) {
					mountshr->update_mount_info();
				}	
			});


			/*
			 * Schedule a periodic 2 min mount disk space check
			 */
			schedshr->add_schedule(120'700, 120'000, 0, "update mountinfo mount disk freespace", 
			[] { 
				auto mountshr = MOUNT_HDLR::get_singleton();
				if (mountshr) {
					mountshr->update_mount_freespace();
				}	
			});
		}

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT("Exception caught while creating global mount info object ... : %s\n", GY_GET_EXCEPT_STRING);
		throw;
	);	
}	

} // namespace gyeeta
