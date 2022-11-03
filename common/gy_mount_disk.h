//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

/*
 * Mounts related stuff
 */ 

#pragma				once

#include 			"gy_common_inc.h"
#include 			"gy_rcu_inc.h"

#include			<unordered_map>
#include			<vector>
#include 			<sys/mount.h>

namespace gyeeta {

/*
 * Mount Flags : Copied from 4.17 Kernel sources
 * These are the fs-independent mount-flags: up to 32 flags are supported
 */
#define 	GY_MS_RDONLY		1	/* Mount read-only */
#define 	GY_MS_NOSUID	 	2	/* Ignore suid and sgid bits */
#define 	GY_MS_NODEV	 	4	/* Disallow access to device special files */
#define 	GY_MS_NOEXEC	 	8	/* Disallow program execution */
#define 	GY_MS_SYNCHRONOUS	16	/* Writes are synced at once */
#define 	GY_MS_REMOUNT		32	/* Alter flags of a mounted FS */
#define 	GY_MS_MANDLOCK		64	/* Allow mandatory locks on an FS */
#define 	GY_MS_DIRSYNC		128	/* Directory modifications are synchronous */
#define 	GY_MS_NOATIME		1024	/* Do not update access times. */
#define 	GY_MS_NODIRATIME	2048	/* Do not update directory access times */
#define 	GY_MS_BIND		4096
#define 	GY_MS_MOVE		8192
#define 	GY_MS_REC		16384
#define 	GY_MS_VERBOSE		32768	/* War is peace. Verbosity is silence.
					 	  GY_MS_VERBOSE is deprecated. */
#define 	GY_MS_SILENT		32768
#define 	GY_MS_POSIXACL		(1<<16)	/* VFS does not apply the umask */
#define 	GY_MS_UNBINDABLE	(1<<17)	/* change to unbindable */
#define 	GY_MS_PRIVATE		(1<<18)	/* change to private */
#define 	GY_MS_SLAVE		(1<<19)	/* change to slave */
#define 	GY_MS_SHARED		(1<<20)	/* change to shared */
#define 	GY_MS_RELATIME		(1<<21)	/* Update atime relative to mtime/ctime. */
#define 	GY_MS_KERNMOUNT		(1<<22) /* this is a kern_mount call */
#define 	GY_MS_I_VERSION		(1<<23) /* Update inode I_version field */
#define 	GY_MS_STRICTATIME	(1<<24) /* Always perform atime updates */
#define 	GY_MS_LAZYTIME		(1<<25) /* Update the on-disk [acm]times lazily */

// Only a subset of FS 
enum FS_TYPES_E
{
	FS_NONE		=	0,
	FS_EXT4		= 	1 << 0,
	FS_XFS		= 	1 << 1,
	FS_BTRFS	= 	1 << 2,
	FS_PROC		=	1 << 3,
	FS_SYSFS	=	1 << 4,
	FS_CGROUP	=	1 << 5,	// cgroupv1
	FS_CGROUP2	=	1 << 6,
	FS_TMPFS	=	1 << 7,
	FS_DEBUGFS	=	1 << 8,
	FS_TRACEFS	=	1 << 9,
	FS_FUSE		=	1 << 10,
	FS_AUFS		=	1 << 11,
	FS_OVERLAY	=	1 << 12,		 
};	

enum FS_CATEGORY_E
{
	FS_CAT_NONE	=	0,
	FS_LOCAL	=	1 << 0,
	FS_NETWORK_FS	=	1 << 1,
	FS_CLUSTERED	=	1 << 2,
	FS_VIRTUAL_API	=	1 << 3,
	FS_UNION	=	1 << 4,	
};
	
enum MOUNT_CGROUP_E
{
	MTYPE_NONE	=	0,	

	// cgroupv1 mounts
	MTYPE_CPU	= 	1 << 0,
	MTYPE_CPUACCT	=	1 << 1,
	MTYPE_CPUSET	=	1 << 2,
	MTYPE_NET_CLS	=	1 << 3,
	MTYPE_NET_PRIO	=	1 << 4,
	MTYPE_BLKIO	=	1 << 5,
	MTYPE_MEMORY	=	1 << 6,
	MTYPE_PIDS	=	1 << 7,
	MTYPE_RDMA	=	1 << 8,
	MTYPE_HUGETLB	=	1 << 9,
	MTYPE_PERFEVENT	=	1 << 10,
	MTYPE_FREEZER	=	1 << 11,
	MTYPE_DEVICES	=	1 << 12,
	MTYPE_SYSTEMD	=	1 << 13,

	MTYPE_CGROUP2	=	1 << 14,
};
	
struct MOUNT_STRING_FLAGS
{
	const char		*pstr;
	uint32_t		flag;	
};		

static constexpr int			MAX_FS_NAME_LEN = 32;
		
static bool is_mount_diskspace_valid(uint32_t fscategory) noexcept
{
	return !(fscategory & (FS_VIRTUAL_API | FS_UNION));
}


class ONE_MOUNT
{
public :	
	int			mnt_id				{0};
	int			parent_mnt_id			{0};
	uint32_t		dev_major_num			{0};
	uint32_t		dev_minor_num			{0};

	char			*pmount_point			{nullptr};
	uint64_t		freespace			{0};
	uint64_t		freespace_init			{0};
	int			mount_options			{0};
	
	char			fsname[MAX_FS_NAME_LEN]		{};
	char			fs_subname[MAX_FS_NAME_LEN]	{};
	uint32_t		fstype				{0};
	uint32_t		fscategory			{0};
	uint32_t		mount_options2			{0};

	time_t			last_warn_tusec_		{0};

	ONE_MOUNT() noexcept	= default;

	ONE_MOUNT(int mnt_id, int parent_mnt_id, uint32_t dev_major_num, uint32_t dev_minor_num, char *pmount_point, int mount_options, char *fsnamein, char *fs_subnamein, uint32_t fstype, uint32_t fscategory, uint32_t mount_options2, uint64_t freespacein) noexcept 
		:
		mnt_id(mnt_id), parent_mnt_id(parent_mnt_id), dev_major_num(dev_major_num), dev_minor_num(dev_minor_num), pmount_point(pmount_point), 
		freespace(freespacein), freespace_init(freespacein),
		mount_options(mount_options), fstype(fstype), fscategory(fscategory), mount_options2(mount_options2)
	{
		if (fsnamein) {
			GY_STRNCPY(fsname, fsnamein, sizeof(fsname) - 1);	
		}
		else {
			*fsname = '\0';	
		}		

		if (fs_subnamein) {
			GY_STRNCPY(fs_subname, fs_subnamein, sizeof(fs_subname) - 1);	
		}
		else {
			*fs_subname = '\0';	
		}		
	}		

	ONE_MOUNT(const ONE_MOUNT & other) noexcept
	{
		std::memcpy(this, &other, sizeof(*this));
		if (other.pmount_point) {
			pmount_point = strdup(other.pmount_point);
		}	
	}	

	ONE_MOUNT(ONE_MOUNT && other) noexcept
	{
		std::memcpy(this, &other, sizeof(*this));

		other.pmount_point 	= nullptr;
		other.mnt_id		= 0;
	}	
	
	ONE_MOUNT & operator= (const ONE_MOUNT & other) noexcept
	{
		if (this == &other) {
			return *this;
		}
			
		if (pmount_point)	free(pmount_point);
			
		std::memcpy(this, &other, sizeof(*this));
		if (other.pmount_point) {
			this->pmount_point = strdup(other.pmount_point);
		}

		return *this;
	}	

	ONE_MOUNT & operator= (ONE_MOUNT && other) noexcept
	{
		if (this == &other) {
			return *this;
		}
			
		if (pmount_point)	free(pmount_point);
			
		std::memcpy(this, &other, sizeof(*this));

		other.pmount_point 	= nullptr;
		other.mnt_id		= 0;

		return *this;
	}	

	bool operator== (const ONE_MOUNT &other) noexcept
	{
		return ((mnt_id == other.mnt_id) && (dev_major_num == other.dev_major_num) && (dev_minor_num == other.dev_minor_num) && 
			(0 == strcmp(pmount_point, other.pmount_point)) && (0 == strcmp(fsname, other.fsname)));
	}
		
	bool is_equal (int mnt_idin, uint32_t dev_major_numin, uint32_t dev_minor_numin, char *pmount_pointin, char *fsnamein) noexcept
	{
		return ((mnt_id == mnt_idin) && (dev_major_num == dev_major_numin) && (dev_minor_num == dev_minor_numin) && 
			(0 == strcmp(pmount_point, pmount_pointin)) && (0 == strcmp(fsname, fsnamein)));
	}

	~ONE_MOUNT() noexcept
	{
		if (pmount_point) {
			free(pmount_point);
			pmount_point = nullptr;
		}
	}	
};	

/*
 * XXX We expect procfs at /proc 
 * The mountmap contains current Mount NS entries
 */
class MOUNT_HDLR
{
public :	
	using MOUNT_ONE_MAP	= std::unordered_map<int, ONE_MOUNT, GY_JHASHER<int>>;

private :
	GY_MUTEX		mountmutex;
	MOUNT_ONE_MAP		mountmap;

	int			mntid_sysfs, mntid_cg_cpu, mntid_cg_cpuacct, mntid_cg_cpuset, mntid_tracefs; 
	int			mntid_cg_net_cls, mntid_cg_net_prio, mntid_cg_blkio, mntid_cg_memory, mntid_cgroup2;

	int			proc_dir_fd;
	int			sysfs_dir_fd;

	bool			mount_proc_if_not;
	bool			mount_sys_if_not;
	bool			mount_tracefs_if_not;

	bool			is_init;

	gy_atomic<uint32_t>	mount_info_errors;	

	int get_mount_one_locked(int mnt_id, ONE_MOUNT & one) noexcept
	{
		if (mnt_id != 0) {
			try {
				const auto it = mountmap.find(mnt_id);
				if (it != mountmap.end()) {
					one = it->second;
					return 0;
				}
			}
			GY_CATCH_EXCEPTION(return -1);
		}
		return -1;	
	}

	int get_mount_one_locked(int mnt_id, ONE_MOUNT & one, char *pmountpoint, size_t bufsz) noexcept
	{
		assert(pmountpoint && bufsz);

		if (mnt_id != 0) {
			try {
				const auto it = mountmap.find(mnt_id);
				if (it != mountmap.end()) {

					std::memcpy((void *)&one, &it->second, sizeof(one));

					if (one.pmount_point) {
						GY_STRNCPY(pmountpoint, one.pmount_point, bufsz - 1);
						one.pmount_point = nullptr;
					}

					return 0;
				}
			}
			GY_CATCH_EXCEPTION(return -1);
		}
		return -1;	
	}

	uint32_t populate_mount_map_locked(FILE *pfp, bool is_update);
		
public :
	MOUNT_HDLR(bool mount_proc_if_not = true, bool mount_sys_if_not = true, bool mount_tracefs_if_not = true);

	~MOUNT_HDLR() noexcept
	{
		if (proc_dir_fd > 0) {
			(void)close(proc_dir_fd);
			proc_dir_fd = -1;	
		}	

		if (sysfs_dir_fd > 0) {
			(void)close(sysfs_dir_fd);
			sysfs_dir_fd = -1;
		}
	}	

	MOUNT_HDLR(const MOUNT_HDLR & other) 			= delete;
	MOUNT_HDLR(MOUNT_HDLR && other) 				= delete;
	MOUNT_HDLR & operator= (const MOUNT_HDLR & other) 		= delete;
	MOUNT_HDLR & operator= (MOUNT_HDLR && other) 		= delete;
	
	int get_cgroup_mount(MOUNT_CGROUP_E cgtype, char *pmountpoint, size_t bufsz) noexcept
	{
		int				mnt_id = 0, ret;	
		ONE_MOUNT			one;
		bool				found = false;
		SCOPE_GY_MUTEX			rlock(&mountmutex);

		switch (cgtype) {
		
		case MTYPE_CPU : 	mnt_id = mntid_cg_cpu; break;
		case MTYPE_CPUACCT :	mnt_id = mntid_cg_cpuacct; break;	
		case MTYPE_CPUSET :	mnt_id = mntid_cg_cpuset; break;
		case MTYPE_NET_CLS :	mnt_id = mntid_cg_net_cls; break;
		case MTYPE_NET_PRIO :	mnt_id = mntid_cg_net_prio; break;
		case MTYPE_BLKIO :	mnt_id = mntid_cg_blkio; break;
		case MTYPE_MEMORY :	mnt_id = mntid_cg_memory; break;
		case MTYPE_CGROUP2 :	mnt_id = mntid_cgroup2; break;

		default :		

			for (auto && it : mountmap) {
				if (it.second.mount_options2 & cgtype) {

					std::memcpy((void *)&one, &it.second, sizeof(one));

					if (one.pmount_point) {
						GY_STRNCPY(pmountpoint, one.pmount_point, bufsz - 1);
						one.pmount_point = nullptr;
					}

					found = true;
					goto done;
				}	
			}	
			return -1;
		}	

		if (mnt_id > 0) {
			ret = get_mount_one_locked(mnt_id, one, pmountpoint, bufsz - 1);
			if (ret == 0) {
				found = true;
			}	
		}	

done :
		if ((found == false) || (*pmountpoint == '\0')) {
			return -1;
		}

		return 0;	
	}	

	int get_tracefs_mount(char *pmount_point, size_t bufsz) noexcept
	{
		int				ret;
		ONE_MOUNT			one;
		SCOPE_GY_MUTEX			rlock(&mountmutex);
		
		if (mntid_tracefs != 0) {
			ret = get_mount_one_locked(mntid_tracefs, one, pmount_point, bufsz - 1);	
			if (ret == 0) {
				return 0;
			}	
		}
		return -1;	
	}

	// one.pmount_point will be set as nullptr on output and pmount_point will be populated	
	int get_mount_by_mntid(int mnt_id, ONE_MOUNT & one, char *pmount_point, size_t bufsz) noexcept
	{
		int				ret;
		SCOPE_GY_MUTEX			rlock(&mountmutex);
		
		if (mnt_id != 0) {
			ret = get_mount_one_locked(mnt_id, one, pmount_point, bufsz - 1);	
			if (ret == 0) {
				return 0;
			}	
		}
		return -1;	
	}

	// one.pmount_point will be set as nullptr on output and pmount_point will be populated	
	int get_mount_by_major_minor(uint32_t dev_major_num, uint32_t dev_minor_num, ONE_MOUNT & one, char *pmount_point, size_t bufsz) noexcept
	{
		SCOPE_GY_MUTEX			rlock(&mountmutex);

		for (auto && it : mountmap) {
			if ((dev_minor_num == it.second.dev_minor_num) && (dev_major_num == it.second.dev_major_num)) {

				std::memcpy((void *)&one, &it.second, sizeof(one));
				GY_STRNCPY(pmount_point, one.pmount_point, bufsz - 1);
				one.pmount_point = nullptr;

				return 0;
			}	
		}	

		return -1;	
	}
		
	// one.pmount_point will be set as nullptr on output
	int get_mount_by_mount_point(const char *pmount_point, ONE_MOUNT & one) noexcept
	{
		SCOPE_GY_MUTEX			rlock(&mountmutex);

		for (auto && it : mountmap) {
			if (0 == strcmp(it.second.pmount_point, pmount_point)) {
				std::memcpy((void *)&one, &it.second, sizeof(one));
				one.pmount_point = nullptr;

				return 0;
			}	
		}	

		return -1;	
	}

	template <typename FCB>
	int get_mounts_by_fs_type(FS_TYPES_E fstype, FCB & cb, void *arg)
	{
		int				nmatch = 0, ret;	
		SCOPE_GY_MUTEX			rlock(&mountmutex);

		for (auto && it : mountmap) {
			if ((it.second.fstype == fstype) || ((it.second.fstype & ~FS_FUSE) == fstype)) {
				nmatch++;

				ret = cb(it.second, arg);
				if (ret == -1) {
					break;
				}	
			}	
		}	

		return nmatch;	
	}

	template <typename FCB>
	int get_mounts_by_fsname(const char *pfsname, FCB & cb, void *arg)
	{
		int				nmatch = 0, ret;	
		SCOPE_GY_MUTEX			rlock(&mountmutex);

		for (auto && it : mountmap) {
			if ((0 == strcmp(it.second.fsname, pfsname)) || (0 == strcmp(it.second.fs_subname, pfsname))) {
				nmatch++;

				ret = cb(it.second, arg);
				if (ret == -1) {
					break;
				}	
			}	
		}	

		return nmatch;	
	}

	int get_proc_dir_fd() const noexcept
	{
		return proc_dir_fd;
	}
	
	int get_sysfs_dir_fd() const noexcept
	{
		return sysfs_dir_fd;
	}
	
	// Returns new mount error count
	uint32_t add_mount_errors(uint32_t increment = 1) noexcept
	{
		return increment + mount_info_errors.fetch_add_relaxed(increment, std::memory_order_relaxed);
	}	

	uint32_t get_mount_errors() const noexcept
	{
		return mount_info_errors.load(std::memory_order_relaxed);
	}	

	int mount_tracefs(void) noexcept;

	int update_mount_info() noexcept;

	int update_mount_freespace() noexcept;

	void print_mount_info(bool print_all = true) noexcept;

	static std::shared_ptr<MOUNT_HDLR> get_singleton() noexcept;

	static int init_singleton(bool mount_proc_if_not = false, bool mount_sys_if_not = false, bool mount_tracefs_if_not = false);
};	

bool 		gy_are_files_same(const char *path1, const char *path2, int flags = AT_NO_AUTOMOUNT) noexcept;

bool 		is_fs_networkfs(const char *fstype) noexcept;
bool 		is_fs_local_fs(const char *fstype) noexcept;
bool 		is_fs_clusterfs(const char *fstype) noexcept;
bool 		is_fs_virtual_api_fs(const char *fstype) noexcept;
bool 		is_fs_union(const char *fstype) noexcept;
uint32_t 	get_fs_category(const char *pfstype) noexcept;

int 		gy_mount_virtual_fs(const char *fstype, const char *dest_dir, mode_t mode, bool mount_on_existing_dir, bool print_error = true) noexcept;

} // namespace gyeeta

