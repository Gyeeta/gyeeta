
#include 		"gy_common_inc.h"
#include 		"gy_mount_disk.h"
#include 		<sys/mount.h>

#include		"./testdata/test_mountinfo1.cc"

using namespace gyeeta;

namespace TEST_SPACE {

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


int test_mounts(FILE *pfp)
{
	int			ret, nmounts = 0;

	while (true) {
		char			*pmount_point = nullptr, *pmount_options = nullptr, *pfstype = nullptr, 
					*pmount_source = nullptr, *pmount_other_options = nullptr, pfs_subname[MAX_FS_NAME_LEN];
		int			mnt_id = 0, parent_mnt_id = 0, mount_options = 0;
		uint32_t		dev_major_num = 0, dev_minor_num = 0;
		uint32_t		fstype = FS_NONE;
		uint32_t		fscategory = FS_CAT_NONE;
		uint32_t 		mount_options2 = MTYPE_NONE;
		int			n; 

		char			buf_fstype[64], buf_fscategory[32], buf_mount_options2[64];
		STR_WR_BUF		strbuf_fstype(buf_fstype, sizeof(buf_fstype)), strbuf_fscategory(buf_fscategory, sizeof(buf_fscategory)),
					strbuf_mount(buf_mount_options2, sizeof(buf_mount_options2));


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

		if (n < 7) {
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
					strbuf_fstype.append(gmount_fs_flags[i].pstr);

					break;
				}	
			}

			if (true == is_fs_networkfs(pfstype)) {
				fscategory |= FS_NETWORK_FS;
				strbuf_fscategory.append("network fs");
			}	
			else if (true == is_fs_local_fs(pfstype)) {
				fscategory |= FS_LOCAL;
				strbuf_fscategory.append("local fs");
			}	
			else if (true == is_fs_virtual_api_fs(pfstype)) {
				fscategory |= FS_VIRTUAL_API;
				strbuf_fscategory.append("virtual api fs");
			}	
			else if (true == is_fs_union(pfstype)) {
				fscategory |= FS_UNION;
				strbuf_fscategory.append("union fs");
			}	

			if (true == is_fs_clusterfs(pfstype)) {
				fscategory |= FS_CLUSTERED;
				strbuf_fscategory.append("clustered fs");
			}	

			if (*pfs_subname) {
				if (true == is_fs_networkfs(pfs_subname)) {
					fscategory |= FS_NETWORK_FS;
					strbuf_fscategory.append("network fs");
				}	
				else if (true == is_fs_local_fs(pfs_subname)) {
					fscategory |= FS_LOCAL;
					strbuf_fscategory.append("local fs");
				}	
				else if (true == is_fs_virtual_api_fs(pfs_subname)) {
					fscategory |= FS_VIRTUAL_API;
					strbuf_fscategory.append("virtual api fs");
				}	
				else if (true == is_fs_union(pfs_subname)) {
					fscategory |= FS_UNION;
					strbuf_fscategory.append("union fs");
				}	

				if (true == is_fs_clusterfs(pfs_subname)) {
					fscategory |= FS_CLUSTERED;
					strbuf_fscategory.append("clustered fs");
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

						if (strbuf_mount.length()) {
							strbuf_mount.append(", ");
						}	
						strbuf_mount.append(gmount_option2_flags[i].pstr);
					}	
				}
		
			}	
		}	


		IRPRINT("%d:%d %u:%u Mount Point %s : Mount Options : %08x : Filesystem " GY_COLOR_GREEN "%s" GY_COLOR_RESET " : Subtype \'" GY_COLOR_YELLOW "%s" GY_COLOR_RESET "\' : fstype 0x%08x (%s) : fscategory 0x%08x (" GY_COLOR_CYAN "%s " GY_COLOR_RESET "): mount_options2 0x%08x (" GY_COLOR_BOLD_YELLOW "%s" GY_COLOR_RESET ")\n",
			mnt_id, parent_mnt_id, dev_major_num, dev_minor_num, pmount_point, mount_options, pfstype, pfs_subname, fstype, strbuf_fstype.buffer(),
			fscategory, strbuf_fscategory.buffer(), mount_options2, strbuf_mount.buffer());
	}

	INFOPRINT("Total Mounts %u\n\n", nmounts);

	return 0;
}
}


int main(int argc, char **argv)
{
	FILE			*pfp;
	int			ret;

	using TEST_SPACE::test_mounts;

	if (argc == 2) {
		pfp = fopen(argv[1], "re");

		if (!pfp) {
			PERRORPRINT("Failed to open file %s", argv[1]);
			return -1;
		}	

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Getting mount info from %s\n", argv[1]);

		return test_mounts(pfp);
	}	

	
	{
		INFOPRINTCOLOR(GY_COLOR_GREEN, "First testing the mounts with /proc/self/mountinfo ...\n\n");
		
		SCOPE_FD		fdscope("/proc", O_PATH | O_CLOEXEC);
		int			fd;

		fd = fdscope.get();
		if (fd < 0) {
			PERRORPRINT("Could not open /proc dir");
			return -1;
		}	

		SCOPE_FILE		fscope(fd, "./self/mountinfo", "r");

		pfp = fscope.get();

		if (!pfp) {
			PERRORPRINT("Failed to open mountinfo");
			return -1;
		}	

		ret = test_mounts(pfp);
		if (ret < 0) {
			return ret;
		}	
	}

	{
		INFOPRINTCOLOR(GY_COLOR_GREEN, "Now testing mounts from test_mount_str1 buffer ...\n\n");

		SCOPE_FILE		fscope((void *)test_mount_str1, sizeof(test_mount_str1) - 1, "r");

		pfp = fscope.get();

		if (!pfp) {
			PERRORPRINT("Failed to fmemopen test_mount_str1");
			return -1;
		}	

		ret = test_mounts(pfp);
		if (ret < 0) {
			return ret;
		}	
	}

	{
		INFOPRINTCOLOR(GY_COLOR_GREEN, "Now testing mounts from test_mount_str2 buffer ...\n\n");

		SCOPE_FILE		fscope((void *)test_mount_str2, sizeof(test_mount_str2) - 1, "r");

		pfp = fscope.get();

		if (!pfp) {
			PERRORPRINT("Failed to fmemopen test_mount_str2");
			return -1;
		}	

		ret = test_mounts(pfp);
		if (ret < 0) {
			return ret;
		}	
	}

	{
		INFOPRINTCOLOR(GY_COLOR_GREEN, "Now testing mounts from test_mount_str3 buffer ...\n\n");

		SCOPE_FILE		fscope((void *)test_mount_str3, sizeof(test_mount_str3) - 1, "r");

		pfp = fscope.get();

		if (!pfp) {
			PERRORPRINT("Failed to fmemopen test_mount_str3");
			return -1;
		}	

		ret = test_mounts(pfp);
		if (ret < 0) {
			return ret;
		}	
	}

	{
		INFOPRINTCOLOR(GY_COLOR_GREEN, "Now testing MOUNT_HDLR class methods...\n\n");

		MOUNT_HDLR		mountinfo;

		mountinfo.print_mount_info();

		mountinfo.add_mount_errors();

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Now testing MOUNT_HDLR update mount...\n\n");

		mountinfo.update_mount_info();

		mountinfo.print_mount_info();

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Now testing MOUNT_HDLR find mount methods...\n\n");

		char			mountdir[GY_PATH_MAX], tracedir[GY_PATH_MAX];
		int			ret;
	
		ret = mountinfo.get_cgroup_mount(MTYPE_CPUACCT, mountdir, sizeof(mountdir));
		if (ret != 0) {
			ERRORPRINTCOLOR(GY_COLOR_RED, "cpuacct cgroup dir not found in valid mounts...\n");
			return -1;
		}	

		ret = mountinfo.get_tracefs_mount(tracedir, sizeof(tracedir));
		if (ret != 0) {
			ERRORPRINTCOLOR(GY_COLOR_RED, "tracefs dir not found in valid mounts...\n");
			return -1;
		}	

		INFOPRINTCOLOR(GY_COLOR_GREEN, "cpuacct mount point is : %s : tracefs mount point is %s\n\n", mountdir, tracedir);
	}	
	
	return 0;
}	
