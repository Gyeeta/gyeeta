
#include 		"gy_common_inc.h"
#include 		"gy_file_api.h"
#include 		"gy_task_stat.h"
#include 		"gy_sys_hardware.h"

#undef 			NDEBUG
#include 		<assert.h>

using namespace gyeeta;


static bool is_fs_networkfs1(const char *fstype)
{
	static constexpr uint32_t 	fshash[] = {
							gy_crc32_constexpr("afs"), gy_crc32_constexpr("cifs"), gy_crc32_constexpr("smbfs"),
							gy_crc32_constexpr("sshfs"), gy_crc32_constexpr("ncpfs"), gy_crc32_constexpr("ncp"),
							gy_crc32_constexpr("nfs"), gy_crc32_constexpr("nfs4"), gy_crc32_constexpr("gfs"),
							gy_crc32_constexpr("gfs2"), gy_crc32_constexpr("glusterfs"), gy_crc32_constexpr("pvfs2") /* OrangeFS */,
							gy_crc32_constexpr("ocfs2"), gy_crc32_constexpr("lustre")
						};

	uint32_t			rhash = gy_crc32(fstype, strlen(fstype));							 	

	for (uint32_t i = 0; i < sizeof(fshash)/sizeof(*fshash); i++) {
		if (rhash == fshash[i]) return true;
	}	

	return false;
}

void test_crc()
{
	constexpr uint32_t 		scrc = gy_crc32_constexpr("/sys/fs/cgroup/cpu/cpuacct.usage_all"), scrc2 = gy_crc32_constexpr("/proc/self/net"),
					scrc3 = gy_crc32_constexpr("/sys/fs/cgroup/cpu/cpuacct.usage"), 
					coll1 = gy_crc32_constexpr("plumless"), coll2 = gy_crc32_constexpr("buckeroo");

	uint32_t 			rscrc = gy_crc32("/sys/fs/cgroup/cpu/cpuacct.usage_all", strlen("/sys/fs/cgroup/cpu/cpuacct.usage_all")), 
					rscrc2 = gy_crc32("/proc/self/net", strlen("/proc/self/net")),
					rscrc3 = gy_crc32("/sys/fs/cgroup/cpu/cpuacct.usage", strlen("/sys/fs/cgroup/cpu/cpuacct.usage"));

	assert(scrc == rscrc);
	assert(scrc2 == rscrc2);
	assert(scrc3 == rscrc3);

	INFOPRINT("Compile time crc32 of /sys/fs/cgroup/cpu/cpuacct.usage_all is %u, scrc2 = %u, scrc3 = %u\n", scrc, scrc2, scrc3);

	INFOPRINT("Test for hash of filesystem : is tmpfs Network FS %d : is glusterfs Network FS %d\n", is_fs_networkfs1("tmpfs"), is_fs_networkfs1("glusterfs"));

	INFOPRINT("Test for hash collision : coll1 = %u coll2 = %u coll1 == coll2 : %d\n", coll1, coll2, coll1 == coll2);

	static_assert(1263642859 == gy_crc32_constexpr("/sys/fs/cgroup/cpu/cpuacct.usage_all"), "Compile time crc fails");

}	

int test_sys()
{
	/*
	 * Test if repeatedly reading /sys/fs/cgroup/cpu/cpuacct.usage_all gives new values
	 */
	SCOPE_FD			fdobj("/sys/fs/cgroup/cpu/cpuacct.usage_all", O_RDONLY | O_CLOEXEC);
	int				fd = fdobj.get();
	 
	if (fd < 0) {
		PERRORPRINT("failed to open /sys/fs/cgroup/cpu/cpuacct.usage_all");
		return -1;
	}	

	for (int i = 0; i < 3; i++) {
		SCOPE_NANOSLEEP			scsleep(1, 0, true);	
		
		lseek(fd, 0, SEEK_SET);
		
		char 				*pbuf;
		size_t				szread;

		pbuf = read_fd_to_alloc_buffer(fd, &szread, 4096);
		
		std::unique_ptr<void, std::integral_constant<decltype(free)*, free>> 	punq(pbuf);
	
		if (!pbuf) {
			PERRORPRINT("Failed to read from fd");
			scsleep.reset_sleep();
			return -1;
		}	

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Current output of /sys/fs/cgroup/cpu/cpuacct.usage_all is (%lu bytes) : \n", szread);

		gy_writebuffer(STDOUT_FILENO, pbuf, szread);
	} 	

	return 0;
}	

int test_proc()
{
	DEBUGEXECN(1, INFOPRINTCOLOR(GY_COLOR_BOLD_GREEN, "Testing data from /proc/stat...\n"););

	/*
	 * Test if repeatedly reading /proc/stat gives new values
	 */
	SCOPE_FD			fdobj("/proc/stat", O_RDONLY | O_CLOEXEC);
	int				fd = fdobj.get();
	off_t				oret;
	const size_t			sz_to_alloc = 16 * 1024;

	bool				is_malloc;
	char				*pbuf;
	 
	if (fd < 0) {
		PERRORPRINT("failed to open /proc/stat");
		return -1;
	}	

	SAFE_STACK_ALLOC(pbuf, sz_to_alloc, is_malloc);

	for (int i = 0; i < 3; i++) {
		SCOPE_NANOSLEEP			scsleep(1, 0, true);	
		
		oret = lseek(fd, 0, SEEK_SET);
		if (oret == (off_t) -1) {
			PERRORPRINT("Could not lseek for /proc/stat");
		}	
		
		size_t				szread;

		szread = gy_readbuffer(fd, pbuf, sz_to_alloc - 1);
		if (szread <= 0) {
			PERRORPRINT("Failed to read from fd");
			scsleep.reset_sleep();
			return -1;
		}

		pbuf[szread] = '\0';

		INFOPRINTCOLOR(GY_COLOR_BOLD_GREEN, "Current output of /proc/stat is (%lu bytes) : \n", szread);

		gy_writebuffer(STDOUT_FILENO, pbuf, szread);
	} 	

	return 0;
}	



int test_proc_ns()
{
	const char *	 		nsstr[] = {"ipc", "mnt", "net", "pid", "user", "uts"};
	ino_t				nsinode[6], nsparentinode[6];
	int				ret, proc_dir_fd;

	proc_dir_fd = open("/proc",  O_PATH | O_CLOEXEC);
	if (proc_dir_fd < 0) {
		PERRORPRINT("Failed to get /proc dir fd");
		return -1;
	}

	ret = get_proc_ns_inodes(getpid(), nsstr, nsinode, sizeof(nsstr)/sizeof(*nsstr), proc_dir_fd);
	if (ret < 0) {
		PERRORPRINT("Failed to get ns inodes");
		return -1;
	}	

	ret = get_proc_ns_inodes(getppid(), nsstr, nsparentinode, sizeof(nsstr)/sizeof(*nsstr), proc_dir_fd);
	if (ret < 0) {
		PERRORPRINT("Failed to get ns parent inodes");
		return -1;
	}	

	for (size_t i = 0; i < sizeof(nsstr)/sizeof(*nsstr); i++) {
		INFOPRINT("Namespace inode of %s is %lu : Parent %lu\n", nsstr[i], nsinode[i], nsparentinode[i]);
		assert(nsinode[i] == nsparentinode[i]);
	}	

	ret = SYS_HARDWARE::rootns_inodes.populate_ns_inodes(proc_dir_fd, 1, &SYS_HARDWARE::rootns_inodes);
	if (ret < 0) {
		PERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Failed to get ns inodes for pid 1");
	}

	TASK_STAT 			task(proc_dir_fd, getpid());

	ret = task.ns_inodes.populate_ns_inodes(proc_dir_fd, getpid(), &SYS_HARDWARE::rootns_inodes);
	if (ret < 0) {
		PERRORPRINTCOLOR(GY_COLOR_RED, "Failed to get ns inodes");
		return -1;
	}

	INFOPRINT("Net Namespace of current PID %lu : Net Namespace of root Net NS %lu : net_in_root_ns %u\n", 
			task.ns_inodes.net_inode, SYS_HARDWARE::rootns_inodes.net_inode, task.ns_inodes.net_in_root_ns);

	return 0;
}	

int test_file(char *pfilename)
{
	char			*pbuf;
	size_t			szread;

	SCOPE_FILE		fobj(pfilename, "re");
	
	if (nullptr == fobj.get()) {
		PERRORPRINTCOLOR(GY_COLOR_RED, "Could not open file %s", pfilename);
		return -1;
	}	

	int			fd = fileno(fobj.get());

	pbuf = read_fd_to_alloc_buffer(fd, &szread);

	if (!pbuf) {
		PERRORPRINT("Failed to read from fd");
		return -1;
	}	

	GY_SCOPE_EXIT { free(pbuf); };

	INFOPRINT("Output of file %s is (%lu bytes) : \n", pfilename, szread);

	gy_writebuffer(STDOUT_FILENO, pbuf, szread);

	int ret = gy_copyfile(pfilename, "/tmp/testfile.out", true);
	if (ret != 0) {
		PERRORPRINTCOLOR(GY_COLOR_RED, "Failed to copy file %s to file /tmp/testfile.out", pfilename);
	}	

	return 0;
}	

int main(int argc, char **argv)
{
	gdebugexecn = 1;

	size_t				currstacksz =  gy_get_thread_local().get_thread_stack_freespace();	

	try {
		test_crc();

		test_sys();
		test_proc();

		test_proc_ns();

		for (int i = 1; i < argc; i++) {
			SCOPE_NANOSLEEP			scsleep(1, 0, true);	

			int ret = test_file(argv[i]);

			if (ret < 0) {
				scsleep.reset_sleep();
			}	
		}	
	}
	GY_CATCH_EXCEPTION(ERRORPRINTCOLOR(GY_COLOR_RED, "Exception occured due to %s\n", GY_GET_EXCEPT_STRING););

	return 0;
}	


