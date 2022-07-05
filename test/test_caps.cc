
/*
 *  sudo  setcap 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20+ep /tmp/test1 # This works on all platforms
 * OR
 *  sudo setcap cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_setpcap,cap_sys_ptrace+ep /tmp/test1
 */ 

#include 	"gy_common_inc.h"
#include 	<sys/capability.h>
#include 	<sys/prctl.h>


using namespace gyeeta;

struct TEST_GY_CAPABILITIES
{
	TEST_GY_CAPABILITIES()			= delete;

	explicit TEST_GY_CAPABILITIES(pid_t pid) noexcept
	{
		cap = cap_get_pid(pid);
	}

	explicit TEST_GY_CAPABILITIES(cap_t capo) noexcept
	{
		if (capo) {
			cap = cap_dup(capo);
		}	
		else {
			cap = nullptr;
		}	
	}

	~TEST_GY_CAPABILITIES()
	{
		reset();
	}	

	TEST_GY_CAPABILITIES(TEST_GY_CAPABILITIES && other) noexcept 
	{
		this->cap  	= other.cap;
		other.cap 	= nullptr;
	}	

	TEST_GY_CAPABILITIES & operator= (TEST_GY_CAPABILITIES && other) noexcept
	{
		if (this != &other) {
			reset();

			this->cap  	= other.cap;
			other.cap 	= nullptr;
		}
		return *this;
	}

	TEST_GY_CAPABILITIES(TEST_GY_CAPABILITIES & other) noexcept
	{
		if (other.cap) {
			this->cap = cap_dup(other.cap);
		}	
		else {
			this->cap = nullptr;
		}	
	}	

	TEST_GY_CAPABILITIES & operator= (TEST_GY_CAPABILITIES & other) noexcept
	{
		if (this != &other) {
			reset();

			if (other.cap) {
				this->cap = cap_dup(other.cap);
			}	
		}
			
		return *this;
	}	 

	void reset() noexcept
	{
		if (cap) {
			cap_free(cap);
			cap = nullptr;
		}	
	}
		
	cap_t get() noexcept
	{
		return cap;
	}

	cap_t					cap;
};	

int main(int argc, char **argv)
{
	if (argc < 2) {
		IRPRINT("\nERROR : Usage %s <File to read>\n\n", argv[0]);
		return -1;
	}	

	gdebugexecn = 1;

	int				ret;
	char				pbuf[8192];
	

	IRPRINT("cap setuid in set: %d\n", prctl(PR_CAPBSET_READ, CAP_SETUID, 0, 0, 0));

	{
		
		TEST_GY_CAPABILITIES		proccap(getpid());

		if (nullptr != proccap.get()) {
			auto 	cap = cap_to_text(proccap.get(), nullptr);

			GY_SCOPE_EXIT { if (cap) cap_free(cap); };

			IRPRINT("Current PID Capabilities : %s\n", cap);
		}

		{
		TEST_GY_CAPABILITIES		filecap(cap_get_file(argv[1]));

		if (nullptr != filecap.get()) {
			auto 	cap = cap_to_text(proccap.get(), nullptr);

			GY_SCOPE_EXIT { if (cap) cap_free(cap); };

			IRPRINT("File Capabilities : %s\n", cap);
		}
		else {
			PERRORPRINT("File cap_to_text failed");
			filecap = std::move(proccap);
		}
		}


	}

	IRPRINT("uid: %d\n", (int) getuid());

	//setresuid(0, 0, 0);
	//setresgid(0, 0, 0);
	//setfsuid(0);

	IRPRINT("euid: %d, egid: %d, uid: %d, gid: %d, PID %d\n", (int) geteuid(), (int)getegid(), (int)getuid(), (int)getgid(), getpid());

	IRPRINT("\nContents of file %s are : \n\n", argv[1]);

	int 		fd = open(argv[1], O_RDONLY);
	if (fd == -1) {
		PERRORPRINT("Open of file %s failed", argv[1]);
		return -1;
	}

	uint8_t		buf[65];

	ret = read(fd, buf, sizeof(buf) - 1);
	if (ret > 0) {
		buf[ret] = '\0';
		gy_print_buf(STDOUT_FILENO, buf, ret, 1 /* print_ascii */, (char *)"First 64 chars");
	}
	else if (ret < 0) {
		PERRORPRINT("Read of file %s failed", argv[1]);
	}

	close(fd);

	return 0;
}	

