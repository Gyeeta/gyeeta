
static const char gstatus_k8s_nginx[] = R"(Name:	nginx
Umask:	0022
State:	S (sleeping)
Tgid:	4976
Ngid:	0
Pid:	4976
PPid:	4956
TracerPid:	0
Uid:	0	0	0	0
Gid:	0	0	0	0
FDSize:	64
Groups:	 
NStgid:	4976	1
NSpid:	4976	1
NSpgid:	4976	1
NSsid:	4976	1
VmPeak:	   42900 kB
VmSize:	   42892 kB
VmLck:	       0 kB
VmPin:	       0 kB
VmHWM:	    7176 kB
VmRSS:	    1548 kB
RssAnon:	     904 kB
RssFile:	     644 kB
RssShmem:	       0 kB
VmData:	    1224 kB
VmStk:	     136 kB
VmExe:	    1376 kB
VmLib:	    7232 kB
VmPTE:	     104 kB
VmPMD:	      16 kB
VmSwap:	       4 kB
HugetlbPages:	       0 kB
Threads:	1
SigQ:	0/7460
SigPnd:	0000000000000000
ShdPnd:	0000000000000000
SigBlk:	0000000000000000
SigIgn:	0000000040001000
SigCgt:	0000000198016a07
CapInh:	00000000a80425fb
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
Seccomp:	0
Cpus_allowed:	3
Cpus_allowed_list:	0-1
Mems_allowed:	00000000,00000001
Mems_allowed_list:	0
voluntary_ctxt_switches:	165
nonvoluntary_ctxt_switches:	97)";


static const char guser_ns_proc[] = R"(Name:	cat
Umask:	0022
State:	R (running)
Tgid:	2664
Ngid:	0
Pid:	2664
PPid:	1169
TracerPid:	0
Uid:	0	0	0	0
Gid:	0	0	0	0
FDSize:	256
Groups:	65534 0 
NStgid:	2664	142
NSpid:	2664	142
NSpgid:	2664	142
NSsid:	789	0
VmPeak:	  107980 kB
VmSize:	  107980 kB
VmLck:	       0 kB
VmPin:	       0 kB
VmHWM:	     712 kB
VmRSS:	     712 kB
RssAnon:	      76 kB
RssFile:	     636 kB
RssShmem:	       0 kB
VmData:	     188 kB
VmStk:	     132 kB
VmExe:	      44 kB
VmLib:	    1948 kB
VmPTE:	      64 kB
VmSwap:	       0 kB
HugetlbPages:	       0 kB
CoreDumping:	0
Threads:	1
SigQ:	0/257190
SigPnd:	0000000000000000
ShdPnd:	0000000000000000
SigBlk:	0000000000001000
SigIgn:	0000000000000000
SigCgt:	0000000000000000
CapInh:	0000000000000000
CapPrm:	0000003fffffffff
CapEff:	0000003fffffffff
CapBnd:	0000003fffffffff
CapAmb:	0000000000000000
NoNewPrivs:	0
Seccomp:	0
Cpus_allowed:	fff
Cpus_allowed_list:	0-11
Mems_allowed:	00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000003
Mems_allowed_list:	0-1
voluntary_ctxt_switches:	0
nonvoluntary_ctxt_switches:	0)";

static const char gnacl_multi_pid_ns[] = R"(Name:	nacl_helper
Umask:	0002
State:	S (sleeping)
Tgid:	1823
Ngid:	0
Pid:	1823
PPid:	1822
TracerPid:	0
Uid:	1001	1001	1001	1001
Gid:	1001	1001	1001	1001
FDSize:	64
Groups:	980 1001 
NStgid:	1823	2	1
NSpid:	1823	2	1
NSpgid:	1806	0	0
NSsid:	4526	0	0
VmPeak:	   25644 kB
VmSize:	   25644 kB
VmLck:	       0 kB
VmPin:	       0 kB
VmHWM:	    4000 kB
VmRSS:	    4000 kB
RssAnon:	     544 kB
RssFile:	    3456 kB
RssShmem:	       0 kB
VmData:	    2012 kB
VmStk:	     132 kB
VmExe:	    2352 kB
VmLib:	    3408 kB
VmPTE:	      92 kB
VmSwap:	       0 kB
HugetlbPages:	       0 kB
CoreDumping:	0
Threads:	1
SigQ:	0/257190
SigPnd:	0000000000000000
ShdPnd:	0000000000000000
SigBlk:	0000000000000000
SigIgn:	0000000000000000
SigCgt:	0000000180000000
CapInh:	0000000000000000
CapPrm:	0000000000200000
CapEff:	0000000000200000
CapBnd:	0000003fffffffff
CapAmb:	0000000000000000
NoNewPrivs:	1
Seccomp:	0
Cpus_allowed:	fff
Cpus_allowed_list:	0-11
Mems_allowed:	00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000003
Mems_allowed_list:	0-1
voluntary_ctxt_switches:	3
nonvoluntary_ctxt_switches:	0)";

static const char gmongod_pid_ns[] = R"(Name:	mongod
Umask:	0006
State:	S (sleeping)
Tgid:	10112
Ngid:	0
Pid:	10112
PPid:	10064
TracerPid:	0
Uid:	1001	1001	1001	1001
Gid:	1001	1001	1001	1001
FDSize:	2048
Groups:	980 1001 
NStgid:	10112
NSpid:	10112
NSpgid:	10064
NSsid:	10064
VmPeak:	16108180 kB
VmSize:	16108172 kB
VmLck:	       0 kB
VmPin:	       0 kB
VmHWM:	15545956 kB
VmRSS:	15151500 kB
RssAnon:	15123976 kB
RssFile:	   27524 kB
RssShmem:	       0 kB
VmData:	15927440 kB
VmStk:	     132 kB
VmExe:	   28600 kB
VmLib:	    8036 kB
VmPTE:	   31008 kB
VmSwap:	       0 kB
HugetlbPages:	       0 kB
CoreDumping:	0
Threads:	304
SigQ:	0/257190
SigPnd:	0000000000000000
ShdPnd:	0000000000000000
SigBlk:	0000000000804203
SigIgn:	0000000000381a01
SigCgt:	00000001800004ec
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	0000003fffffffff
CapAmb:	0000000000000000
NoNewPrivs:	0
Seccomp:	0
Cpus_allowed:	fff
Cpus_allowed_list:	0-11
Mems_allowed:	00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000003
Mems_allowed_list:	0-1
voluntary_ctxt_switches:	238551415
nonvoluntary_ctxt_switches:	1918)";

static const char *gtest_status_arr[] = {gstatus_k8s_nginx, guser_ns_proc, gnacl_multi_pid_ns, gmongod_pid_ns};
static const char *gtest_status_info_arr[] = {"nginx", "user ns process", "chrome nacl multi pid ns", "mongodb"};

