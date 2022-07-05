
static const char gcg_k8s[] = R"(11:pids:/kubepods/besteffort/podd0544205-72df-11e8-b691-080027c5d95e/84ad0790d137467a41a21d7fb29b4973f68d4d00e67390454d587da8e5cc292b
10:memory:/kubepods/besteffort/podd0544205-72df-11e8-b691-080027c5d95e/84ad0790d137467a41a21d7fb29b4973f68d4d00e67390454d587da8e5cc292c
9:hugetlb:/kubepods/besteffort/podd0544205-72df-11e8-b691-080027c5d95e/84ad0790d137467a41a21d7fb29b4973f68d4d00e67390454d587da8e5cc292d
8:perf_event:/kubepods/besteffort/podd0544205-72df-11e8-b691-080027c5d95e/84ad0790d137467a41a21d7fb29b4973f68d4d00e67390454d587da8e5cc292e
7:devices:/kubepods/besteffort/podd0544205-72df-11e8-b691-080027c5d95e/84ad0790d137467a41a21d7fb29b4973f68d4d00e67390454d587da8e5cc292f
6:freezer:/kubepods/besteffort/podd0544205-72df-11e8-b691-080027c5d95e/84ad0790d137467a41a21d7fb29b4973f68d4d00e67390454d587da8e5cc2920
5:net_cls:/kubepods/besteffort/podd0544205-72df-11e8-b691-080027c5d95e/84ad0790d137467a41a21d7fb29b4973f68d4d00e67390454d587da8e5cc2921
4:cpuset:/kubepods/besteffort/podd0544205-72df-11e8-b691-080027c5d95e/84ad0790d137467a41a21d7fb29b4973f68d4d00e67390454d587da8e5cc2922
3:cpu,cpuacct:/kubepods/besteffort/podd0544205-72df-11e8-b691-080027c5d95e/84ad0790d137467a41a21d7fb29b4973f68d4d00e67390454d587da8e5cc2923
2:blkio:/kubepods/besteffort/podd0544205-72df-11e8-b691-080027c5d95e/84ad0790d137467a41a21d7fb29b4973f68d4d00e67390454d587da8e5cc2924
1:name=systemd:/kubepods/besteffort/podd0544205-72df-11e8-b691-080027c5d95e/84ad0790d137467a41a21d7fb29b4973f68d4d00e67390454d587da8e5cc2925
)";

static const char gcg_centos7[] = R"(12:pids:/user.slice
11:freezer:/
10:memory:/
9:cpuset:/
8:blkio:/
7:perf_event:/
6:net_cls,net_prio:/
5:devices:/
4:rdma:/
3:cpu,cpuacct:/
2:hugetlb:/
1:name=systemd:/user.slice/user-1001.slice/session-1776.scope
)";

static const char gcg_lxc[] = R"(12:memory:/lxc/first
11:cpuset:/lxc/first
10:rdma:/lxc/first
9:devices:/lxc/first
8:pids:/lxc/first
7:cpu,cpuacct:/lxc/first
6:freezer:/lxc/first
5:hugetlb:/lxc/first
4:net_cls,net_prio:/lxc/first
3:blkio:/lxc/first
2:perf_event:/lxc/first
1:name=systemd:/lxc/first
0::/lxc/first
)";

static const char gcg_nocg[] = "";

static const char gcg_no_net[] = R"(10:pids:/kubepods/besteffort/podd0544205-72df-11e8-b691-080027c5d95e/84ad0790d137467a41a21d7fb29b4973f68d4d00e67390454d587da8e5cc292b
9:memory:/sys/fs/cgroup/cpuacct/system.slice/mnt-sda1-var-lib-kubelet-pods-d0544205-72df-11e8-b691-080027c5d95e-volumes-kubernetes.io~secret-storage-provisioner-token-k744p.mount
8:hugetlb:/kubepods/besteffort/podd0544205-72df-11e8-b691-080027c5d95e/84ad0790d137467a41a21d7fb29b4973f68d4d00e67390454d587da8e5cc292b
7:perf_event:/kubepods/besteffort/podd0544205-72df-11e8-b691-080027c5d95e/84ad0790d137467a41a21d7fb29b4973f68d4d00e67390454d587da8e5cc292b
6:devices:/kubepods/besteffort/podd0544205-72df-11e8-b691-080027c5d95e/84ad0790d137467a41a21d7fb29b4973f68d4d00e67390454d587da8e5cc292b
5:freezer:/kubepods/besteffort/podd0544205-72df-11e8-b691-080027c5d95e/84ad0790d137467a41a21d7fb29b4973f68d4d00e67390454d587da8e5cc292b
4:cpuset:/kubepods/besteffort/podd0544205-72df-11e8-b691-080027c5d95e/84ad0790d137467a41a21d7fb29b4973f68d4d00e67390454d587da8e5cc292b
3:cpu,cpuacct:/kubepods/besteffort/podd0544205-72df-11e8-b691-080027c5d95e/84ad0790d137467a41a21d7fb29b4973f68d4d00e67390454d587da8e5cc292b
2:blkio:/kubepods/besteffort/podd0544205-72df-11e8-b691-080027c5d95e/84ad0790d137467a41a21d7fb29b4973f68d4d00e67390454d587da8e5cc292b
1:name=systemd:/kubepods/besteffort/podd0544205-72df-11e8-b691-080027c5d95e/84ad0790d137467a41a21d7fb29b4973f68d4d00e67390454d587da8e5cc292b
)";

static const char gcg_cg2_only[] = "0::/kubepods/besteffort/podd0544205-72df-11e8-b691-080027c5d95e/84ad0790d137467a41a21d7fb29b4973f68d4d00e67390454d587da8e5cc292b";

static const char *gtest_proc_cgroup_arr[] = {gcg_k8s, gcg_centos7, gcg_lxc, gcg_nocg, gcg_no_net, gcg_cg2_only};
static const char *gtest_proc_cgroup_info_arr[] = {"k8s", "centos 7 4.17", "lxc", "no cgroup mounts", "missing net cgroups", "only cgroupv2"};

