
include ../Makefile.common

INC_MAKE_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

include ../Makefile.bcc

CXXFLAGS += -UNDEBUG

POSTGRES_LIBS := $(POSTGRES_HOME)/lib/libpq.a $(POSTGRES_HOME)/lib/libpgport.a $(POSTGRES_HOME)/lib/libpgcommon.a

CPPFLAGS += -I$(POSTGRES_HOME)/include/

%.o: %.cc
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c -o $@ $<	

$(CXXSRCS:.cc=.d):%.d:%.cc
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -MM $< >$@

-include $(CXXSRCS:.cc=.d)

EXTRALDLIBS = -rdynamic -static-libgcc -static-libstdc++ -ldl

BINARIES := tcptracer tcpresponse test_caps test_ipaddr test_inet_diag test_timeseries_hist test_threadlocal test_rcu test_rcu_hashtable \
		test_namespaces test_cpubitset test_procsys test_mountinfo test_misc taskmon task_cgroup_monitor hardware_config test_str_wr_buf \
		test_shared_ptr test_shared_ptr2 test_prio1 test_exceptions test_stack test_stack_map test_tmpl_str test_boost_intrusive \
		iflink_info test_pcap_capture test_dns_parser tcp_sock_monitor test_mpmcqueue test_logging test_settings test_malloc_sz test_sock_queued \
		test_timezone test_taskstats test_quantiles test_histogram test_utf8 test_sys_stats test_tcp_client test_tcp_server test_str_rd_buf \
		test_rcu_list test_multi_proc_comm test_listener test_gy_pool test_strncpy test_sso_string test2_rcu_hashtable	\
		test_rapidjson test_bufcache test_pg1 test_postgres_qry test_postgres_insert test_filterparse test_re2 test_tinyregex test_in_clause \
		test_criterion1 test_options test_boolparse test_boost_rolling_sum test_libcurl test_cloud_metadata

.PHONY: all libpath clean distclean install ci

all: gitignores $(BINARIES)

gitignores:
	@-echo " $(BINARIES)" | sed "s/ /\\n/g" > .gitignore

tcptracer: tcptracer.o nlhandler.o $(INC_MAKE_DIR)/common/gy_no_partha_server.o $(INC_MAKE_DIR)/common/libgycommon.a
	$(CXX) $(CXXFLAGS) $(EXTRALDLIBS) $^ $(BCCLIBS) $(LDLIBS) -o $@

tcpresponse: tcpresponse.o $(INC_MAKE_DIR)/common/gy_no_partha_server.o $(INC_MAKE_DIR)/common/libgycommon.a
	$(CXX) $(CXXFLAGS) $(EXTRALDLIBS) $^ $(BCCLIBS) $(LDLIBS) -o $@

test_caps: test_caps.o $(INC_MAKE_DIR)/common/libgycommon.a
	$(CXX) $(CXXFLAGS) $^ $(LDLIBS) -lcap -o $@
	sudo -n setcap cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_ipc_lock,cap_kill,cap_mac_admin,cap_mknod,cap_sys_chroot,cap_sys_resource,cap_setpcap,cap_sys_ptrace,cap_sys_admin,cap_net_admin,cap_net_raw,cap_sys_module+ep $@ || echo

tcp_sock_monitor: tcp_sock_monitor.o $(INC_MAKE_DIR)/common/gy_no_partha_server.o $(INC_MAKE_DIR)/common/libgycommon.a
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ $(EXTRALDLIBS) $(BCCLIBS) $(LDLIBS) -o $@
	sudo -n setcap cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_ipc_lock,cap_kill,cap_mac_admin,cap_mknod,cap_sys_chroot,cap_sys_resource,cap_setpcap,cap_sys_ptrace,cap_sys_admin,cap_net_admin,cap_net_raw,cap_sys_module+ep $@ || echo

task_cgroup_monitor: task_cgroup_monitor.o $(INC_MAKE_DIR)/common/gy_no_partha_server.o $(INC_MAKE_DIR)/common/libgycommon.a
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ $(EXTRALDLIBS) $(LDLIBS) -o $@

test_procsys: test_procsys.o $(INC_MAKE_DIR)/common/gy_no_partha_server.o $(INC_MAKE_DIR)/common/libgycommon.a
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ $(EXTRALDLIBS) $(LDLIBS) -o $@

taskmon: taskmon.o $(INC_MAKE_DIR)/common/gy_no_partha_server.o $(INC_MAKE_DIR)/common/libgycommon.a
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ $(EXTRALDLIBS) $(LDLIBS) -o $@

test_sys_stats: test_sys_stats.o $(INC_MAKE_DIR)/common/gy_no_partha_server.o $(INC_MAKE_DIR)/common/libgycommon.a
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ $(EXTRALDLIBS) $(LDLIBS) -o $@

test_mountinfo: test_mountinfo.o $(INC_MAKE_DIR)/common/gy_no_partha_server.o $(INC_MAKE_DIR)/common/libgycommon.a
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ $(EXTRALDLIBS) $(LDLIBS) -o $@

test_misc: test_misc.o $(INC_MAKE_DIR)/common/gy_no_partha_server.o $(INC_MAKE_DIR)/common/libgycommon.a
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ $(EXTRALDLIBS) $(LDLIBS) -o $@

hardware_config: hardware_config.o $(INC_MAKE_DIR)/common/gy_no_partha_server.o $(INC_MAKE_DIR)/common/libgycommon.a
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ $(EXTRALDLIBS) $(LDLIBS) -o $@

test_dns_parser: test_dns_parser.o $(INC_MAKE_DIR)/common/gy_no_partha_server.o $(INC_MAKE_DIR)/common/libgycommon.a
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ $(EXTRALDLIBS) $(LDLIBS) -o $@

test_pg1: test_pg1.o $(INC_MAKE_DIR)/common/libgycommon.a
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ $(LDLIBS) $(POSTGRES_LIBS) -o $@

test_postgres_qry: test_postgres_qry.o $(INC_MAKE_DIR)/common/libgycommon.a
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ $(LDLIBS) $(POSTGRES_LIBS) -o $@

test_postgres_insert: test_postgres_insert.o $(INC_MAKE_DIR)/common/libgycommon.a
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ $(LDLIBS) $(POSTGRES_LIBS) -o $@

test_shared_ptr2: test_shared_ptr2.o
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ $(EXTRALDFLAGS) -o $@

test_exceptions: test_exceptions.o $(INC_MAKE_DIR)/common/libgycommon.a
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ $(LDLIBS) -o $@

test_shared_ptr: test_shared_ptr.o $(INC_MAKE_DIR)/common/libgycommon.a
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ $(LDLIBS) -o $@

test_prio1: test_prio1.o
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ $(EXTRALDFLAGS) -o $@

test_stack: test_stack.o $(INC_MAKE_DIR)/common/libgycommon.a
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^  $(LDLIBS) -o $@

test_stack_map: test_stack_map.o $(INC_MAKE_DIR)/common/libgycommon.a
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ $(LDLIBS) -o $@


clean:
	rm -f *.o core core.* vgcore.* *.da *.bb *.bbg *.gcda *.gcno *.d .depend $(BINARIES)

cleaninstall::
	$(MAKE) clean && $(MAKE) -j 3 

ci:
	$(MAKE) cleaninstall

ciprof:
	$(MAKE) ci profile=yes
