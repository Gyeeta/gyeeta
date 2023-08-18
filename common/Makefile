
include ../Makefile.common

include ../Makefile.bcc


.DEFAULT_GOAL := libgycommon.a

MKFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
CURRENT_DIR := $(notdir $(patsubst %/,%,$(dir $(MKFILE_PATH))))

CPPFLAGS += -I$(POSTGRES_HOME)/include/

AR := ar
ARFLAGS := rcs

CXXSRCS = gy_file_api.cc gy_pkt_pool.cc gy_rcu.cc gy_task_handler.cc				\
		gy_task_stat.cc gy_mount_disk.cc gy_cgroup_stat.cc gy_async_func.cc		\
		gy_scheduler.cc gy_sys_hardware.cc gy_netif.cc gy_pcap_read.cc			\
		gy_network_capture.cc gy_dns_mapping.cc gy_socket_stat.cc			\
		gy_init_proc.cc gy_msg_comm.cc gy_print_offload.cc gy_acct_taskstat.cc		\
		gy_sys_stat.cc gy_multi_proc_comm.cc gy_listen_sock.cc gy_comm_proto.cc		\
		gy_svc_net_capture.cc gy_query_common.cc gy_query_criteria.cc gy_boolparse.cc	\
		gy_alerts.cc gy_openssl_pthr.cc gy_cloud_metadata.cc gy_libbpf.cc		\
		gy_pcap_write.cc gy_elf.cc gy_ssl_cap_util.cc

OBJS = $(CXXSRCS:.cc=.o)

%.o: %.cc
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c -o $@ $<	

$(CXXSRCS:.cc=.d):%.d:%.cc
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -MM $< >$@

-include $(CXXSRCS:.cc=.d)


.PHONY: all clean install cleaninstall ci ciprof

all: libgycommon.a

libgycommon.a: $(OBJS) 
	$(AR) $(ARFLAGS) $@ $^

clean:
	rm -f *.o *.a core core.* vgcore.* *.da *.bb *.bbg *.gcda *.gcno *.d .depend

install::
	$(MAKE) -j 2

cleaninstall::
	$(MAKE) clean && $(MAKE) -j 2

ci:
	$(MAKE) cleaninstall

ciprof:
	$(MAKE) ci profile=yes


