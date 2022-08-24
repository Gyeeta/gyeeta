

include ../Makefile.common

include ../Makefile.bcc

INC_MAKE_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

INSTALLDIR := $(INC_MAKE_DIR)/install/partha/

%.o: %.cc
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c -o $@ $<	

$(CXXSRCS:.cc=.d):%.d:%.cc
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -MM $< >$@

-include $(CXXSRCS:.cc=.d)

EXTRALDLIBS = -rdynamic -static-libgcc -static-libstdc++ -ldl

BINARIES := partha

.PHONY: all clean distclean install cleaninstall ci

all: $(BINARIES)

PARTHAOBJS := gypartha.o sversion.o gy_paconnhdlr.o gy_server_int.o sys_hardware_partha.o

partha: $(PARTHAOBJS) $(INC_MAKE_DIR)/common/libgycommon.a
	$(CXX) $(CXXFLAGS) $^ $(EXTRALDLIBS) $(BCCLIBS) $(LDLIBS) -o $@

install:
	[ -f $(INSTALLDIR)/runpartha.sh ] && $(INSTALLDIR)/runpartha.sh stop
	cp -p $(BINARIES) ./runpartha.sh ./container_init.sh ./check_kernel_hdr.sh ./setperm.sh ./sample_partha_main.json $(INSTALLDIR)/
	sudo -n setcap cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_ipc_lock,cap_kill,cap_mac_admin,cap_mknod,cap_sys_chroot,cap_sys_resource,cap_setpcap,cap_sys_ptrace,cap_sys_admin,cap_net_admin,cap_net_raw,cap_sys_module+ep $(INSTALLDIR)/partha || echo


clean:
	rm -f *.o $(BINARIES) core core.* vgcore.* *.da *.bb *.bbg *.gcda *.gcno *.d .depend


cleaninstall::
	$(MAKE) clean && $(MAKE) -j 3 && $(MAKE) install

ci:
	$(MAKE) cleaninstall

ciprof:
	$(MAKE) ci profile=yes

dockerpartha:
	$(shell export DOCKER_BUILDKIT=1; export PARTHA_VERSION="`./partha --version | grep Version | cut -d " " -f 4`"; docker build -t ghcr.io/gyeeta/partha:latest -t ghcr.io/gyeeta/partha:"$${PARTHA_VERSION}" -f ./Dockerfile --build-arg PARTHA_VERSION=v"$${PARTHA_VERSION}" $(INSTALLDIR) )

