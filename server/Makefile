
include ../Makefile.common

INC_MAKE_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

BASEINSTALLDIR := $(INC_MAKE_DIR)/install/

%.o: %.cc
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c -o $@ $<	

$(CXXSRCS:.cc=.d):%.d:%.cc
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -MM $< >$@

-include $(CXXSRCS:.cc=.d)

EXTRALDLIBS = -rdynamic -static-libgcc -static-libstdc++ -ldl

BINARIES := madhava shyama

.PHONY: all clean distclean install cleaninstall ci

all: $(BINARIES)

MADHAVAOBJS := gymadhava.o gy_mconnhdlr.o gy_mnodehandle.o gy_mdb_schema.o gy_malerts.o mversion.o

SHYAMAOBJS := gyshyama.o gy_shconnhdlr.o gy_shnodehandle.o gy_sdb_schema.o gy_alertmgr.o gy_shalerts.o sversion.o

COMMONOBJS := $(INC_MAKE_DIR)/common/gy_no_partha_server.o 

madhava: $(MADHAVAOBJS) $(COMMONOBJS) $(INC_MAKE_DIR)/common/libgycommon.a
	$(CXX) $(CXXFLAGS) $^ $(EXTRALDLIBS) $(LDLIBS) -o $@

shyama: $(SHYAMAOBJS) $(COMMONOBJS) $(INC_MAKE_DIR)/common/libgycommon.a
	$(CXX) $(CXXFLAGS) $^ $(EXTRALDLIBS) $(LDLIBS) -o $@

install::
	[ -f $(BASEINSTALLDIR)/madhava/runmadhava.sh ] && $(BASEINSTALLDIR)/madhava/runmadhava.sh stop
	[ -f $(BASEINSTALLDIR)/shyama/runshyama.sh ] && $(BASEINSTALLDIR)/shyama/runshyama.sh stop
	cp -p ./madhava ./runmadhava.sh ./container_madhava.sh ./sample_madhava_main.json $(BASEINSTALLDIR)/madhava/
	cp -p ./shyama ./runshyama.sh ./container_shyama.sh ./sample_shyama_main.json $(BASEINSTALLDIR)/shyama/

clean:
	rm -f *.o $(BINARIES) core core.* vgcore.* *.da *.bb *.bbg *.gcda *.gcno *.d .depend


cleaninstall::
	$(MAKE) clean && $(MAKE) -j 2 && $(MAKE) install

ci:
	$(MAKE) cleaninstall

ciprof:
	$(MAKE) ci profile=yes

dockermadhava:
	DOCKER_BUILDKIT=1 docker build -t gyeeta/madhava:latest -f ./Dockerfile.madhava --build-arg MADHAVA_VERSION="v`./madhava --version | grep Version | cut -d " " -f 4`" $(BASEINSTALLDIR)/madhava

dockershyama:
	DOCKER_BUILDKIT=1 docker build -t gyeeta/shyama:latest -f ./Dockerfile.shyama --build-arg SHYAMA_VERSION="v`./shyama --version | grep Version | cut -d " " -f 4`" $(BASEINSTALLDIR)/shyama

