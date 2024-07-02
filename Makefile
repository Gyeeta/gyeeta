
include ./Makefile.llvm

.PHONY: compile clean install cleaninstall tags ci

all: compile

compile:
	$(MAKE) -C $(PWD)/common && $(MAKE) -C $(PWD)/partha && $(MAKE) -C $(PWD)/server

clean:
	$(MAKE) -C $(PWD)/common clean && $(MAKE) -C $(PWD)/partha clean && $(MAKE) -C $(PWD)/server clean

install:
	$(MAKE) -C $(PWD)/common install && $(MAKE) -C $(PWD)/partha install && $(MAKE) -C $(PWD)/server install && ./scripts/checkinstall.sh --check 

cleaninstall:
	$(MAKE) -C $(PWD)/common cleaninstall && $(MAKE) -C $(PWD)/partha cleaninstall && $(MAKE) -C $(PWD)/server cleaninstall 

ci:
	$(MAKE) cleaninstall

ciprof:
	$(MAKE) ci profile=yes

test:
	$(MAKE) -C $(PWD)/test ciprof 

tags:	
	$(shell set -x; rm -f ./tags 2> /dev/null; find `pwd` `pwd`/../privgyeeta $(BCC_BASE_DIR) $(LIBBPF_DIR) \( -name \*.c -o -name \*.h -o -name \*.cc -o -name \*.cpp -o -name \*.C -o -name \*.cxx -o -name \*.H -o -name \*.hpp -o -name \*.hh -o -name \*.hxx -o -name \*.py -o -name \*.java -o -name \*.go -o -name \*.lua -o -name \*.rs -o -name \*.swift -o -name \*.php -o -name \*.sh -o -name \*.bash \) -a -type f | ctags -a --sort=yes -L-)
	@echo
