#! /bin/bash

if [ $# -lt 4 ]; then
	printf '\n\nUsage : ./test_multi_partha.sh <Number of partha hosts> <Test Dest Dir e.g. /tmp> <Start Partha Number : e.g. 1> <Partha Config File>\n\n'
	exit 1
fi	

if [ ! -f ./partha ] || [ ! -f ./runpartha.sh ]; then
	printf "\n\nERROR : Please run this script from a valid Partha install dir...\n\n"
	exit 1
fi	

sudo ps &> /dev/null

if [ $? -ne 0 ]; then
	printf "\n\nPlease run as sudo...\n\n"
	exit 1
fi	

NUMPARTHA=$1
DEST_DIR="$2/testpartha"
STARTID=$3
CFG=$4

if [ ! -f $CFG ]; then
	printf "\n\nERROR : Partha Config File $CFG not found.\n\n"
	exit 1
fi	

mkdir $DEST_DIR 2> /dev/null

for i in `seq $STARTID $(( $STARTID + $NUMPARTHA ))`;do 
	PARID=`printf "%016u%016u" 1 $i`
	PARHOST="test${i}.local"
	PARDIR=$DEST_DIR/partha_${PARID}

	mkdir -p $PARDIR/{cfg,log,tmp} 2> /dev/null

	\rm -f $PARDIR/log/*.log 2> /dev/null
	 
	ln -s /dev/null $PARDIR/log/partha.log
	ln -s /dev/null $PARDIR/log/parmon.log

	cp -a `pwd`/{lib,partha,runpartha.sh} $PARDIR 2> /dev/null

	sudo -n setcap cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_ipc_lock,cap_kill,cap_mac_admin,cap_mknod,cap_sys_chroot,cap_sys_resource,cap_setpcap,cap_sys_ptrace,cap_sys_admin,cap_net_admin,cap_net_raw,cap_sys_module+ep $PARDIR/partha || echo

	cp -f $CFG $PARDIR/cfg/partha_main.json
	
	printf "\nparid=$PARID\nhost=$PARHOST\n" > $PARDIR/cfg/.__testpartha__.cfg
	
	printf "\nStarting Test Partha Host $PARHOST with PARID $PARID ...\n\n"

	$PARDIR/runpartha.sh start --debuglevel 11
done	

