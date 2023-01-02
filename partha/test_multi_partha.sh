#! /bin/bash

if [ $# -lt 4 ]; then
	printf '\n\nUsage : ./test_multi_partha.sh <Number of partha hosts> <Test Dest Dir e.g. /tmp> <Start Partha Number : e.g. 1> <Partha Config File>\n\n'
	exit 1
fi	

if [ ! -f ./partha-bpf ] || [ ! -f ./partha-bcc ] || [ ! -f ./runpartha.sh ]; then
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

	cp -a ../install/partha/* $PARDIR 2> /dev/null

	\rm -f $PARDIR/log/*.log 2> /dev/null
	 
	ln -s /dev/null $PARDIR/log/partha.log
	ln -s /dev/null $PARDIR/log/parmon.log
	ln -s /dev/null $PARDIR/log/partha_cmd_child.log

	cd $PARDIR

	./setperm.sh

	cd -

	cp -f $CFG $PARDIR/cfg/partha_main.json
	
	printf "\nparid=$PARID\nhost=$PARHOST\n" > $PARDIR/cfg/.__testpartha__.cfg
	
	printf "\nStarting Test Partha Host $PARHOST with PARID $PARID ...\n\n"

	$PARDIR/runpartha.sh start --debuglevel 11
done	

