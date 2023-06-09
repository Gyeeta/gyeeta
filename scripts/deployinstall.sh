#!/bin/bash

if [ -z "$1" ]; then
	echo -e "\n\nUsage : $0 <Install Base Dir>\n\n"
	exit 1
fi	

set -x 

ODIR="$1"
ODIR_SHYAMA="$ODIR"/shyama
ODIR_MADHAVA="$ODIR"/madhava
ODIR_PARTHA="$ODIR"/partha

mkdir -p $ODIR_SHYAMA $ODIR_MADHAVA $ODIR_PARTHA 2> /dev/null

if [ ! -d $ODIR_SHYAMA ] || [ ! -d $ODIR_MADHAVA ] || [ ! -d $ODIR_PARTHA ]; then
	echo -e "\n\nERROR : Failed to create install Gyeeta install dirs\n\n"
	exit 1
fi	

rm -rf $ODIR_SHYAMA $ODIR_MADHAVA $ODIR_PARTHA 2> /dev/null	
	
cp -a ./install/{shyama,madhava,partha} $ODIR/

if [ $? -ne 0 ]; then
	echo -e "\n\nERROR : Failed to copy to Gyeeta install dirs\n\n"
	exit 1
fi

cd $ODIR_PARTHA 

./setperm.sh 

if [ $? -ne 0 ]; then
	echo -e "\n\nERROR : Failed to setcap partha binaries\n\n"
	exit 1
fi

cd -

echo -e "\nInstalled shyama, madhava and partha to $ODIR successfully...\n"

exit 0
