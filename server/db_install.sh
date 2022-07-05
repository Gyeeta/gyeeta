#!/bin/bash

PATH=$PATH:/usr/bin:/sbin:/usr/sbin:.
export PATH

if [ $# -ne 3 ]; then
	printf "\nUsage : $0 <DB Data directory> <db user 'postgres' password> <Postgres Port to Listen on>\n\n"
	exit 1
fi	

if [ ! -f ./bin/pg_ctl ]; then
	printf "\n\nERROR : Please run this script from a proper install dir where bin/pg_ctl binary exists\n\n"
	exit 1
fi	

INSTALLDIR=$PWD
DBDIR=$1/gyeetadb/
PASS=$2
PORT=$3
PASSFILE=/tmp/.___gy_pass_"$$".dat

if [ ! -d $DBDIR ]; then
	mkdir -m 0755 -p $DBDIR

	if [ ! -d $DBDIR ]; then
		printf "\n\nERROR : Could not create DB Data dir $DBDIR \n\n"
		exit 1
	fi	
fi	

echo -n "$PASS" > $PASSFILE

if [ $? -ne 0 ]; then
	printf "\n\nERROR : Failed to create a temporary file in $PASSFILE : Please check if write permissions exist for /tmp/ dir\n\n"
	exit 1
fi	

printf "\n\nNow creating new database in $DBDIR directory...\n\n"

./bin/initdb -D $DBDIR --locale=C --pwfile=$PASSFILE -A password --username=postgres

if [ $? -ne 0 ]; then
	rm -f $PASSFILE
	printf "\n\nERROR : Failed to create DB Database : Exiting\n\n"
	exit 1
fi

rm -f $PASSFILE

cp -f ./{postgresql.conf,pg_hba.conf,memory.conf,server.conf} $DBDIR/

if [ $? -ne 0 ]; then
	printf "\n\nERROR : Failed to copy files to DB Data directory\n\n"
	exit 1
fi	

MEMMB=$( cat /proc/meminfo | grep MemTotal | awk -F: '{print $2}' | awk -Fk '{printf "%luMB", $1/1024/5}' )

printf "shared_buffers = $MEMMB\n" > $DBDIR/memory.conf

if [ $? -ne 0 ]; then
	printf "\n\nERROR : Failed to write to file in DB Data directory\n\n"
	exit 1
fi	

printf "port = $PORT\nmax_connections = 500\nlog_directory = '../log'\n" > $DBDIR/server.conf

if [ $? -ne 0 ]; then
	printf "\n\nERROR : Failed to write to file in DB Data directory\n\n"
	exit 1
fi	

echo -n $INSTALLDIR > $DBDIR/gy_install.cfg

if [ $? -ne 0 ]; then
	printf "\n\nERROR : Failed to create a file in DB Data dir\n\n"
	exit 1
fi

echo -n $DBDIR > ./cfg/dbdir.cfg

if [ $? -ne 0 ]; then
	printf "\n\nERROR : Failed to create a file in ./cfg dir : Please check if write permissions exist for that dir\n\n"
	exit 1
fi	

printf "\n\nInstalled Postgres DB with DB Dir $DBDIR successfully : To start the DB please run ./rundb.sh start : To connect to DB username is \'postgres\' password is \'$PASS\'\n\n"

exit 0

