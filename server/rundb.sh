#!/bin/bash

PATH=$PATH:/usr/bin:/sbin:/usr/sbin:.
export PATH

print_start()
{
	echo 
	echo ' Option <start> - To start the Gyeeta Postgres DB : 

 ./rundb.sh start
'
}

print_stop()
{
	echo 
	echo ' Option <stop> - To stop the Gyeeta Postgres DB components : 

 ./rundb.sh stop
'
}

print_restart()
{
	echo 
	echo ' Option <restart> - To restart the Gyeeta Postgres DB components : 

 ./rundb.sh restart
'
}


print_ps()
{
	echo
	echo ' Option <ps> -	To check the PID status of Gyeeta Postgres DB components

 ./rundb.sh ps
'
}

print_version()
{
	echo
	echo ' Option <version OR -v OR --version> - To get the Version information :

 ./rundb.sh version OR ./rundb.sh -v OR ./rundb.sh --version
'
}

print_complete_set()
{
printf "\n\n		Complete Set of Options : \n"

printf "	
	ps 	restart 	start		stop 	version 

	For Help on any option : please type 
	
	$0 help <Option>

	e.g. $0 help start

"

}

printusage()
{
printf "\n\n ------------------  Usage  -------------------\n"
print_start
print_stop
print_ps
print_version

print_complete_set

}

# ----------------  Help functions end for commands available ------------------------


GLOB_PRINT_PID=0

gy_pgrep()
{
	GLOB_PGREP_PID=""
	
	IS_FOUND=`./bin/pg_ctl -D $( cat ./cfg/dbdir.cfg ) status 2>&1 | grep "server is running" | awk -F"PID:" '{print $2}' | awk '{printf "%u", $1}'`

	if [ -n "$IS_FOUND" ]; then
		GLOB_PGREP_PID="$IS_FOUND"
		if [ $GLOB_PRINT_PID -eq 1 ]; then
			printf "$IS_FOUND"
		fi	
	fi
}


db_start_validate()
{
	gy_pgrep
	if [ -n "$GLOB_PGREP_PID" ]; then
		printf "\nNOTE : Gyeeta Postgres component(s) already running : PID(s) $GLOB_PGREP_PID\n\n"
		printf "Please run \"$0 restart\" if you need to restart the components...\n\n"

		exit 1
	fi
}

if [ $# -lt 1 ]; then
	printusage
	exit 1
fi

umask 0006

DNAME=`dirname $0 2> /dev/null`

if [ $? -eq 0 ]; then
	cd $DNAME
	CURRDIR=`pwd`
fi

if [ ! -f ./cfg/dbdir.cfg ]; then 
	printf "\n\nERROR : DB Data config not found in $PWD/cfg/dbdir.cfg : Please run from a proper install...\n\n"
	exit 1
fi

if [ ! -f ./bin/pg_ctl ]; then 
	printf "\n\nERROR : Required binaries not found in $PWD/bin dir : Please run from a proper install...\n\n"
	exit 1
fi

ARGV_ARRAY=("$@") 
ARGC_CNT=${#ARGV_ARRAY[@]} 
 

case "$1" in 

	help | -h | --help | \?)
		if [ $# -eq 1 ]; then	

			printusage
		else 
			shift

			for opt in $*;
			do	
				print_"$opt" 2> /dev/null
				if [ $? -ne 0 ]; then
					printf "\nERROR : Invalid Option $opt...\n\n"
					exit 1
				fi

				shift
			done
		fi

		;;

	start) 

		db_start_validate

		printf "\n\tStarting Gyeeta Postgres DB components...\n\n"

		shift 1

		./bin/pg_ctl -D $( cat ./cfg/dbdir.cfg ) start

		./rundb.sh ps

		gy_pgrep 
		if [ -z "$GLOB_PGREP_PID" ]; then
			printf "\n\tERROR : Gyeeta Postgres DB process not running. Please check log for ERRORs if no errors already printed...\n\n"
			exit 1
		fi

		exit 0

		;;

	
	stop)

		printf "\n\tStopping Gyeeta Postgres DB components : "

		gy_pgrep 
		[ -n "$GLOB_PGREP_PID" ] && ./bin/pg_ctl -D $( cat ./cfg/dbdir.cfg ) stop 2> /dev/null

		gy_pgrep 
		if [ -n "$GLOB_PGREP_PID" ]; then
			sleep 3
			gy_pgrep 
			
			if [ -n "$GLOB_PGREP_PID" ]; then
				printf "\n\t[ERROR]: Gyeeta Postgres process $GLOB_PGREP_PID not yet exited. Sending SIGKILL...\n\n"
				kill -KILL $GLOB_PGREP_PID
			fi	
		fi	

		printf "\n\n\tStopped all components successfully...\n\n"

		exit 0

		;;

	ps)

		printf "\n\tPID status of Gyeeta Postgres DB package components : "

		GLOB_PRINT_PID=1

		printf "\n\n\tGyeeta Postgres PID(s) : "
		gy_pgrep 
		
		if [ -n "$GLOB_PGREP_PID" ]; then
			printf "\n\n\n\tAll Components Running : Yes\n\n"
		else
			printf "\n\n\n\tAll Components Running : No\n\n"
		fi	

		exit 0

		;;

	restart)
	
		shift 

		./rundb.sh stop && sleep 1 && ./rundb.sh start "$@"

		exit $?
		;;

	-v | --version)

		./bin/postgres --version
		
		;;

	*)
		printusage
		exit 1

		;;
esac

exit 0

