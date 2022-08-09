#!/usr/bin/env bash

PATH=$PATH:/usr/bin:/sbin:/usr/sbin:.
export PATH

print_start()
{
	echo 
	echo ' Option <start> - To start the shyama components : 

 ./runshyama.sh start <Optional arguments>

 Optional Arguments list :
'
 ./shyama --help 2> /dev/null | egrep -v "Usage :"
}

print_stop()
{
	echo 
	echo ' Option <stop> - To stop the shyama components : 

 ./runshyama.sh stop
'
}

print_restart()
{
	echo 
	echo ' Option <restart> - To restart the shyama components : 

 ./runshyama.sh restart
'
}


print_ps()
{
	echo
	echo ' Option <ps> -	To check the PID status of shyama components

 ./runshyama.sh ps
'
}

print_version()
{
	echo
	echo ' Option <version OR -v OR --version> - To get the Version information :

 ./runshyama.sh version OR ./runshyama.sh -v OR ./runshyama.sh --version
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
print_configure
print_version

print_complete_set

}

# ----------------  Help functions end for commands available ------------------------


GLOB_PRINT_PID=0

gy_pgrep()
{
	PROCNAME=$1

	GLOB_PGREP_PID=""
	
	PIDLIST=`pgrep -x $PROCNAME`

	IS_FOUND=`
		for i in $PIDLIST; do	
			CDIR=$( readlink /proc/self/cwd )
			IDIR=$( readlink /proc/${i}/cwd 2> /dev/null )

			echo $i $CDIR $IDIR  | awk '{if (match($3, $2) == 1) printf("%d ", $1)}'	
		done 
		`


	if [ -n "$IS_FOUND" ]; then
		GLOB_PGREP_PID="$IS_FOUND"
		if [ $GLOB_PRINT_PID -eq 1 ]; then
			printf "$IS_FOUND"
		fi	
	fi
}


shyama_start_validate()
{
	# TODO : Validate config file

	gy_pgrep shyama
	if [ -n "$GLOB_PGREP_PID" ]; then
		printf "\nNOTE : shyama is already running : PID(s) $GLOB_PGREP_PID\n\n"
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

if [ ! -f ./shyama ]; then 
	printf "\n\nERROR : Binary shyama not found in dir $PWD. Please run from a proper install...\n\n"
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

		shyama_start_validate

		printf "\n\tStarting shyama components...\n\n"

		shift 1

		LOGDIR="./log"

		for (( i=0; i<$ARGC_CNT; i++ )); do
			if [ "--nolog" = "${ARGV_ARRAY[${i}]}" ]; then
				LOGDIR=
				break
			elif [ "--logdir" = "${ARGV_ARRAY[${i}]}" ]; then
				LOGDIR="${ARGV_ARRAY[$(( i + 1 ))]}"
				if [ -z "$LOGDIR" ]; then
					LOGDIR="./log"
				fi	
			fi	
		done

		( ./shyama "$@" &) &

		sleep 2

		./runshyama.sh ps

		gy_pgrep shyama
		if [ -z "$GLOB_PGREP_PID" ]; then
			if [ -n "$LOGDIR" ] && [ -f "$LOGDIR"/shyama.log ]; then
				printf "\n\tERROR : shyama process not running. Please check ./log/shyama.log for ERRORs if no errors already printed...\n\n"

				LASTERRS=`tail -100 $LOGDIR/shyama.log | grep ERROR`
				if [ -n "$LASTERRS" ]; then
					printf "\tSnippet of last ERRORs seen : \n\n$LASTERRS\n\n"
				fi
			fi
		fi

		exit 0

		;;

	
	stop)

		printf "\n\tStopping shyama components : "

		gy_pgrep shymon
		[ -n "$GLOB_PGREP_PID" ] && kill $GLOB_PGREP_PID 2> /dev/null

		gy_pgrep shyama
		[ -n "$GLOB_PGREP_PID" ] && kill $GLOB_PGREP_PID 2> /dev/null

		for proc in shyama shymon; do
			for (( i=0; i<30; i++ )); do
				gy_pgrep $proc
				if [ -n "$GLOB_PGREP_PID" ]; then
					sleep 1
					continue
				else
					break
				fi
			done

			gy_pgrep $proc
			if [ -n "$GLOB_PGREP_PID" ]; then
				printf "\n\t[ERROR]: shyama process $GLOB_PGREP_PID not yet exited. Sending SIGKILL...\n\n"
				kill -KILL $GLOB_PGREP_PID
			fi	
		done

		printf "\n\n\tStopped all components successfully...\n\n"

		exit 0

		;;


	ps)

		printf "\n\tPID status of shyama package components : "

		GLOB_PRINT_PID=1

		printf "\n\n\tshyama PID(s) : "
		gy_pgrep shyama
		
		PAPID="$GLOB_PGREP_PID"

		printf "\n\n\tshymon PID : "
		gy_pgrep shymon

		PMPID="$GLOB_PGREP_PID"

		if [ -n "$PAPID" ] && [ -n "$PMPID" ]; then
			printf "\n\n\n\tAll Components Running : Yes\n\n"
		else
			printf "\n\n\n\tAll Components Running : No\n\n"
		fi	

		exit 0

		;;

	printpids)
		shift

		GLOB_PRINT_PID=1
		
		gy_pgrep ${1:-"shyama"}

		exit 0;
		;;

	restart)
	
		shift 

		./runshyama.sh stop && sleep 1 && ./runshyama.sh start "$@"

		exit $?
		;;

	-v | --version)

		./shyama --version

		;;

	*)
		printusage
		exit 1

		;;
esac

exit 0

