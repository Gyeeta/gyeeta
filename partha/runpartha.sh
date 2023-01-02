#!/usr/bin/env bash

PATH=$PATH:/usr/bin:/sbin:/usr/sbin:.
export PATH

print_start()
{
	echo 
	echo ' Option <start> - To start the partha components : 

 ./runpartha.sh start <Optional arguments>

 Optional Arguments list :
'
 ./partha-bpf --help 2> /dev/null | egrep -v "Usage :"
}

print_stop()
{
	echo 
	echo ' Option <stop> - To stop the partha components : 

 ./runpartha.sh stop
'
}

print_restart()
{
	echo 
	echo ' Option <restart> - To restart the partha components : 

 ./runpartha.sh restart
'
}


print_ps()
{
	echo
	echo ' Option <ps> -	To check the PID status of partha components

 ./runpartha.sh ps
'
}

print_version()
{
	echo
	echo ' Option <version OR -v OR --version> - To get the Version information :

 ./runpartha.sh version OR ./runpartha.sh -v OR ./runpartha.sh --version
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

	IS_FOUND=`./partha-bpf --exepath $PIDLIST`

	if [ -n "$IS_FOUND" ]; then
		GLOB_PGREP_PID="$IS_FOUND"
		if [ $GLOB_PRINT_PID -eq 1 ]; then
			printf "$IS_FOUND"
		fi	
	fi
}

IS_VALID_HOSTIP=0

validate_iphost()
{
	HOSTSTR=$1

	IS_VALID_HOSTIP=0

	ERRORSTRING=`./partha-bpf --validdomain $HOSTSTR`
	ISRET=$?

	if [ $ISRET -eq 0 ]; then
		IS_VALID_HOSTIP=1
	else
		IS_VALID_HOSTIP=0
	fi

	return
}

get_shyama_ip_port()
{
	LISTIP_PORT=

	while `true`; do
		printf "\nPlease enter the IP Address or Hostname of the Shyama server : "
		read answer

		answer=`echo $answer | sed "s/ *//g"`

		validate_iphost $answer
		if [ $IS_VALID_HOSTIP -ne 1 ]; then
			printf "\nERROR : Invalid address $answer : $ERRORSTRING. Please specify a proper IP address or hostname...\n"
			continue
		fi

		LISTIP_PORT=$answer
		break
	done

	while `true`; do
		printf "\nPlease enter the corresponding Server TCP Port : "
		read answer
		
		if [ x"$answer" = "x" ]; then
			continue
		else
			answer=`echo $answer | sed "s/ *//g"`

			IS_CORR=""

			case $answer in
				''|*[!0-9]*) IS_CORR="\nPlease enter a valid TCP Port..." ;;
				*) ;;
			esac

			if [ "x""$IS_CORR" != "x" ]; then
				printf "$IS_CORR\n"
				continue
			fi

			if [ $answer -lt 1 ] || [ $answer -gt 65535 ]; then
				printf "\nERROR : Invalid TCP Port $answer specified. Please specify a proper port...\n\n"
				continue
			fi	
		fi

		LISTIP_PORT="$LISTIP_PORT"" ""$answer"

		break
	done
}


partha_start_validate()
{
	# TODO : Validate config file

	gy_pgrep partha-b..

	if [ -n "$GLOB_PGREP_PID" ]; then
		printf "\nNOTE : partha is already running : PID(s) $GLOB_PGREP_PID\n\n"
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

if [ ! -f ./partha-bpf ]; then 
	printf "\n\nERROR : Binary partha-bpf not found in dir $PWD. Please run from a proper install...\n\n"
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

		partha_start_validate

		printf "\n\tStarting partha components...\n\n"

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

		( ./partha-bpf --trybcc "$@" &) &

		sleep 2

		./runpartha.sh ps

		gy_pgrep partha-b..
		if [ -z "$GLOB_PGREP_PID" ]; then
			if [ -n "$LOGDIR" ] && [ -f "$LOGDIR"/partha.log ]; then
				printf "\n\tERROR : partha process not running. Please check ./log/partha.log for ERRORs if no errors already printed...\n\n"

				LASTERRS=`tail -100 $LOGDIR/partha.log | grep ERROR`
				if [ -n "$LASTERRS" ]; then
					printf "\tSnippet of last ERRORs seen : \n\n$LASTERRS\n\n"
				fi
			fi
		fi

		exit 0

		;;

	
	stop)

		printf "\n\tStopping partha components : "

		gy_pgrep partha-b..
		[ -n "$GLOB_PGREP_PID" ] && kill $GLOB_PGREP_PID 2> /dev/null

		gy_pgrep parmon
		[ -n "$GLOB_PGREP_PID" ] && kill $GLOB_PGREP_PID 2> /dev/null

		printf "\n\n"

		for proc in partha-bpf partha-bcc parmon; do
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
				printf "\n\t[ERROR]: partha process $GLOB_PGREP_PID not yet exited. Sending SIGKILL...\n\n"
				kill -KILL $GLOB_PGREP_PID
			fi	
		done

		printf "\n\tStopped all components successfully...\n\n"

		exit 0

		;;

	ps)

		printf "\n\tPID status of partha package components : "

		GLOB_PRINT_PID=1

		printf "\n\n\tpartha PID(s) : "
		gy_pgrep partha-b..
		
		PAPID="$GLOB_PGREP_PID"

		printf "\n\n\tparmon PID : "
		gy_pgrep parmon

		PMPID="$GLOB_PGREP_PID"

		if [ -n "$PAPID" ] && [ -n "$PMPID" ]; then
			printf "\n\n\n\tAll Components Running 		: Yes"
		else
			printf "\n\n\n\tAll Components Running 		: No"
		fi	

		if [ -n "$PAPID" ]; then

			ONEPID=$( echo "$PAPID" | awk '{print $1}' )
			PGREPOUT=$( pgrep -x -a partha-b.. | grep "$ONEPID" )

			TMPDIR=$( echo "$PGREPOUT" | awk -F"--tmpdir" '{print $2}' | awk '{print $1}' )
			if [ -z "$TMPDIR" ]; then
				TMPDIR="./tmp"
			fi
			SERVER_STATUS_LOG=${TMPDIR}/server_conn_status.log

			sleep 1

			printf "\n\n\tServer Connectivity Status 	: "

			for (( i=0; i<5; i++ )); do
				if [ `cat $SERVER_STATUS_LOG 2> /dev/null | wc -c` -lt 2 ]; then
					printf "."
					sleep 1
				else
					cat $SERVER_STATUS_LOG 2> /dev/null
					printf "\n\n"
					break
				fi	
			done	

			if [ `cat $SERVER_STATUS_LOG 2> /dev/null | wc -c` -lt 2 ]; then
				printf " : No status updated by partha yet. Please try later...\n\n";
			fi	
		else
			printf "\n\n\tServer Connectivity Status : Not connected\n\n"
		fi

		exit 0

		;;

	printpids)
		shift

		GLOB_PRINT_PID=1
		
		gy_pgrep ${1:-"partha-b.."}

		exit 0;
		;;

	restart)
	
		shift 

		./runpartha.sh stop && sleep 1 && ./runpartha.sh start "$@"

		exit $?
		;;

	-v | --version)

		./partha-bpf --version

		;;

	*)
		printusage
		exit 1

		;;
esac

exit 0

