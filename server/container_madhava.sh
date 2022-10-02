#!/usr/bin/env bash

PATH=$PATH:/usr/bin:/sbin:/usr/sbin:.
export PATH

if [ ! -f /madhava/madhava ]; then
	echo -e "\n\nERROR : Invalid madhava container image as /madhava/madhava binary not found...\n\n"
	exit 1
fi

check_processor()
{
	if [ $( cat /proc/cpuinfo | grep -w flags | grep -ic avx ) -eq 0 ]; then
		echo -e "\n\nERROR : This container can run on hosts with processors having avx instruction support (Intel Sandybridge (2012) or above).\n\nYour processor seems to be a very old one. Please install on a machine with a newer processor.\n\nExiting ...\n\n"
		exit 1
	fi
}

check_processor

cd /madhava

./madhava --version &> /dev/null

if [ $? -ne 0 ]; then
	echo -e "\n\nERROR : Failed to execute madhava binary. Exiting... : Error is `./madhava --version`\n\n"
	exit 1
fi	

trap 'echo "	Exiting now... Cleaning up..."; ./runmadhava.sh stop; exit 0' SIGINT SIGQUIT SIGTERM

CMD=${1:-"start"}

shift

TLOGTMP=

if [ "$CMD" = "start" ] || [ "$CMD" = "restart" ]; then
	if [ ! -d /hostdata ]; then
		echo -e "\n\nERROR : Volume mount dir /hostdata not found. Please run with a Volume mounted at /hostdata. Exiting...\n\n"
		exit 1
	fi

	if [ ! -d /hostdata/log ]; then
		mkdir -m 0777 /hostdata/log
	fi	
		
	if [ ! -d /hostdata/tmp ]; then
		mkdir -m 0777 /hostdata/tmp
	fi	

	if [ ! -d /hostdata/reports ]; then
		mkdir -m 0777 /hostdata/reports
	fi	

	if [ ! -d /hostdata/log ] || [ ! -d /hostdata/tmp ] || [ ! -d /hostdata/reports ]; then
		echo -e "\n\nERROR : Failed to create /hostdata/log or /hostdata/tmp or /hostdata/reports directories. Exiting...\n\n"
		exit 1
	fi

	# Handle Kubernetes Statefulset Replica Madhava Name as Replica Index not available directly
	if [ -n "$GY_SET_MADHAVA_NAME" ] && [ -n "$GY_POD_NAME" ] && [ -z "$CFG_MADHAVA_NAME" ]; then
		export CFG_MADHAVA_NAME="${GY_SET_MADHAVA_NAME}"_$( echo -n ${GY_POD_NAME##*-} )
	fi

	TLOGTMP='--logdir /hostdata/log --tmpdir /hostdata/tmp --reportsdir /hostdata/reports'
fi	

./runmadhava.sh "$CMD" "$@" $TLOGTMP < /dev/null

if [ "$CMD" = "start" ] || [ "$CMD" = "restart" ]; then
	sleep 10

	if [ "x""`./runmadhava.sh printpids madhava`" = "x" ]; then
		echo -e "\n\nERROR : madhava not running currently. Exiting...\n\n"
		exit 1
	fi	

	NRESTART=0

	while `true`; do
		sleep 30

		./runmadhava.sh ps

		echo -e "Latest madhava.log snippet : \n\n"

		tail -10 /hostdata/log/madhava.log 2> /dev/null

		if [ "x""`./runmadhava.sh printpids madhava`" = "x" ]; then
			sleep 10
			
			if [ "x""`./runmadhava.sh printpids madhava`" = "x" ]; then
				NRESTART=$(( $NRESTART + 1 ))

				if [ $NRESTART -lt 100 ]; then
					echo -e "\n\nERROR : madhava not running currently. Will try restarting... : Total restarts $NRESTART\n\n"
					./runmadhava.sh start "$@" $TLOGTMP < /dev/null
				else
					echo -e "\n\nERROR : madhava not running currently. Too many restarts seen $NRESTART : Exiting now...\n\n"
					exit 1
				fi	
			fi
		fi	

	done	

	# Wait indefinitely
	read /dev/null

fi

exit $?

