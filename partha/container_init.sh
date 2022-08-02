#!/usr/bin/env bash

PATH=$PATH:/usr/bin:/sbin:/usr/sbin:.
export PATH

if [ ! -f /partha/partha ]; then
	echo -e "\n\nERROR : Invalid partha container image as /partha/partha binary not found...\n\n"
	exit 1
fi

CAPBND=`capsh --decode=$( cat /proc/self/status | grep CapBnd | awk -F: '{print $2}' | awk '{print $1}' )`

for i in cap_chown cap_dac_override cap_dac_read_search cap_fowner cap_fsetid cap_ipc_lock cap_kill cap_mac_admin cap_mknod cap_sys_chroot cap_sys_resource cap_setpcap cap_sys_ptrace cap_sys_admin cap_net_admin cap_net_raw cap_sys_module; do 
	if [ `echo "$CAPBND" | grep -c $i` -eq 0 ]; then 
		echo -e "\n\nERROR : Partha Container started without required Capabilities ($i). Please start the container with --priviliged flag (For Kubernetes use securityContext: privileged: true).\n\n"
		exit 1
	fi	
done

cd /partha

./partha --version &> /dev/null

if [ $? -ne 0 ]; then
	echo -e "\n\nERROR : Failed to execute partha binary. Exiting... : Error is `./partha --version`\n\n"
	exit 1
fi	

trap 'echo "	Exiting now... Cleaning up..."; ./runpartha.sh stop; exit 0' SIGINT SIGQUIT SIGTERM

CMD=${1:-"start"}

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

	if [ ! -d /hostdata/log ] || [ ! -d /hostdata/tmp ]; then
		echo -e "\n\nERROR : Failed to create /hostdata/log or /hostdata/tmp directories. Exiting...\n\n"
		exit 1
	fi

	if [ -d /hostdata/log ]; then
		TLOGTMP='--logdir /hostdata/log --tmpdir /hostdata/tmp'
	fi
fi	

./runpartha.sh ${@:-"start"} $TLOGTMP < /dev/null

if [ "$CMD" = "start" ] || [ "$CMD" = "restart" ]; then
	sleep 10

	if [ "x""`./runpartha.sh printpids partha`" = "x" ]; then
		echo -e "\n\nERROR : partha not running currently. Exiting...\n\n"
		exit 1
	fi	

	while `true`; do
		sleep 30

		./runpartha.sh ps

		echo -e "Latest partha.log snippet : \n\n"

		tail -10 /hostdata/log/partha.log 2> /dev/null

		if [ "x""`./runpartha.sh printpids partha`" = "x" ]; then
			sleep 10
			
			if [ "x""`./runpartha.sh printpids partha`" = "x" ]; then
				echo -e "\n\nERROR : partha not running currently. Will try restarting...\n\n"
				./runpartha.sh start $TLOGTMP < /dev/null
			fi
		fi	

	done	

	# Wait indefinitely
	read /dev/null

fi

exit $?

