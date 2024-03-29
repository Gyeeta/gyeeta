#!/bin/bash

PATH=$PATH:/usr/bin:/sbin:/usr/sbin:.
export PATH

if [ ! -f /partha/partha-bpf ] ||  [ ! -f /partha/partha-bcc ] || [ ! -f /partha/runpartha.sh ]; then
	echo -e "\n\nERROR : Invalid partha container image as partha binaries not found...\n\n"
	exit 1
elif [ ! -f /partha/check_kernel_hdr.sh ]; then
	echo -e "\n\nERROR : Invalid partha container image as /partha/check_kernel_hdr.sh file not found...\n\n"
	exit 1
fi

check_processor()
{
	PROCINFO=$( cat /proc/cpuinfo )

	if [ $( echo "$PROCINFO" | grep -w flags | grep -ic avx ) -eq 0 ]; then
		echo -e "\n\nERROR : This container can run on hosts with processors having avx instruction support (Intel Sandybridge (2012) or above).\n\nYour processor seems to be a very old one. Please install on a machine with a newer processor.\n\nExiting ...\n\n"
		exit 1
	fi
}


check_linux_kernel_version()
{
	KERN_VER=`uname -r`

	KERN_NUM1=$( echo $KERN_VER | awk -F. '{print $1}' )
	KERN_NUM2=$( echo $KERN_VER | awk -F. '{print $2}' )
	KERN_NUM3=$( echo $KERN_VER | awk -F. '{print $3}' | awk -F- '{print $1}' )

	MIN_VER="4.4.0"

	if [ $KERN_NUM1 -lt 4 ]; then
		printf "ERROR : Host Linux Kernel version $KERN_NUM1 is less than minimum $MIN_VER required for partha. Exiting...\n\n"
		exit 1
	elif [ $KERN_NUM1 -eq 4 ] && [ $KERN_NUM2 -lt 4 ]; then
		printf "ERROR : Host Linux Kernel version $KERN_NUM1 is less than minimum $MIN_VER required for partha. Exiting...\n\n"
		exit 1
	fi
}

check_processor

check_linux_kernel_version

if [ "x""$PPID" = "x1" ] && [ "x"`cat /proc/1/comm` = "xtini" ]; then
	echo -e "\n\nERROR : Partha Container not running in Host PID namespace. If using Docker, please start the container with --pid=host --network=host --cgroupns=host switches. For Kubernetes use hostPID: true and hostNetwork: true.\n\n"
	exit 1
fi	

CAPBND=`capsh --decode=$( cat /proc/self/status | grep CapBnd | awk -F: '{print $2}' | awk '{print $1}' )`

for i in cap_chown cap_dac_override cap_dac_read_search cap_fowner cap_fsetid cap_ipc_lock cap_kill cap_mac_admin cap_mknod cap_sys_chroot cap_sys_resource cap_setpcap cap_sys_ptrace cap_sys_admin cap_net_admin cap_net_raw cap_sys_module cap_setuid; do 
	if [ `echo "$CAPBND" | grep -c $i` -eq 0 ]; then 
		echo -e "\n\nERROR : Partha Container started without required Capabilities ($i). Please start the container with --priviliged flag (For Kubernetes use securityContext: privileged: true).\n\n"
		exit 1
	fi	
done

cd /partha

./partha-bpf --version &> /dev/null

if [ $? -ne 0 ]; then
	echo -e "\n\nERROR : Failed to execute partha binary. Exiting... : Error is `./partha-bpf --version`\n\n"
	exit 1
fi	

trap 'echo "	Exiting now... Cleaning up..."; ./runpartha.sh stop; exit 0' SIGINT SIGQUIT SIGTERM

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

	if [ ! -d /hostdata/log ] || [ ! -d /hostdata/tmp ]; then
		echo -e "\n\nERROR : Failed to create /hostdata/log or /hostdata/tmp directories. Exiting...\n\n"
		exit 1
	fi

	TLOGTMP='--logdir /hostdata/log --tmpdir /hostdata/tmp'

	./check_kernel_hdr.sh 

	if [ $? -ne 0 ]; then
		echo -e "ERROR : Kernel Header check failed. Please install Kernel Headers or Kernel Devel package which provides Kernel Headers needed for eBPF Monitoring. Exiting...\n"
		exit 1
	fi	
fi	

./runpartha.sh "$CMD" "$@" $TLOGTMP < /dev/null

if [ "$CMD" = "start" ] || [ "$CMD" = "restart" ]; then
	sleep 10

	if [ "x""`./runpartha.sh printpids`" = "x" ]; then
		echo -e "\n\nERROR : partha not running currently. Exiting...\n\n"
		exit 1
	fi	

	NRESTART=0

	while true; do
		sleep 30

		./runpartha.sh ps

		echo -e "Latest partha.log snippet : \n\n"

		tail -10 /hostdata/log/partha.log 2> /dev/null

		if [ "x""`./runpartha.sh printpids`" = "x" ]; then
			sleep 10
			
			if [ "x""`./runpartha.sh printpids`" = "x" ]; then
				NRESTART=$(( $NRESTART + 1 ))

				if [ $NRESTART -lt 100 ]; then
					echo -e "\n\nERROR : partha not running currently. Will try restarting... : Total restarts $NRESTART\n\n"
					./runpartha.sh start "$@" $TLOGTMP < /dev/null
				else
					echo -e "\n\nERROR : partha not running currently. Too many restarts seen $NRESTART : Exiting now...\n\n"
					exit 1
				fi	
			fi
		fi	

	done	
fi

exit $?

