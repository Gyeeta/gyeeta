#!/bin/bash

HOST_ROOT=/proc/1/root/

KERN_VER=`uname -r`
KERNARR=( $( echo "$KERN_VER" | sed "s/[\.-]/ /g" ) )
KAPIVER="${KERNARR[0]}.${KERNARR[1]}.${KERNARR[2]}-${KERNARR[3]}"

get_config() 
{
	if [ -f /proc/config.gz ]; then
		KERNCONFIG=$( zcat /proc/config.gz )
	elif [ -f "${HOST_ROOT}/boot/config-${KERN_VER}" ]; then
		KERNCONFIG=$( cat "${HOST_ROOT}/boot/config-${KERN_VER}" )
	elif [ -f "/lib/modules/${KERN_VER}/build/.config" ]; then
		KERNCONFIG=$( cat "/lib/modules/${KERN_VER}/build/.config" )
	elif [ -f "${HOST_ROOT}/usr/lib/ostree-boot/config-${KERN_VER}" ]; then
		KERNCONFIG=$( cat "${HOST_ROOT}/usr/lib/ostree-boot/config-${KERN_VER}" )
	else
		echo -e "\n\nERROR : Could not find Kernel Config file.\n\n"
		exit 1
	fi

	BPFOPTS=( "_BPF=y" "BPF_SYSCALL=y" "BPF_JIT=y" "BPF_EVENTS=y" )

	for bopt in "${BPFOPTS[@]}"; do 
		if [ `echo "$KERNCONFIG" | grep -c "$bopt"` = 0 ]; then
			echo -e "\n\nERROR : BPF Kernel Config option $bopt missing. Please enable eBPF in Kernel first...\n\n"
			exit 1
		fi	
	done	
}

if [ -f "/lib/modules/${kern_ver}/build/include/net/tcp.h" 2> /dev/null ]; then
	get_config

	echo -e "\nLinux kernel headers already mounted. No additional action needed...\n\n"
	exit 0
fi	

# Check if host mount point exists with the kernel headers
if [ -f "/hostdata/modules/${KERN_VER}/build/include/net/tcp.h" ]; then

	ln -sf /hostdata/modules/ /hostdata/kernelsrc	 

	if [ $? -ne 0 ]; then
		echo -e "\n\nERROR : Could not create soft link /hostdata/kernelsrc for /hostdata/modules/ dir required for Kernel Headers.\n\n"
		exit 1
	fi

	get_config

	echo -e "\nLinux kernel headers mount point seen for Kernel Headers...\n\n"
	exit 0
fi	

# Check if headers available in /hostdata/lastkernelsrc directly
if [ -f "/hostdata/lastkernelsrc/${KERN_VER}/build/include/net/tcp.h" ]; then

	ln -sf /hostdata/lastkernelsrc/${KERN_VER} /hostdata/kernelsrc

	if [ ! -f "/lib/modules/${KERN_VER}/build/include/net/tcp.h" ]; then
		echo -e "\n\nERROR : Could not create soft link /hostdata/kernelsrc for /hostdata/lastkernelsrc/ dir required for Kernel Headers.\n\n"
		exit 1
	fi

	get_config

	echo -e "\nUsing previously stored Kernel Headers...\n\n"
	exit 0
fi	

# Check if the host /lib/modules exists with the kernel headers (this could be because of an incorrect Volume mount)
if [ -f "${HOST_ROOT}/lib/modules/${KERN_VER}/build/include/net/tcp.h" ]; then

	ln -sf ${HOST_ROOT}/lib/modules/ /hostdata/kernelsrc	 

	if [ $? -ne 0 ]; then
		echo -e "\n\nERROR : Could not create soft link /hostdata/kernelsrc for ${HOST_ROOT}/lib/modules/ dir required for Kernel Headers.\n\n"
		exit 1
	fi

	get_config

	echo -e "\nLinux kernel headers from Host dir is being used for Kernel Headers...\n\n"
	exit 0
fi	

OSREL=$( cat ${HOST_ROOT}/etc/os-release )
DISTNAME=$( echo "$OSREL" | egrep "^NAME=|^PRETTY_NAME=" | tail -1 )

# Check if its Container-Optimized OS (GKE)
if [[ $DISTNAME =~ "Container-Optimized OS"* ]]; then
	BUILD_ID=$( echo "$OSREL" | grep "^BUILD_ID=" | awk -F= '{print $2}' )

	if [ -n "$BUILD_ID" ]; then
		timeout 30 curl --head -f https://storage.googleapis.com/cos-tools/ &> /dev/null

		if [ $? -ne 0 ]; then
			echo -e "\nDetected Container-Optimized OS but Failed to connect to from https://storage.googleapis.com/cos-tools/ to download Kernel Headers...\n\n"
			exit 1
		fi	

		rm -Rf /hostdata/lastkernelsrc/[1-9]* 2> /dev/null
		
		echo -e "\nDetected Container-Optimized OS : Downloading Kernel Headers from https://storage.googleapis.com/cos-tools/...\n\n"

		curl -L -o /hostdata/kernel-headers.tgz --create-dirs -fsS https://storage.googleapis.com/cos-tools/${BUILD_ID}/kernel-headers.tgz
		if [ $? -ne 0 ]; then
			echo -e "ERROR : Failed to download link https://storage.googleapis.com/cos-tools/${BUILD_ID}/kernel-headers.tgz for downloading Kernel Headers...\n\n"
			exit 1
		fi	

		mkdir -p /hostdata/lastkernelsrc/${KERN_VER}/build 

		tar xzf kernel-headers.tgz --strip-components 4 -C /hostdata/lastkernelsrc/${KERN_VER}/build/

		if [ $? -ne 0 ]; then
			echo -e "ERROR : Failed to extract downloaded Kernel Headers to /hostdata/lastkernelsrc/${KERN_VER}/build/\n\n"
			exit 1
		fi	

		ln -sf /hostdata/lastkernelsrc/${KERN_VER} /hostdata/kernelsrc

		if [ ! -f "/lib/modules/${KERN_VER}/build/include/net/tcp.h" ]; then
			echo -e "ERROR : Could not create soft link /hostdata/kernelsrc for downloaded Kernel headers from /hostdata/lastkernelsrc/${KERN_VER} dir.\n\n"
			exit 1
		fi

		get_config

		echo "$KERNCONFIG" > "/lib/modules/${KERN_VER}/build/.config"

		exit 0
	fi	

	if [ ! -f "/lib/modules/${KERN_VER}/build/include/net/tcp.h" ]; then
		echo -e "\n\nERROR : Could not find Kernel Headers for eBPF monitoring. Exiting...\n\n"
		exit 1
	else
		exit 0
	fi	
fi	

# Have exhausted all options. Last check if CFG_HOST_INSTALL_PKG env set. If set, we install the Kernel Headers package to Host itself... 
if [ -n "$CFG_HOST_INSTALL_PKG" ]; then

	PKGCMD=0

	if [[ $DISTNAME =~ Ubuntu* || $DISTNAME =~ Debian* ]]; then
		PKGCMD=1

		echo -e "\n\nNo Kernel Headers found. Detected Ubuntu/Debian based distribution and CFG_HOST_INSTALL_PKG env is set. Now trying to install the linux-headers package to Host itself.\n\nThis may take some time...\n"

		chroot "$HOST_ROOT" timeout -k 400 300 su -c "apt update && apt-get -y install linux-headers-$(uname -r)"

	elif [[ $DISTNAME =~ Amazon* || $DISTNAME =~ CentOS* || $DISTNAME =~ "Red Hat Enterprise"* || $DISTNAME =~ "Oracle Linux"* || $DISTNAME =~ "Scientific Linux"* ]]; then

		PKGCMD=1

		echo -e "\n\nNo Kernel Headers found. Detected RHEL or related distribution and CFG_HOST_INSTALL_PKG env is set. Now trying to install the kernel-devel package to Host itself.\n\nThis may take some time...\n"

		chroot "$HOST_ROOT" timeout -k 400 300 su -c "yum -y install kernel-devel-$(uname -r)"

	elif [[ $DISTNAME =~ Fedora* || $DISTNAME =~ Rocky* ]]; then	
		PKGCMD=1

		echo -e "\n\nNo Kernel Headers found. Detected Fedora or related distribution and CFG_HOST_INSTALL_PKG env is set. Now trying to install the kernel-devel package to Host itself.\n\nThis may take some time...\n"

		chroot "$HOST_ROOT" timeout -k 400 300 su -c "dnf install -y kernel-devel-$(uname -r)"

	elif [[ $DISTNAME =~ SUSE* || $DISTNAME =~ openSUSE* ]]; then	

		PKGCMD=1

		echo -e "\n\nNo Kernel Headers found. Detected SuSE distribution and CFG_HOST_INSTALL_PKG env is set. Now trying to install the kernel-devel package to Host itself.\n\nThis may take some time...\n"

		chroot "$HOST_ROOT" timeout -k 400 300 su -c "zypper -n install kernel-default-devel-$(uname -r | awk -F- '{print $1}')"
	else
		echo -e "\n\nERROR : Could not find Kernel Headers for eBPF monitoring. CFG_HOST_INSTALL_PKG set but Distribution $DISTNAME not yet handled. Please contact https://github.com/gyeeta/gyeeta : Exiting...\n\n"
		exit 1
	fi

	if [ $? -ne 0 ]; then
		echo -e "\n\nERROR : Failed to install Kernel Headers package for Host...\n"
	fi	

	if [ -f "${HOST_ROOT}/lib/modules/${KERN_VER}/build/include/net/tcp.h" ]; then

		ln -sf ${HOST_ROOT}/lib/modules/ /hostdata/kernelsrc	 

		if [ $? -ne 0 ]; then
			echo -e "\n\nERROR : Could not create soft link /hostdata/kernelsrc for ${HOST_ROOT}/lib/modules/ dir required for Kernel Headers.\n\n"
			exit 1
		fi

		get_config

		echo -e "\nLinux kernel headers from Host dir is being used for Kernel Headers...\n\n"
		exit 0
	else
		echo -e "\n\nERROR : Could not install Kernel Headers package to Host for eBPF monitoring. Exiting...\n\n"
		exit 1
	fi	
	
fi	

if [ ! -f "/lib/modules/${KERN_VER}/build/include/net/tcp.h" ]; then
	echo -e "\n\nERROR : Could not find Kernel Headers for eBPF monitoring. Exiting...\n\n"
	exit 1
else
	get_config

	exit 0
fi	

