#!/bin/bash

PATH=$PATH:/usr/bin:/sbin:/usr/sbin:.
export PATH

if [ $# -lt 1 ]; then
	echo -e "\nUsage : $0 <--check OR --createdir>\n"
	exit 1
fi

umask 0006

DNAME=`dirname $0 2> /dev/null`

if [ $? -eq 0 ]; then
	cd $DNAME/..
	CURRDIR=`pwd`
fi


LAST_RELEASE=

get_last_release()
{
	LAST_RELEASE=$( curl https://api.github.com/repos/gyeeta/gyeeta/releases/latest -s | jq .tag_name -r )
}

if [ "$1" = "--createdir" ]; then
	set -e

	mkdir -m 0755 ./install 2> /dev/null || :
	cd ./install/

	get_last_release

	if [ -z "$LAST_RELEASE" ]; then
		echo -e "\nERROR : Failed to get latest Release tag\n"
		exit 1
	fi	

	if [ ! -f ./partha/runpartha.sh ]; then
		echo "Creating install/partha dir..."

		curl -L https://github.com/gyeeta/gyeeta/releases/download/${LAST_RELEASE}/partha.tar.gz | tar xzf -
	fi	

	if [ ! -f ./madhava/runmadhava.sh ]; then
		echo "Creating install/madhava dir..."

		curl -L https://github.com/gyeeta/gyeeta/releases/download/${LAST_RELEASE}/madhava.tar.gz | tar xzf -
	fi	

	if [ ! -f ./shyama/runshyama.sh ]; then
		echo "Creating install/shyama dir..."

		curl -L https://github.com/gyeeta/gyeeta/releases/download/${LAST_RELEASE}/shyama.tar.gz | tar xzf -
	fi	

	exit 0

elif [ "$1" = "--check" ]; then 	
	# Verify versions of partha, madhava and shyama match

	set -e

	PARTHAVER=$( ./install/partha/runpartha.sh --version 2>&1 | grep Version | awk '{printf "%s", $NF}' )
	MADHAVAVER=$( ./install/madhava/runmadhava.sh --version 2>&1 | grep Version | awk '{printf "%s", $NF}' )
	SHYAMAVER=$( ./install/shyama/runshyama.sh --version 2>&1 | grep Version | awk '{printf "%s", $NF}' )
	
	if [ "$PARTHAVER" != "$MADHAVAVER" ] || [ "$MADHAVAVER" != "$SHYAMAVER" ]; then
		echo -e "\nERROR : Versions differ : Partha $PARTHAVER : Madhava $MADHAVAVER : Shyama $SHYAMAVER\n"
		exit 1
	fi	
	
	exit 0
else
	echo -e "\nUsage : $0 <--check OR --createdir>\n"
	exit 1
fi	

