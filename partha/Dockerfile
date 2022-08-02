# syntax=docker/dockerfile:1

FROM ubuntu:18.04

LABEL description="This container provides partha which is the Gyeeta Host Monitor Agent to be installed on all hosts which need to be monitored"

LABEL usage="docker run -td --rm --name partha --read-only --privileged --env CFG_CLUSTER_NAME=<Cluster Name> --env CFG_CLOUD_TYPE=<Cloud Type e.g. aws or gcp or azure> --env CFG_SHYAMA_HOSTS=<Shyama Hosts in json e.g. [ \"shyama1.local\", \"shyama2.local\" ]> --env CFG_SHYAMA_PORTS=<Shyama Ports in json e.g. [ 10037, 10037 ]>  --env CFG_IS_KUBERNETES=<true or false> --network=host --pid=host --cgroupns=host -v /proc:/proc -v /sys/:/sys/ -v /usr/src/:/usr/src/:ro -v /lib/modules:/lib/modules:ro -v parthavol:/hostdata <Image>"

ARG PARTHA_VERSION
ENV PARTHA_VERSION=${PARTHA_VERSION}

RUN apt-get update \
	&& apt-get install -y --no-install-recommends \
	sudo \
	libcap2-bin \
	&& rm -rf /var/lib/apt/lists/*

# tini handling...
ARG TINI_VERSION=v0.19.0
ARG TINI_SHA256="93dcc18adc78c65a028a84799ecf8ad40c936fdfc5f2a57b1acda5a8117fa82c"
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /tini
RUN chmod 0755 /tini
RUN if [ `sha256sum /tini | awk '{print $1}'` != "$TINI_SHA256" ]; then echo -e "ERROR : SHA256 of tini is different from expected value. Binary has changed. Please contact on Github.\n\n"; return 1; else return 0; fi

# Volume for partha logs
VOLUME ["/hostdata"]

COPY . /partha/

RUN sudo -n setcap cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_ipc_lock,cap_kill,cap_mac_admin,cap_mknod,cap_sys_chroot,cap_sys_resource,cap_setpcap,cap_sys_ptrace,cap_sys_admin,cap_net_admin,cap_net_raw,cap_sys_module+ep /partha/partha

ENTRYPOINT ["/tini", "-s", "-g", "--", "/partha/container_init.sh" ]

CMD ["start"]

