FROM centos:7.6.1810

RUN yum install -y epel-release

RUN yum install -y pciutils \
    && yum install -y tcpdump \
    && yum install -y ethtool \
    && yum install -y hiredis-devel \
    && yum install -y net-tools \
    && yum install -y redhat-lsb \
    && yum install -y tcpreplay msgpack-devel \
    && yum install -y readline-devel libedit-devel \
    && yum install -y gcc automake autoconf libtool make \
    && yum install -y glibc-static libstdc++-static libevent-devel \
    && yum install -y iproute numactl mbedtls gdb numactl-devel numactl-libs \
    && yum install -y gnutls-devel.x86_64 \
    && yum install -y libmicrohttpd-devel.x86_64 \
    && yum install -y jansson-devel.x86_64 \
    && yum install -y systemd-devel.x86_64 \
    && yum install -y libcurl-devel.x86_64 \
    && yum install -y sysstat \
    && yum install -y perf

WORKDIR /opt/upu-5G