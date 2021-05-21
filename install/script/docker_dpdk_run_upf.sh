#!/bin/bash

UPF_INSTALL_PATH="$(dirname "$PWD")"
UPF_BIN_PATH=$UPF_INSTALL_PATH/build/bin
UPF_CONFIG_PATH=$UPF_INSTALL_PATH/config

# CPUs of docker binding
UPF_LBU_CPUS=0-2
UPF_SMU_CPUS=3
# The number of 'UPF_FPU_CPUS - 1' needs to be equal to the number of 'UPF_FPU_DEV'
UPF_FPU_CPUS=4-5

# Program bound network port, Separate with commas, e.g. "04:10.3,04:11.1"
UPF_LBU_EXT_DEV="04:00.0"
UPF_LBU_INT_DEV="04:10.1"
UPF_FPU_DEV="04:10.3"

help()
{
    local BN=`basename $1`
    echo "Usage:"
    echo "      ./$BN \$UPF_INSTALL_PATH "
    echo ""
    exit 0
}

if [ "$1" == "help" ] || [ "$1" == "?" ]
then
    help  $0
    exit 0
fi

if [ `whoami` != "root" ];then
    echo "Please use the root permission!"
    exit 0
fi

if [ -n "$1" ] ;then
    UPF_INSTALL_PATH=$1
fi

UPF_BIN_PATH=$UPF_INSTALL_PATH/bin
UPF_CONFIG_PATH=$UPF_INSTALL_PATH/config
UPF_LIB_PATH=$UPF_INSTALL_PATH/lib
UPF_SCRIPT_PATH=$UPF_INSTALL_PATH/script
echo "UPF_INSTALL_PATH=$UPF_INSTALL_PATH"
echo "UPF_BIN_PATH=$UPF_BIN_PATH"
echo "UPF_CONFIG_PATH=$UPF_CONFIG_PATH"

RUNNING_DOCKER=`docker ps -f name=lbu | awk 'NR==2{print \$NF}'`
if [ "${RUNNING_DOCKER}" != "lbu" ]; then
docker run -tid --privileged --cpuset-cpus="$UPF_LBU_CPUS" -e "UPF_RUNCONFIG=/opt/upf/config/lbu/lbu_docker.ini" -e "PATH=$PATH:/opt/upf/bin" --net=host \
                                -w "/opt/upf" \
                                -e "LD_LIBRARY_PATH=/opt/upf/lib" \
                                -e "UPF_LBU_EXT_DEV=$UPF_LBU_EXT_DEV" \
                                -e "UPF_LBU_INT_DEV=$UPF_LBU_INT_DEV" \
                                -e "DPDK_PCIDEVICE=UPF_LBU_EXT_DEV,UPF_LBU_INT_DEV" \
                                -v $UPF_CONFIG_PATH:/opt/upf/config \
                                -v $UPF_BIN_PATH:/opt/upf/bin \
                                -v $UPF_LIB_PATH:/opt/upf/lib \
                                -v $UPF_SCRIPT_PATH:/opt/upf/script \
                                -v /dev/hugepages:/dev/hugepages \
                                --name lbu air5005/upu /bin/bash
fi

RUNNING_DOCKER=`docker ps -f name=fpu | awk 'NR==2{print \$NF}'`
if [ "${RUNNING_DOCKER}" != "fpu" ]; then
docker run -tid --privileged --cpuset-cpus="$UPF_FPU_CPUS" -e "UPF_RUNCONFIG=/opt/upf/config/fpu/fpu_dpdk_docker.ini" -e "PATH=$PATH:/opt/upf/bin" --net=host \
                                 -w "/opt/upf" \
                                -e "LD_LIBRARY_PATH=/opt/upf/lib" \
                                -e "UPF_FPU_DEV=$UPF_FPU_DEV" \
                                -e "DPDK_PCIDEVICE=UPF_FPU_DEV" \
                                -v $UPF_CONFIG_PATH:/opt/upf/config \
                                -v $UPF_BIN_PATH:/opt/upf/bin \
                                -v $UPF_LIB_PATH:/opt/upf/lib \
                                -v $UPF_SCRIPT_PATH:/opt/upf/script \
                                -v /dev/hugepages:/dev/hugepages \
                                --name fpu air5005/upu /bin/bash
fi

RUNNING_DOCKER=`docker ps -f name=smu | awk 'NR==2{print \$NF}'`
if [ "${RUNNING_DOCKER}" != "smu" ]; then
docker run -tid --cap-add ALL --cpuset-cpus="$UPF_SMU_CPUS" -e "UPF_RUNCONFIG=/opt/upf/config/smu/smu_docker.ini" -e "PATH=$PATH:/opt/upf/bin" --net=host \
                                -w "/opt/upf" \
                                -v $UPF_CONFIG_PATH:/opt/upf/config \
                                -v $UPF_BIN_PATH:/opt/upf/bin \
                                -v $UPF_LIB_PATH:/opt/upf/lib \
                                -v $UPF_SCRIPT_PATH:/opt/upf/script \
                                --name smu air5005/upu /bin/bash
fi
