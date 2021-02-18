#!/bin/bash

UPF_INSTALL_PATH="$(dirname "$PWD")"
UPF_BIN_PATH=$UPF_INSTALL_PATH/build/bin
UPF_CONFIG_PATH=$UPF_INSTALL_PATH/config

# CPUs of docker binding
UPF_LBU_CPUS=0-4
UPF_SMU_CPUS=5
UPF_FPU_CPUS=6-10

# Program bound network port
UPF_LBU_EXT_DEV="04:10.4"
UPF_LBU_INT_DEV="04:10.0"
UPF_FPU_DEV="04:10.1"

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


docker run -tid --privileged --cpuset-cpus="$UPF_LBU_CPUS" -e "UPF_RUNCONFIG=/opt/upf/config/lbu/lbu_docker.ini" -e "PATH=$PATH:/opt/upf/bin" --net=host \
                                -w "/opt/upf" \
                                -e "LD_LIBRARY_PATH=/opt/upf/lib" \
                                -e "GIT_VER_INFO=$UPF_GIT_VER_INFO" \
                                -e "PROBLEM_INFO=$UPF_PROBLEM_INFO" \
                                -e "UPF_LBU_EXT_DEV=$UPF_LBU_EXT_DEV" \
                                -e "UPF_LBU_INT_DEV=$UPF_LBU_INT_DEV" \
                                -e "DPDK_PCIDEVICE=UPF_LBU_EXT_DEV,UPF_LBU_INT_DEV" \
                                -v $UPF_CONFIG_PATH:/opt/upf/config \
                                -v $UPF_BIN_PATH:/opt/upf/bin \
                                -v $UPF_LIB_PATH:/opt/upf/lib \
                                -v $UPF_SCRIPT_PATH:/opt/upf/script \
                                -v /dev/hugepages:/dev/hugepages \
                                --name lbu air5005/upu /bin/bash

docker run -tid --privileged --cpuset-cpus="$UPF_FPU_CPUS" -e "UPF_RUNCONFIG=/opt/upf/config/fpu/fpu_dpdk_docker.ini" -e "PATH=$PATH:/opt/upf/bin" --net=host \
                                 -w "/opt/upf" \
                                -e "LD_LIBRARY_PATH=/opt/upf/lib" \
                                -e "GIT_VER_INFO=$UPF_GIT_VER_INFO" \
                                -e "PROBLEM_INFO=$UPF_PROBLEM_INFO" \
                                -e "UPF_FPU_DEV=$UPF_FPU_DEV" \
                                -e "DPDK_PCIDEVICE=UPF_FPU_DEV" \
                                -v $UPF_CONFIG_PATH:/opt/upf/config \
                                -v $UPF_BIN_PATH:/opt/upf/bin \
                                -v $UPF_LIB_PATH:/opt/upf/lib \
                                -v $UPF_SCRIPT_PATH:/opt/upf/script \
                                -v /dev/hugepages:/dev/hugepages \
                                --name fpu air5005/upu /bin/bash

docker run -tid --cap-add ALL --cpuset-cpus="$UPF_SMU_CPUS" -e "UPF_RUNCONFIG=/opt/upf/config/smu/smu_docker.ini" -e "PATH=$PATH:/opt/upf/bin" --net=host \
                                -w "/opt/upf" \
                                -e "GIT_VER_INFO=$UPF_GIT_VER_INFO" \
                                -e "PROBLEM_INFO=$UPF_PROBLEM_INFO" \
                                -v $UPF_CONFIG_PATH:/opt/upf/config \
                                -v $UPF_BIN_PATH:/opt/upf/bin \
                                -v $UPF_LIB_PATH:/opt/upf/lib \
                                -v $UPF_SCRIPT_PATH:/opt/upf/script \
                                --name smu air5005/upu /bin/bash
