#!/bin/bash

UPF_BUILD_SCRIPT_PATH=$(cd `dirname $0`; pwd)
UPF_BUILD_PATH=$UPF_BUILD_SCRIPT_PATH/..
UPF_TOP_PATH=$UPF_BUILD_PATH/..

source $UPF_BUILD_SCRIPT_PATH/build_val.sh

DPDK_LIB_DIR=$UPF_TOP_PATH/libs/dpdk
DPDK_GIT_TAG=v19.11
DPDK_GIT_REPOSITORY=$GIT_REPOSITORY_PREFIX/DPDK/dpdk.git
DPDK_BUILD_DIR=$UPF_BUILD_PATH/dpdk

help()
{
    local BN=`basename $1`
    echo "Usage:"
    echo "      ./$BN \$PARA1"
    echo ""
    echo "\$PARA1 :" 
    echo "       : make/clean"
    exit 0
}

if [ "$1" == "help" ] || [ "$1" == "?" ]
then
    help  $0
    exit 0
fi

DPDK_DOWNLOAD()
{
    if [ ! -d $DPDK_LIB_DIR ]
    then
        git clone -b $DPDK_GIT_TAG $DPDK_GIT_REPOSITORY $DPDK_LIB_DIR
    fi
}

DPDK_BUILD()
{
    if [ ! -f $DPDK_BUILD_DIR/lib/libdpdk.a ]
    then
        make -C $DPDK_LIB_DIR defconfig O=$DPDK_BUILD_DIR
        make -C $DPDK_LIB_DIR -j8 O=$DPDK_BUILD_DIR
    fi
}

if [[ $1 == "clean"  ]]
then
    rm -rf $DPDK_BUILD_DIR
elif [[ $1 == "download" ]]
then
    DPDK_DOWNLOAD
else
    DPDK_DOWNLOAD
    DPDK_BUILD
    if [ ! -f $DPDK_BUILD_DIR/lib/libdpdk.a ]; then
        exit -1
    fi
fi
