#!/bin/bash

UPF_BUILD_SCRIPT_PATH=$(cd `dirname $0`; pwd)
UPF_BUILD_PATH=$UPF_BUILD_SCRIPT_PATH/..
UPF_TOP_PATH=$UPF_BUILD_PATH/..
UPF_INSTALL_PATH=$UPF_TOP_PATH/install

source $UPF_BUILD_SCRIPT_PATH/build_val.sh

DPDK_LIB_DIR=$UPF_TOP_PATH/libs/dpdk
DPDK_GIT_TAG=v20.11
DPDK_GIT_REPOSITORY=$GIT_REPOSITORY_PREFIX/DPDK/dpdk.git
DPDK_BUILD_DIR=$UPF_BUILD_PATH/dpdk
DPDK_INSTALL_DIR=$DPDK_BUILD_DIR/install
DPDK_INSTALL_LIBS_DIR=$DPDK_INSTALL_DIR/lib
DPDK_INSTALL_INCLUDE_DIR=$DPDK_INSTALL_DIR/include
#DPDK_INSTALL_BINS_DIR=$DPDK_INSTALL_DIR/dpdkbin
#DPDK_INSTALL_DATA_DIR=$DPDK_INSTALL_DIR/dpdkshare

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
        RET=-1
        COUNT=0
        
        while [ $RET -ne 0 ]
        do
            git clone -b $DPDK_GIT_TAG $DPDK_GIT_REPOSITORY $DPDK_LIB_DIR
            RET=$?
            COUNT=$(($COUNT+1))
            
            if [ $COUNT -ge 3 ]
            then
                exit -1
            fi
        done
    fi
}

DPDK_BUILD()
{
#$DPDK_INSTALL_LIBS_DIR
    if [ ! -f $DPDK_INSTALL_DIR/lib/pkgconfig/libdpdk.pc ]
    then
        #meson -Dprefix=$DPDK_INSTALL_DIR -Ddefault_library=static -Dlibdir=$DPDK_INSTALL_LIBS_DIR -Dincludedir=$DPDK_INSTALL_INCLUDE_DIR -Dbindir=$DPDK_INSTALL_BINS_DIR -Ddatadir=$DPDK_INSTALL_DATA_DIR $DPDK_BUILD_DIR $DPDK_LIB_DIR
        #meson -Dprefix=$DPDK_INSTALL_DIR -Dlibdir=$DPDK_INSTALL_DIR/lib -Dibverbs_link=static -Dtests=false $DPDK_BUILD_DIR $DPDK_LIB_DIR
        meson -Dprefix=$DPDK_INSTALL_DIR -Dlibdir=$DPDK_INSTALL_DIR/lib $DPDK_BUILD_DIR $DPDK_LIB_DIR
        #sed -ri 's@#define RTE_EAL_PMD_PATH.*(pmds.+)"@#define RTE_EAL_PMD_PATH "/opt/upf/lib/dpdk/\1"@g' $DPDK_BUILD_DIR/rte_build_config.h
        ninja -C $DPDK_BUILD_DIR
        ninja install -C $DPDK_BUILD_DIR
        cp -r $DPDK_INSTALL_DIR/lib $UPF_INSTALL_PATH/
    fi
}

if [[ $1 == "clean"  ]]
then
    rm -rf $DPDK_INSTALL_DIR
    rm -rf $DPDK_BUILD_DIR
    rm -f $UPF_INSTALL_PATH/lib/librte_*
    rm -f $UPF_INSTALL_PATH/lib/pkgconfig/libdpdk*
elif [[ $1 == "download" ]]
then
    DPDK_DOWNLOAD
else
    DPDK_DOWNLOAD
    DPDK_BUILD
    if [ ! -f $DPDK_INSTALL_DIR/lib/pkgconfig/libdpdk.pc ]; then
        exit -1
    fi
fi
