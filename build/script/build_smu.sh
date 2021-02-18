#!/bin/bash

UPF_BUILD_SCRIPT_PATH=$(cd `dirname $0`; pwd)
UPF_BUILD_PATH=$UPF_BUILD_SCRIPT_PATH/..
UPF_TOP_PATH=$UPF_BUILD_PATH/..

UPF_PROGRAM_NAME=smu
PROGRAM_BUILD_PATH=$UPF_BUILD_PATH/$UPF_PROGRAM_NAME

help()
{
    local BN=`basename $1`
    echo "Usage:"
    echo "      ./$BN \$PARA"
    echo ""
    echo "\$PARA:" 
    echo "       : make/clean/all"
    exit 0
}

if [ "$1" == "help" ] || [ "$1" == "?" ]
then
    help $0
    exit 0
fi

BUIL_APPS()
{
    if [[ $1 == "clean" ]]; then
        rm -rf $PROGRAM_BUILD_PATH
    elif [[ $1 == "all"  ]]; then
        rm -rf $PROGRAM_BUILD_PATH
        mkdir -p $PROGRAM_BUILD_PATH
        cd $PROGRAM_BUILD_PATH
        cmake $UPF_TOP_PATH -DPROGRAM_NAME=$UPF_PROGRAM_NAME
        make -j8
        make install
    else
        mkdir -p $PROGRAM_BUILD_PATH
        cd $PROGRAM_BUILD_PATH
        cmake $UPF_TOP_PATH -DPROGRAM_NAME=$UPF_PROGRAM_NAME
        make -j8
        make install
    fi    
}

BUIL_APPS $1
