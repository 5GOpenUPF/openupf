#!/bin/bash

UPF_BUILD_SCRIPT_PATH=$(cd `dirname $0`; pwd)

$UPF_BUILD_SCRIPT_PATH/build_dpdk.sh download
if [ $? -ne 0 ]; then
    exit -1
fi

$UPF_BUILD_SCRIPT_PATH/build_ulfius.sh download
if [ $? -ne 0 ]; then
    exit -1
fi

echo -e "------------------- Download dependencies finish! --------------------\n\n"