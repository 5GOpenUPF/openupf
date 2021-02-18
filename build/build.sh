#!/bin/bash

UPF_BUILD_DIR=$(cd `dirname $0`; pwd)
UPF_BUILD_SCRIPT_DIR=$UPF_BUILD_DIR/script
UPF_TOP_DIR=$UPF_BUILD_DIR/..
UPF_INSTALL_DIR=$UPF_TOP_DIR/install


$UPF_BUILD_SCRIPT_DIR/build_dpdk.sh
if [ $? -ne 0  ]; then
    exit -1
fi

$UPF_BUILD_SCRIPT_DIR/build_ulfius.sh
if [ $? -ne 0  ]; then
    exit -1
fi

$UPF_BUILD_SCRIPT_DIR/build_fpu.sh all
if [ ! -f $UPF_INSTALL_DIR/bin/fpu ]; then
    exit -1
fi

$UPF_BUILD_SCRIPT_DIR/build_smu.sh all
if [ ! -f $UPF_INSTALL_DIR/bin/smu ]; then
    exit -1
fi

$UPF_BUILD_SCRIPT_DIR/build_lbu.sh all
if [ ! -f $UPF_INSTALL_DIR/bin/lbu ]; then
    exit -1
fi

if [ -f $UPF_BUILD_SCRIPT_DIR/build_stub.sh ]; then
    $UPF_BUILD_SCRIPT_DIR/build_stub.sh all
    if [ ! -f $UPF_INSTALL_DIR/bin/stub ]; then
        exit -1
    fi
fi

echo -e "--------------------- Build version success! --------------------\n\n"
