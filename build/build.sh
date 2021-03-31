#!/bin/bash

UPF_BUILD_DIR=$(cd `dirname $0`; pwd)
UPF_BUILD_SCRIPT_DIR=$UPF_BUILD_DIR/script
UPF_TOP_DIR=$UPF_BUILD_DIR/..
UPF_INSTALL_DIR=$UPF_TOP_DIR/install


$UPF_BUILD_SCRIPT_DIR/build_dpdk.sh
if [ $? -ne 0 ]; then
    echo -e "--------------------- Build dpdk failed! --------------------\n\n"
    exit -1
fi

$UPF_BUILD_SCRIPT_DIR/build_ulfius.sh
if [ $? -ne 0 ]; then
    echo -e "--------------------- Build ulfius failed! --------------------\n\n"
    exit -1
fi

$UPF_BUILD_SCRIPT_DIR/build_fpu.sh all
if [ $? -ne 0 ] || [ ! -f $UPF_INSTALL_DIR/bin/fpu ]; then
    echo -e "--------------------- Build fpu failed! --------------------\n\n"
    exit -1
fi

$UPF_BUILD_SCRIPT_DIR/build_smu.sh all
if [ $? -ne 0 ] || [ ! -f $UPF_INSTALL_DIR/bin/smu ]; then
    echo -e "--------------------- Build smu failed! --------------------\n\n"
    exit -1
fi

$UPF_BUILD_SCRIPT_DIR/build_lbu.sh all
if [ $? -ne 0 ] || [ ! -f $UPF_INSTALL_DIR/bin/lbu ]; then
    echo -e "--------------------- Build lbu failed! --------------------\n\n"
    exit -1
fi

if [ -f $UPF_BUILD_SCRIPT_DIR/build_stub.sh ]; then
    $UPF_BUILD_SCRIPT_DIR/build_stub.sh all
    if [ $? -ne 0 ] || [ ! -f $UPF_INSTALL_DIR/bin/stub ]; then
        echo -e "--------------------- Build stub failed! --------------------\n\n"
        exit -1
    fi
fi

echo -e "--------------------- Build success! --------------------\n\n"
