#!/bin/bash

UPF_BUILD_DIR=$(cd `dirname $0`; pwd)
UPF_BUILD_SCRIPT_DIR=$UPF_BUILD_DIR/script
UPF_TOP_DIR=$UPF_BUILD_DIR/..

${UPF_BUILD_SCRIPT_DIR}/build_fpu.sh clean
if [ -e ${UPF_BUILD_SCRIPT_DIR}/build_stub.sh ]
then
    ${UPF_BUILD_SCRIPT_DIR}/build_stub.sh clean
    rm -rf ${UPF_TOP_DIR}/install/test
    ${UPF_TOP_DIR}/test/autotest/clean_test_ret.sh
fi
${UPF_BUILD_SCRIPT_DIR}/build_smu.sh clean
${UPF_BUILD_SCRIPT_DIR}/build_lbu.sh clean
${UPF_BUILD_SCRIPT_DIR}/build_ulfius.sh clean
rm -rf ${UPF_BUILD_DIR}/dpdk
rm -rf ${UPF_TOP_DIR}/install/bin
rm -rf ${UPF_TOP_DIR}/install/include
rm -rf ${UPF_TOP_DIR}/install/lib
rm -rf ${UPF_TOP_DIR}/install/config

# Delete downloaded dependent Libraries
if [ -d $UPF_TOP_DIR/libs/dpdk ]
then
    rm -rf $UPF_TOP_DIR/libs/dpdk
fi

if [ -d $UPF_TOP_DIR/libs/ulfius ]
then
    rm -rf $UPF_TOP_DIR/libs/ulfius
fi

if [ -d $UPF_TOP_DIR/libs/orcania ]
then
    rm -rf  $UPF_TOP_DIR/libs/orcania
fi