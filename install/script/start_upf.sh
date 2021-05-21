#!/bin/bash

UPF_SCRIPT_PATH=$(cd `dirname $0`; pwd)
PROG_LIST=("lbu" "fpu" "smu")
PROG_LIST_SIZE=${#PROG_LIST[@]}
result=0

if [ `whoami` != "root" ];then
    echo "Please use the root permission!"
    exit 0
fi
pushd $UPF_SCRIPT_PATH >> /dev/null 2>&1

sh ./docker_dpdk_run_upf.sh

# Start all processes
i=0
while [ $i -lt ${PROG_LIST_SIZE} ]
do
    RUNNING_DOCKER=`docker ps -f name=${PROG_LIST[${i}]} --filter status=running | awk 'NR==2{print \$NF}'`
    if [ "${RUNNING_DOCKER}" == "${PROG_LIST[${i}]}" ]; then
        PROG_ID=`docker exec -i ${PROG_LIST[${i}]} sh -c "pgrep ${PROG_LIST[${i}]}"`
        if [ "${PROG_ID}" == "" ]; then
            docker exec -di ${PROG_LIST[${i}]} sh -c "./bin/${PROG_LIST[${i}]}"
        fi
    else
        echo "Docker ${PROG_LIST[${i}]} non-existent"
        exit -1
    fi
    
    i=$(($i+1))
done

popd >> /dev/null 2>&1

# Wait for the process to start
sleep 3

# Check whether the process started successfully
i=0
fail_cnt=0
while [ $i -lt ${PROG_LIST_SIZE} ]
do
    PROG_ID=`docker exec -i ${PROG_LIST[${i}]} sh -c "pgrep ${PROG_LIST[${i}]}"`
    if [ "${PROG_ID}" == "" ]; then
        fail_cnt=$(($fail_cnt+1))
        if [ $fail_cnt -lt 3 ]; then
            docker exec -di ${PROG_LIST[${i}]} sh -c "./bin/${PROG_LIST[${i}]}"
            sleep 4
            continue
        fi
        echo "Program ${PROG_LIST[${i}]} failed to start."
        result=-1
    fi

    fail_cnt=0
    i=$(($i+1))
done

echo "Start UPF complete."

exit $result