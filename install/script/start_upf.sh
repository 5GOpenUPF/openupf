#!/bin/bash

UPF_SCRIPT_PATH="$(dirname "$PWD")"/script

if [ `whoami` != "root" ];then
    echo "Please use the root permission!"
    exit 0
fi
pushd $UPF_SCRIPT_PATH >> /dev/null 2>&1

# Only check the status of SMU. If SMU does not exist, clear it, and then re deploy it. If SMU exists, start it directly
RUNNING_DOCKER=`docker ps -f name=smu --filter status=running | awk 'NR==2{print \$NF}'`
if [ "${RUNNING_DOCKER}" != "smu" ]; then
    sh ./docker_clr.sh
    sh ./docker_dpdk_run_upf.sh
    sleep 3
fi

PROG_LIST=("lbu" "fpu" "smu")
PROG_LIST_SIZE=${#PROG_LIST[@]}

i=0
result=0

# Start all processes
while [ $i -lt ${PROG_LIST_SIZE} ]
do
    RUNNING_DOCKER=`docker ps -f name=${PROG_LIST[${i}]} --filter status=running | awk 'NR==2{print \$NF}'`
    if [ "${RUNNING_DOCKER}" == "${PROG_LIST[${i}]}" ]; then
        docker exec -di ${PROG_LIST[${i}]} sh -c "./bin/${PROG_LIST[${i}]}"
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
result=0
while [ $i -lt ${PROG_LIST_SIZE} ]
do
    PROG_ID=`docker exec -i ${PROG_LIST[${i}]} sh -c "pgrep ${PROG_LIST[${i}]}"`
    if [ "${PROG_ID}" == "" ]; then
        echo "Program ${PROG_LIST[${i}]} failed to start."
        result=-1
    fi

    i=$(($i+1))
done

echo "Start UPF complete."

exit $result