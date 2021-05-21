#!/bin/bash

if [ `whoami` != "root" ];then
    echo "Please use the root permission!"
    exit 0
fi

docker ps --all|grep -e "\bfpu\b" >/dev/null 2>&1
if [ $? -eq 0 ]; then  
    export fpu_pid=$(docker inspect -f {{.State.Pid}} fpu)
    docker stop fpu;docker rm fpu >/dev/null 2>&1
    rm /var/run/netns/$fpu_pid >/dev/null 2>&1
fi

docker ps --all|grep -e "\bstub\b" >/dev/null 2>&1
if [ $? -eq 0 ]; then  
    export stub_pid=$(docker inspect -f {{.State.Pid}} stub)
    docker stop stub;docker rm stub >/dev/null 2>&1
    rm /var/run/netns/$stub_pid >/dev/null 2>&1
fi

docker ps --all|grep -e "\bsmu\b" >/dev/null 2>&1
if [ $? -eq 0 ]; then  
    export smu_pid=$(docker inspect -f {{.State.Pid}} smu)
    docker stop smu;docker rm smu >/dev/null 2>&1
    rm /var/run/netns/$smu_pid >/dev/null 2>&1
fi

docker ps --all|grep -e "\blbu\b" >/dev/null 2>&1
if [ $? -eq 0 ]; then  
    export lbu_pid=$(docker inspect -f {{.State.Pid}} lbu)
    docker stop lbu;docker rm lbu >/dev/null 2>&1
    rm /var/run/netns/$lbu_pid >/dev/null 2>&1
fi

exit 0