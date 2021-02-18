#!/bin/bash

#ubuntu centos debian fedora or unknown
export System_Types

export System_Distributor
export System_Description
export System_Release

#get by uname -m
export System_Arch=`uname -m`

if [ `whoami` != "root" ];then
    echo "Please use the root permission!"
    exit 0
fi

dist_system_type()
{
    if [ -s /etc/redhat-release ]; then
        System_Distributor=`lsb_release -a |grep Distributor | awk -F ':' '{print $2}'`
        System_Description=`lsb_release -a |grep Description | awk -F ':' '{print $2}'`
        System_Release=`lsb_release -a |grep Release | awk -F ':' '{print $2}'`
        
        System_Release=${System_Release//\./\_}

        System_Distributor=$(echo $System_Distributor)
        System_Description=$(echo $System_Description)
        System_Release=$(echo $System_Release)

        if [ -f /etc/centos-release ]; then
            System_Types=centos
        else
            System_Types=fedora
        fi
    elif [ -f /etc/debian_version ]; then
        System_Distributor=`lsb_release -a |grep Distributor | awk -F ':' '{print $2}'`
        System_Description=`lsb_release -a |grep Description | awk -F ':' '{print $2}'`
        System_Release=`lsb_release -a |grep Release | awk -F ':' '{print $2}'`
        
        System_Release=${System_Release//\./\_}

        System_Distributor=$(echo $System_Distributor)
        System_Description=$(echo $System_Description)
        System_Release=$(echo $System_Release)
        
        if [ "$System_Distributor" == "Ubuntu" ];then
            System_Types=ubuntu
        elif [ "$System_Distributor" == "Debian" ]; then
            System_Types=debian
        else
            System_Types=unknown
        fi
    else
        echo "unknown system type."
        System_Types=unknown
    fi
}

if [ `whoami` != "root" ];then
    echo "Please use the root permission!"
    exit 0
fi  

dist_system_type

case $System_Types in 
  ubuntu | debian) 
      echo "There is no experiment in $System_Types system at present."
  ;; 
  centos | fedora) 
    yum install -y epel-release
    yum install -y readline-devel libedit-devel numactl-devel*x86_64 gcc
    yum install -y yum-utils device-mapper-persistent-data lvm2
    yum install -y gnutls-devel.x86_64
    yum install -y libmicrohttpd-devel.x86_64
    yum install -y jansson-devel.x86_64
    yum install -y systemd-devel.x86_64
    yum install -y psmisc 
    yum install -y bison
    yum install -y flex
  ;; 
  *) 
     echo "$0 unknown system type."
     exit 1
  ;; 
esac 
