#!/bin/bash

UPF_BUILD_SCRIPT_PATH=$(cd `dirname $0`; pwd)
UPF_BUILD_PATH=$UPF_BUILD_SCRIPT_PATH/..
UPF_TOP_PATH=$UPF_BUILD_PATH/..

UPF_INSTALL_PATH=$UPF_TOP_PATH/install
source $UPF_BUILD_SCRIPT_PATH/build_val.sh

ULFIUS_LIB_DIR=$UPF_TOP_PATH/libs/ulfius
ULFIUS_VERSION=2.7.1
ULFIUS_GIT_TAG=v$ULFIUS_VERSION
ULFIUS_GIT_REPOSITORY=$GIT_REPOSITORY_PREFIX/babelouest/ulfius.git
ULFIUS_LIB_PATH=$UPF_INSTALL_PATH/lib/libulfius.so

ORCANIA_LIB_DIR=$UPF_TOP_PATH/libs/orcania
ORCANIA_VERSION=2.1.1
ORCANIA_GIT_TAG=v$ORCANIA_VERSION
ORCANIA_GIT_REPOSITORY=$GIT_REPOSITORY_PREFIX/babelouest/orcania.git
ULFIUS_DEP_FLAG="CURLFLAG=1 JANSSONFLAG=1 GNUTLSFLAG=1 WEBSOCKETFLAG=1 YDERFLAG=1 UWSCFLAG=1"
ORCANIA_LIB_PATH=$UPF_INSTALL_PATH/lib/liborcania.so

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

LIBS_DOWNLOAD()
{
    if [ ! -d $ORCANIA_LIB_DIR ]
    then
        git clone -b $ORCANIA_GIT_TAG $ORCANIA_GIT_REPOSITORY $ORCANIA_LIB_DIR
    fi
    
    if [ ! -d $ULFIUS_LIB_DIR ]
    then
        git clone -b $ULFIUS_GIT_TAG $ULFIUS_GIT_REPOSITORY $ULFIUS_LIB_DIR
    fi
}

LIBS_BUILD()
{
    if [ ! -f $ORCANIA_LIB_PATH ]
    then
        sed -i s#DESTDIR=/usr/local#DESTDIR=${UPF_INSTALL_PATH}#g $ORCANIA_LIB_DIR/src/Makefile
        sed -i /ldconfig/d $ORCANIA_LIB_DIR/src/Makefile
        make install -C $ORCANIA_LIB_DIR
        mv -f $ORCANIA_LIB_PATH.$ORCANIA_VERSION $ORCANIA_LIB_PATH
    fi
    
    if [ ! -f $ULFIUS_LIB_PATH ]
    then
        export CPPFLAGS=-I${ORCANIA_LIB_DIR}/include
        export LDFLAGS=-L${UPF_INSTALL_PATH}/lib
        sed -i s#DESTDIR=/usr/local#DESTDIR=${UPF_INSTALL_PATH}#g $ULFIUS_LIB_DIR/src/Makefile
        sed -i /ldconfig/d $ULFIUS_LIB_DIR/src/Makefile
        make install -C $ULFIUS_LIB_DIR $ULFIUS_DEP_FLAG
        mv -f $ULFIUS_LIB_PATH.$ULFIUS_VERSION $ULFIUS_LIB_PATH
    fi
}

if [[ $1 == "clean"  ]]
then
    if [ -d $ORCANIA_LIB_DIR ]
    then
        make uninstall -C $ORCANIA_LIB_DIR
        make clean -C $ORCANIA_LIB_DIR
    fi
    
    if [ -d $ULFIUS_LIB_DIR ]
    then
        make uninstall -C $ULFIUS_LIB_DIR
        make clean -C $ULFIUS_LIB_DIR
    fi
elif [[ $1 == "download" ]]
then
    LIBS_DOWNLOAD
else
    mkdir -p $UPF_INSTALL_PATH/lib
    mkdir -p $UPF_INSTALL_PATH/include
    LIBS_DOWNLOAD
    LIBS_BUILD
    if [ ! -f $UPF_INSTALL_PATH/lib/liborcania.so ]; then
        exit -1
    fi
    if [ ! -f $UPF_INSTALL_PATH/lib/libulfius.so ]; then
        exit -1
    fi
fi
