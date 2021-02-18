/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _COMMON_H__
#define _COMMON_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <math.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netinet/tcp.h>

#include "common_typedef.h"
#include "common_config.h"


#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _COMMON_H__ */
