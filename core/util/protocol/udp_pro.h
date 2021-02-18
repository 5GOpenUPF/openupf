/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __UDP_PRO_H
#define __UDP_PRO_H

#define UDP_PRO_PFCP    (8805)

#define UDP_HLEN (8)

struct pro_udp_hdr {
	unsigned short	source;
	unsigned short	dest;
	unsigned short	len;
	unsigned short	check;
}__packed;

#endif

