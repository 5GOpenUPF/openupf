/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __TCP_PRO_H
#define __TCP_PRO_H

struct pro_tcp_hdr {
	unsigned short	source;
	unsigned short	dest;
	unsigned int	seq;
	unsigned int	ack_seq;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	unsigned short	res1 : 4;
	unsigned short	doff : 4;
	unsigned short	fin  : 1;
	unsigned short	syn  : 1;
	unsigned short	rst  : 1;
	unsigned short	psh  : 1;
	unsigned short	ack  : 1;
	unsigned short	urg  : 1;
	unsigned short	ece  : 1;
	unsigned short	cwr  : 1;
#else
	unsigned short	doff : 4;
	unsigned short	res1 : 4;
	unsigned short	cwr  : 1;
	unsigned short	ece  : 1;
	unsigned short	urg  : 1;
	unsigned short	ack  : 1;
	unsigned short	psh  : 1;
	unsigned short	rst  : 1;
	unsigned short	syn  : 1;
	unsigned short	fin  : 1;
#endif
	unsigned short	window;
	unsigned short	check;
	unsigned short	urg_ptr;
}__packed;

#endif

