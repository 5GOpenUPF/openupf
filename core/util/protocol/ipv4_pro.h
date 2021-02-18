/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __IPV4_PRO_H
#define __IPV4_PRO_H

#define IP_PRO_ICMP    1    /* Internet Control Message Protocol    */
#define IP_PRO_IGMP    2    /* Internet Group Management Protocol   */
#define IP_PRO_TCP     6    /* Transmission Control Protocol    */
#define IP_PRO_UDP     17   /* User Datagram Protocol       */
#define IP_PRO_GRE     47   /* Internet Control Message Protocol    */
#define IP_PRO_ESP     50   /* Encapsulation Security Payload protocol */
#define IP_PRO_AH      51   /* Authentication Header protocol       */
#define IP_PRO_ICMPV6  58   /* Internet Control Message Protocol V6   */
#define IP_PRO_OSPF    89   /* OSPF  */
#define IP_PRO_COMP    108  /* Compression Header protocol */
#define IP_PRO_SCTP    132  	/* Stream Control Transport Protocol    */

#define IP_PRO_FRAG_MORE        0x2000
#define IP_PRO_FRAG_OFF_MASK    0x1FFF

struct pro_ipv4_hdr {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    unsigned char  ihl      : 4;
    unsigned char  version  : 4;
#else
    unsigned char  version  : 4;
    unsigned char  ihl      : 4;
#endif
	unsigned char  tos;
	unsigned short tot_len;
	unsigned short id;
	unsigned short frag_off;
	unsigned char  ttl;
	unsigned char  protocol;
	unsigned short check;
	unsigned int   source;
	unsigned int   dest;
}__packed;

#endif

