/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __ICMP_PRO_H
#define __ICMP_PRO_H


/* ICMP packet types */
#define ICMP_ECHO_REPLY   0
#define ICMP_ECHO_REQUEST 8

struct pro_icmp_hdr {
    uint8_t     type;   /* ICMP packet type. */
    uint8_t     code;   /* ICMP packet code. */
    uint16_t    cksum;  /* ICMP packet checksum. */
    uint16_t    ident;  /* ICMP packet identifier. */
    uint16_t    seq_nb; /* ICMP packet sequence number. */
}__packed;


#endif /* __ICMP_PRO_H */


