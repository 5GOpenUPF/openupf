/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __IPSEC_PRO_H
#define __IPSEC_PRO_H

struct pro_ah_hdr {
    unsigned char   next_hdr;
    unsigned char   payload_len;
    unsigned short  reserve;
    unsigned int    spi;
    unsigned int    seq;
    unsigned int    auth;
}__packed;

struct pro_esp_hdr {
    unsigned int    spi;
    unsigned int    seq;
}__packed;

#endif
