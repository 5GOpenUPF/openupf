/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __VLAN_PRO_H
#define __VLAN_PRO_H

#ifndef VLAN_HLEN
#define VLAN_HLEN  (4)
#endif

union vlan_tci {
    unsigned short data;
    struct {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        unsigned short vid : 12;
        unsigned short dei : 1;    
        unsigned short pri : 3;
#else
        unsigned short pri : 3;
        unsigned short dei : 1;
        unsigned short vid : 12;
#endif
    } s;
};

struct pro_vlan_hdr {
    union vlan_tci tci;
    unsigned short  eth_type;
}__packed;

#endif

