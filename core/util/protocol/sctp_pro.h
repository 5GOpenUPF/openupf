/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __SCTP_PRO_H
#define __SCTP_PRO_H

struct pro_sctp_hdr {
    unsigned short source;
    unsigned short dest;
    unsigned int   vtag;
    unsigned int   checksum;
}__packed;

#endif
