/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __GTPU_PRO_H
#define __GTPU_PRO_H

/* Echo Request */
#define MSG_TYPE_T_ECHO_REQ     (1)
/* Echo Response */
#define MSG_TYPE_T_ECHO_RESP    (2)
/* Error Indication */
#define MSG_TYPE_T_ERR_INDI   	(26)
/* Supported Extension Headers Notification */
#define MSG_TYPE_SEHN   	    (31)
/* End Marker */
#define MSG_TYPE_T_END_MARKER   (254)
/* G-PDU */
#define MSG_TYPE_T_PDU          (255)

/* Gtpu头部最小长度是8个字节 */
#define GTP_HDR_LEN_MIN   (8)

union pro_gtp_flags {
    unsigned char     data;
    struct {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    unsigned char pn        : 1;        /* Is N-PDU Number present */
    unsigned char s         : 1;        /* Is Sequence Number present */
    unsigned char e         : 1;        /* Is Next Extension Header present */
    unsigned char reserve   : 1;        /* Reserved */
    unsigned char type      : 1;        /* Protocol type */
    unsigned char version   : 3;        /* GTP Version */
#else
    unsigned char version   : 3;        /* GTP Version */
    unsigned char type      : 1;        /* Protocol type */
    unsigned char reserve   : 1;        /* Reserved */
    unsigned char e         : 1;        /* Is Next Extension Header present */
    unsigned char s         : 1;        /* Is Sequence Number present */
    unsigned char pn        : 1;        /* Is N-PDU Number present */
#endif
    }s;
}__packed;

struct pro_gtp_hdr{
    union pro_gtp_flags     flags;      /* flags */
    unsigned char           msg_type;   /* message type */
    unsigned short          length;     /* length */
    unsigned int            teid;       /* TEID */
}__packed;

#endif

