/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _FP_MAIN_H__
#define _FP_MAIN_H__

#ifndef ENABLE_OCTEON_III
#include "fp_dpdk_adapter.h"
#else
#include "fp_nic_adapter.h"
#endif
#include "fp_msg.h"

#ifdef __cplusplus
extern "C" {
#endif

//#define ENABLE_FP_URR

/* Enable IP frag */
#define ENABLE_IP_FRAG

/* Enable DNS cache */
#define ENABLE_DNS_CACHE

/* DEBUG new outer-header_create/removal function */
#define DEBUG_NEW_OHCR

/* Ethernet simple process */
#define ETHERNET_SIMPLE_PROC

#define FP_1M                   0x100000
#define FP_1K                   0x400
#define FP_CACHE_LINE           128
#define FP_CACHE_LINE_BIT       7
#define FP_CACHE_LINE_MASK      (FP_CACHE_LINE - 1)

#define FP_MAX_NAME_LEN         32

#define FP_FWD_RESEND_TIME_LEN                  2       /* 2 second */
#define FP_FWD_TMP_PKT_NUM                      128


/* FPU Signaling trace logs */
#define MAX_TRACE_FLOW_NUM      (10)

typedef struct tag_fpu_Signaling_trace_t {
    uint32_t    sip;
    uint32_t    dip;
    uint16_t    spt;
    uint16_t    dpt;
    uint8_t     pro;
    uint8_t     valid;  /* 0:invalid, 1: valid */
    uint16_t    spare;
} fpu_Signaling_trace_t;

typedef struct tag_fpu_Signaling_trace_ueip_t {
    uint32_t   					ueip;
	ros_rwlock_t                rwlock;
} fpu_Signaling_trace_ueip_t;


typedef enum {
    FP_SOCK_TO_SPU_CTRL,
    FP_SOCK_TO_SPU_SRVC,
    FP_SOCK_TO_SPU_N3_ARP,
    FP_SOCK_TO_SPU_N6_ARP,
    FP_SOCK_TO_PHY_N3_SRVC,
    FP_SOCK_TO_PHY_N6_SRVC,
    FP_SOCK_TO_PHY_N4_SRVC,
    FP_SOCK_BUTT,
}fp_socket_t;

typedef struct tag_fp_connect_mb_channel_cfg {
    uint16_t                    mb_ips_num;
    uint16_t                    mb_port;
    uint32_t                    spare;
    uint32_t                    mb_ips[COMM_MSG_MAX_CONNECT_CHANNEL];
}fp_connect_mb_channel_cfg;

typedef struct tag_fp_packet_info {
    char                *buf;
    void                *arg;
    struct filter_key   match_key;
    int                 len;
}fp_packet_info;

static inline comm_msg_header_t *fp_fill_msg_header(uint8_t *buf)
{
    comm_msg_header_t *msg_hdr = (comm_msg_header_t *)buf;

    msg_hdr->magic_word    = htonl(COMM_MSG_MAGIC_WORD);
    msg_hdr->comm_id       = 0;
    msg_hdr->major_version = COMM_MSG_MAJOR_VERSION;
    msg_hdr->minor_version = COMM_MSG_MINOR_VERSION;
    msg_hdr->total_len     = COMM_MSG_HEADER_LEN;

    return msg_hdr;
}

inline fp_connect_mb_channel_cfg *fp_get_mb_chnl_config(void);
void fp_trace_capture_packet(int trace_flag, void *mbuf);

void fp_forward_pkt_to_sp(fp_packet_info *pkt_info, fp_fast_entry *entry,
    int trace_flag, uint8_t pkt_type);
void fp_forward_pkt_buf_to_sp(char *buf, uint32_t len, fp_fast_entry *entry,
    int trace_flag, uint8_t pkt_type);

uint8_t *fp_get_port_mac(uint8_t port);
comm_msg_system_config_t *fp_config_var_get(void);
void fp_collect_status(comm_msg_fpu_stat *stat);
int32_t fp_init_phaseI(void);
void    fp_deinit(void);
int32_t fp_init_phaseII(void);
void    fp_init_phaseII_deinit(void);
int     fp_phy_pkt_entry(char *buf, int len, uint16_t port_id, void *arg);
int     fp_quagga_pkt_entry(char *buf, int len, void *arg);

uint32_t fp_get_time(void);
void *fp_fast_table_get(uint32_t type);
void *fp_inst_table_get(void);
void *fp_far_table_get(void);
void *fp_bar_table_get(void);
void *fp_qer_table_get(void);
void *fp_buff_pool_get(void);
void *fp_mac_table_get(void);
void *fp_frag_buff_get(void);

void fp_packet_stat_count(uint32_t stat_mod);
int fp_phy_n4_pkt_entry(char *buf, int len, void *arg);

int fp_check_signal_trace(uint32_t sip, uint32_t dip, uint16_t spt, uint16_t dpt, uint8_t pro);

uint32_t fp_get_capture2spu_switch(void);

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _FP_MAIN_H__ */

