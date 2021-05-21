/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _FP_FWD_IPV6__
#define _FP_FWD_IPV6__

#ifdef __cplusplus
extern "C" {
#endif


#define fp_calc_hash_ipv6(a, b, c, d, e) \
    hash16_calc_ipv6(a, b, c, d, e)


#pragma pack(1)
typedef struct  tag_comm_msg_fast_cfg_ipv6 {
    struct ipv6_key     detail;         /* detail info */
    uint8_t             dst_mac[6];     /* next hop mac */
    uint8_t             temp_flag;      /* 1:fist packet sent to sp, 0:normal */
    uint8_t             pdr_si;         /* pdr source interface */
    uint32_t            inst_index;     /* relative inst table index */
}comm_msg_fast_cfg_ipv6;
#pragma pack()


void fp_pkt_match_n3_ipv6(fp_packet_info *pkt_info, fp_fast_table *head,
    fp_fast_entry *entry, fp_cblk_entry *cblk, int trace_flag);

void fp_pkt_match_n6_ipv6(fp_packet_info *pkt_info, fp_fast_table *head,
    fp_fast_entry *entry, fp_cblk_entry *cblk, int trace_flag);

void fp_pkt_inner_ipv6_proc(fp_packet_info *pkt_info);

void fp_pkt_ipv6_entry(fp_packet_info *pkt_info);

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _FP_FWD_IPV6__ */

