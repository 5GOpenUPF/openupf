/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _FP_FWD_NONIP__
#define _FP_FWD_NONIP__

#ifdef __cplusplus
extern "C" {
#endif

#define fp_calc_hash_nonip(a, b, c, e) \
    hash16_calc_ipv4(a, b, c, e)

void fp_pkt_match_n3_nonip(fp_packet_info *pkt_info, fp_fast_table *head,
    fp_fast_entry *entry, fp_cblk_entry *cblk, int trace_flag);

void fp_pkt_match_n6_nonip(fp_packet_info *pkt_info, fp_fast_table *head,
    fp_fast_entry *entry, fp_cblk_entry *cblk, int trace_flag);

void fp_pkt_inner_non_ip_proc(fp_packet_info *pkt_info);

int fp_pkt_n3_nonip_forw(fp_packet_info *pkt_info, fp_fast_entry *entry,
    fp_inst_entry *inst_entry, fp_far_entry *far_entry, int count_len, int trace_flag);

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _FP_FWD_NONIP__ */

