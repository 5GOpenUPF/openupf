/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _FP_FWD_IPV4__
#define _FP_FWD_IPV4__

#ifdef __cplusplus
extern "C" {
#endif

#define fp_calc_hash_ipv4(a, b, c, e) \
    hash16_calc_ipv4(a, b, c, e)


inline void fp_pkt_match_n3_ipv4(fp_packet_info *pkt_info, fp_fast_table *head,
    fp_fast_entry *entry, fp_cblk_entry *cblk, int trace_flag);

inline void fp_pkt_match_n6_ipv4(fp_packet_info *pkt_info, fp_fast_table *head,
    fp_fast_entry *entry, fp_cblk_entry *cblk, int trace_flag);

void fp_pkt_inner_ipv4_proc(fp_packet_info *pkt_info);

void fp_pkt_ipv4_entry(fp_packet_info *pkt_info);


#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _FP_FWD_IPV4__ */

