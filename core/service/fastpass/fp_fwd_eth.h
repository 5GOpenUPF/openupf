/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _FP_FWD_ETH__
#define _FP_FWD_ETH__

#ifdef __cplusplus
extern "C" {
#endif


#define fp_calc_hash_eth(a, b, c) \
    hash16_calc_ethernet(a, b, c)


void fp_pkt_inner_ethernet_proc(fp_packet_info *pkt_info);
void fp_pkt_eth_n6_entry(fp_packet_info *pkt_info);

void fp_pkt_match_n6_eth(fp_packet_info *pkt_info, fp_fast_table *head,
    fp_fast_entry *entry, fp_cblk_entry *cblk, int trace_flag);

#ifdef ETHERNET_SIMPLE_PROC
/* Return 0: forward   1: drop */
int fp_pkt_n3_eth_forw(fp_packet_info *pkt_info, comm_msg_fast_cfg *entry_cfg,
    fp_inst_entry *inst_entry, fp_far_entry *far_entry, int count_len, int trace_flag);
#endif

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _FP_FWD_ETH__ */


