/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _FP_FWD_COMMON__
#define _FP_FWD_COMMON__

#ifdef __cplusplus
extern "C" {
#endif

#define NON_IP_SOURCE_PORT      2333

#define FP_STAT_PER_COLLECT_BYTES 50000

fp_fast_entry *fp_table_match_fast_entry(fp_fast_table *table, uint32_t hash_key, uint32_t aux_info);

inline void fp_pkt_stat_drop(fp_inst_entry *inst_entry, int pktlen);
inline void fp_pkt_stat_forw(fp_inst_entry *inst_entry, int pktlen, comm_msg_fast_cfg *entry_cfg);
inline void fp_pkt_stat_err(fp_inst_entry *inst_entry);

inline fp_fast_entry *fp_pkt_no_match(fp_packet_info *pkt_info, uint8_t is_tcp,
    fp_fast_table *head, uint32_t hash_key, uint32_t aux_info, int trace_flag);

int fp_pkt_temp_buffer(fp_packet_info *pkt_info, fp_fast_table *head,
    fp_fast_entry *entry, int trace_flag);

inline void fp_pkt_set_transport_level(uint8_t *pkt, comm_msg_transport_level_t *forw_trans);

int fp_pkt_qer_process(comm_msg_inst_config *inst_config, comm_msg_qer_gtpu_ext **gtpu_ext,
    uint8_t is_ul, int count_len, int trace_flag);

int fp_pkt_buffer_action_process(fp_packet_info *pkt_info, fp_fast_table *head, fp_fast_entry *entry,
    comm_msg_far_config *far_cfg, int trace_flag);

void fp_pkt_send2phy(void *m, fp_cblk_entry *cblk, uint8_t fwd_if, uint16_t port_id);

char *fp_pkt_outer_header_remove(fp_packet_info *pkt_info, comm_msg_outh_rm_t *outh_rm);

char *fp_pkt_outer_header_create(char *pkt, int *pkt_len, void *mbuf, comm_msg_outh_cr_t *outh,
    comm_msg_inst_config *inst, char *extension, comm_msg_qer_gtpu_ext *gtpu_ext, uint8_t forw_if);

int32_t fp_pkt_ipv4_reply_dns(fp_packet_info *pkt_info, struct pro_udp_hdr *udp_header);

void fp_pkt_inner_eth_nonip_proc(fp_packet_info *pkt_info);

void fp_pkt_match_n3_eth_and_nonip(fp_packet_info *pkt_info, fp_fast_table *head,
    fp_fast_entry *entry, fp_cblk_entry *cblk, int trace_flag);

void fp_pkt_redirect_N3_http(fp_packet_info *pkt_info, struct pro_tcp_hdr *tcp_hdr,
    char *url, uint8_t ip_ver);


static inline void fp_pkt_fill_outer_src_mac(struct pro_eth_hdr *eth_hdr, uint8_t port_id)
{
    ros_memcpy(eth_hdr->source, fp_get_port_mac(port_id), ETH_ALEN);
}

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _FP_FWD_COMMON__ */


