/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"

#ifndef ENABLE_OCTEON_III
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include "dpdk.h"
#endif
#include "fp_fwd_common.h"
#include "fp_fwd_eth.h"


static void fp_pkt_match_n3_eth(fp_packet_info *pkt_info, fp_fast_table *head,
    fp_fast_entry *entry, fp_cblk_entry *cblk, int trace_flag)
{
    void                    *mbuf = pkt_info->arg;
    char                    *pkt = pkt_info->buf;
    int                     len = pkt_info->len;
    int						count_len = len - pkt_info->match_key.field_offset[FLOW_FIELD_GTP_CONTENT];
    comm_msg_fast_cfg       *entry_cfg;
    int                     efflen = len;
    char                    *pktforw = pkt;
    fp_inst_entry           *inst_entry = NULL;
    comm_msg_inst_config    *inst_config;
    fp_far_entry            *far_entry;
    pkt_buf_struct          *m = (pkt_buf_struct *)mbuf;
    int                     len_diff;

    /* Get configuration */
    entry_cfg = (comm_msg_fast_cfg *)&(entry->cfg_data);

    LOG_TRACE(FASTPASS, RUNNING, trace_flag,
        "handle packet, buf %p, pkt %p, len %d, queue(%d, %d), fast entry %d, "
        "dst mac %02x:%02x:%02x:%02x:%02x:%02x, "
        "src mac %02x:%02x:%02x:%02x:%02x:%02x, ",
        mbuf, pkt, len, head->port_no, head->port_type, entry->index,
        *(uint8_t *)(pkt + 0), *(uint8_t *)(pkt + 1), *(uint8_t *)(pkt + 2),
        *(uint8_t *)(pkt + 3), *(uint8_t *)(pkt + 4), *(uint8_t *)(pkt + 5),
        *(uint8_t *)(pkt + 6), *(uint8_t *)(pkt + 7), *(uint8_t *)(pkt + 8),
        *(uint8_t *)(pkt + 9), *(uint8_t *)(pkt + 10), *(uint8_t *)(pkt + 11));

    /* If temp status, buffer it */
    if (unlikely(entry_cfg->temp_flag)) {
        if (likely(0 == fp_pkt_temp_buffer(pkt_info, head, entry, trace_flag))) {
            /* Don't check other action bit */
            /* Exit 1, temp branch. Queue mbuf, no cblk in this case, update 2 stats */
            return;
        } else {
            LOG_TRACE(FASTPASS, ERR, trace_flag, "Packet temp buffer failed.");

            goto err;
        }
    }

    /* Get inst entry */
    inst_entry = fp_inst_entry_get(entry_cfg->inst_index);
    if (unlikely((!inst_entry)||(!inst_entry->valid))) {
        LOG_TRACE(FASTPASS, ERR, trace_flag, "get inst entry(%d) failed!", entry_cfg->inst_index);

        goto err;
    }
    inst_config  = &(inst_entry->config);

    /* when get inst_entry, first thing is check light */
    if (unlikely(inst_entry->control.light == COMM_MSG_LIGHT_RED)){
        LOG_TRACE(FASTPASS, RUNNING, trace_flag, "get inst entry(%d) light(%d), drop!",
            entry_cfg->inst_index, inst_entry->control.light);

        goto drop;
    }

    /* Get configuration */
    if (likely(inst_config->choose.d.flag_far1 || inst_config->choose.d.flag_far2)) {
        far_entry = fp_far_entry_get(entry_cfg->far_index);
        if ((!far_entry)||(!far_entry->valid)) {
            LOG_TRACE(FASTPASS, ERR, trace_flag, "get far entry failed!");

            goto err;
        }
    }
    else {
        /* If no far, should drop it */
        goto err;
    }

    /* when get far_entry, first thing is check drop flag */
    if (unlikely(far_entry->config.action.d.drop)){
        LOG_TRACE(FASTPASS, RUNNING, trace_flag, "get far entry(%d) action(%d), drop!",
            entry_cfg->far_index, far_entry->config.action.d.drop);

        goto drop;
    }

    /* get read lock, keep no reading when writing */
    ros_rwlock_read_lock(&inst_entry->rwlock);
    fp_print_action_str(&far_entry->config.action, trace_flag);

    /* If forw */
    if (likely(far_entry->config.action.d.forw)) {
        comm_msg_outh_rm_t      *outh_rm;
        comm_msg_far_choose_t   *far_choose;

        far_choose = &(far_entry->config.choose);

        /* forwarding policy */
        if (unlikely(far_choose->d.flag_forward_policy1)) {
        }

        /* outer header removal */
        if (likely(inst_config->choose.d.flag_rm_header)) {

            outh_rm = (comm_msg_outh_rm_t *)&(inst_entry->config.rm_outh);
            pktforw = fp_pkt_outer_header_remove(pkt_info, outh_rm);

            /* set pkt start position */
            efflen -= (pktforw - pkt);
        }

        /* outer header creation */
        if (likely(far_choose->d.flag_out_header1)) {
            /* Save original MAC address */
            uint8_t orig_mac[12]; /* Dest MAC and Source MAC */

            ros_memcpy(orig_mac, pktforw, sizeof(orig_mac));
            pktforw += sizeof(orig_mac);

            pktforw = fp_pkt_outer_header_create(pktforw, &efflen, m,
                &(far_entry->config.forw_cr_outh), inst_config, NULL,
                NULL, far_entry->config.forw_if);

            /* set mac header */
            pktforw -= sizeof(orig_mac);
            ros_memcpy(pktforw, orig_mac, sizeof(orig_mac));

            LOG_TRACE(FASTPASS, RUNNING, trace_flag,
                "effective length(after add outer header) is %d, pkt start %p.",
                efflen, pktforw);
        }

        /* transport level marking */
        /* put it on outer header if have */
        if (unlikely(far_choose->d.flag_transport_level1)) {
            fp_pkt_set_transport_level((uint8_t *)pktforw,
                &far_entry->config.forw_trans);
        }

        /* send to the port that FAR given */
        /* Set data off */
        len_diff = (char *)pktforw - pkt;
        pkt_buf_data_off(m) += len_diff;
        pkt_buf_set_len(m, pkt_buf_data_len(m) - len_diff);

		/* in forw case, check QER first */
#ifdef ENABLE_FP_QER
		if (inst_config->choose.d.flag_qer) {
            if (0 > fp_pkt_qer_process(inst_config, NULL, G_TRUE, count_len, trace_flag)) {
                ros_read_write_unlock(&inst_entry->rwlock);
                /* Color red */
                goto drop;
            }
        }
#endif

        /* update stat */
        fp_pkt_stat_forw(inst_entry, count_len, entry_cfg);

		/* tracking */
		fp_trace_capture_packet(trace_flag, m);
    }

    /* If buff and nocp, buffer it */
    /* only download flow support BUFF and NOCP, refer to 3gpp 25244-5.2.3.1 */

    /* Transmit branch */
    ros_rwlock_read_unlock(&inst_entry->rwlock);

    /* Send buffer */
    fp_pkt_send2phy(m, cblk, far_entry->config.forw_if, pkt_info->port_id);

    LOG_TRACE(FASTPASS, RUNNING, trace_flag,
        "forward ipv4 packet(len %d) to interface %d!",
        pkt_buf_data_len(m), far_entry->config.forw_if);

    /* Exit 2, forward branch. Queue mbuf, queue(dpdk mode) or free(nic mode) cblk, update 2 stats */
    return;

drop:

    fp_packet_stat_count(COMM_MSG_FP_STAT_UP_DROP);
    /* update stat */
    fp_pkt_stat_drop(inst_entry, count_len);

    /* if fail, free cblk or mbuf */
#ifdef CONFIG_FP_DPDK_PORT
    if (cblk) {
        cblk->port = FP_DROP_PORT_ID; /* Let the applicant release */
        fp_dpdk_add_cblk_buf(cblk);
    } else {
        /* free buffer */
        fp_free_pkt(mbuf);
    }
#else
    /* free buffer */
    fp_free_pkt(mbuf);

    if (cblk)
        fp_cblk_free(cblk);
#endif

    /* Exit 3, drop branch. Free mbuf and cblk, update 2 stats */
    return;

err:
    /* for debug, count by error types and core id */
    fp_packet_stat_count(COMM_MSG_FP_STAT_ERR_PROC);

    /* update stat for showing */
    fp_pkt_stat_err(inst_entry);

    /* if fail, free cblk or mbuf */
#ifdef CONFIG_FP_DPDK_PORT
    if (cblk) {
        cblk->port = FP_DROP_PORT_ID; /* Let the applicant release */
        fp_dpdk_add_cblk_buf(cblk);
    } else {
        /* free buffer */
        fp_free_pkt(mbuf);
    }
#else
    /* free buffer */
    fp_free_pkt(mbuf);

    if (cblk)
        fp_cblk_free(cblk);
#endif

    /* Exit 4, error branch. Free mbuf, cblk, update 2 stats */
    return;
}

void fp_pkt_match_n6_eth(fp_packet_info *pkt_info, fp_fast_table *head,
    fp_fast_entry *entry, fp_cblk_entry *cblk, int trace_flag)
{
    void                    *mbuf = pkt_info->arg;
    char                    *pkt = pkt_info->buf;
    int                     len = pkt_info->len;
	int						count_len = len - (pkt_info->match_key.field_offset[FLOW_FIELD_L1_UDP] + UDP_HLEN);
    comm_msg_fast_cfg       *entry_cfg;
    struct pro_eth_hdr      *eth_hdr;
    int                     efflen = len;
    char                    *pktforw = pkt;
    fp_inst_entry           *inst_entry = NULL;
    comm_msg_inst_config    *inst_config;
    fp_far_entry            *far_entry;
    pkt_buf_struct          *m = (pkt_buf_struct *)mbuf;
    int                     len_diff;
#ifdef ENABLE_FP_QER
    comm_msg_qer_gtpu_ext   *gtpu_ext = NULL;   /* init gtpu extension, don't remove */
#endif
#ifdef ENABLE_OCTEON_III
    char *localbuf;
#endif

    /* Get configuration */
    entry_cfg = (comm_msg_fast_cfg *)&(entry->cfg_data);

    LOG_TRACE(FASTPASS, RUNNING, trace_flag,
        "handle packet, buf %p, pkt %p, len %d, queue(%d, %d), fast entry %d, "
        "dst mac %02x:%02x:%02x:%02x:%02x:%02x, "
        "src mac %02x:%02x:%02x:%02x:%02x:%02x, ",
        mbuf, pkt, len, head->port_no, head->port_type, entry->index,
        *(uint8_t *)(pkt + 0), *(uint8_t *)(pkt + 1), *(uint8_t *)(pkt + 2),
        *(uint8_t *)(pkt + 3), *(uint8_t *)(pkt + 4), *(uint8_t *)(pkt + 5),
        *(uint8_t *)(pkt + 6), *(uint8_t *)(pkt + 7), *(uint8_t *)(pkt + 8),
        *(uint8_t *)(pkt + 9), *(uint8_t *)(pkt + 10), *(uint8_t *)(pkt + 11));

    /* If temp status, buffer it */
    if (unlikely(entry_cfg->temp_flag)) {
        if (likely(0 == fp_pkt_temp_buffer(pkt_info, head, entry, trace_flag))) {
            /* Don't check other action bit */
            /* Exit 1, temp branch. Queue mbuf, no cblk in this case, update 2 stats */
            return;
        } else {
            LOG_TRACE(FASTPASS, ERR, trace_flag, "Packet temp buffer failed.");

            goto err;
        }
    }

    /* Get inst entry */
    inst_entry = fp_inst_entry_get(entry_cfg->inst_index);
    if (unlikely((!inst_entry)||(!inst_entry->valid))) {

        LOG_TRACE(FASTPASS, ERR, trace_flag, "get inst entry %u failed!", entry_cfg->inst_index);

        goto err;
    }
    inst_config  = &(inst_entry->config);
    if (unlikely(inst_entry->control.light == COMM_MSG_LIGHT_RED)) {
        LOG_TRACE(FASTPASS, RUNNING, trace_flag, "get inst entry(%d) light(%d), drop!",
            entry_cfg->inst_index, inst_entry->control.light);

        goto drop;
    }

    /* Get configuration */
    if (likely(inst_config->choose.d.flag_far1 || inst_config->choose.d.flag_far2)) {
        far_entry = fp_far_entry_get(entry_cfg->far_index);
        if ((!far_entry)||(!far_entry->valid)) {
            LOG_TRACE(FASTPASS, ERR, trace_flag, "get far entry(%d) failed!", entry_cfg->far_index);

            goto err;
        }
    }
    else {
        /* If no far, should drop it */
        goto err;
    }

    /* when get far_entry, first thing is check drop flag */
    if (unlikely(far_entry->config.action.d.drop)){
        LOG_TRACE(FASTPASS, RUNNING, trace_flag, "get far entry(%d) action(%d), drop!",
            entry_cfg->far_index, far_entry->config.action.d.drop);

        goto drop;
    }

    /* get read lock, keep no reading when writing */
    ros_rwlock_read_lock(&inst_entry->rwlock);
    fp_print_action_str(&far_entry->config.action, trace_flag);

    /* If forw */
    if (likely(far_entry->config.action.d.forw)) {
        comm_msg_far_choose_t   *far_choose;

        /* in forw case, check QER first */
#ifdef ENABLE_FP_QER
        if (inst_config->choose.d.flag_qer) {
            if (0 > fp_pkt_qer_process(inst_config, &gtpu_ext, G_FALSE, count_len, trace_flag)) {
                ros_rwlock_read_unlock(&inst_entry->rwlock);
                /* Color red */
                goto drop;
            }
        }
#endif

        far_choose = &(far_entry->config.choose);

        /* forwarding policy */


        /* header enrichment */
        /* only up flow support header enrichment, refer to 3gpp 29244-8.2.25.1 */

        /* outer header removal */
        if (likely(inst_config->choose.d.flag_rm_header)) {
            comm_msg_outh_rm_t *outh_rm = (comm_msg_outh_rm_t *)&inst_entry->config.rm_outh;

            pktforw = fp_pkt_outer_header_remove(pkt_info, outh_rm);

            /* set pkt start position */
            efflen -= (pktforw - pkt);
        }

        /* outer header creation */
        if (likely(far_choose->d.flag_out_header1)) {
            pktforw = fp_pkt_outer_header_create(pktforw, &efflen, m,
                &(far_entry->config.forw_cr_outh), inst_config, NULL,
#ifdef ENABLE_FP_QER
                gtpu_ext, far_entry->config.forw_if);
#else
                NULL, far_entry->config.forw_if);
#endif
            LOG_TRACE(FASTPASS, RUNNING, trace_flag,
                "effective length(after add outer header) is %d, pkt start %p.",
                efflen, pktforw);
        }

        /* set mac header */
        eth_hdr  = (struct pro_eth_hdr *)(pktforw - ETH_ALEN - ETH_ALEN);

        ros_memcpy(eth_hdr->dest, entry_cfg->dst_mac, ETH_ALEN);
        fp_pkt_fill_outer_src_mac(eth_hdr, pkt_info->port_id);

        /* transport level marking */
        /* put it on outer header if have */
        if (unlikely(far_choose->d.flag_transport_level1)) {
            fp_pkt_set_transport_level((uint8_t *)eth_hdr,
                &far_entry->config.forw_trans);
        }

        /* send to the port that FAR given */
        /* Set data off */
        len_diff = (char *)eth_hdr - pkt;
        pkt_buf_data_off(m) += len_diff;
        pkt_buf_set_len(m, pkt_buf_data_len(m) - len_diff);

        /* update stat */
        fp_pkt_stat_forw(inst_entry, count_len, entry_cfg);

		/* tracking */
		fp_trace_capture_packet(trace_flag, m);
    }
    /* If buff and nocp, buffer it */
    else if (unlikely((far_entry->config.action.d.buff)
      || (far_entry->config.action.d.nocp))) {
        if (likely(0 == fp_pkt_buffer_action_process(pkt_info, head, entry,
                &far_entry->config, trace_flag))) {

            /* Don't check other action bit */
            ros_rwlock_read_unlock(&inst_entry->rwlock);

            /* if cblk exist, free it */
            if (cblk)
                fp_cblk_free(cblk);

            /* Exit 2, buff and nocp branch. Queue mbuf, free cblk, update 2 stats */
            return;
        } else {
            ros_rwlock_read_unlock(&inst_entry->rwlock);

            goto err;
        }
    }

    /* Transmit branch */
    ros_rwlock_read_unlock(&inst_entry->rwlock);

    /* Send buffer */
    fp_pkt_send2phy(m, cblk, far_entry->config.forw_if, pkt_info->port_id);

    LOG_TRACE(FASTPASS, RUNNING, trace_flag,
        "forward ipv4 packet(len %d) to interface %d!",
        pkt_buf_data_len(m), far_entry->config.forw_if);

    /* Exit 3, forw branch. Queue mbuf, queue(dpdk mode) or free(nic mode) cblk, update 2 stats */
    return;


drop:

    fp_packet_stat_count(COMM_MSG_FP_STAT_DOWN_DROP);

    /* update stat */
    fp_pkt_stat_drop(inst_entry, count_len);

    /* if fail, free cblk or mbuf */
#ifdef CONFIG_FP_DPDK_PORT
    if (cblk) {
        cblk->port = FP_DROP_PORT_ID; /* Let the applicant release */
        fp_dpdk_add_cblk_buf(cblk);
    } else {
        /* free buffer */
        fp_free_pkt(mbuf);
    }
#else
    /* free buffer */
    fp_free_pkt(mbuf);

    if (cblk)
        fp_cblk_free(cblk);
#endif

    /* Exit 4, drop branch. Free mbuf and cblk, update 2 stats */
    return;


err:
    /* for debug, count by error types and core id */
    fp_packet_stat_count(COMM_MSG_FP_STAT_ERR_PROC);

    /* update stat for showing */
    fp_pkt_stat_err(inst_entry);

    /* if fail, free cblk or mbuf */
#ifdef CONFIG_FP_DPDK_PORT
    if (cblk) {
        cblk->port = FP_DROP_PORT_ID; /* Let the applicant release */
        fp_dpdk_add_cblk_buf(cblk);
    } else {
        /* free buffer */
        fp_free_pkt(mbuf);
    }
#else
    /* free buffer */
    fp_free_pkt(mbuf);

    if (cblk)
        fp_cblk_free(cblk);
#endif

    /* Exit 5, error branch. Free mbuf, cblk, update 2 stats */
    return;
}

/* Return 0: forward   1: drop */
int fp_pkt_n3_eth_forw(fp_packet_info *pkt_info, comm_msg_fast_cfg *entry_cfg,
    fp_inst_entry *inst_entry, fp_far_entry *far_entry, int count_len, int trace_flag)
{
    void                    *mbuf = pkt_info->arg;
    char                    *pkt = pkt_info->buf;
    int                     len = pkt_info->len;
    int                     efflen = len;
    char                    *pktforw = pkt;
    comm_msg_inst_config    *inst_config = &inst_entry->config;
    pkt_buf_struct          *m = (pkt_buf_struct *)mbuf;
    int                     len_diff;
    comm_msg_far_choose_t   *far_choose = &far_entry->config.choose;

    /* forwarding policy */
    if (unlikely(far_choose->d.flag_forward_policy1)) {
    }

    /* outer header removal */
    if (likely(inst_config->choose.d.flag_rm_header)) {
        comm_msg_outh_rm_t *outh_rm = (comm_msg_outh_rm_t *)&(inst_entry->config.rm_outh);

        pktforw = fp_pkt_outer_header_remove(pkt_info, outh_rm);

        /* set pkt start position */
        efflen -= (pktforw - pkt);
    }

    /* outer header creation */
    if (likely(far_choose->d.flag_out_header1)) {
        /* Save original MAC address */
        uint8_t orig_mac[12]; /* Dest MAC and Source MAC */

        ros_memcpy(orig_mac, pktforw, sizeof(orig_mac));
        pktforw += sizeof(orig_mac);

        pktforw = fp_pkt_outer_header_create(pktforw, &efflen, m,
            &(far_entry->config.forw_cr_outh), inst_config, NULL,
            NULL, far_entry->config.forw_if);

        /* set mac header */
        pktforw -= sizeof(orig_mac);
        ros_memcpy(pktforw, orig_mac, sizeof(orig_mac));

        LOG_TRACE(FASTPASS, RUNNING, trace_flag,
            "effective length(after add outer header) is %d, pkt start %p.",
            efflen, pktforw);
    }

    /* transport level marking */
    /* put it on outer header if have */
    if (unlikely(far_choose->d.flag_transport_level1)) {
        fp_pkt_set_transport_level((uint8_t *)pktforw,
            &far_entry->config.forw_trans);
    }

    /* send to the port that FAR given */
    /* Set data off */
    len_diff = (char *)pktforw - pkt;
    pkt_buf_data_off(m) += len_diff;
    pkt_buf_set_len(m, pkt_buf_data_len(m) - len_diff);

	/* in forw case, check QER first */
#ifdef ENABLE_FP_QER
	if (inst_config->choose.d.flag_qer) {
        if (0 > fp_pkt_qer_process(inst_config, NULL, G_TRUE, count_len, trace_flag)) {
            /* Color red */
            return -1;
        }
    }
#endif

    /* update stat */
    fp_pkt_stat_forw(inst_entry, count_len, entry_cfg);

	/* tracking */
	fp_trace_capture_packet(trace_flag, m);

    return 0;
}

void fp_pkt_inner_ethernet_proc(fp_packet_info *pkt_info)
{
    uint32_t hash_key, aux_info;
    fp_fast_entry  *entry;
    int trace_flag = G_FALSE;
    uint8_t *buf = (uint8_t *)pkt_info->buf;
    fp_fast_table *head = fp_fast_table_get(COMM_MSG_FAST_MAC);

    /* Calc hash key */
    hash_key = fp_calc_hash_eth((uint8_t *)buf, 0, &aux_info);
    aux_info = (*(uint32_t *)&buf[0] ^ *(uint32_t *)&buf[4] ^ *(uint32_t *)&buf[8]);

    LOG_TRACE(FASTPASS, RUNNING, trace_flag,
        "N3 fast table match(dmac: %02x:%02x:%02x:%02x:%02x:%02x, smac: %02x:%02x:%02x:%02x:%02x:%02x),"
        " key 0x%08x aux 0x%08x len %d!",
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5],
        buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
        hash_key, aux_info, pkt_info->len);

    /* Match fast table */
    entry = fp_table_match_fast_entry(head, hash_key, aux_info);

    /* Entry exist, handle packet by entry content */
    if (likely(entry)) {
        /* Match success, forwarding */
        LOG_TRACE(FASTPASS, RUNNING, trace_flag, "N3 fast table match failed");

        /* send out by action */
        fp_pkt_match_n3_eth(pkt_info, head, entry, NULL, trace_flag);

        fp_packet_stat_count(COMM_MSG_FP_STAT_N3_MATCH);
    }
    /* Match failed, transfer to slow plane */
    else {
        LOG_TRACE(FASTPASS, RUNNING, trace_flag, "N3 fast table match failed");

        /* Alloc new entry */
        entry = fp_pkt_no_match(pkt_info, G_FALSE, head, hash_key, aux_info, trace_flag);
        if (unlikely(NULL == entry)) {
            LOG_TRACE(FASTPASS, ERR, trace_flag, "Alloc fast entry failed.");
            fp_free_pkt(pkt_info->arg);
            fp_packet_stat_count(COMM_MSG_FP_STAT_UP_DROP);
            return;
        }
        fp_forward_pkt_to_sp(pkt_info, entry, trace_flag, FAST_TBL_IPV4);

        fp_packet_stat_count(COMM_MSG_FP_STAT_N3_NOMATCH);

        /* pkt have been buffered, don't free here */
        /* fp_free_pkt(arg); */
    }
}

void fp_pkt_eth_n6_entry(fp_packet_info *pkt_info)
{
    fp_fast_entry  *entry;
    uint32_t hash_key, aux_info;
    int trace_flag = G_FALSE;
    uint8_t *buf = (uint8_t *)pkt_info->buf;
    fp_fast_table *head = fp_fast_table_get(COMM_MSG_FAST_MAC);

    LOG(FASTPASS, RUNNING, "Recv N6 Ethernet packet----");
    fp_packet_stat_count(COMM_MSG_FP_STAT_DOWN_RECV);

    /* Calc hash key */
    hash_key = fp_calc_hash_eth((uint8_t *)buf, 0, &aux_info);
    aux_info = (*(uint32_t *)&buf[0] ^ *(uint32_t *)&buf[4] ^ *(uint32_t *)&buf[8]);

    LOG_TRACE(FASTPASS, RUNNING, trace_flag,
        "N6 fast table match(dmac: %02x:%02x:%02x:%02x:%02x:%02x, smac: %02x:%02x:%02x:%02x:%02x:%02x),"
        " key 0x%08x aux 0x%08x len %d!",
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5],
        buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
        hash_key, aux_info, pkt_info->len);

    /* Match fast table */
    entry = fp_table_match_fast_entry(head, hash_key, aux_info);

    /* Match failed, transfer to slow plane */
    if (unlikely(NULL == entry)) {
        LOG_TRACE(FASTPASS, RUNNING, trace_flag, "N6 fast table match failed");

        /* Alloc new entry */
        entry = fp_pkt_no_match(pkt_info, G_FALSE, head, hash_key, aux_info, trace_flag);
        if (unlikely(NULL == entry)) {
            LOG_TRACE(FASTPASS, ERR, trace_flag, "Alloc fast entry failed.");
            fp_free_pkt(pkt_info->arg);
            fp_packet_stat_count(COMM_MSG_FP_STAT_DOWN_DROP);
            return;
        }
        fp_forward_pkt_to_sp(pkt_info, entry, trace_flag, FAST_TBL_MAC);

        fp_packet_stat_count(COMM_MSG_FP_STAT_N6_NOMATCH);

        /* pky have been buffered, don't free here */
        /* fp_free_pkt(arg); */
    }
    else {   /* Entry exist, handle packet by entry content */
        /* Match success, forwarding */
        LOG_TRACE(FASTPASS, RUNNING, trace_flag, "N6 fast table match success");

        /* send out by action */
        fp_pkt_match_n6_eth(pkt_info, head, entry, NULL, trace_flag);

        fp_packet_stat_count(COMM_MSG_FP_STAT_N6_MATCH);
    }
}


