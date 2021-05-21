/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "common.h"
#include "util.h"
#include "platform.h"
#include "comm_msg.h"
#include "key_extract.h"
#include "fp_msg.h"
#include "fp_main.h"
#include "fp_qer.h"
#include "fp_dns.h"
#include "fp_fwd_nonip.h"
#include "fp_fwd_eth.h"

#ifndef ENABLE_OCTEON_III
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include "dpdk.h"
#endif
#include "fp_fwd_common.h"


extern CVMX_SHARED uint32_t fp_net_n3_local_ip;
extern CVMX_SHARED uint32_t fp_net_n4_local_ip;
extern CVMX_SHARED uint8_t  fp_host_n3_local_ipv6[IPV6_ALEN];
extern CVMX_SHARED uint8_t  fp_host_n4_local_ipv6[IPV6_ALEN];

#ifdef ENABLE_OCTEON_III
extern uint32_t core_id;
#endif

fp_fast_entry *fp_table_match_fast_entry(fp_fast_table *table, uint32_t hash_key, uint32_t aux_info)
{
    fp_fast_bucket *bucket;
    fp_fast_entry  *entry;

    bucket = &table->bucket[(hash_key & table->bucket_mask)];
    if (unlikely(!bucket))
    {
        LOG(FASTPASS, ERR, "uiIndex:%d", (hash_key & table->bucket_mask));
        return G_NULL;
    }

    LOG(FASTPASS, RUNNING, "search tree 0x%x, uiInfo 0x%x.",
        (hash_key & table->bucket_mask), aux_info);

    ros_rwlock_read_lock(&bucket->rwlock);
    entry = (fp_fast_entry *)avluint_search(bucket->hash_tree, aux_info);
    if (!entry)
    {
        ros_rwlock_read_unlock(&bucket->rwlock);
        LOG(FASTPASS, RUNNING, "entry is NULL.");
        return G_NULL;
    }
    entry->count = 0;
    ros_rwlock_read_unlock(&bucket->rwlock);

    return entry;
}

inline void fp_pkt_stat_drop(fp_inst_entry *inst_entry, int pktlen)
{
    fp_inst_table *head = fp_inst_table_get();

    /* update stat */
    ++inst_entry->stat.drop_pkts;
    inst_entry->stat.drop_bytes += pktlen;

    Res_MarkSet(head->res_stat, inst_entry->index);
    if (unlikely(!inst_entry->active)) {
        inst_entry->active = G_TRUE;
    }
}

inline void fp_pkt_stat_forw(fp_inst_entry *inst_entry, int pktlen, comm_msg_fast_cfg *entry_cfg)
{
    fp_inst_table *head = fp_inst_table_get();

    /* update stat */
    ++inst_entry->stat.forw_pkts;
    inst_entry->stat.forw_bytes += pktlen;

    if (unlikely(entry_cfg->tcp_push)) {
        entry_cfg->tcp_hs_stat += pktlen;
    }

    Res_MarkSet(head->res_stat, inst_entry->index);
    if (unlikely(!inst_entry->active)) {
        inst_entry->active = G_TRUE;
    }
}

inline void fp_pkt_stat_err(fp_inst_entry *inst_entry)
{
    fp_inst_table *head = fp_inst_table_get();

    if (inst_entry) {
        /* update stat */
        ++inst_entry->stat.err_cnt;

        Res_MarkSet(head->res_stat, inst_entry->index);
        if (unlikely(!inst_entry->active)) {
            inst_entry->active = G_TRUE;
        }
    }
}

inline fp_fast_entry *fp_pkt_no_match(fp_packet_info *pkt_info, uint8_t is_tcp,
        fp_fast_table *head, uint32_t hash_key, uint32_t aux_info, int trace_flag)
{
    fp_fast_entry *entry;
#ifdef ENABLE_OCTEON_III
    char *localbuf;
#endif
    void *mbuf = pkt_info->arg;
    char *pkt = pkt_info->buf;
    int len = pkt_info->len;

    LOG_TRACE(FASTPASS, RUNNING, trace_flag,
        "handle no match packet buf %p, pkt %p, len %d!",
        mbuf, pkt, len);

    /* Alloc a entry in local */
    entry = fp_fast_alloc(head);
    if (unlikely(NULL == entry)) {
        LOG_TRACE(FASTPASS, ERR, trace_flag, "alloc fast entry failed(head %p)!", head);
        return NULL;
    }
    else {
        comm_msg_fast_cfg *entry_cfg;
        fp_fast_shadow *shadow;
        fp_cblk_entry  *node;

        /* Need to associate in advance to prevent the release of fast entry in case of failure */
        shadow = fp_fast_shadow_get(head, entry->index);
        shadow->head = head;
        shadow->key  = hash_key;

        /* get cblk */
        node = (fp_cblk_entry *)fp_cblk_alloc();
        if (unlikely(!node)) {
            LOG_TRACE(FASTPASS, ERR, trace_flag, "alloc cblk node failed!");
            fp_fast_free(head, entry->index);
            return NULL;
        }

        /* don't support wqe buffering on nic */
#ifdef ENABLE_OCTEON_III
        localbuf = fp_block_alloc();
        if (unlikely(!localbuf)) {
            fp_free_pkt(mbuf);
            fp_cblk_free(node);
            LOG_TRACE(FASTPASS, ERR, trace_flag, "alloc block node failed!");
            return NULL;
        }

        /* copy content to buffer */
        memcpy(localbuf, pkt, len);
        node->buf       = localbuf;
        node->pkt       = localbuf;
        node->free      = (CBLK_FREE)fp_block_free;
        node->lcore_id  = core_id;

#ifdef RECORD_FAST_INFO_NEW_VER
        /* Record fast ID and fast type */
        SET_FAST_TID(&localbuf[len], entry->index);
        SET_FAST_TYPE(&localbuf[len], head->port_type);
#endif

        fp_free_pkt(mbuf);
#else
        node->buf       = mbuf;
        node->pkt       = pkt;
        node->free      = NULL;
        node->lcore_id  = fp_get_coreid();

#ifdef RECORD_FAST_INFO_NEW_VER
        /* Record fast ID and fast type */
        SET_FAST_TID(&pkt[len], entry->index);
        SET_FAST_TYPE(&pkt[len], head->port_type);
        pkt_buf_set_len(mbuf, pkt_buf_data_len(mbuf) + RECORD_FAST_INFO_LEN);
#endif
#endif

        /* fill cblk */
#ifdef RECORD_FAST_INFO_NEW_VER
        node->len       = len + RECORD_FAST_INFO_LEN;
#else
        node->len       = len;
#endif
        node->port      = pkt_info->port_id;

        /* enqueue */
        ros_rwlock_write_lock(&shadow->rwlock);
        lstAdd(&(shadow->list), (NODE *)node);
        ros_rwlock_write_unlock(&shadow->rwlock);

        LOG_TRACE(FASTPASS, RUNNING, trace_flag,
            "add cblk(%p) node %d(with buf %p) to shadow %d buf list.",
            node, node->index, node->buf, shadow->index);

        /* Set entry number to 1(in default) */
        entry_cfg = (comm_msg_fast_cfg *)&(entry->cfg_data);

        /* Set tmp flag */
        entry_cfg->temp_flag  = G_TRUE;
        entry_cfg->tcp_push   = entry_cfg->is_tcp = is_tcp ? G_TRUE : G_FALSE;
        entry_cfg->inst_index = COMM_MSG_ORPHAN_NUMBER;
        entry_cfg->tcp_hs_stat = 0;

        /* Put in hash tree */
        if (NULL == fp_fast_table_add(head, entry, hash_key, aux_info)) {
            LOG_TRACE(FASTPASS, ERR, trace_flag,
                "put fast entry %d aux_info 0x%x in tree %p IPV4 pool failed!",
                entry->index, aux_info, head);

            /* dequeue cblock, MBUF will be free outside */
            ros_rwlock_write_lock(&shadow->rwlock);
            lstDelete(&(shadow->list), (NODE *)node);
            ros_rwlock_write_unlock(&shadow->rwlock);
            fp_cblk_free(node);

            /* Free entry, the free of cblock is also among them */
            fp_fast_free(head, entry->index);

            return NULL;
        }
        shadow->entry = entry;

        fp_fast_link_add(COMM_MSG_ORPHAN_NUMBER, shadow);
    }

    return entry;
}

int fp_pkt_temp_buffer(fp_packet_info *pkt_info, fp_fast_table *head,
    fp_fast_entry *entry, int trace_flag)
{
#ifdef ENABLE_OCTEON_III
    char            *localbuf;
#endif
    uint32_t        cur_time = ros_getime();
    fp_cblk_entry   *node, *old_cblk;
    fp_fast_shadow  *shadow = fp_fast_shadow_get(head, entry->index);

    LOG_TRACE(FASTPASS, RUNNING, trace_flag, "action: temp buffer.");

    /* if over than max number of buffering, free it */
    if (lstCount(&(shadow->list)) >= FP_FWD_TMP_PKT_NUM) {

        LOG_TRACE(FASTPASS, ERR, trace_flag,
            "over single flow temp packet limit(%d), drop it!",
            FP_FWD_TMP_PKT_NUM);

        return -1;
    }

    /* get cblk */
    node = (fp_cblk_entry *)fp_cblk_alloc();
    if (unlikely(!node)) {
        LOG_TRACE(FASTPASS, ERR, trace_flag, "alloc cblk node failed!");

        return -1;
    }

    /* don't support wqe buffering on nic */
#ifdef ENABLE_OCTEON_III
    localbuf = fp_block_alloc();
    if (unlikely(!localbuf)) {

        /* free node */
        fp_cblk_free(node);
        LOG_TRACE(FASTPASS, ERR, trace_flag, "alloc block node failed!");

        return -1;
    }

    /* copy content to buffer */
    memcpy(localbuf, pkt_info->pkt, pkt_info->len);
    node->buf       = localbuf;
    node->pkt       = localbuf;
    node->free      = (CBLK_FREE)fp_block_free;
    node->lcore_id  = core_id;

#ifdef RECORD_FAST_INFO_NEW_VER
    /* Record fast ID and fast type */
    SET_FAST_TID(&localbuf[pkt_info->len], entry->index);
    SET_FAST_TYPE(&localbuf[pkt_info->len], head->port_type);
#endif
#else
    node->buf       = pkt_info->arg;
    node->pkt       = pkt_info->buf;
    node->free      = NULL;
    node->lcore_id  = fp_get_coreid();

#ifdef RECORD_FAST_INFO_NEW_VER
    /* Record fast ID and fast type */
    SET_FAST_TID(&pkt_info->buf[pkt_info->len], entry->index);
    SET_FAST_TYPE(&pkt_info->buf[pkt_info->len], head->port_type);
    pkt_buf_set_len(pkt_info->arg, pkt_buf_data_len(pkt_info->arg) + RECORD_FAST_INFO_LEN);
#endif
#endif

    /* fill cblk */
#ifdef RECORD_FAST_INFO_NEW_VER
    node->len       = pkt_info->len + RECORD_FAST_INFO_LEN;
#else
    node->len       = pkt_info->len;
#endif
    node->port      = pkt_info->port_id;

    ros_rwlock_write_lock(&shadow->rwlock);

    LOG(FASTPASS, RUNNING, "Fast entry tcp_seg_mgmt(%p), shadow temp count: %d",
        entry->tcp_seg_mgmt, lstCount(&(shadow->list)));

    if (NULL == entry->tcp_seg_mgmt) {
        /* check time diff with first pkt, if greater than 1 second, resend */
        old_cblk = (fp_cblk_entry *)lstFirst(&(shadow->list));
        LOG(FASTPASS, RUNNING, "Temp buffer first node(%p)", old_cblk);
        if (old_cblk) {
            /* if over 1 second, the entry still is in temp mode, resend */
            if (old_cblk->time < (cur_time - FP_FWD_RESEND_TIME_LEN)) {
                /* update time */
                old_cblk->time = cur_time;

                /* resend current packet, because they belong to same flow */
                if (unlikely(ERROR == fp_send_to_chn_port(rte_pktmbuf_mtod((struct rte_mbuf *)pkt_info->arg, char *),
                    rte_pktmbuf_data_len((struct rte_mbuf *)pkt_info->arg)))) {
                    LOG_TRACE(FASTPASS, RUNNING, trace_flag, "forward ipv4 packet to SMU failed!");
                }

                /* update stat */
                fp_packet_stat_count(COMM_MSG_FP_STAT_N3_NOMATCH);
            }
        } else {
            fp_forward_pkt_to_sp(pkt_info, entry, trace_flag, head->port_type);
            fp_packet_stat_count(COMM_MSG_FP_STAT_N3_NOMATCH);
        }
    }
    /* add node to tmp pkt list tail */
    lstAdd(&(shadow->list), (NODE *)node);

    ros_rwlock_write_unlock(&shadow->rwlock);

#ifdef ENABLE_OCTEON_III
    /* in nic mode, we saved the copied buffer, so the original buffer needs to be released */
    fp_free_pkt(pkt_info->arg);
#endif

    return 0;
}

inline void fp_pkt_set_transport_level(uint8_t *pkt, comm_msg_transport_level_t *forw_trans)
{
    struct pro_ipv4_hdr *ip_hdr;
    struct pro_ipv6_hdr *ip6_hdr;
    uint16_t ethtype = *(uint16_t *)&pkt[12], offset = 12;
    uint8_t flag = G_TRUE;

    LOG(FASTPASS, RUNNING, "Ethtype: 0x%hx", ethtype);
    while (flag) {
        switch (ethtype) {
            case FLOW_ETH_PRO_8021Q:
            case FLOW_ETH_PRO_8021AD:
                offset += VLAN_HLEN;
                ethtype = *(uint16_t *)&pkt[offset];
                break;

            case FLOW_ETH_PRO_IP:
                offset += 2;
                ip_hdr = (struct pro_ipv4_hdr *)&pkt[offset];
                ip_hdr->tos = (forw_trans->tos & forw_trans->mask);
                flag = G_FALSE;
                break;

            case FLOW_ETH_PRO_IPV6:
                offset += 2;
                ip6_hdr = (struct pro_ipv6_hdr *)&pkt[offset];
                ip6_hdr->vtc_flow.d.priority = (forw_trans->tos & forw_trans->mask);
                flag = G_FALSE;
                break;

            default:
                flag = G_FALSE;
                break;
        }
    }
}

#ifdef ENABLE_FP_QER
int fp_pkt_qer_process(comm_msg_inst_config *inst_config, comm_msg_qer_gtpu_ext **gtpu_ext,
    uint8_t is_ul, int count_len, int trace_flag)
{
    fp_qer_entry *qer_entry;
    int qer_idx;
    int color = COMM_MSG_LIGHT_YELLOW;
    FP_QER_HANDLE fp_qer_handle;
    fp_qos_meter *meter;

    if (is_ul) {
        fp_qer_handle = fp_qer_handle_ul;
    } else {
        fp_qer_handle = fp_qer_handle_dl;
    }

    /* As long as there is a QER marked green, it will be forwarded */
    /* check all valid qer items */
    for (qer_idx = 0; qer_idx < inst_config->qer_number; qer_idx++) {

        /* get entry */
        qer_entry = fp_qer_entry_get(inst_config->qer_index[qer_idx]);
        if ((!qer_entry)||(!qer_entry->valid)) {
            continue;
        }

        if (NULL != gtpu_ext && qer_entry->qer_cfg.gtpu_ext.ext_len != 0) {
            *gtpu_ext = &qer_entry->qer_cfg.gtpu_ext;
        }

        /* check qer action */
        /* gtpu_ext initialized when declearation */
        color = fp_qer_handle(count_len, 1, qer_entry, color);
    }

    if ((inst_config->qer_number > 1) && (color == COMM_MSG_LIGHT_GREEN)) {
        for (qer_idx = 0; qer_idx < inst_config->qer_number; qer_idx++) {

            /* get entry */
            qer_entry = fp_qer_entry_get(inst_config->qer_index[qer_idx]);
            if ((!qer_entry)||(!qer_entry->valid)) {
                continue;
            }

            if (is_ul) {
                meter = &qer_entry->ul_meter;
            } else {
                meter = &qer_entry->dl_meter;
            }

            if(meter->color == COMM_MSG_LIGHT_RED) {
                ros_atomic64_add(&meter->debt, count_len);
                LOG_TRACE(FASTPASS, RUNNING, trace_flag, "get qer(%d) debt %ld!",
                    qer_entry->index, ros_atomic64_read(&meter->debt));
            }
        }
    }

    LOG_TRACE(FASTPASS, RUNNING, trace_flag, "qer handle finish, color: %s.",
        color == COMM_MSG_LIGHT_RED ? "Red" : color == COMM_MSG_LIGHT_GREEN ? "Green" : "Yellow");

    /* if action is drop */
    if (color == COMM_MSG_LIGHT_RED) {
        return -1;
    }

    return 0;
}
#endif

int fp_pkt_buffer_action_process(fp_packet_info *pkt_info, fp_fast_table *head, fp_fast_entry *entry,
    comm_msg_far_config *far_cfg, int trace_flag)
{
    fp_bar_entry        *bar_entry;
    comm_msg_bar_config *bar_conf;
    fp_bar_container    *bar_cont;
#ifdef ENABLE_OCTEON_III
    char *localbuf;
#endif
    fp_fast_shadow      *shadow;
    fp_cblk_entry       *node;

    /* If action is buff or nocp, config process should confirm bar exist */
    if (far_cfg->choose.d.section_bar) {
        bar_entry = fp_bar_entry_get(far_cfg->bar_index);
        if ((!bar_entry)||(!bar_entry->valid)) {
            LOG_TRACE(FASTPASS, ERR, trace_flag, "get bar entry failed!");

            /* Don't check other action bit */
            return -1;
        }
    }
    else {
        LOG_TRACE(FASTPASS, ERR, trace_flag, "set buff action but no config BAR!");

        /* Don't check other action bit */
        return -1;
    }
    bar_conf = &(bar_entry->config);
    bar_cont = &(bar_entry->container);

    /* get buff list */
    shadow = fp_fast_shadow_get(head, entry->index);

    /* check bar packet number */
    if (bar_conf->pkts_max) {
        /* if buffered packet over number limit, drop */
        if (ros_atomic32_read(&(bar_cont->pkts_count)) >= bar_conf->pkts_max) {
            LOG_TRACE(FASTPASS, RUNNING, trace_flag,
                "buffered packets(%d) over number limit(%d), port %d, type %d.",
                ros_atomic32_read(&(bar_cont->pkts_count)), bar_conf->pkts_max,
                head->port_no, head->port_type);

            return -1;
        }
    }

    /* check bar_conf packet time */
    if (bar_conf->time_max) {
        if (!ros_atomic32_read(&(bar_cont->time_start))) {
            ros_atomic32_set(&(bar_cont->time_start), fp_get_time());
        }
        else {
            /* if buffered packet over time limit, drop */
            if (fp_get_time() - ros_atomic32_read(&(bar_cont->time_start))
                >= bar_conf->time_max) {
                LOG_TRACE(FASTPASS, RUNNING, trace_flag,
                    "buffered packets(%d) over time limit(%d), port %d, type %d.",
                    ros_atomic32_read(&bar_cont->pkts_count),
                    bar_conf->pkts_max, head->port_no, head->port_type);

                return -1;
            }
        }
    }

    /* get cblk */
    node = (fp_cblk_entry *)fp_cblk_alloc();
    if (unlikely(NULL == node)) {
        LOG_TRACE(FASTPASS, ERR, trace_flag, "alloc cblk node failed!");

        return -1;
    }

    /* don't support wqe buffering on nic */
#ifdef ENABLE_OCTEON_III
    localbuf = fp_block_alloc();
    if (unlikely(NULL == localbuf)) {
        fp_cblk_free(node);
        LOG_TRACE(FASTPASS, ERR, trace_flag, "alloc block node failed!");
        return -1;
    }

    /* copy content to buffer */
    memcpy(localbuf, pkt_info->buf, pkt_info->len);
    node->buf       = localbuf;
    node->pkt       = localbuf;
    node->free      = (CBLK_FREE)fp_block_free;
    node->lcore_id  = core_id;

    /* in nic mode, we saved the copied buffer, so the original buffer needs to be released */
    fp_free_pkt(pkt_info->arg);
#else
    node->buf       = pkt_info->arg;
    node->pkt       = pkt_info->buf;
    node->free      = NULL;
    node->lcore_id  = fp_get_coreid();
#endif

    /* fill cblk */
    node->len       = pkt_info->len;
    node->port      = pkt_info->port_id;

    /* enqueue */
    ros_rwlock_write_lock(&shadow->rwlock);
    lstAdd(&(shadow->list), (NODE *)node);
    ros_rwlock_write_unlock(&shadow->rwlock);

    ros_atomic32_add(&(bar_cont->pkts_count), 1);

    return 0;
}

void fp_pkt_send2phy(void *m, fp_cblk_entry *cblk, uint8_t fwd_if, uint16_t port_id)
{
    /* Send buffer */
#ifdef CONFIG_FP_DPDK_PORT
    if (unlikely(cblk)) {
        switch (fwd_if) {
            case EN_COMM_DST_IF_ACCESS:
                fp_dpdk_add_cblk_buf(cblk);
                fp_packet_stat_count(COMM_MSG_FP_STAT_DOWN_FWD);
                break;

            default:
                fp_dpdk_add_cblk_buf(cblk);
                fp_packet_stat_count(COMM_MSG_FP_STAT_UP_FWD);
                break;
        }
    }
    else
#endif
    {
        fp_fwd_snd_to_phy(m, port_id);
        switch (fwd_if) {
            case EN_COMM_DST_IF_ACCESS:
                fp_packet_stat_count(COMM_MSG_FP_STAT_DOWN_FWD);
                break;

            case EN_COMM_DST_IF_CORE:
                fp_packet_stat_count(COMM_MSG_FP_STAT_UP_FWD);
                break;

            default:
                fp_packet_stat_count(COMM_MSG_FP_STAT_UP_FWD);
                break;
        }

        if (cblk)
            fp_cblk_free(cblk);
    }
}

char *fp_pkt_outer_header_remove(fp_packet_info *pkt_info, comm_msg_outh_rm_t *outh_rm)
{
    uint8_t     *field_ofs = pkt_info->match_key.field_offset;
    uint8_t     *field_len = pkt_info->match_key.field_length;
    char        *resp_pos = pkt_info->buf;

    switch (outh_rm->type) {
        case 0:
            /* GTP-U/UDP/IPv4 */
            if (likely(FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_L1_IPV4) &&
                       FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_L1_UDP) &&
                       FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_GTP_T_PDU))) {

                resp_pos += (field_ofs[FLOW_FIELD_GTP_U] + GTP_HDR_LEN_MIN);
            } else {
                LOG(FASTPASS, ERR, "ERROR: Outer header removal description: %d, packet not GTP-U",
                    outh_rm->ohr_flag);
            }
            break;

        case 1:
            /* GTP-U/UDP/IPv6 */
            if (likely(FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_L1_IPV6) &&
                       FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_L1_UDP) &&
                       FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_GTP_T_PDU))) {

                resp_pos += (field_ofs[FLOW_FIELD_GTP_U] + GTP_HDR_LEN_MIN);
            } else {
                LOG(FASTPASS, ERR, "ERROR: Outer header removal description: %d, packet not GTP-U",
                    outh_rm->ohr_flag);
            }
            break;

        case 2:
            /* UDP/IPv4 */
            if (likely(FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_L1_IPV4) &&
                       FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_L1_UDP))) {

                resp_pos += (field_ofs[FLOW_FIELD_L1_UDP] + UDP_HLEN);
            } else {
                LOG(FASTPASS, ERR, "ERROR: Outer header removal description: %d, packet not IPv4 & UDP",
                    outh_rm->ohr_flag);
            }
            break;

        case 3:
            /* UDP/IPv6 */
            if (likely(FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_L1_IPV6) &&
                       FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_L1_UDP))) {

                resp_pos += (field_ofs[FLOW_FIELD_L1_UDP] + UDP_HLEN);
            } else {
                LOG(FASTPASS, ERR, "ERROR: Outer header removal description: %d, packet not IPv4 & UDP",
                    outh_rm->ohr_flag);
            }
            break;

        case 4:
            /* IPv4 */
            if (likely(FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_L1_IPV4))) {

                resp_pos += (field_ofs[FLOW_FIELD_L1_IPV4] + field_len[FLOW_FIELD_L1_IPV4]);
            } else {
                LOG(FASTPASS, ERR, "ERROR: Outer header removal description: %d, packet not IPv4",
                    outh_rm->ohr_flag);
            }
            break;

        case 5:
            /* IPv6 */
            if (likely(FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_L1_IPV6))) {

                resp_pos += (field_ofs[FLOW_FIELD_L1_IPV6] + field_len[FLOW_FIELD_L1_IPV6]);
            } else {
                LOG(FASTPASS, ERR, "ERROR: Outer header removal description: %d, packet not IPv4",
                    outh_rm->ohr_flag);
            }
            break;

        case 6:
            /* GTP-U/UDP/IP */
            if (likely((FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_L1_IPV4) ||
                        FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_L1_IPV6)) &&
                       FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_L1_UDP) &&
                       FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_GTP_T_PDU))) {

                resp_pos += (field_ofs[FLOW_FIELD_GTP_U] + GTP_HDR_LEN_MIN);
            } else {
                LOG(FASTPASS, ERR, "ERROR: Outer header removal description: %d, packet not GTP-U",
                    outh_rm->ohr_flag);
            }
            break;

        case 7:
            /* VLAN S-TAG */
            if (likely(FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_L1_SVLAN))) {
                /* Save original MAC address */
                uint8_t orig_mac[12]; /* Dest MAC and Source MAC */

                ros_memcpy(orig_mac, resp_pos, sizeof(orig_mac));
                resp_pos += VLAN_HLEN;
                ros_memcpy(resp_pos, orig_mac, sizeof(orig_mac));

            } else {
                LOG(FASTPASS, ERR, "ERROR: Outer header removal description: %d, packet not IPv4",
                    outh_rm->ohr_flag);
            }
            break;

        case 8:
            /* S-TAG and C-TAG */
            if (likely(FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_L1_SVLAN) &&
                       FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_L1_CVLAN))) {
                /* Save original MAC address */
                uint8_t orig_mac[12]; /* Dest MAC and Source MAC */

                ros_memcpy(orig_mac, resp_pos, sizeof(orig_mac));
                resp_pos += (VLAN_HLEN << 1);
                ros_memcpy(resp_pos, orig_mac, sizeof(orig_mac));

            } else {
                LOG(FASTPASS, ERR, "ERROR: Outer header removal description: %d, packet not IPv4",
                    outh_rm->ohr_flag);
            }
            break;

        default:
            LOG(FASTPASS, ERR, "ERROR: Unsupported Outer header removal description: %d",
                    outh_rm->ohr_flag);
            break;
    }

    if (outh_rm->flag) {
        if (likely(FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_GTP_EXT))) {

            //resp_pos = pkt_info->buf + (field_ofs[FLOW_FIELD_GTP_EXT] + field_len[FLOW_FIELD_GTP_EXT]);
            resp_pos += field_len[FLOW_FIELD_GTP_EXT];
        } else {
            LOG(FASTPASS, ERR, "ERROR: Outer header removal Extension header fail, no such header");
        }
    }

    return resp_pos;
}

char *fp_pkt_outer_header_create(char *pkt, int *pkt_len, void *mbuf, comm_msg_outh_cr_t *outh,
    comm_msg_inst_config *inst, char *extension, comm_msg_qer_gtpu_ext *gtpu_ext, uint8_t forw_if)
{
    struct pro_udp_hdr  *udp_hdr;
    uint32_t            content_len = *pkt_len;
    uint32_t            extlen = 0;
    char                *payload = pkt;
#ifdef CONFIG_FP_DPDK_PORT
    pkt_buf_struct      *m_local = mbuf;
#endif

    /* Add outer header */
    if (outh->type.d.gtp_udp_ipv4 || outh->type.d.gtp_udp_ipv6) {
        struct pro_gtp_hdr  *gtpu_hdr;

        /* if qer need extension, add it first */
        /* all gtpu extension length don't over than 12 bytes */
        if ((gtpu_ext)&&(gtpu_ext->ext_len <= 12)) {
            uint8_t gtpu_ext_len = gtpu_ext->ext_len;
            //uint8_t old_sq_npdu[3];

            if (extension) {
                /* Save old Sequence Number and N-PDU Number */
                //ros_memcmp(old_sq_npdu, payload, sizeof(old_sq_npdu));

                /* Existing extension header, add another extension header */
                payload += 3;
                --gtpu_ext_len;
                /* Valid for the next extension header type */
            }

            /* copy data to header */
            payload -= gtpu_ext_len;
            ros_memcpy(payload, gtpu_ext->content.data, gtpu_ext_len);

            /* if time stamp exist */
            if (gtpu_ext->content.s.qmp) {
                uint32_t *time_pos;
                comm_msg_qer_gtpu_ext *new_ext;

                /* copy time to extension */
                new_ext = (comm_msg_qer_gtpu_ext *)payload;
                time_pos = (uint32_t *)&new_ext->content.s.optional[gtpu_ext->ts_ofs];
                *time_pos = htonl(fp_get_time());
            }
            extlen = gtpu_ext_len;
        }

        /* get header */
        gtpu_hdr = (struct pro_gtp_hdr *)(payload - sizeof(struct pro_gtp_hdr));
        udp_hdr  = (struct pro_udp_hdr *)((char *)gtpu_hdr - sizeof(struct pro_udp_hdr));

        /* set gtpu header */
        gtpu_hdr->flags.data        = 0;
        gtpu_hdr->flags.s.version   = 1;
        gtpu_hdr->flags.s.type      = 1;
        if (extlen || extension) {
            gtpu_hdr->flags.s.e     = 1;
        }
        gtpu_hdr->teid      = htonl(outh->teid);
        gtpu_hdr->msg_type  = 0xFF;
        content_len         += (uint64_t)pkt - (uint64_t)payload;
        gtpu_hdr->length    = htons(content_len);

        /* set udp header */
        udp_hdr->dest       = FLOW_UDP_PORT_GTPU;
        udp_hdr->source     = FLOW_UDP_PORT_GTPU;
        content_len         += sizeof(struct pro_udp_hdr) + sizeof(struct pro_gtp_hdr);
        udp_hdr->len        = htons(content_len);
        udp_hdr->check      = 0;

        if (outh->type.d.gtp_udp_ipv4) {
            struct pro_ipv4_hdr *ip_hdr = (struct pro_ipv4_hdr *)((char *)udp_hdr
                - sizeof(struct pro_ipv4_hdr));

            /* set ip header */
            ip_hdr->version     = 4;
            ip_hdr->ihl         = 5;
            ip_hdr->tos         = 0;
            content_len        += 20;
            ip_hdr->tot_len     = htons(content_len);
            ip_hdr->id          = (uint16_t)ros_rdtsc();
            ip_hdr->frag_off    = 0;
            ip_hdr->ttl         = 0xFF;
            ip_hdr->protocol    = IP_PRO_UDP;
            ip_hdr->dest        = htonl(outh->ipv4);
            ip_hdr->check       = 0;

            switch (forw_if) {
                case EN_COMM_DST_IF_ACCESS:
                    ip_hdr->source = fp_net_n3_local_ip;
                    break;

                case EN_COMM_DST_IF_CORE:
                    break;

                case EN_COMM_DST_IF_SGILAN:
                    break;

                case EN_COMM_DST_IF_CP:
                    ip_hdr->source  = fp_net_n4_local_ip;
                    ip_hdr->check   = calc_crc_ip(ip_hdr);
                    udp_hdr->check  = calc_crc_udp(udp_hdr,ip_hdr);
                    break;

                case EN_COMM_DST_IF_5GVN:
                    break;

                default:
                    LOG(FASTPASS, ERR, "Abnormal source interface: %d", forw_if);
                    break;
            }

#ifdef CONFIG_FP_DPDK_PORT
            if (likely(dpdk_get_tx_offload() & DEV_TX_OFFLOAD_IPV4_CKSUM)) {
                m_local->l2_len    = ETH_HLEN;
                m_local->ol_flags |= (PKT_TX_IPV4|PKT_TX_IP_CKSUM);
            }
            else
#endif
            {
                ip_hdr->check   = calc_crc_ip(ip_hdr);
            }

            /* set udp header checksum */
#ifdef CONFIG_FP_DPDK_PORT
            if (likely(dpdk_get_tx_offload() & DEV_TX_OFFLOAD_UDP_CKSUM)) {
                m_local->l3_len    = (ip_hdr->ihl << 2);
                m_local->ol_flags |= (PKT_TX_IPV4|PKT_TX_IP_CKSUM|PKT_TX_UDP_CKSUM);

                udp_hdr->check = rte_ipv4_phdr_cksum(
                    (const struct rte_ipv4_hdr *)ip_hdr, m_local->ol_flags);
            }
            else
#endif
            {
                udp_hdr->check = calc_crc_udp(udp_hdr, ip_hdr);
            }

#ifdef CONFIG_FP_DPDK_PORT
            m_local->packet_type |= RTE_PTYPE_L3_IPV4; /* For IP fragment */
#endif

            /* change packet start position and length */
            payload   = (char *)ip_hdr - 2;
            *(uint16_t *)payload = FLOW_ETH_PRO_IP;
            *pkt_len = content_len + 2;
        }

        if (outh->type.d.gtp_udp_ipv6) {
            struct pro_ipv6_hdr *ip_hdr = (struct pro_ipv6_hdr *)((char *)udp_hdr
                - sizeof(struct pro_ipv6_hdr));

            /* set ip header */
            ip_hdr->vtc_flow.d.version  = 6;
            ip_hdr->vtc_flow.d.priority = 0;
            ip_hdr->vtc_flow.d.flow_lbl = 0;
            ip_hdr->vtc_flow.value      = htonl(ip_hdr->vtc_flow.value);
            ip_hdr->payload_len         = htons(content_len);
            ip_hdr->nexthdr             = IP_PRO_UDP;
            ip_hdr->hop_limit           = 64;

            switch (forw_if) {
                case EN_COMM_DST_IF_ACCESS:
                    ros_memcpy(ip_hdr->saddr, fp_host_n3_local_ipv6, IPV6_ALEN);
                    break;

                case EN_COMM_DST_IF_CORE:
                    break;

                case EN_COMM_DST_IF_SGILAN:
                    break;

                case EN_COMM_DST_IF_CP:
                    ros_memcpy(ip_hdr->saddr, fp_host_n4_local_ipv6, IPV6_ALEN);
                    udp_hdr->check = calc_crc_udp6(udp_hdr, ip_hdr);
                    break;

                case EN_COMM_DST_IF_5GVN:
                    break;

                default:
                    LOG(FASTPASS, ERR, "Abnormal source interface: %d", forw_if);
                    break;
            }

            ros_memcpy(ip_hdr->daddr, outh->ipv6.s6_addr, IPV6_ALEN);
            content_len += 40;

#ifdef CONFIG_FP_DPDK_PORT
            /* set udp header checksum */
            if (likely(dpdk_get_tx_offload()&DEV_TX_OFFLOAD_UDP_CKSUM)) {
                m_local->l2_len = ETH_HLEN;
                m_local->l3_len = 40;
                m_local->ol_flags |= (PKT_TX_IPV6|PKT_TX_UDP_CKSUM);

                udp_hdr->check = rte_ipv6_phdr_cksum(
                    (const struct rte_ipv6_hdr *)ip_hdr, m_local->ol_flags);
            }
            else
#endif
            {
                udp_hdr->check  = calc_crc_udp6(udp_hdr, ip_hdr);
            }

#ifdef CONFIG_FP_DPDK_PORT
            m_local->packet_type |= RTE_PTYPE_L3_IPV6; /* For IP fragment */
#endif

            /* change packet start position and length */
            payload = (char *)ip_hdr - 2;
            *(uint16_t *)payload = FLOW_ETH_PRO_IPV6;
            *pkt_len = content_len + 2;
        }
    }

    if (outh->type.d.udp_ipv4 || outh->type.d.udp_ipv6) {

        /* get header */
        udp_hdr  = (struct pro_udp_hdr *)(payload
            - sizeof(struct pro_udp_hdr));

        /* set udp header */
        udp_hdr->dest       = htons(outh->port);
        udp_hdr->source     = htons(NON_IP_SOURCE_PORT);
        content_len        += sizeof(struct pro_udp_hdr);
        udp_hdr->len        = htons(content_len);
        udp_hdr->check      = 0;

        if (outh->type.d.udp_ipv4) {
            struct pro_ipv4_hdr *ip_hdr = (struct pro_ipv4_hdr *)((char *)udp_hdr
                - sizeof(struct pro_ipv4_hdr));

            /* set ip header */
            ip_hdr->version     = 4;
            ip_hdr->ihl         = 5;
            ip_hdr->tos         = 0;
            content_len        += 20;
            ip_hdr->tot_len     = htons(content_len);
            ip_hdr->id          = (uint16_t)ros_rdtsc();
            ip_hdr->frag_off    = 0;
            ip_hdr->ttl         = 0xFF;
            ip_hdr->protocol    = IP_PRO_UDP;
            ip_hdr->dest        = htonl(outh->ipv4);
            ip_hdr->check       = 0;

            switch (forw_if) {
                case EN_COMM_DST_IF_ACCESS:
                    ip_hdr->source = fp_net_n3_local_ip;
                    break;

                case EN_COMM_DST_IF_CORE:
                    if (0 == inst->choose.d.flag_ueip_type) {
                        ip_hdr->source = htonl(inst->ueip.ipv4);
                    } else {
                        LOG(FASTPASS, ERR, "Outer header create failed, UEIP type: %s error.",
                            inst->choose.d.flag_ueip_type ? "IPv6" : "IPv4");
                    }
                    break;

                case EN_COMM_DST_IF_SGILAN:
                    break;

                case EN_COMM_DST_IF_CP:
                    ip_hdr->source  = fp_net_n4_local_ip;
                    ip_hdr->check   = calc_crc_ip(ip_hdr);
                    udp_hdr->check  = calc_crc_udp(udp_hdr, ip_hdr);
                    break;

                case EN_COMM_DST_IF_5GVN:
                    break;

                default:
                    LOG(FASTPASS, ERR, "Abnormal source interface: %d", forw_if);
                    break;
            }

#ifdef CONFIG_FP_DPDK_PORT
            if (likely(dpdk_get_tx_offload() & DEV_TX_OFFLOAD_IPV4_CKSUM)) {
                m_local->l2_len = ETH_HLEN;
                m_local->ol_flags |= (PKT_TX_IPV4|PKT_TX_IP_CKSUM);
            }
            else
#endif
            {
                ip_hdr->check   = calc_crc_ip(ip_hdr);
            }

            /* set udp header checksum */
#ifdef CONFIG_FP_DPDK_PORT
            if (likely(dpdk_get_tx_offload() & DEV_TX_OFFLOAD_UDP_CKSUM)) {
                m_local->l3_len    = (ip_hdr->ihl << 2);
                m_local->ol_flags |= (PKT_TX_IPV4|PKT_TX_IP_CKSUM|PKT_TX_UDP_CKSUM);

                udp_hdr->check = rte_ipv4_phdr_cksum(
                    (const struct rte_ipv4_hdr *)ip_hdr, m_local->ol_flags);
            }
            else
#endif
            {
                udp_hdr->check  = calc_crc_udp(udp_hdr, ip_hdr);
            }

#ifdef CONFIG_FP_DPDK_PORT
            m_local->packet_type |= RTE_PTYPE_L3_IPV4; /* For IP fragment */
#endif

            /* change packet start position and length */
            payload   = (char *)ip_hdr - 2;
            *(uint16_t *)payload = FLOW_ETH_PRO_IP;
            *pkt_len = content_len + 2;
        }

        if (outh->type.d.udp_ipv6) {
            struct pro_ipv6_hdr *ip_hdr = (struct pro_ipv6_hdr *)((char *)udp_hdr
                - sizeof(struct pro_ipv6_hdr));

            /* set ip header */
            ip_hdr->vtc_flow.d.version  = 6;
            ip_hdr->vtc_flow.d.priority = 0;
            ip_hdr->vtc_flow.d.flow_lbl = 0;
            ip_hdr->vtc_flow.value      = htonl(ip_hdr->vtc_flow.value);
            ip_hdr->payload_len         = htons(content_len);
            ip_hdr->nexthdr             = IP_PRO_UDP;
            ip_hdr->hop_limit           = 64;

            switch (forw_if) {
                case EN_COMM_DST_IF_ACCESS:
                    ros_memcpy(ip_hdr->saddr, fp_host_n3_local_ipv6, IPV6_ALEN);
                    break;

                case EN_COMM_DST_IF_CORE:
                    if (1 == inst->choose.d.flag_ueip_type) {
                        ros_memcpy(ip_hdr->saddr, inst->ueip.ipv6, IPV6_ALEN);
                    } else {
                        LOG(FASTPASS, ERR, "Outer header create failed, UEIP type: %s error.",
                            inst->choose.d.flag_ueip_type ? "IPv6" : "IPv4");
                    }
                    break;

                case EN_COMM_DST_IF_SGILAN:
                    break;

                case EN_COMM_DST_IF_CP:
                    ros_memcpy(ip_hdr->saddr, fp_host_n4_local_ipv6, IPV6_ALEN);
                    udp_hdr->check = calc_crc_udp6(udp_hdr, ip_hdr);
                    break;

                case EN_COMM_DST_IF_5GVN:
                    break;

                default:
                    LOG(FASTPASS, ERR, "Abnormal source interface: %d", forw_if);
                    break;
            }

            ros_memcpy(ip_hdr->daddr, outh->ipv6.s6_addr, IPV6_ALEN);
            content_len += 40;

#ifdef CONFIG_FP_DPDK_PORT
            /* set udp header checksum */
            if (likely(dpdk_get_tx_offload()&DEV_TX_OFFLOAD_UDP_CKSUM)) {
                m_local->l2_len = ETH_HLEN;
                m_local->l3_len = 40;
                m_local->ol_flags |= (PKT_TX_IPV6|PKT_TX_UDP_CKSUM);

                udp_hdr->check = rte_ipv6_phdr_cksum(
                    (const struct rte_ipv6_hdr *)ip_hdr, m_local->ol_flags);
            }
            else
#endif
            {
                udp_hdr->check  = calc_crc_udp6(udp_hdr, ip_hdr);
            }

#ifdef CONFIG_FP_DPDK_PORT
            m_local->packet_type |= RTE_PTYPE_L3_IPV6; /* For IP fragment */
#endif

            /* change packet start position and length */
            payload = (char *)ip_hdr - 2;
            *(uint16_t *)payload = FLOW_ETH_PRO_IPV6;
            *pkt_len = content_len + 2;
        }
    }
    if (outh->type.d.ipv4) {
        struct pro_ipv4_hdr *ip_hdr = (struct pro_ipv4_hdr *)(payload - sizeof(struct pro_ipv4_hdr));

        /* set ip header */
        ip_hdr->version     = 4;
        ip_hdr->ihl         = 5;
        ip_hdr->tos         = 0;
        content_len        += sizeof(struct pro_ipv4_hdr);
        ip_hdr->tot_len     = htons(content_len);
        ip_hdr->id          = (uint16_t)ros_rdtsc();
        ip_hdr->frag_off    = 0;
        ip_hdr->ttl         = 0xFF;
        ip_hdr->protocol    = 0;
        ip_hdr->dest        = htonl(outh->ipv4);
        ip_hdr->check       = 0;

        switch (forw_if) {
            case EN_COMM_DST_IF_ACCESS:
                ip_hdr->source = fp_net_n3_local_ip;
                break;

            case EN_COMM_DST_IF_CORE:
                if (0 == inst->choose.d.flag_ueip_type) {
                    ip_hdr->source = htonl(inst->ueip.ipv4);
                } else {
                    LOG(FASTPASS, ERR, "Outer header create failed, UEIP type: %s error.",
                        inst->choose.d.flag_ueip_type ? "IPv6" : "IPv4");
                }
                break;

            case EN_COMM_DST_IF_SGILAN:
                break;

            case EN_COMM_SRC_IF_CP:
                ip_hdr->source  = fp_net_n4_local_ip;
                ip_hdr->check   = calc_crc_ip(ip_hdr);
                break;

            case EN_COMM_DST_IF_5GVN:
                break;

            default:
                LOG(FASTPASS, ERR, "Abnormal source interface: %d", forw_if);
                break;
        }

#ifdef CONFIG_FP_DPDK_PORT
        if (likely(dpdk_get_tx_offload() & DEV_TX_OFFLOAD_IPV4_CKSUM)) {
            m_local->l2_len = ETH_HLEN;
            m_local->ol_flags |= (PKT_TX_IPV4|PKT_TX_IP_CKSUM);
        }
        else
#endif
        {
            ip_hdr->check   = calc_crc_ip(ip_hdr);
        }

#ifdef CONFIG_FP_DPDK_PORT
        m_local->packet_type |= RTE_PTYPE_L3_IPV4; /* For IP fragment */
#endif

        /* change packet start position and length */
        payload   = (char *)ip_hdr - 2;
        *(uint16_t *)payload = FLOW_ETH_PRO_IP;
        *pkt_len = content_len + 2;
    }
    if (outh->type.d.ipv6) {
        struct pro_ipv6_hdr *ip_hdr = (struct pro_ipv6_hdr *)(payload - sizeof(struct pro_ipv6_hdr));

        /* set ip header */
        ip_hdr->vtc_flow.d.version  = 6;
        ip_hdr->vtc_flow.d.priority = 0;
        ip_hdr->vtc_flow.d.flow_lbl = 0;
        ip_hdr->vtc_flow.value      = htonl(ip_hdr->vtc_flow.value);
        ip_hdr->payload_len         = htons(content_len);
        ip_hdr->nexthdr             = IP_PRO_UDP;
        ip_hdr->hop_limit           = 64;

        switch (forw_if) {
            case EN_COMM_DST_IF_ACCESS:
                ros_memcpy(ip_hdr->saddr, fp_host_n3_local_ipv6, IPV6_ALEN);
                break;

            case EN_COMM_DST_IF_CORE:
                if (1 == inst->choose.d.flag_ueip_type) {
                    ros_memcpy(ip_hdr->saddr, inst->ueip.ipv6, IPV6_ALEN);
                } else {
                    LOG(FASTPASS, ERR, "Outer header create failed, UEIP type: %s error.",
                        inst->choose.d.flag_ueip_type ? "IPv6" : "IPv4");
                }
                break;

            case EN_COMM_DST_IF_SGILAN:
                break;

            case EN_COMM_DST_IF_CP:
                ros_memcpy(ip_hdr->saddr, fp_host_n4_local_ipv6, IPV6_ALEN);
                break;

            case EN_COMM_DST_IF_5GVN:
                break;

            default:
                LOG(FASTPASS, ERR, "Abnormal source interface: %d", forw_if);
                break;
        }

        ros_memcpy(ip_hdr->daddr, outh->ipv6.s6_addr, IPV6_ALEN);
        content_len += sizeof(struct pro_ipv6_hdr);

#ifdef CONFIG_FP_DPDK_PORT
        m_local->packet_type |= RTE_PTYPE_L3_IPV6; /* For IP fragment */
#endif

        /* change packet start position and length */
        payload = (char *)ip_hdr - 2;
        *(uint16_t *)payload = FLOW_ETH_PRO_IPV6;
        *pkt_len = content_len + 2;
    }
    if (outh->type.d.ctag) {
        union vlan_tci *vlan_hdr = (union vlan_tci *)(payload
                - sizeof(union vlan_tci));

        vlan_hdr->data = 0;
        if (outh->ctag.vlan_flag.d.vid) {
            vlan_hdr->s.vid = outh->ctag.vlan_value.s.vid;
        }
        if (outh->ctag.vlan_flag.d.dei) {
            vlan_hdr->s.dei = outh->ctag.vlan_value.s.dei;
        }
        if (outh->ctag.vlan_flag.d.pcp) {
            vlan_hdr->s.pri = outh->ctag.vlan_value.s.pri;
        }
        vlan_hdr->data = htons(vlan_hdr->data);
        payload = (char *)vlan_hdr - 2;
        *(uint16_t *)payload = FLOW_ETH_PRO_8021Q;
        *pkt_len += VLAN_HLEN;
    }
    if (outh->type.d.stag) {
        union vlan_tci *vlan_hdr = (union vlan_tci *)(payload
                - sizeof(union vlan_tci));

        vlan_hdr->data = 0;
        if (outh->ctag.vlan_flag.d.vid) {
            vlan_hdr->s.vid = outh->ctag.vlan_value.s.vid;
        }
        if (outh->ctag.vlan_flag.d.dei) {
            vlan_hdr->s.dei = outh->ctag.vlan_value.s.dei;
        }
        if (outh->ctag.vlan_flag.d.pcp) {
            vlan_hdr->s.pri = outh->ctag.vlan_value.s.pri;
        }
        vlan_hdr->data = htons(vlan_hdr->data);
        payload = (char *)vlan_hdr - 2;
        *(uint16_t *)payload = FLOW_ETH_PRO_8021Q;
        *pkt_len += VLAN_HLEN;
    }

    return payload;
}

int32_t fp_pkt_ipv4_reply_dns(fp_packet_info *pkt_info, struct pro_udp_hdr *udp_header)
{
    int32_t             newlen, oldlen;
    pkt_buf_struct      *m = (pkt_buf_struct *)pkt_info->arg;
    char                *buf = pkt_info->buf;

    oldlen = ntohs(udp_header->len) - sizeof(struct pro_udp_hdr);
    newlen = fp_dns_handle_query((uint8_t *)(udp_header + 1), oldlen);
    if (newlen != ERROR) {
        uint8_t  tmp_mac[ETH_ALEN];
        uint16_t tmp_port;
        struct pro_udp_hdr *udp_l1;
        struct pro_gtp_hdr *gtp_hdr;

        /* match local dns cache */
        LOG(FASTPASS, RUNNING, "Udp dns packet, match local dns cache");

        LOG(FASTPASS, RUNNING, "Udp dns packet, newlen: %d, oldlen: %d", newlen, oldlen);
        LOG(FASTPASS, RUNNING, "dst:%02x %02x %02x %02x %02x %02x",
            *(uint8_t *)(buf + 0),
            *(uint8_t *)(buf + 1),
            *(uint8_t *)(buf + 2),
            *(uint8_t *)(buf + 3),
            *(uint8_t *)(buf + 4),
            *(uint8_t *)(buf + 5)
            );

        LOG(FASTPASS, RUNNING, "src:%02x %02x %02x %02x %02x %02x",
            *(uint8_t *)(buf + 0 + ETH_ALEN),
            *(uint8_t *)(buf + 1 + ETH_ALEN),
            *(uint8_t *)(buf + 2 + ETH_ALEN),
            *(uint8_t *)(buf + 3 + ETH_ALEN),
            *(uint8_t *)(buf + 4 + ETH_ALEN),
            *(uint8_t *)(buf + 5 + ETH_ALEN)
            );

        /* switch l1 mac */
        ros_memcpy(tmp_mac, buf, ETH_ALEN);
        ros_memcpy(buf, buf + ETH_ALEN, ETH_ALEN);
        ros_memcpy(buf + ETH_ALEN, tmp_mac, ETH_ALEN);

        LOG(FASTPASS, RUNNING, "new dst:%02x %02x %02x %02x %02x %02x",
            *(uint8_t *)(buf + 0),
            *(uint8_t *)(buf + 1),
            *(uint8_t *)(buf + 2),
            *(uint8_t *)(buf + 3),
            *(uint8_t *)(buf + 4),
            *(uint8_t *)(buf + 5)
            );

        LOG(FASTPASS, RUNNING, "new src:%02x %02x %02x %02x %02x %02x",
            *(uint8_t *)(buf + 0 + ETH_ALEN),
            *(uint8_t *)(buf + 1 + ETH_ALEN),
            *(uint8_t *)(buf + 2 + ETH_ALEN),
            *(uint8_t *)(buf + 3 + ETH_ALEN),
            *(uint8_t *)(buf + 4 + ETH_ALEN),
            *(uint8_t *)(buf + 5 + ETH_ALEN)
            );

        /* switch l1 ip */
        switch (FlowGetL1IpVersion(&pkt_info->match_key)) {
            case 4:
                {
                    struct pro_ipv4_hdr *l1_hdr = FlowGetL1Ipv4Header(&pkt_info->match_key);
                    uint32_t tmp_ip = l1_hdr->dest;

                    l1_hdr->dest = l1_hdr->source;
                    l1_hdr->source = tmp_ip;
                    l1_hdr->tot_len = htons(ntohs(l1_hdr->tot_len) + (newlen - oldlen));
                    l1_hdr->check = 0;
                    l1_hdr->ttl = 125;
                    l1_hdr->check = calc_crc_ip(l1_hdr);
                }
                break;

            case 6:
                {
                    struct pro_ipv6_hdr *l1_hdr = FlowGetL1Ipv6Header(&pkt_info->match_key);
                    uint8_t tmp_ip[IPV6_ALEN];

                    ros_memcpy(tmp_ip, l1_hdr->daddr, IPV6_ALEN);
                    ros_memcpy(l1_hdr->daddr, l1_hdr->saddr, IPV6_ALEN);
                    ros_memcpy(l1_hdr->saddr, tmp_ip, IPV6_ALEN);
                    l1_hdr->payload_len = htons(ntohs(l1_hdr->payload_len) + (newlen - oldlen));
                    l1_hdr->hop_limit   = 64;
                }
                break;

            default:
                LOG(FASTPASS, ERR, "ERROR: Unknown IP type:%d, What should not happen.\r\n",
                    FlowGetL1IpVersion(&pkt_info->match_key));
                break;
        }

        /* switch l1 port */
        udp_l1 = FlowGetL1UdpHeader(&pkt_info->match_key);
        tmp_port = udp_l1->dest;
        udp_l1->dest = udp_l1->source;
        udp_l1->source = tmp_port;
        udp_l1->len = htons(ntohs(udp_l1->len) + (newlen - oldlen));
        udp_l1->check = 0;

        /* update GTP length */
        gtp_hdr = (struct pro_gtp_hdr *)(udp_l1 + 1);
        gtp_hdr->length = htons(ntohs(gtp_hdr->length) + (newlen - oldlen));

        /* switch l2 ip */
        switch (FlowGetL2IpVersion(&pkt_info->match_key)) {
            case 4:
                {
                    struct pro_ipv4_hdr *l2_hdr = FlowGetL2Ipv4Header(&pkt_info->match_key);
                    uint32_t tmp_ip = l2_hdr->dest;

                    l2_hdr->dest = l2_hdr->source;
                    l2_hdr->source = tmp_ip;
                    l2_hdr->tot_len = htons(ntohs(l2_hdr->tot_len) + (newlen - oldlen));
                    l2_hdr->check = 0;
                    l2_hdr->ttl = 125;
                    l2_hdr->check = calc_crc_ip(l2_hdr);
                }
                break;

            case 6:
                {
                    struct pro_ipv6_hdr *l2_hdr = FlowGetL2Ipv6Header(&pkt_info->match_key);
                    uint8_t tmp_ip[IPV6_ALEN];

                    ros_memcpy(tmp_ip, l2_hdr->daddr, IPV6_ALEN);
                    ros_memcpy(l2_hdr->daddr, l2_hdr->saddr, IPV6_ALEN);
                    ros_memcpy(l2_hdr->saddr, tmp_ip, IPV6_ALEN);
                    l2_hdr->payload_len = htons(ntohs(l2_hdr->payload_len) + (newlen - oldlen));
                    l2_hdr->hop_limit   = 64;
                }
                break;

            default:
                LOG(FASTPASS, ERR, "ERROR: Unknown IP type:%d, What should not happen.\r\n",
                    FlowGetL2IpVersion(&pkt_info->match_key));
                break;
        }

        /* switch l2 port */
        tmp_port = udp_header->dest;
        udp_header->dest = udp_header->source;
        udp_header->source = tmp_port;
        udp_header->len = htons(ntohs(udp_header->len) + (newlen - oldlen));
        udp_header->check = 0;

        /* set length to mblk */
        pkt_buf_set_len(m, pkt_buf_data_len(m) + (newlen - oldlen));

        return OK;
    }
    else {
        return ERROR;
    }
}

#ifdef ETHERNET_SIMPLE_PROC
void fp_pkt_match_n3_eth_and_nonip(fp_packet_info *pkt_info, fp_fast_table *head,
    fp_fast_entry *entry, fp_cblk_entry *cblk, int trace_flag)
{
    void                    *mbuf = pkt_info->arg;
    char                    *pkt = pkt_info->buf;
    int                     len = pkt_info->len;
    int                     count_len = len - pkt_info->match_key.field_offset[FLOW_FIELD_GTP_CONTENT];
    comm_msg_fast_cfg       *entry_cfg;
    fp_inst_entry           *inst_entry = NULL;
    comm_msg_inst_config    *inst_config;
    pkt_buf_struct          *m = (pkt_buf_struct *)mbuf;
    fp_far_entry            *far_entry;

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
        switch (inst_config->choose.d.flag_bearer_net) {
            case 1:
                /* Ethernet */
                if (-1 == fp_pkt_n3_eth_forw(pkt_info, entry_cfg,
                    inst_entry, far_entry, count_len, trace_flag)) {
                    ros_rwlock_read_unlock(&inst_entry->rwlock);

                    goto drop;
                }
                break;

            case 2:
                /* Unstructured */
                if (-1 == fp_pkt_n3_nonip_forw(pkt_info, entry,
                    inst_entry, far_entry, count_len, trace_flag)) {
                    ros_rwlock_read_unlock(&inst_entry->rwlock);

                    goto drop;
                }
                break;

            default:
                /* IP */

                ros_rwlock_read_unlock(&inst_entry->rwlock);

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
                return;
        }
    }

    /* If buff and nocp, buffer it */
    /* only download flow support BUFF and NOCP, refer to 3gpp 25244-5.2.3.1 */

    /* Transmit branch */
    ros_rwlock_read_unlock(&inst_entry->rwlock);

    /* Send buffer */
    fp_pkt_send2phy(m, cblk, EN_COMM_DST_IF_CORE, pkt_info->port_id);

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

void fp_pkt_inner_eth_nonip_proc(fp_packet_info *pkt_info)
{
    uint32_t hash_key, aux_info;
    fp_fast_entry  *entry;
    int trace_flag = G_FALSE;
    fp_fast_table *head = fp_fast_table_get(COMM_MSG_FAST_MAC);
    struct pro_gtp_hdr *gtp_hdr = FlowGetGtpuHeader(&pkt_info->match_key);

    switch (FlowGetL1IpVersion(&pkt_info->match_key)) {
        case 4:
            {
                struct pro_ipv4_hdr *ipheader = FlowGetL1Ipv4Header(&pkt_info->match_key);

                /* Calc hash key */
                hash_key = fp_calc_hash_nonip(PktGetIpv4Long(ipheader),
                    gtp_hdr->teid, 0, &aux_info);
                aux_info = (ipheader->source ^ gtp_hdr->teid);

                LOG_TRACE(FASTPASS, RUNNING, trace_flag,
                    "N3 fast table match(d:0x%08x, s:0x%08x, teid:0x%x, pro:%d),  key %x len %d!",
                    ntohl(ipheader->dest), ntohl(ipheader->source), ntohl(gtp_hdr->teid),
                    ipheader->protocol, hash_key, pkt_info->len);
            }
            break;

        case 6:
            {
                struct pro_ipv6_hdr *ipheader = FlowGetL1Ipv6Header(&pkt_info->match_key);
                uint64_t ip6_tmp = PktGetIpv6Long(ipheader);

                /* Calc hash key */
                hash_key = fp_calc_hash_nonip(ip6_tmp, gtp_hdr->teid, 0, &aux_info);
                aux_info = ((uint32_t)(ip6_tmp & 0xFFFFFFFF) ^ (uint32_t)(ip6_tmp >> 32) ^ gtp_hdr->teid);

                LOG_TRACE(FASTPASS, RUNNING, trace_flag,
                    "N3 fast table match(d:0x%08x %08x %08x %08x, s:0x%08x %08x %08x %08x,"
                    " teid:0x%x, pro:%d),  key %x len %d!",
                    *(uint32_t *)&ipheader->daddr[0], *(uint32_t *)&ipheader->daddr[4],
                    *(uint32_t *)&ipheader->daddr[8], *(uint32_t *)&ipheader->daddr[12],
                    *(uint32_t *)&ipheader->saddr[0], *(uint32_t *)&ipheader->saddr[4],
                    *(uint32_t *)&ipheader->saddr[8], *(uint32_t *)&ipheader->saddr[12],
                    ntohl(gtp_hdr->teid), ipheader->nexthdr, hash_key, pkt_info->len);
            }
            break;

        default:
            LOG_TRACE(FASTPASS, ERR, trace_flag, "Get L1 packet version error.\r\n");
            fp_free_pkt(pkt_info->arg);
            fp_packet_stat_count(COMM_MSG_FP_STAT_UP_DROP);
            return;
    }

    /* Match fast table */
    entry = fp_table_match_fast_entry(head, hash_key, aux_info);

    /* Entry exist, handle packet by entry content */
    if (likely(entry)) {
        /* Match success, forwarding */
        LOG_TRACE(FASTPASS, RUNNING, trace_flag, "N3 fast table match success");

        /* send out by action */
        fp_pkt_match_n3_eth_and_nonip(pkt_info, head, entry, NULL, trace_flag);

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
#endif

void fp_pkt_redirect_N3_http(fp_packet_info *pkt_info, struct pro_tcp_hdr *tcp_hdr,
    char *url, uint8_t ip_ver)
{
    char http_url[512];
    uint16_t tmp_port;
    int diff_len, payload_len;
    char *payload;

    if (NULL == tcp_hdr || NULL == url) {
        LOG(FASTPASS, ERR, "Parameters abnormal, tcp_hdr(%p), url(%p)", tcp_hdr, url);
        return;
    }

    if (-1 == layer7_url_extract(tcp_hdr, pkt_info->len, http_url, NULL, sizeof(http_url))) {
        LOG(FASTPASS, DEBUG, "Maybe not HTTP request packet");
        return;
    }

    if (0 == strncmp(url, http_url, strlen(url))) {
        LOG(FASTPASS, DEBUG, "The URL of the HTTP request and the redirection URL match");
        return;
    }

    /* Send HTTP response, status code 302 */
    tmp_port = tcp_hdr->dest;
    tcp_hdr->dest = tcp_hdr->source;
    tcp_hdr->source = tmp_port;
    tcp_hdr->check = 0;

    payload = (char *)tcp_hdr + (tcp_hdr->doff << 2);

    payload_len = sprintf(payload, "HTTP/1.1 302 Found\r\nLocation: %s\r\nContent-Length: 0\r\n\r\n", url);

    diff_len = pkt_info->len - (payload - pkt_info->buf) - payload_len;
    pkt_buf_set_len(pkt_info->arg, pkt_buf_data_len(pkt_info->arg) - diff_len);
    pkt_info->len = pkt_buf_data_len(pkt_info->arg);

    switch (ip_ver) {
        case SESSION_IP_V4:
            {
                struct pro_ipv4_hdr *l2_hdr = FlowGetL2Ipv4Header(&pkt_info->match_key);
                uint32_t tmp_addr;

                tmp_addr        = l2_hdr->dest;
                l2_hdr->dest    = l2_hdr->source;
                l2_hdr->source  = tmp_addr;
                l2_hdr->tot_len = htons(ntohs(l2_hdr->tot_len) - diff_len);
                l2_hdr->check   = 0;

                /* Calc checksum */
                l2_hdr->check   = calc_crc_ip(l2_hdr);
                tcp_hdr->check  = calc_crc_tcp(tcp_hdr, l2_hdr);
            }
            break;

        case SESSION_IP_V6:
            {
                struct pro_ipv6_hdr *l2_hdr = FlowGetL2Ipv6Header(&pkt_info->match_key);
                uint8_t tmp_addr6[IPV6_ALEN];

                ros_memcpy(tmp_addr6, l2_hdr->daddr, IPV6_ALEN);
                ros_memcpy(l2_hdr->daddr, l2_hdr->saddr, IPV6_ALEN);
                ros_memcpy(l2_hdr->saddr, tmp_addr6, IPV6_ALEN);
                l2_hdr->payload_len = htons(ntohs(l2_hdr->payload_len) - diff_len);

                /* Calc checksum */
                tcp_hdr->check  = calc_crc_tcp6(tcp_hdr, l2_hdr);
            }
            break;
    }
}


