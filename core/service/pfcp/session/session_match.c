/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "session_msg.h"
#include "pdr_mgmt.h"

#include "session_orphan.h"
#include "session_teid.h"
#include "session_report.h"
#include "mar_mgmt.h"
#include "session_mgmt.h"
#include "sp_backend_mgmt.h"
#include "session_match.h"
#include "far_mgmt.h"


inline uint32_t session_msg_set_type(uint8_t type)
{
    return ((type & 0x3) << 2);
}

inline uint32_t session_msg_set_port(uint8_t port)
{
    return (port & 0x3);
}

void session_match(struct filter_key *key, uint32_t fast_tid, uint8_t fast_type, int fd)
{
    struct session_t       *session = NULL;
    struct pdr_table       *pdr_tbl = NULL;
    comm_msg_header_t      *msg;
    comm_msg_ie_t          *ie = NULL;
    comm_msg_fast_ie_t     *fast_ie = NULL;
    uint8_t                 no_match_pdr_or_sess = 0;
    struct pdr_key          p_key = {.teid = 0};
    uint8_t                 pkt_type = 0;
    uint32_t                far_index = 0;
    comm_msg_fast_cfg       *fast_cfg;
    uint8_t                 buf[SERVICE_BUF_TOTAL_LEN];
    uint32_t                buf_len;
    struct far_table        *far_tbl;
    uint8_t                 fwd_port;

    msg = upc_fill_msg_header(buf);
    ie = COMM_MSG_GET_IE(msg);
    ie->cmd    = htons(EN_COMM_MSG_UPU_ENTR_MOD);
    fast_ie    = (comm_msg_fast_ie_t *)ie;
    fast_ie->index = fast_tid;
    fast_ie->table = session_msg_set_type(fast_type);

    if (likely(NULL != key)) {
        LOG(SESSION, DEBUG, "fast_ie->index: %d.", fast_ie->index);
        /* pdr lookup */
        pdr_tbl = pdr_map_lookup(key);
        if (NULL == pdr_tbl) {
            LOG(SESSION, RUNNING, "pdr lookup failed.");
            no_match_pdr_or_sess = 1;

            /* 如果是上行报文匹配不成功需要发送Error Indication */
            if (FLOW_MASK_FIELD_ISSET(key->field_offset, FLOW_FIELD_GTP_T_PDU)) {
                session_gtpu_send_error_indication(key);
            }
        } else {
            session = pdr_tbl->session_link;
            if (unlikely(NULL == session)) {
                no_match_pdr_or_sess = 1;
                ie->cmd    = htons(EN_COMM_MSG_UPU_ENTR_DEL);
                LOG(SESSION, ERR, "match session failed, session(%p).",
                    session);
                goto fast_handle;
            }

            if (0 > pdr_fraud_identify(key, pdr_tbl)) {
                LOG(SESSION, ERR, "HTTP header fraud identification fail, Reject connection.");
                ie->cmd    = htons(EN_COMM_MSG_UPU_ENTR_DEL);
                goto fast_handle;
            }
        }

        /* fill fast table */
        fast_cfg = (comm_msg_fast_cfg *)ie->data;
        if (0 == no_match_pdr_or_sess) {
            fast_cfg->inst_index = htonl(pdr_tbl->index);
            fast_cfg->pdr_si     = pdr_tbl->pdr.pdi_content.si;
			fast_cfg->head_enrich_flag = htonl(pdr_tbl->pdr.pdi_content.head_enrich_flag);
            if (pdr_tbl->pdr.far_present) {
                far_index = pdr_tbl->pdr_pri.far_index;
                fast_cfg->far_index = htonl(far_index);
            }
            else if (pdr_tbl->pdr.mar_present) {
                far_index = mar_get_far_index(session, pdr_tbl->pdr_pri.mar_index);
                if (0 == far_index) {
                    LOG(SESSION, ERR,
                        "search far index failed from mar.");

                    fast_cfg->far_index = htonl(COMM_MSG_ORPHAN_NUMBER);
                    no_match_pdr_or_sess = 1;
                }
                else {
                    fast_cfg->far_index = htonl(far_index);
                }
            }
        }
        else {
            /* not macth pdr */
            fast_cfg->inst_index   = htonl(COMM_MSG_ORPHAN_NUMBER);
            fast_cfg->far_index    = htonl(COMM_MSG_ORPHAN_NUMBER);
        }
        fast_cfg->temp_flag = 0;

        if (FLOW_MASK_FIELD_ISSET(key->field_offset, FLOW_FIELD_L1_IPV4)) {
            struct pro_ipv4_hdr *ip_hdr;

            ip_hdr = FlowGetL1Ipv4Header(key);
            if (!ip_hdr) {
                LOG(SESSION, ERR, "get ipv4 header failed.");
                return;
            }

            p_key.ip_addr.ipv4 = ntohl(ip_hdr->dest);
            pkt_type = EN_PKT_TYPE_IPV4;
        }
        else if (FLOW_MASK_FIELD_ISSET(key->field_offset, FLOW_FIELD_L1_IPV6)) {
            struct pro_ipv6_hdr *ip_hdr;

            ip_hdr = FlowGetL1Ipv6Header(key);
            if (!ip_hdr) {
                LOG(SESSION, ERR, "get ipv4 header failed.");
                return;
            }

            ros_memcpy(&p_key.ip_addr.ipv6, ip_hdr->daddr, IPV6_ALEN);
            pkt_type = EN_PKT_TYPE_IPV6;
        }
        else {
            /* default ipv4 */
            no_match_pdr_or_sess = 1;
            pkt_type = EN_PKT_TYPE_IPV4;
        }

        if (FLOW_MASK_FIELD_ISSET(key->field_offset, FLOW_FIELD_GTP_T_PDU)) {
            struct pro_gtp_hdr *gtp_hdr = FlowGetGtpuHeader(key);
            if (likely(gtp_hdr)) {
                p_key.teid = ntohl(gtp_hdr->teid);
            } else {
                LOG(SESSION, ERR, "gtpu packet, but gtp_hdr is NULL.");
            }
        }
    }
    else {
        /* default ipv4 */
        comm_msg_fast_cfg *fast_cfg_ipv4 = (comm_msg_fast_cfg *)ie->data;

        ie->cmd    = htons(EN_COMM_MSG_UPU_ENTR_DEL);

        fast_cfg_ipv4->inst_index   = htonl(COMM_MSG_ORPHAN_NUMBER);
        fast_cfg_ipv4->far_index    = htonl(COMM_MSG_ORPHAN_NUMBER);
        fast_cfg_ipv4->temp_flag    = 0;
        no_match_pdr_or_sess = 1;
        pkt_type = EN_PKT_TYPE_IPV4;
    }

    if (no_match_pdr_or_sess) {

        LOG(SESSION, RUNNING, "insert fast entry to orphan.");
        if (FLOW_MASK_FIELD_ISSET(key->field_offset, FLOW_FIELD_ETHERNET_DL)) {
            struct pro_eth_hdr *eth_hdr = FlowGetL1MACHeader(key);

            if (0 > session_orphan_insert(fast_tid, 0, pkt_type, eth_hdr->dest)) {
                LOG(SESSION, ERR, "insert fast entry to orphan failed.");
            }
        } else {
            if (0 > session_orphan_insert(fast_tid,
                (FLOW_MASK_FIELD_ISSET(key->field_offset, FLOW_FIELD_GTP_T_PDU)), pkt_type, &p_key)) {
                LOG(SESSION, ERR, "insert fast entry to orphan failed.");
            }
        }

        goto fast_handle;
    }

    /* If the notification of the PDR has not been reported yet */
    if ((EN_COMM_SRC_IF_ACCESS != pdr_tbl->pdr.pdi_content.si) &&
        ros_atomic16_read(&pdr_tbl->nocp_flag)) {
        if (-1 == session_start_nocp_timer(session, pdr_tbl, far_index)) {
            LOG(SESSION, ERR, "session_report_nocp error.");

            fast_cfg->inst_index   = htonl(COMM_MSG_ORPHAN_NUMBER);

            goto fast_handle;
        }
    }

    /* Filling next hop mac address */
    /* Get mac address with create outer header first */
    far_tbl = far_public_get_table(far_index);
    if (likely(far_tbl)) {
        fwd_port = far_tbl->far_cfg.forw_if;

        if (far_tbl->far_cfg.forw_if == EN_COMM_DST_IF_CORE &&
            session->session.pdn_type == PDN_TYPE_ETHERNET) {
            LOG(SESSION, RUNNING, "Ethernet 802.3 packet, Do not replace MAC address.");
            goto fast_handle;
        }

    } else {
        LOG(SESSION, ERR, "Get far failed.");
        ie->cmd = htons(EN_COMM_MSG_UPU_ENTR_DEL);

        goto fast_handle;
    }

    /* 直接将报文发送到负载均衡器 */
    upc_mb_copy_port_mac(fwd_port, fast_cfg->dst_mac);
    LOG(SESSION, RUNNING, "Filling load-balancer MAC: %02x:%02x:%02x:%02x:%02x:%02x",
        fast_cfg->dst_mac[0], fast_cfg->dst_mac[1], fast_cfg->dst_mac[2],
        fast_cfg->dst_mac[3], fast_cfg->dst_mac[4], fast_cfg->dst_mac[5]);

fast_handle:
    buf_len = COMM_MSG_IE_LEN_COMMON + COMM_MSG_IE_LEN_FAST;
    ie->len = htons(buf_len);
    ie->index  = htonl(ie->index);
    buf_len += COMM_MSG_HEADER_LEN;
    msg->total_len = htonl(buf_len);

    if (0 > session_msg_send_to_fp((char *)buf, buf_len, fd)) {
        LOG(SESSION, ERR, "session send buffer to fpu failed.");
    }
    session_pkt_status_add(SESSION_PKT_MDF_FAST);
}

int session_remove_orphan_fast(struct sp_fast_entry *fast_entry, uint8_t pkt_type)
{
    comm_msg_header_t      *msg;
    comm_msg_ie_t          *ie = NULL;
    comm_msg_fast_ie_t     *fast_ie = NULL;
    uint8_t                 buf[SERVICE_BUF_TOTAL_LEN];
    uint32_t                buf_len;
    comm_msg_fast_cfg       *fast_cfg = NULL;

    if (unlikely(NULL == fast_entry)) {
        LOG(SESSION, ERR, "Abnormal parameter, fast_entry(%p).", fast_entry);
        return -1;
    }

    msg         = upc_fill_msg_header(buf);
    ie          = COMM_MSG_GET_IE(msg);
    ie->cmd     = htons(EN_COMM_MSG_UPU_ENTR_DEL);
    fast_ie     = (comm_msg_fast_ie_t *)ie;
    fast_cfg                = (comm_msg_fast_cfg *)ie->data;
    fast_cfg->pdr_si        = fast_entry->pdr_si;
    fast_cfg->temp_flag     = 1;
    fast_ie->index          = fast_entry->fast_id;

    LOG(SESSION, RUNNING, "Remove orphan fast id: %u, packet type: %d.",
        fast_entry->fast_id, pkt_type);

    /* fill ipv4 fast table */
    switch (pkt_type) {
        case EN_PKT_TYPE_IPV4:
            fast_ie->table = session_msg_set_type(COMM_MSG_FAST_IPV4);
            break;

        case EN_PKT_TYPE_IPV6:
            fast_ie->table = session_msg_set_type(COMM_MSG_FAST_IPV6);
            break;

        case EN_PKT_TYPE_ETH:
            fast_ie->table = session_msg_set_type(COMM_MSG_FAST_MAC);
            break;

        default:
            LOG(SESSION, ERR, "packet type is other.");
            return -1;
    }

    buf_len = COMM_MSG_IE_LEN_COMMON + COMM_MSG_IE_LEN_FAST;
    ie->len = htons(buf_len);
    ie->index  = htonl(ie->index);
    buf_len += COMM_MSG_HEADER_LEN;
    msg->total_len = htonl(buf_len);

    if (0 > session_msg_send_to_fp((char *)buf, buf_len, MB_SEND2BE_BROADCAST_FD)) {
        LOG(SESSION, RUNNING, "Send fast table failed.");
        return -1;
    }

    return 0;
}

