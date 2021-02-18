/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "session_mgmt.h"
#include "pdr_mgmt.h"
#include "session_teid.h"
#include "session_msg.h"
#include "session_report.h"
#include "sp_backend_mgmt.h"

struct session_gtpu_table g_session_gtpu_table;
struct session_peer_fteid_table g_session_peer_fteid_table;
static ros_atomic16_t g_echo_seq_num = {-1};

static int64_t session_peer_fteid_init(uint32_t session_num);
static int session_gtpu_recv_error_indication(struct filter_key *key);

static inline struct session_gtpu_table *session_gtpu_table_get(void)
{
    return &g_session_gtpu_table;
}

static inline struct session_gtpu_entry *session_gtpu_entry_get(uint32_t gtpu_index)
{
    return &g_session_gtpu_table.gtpu_entry[gtpu_index];
}

static inline int session_gtpu_compare(struct rb_node *node, void *key)
{
    struct session_gtpu_entry *node_entry = (struct session_gtpu_entry *)node;

    return memcmp(node_entry->ip_addr.ipv6, key, sizeof(session_gtpu_key));
}

static int session_gtpu_table_match(struct filter_key *key)
{
    struct session_gtpu_table *gtpu_head = session_gtpu_table_get();
    struct session_gtpu_entry  *gtpu_entry = NULL;
    struct pro_gtp_hdr *gtpu_hdr = NULL;
    session_gtpu_key tmp_key = {.ipv6 = {0}};

    gtpu_hdr = FlowGetGtpuHeader(key);
    if (NULL == gtpu_hdr){
        LOG(SESSION, ERR, "gtpu_hdr is NULL.");
        return -1;
    }

    if (FLOW_MASK_FIELD_ISSET(key->field_offset, FLOW_FIELD_L1_IPV4)) {
        struct pro_ipv4_hdr *ipv4_hdr = FlowGetL1Ipv4Header(key);

        tmp_key.ipv4 = ntohl(ipv4_hdr->source);
        LOG(SESSION, ERR, "search ipv4: 0x%08x.", tmp_key.ipv4);
    } else if(FLOW_MASK_FIELD_ISSET(key->field_offset, FLOW_FIELD_L1_IPV6)) {
        struct pro_ipv6_hdr *ipv6_hdr = FlowGetL1Ipv6Header(key);

        memcpy(tmp_key.ipv6, ipv6_hdr->saddr, IPV6_ALEN);

        LOG(SESSION, ERR, "search peer_ipv6: 0x%016lx %016lx.",
            *(uint64_t *)tmp_key.ipv6, *(uint64_t *)(tmp_key.ipv6 + 8));
    }

    ros_rwlock_read_lock(&gtpu_head->lock);
    gtpu_entry = (struct session_gtpu_entry *)rbtree_search(&gtpu_head->gtpu_root,
            (void *)&tmp_key, session_gtpu_compare);
    ros_rwlock_read_unlock(&gtpu_head->lock);
    if (NULL == gtpu_entry) {
        LOG(SESSION, ERR, "teid entry is NULL.");
        return -1;
    } else {
        ros_rwlock_write_lock(&gtpu_entry->lock);
        gtpu_entry->timeout_num = 0;
        ros_rwlock_write_unlock(&gtpu_entry->lock);
    }

    return 0;
}

static void session_gtpu_send_echo_req(struct session_gtpu_entry *gtpu_entry)
{
    uint8_t buf[256];
    uint16_t buf_len = 0;
    upc_config_info *upc_cfg = upc_get_config();
    struct pro_eth_hdr *eth_hdr = NULL;
    struct pro_ipv4_hdr *ipv4_hdr = NULL;
    struct pro_ipv6_hdr *ipv6_hdr = NULL;
    struct pro_udp_hdr *udp_hdr = NULL;
    struct pro_gtp_hdr *gtpu_hdr = NULL;
    uint16_t *seq_num = NULL;
    uint8_t *recovery;

    /* Filling ETH header */
    eth_hdr = (struct pro_eth_hdr *)buf;
    buf_len = sizeof(struct pro_eth_hdr);

    upc_mb_copy_port_mac(gtpu_entry->port, eth_hdr->dest);
    ros_memcpy(eth_hdr->source, upc_cfg->n4_local_mac, ETH_ALEN);

    /* Filling IP header */
    switch (gtpu_entry->ip_flag) {
        case SESSION_IP_V4:
            eth_hdr->eth_type = htons(ETH_PRO_IP);

            ipv4_hdr = (struct pro_ipv4_hdr *)(buf + buf_len);
            buf_len += sizeof(struct pro_ipv4_hdr);

            ipv4_hdr->version       = 4;
            ipv4_hdr->ihl           = 5;
            ipv4_hdr->tos           = 0;
            ipv4_hdr->protocol      = IP_PRO_UDP;
            ipv4_hdr->tot_len       = 0;
            ipv4_hdr->id            = (uint16_t)ros_get_tsc_hz();
            ipv4_hdr->frag_off      = 0x0040;
            ipv4_hdr->ttl           = 64;
            ipv4_hdr->dest          = htonl(gtpu_entry->ip_addr.ipv4);
            ipv4_hdr->source        = htonl(upc_cfg->upf_ip_cfg[gtpu_entry->port].ipv4);
            ipv4_hdr->check         = 0;
            break;

        case SESSION_IP_V6:
            eth_hdr->eth_type = htons(ETH_PRO_IPV6);

            ipv6_hdr = (struct pro_ipv6_hdr *)(buf + buf_len);
            buf_len += sizeof(struct pro_ipv6_hdr);

            ipv6_hdr->vtc_flow.d.version    = 6;
            ipv6_hdr->vtc_flow.d.priority   = 0;
            ipv6_hdr->vtc_flow.d.flow_lbl   = 0;
            ipv6_hdr->vtc_flow.value        = htonl(ipv6_hdr->vtc_flow.value);
            ipv6_hdr->payload_len           = 0;
            ipv6_hdr->nexthdr               = IP_PRO_UDP;
            ipv6_hdr->hop_limit             = 64;
            memcpy(ipv6_hdr->saddr, upc_cfg->upf_ip_cfg[gtpu_entry->port].ipv6, IPV6_ALEN);
            memcpy(ipv6_hdr->daddr, gtpu_entry->ip_addr.ipv6, IPV6_ALEN);
            break;

        default:
            LOG(SESSION, ERR, "Should not be to here, maybe coding error.");
            return;
    }

    /* Filling udp header */
    udp_hdr = (struct pro_udp_hdr *)(buf + buf_len);
    buf_len += sizeof(struct pro_udp_hdr);
    udp_hdr->dest   = FLOW_UDP_PORT_GTPU;
    udp_hdr->source = FLOW_UDP_PORT_GTPU;
    udp_hdr->len    = 0;
    udp_hdr->check  = 0;

    /* Filling gtpu header */
    gtpu_hdr = (struct pro_gtp_hdr *)(buf + buf_len);
    buf_len +=  sizeof(struct pro_gtp_hdr);

    gtpu_hdr->flags.data        = 0;
    gtpu_hdr->flags.s.version   = 1;
    gtpu_hdr->flags.s.type      = 1;
    gtpu_hdr->flags.s.e         = 0;
    gtpu_hdr->flags.s.s         = 1;
    gtpu_hdr->flags.s.reserve   = 0;
    gtpu_hdr->teid              = 0;
    gtpu_hdr->msg_type          = MSG_TYPE_T_ECHO_REQ;
    gtpu_hdr->length            = 0;

    /* Filling sequnce number */
    seq_num = (uint16_t *)(buf + buf_len);
    buf_len +=  sizeof(uint16_t);
    *seq_num = htons(ros_atomic16_add_return(&g_echo_seq_num, 1));
    /* Filling N-PDU Number */
    buf[buf_len++] = 0;
    /* Filling Next Extension Header Type */
    buf[buf_len++] = EN_GTP_EH_NO_MORE;

    /* Recovery */
    recovery = (uint8_t *)(buf + buf_len);
    buf_len     += 2;
    recovery[0] = GTP_IE_RECOVERY;
    recovery[1] = 0;

    /* set checksum */
    switch (gtpu_entry->ip_flag) {
        case SESSION_IP_V4:
            gtpu_hdr->length = htons((uint16_t)(buf_len - ((uint8_t *)seq_num - buf)));

            ipv4_hdr->tot_len = htons((uint16_t)(buf_len - ((uint8_t *)ipv4_hdr - buf)));
            ipv4_hdr->check = calc_crc_ip(ipv4_hdr);
            udp_hdr->len    = htons((uint16_t)(buf_len - ((uint8_t *)udp_hdr - buf)));
            udp_hdr->check = calc_crc_udp(udp_hdr, ipv4_hdr);
            break;

        case SESSION_IP_V6:
            gtpu_hdr->length = htons((uint16_t)(buf_len - ((uint8_t *)seq_num - buf)));

            ipv6_hdr->payload_len = htons((uint16_t)(buf_len - ((uint8_t *)udp_hdr - buf)));
            udp_hdr->len    = ipv6_hdr->payload_len;
            udp_hdr->check = calc_crc_udp6(udp_hdr, ipv6_hdr);
            break;
    }

    /* send packet */
    if (0 > upc_channel_trans(buf, buf_len)) {
        LOG(SESSION, ERR, "send echo request packet failed.");
    }
}

static int session_gtpu_send_echo_resp(struct filter_key *key)
{
    uint8_t buf[512];
    uint16_t buf_len = 0;
    upc_config_info *upc_cfg = upc_get_config();
    struct pro_eth_hdr *eth_hdr = NULL;
    struct pro_ipv4_hdr *ipv4_hdr = NULL;
    struct pro_ipv6_hdr *ipv6_hdr = NULL;
    struct pro_udp_hdr *udp_hdr = NULL, *tmp_udp_hdr = NULL;
    struct pro_gtp_hdr *gtpu_hdr = NULL, *tmp_gtp_hdr = NULL;
    uint16_t *seq_num = NULL;
    uint8_t default_port = EN_PORT_N3;
    uint8_t *recovery;

    /* Filling ETH header */
    eth_hdr = (struct pro_eth_hdr *)buf;
    buf_len += sizeof(struct pro_eth_hdr);

    /* Set default port, if port only one */
    upc_mb_copy_port_mac(default_port, eth_hdr->dest);
    ros_memcpy(eth_hdr->source, upc_cfg->n4_local_mac, ETH_ALEN);

    /* Filling IP header */
    switch (FlowGetL1IpVersion(key)) {
        case 4:
            {
                struct pro_ipv4_hdr *tmp_ipv4_hdr = FlowGetL1Ipv4Header(key);

                eth_hdr->eth_type = FLOW_ETH_PRO_IP;

                ipv4_hdr = (struct pro_ipv4_hdr *)(buf + buf_len);
                buf_len += sizeof(struct pro_ipv4_hdr);

                ipv4_hdr->version       = 4;
                ipv4_hdr->ihl           = 5;
                ipv4_hdr->tos           = 0;
                ipv4_hdr->protocol      = IP_PRO_UDP;
                ipv4_hdr->tot_len       = 0; /* Finally, set it up */
                ipv4_hdr->id            = (uint16_t)ros_get_tsc_hz();
                ipv4_hdr->frag_off      = 0x0040;
                ipv4_hdr->ttl           = 64;
                ipv4_hdr->dest          = tmp_ipv4_hdr->source;
                ipv4_hdr->source        = tmp_ipv4_hdr->dest;
                ipv4_hdr->check         = 0; /* Finally, set it up */
            }
            break;

        case 6:
            {
                struct pro_ipv6_hdr *tmp_ipv6_hdr = FlowGetL1Ipv6Header(key);

                eth_hdr->eth_type = FLOW_ETH_PRO_IPV6;

                ipv6_hdr = (struct pro_ipv6_hdr *)(buf + buf_len);
                buf_len += sizeof(struct pro_ipv6_hdr);

                ipv6_hdr->vtc_flow.d.version    = 6;
                ipv6_hdr->vtc_flow.d.priority   = 0;
                ipv6_hdr->vtc_flow.d.flow_lbl   = 0;
                ipv6_hdr->vtc_flow.value        = htonl(ipv6_hdr->vtc_flow.value);
                ipv6_hdr->payload_len           = 0; /* Finally, set it up */
                ipv6_hdr->nexthdr               = IP_PRO_UDP;
                ipv6_hdr->hop_limit             = 64;
                memcpy(ipv6_hdr->saddr, tmp_ipv6_hdr->daddr, IPV6_ALEN);
                memcpy(ipv6_hdr->daddr, tmp_ipv6_hdr->saddr, IPV6_ALEN);
            }
            break;

        default:
            LOG(UPC, ERR, "Abnormal IP version.\n");
            return -1;
    }

    /* Filling udp header */
    udp_hdr = (struct pro_udp_hdr *)(buf + buf_len);
    buf_len += sizeof(struct pro_udp_hdr);
    tmp_udp_hdr = FlowGetL1UdpHeader(key);

    udp_hdr->dest   = tmp_udp_hdr->source;
    udp_hdr->source = FLOW_UDP_PORT_GTPU;
    udp_hdr->len    = 0; /* Finally, set it up */
    udp_hdr->check  = 0;

    /* Filling gtpu header */
    gtpu_hdr = (struct pro_gtp_hdr *)(buf + buf_len);
    buf_len +=  sizeof(struct pro_gtp_hdr);

    gtpu_hdr->flags.data        = 0;
    gtpu_hdr->flags.s.version   = 1;
    gtpu_hdr->flags.s.type      = 1;
    gtpu_hdr->flags.s.e         = 0;
    gtpu_hdr->flags.s.s         = 1;
    gtpu_hdr->flags.s.reserve   = 0;
    gtpu_hdr->teid              = 0;
    gtpu_hdr->msg_type          = MSG_TYPE_T_ECHO_RESP;
    gtpu_hdr->length            = 0;

    /* Filling sequnce number */
    seq_num = (uint16_t *)(buf + buf_len);
    buf_len +=  sizeof(uint16_t);
    tmp_gtp_hdr = FlowGetGtpuHeader(key);
    if (tmp_gtp_hdr->flags.s.s) {
        *seq_num = htons(ros_atomic16_add_return(&g_echo_seq_num, 1));
    } else {
        *seq_num = *(uint16_t *)(tmp_gtp_hdr + 1);
    }
    /* Filling N-PDU Number */
    buf[buf_len++] = 0;
    /* Filling Next Extension Header Type */
    buf[buf_len++] = EN_GTP_EH_NO_MORE;

    /* Recovery */
    recovery = (uint8_t *)(buf + buf_len);
    buf_len     += 2;
    recovery[0] = GTP_IE_RECOVERY;
    recovery[1] = 0;

    /* set checksum */
    if (ipv4_hdr) {
        gtpu_hdr->length = htons((uint16_t)(buf_len - ((uint8_t *)seq_num - buf)));

        ipv4_hdr->tot_len = htons((uint16_t)(buf_len - ((uint8_t *)ipv4_hdr - buf)));
        ipv4_hdr->check = calc_crc_ip(ipv4_hdr);
        udp_hdr->len    = htons((uint16_t)(buf_len - ((uint8_t *)udp_hdr - buf)));
        udp_hdr->check = calc_crc_udp(udp_hdr, ipv4_hdr);
    } else if (ipv6_hdr) {
        gtpu_hdr->length = htons((uint16_t)(buf_len - ((uint8_t *)seq_num - buf)));

        ipv6_hdr->payload_len = htons((uint16_t)(buf_len - ((uint8_t *)udp_hdr - buf)));
        udp_hdr->len    = ipv6_hdr->payload_len;
        udp_hdr->check = calc_crc_udp6(udp_hdr, ipv6_hdr);
    }

    if (0 > upc_channel_trans(buf, buf_len)) {
        LOG(SESSION, ERR, "send resp packet buff to LB failed.");
        return  -1;
    }

    return 0;
}

static void session_gtpu_send_request(struct session_gtpu_entry *gtpu_entry)
{
    ros_rwlock_write_lock(&gtpu_entry->lock); /* lock */
    if (gtpu_entry->timeout_num < SESSION_ECHO_RETRY_TIMES) {
        LOG(SESSION, RUNNING, "send echo request packet begin.");

        session_gtpu_send_echo_req(gtpu_entry);

        ++gtpu_entry->timeout_num;
    } else if (gtpu_entry->timeout_num != SESSION_ECHO_INVALID_CODE) {
        gtpu_entry->timeout_num = SESSION_ECHO_INVALID_CODE;
        /* echo timeout, send msg to fp */
        LOG(SESSION, RUNNING, "Report user path failure to UPC.");

        if (-1 == session_node_report_gtpu_err(gtpu_entry)) {
            LOG(SESSION, ERR, "Gtpu channel node report to upc failed.");
        }
    }
    ros_rwlock_write_unlock(&gtpu_entry->lock); /* unlock */
}

static void *session_gtpu_send_request_task(void *arg)
{
    uint32_t cnt = 0, per_round_proc_num = 0, cur_round;
    int32_t cur_index = -1;
    struct session_gtpu_table *gtpu_table = session_gtpu_table_get();
    struct session_gtpu_entry *gtpu_entry = NULL;
    uint64_t cut_us, next_round_us;
    uint64_t tsc_resolution_hz = ros_get_tsc_hz(), per_us_tsc = ros_get_tsc_hz()/ 1000000;


    per_round_proc_num = Res_GetAlloced(gtpu_table->pool_id);
    per_round_proc_num = per_round_proc_num < SESSION_ECHO_PERIOD_TIMES ?
        SESSION_ECHO_PERIOD_TIMES : per_round_proc_num / SESSION_ECHO_PERIOD_TIMES;
    cur_round = 0;
    while (1) {
        next_round_us = (ros_rdtsc() + (SESSION_ECHO_PERIOD_INTERVAL * tsc_resolution_hz)) / per_us_tsc;

        if (cur_round + 1 >= SESSION_ECHO_PERIOD_TIMES) {
            /* 当最后一轮处理将这一次处理的数量设置为最大, 直至获取到最后一个 */
            per_round_proc_num = gtpu_table->max_num;
        }

        ++cur_round;
        cur_index = Res_GetAvailableInBand(gtpu_table->pool_id, cur_index + 1, gtpu_table->max_num);
        for (cnt = 0; cnt < per_round_proc_num && -1 != cur_index; ++cnt) {
            gtpu_entry = session_gtpu_entry_get(cur_index);

            session_gtpu_send_request(gtpu_entry);

            cur_index = Res_GetAvailableInBand(gtpu_table->pool_id, cur_index + 1, gtpu_table->max_num);
        }

        if (-1 == cur_index || cur_round >= SESSION_ECHO_PERIOD_TIMES) {
            if (cur_round < SESSION_ECHO_PERIOD_TIMES) {
                /* 提前处理完了 */
                LOG(SESSION, RUNNING, "Finished in advance, cur_round: %u, max_round: %u.",
                    cur_round, SESSION_ECHO_PERIOD_TIMES);
                sleep((SESSION_ECHO_PERIOD_TIMES - cur_round) * SESSION_ECHO_PERIOD_INTERVAL);
            }

            cur_round = 0;
            cur_index = -1;
            per_round_proc_num = Res_GetAlloced(gtpu_table->pool_id);
            per_round_proc_num = per_round_proc_num < SESSION_ECHO_PERIOD_TIMES ?
                SESSION_ECHO_PERIOD_TIMES : per_round_proc_num / SESSION_ECHO_PERIOD_TIMES;

            continue;
        }

        cut_us = ros_rdtsc() / per_us_tsc;
        if ((next_round_us - 3000) > cut_us) {
            usleep(next_round_us - cut_us);
        }
        LOG(SESSION, PERIOD, "Round %u, cur_us: %lu %s next_round_us: %lu, diff_us: %lu.",
            cur_round, cut_us, cut_us > next_round_us ? ">" : "<", next_round_us,
            cut_us > next_round_us ? cut_us - next_round_us : next_round_us - cut_us);
    } /* Never break */

    return NULL;
}

void session_gtpu_send_error_indication(struct filter_key *key)
{
    uint8_t buf[512];
    uint16_t buf_len = 0;
    upc_config_info *upc_cfg = upc_get_config();
    struct pro_eth_hdr *eth_hdr = NULL;
    struct pro_ipv4_hdr *ipv4_hdr = NULL;
    struct pro_ipv6_hdr *ipv6_hdr = NULL;
    struct pro_udp_hdr *udp_hdr = NULL, *tmp_udp_hdr = NULL;
    struct pro_gtp_hdr *gtpu_hdr = NULL, *tmp_gtp_hdr = NULL;
    uint16_t *seq_num = NULL;
    uint8_t default_port = EN_PORT_N3;

    /* Filling ETH header */
    eth_hdr = (struct pro_eth_hdr *)buf;
    buf_len += sizeof(struct pro_eth_hdr);

    /* Set default port, if port only one */
    upc_mb_copy_port_mac(default_port, eth_hdr->dest);
    ros_memcpy(eth_hdr->source, upc_cfg->n4_local_mac, ETH_ALEN);

    /* Filling IP header */
    switch (FlowGetL1IpVersion(key)) {
        case 4:
            {
                struct pro_ipv4_hdr *tmp_ipv4_hdr = FlowGetL1Ipv4Header(key);

                eth_hdr->eth_type = FLOW_ETH_PRO_IP;

                ipv4_hdr = (struct pro_ipv4_hdr *)(buf + buf_len);
                buf_len += sizeof(struct pro_ipv4_hdr);

                ipv4_hdr->version       = 4;
                ipv4_hdr->ihl           = 5;
                ipv4_hdr->tos           = 0;
                ipv4_hdr->protocol      = IP_PRO_UDP;
                ipv4_hdr->tot_len       = 0; /* Finally, set it up */
                ipv4_hdr->id            = (uint16_t)ros_get_tsc_hz();
                ipv4_hdr->frag_off      = 0x0040;
                ipv4_hdr->ttl           = 64;
                ipv4_hdr->dest          = tmp_ipv4_hdr->source;
                ipv4_hdr->source        = tmp_ipv4_hdr->dest;
                ipv4_hdr->check         = 0; /* Finally, set it up */
            }
            break;

        case 6:
            {
                struct pro_ipv6_hdr *tmp_ipv6_hdr = FlowGetL1Ipv6Header(key);

                eth_hdr->eth_type = FLOW_ETH_PRO_IPV6;

                ipv6_hdr = (struct pro_ipv6_hdr *)(buf + buf_len);
                buf_len += sizeof(struct pro_ipv6_hdr);

                ipv6_hdr->vtc_flow.d.version    = 6;
                ipv6_hdr->vtc_flow.d.priority   = 0;
                ipv6_hdr->vtc_flow.d.flow_lbl   = 0;
                ipv6_hdr->vtc_flow.value        = htonl(ipv6_hdr->vtc_flow.value);
                ipv6_hdr->payload_len           = 0; /* Finally, set it up */
                ipv6_hdr->nexthdr               = IP_PRO_UDP;
                ipv6_hdr->hop_limit             = 64;
                memcpy(ipv6_hdr->saddr, tmp_ipv6_hdr->daddr, IPV6_ALEN);
                memcpy(ipv6_hdr->daddr, tmp_ipv6_hdr->saddr, IPV6_ALEN);
            }
            break;

        default:
            LOG(UPC, ERR, "Abnormal IP version.\n");
            return;
    }

    /* Filling udp header */
    udp_hdr = (struct pro_udp_hdr *)(buf + buf_len);
    buf_len += sizeof(struct pro_udp_hdr);

    udp_hdr->dest   = FLOW_UDP_PORT_GTPU;
    udp_hdr->source = FLOW_UDP_PORT_GTPU;
    udp_hdr->len    = 0; /* Finally, set it up */
    udp_hdr->check  = 0;

    /* Filling gtpu header */
    gtpu_hdr = (struct pro_gtp_hdr *)(buf + buf_len);
    buf_len +=  sizeof(struct pro_gtp_hdr);

    gtpu_hdr->flags.data        = 0;
    gtpu_hdr->flags.s.version   = 1;
    gtpu_hdr->flags.s.type      = 1;
    gtpu_hdr->flags.s.e         = 1;
    gtpu_hdr->flags.s.s         = 1;
    gtpu_hdr->flags.s.reserve   = 0;
    gtpu_hdr->teid              = 0;
    gtpu_hdr->msg_type          = MSG_TYPE_T_ERR_INDI;
    gtpu_hdr->length            = 0;

    /* Filling sequnce number */
    seq_num = (uint16_t *)(buf + buf_len);
    *seq_num = htons(ros_atomic16_add_return(&g_echo_seq_num, 1));
    buf_len +=  sizeof(*seq_num);
    /* Filling N-PDU Number */
    buf[buf_len++] = 0;
    /* Filling Next Extension Header Type */
    buf[buf_len++] = EN_GTP_EH_UDP_PORT;

    /* UDP Port Extension Header */
    buf[buf_len++] = 0x1;
    tmp_udp_hdr = FlowGetL1UdpHeader(key);
    *(uint16_t *)&buf[buf_len] = tmp_udp_hdr->source;
    buf_len += 2;
    buf[buf_len++] = EN_GTP_EH_NO_MORE;

    /* Filling Tunnel Endpoint Identifier Data I */
    tmp_gtp_hdr = FlowGetGtpuHeader(key);
    buf[buf_len++] = GTP_IE_TEID_DATA_I;
    *(uint32_t *)(buf + buf_len) = tmp_gtp_hdr->teid;
    buf_len += sizeof(uint32_t);

    /* set checksum */
    if (ipv4_hdr) {
        /* Filling GTP-U Peer Address */
        struct pro_ipv4_hdr *tmp_ipv4_hdr = FlowGetL1Ipv4Header(key);
        buf[buf_len++] = GTP_IE_PEER_ADDRESS;
        buf[buf_len++] = 0;
        buf[buf_len++] = 4; /* Value length */
        *(uint32_t *)(buf + buf_len) = tmp_ipv4_hdr->dest;
        buf_len += 4;

        gtpu_hdr->length = htons((uint16_t)(buf_len - ((uint8_t *)seq_num - buf)));

        ipv4_hdr->tot_len = htons((uint16_t)(buf_len - ((uint8_t *)ipv4_hdr - buf)));
        ipv4_hdr->check = calc_crc_ip(ipv4_hdr);
        udp_hdr->len    = htons((uint16_t)(buf_len - ((uint8_t *)udp_hdr - buf)));
        udp_hdr->check = calc_crc_udp(udp_hdr, ipv4_hdr);
    } else if (ipv6_hdr) {
        /* Filling GTP-U Peer Address */
        struct pro_ipv6_hdr *tmp_ipv6_hdr = FlowGetL1Ipv6Header(key);
        buf[buf_len++] = GTP_IE_PEER_ADDRESS;
        buf[buf_len++] = 0;
        buf[buf_len++] = IPV6_ALEN; /* Value length */
        memcpy((buf + buf_len), tmp_ipv6_hdr->daddr, IPV6_ALEN);
        buf_len += IPV6_ALEN;

        gtpu_hdr->length = htons((uint16_t)(buf_len - ((uint8_t *)seq_num - buf)));

        ipv6_hdr->payload_len = htons((uint16_t)(buf_len - ((uint8_t *)udp_hdr - buf)));
        udp_hdr->len    = ipv6_hdr->payload_len;
        udp_hdr->check = calc_crc_udp6(udp_hdr, ipv6_hdr);
    }

    if (0 > upc_channel_trans(buf, buf_len)) {
        LOG(SESSION, ERR, "send resp packet buff to LB failed.");
        return;
    }
}

int session_gtp_pkt_process(struct filter_key *key)
{
    struct pro_gtp_hdr *gtpu_hdr = NULL;

    if (NULL == key) {
        LOG(SESSION, ERR, "Abnormal parameter, key(%p).", key);
        return -1;
    }

    gtpu_hdr = FlowGetGtpuHeader(key);
    if (NULL == gtpu_hdr) {
        LOG(SESSION, ERR, "gtpu_hdr is NULL.");
        return -1;
    }

    switch (gtpu_hdr->msg_type) {
        case MSG_TYPE_T_ECHO_REQ:
            (void)session_gtpu_send_echo_resp(key);
            break;

        case MSG_TYPE_T_ECHO_RESP:
            if (0 > session_gtpu_table_match(key)) {
                LOG(SESSION, ERR, "Match gtpu entry failed.");
            }
            break;

        case MSG_TYPE_T_ERR_INDI:
            if (0 > session_gtpu_recv_error_indication(key)) {
                LOG(SESSION, ERR, "Processing Error Indication failed.");
    		}
            break;

        default:
            break;
    }
    LOG(SESSION, RUNNING,"Process GTP-U packet finish.\n");

    return 0;
}

int session_gtpu_insert(void *ip, uint8_t ip_ver, uint8_t port, uint32_t node_index)
{
    struct session_gtpu_table *table = session_gtpu_table_get();
    struct session_gtpu_entry *entry = NULL;
    uint32_t res_key = 0, res_index = 0;
    session_gtpu_key rb_key = {.ipv6 = {0}};

    if (NULL == ip) {
        LOG(SESSION, ERR, "Abnormal parameter, ip(%p).", ip);
        return -1;
    }

    switch (ip_ver) {
        case SESSION_IP_V4:
            rb_key.ipv4 = *(uint32_t *)ip;
            break;

        case SESSION_IP_V6:
            memcpy(rb_key.ipv6, ip, IPV6_ALEN);
            break;

        default:
            LOG(SESSION, ERR, "IP version type: %d unsupport.", ip_ver);
            return -1;
    }

    ros_rwlock_write_lock(&table->lock); /* lock */
    entry = (struct session_gtpu_entry *)rbtree_search(&table->gtpu_root,
        &rb_key, session_gtpu_compare);
    ros_rwlock_write_unlock(&table->lock); /* unlock */
    if (entry) {
        LOG(SESSION, RUNNING,
            "The same GTPU entry already exists, ready change count.");
        ros_atomic32_inc(&entry->assoc_num);

        return 0;
    }
    LOG(SESSION, RUNNING, "No such gtpu entry, ready insert. node_index:%d", node_index);

    if (G_FAILURE == Res_Alloc(table->pool_id, &res_key, &res_index, EN_RES_ALLOC_MODE_OC)) {
        LOG(SESSION, ERR, "Res_Alloc gtpu entry failed, pool_id: %u.",
            table->pool_id);
        return -1;
    }
    entry = session_gtpu_entry_get(res_index);

    ros_rwlock_write_lock(&entry->lock); /* lock */
    entry->ip_flag = ip_ver;
    ros_memcpy(&entry->ip_addr, &rb_key, sizeof(session_gtpu_key));
	entry->port = port;
    entry->node_index = node_index;
    ros_atomic32_set(&entry->assoc_num, 1);
    /* Check echo_flag */
    entry->timeout_num = 0;
    ros_rwlock_write_unlock(&entry->lock); /* unlock */

    ros_rwlock_write_lock(&table->lock); /* lock */
    if (0 > rbtree_insert(&table->gtpu_root, &entry->entry_node,
        &entry->ip_addr, session_gtpu_compare)) {
        Res_Free(table->pool_id, 0, res_index);
        ros_rwlock_write_unlock(&table->lock); /* unlock */
        LOG(SESSION, ERR, "gtpu entry insert failed.");
        return -1;
    }
    ros_rwlock_write_unlock(&table->lock); /* unlock */

    return 0;
}

int session_gtpu_delete(comm_msg_outh_cr_t *ohc)
{
    struct session_gtpu_table *table = session_gtpu_table_get();
    struct session_gtpu_entry *entry = NULL;
    session_gtpu_key key = {.ipv6 = {0}};

    if (NULL == ohc) {
        LOG(SESSION, ERR, "Abnormal parameter, ohc(%p).", ohc);
        return -1;
    }

    switch (ohc->type.value) {
        case 0x100:
            key.ipv4 = ohc->ipv4;
            break;

        case 0x200:
            memcpy(key.ipv6, ohc->ipv6.s6_addr, IPV6_ALEN);
            break;

        case 0x300:
            key.ipv4 = ohc->ipv4;

            ros_rwlock_write_lock(&table->lock); /* lock */
            entry = (struct session_gtpu_entry *)rbtree_search(&table->gtpu_root, &key, session_gtpu_compare);
            ros_rwlock_write_unlock(&table->lock); /* unlock */
            if (entry) {
                LOG(SESSION, RUNNING, "The same GTPU entry already exists, assoc_num: %d.",
                    ros_atomic32_read(&entry->assoc_num));

                ros_atomic32_dec(&entry->assoc_num);
                if (0 == ros_atomic32_read(&entry->assoc_num)) {
                    ros_rwlock_write_lock(&table->lock); /* lock */
                    entry = (struct session_gtpu_entry *)rbtree_delete(&table->gtpu_root, &key, session_gtpu_compare);
                    ros_rwlock_write_unlock(&table->lock); /* unlock */
                    if (entry) {
                        ros_atomic32_init(&entry->assoc_num);
                        Res_Free(table->pool_id, 0, entry->index);
                    }
                }
            }

            memcpy(key.ipv6, ohc->ipv6.s6_addr, IPV6_ALEN);
            ros_rwlock_write_lock(&table->lock); /* lock */
            entry = (struct session_gtpu_entry *)rbtree_search(&table->gtpu_root, &key, session_gtpu_compare);
            ros_rwlock_write_unlock(&table->lock); /* unlock */
            if (entry) {
                LOG(SESSION, RUNNING, "The same GTPU entry already exists, assoc_num: %d.",
                    ros_atomic32_read(&entry->assoc_num));

                ros_atomic32_dec(&entry->assoc_num);
                if (0 == ros_atomic32_read(&entry->assoc_num)) {
                    ros_rwlock_write_lock(&table->lock); /* lock */
                    entry = (struct session_gtpu_entry *)rbtree_delete(&table->gtpu_root, &key, session_gtpu_compare);
                    ros_rwlock_write_unlock(&table->lock); /* unlock */
                    if (entry) {
                        ros_atomic32_init(&entry->assoc_num);
                        Res_Free(table->pool_id, 0, entry->index);
                    }
                }
            }
            return 0;

        default:
            LOG(SESSION, RUNNING, "OHC type unsupported, type: %d.",
                ohc->type.value);
            return -1;
    }

    ros_rwlock_write_lock(&table->lock); /* lock */
    entry = (struct session_gtpu_entry *)rbtree_search(&table->gtpu_root, &key, session_gtpu_compare);
    ros_rwlock_write_unlock(&table->lock); /* unlock */
    if (entry) {
        LOG(SESSION, RUNNING, "The same GTPU entry already exists, assoc_num: %d.",
            ros_atomic32_read(&entry->assoc_num));

        ros_atomic32_dec(&entry->assoc_num);

        if (0 == ros_atomic32_read(&entry->assoc_num)) {
            ros_rwlock_write_lock(&table->lock); /* lock */
            entry = (struct session_gtpu_entry *)rbtree_delete(&table->gtpu_root, &key, session_gtpu_compare);
            ros_rwlock_write_unlock(&table->lock); /* unlock */
            if (NULL == entry) {
                LOG(SESSION, ERR, "gtpu entry delete failed, no such entry.");
                return -1;
            }

            ros_atomic32_init(&entry->assoc_num);
            Res_Free(table->pool_id, 0, entry->index);
        }

        return 0;
    } else {
        LOG(SESSION, ERR, "Delete gtpu entry failed, No such entry.");
        return -1;
    }

    return 0;
}

int64_t session_gtpu_init(uint32_t session_num)
{
    uint32_t index = 0;
    int pool_id = -1;
    struct session_gtpu_table *gtpu_table = session_gtpu_table_get();
    struct session_gtpu_entry *gtpu_entry = NULL;
    uint32_t max_num = 0;
    int64_t size = 0, total_mem = 0;
    pthread_t pth_id;

    /* init gtpu table */
    max_num = session_num;
    size = sizeof(struct session_gtpu_entry) * max_num;
    total_mem += size;
    gtpu_entry = ros_malloc(size);
    if (NULL == gtpu_entry) {
        LOG(SESSION, ERR, "session teid init failed, no enough memory, max_num: %u.",
            max_num);
        return -1;
    }
    ros_memset(gtpu_entry, 0, size);

    for (index = 0; index < max_num; ++index) {
        gtpu_entry[index].index  = index;
        ros_rwlock_init(&gtpu_entry[index].lock);
        ros_atomic32_init(&gtpu_entry[index].assoc_num);
    }

    pool_id = Res_CreatePool();
    if (pool_id < 0) {
        LOG(SESSION, ERR, "Res_CreatePool failed.");
        return -1;
    }
    if (G_FAILURE == Res_AddSection(pool_id, 0, 0, max_num)) {
        LOG(SESSION, ERR, "Res_AddSection failed.");
        return -1;
    }

    gtpu_table->pool_id     = pool_id;
    gtpu_table->gtpu_entry  = gtpu_entry;
    gtpu_table->max_num     = max_num;
    gtpu_table->gtpu_root   = RB_ROOT_INIT_VALUE;
	ros_rwlock_init(&gtpu_table->lock);

    /* Init ECHO task */
    if (0 != pthread_create(&pth_id, NULL, session_gtpu_send_request_task, NULL)) {
		LOG(SESSION, ERR, "create audit pthread failed.");
        return -1;
	}

    size = session_peer_fteid_init(session_num);
    if (size < 0) {
        LOG(SESSION, ERR, "Peer f-teid table init failed.");
        return -1;
    }
    total_mem += size;

    LOG(SESSION, MUST, "Gtp-u echo table init success.");
    return total_mem;
}

int session_gtpu_end_marker(comm_msg_outh_cr_t *ohc)
{
    upc_config_info *upc_cfg = upc_get_config();
    uint8_t buf[256];
    uint32_t buf_len = 0;
    struct pro_eth_hdr *eth_hdr = NULL;
    struct pro_ipv4_hdr *ipv4_hdr = NULL;
    struct pro_ipv6_hdr *ipv6_hdr = NULL;
    struct pro_udp_hdr *udp_hdr = NULL;
    struct pro_gtp_hdr *gtpu_hdr = NULL;
    struct session_gtpu_entry *entry = NULL;

    if (NULL == ohc) {
        LOG(SESSION, ERR, "Abnormal parameter, ohc(%p).", ohc);
        return -1;
    }

    /* set eth header */
    eth_hdr = (struct pro_eth_hdr *)buf;
    buf_len += ETH_HLEN;

    upc_mb_copy_port_mac(entry->port, eth_hdr->dest);
    ros_memcpy(eth_hdr->source, upc_cfg->n4_local_mac, ETH_ALEN);
    eth_hdr->eth_type = htons(ETH_PRO_IP);

    ros_rwlock_read_lock(&entry->lock);   /* lock */
    switch (entry->ip_flag) {
        case SESSION_IP_V4:
            ipv4_hdr = (struct pro_ipv4_hdr *)(buf + buf_len);
            buf_len += sizeof(struct pro_ipv4_hdr);

            ipv4_hdr->version       = 4;
            ipv4_hdr->ihl           = 5;
            ipv4_hdr->tos           = 0;
            ipv4_hdr->protocol      = IP_PRO_UDP;
            ipv4_hdr->tot_len       = htons(sizeof(struct pro_gtp_hdr) +
                sizeof(struct pro_udp_hdr) + sizeof(struct pro_ipv4_hdr));
            ipv4_hdr->id            = (uint16_t)ros_get_tsc_hz();
            ipv4_hdr->frag_off      = 0x0040;
            ipv4_hdr->ttl           = 0xFF;
            ipv4_hdr->dest          = htonl(ohc->ipv4);
            ipv4_hdr->source        = htonl(upc_cfg->upf_ip_cfg[EN_PORT_N3].ipv4);
            ipv4_hdr->check         = 0;
            break;

        case SESSION_IP_V6:
            ipv6_hdr = (struct pro_ipv6_hdr *)(buf + buf_len);
            buf_len += sizeof(struct pro_ipv6_hdr);

            ipv6_hdr->vtc_flow.d.version    = 6;
    		ipv6_hdr->vtc_flow.d.priority	= 0;
    		ipv6_hdr->vtc_flow.d.flow_lbl	= 0;
            ipv6_hdr->vtc_flow.value        = htonl(ipv6_hdr->vtc_flow.value);
    		ipv6_hdr->payload_len           = htons(sizeof(struct pro_gtp_hdr) +
                sizeof(struct pro_udp_hdr));
    		ipv6_hdr->nexthdr		        = IP_PRO_UDP;
    		ipv6_hdr->hop_limit	            = 64;
            ros_memcpy(ipv6_hdr->saddr, upc_cfg->upf_ip_cfg[EN_PORT_N3].ipv6, IPV6_ALEN);
            ros_memcpy(ipv6_hdr->daddr, &ohc->ipv6, IPV6_ALEN);
            break;
    }

    /* set udp header */
    udp_hdr = (struct pro_udp_hdr *)(buf + buf_len);
    buf_len += sizeof(struct pro_udp_hdr);

    udp_hdr->dest       = FLOW_UDP_PORT_GTPU;
    udp_hdr->source     = FLOW_UDP_PORT_GTPU;
    udp_hdr->len        = htons(sizeof(struct pro_gtp_hdr) +
            sizeof(struct pro_udp_hdr));
    udp_hdr->check      = 0;

    gtpu_hdr = (struct pro_gtp_hdr *)(buf + buf_len);
    buf_len += sizeof(struct pro_gtp_hdr);

    /* set gtpu header */
    gtpu_hdr->flags.data        = 0;
    gtpu_hdr->flags.s.version   = 1;
    gtpu_hdr->flags.s.type      = 1;
    gtpu_hdr->flags.s.e         = 0;
    gtpu_hdr->flags.s.s         = 0;
    gtpu_hdr->flags.s.reserve   = 0;
    gtpu_hdr->teid              = htonl(ohc->teid);
    gtpu_hdr->msg_type          = MSG_TYPE_T_END_MARKER;
    gtpu_hdr->length            = 0;

    ros_rwlock_read_unlock(&entry->lock); /* unlock */

    /* set checksum */
    switch (entry->ip_flag) {
        case SESSION_IP_V4:
            ipv4_hdr->check = calc_crc_ip(ipv4_hdr);
            udp_hdr->check = calc_crc_udp(udp_hdr, ipv4_hdr);
            break;

        case SESSION_IP_V6:
            udp_hdr->check = calc_crc_udp6(udp_hdr, ipv6_hdr);
            break;
    }

    /* send to LB */
    if (0 > upc_channel_trans(buf, buf_len)) {
        LOG(SESSION, ERR, "Send packet to LB failed.");
        return -1;
    }

    LOG(SESSION, RUNNING, "Send END MARKER packet success, teid %u, buf(%p), len: %d.",
        ohc->teid, buf, buf_len);

    return 0;
}

/******************************** Peer f-teid table ***********************************/
static inline struct session_peer_fteid_table *session_peer_fteid_table_get(void)
{
    return &g_session_peer_fteid_table;
}

static inline struct session_peer_fteid_entry *session_peer_fteid_entry_get(uint32_t index)
{
    return &g_session_peer_fteid_table.fteid_entry[index];
}

static inline int session_peer_fteid_compare(struct rb_node *node, void *key)
{
    struct session_peer_fteid_entry *node_entry = (struct session_peer_fteid_entry *)node;

    return memcmp(&node_entry->fteid_key, key, sizeof(session_fteid_key));
}

static int session_gtpu_recv_error_indication(struct filter_key *key)
{
    struct session_peer_fteid_table *fteid_head = session_peer_fteid_table_get();
    struct session_peer_fteid_entry  *fteid_entry = NULL;
    struct pro_gtp_hdr *gtpu_hdr = NULL;
    session_fteid_key tmp_key = {.ipv6 = {0}};
    uint8_t     *buffer;
    uint16_t    buf_pos;
    uint32_t    buf_max;
    uint8_t     obj_type;
    uint16_t    len;
    uint8_t     mandatory_ie = 0; /* 1: TEID  2:Peer Address */

    gtpu_hdr = FlowGetGtpuHeader(key);
    if (NULL == gtpu_hdr){
        LOG(SESSION, ERR, "gtpu_hdr is NULL.");
        return -1;
    }

    buf_max = ntohs(gtpu_hdr->length);
    buffer = FlowGetGtpuInnerContext(key);
    if (unlikely(NULL == buffer)) {
        LOG(SESSION, RUNNING, "Abnormal error indication packet, Missing mandatory IE.\n");
        return -1;
    }
    buf_max -= buffer - (uint8_t *)(gtpu_hdr + 1);
    buf_pos = 0;

    while (buf_pos < buf_max) {
        obj_type = tlv_decode_uint8_t(buffer, &buf_pos);
        switch (obj_type) {
            case GTP_IE_TEID_DATA_I:
                tmp_key.teid = tlv_decode_uint32_t(buffer, &buf_pos);
                mandatory_ie |= 1;
                break;

            case GTP_IE_PEER_ADDRESS:
                len = tlv_decode_uint16_t(buffer, &buf_pos);
                if (4 == len) {
                    tmp_key.ipv4 = tlv_decode_uint32_t(buffer, &buf_pos);
                    LOG(SESSION, RUNNING, "search ipv4: 0x%08x.", tmp_key.ipv4);
                } else if (IPV6_ALEN == len){
                    tlv_decode_binary(buffer, &buf_pos, IPV6_ALEN, tmp_key.ipv6);

                    LOG(SESSION, RUNNING, "search peer_ipv6: 0x%016lx %016lx.",
                        *(uint64_t *)tmp_key.ipv6, *(uint64_t *)(tmp_key.ipv6 + 8));
                } else {
                    LOG(SESSION, ERR, "GSN Address len(%d) invaild.", len);
                    return -1;
                }
                mandatory_ie |= 2;
                break;

            case GTP_IE_PRVIVATE_EXTENSION:
                len = tlv_decode_uint16_t(buffer, &buf_pos);
                buf_pos += len;
                break;

            default:
                LOG(UPC, ERR, "type %d, not support.", obj_type);
                return -1;
        }
    }

    if (3 != mandatory_ie) {
        LOG(UPC, ERR, "Missing mandatory IE, mandatory_ie: %d", mandatory_ie);
        return -1;
    }

    ros_rwlock_read_lock(&fteid_head->lock); /* lock */
    fteid_entry = (struct session_peer_fteid_entry *)rbtree_search(&fteid_head->peer_fteid_root,
            (void *)&tmp_key, session_peer_fteid_compare);
    ros_rwlock_read_unlock(&fteid_head->lock); /* unlock */
    if (NULL == fteid_entry || NULL == fteid_entry->sess_cfg) {
        LOG(SESSION, ERR, "Peer f-teid entry is NULL.");
        return -1;
    } else {
        if (-1 == session_report_teid_err(fteid_entry)) {
            LOG(SESSION, ERR, "Error indication report failed.");
        }
    }

    return 0;
}

int session_peer_fteid_insert(void *ip, uint8_t ip_ver, uint32_t teid, struct pfcp_session *sess_cfg)
{
    struct session_peer_fteid_table *table = session_peer_fteid_table_get();
    struct session_peer_fteid_entry *entry = NULL;
    uint32_t res_key = 0, res_index = 0;

    if (NULL == ip) {
        LOG(SESSION, ERR, "Abnormal parameter, ip(%p).", ip);
        return -1;
    }

    if (G_FAILURE == Res_Alloc(table->pool_id, &res_key, &res_index, EN_RES_ALLOC_MODE_OC)) {
        LOG(SESSION, ERR, "Res_Alloc gtpu entry failed, pool_id: %u.",
            table->pool_id);
        return -1;
    }
    entry = session_peer_fteid_entry_get(res_index);

    ros_rwlock_write_lock(&entry->lock); /* lock */
    ros_memset(&entry->fteid_key, 0, sizeof(session_fteid_key));
    entry->ip_flag = ip_ver;
    entry->fteid_key.teid = teid;
    switch (ip_ver) {
        case SESSION_IP_V4:
            entry->fteid_key.ipv4 = *(uint32_t *)ip;
            break;

        case SESSION_IP_V6:
            memcpy(entry->fteid_key.ipv6, ip, IPV6_ALEN);
            break;

        default:
            ros_rwlock_write_unlock(&entry->lock); /* unlock */
            LOG(SESSION, ERR, "IP version type: %d unsupport.", ip_ver);
            return -1;
    }
    entry->sess_cfg = sess_cfg;
    ros_rwlock_write_unlock(&entry->lock); /* unlock */

    ros_rwlock_write_lock(&table->lock); /* lock */
    if (0 > rbtree_insert(&table->peer_fteid_root, &entry->entry_node,
        &entry->fteid_key, session_peer_fteid_compare)) {
        Res_Free(table->pool_id, 0, res_index);
        ros_rwlock_write_unlock(&table->lock); /* unlock */
        LOG(SESSION, ERR, "Peer f-teid entry insert failed.");
        return -1;
    }
    ros_rwlock_write_unlock(&table->lock); /* unlock */

    return 0;
}

int session_peer_fteid_delete(comm_msg_outh_cr_t *ohc)
{
    struct session_peer_fteid_table *table = session_peer_fteid_table_get();
    struct session_peer_fteid_entry *entry = NULL;
    session_fteid_key key = {.ipv6 = {0}};

    if (NULL == ohc) {
        LOG(SESSION, ERR, "Abnormal parameter, ohc(%p).", ohc);
        return -1;
    }

    key.teid = ohc->teid;
    switch (ohc->type.value) {
        case 0x100:
            key.ipv4 = ohc->ipv4;
            break;

        case 0x200:
            memcpy(key.ipv6, ohc->ipv6.s6_addr, IPV6_ALEN);
            break;

        case 0x300:
            key.ipv4 = ohc->ipv4;

            ros_rwlock_write_lock(&table->lock); /* lock */
            entry = (struct session_peer_fteid_entry *)rbtree_delete(&table->peer_fteid_root, &key,
                session_peer_fteid_compare);
            ros_rwlock_write_unlock(&table->lock); /* unlock */
            if (entry) {
                Res_Free(table->pool_id, 0, entry->index);
            }

            memcpy(key.ipv6, ohc->ipv6.s6_addr, IPV6_ALEN);
            ros_rwlock_write_lock(&table->lock); /* lock */
            entry = (struct session_peer_fteid_entry *)rbtree_delete(&table->peer_fteid_root, &key,
                session_peer_fteid_compare);
            ros_rwlock_write_unlock(&table->lock); /* unlock */
            if (entry) {
                Res_Free(table->pool_id, 0, entry->index);
            }
            return 0;

        default:
            LOG(SESSION, RUNNING, "OHC type unsupported, type: %d.",
                ohc->type.value);
            return -1;
    }

    ros_rwlock_write_lock(&table->lock); /* lock */
    entry = (struct session_peer_fteid_entry *)rbtree_delete(&table->peer_fteid_root, &key,
        session_peer_fteid_compare);
    ros_rwlock_write_unlock(&table->lock); /* unlock */
    if (NULL == entry) {
        LOG(SESSION, ERR, "gtpu entry delete failed, no such entry.");
        return -1;
    }
    Res_Free(table->pool_id, 0, entry->index);

    return 0;
}

static int64_t session_peer_fteid_init(uint32_t session_num)
{
    uint32_t index = 0;
    int pool_id = -1;
    struct session_peer_fteid_table *table = session_peer_fteid_table_get();
    struct session_peer_fteid_entry *entry = NULL;
    uint32_t max_num = 0;
    int64_t size = 0, total_mem = 0;

    /* init gtpu table */
    max_num = session_num * MAX_FAR_NUM;
    size = sizeof(struct session_peer_fteid_entry) * max_num;
    total_mem += size;
    entry = ros_malloc(size);
    if (NULL == entry) {
        LOG(SESSION, ERR, "Session peer f-teid init failed, no enough memory, max_num: %u.",
            max_num);
        return -1;
    }
    ros_memset(entry, 0, size);

    for (index = 0; index < max_num; ++index) {
        entry[index].index  = index;
        ros_rwlock_init(&entry[index].lock);
    }

    pool_id = Res_CreatePool();
    if (pool_id < 0) {
        LOG(SESSION, ERR, "Res_CreatePool failed.");
        return -1;
    }
    if (G_FAILURE == Res_AddSection(pool_id, 0, 0, max_num)) {
        LOG(SESSION, ERR, "Res_AddSection failed.");
        return -1;
    }

    table->pool_id     = pool_id;
    table->fteid_entry  = entry;
    table->max_num     = max_num;
    table->peer_fteid_root   = RB_ROOT_INIT_VALUE;
	ros_rwlock_init(&table->lock);

    LOG(SESSION, MUST, "Peer f-teid table init success.");
    return total_mem;
}


