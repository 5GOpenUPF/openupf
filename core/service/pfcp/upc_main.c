/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "upc_node.h"
#ifdef ENABLED_HA
#include "upc_high_availability.h"
#endif
#include "upc_session.h"
#include "upc_seid.h"
#include "pfcp_client.h"
#include "upc_ueip.h"
#include "upc_teid.h"
#include "pfcp_pfd_mgmt.h"

#ifdef SUPPORT_REST_API
#include "ulfius.h"
#endif

#include "session.h"
#include "session_teid.h"
#include "sp_backend_mgmt.h"
#include "session_mgmt.h"
#include "far_mgmt.h"
#include "bar_mgmt.h"
#include "urr_mgmt.h"
#include "qer_mgmt.h"
#include "mar_mgmt.h"
#include "pfd_mgmt.h"
#include "session_instance.h"
#include "session_audit.h"
#include "sp_dns_cache.h"
#include "urr_proc.h"
#include "tuple_table.h"
#include "local_parse.h"
#include "parse_session_config.h"
#include "predefine_rule_mgmt.h"

upc_config_info g_upc_config;
user_Signaling_trace_t user_sig_trace;

struct service_raw *upc_pfcp_channel;

/* SMU packets status */
ros_atomic64_t upc_pkt_stat[UPC_PKT_STATUS_BUTT];

#ifdef SUPPORT_REST_API
/* REST api instance */
struct _u_instance upc_restful_instance;
#endif

/* If you use network address translation, you need to turn it on */
static int upc_nat_enabled = 0;

static ros_atomic16_t  upc_work_status = {.cnt = HA_STATUS_INIT};    /* init | active | standby */
static ros_atomic16_t  upc_standby_alive = {.cnt = G_FALSE};

UPC_SYNC_BACKEND             upc_hk_sync_backend = NULL;
UPC_BUILD_DATA_BLOCK         upc_hk_build_data_block = NULL;
UPC_CHANGE_SYNC_BLOCK_STATUS upc_hk_change_sync_blk_status = NULL;
UPC_HA_MSG_PROC              upc_hk_ha_msg_proc = NULL;
UPC_HA_INIT                  upc_hk_ha_init = NULL;
UPC_HA_DEINIT                upc_hk_ha_deinit = NULL;
UPC_HA_ASS                   upc_hk_ha_ass = NULL;

static inline void upc_register_high_availability_module(UPC_SYNC_BACKEND sync_backend,
                                           UPC_BUILD_DATA_BLOCK build_data_blk,
                                           UPC_CHANGE_SYNC_BLOCK_STATUS change_sync_blk_status,
                                           UPC_HA_MSG_PROC ha_msg_proc,
                                           UPC_HA_INIT ha_init,
                                           UPC_HA_DEINIT ha_deinit,
                                           UPC_HA_ASS ha_ass)
{
    upc_hk_sync_backend             = sync_backend;
    upc_hk_build_data_block         = build_data_blk;
    upc_hk_change_sync_blk_status   = change_sync_blk_status;
    upc_hk_ha_msg_proc              = ha_msg_proc;
    upc_hk_ha_init                  = ha_init;
    upc_hk_ha_deinit                = ha_deinit;
    upc_hk_ha_ass                   = ha_ass;
}

static inline void upc_shutdown_function(void)
{
    upc_management_end_config *mb_cfg = upc_mb_config_get_public();

    upc_node_hb_timer_stop();
    comm_msg_channel_server_shutdown(&mb_cfg->be_mgmt_server);
    comm_msg_channel_client_shutdown(&mb_cfg->chnl_client);
}

static inline void upc_activation_function(void)
{
    upc_config_info *cfg = upc_get_config();
    upc_management_end_config *mb_cfg = upc_mb_config_get_public();

    if (0 > comm_msg_create_channel_client(&mb_cfg->chnl_client, cfg->lb_ips, cfg->lb_ips_num,
        cfg->lb_port, cfg->cpus, cfg->core_num)) {
        LOG(UPC, ERR , "Create channel-client failed.");
    }
    /* Init backend management service */
    if (0 > comm_msg_create_channel_server(&mb_cfg->be_mgmt_server,
        cfg->fpu_mgmt_port, cfg->cpus, cfg->core_num)) {
        LOG(UPC, ERR, "Create channel server failed.");
    }

    upc_node_hb_timer_start();
}

void upc_set_work_status(int16_t status)
{
    switch (status) {
        case HA_STATUS_ACTIVE:
            if (HA_STATUS_SMOOTH2ACTIVE != upc_get_work_status()) {
                /* 避免从平滑切到主的时候重复操作 */
                upc_activation_function();
            }
            break;

        case HA_STATUS_STANDBY:
            if (HA_STATUS_SMOOTH2STANDBY != upc_get_work_status()) {
                upc_shutdown_function();
            }
            break;

        case HA_STATUS_SMOOTH2ACTIVE:
            /* 平滑升级为主用 */
            upc_activation_function();
            break;

        case HA_STATUS_SMOOTH2STANDBY:
            /* 平滑降级为备用 */
            upc_shutdown_function();
            break;

        default:
            return;
    }

    ros_atomic16_set(&upc_work_status, status);
}

int16_t upc_get_work_status(void)
{
    return ros_atomic16_read(&upc_work_status);
}

void upc_set_standby_alive(int16_t status)
{
    ros_atomic16_set(&upc_standby_alive, status);
}

int16_t upc_get_standby_alive(void)
{
    return ros_atomic16_read(&upc_standby_alive);
}

int upc_set_up_config(const uint64_t up)
{
	upc_config_info *conf = upc_get_config();
	conf->up_features.value = up;
	return 0;
}

upc_config_info *upc_get_config(void)
{
    return &g_upc_config;
}

session_ip_addr *upc_get_local_ip(void)
{
    return &g_upc_config.upf_ip_cfg[EN_PORT_N4];
}

char *upc_get_2smf_ethname(void)
{
    return g_upc_config.upc2smf_name;
}

session_ip_addr *upc_get_n3_local_ip(void)
{
    return &(g_upc_config.upf_ip_cfg[EN_PORT_N3]);
}

uint64_t upc_get_up_features(void)
{
    return g_upc_config.up_features.value;
}

void upc_pkt_status_add(int unit)
{
    if (likely(unit < UPC_PKT_STATUS_BUTT))
        ros_atomic64_inc(&upc_pkt_stat[unit]);
}

static inline int64_t upc_pkt_status_read(int unit)
{
    if (likely(unit < UPC_PKT_STATUS_BUTT))
        return ros_atomic64_read(&upc_pkt_stat[unit]);

    return 0;
}

struct service_raw *upc_get_pfcp_channel(void)
{
    return upc_pfcp_channel;
}

static inline void upc_pkt_status_init(void)
{
    int cnt;

    for (cnt = 0; cnt < UPC_PKT_STATUS_BUTT; ++cnt)
        ros_atomic64_init(&upc_pkt_stat[cnt]);
}

static int upc_check_eth_name(char *ethname)
{
    if (if_nametoindex(ethname) == 0) {
        return ERROR;
    }

    return OK;
}

int upc_get_nat_flag(void)
{
    return upc_nat_enabled;
}

void upc_set_nat_flag(int act)
{
    upc_nat_enabled = act ? 1 : 0;
}

void upc_dump_packet(uint8_t *buf, uint16_t buf_len)
{
    uint16_t cnt = 0;

    for (cnt = 0; cnt < buf_len; ++cnt) {
        printf("%02x ", buf[cnt]);
        if (15 == cnt % 16) {
            printf("\r\n");
        } else if (7 == cnt % 16) {
            printf("   ");
        }
    }
    printf("\r\n");

    printf("buf_len: %d.\r\n", buf_len);
}

void upc_fill_ip_udp_hdr(uint8_t *buf, uint16_t *buf_len, struct sockaddr *sa)
{
    upc_management_end_config *mb_cfg = upc_mb_config_get_public();
    upc_config_info *upc_conf = upc_get_config();
    uint16_t offset = *buf_len, dest_port;
    struct pro_eth_hdr *eth_hdr;
    struct pro_udp_hdr  *udp_hdr;

    /* Filling ethernet header */
    eth_hdr = (struct pro_eth_hdr *)(buf + offset);
    offset += ETH_HLEN;
    memcpy(eth_hdr->dest, mb_cfg->lb_mac[EN_PORT_N4], ETH_ALEN);
    memcpy(eth_hdr->source, upc_conf->n4_local_mac, ETH_ALEN);

    switch (sa->sa_family) {
        case AF_INET6:
            {
                struct sockaddr_in6 *sa_v6 = (struct sockaddr_in6 *)sa;
                struct pro_ipv6_hdr *ip6_hdr;

                eth_hdr->eth_type = FLOW_ETH_PRO_IPV6;

                /*-------------- IPv6 header --------------*/
                ip6_hdr = (struct pro_ipv6_hdr *)(buf + offset);
                offset += sizeof(struct pro_ipv6_hdr);
                ip6_hdr->vtc_flow.d.version     = 6;
                ip6_hdr->vtc_flow.d.priority    = 0;
                ip6_hdr->vtc_flow.d.flow_lbl    = (uint32_t)ros_rdtsc();
                ip6_hdr->vtc_flow.value         = htonl(ip6_hdr->vtc_flow.value);
                ip6_hdr->payload_len            = 0;
                ip6_hdr->nexthdr                = IP_PRO_UDP;
                ip6_hdr->hop_limit              = 64;
                ros_memcpy(ip6_hdr->saddr, upc_conf->upf_ip_cfg[EN_PORT_N4].ipv6, IPV6_ALEN);
                ros_memcpy(ip6_hdr->daddr, &sa_v6->sin6_addr, IPV6_ALEN);

                dest_port = sa_v6->sin6_port;
            }
            break;

        case AF_INET:
        default:
            {
                struct sockaddr_in *sa_v4 = (struct sockaddr_in *)sa;
                struct pro_ipv4_hdr *ip_hdr;

                eth_hdr->eth_type = FLOW_ETH_PRO_IP;

                /*-------------- IPv4 header --------------*/
                ip_hdr = (struct pro_ipv4_hdr *)(buf + offset);
                offset += sizeof(struct pro_ipv4_hdr);
                /* Encode ip version and header length */
                ip_hdr->version = 4;
                ip_hdr->ihl = 5;
                ip_hdr->tos = 0;
                /* Encode total length */
                ip_hdr->tot_len = 0;
                /* Encode ID */
                ip_hdr->id = (uint16_t)ros_rdtsc();
                /* Encode fragment */
                ip_hdr->frag_off = 0;
                /* Encode TTL */
                ip_hdr->ttl = 0x40;
                /* Encode protocol */
                ip_hdr->protocol = IP_PRO_UDP;
                /* Encode checksum */
                ip_hdr->check = 0;
                /* Encode src ip */
                ip_hdr->source = htonl(upc_conf->upf_ip_cfg[EN_PORT_N4].ipv4);
                /* Encode dest ip */
                ip_hdr->dest = sa_v4->sin_addr.s_addr;

                dest_port = sa_v4->sin_port;
            }
            break;
    }

    /*-------------- UDP header --------------*/
    udp_hdr = (struct pro_udp_hdr *)(buf + offset);
    offset += sizeof(struct pro_udp_hdr);
    /* Encode src port */
    udp_hdr->source = FLOW_PFCP_PORT;
    /* Encode dest port */
    udp_hdr->dest = dest_port;
    /* Encode udp length */
    udp_hdr->len = 0;
    /* Encode checksum */
    udp_hdr->check = 0;

    *buf_len = offset;
}

static inline void upc_fill_v4_pkt_len(uint8_t *buf, uint16_t buf_len, struct sockaddr *sa)
{
    switch (sa->sa_family) {
        case AF_INET6:
            {
                struct pro_ipv6_hdr *ip6_hdr = (struct pro_ipv6_hdr *)(buf + ETH_HLEN);
                struct pro_udp_hdr  *udp_hdr = (struct pro_udp_hdr *)(ip6_hdr + 1);
                uint16_t pl_len = buf_len - ETH_HLEN - sizeof(struct pro_ipv6_hdr);

                ip6_hdr->payload_len = htons(pl_len);

                udp_hdr->len = htons(pl_len);
                udp_hdr->check = calc_crc_udp6(udp_hdr, ip6_hdr);
            }
            break;

        case AF_INET:
        default:
            {
                struct pro_ipv4_hdr *ip_hdr = (struct pro_ipv4_hdr *)(buf + ETH_HLEN);
                struct pro_udp_hdr  *udp_hdr = (struct pro_udp_hdr *)(ip_hdr + 1);

                ip_hdr->tot_len = htons(buf_len - ETH_HLEN);
                ip_hdr->check = calc_crc_ip(ip_hdr);

                udp_hdr->len = htons(buf_len - (((uint8_t *)udp_hdr) - buf));
                udp_hdr->check = calc_crc_udp(udp_hdr, ip_hdr);
            }
            break;
    }
}

int upc_channel_trans(uint8_t *buf, uint16_t len)
{
    if (likely(upc_pfcp_channel)) {
        upc_pkt_status_add(UPC_PKT_SEND_TO_SMF);

        ros_rwlock_write_lock(&upc_pfcp_channel->lock); /* lock */
        if (sendto(upc_pfcp_channel->fd, buf, len, 0, 0, 0) < 0) {
            upc_pfcp_channel->work_flag = FALSE;
            ros_rwlock_write_unlock(&upc_pfcp_channel->lock); /* unlock */
            LOG(UPC, ERR, "Send failed(%s).", strerror(errno));
            return -1;
        }
        ros_rwlock_write_unlock(&upc_pfcp_channel->lock); /* unlock */

        LOG(UPC, RUNNING, "send packet (payload length %d) success!\r\n", len);
    }

    return 0;
}

int upc_buff_send2smf(uint8_t *buf, uint16_t len, struct sockaddr *sa)
{
    if (unlikely((buf == NULL) || (len == 0) || (NULL == sa))) {
        LOG(UPC, ERR, "Input Para Err, buf(%p), len: %d, sa(%p).",
            buf, len, sa);
        return -1;
	}

    upc_fill_v4_pkt_len(buf, len, sa);

    return upc_channel_trans(buf, len);
}

static int upc_packet_entry(char *buf, int len, void *arg)
{
    struct packet_desc  desc = {.buf = buf, .len = len, .offset = 0};
    struct filter_key   match_key;
    struct pro_udp_hdr *udp_hdr;
    char *payload_buf;

    if (unlikely(0 == len)) {
        LOG(UPC, ERR, "Abnormal packet received, buf(%p), len: %d, arg(%p)\n", buf, len, arg);
        return -1;
    }

    /* Discard broadcast packets */
    if (0xFFFFFFFF == *(uint32_t *)buf) {
        LOG(UPC, PERIOD, "Discard broadcast packets.");
        return 0;
    }

    if (unlikely(packet_dissect(&desc, &match_key) < 0)) {
        LOG(UPC, PERIOD, "Packet dissect failed!\n");
        return -1;
    }

    if (!FLOW_MASK_FIELD_ISSET(match_key.field_offset, FLOW_FIELD_L1_UDP)) {
        LOG(UPC, DEBUG, "It's not a UDP packet.\n");
        /* 非UDP报文直接丢弃 */
        return 0;
    }

    udp_hdr = FlowGetL1UdpHeader(&match_key);
    payload_buf = (char *)(udp_hdr + 1);
    len -= (payload_buf - buf);

    LOG(UPC, DEBUG, "Recv packet length: %d.", len);

    switch (udp_hdr->dest) {
        case FLOW_PFCP_PORT:
            upc_pkt_status_add(UPC_PKT_RECV_FORM_SMF);
            switch (upc_get_work_status()) {
                case HA_STATUS_ACTIVE:
                case HA_STATUS_SMOOTH2ACTIVE:
                    switch (FlowGetL1IpVersion(&match_key)) {
                        case 4:
                            {
                                struct pro_ipv4_hdr *ip4_hdr = FlowGetL1Ipv4Header(&match_key);
                                struct sockaddr_in sa_v4 = {.sin_family = AF_INET, .sin_addr.s_addr = ip4_hdr->source,
                                    .sin_port = udp_hdr->source};

                                pfcp_client_entry(payload_buf, len, &sa_v4);
                            }
                            break;

                        case 6:
                            {
                                struct pro_ipv6_hdr *ip6_hdr = FlowGetL1Ipv6Header(&match_key);
                                struct sockaddr_in6 sa_v6 = {.sin6_family = AF_INET6, .sin6_port = udp_hdr->source};

                                memcpy(&sa_v6.sin6_addr, ip6_hdr->saddr, IPV6_ALEN);

                                pfcp_client_entry(payload_buf, len, &sa_v6);
                            }
                            break;

                        default:
                            return -1;
                    }
                    break;

                case HA_STATUS_SMOOTH2STANDBY:
                case HA_STATUS_STANDBY:
                    /* 可能在主备切换的情况下收到报文, 直接转发到主SMU去处理 */
                    {
                        upc_config_info *upc_conf = upc_get_config();
                        struct pro_eth_hdr *eth_hdr = (struct pro_eth_hdr *)buf;

                        memcpy(eth_hdr->source, upc_conf->n4_local_mac, ETH_ALEN);
                        memcpy(eth_hdr->dest, upc_conf->peer_smu_mac[EN_PORT_N4], ETH_ALEN);

                        upc_channel_trans((uint8_t *)buf, len);
                    }
                    break;

                default:
                    return 0;
            }
            break;

        case FLOW_UDP_PORT_GTPU:
            /* GTP-U echo | GTP-U Error indication */
            session_gtp_pkt_process(&match_key);
            break;

        default:
            return 0;
    }

    return 0;
}

static uint32_t upc_msg_proc(void *token, comm_msg_ie_t *ie)
{
    int fd = (uint64_t)token;
    uint32_t ret = EN_COMM_ERRNO_OK;

    switch(ie->cmd)
    {
        case EN_COMM_MSG_HA_HB:
        case EN_COMM_MSG_HA_SYNC_BLOCK:
        case EN_COMM_MSG_HA_SYNC_REQUEST:
        case EN_COMM_MSG_HA_GET_STAT_REQ:
        case EN_COMM_MSG_HA_GET_STAT_RESP:
        case EN_COMM_MSG_HA_ASS_REQ:
        case EN_COMM_MSG_HA_ASS_RESP:
        case EN_COMM_MSG_HA_SYNC_BACKEND:
            if (upc_hk_ha_msg_proc) {
                ret = upc_hk_ha_msg_proc(token, ie);
            }
            break;

        case EN_COMM_MSG_MATCH_SESSION:
            LOG(SESSION, RUNNING, "Recv new flow match.");
            session_pkt_match_process((char *)ie->data, ie->len - COMM_MSG_IE_LEN_COMMON, fd);
            break;

        case EN_COMM_MSG_UPU_QER_GET:
            qer_check_all(ie, fd);
            break;

        case EN_COMM_MSG_UPU_QER_SUM:
            {
                comm_msg_resp_ie_t *resp_ie = (comm_msg_resp_ie_t *)ie;
                upc_backend_config *be_cfg;
                uint32_t resp_ret = ntohl(resp_ie->ret);

                resp_ie->flag_key = ntohll(resp_ie->flag_key);

                LOG(UPC, DEBUG, "Back-end compare QER entry sum, key: %lu", resp_ie->flag_key);
                be_cfg = upc_backend_search(resp_ie->flag_key);
                if (NULL == be_cfg) {
                    LOG(UPC, ERR, "No such backend, maybe it's cancelled.\n");
                } else {
                    rules_sum_check(resp_ret, be_cfg->fsm, EN_QER_AUDIT);
                }
            }
            break;

        case EN_COMM_MSG_UPU_QER_VAL:
            {
                comm_msg_entry_val_config_t *val_cfg = (comm_msg_entry_val_config_t *)ie->data;
                if (0 > qer_check_table_validity(val_cfg, fd)) {
                    LOG(SESSION, ERR, "Check table validity failed.");
                }
            }
            break;

        case EN_COMM_MSG_UPU_QER_PRS:
            {
                if (0 > session_proc_qer_prss(ie)) {
                    LOG(SESSION, ERR, "Process fpu qer packet rate status failed.");
                }
            }
            break;

        case EN_COMM_MSG_UPU_INST_GET:
            session_instance_check_all(ie, fd);
            break;

        case EN_COMM_MSG_UPU_INST_SUM:
            {
                comm_msg_resp_ie_t *resp_ie = (comm_msg_resp_ie_t *)ie;
                upc_backend_config *be_cfg;
                uint32_t resp_ret = ntohl(resp_ie->ret);

                resp_ie->flag_key = ntohll(resp_ie->flag_key);

                LOG(UPC, DEBUG, "Back-end compare INST entry sum, key: %lu", resp_ie->flag_key);
                be_cfg = upc_backend_search(resp_ie->flag_key);
                if (NULL == be_cfg) {
                    LOG(UPC, ERR, "No such backend, maybe it's cancelled.\n");
                } else {
                    rules_sum_check(resp_ret, be_cfg->fsm, EN_INST_AUDIT);
                }
            }
            break;

        case EN_COMM_MSG_UPU_INST_VALIDITY:
            {
                comm_msg_entry_val_config_t *val_cfg = (comm_msg_entry_val_config_t *)ie->data;
                if (0 > session_instance_check_table_validity(val_cfg, fd)) {
                    LOG(SESSION, ERR, "Check table validity failed.");
                }
            }
            break;

        case EN_COMM_MSG_UPU_FAR_GET:
            far_check_all(ie, fd);
            break;

        case EN_COMM_MSG_UPU_FAR_SUM:
            {
                comm_msg_resp_ie_t *resp_ie = (comm_msg_resp_ie_t *)ie;
                upc_backend_config *be_cfg;
                uint32_t resp_ret = ntohl(resp_ie->ret);

                resp_ie->flag_key = ntohll(resp_ie->flag_key);

                LOG(UPC, DEBUG, "Back-end compare FAR entry sum, key: %lu", resp_ie->flag_key);
                be_cfg = upc_backend_search(resp_ie->flag_key);
                if (NULL == be_cfg) {
                    LOG(UPC, ERR, "No such backend, maybe it's cancelled.\n");
                } else {
                    rules_sum_check(resp_ret, be_cfg->fsm, EN_FAR_AUDIT);
                }
            }
            break;

        case EN_COMM_MSG_UPU_FAR_VAL:
            {
                comm_msg_entry_val_config_t *val_cfg = (comm_msg_entry_val_config_t *)ie->data;
                if (0 > far_check_table_validity(val_cfg, fd)) {
                    LOG(SESSION, ERR, "Check table validity failed.");
                }
            }
            break;

        case EN_COMM_MSG_UPU_BAR_GET:
            bar_check_all(ie, fd);
            break;

        case EN_COMM_MSG_UPU_BAR_SUM:
            {
                comm_msg_resp_ie_t *resp_ie = (comm_msg_resp_ie_t *)ie;
                upc_backend_config *be_cfg;
                uint32_t resp_ret = ntohl(resp_ie->ret);

                resp_ie->flag_key = ntohll(resp_ie->flag_key);

                LOG(UPC, DEBUG, "Back-end compare BAR entry sum, key: %lu", resp_ie->flag_key);
                be_cfg = upc_backend_search(resp_ie->flag_key);
                if (NULL == be_cfg) {
                    LOG(UPC, ERR, "No such backend, maybe it's cancelled.\n");
                } else {
                    rules_sum_check(resp_ret, be_cfg->fsm, EN_BAR_AUDIT);
                }
            }
            break;

        case EN_COMM_MSG_UPU_BAR_VAL:
            {
                comm_msg_entry_val_config_t *val_cfg = (comm_msg_entry_val_config_t *)ie->data;
                if (0 > bar_check_table_validity(val_cfg, fd)) {
                    LOG(SESSION, ERR, "Check table validity failed.");
                }
            }
            break;

        case EN_COMM_MSG_UPU_DNS_ADD:
            sdc_update_ie_proc(ie);
            break;

        case EN_COMM_MSG_UPU_DNS_GET:
            sdc_check_all(ie, fd);
            break;

        case EN_COMM_MSG_UPU_DNS_SUM:
            {
                comm_msg_resp_ie_t *resp_ie = (comm_msg_resp_ie_t *)ie;
                upc_backend_config *be_cfg;
                uint32_t resp_ret = ntohl(resp_ie->ret);

                resp_ie->flag_key = ntohll(resp_ie->flag_key);

                LOG(UPC, DEBUG, "Back-end compare DNS entry sum, key: %lu", resp_ie->flag_key);
                be_cfg = upc_backend_search(resp_ie->flag_key);
                if (NULL == be_cfg) {
                    LOG(UPC, ERR, "No such backend, maybe it's cancelled.\n");
                } else {
                    rules_sum_check(resp_ret, be_cfg->fsm, EN_DNS_AUDIT);
                }
            }
            break;

        case EN_COMM_MSG_UPU_DNS_VAL:
            {
                comm_msg_entry_val_config_t *val_cfg = (comm_msg_entry_val_config_t *)ie->data;
                if (0 > sdc_check_table_validity(val_cfg, fd)) {
                    LOG(SESSION, ERR, "Check table validity failed.");
                }
            }
            break;

        case EN_COMM_MSG_COLLECT_STATUS:
            {
                comm_msg_fpu_stat *stat = (comm_msg_fpu_stat *)(ie->data);

                session_update_fpu_status(stat);
            }
            break;

        case EN_COMM_MSG_UPU_FP_STAT:
            {
                comm_msg_urr_stat_conf_t *stat = (comm_msg_urr_stat_conf_t *)(ie->data);

                urr_count_proc(ie->index, stat);
            }
            break;

        case EN_COMM_MSG_BACKEND_HB:
            {
                comm_msg_backend_config *hb_cfg = (comm_msg_backend_config *)ie->data;
                upc_backend_config *be_cfg;

                LOG(UPC, PERIOD, "Back-end heartbeat, key: %lu", hb_cfg->key);
                be_cfg = upc_backend_search(hb_cfg->key);
                if (NULL == be_cfg) {
                    LOG(UPC, MUST, "Back-end register, key: %lu", hb_cfg->key);

                    be_cfg = upc_backend_register(hb_cfg, fd);
                    if (NULL == be_cfg) {
                        LOG(UPC, ERR, "Register backend failed.");
                        upc_tell_backend_re_register(fd);
                    } else {
                        LOG(UPC, MUST, "Add a new back-end node, key: %lu", hb_cfg->key);
                        upc_tell_backend_config(fd);
                    }
                } else {
                    be_cfg->fd = fd;
                    ros_atomic16_init(&be_cfg->be_timeout_times);
                }
                upc_backend_heartbeat_reply(fd);
            }
            break;

        case EN_COMM_MSG_BACKEND_ACTIVE:
            {
                comm_msg_backend_config *hb_cfg = (comm_msg_backend_config *)ie->data;
                upc_backend_config *be_cfg;

                be_cfg = upc_backend_search(hb_cfg->key);
                if (NULL == be_cfg) {
                    LOG(UPC, ERR, "Active back-end node failed, no such key: %lu", hb_cfg->key);
                } else {
                    LOG(SESSION, RUNNING, "session synchronize table.");
                    ros_atomic32_set(&be_cfg->be_state, EN_BACKEND_SYNC);
                    session_send_simple_cmd_to_fp(EN_COMM_MSG_UPU_BAR_VAL, fd);
                    session_send_simple_cmd_to_fp(EN_COMM_MSG_UPU_QER_VAL, fd);
                    session_send_simple_cmd_to_fp(EN_COMM_MSG_UPU_FAR_VAL, fd);
                    session_send_simple_cmd_to_fp(EN_COMM_MSG_UPU_INST_VALIDITY, fd);

                    upc_backend_activate(be_cfg);
                }
            }
            break;

        case EN_COMM_MSG_BACKEND_DEACTIVE:
            {
                comm_msg_backend_config *hb_cfg = (comm_msg_backend_config *)ie->data;
                upc_backend_config *be_cfg;

                be_cfg = upc_backend_search(hb_cfg->key);
                if (NULL == be_cfg) {
                    LOG(UPC, ERR, "Deactive back-end failed, no such key: %lu", hb_cfg->key);
                } else {
                    LOG(SESSION, MUST, "Deactive back-end, key: %lu", hb_cfg->key);
                    upc_backend_unregister((uint8_t)be_cfg->index);
                }
            }
            break;

        case EN_COMM_MSG_MB_HB:
            {
                upc_management_end_config *mb_fsm = upc_mb_config_get_public();
                comm_msg_heartbeat_config *hb_cfg = (comm_msg_heartbeat_config *)ie->data;

                if (mb_fsm->peer_key != hb_cfg->key) {

                    mb_fsm->peer_key = hb_cfg->key;
                    memcpy(mb_fsm->lb_mac, hb_cfg->mac, EN_PORT_BUTT * ETH_ALEN);

                    /* 连接成功, 通知LB的MAC到已有fpu */
                    upc_mb_set_work_status(EN_UPC_STATE_CONNECTED);
                    upc_tell_backend_change_active_mac();

                    /* 发送已有fpu的配置到LB */
                    upc_lb_register_all_backend();
                } else {
                    /* 审计两边backend的数量 */
                    upc_backend_mgmt *be_mgmt = upc_get_backend_mgmt_public();
                    comm_msg_rules_ie_t *rules_ie = (comm_msg_rules_ie_t *)ie;

                    if (be_mgmt->last_num == Res_GetAlloced(be_mgmt->pool_id) &&
                        be_mgmt->last_num != rules_ie->rules_num) {
                        /* 调整LB的backend数量 */
                        upc_get_backend_validity(fd);
                    } else {
                        be_mgmt->last_num = Res_GetAlloced(be_mgmt->pool_id);
                    }
                }
                ros_atomic32_init(&mb_fsm->hb_cnt);
            }
            break;

        case EN_COMM_MSG_LBMAC_RESET:
            {
                upc_management_end_config *mb_fsm = upc_mb_config_get_public();
                comm_msg_heartbeat_config *hb_cfg = (comm_msg_heartbeat_config *)ie->data;

                mb_fsm->peer_key = hb_cfg->key;
                memcpy(mb_fsm->lb_mac, hb_cfg->mac, EN_PORT_BUTT * ETH_ALEN);

                /* 通知LB的MAC到已有fpu */
                upc_tell_backend_change_active_mac();
            }
            break;

        case EN_COMM_MSG_BACKEND_VALIDITY:
            {
                comm_msg_entry_val_config_t *val_cfg = (comm_msg_entry_val_config_t *)ie->data;
                if (0 > upc_backend_compare_validity(val_cfg)) {
                    LOG(UPC, ERR, "Check table validity failed.");
                }
            }
            break;

        default:
            LOG(UPC, ERR, "Unknown ie cmd 0x%04x.", ie->cmd);
            break;
    }
    LOG(UPC, DEBUG, "msg (%x) process finished, return value 0x%x.\r\n",
        ie->cmd, ret);

    return ret;
}

int upc_show_packet_stats(struct cli_def *cli, int argc, char **argv)
{
    cli_print(cli,"SMU packets statistics:\r\n");
    cli_print(cli,"\treceived smf packets:\t%ld\r\n",
        upc_pkt_status_read(UPC_PKT_RECV_FORM_SMF));
    cli_print(cli,"\tsend smf packets:\t%ld\r\n",
        upc_pkt_status_read(UPC_PKT_SEND_TO_SMF));

    cli_print(cli,"\tsend sess_est response to smf:\t%ld\r\n",
        upc_pkt_status_read(UPC_PKT_SESS_EST_SEND2SMF));
    cli_print(cli,"\trecv sess_est request from smf:\t%ld\r\n",
        upc_pkt_status_read(UPC_PKT_SESS_EST_RECV4SMF));

    cli_print(cli,"\tsend sess_mdf response to smf:\t%ld\r\n",
        upc_pkt_status_read(UPC_PKT_SESS_MDF_SEND2SMF));
    cli_print(cli,"\trecv sess_mdf request from smf:\t%ld\r\n",
        upc_pkt_status_read(UPC_PKT_SESS_MDF_RECV4SMF));

    cli_print(cli,"\tsend sess_del response to smf:\t%ld\r\n",
        upc_pkt_status_read(UPC_PKT_SESS_DEL_SEND2SMF));
    cli_print(cli,"\trecv sess_del request from smf:\t%ld\r\n",
        upc_pkt_status_read(UPC_PKT_SESS_DEL_RECV4SMF));

    cli_print(cli,"\tsend sess_report request to smf:\t%ld\r\n",
        upc_pkt_status_read(UPC_PKT_SESS_REPORT_SEND2SMF));
    cli_print(cli,"\trecv sess_report response from smf:\t%ld\r\n",
        upc_pkt_status_read(UPC_PKT_SESS_REPORT_RECV4SMF));

    cli_print(cli,"\tsend node_create response to smf:\t%ld\r\n",
        upc_pkt_status_read(UPC_PKT_NODE_CREATE_SEND2SMF));
    cli_print(cli,"\trecv node_create request from smf:\t%ld\r\n",
        upc_pkt_status_read(UPC_PKT_NODE_CREATE_RECV4SMF));
    cli_print(cli,"\tsend node_update response to smf:\t%ld\r\n",
        upc_pkt_status_read(UPC_PKT_NODE_UPDATE_SEND2SMF));
    cli_print(cli,"\trecv node_update request from smf:\t%ld\r\n",
        upc_pkt_status_read(UPC_PKT_NODE_UPDATE_RECV4SMF));
    cli_print(cli,"\tsend node_remove response to smf:\t%ld\r\n",
        upc_pkt_status_read(UPC_PKT_NODE_REMOVE_SEND2SMF));
    cli_print(cli,"\trecv node_remove request from smf:\t%ld\r\n",
        upc_pkt_status_read(UPC_PKT_NODE_REMOVE_RECV4SMF));

    cli_print(cli,"\tsend node_report request to smf:\t%ld\r\n",
        upc_pkt_status_read(UPC_PKT_NODE_REPORT_SEND2SMF));
    cli_print(cli,"\trecv node_report response from smf:\t%ld\r\n",
        upc_pkt_status_read(UPC_PKT_NODE_REPORT_RECV4SMF));

    cli_print(cli,"\tsend pfd management response to smf:\t%ld\r\n",
        upc_pkt_status_read(UPC_PKT_PFD_MANAGEMENT_SEND2SMF));
    cli_print(cli,"\treceive pfd management request from smf:\t%ld\r\n",
        upc_pkt_status_read(UPC_PKT_PFD_MANAGEMENT_RECV4SMF));

    cli_print(cli,"\tsend PFCP heartbeat response to smf:\t%ld\r\n",
        upc_pkt_status_read(UPC_PKT_HEARTBEAT_RESP_SEND2SMF));
    cli_print(cli,"\treceive PFCP heartbeat request from smf:\t%ld\r\n",
        upc_pkt_status_read(UPC_PKT_HEARTBEAT_REQU_RECV4SMF));
    cli_print(cli,"\tsend PFCP heartbeat request to smf:\t%ld\r\n",
        upc_pkt_status_read(UPC_PKT_HEARTBEAT_REQU_SEND2SMF));
    cli_print(cli,"\treceive PFCP heartbeat response from smf:\t%ld\r\n",
        upc_pkt_status_read(UPC_PKT_HEARTBEAT_RESP_RECV4SMF));

    cli_print(cli,"\treceived fpu packets:\t%ld\n",
        session_pkt_status_read(SESSION_PKT_RECV_FORM_FPU));
    cli_print(cli,"\tsend fast modify:\t%ld\n",
        session_pkt_status_read(SESSION_PKT_MDF_FAST));

    cli_print(cli,"\r\n");

    if (argc > 0 && 0 == strncmp(argv[0], "clean", strlen("clean"))) {
        upc_pkt_status_init();
        session_pkt_status_init();
    }

    return 0;
}

static int64_t upc_parse_ueip_pool(struct pcf_file *conf)
{
    char section_ueip_pool[] = "ueip";
    char ueip_pool_prefix[] = "ueip_pool";
    char pool_num_key[] = "ueip_pool_num", *value = NULL;
    int cnt = 0, ip_pool_num = 0;
    char ueip_pool_name[64];
    struct ueip_pool_info *ip_pool_arr = NULL;
    int64_t use_memory = 0;

    value = pcf_get_key_value(conf, section_ueip_pool, pool_num_key);
    if (NULL == value) {
        printf("Can't get key[%s] in section[%s].\n",
            pool_num_key, section_ueip_pool);
        return -1;
    }

    /* node num */
    ip_pool_num = strtol(value, NULL, 10);

    if (ip_pool_num > 0) {
        char ip_addr[64] = "";

        ip_pool_arr = ros_malloc(sizeof(struct ueip_pool_info) * ip_pool_num);

        for (cnt = 0; cnt < ip_pool_num; ++cnt) {
            sprintf(ueip_pool_name, "%s_%d", ueip_pool_prefix, cnt + 1);
            value = pcf_get_key_value(conf, section_ueip_pool, ueip_pool_name);
            if (NULL == value) {
                printf("Can't get key[%s] in section[%s].\n",
                    ueip_pool_name, section_ueip_pool);
                return -1;
            }

            sscanf(value, "%[^/]/%hhu", ip_addr, &ip_pool_arr[cnt].prefix);

            if (strchr(ip_addr, ':')) {
                uint8_t v6_mask[IPV6_ALEN] = {0};
                uint8_t prefix = ip_pool_arr[cnt].prefix;

                /* ipv6 address */
                ip_pool_arr[cnt].ip_ver = SESSION_IP_V6;
                if(1 > inet_pton(AF_INET6, ip_addr,
                    ip_pool_arr[cnt].net_segment.ipv6)){
                    printf("domain: %d or ip address string: %s error.\n",
                        AF_INET6, ip_addr);
                    return -1;
                }
                ipv6_prefix_to_mask(v6_mask, prefix);
                *(uint64_t *)(ip_pool_arr[cnt].net_segment.ipv6) &=
                    *(uint64_t *)(v6_mask);
                *(uint64_t *)(ip_pool_arr[cnt].net_segment.ipv6 + 8) &=
                    *(uint64_t *)(v6_mask + 8);

                LOG(UPC, RUNNING,
                    "Add ueip ipv6 network segment: 0x%08x %08x %08x %08x.",
                    ntohl(*(uint32_t *)(ip_pool_arr[cnt].net_segment.ipv6)),
                    ntohl(*(uint32_t *)(ip_pool_arr[cnt].net_segment.ipv6 + 4)),
                    ntohl(*(uint32_t *)(ip_pool_arr[cnt].net_segment.ipv6 + 8)),
                    ntohl(*(uint32_t *)(ip_pool_arr[cnt].net_segment.ipv6 +
                    12)));

            } else if (strchr(ip_addr, '.')) {
                /* ipv4 address */
                uint32_t v4_addr = 0;
                uint8_t prefix = ip_pool_arr[cnt].prefix;

                ip_pool_arr[cnt].ip_ver = SESSION_IP_V4;
                if (1 != inet_pton(AF_INET, ip_addr, &v4_addr)) {
                    printf("domain: %d or ip address string: %s error.\n",
                        AF_INET, ip_addr);
                    return -1;
                }
                v4_addr = ntohl(v4_addr);

                v4_addr = ((uint64_t)v4_addr >> (32 - prefix)) << (32 - prefix);
                ip_pool_arr[cnt].net_segment.ipv4 = v4_addr;

                LOG(UPC, RUNNING,
                    "Add ueip ipv4 network segment: 0x%08x.",
                    ip_pool_arr[cnt].net_segment.ipv4);
            }
            LOG(UPC, RUNNING,"Add UEIP address pool: %s.", value);
        }

        use_memory = ueip_pool_init(ip_pool_arr, ip_pool_num);
        if (0 > use_memory) {
            ros_free(ip_pool_arr);
            printf("Init ueip address pool failed.\n");
            return -1;
        }

        ros_free(ip_pool_arr);
    }

    return use_memory;
}

static int upc_parse_up_features(struct pcf_file *conf)
{
    char up_features_sec[] = "UP_features";
    upc_config_info *upc_conf = upc_get_config();
    session_up_features *up_features = &upc_conf->up_features;
    int index = 0;
    struct kv_pair cfg_key_pair[] = {
        { "BUCP", NULL },
        { "DDND", NULL },
        { "DLBD", NULL },
        { "TRST", NULL },
        { "FTUP", NULL },
        { "PFDM", NULL },
        { "HEEU", NULL },
        { "TREU", NULL },
        { "EMPU", NULL },
        { "PDIU", NULL },
        { "UDBC", NULL },
        { "QUOAC", NULL },
        { "TRACE", NULL },
        { "FRRT", NULL },
        { "PFDE", NULL },
        { "EPFAR", NULL },
        { "DPDRA", NULL },
        { "ADPDP", NULL },
        { "UEIP", NULL },
        { "SSET", NULL },
        { "MNOP", NULL },
        { "MTE", NULL },
        { "BUNDL", NULL },
        { "GCOM", NULL },
        { "MPAS", NULL },
        { "RTTL", NULL },
        { "VTIME", NULL },
        { "NORP", NULL },
        { "IPTV", NULL },
        { "IP6PL", NULL },
        { "TSCU", NULL },
        { "MPTCP", NULL },
        { "ATSSS-LL", NULL },
        { "QFQM", NULL },
        { "GPQM", NULL },
        { "MT-EDT", NULL },
        { "CIOT", NULL },
        { "ETHAR", NULL },
        { NULL, NULL, }
    };

    while (cfg_key_pair[index].key != NULL) {
        cfg_key_pair[index].val = pcf_get_key_value(conf,
                     up_features_sec, cfg_key_pair[index].key);
        if (!cfg_key_pair[index].val) {
            LOG(UPC,ERR,"Can't get key[%s] in section[%s].\n",
                cfg_key_pair[index].key, up_features_sec);
            return -1;
        }
        ++index;
    }
    index = 0;

    /* BUCP */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.BUCP =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* DDND */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.DDND =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* DLBD */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.DLBD =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* TRST */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.TRST =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* FTUP */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.FTUP =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* PFDM */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.PFDM =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* HEEU */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.HEEU =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* TREU */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.TREU =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* EMPU */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.EMPU =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* PDIU */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.PDIU =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* UDBC */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.UDBC =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* QUOAC */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.QUOAC =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* TRACE */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.TRACE =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* FRRT */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.FRRT =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* PFDE */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.PFDE =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* EPFAR */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.EPFAR =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* DPDRA */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.DPDRA =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* ADPDP */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.ADPDP =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* UEIP */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.UEIP =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* SSET */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.SSET =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* MNOP */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.MNOP =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* MTE */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.MTE =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* BUNDL */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.BUNDL =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* GCOM */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.GCOM =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* MPAS */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.MPAS =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* RTTL */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.RTTL =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* VTIME */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.VTIME1 =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* NORP */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.NORP =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* IPTV */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.IPTV =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* IP6PL */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.IP6PL =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* TSCU */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.TSCU =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* MPTCP */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.MPTCP =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* ATSSS-LL */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.ATSSS_LL =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* QFQM */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.QFQM =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* GPQM */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.GPQM =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* MT-EDT */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.MT_EDT =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* CIOT */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.CIOT =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* ETHAR */
    if (strlen(cfg_key_pair[index].val) > 0) {
        up_features->d.ETHAR =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        printf("Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    return 0;
}

static int upc_parse_cfg(struct pcf_file *conf)
{
    upc_config_info *upc_conf = upc_get_config();
    int index = 0, cnt;
    struct kv_pair upc_key_pair[] = {
        { "n4_ethname", NULL },
        { "node_num", NULL },
        { "session_num", NULL },
        { "pfd_number", NULL },
        { "fast_number", NULL },
        { "n3_ip_v4", NULL },
        { "n3_ip_v6", NULL },
        { "n6_ip_v4", NULL },
        { "n6_ip_v6", NULL },
        { "n9_ip_v4", NULL },
        { "n9_ip_v6", NULL },
        { "n4_ip_v4", NULL },
        { "n4_ip_v6", NULL },
        { "orphan_number", NULL },
        { "teid_number", NULL },
        { "dns_num", NULL },
        { "ha_block_num", NULL },
        { "fast_bucket_number", NULL },
        { "block_number", NULL },
        { "block_size", NULL },
        { "cblock_number", NULL },
        { "restful_listen", NULL },
        { "lb_ips", NULL },
        { "lb_port", NULL },
        { "ha_ip", NULL },
        { "ha_port", NULL },
        { "default_master", NULL },
        { "fpu_mgmt_port", NULL },
        { "audit_period", NULL },
        { "audit_switch", NULL },
        { NULL, NULL, }
    };

    while (upc_key_pair[index].key != NULL) {
        upc_key_pair[index].val = pcf_get_key_value(conf,
                     SECTION_SRV_NAME, upc_key_pair[index].key);
        if (!upc_key_pair[index].val) {
            LOG(UPC,ERR,"Can't get key[%s] in section[%s].\n",
                upc_key_pair[index].key, SECTION_SRV_NAME);
            return -1;
        }
        ++index;
    }
    index = 0;

    /* effective cpus number */
    upc_conf->core_num = ros_get_avail_core_num();
    if (upc_conf->core_num != ros_parse_cpuset_cpus(upc_conf->cpus)) {
        LOG(UPC, ERR, "Parse cpuset cpus fail.");
        return -1;
    }

    if (-1 == upc_parse_up_features(conf)) {
        LOG(UPC,ERR,"Parse UP features failed.\n");
        return -1;
    }

    /* n4_ethname */
    if (strlen(upc_key_pair[index].val) < UPC_IF_NAME_LEN) {
        strcpy(upc_conf->upc2smf_name, upc_key_pair[index].val);
        if ((upc_check_eth_name(upc_conf->upc2smf_name) != OK)) {
            LOG(UPC,ERR,"Invalid interface name %s.\n", upc_conf->upc2smf_name);
            return -1;
        }
        if (-1 == ros_get_if_mac_addr(upc_conf->upc2smf_name, upc_conf->n4_local_mac)) {
            LOG(UPC, ERR, "Get upc2smf interface MAC address failed.");
            return -1;
        }

        ++index;
    } else {
        LOG(UPC, ERR, "Parse upc2smf interface failed, %s too long.",
            upc_key_pair[index].val);
        return -1;
    }

    /* node num */
    if (strlen(upc_key_pair[index].val) > 0) {
        upc_conf->node_num = strtol(upc_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(UPC, ERR, "Parse config failed, key: %s, value: %s",
            upc_key_pair[index].key, upc_key_pair[index].val);
        return -1;
    }

    /* session num */
    if (strlen(upc_key_pair[index].val) > 0) {
        upc_conf->session_num = strtol(upc_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(UPC, ERR, "Parse config failed, key: %s, value: %s",
            upc_key_pair[index].key, upc_key_pair[index].val);
        return -1;
    }

    /* pfd_number */
    if (strlen(upc_key_pair[index].val) > 0) {
        upc_conf->pfd_number = strtol(upc_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(UPC, ERR, "Parse config failed, key: %s, value: %s",
            upc_key_pair[index].key, upc_key_pair[index].val);
        return -1;
    }

    /* fast_number */
    if (strlen(upc_key_pair[index].val) > 0) {
        upc_conf->fast_num = strtol(upc_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(UPC, ERR, "Parse config failed, key: %s, value: %s",
            upc_key_pair[index].key, upc_key_pair[index].val);
        return -1;
    }

    /* N3 N6 N9 N4 IP */
    for (cnt = EN_PORT_N3; cnt < EN_PORT_BUTT; ++cnt) {
        if (strlen(upc_key_pair[index].val) > 0) {
            upc_conf->upf_ip_cfg[cnt].version |= SESSION_IP_V4;
            upc_conf->upf_ip_cfg[cnt].ipv4 =
                htonl(inet_addr(upc_key_pair[index].val));
            ++index;
        } else {
            LOG(UPC,ERR,"Invalid %s:%s config.\n", upc_key_pair[index].key,
                upc_key_pair[index].val);
            return -1;
        }

        if (strlen(upc_key_pair[index].val) > 0) {
            upc_conf->upf_ip_cfg[cnt].version |= SESSION_IP_V6;
            if(1 > inet_pton(AF_INET6, upc_key_pair[index].val,
                upc_conf->upf_ip_cfg[cnt].ipv6)){
                LOG(UPC,ERR,"domain: %d or ip address string: %s error.\n",
                    AF_INET6, upc_key_pair[index].val);
                return -1;
            }
            ++index;
        } else {
            LOG(UPC, ERR, "Invalid %s:%s config.\n", upc_key_pair[index].key,
                upc_key_pair[index].val);
            return -1;
        }
    }

    /* orphan_number */
    if (strlen(upc_key_pair[index].val) > 0) {
        upc_conf->orphan_number = strtol(upc_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(UPC, ERR, "Parse config failed, key: %s, value: %s",
            upc_key_pair[index].key, upc_key_pair[index].val);
        return -1;
    }

    /* teid_number */
    if (strlen(upc_key_pair[index].val) > 0) {
        upc_conf->teid_num = strtol(upc_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(UPC, ERR, "Parse config failed, key: %s, value: %s",
            upc_key_pair[index].key, upc_key_pair[index].val);
        return -1;
    }

    /* dns_num */
    if (strlen(upc_key_pair[index].val) > 0) {
        upc_conf->dns_num = strtol(upc_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(UPC, ERR, "Parse config failed, key: %s, value: %s",
            upc_key_pair[index].key, upc_key_pair[index].val);
        return -1;
    }

    /* ha_block_num */
    if (strlen(upc_key_pair[index].val) > 0) {
        upc_conf->ha_sync_block_num = strtol(upc_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(UPC, ERR, "Parse config failed, key: %s, value: %s",
            upc_key_pair[index].key, upc_key_pair[index].val);
        return -1;
    }

    /* fast_bucket_number */
    if (strlen(upc_key_pair[index].val) > 0) {
        upc_conf->fast_bucket_num = strtol(upc_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(UPC, ERR, "Parse config failed, key: %s, value: %s",
            upc_key_pair[index].key, upc_key_pair[index].val);
        return -1;
    }

    /* block_number */
    if (strlen(upc_key_pair[index].val) > 0) {
        upc_conf->block_num = strtol(upc_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(UPC, ERR, "Parse config failed, key: %s, value: %s",
            upc_key_pair[index].key, upc_key_pair[index].val);
        return -1;
    }

    /* block_size */
    if (strlen(upc_key_pair[index].val) > 0) {
        upc_conf->block_size = strtol(upc_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(UPC, ERR, "Parse config failed, key: %s, value: %s",
            upc_key_pair[index].key, upc_key_pair[index].val);
        return -1;
    }

    /* cblock_number */
    if (strlen(upc_key_pair[index].val) > 0) {
        upc_conf->cblock_num = strtol(upc_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(UPC, ERR, "Parse config failed, key: %s, value: %s",
            upc_key_pair[index].key, upc_key_pair[index].val);
        return -1;
    }

    /* restful_listen */
    if (strlen(upc_key_pair[index].val) > 0) {
        upc_conf->restful_listen = strtol(upc_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(UPC, ERR, "Parse config failed, key: %s, value: %s",
            upc_key_pair[index].key, upc_key_pair[index].val);
        return -1;
    }

    /* lb_ips */
    upc_conf->lb_ips_num = 0;
    if (strlen(upc_key_pair[index].val) > 0) {
        char *valid_ip = upc_key_pair[index].val, *token = NULL, print_str[512];
        uint16_t print_len = 0;

        for (token = strsep(&valid_ip, "|"); token != NULL; token = strsep(&valid_ip, "|")) {
            if (*token == 0) {
                continue;
            }

            upc_conf->lb_ips[upc_conf->lb_ips_num++]= htonl(inet_addr(token));
            print_len += sprintf(&print_str[print_len], "%s ", token);
        }

        LOG(LB, MUST, "Set load-balancer IP number: %d, IP: %s.", upc_conf->lb_ips_num, print_str);
    } else {
        LOG(LB, MUST, "Set load-balancer IP number: %d.", upc_conf->lb_ips_num);
    }
    ++index;

    /* lb_port */
    if (strlen(upc_key_pair[index].val) > 0) {
        upc_conf->lb_port = strtol(upc_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(UPC, ERR, "Parse config failed, key: %s, value: %s",
            upc_key_pair[index].key, upc_key_pair[index].val);
        return -1;
    }

    /* ha_ip */
    upc_conf->ha_remote_ip_num = 0;
    if (strlen(upc_key_pair[index].val) > 0) {
        char *valid_ip = upc_key_pair[index].val, *token = NULL, print_str[512];
        uint16_t print_len = 0;

        for (token = strsep(&valid_ip, "|"); token != NULL; token = strsep(&valid_ip, "|")) {
            if (*token == 0) {
                continue;
            }

            upc_conf->ha_remote_ip[upc_conf->ha_remote_ip_num++]= htonl(inet_addr(token));
            print_len += sprintf(&print_str[print_len], "%s ", token);
        }

        LOG(LB, MUST, "Set H-A IP number: %d, IP: %s.", upc_conf->ha_remote_ip_num, print_str);
    } else {
        LOG(LB, MUST, "Set H-A IP number: %d.", upc_conf->ha_remote_ip_num);
    }
    ++index;

    /* ha_port */
    if (strlen(upc_key_pair[index].val) > 0) {
        upc_conf->ha_local_port = strtol(upc_key_pair[index].val, NULL, 10);
        upc_conf->ha_remote_port = upc_conf->ha_local_port;
        ++index;
    } else {
        LOG(UPC, ERR, "Parse config failed, key: %s, value: %s",
            upc_key_pair[index].key, upc_key_pair[index].val);
        return -1;
    }

    /* default_master */
    if (strlen(upc_key_pair[index].val) > 0) {
        upc_conf->default_master = strtol(upc_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(UPC, ERR, "Parse config failed, key: %s, value: %s",
            upc_key_pair[index].key, upc_key_pair[index].val);
        return -1;
    }

    /* fpu_mgmt_port */
    if (strlen(upc_key_pair[index].val) > 0) {
        upc_conf->fpu_mgmt_port = strtol(upc_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(UPC, ERR, "Parse config failed, key: %s, value: %s",
            upc_key_pair[index].key, upc_key_pair[index].val);
        return -1;
    }

    /* audit_period */
    if (strlen(upc_key_pair[index].val) > 0) {
        upc_conf->audit_period = strtol(upc_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(UPC, ERR, "Parse config failed, key: %s, value: %s",
            upc_key_pair[index].key, upc_key_pair[index].val);
        return -1;
    }

    /* audit_switch */
    if (strlen(upc_key_pair[index].val) > 0) {
        upc_conf->audit_switch = strtol(upc_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(UPC, ERR, "Parse config failed, key: %s, value: %s",
            upc_key_pair[index].key, upc_key_pair[index].val);
        return -1;
    }

    LOG(UPC, MUST,
        "Init configure: N3_IP: 0x%08x, N4_IP: 0x%08x, N6_IP: 0x%08x, N9_IP: 0x%08x",
        upc_conf->upf_ip_cfg[EN_PORT_N3].ipv4, upc_conf->upf_ip_cfg[EN_PORT_N4].ipv4,
        upc_conf->upf_ip_cfg[EN_PORT_N6].ipv4, upc_conf->upf_ip_cfg[EN_PORT_N9].ipv4);
    LOG(UPC, MUST,
        "N4 MAC: %02x:%02x:%02x:%02x:%02x:%02x",
        upc_conf->n4_local_mac[0], upc_conf->n4_local_mac[1], upc_conf->n4_local_mac[2],
        upc_conf->n4_local_mac[3], upc_conf->n4_local_mac[4], upc_conf->n4_local_mac[5]);

    return 0;
}

#ifdef SUPPORT_REST_API
static int upc_collect_status_data(const struct _u_request *request,
    struct _u_response *response, void *user_data)
{
    char data[8192];
    uint32_t data_len = 0;
    uint32_t equ_flag = 0, cnt = 0;
    upc_node_header *node_mng = upc_node_mng_get();
    upc_seid_table_header *seid_mng = upc_seid_get_table_head();
    struct ueip_pool_table *ueip_mng = ueip_pool_mgmt_get();
    struct ueip_addr_pool *ueip_sec_pool = NULL;
    struct upc_teid_mgmt *teid_mng = upc_teid_mgmt_get();
    pfcp_pfd_table_header *pfd_mgmt = pfcp_pfd_get_table_header_public();
    char stat_name[32];

    /*---------------resource status---------------*/
    sprintf(stat_name, "smu_res_status");

    data_len += sprintf(&data[data_len], "# HELP %s Statistics of SMU in UPF.\n", stat_name);
    data_len += sprintf(&data[data_len], "# TYPE %s gauge\n", stat_name);

    /* node resource */
    data_len += sprintf(&data[data_len], "%s{name=\"node\"} %u\n", stat_name, Res_GetAlloced(node_mng->res_no));

    /* seid resource */
    equ_flag = (Res_GetAlloced(seid_mng->pool_id) == ros_atomic32_read(&seid_mng->use_num));
    data_len += sprintf(&data[data_len], "%s{name=\"seid\"} %u\n", stat_name,
        equ_flag ? Res_GetAlloced(seid_mng->pool_id) : (uint32_t)-1);

    /* ueip resource */
    for (cnt = 0; cnt < ueip_mng->ip_pool_num; ++cnt) {
        ueip_sec_pool = ueip_addr_pool_get(cnt);
        equ_flag = (Res_GetAlloced(ueip_sec_pool->pool_id) == ros_atomic32_read(&ueip_sec_pool->use_num));
        data_len += sprintf(&data[data_len], "%s{name=\"ueip_pool_%u\"} %u\n", stat_name, cnt,
            equ_flag ? Res_GetAlloced(ueip_sec_pool->pool_id) : (uint32_t)-1);
    }

    /* teid resource */
    data_len += sprintf(&data[data_len], "%s{name=\"teid\"} %u\n", stat_name,
        ros_atomic32_read(&teid_mng->teid_use_num));

    /* pfd request msg resource */
    data_len += sprintf(&data[data_len], "%s{name=\"pfd-req\"} %u\n", stat_name,
        Res_GetAlloced(pfd_mgmt->pool_id));


    /*---------------packets status---------------*/
    sprintf(stat_name, "smu_pkt_status");

    data_len += sprintf(&data[data_len], "# HELP %s Statistics of SMU in UPF.\n", stat_name);
    data_len += sprintf(&data[data_len], "# TYPE %s gauge\n", stat_name);

    data_len += sprintf(&data[data_len], "%s{name=\"recv_form_smf\"} %ld\n", stat_name,
        upc_pkt_status_read(UPC_PKT_RECV_FORM_SMF));
    data_len += sprintf(&data[data_len], "%s{name=\"send_to_smf\"} %ld\n", stat_name,
        upc_pkt_status_read(UPC_PKT_SEND_TO_SMF));

    /*----------------detail packets status------------------*/
    sprintf(stat_name, "smu_sess_detail");

    data_len += sprintf(&data[data_len], "# HELP %s Statistics of SMU in UPF.\n", stat_name);
    data_len += sprintf(&data[data_len], "# TYPE %s gauge\n", stat_name);

    data_len += sprintf(&data[data_len], "%s{name=\"send2smf_sess_est_resp\"} %ld\n", stat_name,
        upc_pkt_status_read(UPC_PKT_SESS_EST_SEND2SMF));
    data_len += sprintf(&data[data_len], "%s{name=\"recv4smf_sess_est_req\"} %ld\n", stat_name,
        upc_pkt_status_read(UPC_PKT_SESS_EST_RECV4SMF));

    data_len += sprintf(&data[data_len], "%s{name=\"send2smf_sess_mdf_resp\"} %ld\n", stat_name,
        upc_pkt_status_read(UPC_PKT_SESS_MDF_SEND2SMF));
    data_len += sprintf(&data[data_len], "%s{name=\"recv4smf_sess_mdf_req\"} %ld\n", stat_name,
        upc_pkt_status_read(UPC_PKT_SESS_MDF_RECV4SMF));

    data_len += sprintf(&data[data_len], "%s{name=\"send2smf_sess_del_resp\"} %ld\n", stat_name,
        upc_pkt_status_read(UPC_PKT_SESS_DEL_SEND2SMF));
    data_len += sprintf(&data[data_len], "%s{name=\"recv4smf_sess_del_req\"} %ld\n", stat_name,
        upc_pkt_status_read(UPC_PKT_SESS_DEL_RECV4SMF));

    data_len += sprintf(&data[data_len], "%s{name=\"send2smf_sess_report_req\"} %ld\n", stat_name,
        upc_pkt_status_read(UPC_PKT_SESS_REPORT_SEND2SMF));
    data_len += sprintf(&data[data_len], "%s{name=\"recv4smf_sess_report_resp\"} %ld\n", stat_name,
        upc_pkt_status_read(UPC_PKT_SESS_REPORT_RECV4SMF));

    sprintf(stat_name, "smu_node_detail");

    data_len += sprintf(&data[data_len], "# HELP %s Statistics of SMU in UPF.\n", stat_name);
    data_len += sprintf(&data[data_len], "# TYPE %s gauge\n", stat_name);

    data_len += sprintf(&data[data_len], "%s{name=\"send2spu_node_create_resp\"} %ld\n", stat_name,
        upc_pkt_status_read(UPC_PKT_NODE_CREATE_SEND2SMF));
    data_len += sprintf(&data[data_len], "%s{name=\"send2spu_node_create_req\"} %ld\n", stat_name,
        upc_pkt_status_read(UPC_PKT_NODE_CREATE_RECV4SMF));
    data_len += sprintf(&data[data_len], "%s{name=\"send2spu_node_update_resp\"} %ld\n", stat_name,
        upc_pkt_status_read(UPC_PKT_NODE_UPDATE_SEND2SMF));
    data_len += sprintf(&data[data_len], "%s{name=\"send2spu_node_update_req\"} %ld\n", stat_name,
        upc_pkt_status_read(UPC_PKT_NODE_UPDATE_RECV4SMF));
    data_len += sprintf(&data[data_len], "%s{name=\"send2spu_node_remove_resp\"} %ld\n", stat_name,
        upc_pkt_status_read(UPC_PKT_NODE_REMOVE_SEND2SMF));
    data_len += sprintf(&data[data_len], "%s{name=\"send2spu_node_remove_req\"} %ld\n", stat_name,
        upc_pkt_status_read(UPC_PKT_NODE_REMOVE_RECV4SMF));

    data_len += sprintf(&data[data_len], "%s{name=\"send2smf_node_report_req\"} %ld\n", stat_name,
        upc_pkt_status_read(UPC_PKT_NODE_REPORT_SEND2SMF));
    data_len += sprintf(&data[data_len], "%s{name=\"recv4smf_node_report_resp\"} %ld\n", stat_name,
        upc_pkt_status_read(UPC_PKT_NODE_REPORT_RECV4SMF));

    data_len += sprintf(&data[data_len], "%s{name=\"send2smf_pfd_mgmt_resp\"} %ld\n", stat_name,
        upc_pkt_status_read(UPC_PKT_PFD_MANAGEMENT_SEND2SMF));
    data_len += sprintf(&data[data_len], "%s{name=\"recv4smf_pfd_mgmt_req\"} %ld\n", stat_name,
        upc_pkt_status_read(UPC_PKT_PFD_MANAGEMENT_RECV4SMF));

    data_len += sprintf(&data[data_len], "%s{name=\"send2smf_heartbeat_resp\"} %ld\n",stat_name,
        upc_pkt_status_read(UPC_PKT_HEARTBEAT_RESP_SEND2SMF));
    data_len += sprintf(&data[data_len], "%s{name=\"recv4smf_heartbeat_req\"} %ld\n", stat_name,
        upc_pkt_status_read(UPC_PKT_HEARTBEAT_REQU_RECV4SMF));
    data_len += sprintf(&data[data_len], "%s{name=\"send2smf_heartbeat_req\"} %ld\n", stat_name,
        upc_pkt_status_read(UPC_PKT_HEARTBEAT_REQU_SEND2SMF));
    data_len += sprintf(&data[data_len], "%s{name=\"recv4smf_heartbeat_resp\"} %ld\n", stat_name,
        upc_pkt_status_read(UPC_PKT_HEARTBEAT_RESP_RECV4SMF));

    ulfius_set_string_body_response(response, 200, data);

    return U_CALLBACK_CONTINUE;
}

static int upc_update_status_init(uint32_t port)
{
    /* Initialize instance with the port number */
    if (ulfius_init_instance(&upc_restful_instance, port, NULL, NULL) != U_OK) {
        LOG(UPC, ERR, "Error ulfius_init_instance, abort\n");
        return -1;
    }

    /* Endpoint list declaration */
    ulfius_add_endpoint_by_val(&upc_restful_instance, "GET", "/status",
        NULL, 0, &upc_collect_status_data, NULL);

    /* Start the framework */
    if (ulfius_start_framework(&upc_restful_instance) == U_OK) {
        LOG(UPC, RUNNING, "Start framework on port %d\n", upc_restful_instance.port);

    } else {
        LOG(UPC, ERR, "Error starting framework\n");
        return -1;
    }

    return 0;
}
#endif

/**
 * Get qualified health threshold
 */
uint16_t upc_get_qualified_health_threshold(void)
{
    return SMU_PORT_WEIGHT;
}

/**
 * Gets the current health value
 */
uint16_t upc_get_health_value(void)
{
    upc_config_info *upc_conf = upc_get_config();
    uint16_t health_value = 0;

    /* Check DPDK port */
    health_value += ros_get_if_link_status(upc_conf->upc2smf_name) ? SMU_PORT_WEIGHT : 0;

    /**
     *  Check whether it is on the same server as LBU
     *  (you need to deploy to the same server as much as possible)
     */


    return health_value;
}

int32_t upc_init(struct pcf_file *conf)
{
    upc_config_info *upc_conf = upc_get_config();
    /* First add the memory used by ros_timer */
    int64_t total_mem = sizeof(struct ros_timer) * ROS_TIMER_EACH_CORE_MAX_NUM, ret = 0;

    /* Prepare */
    ret = Res_Init(80, 80, 16000*1024);
    if (ret != G_TRUE) {
        LOG(UPC, ERR, "Res_Init failed!");
        return -1;
    }

    /* Parse parameters */
    ret = upc_parse_cfg(conf);
    if (ret != 0) {
        LOG(UPC, ERR, "parse configure failed!");
        return -1;
    }

    /* Init compressor */
    ret = comp_init();
    if (ret < 0) {
        LOG(UPC, ERR, "comp_init init failed!");
        return -1;
    }
    total_mem += ret;
    LOG(UPC, ERR, "comp_init init success!");

    upc_conf->local_key = ros_rdtsc() ^ (uint64_t)upc_conf->ha_remote_ip[0];

    /* Setup smu2smu_s service */
    comm_msg_cmd_callback = upc_msg_proc;

    /* Init node */
    ret = upc_node_init(upc_conf->node_num);
    if (ret < 0) {
        LOG(UPC, ERR,
            "upc_node_init init %d nodes failed!", upc_conf->node_num);
        return -1;
    }
    total_mem += ret;
    LOG(UPC, ERR,
        "upc_node_init init %d nodes success!", upc_conf->node_num);

    /* Init SEID table */
    ret = upc_seid_table_init(upc_conf->session_num);
    if (ret < 0) {
        LOG(UPC, ERR,
            "upc_seid_table_init init %d entry failed!", upc_conf->session_num);
        return -1;
    }
    total_mem += ret;
    LOG(UPC, ERR,
        "upc_seid_table_init init %d entry success!", upc_conf->session_num);

    /* Init UEIP addresss pool */
    ret = upc_parse_ueip_pool(conf);
    if (0 > ret) {
        LOG(UPC, ERR, "Parse ueip address pool failed.\n");
        return -1;
    }
    total_mem += ret;

    /* Init TEID */
    ret = upc_teid_init(upc_conf->node_num, upc_conf->teid_num);
    if (0 > ret) {
        LOG(UPC, ERR, "Init teid failed.\n");
        return -1;
    }
    total_mem += ret;

    /* Init pfd temp data */
    ret = pfcp_pfd_table_init(upc_conf->pfd_number);
    if (0 > ret) {
        LOG(UPC, ERR, "Init pfd management table failed.\n");
        return -1;
    }
    total_mem += ret;

    /* Init backend management (Backend must be initialized before session) */
    ret = upc_backend_init(upc_conf);
    if (ret < 0) {
        LOG(UPC, ERR, "Backend init failed!");
        return -1;
    }
    total_mem += ret;

    /* Init session management */
    ret = session_init(upc_conf);
    if (ret < 0) {
        LOG(UPC, ERR, "session init failed!");
        return -1;
    }
    total_mem += ret;

    /* Init pfcp channel */
    upc_pfcp_channel = service_register_raw(upc_conf->cpus, upc_conf->core_num,
        upc_conf->upc2smf_name, upc_packet_entry, NULL, NULL);
    if (NULL == upc_pfcp_channel) {
        LOG(UPC, MUST, "Register raw channel ifname %s failed.", upc_conf->upc2smf_name);
        return -1;
    }

    /* Init HA */
#ifdef ENABLED_HA
    upc_register_high_availability_module(upc_ha_sync_backend,
                                          upc_ha_build_data_block,
                                          upc_ha_change_sync_block_status,
                                          upc_ha_msg_proc,
                                          upc_ha_init,
                                          upc_ha_deinit,
                                          upc_ha_ass);
#else
    upc_register_high_availability_module(NULL,
                                          NULL,
                                          NULL,
                                          NULL,
                                          NULL,
                                          NULL,
                                          NULL);
#endif
    if (upc_hk_ha_init) {
        ret = upc_hk_ha_init(upc_conf);
        if (ret < 0) {
            LOG(UPC, ERR, "High availability module init failed!");
            return -1;
        }
        total_mem += ret;
        LOG(UPC, RUNNING, "High availability module init success!");
    } else {
        upc_set_standby_alive(G_FALSE);
        upc_set_work_status(HA_STATUS_ACTIVE);
    }

#ifdef SUPPORT_REST_API
    if (0 > upc_update_status_init(upc_conf->restful_listen)) {
        LOG(UPC, ERR, "Update_status_init failed!");
        return -1;
    }
#endif

    LOG(UPC, MUST,
        "-------UPC init success(cost memory %ld M)-------\n", total_mem >> 20);

    return 0;
}

void upc_deinit(void)
{
    if (upc_hk_ha_deinit) {
        upc_hk_ha_deinit();
    }

    if (upc_pfcp_channel) {
        service_unregister_raw(upc_pfcp_channel);
    }
    upc_backend_deinit();

#ifdef SUPPORT_REST_API
    ulfius_stop_framework(&upc_restful_instance);
    ulfius_clean_instance(&upc_restful_instance);
#endif
}

int upc_stats_resource_info(struct cli_def *cli, int argc, char **argv)
{
    uint32_t equ_flag = 0, cnt = 0;
    upc_node_header *node_mng = upc_node_mng_get();
    upc_seid_table_header *seid_mng = upc_seid_get_table_head();
    struct ueip_pool_table *ueip_mng = ueip_pool_mgmt_get();
    struct ueip_addr_pool *ueip_sec_pool = NULL;
    struct upc_teid_mgmt *teid_mng = upc_teid_mgmt_get();
    pfcp_pfd_table_header *tmp_pfd_mgmt = pfcp_pfd_get_table_header_public();
    struct session_mgmt_cb *sess_mgmt = session_mgmt_head();
    struct pdr_table_head *pdr_mgmt = pdr_get_head();
    struct far_table_head *far_mgmt = far_get_head();
    struct qer_table_head *qer_mgmt = qer_get_head();
    struct urr_table_head *urr_mgmt = urr_get_head();
    struct bar_table_head *bar_mgmt = bar_get_head();
    struct mar_table_head *mar_mgmt = mar_get_head();
    pfd_table_header *pfd_mgmt = pfd_get_table_header_public();
    tuple_table_head *tuple_mgmt = tuple_head_get_public();
    sp_dns_cache_table *dns_mgmt = sdc_get_table_public();
    upc_backend_mgmt *be_mgmt = upc_get_backend_mgmt_public();
    upc_management_end_config *mb_mgmt = upc_mb_config_get_public();
    predefined_rules_table *predef_mgmt = predef_get_table_public();

    cli_print(cli,"                Maximum number        Use number        \n");

    /* node resource */
    cli_print(cli,"node:            %-8u             %-8u\n", node_mng->node_max, Res_GetAlloced(node_mng->res_no));

    /* seid resource */
    equ_flag = (Res_GetAlloced(seid_mng->pool_id) == ros_atomic32_read(&seid_mng->use_num));
    cli_print(cli,"seid:            %-8u             %-8u\n", seid_mng->max_num,
        equ_flag ? Res_GetAlloced(seid_mng->pool_id) : (uint32_t)-1);

    /* ueip resource */
    /*equ_flag = (Res_GetAlloced(ueip_mng->pool_id) == ros_atomic32_read(&ueip_mng->use_num));
    cli_print(cli,"ueip mng:        %-8u             %-8u\n", ueip_mng->ip_pool_num,
        equ_flag ? Res_GetAlloced(ueip_mng->pool_id) : (uint32_t)-1);*/
    cli_print(cli,"ueip mng:        %-8u             ALL\n", ueip_mng->ip_pool_num);
    for (cnt = 0; cnt < ueip_mng->ip_pool_num; ++cnt) {
        ueip_sec_pool = ueip_addr_pool_get(cnt);
        equ_flag = (Res_GetAlloced(ueip_sec_pool->pool_id) == ros_atomic32_read(&ueip_sec_pool->use_num));
        cli_print(cli,"ueip pool(%-3u):  null                 %-8u\n", cnt,
            equ_flag ? Res_GetAlloced(ueip_sec_pool->pool_id) : (uint32_t)-1);
    }

    /* teid resource */
    cli_print(cli,"teid:            %-8u             %-8u\n", teid_mng->teid_table[0].max_num * teid_mng->node_max_num,
        ros_atomic32_read(&teid_mng->teid_use_num));

    /* PFD resource */
    cli_print(cli,"pfd-req:         %-8u             %-8u\n", tmp_pfd_mgmt->max_num,
        Res_GetAlloced(tmp_pfd_mgmt->pool_id));

    /* session resource */
    equ_flag = (Res_GetAlloced(sess_mgmt->pool_id) == ros_atomic32_read(&sess_mgmt->use_num));
    cli_print(cli,"session:         %-8u             %-8u\n", sess_mgmt->max_num,
        equ_flag ? Res_GetAlloced(sess_mgmt->pool_id) : (uint32_t)-1);

    /* pdr resource */
    equ_flag = (Res_GetAlloced(pdr_mgmt->pool_id) == ros_atomic32_read(&pdr_mgmt->use_num));
    cli_print(cli,"pdr:             %-8u             %-8u\n", pdr_mgmt->max_num,
        equ_flag ? Res_GetAlloced(pdr_mgmt->pool_id) : (uint32_t)-1);

    /* far resource */
    equ_flag = (Res_GetAlloced(far_mgmt->pool_id) == ros_atomic32_read(&far_mgmt->use_num));
    cli_print(cli,"far:             %-8u             %-8u\n", far_mgmt->max_num,
        equ_flag ? Res_GetAlloced(far_mgmt->pool_id) : (uint32_t)-1);

    /* qer resource */
    equ_flag = (Res_GetAlloced(qer_mgmt->pool_id) == ros_atomic32_read(&qer_mgmt->use_num));
    cli_print(cli,"qer:             %-8u             %-8u\n", qer_mgmt->max_num,
        equ_flag ? Res_GetAlloced(qer_mgmt->pool_id) : (uint32_t)-1);

    /* urr resource */
    equ_flag = (Res_GetAlloced(urr_mgmt->pool_id) == ros_atomic32_read(&urr_mgmt->use_num));
    cli_print(cli,"urr:             %-8u             %-8u\n", urr_mgmt->max_num,
        equ_flag ? Res_GetAlloced(urr_mgmt->pool_id) : (uint32_t)-1);

    /* bar resource */
    equ_flag = (Res_GetAlloced(bar_mgmt->pool_id) == ros_atomic32_read(&bar_mgmt->use_num));
    cli_print(cli,"bar:             %-8u             %-8u\n", bar_mgmt->max_num,
        equ_flag ? Res_GetAlloced(bar_mgmt->pool_id) : (uint32_t)-1);

    /* mar resource */
    equ_flag = (Res_GetAlloced(mar_mgmt->pool_id) == ros_atomic32_read(&mar_mgmt->use_num));
    cli_print(cli,"mar:             %-8u             %-8u\n", mar_mgmt->max_num,
        equ_flag ? Res_GetAlloced(mar_mgmt->pool_id) : (uint32_t)-1);

    /* pfd management resource */
    cli_print(cli,"pfd:             %-8u             %-8u\n", pfd_mgmt->max_num,
        Res_GetAlloced(pfd_mgmt->pool_id));

    /* tuple table resource */
    cli_print(cli,"tuple:           %-8u             %-8u\n", tuple_mgmt->max_num,
        Res_GetAlloced(tuple_mgmt->pool_id));

    /* dns table resource */
    cli_print(cli,"dns:             %-8u             %-8u\n", dns_mgmt->max_num,
        Res_GetAlloced(dns_mgmt->pool_id));

    /* Predefined rules resource */
    cli_print(cli,"predef_pdr:      %-8u             %-8u\n", predef_mgmt->max_pdr_num,
        Res_GetAlloced(predef_mgmt->pdr_pool_id));
    cli_print(cli,"predef_far:      %-8u             %-8u\n", predef_mgmt->max_far_num,
        Res_GetAlloced(predef_mgmt->far_pool_id));
    cli_print(cli,"predef_qer:      %-8u             %-8u\n", predef_mgmt->max_qer_num,
        Res_GetAlloced(predef_mgmt->qer_pool_id));
    cli_print(cli,"predef_urr:      %-8u             %-8u\n", predef_mgmt->max_urr_num,
        Res_GetAlloced(predef_mgmt->urr_pool_id));

    /* backend resource */
    cli_print(cli,"backend:         %-8u             %-8u        Active: %u\n",
        COMM_MSG_BACKEND_NUMBER - COMM_MSG_BACKEND_START_INDEX,
        Res_GetAlloced(be_mgmt->pool_id), upc_backend_get_active_num());

    /* MB work state */
    cli_print(cli,"mb_state:        %s\n", ros_atomic32_read(&mb_mgmt->work_state) ? "Active" : "Not Active");

    /*if (argc > 0 && 0 == strncmp(argv[0], "ha-data", 7)) {
        upc_show_ha_data_status(cli);
    }*/

    return 0;
}

int upc_sig_trace_show(struct cli_def *cli, int argc, char **argv)
{
	cli_print(cli,"valid %d, sig_type %d, user_id %s | %s\n",
		user_sig_trace.valid ,user_sig_trace.type, user_sig_trace.imsi, user_sig_trace.msisdn);
	return 0;
}

int upc_set_sig_trace(struct cli_def *cli, char *sig_type,char *user_id)
{
	upc_seid_entry *seid_entry = NULL;
	upc_seid_table_header *seid_head = upc_seid_get_table_head();
	seid_entry = (upc_seid_entry *)rbtree_first(&seid_head->seid_root);

	if(!sig_type) {
		cli_print(cli,"Parameters sig_type error,(null)\n");
		return -1;
	}
	if(!user_id) {
		cli_print(cli,"Parameters user_id error,(null)\n");
		return -1;
	}

	if(strlen(user_id) > SESSION_MAX_BCD_BYTES * 2) {
		cli_print(cli,"Parameters user_id out of range\n");
		return -1;
	}

	if(strcmp(sig_type, "imsi") == 0) {
		memcpy(user_sig_trace.imsi, user_id, strlen(user_id));
		user_sig_trace.type = USER_SIGNALING_TRACE_IMSI;
	}
	else if(strcmp(sig_type, "msisdn") == 0) {
		memcpy(user_sig_trace.msisdn, user_id, strlen(user_id));
		user_sig_trace.type = USER_SIGNALING_TRACE_MSISDN;
	}
	else {
		cli_print(cli,"Parameters sig_type error, %s\n", sig_type);
		return -1;
	}

	user_sig_trace.valid = 1;

	while (NULL != seid_entry) {

		if (1 == seid_entry->sig_trace.user_id_present) {

			if (USER_SIGNALING_TRACE_IMSI == user_sig_trace.type) {

				if (0 == strcmp((char *)user_sig_trace.imsi, (char *)seid_entry->sig_trace.imsi)) {
					seid_entry->sig_trace.valid = 1;
					seid_entry->sig_trace.type = USER_SIGNALING_TRACE_IMSI;
					cli_print(cli,"find imsi %s\n", seid_entry->sig_trace.imsi);
					if (0 > upc_publish_sess_sig_trace(SESS_SESSION_SIGTRACE_SET,
		                seid_entry->index, seid_entry->session_config.cp_f_seid.seid, 1)) {
		                LOG(UPC, ERR, "Publish session rollback failed.");
		            }
					break;
				}
				else {
					seid_entry->sig_trace.valid = 0;
				}

			}
			else if (USER_SIGNALING_TRACE_MSISDN == user_sig_trace.type) {
				if (0 == strcmp((char *)user_sig_trace.msisdn, (char *)seid_entry->sig_trace.msisdn)) {
					seid_entry->sig_trace.valid = 1;
					seid_entry->sig_trace.type = USER_SIGNALING_TRACE_MSISDN;
					cli_print(cli,"find msisdn %s\n", seid_entry->sig_trace.msisdn);
					if (0 > upc_publish_sess_sig_trace(SESS_SESSION_SIGTRACE_SET,
		                seid_entry->index, seid_entry->session_config.cp_f_seid.seid, 1)) {
		                LOG(UPC, ERR, "Publish session rollback failed.");
		            }
					break;
				}
				else {
					seid_entry->sig_trace.valid = 0;
				}
			}
		}
		seid_entry = (upc_seid_entry *)rbtree_next(&seid_entry->node);
	}

	return 0;
}

int upc_off_sig_trace(struct cli_def *cli)
{
	upc_seid_entry *seid_entry = NULL;
	upc_seid_table_header *seid_head = upc_seid_get_table_head();
	seid_entry = (upc_seid_entry *)rbtree_first(&seid_head->seid_root);

	while (NULL != seid_entry) {

		if (1 == seid_entry->sig_trace.user_id_present) {

			if (1 == seid_entry->sig_trace.valid) {
				/*stop sig trace*/
				seid_entry->sig_trace.valid = 0;
				cli_print(cli,"off sig trace imsi: %s, msisdn: %s\n", seid_entry->sig_trace.imsi, seid_entry->sig_trace.msisdn);
				if (0 > upc_publish_sess_sig_trace(SESS_SESSION_SIGTRACE_SET,
	                seid_entry->index, seid_entry->session_config.cp_f_seid.seid, 0)) {
	                LOG(UPC, ERR, "Publish session sigtrace failed.");
	            }
				break;
			}

		}
		seid_entry = (upc_seid_entry *)rbtree_next(&seid_entry->node);
	}

	memset(&user_sig_trace, 0, sizeof(user_sig_trace));

	return 0;
}

int upc_show_working_status(struct cli_def *cli,int argc, char **argv)
{
    switch (upc_get_work_status()) {
        case HA_STATUS_ACTIVE:
            cli_print(cli,"Work status: Active\n");
            break;
        case HA_STATUS_STANDBY:
            cli_print(cli,"Work status: Standby\n");
            break;
        case HA_STATUS_SMOOTH2ACTIVE:
            cli_print(cli,"Work status: Smooth to active\n");
            break;
        case HA_STATUS_SMOOTH2STANDBY:
            cli_print(cli,"Work status: Smooth to standby\n");
            break;
        case HA_STATUS_INIT:
            cli_print(cli,"Work status: Init\n");
            break;
    }

    cli_print(cli,"Standby status: %s\n", upc_get_standby_alive() ? "On-line" : "Off-line");

    return 0;
}

int upc_ha_active_standby_switch(struct cli_def *cli, int argc, char **argv)
{
    if (upc_hk_ha_ass) {
        if (0 > upc_hk_ha_ass()) {
            cli_print(cli, "Active/Standby switch failed.\n");
            return -1;
        } else {
            cli_print(cli, "Active/Standby switch success.\n");
        }
    } else {
        cli_print(cli, "High availability is not supported.\n");
    }

    return 0;
}

static inline int upc_up_feature_to_num(uint64_t value)
{
    uint8_t cnt;

    if (value == 0) {
        return -1;
    }

    for (cnt = 0; value && cnt < 64; ++cnt) {
        if (1 == (value >> cnt)) {
            return cnt;
        }
    }

    return -1;
}

int upc_set_features(struct cli_def *cli, int argc, char **argv)
{
    uint64_t change_value = htonll(upc_get_up_features());
    uint32_t cnt, up_name_cnt;
    char up_name[][16] = {"BUCP", "DDND", "DLBD", "TRST", "FTUP", "PFDM", "HEEU", "TREU",
                          "EMPU", "PDIU", "UDBC", "QUOAC", "TRACE", "FRRT", "PFDE", "EPFAR",
                          "DPDRA", "ADPDP", "UEIP", "SSET", "MNOP", "MTE", "BUNDL", "GCOM",
                          "MPAS", "RTTL", "VTIME", "NORP", "IPTV", "IP6PL", "TSCU", "MPTCP",
                          "ATSSS-LL", "QFQM", "GPQM", "MT_EDT", "CIOT", "ETHAR", "DDDS", "RDS",
                          "RTTWP"};
    uint32_t up_name_num = sizeof(up_name)/sizeof(up_name[0]);
    char print_str[256];
    uint32_t print_str_len;
    if (argc == 1 && 0 == strcmp("help", argv[0]))
		goto help;

    if (argc < 2) {
        cli_print(cli, "Parameters too few.");
        goto help;
    }

    if (0 == strcmp("all", argv[1])) {
        if (0 == strcmp("enable", argv[0])) {
            session_up_features tmp_up = {.value = (uint64_t)-1};
            tmp_up.d.spare_6 = 0;
            tmp_up.d.spare_7 = 0;
            tmp_up.d.spare_8 = 0;

            upc_set_up_config(tmp_up.value);
        } else {
            upc_set_up_config(0UL);
        }
        cli_print(cli, "Finish.");

        return 0;
    }

    for (cnt = 1; cnt < argc; ++cnt) {
        for (up_name_cnt = 0; up_name_cnt < up_name_num; ++up_name_cnt) {
            if (0 == strcmp(up_name[up_name_cnt], argv[cnt])) {
                if (0 == strcmp("enable", argv[0])) {
                    change_value |= (uint64_t)1 << up_name_cnt;
                } else if (0 == strcmp("disable", argv[0]))  {
                    change_value &= ~((uint64_t)1 << up_name_cnt);
                } else {
                    cli_print(cli, "Unrecognized parameter <%s>", argv[0]);
                    goto help;
                }
                break;
            }
        }

        if (up_name_cnt >= up_name_num) {
	        cli_print(cli, "No such featrue %s", argv[cnt]);
        }
    }
    upc_set_up_config(ntohll(change_value));
    cli_print(cli, "Finish.");

    return 0;

help:
    cli_print(cli, "up_features configure <enable|disable> <feature|all> [feature] ...");
    cli_print(cli, "feature:");
    if (up_name_num > 8) {
    	uint32_t cnt_max = up_name_num & 0xFFFFFFF8;

        for (cnt = 0; cnt < cnt_max; cnt += 8) {
            cli_print(cli, "%s %s %s %s %s %s %s %s",
                up_name[cnt + 0], up_name[cnt + 1], up_name[cnt + 2], up_name[cnt + 3],
                up_name[cnt + 4], up_name[cnt + 5], up_name[cnt + 6], up_name[cnt + 7]);
        }
    }

    print_str_len = 0;
    for (cnt = up_name_num - (up_name_num % 8); cnt < up_name_num; ++cnt) {
        print_str_len += sprintf(&print_str[print_str_len], "%s ", up_name[cnt]);
    }
    cli_print(cli, "%s", print_str);
    cli_print(cli, "e.g.\n\tup_features enable UDBC DDND");

    return 0;
}

int upc_configure_nat(struct cli_def *cli, int argc, char **argv)
{
    if (argc < 1) {
        cli_print(cli, "Parameters too few.");
        goto help;
    }

    if (0 == strcmp("enable", argv[0])) {
        upc_set_nat_flag(G_TRUE);
    } else if (0 == strcmp("disable", argv[0])) {
        upc_set_nat_flag(G_FALSE);
    }

    cli_print(cli, "Set the NAT flag to %s successfully.", upc_get_nat_flag() ? "enable" : "disable");

    return 0;

help:
    cli_print(cli, "nat <enable|disable>");

    return 0;
}

int upc_configure_predefined_rules(struct cli_def *cli, int argc, char *argv[])
{
    char *filename;
    session_content_create sess = {{0}};

    if (argc < 2) {
        cli_print(cli, "Parameters too few...");
        goto help;
    }
    filename = argv[1];

    if (0 == strncmp("add", argv[0], 3)) {
        if (0 > psc_parse_predefined_rules(&sess, filename)) {
            cli_print(cli, "Parse pre-defined rules failed.\n");
        }

        if (0 > predef_rules_add(&sess)) {
            cli_print(cli, "Add pre-defined rules failed.\n");
        } else {
            cli_print(cli, "Add pre-defined rules success.\n");
        }
    } else if (0 == strncmp("del", argv[0], 3)) {
        if (0 > psc_parse_predefined_rules(&sess, filename)) {
            cli_print(cli, "Parse pre-defined rules failed.\n");
        }

        if (0 > predef_rules_del(&sess)) {
            cli_print(cli, "Delete pre-defined rules failed.\n");
        } else {
            cli_print(cli, "Delete pre-defined rules success.\n");
        }
    } else if (0 == strncmp("show", argv[0], 4)) {

    }

    return 0;

help:
    cli_print(cli, "predef <action> <filename|predefined name>");
    cli_print(cli, "action: add|del|show");
    cli_print(cli, "e.g.    test_predef add ./config/predef_5_pdr.json");
    cli_print(cli, "e.g.    test_predef del ./config/predef_5_pdr.json");
    cli_print(cli, "e.g.    test_predef show userdefined_1");

    return 0;
}

