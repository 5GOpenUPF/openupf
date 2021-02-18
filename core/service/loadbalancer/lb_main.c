/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include <rte_mbuf.h>
#include <rte_meter.h>

#include "dpdk.h"
#include "lb_backend_mgmt.h"
#ifdef ENABLED_HA
#include "lb_ha_mgmt.h"
#endif
#include "lb_neighbor.h"
#include "lb_main.h"


static uint32_t lb_net_local_ip[EN_PORT_BUTT];
static uint32_t lb_host_local_ip[EN_PORT_BUTT];
static uint8_t lb_net_local_ipv6[EN_PORT_BUTT][IPV6_ALEN];
static uint32_t lb_host_n6_ip_mask;
static uint8_t lb_host_n6_ipv6_mask[IPV6_ALEN];

uint16_t lb_c_vlan_id[EN_LB_PORT_BUTT], lb_s_vlan_id[EN_LB_PORT_BUTT];
uint16_t lb_c_vlan_type[EN_LB_PORT_BUTT], lb_s_vlan_type[EN_LB_PORT_BUTT];

/* Local port MAC address */
uint8_t lb_local_port_mac[EN_LB_PORT_BUTT][ETH_ALEN];
/* Peer port MAC address */
uint8_t lb_peer_port_mac[EN_LB_PORT_BUTT][ETH_ALEN];


/* Management end is working */
static uint8_t lb_mb_is_working = FALSE;
static uint64_t lb_mb_flag_key;
/* Master SMU port MAC address */
static uint8_t lb_smu_port_mac[ETH_ALEN];

static uint16_t lb_dpdk_port_num;

lb_system_config lb_system_cfg;

static ros_atomic16_t lb_work_status;    /* init | active | standby */
static ros_atomic16_t lb_standby_alive;  /* FALSE | TRUE */

LB_SYNC_BACKEND_TABLE           lb_hk_sync_be_table;
LB_UPDATE_DELAY_SYNC_HASH       lb_hk_delay_sync_hash;
LB_UPDATE_DELAY_SYNC_BACKEND    lb_hk_delay_sync_be;
LB_HA_MSG_PROC                  lb_hk_ha_msg_proc;
LB_HA_INIT                      lb_hk_ha_init;
LB_HA_DEINIT                    lb_hk_ha_deinit;
LB_HA_ASS                       lb_hk_ha_ass;


#if (defined(ENABLE_DPDK_DEBUG))
#define lb_free_pkt(buf) \
    do { \
        dpdk_mbuf_del_record(((struct rte_mbuf *)buf)->buf_addr, __LINE__); \
        dpdk_free_mbuf((struct rte_mbuf *)buf); \
    } while(0)
#else
#define lb_free_pkt(buf) dpdk_free_mbuf((struct rte_mbuf *)buf)
#endif


static inline void lb_register_high_availability_module(LB_SYNC_BACKEND_TABLE sync_be_table,
                                           LB_UPDATE_DELAY_SYNC_HASH update_delay_sync_hash,
                                           LB_UPDATE_DELAY_SYNC_BACKEND update_delay_sync_be,
                                           LB_HA_MSG_PROC ha_msg_proc,
                                           LB_HA_INIT ha_init,
                                           LB_HA_DEINIT ha_deinit,
                                           LB_HA_ASS ha_ass)
{
    lb_hk_sync_be_table     = sync_be_table;
    lb_hk_delay_sync_hash   = update_delay_sync_hash;
    lb_hk_delay_sync_be     = update_delay_sync_be;
    lb_hk_ha_msg_proc       = ha_msg_proc;
    lb_hk_ha_init           = ha_init;
    lb_hk_ha_deinit         = ha_deinit;
    lb_hk_ha_ass            = ha_ass;
}

void lb_mb_work_state_set(uint8_t vl)
{
    lb_mb_is_working = vl;
}

void lb_set_work_status(int16_t status)
{
    lb_system_config *system_cfg = lb_get_system_config();

    switch (status) {
        case LB_STATUS_SMOOTH2ACTIVE:
            if (0 > comm_msg_create_channel_server(lb_get_backend_mgmt_server(),
                system_cfg->be_mgmt_port, &system_cfg->cpus[0], 1)) {
                LOG(LB, ERR, "Create channel server failed.");
            }
            break;

        case LB_STATUS_ACTIVE:
            if (LB_STATUS_SMOOTH2ACTIVE != lb_get_work_status()) {
                if (0 > comm_msg_create_channel_server(lb_get_backend_mgmt_server(),
                    system_cfg->be_mgmt_port, &system_cfg->cpus[0], 1)) {
                    LOG(LB, ERR, "Create channel server failed.");
                }
            }
            break;

        case LB_STATUS_STANDBY:
            /* Disconnect backend management server */
            if (LB_STATUS_SMOOTH2STANDBY != lb_get_work_status()) {
                comm_msg_channel_server_shutdown(lb_get_backend_mgmt_server());
            }
            lb_mb_work_state_set(FALSE);
            break;

        case LB_STATUS_SMOOTH2STANDBY:
            comm_msg_channel_server_shutdown(lb_get_backend_mgmt_server());
            break;

        default:
            return;
    }

    ros_atomic16_set(&lb_work_status, status);
}

int16_t lb_get_work_status(void)
{
    return ros_atomic16_read(&lb_work_status);
}

void lb_set_standby_alive(int16_t status)
{
    ros_atomic16_set(&lb_standby_alive, status);
}

int16_t lb_get_standby_alive(void)
{
    return ros_atomic16_read(&lb_standby_alive);
}

static inline uint16_t lb_port_to_index(uint16_t port)
{
    /* The port value is converted to the DPDK port ID, port must less EN_PORT_BUTT */
    return lb_dpdk_port_num == (uint16_t)EN_LB_PORT_BUTT ? (uint16_t)port : 0;
}

static inline uint8_t lb_mb_work_state_get(void)
{
    return lb_mb_is_working;
}

inline uint8_t lb_mb_work_state_get_public(void)
{
    return lb_mb_work_state_get();
}

lb_system_config *lb_get_system_config(void)
{
    return &lb_system_cfg;
}

uint8_t *lb_get_local_port_mac(uint8_t port)
{
    return lb_local_port_mac[port];
}

uint8_t *lb_get_peer_port_mac(uint8_t port)
{
    return lb_peer_port_mac[port];
}

uint8_t *lb_get_nexthop_mac(void *dst_ip, uint8_t ip_ver)
{
    lb_system_config *sys_cfg = lb_get_system_config();
    lb_neighbor_comp_key key = {.v4_value = 0};

    /* Check gateway */
    switch (ip_ver) {
        case SESSION_IP_V4:
            {
                uint32_t dst_ipv4 = ntohl(*(uint32_t *)dst_ip);
                uint8_t prefix_diff;

                /* 先默认对外一个网口，必须连接到交换机 */
                prefix_diff = 32 - sys_cfg->upf_ip[EN_PORT_N3].ipv4_prefix;

                if (((uint64_t)dst_ipv4 >> prefix_diff) !=
                    ((uint64_t)sys_cfg->upf_ip[EN_PORT_N3].ipv4 >> prefix_diff)) {
                    LOG(LB, RUNNING, "N3 ip: 0x%08x, dest ip: 0x%08x, prefix: %d.",
                        sys_cfg->upf_ip[EN_PORT_N3].ipv4,
                        dst_ipv4, sys_cfg->upf_ip[EN_PORT_N3].ipv4_prefix);

                    key.v4_value = sys_cfg->nexthop_net_ip[EN_PORT_N3];
                } else {
                    key.v4_value = *(uint32_t *)dst_ip;
                }

            }
            break;

        case SESSION_IP_V6:
            {
                memcpy(&key.value, dst_ip, IPV6_ALEN);
            }
            break;
    }


    switch (ip_ver) {
        case SESSION_IP_V4:
            LOG(LB, PERIOD, "Find Destination IPv4: 0x%08x nexthop.", ntohl(key.v4_value));
            return lb_neighbor_cache_get_mac(&key);

        case SESSION_IP_V6:
            LOG(LB, PERIOD, "Find Destination IPv6: 0x%16lx 0x%16lx nexthop.",
                ntohll(key.d.key1), ntohll(key.d.key2));
            return lb_neighbor_cache_get_mac(&key);

        default:
            LOG(LB, ERR, "Unknown IP version: %d.", ip_ver);
            return NULL;
    }
}

static inline void lb_outer_add_vlan(void *m, uint8_t lb_port)
{
    if (lb_c_vlan_id[lb_port]) {
        pkt_buf_struct *mbuf = (pkt_buf_struct *)m;
        uint8_t *pkt = rte_pktmbuf_mtod(mbuf, uint8_t *);
        uint8_t ofs_len = VLAN_HLEN;
        uint8_t mac_addr[12];
        uint16_t *vlan_type = (uint16_t *)&pkt[8];
        union vlan_tci *vlan_value = (union vlan_tci *)&pkt[10];

        memcpy(mac_addr, pkt, sizeof(mac_addr));

        *vlan_type = lb_c_vlan_type[lb_port];
        vlan_value->s.vid = lb_c_vlan_id[lb_port];
        vlan_value->s.dei = 0;
        vlan_value->s.pri = 0;
        vlan_value->data = htons(vlan_value->data);

        if (lb_s_vlan_id[lb_port]) {
            vlan_type = (uint16_t *)&pkt[4];
            vlan_value = (union vlan_tci *)&pkt[6];

            ofs_len += VLAN_HLEN;

            *vlan_type = lb_s_vlan_type[lb_port];
            vlan_value->s.vid = lb_s_vlan_id[lb_port];
            vlan_value->s.dei = 0;
            vlan_value->s.pri = 0;
            vlan_value->data = htons(vlan_value->data);
        }

        mbuf->l2_len += ofs_len;

        memcpy(pkt - ofs_len, mac_addr, sizeof(mac_addr));

        pkt_buf_data_off(mbuf) -= ofs_len;
        pkt_buf_set_len(mbuf, pkt_buf_data_len(mbuf) + ofs_len);
    }
}

static inline void lb_mac_updating(struct rte_mbuf *m, struct rte_ether_addr *src_mac,
    struct rte_ether_addr *dest_mac)
{
	struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

	/* src addr */
    if (likely(src_mac))
        rte_ether_addr_copy(src_mac, &eth->s_addr);

	/* dest addr */
    if (likely(dest_mac))
        rte_ether_addr_copy(dest_mac, &eth->d_addr);
}

static inline void lb_fwd_to_external_network(void *m)
{
    LOG(LB, PERIOD, "Packet forward to external network.");
    lb_outer_add_vlan(m, EN_LB_PORT_EXT);

    dpdk_send_packet(m, lb_port_to_index(EN_LB_PORT_EXT), __FUNCTION__, __LINE__);
}

static inline void lb_fwd_to_internal_network(void *m)
{
    LOG(LB, PERIOD, "Packet forward to internal network(back-end).");
    if (likely(lb_mb_is_working)) {
        lb_outer_add_vlan(m, EN_LB_PORT_INT);

        dpdk_send_packet(m, lb_port_to_index(EN_LB_PORT_INT), __FUNCTION__, __LINE__);
    } else {
        lb_free_pkt(m);
    }
}

static inline void lb_fwd_to_smu(struct rte_mbuf *mbuf)
{
    LOG(LB, PERIOD, "Packet forward to smu, mac: %02x:%02x:%02x:%02x:%02x:%02x", lb_smu_port_mac[0],
        lb_smu_port_mac[1], lb_smu_port_mac[2], lb_smu_port_mac[3], lb_smu_port_mac[4], lb_smu_port_mac[5]);
    /* PFCP和GTP echo|EndMarker|ErrorIndication forward to smu */
    if (likely(lb_mb_is_working)) {
        lb_mac_updating(mbuf, (struct rte_ether_addr *)lb_local_port_mac[EN_LB_PORT_INT],
            (struct rte_ether_addr *)lb_smu_port_mac);
        lb_fwd_to_internal_network(mbuf);
    } else {
        lb_free_pkt(mbuf);
    }
}

/**
 * @param key
 *  IPv4 address IPv6 address or MAC info
 * @param br_mode
 *  Bearing mode COMM_MSG_FAST_IPV4 COMM_MSG_FAST_IPV6 or COMM_MSG_FAST_MAC
 * @return
 *  Hash key
 */
static inline uint32_t lb_clac_hash(void *key, uint8_t br_mode)
{
    uint32_t hash;

    switch (br_mode) {
        case COMM_MSG_FAST_IPV4:
            hash = *(uint32_t *)key;
            break;

        case COMM_MSG_FAST_IPV6:
            {
                uint32_t *key_u32 = (uint32_t *)key;

                hash = key_u32[0] ^ key_u32[1] ^ key_u32[2] ^ key_u32[3];
            }
            break;

        case COMM_MSG_FAST_MAC:
            hash = 0;
            break;

        default:
            hash = 0;
            break;
    }

    return hash;
}

static inline int lb_ipv6_net_segment_cmp(uint8_t *ip1, uint8_t *ip2, uint8_t *ip_mask)
{
    uint64_t *ip_1 = (uint64_t *)ip1;
    uint64_t *ip_2 = (uint64_t *)ip2;
    uint64_t *mask = (uint64_t *)ip_mask;

    if (((ip_1[0] & mask[0]) == (ip_2[0] & mask[0])) &&
        ((ip_1[1] & mask[1]) == (ip_2[1] & mask[1]))) {
        return 0;
    }

    return -1;
}

static inline int lb_arp_pkt_proc(struct filter_key *match_key, struct rte_mbuf *mbuf)
{
    struct pro_arp_hdr *arp_hdr = FlowGetARPHeader(match_key);

    if (arp_hdr && (1 == ntohs(arp_hdr->ar_hrd)) &&
        (ETH_PRO_IP == ntohs(arp_hdr->ar_pro))) {
        uint32_t arp_dstip = *(uint32_t *)arp_hdr->ar_tip;

        if (arp_dstip == lb_net_local_ip[EN_PORT_N3]) {
            /* N3 ARP */
            LOG(LB, RUNNING, "N3 ARP packet.");
        }
        else if (arp_dstip == lb_net_local_ip[EN_PORT_N6]) {
            /* N6 ARP */
            LOG(LB, RUNNING, "N6 ARP packet");
        }
        else if (arp_dstip == lb_net_local_ip[EN_PORT_N9]) {
            /* N6 ARP */
            LOG(LB, RUNNING, "N9 ARP packet");
        }
        else if (arp_dstip == lb_net_local_ip[EN_PORT_N4]) {
            /* N6 ARP */
            LOG(LB, RUNNING, "N4 ARP packet");
        }
        else {
            LOG(LB, PERIOD,  "Unknown ARP packet, sender: 0x%08x, target: 0x%08x.\r\n",
                ntohl(*(uint32_t *)arp_hdr->ar_sip), ntohl(arp_dstip));
            return -1;
        }

        /* 本地建立/更新 arp cache表 */
        lb_neighbor_recv_arp(*(uint32_t *)arp_hdr->ar_sip, arp_hdr->ar_sha, EN_LB_PORT_EXT);

        if (ntohs(arp_hdr->ar_op) == 1) {
            /* Reply ARP */
            memcpy(arp_hdr->ar_tha, arp_hdr->ar_sha, ETH_ALEN);
            memcpy(arp_hdr->ar_sha, lb_local_port_mac[EN_LB_PORT_EXT], ETH_ALEN);
            arp_hdr->ar_op  = htons(2);
            *(uint32_t *)arp_hdr->ar_tip = *(uint32_t *)arp_hdr->ar_sip;
            *(uint32_t *)arp_hdr->ar_sip = arp_dstip;

            lb_mac_updating(mbuf,
                (struct rte_ether_addr *)lb_local_port_mac[EN_LB_PORT_EXT],
                (struct rte_ether_addr *)arp_hdr->ar_tha);
        }

        LOG(LB, RUNNING, "Recv ARP packet, sender: 0x%08x, target: 0x%08x.\r\n",
            ntohl(*(uint32_t *)arp_hdr->ar_sip), ntohl(arp_dstip));
    } else {
        LOG(LB, DEBUG, "Unknown packet, ready drop it.");
        return -1;
    }

    return 0;
}

/**
 * @param hash
 *  Hash point
 * @param match_key
 *  filter key
 * @return
 *  0:T-PDU packet  1:Echo|EndMarker|ErrorIndication  -1:Error
 */
static inline int lb_gtpu_pkt_proc(uint32_t *hash, struct filter_key *match_key)
{
    struct pro_ipv4_hdr *ipv4;
    struct pro_ipv6_hdr *ipv6;
    struct pro_gtp_hdr *gtp_hdr = FlowGetGtpuHeader(match_key);
    if (unlikely(NULL == gtp_hdr)) {
        LOG(LB, DEBUG, "Discard N3/N9/N4 non gtpu packets.\n");
        return -1;
    }

    switch (gtp_hdr->msg_type) {
        case MSG_TYPE_T_ECHO_REQ:
        case MSG_TYPE_T_ECHO_RESP:
        case MSG_TYPE_T_ERR_INDI:
        case MSG_TYPE_T_END_MARKER:
            /* Forward to smu */
            return 1;

        case MSG_TYPE_T_PDU:
            switch (FlowGetL2IpVersion(match_key)) {
                case 4:
                    ipv4 = FlowGetL2Ipv4Header(match_key);
                    *hash = lb_clac_hash(&ipv4->source, COMM_MSG_FAST_IPV4);
                    break;

                case 6:
                    ipv6 = FlowGetL2Ipv6Header(match_key);
                    *hash = lb_clac_hash(ipv6->saddr, COMM_MSG_FAST_IPV6);
                    break;

                default:
                    /* Maybe Ethernet or Non-IP bearer */
                    LOG(LB, PERIOD, "Unsupported packet, unable to get inner header!\r\n");
                    return -1;

            }
            break;

        default:
            LOG(LB, PERIOD, "Unsupported packet, Unknown msg-type: %d", gtp_hdr->msg_type);
            return -1;
    }

    return 0;
}

void lb_reply_icmp_echo_request(uint8_t port, struct rte_mbuf *mbuf)
{
    struct pro_eth_hdr *eth = NULL;
    struct pro_ipv4_hdr *ip_hdr = NULL;
    struct pro_icmp_hdr *icmp_hdr = NULL;
    uint32_t cksum;
	uint32_t tmp_ip;

    eth = rte_pktmbuf_mtod(mbuf, struct pro_eth_hdr *);
	memcpy(eth->dest, eth->source, ETH_ALEN);
	memcpy(eth->source, lb_local_port_mac[EN_LB_PORT_EXT], ETH_ALEN);

	ip_hdr = (struct pro_ipv4_hdr *)(eth + 1);
	tmp_ip = ip_hdr->dest;
	ip_hdr->dest = ip_hdr->source;
	ip_hdr->source = tmp_ip;
	ip_hdr->check = 0;

	icmp_hdr = (struct pro_icmp_hdr *)(ip_hdr + 1);
	icmp_hdr->type = ICMP_ECHO_REPLY;
	icmp_hdr->cksum = 0;

	ip_hdr->check = calc_crc_ip(ip_hdr);
	cksum = ~icmp_hdr->cksum & 0xffff;
	cksum += ~htons(ICMP_ECHO_REQUEST << 8) & 0xffff;
	cksum += htons(ICMP_ECHO_REPLY << 8);
	cksum = (cksum & 0xffff) + (cksum >> 16);
	cksum = (cksum & 0xffff) + (cksum >> 16);
	icmp_hdr->cksum = ~cksum;

    lb_fwd_to_external_network(mbuf);
}

static void lb_internal_pkt_entry(char *buf, int len, struct rte_mbuf *mbuf)
{
    struct packet_desc  desc = {.buf = buf, .len = len, .offset = 0};
    struct filter_key   match_key;
    uint8_t             *dest_mac;

    /* Discard broadcast packets */
    if (0xFFFFFFFF == *(uint32_t *)buf) {
        LOG(LB, PERIOD, "Discard broadcast packets.");
        lb_free_pkt(mbuf);
        return;
    }

    if (likely(LB_FORWARD_THRESHOLD < lb_get_work_status())) {
    /* Forward to backend */
        /* Dissecting packet */
        if (unlikely(packet_dissect(&desc, &match_key) < 0)) {
            LOG(LB, PERIOD, "Packet dissect failed!");
            lb_free_pkt(mbuf);

            return;
        }

        LOG(LB, RUNNING, "Recv internal packet");

        switch (FlowGetL1IpVersion(&match_key)) {
            case 4:
                {
                    struct pro_ipv4_hdr *ipv4 = FlowGetL1Ipv4Header(&match_key);

                    dest_mac = lb_get_nexthop_mac(&ipv4->dest, SESSION_IP_V4);
                    if (unlikely(NULL == dest_mac)) {
                        /* No backend available */
                        lb_free_pkt(mbuf);
                        LOG(LB, RUNNING, "Destination 0x%08x Host Unreachable, drop packet.",
                            ntohl(ipv4->dest));
                        return;
                    }
                    lb_mac_updating(mbuf, (struct rte_ether_addr *)lb_local_port_mac[EN_LB_PORT_EXT],
                        (struct rte_ether_addr *)dest_mac);
                }
                break;

            case 6:
                {
                    struct pro_ipv6_hdr *ipv6 = FlowGetL1Ipv6Header(&match_key);

                    dest_mac = lb_get_nexthop_mac(ipv6->daddr, SESSION_IP_V6);
                    if (unlikely(NULL == dest_mac)) {
                        /* No backend available */
                        lb_free_pkt(mbuf);
                        LOG(LB, RUNNING, "Destination %016lx %016lx Host Unreachable, drop packet.",
                            ntohll(*(uint64_t *)ipv6->daddr), ntohll(*(uint64_t *)(ipv6->daddr + 8)));
                        return;
                    }
                    lb_mac_updating(mbuf, (struct rte_ether_addr *)lb_local_port_mac[EN_LB_PORT_EXT],
                        (struct rte_ether_addr *)dest_mac);
                }
                break;

            default:
                /* Maybe Ethernet 802.3 */
                lb_free_pkt(mbuf);

                /* Otherwise, forward it directly */
                //break;
                return;

        }

        /* Send from port EN_LB_PORT_EXT */
        lb_fwd_to_external_network(mbuf);

    } else {
    /* Forward to LB */

        LOG(LB, PERIOD, "Standby recv buf %p, len %d, forward to actived LB.", buf, len);

        /* Send from port EN_LB_PORT_INT */
        lb_mac_updating(mbuf, (struct rte_ether_addr *)lb_local_port_mac[EN_LB_PORT_INT],
            (struct rte_ether_addr *)lb_peer_port_mac[EN_LB_PORT_INT]);
        lb_fwd_to_internal_network(mbuf);
    }

    return;
}

static inline void lb_external_pkt_entry(char *buf, int len, struct rte_mbuf *mbuf)
{
    struct packet_desc  desc = {.buf = buf, .len = len, .offset = 0};
    uint32_t            hash = 0;
    struct filter_key   match_key;
    uint8_t             *dest_mac;

    if (likely(LB_FORWARD_THRESHOLD < lb_get_work_status())) {
    /* Forward to internet/backend */
        /* Dissecting packet */
        if (unlikely(packet_dissect(&desc, &match_key) < 0)) {
            LOG(LB, DEBUG, "Packet dissect failed!");
            lb_free_pkt(mbuf);

            return;
        }

        /* Distinguish between Ethernet II and 802.3 */
        if (likely(0 == FLOW_MASK_FIELD_ISSET(match_key.field_offset, FLOW_FIELD_ETHERNET_DL))) {
            /* Ethernet II should be >= 1536(0x0600) */

            LOG(LB, DEBUG, "Recv Ethernet II packet");

            /* 目的IP地址是UPF才去转发 */
            switch (FlowGetL1IpVersion(&match_key)) {
                case 4:
                    {
                        struct pro_ipv4_hdr *ipv4 = FlowGetL1Ipv4Header(&match_key);
                        uint32_t dest_ip = ipv4->dest;

                        LOG(LB, DEBUG, "Packet is IPv4, IP: 0x%08x", ntohl(dest_ip));
                        if (!(dest_ip ^ lb_net_local_ip[EN_PORT_N3])) {
                            /* N3 packets */
                            LOG(LB, DEBUG, "Packets sent to N3.");
                            switch (lb_gtpu_pkt_proc(&hash, &match_key)) {
                                case 0:
                                    break;

                                case 1:
                                    /* Forward to smu */
                                    lb_fwd_to_smu(mbuf);
                                    return;

                                case -1:
                                default:
                                    lb_free_pkt(mbuf);
                                    return;
                            }
                        } else if ((ntohl(dest_ip) & lb_host_n6_ip_mask) ==
                            (lb_host_local_ip[EN_PORT_N6] & lb_host_n6_ip_mask)) {
                            /* N6 packets */
                            LOG(LB, DEBUG, "Packets sent to N6.");

                            hash = lb_clac_hash(&dest_ip, COMM_MSG_FAST_IPV4);
                        } else if (!(dest_ip ^ lb_net_local_ip[EN_PORT_N9])) {
                            /* N9 packets */
                            LOG(LB, DEBUG, "Packets sent to N9.");
                            switch (lb_gtpu_pkt_proc(&hash, &match_key)) {
                                case 0:
                                    break;

                                case 1:
                                    /* Forward to smu */
                                    lb_fwd_to_smu(mbuf);
                                    return;

                                case -1:
                                default:
                                    lb_free_pkt(mbuf);
                                    return;
                            }
                        } else if (!(dest_ip ^ lb_net_local_ip[EN_PORT_N4])) {
                            /* N4 packets */
                            LOG(LB, DEBUG, "Packets sent to N4.");
                            struct pro_udp_hdr *udp_hdr = FlowGetL1UdpHeader(&match_key);
                            if (udp_hdr && (FLOW_PFCP_PORT == udp_hdr->dest || FLOW_PFCP_PORT == udp_hdr->source)) {
                                /* Forward to smu */
                                lb_fwd_to_smu(mbuf);
                                return;
                            }
                            /* Forward to backend */
                            switch (lb_gtpu_pkt_proc(&hash, &match_key)) {
                                case 0:
                                    break;

                                case 1:
                                    /* Forward to smu */
                                    lb_fwd_to_smu(mbuf);
                                    return;

                                case -1:
                                default:
                                    lb_free_pkt(mbuf);
                                    return;
                            }
                        } else {
                            LOG(LB, DEBUG, "Packets with non local destination address are not processed.\n");
                            lb_free_pkt(mbuf);
                            return;
                        }
                    }
                    break;

                case 6:
                    {
                        struct pro_ipv6_hdr *ipv6 = FlowGetL1Ipv6Header(&match_key);
                        uint8_t *dest_ipv6 = ipv6->daddr;

                        LOG(LB, DEBUG, "Packet is IPv6, IP: %02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                            "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                            dest_ipv6[0], dest_ipv6[1], dest_ipv6[2], dest_ipv6[3], dest_ipv6[4],
                            dest_ipv6[5], dest_ipv6[6], dest_ipv6[7], dest_ipv6[8], dest_ipv6[9],
                            dest_ipv6[10], dest_ipv6[11], dest_ipv6[12], dest_ipv6[13], dest_ipv6[14],
                            dest_ipv6[15]);
                        if (0 == memcmp(dest_ipv6, lb_net_local_ipv6[EN_PORT_N3], IPV6_ALEN)) {
                            /* N3 packets */
                            LOG(LB, PERIOD, "Packets sent to N3.");
                            switch (lb_gtpu_pkt_proc(&hash, &match_key)) {
                                case 0:
                                    break;

                                case 1:
                                    /* Forward to smu */
                                    lb_fwd_to_smu(mbuf);
                                    return;

                                case -1:
                                default:
                                    lb_free_pkt(mbuf);
                                    return;
                            }
                        } else if (0 == lb_ipv6_net_segment_cmp(dest_ipv6, lb_net_local_ipv6[EN_PORT_N6],
                            lb_host_n6_ipv6_mask)) {
                            /* N6 packets */
                            LOG(LB, DEBUG, "Packets sent to N6.");

                            hash = lb_clac_hash(dest_ipv6, COMM_MSG_FAST_IPV6);
                        } else if (0 == memcmp(dest_ipv6, lb_net_local_ipv6[EN_PORT_N9], IPV6_ALEN)) {
                            /* N9 packets */
                            LOG(LB, DEBUG, "Packets sent to N9.");
                            switch (lb_gtpu_pkt_proc(&hash, &match_key)) {
                                case 0:
                                    break;

                                case 1:
                                    /* Forward to smu */
                                    lb_fwd_to_smu(mbuf);
                                    return;

                                case -1:
                                default:
                                    lb_free_pkt(mbuf);
                                    return;
                            }
                        } else if (0 == memcmp(dest_ipv6, lb_net_local_ipv6[EN_PORT_N4], IPV6_ALEN)) {
                            /* N4 packets */
                            LOG(LB, DEBUG, "Packets sent to N4.");
                            struct pro_udp_hdr *udp_hdr = FlowGetL1UdpHeader(&match_key);
                            if (udp_hdr && (FLOW_PFCP_PORT == udp_hdr->dest || FLOW_PFCP_PORT == udp_hdr->source)) {
                                /* Forward to smu */
                                lb_fwd_to_smu(mbuf);
                                return;
                            }
                            /* Forward to backend */
                            switch (lb_gtpu_pkt_proc(&hash, &match_key)) {
                                case 0:
                                    break;

                                case 1:
                                    /* Forward to smu */
                                    lb_fwd_to_smu(mbuf);
                                    return;

                                case -1:
                                default:
                                    lb_free_pkt(mbuf);
                                    return;
                            }
                        } else {
                            LOG(LB, DEBUG, "Packets with non local destination address are not processed.\n");
                            lb_free_pkt(mbuf);
                            return;
                        }
                    }
                    break;

                default:
                    /* Maybe ARP */
                    if (0 == lb_arp_pkt_proc(&match_key, mbuf)) {
                        lb_fwd_to_external_network(mbuf);
                    } else {
                        /* Maybe Ethernet 802.3 or Non-IP packet */
                        lb_free_pkt(mbuf);
                    }
                    return;

            }
        }
        else {
            /* 802.3 should be <= 1500 */
            LOG(LB, DEBUG, "Recv IEEE 802.3 packet");
            lb_free_pkt(mbuf);

            return;
        }

        /* Send from port EN_LB_PORT_INT */
        dest_mac = lb_match_backend(hash);
        if (unlikely(NULL == dest_mac)) {
            /* No backend available */
            lb_free_pkt(mbuf);
            LOG(LB, ERR, "No ready backend found, drop packet.");
            return;
        }
        lb_mac_updating(mbuf, (struct rte_ether_addr *)lb_local_port_mac[EN_LB_PORT_INT],
            (struct rte_ether_addr *)dest_mac);
        lb_fwd_to_internal_network(mbuf);

    } else {
    /* Forward to LB */

        LOG(LB, DEBUG, "Standby recv buf %p, len %d, forward to active LB.", buf, len);

        /* Send from port EN_LB_PORT_INT */
        lb_mac_updating(mbuf, (struct rte_ether_addr *)lb_local_port_mac[EN_LB_PORT_EXT],
            (struct rte_ether_addr *)lb_peer_port_mac[EN_LB_PORT_EXT]);
        lb_fwd_to_external_network(mbuf);
    }

    return;
}

int lb_data_pkt_entry(char *buf, int len, uint16_t port_id, void *arg)
{
#if (defined(ENABLE_DPDK_DEBUG))
    dpdk_mbuf_record(((struct rte_mbuf *)arg)->buf_addr, __LINE__);

    if (unlikely(0 == len)) {
        LOG(LB, ERR, "ERROR: buf(%p), len: %d, arg(%p), core_id: %u", buf, len, arg, rte_lcore_id());
        dpdk_dump_packet(buf, 64);
        lb_free_pkt((struct rte_mbuf *)arg);
        return -1;
    }
#endif

    switch (port_id) {
        case EN_LB_PORT_EXT:
            /* Send from port EN_LB_PORT_INT */
            LOG(LB, RUNNING, "Recv external packet");
            lb_external_pkt_entry(buf, len, (struct rte_mbuf *)arg);
            break;

        case EN_LB_PORT_INT:
            LOG(LB, RUNNING, "Recv internal packet");
            lb_internal_pkt_entry(buf, len, (struct rte_mbuf *)arg);
            break;

        default:
            lb_free_pkt((struct rte_mbuf *)arg);
            LOG(LB, ERR, "recv buf %p, len %d, But port ID is not supported!", buf, len);
            return -1;
    }
    LOG(LB, RUNNING, "handle packet(buf %p, len %d) finished!\r\n", buf, len);

    return 0;
}

comm_msg_header_t *lb_fill_msg_header(uint8_t *buf)
{
    comm_msg_header_t *msg_hdr = (comm_msg_header_t *)buf;

    msg_hdr->magic_word    = htonl(COMM_MSG_MAGIC_WORD);
    msg_hdr->comm_id       = 0;
    msg_hdr->major_version = COMM_MSG_MAJOR_VERSION;
    msg_hdr->minor_version = COMM_MSG_MINOR_VERSION;
    msg_hdr->total_len     = COMM_MSG_HEADER_LEN;

    return msg_hdr;
}

static uint32_t lb_control_msg_proc(void *token, comm_msg_ie_t *ie)
{
    uint32_t ret = EN_COMM_ERRNO_OK;
    int fd = (uint64_t)token;

    switch(ie->cmd)
    {
        case EN_COMM_MSG_LB_HA_HB:
        case EN_COMM_MSG_LB_HA_SYNC_HASH:
        case EN_COMM_MSG_LB_HA_SYNC_BE:
        case EN_COMM_MSG_LB_HA_SYNC_REQ:
        case EN_COMM_MSG_LB_HA_GET_STAT_REQ:
        case EN_COMM_MSG_LB_HA_GET_STAT_RESP:
        case EN_COMM_MSG_LB_HA_ASS_REQ:
        case EN_COMM_MSG_LB_HA_ASS_RESP:
            if (lb_hk_ha_msg_proc) {
                ret = lb_hk_ha_msg_proc(token, ie);
            }
            break;

        case EN_COMM_MSG_MB_HB:
            {
                comm_msg_heartbeat_config *hb_cfg = (comm_msg_heartbeat_config *)ie->data;
                int fd = (uint64_t)token;

                lb_mb_work_state_set(TRUE);
                if (lb_mb_flag_key != hb_cfg->key) {
                    lb_mb_flag_key = hb_cfg->key;
                    /* Reset SMU target MAC info */
                    memcpy(lb_smu_port_mac, hb_cfg->mac[EN_PORT_N4], ETH_ALEN);
                    lb_ha_tell_backend_change_active_mac(TRUE);
                }

                lb_reset_mb_heartbeat_count();
                lb_backend_heartbeat_reply(fd);

            }
            break;

        case EN_COMM_MSG_MB_REGISTER:
            {
                comm_msg_rules_ie_t *rule_ie = (comm_msg_rules_ie_t *)ie;
                comm_msg_heartbeat_config *reg_cfg = (comm_msg_heartbeat_config *)ie->data;
                lb_backend_config *be_cfg;
                uint32_t cnt;

                LOG(LB, MUST, "Backend register request received");

                for (cnt = 0; cnt < rule_ie->rules_num; ++cnt) {
                    /* Default use one port */
                    be_cfg = lb_backend_register(&reg_cfg[cnt]);
                    if (NULL == be_cfg) {
                        LOG(LB, ERR, "Register backend failed, N3 mac: %02x:%02x:%02x:%02x:%02x:%02x.",
                            reg_cfg->mac[EN_PORT_N3][0], reg_cfg->mac[EN_PORT_N3][1], reg_cfg->mac[EN_PORT_N3][2],
                            reg_cfg->mac[EN_PORT_N3][3], reg_cfg->mac[EN_PORT_N3][4], reg_cfg->mac[EN_PORT_N3][5]);
                    } else {
                        LOG(LB, ERR, "Register backend success, N3 mac: %02x:%02x:%02x:%02x:%02x:%02x, index: %d.",
                            reg_cfg->mac[EN_PORT_N3][0], reg_cfg->mac[EN_PORT_N3][1], reg_cfg->mac[EN_PORT_N3][2],
                            reg_cfg->mac[EN_PORT_N3][3], reg_cfg->mac[EN_PORT_N3][4], reg_cfg->mac[EN_PORT_N3][5],
                            be_cfg->index);
                    }
                }
            }
            break;

        case EN_COMM_MSG_MB_UNREGISTER:
            {
                comm_msg_rules_ie_t *rule_ie = (comm_msg_rules_ie_t *)ie;
                comm_msg_heartbeat_config *reg_cfg = (comm_msg_heartbeat_config *)ie->data;
                lb_backend_config *be_cfg;
                uint32_t cnt;

                LOG(LB, MUST, "Backend unregister request received");

                for (cnt = 0; cnt < rule_ie->rules_num; ++cnt) {
                    /* Default use one port */
                    be_cfg = lb_backend_search(reg_cfg[cnt].key);
                    if (NULL == be_cfg) {
                        LOG(LB, ERR, "Unregister backend failed, no such backend %lu.", reg_cfg[cnt].key);
                    } else {
                        lb_backend_unregister((uint8_t)be_cfg->index);
                    }
                }
            }
            break;

        case EN_COMM_MSG_BACKEND_VALIDITY:
            LOG(LB, RUNNING, "Backend get validity request received");

            lb_backend_validity(fd);
            break;

        default:
            LOG(LB, ERR, "Unknown ie cmd 0x%04x.", ie->cmd);
            break;
    }
    LOG(LB, DEBUG, "msg (%x) process finished, return value 0x%x.\r\n",
        ie->cmd, ret);

    return ret;
}

static int lb_parse_cfg(struct pcf_file *conf)
{
    lb_system_config *system_cfg = lb_get_system_config();
    int index = 0, cnt;

    struct kv_pair key_pair[] = {
        { "ha_port", NULL },
        { "ha_ip", NULL },
        { "be_mgmt_port", NULL },
        { "default_master", NULL },
        { "N3_IPv4", NULL },
        { "N3_IPv6", NULL },
        { "N3_IPv4_gateway", NULL },
        { "N6_IPv4", NULL },
        { "N6_IPv6", NULL },
        { "N6_IPv4_gateway", NULL },
        { "N9_IPv4", NULL },
        { "N9_IPv6", NULL },
        { "N9_IPv4_gateway", NULL },
        { "N4_IPv4", NULL },
        { "N4_IPv6", NULL },
        { "N4_IPv4_gateway", NULL },
        { NULL, NULL, }
    };

    while (key_pair[index].key != NULL) {
        key_pair[index].val = pcf_get_key_value(conf,
                     SECTION_SRV_NAME, key_pair[index].key);
        if (!key_pair[index].val) {
            printf("Can't get key[%s] in section[%s].\n",
                key_pair[index].key, SECTION_SRV_NAME);
            return -1;
        }
        ++index;
    }
    index = 0;

    /* ha_port */
    if (strlen(key_pair[index].val) > 0) {
        system_cfg->ha_local_port = atoi(key_pair[index].val);
        system_cfg->ha_remote_port = system_cfg->ha_local_port;
        ++index;
    } else {
        LOG(LB, ERR, "Invalid %s:%s config.\n", key_pair[index].key,
            key_pair[index].val);
        return -1;
    }

    /* ha_ip */
    system_cfg->ha_remote_ip_num = 0;
    if (strlen(key_pair[index].val) > 0) {
        char *valid_ip = key_pair[index].val, *token = NULL, print_str[512];
        uint16_t print_len = 0;

        for (token = strsep(&valid_ip, "|"); token != NULL; token = strsep(&valid_ip, "|")) {
            if (*token == 0) {
                continue;
            }

            system_cfg->ha_remote_ip[system_cfg->ha_remote_ip_num++]= htonl(inet_addr(token));
            print_len += sprintf(&print_str[print_len], "%s ", token);
        }

        LOG(LB, MUST, "Set H-A IP number: %d, IP: %s.", system_cfg->ha_remote_ip_num, print_str);
    } else {
        LOG(LB, MUST, "Set H-A IP number: %d.", system_cfg->ha_remote_ip_num);
    }
    ++index;

    /* be_mgmt_port */
    if (strlen(key_pair[index].val) > 0) {
        system_cfg->be_mgmt_port = atoi(key_pair[index].val);
        ++index;
    } else {
        LOG(LB, ERR, "Invalid %s:%s config.\n", key_pair[index].key,
            key_pair[index].val);
        return -1;
    }

    /* default_master */
    if (strlen(key_pair[index].val) > 0) {
        system_cfg->default_master = atoi(key_pair[index].val);
        ++index;
    } else {
        LOG(LB, ERR, "Invalid %s:%s config.\n", key_pair[index].key,
            key_pair[index].val);
        return -1;
    }

    /* N3 IPv4 IPv6 gateway */
    for (cnt = EN_PORT_N3; cnt < EN_PORT_BUTT; ++cnt) {
        if (strlen(key_pair[index].val) > 0) {
            if (0 > comm_msg_parse_ip_addr(&system_cfg->upf_ip[cnt], key_pair[index].val)) {
                LOG(LB, ERR, "Parse ip address failed.\n");
                return -1;
            }
            ++index;
        } else {
            LOG(LB, ERR, "Invalid %s:%s config.\n", key_pair[index].key,
                key_pair[index].val);
            return -1;
        }

        if (strlen(key_pair[index].val) > 0) {
            if (0 > comm_msg_parse_ip_addr(&system_cfg->upf_ip[cnt], key_pair[index].val)) {
                LOG(LB, ERR, "Parse ip address failed.\n");
                return -1;
            }
            ++index;
        } else {
            LOG(LB, ERR, "Invalid %s:%s config.\n", key_pair[index].key,
                key_pair[index].val);
            return -1;
        }

        if (strlen(key_pair[index].val) > 0) {
            if (1 != inet_pton(AF_INET, key_pair[index].val, &system_cfg->nexthop_net_ip[cnt])) {
                LOG(LB, ERR, "inet_ntop failed, error: %s.", strerror(errno));
                return -1;
            }
            ++index;
        } else {
            LOG(LB, ERR, "Invalid %s:%s config.\n", key_pair[index].key,
                key_pair[index].val);
            return -1;
        }

        /* Copy to local */
        lb_net_local_ip[cnt] = htonl(system_cfg->upf_ip[cnt].ipv4);
        lb_host_local_ip[cnt] = system_cfg->upf_ip[cnt].ipv4;
        memcpy(lb_net_local_ipv6[cnt], system_cfg->upf_ip[cnt].ipv6, IPV6_ALEN);
    }
    lb_host_n6_ip_mask = num_to_mask(system_cfg->upf_ip[EN_PORT_N6].ipv4_prefix);
    ipv6_prefix_to_mask(lb_host_n6_ipv6_mask, system_cfg->upf_ip[EN_PORT_N6].ipv6_prefix);

    LOG(LB, MUST, "H-A local port: %hu, H-A remote port: %hu, backend management port: %hu, default master: %s.",
        system_cfg->ha_local_port, system_cfg->ha_remote_port, system_cfg->be_mgmt_port,
        system_cfg->default_master ? "TRUE":"FALSE");

    return 0;
}

int32_t lb_init_prepare(struct pcf_file *conf)
{
    int ret;
    uint32_t cnt;
    lb_system_config *system_cfg = lb_get_system_config();

    /* Parse parameters */
    ret = lb_parse_cfg(conf);
    if (ret != 0) {
        LOG(LB, ERR, "parse configure failed!");
        return -1;
    }

    /* Init DPDK */
    ret = dpdk_init(conf, lb_data_pkt_entry, NULL);
    if (ret != 0) {
        LOG(LB, ERR, "dpdk_init failed!");
        return -1;
    }

    lb_dpdk_port_num = (uint16_t)rte_eth_dev_count_avail();

    /* Set cpus */
    system_cfg->core_num = dpdk_get_core_num();
    memcpy(system_cfg->cpus, dpdk_get_cpus(), system_cfg->core_num);

    /* Updating local MAC address table */
    for (cnt = EN_LB_PORT_EXT; cnt < EN_LB_PORT_BUTT; ++cnt) {
        memcpy(lb_local_port_mac[cnt], dpdk_get_mac(cnt), ETH_ALEN);
    }

    LOG(LB, MUST, "------Load-balancer init prepare finish------\n");

    return 0;
}

int32_t lb_init(void)
{
    lb_system_config *system_cfg = lb_get_system_config();

    if (G_TRUE != Res_Init(16, 16, 2048*1024)) {
        LOG(LB, ERR, "Res_Init failed!");
        return -1;
    }

    /* Set callback function */
    comm_msg_cmd_callback = lb_control_msg_proc;

    /* Init neighbor table */
    if (0 > lb_neighbor_init(1000)) {
        LOG(LB, ERR, "Neighbor init failed.\n");
        return -1;
    }

    /* Init backend-table and hash-table */
    if (0 > lb_backend_init(system_cfg)) {
        LOG(LB, ERR, "Backend management init failed.\n");
        return -1;
    }

    /* Init H-A management unit */
#ifdef ENABLED_HA
    lb_register_high_availability_module(lb_ha_sync_be_table,
                                          lb_ha_update_period_sync_hash,
                                          lb_ha_update_period_sync_be,
                                          lb_ha_msg_proc,
                                          lb_ha_init,
                                          lb_ha_deinit,
                                          lb_ha_ass);
#else
    lb_register_high_availability_module(NULL,
                                         NULL,
                                         NULL,
                                         NULL,
                                         NULL,
                                         NULL,
                                         NULL);
#endif
    if (lb_hk_ha_init) {
        if (0 > lb_hk_ha_init(system_cfg)) {
            LOG(LB, ERR, "H-A management init failed.\n");
            return -1;
        }
    } else {
        lb_set_standby_alive(G_FALSE);
        lb_set_work_status(LB_STATUS_ACTIVE);
    }

    LOG(LB, MUST, "------Load-balancer init success------\n");

    return 0;
}

int32_t lb_deinit()
{
    dpdk_deinit();
    if (lb_hk_ha_deinit) {
        lb_hk_ha_deinit();
    }

    return 0;
}

int lb_ha_active_standby_switch(struct cli_def *cli,int argc, char **argv)
{
    if (lb_hk_ha_ass) {
        if (0 > lb_hk_ha_ass()) {
            cli_print(cli,"Active/Standby switch failed.\n");
            return -1;
        } else {
            cli_print(cli,"Active/Standby switch success.\n");
        }
    } else {
        cli_print(cli, "High availability is not supported.\n");
    }

    return 0;
}

int lb_ha_get_lbu_status(struct cli_def *cli,int argc, char **argv)
{
    switch (lb_get_work_status()) {
        case LB_STATUS_ACTIVE:
            cli_print(cli,"Work status: Active\n");
            break;
        case LB_STATUS_STANDBY:
            cli_print(cli,"Work status: Standby\n");
            break;
        case LB_STATUS_SMOOTH2ACTIVE:
            cli_print(cli,"Work status: Smooth to active\n");
            break;
        case LB_STATUS_SMOOTH2STANDBY:
            cli_print(cli,"Work status: Smooth to standby\n");
            break;
        case LB_STATUS_INIT:
            cli_print(cli,"Work status: Init\n");
            break;
    }

    cli_print(cli,"Standby status: %s\n",
        lb_get_standby_alive() ? "On-line" : "Off-line");

    return 0;
}

